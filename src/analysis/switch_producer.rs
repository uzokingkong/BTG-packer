//! Conservative producer for compiler-style dense switch jumps.
//!
//! Only bounded, in-block idioms are accepted.  A missing bound, an unreadable
//! entry, or a target outside executable image ranges is retained as partial
//! evidence; no heuristic target is ever invented.

use std::collections::BTreeSet;

use iced_x86::{
    FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};

use super::indirect_resolver::IndirectResolution;
use super::indirect_targets::{
    IndirectKind, JumpTableDescriptor, TableDescriptor, TargetProvenance,
};
use super::program_model::{EdgeKind, EdgeTarget, ProgramModel, RvaRange};
use super::switch_targets::{
    resolve_switch_targets, SwitchEntryEncoding, SwitchSection, SwitchTableLayout,
};
use super::value_flow::{self, AbstractValue, CompareKind, ValueBase, ValueFlowConfig};

const MAX_SWITCH_ENTRIES: u32 = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducedSwitchResolution {
    pub resolution: IndirectResolution,
    pub table: Option<TableDescriptor>,
}

/// Produces resolutions for the switch forms whose table address, index and
/// exhaustive upper bound can all be proved inside one canonical basic block.
pub fn produce_switch_resolutions(
    program: &ProgramModel,
    image_base: u64,
    sections: &[SwitchSection<'_>],
) -> Vec<ProducedSwitchResolution> {
    let mut out = Vec::new();
    for site in program.indirect_targets.sites.values() {
        if site.kind != IndirectKind::Jump {
            continue;
        }
        // The CFG importer may split at every branch target, including the
        // three-instruction table dispatch itself. Reconstruct an ordered,
        // function-local instruction view; pattern recovery still requires
        // adjacent load/add/jump instructions and an explicit bound proof.
        let Some(function) = program.functions.get(&site.source_function) else {
            continue;
        };
        let mut function_instructions = function
            .blocks
            .iter()
            .filter_map(|block_id| program.blocks.get(block_id))
            .flat_map(|block| block.instructions.iter().cloned())
            .collect::<Vec<_>>();
        function_instructions.sort_by_key(|instruction| instruction.ip());
        function_instructions.dedup_by_key(|instruction| instruction.ip());
        let Some(global_jump_index) = function_instructions.iter().position(|i| {
            i.ip()
                .checked_sub(image_base)
                .and_then(|x| u32::try_from(x).ok())
                == Some(site.instruction_rva)
        }) else {
            continue;
        };
        let window_start = global_jump_index.saturating_sub(4095);
        let instructions = &function_instructions[window_start..=global_jump_index];
        let jump_index = instructions.len() - 1;
        let flow = value_flow::analyze(
            &instructions,
            ValueFlowConfig {
                image_base,
                ..Default::default()
            },
        );
        if flow.truncated {
            continue;
        }
        let Some(pattern) = recover_pattern(&instructions, jump_index, &flow, image_base) else {
            continue;
        };
        let entry_count = flow
            // In the rel32 idiom the table load overwrites the index register
            // (`movsxd rax,[base+rax*4]`). Query before that load, while the
            // compare-derived bound is still live.
            .bound_before(pattern.load_index, pattern.index)
            .and_then(|bound| match bound.compare {
                CompareKind::BelowOrEqual => bound.upper.checked_add(1),
                CompareKind::Below => Some(bound.upper),
                _ => None,
            })
            .or_else(|| masked_entry_count(&instructions, pattern.load_index, pattern.index))
            .or_else(|| compared_entry_count(&instructions, pattern.load_index, pattern.index))
            .or_else(|| {
                matches!(
                    flow.value_before(pattern.load_index, pattern.index),
                    AbstractValue::Constant(0)
                )
                .then_some(1)
            })
            .or_else(|| {
                cfg_taken_entry_count(
                    program,
                    image_base,
                    instructions[pattern.load_index].ip(),
                    pattern.index,
                )
            });
        let Some(entry_count) = entry_count.and_then(|n| u32::try_from(n).ok()) else {
            continue;
        };
        if entry_count == 0 || entry_count > MAX_SWITCH_ENTRIES {
            continue;
        }
        let layout = SwitchTableLayout::Direct {
            table_rva: pattern.table_rva,
            encoding: pattern.encoding,
        };
        let Ok(set) = resolve_switch_targets(
            site.instruction_rva,
            layout,
            entry_count,
            image_base,
            sections,
            &program.executable_ranges,
        ) else {
            continue;
        };
        let target_rvas = set
            .targets
            .iter()
            .map(|t| t.target_rva)
            .collect::<BTreeSet<_>>();
        if target_rvas.is_empty() {
            continue;
        }
        let width = pattern.width;
        let table = pattern
            .table_rva
            .checked_add(entry_count.saturating_mul(u32::from(width)))
            .and_then(|end| RvaRange::new(pattern.table_rva, end).ok())
            .filter(|range| {
                sections.iter().any(|s| {
                    let end = s.rva.checked_add(s.bytes.len() as u32);
                    s.rva <= range.start && end.is_some_and(|e| range.end <= e)
                })
            })
            .map(|table| {
                TableDescriptor::Jump(JumpTableDescriptor {
                    table,
                    entry_width: width,
                    entry_count,
                    base_rva: pattern.base_rva,
                    entries_are_relative: matches!(
                        pattern.encoding,
                        SwitchEntryEncoding::Rel32 { .. }
                    ),
                })
            });
        out.push(ProducedSwitchResolution {
            resolution: IndirectResolution {
                site: site.id,
                target_rvas,
                provenance: TargetProvenance::JumpTable,
                complete: set.complete,
            },
            table,
        });
    }
    out
}

/// Recovers the range proof carried by a conditional taken edge into the
/// dispatch block. MSVC and rustc commonly emit `cmp index,N; jbe dispatch`
/// with the default case on the fallthrough path, so a linear instruction
/// window cannot soundly retain that proof.
fn cfg_taken_entry_count(
    program: &ProgramModel,
    image_base: u64,
    load_ip: u64,
    index: Register,
) -> Option<u64> {
    let load_rva = u32::try_from(load_ip.checked_sub(image_base)?).ok()?;
    let (load_block_id, load_block) = program
        .blocks
        .iter()
        .find(|(_, block)| block.range.start <= load_rva && load_rva < block.range.end)?;
    let load_position = load_block
        .instructions
        .iter()
        .position(|instruction| instruction.ip() == load_ip)?;
    let mut compared_register = index.full_register();
    for instruction in load_block.instructions[..load_position].iter().rev() {
        if !writes_register(instruction, compared_register) {
            continue;
        }
        if instruction.mnemonic() == Mnemonic::Mov && instruction.op1_kind() == OpKind::Register {
            compared_register = instruction.op1_register().full_register();
        } else {
            return None;
        }
    }

    let mut counts = BTreeSet::new();
    for edge in program.edges.iter().filter(|edge| {
        edge.kind == EdgeKind::DirectBranch && edge.target == EdgeTarget::Block(*load_block_id)
    }) {
        let Some(source) = program.blocks.get(&edge.source) else {
            continue;
        };
        if source.function_id != load_block.function_id || source.instructions.len() < 2 {
            continue;
        }
        let Some(branch) = source.instructions.last() else {
            continue;
        };
        let compare = &source.instructions[source.instructions.len() - 2];
        let Some(branch_target_rva) = branch
            .near_branch_target()
            .checked_sub(image_base)
            .and_then(|rva| u32::try_from(rva).ok())
        else {
            continue;
        };
        if branch_target_rva != load_block.range.start
            || compare.mnemonic() != Mnemonic::Cmp
            || compare.op0_kind() != OpKind::Register
            || compare.op0_register().full_register() != compared_register
        {
            continue;
        }
        let Some(upper) = immediate_operand(compare, 1) else {
            continue;
        };
        let count = match branch.mnemonic() {
            Mnemonic::Jbe => upper.checked_add(1),
            Mnemonic::Jb => Some(upper),
            _ => None,
        };
        if let Some(count) = count {
            counts.insert(count);
        }
    }
    (counts.len() == 1).then(|| *counts.first().unwrap())
}

fn immediate_operand(instruction: &Instruction, operand: u32) -> Option<u64> {
    match instruction.op_kind(operand) {
        OpKind::Immediate8 => Some(u64::from(instruction.immediate8())),
        OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
            Some(instruction.immediate8to64() as u64)
        }
        OpKind::Immediate16 => Some(u64::from(instruction.immediate16())),
        OpKind::Immediate32 => Some(u64::from(instruction.immediate32())),
        OpKind::Immediate32to64 => Some(instruction.immediate32to64() as u64),
        OpKind::Immediate64 => Some(instruction.immediate64()),
        _ => None,
    }
}

fn writes_register(instruction: &Instruction, register: Register) -> bool {
    if instruction.op0_kind() != OpKind::Register
        || instruction.op0_register().full_register() != register.full_register()
    {
        return false;
    }
    let mut factory = InstructionInfoFactory::new();
    matches!(
        factory.info(instruction).op0_access(),
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn compared_entry_count(ins: &[Instruction], load_index: usize, index: Register) -> Option<u64> {
    let window_start = load_index.saturating_sub(24);
    let compared_register = selector_copy_origin(ins, load_index, index);
    for (offset, instruction) in ins[window_start..load_index].iter().enumerate().rev() {
        if instruction.mnemonic() != Mnemonic::Cmp
            || instruction.op0_kind() != OpKind::Register
            || instruction.op0_register().full_register() != compared_register
        {
            continue;
        }
        let upper = match instruction.op1_kind() {
            OpKind::Immediate8 => u64::from(instruction.immediate8()),
            OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
                instruction.immediate8to64() as u64
            }
            OpKind::Immediate32 => u64::from(instruction.immediate32()),
            OpKind::Immediate32to64 => instruction.immediate32to64() as u64,
            _ => return None,
        };
        let absolute = window_start + offset;
        let guard = ins.get(absolute + 1)?;
        let count = match guard.mnemonic() {
            Mnemonic::Ja => upper.checked_add(1),
            Mnemonic::Jae => Some(upper),
            _ => None,
        }?;
        // No later write may change the selector before the table load.
        if ins[absolute + 2..load_index].iter().any(|candidate| {
            writes_register(candidate, index)
                || (compared_register != index && writes_register(candidate, compared_register))
        }) {
            return None;
        }
        return Some(count);
    }
    None
}

fn selector_copy_origin(ins: &[Instruction], load_index: usize, index: Register) -> Register {
    let mut current = index.full_register();
    for instruction in ins[load_index.saturating_sub(32)..load_index].iter().rev() {
        if !writes_register(instruction, current) {
            continue;
        }
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op1_kind() == OpKind::Register
        {
            current = instruction.op1_register().full_register();
        }
        break;
    }
    current
}

fn masked_entry_count(ins: &[Instruction], load_index: usize, index: Register) -> Option<u64> {
    for instruction in ins[load_index.saturating_sub(12)..load_index].iter().rev() {
        if instruction.op0_kind() != OpKind::Register
            || instruction.op0_register().full_register() != index
        {
            continue;
        }
        if instruction.mnemonic() != Mnemonic::And {
            return None;
        }
        let mask = match instruction.op1_kind() {
            OpKind::Immediate8 => u64::from(instruction.immediate8()),
            OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
                instruction.immediate8to64() as u64
            }
            OpKind::Immediate32 => u64::from(instruction.immediate32()),
            OpKind::Immediate32to64 => instruction.immediate32to64() as u64,
            _ => return None,
        };
        // A low-bit mask produces the exhaustive domain 0..=mask only when it
        // is of the form 2^n-1. Arbitrary bit masks have holes.
        return mask.checked_add(1).filter(|count| count.is_power_of_two());
    }
    None
}

#[derive(Clone, Copy)]
struct Pattern {
    index: Register,
    table_rva: u32,
    base_rva: u32,
    width: u8,
    encoding: SwitchEntryEncoding,
    load_index: usize,
}

fn recover_pattern(
    ins: &[Instruction],
    j: usize,
    flow: &value_flow::ValueFlowResult,
    image_base: u64,
) -> Option<Pattern> {
    let jump = ins.get(j)?;
    if jump.mnemonic() != Mnemonic::Jmp {
        return None;
    }
    if jump.op0_kind() == OpKind::Memory {
        let index = jump.memory_index().full_register();
        if index == Register::None || jump.memory_index_scale() != 8 {
            return None;
        }
        let table_rva = memory_base_rva(jump, j, flow, image_base)?;
        return Some(Pattern {
            index,
            table_rva,
            base_rva: 0,
            width: 8,
            encoding: SwitchEntryEncoding::Va64,
            load_index: j,
        });
    }
    // lea base,[rip+table]; movsxd tmp,dword ptr [base+index*4]; add tmp,base; jmp tmp
    let target =
        (jump.op0_kind() == OpKind::Register).then(|| jump.op0_register().full_register())?;
    let add_index = (j.saturating_sub(8)..j).rev().find(|&candidate| {
        let instruction = &ins[candidate];
        instruction.mnemonic() == Mnemonic::Add
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == target
            && instruction.op1_kind() == OpKind::Register
            && ins[candidate + 1..j].iter().all(|between| {
                between.flow_control() == FlowControl::Next
                    && !(between.op0_kind() == OpKind::Register
                        && between.op0_register().full_register() == target)
            })
    })?;
    let load_index = add_index.checked_sub(1)?;
    let add = &ins[add_index];
    let load = &ins[load_index];
    if load.ip().checked_add(load.len() as u64) != Some(add.ip()) {
        return None;
    }
    if add.mnemonic() != Mnemonic::Add
        || add.op0_register().full_register() != target
        || add.op1_kind() != OpKind::Register
        || load.mnemonic() != Mnemonic::Movsxd
        || load.op0_register().full_register() != target
        || load.op1_kind() != OpKind::Memory
        || load.memory_index_scale() != 4
    {
        return None;
    }
    let base = add.op1_register().full_register();
    if load.memory_base().full_register() != base {
        return None;
    }
    let index = load.memory_index().full_register();
    let table_rva = memory_base_rva(load, load_index, flow, image_base)?;
    let base_rva = abstract_rva(flow.value_before(add_index, base), image_base)?;
    Some(Pattern {
        index,
        table_rva,
        base_rva,
        width: 4,
        encoding: SwitchEntryEncoding::Rel32 { base_rva },
        load_index,
    })
}

fn memory_base_rva(
    ins: &Instruction,
    at: usize,
    flow: &value_flow::ValueFlowResult,
    image_base: u64,
) -> Option<u32> {
    let disp = ins.memory_displacement64() as i64;
    let base = ins.memory_base().full_register();
    if base == Register::RIP {
        return u32::try_from(ins.ip_rel_memory_address().checked_sub(image_base)?).ok();
    }
    let rva = abstract_rva(flow.value_before(at, base), image_base)?;
    rva.checked_add_signed(i32::try_from(disp).ok()?)
}

fn abstract_rva(value: AbstractValue, image_base: u64) -> Option<u32> {
    let va = match value {
        AbstractValue::Constant(n) => n,
        AbstractValue::ImageBase { addend } => image_base.checked_add_signed(addend)?,
        AbstractValue::RipRelative { target } => target,
        AbstractValue::Affine {
            base: ValueBase::ImageBase,
            addend,
            index: Register::None,
            ..
        } => image_base.checked_add_signed(addend)?,
        _ => return None,
    };
    u32::try_from(va.checked_sub(image_base)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::program_model::{BlockId, BlockModel, ByteClass, EdgeModel, FunctionId};
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bytes: &[u8]) -> Vec<Instruction> {
        decode_at(bytes, 0x140001000)
    }

    fn decode_at(bytes: &[u8], ip: u64) -> Vec<Instruction> {
        let mut d = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        let mut result = Vec::new();
        while d.can_decode() {
            result.push(d.decode());
        }
        result
    }

    #[test]
    fn carries_taken_edge_bound_through_exact_selector_copy() {
        let image_base = 0x140000000;
        // cmp r12d,27h; jbe 140001010
        let source_instructions =
            decode_at(&[0x41, 0x83, 0xfc, 0x27, 0x76, 0x0a], image_base + 0x1000);
        // mov eax,r12d; movsxd rax,dword ptr [r14+rax*4]
        let dispatch_instructions = decode_at(
            &[0x41, 0x8b, 0xc4, 0x49, 0x63, 0x04, 0x86],
            image_base + 0x1010,
        );
        let source_id = BlockId(1);
        let dispatch_id = BlockId(2);
        let function_id = FunctionId(1);
        let mut program = ProgramModel::default();
        program.blocks.insert(
            source_id,
            BlockModel {
                id: source_id,
                function_id,
                range: RvaRange::new(0x1000, 0x1006).unwrap(),
                instructions: source_instructions,
                byte_class: ByteClass::Instruction,
            },
        );
        program.blocks.insert(
            dispatch_id,
            BlockModel {
                id: dispatch_id,
                function_id,
                range: RvaRange::new(0x1010, 0x1017).unwrap(),
                instructions: dispatch_instructions,
                byte_class: ByteClass::Instruction,
            },
        );
        program.edges.push(EdgeModel {
            source: source_id,
            kind: EdgeKind::DirectBranch,
            target: EdgeTarget::Block(dispatch_id),
        });
        assert_eq!(
            cfg_taken_entry_count(&program, image_base, image_base + 0x1013, Register::RAX),
            Some(40)
        );
    }

    #[test]
    fn recognizes_bounded_dense_va_table() {
        // cmp ecx,2; ja default; lea rax,[rip+0x20]; jmp [rax+rcx*8]
        let ins = decode(&[
            0x83, 0xf9, 2, 0x77, 0, 0x48, 0x8d, 0x05, 0x20, 0, 0, 0, 0xff, 0x24, 0xc8,
        ]);
        let flow = value_flow::analyze(
            &ins,
            ValueFlowConfig {
                image_base: 0x140000000,
                ..Default::default()
            },
        );
        let p = recover_pattern(&ins, 3, &flow, 0x140000000).unwrap();
        assert_eq!((p.index, p.width), (Register::RCX, 8));
        assert_eq!(flow.bound_before(3, Register::RCX).unwrap().upper, 2);
    }

    #[test]
    fn recognizes_signed_rel32_table() {
        // cmp ecx,1; ja; lea rdx,[rip+table]; movsxd rax,[rdx+rcx*4]; add rax,rdx; jmp rax
        let ins = decode(&[
            0x83, 0xf9, 1, 0x77, 0, 0x48, 0x8d, 0x15, 0x20, 0, 0, 0, 0x48, 0x63, 0x04, 0x8a, 0x48,
            0x01, 0xd0, 0xff, 0xe0,
        ]);
        let flow = value_flow::analyze(
            &ins,
            ValueFlowConfig {
                image_base: 0x140000000,
                ..Default::default()
            },
        );
        let p = recover_pattern(&ins, 5, &flow, 0x140000000).unwrap();
        assert!(matches!(p.encoding, SwitchEntryEncoding::Rel32 { .. }));
        assert_eq!(p.width, 4);
    }

    #[test]
    fn recognizes_sign_extended_imm8_selector_mask() {
        // and eax,3; movsxd rax,dword ptr [rdx+rax*4]
        let ins = decode(&[0x83, 0xe0, 0x03, 0x48, 0x63, 0x04, 0x82]);
        assert_eq!(ins[0].op1_kind(), OpKind::Immediate8to32);
        assert_eq!(masked_entry_count(&ins, 1, Register::RAX), Some(4));
    }

    #[test]
    fn unreadable_or_nonexec_entry_is_partial() {
        let bytes = [0x00, 0x10, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00];
        let set = resolve_switch_targets(
            0x1010,
            SwitchTableLayout::Direct {
                table_rva: 0x2000,
                encoding: SwitchEntryEncoding::Rva32,
            },
            3,
            0x140000000,
            &[SwitchSection {
                name: ".rdata",
                rva: 0x2000,
                bytes: &bytes,
            }],
            &[RvaRange {
                start: 0x1000,
                end: 0x1100,
            }],
        )
        .unwrap();
        assert!(!set.complete);
        assert_eq!(set.targets.len(), 1);
    }
}
