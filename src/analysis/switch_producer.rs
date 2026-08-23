//! Conservative producer for compiler-style dense switch jumps.
//!
//! Only bounded, in-block idioms are accepted.  A missing bound, an unreadable
//! entry, or a target outside executable image ranges is retained as partial
//! evidence; no heuristic target is ever invented.

use std::collections::BTreeSet;

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use super::indirect_resolver::IndirectResolution;
use super::indirect_targets::{
    IndirectKind, JumpTableDescriptor, TableDescriptor, TargetProvenance,
};
use super::program_model::{ProgramModel, RvaRange};
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
        let Some(block) = program.blocks.get(&site.source_block) else {
            continue;
        };
        let Some(jump_index) = block.instructions.iter().position(|i| {
            i.ip()
                .checked_sub(image_base)
                .and_then(|x| u32::try_from(x).ok())
                == Some(site.instruction_rva)
        }) else {
            continue;
        };
        let flow = value_flow::analyze(
            &block.instructions,
            ValueFlowConfig {
                image_base,
                ..Default::default()
            },
        );
        if flow.truncated {
            continue;
        }
        let Some(pattern) = recover_pattern(&block.instructions, jump_index, &flow, image_base)
        else {
            continue;
        };
        let Some(bound) = flow.bound_before(jump_index, pattern.index) else {
            continue;
        };
        let entry_count = match bound.compare {
            CompareKind::BelowOrEqual => bound.upper.checked_add(1),
            CompareKind::Below => Some(bound.upper),
            _ => None,
        };
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

#[derive(Clone, Copy)]
struct Pattern {
    index: Register,
    table_rva: u32,
    base_rva: u32,
    width: u8,
    encoding: SwitchEntryEncoding,
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
        });
    }
    // lea base,[rip+table]; movsxd tmp,dword ptr [base+index*4]; add tmp,base; jmp tmp
    let target =
        (jump.op0_kind() == OpKind::Register).then(|| jump.op0_register().full_register())?;
    let add = ins.get(j.checked_sub(1)?)?;
    let load = ins.get(j.checked_sub(2)?)?;
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
    let table_rva = memory_base_rva(load, j - 2, flow, image_base)?;
    let base_rva = abstract_rva(flow.value_before(j - 1, base), image_base)?;
    Some(Pattern {
        index,
        table_rva,
        base_rva,
        width: 4,
        encoding: SwitchEntryEncoding::Rel32 { base_rva },
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
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bytes: &[u8]) -> Vec<Instruction> {
        let mut d = Decoder::with_ip(64, bytes, 0x140001000, DecoderOptions::NONE);
        let mut result = Vec::new();
        while d.can_decode() {
            result.push(d.decode());
        }
        result
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
