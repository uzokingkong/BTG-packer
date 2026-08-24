//! Conservative indirect-call target production from canonical code pointers.
//!
//! A code pointer is not, by itself, evidence for any particular indirect
//! site.  This pass only associates pointers with a site when the site's
//! memory operand names the slot/table.  Indexed tables require an externally
//! proven extent; a contiguous run of relocations is deliberately not treated
//! as a bound.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use super::indirect_resolver::IndirectResolution;
use super::indirect_targets::{ResolutionStatus, TargetProvenance};
#[cfg(test)]
use super::indirect_targets::IndirectKind;
use super::program_model::{CodePointerEncoding, ProgramModel, RvaRange};
use crate::pe::builder::SectionData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenPointerTable {
    pub table: RvaRange,
    pub entry_width: u8,
    /// Set only when a typed parser or bounded value-flow proof established
    /// both ends of the table.  Relocation adjacency is not sufficient.
    pub extent_proven: bool,
    pub provenance: TargetProvenance,
}

/// Produces site-scoped resolutions. Unrelated global pointer candidates are
/// never assigned to a site.
pub fn produce(
    program: &ProgramModel,
    image_base: u64,
    proven_tables: &[ProvenPointerTable],
) -> Vec<IndirectResolution> {
    let pointers: BTreeMap<u32, _> = program
        .code_pointers
        .values()
        .map(|pointer| (pointer.location.start, pointer))
        .collect();
    let mut out = Vec::new();

    for site in program
        .indirect_targets
        .sites
        .values()
        .filter(|site| site.status == ResolutionStatus::Unresolved)
    {
        let Some(block) = program.blocks.get(&site.source_block) else {
            continue;
        };
        let Some(instruction) = block.instructions.iter().find(|instruction| {
            instruction
                .ip()
                .checked_sub(image_base)
                .and_then(|rva| u32::try_from(rva).ok())
                == Some(site.instruction_rva)
        }) else {
            continue;
        };
        if instruction.op0_kind() != OpKind::Memory {
            continue;
        }
        let Some(operand_rva) = memory_operand_rva(instruction, image_base) else {
            continue;
        };

        let indexed = instruction.memory_index() != Register::None;
        let (range, width, complete, provenance) = if indexed {
            let Some(table) = proven_tables
                .iter()
                .find(|table| table.table.start <= operand_rva && operand_rva < table.table.end)
            else {
                // A register/indexed call without a proven linkage range must
                // not consume global relocation candidates.
                continue;
            };
            (
                table.table,
                table.entry_width,
                table.extent_proven,
                table.provenance,
            )
        } else {
            let Some(pointer) = pointers.get(&operand_rva) else {
                continue;
            };
            let width = pointer.location.end.saturating_sub(pointer.location.start) as u8;
            (
                pointer.location,
                width,
                true,
                provenance_for(pointer.encoding),
            )
        };

        if width == 0 || range.end.saturating_sub(range.start) % u32::from(width) != 0 {
            continue;
        }
        let slots = range.end.saturating_sub(range.start) / u32::from(width);
        let mut targets = BTreeSet::new();
        let mut populated = 0u32;
        for index in 0..slots {
            let location = range.start + index * u32::from(width);
            if let Some(pointer) = pointers.get(&location).filter(|pointer| {
                pointer.location.end.saturating_sub(pointer.location.start) == u32::from(width)
            }) {
                let Some(function) = program.functions.get(&pointer.target) else {
                    continue;
                };
                if let Some(&entry) = function.entries.iter().next() {
                    targets.insert(entry);
                    populated += 1;
                }
            }
        }
        if targets.is_empty() {
            continue;
        }
        out.push(IndirectResolution {
            site: site.id,
            target_rvas: targets,
            provenance,
            complete: complete && populated == slots,
        });
    }
    out.sort_by_key(|resolution| resolution.site);
    out
}

/// Finds direct memory calls whose slot lies in the typed PE IAT directory.
/// Such a site is completely external even though the loader-populated target
/// address is unavailable in the file image.
pub fn produce_iat_slots(
    program: &ProgramModel,
    image_base: u64,
    iat: RvaRange,
) -> Vec<(crate::analysis::indirect_targets::IndirectSiteId, u64)> {
    let mut out = Vec::new();
    if iat.start >= iat.end {
        return out;
    }
    for site in program
        .indirect_targets
        .sites
        .values()
        .filter(|site| site.status == ResolutionStatus::Unresolved)
    {
        let Some(block) = program.blocks.get(&site.source_block) else {
            continue;
        };
        let Some(instruction) = block.instructions.iter().find(|instruction| {
            instruction
                .ip()
                .checked_sub(image_base)
                .and_then(|rva| u32::try_from(rva).ok())
                == Some(site.instruction_rva)
        }) else {
            continue;
        };
        let slot_instructions = if instruction.op0_kind() == OpKind::Memory
            && instruction.memory_index() == Register::None
        {
            vec![instruction]
        } else if instruction.op0_kind() == OpKind::Register {
            let Some(site_index) = block
                .instructions
                .iter()
                .position(|candidate| candidate.ip() == instruction.ip())
            else {
                continue;
            };
            let register = instruction.op0_register().full_register();
            let definitions = find_contiguous_register_definition(
                program,
                site.source_function,
                site.instruction_rva,
                register,
                image_base,
            )
            .map(|definition| vec![definition])
            .or_else(|| {
                find_reaching_register_definitions(program, site.source_block, site_index, register)
            });
            let Some(definitions) = definitions else {
                continue;
            };
            definitions
        } else {
            continue;
        };
        let slots = slot_instructions
            .iter()
            .map(|definition| {
                if definition.ip() == instruction.ip() {
                    memory_operand_rva(definition, image_base)
                } else {
                    (definition.mnemonic() == Mnemonic::Mov
                        && definition.op1_kind() == OpKind::Memory
                        && definition.memory_index() == Register::None)
                        .then(|| memory_operand_rva(definition, image_base))
                        .flatten()
                }
            })
            .collect::<Option<Vec<_>>>();
        let Some(slots) = slots.filter(|slots| {
            !slots.is_empty()
                && slots
                    .iter()
                    .all(|slot| iat.start <= *slot && *slot < iat.end)
        }) else {
            continue;
        };
        out.push((site.id, image_base + u64::from(slots[0])));
    }
    out.sort_by_key(|(site, _)| *site);
    out
}

/// Returns whether operand zero actually modifies `register`.
///
/// Merely naming a register as operand zero is insufficient: indirect calls,
/// tests, comparisons, and pushes read that operand. Treating those uses as
/// definitions cuts reaching-definition walks off before an earlier typed IAT
/// or table load can be observed.
fn writes_op0_register(instruction: &Instruction, register: Register) -> bool {
    if instruction.op0_kind() != OpKind::Register
        || instruction.op0_register().full_register() != register
    {
        return false;
    }
    let mut factory = InstructionInfoFactory::new();
    matches!(
        factory.info(instruction).op0_access(),
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

/// Resolves function pointers obtained from GetProcAddress and cached in
/// zero-initialized image globals. A cache slot is trusted only when every
/// decoded store to it is reached directly from the typed resolver return.
pub fn produce_dynamic_import_resolutions(
    program: &ProgramModel,
    image_base: u64,
    get_proc_address_slots: &BTreeSet<u32>,
    sections: &[SectionData],
) -> Vec<(crate::analysis::indirect_targets::IndirectSiteId, u64)> {
    let dynamic_slots = discover_dynamic_import_slots(
        program,
        image_base,
        get_proc_address_slots,
        sections,
    );
    if dynamic_slots.is_empty() {
        return Vec::new();
    }
    let identity = image_base + u64::from(*get_proc_address_slots.iter().next().unwrap());
    let mut out = Vec::new();
    for site in program.indirect_targets.sites.values().filter(|site| {
        site.status == ResolutionStatus::Unresolved
    }) {
        let Some(block) = program.blocks.get(&site.source_block) else { continue };
        let Some(index) = block.instructions.iter().position(|instruction| {
            instruction.ip().checked_sub(image_base)
                .and_then(|rva| u32::try_from(rva).ok()) == Some(site.instruction_rva)
        }) else { continue };
        let transfer = &block.instructions[index];
        if transfer.op0_kind() != OpKind::Register {
            continue;
        }
        let mut visiting = BTreeSet::new();
        let proven = prove_dynamic_external_register(
            program,
            site.source_block,
            index,
            transfer.op0_register().full_register(),
            image_base,
            get_proc_address_slots,
            &dynamic_slots,
            &mut visiting,
        );
        if proven {
            out.push((site.id, identity));
        }
    }
    out.sort_by_key(|(site, _)| *site);
    out
}

fn discover_dynamic_import_slots(
    program: &ProgramModel,
    image_base: u64,
    resolver_slots: &BTreeSet<u32>,
    sections: &[SectionData],
) -> BTreeSet<u32> {
    let mut candidates = BTreeMap::<u32, BTreeSet<u64>>::new();
    for function in program.functions.keys() {
        let mut instructions = program.blocks.values()
            .filter(|block| block.function_id == *function)
            .flat_map(|block| block.instructions.iter())
            .collect::<Vec<_>>();
        instructions.sort_by_key(|instruction| instruction.ip());
        instructions.dedup_by_key(|instruction| instruction.ip());
        for (index, call) in instructions.iter().enumerate() {
            if call.flow_control() != iced_x86::FlowControl::IndirectCall
                || call.op0_kind() != OpKind::Memory
                || call.memory_index() != Register::None
                || memory_operand_rva(call, image_base)
                    .is_none_or(|slot| !resolver_slots.contains(&slot))
            {
                continue;
            }
            let mut aliases = BTreeSet::from([Register::RAX]);
            for instruction in instructions.iter().skip(index + 1).take(12) {
                if matches!(instruction.flow_control(), iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall) {
                    break;
                }
                if instruction.mnemonic() != Mnemonic::Mov {
                    continue;
                }
                if instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                    && aliases.contains(&instruction.op1_register().full_register())
                {
                    aliases.insert(instruction.op0_register().full_register());
                } else if instruction.op0_kind() == OpKind::Memory
                    && instruction.memory_index() == Register::None
                    && instruction.op1_kind() == OpKind::Register
                    && aliases.contains(&instruction.op1_register().full_register())
                {
                    if let Some(slot) = memory_operand_rva(instruction, image_base) {
                        candidates.entry(slot).or_default().insert(instruction.ip());
                    }
                }
            }
        }
    }
    candidates.retain(|slot, proven_stores| {
        read_u64(sections, *slot) == Some(0)
            && program.blocks.values().flat_map(|block| block.instructions.iter()).all(|instruction| {
                if instruction.mnemonic() != Mnemonic::Mov
                    || instruction.op0_kind() != OpKind::Memory
                    || instruction.memory_index() != Register::None
                    || memory_operand_rva(instruction, image_base) != Some(*slot)
                {
                    true
                } else {
                    proven_stores.contains(&instruction.ip())
                        || unsigned_immediate(instruction, 1) == Some(0)
                }
            })
    });
    candidates.into_keys().collect()
}

#[allow(clippy::too_many_arguments)]
fn prove_dynamic_external_register(
    program: &ProgramModel,
    block_id: super::program_model::BlockId,
    before: usize,
    register: Register,
    image_base: u64,
    resolver_slots: &BTreeSet<u32>,
    dynamic_slots: &BTreeSet<u32>,
    visiting: &mut BTreeSet<(super::program_model::BlockId, usize, Register)>,
) -> bool {
    use super::program_model::EdgeTarget;
    let key = (block_id, before, register);
    if !visiting.insert(key) {
        return false;
    }
    let Some(block) = program.blocks.get(&block_id) else { return false };
    for (index, instruction) in block.instructions[..before].iter().enumerate().rev() {
        if register == Register::RAX
            && instruction.flow_control() == iced_x86::FlowControl::IndirectCall
            && instruction.op0_kind() == OpKind::Memory
            && instruction.memory_index() == Register::None
            && memory_operand_rva(instruction, image_base)
                .is_some_and(|slot| resolver_slots.contains(&slot))
        {
            visiting.remove(&key);
            return true;
        }
        if writes_op0_register(instruction, register) {
            let result = if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op1_kind() == OpKind::Register
            {
                prove_dynamic_external_register(
                    program, block_id, index, instruction.op1_register().full_register(),
                    image_base, resolver_slots, dynamic_slots, visiting,
                )
            } else if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op1_kind() == OpKind::Memory
                && instruction.memory_index() == Register::None
            {
                memory_operand_rva(instruction, image_base)
                    .is_some_and(|slot| dynamic_slots.contains(&slot))
            } else {
                false
            };
            visiting.remove(&key);
            return result;
        }
        if matches!(instruction.flow_control(), iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall)
            && matches!(register, Register::RAX | Register::RCX | Register::RDX | Register::R8 | Register::R9 | Register::R10 | Register::R11)
        {
            visiting.remove(&key);
            return false;
        }
    }
    let function = block.function_id;
    let predecessors = program.edges.iter().filter_map(|edge| match edge.target {
        EdgeTarget::Block(target) if target == block_id
            && program.blocks.get(&edge.source).is_some_and(|source| source.function_id == function) => Some(edge.source),
        _ => None,
    }).collect::<BTreeSet<_>>();
    let result = !predecessors.is_empty() && predecessors.into_iter().all(|predecessor| {
        let len = program.blocks.get(&predecessor).map_or(0, |owner| owner.instructions.len());
        prove_dynamic_external_register(program, predecessor, len, register, image_base, resolver_slots, dynamic_slots, visiting)
    });
    visiting.remove(&key);
    result
}

/// Returns the nearest definition on every CFG path reaching a register use.
/// A path that enters with no definition, or a volatile register crossing a
/// call, makes the proof incomplete. Multiple definitions are accepted only
/// after the caller validates every one against the same typed domain (IAT).
fn find_reaching_register_definitions<'a>(
    program: &'a ProgramModel,
    start_block: super::program_model::BlockId,
    start_index: usize,
    register: Register,
) -> Option<Vec<&'a iced_x86::Instruction>> {
    use super::program_model::EdgeTarget;

    let function = program.blocks.get(&start_block)?.function_id;
    let volatile = matches!(
        register,
        Register::RAX
            | Register::RCX
            | Register::RDX
            | Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
    );
    let mut pending = vec![(start_block, start_index)];
    let mut visited = BTreeSet::new();
    let mut definitions = BTreeMap::new();
    while let Some((block_id, before)) = pending.pop() {
        if !visited.insert(block_id) {
            continue;
        }
        let block = program.blocks.get(&block_id)?;
        let mut found = None;
        for instruction in block.instructions[..before].iter().rev() {
            if volatile
                && matches!(
                    instruction.flow_control(),
                    iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall
                )
            {
                return None;
            }
            if writes_op0_register(instruction, register) {
                found = Some(instruction);
                break;
            }
        }
        if let Some(definition) = found {
            definitions.insert(definition.ip(), definition);
            continue;
        }
        let predecessors = program
            .edges
            .iter()
            .filter_map(|edge| match edge.target {
                EdgeTarget::Block(target)
                    if target == block_id
                        && program
                            .blocks
                            .get(&edge.source)
                            .is_some_and(|source| source.function_id == function) =>
                {
                    Some(edge.source)
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if predecessors.is_empty() {
            return None;
        }
        pending.extend(predecessors.into_iter().map(|predecessor| {
            let len = program
                .blocks
                .get(&predecessor)
                .map_or(0, |owner| owner.instructions.len());
            (predecessor, len)
        }));
    }
    (!definitions.is_empty()).then(|| definitions.into_values().collect())
}

fn find_contiguous_register_definition<'a>(
    program: &'a ProgramModel,
    function: super::program_model::FunctionId,
    site_rva: u32,
    register: Register,
    image_base: u64,
) -> Option<&'a iced_x86::Instruction> {
    let site_va = image_base.checked_add(u64::from(site_rva))?;
    let mut instructions = program
        .blocks
        .values()
        .filter(|block| block.function_id == function)
        .flat_map(|block| block.instructions.iter())
        .filter(|instruction| instruction.ip() < site_va)
        .collect::<Vec<_>>();
    instructions.sort_by_key(|instruction| instruction.ip());
    let mut expected_ip = site_va;
    for instruction in instructions.into_iter().rev().take(32) {
        if instruction.ip().checked_add(instruction.len() as u64) != Some(expected_ip) {
            return None;
        }
        if matches!(
            instruction.flow_control(),
            iced_x86::FlowControl::UnconditionalBranch
                | iced_x86::FlowControl::IndirectBranch
                | iced_x86::FlowControl::Return
        ) {
            return None;
        }
        if matches!(
            instruction.flow_control(),
            iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall
        ) && matches!(
            register,
            Register::RAX
                | Register::RCX
                | Register::RDX
                | Register::R8
                | Register::R9
                | Register::R10
                | Register::R11
        ) {
            return None;
        }
        if writes_op0_register(instruction, register) {
            return Some(instruction);
        }
        expected_ip = instruction.ip();
    }
    None
}

/// Resolves monomorphic local function-pointer/vtable loads. Every resolved
/// memory address must name an existing canonical code-pointer slot, so local
/// value flow never turns an arbitrary constant into a call target.
pub fn produce_local_value_flow(
    program: &ProgramModel,
    image_base: u64,
) -> Vec<IndirectResolution> {
    use crate::analysis::value_flow::{analyze, AbstractValue, ValueFlowConfig};

    let pointers: BTreeMap<u32, _> = program
        .code_pointers
        .values()
        .map(|pointer| (pointer.location.start, pointer))
        .collect();
    let mut out = Vec::new();
    for site in program
        .indirect_targets
        .sites
        .values()
        .filter(|site| site.status == ResolutionStatus::Unresolved)
    {
        let Some(block) = program.blocks.get(&site.source_block) else {
            continue;
        };
        let Some(site_index) = block.instructions.iter().position(|instruction| {
            instruction
                .ip()
                .checked_sub(image_base)
                .and_then(|rva| u32::try_from(rva).ok())
                == Some(site.instruction_rva)
        }) else {
            continue;
        };
        let call = &block.instructions[site_index];
        let slot_value = if call.op0_kind() == OpKind::Memory {
            let flow = analyze(
                &block.instructions,
                ValueFlowConfig {
                    image_base,
                    ..ValueFlowConfig::default()
                },
            );
            if flow.truncated {
                continue;
            }
            flow.memory_address_before(site_index, call, image_base)
        } else if call.op0_kind() == OpKind::Register {
            let target = call.op0_register().full_register();
            let Some((definition_block, definition_index)) =
                find_unique_register_definition(program, site.source_block, site_index, target)
            else {
                continue;
            };
            let Some(definition_owner) = program.blocks.get(&definition_block) else {
                continue;
            };
            let definition = &definition_owner.instructions[definition_index];
            let flow = analyze(
                &definition_owner.instructions,
                ValueFlowConfig {
                    image_base,
                    ..ValueFlowConfig::default()
                },
            );
            if flow.truncated {
                continue;
            }
            if definition.mnemonic() == Mnemonic::Mov && definition.op1_kind() == OpKind::Memory {
                flow.memory_address_before(definition_index, definition, image_base)
            } else {
                continue;
            }
        } else {
            continue;
        };
        let slot_va = match slot_value {
            AbstractValue::Constant(value) | AbstractValue::RipRelative { target: value } => value,
            AbstractValue::ImageBase { addend } if addend >= 0 => image_base + addend as u64,
            _ => continue,
        };
        let Some(slot_rva) = slot_va
            .checked_sub(image_base)
            .and_then(|v| u32::try_from(v).ok())
        else {
            continue;
        };
        let Some(pointer) = pointers.get(&slot_rva) else {
            continue;
        };
        let Some(function) = program.functions.get(&pointer.target) else {
            continue;
        };
        let Some(&entry) = function.entries.iter().next() else {
            continue;
        };
        out.push(IndirectResolution {
            site: site.id,
            target_rvas: BTreeSet::from([entry]),
            provenance: TargetProvenance::Vtable,
            complete: true,
        });
    }
    out.sort_by_key(|resolution| resolution.site);
    out
}

/// Resolves a direct call through an RBP-relative spill slot when the same
/// straight-line region contains the unique typed store that initializes it.
pub fn produce_stack_spill_resolutions(
    program: &ProgramModel,
    image_base: u64,
) -> Vec<IndirectResolution> {
    let mut out = Vec::new();
    for site in program
        .indirect_targets
        .sites
        .values()
        .filter(|site| site.status == ResolutionStatus::Unresolved)
    {
        let Some(block) = program.blocks.get(&site.source_block) else { continue };
        let Some(call) = block.instructions.iter().find(|instruction| {
            instruction.ip().checked_sub(image_base)
                .and_then(|rva| u32::try_from(rva).ok()) == Some(site.instruction_rva)
        }) else { continue };
        if call.op0_kind() != OpKind::Memory
            || call.memory_base().full_register() != Register::RBP
        {
            continue;
        }
        if call.memory_index() != Register::None {
            if let Some(target_rvas) = resolve_bounded_stack_callback_table(
                program,
                site.source_function,
                call,
                image_base,
            ) {
                out.push(IndirectResolution {
                    site: site.id,
                    target_rvas,
                    provenance: TargetProvenance::ConstantPropagation,
                    complete: true,
                });
            }
            continue;
        }
        let mut instructions = program.blocks.values()
            .filter(|candidate| candidate.function_id == site.source_function)
            .flat_map(|candidate| candidate.instructions.iter())
            .collect::<Vec<_>>();
        instructions.sort_by_key(|instruction| instruction.ip());
        let Some(call_index) = instructions.iter().position(|instruction| instruction.ip() == call.ip()) else {
            continue;
        };
        let displacement = call.memory_displacement64();
        let mut store = None;
        for instruction in instructions[call_index.saturating_sub(64)..call_index].iter().rev() {
            if !matches!(instruction.flow_control(), iced_x86::FlowControl::Next) {
                break;
            }
            if instruction.op0_kind() == OpKind::Memory
                && instruction.memory_base().full_register() == Register::RBP
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == displacement
            {
                store = Some(*instruction);
                break;
            }
        }
        let Some(store) = store.filter(|instruction| instruction.mnemonic() == Mnemonic::Mov) else {
            continue;
        };
        let target_rva = if store.op1_kind() == OpKind::Register {
            let source = store.op1_register().full_register();
            let Some(definition) = find_contiguous_register_definition(
                program,
                site.source_function,
                u32::try_from(store.ip().checked_sub(image_base).unwrap_or(u64::MAX)).unwrap_or(u32::MAX),
                source,
                image_base,
            ) else { continue };
            direct_definition_target(program, definition, image_base)
        } else {
            direct_definition_target(program, &store, image_base)
        };
        let Some(target_rva) = target_rva else { continue };
        out.push(IndirectResolution {
            site: site.id,
            target_rvas: BTreeSet::from([target_rva]),
            provenance: TargetProvenance::ConstantPropagation,
            complete: true,
        });
    }
    out.sort_by_key(|resolution| resolution.site);
    out
}

/// Resolves compiler-generated callback arrays materialized in a stack frame.
/// Completeness requires a zero-based, pointer-stride loop, an equality bound,
/// and a typed internal target for every stack slot in the proven extent.
fn resolve_bounded_stack_callback_table(
    program: &ProgramModel,
    function: super::program_model::FunctionId,
    call: &Instruction,
    image_base: u64,
) -> Option<BTreeSet<u32>> {
    let index = call.memory_index().full_register();
    if call.memory_index_scale() != 1 || index == Register::None {
        return None;
    }
    let mut instructions = program
        .blocks
        .values()
        .filter(|block| block.function_id == function)
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();
    instructions.sort_by_key(|instruction| instruction.ip());
    instructions.dedup_by_key(|instruction| instruction.ip());
    let call_index = instructions.iter().position(|candidate| candidate.ip() == call.ip())?;
    let before = &instructions[call_index.saturating_sub(96)..call_index];
    let bound = before.iter().rev().find_map(|instruction| {
        (instruction.mnemonic() == Mnemonic::Cmp
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == index)
            .then(|| unsigned_immediate(instruction, 1))
            .flatten()
    })?;
    if bound == 0 || bound > 0x100 || bound % 8 != 0 {
        return None;
    }
    let zero_based = before.iter().any(|instruction| {
        instruction.mnemonic() == Mnemonic::Xor
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && instruction.op0_register().full_register() == index
            && instruction.op1_register().full_register() == index
    });
    let pointer_stride = before.iter().any(|instruction| {
        instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Memory
            && instruction.memory_base().full_register() == index
            && instruction.memory_index() == Register::None
            && instruction.memory_displacement64() == 8
    });
    if !zero_based || !pointer_stride {
        return None;
    }

    let base = call.memory_displacement64() as i64;
    let mut targets = BTreeSet::new();
    for offset in (0..bound).step_by(8) {
        let displacement = base.wrapping_add(offset as i64) as u64;
        let store = before.iter().rev().find(|instruction| {
            instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.memory_base().full_register() == Register::RBP
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == displacement
        })?;
        let target = if store.op1_kind() == OpKind::Register {
            let source = store.op1_register().full_register();
            let store_index = instructions
                .iter()
                .position(|instruction| instruction.ip() == store.ip())?;
            let mut expected_ip = store.ip();
            let definition = instructions[..store_index]
                .iter()
                .rev()
                .take(8)
                .find(|instruction| {
                    let contiguous = instruction.ip().checked_add(instruction.len() as u64)
                        == Some(expected_ip);
                    expected_ip = instruction.ip();
                    contiguous && writes_op0_register(instruction, source)
                })?;
            direct_definition_target(program, definition, image_base)?
        } else {
            direct_definition_target(program, store, image_base)?
        };
        targets.insert(target);
    }
    (!targets.is_empty()).then_some(targets)
}

fn unsigned_immediate(instruction: &Instruction, operand: u32) -> Option<u64> {
    Some(match instruction.op_kind(operand) {
        OpKind::Immediate8 => instruction.immediate8() as u64,
        OpKind::Immediate8to16 => instruction.immediate8to16() as u16 as u64,
        OpKind::Immediate8to32 => instruction.immediate8to32() as u32 as u64,
        OpKind::Immediate8to64 => instruction.immediate8to64() as u64,
        OpKind::Immediate16 => instruction.immediate16() as u64,
        OpKind::Immediate32 => instruction.immediate32() as u64,
        OpKind::Immediate32to64 => instruction.immediate32to64() as u64,
        OpKind::Immediate64 => instruction.immediate64(),
        _ => return None,
    })
}

fn direct_definition_target(
    program: &ProgramModel,
    definition: &iced_x86::Instruction,
    image_base: u64,
) -> Option<u32> {
    let target_va = match definition.mnemonic() {
        Mnemonic::Lea if definition.op1_kind() == OpKind::Memory
            && definition.is_ip_rel_memory_operand() => definition.ip_rel_memory_address(),
        Mnemonic::Mov if definition.op1_kind() == OpKind::Immediate64 => definition.immediate64(),
        Mnemonic::Mov if definition.op1_kind() == OpKind::Immediate32to64 => {
            definition.immediate32to64() as u64
        }
        Mnemonic::Mov if definition.op1_kind() == OpKind::Memory
            && definition.is_ip_rel_memory_operand() => {
            let slot = u32::try_from(definition.ip_rel_memory_address().checked_sub(image_base)?).ok()?;
            let pointer = program.code_pointers.values().find(|pointer| pointer.location.start == slot)?;
            return program.functions.get(&pointer.target)?.entries.iter().next().copied();
        }
        _ => return None,
    };
    let rva = u32::try_from(target_va.checked_sub(image_base)?).ok()?;
    (program
        .functions
        .values()
        .any(|function| function.entries.contains(&rva))
        || program.blocks.values().any(|block| block.range.start == rva))
    .then_some(rva)
}

/// Resolves callbacks passed through the four Windows x64 integer argument
/// registers. The target set is complete only for an internal callee whose
/// address is not materialized anywhere and when every canonical direct
/// caller supplies a relocation-backed function value for that argument.
/// This is a deliberately small interprocedural points-to analysis: it handles
/// register copies in the callee, but refuses stack aliases and CFG joins.
pub fn produce_abi_argument_resolutions(
    program: &ProgramModel,
    image_base: u64,
) -> Vec<IndirectResolution> {
    use super::program_model::{EdgeKind, EdgeTarget, FunctionId, FunctionProvenance};

    const ABI_ARGS: [Register; 4] = [Register::RCX, Register::RDX, Register::R8, Register::R9];
    let address_taken = program
        .code_pointers
        .values()
        .map(|p| p.target)
        .collect::<BTreeSet<_>>();
    let mut incoming = BTreeMap::<FunctionId, Vec<super::program_model::BlockId>>::new();
    for edge in &program.edges {
        if edge.kind != EdgeKind::DirectCall {
            continue;
        }
        let target = match edge.target {
            EdgeTarget::Function(id) => Some(id),
            EdgeTarget::Block(id) => program.blocks.get(&id).map(|block| block.function_id),
            _ => None,
        };
        if let Some(target) = target {
            incoming.entry(target).or_default().push(edge.source);
        }
    }

    let mut argument_targets = BTreeMap::<(FunctionId, Register), BTreeSet<u32>>::new();
    for (&callee, callers) in &incoming {
        let Some(function) = program.functions.get(&callee) else {
            continue;
        };
        let externally_reachable = address_taken.contains(&callee)
            || program.exports.contains(&callee)
            || program.tls_callbacks.contains(&callee)
            || program.crt_entries.contains(&callee)
            || function
                .provenance
                .contains(&FunctionProvenance::EntryPoint)
            || function
                .provenance
                .contains(&FunctionProvenance::LoadConfig);
        if externally_reachable || callers.is_empty() {
            continue;
        }
        for argument in ABI_ARGS {
            let mut targets = BTreeSet::new();
            let mut all_callers_proven = true;
            for &caller_block in callers {
                let Some(target) =
                    direct_call_argument_target(program, caller_block, argument, image_base)
                else {
                    all_callers_proven = false;
                    break;
                };
                targets.insert(target);
            }
            if all_callers_proven && !targets.is_empty() {
                argument_targets.insert((callee, argument), targets);
            }
        }
    }

    let mut out = Vec::new();
    for site in program
        .indirect_targets
        .sites
        .values()
        .filter(|site| site.status == ResolutionStatus::Unresolved)
    {
        let Some(block) = program.blocks.get(&site.source_block) else {
            continue;
        };
        let Some(site_index) = block.instructions.iter().position(|instruction| {
            instruction
                .ip()
                .checked_sub(image_base)
                .and_then(|rva| u32::try_from(rva).ok())
                == Some(site.instruction_rva)
        }) else {
            continue;
        };
        let call = &block.instructions[site_index];
        if call.op0_kind() != OpKind::Register {
            continue;
        }
        let Some(origin) = trace_register_copy_origin(
            program,
            site.source_block,
            site_index,
            call.op0_register().full_register(),
        ) else {
            continue;
        };
        let Some(target_rvas) = argument_targets.get(&(site.source_function, origin)) else {
            continue;
        };
        out.push(IndirectResolution {
            site: site.id,
            target_rvas: target_rvas.clone(),
            provenance: TargetProvenance::AbiArgument,
            complete: true,
        });
    }
    out.sort_by_key(|resolution| resolution.site);
    out
}

fn direct_call_argument_target(
    program: &ProgramModel,
    block_id: super::program_model::BlockId,
    argument: Register,
    image_base: u64,
) -> Option<u32> {
    let block = program.blocks.get(&block_id)?;
    let call_index = block.instructions.len().checked_sub(1)?;
    let (_, definition) = block.instructions[..call_index]
        .iter()
        .enumerate()
        .rev()
        .find(|(_, instruction)| {
            instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().full_register() == argument
        })?;
    let target_va = match definition.mnemonic() {
        Mnemonic::Lea
            if definition.op1_kind() == OpKind::Memory && definition.is_ip_rel_memory_operand() =>
        {
            definition.ip_rel_memory_address()
        }
        Mnemonic::Mov if definition.op1_kind() == OpKind::Immediate64 => definition.immediate64(),
        Mnemonic::Mov if definition.op1_kind() == OpKind::Immediate32to64 => {
            definition.immediate32to64() as u64
        }
        Mnemonic::Mov
            if definition.op1_kind() == OpKind::Memory && definition.is_ip_rel_memory_operand() =>
        {
            let slot =
                u32::try_from(definition.ip_rel_memory_address().checked_sub(image_base)?).ok()?;
            let pointer = program
                .code_pointers
                .values()
                .find(|p| p.location.start == slot)?;
            return program
                .functions
                .get(&pointer.target)?
                .entries
                .iter()
                .next()
                .copied();
        }
        _ => return None,
    };
    let target_rva = u32::try_from(target_va.checked_sub(image_base)?).ok()?;
    program
        .functions
        .values()
        .find(|function| function.entries.contains(&target_rva))?;
    Some(target_rva)
}

fn trace_register_copy_origin(
    program: &ProgramModel,
    mut block_id: super::program_model::BlockId,
    mut before_index: usize,
    mut register: Register,
) -> Option<Register> {
    const ABI_ARGS: [Register; 4] = [Register::RCX, Register::RDX, Register::R8, Register::R9];
    let function_id = program.blocks.get(&block_id)?.function_id;
    let mut visited = BTreeSet::new();
    for _ in 0..24 {
        if !visited.insert((block_id, register)) {
            return None;
        }
        let block = program.blocks.get(&block_id)?;
        if let Some((_, definition)) = block.instructions[..before_index]
            .iter()
            .enumerate()
            .rev()
            .find(|(_, instruction)| writes_op0_register(instruction, register))
        {
            if definition.mnemonic() == Mnemonic::Mov && definition.op1_kind() == OpKind::Register {
                register = definition.op1_register().full_register();
                before_index = block
                    .instructions
                    .iter()
                    .position(|i| i.ip() == definition.ip())?;
                continue;
            }
            return None;
        }
        let predecessors = program
            .edges
            .iter()
            .filter_map(|edge| match edge.target {
                super::program_model::EdgeTarget::Block(target)
                    if target == block_id
                        && program
                            .blocks
                            .get(&edge.source)
                            .is_some_and(|source| source.function_id == function_id) =>
                {
                    Some(edge.source)
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if predecessors.is_empty() {
            return ABI_ARGS.contains(&register).then_some(register);
        }
        if predecessors.len() != 1 {
            return None;
        }
        block_id = *predecessors.iter().next()?;
        before_index = program.blocks.get(&block_id)?.instructions.len();
    }
    None
}

/// Finds the nearest dominating definition while walking only a unique,
/// intra-function predecessor chain. A join or loop is deliberately a proof
/// boundary: different incoming ABI values must never be merged by guessing.
fn find_unique_register_definition(
    program: &ProgramModel,
    mut block_id: super::program_model::BlockId,
    mut before_index: usize,
    target: Register,
) -> Option<(super::program_model::BlockId, usize)> {
    let function_id = program.blocks.get(&block_id)?.function_id;
    let mut visited = BTreeSet::new();
    for _ in 0..16 {
        if !visited.insert(block_id) {
            return None;
        }
        let block = program.blocks.get(&block_id)?;
        if let Some((index, _)) = block.instructions[..before_index]
            .iter()
            .enumerate()
            .rev()
            .find(|(_, instruction)| writes_op0_register(instruction, target))
        {
            return Some((block_id, index));
        }
        let predecessors = program
            .edges
            .iter()
            .filter_map(|edge| match edge.target {
                super::program_model::EdgeTarget::Block(predecessor_target)
                    if predecessor_target == block_id
                        && program
                            .blocks
                            .get(&edge.source)
                            .is_some_and(|source| source.function_id == function_id) =>
                {
                    Some(edge.source)
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let predecessors = predecessors.into_iter().collect::<Vec<_>>();
        let [predecessor] = predecessors.as_slice() else {
            return None;
        };
        block_id = *predecessor;
        before_index = program.blocks.get(&block_id)?.instructions.len();
    }
    None
}

/// Discovers Rust trait-object vtables using their stable data ABI prefix:
/// `(drop pointer, size, alignment, first method pointer)`. Both pointer slots
/// must come from canonical relocation-backed code-pointer inventory, while
/// size/alignment are read bounds-safely from non-executable mapped data.
pub fn discover_rust_vtable_bases(
    program: &ProgramModel,
    sections: &[SectionData],
) -> BTreeSet<u32> {
    let pointer_slots = program
        .code_pointers
        .values()
        .filter(|pointer| pointer.encoding == CodePointerEncoding::Va64)
        .map(|pointer| pointer.location.start)
        .collect::<BTreeSet<_>>();
    let mut bases = BTreeSet::new();
    for &first_method in &pointer_slots {
        let Some(base) = first_method.checked_sub(0x18) else {
            continue;
        };
        let Some(size) = read_u64(sections, base.saturating_add(8)) else {
            continue;
        };
        let Some(align) = read_u64(sections, base.saturating_add(0x10)) else {
            continue;
        };
        let drop_value = read_u64(sections, base);
        let drop_is_typed = drop_value == Some(0) || pointer_slots.contains(&base);
        if drop_is_typed && size <= (1u64 << 40) && align.is_power_of_two() && align <= 0x1_0000 {
            bases.insert(base);
        }
    }
    bases
}

/// Produces exhaustive internal target sets for statically materialized Rust
/// trait vtables. External implementations remain native passthrough targets;
/// every in-image target must occupy the same validated method slot in one of
/// the discovered vtables.
pub fn produce_rust_vtable_resolutions(
    program: &ProgramModel,
    image_base: u64,
    vtable_bases: &BTreeSet<u32>,
) -> Vec<IndirectResolution> {
    let pointers = program
        .code_pointers
        .values()
        .map(|pointer| (pointer.location.start, pointer))
        .collect::<BTreeMap<_, _>>();
    let mut out = Vec::new();
    for site in program
        .indirect_targets
        .sites
        .values()
        .filter(|site| site.status == ResolutionStatus::Unresolved)
    {
        let Some(block) = program.blocks.get(&site.source_block) else {
            continue;
        };
        let Some(site_index) = block.instructions.iter().position(|instruction| {
            instruction
                .ip()
                .checked_sub(image_base)
                .and_then(|rva| u32::try_from(rva).ok())
                == Some(site.instruction_rva)
        }) else {
            continue;
        };
        let call = &block.instructions[site_index];
        let method_offset = if call.op0_kind() == OpKind::Memory
            && call.memory_index() == Register::None
            && call.memory_base() != Register::None
        {
            u32::try_from(call.memory_displacement64()).ok()
        } else if call.op0_kind() == OpKind::Register {
            find_vtable_method_load(
                program,
                site.source_block,
                site_index,
                call.op0_register().full_register(),
            )
            .or_else(|| {
                find_linear_vtable_method_load(
                    program,
                    site.source_function,
                    site.instruction_rva,
                    call.op0_register().full_register(),
                    image_base,
                )
            })
        } else {
            None
        };
        let Some(method_offset) = method_offset.filter(|offset| {
            (*offset >= 0x18 && *offset <= 0x400 && *offset % 8 == 0)
                || (*offset == 0
                    && call.op0_kind() == OpKind::Register
                    && (has_rust_drop_load_chain(
                            program,
                            site.source_function,
                            site.instruction_rva,
                            call.op0_register().full_register(),
                            image_base,
                        ) || has_rust_drop_layout_prefix(
                            program,
                            site.source_function,
                            site.instruction_rva,
                            call.op0_register().full_register(),
                            image_base,
                        )))
        })
        else {
            continue;
        };
        let mut target_rvas = BTreeSet::new();
        for &base in vtable_bases {
            let Some(slot) = base.checked_add(method_offset) else {
                continue;
            };
            let Some(pointer) = pointers.get(&slot) else {
                continue;
            };
            let Some(function) = program.functions.get(&pointer.target) else {
                continue;
            };
            if let Some(&entry) = function.entries.iter().next() {
                target_rvas.insert(entry);
            }
        }
        if !target_rvas.is_empty() {
            out.push(IndirectResolution {
                site: site.id,
                target_rvas,
                provenance: TargetProvenance::Vtable,
                complete: true,
            });
        }
    }
    out.sort_by_key(|resolution| resolution.site);
    out
}

fn find_linear_vtable_method_load(
    program: &ProgramModel,
    function: super::program_model::FunctionId,
    site_rva: u32,
    target: Register,
    image_base: u64,
) -> Option<u32> {
    let site_va = image_base.checked_add(u64::from(site_rva))?;
    let mut instructions = program.blocks.values()
        .filter(|block| block.function_id == function)
        .flat_map(|block| block.instructions.iter())
        .filter(|instruction| instruction.ip() < site_va)
        .collect::<Vec<_>>();
    instructions.sort_by_key(|instruction| instruction.ip());
    instructions.into_iter().rev().take(16).find_map(|instruction| {
        (instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == target)
            .then(|| {
                (instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op1_kind() == OpKind::Memory
                    && instruction.memory_index() == Register::None
                    && instruction.memory_base() != Register::None)
                    .then(|| u32::try_from(instruction.memory_displacement64()).ok())
                    .flatten()
            })
            .flatten()
    })
}

fn has_rust_drop_load_chain(
    program: &ProgramModel,
    function: super::program_model::FunctionId,
    site_rva: u32,
    target: Register,
    image_base: u64,
) -> bool {
    let Some(site_va) = image_base.checked_add(u64::from(site_rva)) else {
        return false;
    };
    let mut instructions = program
        .blocks
        .values()
        .filter(|block| block.function_id == function)
        .flat_map(|block| block.instructions.iter())
        .filter(|instruction| instruction.ip() < site_va)
        .collect::<Vec<_>>();
    instructions.sort_by_key(|instruction| instruction.ip());
    let window = &instructions[instructions.len().saturating_sub(12)..];
    let Some(drop_index) = window.iter().rposition(|instruction| {
        instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == target
            && instruction.op1_kind() == OpKind::Memory
            && instruction.memory_base().full_register() == target
            && instruction.memory_index() == Register::None
            && instruction.memory_displacement64() == 0
    }) else {
        return false;
    };
    let vtable_loaded = window[..drop_index].iter().rev().any(|instruction| {
        instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == target
            && instruction.op1_kind() == OpKind::Memory
    });
    let null_checked = window[drop_index + 1..].iter().any(|instruction| {
        instruction.mnemonic() == Mnemonic::Test
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && instruction.op0_register().full_register() == target
            && instruction.op1_register().full_register() == target
    });
    vtable_loaded && null_checked
}

/// Recognizes Rust's `(drop, size, align)` vtable prefix around a nullable
/// drop invocation. Requiring both post-call metadata slots prevents a generic
/// optional callback at offset zero from being mislabeled as trait dispatch.
fn has_rust_drop_layout_prefix(
    program: &ProgramModel,
    function: super::program_model::FunctionId,
    site_rva: u32,
    target: Register,
    image_base: u64,
) -> bool {
    let Some(site_va) = image_base.checked_add(u64::from(site_rva)) else {
        return false;
    };
    let mut instructions = program
        .blocks
        .values()
        .filter(|block| block.function_id == function)
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();
    instructions.sort_by_key(|instruction| instruction.ip());
    instructions.dedup_by_key(|instruction| instruction.ip());
    let Some(site_index) = instructions.iter().position(|instruction| instruction.ip() == site_va)
    else {
        return false;
    };
    let before = &instructions[site_index.saturating_sub(10)..site_index];
    let loaded_drop = before.iter().rev().any(|instruction| {
        instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == target
            && instruction.op1_kind() == OpKind::Memory
            && instruction.memory_index() == Register::None
            && instruction.memory_displacement64() == 0
    });
    let null_checked = before.iter().any(|instruction| {
        instruction.mnemonic() == Mnemonic::Test
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && instruction.op0_register().full_register() == target
            && instruction.op1_register().full_register() == target
    });
    if !loaded_drop || !null_checked {
        return false;
    }
    let after = &instructions[site_index + 1..instructions.len().min(site_index + 18)];
    let metadata_bases = |displacement| {
        after
            .iter()
            .filter(|instruction| {
                instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op1_kind() == OpKind::Memory
                    && instruction.memory_index() == Register::None
                    && instruction.memory_base() != Register::None
                    && instruction.memory_displacement64() == displacement
            })
            .map(|instruction| instruction.memory_base().full_register())
            .collect::<BTreeSet<_>>()
    };
    !metadata_bases(8).is_disjoint(&metadata_bases(0x10))
}

fn find_vtable_method_load(
    program: &ProgramModel,
    mut block_id: super::program_model::BlockId,
    mut before_index: usize,
    target: Register,
) -> Option<u32> {
    let function_id = program.blocks.get(&block_id)?.function_id;
    let mut visited = BTreeSet::new();
    for _ in 0..8 {
        if !visited.insert(block_id) {
            return None;
        }
        let block = program.blocks.get(&block_id)?;
        for instruction in block.instructions[..before_index].iter().rev() {
            if instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().full_register() == target
            {
                return (instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op1_kind() == OpKind::Memory
                    && instruction.memory_index() == Register::None
                    && instruction.memory_base() != Register::None)
                    .then(|| u32::try_from(instruction.memory_displacement64()).ok())
                    .flatten();
            }
        }
        let predecessors = program
            .edges
            .iter()
            .filter_map(|edge| match edge.target {
                super::program_model::EdgeTarget::Block(target_block)
                    if target_block == block_id
                        && program
                            .blocks
                            .get(&edge.source)
                            .is_some_and(|source| source.function_id == function_id) =>
                {
                    Some(edge.source)
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let predecessors = predecessors.into_iter().collect::<Vec<_>>();
        let [predecessor] = predecessors.as_slice() else {
            return None;
        };
        block_id = *predecessor;
        before_index = program.blocks.get(&block_id)?.instructions.len();
    }
    None
}

fn read_u64(sections: &[SectionData], rva: u32) -> Option<u64> {
    for section in sections {
        let Some(offset) = rva.checked_sub(section.virtual_address).map(|v| v as usize) else {
            continue;
        };
        let Some(end) = offset.checked_add(8) else {
            continue;
        };
        if end > section.virtual_size as usize {
            continue;
        }
        // PE maps VirtualSize, zero-filling the portion beyond SizeOfRawData.
        // Dynamic import caches commonly live in that BSS tail and therefore
        // have a typed initial value of null even though no file bytes exist.
        let mut value = [0u8; 8];
        if offset < section.bytes.len() {
            let available = (section.bytes.len() - offset).min(8);
            value[..available].copy_from_slice(&section.bytes[offset..offset + available]);
        }
        return Some(u64::from_le_bytes(value));
    }
    None
}

fn memory_operand_rva(instruction: &iced_x86::Instruction, image_base: u64) -> Option<u32> {
    let address = if instruction.is_ip_rel_memory_operand() {
        instruction.ip_rel_memory_address()
    } else {
        instruction.memory_displacement64()
    };
    u32::try_from(address.checked_sub(image_base)?).ok()
}

fn provenance_for(encoding: CodePointerEncoding) -> TargetProvenance {
    match encoding {
        CodePointerEncoding::Va64 => TargetProvenance::Relocation,
        _ => TargetProvenance::PointerTable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};
    use crate::analysis::indirect_targets::IndirectSiteId;
    use crate::analysis::indirect_targets::{IndirectSite, ResolutionStatus, TargetSet};
    use crate::analysis::program_model::{
        BlockId, BlockModel, ByteClass, CodePointerId, CodePointerModel, FunctionId, FunctionModel,
        FunctionProvenance,
    };

    #[test]
    fn register_uses_do_not_hide_the_reaching_definition() {
        let decode = |bytes: &[u8]| {
            Decoder::with_ip(64, bytes, 0x140001000, DecoderOptions::NONE).decode()
        };
        assert!(writes_op0_register(
            &decode(&[0x48, 0x8B, 0x3D, 0, 0, 0, 0]),
            Register::RDI
        ));
        assert!(!writes_op0_register(&decode(&[0xFF, 0xD7]), Register::RDI));
        assert!(!writes_op0_register(&decode(&[0x48, 0x85, 0xFF]), Register::RDI));
        assert!(!writes_op0_register(&decode(&[0x48, 0x39, 0xF7]), Register::RDI));
        assert!(!writes_op0_register(&decode(&[0x57]), Register::RDI));
    }

    #[test]
    fn section_reads_use_loader_zero_fill_for_bss_tail() {
        let section = SectionData {
            name: ".data".into(),
            virtual_address: 0x3000,
            virtual_size: 0x20,
            characteristics: 0,
            bytes: vec![0xAA; 8],
        };
        assert_eq!(read_u64(&[section.clone()], 0x3008), Some(0));
        assert_eq!(read_u64(&[section.clone()], 0x3018), Some(0));
        assert_eq!(read_u64(&[section], 0x3019), None);
    }
    const BASE: u64 = 0x0040_0000;

    fn model(code: &[u8], pointer_locations: &[u32]) -> ProgramModel {
        let mut program = ProgramModel::default();
        let mut decoder = Decoder::with_ip(64, code, BASE + 0x1000, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let block_range = RvaRange::new(0x1000, 0x1000 + instruction.len() as u32).unwrap();
        program.blocks.insert(
            BlockId(1),
            BlockModel {
                id: BlockId(1),
                function_id: FunctionId(1),
                range: block_range,
                instructions: vec![instruction],
                byte_class: ByteClass::Instruction,
            },
        );
        for (id, entry) in [(1, 0x1000), (2, 0x2000), (3, 0x2100)] {
            program.functions.insert(
                FunctionId(id),
                FunctionModel {
                    id: FunctionId(id),
                    ranges: vec![RvaRange::new(entry, entry + 1).unwrap()],
                    entries: BTreeSet::from([entry]),
                    blocks: if id == 1 {
                        BTreeSet::from([BlockId(1)])
                    } else {
                        BTreeSet::new()
                    },
                    provenance: BTreeSet::from([FunctionProvenance::DataCodePointer]),
                    unwind: None,
                },
            );
        }
        program.indirect_targets.sites.insert(
            IndirectSiteId(4),
            IndirectSite {
                id: IndirectSiteId(4),
                instruction_rva: 0x1000,
                source_block: BlockId(1),
                source_function: FunctionId(1),
                kind: IndirectKind::Call,
                status: ResolutionStatus::Unresolved,
                targets: TargetSet::default(),
                table: None,
            },
        );
        for (id, (&location, target)) in pointer_locations
            .iter()
            .zip([FunctionId(2), FunctionId(3)])
            .enumerate()
        {
            program.code_pointers.insert(
                CodePointerId(id as u32),
                CodePointerModel {
                    id: CodePointerId(id as u32),
                    location: RvaRange::new(location, location + 8).unwrap(),
                    encoding: CodePointerEncoding::Va64,
                    target,
                    provenance: "dir64-relocation",
                },
            );
        }
        program
    }

    #[test]
    fn direct_rip_slot_is_linked_and_complete_but_unrelated_pointer_is_excluded() {
        // call qword ptr [rip + 0x1ffa] => RVA 0x3000
        let program = model(&[0xff, 0x15, 0xfa, 0x1f, 0, 0], &[0x3000, 0x4000]);
        let resolutions = produce(&program, BASE, &[]);
        assert_eq!(resolutions.len(), 1);
        assert_eq!(resolutions[0].target_rvas, BTreeSet::from([0x2000]));
        assert!(resolutions[0].complete);
    }

    #[test]
    fn direct_iat_slot_is_typed_external_without_file_target() {
        let program = model(&[0xff, 0x15, 0xfa, 0x1f, 0, 0], &[]);
        let slots = produce_iat_slots(&program, BASE, RvaRange::new(0x3000, 0x3008).unwrap());
        assert_eq!(slots, vec![(IndirectSiteId(4), BASE + 0x3000)]);
    }

    #[test]
    fn rust_vtable_header_proves_method_slot_targets() {
        // call qword ptr [rax+18h]
        let program = model(&[0xff, 0x50, 0x18], &[0x3000, 0x3018]);
        let mut bytes = vec![0u8; 0x20];
        bytes[0..8].copy_from_slice(&(BASE + 0x2000).to_le_bytes());
        bytes[8..16].copy_from_slice(&24u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&8u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&(BASE + 0x2100).to_le_bytes());
        let sections = vec![SectionData {
            name: ".rdata".into(),
            virtual_address: 0x3000,
            virtual_size: bytes.len() as u32,
            characteristics: 0x4000_0040,
            bytes,
        }];
        let bases = discover_rust_vtable_bases(&program, &sections);
        assert_eq!(bases, BTreeSet::from([0x3000]));
        let resolutions = produce_rust_vtable_resolutions(&program, BASE, &bases);
        assert_eq!(resolutions.len(), 1);
        assert_eq!(resolutions[0].target_rvas, BTreeSet::from([0x2100]));
        assert!(resolutions[0].complete);
    }

    #[test]
    fn rust_drop_prefix_requires_size_and_alignment_slots() {
        let bytes = [
            0x48, 0x8b, 0x02, // mov rax,[rdx]
            0x48, 0x85, 0xc0, // test rax,rax
            0xff, 0xd0, // call rax
            0x48, 0x8b, 0x51, 0x08, // mov rdx,[rcx+8]
            0x4c, 0x8b, 0x41, 0x10, // mov r8,[rcx+10h]
        ];
        let mut decoder = Decoder::with_ip(64, &bytes, BASE + 0x1000, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            instructions.push(decoder.decode());
        }
        let mut program = ProgramModel::default();
        program.blocks.insert(
            BlockId(1),
            BlockModel {
                id: BlockId(1),
                function_id: FunctionId(1),
                range: RvaRange::new(0x1000, 0x1000 + bytes.len() as u32).unwrap(),
                instructions,
                byte_class: ByteClass::Instruction,
            },
        );
        assert!(has_rust_drop_layout_prefix(
            &program,
            FunctionId(1),
            0x1006,
            Register::RAX,
            BASE,
        ));
        program.blocks.get_mut(&BlockId(1)).unwrap().instructions.pop();
        assert!(!has_rust_drop_layout_prefix(
            &program,
            FunctionId(1),
            0x1006,
            Register::RAX,
            BASE,
        ));
    }

    #[test]
    fn indexed_table_needs_proven_extent_and_all_slots_for_complete() {
        // call qword ptr [rax*8 + image_base+0x3000]
        let mut bytes = vec![0xff, 0x14, 0xc5];
        bytes.extend_from_slice(&(BASE + 0x3000).to_le_bytes()[..4]);
        let program = model(&bytes, &[0x3000, 0x3008]);
        assert!(produce(&program, BASE, &[]).is_empty());
        let partial = produce(
            &program,
            BASE,
            &[ProvenPointerTable {
                table: RvaRange::new(0x3000, 0x3010).unwrap(),
                entry_width: 8,
                extent_proven: false,
                provenance: TargetProvenance::Vtable,
            }],
        );
        assert_eq!(partial.len(), 1);
        assert!(!partial[0].complete);
        let complete = produce(
            &program,
            BASE,
            &[ProvenPointerTable {
                table: RvaRange::new(0x3000, 0x3010).unwrap(),
                entry_width: 8,
                extent_proven: true,
                provenance: TargetProvenance::Vtable,
            }],
        );
        assert!(complete[0].complete);
    }

    #[test]
    fn proven_extent_with_a_hole_remains_partial() {
        let mut bytes = vec![0xff, 0x14, 0xc5];
        bytes.extend_from_slice(&(BASE + 0x3000).to_le_bytes()[..4]);
        let program = model(&bytes, &[0x3000]);
        let result = produce(
            &program,
            BASE,
            &[ProvenPointerTable {
                table: RvaRange::new(0x3000, 0x3010).unwrap(),
                entry_width: 8,
                extent_proven: true,
                provenance: TargetProvenance::PointerTable,
            }],
        );
        assert_eq!(result.len(), 1);
        assert!(!result[0].complete);
    }
}
