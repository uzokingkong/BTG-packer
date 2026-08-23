//! Conservative indirect-call target production from canonical code pointers.
//!
//! A code pointer is not, by itself, evidence for any particular indirect
//! site.  This pass only associates pointers with a site when the site's
//! memory operand names the slot/table.  Indexed tables require an externally
//! proven extent; a contiguous run of relocations is deliberately not treated
//! as a bound.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{OpKind, Register};

use super::indirect_resolver::IndirectResolution;
use super::indirect_targets::{IndirectKind, TargetProvenance};
use super::program_model::{CodePointerEncoding, ProgramModel, RvaRange};

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
        .filter(|site| site.kind == IndirectKind::Call)
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
    use crate::analysis::indirect_targets::IndirectSiteId;
    use crate::analysis::indirect_targets::{IndirectSite, ResolutionStatus, TargetSet};
    use crate::analysis::program_model::{
        BlockId, BlockModel, ByteClass, CodePointerId, CodePointerModel, FunctionId, FunctionModel,
        FunctionProvenance,
    };
    use iced_x86::{Decoder, DecoderOptions};

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
