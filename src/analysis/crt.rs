//! Conservative discovery of PE CRT initializer and callback pointer arrays.
//!
//! Named `.CRT$X*` contributions are compiler-defined tables.  Anonymous
//! MSVC/Rust arrays are accepted only when every pointer slot has DIR64
//! relocation provenance, which avoids treating arbitrary constants as code
//! pointers.

use crate::pe::builder::SectionData;
use crate::pe::parser::ExecutableSection;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrtTableKind {
    CInitializer,
    CxxInitializer,
    PreTerminator,
    Terminator,
    RelocationBacked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableTermination {
    Null { slot_rva: u32 },
    SectionEnd,
    NonPointer { slot_rva: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotProvenance {
    Dir64Relocation,
    NamedSection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackSlot {
    pub slot_rva: u32,
    pub target_rva: u32,
    pub provenance: SlotProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackTable {
    pub section_name: String,
    pub table_rva: u32,
    pub kind: CrtTableKind,
    pub slots: Vec<CallbackSlot>,
    pub termination: TableTermination,
}

pub fn discover_callback_tables(
    image_base: u64,
    sections: &[SectionData],
    executable: &[ExecutableSection],
    dir64_relocations: &[u32],
) -> Vec<CallbackTable> {
    let reloc: HashSet<u32> = dir64_relocations.iter().copied().collect();
    let mut out = Vec::new();
    for section in sections {
        if let Some(kind) = named_kind(&section.name) {
            if let Some(table) = scan_named(image_base, section, executable, &reloc, kind) {
                out.push(table);
            }
        } else {
            out.extend(scan_relocation_runs(
                image_base, section, executable, &reloc,
            ));
        }
    }
    out
}

fn named_kind(name: &str) -> Option<CrtTableKind> {
    let upper = name.to_ascii_uppercase();
    if upper.starts_with(".CRT$XI") {
        Some(CrtTableKind::CInitializer)
    } else if upper.starts_with(".CRT$XC") {
        Some(CrtTableKind::CxxInitializer)
    } else if upper.starts_with(".CRT$XP") {
        Some(CrtTableKind::PreTerminator)
    } else if upper.starts_with(".CRT$XT") {
        Some(CrtTableKind::Terminator)
    } else {
        None
    }
}

fn scan_named(
    image_base: u64,
    s: &SectionData,
    exec: &[ExecutableSection],
    reloc: &HashSet<u32>,
    kind: CrtTableKind,
) -> Option<CallbackTable> {
    let mut slots = Vec::new();
    let mut termination = TableTermination::SectionEnd;
    for (index, bytes) in s.bytes.chunks_exact(8).enumerate() {
        let Some(slot_rva) = s
            .virtual_address
            .checked_add((index as u32).saturating_mul(8))
        else {
            break;
        };
        let va = u64::from_le_bytes(bytes.try_into().unwrap());
        if va == 0 {
            termination = TableTermination::Null { slot_rva };
            break;
        }
        let Some(target_rva) = va
            .checked_sub(image_base)
            .and_then(|v| u32::try_from(v).ok())
        else {
            termination = TableTermination::NonPointer { slot_rva };
            break;
        };
        if !is_executable(target_rva, exec) {
            termination = TableTermination::NonPointer { slot_rva };
            break;
        }
        slots.push(CallbackSlot {
            slot_rva,
            target_rva,
            provenance: if reloc.contains(&slot_rva) {
                SlotProvenance::Dir64Relocation
            } else {
                SlotProvenance::NamedSection
            },
        });
    }
    (!slots.is_empty()).then(|| CallbackTable {
        section_name: s.name.clone(),
        table_rva: slots[0].slot_rva,
        kind,
        slots,
        termination,
    })
}

fn scan_relocation_runs(
    image_base: u64,
    s: &SectionData,
    exec: &[ExecutableSection],
    reloc: &HashSet<u32>,
) -> Vec<CallbackTable> {
    let mut out = Vec::new();
    let mut index = 0usize;
    while index + 8 <= s.bytes.len() {
        let start = index;
        let mut slots = Vec::new();
        while index + 8 <= s.bytes.len() {
            let Some(slot_rva) = s.virtual_address.checked_add(index as u32) else {
                break;
            };
            if !reloc.contains(&slot_rva) {
                break;
            }
            let va = u64::from_le_bytes(s.bytes[index..index + 8].try_into().unwrap());
            let Some(target_rva) = va
                .checked_sub(image_base)
                .and_then(|v| u32::try_from(v).ok())
            else {
                break;
            };
            if !is_executable(target_rva, exec) {
                break;
            }
            slots.push(CallbackSlot {
                slot_rva,
                target_rva,
                provenance: SlotProvenance::Dir64Relocation,
            });
            index += 8;
        }
        if slots.len() >= 2 {
            let next_rva = s.virtual_address.saturating_add(index as u32);
            let termination = if index + 8 <= s.bytes.len() && s.bytes[index..index + 8] == [0; 8] {
                TableTermination::Null { slot_rva: next_rva }
            } else if index + 8 > s.bytes.len() {
                TableTermination::SectionEnd
            } else {
                TableTermination::NonPointer { slot_rva: next_rva }
            };
            out.push(CallbackTable {
                section_name: s.name.clone(),
                table_rva: slots[0].slot_rva,
                kind: CrtTableKind::RelocationBacked,
                slots,
                termination,
            });
        }
        index = if index == start { index + 8 } else { index + 8 };
    }
    out
}

fn is_executable(rva: u32, sections: &[ExecutableSection]) -> bool {
    sections.iter().any(|s| {
        rva >= s.virtual_address
            && rva
                .checked_sub(s.virtual_address)
                .is_some_and(|d| d < s.virtual_size)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn exec() -> Vec<ExecutableSection> {
        vec![ExecutableSection {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x100,
            characteristics: 0x2000_0000,
            bytes: vec![],
        }]
    }
    fn section(name: &str, rva: u32, values: &[u64]) -> SectionData {
        SectionData {
            name: name.into(),
            virtual_address: rva,
            virtual_size: (values.len() * 8) as u32,
            characteristics: 0x4000_0040,
            bytes: values.iter().flat_map(|v| v.to_le_bytes()).collect(),
        }
    }

    #[test]
    fn named_crt_table_records_kind_provenance_and_null() {
        let base = 0x1400_0000_0;
        let tables = discover_callback_tables(
            base,
            &[section(
                ".CRT$XCU",
                0x3000,
                &[base + 0x1010, base + 0x1020, 0],
            )],
            &exec(),
            &[0x3000],
        );
        assert_eq!(tables[0].kind, CrtTableKind::CxxInitializer);
        assert_eq!(
            tables[0].slots[0].provenance,
            SlotProvenance::Dir64Relocation
        );
        assert_eq!(tables[0].slots[1].provenance, SlotProvenance::NamedSection);
        assert_eq!(
            tables[0].termination,
            TableTermination::Null { slot_rva: 0x3010 }
        );
    }

    #[test]
    fn anonymous_array_requires_two_relocated_executable_targets() {
        let base = 0x1400_0000_0;
        let s = section(".rdata", 0x4000, &[base + 0x1010, base + 0x1020, 7]);
        let tables = discover_callback_tables(base, &[s], &exec(), &[0x4000, 0x4008]);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].slots.len(), 2);
        assert_eq!(
            tables[0].termination,
            TableTermination::NonPointer { slot_rva: 0x4010 }
        );
    }

    #[test]
    fn truncated_and_overflowing_sections_are_bounds_safe() {
        let mut s = section(".CRT$XIA", u32::MAX - 3, &[]);
        s.bytes = vec![1, 2, 3, 4, 5, 6, 7];
        assert!(discover_callback_tables(0x1400_0000_0, &[s], &exec(), &[]).is_empty());
    }
}
