//! Conservative inventory of code pointers stored in loader-mapped data.
//!
//! Absolute VA candidates prefer typed `IMAGE_REL_BASED_DIR64` slots, but
//! fixed-base/relocation-stripped Rust and MSVC images also contain naturally
//! aligned vtable leaf targets without DIR64 records. Those are inventoried as
//! lower-provenance data VAs when they point exactly into executable ranges.
//! RVA candidates do not have relocation evidence, so callers can
//! exclude directory/table ranges whose layouts are already interpreted by a
//! typed PE parser (imports, unwind, TLS, load-config, and similar metadata).

use crate::analysis::program_model::{CodePointerEncoding, RvaRange};
use crate::pe::builder::SectionData;
use std::collections::BTreeSet;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CodePointerProvenance {
    Dir64Relocation,
    DataVa64,
    DataRva32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodePointerSeed {
    pub location: RvaRange,
    pub encoding: CodePointerEncoding,
    pub target_rva: u32,
    pub provenance: CodePointerProvenance,
}

/// Inputs deliberately kept independent of `ProgramModelBuilder`, so the
/// builder can consume this inventory without the scanner mutating the model.
pub struct CodePointerScan<'a> {
    pub image_base: u64,
    pub sections: &'a [SectionData],
    pub executable_ranges: &'a [RvaRange],
    pub dir64_slots: &'a [u32],
    pub protected_metadata: &'a [RvaRange],
}

impl CodePointerScan<'_> {
    pub fn inventory(&self) -> Vec<CodePointerSeed> {
        let mut seeds = Vec::new();
        let dir64_index = self.dir64_slots.iter().copied().collect::<BTreeSet<_>>();
        let non_exec = self
            .sections
            .iter()
            .filter(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0)
            .collect::<Vec<_>>();
        let total_probes = self.dir64_slots.len()
            + non_exec
                .iter()
                .map(|section| section.bytes.len().saturating_sub(7).div_ceil(8))
                .sum::<usize>()
            + non_exec
                .iter()
                .map(|section| section.bytes.len().saturating_sub(3).div_ceil(4))
                .sum::<usize>();
        crate::progress::begin_detail_task(
            "ProgramModel: scanning loader-mapped code pointers",
            total_probes as u64,
            "pointer probes",
        );
        let mut probes = 0u64;
        let mut advance = || {
            probes = probes.saturating_add(1);
            if probes & 0x0fff == 0 || probes == total_probes as u64 {
                crate::progress::set_position(probes);
            }
        };

        // A DIR64 entry is authoritative evidence that this exact slot is an
        // image-base-dependent address. Never heuristically read arbitrary
        // eight-byte data as a VA.
        for &slot in self.dir64_slots {
            advance();
            let Some(slot_end) = slot.checked_add(8) else {
                continue;
            };
            if self.is_protected(slot, 8) {
                continue;
            }
            let Some(value) = self
                .read(slot, 8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            else {
                continue;
            };
            let Some(target) = value
                .checked_sub(self.image_base)
                .and_then(|v| u32::try_from(v).ok())
            else {
                continue;
            };
            if self.is_executable(target) {
                seeds.push(CodePointerSeed {
                    location: RvaRange {
                        start: slot,
                        end: slot_end,
                    },
                    encoding: CodePointerEncoding::Va64,
                    target_rva: target,
                    provenance: CodePointerProvenance::Dir64Relocation,
                });
            }
        }

        // Rust trait/vtable leaves and MSVC callback tables can survive in a
        // fixed-base image without a relocation for every absolute slot. Scan
        // aligned loader-mapped data so these real internal entry points become
        // canonical functions instead of falling through to NX original text.
        for section in &non_exec {
            for offset in (0..section.bytes.len().saturating_sub(7)).step_by(8) {
                advance();
                let Some(location) = section.virtual_address.checked_add(offset as u32) else {
                    break;
                };
                let Some(location_end) = location.checked_add(8) else {
                    continue;
                };
                if self.is_protected(location, 8)
                    || Self::overlaps_dir64(&dir64_index, location, location_end)
                {
                    continue;
                }
                let value =
                    u64::from_le_bytes(section.bytes[offset..offset + 8].try_into().unwrap());
                let Some(target) = value
                    .checked_sub(self.image_base)
                    .and_then(|value| u32::try_from(value).ok())
                else {
                    continue;
                };
                if self.is_executable(target) {
                    seeds.push(CodePointerSeed {
                        location: RvaRange {
                            start: location,
                            end: location_end,
                        },
                        encoding: CodePointerEncoding::Va64,
                        target_rva: target,
                        provenance: CodePointerProvenance::DataVa64,
                    });
                }
            }
        }

        // RVA tables have no base relocations. Restrict the heuristic to
        // naturally aligned, non-executable, file-backed data and let typed
        // metadata parsers reserve their ranges.
        for section in &non_exec {
            for offset in (0..section.bytes.len().saturating_sub(3)).step_by(4) {
                advance();
                let Some(location) = section.virtual_address.checked_add(offset as u32) else {
                    break;
                };
                let Some(location_end) = location.checked_add(4) else {
                    continue;
                };
                if self.is_protected(location, 4)
                    || Self::overlaps_dir64(&dir64_index, location, location_end)
                {
                    continue;
                }
                let target =
                    u32::from_le_bytes(section.bytes[offset..offset + 4].try_into().unwrap());
                if self.is_executable(target) {
                    seeds.push(CodePointerSeed {
                        location: RvaRange {
                            start: location,
                            end: location_end,
                        },
                        encoding: CodePointerEncoding::Rva32,
                        target_rva: target,
                        provenance: CodePointerProvenance::DataRva32,
                    });
                }
            }
        }

        crate::progress::set_position(total_probes as u64);
        crate::progress::finish_task(format!(
            "ProgramModel code-pointer scan complete: {} candidate(s)",
            seeds.len()
        ));
        seeds.sort_by_key(|s| (s.location.start, s.encoding as u8, s.target_rva));
        seeds.dedup_by_key(|s| (s.location.start, s.encoding as u8, s.target_rva));
        seeds
    }

    fn is_executable(&self, rva: u32) -> bool {
        self.executable_ranges
            .iter()
            .any(|r| r.start <= rva && rva < r.end)
    }

    fn is_protected(&self, start: u32, size: u32) -> bool {
        let Some(end) = start.checked_add(size) else {
            return true;
        };
        self.protected_metadata
            .iter()
            .any(|r| start < r.end && r.start < end)
    }

    fn overlaps_dir64(slots: &BTreeSet<u32>, start: u32, end: u32) -> bool {
        // Only relocation slots beginning at most seven bytes before start can
        // overlap an 8-byte DIR64 cell. Indexed lookup avoids scanning every
        // relocation for every 4/8-byte candidate on large images.
        let earliest = start.saturating_sub(7);
        slots.range(earliest..end).any(|&slot| {
            slot.checked_add(8)
                .is_some_and(|slot_end| start < slot_end && slot < end)
        })
    }

    fn read(&self, rva: u32, size: usize) -> Option<&[u8]> {
        self.sections.iter().find_map(|section| {
            let offset = rva.checked_sub(section.virtual_address)? as usize;
            let end = offset.checked_add(size)?;
            section.bytes.get(offset..end)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(bytes: Vec<u8>) -> SectionData {
        SectionData {
            name: ".rdata".into(),
            virtual_address: 0x3000,
            virtual_size: bytes.len() as u32,
            characteristics: 0x4000_0040,
            bytes,
        }
    }

    #[test]
    fn inventories_typed_va_and_unprotected_rva_candidates() {
        let base = 0x1_4000_0000u64;
        let mut bytes = vec![0u8; 24];
        bytes[0..8].copy_from_slice(&(base + 0x1010).to_le_bytes());
        bytes[8..16].copy_from_slice(&(base + 0x1020).to_le_bytes()); // no typed relocation
        bytes[16..20].copy_from_slice(&0x1030u32.to_le_bytes());
        let sections = [data(bytes)];
        let seeds = CodePointerScan {
            image_base: base,
            sections: &sections,
            executable_ranges: &[RvaRange {
                start: 0x1000,
                end: 0x1100,
            }],
            dir64_slots: &[0x3000],
            protected_metadata: &[],
        }
        .inventory();
        assert!(seeds
            .iter()
            .any(|s| s.location.start == 0x3000 && s.encoding == CodePointerEncoding::Va64));
        assert!(seeds
            .iter()
            .any(|s| s.location.start == 0x3010 && s.encoding == CodePointerEncoding::Rva32));
        assert!(seeds
            .iter()
            .any(|s| s.location.start == 0x3008 && s.encoding == CodePointerEncoding::Va64));
    }

    #[test]
    fn rejects_protected_truncated_overflow_and_non_executable_values() {
        let base = u64::MAX - 0x10;
        let mut bytes = vec![0u8; 12];
        bytes[0..4].copy_from_slice(&0x1004u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0x9000u32.to_le_bytes());
        let sections = [data(bytes)];
        let seeds = CodePointerScan {
            image_base: base,
            sections: &sections,
            executable_ranges: &[RvaRange {
                start: 0x1000,
                end: 0x1100,
            }],
            dir64_slots: &[0x3008, u32::MAX],
            protected_metadata: &[RvaRange {
                start: 0x3000,
                end: 0x3004,
            }],
        }
        .inventory();
        assert!(seeds.is_empty());
    }
}
