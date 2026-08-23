//! Typed, bounds-checked switch table resolution.
//!
//! Unlike the VM compatibility resolver, this module does not infer an encoding
//! from instruction shape.  Callers supply the recovered table description and
//! receive targets together with the image ranges that justified every read.

use crate::analysis::program_model::RvaRange;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchEntryEncoding {
    /// Little-endian RVA from the image base.
    Rva32,
    /// Little-endian absolute VA.
    Va64,
    /// Signed displacement from `base_rva`.
    Rel32 { base_rva: u32 },
    /// Unsigned RVA-sized offset from `base_rva`.
    BaseRelative32 { base_rva: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchTableLayout {
    Direct {
        table_rva: u32,
        encoding: SwitchEntryEncoding,
    },
    /// Primary u32 entries select an element in a secondary target table.
    TwoLevel {
        index_table_rva: u32,
        target_table_rva: u32,
        target_encoding: SwitchEntryEncoding,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchSection<'a> {
    pub name: &'a str,
    pub rva: u32,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchReadEvidence {
    pub section_name: String,
    pub location: RvaRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchTarget {
    pub case_value: u32,
    pub target_rva: u32,
    pub reads: Vec<SwitchReadEvidence>,
}

/// Target-set shape suitable for attaching to an indirect jump/call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchTargetSet {
    pub site_rva: u32,
    pub targets: Vec<SwitchTarget>,
    /// True when all requested entries were readable and executable.
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchResolveError {
    AddressOverflow,
    OverlappingSections,
}

pub fn resolve_switch_targets(
    site_rva: u32,
    layout: SwitchTableLayout,
    entry_count: u32,
    image_base: u64,
    sections: &[SwitchSection<'_>],
    executable_ranges: &[RvaRange],
) -> Result<SwitchTargetSet, SwitchResolveError> {
    validate_sections(sections)?;
    let mut targets = Vec::new();
    let mut complete = true;
    for case_value in 0..entry_count {
        let resolved = match layout {
            SwitchTableLayout::Direct {
                table_rva,
                encoding,
            } => read_target(table_rva, case_value, encoding, image_base, sections)
                .map(|(target, read)| (target, vec![read])),
            SwitchTableLayout::TwoLevel {
                index_table_rva,
                target_table_rva,
                target_encoding,
            } => read_u32_at(index_table_rva, case_value, sections).and_then(|(index, first)| {
                read_target(
                    target_table_rva,
                    index,
                    target_encoding,
                    image_base,
                    sections,
                )
                .map(|(target, second)| (target, vec![first, second]))
            }),
        };
        let Some((target_rva, reads)) = resolved else {
            complete = false;
            continue;
        };
        if !executable_ranges
            .iter()
            .any(|range| range.start <= target_rva && target_rva < range.end)
        {
            complete = false;
            continue;
        }
        targets.push(SwitchTarget {
            case_value,
            target_rva,
            reads,
        });
    }
    Ok(SwitchTargetSet {
        site_rva,
        targets,
        complete,
    })
}

fn read_target(
    table_rva: u32,
    index: u32,
    encoding: SwitchEntryEncoding,
    image_base: u64,
    sections: &[SwitchSection<'_>],
) -> Option<(u32, SwitchReadEvidence)> {
    let width = if matches!(encoding, SwitchEntryEncoding::Va64) {
        8
    } else {
        4
    };
    let location = table_rva.checked_add(index.checked_mul(width)?)?;
    let (raw, evidence) = read(location, width, sections)?;
    let target = match encoding {
        SwitchEntryEncoding::Rva32 => u32::from_le_bytes(raw.try_into().ok()?),
        SwitchEntryEncoding::Va64 => {
            let va = u64::from_le_bytes(raw.try_into().ok()?);
            u32::try_from(va.checked_sub(image_base)?).ok()?
        }
        SwitchEntryEncoding::Rel32 { base_rva } => {
            let displacement = i32::from_le_bytes(raw.try_into().ok()?);
            let value = i64::from(base_rva) + i64::from(displacement);
            u32::try_from(value).ok()?
        }
        SwitchEntryEncoding::BaseRelative32 { base_rva } => {
            base_rva.checked_add(u32::from_le_bytes(raw.try_into().ok()?))?
        }
    };
    Some((target, evidence))
}

fn read_u32_at(
    table_rva: u32,
    index: u32,
    sections: &[SwitchSection<'_>],
) -> Option<(u32, SwitchReadEvidence)> {
    let location = table_rva.checked_add(index.checked_mul(4)?)?;
    let (raw, evidence) = read(location, 4, sections)?;
    Some((u32::from_le_bytes(raw.try_into().ok()?), evidence))
}

fn read<'a>(
    rva: u32,
    width: u32,
    sections: &'a [SwitchSection<'a>],
) -> Option<(&'a [u8], SwitchReadEvidence)> {
    let end = rva.checked_add(width)?;
    let section = sections.iter().find(|section| {
        let section_end = section.rva.checked_add(section.bytes.len() as u32);
        section.rva <= rva && section_end.is_some_and(|value| end <= value)
    })?;
    let offset = (rva - section.rva) as usize;
    Some((
        &section.bytes[offset..offset + width as usize],
        SwitchReadEvidence {
            section_name: section.name.to_owned(),
            location: RvaRange { start: rva, end },
        },
    ))
}

fn validate_sections(sections: &[SwitchSection<'_>]) -> Result<(), SwitchResolveError> {
    let mut ranges = sections
        .iter()
        .map(|s| {
            let end = s
                .rva
                .checked_add(
                    u32::try_from(s.bytes.len())
                        .map_err(|_| SwitchResolveError::AddressOverflow)?,
                )
                .ok_or(SwitchResolveError::AddressOverflow)?;
            Ok((s.rva, end))
        })
        .collect::<Result<Vec<_>, SwitchResolveError>>()?;
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[1].0 < pair[0].1) {
        return Err(SwitchResolveError::OverlappingSections);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range() -> Vec<RvaRange> {
        vec![RvaRange {
            start: 0x1000,
            end: 0x2000,
        }]
    }

    #[test]
    fn resolves_all_scalar_encodings_with_read_evidence() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1010u32.to_le_bytes());
        data.extend_from_slice(&0x140001020u64.to_le_bytes());
        data.extend_from_slice(&0x30i32.to_le_bytes());
        data.extend_from_slice(&0x40u32.to_le_bytes());
        let sections = [SwitchSection {
            name: ".rdata",
            rva: 0x3000,
            bytes: &data,
        }];
        let cases = [
            (0x3000, SwitchEntryEncoding::Rva32, 0x1010),
            (0x3004, SwitchEntryEncoding::Va64, 0x1020),
            (
                0x300c,
                SwitchEntryEncoding::Rel32 { base_rva: 0x1000 },
                0x1030,
            ),
            (
                0x3010,
                SwitchEntryEncoding::BaseRelative32 { base_rva: 0x1000 },
                0x1040,
            ),
        ];
        for (table_rva, encoding, expected) in cases {
            let set = resolve_switch_targets(
                0x1100,
                SwitchTableLayout::Direct {
                    table_rva,
                    encoding,
                },
                1,
                0x140000000,
                &sections,
                &range(),
            )
            .unwrap();
            assert!(set.complete);
            assert_eq!(set.targets[0].target_rva, expected);
            assert_eq!(set.targets[0].reads[0].section_name, ".rdata");
        }
    }

    #[test]
    fn resolves_two_level_table_and_marks_partial_sets() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0x1010u32.to_le_bytes());
        data.extend_from_slice(&0x1020u32.to_le_bytes());
        let sections = [SwitchSection {
            name: ".rdata",
            rva: 0x3000,
            bytes: &data,
        }];
        let set = resolve_switch_targets(
            0x1100,
            SwitchTableLayout::TwoLevel {
                index_table_rva: 0x3000,
                target_table_rva: 0x3008,
                target_encoding: SwitchEntryEncoding::Rva32,
            },
            3,
            0x140000000,
            &sections,
            &range(),
        )
        .unwrap();
        assert!(!set.complete);
        assert_eq!(
            set.targets.iter().map(|t| t.target_rva).collect::<Vec<_>>(),
            vec![0x1020, 0x1010]
        );
        assert_eq!(set.targets[0].reads.len(), 2);
    }

    #[test]
    fn rejects_overlapping_section_authority() {
        let a = [0u8; 8];
        let sections = [
            SwitchSection {
                name: "a",
                rva: 0x3000,
                bytes: &a,
            },
            SwitchSection {
                name: "b",
                rva: 0x3004,
                bytes: &a,
            },
        ];
        assert_eq!(
            resolve_switch_targets(
                0,
                SwitchTableLayout::Direct {
                    table_rva: 0x3000,
                    encoding: SwitchEntryEncoding::Rva32
                },
                1,
                0,
                &sections,
                &range()
            ),
            Err(SwitchResolveError::OverlappingSections)
        );
    }
}
