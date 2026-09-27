//! Attacker-oriented exposure measurements for generated VM artifacts.
//!
//! This module is intentionally read-only.  It recognizes simple structures an
//! offline extractor can reuse and turns them into release-gate metrics.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Register};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VmExposureReport {
    pub semantic_anchor_hits: usize,
    pub pointer_table_candidates: usize,
    pub recoverable_handler_entries: usize,
    pub state_offset_peak_frequency: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    fn contains(self, value: u64) -> bool {
        self.start <= value && value < self.end
    }
}

const SEMANTIC_ANCHORS: &[&[u8]] = &[
    b".vstate",
    b".vmeta",
    b".vmroute",
    b".nisland",
    b"FINAL CHECKSUM",
];

pub fn measure(
    image: &[u8],
    executable_va_ranges: &[AddressRange],
    observed_state_displacements: &[i64],
) -> VmExposureReport {
    let semantic_anchor_hits = SEMANTIC_ANCHORS
        .iter()
        .map(|anchor| count_occurrences(image, anchor))
        .sum();
    let (pointer_table_candidates, recoverable_handler_entries) =
        pointer_table_exposure(image, executable_va_ranges, 16);
    let mut histogram = BTreeMap::<i64, usize>::new();
    for &displacement in observed_state_displacements {
        *histogram.entry(displacement).or_default() += 1;
    }
    VmExposureReport {
        semantic_anchor_hits,
        pointer_table_candidates,
        recoverable_handler_entries,
        state_offset_peak_frequency: histogram.values().copied().max().unwrap_or(0),
    }
}

/// Measure a final PE using only information available to an offline analyst.
pub fn measure_pe(image: &[u8]) -> Result<VmExposureReport> {
    let pe = PE::parse(image).map_err(|error| anyhow!("VM exposure PE parse failed: {error}"))?;
    let image_base = pe.image_base as u64;
    let mut executable_ranges = Vec::new();
    let mut displacements = Vec::new();
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = image_base + section.virtual_address as u64;
        executable_ranges.push(AddressRange {
            start,
            end: start + section.virtual_size.max(section.size_of_raw_data) as u64,
        });
        let raw_start = section.pointer_to_raw_data as usize;
        let raw_end = raw_start
            .saturating_add(section.size_of_raw_data as usize)
            .min(image.len());
        if raw_start >= raw_end {
            continue;
        }
        let mut decoder =
            Decoder::with_ip(64, &image[raw_start..raw_end], start, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                continue;
            }
            if instruction.memory_base() != Register::None
                || instruction.memory_index() != Register::None
            {
                let displacement = instruction.memory_displacement64();
                if (8..=0x1_0000).contains(&displacement) {
                    displacements.push(displacement as i64);
                }
            }
        }
    }
    Ok(measure(image, &executable_ranges, &displacements))
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn pointer_table_exposure(
    image: &[u8],
    executable_va_ranges: &[AddressRange],
    minimum_run: usize,
) -> (usize, usize) {
    let mut candidates = 0usize;
    let mut recoverable = 0usize;
    let mut run = 0usize;
    for chunk in image.chunks_exact(8) {
        let value = u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"));
        if executable_va_ranges
            .iter()
            .copied()
            .any(|range| range.contains(value))
        {
            run += 1;
        } else {
            if run >= minimum_run {
                candidates += 1;
                recoverable += run;
            }
            run = 0;
        }
    }
    if run >= minimum_run {
        candidates += 1;
        recoverable += run;
    }
    (candidates, recoverable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_plain_handler_pointer_run_and_semantic_anchor() {
        let mut image = b"prefix.vstate\0".to_vec();
        while image.len() % 8 != 0 {
            image.push(0);
        }
        for i in 0..32u64 {
            image.extend_from_slice(&(0x1400_1000 + i * 8).to_le_bytes());
        }
        let report = measure(
            &image,
            &[AddressRange {
                start: 0x1400_0000,
                end: 0x1401_0000,
            }],
            &[0x5000, 0x5000, 0x5010],
        );
        assert_eq!(report.semantic_anchor_hits, 1);
        assert_eq!(report.pointer_table_candidates, 1);
        assert_eq!(report.recoverable_handler_entries, 32);
        assert_eq!(report.state_offset_peak_frequency, 2);
    }

    #[test]
    fn masked_values_do_not_look_like_executable_pointer_table() {
        let image = [0xA5u8; 256];
        let report = measure(
            &image,
            &[AddressRange {
                start: 0x1400_0000,
                end: 0x1401_0000,
            }],
            &[],
        );
        assert_eq!(report.pointer_table_candidates, 0);
        assert_eq!(report.recoverable_handler_entries, 0);
    }
}
