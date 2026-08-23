// ==============================================================================
// BTG Pipeline - Stealth Metadata & String Stripping (Pillar 1)
// ==============================================================================
// Source paths in loadable data may only be rewritten when a preceding ownership
// analysis identifies the exact literal object and byte range. Pattern scanning
// alone is intentionally a no-op: it cannot distinguish metadata from live data.
// ==============================================================================

use crate::pe::builder::SectionData;

const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const REPLACEMENT_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Proof supplied by the object-ownership pass for one literal object.
///
/// Zero is reserved so an omitted/default object identity cannot accidentally
/// authorize a rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePathOwnership {
    object_id: u64,
}

impl SourcePathOwnership {
    pub fn vm_object(object_id: u64) -> Option<Self> {
        (object_id != 0).then_some(Self { object_id })
    }
}

/// Exact section-local range owned by a previously classified literal object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnedSourcePathRange {
    pub section_index: usize,
    pub offset: usize,
    pub len: usize,
    pub ownership: SourcePathOwnership,
}

impl OwnedSourcePathRange {
    pub fn new(
        section_index: usize,
        offset: usize,
        len: usize,
        ownership: SourcePathOwnership,
    ) -> Self {
        Self {
            section_index,
            offset,
            len,
            ownership,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcePathRejection {
    InvalidBounds,
    InvalidSectionCharacteristics,
    OverlappingRange,
    NotRecognizedSourcePath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcePathRangeResult {
    Replaced,
    Rejected(SourcePathRejection),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SourcePathSanitizeReport {
    pub results: Vec<SourcePathRangeResult>,
    pub replaced_ranges: usize,
    pub replaced_bytes: usize,
}

pub struct RdataMetadataStripper;

impl RdataMetadataStripper {
    /// Returns without modifying loadable section data.
    ///
    /// A byte-pattern scan cannot establish that an `RSDS` occurrence belongs to
    /// the PE debug directory. Likewise, a path-looking byte run can be a live
    /// constant, vtable-adjacent data, or TLS initialization data. Callers that
    /// have object ownership must use [`Self::sanitize_owned_source_paths`].
    pub fn sanitize_sections(sections: &mut [SectionData], _seed: u64) -> usize {
        let _ = sections;
        0
    }

    /// Replaces only caller-owned, exact source-path ranges with deterministic,
    /// printable, length-preserving pseudonyms.
    ///
    /// Rewrites are restricted to readable, non-executable initialized-data
    /// sections. Invalid, overlapping, and non-path ranges are left byte-exact.
    pub fn sanitize_owned_source_paths(
        sections: &mut [SectionData],
        ranges: &[OwnedSourcePathRange],
        seed: u64,
    ) -> SourcePathSanitizeReport {
        let mut preflight = Vec::with_capacity(ranges.len());
        let mut validated_ends = vec![None; ranges.len()];
        let range_ends: Vec<Option<usize>> = ranges
            .iter()
            .map(|range| {
                (range.len != 0)
                    .then(|| range.offset.checked_add(range.len))
                    .flatten()
            })
            .collect();

        for (index, range) in ranges.iter().enumerate() {
            let Some(section) = sections.get(range.section_index) else {
                preflight.push(SourcePathRangeResult::Rejected(
                    SourcePathRejection::InvalidBounds,
                ));
                continue;
            };
            let Some(end) = range.offset.checked_add(range.len) else {
                preflight.push(SourcePathRangeResult::Rejected(
                    SourcePathRejection::InvalidBounds,
                ));
                continue;
            };
            let loadable_len = section.bytes.len().min(section.virtual_size as usize);
            if range.len == 0 || end > loadable_len {
                preflight.push(SourcePathRangeResult::Rejected(
                    SourcePathRejection::InvalidBounds,
                ));
                continue;
            }
            if !is_safe_data_section(section.characteristics) {
                preflight.push(SourcePathRangeResult::Rejected(
                    SourcePathRejection::InvalidSectionCharacteristics,
                ));
                continue;
            }

            validated_ends[index] = Some(end);
            preflight.push(SourcePathRangeResult::Rejected(
                SourcePathRejection::NotRecognizedSourcePath,
            ));
        }

        let mut overlaps = vec![false; ranges.len()];
        for left in 0..ranges.len() {
            let Some(left_end) = range_ends[left] else {
                continue;
            };
            for right in (left + 1)..ranges.len() {
                let Some(right_end) = range_ends[right] else {
                    continue;
                };
                if ranges[left].section_index == ranges[right].section_index
                    && ranges[left].offset < right_end
                    && ranges[right].offset < left_end
                {
                    overlaps[left] = true;
                    overlaps[right] = true;
                }
            }
        }

        let mut report = SourcePathSanitizeReport::default();
        for (index, range) in ranges.iter().enumerate() {
            let Some(end) = validated_ends[index] else {
                report.results.push(preflight[index]);
                continue;
            };
            if overlaps[index] {
                report.results.push(SourcePathRangeResult::Rejected(
                    SourcePathRejection::OverlappingRange,
                ));
                continue;
            }

            let source = &sections[range.section_index].bytes[range.offset..end];
            if !is_recognized_source_path(source) {
                report.results.push(SourcePathRangeResult::Rejected(
                    SourcePathRejection::NotRecognizedSourcePath,
                ));
                continue;
            }

            let replacement = deterministic_replacement(range, seed);
            sections[range.section_index].bytes[range.offset..end].copy_from_slice(&replacement);
            report.results.push(SourcePathRangeResult::Replaced);
            report.replaced_ranges += 1;
            report.replaced_bytes += range.len;
        }

        report
    }
}

fn is_safe_data_section(characteristics: u32) -> bool {
    characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
        && characteristics & IMAGE_SCN_MEM_READ != 0
        && characteristics & IMAGE_SCN_MEM_EXECUTE == 0
}

fn is_recognized_source_path(bytes: &[u8]) -> bool {
    if bytes.is_empty() || !bytes.iter().all(|byte| byte.is_ascii_graphic()) {
        return false;
    }
    is_rustc_library_path(bytes) || is_windows_rs_path(bytes)
}

fn is_rustc_library_path(bytes: &[u8]) -> bool {
    let Some(rest) = bytes.strip_prefix(b"/rustc/") else {
        return false;
    };
    let Some(hash_end) = rest.iter().position(|byte| is_path_separator(*byte)) else {
        return false;
    };
    let hash = &rest[..hash_end];
    if !(7..=64).contains(&hash.len()) || !hash.iter().all(u8::is_ascii_hexdigit) {
        return false;
    }

    let library_path = &rest[hash_end + 1..];
    let Some(source_path) = strip_ascii_case_prefix(library_path, b"library") else {
        return false;
    };
    source_path
        .first()
        .is_some_and(|byte| is_path_separator(*byte))
        && has_rs_suffix(&source_path[1..])
}

fn is_windows_rs_path(bytes: &[u8]) -> bool {
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && is_path_separator(bytes[2]);
    let unc_absolute = bytes.starts_with(b"\\\\") && bytes.len() > 2;
    (drive_absolute || unc_absolute)
        && bytes.iter().any(|byte| is_path_separator(*byte))
        && has_rs_suffix(bytes)
}

fn has_rs_suffix(bytes: &[u8]) -> bool {
    bytes.windows(3).enumerate().any(|(offset, extension)| {
        if !extension.eq_ignore_ascii_case(b".rs") {
            return false;
        }
        let path_end = offset + extension.len();
        bytes[..path_end]
            .iter()
            .any(|byte| is_path_separator(*byte))
            && valid_location_suffix(&bytes[path_end..])
    })
}

fn valid_location_suffix(suffix: &[u8]) -> bool {
    suffix.is_empty()
        || suffix.strip_prefix(b":").is_some_and(|line_and_column| {
            !line_and_column.is_empty()
                && line_and_column
                    .split(|byte| *byte == b':')
                    .all(|number| !number.is_empty() && number.iter().all(u8::is_ascii_digit))
        })
}

fn strip_ascii_case_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    (bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then_some(&bytes[prefix.len()..])
}

fn is_path_separator(byte: u8) -> bool {
    matches!(byte, b'/' | b'\\')
}

fn deterministic_replacement(range: &OwnedSourcePathRange, seed: u64) -> Vec<u8> {
    let mut state = seed
        ^ range.ownership.object_id.rotate_left(17)
        ^ (range.section_index as u64).rotate_left(31)
        ^ (range.offset as u64).rotate_left(43)
        ^ (range.len as u64).rotate_left(7);
    let mut output = Vec::with_capacity(range.len);
    for index in 0..range.len {
        state = splitmix64(state ^ index as u64);
        output.push(REPLACEMENT_ALPHABET[(state as usize) % REPLACEMENT_ALPHABET.len()]);
    }
    output
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_section(bytes: Vec<u8>) -> SectionData {
        SectionData {
            name: ".rdata".to_string(),
            virtual_size: bytes.len() as u32,
            virtual_address: 0x1000,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            bytes,
        }
    }

    fn owned(
        section_index: usize,
        offset: usize,
        len: usize,
        object_id: u64,
    ) -> OwnedSourcePathRange {
        OwnedSourcePathRange::new(
            section_index,
            offset,
            len,
            SourcePathOwnership::vm_object(object_id).unwrap(),
        )
    }

    #[test]
    fn unowned_scan_remains_a_noop() {
        let test_bytes =
            b"SomePrefix\0C:\\projects\\rust\\src\\mini_vm.rs:42:10\0RSDS_dummy.pdb\0".to_vec();
        let mut sections = vec![data_section(test_bytes)];
        let original = sections[0].bytes.clone();

        let count = RdataMetadataStripper::sanitize_sections(&mut sections, 0x1337);

        assert_eq!(count, 0);
        assert_eq!(sections[0].bytes, original);
    }

    #[test]
    fn owned_rustc_and_windows_paths_are_replaced_deterministically() {
        let rustc =
            b"/rustc/8bab26f4f68e0e26f0bb7960be334d5b520ea452/library\\alloc\\src\\raw_vec\\mod.rs";
        let windows = b"C:\\projects\\rust\\src\\mini_vm.rs:42:10";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(rustc);
        bytes.push(0);
        let windows_offset = bytes.len();
        bytes.extend_from_slice(windows);
        bytes.push(0);
        let original_len = bytes.len();
        let ranges = [
            owned(0, 0, rustc.len(), 11),
            owned(0, windows_offset, windows.len(), 12),
        ];

        let mut first = vec![data_section(bytes.clone())];
        let mut second = vec![data_section(bytes)];
        let first_report =
            RdataMetadataStripper::sanitize_owned_source_paths(&mut first, &ranges, 0xA55A);
        let second_report =
            RdataMetadataStripper::sanitize_owned_source_paths(&mut second, &ranges, 0xA55A);

        assert_eq!(first_report.replaced_ranges, 2);
        assert_eq!(first_report.replaced_bytes, rustc.len() + windows.len());
        assert_eq!(first_report, second_report);
        assert_eq!(first[0].bytes, second[0].bytes);
        assert_eq!(first[0].bytes.len(), original_len);
        assert_eq!(first[0].bytes[rustc.len()], 0);
        assert_eq!(first[0].bytes[windows_offset + windows.len()], 0);
        let text = String::from_utf8_lossy(&first[0].bytes).to_ascii_lowercase();
        assert!(!text.contains("/rustc/"));
        assert!(!text.contains(".rs"));
        assert!(!text.contains("c:\\"));
    }

    #[test]
    fn overlapping_ranges_are_both_left_untouched() {
        let path = b"C:\\workspace\\crate\\src\\module.rs".to_vec();
        let mut sections = vec![data_section(path.clone())];
        let ranges = [owned(0, 0, path.len(), 1), owned(0, 2, path.len() - 2, 2)];

        let report = RdataMetadataStripper::sanitize_owned_source_paths(&mut sections, &ranges, 7);

        assert_eq!(sections[0].bytes, path);
        assert_eq!(report.replaced_ranges, 0);
        assert_eq!(
            report.results,
            vec![
                SourcePathRangeResult::Rejected(SourcePathRejection::OverlappingRange),
                SourcePathRangeResult::Rejected(SourcePathRejection::OverlappingRange),
            ]
        );
    }

    #[test]
    fn out_of_bounds_overlap_blocks_the_otherwise_valid_rewrite() {
        let path = b"C:\\workspace\\crate\\src\\module.rs".to_vec();
        let mut sections = vec![data_section(path.clone())];
        let ranges = [owned(0, 0, path.len() + 1, 1), owned(0, 0, path.len(), 2)];

        let report = RdataMetadataStripper::sanitize_owned_source_paths(&mut sections, &ranges, 7);

        assert_eq!(sections[0].bytes, path);
        assert_eq!(
            report.results,
            vec![
                SourcePathRangeResult::Rejected(SourcePathRejection::InvalidBounds),
                SourcePathRangeResult::Rejected(SourcePathRejection::OverlappingRange),
            ]
        );
    }

    #[test]
    fn invalid_bounds_section_and_non_path_data_are_untouched() {
        let path = b"C:\\workspace\\crate\\src\\module.rs".to_vec();
        let constant = b"this_is_not_a_source_path".to_vec();
        let mut executable = data_section(path.clone());
        executable.characteristics |= IMAGE_SCN_MEM_EXECUTE;
        let mut unreadable = data_section(path.clone());
        unreadable.characteristics &= !IMAGE_SCN_MEM_READ;
        let mut virtual_truncated = data_section(path.clone());
        virtual_truncated.virtual_size -= 1;
        let mut sections = vec![
            data_section(path.clone()),
            executable,
            unreadable,
            virtual_truncated,
            data_section(constant.clone()),
        ];
        let originals: Vec<Vec<u8>> = sections
            .iter()
            .map(|section| section.bytes.clone())
            .collect();
        let ranges = [
            owned(0, path.len() - 1, 2, 1),
            owned(1, 0, path.len(), 2),
            owned(2, 0, path.len(), 3),
            owned(3, 0, path.len(), 4),
            owned(4, 0, constant.len(), 5),
            owned(99, 0, 1, 6),
        ];

        let report = RdataMetadataStripper::sanitize_owned_source_paths(&mut sections, &ranges, 9);

        assert_eq!(
            sections
                .iter()
                .map(|section| section.bytes.clone())
                .collect::<Vec<_>>(),
            originals
        );
        assert_eq!(
            report.results,
            vec![
                SourcePathRangeResult::Rejected(SourcePathRejection::InvalidBounds),
                SourcePathRangeResult::Rejected(SourcePathRejection::InvalidSectionCharacteristics),
                SourcePathRangeResult::Rejected(SourcePathRejection::InvalidSectionCharacteristics),
                SourcePathRangeResult::Rejected(SourcePathRejection::InvalidBounds),
                SourcePathRangeResult::Rejected(SourcePathRejection::NotRecognizedSourcePath),
                SourcePathRangeResult::Rejected(SourcePathRejection::InvalidBounds),
            ]
        );
    }

    #[test]
    fn ownership_id_and_seed_change_the_pseudonym_without_changing_length() {
        let path = b"D:\\src\\crate\\lib.rs".to_vec();
        let mut first = vec![data_section(path.clone())];
        let mut second = vec![data_section(path.clone())];
        let mut third = vec![data_section(path.clone())];

        RdataMetadataStripper::sanitize_owned_source_paths(
            &mut first,
            &[owned(0, 0, path.len(), 1)],
            100,
        );
        RdataMetadataStripper::sanitize_owned_source_paths(
            &mut second,
            &[owned(0, 0, path.len(), 2)],
            100,
        );
        RdataMetadataStripper::sanitize_owned_source_paths(
            &mut third,
            &[owned(0, 0, path.len(), 1)],
            101,
        );

        assert_ne!(first[0].bytes, path);
        assert_ne!(first[0].bytes, second[0].bytes);
        assert_ne!(first[0].bytes, third[0].bytes);
        assert_eq!(first[0].bytes.len(), path.len());
    }
}
