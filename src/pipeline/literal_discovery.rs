//! Heuristic discovery, separate from the disjoint, explicitly declared map.
//! Candidates may overlap and are NEVER approved for encryption by this API.
use super::literal_catalog::Encoding;
use super::literal_metadata::MetadataIndex;
use anyhow::{bail, Context, Result};
use goblin::pe::PE;

const MAX_CANDIDATES: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateDecision {
    ExcludeLoader,
    ExcludeResourceSection,
    RequireAnnotation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub rva: u32,
    pub byte_len: u32,
    pub terminator_len: u8,
    pub encoding: Encoding,
    pub decision: CandidateDecision,
    /// Connected overlap group, not a count of all pairwise intersections.
    pub ambiguous: bool,
}

impl Candidate {
    fn end(&self) -> u64 {
        u64::from(self.rva) + u64::from(self.byte_len) + u64::from(self.terminator_len)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct DiscoverySummary {
    pub candidates: usize,
    pub ascii: usize,
    pub utf8: usize,
    pub utf16: usize,
    pub excluded_loader: usize,
    pub excluded_resource: usize,
    pub require_annotation: usize,
    pub ambiguous: usize,
    pub unterminated: usize,
}

#[derive(Debug, Default)]
pub struct CandidateCatalog {
    candidates: Vec<Candidate>,
}

impl CandidateCatalog {
    /// Private address inventory; do not export this into a release package.
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    pub fn summary(&self) -> DiscoverySummary {
        let mut s = DiscoverySummary::default();
        for c in &self.candidates {
            s.candidates += 1;
            match c.encoding {
                Encoding::Ascii => s.ascii += 1,
                Encoding::Utf8 => s.utf8 += 1,
                Encoding::Utf16Le => s.utf16 += 1,
            }
            match c.decision {
                CandidateDecision::ExcludeLoader => s.excluded_loader += 1,
                CandidateDecision::ExcludeResourceSection => s.excluded_resource += 1,
                CandidateDecision::RequireAnnotation => s.require_annotation += 1,
            }
            s.ambiguous += usize::from(c.ambiguous);
            s.unterminated += usize::from(c.terminator_len == 0);
        }
        s
    }

    pub fn public_summary(&self) -> String {
        let s = self.summary();
        format!("literal candidate catalog (readable non-executable sections only): candidates={} ascii={} utf8={} utf16={} excluded_loader={} excluded_resource={} require_annotation={} ambiguous={} unterminated={}; eligible=0 encrypted=0; heuristic candidates are not verified literals",
            s.candidates, s.ascii, s.utf8, s.utf16, s.excluded_loader, s.excluded_resource, s.require_annotation, s.ambiguous, s.unterminated)
    }
}

pub fn discover(input: &[u8]) -> Result<CandidateCatalog> {
    discover_with_limit(input, MAX_CANDIDATES)
}

fn discover_with_limit(input: &[u8], limit: usize) -> Result<CandidateCatalog> {
    let pe =
        PE::parse(input).map_err(|_| anyhow::anyhow!("literal discovery requires a valid PE"))?;
    let metadata = MetadataIndex::build(input, &pe)
        .map_err(|_| anyhow::anyhow!("cannot establish loader ownership for literal discovery"))?;
    let resource = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|h| h.data_directories.data_directories.get(2))
        .and_then(|d| d.as_ref())
        .filter(|(_, d)| d.size != 0)
        .map(|(_, d)| u64::from(d.virtual_address));
    let mut sections = Vec::new();
    for section in &pe.sections {
        if section.characteristics & 0x4000_0000 == 0 || section.characteristics & 0x2000_0000 != 0
        {
            continue;
        }
        let len = u64::from(section.virtual_size).min(u64::from(section.size_of_raw_data));
        if len == 0 {
            continue;
        }
        let base = u64::from(section.virtual_address);
        let end = base + len;
        if end > u64::from(u32::MAX) + 1 {
            bail!("literal discovery section RVA overflow");
        }
        let raw = section.pointer_to_raw_data as usize;
        let raw_end = raw
            .checked_add(len as usize)
            .context("literal discovery file span overflow")?;
        let bytes = input
            .get(raw..raw_end)
            .context("literal discovery section exceeds file")?;
        sections.push((
            base,
            end,
            bytes,
            resource.is_some_and(|r| r >= base && r < end),
        ));
    }
    sections.sort_by_key(|(base, _, _, _)| *base);
    for pair in sections.windows(2) {
        if pair[0].1 > pair[1].0 {
            bail!("overlapping literal discovery section ranges");
        }
    }
    let mut catalog = CandidateCatalog::default();
    for (base, _, bytes, resource_section) in sections {
        let mut emit = |offset: usize, length: usize, terminator: u8, encoding| -> Result<()> {
            if length == 0 {
                return Ok(());
            }
            if catalog.candidates.len() >= limit {
                bail!("literal candidate limit exceeded; discovery incomplete");
            }
            let start = base + offset as u64;
            let end = start + length as u64 + u64::from(terminator);
            let decision = if metadata.overlaps(start, end) {
                CandidateDecision::ExcludeLoader
            } else if resource_section {
                CandidateDecision::ExcludeResourceSection
            } else {
                CandidateDecision::RequireAnnotation
            };
            catalog.candidates.push(Candidate {
                rva: u32::try_from(start)?,
                byte_len: u32::try_from(length)?,
                terminator_len: terminator,
                encoding,
                decision,
                ambiguous: false,
            });
            Ok(())
        };
        scan_utf8(bytes, &mut emit)?;
        scan_utf16(bytes, 0, &mut emit)?;
        scan_utf16(bytes, 1, &mut emit)?;
    }
    catalog.candidates.sort_by_key(|c| {
        (
            c.rva,
            c.byte_len,
            encoding_rank(c.encoding),
            c.terminator_len,
        )
    });
    mark_overlaps(&mut catalog.candidates);
    Ok(catalog)
}

fn encoding_rank(encoding: Encoding) -> u8 {
    match encoding {
        Encoding::Ascii => 0,
        Encoding::Utf8 => 1,
        Encoding::Utf16Le => 2,
    }
}

fn printable(c: char) -> bool {
    !c.is_control() || matches!(c, '\t' | '\n' | '\r')
}

type Emit<'a> = dyn FnMut(usize, usize, u8, Encoding) -> Result<()> + 'a;

fn utf8_scalar(bytes: &[u8], offset: usize) -> Option<(char, usize)> {
    let first = bytes[offset];
    let width = match first {
        0..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let scalar = std::str::from_utf8(bytes.get(offset..offset + width)?)
        .ok()?
        .chars()
        .next()?;
    printable(scalar).then_some((scalar, width))
}

fn scan_utf8(bytes: &[u8], emit: &mut Emit<'_>) -> Result<()> {
    let mut offset = 0;
    let mut start = None;
    let mut ascii = true;
    while offset < bytes.len() {
        if let Some((scalar, width)) = utf8_scalar(bytes, offset) {
            start.get_or_insert(offset);
            ascii &= scalar.is_ascii();
            offset += width;
        } else {
            if let Some(begin) = start.take() {
                emit(
                    begin,
                    offset - begin,
                    u8::from(bytes[offset] == 0),
                    if ascii {
                        Encoding::Ascii
                    } else {
                        Encoding::Utf8
                    },
                )?;
            }
            ascii = true;
            offset += 1;
        }
    }
    if let Some(begin) = start {
        emit(
            begin,
            offset - begin,
            0,
            if ascii {
                Encoding::Ascii
            } else {
                Encoding::Utf8
            },
        )?;
    }
    Ok(())
}

fn utf16_scalar(bytes: &[u8], offset: usize) -> Option<(char, usize)> {
    let first = u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?);
    let (value, width) = if (0xd800..=0xdbff).contains(&first) {
        let second = u16::from_le_bytes(bytes.get(offset + 2..offset + 4)?.try_into().ok()?);
        if !(0xdc00..=0xdfff).contains(&second) {
            return None;
        }
        (
            0x10000 + ((u32::from(first) - 0xd800) << 10) + u32::from(second) - 0xdc00,
            4,
        )
    } else {
        (u32::from(first), 2)
    };
    let scalar = char::from_u32(value)?;
    printable(scalar).then_some((scalar, width))
}

fn scan_utf16(bytes: &[u8], alignment: usize, emit: &mut Emit<'_>) -> Result<()> {
    let mut offset = alignment;
    let mut start = None;
    while offset + 1 < bytes.len() {
        if let Some((_, width)) = utf16_scalar(bytes, offset) {
            start.get_or_insert(offset);
            offset += width;
        } else {
            if let Some(begin) = start.take() {
                let terminator = if bytes[offset] == 0 && bytes[offset + 1] == 0 {
                    2
                } else {
                    0
                };
                emit(begin, offset - begin, terminator, Encoding::Utf16Le)?;
            }
            offset += 2;
        }
    }
    if let Some(begin) = start {
        emit(begin, offset - begin, 0, Encoding::Utf16Le)?;
    }
    Ok(())
}

fn mark_overlaps(candidates: &mut [Candidate]) {
    let mut group = 0;
    while group < candidates.len() {
        let mut end = candidates[group].end();
        let mut next = group + 1;
        while next < candidates.len() && u64::from(candidates[next].rva) < end {
            end = end.max(candidates[next].end());
            next += 1;
        }
        if next - group > 1 {
            for candidate in &mut candidates[group..next] {
                candidate.ambiguous = true;
            }
        }
        group = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runs(bytes: &[u8], wide: bool) -> Vec<(usize, usize, u8, Encoding)> {
        let mut found = Vec::new();
        let mut emit = |offset, length, terminator, encoding| {
            found.push((offset, length, terminator, encoding));
            Ok(())
        };
        if wide {
            scan_utf16(bytes, 0, &mut emit).unwrap();
        } else {
            scan_utf8(bytes, &mut emit).unwrap();
        }
        found
    }

    #[test]
    fn short_ascii_unicode_and_unterminated_runs_are_retained() {
        let bytes = "A\0IOError\0한🙂\0tail".as_bytes();
        assert_eq!(
            runs(bytes, false),
            vec![
                (0, 1, 1, Encoding::Ascii),
                (2, 7, 1, Encoding::Ascii),
                (10, 7, 1, Encoding::Utf8),
                (18, 4, 0, Encoding::Ascii),
            ]
        );
    }

    #[test]
    fn invalid_utf8_does_not_hide_a_following_literal() {
        assert_eq!(
            runs(b"\xff\xc0ab\0\xed\xa0\x80z\0", false),
            vec![(2, 2, 1, Encoding::Ascii), (8, 1, 1, Encoding::Ascii),]
        );
    }

    #[test]
    fn wide_surrogates_are_checked_and_lengths_are_bytes() {
        let mut bytes = Vec::new();
        for unit in "한🙂".encode_utf16().chain([0]) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(runs(&bytes, true), vec![(0, 6, 2, Encoding::Utf16Le)]);
        assert_eq!(
            runs(&[0, 0xd8, b'A', 0, 0, 0], true),
            vec![(2, 2, 2, Encoding::Utf16Le)]
        );
        assert_eq!(
            runs(&[b'A', 0, 0xff], true),
            vec![(0, 2, 0, Encoding::Utf16Le)]
        );
    }

    #[test]
    fn overlap_groups_include_terminators_without_quadratic_pair_search() {
        let c = |rva, len| Candidate {
            rva,
            byte_len: len,
            terminator_len: 1,
            encoding: Encoding::Ascii,
            decision: CandidateDecision::RequireAnnotation,
            ambiguous: false,
        };
        let mut candidates = vec![c(10, 2), c(12, 2), c(14, 2), c(17, 1)];
        mark_overlaps(&mut candidates);
        assert!(candidates[..3].iter().all(|c| c.ambiguous));
        assert!(!candidates[3].ambiguous);
    }

    fn fixture(payload: &[u8], executable: bool) -> Vec<u8> {
        let mut input = crate::pe::generate_dummy_target_pe().unwrap();
        let pe = PE::parse(&input).unwrap();
        let raw = pe.sections[0].pointer_to_raw_data as usize;
        let pe_offset = u32::from_le_bytes(input[0x3c..0x40].try_into().unwrap()) as usize;
        let optional_size =
            u16::from_le_bytes(input[pe_offset + 20..pe_offset + 22].try_into().unwrap()) as usize;
        let section = pe_offset + 24 + optional_size;
        input[section + 8..section + 12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let flags: u32 = if executable { 0x6000_0020 } else { 0x4000_0040 };
        input[section + 36..section + 40].copy_from_slice(&flags.to_le_bytes());
        input[raw..raw + 512].fill(0);
        input[raw..raw + payload.len()].copy_from_slice(payload);
        input
    }

    #[test]
    fn discover_is_deterministic_read_only_and_never_approves() {
        let input = fixture(b"IOError\0A\0", false);
        let original = input.clone();
        let first = discover(&input).unwrap();
        let second = discover(&input).unwrap();
        assert_eq!(first.candidates(), second.candidates());
        assert_eq!(input, original);
        assert!(first
            .candidates()
            .iter()
            .all(|c| c.decision == CandidateDecision::RequireAnnotation));
        assert!(first
            .candidates()
            .iter()
            .any(|c| c.byte_len == 7 && c.encoding == Encoding::Ascii));
        let output = first.public_summary();
        assert!(output.contains("eligible=0 encrypted=0"));
        assert!(!output.contains("IOError"));
        assert_eq!(
            discover(&fixture(b"IOError\0", true))
                .unwrap()
                .summary()
                .candidates,
            0
        );
    }

    #[test]
    fn scanner_keeps_odd_alignment_wide_candidates() {
        let bytes = [0xff, b'A', 0, 0, 0];
        let mut found = Vec::new();
        scan_utf16(&bytes, 1, &mut |offset, len, term, enc| {
            found.push((offset, len, term, enc));
            Ok(())
        })
        .unwrap();
        assert_eq!(found, vec![(1, 2, 2, Encoding::Utf16Le)]);
    }

    #[test]
    fn scanner_survives_arbitrary_small_byte_sequences() {
        for value in 0u16..=u16::MAX {
            let bytes = value.to_le_bytes();
            for wide in [false, true] {
                for (offset, len, term, _) in runs(&bytes, wide) {
                    assert!(len > 0 && offset + len + term as usize <= bytes.len());
                }
            }
        }
    }

    fn directory(input: &mut [u8], number: usize, offset: u32, size: u32) {
        let pe = PE::parse(input).unwrap();
        let rva = pe.sections[0].virtual_address + offset;
        let pe_offset = u32::from_le_bytes(input[0x3c..0x40].try_into().unwrap()) as usize;
        let slot = pe_offset + 24 + 112 + number * 8;
        input[slot..slot + 4].copy_from_slice(&rva.to_le_bytes());
        input[slot + 4..slot + 8].copy_from_slice(&size.to_le_bytes());
    }

    #[test]
    fn tls_template_candidates_are_excluded_as_loader_owned() {
        let mut payload = vec![0u8; 256];
        payload[0x80..0x88].copy_from_slice(b"IOError\0");
        payload[0xb0..0xb5].copy_from_slice(b"tail\0");
        let mut input = fixture(&payload, false);
        let pe = PE::parse(&input).unwrap();
        let base = pe.sections[0].virtual_address;
        let raw = pe.sections[0].pointer_to_raw_data as usize;
        let template = pe.image_base as u64 + u64::from(base) + 0x80;
        input[raw + 0x20..raw + 0x28].copy_from_slice(&template.to_le_bytes());
        input[raw + 0x28..raw + 0x30].copy_from_slice(&(template + 8).to_le_bytes());
        directory(&mut input, 9, 0x20, 40);
        let catalog = discover(&input).unwrap();
        assert!(catalog.candidates().iter().any(|c| c.rva == base + 0x80
            && c.encoding == Encoding::Ascii
            && c.decision == CandidateDecision::ExcludeLoader));
        assert!(catalog.candidates().iter().any(|c| c.rva == base + 0xb0
            && c.encoding == Encoding::Ascii
            && c.decision == CandidateDecision::RequireAnnotation));
    }

    #[test]
    fn resource_section_candidates_are_conservatively_excluded() {
        let mut payload = vec![0u8; 256];
        payload[0x80..0x85].copy_from_slice(b"icon\0");
        let mut input = fixture(&payload, false);
        directory(&mut input, 2, 0x20, 16);
        let catalog = discover(&input).unwrap();
        assert!(catalog
            .candidates()
            .iter()
            .any(|c| c.encoding == Encoding::Ascii
                && c.byte_len == 4
                && c.decision == CandidateDecision::ExcludeResourceSection));
    }

    #[test]
    fn candidate_limit_fails_instead_of_returning_silently_truncated_inventory() {
        let input = fixture(b"A\0B\0C\0", false);
        assert!(discover_with_limit(&input, 2)
            .unwrap_err()
            .to_string()
            .contains("discovery incomplete"));
    }
}
