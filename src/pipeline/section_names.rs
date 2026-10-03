use crate::cli::SectionNameMode;
use anyhow::{anyhow, bail, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashSet;

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Debug, Clone)]
pub struct SectionNamePlan {
    replacements: Vec<(String, String)>,
}

impl SectionNamePlan {
    pub fn create(
        mode: SectionNameMode,
        seed: Option<u64>,
        existing_names: impl IntoIterator<Item = String>,
    ) -> Result<Option<Self>> {
        if mode == SectionNameMode::Semantic {
            return Ok(None);
        }
        let mut rng = match mode {
            SectionNameMode::Semantic => unreachable!(),
            SectionNameMode::Seeded => StdRng::seed_from_u64(
                seed.ok_or_else(|| {
                    anyhow!("--section-name-mode seeded requires an explicit --seed")
                })? ^ 0x5345_4354_4E41_4D45,
            ),
            SectionNameMode::Random => StdRng::from_entropy(),
        };
        let mut originals: Vec<_> = existing_names.into_iter().collect();
        let mut used: HashSet<String> = originals.iter().cloned().collect();
        originals.sort_unstable();
        let mut replacements = Vec::with_capacity(originals.len());
        for semantic in originals {
            let name = loop {
                let candidate: String = (0..8)
                    .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
                    .collect();
                if used.insert(candidate.clone()) {
                    break candidate;
                }
            };
            replacements.push((semantic, name));
        }
        Ok(Some(Self { replacements }))
    }

    pub fn rewrite_pe_headers(&self, image: &mut [u8]) -> Result<usize> {
        if image.len() < 0x40 || &image[..2] != b"MZ" {
            bail!("section-name rewrite: missing DOS header");
        }
        let pe = read_u32(image, 0x3c)? as usize;
        if pe.checked_add(24).is_none_or(|end| end > image.len())
            || image.get(pe..pe + 4) != Some(b"PE\0\0")
        {
            bail!("section-name rewrite: invalid PE header");
        }
        let section_count = read_u16(image, pe + 6)? as usize;
        let optional_size = read_u16(image, pe + 20)? as usize;
        let table = pe
            .checked_add(24)
            .and_then(|value| value.checked_add(optional_size))
            .ok_or_else(|| anyhow!("section-name rewrite: section table overflow"))?;
        let table_end = table
            .checked_add(section_count.saturating_mul(40))
            .ok_or_else(|| anyhow!("section-name rewrite: section table overflow"))?;
        if table_end > image.len() {
            bail!("section-name rewrite: truncated section table");
        }

        let mut rewritten = 0usize;
        let mut consumed = vec![false; self.replacements.len()];
        for index in 0..section_count {
            let offset = table + index * 40;
            let current = decode_name(&image[offset..offset + 8]);
            if let Some((replacement_index, (_, replacement))) = self
                .replacements
                .iter()
                .enumerate()
                .find(|(i, (semantic, _))| !consumed[*i] && semantic == &current)
            {
                image[offset..offset + 8].fill(0);
                image[offset..offset + replacement.len()].copy_from_slice(replacement.as_bytes());
                rewritten += 1;
                consumed[replacement_index] = true;
            }
        }
        Ok(rewritten)
    }
}

fn decode_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("section-name rewrite: truncated u16"))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow!("section-name rewrite: truncated u32"))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_plan_is_reproducible_and_opaque() {
        let originals = vec![
            ".text".into(),
            ".rdata".into(),
            ".textb".into(),
            ".vstate".into(),
        ];
        let a = SectionNamePlan::create(SectionNameMode::Seeded, Some(7), originals.clone())
            .unwrap()
            .unwrap();
        let b = SectionNamePlan::create(SectionNameMode::Seeded, Some(7), originals)
            .unwrap()
            .unwrap();
        assert_eq!(a.replacements, b.replacements);
        assert!(a.replacements.iter().all(|(old, new)| old != new
            && new.len() == 8
            && new.bytes().all(|b| b.is_ascii_alphanumeric())));
        assert_eq!(a.replacements.len(), 4);
        assert_eq!(
            a.replacements
                .iter()
                .map(|(_, name)| name)
                .collect::<HashSet<_>>()
                .len(),
            4
        );
    }

    #[test]
    fn seeded_mode_requires_seed() {
        assert!(SectionNamePlan::create(SectionNameMode::Seeded, None, Vec::new()).is_err());
    }

    #[test]
    fn all_headers_are_renamed_without_changing_other_bytes() {
        let mut image = vec![0x55; 512];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&0u16.to_le_bytes());
        for offset in [0x98, 0xc0] {
            image[offset..offset + 8].fill(0);
            image[offset..offset + 5].copy_from_slice(b".text");
        }
        let before = image.clone();
        let plan = SectionNamePlan::create(
            SectionNameMode::Seeded,
            Some(2),
            vec![".text".into(), ".text".into()],
        )
        .unwrap()
        .unwrap();
        assert_eq!(plan.rewrite_pe_headers(&mut image).unwrap(), 2);
        assert_ne!(&image[0x98..0xa0], &image[0xc0..0xc8]);
        for index in 0..image.len() {
            if !(0x98..0xa0).contains(&index) && !(0xc0..0xc8).contains(&index) {
                assert_eq!(image[index], before[index]);
            }
        }
    }
}
