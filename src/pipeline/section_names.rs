use crate::cli::SectionNameMode;
use anyhow::{anyhow, bail, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;

const ROLES: [(&str, &str); 6] = [
    (".textb", ".text"),
    (".vstate", ".data"),
    (".vmeta", ".rdat"),
    (".vdata", ".blob"),
    (".vmroute", ".cfg"),
    (".nisland", ".code"),
];

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
        let mut state = match mode {
            SectionNameMode::Semantic => unreachable!(),
            SectionNameMode::Seeded => seed.ok_or_else(|| {
                anyhow!("--section-name-mode seeded requires an explicit --seed")
            })? ^ 0x5345_4354_4E41_4D45,
            SectionNameMode::Random => OsRng.next_u64(),
        };
        let mut used: HashSet<String> = existing_names.into_iter().collect();
        let mut replacements = Vec::with_capacity(ROLES.len());
        for (semantic, prefix) in ROLES {
            let name = loop {
                state = splitmix64(state);
                let width = 8usize.saturating_sub(prefix.len());
                let suffix = format!("{:016X}", state);
                let candidate = format!("{}{}", prefix, &suffix[..width]);
                if candidate.len() <= 8 && used.insert(candidate.clone()) {
                    break candidate;
                }
            };
            replacements.push((semantic.to_string(), name));
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
        for index in 0..section_count {
            let offset = table + index * 40;
            let current = decode_name(&image[offset..offset + 8]);
            if let Some((_, replacement)) = self
                .replacements
                .iter()
                .find(|(semantic, _)| semantic == &current)
            {
                image[offset..offset + 8].fill(0);
                image[offset..offset + replacement.len()].copy_from_slice(replacement.as_bytes());
                rewritten += 1;
            }
        }
        Ok(rewritten)
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
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
        let a = SectionNamePlan::create(SectionNameMode::Seeded, Some(7), Vec::new())
            .unwrap()
            .unwrap();
        let b = SectionNamePlan::create(SectionNameMode::Seeded, Some(7), Vec::new())
            .unwrap()
            .unwrap();
        assert_eq!(a.replacements, b.replacements);
        assert!(a
            .replacements
            .iter()
            .all(|(old, new)| old != new && new.len() <= 8));
    }

    #[test]
    fn seeded_mode_requires_seed() {
        assert!(SectionNamePlan::create(SectionNameMode::Seeded, None, Vec::new()).is_err());
    }
}
