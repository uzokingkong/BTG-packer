//! Read-only auditing, intentionally separate from release artifact export.
use super::literal_catalog::{CatalogSummary, LiteralCatalog};
use super::literal_map::{LiteralMap, MAX_MAP_BYTES};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Build inputs are captured once, before logging/cache/output mutation.
/// Expected hashes cover owned terminators as well as payload bytes.
pub struct LiteralBuildInput {
    input: Vec<u8>,
    catalog: LiteralCatalog,
    map_identity: [u8; 32],
    payload_hashes: BTreeMap<u64, [u8; 32]>,
}
impl LiteralBuildInput {
    pub fn read(input_path: &Path, map_path: &Path) -> Result<Self> {
        let json = read_map_json(map_path)?;
        let map = LiteralMap::from_json(&json)?;
        let input = std::fs::read(input_path).context("cannot read literal build input")?;
        let catalog = map.validate(&input)?;
        let pe = goblin::pe::PE::parse(&input).context("cannot map literal build input")?;
        let mut payload_hashes = BTreeMap::new();
        for entry in catalog.entries() {
            let span = &entry.span;
            let section = pe
                .sections
                .iter()
                .find(|section| {
                    let start = u64::from(span.rva);
                    let end = start + u64::from(span.byte_len) + u64::from(span.terminator_len);
                    let base = u64::from(section.virtual_address);
                    start >= base
                        && end
                            <= base
                                + u64::from(section.virtual_size)
                                    .min(u64::from(section.size_of_raw_data))
                })
                .context("validated literal source ownership disappeared")?;
            let offset = section.pointer_to_raw_data as usize
                + (span.rva - section.virtual_address) as usize;
            let len = span.byte_len as usize + span.terminator_len as usize;
            payload_hashes.insert(span.id, Sha256::digest(&input[offset..offset + len]).into());
        }
        Ok(Self {
            input,
            catalog,
            map_identity: Sha256::digest(json).into(),
            payload_hashes,
        })
    }
    pub fn take_input(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.input)
    }
    pub fn catalog(&self) -> &LiteralCatalog {
        &self.catalog
    }
    pub fn map_identity(&self) -> [u8; 32] {
        self.map_identity
    }
    pub fn payload_hashes(&self) -> &BTreeMap<u64, [u8; 32]> {
        &self.payload_hashes
    }
}

#[derive(Debug)]
pub struct AuditResult {
    catalog: LiteralCatalog,
}

impl AuditResult {
    pub fn into_catalog(self) -> LiteralCatalog {
        self.catalog
    }
    pub fn summary(&self) -> CatalogSummary {
        self.catalog.summary()
    }

    /// No RVAs, IDs, text, paths, or private map contents in public output.
    pub fn public_summary(&self) -> String {
        let s = self.summary();
        format!("literal audit (map-declared objects only): candidates={} eligible={} excluded={} require_annotation={}; encrypted=0; access phases are declarations, not verified references",
            s.candidates, s.eligible, s.excluded, s.require_annotation)
    }
}

pub fn audit_bytes(input: &[u8], map_json: &[u8]) -> Result<AuditResult> {
    let map = LiteralMap::from_json(map_json)?;
    Ok(AuditResult {
        catalog: map.validate(input)?,
    })
}

pub fn audit_files(input_path: &Path, map_path: &Path) -> Result<AuditResult> {
    let json = read_map_json(map_path)?;
    let map = LiteralMap::from_json(&json)?;
    let input = std::fs::read(input_path).context("cannot read literal audit input")?;
    Ok(AuditResult {
        catalog: map.validate(&input)?,
    })
}

pub(crate) fn read_map_json(map_path: &Path) -> Result<Vec<u8>> {
    // Bounded read also protects against a file growing after metadata lookup.
    let map_file = File::open(map_path).context("cannot open private literal map")?;
    let mut json = Vec::new();
    map_file
        .take(MAX_MAP_BYTES as u64 + 1)
        .read_to_end(&mut json)
        .context("cannot read private literal map")?;
    if json.len() > MAX_MAP_BYTES {
        bail!("literal map exceeds size limit");
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn pe_map_audit_is_read_only_and_summary_is_aggregate() {
        let input = crate::pe::generate_dummy_target_pe().unwrap();
        let original = input.clone();
        let hash = format!("{:x}", Sha256::digest(&input));
        let json = format!(r#"{{"schema_version":1,"input_sha256":"{hash}","spans":[]}}"#);
        let audit = audit_bytes(&input, json.as_bytes()).unwrap();
        assert_eq!(input, original);
        assert_eq!(audit.summary().candidates, 0);
        assert!(audit.public_summary().contains("encrypted=0"));
        assert!(!audit.public_summary().contains(&hash));
    }

    #[test]
    fn malformed_private_values_are_not_echoed() {
        let json = br#"{"schema_version":1,"input_sha256":"private-secret-marker","spans":[],"key":"private-secret-marker"}"#;
        let err = audit_bytes(b"", json).unwrap_err().to_string();
        assert!(!err.contains("private-secret-marker"));
    }

    #[test]
    fn mapped_literal_and_exclusion_are_audited_without_mutation() {
        let mut input = crate::pe::generate_dummy_target_pe().unwrap();
        let pe = goblin::pe::PE::parse(&input).unwrap();
        let rva = pe.sections[0].virtual_address;
        let offset = pe.sections[0].pointer_to_raw_data as usize;
        input[offset..offset + 4].copy_from_slice(b"abc\0");
        let hash = format!("{:x}", Sha256::digest(&input));
        let original = input.clone();
        let json = |rva: u32, phase: &str| {
            format!(
                r#"{{"schema_version":1,"input_sha256":"{hash}","spans":[{{"id":1,"rva":{rva},"byte_len":3,"terminator_len":1,"encoding":"ascii","access_phase":"{phase}"}}]}}"#
            )
        };
        let approved = audit_bytes(&input, json(rva, "post_boot").as_bytes()).unwrap();
        assert_eq!(approved.summary().eligible, 1);
        let excluded = audit_bytes(&input, json(rva, "pre_boot_tls").as_bytes()).unwrap();
        assert_eq!(excluded.summary().excluded, 1);
        assert_eq!(excluded.summary().eligible, 0);
        assert!(audit_bytes(&input, json(u32::MAX - 1, "post_boot").as_bytes()).is_err());
        assert!(audit_bytes(&input, json(1, "post_boot").as_bytes()).is_err());
        assert_eq!(input, original);
    }
}
