//! Private JSON map ingestion. No automatic release export.
use super::literal_catalog::{Encoding, Evidence, LiteralCatalog, LiteralSpan};
use anyhow::{bail, Context, Result};
use goblin::pe::PE;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct LiteralMap {
    pub schema_version: u32,
    pub input_sha256: [u8; 32],
    pub spans: Vec<LiteralSpan>,
}

impl LiteralMap {
    /// Strict private JSON schema. Parse errors omit source excerpts so literal
    /// maps or accidental key values cannot leak into public logs.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MAP_BYTES {
            bail!("literal map exceeds size limit");
        }
        let wire: WireMap = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid literal map JSON schema"))?;
        if wire.schema_version != SCHEMA_VERSION {
            bail!("unsupported literal map schema");
        }
        if wire.spans.len() > MAX_MAP_OBJECTS {
            bail!("literal map exceeds object limit");
        }
        let hex = wire.input_sha256.as_bytes();
        if hex.len() != 64 || !hex.iter().all(u8::is_ascii_hexdigit) {
            bail!("literal map SHA-256 must be 64 hexadecimal characters");
        }
        let mut digest = [0u8; 32];
        for (index, pair) in hex.chunks_exact(2).enumerate() {
            let digit = |b: u8| {
                if b <= b'9' {
                    b - b'0'
                } else {
                    b.to_ascii_lowercase() - b'a' + 10
                }
            };
            digest[index] = (digit(pair[0]) << 4) | digit(pair[1]);
        }
        let spans = wire
            .spans
            .into_iter()
            .map(|s| LiteralSpan {
                id: s.id,
                rva: s.rva,
                byte_len: s.byte_len,
                terminator_len: s.terminator_len,
                encoding: match s.encoding {
                    WireEncoding::Ascii => Encoding::Ascii,
                    WireEncoding::Utf8 => Encoding::Utf8,
                    WireEncoding::Utf16Le => Encoding::Utf16Le,
                },
                phase: match s.access_phase {
                    WirePhase::Loader => super::literal_catalog::AccessPhase::Loader,
                    WirePhase::PreBootTls => super::literal_catalog::AccessPhase::PreBootTls,
                    WirePhase::Bootstrap => super::literal_catalog::AccessPhase::Bootstrap,
                    WirePhase::PostBoot => super::literal_catalog::AccessPhase::PostBoot,
                    WirePhase::Unknown => super::literal_catalog::AccessPhase::Unknown,
                },
                evidence: Evidence::ExplicitMap,
            })
            .collect();
        Ok(Self {
            schema_version: wire.schema_version,
            input_sha256: digest,
            spans,
        })
    }

    /// Validate against the original file, never a relocated intermediate PE.
    pub fn validate(&self, input: &[u8]) -> Result<LiteralCatalog> {
        if self.schema_version != SCHEMA_VERSION {
            bail!("unsupported literal map schema");
        }
        let digest: [u8; 32] = Sha256::digest(input).into();
        if digest != self.input_sha256 {
            bail!("literal map input SHA-256 mismatch");
        }
        let catalog = LiteralCatalog::from_spans(self.spans.clone()).map_err(anyhow::Error::msg)?;
        let pe = PE::parse(input).context("literal map requires a valid PE")?;
        let metadata = super::literal_metadata::MetadataIndex::build(input, &pe).map_err(|_| {
            anyhow::anyhow!("cannot establish loader metadata ownership for literal audit")
        })?;
        for entry in catalog.entries() {
            let span = &entry.span;
            if span.evidence != Evidence::ExplicitMap {
                bail!("literal map entry must use explicit-map evidence");
            }
            let start = u64::from(span.rva);
            let end = start + u64::from(span.byte_len) + u64::from(span.terminator_len);
            if metadata.overlaps(start, end) {
                bail!("literal map overlaps loader-owned metadata");
            }
            let matches: Vec<_> = pe
                .sections
                .iter()
                .filter(|section| {
                    let base = u64::from(section.virtual_address);
                    let len =
                        u64::from(section.virtual_size).min(u64::from(section.size_of_raw_data));
                    start >= base && end <= base + len
                })
                .collect();
            if matches.len() != 1 {
                bail!("literal map span is not uniquely file-backed");
            }
            let section = matches[0];
            let offset =
                u64::from(section.pointer_to_raw_data) + start - u64::from(section.virtual_address);
            let length = end - start;
            let offset = usize::try_from(offset).context("literal file offset overflow")?;
            let length = usize::try_from(length).context("literal length overflow")?;
            let file_end = offset
                .checked_add(length)
                .context("literal file span overflow")?;
            let bytes = input
                .get(offset..file_end)
                .context("literal span exceeds input file")?;
            validate_bytes(span, bytes)?;
        }
        Ok(catalog)
    }
}

pub const MAX_MAP_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MAP_OBJECTS: usize = 100_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMap {
    schema_version: u32,
    input_sha256: String,
    spans: Vec<WireSpan>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSpan {
    id: u64,
    rva: u32,
    byte_len: u32,
    terminator_len: u8,
    encoding: WireEncoding,
    access_phase: WirePhase,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireEncoding {
    Ascii,
    Utf8,
    Utf16Le,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WirePhase {
    Loader,
    PreBootTls,
    Bootstrap,
    PostBoot,
    Unknown,
}

fn validate_bytes(span: &LiteralSpan, bytes: &[u8]) -> Result<()> {
    let (payload, terminator) = bytes.split_at(span.byte_len as usize);
    if terminator.iter().any(|b| *b != 0) {
        bail!("literal terminator is not NUL");
    }
    match span.encoding {
        Encoding::Ascii => {
            if !payload.is_ascii() {
                bail!("literal payload is not ASCII");
            }
        }
        Encoding::Utf8 => {
            std::str::from_utf8(payload).context("invalid literal UTF-8")?;
        }
        Encoding::Utf16Le => {
            let units = payload
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]));
            for scalar in char::decode_utf16(units) {
                scalar.context("invalid literal UTF-16 surrogate")?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::literal_catalog::AccessPhase;

    fn literal(encoding: Encoding, byte_len: u32, terminator_len: u8) -> LiteralSpan {
        LiteralSpan {
            id: 1,
            rva: 0,
            byte_len,
            terminator_len,
            encoding,
            phase: AccessPhase::PostBoot,
            evidence: Evidence::ExplicitMap,
        }
    }

    #[test]
    fn json_schema_is_strict_and_does_not_echo_private_data() {
        let hash = "0".repeat(64);
        let json = format!(
            r#"{{"schema_version":1,"input_sha256":"{hash}","spans":[{{"id":9,"rva":4096,"byte_len":3,"terminator_len":0,"encoding":"utf8","access_phase":"post_boot"}}]}}"#
        );
        let map = LiteralMap::from_json(json.as_bytes()).unwrap();
        assert_eq!(map.spans[0].id, 9);
        assert_eq!(map.spans[0].phase, AccessPhase::PostBoot);
        assert_eq!(map.spans[0].evidence, Evidence::ExplicitMap);
        for invalid in [
            json.replace("\"utf8\"", "\"private-secret-marker\""),
            json.replace("\"rva\":4096", "\"rva\":-1"),
            json.replace("\"id\":9", "\"id\":9,\"id\":10"),
            json.replace(
                "\"rva\":4096",
                "\"rva\":4096,\"key\":\"private-secret-marker\"",
            ),
            json.replace("\"access_phase\":\"post_boot\"", "\"phase\":\"post_boot\""),
        ] {
            let err = LiteralMap::from_json(invalid.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(!err.contains("private-secret-marker"));
        }
    }

    #[test]
    fn json_rejects_bad_digest_and_oversized_input() {
        let json = br#"{"schema_version":1,"input_sha256":"xyz","spans":[]}"#;
        assert!(LiteralMap::from_json(json).is_err());
        assert!(LiteralMap::from_json(&vec![b' '; MAX_MAP_BYTES + 1]).is_err());
    }

    #[test]
    fn unicode_and_terminator_validation() {
        assert!(validate_bytes(&literal(Encoding::Utf8, 3, 0), "한".as_bytes()).is_ok());
        assert!(validate_bytes(&literal(Encoding::Utf8, 1, 0), &[0xff]).is_err());
        assert!(validate_bytes(&literal(Encoding::Ascii, 1, 1), b"ab").is_err());
        assert!(validate_bytes(&literal(Encoding::Utf16Le, 4, 0), &[0x3d, 0xd8, 0, 0xde]).is_ok());
        assert!(validate_bytes(&literal(Encoding::Utf16Le, 2, 0), &[0, 0xd8]).is_err());
    }

    #[test]
    fn binds_schema_and_original_file_digest() {
        let mut map = LiteralMap {
            schema_version: SCHEMA_VERSION,
            input_sha256: [0; 32],
            spans: Vec::new(),
        };
        assert!(map
            .validate(b"not a PE")
            .unwrap_err()
            .to_string()
            .contains("SHA-256"));
        map.schema_version = 999;
        assert!(map
            .validate(b"")
            .unwrap_err()
            .to_string()
            .contains("schema"));
    }
}
