//! Local build packages. Cache data is trusted like Cargo's target directory;
//! checksums detect corruption, not malicious modification by a local user.
use crate::{cli::CliArgs, manifest::sha256_hex};
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAGIC: &[u8] = b"BTGCACHE\x01";
static SERIAL: AtomicU64 = AtomicU64::new(0);
thread_local! { static ACTIVE: RefCell<Option<BuildCache>> = const { RefCell::new(None) }; }

#[derive(Clone)]
pub struct BuildCache {
    root: PathBuf,
    rebuild: bool,
}
pub struct Session(Option<BuildCache>);
impl Drop for Session {
    fn drop(&mut self) {
        ACTIVE.with(|c| *c.borrow_mut() = self.0.take());
    }
}

impl BuildCache {
    pub fn open(args: &CliArgs, input: &[u8]) -> Result<Option<Self>> {
        if !args.build_cache {
            return Ok(None);
        }
        ensure!(args.seed.is_some(), "--build-cache requires --seed");
        ensure!(
            args.section_name_mode != crate::cli::SectionNameMode::Random,
            "--build-cache cannot reuse --section-name-mode random; use seeded"
        );
        let mut normalized = args.clone();
        normalized.input = PathBuf::new();
        normalized.output = PathBuf::new();
        normalized.cache_dir = PathBuf::new();
        normalized.rebuild = false;
        normalized.no_progress = false;
        normalized.progress_only = false;
        normalized.progress_refresh_ms = 0;
        normalized.log_file = None;
        let mut env: Vec<_> = std::env::vars_os()
            .filter(|(k, _)| k.to_string_lossy().starts_with("BTG_"))
            .collect();
        env.sort();
        let executable = fs::read(std::env::current_exe()?)?;
        let identity = format!(
            "package-v1\n{}\n{}\n{normalized:?}\n{env:?}",
            sha256_hex(input),
            sha256_hex(&executable)
        );
        let root = args.cache_dir.join(sha256_hex(identity.as_bytes()));
        fs::create_dir_all(&root)?;
        Ok(Some(Self {
            root,
            rebuild: args.rebuild,
        }))
    }
    pub fn activate(&self) -> Session {
        Session(ACTIVE.with(|c| c.borrow_mut().replace(self.clone())))
    }
    pub fn read(&self, name: &str) -> Option<Vec<u8>> {
        if self.rebuild {
            return None;
        }
        let bytes = fs::read(self.root.join(name)).ok()?;
        let header = MAGIC.len() + 32;
        if bytes.len() < header || &bytes[..MAGIC.len()] != MAGIC {
            return None;
        }
        let payload = &bytes[header..];
        if Sha256::digest(payload).as_slice() != &bytes[MAGIC.len()..header] {
            log::warn!("Ignoring corrupt build cache entry: {name}");
            return None;
        }
        Some(payload.to_vec())
    }
    pub fn write(&self, name: &str, payload: &[u8]) -> Result<()> {
        let destination = self.root.join(name);
        let temporary = self.root.join(format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| -> Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(MAGIC)?;
            file.write_all(&Sha256::digest(payload))?;
            file.write_all(payload)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &destination)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    pub fn restore(&self, output: &Path) -> Result<bool> {
        let Some(payload) = self.read("completed.pkg") else {
            return Ok(false);
        };
        let mut reader = Reader(&payload);
        let decoded = (|| -> Option<_> {
            let pe = reader.blob()?;
            let manifest = reader.blob()?;
            if !reader.0.is_empty() {
                return None;
            }
            Some((pe, manifest))
        })();
        let Some((pe, manifest)) = decoded else {
            return Ok(false);
        };
        // Do not emit a corrupt/non-PE image even when a package checksum matches.
        // TargetPeInfo is an *input* model and requires original section names;
        // protected outputs may intentionally use a different section layout.
        if goblin::pe::PE::parse(pe).is_err() {
            return Ok(false);
        }
        fs::write(output, pe)?;
        fs::write(manifest_path(output), manifest)?;
        Ok(true)
    }
    pub fn save(&self, output: &Path, pe: &[u8]) -> Result<()> {
        let manifest = fs::read(manifest_path(output))?;
        let mut payload = Vec::new();
        blob(&mut payload, pe);
        blob(&mut payload, &manifest);
        self.write("completed.pkg", &payload)
    }
}

pub fn manifest_path(output: &Path) -> PathBuf {
    let mut path = output.to_owned();
    path.set_extension(
        output
            .extension()
            .map(|e| format!("{}.btgmanifest", e.to_string_lossy()))
            .unwrap_or_else(|| "btgmanifest".into()),
    );
    path
}
pub fn active() -> Option<BuildCache> {
    ACTIVE.with(|c| c.borrow().clone())
}
pub fn encode_module(module: &crate::vm::VmModule) -> Vec<u8> {
    let mut out = Vec::new();
    for bytes in [&module.code, &module.table, &module.bytecode] {
        blob(&mut out, bytes);
    }
    let mut offsets = Vec::new();
    for &offset in &module.handler_offsets {
        offsets.extend_from_slice(&(offset as u64).to_le_bytes());
    }
    blob(&mut out, &offsets);
    for value in [
        module.native_bridge_range.map(|r| r.0),
        module.native_bridge_range.map(|r| r.1),
        module.lifetime_cleanup_handler_offset,
        module.dynamic_state_entry_offset,
    ] {
        out.extend_from_slice(&value.map(|v| v as u64).unwrap_or(u64::MAX).to_le_bytes());
    }
    out
}
pub fn decode_module(
    payload: &[u8],
    expected_bytecode: &[u8],
    minimum_table: usize,
) -> Option<crate::vm::VmModule> {
    let mut r = Reader(payload);
    let code = r.blob()?.to_vec();
    let table = r.blob()?.to_vec();
    let bytecode = r.blob()?.to_vec();
    let offsets = r.blob()?;
    if code.is_empty()
        || table.len() < minimum_table
        || bytecode != expected_bytecode
        || offsets.len() % 8 != 0
    {
        return None;
    }
    let handler_offsets: Vec<usize> = offsets
        .chunks_exact(8)
        .map(|b| usize::try_from(u64::from_le_bytes(b.try_into().unwrap())).ok())
        .collect::<Option<_>>()?;
    let mut optional = || -> Option<Option<usize>> {
        let n = r.number()?;
        if n == u64::MAX {
            Some(None)
        } else {
            Some(Some(usize::try_from(n).ok()?))
        }
    };
    let start = optional()?;
    let end = optional()?;
    let cleanup = optional()?;
    let dynamic = optional()?;
    if !r.0.is_empty()
        || handler_offsets.iter().any(|&o| o >= code.len())
        || cleanup.is_some_and(|o| o >= code.len())
        || dynamic.is_some_and(|o| o >= code.len())
    {
        return None;
    }
    let native_bridge_range = match (start, end) {
        (None, None) => None,
        (Some(s), Some(e)) if s < e && e <= code.len() => Some((s, e)),
        _ => return None,
    };
    Some(crate::vm::VmModule {
        code,
        table,
        bytecode,
        handler_offsets,
        native_bridge_range,
        lifetime_cleanup_handler_offset: cleanup,
        dynamic_state_entry_offset: dynamic,
    })
}
pub fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}
pub struct Reader<'a>(pub &'a [u8]);
impl<'a> Reader<'a> {
    pub fn number(&mut self) -> Option<u64> {
        let bytes: [u8; 8] = self.0.get(..8)?.try_into().ok()?;
        self.0 = &self.0[8..];
        Some(u64::from_le_bytes(bytes))
    }
    pub fn blob(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.number()?).ok()?;
        let value = self.0.get(..len)?;
        self.0 = &self.0[len..];
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn module_roundtrip_and_boundary_validation() {
        let module = crate::vm::VmModule {
            code: vec![0x90, 0xc3],
            table: vec![0; 16],
            bytecode: vec![1, 2],
            handler_offsets: vec![1],
            native_bridge_range: Some((0, 2)),
            lifetime_cleanup_handler_offset: None,
            dynamic_state_entry_offset: Some(0),
        };
        let encoded = encode_module(&module);
        let restored = decode_module(&encoded, &[1, 2], 16).unwrap();
        assert_eq!(restored.code, module.code);
        assert_eq!(restored.native_bridge_range, module.native_bridge_range);
        assert!(decode_module(&encoded, &[2, 1], 16).is_none());
        assert!(decode_module(&encoded, &[1, 2], 17).is_none());
        assert!(decode_module(&encoded[..encoded.len() - 1], &[1, 2], 16).is_none());
        let mut invalid = module;
        invalid.dynamic_state_entry_offset = Some(2);
        assert!(decode_module(&encode_module(&invalid), &[1, 2], 16).is_none());
    }
    #[test]
    fn cache_cli_requires_seed_and_rebuild_requires_cache() {
        assert!(CliArgs::try_parse_from(["btg", "--build-cache"]).is_err());
        assert!(CliArgs::try_parse_from(["btg", "--rebuild"]).is_err());
        assert!(
            CliArgs::try_parse_from(["btg", "--resume", "--seed", "2"])
                .unwrap()
                .build_cache
        );
    }
    #[test]
    fn identity_changes_with_input_and_options_not_output_path() {
        let directory = std::env::temp_dir().join(format!(
            "btg-identity-test-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        let mut args = CliArgs::try_parse_from(["btg", "--build-cache", "--seed", "2"]).unwrap();
        args.cache_dir = directory.clone();
        let first = BuildCache::open(&args, b"input").unwrap().unwrap();
        args.output = PathBuf::from("elsewhere.exe");
        args.progress_only = true;
        assert_eq!(
            first.root,
            BuildCache::open(&args, b"input").unwrap().unwrap().root
        );
        assert_ne!(
            first.root,
            BuildCache::open(&args, b"changed").unwrap().unwrap().root
        );
        args.seed = Some(3);
        assert_ne!(
            first.root,
            BuildCache::open(&args, b"input").unwrap().unwrap().root
        );
        args.section_name_mode = crate::cli::SectionNameMode::Random;
        assert!(BuildCache::open(&args, b"input").is_err());
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn corruption_and_rebuild_never_return_cached_data() {
        let root = std::env::temp_dir().join(format!(
            "btg-cache-test-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let cache = BuildCache {
            root: root.clone(),
            rebuild: false,
        };
        cache.write("test.pkg", b"checkpoint").unwrap();
        assert_eq!(cache.read("test.pkg").unwrap(), b"checkpoint");
        cache.write("test.pkg", b"replacement").unwrap();
        assert_eq!(cache.read("test.pkg").unwrap(), b"replacement");
        let bypass = BuildCache {
            root: root.clone(),
            rebuild: true,
        };
        assert!(bypass.read("test.pkg").is_none());
        fs::write(root.join("test.pkg"), b"broken").unwrap();
        assert!(cache.read("test.pkg").is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn oversized_blob_is_rejected_without_allocation() {
        let bytes = u64::MAX.to_le_bytes();
        assert!(Reader(&bytes).blob().is_none());
    }
}
