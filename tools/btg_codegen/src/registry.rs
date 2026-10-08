//! Live RiscOp registry loader (Priority 5 — anti-drift).
//!
//! The generator's `KNOWN_RISC_OPS` const is a convenience fallback for offline
//! runs, but the authoritative list is the one the core VM actually implements,
//! emitted by the `btg-op-registry` binary into `op_registry.json`. CI loads
//! that live list and validates auto-template RiscOps against it, and a test in
//! this crate asserts the committed snapshot equals the const — so the core
//! registry, the snapshot, and the const cannot silently drift apart.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct OpRegistry {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub ops: Vec<String>,
}

impl OpRegistry {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading op registry: {}", path.display()))?;
        let reg: OpRegistry = serde_json::from_str(&raw)
            .with_context(|| format!("parsing op registry: {}", path.display()))?;
        Ok(reg)
    }

    pub fn contains(&self, op: &str) -> bool {
        self.ops.iter().any(|o| o == op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::KNOWN_RISC_OPS;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn snapshot_path() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("op_registry.json");
        p
    }

    #[test]
    fn const_matches_committed_registry_snapshot() {
        let reg = OpRegistry::load(&snapshot_path()).expect("load op_registry.json snapshot");
        let snap: BTreeSet<&str> = reg.ops.iter().map(String::as_str).collect();
        let konst: BTreeSet<&str> = KNOWN_RISC_OPS.iter().copied().collect();

        let missing_from_const: Vec<_> = snap.difference(&konst).collect();
        let extra_in_const: Vec<_> = konst.difference(&snap).collect();
        assert!(
            missing_from_const.is_empty() && extra_in_const.is_empty(),
            "KNOWN_RISC_OPS drifted from op_registry.json snapshot.\n  \
             in snapshot but not const: {missing_from_const:?}\n  \
             in const but not snapshot: {extra_in_const:?}\n  \
             Regenerate: cargo run --bin btg-op-registry > tools/btg_codegen/op_registry.json \
             and update KNOWN_RISC_OPS to match."
        );
        assert_eq!(reg.count, reg.ops.len(), "registry count field is consistent");
    }
}
