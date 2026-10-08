//! Loader for the coverage DB produced by the `vm-coverage` /
//! `btg-cpu-coverage-db` binaries in the root crate.
//!
//! We deserialize only the fields the generator needs. `serde` ignores unknown
//! fields by default, so this stays forward-compatible with additions to the
//! upstream `CodeRecord` shape.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// One iced-x86 `Code` record as emitted by the coverage auditor.
#[derive(Debug, Clone, Deserialize)]
pub struct CoverageRecord {
    #[serde(default)]
    pub code_id: usize,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub mnemonic: String,
    #[serde(default)]
    pub encoding: String,
    #[serde(default)]
    pub is_instruction: bool,
    #[serde(default)]
    pub mode64: bool,
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub cpuid_features: Vec<String>,
    #[serde(default)]
    pub op_kinds: Vec<String>,
    /// EVEX opmask register selection as recorded by the auditor ("none" / "K1").
    #[serde(default)]
    pub opmask: String,
    /// EVEX zeroing-masking (`{z}`) in effect.
    #[serde(default)]
    pub zeroing: bool,
    /// EVEX embedded broadcast (`{1toN}`) in effect.
    #[serde(default)]
    pub broadcast: bool,
    /// Pipeline status string: FULL_PIPELINE / LIFTED_NO_MICRO_OP / UNSUPPORTED /
    /// LIFT_ERROR / EVALUATOR_GAP / ISA_GAP / INTERPRETER_GAP / THREADED_GAP / ...
    #[serde(default)]
    pub status: String,
    /// RiscOps the real lifter already emits for this code (when supported).
    #[serde(default)]
    pub risc_ops: Vec<String>,
}

impl CoverageRecord {
    /// A record the generator should try to close: the lifter does not yet
    /// produce a usable, fully-capable micro-program for it.
    pub fn is_gap(&self) -> bool {
        self.is_instruction
            && matches!(
                self.status.as_str(),
                "UNSUPPORTED"
                    | "LIFT_ERROR"
                    | "EVALUATOR_GAP"
                    | "ISA_GAP"
                    | "INTERPRETER_GAP"
                    | "THREADED_GAP"
            )
    }

    pub fn is_supported(&self) -> bool {
        matches!(self.status.as_str(), "FULL_PIPELINE" | "LIFTED_NO_MICRO_OP")
    }
}

/// The top-level coverage report. Only `records` is required; everything else is
/// optional metadata that we surface in our own report when present.
#[derive(Debug, Clone, Deserialize)]
pub struct CoverageReport {
    #[serde(default)]
    pub iced_x86_version: String,
    #[serde(default)]
    pub records: Vec<CoverageRecord>,
}

impl CoverageReport {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading coverage DB: {}", path.display()))?;
        Self::from_json(&raw)
            .with_context(|| format!("parsing coverage DB: {}", path.display()))
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        let report: CoverageReport = serde_json::from_str(raw)?;
        Ok(report)
    }

    pub fn instructions(&self) -> impl Iterator<Item = &CoverageRecord> {
        self.records.iter().filter(|r| r.is_instruction)
    }

    pub fn gaps(&self) -> impl Iterator<Item = &CoverageRecord> {
        self.records.iter().filter(|r| r.is_gap())
    }
}
