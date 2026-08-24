// ==============================================================================
// WS2.1 (readccc §4.6 / function-atomicity-bridge-spec §1.3): function-ownership
// ↔ .pdata consistency AUTO-CHECK
// ==============================================================================
// The spec's §1.3 FUNCTION-OWNERSHIP contract:
//
//   FUNCTION-OWNERSHIP("F ∈ VM"):    every block of F is liftable AND F is fully
//     contained in a .pdata RUNTIME_FUNCTION [Begin,End]. No native entry point
//     of F may bypass F's prologue.
//   FUNCTION-OWNERSHIP("F ∈ NATIVE"): no block of F is virtualized. The VM must
//     not branch into F's mid-function address (crossing only at F's entry or
//     call-site).
//
// This module is a *self-contained* checker over an explicit ownership model
// (Vec<FunctionOwnership>) and the output's RUNTIME_FUNCTION (.pdata) table. It
// verifies:
//   1. Every VM-owned function is fully covered by some RUNTIME_FUNCTION
//      (Begin <= start_rva && end_rva <= End).
//   2. Every VM-owned function's entry RVA is the BeginAddress of its covering
//      RUNTIME_FUNCTION, so no VM function's native entry bypasses its prologue
//      (no landing mid-body inside another function).
//   3. VM-owned function entries do not overlap one another.
//   4. A native function listed in the model is NOT covered by any RUNTIME_FUNCTION
//      whose body would be reached only through a VM entry (informational).
//
// Ownership decisions are build-time fixed; they are emitted as a mapping file
// (CSV, per the project's mapping-file convention) via `render_csv`.
// ==============================================================================

use anyhow::{bail, Result};
use iced_x86::Code;

/// Stable, machine-readable reason for a function's ownership decision.
///
/// `FunctionOwnership::reason` remains a string for source compatibility with
/// the existing pipeline. New analysis code should use this enum and
/// `FunctionOwnershipDiagnostic`; legacy strings are normalized by
/// `OwnershipReason::from_legacy` when reports are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OwnershipReason {
    VmOwned,
    TlsReachable,
    CrtInitializer,
    SehPersonality,
    SehLandingPad,
    SetjmpLongjmp,
    UnsupportedInstruction,
    UnresolvedIndirectTarget,
    AmbiguousFunctionBoundary,
    NativeImportGateway,
    NativeCallbackGateway,
    DataCodeOverlap,
    SehOrPanicPolicy,
    SetjmpLongjmpPolicy,
    LegacyHighByteRegister,
    SemanticDependencyPropagation,
    IntegrationQuarantine,
    UnsupportedVmOpcode,
    FunctionAtomicityPropagation,
    AnalysisFailure,
}

impl OwnershipReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VmOwned => "vm-owned",
            Self::TlsReachable => "tls-reachable",
            Self::CrtInitializer => "crt-initializer",
            Self::SehPersonality => "seh-personality",
            Self::SehLandingPad => "seh-landing-pad",
            Self::SetjmpLongjmp => "setjmp-longjmp",
            Self::UnsupportedInstruction => "unsupported-instruction",
            Self::UnresolvedIndirectTarget => "unresolved-indirect-target",
            Self::AmbiguousFunctionBoundary => "ambiguous-function-boundary",
            Self::NativeImportGateway => "native-import-gateway",
            Self::NativeCallbackGateway => "native-callback-gateway",
            Self::DataCodeOverlap => "data-code-overlap",
            Self::SehOrPanicPolicy => "seh-or-panic-policy",
            Self::SetjmpLongjmpPolicy => "setjmp-longjmp-policy",
            Self::LegacyHighByteRegister => "legacy-high-byte-register",
            Self::SemanticDependencyPropagation => "semantic-dependency-propagation",
            Self::IntegrationQuarantine => "integration-quarantine",
            Self::UnsupportedVmOpcode => "unsupported-vm-opcode",
            Self::FunctionAtomicityPropagation => "function-atomicity-propagation",
            Self::AnalysisFailure => "analysis-failure",
        }
    }

    /// Convert historical free-form reasons without leaking an ambiguous
    /// catch-all such as `native-seh-or-plain` into the new report.
    pub fn from_legacy(reason: &str, owned_by_vm: bool) -> Self {
        if owned_by_vm {
            return Self::VmOwned;
        }
        match reason.trim().to_ascii_lowercase().as_str() {
            "tls-reachable" | "tls_reachable" => Self::TlsReachable,
            "crt-initializer" | "crt_initializer" => Self::CrtInitializer,
            "seh-personality" | "seh_personality" => Self::SehPersonality,
            "seh-landing-pad" | "seh_landing_pad" => Self::SehLandingPad,
            "setjmp-longjmp" | "setjmp_longjmp" => Self::SetjmpLongjmp,
            "unsupported-instruction" | "unsupported_instruction" => Self::UnsupportedInstruction,
            "unresolved-indirect-target" | "unresolved_indirect_target" => {
                Self::UnresolvedIndirectTarget
            }
            "ambiguous-function-boundary" | "ambiguous_function_boundary" => {
                Self::AmbiguousFunctionBoundary
            }
            "native-import-gateway" | "native_import_gateway" => Self::NativeImportGateway,
            "native-callback-gateway" | "native_callback_gateway" => Self::NativeCallbackGateway,
            "data-code-overlap" | "data_code_overlap" => Self::DataCodeOverlap,
            "analysis-failure" | "analysis_failure" => Self::AnalysisFailure,
            _ => Self::AnalysisFailure,
        }
    }
}

impl std::fmt::Display for OwnershipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single build-time ownership decision for one function (by RVA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionOwnership {
    /// Function begin RVA (the native entry point).
    pub start_rva: u32,
    /// Function end RVA (exclusive).
    pub end_rva: u32,
    /// true = "∈ VM" (virtualized / fully covered by program-VM), false = native.
    pub owned_by_vm: bool,
    /// Whether the function's entry must be the BeginAddress of its covering
    /// RUNTIME_FUNCTION (prologue-bypass check). True for virtualized *original*
    /// functions (entry == .pdata Begin); false for packer-inserted regions
    /// (e.g. the program-VM module, which is not an original function and may sit
    /// inside an original function's unwind range).
    pub enforce_entry_begin: bool,
    /// Human-readable reason (e.g. "program-vm-module", "seh-native-keep").
    pub reason: &'static str,
}

/// One .pdata RUNTIME_FUNCTION entry: [begin_rva, end_rva).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin_rva: u32,
    pub end_rva: u32,
}

/// Whether a diagnostic contributes to original-application coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipOrigin {
    Original,
    Generated,
}

/// The first concrete reason a function could not be VM-owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipBlocker {
    pub rva: u32,
    pub code: Option<Code>,
    pub caller_rvas: Vec<u32>,
    pub callee_rvas: Vec<u32>,
    pub pdata_range: Option<RuntimeFunction>,
}

impl OwnershipBlocker {
    pub fn new(rva: u32, code: Option<Code>) -> Self {
        Self {
            rva,
            code,
            caller_rvas: Vec::new(),
            callee_rvas: Vec::new(),
            pdata_range: None,
        }
    }
}

/// Rich diagnostics layered over the source-compatible ownership record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionOwnershipDiagnostic {
    pub function: FunctionOwnership,
    pub reason: OwnershipReason,
    pub origin: OwnershipOrigin,
    pub block_count: u64,
    pub instruction_count: u64,
    pub first_blocker: Option<OwnershipBlocker>,
}

impl FunctionOwnershipDiagnostic {
    pub fn from_legacy(function: FunctionOwnership) -> Self {
        let origin = if function.reason == "program-vm-module" {
            OwnershipOrigin::Generated
        } else {
            OwnershipOrigin::Original
        };
        Self {
            reason: OwnershipReason::from_legacy(function.reason, function.owned_by_vm),
            function,
            origin,
            block_count: 0,
            instruction_count: 0,
            first_blocker: None,
        }
    }

    pub fn new(function: FunctionOwnership, reason: OwnershipReason) -> Self {
        Self {
            function,
            reason,
            origin: OwnershipOrigin::Original,
            block_count: 0,
            instruction_count: 0,
            first_blocker: None,
        }
    }

    pub fn with_counts(mut self, block_count: u64, instruction_count: u64) -> Self {
        self.block_count = block_count;
        self.instruction_count = instruction_count;
        self
    }

    pub fn with_first_blocker(mut self, blocker: OwnershipBlocker) -> Self {
        self.first_blocker = Some(blocker);
        self
    }

    pub fn generated(mut self) -> Self {
        self.origin = OwnershipOrigin::Generated;
        self
    }
}

/// Apply canonical ProgramModel indirect-target evidence to commercial
/// ownership. This is intentionally the only unresolved-indirect policy hook:
/// callers must not rescan instructions or inspect derived unresolved edges.
pub fn apply_canonical_indirect_ownership(
    model: &crate::analysis::program_model::ProgramModel,
    diagnostics: &mut [FunctionOwnershipDiagnostic],
) {
    for (&function_id, &site_rva) in &model.incomplete_indirect_functions() {
        let Some(function) = model.functions.get(&function_id) else {
            continue;
        };
        for diagnostic in diagnostics.iter_mut().filter(|diagnostic| {
            function.ranges.iter().any(|range| {
                diagnostic.function.start_rva < range.end
                    && range.start < diagnostic.function.end_rva
            })
        }) {
            diagnostic.function.owned_by_vm = false;
            diagnostic.function.reason = OwnershipReason::UnresolvedIndirectTarget.as_str();
            diagnostic.reason = OwnershipReason::UnresolvedIndirectTarget;
            diagnostic.first_blocker = Some(OwnershipBlocker::new(site_rva, None));
        }
    }
}

/// A non-overlapping original-code interval used as the coverage denominator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalOwnershipInterval {
    pub start_rva: u32,
    pub end_rva: u32,
}

/// Build the original-function denominator and reject duplicate/overlapping
/// ownership. Generated modules are deliberately excluded.
pub fn canonical_original_intervals(
    model: &[FunctionOwnershipDiagnostic],
) -> Result<Vec<CanonicalOwnershipInterval>> {
    let mut intervals = model
        .iter()
        .filter(|record| record.origin == OwnershipOrigin::Original)
        .map(|record| CanonicalOwnershipInterval {
            start_rva: record.function.start_rva,
            end_rva: record.function.end_rva,
        })
        .collect::<Vec<_>>();
    intervals.sort_by_key(|interval| (interval.start_rva, interval.end_rva));

    for interval in &intervals {
        if interval.end_rva <= interval.start_rva {
            bail!(
                "ownership interval 0x{:X}..0x{:X} is empty or inverted",
                interval.start_rva,
                interval.end_rva
            );
        }
    }
    for pair in intervals.windows(2) {
        if pair[0].end_rva > pair[1].start_rva {
            bail!(
                "ownership intervals overlap: 0x{:X}..0x{:X} and 0x{:X}..0x{:X}",
                pair[0].start_rva,
                pair[0].end_rva,
                pair[1].start_rva,
                pair[1].end_rva
            );
        }
    }
    Ok(intervals)
}

/// Validate that original ownership is an exact, gapless partition of an
/// expected executable range. Callers that classify padding separately can
/// invoke this once per expected function/code span.
pub fn canonical_original_partition(
    model: &[FunctionOwnershipDiagnostic],
    expected_start_rva: u32,
    expected_end_rva: u32,
) -> Result<Vec<CanonicalOwnershipInterval>> {
    if expected_end_rva <= expected_start_rva {
        bail!(
            "expected ownership range 0x{:X}..0x{:X} is empty or inverted",
            expected_start_rva,
            expected_end_rva
        );
    }
    let intervals = canonical_original_intervals(model)?;
    let Some(first) = intervals.first() else {
        bail!(
            "ownership gap: expected 0x{:X}..0x{:X}, found no original intervals",
            expected_start_rva,
            expected_end_rva
        );
    };
    if first.start_rva != expected_start_rva {
        bail!(
            "ownership gap: expected start 0x{:X}, first interval starts at 0x{:X}",
            expected_start_rva,
            first.start_rva
        );
    }
    for pair in intervals.windows(2) {
        if pair[0].end_rva != pair[1].start_rva {
            bail!(
                "ownership gap: 0x{:X}..0x{:X}",
                pair[0].end_rva,
                pair[1].start_rva
            );
        }
    }
    let last_end = intervals.last().map(|interval| interval.end_rva).unwrap();
    if last_end != expected_end_rva {
        bail!(
            "ownership gap or overflow at end: last interval ends at 0x{:X}, expected 0x{:X}",
            last_end,
            expected_end_rva
        );
    }
    Ok(intervals)
}

/// Result of the consistency check.
#[derive(Debug, Clone, Default)]
pub struct OwnershipReport {
    pub total_functions: usize,
    pub vm_functions: usize,
    pub native_functions: usize,
    /// Count of inconsistencies found (bail on > 0 for hard paths).
    pub inconsistencies: usize,
    /// Human-readable list of every inconsistency.
    pub notes: Vec<String>,
}

impl OwnershipReport {
    pub fn is_clean(&self) -> bool {
        self.inconsistencies == 0
    }
}

/// Find the RUNTIME_FUNCTION that owns `rva` as its entry (BeginAddress) or,
/// failing that, whose [Begin,End) fully covers `rva`. A VM function's native
/// entry must be the BeginAddress of *its own* RUNTIME_FUNCTION (the bridge
/// leaf), not merely inside some overlapping original entry — so an exact
/// Begin match is preferred.
fn covering_rf(runtime_functions: &[RuntimeFunction], rva: u32) -> Option<(u32, u32)> {
    if let Some(rf) = runtime_functions.iter().find(|rf| rf.begin_rva == rva) {
        return Some((rf.begin_rva, rf.end_rva));
    }
    runtime_functions
        .iter()
        .find(|rf| rf.begin_rva <= rva && rva < rf.end_rva)
        .map(|rf| (rf.begin_rva, rf.end_rva))
}

/// Extend coverage across adjacent RUNTIME_FUNCTION records. A generated VM
/// module legitimately uses different unwind recipes for its entry, native-call
/// bridge, and post-bridge code while remaining gaplessly covered.
fn contiguous_coverage_end(
    runtime_functions: &[RuntimeFunction],
    start: u32,
) -> Option<(u32, u32)> {
    let (first_begin, mut end) = covering_rf(runtime_functions, start)?;
    let mut sorted: Vec<_> = runtime_functions.iter().collect();
    sorted.sort_by_key(|rf| rf.begin_rva);
    loop {
        let Some(next) = sorted
            .iter()
            .find(|rf| rf.begin_rva <= end && rf.end_rva > end)
        else {
            break;
        };
        end = next.end_rva;
    }
    Some((first_begin, end))
}

/// Run the §1.3 consistency check over the explicit ownership model.
///
/// Returns `Ok(report)` when the model is consistent (report.is_clean() == true).
/// Returns `Err` with a descriptive message on the first hard inconsistency.
/// The caller decides whether an inconsistency is fatal (validate) or recorded.
pub fn check_ownership(
    model: &[FunctionOwnership],
    runtime_functions: &[RuntimeFunction],
) -> Result<OwnershipReport> {
    let mut report = OwnershipReport {
        total_functions: model.len(),
        vm_functions: model.iter().filter(|f| f.owned_by_vm).count(),
        native_functions: model.iter().filter(|f| !f.owned_by_vm).count(),
        ..Default::default()
    };

    let mut vm_entries: Vec<&FunctionOwnership> = Vec::new();

    for f in model {
        if !f.owned_by_vm {
            // NATIVE functions must not be claimed VM; nothing further to check
            // structurally (they are kept native verbatim).
            continue;
        }
        if f.end_rva <= f.start_rva {
            report.inconsistencies += 1;
            report.notes.push(format!(
                "VM function 0x{:X}..0x{:X} has empty/inverted range",
                f.start_rva, f.end_rva
            ));
            continue;
        }
        vm_entries.push(f);

        // (1) fully covered by a RUNTIME_FUNCTION
        let Some((b, e)) = contiguous_coverage_end(runtime_functions, f.start_rva) else {
            report.inconsistencies += 1;
            report.notes.push(format!(
                "VM function 0x{:X}..0x{:X} is NOT covered by any RUNTIME_FUNCTION",
                f.start_rva, f.end_rva
            ));
            continue;
        };
        if f.end_rva > e {
            report.inconsistencies += 1;
            report.notes.push(format!(
                "VM function 0x{:X}..0x{:X} extends beyond contiguous RUNTIME_FUNCTION coverage \
                 (covering [0x{:X}..0x{:X}))",
                f.start_rva, f.end_rva, b, e
            ));
        }

        // (2) entry == BeginAddress of the covering entry (no prologue bypass)
        //     — only enforced for real virtualized functions, not for packer-
        //     inserted regions (program-VM module) whose entry is a dispatch
        //     target rather than a function prologue.
        if f.enforce_entry_begin && b != f.start_rva {
            report.inconsistencies += 1;
            report.notes.push(format!(
                "VM function entry 0x{:X} is not the BeginAddress of its \
                 RUNTIME_FUNCTION (Begin=0x{:X}) — native entry would bypass prologue",
                f.start_rva, b
            ));
        }
    }

    // (3) VM function entries must not overlap one another.
    let mut sorted = vm_entries.to_vec();
    sorted.sort_by_key(|f| f.start_rva);
    for w in sorted.windows(2) {
        let (a, b) = (w[0], w[1]);
        if a.end_rva > b.start_rva {
            report.inconsistencies += 1;
            report.notes.push(format!(
                "VM functions overlap: 0x{:X}..0x{:X} vs 0x{:X}..0x{:X}",
                a.start_rva, a.end_rva, b.start_rva, b.end_rva
            ));
        }
    }

    if !report.is_clean() {
        let joined = report.notes.join("; ");
        bail!(
            "function-ownership ↔ .pdata inconsistency ({}): {}",
            report.inconsistencies,
            joined
        );
    }
    Ok(report)
}

/// Render rich ownership diagnostics as stable CSV.
///
/// Records are ordered by owner (`vm`, then `native`) and then by function
/// range. No free-form legacy reason is copied to the output. This keeps the
/// schema and values deterministic across callers and prevents the historical
/// `native-seh-or-plain` bucket from reappearing.
pub fn render_diagnostic_csv(model: &[FunctionOwnershipDiagnostic]) -> String {
    let mut records = model.iter().collect::<Vec<_>>();
    records.sort_by_key(|record| {
        (
            !record.function.owned_by_vm,
            record.function.start_rva,
            record.function.end_rva,
            record.reason,
        )
    });

    let mut csv = String::from(
        "origin,function_id,function_start_rva,function_end_rva,owner,reason,block_count,instruction_count,first_blocker_rva,first_blocker_code,caller_rvas,callee_rvas,pdata_range,unwind\n",
    );
    for record in records {
        let owner = if record.function.owned_by_vm {
            "vm"
        } else {
            "native"
        };
        let origin = match record.origin {
            OwnershipOrigin::Original => "original",
            OwnershipOrigin::Generated => "generated",
        };
        let render_rvas = |values: &[u32]| {
            let mut values = values.to_vec();
            values.sort_unstable();
            values.dedup();
            values
                .iter()
                .map(|rva| format!("0x{rva:X}"))
                .collect::<Vec<_>>()
                .join("|")
        };
        let (blocker_rva, blocker_code, callers, callees, pdata) = record
            .first_blocker
            .as_ref()
            .map(|blocker| {
                (
                    format!("0x{:X}", blocker.rva),
                    blocker
                        .code
                        .map(|code| format!("{code:?}"))
                        .unwrap_or_default(),
                    render_rvas(&blocker.caller_rvas),
                    render_rvas(&blocker.callee_rvas),
                    blocker
                        .pdata_range
                        .map(|rf| format!("0x{:X}-0x{:X}", rf.begin_rva, rf.end_rva))
                        .unwrap_or_default(),
                )
            })
            .unwrap_or_default();
        csv.push_str(&format!(
            "{},{}:0x{:X},0x{:X},0x{:X},{},{},{},{},{},{},{},{},{},{}\n",
            origin,
            origin,
            record.function.start_rva,
            record.function.start_rva,
            record.function.end_rva,
            owner,
            record.reason,
            record.block_count,
            record.instruction_count,
            blocker_rva,
            blocker_code,
            callers,
            callees,
            pdata,
            record.function.enforce_entry_begin,
        ));
    }
    csv
}

/// Source-compatible adapter for existing callers. Until they supply detailed
/// analysis records, counts are zero and the first-blocker column is empty.
pub fn render_csv(model: &[FunctionOwnership]) -> String {
    let diagnostics = model
        .iter()
        .copied()
        .map(FunctionOwnershipDiagnostic::from_legacy)
        .collect::<Vec<_>>();
    render_diagnostic_csv(&diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rf(b: u32, e: u32) -> RuntimeFunction {
        RuntimeFunction {
            begin_rva: b,
            end_rva: e,
        }
    }
    fn own(start: u32, end: u32, vm: bool) -> FunctionOwnership {
        FunctionOwnership {
            start_rva: start,
            end_rva: end,
            owned_by_vm: vm,
            enforce_entry_begin: true,
            reason: if vm { "test-vm" } else { "test-native" },
        }
    }

    /// A packer-inserted region (module) does not require its entry to be a
    /// .pdata BeginAddress, but must still be fully covered.
    #[test]
    fn module_region_requires_coverage_not_entry_begin() {
        // module at 0xE9380 inside an original function [0x50701..) — no entry
        // BeginAddress, but fully covered → clean when entry enforcement off.
        let model = vec![FunctionOwnership {
            start_rva: 0xE9380,
            end_rva: 0xEA000,
            owned_by_vm: true,
            enforce_entry_begin: false,
            reason: "program-vm-module",
        }];
        let rfs = vec![rf(0x50701, 0xEA500)];
        let rep = check_ownership(&model, &rfs).unwrap();
        assert!(rep.is_clean());
        // The same region with entry enforcement ON must fail (prologue bypass).
        let mut strict = model;
        strict[0].enforce_entry_begin = true;
        assert!(check_ownership(&strict, &rfs).is_err());
    }

    #[test]
    fn clean_vm_function_fully_covered() {
        let model = vec![own(0x1000, 0x1100, true), own(0x2000, 0x2100, false)];
        let rfs = vec![rf(0x1000, 0x1100), rf(0x2000, 0x2100)];
        let rep = check_ownership(&model, &rfs).unwrap();
        assert!(rep.is_clean());
        assert_eq!(rep.vm_functions, 1);
        assert_eq!(rep.native_functions, 1);
    }

    #[test]
    fn vm_module_accepts_gapless_multi_recipe_coverage() {
        let model = vec![FunctionOwnership {
            start_rva: 0x5000,
            end_rva: 0x9000,
            owned_by_vm: true,
            enforce_entry_begin: false,
            reason: "program-vm-module",
        }];
        let rfs = vec![rf(0x5000, 0x6100), rf(0x6100, 0x6800), rf(0x6800, 0x9000)];
        assert!(check_ownership(&model, &rfs).unwrap().is_clean());
    }

    #[test]
    fn vm_module_rejects_gap_between_unwind_recipes() {
        let model = vec![FunctionOwnership {
            start_rva: 0x5000,
            end_rva: 0x9000,
            owned_by_vm: true,
            enforce_entry_begin: false,
            reason: "program-vm-module",
        }];
        let rfs = vec![rf(0x5000, 0x6100), rf(0x6110, 0x9000)];
        assert!(check_ownership(&model, &rfs).is_err());
    }

    #[test]
    fn vm_function_not_covered_fails() {
        let model = vec![own(0x1000, 0x1100, true)];
        let rfs = vec![rf(0x3000, 0x3100)]; // unrelated
        assert!(check_ownership(&model, &rfs).is_err());
    }

    #[test]
    fn vm_function_partial_cover_fails() {
        let model = vec![own(0x1000, 0x1200, true)];
        let rfs = vec![rf(0x1000, 0x1100)]; // ends early
        assert!(check_ownership(&model, &rfs).is_err());
    }

    #[test]
    fn entry_bypassing_prologue_fails() {
        // entry at 0x1080 inside a function that begins at 0x1000
        let model = vec![own(0x1080, 0x1100, true)];
        let rfs = vec![rf(0x1000, 0x1100)];
        assert!(check_ownership(&model, &rfs).is_err());
    }

    #[test]
    fn overlapping_vm_functions_fail() {
        let model = vec![own(0x1000, 0x1100, true), own(0x1080, 0x1180, true)];
        let rfs = vec![rf(0x1000, 0x1100), rf(0x1080, 0x1180)];
        assert!(check_ownership(&model, &rfs).is_err());
    }

    #[test]
    fn native_functions_are_not_checked_as_vm() {
        // A native function with no covering RF is fine — only VM functions are.
        let model = vec![own(0x4000, 0x4100, false)];
        let rep = check_ownership(&model, &[]).unwrap();
        assert!(rep.is_clean());
        assert_eq!(rep.native_functions, 1);
    }

    #[test]
    fn csv_renders_all_functions_sorted() {
        let model = vec![
            own(0x2000, 0x2100, false),
            own(0x1000, 0x1100, true),
            own(0x1800, 0x1900, true),
        ];
        let csv = render_csv(&model);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "origin,function_id,function_start_rva,function_end_rva,owner,reason,block_count,instruction_count,first_blocker_rva,first_blocker_code,caller_rvas,callee_rvas,pdata_range,unwind"
        );
        assert_eq!(lines.len(), 4); // header + 3
        assert!(lines[1].contains(",vm,"));
        assert!(lines[3].contains(",native,"));
        // VM entries sorted first, native after
        assert!(lines[1].starts_with("original,original:0x1000"));
        assert!(lines[2].starts_with("original,original:0x1800"));
        assert!(lines[3].starts_with("original,original:0x2000"));
        assert!(!csv.contains("test-native"));
        assert!(csv.contains("analysis-failure"));
    }

    #[test]
    fn reason_model_covers_every_required_class_stably() {
        let reasons = [
            OwnershipReason::VmOwned,
            OwnershipReason::TlsReachable,
            OwnershipReason::CrtInitializer,
            OwnershipReason::SehPersonality,
            OwnershipReason::SehLandingPad,
            OwnershipReason::SetjmpLongjmp,
            OwnershipReason::UnsupportedInstruction,
            OwnershipReason::UnresolvedIndirectTarget,
            OwnershipReason::AmbiguousFunctionBoundary,
            OwnershipReason::NativeImportGateway,
            OwnershipReason::NativeCallbackGateway,
            OwnershipReason::DataCodeOverlap,
            OwnershipReason::AnalysisFailure,
        ];
        let names = reasons.map(OwnershipReason::as_str);
        assert_eq!(names.len(), 13);
        assert_eq!(names[0], "vm-owned");
        assert_eq!(names[12], "analysis-failure");
        assert_eq!(
            OwnershipReason::from_legacy("native-seh-or-plain", false),
            OwnershipReason::AnalysisFailure
        );
        assert_eq!(
            OwnershipReason::from_legacy("tls_reachable", false),
            OwnershipReason::TlsReachable
        );
    }

    #[test]
    fn rich_csv_contains_counts_and_deterministic_blocker_context() {
        let mut blocker = OwnershipBlocker::new(0x1012, Some(Code::Nopd));
        blocker.caller_rvas = vec![0x3000, 0x2000, 0x2000];
        blocker.callee_rvas = vec![0x5000, 0x4000];
        blocker.pdata_range = Some(rf(0x1000, 0x1100));
        let diagnostic = FunctionOwnershipDiagnostic::new(
            own(0x1000, 0x1100, false),
            OwnershipReason::UnsupportedInstruction,
        )
        .with_counts(3, 17)
        .with_first_blocker(blocker);

        let csv = render_diagnostic_csv(&[diagnostic]);
        assert!(csv.contains(
            "original,original:0x1000,0x1000,0x1100,native,unsupported-instruction,3,17,0x1012,Nopd,0x2000|0x3000,0x4000|0x5000,0x1000-0x1100,true"
        ));
    }

    #[test]
    fn canonical_intervals_exclude_generated_modules() {
        let original =
            FunctionOwnershipDiagnostic::new(own(0x1000, 0x1100, true), OwnershipReason::VmOwned);
        let generated =
            FunctionOwnershipDiagnostic::new(own(0x1080, 0x1200, true), OwnershipReason::VmOwned)
                .generated();
        assert_eq!(
            canonical_original_intervals(&[generated, original]).unwrap(),
            vec![CanonicalOwnershipInterval {
                start_rva: 0x1000,
                end_rva: 0x1100
            }]
        );
    }

    #[test]
    fn canonical_intervals_reject_overlap_and_invalid_ranges() {
        let overlap = vec![
            FunctionOwnershipDiagnostic::new(own(0x1000, 0x1100, true), OwnershipReason::VmOwned),
            FunctionOwnershipDiagnostic::new(
                own(0x1080, 0x1200, false),
                OwnershipReason::AnalysisFailure,
            ),
        ];
        assert!(canonical_original_intervals(&overlap).is_err());

        let invalid = FunctionOwnershipDiagnostic::new(
            own(0x2000, 0x2000, false),
            OwnershipReason::AmbiguousFunctionBoundary,
        );
        assert!(canonical_original_intervals(&[invalid]).is_err());
    }

    #[test]
    fn canonical_partition_accepts_exact_coverage_and_rejects_gaps() {
        let exact = vec![
            FunctionOwnershipDiagnostic::new(own(0x1000, 0x1080, true), OwnershipReason::VmOwned),
            FunctionOwnershipDiagnostic::new(
                own(0x1080, 0x1100, false),
                OwnershipReason::UnsupportedInstruction,
            ),
        ];
        assert_eq!(
            canonical_original_partition(&exact, 0x1000, 0x1100)
                .unwrap()
                .len(),
            2
        );

        let gap = vec![
            exact[0].clone(),
            FunctionOwnershipDiagnostic {
                function: own(0x1090, 0x1100, false),
                ..exact[1].clone()
            },
        ];
        assert!(canonical_original_partition(&gap, 0x1000, 0x1100).is_err());
        assert!(canonical_original_partition(&[], 0x1000, 0x1100).is_err());
    }

    #[test]
    fn legacy_program_module_is_generated_vm_owned() {
        let record = FunctionOwnershipDiagnostic::from_legacy(FunctionOwnership {
            start_rva: 0x5000,
            end_rva: 0x6000,
            owned_by_vm: true,
            enforce_entry_begin: false,
            reason: "program-vm-module",
        });
        assert_eq!(record.reason, OwnershipReason::VmOwned);
        assert_eq!(record.origin, OwnershipOrigin::Generated);
    }
}
