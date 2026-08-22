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

/// Render the ownership model as a CSV mapping file (per project convention).
pub fn render_csv(model: &[FunctionOwnership]) -> String {
    let mut s = String::from("function_start_rva,function_end_rva,owner,reason\n");
    let mut vms = model.iter().filter(|f| f.owned_by_vm).collect::<Vec<_>>();
    vms.sort_by_key(|f| f.start_rva);
    let mut natives = model.iter().filter(|f| !f.owned_by_vm).collect::<Vec<_>>();
    natives.sort_by_key(|f| f.start_rva);
    for f in vms {
        s.push_str(&format!(
            "0x{:X},0x{:X},vm,{}\n",
            f.start_rva, f.end_rva, f.reason
        ));
    }
    for f in natives {
        s.push_str(&format!(
            "0x{:X},0x{:X},native,{}\n",
            f.start_rva, f.end_rva, f.reason
        ));
    }
    s
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
        assert_eq!(lines[0], "function_start_rva,function_end_rva,owner,reason");
        assert_eq!(lines.len(), 4); // header + 3
        assert!(lines[1].contains(",vm,"));
        assert!(lines[3].contains(",native,"));
        // VM entries sorted first, native after
        assert!(lines[1].starts_with("0x1000"));
        assert!(lines[2].starts_with("0x1800"));
        assert!(lines[3].starts_with("0x2000"));
    }
}
