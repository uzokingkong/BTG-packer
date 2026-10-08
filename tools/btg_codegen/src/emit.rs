//! Emitters: turn resolved lowering plans into generated artifacts.
//!
//! Everything here writes to the generator's `generated/` output directory and
//! NEVER into the core crate's `src/`. The emitted `.rs` files are review
//! artifacts (candidate lifter arms + test skeletons), not code that is wired
//! into the build automatically — integration is a deliberate human step.

use crate::coverage::CoverageReport;
use crate::family::classify;
use crate::rules::{resolve, template_ops_are_known, Strategy};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// One row of the resolved plan.
#[derive(Debug, Clone, Serialize)]
pub struct PlanEntry {
    pub code: String,
    pub mnemonic: String,
    pub encoding: String,
    pub status: String,
    pub family: String,
    pub strategy: String,
    pub risc_ops: Vec<String>,
    pub notes: String,
    pub ops_known: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PlanSummary {
    pub total_records: usize,
    pub instructions: usize,
    pub supported: usize,
    pub gaps: usize,
    pub auto_template: usize,
    pub manual_semantics: usize,
    pub native_fallback: usize,
    pub by_family: BTreeMap<String, usize>,
    pub gaps_by_family: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub iced_x86_version: String,
    pub summary: PlanSummary,
    /// Only the gap entries (what the generator is trying to close).
    pub entries: Vec<PlanEntry>,
}

/// Build the resolved plan for every gap record in the report.
pub fn build_plan(report: &CoverageReport) -> Plan {
    let mut summary = PlanSummary {
        total_records: report.records.len(),
        ..Default::default()
    };

    let mut entries = Vec::new();

    for rec in &report.records {
        if !rec.is_instruction {
            continue;
        }
        summary.instructions += 1;
        let family = classify(rec);
        *summary.by_family.entry(family.as_str().to_string()).or_insert(0) += 1;

        if rec.is_supported() {
            summary.supported += 1;
            continue;
        }
        if !rec.is_gap() {
            continue;
        }

        summary.gaps += 1;
        *summary
            .gaps_by_family
            .entry(family.as_str().to_string())
            .or_insert(0) += 1;

        let lowering = resolve(family, &rec.mnemonic.to_ascii_uppercase());
        match lowering.strategy {
            Strategy::AutoTemplate => summary.auto_template += 1,
            Strategy::ManualSemantics => summary.manual_semantics += 1,
            Strategy::NativeFallback => summary.native_fallback += 1,
        }

        entries.push(PlanEntry {
            code: rec.code.clone(),
            mnemonic: rec.mnemonic.clone(),
            encoding: rec.encoding.clone(),
            status: rec.status.clone(),
            family: family.as_str().to_string(),
            strategy: lowering.strategy.as_str().to_string(),
            risc_ops: lowering.risc_ops.iter().map(|s| s.to_string()).collect(),
            notes: lowering.notes.to_string(),
            ops_known: template_ops_are_known(&lowering),
        });
    }

    entries.sort_by(|a, b| {
        a.family
            .cmp(&b.family)
            .then(a.mnemonic.cmp(&b.mnemonic))
            .then(a.code.cmp(&b.code))
    });

    Plan {
        iced_x86_version: report.iced_x86_version.clone(),
        summary,
        entries,
    }
}

// ── report (markdown) ───────────────────────────────────────────────────────

pub fn render_report_md(plan: &Plan) -> String {
    let s = &plan.summary;
    let mut out = String::new();
    out.push_str("# BTG Codegen — Coverage Gap & Lowering Plan\n\n");
    if !plan.iced_x86_version.is_empty() {
        out.push_str(&format!("iced-x86: `{}`\n\n", plan.iced_x86_version));
    }
    out.push_str("## Summary\n\n");
    out.push_str("| metric | count |\n|---|---:|\n");
    out.push_str(&format!("| records | {} |\n", s.total_records));
    out.push_str(&format!("| instructions | {} |\n", s.instructions));
    out.push_str(&format!("| supported (full / lifted-no-microop) | {} |\n", s.supported));
    out.push_str(&format!("| **gaps** | **{}** |\n", s.gaps));
    out.push_str(&format!("| ↳ auto-template candidates | {} |\n", s.auto_template));
    out.push_str(&format!("| ↳ manual-semantics required | {} |\n", s.manual_semantics));
    out.push_str(&format!("| ↳ intentional native fallback | {} |\n", s.native_fallback));
    out.push('\n');

    out.push_str("## Instructions by family\n\n");
    out.push_str("| family | total | gaps |\n|---|---:|---:|\n");
    for (fam, total) in &s.by_family {
        let gaps = s.gaps_by_family.get(fam).copied().unwrap_or(0);
        out.push_str(&format!("| {fam} | {total} | {gaps} |\n"));
    }
    out.push('\n');

    out.push_str("## Auto-template candidates (review before wiring)\n\n");
    out.push_str("| code | mnemonic | enc | family | RiscOps | notes |\n|---|---|---|---|---|---|\n");
    for e in plan.entries.iter().filter(|e| e.strategy == "AUTO_TEMPLATE") {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            e.code,
            e.mnemonic,
            e.encoding,
            e.family,
            if e.risc_ops.is_empty() { "—".to_string() } else { e.risc_ops.join(", ") },
            e.notes,
        ));
    }
    out.push('\n');

    out.push_str("## Manual-semantics backlog (grouped)\n\n");
    let mut by_fam: BTreeMap<&str, Vec<&PlanEntry>> = BTreeMap::new();
    for e in plan.entries.iter().filter(|e| e.strategy == "MANUAL_SEMANTICS") {
        by_fam.entry(e.family.as_str()).or_default().push(e);
    }
    for (fam, items) in &by_fam {
        out.push_str(&format!("### {fam} ({} instructions)\n\n", items.len()));
        if let Some(first) = items.first() {
            out.push_str(&format!("_Reason:_ {}\n\n", first.notes));
        }
        let sample: Vec<String> = items.iter().take(24).map(|e| format!("`{}`", e.mnemonic)).collect();
        out.push_str(&sample.join(", "));
        if items.len() > 24 {
            out.push_str(&format!(" … (+{} more)", items.len() - 24));
        }
        out.push_str("\n\n");
    }

    out.push_str("## Native fallback (kept native by policy)\n\n");
    let native_fams: BTreeMap<&str, usize> = plan
        .entries
        .iter()
        .filter(|e| e.strategy == "NATIVE_FALLBACK")
        .fold(BTreeMap::new(), |mut acc, e| {
            *acc.entry(e.family.as_str()).or_insert(0) += 1;
            acc
        });
    out.push_str("| family | count |\n|---|---:|\n");
    for (fam, n) in &native_fams {
        out.push_str(&format!("| {fam} | {n} |\n"));
    }
    out.push('\n');

    out
}

// ── generated lifter rule skeletons (.rs artifact; not auto-compiled) ────────

pub fn render_lifter_rules_rs(plan: &Plan) -> String {
    let mut out = String::new();
    out.push_str(GENERATED_HEADER);
    out.push_str(
        "//! Candidate lifter match-arms for currently-unsupported `Code` values.\n\
         //!\n\
         //! Each arm is a SKELETON over existing RiscOps. Operand wiring (VReg/\n\
         //! Temp/Imm, effective-address lowering, width/lane params, flag\n\
         //! preservation) is left as `todo!()` for a human to complete against\n\
         //! `src/vm/risc/lifter/mod.rs`. Do NOT paste wholesale into the core.\n\n",
    );
    out.push_str("#[allow(unused)]\n");
    out.push_str("mod generated_lifter_rules {\n");
    out.push_str("    // use btg_packer::vm::risc::{RiscOp, MicroInstr, MicroOperand};\n\n");

    for e in plan.entries.iter().filter(|e| e.strategy == "AUTO_TEMPLATE") {
        out.push_str(&format!(
            "    // ── {} [{}] family={} ──\n",
            e.mnemonic, e.encoding, e.family
        ));
        out.push_str(&format!("    // {}\n", e.notes));
        out.push_str(&format!("    // Code::{} => {{\n", e.code));
        if e.risc_ops.is_empty() {
            out.push_str("    //     // no micro-op (NOP / fence); emit nothing\n");
        } else {
            for op in &e.risc_ops {
                out.push_str(&format!(
                    "    //     self.desynth.instrs.push(MicroInstr::new(RiscOp::{}{{ /* params */ }}));\n",
                    riscop_ident(op)
                ));
            }
        }
        out.push_str("    //     // TODO: wire operands / widths / flags\n");
        out.push_str("    // }\n\n");
    }

    out.push_str("}\n");
    out
}

// ── generated semantic test skeletons (.rs artifact; not auto-compiled) ──────

pub fn render_semantic_tests_rs(plan: &Plan) -> String {
    let mut out = String::new();
    out.push_str(GENERATED_HEADER);
    out.push_str(
        "//! Candidate semantic tests for auto-template lowerings.\n\
         //!\n\
         //! Each test is a skeleton: build the probe instruction, run the real\n\
         //! lifter, and assert the expected RiscOp stable-names are emitted.\n\
         //! Fill the `build_probe` body per instruction before enabling.\n\n",
    );
    out.push_str("#[cfg(test)]\n#[allow(unused)]\nmod generated_semantic_tests {\n");
    out.push_str("    // use btg_packer::vm::risc::RiscLifter;\n");
    out.push_str("    // use iced_x86::{Code, Instruction};\n\n");

    for e in plan.entries.iter().filter(|e| e.strategy == "AUTO_TEMPLATE" && !e.risc_ops.is_empty())
    {
        let test_name = format!("lifts_{}", sanitize_ident(&e.code));
        out.push_str(&format!("    // #[test]\n    // fn {test_name}() {{\n"));
        out.push_str(&format!(
            "    //     // expect RiscOps: {}\n",
            e.risc_ops.join(", ")
        ));
        out.push_str(&format!(
            "    //     let inst = Instruction::with(Code::{}); // TODO: set operands\n",
            e.code
        ));
        out.push_str("    //     let mut lifter = RiscLifter::new();\n");
        out.push_str("    //     lifter.lift_instruction(&inst).expect(\"lift\");\n");
        out.push_str("    //     let names: Vec<_> = lifter.desynth.instrs.iter()\n");
        out.push_str("    //         .map(|m| m.op.kind().stable_name()).collect();\n");
        for op in &e.risc_ops {
            out.push_str(&format!(
                "    //     assert!(names.contains(&\"{op}\"));\n"
            ));
        }
        out.push_str("    // }\n\n");
    }

    out.push_str("}\n");
    out
}

// ── generated lifter fallback (compilable; seed for src/.../generated_fallback.rs)

/// Emit a compilable `generated_fallback.rs` whose effect-free no-op class is
/// drawn straight from the coverage DB's `NopFence`-family gaps. Because the
/// match is on the mnemonic DEBUG STRING recorded by the auditor, every emitted
/// entry is guaranteed to match at runtime, and a stale entry can only fail to
/// fire — never miscompile or mis-lower. This is the artifact a human reviews
/// and copies into `src/vm/risc/lifter/generated_fallback.rs`.
pub fn render_fallback_rs(plan: &Plan) -> String {
    let hints: BTreeSet<&str> = plan
        .entries
        .iter()
        .filter(|e| e.family == "NopFence")
        .map(|e| e.mnemonic.as_str())
        .collect();

    let mut out = String::new();
    out.push_str("// @generated by tools/btg_codegen --emit-fallback\n");
    out.push_str("// Candidate for src/vm/risc/lifter/generated_fallback.rs (review before copying).\n");
    out.push_str("// Effect-free hint/fence/CET class -> no micro-op (exact in single-threaded semantics).\n\n");
    out.push_str("use super::RiscLifter;\nuse anyhow::Result;\nuse iced_x86::Instruction;\n\n");
    out.push_str("impl RiscLifter {\n");
    out.push_str("    pub(crate) fn try_generated_fallback(&mut self, inst: &Instruction) -> Result<bool> {\n");
    out.push_str("        let mnemonic = format!(\"{:?}\", inst.mnemonic());\n");
    out.push_str("        if is_effect_free_hint(&mnemonic) {\n");
    out.push_str("            return Ok(true);\n");
    out.push_str("        }\n");
    out.push_str("        Ok(false)\n");
    out.push_str("    }\n}\n\n");

    out.push_str("fn is_effect_free_hint(mnemonic: &str) -> bool {\n");
    if hints.is_empty() {
        out.push_str("    let _ = mnemonic;\n    false\n");
    } else {
        out.push_str("    matches!(\n        mnemonic,\n");
        let arms: Vec<String> = hints.iter().map(|m| format!("        \"{m}\"")).collect();
        out.push_str(&arms.join("\n            | "));
        out.push('\n');
        out.push_str("    )\n");
    }
    out.push_str("}\n");
    out
}

const GENERATED_HEADER: &str = "// @generated by tools/btg_codegen — DO NOT EDIT BY HAND.\n\
// Review artifact only; not wired into the core build.\n\n";

/// Map a RiscOp stable-name back to its Rust enum identifier (best-effort, for
/// the skeleton comments only).
fn riscop_ident(stable: &str) -> String {
    stable
        .split('_')
        .map(|part| {
            let mut c = part.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn sanitize_ident(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
        .collect()
}
