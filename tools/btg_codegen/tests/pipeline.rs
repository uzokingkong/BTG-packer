//! End-to-end tests for the btg_codegen pipeline, driven by the committed
//! sample coverage fixture.

use btg_codegen::coverage::{CoverageRecord, CoverageReport};
use btg_codegen::emit::{build_plan, render_lifter_rules_rs, render_report_md, render_semantic_tests_rs};
use btg_codegen::family::{classify, Family};
use btg_codegen::rules::{resolve, template_ops_are_known, Strategy};
use std::path::PathBuf;

fn fixture() -> CoverageReport {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("fixtures/sample_vm_coverage.json");
    CoverageReport::load(&p).expect("load fixture")
}

fn rec_by_code<'a>(report: &'a CoverageReport, code: &str) -> &'a CoverageRecord {
    report
        .records
        .iter()
        .find(|r| r.code == code)
        .unwrap_or_else(|| panic!("fixture missing code {code}"))
}

#[test]
fn classifies_representative_families() {
    let r = fixture();
    assert_eq!(classify(rec_by_code(&r, "Add_rm64_r64")), Family::IntegerAlu);
    assert_eq!(classify(rec_by_code(&r, "Shld_rm64_r64_imm8")), Family::ShiftRotate);
    assert_eq!(classify(rec_by_code(&r, "Popcnt_r64_rm64")), Family::BitManip);
    assert_eq!(classify(rec_by_code(&r, "Xadd_rm64_r64")), Family::Atomic);
    assert_eq!(classify(rec_by_code(&r, "Paddd_mm_mmm64")), Family::SsePackedInt);
    assert_eq!(classify(rec_by_code(&r, "Addss_xmm_xmmm32")), Family::SseFloat);
    assert_eq!(classify(rec_by_code(&r, "VEX_Vpaddd_ymm_ymm_ymmm256")), Family::AvxVex);
    assert_eq!(
        classify(rec_by_code(&r, "EVEX_Vaddps_zmm_k1z_zmm_zmmm512b32")),
        Family::Avx512Evex
    );
    assert_eq!(classify(rec_by_code(&r, "Rdrand_r64")), Family::Random);
    assert_eq!(classify(rec_by_code(&r, "Aesenc_xmm_xmmm128")), Family::Crypto);
    assert_eq!(classify(rec_by_code(&r, "Tileloadd_tmm_sibmem")), Family::Amx);
    assert_eq!(classify(rec_by_code(&r, "Xsave_mem")), Family::StateSave);
    assert_eq!(classify(rec_by_code(&r, "In_AL_imm8")), Family::SystemPrivileged);
    assert_eq!(classify(rec_by_code(&r, "Movsq_m64_m64")), Family::StringOp);
    assert_eq!(classify(rec_by_code(&r, "Fadd_m32fp")), Family::X87);
    assert_eq!(classify(rec_by_code(&r, "Nopd")), Family::NopFence);
    // BMI is VEX-encoded but must not be mistaken for AVX.
    assert_eq!(classify(rec_by_code(&r, "Andnd_r32_r32_rm32")), Family::Bmi);
}

#[test]
fn resolves_expected_strategies() {
    let add = resolve(Family::IntegerAlu, "ADD");
    assert_eq!(add.strategy, Strategy::AutoTemplate);
    assert_eq!(add.risc_ops, vec!["add"]);

    let sub = resolve(Family::IntegerAlu, "SUB");
    assert_eq!(sub.strategy, Strategy::AutoTemplate);
    assert_eq!(sub.risc_ops, vec!["sub_with_borrow"]);

    assert_eq!(resolve(Family::Random, "RDRAND").strategy, Strategy::NativeFallback);
    assert_eq!(resolve(Family::Amx, "TILELOADD").strategy, Strategy::NativeFallback);
    assert_eq!(resolve(Family::Avx512Evex, "VADDPS").strategy, Strategy::ManualSemantics);
    assert_eq!(resolve(Family::Bmi, "ANDN").strategy, Strategy::ManualSemantics);

    // RCL rotates through carry: no direct op -> manual.
    assert_eq!(resolve(Family::ShiftRotate, "RCL").strategy, Strategy::ManualSemantics);
}

#[test]
fn every_auto_template_references_only_known_riscops() {
    // This is the core integrity guarantee enforced by `--strict` in CI:
    // the generator must never propose a RiscOp the core does not implement.
    let r = fixture();
    let plan = build_plan(&r);
    for e in &plan.entries {
        if e.strategy == "AUTO_TEMPLATE" {
            assert!(
                e.ops_known,
                "auto-template for {} references unknown RiscOp(s): {:?}",
                e.code, e.risc_ops
            );
        }
    }
    // Spot-check the validator directly too.
    assert!(template_ops_are_known(&resolve(Family::MulDiv, "IMUL")));
}

#[test]
fn plan_summary_is_consistent() {
    let r = fixture();
    let plan = build_plan(&r);
    let s = &plan.summary;

    // 22 instruction records + 1 non-instruction in the fixture.
    assert_eq!(s.instructions, 22);
    assert!(s.gaps > 0);
    // Buckets partition the gap set exactly.
    assert_eq!(s.auto_template + s.manual_semantics + s.native_fallback, s.gaps);
    assert_eq!(plan.entries.len(), s.gaps);

    // Known native-only families land in native fallback.
    let native: Vec<&str> = plan
        .entries
        .iter()
        .filter(|e| e.strategy == "NATIVE_FALLBACK")
        .map(|e| e.mnemonic.as_str())
        .collect();
    for want in ["Rdrand", "Aesenc", "Tileloadd", "Xsave", "In", "Fadd"] {
        assert!(native.contains(&want), "{want} should be native fallback");
    }

    // Clean reuse of existing RiscOps shows up as auto-template.
    let auto: Vec<&str> = plan
        .entries
        .iter()
        .filter(|e| e.strategy == "AUTO_TEMPLATE")
        .map(|e| e.mnemonic.as_str())
        .collect();
    for want in ["Sub", "Popcnt", "Paddd", "Addss", "Shld", "Bt", "Xadd"] {
        assert!(auto.contains(&want), "{want} should be an auto-template candidate");
    }
}

#[test]
fn emitters_produce_wellformed_artifacts() {
    let r = fixture();
    let plan = build_plan(&r);

    let md = render_report_md(&plan);
    assert!(md.starts_with("# BTG Codegen"));
    assert!(md.contains("Auto-template candidates"));

    let lifter = render_lifter_rules_rs(&plan);
    assert!(lifter.contains("@generated by tools/btg_codegen"));
    assert!(lifter.contains("Code::"));

    let tests = render_semantic_tests_rs(&plan);
    assert!(tests.contains("@generated by tools/btg_codegen"));

    // The machine-readable plan round-trips as valid JSON.
    let json = serde_json::to_string(&plan).expect("serialize plan");
    let back: serde_json::Value = serde_json::from_str(&json).expect("parse plan");
    assert!(back.get("summary").is_some());
    assert!(back.get("entries").is_some());
}
