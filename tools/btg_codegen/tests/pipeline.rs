//! End-to-end tests for the btg_codegen pipeline, driven by the committed
//! sample coverage fixture.

use btg_codegen::coverage::{CoverageRecord, CoverageReport};
use btg_codegen::emit::{
    build_plan, render_fallback_rs, render_lifter_rules_rs, render_report_md,
    render_semantic_tests_rs,
};
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
    assert_eq!(classify(rec_by_code(&r, "Sfence")), Family::NopFence);
    assert_eq!(classify(rec_by_code(&r, "Prefetcht0_m8")), Family::NopFence);
    assert_eq!(classify(rec_by_code(&r, "Endbr64")), Family::NopFence);
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

    // 27 instruction records + 1 non-instruction in the fixture.
    assert_eq!(s.instructions, 27);
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

#[test]
fn fallback_emits_effect_free_hints_from_db() {
    let r = fixture();
    let plan = build_plan(&r);
    let rs = render_fallback_rs(&plan);

    // Structural contract the core file relies on.
    assert!(rs.contains("fn try_generated_fallback"));
    assert!(rs.contains("fn is_effect_free_hint"));
    assert!(rs.contains("format!(\"{:?}\", inst.mnemonic())"));

    // Mnemonics observed as NopFence gaps are present, verbatim from the DB.
    assert!(rs.contains("\"Sfence\""));
    assert!(rs.contains("\"Prefetcht0\""));
    assert!(rs.contains("\"Endbr64\""));

    // An instruction with real effects must never land in the no-op class.
    assert!(!rs.contains("\"Rdrand\""));
    assert!(!rs.contains("\"Add\""));
}

#[test]
fn fallback_emits_redispatch_aliases_from_db() {
    let r = fixture();
    let plan = build_plan(&r);
    let rs = render_fallback_rs(&plan);

    assert!(rs.contains("fn alias_target"));
    // SAL aliases to SHL; the 0x82 dup aliases to its base encoding.
    assert!(rs.contains("Sal_rm64_CL => Shl_rm64_CL"));
    assert!(rs.contains("Add_rm8_imm8_82 => Add_rm8_imm8"));
    assert!(rs.contains("self.lift_instruction_inner(&aliased)"));
}

// ── Priority 1: Semantic IR / confidence tiers ───────────────────────────────

#[test]
fn semantic_template_tiers_pseudo_vs_faithful() {
    use btg_codegen::rules::{resolve, semantic_template};
    use btg_codegen::template::Confidence;

    // Pseudo lowerings (value-correct, flags not reproduced) are pinned at
    // AUTO_VALUE_ONLY and can never be auto-emitted.
    for m in ["AND", "OR", "XOR", "TEST", "NEG"] {
        let l = resolve(Family::IntegerAlu, m);
        let t = semantic_template(&l, m);
        assert_eq!(
            t.confidence,
            Confidence::AutoValueOnly,
            "{m} must be AUTO_VALUE_ONLY (pseudo lowering)"
        );
        assert!(!t.is_auto_emittable(), "{m} must never auto-emit");
    }

    // Flag-faithful scalar ALU maps 1:1 onto flag-aware ops -> AUTO_FLAG_EXACT
    // ceiling (still unproven, so still not auto-emittable yet).
    for m in ["ADD", "SUB", "CMP", "ADC", "SBB", "INC", "DEC", "NOT"] {
        let l = resolve(Family::IntegerAlu, m);
        let t = semantic_template(&l, m);
        assert_eq!(
            t.confidence,
            Confidence::AutoFlagExact,
            "{m} should carry an AUTO_FLAG_EXACT ceiling"
        );
        assert!(!t.is_auto_emittable(), "{m} is unproven -> not auto-emittable");
    }
}

#[test]
fn semantic_template_records_flag_and_memory_spec() {
    use btg_codegen::rules::{resolve, semantic_template};
    use btg_codegen::template::{ExceptionClass, Flag};

    // ADC consumes CF and defines all six arithmetic flags.
    let adc = semantic_template(&resolve(Family::IntegerAlu, "ADC"), "ADC");
    assert!(adc.flags_read.contains(&Flag::Cf));
    assert!(adc.flags_write.contains(&Flag::Of));

    // INC defines every arithmetic flag except CF.
    let inc = semantic_template(&resolve(Family::IntegerAlu, "INC"), "INC");
    assert!(!inc.flags_write.contains(&Flag::Cf));
    assert!(inc.flags_write.contains(&Flag::Zf));

    // DIV carries the divide-error fault class.
    let div = semantic_template(&resolve(Family::MulDiv, "DIV"), "DIV");
    assert_eq!(div.exception, ExceptionClass::DivideError);

    // MOV is flag-transparent and memory-capable.
    let mov = semantic_template(&resolve(Family::DataMove, "MOV"), "MOV");
    assert!(mov.flags_write.is_empty());
    assert!(mov.mem_read && mov.mem_write);
}

#[test]
fn native_and_manual_map_to_their_tiers() {
    use btg_codegen::rules::{resolve, semantic_template};
    use btg_codegen::template::Confidence;

    // Crypto is an intentional native fallback.
    let aes = semantic_template(&resolve(Family::Crypto, "AESENC"), "AESENC");
    assert_eq!(aes.confidence, Confidence::NativeFallback);

    // BMI needs hand-written semantics.
    let pdep = semantic_template(&resolve(Family::Bmi, "PDEP"), "PDEP");
    assert_eq!(pdep.confidence, Confidence::Manual);
}

// ── Priority 2: operand binder ───────────────────────────────────────────────

#[test]
fn generated_skeleton_carries_bound_operands() {
    let r = fixture();
    let plan = build_plan(&r);
    let rs = render_lifter_rules_rs(&plan);

    // The old `/* params */` placeholder is gone; operands are spelled out.
    assert!(!rs.contains("/* params */"), "operands should be bound, not placeholder");
    assert!(rs.contains("operand[0]: role="), "per-operand binding must be emitted");
    assert!(rs.contains("confidence="), "confidence tier must be surfaced");
    // A concrete role/class/width binding for a GPR slot.
    assert!(rs.contains("class=gpr"));
}

#[test]
fn plan_entries_bind_width_and_confidence() {
    let r = fixture();
    let plan = build_plan(&r);

    // Every auto-template entry should have a confidence tier and, when the DB
    // recorded operands, a non-zero primary width.
    let add = plan
        .entries
        .iter()
        .find(|e| e.mnemonic.eq_ignore_ascii_case("add"))
        .expect("fixture has ADD");
    assert_eq!(add.confidence, "AUTO_FLAG_EXACT");
    assert!(!add.operands.is_empty(), "ADD should have bound operands");
    assert!(add.width_bits > 0, "ADD primary width should be bound");

    // AND stays value-only (pseudo NOR lowering).
    if let Some(and) = plan.entries.iter().find(|e| e.mnemonic.eq_ignore_ascii_case("and")) {
        assert_eq!(and.confidence, "AUTO_VALUE_ONLY");
    }
}

// ── Priority 4: SIMD / EVEX parameter engine ─────────────────────────────────

#[test]
fn simd_params_and_evex_demotion_in_plan() {
    let r = fixture();
    let plan = build_plan(&r);

    // Scalar SS/SD forms are a single lane, not VL/elem lanes.
    if let Some(s) = plan.entries.iter().find(|e| e.mnemonic.eq_ignore_ascii_case("addss")) {
        assert_eq!(s.vector_len, 128);
        assert_eq!(s.element_bits, 32);
        assert_eq!(s.lanes, 1, "ADDSS is scalar: one lane");
    }

    // EVEX 512-bit masked form must be demoted to MANUAL (cannot auto-lower onto
    // the 128-bit slot ops) and expose its decorations + 16 packed lanes.
    if let Some(z) = plan.entries.iter().find(|e| e.vector_len == 512) {
        assert_eq!(z.confidence, "MANUAL", "EVEX 512-bit must not auto-lower");
        assert_eq!(z.lanes, 16, "512-bit / 32-bit elem = 16 lanes");
        assert!(z.masked || z.zeroing, "EVEX form should record its mask decoration");
    }

    // A 256-bit VEX vector is demoted to MANUAL (needs lane fan-out).
    if let Some(y) = plan.entries.iter().find(|e| e.vector_len == 256) {
        assert_eq!(y.confidence, "MANUAL", "256-bit vector needs lane fan-out");
    }
}

#[test]
fn simd_params_surface_in_skeleton() {
    let r = fixture();
    let plan = build_plan(&r);
    let rs = render_lifter_rules_rs(&plan);
    // Only auto-template entries reach the skeleton; at least the 128-bit packed
    // ones should print their SIMD shape.
    if plan.entries.iter().any(|e| e.strategy == "AUTO_TEMPLATE" && e.vector_len != 0) {
        assert!(rs.contains("simd: VL="), "SIMD shape must be surfaced in the skeleton");
    }
}
