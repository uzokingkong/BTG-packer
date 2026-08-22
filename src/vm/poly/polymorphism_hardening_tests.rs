// ==============================================================================
// WS3 (T2 hardening): per-seed handler/opcode polymorphism verification
// ==============================================================================
// P6-series hardening makes each build's VM ISA seed-dependent: the same logical
// RISC op must map to a *different* opcode in different builds, and the opcode
// map must be injective within a build. This prevents static signature reuse of
// the dispatch table / handler identities across builds (handler polymorphism +
// metadata minimization — the dispatch table no longer leaks a stable opcode→
// handler identity).
//
// These are hardening *property* tests (not holistic output-diff equivalence),
// consistent with the existing P6/P6-1..P6-3 tests.
// ==============================================================================

use crate::vm::poly::isa_spec::VirtualIsaSpec;
use crate::vm::risc::RiscOp;

/// Two different ISA seeds must produce different opcode assignments for the
/// same logical op — build-to-build handler polymorphism.
#[test]
fn per_seed_opcode_map_polymorphism() {
    // field-less RiscOps only (safe to construct directly)
    let ops = [
        RiscOp::Mov,
        RiscOp::Nor,
        RiscOp::NativeCallBridge,
        RiscOp::Halt,
        RiscOp::AddWithCarry,
    ];
    let s1 = VirtualIsaSpec::from_seed(0xAAAA_AAAA_AAAA_AAAA);
    let s2 = VirtualIsaSpec::from_seed(0x5555_5555_5555_5555);

    let mut differing = 0usize;
    for op in &ops {
        let a = s1.opcode_for(*op);
        let b = s2.opcode_for(*op);
        assert!(
            a.is_some() && b.is_some(),
            "op {op:?} must be encodable in both specs"
        );
        if a != b {
            differing += 1;
        }
    }
    assert!(
        differing > 0,
        "different seeds must produce different opcode maps (polymorphism)"
    );
}

/// The opcode map must be injective within a single build — no two distinct
/// ops may share an opcode (else the dispatcher could not recover semantics).
#[test]
fn opcode_map_is_injective_per_build() {
    let spec = VirtualIsaSpec::from_seed(0x1234_5678_9ABC_DEF0);
    let ops = [
        RiscOp::Mov,
        RiscOp::Nor,
        RiscOp::NativeCallBridge,
        RiscOp::Halt,
        RiscOp::AddWithCarry,
    ];
    let mut seen = std::collections::HashSet::new();
    for op in &ops {
        let code = spec
            .opcode_for(*op)
            .unwrap_or_else(|| panic!("op {op:?} must be encodable"));
        assert!(
            seen.insert(code),
            "opcode for {op:?} collides within a single build"
        );
    }
}
