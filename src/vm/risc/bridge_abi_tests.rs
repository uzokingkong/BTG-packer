// ==============================================================================
// WS2 (readccc §4.6): NativeCallBridge full-state-transparency differential guard
// ==============================================================================
// The reference `RiscProgram::eval_state` treats `RiscOp::NativeCallBridge` as an
// acknowledged no-op stub (stream consumption + full VM-state preservation). This
// is the §2.3 contract of `docs/architecture/function-atomicity-bridge-spec.md`:
// the bridge must NOT change any virtual register / temp / flag / vsp / stack /
// mem. These tests pin that invariant so a future bridge implementation that
// clobbers VM state is caught immediately.
//
// Linear block-level equivalence only — no holistic output-diff equivalence.
// ==============================================================================

use crate::vm::risc::{MicroInstr, RiscOp, RiscProgram};

fn state_of(instrs: &[RiscOp]) -> crate::vm::risc::RiscEvalState {
    let prog = RiscProgram::new(instrs.iter().map(|op| MicroInstr::new(*op)).collect());
    // exercise non-trivial initial registers so any clobber is observable
    let mut init = [0u64; 16];
    for (i, r) in init.iter_mut().enumerate() {
        *r = (i as u64)
            .wrapping_mul(0x9E3779B97F4A7C15)
            .wrapping_add(0x1122334455667788);
    }
    prog.eval_state(&init)
}

/// A program containing only NativeCallBridge(es) must produce the same final VM
/// state as an empty program (all regs/temps/flags/vsp/stack/mem preserved).
#[test]
fn bridge_noop_preserves_full_state() {
    let empty = state_of(&[]);
    let bridged = state_of(&[
        RiscOp::NativeCallBridge,
        RiscOp::NativeCallBridge,
        RiscOp::NativeCallBridge,
        RiscOp::Halt,
    ]);
    assert_eq!(
        empty, bridged,
        "NativeCallBridge must not alter any VM state"
    );
}

/// Sandwiching a bridge between register-mutating ops must not change the result
/// relative to the same ops without the bridge (the bridge is transparent).
/// Uses Nor (the primitive from which all boolean logic is de-synthesised) so the
/// flags path is also exercised.
#[test]
fn bridge_mid_program_is_transparent() {
    use crate::vm::risc::{MicroOperand, RiscOp::*};

    // Program WITHOUT bridge: mov r0=0x1234; mov r1=0x5678; nor r2 = ~(r0|r1); halt
    let no_bridge = RiscProgram::new(vec![
        MicroInstr::new(Mov)
            .with_dst(MicroOperand::VReg(0))
            .with_imm(0x1234),
        MicroInstr::new(Mov)
            .with_dst(MicroOperand::VReg(1))
            .with_imm(0x5678),
        MicroInstr::new(Nor)
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::VReg(1)),
        MicroInstr::new(Halt),
    ]);
    // Program WITH a bridge injected between the moves and the nor
    let with_bridge = RiscProgram::new(vec![
        MicroInstr::new(Mov)
            .with_dst(MicroOperand::VReg(0))
            .with_imm(0x1234),
        MicroInstr::new(Mov)
            .with_dst(MicroOperand::VReg(1))
            .with_imm(0x5678),
        MicroInstr::new(NativeCallBridge),
        MicroInstr::new(Nor)
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::VReg(1)),
        MicroInstr::new(Halt),
    ]);

    let init = [0u64; 16];
    let a = no_bridge.eval_state(&init);
    let b = with_bridge.eval_state(&init);
    assert_eq!(
        a, b,
        "injected NativeCallBridge must be semantically transparent"
    );
}

// ==============================================================================
// WS2.2 (readccc §4.6 / function-atomicity-bridge-spec §2.4): reentrant callback
// & vtable/indirect-dispatch test matrix.
//
// Differential discipline: linear block-level equivalence only (no holistic
// output-diff equivalence). These tests model the boundary scenarios at the
// RISC virtual-state level and assert that VM state is preserved/restored
// across re-entrancy and that indirect dispatch lands on the ownership
// boundary (entry-only) without corrupting the VM.
// ==============================================================================

/// native→callback→VM reentrancy: the caller pushes VM state on the virtual
/// stack, enters a "callback" sub-VM (VmCallBridge), and resumes — the outer VM
/// state must be bit-identical to a run that performed the same pushes/pops
/// without ever calling the callback (block-level equivalence).
#[test]
fn reentrant_callback_preserves_outer_vm_state() {
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscOp, RiscProgram};
    use std::collections::HashMap;

    // Callback sub-VM (id=7): RAX = 0xDEAD; also mutates regs[5] and pushes/pops.
    let mut sub = crate::vm::risc::RiscDesynthesizer::new();
    sub.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0xDEAD),
        MicroOperand::Imm64(0),
    );
    sub.emit_add(
        MicroOperand::VReg(5),
        MicroOperand::Imm64(0x11),
        MicroOperand::Imm64(0),
    );
    sub.instrs.push(MicroInstr::new(RiscOp::Halt));
    let sub_prog = RiscProgram::new(sub.instrs);

    // Outer program: R1=0xCAFE; push R1; R2=0x777; push R2; VmCallBridge(7);
    // pop R3; pop R4; R5 = R0 (callback return copied after reentry).
    let mut outer = crate::vm::risc::RiscDesynthesizer::new();
    outer.emit_add(
        MicroOperand::VReg(1),
        MicroOperand::Imm64(0xCAFE),
        MicroOperand::Imm64(0),
    );
    outer.emit_push(MicroOperand::VReg(1));
    outer.emit_add(
        MicroOperand::VReg(2),
        MicroOperand::Imm64(0x777),
        MicroOperand::Imm64(0),
    );
    outer.emit_push(MicroOperand::VReg(2));
    outer
        .instrs
        .push(MicroInstr::new(RiscOp::VmCallBridge).with_imm(7));
    outer.emit_pop(MicroOperand::VReg(3));
    outer.emit_pop(MicroOperand::VReg(4));
    outer.instrs.push(
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::VReg(5))
            .with_src1(MicroOperand::VReg(0)),
    );
    outer.instrs.push(MicroInstr::new(RiscOp::Halt));
    let outer_prog = RiscProgram::new(outer.instrs);

    // Without the callback: same pushes/pops, RAX stays 0 → R5=0.
    let mut plain = crate::vm::risc::RiscDesynthesizer::new();
    plain.emit_add(
        MicroOperand::VReg(1),
        MicroOperand::Imm64(0xCAFE),
        MicroOperand::Imm64(0),
    );
    plain.emit_push(MicroOperand::VReg(1));
    plain.emit_add(
        MicroOperand::VReg(2),
        MicroOperand::Imm64(0x777),
        MicroOperand::Imm64(0),
    );
    plain.emit_push(MicroOperand::VReg(2));
    plain.emit_pop(MicroOperand::VReg(3));
    plain.emit_pop(MicroOperand::VReg(4));
    plain.instrs.push(
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::VReg(5))
            .with_src1(MicroOperand::VReg(0)),
    );
    plain.instrs.push(MicroInstr::new(RiscOp::Halt));
    let plain_prog = RiscProgram::new(plain.instrs);

    let mut sub_vms = HashMap::new();
    sub_vms.insert(7, sub_prog);
    let outer_prog = RiscProgram::with_sub_vms(outer_prog.instrs, sub_vms);

    let mut init = [0u64; 16];
    for (i, r) in init.iter_mut().enumerate() {
        *r = (i as u64)
            .wrapping_mul(0x9E3779B97F4A7C15)
            .wrapping_add(0x1122334455667788);
    }
    let st = outer_prog.eval_state(&init);
    let stp = plain_prog.eval_state(&init);

    // Re-entrancy must restore the outer stack LIFO exactly (R3=0x777, R4=0xCAFE).
    assert_eq!(
        st.regs[3], 0x777,
        "outer stack top preserved across callback re-entry"
    );
    assert_eq!(
        st.regs[4], 0xCAFE,
        "outer second frame preserved across callback re-entry"
    );
    // Only RAX (and regs[5] which the callback mutated) may differ from the plain run;
    // everything else — incl. temps/flags/vsp/stack — must be bit-identical.
    assert_eq!(st.regs[0], 0xDEAD, "callback return value lands in RAX");
    assert_eq!(
        st.regs[5], 0xDEAD,
        "caller copies callback return after re-entry"
    );
    for i in 1..16 {
        if i == 5 {
            continue; // callback mutated regs[5]
        }
        assert_eq!(
            st.regs[i], stp.regs[i],
            "outer vreg {} identical with/without callback",
            i
        );
    }
    assert_eq!(
        st.flags, stp.flags,
        "outer flags preserved across callback re-entry"
    );
    assert_eq!(st.vsp, stp.vsp, "outer virtual stack pointer preserved");
    assert_eq!(
        st.stack, stp.stack,
        "outer virtual stack contents preserved"
    );
}

/// Deep (nested) reentrancy: callback that itself calls a VM — outer state must
/// survive two nested levels of save/restore.
#[test]
fn doubly_nested_callback_preserves_outer_state() {
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscOp, RiscProgram};
    use std::collections::HashMap;

    // innermost (id=9): RAX = 0x1234
    let mut inn = crate::vm::risc::RiscDesynthesizer::new();
    inn.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0x1234),
        MicroOperand::Imm64(0),
    );
    inn.instrs.push(MicroInstr::new(RiscOp::Halt));
    let inn_prog = RiscProgram::new(inn.instrs);

    // mid callback (id=8): VmCallBridge(9), then RAX = RAX + 1 → 0x1235.
    // mid must carry its own sub_vms map so its inner VmCallBridge(9) resolves.
    let mut mid = crate::vm::risc::RiscDesynthesizer::new();
    mid.instrs
        .push(MicroInstr::new(RiscOp::VmCallBridge).with_imm(9));
    mid.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::VReg(0),
        MicroOperand::Imm64(1),
    );
    mid.instrs.push(MicroInstr::new(RiscOp::Halt));
    let mut mid_subs = HashMap::new();
    mid_subs.insert(9, inn_prog.clone());
    let mid_prog = RiscProgram::with_sub_vms(mid.instrs, mid_subs);

    let mut outer = crate::vm::risc::RiscDesynthesizer::new();
    outer.emit_add(
        MicroOperand::VReg(1),
        MicroOperand::Imm64(0xABCD),
        MicroOperand::Imm64(0),
    );
    outer.emit_push(MicroOperand::VReg(1));
    outer.emit_add(
        MicroOperand::VReg(2),
        MicroOperand::Imm64(0x5555),
        MicroOperand::Imm64(0),
    );
    outer
        .instrs
        .push(MicroInstr::new(RiscOp::VmCallBridge).with_imm(8));
    outer.emit_pop(MicroOperand::VReg(3));
    outer.instrs.push(MicroInstr::new(RiscOp::Halt));
    let outer_prog = RiscProgram::new(outer.instrs);

    let mut sub_vms = HashMap::new();
    sub_vms.insert(8, mid_prog);
    sub_vms.insert(9, inn_prog);
    let outer_prog = RiscProgram::with_sub_vms(outer_prog.instrs, sub_vms);

    let st = outer_prog.eval_state(&[0u64; 16]);
    assert_eq!(
        st.regs[0], 0x1235,
        "nested callback chain return (0x1234+1)"
    );
    assert_eq!(
        st.regs[3], 0xABCD,
        "outer stack frame preserved across double nesting"
    );
    assert_eq!(
        st.regs[2], 0x5555,
        "outer live register preserved across double nesting"
    );
}

/// vtable / indirect-call dispatch crossing the VM↔native ownership boundary:
/// an indirect target loaded from a virtual "vtable" slot selects between a
/// VM-owned callee block and a native-kept stub; the VM must resume correctly
/// with state intact and only the selected path observable.
#[test]
fn vtable_indirect_dispatch_at_boundary() {
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscOp, RiscProgram};

    // Program with two dispatch targets reached through a register-indirect
    // branch (the vtable slot value in vreg[1] IS the entry-point offset).
    //   ip0: RAX = 0
    //   ip1: VirtualBranch(Always, src1=VReg(1))  -> indirect dispatch
    //   ip2: (target A) RAX += 1; Halt
    //   ip5: (target B) RAX += 0x100; Halt
    let prog = RiscProgram::new(vec![
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::VReg(0))
            .with_imm(0), // RAX=0
        MicroInstr::new(RiscOp::VirtualBranch {
            cond: crate::vm::risc::BranchCondition::Always,
        })
        .with_src1(MicroOperand::VReg(1)), // ip = vtable slot value
        MicroInstr::new(RiscOp::Add { width: 8 })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::Imm64(1)),
        MicroInstr::new(RiscOp::Halt),
        MicroInstr::new(RiscOp::Halt), // pad (ip4, never reached)
        MicroInstr::new(RiscOp::Add { width: 8 })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::Imm64(0x100)),
        MicroInstr::new(RiscOp::Halt),
    ]);

    let mut init = [0u64; 16];
    init[1] = 2; // vtable slot → target A entry (ip 2)
    let st_a = prog.eval_state(&init);
    assert_eq!(st_a.regs[0], 1, "indirect dispatch to VM callee A");

    let mut init = [0u64; 16];
    init[1] = 5; // vtable slot → target B entry (ip 5)
    let st_b = prog.eval_state(&init);
    assert_eq!(st_b.regs[0], 0x100, "indirect dispatch to VM callee B");

    // Ownership-boundary property: dispatch lands on a function entry (ip2/ip5),
    // never mid-function. Both adds are carry-free (no CF), confirming the branch
    // itself does not corrupt the arithmetic flag path.
    assert_eq!(
        st_a.flags & crate::vm::risc::VFLAG_CF,
        0,
        "callee A add is carry-free"
    );
    assert_eq!(
        st_b.flags & crate::vm::risc::VFLAG_CF,
        0,
        "callee B add is carry-free"
    );
}
