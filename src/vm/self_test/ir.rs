// ==============================================================================
// VM self-test submodule: ir.rs
// ==============================================================================
//
// v56 (Phase 2.3): the VInstr lightweight IR between lift_one's 1:1 emission
// and the final bytecode. Verifies:
//   [A] parse→emit round-trip fidelity: a no-op pipeline is byte-identical to
//       the legacy BytecodeBuilder::finish path (labels + branches resolved
//       the same, including rel8 widening to rel32).
//   [B] the optimization passes (constant copy-propagation, dead-mov
//       elimination, self-mov peephole) preserve execution semantics
//       (interp(orig) == interp(optimized)) while shrinking the stream.

use anyhow::{Result, anyhow};
use crate::vm::bytecode::{BytecodeBuilder, COND_JE, OP_ADD_R_IMM64};
use crate::vm::{interp, lifter::ir};

use super::util::{interp_state, vreg};

/// Build the same program in two fresh builders (identical label numbering):
/// returns (legacy finish() bytes, IR-pipeline bytes).
fn build_both(f: impl Fn(&mut BytecodeBuilder)) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut b1 = BytecodeBuilder::new();
    f(&mut b1);
    let legacy = b1.finish();
    let mut b2 = BytecodeBuilder::new();
    f(&mut b2);
    let (bytes, branches, labels) = b2.into_parts();
    let noop = ir::emit(&ir::parse(&bytes, &branches, &labels).unwrap()).unwrap();
    let opt = ir::run_ir_pipeline(&bytes, &branches, &labels).unwrap();
    (legacy, noop, opt)
}

/// Interpret `bc` and return the final vregs (a selected window).
fn run(bc: &[u8], seed: &[u64]) -> [u64; 20] {
    let (mut st, mut mem) = interp_state();
    for (i, &v) in seed.iter().enumerate() {
        st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8]
            .copy_from_slice(&v.to_le_bytes());
    }
    interp::interpret(&mut st, &mut mem, bc).expect("ir test interp failed");
    let mut out = [0u64; 20];
    for i in 0..20 {
        out[i] = vreg(&st, i);
    }
    out
}

/// Run the IR group check.
pub(crate) fn run_ir_test() -> Result<()> {
    // ── [A] round-trip fidelity: labels/branches/loops ──────────────────────
    {
        let (legacy, noop, _opt) = build_both(|b| {
            let loop_lbl = b.new_label();
            let done = b.new_label();
            b.mov_r_imm64(3, 42);
            b.mov_r_imm32(1, 5);
            b.mark_label(loop_lbl);
            b.test_r_r32(1, 1);
            b.jcc8(COND_JE, done);
            b.binop_r_imm64(OP_ADD_R_IMM64, 0, 7);
            b.dec_r(1);
            b.jmp8(loop_lbl);
            b.mark_label(done);
            b.mov_r_r64(4, 0);
            b.halt();
        });
        assert_eq!(noop, legacy, "[A] IR no-op pipeline must be byte-identical");
        let r = run(&noop, &[0u64; 20]);
        assert_eq!(r[0], 35, "[A] loop sum 0+7*5");
        assert_eq!(r[3], 42, "[A] imm64");
        assert_eq!(r[1], 0, "[A] counter ends at 0");
    }
    // ── [A2] rel8 widening fidelity: a far rel8 branch must widen exactly
    // like the legacy builder's widen (jcc8 -> jcc32). ────────────────────────
    {
        let (legacy, noop, _opt) = build_both(|b| {
            let far = b.new_label();
            let end = b.new_label();
            b.test_r_r32(1, 1);
            b.jcc8(COND_JE, far);
            // ~200 bytes of mov-imm64 (10 bytes each) to blow past rel8
            for i in 0..22u8 {
                b.mov_r_imm64(6, i as u64);
            }
            b.mov_r_imm32(5, 0xEE);   // fall-through marker
            b.jmp8(end);
            b.mark_label(far);
            b.mov_r_imm32(5, 7);      // taken marker
            b.mark_label(end);
            b.halt();
        });
        assert_eq!(noop, legacy, "[A2] rel8 widening must match the legacy path");
        // v1=0 -> test sets ZF=1 -> jcc JE widened branch TAKEN -> v5=7, v6=0
        let r1 = run(&legacy, &[0u64; 20]);
        assert_eq!(r1[5], 7, "[A2] widened jcc taken");
        assert_eq!(r1[6], 0, "[A2] taken: fall-through body skipped");
        // v1=3 -> ZF=0 -> not taken -> fall through -> v5=0xEE, v6=21
        let mut s2 = [0u64; 20];
        s2[1] = 3;
        let r2 = run(&legacy, &s2);
        assert_eq!(r2[5], 0xEE, "[A2] widened jcc not taken");
        assert_eq!(r2[6], 21, "[A2] fall-through body executed");
    }
    // ── [B] optimization passes: semantics preserved + stream shrinks ────────
    {
        let (legacy, _noop, opt) = build_both(|b| {
            // constant copy-propagation: mov v3, v2 -> mov v3, 0x33
            b.mov_r_imm32(2, 0x33);
            b.mov_r_r(3, 2);
            // dead mov: v5 overwritten before any read -> first mov removed
            b.mov_r_imm32(5, 0x11);
            b.mov_r_imm32(5, 0x22);
            // self-mov64: v7,v7 true no-op -> removed
            b.mov_r_imm64(7, 0xDEAD_BEEF);
            b.mov_r_r64(7, 7);
            // real work (flag writing) so the values are observable
            b.binop_r_imm64(OP_ADD_R_IMM64, 2, 1);
            b.binop_r_imm64(OP_ADD_R_IMM64, 3, 1);
            b.binop_r_imm64(OP_ADD_R_IMM64, 5, 1);
            b.binop_r_imm64(OP_ADD_R_IMM64, 7, 1);
            b.halt();
        });
        assert!(opt.len() < legacy.len(), "[B] optimized stream must shrink ({} !< {})", opt.len(), legacy.len());
        let r_legacy = run(&legacy, &[0u64; 20]);
        let r_opt = run(&opt, &[0u64; 20]);
        assert_eq!(r_legacy, r_opt, "[B] interp(legacy) != interp(optimized)");
        assert_eq!(r_opt[2], 0x34, "[B] v2");
        assert_eq!(r_opt[3], 0x34, "[B] v3 (copy-propagated)");
        assert_eq!(r_opt[5], 0x23, "[B] v5 (dead mov removed)");
        assert_eq!(r_opt[7], 0xDEAD_BEEF + 1, "[B] v7 (self-mov removed)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ir_runs_under_cargo() {
        run_ir_test().expect("IR pipeline check failed");
    }
}
