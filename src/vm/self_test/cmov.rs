// ==============================================================================
// VM self-test submodule: cmov.rs
// ==============================================================================
//
// Group D (Phase 2.1): CMOVcc. The lifter lowers every CMOVcc form to an
// existing JCC+MOV sequence (`lift_cmovcc` in lifter/control.rs), so no new
// opcodes are needed — the group is verified by lifting a block that exercises
// every condition family and executing it through BOTH the reference
// interpreter and the native VM (interp == native == expected).

use crate::vm::lifter::{diagnose_unsupported, lift_block, LiftedInstr};
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, Register};

use super::util::{interp_state, run_native, set_vreg, vreg};

/// The value every not-taken cmov destination keeps.
const SENTINEL: u64 = 0x1111_2222_3333_4444;
/// The source value a taken cmov copies.
const SRC: u64 = 0xABCD_1234_5678_9FED;

/// Run the CMOVcc group check. Returns Ok(()) iff interp and native both match.
pub(crate) fn run_cmovcc_test() -> Result<()> {
    use crate::vm::interp;

    // Lift a block that seeds ZF/SF/CF/OF/PF via `cmp rax,rax` (all clear except
    // ZF=1 and PF=1 for a zero result) then issues every CMOVcc family member.
    let mut seq: Vec<LiftedInstr> = Vec::new();
    seq.push(LiftedInstr::plain(
        Instruction::with2(Code::Cmp_rm64_r64, Register::RAX, Register::RAX).unwrap(),
    ));
    // (dst, cond code) — condition taken given ZF=1,CF=0,SF=0,OF=0,PF=1:
    //   e→T ne→F  b→F ae→T  a→F be→T  s→F ns→T  o→F no→T  p→T np→F  l→F ge→T  le→T g→F
    let cmovs: &[(iced_x86::Register, Code)] = &[
        (Register::R10, Code::Cmove_r64_rm64),
        (Register::R11, Code::Cmovne_r64_rm64),
        (Register::R12, Code::Cmovb_r64_rm64),
        (Register::R13, Code::Cmovae_r64_rm64),
        (Register::R14, Code::Cmova_r64_rm64),
        (Register::R15, Code::Cmovbe_r64_rm64),
        (Register::RDX, Code::Cmovs_r64_rm64),
        (Register::RBX, Code::Cmovns_r64_rm64),
        (Register::RSI, Code::Cmovo_r64_rm64),
        (Register::RDI, Code::Cmovno_r64_rm64),
        (Register::RBP, Code::Cmovp_r64_rm64),
        (Register::R9, Code::Cmovnp_r64_rm64),
        (Register::RCX, Code::Cmovl_r64_rm64),
        (Register::RAX, Code::Cmovge_r64_rm64),
    ];
    for (dst, code) in cmovs {
        seq.push(LiftedInstr::plain(
            Instruction::with2(*code, *dst, Register::R8).unwrap(),
        ));
    }

    let bad = diagnose_unsupported(&seq);
    assert!(bad.is_empty(), "cmov: unexpected unsupported {:?}", bad);

    let bc = lift_block(&seq, 0)?;

    // ── interpreter ────────────────────────────────────────────────────────
    let (mut st, mut mem) = interp_state();
    seed_state(&mut st);
    interp::interpret(&mut st, &mut mem, &bc)
        .map_err(|e| anyhow!("cmov interp failed: {:?}", e))?;
    let st_i = st.clone();

    // ── native VM ──────────────────────────────────────────────────────────
    let (st_n, _nb) = run_native(&bc, &[], 0, |s, _base| seed_state(s))?;

    for (dst, code) in cmovs {
        let taken = cmov_taken(*code);
        let expect = if taken { SRC } else { SENTINEL };
        let idx = dst.number() as usize;
        let vi = vreg(&st_i, idx);
        let vn = vreg(&st_n, idx);
        if vi != expect {
            return Err(anyhow!(
                "cmov interp mismatch: {:?} dst={:?} expected 0x{:X} got 0x{:X}",
                code,
                dst,
                expect,
                vi
            ));
        }
        if vn != expect {
            return Err(anyhow!(
                "cmov native mismatch: {:?} dst={:?} expected 0x{:X} got 0x{:X}",
                code,
                dst,
                expect,
                vn
            ));
        }
    }
    Ok(())
}

/// Expected taken/not-taken given ZF=1, CF=0, SF=0, OF=0, PF=1.
fn cmov_taken(code: Code) -> bool {
    use iced_x86::Code::*;
    matches!(
        code,
        Cmove_r64_rm64
            | Cmove_r32_rm32
            | Cmovae_r64_rm64
            | Cmovae_r32_rm32
            | Cmovbe_r64_rm64
            | Cmovbe_r32_rm32
            | Cmovns_r64_rm64
            | Cmovns_r32_rm32
            | Cmovno_r64_rm64
            | Cmovno_r32_rm32
            | Cmovp_r64_rm64
            | Cmovp_r32_rm32
            | Cmovge_r64_rm64
            | Cmovge_r32_rm32
            | Cmovle_r64_rm64
            | Cmovle_r32_rm32
    )
}

/// Seed vregs: RAX=0 (cmp rax,rax → ZF=1,PF=1), R8=SRC, all dests=SENTINEL.
/// `base` is 0 for the interpreter (no absolute addresses used).
fn seed_state(st: &mut [u8]) {
    set_vreg(st, 0, 0);
    set_vreg(st, 8, SRC);
    for r in [1usize, 2, 3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15] {
        set_vreg(st, r, SENTINEL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmovcc_runs_under_cargo() {
        run_cmovcc_test().expect("cmovcc group check failed");
    }
}
