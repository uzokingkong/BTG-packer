// ==============================================================================
// VM self-test submodule: string_ops.rs
// ==============================================================================
//
// Group C (Phase 2.1): string ops. MOVS / STOS / LODS / SCAS / CMPS are lowered
// to explicit VM loops in lifter/string.rs (all widths, REP + non-REP, REPE/REPNE
// ZF stop). No new opcodes are needed. This test decodes real x86 string
// instructions (so the rep-prefix / width is exact), lifts each, and executes it
// through BOTH the reference interpreter and the native VM, checking registers
// and memory (interp == native == expected).

use anyhow::{Result, anyhow};
use crate::vm::bytecode::F_ZF;
use crate::vm::interp;
use crate::vm::lifter::{LiftedInstr, lift_block, diagnose_unsupported};
use iced_x86::{Decoder, DecoderOptions, Instruction};

use super::util::{interp_state, run_native, set_vreg, vreg};

/// Data-buffer base offset inside the 64 KiB mem arena (shared by interp/native).
const BASE: u64 = 0x9000;

/// Decode a small x86 byte sequence (with 64-bit address size) into an
/// Instruction. Keeps the REP prefix and width exact without guessing iced
/// constructor names.
fn decode(code: &[u8]) -> Instruction {
    let mut dec = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
    dec.decode()
}

/// Lift `inst`, run it through interp and native VM with the given seed
/// (`Fn(&mut [u8], base)` — base is 0 for interp, arena base for native) and a
/// data buffer placed at mem offset `BASE`. Returns (interp_state, native_state)
/// with the native state's address vregs (rsi/rdi) normalized back to
/// base-relative offsets, so interp and native results compare equal.
fn run_case(
    inst: Instruction,
    data: &[u8],
    seed: impl Fn(&mut [u8], u64),
) -> Result<(Vec<u8>, Vec<u8>)> {
    use crate::vm::interp;
    let seq = vec![LiftedInstr::plain(inst)];
    let bad = diagnose_unsupported(&seq);
    assert!(bad.is_empty(), "string: unexpected unsupported {:?}", bad);
    let bc = lift_block(&seq, 0)?;
    let (mut st, mut mem) = interp_state();
    mem[BASE as usize..BASE as usize + data.len()].copy_from_slice(data);
    seed(&mut st, 0);
    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("string interp failed: {:?}", e))?;
    let (mut st_n, vbase) = run_native(&bc, data, 0, seed)?;
    // Native address vregs are absolute VAs (arena base + offset); the interp
    // holds base-relative offsets. Normalize rsi(6)/rdi(7) back to offsets.
    for r in [6usize, 7] {
        let cur = vreg(&st_n, r);
        if cur >= vbase {
            set_vreg(&mut st_n, r, cur - vbase);
        }
    }
    Ok((st, st_n))
}

fn addr(base: u64, off: u64) -> u64 {
    base + BASE + off
}

/// Read the STATE_FLAGS word of a state buffer.
fn flags(state: &[u8]) -> u64 {
    u64::from_le_bytes(
        state[crate::vm::interp::STATE_FLAGS..crate::vm::interp::STATE_FLAGS + 8]
            .try_into()
            .unwrap(),
    )
}

/// Run the string-ops group check. Returns Ok(()) iff interp and native match.
pub(crate) fn run_string_ops_test() -> Result<()> {
    run_cases()
}

fn run_cases() -> Result<()> {
    use iced_x86::Register;

    // ── rep stosq ─────────────────────────────────────────────────────────────
    {
        let data = vec![0u8; 0x100];
        let seed = |s: &mut [u8], base: u64| {
            set_vreg(s, 0, 0x1122_3344_5566_7788u64);
            set_vreg(s, 7, addr(base, 0x000));
            set_vreg(s, 1, 3);
        };
        let (si, sn) = run_case(decode(&[0xF3, 0x48, 0xAB]), &data, seed)?;
        for st in [&si, &sn] {
            assert_eq!(vreg(st, 7), addr(0, 0x18), "stosq rdi advance");
            assert_eq!(vreg(st, 1), 0, "stosq rcx zeroed");
        }
    }

    // ── rep movsq: copy 2 qwords [rsi] -> [rdi] ───────────────────────────────
    {
        let mut data = vec![0u8; 0x200];
        data[0x000..0x010].copy_from_slice(&[1u8; 16]);
        data[0x010..0x020].copy_from_slice(&[2u8; 16]);
        let seed = |s: &mut [u8], base: u64| {
            set_vreg(s, 6, addr(base, 0x000)); // rsi
            set_vreg(s, 7, addr(base, 0x100)); // rdi
            set_vreg(s, 1, 2); // rcx
        };
        let (si, sn) = run_case(decode(&[0xF3, 0x48, 0xA5]), &data, seed)?;
        for st in [&si, &sn] {
            assert_eq!(vreg(st, 6), addr(0, 0x010), "movsq rsi");
            assert_eq!(vreg(st, 7), addr(0, 0x110), "movsq rdi");
            assert_eq!(vreg(st, 1), 0, "movsq rcx");
        }
    }

    // ── rep lodsq: load 2 qwords [rsi] -> rax (last one wins) ─────────────────
    {
        let mut data = vec![0u8; 0x100];
        data[0x000..0x008].copy_from_slice(&0xAAAA_BBBB_CCCC_DDDDu64.to_le_bytes());
        data[0x008..0x010].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        let seed = |s: &mut [u8], base: u64| {
            set_vreg(s, 6, addr(base, 0x000)); // rsi
            set_vreg(s, 1, 2); // rcx
        };
        let (si, sn) = run_case(decode(&[0xF3, 0x48, 0xAD]), &data, seed)?;
        for st in [&si, &sn] {
            assert_eq!(vreg(st, 0), 0x1111_2222_3333_4444, "lodsq rax");
            assert_eq!(vreg(st, 6), addr(0, 0x010), "lodsq rsi");
            assert_eq!(vreg(st, 1), 0, "lodsq rcx");
        }
    }

    // ── repe scasq: stop at the first qword != rax ────────────────────────────
    // buffer = {0xAA, 0xBB, 0xCC}; rax = 0xAA; rcx = 3 → 1 match, stop on BB.
    // x86-exact: the terminating iteration still advances rdi and decrements
    // rcx (rdi points PAST the mismatch, 1 iteration left, ZF=0 at exit).
    {
        let mut data = vec![0u8; 0x100];
        data[0x000..0x008].copy_from_slice(&0xAAu64.to_le_bytes());
        data[0x008..0x010].copy_from_slice(&0xBBu64.to_le_bytes());
        data[0x010..0x018].copy_from_slice(&0xCCu64.to_le_bytes());
        let seed = |s: &mut [u8], base: u64| {
            set_vreg(s, 0, 0xAA); // rax
            set_vreg(s, 7, addr(base, 0x000)); // rdi
            set_vreg(s, 1, 3); // rcx
        };
        let (si, sn) = run_case(decode(&[0xF3, 0x48, 0xAF]), &data, seed)?;
        for st in [&si, &sn] {
            assert_eq!(vreg(st, 7), addr(0, 0x010), "scasq rdi (past mismatch)");
            assert_eq!(vreg(st, 1), 1, "scasq rcx (1 iteration left)");
            assert_eq!(flags(st) & F_ZF, 0, "scasq exit flags ZF=0 (mismatch)");
        }
    }

    // ── repne scasq: stop at the first qword == rax ───────────────────────────
    // buffer = {0xBB, 0xAA, 0xCC}; rax = 0xAA; rcx = 3 → match at index 1.
    {
        let mut data = vec![0u8; 0x100];
        data[0x000..0x008].copy_from_slice(&0xBBu64.to_le_bytes());
        data[0x008..0x010].copy_from_slice(&0xAAu64.to_le_bytes());
        data[0x010..0x018].copy_from_slice(&0xCCu64.to_le_bytes());
        let seed = |s: &mut [u8], base: u64| {
            set_vreg(s, 0, 0xAA); // rax
            set_vreg(s, 7, addr(base, 0x000)); // rdi
            set_vreg(s, 1, 3); // rcx
        };
        let (si, sn) = run_case(decode(&[0xF2, 0x48, 0xAF]), &data, seed)?;
        for st in [&si, &sn] {
            assert_eq!(vreg(st, 7), addr(0, 0x010), "repne scasq rdi (past match)");
            assert_eq!(vreg(st, 1), 1, "repne scasq rcx (1 iteration left)");
            assert_eq!(flags(st) & F_ZF, F_ZF, "repne scasq exit flags ZF=1 (match)");
        }
    }

    // ── movsq (non-REP): single copy, rcx untouched ───────────────────────────
    {
        let mut data = vec![0u8; 0x200];
        data[0x000..0x008].copy_from_slice(&0xDEAD_BEEF_CAFE_F00Du64.to_le_bytes());
        let seed = |s: &mut [u8], base: u64| {
            set_vreg(s, 6, addr(base, 0x000)); // rsi
            set_vreg(s, 7, addr(base, 0x100)); // rdi
            set_vreg(s, 1, 0x77); // rcx (must stay unchanged)
        };
        let (si, sn) = run_case(decode(&[0x48, 0xA5]), &data, seed)?;
        for st in [&si, &sn] {
            assert_eq!(vreg(st, 6), addr(0, 0x008), "movsq rsi");
            assert_eq!(vreg(st, 7), addr(0, 0x108), "movsq rdi");
            assert_eq!(vreg(st, 1), 0x77, "movsq non-rep rcx unchanged");
        }
    }

    // ── rep stosb: fill rcx bytes at [rdi] with AL (low byte of rax) ──────────
    {
        let data = vec![0u8; 0x100];
        let seed = |s: &mut [u8], base: u64| {
            set_vreg(s, 0, 0xAA); // rax (AL = 0xAA)
            set_vreg(s, 7, addr(base, 0x000)); // rdi
            set_vreg(s, 1, 5); // rcx
        };
        let (si, sn) = run_case(decode(&[0xF3, 0xAA]), &data, seed)?;
        for st in [&si, &sn] {
            assert_eq!(vreg(st, 7), addr(0, 0x005), "stosb rdi");
            assert_eq!(vreg(st, 1), 0, "stosb rcx");
        }
    }

    // ── v64: REP string ops preserve RFLAGS (stos/movs/lods) ─────────────────
    // x86: rep stos/movs/lods 는 RFLAGS 를 변경하지 않는다. 루프 제어(TEST/DEC)가
    // 플래그를 덮어쓰지 않도록 진입 시점을 저장·복원해야 한다 (interp == native).
    {
        let data = vec![0u8; 0x100];
        let seed = |s: &mut [u8], base: u64| {
            set_vreg(s, 0, 0x1122_3344_5566_7788u64);
            set_vreg(s, 6, addr(base, 0x000)); // rsi
            set_vreg(s, 7, addr(base, 0x040)); // rdi
            set_vreg(s, 1, 3);
            s[crate::vm::interp::STATE_FLAGS..crate::vm::interp::STATE_FLAGS + 8]
                .copy_from_slice(&0x8D5u64.to_le_bytes()); // CF|PF|AF|ZF|SF|OF 전부
        };
        let (si, sn) = run_case(decode(&[0xF3, 0x48, 0xAB]), &data, seed)?; // rep stosq
        for st in [&si, &sn] {
            assert_eq!(flags(st), 0x8D5, "rep stosq must preserve RFLAGS");
        }
        let (si, sn) = run_case(decode(&[0xF3, 0x48, 0xA5]), &data, seed)?; // rep movsq
        for st in [&si, &sn] {
            assert_eq!(flags(st), 0x8D5, "rep movsq must preserve RFLAGS");
        }
        let (si, sn) = run_case(decode(&[0xF3, 0x48, 0xAD]), &data, seed)?; // rep lodsq
        for st in [&si, &sn] {
            assert_eq!(flags(st), 0x8D5, "rep lodsq must preserve RFLAGS");
        }
    }

    // ── v64: 0-count REP string ops — 아무 것도 하지 않고 RFLAGS 유지 ────────
    // x86: rcx==0 이면 REP 명령은 실행되지 않는다 (flags 불변, 포인터 불변).
    {
        let data = vec![0u8; 0x100];
        let seed = |s: &mut [u8], base: u64| {
            set_vreg(s, 0, 0xAA);
            set_vreg(s, 7, addr(base, 0x000));
            set_vreg(s, 1, 0); // rcx = 0
            s[crate::vm::interp::STATE_FLAGS..crate::vm::interp::STATE_FLAGS + 8]
                .copy_from_slice(&0x8D5u64.to_le_bytes());
        };
        let (si, sn) = run_case(decode(&[0xF3, 0xAA]), &data, seed)?; // rep stosb, rcx=0
        for st in [&si, &sn] {
            assert_eq!(vreg(st, 7), addr(0, 0x000), "0-count rep stosb rdi unchanged");
            assert_eq!(vreg(st, 1), 0, "0-count rep stosb rcx");
            assert_eq!(flags(st), 0x8D5, "0-count rep stosb must preserve RFLAGS");
        }
        let (si, sn) = run_case(decode(&[0xF3, 0x48, 0xAF]), &data, seed)?; // repe scasq, rcx=0
        for st in [&si, &sn] {
            assert_eq!(vreg(st, 7), addr(0, 0x000), "0-count repe scasq rdi unchanged");
            assert_eq!(flags(st), 0x8D5, "0-count repe scasq must preserve RFLAGS");
        }
    }

    // ── v65: DF direction — std; rep movsb copies BACKWARD (DF=1) ─────────────
    // Sequence: `std; rep movsb` — [rsi] -> [rdi] with rsi/rdi DECREMENTED each
    // iteration. The whole thing must run identically through interp and native.
    {
        let mut data = vec![0u8; 0x200];
        // source block [BASE+0x010..BASE+0x014] = {1,2,3,4}
        data[0x010..0x014].copy_from_slice(&[1u8, 2, 3, 4]);
        let seq = vec![
            LiftedInstr::plain(decode(&[0xFD])),                      // std
            LiftedInstr::plain(decode(&[0xF3, 0xA4])),                // rep movsb
        ];
        let bad = diagnose_unsupported(&seq);
        assert!(bad.is_empty(), "std/rep movsb: unexpected unsupported {:?}", bad);
        let bc = lift_block(&seq, 0)?;
        let (mut st, mut mem) = interp_state();
        // source {1,2,3,4} at mem[0x9010..0x9014]; rsi starts at the LAST byte.
        mem[0x9010..0x9014].copy_from_slice(&[1u8, 2, 3, 4]);
        set_vreg(&mut st, 6, addr(0, 0x013)); // rsi = last byte of source
        set_vreg(&mut st, 7, addr(0, 0x023)); // rdi = last byte of dest
        set_vreg(&mut st, 1, 4);     // rcx = 4
        interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("std interp failed: {:?}", e))?;
        assert_eq!(vreg(&st, 6), addr(0, 0x00F), "std rep movsb rsi decremented");
        assert_eq!(vreg(&st, 7), addr(0, 0x01F), "std rep movsb rdi decremented");
        assert_eq!(&mem[0x9020..0x9024], &[1u8, 2, 3, 4], "std rep movsb copied backward");
        assert_eq!(vreg(&st, 1), 0, "std rep movsb rcx");
        let (mut st_n, vbase) = run_native(&bc, &data, 0, |s, base| {
            set_vreg(s, 6, addr(base, 0x013));
            set_vreg(s, 7, addr(base, 0x023));
            set_vreg(s, 1, 4);
        })?;
        // normalize native absolute VAs back to base-relative (like run_case)
        for r in [6usize, 7] {
            let cur = vreg(&st_n, r);
            if cur >= vbase {
                set_vreg(&mut st_n, r, cur - vbase);
            }
        }
        assert_eq!(vreg(&st_n, 6), addr(0, 0x00F), "std rep movsb native rsi");
        assert_eq!(vreg(&st_n, 7), addr(0, 0x01F), "std rep movsb native rdi");
        assert_eq!(vreg(&st_n, 1), 0, "std rep movsb native rcx");
        let _ = vbase;
    }

    // ── v65: cld; rep stosq — forward fill after clearing DF ─────────────────
    {
        let data = vec![0u8; 0x100];
        let seq = vec![
            LiftedInstr::plain(decode(&[0xFC])), // cld (DF=0)
            LiftedInstr::plain(decode(&[0xF3, 0x48, 0xAB])), // rep stosq
        ];
        let bad = diagnose_unsupported(&seq);
        assert!(bad.is_empty(), "cld/rep stosq: unexpected unsupported {:?}", bad);
        let bc = lift_block(&seq, 0)?;
        let (mut st, mut mem) = interp_state();
        set_vreg(&mut st, 0, 0x1122_3344_5566_7788u64);
        set_vreg(&mut st, 7, addr(0, 0x000));
        set_vreg(&mut st, 1, 3);
        interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("cld interp failed: {:?}", e))?;
        assert_eq!(vreg(&st, 7), addr(0, 0x018), "cld rep stosq rdi advanced forward");
        assert_eq!(mem[0x9000..0x9008], 0x1122_3344_5566_7788u64.to_le_bytes());
        // native parity: rep stosq forward after cld
        let (mut st_n, vbase) = run_native(&bc, &data, 0, |s, base| {
            set_vreg(s, 0, 0x1122_3344_5566_7788u64);
            set_vreg(s, 7, addr(base, 0x000));
            set_vreg(s, 1, 3);
        })?;
        let cur = vreg(&st_n, 7);
        if cur >= vbase {
            set_vreg(&mut st_n, 7, cur - vbase);
        }
        assert_eq!(vreg(&st_n, 7), addr(0, 0x018), "cld rep stosq native rdi");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_ops_runs_under_cargo() {
        run_string_ops_test().expect("string ops group check failed");
    }
}
