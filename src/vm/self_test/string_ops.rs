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
    // buffer = {0xAA, 0xAA, 0xBB}; rax = 0xAA; rcx = 3 → 2 matches then stop.
    {
        let mut data = vec![0u8; 0x100];
        data[0x000..0x008].copy_from_slice(&0xAAu64.to_le_bytes());
        data[0x008..0x010].copy_from_slice(&0xAAu64.to_le_bytes());
        data[0x010..0x018].copy_from_slice(&0xBBu64.to_le_bytes());
        let seed = |s: &mut [u8], base: u64| {
            set_vreg(s, 0, 0xAA); // rax
            set_vreg(s, 7, addr(base, 0x000)); // rdi
            set_vreg(s, 1, 3); // rcx
        };
        let (si, sn) = run_case(decode(&[0xF3, 0x48, 0xAF]), &data, seed)?;
        for st in [&si, &sn] {
            // stopped at the mismatch (not advanced past it); 1 iteration left
            assert_eq!(vreg(st, 7), addr(0, 0x010), "scasq rdi (points at mismatch)");
            assert_eq!(vreg(st, 1), 1, "scasq rcx (1 iteration left)");
        }
    }

    // ── repne scasq: stop at the first qword == rax ───────────────────────────
    // buffer = {0xBB, 0xBB, 0xAA}; rax = 0xAA; rcx = 3 → match at index 2.
    {
        let mut data = vec![0u8; 0x100];
        data[0x000..0x008].copy_from_slice(&0xBBu64.to_le_bytes());
        data[0x008..0x010].copy_from_slice(&0xBBu64.to_le_bytes());
        data[0x010..0x018].copy_from_slice(&0xAAu64.to_le_bytes());
        let seed = |s: &mut [u8], base: u64| {
            set_vreg(s, 0, 0xAA); // rax
            set_vreg(s, 7, addr(base, 0x000)); // rdi
            set_vreg(s, 1, 3); // rcx
        };
        let (si, sn) = run_case(decode(&[0xF2, 0x48, 0xAF]), &data, seed)?;
        for st in [&si, &sn] {
            // stopped at the match (not advanced past it); 1 iteration left
            assert_eq!(vreg(st, 7), addr(0, 0x010), "repne scasq rdi (at match)");
            assert_eq!(vreg(st, 1), 1, "repne scasq rcx (1 iteration left)");
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
