// ==============================================================================
// VM self-test submodule: lock_incdec.rs
// ==============================================================================
//
// v55: LOCK-prefixed atomic INC/DEC (Rust refcount bump/drop, the last
// `--text-vm` coverage hole). OP_LOCK_INC/DEC_MEM{8,16,32,64}_A are built
// directly from the registry opcodes and run through BOTH the reference
// interpreter and the native VM, comparing the final memory bytes AND the
// status flags (INC/DEC semantics: width-exact OF/SF/ZF/AF/PF, CF preserved).
// A lift smoke test also decodes real `lock inc/dec [rdi]` bytes end-to-end.

use crate::vm::bytecode::{BytecodeBuilder, FLAG_MASK};
use crate::vm::{bytecode, interp};
use anyhow::{anyhow, Result};

use super::util::{interp_state, run_native_with_data, set_vreg};

/// Data-buffer offset inside the mem arena (shared by interp/native).
const BASE: usize = 0x9000;

fn flags_of(st: &[u8]) -> u64 {
    u64::from_le_bytes(
        st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8]
            .try_into()
            .unwrap(),
    )
}

fn set_flags(st: &mut [u8], f: u64) {
    st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8].copy_from_slice(&f.to_le_bytes());
}

/// Run one lock inc/dec case: operand at data[0..w] (u64 seed value), address
/// in v3. Returns (interp_bytes, interp_flags, native_bytes, native_flags).
fn run_case(
    op: u8,
    seed_val: u64,
    w: usize,
    init_flags: u64,
) -> Result<(Vec<u8>, u64, Vec<u8>, u64)> {
    let mut b = BytecodeBuilder::new();
    b.lock_inc_a(op, 3);
    b.halt();
    let bc = b.finish();

    // interp
    let (mut st, mut mem) = interp_state();
    mem[BASE..BASE + 8].copy_from_slice(&seed_val.to_le_bytes());
    set_vreg(&mut st, 3, BASE as u64);
    set_flags(&mut st, init_flags);
    interp::interpret(&mut st, &mut mem, &bc)
        .map_err(|e| anyhow!("lock_incdec interp failed: {:?}", e))?;

    // native
    let (st_n, _vbase, mem_n) =
        run_native_with_data(&bc, &seed_val.to_le_bytes(), 0, 8, |s, base| {
            set_vreg(s, 3, base + BASE as u64);
            set_flags(s, init_flags);
        })?;
    Ok((
        mem[BASE..BASE + w].to_vec(),
        flags_of(&st),
        mem_n[0..w].to_vec(),
        flags_of(&st_n),
    ))
}

/// Run the lock-inc/dec group check.
pub(crate) fn run_lock_incdec_test() -> Result<()> {
    use bytecode::*;
    let f = |op: u8, seed: u64, w: usize, flags: u64| run_case(op, seed, w, flags);

    // (name, op, seed value, width, initial flags, expected u64 result, expected flags)
    let cases: Vec<(&str, u8, u64, usize, u64, u64, u64)> = vec![
        // inc64: 41 -> 42, no flags
        ("inc64", OP_LOCK_INC_MEM64_A, 41, 8, 0, 42, 0),
        // dec64: 1 -> 0 (ZF=1; low byte 0x00 -> PF=1)
        ("dec64_zf", OP_LOCK_DEC_MEM64_A, 1, 8, 0, 0, F_ZF | F_PF),
        // inc64: 0x7FFF..+1 -> 0x8000.. (SF/OF/AF/PF; incoming CF preserved)
        (
            "inc64_keep_cf",
            OP_LOCK_INC_MEM64_A,
            0x7FFF_FFFF_FFFF_FFFF,
            8,
            F_CF | F_AF | F_PF | F_ZF | F_SF | F_OF,
            0x8000_0000_0000_0000u64,
            F_CF | F_SF | F_OF | F_AF | F_PF,
        ),
        // inc32: 0xFFFF_FFFF -> 0 (ZF/AF/PF; OF=0, SF=0, no CF — INC never sets CF)
        (
            "inc32_wrap_zf",
            OP_LOCK_INC_MEM32_A,
            0xFFFF_FFFF,
            4,
            0,
            0,
            F_ZF | F_AF | F_PF,
        ),
        // dec32: 0x8000_0000 -> 0x7FFF_FFFF (OF=1, AF=1, PF=1; SF=0)
        (
            "dec32_of",
            OP_LOCK_DEC_MEM32_A,
            0x8000_0000,
            4,
            0,
            0x7FFF_FFFF,
            F_OF | F_AF | F_PF,
        ),
        // inc16: 0x00FF -> 0x0100 (AF + PF)
        (
            "inc16",
            OP_LOCK_INC_MEM16_A,
            0x00FF,
            2,
            0,
            0x0100,
            F_AF | F_PF,
        ),
        // inc8: 0xFF -> 0x00 (ZF/AF/PF; incoming CF preserved)
        (
            "inc8_wrap_keep_cf",
            OP_LOCK_INC_MEM8_A,
            0xFF,
            1,
            F_CF,
            0x00,
            F_CF | F_ZF | F_AF | F_PF,
        ),
        // dec8: 0x00 -> 0xFF (SF/AF/PF; incoming CF preserved)
        (
            "dec8_wrap_keep_cf",
            OP_LOCK_DEC_MEM8_A,
            0x00,
            1,
            F_CF,
            0xFF,
            F_CF | F_SF | F_AF | F_PF,
        ),
    ];
    for (name, op, seed, w, infl, want_v, want_f) in cases {
        let (ib, ifl, nb, nfl) = f(op, seed, w, infl)?;
        let want_b = &want_v.to_le_bytes()[..w];
        assert_eq!(
            ib, want_b,
            "{} interp bytes: {:?} != {:?}",
            name, ib, want_b
        );
        assert_eq!(
            nb, want_b,
            "{} native bytes: {:?} != {:?}",
            name, nb, want_b
        );
        assert_eq!(
            ifl & FLAG_MASK,
            want_f & FLAG_MASK,
            "{} interp flags: 0x{:X} != 0x{:X}",
            name,
            ifl,
            want_f
        );
        assert_eq!(
            nfl & FLAG_MASK,
            want_f & FLAG_MASK,
            "{} native flags: 0x{:X} != 0x{:X}",
            name,
            nfl,
            want_f
        );
    }

    // ── lift smoke test: decode real `lock inc/dec [rdi]` bytes ─────────────
    {
        use crate::vm::lifter::{diagnose_unsupported, lift_block, LiftedInstr};
        use iced_x86::{Decoder, DecoderOptions};
        let raw: [u8; 8] = [
            0xF0, 0x48, 0xFF, 0x07, // lock inc qword [rdi]
            0xF0, 0x48, 0xFF, 0x0F, // lock dec qword [rdi]
        ];
        let mut dec = Decoder::with_ip(64, &raw, 0, DecoderOptions::NONE);
        let seq: Vec<LiftedInstr> = (0..2).map(|_| LiftedInstr::plain(dec.decode())).collect();
        let bad = diagnose_unsupported(&seq);
        assert!(bad.is_empty(), "lock inc/dec lift: unsupported {:?}", bad);
        let bc = lift_block(&seq, 0)?;
        let seed: u64 = 0x1122_3344_5566_7788;
        let (ib, _ifl, nb, _nfl) = {
            let (mut st, mut mem) = interp_state();
            mem[BASE..BASE + 8].copy_from_slice(&seed.to_le_bytes());
            set_vreg(&mut st, 7, BASE as u64); // rdi
            interp::interpret(&mut st, &mut mem, &bc)
                .map_err(|e| anyhow!("lock lift interp failed: {:?}", e))?;
            let (mut st_n, _vbase, mem_n) =
                run_native_with_data(&bc, &seed.to_le_bytes(), 0, 8, |s, base| {
                    set_vreg(s, 7, base + BASE as u64);
                })?;
            set_vreg(&mut st_n, 7, 0);
            (
                mem[BASE..BASE + 8].to_vec(),
                0u64,
                mem_n[0..8].to_vec(),
                0u64,
            )
        };
        assert_eq!(
            ib,
            seed.to_le_bytes(),
            "lift lock inc+dec round-trip (interp)"
        );
        assert_eq!(
            nb,
            seed.to_le_bytes(),
            "lift lock inc+dec round-trip (native)"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_incdec_runs_under_cargo() {
        run_lock_incdec_test().expect("LOCK inc/dec group check failed");
    }
}
