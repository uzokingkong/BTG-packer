// ==============================================================================
// VM self-test submodule: fuzz.rs
// ==============================================================================
//
// 리뷰 지적 #15 — randomized differential testing. 손으로 고른 고정 케이스가
// 아니라 시드 고정(재현 가능) RNG 로 랜덤 operand 를 뽑아, 같은 바이트코드를
// (a) reference interpreter 와 (b) native VM 두 경로로 실행해 결과 vreg 와
// flags 가 반드시 일치하는지 검증한다. 기대값은 flags.rs 참조 + 연산 의미론에서
// 직접 계산해 세 경로(interp == native == reference)를 동시에 확인한다.
//
// 커버하는 그룹:
//   * BMI1/2 BLSR/BLSMSK/BLSI/ANDN (32/64) — flags 회귀를 랜덤 operand 로.
//   * POPCNT (32/64) — ZF-only flags.
//   * 64-bit ADD/SUB/XOR/AND/OR — flags.rs 의 12쌍보다 넓은 랜덤 커버리지.

use anyhow::{anyhow, Result};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crate::vm::bytecode::FLAG_MASK;
use crate::vm::{flags, interp};
use crate::vm::interp::STATE_FLAGS;

use super::util::{run_native, set_vreg, vreg};

/// Read the modelled flags word (masked to the six status bits).
fn flags_of(st: &[u8]) -> u64 {
    u64::from_le_bytes(st[STATE_FLAGS..STATE_FLAGS + 8].try_into().unwrap()) & FLAG_MASK
}

/// Run `prog` through both the interpreter and the native VM. `seed` mutates
/// the state buffer (identical for both sides — the native variant additionally
/// receives the arena base, which state-only seeds ignore). Returns
/// (interp_state, native_state).
fn run_prog_diff(
    prog: &[u8],
    seed: impl Fn(&mut [u8]),
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (mut st, mut mem) = super::util::interp_state();
    seed(&mut st);
    interp::interpret(&mut st, &mut mem, prog)
        .map_err(|e| anyhow!("fuzz: interp failed: {:?}", e))?;
    let (st_n, _base) = run_native(prog, &[], 0, |s, _base| seed(s))?;
    Ok((st, st_n))
}

/// Seed the state with dirty flags (every status bit set, DF clear so it
/// matches the native entry stub's `cld`) plus the given operand vregs.
fn seed_state(st: &mut [u8], dirty: u64, a: u64, b: u64) {
    st[STATE_FLAGS..STATE_FLAGS + 8].copy_from_slice(&dirty.to_le_bytes());
    set_vreg(st, 4, a);
    set_vreg(st, 5, b);
}

/// Randomized differential check for the BMI group: BLSR/BLSMSK/BLSI/ANDN.
pub(crate) fn run_fuzz_bmi_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let iters = 32;
    let dirty = FLAG_MASK & !F_DF;

    // (name, op32, op64, is64, dst(a,b), flags(dst))
    let cases: Vec<(
        &'static str,
        u8,
        u8,
        bool,
        fn(u64, u64) -> u64,
        fn(u64) -> u64,
    )> = vec![
        (
            "blsr32", OP_BLSR_R32, OP_BLSR_R64, false,
            |a, _| ((a as u32) & (a as u32).wrapping_sub(1)) as u64,
            |d| flags::bls_flags(d),
        ),
        (
            "blsr64", OP_BLSR_R32, OP_BLSR_R64, true,
            |a, _| a & a.wrapping_sub(1),
            flags::bls_flags,
        ),
        (
            "blsmsk32", OP_BLSMSK_R32, OP_BLSMSK_R64, false,
            |a, _| ((a as u32) ^ (a as u32).wrapping_sub(1)) as u64,
            |d| flags::bls_flags(d),
        ),
        (
            "blsmsk64", OP_BLSMSK_R32, OP_BLSMSK_R64, true,
            |a, _| a ^ a.wrapping_sub(1),
            flags::bls_flags,
        ),
        (
            "blsi32", OP_BLSI_R32, OP_BLSI_R64, false,
            |a, _| ((a as u32) & (a as u32).wrapping_neg()) as u64,
            |d| flags::bls_flags(d),
        ),
        (
            "blsi64", OP_BLSI_R32, OP_BLSI_R64, true,
            |a, _| a & a.wrapping_neg(),
            flags::bls_flags,
        ),
        (
            "andn32", OP_ANDN_R_R32, OP_ANDN_R_R64, false,
            |a, b| ((!a as u32) & b as u32) as u64,
            |d| flags::andn_flags(d, false),
        ),
        (
            "andn64", OP_ANDN_R_R32, OP_ANDN_R_R64, true,
            |a, b| !a & b,
            |d| flags::andn_flags(d, true),
        ),
    ];

    for (name, op32, op64, is64, dst_sem, fl_sem) in cases {
        let mut rng = StdRng::seed_from_u64(0xB0B1_F00D ^ (op32 as u64).rotate_left(32));
        for _ in 0..iters {
            let a = rng.next_u64();
            let b = rng.next_u64();
            let want_dst = dst_sem(a, b);
            let want_flags = fl_sem(want_dst) & FLAG_MASK;

            let mut bc = BytecodeBuilder::new();
            let op = if is64 { op64 } else { op32 };
            match name {
                n if n.starts_with("blsr") => bc.blsr_r(op, 3, 4),
                n if n.starts_with("blsmsk") => bc.blsmsk_r(op, 3, 4),
                n if n.starts_with("blsi") => bc.blsi_r(op, 3, 4),
                _ => bc.andn_r(op, 3, 4, 5),
            }
            bc.halt();
            let prog = bc.finish();

            let (st_i, st_n) = run_prog_diff(&prog, |s| {
                if is64 {
                    seed_state(s, dirty, a, b);
                } else {
                    seed_state(s, dirty, a as u32 as u64, b as u32 as u64);
                }
            })?;

            let (di, fi) = (vreg(&st_i, 3), flags_of(&st_i));
            let (dn, fn_) = (vreg(&st_n, 3), flags_of(&st_n));
            assert_eq!(di, want_dst, "{name}(a=0x{a:X},b=0x{b:X}): interp dst 0x{di:X} != expected 0x{want_dst:X}");
            assert_eq!(dn, want_dst, "{name}(a=0x{a:X},b=0x{b:X}): native dst 0x{dn:X} != expected 0x{want_dst:X}");
            assert_eq!(fi, want_flags, "{name}(a=0x{a:X},b=0x{b:X}): interp flags 0x{fi:X} != expected 0x{want_flags:X}");
            assert_eq!(fn_, want_flags, "{name}(a=0x{a:X},b=0x{b:X}): native flags 0x{fn_:X} != expected 0x{want_flags:X}");
        }
    }
    Ok(())
}

/// Randomized differential check for POPCNT (ZF-only flags) and 64-bit
/// arithmetic/logical ops (interp == native == flags.rs reference).
pub(crate) fn run_fuzz_arith_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let iters = 24;
    let dirty = FLAG_MASK & !F_DF;

    // POPCNT 32/64: ZF iff result == 0; CF/OF/SF cleared (PF defined 0 by the
    // interpreter; native popcnt leaves PF undefined, masked out both sides).
    for (name, op, is64) in [
        ("popcnt32", OP_POPCNT_R32, false),
        ("popcnt64", OP_POPCNT_R64, true),
    ] {
        let mut rng = StdRng::seed_from_u64(0x50FF_CAFE ^ (op as u64) << 1);
        for _ in 0..iters {
            let a = rng.next_u64();
            let am = if is64 { a } else { a as u32 as u64 };
            let pc = am.count_ones() as u64;
            let want_flags = if pc == 0 { F_ZF } else { 0 } & FLAG_MASK;

            let mut bc = BytecodeBuilder::new();
            if is64 {
                bc.mov_r_imm64(4, a);
            } else {
                bc.mov_r_imm32(4, a as u32);
            }
            bc.popcnt_r(op, 3, 4);
            bc.halt();
            let prog = bc.finish();

            let (st_i, st_n) = run_prog_diff(&prog, |s| seed_state(s, dirty, am, 0))?;
            let (di, fi) = (vreg(&st_i, 3), flags_of(&st_i));
            let (dn, fn_) = (vreg(&st_n, 3), flags_of(&st_n));
            assert_eq!(di, pc, "{name}(a=0x{a:X}): interp dst 0x{di:X} != popcount {pc}");
            assert_eq!(dn, pc, "{name}(a=0x{a:X}): native dst 0x{dn:X} != popcount {pc}");
            assert_eq!(fi, want_flags, "{name}(a=0x{a:X}): interp flags 0x{fi:X} != expected 0x{want_flags:X}");
            assert_eq!(fn_, want_flags, "{name}(a=0x{a:X}): native flags 0x{fn_:X} != expected 0x{want_flags:X}");
        }
    }

    // 64-bit arithmetic/logical: wider random coverage than flags.rs (24 iters).
    let arith: Vec<(u8, fn(u64, u64) -> u64, fn(u64, u64) -> u64)> = vec![
        (OP_ADD_R_R64, |a, b| a.wrapping_add(b), |a, b| flags::add_flags64(a, b)),
        (OP_SUB_R_R64, |a, b| a.wrapping_sub(b), |a, b| flags::sub_flags64(a, b)),
        (OP_XOR_R_R64, |a, b| a ^ b, |a, b| flags::logical_flags64(a ^ b)),
        (OP_AND_R_R64, |a, b| a & b, |a, b| flags::logical_flags64(a & b)),
        (OP_OR_R_R64, |a, b| a | b, |a, b| flags::logical_flags64(a | b)),
    ];
    for (op, dst_sem, fl_sem) in arith {
        let mut rng = StdRng::seed_from_u64(
            0xADD_64 ^ (op as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        );
        for _ in 0..iters {
            let (a, b) = (rng.next_u64(), rng.next_u64());
            let want_dst = dst_sem(a, b);
            let want_flags = fl_sem(a, b) & FLAG_MASK;

            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm64(3, a);
            bc.mov_r_imm64(4, b);
            bc.binop_r_r64(op, 3, 4);
            bc.halt();
            let prog = bc.finish();

            let (st_i, st_n) = run_prog_diff(&prog, |s| seed_state(s, dirty, a, b))?;
            let (di, fi) = (vreg(&st_i, 3), flags_of(&st_i));
            let (dn, fn_) = (vreg(&st_n, 3), flags_of(&st_n));
            assert_eq!(di, want_dst, "op64 0x{op:02X}(a=0x{a:X},b=0x{b:X}): interp dst 0x{di:X} != expected 0x{want_dst:X}");
            assert_eq!(dn, want_dst, "op64 0x{op:02X}(a=0x{a:X},b=0x{b:X}): native dst 0x{dn:X} != expected 0x{want_dst:X}");
            assert_eq!(fi, want_flags, "op64 0x{op:02X}(a=0x{a:X},b=0x{b:X}): interp flags 0x{fi:X} != expected 0x{want_flags:X}");
            assert_eq!(fn_, want_flags, "op64 0x{op:02X}(a=0x{a:X},b=0x{b:X}): native flags 0x{fn_:X} != expected 0x{want_flags:X}");
        }
    }
    Ok(())
}

/// Randomized differential check for the bit-scan/count family whose flag
/// semantics are the subtlest: TZCNT / LZCNT / BSR / BSF (32/64). References
/// are computed in Rust and locked against the real-hardware probe in
/// `vm::semantics` (CF=1 iff src==0, ZF follows the result for TZCNT/LZCNT;
/// ZF=1 iff src==0 for BSR/BSF). Each op's flags are compared only within its
/// documented contract (semantics::flag_contract) — undefined bits never fail.
pub(crate) fn run_fuzz_bitscan_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::semantics;

    let iters = 40;
    let dirty = FLAG_MASK & !F_DF;

    // (name, op, is64, width, dst(a), flags(a, dst), contract_mask)
    let cases: Vec<(
        &'static str,
        u8,
        bool,
        u32,
        fn(u64, u32) -> u64,
        fn(u64, u64) -> u64,
        u64,
    )> = vec![
        (
            "tzcnt32", OP_TZCNT_R32, false, 32,
            |a, w| if a == 0 { w as u64 } else { (a as u32).trailing_zeros() as u64 },
            |a, d| (if a == 0 { F_CF } else { 0 }) | (if d == 0 { F_ZF } else { 0 }),
            F_CF | F_ZF,
        ),
        (
            "lzcnt32", OP_LZCNT_R32, false, 32,
            |a, w| if a == 0 { w as u64 } else { (a as u32).leading_zeros() as u64 },
            |a, d| (if a == 0 { F_CF } else { 0 }) | (if d == 0 { F_ZF } else { 0 }),
            F_CF | F_ZF,
        ),
        (
            "lzcnt64", OP_LZCNT_R64, true, 64,
            |a, w| if a == 0 { w as u64 } else { a.leading_zeros() as u64 },
            |a, d| (if a == 0 { F_CF } else { 0 }) | (if d == 0 { F_ZF } else { 0 }),
            F_CF | F_ZF,
        ),
        (
            "bsr32", OP_BSR_R32, false, 32,
            |a, w| if a == 0 { 0 } else { (w - 1 - (a as u32).leading_zeros()) as u64 },
            |a, _| if a == 0 { F_ZF } else { 0 },
            F_ZF,
        ),
        (
            "bsr64", OP_BSR_R64, true, 64,
            |a, w| if a == 0 { 0 } else { (w - 1 - a.leading_zeros()) as u64 },
            |a, _| if a == 0 { F_ZF } else { 0 },
            F_ZF,
        ),
        (
            "bsf32", OP_BSF_R32, false, 32,
            |a, _| if a == 0 { 0 } else { (a as u32).trailing_zeros() as u64 },
            |a, _| if a == 0 { F_ZF } else { 0 },
            F_ZF,
        ),
        (
            "bsf64", OP_BSF_R64, true, 64,
            |a, _| if a == 0 { 0 } else { a.trailing_zeros() as u64 },
            |a, _| if a == 0 { F_ZF } else { 0 },
            F_ZF,
        ),
    ];

    for (name, op, is64, width, dst_sem, fl_sem, contract) in cases {
        assert_eq!(
            semantics::flag_contract(op).0,
            contract,
            "{name}: flag_contract mismatch (semantics table out of sync with fuzz)"
        );
        let mut rng = StdRng::seed_from_u64(0xB175C3A4 ^ (op as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for _ in 0..iters {
            let a = rng.next_u64();
            let am = if is64 { a } else { a as u32 as u64 };
            let want_dst = dst_sem(am, width);
            let want_flags = fl_sem(am, want_dst) & contract;

            let mut bc = BytecodeBuilder::new();
            if is64 {
                bc.mov_r_imm64(4, a);
            } else {
                bc.mov_r_imm32(4, a as u32);
            }
            match name {
                n if n.starts_with("tzcnt") => bc.tzcnt_r(op, 3, 4),
                n if n.starts_with("lzcnt") => bc.lzcnt_r(op, 3, 4),
                n if n.starts_with("bsr") => bc.bsr_r(op, 3, 4),
                _ => bc.bsf_r(op, 3, 4),
            }
            bc.halt();
            let prog = bc.finish();

            let (st_i, st_n) = run_prog_diff(&prog, |s| seed_state(s, dirty, am, 0))?;
            let (di, fi) = (vreg(&st_i, 3), flags_of(&st_i));
            let (dn, fn_) = (vreg(&st_n, 3), flags_of(&st_n));
            assert_eq!(di, want_dst, "{name}(a=0x{a:X}): interp dst 0x{di:X} != expected 0x{want_dst:X}");
            assert_eq!(dn, want_dst, "{name}(a=0x{a:X}): native dst 0x{dn:X} != expected 0x{want_dst:X}");
            assert_eq!(fi & contract, want_flags, "{name}(a=0x{a:X}): interp flags 0x{fi:X} != expected 0x{want_flags:X}");
            assert_eq!(fn_ & contract, want_flags, "{name}(a=0x{a:X}): native flags 0x{fn_:X} != expected 0x{want_flags:X}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_bmi_differential() {
        run_fuzz_bmi_test().expect("BMI randomized differential check failed");
    }

    #[test]
    fn fuzz_arith_differential() {
        run_fuzz_arith_test().expect("arith/popcnt randomized differential check failed");
    }

    #[test]
    fn fuzz_bitscan_differential() {
        run_fuzz_bitscan_test().expect("bitscan randomized differential check failed");
    }
}
