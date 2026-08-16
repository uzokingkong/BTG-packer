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

use crate::vm::bytecode::{BytecodeBuilder, FLAG_MASK};
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

/// Reference for the 1-op MUL/IMUL1/DIV/IDIV accumulator pair. Returns
/// (valid, lo_out, hi_out) — `valid=false` means real x86 would raise #DE
/// (divisor 0 or quotient overflow), which the VM surfaces as an error / would
/// crash natively, so the fuzz skips those inputs.
fn muldiv_ref(op: u8, width: u8, rax: u64, rdx: u64, src: u64) -> (bool, u64, u64) {
    use crate::vm::bytecode::*;
    let w = width as u32;
    let mask: u64 = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
    let lo = |v: u64| v & mask;
    let a = lo(rax);
    let b = lo(src);

    match op {
        // unsigned MUL: RDX:RAX = RAX * src (8-bit: AX only, RDX untouched)
        OP_MUL_R_R8 => (true, (a as u16 * b as u16) as u64, rdx),
        OP_MUL_R_R16 | OP_MUL_R_R32 | OP_MUL_R_R64 => {
            let p = (a as u128) * (b as u128);
            (true, p as u64 & mask, ((p >> w) & mask as u128) as u64)
        }
        // signed IMUL1 (8-bit: AX only, RDX untouched)
        OP_IMUL1_R_R8 => {
            let p = (a as u8 as i8 as i16) as i16 * (b as u8 as i8 as i16) as i16;
            (true, (p as u16) as u64, rdx)
        }
        OP_IMUL1_R_R16 | OP_IMUL1_R_R32 | OP_IMUL1_R_R64 => {
            let sa = if w >= 64 { a as i64 as i128 } else { ((a << (64 - w)) as i64 >> (64 - w)) as i128 };
            let sb = if w >= 64 { b as i64 as i128 } else { ((b << (64 - w)) as i64 >> (64 - w)) as i128 };
            let p = (sa * sb) as u128;
            (true, p as u64 & mask, ((p >> w) & mask as u128) as u64)
        }
        // unsigned DIV (8-bit: quotient+remainder packed in AX, RDX untouched)
        OP_DIV_R_R8 => {
            let dividend = (rax & 0xFFFF) as u16;
            let d = b as u16;
            if d == 0 { return (false, 0, rdx); }
            let (q, r) = (dividend / d, dividend % d);
            (q <= 0xFF, (q as u64) | ((r as u64) << 8), rdx)
        }
        OP_DIV_R_R16 | OP_DIV_R_R32 | OP_DIV_R_R64 => {
            let dividend = if w >= 64 {
                ((rdx as u128) << 64) | (rax as u128)
            } else {
                (((lo(rdx) as u128) << w) | (lo(rax) as u128))
            };
            let d = b as u128;
            if d == 0 { return (false, 0, 0); }
            let (q, r) = (dividend / d, dividend % d);
            let fits = if w >= 64 { q <= u64::MAX as u128 } else { q < (1u128 << w) };
            (fits, q as u64 & mask, r as u64 & mask)
        }
        // signed IDIV (8-bit: packed in AX, RDX untouched)
        OP_IDIV_R_R8 => {
            let dividend = (rax & 0xFFFF) as u16 as i16;
            let d = b as u8 as i8 as i16;
            if d == 0 { return (false, 0, rdx); }
            let (q, r) = (dividend / d, dividend % d);
            ((-128..=127).contains(&(q as i32)), (q as u8 as u64) | ((r as u8 as u64) << 8), rdx)
        }
        OP_IDIV_R_R16 | OP_IDIV_R_R32 | OP_IDIV_R_R64 => {
            let sign_ext = |v: u64| -> i128 {
                if w >= 64 { v as i64 as i128 } else { ((v << (64 - w)) as i64 >> (64 - w)) as i128 }
            };
            let dividend_u: u128 = if w >= 64 {
                ((rdx as u128) << 64) | (rax as u128)
            } else {
                (lo(rax) as u128) | ((lo(rdx) as u128) << w)
            };
            let dividend: i128 = if w >= 64 {
                dividend_u as i128
            } else {
                ((dividend_u << (64 - w)) as i128) >> (64 - w)
            };
            let d = sign_ext(b);
            if d == 0 { return (false, 0, 0); }
            // i128::MIN / -1 panics in Rust; real x86 raises #DE for it too.
            if d == -1 && dividend == i128::MIN {
                return (false, 0, 0);
            }
            let q = dividend / d;
            let r = dividend % d;
            let (qmin, qmax) = match w {
                16 => (-32768i128, 32767i128),
                32 => (-2147483648i128, 2147483647i128),
                _ => (-9223372036854775808i128, 9223372036854775807i128),
            };
            let fits = q >= qmin && q <= qmax;
            (fits, (q as u64) & mask, (r as u64) & mask)
        }
        _ => (false, 0, 0),
    }
}

/// Randomized differential check for the 1-op multiply/divide accumulator
/// family (MUL/IMUL1/DIV/IDIV at 8/16/32/64). Compares the RAX(v0)/RDX(v2)
/// pair across interp == native == reference, and asserts the M1 flagless
/// contract (modelled status flags pass through unchanged). Inputs that would
/// raise #DE on real x86 (divisor 0 / quotient overflow) are skipped.
pub(crate) fn run_fuzz_muldiv_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let iters = 30;
    let dirty = FLAG_MASK & !F_DF;

    let cases: Vec<(u8, u8)> = vec![
        (OP_MUL_R_R8, 8), (OP_MUL_R_R16, 16), (OP_MUL_R_R32, 32), (OP_MUL_R_R64, 64),
        (OP_IMUL1_R_R8, 8), (OP_IMUL1_R_R16, 16), (OP_IMUL1_R_R32, 32), (OP_IMUL1_R_R64, 64),
        (OP_DIV_R_R8, 8), (OP_DIV_R_R16, 16), (OP_DIV_R_R32, 32), (OP_DIV_R_R64, 64),
        (OP_IDIV_R_R8, 8), (OP_IDIV_R_R16, 16), (OP_IDIV_R_R32, 32), (OP_IDIV_R_R64, 64),
    ];

    for (op, width) in cases {
        assert_eq!(
            crate::vm::semantics::flag_contract(op),
            (0, 0),
            "mul/div op 0x{op:02X}: must stay flagless (M1) in the contract"
        );
        let mut rng = StdRng::seed_from_u64(0x01D0_0D1E ^ (op as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut ran = 0;
        let mut skipped = 0;
        for _ in 0..(iters * 4) {
            if ran >= iters {
                break;
            }
            let (rax, rdx, src) = (rng.next_u64(), rng.next_u64(), rng.next_u64());
            let (valid, want_lo, want_hi) = muldiv_ref(op, width, rax, rdx, src);
            if !valid {
                skipped += 1;
                continue;
            }
            ran += 1;

            let mut bc = BytecodeBuilder::new();
            let bop = match width {
                8 => match op {
                    OP_MUL_R_R8 => OP_MUL_R_R8, OP_IMUL1_R_R8 => OP_IMUL1_R_R8,
                    OP_DIV_R_R8 => OP_DIV_R_R8, _ => OP_IDIV_R_R8,
                },
                16 => match op {
                    OP_MUL_R_R16 => OP_MUL_R_R16, OP_IMUL1_R_R16 => OP_IMUL1_R_R16,
                    OP_DIV_R_R16 => OP_DIV_R_R16, _ => OP_IDIV_R_R16,
                },
                32 => match op {
                    OP_MUL_R_R32 => OP_MUL_R_R32, OP_IMUL1_R_R32 => OP_IMUL1_R_R32,
                    OP_DIV_R_R32 => OP_DIV_R_R32, _ => OP_IDIV_R_R32,
                },
                _ => match op {
                    OP_MUL_R_R64 => OP_MUL_R_R64, OP_IMUL1_R_R64 => OP_IMUL1_R_R64,
                    OP_DIV_R_R64 => OP_DIV_R_R64, _ => OP_IDIV_R_R64,
                },
            };
            bc.mul_r(bop, 3);
            bc.halt();
            let prog = bc.finish();

            let (st_i, st_n) = run_prog_diff(&prog, |s| {
                // RAX=v0, RDX=v2, src=v3; dirty flags to verify flagless.
                s[STATE_FLAGS..STATE_FLAGS + 8].copy_from_slice(&dirty.to_le_bytes());
                set_vreg(s, 0, rax);
                set_vreg(s, 2, rdx);
                set_vreg(s, 3, src);
            })?;

            let name = crate::vm::bytecode::opcode_name(op);
            let (i0, i2, fi) = (vreg(&st_i, 0), vreg(&st_i, 2), flags_of(&st_i));
            let (n0, n2, fn_) = (vreg(&st_n, 0), vreg(&st_n, 2), flags_of(&st_n));
            assert_eq!(i0, want_lo, "{name}(rax=0x{rax:X},rdx=0x{rdx:X},src=0x{src:X}): interp v0 0x{i0:X} != expected 0x{want_lo:X}");
            assert_eq!(i2, want_hi, "{name}(rax=0x{rax:X},rdx=0x{rdx:X},src=0x{src:X}): interp v2 0x{i2:X} != expected 0x{want_hi:X}");
            assert_eq!(n0, want_lo, "{name}(rax=0x{rax:X},rdx=0x{rdx:X},src=0x{src:X}): native v0 0x{n0:X} != expected 0x{want_lo:X}");
            assert_eq!(n2, want_hi, "{name}(rax=0x{rax:X},rdx=0x{rdx:X},src=0x{src:X}): native v2 0x{n2:X} != expected 0x{want_hi:X}");
            assert_eq!(i0, n0, "{name}: interp v0 0x{i0:X} != native v0 0x{n0:X}");
            assert_eq!(i2, n2, "{name}: interp v2 0x{i2:X} != native v2 0x{n2:X}");
            assert_eq!(fi, dirty, "{name}: interp must be flagless, flags changed to 0x{fi:X}");
            assert_eq!(fn_, dirty, "{name}: native must be flagless, flags changed to 0x{fn_:X}");
        }
        assert!(ran > 0, "op 0x{op:02X}: no valid inputs found (all skipped)");
    }
    Ok(())
}

/// Randomized differential check for SHLD/SHRD (32/64, imm8 & CL) and ROL/ROR
/// (32, imm8). SHLD/SHRD flags (count>0): CF/PF/ZF/SF per `shift_flags`, and
/// count==0 preserves everything — the native handlers use real shld/shrd with
/// a post-op capture, so both cases match the interpreter. ROL/ROR are modelled
/// flagless on BOTH sides (real x86 defines CF/OF for them, but the VM does not
/// consume those — documented in `flag_contract`).
pub(crate) fn run_fuzz_shld_rol_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let iters = 24;
    let dirty = FLAG_MASK & !F_DF;
    let shift_contract = F_CF | F_PF | F_ZF | F_SF;

    // (name, op_imm, op_cl, is64, dst(dst,src,cnt), flags(dst,src,cnt,res))
    let cases: Vec<(
        &'static str,
        u8,
        u8,
        bool,
        fn(u64, u64, u8) -> (u64, bool),
        fn(u64, u64, u8, u64) -> u64,
    )> = vec![
        (
            "shld32", OP_SHLD_R_R_IMM8, OP_SHLD_R_R_CL, false,
            |d, s, c| if c & 31 == 0 { (d as u32 as u64, false) } else { let r = ((d as u32) << (c & 31)) | ((s as u32) >> (32 - (c & 31))); (r as u64, true) },
            |d, s, c, r| flags::shift_flags(flags::ShiftKind::Shl, d as u32, (c & 31) as u32, r as u32),
        ),
        (
            "shrd32", OP_SHRD_R_R_IMM8, OP_SHRD_R_R_CL, false,
            |d, s, c| if c & 31 == 0 { (d as u32 as u64, false) } else { let r = ((d as u32) >> (c & 31)) | ((s as u32) << (32 - (c & 31))); (r as u64, true) },
            |d, s, c, r| flags::shift_flags(flags::ShiftKind::Shr, d as u32, (c & 31) as u32, r as u32),
        ),
        (
            "shld64", OP_SHLD64_R_R_IMM8, OP_SHLD64_R_R_CL, true,
            |d, s, c| if c & 63 == 0 { (d, false) } else { let r = (d << (c & 63)) | (s >> (64 - (c & 63))); (r, true) },
            |d, s, c, r| flags::shift_flags64(flags::ShiftKind::Shl, d, (c & 63) as u32, r),
        ),
        (
            "shrd64", OP_SHRD64_R_R_IMM8, OP_SHRD64_R_R_CL, true,
            |d, s, c| if c & 63 == 0 { (d, false) } else { let r = (d >> (c & 63)) | (s << (64 - (c & 63))); (r, true) },
            |d, s, c, r| flags::shift_flags64(flags::ShiftKind::Shr, d, (c & 63) as u32, r),
        ),
    ];

    for (name, op_imm, op_cl, is64, dst_sem, fl_sem) in cases {
        for mode in ["imm8", "cl"] {
            let mut rng = StdRng::seed_from_u64(
                0x51DF_0D0E ^ ((op_imm as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)) ^ (if mode == "cl" { 0x1 } else { 0x2 }),
            );
            for _ in 0..iters {
                let dst = rng.next_u64();
                let src = rng.next_u64();
                let cnt = (rng.next_u32() & 0x7F) as u8;
                let (want_dst, changed) = dst_sem(dst, src, cnt);
                let want_flags = if changed {
                    fl_sem(dst, src, cnt, want_dst) & shift_contract
                } else {
                    0 // count==0 → all flags preserved (we seed dirty, expect unchanged)
                };

                let mut bc = BytecodeBuilder::new();
                if mode == "imm8" {
                    bc.shld_imm(op_imm, 3, 4, cnt);
                } else {
                    bc.mov_r_imm64(1, cnt as u64);
                    bc.shld_cl(op_cl, 3, 4);
                }
                bc.halt();
                let prog = bc.finish();

                let (st_i, st_n) = run_prog_diff(&prog, |s| {
                    s[STATE_FLAGS..STATE_FLAGS + 8].copy_from_slice(&dirty.to_le_bytes());
                    if is64 {
                        set_vreg(s, 3, dst);
                        set_vreg(s, 4, src);
                    } else {
                        set_vreg(s, 3, dst as u32 as u64);
                        set_vreg(s, 4, src as u32 as u64);
                    }
                    if mode == "cl" {
                        set_vreg(s, 1, cnt as u64);
                    }
                })?;

                let label = format!("{name}/{mode}(dst=0x{dst:X},src=0x{src:X},cnt={cnt})");
                let (di, fi) = (vreg(&st_i, 3), flags_of(&st_i));
                let (dn, fn_) = (vreg(&st_n, 3), flags_of(&st_n));
                assert_eq!(di, want_dst, "{label}: interp dst 0x{di:X} != expected 0x{want_dst:X}");
                assert_eq!(dn, want_dst, "{label}: native dst 0x{dn:X} != expected 0x{want_dst:X}");
                let fi_c = if changed { fi & shift_contract } else { fi & FLAG_MASK };
                let fn_c = if changed { fn_ & shift_contract } else { fn_ & FLAG_MASK };
                if changed {
                    assert_eq!(fi_c, want_flags, "{label}: interp flags 0x{fi:X} != expected 0x{want_flags:X}");
                    assert_eq!(fn_c, want_flags, "{label}: native flags 0x{fn_:X} != expected 0x{want_flags:X}");
                } else {
                    assert_eq!(fi_c, dirty, "{label}: interp must preserve flags (count==0), got 0x{fi:X}");
                    assert_eq!(fn_c, dirty, "{label}: native must preserve flags (count==0), got 0x{fn_:X}");
                }
            }
        }
    }

    // ROL/ROR (32-bit imm8): modelled flagless on both sides.
    for (name, op) in [("rol32", OP_ROL_R_IMM8), ("ror32", OP_ROR_R_IMM8)] {
        assert_eq!(
            crate::vm::semantics::flag_contract(op),
            (0, 0),
            "{name}: must stay flagless in the contract"
        );
        let mut rng = StdRng::seed_from_u64(0x9012_3456 ^ (op as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for _ in 0..iters {
            let v = rng.next_u32();
            let cnt = (rng.next_u32() & 31) as u8;
            let want = if op == OP_ROL_R_IMM8 {
                v.rotate_left(cnt as u32) as u64
            } else {
                v.rotate_right(cnt as u32) as u64
            };
            let mut bc = BytecodeBuilder::new();
            if op == OP_ROL_R_IMM8 {
                bc.rol_r_imm8(3, cnt);
            } else {
                bc.ror_r_imm8(3, cnt);
            }
            bc.halt();
            let prog = bc.finish();
            let (st_i, st_n) = run_prog_diff(&prog, |s| {
                s[STATE_FLAGS..STATE_FLAGS + 8].copy_from_slice(&dirty.to_le_bytes());
                set_vreg(s, 3, v as u64);
            })?;
            let (di, fi) = (vreg(&st_i, 3), flags_of(&st_i));
            let (dn, fn_) = (vreg(&st_n, 3), flags_of(&st_n));
            assert_eq!(di, want, "{name}(v=0x{v:X},cnt={cnt}): interp dst 0x{di:X} != expected 0x{want:X}");
            assert_eq!(dn, want, "{name}(v=0x{v:X},cnt={cnt}): native dst 0x{dn:X} != expected 0x{want:X}");
            assert_eq!(fi, dirty, "{name}: interp must be flagless, got 0x{fi:X}");
            assert_eq!(fn_, dirty, "{name}: native must be flagless, got 0x{fn_:X}");
        }
    }
    Ok(())
}

/// Run one atomic opcode through interp (mem-offset addressing) and native
/// (absolute-VA addressing) with a shared data buffer at BASE. Returns
/// (interp_mem, interp_flags, interp_vregs[0..8], native_mem, native_flags).
const ATOM_BASE: usize = 0x9000;

#[allow(clippy::too_many_arguments)]
fn run_atomic_case(
    op: u8,
    w: usize,
    mem_init: u64,
    src: u64,
    rax: u64,
    init_flags: u64,
) -> Result<(Vec<u8>, u64, [u64; 16], Vec<u8>, u64)> {
    use super::util::{interp_state, run_native_with_data, set_vreg};
    let mut b = BytecodeBuilder::new();
    match op {
        _ if op == crate::vm::bytecode::OP_CMPXCHG_MEM8_A || op == crate::vm::bytecode::OP_CMPXCHG_MEM16_A
            || op == crate::vm::bytecode::OP_CMPXCHG_MEM32_A || op == crate::vm::bytecode::OP_CMPXCHG_MEM64_A => {
            b.mem_cmpxchg_a(op, 15, 14);
        }
        _ if op == crate::vm::bytecode::OP_XADD_MEM8_A || op == crate::vm::bytecode::OP_XADD_MEM16_A
            || op == crate::vm::bytecode::OP_XADD_MEM32_A || op == crate::vm::bytecode::OP_XADD_MEM64_A => {
            b.mem_xadd_a(op, 15, 14);
        }
        _ if op == crate::vm::bytecode::OP_XCHG_MEM8_A || op == crate::vm::bytecode::OP_XCHG_MEM16_A
            || op == crate::vm::bytecode::OP_XCHG_MEM32_A || op == crate::vm::bytecode::OP_XCHG_MEM64_A => {
            b.mem_xchg_a(op, 15, 14);
        }
        _ => b.lock_inc_a(op, 15),
    }
    b.halt();
    let bc = b.finish();
    let init = mem_init.to_le_bytes();

    // interp
    let (mut st, mut mem) = super::util::interp_state();
    mem[ATOM_BASE..ATOM_BASE + 8].copy_from_slice(&init);
    st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8].copy_from_slice(&init_flags.to_le_bytes());
    set_vreg(&mut st, 15, ATOM_BASE as u64);
    set_vreg(&mut st, 14, src);
    set_vreg(&mut st, 0, rax);
    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("atomic interp failed: {:?}", e))?;
    let mut vi = [0u64; 16];
    for (i, v) in vi.iter_mut().enumerate() {
        *v = vreg(&st, i);
    }
    let fi = flags_of(&st);
    let mi = mem[ATOM_BASE..ATOM_BASE + 8].to_vec();

    // native
    let (st_n, _base, mem_n) = run_native_with_data(&bc, &init, 0, 8, |s, base| {
        s[interp::STATE_FLAGS..interp::STATE_FLAGS + 8].copy_from_slice(&init_flags.to_le_bytes());
        set_vreg(s, 15, base + ATOM_BASE as u64);
        set_vreg(s, 14, src);
        set_vreg(s, 0, rax);
    })?;
    let fn_ = flags_of(&st_n);
    Ok((mi, fi, vi, mem_n[0..8].to_vec(), fn_))
}

/// Randomized differential check for the atomic family (CMPXCHG / XADD / XCHG /
/// LOCK INC/DEC at 8/16/32/64). Interp and native must agree on the memory
/// bytes, the modelled flags (per `flag_contract`), and the touched vregs.
pub(crate) fn run_fuzz_atomic_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::flags;

    let iters = 20;
    let mask = |w: usize| -> u64 {
        match w {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            _ => u64::MAX,
        }
    };

    // XCHG: no flags; mem <-> src (upper bits preserved for 8/16).
    for (op, w) in [
        (OP_XCHG_MEM8_A, 1), (OP_XCHG_MEM16_A, 2), (OP_XCHG_MEM32_A, 4), (OP_XCHG_MEM64_A, 8),
    ] {
        let mut rng = StdRng::seed_from_u64(0xC0DE_0001 ^ (op as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for _ in 0..iters {
            let mem_init = rng.next_u64();
            let src = rng.next_u64();
            let (mi, fi, vi, mn, fn_) = run_atomic_case(op, w, mem_init, src, 0, 0)?;
            let old = mem_init & mask(w);
            let want_mem = src & mask(w);
            let want_src = match w {
                1 => (src & !0xFF) | old,
                2 => (src & !0xFFFF) | old,
                4 => old,
                _ => old,
            };
            assert_eq!(u64::from_le_bytes(mi[..8].try_into().unwrap()) & mask(w), want_mem, "xchg{w} mem");
            assert_eq!(u64::from_le_bytes(mn[..8].try_into().unwrap()) & mask(w), want_mem, "xchg{w} native mem");
            assert_eq!(vi[14], want_src, "xchg{w} src vreg");
            assert_eq!(fi, 0, "xchg{w} flags must be untouched (0x{fi:X})");
            assert_eq!(fn_, 0, "xchg{w} native flags must be untouched (0x{fn_:X})");
        }
    }

    // XADD: ADD flags, width-exact.
    for (op, w, fl) in [
        (OP_XADD_MEM8_A, 1, flags::add_flags_width(0, 0, 8)),
        (OP_XADD_MEM16_A, 2, flags::add_flags_width(0, 0, 16)),
        (OP_XADD_MEM32_A, 4, flags::add_flags(0, 0)),
        (OP_XADD_MEM64_A, 8, flags::add_flags64(0, 0)),
    ] {
        let _ = fl;
        let mut rng = StdRng::seed_from_u64(0xC0DE_0002 ^ (op as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for _ in 0..iters {
            let mem_init = rng.next_u64();
            let src = rng.next_u64();
            let (mi, fi, vi, mn, fn_) = run_atomic_case(op, w, mem_init, src, 0, 0)?;
            let a = mem_init & mask(w);
            let b = src & mask(w);
            let (want_mem, want_flags) = match w {
                1 => { let r = (a as u8).wrapping_add(b as u8) as u64; (r, flags::add_flags_width(a, b, 8)) }
                2 => { let r = (a as u16).wrapping_add(b as u16) as u64; (r, flags::add_flags_width(a, b, 16)) }
                4 => { let r = (a as u32).wrapping_add(b as u32) as u64; (r, flags::add_flags(a as u32, b as u32)) }
                _ => { let r = a.wrapping_add(b); (r, flags::add_flags64(a, b)) }
            };
            let want_src = match w {
                1 => (src & !0xFF) | (a & 0xFF),
                2 => (src & !0xFFFF) | (a & 0xFFFF),
                4 => a & 0xFFFF_FFFF,
                _ => a,
            };
            assert_eq!(u64::from_le_bytes(mi[..8].try_into().unwrap()) & mask(w), want_mem, "xadd{w} mem");
            assert_eq!(u64::from_le_bytes(mn[..8].try_into().unwrap()) & mask(w), want_mem, "xadd{w} native mem");
            assert_eq!(vi[14], want_src, "xadd{w} src vreg");
            assert_eq!(fi & FLAG_MASK, want_flags & FLAG_MASK, "xadd{w} flags 0x{fi:X} != 0x{want_flags:X}");
            assert_eq!(fn_ & FLAG_MASK, want_flags & FLAG_MASK, "xadd{w} native flags 0x{fn_:X} != 0x{want_flags:X}");
        }
    }

    // CMPXCHG: ZF set on success / cleared on failure, other flags preserved.
    for (op, w) in [
        (OP_CMPXCHG_MEM8_A, 1), (OP_CMPXCHG_MEM16_A, 2), (OP_CMPXCHG_MEM32_A, 4), (OP_CMPXCHG_MEM64_A, 8),
    ] {
        let mut rng = StdRng::seed_from_u64(0xC0DE_0003 ^ (op as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for _ in 0..iters {
            let mem_init = rng.next_u64();
            let rax = rng.next_u64();
            let src = rng.next_u64();
            let init_flags = F_CF | F_OF | F_AF | F_PF; // preserve-only flags
            let (mi, fi, vi, mn, fn_) = run_atomic_case(op, w, mem_init, src, rax, init_flags)?;
            let cur = mem_init & mask(w);
            let expected = rax & mask(w);
            let (want_mem, want_v0, zf) = if cur == expected {
                (src & mask(w), rax, true)
            } else {
                (cur, match w { 1 => (rax & !0xFF) | cur, 2 => (rax & !0xFFFF) | cur, 4 => cur, _ => cur }, false)
            };
            let want_flags = (init_flags & !F_ZF) | if zf { F_ZF } else { 0 };
            assert_eq!(u64::from_le_bytes(mi[..8].try_into().unwrap()) & mask(w), want_mem, "cmpxchg{w} mem");
            assert_eq!(u64::from_le_bytes(mn[..8].try_into().unwrap()) & mask(w), want_mem, "cmpxchg{w} native mem");
            assert_eq!(vi[0], want_v0, "cmpxchg{w} v0(RAX) 0x{:X} != 0x{want_v0:X}", vi[0]);
            assert_eq!(fi & FLAG_MASK, want_flags & FLAG_MASK, "cmpxchg{w} flags 0x{fi:X} != 0x{want_flags:X}");
            assert_eq!(fn_ & FLAG_MASK, want_flags & FLAG_MASK, "cmpxchg{w} native flags 0x{fn_:X} != 0x{want_flags:X}");
        }
    }

    // LOCK INC/DEC: INC/DEC flags, CF preserved.
    for (op, w, is_inc) in [
        (OP_LOCK_INC_MEM8_A, 1, true), (OP_LOCK_INC_MEM16_A, 2, true),
        (OP_LOCK_INC_MEM32_A, 4, true), (OP_LOCK_INC_MEM64_A, 8, true),
        (OP_LOCK_DEC_MEM8_A, 1, false), (OP_LOCK_DEC_MEM16_A, 2, false),
        (OP_LOCK_DEC_MEM32_A, 4, false), (OP_LOCK_DEC_MEM64_A, 8, false),
    ] {
        let mut rng = StdRng::seed_from_u64(0xC0DE_0004 ^ (op as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for _ in 0..iters {
            let mem_init = rng.next_u64();
            let init_flags = F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF; // dirty; CF must survive
            let (mi, fi, vi, mn, fn_) = run_atomic_case(op, w, mem_init, 0, 0, init_flags)?;
            let a = mem_init & mask(w);
            let want_mem = if is_inc { a.wrapping_add(1) & mask(w) } else { a.wrapping_sub(1) & mask(w) };
            let want_flags = match (w, is_inc) {
                (1, true) => flags::incdec_flags_width(a, 8, true, init_flags),
                (1, false) => flags::incdec_flags_width(a, 8, false, init_flags),
                (2, true) => flags::incdec_flags_width(a, 16, true, init_flags),
                (2, false) => flags::incdec_flags_width(a, 16, false, init_flags),
                (4, true) => flags::inc_flags(a as u32, init_flags),
                (4, false) => flags::dec_flags(a as u32, init_flags),
                (_, true) => flags::inc_flags64(a, init_flags),
                (_, false) => flags::dec_flags64(a, init_flags),
            };
            assert_eq!(u64::from_le_bytes(mi[..8].try_into().unwrap()) & mask(w), want_mem, "lock_{} mem", if is_inc { "inc" } else { "dec" });
            assert_eq!(u64::from_le_bytes(mn[..8].try_into().unwrap()) & mask(w), want_mem, "lock_{} native mem", if is_inc { "inc" } else { "dec" });
            assert_eq!(fi & FLAG_MASK, want_flags & FLAG_MASK, "lock_{}{} flags 0x{fi:X} != 0x{want_flags:X}", if is_inc { "inc" } else { "dec" }, w * 8);
            assert_eq!(fn_ & FLAG_MASK, want_flags & FLAG_MASK, "lock_{}{} native flags 0x{fn_:X} != 0x{want_flags:X}", if is_inc { "inc" } else { "dec" }, w * 8);
            let _ = vi;
        }
    }
    Ok(())
}

/// Randomized differential check for the float→int conversion family
/// (CVTTSS2SI / CVTSS2SI / CVTTSD2SI / CVTSD2SI). The outputs are integers and
/// deterministic — including the x86 "integer indefinite" 0x8000_0000 for
/// NaN / ±∞ / out-of-range — so interp == native == reference exactly.
pub(crate) fn run_fuzz_fpconv_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let iters = 60;

    // (name, op, is_ss, trunc)
    let cases: Vec<(&'static str, u8, bool, bool)> = vec![
        ("cvttss2si", OP_CVTTSS2SI, true, true),
        ("cvtss2si", OP_CVTSS2SI, true, false),
        ("cvttsd2si", OP_CVTTSD2SI, false, true),
        ("cvtsd2si", OP_CVTSD2SI, false, false),
    ];

    for (name, op, is_ss, trunc) in cases {
        let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_CAFE ^ (op as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for i in 0..iters {
            let bits = rng.next_u64();
            let x = if is_ss {
                f32::from_bits(bits as u32) as f64
            } else {
                f64::from_bits(bits)
            };
            // x86 reference: trunc toward zero / round-to-nearest-even, then the
            // 32-bit integer-indefinite for NaN/±∞/out-of-range.
            let r = if trunc { x.trunc() } else { x.round_ties_even() };
            let want = if !r.is_finite() || r < -2147483648.0 || r >= 2147483648.0 {
                0x8000_0000
            } else {
                (r as i32) as u32 as u64
            };

            let mut bc = BytecodeBuilder::new();
            bc.cvt_fp_int(op, 3, 4); // v3 = convert(xmm4.low)
            bc.halt();
            let prog = bc.finish();

            let (st_i, st_n) = run_prog_diff(&prog, |s| {
                let mut xb = [0u8; 16];
                if is_ss {
                    xb[0..4].copy_from_slice(&(bits as u32).to_le_bytes());
                } else {
                    xb[0..8].copy_from_slice(&bits.to_le_bytes());
                }
                s[interp::STATE_XMM + 4 * 16..interp::STATE_XMM + 4 * 16 + 16].copy_from_slice(&xb);
            })?;

            let (di, dn) = (vreg(&st_i, 3), vreg(&st_n, 3));
            let xstr = if is_ss { format!("f32 0x{:08X}", bits as u32) } else { format!("f64 0x{bits:016X}") };
            assert_eq!(di, want, "{name}#{i}({xstr}): interp 0x{di:X} != expected 0x{want:X}");
            assert_eq!(dn, want, "{name}#{i}({xstr}): native 0x{dn:X} != expected 0x{want:X}");
        }
    }
    Ok(())
}

/// Read the 16 architectural vregs from a state buffer.
fn st_vregs(st: &[u8]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (i, v) in out.iter_mut().enumerate() {
        *v = vreg(st, i);
    }
    out
}

/// 아이템 9 — 멀티스레드 진입 안전성. Reference 인터프리터는 per-invocation
/// state 를 받으므로 동시 호출에 재진입 안전해야 한다. N 개 스레드가 각자
/// 독립 state 로 같은 프로그램을 입력별로 200회씩 실행하고, 그 결과가
/// 단일스레드 참조와 완전히 일치하는지 검증한다. 만약 어떤 전역/공유 상태가
/// 끼어 있다면 여기서 flake 로 드러난다.
///
/// 이 모델은 배포 런타임의 요구사항이기도 하다: 패킹된 바이너리의 프로그램 VM 은
/// 단일 state 버퍼를 쓰므로, 멀티스레드 진입은 **스레드당 독립 state**가 필요하다
/// (이 테스트가 그 모델의 정확성을 참조 레벨에서 고정한다).
pub(crate) fn run_mt_reentrancy_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use std::sync::Arc;

    // 산술/논리/시프트/BMI/inc-dec 를 섞은 결정적 프로그램.
    let mut b = BytecodeBuilder::new();
    b.mov_r_imm64(4, 0x1122_3344_5566_7788);
    b.mov_r_imm64(5, 0xFEDC_BA98_7654_3210);
    b.binop_r_r64(OP_ADD_R_R64, 3, 4);
    b.binop_r_r64(OP_SUB_R_R64, 3, 5);
    b.binop_r_r64(OP_XOR_R_R64, 3, 4);
    b.binop_r_r64(OP_AND_R_R64, 3, 5);
    b.inc_r64(3);
    b.dec_r64(3);
    b.bsr_r(OP_BSR_R64, 6, 3);
    b.popcnt_r(OP_POPCNT_R64, 7, 3);
    b.lzcnt_r(OP_LZCNT_R64, 8, 3);
    b.halt();
    let prog = Arc::new(b.finish());

    let inputs: Vec<u64> = (0..8u64).map(|i| 0x0102_0304_0506_0708u64.wrapping_mul(i.wrapping_add(1)).wrapping_add(i)).collect();

    // 단일 스레드 참조 (입력별).
    let refs: Vec<[u64; 16]> = inputs
        .iter()
        .map(|&v| {
            let (mut st, mut mem) = super::util::interp_state();
            set_vreg(&mut st, 0, v);
            interp::interpret(&mut st, &mut mem, &prog)
                .expect("reference interp");
            st_vregs(&st)
        })
        .collect();

    // 멀티스레드: 각 스레드가 독립 state 로 같은 프로그램을 반복 실행.
    let threads: Vec<_> = inputs
        .into_iter()
        .zip(refs)
        .map(|(v, r)| {
            let prog = Arc::clone(&prog);
            std::thread::spawn(move || {
                for _ in 0..200 {
                    let (mut st, mut mem) = super::util::interp_state();
                    set_vreg(&mut st, 0, v);
                    interp::interpret(&mut st, &mut mem, &prog)
                        .expect("mt interp");
                    assert_eq!(st_vregs(&st), r, "mt reentrancy: result diverged from single-thread reference");
                }
            })
        })
        .collect();
    for t in threads {
        t.join().map_err(|_| anyhow!("mt thread panicked"))?;
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

    #[test]
    fn fuzz_muldiv_differential() {
        run_fuzz_muldiv_test().expect("mul/div randomized differential check failed");
    }

    #[test]
    fn fuzz_shld_rol_differential() {
        run_fuzz_shld_rol_test().expect("shld/shrd/rol/ror randomized differential check failed");
    }

    #[test]
    fn fuzz_atomic_differential() {
        run_fuzz_atomic_test().expect("atomic randomized differential check failed");
    }

    #[test]
    fn fuzz_fpconv_differential() {
        run_fuzz_fpconv_test().expect("float->int conversion randomized differential check failed");
    }

    #[test]
    fn mt_reentrancy() {
        run_mt_reentrancy_test().expect("multithreaded reentrancy check failed");
    }
}
