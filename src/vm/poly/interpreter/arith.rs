// ==============================================================================
// BTG - Polymorphic Interpreter: integer/bit composite ops - split from interpreter.rs
// ==============================================================================

use crate::vm::poly::isa_spec::VirtualIsaSpec;
use crate::vm::risc::VirtualFlags;

/// `width`바이트 폭의 비트 마스크.
pub(crate) fn width_mask_interp(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// R4: x86 CVT(T)Sx2SI — eval_state `cvt_f64_int`(참조)와 동일.
/// NaN / 무한 / out-of-range 는 "integer indefinite" (32비트 dst: 0x8000_0000,
/// 64비트 dst: 0x8000_0000_0000_0000). Rust `as i64` 는 포화시켜 사용 불가.
pub(crate) fn cvt_f64_int_interp(f: f64, dst_bits: u8, truncate: bool) -> u64 {
    let r = if truncate {
        f.trunc()
    } else {
        round_ties_even_interp(f) as f64
    };
    match dst_bits {
        4 => {
            if !r.is_finite() || r < -2147483648.0 || r >= 2147483648.0 {
                0x8000_0000
            } else {
                r as i32 as u32 as u64
            }
        }
        _ => {
            if !r.is_finite() || r < -9_223_372_036_854_775_808.0 || r >= 9_223_372_036_854_775_808.0 {
                0x8000_0000_0000_0000
            } else {
                r as i64 as u64
            }
        }
    }
}

/// R4: round-half-to-even (banker's rounding) — eval_state `round_ties_even`와 동일.
fn round_ties_even_interp(x: f64) -> i64 {
    let fl = x.floor();
    let diff = x - fl;
    if diff == 0.5 {
        let f = fl as i64;
        if f % 2 == 0 { f } else { f + 1 }
    } else {
        x.round() as i64
    }
}

/// `bits` 비트 값 `v`를 i128 로 부호 확장 (bits < 128).
pub(crate) fn sign_extend_i128_interp(v: u128, bits: u32) -> i128 {
    let shift = 128 - bits;
    ((v << shift) as i128) >> shift
}

/// 인터프리터 dst 저장 — `store_operand`와 동일.
pub(crate) fn interp_store(regs: &mut [u64; 16], temps: &mut [u64; 8], spec: &VirtualIsaSpec, raw: u8, val: u64) {
    let kind = raw & 0xC0;
    let payload = raw & 0x3F;
    match kind {
        0x80 => {
            let reg_idx = spec.decode_reg(payload);
            regs[reg_idx as usize] = val;
        }
        0xC0 => {
            temps[(payload & 0x07) as usize] = val;
        }
        _ => {}
    }
}

/// 1-피연산자 MUL/IMUL — eval_state `mul_wide`와 동일.
pub(crate) fn mul_wide_interp(
    regs: &mut [u64; 16],
    temps: &mut [u64; 8],
    spec: &VirtualIsaSpec,
    flags: &mut VirtualFlags,
    a: u64,
    b: u64,
    signed: bool,
    width: u8,
    op_dst: u8,
) {
    let bits = width as u32 * 8;
    let mask = width_mask_interp(bits);
    // P0-2 signed MUL/IMUL: 피연산자를 2*bits 폭으로 부호 확장해 고 half 정합.
    let full = if signed {
        sign_extend_to_interp(a & mask, bits, bits * 2).wrapping_mul(sign_extend_to_interp(b & mask, bits, bits * 2))
    } else {
        ((a & mask) as u128).wrapping_mul((b & mask) as u128)
    };
    let low = (full & width_mask_interp(bits * 2) as u128) as u64;
    let high = ((full >> bits) as u64) & mask;
    let ovf = if signed {
        let sign_ext = if low & (1u64 << (bits - 1)) != 0 { mask } else { 0 };
        high != sign_ext
    } else {
        high != 0
    };
    flags.set_cf_of(ovf);
    if width == 1 {
        interp_store(regs, temps, spec, op_dst, (low & 0xFF) | ((high & 0xFF) << 8));
    } else {
        interp_store(regs, temps, spec, op_dst, low);
        regs[2] = high; // RDX
    }
}

/// 2/3-피연산자 IMUL — eval_state `mul_low`와 동일.
pub(crate) fn mul_low_interp(
    regs: &mut [u64; 16],
    temps: &mut [u64; 8],
    spec: &VirtualIsaSpec,
    flags: &mut VirtualFlags,
    a: u64,
    b: u64,
    signed: bool,
    width: u8,
    op_dst: u8,
) {
    let bits = width as u32 * 8;
    let mask = width_mask_interp(bits);
    let full = if signed {
        sign_extend_to_interp(a & mask, bits, bits * 2).wrapping_mul(sign_extend_to_interp(b & mask, bits, bits * 2))
    } else {
        ((a & mask) as u128).wrapping_mul((b & mask) as u128)
    };
    let low = (full & width_mask_interp(bits * 2) as u128) as u64;
    let high = ((full >> bits) as u64) & mask;
    let ovf = if signed {
        let sign_ext = if low & (1u64 << (bits - 1)) != 0 { mask } else { 0 };
        high != sign_ext
    } else {
        high != 0
    };
    flags.set_cf_of(ovf);
    interp_store(regs, temps, spec, op_dst, low);
}

/// `from_bits` 폭 값을 `to_bits`(≤128) 폭으로 부호 확장 (signed MUL/IMUL 고 half).
pub(crate) fn sign_extend_to_interp(v: u64, from_bits: u32, to_bits: u32) -> u128 {
    let sign = (v >> (from_bits - 1)) & 1;
    let low = (v as u128) & ((1u128 << from_bits) - 1);
    let ext = if sign != 0 { low | (u128::MAX << from_bits) } else { low };
    ext & (if to_bits < 128 { (1u128 << to_bits) - 1 } else { u128::MAX })
}

/// DIV/IDIV — eval_state `div_wide`와 동일. (제수 0 → 참조 기본값 0.)
pub(crate) fn div_wide_interp(
    regs: &mut [u64; 16],
    temps: &mut [u64; 8],
    spec: &VirtualIsaSpec,
    divisor: u64,
    signed: bool,
    width: u8,
    op_dst: u8,
) {
    let bits = width as u32 * 8;
    let mask = width_mask_interp(bits);
    // 폭 1(8비트)은 AX(reg0 low16)가 피제수 — RDX 미사용.
    let (dividend, dvbits) = if width == 1 {
        ((regs[0] & 0xFFFF) as u128, 16u32)
    } else {
        (
            ((regs[2] & mask) as u128) << bits | (regs[0] & mask) as u128,
            bits * 2,
        )
    };
    let dv = (divisor & mask) as u128;
    if dv == 0 {
        interp_store(regs, temps, spec, op_dst, 0);
        if width != 1 {
            regs[2] = 0;
        }
        return;
    }
    let (q, r) = if signed {
        let d = sign_extend_i128_interp(dividend, dvbits);
        let s = sign_extend_i128_interp(dv as u64 as u128, bits);
        let (q, r) = (d / s, d % s);
        (q as u128, r as u128)
    } else {
        (dividend / dv, dividend % dv)
    };
    // P1-7: x86 DIV/IDIV 몫 폭 초과 → #DE (참조 eval_state 와 동일 — 조용한 잘림 방지).
    let overflow = if signed {
        let q = q as i128;
        let qmin = -(1i128 << (bits - 1));
        let qmax = (1i128 << (bits - 1)) - 1;
        q < qmin || q > qmax
    } else {
        let qmax: u128 = (if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }) as u128;
        q > qmax
    };
    if overflow {
        panic!(
            "RISC DIV/IDIV interp: x86 #DE — quotient does not fit destination width {} bits (dividend 0x{dividend:X}, divisor 0x{dv:X})",
            bits
        );
    }
    if width == 1 {
        interp_store(regs, temps, spec, op_dst, ((r as u64) & 0xFF) << 8 | ((q as u64) & 0xFF));
    } else {
        interp_store(regs, temps, spec, op_dst, (q as u64) & mask);
        regs[2] = (r as u64) & mask;
    }
}
