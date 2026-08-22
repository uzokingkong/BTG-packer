use std::collections::HashMap;

use super::flags::VirtualFlags;
use super::opcodes::{BranchCondition, MicroOperand};
use super::RiscEvalState;

/// 브랜치 조건 평가 (flags만 사용). (x86 조건부 점프 참조 의미론).
pub(super) fn branch_taken(cond: BranchCondition, flags: &VirtualFlags) -> bool {
    match cond {
        BranchCondition::Always => true,
        BranchCondition::Zero => flags.zf(),
        BranchCondition::NotZero => !flags.zf(),
        BranchCondition::Carry => flags.cf(),
        BranchCondition::NotCarry => !flags.cf(),
        BranchCondition::Sign => flags.sf(),
        BranchCondition::NotSign => !flags.sf(),
        BranchCondition::Overflow => flags.of(),
        BranchCondition::NotOverflow => !flags.of(),
        // signed comparisons
        BranchCondition::Greater => !flags.zf() && (flags.sf() == flags.of()), // JG
        BranchCondition::Less => flags.sf() != flags.of(),                     // JL
        BranchCondition::GreaterOrEqual => flags.sf() == flags.of(),           // JGE
        BranchCondition::LessOrEqual => flags.zf() || (flags.sf() != flags.of()), // JLE
        // unsigned comparisons (precise)
        BranchCondition::Above => !flags.cf() && !flags.zf(), // JA: CF=0 && ZF=0
        BranchCondition::AboveOrEqual => !flags.cf(),         // JAE: CF=0
        BranchCondition::Below => flags.cf(),                 // JB: CF=1
        BranchCondition::BelowOrEqual => flags.cf() || flags.zf(), // JBE: CF=1 || ZF=1
        // parity
        BranchCondition::Parity => flags.pf(),     // JP
        BranchCondition::NotParity => !flags.pf(), // JNP
        // counter-based (Jcxz/Jecxz/Jrcxz): handled by branch_taken_with_state
        BranchCondition::CounterZero(_) => false,
    }
}

/// 브랜치 조건 평가. `CounterZero`(카운터 기반)는 레지스터 상태도 참조한다.
pub(super) fn branch_taken_with_state(
    cond: BranchCondition,
    flags: &VirtualFlags,
    regs: &[u64; 16],
) -> bool {
    if let BranchCondition::CounterZero(width) = cond {
        // Jcxz(2)/Jecxz(4)/Jrcxz(8): RCX(reg[1])를 지정된 width 크기로 잘라 0인지 확인
        let mask = match width {
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            _ => u64::MAX,
        };
        return (regs[1] & mask) == 0;
    }
    branch_taken(cond, flags)
}

/// 주어진 주소에서 `width`크기만큼 메모리를 읽기. 초기화되지 않은 바이트는 0으로 처리.
pub(super) fn mem_read(mem: &HashMap<u64, u8>, addr: u64, width: u8) -> u64 {
    let mut v = 0u64;
    for i in 0..width {
        if let Some(&b) = mem.get(&addr.wrapping_add(i as u64)) {
            v |= (b as u64) << (i as u64 * 8);
        }
    }
    v
}

/// 주어진 주소에서 `width`크기만큼 메모리를 쓰기.
pub(super) fn mem_write(mem: &mut HashMap<u64, u8>, addr: u64, width: u8, val: u64) {
    for i in 0..width {
        mem.insert(addr.wrapping_add(i as u64), (val >> (i as u64 * 8)) as u8);
    }
}

// ── P2: 확장 연산·수학 유틸 ──────────────────────────────────────────────────

/// `width`크기(바이트)에 대한 비트마스크.
pub(super) fn width_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// round-to-nearest-even (x86 MXCSR 기본값 RC) — half-way 케이스를 짝수쪽으로 반올림.
pub(super) fn round_ties_even(x: f64) -> i64 {
    let fl = x.floor();
    let diff = x - fl;
    if diff == 0.5 {
        let f = fl as i64;
        if f % 2 == 0 {
            f
        } else {
            f + 1
        }
    } else {
        x.round() as i64
    }
}

/// x86 CVT(T)Sx2SI reference semantics (must match the bytecode interpreter's
/// `cvt_f64_i32` in interp/xmm.rs). NaN / 무한 / out-of-range produce the
/// "integer indefinite": 0x8000_0000 for a 32-bit destination, and
/// 0x8000_0000_0000_0000 for a 64-bit destination. Rust's `as i64` saturates
/// instead (NaN→0, +무한→i64::MAX), so it CANNOT be used directly.
pub(super) fn cvt_f64_int(f: f64, dst_bits: u8, truncate: bool) -> u64 {
    let r = if truncate {
        f.trunc()
    } else {
        round_ties_even(f) as f64
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
            if !r.is_finite()
                || r < -9_223_372_036_854_775_808.0
                || r >= 9_223_372_036_854_775_808.0
            {
                0x8000_0000_0000_0000
            } else {
                r as i64 as u64
            }
        }
    }
}

/// `bits` 폭으로 `v`를 i128 부호 확장한다(bits < 128).
pub(super) fn sign_extend_i128(v: u128, bits: u32) -> i128 {
    let shift = 128 - bits;
    ((v << shift) as i128) >> shift
}

/// x86 signed MUL/IMUL 고 half 정합용 부호 확장.
/// signed 곱셈은 피연산자를 부호 확장해 폭×2 결과를 만들어야 하므로
/// (8-bit −1 × 2 → 16-bit 0xFFFE, high 0xFF), `from_bits` 값을
/// `to_bits`(≤128) 폭으로 부호 확장해 돌려준다.
pub(super) fn sign_extend_to(v: u64, from_bits: u32, to_bits: u32) -> u128 {
    debug_assert!(from_bits >= 1 && from_bits <= 64 && to_bits >= from_bits && to_bits <= 128);
    let sign = (v >> (from_bits - 1)) & 1;
    let low = (v as u128) & ((1u128 << from_bits) - 1);
    let ext = if sign != 0 {
        low | (u128::MAX << from_bits)
    } else {
        low
    };
    ext & (if to_bits < 128 {
        (1u128 << to_bits) - 1
    } else {
        u128::MAX
    })
}

/// 1-피연산자 형식 MUL/IMUL 구현: low → dst, high → RDX(레지스터 2) 또는 AX(레지스터 1).
pub(super) fn mul_wide(
    st: &mut RiscEvalState,
    flags: &mut VirtualFlags,
    a: u64,
    b: u64,
    signed: bool,
    width: u8,
    dst: Option<MicroOperand>,
) {
    let bits = width as u32 * 8;
    let mask = width_mask(bits);
    // x86 signed MUL/IMUL: 피연산자를 부호 확장한 폭×2 곱의 low/high half를
    // 만든다 (unsigned는 폭 마스크 그대로). high half가 원본과 일치하도록
    // signed 피연산자는 2*bits 폭으로 부호 확장한다.
    let am = if signed {
        sign_extend_to(a & mask, bits, bits * 2)
    } else {
        (a & mask) as u128
    };
    let bm = if signed {
        sign_extend_to(b & mask, bits, bits * 2)
    } else {
        (b & mask) as u128
    };
    let full = am.wrapping_mul(bm);
    // low half = 2w-bit 곱의 하위 half (signed 부호 확장 잔여/상위 가비지 제거).
    let low = (full & width_mask(bits * 2) as u128) as u64;
    let high = ((full >> bits) as u64) & mask;
    let ovf = if signed {
        let sign_ext = if low & (1u64 << (bits - 1)) != 0 {
            mask
        } else {
            0
        };
        high != sign_ext
    } else {
        high != 0
    };
    flags.set_cf_of(ovf);
    if width == 1 {
        // AX = AL×reg/m8 — AH(high 8비트)는 RAX 비트 8..15 에
        store_dst(st, dst, (low & 0xFF) | ((high & 0xFF) << 8));
    } else {
        store_dst(st, dst, low);
        st.regs[2] = high; // RDX
    }
}

/// 2/3-피연산자 형식 IMUL 구현: dst = low(src1×src2), RDX 기록하지 않는다.
pub(super) fn mul_low(
    st: &mut RiscEvalState,
    flags: &mut VirtualFlags,
    a: u64,
    b: u64,
    signed: bool,
    width: u8,
    dst: Option<MicroOperand>,
) {
    let bits = width as u32 * 8;
    let mask = width_mask(bits);
    // signed IMUL low: low는 signed/unsigned가 동일(모듈로)하지만 overflow
    // 판정(CF=OF)은 signed 고 half를 봐야 하므로 피연산자를 2*bits 폭으로
    // 부호 확장한 곱으로 계산한다.
    let am = if signed {
        sign_extend_to(a & mask, bits, bits * 2)
    } else {
        (a & mask) as u128
    };
    let bm = if signed {
        sign_extend_to(b & mask, bits, bits * 2)
    } else {
        (b & mask) as u128
    };
    let full = am.wrapping_mul(bm);
    // low half = 2w-bit 곱의 하위 half (signed 부호 확장 잔여 제거).
    let low = (full & width_mask(bits * 2) as u128) as u64;
    let high = ((full >> bits) as u64) & mask;
    let ovf = if signed {
        let sign_ext = if low & (1u64 << (bits - 1)) != 0 {
            mask
        } else {
            0
        };
        high != sign_ext
    } else {
        high != 0
    };
    flags.set_cf_of(ovf);
    store_dst(st, dst, low);
}

/// DIV/IDIV 구현: 피연산자 = RDX:RAX(레지스터 2 및 1 또는 AX), 나눗수 = divisor,
/// 몫→dst(RAX), 나머지 → RDX. (나눗수 0 이거나 몫이 destination 폭 초과 시 x86 #DE 계약.)
/// (롤백은 0 을 쓰거나 panic 처리 — 문서화된 완화.)
pub(super) fn div_wide(
    st: &mut RiscEvalState,
    divisor: u64,
    signed: bool,
    width: u8,
    dst: Option<MicroOperand>,
) {
    let bits = width as u32 * 8;
    let mask = width_mask(bits);
    // 1바이트(8비트) DIV/IDIV에서 AX(reg0 low16)가 피연산자; RDX 기록하지 않음.
    let (dividend, dvbits) = if width == 1 {
        ((st.regs[0] & 0xFFFF) as u128, 16u32)
    } else {
        (
            ((st.regs[2] & mask) as u128) << bits | (st.regs[0] & mask) as u128,
            bits * 2,
        )
    };
    let dv = (divisor & mask) as u128;
    if dv == 0 {
        // P1-7: x86 DIV/IDIV divisor==0 → #DE (STATUS_INTEGER_DIVIDE_BY_ZERO).
        // 네이티브 핸들러와 동일한 가드 계약(0 결과, 문서화된 완화)을 유지해
        // 차등 테스트 정합을 지킨다 — 정확한 #DE 는 네이티브 경로의 하드웨어
        // div 가 담당한다 (참조는 VM 크래시를 피하는 완화).
        if width == 1 {
            store_dst(st, dst, 0);
        } else {
            store_dst(st, dst, 0);
            st.regs[2] = 0;
        }
        return;
    }
    // P1-7: x86 DIV/IDIV 는 몫이 destination 폭에 안 맞으면 #DE 를 발생시키고
    // **아무 레지스터도 쓰지 않는다** (fault-before-store). 네이티브 핸들러는
    // 하드웨어 div 가 #DE 로 크래시하지만, 참조는 조용히 잘라 저장하지 않도록
    // 명시적으로 감지해 실패시킨다 (조용한 오답 방지).
    let overflow;
    let (q, r): (u128, u128) = if signed {
        let d = sign_extend_i128(dividend, dvbits);
        let s = sign_extend_i128(dv as u64 as u128, bits);
        // Rust 정수 나눗셈은 0 나누기는 패닉 — IDIV 와 동일하다.
        let (q, r) = (d / s, d % s);
        let qmin = -(1i128 << (bits - 1));
        let qmax = (1i128 << (bits - 1)) - 1;
        overflow = q < qmin || q > qmax;
        (q as u128, r as u128)
    } else {
        let (q, r) = (dividend / dv, dividend % dv);
        let qmax: u128 = (if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        }) as u128;
        overflow = q > qmax;
        (q, r)
    };
    if overflow {
        panic!(
            "RISC DIV/IDIV: x86 #DE — quotient does not fit destination width {} bits (dividend 0x{dividend:X}, divisor 0x{dv:X})",
            bits
        );
    }
    if width == 1 {
        // AL = 몫, AH = 나머지 → AX(dst).
        let ax = ((r as u64) & 0xFF) << 8 | ((q as u64) & 0xFF);
        store_dst(st, dst, ax);
    } else {
        store_dst(st, dst, (q as u64) & mask);
        st.regs[2] = (r as u64) & mask;
    }
}

/// dst(Some VReg/Temp) 에 val을 eval_state 의 `store` 경로로 기록한다.
pub(super) fn store_dst(st: &mut RiscEvalState, dst: Option<MicroOperand>, val: u64) {
    if let Some(d) = dst {
        match d {
            MicroOperand::VReg(i) => st.regs[i as usize] = val,
            MicroOperand::Temp(i) => st.temps[i as usize] = val,
            _ => {}
        }
    }
}
