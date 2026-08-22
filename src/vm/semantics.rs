// ==============================================================================
// VM Semantic Core — x86 ground-truth reference (single source of truth)
// ==============================================================================
//
// Semantic core 완성(Phase 1): 정적 ISA 명세 주석이 아니라 **실제 x86 하드웨어의
// flag/결과를 직접 프로브**해서, portable 에뮬레이션으로 구현된 opcode(TZCNT/LZCNT
// 등)가 진짜 CPU 와 같은 의미론을 갖는지 lock 한다.
//
// 이 모듈의 규약:
//   * `probe_*` 함수 — 인라인 어셈블리로 실제 x86 명령을 실행하고 (result, rflags)
//     를 반환. VM 이 "지향해야 하는" ground truth.
//   * self-test 는 이 프로브 결과와 interp/native 핸들러의 결과를 차등 검증한다.
//   * `flag_contract(op)` — VM opcode 가 쓸 수 있는 flag 비트의 계약(문서/검증용).
//
// 모든 프로브는 `pushfq/pop` 직후의 raw rflags 를 반환한다 (VM 의 FLAG_MASK
// 비트만 의미 있음).

use crate::vm::bytecode::{F_CF, F_OF, F_PF, F_SF, F_ZF};

/// tzcnt r32 — (result, raw rflags). Intel SDM: ZF is set according to the
/// *result*; CF=1 iff src==0. So tzcnt(0)=32 (CF=1, ZF=0), tzcnt(odd)=0 (ZF=1).
#[cfg(target_arch = "x86_64")]
pub fn probe_tzcnt32(x: u32) -> (u32, u64) {
    let mut out: u32 = x;
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "tzcnt {0:e}, {0:e}",
            "pushfq",
            "pop {1}",
            inout(reg) out,
            out(reg) flags,
            options(nostack),
        );
    }
    (out, flags)
}

/// tzcnt r64 — see `probe_tzcnt32`.
#[cfg(target_arch = "x86_64")]
pub fn probe_tzcnt64(x: u64) -> (u64, u64) {
    let mut out: u64 = x;
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "tzcnt {0}, {0}",
            "pushfq",
            "pop {1}",
            inout(reg) out,
            out(reg) flags,
            options(nostack),
        );
    }
    (out, flags)
}

/// lzcnt r32 — (result, raw rflags). CF=1 iff src==0 (result==width); ZF is
/// set according to the result (lzcnt(0)=32 → ZF=0; lzcnt(msb-set)=0 → ZF=1).
#[cfg(target_arch = "x86_64")]
pub fn probe_lzcnt32(x: u32) -> (u32, u64) {
    let mut out: u32 = x;
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "lzcnt {0:e}, {0:e}",
            "pushfq",
            "pop {1}",
            inout(reg) out,
            out(reg) flags,
            options(nostack),
        );
    }
    (out, flags)
}

/// lzcnt r64 — see `probe_lzcnt32`.
#[cfg(target_arch = "x86_64")]
pub fn probe_lzcnt64(x: u64) -> (u64, u64) {
    let mut out: u64 = x;
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "lzcnt {0}, {0}",
            "pushfq",
            "pop {1}",
            inout(reg) out,
            out(reg) flags,
            options(nostack),
        );
    }
    (out, flags)
}

/// popcnt r32 — (result, raw rflags). ZF set iff result==0; CF/OF/SF cleared.
#[cfg(target_arch = "x86_64")]
pub fn probe_popcnt32(x: u32) -> (u32, u64) {
    let mut out: u32 = x;
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "popcnt {0:e}, {0:e}",
            "pushfq",
            "pop {1}",
            inout(reg) out,
            out(reg) flags,
            options(nostack),
        );
    }
    (out, flags)
}

/// popcnt r64 — see `probe_popcnt32`.
#[cfg(target_arch = "x86_64")]
pub fn probe_popcnt64(x: u64) -> (u64, u64) {
    let mut out: u64 = x;
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "popcnt {0}, {0}",
            "pushfq",
            "pop {1}",
            inout(reg) out,
            out(reg) flags,
            options(nostack),
        );
    }
    (out, flags)
}

/// bsr r32 — (result, raw rflags). ZF=1 iff src==0 (dest defined as 0 by the
/// VM, matching interp/native); else dest = index of highest set bit, ZF=0.
/// Intel leaves dest undefined when src==0, so `out` is pre-set to 0 and the
/// probe observes whether hardware keeps it (it does on x86-64).
#[cfg(target_arch = "x86_64")]
pub fn probe_bsr32(x: u32) -> (u32, u64) {
    let mut out: u32 = 0;
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "bsr {0:e}, {1:e}",
            "pushfq",
            "pop {2}",
            inout(reg) out,
            in(reg) x,
            out(reg) flags,
            options(nostack),
        );
    }
    (out, flags)
}

/// bsf r32 — see `probe_bsr32` (lowest set bit).
#[cfg(target_arch = "x86_64")]
pub fn probe_bsf32(x: u32) -> (u32, u64) {
    let mut out: u32 = 0;
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "bsf {0:e}, {1:e}",
            "pushfq",
            "pop {2}",
            inout(reg) out,
            in(reg) x,
            out(reg) flags,
            options(nostack),
        );
    }
    (out, flags)
}

/// Documented flag contract per opcode family: which of the six status flags
/// the op writes, and which pass through unchanged. Used by the differential
/// fuzz to scope the flag comparison (an op never touches bits outside this).
/// Returns `(written_mask, preserved_mask)`.
pub fn flag_contract(op: u8) -> (u64, u64) {
    use crate::vm::bytecode::*;
    let all = FLAG_MASK;
    match op {
        OP_ADD_R_R | OP_ADD_R_IMM32 | OP_ADD_R_R64 | OP_ADD_R_IMM64 | OP_SUB_R_R | OP_SUB_R_R64
        | OP_CMP_R_IMM32 | OP_XADD_MEM8_A | OP_XADD_MEM16_A | OP_XADD_MEM32_A | OP_XADD_MEM64_A => {
            (F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF, 0) // full arithmetic set
        }
        // P0-⑤: MUL/IMUL define CF/OF (upper-half overflow) — written here;
        // SF/ZF/AF/PF are undefined on x86 so they pass through (preserved).
        // DIV/IDIV leave ALL status flags undefined on x86 → pass through
        // (no written bits). Matches the RISC reference (mul_wide/mul_low set
        // CF/OF via set_cf_of; div_wide leaves flags untouched) and the native
        // handler capture (cap_flags_cf_of), so every path agrees.
        OP_MUL_R_R32 | OP_MUL_R_R64 | OP_MUL_R_R8 | OP_MUL_R_R16 | OP_IMUL1_R_R32
        | OP_IMUL1_R_R64 | OP_IMUL1_R_R8 | OP_IMUL1_R_R16 | OP_IMUL_R_R | OP_IMUL_R_R64 => {
            (F_CF | F_OF, FLAG_MASK & !(F_CF | F_OF))
        }
        OP_DIV_R_R32 | OP_DIV_R_R64 | OP_DIV_R_R8 | OP_DIV_R_R16 | OP_IDIV_R_R32
        | OP_IDIV_R_R64 | OP_IDIV_R_R8 | OP_IDIV_R_R16 => (0, 0),
        OP_AND_R_R | OP_AND_R_IMM32 | OP_AND_R_R64 | OP_AND_R_IMM64 | OP_XOR_R_R
        | OP_XOR_R_IMM32 | OP_XOR_R_R64 | OP_XOR_R_IMM64 | OP_OR_R_R | OP_OR_R_R64
        | OP_OR_R_IMM32 | OP_OR_R_IMM64 | OP_TEST_R_R32 | OP_TEST_R_IMM32 => {
            (F_PF | F_ZF | F_SF, 0) // logical: CF/OF/AF cleared
        }
        // SHLD/SHRD (count>0): CF = last bit shifted out of dst; SF/ZF/PF from
        // the result; OF/AF undefined (defined 0). count==0 preserves all flags.
        OP_SHLD_R_R_IMM8 | OP_SHLD_R_R_CL | OP_SHRD_R_R_IMM8 | OP_SHRD_R_R_CL
        | OP_SHLD64_R_R_IMM8 | OP_SHLD64_R_R_CL | OP_SHRD64_R_R_IMM8 | OP_SHRD64_R_R_CL => {
            (F_CF | F_PF | F_ZF | F_SF, 0)
        }
        OP_SHL_R_IMM8 | OP_SHR_R_IMM8 | OP_SAR_R_IMM8 | OP_SHL_R_CL | OP_SHR_R_CL | OP_SAR_R_CL
        | OP_SHL64_R_IMM8 | OP_SHR64_R_IMM8 | OP_SAR64_R_IMM8 | OP_SHL64_R_CL | OP_SHR64_R_CL
        | OP_SAR64_R_CL => {
            (F_CF | F_PF | F_ZF | F_SF, 0) // OF/AF defined 0
        }
        OP_INC_R | OP_DEC_R | OP_INC_R64 | OP_DEC_R64 | OP_LOCK_INC_MEM8_A
        | OP_LOCK_INC_MEM16_A | OP_LOCK_INC_MEM32_A | OP_LOCK_INC_MEM64_A | OP_LOCK_DEC_MEM8_A
        | OP_LOCK_DEC_MEM16_A | OP_LOCK_DEC_MEM32_A | OP_LOCK_DEC_MEM64_A => {
            (F_PF | F_AF | F_ZF | F_SF | F_OF, F_CF) // CF preserved
        }
        // CMPXCHG writes only ZF; the other status flags pass through untouched.
        OP_CMPXCHG_MEM8_A | OP_CMPXCHG_MEM16_A | OP_CMPXCHG_MEM32_A | OP_CMPXCHG_MEM64_A => {
            (F_ZF, FLAG_MASK & !F_ZF)
        }
        OP_NEG_R | OP_NEG_R64 => (F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF, 0),
        OP_BSR_R32 | OP_BSR_R64 | OP_BSF_R32 | OP_BSF_R64 => (F_ZF, 0),
        OP_TZCNT_R32 => (F_CF | F_ZF, 0),
        OP_LZCNT_R32 | OP_LZCNT_R64 => (F_CF | F_ZF, 0),
        OP_POPCNT_R32 | OP_POPCNT_R64 => (F_ZF, 0),
        OP_BLSR_R32 | OP_BLSR_R64 | OP_BLSMSK_R32 | OP_BLSMSK_R64 | OP_BLSI_R32 | OP_BLSI_R64 => {
            (F_ZF, 0)
        } // SF/OF/CF cleared by SDM
        OP_ANDN_R_R32 | OP_ANDN_R_R64 => (F_ZF | F_SF, 0),
        _ => (0, 0),
    }
}

/// Normalize a raw rflags value from the probes to the six modelled status
/// bits (same masking the VM applies via FLAG_MASK).
pub fn status_flags(raw: u64) -> u64 {
    use crate::vm::bytecode::FLAG_MASK;
    raw & FLAG_MASK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::bytecode::FLAG_MASK;

    /// Ground truth from this machine's real x86-64 (locked assertions). If any
    /// of these fail, the portable emulation in interp/handlers is wrong too.
    #[test]
    fn ground_truth_tzcnt_lzcnt_popcnt_bsr_bsf() {
        let m = |raw: u64| raw & FLAG_MASK;

        // TZCNT: ZF follows the RESULT. tzcnt(0)=32 → ZF=0, CF=1.
        let (r, f) = probe_tzcnt32(0);
        assert_eq!(r, 32, "tzcnt32(0) result");
        assert_eq!(m(f), F_CF, "tzcnt32(0) flags (CF=1, ZF=0) got 0x{:X}", m(f));
        let (r, f) = probe_tzcnt32(0x18); // 11000b → 3 trailing zeros
        assert_eq!(r, 3);
        assert_eq!(m(f), 0, "tzcnt32(0x18) flags (CF=0, ZF=0) got 0x{:X}", m(f));
        let (r, f) = probe_tzcnt32(1); // odd → 0 trailing zeros → ZF=1
        assert_eq!(r, 0);
        assert_eq!(m(f), F_ZF, "tzcnt32(1) flags (ZF=1) got 0x{:X}", m(f));

        let (r, f) = probe_tzcnt64(0);
        assert_eq!(r, 64);
        assert_eq!(m(f), F_CF, "tzcnt64(0) flags got 0x{:X}", m(f));
        let (r, f) = probe_tzcnt64(1);
        assert_eq!(r, 0);
        assert_eq!(m(f), F_ZF, "tzcnt64(1) flags got 0x{:X}", m(f));

        // LZCNT: ZF follows the RESULT. lzcnt(0)=32 → ZF=0, CF=1.
        let (r, f) = probe_lzcnt32(0);
        assert_eq!(r, 32);
        assert_eq!(m(f), F_CF, "lzcnt32(0) flags got 0x{:X}", m(f));
        let (r, f) = probe_lzcnt32(0x8000_0000); // msb set → 0 leading zeros
        assert_eq!(r, 0);
        assert_eq!(m(f), F_ZF, "lzcnt32(0x80000000) flags got 0x{:X}", m(f));
        let (r, f) = probe_lzcnt64(0);
        assert_eq!(r, 64);
        assert_eq!(m(f), F_CF, "lzcnt64(0) flags got 0x{:X}", m(f));

        // POPCNT: ZF iff result==0; CF/OF/SF cleared; PF undefined (masked out).
        let (r, f) = probe_popcnt32(0);
        assert_eq!(r, 0);
        assert_eq!(m(f) & F_ZF, F_ZF, "popcnt32(0) ZF got 0x{:X}", m(f));
        assert_eq!(
            m(f) & (F_CF | F_SF | F_OF),
            0,
            "popcnt32(0) CF/SF/OF got 0x{:X}",
            m(f)
        );
        let (r, f) = probe_popcnt32(0xFFFF_FFFF);
        assert_eq!(r, 32);
        assert_eq!(
            m(f) & (F_CF | F_ZF | F_SF | F_OF),
            0,
            "popcnt32(~0) flags got 0x{:X}",
            m(f)
        );
        let (r, f) = probe_popcnt64(0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(r, 64);
        assert_eq!(m(f) & (F_CF | F_ZF | F_SF | F_OF), 0);

        // BSR/BSF: ZF=1 iff src==0 (dest left as 0 by x86-64); every other
        // status flag is UNDEFINED on x86, so only ZF is asserted here (PF/SF/
        // OF/AF reflect whatever the CPU had — the VM defines them 0).
        let (r, f) = probe_bsr32(0);
        assert_eq!(r, 0);
        assert_eq!(m(f) & F_ZF, F_ZF, "bsr32(0) ZF got 0x{:X}", m(f));
        let (r, f) = probe_bsr32(0x10);
        assert_eq!(r, 4);
        assert_eq!(m(f) & F_ZF, 0, "bsr32(0x10) ZF got 0x{:X}", m(f));
        let (r, f) = probe_bsf32(0x10);
        assert_eq!(r, 4);
        assert_eq!(m(f) & F_ZF, 0, "bsf32(0x10) ZF got 0x{:X}", m(f));
        let (r, f) = probe_bsf32(0);
        assert_eq!(r, 0);
        assert_eq!(m(f) & F_ZF, F_ZF, "bsf32(0) ZF got 0x{:X}", m(f));
    }

    #[test]
    fn flag_contract_is_consistent() {
        use crate::vm::bytecode::*;
        // (written, preserved) must be disjoint, within FLAG_MASK, and the
        // union must cover the modelled status flags for the written group.
        let ops = [
            OP_ADD_R_R,
            OP_SUB_R_R,
            OP_XOR_R_R,
            OP_AND_R_R,
            OP_OR_R_R,
            OP_TEST_R_R32,
            OP_CMP_R_IMM32,
            OP_INC_R,
            OP_DEC_R,
            OP_NEG_R,
            OP_SHL_R_IMM8,
            OP_SHL_R_CL,
            OP_SHL64_R_IMM8,
            OP_SHLD_R_R_IMM8,
            OP_BSR_R32,
            OP_BSF_R64,
            OP_TZCNT_R32,
            OP_LZCNT_R64,
            OP_POPCNT_R32,
            OP_BLSR_R64,
            OP_ANDN_R_R32,
            OP_CMPXCHG_MEM32_A,
            OP_XADD_MEM64_A,
            OP_LOCK_INC_MEM8_A,
            OP_MUL_R_R32,
            OP_DIV_R_R64,
            OP_IMUL_R_R,
        ];
        for op in ops {
            let (written, preserved) = flag_contract(op);
            assert_eq!(
                written & preserved,
                0,
                "flag_contract(0x{op:02X}): written 0x{written:X} overlaps preserved 0x{preserved:X}"
            );
            assert_eq!(
                written | preserved,
                (written | preserved) & FLAG_MASK,
                "flag_contract(0x{op:02X}): bits outside FLAG_MASK"
            );
        }
        // Spot-check representative contracts.
        assert_eq!(flag_contract(OP_ADD_R_R).0, FLAG_MASK);
        assert_eq!(flag_contract(OP_TZCNT_R32).0, F_CF | F_ZF);
        assert_eq!(flag_contract(OP_BSR_R32).0, F_ZF);
        assert_eq!(
            flag_contract(OP_MUL_R_R32),
            (F_CF | F_OF, FLAG_MASK & !(F_CF | F_OF))
        );
        assert_eq!(
            flag_contract(OP_IMUL_R_R),
            (F_CF | F_OF, FLAG_MASK & !(F_CF | F_OF))
        );
        // DIV/IDIV leave ALL flags undefined on x86 → pass through (flagless).
        assert_eq!(flag_contract(OP_DIV_R_R64), (0, 0));
        assert_eq!(flag_contract(OP_CMPXCHG_MEM32_A), (F_ZF, FLAG_MASK & !F_ZF));
        assert_eq!(flag_contract(OP_INC_R).1, F_CF, "INC preserves CF");
        // Flagless ops (mov/jmp/lea/bswap/not) must not claim any writes.
        assert_eq!(flag_contract(OP_MOV_R_R), (0, 0));
        assert_eq!(flag_contract(OP_JMP8), (0, 0));
        assert_eq!(flag_contract(OP_BSWAP_R32), (0, 0));
        assert_eq!(flag_contract(OP_NOT_R), (0, 0));
    }
}
