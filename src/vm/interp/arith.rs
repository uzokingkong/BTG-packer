// ==============================================================================
// BTG v21 - VM Interpreter: arithmetic / logical / shift / bitwise ops
// ==============================================================================
//
// Covers ADD/SUB/XOR/AND/OR/IMUL (32 & 64), IMM variants, shifts (imm & CL,
// 32 & 64), ROL/ROR, INC/DEC, CMP/TEST, NEG/NOT, BSWAP, BSR/BSF, TZCNT, SETCC
// and the CPUID / XGETBV bridge.

use super::state::{VmError, flags_of, set_flags, set_vreg64, vreg32, vreg64};
use crate::vm::bytecode::*;
use crate::vm::flags;

/// Execute one arithmetic/logical opcode. `ip` points at the first operand
/// byte (opcode already consumed). Returns the updated ip.
pub(crate) fn exec(
    state: &mut [u8],
    _mem: &mut [u8],
    code: &[u8],
    ip: usize,
    op: u8,
) -> Result<usize, VmError> {
    match op {
        OP_XOR_R_R => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let ip = ip + 2;
            let r = vreg32(state, d)? ^ vreg32(state, s)?;
            set_vreg64(state, d, r as u64)?;
            set_flags(state, flags::logical_flags(r));
            Ok(ip)
        }
        OP_ADD_R_R => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let ip = ip + 2;
            let a = vreg32(state, d)?;
            let b = vreg32(state, s)?;
            set_vreg64(state, d, a.wrapping_add(b) as u64)?;
            set_flags(state, flags::add_flags(a, b));
            Ok(ip)
        }
        OP_IMUL_R_R => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let ip = ip + 2;
            let a = vreg32(state, d)? as u64;
            let b = vreg32(state, s)? as u64;
            set_vreg64(state, d, a.wrapping_mul(b) as u64)?;
            // P0-⑤: 2/3-op IMUL sets CF/OF iff the signed product doesn't fit
            // the 32-bit destination (matches the native `imul eax, edx`).
            let ovf = flags::imul_fit_ovf(a, b, 32);
            set_flags(state, flags::muldiv_cf_of(flags_of(state), ovf));
            Ok(ip)
        }
        OP_SUB_R_R => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let ip = ip + 2;
            let a = vreg32(state, d)?;
            let b = vreg32(state, s)?;
            set_vreg64(state, d, a.wrapping_sub(b) as u64)?;
            set_flags(state, flags::sub_flags(a, b));
            Ok(ip)
        }
        OP_SUB_R_R8 | OP_SUB_R_R16 => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let ip = ip + 2;
            let bits = if op == OP_SUB_R_R8 { 8u32 } else { 16u32 };
            let mask = if bits == 8 { 0xFFu64 } else { 0xFFFFu64 };
            let a = vreg64(state, d)?;
            let b = vreg64(state, s)?;
            set_vreg64(state, d, a.wrapping_sub(b) & mask)?;
            set_flags(state, flags::sub_flags_width(a, b, bits));
            Ok(ip)
        }
        OP_AND_R_R => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let ip = ip + 2;
            let r = vreg32(state, d)? & vreg32(state, s)?;
            set_vreg64(state, d, r as u64)?;
            set_flags(state, flags::logical_flags(r));
            Ok(ip)
        }
        OP_AND_R_IMM32 | OP_XOR_R_IMM32 | OP_ADD_R_IMM32 => {
            let r = code[ip] as usize;
            let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
            let ip = ip + 5;
            let v = vreg32(state, r)?;
            let r2 = match op {
                OP_AND_R_IMM32 => v & imm,
                OP_XOR_R_IMM32 => v ^ imm,
                _ => v.wrapping_add(imm),
            };
            set_vreg64(state, r, r2 as u64)?;
            match op {
                OP_ADD_R_IMM32 => set_flags(state, flags::add_flags(v, imm)),
                _ => set_flags(state, flags::logical_flags(r2)),
            }
            Ok(ip)
        }
        OP_ROL_R_IMM8 => {
            let r = code[ip] as usize;
            let amt = code[ip + 1] & 31;
            let ip = ip + 2;
            set_vreg64(state, r, vreg32(state, r)?.rotate_left(amt as u32) as u64)?;
            Ok(ip)
        }
        OP_ROR_R_IMM8 => {
            let r = code[ip] as usize;
            let amt = code[ip + 1] & 31;
            let ip = ip + 2;
            set_vreg64(state, r, vreg32(state, r)?.rotate_right(amt as u32) as u64)?;
            Ok(ip)
        }
        OP_INC_R => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let a = vreg32(state, r)?;
            let prev = flags_of(state);
            set_vreg64(state, r, a.wrapping_add(1) as u64)?;
            set_flags(state, flags::inc_flags(a, prev));
            Ok(ip)
        }
        OP_DEC_R => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let a = vreg32(state, r)?;
            let prev = flags_of(state);
            set_vreg64(state, r, a.wrapping_sub(1) as u64)?;
            set_flags(state, flags::dec_flags(a, prev));
            Ok(ip)
        }
        OP_INC_R64 => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let a = vreg64(state, r)?;
            let prev = flags_of(state);
            set_vreg64(state, r, a.wrapping_add(1))?;
            set_flags(state, flags::inc_flags64(a, prev));
            Ok(ip)
        }
        OP_DEC_R64 => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let a = vreg64(state, r)?;
            let prev = flags_of(state);
            set_vreg64(state, r, a.wrapping_sub(1))?;
            set_flags(state, flags::dec_flags64(a, prev));
            Ok(ip)
        }
        OP_CMP_R_IMM32 => {
            let r = code[ip] as usize;
            let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
            let ip = ip + 5;
            set_flags(state, flags::sub_flags(vreg32(state, r)?, imm));
            Ok(ip)
        }
        OP_SETCC => {
            // v50: setcc writes ONLY the low byte of the destination vreg and
            // preserves the status flags. (x86 setcc is a partial-register
            // write: the upper bits of the destination are untouched and the
            // flags are not modified.)
            let dst = code[ip] as usize;
            let cond = code[ip + 1];
            let ip = ip + 2;
            let cur = vreg64(state, dst)?;
            let taken = flags::cond_taken(cond, flags_of(state));
            let newv = (cur & !0xFFu64) | if taken { 1u64 } else { 0 };
            set_vreg64(state, dst, newv)?;
            Ok(ip)
        }
        OP_ADD_R_R64 | OP_SUB_R_R64 | OP_XOR_R_R64 | OP_AND_R_R64 | OP_IMUL_R_R64 => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let ip = ip + 2;
            let a = vreg64(state, d)?;
            let b = vreg64(state, s)?;
            set_vreg64(state, d, match op {
                OP_ADD_R_R64 => a.wrapping_add(b),
                OP_SUB_R_R64 => a.wrapping_sub(b),
                OP_XOR_R_R64 => a ^ b,
                OP_AND_R_R64 => a & b,
                _ => a.wrapping_mul(b),
            })?;
            if op != OP_IMUL_R_R64 {
                let fl = match op {
                    OP_ADD_R_R64 => flags::add_flags64(a, b),
                    OP_SUB_R_R64 => flags::sub_flags64(a, b),
                    _ => flags::logical_flags64(a & b), // AND
                };
                // XOR uses the combined result
                let fl = if op == OP_XOR_R_R64 { flags::logical_flags64(a ^ b) } else { fl };
                set_flags(state, fl);
            } else {
                // P0-⑤: 2/3-op IMUL64 sets CF/OF iff the signed product doesn't
                // fit the 64-bit destination (matches native `imul rax, rdx`).
                let ovf = flags::imul_fit_ovf(a, b, 64);
                set_flags(state, flags::muldiv_cf_of(flags_of(state), ovf));
            }
            Ok(ip)
        }
        OP_ADD_R_IMM64 | OP_XOR_R_IMM64 | OP_AND_R_IMM64 => {
            let r = code[ip] as usize;
            let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
            let ip = ip + 5;
            let imm = imm as i32 as i64 as u64; // sign-extend
            let v = vreg64(state, r)?;
            let r2 = match op {
                OP_ADD_R_IMM64 => v.wrapping_add(imm),
                OP_XOR_R_IMM64 => v ^ imm,
                _ => v & imm,
            };
            set_vreg64(state, r, r2)?;
            let fl = match op {
                OP_ADD_R_IMM64 => flags::add_flags64(v, imm),
                _ => flags::logical_flags64(r2),
            };
            set_flags(state, fl);
            Ok(ip)
        }
        OP_SHL_R_IMM8 | OP_SHR_R_IMM8 | OP_SAR_R_IMM8 => {
            let r = code[ip] as usize;
            let cnt = (code[ip + 1] & 31) as u32;
            let ip = ip + 2;
            let v = vreg32(state, r)?;
            let r2 = match op {
                OP_SHL_R_IMM8 => v.wrapping_shl(cnt),
                OP_SHR_R_IMM8 => v.wrapping_shr(cnt),
                _ => ((v as i32) >> cnt) as u32,
            };
            set_vreg64(state, r, r2 as u64)?;
            if cnt != 0 {
                let kind = match op {
                    OP_SHL_R_IMM8 => flags::ShiftKind::Shl,
                    OP_SHR_R_IMM8 => flags::ShiftKind::Shr,
                    _ => flags::ShiftKind::Sar,
                };
                set_flags(state, flags::shift_flags(kind, v, cnt, r2));
            }
            Ok(ip)
        }
        OP_SHL_R_CL | OP_SHR_R_CL | OP_SAR_R_CL => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let cnt = (vreg64(state, 1)? & 31) as u32;
            let v = vreg32(state, r)?;
            let r2 = match op {
                OP_SHL_R_CL => v.wrapping_shl(cnt),
                OP_SHR_R_CL => v.wrapping_shr(cnt),
                _ => ((v as i32) >> cnt) as u32,
            };
            set_vreg64(state, r, r2 as u64)?;
            if cnt != 0 {
                let kind = match op {
                    OP_SHL_R_CL => flags::ShiftKind::Shl,
                    OP_SHR_R_CL => flags::ShiftKind::Shr,
                    _ => flags::ShiftKind::Sar,
                };
                set_flags(state, flags::shift_flags(kind, v, cnt, r2));
            }
            Ok(ip)
        }
        OP_TEST_R_R32 => {
            let a = code[ip] as usize;
            let b = code[ip + 1] as usize;
            let ip = ip + 2;
            set_flags(state, flags::logical_flags(vreg32(state, a)? & vreg32(state, b)?));
            Ok(ip)
        }
        OP_TEST_R_IMM32 => {
            let r = code[ip] as usize;
            let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
            let ip = ip + 5;
            set_flags(state, flags::logical_flags(vreg32(state, r)? & imm));
            Ok(ip)
        }
        OP_OR_R_R => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let ip = ip + 2;
            let r = vreg32(state, d)? | vreg32(state, s)?;
            set_vreg64(state, d, r as u64)?;
            set_flags(state, flags::logical_flags(r));
            Ok(ip)
        }
        OP_OR_R_R64 => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let ip = ip + 2;
            let r = vreg64(state, d)? | vreg64(state, s)?;
            set_vreg64(state, d, r)?;
            set_flags(state, flags::logical_flags64(r));
            Ok(ip)
        }
        OP_OR_R_IMM32 => {
            let r = code[ip] as usize;
            let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
            let ip = ip + 5;
            let v = vreg32(state, r)? | imm;
            set_vreg64(state, r, v as u64)?;
            set_flags(state, flags::logical_flags(v));
            Ok(ip)
        }
        OP_OR_R_IMM64 => {
            let r = code[ip] as usize;
            let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
            let ip = ip + 5;
            let imm = imm as i32 as i64 as u64; // sign-extend
            let v = vreg64(state, r)? | imm;
            set_vreg64(state, r, v)?;
            set_flags(state, flags::logical_flags64(v));
            Ok(ip)
        }
        OP_NEG_R => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let a = vreg32(state, r)?;
            let res = 0u32.wrapping_sub(a);
            set_vreg64(state, r, res as u64)?;
            set_flags(state, flags::sub_flags(0, a));
            Ok(ip)
        }
        OP_NEG_R64 => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let a = vreg64(state, r)?;
            let res = 0u64.wrapping_sub(a);
            set_vreg64(state, r, res)?;
            set_flags(state, flags::sub_flags64(0, a));
            Ok(ip)
        }
        OP_NOT_R => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            set_vreg64(state, r, (!vreg32(state, r)?) as u64)?;
            Ok(ip)
        }
        OP_NOT_R64 => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            set_vreg64(state, r, !vreg64(state, r)?)?;
            Ok(ip)
        }
        OP_SHL64_R_IMM8 | OP_SHR64_R_IMM8 | OP_SAR64_R_IMM8 => {
            let r = code[ip] as usize;
            let cnt = (code[ip + 1] & 63) as u32;
            let ip = ip + 2;
            let v = vreg64(state, r)?;
            let r2 = match op {
                OP_SHL64_R_IMM8 => v.wrapping_shl(cnt),
                OP_SHR64_R_IMM8 => v.wrapping_shr(cnt),
                _ => ((v as i64) >> cnt) as u64,
            };
            set_vreg64(state, r, r2)?;
            if cnt != 0 {
                let kind = match op {
                    OP_SHL64_R_IMM8 => flags::ShiftKind::Shl,
                    OP_SHR64_R_IMM8 => flags::ShiftKind::Shr,
                    _ => flags::ShiftKind::Sar,
                };
                set_flags(state, flags::shift_flags64(kind, v, cnt, r2));
            }
            Ok(ip)
        }
        OP_SHL64_R_CL | OP_SHR64_R_CL | OP_SAR64_R_CL => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let cnt = (vreg64(state, 1)? & 63) as u32;
            let v = vreg64(state, r)?;
            let r2 = match op {
                OP_SHL64_R_CL => v.wrapping_shl(cnt),
                OP_SHR64_R_CL => v.wrapping_shr(cnt),
                _ => ((v as i64) >> cnt) as u64,
            };
            set_vreg64(state, r, r2)?;
            if cnt != 0 {
                let kind = match op {
                    OP_SHL64_R_CL => flags::ShiftKind::Shl,
                    OP_SHR64_R_CL => flags::ShiftKind::Shr,
                    _ => flags::ShiftKind::Sar,
                };
                set_flags(state, flags::shift_flags64(kind, v, cnt, r2));
            }
            Ok(ip)
        }
        OP_LZCNT_R32 | OP_LZCNT_R64 => {
            let d = code[ip] as usize;
            let sr = code[ip + 1] as usize;
            let ip = ip + 2;
            let is64 = op == OP_LZCNT_R64;
            let v = if is64 { vreg64(state, sr)? } else { vreg32(state, sr)? as u64 };
            let lz = if is64 { v.leading_zeros() as u64 } else { (v as u32).leading_zeros() as u64 };
            set_vreg64(state, d, lz)?;
            // Real x86 (probe-verified): CF=1 iff src==0; ZF follows the RESULT
            // (lzcnt(0)=width → ZF=0; lzcnt(msb-set)=0 → ZF=1). OF/SF/AF cleared.
            let cf = if v == 0 { F_CF } else { 0 };
            let zf = if lz == 0 { F_ZF } else { 0 };
            set_flags(state, cf | zf);
            Ok(ip)
        }
        OP_POPCNT_R32 | OP_POPCNT_R64 => {
            let d = code[ip] as usize;
            let sr = code[ip + 1] as usize;
            let ip = ip + 2;
            let is64 = op == OP_POPCNT_R64;
            let v = if is64 { vreg64(state, sr)? } else { vreg32(state, sr)? as u64 };
            let pc = if is64 { v.count_ones() as u64 } else { (v as u32).count_ones() as u64 };
            set_vreg64(state, d, pc)?;
            if pc == 0 { set_flags(state, F_ZF); } else { set_flags(state, 0); }
            Ok(ip)
        }
        OP_BLSR_R32 | OP_BLSR_R64 | OP_BLSMSK_R32 | OP_BLSMSK_R64 | OP_BLSI_R32 | OP_BLSI_R64 => {
            let d = code[ip] as usize;
            let sr = code[ip + 1] as usize;
            let ip = ip + 2;
            let is64 = matches!(op, OP_BLSR_R64 | OP_BLSMSK_R64 | OP_BLSI_R64);
            let r = if is64 {
                let v = vreg64(state, sr)?;
                match op {
                    OP_BLSR_R64 => v & v.wrapping_sub(1),
                    OP_BLSMSK_R64 => v ^ v.wrapping_sub(1),
                    _ => v & v.wrapping_neg(),
                }
            } else {
                let v = vreg32(state, sr)?;
                let r = match op {
                    OP_BLSR_R32 => v & v.wrapping_sub(1),
                    OP_BLSMSK_R32 => v ^ v.wrapping_sub(1),
                    _ => v & v.wrapping_neg(),
                };
                r as u64
            };
            set_vreg64(state, d, r)?;
            // Intel SDM: BLSR/BLSMSK/BLSI clear SF/OF/CF and set ZF iff the
            // result is zero (BLS* are NOT flagless — a following jz must work).
            set_flags(state, flags::bls_flags(r));
            Ok(ip)
        }
        OP_ANDN_R_R32 | OP_ANDN_R_R64 => {
            let d = code[ip] as usize;
            let s1 = code[ip + 1] as usize;
            let s2 = code[ip + 2] as usize;
            let ip = ip + 3;
            let is64 = op == OP_ANDN_R_R64;
            let r = if is64 {
                let a = vreg64(state, s1)?;
                let b = vreg64(state, s2)?;
                !a & b
            } else {
                let a = vreg32(state, s1)?;
                let b = vreg32(state, s2)?;
                (!a & b) as u64
            };
            set_vreg64(state, d, r)?;
            // Intel SDM: ANDN updates SF/ZF from the result, clears CF/OF.
            set_flags(state, flags::andn_flags(r, is64));
            Ok(ip)
        }
        OP_TZCNT_R32 => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let ip = ip + 2;
            let v = vreg32(state, s)?;
            let lsb = v.wrapping_neg() & v;
            let cnt = lsb.wrapping_sub(1).count_ones() as u64; // == tzcnt, 32 when v==0
            set_vreg64(state, d, cnt)?;
            // Real x86 (probe-verified): CF=1 iff src==0; ZF follows the RESULT
            // (tzcnt(0)=width → ZF=0; tzcnt(odd)=0 → ZF=1). OF/SF/AF cleared.
            let cf = if v == 0 { F_CF } else { 0 };
            let zf = if cnt == 0 { F_ZF } else { 0 };
            set_flags(state, cf | zf);
            Ok(ip)
        }
        OP_CPUID => {
            let leaf = vreg64(state, 0)? as u32;
            let subleaf = vreg64(state, 2)? as u32;
            let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
            set_vreg64(state, 0, r.eax as u64)?;
            set_vreg64(state, 1, r.ebx as u64)?;
            set_vreg64(state, 2, r.ecx as u64)?;
            set_vreg64(state, 3, r.edx as u64)?;
            Ok(ip)
        }
        OP_XGETBV => {
            let ecxv = vreg64(state, 2)? as u32;
            let mut lo: u32;
            let mut hi: u32;
            unsafe {
                core::arch::asm!("xgetbv", in("ecx") ecxv, out("eax") lo, out("edx") hi, options(nostack, preserves_flags));
            }
            set_vreg64(state, 0, lo as u64)?;
            set_vreg64(state, 3, hi as u64)?;
            Ok(ip)
        }
        OP_BSWAP_R32 => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let v = vreg32(state, r)?.swap_bytes() as u64;
            set_vreg64(state, r, v)?;
            Ok(ip)
        }
        OP_BSWAP_R64 => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let v = vreg64(state, r)?.swap_bytes();
            set_vreg64(state, r, v)?;
            Ok(ip)
        }
        OP_BSR_R32 | OP_BSR_R64 | OP_BSF_R32 | OP_BSF_R64 => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let ip = ip + 2;
            let is64 = matches!(op, OP_BSR_R64 | OP_BSF_R64);
            let is_bsr = matches!(op, OP_BSR_R32 | OP_BSR_R64);
            let v = if is64 { vreg64(state, s)? } else { vreg32(state, s)? as u64 };
            if v == 0 {
                // ZF=1; dest undefined per Intel, set 0
                set_vreg64(state, d, 0)?;
                set_flags(state, F_ZF);
            } else {
                let idx = if is_bsr {
                    if is64 { 63 - v.leading_zeros() } else { 31 - (v as u32).leading_zeros() }
                } else {
                    v.trailing_zeros()
                } as u64;
                set_vreg64(state, d, idx)?;
                set_flags(state, 0); // ZF clear (src nonzero)
            }
            Ok(ip)
        }
        OP_SHLD_R_R_IMM8 | OP_SHLD_R_R_CL => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let (cnt, next_ip) = if op == OP_SHLD_R_R_IMM8 {
                (code[ip + 2] & 31, ip + 3)
            } else {
                ((vreg32(state, 1)? & 31) as u8, ip + 2)
            };
            if cnt > 0 {
                let dst = vreg32(state, d)?;
                let src = vreg32(state, s)?;
                let res = (dst << cnt) | (src >> (32 - cnt));
                set_vreg64(state, d, res as u64)?;
                // x86 SHLD: SF/ZF/PF from result; CF = last bit shifted out of
                // dst; OF/AF undefined (defined 0). Mirrors shift_flags(Shl).
                set_flags(state, flags::shift_flags(flags::ShiftKind::Shl, dst, cnt as u32, res));
            }
            Ok(next_ip)
        }
        OP_SHRD_R_R_IMM8 | OP_SHRD_R_R_CL => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let (cnt, next_ip) = if op == OP_SHRD_R_R_IMM8 {
                (code[ip + 2] & 31, ip + 3)
            } else {
                ((vreg32(state, 1)? & 31) as u8, ip + 2)
            };
            if cnt > 0 {
                let dst = vreg32(state, d)?;
                let src = vreg32(state, s)?;
                let res = (dst >> cnt) | (src << (32 - cnt));
                set_vreg64(state, d, res as u64)?;
                set_flags(state, flags::shift_flags(flags::ShiftKind::Shr, dst, cnt as u32, res));
            }
            Ok(next_ip)
        }
        OP_SHLD64_R_R_IMM8 | OP_SHLD64_R_R_CL => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let (cnt, next_ip) = if op == OP_SHLD64_R_R_IMM8 {
                (code[ip + 2] & 63, ip + 3)
            } else {
                ((vreg64(state, 1)? & 63) as u8, ip + 2)
            };
            if cnt > 0 {
                let dst = vreg64(state, d)?;
                let src = vreg64(state, s)?;
                let res = (dst << cnt) | (src >> (64 - cnt));
                set_vreg64(state, d, res)?;
                set_flags(state, flags::shift_flags64(flags::ShiftKind::Shl, dst, cnt as u32, res));
            }
            Ok(next_ip)
        }
        OP_SHRD64_R_R_IMM8 | OP_SHRD64_R_R_CL => {
            let d = code[ip] as usize;
            let s = code[ip + 1] as usize;
            let (cnt, next_ip) = if op == OP_SHRD64_R_R_IMM8 {
                (code[ip + 2] & 63, ip + 3)
            } else {
                ((vreg64(state, 1)? & 63) as u8, ip + 2)
            };
            if cnt > 0 {
                let dst = vreg64(state, d)?;
                let src = vreg64(state, s)?;
                let res = (dst >> cnt) | (src << (64 - cnt));
                set_vreg64(state, d, res)?;
                set_flags(state, flags::shift_flags64(flags::ShiftKind::Shr, dst, cnt as u32, res));
            }
            Ok(next_ip)
        }
        other => Err(VmError::UnknownOpcode(other)),
    }
}
