// ==============================================================================
// BTG v21 - VM Interpreter: 1-op multiply/divide (accumulator pair) opcodes
// ==============================================================================
//
// Covers MUL/IMUL1/DIV/IDIV with the RAX=v0 / RDX=v2 accumulator pair at
// 8/16/32/64-bit widths (v31 + v33).
//
// P0-⑤: MUL/IMUL set CF/OF = upper-half overflow (x86-defined); SF/ZF/AF/PF
// pass through unchanged (undefined on x86) — matching the RISC reference and
// the native handlers. DIV/IDIV leave ALL flags unchanged (undefined on x86).

use super::state::{flags_of, set_flags, set_vreg64, vreg32, vreg64, VmError};
use crate::vm::bytecode::*;
use crate::vm::flags;

/// Write CF/OF per the 1-op MUL/IMUL overflow rule, preserving the other bits.
#[inline]
fn set_mul_cf_of(state: &mut [u8], low: u64, high: u64, bits: u32, signed: bool) {
    let ovf = flags::mul_upper_ovf(low, high, bits, signed);
    set_flags(state, flags::muldiv_cf_of(flags_of(state), ovf));
}

/// Execute one multiply/divide opcode. `ip` points at the first operand byte
/// (opcode already consumed). Returns the updated ip.
pub(crate) fn exec(
    state: &mut [u8],
    _mem: &mut [u8],
    code: &[u8],
    ip: usize,
    op: u8,
) -> Result<usize, VmError> {
    match op {
        OP_MUL_R_R32 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let a = vreg32(state, 0)? as u64;
            let b = vreg32(state, src)? as u64;
            let p = a * b; // 64-bit product
            set_vreg64(state, 0, (p as u32) as u64)?; // EAX = low32
            set_vreg64(state, 2, ((p >> 32) as u32) as u64)?; // EDX = high32
            set_mul_cf_of(state, p as u32 as u64, p >> 32, 32, false);
            Ok(ip)
        }
        OP_MUL_R_R64 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let a = vreg64(state, 0)?;
            let b = vreg64(state, src)?;
            let p = (a as u128) * (b as u128);
            set_vreg64(state, 0, p as u64)?;
            set_vreg64(state, 2, (p >> 64) as u64)?;
            set_mul_cf_of(state, p as u64, (p >> 64) as u64, 64, false);
            Ok(ip)
        }
        OP_IMUL1_R_R32 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let a = vreg32(state, 0)? as i32 as i64;
            let b = vreg32(state, src)? as i32 as i64;
            let p = a * b; // signed 64-bit product
            set_vreg64(state, 0, (p as u32) as u64)?;
            set_vreg64(state, 2, ((p >> 32) as u32) as u64)?;
            set_mul_cf_of(state, p as u64, (p >> 32) as u64, 32, true);
            Ok(ip)
        }
        OP_IMUL1_R_R64 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let a = vreg64(state, 0)? as i64 as i128;
            let b = vreg64(state, src)? as i64 as i128;
            let p = a * b;
            set_vreg64(state, 0, p as u64)?;
            set_vreg64(state, 2, (p >> 64) as u64)?;
            set_mul_cf_of(state, p as u64, (p >> 64) as u64, 64, true);
            Ok(ip)
        }
        OP_DIV_R_R32 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let hi = (vreg32(state, 2)? as u64) << 32;
            let lo = vreg32(state, 0)? as u64;
            let dividend = hi | lo;
            let d = vreg32(state, src)? as u64;
            if d == 0 {
                return Err(VmError::DivByZero);
            }
            let q = dividend / d;
            let r = dividend % d;
            set_vreg64(state, 0, (q as u32) as u64)?;
            set_vreg64(state, 2, (r as u32) as u64)?;
            Ok(ip)
        }
        OP_DIV_R_R64 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let dividend = ((vreg64(state, 2)? as u128) << 64) | (vreg64(state, 0)? as u128);
            let d = vreg64(state, src)? as u128;
            if d == 0 {
                return Err(VmError::DivByZero);
            }
            let q = dividend / d;
            let r = dividend % d;
            set_vreg64(state, 0, q as u64)?;
            set_vreg64(state, 2, r as u64)?;
            Ok(ip)
        }
        OP_IDIV_R_R32 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            // EDX:EAX interpreted as signed 64-bit
            let hi = (vreg32(state, 2)? as u64) << 32;
            let lo = vreg32(state, 0)? as u64;
            let dividend = (hi | lo) as i64;
            let d = vreg32(state, src)? as i32 as i64;
            if d == 0 {
                return Err(VmError::DivByZero);
            }
            let q = dividend / d;
            let r = dividend % d;
            set_vreg64(state, 0, (q as u32) as u64)?;
            set_vreg64(state, 2, (r as u32) as u64)?;
            Ok(ip)
        }
        OP_IDIV_R_R64 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let dividend =
                (((vreg64(state, 2)? as u128) << 64) | (vreg64(state, 0)? as u128)) as i128;
            let d = vreg64(state, src)? as i64 as i128;
            if d == 0 {
                return Err(VmError::DivByZero);
            }
            let q = dividend / d;
            let r = dividend % d;
            set_vreg64(state, 0, q as u64)?;
            set_vreg64(state, 2, r as u64)?;
            Ok(ip)
        }
        OP_MUL_R_R8 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let a = (vreg64(state, 0)? & 0xFF) as u16;
            let b = (vreg64(state, src)? & 0xFF) as u16;
            let p = a * b; // 16-bit product ??AX
            set_vreg64(state, 0, p as u64)?; // zero-extend into v0
            set_mul_cf_of(state, p as u64, (p >> 8) as u64, 8, false);
            Ok(ip)
        }
        OP_MUL_R_R16 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let a = (vreg64(state, 0)? & 0xFFFF) as u32;
            let b = (vreg64(state, src)? & 0xFFFF) as u32;
            let p = a * b; // 32-bit product ??DX:AX
            set_vreg64(state, 0, (p & 0xFFFF) as u64)?;
            set_vreg64(state, 2, ((p >> 16) & 0xFFFF) as u64)?;
            set_mul_cf_of(state, p as u64, (p >> 16) as u64, 16, false);
            Ok(ip)
        }
        OP_IMUL1_R_R8 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let a = (vreg64(state, 0)? & 0xFF) as u8 as i8 as i16;
            let b = (vreg64(state, src)? & 0xFF) as u8 as i8 as i16;
            let p = a * b; // signed 16-bit product
            set_vreg64(state, 0, (p as u16) as u64)?;
            set_mul_cf_of(state, p as u64, (p >> 8) as u64, 8, true);
            Ok(ip)
        }
        OP_IMUL1_R_R16 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let a = (vreg64(state, 0)? & 0xFFFF) as u16 as i16 as i32;
            let b = (vreg64(state, src)? & 0xFFFF) as u16 as i16 as i32;
            let p = a * b; // signed 32-bit product ??DX:AX
            set_vreg64(state, 0, ((p as u32) & 0xFFFF) as u64)?;
            set_vreg64(state, 2, (((p as u32) >> 16) & 0xFFFF) as u64)?;
            set_mul_cf_of(state, p as u64, ((p >> 16) & 0xFFFF) as u64, 16, true);
            Ok(ip)
        }
        OP_DIV_R_R8 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let dividend = (vreg64(state, 0)? & 0xFFFF); // AX
            let d = (vreg64(state, src)? & 0xFF) as u16;
            if d == 0 {
                return Err(VmError::DivByZero);
            }
            let q = (dividend as u16) / d;
            let r = (dividend as u16) % d;
            // AL = quotient, AH = remainder (must fit 8 bits, else #DE)
            set_vreg64(state, 0, ((q & 0xFF) as u64) | (((r & 0xFF) as u64) << 8))?;
            Ok(ip)
        }
        OP_DIV_R_R16 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let lo = (vreg64(state, 0)? & 0xFFFF); // AX
            let hi = (vreg64(state, 2)? & 0xFFFF); // DX
            let dividend = (((hi << 16) | lo) & 0xFFFF_FFFF) as u32; // 32-bit DX:AX
            let d = (vreg64(state, src)? & 0xFFFF) as u32;
            if d == 0 {
                return Err(VmError::DivByZero);
            }
            let q = dividend / d;
            let r = dividend % d;
            set_vreg64(state, 0, (q & 0xFFFF) as u64)?;
            set_vreg64(state, 2, (r & 0xFFFF) as u64)?;
            Ok(ip)
        }
        OP_IDIV_R_R8 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let dividend = (vreg64(state, 0)? & 0xFFFF) as u16 as i16; // signed AX
            let d = (vreg64(state, src)? & 0xFF) as u8 as i8 as i16;
            if d == 0 {
                return Err(VmError::DivByZero);
            }
            let q = dividend / d;
            let r = dividend % d;
            set_vreg64(state, 0, ((q as u8) as u64) | (((r as u8) as u64) << 8))?;
            Ok(ip)
        }
        OP_IDIV_R_R16 => {
            let src = code[ip] as usize;
            let ip = ip + 1;
            let lo = (vreg64(state, 0)? & 0xFFFF);
            let hi = (vreg64(state, 2)? & 0xFFFF);
            let dividend = (((hi << 16) | lo) & 0xFFFF_FFFF) as i32; // signed 32-bit DX:AX
            let d = (vreg64(state, src)? & 0xFFFF) as u32 as i16 as i32;
            if d == 0 {
                return Err(VmError::DivByZero);
            }
            let q = dividend / d;
            let r = dividend % d;
            set_vreg64(state, 0, (q as i16 as u16) as u64)?;
            set_vreg64(state, 2, (r as i16 as u16) as u64)?;
            Ok(ip)
        }
        other => Err(VmError::UnknownOpcode(other)),
    }
}
