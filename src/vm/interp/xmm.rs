// ==============================================================================
// BTG v21 - VM Interpreter: XMM moves / shuffles / packed shifts / PINSRW
// ==============================================================================

use super::state::{VmError, STATE_XMM, mem_get, mem_put, set_vreg64, vreg32, vreg64};
use crate::vm::bytecode::*;

/// Execute one XMM opcode. `ip` points at the first operand byte (opcode
/// already consumed). Returns the updated ip.
pub(crate) fn exec(
    state: &mut [u8],
    mem: &mut [u8],
    code: &[u8],
    ip: usize,
    op: u8,
) -> Result<usize, VmError> {
    match op {
        OP_PINSRW_XMM => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let lane = code[ip + 2];
            let ip = ip + 3;
            let v = (vreg64(state, src)? & 0xFFFF) as u16;
            let base = STATE_XMM + dst * 16 + (lane as usize & 7) * 2;
            state[base..base + 2].copy_from_slice(&v.to_le_bytes());
            Ok(ip)
        }
        OP_MOVSD_XMM_MEM => {
            let xmm = code[ip] as usize;
            let addr = vreg64(state, code[ip + 1] as usize)? as usize;
            let ip = ip + 2;
            let v = u64::from_le_bytes(mem_get(mem, addr, 8).ok_or(VmError::OobMem)?.try_into().unwrap());
            let base = STATE_XMM + xmm * 16;
            state[base..base + 8].copy_from_slice(&v.to_le_bytes());
            state[base + 8..base + 16].fill(0);
            Ok(ip)
        }
        OP_MOVQ_XMM_GPR => {
            let gpr = code[ip] as usize;
            let xmm = code[ip + 1] as usize;
            let ip = ip + 2;
            let base = STATE_XMM + xmm * 16;
            let lo = u64::from_le_bytes(state[base..base + 8].try_into().unwrap());
            set_vreg64(state, gpr, lo)?;
            Ok(ip)
        }
        OP_MOVQ_GPR_XMM => {
            let xmm = code[ip] as usize;
            let gpr = code[ip + 1] as usize;
            let ip = ip + 2;
            let base = STATE_XMM + xmm * 16;
            let v = vreg64(state, gpr)?;
            state[base..base + 8].copy_from_slice(&v.to_le_bytes());
            state[base + 8..base + 16].fill(0);
            Ok(ip)
        }
        OP_MOVSD_MEM_XMM => {
            let addr = vreg64(state, code[ip] as usize)? as usize;
            let xmm = code[ip + 1] as usize;
            let ip = ip + 2;
            let base = STATE_XMM + xmm * 16;
            let lo = u64::from_le_bytes(state[base..base + 8].try_into().unwrap());
            mem_put(mem, addr, &lo.to_le_bytes())?;
            Ok(ip)
        }
        OP_MOVUPS_XMM_MEM => {
            let xmm = code[ip] as usize;
            let addr = vreg64(state, code[ip + 1] as usize)? as usize;
            let ip = ip + 2;
            let bytes = mem_get(mem, addr, 8).ok_or(VmError::OobMem)?.to_vec();
            let bytes2 = mem_get(mem, addr + 8, 8).ok_or(VmError::OobMem)?.to_vec();
            let base = STATE_XMM + xmm * 16;
            state[base..base + 8].copy_from_slice(&bytes);
            state[base + 8..base + 16].copy_from_slice(&bytes2);
            Ok(ip)
        }
        OP_MOVUPS_MEM_XMM => {
            let addr = vreg64(state, code[ip] as usize)? as usize;
            let xmm = code[ip + 1] as usize;
            let ip = ip + 2;
            let base = STATE_XMM + xmm * 16;
            let lo = state[base..base + 8].to_vec();
            let hi = state[base + 8..base + 16].to_vec();
            mem_put(mem, addr, &lo)?;
            mem_put(mem, addr + 8, &hi)?;
            Ok(ip)
        }
        OP_UNPCKLPD_XMM => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            let dbase = STATE_XMM + dst * 16;
            let sbase = STATE_XMM + src * 16;
            let dlo = state[dbase..dbase + 8].to_vec();
            let slo = state[sbase..sbase + 8].to_vec();
            state[dbase..dbase + 8].copy_from_slice(&dlo);
            state[dbase + 8..dbase + 16].copy_from_slice(&slo);
            Ok(ip)
        }
        OP_UNPCKLPS_XMM => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            let dbase = STATE_XMM + dst * 16;
            let sbase = STATE_XMM + src * 16;
            // Read all four dwords BEFORE writing (dst == src must be safe):
            // result = { src.d1, dst.d1, src.d0, dst.d0 }.
            let d0 = state[dbase..dbase + 4].to_vec();
            let d1 = state[dbase + 4..dbase + 8].to_vec();
            let s0 = state[sbase..sbase + 4].to_vec();
            let s1 = state[sbase + 4..sbase + 8].to_vec();
            state[dbase..dbase + 4].copy_from_slice(&d0);
            state[dbase + 4..dbase + 8].copy_from_slice(&s0);
            state[dbase + 8..dbase + 12].copy_from_slice(&d1);
            state[dbase + 12..dbase + 16].copy_from_slice(&s1);
            Ok(ip)
        }
        OP_XORPS_XMM => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            let db = STATE_XMM + dst * 16;
            let sb = STATE_XMM + src * 16;
            for k in 0..16 {
                state[db + k] ^= state[sb + k];
            }
            Ok(ip)
        }
        OP_PSRLQ_XMM_IMM8 | OP_PSLLQ_XMM_IMM8 => {
            let dst = code[ip] as usize;
            let imm = code[ip + 1];
            let ip = ip + 2;
            let db = STATE_XMM + dst * 16;
            let shl = op == OP_PSLLQ_XMM_IMM8;
            let cnt = (imm & 0x3F) as u32;
            for lane in 0..2 {
                let off = db + lane * 8;
                let v = u64::from_le_bytes(state[off..off + 8].try_into().unwrap());
                let r = if shl { v.wrapping_shl(cnt) } else { v.wrapping_shr(cnt) };
                state[off..off + 8].copy_from_slice(&r.to_le_bytes());
            }
            Ok(ip)
        }
        OP_PSHUFLW_XMM | OP_PSHUFHW_XMM | OP_PSHUFD_XMM => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let imm = code[ip + 2];
            let ip = ip + 3;
            let db = STATE_XMM + dst * 16;
            let sb = STATE_XMM + src * 16;
            // 16-bit words little-endian
            let mut w = [0u16; 8];
            for i in 0..8 {
                w[i] = u16::from_le_bytes(state[sb + i * 2..sb + i * 2 + 2].try_into().unwrap());
            }
            if op == OP_PSHUFLW_XMM {
                // low 4 words shuffled; high 4 words unchanged
                let mut nw = w;
                for i in 0..4 {
                    let sel = ((imm >> (2 * i)) & 3) as usize;
                    nw[i] = w[sel];
                }
                for i in 0..4 {
                    state[db + i * 2..db + i * 2 + 2].copy_from_slice(&nw[i].to_le_bytes());
                }
            } else if op == OP_PSHUFHW_XMM {
                // high 4 words shuffled; low 4 words unchanged
                let mut nw = w;
                for i in 0..4 {
                    let sel = ((imm >> (2 * i)) & 3) as usize;
                    nw[i + 4] = w[sel + 4];
                }
                for i in 4..8 {
                    state[db + i * 2..db + i * 2 + 2].copy_from_slice(&nw[i].to_le_bytes());
                }
            } else {
                // pshufd: 4 dwords shuffled
                let mut d = [0u32; 4];
                for i in 0..4 {
                    d[i] = u32::from_le_bytes(state[sb + i * 4..sb + i * 4 + 4].try_into().unwrap());
                }
                let mut nd = d;
                for i in 0..4 {
                    let sel = ((imm >> (2 * i)) & 3) as usize;
                    nd[i] = d[sel];
                }
                for i in 0..4 {
                    state[db + i * 4..db + i * 4 + 4].copy_from_slice(&nd[i].to_le_bytes());
                }
            }
            Ok(ip)
        }
        // ?? v54: SSE/FPU (Group A) ??????????????????????????????????????????
        // Scalar FP arithmetic: xmm[dst].low = xmm[dst].low OP xmm[src].low;
        // all other bytes of dst are preserved. No status flags are touched
        // (x86 SSE scalar FP writes MXCSR, not rflags).
        OP_ADDSS_XMM | OP_ADDSD_XMM | OP_SUBSS_XMM | OP_SUBSD_XMM
        | OP_MULSS_XMM | OP_MULSD_XMM | OP_DIVSS_XMM | OP_DIVSD_XMM => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            let db = STATE_XMM + dst * 16;
            let sb = STATE_XMM + src * 16;
            match op {
                OP_ADDSS_XMM | OP_SUBSS_XMM | OP_MULSS_XMM | OP_DIVSS_XMM => {
                    let a = f32::from_le_bytes(state[db..db + 4].try_into().unwrap());
                    let b = f32::from_le_bytes(state[sb..sb + 4].try_into().unwrap());
                    let r = match op {
                        OP_ADDSS_XMM => a + b,
                        OP_SUBSS_XMM => a - b,
                        OP_MULSS_XMM => a * b,
                        _ => a / b,
                    };
                    state[db..db + 4].copy_from_slice(&r.to_le_bytes());
                }
                _ => {
                    let a = f64::from_le_bytes(state[db..db + 8].try_into().unwrap());
                    let b = f64::from_le_bytes(state[sb..sb + 8].try_into().unwrap());
                    let r = match op {
                        OP_ADDSD_XMM => a + b,
                        OP_SUBSD_XMM => a - b,
                        OP_MULSD_XMM => a * b,
                        _ => a / b,
                    };
                    state[db..db + 8].copy_from_slice(&r.to_le_bytes());
                }
            }
            Ok(ip)
        }
        // 128-bit packed logic: PAND (dst &= src), POR (dst |= src),
        // PANDN (dst = ~dst & src).
        OP_PAND_XMM | OP_POR_XMM | OP_PANDN_XMM => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            let db = STATE_XMM + dst * 16;
            let sb = STATE_XMM + src * 16;
            for k in 0..16 {
                state[db + k] = match op {
                    OP_PAND_XMM => state[db + k] & state[sb + k],
                    OP_POR_XMM => state[db + k] | state[sb + k],
                    _ => !state[db + k] & state[sb + k],
                };
            }
            Ok(ip)
        }
        // cvtsi2sd/cvtsi2ss: xmm[dst].low = (f64/f32)(signed vreg[src]);
        // everything above the converted element is zeroed.
        OP_CVTSI2SD_XMM | OP_CVTSI2SS_XMM => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            let db = STATE_XMM + dst * 16;
            if op == OP_CVTSI2SD_XMM {
                let v = vreg64(state, src)? as i64;
                state[db..db + 16].fill(0);
                state[db..db + 8].copy_from_slice(&(v as f64).to_le_bytes());
            } else {
                let v = vreg32(state, src)? as i32;
                state[db..db + 16].fill(0);
                state[db..db + 4].copy_from_slice(&(v as f32).to_le_bytes());
            }
            Ok(ip)
        }
        // cvtss2sd: xmm[dst].low64 = (f64)xmm[src].low32 (upper 64 bits zeroed).
        // cvtsd2ss: xmm[dst].low32 = (f32)xmm[src].low64 (upper 96 bits zeroed).
        OP_CVTSS2SD_XMM | OP_CVTSD2SS_XMM => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            let db = STATE_XMM + dst * 16;
            let sb = STATE_XMM + src * 16;
            if op == OP_CVTSS2SD_XMM {
                let v = f32::from_le_bytes(state[sb..sb + 4].try_into().unwrap()) as f64;
                state[db..db + 16].fill(0);
                state[db..db + 8].copy_from_slice(&v.to_le_bytes());
            } else {
                let v = f64::from_le_bytes(state[sb..sb + 8].try_into().unwrap()) as f32;
                state[db..db + 16].fill(0);
                state[db..db + 4].copy_from_slice(&v.to_le_bytes());
            }
            Ok(ip)
        }
        // cvttss2si/cvttsd2si (truncate toward zero) and cvtss2si/cvtsd2si
        // (round to nearest even): vreg[dst] = (i32)(low elem), zero-extended.
        // NaN / out-of-range yield the x86 "integer indefinite" 0x8000_0000.
        OP_CVTTSS2SI | OP_CVTTSD2SI | OP_CVTSS2SI | OP_CVTSD2SI => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            let sb = STATE_XMM + src * 16;
            let is_ss = matches!(op, OP_CVTTSS2SI | OP_CVTSS2SI);
            let trunc = matches!(op, OP_CVTTSS2SI | OP_CVTTSD2SI);
            let x = if is_ss {
                f32::from_le_bytes(state[sb..sb + 4].try_into().unwrap()) as f64
            } else {
                f64::from_le_bytes(state[sb..sb + 8].try_into().unwrap())
            };
            set_vreg64(state, dst, cvt_f64_i32(x, trunc) as u64)?;
            Ok(ip)
        }
        // pextrd: vreg[dst] = xmm[src].dword[imm & 3] (zero-extended).
        OP_PEXTRD_XMM => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let lane = (code[ip + 2] & 3) as usize;
            let ip = ip + 3;
            let base = STATE_XMM + src * 16 + lane * 4;
            let v = u32::from_le_bytes(state[base..base + 4].try_into().unwrap());
            set_vreg64(state, dst, v as u64)?;
            Ok(ip)
        }
        // pinsrd: xmm[dst].dword[imm & 3] = vreg[src].low32 (others kept).
        OP_PINSRD_XMM => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let lane = (code[ip + 2] & 3) as usize;
            let ip = ip + 3;
            let v = (vreg64(state, src)? & 0xFFFF_FFFF) as u32;
            let base = STATE_XMM + dst * 16 + lane * 4;
            state[base..base + 4].copy_from_slice(&v.to_le_bytes());
            Ok(ip)
        }
        other => Err(VmError::UnknownOpcode(other)),
    }
}

/// Round to nearest, ties to even (the default SSE MXCSR rounding mode).
fn round_ties_even(x: f64) -> f64 {
    let t = x.trunc();
    let d = (x - t).abs();
    if d < 0.5 {
        t
    } else if d > 0.5 {
        t + x.signum()
    } else if (t as i64) % 2 == 0 {
        t
    } else {
        t + x.signum()
    }
}

/// Float -> 32-bit integer with x86 CVT(T)Sx2SI semantics: NaN / out-of-range
/// produce the "integer indefinite" value 0x8000_0000.
fn cvt_f64_i32(x: f64, trunc: bool) -> u32 {
    let r = if trunc { x.trunc() } else { round_ties_even(x) };
    if !r.is_finite() || r < -2147483648.0 || r >= 2147483648.0 {
        return 0x8000_0000;
    }
    r as i32 as u32
}
