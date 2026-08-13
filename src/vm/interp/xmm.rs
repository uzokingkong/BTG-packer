// ==============================================================================
// BTG v21 - VM Interpreter: XMM moves / shuffles / packed shifts / PINSRW
// ==============================================================================

use super::state::{VmError, STATE_XMM, mem_get, mem_put, vreg64};
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
            let v = (*vreg64(state, src)? & 0xFFFF) as u16;
            let base = STATE_XMM + dst * 16 + (lane as usize & 7) * 2;
            state[base..base + 2].copy_from_slice(&v.to_le_bytes());
            Ok(ip)
        }
        OP_MOVSD_XMM_MEM => {
            let xmm = code[ip] as usize;
            let addr = *vreg64(state, code[ip + 1] as usize)? as usize;
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
            *vreg64(state, gpr)? = lo;
            Ok(ip)
        }
        OP_MOVQ_GPR_XMM => {
            let xmm = code[ip] as usize;
            let gpr = code[ip + 1] as usize;
            let ip = ip + 2;
            let base = STATE_XMM + xmm * 16;
            let v = *vreg64(state, gpr)?;
            state[base..base + 8].copy_from_slice(&v.to_le_bytes());
            state[base + 8..base + 16].fill(0);
            Ok(ip)
        }
        OP_MOVSD_MEM_XMM => {
            let addr = *vreg64(state, code[ip] as usize)? as usize;
            let xmm = code[ip + 1] as usize;
            let ip = ip + 2;
            let base = STATE_XMM + xmm * 16;
            let lo = u64::from_le_bytes(state[base..base + 8].try_into().unwrap());
            mem_put(mem, addr, &lo.to_le_bytes())?;
            Ok(ip)
        }
        OP_MOVUPS_XMM_MEM => {
            let xmm = code[ip] as usize;
            let addr = *vreg64(state, code[ip + 1] as usize)? as usize;
            let ip = ip + 2;
            let bytes = mem_get(mem, addr, 8).ok_or(VmError::OobMem)?.to_vec();
            let bytes2 = mem_get(mem, addr + 8, 8).ok_or(VmError::OobMem)?.to_vec();
            let base = STATE_XMM + xmm * 16;
            state[base..base + 8].copy_from_slice(&bytes);
            state[base + 8..base + 16].copy_from_slice(&bytes2);
            Ok(ip)
        }
        OP_MOVUPS_MEM_XMM => {
            let addr = *vreg64(state, code[ip] as usize)? as usize;
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
        other => Err(VmError::UnknownOpcode(other)),
    }
}
