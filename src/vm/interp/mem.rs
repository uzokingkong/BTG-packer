// ==============================================================================
// BTG v21 - VM Interpreter: memory load/store + addressing-mode ops
// ==============================================================================
//
// Covers slot-relative loads/stores (MOVZX/MOVSX/MOV widths), absolute
// addressing-mode loads/stores (v24 _A suffix), and the address-computation
// ops (LEA / SET_RIP / LEA_RIP / LEA_GS).

use super::state::{
    mem_get, mem_put, ptr_slot, set_vreg64, vreg64, VmError, STATE_RIP, STATE_SEG_GS,
};
use crate::vm::bytecode::*;

/// Execute one memory / addressing opcode. `ip` points at the first operand
/// byte (opcode already consumed). Returns the updated ip.
pub(crate) fn exec(
    state: &mut [u8],
    mem: &mut [u8],
    code: &[u8],
    ip: usize,
    op: u8,
) -> Result<usize, VmError> {
    match op {
        OP_MOVZX_R_MEM8 => {
            let dst = code[ip] as usize;
            let slot = code[ip + 1] as usize;
            let idx = code[ip + 2] as usize;
            let ip = ip + 3;
            let base = ptr_slot(state, slot)?;
            let off = vreg64(state, idx)? as usize;
            let addr = base.checked_add(off).ok_or(VmError::OobMem)?;
            let byte = mem.get(addr).copied().ok_or(VmError::OobMem)?;
            set_vreg64(state, dst, byte as u64)?;
            Ok(ip)
        }
        OP_MOV_MEM8_R => {
            let slot = code[ip] as usize;
            let idx = code[ip + 1] as usize;
            let src = code[ip + 2] as usize;
            let ip = ip + 3;
            let base = ptr_slot(state, slot)?;
            let off = vreg64(state, idx)? as usize;
            let addr = base.checked_add(off).ok_or(VmError::OobMem)?;
            let byte = vreg64(state, src)? as u8;
            *mem.get_mut(addr).ok_or(VmError::OobMem)? = byte;
            Ok(ip)
        }
        OP_MOVZX_R_MEM16 | OP_MOVZX_R_MEM32 | OP_MOVSX_R_MEM8 | OP_MOVSX_R_MEM16
        | OP_MOV_R_MEM64 => {
            let dst = code[ip] as usize;
            let slot = code[ip + 1] as usize;
            let idx = code[ip + 2] as usize;
            let ip = ip + 3;
            let base = ptr_slot(state, slot)?;
            let off = vreg64(state, idx)? as usize;
            let addr = base.checked_add(off).ok_or(VmError::OobMem)?;
            let val = match op {
                OP_MOVZX_R_MEM16 => {
                    let v = mem_get(mem, addr, 2).ok_or(VmError::OobMem)?;
                    u16::from_le_bytes(v[..2].try_into().unwrap()) as u64
                }
                OP_MOVZX_R_MEM32 => {
                    let v = mem_get(mem, addr, 4).ok_or(VmError::OobMem)?;
                    u32::from_le_bytes(v[..4].try_into().unwrap()) as u64
                }
                OP_MOVSX_R_MEM8 => {
                    mem_get(mem, addr, 1).ok_or(VmError::OobMem)?[0] as i8 as i64 as u64
                }
                OP_MOVSX_R_MEM16 => {
                    let v = mem_get(mem, addr, 2).ok_or(VmError::OobMem)?;
                    i16::from_le_bytes(v[..2].try_into().unwrap()) as i64 as u64
                }
                _ => u64::from_le_bytes(
                    mem_get(mem, addr, 8)
                        .ok_or(VmError::OobMem)?
                        .try_into()
                        .unwrap(),
                ),
            };
            set_vreg64(state, dst, val)?;
            Ok(ip)
        }
        OP_MOV_MEM16_R | OP_MOV_MEM32_R | OP_MOV_MEM64_R => {
            let slot = code[ip] as usize;
            let idx = code[ip + 1] as usize;
            let src = code[ip + 2] as usize;
            let ip = ip + 3;
            let base = ptr_slot(state, slot)?;
            let off = vreg64(state, idx)? as usize;
            let addr = base.checked_add(off).ok_or(VmError::OobMem)?;
            let sv = vreg64(state, src)?;
            match op {
                OP_MOV_MEM16_R => mem_put(mem, addr, &(sv as u16).to_le_bytes())?,
                OP_MOV_MEM32_R => mem_put(mem, addr, &(sv as u32).to_le_bytes())?,
                _ => mem_put(mem, addr, &sv.to_le_bytes())?,
            }
            Ok(ip)
        }
        OP_LEA => {
            let dst = code[ip] as usize;
            let base = code[ip + 1] as usize;
            let idx = code[ip + 2] as usize;
            let sc = code[ip + 3] as u32;
            let disp = i32::from_le_bytes(code[ip + 4..ip + 8].try_into().unwrap()) as i64 as u64;
            let ip = ip + 8;
            let mut a = vreg64(state, base)?.wrapping_add(disp);
            if idx != ADDR_NO_INDEX as usize {
                a = a.wrapping_add(vreg64(state, idx)?.wrapping_mul(1u64 << sc));
            }
            set_vreg64(state, dst, a)?;
            Ok(ip)
        }
        OP_SET_RIP => {
            let rip = u64::from_le_bytes(code[ip..ip + 8].try_into().unwrap());
            let ip = ip + 8;
            state[STATE_RIP..STATE_RIP + 8].copy_from_slice(&rip.to_le_bytes());
            Ok(ip)
        }
        OP_LEA_RIP => {
            let dst = code[ip] as usize;
            let rel = i32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap()) as i64 as u64;
            let ip = ip + 5;
            let rip = u64::from_le_bytes(state[STATE_RIP..STATE_RIP + 8].try_into().unwrap());
            set_vreg64(state, dst, rip.wrapping_add(rel))?;
            Ok(ip)
        }
        OP_LEA_GS => {
            let dst = code[ip] as usize;
            let disp = i32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap()) as i64 as u64;
            let ip = ip + 5;
            let gs = u64::from_le_bytes(state[STATE_SEG_GS..STATE_SEG_GS + 8].try_into().unwrap());
            set_vreg64(state, dst, gs.wrapping_add(disp))?;
            Ok(ip)
        }
        OP_MOVZX_R_MEM8_A | OP_MOVZX_R_MEM16_A | OP_MOVZX_R_MEM32_A | OP_MOVSX_R_MEM8_A
        | OP_MOVSX_R_MEM16_A | OP_MOV_R_MEM64_A => {
            let dst = code[ip] as usize;
            let addr = vreg64(state, code[ip + 1] as usize)? as usize;
            let ip = ip + 2;
            let val = match op {
                OP_MOVZX_R_MEM8_A => mem_get(mem, addr, 1).ok_or(VmError::OobMem)?[0] as u64,
                OP_MOVZX_R_MEM16_A => {
                    let v = mem_get(mem, addr, 2).ok_or(VmError::OobMem)?;
                    u16::from_le_bytes(v[..2].try_into().unwrap()) as u64
                }
                OP_MOVZX_R_MEM32_A => {
                    let v = mem_get(mem, addr, 4).ok_or(VmError::OobMem)?;
                    u32::from_le_bytes(v[..4].try_into().unwrap()) as u64
                }
                OP_MOVSX_R_MEM8_A => {
                    mem_get(mem, addr, 1).ok_or(VmError::OobMem)?[0] as i8 as i64 as u64
                }
                OP_MOVSX_R_MEM16_A => {
                    let v = mem_get(mem, addr, 2).ok_or(VmError::OobMem)?;
                    i16::from_le_bytes(v[..2].try_into().unwrap()) as i64 as u64
                }
                _ => u64::from_le_bytes(
                    mem_get(mem, addr, 8)
                        .ok_or(VmError::OobMem)?
                        .try_into()
                        .unwrap(),
                ),
            };
            set_vreg64(state, dst, val)?;
            Ok(ip)
        }
        OP_MOV_MEM8_A | OP_MOV_MEM16_A | OP_MOV_MEM32_A | OP_MOV_MEM64_A => {
            let addr = vreg64(state, code[ip] as usize)? as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            let sv = vreg64(state, src)?;
            match op {
                OP_MOV_MEM8_A => mem_put(mem, addr, &(sv as u8).to_le_bytes())?,
                OP_MOV_MEM16_A => mem_put(mem, addr, &(sv as u16).to_le_bytes())?,
                OP_MOV_MEM32_A => mem_put(mem, addr, &(sv as u32).to_le_bytes())?,
                _ => mem_put(mem, addr, &sv.to_le_bytes())?,
            }
            Ok(ip)
        }
        other => Err(VmError::UnknownOpcode(other)),
    }
}
