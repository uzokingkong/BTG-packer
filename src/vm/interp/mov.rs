// ==============================================================================
// BTG v21 - VM Interpreter: register / immediate moves
// ==============================================================================

use super::state::{VmError, vreg32, vreg64};
use crate::vm::bytecode::*;

/// Execute one pure register/immediate move opcode.
/// `ip` points at the first operand byte (opcode already consumed).
/// Returns the updated ip.
pub(crate) fn exec(
    state: &mut [u8],
    _mem: &mut [u8],
    code: &[u8],
    ip: usize,
    op: u8,
) -> Result<usize, VmError> {
    match op {
        OP_MOV_R_IMM32 => {
            let r = code[ip] as usize;
            let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
            let ip = ip + 5;
            *vreg64(state, r)? = imm as u64;
            Ok(ip)
        }
        OP_MOV_R_IMM64 => {
            let r = code[ip] as usize;
            let imm = u64::from_le_bytes(code[ip + 1..ip + 9].try_into().unwrap());
            let ip = ip + 9;
            *vreg64(state, r)? = imm;
            Ok(ip)
        }
        OP_MOV_R_R => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            *vreg64(state, dst)? = vreg32(state, src)? as u64;
            Ok(ip)
        }
        OP_MOV_R_R64 => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            *vreg64(state, dst)? = *vreg64(state, src)?;
            Ok(ip)
        }
        other => Err(VmError::UnknownOpcode(other)),
    }
}
