// ==============================================================================
// BTG v21 - VM Interpreter: register / immediate moves
// ==============================================================================

use super::state::{flags_of, set_vreg64, vreg32, vreg64, VmError};
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
            set_vreg64(state, r, imm as u64)?;
            Ok(ip)
        }
        OP_MOV_R_IMM64 => {
            let r = code[ip] as usize;
            let imm = u64::from_le_bytes(code[ip + 1..ip + 9].try_into().unwrap());
            let ip = ip + 9;
            set_vreg64(state, r, imm)?;
            Ok(ip)
        }
        OP_MOV_R_R => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            set_vreg64(state, dst, vreg32(state, src)? as u64)?;
            Ok(ip)
        }
        OP_MOV_R_R64 => {
            let dst = code[ip] as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
            set_vreg64(state, dst, vreg64(state, src)?)?;
            Ok(ip)
        }
        // v64: flags ↔ vreg 이동 (REP 문자열 루프가 x86 RFLAGS 를 보존).
        OP_MOV_R_FLAGS => {
            let d = code[ip] as usize;
            let ip = ip + 1;
            set_vreg64(state, d, flags_of(state))?;
            Ok(ip)
        }
        OP_MOV_FLAGS_R => {
            let s = code[ip] as usize;
            let ip = ip + 1;
            let v = vreg64(state, s)?;
            // Exact restore (get_flags/set_flags round-trip): unlike arithmetic
            // set_flags this must also write the saved DF bit.
            state[super::state::STATE_FLAGS..super::state::STATE_FLAGS + 8]
                .copy_from_slice(&(v & (FLAG_MASK | F_DF)).to_le_bytes());
            Ok(ip)
        }
        other => Err(VmError::UnknownOpcode(other)),
    }
}
