// ==============================================================================
// BTG v21 - VM Interpreter: control-flow / branch opcodes
// ==============================================================================
//
// Covers JMP/JB/JCC (rel8) and JMP/JCC (rel32). HALT is handled directly in
// mod.rs (it terminates the interpret loop), not here.

use super::state::{flags_of, VmError};
use crate::vm::bytecode::*;
use crate::vm::flags;

/// Execute one branch opcode. `ip` points at the first operand byte (opcode
/// already consumed). Returns the updated ip (target).
pub(crate) fn exec(
    state: &mut [u8],
    _mem: &mut [u8],
    code: &[u8],
    ip: usize,
    op: u8,
) -> Result<usize, VmError> {
    match op {
        OP_JMP8 => {
            let rel = code[ip] as i8 as i64;
            let ip = ip + 1;
            Ok((ip as i64 + rel) as usize)
        }
        OP_JB8 => {
            let rel = code[ip] as i8 as i64;
            let ip = ip + 1;
            if flags_of(state) & F_CF != 0 {
                Ok((ip as i64 + rel) as usize)
            } else {
                Ok(ip)
            }
        }
        OP_JCC8 => {
            let cond = code[ip];
            let rel = code[ip + 1] as i8 as i64;
            let ip = ip + 2;
            if flags::cond_taken(cond, flags_of(state)) {
                Ok((ip as i64 + rel) as usize)
            } else {
                Ok(ip)
            }
        }
        OP_JMP32 => {
            let rel = i32::from_le_bytes(code[ip..ip + 4].try_into().unwrap());
            let ip = ip + 4;
            Ok((ip as i64 + rel as i64) as usize)
        }
        OP_JCC32 => {
            let cond = code[ip];
            let rel = i32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
            let ip = ip + 5;
            if flags::cond_taken(cond, flags_of(state)) {
                Ok((ip as i64 + rel as i64) as usize)
            } else {
                Ok(ip)
            }
        }
        other => Err(VmError::UnknownOpcode(other)),
    }
}
