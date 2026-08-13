// ==============================================================================
// BTG v21 - VM Interpreter: stack + call/ret opcodes
// ==============================================================================
//
// Two-stack model (v13.4e): PUSH/POP operate on the *architectural* program
// stack (vreg[4] = RSP, an absolute mem address); CALL/RET move the bytecode
// return IP on the dedicated VM return-IP stack (STATE_CALL_SP /
// STATE_PTR_CALL_STACK) and keep the program's observed return VA on [v4].

use super::state::{
    VmError, call_sp_of, call_stack_addr, mem_get, mem_put, set_call_sp, set_sp, sp_of, vreg64,
};
use crate::vm::bytecode::*;

/// Execute one stack/call opcode. `ip` points at the first operand byte
/// (opcode already consumed). Returns the updated ip.
pub(crate) fn exec(
    state: &mut [u8],
    mem: &mut [u8],
    code: &[u8],
    ip: usize,
    op: u8,
) -> Result<usize, VmError> {
    match op {
        OP_PUSH_R => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let sp = sp_of(state).wrapping_sub(8);
            set_sp(state, sp);
            let addr = sp as usize;
            mem_put(mem, addr, &vreg64(state, r)?.to_le_bytes())?;
            Ok(ip)
        }
        OP_POP_R => {
            let r = code[ip] as usize;
            let ip = ip + 1;
            let sp = sp_of(state);
            let addr = sp as usize;
            let val = u64::from_le_bytes(mem_get(mem, addr, 8).ok_or(VmError::OobMem)?.try_into().unwrap());
            *vreg64(state, r)? = val;
            set_sp(state, sp.wrapping_add(8));
            Ok(ip)
        }
        OP_CALL8 => {
            let rel = code[ip] as i8 as i64;
            let ip = ip + 1;
            // Two-stack model: the bytecode return IP goes on the VM return-IP
            // stack (STATE_CALL_SP), NOT on the architectural stack [v4]. The
            // program's observed return address (original x86 return VA) is
            // pushed to [v4] separately by the lifter before the call.
            let ret_ip = ip as u64;
            let csp = call_sp_of(state).wrapping_sub(8);
            set_call_sp(state, csp);
            let caddr = call_stack_addr(state, csp);
            mem_put(mem, caddr, &ret_ip.to_le_bytes())?;
            Ok((ip as i64 + rel) as usize)
        }
        OP_RET => {
            // Pop the bytecode return IP from the VM return-IP stack (control
            // flow); advance the architectural RSP (v4) past the caller's
            // pushed return VA.
            let csp = call_sp_of(state);
            let val = u64::from_le_bytes(mem_get(mem, call_stack_addr(state, csp), 8).ok_or(VmError::OobMem)?.try_into().unwrap());
            set_call_sp(state, csp.wrapping_add(8));
            set_sp(state, sp_of(state).wrapping_add(8));
            Ok(val as usize)
        }
        OP_RET_IMM16 => {
            let imm = u16::from_le_bytes(code[ip..ip + 2].try_into().unwrap());
            let ip = ip + 2;
            let csp = call_sp_of(state);
            let val = u64::from_le_bytes(mem_get(mem, call_stack_addr(state, csp), 8).ok_or(VmError::OobMem)?.try_into().unwrap());
            set_call_sp(state, csp.wrapping_add(8));
            set_sp(state, sp_of(state).wrapping_add(8 + imm as u64));
            Ok(val as usize)
        }
        OP_CALL32 => {
            let rel = i32::from_le_bytes(code[ip..ip + 4].try_into().unwrap());
            let ip = ip + 4;
            let ret_ip = ip as u64;
            let csp = call_sp_of(state).wrapping_sub(8);
            set_call_sp(state, csp);
            let caddr = call_stack_addr(state, csp);
            mem_put(mem, caddr, &ret_ip.to_le_bytes())?;
            Ok((ip as i64 + rel as i64) as usize)
        }
        other => Err(VmError::UnknownOpcode(other)),
    }
}
