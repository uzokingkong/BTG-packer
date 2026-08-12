// ==============================================================================
// BTG v21 - VM Bytecode Reference Interpreter (Rust)
// ==============================================================================
//
// Executes the VM bytecode in software. Used by the --vm-test self-test to
// cross-check the generated x86-64 handlers: bytecode interpreted here must
// produce byte-identical results to the handlers executed natively.
//
// The interpreter models the runtime memory as two regions:
//   * `state` — the VM state buffer (layout below). Pointer slots hold
//     *offsets into `mem`* (the addressable arena). The real generated VM
//     instead holds absolute VAs in the slots; semantics are identical.
//   * `mem`   — the memory arena the virtualized routine reads/writes
//     (e.g. the S-box and masked seed arrays).
//
// State layout (matches handlers.rs / the packer integration):
//   [0x000] vregs[16] x u64
//   [0x100] flags u64       (x86 RFLAGS bit positions: CF/PF/AF/ZF/SF/OF — v21)
//   [0x110] ptr_sbox u64     (offset into mem)
//   [0x118] ptr_seed u64
//   [0x120] ptr_buf u64
//   [0x128] ptr_runs u64
//   [0x130] STATE_SIZE (end)
// ==============================================================================


use crate::vm::bytecode::*;
use crate::vm::flags;

pub const STATE_VREGS: usize = 0x000;
/// Number of valid virtual registers (indices 0..NREG).
/// 0..=15 = the 16 program GPRs (RAX..R15), 16/17 = lifter SCRATCH/SCRATCH2,
/// 18 = lifter TMP, 19 = lifter temp. Anything >= NREG would overrun into the
/// control slots (STATE_FLAGS at vreg 32) or past the state buffer.
pub const NREG: usize = 20;
pub const STATE_FLAGS: usize = 0x100;
pub const STATE_SP: usize = 0x108;      // M3: stack pointer (offset from stack base)
pub const STATE_PTR_SBOX: usize = 0x110;
pub const STATE_PTR_SEED: usize = 0x118;
pub const STATE_PTR_BUF: usize = 0x120;
pub const STATE_PTR_RUNS: usize = 0x128;
pub const STATE_PTR_STACK: usize = 0x130; // M3: stack base pointer
pub const STATE_RIP: usize = 0x138;       // v24: base VA of current lifted instruction (RIP-rel)
pub const STATE_XMM: usize = 0x140;       // v29: XMM register file (16 regs x 16 bytes = 0x100)
pub const STATE_SEG_GS: usize = 0x240;    // v43: GS segment base (= TEB). M6 Phase-2 PEB/TEB 접근.
// ── Two-stack model (v13.4e): the VM keeps the *architectural* program stack on
//    vreg[4] (RSP) and a SEPARATE VM bytecode return-IP stack here. CALL/RET no
//    longer conflate the bytecode IP with the program's observed return address:
//    CALL stores the program's original return VA on [v4] (RSP) and the bytecode
//    return IP on this dedicated stack; RET pops the bytecode IP for control flow
//    and advances v4 past the return VA. STATE_SP/STATE_PTR_STACK (0x108/0x130)
//    are legacy M3 slots no longer used by call/ret/push/pop.
pub const STATE_CALL_SP: usize = 0x248;          // VM bytecode return-IP stack offset (from base)
pub const STATE_PTR_CALL_STACK: usize = 0x250;   // VM bytecode return-IP stack base
// Dedicated bytecode return-IP stack buffer lives OUTSIDE the state buffer (the
// boot stub reserves CALL_STACK_SIZE right after it and points STATE_PTR_CALL_STACK
// at STATE_CALL_STACK_BUF). Kept out of STATE_SIZE so the small KSA/PRGA VMs (which
// never call) don't balloon their state buffer.
pub const CALL_STACK_SIZE: usize = 0x2000;       // 8 KiB = 1024 nested calls
pub const STATE_SIZE: usize = 0x258;
/// Offset from the VM state base where the dedicated return-IP stack buffer begins.
pub const STATE_CALL_STACK_BUF: usize = STATE_SIZE;

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    #[error("Unknown opcode: 0x{0:02X}")]
    UnknownOpcode(u8),
    #[error("Instruction pointer out of bounds: ip = {0}")]
    OobIp(usize),
    #[error("Memory access out of bounds")]
    OobMem,
    #[error("Division by zero")]
    DivByZero,
    #[error("Virtual register index out of bounds: r = {0}")]
    OobReg(u8),
}

/// Interpret `code` starting at ip=0.
/// `state` = VM state buffer, `mem` = memory arena (see module docs).
pub fn interpret(state: &mut [u8], mem: &mut [u8], code: &[u8]) -> Result<(), VmError> {
    let mut ip = 0usize;
    loop {
        if ip >= code.len() {
            return Err(VmError::OobIp(ip));
        }
        let op = code[ip];
        ip += 1;
        match op {
            OP_MOV_R_IMM32 => {
                let r = code[ip] as usize;
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                *vreg64(state, r)? = imm as u64;
            }
            OP_MOV_R_IMM64 => {
                let r = code[ip] as usize;
                let imm = u64::from_le_bytes(code[ip + 1..ip + 9].try_into().unwrap());
                ip += 9;
                *vreg64(state, r)? = imm;
            }
            OP_MOV_R_R => {
                let dst = code[ip] as usize;
                let src = code[ip + 1] as usize;
                ip += 2;
                *vreg64(state, dst)? = vreg32(state, src)? as u64;
            }
            OP_XOR_R_R => {
                let d = code[ip] as usize;
                let s = code[ip + 1] as usize;
                ip += 2;
                let r = vreg32(state, d)? ^ vreg32(state, s)?;
                *vreg64(state, d)? = r as u64;
                set_flags(state, flags::logical_flags(r));
            }
            OP_ADD_R_R => {
                let d = code[ip] as usize;
                let s = code[ip + 1] as usize;
                ip += 2;
                let a = vreg32(state, d)?;
                let b = vreg32(state, s)?;
                *vreg64(state, d)? = a.wrapping_add(b) as u64;
                set_flags(state, flags::add_flags(a, b));
            }
            OP_IMUL_R_R => {
                let d = code[ip] as usize;
                let s = code[ip + 1] as usize;
                ip += 2;
                *vreg64(state, d)? = vreg32(state, d)?.wrapping_mul(vreg32(state, s)?) as u64;
                // M1: IMUL leaves flags untouched (x86 defines only CF/OF; not consumed).
            }
            OP_SUB_R_R => {
                let d = code[ip] as usize;
                let s = code[ip + 1] as usize;
                ip += 2;
                let a = vreg32(state, d)?;
                let b = vreg32(state, s)?;
                *vreg64(state, d)? = a.wrapping_sub(b) as u64;
                set_flags(state, flags::sub_flags(a, b));
            }
            OP_AND_R_R => {
                let d = code[ip] as usize;
                let s = code[ip + 1] as usize;
                ip += 2;
                let r = vreg32(state, d)? & vreg32(state, s)?;
                *vreg64(state, d)? = r as u64;
                set_flags(state, flags::logical_flags(r));
            }
            OP_AND_R_IMM32 | OP_XOR_R_IMM32 | OP_ADD_R_IMM32 => {
                let r = code[ip] as usize;
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                let v = vreg32(state, r)?;
                let r2 = match op {
                    OP_AND_R_IMM32 => v & imm,
                    OP_XOR_R_IMM32 => v ^ imm,
                    _ => v.wrapping_add(imm),
                };
                *vreg64(state, r)? = r2 as u64;
                match op {
                    OP_ADD_R_IMM32 => set_flags(state, flags::add_flags(v, imm)),
                    _ => set_flags(state, flags::logical_flags(r2)),
                }
            }
            OP_ROL_R_IMM8 => {
                let r = code[ip] as usize;
                let amt = code[ip + 1] & 31;
                ip += 2;
                *vreg64(state, r)? = vreg32(state, r)?.rotate_left(amt as u32) as u64;
            }
            OP_ROR_R_IMM8 => {
                let r = code[ip] as usize;
                let amt = code[ip + 1] & 31;
                ip += 2;
                *vreg64(state, r)? = vreg32(state, r)?.rotate_right(amt as u32) as u64;
            }
            OP_INC_R => {
                let r = code[ip] as usize;
                ip += 1;
                let a = vreg32(state, r)?;
                let prev = flags_of(state);
                *vreg64(state, r)? = a.wrapping_add(1) as u64;
                set_flags(state, flags::inc_flags(a, prev));
            }
            OP_DEC_R => {
                let r = code[ip] as usize;
                ip += 1;
                let a = vreg32(state, r)?;
                let prev = flags_of(state);
                *vreg64(state, r)? = a.wrapping_sub(1) as u64;
                set_flags(state, flags::dec_flags(a, prev));
            }
            OP_CMP_R_IMM32 => {
                let r = code[ip] as usize;
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                set_flags(state, flags::sub_flags(vreg32(state, r)?, imm));
            }
            OP_MOVZX_R_MEM8 => {
                let dst = code[ip] as usize;
                let slot = code[ip + 1] as usize;
                let idx = code[ip + 2] as usize;
                ip += 3;
                let base = ptr_slot(state, slot)?;
                let off = *vreg64(state, idx)? as usize;
                let addr = base.checked_add(off).ok_or(VmError::OobMem)?;
                let byte = mem.get(addr).copied().ok_or(VmError::OobMem)?;
                *vreg64(state, dst)? = byte as u64;
            }
            OP_MOV_MEM8_R => {
                let slot = code[ip] as usize;
                let idx = code[ip + 1] as usize;
                let src = code[ip + 2] as usize;
                ip += 3;
                let base = ptr_slot(state, slot)?;
                let off = *vreg64(state, idx)? as usize;
                let addr = base.checked_add(off).ok_or(VmError::OobMem)?;
                let byte = *vreg64(state, src)? as u8;
                *mem.get_mut(addr).ok_or(VmError::OobMem)? = byte;
            }
            OP_JMP8 => {
                let rel = code[ip] as i8 as i64;
                ip += 1;
                ip = (ip as i64 + rel) as usize;
            }
            OP_JB8 => {
                let rel = code[ip] as i8 as i64;
                ip += 1;
                if flags_of(state) & F_CF != 0 {
                    ip = (ip as i64 + rel) as usize;
                }
            }
            OP_JCC8 => {
                let cond = code[ip];
                let rel = code[ip + 1] as i8 as i64;
                ip += 2;
                if flags::cond_taken(cond, flags_of(state)) {
                    ip = (ip as i64 + rel) as usize;
                }
            }
            OP_SETCC => {
                // v50: setcc writes ONLY the low byte of the destination vreg and
                // preserves the status flags. (x86 setcc is a partial-register
                // write: the upper bits of the destination are untouched and the
                // flags are not modified.)
                let dst = code[ip] as usize;
                let cond = code[ip + 1];
                ip += 2;
                let cur = *vreg64(state, dst)?;
                let taken = flags::cond_taken(cond, flags_of(state));
                let newv = (cur & !0xFFu64) | if taken { 1u64 } else { 0 };
                *vreg64(state, dst)? = newv;
            }
            OP_HALT => return Ok(()),
            // ── M2 (v22) opcodes ─────────────────────────────────────────────
            OP_MOV_R_R64 => {
                let dst = code[ip] as usize;
                let src = code[ip + 1] as usize;
                ip += 2;
                *vreg64(state, dst)? = *vreg64(state, src)?;
            }
            OP_ADD_R_R64 | OP_SUB_R_R64 | OP_XOR_R_R64 | OP_AND_R_R64 | OP_IMUL_R_R64 => {
                let d = code[ip] as usize;
                let s = code[ip + 1] as usize;
                ip += 2;
                let a = *vreg64(state, d)?;
                let b = *vreg64(state, s)?;
                *vreg64(state, d)? = match op {
                    OP_ADD_R_R64 => a.wrapping_add(b),
                    OP_SUB_R_R64 => a.wrapping_sub(b),
                    OP_XOR_R_R64 => a ^ b,
                    OP_AND_R_R64 => a & b,
                    _ => a.wrapping_mul(b),
                };
                if op != OP_IMUL_R_R64 {
                    let fl = match op {
                        OP_ADD_R_R64 => flags::add_flags64(a, b),
                        OP_SUB_R_R64 => flags::sub_flags64(a, b),
                        _ => flags::logical_flags64(a & b), // AND
                    };
                    // XOR uses the combined result
                    let fl = if op == OP_XOR_R_R64 { flags::logical_flags64(a ^ b) } else { fl };
                    set_flags(state, fl);
                }
            }
            OP_ADD_R_IMM64 | OP_XOR_R_IMM64 | OP_AND_R_IMM64 => {
                let r = code[ip] as usize;
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                let imm = imm as i32 as i64 as u64; // sign-extend
                let v = *vreg64(state, r)?;
                let r2 = match op {
                    OP_ADD_R_IMM64 => v.wrapping_add(imm),
                    OP_XOR_R_IMM64 => v ^ imm,
                    _ => v & imm,
                };
                *vreg64(state, r)? = r2;
                let fl = match op {
                    OP_ADD_R_IMM64 => flags::add_flags64(v, imm),
                    _ => flags::logical_flags64(r2),
                };
                set_flags(state, fl);
            }
            OP_SHL_R_IMM8 | OP_SHR_R_IMM8 | OP_SAR_R_IMM8 => {
                let r = code[ip] as usize;
                let cnt = (code[ip + 1] & 31) as u32;
                ip += 2;
                let v = vreg32(state, r)?;
                let r2 = match op {
                    OP_SHL_R_IMM8 => v.wrapping_shl(cnt),
                    OP_SHR_R_IMM8 => v.wrapping_shr(cnt),
                    _ => ((v as i32) >> cnt) as u32,
                };
                *vreg64(state, r)? = r2 as u64;
                if cnt != 0 {
                    let kind = match op {
                        OP_SHL_R_IMM8 => flags::ShiftKind::Shl,
                        OP_SHR_R_IMM8 => flags::ShiftKind::Shr,
                        _ => flags::ShiftKind::Sar,
                    };
                    set_flags(state, flags::shift_flags(kind, v, cnt, r2));
                }
            }
            OP_SHL_R_CL | OP_SHR_R_CL | OP_SAR_R_CL => {
                let r = code[ip] as usize;
                ip += 1;
                let cnt = (*vreg64(state, 1)? & 31) as u32;
                let v = vreg32(state, r)?;
                let r2 = match op {
                    OP_SHL_R_CL => v.wrapping_shl(cnt),
                    OP_SHR_R_CL => v.wrapping_shr(cnt),
                    _ => ((v as i32) >> cnt) as u32,
                };
                *vreg64(state, r)? = r2 as u64;
                if cnt != 0 {
                    let kind = match op {
                        OP_SHL_R_CL => flags::ShiftKind::Shl,
                        OP_SHR_R_CL => flags::ShiftKind::Shr,
                        _ => flags::ShiftKind::Sar,
                    };
                    set_flags(state, flags::shift_flags(kind, v, cnt, r2));
                }
            }
            OP_TEST_R_R32 => {
                let a = code[ip] as usize;
                let b = code[ip + 1] as usize;
                ip += 2;
                set_flags(state, flags::logical_flags(vreg32(state, a)? & vreg32(state, b)?));
            }
            OP_TEST_R_IMM32 => {
                let r = code[ip] as usize;
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                set_flags(state, flags::logical_flags(vreg32(state, r)? & imm));
            }
            OP_MOVZX_R_MEM16 | OP_MOVZX_R_MEM32 | OP_MOVSX_R_MEM8 | OP_MOVSX_R_MEM16 | OP_MOV_R_MEM64 => {
                let dst = code[ip] as usize;
                let slot = code[ip + 1] as usize;
                let idx = code[ip + 2] as usize;
                ip += 3;
                let base = ptr_slot(state, slot)?;
                let off = *vreg64(state, idx)? as usize;
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
                    OP_MOVSX_R_MEM8 => mem_get(mem, addr, 1).ok_or(VmError::OobMem)?[0] as i8 as i64 as u64,
                    OP_MOVSX_R_MEM16 => {
                        let v = mem_get(mem, addr, 2).ok_or(VmError::OobMem)?;
                        i16::from_le_bytes(v[..2].try_into().unwrap()) as i64 as u64
                    }
                    _ => u64::from_le_bytes(mem_get(mem, addr, 8).ok_or(VmError::OobMem)?.try_into().unwrap()),
                };
                *vreg64(state, dst)? = val;
            }
            OP_MOV_MEM16_R | OP_MOV_MEM32_R | OP_MOV_MEM64_R => {
                let slot = code[ip] as usize;
                let idx = code[ip + 1] as usize;
                let src = code[ip + 2] as usize;
                ip += 3;
                let base = ptr_slot(state, slot)?;
                let off = *vreg64(state, idx)? as usize;
                let addr = base.checked_add(off).ok_or(VmError::OobMem)?;
                let sv = *vreg64(state, src)?;
                match op {
                    OP_MOV_MEM16_R => mem_put(mem, addr, &(sv as u16).to_le_bytes())?,
                    OP_MOV_MEM32_R => mem_put(mem, addr, &(sv as u32).to_le_bytes())?,
                    _ => mem_put(mem, addr, &sv.to_le_bytes())?,
                }
            }
            // ── M3 (v23): stack + call/ret ────────────────────────────────────
            OP_PUSH_R => {
                let r = code[ip] as usize;
                ip += 1;
                let sp = sp_of(state).wrapping_sub(8);
                set_sp(state, sp);
                let addr = sp as usize;
                mem_put(mem, addr, &vreg64(state, r)?.to_le_bytes())?;
            }
            OP_POP_R => {
                let r = code[ip] as usize;
                ip += 1;
                let sp = sp_of(state);
                let addr = sp as usize;
                let val = u64::from_le_bytes(mem_get(mem, addr, 8).ok_or(VmError::OobMem)?.try_into().unwrap());
                *vreg64(state, r)? = val;
                set_sp(state, sp.wrapping_add(8));
            }
            OP_CALL8 => {
                let rel = code[ip] as i8 as i64;
                ip += 1;
                // Two-stack model: the bytecode return IP goes on the VM return-IP
                // stack (STATE_CALL_SP), NOT on the architectural stack [v4]. The
                // program's observed return address (original x86 return VA) is
                // pushed to [v4] separately by the lifter before the call.
                let ret_ip = ip as u64;
                let csp = call_sp_of(state).wrapping_sub(8);
                set_call_sp(state, csp);
                let caddr = call_stack_addr(state, csp);
                mem_put(mem, caddr, &ret_ip.to_le_bytes())?;
                ip = (ip as i64 + rel) as usize;
            }
            OP_RET => {
                // Pop the bytecode return IP from the VM return-IP stack (control
                // flow); advance the architectural RSP (v4) past the caller's
                // pushed return VA.
                let csp = call_sp_of(state);
                let val = u64::from_le_bytes(mem_get(mem, call_stack_addr(state, csp), 8).ok_or(VmError::OobMem)?.try_into().unwrap());
                set_call_sp(state, csp.wrapping_add(8));
                set_sp(state, sp_of(state).wrapping_add(8));
                ip = val as usize;
            }
            OP_RET_IMM16 => {
                let imm = u16::from_le_bytes(code[ip..ip + 2].try_into().unwrap());
                ip += 2;
                let csp = call_sp_of(state);
                let val = u64::from_le_bytes(mem_get(mem, call_stack_addr(state, csp), 8).ok_or(VmError::OobMem)?.try_into().unwrap());
                set_call_sp(state, csp.wrapping_add(8));
                set_sp(state, sp_of(state).wrapping_add(8 + imm as u64));
                ip = val as usize;
            }
            OP_PINSRW_XMM => {
                let dst = code[ip] as usize;
                let src = code[ip + 1] as usize;
                let lane = code[ip + 2];
                ip += 3;
                let v = (*vreg64(state, src)? & 0xFFFF) as u16;
                let base = STATE_XMM + dst * 16 + (lane as usize & 7) * 2;
                state[base..base + 2].copy_from_slice(&v.to_le_bytes());
            }
            OP_CPUID => {
                let leaf = *vreg64(state, 0)? as u32;
                let subleaf = *vreg64(state, 2)? as u32;
                let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
                *vreg64(state, 0)? = r.eax as u64;
                *vreg64(state, 1)? = r.ebx as u64;
                *vreg64(state, 2)? = r.ecx as u64;
                *vreg64(state, 3)? = r.edx as u64;
            }
            OP_XGETBV => {
                let ecxv = *vreg64(state, 2)? as u32;
                let mut lo: u32;
                let mut hi: u32;
                unsafe {
                    core::arch::asm!("xgetbv", in("ecx") ecxv, out("eax") lo, out("edx") hi, options(nostack, preserves_flags));
                }
                *vreg64(state, 0)? = lo as u64;
                *vreg64(state, 3)? = hi as u64;
            }
            OP_TZCNT_R32 => {
                let d = code[ip] as usize;
                let s = code[ip + 1] as usize;
                ip += 2;
                let v = vreg32(state, s)?;
                let lsb = v.wrapping_neg() & v;
                let cnt = lsb.wrapping_sub(1).count_ones() as u64; // == tzcnt, 32 when v==0
                *vreg64(state, d)? = cnt;
                if v == 0 { set_flags(state, F_CF | F_ZF); } else { set_flags(state, 0); }
            }
            // ── M5 (v30): rel32 branches ────────────────────────────────────
            OP_JMP32 => {
                let rel = i32::from_le_bytes(code[ip..ip + 4].try_into().unwrap());
                ip += 4;
                ip = (ip as i64 + rel as i64) as usize;
            }
            OP_JCC32 => {
                let cond = code[ip];
                let rel = i32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                if flags::cond_taken(cond, flags_of(state)) {
                    ip = (ip as i64 + rel as i64) as usize;
                }
            }
            OP_CALL32 => {
                let rel = i32::from_le_bytes(code[ip..ip + 4].try_into().unwrap());
                ip += 4;
                let ret_ip = ip as u64;
                let csp = call_sp_of(state).wrapping_sub(8);
                set_call_sp(state, csp);
                let caddr = call_stack_addr(state, csp);
                mem_put(mem, caddr, &ret_ip.to_le_bytes())?;
                ip = (ip as i64 + rel as i64) as usize;
            }
            // ── M2 follow-up (v24): addressing modes ────────────────────────
            OP_LEA => {
                let dst = code[ip] as usize;
                let base = code[ip + 1] as usize;
                let idx = code[ip + 2] as usize;
                let sc = code[ip + 3] as u32;
                let disp = i32::from_le_bytes(code[ip + 4..ip + 8].try_into().unwrap()) as i64 as u64;
                ip += 8;
                let mut a = vreg64(state, base)?.wrapping_add(disp);
                if idx != ADDR_NO_INDEX as usize {
                    a = a.wrapping_add(vreg64(state, idx)?.wrapping_mul(1u64 << sc));
                }
                *vreg64(state, dst)? = a;
            }
            OP_SET_RIP => {
                let rip = u64::from_le_bytes(code[ip..ip + 8].try_into().unwrap());
                ip += 8;
                state[STATE_RIP..STATE_RIP + 8].copy_from_slice(&rip.to_le_bytes());
            }
            OP_LEA_RIP => {
                let dst = code[ip] as usize;
                let rel = i32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap()) as i64 as u64;
                ip += 5;
                let rip = u64::from_le_bytes(state[STATE_RIP..STATE_RIP + 8].try_into().unwrap());
                *vreg64(state, dst)? = rip.wrapping_add(rel);
            }
            // ── v43: gs:/fs: 세그먼트(PEB/TEB) — vreg[dst] = STATE_SEG_GS + sext(disp32)
            OP_LEA_GS => {
                let dst = code[ip] as usize;
                let disp = i32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap()) as i64 as u64;
                ip += 5;
                let gs = u64::from_le_bytes(state[STATE_SEG_GS..STATE_SEG_GS + 8].try_into().unwrap());
                *vreg64(state, dst)? = gs.wrapping_add(disp);
            }
            OP_MOVZX_R_MEM8_A | OP_MOVZX_R_MEM16_A | OP_MOVZX_R_MEM32_A | OP_MOVSX_R_MEM8_A | OP_MOVSX_R_MEM16_A | OP_MOV_R_MEM64_A => {
                let dst = code[ip] as usize;
                let addr = *vreg64(state, code[ip + 1] as usize)? as usize;
                ip += 2;
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
                    OP_MOVSX_R_MEM8_A => mem_get(mem, addr, 1).ok_or(VmError::OobMem)?[0] as i8 as i64 as u64,
                    OP_MOVSX_R_MEM16_A => {
                        let v = mem_get(mem, addr, 2).ok_or(VmError::OobMem)?;
                        i16::from_le_bytes(v[..2].try_into().unwrap()) as i64 as u64
                    }
                    _ => u64::from_le_bytes(mem_get(mem, addr, 8).ok_or(VmError::OobMem)?.try_into().unwrap()),
                };
                *vreg64(state, dst)? = val;
            }
            OP_MOV_MEM8_A | OP_MOV_MEM16_A | OP_MOV_MEM32_A | OP_MOV_MEM64_A => {
                let addr = *vreg64(state, code[ip] as usize)? as usize;
                let src = code[ip + 1] as usize;
                ip += 2;
                let sv = *vreg64(state, src)?;
                match op {
                    OP_MOV_MEM8_A => mem_put(mem, addr, &(sv as u8).to_le_bytes())?,
                    OP_MOV_MEM16_A => mem_put(mem, addr, &(sv as u16).to_le_bytes())?,
                    OP_MOV_MEM32_A => mem_put(mem, addr, &(sv as u32).to_le_bytes())?,
                    _ => mem_put(mem, addr, &sv.to_le_bytes())?,
                }
            }
            OP_CMPXCHG_MEM8_A | OP_CMPXCHG_MEM16_A | OP_CMPXCHG_MEM32_A | OP_CMPXCHG_MEM64_A => {
                // Atomic compare-exchange: if [addr] == v0-low(width) (expected)
                // { [addr]=v[src]; ZF=1 } else { v0-low(width)=[addr]; ZF=0 }.
                // Mirrors the native `lock cmpxchg` handler. The comparison uses only
                // the operand-width bytes of RAX (AL/AX/EAX/RAX). This fixes the old
                // 32/64-only path, which (a) had no 8/16 support and (b) truncated the
                // 64-bit expected AND current value to u32, so a 64-bit CAS compared
                // only the low dword.
                let addr = *vreg64(state, code[ip] as usize)? as usize;
                let src = code[ip + 1] as usize;
                ip += 2;
                let width = match op {
                    OP_CMPXCHG_MEM8_A => 1,
                    OP_CMPXCHG_MEM16_A => 2,
                    OP_CMPXCHG_MEM32_A => 4,
                    _ => 8,
                };
                let g = mem_get(mem, addr, width).ok_or(VmError::OobMem)?;
                let cur = match width {
                    1 => g[0] as u64,
                    2 => u16::from_le_bytes(g[..2].try_into().unwrap()) as u64,
                    4 => u32::from_le_bytes(g[..4].try_into().unwrap()) as u64,
                    _ => u64::from_le_bytes(g[..8].try_into().unwrap()),
                };
                let rax0 = *vreg64(state, 0)?;
                let expected = match width {
                    1 => (rax0 as u8) as u64,
                    2 => (rax0 as u16) as u64,
                    4 => (rax0 as u32) as u64,
                    _ => rax0,
                };
                if cur == expected {
                    let sv = *vreg64(state, src)?;
                    let bytes: Vec<u8> = match width {
                        1 => (sv as u8).to_le_bytes().to_vec(),
                        2 => (sv as u16).to_le_bytes().to_vec(),
                        4 => (sv as u32).to_le_bytes().to_vec(),
                        _ => sv.to_le_bytes().to_vec(),
                    };
                    mem_put(mem, addr, &bytes)?;
                    // native handler captures ONLY ZF and preserves the other
                    // (undefined-on-x86) flags; the interpreter must mirror that
                    // so interp == native. Preserve all bits except ZF, set ZF.
                    set_flags(state, (flags_of(state) & !F_ZF) | F_ZF);
                } else {
                    // On failure RAX's operand-width bytes become [addr]. x86 writes
                    // only AL/AX for 8/16 (upper RAX untouched); EAX zero-extends for
                    // 32 and RAX is fully replaced for 64 — matches the native handler.
                    let new_v0 = match width {
                        1 => (rax0 & !0xFF) | cur,
                        2 => (rax0 & !0xFFFF) | cur,
                        _ => cur,
                    };
                    *vreg64(state, 0)? = new_v0;
                    // ZF cleared, all other flags preserved (mirror native handler).
                    set_flags(state, flags_of(state) & !F_ZF);
                }
            }
            OP_XCHG_MEM8_A | OP_XCHG_MEM16_A | OP_XCHG_MEM32_A | OP_XCHG_MEM64_A => {
                // Atomic exchange: [addr] <-> vreg[src]. Flags unchanged. Mirrors
                // the native `xchg [addr], reg`: for 8/16-bit the register's upper
                // bits are preserved; for 32-bit the result is zero-extended.
                let addr = *vreg64(state, code[ip] as usize)? as usize;
                let src = code[ip + 1] as usize;
                ip += 2;
                let w = match op {
                    OP_XCHG_MEM8_A => 1,
                    OP_XCHG_MEM16_A => 2,
                    OP_XCHG_MEM32_A => 4,
                    _ => 8,
                };
                let g = mem_get(mem, addr, w).ok_or(VmError::OobMem)?;
                let old = u64::from_le_bytes(g);
                let sv = *vreg64(state, src)?;
                // memory gets the low w bytes of the register
                match w {
                    1 => mem_put(mem, addr, &(sv as u8).to_le_bytes())?,
                    2 => mem_put(mem, addr, &(sv as u16).to_le_bytes())?,
                    4 => mem_put(mem, addr, &(sv as u32).to_le_bytes())?,
                    _ => mem_put(mem, addr, &sv.to_le_bytes())?,
                }
                // register gets the old memory value (upper bits per x86 semantics)
                *vreg64(state, src)? = match w {
                    1 => (sv & !0xFF) | (old & 0xFF),
                    2 => (sv & !0xFFFF) | (old & 0xFFFF),
                    4 => old & 0xFFFF_FFFF,
                    _ => old,
                };
            }
            OP_XADD_MEM8_A | OP_XADD_MEM16_A | OP_XADD_MEM32_A | OP_XADD_MEM64_A => {
                // Atomic fetch-and-add: tmp=[addr]; [addr]=tmp+src; src=tmp. ADD
                // flags. Mirrors native `lock xadd [addr], reg`.
                let addr = *vreg64(state, code[ip] as usize)? as usize;
                let src = code[ip + 1] as usize;
                ip += 2;
                let w = match op {
                    OP_XADD_MEM8_A => 1,
                    OP_XADD_MEM16_A => 2,
                    OP_XADD_MEM32_A => 4,
                    _ => 8,
                };
                let g = mem_get(mem, addr, w).ok_or(VmError::OobMem)?;
                let sv = *vreg64(state, src)?;
                match w {
                    1 => {
                        let a = g[0] as u8;
                        let b = sv as u8;
                        mem_put(mem, addr, &a.wrapping_add(b).to_le_bytes())?;
                        *vreg64(state, src)? = (sv & !0xFF) | (a as u64);
                        // width-correct 8-bit ADD flags (matches native `lock xadd [addr], al`)
                        set_flags(state, flags::add_flags_width(a as u64, b as u64, 8));
                    }
                    2 => {
                        let a = u16::from_le_bytes([g[0], g[1]]);
                        let b = sv as u16;
                        mem_put(mem, addr, &a.wrapping_add(b).to_le_bytes())?;
                        *vreg64(state, src)? = (sv & !0xFFFF) | (a as u64);
                        // width-correct 16-bit ADD flags (matches native `lock xadd [addr], ax`)
                        set_flags(state, flags::add_flags_width(a as u64, b as u64, 16));
                    }
                    4 => {
                        let a = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
                        let b = sv as u32;
                        mem_put(mem, addr, &a.wrapping_add(b).to_le_bytes())?;
                        *vreg64(state, src)? = a as u64; // xadd eax zero-extends
                        set_flags(state, flags::add_flags(a, b));
                    }
                    _ => {
                        let a = u64::from_le_bytes(g);
                        let b = sv;
                        mem_put(mem, addr, &a.wrapping_add(b).to_le_bytes())?;
                        *vreg64(state, src)? = a;
                        set_flags(state, flags::add_flags64(a, b));
                    }
                }
            }
            // ── M3 follow-up (v24): native API bridge ───────────────────────
            // The reference interpreter cannot call real native code; it models the
            // bridge ABI purely so bytecode that contains it still decodes. The
            // native handler is the authoritative implementation (self-test [13]).
            OP_NATIVE_CALL => {
                ip += 1; // skip target_vreg operand
            }
            // ── A-2 보강 (v25): OR / NEG / NOT / 64-bit shift ─────────────────
            OP_OR_R_R => {
                let d = code[ip] as usize;
                let s = code[ip + 1] as usize;
                ip += 2;
                let r = vreg32(state, d)? | vreg32(state, s)?;
                *vreg64(state, d)? = r as u64;
                set_flags(state, flags::logical_flags(r));
            }
            OP_OR_R_R64 => {
                let d = code[ip] as usize;
                let s = code[ip + 1] as usize;
                ip += 2;
                let r = *vreg64(state, d)? | *vreg64(state, s)?;
                *vreg64(state, d)? = r;
                set_flags(state, flags::logical_flags64(r));
            }
            OP_OR_R_IMM32 => {
                let r = code[ip] as usize;
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                let v = vreg32(state, r)? | imm;
                *vreg64(state, r)? = v as u64;
                set_flags(state, flags::logical_flags(v));
            }
            OP_OR_R_IMM64 => {
                let r = code[ip] as usize;
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                let imm = imm as i32 as i64 as u64; // sign-extend
                let v = *vreg64(state, r)? | imm;
                *vreg64(state, r)? = v;
                set_flags(state, flags::logical_flags64(v));
            }
            OP_NEG_R => {
                let r = code[ip] as usize;
                ip += 1;
                let a = vreg32(state, r)?;
                let res = 0u32.wrapping_sub(a);
                *vreg64(state, r)? = res as u64;
                set_flags(state, flags::sub_flags(0, a));
            }
            OP_NEG_R64 => {
                let r = code[ip] as usize;
                ip += 1;
                let a = *vreg64(state, r)?;
                let res = 0u64.wrapping_sub(a);
                *vreg64(state, r)? = res;
                set_flags(state, flags::sub_flags64(0, a));
            }
            OP_NOT_R => {
                let r = code[ip] as usize;
                ip += 1;
                *vreg64(state, r)? = (!vreg32(state, r)?) as u64;
            }
            OP_NOT_R64 => {
                let r = code[ip] as usize;
                ip += 1;
                *vreg64(state, r)? = !*vreg64(state, r)?;
            }
            OP_SHL64_R_IMM8 | OP_SHR64_R_IMM8 | OP_SAR64_R_IMM8 => {
                let r = code[ip] as usize;
                let cnt = (code[ip + 1] & 63) as u32;
                ip += 2;
                let v = *vreg64(state, r)?;
                let r2 = match op {
                    OP_SHL64_R_IMM8 => v.wrapping_shl(cnt),
                    OP_SHR64_R_IMM8 => v.wrapping_shr(cnt),
                    _ => ((v as i64) >> cnt) as u64,
                };
                *vreg64(state, r)? = r2;
                if cnt != 0 {
                    let kind = match op {
                        OP_SHL64_R_IMM8 => flags::ShiftKind::Shl,
                        OP_SHR64_R_IMM8 => flags::ShiftKind::Shr,
                        _ => flags::ShiftKind::Sar,
                    };
                    set_flags(state, flags::shift_flags64(kind, v, cnt, r2));
                }
            }
            OP_SHL64_R_CL | OP_SHR64_R_CL | OP_SAR64_R_CL => {
                let r = code[ip] as usize;
                ip += 1;
                let cnt = (*vreg64(state, 1)? & 63) as u32;
                let v = *vreg64(state, r)?;
                let r2 = match op {
                    OP_SHL64_R_CL => v.wrapping_shl(cnt),
                    OP_SHR64_R_CL => v.wrapping_shr(cnt),
                    _ => ((v as i64) >> cnt) as u64,
                };
                *vreg64(state, r)? = r2;
                if cnt != 0 {
                    let kind = match op {
                        OP_SHL64_R_CL => flags::ShiftKind::Shl,
                        OP_SHR64_R_CL => flags::ShiftKind::Shr,
                        _ => flags::ShiftKind::Sar,
                    };
                    set_flags(state, flags::shift_flags64(kind, v, cnt, r2));
                }
            }
            OP_NOP => { /* no-op */ }
            OP_MOVSD_XMM_MEM => {
                let xmm = code[ip] as usize;
                let addr = *vreg64(state, code[ip + 1] as usize)? as usize;
                ip += 2;
                let v = u64::from_le_bytes(mem_get(mem, addr, 8).ok_or(VmError::OobMem)?.try_into().unwrap());
                let base = STATE_XMM + xmm * 16;
                state[base..base + 8].copy_from_slice(&v.to_le_bytes());
                state[base + 8..base + 16].fill(0);
            }
            OP_MOVQ_XMM_GPR => {
                let gpr = code[ip] as usize;
                let xmm = code[ip + 1] as usize;
                ip += 2;
                let base = STATE_XMM + xmm * 16;
                let lo = u64::from_le_bytes(state[base..base + 8].try_into().unwrap());
                *vreg64(state, gpr)? = lo;
            }
            OP_MOVQ_GPR_XMM => {
                let xmm = code[ip] as usize;
                let gpr = code[ip + 1] as usize;
                ip += 2;
                let base = STATE_XMM + xmm * 16;
                let v = *vreg64(state, gpr)?;
                state[base..base + 8].copy_from_slice(&v.to_le_bytes());
                state[base + 8..base + 16].fill(0);
            }
            OP_MOVSD_MEM_XMM => {
                let addr = *vreg64(state, code[ip] as usize)? as usize;
                let xmm = code[ip + 1] as usize;
                ip += 2;
                let base = STATE_XMM + xmm * 16;
                let lo = u64::from_le_bytes(state[base..base + 8].try_into().unwrap());
                mem_put(mem, addr, &lo.to_le_bytes())?;
            }
            OP_MOVUPS_XMM_MEM => {
                let xmm = code[ip] as usize;
                let addr = *vreg64(state, code[ip + 1] as usize)? as usize;
                ip += 2;
                let bytes = mem_get(mem, addr, 8).ok_or(VmError::OobMem)?.to_vec();
                let bytes2 = mem_get(mem, addr + 8, 8).ok_or(VmError::OobMem)?.to_vec();
                let base = STATE_XMM + xmm * 16;
                state[base..base + 8].copy_from_slice(&bytes);
                state[base + 8..base + 16].copy_from_slice(&bytes2);
            }
            OP_MOVUPS_MEM_XMM => {
                let addr = *vreg64(state, code[ip] as usize)? as usize;
                let xmm = code[ip + 1] as usize;
                ip += 2;
                let base = STATE_XMM + xmm * 16;
                let lo = state[base..base + 8].to_vec();
                let hi = state[base + 8..base + 16].to_vec();
                mem_put(mem, addr, &lo)?;
                mem_put(mem, addr + 8, &hi)?;
            }
            OP_UNPCKLPD_XMM => {
                let dst = code[ip] as usize;
                let src = code[ip + 1] as usize;
                ip += 2;
                let dbase = STATE_XMM + dst * 16;
                let sbase = STATE_XMM + src * 16;
                let dlo = state[dbase..dbase + 8].to_vec();
                let slo = state[sbase..sbase + 8].to_vec();
                state[dbase..dbase + 8].copy_from_slice(&dlo);
                state[dbase + 8..dbase + 16].copy_from_slice(&slo);
            }
            OP_UNPCKLPS_XMM => {
                let dst = code[ip] as usize;
                let src = code[ip + 1] as usize;
                ip += 2;
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
            }
            OP_XORPS_XMM => {
                let dst = code[ip] as usize;
                let src = code[ip + 1] as usize;
                ip += 2;
                let db = STATE_XMM + dst * 16;
                let sb = STATE_XMM + src * 16;
                for k in 0..16 {
                    state[db + k] ^= state[sb + k];
                }
            }
            OP_PSRLQ_XMM_IMM8 | OP_PSLLQ_XMM_IMM8 => {
                let dst = code[ip] as usize;
                let imm = code[ip + 1];
                ip += 2;
                let db = STATE_XMM + dst * 16;
                let shl = op == OP_PSLLQ_XMM_IMM8;
                let cnt = (imm & 0x3F) as u32;
                for lane in 0..2 {
                    let off = db + lane * 8;
                    let v = u64::from_le_bytes(state[off..off + 8].try_into().unwrap());
                    let r = if shl { v.wrapping_shl(cnt) } else { v.wrapping_shr(cnt) };
                    state[off..off + 8].copy_from_slice(&r.to_le_bytes());
                }
            }
            OP_PSHUFLW_XMM | OP_PSHUFHW_XMM | OP_PSHUFD_XMM => {
                let dst = code[ip] as usize;
                let src = code[ip + 1] as usize;
                let imm = code[ip + 2];
                ip += 3;
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
            }
            // ── v31: 1-op multiply/divide (RAX=v0, RDX=v2 accumulator pair) ──
            OP_MUL_R_R32 => {
                let src = code[ip] as usize;
                ip += 1;
                let a = vreg32(state, 0)? as u64;
                let b = vreg32(state, src)? as u64;
                let p = a * b; // 64-bit product
                *vreg64(state, 0)? = (p as u32) as u64; // EAX = low32
                *vreg64(state, 2)? = ((p >> 32) as u32) as u64; // EDX = high32
            }
            OP_MUL_R_R64 => {
                let src = code[ip] as usize;
                ip += 1;
                let a = *vreg64(state, 0)?;
                let b = *vreg64(state, src)?;
                let p = (a as u128) * (b as u128);
                *vreg64(state, 0)? = p as u64;
                *vreg64(state, 2)? = (p >> 64) as u64;
            }
            OP_IMUL1_R_R32 => {
                let src = code[ip] as usize;
                ip += 1;
                let a = vreg32(state, 0)? as i32 as i64;
                let b = vreg32(state, src)? as i32 as i64;
                let p = a * b; // signed 64-bit product
                *vreg64(state, 0)? = (p as u32) as u64;
                *vreg64(state, 2)? = ((p >> 32) as u32) as u64;
            }
            OP_IMUL1_R_R64 => {
                let src = code[ip] as usize;
                ip += 1;
                let a = *vreg64(state, 0)? as i64 as i128;
                let b = *vreg64(state, src)? as i64 as i128;
                let p = a * b;
                *vreg64(state, 0)? = p as u64;
                *vreg64(state, 2)? = (p >> 64) as u64;
            }
            OP_DIV_R_R32 => {
                let src = code[ip] as usize;
                ip += 1;
                let hi = (vreg32(state, 2)? as u64) << 32;
                let lo = vreg32(state, 0)? as u64;
                let dividend = hi | lo;
                let d = vreg32(state, src)? as u64;
                if d == 0 {
                    return Err(VmError::DivByZero);
                }
                let q = dividend / d;
                let r = dividend % d;
                *vreg64(state, 0)? = (q as u32) as u64;
                *vreg64(state, 2)? = (r as u32) as u64;
            }
            OP_DIV_R_R64 => {
                let src = code[ip] as usize;
                ip += 1;
                let dividend = ((*vreg64(state, 2)? as u128) << 64) | (*vreg64(state, 0)? as u128);
                let d = *vreg64(state, src)? as u128;
                if d == 0 {
                    return Err(VmError::DivByZero);
                }
                let q = dividend / d;
                let r = dividend % d;
                *vreg64(state, 0)? = q as u64;
                *vreg64(state, 2)? = r as u64;
            }
            OP_IDIV_R_R32 => {
                let src = code[ip] as usize;
                ip += 1;
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
                *vreg64(state, 0)? = (q as u32) as u64;
                *vreg64(state, 2)? = (r as u32) as u64;
            }
            OP_IDIV_R_R64 => {
                let src = code[ip] as usize;
                ip += 1;
                let dividend =
                    (((*vreg64(state, 2)? as u128) << 64) | (*vreg64(state, 0)? as u128)) as i128;
                let d = *vreg64(state, src)? as i64 as i128;
                if d == 0 {
                    return Err(VmError::DivByZero);
                }
                let q = dividend / d;
                let r = dividend % d;
                *vreg64(state, 0)? = q as u64;
                *vreg64(state, 2)? = r as u64;
            }
            OP_BSWAP_R32 => {
                let r = code[ip] as usize;
                ip += 1;
                let v = vreg32(state, r)?.swap_bytes() as u64;
                *vreg64(state, r)? = v;
            }
            OP_BSWAP_R64 => {
                let r = code[ip] as usize;
                ip += 1;
                let v = vreg64(state, r)?.swap_bytes();
                *vreg64(state, r)? = v;
            }
            OP_BSR_R32 | OP_BSR_R64 | OP_BSF_R32 | OP_BSF_R64 => {
                let d = code[ip] as usize;
                let s = code[ip + 1] as usize;
                ip += 2;
                let is64 = matches!(op, OP_BSR_R64 | OP_BSF_R64);
                let is_bsr = matches!(op, OP_BSR_R32 | OP_BSR_R64);
                let v = if is64 { *vreg64(state, s)? } else { vreg32(state, s)? as u64 };
                if v == 0 {
                    // ZF=1; dest undefined per Intel, set 0
                    *vreg64(state, d)? = 0;
                    set_flags(state, F_ZF);
                } else {
                    let idx = if is_bsr {
                        if is64 { 63 - v.leading_zeros() } else { 31 - (v as u32).leading_zeros() }
                    } else {
                        v.trailing_zeros()
                    } as u64;
                    *vreg64(state, d)? = idx;
                    set_flags(state, 0); // ZF clear (src nonzero)
                }
            }
            // ── v33: 1-op multiply/divide 8/16-bit width (accumulator AX/DX) ─
            OP_MUL_R_R8 => {
                let src = code[ip] as usize;
                ip += 1;
                let a = ((*vreg64(state, 0)?) & 0xFF) as u16;
                let b = ((*vreg64(state, src)?) & 0xFF) as u16;
                let p = a * b; // 16-bit product → AX
                *vreg64(state, 0)? = p as u64; // zero-extend into v0
            }
            OP_MUL_R_R16 => {
                let src = code[ip] as usize;
                ip += 1;
                let a = ((*vreg64(state, 0)?) & 0xFFFF) as u32;
                let b = ((*vreg64(state, src)?) & 0xFFFF) as u32;
                let p = a * b; // 32-bit product → DX:AX
                *vreg64(state, 0)? = (p & 0xFFFF) as u64;
                *vreg64(state, 2)? = ((p >> 16) & 0xFFFF) as u64;
            }
            OP_IMUL1_R_R8 => {
                let src = code[ip] as usize;
                ip += 1;
                let a = ((*vreg64(state, 0)?) & 0xFF) as u8 as i8 as i16;
                let b = ((*vreg64(state, src)?) & 0xFF) as u8 as i8 as i16;
                let p = a * b; // signed 16-bit product
                *vreg64(state, 0)? = (p as u16) as u64;
            }
            OP_IMUL1_R_R16 => {
                let src = code[ip] as usize;
                ip += 1;
                let a = ((*vreg64(state, 0)?) & 0xFFFF) as u16 as i16 as i32;
                let b = ((*vreg64(state, src)?) & 0xFFFF) as u16 as i16 as i32;
                let p = a * b; // signed 32-bit product → DX:AX
                *vreg64(state, 0)? = ((p as u32) & 0xFFFF) as u64;
                *vreg64(state, 2)? = (((p as u32) >> 16) & 0xFFFF) as u64;
            }
            OP_DIV_R_R8 => {
                let src = code[ip] as usize;
                ip += 1;
                let dividend = (*vreg64(state, 0)?) & 0xFFFF; // AX
                let d = ((*vreg64(state, src)?) & 0xFF) as u16;
                if d == 0 {
                    return Err(VmError::DivByZero);
                }
                let q = (dividend as u16) / d;
                let r = (dividend as u16) % d;
                // AL = quotient, AH = remainder (must fit 8 bits, else #DE)
                *vreg64(state, 0)? = ((q & 0xFF) as u64) | (((r & 0xFF) as u64) << 8);
            }
            OP_DIV_R_R16 => {
                let src = code[ip] as usize;
                ip += 1;
                let lo = (*vreg64(state, 0)?) & 0xFFFF; // AX
                let hi = (*vreg64(state, 2)?) & 0xFFFF; // DX
                let dividend = (((hi << 16) | lo) & 0xFFFF_FFFF) as u32; // 32-bit DX:AX
                let d = ((*vreg64(state, src)?) & 0xFFFF) as u32;
                if d == 0 {
                    return Err(VmError::DivByZero);
                }
                let q = dividend / d;
                let r = dividend % d;
                *vreg64(state, 0)? = (q & 0xFFFF) as u64;
                *vreg64(state, 2)? = (r & 0xFFFF) as u64;
            }
            OP_IDIV_R_R8 => {
                let src = code[ip] as usize;
                ip += 1;
                let dividend = ((*vreg64(state, 0)?) & 0xFFFF) as u16 as i16; // signed AX
                let d = ((*vreg64(state, src)?) & 0xFF) as u8 as i8 as i16;
                if d == 0 {
                    return Err(VmError::DivByZero);
                }
                let q = dividend / d;
                let r = dividend % d;
                *vreg64(state, 0)? = ((q as u8) as u64) | (((r as u8) as u64) << 8);
            }
            OP_IDIV_R_R16 => {
                let src = code[ip] as usize;
                ip += 1;
                let lo = (*vreg64(state, 0)?) & 0xFFFF;
                let hi = (*vreg64(state, 2)?) & 0xFFFF;
                let dividend = (((hi << 16) | lo) & 0xFFFF_FFFF) as i32; // signed 32-bit DX:AX
                let d = ((*vreg64(state, src)?) & 0xFFFF) as u32 as i16 as i32;
                if d == 0 {
                    return Err(VmError::DivByZero);
                }
                let q = dividend / d;
                let r = dividend % d;
                *vreg64(state, 0)? = (q as i16 as u16) as u64;
                *vreg64(state, 2)? = (r as i16 as u16) as u64;
            }
            other => return Err(VmError::UnknownOpcode(other)),
        }
    }
}

#[inline]
fn vreg64(state: &mut [u8], r: usize) -> Result<&mut u64, VmError> {
    if r >= NREG {
        return Err(VmError::OobReg(r as u8));
    }
    let off = STATE_VREGS + r * 8;
    // SAFETY: byte-slice reinterpretation of a u64 slot; layout is controlled
    // and the index is bounded by NREG above.
    Ok(unsafe { &mut *(state.as_mut_ptr().add(off) as *mut u64) })
}

#[inline]
fn vreg32(state: &[u8], r: usize) -> Result<u32, VmError> {
    if r >= NREG {
        return Err(VmError::OobReg(r as u8));
    }
    let off = STATE_VREGS + r * 8;
    Ok(u32::from_le_bytes(state[off..off + 4].try_into().unwrap()))
}

/// Read the current flags word (low 64-bit slot at STATE_FLAGS).
#[inline]
fn flags_of(state: &[u8]) -> u64 {
    u64::from_le_bytes(state[STATE_FLAGS..STATE_FLAGS + 8].try_into().unwrap())
}

/// Write the flags word (masked to the modelled flag bits).
#[inline]
fn set_flags(state: &mut [u8], v: u64) {
    let v = v & FLAG_MASK;
    state[STATE_FLAGS..STATE_FLAGS + 8].copy_from_slice(&v.to_le_bytes());
}

/// Read a pointer slot (offset into `mem` for the interpreter).
fn ptr_slot(state: &[u8], slot: usize) -> Result<usize, VmError> {
    let off = match slot as u8 {
        MEM_SBOX => STATE_PTR_SBOX,
        MEM_SEED => STATE_PTR_SEED,
        MEM_BUF => STATE_PTR_BUF,
        MEM_RUNS => STATE_PTR_RUNS,
        MEM_STACK => STATE_PTR_STACK,
        _ => return Err(VmError::OobMem),
    };
    Ok(u64::from_le_bytes(state[off..off + 8].try_into().unwrap()) as usize)
}

/// Read the VM stack pointer (vreg[4] = the real RSP). Single-stack model:
/// call/ret/push/pop and `[rsp+disp]` addressing all share this one pointer,
/// matching real x86. See the fix note in handlers.rs (vreg4-as-single-stack).
#[inline]
fn sp_of(state: &[u8]) -> u64 {
    u64::from_le_bytes(state[STATE_VREGS + 4 * 8..STATE_VREGS + 4 * 8 + 8].try_into().unwrap())
}

/// Write the VM stack pointer (vreg[4]).
#[inline]
fn set_sp(state: &mut [u8], sp: u64) {
    state[STATE_VREGS + 4 * 8..STATE_VREGS + 4 * 8 + 8].copy_from_slice(&sp.to_le_bytes());
}

/// Read the VM bytecode return-IP stack offset (STATE_CALL_SP). This is an offset
/// from STATE_PTR_CALL_STACK base (a mem-offset in the interpreter, an absolute VA
/// in the native handlers), growing downward as the return-IP stack fills.
#[inline]
fn call_sp_of(state: &[u8]) -> u64 {
    u64::from_le_bytes(state[STATE_CALL_SP..STATE_CALL_SP + 8].try_into().unwrap())
}

/// Write the VM bytecode return-IP stack offset.
#[inline]
fn set_call_sp(state: &mut [u8], csp: u64) {
    state[STATE_CALL_SP..STATE_CALL_SP + 8].copy_from_slice(&csp.to_le_bytes());
}

/// Absolute (mem-space) address of the VM bytecode return-IP stack slot at the
/// given offset: STATE_PTR_CALL_STACK (base) + csp.
#[inline]
fn call_stack_addr(state: &[u8], csp: u64) -> usize {
    let base = u64::from_le_bytes(state[STATE_PTR_CALL_STACK..STATE_PTR_CALL_STACK + 8].try_into().unwrap());
    base.wrapping_add(csp) as usize
}

/// Read `n` bytes from the arena at `addr` (n = 1..=8).
fn mem_get(mem: &[u8], addr: usize, n: usize) -> Option<[u8; 8]> {
    let mut out = [0u8; 8];
    let s = mem.get(addr..addr + n)?;
    out[..n].copy_from_slice(s);
    Some(out)
}

/// Write `bytes` (LE, 1..=8) to the arena at `addr`.
fn mem_put(mem: &mut [u8], addr: usize, bytes: &[u8]) -> Result<(), VmError> {
    let dst = mem.get_mut(addr..addr + bytes.len()).ok_or(VmError::OobMem)?;
    dst.copy_from_slice(bytes);
    Ok(())
}
