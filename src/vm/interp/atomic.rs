// ==============================================================================
// BTG v21 - VM Interpreter: atomic compare-exchange / exchange / fetch-add ops
// ==============================================================================

use super::state::{VmError, flags_of, mem_get, mem_put, set_flags, vreg64};
use crate::vm::bytecode::*;
use crate::vm::flags;

/// Execute one atomic opcode. `ip` points at the first operand byte (opcode
/// already consumed). Returns the updated ip.
pub(crate) fn exec(
    state: &mut [u8],
    mem: &mut [u8],
    code: &[u8],
    ip: usize,
    op: u8,
) -> Result<usize, VmError> {
    match op {
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
            let ip = ip + 2;
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
            Ok(ip)
        }
        OP_XCHG_MEM8_A | OP_XCHG_MEM16_A | OP_XCHG_MEM32_A | OP_XCHG_MEM64_A => {
            // Atomic exchange: [addr] <-> vreg[src]. Flags unchanged. Mirrors
            // the native `xchg [addr], reg`: for 8/16-bit the register's upper
            // bits are preserved; for 32-bit the result is zero-extended.
            let addr = *vreg64(state, code[ip] as usize)? as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
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
            Ok(ip)
        }
        OP_XADD_MEM8_A | OP_XADD_MEM16_A | OP_XADD_MEM32_A | OP_XADD_MEM64_A => {
            // Atomic fetch-and-add: tmp=[addr]; [addr]=tmp+src; src=tmp. ADD
            // flags. Mirrors native `lock xadd [addr], reg`.
            let addr = *vreg64(state, code[ip] as usize)? as usize;
            let src = code[ip + 1] as usize;
            let ip = ip + 2;
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
            Ok(ip)
        }
        OP_LOCK_INC_MEM8_A | OP_LOCK_INC_MEM16_A | OP_LOCK_INC_MEM32_A | OP_LOCK_INC_MEM64_A
        | OP_LOCK_DEC_MEM8_A | OP_LOCK_DEC_MEM16_A | OP_LOCK_DEC_MEM32_A | OP_LOCK_DEC_MEM64_A => {
            // LOCK-prefixed atomic INC/DEC at the absolute address vreg[addr]
            // (Rust refcount bump/drop). INC/DEC flags (OF/SF/ZF/AF/PF
            // recomputed at the operand width, CF preserved) — mirrors the
            // native `lock inc/dec [addr]` + cap_flags_incdec handler.
            let addr = *vreg64(state, code[ip] as usize)? as usize;
            let ip = ip + 1;
            let w = match op {
                OP_LOCK_INC_MEM8_A | OP_LOCK_DEC_MEM8_A => 1,
                OP_LOCK_INC_MEM16_A | OP_LOCK_DEC_MEM16_A => 2,
                OP_LOCK_INC_MEM32_A | OP_LOCK_DEC_MEM32_A => 4,
                _ => 8,
            };
            let is_inc = matches!(op,
                OP_LOCK_INC_MEM8_A | OP_LOCK_INC_MEM16_A | OP_LOCK_INC_MEM32_A | OP_LOCK_INC_MEM64_A);
            let prev = flags_of(state);
            let g = mem_get(mem, addr, w).ok_or(VmError::OobMem)?;
            match w {
                1 => {
                    let a = g[0];
                    let r = if is_inc { a.wrapping_add(1) } else { a.wrapping_sub(1) };
                    mem_put(mem, addr, &r.to_le_bytes())?;
                    set_flags(state, flags::incdec_flags_width(a as u64, 8, is_inc, prev));
                }
                2 => {
                    let a = u16::from_le_bytes([g[0], g[1]]);
                    let r = if is_inc { a.wrapping_add(1) } else { a.wrapping_sub(1) };
                    mem_put(mem, addr, &r.to_le_bytes())?;
                    set_flags(state, flags::incdec_flags_width(a as u64, 16, is_inc, prev));
                }
                4 => {
                    let a = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
                    let r = if is_inc { a.wrapping_add(1) } else { a.wrapping_sub(1) };
                    mem_put(mem, addr, &r.to_le_bytes())?;
                    set_flags(state, if is_inc { flags::inc_flags(a, prev) } else { flags::dec_flags(a, prev) });
                }
                _ => {
                    let a = u64::from_le_bytes(g);
                    let r = if is_inc { a.wrapping_add(1) } else { a.wrapping_sub(1) };
                    mem_put(mem, addr, &r.to_le_bytes())?;
                    set_flags(state, if is_inc { flags::inc_flags64(a, prev) } else { flags::dec_flags64(a, prev) });
                }
            }
            Ok(ip)
        }
        other => Err(VmError::UnknownOpcode(other)),
    }
}
