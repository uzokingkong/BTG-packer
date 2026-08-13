// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: memory / addressing-mode helpers
// ==============================================================================
// Effective-address lowering for memory operands: RIP-relative (OP_SET_RIP +
// OP_LEA_RIP), GS/FS segment (PEB/TEB) access, and the general
// [base + index*scale + disp] form lowered to a single LEA into a vreg. Shared
// infra (`vreg`, `SCRATCH`, `SCRATCH2`) lives in `super` (mod.rs); this file is
// used by every family submodule for address computation.
// ==============================================================================

use super::{SCRATCH, SCRATCH2, vreg};
use crate::vm::bytecode::*;
use anyhow::{Result, anyhow};
use iced_x86::{Instruction, OpKind, Register};

/// Does this instruction use a RIP-relative memory operand?
pub(super) fn has_rip_operand(inst: &Instruction) -> bool {
    (0..inst.op_count()).any(|i| inst.op_kind(i) == OpKind::Memory && inst.is_ip_rel_memory_operand())
}

/// Emit the effective-address computation for memory operand `op_idx`, returning
/// the scratch vreg that holds the absolute address. RIP-relative operands use
/// the already-set STATE_RIP (caller must set_rip before).
pub(super) fn mem_emit(b: &mut BytecodeBuilder, inst: &Instruction, op_idx: u32) -> Result<u8> {
    if inst.op_kind(op_idx) != OpKind::Memory {
        return Err(anyhow!("lifter: expected memory operand"));
    }
    mem_emit_lea(b, inst, SCRATCH)?;
    Ok(SCRATCH)
}

/// Emit LEA(dst, base, idx, scale, disp) or LEA_RIP for the first memory operand.
pub(super) fn mem_emit_lea(b: &mut BytecodeBuilder, inst: &Instruction, dst: u8) -> Result<()> {
    // find the memory operand
    let mut mop: Option<u32> = None;
    for i in 0..inst.op_count() {
        if inst.op_kind(i) == OpKind::Memory {
            mop = Some(i);
            break;
        }
    }
    let mi = mop.ok_or_else(|| anyhow!("lifter: no memory operand"))?;

    if inst.is_ip_rel_memory_operand() {
        // C-1 fix (--vm-oep): iced_x86's `memory_displacement64()` returns the
        // *absolute* target VA for a RIP-relative operand (e.g. 0x1400044e0),
        // not the disp32 field. Casting that to i32 truncates it (-> 0x400044e0)
        // and then OP_LEA_RIP computes STATE_RIP + that -> a garbage 64-bit VA.
        // LEA_RIP evaluates `STATE_RIP + sext(rel32)` with STATE_RIP already set
        // to this instruction's own VA, so the rel32 must be target - inst_va.
        let target = inst.memory_displacement64();
        let rel = (target as i64 - inst.ip() as i64) as i32;
        b.lea_rip(dst, rel);
        return Ok(());
    }

    // ── v43: gs:/fs: 세그먼트(PEB/TEB) 접근 — OP_LEA_GS (SEG_GS + disp).
    // x64 Windows CRT는 entry에서 `mov rax, gs:[0x30]`(TEB.Self→PEB) 등을 수행.
    // 세그먼트 오버라이드가 있으면 메모리 base를 GS base로 취급한다.
    let seg = inst.segment_prefix();
    if seg == Register::GS || seg == Register::FS {
        let disp = inst.memory_displacement64() as i32;
        let base: Register = inst.memory_base();
        let index: Register = inst.memory_index();
        if base == Register::None && index == Register::None {
            b.lea_gs(dst, disp);
        } else {
            b.lea_gs(SCRATCH, disp);
            if base != Register::None {
                b.binop_r_r(OP_ADD_R_R64, SCRATCH, vreg(base)?);
            }
            if index != Register::None {
                let scale = inst.memory_index_scale();
                let scale_enc = match scale {
                    0 | 1 => 0u8, 2 => 1, 4 => 2, 8 => 3,
                    _ => return Err(anyhow!("lifter: unsupported scale {}", scale)),
                };
                b.mov_r_r(SCRATCH2, vreg(index)?);
                if scale_enc > 0 { b.shift64_r_imm8(OP_SHL64_R_IMM8, SCRATCH2, scale_enc); }
                b.binop_r_r(OP_ADD_R_R64, SCRATCH, SCRATCH2);
            }
            if dst != SCRATCH {
                b.mov_r_r64(dst, SCRATCH);
            }
        }
        return Ok(());
    }

    // base register (may be Register::None)
    let base: Register = inst.memory_base();
    let index: Register = inst.memory_index();
    let scale = inst.memory_index_scale();
    let disp = inst.memory_displacement64() as i32;

    let scale_enc = match scale {
        0 | 1 => 0u8,
        2 => 1,
        4 => 2,
        8 => 3,
        _ => return Err(anyhow!("lifter: unsupported scale {}", scale)),
    };

    let has_base = base != Register::None;
    let has_index = index != Register::None;
    match (has_base, has_index) {
        (true, true) => {
            b.lea(dst, vreg(base)?, vreg(index)?, scale_enc, disp);
        }
        (true, false) => {
            b.lea(dst, vreg(base)?, ADDR_NO_INDEX, 0, disp);
        }
        (false, true) => {
            b.lea(dst, 0, vreg(index)?, scale_enc, disp);
        }
        (false, false) => {
            let disp64 = inst.memory_displacement64();
            b.mov_r_imm64(dst, disp64);
        }
    }
    Ok(())
}
