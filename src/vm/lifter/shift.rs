// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: shift / rotate / INC-DEC / NOT-NEG
// ==============================================================================
// SHL/SHR/SAR/ROL/ROR (all widths, 1/imm8/CL forms), INC/DEC and NOT/NEG on
// register or memory destinations (load-modify-store via the scratch vregs).
// Shared infra (`vreg`, `reg_bits`, `SCRATCH`, `SCRATCH2`, `mem_emit`) lives in
// `super`.
// ==============================================================================

use super::mem::mem_emit;
use super::{vreg, SCRATCH2};
use crate::vm::bytecode::*;
use anyhow::{Result, anyhow};
use iced_x86::{Instruction, OpKind};

/// Unified lifter for SHL, SHR, SAR, ROL, ROR (8/16/32/64-bit, reg/mem, _1/_imm8/_CL).
pub(super) fn lift_shift_rotate(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    use iced_x86::OpKind;
    let code = inst.code();

    let name = format!("{:?}", code);
    let is_shl = name.starts_with("Shl_");
    let is_shr = name.starts_with("Shr_");
    let is_sar = name.starts_with("Sar_");
    let is_rol = name.starts_with("Rol_");

    let is8 = name.contains("_rm8_");
    let is16 = name.contains("_rm16_");
    let is64 = name.contains("_rm64_");

    let mem_target = inst.op0_kind() == OpKind::Memory;
    let (dst_reg, mem_addr) = if mem_target {
        let addr = mem_emit(b, inst, 0)?;
        let load_op = if is8 {
            OP_MOVZX_R_MEM8_A
        } else if is16 {
            OP_MOVZX_R_MEM16_A
        } else if is64 {
            OP_MOV_R_MEM64_A
        } else {
            OP_MOVZX_R_MEM32_A
        };
        b.mem_load_a(load_op, SCRATCH2, addr);
        (SCRATCH2, Some(addr))
    } else {
        (vreg(inst.op0_register())?, None)
    };

    let is_cl = name.ends_with("_CL");
    let is_one = name.ends_with("_1");

    if is_rol || name.starts_with("Ror_") {
        let cnt = if is_one {
            1
        } else if is_cl {
            if vreg(inst.op1_register())? != 1 {
                return Err(anyhow!("lifter: CL shift source must be RCX"));
            }
            1
        } else {
            inst.immediate8() as u8
        };

        if is_rol {
            b.rol_r_imm8(dst_reg, cnt);
        } else {
            b.ror_r_imm8(dst_reg, cnt);
        }
    } else if is_cl {
        if vreg(inst.op1_register())? != 1 {
            return Err(anyhow!("lifter: CL shift source must be RCX"));
        }
        let op = if is64 {
            if is_shl {
                OP_SHL64_R_CL
            } else if is_shr {
                OP_SHR64_R_CL
            } else {
                OP_SAR64_R_CL
            }
        } else {
            if is_shl {
                OP_SHL_R_CL
            } else if is_shr {
                OP_SHR_R_CL
            } else {
                OP_SAR_R_CL
            }
        };
        b.shift_r_cl(op, dst_reg);
    } else {
        let cnt = if is_one { 1 } else { inst.immediate8() as u8 };
        if is64 {
            let op = if is_shl {
                OP_SHL64_R_IMM8
            } else if is_shr {
                OP_SHR64_R_IMM8
            } else {
                OP_SAR64_R_IMM8
            };
            b.shift64_r_imm8(op, dst_reg, cnt);
        } else {
            let op = if is_shl {
                OP_SHL_R_IMM8
            } else if is_shr {
                OP_SHR_R_IMM8
            } else {
                OP_SAR_R_IMM8
            };
            b.shift_r_imm8(op, dst_reg, cnt);
        }
    }

    if is8 {
        b.binop_r_imm32(OP_AND_R_IMM32, dst_reg, 0xFF);
    } else if is16 {
        b.binop_r_imm32(OP_AND_R_IMM32, dst_reg, 0xFFFF);
    }

    if let Some(addr) = mem_addr {
        let store_op = if is8 {
            OP_MOV_MEM8_A
        } else if is16 {
            OP_MOV_MEM16_A
        } else if is64 {
            OP_MOV_MEM64_A
        } else {
            OP_MOV_MEM32_A
        };
        b.mem_store_a(store_op, addr, dst_reg);
    }

    Ok(())
}

/// INC/DEC on a register or a memory destination (load-modify-store).
pub(super) fn lift_incdec(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let is_inc = matches!(inst.code(), Inc_rm32 | Inc_rm64 | Inc_rm8 | Inc_rm16);
    // LOCK-prefixed memory INC/DEC — atomic RMW (Rust refcount bump/drop).
    // Lifted to the dedicated LOCK_INC/DEC_MEM*_A opcodes (real `lock inc/dec`
    // in the native handler), NOT decomposed into a non-atomic load/mod/store
    // (a racing thread must observe the atomic update).
    if inst.has_lock_prefix() && inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        let op = match inst.code() {
            Inc_rm8 => OP_LOCK_INC_MEM8_A,
            Inc_rm16 => OP_LOCK_INC_MEM16_A,
            Inc_rm32 => OP_LOCK_INC_MEM32_A,
            Inc_rm64 => OP_LOCK_INC_MEM64_A,
            Dec_rm8 => OP_LOCK_DEC_MEM8_A,
            Dec_rm16 => OP_LOCK_DEC_MEM16_A,
            Dec_rm32 => OP_LOCK_DEC_MEM32_A,
            _ => OP_LOCK_DEC_MEM64_A,
        };
        if is_inc { b.lock_inc_a(op, addr); } else { b.lock_dec_a(op, addr); }
        return Ok(());
    }
    if inst.op0_kind() == OpKind::Register {
        let r = vreg(inst.op0_register())?;
        let is64 = matches!(inst.code(), Inc_rm64 | Dec_rm64);
        if is_inc {
            if is64 { b.inc_r64(r); } else { b.inc_r(r); }
        } else if is64 {
            b.dec_r64(r);
        } else {
            b.dec_r(r);
        }
        return Ok(());
    }
    let addr = mem_emit(b, inst, 0)?;
    let sz = match inst.code() {
        Inc_rm8 | Dec_rm8 => 8,
        Inc_rm16 | Dec_rm16 => 16,
        Inc_rm32 | Dec_rm32 => 32,
        _ => 64,
    };
    let load = match sz { 8 => OP_MOVZX_R_MEM8_A, 16 => OP_MOVZX_R_MEM16_A, 32 => OP_MOVZX_R_MEM32_A, _ => OP_MOV_R_MEM64_A };
    let store = match sz { 8 => OP_MOV_MEM8_A, 16 => OP_MOV_MEM16_A, 32 => OP_MOV_MEM32_A, _ => OP_MOV_MEM64_A };
    b.mem_load_a(load, SCRATCH2, addr);
    if is_inc {
        if sz == 64 { b.inc_r64(SCRATCH2); } else { b.inc_r(SCRATCH2); }
    } else if sz == 64 {
        b.dec_r64(SCRATCH2);
    } else {
        b.dec_r(SCRATCH2);
    }
    b.mem_store_a(store, addr, SCRATCH2);
    Ok(())
}

/// NOT / NEG — unary ops on register or memory operand.
pub(super) fn lift_not_neg(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let name = format!("{:?}", code);
    let is_not = name.starts_with("Not_");
    let is8  = name.contains("_rm8");
    let is16 = name.contains("_rm16");
    let is64 = name.contains("_rm64");

    if inst.op0_kind() == OpKind::Register {
        let r = vreg(inst.op0_register())?;
        if is_not {
            if is64 { b.not_r64(r); } else { b.not_r(r); }
        } else {
            if is64 { b.neg_r64(r); } else { b.neg_r(r); }
        }
        if is8  { b.binop_r_imm32(OP_AND_R_IMM32, r, 0xFF); }
        if is16 { b.binop_r_imm32(OP_AND_R_IMM32, r, 0xFFFF); }
        return Ok(());
    }

    let addr = mem_emit(b, inst, 0)?;
    let (load, store) = if is8 {
        (OP_MOVZX_R_MEM8_A,  OP_MOV_MEM8_A)
    } else if is16 {
        (OP_MOVZX_R_MEM16_A, OP_MOV_MEM16_A)
    } else if is64 {
        (OP_MOV_R_MEM64_A,   OP_MOV_MEM64_A)
    } else {
        (OP_MOVZX_R_MEM32_A, OP_MOV_MEM32_A)
    };
    b.mem_load_a(load, SCRATCH2, addr);
    if is_not {
        if is64 { b.not_r64(SCRATCH2); } else { b.not_r(SCRATCH2); }
    } else {
        if is64 { b.neg_r64(SCRATCH2); } else { b.neg_r(SCRATCH2); }
    }
    if is8  { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, 0xFF); }
    if is16 { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, 0xFFFF); }
    b.mem_store_a(store, addr, SCRATCH2);
    Ok(())
}

/// SHLD / SHRD double-precision shift lifter (Phase 4).
pub(super) fn lift_shld_shrd(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let code = inst.code();
    let name = format!("{:?}", code);
    let is_shld = name.starts_with("Shld_");
    let is64 = name.contains("_rm64_");
    let is_cl = name.ends_with("_CL");

    let dst = vreg(inst.op0_register())?;
    let src = vreg(inst.op1_register())?;

    if is_shld {
        if is_cl {
            let op = if is64 { OP_SHLD64_R_R_CL } else { OP_SHLD_R_R_CL };
            b.shld_cl(op, dst, src);
        } else {
            let imm = inst.immediate8();
            let op = if is64 { OP_SHLD64_R_R_IMM8 } else { OP_SHLD_R_R_IMM8 };
            b.shld_imm(op, dst, src, imm);
        }
    } else {
        if is_cl {
            let op = if is64 { OP_SHRD64_R_R_CL } else { OP_SHRD_R_R_CL };
            b.shld_cl(op, dst, src);
        } else {
            let imm = inst.immediate8();
            let op = if is64 { OP_SHRD64_R_R_IMM8 } else { OP_SHRD_R_R_IMM8 };
            b.shld_imm(op, dst, src, imm);
        }
    }
    Ok(())
}
