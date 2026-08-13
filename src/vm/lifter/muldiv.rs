// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: 1-op multiply/divide + bit-scan / bit-test
// ==============================================================================
// 1-operand MUL/IMUL/DIV/IDIV (implicit accumulator pair), BSR/BSF, and the
// BT/BTS/BTR/BTC bit test-and-modify family. Shared infra (`vreg`, `SCRATCH`,
// `SCRATCH2`, `mem_emit`) lives in `super`.
// ==============================================================================

use super::mem::mem_emit;
use super::{vreg, SCRATCH, SCRATCH2};
use crate::vm::bytecode::*;
use anyhow::Result;
use iced_x86::{Instruction, OpKind};

/// 1-operand MUL/IMUL/DIV/IDIV.
pub(super) fn lift_muldiv(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let c = inst.code();
    let bits = if matches!(c, Mul_rm8 | Imul_rm8 | Div_rm8 | Idiv_rm8) {
        8
    } else if matches!(c, Mul_rm16 | Imul_rm16 | Div_rm16 | Idiv_rm16) {
        16
    } else if matches!(c, Mul_rm64 | Imul_rm64 | Div_rm64 | Idiv_rm64) {
        64
    } else {
        32
    };
    let is_imul = matches!(c, Imul_rm8 | Imul_rm16 | Imul_rm32 | Imul_rm64);
    let is_idiv = matches!(c, Idiv_rm8 | Idiv_rm16 | Idiv_rm32 | Idiv_rm64);
    let is_mul = matches!(c, Mul_rm8 | Mul_rm16 | Mul_rm32 | Mul_rm64);
    let src: u8 = if inst.op0_kind() == OpKind::Register {
        vreg(inst.op0_register())?
    } else {
        let addr = mem_emit(b, inst, 0)?;
        let load = match bits {
            8 => OP_MOVZX_R_MEM8_A,
            16 => OP_MOVZX_R_MEM16_A,
            64 => OP_MOV_R_MEM64_A,
            _ => OP_MOVZX_R_MEM32_A,
        };
        b.mem_load_a(load, SCRATCH, addr);
        SCRATCH
    };
    let op = match bits {
        8 => {
            if is_mul { OP_MUL_R_R8 }
            else if is_imul { OP_IMUL1_R_R8 }
            else if is_idiv { OP_IDIV_R_R8 }
            else { OP_DIV_R_R8 }
        }
        16 => {
            if is_mul { OP_MUL_R_R16 }
            else if is_imul { OP_IMUL1_R_R16 }
            else if is_idiv { OP_IDIV_R_R16 }
            else { OP_DIV_R_R16 }
        }
        64 => {
            if is_mul { OP_MUL_R_R64 }
            else if is_imul { OP_IMUL1_R_R64 }
            else if is_idiv { OP_IDIV_R_R64 }
            else { OP_DIV_R_R64 }
        }
        _ => {
            if is_mul { OP_MUL_R_R32 }
            else if is_imul { OP_IMUL1_R_R32 }
            else if is_idiv { OP_IDIV_R_R32 }
            else { OP_DIV_R_R32 }
        }
    };
    b.mul_r(op, src);
    Ok(())
}

/// BSR / BSF.
pub(super) fn lift_bs(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let dst = vreg(inst.op0_register())?;
    let is64 = matches!(code, Bsr_r64_rm64 | Bsf_r64_rm64);
    let op = if matches!(code, Bsr_r32_rm32 | Bsr_r64_rm64) {
        if is64 { OP_BSR_R64 } else { OP_BSR_R32 }
    } else {
        if is64 { OP_BSF_R64 } else { OP_BSF_R32 }
    };
    if inst.op1_kind() == OpKind::Register {
        let src = vreg(inst.op1_register())?;
        b.bsr_r(op, dst, src);
    } else {
        let addr = mem_emit(b, inst, 1)?;
        if is64 { b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH, addr); }
        else { b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH, addr); }
        b.bsr_r(op, dst, SCRATCH);
    }
    Ok(())
}

/// BT dst, src.
pub(super) fn lift_bt(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let name = format!("{:?}", code);
    let wbits = if name.contains("rm16_") { 16 }
        else if name.contains("rm64_") { 64 }
        else { 32 };
    let mask: u32 = match wbits { 16 => 0xF, 32 => 0x1F, _ => 0x3F };
    if inst.op0_kind() == OpKind::Register {
        let d = vreg(inst.op0_register())?;
        if wbits == 64 { b.mov_r_r64(SCRATCH, d); } else { b.mov_r_r(SCRATCH, d); }
    } else {
        let addr = mem_emit(b, inst, 0)?;
        match wbits {
            16 => b.mem_load_a(OP_MOVZX_R_MEM16_A, SCRATCH, addr),
            64 => b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH, addr),
            _ => b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH, addr),
        }
    }
    if inst.op1_kind() == OpKind::Register {
        let idx = vreg(inst.op1_register())?;
        if wbits == 64 { b.mov_r_r64(SCRATCH2, idx); } else { b.mov_r_r(SCRATCH2, idx); }
        b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, mask);
        let loop_lbl = b.new_label();
        let done = b.new_label();
        b.mark_label(loop_lbl);
        b.test_r_r32(SCRATCH2, SCRATCH2);
        b.jcc8(COND_JE, done);
        if wbits == 64 { b.shift64_r_imm8(OP_SHR64_R_IMM8, SCRATCH, 1); }
        else { b.shift_r_imm8(OP_SHR_R_IMM8, SCRATCH, 1); }
        b.dec_r(SCRATCH2);
        b.jmp8(loop_lbl);
        b.mark_label(done);
    } else {
        let cnt = if wbits == 64 { inst.immediate8() & 0x3F } else { inst.immediate8() & 0x1F };
        if wbits == 64 { b.shift64_r_imm8(OP_SHR64_R_IMM8, SCRATCH, cnt); }
        else { b.shift_r_imm8(OP_SHR_R_IMM8, SCRATCH, cnt); }
    }
    b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, 1);
    b.mov_r_imm32(SCRATCH2, 0);
    b.binop_r_r(OP_SUB_R_R, SCRATCH2, SCRATCH);
    Ok(())
}

/// BTS/BTR/BTC.
pub(super) fn lift_bts(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let name = format!("{:?}", code);
    let is_bts = name.starts_with("Bts_");
    let is_btr = name.starts_with("Btr_");
    let wbits = if name.contains("rm16_") { 16 }
        else if name.contains("rm64_") { 64 }
        else { 32 };
    let mask: u32 = match wbits { 16 => 0xF, 32 => 0x1F, _ => 0x3F };
    let is_mem = inst.op0_kind() == OpKind::Memory;

    if inst.op1_kind() == OpKind::Register {
        let idx = vreg(inst.op1_register())?;
        if wbits == 64 { b.mov_r_r64(SCRATCH2, idx); } else { b.mov_r_r(SCRATCH2, idx); }
        b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, mask);
    } else {
        let cnt = if wbits == 64 { inst.immediate8() & 0x3F } else { inst.immediate8() & 0x1F };
        b.mov_r_imm32(SCRATCH2, cnt as u32);
    }

    let (mem_addr, dst_r) = if is_mem {
        let addr = mem_emit(b, inst, 0)?;
        let load = match wbits { 16 => OP_MOVZX_R_MEM16_A, 64 => OP_MOV_R_MEM64_A, _ => OP_MOVZX_R_MEM32_A };
        b.mem_load_a(load, 19, addr);
        (Some(addr), 19)
    } else {
        let r = vreg(inst.op0_register())?;
        (None, r)
    };

    const TMP: u8 = 18;
    b.mov_r_imm32(TMP, 1);
    let loop_lbl = b.new_label();
    let done_shift = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(SCRATCH2, SCRATCH2);
    b.jcc8(COND_JE, done_shift);
    if wbits == 64 { b.shift64_r_imm8(OP_SHL64_R_IMM8, TMP, 1); }
    else { b.shift_r_imm8(OP_SHL_R_IMM8, TMP, 1); }
    b.dec_r(SCRATCH2);
    b.jmp8(loop_lbl);
    b.mark_label(done_shift);

    if wbits == 64 {
        b.mov_r_r64(SCRATCH2, dst_r);
        b.binop_r_r64(OP_AND_R_R64, SCRATCH2, TMP);
    } else {
        b.mov_r_r(SCRATCH2, dst_r);
        b.binop_r_r(OP_AND_R_R, SCRATCH2, TMP);
    }
    b.mov_r_imm32(TMP, 0);
    b.binop_r_r(OP_SUB_R_R, TMP, SCRATCH2);

    if inst.op1_kind() == OpKind::Register {
        let idx = vreg(inst.op1_register())?;
        if wbits == 64 { b.mov_r_r64(SCRATCH2, idx); } else { b.mov_r_r(SCRATCH2, idx); }
        b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, mask);
    } else {
        let cnt = if wbits == 64 { inst.immediate8() & 0x3F } else { inst.immediate8() & 0x1F };
        b.mov_r_imm32(SCRATCH2, cnt as u32);
    }
    b.mov_r_imm32(TMP, 1);
    let loop2 = b.new_label();
    let done2 = b.new_label();
    b.mark_label(loop2);
    b.test_r_r32(SCRATCH2, SCRATCH2);
    b.jcc8(COND_JE, done2);
    if wbits == 64 { b.shift64_r_imm8(OP_SHL64_R_IMM8, TMP, 1); }
    else { b.shift_r_imm8(OP_SHL_R_IMM8, TMP, 1); }
    b.dec_r(SCRATCH2);
    b.jmp8(loop2);
    b.mark_label(done2);

    if is_bts {
        if wbits == 64 { b.binop_r_r64(OP_OR_R_R64, dst_r, TMP); }
        else { b.binop_r_r(OP_OR_R_R, dst_r, TMP); }
    } else if is_btr {
        if wbits == 64 { b.not_r64(TMP); b.binop_r_r64(OP_AND_R_R64, dst_r, TMP); }
        else { b.not_r(TMP); b.binop_r_r(OP_AND_R_R, dst_r, TMP); }
    } else {
        if wbits == 64 { b.binop_r_r64(OP_XOR_R_R64, dst_r, TMP); }
        else { b.binop_r_r(OP_XOR_R_R, dst_r, TMP); }
    }

    if let Some(addr) = mem_addr {
        let store = match wbits { 16 => OP_MOV_MEM16_A, 64 => OP_MOV_MEM64_A, _ => OP_MOV_MEM32_A };
        b.mem_store_a(store, addr, dst_r);
    }
    Ok(())
}
