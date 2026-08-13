// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: arithmetic / logic (reg, reg/mem,
// immediate) family
// ==============================================================================
// Lowers 32/64-bit ADD/SUB/XOR/AND/OR (reg/reg, reg/mem, reg/imm), the 8/16-bit
// narrow forms, IMUL immediate, and the shared immediate-decode helpers used by
// the control-flow family (`is_imm8_op`, `inst_imm`). Shared infra (`vreg`,
// `reg_bits`, `SCRATCH`, `SCRATCH2`, `mem_emit`) lives in `super`.
// ==============================================================================

use super::mem::mem_emit;
use super::{reg_bits, vreg, SCRATCH, SCRATCH2};
use crate::vm::bytecode::*;
use anyhow::{Result, anyhow};
use iced_x86::{Code, Instruction, OpKind};

/// Two-operand reg/reg or reg/mem binary op. Memory sources are lowered by
/// loading into SCRATCH first (the VM op set has no reg/mem forms).
pub(super) fn two_op(b: &mut BytecodeBuilder, inst: &Instruction, op32: u8, op64: u8) -> Result<()> {
    let mem_dst = inst.op0_kind() == OpKind::Memory;
    let is64_code = matches!(inst.code(),
        iced_x86::Code::Add_rm64_r64 | iced_x86::Code::Sub_rm64_r64
        | iced_x86::Code::Xor_rm64_r64 | iced_x86::Code::And_rm64_r64
        | iced_x86::Code::Or_rm64_r64 | iced_x86::Code::Imul_r64_rm64
        | iced_x86::Code::Add_r64_rm64 | iced_x86::Code::Sub_r64_rm64
        | iced_x86::Code::Xor_r64_rm64 | iced_x86::Code::And_r64_rm64
        | iced_x86::Code::Or_r64_rm64 | iced_x86::Code::Imul_r64_rm64);
    let mut d = 0u8;
    let mut mem_addr = 0u8;
    if mem_dst {
        mem_addr = mem_emit(b, inst, 0)?;
        if is64_code { b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH2, mem_addr); }
        else { b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH2, mem_addr); }
        d = SCRATCH2;
    } else {
        d = vreg(inst.op0_register())?;
    }
    let sz = if is64_code { 64 } else { reg_bits(inst.op0_register()) };
    let op = if sz == 64 { op64 } else { op32 };

    if inst.op1_kind() == OpKind::Register {
        let s = vreg(inst.op1_register())?;
        if sz == 64 { b.binop_r_r64(op, d, s); }
        else { b.binop_r_r(op, d, s); }
    } else {
        let src_addr = mem_emit(b, inst, 1)?;
        if sz == 64 {
            b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH2, src_addr);
            b.binop_r_r64(op, d, SCRATCH2);
        } else {
            b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH2, src_addr);
            b.binop_r_r(op, d, SCRATCH2);
        }
    }
    if mem_dst {
        let store_op = if sz == 64 { OP_MOV_MEM64_A } else { OP_MOV_MEM32_A };
        b.mem_store_a(store_op, mem_addr, d);
    }
    Ok(())
}

fn lift_sub_imm(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let r = vreg(inst.op0_register())?;
    let imm = inst.immediate32();
    b.binop_r_imm32(OP_ADD_R_IMM32, r, imm.wrapping_neg());
    Ok(())
}

/// True for immediate-8 (sign-extended) opcode forms.
pub(super) fn is_imm8_op(code: Code) -> bool {
    use iced_x86::Code::*;
    matches!(code,
        Add_rm32_imm8 | Add_rm64_imm8 | Sub_rm32_imm8 | Sub_rm64_imm8
        | Adc_rm32_imm8 | Adc_rm64_imm8 | Adc_rm8_imm8 | Adc_rm16_imm8 | Adc_AL_imm8
        | And_rm32_imm8 | And_rm64_imm8 | Or_rm32_imm8 | Or_rm64_imm8
        | Xor_rm32_imm8 | Xor_rm64_imm8
        | Cmp_rm32_imm8 | Cmp_rm64_imm8 | Cmp_rm8_imm8 | Cmp_rm16_imm8 | Cmp_AL_imm8
        | Test_rm8_imm8 | Test_AL_imm8
        | Mov_rm8_imm8)
}

/// Sign-extended immediate value for an instruction.
pub(super) fn inst_imm(inst: &Instruction, is8: bool) -> i64 {
    if is8 {
        (inst.immediate8() as i8) as i64
    } else {
        (inst.immediate32() as i32) as i64
    }
}

/// Width (bits) of the operand for an add/sub/and/or/xor-imm opcode.
fn imm_op_width(code: Code) -> usize {
    use iced_x86::Code::*;
    if matches!(code,
        Add_rm32_imm8 | Add_rm32_imm32 | Sub_rm32_imm8 | Sub_rm32_imm32
        | And_rm32_imm8 | And_rm32_imm32 | Or_rm32_imm8 | Or_rm32_imm32
        | Xor_rm32_imm8 | Xor_rm32_imm32
        | Add_EAX_imm32 | And_EAX_imm32 | Or_EAX_imm32 | Xor_EAX_imm32) { 32 } else { 64 }
}

/// Add/Sub/And/Or/Xor r/m, imm8/imm32.
pub(super) fn lift_arith_imm(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let is8 = is_imm8_op(code);
    let mut imm = inst_imm(inst, is8);
    let is_sub = matches!(code,
        Sub_RAX_imm32 | Sub_rm32_imm8 | Sub_rm32_imm32 | Sub_rm64_imm8 | Sub_rm64_imm32);
    if is_sub { imm = -imm; }

    let (op32, op64) = if matches!(code,
        Add_EAX_imm32 | Add_rm32_imm8 | Add_rm32_imm32 | Add_rm64_imm8 | Add_rm64_imm32
        | Sub_RAX_imm32 | Sub_rm32_imm8 | Sub_rm32_imm32 | Sub_rm64_imm8 | Sub_rm64_imm32)
    {
        (OP_ADD_R_IMM32, OP_ADD_R_IMM64)
    } else if matches!(code,
        And_EAX_imm32 | And_rm32_imm8 | And_rm32_imm32 | And_rm64_imm8 | And_rm64_imm32)
    {
        (OP_AND_R_IMM32, OP_AND_R_IMM64)
    } else if matches!(code,
        Or_EAX_imm32 | Or_rm32_imm8 | Or_rm32_imm32 | Or_rm64_imm8 | Or_rm64_imm32)
    {
        (OP_OR_R_IMM32, OP_OR_R_IMM64)
    } else {
        (OP_XOR_R_IMM32, OP_XOR_R_IMM64)
    };

    if inst.op0_kind() == OpKind::Register {
        let r = vreg(inst.op0_register())?;
        if reg_bits(inst.op0_register()) == 64 {
            b.binop_r_imm64(op64, r, imm as u32);
        } else {
            b.binop_r_imm32(op32, r, imm as u32);
        }
    } else if inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        let sz = imm_op_width(code);
        let (load, store) = match sz {
            8 => (OP_MOVZX_R_MEM8_A, OP_MOV_MEM8_A),
            32 => (OP_MOVZX_R_MEM32_A, OP_MOV_MEM32_A),
            _ => (OP_MOV_R_MEM64_A, OP_MOV_MEM64_A),
        };
        b.mem_load_a(load, SCRATCH2, addr);
        if sz == 64 { b.binop_r_imm64(op64, SCRATCH2, imm as u32); }
        else { b.binop_r_imm32(op32, SCRATCH2, imm as u32); }
        b.mem_store_a(store, addr, SCRATCH2);
    } else {
        return Err(anyhow!("lifter: unsupported arith-imm operand {}", inst));
    }
    Ok(())
}

/// IMUL reg, r/m, imm.
pub(super) fn lift_imul_imm(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let d = vreg(inst.op0_register())?;
    let is64 = reg_bits(inst.op0_register()) == 64;
    let is_imm8_form = matches!(inst.code(), Imul_r32_rm32_imm8 | Imul_r64_rm64_imm8);
    let imm: i64 = if is_imm8_form {
        (inst.immediate8() as i8) as i64
    } else {
        (inst.immediate32() as i32) as i64
    };
    if is64 {
        b.mov_r_imm64(SCRATCH, imm as u64);
        b.binop_r_r64(OP_IMUL_R_R64, d, SCRATCH);
    } else {
        b.mov_r_imm32(SCRATCH, imm as u32);
        b.binop_r_r(OP_IMUL_R_R, d, SCRATCH);
    }
    Ok(())
}

/// 8-bit ADD.
pub(super) fn lift_add8(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    lift_narrow_arith(b, inst)
}

/// A-2 잔여 (v32): 8/16-bit ADD/SUB/XOR/AND/OR (reg/mem/imm forms).
pub(super) fn lift_narrow_arith(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    use iced_x86::OpKind;
    let code = inst.code();
    let (op, _is_sub) = if matches!(code,
        Sub_rm8_r8 | Sub_r8_rm8 | Sub_rm16_r16 | Sub_r16_rm16
        | Sub_AL_imm8 | Sub_AX_imm16 | Sub_rm8_imm8 | Sub_rm16_imm8 | Sub_rm16_imm16)
    { (OP_SUB_R_R, true) } else if matches!(code,
        Add_rm8_r8 | Add_r8_rm8 | Add_rm16_r16 | Add_r16_rm16
        | Add_AL_imm8 | Add_AX_imm16 | Add_rm8_imm8 | Add_rm16_imm8 | Add_rm16_imm16)
    { (OP_ADD_R_R, false) } else if matches!(code,
        Xor_rm8_r8 | Xor_r8_rm8 | Xor_rm16_r16 | Xor_r16_rm16
        | Xor_AL_imm8 | Xor_AX_imm16 | Xor_rm8_imm8 | Xor_rm16_imm8 | Xor_rm16_imm16)
    { (OP_XOR_R_R, false) } else if matches!(code,
        And_rm8_r8 | And_r8_rm8 | And_rm16_r16 | And_r16_rm16
        | And_AL_imm8 | And_AX_imm16 | And_rm8_imm8 | And_rm16_imm8 | And_rm16_imm16)
    { (OP_AND_R_R, false) } else {
        (OP_OR_R_R, false)
    };
    let is8 = matches!(code,
        Add_rm8_r8 | Add_r8_rm8 | Add_AL_imm8 | Add_rm8_imm8
        | Sub_rm8_r8 | Sub_r8_rm8 | Sub_AL_imm8 | Sub_rm8_imm8
        | Xor_rm8_r8 | Xor_r8_rm8 | Xor_AL_imm8 | Xor_rm8_imm8
        | And_rm8_r8 | And_r8_rm8 | And_AL_imm8 | And_rm8_imm8
        | Or_rm8_r8 | Or_r8_rm8 | Or_AL_imm8 | Or_rm8_imm8);
    let mask: u32 = if is8 { 0xFF } else { 0xFFFF };
    let load = if is8 { OP_MOVZX_R_MEM8_A } else { OP_MOVZX_R_MEM16_A };
    let store = if is8 { OP_MOV_MEM8_A } else { OP_MOV_MEM16_A };

    let mem_dst = inst.op0_kind() == OpKind::Memory;
    let mem_addr = if mem_dst { Some(mem_emit(b, inst, 0)?) } else { None };
    if mem_dst {
        b.mem_load_a(load, SCRATCH2, mem_addr.unwrap());
    } else {
        let d = vreg(inst.op0_register())?;
        b.mov_r_r(SCRATCH, d);
    }
    const TMP18: u8 = 18;
    let src_r = if inst.op1_kind() == OpKind::Register {
        let s = vreg(inst.op1_register())?;
        if mem_dst { s } else { b.mov_r_r(SCRATCH2, s); SCRATCH2 }
    } else if inst.op1_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 1)?;
        b.mem_load_a(load, SCRATCH2, addr);
        SCRATCH2
    } else {
        let is8imm = matches!(inst.op1_kind(), OpKind::Immediate8);
        let imm = inst_imm(inst, is8imm) as u64;
        if mem_dst {
            b.mov_r_imm64(TMP18, imm);
            TMP18
        } else {
            b.mov_r_imm64(SCRATCH2, imm);
            SCRATCH2
        }
    };
    let (val_r, out) = if mem_dst { (SCRATCH2, mem_addr.unwrap()) } else { (SCRATCH, 0u8) };
    b.binop_r_r(op, val_r, src_r);
    b.binop_r_imm32(OP_AND_R_IMM32, val_r, mask);
    if mem_dst {
        b.mem_store_a(store, out, val_r);
    } else {
        let d = vreg(inst.op0_register())?;
        b.mov_r_r(d, val_r);
    }
    Ok(())
}
