// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: REP string ops
// ==============================================================================
// REP STOSQ / REP MOVS / REP CMPS lowered to explicit VM loops (the DF flag is
// assumed clear/forward). Shared infra (`SCRATCH`, `SCRATCH2`) lives in `super`.
// ==============================================================================

use super::{SCRATCH, SCRATCH2};
use crate::vm::bytecode::*;
use anyhow::Result;
use iced_x86::Instruction;

/// REP STOSQ.
pub(super) fn lift_rep_stosq(b: &mut BytecodeBuilder) -> Result<()> {
    let rdi = 7u8; let rax = 0u8; let rcx = 1u8;
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    b.mem_store_a(OP_MOV_MEM64_A, rdi, rax);
    b.binop_r_imm32(OP_ADD_R_IMM32, rdi, 8);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    Ok(())
}

/// REP MOVS.
pub(super) fn lift_rep_movs(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let n = match inst.code() {
        Movsb_m8_m8 => 1u64,
        Movsw_m16_m16 => 2,
        Movsd_m32_m32 => 4,
        _ => 8,
    };
    let (load, store) = match n {
        1 => (OP_MOVZX_R_MEM8_A, OP_MOV_MEM8_A),
        2 => (OP_MOVZX_R_MEM16_A, OP_MOV_MEM16_A),
        4 => (OP_MOVZX_R_MEM32_A, OP_MOV_MEM32_A),
        _ => (OP_MOV_R_MEM64_A, OP_MOV_MEM64_A),
    };
    let rsi = 6u8; let rdi = 7u8; let rcx = 1u8;
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    b.mem_load_a(load, SCRATCH, rsi);
    b.mem_store_a(store, rdi, SCRATCH);
    b.binop_r_imm32(OP_ADD_R_IMM32, rsi, n as u32);
    b.binop_r_imm32(OP_ADD_R_IMM32, rdi, n as u32);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    Ok(())
}

/// REP CMPS.
pub(super) fn lift_rep_cmps(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let n = match inst.code() {
        Cmpsb_m8_m8 => 1u64,
        Cmpsw_m16_m16 => 2,
        Cmpsd_m32_m32 => 4,
        _ => 8,
    };
    let load = match n {
        1 => OP_MOVZX_R_MEM8_A,
        2 => OP_MOVZX_R_MEM16_A,
        4 => OP_MOVZX_R_MEM32_A,
        _ => OP_MOV_R_MEM64_A,
    };
    let rsi = 6u8; let rdi = 7u8; let rcx = 1u8;
    let loop_lbl = b.new_label();
    let done = b.new_label();
    let mismatch = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    b.mem_load_a(load, SCRATCH, rdi);
    b.mem_load_a(load, SCRATCH2, rsi);
    b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2);
    b.jcc8(COND_JNE, mismatch);
    b.binop_r_imm32(OP_ADD_R_IMM32, rsi, n as u32);
    b.binop_r_imm32(OP_ADD_R_IMM32, rdi, n as u32);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(mismatch);
    b.dec_r(rcx);
    b.mark_label(done);
    Ok(())
}
