// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: string ops
// ==============================================================================
// MOVS / STOS / LODS / SCAS / CMPS, all widths (byte/word/dword/qword), with and
// without the REP prefix. REP forms are lowered to explicit VM loops (DF assumed
// clear/forward). STOS/MOVS/LODS use a plain count-down loop; SCAS/CMPS honour
// the REPE/REPNE stop condition (ZF). The accumulator for STOS/LODS/SCAS is
// vreg0 (RAX/EAX/AX/AL). Shared infra (`SCRATCH`, `SCRATCH2`) lives in `super`.
// ==============================================================================

use super::{SCRATCH, SCRATCH2};
use crate::vm::bytecode::*;
use anyhow::Result;
use iced_x86::Instruction;

/// (load, store, width) triple for a given element width in bytes.
fn width_ops(n: u64) -> (u8, u8, u32) {
    match n {
        1 => (OP_MOVZX_R_MEM8_A, OP_MOV_MEM8_A, 0xFF),
        2 => (OP_MOVZX_R_MEM16_A, OP_MOV_MEM16_A, 0xFFFF),
        4 => (OP_MOVZX_R_MEM32_A, OP_MOV_MEM32_A, 0xFFFF_FFFF),
        _ => (OP_MOV_R_MEM64_A, OP_MOV_MEM64_A, 0xFFFF_FFFF),
    }
}

fn is64(n: u64) -> bool {
    n == 8
}

/// True if the instruction has any REP-family prefix (REP / REPE / REPNE).
/// `has_rep_prefix()` alone returns false for REPNE (0xF2), so string ops must
/// check both to decide between the loop and the single-op form.
fn has_any_rep(inst: &Instruction) -> bool {
    inst.has_rep_prefix() || inst.has_repne_prefix()
}

/// STOS: [rdi] = AL/AX/EAX/RAX (vreg0); rdi += n. REP → count-down loop.
pub(super) fn lift_stos(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let n = stos_lods_width(inst.code());
    let (_, store, _) = width_ops(n);
    let rdi = 7u8; let rcx = 1u8;
    let single = |b: &mut BytecodeBuilder| {
        b.mem_store_a(store, rdi, 0);
        b.binop_r_imm64(OP_ADD_R_IMM64, rdi, n as u32);
    };
    if !has_any_rep(inst) {
        single(b);
        return Ok(());
    }
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    single(b);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    Ok(())
}

/// LODS: AL/AX/EAX/RAX (vreg0) = [rsi]; rsi += n. REP → count-down loop.
/// Note: x86 LODSB only writes AL; we zero-extend into vreg0 for simplicity.
pub(super) fn lift_lods(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let n = stos_lods_width(inst.code());
    let (load, _, _) = width_ops(n);
    let rsi = 6u8; let rcx = 1u8;
    let single = |b: &mut BytecodeBuilder| {
        b.mem_load_a(load, 0, rsi);
        b.binop_r_imm64(OP_ADD_R_IMM64, rsi, n as u32);
    };
    if !has_any_rep(inst) {
        single(b);
        return Ok(());
    }
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    single(b);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    Ok(())
}

/// MOVS: [rdi] = [rsi]; rsi += n; rdi += n. REP → count-down loop.
pub(super) fn lift_movs(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let n = match inst.code() {
        Movsb_m8_m8 => 1u64,
        Movsw_m16_m16 => 2,
        Movsd_m32_m32 => 4,
        _ => 8,
    };
    let (load, store, _) = width_ops(n);
    let rsi = 6u8; let rdi = 7u8; let rcx = 1u8;
    let single = |b: &mut BytecodeBuilder| {
        b.mem_load_a(load, SCRATCH, rsi);
        b.mem_store_a(store, rdi, SCRATCH);
        b.binop_r_imm64(OP_ADD_R_IMM64, rsi, n as u32);
        b.binop_r_imm64(OP_ADD_R_IMM64, rdi, n as u32);
    };
    if !has_any_rep(inst) {
        single(b);
        return Ok(());
    }
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    single(b);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    Ok(())
}

/// SCAS: flags = [rdi] - AL/AX/EAX/RAX; rdi += n. REPE/REPNE honour ZF stop.
pub(super) fn lift_scas(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let n = scas_cmps_width(inst.code());
    let (load, _, mask) = width_ops(n);
    let rdi = 7u8; let rcx = 1u8;
    // compare body: SCRATCH = [rdi] - accumulator (vreg0), sets flags
    let cmp_body = |b: &mut BytecodeBuilder| {
        b.mem_load_a(load, SCRATCH, rdi);
        if is64(n) {
            b.mov_r_r64(SCRATCH2, 0);
            b.binop_r_r64(OP_SUB_R_R64, SCRATCH, SCRATCH2);
        } else {
            b.mov_r_r(SCRATCH2, 0);
            if mask != 0xFFFF_FFFF { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, mask); }
            b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2);
        }
    };
    let advance = |b: &mut BytecodeBuilder| {
        b.binop_r_imm64(OP_ADD_R_IMM64, rdi, n as u32);
    };
    if !has_any_rep(inst) {
        cmp_body(b);
        advance(b);
        return Ok(());
    }
    let exit_cond = rep_exit_cond(inst);
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    cmp_body(b);
    if let Some(c) = exit_cond {
        b.jcc8(c, done);
    }
    advance(b);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    Ok(())
}

/// CMPS: flags = [rdi] - [rsi]; rsi += n; rdi += n. REPE/REPNE honour ZF stop.
pub(super) fn lift_cmps(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let n = scas_cmps_width(inst.code());
    let (load, _, mask) = width_ops(n);
    let rsi = 6u8; let rdi = 7u8; let rcx = 1u8;
    let cmp_body = |b: &mut BytecodeBuilder| {
        b.mem_load_a(load, SCRATCH, rdi);
        b.mem_load_a(load, SCRATCH2, rsi);
        if is64(n) {
            b.binop_r_r64(OP_SUB_R_R64, SCRATCH, SCRATCH2);
        } else {
            if mask != 0xFFFF_FFFF { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, mask); }
            b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2);
        }
    };
    let advance = |b: &mut BytecodeBuilder| {
        b.binop_r_imm64(OP_ADD_R_IMM64, rsi, n as u32);
        b.binop_r_imm64(OP_ADD_R_IMM64, rdi, n as u32);
    };
    if !has_any_rep(inst) {
        cmp_body(b);
        advance(b);
        return Ok(());
    }
    let exit_cond = rep_exit_cond(inst);
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    cmp_body(b);
    if let Some(c) = exit_cond {
        b.jcc8(c, done);
    }
    advance(b);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    Ok(())
}

/// Element width (bytes) of a STOS/LODS instruction from its iced code.
fn stos_lods_width(code: iced_x86::Code) -> u64 {
    use iced_x86::Code::*;
    match code {
        Stosb_m8_AL | Lodsb_AL_m8 => 1,
        Stosw_m16_AX | Lodsw_AX_m16 => 2,
        Stosd_m32_EAX | Lodsd_EAX_m32 => 4,
        _ => 8,
    }
}

/// Element width (bytes) of a SCAS/CMPS instruction from its iced code.
fn scas_cmps_width(code: iced_x86::Code) -> u64 {
    use iced_x86::Code::*;
    match code {
        Scasb_AL_m8 | Cmpsb_m8_m8 => 1,
        Scasw_AX_m16 | Cmpsw_m16_m16 => 2,
        Scasd_EAX_m32 | Cmpsd_m32_m32 => 4,
        _ => 8,
    }
}

/// The VM cond code to exit a REPE/REPNE loop on, or None for a plain REP
/// (which has no ZF stop condition). REPE stops on not-equal (JNE); REPNE stops
/// on equal (JE).
fn rep_exit_cond(inst: &Instruction) -> Option<u8> {
    if inst.has_repe_prefix() {
        Some(COND_JNE)
    } else if inst.has_repne_prefix() {
        Some(COND_JE)
    } else {
        None
    }
}
