// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: string ops
// ==============================================================================
// MOVS / STOS / LODS / SCAS / CMPS, all widths (byte/word/dword/qword), with and
// without the REP prefix. REP forms are lowered to explicit VM loops (DF assumed
// clear/forward). STOS/MOVS/LODS use a plain count-down loop; SCAS/CMPS honour
// the REPE/REPNE stop condition (ZF). The accumulator for STOS/LODS/SCAS is
// vreg0 (RAX/EAX/AX/AL). Shared infra (`SCRATCH`, `SCRATCH2`) lives in `super`.
//
// x86-exactness notes (v52 fix):
//   * The compare direction is the real one: SCAS is `accumulator - [RDI]`,
//     CMPS is `[RSI] - [RDI]` (ZF unchanged by direction, CF/SF differ).
//   * REP SCAS/CMPS consume the count and advance the pointer(s) on the
//     terminating iteration too, exactly like the hardware: the ZF info is
//     captured via SETcc (which preserves rflags) BEFORE advance/dec, the
//     pointers/count are bumped, and the loop-exit flags are regenerated from
//     the saved operand pair so the flags after the instruction are the flags
//     of the *final* compare — the hardware's observable result.
//   * Non-REP pointer bumps use LEA so the single-op forms do not clobber the
//     compare's flags (x86 string primitives without REP leave rflags alone
//     except for the compare itself).
// ==============================================================================

use super::{SCRATCH, SCRATCH2};
use crate::vm::bytecode::*;
use anyhow::Result;
use iced_x86::Instruction;

/// Extra lifter temporaries (vregs 18/19; 16/17 are SCRATCH/SCRATCH2).
const TMP3: u8 = 18;
const TMP4: u8 = 19;

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
/// The single-op form bumps rdi via LEA so the caller's flags stay untouched
/// (plain STOS writes no rflags).
pub(super) fn lift_stos(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let n = stos_lods_width(inst.code());
    let (_, store, _) = width_ops(n);
    let rdi = 7u8; let rcx = 1u8;
    let single = |b: &mut BytecodeBuilder| {
        b.mem_store_a(store, rdi, 0);
        b.lea(rdi, rdi, ADDR_NO_INDEX, 0, n as i32);
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
        b.lea(rsi, rsi, ADDR_NO_INDEX, 0, n as i32);
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
        b.lea(rsi, rsi, ADDR_NO_INDEX, 0, n as i32);
        b.lea(rdi, rdi, ADDR_NO_INDEX, 0, n as i32);
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

/// The width-matched SUB used for SCAS/CMPS compares (32-bit, or 64-bit for
/// qword operands). Narrow (8/16-bit) compares run the 32-bit SUB on
/// pre-masked operands: ZF is exact, CF/SF/OF are the 32-bit approximations
/// (the pre-existing model).
fn cmp_sub(b: &mut BytecodeBuilder, n: u64, lhs: u8, rhs: u8) {
    if is64(n) {
        b.binop_r_r64(OP_SUB_R_R64, lhs, rhs);
    } else {
        b.binop_r_r(OP_SUB_R_R, lhs, rhs);
    }
}

/// Emit the operand pair for a REP SCAS/CMPS loop: after this closure the
/// masked compare operands live in (TMP3 = lhs, TMP4 = rhs) and STATE_FLAGS
/// holds the real compare result (lhs - rhs).
///   * SCAS: lhs = accumulator (vreg0, masked), rhs = [rdi]
///   * CMPS: lhs = [rsi]  (masked), rhs = [rdi]
fn rep_cmp_operands(b: &mut BytecodeBuilder, n: u64, is_cmps: bool) {
    let rsi = 6u8; let rdi = 7u8;
    let (load, _, mask) = width_ops(n);
    // The width loads zero-extend, so memory operands are already masked; the
    // accumulator (vreg0) must be masked down to the element width for SCAS.
    if is_cmps {
        b.mem_load_a(load, TMP3, rsi);
    } else if is64(n) {
        b.mov_r_r64(TMP3, 0);
    } else {
        b.mov_r_r(TMP3, 0);
        if mask != 0xFFFF_FFFF { b.binop_r_imm32(OP_AND_R_IMM32, TMP3, mask); }
    }
    b.mem_load_a(load, TMP4, rdi);
    // Compare through a scratch copy: SUB clobbers its destination, and TMP3
    // must survive so REP loops can regenerate the final compare's exact
    // flags on exit (`fix_flags`).
    if is64(n) { b.mov_r_r64(SCRATCH, TMP3); } else { b.mov_r_r(SCRATCH, TMP3); }
    cmp_sub(b, n, SCRATCH, TMP4);
}

/// SCAS: flags = AL/AX/EAX/RAX - [rdi]; rdi += n. REPE/REPNE honour ZF stop.
pub(super) fn lift_scas(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let n = scas_cmps_width(inst.code());
    let rdi = 7u8; let rcx = 1u8;
    if !has_any_rep(inst) {
        rep_cmp_operands(b, n, false);
        b.lea(rdi, rdi, ADDR_NO_INDEX, 0, n as i32); // LEA: no flag clobber
        return Ok(());
    }
    let exit_cond = rep_exit_cond(inst); // REP SCAS/CMPS is always REPE/REPNE
    let loop_lbl = b.new_label();
    let done = b.new_label();
    let fix_flags = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    rep_cmp_operands(b, n, false);
    // Capture the ZF-stop decision BEFORE any flag-clobbering bookkeeping.
    b.setcc(SCRATCH2, exit_cond.unwrap_or(COND_JNE));
    b.lea(rdi, rdi, ADDR_NO_INDEX, 0, n as i32);
    b.lea(rcx, rcx, ADDR_NO_INDEX, 0, -1);
    b.test_r_r32(SCRATCH2, SCRATCH2);
    b.jcc8(COND_JNE, fix_flags);
    b.jmp8(loop_lbl);
    // Restore the final compare's exact flags on exit (rep count consumed,
    // pointer advanced — the hardware result).
    b.mark_label(fix_flags);
    cmp_sub(b, n, TMP3, TMP4);
    b.mark_label(done);
    Ok(())
}

/// CMPS: flags = [rsi] - [rdi]; rsi += n; rdi += n. REPE/REPNE honour ZF stop.
pub(super) fn lift_cmps(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let n = scas_cmps_width(inst.code());
    let rsi = 6u8; let rdi = 7u8; let rcx = 1u8;
    if !has_any_rep(inst) {
        rep_cmp_operands(b, n, true);
        b.lea(rsi, rsi, ADDR_NO_INDEX, 0, n as i32);
        b.lea(rdi, rdi, ADDR_NO_INDEX, 0, n as i32);
        return Ok(());
    }
    let exit_cond = rep_exit_cond(inst);
    let loop_lbl = b.new_label();
    let done = b.new_label();
    let fix_flags = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    rep_cmp_operands(b, n, true);
    b.setcc(SCRATCH2, exit_cond.unwrap_or(COND_JNE));
    b.lea(rsi, rsi, ADDR_NO_INDEX, 0, n as i32);
    b.lea(rdi, rdi, ADDR_NO_INDEX, 0, n as i32);
    b.lea(rcx, rcx, ADDR_NO_INDEX, 0, -1);
    b.test_r_r32(SCRATCH2, SCRATCH2);
    b.jcc8(COND_JNE, fix_flags);
    b.jmp8(loop_lbl);
    b.mark_label(fix_flags);
    cmp_sub(b, n, TMP3, TMP4);
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
