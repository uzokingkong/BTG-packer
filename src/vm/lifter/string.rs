// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: string ops
// ==============================================================================
// MOVS / STOS / LODS / SCAS / CMPS, all widths (byte/word/dword/qword), with and
// without the REP prefix. REP forms are lowered to explicit VM loops. STOS/MOVS/
// LODS use a plain count-down loop; SCAS/CMPS honour the REPE/REPNE stop
// condition (ZF). The accumulator for STOS/LODS/SCAS is vreg0 (RAX/EAX/AX/AL).
// Shared infra (`SCRATCH`, `SCRATCH2`) lives in `super`.
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
//
// v65 — Direction Flag (DF): string ops bump the pointer by +n when DF=0 and
// by -n when DF=1. DF lives in STATE_FLAGS bit 10 (F_DF), changed only by the
// lifted CLD/STD bytecodes. Because DF is loop-invariant, the bump direction is
// selected ONCE per string op: `emit_dir_delta` computes a signed delta (±n)
// into a scratch vreg from the DF bit, and every pointer bump becomes an LEA by
// that register (LEA stays flag-neutral, so the SCAS/CMPS compare flags and the
// non-REP preserved rflags are unaffected).
// ==============================================================================

use super::{SCRATCH, SCRATCH2};
use crate::vm::bytecode::*;
use anyhow::Result;
use iced_x86::Instruction;

/// Extra lifter temporaries (vregs 18/19; 16/17 are SCRATCH/SCRATCH2).
const TMP3: u8 = 18;
const TMP4: u8 = 19;

/// Emit code to compute a signed element delta into `delta`:
///   delta = +n  (DF clear — forward)   |   delta = -n  (DF set — backward)
/// `flags_tmp` is a scratch vreg clobbered by the DF test. STATE_FLAGS is
/// clobbered by the test (callers that must preserve flags save/restore around
/// this; SCAS/CMPS re-set STATE_FLAGS with the compare afterwards).
fn emit_dir_delta(b: &mut BytecodeBuilder, flags_tmp: u8, delta: u8, n: u64) {
    let fwd = b.new_label();
    let done = b.new_label();
    b.get_flags(flags_tmp);
    b.test_r_imm32(flags_tmp, F_DF as u32); // ZF = (DF == 0)
    b.jcc8(COND_JE, fwd);                    // DF clear → forward (+n)
    b.mov_r_imm64(delta, (-(n as i64)) as u64); // DF set → backward (-n)
    b.jmp8(done);
    b.mark_label(fwd);
    b.mov_r_imm64(delta, n as u64);
    b.mark_label(done);
}

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

/// STOS: [rdi] = AL/AX/EAX/RAX (vreg0); rdi += DF ? -n : n. REP → count-down loop.
/// The single-op form bumps rdi via LEA so the caller's flags stay untouched
/// (plain STOS writes no rflags). REP STOS likewise writes no rflags — the loop
/// control (TEST/DEC) would clobber them, so we save/restore STATE_FLAGS
/// around the loop (v64; x86 `rep stosb` leaves RFLAGS unchanged).
///
/// v65: the bump direction honours DF. `emit_dir_delta` computes a signed
/// element delta (±n) into TMP4 from STATE_FLAGS once, and every bump becomes
/// `lea(rdi, rdi, TMP4, 0, 0)` (LEA is flag-neutral).
pub(super) fn lift_stos(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let n = stos_lods_width(inst.code());
    let (_, store, _) = width_ops(n);
    let rdi = 7u8; let rcx = 1u8;
    let single = |b: &mut BytecodeBuilder, delta: u8| {
        b.mem_store_a(store, rdi, 0);
        b.lea(rdi, rdi, delta, 0, 0);
    };
    if !has_any_rep(inst) {
        // Preserve the caller's flags: the delta computation clobbers STATE_FLAGS.
        b.get_flags(TMP3);
        emit_dir_delta(b, SCRATCH2, TMP4, n);
        b.set_flags(TMP3);
        single(b, TMP4);
        return Ok(());
    }
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.get_flags(TMP3); // REP string ops는 RFLAGS를 변경하지 않는다 — 진입 시 저장
    emit_dir_delta(b, SCRATCH2, TMP4, n);
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    single(b, TMP4);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    b.set_flags(TMP3);
    Ok(())
}

/// LODS: AL/AX/EAX/RAX (vreg0) = [rsi]; rsi += DF ? -n : n. REP → count-down loop.
/// Note: x86 LODSB only writes AL; we zero-extend into vreg0 for simplicity.
/// REP LODS leaves RFLAGS unchanged — saved/restored around the loop (v64).
pub(super) fn lift_lods(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let n = stos_lods_width(inst.code());
    let (load, _, _) = width_ops(n);
    let rsi = 6u8; let rcx = 1u8;
    let single = |b: &mut BytecodeBuilder, delta: u8| {
        b.mem_load_a(load, 0, rsi);
        b.lea(rsi, rsi, delta, 0, 0);
    };
    if !has_any_rep(inst) {
        b.get_flags(TMP3);
        emit_dir_delta(b, SCRATCH2, TMP4, n);
        b.set_flags(TMP3);
        single(b, TMP4);
        return Ok(());
    }
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.get_flags(TMP3); // REP string ops는 RFLAGS를 변경하지 않는다 — 진입 시 저장
    emit_dir_delta(b, SCRATCH2, TMP4, n);
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    single(b, TMP4);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    b.set_flags(TMP3);
    Ok(())
}

/// MOVS: [rdi] = [rsi]; rsi += ±n; rdi += ±n. REP → count-down loop.
/// REP MOVS leaves RFLAGS unchanged — saved/restored around the loop (v64).
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
    let single = |b: &mut BytecodeBuilder, delta: u8| {
        b.mem_load_a(load, SCRATCH, rsi);
        b.mem_store_a(store, rdi, SCRATCH);
        b.lea(rsi, rsi, delta, 0, 0);
        b.lea(rdi, rdi, delta, 0, 0);
    };
    if !has_any_rep(inst) {
        b.get_flags(TMP3);
        emit_dir_delta(b, SCRATCH2, TMP4, n);
        b.set_flags(TMP3);
        single(b, TMP4);
        return Ok(());
    }
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.get_flags(TMP3); // REP string ops는 RFLAGS를 변경하지 않는다 — 진입 시 저장
    emit_dir_delta(b, SCRATCH2, TMP4, n);
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    single(b, TMP4);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    b.set_flags(TMP3);
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

/// SCAS: flags = AL/AX/EAX/RAX - [rdi]; rdi += DF ? -n : n. REPE/REPNE honour
/// ZF stop. v64: REPE/REPNE SCAS 의 종료 플래그는 항상 **마지막 비교**의 플래그이며,
/// count==0 이면 아무 것도 하지 않고 RFLAGS 를 유지한다 (x86). 기존 코드는
/// 루프 제어의 TEST/DEC 가 플래그를 덮어쓰고, 0회·카운트 소진 경로에서 마지막
/// 비교 플래그 대신 TEST 플래그를 남겼다.
///
/// v65: the SCAS/CMPS loop bodies use all four scratch vregs (TMP3=lhs,
/// TMP4=rhs, SCRATCH=cmp copy, SCRATCH2=setcc capture), so instead of a delta
/// register the direction is baked into two loop variants selected ONCE at
/// entry (DF is loop-invariant — only the lifted CLD/STD change it).
pub(super) fn lift_scas(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let n = scas_cmps_width(inst.code());
    let rdi = 7u8; let rcx = 1u8;
    if !has_any_rep(inst) {
        // Direction via a delta vreg before the compare; the compare's flags are
        // the instruction result and the LEA bump (by delta) does not clobber them.
        emit_dir_delta(b, TMP4, SCRATCH2, n);
        rep_cmp_operands(b, n, false);
        b.lea(rdi, rdi, SCRATCH2, 0, 0); // LEA: no flag clobber
        return Ok(());
    }
    let exit_cond = rep_exit_cond(inst); // REP SCAS/CMPS is always REPE/REPNE
    let fwd_loop = b.new_label();
    let bwd_loop = b.new_label();
    let done = b.new_label();
    let fix_flags = b.new_label();
    let zero_exit = b.new_label();
    // 0회 비교(진입 시 RCX==0) 경로에서만 복원할 진입 플래그를 TMP4 에 저장.
    // (반복이 한 번이라도 시작되면 rep_cmp_operands 가 TMP4 를 rhs 로 덮어쓴다.)
    b.get_flags(TMP4);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, zero_exit);
    // DF dispatch — test the saved entry flags (TMP4 still holds them here).
    b.test_r_imm32(TMP4, F_DF as u32); // ZF = (DF == 0)
    b.jcc8(COND_JNE, bwd_loop);        // DF set → backward
    b.mark_label(fwd_loop);
    rep_cmp_operands(b, n, false);
    // Capture the ZF-stop decision BEFORE any flag-clobbering bookkeeping.
    b.setcc(SCRATCH2, exit_cond.unwrap_or(COND_JNE));
    b.lea(rdi, rdi, ADDR_NO_INDEX, 0, n as i32);
    b.lea(rcx, rcx, ADDR_NO_INDEX, 0, -1);
    // stop 조건이면 → fix_flags; 아니면 카운트가 남았는지 재확인해 반복.
    b.test_r_r32(SCRATCH2, SCRATCH2);
    b.jcc8(COND_JNE, fix_flags);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JNE, fwd_loop);
    b.jmp8(fix_flags); // count exhausted
    b.mark_label(bwd_loop);
    rep_cmp_operands(b, n, false);
    b.setcc(SCRATCH2, exit_cond.unwrap_or(COND_JNE));
    b.lea(rdi, rdi, ADDR_NO_INDEX, 0, -(n as i32));
    b.lea(rcx, rcx, ADDR_NO_INDEX, 0, -1);
    b.test_r_r32(SCRATCH2, SCRATCH2);
    b.jcc8(COND_JNE, fix_flags);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JNE, bwd_loop);
    // 카운트 소진(마지막 비교 플래그 유지) → fix_flags 로 합류.
    // Restore the final compare's exact flags on exit (rep count consumed,
    // pointer advanced — the hardware result).
    b.mark_label(fix_flags);
    cmp_sub(b, n, TMP3, TMP4);
    b.jmp8(done);
    // 0회 비교 → 진입 시점 RFLAGS 복원.
    b.mark_label(zero_exit);
    b.set_flags(TMP4);
    b.mark_label(done);
    Ok(())
}

/// CMPS: flags = [rsi] - [rdi]; rsi += ±n; rdi += ±n. REPE/REPNE honour ZF stop.
/// v64: 위 SCAS 와 동일한 종료 플래그/0-count 정합.
pub(super) fn lift_cmps(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let n = scas_cmps_width(inst.code());
    let rsi = 6u8; let rdi = 7u8; let rcx = 1u8;
    if !has_any_rep(inst) {
        emit_dir_delta(b, TMP4, SCRATCH2, n);
        rep_cmp_operands(b, n, true);
        b.lea(rsi, rsi, SCRATCH2, 0, 0);
        b.lea(rdi, rdi, SCRATCH2, 0, 0);
        return Ok(());
    }
    let exit_cond = rep_exit_cond(inst);
    let fwd_loop = b.new_label();
    let bwd_loop = b.new_label();
    let done = b.new_label();
    let fix_flags = b.new_label();
    let zero_exit = b.new_label();
    // 0회 비교 경로에서만 복원할 진입 플래그를 TMP4 에 저장.
    b.get_flags(TMP4);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, zero_exit);
    b.test_r_imm32(TMP4, F_DF as u32); // ZF = (DF == 0)
    b.jcc8(COND_JNE, bwd_loop);        // DF set → backward
    b.mark_label(fwd_loop);
    rep_cmp_operands(b, n, true);
    b.setcc(SCRATCH2, exit_cond.unwrap_or(COND_JNE));
    b.lea(rsi, rsi, ADDR_NO_INDEX, 0, n as i32);
    b.lea(rdi, rdi, ADDR_NO_INDEX, 0, n as i32);
    b.lea(rcx, rcx, ADDR_NO_INDEX, 0, -1);
    b.test_r_r32(SCRATCH2, SCRATCH2);
    b.jcc8(COND_JNE, fix_flags);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JNE, fwd_loop);
    b.jmp8(fix_flags);
    b.mark_label(bwd_loop);
    rep_cmp_operands(b, n, true);
    b.setcc(SCRATCH2, exit_cond.unwrap_or(COND_JNE));
    b.lea(rsi, rsi, ADDR_NO_INDEX, 0, -(n as i32));
    b.lea(rdi, rdi, ADDR_NO_INDEX, 0, -(n as i32));
    b.lea(rcx, rcx, ADDR_NO_INDEX, 0, -1);
    b.test_r_r32(SCRATCH2, SCRATCH2);
    b.jcc8(COND_JNE, fix_flags);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JNE, bwd_loop);
    // 카운트 소진 → 마지막 비교 플래그.
    b.mark_label(fix_flags);
    cmp_sub(b, n, TMP3, TMP4);
    b.jmp8(done);
    // 0회 비교 → 진입 시점 RFLAGS 복원.
    b.mark_label(zero_exit);
    b.set_flags(TMP4);
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
