// ==============================================================================
// BTG v3 - VM Handler Codegen: branch family
// ==============================================================================
// Control-flow handlers: JMP8/JMP32, JB8, JCC8/JCC32 (full conditional dispatch),
// SETCC (v50), and HALT (frame restore + retnq). Shared helpers (`hdr`, `m`,
// `vreg`, `cap_flags`, `state_flags_mem`, `jmp_disp`, `XMM_SAVE`, ...) and the
// `Cl` label enum live in `super` (mod.rs).
// ==============================================================================

use super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

// ── 0x11 JMP8 rel ───────────────────────────────────────────────────────────
pub(super) fn emit_jmp8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_JMP8,
        vec![
            Instruction::with2(
                Code::Movsx_r64_rm8,
                Register::RAX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::RAX).unwrap(),
        ],
    );
}

// ── 0x12 JB8 rel (uses CF flag slot) ────────────────────────────────────────
pub(super) fn emit_jb8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            m(Register::R8, STATE_FLAGS as i32),
        )
        .unwrap(),
        Some(Cl::Handler(OP_JB8)),
    ));
    seq.push((
        Instruction::with2(Code::Test_rm8_imm8, Register::AL, 1).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
        Some(Cl::JbTaken),
    ));
    seq.push((
        Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(),
        None,
    ));
    emit_dispatch(seq, None);
    seq.push((
        Instruction::with2(
            Code::Movsx_r64_rm8,
            Register::RAX,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        Some(Cl::JbTaken),
    ));
    seq.push((
        Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::RAX).unwrap(),
        None,
    ));
    emit_dispatch(seq, None);
}

// ── 0x16 JCC8 cond, rel8 (M1: full x86 conditional-branch model) ──────────
// Evaluates the condition against the VM STATE_FLAGS slot and branches.
// The cond byte selects one of 14 sub-blocks; each builds the boolean in
// registers (no popfq/pushfq), then jumps to the shared taken/not epilogues.
// M5 (v30): JCC32 shares the JCC8 cond-dispatch (set up rdx=taken-ip / r9=
// fallthrough with a 4-byte rel, then jump into the shared dispatch chain).
pub(super) fn emit_jcc(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    // (cond_id, native Jcc to emit for "taken" when the flag bit is set)
    // Each simple condition = test a single flag bit.
    let simple: [(u8, Code, u64, bool); 10] = [
        // cond, branch-taken jcc, flag bit, bit-set-means-taken
        (COND_JE, Code::Jne_rel32_64, F_ZF, true),
        (COND_JNE, Code::Je_rel32_64, F_ZF, false),
        (COND_JB, Code::Jne_rel32_64, F_CF, true),
        (COND_JAE, Code::Je_rel32_64, F_CF, false),
        (COND_JS, Code::Jne_rel32_64, F_SF, true),
        (COND_JNS, Code::Je_rel32_64, F_SF, false),
        (COND_JO, Code::Jne_rel32_64, F_OF, true),
        (COND_JNO, Code::Je_rel32_64, F_OF, false),
        (COND_JP, Code::Jne_rel32_64, F_PF, true),
        (COND_JNP, Code::Je_rel32_64, F_PF, false),
    ];
    let signed: [(u8, bool, bool); 4] = [
        // (cond, test_zf_or_delta, taken_when_zero)
        (COND_JG, true, true),   // JG:  test (ZF||delta), taken when ==0
        (COND_JGE, false, true), // JGE: test delta,        taken when ==0
        (COND_JL, false, false), // JL:  test delta,        taken when !=0
        (COND_JLE, true, false), // JLE: test (ZF||delta),  taken when !=0
    ];
    // delta = SF ^ OF ; zf = ZF flag.
    // We build r11 = (ZF || delta) as a 0/1-style non-zero value, and
    // rdx = delta as non-zero/zero. Then branch accordingly.

    // ── M5 (v30): rel32 branch handlers ────────────────────────────────
    // JCC32 shares the JCC8 cond-dispatch: set up rdx=taken-ip/r9=fallthrough
    // with a 4-byte rel, then jump into the shared dispatch chain.
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::ECX,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        Some(Cl::Handler(OP_JCC32)),
    ));
    seq.push((
        Instruction::with2(Code::Movsxd_r64_rm32, Register::RDX, m(Register::R9, 1)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_r64, Register::RDX, Register::R9).unwrap(),
        None,
    ));
    seq.push((jmp_disp(), Some(Cl::JccDispatch)));
    // JMP32 rel32: r9 += 4 + rel
    hdr(
        seq,
        OP_JMP32,
        vec![
            Instruction::with2(
                Code::Movsxd_r64_rm32,
                Register::RAX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 4).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::RAX).unwrap(),
        ],
    );
    // CALL32 rel32: push r9+4 (bytecode return IP) onto the VM return-IP stack
    // (STATE_CALL_SP); r9 += 4 + rel. (Two-stack model — see CALL8.)
    {
        seq.push((
            Instruction::with2(
                Code::Movsxd_r64_rm32,
                Register::RAX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Some(Cl::Handler(OP_CALL32)),
        ));
        seq.push((
            Instruction::with2(
                Code::Lea_r64_m,
                Register::RDX,
                MemoryOperand::with_base_displ(Register::R9, 4),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R11,
                m(Register::R8, STATE_CALL_SP as i32),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Sub_rm64_imm32, Register::R11, 8).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm64_r64,
                m(Register::R8, STATE_CALL_SP as i32),
                Register::R11,
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                m(Register::R8, STATE_PTR_CALL_STACK as i32),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::R11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base(Register::RCX),
                Register::RDX,
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 4).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::RAX).unwrap(),
            None,
        ));
        emit_dispatch(seq, None);
    }

    // Handler entry: r9 -> (cond, rel)
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::ECX,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        Some(Cl::Handler(OP_JCC8)),
    ));
    // rdx = sign-extended rel; r9 += 2 -> fallthrough ip
    seq.push((
        Instruction::with2(Code::Movsx_r64_rm8, Register::RDX, m(Register::R9, 1)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        None,
    ));
    // taken ip = fallthrough + rel  (rdx = rel now, add fallthrough)
    seq.push((
        Instruction::with2(Code::Add_rm64_r64, Register::RDX, Register::R9).unwrap(),
        None,
    ));

    // cond dispatch chain: cmp ecx,cond ; je block
    let unsigned: [(u8, Code, bool); 2] = [
        (COND_JA, Code::Je_rel32_64, false),  // taken when (CF|ZF)==0
        (COND_JBE, Code::Jne_rel32_64, true), // taken when (CF|ZF)!=0
    ];
    let dispatch_conds = simple
        .iter()
        .map(|(c, ..)| *c)
        .chain(signed.iter().map(|(c, ..)| *c))
        .chain(unsigned.iter().map(|(c, ..)| *c));
    let conds: Vec<u8> = dispatch_conds.collect();
    for (i, c) in conds.iter().enumerate() {
        let lbl = if i == 0 { Some(Cl::JccDispatch) } else { None };
        seq.push((
            Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, *c as i32).unwrap(),
            lbl,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Cl::JccBlk(*c)),
        ));
    }
    // unknown cond: treat as not taken (jump to not-taken epilogue)
    seq.push((jmp_disp(), Some(Cl::JccNotTaken)));

    // simple single-bit blocks
    for (cond, cc, bit, _) in &simple {
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(),
            Some(Cl::JccBlk(*cond)),
        ));
        seq.push((
            Instruction::with2(Code::Test_rm64_imm32, Register::R11, *bit as i32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(*cc, 0).unwrap(),
            Some(Cl::JccTaken),
        ));
        seq.push((jmp_disp(), Some(Cl::JccNotTaken)));
    }

    // signed blocks (JG/JGE/JL/JLE). delta = SF^OF ; zf = ZF flag.
    // RAX ends with the tested boolean; branch per config.
    for (cond, test_zf_or_delta, taken_when_zero) in &signed {
        // r11 = flags ; rax = SF
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(),
            Some(Cl::JccBlk(*cond)),
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 7).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Shr_rm64_CL, Register::RAX, Register::CL).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).unwrap(),
            None,
        ));
        // rsi = OF
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Shr_rm64_CL, Register::RSI, Register::CL).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::And_rm64_imm32, Register::RSI, 1).unwrap(),
            None,
        ));
        // rax = delta = SF^OF
        seq.push((
            Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RSI).unwrap(),
            None,
        ));
        // rsi = ZF (nonzero iff ZF set)
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::And_rm64_imm32, Register::RSI, F_ZF as i32).unwrap(),
            None,
        ));
        if *test_zf_or_delta {
            // test (ZF||delta): OR ZF into rax(delta)
            seq.push((
                Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RSI).unwrap(),
                None,
            ));
        }
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
            None,
        ));
        let cc = if *taken_when_zero {
            Code::Je_rel32_64
        } else {
            Code::Jne_rel32_64
        };
        seq.push((Instruction::with_branch(cc, 0).unwrap(), Some(Cl::JccTaken)));
        seq.push((jmp_disp(), Some(Cl::JccNotTaken)));
    }

    // unsigned combined conditions: JA (cond 14) and JBE (cond 15).
    // JA = !CF && !ZF  (above); JBE = CF || ZF (below/equal).
    // Build RAX = CF|ZF as 0/1, then branch taken iff (CF|ZF) is zero (JA)
    // or nonzero (JBE).
    for (cond, cc, _nonzero) in &unsigned {
        // r11 = flags ; rax = CF (bit 0)
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(),
            Some(Cl::JccBlk(*cond)),
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, F_CF as i32).unwrap(),
            None,
        ));
        // rsi = ZF (bit 6), OR into rax -> rax = CF|ZF
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::And_rm64_imm32, Register::RSI, F_ZF as i32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RSI).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(*cc, 0).unwrap(),
            Some(Cl::JccTaken),
        ));
        seq.push((jmp_disp(), Some(Cl::JccNotTaken)));
    }

    // taken epilogue: r9 = taken ip (rdx holds it)
    seq.push((
        Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RDX).unwrap(),
        Some(Cl::JccTaken),
    ));
    emit_dispatch(seq, None);
    // not-taken epilogue: r9 already = fallthrough (label on a non-branch)
    seq.push((
        Instruction::with2(Code::Xor_rm64_r64, Register::R11, Register::R11).unwrap(),
        Some(Cl::JccNotTaken),
    ));
    emit_dispatch(seq, None);
}

// ── v50: 0x89 SETCC (dst_vreg, cond) — writes ONLY the low byte, preserves
// STATE_FLAGS (x86 setcc is a partial-register write that does not modify
// flags). Evaluates cond against STATE_FLAGS, producing a 0/1, then merges
// it into the low byte of the destination vreg. Never writes STATE_FLAGS,
// so a following cmovcc/sbb reads the flags the setcc's source cmp set.
pub(super) fn emit_setcc(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    // entry: edi = dst vreg (preserved across cond blocks), edx = cond; r9 += 2
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EDI,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        Some(Cl::Handler(OP_SETCC)),
    ));
    seq.push((
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        None,
    ));

    // cond dispatch chain: cmp edx,cond ; je SetccBlk(cond)
    let simple: [(u8, Code, u64, bool); 10] = [
        (COND_JE, Code::Setne_rm8, F_ZF, true),
        (COND_JNE, Code::Sete_rm8, F_ZF, false),
        (COND_JB, Code::Setne_rm8, F_CF, true),
        (COND_JAE, Code::Sete_rm8, F_CF, false),
        (COND_JS, Code::Setne_rm8, F_SF, true),
        (COND_JNS, Code::Sete_rm8, F_SF, false),
        (COND_JO, Code::Setne_rm8, F_OF, true),
        (COND_JNO, Code::Sete_rm8, F_OF, false),
        (COND_JP, Code::Setne_rm8, F_PF, true),
        (COND_JNP, Code::Sete_rm8, F_PF, false),
    ];
    let signed: [(u8, bool, bool); 4] = [
        (COND_JG, true, true),   // test (ZF||delta), taken when ==0
        (COND_JGE, false, true), // test delta,        taken when ==0
        (COND_JL, false, false), // test delta,        taken when !=0
        (COND_JLE, true, false), // test (ZF||delta),  taken when !=0
    ];
    let unsigned: [(u8, Code); 2] = [
        (COND_JA, Code::Sete_rm8),   // taken when (CF|ZF)==0
        (COND_JBE, Code::Setne_rm8), // taken when (CF|ZF)!=0
    ];
    let dispatch_conds: Vec<u8> = simple
        .iter()
        .map(|(c, ..)| *c)
        .chain(signed.iter().map(|(c, ..)| *c))
        .chain(unsigned.iter().map(|(c, ..)| *c))
        .collect();
    for (i, c) in dispatch_conds.iter().enumerate() {
        let lbl = if i == 0 {
            Some(Cl::SetccDispatch)
        } else {
            None
        };
        seq.push((
            Instruction::with2(Code::Cmp_rm32_imm32, Register::EDX, *c as i32).unwrap(),
            lbl,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Cl::SetccBlk(*c)),
        ));
    }
    // unknown cond -> treat as set to 0, merge
    seq.push((
        Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RAX).unwrap(),
        Some(Cl::SetccBlk(0xFF)),
    ));
    seq.push((jmp_disp(), Some(Cl::SetccMerge)));

    // simple single-bit blocks: load flags, test bit, set AL via setcc
    for (cond, cc, bit, _set) in &simple {
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(),
            Some(Cl::SetccBlk(*cond)),
        ));
        seq.push((
            Instruction::with2(Code::Test_rm64_imm32, Register::R11, *bit as i32).unwrap(),
            None,
        ));
        seq.push((Instruction::with1(*cc, Register::AL).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::SetccMerge)));
    }

    // signed blocks: delta = SF^OF ; optionally OR ZF ; test -> set AL
    for (cond, test_zf_or_delta, taken_when_zero) in &signed {
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(),
            Some(Cl::SetccBlk(*cond)),
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 7).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Shr_rm64_CL, Register::RAX, Register::CL).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Shr_rm64_CL, Register::RSI, Register::CL).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::And_rm64_imm32, Register::RSI, 1).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RSI).unwrap(),
            None,
        )); // rax = delta
        if *test_zf_or_delta {
            seq.push((
                Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::And_rm64_imm32, Register::RSI, F_ZF as i32).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RSI).unwrap(),
                None,
            ));
        }
        let cc = if *taken_when_zero {
            Code::Sete_rm8
        } else {
            Code::Setne_rm8
        };
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
            None,
        ));
        seq.push((Instruction::with1(cc, Register::AL).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::SetccMerge)));
    }

    // unsigned combined: rax = CF|ZF (0/1), then set AL per JA/JBE
    for (cond, cc) in &unsigned {
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(),
            Some(Cl::SetccBlk(*cond)),
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, F_CF as i32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::And_rm64_imm32, Register::RSI, F_ZF as i32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RSI).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
            None,
        ));
        seq.push((Instruction::with1(*cc, Register::AL).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::SetccMerge)));
    }

    // merge: dst = (dst & ~0xFF) | (AL & 1). STATE_FLAGS untouched (setcc must
    // not modify flags). rdi (value) still holds the dst vreg index.
    seq.push((
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap(),
        Some(Cl::SetccMerge),
    ));
    // [r8 + rdi*8] = dst vreg (rdi holds the *vreg index value*, not the reg)
    seq.push((
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::R11,
            MemoryOperand::with_base_index_scale(Register::R8, Register::RDI, 8),
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::And_rm64_imm32, Register::R11, !0xFFu32 as i32).unwrap(),
        None,
    )); // clear low byte
    seq.push((
        Instruction::with2(Code::Or_rm64_r64, Register::R11, Register::RAX).unwrap(),
        None,
    )); // OR in boolean
    seq.push((
        Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base_index_scale(Register::R8, Register::RDI, 8),
            Register::R11,
        )
        .unwrap(),
        None,
    ));
    emit_dispatch(seq, None);
}

// ── 0x13 HALT: restore + ret ───────────────────────────────────────────────
// Pop in the exact reverse of the entry pushes (see entry stub). This restores
// the caller's callee-saved GPRs (incl. RBP) before retnq.
pub(super) fn emit_halt(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    seq.push((
        Instruction::with1(Code::Pop_r64, Register::R12).unwrap(),
        Some(Cl::Handler(OP_HALT)),
    ));
    for r in [Register::R13, Register::R14, Register::R15] {
        seq.push((Instruction::with1(Code::Pop_r64, r).unwrap(), None));
    }
    seq.push((
        Instruction::with1(Code::Pop_r64, Register::R11).unwrap(),
        None,
    ));
    for r in [
        Register::R10,
        Register::R9,
        Register::R8,
        Register::RDI,
        Register::RSI,
        Register::RBP,
        Register::RBX,
        Register::RDX,
        Register::RCX,
        Register::RAX,
    ] {
        seq.push((Instruction::with1(Code::Pop_r64, r).unwrap(), None));
    }
    // Bug-6 fix: restore the Win64 callee-saved XMM6..XMM15 saved at entry
    // (160-byte block below the GPR saves), then retract the frame.
    for (i, xr) in XMM_SAVE.iter().enumerate() {
        seq.push((
            Instruction::with2(
                Code::Movdqu_xmm_xmmm128,
                *xr,
                MemoryOperand::with_base_displ(Register::RSP, (i * 16) as i64),
            )
            .unwrap(),
            None,
        ));
    }
    seq.push((
        Instruction::with2(Code::Add_rm64_imm32, Register::RSP, 0xA0).unwrap(),
        None,
    ));
    // Win64 callers assume DF is clear. A guest STD must never leak into the
    // host after the VM returns (it can corrupt Rust/C memcpy-style routines).
    // The guest value remains in STATE_FLAGS; this only restores the host ABI.
    seq.push((Instruction::with(Code::Cld), None));
    seq.push((Instruction::with(Code::Retnq), None));
}
