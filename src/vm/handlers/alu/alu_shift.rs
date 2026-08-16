// ==============================================================================
// BTG v3 - VM Handler Codegen: shift family - split from alu.rs
// ==============================================================================
// SHL/SHR/SAR (imm8 & CL, 32/64-bit) and SHLD/SHRD (imm8 & CL, 32/64-bit).
// Shared helpers (`hdr`, `m`, `vreg`, `cap_flags_shift`, ...) live in
// `super::super` (handlers/mod.rs).
//
// v64: shl/shr/sar count==0 는 x86 RFLAGS 를 그대로 유지한다. 각 shift 핸들러는
//      count 를 test 한 뒤 0 이면 `cap_flags_shift`를 건너뛴다(기존엔 count==0
//      에도 디스패처/전단 `and` 명령이 세운 플래그를 capture해 STATE_FLAGS 를
//      덮어썼다 — 참조·폴리와의 차등 불일치 및 잘못된 조건 분기 원인).
// ==============================================================================

use super::super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

/// `hdr`와 동일하지만 라벨(`Option<Cl>`)이 포함된 body 를 받는다. 첫 명령에
/// `Cl::Handler(op)`를 붙이고 나머지를 그대로 이어붙인 뒤 threaded-dispatch
/// epilogue 를 붙인다. (shift count==0 의 조건부 플래그 캡처용.)
fn hdr_labeled(seq: &mut Vec<(Instruction, Option<Cl>)>, op: u8, body: Vec<(Instruction, Option<Cl>)>) {
    let mut it = body.into_iter();
    seq.push((it.next().unwrap().0, Some(Cl::Handler(op))));
    seq.extend(it);
    emit_dispatch(seq, None);
}

// ── M2 (v22) 0x20-0x22 shifts by imm8 (32-bit) ───────────────────────────────
pub(crate) fn emit_shift_imm8_32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_SHL_R_IMM8, Code::Shl_rm32_CL),
        (OP_SHR_R_IMM8, Code::Shr_rm32_CL),
        (OP_SAR_R_IMM8, Code::Sar_rm32_CL),
    ] {
        let mut body: Vec<(Instruction, Option<Cl>)> = vec![
            (Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(), None),
            (Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::ECX).unwrap(), None),
            (Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::R11)).unwrap(), None),
            (Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(), None),
            (Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(), None),
            // interp 와 동일하게 32-bit shift 카운트는 하위 5비트만 사용 (count==0
            // 감지도 이 마스크된 값 기준 — imm8=32,64,... 도 count 0 으로 취급).
            (Instruction::with2(Code::And_rm32_imm32, Register::ECX, 31).unwrap(), None),
            // count==0 → RFLAGS 유지. count 테스트를 shift *이전*에 수행한다.
            // (shift 이후에 test 하면 shift 가 세운 실제 플래그가 덮어써진다.)
            (Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX).unwrap(), None),
            (Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Cl::ShiftSkip(op))),
            (Instruction::with2(code, Register::EAX, Register::CL).unwrap(), None),
            (Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(), None),
        ];
        body.extend(cap_flags_shift().into_iter().map(|i| (i, None)));
        body.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(), Some(Cl::ShiftSkip(op))));
        hdr_labeled(seq, op, body);
    }
}

// ── M2 (v22) 0x23-0x25 shifts by CL (count = vreg[1] & 31, 32-bit) ──────────
pub(crate) fn emit_shift_cl_32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_SHL_R_CL, Code::Shl_rm32_CL),
        (OP_SHR_R_CL, Code::Shr_rm32_CL),
        (OP_SAR_R_CL, Code::Sar_rm32_CL),
    ] {
        let mut body: Vec<(Instruction, Option<Cl>)> = vec![
            (Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(), None),
            (Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::ECX).unwrap(), None),
            (Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::R11)).unwrap(), None),
            // count = vreg[1]
            (Instruction::with2(Code::Mov_r32_imm32, Register::EDX, 1).unwrap(), None),
            (Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RDX)).unwrap(), None),
            (Instruction::with2(Code::And_rm32_imm32, Register::ECX, 31).unwrap(), None),
            // count==0 → RFLAGS 유지. count 테스트를 shift *이전*에 수행.
            (Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX).unwrap(), None),
            (Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Cl::ShiftSkip(op))),
            (Instruction::with2(code, Register::EAX, Register::CL).unwrap(), None),
            (Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(), None),
        ];
        body.extend(cap_flags_shift().into_iter().map(|i| (i, None)));
        body.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(), Some(Cl::ShiftSkip(op))));
        hdr_labeled(seq, op, body);
    }
}

// 0x4A-0x4C 64-bit shifts by imm8 (count masked to 63)
pub(crate) fn emit_shift_imm8_64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_SHL64_R_IMM8, Code::Shl_rm64_CL),
        (OP_SHR64_R_IMM8, Code::Shr_rm64_CL),
        (OP_SAR64_R_IMM8, Code::Sar_rm64_CL),
    ] {
        let mut body: Vec<(Instruction, Option<Cl>)> = vec![
            (Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(), None),
            // FIX(v26): R11 은 vreg 인덱스(번지)로 복사해야 한다. 과거 코드는
            // `mov r11, vreg[rcx]`(값)로 R11 을 vreg[R11] 인덱스로 써 OOB 액세스
            // 위험이 있었다. 32-bit imm8 버전과 동일하게 인덱스를 복사한다.
            (Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RCX).unwrap(), None), // R11 = reg index
            (Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(), None),
            (Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(), None),
            (Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap(), None),
            (Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::R11)).unwrap(), None),
            // count==0 → RFLAGS 유지. count 테스트를 shift *이전*에 수행.
            (Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX).unwrap(), None),
            (Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Cl::ShiftSkip(op))),
            (Instruction::with2(code, Register::RAX, Register::CL).unwrap(), None),
            (Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(), None),
        ];
        body.extend(cap_flags_shift().into_iter().map(|i| (i, None)));
        body.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(), Some(Cl::ShiftSkip(op))));
        hdr_labeled(seq, op, body);
    }
}

// 0x4D-0x4F 64-bit shifts by CL (count = vreg[1] & 63)
pub(crate) fn emit_shift_cl_64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_SHL64_R_CL, Code::Shl_rm64_CL),
        (OP_SHR64_R_CL, Code::Shr_rm64_CL),
        (OP_SAR64_R_CL, Code::Sar_rm64_CL),
    ] {
        // FIX(v26): vreg 인덱스(ECX)를 R11 로 **복사**해서 vreg[R11] 로 인덱싱한다.
        // 과거 코드는 `mov r11, vreg[rcx]` 로 **값**을 R11 에 넣어 vreg[R11] 을
        // 인덱스로 해 out-of-bounds 액세스(잠재 0xC0000005)가 있었다. 32-bit CL
        // 버전(0x23-0x25)과 동일하게 카운트는 vreg[1] 에서 가져온다.
        let mut body: Vec<(Instruction, Option<Cl>)> = vec![
            (Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(), None),
            (Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RCX).unwrap(), None), // R11 = reg index (copy)
            (Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::R11)).unwrap(), None), // RAX = vreg[reg]
            // count index = 1 (CL)
            (Instruction::with2(Code::Mov_r32_imm32, Register::EDX, 1).unwrap(), None),
            (Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RDX)).unwrap(), None), // ECX = vreg[1]
            (Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap(), None),
            // count==0 → RFLAGS 유지. count 테스트를 shift *이전*에 수행.
            (Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX).unwrap(), None),
            (Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Cl::ShiftSkip(op))),
            (Instruction::with2(code, Register::RAX, Register::CL).unwrap(), None),
            (Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(), None),
        ];
        body.extend(cap_flags_shift().into_iter().map(|i| (i, None)));
        body.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(), Some(Cl::ShiftSkip(op))));
        hdr_labeled(seq, op, body);
    }
}

// ── Phase 4: SHLD / SHRD double-precision shift handlers ────────────────────
// x86 SHLD/SHRD (count>0) set SF/ZF/PF from the result and CF = last bit
// shifted out of the DST operand; OF/AF undefined (defined 0). count==0 leaves
// flags untouched — the real instruction does that, so capturing the post-op
// flags is correct for both cases. The result sits in R11 until the store, so
// flags are captured into RAX (which holds only the already-consumed count)
// IMMEDIATELY after the shld/shrd, before the dst-index reload clobbers them.
fn cap_shld_flags() -> Vec<Instruction> {
    let keep = (FLAG_MASK & !(F_OF | F_AF)) | F_DF;
    vec![
        Instruction::with(Code::Pushfq),
        Instruction::with1(Code::Pop_r64, Register::RAX).unwrap(),
        Instruction::with2(Code::And_rm64_imm32, Register::RAX, (keep as u32) as i32).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, state_flags_mem(), Register::RAX).unwrap(),
    ]
}

pub(crate) fn emit_shld_shrd(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    // (op, is64, is_shld, has_imm)
    for (op, is64, is_shld, has_imm) in [
        (OP_SHLD_R_R_IMM8, false, true, true),
        (OP_SHLD_R_R_CL, false, true, false),
        (OP_SHRD_R_R_IMM8, false, false, true),
        (OP_SHRD_R_R_CL, false, false, false),
        (OP_SHLD64_R_R_IMM8, true, true, true),
        (OP_SHLD64_R_R_CL, true, true, false),
        (OP_SHRD64_R_R_IMM8, true, false, true),
        (OP_SHRD64_R_R_CL, true, false, false),
    ] {
        let (mv, shc, adv, cmask) = if is64 {
            (
                Code::Mov_r64_rm64,
                if is_shld { Code::Shld_rm64_r64_CL } else { Code::Shrd_rm64_r64_CL },
                if has_imm { 3 } else { 2 },
                63i32,
            )
        } else {
            (
                Code::Mov_r32_rm32,
                if is_shld { Code::Shld_rm32_r32_CL } else { Code::Shrd_rm32_r32_CL },
                if has_imm { 3 } else { 2 },
                31i32,
            )
        };
        let (dst, src) = if is64 { (Register::R11, Register::RDX) } else { (Register::R11D, Register::EDX) };

        let mut body: Vec<(Instruction, Option<Cl>)> = vec![
            (Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(), None),
            (Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(), None),
            (Instruction::with2(mv, dst, vreg(Register::RCX)).unwrap(), None), // dst value
            (Instruction::with2(mv, src, vreg(Register::RDX)).unwrap(), None), // src value
        ];
        if has_imm {
            body.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(), None)); // imm8
            body.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(), None)); // count
        } else {
            body.push((Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 1).unwrap(), None));
            body.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RAX)).unwrap(), None)); // count = vreg[1]
        }
        // count (mod width) == 0 → shld/shrd no-op and RFLAGS unchanged: skip the
        // shift/store/capture entirely (same pattern as the SHL/SHR/SAR handlers).
        body.push((Instruction::with2(Code::And_rm32_imm32, Register::ECX, cmask).unwrap(), None));
        body.push((Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX).unwrap(), None));
        body.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Cl::ShiftSkip(op))));
        body.push((Instruction::with3(shc, dst, src, Register::CL).unwrap(), None));
        // Capture CF/ZF/SF/PF into RAX (holds only the consumed count) before the
        // dst-index reload clobbers the flags.
        body.extend(cap_shld_flags().into_iter().map(|i| (i, None)));
        body.push((Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(), None));
        body.push((Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(), None));
        body.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, adv).unwrap(), Some(Cl::ShiftSkip(op))));
        hdr_labeled(seq, op, body);
    }
}