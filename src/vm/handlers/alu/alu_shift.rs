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
pub(crate) fn emit_shld_shrd(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    // 32-bit imm8
    hdr(seq, OP_SHLD_R_R_IMM8, vec![
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(), // imm8
        Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(), // dst
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, vreg(Register::RDX)).unwrap(), // src
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(), // count
        Instruction::with3(Code::Shld_rm32_r32_CL, Register::R11D, Register::EDX, Register::CL).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
    ]);
    // 32-bit CL
    hdr(seq, OP_SHLD_R_R_CL, vec![
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(), // dst
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, vreg(Register::RDX)).unwrap(), // src
        // count from vreg[1] (RCX)
        Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 1).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RAX)).unwrap(),
        Instruction::with3(Code::Shld_rm32_r32_CL, Register::R11D, Register::EDX, Register::CL).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
    ]);
    // 32-bit SHRD imm8
    hdr(seq, OP_SHRD_R_R_IMM8, vec![
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, vreg(Register::RDX)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
        Instruction::with3(Code::Shrd_rm32_r32_CL, Register::R11D, Register::EDX, Register::CL).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
    ]);
    // 32-bit SHRD CL
    hdr(seq, OP_SHRD_R_R_CL, vec![
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, vreg(Register::RDX)).unwrap(),
        Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 1).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RAX)).unwrap(),
        Instruction::with3(Code::Shrd_rm32_r32_CL, Register::R11D, Register::EDX, Register::CL).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
    ]);
    // 64-bit SHLD imm8
    hdr(seq, OP_SHLD64_R_R_IMM8, vec![
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, Register::RDX, vreg(Register::RDX)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
        Instruction::with3(Code::Shld_rm64_r64_CL, Register::R11, Register::RDX, Register::CL).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
    ]);
    // 64-bit SHLD CL
    hdr(seq, OP_SHLD64_R_R_CL, vec![
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, Register::RDX, vreg(Register::RDX)).unwrap(),
        Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 1).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RAX)).unwrap(),
        Instruction::with3(Code::Shld_rm64_r64_CL, Register::R11, Register::RDX, Register::CL).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
    ]);
    // 64-bit SHRD imm8
    hdr(seq, OP_SHRD64_R_R_IMM8, vec![
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, Register::RDX, vreg(Register::RDX)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
        Instruction::with3(Code::Shrd_rm64_r64_CL, Register::R11, Register::RDX, Register::CL).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
    ]);
    // 64-bit SHRD CL
    hdr(seq, OP_SHRD64_R_R_CL, vec![
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, Register::RDX, vreg(Register::RDX)).unwrap(),
        Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 1).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RAX)).unwrap(),
        Instruction::with3(Code::Shrd_rm64_r64_CL, Register::R11, Register::RDX, Register::CL).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
    ]);
}