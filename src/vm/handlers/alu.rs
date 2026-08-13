// ==============================================================================
// BTG v3 - VM Handler Codegen: ALU family
// ==============================================================================
// Arithmetic / logical / bit-manipulation handlers: XOR/ADD/IMUL/SUB/AND/OR,
// ROL/ROR, INC/DEC, CMP, TEST, shifts (imm8 and CL, 32/64-bit), NEG/NOT/NOP,
// and the v45 --vm-oep system instructions (CPUID / XGETBV / TZCNT).
// Shared helpers (`hdr`, `m`, `vreg`, `cap_flags`, ...) and the `Cl` label enum
// live in `super` (mod.rs).
// ==============================================================================

use super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

// ── 0x04-0x07 + 0x15 XOR/ADD/IMUL/SUB/AND r,r  (op, dst, src) ─────────────
// fmod: 0 = no flags (IMUL), 1 = full flags (ADD/SUB), 2 = logical (XOR/AND)
pub(super) fn emit_alu_rr(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, fmod) in [
        (OP_XOR_R_R, Code::Xor_rm32_r32, 2),
        (OP_ADD_R_R, Code::Add_rm32_r32, 1),
        (OP_IMUL_R_R, Code::Imul_r32_rm32, 0),
        (OP_SUB_R_R, Code::Sub_rm32_r32, 1),
        (OP_AND_R_R, Code::And_rm32_r32, 2),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(code, Register::EAX, Register::EDX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        ];
        match fmod {
            1 => body.extend(cap_flags(true)),
            2 => body.extend(cap_flags(false)),
            _ => {}
        }
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// ── 0x08-0x0A AND/XOR/ADD r,imm32  (op, r, imm32) — fmod 1=full 2=logical ──
pub(super) fn emit_alu_imm32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, fmod) in [
        (OP_AND_R_IMM32, Code::And_rm32_r32, 2),
        (OP_XOR_R_IMM32, Code::Xor_rm32_r32, 2),
        (OP_ADD_R_IMM32, Code::Add_rm32_r32, 1),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(code, Register::EAX, Register::EDX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        ];
        if fmod == 1 {
            body.extend(cap_flags(true));
        } else {
            body.extend(cap_flags(false));
        }
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap());
        hdr(seq, op, body);
    }
}

// ── 0x0B ROL r,imm8  (op, r, imm8) ──────────────────────────────────────────
pub(super) fn emit_rol_r_imm8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_ROL_R_IMM8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::ECX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
            Instruction::with2(Code::Rol_rm32_CL, Register::EAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// ── 0x14 ROR r,imm8  (op, r, imm8) — v10 (강화된 key_mix의 ror) ────────────
pub(super) fn emit_ror_r_imm8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_ROR_R_IMM8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::ECX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
            Instruction::with2(Code::Ror_rm32_CL, Register::EAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// ── 0x0C / 0x0D INC/DEC r  (op, r) — sets flags, CF preserved ─────────────
pub(super) fn emit_inc_dec(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [(OP_INC_R, Code::Inc_rm32), (OP_DEC_R, Code::Dec_rm32)] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with1(code, vreg(Register::RCX)).unwrap(),
        ];
        body.extend(cap_flags_incdec());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap());
        hdr(seq, op, body);
    }
}

// ── 0x0E CMP r,imm32  (op, r, imm32) — sets full flags ────────────────────
pub(super) fn emit_cmp_r_imm32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    let mut body = vec![
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Cmp_rm32_r32, Register::EAX, Register::EDX).unwrap(),
    ];
    body.extend(cap_flags(true));
    body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap());
    hdr(seq, OP_CMP_R_IMM32, body);
}

// ── M2 (v22) 0x18-0x1C 64-bit reg-reg ops (fmod: 1=full, 2=logical, 0=none) ─
pub(super) fn emit_alu_rr64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, fmod) in [
        (OP_ADD_R_R64, Code::Add_rm64_r64, 1),
        (OP_SUB_R_R64, Code::Sub_rm64_r64, 1),
        (OP_XOR_R_R64, Code::Xor_rm64_r64, 2),
        (OP_AND_R_R64, Code::And_rm64_r64, 2),
        (OP_IMUL_R_R64, Code::Imul_r64_rm64, 0),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(code, Register::RAX, Register::RDX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        ];
        match fmod {
            1 => body.extend(cap_flags(true)),
            2 => body.extend(cap_flags(false)),
            _ => {}
        }
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// ── M2 (v22) 0x1D-0x1F 64-bit imm32 (sign-extended) ─────────────────────────
pub(super) fn emit_alu_imm64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, fmod) in [
        (OP_ADD_R_IMM64, Code::Add_rm64_r64, 1),
        (OP_XOR_R_IMM64, Code::Xor_rm64_r64, 2),
        (OP_AND_R_IMM64, Code::And_rm64_r64, 2),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movsxd_r64_rm32, Register::RDX, Register::EDX).unwrap(),
            Instruction::with2(code, Register::RAX, Register::RDX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        ];
        if fmod == 1 {
            body.extend(cap_flags(true));
        } else {
            body.extend(cap_flags(false));
        }
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap());
        hdr(seq, op, body);
    }
}

// ── M2 (v22) 0x20-0x22 shifts by imm8 (32-bit) ──────────────────────────────
pub(super) fn emit_shift_imm8_32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_SHL_R_IMM8, Code::Shl_rm32_CL),
        (OP_SHR_R_IMM8, Code::Shr_rm32_CL),
        (OP_SAR_R_IMM8, Code::Sar_rm32_CL),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::ECX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::R11)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
            Instruction::with2(code, Register::EAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
        ];
        body.extend(cap_flags_shift());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// ── M2 (v22) 0x23-0x25 shifts by CL (count = vreg[1] & 31, 32-bit) ──────────
pub(super) fn emit_shift_cl_32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_SHL_R_CL, Code::Shl_rm32_CL),
        (OP_SHR_R_CL, Code::Shr_rm32_CL),
        (OP_SAR_R_CL, Code::Sar_rm32_CL),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::ECX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::R11)).unwrap(),
            // count = vreg[1]
            Instruction::with2(Code::Mov_r32_imm32, Register::EDX, 1).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 31).unwrap(),
            Instruction::with2(code, Register::EAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
        ];
        body.extend(cap_flags_shift());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap());
        hdr(seq, op, body);
    }
}

// ── M2 (v22) 0x26 TEST_R_R32 / 0x27 TEST_R_IMM32 (flags from AND, no write) ─
pub(super) fn emit_test(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RAX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EDX).unwrap(),
        ];
        body.extend(cap_flags(false));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, OP_TEST_R_R32, body);
    }
    {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RAX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EDX).unwrap(),
        ];
        body.extend(cap_flags(false));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap());
        hdr(seq, OP_TEST_R_IMM32, body);
    }
}

// ── A-2 보강 (v25) — OR / NEG / NOT / 64-bit shift ────────────────────────
// 0x42-0x45 OR r,r / r,r64 / r,imm32 / r,imm64 (logical flags)
pub(super) fn emit_or_rr(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, is64) in [
        (OP_OR_R_R, Code::Or_rm32_r32, false),
        (OP_OR_R_R64, Code::Or_rm64_r64, true),
    ] {
        let mut body = if !is64 {
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, vreg(Register::RDX)).unwrap(),
                Instruction::with2(code, Register::EAX, Register::EDX).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            ]
        } else {
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RDX, vreg(Register::RDX)).unwrap(),
                Instruction::with2(code, Register::RAX, Register::RDX).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            ]
        };
        body.extend(cap_flags(false));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// 0x44-0x45 OR r,imm32 / r,imm64 (logical flags)
pub(super) fn emit_or_imm(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, is64) in [
        (OP_OR_R_IMM32, Code::Or_rm32_r32, false),
        (OP_OR_R_IMM64, Code::Or_rm64_r64, true),
    ] {
        let mut body = if !is64 {
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(code, Register::EAX, Register::EDX).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            ]
        } else {
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Movsxd_r64_rm32, Register::RDX, Register::EDX).unwrap(),
                Instruction::with2(code, Register::RAX, Register::RDX).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            ]
        };
        body.extend(cap_flags(false));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap());
        hdr(seq, op, body);
    }
}

// 0x46-0x47 NEG r (full flags), 0x48-0x49 NOT r (no flags)
pub(super) fn emit_neg(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, is64) in [
        (OP_NEG_R, Code::Neg_rm32, false),
        (OP_NEG_R64, Code::Neg_rm64, true),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        ];
        if !is64 {
            body.push(Instruction::with1(code, vreg(Register::RCX)).unwrap());
        } else {
            body.push(Instruction::with1(code, vreg(Register::RCX)).unwrap());
        }
        body.extend(cap_flags(true));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap());
        hdr(seq, op, body);
    }
}

pub(super) fn emit_not(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, is64) in [
        (OP_NOT_R, Code::Not_rm32, false),
        (OP_NOT_R64, Code::Not_rm64, true),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with1(code, vreg(Register::RCX)).unwrap(),
        ];
        // NOT does not modify flags: no cap_flags.
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap());
        hdr(seq, op, body);
    }
}

// 0x4A-0x4C 64-bit shifts by imm8 (count masked to 63)
pub(super) fn emit_shift_imm8_64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_SHL64_R_IMM8, Code::Shl_rm64_CL),
        (OP_SHR64_R_IMM8, Code::Shr_rm64_CL),
        (OP_SAR64_R_IMM8, Code::Sar_rm64_CL),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            // FIX(v26): R11에 vreg 인덱스(레지스터 번호)를 복사해야 한다. 과거 코드는
            // `mov r11, vreg[rcx]`(값)로 넣은 뒤 vreg[R11]을 인덱싱해 OOB 읽기
            // → 네이티브 크래시. 32-bit imm8 버전과 동일하게 인덱스를 복사한다.
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RCX).unwrap(), // R11 = reg index
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::R11)).unwrap(),
            Instruction::with2(code, Register::RAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
        ];
        body.extend(cap_flags_shift());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// 0x4D-0x4F 64-bit shifts by CL (count = vreg[1] & 63)
pub(super) fn emit_shift_cl_64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_SHL64_R_CL, Code::Shl_rm64_CL),
        (OP_SHR64_R_CL, Code::Shr_rm64_CL),
        (OP_SAR64_R_CL, Code::Sar_rm64_CL),
    ] {
        // FIX(v26): 이 핸들러는 vreg index 바이트(ECX)를 R11로 **복사**한 뒤
        // vreg[R11]로 읽어야 한다. 과거 코드는 `mov r11, vreg[rcx]`로 **값**을
        // R11에 넣은 채 vreg[R11]을 인덱싱해 out-of-bounds 읽기 → 네이티브
        // 크래시(0xC0000005)를 일으켰다. 32-bit CL 버전(0x23-0x25)과 동일하게
        // 카운트도 vreg[1]에서 읽는다.
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RCX).unwrap(), // R11 = reg index (copy)
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::R11)).unwrap(), // RAX = vreg[reg]
            // count index = 1 (CL)
            Instruction::with2(Code::Mov_r32_imm32, Register::EDX, 1).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RDX)).unwrap(), // ECX = vreg[1]
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap(),
            Instruction::with2(code, Register::RAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
        ];
        body.extend(cap_flags_shift());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap());
        hdr(seq, op, body);
    }
}

// ── A-5 (v25): 0x50 NOP (no operands, no flags) ────────────────────────────
pub(super) fn emit_nop(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(seq, OP_NOP, vec![Instruction::with(Code::Nopw)]);
}

// ── v45: --vm-oep Rust-runtime additions ──────────────────────────────────
// 0x79 cpuid (0 operands): run native CPUID. vreg0=leaf, vreg2=subleaf;
// results EAX/EBX/ECX/EDX stored back to vreg0..3 (32-bit, zero-extended).
pub(super) fn emit_cpuid(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_CPUID,
        vec![
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0x00)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::R8, 0x10)).unwrap(),
            Instruction::with(Code::Cpuid),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x00), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x08), Register::RBX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x10), Register::RCX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x18), Register::RDX).unwrap(),
        ],
    );
}

// 0x7A xgetbv (0 operands): run native XGETBV. vreg2=RCX (subleaf), result
// EDX:EAX stored to vreg3:vreg0 (32-bit each, zero-extended).
pub(super) fn emit_xgetbv(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_XGETBV,
        vec![
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::R8, 0x10)).unwrap(),
            Instruction::with(Code::Xgetbv),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x00), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x18), Register::RDX).unwrap(),
        ],
    );
}

// 0x7B tzcnt32 vreg[dst], vreg[src] (2 operands).
// cnt = popcount((src & -src) - 1)  (== trailing zeros; == 32 when src==0).
// flags: CF=ZF=1 if src==0 else 0. Branch-free, portable (no POPCNT/BSF dep).
pub(super) fn emit_tzcnt(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_TZCNT_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ESI, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::EAX).unwrap(),
            // cnt: EBX = popcount((src & -src) - 1)
            Instruction::with2(Code::Mov_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with1(Code::Neg_rm32, Register::EBX).unwrap(),
            Instruction::with2(Code::And_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with1(Code::Dec_rm32, Register::EBX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 1).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x55555555).unwrap(),
            Instruction::with2(Code::Sub_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x33333333).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EBX, 2).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EBX, 0x33333333).unwrap(),
            Instruction::with2(Code::Add_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 4).unwrap(),
            Instruction::with2(Code::Add_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EBX, 0x0F0F0F0F).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap(),
            Instruction::with2(Code::Add_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 16).unwrap(),
            Instruction::with2(Code::Add_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EBX, 0xFF).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RSI), Register::RAX).unwrap(),
            // flags: CF=ZF=1 iff src==0
            Instruction::with2(Code::Mov_r32_rm32, Register::EDI, Register::R11D).unwrap(),
            Instruction::with1(Code::Neg_rm32, Register::EDI).unwrap(),
            Instruction::with2(Code::Or_r32_rm32, Register::EDI, Register::R11D).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EDI, 31).unwrap(),
            Instruction::with1(Code::Neg_rm32, Register::EDI).unwrap(),
            Instruction::with1(Code::Not_rm32, Register::EDI).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EDI, (F_CF | F_ZF) as u32).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, STATE_FLAGS as i32), Register::RDI).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}
