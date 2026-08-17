// ==============================================================================
// BTG v3 - VM Handler Codegen: ALU arithmetic family - split from alu.rs
// ==============================================================================
// XOR/ADD/IMUL/SUB/AND/OR reg-reg & imm32/imm64, ROL/ROR, INC/DEC, CMP, TEST,
// NEG/NOT. Shared helpers (`hdr`, `m`, `vreg`, `cap_flags`, `cap_flags_incdec`,
// ...) and the `Cl` label enum live in `super::super` (handlers/mod.rs).
// ==============================================================================

use super::super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

// ?? 0x04-0x07 + 0x15 XOR/ADD/IMUL/SUB/AND r,r  (op, dst, src) ?????????????
// fmod: 0 = no flags (reserved), 1 = full flags (ADD/SUB), 2 = logical (XOR/AND),
//       3 = MUL/IMUL CF/OF only (P0-⑤)
pub(crate) fn emit_alu_rr(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, fmod) in [
        (OP_XOR_R_R, Code::Xor_rm32_r32, 2),
        (OP_ADD_R_R, Code::Add_rm32_r32, 1),
        (OP_IMUL_R_R, Code::Imul_r32_rm32, 3),
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
            3 => body.extend(cap_flags_cf_of()),
            _ => {}
        }
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// ?? 0x08-0x0A AND/XOR/ADD r,imm32  (op, r, imm32) ??fmod 1=full 2=logical ??
pub(crate) fn emit_alu_imm32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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

// ?? 0x0B ROL r,imm8  (op, r, imm8) ??????????????????????????????????????????
pub(crate) fn emit_rol_r_imm8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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

// ?? 0x14 ROR r,imm8  (op, r, imm8) ??v10 (媛뺥솕??key_mix??ror) ????????????
pub(crate) fn emit_ror_r_imm8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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

// ?? 0x0C / 0x0D INC/DEC r  (op, r) ??sets flags, CF preserved ?????????????
pub(crate) fn emit_inc_dec(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_INC_R, Code::Inc_rm32),
        (OP_DEC_R, Code::Dec_rm32),
        (OP_INC_R64, Code::Inc_rm64),
        (OP_DEC_R64, Code::Dec_rm64),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with1(code, vreg(Register::RCX)).unwrap(),
        ];
        body.extend(cap_flags_incdec());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap());
        hdr(seq, op, body);
    }
}

// ?? 0x0E CMP r,imm32  (op, r, imm32) ??sets full flags ????????????????????
pub(crate) fn emit_cmp_r_imm32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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

// ?? M2 (v22) 0x18-0x1C 64-bit reg-reg ops (fmod: 1=full, 2=logical, 0=none) ?
pub(crate) fn emit_alu_rr64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, fmod) in [
        (OP_ADD_R_R64, Code::Add_rm64_r64, 1),
        (OP_SUB_R_R64, Code::Sub_rm64_r64, 1),
        (OP_XOR_R_R64, Code::Xor_rm64_r64, 2),
        (OP_AND_R_R64, Code::And_rm64_r64, 2),
        (OP_IMUL_R_R64, Code::Imul_r64_rm64, 3),
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
            3 => body.extend(cap_flags_cf_of()),
            _ => {}
        }
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// ?? M2 (v22) 0x1D-0x1F 64-bit imm32 (sign-extended) ?????????????????????????
pub(crate) fn emit_alu_imm64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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

// ?? M2 (v22) 0x26 TEST_R_R32 / 0x27 TEST_R_IMM32 (flags from AND, no write) ?
pub(crate) fn emit_test(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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

// ?? A-2 蹂닿컯 (v25) ??OR / NEG / NOT / 64-bit shift ????????????????????????
// 0x42-0x45 OR r,r / r,r64 / r,imm32 / r,imm64 (logical flags)
pub(crate) fn emit_or_rr(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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
pub(crate) fn emit_or_imm(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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
pub(crate) fn emit_neg(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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

pub(crate) fn emit_not(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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