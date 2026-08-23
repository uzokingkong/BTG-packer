// ==============================================================================
// BTG v3 - VM Handler Codegen: BMI1/2 (Group B) - split from alu.rs
// ==============================================================================
// LZCNT/POPCNT/BLSR/BLSMSK/BLSI/ANDN register-register handlers.
// Encoding: [op, dst_vreg, src_vreg] (2 operands). ANDN is [op, dst, src1, src2].
// LZCNT/POPCNT use native lzcnt/popcnt (flags: CF|ZF captured, matching the
// interpreter); BLSR/BLSMSK/BLSI/ANDN are NOT flagless — Intel SDM defines
// ZF (and SF for ANDN) on the result with CF/OF cleared, and the native
// instructions set them on the real CPU, so the interpreter must too.
// ==============================================================================

use super::super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

fn cap_flags_zf_cf() -> Vec<Instruction> {
    vec![
        Instruction::with(Code::Pushfq),
        Instruction::with1(Code::Pop_r64, Register::R11).unwrap(),
        Instruction::with2(
            Code::And_rm64_imm32,
            Register::R11,
            (F_CF | F_ZF) as u32 as i32,
        )
        .unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, state_flags_mem(), Register::R11).unwrap(),
    ]
}

/// Capture BLSR/BLSMSK/BLSI flags. Intel SDM: SF/OF/CF are *cleared*, ZF is
/// set iff the result is zero (PF/AF undefined → defined 0). The decomposed
/// `and`/`xor` already set ZF from the result, so masking to F_ZF alone (plus
/// carrying DF through) reproduces the real instruction's flags exactly.
fn cap_flags_bls() -> Vec<Instruction> {
    let keep = F_ZF | F_DF;
    vec![
        Instruction::with(Code::Pushfq),
        Instruction::with1(Code::Pop_r64, Register::R11).unwrap(),
        Instruction::with2(Code::And_rm64_imm32, Register::R11, (keep as u32) as i32).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, state_flags_mem(), Register::R11).unwrap(),
    ]
}

/// Capture ANDN flags. Intel SDM: SF/ZF updated from the result, CF/OF cleared
/// (AF/PF undefined → defined 0). The decomposed trailing `and` sets SF/ZF
/// correctly; masking to F_ZF|F_SF (plus DF) reproduces the real instruction.
fn cap_flags_andn() -> Vec<Instruction> {
    let keep = F_ZF | F_SF | F_DF;
    vec![
        Instruction::with(Code::Pushfq),
        Instruction::with1(Code::Pop_r64, Register::R11).unwrap(),
        Instruction::with2(Code::And_rm64_imm32, Register::R11, (keep as u32) as i32).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, state_flags_mem(), Register::R11).unwrap(),
    ]
}

// LZCNT r32/r64
pub(crate) fn emit_lzcnt(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, is64) in [
        (OP_LZCNT_R32, Code::Lzcnt_r32_rm32, false),
        (OP_LZCNT_R64, Code::Lzcnt_r64_rm64, true),
    ] {
        let mut body = vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        ];
        if is64 {
            body.push(
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
            );
            body.push(Instruction::with2(code, Register::RAX, Register::RAX).unwrap());
        } else {
            body.push(
                Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RDX)).unwrap(),
            );
            body.push(Instruction::with2(code, Register::EAX, Register::EAX).unwrap());
        }
        body.push(
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        );
        body.extend(cap_flags_zf_cf());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// POPCNT r32/r64
pub(crate) fn emit_popcnt(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, is64) in [
        (OP_POPCNT_R32, Code::Popcnt_r32_rm32, false),
        (OP_POPCNT_R64, Code::Popcnt_r64_rm64, true),
    ] {
        let mut body = vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        ];
        if is64 {
            body.push(
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
            );
            body.push(Instruction::with2(code, Register::RAX, Register::RAX).unwrap());
        } else {
            body.push(
                Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RDX)).unwrap(),
            );
            body.push(Instruction::with2(code, Register::EAX, Register::EAX).unwrap());
        }
        body.push(
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        );
        body.extend(cap_flags_zf_cf());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// BLSR r32/r64 : dst = src & (src-1)
pub(crate) fn emit_blsr(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, is64) in [(OP_BLSR_R32, false), (OP_BLSR_R64, true)] {
        let (mv, sreg, lreg) = if is64 {
            (Code::Mov_r64_rm64, Register::RAX, Register::R11)
        } else {
            (Code::Mov_r32_rm32, Register::EAX, Register::R11D)
        };
        let mut body = vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(mv, sreg, vreg(Register::RDX)).unwrap(),
            Instruction::with2(mv, lreg, vreg(Register::RDX)).unwrap(),
            if is64 {
                Instruction::with2(Code::Sub_rm64_imm8, lreg, 1).unwrap()
            } else {
                Instruction::with2(Code::Sub_rm32_imm8, lreg, 1).unwrap()
            },
            if is64 {
                Instruction::with2(Code::And_rm64_r64, sreg, lreg).unwrap()
            } else {
                Instruction::with2(Code::And_rm32_r32, sreg, lreg).unwrap()
            },
            // EAX writes zero-extend into RAX; store the full 64-bit slot.
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        ];
        body.extend(cap_flags_bls());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// BLSMSK r32/r64 : dst = src ^ (src-1)
pub(crate) fn emit_blsmsk(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, is64) in [(OP_BLSMSK_R32, false), (OP_BLSMSK_R64, true)] {
        let (mv, sreg, lreg) = if is64 {
            (Code::Mov_r64_rm64, Register::RAX, Register::R11)
        } else {
            (Code::Mov_r32_rm32, Register::EAX, Register::R11D)
        };
        let mut body = vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(mv, sreg, vreg(Register::RDX)).unwrap(),
            Instruction::with2(mv, lreg, vreg(Register::RDX)).unwrap(),
            if is64 {
                Instruction::with2(Code::Sub_rm64_imm8, lreg, 1).unwrap()
            } else {
                Instruction::with2(Code::Sub_rm32_imm8, lreg, 1).unwrap()
            },
            if is64 {
                Instruction::with2(Code::Xor_rm64_r64, sreg, lreg).unwrap()
            } else {
                Instruction::with2(Code::Xor_rm32_r32, sreg, lreg).unwrap()
            },
            // EAX writes zero-extend into RAX; store the full 64-bit slot.
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        ];
        body.extend(cap_flags_bls());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// BLSI r32/r64 : dst = src & (-src)
pub(crate) fn emit_blsi(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, is64) in [(OP_BLSI_R32, false), (OP_BLSI_R64, true)] {
        let (mv, sreg, lreg) = if is64 {
            (Code::Mov_r64_rm64, Register::RAX, Register::R11)
        } else {
            (Code::Mov_r32_rm32, Register::EAX, Register::R11D)
        };
        let mut body = vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(mv, sreg, vreg(Register::RDX)).unwrap(),
            Instruction::with2(mv, lreg, vreg(Register::RDX)).unwrap(),
            if is64 {
                Instruction::with1(Code::Neg_rm64, lreg).unwrap()
            } else {
                Instruction::with1(Code::Neg_rm32, lreg).unwrap()
            },
            if is64 {
                Instruction::with2(Code::And_rm64_r64, sreg, lreg).unwrap()
            } else {
                Instruction::with2(Code::And_rm32_r32, sreg, lreg).unwrap()
            },
            // EAX writes zero-extend into RAX; store the full 64-bit slot.
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        ];
        body.extend(cap_flags_bls());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// ANDN r32/r64 : dst = ~src1 & src2. Encoding [op, dst, src1, src2].
// Registers: ECX=dst idx, EDX=src1 idx, ESI=src2 idx (byte2).
//   R11 = src1 ; RAX = src2 ; R11 = ~R11 & RAX ; store.
pub(crate) fn emit_andn(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, is64) in [(OP_ANDN_R_R32, false), (OP_ANDN_R_R64, true)] {
        let (mv, s1, s2, notc, andc) = if is64 {
            (
                Code::Mov_r64_rm64,
                Register::R11,
                Register::RAX,
                Code::Not_rm64,
                Code::And_rm64_r64,
            )
        } else {
            (
                Code::Mov_r32_rm32,
                Register::R11D,
                Register::EAX,
                Code::Not_rm32,
                Code::And_rm32_r32,
            )
        };
        let mut body = vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::ESI, m(Register::R9, 2)).unwrap(),
            // src1 -> s1
            Instruction::with2(mv, s1, vreg(Register::RDX)).unwrap(),
            // src2 -> s2 (from vreg[RSI])
            Instruction::with2(mv, s2, vreg(Register::RSI)).unwrap(),
            Instruction::with1(notc, s1).unwrap(),
            Instruction::with2(andc, s1, s2).unwrap(),
            // R11D writes zero-extend into R11; store the full 64-bit slot.
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
        ];
        body.extend(cap_flags_andn());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap());
        hdr(seq, op, body);
    }
}
