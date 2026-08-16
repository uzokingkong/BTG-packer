// ==============================================================================
// BTG v3 - VM Handler Codegen: system / control instructions - split from alu.rs
// ==============================================================================
// NOP, CPUID, XGETBV, TZCNT (v45 --vm-oep Rust-runtime additions).
// Shared helpers (`hdr`, `m`, `vreg`, ...) live in `super::super`
// (handlers/mod.rs).
// ==============================================================================

use super::super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

// ?? A-5 (v25): 0x50 NOP (no operands, no flags) ????????????????????????????
pub(crate) fn emit_nop(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(seq, OP_NOP, vec![Instruction::with(Code::Nopw)]);
}

// ?? v45: --vm-oep Rust-runtime additions ??????????????????????????????????
// 0x79 cpuid (0 operands): run native CPUID. vreg0=leaf, vreg2=subleaf;
// results EAX/EBX/ECX/EDX stored back to vreg0..3 (32-bit, zero-extended).
pub(crate) fn emit_cpuid(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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
pub(crate) fn emit_xgetbv(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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
pub(crate) fn emit_tzcnt(seq: &mut Vec<(Instruction, Option<Cl>)>) {
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