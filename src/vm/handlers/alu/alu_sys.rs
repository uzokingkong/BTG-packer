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
// Real `tzcnt r32, r/m32` (probe-verified semantics): CF=1 iff src==0, ZF
// follows the RESULT (tzcnt(0)=32 → ZF=0; tzcnt(odd)=0 → ZF=1), OF/SF/AF
// cleared, PF undefined → masked out. Captured with the same CF|ZF mask the
// LZCNT/POPCNT handlers use, matching the reference interpreter. (Replaces the
// old portable popcount emulation whose "CF=ZF=1 iff src==0" flags did NOT
// match real x86.)
pub(crate) fn emit_tzcnt(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    let mut body = vec![
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RDX)).unwrap(),
        Instruction::with2(Code::Tzcnt_r32_rm32, Register::EAX, Register::EAX).unwrap(),
        // EAX writes zero-extend into RAX; store the full 64-bit slot.
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
    ];
    // Capture CF|ZF right after tzcnt (mov above does not touch flags); DF kept.
    body.extend(vec![
        Instruction::with(Code::Pushfq),
        Instruction::with1(Code::Pop_r64, Register::R11).unwrap(),
        Instruction::with2(
            Code::And_rm64_imm32,
            Register::R11,
            ((F_CF | F_ZF) | F_DF) as u32 as i32,
        )
        .unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, state_flags_mem(), Register::R11).unwrap(),
    ]);
    body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
    hdr(seq, OP_TZCNT_R32, body);
}