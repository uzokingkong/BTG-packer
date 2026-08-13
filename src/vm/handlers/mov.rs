// ==============================================================================
// BTG v3 - VM Handler Codegen: MOV family
// ==============================================================================
// Data movement handlers: register/immediate moves and wider (16/32/64-bit)
// memory loads/stores. Shared helpers (`hdr`, `m`, `vreg`, `ptrslot`, ...) and
// the `Cl` label enum live in `super` (mod.rs).
// ==============================================================================

use super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

// ── 0x01 MOV_R_IMM32  (op, r, imm32) ────────────────────────────────────────
pub(super) fn emit_mov_r_imm32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOV_R_IMM32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap(),
        ],
    );
}

// ── 0x02 MOV_R_IMM64  (op, r, imm64) ────────────────────────────────────────
pub(super) fn emit_mov_r_imm64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOV_R_IMM64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 9).unwrap(),
        ],
    );
}

// ── 0x03 MOV_R_R  (op, dst, src) ────────────────────────────────────────────
pub(super) fn emit_mov_r_r(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOV_R_R,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// ── M2 (v22) 0x17 MOV_R_R64 (dst, src) — full 64-bit copy ───────────────────
pub(super) fn emit_mov_r_r64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOV_R_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// ── M2 (v22) 0x28-0x2C wider / sign-extending memory loads (dst, slot, idx) ─
// MOVSX sign-extends to the full 64-bit vreg (matches flags/interp).
pub(super) fn emit_mem_loads_wider(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, dst) in [
        (OP_MOVZX_R_MEM16, Code::Movzx_r32_rm16, Register::EAX),
        (OP_MOVZX_R_MEM32, Code::Mov_r32_rm32, Register::EAX),
        (OP_MOVSX_R_MEM8, Code::Movsx_r64_rm8, Register::RAX),
        (OP_MOVSX_R_MEM16, Code::Movsx_r64_rm16, Register::RAX),
        (OP_MOV_R_MEM64, Code::Mov_r64_rm64, Register::RAX),
    ] {
        hdr(
            seq,
            op,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RAX)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, ptrslot(Register::RDX)).unwrap(),
                Instruction::with2(code, dst, MemoryOperand::with_base_index_scale(Register::R11, Register::RAX, 1)).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
            ],
        );
    }
}

// ── M2 (v22) 0x2D-0x2F wider memory stores (slot, idx, src) ─────────────────
pub(super) fn emit_mem_stores_wider(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, store_code, src, load_code) in [
        (OP_MOV_MEM16_R, Code::Mov_rm16_r16, Register::AX, Code::Mov_r16_rm16),
        (OP_MOV_MEM32_R, Code::Mov_rm32_r32, Register::EAX, Code::Mov_r32_rm32),
        (OP_MOV_MEM64_R, Code::Mov_rm64_r64, Register::RAX, Code::Mov_r64_rm64),
    ] {
        hdr(
            seq,
            op,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, ptrslot(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RCX, vreg(Register::RDX)).unwrap(),
                Instruction::with2(load_code, src, vreg(Register::RAX)).unwrap(),
                Instruction::with2(store_code, MemoryOperand::with_base_index_scale(Register::R11, Register::RCX, 1), src).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
            ],
        );
    }
}
