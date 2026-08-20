// ==============================================================================
// BTG - Native Self-Decoding Dispatcher: arena layout / code builder - split from poly_direct.rs
// ==============================================================================
// Shared layout constants, rolling-key constants, the small two-pass CodeBuilder,
// and the instruction-emission helpers used by the dispatcher builder and tests.
// ==============================================================================

use crate::vm::risc::BranchCondition;
use anyhow::{anyhow, Result};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};
// ── arena layout ─────────────────────────────────────────────────────────────
pub(crate) const OFF_CODE: usize = 0x1000;      // entry + dispatch + handlers + helpers
pub(crate) const OFF_TABLE: usize = 0x8000;     // handler table: decrypted opcode byte -> handler VA (256 x u64)
pub(crate) const OFF_OP_OFFS: usize = 0x8800;   // operand-encoding -> state offset (256 x u8)
pub(crate) const OFF_OP_FLAGS: usize = 0x8900;  // operand-encoding -> kind flag (256 x u8): 0=reg/temp/vsp/flags,1=imm,2=none
pub(crate) const OFF_COND_CODES: usize = 0x8A00; // decrypted cond byte -> canonical COND_* code (256 x u8)
pub(crate) const OFF_BRANCH_MAP: usize = 0x8B00; // branch-resolution table: u32 count + count x (u64 target_value, u64 byte_offset)
pub(crate) const OFF_BYTECODE: usize = 0x9000;  // encrypted polymorphic stream (copied)
pub(crate) const OFF_STATE: usize = 0xA000;     // VM state buffer
pub(crate) const OFF_STACK_BASE: usize = 0xE000; // virtual stack (grows down)
pub(crate) const ARENA_SIZE: usize = 0x40000;

// state buffer offsets (relative to state_base, held in RDX)
pub(crate) const REGS_OFF: i32 = 0x000;
pub(crate) const TEMPS_OFF: i32 = 0x080;
pub(crate) const FLAGS_OFF: i32 = 0x0C0;
pub(crate) const VSP_OFF: i32 = 0x0C8;
pub(crate) const DEC_DST: i32 = 0x0D0;  // u8
pub(crate) const DEC_SRC1: i32 = 0x0D1; // u8
pub(crate) const DEC_SRC2: i32 = 0x0D2; // u8
pub(crate) const DEC_COND: i32 = 0x0D3; // u8  — decoded branch condition byte (VirtualBranch/Setcc/CMOV)
pub(crate) const DEC_IMM1: i32 = 0x0D8; // u64
pub(crate) const DEC_IMM2: i32 = 0x0E0; // u64
pub(crate) const DEC_CIN: i32 = 0x0E8;  // u64
pub(crate) const STATE_END: i32 = 0x100;
/// F1: 네이티브 브릿지 FP 리턴 폭 슬롯 (u64, 0=정수/무시, 4=f32, 8=f64).
/// 상용 self-decoding 디스패처의 `SetNativeFpReturn{width}` 핸들러가 기록하고,
/// 브릿지(nf_real)가 네이티브 콜 후 반환값을 XMM0(FP) 대신 RAX(정수) 중 어느
/// 것에서 regs[0] 로 동기화할지 결정한다. DEC_* (0xD0..0xEF) 와 겹치지 않는
/// 여유 영역 0xF0..0xFF 사용.
pub(crate) const FP_RET_OFF: i32 = 0x0F0;
/// P1-8: Win64 FP/vector ABI — 네이티브 브릿지가 VM 상태의 XMM 슬롯에서
/// XMM0-5 로 물질화/동기화한다 (state_base + XMM_OFF, 6 × 16B). 로더가 이
/// 슬롯에 FP 인자를 심으면 (lifter/ABI 분석 — 후속) 브릿지가 ABI-정확하게
/// 전달한다. 상태 버퍼 뒤의 예약 영역이라 기존 REGS/TEMPS/FLAGS 와 겹치지 않는다.
pub(crate) const XMM_OFF: i32 = 0x100;
pub(crate) const XMM_SLOTS: usize = 6; // XMM0..XMM5 (Win64 FP 레지스터 인자)

// operand kind flags (OFF_OP_FLAGS)
pub(crate) const K_REG: u8 = 0;
pub(crate) const K_IMM: u8 = 1;
pub(crate) const K_NONE: u8 = 2;

// ── canonical branch-condition codes (OFF_COND_CODES table values) ───────────
// Mirror the BranchCondition variant ordering in src/vm/risc/opcodes.rs so the
// native VirtualBranch/Setcc/CMOV handlers can switch on a stable code instead of
// the seed-randomized cond bytes. 0xFF = unknown/invalid cond byte.
pub const COND_ALWAYS: u8 = 0;
pub const COND_ZERO: u8 = 1;
pub const COND_NOT_ZERO: u8 = 2;
pub const COND_CARRY: u8 = 3;
pub const COND_NOT_CARRY: u8 = 4;
pub const COND_SIGN: u8 = 5;
pub const COND_NOT_SIGN: u8 = 6;
pub const COND_OVERFLOW: u8 = 7;
pub const COND_NOT_OVERFLOW: u8 = 8;
pub const COND_GREATER: u8 = 9;
pub const COND_LESS: u8 = 10;
pub const COND_GREATER_OR_EQUAL: u8 = 11;
pub const COND_LESS_OR_EQUAL: u8 = 12;
pub const COND_ABOVE: u8 = 13;
pub const COND_ABOVE_OR_EQUAL: u8 = 14;
pub const COND_BELOW: u8 = 15;
pub const COND_BELOW_OR_EQUAL: u8 = 16;
pub const COND_PARITY: u8 = 17;
pub const COND_NOT_PARITY: u8 = 18;
pub const COND_COUNTER_ZERO_2: u8 = 19;
pub const COND_COUNTER_ZERO_4: u8 = 20;
pub const COND_COUNTER_ZERO_8: u8 = 21;
pub const COND_INVALID: u8 = 0xFF;

pub(crate) const FLAG_MASK: u64 = 0x8C5; // CF|PF|ZF|SF|OF (reference update_logic64/update_add64 recompute PF from result parity)

/// Map a `BranchCondition` to its canonical native code (OFF_COND_CODES value).
pub(crate) fn cond_code(cond: BranchCondition) -> u8 {
    use BranchCondition::*;
    match cond {
        Always => COND_ALWAYS,
        Zero => COND_ZERO,
        NotZero => COND_NOT_ZERO,
        Carry => COND_CARRY,
        NotCarry => COND_NOT_CARRY,
        Sign => COND_SIGN,
        NotSign => COND_NOT_SIGN,
        Overflow => COND_OVERFLOW,
        NotOverflow => COND_NOT_OVERFLOW,
        Greater => COND_GREATER,
        Less => COND_LESS,
        GreaterOrEqual => COND_GREATER_OR_EQUAL,
        LessOrEqual => COND_LESS_OR_EQUAL,
        Above => COND_ABOVE,
        AboveOrEqual => COND_ABOVE_OR_EQUAL,
        Below => COND_BELOW,
        BelowOrEqual => COND_BELOW_OR_EQUAL,
        Parity => COND_PARITY,
        NotParity => COND_NOT_PARITY,
        CounterZero(2) => COND_COUNTER_ZERO_2,
        CounterZero(4) => COND_COUNTER_ZERO_4,
        CounterZero(_) => COND_COUNTER_ZERO_8,
    }
}

// Rolling-key engine constants (must match `RollingKeyEngine`).
pub(crate) const C1: u64 = 0x9E3779B97F4A7C15;
pub(crate) const C2: u64 = 0xBF58476D1CE4E5B9;
pub(crate) const C3: u64 = 0x517CC1B727220A95;
pub(crate) const C4: u64 = 0x1337BEEFCAFE0001;
pub(crate) const C5: u64 = 0x94D049BB133111EB;

// ── small code builder (two-pass branch patching, mirroring pass3) ──────────
pub(crate) struct CodeBuilder {
    instrs: Vec<Instruction>,
    /// (branch instruction index, target instruction index)
    pub(crate) branches: Vec<(usize, usize)>,
}

impl CodeBuilder {
    pub(crate) fn new() -> Self {
        Self { instrs: Vec::new(), branches: Vec::new() }
    }
    pub(crate) fn push(&mut self, i: Instruction) -> usize {
        self.instrs.push(i);
        self.instrs.len() - 1
    }
    pub(crate) fn len(&self) -> usize {
        self.instrs.len()
    }
    pub(crate) fn br(&mut self, code: Code, target: usize) -> usize {
        let idx = self.push(Instruction::with_branch(code, 0).unwrap());
        self.branches.push((idx, target));
        idx
    }
    pub(crate) fn jmp(&mut self, target: usize) {
        self.br(Code::Jmp_rel32_64, target);
    }
    pub(crate) fn jne(&mut self, target: usize) {
        self.br(Code::Jne_rel32_64, target);
    }
    pub(crate) fn je(&mut self, target: usize) {
        self.br(Code::Je_rel32_64, target);
    }
    pub(crate) fn call(&mut self, target: usize) {
        self.br(Code::Call_rel32_64, target);
    }

    pub(crate) fn assemble(&mut self, base_va: u64) -> Result<(Vec<u8>, Vec<u64>)> {
        // Branch sizes may be shrunk by BlockEncoder (rel32 -> rel8), so the layout
        // is not known a priori. Iterate: guess branch targets, encode, read back the
        // true per-instruction offsets, and re-target until it converges.
        let mut ips: Vec<u64> = (0..self.instrs.len()).map(|_| base_va).collect();
        let mut code = Vec::new();
        for _ in 0..16 {
            for &(bi, ti) in &self.branches {
                self.instrs[bi].set_near_branch64(ips[ti]);
            }
            let blk = InstructionBlock::new(&self.instrs, base_va);
            let enc = BlockEncoder::encode(
                64,
                blk,
                BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
            )
            .map_err(|e| anyhow!("block: {e:?}"))?;
            let new_ips: Vec<u64> = enc
                .new_instruction_offsets
                .iter()
                .map(|o| base_va + *o as u64)
                .collect();
            code = enc.code_buffer;
            if new_ips == ips {
                ips = new_ips;
                break;
            }
            ips = new_ips;
        }
        Ok((code, ips))
    }
}

pub(crate) fn m(disp: i32) -> MemoryOperand {
    MemoryOperand::with_base_index_scale_displ_size(Register::RDX, Register::None, 1, disp as i64, 8)
}
pub(crate) fn m8(disp: i32) -> MemoryOperand {
    MemoryOperand::with_base_index_scale_displ_size(Register::RDX, Register::None, 1, disp as i64, 1)
}
pub(crate) fn movi(b: &mut CodeBuilder, r: Register, v: u64) {
    b.push(Instruction::with2(Code::Mov_r64_imm64, r, v).unwrap());
}
pub(crate) fn mov_m(b: &mut CodeBuilder, r: Register, disp: i32) {
    b.push(Instruction::with2(Code::Mov_r64_rm64, r, m(disp)).unwrap());
}
pub(crate) fn store_m(b: &mut CodeBuilder, disp: i32, r: Register) {
    b.push(Instruction::with2(Code::Mov_rm64_r64, m(disp), r).unwrap());
}
pub(crate) fn movzx8_m(b: &mut CodeBuilder, r: Register, disp: i32) {
    b.push(Instruction::with2(Code::Movzx_r32_rm8, r, m8(disp)).unwrap());
}

/// 8-byte little-endian immediate read via decrypt_byte calls, XOR operand_mask.
/// Result stored in the state DEC_* slot. Clobbers RAX,RCX,RBX,R11 (stream advanced).
///
/// NOTE: the 64-bit accumulator MUST be a register that `sub_decrypt` preserves.
/// `sub_decrypt` clobbers RAX/RCX/R9/R10/R11/R12/R14 but keeps RBX/R13/R15/RDX, so
/// we accumulate in RBX. The original code used R9 — on the 2nd..8th `call` the
/// partial immediate was destroyed by the callee, corrupting every decoded value.
pub(crate) fn emit_read_imm8(b: &mut CodeBuilder, slot: i32, sub_decrypt: usize, mask: u64) {
    b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RBX, Register::RBX).unwrap());
    for i in 0..8 {
        b.call(sub_decrypt);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
        if i == 0 {
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RAX).unwrap());
        } else {
            b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RAX, (i * 8) as i32).unwrap());
            b.push(Instruction::with2(Code::Or_rm64_r64, Register::RBX, Register::RAX).unwrap());
        }
    }
    movi(b, Register::RCX, mask);
    b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RBX, Register::RCX).unwrap());
    store_m(b, slot, Register::RBX);
}
