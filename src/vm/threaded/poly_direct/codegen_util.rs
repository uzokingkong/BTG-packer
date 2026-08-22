// ==============================================================================
// BTG - Native Self-Decoding Dispatcher: arena layout / code builder - split from poly_direct.rs
// ==============================================================================
// Shared layout constants, rolling-key constants, the small two-pass CodeBuilder,
// and the instruction-emission helpers used by the dispatcher builder and tests.
// ==============================================================================

use crate::vm::risc::BranchCondition;
use crate::vm::threaded::VmRuntimeLayout;
use anyhow::{anyhow, Result};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};
use std::cell::RefCell;
// ── arena layout ─────────────────────────────────────────────────────────────
pub(crate) const OFF_CODE: usize = 0x1000; // entry + dispatch + handlers + helpers
pub(crate) const OFF_TABLE: usize = 0x8000; // handler table: decrypted opcode byte -> handler VA (256 x u64)
pub(crate) const OFF_OP_OFFS: usize = 0x8800; // operand-encoding -> state offset (256 x u8)
pub(crate) const OFF_OP_FLAGS: usize = 0x8900; // operand-encoding -> kind flag (256 x u8): 0=reg/temp/vsp/flags,1=imm,2=none
pub(crate) const OFF_COND_CODES: usize = 0x8A00; // decrypted cond byte -> canonical COND_* code (256 x u8)
pub(crate) const OFF_BRANCH_MAP: usize = 0x8B00; // branch-resolution table: u32 count + count x (u64 target_value, u64 byte_offset)
pub(crate) const OFF_BYTECODE: usize = 0x9000; // encrypted polymorphic stream (copied)
pub(crate) const OFF_STATE: usize = 0xA000; // VM state buffer
pub(crate) const OFF_STACK_BASE: usize = 0xE000; // virtual stack (grows down)
pub(crate) const ARENA_SIZE: usize = 0x40000;

// state buffer offsets (relative to state_base, held in RDX)
pub(crate) const REGS_OFF: i32 = 0x000;
pub(crate) const TEMPS_OFF: i32 = 0x080;
pub(crate) const FLAGS_OFF: i32 = 0x0C0;
pub(crate) const VSP_OFF: i32 = 0x0C8;
pub(crate) const DEC_DST: i32 = 0x0D0; // u8
pub(crate) const DEC_SRC1: i32 = 0x0D1; // u8
pub(crate) const DEC_SRC2: i32 = 0x0D2; // u8
pub(crate) const DEC_COND: i32 = 0x0D3; // u8  — decoded branch condition byte (VirtualBranch/Setcc/CMOV)
pub(crate) const DEC_IMM1: i32 = 0x0D8; // u64
pub(crate) const DEC_IMM2: i32 = 0x0E0; // u64
pub(crate) const DEC_CIN: i32 = 0x0E8; // u64
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

thread_local! {
    static ACTIVE_RUNTIME_LAYOUT: RefCell<VmRuntimeLayout> =
        RefCell::new(VmRuntimeLayout::legacy());
}

/// Restores the previous code-generation layout even when a builder returns
/// early through `?`. Each test/build thread owns its layout independently.
pub(crate) struct RuntimeLayoutGuard(VmRuntimeLayout);

impl Drop for RuntimeLayoutGuard {
    fn drop(&mut self) {
        ACTIVE_RUNTIME_LAYOUT.with(|active| *active.borrow_mut() = self.0.clone());
    }
}

pub(crate) fn install_runtime_layout(layout: &VmRuntimeLayout) -> RuntimeLayoutGuard {
    let previous = ACTIVE_RUNTIME_LAYOUT
        .with(|active| std::mem::replace(&mut *active.borrow_mut(), layout.clone()));
    RuntimeLayoutGuard(previous)
}

/// Translate the historical logical state ABI to the active physical layout.
/// Dynamic operand accesses already carry a physical offset and therefore do
/// not pass through this function.
pub(crate) fn state_disp(logical: i32) -> i32 {
    ACTIVE_RUNTIME_LAYOUT.with(|active| {
        let l = active.borrow();
        match logical {
            0x000..=0x078 if logical % 8 == 0 => l.vregs[(logical / 8) as usize],
            0x080..=0x0B8 if logical % 8 == 0 => l.temps[((logical - 0x80) / 8) as usize],
            0x0C0 => l.flags,
            0x0C8 => l.vsp,
            0x0D0..=0x0D3 => l.decode_operands + (logical - 0x0D0),
            0x0D8 => l.imm1,
            0x0E0 => l.imm2,
            0x0E8 => l.carry_in,
            0x0F0 => l.fp_return,
            0x100..=0x15F => l.xmm + (logical - 0x100),
            _ => logical,
        }
    })
}

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

pub(crate) const FLAG_MASK: u64 = 0x8D5; // CF|PF|AF|ZF|SF|OF — must match VirtualFlags::VFLAG_STATUS_MASK

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
        Self {
            instrs: Vec::new(),
            branches: Vec::new(),
        }
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

    /// Clone a handler body while preserving its branch graph. Targets inside
    /// the source range are rebased to the clone, and every edge to `old_exit`
    /// is redirected to `new_exit`. This is the primitive needed to compose a
    /// super-op from already verified production handler bodies.
    pub(crate) fn clone_range_retarget_exit(
        &mut self,
        start: usize,
        end: usize,
        old_exit: usize,
        new_exit: usize,
    ) -> Result<usize> {
        if start >= end || end > self.instrs.len() {
            return Err(anyhow!(
                "invalid code clone range [{start}..{end}) for {} instructions",
                self.instrs.len()
            ));
        }
        let source_instrs = self.instrs[start..end].to_vec();
        let source_branches: Vec<_> = self
            .branches
            .iter()
            .copied()
            .filter(|(branch, _)| (start..end).contains(branch))
            .collect();
        let clone_start = self.instrs.len();
        self.instrs.extend(source_instrs);
        for (branch, target) in source_branches {
            let cloned_branch = clone_start + (branch - start);
            let cloned_target = if target == old_exit {
                new_exit
            } else if (start..end).contains(&target) {
                clone_start + (target - start)
            } else {
                target
            };
            self.branches.push((cloned_branch, cloned_target));
        }
        Ok(clone_start)
    }

    /// Compose handler ranges into one entry point. Cloning backwards makes
    /// each preceding body's dispatch exits target the already-created next
    /// body, while the final body still exits through the real dispatcher.
    pub(crate) fn clone_handler_chain(
        &mut self,
        ranges: &[(usize, usize)],
        dispatch: usize,
    ) -> Result<usize> {
        if ranges.len() < 2 {
            return Err(anyhow!(
                "a super-op handler chain needs at least two bodies"
            ));
        }
        let mut next = dispatch;
        for &(start, end) in ranges.iter().rev() {
            next = self.clone_range_retarget_exit(start, end, dispatch, next)?;
        }
        Ok(next)
    }

    pub(crate) fn remap_legacy_carriers(
        &mut self,
        assignment: &crate::vm::threaded::reg_permutation::RegisterAssignment,
    ) {
        for ins in &mut self.instrs {
            for op in 0..ins.op_count() {
                if ins.op_kind(op) == iced_x86::OpKind::Register {
                    ins.set_op_register(op, assignment.map_legacy_carrier(ins.op_register(op)));
                }
            }
            ins.set_memory_base(assignment.map_legacy_carrier(ins.memory_base()));
            ins.set_memory_index(assignment.map_legacy_carrier(ins.memory_index()));
        }
    }

    /// Retarget direct handler tails through seed-selected, semantics-neutral
    /// islands. Islands contain only architectural NOPs followed by a direct
    /// jump, so flags, registers, stack alignment and unwind state are unchanged.
    pub(crate) fn diversify_direct_tails(&mut self, target: usize, seed: u64) -> usize {
        let tail_branches: Vec<usize> = self
            .branches
            .iter()
            .filter_map(|&(bi, ti)| {
                (ti == target && self.instrs[bi].code() == Code::Jmp_rel32_64).then_some(bi)
            })
            .collect();
        if tail_branches.len() < 2 {
            return tail_branches.len();
        }

        let mut islands = Vec::with_capacity(8);
        for variant in 0..8usize {
            let start = self.len();
            // 0..7 distinct instruction-level padding recipes. BlockEncoder may
            // choose different branch widths as a consequence, adding another
            // harmless source of layout diversity.
            for n in 0..variant {
                self.push(if n & 1 == 0 {
                    Instruction::with(Code::Nopd)
                } else {
                    Instruction::with(Code::Nopw)
                });
            }
            self.jmp(target);
            islands.push(start);
        }

        let mut mixed = seed ^ 0xE703_7ED1_A0B4_28DB;
        for (ordinal, bi) in tail_branches.iter().copied().enumerate() {
            mixed = mixed
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add((ordinal as u64) ^ 0xD1B5_4A32_D192_ED03);
            let island = islands[((mixed >> 32) as usize) % islands.len()];
            if let Some((_, ti)) = self.branches.iter_mut().find(|(branch, _)| *branch == bi) {
                *ti = island;
            }
        }
        tail_branches.len()
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
            let enc =
                BlockEncoder::encode(64, blk, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
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
    MemoryOperand::with_base_index_scale_displ_size(
        Register::RDX,
        Register::None,
        1,
        state_disp(disp) as i64,
        8,
    )
}
pub(crate) fn m8(disp: i32) -> MemoryOperand {
    MemoryOperand::with_base_index_scale_displ_size(
        Register::RDX,
        Register::None,
        1,
        state_disp(disp) as i64,
        1,
    )
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

/// Store the decoded byte currently in AL using one of four equivalent
/// scratch-register recipes. The selected scratch is caller-clobbered by the
/// decoder contract and no flags are consumed across this operation.
pub(crate) fn store_decoded_al(b: &mut CodeBuilder, disp: i32, recipe: u8) {
    match recipe & 3 {
        0 => b.push(Instruction::with2(Code::Mov_rm8_r8, m8(disp), Register::AL).unwrap()),
        1 => {
            b.push(Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::EAX).unwrap());
            b.push(Instruction::with2(Code::Mov_rm8_r8, m8(disp), Register::R11L).unwrap())
        }
        2 => {
            b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap());
            b.push(Instruction::with2(Code::Mov_rm8_r8, m8(disp), Register::CL).unwrap())
        }
        _ => {
            b.push(Instruction::with2(Code::Mov_r32_rm32, Register::R9D, Register::EAX).unwrap());
            b.push(Instruction::with2(Code::Mov_rm8_r8, m8(disp), Register::R9L).unwrap())
        }
    };
}

/// 8-byte little-endian immediate read via decrypt_byte calls, XOR operand_mask.
/// Result stored in the state DEC_* slot. Clobbers RAX,RCX,R11 and one of
/// RBX/RBP selected by the recipe (stream advanced).
///
/// NOTE: the 64-bit accumulator MUST be a register that `sub_decrypt` preserves.
/// `sub_decrypt` clobbers RAX/RCX/R9/R10/R11/R12/R14 but keeps RBX/R13/R15/RDX, so
/// we accumulate in RBX or RBP. The original code used R9 — on the 2nd..8th `call` the
/// partial immediate was destroyed by the callee, corrupting every decoded value.
pub(crate) fn emit_read_imm8(
    b: &mut CodeBuilder,
    slot: i32,
    sub_decrypt: usize,
    mask: u64,
    recipe: u8,
) {
    let accum = if recipe & 1 == 0 {
        Register::RBX
    } else {
        Register::RBP
    };
    b.push(Instruction::with2(Code::Xor_rm64_r64, accum, accum).unwrap());
    for i in 0..8 {
        b.call(sub_decrypt);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
        if i == 0 {
            b.push(Instruction::with2(Code::Mov_r64_rm64, accum, Register::RAX).unwrap());
        } else {
            b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RAX, (i * 8) as i32).unwrap());
            let combine = if recipe & 2 == 0 {
                Code::Or_rm64_r64
            } else {
                Code::Add_rm64_r64
            };
            b.push(Instruction::with2(combine, accum, Register::RAX).unwrap());
        }
    }
    movi(b, Register::RCX, mask);
    b.push(Instruction::with2(Code::Xor_rm64_r64, accum, Register::RCX).unwrap());
    store_m(b, slot, accum);
}

/// Read a compact immediate whose descriptor is stored in `marker_slot`.
/// The operand-offset table carries its family-local decoded width (1/2/4/8).
pub(crate) fn emit_read_compact_imm(
    b: &mut CodeBuilder,
    marker_slot: i32,
    slot: i32,
    sub_decrypt: usize,
    mask: u64,
    operand_offs: usize,
    sign_extend: bool,
) {
    movzx8_m(b, Register::EAX, marker_slot);
    let width_mem = MemoryOperand::with_base_index_scale_displ_size(
        Register::R15,
        Register::RAX,
        1,
        operand_offs as i64,
        1,
    );
    b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, width_mem).unwrap());
    store_m(b, DEC_CIN, Register::RAX);
    b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RBX, Register::RBX).unwrap());
    b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RBP, Register::RBP).unwrap());
    let loop_start = b.len();
    b.call(sub_decrypt);
    b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
    b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EBP).unwrap());
    b.push(Instruction::with2(Code::Shl_rm64_CL, Register::RAX, Register::CL).unwrap());
    b.push(Instruction::with2(Code::Or_rm64_r64, Register::RBX, Register::RAX).unwrap());
    b.push(Instruction::with2(Code::Add_rm64_imm8, Register::RBP, 8).unwrap());
    b.push(Instruction::with1(Code::Dec_rm64, m(DEC_CIN)).unwrap());
    b.br(Code::Jne_rel32_64, loop_start);
    movi(b, Register::RCX, mask);
    b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RBX, Register::RCX).unwrap());
    // Zero bits above the encoded width after applying the full operand mask.
    movi(b, Register::RCX, 64);
    b.push(Instruction::with2(Code::Sub_rm64_r64, Register::RCX, Register::RBP).unwrap());
    b.push(Instruction::with2(Code::Shl_rm64_CL, Register::RBX, Register::CL).unwrap());
    if sign_extend {
        movzx8_m(b, Register::EAX, marker_slot);
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 5).unwrap());
        let signed_edge = b.br(Code::Jae_rel32_64, usize::MAX - 1);
        b.push(Instruction::with2(Code::Shr_rm64_CL, Register::RBX, Register::CL).unwrap());
        let done_edge = b.br(Code::Jmp_rel32_64, usize::MAX);
        let signed = b.len();
        b.push(Instruction::with2(Code::Sar_rm64_CL, Register::RBX, Register::CL).unwrap());
        let done = b.len();
        for (branch, target) in &mut b.branches {
            if *branch == signed_edge {
                *target = signed;
            }
            if *branch == done_edge {
                *target = done;
            }
        }
    } else {
        b.push(Instruction::with2(Code::Shr_rm64_CL, Register::RBX, Register::CL).unwrap());
    }
    store_m(b, slot, Register::RBX);
}

#[cfg(test)]
mod code_builder_tests {
    use super::*;

    #[test]
    fn clone_range_rebases_internal_edges_and_retargets_exit() {
        let mut b = CodeBuilder::new();
        let next_handler = b.push(Instruction::with(Code::Retnq));
        let dispatch = b.push(Instruction::with(Code::Nopd));
        let start = b.len();
        b.push(Instruction::with(Code::Nopw));
        b.br(Code::Je_rel32_64, start + 2);
        b.jmp(dispatch);
        let end = b.len();

        let clone = b
            .clone_range_retarget_exit(start, end, dispatch, next_handler)
            .unwrap();
        assert_eq!(clone, end);
        assert!(b.branches.contains(&(clone + 1, clone + 2)));
        assert!(b.branches.contains(&(clone + 2, next_handler)));
        b.assemble(0x1400_0000_0).unwrap();
    }

    #[test]
    fn clone_range_rejects_invalid_bounds() {
        let mut b = CodeBuilder::new();
        b.push(Instruction::with(Code::Nopd));
        assert!(b.clone_range_retarget_exit(1, 1, 0, 0).is_err());
        assert!(b.clone_range_retarget_exit(0, 2, 0, 0).is_err());
    }

    #[test]
    fn clone_handler_chain_links_each_body_once() {
        let mut b = CodeBuilder::new();
        let dispatch = b.push(Instruction::with(Code::Nopd));
        let first = b.len();
        b.push(Instruction::with(Code::Nopw));
        b.jmp(dispatch);
        let first_end = b.len();
        let second = b.len();
        b.push(Instruction::with(Code::Nopd));
        b.jmp(dispatch);
        let second_end = b.len();

        let entry = b
            .clone_handler_chain(&[(first, first_end), (second, second_end)], dispatch)
            .unwrap();
        let second_clone = second_end;
        assert_eq!(entry, second_clone + (second_end - second));
        assert!(b.branches.contains(&(entry + 1, second_clone)));
        assert!(b.branches.contains(&(second_clone + 1, dispatch)));
        b.assemble(0x1800_0000_0).unwrap();
    }
}
