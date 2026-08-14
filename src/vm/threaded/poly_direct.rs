// ==============================================================================
// BTG - Commercial-Grade VM: Native Self-Decoding Rolling-Key Dispatcher (T1-4)
// ==============================================================================
// `run_native_poly_direct` — the native runtime **itself** decodes the
// rolling-key polymorphic bytecode stream while executing (no Rust pre-pass).
//
// vs. `run_native_poly` (Rust `PolymorphicDecoder` → specialized blocks), this
// path places the **encrypted** stream in the arena and generates native code
// that, at runtime:
//   1. computes the rolling-key keystream byte for the current VIP,
//   2. XORs it with the stream byte to recover the plaintext opcode/operand,
//   3. advances the rolling-key state (`step`) exactly like the interpreter,
//   4. dispatches on the decrypted opcode byte through a 256-entry table,
//   5. decodes operands (register permutation + immediates) and executes.
//
// Differential test: native(self-decoding) == PolymorphicInterpreter ==
// `RiscProgram::eval_state` across multiple seeds.
// ==============================================================================

use crate::vm::arena::Arena;
use crate::vm::poly::VirtualIsaSpec;
use crate::vm::risc::{MicroInstr, MicroOperand, RiscEvalState, RiscOp, RiscProgram};
use anyhow::{anyhow, Result};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};

// ── arena layout ─────────────────────────────────────────────────────────────
const OFF_CODE: usize = 0x1000;      // entry + dispatch + handlers + helpers
const OFF_TABLE: usize = 0x8000;     // handler table: decrypted opcode byte -> handler VA (256 x u64)
const OFF_OP_OFFS: usize = 0x8800;   // operand-encoding -> state offset (256 x u8)
const OFF_OP_FLAGS: usize = 0x8900;  // operand-encoding -> kind flag (256 x u8): 0=reg/temp/vsp/flags,1=imm,2=none
const OFF_BYTECODE: usize = 0x9000;  // encrypted polymorphic stream (copied)
const OFF_STATE: usize = 0xA000;     // VM state buffer
const OFF_STACK_BASE: usize = 0xE000; // virtual stack (grows down)
const ARENA_SIZE: usize = 0x40000;

// state buffer offsets (relative to state_base, held in RDX)
const REGS_OFF: i32 = 0x000;
const TEMPS_OFF: i32 = 0x080;
const FLAGS_OFF: i32 = 0x0C0;
const VSP_OFF: i32 = 0x0C8;
const DEC_DST: i32 = 0x0D0;  // u8
const DEC_SRC1: i32 = 0x0D1; // u8
const DEC_SRC2: i32 = 0x0D2; // u8
const DEC_IMM1: i32 = 0x0D8; // u64
const DEC_IMM2: i32 = 0x0E0; // u64
const DEC_CIN: i32 = 0x0E8;  // u64
const STATE_END: i32 = 0x100;

// operand kind flags (OFF_OP_FLAGS)
const K_REG: u8 = 0;
const K_IMM: u8 = 1;
const K_NONE: u8 = 2;

const FLAG_MASK: u64 = 0x8C1; // CF|ZF|SF|OF

// Rolling-key engine constants (must match `RollingKeyEngine`).
const C1: u64 = 0x9E3779B97F4A7C15;
const C2: u64 = 0xBF58476D1CE4E5B9;
const C3: u64 = 0x517CC1B727220A95;
const C4: u64 = 0x1337BEEFCAFE0001;
const C5: u64 = 0x94D049BB133111EB;

// ── small code builder (two-pass branch patching, mirroring pass3) ──────────
struct CodeBuilder {
    instrs: Vec<Instruction>,
    /// (branch instruction index, target instruction index)
    branches: Vec<(usize, usize)>,
}

impl CodeBuilder {
    fn new() -> Self {
        Self { instrs: Vec::new(), branches: Vec::new() }
    }
    fn push(&mut self, i: Instruction) -> usize {
        self.instrs.push(i);
        self.instrs.len() - 1
    }
    fn len(&self) -> usize {
        self.instrs.len()
    }
    fn br(&mut self, code: Code, target: usize) {
        let idx = self.push(Instruction::with_branch(code, 0).unwrap());
        self.branches.push((idx, target));
    }
    fn jmp(&mut self, target: usize) {
        self.br(Code::Jmp_rel32_64, target);
    }
    fn jne(&mut self, target: usize) {
        self.br(Code::Jne_rel32_64, target);
    }
    fn je(&mut self, target: usize) {
        self.br(Code::Je_rel32_64, target);
    }
    fn call(&mut self, target: usize) {
        self.br(Code::Call_rel32_64, target);
    }

    fn assemble(&mut self, base_va: u64) -> Result<(Vec<u8>, Vec<u64>)> {
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

fn m(disp: i32) -> MemoryOperand {
    MemoryOperand::with_base_index_scale_displ_size(Register::RDX, Register::None, 1, disp as i64, 8)
}
fn m8(disp: i32) -> MemoryOperand {
    MemoryOperand::with_base_index_scale_displ_size(Register::RDX, Register::None, 1, disp as i64, 1)
}
fn movi(b: &mut CodeBuilder, r: Register, v: u64) {
    b.push(Instruction::with2(Code::Mov_r64_imm64, r, v).unwrap());
}
fn mov_m(b: &mut CodeBuilder, r: Register, disp: i32) {
    b.push(Instruction::with2(Code::Mov_r64_rm64, r, m(disp)).unwrap());
}
fn store_m(b: &mut CodeBuilder, disp: i32, r: Register) {
    b.push(Instruction::with2(Code::Mov_rm64_r64, m(disp), r).unwrap());
}
fn movzx8_m(b: &mut CodeBuilder, r: Register, disp: i32) {
    b.push(Instruction::with2(Code::Movzx_r32_rm8, r, m8(disp)).unwrap());
}

/// 8-byte little-endian immediate read via decrypt_byte calls, XOR operand_mask.
/// Result stored in the state DEC_* slot. Clobbers RAX,RCX,RBX,R11 (stream advanced).
///
/// NOTE: the 64-bit accumulator MUST be a register that `sub_decrypt` preserves.
/// `sub_decrypt` clobbers RAX/RCX/R9/R10/R11/R12/R14 but keeps RBX/R13/R15/RDX, so
/// we accumulate in RBX. The original code used R9 — on the 2nd..8th `call` the
/// partial immediate was destroyed by the callee, corrupting every decoded value.
fn emit_read_imm8(b: &mut CodeBuilder, slot: i32, sub_decrypt: usize, mask: u64) {
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

// ==============================================================================
// The native self-decoding dispatcher.
// ==============================================================================

pub fn run_native_poly_direct(bytecode: &[u8], seed: u64, init_regs: &[u64; 16]) -> Result<RiscEvalState> {
    let spec = VirtualIsaSpec::from_seed(seed);
    let mut arena = Arena::new(ARENA_SIZE)?;
    let code_base = (arena.base + OFF_CODE) as u64;
    let state_base = (arena.base + OFF_STATE) as u64;
    let table_base = (arena.base + OFF_TABLE) as u64;
    let bytecode_base = (arena.base + OFF_BYTECODE) as u64;
    let stack_base = (arena.base + OFF_STACK_BASE) as u64;
    let init_key = seed.wrapping_mul(C1) ^ 0x517CC1B727220A95;

    // operand offset / flag tables
    let mut offs_tab = vec![0u8; 256];
    let mut flags_tab = vec![K_NONE; 256];
    for raw in 0u16..256 {
        let raw = raw as u8;
        let kind = raw & 0xC0;
        let payload = raw & 0x3F;
        let (off, flag) = match kind {
            0x80 => {
                let idx = spec.decode_reg(payload) as usize;
                (REGS_OFF as u8 + (idx as u8) * 8, K_REG)
            }
            0xC0 => (TEMPS_OFF as u8 + (payload & 7) * 8, K_REG),
            0x40 => {
                if payload == 0x01 {
                    (FLAGS_OFF as u8, K_REG)
                } else {
                    (VSP_OFF as u8, K_REG)
                }
            }
            _ => {
                if raw == 0x01 {
                    (0, K_IMM)
                } else {
                    (0, K_NONE)
                }
            }
        };
        offs_tab[raw as usize] = off;
        flags_tab[raw as usize] = flag;
    }

    let mut b = CodeBuilder::new();

    // Entry is emitted later in this function; place a jump at the very start
    // (arena.call(OFF_CODE) targets index 0) that transfers control to it.
    let start_jmp = b.len();
    b.br(Code::Jmp_rel32_64, 0); // placeholder target, patched below to `entry`


    // decrypt_byte subroutine
    // in:  R8=bytecode_base, R12=vip, R14=current_key
    // out: AL=plaintext byte, R12+=1, R14=advanced key
    // preserves R13,R15,RDX,RBX; clobbers RAX,RCX,R9,R10,R11 (+R12,R14)
    let sub_decrypt = b.len();
    {
        // lane*8 -> R10D
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::R10D, Register::R12D).unwrap());
        b.push(Instruction::with2(Code::And_rm32_imm32, Register::R10D, 7).unwrap());
        b.push(Instruction::with2(Code::Shl_rm32_imm8, Register::R10D, 3).unwrap());
        // a = rol(key, lane*8)
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R14).unwrap());
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R10D).unwrap());
        b.push(Instruction::with2(Code::Rol_rm64_CL, Register::RAX, Register::CL).unwrap());
        // b = ror(key, (64-lane*8)&63)
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::R14).unwrap());
        b.push(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 64).unwrap());
        b.push(Instruction::with2(Code::Sub_rm32_r32, Register::ECX, Register::R10D).unwrap());
        b.push(Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap());
        b.push(Instruction::with2(Code::Ror_rm64_CL, Register::R9, Register::CL).unwrap());
        // x = (a+b)*C1
        b.push(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R9).unwrap());
        movi(&mut b, Register::RCX, C1);
        b.push(Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::RCX).unwrap());
        // y = x ^ (x>>32)
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R9, 32).unwrap());
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R9).unwrap());
        // z = y ^ (y>>16)
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R9, 16).unwrap());
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R9).unwrap());
        // ks = z0 ^ z8 ^ z24 (low bytes), keep z in RAX
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R9, 8).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R10, 24).unwrap());
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, Register::AL).unwrap());
        b.push(Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::R9D).unwrap());
        b.push(Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::R10D).unwrap());
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::CL).unwrap()); // al = ks
        // enc = [R8 + R12]; orig = enc ^ ks
        let enc_mem = MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::R12, 1, 0, 1);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, enc_mem).unwrap());
        b.push(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::ECX).unwrap()); // al = orig
        // save orig in R11D (low byte)
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::EAX).unwrap());
        // step(orig, vip): update R14
        // mixed = (k ^ orig*C2 ^ vip*C3) * C1 ; rol 17 ; + C4
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::R14).unwrap()); // k
        movi(&mut b, Register::RCX, C2);
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R11D).unwrap());
        b.push(Instruction::with2(Code::Imul_r64_rm64, Register::RCX, Register::RAX).unwrap()); // orig*C2
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::RCX).unwrap());
        movi(&mut b, Register::RCX, C3);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R12).unwrap()); // vip
        b.push(Instruction::with2(Code::Imul_r64_rm64, Register::RCX, Register::RAX).unwrap()); // vip*C3
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::RCX).unwrap());
        movi(&mut b, Register::RCX, C1);
        b.push(Instruction::with2(Code::Imul_r64_rm64, Register::R9, Register::RCX).unwrap());
        b.push(Instruction::with2(Code::Rol_rm64_imm8, Register::R9, 17).unwrap());
        movi(&mut b, Register::RCX, C4);
        b.push(Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::RCX).unwrap()); // mixed
        // rot = ((vip as u32) ^ (k>>32 as u32)) & 63
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R12D).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R14).unwrap());
        b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 32).unwrap());
        b.push(Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX).unwrap());
        b.push(Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R9).unwrap());
        b.push(Instruction::with2(Code::Rol_rm64_CL, Register::RAX, Register::CL).unwrap());
        // next = rol + k*C5
        movi(&mut b, Register::RCX, C5);
        b.push(Instruction::with2(Code::Imul_r64_rm64, Register::RCX, Register::R14).unwrap());
        b.push(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap());
        // vip++
        b.push(Instruction::with1(Code::Inc_rm64, Register::R12).unwrap());
        // return orig in AL
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R11D).unwrap());
        b.push(Instruction::with(Code::Retnq));
    }

    // decode_operands subroutine: dst/src1/src2 + immediates (+cin for AddWithCarry)
    // in: R8,R12,R14 stream; R15=table_base; RDX=state
    // out: DEC_DST/SRC1/SRC2/IMM1/IMM2/CIN filled
    let sub_dec_ops = b.len();
    {
        b.call(sub_decrypt);
        b.push(Instruction::with2(Code::Mov_rm8_r8, m8(DEC_DST), Register::AL).unwrap());
        b.call(sub_decrypt);
        b.push(Instruction::with2(Code::Mov_rm8_r8, m8(DEC_SRC1), Register::AL).unwrap());
        b.call(sub_decrypt);
        b.push(Instruction::with2(Code::Mov_rm8_r8, m8(DEC_SRC2), Register::AL).unwrap());
        // imm1 if src1 == 0x01
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 0x01).unwrap());
        let after_imm1 = b.len() + 1;
        b.jne(after_imm1);
        emit_read_imm8(&mut b, DEC_IMM1, sub_decrypt, spec.operand_mask);
        let t1 = b.len();
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == after_imm1 {
                *ti = t1;
            }
        }
        // imm2 if src2 == 0x01
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 0x01).unwrap());
        let after_imm2 = b.len() + 1;
        b.jne(after_imm2);
        emit_read_imm8(&mut b, DEC_IMM2, sub_decrypt, spec.operand_mask);
        let t2 = b.len();
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == after_imm2 {
                *ti = t2;
            }
        }
        // Note: cin is NOT decoded generically here — it is only present for
        // AddWithCarry (handled in the ADD handler). Reading it here would wrongly
        // consume 8 bytes for other ops with register operands.
        b.push(Instruction::with(Code::Retnq));
    }

    // resolve_src subroutine: al = raw operand byte; R11=imm; returns value in RAX
    let sub_resolve = b.len();
    {
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
        let fm = MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::RAX, 1, (OFF_OP_FLAGS - OFF_TABLE) as i64, 1);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, fm).unwrap());
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, K_IMM as u32).unwrap());
        let l_imm = b.len() + 2;
        b.je(l_imm);
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, K_NONE as u32).unwrap());
        let l_none = b.len() + 2;
        b.je(l_none);
        let om = MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::RAX, 1, (OFF_OP_OFFS - OFF_TABLE) as i64, 1);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, om).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base_index_scale_displ_size(Register::RDX, Register::RCX, 1, 0, 8)).unwrap());
        b.push(Instruction::with(Code::Retnq));
        let l_done_imm = b.len();
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap());
        b.push(Instruction::with(Code::Retnq));
        let l_done_none = b.len();
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RAX).unwrap());
        b.push(Instruction::with(Code::Retnq));
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == l_imm {
                *ti = l_done_imm;
            }
            if *ti == l_none {
                *ti = l_done_none;
            }
        }
    }

    // store_dst subroutine: RAX=value; store per DEC_DST if reg/temp
    let sub_store = b.len();
    {
        movzx8_m(&mut b, Register::ECX, DEC_DST);
        let fm = MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::RCX, 1, (OFF_OP_FLAGS - OFF_TABLE) as i64, 1);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, fm).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9).unwrap());
        let l_skip = b.len() + 1;
        b.jne(l_skip);
        let om = MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::RCX, 1, (OFF_OP_OFFS - OFF_TABLE) as i64, 1);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, om).unwrap());
        b.push(Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::RDX, Register::RCX, 1, 0, 8), Register::RAX).unwrap());
        let l_done = b.len();
        b.push(Instruction::with(Code::Retnq));
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == l_skip {
                *ti = l_done;
            }
        }
    }

    // store_flags helper inline macro: after a `test`/flags set, merge into FLAGS slot.
    fn emit_store_flags(b: &mut CodeBuilder) {
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, FLAG_MASK as u32).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!FLAG_MASK) as i32).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
        store_m(b, FLAGS_OFF, Register::RAX);
    }

    // entry
    let entry = b.len();
    // Patch the leading jump (start_jmp) to transfer control to entry.
    for &mut (bi, ref mut ti) in b.branches.iter_mut() {
        if bi == start_jmp {
            *ti = entry;
        }
    }
    {
        b.push(Instruction::with1(Code::Push_r64, Register::R12).unwrap());
        b.push(Instruction::with1(Code::Push_r64, Register::R13).unwrap());
        b.push(Instruction::with1(Code::Push_r64, Register::R14).unwrap());
        b.push(Instruction::with1(Code::Push_r64, Register::R15).unwrap());
        movi(&mut b, Register::R8, bytecode_base);
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R12, Register::R12).unwrap());
        movi(&mut b, Register::R13, stack_base);
        movi(&mut b, Register::R14, init_key);
        movi(&mut b, Register::R15, table_base);
        movi(&mut b, Register::RDX, state_base);
    }

    // dispatch loop
    let dispatch = b.len();
    {
        b.call(sub_decrypt);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
        let tbl = MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::RAX, 8, 0, 8);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, tbl).unwrap());
        b.push(Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap());
    }

    // helper: resolve src1 -> R10, src2 -> R11 (inline per handler)
    // (each handler calls decode_operands then resolves)

    let h_nop = b.len();
    {
        b.call(sub_dec_ops);
        b.jmp(dispatch);
    }

    let h_nor = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        mov_m(&mut b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::R10, Register::R11).unwrap());
        b.push(Instruction::with1(Code::Not_rm64, Register::R10).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap());
        emit_store_flags(&mut b);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    let h_add = b.len();
    {
        b.call(sub_dec_ops);
        // cin is present only when src1 and src2 are both non-immediate (encoder contract).
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 0x01).unwrap());
        let no_cin = b.len() + 1;
        b.je(no_cin);
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 0x01).unwrap());
        let no_cin2 = b.len() + 1;
        b.je(no_cin2);
        emit_read_imm8(&mut b, DEC_CIN, sub_decrypt, spec.operand_mask);
        let cin_done = b.len();
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == no_cin || *ti == no_cin2 {
                *ti = cin_done;
            }
        }
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        mov_m(&mut b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        mov_m(&mut b, Register::RAX, DEC_CIN);
        // save a in RBX, b in R9 for OF
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R10).unwrap()); // a
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::R11).unwrap()); // b
        // res = a+b ; capture CF (c1)
        b.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11).unwrap());
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RCX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 1).unwrap()); // c1
        // res += cin ; capture CF (c2)
        b.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RCX, Register::RAX).unwrap()); // CF = c1|c2
        // ZF|SF from res (test)
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap());
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xC0).unwrap()); // ZF|SF
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap()); // +CF
        // OF = ((a^res)&(b^res))>>63, placed at bit 11
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RBX, Register::R10).unwrap()); // a^res
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::R10).unwrap()); // b^res
        b.push(Instruction::with2(Code::And_rm64_r64, Register::RBX, Register::R9).unwrap());
        b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RBX, 63).unwrap());
        b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RBX, 11).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RBX).unwrap());
        // merge with slot preserving PF/AF
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!FLAG_MASK) as i32).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
        store_m(&mut b, FLAGS_OFF, Register::RAX);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    let h_shr = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        mov_m(&mut b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::R11, 63).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R11, Register::R11).unwrap());
        let skip0 = b.len() + 1;
        b.je(skip0);
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).unwrap());
        b.push(Instruction::with2(Code::Shr_rm64_CL, Register::R10, Register::CL).unwrap());
        let done0 = b.len();
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == skip0 {
                *ti = done0;
            }
        }
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap());
        emit_store_flags(&mut b);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    let h_shl = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        mov_m(&mut b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::R11, 63).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R11, Register::R11).unwrap());
        let skip0 = b.len() + 1;
        b.je(skip0);
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).unwrap());
        b.push(Instruction::with2(Code::Shl_rm64_CL, Register::R10, Register::CL).unwrap());
        let done0 = b.len();
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == skip0 {
                *ti = done0;
            }
        }
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap());
        emit_store_flags(&mut b);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    let h_push = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Sub_rm64_imm8, Register::R13, 8).unwrap());
        let sp = MemoryOperand::with_base(Register::R13);
        b.push(Instruction::with2(Code::Mov_rm64_r64, sp, Register::R10).unwrap());
        mov_m(&mut b, Register::RAX, VSP_OFF);
        b.push(Instruction::with2(Code::Sub_rm64_imm8, Register::RAX, 8).unwrap());
        store_m(&mut b, VSP_OFF, Register::RAX);
        b.jmp(dispatch);
    }

    let h_pop = b.len();
    {
        b.call(sub_dec_ops);
        let sp = MemoryOperand::with_base(Register::R13);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, sp).unwrap());
        b.push(Instruction::with2(Code::Add_rm64_imm8, Register::R13, 8).unwrap());
        mov_m(&mut b, Register::RAX, VSP_OFF);
        b.push(Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 8).unwrap());
        store_m(&mut b, VSP_OFF, Register::RAX);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    let h_setflag = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x8D5).unwrap());
        store_m(&mut b, FLAGS_OFF, Register::RAX);
        b.jmp(dispatch);
    }

    let h_halt = b.len();
    {
        b.push(Instruction::with1(Code::Pop_r64, Register::R15).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::R14).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::R13).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::R12).unwrap());
        b.push(Instruction::with(Code::Retnq));
    }

    let handlers: std::collections::HashMap<RiscOp, usize> = {
        use std::collections::HashMap;
        let mut h = HashMap::new();
        h.insert(RiscOp::Nor, h_nor);
        h.insert(RiscOp::AddWithCarry, h_add);
        h.insert(RiscOp::ShiftRight, h_shr);
        h.insert(RiscOp::ShiftLeft, h_shl);
        h.insert(RiscOp::VirtualPush, h_push);
        h.insert(RiscOp::VirtualPop, h_pop);
        h.insert(RiscOp::SetFlag, h_setflag);
        h.insert(RiscOp::Halt, h_halt);
        h
    };

    // Assemble; use the true per-instruction IPs for handler VAs.
    let (code, ips) = b.assemble(code_base)?;
    let va_of = |idx: usize| -> u64 { ips[idx] };

    if std::env::var("BTG_DUMP_POLY").is_ok() {
        let mut s = String::new();
        let mut dec = iced_x86::Decoder::with_ip(64, &code, code_base, iced_x86::DecoderOptions::NONE);
        let mut n = 0;
        while dec.can_decode() && n < 4000 {
            let ins = dec.decode();
            if ins.is_invalid() {
                s.push_str(&format!("INVALID @ 0x{:08x}\n", ins.ip()));
                break;
            }
            s.push_str(&format!("0x{:08x}  {:?}\n", ins.ip(), ins));
            n += 1;
        }
        let _ = std::fs::write("C:\\Users\\uzoki\\Desktop\\asdfsadfecwecc\\_poly_dump.txt", s);
    }

    // Handler table: decrypted opcode byte -> handler VA.
    let mut table = vec![va_of(h_nop) as u64; 256];
    for (op, byte) in &spec.opcode_map {
        if let Some(&hidx) = handlers.get(op) {
            table[*byte as usize] = va_of(hidx);
        }
    }

    // Copy into arena.
    {
        let buf = arena.bytes();
        buf[OFF_CODE..OFF_CODE + code.len()].copy_from_slice(&code);
        for (i, v) in table.iter().enumerate() {
            buf[OFF_TABLE + i * 8..OFF_TABLE + i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        buf[OFF_OP_OFFS..OFF_OP_OFFS + 256].copy_from_slice(&offs_tab);
        buf[OFF_OP_FLAGS..OFF_OP_FLAGS + 256].copy_from_slice(&flags_tab);
        buf[OFF_BYTECODE..OFF_BYTECODE + bytecode.len()].copy_from_slice(bytecode);
        buf[OFF_STATE..OFF_STATE + STATE_END as usize].fill(0);
        buf[OFF_STACK_BASE - 0x2000..OFF_STACK_BASE].fill(0);
        for (i, v) in init_regs.iter().enumerate() {
            buf[OFF_STATE + REGS_OFF as usize + i * 8..OFF_STATE + REGS_OFF as usize + i * 8 + 8]
                .copy_from_slice(&v.to_le_bytes());
        }
    }

    arena.call(OFF_CODE);

    let buf = arena.bytes();
    let s = OFF_STATE;
    let mut st = RiscEvalState::default();
    for i in 0..16 {
        st.regs[i] = u64::from_le_bytes(buf[s + REGS_OFF as usize + i * 8..s + REGS_OFF as usize + i * 8 + 8].try_into().unwrap());
    }
    for i in 0..8 {
        st.temps[i] = u64::from_le_bytes(buf[s + TEMPS_OFF as usize + i * 8..s + TEMPS_OFF as usize + i * 8 + 8].try_into().unwrap());
    }
    st.flags = u64::from_le_bytes(buf[s + FLAGS_OFF as usize..s + FLAGS_OFF as usize + 8].try_into().unwrap());
    st.vsp = u64::from_le_bytes(buf[s + VSP_OFF as usize..s + VSP_OFF as usize + 8].try_into().unwrap());
    let pending = if (st.vsp as i64) < 0 { (-(st.vsp as i64) as u64) / 8 } else { 0 };
    let mut stack = Vec::new();
    for k in 0..pending as usize {
        let base = OFF_STACK_BASE as isize - ((k + 1) as isize) * 8;
        let base = base as usize;
        let v = u64::from_le_bytes(buf[base..base + 8].try_into().unwrap());
        stack.push(v);
    }
    st.stack = stack;
    Ok(st)
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::poly::{PolymorphicEncoder, PolymorphicInterpreter};
    use crate::vm::risc::RiscDesynthesizer;

    /// Differential: native self-decoding == interpreter == reference.
    #[test]
    fn test_native_poly_direct_matches_interpreter_and_reference() {
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x200), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(5), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftRight)
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftLeft)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(2)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::AddWithCarry)
                .with_dst(MicroOperand::VReg(7))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1))
                .with_imm(0),
        );
        d.emit_push(MicroOperand::VReg(3));
        d.emit_push(MicroOperand::VReg(0));
        d.emit_pop(MicroOperand::VReg(4));
        d.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::VReg(1)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);

        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();

            let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16]).unwrap();

            let mut interp = PolymorphicInterpreter::new(seed);
            interp.run(&bytecode).unwrap();

            let ref_st = prog.eval_state(&[0u64; 16]);

            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: native regs != ref");
            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: interp regs != ref");
            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: native temps != ref");
            assert_eq!(
                native.flags, ref_st.flags,
                "seed {seed:#x}: native flags {:#x} != ref {:#x}",
                native.flags, ref_st.flags
            );
            assert_eq!(interp.flags.raw, ref_st.flags, "seed {seed:#x}: interp flags != ref");
            assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: native vsp != ref");
            assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: native stack != ref");
            assert_eq!(native.regs[2], 0x10);
            assert_eq!(native.regs[3], 0x800);
            assert_eq!(native.regs[5], !(0x10 | 5));
        }
    }

    /// Simple add/xor/sub path.
    #[test]
    fn test_native_poly_direct_matches_decoder_path() {
        let seed = 0x8899AABBCCDDEEFF;
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(1200), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(450), MicroOperand::Imm64(0));
        d.emit_sub(MicroOperand::VReg(0), MicroOperand::VReg(0), MicroOperand::VReg(1));
        d.emit_xor(MicroOperand::VReg(0), MicroOperand::VReg(0), MicroOperand::Imm64(0x55));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);

        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();

        let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16]).unwrap();
        let ref_st = prog.eval_state(&[0u64; 16]);
        assert_eq!(native.regs[0], ref_st.regs[0]);
        assert_eq!(native.regs[1], ref_st.regs[1]);
        assert_eq!(native.regs[0], (1200 - 450) ^ 0x55);
    }
}
