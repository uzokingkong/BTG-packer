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
use crate::vm::poly::{PolymorphicDecoder, PolymorphicEncoder, VirtualIsaSpec};
use crate::vm::risc::{BranchCondition, MicroInstr, MicroOperand, RiscEvalState, RiscOp, RiscProgram};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};

// ── arena layout ─────────────────────────────────────────────────────────────
const OFF_CODE: usize = 0x1000;      // entry + dispatch + handlers + helpers
const OFF_TABLE: usize = 0x8000;     // handler table: decrypted opcode byte -> handler VA (256 x u64)
const OFF_OP_OFFS: usize = 0x8800;   // operand-encoding -> state offset (256 x u8)
const OFF_OP_FLAGS: usize = 0x8900;  // operand-encoding -> kind flag (256 x u8): 0=reg/temp/vsp/flags,1=imm,2=none
const OFF_COND_CODES: usize = 0x8A00; // decrypted cond byte -> canonical COND_* code (256 x u8)
const OFF_BRANCH_MAP: usize = 0x8B00; // branch-resolution table: u32 count + count x (u64 target_value, u64 byte_offset)
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
const DEC_COND: i32 = 0x0D3; // u8  — decoded branch condition byte (VirtualBranch/Setcc/CMOV)
const DEC_IMM1: i32 = 0x0D8; // u64
const DEC_IMM2: i32 = 0x0E0; // u64
const DEC_CIN: i32 = 0x0E8;  // u64
const STATE_END: i32 = 0x100;

// operand kind flags (OFF_OP_FLAGS)
const K_REG: u8 = 0;
const K_IMM: u8 = 1;
const K_NONE: u8 = 2;

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

const FLAG_MASK: u64 = 0x8C1; // CF|ZF|SF|OF

/// Map a `BranchCondition` to its canonical native code (OFF_COND_CODES value).
fn cond_code(cond: BranchCondition) -> u8 {
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

/// P3 (G1): assembled self-decoding dispatcher pieces (machine code + tables).
pub struct SelfDecodingParts {
    pub code: Vec<u8>,
    /// 256 x u64 handler table (decrypted opcode byte -> handler VA).
    pub table: Vec<u64>,
    /// 256 x u8 operand-offset table (operand-encoding -> state offset).
    pub offs_tab: Vec<u8>,
    /// 256 x u8 operand-kind table (0=reg/temp/vsp/flags, 1=imm, 2=none).
    pub flags_tab: Vec<u8>,
    /// 256 x u8 cond-code table (decrypted cond byte -> canonical COND_* code, 0xFF invalid).
    pub cond_codes: Vec<u8>,
}

/// P3 (G1): build the self-decoding rolling-key dispatcher machine code and its
/// handler/operand tables, parameterized by the VAs the caller will place them
/// at. This is the *verified* commercial execution engine (T1-4): the native
/// runtime itself decrypts the poly bytecode with the rolling key, decodes
/// operands and dispatches through the handler table.
///
/// `code_base` = where the assembled `code` is placed, `table_base` = handler
/// table VA, `bytecode_base` = encrypted poly stream VA, `state_base` = VM state
/// buffer VA, `stack_base` = virtual stack top VA. The `code` embeds these as
/// absolute immediates in the entry stub.
pub fn build_self_decoding_parts(
    bytecode: &[u8],
    seed: u64,
    code_base: u64,
    table_base: u64,
    bytecode_base: u64,
    state_base: u64,
    stack_base: u64,
) -> Result<SelfDecodingParts> {
    let spec = VirtualIsaSpec::from_seed(seed);
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

    // cond-codes table: decrypted cond byte -> canonical COND_* code (0xFF = unknown).
    // Built from the spec's reverse_branch_cond_map so native handlers can switch
    // on a stable COND_* code instead of the seed-randomized cond bytes.
    let mut cond_codes = vec![COND_INVALID; 256];
    for (cond, &byte) in &spec.branch_cond_map {
        cond_codes[byte as usize] = cond_code(*cond);
    }

    // ── branch-resolution map (OFF_BRANCH_MAP / table_va+0xB00) ────────────────
    // Decode the (encrypted) bytecode back to a RiscProgram and re-encode to learn
    // each micro-op's bytecode byte offset. Then build a sorted (target_value ->
    // byte_offset) table that the native VirtualBranch handler scans at runtime:
    //   * every absolute-index VirtualBranch target (src1 == none) is resolved
    //     through ip_map when present (source-IP -> byte offset), else treated as a
    //     direct micro-op index (offset fallback) — matching `RiscProgram::resolve_target`;
    //   * every ip_map entry is also emitted (source-IP -> byte offset) so dynamic /
    //     indirect branch targets (jmp reg) resolve too.
    // The rolling-key re-sync then jumps to the resolved byte offset (forward or
    // backward), decrypting intermediate bytes so the key state matches the encoder's.
    // ip_map is optional; when absent, absolute-index VirtualBranch targets fall
    // back to direct micro-op index resolution (matching `resolve_target`).
    let ip_map: Option<&HashMap<u64, usize>> = None;
    let mut dec = PolymorphicDecoder::new(seed);
    let prog = dec.decode(bytecode)?;
    let mut reenc = PolymorphicEncoder::new(seed);
    let (_re_bc, op_offsets) = reenc.encode_with_offsets(&prog)?;
    debug_assert_eq!(_re_bc, bytecode, "decode+re-encode must reproduce the bytecode");
    let resolve_off = |tgt: u64, op_offsets: &[usize], ip_map: &Option<&HashMap<u64, usize>>| -> Option<u64> {
        if let Some(im) = ip_map {
            if let Some(&idx) = im.get(&tgt) {
                return op_offsets.get(idx).copied().map(|o| o as u64);
            }
        }
        if (tgt as usize) < op_offsets.len() {
            return Some(op_offsets[tgt as usize] as u64);
        }
        None
    };
    let mut entries: Vec<(u64, u64)> = Vec::new();
    for ins in &prog.instrs {
        if let RiscOp::VirtualBranch { .. } = ins.op {
            if ins.src1.is_none() {
                if let Some(off) = resolve_off(ins.imm, &op_offsets, &ip_map) {
                    entries.push((ins.imm, off));
                }
            }
        }
    }
    if let Some(im) = ip_map {
        for (&src_ip, &idx) in im {
            if let Some(&off) = op_offsets.get(idx) {
                entries.push((src_ip, off as u64));
            }
        }
    }
    entries.sort_unstable_by_key(|e| e.0);
    entries.dedup_by_key(|e| e.0);
    let mut branch_map = Vec::new();
    branch_map.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (k, off) in entries {
        branch_map.extend_from_slice(&k.to_le_bytes());
        branch_map.extend_from_slice(&off.to_le_bytes());
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

    // decode_cond subroutine: decrypt ONE cond byte (right after the opcode for
    // VirtualBranch/Setcc/ConditionalMove), map it to a canonical COND_* code via
    // the cond-codes table, store it into DEC_COND, and return it in AL.
    // in: R8,R12,R14 stream; R15=table_base; RDX=state
    // out: DEC_COND slot = canonical COND_* code; AL = same code
    let sub_dec_ops_cond = b.len();
    {
        b.call(sub_decrypt); // AL = decrypted cond byte (stream advanced)
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
        let cm = MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::RAX, 1, (OFF_COND_CODES - OFF_TABLE) as i64, 1);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, cm).unwrap());
        b.push(Instruction::with2(Code::Mov_rm8_r8, m8(DEC_COND), Register::CL).unwrap());
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::ECX).unwrap());
        b.push(Instruction::with(Code::Retnq));
    }

    // eval_cond subroutine: DEC_COND (canonical code) + FLAGS slot + regs[1] -> taken.
    // in: RDX=state; R8/R12/R14 untouched. out: AL = 1 (taken) / 0 (not taken).
    // Clobbers RAX, RCX, R8; preserves RBX, R9, R10, R11, R12, R13, R14, R15, RDX.
    let sub_eval_cond = b.len();
    {
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, m8(DEC_COND)).unwrap());
        for k in 0..22u32 {
            b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, k as i32).unwrap());
            b.br(Code::Je_rel32_64, 0x1000 + k as usize);
        }
        // unknown cond code -> not taken.
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RAX).unwrap());
        b.br(Code::Jmp_rel32_64, 0x9000);
        // fragments
        let mut frag_idx = [0usize; 22];
        for k in 0..22 {
            frag_idx[k] = b.len();
            if k == 0 {
                // Always
                b.push(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 1).unwrap());
            } else if k >= 19 {
                // CounterZero(w): virtual RCX (regs[1]) low w bytes == 0
                let width = if k == 19 { 2 } else if k == 20 { 4 } else { 8 };
                let mem = MemoryOperand::with_base_index_scale_displ_size(
                    Register::RDX, Register::None, 1, (REGS_OFF + 8) as i64, width as u32,
                );
                match width {
                    2 => b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, mem).unwrap()),
                    4 => b.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem).unwrap()),
                    _ => b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, mem).unwrap()),
                }
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
                b.push(Instruction::with1(Code::Setz_rm8, Register::R8L).unwrap());
                b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::R8L).unwrap());
            } else {
                // flag-based: the FLAGS slot uses x86 RFLAGS bit layout (CF=1,ZF=0x40,
                // SF=0x80,OF=0x800,PF=4), so load it into RFLAGS and use the setcc
                // matching the x86 condition code semantics.
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(FLAGS_OFF)).unwrap());
                b.push(Instruction::with(Code::Pushfq));
                b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
                let setcc = match k {
                    1 => Code::Setz_rm8,
                    2 => Code::Setnz_rm8,
                    3 => Code::Setc_rm8,
                    4 => Code::Setnc_rm8,
                    5 => Code::Sets_rm8,
                    6 => Code::Setns_rm8,
                    7 => Code::Seto_rm8,
                    8 => Code::Setno_rm8,
                    9 => Code::Setg_rm8,
                    10 => Code::Setl_rm8,
                    11 => Code::Setge_rm8,
                    12 => Code::Setle_rm8,
                    13 => Code::Seta_rm8,
                    14 => Code::Setae_rm8,
                    15 => Code::Setb_rm8,
                    16 => Code::Setbe_rm8,
                    17 => Code::Setp_rm8,
                    _ => Code::Setnp_rm8,
                };
                b.push(Instruction::with1(setcc, Register::R8L).unwrap());
                b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::R8L).unwrap());
            }
            b.br(Code::Jmp_rel32_64, 0x9000);
        }
        let done = b.len();
        b.push(Instruction::with(Code::Retnq));
        for i in 0..b.branches.len() {
            let t = b.branches[i].1;
            if (0x1000..0x1000 + 22).contains(&t) {
                b.branches[i].1 = frag_idx[t - 0x1000];
            } else if t == 0x9000 {
                b.branches[i].1 = done;
            }
        }
    }

    // resync_key subroutine: advance (forward) or rewind (reverse) the rolling-key
    // state so R14 matches the encoder's key at RBX (target byte offset). Decrypting
    // intermediate bytes feeds the plaintext feedback of `step`, so the key state at
    // the target is reproduced exactly (linear-extension property of the rolling key).
    // in: RBX = target byte offset; R12 = current vip; R14 = current key; R8 = bytecode_base.
    // out: R12 = target; R14 = key at target. Clobbers RAX,RCX,R9,R10,R11; preserves RBX,R13,R15,RDX.
    let sub_resync = b.len();
    {
        b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R12, Register::RBX).unwrap());
        b.br(Code::Je_rel32_64, 0x9100); // equal -> done
        b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R12, Register::RBX).unwrap());
        b.br(Code::Ja_rel32_64, 0x9101); // R12 > RBX -> reverse
        // forward: fall through to the loop
        let loop_top = b.len();
        {
            b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R12, Register::RBX).unwrap());
            b.br(Code::Jae_rel32_64, 0x9100); // R12 >= RBX -> done
            b.call(sub_decrypt);
            b.jmp(loop_top);
        }
        let reverse = b.len();
        movi(&mut b, Register::R14, init_key);
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R12, Register::R12).unwrap());
        b.jmp(loop_top);
        let done = b.len();
        b.push(Instruction::with(Code::Retnq));
        for i in 0..b.branches.len() {
            let t = b.branches[i].1;
            if t == 0x9100 {
                b.branches[i].1 = done;
            } else if t == 0x9101 {
                b.branches[i].1 = reverse;
            }
        }
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

    // store_zf helper: after an op that sets ZF (BSF/BSR), merge only ZF into FLAGS.
    fn emit_store_zf(b: &mut CodeBuilder) {
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x40).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x40i32)).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
        store_m(b, FLAGS_OFF, Register::RAX);
    }

    // store CF|ZF helper for TZCNT/LZCNT: the reference sets ZF=1 when the
    // (width-truncated) source is zero, which HW tzcnt/lzcnt reports via CF, so
    // ZF' = ZF_hw | CF_hw.
    fn emit_store_cf_zf_tz(b: &mut CodeBuilder) {
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x41).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 1).unwrap());
        b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 6).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x41i32)).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
        store_m(b, FLAGS_OFF, Register::RAX);
    }

    // store flags for PopCount: after `test`, capture CF|PF|ZF|SF|OF (0x8C5) to match
    // update_logic64 (reference sets PF too), preserving AF from the slot.
    fn emit_store_flags_popcnt(b: &mut CodeBuilder) {
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x8C5).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x8C5i32)).unwrap());
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

    // ── P3: VIRTUAL_BRANCH — conditional branch: DEC_COND decides taken/not-taken;
    //    a taken branch resolves the target to a bytecode byte offset via the branch
    //    map (OFF_BRANCH_MAP, built from ip_map) and re-syncs the rolling key (forward
    //    or reverse) before dispatching to the target instruction.
    let h_branch = b.len();
    {
        b.call(sub_dec_ops_cond); // cond byte -> DEC_COND
        b.call(sub_dec_ops);      // dst/src1/src2 + imms (consumes the stream)
        // absolute-index target (src1 == 0x00): read the 8B target into DEC_IMM1.
        // This must be consumed even when not-taken so the key stays in sync.
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        b.push(Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap());
        b.br(Code::Je_rel32_64, 0xA100); // src1 == 0x00 -> absolute target read
        // dynamic target: resolve src1 into DEC_IMM1 (indirect branch).
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        store_m(&mut b, DEC_IMM1, Register::RAX);
        b.br(Code::Jmp_rel32_64, 0xA200); // -> after_all
        let abs_read = b.len();
        emit_read_imm8(&mut b, DEC_IMM1, sub_decrypt, spec.operand_mask);
        let after_all = b.len();
        // evaluate the condition (AL = taken).
        b.call(sub_eval_cond);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
        b.br(Code::Je_rel32_64, 0x9300); // not taken -> dispatch (fall through)
        // taken: target value = [DEC_IMM1] -> R10.
        mov_m(&mut b, Register::R10, DEC_IMM1);
        // branch-map base = R15 + (OFF_BRANCH_MAP - OFF_TABLE); linear-scan for R10.
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R15).unwrap());
        b.push(Instruction::with2(Code::Add_rm64_imm32, Register::RBX, (OFF_BRANCH_MAP - OFF_TABLE) as i32).unwrap());
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, MemoryOperand::with_base(Register::RBX)).unwrap()); // count
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
        b.br(Code::Je_rel32_64, 0x9400); // count == 0 -> not found
        b.push(Instruction::with2(Code::Lea_r64_m64, Register::R11, MemoryOperand::with_base_displ_size(Register::RBX, 4, 8)).unwrap());
        let scan_top = b.len();
        {
            b.push(Instruction::with2(Code::Cmp_rm64_r64, MemoryOperand::with_base(Register::R11), Register::R10).unwrap());
            b.br(Code::Je_rel32_64, 0x9401); // found
            b.push(Instruction::with2(Code::Add_rm64_imm32, Register::R11, 16).unwrap());
            b.push(Instruction::with1(Code::Dec_rm64, Register::RCX).unwrap());
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
            b.jne(scan_top);
        }
        // not found (fallback): treat the target value as a direct byte offset.
        let nf_real = b.len();
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R10).unwrap());
        b.br(Code::Jmp_rel32_64, 0x9500);
        // found: byte offset = [R11 + 8].
        let found_real = b.len();
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, MemoryOperand::with_base_displ_size(Register::R11, 8, 8)).unwrap());
        b.br(Code::Jmp_rel32_64, 0x9500);
        // re-sync the rolling key to the target byte offset, then dispatch.
        let resync = b.len();
        b.call(sub_resync);
        b.jmp(dispatch);
        // not-taken path: stream already points at the next instruction (key synced).
        let not_taken_real = b.len();
        b.jmp(dispatch);
        for i in 0..b.branches.len() {
            let t = b.branches[i].1;
            if t == 0xA100 {
                b.branches[i].1 = abs_read;
            } else if t == 0xA200 {
                b.branches[i].1 = after_all;
            } else if t == 0x9300 {
                b.branches[i].1 = not_taken_real;
            } else if t == 0x9400 {
                b.branches[i].1 = nf_real;
            } else if t == 0x9401 {
                b.branches[i].1 = found_real;
            } else if t == 0x9500 {
                b.branches[i].1 = resync;
            }
        }
    }

    let h_halt = b.len();
    {
        b.push(Instruction::with1(Code::Pop_r64, Register::R15).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::R14).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::R13).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::R12).unwrap());
        b.push(Instruction::with(Code::Retnq));
    }

    // ── P3: MOV — dst = src1 (no flags). ──
    let h_mov = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RAX).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    // ── P3: ARITHMETIC_SHIFT_RIGHT — sar r10, cl (flags via test). ──
    let h_ashr = b.len();
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
        b.push(Instruction::with2(Code::Sar_rm64_CL, Register::R10, Register::CL).unwrap());
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

    // ── P3: MEMORY_READ{width} — R10 = addr; R10 = *(addr, width); store dst. ──
    let h_memrd8 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        let m = MemoryOperand::with_base(Register::R10);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }
    let h_memrd4 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        let m = MemoryOperand::with_base(Register::R10);
        // Writing R10D zero-extends into R10 (x86-64 semantics).
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::R10D, m).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }
    let h_memrd2 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        let m = MemoryOperand::with_base(Register::R10);
        b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, m).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }
    let h_memrd1 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        let m = MemoryOperand::with_base(Register::R10);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    // ── P3: MEMORY_WRITE{width} — R10=addr, R11=value; *(addr,width)=value. ──
    let h_memwr8 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        mov_m(&mut b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        let m = MemoryOperand::with_base(Register::R10);
        b.push(Instruction::with2(Code::Mov_rm64_r64, m, Register::RAX).unwrap());
        b.jmp(dispatch);
    }
    let h_memwr4 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        mov_m(&mut b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        let m = MemoryOperand::with_base(Register::R10);
        b.push(Instruction::with2(Code::Mov_rm32_r32, m, Register::EAX).unwrap());
        b.jmp(dispatch);
    }
    let h_memwr2 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        mov_m(&mut b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        let m = MemoryOperand::with_base(Register::R10);
        b.push(Instruction::with2(Code::Mov_rm16_r16, m, Register::AX).unwrap());
        b.jmp(dispatch);
    }
    let h_memwr1 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        mov_m(&mut b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        let m = MemoryOperand::with_base(Register::R10);
        b.push(Instruction::with2(Code::Mov_rm8_r8, m, Register::AL).unwrap());
        b.jmp(dispatch);
    }

    // ── P2: Multiply (1-op MUL/IMUL) / MultiplyLow (2/3-op IMUL) ────────────────
    // Matches `eval_state::mul_wide` / `mul_low`: full = (a&mask)*(b&mask) as u128
    // (unsigned product of the width-masked operands), low = full, high =
    // (full>>bits)&mask. `signed` only affects the overflow (CF=OF) flag. For
    // Multiply (write_rdx) width>=2 the high half is stored to RDX (regs[2]);
    // width 1 packs AX = (high<<8)|low. MultiplyLow never writes RDX.
    //
    // Register contract: physical RDX holds the state_base pointer and must be
    // preserved across the 64x64 `mul` (which clobbers RDX:RAX), so we stage it
    // in RBX (RBX is preserved by sub_decrypt / sub_resolve / sub_store).
    fn emit_mul_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        sub_store: usize,
        signed: bool,
        width: u8,
        write_rdx: bool,
        dispatch: usize,
    ) {
        let bits = width as u32 * 8;
        let mask: u64 = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        b.call(sub_dec_ops);
        // src1 -> R10
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        // src2 -> R11
        movzx8_m(b, Register::EAX, DEC_SRC2);
        mov_m(b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        // width-mask the operands (zero-extend the kept low bits).
        match width {
            1 => {
                b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).unwrap());
                b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R11D, Register::R11L).unwrap());
            }
            2 => {
                b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::R10W).unwrap());
                b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R11D, Register::R11W).unwrap());
            }
            4 => {
                b.push(Instruction::with2(Code::Mov_r32_rm32, Register::R10D, Register::R10D).unwrap());
                b.push(Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::R11D).unwrap());
            }
            _ => {}
        }
        // stage state_base (RDX) in RBX, then RDX:RAX = a*b.
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RDX).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.push(Instruction::with1(Code::Mul_rm64, Register::R11).unwrap());
        // high = (full>>bits)&mask -> R9 (low = RAX). For bits<64 the product
        // already fits in RAX so no mask is needed after the shift.
        if bits == 64 {
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RDX).unwrap());
        } else {
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RAX).unwrap());
            b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R9, bits as i32).unwrap());
        }
        // width 1 packs the 16-bit AX result (low|high<<8).
        if width == 1 {
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap());
        }
        // restore state_base.
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RBX).unwrap());
        // Multiply (write_rdx) width>=2: store high to RDX (regs[2]).
        if write_rdx && width != 1 {
            store_m(b, (REGS_OFF + 16) as i32, Register::R9);
        }
        // ovf -> R10 (0/1).
        if signed {
            // sign_ext = (low>>(bits-1) & 1) ? mask : 0 ; ovf = high != sign_ext
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).unwrap()); // low
            b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RCX, (bits - 1) as i32).unwrap());
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 1).unwrap());
            b.push(Instruction::with1(Code::Neg_rm64, Register::RCX).unwrap()); // 0 or all-ones
            movi(b, Register::R10, mask);
            b.push(Instruction::with2(Code::And_rm64_r64, Register::RCX, Register::R10).unwrap()); // sign_ext
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::RCX).unwrap()); // high ^ sign_ext
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9).unwrap());
            b.push(Instruction::with1(Code::Setne_rm8, Register::R10L).unwrap());
            b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).unwrap());
        } else {
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9).unwrap());
            b.push(Instruction::with1(Code::Setne_rm8, Register::R10L).unwrap());
            b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).unwrap());
        }
        // store CF=OF=ovf into FLAGS, preserving ZF/SF/PF/AF (0x801 = CF|OF).
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, m(FLAGS_OFF)).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::R9, (!0x801) as i32).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R10).unwrap()); // ovf
        b.push(Instruction::with1(Code::Neg_rm64, Register::RCX).unwrap()); // 0 or all-ones
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 0x801).unwrap()); // CF|OF
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::R9, Register::RCX).unwrap());
        store_m(b, FLAGS_OFF, Register::R9);
        // store low.
        b.call(sub_store);
        b.jmp(dispatch);
    }

    // ── P2: Divide (DIV/IDIV) ──────────────────────────────────────────────────
    // Matches `eval_state::div_wide`: dividend = AX (w1) or RDX:RAX (w>=2),
    // divisor = src1 (width-masked). Quotient -> dst, remainder -> RDX (regs[2],
    // w>=2); width 1 packs AX = (r<<8)|q. #DE (divisor==0) -> 0 like the reference.
    // Physical RDX (state_base) is staged in RBX across the div.
    fn emit_div_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        sub_store: usize,
        signed: bool,
        width: u8,
        dispatch: usize,
    ) {
        b.call(sub_dec_ops);
        // src1 -> R10 (divisor).
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        // width-mask divisor.
        match width {
            1 => {
                b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).unwrap());
            }
            2 => {
                b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::R10W).unwrap());
            }
            4 => {
                b.push(Instruction::with2(Code::Mov_r32_rm32, Register::R10D, Register::R10D).unwrap());
            }
            _ => {}
        }
        // div-by-zero guard -> store 0 (matches reference #DE -> 0).
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap());
        let fall = b.len() + 1;
        b.je(fall);
        // stage state_base in RBX, load dividend (RBX-relative).
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RDX).unwrap());
        let rbxmem = |disp: i64, _sz: u32| -> MemoryOperand {
            let a = disp.unsigned_abs();
            let dsz = if a == 0 { 0 } else if a <= 0x7F { 1 } else if a <= 0x7FFF { 2 } else if a <= 0x7FFFFFFF { 4 } else { 8 };
            MemoryOperand::with_base_index_scale_displ_size(Register::RBX, Register::None, 1, disp, dsz)
        };
        match width {
            1 => {
                b.push(Instruction::with2(Code::Mov_r16_rm16, Register::AX, rbxmem(REGS_OFF as i64, 0)).unwrap());
            }
            2 => {
                b.push(Instruction::with2(Code::Mov_r16_rm16, Register::DX, rbxmem((REGS_OFF + 16) as i64, 4)).unwrap());
                b.push(Instruction::with2(Code::Mov_r16_rm16, Register::AX, rbxmem(REGS_OFF as i64, 0)).unwrap());
            }
            4 => {
                b.push(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, rbxmem((REGS_OFF + 16) as i64, 4)).unwrap());
                b.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, rbxmem(REGS_OFF as i64, 4)).unwrap());
            }
            _ => {
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, rbxmem((REGS_OFF + 16) as i64, 8)).unwrap());
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, rbxmem(REGS_OFF as i64, 8)).unwrap());
            }
        }
        let (c, reg) = match (signed, width) {
            (false, 1) => (Code::Div_rm8, Register::R10L),
            (false, 2) => (Code::Div_rm16, Register::R10W),
            (false, 4) => (Code::Div_rm32, Register::R10D),
            (false, _) => (Code::Div_rm64, Register::R10),
            (true, 1) => (Code::Idiv_rm8, Register::R10L),
            (true, 2) => (Code::Idiv_rm16, Register::R10W),
            (true, 4) => (Code::Idiv_rm32, Register::R10D),
            (true, _) => (Code::Idiv_rm64, Register::R10),
        };
        b.push(Instruction::with1(c, reg).unwrap());
        // extract quotient -> R10, remainder -> R9 (w>=2). width 1: AX holds (r<<8)|q.
        match width {
            1 => {
                b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::AX).unwrap());
            }
            2 => {
                b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::AX).unwrap());
                b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R9D, Register::DX).unwrap());
            }
            4 => {
                b.push(Instruction::with2(Code::Mov_r32_rm32, Register::R10D, Register::EAX).unwrap());
                b.push(Instruction::with2(Code::Mov_r32_rm32, Register::R9D, Register::EDX).unwrap());
            }
            _ => {
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RDX).unwrap());
            }
        }
        // restore state_base.
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RBX).unwrap());
        // remainder -> regs[2] (w>=2).
        if width >= 2 {
            store_m(b, (REGS_OFF + 16) as i32, Register::R9);
        }
        // quotient -> dst.
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
        // div-by-zero path.
        let zero_idx = b.len();
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == fall {
                *ti = zero_idx;
            }
        }
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RAX).unwrap());
        b.call(sub_store);
        if width >= 2 {
            store_m(b, (REGS_OFF + 16) as i32, Register::RAX);
        }
        b.jmp(dispatch);
    }

    // ── P2: emit Multiply / MultiplyLow / Divide handler sets (signed × width). ──
    let mut mul_h: [[usize; 4]; 2] = [[0; 4]; 2];
    for (si, signed) in [false, true].iter().enumerate() {
        for (wi, w) in [1u8, 2, 4, 8].iter().enumerate() {
            mul_h[si][wi] = b.len();
            emit_mul_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, *signed, *w, true, dispatch);
        }
    }
    let mut mullow_h: [[usize; 3]; 2] = [[0; 3]; 2];
    for (si, signed) in [false, true].iter().enumerate() {
        for (wi, w) in [2u8, 4, 8].iter().enumerate() {
            mullow_h[si][wi] = b.len();
            emit_mul_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, *signed, *w, false, dispatch);
        }
    }
    let mut div_h: [[usize; 4]; 2] = [[0; 4]; 2];
    for (si, signed) in [false, true].iter().enumerate() {
        for (wi, w) in [1u8, 2, 4, 8].iter().enumerate() {
            div_h[si][wi] = b.len();
            emit_div_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, *signed, *w, dispatch);
        }
    }

    // ── P3: COMPARE_EXCHANGE{width} — atomic lock cmpxchg (Once/futex CAS). ──
    // Semantics == eval_state CompareExchange: addr=src1, newv=src2, acc=regs[0].
    //   if [addr]&mask == acc: mem[addr]=newv&mask, ZF=1, regs[0] unchanged.
    //   else:                  regs[0]=old([addr]&mask), ZF=0.
    // Native `lock cmpxchg [R10], R11x` with RAX=acc. On success RAX stays acc
    // (cmovz restores the full original regs[0] via RBX so high bits above the
    // operand width are preserved, exactly matching eval_state); on failure the
    // hardware writes the actual [addr] into AL/AX/EAX/RAX (= old, zero-extended
    // for 8/16/32-bit), which we commit to regs[0]. Only ZF is stored.
    let mut h_cmpxchg = std::collections::HashMap::new();
    for (w, cmp_code, regx, mask) in [
        (8u8, Code::Cmpxchg_rm64_r64, Register::R11, None),
        (4u8, Code::Cmpxchg_rm32_r32, Register::R11D, None),
        (2u8, Code::Cmpxchg_rm16_r16, Register::R11W, Some(0xFFFFu64)),
        (1u8, Code::Cmpxchg_rm8_r8, Register::R11L, Some(0xFFu64)),
    ] {
        let h = b.len();
        {
            b.call(sub_dec_ops);
            // addr = resolve(src1) -> R10
            movzx8_m(&mut b, Register::EAX, DEC_SRC1);
            mov_m(&mut b, Register::R11, DEC_IMM1);
            b.call(sub_resolve);
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
            // newv = resolve(src2) -> R11
            movzx8_m(&mut b, Register::EAX, DEC_SRC2);
            mov_m(&mut b, Register::R11, DEC_IMM2);
            b.call(sub_resolve);
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
            // acc = regs[0] & mask ; keep original regs[0] in RBX.
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, m(REGS_OFF)).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RBX).unwrap());
            if let Some(mk) = mask {
                b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, mk as i32).unwrap());
            }
            let mut ci = Instruction::with2(cmp_code, MemoryOperand::with_base(Register::R10), regx).unwrap();
            ci.set_has_lock_prefix(true);
            b.push(ci);
            // success -> restore original regs[0]; failure -> regs[0]=old (RAX).
            b.push(Instruction::with2(Code::Cmove_r64_rm64, Register::RAX, Register::RBX).unwrap());
            store_m(&mut b, REGS_OFF, Register::RAX);
            // store ZF only (preserve CF/SF/OF/PF/AF), matching eval_state.
            b.push(Instruction::with(Code::Pushfq));
            b.push(Instruction::with1(Code::Pop_r64, Register::RCX).unwrap());
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 0x40).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RCX).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x40i32)).unwrap());
            b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
            store_m(&mut b, FLAGS_OFF, Register::RAX);
            b.jmp(dispatch);
        }
        h_cmpxchg.insert(w, h);
    }

    // ── P2: BSWAP{4,8} — dst = bswap(src1); no flags. ──
    let h_bswap4 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with1(Code::Bswap_r32, Register::R10D).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }
    let h_bswap8 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with1(Code::Bswap_r64, Register::R10).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    // ── P2: BSF — dst = ctz(src) if src!=0 else 0; only ZF changes (ZF=1 iff src==0). ──
    let h_bsf = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Bsf_r64_rm64, Register::R10, Register::R10).unwrap());
        // capture ZF(=src==0) into slot, and src!=0 into R9L for the dst fix, before
        // any later flag-modifying instruction.
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with1(Code::Setne_rm8, Register::R9L).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x40).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x40i32)).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
        store_m(&mut b, FLAGS_OFF, Register::RAX);
        // if src==0 (R9L==0) zero the (undefined) BSF result.
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::R9L).unwrap());
        b.push(Instruction::with1(Code::Neg_rm64, Register::R9).unwrap());
        b.push(Instruction::with2(Code::And_rm64_r64, Register::R10, Register::R9).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    // ── P2: BSR — dst = msb index; only ZF changes. ──
    let h_bsr = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Bsr_r64_rm64, Register::R10, Register::R10).unwrap());
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with1(Code::Setne_rm8, Register::R9L).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x40).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x40i32)).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
        store_m(&mut b, FLAGS_OFF, Register::RAX);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::R9L).unwrap());
        b.push(Instruction::with1(Code::Neg_rm64, Register::R9).unwrap());
        b.push(Instruction::with2(Code::And_rm64_r64, Register::R10, Register::R9).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    // ── P2: TZCNT{2,4,8} — dst = ctz(width-truncated src) else width; CF=(s==0), ZF. ──
    let h_tzcnt2 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Tzcnt_r16_rm16, Register::R10W, Register::R10W).unwrap());
        b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::R10W).unwrap());
        emit_store_cf_zf_tz(&mut b);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }
    let h_tzcnt4 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Tzcnt_r32_rm32, Register::R10D, Register::R10D).unwrap());
        emit_store_cf_zf_tz(&mut b);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }
    let h_tzcnt8 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Tzcnt_r64_rm64, Register::R10, Register::R10).unwrap());
        emit_store_cf_zf_tz(&mut b);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    // ── P2: LZCNT{2,4,8} — dst = clz(width-truncated src) else width; CF=(s==0), ZF. ──
    let h_lzcnt2 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Lzcnt_r16_rm16, Register::R10W, Register::R10W).unwrap());
        b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::R10W).unwrap());
        emit_store_cf_zf_tz(&mut b);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }
    let h_lzcnt4 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Lzcnt_r32_rm32, Register::R10D, Register::R10D).unwrap());
        emit_store_cf_zf_tz(&mut b);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }
    let h_lzcnt8 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Lzcnt_r64_rm64, Register::R10, Register::R10).unwrap());
        emit_store_cf_zf_tz(&mut b);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    // ── P2: POPCNT — dst = popcount(src1); flags via `test` (update_logic64). ──
    let h_popcnt = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Popcnt_r64_rm64, Register::R10, Register::R10).unwrap());
        // `test r10,r10` sets CF=0,OF=0,ZF,SF,PF exactly like update_logic64.
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap());
        emit_store_flags_popcnt(&mut b);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    let handlers: std::collections::HashMap<RiscOp, usize> = {
        use std::collections::HashMap;
        let mut h = HashMap::new();
        h.insert(RiscOp::Nor, h_nor);
        h.insert(RiscOp::AddWithCarry, h_add);
        h.insert(RiscOp::ShiftRight, h_shr);
        h.insert(RiscOp::ShiftLeft, h_shl);
        h.insert(RiscOp::ArithmeticShiftRight, h_ashr);
        h.insert(RiscOp::Mov, h_mov);
        h.insert(RiscOp::VirtualPush, h_push);
        h.insert(RiscOp::VirtualPop, h_pop);
        h.insert(RiscOp::SetFlag, h_setflag);
        h.insert(RiscOp::MemoryRead { width: 8 }, h_memrd8);
        h.insert(RiscOp::MemoryRead { width: 4 }, h_memrd4);
        h.insert(RiscOp::MemoryRead { width: 2 }, h_memrd2);
        h.insert(RiscOp::MemoryRead { width: 1 }, h_memrd1);
        h.insert(RiscOp::MemoryWrite { width: 8 }, h_memwr8);
        h.insert(RiscOp::MemoryWrite { width: 4 }, h_memwr4);
        h.insert(RiscOp::MemoryWrite { width: 2 }, h_memwr2);
        h.insert(RiscOp::MemoryWrite { width: 1 }, h_memwr1);
        h.insert(RiscOp::CompareExchange { width: 8 }, h_cmpxchg[&8]);
        h.insert(RiscOp::CompareExchange { width: 4 }, h_cmpxchg[&4]);
        h.insert(RiscOp::CompareExchange { width: 2 }, h_cmpxchg[&2]);
        h.insert(RiscOp::CompareExchange { width: 1 }, h_cmpxchg[&1]);
        // P2: BSwap / BitScan / Count / PopCount native handlers.
        h.insert(RiscOp::BSwap { width: 4 }, h_bswap4);
        h.insert(RiscOp::BSwap { width: 8 }, h_bswap8);
        h.insert(RiscOp::BitScanForward, h_bsf);
        h.insert(RiscOp::BitScanReverse, h_bsr);
        h.insert(RiscOp::CountTrailingZeros { width: 2 }, h_tzcnt2);
        h.insert(RiscOp::CountTrailingZeros { width: 4 }, h_tzcnt4);
        h.insert(RiscOp::CountTrailingZeros { width: 8 }, h_tzcnt8);
        h.insert(RiscOp::CountLeadingZeros { width: 2 }, h_lzcnt2);
        h.insert(RiscOp::CountLeadingZeros { width: 4 }, h_lzcnt4);
        h.insert(RiscOp::CountLeadingZeros { width: 8 }, h_lzcnt8);
        h.insert(RiscOp::PopCount, h_popcnt);
        h.insert(RiscOp::VirtualBranch { cond: BranchCondition::Always }, h_branch);
        for (si, signed) in [false, true].iter().enumerate() {
            for (wi, w) in [1u8, 2, 4, 8].iter().enumerate() {
                h.insert(RiscOp::Multiply { signed: *signed, width: *w }, mul_h[si][wi]);
            }
        }
        for (si, signed) in [false, true].iter().enumerate() {
            for (wi, w) in [2u8, 4, 8].iter().enumerate() {
                h.insert(RiscOp::MultiplyLow { signed: *signed, width: *w }, mullow_h[si][wi]);
            }
        }
        for (si, signed) in [false, true].iter().enumerate() {
            for (wi, w) in [1u8, 2, 4, 8].iter().enumerate() {
                h.insert(RiscOp::Divide { signed: *signed, width: *w }, div_h[si][wi]);
            }
        }
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

    Ok(SelfDecodingParts { code, table, offs_tab, flags_tab, cond_codes, branch_map })
}

/// Run the self-decoding dispatcher in an RWX arena (host-side test/bench path):
/// build the parts at arena-relative VAs, copy them in, set the initial regs in
/// the state buffer and jump to the dispatcher entry.
pub fn run_native_poly_direct(
    bytecode: &[u8],
    seed: u64,
    init_regs: &[u64; 16],
    ip_map: Option<&HashMap<u64, usize>>,
) -> Result<RiscEvalState> {
    let mut arena = Arena::new(ARENA_SIZE)?;
    let code_base = (arena.base + OFF_CODE) as u64;
    let state_base = (arena.base + OFF_STATE) as u64;
    let table_base = (arena.base + OFF_TABLE) as u64;
    let bytecode_base = (arena.base + OFF_BYTECODE) as u64;
    let stack_base = (arena.base + OFF_STACK_BASE) as u64;
    let parts = build_self_decoding_parts(
        bytecode, seed, code_base, table_base, bytecode_base, state_base, stack_base, ip_map,
    )?;

    // Copy into arena.
    {
        let buf = arena.bytes();
        buf[OFF_CODE..OFF_CODE + parts.code.len()].copy_from_slice(&parts.code);
        for (i, v) in parts.table.iter().enumerate() {
            buf[OFF_TABLE + i * 8..OFF_TABLE + i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        buf[OFF_OP_OFFS..OFF_OP_OFFS + 256].copy_from_slice(&parts.offs_tab);
        buf[OFF_OP_FLAGS..OFF_OP_FLAGS + 256].copy_from_slice(&parts.flags_tab);
        buf[OFF_COND_CODES..OFF_COND_CODES + 256].copy_from_slice(&parts.cond_codes);
        assert!(
            OFF_BRANCH_MAP + parts.branch_map.len() <= OFF_BYTECODE,
            "branch map overflowed into bytecode region: {}",
            parts.branch_map.len()
        );
        buf[OFF_BRANCH_MAP..OFF_BRANCH_MAP + parts.branch_map.len()]
            .copy_from_slice(&parts.branch_map);
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

            let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16], None).unwrap();

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

    /// NativeCallBridge no-op: the self-decoding dispatcher must CONSUME the
    /// stream (opcode + 3 operand bytes + immediates) without changing any VM
    /// state, so a following op is still reached. Differential: native
    /// self-decoding == interpreter == reference (which treat NativeCallBridge
    /// as a no-op), across multiple seeds and with both imm & vreg operands.
    #[test]
    fn test_native_poly_direct_native_call_bridge_noop() {
        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut d = RiscDesynthesizer::new();
            // R0 = 0x200
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x200), MicroOperand::Imm64(0));
            // Bridge with imm src1 + dst: must consume stream, change nothing.
            d.instrs.push(
                MicroInstr::new(RiscOp::NativeCallBridge)
                    .with_dst(MicroOperand::VReg(1))
                    .with_src1(MicroOperand::Imm64(0x9999)),
            );
            // Bridge with vreg src1/src2 + dst: must consume stream, change nothing.
            d.instrs.push(
                MicroInstr::new(RiscOp::NativeCallBridge)
                    .with_dst(MicroOperand::VReg(2))
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::VReg(1)),
            );
            // State-changing op AFTER the bridges: only reached if the stream was
            // consumed by the no-op handlers (no desync / no premature stop).
            d.emit_add(MicroOperand::VReg(6), MicroOperand::VReg(0), MicroOperand::Imm64(1));
            d.instrs.push(MicroInstr::new(RiscOp::Halt));
            let prog = RiscProgram::new(d.instrs);

            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();

            let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16], None).unwrap();

            let mut interp = PolymorphicInterpreter::new(seed);
            interp.run(&bytecode).unwrap();

            let ref_st = prog.eval_state(&[0u64; 16]);

            // Bridge must not have written regs 1/2 (no-op), and the post-bridge
            // op must have run (stream consumed correctly).
            assert_eq!(ref_st.regs[1], 0, "seed {seed:#x}: bridge wrote dst VReg(1)");
            assert_eq!(ref_st.regs[2], 0, "seed {seed:#x}: bridge wrote dst VReg(2)");
            assert_eq!(ref_st.regs[6], 0x201, "seed {seed:#x}: post-bridge op not reached");

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
        }
    }

    /// P3: CompareExchange{1,2,4,8} — native self-decoding handler == eval_state
    /// (linear-block unit equivalence; success and failure paths, all widths).
    #[test]
    fn test_poly_direct_compare_exchange_all_widths_matches_reference() {
        use std::collections::HashMap;

        let seed = 0x13579BDF2468ACE0u64;
        let mut arena = Arena::new(ARENA_SIZE).unwrap();
        let base = arena.base;
        let code_off = OFF_CODE;
        let table_off = OFF_TABLE;
        let bytecode_off = OFF_BYTECODE;
        let state_off = OFF_STATE;
        let window_off = 0x30000usize; // clear of code/table/bytecode/state/stack
        let addr = (base + window_off) as u64;
        let code_va = (base + code_off) as u64;
        let table_va = (base + table_off) as u64;
        let bytecode_va = (base + bytecode_off) as u64;
        let state_va = (base + state_off) as u64;
        let stack_base = (base + OFF_STACK_BASE) as u64;

        for width in [1u8, 2, 4, 8] {
            let newv: u64 = 0x0BAD_F00D_CAFE_1234;
            let mut d = RiscDesynthesizer::new();
            d.instrs.push(
                MicroInstr::new(RiscOp::CompareExchange { width })
                    .with_src1(MicroOperand::VReg(1)) // addr (set in init_regs)
                    .with_src2(MicroOperand::Imm64(newv)),
            );
            d.instrs.push(MicroInstr::new(RiscOp::Halt));
            let prog = RiscProgram::new(d.instrs);

            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();

            let parts = build_self_decoding_parts(
                &bytecode, seed, code_va, table_va, bytecode_va, state_va, stack_base,
            )
            .expect("build self-decoding parts");
            assert!(
                parts.code.len() + OFF_CODE <= OFF_TABLE,
                "dispatcher code overflowed into table region: code_len={}",
                parts.code.len()
            );

            // Place parts into arena once per width; state/memory re-seeded per scenario.
            {
                let buf = arena.bytes();
                buf[code_off..code_off + parts.code.len()].copy_from_slice(&parts.code);
                for (i, v) in parts.table.iter().enumerate() {
                    buf[table_off + i * 8..table_off + i * 8 + 8].copy_from_slice(&v.to_le_bytes());
                }
                buf[OFF_OP_OFFS..OFF_OP_OFFS + 256].copy_from_slice(&parts.offs_tab);
                buf[OFF_OP_FLAGS..OFF_OP_FLAGS + 256].copy_from_slice(&parts.flags_tab);
                buf[bytecode_off..bytecode_off + bytecode.len()].copy_from_slice(&bytecode);
            }

            let old: u64 = 0xFEDC_BA98_7654_3210;
            let scenarios: [(&str, u64, u64, bool); 2] = [
                ("success", old, old, true),
                ("failure", old ^ 0x1, old, false),
            ];
            for (label, acc, old, success) in scenarios {
                let mask = if width == 8 { u64::MAX } else { (1u64 << (width * 8)) - 1 };

                // init regs: reg[0]=acc (expected), reg[1]=addr
                let mut init = [0u64; 16];
                init[0] = acc;
                init[1] = addr;

                // seed window + state identically in native arena and reference HashMap.
                {
                    let buf = arena.bytes();
                    buf[window_off..window_off + 8].copy_from_slice(&old.to_le_bytes());
                    buf[state_off..state_off + STATE_END as usize].fill(0);
                    for (i, v) in init.iter().enumerate() {
                        buf[state_off + REGS_OFF as usize + i * 8..state_off + REGS_OFF as usize + i * 8 + 8]
                            .copy_from_slice(&v.to_le_bytes());
                    }
                }
                let mut seed_mem = HashMap::new();
                for (k, b) in old.to_le_bytes().iter().enumerate() {
                    seed_mem.insert(addr.wrapping_add(k as u64), *b);
                }

                let ref_st = prog.eval_state_with_mem(&init, seed_mem);

                arena.call(code_off);

                let buf = arena.bytes();
                let s = state_off;
                let mut nat = RiscEvalState::default();
                for i in 0..16 {
                    nat.regs[i] = u64::from_le_bytes(
                        buf[s + REGS_OFF as usize + i * 8..s + REGS_OFF as usize + i * 8 + 8]
                            .try_into()
                            .unwrap(),
                    );
                }
                for i in 0..8 {
                    nat.temps[i] = u64::from_le_bytes(
                        buf[s + TEMPS_OFF as usize + i * 8..s + TEMPS_OFF as usize + i * 8 + 8]
                            .try_into()
                            .unwrap(),
                    );
                }
                nat.flags = u64::from_le_bytes(buf[s + FLAGS_OFF as usize..s + FLAGS_OFF as usize + 8].try_into().unwrap());
                nat.vsp = u64::from_le_bytes(buf[s + VSP_OFF as usize..s + VSP_OFF as usize + 8].try_into().unwrap());

                assert_eq!(nat.regs, ref_st.regs, "w{width} {label}: regs mismatch (nat={:?} ref={:?})", nat.regs, ref_st.regs);
                assert_eq!(nat.flags, ref_st.flags, "w{width} {label}: flags nat={:#x} ref={:#x}", nat.flags, ref_st.flags);
                assert_eq!(nat.temps, ref_st.temps, "w{width} {label}: temps mismatch");
                assert_eq!(nat.vsp, ref_st.vsp, "w{width} {label}: vsp mismatch");

                // memory side-effect: width low bytes written/unchanged == reference.
                let nat_mem = u64::from_le_bytes(buf[window_off..window_off + 8].try_into().unwrap());
                let mut ref_mem = 0u64;
                for k in 0..width as usize {
                    ref_mem |= (*ref_st.mem.get(&addr.wrapping_add(k as u64)).unwrap_or(&0) as u64) << (k * 8);
                }
                assert_eq!(nat_mem & mask, ref_mem, "w{width} {label}: mem mismatch nat={:#x} ref={:#x}", nat_mem & mask, ref_mem);
                assert_eq!(
                    nat_mem & mask,
                    if success { newv & mask } else { old & mask },
                    "w{width} {label}: mem side-effect wrong (expect {:#x})",
                    if success { newv & mask } else { old & mask }
                );
                assert_eq!(nat.flags & 0x40 != 0, success, "w{width} {label}: ZF wrong (nat.flags={:#x})", nat.flags);
            }
        }
    }

    /// Differential: native self-decoding Multiply/MultiplyLow == interpreter ==
    /// reference (linear-block unit equivalence), signed/unsigned across widths —
    /// including RDX(high)/regs[2] and the CF=OF overflow flags, and the width-1
    /// AX packing ((high<<8)|low).
    #[test]
    fn test_poly_direct_multiply_matches_reference() {
        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut d = RiscDesynthesizer::new();
            // Load operands via adds (interpreter starts from zero regs).
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x1_0000_0001), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(3), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(3), MicroOperand::Imm64(0x7FFF_FFFF), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(4), MicroOperand::Imm64(0xFF), MicroOperand::Imm64(0));
            // Clean flag base: isolates the multiply CF/OF handling from the
            // AddWithCarry setup (native h_add preserves PF/AF instead of recomputing).
            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0)));
            // unsigned MUL r64: R0=0x1_0000_0001, R1=3 -> RDX:RAX, low->R0, high->R2.
            d.instrs.push(
                MicroInstr::new(RiscOp::Multiply { signed: false, width: 8 })
                    .with_dst(MicroOperand::VReg(0))
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::VReg(1)),
            );
            // signed IMUL r32 (MultiplyLow): 0x7FFFFFFF * 2 = 0xFFFFFFFE, CF=OF=1.
            d.instrs.push(
                MicroInstr::new(RiscOp::MultiplyLow { signed: true, width: 4 })
                    .with_dst(MicroOperand::VReg(6))
                    .with_src1(MicroOperand::VReg(3))
                    .with_src2(MicroOperand::Imm64(2)),
            );
            // signed IMUL r8 (Multiply width 1): 0xFF * 0xFF -> AX = 0xFE01, CF=OF=1.
            d.instrs.push(
                MicroInstr::new(RiscOp::Multiply { signed: true, width: 1 })
                    .with_dst(MicroOperand::VReg(7))
                    .with_src1(MicroOperand::VReg(4))
                    .with_src2(MicroOperand::VReg(4)),
            );
            d.instrs.push(MicroInstr::new(RiscOp::Halt));
            let prog = RiscProgram::new(d.instrs);

            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();
            let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16], None).unwrap();
            let mut interp = PolymorphicInterpreter::new(seed);
            interp.run(&bytecode).unwrap();
            let ref_st = prog.eval_state(&[0u64; 16]);

            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: mul native regs != ref");
            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: mul interp regs != ref");
            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: mul native temps != ref");
            assert_eq!(
                native.flags, ref_st.flags,
                "seed {seed:#x}: mul native flags {:#x} != ref {:#x}",
                native.flags, ref_st.flags
            );
            assert_eq!(interp.flags.raw, ref_st.flags, "seed {seed:#x}: mul interp flags != ref");
            assert_eq!(native.regs[0], 0x3_0000_0003, "seed {seed:#x}: MUL low wrong");
            assert_eq!(native.regs[2], 0, "seed {seed:#x}: MUL high wrong");
            assert_eq!(native.regs[6], 0xFFFF_FFFE, "seed {seed:#x}: IMUL low wrong");
            assert_eq!(native.regs[7], 0xFE01, "seed {seed:#x}: IMUL r8 AX pack wrong");
            assert_eq!(native.flags & 0x801, 0x801, "seed {seed:#x}: CF|OF not set");
        }
    }

    /// Differential: native self-decoding Divide/IDivide == interpreter ==
    /// reference, unsigned/signed across widths — quotient -> dst, remainder ->
    /// RDX (regs[2], w>=2), width-1 AX packing, and div-by-zero -> 0.
    #[test]
    fn test_poly_direct_divide_matches_reference() {
        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut d = RiscDesynthesizer::new();
            // Load all operands first (interpreter starts from zero regs).
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(1000), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64(0), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(7), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(3), MicroOperand::Imm64(1000), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(4), MicroOperand::Imm64(0), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(5), MicroOperand::Imm64((-3i64) as u64), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(0), MicroOperand::Imm64(0));
            // Clean flag base (divide does not touch flags).
            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0)));
            // unsigned DIV r64: R0=1000, R2(RDX)=0, divisor R1=7 -> q=142, r=6.
            d.instrs.push(
                MicroInstr::new(RiscOp::Divide { signed: false, width: 8 })
                    .with_dst(MicroOperand::VReg(0))
                    .with_src1(MicroOperand::VReg(1)),
            );
            // signed IDIV r32: R3=1000, R4(RDX)=0, divisor R5=-3 -> q=-333, r=1.
            d.instrs.push(
                MicroInstr::new(RiscOp::Divide { signed: true, width: 4 })
                    .with_dst(MicroOperand::VReg(3))
                    .with_src1(MicroOperand::VReg(5)),
            );
            // div-by-zero: divisor 0 -> 0 (dst stays 0, regs[2]=0).
            d.instrs.push(
                MicroInstr::new(RiscOp::Divide { signed: false, width: 8 })
                    .with_dst(MicroOperand::VReg(6))
                    .with_src1(MicroOperand::VReg(6)),
            );
            d.instrs.push(MicroInstr::new(RiscOp::Halt));
            let prog = RiscProgram::new(d.instrs);

            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();
            let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16], None).unwrap();
            let mut interp = PolymorphicInterpreter::new(seed);
            interp.run(&bytecode).unwrap();
            let ref_st = prog.eval_state(&[0u64; 16]);

            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: div native regs != ref");
            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: div interp regs != ref");
            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: div native temps != ref");
            assert_eq!(
                native.flags, ref_st.flags,
                "seed {seed:#x}: div native flags {:#x} != ref {:#x}",
                native.flags, ref_st.flags
            );
            assert_eq!(interp.flags.raw, ref_st.flags, "seed {seed:#x}: div interp flags != ref");
            assert_eq!(native.regs[0], 142, "seed {seed:#x}: DIV w8 quotient wrong");
            assert_eq!(native.regs[3] as i32, -333, "seed {seed:#x}: IDIV w4 quotient wrong");
            assert_eq!(native.regs[4], 1, "seed {seed:#x}: IDIV w4 remainder wrong");
            assert_eq!(native.regs[6], 0, "seed {seed:#x}: div-by-zero must yield 0");
            assert_eq!(native.regs[2], 0, "seed {seed:#x}: div-by-zero clears regs[2]");
        }
    }

    /// P2 differential: BSwap / BitScanForward/Reverse / TZCNT / LZCNT / PopCount
    /// native self-decoding handlers == eval_state (regs/temps/flags/vsp/stack).
    #[test]
    fn test_native_poly_direct_bitscan_count_popcnt_matches_reference() {
        let seeds = [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789];
        for seed in seeds {
            let mut d = RiscDesynthesizer::new();
            // BSWAP r64
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x0102_0304_0506_0708), MicroOperand::Imm64(0));
            d.instrs.push(MicroInstr::new(RiscOp::BSwap { width: 8 }).with_dst(MicroOperand::VReg(8)).with_src1(MicroOperand::VReg(0)));
            // BSWAP r32 (low 32 bits swapped, high bits discarded)
            d.instrs.push(MicroInstr::new(RiscOp::BSwap { width: 4 }).with_dst(MicroOperand::VReg(9)).with_src1(MicroOperand::VReg(0)));
            // BSF / BSR
            d.emit_add(MicroOperand::VReg(3), MicroOperand::Imm64(0x1000), MicroOperand::Imm64(0));
            d.instrs.push(MicroInstr::new(RiscOp::BitScanForward).with_dst(MicroOperand::VReg(4)).with_src1(MicroOperand::VReg(3)));
            d.instrs.push(MicroInstr::new(RiscOp::BitScanReverse).with_dst(MicroOperand::VReg(5)).with_src1(MicroOperand::VReg(3)));
            // BSF src==0 -> ZF=1, dst=0
            d.instrs.push(MicroInstr::new(RiscOp::BitScanForward).with_dst(MicroOperand::VReg(6)).with_src1(MicroOperand::Imm64(0)));
            // TZCNT / LZCNT across widths, incl. width-truncated-zero (bit above width)
            d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(0x8000_0000_0000_1000), MicroOperand::Imm64(0));
            d.instrs.push(MicroInstr::new(RiscOp::CountTrailingZeros { width: 8 }).with_dst(MicroOperand::Temp(0)).with_src1(MicroOperand::VReg(7)));
            d.instrs.push(MicroInstr::new(RiscOp::CountLeadingZeros { width: 8 }).with_dst(MicroOperand::Temp(1)).with_src1(MicroOperand::VReg(7)));
            d.instrs.push(MicroInstr::new(RiscOp::CountTrailingZeros { width: 4 }).with_dst(MicroOperand::Temp(2)).with_src1(MicroOperand::VReg(7)));
            d.instrs.push(MicroInstr::new(RiscOp::CountLeadingZeros { width: 4 }).with_dst(MicroOperand::Temp(3)).with_src1(MicroOperand::VReg(7)));
            // width 2 with low 16 bits == 0 -> dst=16, CF=1, ZF=1
            d.instrs.push(MicroInstr::new(RiscOp::CountTrailingZeros { width: 2 }).with_dst(MicroOperand::Temp(4)).with_src1(MicroOperand::VReg(7)));
            // LZCNT w2 on odd low value
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(1), MicroOperand::Imm64(0));
            d.instrs.push(MicroInstr::new(RiscOp::CountLeadingZeros { width: 2 }).with_dst(MicroOperand::Temp(5)).with_src1(MicroOperand::VReg(0)));
            // POPCNT (even popcount -> PF set) and POPCNT(0) -> ZF=1
            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(0xFF), MicroOperand::Imm64(0));
            d.instrs.push(MicroInstr::new(RiscOp::PopCount).with_dst(MicroOperand::Temp(6)).with_src1(MicroOperand::VReg(1)));
            d.instrs.push(MicroInstr::new(RiscOp::PopCount).with_dst(MicroOperand::Temp(7)).with_src1(MicroOperand::Imm64(0)));
            d.instrs.push(MicroInstr::new(RiscOp::Halt));

            let prog = RiscProgram::new(d.instrs);
            let init = [0u64; 16];
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();
            let native = run_native_poly_direct(&bytecode, seed, &init, None).unwrap();
            let ref_st = prog.eval_state(&init);

            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: regs");
            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: temps");
            assert_eq!(native.flags, ref_st.flags, "seed {seed:#x}: flags ref={:#x} native={:#x}", ref_st.flags, native.flags);
            assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: vsp");
            assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: stack");
            assert_eq!(native.regs[8], 0x0807_0605_0403_0201, "seed {seed:#x}: bswap64");
            assert_eq!(native.regs[9], 0x0807_0605, "seed {seed:#x}: bswap32");
            assert_eq!(native.regs[4], 12, "seed {seed:#x}: bsf(0x1000)");
            assert_eq!(native.regs[5], 12, "seed {seed:#x}: bsr(0x1000)");
            assert_eq!(native.regs[6], 0, "seed {seed:#x}: bsf(0)");
        }
    }

    /// Cond-byte decode foundation: the cond-codes table built from the spec's
    /// branch_cond_map must map every BranchCondition's encoded byte to the
    /// canonical COND_* code (and unknown bytes to COND_INVALID). This is the
    /// table `sub_dec_ops_cond` reads to decode the cond byte of
    /// VirtualBranch/Setcc/ConditionalMove into the DEC_COND state slot.
    #[test]
    fn test_cond_codes_table_matches_branch_cond_map() {
        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let spec = VirtualIsaSpec::from_seed(seed);
            let parts = build_self_decoding_parts(
                &[],
                seed,
                0x100000,
                0x200000,
                0x300000,
                0x400000,
                0x500000,
            )
            .unwrap();
            // Every encoded cond byte -> its canonical code; everything else invalid.
            for (cond, &byte) in &spec.branch_cond_map {
                assert_eq!(
                    parts.cond_codes[byte as usize],
                    cond_code(*cond),
                    "seed {seed:#x}: cond {cond:?} (byte {byte:#04x}) code mismatch"
                );
            }
            for raw in 0u16..256 {
                let raw = raw as u8;
                if !spec.branch_cond_map.values().any(|&b| b == raw) {
                    assert_eq!(
                        parts.cond_codes[raw as usize],
                        COND_INVALID,
                        "seed {seed:#x}: stray byte {raw:#04x} must be invalid"
                    );
                }
            }
            // cond_code() is injective across the 22 supported conditions.
            let mut seen = std::collections::HashSet::new();
            for cond in spec.branch_cond_map.keys() {
                assert!(seen.insert(cond_code(*cond)), "seed {seed:#x}: dup code for {cond:?}");
            }
        }
    }
}
