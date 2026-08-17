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

mod codegen_util;

pub(crate) use codegen_util::{
    cond_code, emit_read_imm8, m, m8, mov_m, movi, movzx8_m, store_m, CodeBuilder,
    ARENA_SIZE, C1, C2, C3, C4, C5, DEC_CIN, DEC_DST, DEC_IMM1, DEC_IMM2, DEC_SRC1, DEC_SRC2, DEC_COND,
    FLAG_MASK, FLAGS_OFF, K_IMM, K_NONE, K_REG, OFF_BRANCH_MAP, OFF_BYTECODE, OFF_COND_CODES, OFF_CODE,
    OFF_OP_FLAGS, OFF_OP_OFFS, OFF_STACK_BASE, OFF_STATE, OFF_TABLE, REGS_OFF, STATE_END,
    TEMPS_OFF, VSP_OFF,
    COND_ABOVE, COND_ABOVE_OR_EQUAL, COND_ALWAYS, COND_BELOW, COND_BELOW_OR_EQUAL, COND_CARRY,
    COND_COUNTER_ZERO_2, COND_COUNTER_ZERO_4, COND_COUNTER_ZERO_8, COND_GREATER,
    COND_GREATER_OR_EQUAL, COND_INVALID, COND_LESS, COND_LESS_OR_EQUAL, COND_NOT_CARRY,
    COND_NOT_OVERFLOW, COND_NOT_PARITY, COND_NOT_SIGN, COND_NOT_ZERO, COND_OVERFLOW,
    COND_PARITY, COND_SIGN, COND_ZERO,
};
#[cfg(test)]
mod poly_direct_tests;

/// P2 (G3): 폭별 ALU 네이티브 핸들러 종류 (Add/SubWithBorrow/Inc/Dec/Not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WidthAluOp {
    Add,
    Sub,
    Inc,
    Dec,
    Not,
}

/// R4: SSE/FPU 스칼라 unary 변환 핸들러 종류 (IntToFloat/FloatToInt/FloatToFloat).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FloatCvtMode {
    IntToFloat,
    FloatToInt,
    FloatToFloat,
}

/// P3 (G1): assembled self-decoding dispatcher pieces (machine code + tables).
pub struct SelfDecodingParts {
    pub code: Vec<u8>,
    /// 256 x u64 handler table (decrypted opcode byte -> handler VA).
    pub table: Vec<u64>,
    /// P6-1: handler 테이블 암호화 키 (시드 유래). dispatch 시 `table[op] ^ key` 로
    /// handler VA 를 복호화한다 — 평문 테이블에는 암호화된 값만 있어 opcode↔handler
    /// 1:1 매핑이 노출되지 않는다. build/run 시점에 dispatch 코드가 이 키를 임베드.
    pub table_key: u64,
    /// 256 x u8 operand-offset table (operand-encoding -> state offset).
    pub offs_tab: Vec<u8>,
    /// 256 x u8 operand-kind table (0=reg/temp/vsp/flags, 1=imm, 2=none).
    pub flags_tab: Vec<u8>,
    /// 256 x u8 cond-code table (decrypted cond byte -> canonical COND_* code, 0xFF invalid).
    pub cond_codes: Vec<u8>,
    /// Branch-resolution table (u32 count + count x (u64 target_value, u64 byte_offset)),
    /// embedded at OFF_BRANCH_MAP / table_va+0xB00. The VirtualBranch handler scans it
    /// to map a target (source-IP via ip_map, or direct micro-op index) to a bytecode
    /// byte offset for the rolling-key re-sync.
    pub branch_map: Vec<u8>,
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
/// Backward-compatible 7-arg builder (no ip_map) — delegates to `_with` with None.
pub fn build_self_decoding_parts(
    bytecode: &[u8],
    seed: u64,
    code_base: u64,
    table_base: u64,
    bytecode_base: u64,
    state_base: u64,
    stack_base: u64,
) -> Result<SelfDecodingParts> {
    build_self_decoding_parts_with(
        bytecode, seed, code_base, table_base, bytecode_base, state_base, stack_base, None,
    )
}

/// Full builder with optional ip_map (source-IP -> program index) for VirtualBranch
/// branch resolution.
pub fn build_self_decoding_parts_with(
    bytecode: &[u8],
    seed: u64,
    code_base: u64,
    table_base: u64,
    bytecode_base: u64,
    state_base: u64,
    stack_base: u64,
    ip_map: Option<&HashMap<u64, usize>>,
) -> Result<SelfDecodingParts> {
    let spec = VirtualIsaSpec::from_seed(seed);
    let init_key = seed.wrapping_mul(C1) ^ 0x517CC1B727220A95;
    // P6-1: handler 테이블 암호화 키 — dispatch loop 코드에 임베드하고, 테이블
    // build 시에도 동일 파생식으로 사용한다 (seed→init_key→table_key 결정적).
    let table_key = init_key
        .wrapping_mul(0x9E3779B97F4A7C15)
        .rotate_right(17)
        .wrapping_add(0xBF58476D1CE4E5B9);

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
    let ip_map: Option<&HashMap<u64, usize>> = ip_map;
    let mut dec = PolymorphicDecoder::new(seed);
    let prog = dec.decode_full(bytecode, false)?;
    let mut reenc = PolymorphicEncoder::new(seed);
    let (re_bc, op_offsets) = reenc.encode_with_offsets(&prog)?;
    if re_bc != bytecode {
        return Err(anyhow!(
            "self-decoding branch-map: decode+re-encode diverged from the placed bytecode ({} vs {} bytes); \
             branch-map offsets would be invalid",
            re_bc.len(),
            bytecode.len()
        ));
    }
    for (i, &off) in op_offsets.iter().enumerate() {
        if off >= bytecode.len() {
            return Err(anyhow!(
                "self-decoding branch-map: micro-op {i} byte offset {off:#x} exceeds bytecode len {:#x}",
                bytecode.len()
            ));
        }
    }
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
    // Clobbers RAX, RCX only; preserves RBX, R8, R9, R10, R11, R12, R13, R14, R15, RDX.
    // NOTE: R8 (bytecode_base) must survive — VirtualBranch calls sub_resync ->
    // sub_decrypt (reads [R8+R12]) right after this. The setcc result is staged in
    // AL, not R8L (previous code clobbered R8L, corrupting bytecode_base -> wrong
    // rolling key -> garbage dispatch target -> AV on taken backward branches).
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
                // CounterZero(w): virtual RCX (regs[1]) low w bytes == 0. Load the
                // full 64-bit regs[1] (qword memory operand) and isolate the low w
                // bytes with shifts (avoids iced's 16-bit MemoryOperand quirks).
                let width = if k == 19 { 2 } else if k == 20 { 4 } else { 8 };
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(REGS_OFF + 8)).unwrap());
                if width == 2 {
                    b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RAX, 48).unwrap());
                    b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 48).unwrap());
                } else if width == 4 {
                    b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RAX, 32).unwrap());
                    b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 32).unwrap());
                }
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
                b.push(Instruction::with1(Code::Sete_rm8, Register::AL).unwrap());
                b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
            } else {
                // flag-based: the FLAGS slot uses x86 RFLAGS bit layout (CF=1,ZF=0x40,
                // SF=0x80,OF=0x800,PF=4), so load it into RFLAGS and use the setcc
                // matching the x86 condition code semantics.
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(FLAGS_OFF)).unwrap());
                b.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
                b.push(Instruction::with(Code::Popfq));
                let setcc = match k {
                    1 => Code::Sete_rm8,
                    2 => Code::Setne_rm8,
                    3 => Code::Setb_rm8,
                    4 => Code::Setae_rm8,
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
                b.push(Instruction::with1(setcc, Register::AL).unwrap());
                b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
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

    // P2 (G3): INC/DEC 플래그 저장 — x86 INC/DEC는 **CF를 보존**한다 (eval_state의
    // update_inc/update_dec와 동일). 하드웨어 `inc/dec`는 CF를 변경하지 않으므로
    // FLAG_MASK에서 CF 비트를 제외하고, FLAGS_OFF 슬롯의 기존 CF를 그대로 합병한다.
    fn emit_store_flags_incdec(b: &mut CodeBuilder) {
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, (FLAG_MASK & !1) as u32).unwrap()); // CF 제외
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 1).unwrap()); // 기존 CF
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
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
        // FIX(ABI): the dispatcher is invoked via an `extern "C"` call (arena.call
        // / boot stub), which requires the callee to preserve ALL Win64
        // callee-saved registers (RDI, RSI, RBX, RBP in addition to R12-R15).
        // Handlers (CompareExchange uses RBX, others use RDI/RSI/RBX/RBP) clobber
        // them; without saving here the Rust caller's state is corrupted after the
        // call returns (AV in the differential tests). HALT pops them in reverse.
        b.push(Instruction::with1(Code::Push_r64, Register::RDI).unwrap());
        b.push(Instruction::with1(Code::Push_r64, Register::RSI).unwrap());
        b.push(Instruction::with1(Code::Push_r64, Register::RBX).unwrap());
        b.push(Instruction::with1(Code::Push_r64, Register::RBP).unwrap());
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
        // P6-1: handler 테이블 XOR 복호화 — 평문 테이블에는 `handler_va ^ table_key`
        // 만 있어 정적 분석으로 handler 위치를 읽을 수 없다.
        movi(&mut b, Register::RCX, table_key);
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RCX).unwrap());
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
        // Zero the DEC_CIN slot first so immediate-operand adds don't add a stale cin
        // left by an earlier register-operand add/sub (emit_sub writes cin=1 there).
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RAX).unwrap());
        store_m(&mut b, DEC_CIN, Register::RAX);
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
        // ZF|SF|PF from res (test sets x86 PF = parity of low byte, matching the
        // reference update_add64 which recomputes PF from the result)
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap());
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xC4).unwrap()); // ZF|SF|PF
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
        b.push(Instruction::with2(Code::Lea_r64_m, Register::R11, MemoryOperand::with_base_displ_size(Register::RBX, 4, 8)).unwrap());
        let scan_top = b.len();
        {
            b.push(Instruction::with2(Code::Cmp_rm64_r64, MemoryOperand::with_base(Register::R11), Register::R10).unwrap());
            b.br(Code::Je_rel32_64, 0x9401); // found
            b.push(Instruction::with2(Code::Add_rm64_imm32, Register::R11, 16).unwrap());
            b.push(Instruction::with1(Code::Dec_rm64, Register::RCX).unwrap());
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
            b.jne(scan_top);
        }
        // ── NATIVE CALL BRIDGE (legacy OP_NATIVE_CALL equivalent) ─────────────
        // The target was NOT found in the branch map → it is an excluded (SEH /
        // RISC-unliftable) function kept native. The lifted call was
        // `VirtualPush(ret_ip); VirtualBranch(Always, target)`, so the virtual
        // stack top holds the return address. Bridge to the native function:
        //   1. pop ret_ip from the virtual stack,
        //   2. save the VM infra the callee will clobber (state_base/bytecode_base)
        //      in callee-saved registers (re-synced after the call),
        //   3. materialize the program's real GPRs (regs[0..15]) for the Win64 call,
        //   4. build a fresh 16-aligned native frame + forward stack args,
        //   5. `call target`, sync the clobbered volatile GPRs + RFLAGS back,
        //   6. restore the VM infra and resume at ret_ip (branch-map → rolling-key
        //      re-sync → dispatch).
        // Register contract across the call (Win64 callee-saved, preserved by the
        // callee): RBX/RBP/RSI/RDI/R12-R15. We use them as scratch for the infra:
        //   RBX = original RSP, RBP = ret_ip, RSI = align remainder,
        //   RDI = target, R12 = state_base, R14 = bytecode_base.
        //   R13 (vstack top) / R15 (table) stay intact throughout.
        let nf_real = b.len();
        {
            // 1. pop ret_ip from the virtual stack (R13 top).
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBP, MemoryOperand::with_base(Register::R13)).unwrap());
            b.push(Instruction::with2(Code::Add_rm64_imm8, Register::R13, 8).unwrap());
            mov_m(&mut b, Register::RAX, VSP_OFF);
            b.push(Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 8).unwrap());
            store_m(&mut b, VSP_OFF, Register::RAX);

            // 2. stage infra in callee-saved regs.
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R12, Register::RDX).unwrap()); // state_base
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::R8).unwrap());  // bytecode_base
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDI, Register::R10).unwrap()); // target
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP).unwrap()); // original S

            // 3. load the program's real GPRs from the state buffer (R12 = state_base).
            //    RAX/RCX/RDX/R8/R9/R10/R11 are the call args + return + volatile scratch.
            //    RBX/RBP/RSI/RDI/R12..R15 are NOT loaded (they hold the VM infra /
            //    bridge scratch); regs[3,5,6,7,12..15] keep their pre-call values in
            //    the state buffer, which is correct — they are callee-saved.
            let sl = |b: &mut CodeBuilder, dst: Register, off: i32| {
                b.push(Instruction::with2(
                    Code::Mov_r64_rm64,
                    dst,
                    MemoryOperand::with_base_displ_size(Register::R12, off as i64, 8),
                ).unwrap());
            };
            sl(&mut b, Register::RAX, 0x00);
            sl(&mut b, Register::RCX, 0x08);
            sl(&mut b, Register::RDX, 0x10);
            sl(&mut b, Register::R8, 0x40);
            sl(&mut b, Register::R9, 0x48);
            sl(&mut b, Register::R10, 0x50);
            sl(&mut b, Register::R11, 0x58);

            // 4. native frame: align RSP to 16, allocate 0x70 (ret + 0x20 home +
            //    0x40 stack args). RSI = align remainder for the restore.
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::RBX).unwrap());
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RSI, 15).unwrap());
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RSP, -16).unwrap());
            b.push(Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, 0x70).unwrap());

            // 5. forward stack args (5..12) from the virtual stack to [RSP+0x28..].
            //    pending = |VSP|/8 (after the ret_ip pop) capped at 8; VSP >= 0 → none.
            //    NOTE: RDX no longer holds state_base here (it was loaded with regs[2]),
            //    so the VSP slot is read via R12.
            b.push(Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_displ_size(Register::R12, VSP_OFF as i64, 8),
            ).unwrap());
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
            b.br(Code::Jns_rel32_64, 0xB0FF); // VSP >= 0 -> no pending entries
            b.push(Instruction::with1(Code::Neg_rm64, Register::RAX).unwrap());
            b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 3).unwrap());
            // cap pending at 8: RAX = min(RAX, 8).
            b.push(Instruction::with2(Code::Mov_r64_imm64, Register::RCX, 8).unwrap());
            b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::RAX, Register::RCX).unwrap());
            b.push(Instruction::with2(Code::Cmova_r64_rm64, Register::RAX, Register::RCX).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).unwrap());
            let fwd_top = b.len();
            {
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
                let fwd_done = b.len() + 1;
                b.je(fwd_done);
                // index = RCX-1 (forward from the top of the virtual stack).
                b.push(Instruction::with2(Code::Lea_r64_m, Register::R10, MemoryOperand::with_base_index_scale_displ_size(Register::R13, Register::RCX, 8, -8, 8)).unwrap());
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, MemoryOperand::with_base(Register::R10)).unwrap());
                // slot = RSP + 0x28 + (RCX-1)*8
                b.push(Instruction::with2(Code::Lea_r64_m, Register::R11, MemoryOperand::with_base_index_scale_displ_size(Register::RSP, Register::RCX, 8, 0x20, 8)).unwrap());
                b.push(Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base(Register::R11), Register::R10).unwrap());
                b.push(Instruction::with1(Code::Dec_rm64, Register::RCX).unwrap());
                b.jmp(fwd_top);
                let loop_end = b.len();
                for &mut (bi, ref mut ti) in b.branches.iter_mut() {
                    if *ti == fwd_done {
                        *ti = loop_end;
                    }
                }
            }
            let after_fwd = b.len();
            for &mut (bi, ref mut ti) in b.branches.iter_mut() {
                if *ti == 0xB0FF {
                    *ti = after_fwd;
                }
            }

            // 6. Win64 call target (RDI). args are already in RCX/RDX/R8/R9, stack
            //    args 5..12 in [RSP+0x28..0x68], home space at [RSP+0x08..0x28].
            b.push(Instruction::with1(Code::Call_rm64, Register::RDI).unwrap());

            // 7. after the call: RSP == RSP_call. Sync volatile GPRs + RFLAGS back.
            b.push(Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ_size(Register::R12, 0x00, 8), Register::RAX).unwrap());
            b.push(Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ_size(Register::R12, 0x08, 8), Register::RCX).unwrap());
            b.push(Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ_size(Register::R12, 0x10, 8), Register::RDX).unwrap());
            b.push(Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ_size(Register::R12, 0x40, 8), Register::R8).unwrap());
            b.push(Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ_size(Register::R12, 0x48, 8), Register::R9).unwrap());
            b.push(Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ_size(Register::R12, 0x50, 8), Register::R10).unwrap());
            b.push(Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ_size(Register::R12, 0x58, 8), Register::R11).unwrap());
            // RFLAGS (whatever the callee left) → FLAGS slot.
            b.push(Instruction::with(Code::Pushfq));
            b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x8D5).unwrap());
            b.push(Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ_size(Register::R12, 0xC0, 8), Register::RAX).unwrap());

            // 8. restore the VM real stack (RSP = original S) and infra.
            b.push(Instruction::with2(Code::Add_rm64_imm32, Register::RSP, 0x70).unwrap());
            b.push(Instruction::with2(Code::Add_rm64_r64, Register::RSP, Register::RSI).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R12).unwrap()); // state_base
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::R14).unwrap());  // bytecode_base

            // 9. resume at ret_ip (RBP): branch-map lookup -> byte offset.
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R15).unwrap());
            b.push(Instruction::with2(Code::Add_rm64_imm32, Register::RBX, (OFF_BRANCH_MAP - OFF_TABLE) as i32).unwrap());
            b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, MemoryOperand::with_base(Register::RBX)).unwrap());
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
            b.br(Code::Je_rel32_64, 0xB100); // count == 0 -> not found
            b.push(Instruction::with2(Code::Lea_r64_m, Register::R11, MemoryOperand::with_base_displ_size(Register::RBX, 4, 8)).unwrap());
            let rscan_top = b.len();
            {
                b.push(Instruction::with2(Code::Cmp_rm64_r64, MemoryOperand::with_base(Register::R11), Register::RBP).unwrap());
                b.br(Code::Je_rel32_64, 0xB101); // found
                b.push(Instruction::with2(Code::Add_rm64_imm32, Register::R11, 16).unwrap());
                b.push(Instruction::with1(Code::Dec_rm64, Register::RCX).unwrap());
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
                b.jne(rscan_top);
                b.br(Code::Jmp_rel32_64, 0xB100); // not found
            }
            // found: RBX = [R11+8] (byte offset).
            let resume_found_real = b.len();
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, MemoryOperand::with_base_displ_size(Register::R11, 8, 8)).unwrap());
            b.br(Code::Jmp_rel32_64, 0xB200);
            // not found: fall back to treating ret_ip as a direct byte offset.
            let resume_nf_real = b.len();
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RBP).unwrap());
            // re-sync the rolling key from bytecode start to the resume offset.
            let resume_sync = b.len();
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R12, Register::R12).unwrap());
            movi(&mut b, Register::R14, init_key);
            b.call(sub_resync);
            b.jmp(dispatch);
            for i in 0..b.branches.len() {
                let t = b.branches[i].1;
                if t == 0xB100 {
                    b.branches[i].1 = resume_nf_real;
                } else if t == 0xB101 {
                    b.branches[i].1 = resume_found_real;
                } else if t == 0xB200 {
                    b.branches[i].1 = resume_sync;
                }
            }
        }
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
        // restore ALL callee-saved registers pushed at entry (reverse order).
        b.push(Instruction::with1(Code::Pop_r64, Register::RBP).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::RBX).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::RSI).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::RDI).unwrap());
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

    // ── P2 (G3): 폭별 ALU 핸들러 — Add/SubWithBorrow/Inc/Dec/Not {width}. ──────
    // eval_state와 동치: 폭별 하드웨어 플래그(Add/Sub), CF 보존(Inc/Dec), 플래그
    // 불변(Not), 부분-쓰기 상위 비트 보존(8/16비트는 하드웨어가 이미 보존).
    fn emit_width_alu_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        sub_store: usize,
        dispatch: usize,
        op: WidthAluOp,
        width: u8,
    ) {
        b.call(sub_dec_ops);
        // src1 -> R10
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        // src2 -> R11 (Add/Sub만; Inc/Dec/Not는 src1 단일)
        if op == WidthAluOp::Add || op == WidthAluOp::Sub {
            movzx8_m(b, Register::EAX, DEC_SRC2);
            mov_m(b, Register::R11, DEC_IMM2);
            b.call(sub_resolve);
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        }
        // 폭별 연산 (x86 부분-쓰기: 8/16비트는 상위 비트 보존 — eval_state의
        // preserve_upper와 동치).
        match (op, width) {
            (WidthAluOp::Add, 1) => b.push(Instruction::with2(Code::Add_rm8_r8, Register::R10L, Register::R11L).unwrap()),
            (WidthAluOp::Add, 2) => b.push(Instruction::with2(Code::Add_rm16_r16, Register::R10W, Register::R11W).unwrap()),
            (WidthAluOp::Add, 4) => b.push(Instruction::with2(Code::Add_rm32_r32, Register::R10D, Register::R11D).unwrap()),
            (WidthAluOp::Add, _) => b.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11).unwrap()),
            (WidthAluOp::Sub, 1) => b.push(Instruction::with2(Code::Sub_rm8_r8, Register::R10L, Register::R11L).unwrap()),
            (WidthAluOp::Sub, 2) => b.push(Instruction::with2(Code::Sub_rm16_r16, Register::R10W, Register::R11W).unwrap()),
            (WidthAluOp::Sub, 4) => b.push(Instruction::with2(Code::Sub_rm32_r32, Register::R10D, Register::R11D).unwrap()),
            (WidthAluOp::Sub, _) => b.push(Instruction::with2(Code::Sub_rm64_r64, Register::R10, Register::R11).unwrap()),
            (WidthAluOp::Inc, 1) => b.push(Instruction::with1(Code::Inc_rm8, Register::R10L).unwrap()),
            (WidthAluOp::Inc, 2) => b.push(Instruction::with1(Code::Inc_rm16, Register::R10W).unwrap()),
            (WidthAluOp::Inc, 4) => b.push(Instruction::with1(Code::Inc_rm32, Register::R10D).unwrap()),
            (WidthAluOp::Inc, _) => b.push(Instruction::with1(Code::Inc_rm64, Register::R10).unwrap()),
            (WidthAluOp::Dec, 1) => b.push(Instruction::with1(Code::Dec_rm8, Register::R10L).unwrap()),
            (WidthAluOp::Dec, 2) => b.push(Instruction::with1(Code::Dec_rm16, Register::R10W).unwrap()),
            (WidthAluOp::Dec, 4) => b.push(Instruction::with1(Code::Dec_rm32, Register::R10D).unwrap()),
            (WidthAluOp::Dec, _) => b.push(Instruction::with1(Code::Dec_rm64, Register::R10).unwrap()),
            (WidthAluOp::Not, 1) => b.push(Instruction::with1(Code::Not_rm8, Register::R10L).unwrap()),
            (WidthAluOp::Not, 2) => b.push(Instruction::with1(Code::Not_rm16, Register::R10W).unwrap()),
            (WidthAluOp::Not, 4) => b.push(Instruction::with1(Code::Not_rm32, Register::R10D).unwrap()),
            (WidthAluOp::Not, _) => b.push(Instruction::with1(Code::Not_rm64, Register::R10).unwrap()),
        };
        // 플래그: Add/Sub → 폭별 하드웨어 플래그(CF|PF|ZF|SF|OF). Inc/Dec → CF
        // 보존(emit_store_flags_incdec). Not → 플래그 불변 (x86 NOT).
        match op {
            WidthAluOp::Add | WidthAluOp::Sub => emit_store_flags(b),
            WidthAluOp::Inc | WidthAluOp::Dec => emit_store_flags_incdec(b),
            WidthAluOp::Not => {}
        }
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    // ── R4: SSE/FPU 스칼라 네이티브 핸들러 ─────────────────────────────────────
    // eval_state(참조)와 동치: 피연산자는 폭(4/8) f32/f64 **비트 패턴** u64 값이고,
    // 결과도 비트 패턴으로 저장한다. XMM0/XMM1 만 스크래치로 쓰고 플래그를
    // 변경하지 않는다 (SSE 스칼라 산술은 RFLAGS 불변 — 참조도 플래그 무변경).
    // (호스트 XMM 레지스터는 게스트 XMM 상태와 무관 — 게스트는 XMM_SLOT_BASE
    // 가상 메모리에 저장되므로 네이티브 XMM 클로버는 안전.)
    fn emit_float_bin_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        sub_store: usize,
        dispatch: usize,
        width: u8,
        op32: Code, // f32: Addss/Subss/Mulss/Divss
        op64: Code, // f64: Addsd/Subsd/Mulsd/Divsd
    ) {
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
        // XMM0 = src1 bits, XMM1 = src2 bits, op, result bits -> R10.
        if width == 4 {
            b.push(Instruction::with2(Code::Movd_xmm_rm32, Register::XMM0, Register::R10D).unwrap());
            b.push(Instruction::with2(Code::Movd_xmm_rm32, Register::XMM1, Register::R11D).unwrap());
            b.push(Instruction::with2(op32, Register::XMM0, Register::XMM1).unwrap());
            b.push(Instruction::with2(Code::Movd_rm32_xmm, Register::R10D, Register::XMM0).unwrap());
        } else {
            b.push(Instruction::with2(Code::Movq_xmm_rm64, Register::XMM0, Register::R10).unwrap());
            b.push(Instruction::with2(Code::Movq_xmm_rm64, Register::XMM1, Register::R11).unwrap());
            b.push(Instruction::with2(op64, Register::XMM0, Register::XMM1).unwrap());
            b.push(Instruction::with2(Code::Movq_rm64_xmm, Register::R10, Register::XMM0).unwrap());
        }
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    /// R4: unary float 변환 — IntToFloat / FloatToInt / FloatToFloat.
    /// IntToFloat:  (int)src → f32/f64 bits. src_bits=4: 부호-확장(i32→i64).
    /// FloatToInt:  f32/f64 → int, truncate=false 는 round-half-even (MXCSR 기본
    ///              RC=RN-even 과 동일), NaN/overflow 는 hardware가 indefinite
    ///              (0x8000_0000 / 0x8000_0000_0000_0000) 생성 = 참조와 동일.
    /// FloatToFloat: f32↔f64 변환.
    fn emit_float_cvt_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        sub_store: usize,
        dispatch: usize,
        src_bits: u8,
        dst_bits: u8,
        truncate: bool,
        mode: FloatCvtMode,
    ) {
        b.call(sub_dec_ops);
        // src1 -> R10
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        match mode {
            // IntToFloat: src 는 정수, dst 는 float bits.
            FloatCvtMode::IntToFloat => {
                let (load_code, use_32) = if src_bits == 4 {
                    (Code::Cvtsi2ss_xmm_rm32, true)
                } else {
                    (Code::Cvtsi2ss_xmm_rm64, false)
                };
                let load_code = if dst_bits == 8 {
                    if use_32 { Code::Cvtsi2sd_xmm_rm32 } else { Code::Cvtsi2sd_xmm_rm64 }
                } else {
                    load_code
                };
                let src_reg = if use_32 { Register::R10D } else { Register::R10 };
                b.push(Instruction::with2(load_code, Register::XMM0, src_reg).unwrap());
                if dst_bits == 4 {
                    b.push(Instruction::with2(Code::Movd_rm32_xmm, Register::R10D, Register::XMM0).unwrap());
                } else {
                    b.push(Instruction::with2(Code::Movq_rm64_xmm, Register::R10, Register::XMM0).unwrap());
                }
            }
            // FloatToInt: src 는 float bits, dst 는 정수 (indefinite 포함).
            FloatCvtMode::FloatToInt => {
                if src_bits == 4 {
                    b.push(Instruction::with2(Code::Movd_xmm_rm32, Register::XMM0, Register::R10D).unwrap());
                } else {
                    b.push(Instruction::with2(Code::Movq_xmm_rm64, Register::XMM0, Register::R10).unwrap());
                }
                let (cvt_code, dst_reg) = match (src_bits, dst_bits, truncate) {
                    (4, 4, true) => (Code::Cvttss2si_r32_xmmm32, Register::R10D),
                    (4, 4, false) => (Code::Cvtss2si_r32_xmmm32, Register::R10D),
                    (4, 8, true) => (Code::Cvttss2si_r64_xmmm32, Register::R10),
                    (4, 8, false) => (Code::Cvtss2si_r64_xmmm32, Register::R10),
                    (8, 4, true) => (Code::Cvttsd2si_r32_xmmm64, Register::R10D),
                    (8, 4, false) => (Code::Cvtsd2si_r32_xmmm64, Register::R10D),
                    (8, 8, true) => (Code::Cvttsd2si_r64_xmmm64, Register::R10),
                    _ => (Code::Cvtsd2si_r64_xmmm64, Register::R10),
                };
                b.push(Instruction::with2(cvt_code, dst_reg, Register::XMM0).unwrap());
            }
            // FloatToFloat: f32↔f64 변환.
            FloatCvtMode::FloatToFloat => {
                if src_bits == 4 {
                    b.push(Instruction::with2(Code::Movd_xmm_rm32, Register::XMM0, Register::R10D).unwrap());
                    b.push(Instruction::with2(Code::Cvtss2sd_xmm_xmmm32, Register::XMM0, Register::XMM0).unwrap());
                    b.push(Instruction::with2(Code::Movq_rm64_xmm, Register::R10, Register::XMM0).unwrap());
                } else {
                    b.push(Instruction::with2(Code::Movq_xmm_rm64, Register::XMM0, Register::R10).unwrap());
                    b.push(Instruction::with2(Code::Cvtsd2ss_xmm_xmmm64, Register::XMM0, Register::XMM0).unwrap());
                    b.push(Instruction::with2(Code::Movd_rm32_xmm, Register::R10D, Register::XMM0).unwrap());
                }
            }
        }
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    // ── P3: SETCC / CONDITIONAL_MOVE — cond-byte native handlers. ──────────────
    // Both decode a single cond byte (right after the opcode) via `sub_dec_ops_cond`,
    // which maps it through the OFF_COND_CODES table into the DEC_COND state slot
    // (canonical COND_* code). The cond is evaluated from the FLAGS slot
    // (CF/ZF/SF/OF at 0x1/0x40/0x80/0x800, PF at 0x4) plus regs[1] (CounterZero),
    // producing a 0/1 boolean in R10. Reference semantics (eval_state / interpreter):
    //   Setcc:            dst = taken ? 1 : 0           (flags untouched)
    //   ConditionalMove:  if taken: dst = src1          (flags untouched)
    // A dispatch chain branches on the canonical cond code; each cond block sets
    // R10 = 0/1 branch-free (test+setcc, arithmetic for the signed pairs), then
    // jumps to the handler continuation. Unknown cond (0xFF) falls through with
    // R10 = 0 (Setcc -> 0, CMOV -> no-op).
    /// Emit the body of one cond block: set R10 = 0/1 for canonical cond code `c`,
    /// given R11 = flags and R9 = regs[1]. RAX/RCX are scratch.
    fn emit_cond_block_body(b: &mut CodeBuilder, c: u8) {
        let setne = |b: &mut CodeBuilder| {
            b.push(Instruction::with1(Code::Setne_rm8, Register::R10L).unwrap());
            b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).unwrap());
        };
        let sete = |b: &mut CodeBuilder| {
            b.push(Instruction::with1(Code::Sete_rm8, Register::R10L).unwrap());
            b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).unwrap());
        };
        // delta = SF^OF (0 iff SF==OF) computed in RAX.
        let emit_delta = |b: &mut CodeBuilder| {
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap());
            b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 7).unwrap());
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R11).unwrap());
            b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RCX, 11).unwrap());
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 1).unwrap());
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RCX).unwrap());
        };
        match c {
            COND_ALWAYS => {
                b.push(Instruction::with2(Code::Mov_r64_imm64, Register::R10, 1).unwrap());
            }
            COND_ZERO => {
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x40).unwrap());
                setne(b);
            }
            COND_NOT_ZERO => {
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x40).unwrap());
                sete(b);
            }
            COND_CARRY => {
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x1).unwrap());
                setne(b);
            }
            COND_NOT_CARRY => {
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x1).unwrap());
                sete(b);
            }
            COND_SIGN => {
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x80).unwrap());
                setne(b);
            }
            COND_NOT_SIGN => {
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x80).unwrap());
                sete(b);
            }
            COND_OVERFLOW => {
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x800).unwrap());
                setne(b);
            }
            COND_NOT_OVERFLOW => {
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x800).unwrap());
                sete(b);
            }
            COND_GREATER => {
                // G = !ZF && (SF==OF) = e & nz
                emit_delta(b);
                b.push(Instruction::with2(Code::Xor_rm64_imm32, Register::RAX, 1).unwrap()); // e = SF==OF
                b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).unwrap());
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R11).unwrap());
                b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RCX, 6).unwrap());
                b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 1).unwrap());
                b.push(Instruction::with2(Code::Xor_rm64_imm32, Register::RCX, 1).unwrap()); // nz = !ZF
                b.push(Instruction::with2(Code::And_rm64_r64, Register::RAX, Register::RCX).unwrap());
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
            }
            COND_LESS => {
                // L = SF!=OF = delta
                emit_delta(b);
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
                setne(b);
            }
            COND_GREATER_OR_EQUAL => {
                // GE = SF==OF = !delta
                emit_delta(b);
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
                sete(b);
            }
            COND_LESS_OR_EQUAL => {
                // LE = ZF || (SF!=OF) = z | delta
                emit_delta(b);
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R11).unwrap());
                b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RCX, 6).unwrap());
                b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 1).unwrap());
                b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
            }
            COND_ABOVE => {
                // A = !CF && !ZF
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x41).unwrap());
                sete(b);
            }
            COND_ABOVE_OR_EQUAL => {
                // AE = !CF
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x1).unwrap());
                sete(b);
            }
            COND_BELOW => {
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x1).unwrap());
                setne(b);
            }
            COND_BELOW_OR_EQUAL => {
                // BE = CF || ZF
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x41).unwrap());
                setne(b);
            }
            COND_PARITY => {
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x4).unwrap());
                setne(b);
            }
            COND_NOT_PARITY => {
                b.push(Instruction::with2(Code::Test_rm64_imm32, Register::R11, 0x4).unwrap());
                sete(b);
            }
            COND_COUNTER_ZERO_2 => {
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R9).unwrap());
                b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RAX, 48).unwrap());
                b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 48).unwrap());
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
                sete(b);
            }
            COND_COUNTER_ZERO_4 => {
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R9).unwrap());
                b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RAX, 32).unwrap());
                b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 32).unwrap());
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
                sete(b);
            }
            COND_COUNTER_ZERO_8 => {
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9).unwrap());
                sete(b);
            }
            _ => {
                // invalid cond: R10 stays 0.
            }
        }
    }

    fn emit_setcc_cmov_handler(
        b: &mut CodeBuilder,
        sub_dec_ops_cond: usize,
        sub_dec_ops: usize,
        sub_resolve: usize,
        sub_store: usize,
        dispatch: usize,
        is_cmov: bool,
    ) -> usize {
        let h = b.len();
        {
            // consume cond byte -> DEC_COND, then dst/src1/src2 + imms.
            b.call(sub_dec_ops_cond);
            b.call(sub_dec_ops);
            // prelude: flags -> R11, regs[1] -> R9, result R10 = 0, cond -> ECX.
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(FLAGS_OFF)).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, m(REGS_OFF + 8)).unwrap());
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R10, Register::R10).unwrap());
            movzx8_m(b, Register::ECX, DEC_COND);
            // dispatch chain over the canonical cond codes.
            let conds: [u8; 22] = [
                COND_ALWAYS, COND_ZERO, COND_NOT_ZERO, COND_CARRY, COND_NOT_CARRY,
                COND_SIGN, COND_NOT_SIGN, COND_OVERFLOW, COND_NOT_OVERFLOW, COND_GREATER,
                COND_LESS, COND_GREATER_OR_EQUAL, COND_LESS_OR_EQUAL, COND_ABOVE,
                COND_ABOVE_OR_EQUAL, COND_BELOW, COND_BELOW_OR_EQUAL, COND_PARITY,
                COND_NOT_PARITY, COND_COUNTER_ZERO_2, COND_COUNTER_ZERO_4, COND_COUNTER_ZERO_8,
            ];
            let mut je_bi: Vec<(u8, usize)> = Vec::with_capacity(conds.len());
            for c in conds {
                b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, c as i32).unwrap());
                je_bi.push((c, b.br(Code::Je_rel32_64, 0)));
            }
            // continuation (unknown cond falls through here with R10 = 0).
            let cont = b.len();
            if is_cmov {
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap());
                let skip_guess = b.len() + 1;
                b.je(skip_guess);
                movzx8_m(b, Register::EAX, DEC_SRC1);
                mov_m(b, Register::R11, DEC_IMM1);
                b.call(sub_resolve);
                b.call(sub_store);
                let djmp = b.len();
                b.jmp(dispatch);
                for &mut (bi, ref mut ti) in b.branches.iter_mut() {
                    if *ti == skip_guess {
                        *ti = djmp;
                    }
                }
            } else {
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
                b.call(sub_store);
                b.jmp(dispatch);
            }
            // per-cond blocks (after the continuation): set R10 then jump to cont.
            for &(c, bi) in &je_bi {
                let blk = b.len();
                for &mut (bii, ref mut ti) in b.branches.iter_mut() {
                    if bii == bi {
                        *ti = blk;
                    }
                }
                emit_cond_block_body(b, c);
                b.jmp(cont);
            }
        }
        h
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

    // ── P2 (G3): width-aware ALU 핸들러 (Add/SubWithBorrow/Inc/Dec/Not {width}) ──
    // 전체 프로그램 리프트가 내는 `Add {width}`/`SubWithBorrow {width}`/`Inc`/`Dec`/
    // `Not {width}` op는 지금까지 **핸들러 미등록 → h_nop(no-op)**이었다. h_nop는
    // 바이트만 소비하고 의미를 실행하지 않으므로, `sub rsp`/`cmp`/`test`가 무시되어
    // 새로 가상화된 블록(예: RIP-relative 블록)에서 가상 스택/플래그가 틀어져
    // keystream desync → 0xC0000005를 일으킨다. 여기서 폭별 네이티브 핸들러를
    // 등록해 eval_state와 동치(폭별 하드웨어 플래그 + 부분-쓰기 상위 비트 보존)로
    // 실행한다.
    let mut addw_h = [0usize; 4];
    let mut subw_h = [0usize; 4];
    let mut incw_h = [0usize; 4];
    let mut decw_h = [0usize; 4];
    let mut notw_h = [0usize; 4];
    for (wi, w) in [1u8, 2, 4, 8].iter().enumerate() {
        addw_h[wi] = b.len();
        emit_width_alu_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, WidthAluOp::Add, *w);
        subw_h[wi] = b.len();
        emit_width_alu_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, WidthAluOp::Sub, *w);
        incw_h[wi] = b.len();
        emit_width_alu_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, WidthAluOp::Inc, *w);
        decw_h[wi] = b.len();
        emit_width_alu_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, WidthAluOp::Dec, *w);
        notw_h[wi] = b.len();
        emit_width_alu_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, WidthAluOp::Not, *w);
    }

    // ── R4: SSE/FPU 스칼라 핸들러 세트 — FloatAdd/Sub/Mul/Div{4,8} +
    // IntToFloat/FloatToInt/FloatToFloat (모든 reachable src/dst_bits·truncate).
    // 이전에는 isa_spec 미포함 → `--vm-commercial`이 FP 함수를 통째로 네이티브
    // 유지했다. 여기서 폴리 인코딩 + 네이티브 self-decoding 실행이 eval_state와
    // 동치가 되도록 등록한다. (플래그 불변 — SSE 스칼라 산술은 RFLAGS 미변경.)
    let mut fadd_h = [0usize; 2];
    let mut fsub_h = [0usize; 2];
    let mut fmul_h = [0usize; 2];
    let mut fdiv_h = [0usize; 2];
    for (wi, w) in [4u8, 8].iter().enumerate() {
        fadd_h[wi] = b.len();
        emit_float_bin_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, *w, Code::Addss_xmm_xmmm32, Code::Addsd_xmm_xmmm64);
        fsub_h[wi] = b.len();
        emit_float_bin_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, *w, Code::Subss_xmm_xmmm32, Code::Subsd_xmm_xmmm64);
        fmul_h[wi] = b.len();
        emit_float_bin_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, *w, Code::Mulss_xmm_xmmm32, Code::Mulsd_xmm_xmmm64);
        fdiv_h[wi] = b.len();
        emit_float_bin_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, *w, Code::Divss_xmm_xmmm32, Code::Divsd_xmm_xmmm64);
    }
    let mut fi2f_h = [[0usize; 2]; 2]; // [src_bits_idx][dst_bits_idx]
    let mut ff2i_h = [[[0usize; 2]; 2]; 2]; // [src][dst][truncate]
    let mut ff2f_h = [[0usize; 2]; 2];
    for (si, sb) in [4u8, 8].iter().enumerate() {
        for (di, db) in [4u8, 8].iter().enumerate() {
            fi2f_h[si][di] = b.len();
            emit_float_cvt_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, *sb, *db, false, FloatCvtMode::IntToFloat);
            ff2f_h[si][di] = b.len();
            emit_float_cvt_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, *sb, *db, false, FloatCvtMode::FloatToFloat);
            for (ti, tr) in [false, true].iter().enumerate() {
                ff2i_h[si][di][ti] = b.len();
                emit_float_cvt_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, *sb, *db, *tr, FloatCvtMode::FloatToInt);
            }
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

    // ── P3: SETCC / CONDITIONAL_MOVE handler sets (cond byte via DEC_COND). ────
    let h_setcc = emit_setcc_cmov_handler(&mut b, sub_dec_ops_cond, sub_dec_ops, sub_resolve, sub_store, dispatch, false);
    let h_cmov = emit_setcc_cmov_handler(&mut b, sub_dec_ops_cond, sub_dec_ops, sub_resolve, sub_store, dispatch, true);

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
        h.insert(RiscOp::Setcc { cond: BranchCondition::Always }, h_setcc);
        h.insert(RiscOp::ConditionalMove { cond: BranchCondition::Always }, h_cmov);
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
        // P2 (G3): width-aware ALU — Add/SubWithBorrow/Inc/Dec/Not {width} 핸들러.
        for (wi, w) in [1u8, 2, 4, 8].iter().enumerate() {
            h.insert(RiscOp::Add { width: *w }, addw_h[wi]);
            h.insert(RiscOp::SubWithBorrow { width: *w }, subw_h[wi]);
            h.insert(RiscOp::Inc { width: *w }, incw_h[wi]);
            h.insert(RiscOp::Dec { width: *w }, decw_h[wi]);
            h.insert(RiscOp::Not { width: *w }, notw_h[wi]);
        }
        // R4: SSE/FPU 스칼라 — FloatAdd/Sub/Mul/Div{4,8} + IntToFloat/FloatToInt/
        // FloatToFloat 네이티브 핸들러 등록 (플래그 불변, eval_state와 동치).
        for (wi, w) in [4u8, 8].iter().enumerate() {
            h.insert(RiscOp::FloatAdd { width: *w }, fadd_h[wi]);
            h.insert(RiscOp::FloatSub { width: *w }, fsub_h[wi]);
            h.insert(RiscOp::FloatMul { width: *w }, fmul_h[wi]);
            h.insert(RiscOp::FloatDiv { width: *w }, fdiv_h[wi]);
        }
        for (si, sb) in [4u8, 8].iter().enumerate() {
            for (di, db) in [4u8, 8].iter().enumerate() {
                h.insert(RiscOp::IntToFloat { src_bits: *sb, dst_bits: *db }, fi2f_h[si][di]);
                h.insert(RiscOp::FloatToFloat { src_bits: *sb, dst_bits: *db }, ff2f_h[si][di]);
                for (ti, tr) in [false, true].iter().enumerate() {
                    h.insert(
                        RiscOp::FloatToInt { src_bits: *sb, dst_bits: *db, truncate: *tr },
                        ff2i_h[si][di][ti],
                    );
                }
            }
        }
        h.insert(RiscOp::Halt, h_halt);
        // NativeCallBridge — reference/interpreter는 no-op(스트림 소비, 상태 불변).
        // h_nop과 동일 의미이므로 명시 등록해 [P2-HANDLER-GAP] 감사를 깨끗하게 한다.
        h.insert(RiscOp::NativeCallBridge, h_nop);
        h
    };

    // P2 (G3): **h_nop fallback 전수 감사** — 인코딩 가능한 op 중 네이티브 핸들러가
    // 없는 op는 h_nop(바이트 소비만, 의미 no-op)으로 떨어진다. 이전에 Add/Sub/
    // Inc/Dec/Not {width}가 여기 빠져 전체 프로그램에서 조용히 무시되던 버그가
    // 있었다. 여기서 남은 미등록 op를 즉시 노출해 재발을 막는다.
    {
        let mut unhandled: Vec<String> = Vec::new();
        for (op, _byte) in &spec.opcode_map {
            if !handlers.contains_key(op) {
                unhandled.push(format!("{:?}", op));
            }
        }
        if !unhandled.is_empty() {
            println!(
                "[P2-HANDLER-GAP] {} encodable op(s) have NO native handler (h_nop no-op fallback):",
                unhandled.len()
            );
            for u in unhandled {
                println!("    - {}", u);
            }
        } else {
            println!("[P2-HANDLER-GAP] all encodable ops have native handlers");
        }
    }

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
    // P6-1: 시드 유래 테이블 키로 handler VA 를 XOR 암호화한다. dispatch loop 의
    // `table[op] ^ key` 복호화와 짝을 이룬다. 평문 테이블에는 암호화된 값만 있어
    // 정적 분석으로 opcode↔handler 매핑을 직접 읽을 수 없다.
    let mut table = vec![va_of(h_nop) as u64; 256];
    for (op, byte) in &spec.opcode_map {
        if let Some(&hidx) = handlers.get(op) {
            table[*byte as usize] = va_of(hidx) ^ table_key;
        }
    }

    Ok(SelfDecodingParts { code, table, table_key, offs_tab, flags_tab, cond_codes, branch_map })
}

/// Run the self-decoding dispatcher in an RWX arena (host-side test/bench path):
/// build the parts at arena-relative VAs, copy them in, set the initial regs in
/// the state buffer and jump to the dispatcher entry.
/// Backward-compatible 3-arg runner (no ip_map) — delegates to `_with` with None.
pub fn run_native_poly_direct(
    bytecode: &[u8],
    seed: u64,
    init_regs: &[u64; 16],
) -> Result<RiscEvalState> {
    run_native_poly_direct_with(bytecode, seed, init_regs, None)
}

/// Full runner with optional ip_map (source-IP -> program index) for VirtualBranch
/// branch resolution.
pub fn run_native_poly_direct_with(
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
    let parts = build_self_decoding_parts_with(
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