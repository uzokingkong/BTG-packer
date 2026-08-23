// ==============================================================================
// BTG - VM self-test: fused / permuted / variable encoding (audit weakness #6)
// ==============================================================================
// End-to-end proof that the obfuscated VM path executes the same semantics as
// the plain interpreter, natively, across the fused handler families. Builds a
// plain program, encodes it with a seed-keyed SemanticObfuscator, builds the
// obfuscated VM module, runs it natively in an RWX arena, and cross-checks the
// result against `interpret(decode(obf))` (which == interpret(plain)).
//
// The store/load absolute address is passed in vreg3 by each runner (offset
// 0x8000 in the interpreter's `mem`, `arena.base+0x8000` in the native arena).
// ==============================================================================

use crate::vm::arena::Arena;
use crate::vm::bytecode::*;
use crate::vm::encode::encode_trampoline;
use crate::vm::interp;
use crate::vm::semantic_obf::{FusedGroup, SemanticObfuscator};
use anyhow::{anyhow, Result};

const DATA_OFF: usize = 0x8000;
/// Native arena data area (must not overlap the state buffer at arena 0x9000).
const NATIVE_DATA_OFF: usize = 0xB800;

/// vreg3 (the store/load address) is seeded by each runner.
fn semobf_program() -> Vec<u8> {
    let mut b = BytecodeBuilder::new();
    // Seed two vregs and exercise the fused ALU-RR / ALU-IMM families.
    b.mov_r_imm32(1, 0x1122_3344);
    b.mov_r_imm32(2, 0x0000_F0F0);
    b.binop_r_r(OP_ADD_R_R, 0, 1); // fused ALU-RR: v0 = v1
    b.binop_r_r(OP_ADD_R_R, 0, 2); // v0 = v1 + v2
    b.binop_r_r(OP_XOR_R_R, 0, 1); // v0 ^= v1
    b.binop_r_imm32(OP_AND_R_IMM32, 0, 0x00FF_FFFF); // fused ALU-IMM
    b.binop_r_imm32(OP_ADD_R_IMM32, 0, 7);
    // Fused STORE_ABS then LOAD_ABS through the address in vreg3.
    b.mem_store_a(OP_MOV_MEM32_A, 3, 0); // [v3] = v0
    b.mem_load_a(OP_MOVZX_R_MEM32_A, 4, 3); // v4 = [v3]
                                            // A never-taken branch (rel-fixup across the fused stream must be correct).
    let sk = b.new_label();
    b.jcc8(COND_JNE, sk);
    b.binop_r_imm32(OP_ADD_R_IMM32, 4, 1);
    b.mark_label(sk);
    // Fused mul/div family (32-bit accumulator pair).
    b.mov_r_imm32(5, 6);
    b.mul_r(OP_MUL_R_R32, 5); // RDX:RAX = RAX*6 (RAX=v0)
    b.mov_r_imm32(6, 3);
    b.div_r(OP_DIV_R_R32, 6); // RAX = RDX:RAX / 3
                              // ── MovRr family: mov r,r / r,r64 / r,imm32 / r,imm64 (no flags) ─────
    b.mov_r_imm64(1, 0x1122_3344_5566_7788); // imm64
    b.mov_r_imm32(2, 0x00FF_00FF); // imm32
    b.mov_r_r(3, 2); // rr  (v3 = 0x00FF00FF)
    b.mov_r_r64(4, 1); // rr64 (v4 = full imm64)
                       // ── Shift family: shl/shr/sar by imm8 + CL, 32/64-bit ────────────────
    b.mov_r_imm32(7, 5); // v7 = CL count
    b.shift_r_imm8(OP_SHL_R_IMM8, 3, 4); // v3 <<= 4
    b.shift_r_imm8(OP_SHR_R_IMM8, 3, 2); // v3 >>= 2
    b.shift_r_imm8(OP_SAR_R_IMM8, 3, 1); // v3 >>= 1 (arith)
    b.shift_r_imm8(OP_SHL64_R_IMM8, 4, 8); // v4 <<= 8
    b.shift_r_imm8(OP_SHR64_R_IMM8, 4, 4); // v4 >>= 4
    b.shift_r_imm8(OP_SAR64_R_IMM8, 4, 2); // v4 >>= 2 (arith)
    b.mov_r_imm32(1, 5); // CL count = 5
    b.shift_r_cl(OP_SHL_R_CL, 3); // v3 <<= 5
    b.shift_r_cl(OP_SHR_R_CL, 3); // v3 >>= 5
    b.shift_r_cl(OP_SAR_R_CL, 3); // v3 >>= 5 (arith)
    b.shift_r_cl(OP_SHL64_R_CL, 4); // v4 <<= 5
    b.shift_r_cl(OP_SHR64_R_CL, 4); // v4 >>= 5
    b.shift_r_cl(OP_SAR64_R_CL, 4); // v4 >>= 5 (arith)
                                    // ── Unary family: inc/dec/neg/not (32 + 64-bit) ──────────────────────
    b.inc_r(3); // v3++
    b.dec_r(3); // v3--
    b.inc_r64(4); // v4++
    b.dec_r64(4); // v4--
    b.mov_r_imm32(6, 0x8000_0001); // v6 = -(0x7FFFFFFF) mod 2^32
    b.emit(OP_NEG_R, &[6]); // v6 = -v6 = 0x7FFFFFFF
    b.emit(OP_NOT_R, &[6]); // v6 = ~v6
    b.emit(OP_NEG_R64, &[4]); // v4 = -v4
    b.emit(OP_NOT_R64, &[4]); // v4 = ~v4
                              // ── CmpTest family: cmp r,imm32 / test r,r32 / test r,imm32 ──────────
    b.mov_r_imm32(6, 0x1234_5678);
    b.cmp_r_imm32(6, 0x1234_5678); // CmpTest: ZF=1
    b.test_r_r32(6, 6); // CmpTest: ZF=0
    b.test_r_imm32(6, 0xFFFF_FFFF); // CmpTest: ZF=0
                                    // ── Shift count==0 must PRESERVE RFLAGS (skip cap_flags_shift) ────────
    b.mov_r_imm32(1, 0); // CL count = 0
    b.shift_r_cl(OP_SHL_R_CL, 3); // count==0: flags preserved
    b.shift_r_cl(OP_SHR64_R_CL, 4); // count==0: flags preserved
    b.shift_r_imm8(OP_SHL_R_IMM8, 3, 0); // imm8 count=0: flags preserved
    b.halt();
    b.finish()
}

/// Run a bytecode stream against a pre-seeded state buffer, returning
/// (v0, v4, memv, flags) where memv is the 32-bit value at DATA_OFF and flags
/// is the modelled status flags (masked to FLAG_MASK).
fn run_interpret(code: &[u8], state: &mut [u8], mem: &mut [u8]) -> Result<(u64, u64, u64, u64)> {
    interp::interpret(state, mem, code).map_err(|e| anyhow!("interpret: {:?}", e))?;
    let v0 = u64::from_le_bytes(
        state[interp::STATE_VREGS + 0 * 8..][..8]
            .try_into()
            .unwrap(),
    );
    let v4 = u64::from_le_bytes(
        state[interp::STATE_VREGS + 4 * 8..][..8]
            .try_into()
            .unwrap(),
    );
    let memv = u32::from_le_bytes(mem[DATA_OFF..DATA_OFF + 4].try_into().unwrap()) as u64;
    let flags = u64::from_le_bytes(
        state[interp::STATE_FLAGS..interp::STATE_FLAGS + 8]
            .try_into()
            .unwrap(),
    ) & crate::vm::bytecode::FLAG_MASK;
    Ok((v0, v4, memv, flags))
}

/// Read the modelled status flags from a (native) state buffer.
fn read_flags(state: &[u8]) -> u64 {
    u64::from_le_bytes(
        state[interp::STATE_FLAGS..interp::STATE_FLAGS + 8]
            .try_into()
            .unwrap(),
    ) & crate::vm::bytecode::FLAG_MASK
}

/// Seed the interpreter state: vreg1/vreg2 operands, vreg3 = store address.
fn seed_interp(state: &mut [u8], mem: &mut [u8], addr: u64) {
    state[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
        .copy_from_slice(&(0usize as u64).to_le_bytes());
    let mut put = |v: usize, x: u64| {
        state[interp::STATE_VREGS + v * 8..interp::STATE_VREGS + v * 8 + 8]
            .copy_from_slice(&x.to_le_bytes())
    };
    put(1, 0x1122_3344);
    put(2, 0x0000_F0F0);
    put(3, addr);
    mem.fill(0);
}

fn reference(plain: &[u8]) -> Result<(u64, u64, u64, u64)> {
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x10000];
    seed_interp(&mut st, &mut mem, DATA_OFF as u64);
    run_interpret(plain, &mut st, &mut mem)
}

/// Runs the (fused) obfuscated stream through the reference interpreter.
fn interp_obf(obf: &[u8], seed: u64) -> Result<(u64, u64, u64, u64)> {
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x10000];
    seed_interp(&mut st, &mut mem, DATA_OFF as u64);
    let codec = SemanticObfuscator::from_seed(seed);
    let plain = codec.decode(obf);
    run_interpret(&plain, &mut st, &mut mem)
}

/// Runs the obfuscated stream natively through the fused/permuted VM module.
fn native_obf(plain: &[u8], seed: u64) -> Result<(u64, u64, u64, u64)> {
    let obf = SemanticObfuscator::from_seed(seed);
    let obf_bc = obf.encode(plain);
    let mut arena = Arena::new(0x80000)?;
    let (vc, vt, vb, vs, vtr, vdata) = (
        arena.base + 0x1000, // code (plain + fused handlers)
        arena.base + 0x8000, // handler table (256*8B; code may grow past 0x6000)
        arena.base + 0xA000, // bytecode
        arena.base + 0x9000, // state buffer
        arena.base + 0xC000, // trampoline
        arena.base + 0xD000, // data pointers
    );
    let module = crate::vm::build_vm_module_obf(
        vc as u64,
        vt as u64,
        vb as u64,
        obf_bc.clone(),
        crate::vm::handlers::EntryMode::Ksa,
        seed,
    )?;
    crate::vm::handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vs as u64, vdata as u64, vdata as u64, vc as u64, vtr as u64)?;
    let base = arena.base as u64;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x8000..0x8000 + module.table.len()].copy_from_slice(&module.table);
        b[0xA000..0xA000 + module.bytecode.len()].copy_from_slice(&module.bytecode);
        b[0x9000..0x9000 + interp::STATE_SIZE].fill(0);
        b[0xC000..0xC000 + tramp.len()].copy_from_slice(&tramp);
        // data area lives at arena.base + NATIVE_DATA_OFF (arena offset NATIVE_DATA_OFF).
        let mut put = |v: usize, x: u64| {
            b[0x9000 + interp::STATE_VREGS + v * 8..0x9000 + interp::STATE_VREGS + v * 8 + 8]
                .copy_from_slice(&x.to_le_bytes())
        };
        put(1, 0x1122_3344);
        put(2, 0x0000_F0F0);
        put(3, base + NATIVE_DATA_OFF as u64); // absolute address for the native handlers
        b[NATIVE_DATA_OFF..NATIVE_DATA_OFF + 0x100].fill(0);
    }
    arena.call(0xC000);
    let b = arena.bytes();
    let v0 = u64::from_le_bytes(
        b[0x9000 + interp::STATE_VREGS + 0 * 8..][..8]
            .try_into()
            .unwrap(),
    );
    let v4 = u64::from_le_bytes(
        b[0x9000 + interp::STATE_VREGS + 4 * 8..][..8]
            .try_into()
            .unwrap(),
    );
    let memv =
        u32::from_le_bytes(b[NATIVE_DATA_OFF..NATIVE_DATA_OFF + 4].try_into().unwrap()) as u64;
    let flags = read_flags(&b[0x9000..0x9000 + interp::STATE_SIZE]);
    Ok((v0, v4, memv, flags))
}

/// Main self-test entry: fused handler semantics == reference interpreter, both
/// through `interpret_obf` and through native fused-handler execution.
pub fn run_semobf_test() -> Result<()> {
    let plain = semobf_program();
    let seed = 0x5EED_2026u64;

    // (a) A fused stream dispatches multiple semantics correctly: the obfuscated
    //     stream, decoded + interpreted, matches the plain program exactly
    //     (vregs AND the modelled status flags).
    let exp = reference(&plain)?;
    let obf = SemanticObfuscator::from_seed(seed);
    let obf_bc = obf.encode(&plain);
    // Mechanism active: the obfuscated stream must differ from plain...
    if obf_bc == plain {
        return Err(anyhow!("semobf: encoding must differ from plain"));
    }
    // ...and it must round-trip exactly (fused members re-expand to their plain
    // opcodes; non-fused are permuted then un-permuted).
    if obf.decode(&obf_bc) != plain {
        return Err(anyhow!(
            "semobf: decode(encode(plain)) must equal plain exactly"
        ));
    }
    // Every new fused family must actually be exercised in the encoded stream
    // (i.e. its members were folded into fused handlers, not left 1:1).
    for fam in [
        FusedGroup::MovRr,
        FusedGroup::Shift,
        FusedGroup::Unary,
        FusedGroup::CmpTest,
    ] {
        if !obf_bc.contains(&obf.family_byte(fam)) {
            return Err(anyhow!(
                "semobf: fused family {:?} not present in encoded stream",
                fam
            ));
        }
    }
    let via_interp = interp_obf(&obf_bc, seed)?;
    if via_interp != exp {
        return Err(anyhow!(
            "semobf: interpret_obf mismatch: got {:?} want {:?}",
            via_interp,
            exp
        ));
    }

    // Native fused-handler execution must match too (end-to-end).
    let via_native = native_obf(&plain, seed)?;
    if via_native != exp {
        return Err(anyhow!(
            "semobf: native fused-handler mismatch: got {:?} want {:?}",
            via_native,
            exp
        ));
    }

    // (b) operand length not static in the opcode byte (reassert at the module
    //     level): the fused family tag has no static operand length.
    if opcode_operand_len(obf.family_byte(FusedGroup::AluRr)).is_some() {
        return Err(anyhow!(
            "semobf: fused family tag must have no static operand length"
        ));
    }

    // (c) two seeds encode the same program differently but execute identically.
    let seed2 = seed ^ 0xABCD_EF01;
    let obf2 = SemanticObfuscator::from_seed(seed2);
    let obf_bc2 = obf2.encode(&plain);
    if obf_bc == obf_bc2 {
        return Err(anyhow!(
            "semobf: two seeds must produce different encodings"
        ));
    }
    let via_interp2 = interp_obf(&obf_bc2, seed2)?;
    if via_interp2 != exp {
        return Err(anyhow!(
            "semobf: seed-2 interpret mismatch: got {:?} want {:?}",
            via_interp2,
            exp
        ));
    }
    Ok(())
}
