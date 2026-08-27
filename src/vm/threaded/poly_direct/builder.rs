use crate::vm::poly::{PolymorphicDecoder, PolymorphicEncoder, VirtualIsaSpec};
use crate::vm::risc::{
    assert_commercial_capabilities, BranchCondition, MicroInstr, MicroOperand, RiscOp, RiscProgram,
};
use crate::vm::table_layout::TableLayout;
use crate::vm::threaded::{AssignedSuperOp, SuperOpBuildMetadata, VmRuntimeLayout};
use anyhow::{anyhow, Result};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};
use std::collections::HashMap;

use super::checksum::*;
use super::codegen_util::*;
use super::types::*;

const CHUNK_LEAF_LABEL_BASE: usize = 0xD000_0000;
const BRANCH_ABSOLUTE_LABEL: usize = usize::MAX - 0xA100;
const BRANCH_AFTER_DECODE_LABEL: usize = usize::MAX - 0xA200;
const BRANCH_NOT_TAKEN_LABEL: usize = usize::MAX - 0x9300;
const BRANCH_NOT_FOUND_LABEL: usize = usize::MAX - 0x9400;
const BRANCH_FOUND_LABEL: usize = usize::MAX - 0x9401;
/// Fixed control slot outside the seed-permuted architectural state. A
/// cross-family router writes a bytecode offset here before entering a child
/// module; ordinary boot entry observes zero.
const STATE_CROSS_FAMILY_ENTRY_VIP: i64 = 0x5000;
const STATE_CROSS_FAMILY_RETURN_PTR: i64 = 0x5008;
// Child guest-volatiles must cross the generated-module call boundary through
// state, not through the physical dispatcher registers left by child HALT.
// RAX keeps its historical slot because the FP-return path consumes it
// specially; the remaining Win64 volatile GPR pointers live in this range.
const STATE_CROSS_FAMILY_VOLATILE_PTRS: [(usize, i64); 6] = [
    (1, 0x5020),  // RCX
    (2, 0x5028),  // RDX
    (8, 0x5030),  // R8
    (9, 0x5038),  // R9
    (10, 0x5040), // R10
    (11, 0x5048), // R11
];
const STATE_CROSS_FAMILY_FLAGS_PTR: i64 = 0x5050;
const STATE_CROSS_FAMILY_XMM_PTR_BASE: i64 = 0x5060;
const STATE_CROSS_FAMILY_ACTIVE: i64 = 0x5098;
const STATE_CROSS_FAMILY_TRANSIENT_END: i64 = 0x50A0;
/// Transient build-local descriptor grammar selected by a super-op envelope.
/// Dispatch clears it before every opcode; an extension entry arms it only
/// after validating its encrypted grammar tag.
const STATE_SUPEROP_DESCRIPTOR_MASK: i64 = 0x5010;
const STATE_CROSS_FAMILY_CALLEE_STATE: i64 = 0x5018;

const _: () = assert!(
    crate::vm::data_lifetime::LIFETIME_SYNC_PTR_STATE_OFFSET
        >= STATE_CROSS_FAMILY_TRANSIENT_END as usize
);

fn emit_table_integrity_mix(b: &mut CodeBuilder) {
    b.push(
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::R11,
            MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::R9, 8, 0, 8),
        )
        .unwrap(),
    );
    b.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11).unwrap());
    movi(b, Register::RCX, 0x0100_0000_01B3);
    b.push(Instruction::with2(Code::Imul_r64_rm64, Register::R10, Register::RCX).unwrap());
    b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::R10).unwrap());
    b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R11, 33).unwrap());
    b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R10, Register::R11).unwrap());
    movi(b, Register::RCX, 0xFF51_AFD7_ED55_8CCD);
    b.push(Instruction::with2(Code::Imul_r64_rm64, Register::R10, Register::RCX).unwrap());
}

fn emit_masked_chunk_value(
    b: &mut CodeBuilder,
    descriptor_domain: u64,
    domain: u64,
    index: usize,
    value: u64,
) {
    let mask = crate::vm::seed_lifecycle::derive_seed(descriptor_domain, domain ^ index as u64);
    movi(b, Register::R11, value ^ mask);
    movi(b, Register::R10, mask);
    b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R11, Register::R10).unwrap());
}

fn emit_binary_chunk_lookup(
    b: &mut CodeBuilder,
    chunks: &[crate::vm::chunk_crypto::BytecodeChunk],
    descriptor_domain: u64,
    lo: usize,
    hi: usize,
    internal_label: &mut usize,
) {
    if lo == hi {
        b.br(Code::Jmp_rel32_64, CHUNK_LEAF_LABEL_BASE + lo);
        return;
    }
    let mid = lo + (hi - lo) / 2;
    let end = chunks[mid].offset.saturating_add(chunks[mid].len) as u64;
    emit_masked_chunk_value(b, descriptor_domain, 0x424F_554E_4441_5259, mid, end);
    b.push(Instruction::with2(Code::Cmp_r64_rm64, Register::R12, Register::R11).unwrap());
    let left_sentinel = 0xC000_0000usize + *internal_label;
    *internal_label += 1;
    b.br(Code::Jb_rel32_64, left_sentinel);
    emit_binary_chunk_lookup(b, chunks, descriptor_domain, mid + 1, hi, internal_label);
    let left = b.len();
    for &mut (_, ref mut target) in b.branches.iter_mut() {
        if *target == left_sentinel {
            *target = left;
        }
    }
    emit_binary_chunk_lookup(b, chunks, descriptor_domain, lo, mid, internal_label);
}

/// P3 (G1): build the self-decoding rolling-key dispatcher machine code and its
/// handler/operand tables, parameterized by the VAs the caller will place them
/// at. This is the *verified* commercial execution engine (T1-4): the native
/// runtime itself decrypts the poly bytecode with the rolling key, decodes
/// operands and dispatches through the handler table.
///
/// `code_base` = where the assembled `code` is placed, `table_base` = handler
/// table VA, `bytecode_base` = encrypted poly stream VA, `state_base` = VM state
/// buffer VA, `stack_base` = virtual stack top VA. The entry stub materializes
/// these through RIP-relative references, so the runtime bundle is not exposed
/// as a run of four absolute pointer immediates.
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
        bytecode,
        seed,
        code_base,
        table_base,
        bytecode_base,
        state_base,
        stack_base,
        None,
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
    build_self_decoding_parts_with_layout(
        bytecode,
        seed,
        code_base,
        table_base,
        bytecode_base,
        state_base,
        stack_base,
        ip_map,
        TableLayout::legacy(),
    )
}

/// Commercial production builder with a per-build metadata ABI.  The native
/// dispatcher receives the offsets as code-generation inputs, so the handler,
/// operand, condition, and branch tables no longer have fixed relative
/// positions in a packed PE.
pub fn build_self_decoding_parts_with_layout(
    bytecode: &[u8],
    seed: u64,
    code_base: u64,
    table_base: u64,
    bytecode_base: u64,
    state_base: u64,
    stack_base: u64,
    ip_map: Option<&HashMap<u64, usize>>,
    layout: TableLayout,
) -> Result<SelfDecodingParts> {
    build_self_decoding_parts_with_layouts(
        bytecode,
        seed,
        code_base,
        table_base,
        bytecode_base,
        state_base,
        stack_base,
        ip_map,
        layout,
        VmRuntimeLayout::legacy(),
    )
}

/// Fully parameterized production builder. Metadata and state ABIs are passed
/// together so every generated consumer uses one immutable build contract.
pub fn build_self_decoding_parts_with_layouts(
    bytecode: &[u8],
    seed: u64,
    code_base: u64,
    table_base: u64,
    bytecode_base: u64,
    state_base: u64,
    stack_base: u64,
    ip_map: Option<&HashMap<u64, usize>>,
    layout: TableLayout,
    runtime_layout: VmRuntimeLayout,
) -> Result<SelfDecodingParts> {
    build_self_decoding_parts_with_superops(
        bytecode,
        seed,
        code_base,
        table_base,
        bytecode_base,
        state_base,
        stack_base,
        ip_map,
        layout,
        runtime_layout,
        &[],
        None,
    )
}

/// Production builder with build-local super-op extension handlers. Existing
/// callers retain the canonical ISA through `build_self_decoding_parts_with_layouts`.
pub fn build_self_decoding_parts_with_superops(
    bytecode: &[u8],
    seed: u64,
    code_base: u64,
    table_base: u64,
    bytecode_base: u64,
    state_base: u64,
    stack_base: u64,
    ip_map: Option<&HashMap<u64, usize>>,
    layout: TableLayout,
    runtime_layout: VmRuntimeLayout,
    superops: &[AssignedSuperOp],
    superop_metadata: Option<&SuperOpBuildMetadata>,
) -> Result<SelfDecodingParts> {
    build_self_decoding_parts_with_superops_and_chunks(
        bytecode,
        seed,
        code_base,
        table_base,
        bytecode_base,
        state_base,
        stack_base,
        ip_map,
        layout,
        runtime_layout,
        superops,
        superop_metadata,
        &[],
    )
}

pub fn build_self_decoding_parts_with_superops_and_chunks(
    bytecode: &[u8],
    seed: u64,
    code_base: u64,
    table_base: u64,
    bytecode_base: u64,
    state_base: u64,
    stack_base: u64,
    ip_map: Option<&HashMap<u64, usize>>,
    layout: TableLayout,
    runtime_layout: VmRuntimeLayout,
    superops: &[AssignedSuperOp],
    superop_metadata: Option<&SuperOpBuildMetadata>,
    chunks: &[crate::vm::chunk_crypto::BytecodeChunk],
) -> Result<SelfDecodingParts> {
    build_self_decoding_parts_with_superops_and_chunks_for_family(
        bytecode,
        seed,
        crate::vm::poly::VmArchitectureFamily::for_build(seed),
        code_base,
        table_base,
        bytecode_base,
        state_base,
        stack_base,
        ip_map,
        layout,
        runtime_layout,
        superops,
        superop_metadata,
        chunks,
    )
}

pub fn build_self_decoding_parts_with_superops_and_chunks_for_family(
    bytecode: &[u8],
    seed: u64,
    family: crate::vm::poly::VmArchitectureFamily,
    code_base: u64,
    table_base: u64,
    bytecode_base: u64,
    state_base: u64,
    stack_base: u64,
    ip_map: Option<&HashMap<u64, usize>>,
    layout: TableLayout,
    runtime_layout: VmRuntimeLayout,
    superops: &[AssignedSuperOp],
    superop_metadata: Option<&SuperOpBuildMetadata>,
    chunks: &[crate::vm::chunk_crypto::BytecodeChunk],
) -> Result<SelfDecodingParts> {
    build_self_decoding_parts_with_superops_chunks_family_and_routes(
        bytecode,
        seed,
        family,
        code_base,
        table_base,
        bytecode_base,
        state_base,
        stack_base,
        ip_map,
        layout,
        runtime_layout,
        superops,
        superop_metadata,
        chunks,
        &[],
    )
}

pub fn build_self_decoding_parts_with_superops_chunks_family_and_routes(
    bytecode: &[u8],
    seed: u64,
    family: crate::vm::poly::VmArchitectureFamily,
    code_base: u64,
    table_base: u64,
    bytecode_base: u64,
    state_base: u64,
    stack_base: u64,
    ip_map: Option<&HashMap<u64, usize>>,
    layout: TableLayout,
    runtime_layout: VmRuntimeLayout,
    superops: &[AssignedSuperOp],
    superop_metadata: Option<&SuperOpBuildMetadata>,
    chunks: &[crate::vm::chunk_crypto::BytecodeChunk],
    cross_family_routes: &[NativeCrossFamilyRoute],
) -> Result<SelfDecodingParts> {
    // P1 migration: every state access now passes through the runtime-layout
    // translator. Keep the legacy contract until the embed/bridge initializers
    // consume the same layout value, then production can switch to `from_seed`.
    runtime_layout.validate()?;
    validate_native_cross_family_routes(cross_family_routes)?;
    let _runtime_layout_guard = install_runtime_layout(&runtime_layout);
    let spec = VirtualIsaSpec::from_seed_and_family(seed, family);
    let init_key = seed.wrapping_mul(C1) ^ 0x517CC1B727220A95;
    // P6-1: handler 테이블 마스터 키 — dispatch loop 코드와 테이블 build 시 동일
    // 파생식을 사용한다 (seed→init_key→master 결정적). P6-3 부터 이 값은
    // `per_op_key(op)` 를 거쳐 **opcode별 파생 키**로 사용된다.
    let table_key = init_key
        .wrapping_mul(0x9E3779B97F4A7C15)
        .rotate_right(17)
        .wrapping_add(0xBF58476D1CE4E5B9);
    // P6-3: 마스터 K 를 a+b 로 분할 — dispatch loop 는 `(a^b) + 2*(a&b)` MBA 항등식으로
    // 런타임에 K 를 복원한다. **K 자체는 어떤 단일 상수로도 코드에 존재하지 않는다**
    // (P6-1의 `movi rcx, table_key` 평문 임베드 제거). a/b 만 임베드.
    let mba_a = table_key.wrapping_mul(C3).rotate_left(23) | 1;
    let mba_b = table_key.wrapping_sub(mba_a);

    let (offs_tab, flags_tab) = super::metadata::build_operand_tables(&spec);

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
    let (prog, op_offsets) = if let Some(metadata) = superop_metadata {
        if metadata.source_program.instrs.len() != metadata.original_byte_offsets.len() {
            return Err(anyhow!(
                "P5 super-op metadata length mismatch: program={} offsets={}",
                metadata.source_program.instrs.len(),
                metadata.original_byte_offsets.len()
            ));
        }
        (
            metadata.source_program.clone(),
            metadata.original_byte_offsets.clone(),
        )
    } else {
        let mut dec = PolymorphicDecoder::new_for_family(seed, family);
        let prog = dec.decode_full(bytecode, false)?;
        let mut reenc = PolymorphicEncoder::new_for_family(seed, family);
        let (re_bc, op_offsets) = reenc.encode_with_offsets(&prog)?;
        if re_bc != bytecode {
            return Err(anyhow!(
                "self-decoding branch-map: decode+re-encode diverged from the placed bytecode ({} vs {} bytes); \
                 branch-map offsets would be invalid",
                re_bc.len(),
                bytecode.len()
            ));
        }
        (prog, op_offsets)
    };
    let top_level_exit_byte_offset = prog
        .instrs
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, instr)| (instr.op == RiscOp::Halt).then_some(op_offsets[index] as u64))
        .unwrap_or(0);
    // The native builder is a separate trust boundary: reject decoded or
    // metadata-provided streams unless every production execution stage agrees.
    assert_commercial_capabilities(&prog.instrs)?;
    for (i, &off) in op_offsets.iter().enumerate() {
        if off >= bytecode.len() {
            return Err(anyhow!(
                "self-decoding branch-map: micro-op {i} byte offset {off:#x} exceeds bytecode len {:#x}",
                bytecode.len()
            ));
        }
    }
    let resolve_off =
        |tgt: u64, op_offsets: &[usize], ip_map: &Option<&HashMap<u64, usize>>| -> Option<u64> {
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

    if let Ok(raw) = std::env::var("BTG_TRACE_BRANCH_MAP_TARGET") {
        let parse = |value: &str| {
            let value = value.trim();
            u64::from_str_radix(value.trim_start_matches("0x"), 16)
                .ok()
                .or_else(|| value.parse::<u64>().ok())
        };
        if let Some(target) = parse(&raw) {
            let ip_index = ip_map.and_then(|map| map.get(&target)).copied();
            let resolved = resolve_off(target, &op_offsets, &ip_map);
            let serialized = entries.iter().find(|(key, _)| *key == target).copied();
            eprintln!(
                "[BTG_BRANCH_MAP] family={family:?} seed={seed:#x} target={target:#x} ip_index={ip_index:?} resolved={resolved:?} serialized={serialized:?} entries={} prog_ops={} offsets={} bytecode_len={}",
                entries.len(),
                prog.instrs.len(),
                op_offsets.len(),
                bytecode.len(),
            );
        }
    }
    // P6: branch metadata is encoded independently from the handler table.
    // The two domains use distinct seed-derived keys so target values and byte
    // offsets cannot be correlated directly in the embedded metadata blob.
    let branch_target_key = seed.rotate_left(21) ^ 0xC6BC_2796_92B5_C323;
    let branch_offset_key = seed.rotate_right(17) ^ 0xD6E8_FEB8_6659_FD93;
    let mut branch_map = Vec::new();
    branch_map.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (k, off) in entries {
        branch_map.extend_from_slice(&(k ^ branch_target_key).to_le_bytes());
        branch_map.extend_from_slice(&(off ^ branch_offset_key).to_le_bytes());
    }

    let mut b = CodeBuilder::new();

    // Encode a module-local address without placing its absolute VA in the
    // instruction stream. Production regions live in one PE image and are in
    // rel32 range; BlockEncoder verifies that invariant at final placement.
    let rip_anchor = |b: &mut CodeBuilder, reg: Register, target: u64| {
        b.push(
            Instruction::with2(
                Code::Lea_r64_m,
                reg,
                MemoryOperand::with_base_displ(Register::RIP, target as i64),
            )
            .unwrap(),
        );
    };

    // The Win64 unwindable entry prologue must begin at module RVA 0.  Keeping
    // these pushes behind the old leading JMP made vm_entry_unwind_ops see a
    // leaf function, so an exception in any dispatcher/helper frame caused
    // RtlVirtualUnwind to skip 64 bytes of saved nonvolatiles.
    for r in [
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
        Register::RDI,
        Register::RSI,
        Register::RBX,
        Register::RBP,
    ] {
        b.push(Instruction::with1(Code::Push_r64, r).unwrap());
    }
    // The entry body is emitted later; transfer to it after the contiguous
    // prologue. Helpers located between this jump and the body execute with the
    // same entry frame active and are therefore covered by one RUNTIME_FUNCTION.
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
        let enc_mem =
            MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::R12, 1, 0, 1);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, enc_mem).unwrap());
        if !chunks.is_empty() {
            // P1-4 outer chunk cipher: preserve the polymorphic keystream and
            // ciphertext while selecting the VIP's instruction-aligned chunk.
            // Only the fetched byte is unmasked in a register; bytecode memory
            // remains encrypted for the entire process lifetime.
            b.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
            b.push(Instruction::with1(Code::Push_r64, Register::RCX).unwrap());
            // Boundaries are emitted as independently masked descriptors.  In
            // particular, do not emit `cmp vip, imm32`: that instruction form
            // turned the helper into a plaintext chunk-map oracle.
            let descriptor_domain = crate::vm::seed_lifecycle::derive_seed(
                seed,
                0x5032_2D39_2D44_4553, // "P2-9-DES"
            );
            match crate::vm::chunk_crypto::ChunkLookupTopology::from_seed(seed) {
                crate::vm::chunk_crypto::ChunkLookupTopology::ForwardEnds => {
                    for (index, chunk) in chunks.iter().enumerate() {
                        let end = chunk.offset.saturating_add(chunk.len) as u64;
                        emit_masked_chunk_value(
                            &mut b,
                            descriptor_domain,
                            0x424F_554E_4441_5259,
                            index,
                            end,
                        );
                        b.push(
                            Instruction::with2(Code::Cmp_r64_rm64, Register::R12, Register::R11)
                                .unwrap(),
                        );
                        b.br(Code::Jb_rel32_64, CHUNK_LEAF_LABEL_BASE + index);
                    }
                }
                crate::vm::chunk_crypto::ChunkLookupTopology::ReverseStarts => {
                    for (index, chunk) in chunks.iter().enumerate().rev() {
                        emit_masked_chunk_value(
                            &mut b,
                            descriptor_domain,
                            0x4F46_4653_4554_2D31,
                            index,
                            chunk.offset as u64,
                        );
                        b.push(
                            Instruction::with2(Code::Cmp_r64_rm64, Register::R12, Register::R11)
                                .unwrap(),
                        );
                        b.br(Code::Jae_rel32_64, CHUNK_LEAF_LABEL_BASE + index);
                    }
                }
                crate::vm::chunk_crypto::ChunkLookupTopology::BinaryEnds => {
                    let mut internal_label = 0usize;
                    emit_binary_chunk_lookup(
                        &mut b,
                        chunks,
                        descriptor_domain,
                        0,
                        chunks.len() - 1,
                        &mut internal_label,
                    );
                }
            }
            b.push(Instruction::with(Code::Ud2));
            let chunk_module_key = crate::vm::chunk_crypto::module_key(seed);
            for (index, chunk) in chunks.iter().enumerate() {
                let label = b.len();
                let offset_mask = crate::vm::seed_lifecycle::derive_seed(
                    descriptor_domain,
                    0x4F46_4653_4554_2D31u64 ^ index as u64,
                );
                movi(&mut b, Register::R10, index as u64);
                movi(&mut b, Register::R11, (chunk.offset as u64) ^ offset_mask);
                movi(&mut b, Register::R9, offset_mask);
                b.push(
                    Instruction::with2(Code::Xor_rm64_r64, Register::R11, Register::R9).unwrap(),
                );
                b.br(Code::Jmp_rel32_64, 0xE100_0000);
                for &mut (_, ref mut target) in b.branches.iter_mut() {
                    if *target == CHUNK_LEAF_LABEL_BASE + index {
                        *target = label;
                    }
                }
            }
            let derive = b.len();
            for &mut (_, ref mut target) in b.branches.iter_mut() {
                if *target == 0xE100_0000 {
                    *target = derive;
                }
            }
            // Derive the operational key once, out of line from descriptor
            // selection. R10 enters as chunk index; R11 is the decoded start.
            movi(&mut b, Register::R9, 0x4348_554E_4B2D_4B31);
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::R10).unwrap());
            b.push(Instruction::with2(Code::Rol_rm64_imm8, Register::R9, 17).unwrap());
            movi(&mut b, Register::R10, chunk_module_key);
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R10, Register::R9).unwrap());
            movi(&mut b, Register::R9, 0x517C_C1B7_2722_0A95);
            b.push(Instruction::with2(Code::Imul_r64_rm64, Register::R10, Register::R9).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::R10).unwrap());
            b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R9, 31).unwrap());
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R10, Register::R9).unwrap());
            movi(&mut b, Register::R9, 0x4A55_816D_97C6_D67B);
            b.push(Instruction::with2(Code::Imul_r64_rm64, Register::R10, Register::R9).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::R10).unwrap());
            b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R9, 27).unwrap());
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R10, Register::R9).unwrap());
            // local_offset = vip - decoded chunk start, without changing VIP.
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::R12).unwrap());
            b.push(Instruction::with2(Code::Sub_rm64_r64, Register::R9, Register::R11).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::R9).unwrap());
            // mask = high8(mix(key ^ local_offset*C)). Keep this sequence in
            // sync with vm::chunk_crypto::byte_mask.
            movi(&mut b, Register::R9, 0x9E37_79B1_85EB_CA87);
            b.push(Instruction::with2(Code::Imul_r64_rm64, Register::R11, Register::R9).unwrap());
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R10, Register::R11).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::R10).unwrap());
            b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R11, 33).unwrap());
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R10, Register::R11).unwrap());
            movi(&mut b, Register::R9, 0xFF51_AFD7_ED55_8CCD);
            b.push(Instruction::with2(Code::Imul_r64_rm64, Register::R10, Register::R9).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::R10).unwrap());
            b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R11, 29).unwrap());
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R10, Register::R11).unwrap());
            b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R10, 56).unwrap());
            b.push(Instruction::with1(Code::Pop_r64, Register::RCX).unwrap());
            b.push(Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::R10D).unwrap());
            // Operational chunk key/mix state is dead after the fetched byte
            // has been unmasked. Clear all three scratch registers before the
            // polymorphic decoder continues.
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::R9).unwrap());
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R10, Register::R10).unwrap());
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R11, Register::R11).unwrap());
            b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        }
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
        for logical_slot in spec.operand_order() {
            let (offset, salt) = match logical_slot {
                0 => (DEC_DST, (seed >> 3) as u8),
                1 => (DEC_SRC1, (seed >> 19) as u8),
                2 => (DEC_SRC2, (seed >> 37) as u8),
                _ => unreachable!(),
            };
            b.call(sub_decrypt);
            b.push(
                Instruction::with2(
                    Code::Xor_r8_rm8,
                    Register::AL,
                    MemoryOperand::with_base_displ(Register::RDX, STATE_SUPEROP_DESCRIPTOR_MASK),
                )
                .unwrap(),
            );
            store_decoded_al(&mut b, offset, salt);
        }
        // compact imm1 if src1 is one of the family-local markers
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        b.push(Instruction::with2(Code::Sub_rm32_imm32, Register::EAX, 1).unwrap());
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 7).unwrap());
        let after_imm1 = b.len() + 1;
        b.br(Code::Ja_rel32_64, after_imm1);
        emit_read_compact_imm(
            &mut b,
            DEC_SRC1,
            DEC_IMM1,
            sub_decrypt,
            spec.operand_mask,
            layout.operand_offs_off,
            true,
        );
        let t1 = b.len();
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == after_imm1 {
                *ti = t1;
            }
        }
        // imm2 if src2 == 0x01
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        b.push(Instruction::with2(Code::Sub_rm32_imm32, Register::EAX, 1).unwrap());
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 7).unwrap());
        let after_imm2 = b.len() + 1;
        b.br(Code::Ja_rel32_64, after_imm2);
        emit_read_compact_imm(
            &mut b,
            DEC_SRC2,
            DEC_IMM2,
            sub_decrypt,
            spec.operand_mask,
            layout.operand_offs_off,
            true,
        );
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
        let cm = MemoryOperand::with_base_index_scale_displ_size(
            Register::R15,
            Register::RAX,
            1,
            layout.cond_codes_off as i64,
            1,
        );
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, cm).unwrap());
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::ECX).unwrap());
        store_decoded_al(&mut b, DEC_COND, (seed >> 53) as u8);
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
        emit_materialize_lazy_flags(&mut b);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, m8(DEC_COND)).unwrap());
        for k in 0..22u32 {
            b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, k as i32).unwrap());
            b.br(Code::Je_rel32_64, 0x1000 + k as usize);
        }
        // unknown cond code -> not taken.
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RAX).unwrap());
        b.br(Code::Jmp_rel32_64, usize::MAX - 0x9000);
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
                let width = if k == 19 {
                    2
                } else if k == 20 {
                    4
                } else {
                    8
                };
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(REGS_OFF + 8)).unwrap(),
                );
                if width == 2 {
                    b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RAX, 48).unwrap());
                    b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 48).unwrap());
                } else if width == 4 {
                    b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RAX, 32).unwrap());
                    b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 32).unwrap());
                }
                b.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
                );
                b.push(Instruction::with1(Code::Sete_rm8, Register::AL).unwrap());
                b.push(
                    Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap(),
                );
            } else {
                // flag-based: the FLAGS slot uses x86 RFLAGS bit layout (CF=1,ZF=0x40,
                // SF=0x80,OF=0x800,PF=4), so load it into RFLAGS and use the setcc
                // matching the x86 condition code semantics.
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(FLAGS_OFF)).unwrap(),
                );
                emit_safe_popfq(&mut b, Register::RAX);
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
                b.push(
                    Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap(),
                );
            }
            b.br(Code::Jmp_rel32_64, usize::MAX - 0x9000);
        }
        let done = b.len();
        b.push(Instruction::with(Code::Retnq));
        for i in 0..b.branches.len() {
            let t = b.branches[i].1;
            if (0x1000..0x1000 + 22).contains(&t) {
                b.branches[i].1 = frag_idx[t - 0x1000];
            } else if t == usize::MAX - 0x9000 {
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
        b.br(Code::Je_rel32_64, usize::MAX - 0x9100); // equal -> done
        b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R12, Register::RBX).unwrap());
        b.br(Code::Ja_rel32_64, usize::MAX - 0x9101); // R12 > RBX -> reverse
                                         // forward: fall through to the loop
        let loop_top = b.len();
        {
            b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R12, Register::RBX).unwrap());
            b.br(Code::Jae_rel32_64, usize::MAX - 0x9100); // R12 >= RBX -> done
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
            if t == usize::MAX - 0x9100 {
                b.branches[i].1 = done;
            } else if t == usize::MAX - 0x9101 {
                b.branches[i].1 = reverse;
            }
        }
    }

    // resolve_src subroutine: al = raw operand byte; R11=imm; returns value in RAX
    let sub_resolve = b.len();
    {
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
        let fm = MemoryOperand::with_base_index_scale_displ_size(
            Register::R15,
            Register::RAX,
            1,
            layout.operand_flags_off as i64,
            1,
        );
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, fm).unwrap());
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, K_IMM as u32).unwrap());
        let l_imm = b.len() + 2;
        b.je(l_imm);
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, K_NONE as u32).unwrap());
        let l_none = b.len() + 2;
        b.je(l_none);
        let om = MemoryOperand::with_base_index_scale_displ_size(
            Register::R15,
            Register::RAX,
            2,
            layout.operand_offs_off as i64,
            1,
        );
        b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::ECX, om).unwrap());
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::RDX,
                    Register::RCX,
                    1,
                    0,
                    8,
                ),
            )
            .unwrap(),
        );
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
        let fm = MemoryOperand::with_base_index_scale_displ_size(
            Register::R15,
            Register::RCX,
            1,
            layout.operand_flags_off as i64,
            1,
        );
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, fm).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9).unwrap());
        let l_skip = b.len() + 1;
        b.jne(l_skip);
        let om = MemoryOperand::with_base_index_scale_displ_size(
            Register::R15,
            Register::RCX,
            2,
            layout.operand_offs_off as i64,
            1,
        );
        b.push(Instruction::with2(Code::Movzx_r32_rm16, Register::ECX, om).unwrap());
        b.push(
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::RDX,
                    Register::RCX,
                    1,
                    0,
                    8,
                ),
                Register::RAX,
            )
            .unwrap(),
        );
        let l_done = b.len();
        b.push(Instruction::with(Code::Retnq));
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == l_skip {
                *ti = l_done;
            }
        }
    }

    fn emit_materialize_lazy_flags(b: &mut CodeBuilder) {
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::RDI, Register::RDI).unwrap());
        let clean_edge = b.br(Code::Je_rel32_64, usize::MAX);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RSI).unwrap());
        store_m(b, FLAGS_OFF, Register::RAX);
        let done = b.len();
        for (branch, target) in &mut b.branches {
            if *branch == clean_edge {
                *target = done;
            }
        }
    }

    // General logic/arithmetic producer: capture status now but defer publishing
    // it to the canonical FLAGS bank until a condition/native/HALT boundary.
    fn emit_store_flags(b: &mut CodeBuilder) {
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, FLAG_MASK as u32).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::RDI, Register::RDI).unwrap());
        b.push(Instruction::with2(Code::Cmovne_r64_rm64, Register::RCX, Register::RSI).unwrap());
        b.push(
            Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!FLAG_MASK) as i32).unwrap(),
        );
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Mov_r32_imm32, Register::EDI, 1).unwrap());
    }

    // P2 (G3): INC/DEC 플래그 저장 — x86 INC/DEC는 **CF를 보존**한다 (eval_state의
    // update_inc/update_dec와 동일). 하드웨어 `inc/dec`는 CF를 변경하지 않으므로
    // FLAG_MASK에서 CF 비트를 제외하고, FLAGS_OFF 슬롯의 기존 CF를 그대로 합병한다.
    fn emit_store_flags_incdec(b: &mut CodeBuilder) {
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, (FLAG_MASK & !1) as u32)
                .unwrap(),
        ); // CF 제외
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 1).unwrap()); // 기존 CF
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(
            Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!FLAG_MASK) as i32).unwrap(),
        );
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

    // P0-3/P2: 시프트 플래그 저장 — 참조 eval_state 의
    // `update_logic64(res) + CF = shift-out bit` 와 동일하게:
    //   * CF 는 시프트 명령이 set 한 shift-out 비트를 유지한다 (후속 `test` 가
    //     CF/OF 를 clear 하므로 시프트 **직후** pushfq 로 캡처한다),
    //   * ZF/SF/PF 는 결과 기준 (`test r10, r10`),
    //   * OF/AF 는 clear (update_logic64 가 clear — 하드웨어의 count==1 OF 무시),
    //   * DF 는 보존 (FLAGS_OFF 의 비-status 비트 유지).
    // 호출자는 반드시 시프트 명령 직후, R10 = 시프트 결과 상태에서 호출해야 한다.
    // R9/RAX/RCX 를 clobber 한다 (이 지점 이후엔 sub_store 가 재사용한다).
    fn emit_store_shift_flags(b: &mut CodeBuilder) {
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RAX).unwrap()); // CF
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap());
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xC4).unwrap()); // ZF|SF|PF
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::R9).unwrap()); // +CF
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
        b.push(
            Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x8D5i64) as i32).unwrap(),
        );
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

    // Seed-selected identity decompositions used inside semantic handler bodies.
    // Callers place these before the flag-producing instruction (or in a
    // flag-transparent handler), so the intermediate host flags are dead.
    fn emit_synth_identity(
        b: &mut CodeBuilder,
        reg: Register,
        plan: &crate::vm::handler_poly::HandlerSynthesisPlan,
    ) {
        use crate::vm::handler_poly::SemanticRecipe;
        match plan.recipe {
            SemanticRecipe::Native => {
                b.push(Instruction::with2(Code::Mov_r64_rm64, reg, reg).unwrap());
            }
            SemanticRecipe::DeMorgan => {
                b.push(Instruction::with1(Code::Not_rm64, reg).unwrap());
                b.push(Instruction::with1(Code::Not_rm64, reg).unwrap());
            }
            SemanticRecipe::BooleanBasis => {
                let mask = (plan.context_key | 1) as i32;
                b.push(Instruction::with2(Code::Xor_rm64_imm32, reg, mask).unwrap());
                b.push(Instruction::with2(Code::Xor_rm64_imm32, reg, mask).unwrap());
            }
            SemanticRecipe::CarrySplit => {
                let delta = ((plan.context_key as u32) | 1) as i32;
                b.push(Instruction::with2(Code::Add_rm64_imm32, reg, delta).unwrap());
                b.push(Instruction::with2(Code::Sub_rm64_imm32, reg, delta).unwrap());
            }
            SemanticRecipe::MbaIdentity => {
                b.push(Instruction::with1(Code::Neg_rm64, reg).unwrap());
                b.push(Instruction::with1(Code::Neg_rm64, reg).unwrap());
            }
        }
    }

    // Callable entry for native gateways. Unlike RVA 0 it preserves the state
    // base supplied in RDX, while still creating the exact same unwindable
    // nonvolatile frame as the canonical entry.
    let dynamic_state_entry = b.len();
    for r in [
        Register::R12, Register::R13, Register::R14, Register::R15,
        Register::RDI, Register::RSI, Register::RBX, Register::RBP,
    ] {
        b.push(Instruction::with1(Code::Push_r64, r).unwrap());
    }
    let dynamic_entry_jump = b.len();
    b.br(Code::Jmp_rel32_64, usize::MAX);

    // canonical entry
    let entry = b.len();
    // Patch the leading jump (start_jmp) to transfer control to entry.
    for &mut (bi, ref mut ti) in b.branches.iter_mut() {
        if bi == start_jmp {
            *ti = entry;
        }
    }
    // P6-3: index of the entry's checksum placeholder (`mov r11, imm64`) — patched
    // with the real table checksum after assembly (table VAs are only known then).
    let csum_placeholder_idx;
    let table_integrity_topology = TableIntegrityTopology::for_family(family);
    {
        // The eight Win64 nonvolatile registers were saved by the RVA-0
        // prologue above. HALT restores them in reverse order.
        // Seed-permute independent anchor materialization. Besides removing
        // absolute pointers, this avoids one stable four-LEA entry signature.
        let mut anchors = [
            (Register::R8, bytecode_base),
            (Register::R13, stack_base),
            (Register::R15, table_base),
            (Register::RDX, state_base),
        ];
        let mut anchor_mix = crate::vm::seed_lifecycle::derive_seed(seed, 0x414E_4348_4F52_5332);
        for i in (1..anchors.len()).rev() {
            anchors.swap(i, (anchor_mix as usize) % (i + 1));
            anchor_mix = crate::vm::seed_lifecycle::derive_seed(anchor_mix, i as u64);
        }
        for (ordinal, (reg, target)) in anchors.into_iter().enumerate() {
            rip_anchor(&mut b, reg, target);
            if (anchor_mix >> (ordinal * 3)) & 1 != 0 {
                b.push(Instruction::with(Code::Nopd));
            }
        }
        let canonical_to_common = b.len();
        b.br(Code::Jmp_rel32_64, usize::MAX);

        let dynamic_entry_body = b.len();
        // RDX already names the gateway-selected lane. The remaining anchors
        // are module-immutable and can be materialized normally.
        for (reg, target) in [
            (Register::R8, bytecode_base),
            (Register::R13, stack_base),
            (Register::R15, table_base),
        ] {
            rip_anchor(&mut b, reg, target);
        }
        // The virtual stack must be lane-relative as well. Canonical stack_base
        // belongs to canonical state_base, so carry the lane delta into R13.
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RDX).unwrap());
        rip_anchor(&mut b, Register::RCX, state_base);
        b.push(Instruction::with2(Code::Sub_rm64_r64, Register::RAX, Register::RCX).unwrap());
        b.push(Instruction::with2(Code::Add_rm64_r64, Register::R13, Register::RAX).unwrap());

        let entry_common = b.len();
        for &mut (branch, ref mut target) in b.branches.iter_mut() {
            if branch == dynamic_entry_jump || branch == canonical_to_common {
                *target = if branch == dynamic_entry_jump { dynamic_entry_body } else { entry_common };
            }
        }
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R12, Register::R12).unwrap());
        movi(&mut b, Register::R14, init_key);
        // P2-14 hot state: RSI carries the deferred flag snapshot and RDI its
        // validity.  Every module entry starts canonical/clean.
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RDI, Register::RDI).unwrap());
        if cross_family_routes.is_empty() {
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RBX, Register::RBX).unwrap());
        } else {
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RBX,
                    MemoryOperand::with_base_displ_size(
                        Register::RDX,
                        STATE_CROSS_FAMILY_ENTRY_VIP,
                        8,
                    ),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_imm32,
                    MemoryOperand::with_base_displ_size(
                        Register::RDX,
                        STATE_CROSS_FAMILY_ENTRY_VIP,
                        8,
                    ),
                    0,
                )
                .unwrap(),
            );
        }
        b.call(sub_resync);
        // P6-3: handler-table integrity self-check — recompute the checksum over the
        // 256 encrypted entries and compare with the build-time value. A patched /
        // restored table (e.g. a dumped-and-rewritten handler table) trips `ud2`.
        // R15 must be table_base (set above); clobbers RCX/R9/R10/R11/RAX only.
        movi(&mut b, Register::R10, 0x811C9DC5);
        match table_integrity_topology {
            TableIntegrityTopology::ForwardSingle => {
                b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::R9).unwrap());
                let loop_start = b.len();
                emit_table_integrity_mix(&mut b);
                b.push(Instruction::with1(Code::Inc_rm64, Register::R9).unwrap());
                b.push(Instruction::with2(Code::Cmp_rm64_imm32, Register::R9, 256).unwrap());
                b.jne(loop_start);
            }
            TableIntegrityTopology::ReverseSingle => {
                movi(&mut b, Register::R9, 256);
                let loop_start = b.len();
                b.push(Instruction::with1(Code::Dec_rm64, Register::R9).unwrap());
                emit_table_integrity_mix(&mut b);
                b.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9).unwrap(),
                );
                b.jne(loop_start);
            }
            TableIntegrityTopology::ForwardPair => {
                b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::R9).unwrap());
                let loop_start = b.len();
                emit_table_integrity_mix(&mut b);
                b.push(Instruction::with1(Code::Inc_rm64, Register::R9).unwrap());
                emit_table_integrity_mix(&mut b);
                b.push(Instruction::with1(Code::Inc_rm64, Register::R9).unwrap());
                b.push(Instruction::with2(Code::Cmp_rm64_imm32, Register::R9, 256).unwrap());
                b.jne(loop_start);
            }
            TableIntegrityTopology::ReversePair => {
                movi(&mut b, Register::R9, 256);
                let loop_start = b.len();
                b.push(Instruction::with1(Code::Dec_rm64, Register::R9).unwrap());
                emit_table_integrity_mix(&mut b);
                b.push(Instruction::with1(Code::Dec_rm64, Register::R9).unwrap());
                emit_table_integrity_mix(&mut b);
                b.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9).unwrap(),
                );
                b.jne(loop_start);
            }
        }
        // placeholder expected checksum — patched below with the real value once the
        // (VA-dependent) encrypted table is built. mov r64, imm64 is fixed 10 bytes.
        csum_placeholder_idx =
            b.push(Instruction::with2(Code::Mov_r64_imm64, Register::R11, 0x1234_5678).unwrap());
        b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R10, Register::R11).unwrap());
        let csum_je = b.br(Code::Je_rel32_64, 0);
        b.push(Instruction::with(Code::Ud2));
        let csum_ok = b.len();
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if bi == csum_je {
                *ti = csum_ok;
            }
        }
    }

    // P2-3: select the actual dispatch control-flow topology per build.
    let dispatcher_plan = crate::vm::dispatch_perm::DispatcherPlan::from_seed(seed);
    // dispatch loop
    let dispatch = b.len();
    {
        b.push(
            Instruction::with2(
                Code::Mov_rm8_imm8,
                MemoryOperand::with_base_displ(Register::RDX, STATE_SUPEROP_DESCRIPTOR_MASK),
                0,
            )
            .unwrap(),
        );
        b.call(sub_decrypt);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
        // P6-3: keep the decrypted opcode byte in R9 — it drives the per-opcode
        // table key below. (R9 is scratch here; no handler relies on it at entry.)
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RAX).unwrap());
        let tbl =
            MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::RAX, 8, 0, 8);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, tbl).unwrap());
        // P6-3: derive the master key K = a + b via the MBA identity
        // `a + b == (a ^ b) + 2 * (a & b)`. K is never a plaintext constant in the
        // code — only mba_a / mba_b are embedded (and each alone reveals nothing).
        movi(&mut b, Register::RCX, mba_a);
        movi(&mut b, Register::R10, mba_b);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RCX).unwrap());
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R11, Register::R10).unwrap());
        b.push(Instruction::with2(Code::And_rm64_r64, Register::RCX, Register::R10).unwrap());
        b.push(Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::RCX).unwrap());
        b.push(Instruction::with2(Code::Add_rm64_r64, Register::R11, Register::RCX).unwrap());
        // P6-3: per-opcode key K(op) = (op*C1) ^ (op<<17) ^ C4 ^ master. The table
        // entry was XORed with K(op) at build time, so this exactly recovers the
        // handler VA. A single-XOR restore attack (XOR the whole table with one
        // constant) cannot reproduce K(op) — each entry uses a different key, and
        // even opcode 0 differs from master (C4 mixed in).
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R9).unwrap());
        movi(&mut b, Register::R10, C1);
        b.push(Instruction::with2(Code::Imul_r64_rm64, Register::RCX, Register::R10).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::R9).unwrap());
        b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::R10, 17).unwrap());
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RCX, Register::R10).unwrap());
        movi(&mut b, Register::R10, C4);
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RCX, Register::R10).unwrap());
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RCX, Register::R11).unwrap());
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RCX).unwrap());
        // Seed-sized, reachable instruction-selection prelude. These are true
        // architectural NOPs, so neither native flags nor the VM state changes.
        for n in 0..dispatcher_plan.island_count {
            let kind = (dispatcher_plan.table_lane_rotation.wrapping_add(n)) % 3;
            b.push(Instruction::with(match kind {
                0 => Code::Nopd,
                1 => Code::Nopw,
                _ => Code::Nopq,
            }));
        }
        use crate::vm::dispatch_perm::DispatcherTopology;
        match dispatcher_plan.topology {
            DispatcherTopology::DirectThreaded => {
                b.push(Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap());
            }
            DispatcherTopology::IndirectThreaded => {
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap(),
                );
                b.push(Instruction::with1(Code::Jmp_rm64, Register::R10).unwrap());
            }
            DispatcherTopology::CallRet => {
                b.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
                b.push(Instruction::with(Code::Retnq));
            }
            DispatcherTopology::SwitchSplit => {
                b.push(
                    Instruction::with2(
                        Code::Test_rm64_imm32,
                        Register::R9,
                        dispatcher_plan.split_selector as i32,
                    )
                    .unwrap(),
                );
                let alternate_branch = b.br(Code::Je_rel32_64, 0);
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap(),
                );
                b.push(Instruction::with1(Code::Jmp_rm64, Register::R10).unwrap());
                let alternate = b.len();
                b.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
                b.push(Instruction::with(Code::Retnq));
                if let Some((_, target)) = b
                    .branches
                    .iter_mut()
                    .find(|(branch, _)| *branch == alternate_branch)
                {
                    *target = alternate;
                }
            }
            DispatcherTopology::Distributed => {
                let island_branch = b.br(Code::Jmp_rel32_64, 0);
                let island = b.len();
                b.push(Instruction::with(Code::Nopw));
                b.push(Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap());
                if let Some((_, target)) = b
                    .branches
                    .iter_mut()
                    .find(|(branch, _)| *branch == island_branch)
                {
                    *target = island;
                }
            }
        }
    }

    // helper: resolve src1 -> R10, src2 -> R11 (inline per handler)
    // (each handler calls decode_operands then resolves)

    let h_nop = b.len();
    {
        b.call(sub_dec_ops);
        b.jmp(dispatch);
    }

    // P6-3: trap handler for UNUSED opcode bytes. Every table slot that has no
    // registered opcode points here, so probing an unmapped byte (a restore /
    // reconstruction attempt that feeds a crafted byte) hits `ud2` and faults
    // instead of silently no-op'ing. This is the anti-table-probing counterpart
    // to the per-opcode keys above.
    let h_trap = b.len();
    {
        b.push(Instruction::with(Code::Ud2));
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
        // P5: seed-derived, equivalent NOR recipes. Flags are normalized by the
        // final TEST below, so intermediate recipe flags are intentionally dead.
        let nor_plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::Nor).unwrap_or_default(),
        );
        match nor_plan.recipe {
            crate::vm::handler_poly::SemanticRecipe::DeMorgan
            | crate::vm::handler_poly::SemanticRecipe::CarrySplit => {
                // De Morgan: ~(a|b) == (~a)&(~b)
                b.push(Instruction::with1(Code::Not_rm64, Register::R10).unwrap());
                b.push(Instruction::with1(Code::Not_rm64, Register::R11).unwrap());
                b.push(
                    Instruction::with2(Code::And_rm64_r64, Register::R10, Register::R11).unwrap(),
                );
            }
            crate::vm::handler_poly::SemanticRecipe::Native => {
                b.push(
                    Instruction::with2(Code::Or_rm64_r64, Register::R10, Register::R11).unwrap(),
                );
                b.push(Instruction::with1(Code::Not_rm64, Register::R10).unwrap());
            }
            crate::vm::handler_poly::SemanticRecipe::BooleanBasis
            | crate::vm::handler_poly::SemanticRecipe::MbaIdentity => {
                // a|b == (a^b)|(a&b), with RAX as a dead scratch here.
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap(),
                );
                b.push(
                    Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R11).unwrap(),
                );
                b.push(
                    Instruction::with2(Code::And_rm64_r64, Register::R10, Register::R11).unwrap(),
                );
                b.push(
                    Instruction::with2(Code::Or_rm64_r64, Register::R10, Register::RAX).unwrap(),
                );
                b.push(Instruction::with1(Code::Not_rm64, Register::R10).unwrap());
            }
        }
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
        b.push(Instruction::with2(Code::Sub_rm32_imm32, Register::EAX, 1).unwrap());
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 7).unwrap());
        let no_cin = b.len() + 1;
        b.br(Code::Jbe_rel32_64, no_cin);
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        b.push(Instruction::with2(Code::Sub_rm32_imm32, Register::EAX, 1).unwrap());
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 7).unwrap());
        let no_cin2 = b.len() + 1;
        b.br(Code::Jbe_rel32_64, no_cin2);
        emit_read_imm8(
            &mut b,
            DEC_CIN,
            sub_decrypt,
            spec.operand_mask,
            (seed >> 43) as u8,
        );
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
        b.push(
            Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!FLAG_MASK) as i32).unwrap(),
        );
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
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::ShiftRight).unwrap_or_default(),
        );
        emit_synth_identity(&mut b, Register::R10, &plan);
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::R11, 63).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R11, Register::R11).unwrap());
        let skip0 = b.len() + 1;
        b.je(skip0);
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).unwrap());
        b.push(Instruction::with2(Code::Shr_rm64_CL, Register::R10, Register::CL).unwrap());
        // P0-3: count!=0 만 flags 갱신 — count==0 은 x86 flags 보존(skip0 → done0).
        emit_store_shift_flags(&mut b);
        let done0 = b.len();
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == skip0 {
                *ti = done0;
            }
        }
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
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::ShiftLeft).unwrap_or_default(),
        );
        emit_synth_identity(&mut b, Register::R10, &plan);
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::R11, 63).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R11, Register::R11).unwrap());
        let skip0 = b.len() + 1;
        b.je(skip0);
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).unwrap());
        b.push(Instruction::with2(Code::Shl_rm64_CL, Register::R10, Register::CL).unwrap());
        // P0-3: count!=0 만 flags 갱신 (count==0 은 x86 flags 보존).
        emit_store_shift_flags(&mut b);
        let done0 = b.len();
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == skip0 {
                *ti = done0;
            }
        }
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

    // ── F1: SET_NATIVE_FP_RETURN{width} — FP 리턴 힌트. 폭(0/4/8)은 variant 에
    //    bake 되므로 핸들러는 상수 폭을 FP_RET_OFF 슬롯에 기록하고 dispatch.
    //    (sub_dec_ops 가 3개 오퍼랜드 바이트를 소비해 롤링키를 유지한다.)
    let mut h_set_fp_ret = std::collections::HashMap::new();
    for w in [0u8, 4, 8] {
        let h = b.len();
        {
            b.call(sub_dec_ops);
            movi(&mut b, Register::RAX, w as u64);
            store_m(&mut b, FP_RET_OFF, Register::RAX);
            b.jmp(dispatch);
        }
        h_set_fp_ret.insert(RiscOp::SetNativeFpReturn { width: w }, h);
    }

    // ── P3: VIRTUAL_BRANCH — conditional branch: DEC_COND decides taken/not-taken;
    //    a taken branch resolves the target to a bytecode byte offset via the branch
    //    map (OFF_BRANCH_MAP, built from ip_map) and re-syncs the rolling key (forward
    //    or reverse) before dispatching to the target instruction.
    let native_bridge_instr_begin: usize;
    let native_bridge_instr_end: usize;
    let native_bridge_entry: usize;
    let h_branch = b.len();
    {
        b.call(sub_dec_ops_cond); // cond byte -> DEC_COND
        b.call(sub_dec_ops); // dst/src1/src2 + imms (consumes the stream)
                             // absolute-index target (src1 == 0x00): read compact marker+payload.
                             // This must be consumed even when not-taken so the key stays in sync.
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        b.push(Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap());
        b.br(Code::Je_rel32_64, BRANCH_ABSOLUTE_LABEL); // src1 == 0x00 -> absolute target read
                                         // dynamic target: resolve src1 into DEC_IMM1 (indirect branch).
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        store_m(&mut b, DEC_IMM1, Register::RAX);
        b.br(Code::Jmp_rel32_64, BRANCH_AFTER_DECODE_LABEL); // -> after_all
        let abs_read = b.len();
        b.call(sub_decrypt);
        store_decoded_al(&mut b, DEC_SRC2, (seed >> 57) as u8);
        movzx8_m(&mut b, Register::EAX, DEC_SRC2);
        b.push(Instruction::with2(Code::Sub_rm32_imm32, Register::EAX, 0x10).unwrap());
        b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 3).unwrap());
        let valid_marker = b.len() + 2;
        b.br(Code::Jbe_rel32_64, valid_marker);
        b.push(Instruction::with(Code::Ud2));
        emit_read_compact_imm(
            &mut b,
            DEC_SRC2,
            DEC_IMM1,
            sub_decrypt,
            spec.operand_mask,
            layout.operand_offs_off,
            false,
        );
        if family != crate::vm::poly::VmArchitectureFamily::Stack {
            mov_m(&mut b, Register::RAX, DEC_IMM1);
            match family {
                crate::vm::poly::VmArchitectureFamily::Register => {
                    movi(&mut b, Register::RCX, spec.branch_target_key());
                    b.push(
                        Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RCX)
                            .unwrap(),
                    );
                }
                crate::vm::poly::VmArchitectureFamily::MixedRisc => {
                    b.push(Instruction::with1(Code::Not_rm64, Register::RAX).unwrap());
                }
                crate::vm::poly::VmArchitectureFamily::FusedCisc => {
                    movi(&mut b, Register::RCX, spec.branch_target_key());
                    b.push(
                        Instruction::with2(Code::Sub_rm64_r64, Register::RAX, Register::RCX)
                            .unwrap(),
                    );
                }
                crate::vm::poly::VmArchitectureFamily::Stack => unreachable!(),
            }
            movi(&mut b, Register::RCX, 64);
            b.push(Instruction::with2(Code::Sub_rm64_r64, Register::RCX, Register::RBP).unwrap());
            b.push(Instruction::with2(Code::Shl_rm64_CL, Register::RAX, Register::CL).unwrap());
            b.push(Instruction::with2(Code::Shr_rm64_CL, Register::RAX, Register::CL).unwrap());
            store_m(&mut b, DEC_IMM1, Register::RAX);
        }
        let after_all = b.len();
        // evaluate the condition (AL = taken).
        b.call(sub_eval_cond);
        b.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
        b.br(Code::Je_rel32_64, BRANCH_NOT_TAKEN_LABEL); // not taken -> dispatch (fall through)
                                         // taken: target value = [DEC_IMM1] -> R10.
        mov_m(&mut b, Register::R10, DEC_IMM1);
        // branch-map base is build-specific relative to R15; linear-scan for R10.
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R15).unwrap());
        b.push(
            Instruction::with2(
                Code::Add_rm64_imm32,
                Register::RBX,
                layout.branch_map_off as i32,
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::ECX,
                MemoryOperand::with_base(Register::RBX),
            )
            .unwrap(),
        ); // count
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
        b.br(Code::Je_rel32_64, BRANCH_NOT_FOUND_LABEL); // count == 0 -> not found
        b.push(
            Instruction::with2(
                Code::Lea_r64_m,
                Register::R11,
                MemoryOperand::with_base_displ_size(Register::RBX, 4, 8),
            )
            .unwrap(),
        );
        let scan_top = b.len();
        {
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RAX,
                    MemoryOperand::with_base(Register::R11),
                )
                .unwrap(),
            );
            movi(&mut b, Register::R9, branch_target_key);
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R9).unwrap());
            b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::RAX, Register::R10).unwrap());
            b.br(Code::Je_rel32_64, BRANCH_FOUND_LABEL); // found
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
        // Cross-family routes are deliberately checked only after the local
        // branch map misses. They therefore cannot slow or perturb same-family
        // control flow. A matched route snapshots the caller's architectural
        // state into the independently permuted child state, selects the child
        // bytecode entry offset, and then reuses the canonical native-call ABI
        // below for call/return and volatile-register synchronization.
        for (route_index, route) in cross_family_routes.iter().enumerate() {
            movi(&mut b, Register::RAX, route.target_va);
            b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R10, Register::RAX).unwrap());
            let next_route = 0xE000_0000usize + route_index;
            b.br(Code::Jne_rel32_64, next_route);
            // A target VA is not a unique runtime route key: one family can both
            // CALL and tail-JUMP to the same function from different bytecode
            // sites.  R12 is the bytecode VIP *after* the current VirtualBranch
            // has been fully decoded, so matching that post-instruction VIP
            // disambiguates the source callsite without adding mutable VM state.
            if let Some(source_next_byte_offset) = route.source_next_byte_offset {
                movi(&mut b, Register::RAX, source_next_byte_offset);
                b.push(
                    Instruction::with2(Code::Cmp_rm64_r64, Register::R12, Register::RAX).unwrap(),
                );
                b.br(Code::Jne_rel32_64, next_route);
            }
            // Preserve the caller's invocation/thread lane across a family
            // transition. `target_state_va - state_base` is only the canonical
            // family delta; RDX may point at a parallel lane selected by the
            // external gateway.
            let target_state_delta = i64::try_from(route.target_state_va as i128 - state_base as i128)
                .map_err(|_| anyhow!("cross-family state delta does not fit i64"))?;
            b.push(
                Instruction::with2(
                    Code::Lea_r64_m,
                    Register::RCX,
                    MemoryOperand::with_base_displ_size(Register::RDX, target_state_delta, 8),
                )
                .unwrap(),
            );
            for index in 0..16 {
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        MemoryOperand::with_base_displ_size(
                            Register::RDX,
                            runtime_layout.vregs[index] as i64,
                            8,
                        ),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_r64,
                        MemoryOperand::with_base_displ_size(
                            Register::RCX,
                            route.target_layout.vregs[index] as i64,
                            8,
                        ),
                        Register::RAX,
                    )
                    .unwrap(),
                );
            }
            // Flags are architectural and cross the family boundary. The VM
            // operand stack is invocation-local: the parent continuation was
            // already removed/owned by the native bridge below, so copying its
            // negative VSP into the child makes the child's top-level RET pop a
            // non-existent frame from a different stack buffer.
            for (source_off, target_off) in
                [(runtime_layout.flags, route.target_layout.flags)]
            {
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        MemoryOperand::with_base_displ_size(Register::RDX, source_off as i64, 8),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_r64,
                        MemoryOperand::with_base_displ_size(Register::RCX, target_off as i64, 8),
                        Register::RAX,
                    )
                    .unwrap(),
                );
            }
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RAX).unwrap());
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ_size(
                        Register::RCX,
                        route.target_layout.vsp as i64,
                        8,
                    ),
                    Register::RAX,
                )
                .unwrap(),
            );
            for slot in 0..runtime_layout.xmm_slots.min(route.target_layout.xmm_slots) {
                for lane in [0i64, 8] {
                    let source_off = runtime_layout.xmm as i64 + slot as i64 * 16 + lane;
                    let target_off = route.target_layout.xmm as i64 + slot as i64 * 16 + lane;
                    b.push(
                        Instruction::with2(
                            Code::Mov_r64_rm64,
                            Register::RAX,
                            MemoryOperand::with_base_displ_size(Register::RDX, source_off, 8),
                        )
                        .unwrap(),
                    );
                    b.push(
                        Instruction::with2(
                            Code::Mov_rm64_r64,
                            MemoryOperand::with_base_displ_size(Register::RCX, target_off, 8),
                            Register::RAX,
                        )
                        .unwrap(),
                    );
                }
            }
            movi(&mut b, Register::RAX, route.target_byte_offset);
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ_size(
                        Register::RCX,
                        STATE_CROSS_FAMILY_ENTRY_VIP,
                        8,
                    ),
                    Register::RAX,
                )
                .unwrap(),
            );
            movi(&mut b, Register::RAX, 1);
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ_size(
                        Register::RCX,
                        STATE_CROSS_FAMILY_ACTIVE,
                        8,
                    ),
                    Register::RAX,
                )
                .unwrap(),
            );
            for (index, return_ptr_off) in std::iter::once((0, STATE_CROSS_FAMILY_RETURN_PTR))
                .chain(STATE_CROSS_FAMILY_VOLATILE_PTRS)
            {
                b.push(
                    Instruction::with2(
                        Code::Lea_r64_m,
                        Register::RAX,
                        MemoryOperand::with_base_displ_size(
                            Register::RCX,
                            route.target_layout.vregs[index] as i64,
                            8,
                        ),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_r64,
                        MemoryOperand::with_base_displ_size(Register::RDX, return_ptr_off, 8),
                        Register::RAX,
                    )
                    .unwrap(),
                );
            }
            b.push(
                Instruction::with2(
                    Code::Lea_r64_m,
                    Register::RAX,
                    MemoryOperand::with_base_displ_size(
                        Register::RCX,
                        route.target_layout.flags as i64,
                        8,
                    ),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ_size(
                        Register::RDX,
                        STATE_CROSS_FAMILY_FLAGS_PTR,
                        8,
                    ),
                    Register::RAX,
                )
                .unwrap(),
            );
            for slot in 0..runtime_layout.xmm_slots.min(route.target_layout.xmm_slots) {
                b.push(
                    Instruction::with2(
                        Code::Lea_r64_m,
                        Register::RAX,
                        MemoryOperand::with_base_displ_size(
                            Register::RCX,
                            route.target_layout.xmm as i64 + slot as i64 * 16,
                            8,
                        ),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_r64,
                        MemoryOperand::with_base_displ_size(
                            Register::RDX,
                            STATE_CROSS_FAMILY_XMM_PTR_BASE + slot as i64 * 8,
                            8,
                        ),
                        Register::RAX,
                    )
                    .unwrap(),
                );
            }
            if let Some(resume_offset) = route.tail_jump_resume_offset {
                b.push(Instruction::with2(Code::Sub_rm64_imm8, Register::R13, 8).unwrap());
                movi(&mut b, Register::RAX, resume_offset);
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_r64,
                        MemoryOperand::with_base(Register::R13),
                        Register::RAX,
                    )
                    .unwrap(),
                );
                mov_m(&mut b, Register::RAX, VSP_OFF);
                b.push(Instruction::with2(Code::Sub_rm64_imm8, Register::RAX, 8).unwrap());
                store_m(&mut b, VSP_OFF, Register::RAX);
            }
            // Generated VM dynamic entries use RDX as their state-base ABI.
            // Preserve the selected child state before the shared native bridge
            // materializes the source guest's architectural RDX.
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ_size(
                        Register::RDX,
                        STATE_CROSS_FAMILY_CALLEE_STATE,
                        8,
                    ),
                    Register::RCX,
                )
                .unwrap(),
            );
            movi(&mut b, Register::R10, route.target_entry_va);
            b.br(Code::Jmp_rel32_64, 0xEFFF_FFFE);
            let next = b.len();
            for &mut (_, ref mut target) in b.branches.iter_mut() {
                if *target == next_route {
                    *target = next;
                }
            }
        }
        let nf_real = b.len();
        native_bridge_entry = nf_real;
        for &mut (_, ref mut target) in b.branches.iter_mut() {
            if *target == 0xEFFF_FFFE {
                *target = nf_real;
            }
        }
        native_bridge_instr_begin = nf_real;
        {
            // Native code observes the canonical architectural state.  Publish a
            // deferred producer token before any VM -> native register/stack
            // marshalling, including unconditional cross-family/native routes.
            emit_materialize_lazy_flags(&mut b);
            // P1-2 diagnostic: snapshot the first unresolved VM→native transfer
            // into the otherwise external call-stack buffer, then park the
            // process so ReadProcessMemory can inspect it. This is build-time
            // opt-in and emits no instructions in production modules.
            if let Some(trace_n) = std::env::var("BTG_TRACE_NATIVE_BRIDGE")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|n| *n > 0)
            {
                const SNAP: i64 = crate::vm::interp::STATE_CALL_STACK_BUF as i64;
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        MemoryOperand::with_base_displ_size(Register::RDX, SNAP + 48, 8),
                    )
                    .unwrap(),
                );
                b.push(Instruction::with1(Code::Inc_rm64, Register::RAX).unwrap());
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_r64,
                        MemoryOperand::with_base_displ_size(Register::RDX, SNAP + 48, 8),
                        Register::RAX,
                    )
                    .unwrap(),
                );
                b.push(Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, trace_n).unwrap());
                b.br(Code::Jne_rel32_64, usize::MAX - 0xBC10);
                // target, guest RSP, RCX, RDX, R8, R9
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_r64,
                        MemoryOperand::with_base_displ_size(Register::RDX, SNAP, 8),
                        Register::R10,
                    )
                    .unwrap(),
                );
                for (slot, state_off) in [
                    (1i64, state_disp(REGS_OFF + 4 * 8) as i64),
                    (2, state_disp(REGS_OFF + 1 * 8) as i64),
                    (3, state_disp(REGS_OFF + 2 * 8) as i64),
                    (4, state_disp(REGS_OFF + 8 * 8) as i64),
                    (5, state_disp(REGS_OFF + 9 * 8) as i64),
                ] {
                    b.push(
                        Instruction::with2(
                            Code::Mov_r64_rm64,
                            Register::RAX,
                            MemoryOperand::with_base_displ_size(Register::RDX, state_off, 8),
                        )
                        .unwrap(),
                    );
                    b.push(
                        Instruction::with2(
                            Code::Mov_rm64_r64,
                            MemoryOperand::with_base_displ_size(Register::RDX, SNAP + slot * 8, 8),
                            Register::RAX,
                        )
                        .unwrap(),
                    );
                }
                let park = b.len();
                b.br(Code::Jmp_rel32_64, park);
                let trace_continue = b.len();
                for &mut (_, ref mut target) in b.branches.iter_mut() {
                    if *target == usize::MAX - 0xBC10 {
                        *target = trace_continue;
                    }
                }
            }
            // 1. pop ret_ip from the virtual stack (R13 top).
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RBP,
                    MemoryOperand::with_base(Register::R13),
                )
                .unwrap(),
            );
            b.push(Instruction::with2(Code::Add_rm64_imm8, Register::R13, 8).unwrap());
            mov_m(&mut b, Register::RAX, VSP_OFF);
            b.push(Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 8).unwrap());
            store_m(&mut b, VSP_OFF, Register::RAX);

            // 2. Stage VM infrastructure, then construct a private bridge frame.
            // The native callee must observe every non-RSP program register exactly
            // as it would in the original code.  Keeping RBX/RBP/RSI/RDI/R12-R15 as
            // VM scratch (the old implementation) leaked dispatcher values into a
            // native callee and caused deterministic corruption across VM/native
            // boundaries.  The frame lives above the call's shadow/argument area,
            // so it remains caller-owned for the duration of the call.
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R12, Register::RDX).unwrap()); // state_base
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::R8).unwrap()); // bytecode_base
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDI, Register::R10).unwrap()); // target
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP).unwrap()); // VM host RSP

            // Native Windows code must execute on the real thread stack. The VM
            // dispatcher uses an isolated .vstate host stack so guest architectural
            // stack writes cannot corrupt dispatcher frames, but carrying that
            // synthetic RSP into ucrt/ntdll violates the thread-stack contract.
            // Guest RSP is the real Windows stack position after the lifted CALL's
            // architectural return-address push; build the private bridge frame
            // below it, then restore the VM host RSP after the native call returns.
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RAX,
                    MemoryOperand::with_base_displ_size(
                        Register::R12,
                        state_disp(REGS_OFF + 4 * 8) as i64,
                        8,
                    ),
                )
                .unwrap(),
            );
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::RAX).unwrap());

            // Frame [rsp+0x00..0x6F] = Win64 shadow space + eight stack args;
            // [rsp+0x70..0xAF] = state, bytecode, vstack, table, ret-ip,
            // VM-host-rsp, target, optional child-state. Guest RSP is 8 mod 16,
            // so subtracting 0xB8 yields the required 0-mod-16 pre-call RSP.
            b.push(Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, 0xB8).unwrap());
            for (off, reg) in [
                (0x70, Register::R12),
                (0x78, Register::R14),
                (0x80, Register::R13),
                (0x88, Register::R15),
                (0x90, Register::RBP),
                (0x98, Register::RBX),
                (0xA0, Register::RDI),
            ] {
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_r64,
                        MemoryOperand::with_base_displ_size(Register::RSP, off, 8),
                        reg,
                    )
                    .unwrap(),
                );
            }

            // frame[0xA8] is outside Win64 shadow/forwarded arguments.
            // Snapshot the child state there and clear the transient parent slot
            // so a later ordinary native call cannot reuse a stale route.
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RAX,
                    MemoryOperand::with_base_displ_size(
                        Register::R12,
                        STATE_CROSS_FAMILY_CALLEE_STATE,
                        8,
                    ),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ_size(Register::RSP, 0xA8, 8),
                    Register::RAX,
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_imm32,
                    MemoryOperand::with_base_displ_size(
                        Register::R12,
                        STATE_CROSS_FAMILY_CALLEE_STATE,
                        8,
                    ),
                    0,
                )
                .unwrap(),
            );

            // 3. Forward the caller's real stack-argument area (args 5..12).
            // `VSP_OFF` is the VM's bytecode continuation stack, not the x64 ABI
            // stack. CALL now performs the architectural return-address push as
            // well, so guest RSP points at that return slot and the first Win64
            // stack argument is [RSP+0x28].
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::R10,
                    MemoryOperand::with_base_displ_size(
                        Register::R12,
                        state_disp(REGS_OFF + 4 * 8) as i64,
                        8,
                    ),
                )
                .unwrap(),
            );
            for i in 0..8i32 {
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::R11,
                        MemoryOperand::with_base_displ_size(
                            Register::R10,
                            (0x28 + i * 8) as i64,
                            8,
                        ),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_r64,
                        MemoryOperand::with_base_displ_size(
                            Register::RSP,
                            (0x20 + i * 8) as i64,
                            8,
                        ),
                        Register::R11,
                    )
                    .unwrap(),
                );
            }

            // 4. Materialize all program GPRs except RSP.  R11 carries state_base
            // until the final load; virtual RSP is data in the state buffer and
            // must never replace the physical call stack pointer.
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::R12).unwrap());
            for (index, reg) in [
                (0, Register::RAX),
                (1, Register::RCX),
                (2, Register::RDX),
                (3, Register::RBX),
                (5, Register::RBP),
                (6, Register::RSI),
                (7, Register::RDI),
                (8, Register::R8),
                (9, Register::R9),
                (10, Register::R10),
                (12, Register::R12),
                (13, Register::R13),
                (14, Register::R14),
                (15, Register::R15),
            ] {
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        reg,
                        MemoryOperand::with_base_displ_size(
                            Register::R11,
                            state_disp(REGS_OFF + index * 8) as i64,
                            8,
                        ),
                    )
                    .unwrap(),
                );
            }
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::R11,
                    MemoryOperand::with_base_displ_size(
                        Register::R11,
                        state_disp(REGS_OFF + 11 * 8) as i64,
                        8,
                    ),
                )
                .unwrap(),
            );
            // Mirror positional FP arguments for the Win64 ABI.
            for (xmm, gpr) in [
                (Register::XMM0, Register::RCX),
                (Register::XMM1, Register::RDX),
                (Register::XMM2, Register::R8),
                (Register::XMM3, Register::R9),
            ] {
                b.push(Instruction::with2(Code::Movq_xmm_rm64, xmm, gpr).unwrap());
            }

            // 5. Indirect call through the bridge frame. Ordinary native
            // targets keep guest RDX; generated child modules require
            // dynamic_state_entry's RDX=child-state contract.
            b.push(
                Instruction::with2(
                    Code::Cmp_rm64_imm8,
                    MemoryOperand::with_base_displ_size(Register::RSP, 0xA8, 8),
                    0,
                )
                .unwrap(),
            );
            let native_rdx_ready_edge = b.br(Code::Je_rel32_64, usize::MAX - 0xBC04);
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RDX,
                    MemoryOperand::with_base_displ_size(Register::RSP, 0xA8, 8),
                )
                .unwrap(),
            );
            let native_rdx_ready = b.len();
            for &mut (branch, ref mut target) in b.branches.iter_mut() {
                if branch == native_rdx_ready_edge || *target == usize::MAX - 0xBC04 {
                    *target = native_rdx_ready;
                }
            }
            b.push(
                Instruction::with1(
                    Code::Call_rm64,
                    MemoryOperand::with_base_displ_size(Register::RSP, 0xA0, 8),
                )
                .unwrap(),
            );

            // 6. After the call, recover state_base from the private frame and sync
            // volatile GPRs + RFLAGS back. Nonvolatile GPRs were materialized and
            // are Win64-preserved, so their state slots remain authoritative.
            // F1: regs[0] 동기화는 FP 리턴 여부에 따라 달라진다 — `SetNativeFpReturn`
            // 핸들러가 FP_RET_OFF(0=FALSE, 4=f32, 8=f64)를 기록한다. FP 면 XMM0 의
            // low 폭 바이트를 regs[0] 으로, 아니면 RAX(기존)를 그대로 쓴다. RBX 는
            // orig-RSP 스크래치라 sync-back 대상이 아니므로 스크래치로 안전하다
            // (step 9가 RBX=R15로 다시 적재). sentinel: 0xBC00=int, 0xBC01=f32, 0xBC02=store.
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RBX,
                    MemoryOperand::with_base_displ_size(Register::RSP, 0x70, 8),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RDI,
                    MemoryOperand::with_base_displ_size(
                        Register::RBX,
                        STATE_CROSS_FAMILY_RETURN_PTR,
                        8,
                    ),
                )
                .unwrap(),
            );
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::RDI, Register::RDI).unwrap());
            b.br(Code::Je_rel32_64, usize::MAX - 0xBC03);
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RAX,
                    MemoryOperand::with_base(Register::RDI),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_imm32,
                    MemoryOperand::with_base_displ_size(
                        Register::RBX,
                        STATE_CROSS_FAMILY_RETURN_PTR,
                        8,
                    ),
                    0,
                )
                .unwrap(),
            );
            let integer_result_ready = b.len();
            for &mut (_, ref mut target) in b.branches.iter_mut() {
                if *target == usize::MAX - 0xBC03 {
                    *target = integer_result_ready;
                }
            }
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RDI,
                    MemoryOperand::with_base_displ_size(
                        Register::RBX,
                        state_disp(FP_RET_OFF) as i64,
                        8,
                    ),
                )
                .unwrap(),
            );
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::RDI, Register::RDI).unwrap());
            b.br(Code::Je_rel32_64, usize::MAX - 0xBC00); // width == 0 -> integer return (RAX 그대로)
            b.push(Instruction::with2(Code::Cmp_rm64_imm8, Register::RDI, 4).unwrap());
            b.br(Code::Je_rel32_64, usize::MAX - 0xBC01); // width == 4 -> f32
            b.push(Instruction::with2(Code::Movq_rm64_xmm, Register::RAX, Register::XMM0).unwrap()); // f64
            b.br(Code::Jmp_rel32_64, usize::MAX - 0xBC02);
            let fp4_ret = b.len();
            b.push(Instruction::with2(Code::Movd_rm32_xmm, Register::EAX, Register::XMM0).unwrap()); // f32 (low 32)
            let store_r0 = b.len();
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ_size(
                        Register::RBX,
                        state_disp(REGS_OFF) as i64,
                        8,
                    ),
                    Register::RAX,
                )
                .unwrap(),
            );
            for &mut (bi, ref mut ti) in b.branches.iter_mut() {
                if *ti == usize::MAX - 0xBC00 {
                    *ti = store_r0;
                } else if *ti == usize::MAX - 0xBC01 {
                    *ti = fp4_ret;
                } else if *ti == usize::MAX - 0xBC02 {
                    *ti = store_r0;
                }
            }
            // A generated child returns with dispatcher scratch in the physical
            // volatile registers.  Select the child's authoritative guest slot
            // when a route armed one; ordinary native calls retain ABI sync.
            for ((index, ptr_off), physical) in STATE_CROSS_FAMILY_VOLATILE_PTRS
                .into_iter()
                .zip([
                    Register::RCX,
                    Register::RDX,
                    Register::R8,
                    Register::R9,
                    Register::R10,
                    Register::R11,
                ])
            {
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RDI,
                        MemoryOperand::with_base_displ_size(Register::RBX, ptr_off, 8),
                    )
                    .unwrap(),
                );
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::RDI, Register::RDI).unwrap());
                let native_value = 0xBD00_0000usize + index;
                let stored = 0xBE00_0000usize + index;
                b.br(Code::Je_rel32_64, native_value);
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        MemoryOperand::with_base(Register::RDI),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_imm32,
                        MemoryOperand::with_base_displ_size(Register::RBX, ptr_off, 8),
                        0,
                    )
                    .unwrap(),
                );
                b.br(Code::Jmp_rel32_64, stored);
                let native_at = b.len();
                b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, physical).unwrap());
                let stored_at = b.len();
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_r64,
                        MemoryOperand::with_base_displ_size(
                            Register::RBX,
                            state_disp(REGS_OFF + index as i32 * 8) as i64,
                            8,
                        ),
                        Register::RAX,
                    )
                    .unwrap(),
                );
                for &mut (_, ref mut target) in b.branches.iter_mut() {
                    if *target == native_value {
                        *target = native_at;
                    } else if *target == stored {
                        *target = stored_at;
                    }
                }
            }
            // Generated children publish architectural flags through their
            // state. Physical RFLAGS at HALT belongs to the dispatcher.
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RDI,
                    MemoryOperand::with_base_displ_size(
                        Register::RBX,
                        STATE_CROSS_FAMILY_FLAGS_PTR,
                        8,
                    ),
                )
                .unwrap(),
            );
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::RDI, Register::RDI).unwrap());
            b.br(Code::Je_rel32_64, usize::MAX - 0xBF00);
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RAX,
                    MemoryOperand::with_base(Register::RDI),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_imm32,
                    MemoryOperand::with_base_displ_size(
                        Register::RBX,
                        STATE_CROSS_FAMILY_FLAGS_PTR,
                        8,
                    ),
                    0,
                )
                .unwrap(),
            );
            b.br(Code::Jmp_rel32_64, usize::MAX - 0xBF01);
            let native_flags = b.len();
            b.push(Instruction::with(Code::Pushfq));
            b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x8D5).unwrap());
            let flags_ready = b.len();
            for &mut (_, ref mut target) in b.branches.iter_mut() {
                if *target == usize::MAX - 0xBF00 {
                    *target = native_flags;
                } else if *target == usize::MAX - 0xBF01 {
                    *target = flags_ready;
                }
            }
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ_size(
                        Register::RBX,
                        state_disp(FLAGS_OFF) as i64,
                        8,
                    ),
                    Register::RAX,
                )
                .unwrap(),
            );
            // P1-8: callee 가 clobber 한 XMM0-5 를 VM XMM 슬롯으로 동기화 (반환값/
            // 변경된 FP 상태 보존).
            for i in 0..XMM_SLOTS {
                let xmm = match i {
                    0 => Register::XMM0,
                    1 => Register::XMM1,
                    2 => Register::XMM2,
                    3 => Register::XMM3,
                    4 => Register::XMM4,
                    _ => Register::XMM5,
                };
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RDI,
                        MemoryOperand::with_base_displ_size(
                            Register::RBX,
                            STATE_CROSS_FAMILY_XMM_PTR_BASE + i as i64 * 8,
                            8,
                        ),
                    )
                    .unwrap(),
                );
                b.push(Instruction::with2(Code::Test_rm64_r64, Register::RDI, Register::RDI).unwrap());
                let native_xmm = 0xC000_0000usize + i;
                b.br(Code::Je_rel32_64, native_xmm);
                b.push(
                    Instruction::with2(
                        Code::Movups_xmm_xmmm128,
                        xmm,
                        MemoryOperand::with_base(Register::RDI),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_imm32,
                        MemoryOperand::with_base_displ_size(
                            Register::RBX,
                            STATE_CROSS_FAMILY_XMM_PTR_BASE + i as i64 * 8,
                            8,
                        ),
                        0,
                    )
                    .unwrap(),
                );
                let xmm_ready = b.len();
                for &mut (_, ref mut target) in b.branches.iter_mut() {
                    if *target == native_xmm {
                        *target = xmm_ready;
                    }
                }
                b.push(
                    Instruction::with2(
                        Code::Movups_xmmm128_xmm,
                        MemoryOperand::with_base_displ_size(
                            Register::RBX,
                            (XMM_OFF + (i as i32) * 16) as i64,
                            16,
                        ),
                        xmm,
                    )
                    .unwrap(),
                );
            }

            // 7. Restore VM infrastructure while physical RSP still points at
            // the real-thread-stack bridge frame. Keep the saved VM host RSP in
            // RBX until the frame has been scrubbed.
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RDX,
                    MemoryOperand::with_base_displ_size(Register::RSP, 0x70, 8),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::R8,
                    MemoryOperand::with_base_displ_size(Register::RSP, 0x78, 8),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::R13,
                    MemoryOperand::with_base_displ_size(Register::RSP, 0x80, 8),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::R15,
                    MemoryOperand::with_base_displ_size(Register::RSP, 0x88, 8),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RBP,
                    MemoryOperand::with_base_displ_size(Register::RSP, 0x90, 8),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RBX,
                    MemoryOperand::with_base_displ_size(Register::RSP, 0x98, 8),
                )
                .unwrap(),
            );

            // The source CALL's architectural return slot was pushed by the
            // lifter. Native/generated child execution returned through the
            // bridge rather than through the source VM's VirtualRet, so consume
            // that slot here.
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RAX,
                    MemoryOperand::with_base_displ_size(
                        Register::RDX,
                        state_disp(REGS_OFF + 4 * 8) as i64,
                        8,
                    ),
                )
                .unwrap(),
            );
            b.push(Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 8).unwrap());
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ_size(
                        Register::RDX,
                        state_disp(REGS_OFF + 4 * 8) as i64,
                        8,
                    ),
                    Register::RAX,
                )
                .unwrap(),
            );

            // Scrub context while the real-stack frame is still addressable.
            // RBX already holds the VM host RSP and is repurposed immediately
            // after the stack switch for branch-map lookup.
            for off in [0x70i64, 0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8] {
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_imm32,
                        MemoryOperand::with_base_displ_size(Register::RSP, off, 8),
                        0,
                    )
                    .unwrap(),
                );
            }
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::RBX).unwrap());

            // 9. resume at ret_ip (RBP): branch-map lookup -> byte offset.
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R15).unwrap());
            b.push(
                Instruction::with2(
                    Code::Add_rm64_imm32,
                    Register::RBX,
                    layout.branch_map_off as i32,
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_r32_rm32,
                    Register::ECX,
                    MemoryOperand::with_base(Register::RBX),
                )
                .unwrap(),
            );
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
            b.br(Code::Je_rel32_64, usize::MAX - 0xB100); // count == 0 -> not found
            b.push(
                Instruction::with2(
                    Code::Lea_r64_m,
                    Register::R11,
                    MemoryOperand::with_base_displ_size(Register::RBX, 4, 8),
                )
                .unwrap(),
            );
            let rscan_top = b.len();
            {
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        MemoryOperand::with_base(Register::R11),
                    )
                    .unwrap(),
                );
                movi(&mut b, Register::R9, branch_target_key);
                b.push(
                    Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R9).unwrap(),
                );
                b.push(
                    Instruction::with2(Code::Cmp_rm64_r64, Register::RAX, Register::RBP).unwrap(),
                );
                b.br(Code::Je_rel32_64, usize::MAX - 0xB101); // found
                b.push(Instruction::with2(Code::Add_rm64_imm32, Register::R11, 16).unwrap());
                b.push(Instruction::with1(Code::Dec_rm64, Register::RCX).unwrap());
                b.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap(),
                );
                b.jne(rscan_top);
                b.br(Code::Jmp_rel32_64, usize::MAX - 0xB100); // not found
            }
            // found: RBX = [R11+8] (byte offset).
            let resume_found_real = b.len();
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RBX,
                    MemoryOperand::with_base_displ_size(Register::R11, 8, 8),
                )
                .unwrap(),
            );
            movi(&mut b, Register::R9, branch_offset_key);
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RBX, Register::R9).unwrap());
            b.br(Code::Jmp_rel32_64, usize::MAX - 0xB200);
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
                if t == usize::MAX - 0xB100 {
                    b.branches[i].1 = resume_nf_real;
                } else if t == usize::MAX - 0xB101 {
                    b.branches[i].1 = resume_found_real;
                } else if t == usize::MAX - 0xB200 {
                    b.branches[i].1 = resume_sync;
                }
            }
        }
        // found: byte offset = [R11 + 8].
        let found_real = b.len();
        native_bridge_instr_end = found_real;
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RBX,
                MemoryOperand::with_base_displ_size(Register::R11, 8, 8),
            )
            .unwrap(),
        );
        movi(&mut b, Register::R9, branch_offset_key);
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RBX, Register::R9).unwrap());
        b.br(Code::Jmp_rel32_64, usize::MAX - 0x9500);
        // re-sync the rolling key to the target byte offset, then dispatch.
        let resync = b.len();
        b.call(sub_resync);
        b.jmp(dispatch);
        // not-taken path: stream already points at the next instruction (key synced).
        let not_taken_real = b.len();
        b.jmp(dispatch);
        for i in 0..b.branches.len() {
            let t = b.branches[i].1;
            if t == BRANCH_ABSOLUTE_LABEL {
                b.branches[i].1 = abs_read;
            } else if t == BRANCH_AFTER_DECODE_LABEL {
                b.branches[i].1 = after_all;
            } else if t == BRANCH_NOT_TAKEN_LABEL {
                b.branches[i].1 = not_taken_real;
            } else if t == BRANCH_NOT_FOUND_LABEL {
                b.branches[i].1 = nf_real;
            } else if t == BRANCH_FOUND_LABEL {
                b.branches[i].1 = found_real;
            } else if t == usize::MAX - 0x9500 {
                b.branches[i].1 = resync;
            }
        }
    }

    // Canonical tail bridge for an indirect JMP that resolves outside the VM.
    // Restore the interpreter's saved nonvolatile frame, materialize the guest
    // register file, and transfer with `ret` through a scratch slot below the
    // guest RSP.  This preserves the original caller's return address and does
    // not invent CALL/return semantics for import thunks and tail calls.
    let native_tail_bridge_entry = b.len();
    {
        emit_materialize_lazy_flags(&mut b);

        // Windows x64 has no red zone. Reserve two qwords below guest RSP for
        // guest R11 and the native target; both are consumed before entry.
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_displ_size(
                    Register::RDX,
                    state_disp(REGS_OFF + 4 * 8) as i64,
                    8,
                ),
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ_size(Register::RAX, -8, 8),
                Register::R10,
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                MemoryOperand::with_base_displ_size(
                    Register::RDX,
                    state_disp(REGS_OFF + 11 * 8) as i64,
                    8,
                ),
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ_size(Register::RAX, -16, 8),
                Register::RCX,
            )
            .unwrap(),
        );
        // Restore architectural flags while the interpreter stack is active.
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                MemoryOperand::with_base_displ_size(
                    Register::RDX,
                    state_disp(FLAGS_OFF) as i64,
                    8,
                ),
            )
            .unwrap(),
        );
        emit_safe_popfq(&mut b, Register::RCX);
        for i in 0..XMM_SLOTS {
            let xmm = match i {
                0 => Register::XMM0,
                1 => Register::XMM1,
                2 => Register::XMM2,
                3 => Register::XMM3,
                4 => Register::XMM4,
                _ => Register::XMM5,
            };
            b.push(
                Instruction::with2(
                    Code::Movups_xmm_xmmm128,
                    xmm,
                    MemoryOperand::with_base_displ_size(
                        Register::RDX,
                        (XMM_OFF + i as i32 * 16) as i64,
                        16,
                    ),
                )
                .unwrap(),
            );
        }

        // Undo the generated VM entry prologue before publishing guest
        // nonvolatile registers.
        for reg in [
            Register::RBP,
            Register::RBX,
            Register::RSI,
            Register::RDI,
            Register::R15,
            Register::R14,
            Register::R13,
            Register::R12,
        ] {
            b.push(Instruction::with1(Code::Pop_r64, reg).unwrap());
        }
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RDX).unwrap());
        for (index, reg) in [
            (1, Register::RCX),
            (2, Register::RDX),
            (3, Register::RBX),
            (5, Register::RBP),
            (6, Register::RSI),
            (7, Register::RDI),
            (8, Register::R8),
            (9, Register::R9),
            (10, Register::R10),
            (12, Register::R12),
            (13, Register::R13),
            (14, Register::R14),
            (15, Register::R15),
        ] {
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    reg,
                    MemoryOperand::with_base_displ_size(
                        Register::R11,
                        state_disp(REGS_OFF + index * 8) as i64,
                        8,
                    ),
                )
                .unwrap(),
            );
        }
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RSP,
                MemoryOperand::with_base_displ_size(
                    Register::R11,
                    state_disp(REGS_OFF + 4 * 8) as i64,
                    8,
                ),
            )
            .unwrap(),
        );
        b.push(Instruction::with2(Code::Sub_rm64_imm8, Register::RSP, 16).unwrap());
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_displ_size(
                    Register::R11,
                    state_disp(REGS_OFF) as i64,
                    8,
                ),
            )
            .unwrap(),
        );
        b.push(Instruction::with1(Code::Pop_r64, Register::R11).unwrap());
        b.push(Instruction::with(Code::Retnq));
    }

    // Only arithmetic status flags belong to the virtual ISA. Feeding raw
    // state into POPFQ can enable TF/DF/AC and turn ordinary condition checks
    // into single-step or alignment exceptions. Bit 1 is architecturally set.
    fn emit_safe_popfq(b: &mut CodeBuilder, reg: Register) {
        b.push(Instruction::with2(Code::And_rm64_imm32, reg, 0x8D5).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_imm8, reg, 2).unwrap());
        b.push(Instruction::with1(Code::Push_r64, reg).unwrap());
        b.push(Instruction::with(Code::Popfq));
    }

    // Typed indirect transfers are deliberately separate from VirtualBranch.
    // An indirect CALL may legitimately target an imported/CRT function outside
    // the image (vtable, Rust trait object, callback table).  Such a miss reuses
    // the canonical VM->native call bridge.  An indirect JMP still requires a
    // canonical VM entry: treating an arbitrary computed jump as a native call
    // would invent return semantics and corrupt the virtual stack.
    let emit_indirect_transfer = |b: &mut CodeBuilder, allow_native_call: bool| -> usize {
        let handler = b.len();
        b.call(sub_dec_ops);

        // src1 is the runtime target VA/RVA.
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());

        // Resolve exclusively through the immutable branch map.
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R15).unwrap());
        b.push(
            Instruction::with2(
                Code::Add_rm64_imm32,
                Register::RBX,
                layout.branch_map_off as i32,
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::ECX,
                MemoryOperand::with_base(Register::RBX),
            )
            .unwrap(),
        );
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
        let miss_tag = b.len() + 0x1000_0000;
        b.br(Code::Je_rel32_64, miss_tag);
        b.push(
            Instruction::with2(
                Code::Lea_r64_m,
                Register::R11,
                MemoryOperand::with_base_displ_size(Register::RBX, 4, 8),
            )
            .unwrap(),
        );
        let scan_top = b.len();
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base(Register::R11),
            )
            .unwrap(),
        );
        movi(b, Register::R9, branch_target_key);
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R9).unwrap());
        b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::RAX, Register::R10).unwrap());
        let found_tag = miss_tag + 1;
        b.br(Code::Je_rel32_64, found_tag);
        b.push(Instruction::with2(Code::Add_rm64_imm32, Register::R11, 16).unwrap());
        b.push(Instruction::with1(Code::Dec_rm64, Register::RCX).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
        b.jne(scan_top);

        let miss = b.len();
        if allow_native_call {
            b.jmp(native_bridge_entry);
        } else {
            // A syntactic JMP is a process-level tail call only when this VM
            // invocation has no virtual caller.  Cross-family/internal CALLs
            // keep their continuation on VSP while the callee may finish with
            // an import-thunk JMP. In that case call the external target via
            // the ordinary bridge; it consumes the existing continuation and
            // resumes the VM caller. Bypassing those bridge frames caused CRT
            // callbacks to re-enter suspended family states and corrupt them.
            mov_m(b, Register::RAX, VSP_OFF);
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
            let inspect_cross_family = miss_tag + 2;
            let top_level_tail = miss_tag + 3;
            b.br(Code::Jns_rel32_64, inspect_cross_family);
            b.jmp(native_bridge_entry);
            let inspect_cross_family_real = b.len();
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RAX,
                    MemoryOperand::with_base_displ_size(
                        Register::RDX,
                        STATE_CROSS_FAMILY_ACTIVE,
                        8,
                    ),
                )
                .unwrap(),
            );
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
            b.br(Code::Je_rel32_64, top_level_tail);
            // The child has a physical parent bridge but no child-local VSP
            // continuation. Give the ordinary native bridge a canonical HALT
            // continuation so the external tail target returns through the
            // child and then through every suspended family bridge.
            b.push(Instruction::with2(Code::Sub_rm64_imm8, Register::R13, 8).unwrap());
            movi(b, Register::RAX, top_level_exit_byte_offset);
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base(Register::R13),
                    Register::RAX,
                )
                .unwrap(),
            );
            movi(b, Register::RAX, u64::MAX - 7);
            store_m(b, VSP_OFF, Register::RAX);
            b.jmp(native_bridge_entry);
            let top_level_tail_real = b.len();
            b.jmp(native_tail_bridge_entry);
            for (_, target) in &mut b.branches {
                if *target == inspect_cross_family {
                    *target = inspect_cross_family_real;
                } else if *target == top_level_tail {
                    *target = top_level_tail_real;
                }
            }
        }
        let found = b.len();
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RBX,
                MemoryOperand::with_base_displ_size(Register::R11, 8, 8),
            )
            .unwrap(),
        );
        movi(b, Register::R9, branch_offset_key);
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RBX, Register::R9).unwrap());
        b.call(sub_resync);
        b.jmp(dispatch);
        for (_, target) in &mut b.branches {
            if *target == miss_tag {
                *target = miss;
            } else if *target == found_tag {
                *target = found;
            }
        }
        handler
    };
    // The lifter represents CALL as VirtualPush(ret_ip) followed by the typed
    // transfer, so both handlers perform lookup/transfer only. VirtualRet pops
    // the already-pushed continuation.
    let h_indirect_call = emit_indirect_transfer(&mut b, true);
    let h_indirect_jump = emit_indirect_transfer(&mut b, false);

    let h_halt = b.len();
    {
        emit_materialize_lazy_flags(&mut b);
        // A top-level VirtualRet terminates the VM and returns directly to the
        // original native caller.  The interpreter's scratch RAX is not an ABI
        // result: publish virtual RAX exactly as the lifted RET would have.
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                m(REGS_OFF),
            )
            .unwrap(),
        );
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
    let h_trap = b.len();
    b.push(Instruction::with(Code::Ud2));

    // ── P0-1: VIRTUAL_RET — x86 RET. 가상 스택에서 복귀 주소를 pop 해 branch-map
    //    (ip_map 기반: source-IP → byte offset)에서 찾으면 rolling-key 재동기 후 해당
    //    오프셋으로 dispatch(VM 내부 복귀). branch-map 에 없으면(빈 스택/네이티브 복귀
    //    주소) Halt 로 종료해 네이티브 호출자에게 돌아간다 — not-found 를 native-call-
    //    bridge 로 보내면 복귀 주소를 call 해 잘못된다.
    let h_ret = b.len();
    {
        // 0. VSP < 0 인 경우에만 pop (빈 스택/최상위 ret 는 pop 없이 Halt —
        //    참조 eval_state 의 `stack.pop()` None 과 동일).
        mov_m(&mut b, Register::RAX, VSP_OFF);
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap());
        b.br(Code::Jns_rel32_64, usize::MAX - 0xD200); // VSP >= 0 -> empty -> halt
                                          // 1. pop ret_ip (R13 top) -> R10, update VSP slot.
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R10,
                MemoryOperand::with_base(Register::R13),
            )
            .unwrap(),
        );
        b.push(Instruction::with2(Code::Add_rm64_imm8, Register::R13, 8).unwrap());
        mov_m(&mut b, Register::RAX, VSP_OFF);
        b.push(Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 8).unwrap());
        store_m(&mut b, VSP_OFF, Register::RAX);

        // 2. branch-map scan for R10 (target_value -> byte_offset).
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R15).unwrap());
        b.push(
            Instruction::with2(
                Code::Add_rm64_imm32,
                Register::RBX,
                layout.branch_map_off as i32,
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::ECX,
                MemoryOperand::with_base(Register::RBX),
            )
            .unwrap(),
        );
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
        b.br(Code::Je_rel32_64, usize::MAX - 0xD100); // count == 0 -> not found (halt)
        b.push(
            Instruction::with2(
                Code::Lea_r64_m,
                Register::R11,
                MemoryOperand::with_base_displ_size(Register::RBX, 4, 8),
            )
            .unwrap(),
        );
        let scan_top = b.len();
        {
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RAX,
                    MemoryOperand::with_base(Register::R11),
                )
                .unwrap(),
            );
            movi(&mut b, Register::R9, branch_target_key);
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R9).unwrap());
            b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::RAX, Register::R10).unwrap());
            b.br(Code::Je_rel32_64, usize::MAX - 0xD101); // found
            b.push(Instruction::with2(Code::Add_rm64_imm32, Register::R11, 16).unwrap());
            b.push(Instruction::with1(Code::Dec_rm64, Register::RCX).unwrap());
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap());
            b.jne(scan_top);
        }
        // not found: fall through to halt path.
        b.br(Code::Jmp_rel32_64, usize::MAX - 0xD100);
        // found: byte offset = [R11 + 8]; re-sync rolling key, then dispatch.
        let ret_found = b.len();
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RBX,
                MemoryOperand::with_base_displ_size(Register::R11, 8, 8),
            )
            .unwrap(),
        );
        movi(&mut b, Register::R9, branch_offset_key);
        b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RBX, Register::R9).unwrap());
        let ret_resync = b.len();
        b.call(sub_resync);
        b.jmp(dispatch);
        // not found / empty -> halt (native caller return).
        let ret_halt = b.len();
        for i in 0..b.branches.len() {
            let t = b.branches[i].1;
            if t == usize::MAX - 0xD100 {
                b.branches[i].1 = ret_halt;
            } else if t == usize::MAX - 0xD101 {
                b.branches[i].1 = ret_found;
            } else if t == usize::MAX - 0xD200 {
                b.branches[i].1 = ret_halt;
            }
        }
        b.jmp(h_halt);
    }

    // ── P3: MOV — dst = src1 (no flags). ──
    let h_mov = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        let mov_plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::Mov).unwrap_or_default(),
        );
        match mov_plan.recipe {
            crate::vm::handler_poly::SemanticRecipe::Native => {
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RAX).unwrap(),
                );
            }
            crate::vm::handler_poly::SemanticRecipe::DeMorgan
            | crate::vm::handler_poly::SemanticRecipe::CarrySplit => {
                // Two involutions preserve the resolved value. Host flags are
                // dead here; MOV's guest flags live in the VM state and remain
                // untouched.
                b.push(Instruction::with1(Code::Not_rm64, Register::RAX).unwrap());
                b.push(Instruction::with1(Code::Not_rm64, Register::RAX).unwrap());
            }
            crate::vm::handler_poly::SemanticRecipe::BooleanBasis
            | crate::vm::handler_poly::SemanticRecipe::MbaIdentity => {
                let mask = (mov_plan.context_key | 1) as i32;
                b.push(Instruction::with2(Code::Xor_rm64_imm32, Register::RAX, mask).unwrap());
                b.push(Instruction::with2(Code::Xor_rm64_imm32, Register::RAX, mask).unwrap());
            }
        }
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
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::ArithmeticShiftRight)
                .unwrap_or_default(),
        );
        emit_synth_identity(&mut b, Register::R10, &plan);
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::R11, 63).unwrap());
        b.push(Instruction::with2(Code::Test_rm64_r64, Register::R11, Register::R11).unwrap());
        let skip0 = b.len() + 1;
        b.je(skip0);
        b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).unwrap());
        b.push(Instruction::with2(Code::Sar_rm64_CL, Register::R10, Register::CL).unwrap());
        // P0-3: count!=0 만 flags 갱신 (count==0 은 x86 flags 보존).
        emit_store_shift_flags(&mut b);
        let done0 = b.len();
        for &mut (bi, ref mut ti) in b.branches.iter_mut() {
            if *ti == skip0 {
                *ti = done0;
            }
        }
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    // Translate the lifter's synthetic XMM address window to the VM state's
    // physical XMM backing store. Ordinary process addresses pass unchanged.
    fn translate_xmm_addr(b: &mut CodeBuilder) {
        const XMM_VA: u64 = 0xF000_0000_0000_0000;
        let passthrough = 0x7FFF_FF10usize;
        movi(b, Register::RAX, XMM_VA);
        b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R10, Register::RAX).unwrap());
        b.br(Code::Jb_rel32_64, passthrough);
        movi(b, Register::RCX, XMM_VA + 16 * 16);
        b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R10, Register::RCX).unwrap());
        b.br(Code::Jae_rel32_64, passthrough);
        b.push(Instruction::with2(Code::Sub_rm64_r64, Register::R10, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::RDX).unwrap());
        b.push(
            Instruction::with2(Code::Add_rm64_imm32, Register::R10, state_disp(XMM_OFF)).unwrap(),
        );
        let done = b.len();
        for &mut (_, ref mut target) in b.branches.iter_mut() {
            if *target == passthrough {
                *target = done;
            }
        }
    }

    fn trace_memory_write(b: &mut CodeBuilder) {
        let Ok(raw) = std::env::var("BTG_TRACE_MEMORY_WRITE") else {
            return;
        };
        let stop_at = raw.parse::<u32>().unwrap_or(1);
        const SNAP: i64 = crate::vm::interp::STATE_CALL_STACK_BUF as i64;
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_displ_size(Register::RDX, SNAP + 32, 8),
            )
            .unwrap(),
        );
        b.push(Instruction::with1(Code::Inc_rm64, Register::RAX).unwrap());
        b.push(
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ_size(Register::RDX, SNAP + 32, 8),
                Register::RAX,
            )
            .unwrap(),
        );
        for (off, reg) in [
            (0i64, Register::R10),
            (8, Register::R11),
            (16, Register::R12),
            (24, Register::R14),
        ] {
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ_size(Register::RDX, SNAP + off, 8),
                    reg,
                )
                .unwrap(),
            );
        }
        if stop_at == 0 {
            return;
        }
        b.push(Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, stop_at).unwrap());
        b.br(Code::Jne_rel32_64, usize::MAX - 0xBC11);
        let park = b.len();
        b.br(Code::Jmp_rel32_64, park);
        let trace_continue = b.len();
        for &mut (_, ref mut target) in b.branches.iter_mut() {
            if *target == usize::MAX - 0xBC11 {
                *target = trace_continue;
            }
        }
    }

    // ── P3: MEMORY_READ{width} — R10 = addr; R10 = *(addr, width); store dst. ──
    let h_memrd8 = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        translate_xmm_addr(&mut b);
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::MemoryRead { width: 8 })
                .unwrap_or_default(),
        );
        emit_synth_identity(&mut b, Register::R10, &plan);
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
        translate_xmm_addr(&mut b);
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::MemoryRead { width: 4 })
                .unwrap_or_default(),
        );
        emit_synth_identity(&mut b, Register::R10, &plan);
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
        translate_xmm_addr(&mut b);
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::MemoryRead { width: 2 })
                .unwrap_or_default(),
        );
        emit_synth_identity(&mut b, Register::R10, &plan);
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
        translate_xmm_addr(&mut b);
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::MemoryRead { width: 1 })
                .unwrap_or_default(),
        );
        emit_synth_identity(&mut b, Register::R10, &plan);
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
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        translate_xmm_addr(&mut b);
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::MemoryWrite { width: 8 })
                .unwrap_or_default(),
        );
        emit_synth_identity(&mut b, Register::R10, &plan);
        emit_synth_identity(&mut b, Register::R11, &plan);
        trace_memory_write(&mut b);
        let m = MemoryOperand::with_base(Register::R10);
        b.push(Instruction::with2(Code::Mov_rm64_r64, m, Register::R11).unwrap());
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
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        translate_xmm_addr(&mut b);
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::MemoryWrite { width: 4 })
                .unwrap_or_default(),
        );
        emit_synth_identity(&mut b, Register::R10, &plan);
        emit_synth_identity(&mut b, Register::R11, &plan);
        trace_memory_write(&mut b);
        let m = MemoryOperand::with_base(Register::R10);
        b.push(Instruction::with2(Code::Mov_rm32_r32, m, Register::R11D).unwrap());
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
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        translate_xmm_addr(&mut b);
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::MemoryWrite { width: 2 })
                .unwrap_or_default(),
        );
        emit_synth_identity(&mut b, Register::R10, &plan);
        emit_synth_identity(&mut b, Register::R11, &plan);
        trace_memory_write(&mut b);
        let m = MemoryOperand::with_base(Register::R10);
        b.push(Instruction::with2(Code::Mov_rm16_r16, m, Register::R11W).unwrap());
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
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        translate_xmm_addr(&mut b);
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
            seed,
            spec.opcode_for(RiscOp::MemoryWrite { width: 1 })
                .unwrap_or_default(),
        );
        emit_synth_identity(&mut b, Register::R10, &plan);
        emit_synth_identity(&mut b, Register::R11, &plan);
        trace_memory_write(&mut b);
        let m = MemoryOperand::with_base(Register::R10);
        b.push(Instruction::with2(Code::Mov_rm8_r8, m, Register::R11L).unwrap());
        b.jmp(dispatch);
    }

    // Packed SSE handlers operate directly on 16-byte XMM backing-store ranges.
    // `translate_xmm_addr` makes the lifter's synthetic XMM addresses valid in
    // the native VM while leaving ordinary process-memory operands unchanged.
    fn emit_packed_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        dispatch: usize,
        op: RiscOp,
    ) {
        b.call(sub_dec_ops);
        // Resolve and translate sources, then preserve them on the physical
        // stack. R8 is the bytecode-base register and must never be borrowed by
        // a handler: corrupting it desynchronizes the next opcode decrypt and
        // previously surfaced as STATUS_ILLEGAL_INSTRUCTION.
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        translate_xmm_addr(b);
        b.push(Instruction::with1(Code::Push_r64, Register::R10).unwrap());
        let needs_src2 = !matches!(op, RiscOp::PackedMove);
        if needs_src2 {
            movzx8_m(b, Register::EAX, DEC_SRC2);
            mov_m(b, Register::R11, DEC_IMM2);
            b.call(sub_resolve);
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
            translate_xmm_addr(b);
            b.push(Instruction::with1(Code::Push_r64, Register::R10).unwrap());
        }
        // Translate destination last, after all operand resolution.
        movzx8_m(b, Register::EAX, DEC_DST);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        translate_xmm_addr(b);
        if needs_src2 {
            b.push(Instruction::with1(Code::Pop_r64, Register::R9).unwrap());
        }
        b.push(Instruction::with1(Code::Pop_r64, Register::R11).unwrap());
        b.push(
            Instruction::with2(
                Code::Movups_xmm_xmmm128,
                Register::XMM0,
                MemoryOperand::with_base(Register::R11),
            )
            .unwrap(),
        );
        if needs_src2 {
            b.push(
                Instruction::with2(
                    Code::Movups_xmm_xmmm128,
                    Register::XMM1,
                    MemoryOperand::with_base(Register::R9),
                )
                .unwrap(),
            );
        }
        let code = match op {
            RiscOp::PackedMove => None,
            RiscOp::PackedAdd { elem_width: 1, .. } => Some(Code::Paddb_xmm_xmmm128),
            RiscOp::PackedAdd { elem_width: 2, .. } => Some(Code::Paddw_xmm_xmmm128),
            RiscOp::PackedAdd { elem_width: 4, .. } => Some(Code::Paddd_xmm_xmmm128),
            RiscOp::PackedAdd { .. } => Some(Code::Paddq_xmm_xmmm128),
            RiscOp::PackedSub { elem_width: 1, .. } => Some(Code::Psubb_xmm_xmmm128),
            RiscOp::PackedSub { elem_width: 2, .. } => Some(Code::Psubw_xmm_xmmm128),
            RiscOp::PackedSub { elem_width: 4, .. } => Some(Code::Psubd_xmm_xmmm128),
            RiscOp::PackedSub { .. } => Some(Code::Psubq_xmm_xmmm128),
            RiscOp::PackedXor => Some(Code::Pxor_xmm_xmmm128),
            RiscOp::PackedAnd => Some(Code::Pand_xmm_xmmm128),
            RiscOp::PackedOr => Some(Code::Por_xmm_xmmm128),
            RiscOp::PackedAndNot => Some(Code::Pandn_xmm_xmmm128),
            RiscOp::PackedCmpEq { elem_width: 1, .. } => Some(Code::Pcmpeqb_xmm_xmmm128),
            RiscOp::PackedCmpEq { elem_width: 2, .. } => Some(Code::Pcmpeqw_xmm_xmmm128),
            RiscOp::PackedCmpEq { elem_width: 4, .. } => Some(Code::Pcmpeqd_xmm_xmmm128),
            RiscOp::PackedCmpEq { .. } => Some(Code::Pcmpeqq_xmm_xmmm128),
            RiscOp::PackedCmpGt { elem_width: 1, .. } => Some(Code::Pcmpgtb_xmm_xmmm128),
            RiscOp::PackedCmpGt { elem_width: 2, .. } => Some(Code::Pcmpgtw_xmm_xmmm128),
            RiscOp::PackedCmpGt { elem_width: 4, .. } => Some(Code::Pcmpgtd_xmm_xmmm128),
            RiscOp::PackedCmpGt { .. } => Some(Code::Pcmpgtq_xmm_xmmm128),
            RiscOp::PackedUnpack {
                elem_width: 1,
                high: false,
            } => Some(Code::Punpcklbw_xmm_xmmm128),
            RiscOp::PackedUnpack {
                elem_width: 2,
                high: false,
            } => Some(Code::Punpcklwd_xmm_xmmm128),
            RiscOp::PackedUnpack {
                elem_width: 4,
                high: false,
            } => Some(Code::Punpckldq_xmm_xmmm128),
            RiscOp::PackedUnpack {
                elem_width: 8,
                high: false,
            } => Some(Code::Punpcklqdq_xmm_xmmm128),
            RiscOp::PackedUnpack {
                elem_width: 1,
                high: true,
            } => Some(Code::Punpckhbw_xmm_xmmm128),
            RiscOp::PackedUnpack {
                elem_width: 2,
                high: true,
            } => Some(Code::Punpckhwd_xmm_xmmm128),
            RiscOp::PackedUnpack {
                elem_width: 4,
                high: true,
            } => Some(Code::Punpckhdq_xmm_xmmm128),
            RiscOp::PackedUnpack {
                elem_width: 8,
                high: true,
            } => Some(Code::Punpckhqdq_xmm_xmmm128),
            _ => unreachable!("non-packed RiscOp passed to packed handler"),
        };
        if let Some(code) = code {
            b.push(Instruction::with2(code, Register::XMM0, Register::XMM1).unwrap());
        }
        b.push(
            Instruction::with2(
                Code::Movups_xmmm128_xmm,
                MemoryOperand::with_base(Register::R10),
                Register::XMM0,
            )
            .unwrap(),
        );
        b.jmp(dispatch);
    }

    fn emit_packed_shift_right_q_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        dispatch: usize,
    ) {
        b.call(sub_dec_ops);
        // Source address.
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        translate_xmm_addr(b);
        b.push(Instruction::with1(Code::Push_r64, Register::R10).unwrap());
        // Dynamic count (the poly record preserves the original imm8 value).
        movzx8_m(b, Register::EAX, DEC_SRC2);
        mov_m(b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        b.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
        // Destination address.
        movzx8_m(b, Register::EAX, DEC_DST);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        translate_xmm_addr(b);
        b.push(Instruction::with1(Code::Pop_r64, Register::R9).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::R11).unwrap());
        b.push(
            Instruction::with2(
                Code::Movups_xmm_xmmm128,
                Register::XMM0,
                MemoryOperand::with_base(Register::R11),
            )
            .unwrap(),
        );
        b.push(Instruction::with2(Code::Movq_xmm_rm64, Register::XMM1, Register::R9).unwrap());
        b.push(
            Instruction::with2(Code::Psrlq_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Movups_xmmm128_xmm,
                MemoryOperand::with_base(Register::R10),
                Register::XMM0,
            )
            .unwrap(),
        );
        b.jmp(dispatch);
    }

    fn emit_packed_shuffle_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        dispatch: usize,
        low_words: bool,
    ) {
        b.call(sub_dec_ops);
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        translate_xmm_addr(b);
        b.push(Instruction::with1(Code::Push_r64, Register::R10).unwrap());
        movzx8_m(b, Register::EAX, DEC_SRC2);
        mov_m(b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        b.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
        movzx8_m(b, Register::EAX, DEC_DST);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        translate_xmm_addr(b);
        b.push(Instruction::with1(Code::Pop_r64, Register::R9).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::R11).unwrap());
        // Snapshot the complete input so in-place shuffles cannot overwrite a
        // lane which a later selector still needs.
        b.push(Instruction::with2(Code::Sub_rm64_imm8, Register::RSP, 16).unwrap());
        b.push(
            Instruction::with2(
                Code::Movups_xmm_xmmm128,
                Register::XMM0,
                MemoryOperand::with_base(Register::R11),
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Movups_xmmm128_xmm,
                MemoryOperand::with_base(Register::RSP),
                Register::XMM0,
            )
            .unwrap(),
        );
        if low_words {
            b.push(
                Instruction::with2(
                    Code::Movups_xmmm128_xmm,
                    MemoryOperand::with_base(Register::R10),
                    Register::XMM0,
                )
                .unwrap(),
            );
        }
        let width = if low_words { 2 } else { 4 };
        for lane in 0..4i64 {
            b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R9D).unwrap());
            if lane != 0 {
                b.push(
                    Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, (lane * 2) as i32)
                        .unwrap(),
                );
            }
            b.push(Instruction::with2(Code::And_rm32_imm8, Register::ECX, 3).unwrap());
            let src = MemoryOperand::with_base_index_scale_displ_size(
                Register::RSP,
                Register::RCX,
                width,
                0,
                1,
            );
            let dst = MemoryOperand::with_base_displ(Register::R10, lane * width as i64);
            if low_words {
                b.push(Instruction::with2(Code::Mov_r16_rm16, Register::AX, src).unwrap());
                b.push(Instruction::with2(Code::Mov_rm16_r16, dst, Register::AX).unwrap());
            } else {
                b.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, src).unwrap());
                b.push(Instruction::with2(Code::Mov_rm32_r32, dst, Register::EAX).unwrap());
            }
        }
        b.push(Instruction::with2(Code::Add_rm64_imm8, Register::RSP, 16).unwrap());
        b.jmp(dispatch);
    }

    fn emit_shld_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        sub_store: usize,
        dispatch: usize,
        width: u8,
    ) {
        b.call(sub_dec_ops);
        // Current destination value is resolved from DEC_DST.
        movzx8_m(b, Register::EAX, DEC_DST);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        b.push(Instruction::with1(Code::Push_r64, Register::R11).unwrap());
        movzx8_m(b, Register::EAX, DEC_SRC2);
        mov_m(b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::R11).unwrap());
        // Restore guest flags so count==0 preserves them exactly.
        mov_m(b, Register::RAX, FLAGS_OFF);
        // AF is architecturally undefined for SHLD when count != 0. Preserve
        // the guest value explicitly so host-CPU leakage cannot make native,
        // reference, and poly executions diverge.
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::R9, 0x10).unwrap());
        emit_safe_popfq(b, Register::RAX);
        match width {
            2 => b.push(
                Instruction::with3(
                    Code::Shld_rm16_r16_CL,
                    Register::R10W,
                    Register::R11W,
                    Register::CL,
                )
                .unwrap(),
            ),
            4 => b.push(
                Instruction::with3(
                    Code::Shld_rm32_r32_CL,
                    Register::R10D,
                    Register::R11D,
                    Register::CL,
                )
                .unwrap(),
            ),
            _ => b.push(
                Instruction::with3(
                    Code::Shld_rm64_r64_CL,
                    Register::R10,
                    Register::R11,
                    Register::CL,
                )
                .unwrap(),
            ),
        };
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, FLAG_MASK as i32).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, !0x10i32).unwrap());
        b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::R9).unwrap());
        store_m(b, FLAGS_OFF, Register::RAX);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    fn emit_bit_test_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        sub_store: usize,
        dispatch: usize,
        width: u8,
        modify: u8,
        memory: bool,
    ) {
        b.call(sub_dec_ops);
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        movzx8_m(b, Register::EAX, DEC_SRC2);
        mov_m(b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        if memory {
            translate_xmm_addr(b);
        }
        mov_m(b, Register::RAX, FLAGS_OFF);
        emit_safe_popfq(b, Register::RAX);
        let code = match (modify, width) {
            (0, 4) => Code::Bt_rm32_r32,
            (0, _) => Code::Bt_rm64_r64,
            (1, 4) => Code::Btr_rm32_r32,
            (1, _) => Code::Btr_rm64_r64,
            (2, 4) => Code::Bts_rm32_r32,
            _ => Code::Bts_rm64_r64,
        };
        if memory {
            b.push(
                Instruction::with2(
                    code,
                    MemoryOperand::with_base(Register::R10),
                    if width == 4 {
                        Register::R11D
                    } else {
                        Register::R11
                    },
                )
                .unwrap(),
            );
        } else {
            b.push(
                Instruction::with2(
                    code,
                    if width == 4 {
                        Register::R10D
                    } else {
                        Register::R10
                    },
                    if width == 4 {
                        Register::R11D
                    } else {
                        Register::R11
                    },
                )
                .unwrap(),
            );
        }
        b.push(Instruction::with(Code::Pushfq));
        b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, FLAG_MASK as i32).unwrap());
        store_m(b, FLAGS_OFF, Register::RAX);
        if !memory {
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
            b.call(sub_store);
        }
        b.jmp(dispatch);
    }

    fn emit_movmask_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        sub_store: usize,
        dispatch: usize,
        ps: bool,
    ) {
        b.call(sub_dec_ops);
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        translate_xmm_addr(b);
        b.push(
            Instruction::with2(
                Code::Movups_xmm_xmmm128,
                Register::XMM0,
                MemoryOperand::with_base(Register::R10),
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                if ps {
                    Code::Movmskps_r32_xmm
                } else {
                    Code::Pmovmskb_r32_xmm
                },
                Register::EAX,
                Register::XMM0,
            )
            .unwrap(),
        );
        b.call(sub_store);
        b.jmp(dispatch);
    }

    fn emit_insert_word_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        dispatch: usize,
    ) {
        b.call(sub_dec_ops);
        movzx8_m(b, Register::EAX, DEC_DST);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        translate_xmm_addr(b);
        b.push(Instruction::with1(Code::Push_r64, Register::R10).unwrap());
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
        movzx8_m(b, Register::EAX, DEC_SRC2);
        mov_m(b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 7).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::R11).unwrap());
        b.push(Instruction::with1(Code::Pop_r64, Register::R10).unwrap());
        let dst = MemoryOperand::with_base_index_scale(Register::R10, Register::RCX, 2);
        b.push(Instruction::with2(Code::Mov_rm16_r16, dst, Register::R11W).unwrap());
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
        let mask: u64 = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
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
        // width-mask the operands. unsigned는 폭 마스크(제로 확장), signed는
        // 폭×2 부호 확장 — x86 signed MUL/IMUL의 고 half가 폭 마스크 곱과 다르므로
        // (8-bit −1×2 → high 0xFF) movsx 로 64비트 폭으로 부호 확장한다.
        match width {
            1 => {
                if signed {
                    b.push(
                        Instruction::with2(Code::Movsx_r64_rm8, Register::R10, Register::R10L)
                            .unwrap(),
                    );
                    b.push(
                        Instruction::with2(Code::Movsx_r64_rm8, Register::R11, Register::R11L)
                            .unwrap(),
                    );
                } else {
                    b.push(
                        Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L)
                            .unwrap(),
                    );
                    b.push(
                        Instruction::with2(Code::Movzx_r32_rm8, Register::R11D, Register::R11L)
                            .unwrap(),
                    );
                }
            }
            2 => {
                if signed {
                    b.push(
                        Instruction::with2(Code::Movsx_r64_rm16, Register::R10, Register::R10W)
                            .unwrap(),
                    );
                    b.push(
                        Instruction::with2(Code::Movsx_r64_rm16, Register::R11, Register::R11W)
                            .unwrap(),
                    );
                } else {
                    b.push(
                        Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::R10W)
                            .unwrap(),
                    );
                    b.push(
                        Instruction::with2(Code::Movzx_r32_rm16, Register::R11D, Register::R11W)
                            .unwrap(),
                    );
                }
            }
            4 => {
                if signed {
                    b.push(
                        Instruction::with2(Code::Movsxd_r64_rm32, Register::R10, Register::R10D)
                            .unwrap(),
                    );
                    b.push(
                        Instruction::with2(Code::Movsxd_r64_rm32, Register::R11, Register::R11D)
                            .unwrap(),
                    );
                } else {
                    b.push(
                        Instruction::with2(Code::Mov_r32_rm32, Register::R10D, Register::R10D)
                            .unwrap(),
                    );
                    b.push(
                        Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::R11D)
                            .unwrap(),
                    );
                }
            }
            _ => {}
        }
        // stage state_base (RDX) in RBX, then RDX:RAX = a*b.
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RDX).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        // P0-2: signed 64-bit MUL 은 부호 확장 128-bit 곱(high = RDX) 이 필요하다 —
        // unsigned `mul` 을 쓰면 -1×2 의 high 가 0xFFFFFFFFFFFFFFFF 가 아닌 1 이 된다.
        // 8/16/32비트 signed 는 movsx 로 64비트 부호 확장 후 low-64 를 마스크/시프트로
        // 정합하지만 64비트는 RDX(high)를 그대로 쓰므로 반드시 `imul` 을 사용해야 한다.
        let mcode = if signed {
            Code::Imul_rm64
        } else {
            Code::Mul_rm64
        };
        b.push(Instruction::with1(mcode, Register::R11).unwrap());
        // high = (full>>bits)&mask -> R9 (low = RAX). signed/64비트 곱은 low 64비트
        // = RAX, high = RDX. bits<64 는 high 를 폭 마스크로 잘라 상위 가비지(부호
        // 확장 잔여)를 제거한다.
        if bits == 64 {
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RDX).unwrap());
        } else {
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RAX).unwrap());
            b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R9, bits as i32).unwrap());
            if mask != u64::MAX {
                movi(b, Register::R10, mask);
                b.push(
                    Instruction::with2(Code::And_rm64_r64, Register::R9, Register::R10).unwrap(),
                );
            }
        }
        // low half 정합: 2w-bit 곱의 하위 half로 마스크해 signed 부호 확장 잔여
        // (movsx→mul 의 상위 가비지)를 제거한다. width 1 은 AX=(high<<8)|low 를
        // 0xFFFF 로, width 2 는 low 를 2w-bit(0xFFFFFFFF)로 자른다. width 4/8 은
        // 2w-bit 마스크가 64비트 전체라 추가 AND 가 필요 없다 (참조 low 동일).
        if width == 1 {
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap());
        } else if width == 2 && signed {
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, -1i32).unwrap());
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
            b.push(
                Instruction::with2(Code::Shr_rm64_imm8, Register::RCX, (bits - 1) as i32).unwrap(),
            );
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 1).unwrap());
            b.push(Instruction::with1(Code::Neg_rm64, Register::RCX).unwrap()); // 0 or all-ones
            movi(b, Register::R10, mask);
            b.push(Instruction::with2(Code::And_rm64_r64, Register::RCX, Register::R10).unwrap()); // sign_ext
            b.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::RCX).unwrap()); // high ^ sign_ext
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9).unwrap());
            b.push(Instruction::with1(Code::Setne_rm8, Register::R10L).unwrap());
            b.push(
                Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).unwrap(),
            );
        } else {
            b.push(Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9).unwrap());
            b.push(Instruction::with1(Code::Setne_rm8, Register::R10L).unwrap());
            b.push(
                Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).unwrap(),
            );
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
                b.push(
                    Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L)
                        .unwrap(),
                );
            }
            2 => {
                b.push(
                    Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::R10W)
                        .unwrap(),
                );
            }
            4 => {
                b.push(
                    Instruction::with2(Code::Mov_r32_rm32, Register::R10D, Register::R10D).unwrap(),
                );
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
            let dsz = if a == 0 {
                0
            } else if a <= 0x7F {
                1
            } else if a <= 0x7FFF {
                2
            } else if a <= 0x7FFFFFFF {
                4
            } else {
                8
            };
            MemoryOperand::with_base_index_scale_displ_size(
                Register::RBX,
                Register::None,
                1,
                disp,
                dsz,
            )
        };
        match width {
            1 => {
                b.push(
                    Instruction::with2(
                        Code::Mov_r16_rm16,
                        Register::AX,
                        rbxmem(REGS_OFF as i64, 0),
                    )
                    .unwrap(),
                );
            }
            2 => {
                b.push(
                    Instruction::with2(
                        Code::Mov_r16_rm16,
                        Register::DX,
                        rbxmem((REGS_OFF + 16) as i64, 4),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_r16_rm16,
                        Register::AX,
                        rbxmem(REGS_OFF as i64, 0),
                    )
                    .unwrap(),
                );
            }
            4 => {
                b.push(
                    Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EDX,
                        rbxmem((REGS_OFF + 16) as i64, 4),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EAX,
                        rbxmem(REGS_OFF as i64, 4),
                    )
                    .unwrap(),
                );
            }
            _ => {
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RDX,
                        rbxmem((REGS_OFF + 16) as i64, 8),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        rbxmem(REGS_OFF as i64, 8),
                    )
                    .unwrap(),
                );
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
                b.push(
                    Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::AX).unwrap(),
                );
            }
            2 => {
                b.push(
                    Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::AX).unwrap(),
                );
                b.push(
                    Instruction::with2(Code::Movzx_r32_rm16, Register::R9D, Register::DX).unwrap(),
                );
            }
            4 => {
                b.push(
                    Instruction::with2(Code::Mov_r32_rm32, Register::R10D, Register::EAX).unwrap(),
                );
                b.push(
                    Instruction::with2(Code::Mov_r32_rm32, Register::R9D, Register::EDX).unwrap(),
                );
            }
            _ => {
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap(),
                );
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RDX).unwrap(),
                );
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
        synthesis_plan: Option<crate::vm::handler_poly::HandlerSynthesisPlan>,
    ) {
        b.call(sub_dec_ops);
        // src1 -> R10
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        // src2 -> R11 (Add/Sub만; Inc/Dec/Not는 src1 단일)
        if matches!(
            op,
            WidthAluOp::Add | WidthAluOp::Sub | WidthAluOp::Adc | WidthAluOp::Sbb
        ) {
            movzx8_m(b, Register::EAX, DEC_SRC2);
            mov_m(b, Register::R11, DEC_IMM2);
            b.call(sub_resolve);
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
        }
        if let Some(plan) = synthesis_plan.as_ref() {
            emit_synth_identity(b, Register::R10, plan);
            if matches!(
                op,
                WidthAluOp::Add | WidthAluOp::Sub | WidthAluOp::Adc | WidthAluOp::Sbb
            ) {
                emit_synth_identity(b, Register::R11, plan);
            }
        }
        // ADC/SBB consume the guest CF. Operand resolution calls clobber host
        // flags, so restore only CF from the guest flag word immediately before
        // executing the hardware instruction.
        if matches!(op, WidthAluOp::Adc | WidthAluOp::Sbb) {
            mov_m(b, Register::RAX, FLAGS_OFF);
            b.push(Instruction::with2(Code::Bt_rm64_imm8, Register::RAX, 0u32).unwrap());
        }
        // 폭별 연산 (x86 부분-쓰기: 8/16비트는 상위 비트 보존 — eval_state의
        // preserve_upper와 동치).
        match (op, width) {
            (WidthAluOp::Add, 1) => b.push(
                Instruction::with2(Code::Add_rm8_r8, Register::R10L, Register::R11L).unwrap(),
            ),
            (WidthAluOp::Add, 2) => b.push(
                Instruction::with2(Code::Add_rm16_r16, Register::R10W, Register::R11W).unwrap(),
            ),
            (WidthAluOp::Add, 4) => b.push(
                Instruction::with2(Code::Add_rm32_r32, Register::R10D, Register::R11D).unwrap(),
            ),
            (WidthAluOp::Add, _) => b.push(
                Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11).unwrap(),
            ),
            (WidthAluOp::Sub, 1) => b.push(
                Instruction::with2(Code::Sub_rm8_r8, Register::R10L, Register::R11L).unwrap(),
            ),
            (WidthAluOp::Sub, 2) => b.push(
                Instruction::with2(Code::Sub_rm16_r16, Register::R10W, Register::R11W).unwrap(),
            ),
            (WidthAluOp::Sub, 4) => b.push(
                Instruction::with2(Code::Sub_rm32_r32, Register::R10D, Register::R11D).unwrap(),
            ),
            (WidthAluOp::Sub, _) => b.push(
                Instruction::with2(Code::Sub_rm64_r64, Register::R10, Register::R11).unwrap(),
            ),
            (WidthAluOp::Adc, 1) => b.push(
                Instruction::with2(Code::Adc_rm8_r8, Register::R10L, Register::R11L).unwrap(),
            ),
            (WidthAluOp::Adc, 2) => b.push(
                Instruction::with2(Code::Adc_rm16_r16, Register::R10W, Register::R11W).unwrap(),
            ),
            (WidthAluOp::Adc, 4) => b.push(
                Instruction::with2(Code::Adc_rm32_r32, Register::R10D, Register::R11D).unwrap(),
            ),
            (WidthAluOp::Adc, _) => b.push(
                Instruction::with2(Code::Adc_rm64_r64, Register::R10, Register::R11).unwrap(),
            ),
            (WidthAluOp::Sbb, 1) => b.push(
                Instruction::with2(Code::Sbb_rm8_r8, Register::R10L, Register::R11L).unwrap(),
            ),
            (WidthAluOp::Sbb, 2) => b.push(
                Instruction::with2(Code::Sbb_rm16_r16, Register::R10W, Register::R11W).unwrap(),
            ),
            (WidthAluOp::Sbb, 4) => b.push(
                Instruction::with2(Code::Sbb_rm32_r32, Register::R10D, Register::R11D).unwrap(),
            ),
            (WidthAluOp::Sbb, _) => b.push(
                Instruction::with2(Code::Sbb_rm64_r64, Register::R10, Register::R11).unwrap(),
            ),
            (WidthAluOp::Inc, 1) => {
                b.push(Instruction::with1(Code::Inc_rm8, Register::R10L).unwrap())
            }
            (WidthAluOp::Inc, 2) => {
                b.push(Instruction::with1(Code::Inc_rm16, Register::R10W).unwrap())
            }
            (WidthAluOp::Inc, 4) => {
                b.push(Instruction::with1(Code::Inc_rm32, Register::R10D).unwrap())
            }
            (WidthAluOp::Inc, _) => {
                b.push(Instruction::with1(Code::Inc_rm64, Register::R10).unwrap())
            }
            (WidthAluOp::Dec, 1) => {
                b.push(Instruction::with1(Code::Dec_rm8, Register::R10L).unwrap())
            }
            (WidthAluOp::Dec, 2) => {
                b.push(Instruction::with1(Code::Dec_rm16, Register::R10W).unwrap())
            }
            (WidthAluOp::Dec, 4) => {
                b.push(Instruction::with1(Code::Dec_rm32, Register::R10D).unwrap())
            }
            (WidthAluOp::Dec, _) => {
                b.push(Instruction::with1(Code::Dec_rm64, Register::R10).unwrap())
            }
            (WidthAluOp::Not, width) => {
                let dst = match width {
                    1 => Register::R10L,
                    2 => Register::R10W,
                    4 => Register::R10D,
                    _ => Register::R10,
                };
                let native_code = match width {
                    1 => Code::Not_rm8,
                    2 => Code::Not_rm16,
                    4 => Code::Not_rm32,
                    _ => Code::Not_rm64,
                };
                let xor_code = match width {
                    1 => Code::Xor_rm8_imm8,
                    2 => Code::Xor_rm16_imm16,
                    4 => Code::Xor_rm32_imm32,
                    _ => Code::Xor_rm64_imm32,
                };
                match synthesis_plan.as_ref().map(|plan| plan.recipe) {
                    None | Some(crate::vm::handler_poly::SemanticRecipe::Native) => {
                        b.push(Instruction::with1(native_code, dst).unwrap());
                    }
                    Some(crate::vm::handler_poly::SemanticRecipe::DeMorgan)
                    | Some(crate::vm::handler_poly::SemanticRecipe::CarrySplit) => {
                        // Width-matched XOR -1 preserves upper bits like NOT.
                        b.push(Instruction::with2(xor_code, dst, -1i32).unwrap());
                    }
                    Some(crate::vm::handler_poly::SemanticRecipe::BooleanBasis)
                    | Some(crate::vm::handler_poly::SemanticRecipe::MbaIdentity) => {
                        // Three involutions are still NOT, but normalize to a
                        // distinct semantic body rather than wrapper padding.
                        for _ in 0..3 {
                            b.push(Instruction::with1(native_code, dst).unwrap());
                        }
                    }
                };
                b.len()
            }
        };
        // 플래그: Add/Sub → 폭별 하드웨어 플래그(CF|PF|ZF|SF|OF). Inc/Dec → CF
        // 보존(emit_store_flags_incdec). Not → 플래그 불변 (x86 NOT).
        match op {
            WidthAluOp::Add | WidthAluOp::Sub | WidthAluOp::Adc | WidthAluOp::Sbb => {
                emit_store_flags(b)
            }
            WidthAluOp::Inc | WidthAluOp::Dec => emit_store_flags_incdec(b),
            WidthAluOp::Not => {}
        }
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap());
        b.call(sub_store);
        b.jmp(dispatch);
    }

    fn emit_rotate_left_handler(
        b: &mut CodeBuilder,
        sub_dec_ops: usize,
        sub_resolve: usize,
        sub_store: usize,
        dispatch: usize,
        width: u8,
    ) {
        b.call(sub_dec_ops);
        movzx8_m(b, Register::EAX, DEC_SRC1);
        mov_m(b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
        movzx8_m(b, Register::EAX, DEC_SRC2);
        mov_m(b, Register::R11, DEC_IMM2);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).unwrap());
        mov_m(b, Register::RAX, FLAGS_OFF);
        emit_safe_popfq(b, Register::RAX);
        let (code, dst) = match width {
            1 => (Code::Rol_rm8_CL, Register::R10L),
            2 => (Code::Rol_rm16_CL, Register::R10W),
            4 => (Code::Rol_rm32_CL, Register::R10D),
            _ => (Code::Rol_rm64_CL, Register::R10),
        };
        b.push(Instruction::with2(code, dst, Register::CL).unwrap());
        emit_store_flags(b);
        if width == 1 {
            b.push(
                Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).unwrap(),
            );
        } else if width == 2 {
            b.push(
                Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::R10W).unwrap(),
            );
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
            b.push(
                Instruction::with2(Code::Movd_xmm_rm32, Register::XMM0, Register::R10D).unwrap(),
            );
            b.push(
                Instruction::with2(Code::Movd_xmm_rm32, Register::XMM1, Register::R11D).unwrap(),
            );
            b.push(Instruction::with2(op32, Register::XMM0, Register::XMM1).unwrap());
            b.push(
                Instruction::with2(Code::Movd_rm32_xmm, Register::R10D, Register::XMM0).unwrap(),
            );
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
                    if use_32 {
                        Code::Cvtsi2sd_xmm_rm32
                    } else {
                        Code::Cvtsi2sd_xmm_rm64
                    }
                } else {
                    load_code
                };
                let src_reg = if use_32 {
                    Register::R10D
                } else {
                    Register::R10
                };
                b.push(Instruction::with2(load_code, Register::XMM0, src_reg).unwrap());
                if dst_bits == 4 {
                    b.push(
                        Instruction::with2(Code::Movd_rm32_xmm, Register::R10D, Register::XMM0)
                            .unwrap(),
                    );
                } else {
                    b.push(
                        Instruction::with2(Code::Movq_rm64_xmm, Register::R10, Register::XMM0)
                            .unwrap(),
                    );
                }
            }
            // FloatToInt: src 는 float bits, dst 는 정수 (indefinite 포함).
            FloatCvtMode::FloatToInt => {
                if src_bits == 4 {
                    b.push(
                        Instruction::with2(Code::Movd_xmm_rm32, Register::XMM0, Register::R10D)
                            .unwrap(),
                    );
                } else {
                    b.push(
                        Instruction::with2(Code::Movq_xmm_rm64, Register::XMM0, Register::R10)
                            .unwrap(),
                    );
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
                    b.push(
                        Instruction::with2(Code::Movd_xmm_rm32, Register::XMM0, Register::R10D)
                            .unwrap(),
                    );
                    b.push(
                        Instruction::with2(
                            Code::Cvtss2sd_xmm_xmmm32,
                            Register::XMM0,
                            Register::XMM0,
                        )
                        .unwrap(),
                    );
                    b.push(
                        Instruction::with2(Code::Movq_rm64_xmm, Register::R10, Register::XMM0)
                            .unwrap(),
                    );
                } else {
                    b.push(
                        Instruction::with2(Code::Movq_xmm_rm64, Register::XMM0, Register::R10)
                            .unwrap(),
                    );
                    b.push(
                        Instruction::with2(
                            Code::Cvtsd2ss_xmm_xmmm64,
                            Register::XMM0,
                            Register::XMM0,
                        )
                        .unwrap(),
                    );
                    b.push(
                        Instruction::with2(Code::Movd_rm32_xmm, Register::R10D, Register::XMM0)
                            .unwrap(),
                    );
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
            b.push(
                Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).unwrap(),
            );
        };
        let sete = |b: &mut CodeBuilder| {
            b.push(Instruction::with1(Code::Sete_rm8, Register::R10L).unwrap());
            b.push(
                Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).unwrap(),
            );
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
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R11).unwrap(),
                );
                b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RCX, 6).unwrap());
                b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 1).unwrap());
                b.push(Instruction::with2(Code::Xor_rm64_imm32, Register::RCX, 1).unwrap()); // nz = !ZF
                b.push(
                    Instruction::with2(Code::And_rm64_r64, Register::RAX, Register::RCX).unwrap(),
                );
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap(),
                );
            }
            COND_LESS => {
                // L = SF!=OF = delta
                emit_delta(b);
                b.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
                );
                setne(b);
            }
            COND_GREATER_OR_EQUAL => {
                // GE = SF==OF = !delta
                emit_delta(b);
                b.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
                );
                sete(b);
            }
            COND_LESS_OR_EQUAL => {
                // LE = ZF || (SF!=OF) = z | delta
                emit_delta(b);
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R11).unwrap(),
                );
                b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RCX, 6).unwrap());
                b.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 1).unwrap());
                b.push(
                    Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap(),
                );
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap(),
                );
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
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R9).unwrap(),
                );
                b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RAX, 48).unwrap());
                b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 48).unwrap());
                b.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
                );
                sete(b);
            }
            COND_COUNTER_ZERO_4 => {
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R9).unwrap(),
                );
                b.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RAX, 32).unwrap());
                b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 32).unwrap());
                b.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
                );
                sete(b);
            }
            COND_COUNTER_ZERO_8 => {
                b.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9).unwrap(),
                );
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
                COND_ALWAYS,
                COND_ZERO,
                COND_NOT_ZERO,
                COND_CARRY,
                COND_NOT_CARRY,
                COND_SIGN,
                COND_NOT_SIGN,
                COND_OVERFLOW,
                COND_NOT_OVERFLOW,
                COND_GREATER,
                COND_LESS,
                COND_GREATER_OR_EQUAL,
                COND_LESS_OR_EQUAL,
                COND_ABOVE,
                COND_ABOVE_OR_EQUAL,
                COND_BELOW,
                COND_BELOW_OR_EQUAL,
                COND_PARITY,
                COND_NOT_PARITY,
                COND_COUNTER_ZERO_2,
                COND_COUNTER_ZERO_4,
                COND_COUNTER_ZERO_8,
            ];
            let mut je_bi: Vec<(u8, usize)> = Vec::with_capacity(conds.len());
            for c in conds {
                b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, c as i32).unwrap());
                je_bi.push((c, b.br(Code::Je_rel32_64, 0)));
            }
            // continuation (unknown cond falls through here with R10 = 0).
            let cont = b.len();
            if is_cmov {
                b.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap(),
                );
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
                b.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).unwrap(),
                );
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
            emit_mul_handler(
                &mut b,
                sub_dec_ops,
                sub_resolve,
                sub_store,
                *signed,
                *w,
                true,
                dispatch,
            );
        }
    }
    let mut mullow_h: [[usize; 3]; 2] = [[0; 3]; 2];
    for (si, signed) in [false, true].iter().enumerate() {
        for (wi, w) in [2u8, 4, 8].iter().enumerate() {
            mullow_h[si][wi] = b.len();
            emit_mul_handler(
                &mut b,
                sub_dec_ops,
                sub_resolve,
                sub_store,
                *signed,
                *w,
                false,
                dispatch,
            );
        }
    }
    let mut div_h: [[usize; 4]; 2] = [[0; 4]; 2];
    for (si, signed) in [false, true].iter().enumerate() {
        for (wi, w) in [1u8, 2, 4, 8].iter().enumerate() {
            div_h[si][wi] = b.len();
            emit_div_handler(
                &mut b,
                sub_dec_ops,
                sub_resolve,
                sub_store,
                *signed,
                *w,
                dispatch,
            );
        }
    }

    // P1: packed SSE handlers. Keep the exact RiscOp beside its offset so the
    // randomized ISA and handler table are populated from one canonical list.
    let packed_ops = [
        RiscOp::PackedMove,
        RiscOp::PackedAdd {
            elem_width: 1,
            lanes: 16,
        },
        RiscOp::PackedAdd {
            elem_width: 2,
            lanes: 8,
        },
        RiscOp::PackedAdd {
            elem_width: 4,
            lanes: 4,
        },
        RiscOp::PackedAdd {
            elem_width: 8,
            lanes: 2,
        },
        RiscOp::PackedSub {
            elem_width: 1,
            lanes: 16,
        },
        RiscOp::PackedSub {
            elem_width: 2,
            lanes: 8,
        },
        RiscOp::PackedSub {
            elem_width: 4,
            lanes: 4,
        },
        RiscOp::PackedSub {
            elem_width: 8,
            lanes: 2,
        },
        RiscOp::PackedXor,
        RiscOp::PackedAnd,
        RiscOp::PackedOr,
        RiscOp::PackedAndNot,
        RiscOp::PackedCmpEq {
            elem_width: 1,
            lanes: 16,
        },
        RiscOp::PackedCmpEq {
            elem_width: 2,
            lanes: 8,
        },
        RiscOp::PackedCmpEq {
            elem_width: 4,
            lanes: 4,
        },
        RiscOp::PackedCmpEq {
            elem_width: 8,
            lanes: 2,
        },
        RiscOp::PackedCmpGt {
            elem_width: 1,
            lanes: 16,
        },
        RiscOp::PackedCmpGt {
            elem_width: 2,
            lanes: 8,
        },
        RiscOp::PackedCmpGt {
            elem_width: 4,
            lanes: 4,
        },
        RiscOp::PackedCmpGt {
            elem_width: 8,
            lanes: 2,
        },
        RiscOp::PackedUnpack {
            elem_width: 1,
            high: false,
        },
        RiscOp::PackedUnpack {
            elem_width: 2,
            high: false,
        },
        RiscOp::PackedUnpack {
            elem_width: 4,
            high: false,
        },
        RiscOp::PackedUnpack {
            elem_width: 8,
            high: false,
        },
        RiscOp::PackedUnpack {
            elem_width: 1,
            high: true,
        },
        RiscOp::PackedUnpack {
            elem_width: 2,
            high: true,
        },
        RiscOp::PackedUnpack {
            elem_width: 4,
            high: true,
        },
        RiscOp::PackedUnpack {
            elem_width: 8,
            high: true,
        },
    ];
    let mut packed_h = Vec::with_capacity(packed_ops.len());
    for op in packed_ops {
        let off = b.len();
        emit_packed_handler(&mut b, sub_dec_ops, sub_resolve, dispatch, op);
        packed_h.push((op, off));
    }
    let packed_shr_q_h = b.len();
    emit_packed_shift_right_q_handler(&mut b, sub_dec_ops, sub_resolve, dispatch);
    let packed_shufd_h = b.len();
    emit_packed_shuffle_handler(&mut b, sub_dec_ops, sub_resolve, dispatch, false);
    let packed_shuflw_h = b.len();
    emit_packed_shuffle_handler(&mut b, sub_dec_ops, sub_resolve, dispatch, true);
    let mut shld_h = [0usize; 3];
    for (i, width) in [2u8, 4, 8].iter().enumerate() {
        shld_h[i] = b.len();
        emit_shld_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            *width,
        );
    }
    let mut bit_test_h: HashMap<RiscOp, usize> = HashMap::new();
    for width in [4u8, 8] {
        for modify in [0u8, 1, 2] {
            for memory in [false, true] {
                let op = RiscOp::BitTest {
                    width,
                    modify,
                    memory,
                };
                let off = b.len();
                emit_bit_test_handler(
                    &mut b,
                    sub_dec_ops,
                    sub_resolve,
                    sub_store,
                    dispatch,
                    width,
                    modify,
                    memory,
                );
                bit_test_h.insert(op, off);
            }
        }
    }
    let movmask_bytes_h = b.len();
    emit_movmask_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, false);
    let movmask_ps_h = b.len();
    emit_movmask_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, true);
    let insert_word_h = b.len();
    emit_insert_word_handler(&mut b, sub_dec_ops, sub_resolve, dispatch);
    let cpuid_h = b.len();
    {
        b.call(sub_dec_ops);
        mov_m(&mut b, Register::RAX, REGS_OFF);
        mov_m(&mut b, Register::RCX, REGS_OFF + 8);
        b.push(Instruction::with1(Code::Push_r64, Register::RDX).unwrap());
        b.push(Instruction::with(Code::Cpuid));
        b.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
        b.push(Instruction::with1(Code::Push_r64, Register::RBX).unwrap());
        b.push(Instruction::with1(Code::Push_r64, Register::RCX).unwrap());
        b.push(Instruction::with1(Code::Push_r64, Register::RDX).unwrap());
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R10,
                MemoryOperand::with_base_displ(Register::RSP, 32),
            )
            .unwrap(),
        );
        for (off, disp) in [(0i64, 24i64), (8, 8), (16, 0), (24, 16)] {
            b.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RAX,
                    MemoryOperand::with_base_displ(Register::RSP, disp),
                )
                .unwrap(),
            );
            b.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ(
                        Register::R10,
                        state_disp(REGS_OFF + off as i32) as i64,
                    ),
                    Register::RAX,
                )
                .unwrap(),
            );
        }
        b.push(Instruction::with2(Code::Add_rm64_imm8, Register::RSP, 40).unwrap());
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R10).unwrap());
        b.jmp(dispatch);
    }
    let xgetbv_h = b.len();
    {
        b.call(sub_dec_ops);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RDX).unwrap());
        mov_m(&mut b, Register::RCX, REGS_OFF + 8);
        b.push(Instruction::with(Code::Xgetbv));
        b.push(
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ(Register::R10, state_disp(REGS_OFF) as i64),
                Register::RAX,
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ(Register::R10, state_disp(REGS_OFF + 16) as i64),
                Register::RDX,
            )
            .unwrap(),
        );
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R10).unwrap());
        b.jmp(dispatch);
    }
    let mut segment_base_h = [0usize; 2];
    for (idx, (seg, off)) in [(Register::FS, 0x18i64), (Register::GS, 0x30i64)]
        .iter()
        .enumerate()
    {
        segment_base_h[idx] = b.len();
        b.call(sub_dec_ops);
        let mem = MemoryOperand::with_displ(*off as u64, 4);
        let mut load = Instruction::with2(Code::Mov_r64_rm64, Register::RAX, mem).unwrap();
        load.set_segment_prefix(*seg);
        b.push(load);
        b.call(sub_store);
        b.jmp(dispatch);
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
    let mut adcw_h = [0usize; 4];
    let mut sbbw_h = [0usize; 4];
    let mut incw_h = [0usize; 4];
    let mut decw_h = [0usize; 4];
    let mut notw_h = [0usize; 4];
    let mut rolw_h = [0usize; 4];
    for (wi, w) in [1u8, 2, 4, 8].iter().enumerate() {
        addw_h[wi] = b.len();
        emit_width_alu_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            WidthAluOp::Add,
            *w,
            Some(crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
                seed,
                spec.opcode_for(RiscOp::Add { width: *w })
                    .unwrap_or_default(),
            )),
        );
        subw_h[wi] = b.len();
        emit_width_alu_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            WidthAluOp::Sub,
            *w,
            Some(crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
                seed,
                spec.opcode_for(RiscOp::SubWithBorrow { width: *w })
                    .unwrap_or_default(),
            )),
        );
        adcw_h[wi] = b.len();
        emit_width_alu_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            WidthAluOp::Adc,
            *w,
            Some(crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
                seed,
                spec.opcode_for(RiscOp::Adc { width: *w })
                    .unwrap_or_default(),
            )),
        );
        sbbw_h[wi] = b.len();
        emit_width_alu_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            WidthAluOp::Sbb,
            *w,
            Some(crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
                seed,
                spec.opcode_for(RiscOp::Sbb { width: *w })
                    .unwrap_or_default(),
            )),
        );
        incw_h[wi] = b.len();
        emit_width_alu_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            WidthAluOp::Inc,
            *w,
            Some(crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
                seed,
                spec.opcode_for(RiscOp::Inc { width: *w })
                    .unwrap_or_default(),
            )),
        );
        decw_h[wi] = b.len();
        emit_width_alu_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            WidthAluOp::Dec,
            *w,
            Some(crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
                seed,
                spec.opcode_for(RiscOp::Dec { width: *w })
                    .unwrap_or_default(),
            )),
        );
        notw_h[wi] = b.len();
        emit_width_alu_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            WidthAluOp::Not,
            *w,
            Some(crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(
                seed,
                spec.opcode_for(RiscOp::Not { width: *w })
                    .unwrap_or_default(),
            )),
        );
        rolw_h[wi] = b.len();
        emit_rotate_left_handler(&mut b, sub_dec_ops, sub_resolve, sub_store, dispatch, *w);
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
        emit_float_bin_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            *w,
            Code::Addss_xmm_xmmm32,
            Code::Addsd_xmm_xmmm64,
        );
        fsub_h[wi] = b.len();
        emit_float_bin_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            *w,
            Code::Subss_xmm_xmmm32,
            Code::Subsd_xmm_xmmm64,
        );
        fmul_h[wi] = b.len();
        emit_float_bin_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            *w,
            Code::Mulss_xmm_xmmm32,
            Code::Mulsd_xmm_xmmm64,
        );
        fdiv_h[wi] = b.len();
        emit_float_bin_handler(
            &mut b,
            sub_dec_ops,
            sub_resolve,
            sub_store,
            dispatch,
            *w,
            Code::Divss_xmm_xmmm32,
            Code::Divsd_xmm_xmmm64,
        );
    }
    let mut fi2f_h = [[0usize; 2]; 2]; // [src_bits_idx][dst_bits_idx]
    let mut ff2i_h = [[[0usize; 2]; 2]; 2]; // [src][dst][truncate]
    let mut ff2f_h = [[0usize; 2]; 2];
    for (si, sb) in [4u8, 8].iter().enumerate() {
        for (di, db) in [4u8, 8].iter().enumerate() {
            fi2f_h[si][di] = b.len();
            emit_float_cvt_handler(
                &mut b,
                sub_dec_ops,
                sub_resolve,
                sub_store,
                dispatch,
                *sb,
                *db,
                false,
                FloatCvtMode::IntToFloat,
            );
            ff2f_h[si][di] = b.len();
            emit_float_cvt_handler(
                &mut b,
                sub_dec_ops,
                sub_resolve,
                sub_store,
                dispatch,
                *sb,
                *db,
                false,
                FloatCvtMode::FloatToFloat,
            );
            for (ti, tr) in [false, true].iter().enumerate() {
                ff2i_h[si][di][ti] = b.len();
                emit_float_cvt_handler(
                    &mut b,
                    sub_dec_ops,
                    sub_resolve,
                    sub_store,
                    dispatch,
                    *sb,
                    *db,
                    *tr,
                    FloatCvtMode::FloatToInt,
                );
            }
        }
    }

    // ── P2-14: shared data-lifetime scope synchronization. ──
    // Every family state stores the same entry-family sync-table pointer at
    // +0x5010. src1 is a deterministic 8-byte entry index. These handlers do
    // not publish host flags into virtual FLAGS and do not touch virtual GPRs.
    let h_lifetime_acquire = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).unwrap());
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R10,
                MemoryOperand::with_base_displ_size(
                    Register::RDX,
                    crate::vm::data_lifetime::LIFETIME_SYNC_PTR_STATE_OFFSET as i64,
                    8,
                ),
            )
            .unwrap(),
        );
        b.push(
            Instruction::with3(
                Code::Imul_r64_rm64_imm32,
                Register::RCX,
                Register::RCX,
                crate::vm::data_lifetime::LIFETIME_SYNC_ENTRY_SIZE as i32,
            )
            .unwrap(),
        );
        b.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::RCX).unwrap());
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R9,
                MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x48, false, Register::GS),
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Cmp_rm64_r64,
                MemoryOperand::with_base_displ(Register::R10, 8),
                Register::R9,
            )
            .unwrap(),
        );
        let reentrant_edge = b.br(Code::Je_rel32_64, usize::MAX);
        let spin = b.len();
        b.push(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::EAX).unwrap());
        b.push(Instruction::with2(Code::Mov_r32_imm32, Register::R11D, 1).unwrap());
        let mut cas = Instruction::with2(
            Code::Cmpxchg_rm32_r32,
            MemoryOperand::with_base(Register::R10),
            Register::R11D,
        )
        .unwrap();
        cas.set_has_lock_prefix(true);
        b.push(cas);
        b.br(Code::Jne_rel32_64, spin);
        b.push(
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ(Register::R10, 8),
                Register::R9,
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Mov_rm32_imm32,
                MemoryOperand::with_base_displ(Register::R10, 4),
                1,
            )
            .unwrap(),
        );
        b.jmp(dispatch);
        let reentrant = b.len();
        let mut inc = Instruction::with1(
            Code::Inc_rm32,
            MemoryOperand::with_base_displ(Register::R10, 4),
        )
        .unwrap();
        inc.set_has_lock_prefix(true);
        b.push(inc);
        b.jmp(dispatch);
        for (branch, target) in &mut b.branches {
            if *branch == reentrant_edge {
                *target = reentrant;
            }
        }
    }
    let h_lifetime_release = b.len();
    {
        b.call(sub_dec_ops);
        movzx8_m(&mut b, Register::EAX, DEC_SRC1);
        mov_m(&mut b, Register::R11, DEC_IMM1);
        b.call(sub_resolve);
        b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).unwrap());
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R10,
                MemoryOperand::with_base_displ_size(
                    Register::RDX,
                    crate::vm::data_lifetime::LIFETIME_SYNC_PTR_STATE_OFFSET as i64,
                    8,
                ),
            )
            .unwrap(),
        );
        b.push(
            Instruction::with3(
                Code::Imul_r64_rm64_imm32,
                Register::RCX,
                Register::RCX,
                crate::vm::data_lifetime::LIFETIME_SYNC_ENTRY_SIZE as i32,
            )
            .unwrap(),
        );
        b.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::RCX).unwrap());
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R9,
                MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x48, false, Register::GS),
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Cmp_rm64_r64,
                MemoryOperand::with_base_displ(Register::R10, 8),
                Register::R9,
            )
            .unwrap(),
        );
        b.br(Code::Jne_rel32_64, h_trap);
        b.push(
            Instruction::with2(
                Code::Cmp_rm32_imm32,
                MemoryOperand::with_base_displ(Register::R10, 4),
                0,
            )
            .unwrap(),
        );
        b.br(Code::Je_rel32_64, h_trap);
        let mut dec = Instruction::with1(
            Code::Dec_rm32,
            MemoryOperand::with_base_displ(Register::R10, 4),
        )
        .unwrap();
        dec.set_has_lock_prefix(true);
        b.push(dec);
        b.br(Code::Jne_rel32_64, dispatch);
        b.push(
            Instruction::with2(
                Code::Mov_rm64_imm32,
                MemoryOperand::with_base_displ(Register::R10, 8),
                0,
            )
            .unwrap(),
        );
        b.push(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::EAX).unwrap());
        b.push(
            Instruction::with2(
                Code::Xchg_rm32_r32,
                MemoryOperand::with_base(Register::R10),
                Register::EAX,
            )
            .unwrap(),
        );
        b.jmp(dispatch);
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
            let mut ci =
                Instruction::with2(cmp_code, MemoryOperand::with_base(Register::R10), regx)
                    .unwrap();
            ci.set_has_lock_prefix(true);
            b.push(ci);
            // P1-6: CMPXCHG 는 ZF 뿐 아니라 CMP(acc - old) 의 전체 상태 플래그를 set
            // 한다. 하드웨어 cmpxchg 의 폭별 CMP 플래그를 보존하되, cmove 는 cmpxchg
            // 의 ZF 를 읽으므로 **먼저** 성공/실패 복원을 수행한 뒤 (cmov 는 flags
            // 불변) pushfq 로 상태 플래그를 캡처한다. DF 는 slot 에서 보존
            // (참조 update_sub 와 동일).
            // success -> restore original regs[0]; failure -> regs[0]=old (RAX).
            b.push(Instruction::with2(Code::Cmove_r64_rm64, Register::RAX, Register::RBX).unwrap());
            store_m(&mut b, REGS_OFF, Register::RAX);
            // capture the full CMP status flags (0x8D5) — cmov 는 flags 를 바꾸지 않는다.
            b.push(Instruction::with(Code::Pushfq));
            b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x8D5).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
            b.push(
                Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x8D5i64) as i32)
                    .unwrap(),
            );
            b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
            store_m(&mut b, FLAGS_OFF, Register::RAX);
            b.jmp(dispatch);
        }
        h_cmpxchg.insert(w, h);
    }

    // ── P0-4: ATOMIC_EXCHANGE — x86 `XCHG r, [mem]` (memory 피연산자에서 암시적
    // LOCK). old = [addr]; [addr] = dst; dst = old. 플래그 불변 (x86 XCHG).
    // 하드웨어 `xchg` 는 자체로 원자적이라 RMW 중간 상태가 노출되지 않는다.
    let mut h_xchg = std::collections::HashMap::new();
    for (w, xchg_code, regx, zext) in [
        (8u8, Code::Xchg_rm64_r64, Register::R11, None),
        (4u8, Code::Xchg_rm32_r32, Register::R11D, None),
        (
            2u8,
            Code::Xchg_rm16_r16,
            Register::R11W,
            Some(Code::Movzx_r64_rm16),
        ),
        (
            1u8,
            Code::Xchg_rm8_r8,
            Register::R11L,
            Some(Code::Movzx_r64_rm8),
        ),
    ] {
        let h = b.len();
        {
            b.call(sub_dec_ops);
            // addr = resolve(src1) -> R10
            movzx8_m(&mut b, Register::EAX, DEC_SRC1);
            mov_m(&mut b, Register::R11, DEC_IMM1);
            b.call(sub_resolve);
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
            // reg = resolve(DEC_DST) -> R11 (XCHG의 레지스터 피연산자)
            movzx8_m(&mut b, Register::EAX, DEC_DST);
            mov_m(&mut b, Register::R11, DEC_IMM1);
            b.call(sub_resolve);
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
            // atomic xchg [r10], r11 — R11 = old [r10], [r10] = old R11.
            b.push(
                Instruction::with2(xchg_code, MemoryOperand::with_base(Register::R10), regx)
                    .unwrap(),
            );
            // 폭별 zero-extend (하드웨어는 상위 비트를 보존하므로 vreg 모델 정합).
            if let Some(zc) = zext {
                b.push(Instruction::with2(zc, Register::R11, regx).unwrap());
            }
            // store R11 (old memory value) -> dst.
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap());
            b.call(sub_store);
            b.jmp(dispatch);
        }
        h_xchg.insert(w, h);
    }

    // ── P0-4: ATOMIC_ADD — x86 `LOCK XADD [mem], reg`. old = [addr];
    // [addr] += src2 (폭별 플래그 — 하드웨어 xadd 는 폭 경계 CF/OF/AF 를 set),
    // dst = old. `lock` 접두사로 원자 RMW 보장.
    let mut h_xadd = std::collections::HashMap::new();
    for (w, xadd_code, regx, zext) in [
        (8u8, Code::Xadd_rm64_r64, Register::R11, None),
        (4u8, Code::Xadd_rm32_r32, Register::R11D, None),
        (
            2u8,
            Code::Xadd_rm16_r16,
            Register::R11W,
            Some(Code::Movzx_r64_rm16),
        ),
        (
            1u8,
            Code::Xadd_rm8_r8,
            Register::R11L,
            Some(Code::Movzx_r64_rm8),
        ),
    ] {
        let h = b.len();
        {
            b.call(sub_dec_ops);
            // addr = resolve(src1) -> R10
            movzx8_m(&mut b, Register::EAX, DEC_SRC1);
            mov_m(&mut b, Register::R11, DEC_IMM1);
            b.call(sub_resolve);
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).unwrap());
            // addend = resolve(src2) -> R11
            movzx8_m(&mut b, Register::EAX, DEC_SRC2);
            mov_m(&mut b, Register::R11, DEC_IMM2);
            b.call(sub_resolve);
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX).unwrap());
            // lock xadd [r10], r11 — R11 = old [r10]; [r10] += old addend.
            let mut xi =
                Instruction::with2(xadd_code, MemoryOperand::with_base(Register::R10), regx)
                    .unwrap();
            xi.set_has_lock_prefix(true);
            b.push(xi);
            // flags: 참조 `update_add(old, addend, width)` 는 폭별 CF/OF/AF/SF/ZF/PF
            // 를 set 하고 DF 를 보존한다. 하드웨어 xadd 의 폭별 플래그를 **xadd 직후**
            // 0x8D5 로 캡처하고 비-status(DF)만 slot 에서 유지한다. 반드시 sub_store
            // (내부 `test` 로 flags 를 오염) **이전에** 저장해야 한다.
            b.push(Instruction::with(Code::Pushfq));
            b.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
            b.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x8D5).unwrap());
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(FLAGS_OFF)).unwrap());
            b.push(
                Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x8D5i64) as i32)
                    .unwrap(),
            );
            b.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).unwrap());
            store_m(&mut b, FLAGS_OFF, Register::RAX);
            // 폭별 zero-extend (R11 = old 값, 상위 비트 정화) 후 dst 저장.
            if let Some(zc) = zext {
                b.push(Instruction::with2(zc, Register::R11, regx).unwrap());
            }
            // store R11 (old [addr]) -> dst.
            b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap());
            b.call(sub_store);
            b.jmp(dispatch);
        }
        h_xadd.insert(w, h);
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
    let h_setcc = emit_setcc_cmov_handler(
        &mut b,
        sub_dec_ops_cond,
        sub_dec_ops,
        sub_resolve,
        sub_store,
        dispatch,
        false,
    );
    let h_cmov = emit_setcc_cmov_handler(
        &mut b,
        sub_dec_ops_cond,
        sub_dec_ops,
        sub_resolve,
        sub_store,
        dispatch,
        true,
    );

    let mut handlers: std::collections::HashMap<RiscOp, usize> = {
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
        for w in [0u8, 4, 8] {
            h.insert(
                RiscOp::SetNativeFpReturn { width: w },
                h_set_fp_ret[&RiscOp::SetNativeFpReturn { width: w }],
            );
        }
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
        h.insert(RiscOp::LifetimeAcquire, h_lifetime_acquire);
        h.insert(RiscOp::LifetimeRelease, h_lifetime_release);
        for w in [1u8, 2, 4, 8] {
            h.insert(RiscOp::AtomicExchange { width: w }, h_xchg[&w]);
            h.insert(RiscOp::AtomicAdd { width: w }, h_xadd[&w]);
        }
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
        h.insert(
            RiscOp::Setcc {
                cond: BranchCondition::Always,
            },
            h_setcc,
        );
        h.insert(
            RiscOp::ConditionalMove {
                cond: BranchCondition::Always,
            },
            h_cmov,
        );
        h.insert(
            RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            },
            h_branch,
        );
        h.insert(RiscOp::VirtualIndirectCall, h_indirect_call);
        h.insert(RiscOp::VirtualIndirectJump, h_indirect_jump);
        h.insert(RiscOp::VirtualRet, h_ret);
        for (si, signed) in [false, true].iter().enumerate() {
            for (wi, w) in [1u8, 2, 4, 8].iter().enumerate() {
                h.insert(
                    RiscOp::Multiply {
                        signed: *signed,
                        width: *w,
                    },
                    mul_h[si][wi],
                );
            }
        }
        for (si, signed) in [false, true].iter().enumerate() {
            for (wi, w) in [2u8, 4, 8].iter().enumerate() {
                h.insert(
                    RiscOp::MultiplyLow {
                        signed: *signed,
                        width: *w,
                    },
                    mullow_h[si][wi],
                );
            }
        }
        for (si, signed) in [false, true].iter().enumerate() {
            for (wi, w) in [1u8, 2, 4, 8].iter().enumerate() {
                h.insert(
                    RiscOp::Divide {
                        signed: *signed,
                        width: *w,
                    },
                    div_h[si][wi],
                );
            }
        }
        // P2 (G3): width-aware ALU — Add/SubWithBorrow/Inc/Dec/Not {width} 핸들러.
        for (wi, w) in [1u8, 2, 4, 8].iter().enumerate() {
            h.insert(RiscOp::Add { width: *w }, addw_h[wi]);
            h.insert(RiscOp::SubWithBorrow { width: *w }, subw_h[wi]);
            h.insert(RiscOp::Adc { width: *w }, adcw_h[wi]);
            h.insert(RiscOp::Sbb { width: *w }, sbbw_h[wi]);
            h.insert(RiscOp::Inc { width: *w }, incw_h[wi]);
            h.insert(RiscOp::Dec { width: *w }, decw_h[wi]);
            h.insert(RiscOp::Not { width: *w }, notw_h[wi]);
            h.insert(RiscOp::RotateLeft { width: *w }, rolw_h[wi]);
        }
        for &(op, off) in &packed_h {
            h.insert(op, off);
        }
        h.insert(RiscOp::PackedShiftRightQ, packed_shr_q_h);
        h.insert(RiscOp::PackedShuffle { low_words: false }, packed_shufd_h);
        h.insert(RiscOp::PackedShuffle { low_words: true }, packed_shuflw_h);
        for (i, width) in [2u8, 4, 8].iter().enumerate() {
            h.insert(RiscOp::DoubleShiftLeft { width: *width }, shld_h[i]);
        }
        for (&op, &off) in &bit_test_h {
            h.insert(op, off);
        }
        h.insert(RiscOp::PackedMovMaskBytes, movmask_bytes_h);
        h.insert(RiscOp::PackedMovMaskPs, movmask_ps_h);
        h.insert(RiscOp::PackedInsertWord, insert_word_h);
        h.insert(RiscOp::CpuId, cpuid_h);
        h.insert(RiscOp::XGetBv, xgetbv_h);
        h.insert(RiscOp::ReadSegmentBase { gs: false }, segment_base_h[0]);
        h.insert(RiscOp::ReadSegmentBase { gs: true }, segment_base_h[1]);
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
                h.insert(
                    RiscOp::IntToFloat {
                        src_bits: *sb,
                        dst_bits: *db,
                    },
                    fi2f_h[si][di],
                );
                h.insert(
                    RiscOp::FloatToFloat {
                        src_bits: *sb,
                        dst_bits: *db,
                    },
                    ff2f_h[si][di],
                );
                for (ti, tr) in [false, true].iter().enumerate() {
                    h.insert(
                        RiscOp::FloatToInt {
                            src_bits: *sb,
                            dst_bits: *db,
                            truncate: *tr,
                        },
                        ff2i_h[si][di][ti],
                    );
                }
            }
        }
        h.insert(RiscOp::Halt, h_halt);
        h.insert(RiscOp::Trap, h_trap);
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
            unhandled.sort();
            return Err(anyhow!(
                "[P2-HANDLER-GAP] {} encodable op(s) have no native handler: {}",
                unhandled.len(),
                unhandled.join(", ")
            ));
        }
    }

    // P5: compose build-local extension handlers from the verified primitive
    // bodies. Handler boundaries are frozen before cloning; every copied exit
    // to dispatch is retargeted to the next body by CodeBuilder.
    let mut extension_handlers: HashMap<u8, usize> = HashMap::new();
    if !superops.is_empty() {
        let canonical = |op: RiscOp| match op {
            RiscOp::VirtualBranch { .. } => RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            },
            RiscOp::Setcc { .. } => RiscOp::Setcc {
                cond: BranchCondition::Always,
            },
            RiscOp::ConditionalMove { .. } => RiscOp::ConditionalMove {
                cond: BranchCondition::Always,
            },
            other => other,
        };
        let original_end = b.len();
        let mut starts: Vec<usize> = handlers.values().copied().collect();
        starts.sort_unstable();
        starts.dedup();
        let mut ends = HashMap::new();
        for (i, &start) in starts.iter().enumerate() {
            ends.insert(start, starts.get(i + 1).copied().unwrap_or(original_end));
        }

        for assigned in superops {
            if spec.reverse_opcode_map.contains_key(&assigned.opcode)
                || extension_handlers.contains_key(&assigned.opcode)
            {
                return Err(anyhow!(
                    "P5 extension opcode {:#04x} collides or is duplicated",
                    assigned.opcode
                ));
            }
            let mut ranges = Vec::with_capacity(assigned.plan.candidate.ops.len());
            for op in assigned.plan.candidate.ops.iter().copied() {
                let op = canonical(op);
                let &start = handlers.get(&op).ok_or_else(|| {
                    anyhow!("P5 super-op primitive {:?} has no production handler", op)
                })?;
                let &end = ends
                    .get(&start)
                    .ok_or_else(|| anyhow!("P5 cannot determine handler boundary for {:?}", op))?;
                ranges.push((start, end));
            }
            let body_entry = b.clone_handler_chain(&ranges, dispatch)?;
            let entry = b.len();
            let (tag, descriptor_mask) = PolymorphicEncoder::superop_grammar(seed, assigned.opcode);
            b.call(sub_decrypt);
            b.push(Instruction::with2(Code::Cmp_rm8_imm8, Register::AL, tag as i32).unwrap());
            let valid_edge = b.br(Code::Je_rel32_64, usize::MAX);
            b.push(Instruction::with(Code::Ud2));
            let valid = b.len();
            b.push(
                Instruction::with2(
                    Code::Mov_rm8_imm8,
                    MemoryOperand::with_base_displ(Register::RDX, STATE_SUPEROP_DESCRIPTOR_MASK),
                    descriptor_mask as i32,
                )
                .unwrap(),
            );
            b.jmp(body_entry);
            for (branch, target) in &mut b.branches {
                if *branch == valid_edge {
                    *target = valid;
                }
            }
            extension_handlers.insert(assigned.opcode, entry);
        }
    }

    // P2 handler synthesis production widening: every canonical ISA table
    // entry receives a seed/opcode-derived reachable wrapper CFG. Primitive
    // bodies remain frozen for super-op cloning above; only final table targets
    // are replaced, so semantic behavior and primitive boundaries are unchanged.
    let mut canonical_wrappers: Vec<(u8, RiscOp, usize)> = spec
        .opcode_map
        .iter()
        .filter_map(|(op, byte)| handlers.get(op).copied().map(|body| (*byte, *op, body)))
        .collect();
    canonical_wrappers.sort_by_key(|(byte, _, _)| *byte);
    for (byte, op, body) in canonical_wrappers {
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(seed, byte);
        let wrapper = b.len();
        let nop_count = 1
            + ((plan.context_key ^ plan.dead_state_slots as u64 ^ plan.control_splits as u64) & 3)
                as usize;
        for _ in 0..nop_count {
            b.push(Instruction::with(Code::Nopd));
        }
        b.jmp(body);
        handlers.insert(op, wrapper);
    }

    let mut extension_wrapper_inputs: Vec<_> = extension_handlers
        .iter()
        .map(|(op, body)| (*op, *body))
        .collect();
    extension_wrapper_inputs.sort_by_key(|(op, _)| *op);
    for (opcode, body) in extension_wrapper_inputs {
        let plan = crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(seed, opcode);
        let wrapper = b.len();
        let nop_count = 1
            + ((plan.context_key ^ plan.dead_state_slots as u64 ^ plan.control_splits as u64) & 3)
                as usize;
        for _ in 0..nop_count {
            b.push(Instruction::with(Code::Nopd));
        }
        b.jmp(body);
        extension_handlers.insert(opcode, wrapper);
    }

    // P2-14 call-scoped lifetime unwind cleanup. Windows invokes this as the
    // UNW_FLAG_UHANDLER language-specific handler for each native-call bridge
    // frame during phase-2 unwind. It is deliberately self-contained: no call,
    // allocation, VM dispatcher state, or potentially unwound callee is used.
    // Every entry owned by the current TEB thread is re-encrypted exactly once,
    // then depth/owner/lock are cleared before unwind continues.
    let lifetime_cleanup_handler = b.len();
    for reg in [
        Register::RBX,
        Register::RBP,
        Register::RSI,
        Register::RDI,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ] {
        b.push(Instruction::with1(Code::Push_r64, reg).unwrap());
    }
    rip_anchor(
        &mut b,
        Register::R12,
        state_base + crate::vm::data_lifetime::LIFETIME_SYNC_PTR_STATE_OFFSET as u64,
    );
    b.push(
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::R13,
            MemoryOperand::with_base_displ_size(Register::R12, 8, 8),
        )
        .unwrap(),
    );
    b.push(
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::R12,
            MemoryOperand::with_base(Register::R12),
        )
        .unwrap(),
    );
    b.push(
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::R14,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x48, false, Register::GS),
        )
        .unwrap(),
    );
    let cleanup_entry_loop = b.len();
    b.push(Instruction::with2(Code::Test_rm64_r64, Register::R13, Register::R13).unwrap());
    let cleanup_done_edge = b.br(Code::Je_rel32_64, usize::MAX);
    b.push(
        Instruction::with2(
            Code::Cmp_rm64_r64,
            MemoryOperand::with_base_displ(Register::R12, 8),
            Register::R14,
        )
        .unwrap(),
    );
    let cleanup_next_owner_edge = b.br(Code::Jne_rel32_64, usize::MAX);
    b.push(
        Instruction::with2(
            Code::Cmp_rm32_imm32,
            MemoryOperand::with_base_displ(Register::R12, 4),
            0,
        )
        .unwrap(),
    );
    let cleanup_next_depth_edge = b.br(Code::Je_rel32_64, usize::MAX);
    b.push(
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::R15,
            MemoryOperand::with_base_displ(Register::R12, 16),
        )
        .unwrap(),
    );
    b.push(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::EBX,
            MemoryOperand::with_base_displ(Register::R12, 24),
        )
        .unwrap(),
    );
    b.push(Instruction::with2(Code::Xor_rm32_r32, Register::ESI, Register::ESI).unwrap());
    let cleanup_byte_loop = b.len();
    b.push(Instruction::with2(Code::Cmp_r32_rm32, Register::ESI, Register::EBX).unwrap());
    let cleanup_object_done_edge = b.br(Code::Jae_rel32_64, usize::MAX);
    b.push(
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::R12, 32),
        )
        .unwrap(),
    );
    b.push(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::ESI).unwrap());
    b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 3).unwrap());
    b.push(Instruction::with2(Code::Rol_rm64_imm8, Register::RDX, 17).unwrap());
    b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RDX).unwrap());
    movi(&mut b, Register::RDX, 0x517C_C1B7_2722_0A95);
    b.push(Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::RDX).unwrap());
    b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap());
    b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 31).unwrap());
    b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RDX).unwrap());
    movi(&mut b, Register::RDX, 0x4A55_816D_97C6_D67B);
    b.push(Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::RDX).unwrap());
    b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap());
    b.push(Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 27).unwrap());
    b.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RDX).unwrap());
    b.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::ESI).unwrap());
    b.push(Instruction::with2(Code::And_rm32_imm32, Register::ECX, 7).unwrap());
    b.push(Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 3).unwrap());
    b.push(Instruction::with2(Code::Shr_rm64_CL, Register::RAX, Register::CL).unwrap());
    b.push(
        Instruction::with2(
            Code::Xor_rm8_r8,
            MemoryOperand::with_base_index(Register::R15, Register::RSI),
            Register::AL,
        )
        .unwrap(),
    );
    b.push(Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap());
    b.br(Code::Jmp_rel32_64, cleanup_byte_loop);
    let cleanup_object_done = b.len();
    b.push(
        Instruction::with2(
            Code::Mov_rm32_imm32,
            MemoryOperand::with_base_displ(Register::R12, 4),
            0,
        )
        .unwrap(),
    );
    b.push(
        Instruction::with2(
            Code::Mov_rm64_imm32,
            MemoryOperand::with_base_displ(Register::R12, 8),
            0,
        )
        .unwrap(),
    );
    b.push(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::EAX).unwrap());
    b.push(
        Instruction::with2(
            Code::Xchg_rm32_r32,
            MemoryOperand::with_base(Register::R12),
            Register::EAX,
        )
        .unwrap(),
    );
    let cleanup_next = b.len();
    b.push(
        Instruction::with2(
            Code::Add_rm64_imm8,
            Register::R12,
            crate::vm::data_lifetime::LIFETIME_SYNC_ENTRY_SIZE as i32,
        )
        .unwrap(),
    );
    b.push(Instruction::with1(Code::Dec_rm64, Register::R13).unwrap());
    b.br(Code::Jmp_rel32_64, cleanup_entry_loop);
    let cleanup_done = b.len();
    for reg in [
        Register::R15,
        Register::R14,
        Register::R13,
        Register::R12,
        Register::RDI,
        Register::RSI,
        Register::RBP,
        Register::RBX,
    ] {
        b.push(Instruction::with1(Code::Pop_r64, reg).unwrap());
    }
    // EXCEPTION_DISPOSITION::ExceptionContinueSearch. Returning zero means
    // ContinueExecution, which is invalid during phase-2 unwind and causes
    // STATUS_INVALID_DISPOSITION (0xC0000026) for Rust/MSVC panics.
    b.push(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 1).unwrap());
    b.push(Instruction::with(Code::Retnq));
    for (edge, target) in [
        (cleanup_done_edge, cleanup_done),
        (cleanup_next_owner_edge, cleanup_next),
        (cleanup_next_depth_edge, cleanup_next),
        (cleanup_object_done_edge, cleanup_object_done),
    ] {
        for (branch, branch_target) in &mut b.branches {
            if *branch == edge {
                *branch_target = target;
            }
        }
    }

    // P3: distribute identical handler `jmp dispatch` tails over seed-derived,
    // semantics-neutral tail islands before final branch layout.
    let diversified_tails = b.diversify_direct_tails(dispatch, seed);
    if diversified_tails < 2 {
        return Err(anyhow!(
            "dispatcher tail diversification found only {diversified_tails} tail(s)"
        ));
    }

    // P2: apply the seed-derived persistent-role assignment after semantic
    // emission and before branch layout. R8/RDX and scratch/ABI registers stay
    // pinned; R12-R15 (VIP/VStack/Key/Table) are rewritten consistently in
    // register operands and memory base/index operands.
    let role_assignment =
        crate::vm::threaded::reg_permutation::RegisterAssignment::production_from_seed(seed);
    role_assignment
        .validate()
        .map_err(|e| anyhow!("invalid VM role assignment: {e}"))?;
    b.remap_legacy_carriers(&role_assignment);

    // Assemble; use the true per-instruction IPs for handler VAs.
    let (mut code, ips) = b.assemble(code_base)?;
    let va_of = |idx: usize| -> u64 { ips[idx] };

    if let Some(dump_path) = std::env::var_os("BTG_DUMP_POLY") {
        let mut s = String::new();
        let mut dec =
            iced_x86::Decoder::with_ip(64, &code, code_base, iced_x86::DecoderOptions::NONE);
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
        let dump_path = if dump_path.is_empty() {
            std::path::PathBuf::from("_poly_dump.txt")
        } else {
            std::path::PathBuf::from(dump_path)
        };
        std::fs::write(&dump_path, s).map_err(|e| {
            anyhow!(
                "failed to write BTG_DUMP_POLY output {}: {e}",
                dump_path.display()
            )
        })?;
    }

    // Handler table: decrypted opcode byte -> handler VA.
    // P6-1/P6-3: 시드 유래 마스터 키에서 per-opcode 파생 키 `K(op)` 로 handler VA 를
    // XOR 암호화한다. dispatch loop 의 `table[op] ^ K(op)` 복호화와 짝을 이룬다.
    //   * 미등록 opcode byte 는 트랩 핸들러(h_trap, ud2)를 가리킨다 — 테이블 프로브가
    //     조용히 통과하지 못하고 즉시 fault (P6-3, P6-1의 h_nop 폴백 대체).
    //   * 항목마다 서로 다른 K(op) 를 쓰므로, 덤프/단일-XOR 로는 opcode↔handler
    //     매핑을 일괄 복원할 수 없다.
    let mut table = vec![0u64; 256];
    for byte in 0u16..256 {
        table[byte as usize] = va_of(h_trap) ^ per_op_key(table_key, byte as u8);
    }
    for (op, byte) in &spec.opcode_map {
        if let Some(&hidx) = handlers.get(op) {
            table[*byte as usize] = va_of(hidx) ^ per_op_key(table_key, *byte as u8);
        }
    }
    for (&byte, &hidx) in &extension_handlers {
        table[byte as usize] = va_of(hidx) ^ per_op_key(table_key, byte);
    }
    // P6-3: 엔트리 스텁의 무결성 셀프체크를 위한 테이블 checksum.
    let table_checksum = table_checksum_with_topology(&table, table_integrity_topology);

    // P6-3: 위에서 임베드한 placeholder(`mov r11, imm64`, 10 bytes)의 imm64 를 실제
    // checksum 으로 패치. `ips[csum_placeholder_idx]` = 해당 명령의 IP. mov r64, imm64
    // 는 REX.W + B8+rd + imm64 로 imm64 가 offset+2 에 온다.
    {
        let ip = ips[csum_placeholder_idx];
        let off = (ip - code_base) as usize;
        if off + 2 + 8 <= code.len() {
            code[off + 2..off + 10].copy_from_slice(&table_checksum.to_le_bytes());
        } else {
            return Err(anyhow!(
                "P6-3 checksum placeholder OOB: ip 0x{:X} off {} code_len {}",
                ip,
                off,
                code.len()
            ));
        }
    }

    let parts = SelfDecodingParts {
        code,
        dynamic_state_entry_offset: (ips[dynamic_state_entry] - code_base) as usize,
        native_bridge_range: Some((
            (ips[native_bridge_instr_begin] - code_base) as usize,
            (ips[native_bridge_instr_end] - code_base) as usize,
        )),
        lifetime_cleanup_handler_offset: Some((ips[lifetime_cleanup_handler] - code_base) as usize),
        table,
        table_key,
        table_checksum,
        table_integrity_topology,
        offs_tab,
        flags_tab,
        cond_codes,
        branch_map,
        branch_target_key,
        branch_offset_key,
        layout,
        runtime_layout,
        dispatcher_plan,
        chunk_lookup_topology: crate::vm::chunk_crypto::ChunkLookupTopology::from_seed(seed),
    };
    if std::env::var_os("BTG_TRACE_BRIDGE_OFFSETS").is_some() {
        eprintln!(
            "[VM-BRIDGE-OFFSETS] code_base={code_base:#x} native_call={:#x}..{:#x} native_tail={:#x}",
            ips[native_bridge_instr_begin],
            ips[native_bridge_instr_end],
            ips[native_tail_bridge_entry],
        );
    }
    parts.validate(code_base, bytecode.len())?;
    Ok(parts)
}
