// ==============================================================================
// BTG v3 - Composite VM Module
// ==============================================================================
//
// MVP code-virtualization engine:
//   bytecode.rs   - VM bytecode format + emitter + disassembler
//   ksa.rs        - virtualization target: the boot stub's RC4 KSA routine
//   lifter.rs     - x86-64 -> bytecode lifter (MVP subset)
//   interp/       - reference interpreter (self-test): mod(dispatch) + per-group
//                   opcode handlers + state helpers (directory module)
//   handlers/     - native x86-64 handler / dispatch / entry codegen (directory module)
//
// `build_vm_module` produces a complete, linkable VM module (machine code +
// absolute handler table + bytecode) for a caller-supplied placement. The
// packer embeds it in the .textb boot area and replaces the native KSA loop
// in the boot stub with a call into the module (see pipeline/crypto.rs).
//
// `run_self_test` (--vm-test) verifies end-to-end on the build host:
//   reference Rust KSA == bytecode interpreter == native x86 KSA == VM module
// ==============================================================================

pub mod abi;
pub mod bytecode;
pub mod c1;
pub mod canonical_semantics;
pub mod chunk_crypto;
pub mod commercial_build;
pub mod conceal;
pub mod data_lifetime;
pub mod dispatch_perm;
pub mod distributed_integrity;
pub mod embed_hardening;
pub mod flags;
pub mod handler_poly;
pub mod handlers;
pub mod import_key;
pub mod interp;
pub mod ksa;
pub mod lifter;
pub mod mapper;
pub mod mem_model;
pub mod multi_family;
pub mod nested;
pub mod ownership_verifier;
pub mod poly;
pub mod prga;
pub mod risc;
pub mod seed_lifecycle;
pub mod semantic_obf;
pub mod semantics;
pub mod table_layout;
pub mod text_lift;
pub mod threaded;
pub mod vm_context;
pub use commercial_build::{
    build_program_vm_commercial, build_program_vm_commercial_with_superops, COMMERCIAL_STATE_SIZE,
};
pub use vm_context::VmExecutionContext;

use crate::vm::lifter::LiftedInstr;
use anyhow::{anyhow, Result};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};
use rand::RngCore;

/// VM state buffer size (see interp.rs layout).
pub const VM_STATE_SIZE: usize = interp::STATE_SIZE;

/// A complete, linkable VM module.
#[derive(Debug, Clone)]
pub struct VmModule {
    /// entry + dispatch + handlers machine code
    pub code: Vec<u8>,
    /// absolute-address handler table (NUM_OPS x u64)
    pub table: Vec<u8>,
    /// virtualized routine bytecode
    pub bytecode: Vec<u8>,
    /// handler offset per opcode (index 0 = invalid-opcode handler) ??the
    /// offset of each handler's first instruction within `code`. Exposed for
    /// the obfuscation self-test to verify offsets point at real handlers.
    pub handler_offsets: Vec<usize>,
    /// Optional code-relative range requiring bridge-specific unwind metadata.
    pub native_bridge_range: Option<(usize, usize)>,
}

impl VmModule {
    pub fn total_len(&self) -> usize {
        self.code.len() + self.table.len() + self.bytecode.len() + VM_STATE_SIZE
    }
}

/// Build a VM module for a given placement.
/// `code_va` / `table_va` / `bytecode_va` are the absolute VAs where the
/// caller will place each part. The VM state buffer is expected to follow
/// the bytecode (offset = code_len + table_len + bytecode_len).
pub fn build_vm_module(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    mode: handlers::EntryMode,
) -> Result<VmModule> {
    let vmc = handlers::generate_vm_code(code_va, bytecode_va, table_va, mode, None)?;
    handlers::validate_vm_code(&vmc.code)?;
    let mut table = Vec::with_capacity(bytecode::NUM_OPS * 8);
    for op in 0..bytecode::NUM_OPS {
        let handler_va = code_va + vmc.handler_offsets[op] as u64;
        table.extend_from_slice(&handler_va.to_le_bytes());
    }
    Ok(VmModule {
        code: vmc.code,
        table,
        bytecode,
        handler_offsets: vmc.handler_offsets.clone(),
        native_bridge_range: None,
    })
}

/// M8: build a VM module with an MBA-obfuscated handler table.
///
/// The dispatch derives `K = a + b (mod 2^64)` at runtime via the MBA identity
/// `a + b == (a ^ b) + 2 * (a & b)` from two embedded immediates, and XORs each
/// loaded handler entry with `K` before `jmp` ??so handler addresses are never
/// stored (nor `K` embedded) as a single plaintext constant. This is the opt-in
/// `--m8` path; the default `build_vm_module` above is byte-identical to pre-M8.
///
/// P3-1 (결정적 빌드): `rng`는 **호출자가 공급**해야 한다 (`--seed` 시 단일 시드
/// RNG). 과거 `rand::thread_rng()`를 내부에서 생성해 `--seed --m8` 빌드가 매번
/// 다른 출력을 냈다 — readccc.md §4.2 (build-affecting randomness는 하나의
/// derivation tree에서만). 이제 패커는 `ctx.rng`를, 테스트/벤치는 고정 시드
/// RNG를 넘긴다.
pub fn build_vm_module_mba(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    mode: handlers::EntryMode,
    rng: &mut impl RngCore,
) -> Result<VmModule> {
    // Two random immediates whose MBA sum is the table key. Pick b so that
    // K = a + b is non-zero (avoid an identity key).
    let a: u64 = rng.next_u64();
    let b: u64 = loop {
        let b = rng.next_u64();
        if a.wrapping_add(b) != 0 {
            break b;
        }
    };
    let master = a.wrapping_add(b);
    let vmc = handlers::generate_vm_code(code_va, bytecode_va, table_va, mode, Some((a, b)))?;
    handlers::validate_vm_code(&vmc.code)?;
    // Per-opcode derived dispatch key: each entry is XORed with
    // key(op) = (op*C1) ^ (op<<17) ^ C4 ^ master (see handlers::per_op_dispatch_key),
    // matching the runtime dispatch exactly. No single constant recovers
    // `handler[opcode] = table[opcode] ^ K` anymore.
    let mut table = Vec::with_capacity(bytecode::NUM_OPS * 8);
    for op in 0..bytecode::NUM_OPS {
        let handler_va = code_va + vmc.handler_offsets[op] as u64;
        let k = handlers::per_op_dispatch_key(op as u8, master);
        table.extend_from_slice(&(handler_va ^ k).to_le_bytes());
    }
    Ok(VmModule {
        code: vmc.code,
        table,
        bytecode,
        handler_offsets: vmc.handler_offsets.clone(),
        native_bridge_range: None,
    })
}

/// M6 Phase-2 embed helper: wrap a lifted program's VM bytecode (from
/// `text_lift::lift_program_cfg`) into a linkable VM module with an explicit state
/// buffer VA (used by the boot stub to initialize registers before dispatching into
/// the program VM). `state_va` is where the caller places the VM state buffer.
pub fn build_program_vm(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    state_va: u64,
    m8: bool,
    rng: &mut impl RngCore,
) -> Result<VmModule> {
    let m = if m8 {
        build_vm_module_mba(
            code_va,
            table_va,
            bytecode_va,
            bytecode,
            handlers::EntryMode::Program,
            rng,
        )?
    } else {
        build_vm_module(
            code_va,
            table_va,
            bytecode_va,
            bytecode,
            handlers::EntryMode::Program,
        )?
    };
    // The Ksa entry stub snapshots RBX?뭦tr_sbox/RDX?뭦tr_seed from the caller; for a
    // program VM the boot stub will instead pre-load the original entry GPRs into the
    // state vregs before calling. Keep the entry convention Ksa (state in RCX).
    let _ = state_va;
    Ok(m)
}

/// Build a VM module that executes a *fused / permuted / variable-length*
/// bytecode stream (audit weakness #6). The plain handler table is permuted by
/// the seed-keyed `SemanticObfuscator` so the opcode→semantic mapping differs
/// per build, and fused (multi-op) handlers + a 256-entry table carry the
/// fused families. `obf_bytecode` must be the output of
/// `semantic_obf::SemanticObfuscator::from_seed(seed).encode(plain_bc)`.
///
/// Layout: `code` = plain handler code (entry stub + dispatch + 1:1 handlers)
/// followed by the fused-handler region. The table is 256 u64 slots indexed by
/// the encoded opcode byte: permuted plain opcodes -> their plain handlers,
/// fused family tags -> the fused handlers, everything else -> the invalid
/// (ud2) handler.
pub fn build_vm_module_obf(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    obf_bytecode: Vec<u8>,
    mode: handlers::EntryMode,
    seed: u64,
) -> Result<VmModule> {
    let vmc = handlers::generate_vm_code(code_va, bytecode_va, table_va, mode, None)?;
    handlers::validate_vm_code(&vmc.code)?;

    let obf = crate::vm::semantic_obf::SemanticObfuscator::from_seed(seed);
    let fused_base_va = code_va + vmc.code.len() as u64;
    let fused = handlers::fused::emit_fused_handlers(&obf, fused_base_va)?;

    let invalid_off = vmc.handler_offsets[0];
    let invalid_va = code_va + invalid_off as u64;

    // Combined code: plain handlers, then fused handlers.
    let mut code = vmc.code;
    let fused_base = code.len();
    code.extend_from_slice(&fused.code);

    // 256-entry handler table indexed by encoded opcode byte.
    let mut table = vec![0u8; 256 * 8];
    for slot in 0..256usize {
        let va = if slot < bytecode::NUM_OPS {
            let op = obf.dec_op(slot as u8);
            code_va + vmc.handler_offsets[op as usize] as u64
        } else {
            invalid_va
        };
        table[slot * 8..slot * 8 + 8].copy_from_slice(&va.to_le_bytes());
    }
    // Override fused family slots.
    for (fam_byte, off) in &fused.entries {
        let va = code_va + (fused_base + *off) as u64;
        let s = *fam_byte as usize;
        table[s * 8..s * 8 + 8].copy_from_slice(&va.to_le_bytes());
    }

    Ok(VmModule {
        code,
        table,
        bytecode: obf_bytecode,
        handler_offsets: vmc.handler_offsets,
        native_bridge_range: None,
    })
}

// ?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧??
// Submodules (extracted from the old monolith to keep mod.rs a re-export layer):
//   arena.rs    - RWX native-execution arena (unix/windows)
//   encode.rs   - native x86 reference encoders (self-test / bench)
//   self_test/   - --vm-test cross-validation suite (directory module)
//   bench.rs    - --vm-bench interpreter vs native throughput
// ?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧?먥븧??
pub(crate) mod arena;
mod bench;
mod encode;
mod self_test;

pub use bench::run_vm_bench;
pub use self_test::run_self_test;
