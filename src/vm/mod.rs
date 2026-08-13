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


pub mod bytecode;
pub mod flags;
pub mod handlers;
pub mod import_key;
pub mod interp;
pub mod ksa;
pub mod lifter;
pub mod mapper;
pub mod mem_model;
pub mod prga;
pub mod text_lift;

use crate::vm::lifter::LiftedInstr;
use anyhow::{Result, anyhow};
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
    Ok(VmModule { code: vmc.code, table, bytecode })
}

/// M8: build a VM module with an MBA-obfuscated handler table.
///
/// The dispatch derives `K = a + b (mod 2^64)` at runtime via the MBA identity
/// `a + b == (a ^ b) + 2 * (a & b)` from two embedded immediates, and XORs each
/// loaded handler entry with `K` before `jmp` — so handler addresses are never
/// stored (nor `K` embedded) as a single plaintext constant. This is the opt-in
/// `--m8` path; the default `build_vm_module` above is byte-identical to pre-M8.
pub fn build_vm_module_mba(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    mode: handlers::EntryMode,
) -> Result<VmModule> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    // Two random immediates whose MBA sum is the table key. Pick b so that
    // K = a + b is non-zero (avoid an identity key).
    let a: u64 = rng.next_u64();
    let b: u64 = loop {
        let b = rng.next_u64();
        if a.wrapping_add(b) != 0 {
            break b;
        }
    };
    let key = a.wrapping_add(b);
    let vmc = handlers::generate_vm_code(code_va, bytecode_va, table_va, mode, Some((a, b)))?;
    handlers::validate_vm_code(&vmc.code)?;
    let mut table = Vec::with_capacity(bytecode::NUM_OPS * 8);
    for op in 0..bytecode::NUM_OPS {
        let handler_va = code_va + vmc.handler_offsets[op] as u64;
        table.extend_from_slice(&(handler_va ^ key).to_le_bytes());
    }
    Ok(VmModule { code: vmc.code, table, bytecode })
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
) -> Result<VmModule> {
    let m = if m8 {
        build_vm_module_mba(code_va, table_va, bytecode_va, bytecode, handlers::EntryMode::Program)?
    } else {
        build_vm_module(code_va, table_va, bytecode_va, bytecode, handlers::EntryMode::Program)?
    };
    // The Ksa entry stub snapshots RBX→ptr_sbox/RDX→ptr_seed from the caller; for a
    // program VM the boot stub will instead pre-load the original entry GPRs into the
    // state vregs before calling. Keep the entry convention Ksa (state in RCX).
    let _ = state_va;
    Ok(m)
}

// ═══════════════════════════════════════════════════════════════════════
// Submodules (extracted from the old monolith to keep mod.rs a re-export layer):
//   arena.rs    - RWX native-execution arena (unix/windows)
//   encode.rs   - native x86 reference encoders (self-test / bench)
//   self_test.rs- --vm-test cross-validation suite
//   bench.rs    - --vm-bench interpreter vs native throughput
// ═══════════════════════════════════════════════════════════════════════
mod arena;
mod encode;
mod self_test;
mod bench;

pub use self_test::run_self_test;
pub use bench::run_vm_bench;
