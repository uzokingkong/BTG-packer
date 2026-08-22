// ==============================================================================
// BTG - Boot-stub placement: VM module build strategy - split from place.rs
// ==============================================================================
// M8: MBA-obfuscated VM handler table builder — routes to the MBA variant
// (XOR-encrypted handler table + runtime MBA key derivation) when --m8 is on,
// else the plain builder. Used by both the sizing pass and the final placement.

use crate::vm;
use rand::RngCore;

/// Audit #6 (레거시 1:1 VM 해체): when enabled, the legacy VM path rewrites the
/// bytecode into the fused/permuted/variable form (`semantic_obf`) and builds a
/// matching permuted module (`build_vm_module_obf`) whose fused handlers carry
/// the sub-dispatch. Sizing and final placement both derive the seed from the
/// same `rng`, but the module/bytecode *lengths* are seed-independent (the set
/// of fused ops and every fused body length is fixed), so the two-pass
/// placement stays consistent. Disable with `BTG_NO_SEMOBF=1` (like
/// `BTG_NO_HANDLER_OBF`) for the legacy plain byte-identical path.
fn semobf_enabled() -> bool {
    std::env::var("BTG_NO_SEMOBF").is_err()
}

pub(crate) fn build_vm_mod(
    m8_mod: bool,
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bc: Vec<u8>,
    mode: vm::handlers::EntryMode,
    rng: &mut impl RngCore,
) -> anyhow::Result<vm::VmModule> {
    if semobf_enabled() {
        let seed = rng.next_u64();
        let obf = vm::semantic_obf::SemanticObfuscator::from_seed(seed);
        let obf_bc = obf.encode(&bc);
        vm::build_vm_module_obf(code_va, table_va, bytecode_va, obf_bc, mode, seed)
    } else if m8_mod {
        vm::build_vm_module_mba(code_va, table_va, bytecode_va, bc, mode, rng)
    } else {
        vm::build_vm_module(code_va, table_va, bytecode_va, bc, mode)
    }
}

/// P3 (G1): 상용 프로그램 리프트의 ip_map (source-IP -> micro-op index) — the
/// VirtualBranch native handler uses it to resolve branch targets to bytecode
/// byte offsets. Populated in the lift below and passed to build_prog_vm_mod.
pub(crate) fn build_prog_vm_mod(
    vm_commercial: bool,
    vm_commercial_seed: u64,
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bc: Vec<u8>,
    state_va: u64,
    ip_map: Option<&std::collections::HashMap<u64, usize>>,
    superops: Option<&vm::threaded::PreparedSuperOpProgram>,
    chunks: &[vm::chunk_crypto::BytecodeChunk],
    m8_mod: bool,
    rng: &mut impl RngCore,
) -> anyhow::Result<vm::VmModule> {
    if vm_commercial {
        vm::commercial_build::build_program_vm_commercial_with_superops_and_chunks(
            code_va,
            table_va,
            bytecode_va,
            bc,
            state_va,
            vm_commercial_seed,
            ip_map,
            superops,
            chunks,
        )
    } else if semobf_enabled() {
        let seed = rng.next_u64();
        let obf = vm::semantic_obf::SemanticObfuscator::from_seed(seed);
        let obf_bc = obf.encode(&bc);
        vm::build_vm_module_obf(
            code_va,
            table_va,
            bytecode_va,
            obf_bc,
            vm::handlers::EntryMode::Program,
            seed,
        )
    } else {
        vm::build_program_vm(code_va, table_va, bytecode_va, bc, state_va, m8_mod, rng)
    }
}
