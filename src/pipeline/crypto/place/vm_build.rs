// ==============================================================================
// BTG - Boot-stub placement: VM module build strategy - split from place.rs
// ==============================================================================
// M8: MBA-obfuscated VM handler table builder — routes to the MBA variant
// (XOR-encrypted handler table + runtime MBA key derivation) when --m8 is on,
// else the plain builder. Used by both the sizing pass and the final placement.

use crate::vm;
use rand::RngCore;

pub(crate) fn build_vm_mod(
    m8_mod: bool,
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bc: Vec<u8>,
    mode: vm::handlers::EntryMode,
    rng: &mut impl RngCore,
) -> anyhow::Result<vm::VmModule> {
    if m8_mod {
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
    m8_mod: bool,
    rng: &mut impl RngCore,
) -> anyhow::Result<vm::VmModule> {
    if vm_commercial {
        vm::build_program_vm_commercial(
            code_va,
            table_va,
            bytecode_va,
            bc,
            state_va,
            vm_commercial_seed,
            ip_map,
        )
    } else {
        vm::build_program_vm(code_va, table_va, bytecode_va, bc, state_va, m8_mod, rng)
    }
}