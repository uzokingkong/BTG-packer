// ==============================================================================
// BTG - Boot-stub placement: VM module build strategy - split from place.rs
// ==============================================================================
// M8: MBA-obfuscated VM handler table builder — routes to the MBA variant
// (XOR-encrypted handler table + runtime MBA key derivation) when --m8 is on,
// else the plain builder. Used by both the sizing pass and the final placement.

use crate::vm;
use rand::RngCore;

pub(crate) const MULTI_FAMILY_STATE_STRIDE: usize = 0x8000;

pub(crate) struct MultiFamilyVmModule {
    pub module: vm::VmModule,
    pub families: Vec<vm::poly::VmArchitectureFamily>,
    pub state_offsets: Vec<usize>,
    pub code_ranges: Vec<(usize, usize)>,
    pub table_ranges: Vec<(usize, usize)>,
    pub bytecode_ranges: Vec<(usize, usize)>,
    pub native_bridge_ranges: Vec<(usize, usize)>,
    pub entry_byte_offset: usize,
    pub chunks: Vec<(usize, vm::chunk_crypto::BytecodeChunk)>,
}

pub(crate) fn build_multi_family_prog_mod(
    materialized: &vm::multi_family::MaterializedMultiFamilyProgram,
    entry_family: vm::poly::VmArchitectureFamily,
    entry_va: u64,
    code_va: u64,
    state_va: u64,
    enable_m7: bool,
) -> anyhow::Result<MultiFamilyVmModule> {
    let mut modules: Vec<_> = materialized.modules.iter().collect();
    modules.sort_by_key(|module| (module.family != entry_family, module.family as u8));
    let index_by_family: std::collections::HashMap<_, _> = modules
        .iter()
        .enumerate()
        .map(|(index, module)| (module.family, index))
        .collect();
    let entry_module = modules
        .first()
        .ok_or_else(|| anyhow::anyhow!("multi-family program has no modules"))?;
    let entry_local_op = entry_module
        .ip_map
        .get(&entry_va)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("entry VA {entry_va:#x} is absent from entry family"))?;
    let entry_byte_offset = entry_module.instruction_offsets[entry_local_op];
    let chunk_plans: Vec<Vec<vm::chunk_crypto::BytecodeChunk>> = modules
        .iter()
        .map(|module| {
            if enable_m7 {
                vm::chunk_crypto::plan_chunks(
                    module.bytecode.len(),
                    &module.instruction_offsets,
                    module.module_domain,
                    vm::chunk_crypto::DEFAULT_CHUNK_BYTES,
                )
            } else {
                Vec::new()
            }
        })
        .collect();

    let dummy_routes = |source_family| {
        materialized
            .route_table
            .iter()
            .filter(|route| route.source_family == source_family)
            .map(|route| {
                let target = modules[index_by_family[&route.target_family]];
                vm::threaded::poly_direct::NativeCrossFamilyRoute {
                    target_va: route.target_va,
                    target_entry_va: 0,
                    target_state_va: 0,
                    target_byte_offset: target.instruction_offsets[route.target_local_op] as u64,
                    target_layout: vm::threaded::VmRuntimeLayout::from_seed(target.module_domain),
                    tail_jump_resume_offset: (route.kind
                        == vm::multi_family::CrossFamilyRouteKind::Jump)
                        .then_some(
                            modules[index_by_family[&source_family]].exit_byte_offset as u64,
                        ),
                }
            })
            .collect::<Vec<_>>()
    };

    let mut sized = Vec::with_capacity(modules.len());
    for (module_index, module) in modules.iter().enumerate() {
        let mut routes = dummy_routes(module.family);
        if routes.is_empty() {
            routes.push(vm::threaded::poly_direct::NativeCrossFamilyRoute {
                target_va: u64::MAX,
                target_entry_va: 0,
                target_state_va: 0,
                target_byte_offset: 0,
                target_layout: vm::threaded::VmRuntimeLayout::from_seed(module.module_domain),
                tail_jump_resume_offset: None,
            });
        }
        sized.push(
            vm::commercial_build::build_program_vm_commercial_with_routes_for_family(
                0,
                0,
                0,
                module.bytecode.clone(),
                0,
                module.module_domain,
                module.family,
                Some(&module.ip_map),
                None,
                &chunk_plans[module_index],
                &routes,
            )?,
        );
    }
    let code_total: usize = sized.iter().map(|module| module.code.len()).sum();
    let table_total: usize = sized.iter().map(|module| module.table.len()).sum();
    let mut code_offsets = Vec::with_capacity(modules.len());
    let mut table_offsets = Vec::with_capacity(modules.len());
    let mut bytecode_offsets = Vec::with_capacity(modules.len());
    let (mut code_cursor, mut table_cursor, mut bytecode_cursor) = (0usize, 0usize, 0usize);
    for module in &sized {
        code_offsets.push(code_cursor);
        table_offsets.push(table_cursor);
        bytecode_offsets.push(bytecode_cursor);
        code_cursor += module.code.len();
        table_cursor += module.table.len();
        bytecode_cursor += module.bytecode.len();
    }

    let mut built = Vec::with_capacity(modules.len());
    let mut native_bridge_ranges = Vec::new();
    for (index, module) in modules.iter().enumerate() {
        let mut routes = materialized
            .route_table
            .iter()
            .filter(|route| route.source_family == module.family)
            .map(|route| {
                let target_index = index_by_family[&route.target_family];
                let target = modules[target_index];
                Ok(vm::threaded::poly_direct::NativeCrossFamilyRoute {
                    target_va: route.target_va,
                    target_entry_va: code_va + code_offsets[target_index] as u64,
                    target_state_va: state_va + (target_index * MULTI_FAMILY_STATE_STRIDE) as u64,
                    target_byte_offset: target.instruction_offsets[route.target_local_op] as u64,
                    target_layout: vm::threaded::VmRuntimeLayout::from_seed(target.module_domain),
                    tail_jump_resume_offset: (route.kind
                        == vm::multi_family::CrossFamilyRouteKind::Jump)
                        .then_some(module.exit_byte_offset as u64),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if routes.is_empty() {
            routes.push(vm::threaded::poly_direct::NativeCrossFamilyRoute {
                target_va: u64::MAX,
                target_entry_va: code_va + code_offsets[index] as u64,
                target_state_va: state_va + (index * MULTI_FAMILY_STATE_STRIDE) as u64,
                target_byte_offset: 0,
                target_layout: vm::threaded::VmRuntimeLayout::from_seed(module.module_domain),
                tail_jump_resume_offset: None,
            });
        }
        let built_module =
            vm::commercial_build::build_program_vm_commercial_with_routes_for_family(
                code_va + code_offsets[index] as u64,
                code_va + code_total as u64 + table_offsets[index] as u64,
                code_va + code_total as u64 + table_total as u64 + bytecode_offsets[index] as u64,
                module.bytecode.clone(),
                state_va + (index * MULTI_FAMILY_STATE_STRIDE) as u64,
                module.module_domain,
                module.family,
                Some(&module.ip_map),
                None,
                &chunk_plans[index],
                &routes,
            )?;
        if built_module.code.len() != sized[index].code.len()
            || built_module.table.len() != sized[index].table.len()
        {
            return Err(anyhow::anyhow!(
                "multi-family module sizing drift for {:?}",
                module.family
            ));
        }
        if let Some((start, end)) = built_module.native_bridge_range {
            native_bridge_ranges.push((code_offsets[index] + start, code_offsets[index] + end));
        }
        built.push(built_module);
    }

    let mut code = Vec::with_capacity(code_total);
    let mut table = Vec::with_capacity(table_total);
    let mut bytecode = Vec::with_capacity(bytecode_cursor);
    let mut code_ranges = Vec::with_capacity(built.len());
    let mut table_ranges = Vec::with_capacity(built.len());
    let mut bytecode_ranges = Vec::with_capacity(built.len());
    let mut chunks = Vec::new();
    for module in &built {
        code_ranges.push((code.len(), module.code.len()));
        code.extend_from_slice(&module.code);
    }
    for module in &built {
        table_ranges.push((table.len(), module.table.len()));
        table.extend_from_slice(&module.table);
    }
    for (index, module) in built.iter().enumerate() {
        let start = bytecode.len();
        bytecode.extend_from_slice(&module.bytecode);
        bytecode_ranges.push((start, module.bytecode.len()));
        chunks.extend(
            chunk_plans[index]
                .iter()
                .cloned()
                .map(|chunk| (start, chunk)),
        );
    }
    Ok(MultiFamilyVmModule {
        module: vm::VmModule {
            code,
            table,
            bytecode,
            handler_offsets: Vec::new(),
            native_bridge_range: native_bridge_ranges.first().copied(),
        },
        families: modules.iter().map(|module| module.family).collect(),
        state_offsets: (0..modules.len())
            .map(|index| index * MULTI_FAMILY_STATE_STRIDE)
            .collect(),
        code_ranges,
        table_ranges,
        bytecode_ranges,
        native_bridge_ranges,
        entry_byte_offset,
        chunks,
    })
}

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
    family: Option<vm::poly::VmArchitectureFamily>,
    m8_mod: bool,
    rng: &mut impl RngCore,
) -> anyhow::Result<vm::VmModule> {
    if vm_commercial {
        vm::commercial_build::build_program_vm_commercial_with_superops_and_chunks_for_family(
            code_va,
            table_va,
            bytecode_va,
            bc,
            state_va,
            vm_commercial_seed,
            family.unwrap_or_else(|| vm::poly::VmArchitectureFamily::for_build(vm_commercial_seed)),
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
