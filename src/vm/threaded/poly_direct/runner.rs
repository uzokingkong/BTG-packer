use crate::vm::arena::Arena;
use crate::vm::risc::RiscEvalState;
use anyhow::Result;
use std::collections::HashMap;

use super::builder::{
    build_self_decoding_parts_with_layouts, build_self_decoding_parts_with_superops,
    build_self_decoding_parts_with_superops_and_chunks,
    build_self_decoding_parts_with_superops_and_chunks_for_family,
};
use super::codegen_util::*;
use crate::vm::table_layout::TableLayout;
use crate::vm::threaded::{AssignedSuperOp, SuperOpBuildMetadata, VmRuntimeLayout};

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
    run_native_poly_direct_with_layout(bytecode, seed, init_regs, ip_map, VmRuntimeLayout::legacy())
}

/// Test/benchmark runner for a caller-selected state ABI. Production uses the
/// same builder, so this is the differential gate for seeded layouts.
pub fn run_native_poly_direct_with_layout(
    bytecode: &[u8],
    seed: u64,
    init_regs: &[u64; 16],
    ip_map: Option<&HashMap<u64, usize>>,
    runtime_layout: VmRuntimeLayout,
) -> Result<RiscEvalState> {
    run_native_poly_direct_configured(
        bytecode,
        bytecode,
        seed,
        init_regs,
        ip_map,
        runtime_layout,
        &[],
        None,
        &[],
    )
}

#[cfg(test)]
pub(crate) fn run_native_poly_direct_for_family(
    bytecode: &[u8],
    seed: u64,
    family: crate::vm::poly::VmArchitectureFamily,
    init_regs: &[u64; 16],
    ip_map: Option<&HashMap<u64, usize>>,
) -> Result<RiscEvalState> {
    run_native_poly_direct_configured_for_family(
        bytecode,
        seed,
        family,
        init_regs,
        ip_map,
        VmRuntimeLayout::from_seed(seed),
    )
}

#[cfg(test)]
fn run_native_poly_direct_configured_for_family(
    bytecode: &[u8],
    seed: u64,
    family: crate::vm::poly::VmArchitectureFamily,
    init_regs: &[u64; 16],
    ip_map: Option<&HashMap<u64, usize>>,
    runtime_layout: VmRuntimeLayout,
) -> Result<RiscEvalState> {
    let bytecode_off = 0x20000usize;
    let state_off = (bytecode_off + bytecode.len() + 0xFFF) & !0xFFF;
    let stack_off = state_off + 0x10000;
    let mut arena = Arena::new(stack_off + 0x10000)?;
    let parts = build_self_decoding_parts_with_superops_and_chunks_for_family(
        bytecode,
        seed,
        family,
        (arena.base + OFF_CODE) as u64,
        (arena.base + OFF_TABLE) as u64,
        (arena.base + bytecode_off) as u64,
        (arena.base + state_off) as u64,
        (arena.base + stack_off) as u64,
        ip_map,
        TableLayout::legacy(),
        runtime_layout.clone(),
        &[],
        None,
        &[],
    )?;
    {
        let buf = arena.bytes();
        buf[OFF_CODE..OFF_CODE + parts.code.len()].copy_from_slice(&parts.code);
        for (i, value) in parts.table.iter().enumerate() {
            let p = OFF_TABLE + parts.layout.handler_table_off + i * 8;
            buf[p..p + 8].copy_from_slice(&value.to_le_bytes());
        }
        let p = OFF_TABLE + parts.layout.operand_offs_off;
        for (i, value) in parts.offs_tab.iter().enumerate() {
            buf[p + i * 2..p + i * 2 + 2].copy_from_slice(&value.to_le_bytes());
        }
        let p = OFF_TABLE + parts.layout.operand_flags_off;
        buf[p..p + 256].copy_from_slice(&parts.flags_tab);
        let p = OFF_TABLE + parts.layout.cond_codes_off;
        buf[p..p + 256].copy_from_slice(&parts.cond_codes);
        let p = OFF_TABLE + parts.layout.branch_map_off;
        buf[p..p + parts.branch_map.len()].copy_from_slice(&parts.branch_map);
        buf[bytecode_off..bytecode_off + bytecode.len()].copy_from_slice(bytecode);
        buf[state_off..state_off + runtime_layout.total_size].fill(0);
        buf[stack_off - 0x2000..stack_off].fill(0);
        for (i, value) in init_regs.iter().enumerate() {
            let p = state_off + runtime_layout.vregs[i] as usize;
            buf[p..p + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    arena.call(OFF_CODE);
    let buf = arena.bytes();
    let mut state = RiscEvalState::default();
    for i in 0..16 {
        let p = state_off + runtime_layout.vregs[i] as usize;
        state.regs[i] = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
    }
    for i in 0..8 {
        let p = state_off + runtime_layout.temps[i] as usize;
        state.temps[i] = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
    }
    let p = state_off + runtime_layout.flags as usize;
    state.flags = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
    let p = state_off + runtime_layout.vsp as usize;
    state.vsp = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
    let pending = if (state.vsp as i64) < 0 {
        (-(state.vsp as i64) as u64) / 8
    } else {
        0
    };
    for k in 0..pending as usize {
        let p = stack_off - ((k + 1) * 8);
        state
            .stack
            .push(u64::from_le_bytes(buf[p..p + 8].try_into().unwrap()));
    }
    Ok(state)
}

/// Execute a build-local super-op stream using its original-index to rewritten
/// byte-offset metadata for native branch resolution.
pub fn run_native_poly_direct_superops(
    bytecode: &[u8],
    metadata: &SuperOpBuildMetadata,
    seed: u64,
    init_regs: &[u64; 16],
    runtime_layout: VmRuntimeLayout,
    superops: &[AssignedSuperOp],
) -> Result<RiscEvalState> {
    run_native_poly_direct_configured(
        bytecode,
        bytecode,
        seed,
        init_regs,
        None,
        runtime_layout,
        superops,
        Some(metadata),
        &[],
    )
}

/// Execute the production outer-chunk cipher path. The rolling-polymorphic
/// stream is wrapped exactly as the pack pipeline wraps it, while the native
/// fetch helper unmasks only the byte currently held in registers.
pub fn run_native_poly_direct_chunks(
    bytecode: &[u8],
    seed: u64,
    init_regs: &[u64; 16],
    chunks: &[crate::vm::chunk_crypto::BytecodeChunk],
) -> Result<RiscEvalState> {
    let mut wrapped = bytecode.to_vec();
    for chunk in chunks {
        let start = chunk.offset as usize;
        let end = start + chunk.len as usize;
        crate::vm::chunk_crypto::crypt_chunk(&mut wrapped[start..end], chunk.key);
    }
    run_native_poly_direct_configured(
        &wrapped,
        bytecode,
        seed,
        init_regs,
        None,
        VmRuntimeLayout::legacy(),
        &[],
        None,
        chunks,
    )
}

fn run_native_poly_direct_configured(
    bytecode: &[u8],
    metadata_bytecode: &[u8],
    seed: u64,
    init_regs: &[u64; 16],
    ip_map: Option<&HashMap<u64, usize>>,
    runtime_layout: VmRuntimeLayout,
    superops: &[AssignedSuperOp],
    superop_metadata: Option<&SuperOpBuildMetadata>,
    chunks: &[crate::vm::chunk_crypto::BytecodeChunk],
) -> Result<RiscEvalState> {
    let mut arena = Arena::new(ARENA_SIZE)?;
    let code_base = (arena.base + OFF_CODE) as u64;
    let state_base = (arena.base + OFF_STATE) as u64;
    let table_base = (arena.base + OFF_TABLE) as u64;
    let bytecode_base = (arena.base + OFF_BYTECODE) as u64;
    let stack_base = (arena.base + OFF_STACK_BASE) as u64;
    let parts = if !chunks.is_empty() {
        build_self_decoding_parts_with_superops_and_chunks(
            metadata_bytecode,
            seed,
            code_base,
            table_base,
            bytecode_base,
            state_base,
            stack_base,
            ip_map,
            TableLayout::legacy(),
            runtime_layout,
            superops,
            superop_metadata,
            chunks,
        )?
    } else if superops.is_empty() {
        build_self_decoding_parts_with_layouts(
            metadata_bytecode,
            seed,
            code_base,
            table_base,
            bytecode_base,
            state_base,
            stack_base,
            ip_map,
            TableLayout::legacy(),
            runtime_layout,
        )?
    } else {
        build_self_decoding_parts_with_superops(
            metadata_bytecode,
            seed,
            code_base,
            table_base,
            bytecode_base,
            state_base,
            stack_base,
            ip_map,
            TableLayout::legacy(),
            runtime_layout,
            superops,
            superop_metadata,
        )?
    };
    let state_layout = &parts.runtime_layout;
    let metadata_layout = parts.layout;
    anyhow::ensure!(
        OFF_CODE + parts.code.len() <= OFF_TABLE,
        "native test arena code/table overlap: code_end={:#x} table={OFF_TABLE:#x}",
        OFF_CODE + parts.code.len()
    );

    // Copy into arena.
    {
        let buf = arena.bytes();
        buf[OFF_CODE..OFF_CODE + parts.code.len()].copy_from_slice(&parts.code);
        for (i, v) in parts.table.iter().enumerate() {
            let p = OFF_TABLE + metadata_layout.handler_table_off + i * 8;
            buf[p..p + 8].copy_from_slice(&v.to_le_bytes());
        }
        let p = OFF_TABLE + metadata_layout.operand_offs_off;
        for (index, value) in parts.offs_tab.iter().copied().enumerate() {
            buf[p + index * 2..p + index * 2 + 2].copy_from_slice(&value.to_le_bytes());
        }
        let p = OFF_TABLE + metadata_layout.operand_flags_off;
        buf[p..p + 256].copy_from_slice(&parts.flags_tab);
        let p = OFF_TABLE + metadata_layout.cond_codes_off;
        buf[p..p + 256].copy_from_slice(&parts.cond_codes);
        let branch_off = OFF_TABLE + metadata_layout.branch_map_off;
        assert!(
            branch_off + parts.branch_map.len() <= OFF_BYTECODE,
            "branch map overflowed into bytecode region: {}",
            parts.branch_map.len()
        );
        buf[branch_off..branch_off + parts.branch_map.len()].copy_from_slice(&parts.branch_map);
        buf[OFF_BYTECODE..OFF_BYTECODE + bytecode.len()].copy_from_slice(bytecode);
        buf[OFF_STATE..OFF_STATE + state_layout.total_size].fill(0);
        buf[OFF_STACK_BASE - 0x2000..OFF_STACK_BASE].fill(0);
        for (i, v) in init_regs.iter().enumerate() {
            let p = OFF_STATE + state_layout.vregs[i] as usize;
            buf[p..p + 8].copy_from_slice(&v.to_le_bytes());
        }
    }

    arena.call(OFF_CODE);

    let buf = arena.bytes();
    let s = OFF_STATE;
    let mut st = RiscEvalState::default();
    for i in 0..16 {
        let p = s + state_layout.vregs[i] as usize;
        st.regs[i] = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
    }
    for i in 0..8 {
        let p = s + state_layout.temps[i] as usize;
        st.temps[i] = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
    }
    let p = s + state_layout.flags as usize;
    st.flags = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
    let p = s + state_layout.vsp as usize;
    st.vsp = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
    let pending = if (st.vsp as i64) < 0 {
        (-(st.vsp as i64) as u64) / 8
    } else {
        0
    };
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
