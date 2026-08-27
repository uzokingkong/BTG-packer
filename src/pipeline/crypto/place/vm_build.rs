// ==============================================================================
// BTG - Boot-stub placement: VM module build strategy - split from place.rs
// ==============================================================================
// M8: MBA-obfuscated VM handler table builder — routes to the MBA variant
// (XOR-encrypted handler table + runtime MBA key derivation) when --m8 is on,
// else the plain builder. Used by both the sizing pass and the final placement.

use crate::vm;
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};
use rand::RngCore;
use std::collections::BTreeMap;

pub(crate) const MULTI_FAMILY_STATE_STRIDE: usize = 0x8000;
pub(crate) const VM_THREAD_BUCKETS: usize = 16;
pub(crate) const VM_REENTRY_DEPTHS: usize = 8;
pub(crate) const VM_INVOCATION_LANES: usize = VM_THREAD_BUCKETS * VM_REENTRY_DEPTHS;

/// Per-lane native runtime stack used by native-entry gateways.  The guest's
/// architectural RSP remains in the selected VM state, while dispatcher/helper
/// frames live here.  This prevents lifted guest stack traffic from overwriting
/// the gateway return address or the dynamic-entry nonvolatile frame.
pub(crate) const VM_HOST_STACK_SIZE: usize = 0x1_0000;
pub(crate) const VM_HOST_STACK_SLOTS: usize = VM_INVOCATION_LANES + 1;
const VM_LANE_CONTROL_SIZE: usize = VM_THREAD_BUCKETS * core::mem::size_of::<u32>();
const VM_STATE_TAIL_ALIGN: usize = 0x1000;

#[derive(Debug, Clone, Copy)]
pub(crate) struct MultiFamilyInvocationLayout {
    pub lane_group_stride: usize,
    pub lane_control_va: u64,
    pub lifetime_sync_va: u64,
    pub host_stack_pool_va: u64,
    pub reserve_size: usize,
}

fn align_up_checked(value: usize, align: usize) -> anyhow::Result<usize> {
    debug_assert!(align.is_power_of_two());
    value
        .checked_add(align - 1)
        .map(|v| v & !(align - 1))
        .ok_or_else(|| anyhow::anyhow!("multi-family state layout alignment overflow"))
}

pub(crate) fn multi_family_invocation_layout(
    state_va: u64,
    family_count: usize,
) -> anyhow::Result<MultiFamilyInvocationLayout> {
    if family_count == 0 {
        anyhow::bail!("multi-family state layout requires at least one family");
    }
    let lane_group_stride = family_count
        .checked_mul(MULTI_FAMILY_STATE_STRIDE)
        .ok_or_else(|| anyhow::anyhow!("multi-family lane group stride overflow"))?;
    let groups_size = (VM_INVOCATION_LANES + 1)
        .checked_mul(lane_group_stride)
        .ok_or_else(|| anyhow::anyhow!("multi-family lane state reservation overflow"))?;
    let lane_control_off = align_up_checked(groups_size, 64)?;
    let lifetime_sync_off = align_up_checked(
        lane_control_off
            .checked_add(VM_LANE_CONTROL_SIZE)
            .ok_or_else(|| anyhow::anyhow!("lane-control tail overflow"))?,
        64,
    )?;
    let host_stack_pool_off = align_up_checked(
        lifetime_sync_off
            .checked_add(crate::vm::data_lifetime::LIFETIME_SYNC_TABLE_SIZE)
            .ok_or_else(|| anyhow::anyhow!("lifetime-sync tail overflow"))?,
        VM_STATE_TAIL_ALIGN,
    )?;
    let host_stack_pool_size = VM_HOST_STACK_SLOTS
        .checked_mul(VM_HOST_STACK_SIZE)
        .ok_or_else(|| anyhow::anyhow!("native host-stack pool overflow"))?;
    let reserve_size = align_up_checked(
        host_stack_pool_off
            .checked_add(host_stack_pool_size)
            .ok_or_else(|| anyhow::anyhow!("native host-stack tail overflow"))?,
        VM_STATE_TAIL_ALIGN,
    )?;

    let va = |off: usize| -> anyhow::Result<u64> {
        state_va
            .checked_add(off as u64)
            .ok_or_else(|| anyhow::anyhow!("multi-family state VA overflow"))
    };
    Ok(MultiFamilyInvocationLayout {
        lane_group_stride,
        lane_control_va: va(lane_control_off)?,
        lifetime_sync_va: va(lifetime_sync_off)?,
        host_stack_pool_va: va(host_stack_pool_off)?,
        reserve_size,
    })
}

pub(crate) struct MultiFamilyVmModule {
    pub module: vm::VmModule,
    pub families: Vec<vm::poly::VmArchitectureFamily>,
    pub state_offsets: Vec<usize>,
    pub code_ranges: Vec<(usize, usize)>,
    pub table_ranges: Vec<(usize, usize)>,
    pub bytecode_ranges: Vec<(usize, usize)>,
    pub native_bridge_ranges: Vec<(usize, usize)>,
    pub lifetime_cleanup_handler_offset: Option<usize>,
    pub entry_byte_offset: usize,
    pub chunks: Vec<(usize, vm::chunk_crypto::BytecodeChunk)>,
    pub lifetime_sync: crate::vm::data_lifetime::LifetimeSyncTable,
    pub invocation_layout: MultiFamilyInvocationLayout,
    /// Canonical OEP wrapper offset within `module.code`. The boot stub jumps
    /// here instead of entering the dispatcher on the architectural guest stack.
    pub canonical_entry_gateway_offset: usize,
    /// Original code VA -> native-callable gateway offset within `module.code`.
    pub native_entry_gateways: BTreeMap<u64, usize>,
}

fn build_canonical_oep_gateway(
    gateway_va: u64,
    entry_va: u64,
    state_va: u64,
    layout: &vm::threaded::VmRuntimeLayout,
    host_stack_pool_va: u64,
) -> anyhow::Result<Vec<u8>> {
    let mut ins = Vec::new();
    let host_stack_top = host_stack_pool_va
        .checked_add(VM_HOST_STACK_SIZE as u64)
        .ok_or_else(|| anyhow::anyhow!("canonical host-stack VA overflow"))?;

    // The boot stub arrives with physical RSP equal to the architectural OEP
    // stack. Never let dispatcher/helper frames share that address space.
    // Slot zero is reserved for the canonical OEP invocation.
    ins.push(Instruction::with2(Code::Mov_r64_imm64, Register::R11, host_stack_top)?);
    ins.push(Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::R11)?);
    // Win64 caller shadow space. H is page/16-byte aligned, so pre-call RSP is
    // 0 mod 16 and the dynamic entry observes the required 8 mod 16.
    ins.push(Instruction::with2(Code::Sub_rm64_imm8, Register::RSP, 0x20)?);
    ins.push(Instruction::with2(Code::Mov_r64_imm64, Register::RDX, state_va)?);
    ins.push(Instruction::with_branch(Code::Call_rel32_64, entry_va)?);

    // A top-level lifted RET has already consumed the architectural return slot,
    // so vRSP points at the caller's post-return stack. Recover the original
    // native return target from [vRSP-8], restore physical RSP to vRSP, and tail
    // jump without clobbering virtual RAX (the process/thread entry result).
    ins.push(Instruction::with2(Code::Mov_r64_imm64, Register::R11, state_va)?);
    ins.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::R11,
        MemoryOperand::with_base_displ_size(
            Register::R11,
            layout.vregs[4] as i64,
            8,
        ),
    )?);
    ins.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::R10,
        MemoryOperand::with_base_displ_size(Register::R11, -8, 8),
    )?);
    ins.push(Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::R11)?);
    ins.push(Instruction::with1(Code::Jmp_rm64, Register::R10)?);

    Ok(BlockEncoder::encode(
        64,
        InstructionBlock::new(&ins, gateway_va),
        BlockEncoderOptions::NONE,
    )?
    .code_buffer)
}

fn build_native_entry_gateway(
    gateway_va: u64,
    entry_va: u64,
    state_va: u64,
    entry_byte_offset: u64,
    layout: &vm::threaded::VmRuntimeLayout,
    lane_control_va: u64,
    lane_group_stride: u64,
    host_stack_pool_va: u64,
) -> anyhow::Result<Vec<u8>> {
    let mut ins = Vec::new();
    ins.push(Instruction::with(Code::Pushfq));
    for reg in [Register::RAX, Register::RCX, Register::RDX, Register::RBX, Register::RBP,
        Register::RSI, Register::RDI, Register::R8, Register::R9, Register::R10,
        Register::R11, Register::R12, Register::R13, Register::R14, Register::R15] {
        ins.push(Instruction::with1(Code::Push_r64, reg)?);
    }
    ins.push(Instruction::with2(Code::Mov_r64_imm64, Register::R10, state_va)?);
    // Select (thread bucket, recursive depth) with an atomic depth counter.
    // Lane zero is reserved for the canonical OEP invocation.
    let mut read_tid = Instruction::with2(
        Code::Mov_r32_rm32,
        Register::EAX,
        MemoryOperand::with_displ(0x48, 8),
    )?;
    read_tid.set_segment_prefix(Register::GS);
    ins.push(read_tid);
    ins.push(Instruction::with2(Code::And_rm32_imm32, Register::EAX, (VM_THREAD_BUCKETS - 1) as i32)?);
    ins.push(Instruction::with2(Code::Mov_r64_imm64, Register::RBX, lane_control_va)?);
    ins.push(Instruction::with2(Code::Lea_r64_m, Register::RBX,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RAX, 4))?);
    ins.push(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 1)?);
    let mut xadd = Instruction::with2(Code::Xadd_rm32_r32, MemoryOperand::with_base(Register::RBX), Register::ECX)?;
    xadd.set_has_lock_prefix(true);
    ins.push(xadd);
    ins.push(Instruction::with2(Code::And_rm32_imm32, Register::ECX, (VM_REENTRY_DEPTHS - 1) as i32)?);
    ins.push(Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3)?);
    ins.push(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::ECX)?);
    ins.push(Instruction::with1(Code::Inc_rm32, Register::EAX)?);
    // EAX is now the 1-based invocation lane.  Build the lane-private native
    // stack top in R11 before scaling RAX into the family-state group.
    ins.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RAX)?);
    // Slot zero belongs to canonical OEP. Invocation lane N uses host-stack
    // slot N, whose top is pool + (N + 1) * VM_HOST_STACK_SIZE.
    ins.push(Instruction::with1(Code::Inc_rm64, Register::R11)?);
    ins.push(Instruction::with3(
        Code::Imul_r64_rm64_imm32,
        Register::R11,
        Register::R11,
        VM_HOST_STACK_SIZE as i32,
    )?);
    // Absolute pool base: generated images normally live far outside signed
    // imm32 range, so materialize it explicitly instead of `add r11, imm32`.
    ins.push(Instruction::with2(Code::Mov_r64_imm64, Register::R9, host_stack_pool_va)?);
    ins.push(Instruction::with2(Code::Add_rm64_r64, Register::R11, Register::R9)?);
    ins.push(Instruction::with3(Code::Imul_r64_rm64_imm32, Register::RAX, Register::RAX, lane_group_stride as i32)?);
    ins.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::RAX)?);
    // Saved stack from low to high: r15..rax, rflags; original RSP is +0x80.
    let saved = [112i64, 104, 96, 88, 128, 80, 72, 64, 56, 48, 40, 32, 24, 16, 8, 0];
    for (index, stack_off) in saved.into_iter().enumerate() {
        if index == 4 {
            ins.push(Instruction::with2(Code::Lea_r64_m, Register::RAX,
                MemoryOperand::with_base_displ_size(Register::RSP, stack_off, 8))?);
        } else {
            ins.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
                MemoryOperand::with_base_displ_size(Register::RSP, stack_off, 8))?);
        }
        ins.push(Instruction::with2(Code::Mov_rm64_r64,
            MemoryOperand::with_base_displ_size(Register::R10, layout.vregs[index] as i64, 8),
            Register::RAX)?);
    }
    ins.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
        MemoryOperand::with_base_displ_size(Register::RSP, 120, 8))?);
    ins.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x8D5)?);
    ins.push(Instruction::with2(Code::Or_rm64_imm8, Register::RAX, 2)?);
    ins.push(Instruction::with2(Code::Mov_rm64_r64,
        MemoryOperand::with_base_displ_size(Register::R10, layout.flags as i64, 8), Register::RAX)?);
    for i in 0..layout.xmm_slots.min(6) {
        let xmm = [Register::XMM0, Register::XMM1, Register::XMM2, Register::XMM3, Register::XMM4, Register::XMM5][i];
        ins.push(Instruction::with2(Code::Movups_xmmm128_xmm,
            MemoryOperand::with_base_displ_size(Register::R10, layout.xmm as i64 + i as i64 * 16, 16), xmm)?);
    }
    ins.push(Instruction::with2(Code::Mov_r64_imm64, Register::RAX, entry_byte_offset)?);
    ins.push(Instruction::with2(Code::Mov_rm64_r64,
        MemoryOperand::with_base_displ_size(Register::R10, 0x5000, 8), Register::RAX)?);
    // Every external callback is a fresh top-level VM invocation. Reusing the
    // family state must not reuse a previous invocation's virtual return stack
    // or cross-family result plumbing.
    ins.push(Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RAX)?);
    for off in [
        layout.vsp as i64,
        layout.fp_return as i64,
        0x5008,
        0x5010,
        0x5018,
        0x5020,
        0x5028,
        0x5030,
        0x5038,
        0x5040,
        0x5048,
        0x5050,
        0x5060,
        0x5068,
        0x5070,
        0x5078,
        0x5080,
        0x5088,
        0x5098,
    ] {
        ins.push(Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base_displ_size(Register::R10, off, 8),
            Register::RAX,
        )?);
    }
    for reg in [Register::R15, Register::R14, Register::R13, Register::R12, Register::R11,
        Register::R10, Register::R9, Register::R8, Register::RDI, Register::RSI,
        Register::RBP, Register::RBX, Register::RDX, Register::RCX, Register::RAX] {
        if reg == Register::R10 || reg == Register::R11 {
            // R10 carries the selected state and R11 carries the lane-private
            // native stack top.  Their guest values already live in the lane's
            // architectural state and both registers are volatile in Win64.
            ins.push(Instruction::with2(Code::Add_rm64_imm8, Register::RSP, 8)?);
        } else {
            ins.push(Instruction::with1(Code::Pop_r64, reg)?);
        }
    }
    ins.push(Instruction::with(Code::Popfq));
    ins.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R10)?);

    // Switch away from the architectural guest stack before entering the VM.
    // The previous implementation called the dynamic entry while physical RSP
    // still equalled the saved guest RSP, so lifted `push/sub rsp/[rsp+off]`
    // operations could overwrite the gateway return address/nonvolatile frame.
    // R11 points at a 16-byte-aligned lane-private stack top in `.vstate`.
    ins.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RSP)?);
    ins.push(Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::R11)?);
    // Reserve 0x20 bytes of Win64 shadow space plus a private 0x20-byte
    // persistence frame.  The callee owns the shadow area, so gateway values
    // must live above it rather than inside it.
    ins.push(Instruction::with2(Code::Sub_rm64_imm8, Register::RSP, 0x40)?);
    // Persistent host frame: +0x20 guest RSP, +0x28 original RBX,
    // +0x30 depth-counter VA.
    ins.push(Instruction::with2(
        Code::Mov_rm64_r64,
        MemoryOperand::with_base_displ_size(Register::RSP, 0x20, 8),
        Register::RAX,
    )?);
    ins.push(Instruction::with2(
        Code::Mov_rm64_r64,
        MemoryOperand::with_base_displ_size(Register::RSP, 0x28, 8),
        Register::RBX,
    )?);

    let mut read_tid_release = Instruction::with2(
        Code::Mov_r32_rm32,
        Register::EAX,
        MemoryOperand::with_displ(0x48, 8),
    )?;
    read_tid_release.set_segment_prefix(Register::GS);
    ins.push(read_tid_release);
    ins.push(Instruction::with2(Code::And_rm32_imm32, Register::EAX, (VM_THREAD_BUCKETS - 1) as i32)?);
    ins.push(Instruction::with2(Code::Mov_r64_imm64, Register::RBX, lane_control_va)?);
    ins.push(Instruction::with2(
        Code::Lea_r64_m,
        Register::RBX,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RAX, 4),
    )?);
    ins.push(Instruction::with2(
        Code::Mov_rm64_r64,
        MemoryOperand::with_base_displ_size(Register::RSP, 0x30, 8),
        Register::RBX,
    )?);
    ins.push(Instruction::with_branch(Code::Call_rel32_64, entry_va)?);

    ins.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RBX,
        MemoryOperand::with_base_displ_size(Register::RSP, 0x30, 8),
    )?);
    let mut dec = Instruction::with1(Code::Dec_rm32, MemoryOperand::with_base(Register::RBX))?;
    dec.set_has_lock_prefix(true);
    ins.push(dec);
    ins.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::R11,
        MemoryOperand::with_base_displ_size(Register::RSP, 0x20, 8),
    )?);
    ins.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RBX,
        MemoryOperand::with_base_displ_size(Register::RSP, 0x28, 8),
    )?);
    ins.push(Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::R11)?);
    ins.push(Instruction::with(Code::Retnq));
    Ok(BlockEncoder::encode(64, InstructionBlock::new(&ins, gateway_va), BlockEncoderOptions::NONE)?.code_buffer)
}

pub(crate) fn build_multi_family_prog_mod(
    materialized: &vm::multi_family::MaterializedMultiFamilyProgram,
    entry_family: vm::poly::VmArchitectureFamily,
    entry_va: u64,
    code_va: u64,
    state_va: u64,
    enable_m7: bool,
    image_base: u64,
    lifetime_key: u64,
    lifetime_objects: &[crate::vm::data_lifetime::LiteralObject],
    native_gateway_targets: &[u64],
) -> anyhow::Result<MultiFamilyVmModule> {
    // `place/mod.rs` intentionally calls this function once with both bases set
    // to zero to measure the complete multi-family module before its final PE
    // location is known.  The generated commercial runtime, however, validates
    // every cross-family destination as a non-null native address.  Using the
    // literal zero bases for the second (final-shape) build inside this function
    // therefore makes any route whose target module has offset zero look like a
    // null route even though this is only a sizing pass.
    //
    // Preserve the production validator and give the outer sizing invocation
    // deterministic synthetic bases instead.  Keep the synthetic code/table/
    // bytecode/state bundle inside one +/-2 GiB window: the commercial runtime
    // deliberately materializes its local anchors with RIP-relative LEA, whose
    // disp32 cannot address farther than +/-2 GiB.  The real placement call
    // later rebuilds the module with the actual image VAs.
    if (code_va == 0) != (state_va == 0) {
        return Err(anyhow::anyhow!(
            "multi-family Program-VM received an asymmetric null placement base: code={code_va:#x} state={state_va:#x}"
        ));
    }
    // Sizing-only addresses.  Keep state close to code so every generated
    // RIP-relative anchor remains encodable as disp32.  0x2000_0000 = 512 MiB.
    const OUTER_SIZING_CODE_BASE: u64 = 0x0000_0001_4000_0000;
    const OUTER_SIZING_STATE_BASE: u64 = OUTER_SIZING_CODE_BASE + 0x2000_0000;
    let sizing_only = code_va == 0;
    let effective_code_va = if sizing_only {
        OUTER_SIZING_CODE_BASE
    } else {
        code_va
    };
    let effective_state_va = if sizing_only {
        OUTER_SIZING_STATE_BASE
    } else {
        state_va
    };

    let mut modules: Vec<_> = materialized.modules.iter().collect();
    modules.sort_by_key(|module| (module.family != entry_family, module.family as u8));
    let invocation_layout = multi_family_invocation_layout(effective_state_va, modules.len())?;
    let lifetime_sync = crate::vm::data_lifetime::LifetimeSyncTable::build_at(
        invocation_layout.lifetime_sync_va,
        image_base,
        lifetime_key,
        lifetime_objects,
    )?;
    lifetime_sync.validate_table()?;
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
    let lane_group_stride = invocation_layout.lane_group_stride;
    let lane_control_va = invocation_layout.lane_control_va;
    let host_stack_pool_va = invocation_layout.host_stack_pool_va;
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

    // The first build below is a sizing-only pass.  Cross-family routes still
    // flow through the production route validator, so their address fields must
    // satisfy the same non-null contract even though final per-module code VAs
    // are not known until all module sizes have been measured.
    //
    // Use deterministic, non-zero synthetic addresses here instead of null
    // placeholders.  Cross-family entry/state addresses are currently loaded
    // with imm64, but keeping all sizing addresses in the same local window also
    // preserves the runtime's general near-placement invariant.
    const SIZING_ENTRY_BASE: u64 = OUTER_SIZING_CODE_BASE + 0x0400_0000;
    // The inner module sizing build uses code_base=0, so keep its synthetic
    // state anchors within RIP-relative disp32 range as well.
    const SIZING_STATE_BASE: u64 = 0x1000_0000;

    let dummy_routes = |source_family| -> anyhow::Result<Vec<vm::threaded::poly_direct::NativeCrossFamilyRoute>> {
        let source_index = index_by_family[&source_family];
        let source = modules[source_index];
        let mut routes: Vec<_> = materialized
            .route_table
            .iter()
            .filter(|route| route.source_family == source_family)
            .map(|route| {
                let target_index = index_by_family[&route.target_family];
                let target = modules[target_index];
                let source_next_byte_offset = source
                    .instruction_offsets
                    .get(route.source_local_op + 1)
                    .copied()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "cross-family source op {} in {:?} has no following bytecode offset",
                            route.source_local_op,
                            source_family
                        )
                    })? as u64;
                Ok(vm::threaded::poly_direct::NativeCrossFamilyRoute {
                    target_va: route.target_va,
                    source_next_byte_offset: Some(source_next_byte_offset),
                    target_entry_va: SIZING_ENTRY_BASE
                        + (target_index as u64) * MULTI_FAMILY_STATE_STRIDE as u64,
                    target_state_va: SIZING_STATE_BASE
                        + (target_index as u64) * MULTI_FAMILY_STATE_STRIDE as u64,
                    target_byte_offset: target.instruction_offsets[route.target_local_op] as u64,
                    target_layout: vm::threaded::VmRuntimeLayout::from_seed(target.module_domain),
                    tail_jump_resume_offset: (route.kind
                        == vm::multi_family::CrossFamilyRouteKind::Jump)
                        .then_some(source.exit_byte_offset as u64),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        for (target_index, target) in modules.iter().enumerate() {
            if target.family == source_family {
                continue;
            }
            for &target_va in &target.function_ids {
                if routes.iter().any(|route| {
                    route.target_va == target_va && route.source_next_byte_offset.is_none()
                }) {
                    continue;
                }
                let Some(&target_local_op) = target.ip_map.get(&target_va) else {
                    continue;
                };
                routes.push(vm::threaded::poly_direct::NativeCrossFamilyRoute {
                    target_va,
                    source_next_byte_offset: None,
                    target_entry_va: SIZING_ENTRY_BASE
                        + (target_index as u64) * MULTI_FAMILY_STATE_STRIDE as u64,
                    target_state_va: SIZING_STATE_BASE
                        + (target_index as u64) * MULTI_FAMILY_STATE_STRIDE as u64,
                    target_byte_offset: target.instruction_offsets[target_local_op] as u64,
                    target_layout: vm::threaded::VmRuntimeLayout::from_seed(target.module_domain),
                    tail_jump_resume_offset: None,
                });
            }
        }
        Ok(routes)
    };

    let mut sized = Vec::with_capacity(modules.len());
    for (module_index, module) in modules.iter().enumerate() {
        let mut routes = dummy_routes(module.family)?;
        if routes.is_empty() {
            // Keep one unreachable route so the sizing pass and final pass use
            // the same generated route-scan shape.  It must still satisfy the
            // production validator's non-null address contract.
            routes.push(vm::threaded::poly_direct::NativeCrossFamilyRoute {
                target_va: u64::MAX,
                source_next_byte_offset: None,
                target_entry_va: SIZING_ENTRY_BASE
                    + (module_index as u64) * MULTI_FAMILY_STATE_STRIDE as u64,
                target_state_va: SIZING_STATE_BASE
                    + (module_index as u64) * MULTI_FAMILY_STATE_STRIDE as u64,
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
                SIZING_STATE_BASE
                    + (module_index * MULTI_FAMILY_STATE_STRIDE) as u64,
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

    let entry_runtime_layout = vm::threaded::VmRuntimeLayout::from_seed(entry_module.module_domain);
    let sized_canonical_gateway = build_canonical_oep_gateway(
        effective_code_va + code_total as u64,
        effective_code_va + code_offsets[0] as u64
            + sized[0].dynamic_state_entry_offset.unwrap_or(0) as u64,
        effective_state_va,
        &entry_runtime_layout,
        host_stack_pool_va,
    )?;
    let canonical_gateway_size = sized_canonical_gateway.len();

    let mut gateway_targets = native_gateway_targets.to_vec();
    gateway_targets.sort_unstable();
    gateway_targets.dedup();
    let mut sized_gateway_total = 0usize;
    for &target_va in &gateway_targets {
        let (target_index, target) = modules
            .iter()
            .enumerate()
            .find(|(_, module)| module.ip_map.contains_key(&target_va))
            .ok_or_else(|| anyhow::anyhow!("native gateway target {target_va:#x} has no materialized family entry"))?;
        let local_op = target.ip_map[&target_va];
        let entry_offset = target.instruction_offsets[local_op] as u64;
        let bytes = build_native_entry_gateway(
            effective_code_va
                + code_total as u64
                + canonical_gateway_size as u64
                + sized_gateway_total as u64,
            effective_code_va + code_offsets[target_index] as u64,
            effective_state_va + (target_index * MULTI_FAMILY_STATE_STRIDE) as u64,
            entry_offset,
            &vm::threaded::VmRuntimeLayout::from_seed(target.module_domain),
            lane_control_va,
            lane_group_stride as u64,
            host_stack_pool_va,
        )?;
        sized_gateway_total += bytes.len();
    }
    let full_code_total = code_total + canonical_gateway_size + sized_gateway_total;

    let mut built = Vec::with_capacity(modules.len());
    let mut native_bridge_ranges = Vec::new();
    let mut lifetime_cleanup_handler_offset = None;
    for (index, module) in modules.iter().enumerate() {
        let mut routes = materialized
            .route_table
            .iter()
            .filter(|route| route.source_family == module.family)
            .map(|route| {
                let target_index = index_by_family[&route.target_family];
                let target = modules[target_index];
                let source_next_byte_offset = module
                    .instruction_offsets
                    .get(route.source_local_op + 1)
                    .copied()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "cross-family source op {} in {:?} has no following bytecode offset",
                            route.source_local_op,
                            module.family
                        )
                    })? as u64;
                Ok(vm::threaded::poly_direct::NativeCrossFamilyRoute {
                    target_va: route.target_va,
                    source_next_byte_offset: Some(source_next_byte_offset),
                    target_entry_va: effective_code_va + code_offsets[target_index] as u64
                        + sized[target_index].dynamic_state_entry_offset.unwrap_or(0) as u64,
                    target_state_va: effective_state_va + (target_index * MULTI_FAMILY_STATE_STRIDE) as u64,
                    target_byte_offset: target.instruction_offsets[route.target_local_op] as u64,
                    target_layout: vm::threaded::VmRuntimeLayout::from_seed(target.module_domain),
                    tail_jump_resume_offset: (route.kind
                        == vm::multi_family::CrossFamilyRouteKind::Jump)
                        .then_some(module.exit_byte_offset as u64),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        for (target_index, target) in modules.iter().enumerate() {
            if target.family == module.family {
                continue;
            }
            for &target_va in &target.function_ids {
                if routes.iter().any(|route| {
                    route.target_va == target_va && route.source_next_byte_offset.is_none()
                }) {
                    continue;
                }
                let Some(&target_local_op) = target.ip_map.get(&target_va) else {
                    continue;
                };
                routes.push(vm::threaded::poly_direct::NativeCrossFamilyRoute {
                    target_va,
                    source_next_byte_offset: None,
                    target_entry_va: effective_code_va + code_offsets[target_index] as u64
                        + sized[target_index].dynamic_state_entry_offset.unwrap_or(0) as u64,
                    target_state_va: effective_state_va
                        + (target_index * MULTI_FAMILY_STATE_STRIDE) as u64,
                    target_byte_offset: target.instruction_offsets[target_local_op] as u64,
                    target_layout: vm::threaded::VmRuntimeLayout::from_seed(target.module_domain),
                    tail_jump_resume_offset: None,
                });
            }
        }
        if routes.is_empty() {
            routes.push(vm::threaded::poly_direct::NativeCrossFamilyRoute {
                target_va: u64::MAX,
                source_next_byte_offset: None,
                target_entry_va: effective_code_va + code_offsets[index] as u64
                    + sized[index].dynamic_state_entry_offset.unwrap_or(0) as u64,
                target_state_va: effective_state_va + (index * MULTI_FAMILY_STATE_STRIDE) as u64,
                target_byte_offset: 0,
                target_layout: vm::threaded::VmRuntimeLayout::from_seed(module.module_domain),
                tail_jump_resume_offset: None,
            });
        }
        let built_module =
            vm::commercial_build::build_program_vm_commercial_with_routes_for_family(
                effective_code_va + code_offsets[index] as u64,
                effective_code_va + full_code_total as u64 + table_offsets[index] as u64,
                effective_code_va + full_code_total as u64 + table_total as u64 + bytecode_offsets[index] as u64,
                module.bytecode.clone(),
                effective_state_va + (index * MULTI_FAMILY_STATE_STRIDE) as u64,
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
        if lifetime_cleanup_handler_offset.is_none() {
            lifetime_cleanup_handler_offset = built_module
                .lifetime_cleanup_handler_offset
                .map(|offset| code_offsets[index] + offset);
        }
        built.push(built_module);
    }

    let mut code = Vec::with_capacity(full_code_total);
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
    let canonical_entry_gateway_offset = code.len();
    let canonical_gateway = build_canonical_oep_gateway(
        effective_code_va + canonical_entry_gateway_offset as u64,
        effective_code_va + code_offsets[0] as u64
            + built[0].dynamic_state_entry_offset.unwrap_or(0) as u64,
        effective_state_va,
        &entry_runtime_layout,
        host_stack_pool_va,
    )?;
    if canonical_gateway.len() != canonical_gateway_size {
        return Err(anyhow::anyhow!(
            "canonical OEP gateway sizing drift: {} != {}",
            canonical_gateway.len(),
            canonical_gateway_size
        ));
    }
    code.extend_from_slice(&canonical_gateway);

    let mut native_entry_gateways = BTreeMap::new();
    for &target_va in &gateway_targets {
        let (target_index, target) = modules
            .iter()
            .enumerate()
            .find(|(_, module)| module.ip_map.contains_key(&target_va))
            .ok_or_else(|| anyhow::anyhow!("native gateway target {target_va:#x} disappeared"))?;
        let local_op = target.ip_map[&target_va];
        let gateway_off = code.len();
        let bytes = build_native_entry_gateway(
            effective_code_va + gateway_off as u64,
            effective_code_va + code_offsets[target_index] as u64
                + built[target_index].dynamic_state_entry_offset.unwrap_or(0) as u64,
            effective_state_va + (target_index * MULTI_FAMILY_STATE_STRIDE) as u64,
            target.instruction_offsets[local_op] as u64,
            &vm::threaded::VmRuntimeLayout::from_seed(target.module_domain),
            lane_control_va,
            lane_group_stride as u64,
            host_stack_pool_va,
        )?;
        code.extend_from_slice(&bytes);
        native_entry_gateways.insert(target_va, gateway_off);
    }
    if code.len() != full_code_total {
        return Err(anyhow::anyhow!("native gateway sizing drift: {} != {}", code.len(), full_code_total));
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
            lifetime_cleanup_handler_offset,
            dynamic_state_entry_offset: None,
        },
        families: modules.iter().map(|module| module.family).collect(),
        state_offsets: (0..modules.len())
            .map(|index| index * MULTI_FAMILY_STATE_STRIDE)
            .collect(),
        code_ranges,
        table_ranges,
        bytecode_ranges,
        native_bridge_ranges,
        lifetime_cleanup_handler_offset,
        entry_byte_offset,
        chunks,
        lifetime_sync,
        invocation_layout,
        canonical_entry_gateway_offset,
        native_entry_gateways,
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

#[cfg(test)]
mod invocation_layout_tests {
    use super::*;

    #[test]
    fn global_tail_does_not_overlap_family_states_or_host_stacks() {
        let state_va = 0x0000_0001_6000_0000u64;
        let families = 4usize;
        let layout = multi_family_invocation_layout(state_va, families).unwrap();
        let groups_end = state_va
            + ((VM_INVOCATION_LANES + 1) * families * MULTI_FAMILY_STATE_STRIDE) as u64;
        let sync_end = layout.lifetime_sync_va
            + crate::vm::data_lifetime::LIFETIME_SYNC_TABLE_SIZE as u64;
        let host_end = layout.host_stack_pool_va
            + (VM_HOST_STACK_SLOTS * VM_HOST_STACK_SIZE) as u64;
        let reserve_end = state_va + layout.reserve_size as u64;

        assert!(layout.lane_control_va >= groups_end);
        assert!(layout.lifetime_sync_va >= layout.lane_control_va + VM_LANE_CONTROL_SIZE as u64);
        assert!(layout.host_stack_pool_va >= sync_end);
        assert!(host_end <= reserve_end);
        assert_eq!(layout.host_stack_pool_va & (VM_STATE_TAIL_ALIGN as u64 - 1), 0);
    }
}
