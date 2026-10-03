// ==============================================================================
// BTG v26+ - P3 (G1): Commercial-engine whole-program VM module builder
// ==============================================================================
//
// `build_program_vm_commercial` wraps a whole-program RISC lift (from
// `text_lift::lift_program_cfg_commercial`) that has been `PolymorphicEncoder`-
// encoded into rolling-key bytecode, into the same `VmModule { code, table,
// bytecode }` shape the existing `place.rs` program-VM embed path expects. The
// module is:
//
//   code     = [self-decoding rolling-key dispatcher] (entry + subroutines +
//              handlers + dispatch loop)
//   table    = [256 x u64 handler table][256 x u16 operand-offset table]
//              [256 x u8 operand-kind table]  (0xA00 bytes)
//   bytecode = polymorphic rolling-key bytecode (at-rest encrypted)
//
// The dispatcher is the *verified* T1-4 commercial execution engine
// (`poly_direct::build_self_decoding_parts`): at runtime it computes the
// rolling-key keystream byte for the current VIP, XORs it with the stream byte
// to recover the plaintext opcode/operand, advances the rolling-key state, and
// dispatches through the handler table with full operand decoding (register
// permutation + immediates). This replaces the previous broken generic
// 10-handler dispatch that could not decode operands and XORed the bytecode with
// a full-64-bit key (0xC0000005 root cause).
//
// Win64 ABI: the dispatcher entry pushes R12..R15 and sets up the commercial
// ABI (R8=bytecode base, R12=VIP=0, R13=virtual stack top, R14=rolling key,
// R15=handler table, RDX=state) then enters the dispatch loop. HALT pops
// R12..R15 and returns to the boot stub (which pre-loads the original entry GPRs
// into the state buffer at `state_va` and calls the module entry).
// ==============================================================================

use crate::vm::table_layout::TableLayout;
use crate::vm::threaded::{PreparedSuperOpProgram, VmRuntimeLayout};
use crate::vm::VmModule;
use anyhow::Result;
use std::collections::HashMap;

/// Complete native VM state, including private family/control/codec regions.
/// The independent virtual stack is an internal window in this extent.
pub const COMMERCIAL_STATE_SIZE: u64 = crate::vm::threaded::runtime_layout::SPLIT_STATE_SIZE as u64;

/// Virtual stack occupies state+0x2000..0x4000, below routing/codec/family state.
/// The invocation call-stack pool occupies state+0x6000..0x8000 independently.
pub const VIRTUAL_STACK_SIZE: u64 = 0x2000;

/// P3 (G1): --vm-oep 상용 엔진 백엔드 프로그램 VM 모듈.
///
/// `lift_program_cfg_commercial`(RISC) + `PolymorphicEncoder`로 만든 폴리모픽
/// 롤링키 바이트코드를, `place.rs`의 기존 `VmModule`{code, table, bytecode} 임베드
/// 경로에 그대로 꽂히는 모듈로 감싼다:
///
/// * `code`    — [self-decoding rolling-key dispatcher] (poly_direct codegen,
///               T1-4에서 검증된 경로). entry stub은 Win64 callee-saved(R12..R15)
///               저장 후 commercial ABI(R8=bytecode base, R12=VIP=0,
///               R13=virtual stack top, R14=rolling key, R15=handler table,
///               RDX=state)를 세팅하고 dispatch loop에 진입.
/// * `table`   — [256 x u64 handler table][256 x u16 operand-offset][256 x u8
///               operand-kind] plus condition/branch metadata. The widened
///               offset ABI addresses both P2-14 physical state banks.
/// * `bytecode`— 폴리모픽 롤링키 바이트코드 (at-rest 암호화 대상).
///
/// 상용 경로 실행 정합(부트 스텁이 state 버퍼에 entry GPR을 심고 이 엔트리로
/// 디스패치하는 것)은 `run_native_poly_direct`(== `PolymorphicInterpreter` ==
/// `RiscProgram::eval_state`, 선형 블록 단위 동치)로 검증된 엔진을 재사용한다.
pub fn build_program_vm_commercial(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    state_va: u64,
    seed: u64,
    ip_map: Option<&HashMap<u64, usize>>,
) -> Result<VmModule> {
    build_program_vm_commercial_with_superops(
        code_va,
        table_va,
        bytecode_va,
        bytecode,
        state_va,
        seed,
        ip_map,
        None,
    )
}

pub fn build_program_vm_commercial_with_superops(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    state_va: u64,
    seed: u64,
    ip_map: Option<&HashMap<u64, usize>>,
    prepared: Option<&PreparedSuperOpProgram>,
) -> Result<VmModule> {
    build_program_vm_commercial_with_superops_and_chunks(
        code_va,
        table_va,
        bytecode_va,
        bytecode,
        state_va,
        seed,
        ip_map,
        prepared,
        &[],
    )
}

pub fn build_program_vm_commercial_with_superops_and_chunks(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    state_va: u64,
    seed: u64,
    ip_map: Option<&HashMap<u64, usize>>,
    prepared: Option<&PreparedSuperOpProgram>,
    chunks: &[crate::vm::chunk_crypto::BytecodeChunk],
) -> Result<VmModule> {
    build_program_vm_commercial_with_superops_and_chunks_for_family(
        code_va,
        table_va,
        bytecode_va,
        bytecode,
        state_va,
        seed,
        crate::vm::poly::VmArchitectureFamily::for_build(seed),
        ip_map,
        prepared,
        chunks,
    )
}

pub fn build_program_vm_commercial_with_superops_and_chunks_for_family(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    state_va: u64,
    seed: u64,
    family: crate::vm::poly::VmArchitectureFamily,
    ip_map: Option<&HashMap<u64, usize>>,
    prepared: Option<&PreparedSuperOpProgram>,
    chunks: &[crate::vm::chunk_crypto::BytecodeChunk],
) -> Result<VmModule> {
    build_program_vm_commercial_with_routes_for_family(
        code_va,
        table_va,
        bytecode_va,
        bytecode,
        state_va,
        seed,
        family,
        ip_map,
        prepared,
        chunks,
        &[],
    )
}

pub fn build_program_vm_commercial_with_routes_for_family(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    state_va: u64,
    seed: u64,
    family: crate::vm::poly::VmArchitectureFamily,
    ip_map: Option<&HashMap<u64, usize>>,
    prepared: Option<&PreparedSuperOpProgram>,
    chunks: &[crate::vm::chunk_crypto::BytecodeChunk],
    routes: &[crate::vm::threaded::poly_direct::NativeCrossFamilyRoute],
) -> Result<VmModule> {
    build_program_vm_commercial_with_routes_and_pointer_rewrites_for_family(
        code_va,
        table_va,
        bytecode_va,
        bytecode,
        state_va,
        seed,
        family,
        ip_map,
        prepared,
        chunks,
        routes,
        &[],
        &[],
    )
}

pub fn build_program_vm_commercial_with_routes_and_pointer_rewrites_for_family(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    state_va: u64,
    seed: u64,
    family: crate::vm::poly::VmArchitectureFamily,
    ip_map: Option<&HashMap<u64, usize>>,
    prepared: Option<&PreparedSuperOpProgram>,
    chunks: &[crate::vm::chunk_crypto::BytecodeChunk],
    routes: &[crate::vm::threaded::poly_direct::NativeCrossFamilyRoute],
    native_pointer_rewrites: &[(u64, u64)],
    native_call_rewrites: &[(u64, u64)],
) -> Result<VmModule> {
    use sha2::{Digest, Sha256};
    let plan = crate::vm::poly::VariantPlan::generate(Sha256::digest(&bytecode).into(),
        seed, family, crate::vm::poly::VariantPolicy::Stable)?;
    build_program_vm_commercial_with_variant_plan(code_va, table_va, bytecode_va,
        bytecode, state_va, &plan, ip_map, prepared, chunks, routes,
        native_pointer_rewrites, native_call_rewrites)
}

pub fn build_program_vm_commercial_with_variant_plan(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    state_va: u64,
    variant_plan: &crate::vm::poly::VariantPlan,
    ip_map: Option<&HashMap<u64, usize>>,
    prepared: Option<&PreparedSuperOpProgram>,
    chunks: &[crate::vm::chunk_crypto::BytecodeChunk],
    routes: &[crate::vm::threaded::poly_direct::NativeCrossFamilyRoute],
    native_pointer_rewrites: &[(u64, u64)],
    native_call_rewrites: &[(u64, u64)],
) -> Result<VmModule> {
    let seed = variant_plan.isa().seed;
    let family = variant_plan.isa().family;
    // Virtual stack top: right after the state buffer (COMMERCIAL_STATE_SIZE),
    // Prepared super-op metadata is not yet canonically serializable: never
    // reuse those modules. Sort maps so process-specific HashMap ordering is
    // not part of the cache identity.
    let cache = crate::build_cache::active().filter(|_| prepared.is_none());
    let variant_identity = variant_plan.digest();
    let checkpoint = cache.map(|cache| {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"commercial-module-v2");
        hash.update(variant_identity);
        if let Some(settings) = crate::vm::handler_table_codec::active() {
            hash.update(b"handler-codec-v2");
            hash.update(settings.cache_identity());
        }
        hash.update(&bytecode);
        let mut ips: Vec<_> = ip_map.into_iter().flat_map(|map| map.iter()).map(|(&a, &b)| (a, b)).collect();
        ips.sort_unstable();
        hash.update(format!("{code_va}:{table_va}:{bytecode_va}:{state_va}:{seed}:{family:?}:{ips:?}:{}:{chunks:?}:{routes:?}:{native_pointer_rewrites:?}:{native_call_rewrites:?}", ip_map.is_some()).as_bytes());
        let name = format!("module-{:x}.pkg", hash.finalize());
        (cache, name)
    });
    if let Some((cache, name)) = &checkpoint {
        if let Some(payload) = cache.read(name) {
            if let Some((module, _plan)) = crate::build_cache::decode_variant_module(&payload, &bytecode,
                variant_plan.table_layout().total_size, &variant_identity) {
                log::info!("Resuming completed commercial VM module: {name}");
                return Ok(module);
            }
        }
    }
    let stack_base = state_va
        .checked_add(crate::vm::threaded::runtime_layout::VIRTUAL_STACK_TOP as u64)
        .ok_or_else(||anyhow::anyhow!("commercial virtual stack address overflow"))?;

    let layout = variant_plan.table_layout();
    if let Some(prepared) = prepared {
        if prepared.bytecode != bytecode {
            return Err(anyhow::anyhow!(
                "P5 prepared bytecode differs from commercial module input"
            ));
        }
    }
    let parts = if let Some(prepared) = prepared {
        crate::vm::threaded::poly_direct::build_self_decoding_parts_with_variant_plan(
            &bytecode,
            variant_plan,
            code_va,
            table_va,
            bytecode_va,
            state_va,
            stack_base,
            ip_map,
            &prepared.assigned,
            Some(&prepared.metadata),
            chunks,
            routes,
            native_pointer_rewrites,
            native_call_rewrites,
        )?
    } else {
        crate::vm::threaded::poly_direct::build_self_decoding_parts_with_variant_plan(
            &bytecode,
            variant_plan,
            code_va,
            table_va,
            bytecode_va,
            state_va,
            stack_base,
            ip_map,
            &[],
            None,
            chunks,
            routes,
            native_pointer_rewrites,
            native_call_rewrites,
        )?
    };

    // ── table blob: seed-jittered handler / operand / condition / branch maps ──
    // The generated dispatcher uses the same `layout` values relative to R15.
    // Layout is therefore part of the build ABI, not a fixed file signature.
    let table_len = layout
        .total_size
        .max(layout.branch_map_off.saturating_add(parts.branch_map.len()));
    let mut table = vec![0u8; table_len];
    for (i, v) in parts.table.iter().enumerate() {
        let off = layout.handler_table_off + i * 8;
        table[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    for (index, value) in parts.offs_tab.iter().copied().enumerate() {
        let off = layout.operand_offs_off + index * 2;
        table[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    table[layout.operand_flags_off..layout.operand_flags_off + 256]
        .copy_from_slice(&parts.flags_tab);
    table[layout.cond_codes_off..layout.cond_codes_off + 256].copy_from_slice(&parts.cond_codes);
    table[layout.branch_map_off..layout.branch_map_off + parts.branch_map.len()]
        .copy_from_slice(&parts.branch_map);

    // 상용(poly) 모듈은 bytecode handler 테이블을 쓰지 않으므로 handler_offsets 없음.
    let module = VmModule {
        code: parts.code,
        table,
        bytecode,
        handler_offsets: Vec::new(),
        native_bridge_range: parts.native_bridge_range,
        lifetime_cleanup_handler_offset: parts.lifetime_cleanup_handler_offset,
        dynamic_state_entry_offset: Some(parts.dynamic_state_entry_offset),
    };
    if let Some((cache, name)) = checkpoint {
        if let Err(error) = cache.write(&name, &crate::build_cache::encode_variant_module(&module,
            variant_plan)) {
            log::warn!("Could not save VM module checkpoint: {error}");
        }
    }
    Ok(module)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_commercial_placement_and_nested_family_call_match_reference() {
        let _guard = crate::vm::handler_table_codec::activate(
            crate::vm::handler_table_codec::BuildSettings::with_private_key([0x79;32]));
        test_commercial_module_executes_matches_reference();
        native_cross_family_route_calls_child_and_resumes_parent();
    }
    use crate::vm::arena::Arena;
    use crate::vm::poly::PolymorphicEncoder;
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscDesynthesizer, RiscOp, RiscProgram};

    /// P3 (G1): the module produced by `build_program_vm_commercial` — its
    /// self-decoding rolling-key dispatcher code — when embedded at the VAs it
    /// was built for, must execute a representative linear block exactly like
    /// `RiscProgram::eval_state` (linear-block unit equivalence contract).
    #[test]
    fn test_commercial_module_executes_matches_reference() {
        verify_commercial_module_plan(false);
    }

    #[test]
    fn restored_variant_plan_with_independent_layout_executes_matches_reference() {
        verify_commercial_module_plan(true);
    }

    fn verify_commercial_module_plan(independent_layout: bool) {
        // Representative linear block (no taken branches — linear-block contract):
        //   R0 = 0x200 ; R1 = 5 ; R2 = R0 >> R1 ; R3 = R0 << 2 ; R4 = R0 - R1
        //   push R3 ; push R0 ; pop R4 ; R5 = ~(R2|R1) ; flags = 0x8C1 ; Halt
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x200),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(5),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftRight)
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftLeft)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(2)),
        );
        d.emit_sub(
            MicroOperand::VReg(4),
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
        );
        d.emit_push(MicroOperand::VReg(3));
        d.emit_push(MicroOperand::VReg(0));
        d.emit_pop(MicroOperand::VReg(4));
        d.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::VReg(1)),
        );
        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = crate::vm::risc::RiscProgram::new(d.instrs);

        let init = [0u64; 16];
        let ref_st = prog.eval_state(&init);

        let seed = 0x1122334455667788u64;
        // A valid restored contract may choose state/table layouts independently
        // of its ISA seed. Regenerating either layout would corrupt this run.
        let layout_seed = if independent_layout { seed ^ 0xa5a5 } else { seed };
        let original_plan = crate::vm::poly::VariantPlan::from_contract([0x57;32],
            crate::vm::poly::VirtualIsaSpec::from_seed_and_family(seed,
                crate::vm::poly::VmArchitectureFamily::Stack),
            VmRuntimeLayout::from_seed(layout_seed), TableLayout::from_seed(layout_seed)).unwrap();
        let plan = crate::vm::poly::VariantPlan::restore(&original_plan.canonical_bytes(),
            &original_plan.digest()).unwrap();
        let runtime_layout = plan.runtime_layout().clone();
        let mut enc = PolymorphicEncoder::from_variant_plan(&plan);
        let bytecode = enc.encode(&prog).unwrap();

        // Sizing pass: code/table/bytecode lengths are VA-independent (all
        // runtime anchors use fixed-size RIP-rel32 encodings), so build once
        // with dummy VAs to learn lengths, then lay out and rebuild with real VAs.
        let dummy = build_program_vm_commercial_with_variant_plan(
            0,
            0x100000,
            0x200000,
            bytecode.clone(),
            0x300000,
            &plan,
            None, None, &[], &[], &[], &[],
        )
        .expect("commercial module sizing");
        let code_len = dummy.code.len();
        let table_len = dummy.table.len();
        // The commercial metadata ABI is seed-jittered.  A linear block's
        // branch map has only its 4-byte count, so the reserved layout size
        // remains the table size.
        assert_eq!(
            table_len,
            plan.table_layout().total_size,
            "table blob must honor the seed layout"
        );

        // Real layout inside the arena (matching place.rs: [code][table][bytecode][state]).
        let code_off = 0x1000usize;
        let table_off = code_off + ((code_len + 0xF) & !0xF);
        let bytecode_off = table_off + table_len;
        let state_off = bytecode_off + bytecode.len();
        let stack_off = state_off + crate::vm::threaded::runtime_layout::VIRTUAL_STACK_TOP;

        let mut arena = Arena::new(0x20000).unwrap();
        let base = arena.base;
        let code_va = (base + code_off) as u64;
        let table_va = (base + table_off) as u64;
        let bytecode_va = (base + bytecode_off) as u64;
        let state_va = (base + state_off) as u64;

        let module = build_program_vm_commercial_with_variant_plan(
            code_va,
            table_va,
            bytecode_va,
            bytecode.clone(),
            state_va,
            &plan,
            None, None, &[], &[], &[], &[],
        )
        .expect("commercial module build");

        // Place into arena at the built VAs.
        {
            let buf = arena.bytes();
            buf[code_off..code_off + module.code.len()].copy_from_slice(&module.code);
            buf[table_off..table_off + module.table.len()].copy_from_slice(&module.table);
            buf[bytecode_off..bytecode_off + module.bytecode.len()]
                .copy_from_slice(&module.bytecode);
            // init state buffer
            buf[state_off..state_off + runtime_layout.total_size].fill(0);
            for (i, v) in init.iter().enumerate() {
                let off = runtime_layout.vregs[i] as usize;
                buf[state_off + off..state_off + off + 8].copy_from_slice(&v.to_le_bytes());
            }
        }

        // P2-12: entry runtime anchors must be RIP-relative. No absolute
        // mov-imm64 relocation slot may expose the table/bytecode/state bundle.
        let va_lo = (base) as u64;
        let va_hi = (base + 0x20000) as u64;
        let slots = crate::pe::reloc::scan_mov_imm64_slots(&module.code, va_lo, va_hi);
        let mut rip_targets = Vec::new();
        let mut decoder =
            iced_x86::Decoder::with_ip(64, &module.code, code_va, iced_x86::DecoderOptions::NONE);
        while decoder.can_decode() {
            let ins = decoder.decode();
            if ins.code() == iced_x86::Code::Lea_r64_m
                && ins.memory_base() == iced_x86::Register::RIP
            {
                rip_targets.push(ins.ip_rel_memory_address());
            }
        }
        for (label, want) in [
            ("table_va", table_va),
            ("bytecode_va", bytecode_va),
            ("state_va", state_va),
        ] {
            assert!(
                rip_targets.contains(&want),
                "dispatcher must derive {label} ({want:#x}) through RIP-relative LEA"
            );
            assert!(
                !slots.iter().any(|&off| u64::from_le_bytes(
                    module.code[off as usize..off as usize + 8]
                        .try_into()
                        .unwrap()
                ) == want),
                "dispatcher leaked {label} as mov-imm64"
            );
        }

        arena.call(code_off);

        let buf = arena.bytes();
        let s = state_off;
        let mut nat = crate::vm::risc::RiscEvalState::default();
        for i in 0..16 {
            let off = runtime_layout.vregs[i] as usize;
            nat.regs[i] = u64::from_le_bytes(buf[s + off..s + off + 8].try_into().unwrap());
        }
        for i in 0..8 {
            let off = runtime_layout.temps[i] as usize;
            nat.temps[i] = u64::from_le_bytes(buf[s + off..s + off + 8].try_into().unwrap());
        }
        let flags_off = runtime_layout.flags as usize;
        let vsp_off = runtime_layout.vsp as usize;
        nat.flags = u64::from_le_bytes(buf[s + flags_off..s + flags_off + 8].try_into().unwrap());
        nat.vsp = u64::from_le_bytes(buf[s + vsp_off..s + vsp_off + 8].try_into().unwrap());

        assert_eq!(
            nat.regs, ref_st.regs,
            "regs mismatch (embedded module vs eval_state)"
        );
        assert_eq!(nat.temps, ref_st.temps, "temps mismatch");
        assert_eq!(
            nat.flags, ref_st.flags,
            "flags mismatch (nat={:#x} ref={:#x})",
            nat.flags, ref_st.flags
        );
        assert_eq!(
            nat.vsp, ref_st.vsp,
            "vsp mismatch (nat={:#x} ref={:#x})",
            nat.vsp, ref_st.vsp
        );
        // stack recovery
        let pending = if (nat.vsp as i64) < 0 {
            (-(nat.vsp as i64) as u64) / 8
        } else {
            0
        };
        assert!(
            pending < 4096,
            "vsp look corrupted: nat.vsp={:#x} (pending={}) — module did not complete correctly",
            nat.vsp,
            pending
        );
        for k in 0..pending as usize {
            let off = stack_off - (k + 1) * 8;
            let v = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            nat.stack.push(v);
        }
        assert_eq!(nat.stack, ref_st.stack, "stack mismatch");
    }

    #[test]
    fn commercial_module_uses_seed_jittered_metadata_layout() {
        let seed = 0xA17C_4B29_8E61_D305u64;
        let layout = TableLayout::from_seed(seed);
        assert_ne!(
            layout.operand_offs_off,
            TableLayout::legacy().operand_offs_off
        );
        assert_ne!(
            layout.operand_flags_off,
            TableLayout::legacy().operand_flags_off
        );
        assert_ne!(layout.cond_codes_off, TableLayout::legacy().cond_codes_off);

        let prog = crate::vm::risc::RiscProgram::new(vec![MicroInstr::new(RiscOp::Halt)]);
        let mut encoder = PolymorphicEncoder::new(seed);
        let bytecode = encoder.encode(&prog).expect("encode halt program");
        let module = build_program_vm_commercial(
            0x1400_1000,
            0x1400_8000,
            0x1400_A000,
            bytecode,
            0x1400_B000,
            seed,
            None,
        )
        .expect("build commercial module");

        assert_eq!(module.table.len(), layout.total_size);
        // Operand byte 0x01 represents an immediate.  Its kind must be stored
        // at the generated location, not the legacy +0x900 signature.
        assert_eq!(module.table[layout.operand_flags_off + 1], 1);
    }

    #[test]
    fn native_cross_family_route_calls_child_and_resumes_parent() {
        for parent in crate::vm::poly::VmArchitectureFamily::ALL {
            for child in crate::vm::poly::VmArchitectureFamily::ALL {
                if parent != child { verify_native_family_pair(parent, child); }
            }
        }
    }

    fn verify_native_family_pair(parent_family: crate::vm::poly::VmArchitectureFamily,
        child_family: crate::vm::poly::VmArchitectureFamily) {
        use crate::vm::poly::VmArchitectureFamily;
        use crate::vm::threaded::poly_direct::NativeCrossFamilyRoute;

        let parent_seed = 0x1111_2222_3333_4444;
        let child_seed = 0x9999_AAAA_BBBB_CCCC;
        let parent_layout = VmRuntimeLayout::from_seed(parent_seed);
        let child_layout = VmRuntimeLayout::from_seed(child_seed);
        let parent = RiscProgram::with_ip_map(
            vec![
                MicroInstr::new(RiscOp::Mov)
                    .with_dst(MicroOperand::VReg(1))
                    .with_src1(MicroOperand::Imm64(42)),
                MicroInstr::new(RiscOp::VirtualPush).with_src1(MicroOperand::Imm64(0x1002)),
                MicroInstr::new(RiscOp::VirtualBranch {
                    cond: crate::vm::risc::BranchCondition::Always,
                })
                .with_imm(0x2000),
                MicroInstr::new(RiscOp::Add {width:8})
                    .with_dst(MicroOperand::VReg(1))
                    .with_src1(MicroOperand::VReg(0)).with_src2(MicroOperand::Imm64(0)),
                MicroInstr::new(RiscOp::Halt),
            ],
            HashMap::from([(0x1000, 0), (0x1002, 3)]),
        );
        let child = RiscProgram::with_ip_map(
            std::iter::once(
                MicroInstr::new(RiscOp::Add {width:8})
                    .with_dst(MicroOperand::VReg(0))
                    .with_src1(MicroOperand::VReg(1)).with_src2(MicroOperand::Imm64(0)),
            )
            .chain([2usize, 8, 9, 10, 11].into_iter().map(|reg| {
                MicroInstr::new(RiscOp::Mov)
                    .with_dst(MicroOperand::VReg(reg as u8))
                    .with_src1(MicroOperand::Imm64(0xA000 + reg as u64))
            }))
            .chain(std::iter::once(MicroInstr::new(RiscOp::VirtualRet)))
            .collect(),
            HashMap::from([(0x2000, 0)]),
        );
        let parent = crate::vm::poly::family_lowering::lower(&parent,parent_family).unwrap().program;
        let child = crate::vm::poly::family_lowering::lower(&child,child_family).unwrap().program;
        let mut parent_encoder =
            PolymorphicEncoder::new_for_family(parent_seed, parent_family);
        let parent_bc = parent_encoder.encode(&parent).unwrap();
        let mut child_encoder =
            PolymorphicEncoder::new_for_family(child_seed, child_family);
        let child_bc = child_encoder.encode(&child).unwrap();

        let mut arena = Arena::new(0xA0000).unwrap();
        let base = arena.base as u64;
        let parent_code = base + 0x1000;
        let parent_table = base + 0x12000;
        let parent_bytecode = base + 0x16000;
        let parent_state = base + 0x18000;
        let parent_call_stack = base + 0x19000;
        let child_code = base + 0x30000;
        let child_table = base + 0x42000;
        let child_bytecode = base + 0x46000;
        let child_state = base + 0x48000;
        let child_call_stack = base + 0x49000;

        let child_module = build_program_vm_commercial_with_routes_for_family(
            child_code,
            child_table,
            child_bytecode,
            child_bc,
            child_state,
            child_seed,
            child_family,
            child.ip_map(),
            None,
            &[],
            &[],
        )
        .unwrap();
        let routes = [NativeCrossFamilyRoute {
            target_va: 0x2000,
            source_next_byte_offset: None,
            target_entry_va: child_code,
            target_state_va: child_state,
            child_lane_stride: 0,
            target_byte_offset: 0,
            target_layout: child_layout.clone(),
            tail_jump_resume_offset: None,
        }];
        let parent_module = build_program_vm_commercial_with_routes_for_family(
            parent_code,
            parent_table,
            parent_bytecode,
            parent_bc,
            parent_state,
            parent_seed,
            parent_family,
            parent.ip_map(),
            None,
            &[],
            &routes,
        )
        .unwrap();

        let buf = arena.bytes();
        for (module, code, table, bytecode) in [
            (&parent_module, parent_code, parent_table, parent_bytecode),
            (&child_module, child_code, child_table, child_bytecode),
        ] {
            let code = (code - base) as usize;
            let table = (table - base) as usize;
            let bytecode = (bytecode - base) as usize;
            buf[code..code + module.code.len()].copy_from_slice(&module.code);
            buf[table..table + module.table.len()].copy_from_slice(&module.table);
            buf[bytecode..bytecode + module.bytecode.len()].copy_from_slice(&module.bytecode);
        }
        for (state, call_stack, layout) in [
            (parent_state, parent_call_stack, &parent_layout),
            (child_state, child_call_stack, &child_layout),
        ] {
            let state = (state - base) as usize;
            buf[state..state + 0x260].fill(0);
            buf[state + crate::vm::interp::STATE_PTR_CALL_STACK
                ..state + crate::vm::interp::STATE_PTR_CALL_STACK + 8]
                .copy_from_slice(&call_stack.to_le_bytes());
            let guest_rsp = base + 0x90000;
            let rsp_off = layout.vregs[4] as usize;
            buf[state + rsp_off..state + rsp_off + 8].copy_from_slice(&guest_rsp.to_le_bytes());
        }

        arena.call((parent_code - base) as usize);
        let buf = arena.bytes();
        let child_state_off = (child_state - base) as usize;
        let child_rax_off = child_layout.vregs[0] as usize;
        assert_eq!(
            u64::from_le_bytes(
                buf[child_state_off + child_rax_off..child_state_off + child_rax_off + 8]
                    .try_into()
                    .unwrap()
            ),
            42,
            "child module must execute at the routed local VIP"
        );
        let child_vsp_off = child_layout.vsp as usize;
        assert_eq!(
            u64::from_le_bytes(
                buf[child_state_off + child_vsp_off..child_state_off + child_vsp_off + 8]
                    .try_into()
                    .unwrap()
            ),
            0,
            "cross-family invocation must leave the child operand stack empty"
        );
        for state in [parent_state, child_state] {
            let off = (state-base) as usize+crate::vm::poly::family_lowering::STACK_DEPTH as usize;
            assert_eq!(u64::from_le_bytes(buf[off..off+8].try_into().unwrap()),0,"family stack boundary must be empty");
        }
        let parent_state = (parent_state - base) as usize;
        for reg in [0usize, 1] {
            let off = parent_layout.vregs[reg] as usize;
            assert_eq!(
                u64::from_le_bytes(
                    buf[parent_state + off..parent_state + off + 8]
                        .try_into()
                        .unwrap()
                ),
                42,
                "parent vreg {reg} must observe child return and resume"
            );
        }
        for reg in [2usize, 8, 9, 10, 11] {
            let off = parent_layout.vregs[reg] as usize;
            assert_eq!(
                u64::from_le_bytes(
                    buf[parent_state + off..parent_state + off + 8]
                        .try_into()
                        .unwrap()
                ),
                0xA000 + reg as u64,
                "parent vreg {reg} must use child guest state, not dispatcher scratch"
            );
        }
    }
}
