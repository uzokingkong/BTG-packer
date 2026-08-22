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
//   table    = [256 x u64 handler table][256 x u8 operand-offset table]
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
use crate::vm::threaded::poly_direct::{
    build_self_decoding_parts_with_superops_and_chunks,
    build_self_decoding_parts_with_superops_and_chunks_for_family,
};
use crate::vm::threaded::{PreparedSuperOpProgram, VmRuntimeLayout};
use crate::vm::VmModule;
use anyhow::Result;
use std::collections::HashMap;

/// Commercial VM state buffer size (harness layout: REGS 0x80 + TEMPS 0x40 +
/// FLAGS + VSP + padding = 0x100). Used to place the virtual stack top (R13)
/// right after the state buffer for the embedded program VM.
pub const COMMERCIAL_STATE_SIZE: u64 = 0x100;

/// Virtual stack reserved below the state buffer (grows down from
/// state_va + COMMERCIAL_STATE_SIZE + VIRTUAL_STACK_SIZE). Mirrors the harness
/// arena's dedicated stack region so push/pop cannot collide with the state.
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
/// * `table`   — [256 x u64 handler table][256 x u8 operand-offset][256 x u8
///               operand-kind] = 0xA00 bytes. dispatcher가 R15-relative(+0x800,
///               +0x900)로 operand 테이블을 읽는다.
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
    // Virtual stack top: right after the state buffer (COMMERCIAL_STATE_SIZE),
    // growing down into the reserved VIRTUAL_STACK_SIZE region. Keeps the
    // dispatcher's R13-based push/pop isolated from both state and bytecode.
    let stack_base = state_va
        .wrapping_add(COMMERCIAL_STATE_SIZE)
        .wrapping_add(VIRTUAL_STACK_SIZE);

    let layout = TableLayout::from_seed(seed);
    let runtime_layout = VmRuntimeLayout::from_seed(seed);
    if let Some(prepared) = prepared {
        if prepared.bytecode != bytecode {
            return Err(anyhow::anyhow!(
                "P5 prepared bytecode differs from commercial module input"
            ));
        }
    }
    let parts = if let Some(prepared) = prepared {
        build_self_decoding_parts_with_superops_and_chunks_for_family(
            &bytecode,
            seed,
            family,
            code_va,
            table_va,
            bytecode_va,
            state_va,
            stack_base,
            ip_map,
            layout,
            runtime_layout,
            &prepared.assigned,
            Some(&prepared.metadata),
            chunks,
        )?
    } else {
        build_self_decoding_parts_with_superops_and_chunks_for_family(
            &bytecode,
            seed,
            family,
            code_va,
            table_va,
            bytecode_va,
            state_va,
            stack_base,
            ip_map,
            layout,
            runtime_layout,
            &[],
            None,
            chunks,
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
    table[layout.operand_offs_off..layout.operand_offs_off + 256].copy_from_slice(&parts.offs_tab);
    table[layout.operand_flags_off..layout.operand_flags_off + 256]
        .copy_from_slice(&parts.flags_tab);
    table[layout.cond_codes_off..layout.cond_codes_off + 256].copy_from_slice(&parts.cond_codes);
    table[layout.branch_map_off..layout.branch_map_off + parts.branch_map.len()]
        .copy_from_slice(&parts.branch_map);

    // 상용(poly) 모듈은 bytecode handler 테이블을 쓰지 않으므로 handler_offsets 없음.
    Ok(VmModule {
        code: parts.code,
        table,
        bytecode,
        handler_offsets: Vec::new(),
        native_bridge_range: parts.native_bridge_range,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::arena::Arena;
    use crate::vm::poly::PolymorphicEncoder;
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscDesynthesizer, RiscOp};

    /// P3 (G1): the module produced by `build_program_vm_commercial` — its
    /// self-decoding rolling-key dispatcher code — when embedded at the VAs it
    /// was built for, must execute a representative linear block exactly like
    /// `RiscProgram::eval_state` (linear-block unit equivalence contract).
    #[test]
    fn test_commercial_module_executes_matches_reference() {
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
        let runtime_layout = VmRuntimeLayout::from_seed(seed);
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();

        // Sizing pass: code/table/bytecode lengths are VA-independent (all
        // absolute references are fixed-size imm64/rel encodings), so build once
        // with dummy VAs to learn lengths, then lay out and rebuild with real VAs.
        let dummy = build_program_vm_commercial(
            0,
            0x100000,
            0x200000,
            bytecode.clone(),
            0x300000,
            seed,
            None,
        )
        .expect("commercial module sizing");
        let code_len = dummy.code.len();
        let table_len = dummy.table.len();
        // The commercial metadata ABI is seed-jittered.  A linear block's
        // branch map has only its 4-byte count, so the reserved layout size
        // remains the table size.
        assert_eq!(
            table_len,
            TableLayout::from_seed(seed).total_size,
            "table blob must honor the seed layout"
        );

        // Real layout inside the arena (matching place.rs: [code][table][bytecode][state]).
        let code_off = 0x1000usize;
        let table_off = code_off + ((code_len + 0xF) & !0xF);
        let bytecode_off = table_off + table_len;
        let state_off = bytecode_off + bytecode.len();
        let stack_off = state_off + COMMERCIAL_STATE_SIZE as usize + VIRTUAL_STACK_SIZE as usize;

        let mut arena = Arena::new(0x20000).unwrap();
        let base = arena.base;
        let code_va = (base + code_off) as u64;
        let table_va = (base + table_off) as u64;
        let bytecode_va = (base + bytecode_off) as u64;
        let state_va = (base + state_off) as u64;

        let module = build_program_vm_commercial(
            code_va,
            table_va,
            bytecode_va,
            bytecode.clone(),
            state_va,
            seed,
            None,
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
            buf[state_off..state_off + 0x100].fill(0);
            for (i, v) in init.iter().enumerate() {
                let off = runtime_layout.vregs[i] as usize;
                buf[state_off + off..state_off + off + 8].copy_from_slice(&v.to_le_bytes());
            }
        }

        // P0-5: dispatcher code 의 `mov r64, imm64` 절대 VA 슬롯이 이미지 범위
        // [base, base+0x20000) 안에 존재해야 한다 — ASLR 재배치(.reloc) 대상.
        // (module.code 는 arena 가 아닌 빌드 시점 VAs 를 즉시값으로 박는다.)
        // entry stub: R8=bytecode_base, R13=stack_base, R15=table_base, RDX=state_base
        // (code_va 는 arena.call 의 상대 점프로 진입하므로 imm64 로 박지 않는다.)
        let va_lo = (base) as u64;
        let va_hi = (base + 0x20000) as u64;
        let slots = crate::pe::reloc::scan_mov_imm64_slots(&module.code, va_lo, va_hi);
        for (label, want) in [
            ("table_va", table_va),
            ("bytecode_va", bytecode_va),
            ("state_va", state_va),
        ] {
            assert!(
                slots.iter().any(|&off| u64::from_le_bytes(
                    module.code[off as usize..off as usize + 8].try_into().unwrap()
                ) == want),
                "dispatcher must embed {label} (0x{want:X}) as a mov-imm64 relocatable slot ({} in-range slot(s): {:?})",
                slots.len(),
                slots
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
}
