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

use crate::vm::threaded::poly_direct::build_self_decoding_parts;
use crate::vm::VmModule;
use anyhow::Result;

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
) -> Result<VmModule> {
    // Virtual stack top: right after the state buffer (COMMERCIAL_STATE_SIZE),
    // growing down into the reserved VIRTUAL_STACK_SIZE region. Keeps the
    // dispatcher's R13-based push/pop isolated from both state and bytecode.
    let stack_base = state_va.wrapping_add(COMMERCIAL_STATE_SIZE).wrapping_add(VIRTUAL_STACK_SIZE);

    let parts = build_self_decoding_parts(
        &bytecode,
        seed,
        code_va,
        table_va,
        bytecode_va,
        state_va,
        stack_base,
    )?;

    // ── table blob: [256x8 handler][256x8 op-offset][256 op-kind] = 0xA00 ──
    // The dispatcher reads operand tables relative to R15 (handler table base):
    //   sub_resolve / sub_store use [R15 + (OFF_OP_OFFS - OFF_TABLE)] = +0x800
    //   and [R15 + (OFF_OP_FLAGS - OFF_TABLE)] = +0x900.
    // So the embedded table must place op-offset at table_va+0x800 and op-kind
    // at table_va+0x900.
    let mut table = Vec::with_capacity(0xA00);
    for v in &parts.table {
        table.extend_from_slice(&v.to_le_bytes());
    }
    debug_assert_eq!(table.len(), 0x800, "handler table must be 0x800 bytes");
    table.extend_from_slice(&parts.offs_tab); // at +0x800
    table.extend_from_slice(&parts.flags_tab); // at +0x900
    debug_assert_eq!(table.len(), 0xA00, "module table blob must be 0xA00 bytes");

    Ok(VmModule { code: parts.code, table, bytecode })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::arena::Arena;
    use crate::vm::poly::PolymorphicEncoder;
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscDesynthesizer, RiscOp};

    // State buffer offsets (harness layout, mirrors poly_direct).
    const REGS_OFF: usize = 0x000;
    const TEMPS_OFF: usize = 0x080;
    const FLAGS_OFF: usize = 0x0C0;
    const VSP_OFF: usize = 0x0C8;

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
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x200), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(5), MicroOperand::Imm64(0));
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
        d.emit_sub(MicroOperand::VReg(4), MicroOperand::VReg(0), MicroOperand::VReg(1));
        d.emit_push(MicroOperand::VReg(3));
        d.emit_push(MicroOperand::VReg(0));
        d.emit_pop(MicroOperand::VReg(4));
        d.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::VReg(1)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = crate::vm::risc::RiscProgram::new(d.instrs);

        let init = [0u64; 16];
        let ref_st = prog.eval_state(&init);

        let seed = 0x1122334455667788u64;
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();

        // Sizing pass: code/table/bytecode lengths are VA-independent (all
        // absolute references are fixed-size imm64/rel encodings), so build once
        // with dummy VAs to learn lengths, then lay out and rebuild with real VAs.
        let dummy = build_program_vm_commercial(0, 0x100000, 0x200000, bytecode.clone(), 0x300000, seed)
            .expect("commercial module sizing");
        let code_len = dummy.code.len();
        let table_len = dummy.table.len();
        assert_eq!(table_len, 0xA00, "table blob must be 0xA00");

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
            code_va, table_va, bytecode_va, bytecode.clone(), state_va, seed,
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
                buf[state_off + REGS_OFF + i * 8..state_off + REGS_OFF + i * 8 + 8]
                    .copy_from_slice(&v.to_le_bytes());
            }
        }

        arena.call(code_off);

        let buf = arena.bytes();
        let s = state_off;
        let mut nat = crate::vm::risc::RiscEvalState::default();
        for i in 0..16 {
            nat.regs[i] =
                u64::from_le_bytes(buf[s + REGS_OFF + i * 8..s + REGS_OFF + i * 8 + 8]
                    .try_into()
                    .unwrap());
        }
        for i in 0..8 {
            nat.temps[i] =
                u64::from_le_bytes(buf[s + TEMPS_OFF + i * 8..s + TEMPS_OFF + i * 8 + 8]
                    .try_into()
                    .unwrap());
        }
        nat.flags =
            u64::from_le_bytes(buf[s + FLAGS_OFF..s + FLAGS_OFF + 8].try_into().unwrap());
        nat.vsp = u64::from_le_bytes(buf[s + VSP_OFF..s + VSP_OFF + 8].try_into().unwrap());

        assert_eq!(nat.regs, ref_st.regs, "regs mismatch (embedded module vs eval_state)");
        assert_eq!(nat.temps, ref_st.temps, "temps mismatch");
        assert_eq!(nat.flags, ref_st.flags, "flags mismatch (nat={:#x} ref={:#x})", nat.flags, ref_st.flags);
        assert_eq!(nat.vsp, ref_st.vsp, "vsp mismatch (nat={:#x} ref={:#x})", nat.vsp, ref_st.vsp);
        // stack recovery
        let pending = if (nat.vsp as i64) < 0 { (-(nat.vsp as i64) as u64) / 8 } else { 0 };
        assert!(
            pending < 4096,
            "vsp look corrupted: nat.vsp={:#x} (pending={}) — module did not complete correctly",
            nat.vsp, pending
        );
        for k in 0..pending as usize {
            let off = stack_off - (k + 1) * 8;
            let v = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            nat.stack.push(v);
        }
        assert_eq!(nat.stack, ref_st.stack, "stack mismatch");
    }
}

