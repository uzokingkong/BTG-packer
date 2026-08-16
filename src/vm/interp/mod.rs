// ==============================================================================
// BTG v21 - VM Bytecode Reference Interpreter (Rust)
// ==============================================================================
//
// Executes the VM bytecode in software. Used by the --vm-test self-test to
// cross-check the generated x86-64 handlers: bytecode interpreted here must
// produce byte-identical results to the handlers executed natively.
//
// The interpreter models the runtime memory as two regions:
//   * `state` — the VM state buffer (layout below). Pointer slots hold
//     *offsets into `mem`* (the addressable arena). The real generated VM
//     instead holds absolute VAs in the slots; semantics are identical.
//   * `mem`   — the memory arena the virtualized routine reads/writes
//     (e.g. the S-box and masked seed arrays).
//
// This module is the directory entry point of the decomposed interpreter. The
// old interp.rs monolith was split into per-group submodules below; `interpret`
// (here) is the fetch/dispatch loop and `state` owns the layout + accessors.
//
//   mod.rs     - interpret loop + opcode dispatch + public re-exports
//   state.rs   - VM state layout constants + VmError + byte-buffer accessors
//   mov.rs     - MOV register/imm moves
//   arith.rs   - ADD/SUB/XOR/AND/OR/IMUL/TEST/CMP/INC/DEC/ROL/ROR/shift +
//                NEG/NOT/BSWAP/BSR/BSF/TZCNT/SETCC + CPUID/XGETBV
//   mem.rs     - memory loads/stores (slot-relative, wider, absolute) + LEA/RIP
//   branch.rs  - JMP/JB/JCC rel8/rel32
//   stack.rs   - PUSH/POP/CALL/RET (two-stack model)
//   xmm.rs     - XMM moves / shuffles / packed shifts / PINSRW
//   atomic.rs  - lock cmpxchg / xchg / xadd (Once/futex CAS) handlers
//   muldiv.rs  - 1-op mul/imul/div/idiv (8/16/32/64)
// ==============================================================================

use crate::vm::bytecode::*;

mod arith;
mod atomic;
mod branch;
mod mem;
mod mov;
mod muldiv;
mod stack;
mod state;
mod xmm;

// ── Public surface (unchanged from the pre-split interp.rs) ─────────────────
pub use state::{
    CALL_STACK_SIZE, NREG, STATE_CALL_SP, STATE_CALL_STACK_BUF, STATE_FLAGS, STATE_PTR_BUF,
    STATE_PTR_CALL_STACK, STATE_PTR_RUNS, STATE_PTR_SBOX, STATE_PTR_SEED, STATE_PTR_STACK,
    STATE_RIP, STATE_SEG_GS, STATE_SP, STATE_SIZE, STATE_VREGS, STATE_XMM, VmError,
};

/// Interpret `code` starting at ip=0.
/// `state` = VM state buffer, `mem` = memory arena (see module docs).
pub fn interpret(state: &mut [u8], mem: &mut [u8], code: &[u8]) -> Result<(), VmError> {
    let mut ip = 0usize;
    loop {
        if ip >= code.len() {
            return Err(VmError::OobIp(ip));
        }
        let op = code[ip];
        ip += 1;
        // 리뷰 지적 #13: 핸들러들이 code[ip+1], code[ip+1..ip+5] 등을 직접 읽으므로
        // 잘린 바이트코드가 들어오면 Rust panic 이 났다. opcode 의 고정 피연산자
        // 길이(opcode_operand_len)로 미리 범위를 확인해 `VmError::OobIp` 로 돌린다.
        if let Some(olen) = opcode_operand_len(op) {
            if ip.checked_add(olen).map(|end| end > code.len()).unwrap_or(true) {
                return Err(VmError::OobIp(ip));
            }
        }
        ip = match op {
            // ── register / immediate moves ───────────────────────────────
            OP_MOV_R_IMM32 | OP_MOV_R_IMM64 | OP_MOV_R_R | OP_MOV_R_R64
            | OP_MOV_R_FLAGS | OP_MOV_FLAGS_R => {
                mov::exec(state, mem, code, ip, op)?
            }
            // ── v65: Direction Flag (CLD/STD) ─────────────────────────────
            OP_CLD | OP_STD => {
                let df = op == OP_STD;
                state::set_df(state, df);
                ip
            }
            // ── arithmetic / logical / shifts / bitwise ──────────────────
            OP_XOR_R_R | OP_ADD_R_R | OP_IMUL_R_R | OP_SUB_R_R | OP_AND_R_R
            | OP_AND_R_IMM32 | OP_XOR_R_IMM32 | OP_ADD_R_IMM32 | OP_ROL_R_IMM8
            | OP_ROR_R_IMM8 | OP_INC_R | OP_DEC_R | OP_CMP_R_IMM32 | OP_SETCC
            | OP_ADD_R_R64 | OP_SUB_R_R64 | OP_XOR_R_R64 | OP_AND_R_R64 | OP_IMUL_R_R64
            | OP_ADD_R_IMM64 | OP_XOR_R_IMM64 | OP_AND_R_IMM64
            | OP_SHL_R_IMM8 | OP_SHR_R_IMM8 | OP_SAR_R_IMM8
            | OP_SHL_R_CL | OP_SHR_R_CL | OP_SAR_R_CL
            | OP_TEST_R_R32 | OP_TEST_R_IMM32
            | OP_OR_R_R | OP_OR_R_R64 | OP_OR_R_IMM32 | OP_OR_R_IMM64
            | OP_NEG_R | OP_NEG_R64 | OP_NOT_R | OP_NOT_R64
            | OP_SHL64_R_IMM8 | OP_SHR64_R_IMM8 | OP_SAR64_R_IMM8
            | OP_SHL64_R_CL | OP_SHR64_R_CL | OP_SAR64_R_CL
            | OP_TZCNT_R32 | OP_CPUID | OP_XGETBV
            | OP_BSWAP_R32 | OP_BSWAP_R64
            | OP_BSR_R32 | OP_BSR_R64 | OP_BSF_R32 | OP_BSF_R64
            | OP_LZCNT_R32 | OP_LZCNT_R64 | OP_POPCNT_R32 | OP_POPCNT_R64
            | OP_BLSR_R32 | OP_BLSR_R64 | OP_BLSMSK_R32 | OP_BLSMSK_R64
            | OP_BLSI_R32 | OP_BLSI_R64 | OP_ANDN_R_R32 | OP_ANDN_R_R64 => {
                arith::exec(state, mem, code, ip, op)?
            }
            // ── memory / addressing modes ────────────────────────────────
            OP_MOVZX_R_MEM8 | OP_MOV_MEM8_R
            | OP_MOVZX_R_MEM16 | OP_MOVZX_R_MEM32 | OP_MOVSX_R_MEM8 | OP_MOVSX_R_MEM16
            | OP_MOV_R_MEM64 | OP_MOV_MEM16_R | OP_MOV_MEM32_R | OP_MOV_MEM64_R
            | OP_LEA | OP_SET_RIP | OP_LEA_RIP | OP_LEA_GS
            | OP_MOVZX_R_MEM8_A | OP_MOVZX_R_MEM16_A | OP_MOVZX_R_MEM32_A
            | OP_MOVSX_R_MEM8_A | OP_MOVSX_R_MEM16_A | OP_MOV_R_MEM64_A
            | OP_MOV_MEM8_A | OP_MOV_MEM16_A | OP_MOV_MEM32_A | OP_MOV_MEM64_A => {
                mem::exec(state, mem, code, ip, op)?
            }
            // ── control flow ─────────────────────────────────────────────
            OP_JMP8 | OP_JB8 | OP_JCC8 | OP_JMP32 | OP_JCC32 => {
                branch::exec(state, mem, code, ip, op)?
            }
            // ── stack / call / ret ───────────────────────────────────────
            OP_PUSH_R | OP_POP_R | OP_CALL8 | OP_RET | OP_RET_IMM16 | OP_CALL32 => {
                stack::exec(state, mem, code, ip, op)?
            }
            // ── XMM ──────────────────────────────────────────────────────
            OP_PINSRW_XMM | OP_MOVSD_XMM_MEM | OP_MOVQ_XMM_GPR | OP_MOVQ_GPR_XMM
            | OP_MOVSD_MEM_XMM | OP_MOVUPS_XMM_MEM | OP_MOVUPS_MEM_XMM
            | OP_UNPCKLPD_XMM | OP_UNPCKLPS_XMM | OP_XORPS_XMM
            | OP_PSRLQ_XMM_IMM8 | OP_PSLLQ_XMM_IMM8
            | OP_PSHUFLW_XMM | OP_PSHUFHW_XMM | OP_PSHUFD_XMM
            // ── v54: SSE/FPU (Group A) ───────────────────────────────────
            | OP_ADDSS_XMM | OP_ADDSD_XMM | OP_SUBSS_XMM | OP_SUBSD_XMM
            | OP_MULSS_XMM | OP_MULSD_XMM | OP_DIVSS_XMM | OP_DIVSD_XMM
            | OP_PAND_XMM | OP_POR_XMM | OP_PANDN_XMM
            | OP_CVTSI2SD_XMM | OP_CVTSI2SS_XMM | OP_CVTSS2SD_XMM | OP_CVTSD2SS_XMM
            | OP_CVTTSS2SI | OP_CVTTSD2SI | OP_CVTSS2SI | OP_CVTSD2SI
            | OP_PEXTRD_XMM | OP_PINSRD_XMM => {
                xmm::exec(state, mem, code, ip, op)?
            }
            // ── atomic ───────────────────────────────────────────────────
            OP_CMPXCHG_MEM8_A | OP_CMPXCHG_MEM16_A | OP_CMPXCHG_MEM32_A | OP_CMPXCHG_MEM64_A
            | OP_XCHG_MEM8_A | OP_XCHG_MEM16_A | OP_XCHG_MEM32_A | OP_XCHG_MEM64_A
            | OP_XADD_MEM8_A | OP_XADD_MEM16_A | OP_XADD_MEM32_A | OP_XADD_MEM64_A
            | OP_LOCK_INC_MEM8_A | OP_LOCK_INC_MEM16_A | OP_LOCK_INC_MEM32_A | OP_LOCK_INC_MEM64_A
            | OP_LOCK_DEC_MEM8_A | OP_LOCK_DEC_MEM16_A | OP_LOCK_DEC_MEM32_A | OP_LOCK_DEC_MEM64_A => {
                atomic::exec(state, mem, code, ip, op)?
            }
            // ── 1-op multiply / divide (accumulator pair) ────────────────
            OP_MUL_R_R32 | OP_MUL_R_R64 | OP_IMUL1_R_R32 | OP_IMUL1_R_R64
            | OP_DIV_R_R32 | OP_DIV_R_R64 | OP_IDIV_R_R32 | OP_IDIV_R_R64
            | OP_MUL_R_R8 | OP_MUL_R_R16 | OP_IMUL1_R_R8 | OP_IMUL1_R_R16
            | OP_DIV_R_R8 | OP_DIV_R_R16 | OP_IDIV_R_R8 | OP_IDIV_R_R16 => {
                muldiv::exec(state, mem, code, ip, op)?
            }
            OP_HALT => return Ok(()),
            // ── no-ops ───────────────────────────────────────────────────
            // The reference interpreter cannot call real native code; it models
            // the bridge ABI purely so bytecode that contains it still decodes
            // (the native handler is authoritative — self-test [13]).
            OP_NOP | OP_NATIVE_CALL => ip,
            other => return Err(VmError::UnknownOpcode(other)),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 리뷰 지적 #13: 잘린(truncated) 바이트코드가 panic 이 아니라 `VmError::OobIp`
    /// 를 반환해야 한다 (핸들러가 code[ip+1..] 등을 직접 읽기 전 사전검증).
    #[test]
    fn truncated_bytecode_returns_oob_ip_not_panic() {
        let mut st = vec![0u8; state::STATE_SIZE];
        let mut mem = vec![0u8; 0x1000];

        // OP_MOV_R_IMM32 (0x01) — 피연산자 5바이트 필요, 1바이트만 제공.
        let truncated = [0x01u8, 0x00];
        let r = interpret(&mut st, &mut mem, &truncated);
        assert!(
            matches!(r, Err(VmError::OobIp(_))),
            "truncated MOV_R_IMM32 must return OobIp, got {r:?}"
        );

        // OP_LEA (0x34) — 피연산자 8바이트 필요, 3바이트만 제공.
        let truncated2 = [0x34u8, 0x00, 0x01, 0x02];
        let r2 = interpret(&mut st, &mut mem, &truncated2);
        assert!(
            matches!(r2, Err(VmError::OobIp(_))),
            "truncated LEA must return OobIp, got {r2:?}"
        );

        // 정상 바이트코드는 여전히 동작 (MOV_R_IMM32 + HALT).
        let mut b = BytecodeBuilder::new();
        b.mov_r_imm32(0, 42);
        b.halt();
        let ok = interpret(&mut st, &mut mem, &b.finish());
        assert!(ok.is_ok(), "valid bytecode must still interpret: {ok:?}");
    }

    /// 리뷰 지적 #9: RET without CALL must be an explicit error, not a silent
    /// wrapping read of the (empty) return-IP stack.
    #[test]
    fn ret_without_call_returns_call_stack_underflow() {
        let mut st = vec![0u8; state::STATE_SIZE];
        let mut mem = vec![0u8; 0x1000];
        // Empty return-IP stack (the VM entry convention): csp == CALL_STACK_SIZE.
        st[state::STATE_CALL_SP..state::STATE_CALL_SP + 8]
            .copy_from_slice(&(state::CALL_STACK_SIZE as u64).to_le_bytes());
        let prog = [OP_RET];
        let r = interpret(&mut st, &mut mem, &prog);
        assert!(
            matches!(r, Err(VmError::CallStackUnderflow)),
            "RET with an empty return-IP stack must error, got {r:?}"
        );
    }

    /// 리뷰 지적 #9: exceeding the reserved return-IP stack depth (CALL_STACK_SIZE
    /// bytes = 1024 entries) must be an explicit overflow error.
    #[test]
    fn call_depth_overflow_returns_call_stack_overflow() {
        let mut st = vec![0u8; state::STATE_SIZE];
        let mut mem = vec![0u8; 0x20000];
        // Reserve the call-stack buffer region so deep calls have room in `mem`.
        // base must be >= CALL_STACK_SIZE so even the deepest slot stays >= 0.
        let base = 0x10000usize;
        st[state::STATE_PTR_CALL_STACK..state::STATE_PTR_CALL_STACK + 8]
            .copy_from_slice(&(base as u64).to_le_bytes());
        // Empty stack top.
        st[state::STATE_CALL_SP..state::STATE_CALL_SP + 8]
            .copy_from_slice(&(state::CALL_STACK_SIZE as u64).to_le_bytes());

        let mut prog = Vec::new();
        for _ in 0..(state::CALL_STACK_SIZE / 8 + 2) {
            // OP_CALL8, rel=0 (self-call keeps ip advancing past this instr is
            // irrelevant — we only need the push to accumulate).
            prog.push(OP_CALL8);
            prog.push(0i8 as u8);
        }
        prog.push(OP_HALT);
        let r = interpret(&mut st, &mut mem, &prog);
        assert!(
            matches!(r, Err(VmError::CallStackOverflow(_))),
            "call depth past 1024 must error, got {r:?}"
        );
    }
}
