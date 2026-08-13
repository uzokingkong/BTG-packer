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
        ip = match op {
            // ── register / immediate moves ───────────────────────────────
            OP_MOV_R_IMM32 | OP_MOV_R_IMM64 | OP_MOV_R_R | OP_MOV_R_R64 => {
                mov::exec(state, mem, code, ip, op)?
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
            | OP_BSR_R32 | OP_BSR_R64 | OP_BSF_R32 | OP_BSF_R64 => {
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
            | OP_PSHUFLW_XMM | OP_PSHUFHW_XMM | OP_PSHUFD_XMM => {
                xmm::exec(state, mem, code, ip, op)?
            }
            // ── atomic ───────────────────────────────────────────────────
            OP_CMPXCHG_MEM8_A | OP_CMPXCHG_MEM16_A | OP_CMPXCHG_MEM32_A | OP_CMPXCHG_MEM64_A
            | OP_XCHG_MEM8_A | OP_XCHG_MEM16_A | OP_XCHG_MEM32_A | OP_XCHG_MEM64_A
            | OP_XADD_MEM8_A | OP_XADD_MEM16_A | OP_XADD_MEM32_A | OP_XADD_MEM64_A => {
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
