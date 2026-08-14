// ==============================================================================
// BTG v3 - VM Bytecode Format (MVP)
// ==============================================================================
//
// The composite-VM MVP defines a tiny register-based bytecode that is the
// *virtualized* form of a routine. The boot stub (or the VM test harness)
// executes it through generated x86-64 handlers (see handlers.rs).
//
// Encoding: opcode u8, then operands (little-endian). All register operands
// are u8 virtual-register indices (0..=15, mapping RAX..R15 by number()).
//
// Memory operands address one of the VM's pointer slots: the state buffer
// holds native pointers to the arrays the virtualized routine reads/writes.
//   memslot 0 = S-box   (ptr stored at STATE_PTR_SBOX)
//   memslot 1 = seed    (ptr stored at STATE_PTR_SEED)
//   memslot 2 = buffer  (ptr stored at STATE_PTR_BUF)
//   memslot 3 = runs    (ptr stored at STATE_PTR_RUNS)
//
// All arithmetic is 32-bit (matching the x86 r32 forms used by the
// virtualized boot-stub code); results are zero-extended into 64-bit vregs.
// Only the flags actually consumed by the virtualized code are modelled:
// CF (carry/unsigned-below from the last CMP), stored at STATE_FLAGS.
// ==============================================================================


// =============================================================================
// Opcode registry — SINGLE source of truth for the VM opcode set (P2-10).
// Every opcode is declared exactly once here as `(OP_NAME = 0x..: mnemonic, olen)`.
// The `opcodes!` macro expands this list into:
//   * the `pub const OP_*` value constants (used by handlers/interp/lifter),
//   * `NUM_OPS` (handler-table slot count, 0x00..=0x6B),
//   * an opcode->mnemonic table + `opcode_name()`, and
//   * an opcode->operand-length table + `opcode_operand_len()`.
// Adding an opcode = adding ONE line here; the 4 files (bytecode/handlers/interp/
// lifter) stay in sync automatically because they only consume these symbols.
// =============================================================================
macro_rules! opcodes {
    ( $( $name:ident = $val:literal : $mnem:literal , $olen:literal ; )* ) => {
        $(
            pub const $name: u8 = $val;
        )*

        /// Handler-table slot count (opcodes 0x00..=0xBB). 0x00 = invalid-opcode handler.
        pub const NUM_OPS: usize = 0xBC;

        /// Opcode -> (mnemonic, operand byte length after the opcode byte).
        pub const OPCODE_INFO: &[(u8, &'static str, usize)] = &[
            $( ($val, $mnem, $olen), )*
        ];

        /// Human-readable mnemonic for `op`, or "??" if unknown.
        pub fn opcode_name(op: u8) -> &'static str {
            OPCODE_INFO.iter().find(|(v, _, _)| *v == op).map(|(_, m, _)| *m).unwrap_or("??")
        }

        /// Operand byte length for `op` (bytes following the opcode byte), if defined.
        pub fn opcode_operand_len(op: u8) -> Option<usize> {
            OPCODE_INFO.iter().find(|(v, _, _)| *v == op).map(|(_, _, l)| *l)
        }
    };
}

opcodes! {
    OP_MOV_R_IMM32 = 0x01 : "mov" , 5 ;
    OP_MOV_R_IMM64 = 0x02 : "mov" , 9 ;
    OP_MOV_R_R = 0x03 : "mov" , 2 ;
    OP_XOR_R_R = 0x04 : "xor" , 2 ;
    OP_ADD_R_R = 0x05 : "add" , 2 ;
    OP_IMUL_R_R = 0x06 : "imul" , 2 ;
    OP_SUB_R_R = 0x07 : "sub" , 2 ;
    OP_AND_R_IMM32 = 0x08 : "and" , 5 ;
    OP_XOR_R_IMM32 = 0x09 : "xor" , 5 ;
    OP_ADD_R_IMM32 = 0x0A : "add" , 5 ;
    OP_ROL_R_IMM8 = 0x0B : "rol" , 2 ;
    OP_INC_R = 0x0C : "inc" , 1 ;
    OP_DEC_R = 0x0D : "dec" , 1 ;
    OP_CMP_R_IMM32 = 0x0E : "cmp" , 5 ;
    OP_MOVZX_R_MEM8 = 0x0F : "movzx" , 3 ;
    OP_MOV_MEM8_R = 0x10 : "mov" , 3 ;
    OP_JMP8 = 0x11 : "jmp" , 1 ;
    OP_JB8 = 0x12 : "jb" , 1 ;
    OP_HALT = 0x13 : "halt" , 0 ;
    OP_ROR_R_IMM8 = 0x14 : "ror" , 2 ;
    OP_AND_R_R = 0x15 : "and" , 2 ;
    OP_JCC8 = 0x16 : "jcc" , 2 ;
    OP_MOV_R_R64 = 0x17 : "mov64" , 2 ;
    OP_ADD_R_R64 = 0x18 : "add64" , 2 ;
    OP_SUB_R_R64 = 0x19 : "sub64" , 2 ;
    OP_XOR_R_R64 = 0x1A : "xor64" , 2 ;
    OP_AND_R_R64 = 0x1B : "and64" , 2 ;
    OP_IMUL_R_R64 = 0x1C : "imul64" , 2 ;
    OP_ADD_R_IMM64 = 0x1D : "add64" , 5 ;
    OP_XOR_R_IMM64 = 0x1E : "xor64" , 5 ;
    OP_AND_R_IMM64 = 0x1F : "and64" , 5 ;
    OP_SHL_R_IMM8 = 0x20 : "shl" , 2 ;
    OP_SHR_R_IMM8 = 0x21 : "shr" , 2 ;
    OP_SAR_R_IMM8 = 0x22 : "sar" , 2 ;
    OP_SHL_R_CL = 0x23 : "shl" , 1 ;
    OP_SHR_R_CL = 0x24 : "shr" , 1 ;
    OP_SAR_R_CL = 0x25 : "sar" , 1 ;
    OP_TEST_R_R32 = 0x26 : "test" , 2 ;
    OP_TEST_R_IMM32 = 0x27 : "test" , 5 ;
    OP_MOVZX_R_MEM16 = 0x28 : "movzx" , 3 ;
    OP_MOVZX_R_MEM32 = 0x29 : "movzx" , 3 ;
    OP_MOVSX_R_MEM8 = 0x2A : "movsx" , 3 ;
    OP_MOVSX_R_MEM16 = 0x2B : "movsx" , 3 ;
    OP_MOV_R_MEM64 = 0x2C : "mov" , 3 ;
    OP_MOV_MEM16_R = 0x2D : "mov" , 3 ;
    OP_MOV_MEM32_R = 0x2E : "mov" , 3 ;
    OP_MOV_MEM64_R = 0x2F : "mov" , 3 ;
    OP_PUSH_R = 0x30 : "push" , 1 ;
    OP_POP_R = 0x31 : "pop" , 1 ;
    OP_CALL8 = 0x32 : "call" , 1 ;
    OP_RET = 0x33 : "ret" , 0 ;
    OP_JMP32 = 0x56 : "jmp32" , 4 ;
    OP_JCC32 = 0x57 : "jcc32" , 5 ;
    OP_CALL32 = 0x58 : "call32" , 4 ;
    OP_LEA = 0x34 : "lea" , 8 ;
    OP_SET_RIP = 0x35 : "set_rip" , 8 ;
    OP_LEA_RIP = 0x36 : "lea_rip" , 5 ;
    OP_MOVZX_R_MEM8_A = 0x37 : "movzx" , 2 ;
    OP_MOVZX_R_MEM16_A = 0x38 : "movzx" , 2 ;
    OP_MOVZX_R_MEM32_A = 0x39 : "movzx" , 2 ;
    OP_MOVSX_R_MEM8_A = 0x3A : "movsx" , 2 ;
    OP_MOVSX_R_MEM16_A = 0x3B : "movsx" , 2 ;
    OP_MOV_R_MEM64_A = 0x3C : "mov" , 2 ;
    OP_MOV_MEM8_A = 0x3D : "mov" , 2 ;
    OP_MOV_MEM16_A = 0x3E : "mov" , 2 ;
    OP_MOV_MEM32_A = 0x3F : "mov" , 2 ;
    OP_MOV_MEM64_A = 0x40 : "mov" , 2 ;
    OP_NATIVE_CALL = 0x41 : "native_call" , 1 ;
    OP_OR_R_R = 0x42 : "or" , 2 ;
    OP_OR_R_R64 = 0x43 : "or64" , 2 ;
    OP_OR_R_IMM32 = 0x44 : "or" , 5 ;
    OP_OR_R_IMM64 = 0x45 : "or64" , 5 ;
    OP_NEG_R = 0x46 : "neg" , 1 ;
    OP_NEG_R64 = 0x47 : "neg64" , 1 ;
    OP_NOT_R = 0x48 : "not" , 1 ;
    OP_NOT_R64 = 0x49 : "not64" , 1 ;
    OP_SHL64_R_IMM8 = 0x4A : "shl64" , 2 ;
    OP_SHR64_R_IMM8 = 0x4B : "shr64" , 2 ;
    OP_SAR64_R_IMM8 = 0x4C : "sar64" , 2 ;
    OP_SHL64_R_CL = 0x4D : "shl64" , 1 ;
    OP_SHR64_R_CL = 0x4E : "shr64" , 1 ;
    OP_SAR64_R_CL = 0x4F : "sar64" , 1 ;
    OP_NOP = 0x50 : "nop" , 0 ;
    OP_MOVSD_XMM_MEM = 0x51 : "movsd" , 2 ;
    OP_MOVSD_MEM_XMM = 0x52 : "movsd" , 2 ;
    OP_MOVUPS_XMM_MEM = 0x53 : "movups" , 2 ;
    OP_MOVUPS_MEM_XMM = 0x54 : "movups" , 2 ;
    OP_UNPCKLPD_XMM = 0x55 : "unpcklpd" , 2 ;
    OP_XORPS_XMM = 0x6C : "xorps" , 2 ;
    OP_PSHUFLW_XMM = 0x6D : "pshuflw" , 3 ;
    OP_PSHUFHW_XMM = 0x6E : "pshufhw" , 3 ;
    OP_PSHUFD_XMM = 0x6F : "pshufd" , 3 ;
    OP_BSR_R32 = 0x70 : "bsr32" , 2 ;
    OP_BSR_R64 = 0x71 : "bsr64" , 2 ;
    OP_BSF_R32 = 0x72 : "bsf32" , 2 ;
    OP_BSF_R64 = 0x73 : "bsf64" , 2 ;
    OP_MOVQ_XMM_GPR = 0x74 : "movq_xmm_gpr" , 2 ;
    OP_MOVQ_GPR_XMM = 0x75 : "movq_gpr_xmm" , 2 ;
    OP_PSRLQ_XMM_IMM8 = 0x76 : "psrlq" , 2 ;
    OP_PSLLQ_XMM_IMM8 = 0x77 : "psllq" , 2 ;
    OP_MUL_R_R32 = 0x59 : "mul32" , 1 ;
    OP_MUL_R_R64 = 0x5A : "mul64" , 1 ;
    OP_IMUL1_R_R32 = 0x5B : "imul32" , 1 ;
    OP_IMUL1_R_R64 = 0x5C : "imul64" , 1 ;
    OP_DIV_R_R32 = 0x5D : "div32" , 1 ;
    OP_DIV_R_R64 = 0x5E : "div64" , 1 ;
    OP_IDIV_R_R32 = 0x5F : "idiv32" , 1 ;
    OP_IDIV_R_R64 = 0x60 : "idiv64" , 1 ;
    OP_BSWAP_R32 = 0x61 : "bswap32" , 1 ;
    OP_BSWAP_R64 = 0x62 : "bswap64" , 1 ;
    OP_MUL_R_R8 = 0x63 : "mul8" , 1 ;
    OP_MUL_R_R16 = 0x64 : "mul16" , 1 ;
    OP_IMUL1_R_R8 = 0x65 : "imul8" , 1 ;
    OP_IMUL1_R_R16 = 0x66 : "imul16" , 1 ;
    OP_DIV_R_R8 = 0x67 : "div8" , 1 ;
    OP_DIV_R_R16 = 0x68 : "div16" , 1 ;
    OP_IDIV_R_R8 = 0x69 : "idiv8" , 1 ;
    OP_IDIV_R_R16 = 0x6A : "idiv16" , 1 ;
    OP_LEA_GS = 0x6B : "lea_gs" , 5 ;
    // ── v45: --vm-oep SSE/Rust-runtime additions ──────────────────────────
    OP_PINSRW_XMM = 0x78 : "pinsrw" , 3 ;
    OP_CPUID       = 0x79 : "cpuid" , 0 ;
    OP_XGETBV      = 0x7A : "xgetbv" , 0 ;
    OP_TZCNT_R32   = 0x7B : "tzcnt32" , 2 ;
    OP_RET_IMM16   = 0x7C : "ret_imm16" , 2 ;
    // v46: atomic memory compare-exchange (Once/futex CAS). [addr_vreg, src_vreg].
    //   RAX(v0) = expected; does real `lock cmpxchg` at the absolute addr; on
    //   success [addr]=src and ZF=1, on failure v0=[addr] and ZF=0. Preserves
    //   the atomicity/ordering the lifted Rust `Once`/futex relies on.
    OP_CMPXCHG_MEM32_A = 0x7D : "cmpxchg32" , 2 ;
    OP_CMPXCHG_MEM64_A = 0x7E : "cmpxchg64" , 2 ;
    // v48: atomic memory XCHG / XADD (Once CompletionGuard swap, atomic RMW).
    // [addr_vreg, src_vreg].
    //   XCHG: real `xchg [addr], reg` — x86 memory XCHG is implicitly atomic
    //   (LOCK is not needed). This is what Rust `Once` CompletionGuard::drop()
    //   emits (`xchg [state], COMPLETE`) for the RUNNING->COMPLETE transition.
    //   Lifting it as a plain load+store let a 2nd call_once observe the OLD
    //   state and re-run the closure -> `f.take().unwrap()` panic (once.rs:166).
    OP_XCHG_MEM8_A  = 0x7F : "xchg8" , 2 ;
    OP_XCHG_MEM16_A = 0x80 : "xchg16" , 2 ;
    OP_XCHG_MEM32_A = 0x81 : "xchg32" , 2 ;
    OP_XCHG_MEM64_A = 0x82 : "xchg64" , 2 ;
    //   XADD: real `lock xadd [addr], reg` — the atomic fetch-add Rust
    //   `AtomicUsize::fetch_add` / `AtomicU64` refcounts rely on. LOCK *is*
    //   required for XADD atomicity (unlike XCHG), so the native handler sets it.
    OP_XADD_MEM8_A  = 0x83 : "xadd8" , 2 ;
    OP_XADD_MEM16_A = 0x84 : "xadd16" , 2 ;
    OP_XADD_MEM32_A = 0x85 : "xadd32" , 2 ;
    OP_XADD_MEM64_A = 0x86 : "xadd64" , 2 ;
    // v49: 8/16-bit atomic memory compare-exchange. v46 added the real `lock
    // cmpxchg` only for 32/64-bit; 8/16-bit stayed on the old non-atomic emulation
    // whose 32-bit compare never masked RAX to the operand width, so a byte/word
    // CAS always failed when RAX upper bits were dirty -> the guarded Once flag
    // never reached COMPLETE and a later call_once re-ran the closure
    // (`f.take().unwrap()` panic at once.rs:166). Same [addr_vreg, src_vreg]
    // encoding as the 32/64-bit variants; hardware compares only AL/AX.
    OP_CMPXCHG_MEM8_A  = 0x87 : "cmpxchg8" , 2 ;
    OP_CMPXCHG_MEM16_A = 0x88 : "cmpxchg16" , 2 ;
    // v50: SETcc — writes ONLY the low byte of the destination vreg (AL/CL/…)
    // and preserves all status flags (x86 setcc is a *partial-register* write
    // that does NOT zero the rest of the register and does NOT modify flags).
    // Rust `compare_exchange` -> `lock cmpxchg` -> `sete al` pattern relies on
    // this: RAX keeps the cmpxchg "actual" value in its upper bits while AL holds
    // the success boolean. Lifting it as a full-register mov (zero-extend) wiped
    // the actual value and broke the Once teardown; lifting it as AND/OR clobbers
    // the flags that a following cmovcc/sbb reads. Encoding: [op, dst_vreg, cond].
    OP_SETCC = 0x89 : "setcc" , 2 ;
    // v14 --vm-oep + --full: UNPCKLPS xmm, xmm/m128 (SSE single-precision unpack).
    // Interleaves the low 2 dwords of dst with the low 2 dwords of src:
    //   result = { src.d1, dst.d1, src.d0, dst.d0 }.
    OP_UNPCKLPS_XMM = 0x8A : "unpcklps", 2 ;
    // ── v52: BMI1/2 (Group B, Phase 2.1) ─────────────────────────────────────
    // Register-register bit-manipulation. LZCNT/POPCNT mirror TZCNT's portable
    // (no-CPU-dep) emulation; BLSR/BLSMSK/BLSI/ANDN are plain bit arithmetic.
    // Encoding [op, dst_vreg, src_vreg]; ANDN is [op, dst, src1, src2].
    OP_LZCNT_R32   = 0x8B : "lzcnt32", 2 ;
    OP_LZCNT_R64   = 0x8C : "lzcnt64", 2 ;
    OP_POPCNT_R32  = 0x8D : "popcnt32", 2 ;
    OP_POPCNT_R64  = 0x8E : "popcnt64", 2 ;
    OP_BLSR_R32    = 0x8F : "blsr32", 2 ;
    OP_BLSR_R64    = 0x90 : "blsr64", 2 ;
    OP_BLSMSK_R32  = 0x91 : "blsmsk32", 2 ;
    OP_BLSMSK_R64  = 0x92 : "blsmsk64", 2 ;
    OP_BLSI_R32    = 0x93 : "blsi32", 2 ;
    OP_BLSI_R64    = 0x94 : "blsi64", 2 ;
    OP_ANDN_R_R32  = 0x95 : "andn32", 3 ;
    OP_ANDN_R_R64  = 0x96 : "andn64", 3 ;
    // ── v54: SSE/FPU arithmetic + conversions (Group A, Phase 2.1) ─────────────
    // Scalar FP arithmetic: xmm[dst].low = xmm[dst].low OP xmm[src].low; the
    // upper 12 bytes of dst are preserved (x86 scalar semantics). Encoding
    // [op, dst_xmm, src_xmm]; the register file lives at STATE_XMM + idx*16.
    // These ops do NOT touch the modelled status flags (x86 SSE scalar FP
    // writes MXCSR, not rflags).
    OP_ADDSS_XMM   = 0x97 : "addss", 2 ;
    OP_ADDSD_XMM   = 0x98 : "addsd", 2 ;
    OP_SUBSS_XMM   = 0x99 : "subss", 2 ;
    OP_SUBSD_XMM   = 0x9A : "subsd", 2 ;
    OP_MULSS_XMM   = 0x9B : "mulss", 2 ;
    OP_MULSD_XMM   = 0x9C : "mulsd", 2 ;
    OP_DIVSS_XMM   = 0x9D : "divss", 2 ;
    OP_DIVSD_XMM   = 0x9E : "divsd", 2 ;
    // 128-bit packed bitwise logic [op, dst_xmm, src_xmm]:
    // PAND dst&=src, POR dst|=src, PANDN dst = ~dst & src.
    OP_PAND_XMM    = 0x9F : "pand", 2 ;
    OP_POR_XMM     = 0xA0 : "por", 2 ;
    OP_PANDN_XMM   = 0xA1 : "pandn", 2 ;
    // Integer -> float [op, dst_xmm, src_gpr]: xmm[dst].low = (f64/f32)vreg[src];
    // the upper 64 bits of the XMM slot are zeroed.
    OP_CVTSI2SD_XMM = 0xA2 : "cvtsi2sd", 2 ;
    OP_CVTSI2SS_XMM = 0xA3 : "cvtsi2ss", 2 ;
    // Float <-> float [op, dst_xmm, src_xmm]: convert the low element; the bits
    // above the converted element are zeroed (upper 64 / 96 bits).
    OP_CVTSS2SD_XMM = 0xA4 : "cvtss2sd", 2 ;
    OP_CVTSD2SS_XMM = 0xA5 : "cvtsd2ss", 2 ;
    // Float -> integer [op, dst_gpr, src_xmm]: vreg[dst] = (i32)(xmm low elem),
    // zero-extended. CVTT* truncates toward zero; CVT* rounds to nearest even.
    OP_CVTTSS2SI   = 0xA6 : "cvttss2si", 2 ;
    OP_CVTTSD2SI   = 0xA7 : "cvttsd2si", 2 ;
    OP_CVTSS2SI    = 0xA8 : "cvtss2si", 2 ;
    OP_CVTSD2SI    = 0xA9 : "cvtsd2si", 2 ;
    // Packed dword extract/insert [op, dst, src, imm8] (lane = imm & 3):
    //   PEXTRD: vreg[dst_gpr] = xmm[src].dword[lane] (zero-extended)
    //   PINSRD: xmm[dst].dword[lane] = vreg[src_gpr].low32 (others preserved)
    OP_PEXTRD_XMM  = 0xAA : "pextrd", 3 ;
    OP_PINSRD_XMM  = 0xAB : "pinsrd", 3 ;
    // v55: LOCK-prefixed atomic INC/DEC ( refcount inc/dec — `lock inc/dec [mem]`).
    // Encoding [addr_vreg] (1 operand). Real `lock inc`/`lock dec` at the absolute
    // address; flags are INC/DEC semantics (CF preserved — captured via the same
    // cap_flags_incdec path as the register INC/DEC handlers).
    OP_LOCK_INC_MEM8_A  = 0xAC : "lock_inc8", 1 ;
    OP_LOCK_INC_MEM16_A = 0xAD : "lock_inc16", 1 ;
    OP_LOCK_INC_MEM32_A = 0xAE : "lock_inc32", 1 ;
    OP_LOCK_INC_MEM64_A = 0xAF : "lock_inc64", 1 ;
    OP_LOCK_DEC_MEM8_A  = 0xB0 : "lock_dec8", 1 ;
    OP_LOCK_DEC_MEM16_A = 0xB1 : "lock_dec16", 1 ;
    OP_LOCK_DEC_MEM32_A = 0xB2 : "lock_dec32", 1 ;
    OP_LOCK_DEC_MEM64_A = 0xB3 : "lock_dec64", 1 ;
    // ── Phase 4: SHLD / SHRD double-precision shift ──────────────────────────
    OP_SHLD_R_R_IMM8    = 0xB4 : "shld", 3 ;
    OP_SHLD_R_R_CL      = 0xB5 : "shld", 2 ;
    OP_SHRD_R_R_IMM8    = 0xB6 : "shrd", 3 ;
    OP_SHRD_R_R_CL      = 0xB7 : "shrd", 2 ;
    OP_SHLD64_R_R_IMM8  = 0xB8 : "shld64", 3 ;
    OP_SHLD64_R_R_CL    = 0xB9 : "shld64", 2 ;
    OP_SHRD64_R_R_IMM8  = 0xBA : "shrd64", 3 ;
    OP_SHRD64_R_R_CL    = 0xBB : "shrd64", 2 ;
}

/// Index-slot sentinel for LEA: no index term (see opcodes! / OP_LEA).
pub const ADDR_NO_INDEX: u8 = 0xFF;



// ══════════════════════════════════════════════════════════════════════════════
// M1 — flag model (v21)
// ──────────────────────────────────────────────────────────────────────────────
// The VM state now models the x86 status flags in a single 64-bit STATE_FLAGS
// slot, using the same bit positions as the real x86 RFLAGS register:
//   CF bit0, PF bit2, AF bit4, ZF bit6, SF bit7, OF bit11.
// Arithmetic/logic ops update these flags; conditional branches (Jcc) read them.
// This lets a single OP_JCC8 opcode encode all x86 conditional-jump conditions.
// ══════════════════════════════════════════════════════════════════════════════
pub const F_CF: u64 = 1 << 0;  // carry
pub const F_PF: u64 = 1 << 2;  // parity (even # of 1s in low byte)
pub const F_AF: u64 = 1 << 4;  // auxiliary carry (bit 3)
pub const F_ZF: u64 = 1 << 6;  // zero
pub const F_SF: u64 = 1 << 7;  // sign
pub const F_OF: u64 = 1 << 11; // overflow (signed)
/// The 6 modelled status-flag bits. STATE_FLAGS may hold other (unused) bits,
/// but all comparisons / Jcc evaluation mask against this.
pub const FLAG_MASK: u64 = F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF;

// Condition identifiers for OP_JCC8 (match x86 Jcc semantics).
pub const COND_JE: u8 = 0;    // ZF
pub const COND_JNE: u8 = 1;   // !ZF
pub const COND_JB: u8 = 2;    // CF          (unsigned below)
pub const COND_JAE: u8 = 3;   // !CF         (unsigned above/equal)
pub const COND_JG: u8 = 4;    // signed >    (!ZF && SF==OF)
pub const COND_JGE: u8 = 5;   // signed >=   (SF==OF)
pub const COND_JL: u8 = 6;    // signed <    (SF!=OF)
pub const COND_JLE: u8 = 7;   // signed <=   (ZF || SF!=OF)
pub const COND_JS: u8 = 8;    // SF
pub const COND_JNS: u8 = 9;   // !SF
pub const COND_JO: u8 = 10;   // OF
pub const COND_JNO: u8 = 11;  // !OF
pub const COND_JP: u8 = 12;   // PF
pub const COND_JNP: u8 = 13;  // !PF
pub const COND_JA: u8 = 14;   // unsigned >  (!CF && !ZF)
pub const COND_JBE: u8 = 15;  // unsigned <= (CF || ZF)

/// Evaluate an OP_JCC8 condition against a flags word (see `cond_taken` in flags.rs).
/// JCXZ/JECXZ (register-based) are intentionally deferred to M2.

// Memory slots
pub const MEM_SBOX: u8 = 0;
pub const MEM_SEED: u8 = 1;
pub const MEM_BUF: u8 = 2;
pub const MEM_RUNS: u8 = 3;
pub const MEM_STACK: u8 = 4; // M3: stack region

