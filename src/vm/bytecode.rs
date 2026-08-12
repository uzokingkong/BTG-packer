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

        /// Handler-table slot count (opcodes 0x00..=0x88). 0x00 = invalid-opcode handler.
        pub const NUM_OPS: usize = 0x89;

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

/// Simple growable bytecode emitter with branch fixup support.
#[derive(Debug, Clone, Default)]
pub struct BytecodeBuilder {
    pub bytes: Vec<u8>,
    /// Byte offset of each pending branch's *rel field* (JMP8/JB8: op+1; JCC8: op+2),
    /// paired with the target label id and the rel field width (1 or 4 bytes).
    branches: Vec<(usize, u32, u8)>,
    /// Label id -> byte offset (filled by mark_label)
    labels: std::collections::HashMap<u32, usize>,
    next_label: u32,
}

impl BytecodeBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_label(&mut self) -> u32 {
        let l = self.next_label;
        self.next_label += 1;
        l
    }

    pub fn mark_label(&mut self, label: u32) {
        self.labels.insert(label, self.bytes.len());
    }

    fn fixup_all(&mut self) {
        // Bug-3 fix: widen any rel8 branch whose offset falls outside [-128, 127] to
        // its rel32 form instead of truncating to i8 (which would jump to the wrong
        // address). Widenings splice bytes and shift later offsets, so iterate to a
        // fixpoint (each width-1 branch is widened at most once).
        loop {
            let mut widened_any = false;
            let mut i = 0;
            while i < self.branches.len() {
                let (rel_off, label, width) = self.branches[i];
                if width == 1 {
                    let target = match self.labels.get(&label) {
                        Some(&t) => t,
                        None => panic!("vm bytecode: unresolved label {}", label),
                    };
                    let rel = target as i64 - (rel_off as i64 + 1);
                    if !(-128..=127).contains(&rel) {
                        self.widen_branch(i);
                        widened_any = true;
                        continue; // re-check from this index; offsets have shifted
                    }
                }
                i += 1;
            }
            if !widened_any {
                break;
            }
        }
        // Final pass: write every rel field.
        for (rel_off, label, width) in &self.branches {
            let target = match self.labels.get(label) {
                Some(&t) => t,
                None => panic!("vm bytecode: unresolved label {}", label),
            };
            if *width == 1 {
                let rel = target as i64 - (*rel_off as i64 + 1);
                assert!(
                    (-128..=127).contains(&rel),
                    "vm bytecode: branch out of rel8 range (rel={})",
                    rel
                );
                self.bytes[*rel_off] = rel as i8 as u8;
            } else {
                let rel = target as i64 - (*rel_off as i64 + 4);
                assert!(
                    (-(1i64 << 31)..(1i64 << 31)).contains(&rel),
                    "vm bytecode: branch out of rel32 range (rel={})",
                    rel
                );
                self.bytes[*rel_off..*rel_off + 4].copy_from_slice(&(rel as i32).to_le_bytes());
            }
        }
    }

    /// Widen the rel8 branch at `idx` to its rel32 sibling, splicing bytes into
    /// `self.bytes` and re-basing every later label/branch offset.
    fn widen_branch(&mut self, idx: usize) -> usize {
        let (rel_off, label, width) = self.branches[idx];
        debug_assert_eq!(width, 1);
        let op = self.bytes[rel_off - 1];
        // (splice_at, splice_len, op_pos, new_op, new_rel_off, cond_byte)
        let (splice_at, splice_len, op_pos, new_op, new_rel_off, cond) = match op {
            OP_JMP8 => (rel_off, 3, rel_off - 1, OP_JMP32, rel_off, None),
            OP_CALL8 => (rel_off, 3, rel_off - 1, OP_CALL32, rel_off, None),
            OP_JB8 => (
                // jb8 [op, rel] -> jcc32 [op, COND_JB, rel32]
                rel_off,
                4,
                rel_off - 1,
                OP_JCC32,
                rel_off + 1,
                Some(COND_JB),
            ),
            OP_JCC8 => (rel_off, 3, rel_off - 2, OP_JCC32, rel_off, None),
            other => panic!("vm bytecode: cannot widen branch opcode 0x{:02X}", other),
        };
        self.bytes
            .splice(splice_at..splice_at, std::iter::repeat(0u8).take(splice_len));
        self.bytes[op_pos] = new_op;
        if let Some(c) = cond {
            self.bytes[rel_off] = c;
        }
        // Re-base every label at/after the splice point.
        for v in self.labels.values_mut() {
            if *v >= splice_at {
                *v += splice_len;
            }
        }
        // Re-base every *other* branch's rel field offset.
        for (j, (b_off, _, _)) in self.branches.iter_mut().enumerate() {
            if j == idx {
                continue;
            }
            if *b_off >= splice_at {
                *b_off += splice_len;
            }
        }
        self.branches[idx] = (new_rel_off, label, 4);
        splice_len
    }

    pub fn emit(&mut self, op: u8, operands: &[u8]) {
        self.bytes.push(op);
        self.bytes.extend_from_slice(operands);
    }

    // ── opcode helpers ────────────────────────────────────────────────────────

    pub fn mov_r_imm32(&mut self, r: u8, imm: u32) {
        self.bytes.push(OP_MOV_R_IMM32);
        self.bytes.push(r);
        self.bytes.extend_from_slice(&imm.to_le_bytes());
    }

    pub fn mov_r_imm64(&mut self, r: u8, imm: u64) {
        self.bytes.push(OP_MOV_R_IMM64);
        self.bytes.push(r);
        self.bytes.extend_from_slice(&imm.to_le_bytes());
    }

    pub fn mov_r_r(&mut self, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[OP_MOV_R_R, dst, src]);
    }

    pub fn binop_r_r(&mut self, op: u8, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, dst, src]);
    }

    pub fn binop_r_imm32(&mut self, op: u8, r: u8, imm: u32) {
        self.bytes.push(op);
        self.bytes.push(r);
        self.bytes.extend_from_slice(&imm.to_le_bytes());
    }

    pub fn rol_r_imm8(&mut self, r: u8, imm: u8) {
        self.bytes.extend_from_slice(&[OP_ROL_R_IMM8, r, imm]);
    }

    pub fn ror_r_imm8(&mut self, r: u8, imm: u8) {
        self.bytes.extend_from_slice(&[OP_ROR_R_IMM8, r, imm]);
    }

    pub fn inc_r(&mut self, r: u8) {
        self.bytes.extend_from_slice(&[OP_INC_R, r]);
    }

    pub fn dec_r(&mut self, r: u8) {
        self.bytes.extend_from_slice(&[OP_DEC_R, r]);
    }

    pub fn cmp_r_imm32(&mut self, r: u8, imm: u32) {
        self.bytes.push(OP_CMP_R_IMM32);
        self.bytes.push(r);
        self.bytes.extend_from_slice(&imm.to_le_bytes());
    }

    pub fn movzx_r_mem8(&mut self, dst: u8, memslot: u8, idx: u8) {
        self.bytes.extend_from_slice(&[OP_MOVZX_R_MEM8, dst, memslot, idx]);
    }

    pub fn mov_mem8_r(&mut self, memslot: u8, idx: u8, src: u8) {
        self.bytes.extend_from_slice(&[OP_MOV_MEM8_R, memslot, idx, src]);
    }

    pub fn jmp8(&mut self, label: u32) {
        let off = self.bytes.len();
        self.bytes.extend_from_slice(&[OP_JMP8, 0]);
        self.branches.push((off + 1, label, 1));
    }

    pub fn jb8(&mut self, label: u32) {
        let off = self.bytes.len();
        self.bytes.extend_from_slice(&[OP_JB8, 0]);
        self.branches.push((off + 1, label, 1));
    }

    /// Conditional branch: OP_JCC8, cond, rel8 (rel patched at fixup).
    pub fn jcc8(&mut self, cond: u8, label: u32) {
        let off = self.bytes.len();
        self.bytes.extend_from_slice(&[OP_JCC8, cond, 0]);
        self.branches.push((off + 2, label, 1));
    }

    // ── M2 builder helpers ─────────────────────────────────────────────────────

    /// 64-bit register copy.
    pub fn mov_r_r64(&mut self, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[OP_MOV_R_R64, dst, src]);
    }

    /// 64-bit reg-reg binary op.
    pub fn binop_r_r64(&mut self, op: u8, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, dst, src]);
    }

    /// 64-bit op with a sign-extended imm32.
    pub fn binop_r_imm64(&mut self, op: u8, r: u8, imm: u32) {
        self.bytes.push(op);
        self.bytes.push(r);
        self.bytes.extend_from_slice(&imm.to_le_bytes());
    }

    /// Shift by imm8 (SHL/SHR/SAR).
    pub fn shift_r_imm8(&mut self, op: u8, r: u8, imm: u8) {
        self.bytes.extend_from_slice(&[op, r, imm]);
    }

    /// Shift by CL (vreg 1), 32-bit count masked to 31.
    pub fn shift_r_cl(&mut self, op: u8, r: u8) {
        self.bytes.extend_from_slice(&[op, r]);
    }

    /// TEST: flags from a & b (no destination write).
    pub fn test_r_r32(&mut self, a: u8, b: u8) {
        self.bytes.extend_from_slice(&[OP_TEST_R_R32, a, b]);
    }

    pub fn test_r_imm32(&mut self, r: u8, imm: u32) {
        self.bytes.push(OP_TEST_R_IMM32);
        self.bytes.push(r);
        self.bytes.extend_from_slice(&imm.to_le_bytes());
    }

    /// Wider / sign-extending memory loads (dst, slot, idx).
    pub fn mem_load(&mut self, op: u8, dst: u8, slot: u8, idx: u8) {
        self.bytes.extend_from_slice(&[op, dst, slot, idx]);
    }

    /// Wider memory stores (slot, idx, src).
    pub fn mem_store(&mut self, op: u8, slot: u8, idx: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, slot, idx, src]);
    }

    // ── M3 stack/call helpers ────────────────────────────────────────────────

    pub fn push_r(&mut self, r: u8) {
        self.bytes.extend_from_slice(&[OP_PUSH_R, r]);
    }

    pub fn pop_r(&mut self, r: u8) {
        self.bytes.extend_from_slice(&[OP_POP_R, r]);
    }

    /// Call a subroutine: push return address, branch to label (rel8).
    pub fn call8(&mut self, label: u32) {
        let off = self.bytes.len();
        self.bytes.extend_from_slice(&[OP_CALL8, 0]);
        self.branches.push((off + 1, label, 1));
    }

    // ── M5 (v30): rel32 branches ────────────────────────────────────────────
    pub fn jmp32(&mut self, label: u32) {
        let off = self.bytes.len();
        self.bytes.extend_from_slice(&[OP_JMP32, 0, 0, 0, 0]);
        self.branches.push((off + 1, label, 4));
    }
    pub fn jcc32(&mut self, cond: u8, label: u32) {
        let off = self.bytes.len();
        self.bytes.extend_from_slice(&[OP_JCC32, cond, 0, 0, 0, 0]);
        self.branches.push((off + 2, label, 4));
    }
    pub fn call32(&mut self, label: u32) {
        let off = self.bytes.len();
        self.bytes.extend_from_slice(&[OP_CALL32, 0, 0, 0, 0]);
        self.branches.push((off + 1, label, 4));
    }

    pub fn ret(&mut self) {
        self.bytes.push(OP_RET);
    }

    pub fn halt(&mut self) {
        self.bytes.push(OP_HALT);
    }

    // ── M2 follow-up: addressing-mode builders (v24) ─────────────────────────

    /// LEA: vreg[dst] = vreg[base] + (idx==ADDR_NO_INDEX?0 : vreg[idx]*scale) + sext(disp32).
    pub fn lea(&mut self, dst: u8, base: u8, idx: u8, scale_enc: u8, disp: i32) {
        self.bytes.extend_from_slice(&[OP_LEA, dst, base, idx, scale_enc]);
        self.bytes.extend_from_slice(&disp.to_le_bytes());
    }

    /// LEA_RIP: vreg[dst] = STATE_RIP + sext(rel32).
    pub fn lea_rip(&mut self, dst: u8, rel: i32) {
        self.bytes.push(OP_LEA_RIP);
        self.bytes.push(dst);
        self.bytes.extend_from_slice(&rel.to_le_bytes());
    }

    /// Set the STATE_RIP base used by LEA_RIP (base VA of the current lifted instruction).
    pub fn set_rip(&mut self, rip: u64) {
        self.bytes.push(OP_SET_RIP);
        self.bytes.extend_from_slice(&rip.to_le_bytes());
    }

    /// OP_LEA_GS: vreg[dst] = STATE_SEG_GS + sext(disp32)  (gs:/fs: PEB/TEB access).
    pub fn lea_gs(&mut self, dst: u8, disp: i32) {
        self.bytes.push(OP_LEA_GS);
        self.bytes.push(dst);
        self.bytes.extend_from_slice(&disp.to_le_bytes());
    }

    /// Absolute-address memory load: vreg[dst] = *(width)vreg[addr].
    pub fn mem_load_a(&mut self, op: u8, dst: u8, addr: u8) {
        self.bytes.extend_from_slice(&[op, dst, addr]);
    }

    /// Absolute-address memory store: *(width)vreg[addr] = vreg[src].
    pub fn mem_store_a(&mut self, op: u8, addr: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, addr, src]);
    }
    /// Atomic absolute-address compare-exchange: `lock cmpxchg [vreg[addr]], vreg[src]`
    /// with RAX(v0) as the expected/actual accumulator (32/64-bit). ZF is captured
    /// into STATE_FLAGS by the handler. Used for the Rust `Once`/futex CAS.
    pub fn mem_cmpxchg_a(&mut self, op: u8, addr: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, addr, src]);
    }

    /// Atomic absolute-address exchange: `xchg [vreg[addr]], vreg[src]` — a single
    /// atomic RMW (x86 memory XCHG needs no LOCK prefix). Flags are unchanged.
    /// Used for the Rust `Once` CompletionGuard swap (RUNNING->COMPLETE).
    pub fn mem_xchg_a(&mut self, op: u8, addr: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, addr, src]);
    }

    /// Atomic absolute-address fetch-and-add: `lock xadd [vreg[addr]], vreg[src]`.
    /// [addr] becomes old + src, src becomes old [addr]; ADD flags are captured
    /// into STATE_FLAGS. Used for Rust atomic refcounts / fetch_add.
    pub fn mem_xadd_a(&mut self, op: u8, addr: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, addr, src]);
    }

    // ── M3 follow-up: native API bridge builder (v24) ────────────────────────

    /// OP_NATIVE_CALL target_vreg: Win64 call to vreg[target].
    pub fn native_call(&mut self, target: u8) {
        self.bytes.extend_from_slice(&[OP_NATIVE_CALL, target]);
    }

    // ── A-2 보강 (v25) builders ─────────────────────────────────────────────

    /// NEG: vreg[r] = 0 - vreg[r] (32-bit, full flags).
    pub fn neg_r(&mut self, r: u8) {
        self.bytes.extend_from_slice(&[OP_NEG_R, r]);
    }
    /// NEG: 64-bit form.
    pub fn neg_r64(&mut self, r: u8) {
        self.bytes.extend_from_slice(&[OP_NEG_R64, r]);
    }
    /// NOT: vreg[r] = !vreg[r] (32-bit, no flags).
    pub fn not_r(&mut self, r: u8) {
        self.bytes.extend_from_slice(&[OP_NOT_R, r]);
    }
    /// NOT: 64-bit form.
    pub fn not_r64(&mut self, r: u8) {
        self.bytes.extend_from_slice(&[OP_NOT_R64, r]);
    }
    /// 64-bit shift by imm8 (SHL64/SHR64/SAR64).
    pub fn shift64_r_imm8(&mut self, op: u8, r: u8, imm: u8) {
        self.bytes.extend_from_slice(&[op, r, imm]);
    }
    /// 64-bit shift by CL (vreg[1] & 63).
    pub fn shift64_r_cl(&mut self, op: u8, r: u8) {
        self.bytes.extend_from_slice(&[op, r]);
    }
    /// NOP (no operands).
    pub fn nop(&mut self) {
        self.bytes.push(OP_NOP);
    }
    /// movsd xmm, [addr] (8 bytes).
    pub fn movsd_xmm_mem(&mut self, xmm: u8, addr: u8) {
        self.bytes.extend_from_slice(&[OP_MOVSD_XMM_MEM, xmm, addr]);
    }
    /// movsd [addr], xmm (8 bytes).
    pub fn movsd_mem_xmm(&mut self, addr: u8, xmm: u8) {
        self.bytes.extend_from_slice(&[OP_MOVSD_MEM_XMM, addr, xmm]);
    }
    /// movups xmm, [addr] (16 bytes).
    pub fn movups_xmm_mem(&mut self, xmm: u8, addr: u8) {
        self.bytes.extend_from_slice(&[OP_MOVUPS_XMM_MEM, xmm, addr]);
    }
    /// movups [addr], xmm (16 bytes).
    pub fn movups_mem_xmm(&mut self, addr: u8, xmm: u8) {
        self.bytes.extend_from_slice(&[OP_MOVUPS_MEM_XMM, addr, xmm]);
    }
    /// unpcklpd xmm[dst], xmm[src].
    pub fn unpcklpd_xmm(&mut self, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[OP_UNPCKLPD_XMM, dst, src]);
    }
    /// xorps xmm[dst] ^= xmm[src] (128-bit bitwise XOR).
    pub fn xorps_xmm(&mut self, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[OP_XORPS_XMM, dst, src]);
    }
    /// pshuflw xmm[dst] = shuffle(src words, imm) (low 4 words; high quad copied).
    pub fn pshuflw_xmm(&mut self, dst: u8, src: u8, imm: u8) {
        self.bytes.extend_from_slice(&[OP_PSHUFLW_XMM, dst, src, imm]);
    }
    /// pshufhw xmm[dst] = shuffle(src words, imm) (high 4 words; low quad copied).
    pub fn pshufhw_xmm(&mut self, dst: u8, src: u8, imm: u8) {
        self.bytes.extend_from_slice(&[OP_PSHUFHW_XMM, dst, src, imm]);
    }
    /// pshufd xmm[dst] = shuffle(src dwords, imm) (all 4 dwords).
    pub fn pshufd_xmm(&mut self, dst: u8, src: u8, imm: u8) {
        self.bytes.extend_from_slice(&[OP_PSHUFD_XMM, dst, src, imm]);
    }
    /// bsr: vreg[dst] = index of most significant set bit of vreg[src]; ZF set if src==0.
    pub fn bsr_r(&mut self, op: u8, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, dst, src]);
    }
    /// bsf: vreg[dst] = index of least significant set bit of vreg[src]; ZF set if src==0.
    pub fn bsf_r(&mut self, op: u8, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, dst, src]);
    }
    /// movq xmm[src] -> vreg[dst] (low 64 bits).
    pub fn movq_xmm_gpr(&mut self, dst_gpr: u8, src_xmm: u8) {
        self.bytes.extend_from_slice(&[OP_MOVQ_XMM_GPR, dst_gpr, src_xmm]);
    }
    /// movq vreg[src] -> xmm[dst] (low 64 bits, high zeroed).
    pub fn movq_gpr_xmm(&mut self, dst_xmm: u8, src_gpr: u8) {
        self.bytes.extend_from_slice(&[OP_MOVQ_GPR_XMM, dst_xmm, src_gpr]);
    }
    /// psrlq xmm[dst] >>= imm8 (two 64-bit lanes, logical shift right).
    pub fn psrlq_xmm_imm8(&mut self, dst: u8, imm: u8) {
        self.bytes.extend_from_slice(&[OP_PSRLQ_XMM_IMM8, dst, imm]);
    }
    /// psllq xmm[dst] <<= imm8 (two 64-bit lanes, logical shift left).
    pub fn psllq_xmm_imm8(&mut self, dst: u8, imm: u8) {
        self.bytes.extend_from_slice(&[OP_PSLLQ_XMM_IMM8, dst, imm]);
    }
    /// pinsrw xmm[dst], vreg[src], lane_imm8: insert low 16 bits of src into word lane (imm & 7).
    pub fn pinsrw_xmm(&mut self, dst_xmm: u8, src: u8, lane: u8) {
        self.bytes.extend_from_slice(&[OP_PINSRW_XMM, dst_xmm, src, lane]);
    }
    /// cpuid: run native CPUID (leaf=vreg0, subleaf=vreg2 -> EAX/EBX/ECX/EDX = vreg0..3).
    pub fn cpuid(&mut self) {
        self.bytes.push(OP_CPUID);
    }
    /// xgetbv: run native XGETBV (RCX=vreg2 -> EDX:EAX = vreg3:vreg0).
    pub fn xgetbv(&mut self) {
        self.bytes.push(OP_XGETBV);
    }
    /// tzcnt: vreg[dst] = count trailing zeros of vreg[src]; op = OP_TZCNT_R32/_R64.
    pub fn tzcnt_r(&mut self, op: u8, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, dst, src]);
    }
    /// ret imm16: pop return ip and add imm16 to SP (cdecl cleanup).
    pub fn ret_imm16(&mut self, imm: u16) {
        self.bytes.extend_from_slice(&[OP_RET_IMM16]);
        self.bytes.extend_from_slice(&imm.to_le_bytes());
    }

    // ── v31: multiply/divide (1-op accumulator) + BSWAP ──────────────────────
    /// MUL src: RDX:RAX = RAX * src (unsigned). op = OP_MUL_R_R32/_R64.
    pub fn mul_r(&mut self, op: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, src]);
    }
    /// IMUL src: RDX:RAX = RAX * src (signed). op = OP_IMUL1_R_R32/_R64.
    pub fn imul_r(&mut self, op: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, src]);
    }
    /// DIV src: RAX = RDX:RAX / src; RDX = rem. op = OP_DIV_R_R32/_R64.
    pub fn div_r(&mut self, op: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, src]);
    }
    /// IDIV src: signed. op = OP_IDIV_R_R32/_R64.
    pub fn idiv_r(&mut self, op: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, src]);
    }
    /// BSWAP r (32-bit zero-extend or 64-bit). op = OP_BSWAP_R32/_R64.
    pub fn bswap_r(&mut self, op: u8, r: u8) {
        self.bytes.extend_from_slice(&[op, r]);
    }

    /// Finish: resolve branch offsets and return the bytecode.
    pub fn finish(mut self) -> Vec<u8> {
        self.fixup_all();
        // Bug-5 fix: guarantee the bytecode is self-terminating so neither the
        // interpreter (Err(OobIp)) nor the native VM (dispatch on a raw byte past the
        // buffer) can run off the end. Harmless if a HALT was already emitted.
        if self.bytes.last().copied() != Some(OP_HALT) {
            self.bytes.push(OP_HALT);
        }
        self.bytes
    }
}

/// Human-readable disassembly of the bytecode (used by the self-test / logs).
pub fn disassemble(code: &[u8]) -> String {
    let mut out = String::new();
    let mut ip = 0usize;
    while ip < code.len() {
        let start = ip;
        let op = code[ip];
        ip += 1;
        let mut line = format!("{:04X}: ", start);
        match op {
            OP_MOV_R_IMM32 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                line += &format!("mov v{}, 0x{:X}", r, imm);
            }
            OP_MOV_R_IMM64 => {
                let r = code[ip];
                let imm = u64::from_le_bytes(code[ip + 1..ip + 9].try_into().unwrap());
                ip += 9;
                line += &format!("mov v{}, 0x{:X}", r, imm);
            }
            OP_MOV_R_R => {
                line += &format!("mov v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_XOR_R_R => {
                line += &format!("xor v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_ADD_R_R => {
                line += &format!("add v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_IMUL_R_R => {
                line += &format!("imul v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_SUB_R_R => {
                line += &format!("sub v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_AND_R_R => {
                line += &format!("and v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_AND_R_IMM32 | OP_XOR_R_IMM32 | OP_ADD_R_IMM32 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                let m = match op {
                    OP_AND_R_IMM32 => "and",
                    OP_XOR_R_IMM32 => "xor",
                    _ => "add",
                };
                line += &format!("{} v{}, 0x{:X}", m, r, imm);
            }
            OP_ROL_R_IMM8 | OP_ROR_R_IMM8 => {
                line += &format!("{} v{}, {}", if op == OP_ROL_R_IMM8 { "rol" } else { "ror" }, code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_INC_R => {
                line += &format!("inc v{}", code[ip]);
                ip += 1;
            }
            OP_DEC_R => {
                line += &format!("dec v{}", code[ip]);
                ip += 1;
            }
            OP_CMP_R_IMM32 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                line += &format!("cmp v{}, 0x{:X}", r, imm);
            }
            OP_MOVZX_R_MEM8 => {
                line += &format!("movzx v{}, mem[{}][v{}]", code[ip], code[ip + 1], code[ip + 2]);
                ip += 3;
            }
            OP_MOV_MEM8_R => {
                line += &format!("mov mem[{}][v{}], v{}", code[ip], code[ip + 1], code[ip + 2]);
                ip += 3;
            }
            OP_JMP8 => {
                let rel = code[ip] as i8;
                ip += 1;
                line += &format!("jmp {:+} (-> {:04X})", rel, (ip as i64 + rel as i64) as usize);
            }
            OP_JB8 => {
                let rel = code[ip] as i8;
                ip += 1;
                line += &format!("jb {:+} (-> {:04X})", rel, (ip as i64 + rel as i64) as usize);
            }
            OP_JCC8 => {
                let cond = code[ip];
                let rel = code[ip + 1] as i8;
                ip += 2;
                let name = match cond {
                    COND_JE => "je", COND_JNE => "jne", COND_JB => "jb", COND_JAE => "jae",
                    COND_JG => "jg", COND_JGE => "jge", COND_JL => "jl", COND_JLE => "jle",
                    COND_JS => "js", COND_JNS => "jns", COND_JO => "jo", COND_JNO => "jno",
                    COND_JP => "jp", COND_JNP => "jnp", COND_JA => "ja", COND_JBE => "jbe", _ => "j??",
                };
                line += &format!("{} {:+} (-> {:04X})", name, rel, (ip as i64 + rel as i64) as usize);
            }
            OP_HALT => line += "halt",
            // ── M2 disassembly ──────────────────────────────────────────────
            OP_MOV_R_R64 => {
                line += &format!("mov r64 v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_ADD_R_R64 | OP_SUB_R_R64 | OP_XOR_R_R64 | OP_AND_R_R64 | OP_IMUL_R_R64 => {
                let m = match op {
                    OP_ADD_R_R64 => "add64", OP_SUB_R_R64 => "sub64", OP_XOR_R_R64 => "xor64",
                    OP_AND_R_R64 => "and64", _ => "imul64",
                };
                line += &format!("{} v{}, v{}", m, code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_ADD_R_IMM64 | OP_XOR_R_IMM64 | OP_AND_R_IMM64 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                let m = match op { OP_ADD_R_IMM64 => "add64", OP_XOR_R_IMM64 => "xor64", _ => "and64" };
                line += &format!("{} v{}, 0x{:X}", m, r, imm);
            }
            OP_SHL_R_IMM8 | OP_SHR_R_IMM8 | OP_SAR_R_IMM8 => {
                let r = code[ip];
                let n = code[ip + 1];
                ip += 2;
                let m = match op { OP_SHL_R_IMM8 => "shl", OP_SHR_R_IMM8 => "shr", _ => "sar" };
                line += &format!("{} v{}, {}", m, r, n);
            }
            OP_SHL_R_CL | OP_SHR_R_CL | OP_SAR_R_CL => {
                let r = code[ip];
                ip += 1;
                let m = match op { OP_SHL_R_CL => "shl", OP_SHR_R_CL => "shr", _ => "sar" };
                line += &format!("{} v{}, cl", m, r);
            }
            OP_TEST_R_R32 => {
                line += &format!("test v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_TEST_R_IMM32 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                line += &format!("test v{}, 0x{:X}", r, imm);
            }
            OP_MOVZX_R_MEM16 | OP_MOVZX_R_MEM32 | OP_MOVSX_R_MEM8 | OP_MOVSX_R_MEM16 | OP_MOV_R_MEM64 => {
                let (m, w) = match op {
                    OP_MOVZX_R_MEM16 => ("movzx", 16), OP_MOVZX_R_MEM32 => ("movzx", 32),
                    OP_MOVSX_R_MEM8 => ("movsx", 8), OP_MOVSX_R_MEM16 => ("movsx", 16), _ => ("mov", 64),
                };
                line += &format!("{} v{}, mem[{}][v{}] (u{})", m, code[ip], code[ip + 1], code[ip + 2], w);
                ip += 3;
            }
            OP_MOV_MEM16_R | OP_MOV_MEM32_R | OP_MOV_MEM64_R => {
                let w = match op { OP_MOV_MEM16_R => 16, OP_MOV_MEM32_R => 32, _ => 64 };
                line += &format!("mov mem[{}][v{}], v{} (u{})", code[ip], code[ip + 1], code[ip + 2], w);
                ip += 3;
            }
            // ── M3 disassembly ──────────────────────────────────────────────
            OP_PUSH_R => {
                line += &format!("push v{}", code[ip]);
                ip += 1;
            }
            OP_POP_R => {
                line += &format!("pop v{}", code[ip]);
                ip += 1;
            }
            OP_CALL8 => {
                let rel = code[ip] as i8;
                ip += 1;
                line += &format!("call {:+} (-> {:04X})", rel, (ip as i64 + rel as i64) as usize);
            }
            OP_RET => line += "ret",
            // ── M2 follow-up: addressing modes (v24) ───────────────────────
            OP_LEA => {
                let dst = code[ip];
                let base = code[ip + 1];
                let idx = code[ip + 2];
                let sc = code[ip + 3];
                let disp = i32::from_le_bytes(code[ip + 4..ip + 8].try_into().unwrap());
                ip += 8;
                line += &format!("lea v{}, v{} + {}v{} + 0x{:X}", dst, base, 1i32 << sc, if idx == ADDR_NO_INDEX { 0 } else { idx }, disp);
            }
            OP_SET_RIP => {
                let rip = u64::from_le_bytes(code[ip..ip + 8].try_into().unwrap());
                ip += 8;
                line += &format!("set_rip 0x{:X}", rip);
            }
            OP_LEA_RIP => {
                let dst = code[ip];
                let rel = i32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                line += &format!("lea_rip v{}, 0x{:X}", dst, rel);
            }
            // ── v43: gs:/fs: 세그먼트(PEB/TEB) ───────────────────────────────
            OP_LEA_GS => {
                let dst = code[ip];
                let disp = i32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                line += &format!("lea_gs v{}, 0x{:X}", dst, disp);
            }
            OP_MOVZX_R_MEM8_A | OP_MOVZX_R_MEM16_A | OP_MOVZX_R_MEM32_A | OP_MOVSX_R_MEM8_A | OP_MOVSX_R_MEM16_A | OP_MOV_R_MEM64_A => {
                let (m, w) = match op {
                    OP_MOVZX_R_MEM8_A => ("movzx", 8), OP_MOVZX_R_MEM16_A => ("movzx", 16),
                    OP_MOVZX_R_MEM32_A => ("movzx", 32), OP_MOVSX_R_MEM8_A => ("movsx", 8),
                    OP_MOVSX_R_MEM16_A => ("movsx", 16), _ => ("mov", 64),
                };
                line += &format!("{} v{}, [v{}] (u{})", m, code[ip], code[ip + 1], w);
                ip += 2;
            }
            OP_MOV_MEM8_A | OP_MOV_MEM16_A | OP_MOV_MEM32_A | OP_MOV_MEM64_A => {
                let w = match op { OP_MOV_MEM8_A => 8, OP_MOV_MEM16_A => 16, OP_MOV_MEM32_A => 32, _ => 64 };
                line += &format!("mov [v{}], v{} (u{})", code[ip], code[ip + 1], w);
                ip += 2;
            }
            OP_NATIVE_CALL => {
                line += &format!("native_call v{}", code[ip]);
                ip += 1;
            }
            // ── A-2 보강 (v25) ──────────────────────────────────────────────
            OP_OR_R_R | OP_OR_R_R64 => {
                let m = if op == OP_OR_R_R { "or" } else { "or64" };
                line += &format!("{} v{}, v{}", m, code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_OR_R_IMM32 | OP_OR_R_IMM64 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                let m = if op == OP_OR_R_IMM32 { "or" } else { "or64" };
                line += &format!("{} v{}, 0x{:X}", m, r, imm);
            }
            OP_NEG_R | OP_NEG_R64 => {
                line += &format!("{} v{}", if op == OP_NEG_R { "neg" } else { "neg64" }, code[ip]);
                ip += 1;
            }
            OP_NOT_R | OP_NOT_R64 => {
                line += &format!("{} v{}", if op == OP_NOT_R { "not" } else { "not64" }, code[ip]);
                ip += 1;
            }
            OP_SHL64_R_IMM8 | OP_SHR64_R_IMM8 | OP_SAR64_R_IMM8 => {
                let r = code[ip];
                let n = code[ip + 1];
                ip += 2;
                let m = match op { OP_SHL64_R_IMM8 => "shl64", OP_SHR64_R_IMM8 => "shr64", _ => "sar64" };
                line += &format!("{} v{}, {}", m, r, n);
            }
            OP_SHL64_R_CL | OP_SHR64_R_CL | OP_SAR64_R_CL => {
                let r = code[ip];
                ip += 1;
                let m = match op { OP_SHL64_R_CL => "shl64", OP_SHR64_R_CL => "shr64", _ => "sar64" };
                line += &format!("{} v{}, cl", m, r);
            }
            OP_JMP32 => {
                let rel = i32::from_le_bytes(code[ip..ip+4].try_into().unwrap());
                ip += 4;
                line += &format!("jmp32 {:+} (-> {:08X})", rel, (ip as i64 + rel as i64) as usize);
            }
            OP_JCC32 => {
                let cond = code[ip];
                let rel = i32::from_le_bytes(code[ip+1..ip+5].try_into().unwrap());
                ip += 5;
                let name = match cond {
                    COND_JE => "je", COND_JNE => "jne", COND_JB => "jb", COND_JAE => "jae",
                    COND_JG => "jg", COND_JGE => "jge", COND_JL => "jl", COND_JLE => "jle",
                    COND_JS => "js", COND_JNS => "jns", COND_JO => "jo", COND_JNO => "jno",
                    COND_JP => "jp", COND_JNP => "jnp", COND_JA => "ja", COND_JBE => "jbe", _ => "j??",
                };
                line += &format!("{}32 {:+} (-> {:08X})", name, rel, (ip as i64 + rel as i64) as usize);
            }
            OP_CALL32 => {
                let rel = i32::from_le_bytes(code[ip..ip+4].try_into().unwrap());
                ip += 4;
                line += &format!("call32 {:+} (-> {:08X})", rel, (ip as i64 + rel as i64) as usize);
            }
            OP_NOP => line += "nop",
            OP_MOVSD_XMM_MEM => { line += &format!("movsd xmm{}, [v{}]", code[ip], code[ip+1]); ip += 2; }
            OP_MOVSD_MEM_XMM => { line += &format!("movsd [v{}], xmm{}", code[ip], code[ip+1]); ip += 2; }
            OP_MOVUPS_XMM_MEM => { line += &format!("movups xmm{}, [v{}]", code[ip], code[ip+1]); ip += 2; }
            OP_MOVUPS_MEM_XMM => { line += &format!("movups [v{}], xmm{}", code[ip], code[ip+1]); ip += 2; }
            OP_UNPCKLPD_XMM => { line += &format!("unpcklpd xmm{}, xmm{}", code[ip], code[ip+1]); ip += 2; }
            OP_XORPS_XMM => { line += &format!("xorps xmm{}, xmm{}", code[ip], code[ip+1]); ip += 2; }
            OP_PSHUFLW_XMM => { line += &format!("pshuflw xmm{}, xmm{}, 0x{:02X}", code[ip], code[ip+1], code[ip+2]); ip += 3; }
            OP_PSHUFHW_XMM => { line += &format!("pshufhw xmm{}, xmm{}, 0x{:02X}", code[ip], code[ip+1], code[ip+2]); ip += 3; }
            OP_PSHUFD_XMM => { line += &format!("pshufd xmm{}, xmm{}, 0x{:02X}", code[ip], code[ip+1], code[ip+2]); ip += 3; }
            OP_BSR_R32 | OP_BSR_R64 | OP_BSF_R32 | OP_BSF_R64 => {
                let m = match op { OP_BSR_R32 => "bsr32", OP_BSR_R64 => "bsr64", OP_BSF_R32 => "bsf32", _ => "bsf64" };
                line += &format!("{} v{}, v{}", m, code[ip], code[ip+1]); ip += 2;
            }
            OP_MOVQ_XMM_GPR => { line += &format!("movq v{}, xmm{}", code[ip], code[ip+1]); ip += 2; }
            OP_MOVQ_GPR_XMM => { line += &format!("movq xmm{}, v{}", code[ip], code[ip+1]); ip += 2; }
            OP_PSRLQ_XMM_IMM8 => { line += &format!("psrlq xmm{}, 0x{:02X}", code[ip], code[ip+1]); ip += 2; }
            OP_PSLLQ_XMM_IMM8 => { line += &format!("psllq xmm{}, 0x{:02X}", code[ip], code[ip+1]); ip += 2; }
            // ── v31: multiply/divide + BSWAP ──────────────────────────────
            OP_MUL_R_R32 | OP_MUL_R_R64 => {
                let w = if op == OP_MUL_R_R32 { "mul32" } else { "mul64" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_IMUL1_R_R32 | OP_IMUL1_R_R64 => {
                let w = if op == OP_IMUL1_R_R32 { "imul32" } else { "imul64" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_DIV_R_R32 | OP_DIV_R_R64 => {
                let w = if op == OP_DIV_R_R32 { "div32" } else { "div64" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_IDIV_R_R32 | OP_IDIV_R_R64 => {
                let w = if op == OP_IDIV_R_R32 { "idiv32" } else { "idiv64" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_BSWAP_R32 | OP_BSWAP_R64 => {
                let w = if op == OP_BSWAP_R32 { "bswap32" } else { "bswap64" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            // ── v33: 8/16-bit 1-op multiply/divide ──────────────────────────
            OP_MUL_R_R8 | OP_MUL_R_R16 => {
                let w = if op == OP_MUL_R_R8 { "mul8" } else { "mul16" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_IMUL1_R_R8 | OP_IMUL1_R_R16 => {
                let w = if op == OP_IMUL1_R_R8 { "imul8" } else { "imul16" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_DIV_R_R8 | OP_DIV_R_R16 => {
                let w = if op == OP_DIV_R_R8 { "div8" } else { "div16" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_IDIV_R_R8 | OP_IDIV_R_R16 => {
                let w = if op == OP_IDIV_R_R8 { "idiv8" } else { "idiv16" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            _ => {
                line += &format!("?? op=0x{:02X}", op);
                break;
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backward jmp8 whose offset falls outside [-128, 127] must be auto-widened
    /// to jmp32 (Bug-3 fix) instead of truncating to a wrong i8 target.
    #[test]
    fn rel8_jmp_widens_to_rel32_when_out_of_range() {
        let mut b = BytecodeBuilder::new();
        let target = b.new_label();
        b.mark_label(target); // target at byte 0
        for _ in 0..200 {
            b.nop(); // bytes 0..=199
        }
        b.jmp8(target); // jmp8 at byte 200, rel field at 201 -> rel = 0-(201+1) = -202 (out of range)
        let code = b.finish();
        assert_eq!(code[200], OP_JMP32, "jmp8 should have been widened to jmp32");
        let rel = i32::from_le_bytes(code[201..205].try_into().unwrap());
        assert_eq!(rel, 0 - 205, "widened jmp32 target must still be byte 0");
        // The interpreter must land on byte 0: ip = 205 + rel = 205 - 205 = 0.
    }

    /// jb8 has no rel32 sibling; it must widen to jcc32 with COND_JB (Bug-3 fix).
    #[test]
    fn rel8_jb_widens_to_jcc32() {
        let mut b = BytecodeBuilder::new();
        let target = b.new_label();
        b.mark_label(target);
        for _ in 0..200 {
            b.nop();
        }
        b.jb8(target);
        let code = b.finish();
        assert_eq!(code[200], OP_JCC32, "jb8 should have been widened to jcc32");
        assert_eq!(code[201], COND_JB, "jcc32 cond byte must be COND_JB");
        let rel = i32::from_le_bytes(code[202..206].try_into().unwrap());
        assert_eq!(rel, 0 - 206);
    }

    /// Branches that stay within rel8 range are left untouched.
    #[test]
    fn rel8_in_range_unchanged() {
        let mut b = BytecodeBuilder::new();
        let target = b.new_label();
        b.mark_label(target);
        for _ in 0..40 {
            b.nop();
        }
        b.jmp8(target);
        let code = b.finish();
        assert_eq!(code[40], OP_JMP8, "in-range jmp8 must stay jmp8");
        let rel = code[41] as i8 as i32;
        assert_eq!(rel, 0 - 42);
    }
}
