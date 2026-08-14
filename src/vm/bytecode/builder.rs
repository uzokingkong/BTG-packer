use super::registry::*;

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
        // OP_JCC8's rel field sits one byte past its cond byte ([op, cond, rel]),
        // so `bytes[rel_off - 1]` is the COND value (0..=15), not the opcode —
        // detecting OP_JCC8 at rel_off-2 fixes a long-latent panic when a JCC8
        // branch falls out of rel8 range (no test had widened a JCC8 before).
        let (op_pos, op) = if rel_off >= 2 && self.bytes[rel_off - 2] == OP_JCC8 {
            (rel_off - 2, OP_JCC8)
        } else {
            (rel_off - 1, self.bytes[rel_off - 1])
        };
        let _ = op_pos;
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

    /// SETcc (v50): vreg[dst] low byte = (cond ? 1 : 0); upper bits and flags
    /// preserved. `cond` is a COND_* constant.
    pub fn setcc(&mut self, dst: u8, cond: u8) {
        self.bytes.extend_from_slice(&[OP_SETCC, dst, cond]);
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

    /// unpcklps xmm[dst], xmm[src]: interleave the low 2 dwords (d0,d1) of dst
    /// with (d0,d1) of src -> result = { src.d1, dst.d1, src.d0, dst.d0 }.
    pub fn unpcklps_xmm(&mut self, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[OP_UNPCKLPS_XMM, dst, src]);
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
    // ---- v52: BMI1/2 (Group B) builder helpers -------------------------------
    /// lzcnt: vreg[dst] = count leading zeros of vreg[src]. op = OP_LZCNT_R32/_R64.
    pub fn lzcnt_r(&mut self, op: u8, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, dst, src]);
    }
    /// popcnt: vreg[dst] = popcount of vreg[src]. op = OP_POPCNT_R32/_R64.
    pub fn popcnt_r(&mut self, op: u8, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, dst, src]);
    }
    /// blsr: vreg[dst] = vreg[src] & (vreg[src] - 1). op = OP_BLSR_R32/_R64.
    pub fn blsr_r(&mut self, op: u8, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, dst, src]);
    }
    /// blsmsk: vreg[dst] = vreg[src] ^ (vreg[src] - 1). op = OP_BLSMSK_R32/_R64.
    pub fn blsmsk_r(&mut self, op: u8, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, dst, src]);
    }
    /// blsi: vreg[dst] = vreg[src] & -vreg[src]. op = OP_BLSI_R32/_R64.
    pub fn blsi_r(&mut self, op: u8, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, dst, src]);
    }
    /// andn: vreg[dst] = ~vreg[src1] & vreg[src2]. op = OP_ANDN_R_R32/_R64.
    pub fn andn_r(&mut self, op: u8, dst: u8, src1: u8, src2: u8) {
        self.bytes.extend_from_slice(&[op, dst, src1, src2]);
    }
    // ---- v54: SSE/FPU (Group A) builder helpers -------------------------------
    /// SSE scalar FP arithmetic: xmm[dst].low = xmm[dst].low OP xmm[src].low
    /// (upper bytes of dst preserved). op = OP_ADDSS..OP_DIVSD_XMM.
    pub fn sse_fp_xmm(&mut self, op: u8, dst_xmm: u8, src_xmm: u8) {
        self.bytes.extend_from_slice(&[op, dst_xmm, src_xmm]);
    }
    /// SSE 128-bit logic: PAND (dst &= src) / POR (dst |= src) / PANDN
    /// (dst = ~dst & src). op = OP_PAND_XMM / OP_POR_XMM / OP_PANDN_XMM.
    pub fn sse_logic_xmm(&mut self, op: u8, dst_xmm: u8, src_xmm: u8) {
        self.bytes.extend_from_slice(&[op, dst_xmm, src_xmm]);
    }
    /// Integer -> float: xmm[dst].low = (f32/f64)vreg[src_gpr] (upper bits
    /// zeroed). op = OP_CVTSI2SS_XMM (32-bit int) / OP_CVTSI2SD_XMM (64-bit).
    pub fn cvt_int_fp(&mut self, op: u8, dst_xmm: u8, src_gpr: u8) {
        self.bytes.extend_from_slice(&[op, dst_xmm, src_gpr]);
    }
    /// Float <-> float: xmm[dst].low = convert(xmm[src].low) (upper bits
    /// zeroed). op = OP_CVTSS2SD_XMM / OP_CVTSD2SS_XMM.
    pub fn cvt_fp_fp(&mut self, op: u8, dst_xmm: u8, src_xmm: u8) {
        self.bytes.extend_from_slice(&[op, dst_xmm, src_xmm]);
    }
    /// Float -> integer: vreg[dst_gpr] = (i32)(xmm[src].low), zero-extended.
    /// op = OP_CVTTSS2SI/OP_CVTTSD2SI (trunc) / OP_CVTSS2SI/OP_CVTSD2SI
    /// (round to nearest even).
    pub fn cvt_fp_int(&mut self, op: u8, dst_gpr: u8, src_xmm: u8) {
        self.bytes.extend_from_slice(&[op, dst_gpr, src_xmm]);
    }
    /// pextrd: vreg[dst_gpr] = xmm[src].dword[imm & 3] (zero-extended).
    pub fn pextrd_xmm(&mut self, dst_gpr: u8, src_xmm: u8, imm: u8) {
        self.bytes.extend_from_slice(&[OP_PEXTRD_XMM, dst_gpr, src_xmm, imm]);
    }
    /// pinsrd: xmm[dst].dword[imm & 3] = vreg[src_gpr].low32 (others kept).
    pub fn pinsrd_xmm(&mut self, dst_xmm: u8, src_gpr: u8, imm: u8) {
        self.bytes.extend_from_slice(&[OP_PINSRD_XMM, dst_xmm, src_gpr, imm]);
    }

    // ── v55: LOCK-prefixed atomic INC/DEC (refcounts) ─────────────────────────
    /// `lock inc [vreg[addr]]` (width by op). Flags: INC semantics (CF kept).
    pub fn lock_inc_a(&mut self, op: u8, addr: u8) {
        self.bytes.extend_from_slice(&[op, addr]);
    }
    /// `lock dec [vreg[addr]]` (width by op). Flags: DEC semantics (CF kept).
    pub fn lock_dec_a(&mut self, op: u8, addr: u8) {
        self.bytes.extend_from_slice(&[op, addr]);
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

    /// SHLD / SHRD with immediate count
    pub fn shld_imm(&mut self, op: u8, dst: u8, src: u8, imm: u8) {
        self.bytes.extend_from_slice(&[op, dst, src, imm]);
    }
    /// SHLD / SHRD with CL count
    pub fn shld_cl(&mut self, op: u8, dst: u8, src: u8) {
        self.bytes.extend_from_slice(&[op, dst, src]);
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

    /// Phase 2.3 (v56): decompose the builder into its pre-fixup parts for the
    /// IR pipeline (`lifter::ir`): raw bytes (branch rel fields are still 0),
    /// the `(rel_off, label, width)` branch-fixup list, and label->offset map.
    /// Appends the self-terminating HALT first (same rule as `finish`).
    pub fn into_parts(mut self) -> (Vec<u8>, Vec<(usize, u32, u8)>, std::collections::HashMap<u32, usize>) {
        if self.bytes.last().copied() != Some(OP_HALT) {
            self.bytes.push(OP_HALT);
        }
        (self.bytes, self.branches, self.labels)
    }
}
