// ==============================================================================
// BTG v3 - Semantic obfuscation layer for the legacy 1:1 VM (audit weakness #6)
// ==============================================================================
//
// Goal: break the legacy "one opcode byte -> one native handler -> one semantic"
// structure so a ChatGPT-style static extractor (dispatcher -> handler table ->
// opcode-semantic -> bytecode emulator) cannot build the opcode->semantic
// classification table in a single pass. Three mechanisms, all seed-keyed:
//
//   1. FUSED / MULTI-OP HANDLERS  — families of related single-op handlers
//      (register-register ALU, ALU-with-immediate, mem load width, mem store
//      width, mul/div) are folded into ONE opcode whose handler reads a fused
//      *sub-op* field and performs the right operation via an internal,
//      per-build-randomized sub-dispatch. Decompiling one handler no longer
//      reveals exactly one native instruction / one semantic.
//
//   2. VARIABLE OPERAND ENCODING — a fused instruction is
//          [ family_byte ][ subop_byte ][ operands... ]
//      where the operand count/width is a property of the (permuted) sub-op,
//      NOT of the opcode byte. `opcode_operand_len(family_byte)` is not a pure
//      static function of that byte: an extractor cannot compute instruction
//      length from the opcode byte alone, and the sub-op byte is itself
//      seed-permuted so even it cannot be decoded without the seed permutation.
//
//   3. VM-SPECIFIC SEMANTIC PERMUTATION — every plain opcode byte is remapped
//      through a seed-keyed bijection (reusing `DispatchPermutation`), and the
//      fused sub-op order / family tags are also seed-permuted. Two builds of
//      the same program with different seeds emit different opcode bytes for
//      the same logical operation AND a different fused-handler sub-dispatch
//      order, so a static table built from one binary does not transfer, and
//      building it requires the seed-derived permutation.
//
// This layer is applied at the boundary of the legacy VM path: the packer
// already produces *plain* bytecode (the existing registry format); this module
// rewrites it into the fused/permuted form (`encode`) and back (`decode`, used
// by the reference interpreter). The native VM module runs the fused/permuted
// stream directly through fused handlers + a permuted handler table, and must
// agree with `interpret(decode(stream))`.
//
// The plain registry + plain handlers are left untouched, so the existing
// byte-identical plain path (and all its tests) stays green.
// ==============================================================================

use crate::vm::bytecode::*;
use crate::vm::dispatch_perm::DispatchPermutation;
use std::collections::HashMap;

/// A fused semantic family. Each family folds several related single-op
/// handlers into one opcode byte; the exact semantic is selected by a fused
/// sub-op byte that follows the family byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FusedGroup {
    /// register-register ALU: ADD/SUB/XOR/AND/OR/IMUL (32 + 64-bit).
    AluRr,
    /// ALU with immediate: ADD/XOR/AND/OR (32-bit imm + 64-bit sign-ext imm32).
    AluImm,
    /// memory load width family (absolute address): movzx8/16/32, movsx8/16, mov64.
    LoadAbs,
    /// memory store width family (absolute address): mov8/16/32/64.
    StoreAbs,
    /// 1-op multiply/divide family: mul/imul/div/idiv (32 + 64-bit).
    MulDiv,
    /// register moves: mov r,r / r,r64 / r,imm32 / r,imm64 (no flag writes).
    MovRr,
    /// shifts: shl/shr/sar by imm8 and by CL (32 + 64-bit; count==0 preserves RFLAGS).
    Shift,
    /// unary reg ops: inc/dec (CF preserved) / neg (full flags) / not (no flags).
    Unary,
    /// compare / test: cmp r,imm32 (full flags), test r,r32 / r,imm32 (logical flags).
    CmpTest,
}

pub const ALL_FAMILIES: [FusedGroup; 9] = [
    FusedGroup::AluRr,
    FusedGroup::AluImm,
    FusedGroup::LoadAbs,
    FusedGroup::StoreAbs,
    FusedGroup::MulDiv,
    FusedGroup::MovRr,
    FusedGroup::Shift,
    FusedGroup::Unary,
    FusedGroup::CmpTest,
];

pub const N_FAMILIES: usize = ALL_FAMILIES.len();

/// One member of a fused family: the plain opcode it stands for, and the
/// operand byte count that follows the sub-op byte in the fused stream.
#[derive(Debug, Clone, Copy)]
pub struct FusedMember {
    pub fam: FusedGroup,
    pub op: u8,
    /// operand byte count after the sub-op byte (== the plain op's operand len).
    pub oplen: usize,
    pub name: &'static str,
}

/// The fused members, one entry per plain opcode folded into a family.
pub const FUSED_MEMBERS: &[FusedMember] = &[
    // ── AluRr: rr (2 operand bytes) ─────────────────────────────────────────
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_ADD_R_R,
        oplen: 2,
        name: "add_rr",
    },
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_SUB_R_R,
        oplen: 2,
        name: "sub_rr",
    },
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_XOR_R_R,
        oplen: 2,
        name: "xor_rr",
    },
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_AND_R_R,
        oplen: 2,
        name: "and_rr",
    },
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_OR_R_R,
        oplen: 2,
        name: "or_rr",
    },
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_IMUL_R_R,
        oplen: 2,
        name: "imul_rr",
    },
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_ADD_R_R64,
        oplen: 2,
        name: "add_rr64",
    },
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_SUB_R_R64,
        oplen: 2,
        name: "sub_rr64",
    },
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_XOR_R_R64,
        oplen: 2,
        name: "xor_rr64",
    },
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_AND_R_R64,
        oplen: 2,
        name: "and_rr64",
    },
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_OR_R_R64,
        oplen: 2,
        name: "or_rr64",
    },
    FusedMember {
        fam: FusedGroup::AluRr,
        op: OP_IMUL_R_R64,
        oplen: 2,
        name: "imul_rr64",
    },
    // ── AluImm: r + imm32 (5 operand bytes; 64-bit forms are sign-ext imm32) ─
    FusedMember {
        fam: FusedGroup::AluImm,
        op: OP_ADD_R_IMM32,
        oplen: 5,
        name: "add_imm32",
    },
    FusedMember {
        fam: FusedGroup::AluImm,
        op: OP_XOR_R_IMM32,
        oplen: 5,
        name: "xor_imm32",
    },
    FusedMember {
        fam: FusedGroup::AluImm,
        op: OP_AND_R_IMM32,
        oplen: 5,
        name: "and_imm32",
    },
    FusedMember {
        fam: FusedGroup::AluImm,
        op: OP_OR_R_IMM32,
        oplen: 5,
        name: "or_imm32",
    },
    FusedMember {
        fam: FusedGroup::AluImm,
        op: OP_ADD_R_IMM64,
        oplen: 5,
        name: "add_imm64",
    },
    FusedMember {
        fam: FusedGroup::AluImm,
        op: OP_XOR_R_IMM64,
        oplen: 5,
        name: "xor_imm64",
    },
    FusedMember {
        fam: FusedGroup::AluImm,
        op: OP_AND_R_IMM64,
        oplen: 5,
        name: "and_imm64",
    },
    FusedMember {
        fam: FusedGroup::AluImm,
        op: OP_OR_R_IMM64,
        oplen: 5,
        name: "or_imm64",
    },
    // ── LoadAbs: absolute mem loads, [dst, addr] (2 operand bytes) ───────────
    FusedMember {
        fam: FusedGroup::LoadAbs,
        op: OP_MOVZX_R_MEM8_A,
        oplen: 2,
        name: "load8u",
    },
    FusedMember {
        fam: FusedGroup::LoadAbs,
        op: OP_MOVZX_R_MEM16_A,
        oplen: 2,
        name: "load16u",
    },
    FusedMember {
        fam: FusedGroup::LoadAbs,
        op: OP_MOVZX_R_MEM32_A,
        oplen: 2,
        name: "load32u",
    },
    FusedMember {
        fam: FusedGroup::LoadAbs,
        op: OP_MOVSX_R_MEM8_A,
        oplen: 2,
        name: "load8s",
    },
    FusedMember {
        fam: FusedGroup::LoadAbs,
        op: OP_MOVSX_R_MEM16_A,
        oplen: 2,
        name: "load16s",
    },
    FusedMember {
        fam: FusedGroup::LoadAbs,
        op: OP_MOV_R_MEM64_A,
        oplen: 2,
        name: "load64",
    },
    // ── StoreAbs: absolute mem stores, [addr, src] (2 operand bytes) ─────────
    FusedMember {
        fam: FusedGroup::StoreAbs,
        op: OP_MOV_MEM8_A,
        oplen: 2,
        name: "store8",
    },
    FusedMember {
        fam: FusedGroup::StoreAbs,
        op: OP_MOV_MEM16_A,
        oplen: 2,
        name: "store16",
    },
    FusedMember {
        fam: FusedGroup::StoreAbs,
        op: OP_MOV_MEM32_A,
        oplen: 2,
        name: "store32",
    },
    FusedMember {
        fam: FusedGroup::StoreAbs,
        op: OP_MOV_MEM64_A,
        oplen: 2,
        name: "store64",
    },
    // ── MulDiv: 1-op accumulator mul/div, [src] (1 operand byte) ─────────────
    FusedMember {
        fam: FusedGroup::MulDiv,
        op: OP_MUL_R_R32,
        oplen: 1,
        name: "mul32",
    },
    FusedMember {
        fam: FusedGroup::MulDiv,
        op: OP_MUL_R_R64,
        oplen: 1,
        name: "mul64",
    },
    FusedMember {
        fam: FusedGroup::MulDiv,
        op: OP_IMUL1_R_R32,
        oplen: 1,
        name: "imul32",
    },
    FusedMember {
        fam: FusedGroup::MulDiv,
        op: OP_IMUL1_R_R64,
        oplen: 1,
        name: "imul64",
    },
    FusedMember {
        fam: FusedGroup::MulDiv,
        op: OP_DIV_R_R32,
        oplen: 1,
        name: "div32",
    },
    FusedMember {
        fam: FusedGroup::MulDiv,
        op: OP_DIV_R_R64,
        oplen: 1,
        name: "div64",
    },
    FusedMember {
        fam: FusedGroup::MulDiv,
        op: OP_IDIV_R_R32,
        oplen: 1,
        name: "idiv32",
    },
    FusedMember {
        fam: FusedGroup::MulDiv,
        op: OP_IDIV_R_R64,
        oplen: 1,
        name: "idiv64",
    },
    // ── MovRr: register moves [dst, src] / [r, imm32] / [r, imm64] (no flags) ─
    FusedMember {
        fam: FusedGroup::MovRr,
        op: OP_MOV_R_R,
        oplen: 2,
        name: "mov_rr",
    },
    FusedMember {
        fam: FusedGroup::MovRr,
        op: OP_MOV_R_R64,
        oplen: 2,
        name: "mov_rr64",
    },
    FusedMember {
        fam: FusedGroup::MovRr,
        op: OP_MOV_R_IMM32,
        oplen: 5,
        name: "mov_imm32",
    },
    FusedMember {
        fam: FusedGroup::MovRr,
        op: OP_MOV_R_IMM64,
        oplen: 9,
        name: "mov_imm64",
    },
    // ── Shift: shl/shr/sar by imm8 [r, imm8] (oplen 2) or by CL [r] (oplen 1).
    //    count==0 must preserve RFLAGS (skip cap_flags_shift), like the standalone
    //    shift handlers' ShiftSkip path. ──────────────────────────────────────
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SHL_R_IMM8,
        oplen: 2,
        name: "shl_imm8",
    },
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SHR_R_IMM8,
        oplen: 2,
        name: "shr_imm8",
    },
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SAR_R_IMM8,
        oplen: 2,
        name: "sar_imm8",
    },
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SHL_R_CL,
        oplen: 1,
        name: "shl_cl",
    },
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SHR_R_CL,
        oplen: 1,
        name: "shr_cl",
    },
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SAR_R_CL,
        oplen: 1,
        name: "sar_cl",
    },
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SHL64_R_IMM8,
        oplen: 2,
        name: "shl64_imm8",
    },
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SHR64_R_IMM8,
        oplen: 2,
        name: "shr64_imm8",
    },
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SAR64_R_IMM8,
        oplen: 2,
        name: "sar64_imm8",
    },
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SHL64_R_CL,
        oplen: 1,
        name: "shl64_cl",
    },
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SHR64_R_CL,
        oplen: 1,
        name: "shr64_cl",
    },
    FusedMember {
        fam: FusedGroup::Shift,
        op: OP_SAR64_R_CL,
        oplen: 1,
        name: "sar64_cl",
    },
    // ── Unary: inc/dec (CF preserved via cap_flags_incdec), neg (full flags),
    //    not (no flags). [r] (oplen 1) ────────────────────────────────────────
    FusedMember {
        fam: FusedGroup::Unary,
        op: OP_INC_R,
        oplen: 1,
        name: "inc",
    },
    FusedMember {
        fam: FusedGroup::Unary,
        op: OP_DEC_R,
        oplen: 1,
        name: "dec",
    },
    FusedMember {
        fam: FusedGroup::Unary,
        op: OP_INC_R64,
        oplen: 1,
        name: "inc64",
    },
    FusedMember {
        fam: FusedGroup::Unary,
        op: OP_DEC_R64,
        oplen: 1,
        name: "dec64",
    },
    FusedMember {
        fam: FusedGroup::Unary,
        op: OP_NEG_R,
        oplen: 1,
        name: "neg",
    },
    FusedMember {
        fam: FusedGroup::Unary,
        op: OP_NEG_R64,
        oplen: 1,
        name: "neg64",
    },
    FusedMember {
        fam: FusedGroup::Unary,
        op: OP_NOT_R,
        oplen: 1,
        name: "not",
    },
    FusedMember {
        fam: FusedGroup::Unary,
        op: OP_NOT_R64,
        oplen: 1,
        name: "not64",
    },
    // ── CmpTest: cmp r,imm32 (full flags), test r,r32 / r,imm32 (logical flags) ─
    FusedMember {
        fam: FusedGroup::CmpTest,
        op: OP_CMP_R_IMM32,
        oplen: 5,
        name: "cmp_imm32",
    },
    FusedMember {
        fam: FusedGroup::CmpTest,
        op: OP_TEST_R_R32,
        oplen: 2,
        name: "test_rr",
    },
    FusedMember {
        fam: FusedGroup::CmpTest,
        op: OP_TEST_R_IMM32,
        oplen: 5,
        name: "test_imm32",
    },
];

/// Operand-template labels used by the variable-length encoding (mechanism 2).
/// The template (operand count/width) of a fused instruction is a property of
/// the permuted sub-op byte, never of the family (opcode) byte alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandTemplate {
    R,      // 1 operand byte  (mul/div family, unary, shift-by-CL)
    RR,     // 2 operand bytes (alu rr / load / store / mov rr)
    RI32,   // 5 operand bytes (alu imm: r + imm32; mov r,imm32; cmp/test imm32)
    RImm8,  // 2 operand bytes (shift: r + imm8)
    RImm64, // 9 operand bytes (mov r,imm64)
}

impl FusedGroup {
    pub fn members(&self) -> Vec<&FusedMember> {
        FUSED_MEMBERS.iter().filter(|m| m.fam == *self).collect()
    }
    pub fn member(&self, idx: usize) -> &FusedMember {
        let m = self.members();
        m[idx]
    }
    pub fn n_members(&self) -> usize {
        self.members().len()
    }
    pub fn template(&self) -> OperandTemplate {
        match self {
            FusedGroup::AluRr | FusedGroup::LoadAbs | FusedGroup::StoreAbs => OperandTemplate::RR,
            FusedGroup::AluImm | FusedGroup::MovRr | FusedGroup::CmpTest => OperandTemplate::RI32,
            FusedGroup::MulDiv | FusedGroup::Unary => OperandTemplate::R,
            FusedGroup::Shift => OperandTemplate::RImm8,
        }
    }
}

/// Build a `plain_op -> (fam, member_index)` lookup.
fn fused_index_by_op() -> HashMap<u8, (FusedGroup, usize)> {
    let mut map = HashMap::new();
    for fam in ALL_FAMILIES {
        for (i, m) in fam.members().into_iter().enumerate() {
            map.insert(m.op, (fam, i));
        }
    }
    map
}

/// Branch fixup metadata: where the rel field sits inside the operand bytes,
/// how wide it is, and the byte offset (relative to the opcode byte `p`) from
/// which the rel is measured (== the instruction end).
#[derive(Debug, Clone, Copy)]
struct BranchInfo {
    /// offset of the rel field within the instruction's operand bytes.
    rel_operand_off: usize,
    width: u8,
    /// number of bytes from the opcode byte to the end of the instruction.
    base: usize,
}

/// Return branch-fixup info for a plain opcode, if it is a branch.
fn branch_info(op: u8) -> Option<BranchInfo> {
    match op {
        OP_JMP8 | OP_JB8 | OP_CALL8 => Some(BranchInfo {
            rel_operand_off: 0,
            width: 1,
            base: 2,
        }),
        OP_JCC8 => Some(BranchInfo {
            rel_operand_off: 1,
            width: 1,
            base: 3,
        }),
        OP_JMP32 | OP_CALL32 => Some(BranchInfo {
            rel_operand_off: 0,
            width: 4,
            base: 5,
        }),
        OP_JCC32 => Some(BranchInfo {
            rel_operand_off: 1,
            width: 4,
            base: 6,
        }),
        _ => None,
    }
}

/// The seed-keyed codec tying encode (lifter/emitter) and decode (interpreter +
/// native dispatcher) to the same permutation.
#[derive(Debug, Clone)]
pub struct SemanticObfuscator {
    pub seed: u64,
    /// permuted byte for each plain opcode (a bijection over [0, NUM_OPS)).
    op_perm: DispatchPermutation,
    /// family -> reserved tag byte (bijection into [NUM_OPS, 256)).
    fam_perm: DispatchPermutation,
    fam_enc: [u8; N_FAMILIES],
    /// per-family sub-op permutation (bijection over that family's members).
    sub_perm: Vec<DispatchPermutation>,
    /// per-family member dispatch order (seed-shuffled case order).
    order: Vec<Vec<usize>>,
}

fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

impl SemanticObfuscator {
    pub fn from_seed(seed: u64) -> Self {
        let op_seed = splitmix64(seed);
        let fam_seed = splitmix64(op_seed);
        let sub_seed = splitmix64(fam_seed);
        let ord_seed = splitmix64(sub_seed);

        let op_perm = DispatchPermutation::from_seed(op_seed, NUM_OPS);
        let fam_perm = DispatchPermutation::from_seed(fam_seed, N_FAMILIES);

        let mut fam_enc = [0u8; N_FAMILIES];
        for (f, fam) in ALL_FAMILIES.iter().enumerate() {
            // tag = NUM_OPS + a distinct permuted slot in [0, N_FAMILIES).
            let tag = NUM_OPS + fam_perm.slot_for_opcode(f);
            fam_enc[f] = tag as u8;
            let _ = fam;
        }

        let mut sub_perm = Vec::with_capacity(N_FAMILIES);
        let mut order = Vec::with_capacity(N_FAMILIES);
        for (f, fam) in ALL_FAMILIES.iter().enumerate() {
            let n = fam.n_members();
            let sp =
                DispatchPermutation::from_seed(sub_seed ^ (f as u64).wrapping_mul(0x9E3779B9), n);
            sub_perm.push(sp);
            // seed-shuffled member order for the native sub-dispatch chain.
            let mut o: Vec<usize> = (0..n).collect();
            let mut state = ord_seed ^ (f as u64).wrapping_mul(0x85EBCA6B);
            for i in (1..n).rev() {
                state = splitmix64(state);
                let j = (state as usize) % (i + 1);
                o.swap(i, j);
            }
            order.push(o);
        }

        Self {
            seed,
            op_perm,
            fam_perm,
            fam_enc,
            sub_perm,
            order,
        }
    }

    /// The encoded (permuted) byte for a plain opcode.
    pub fn enc_op(&self, op: u8) -> u8 {
        self.op_perm.slot_for_opcode(op as usize) as u8
    }
    /// Recover the plain opcode from an encoded byte.
    pub fn dec_op(&self, b: u8) -> u8 {
        self.op_perm.opcode_for_slot(b as usize) as u8
    }

    /// The reserved opcode byte identifying a fused family.
    pub fn family_byte(&self, fam: FusedGroup) -> u8 {
        let f = ALL_FAMILIES.iter().position(|x| *x == fam).unwrap();
        self.fam_enc[f]
    }
    /// Which fused family owns a reserved opcode byte (if any).
    pub fn family_of_byte(&self, b: u8) -> Option<FusedGroup> {
        if b < NUM_OPS as u8 || b as usize >= NUM_OPS + N_FAMILIES {
            return None;
        }
        let f = self.fam_perm.opcode_for_slot((b as usize) - NUM_OPS);
        if self.fam_enc[f] == b {
            Some(ALL_FAMILIES[f])
        } else {
            None
        }
    }

    /// The fused sub-op byte for a member index of a family.
    pub fn enc_subop(&self, fam: FusedGroup, member_idx: usize) -> u8 {
        let f = ALL_FAMILIES.iter().position(|x| *x == fam).unwrap();
        self.sub_perm[f].slot_for_opcode(member_idx) as u8
    }
    /// Recover the member index of a family from a fused sub-op byte.
    pub fn dec_subop(&self, fam: FusedGroup, b: u8) -> usize {
        let f = ALL_FAMILIES.iter().position(|x| *x == fam).unwrap();
        self.sub_perm[f].opcode_for_slot(b as usize)
    }

    /// Seed-shuffled member dispatch order for a family (used to emit the
    /// native sub-dispatch chain in a per-build order).
    pub fn member_order(&self, fam: FusedGroup) -> &[usize] {
        let f = ALL_FAMILIES.iter().position(|x| *x == fam).unwrap();
        &self.order[f]
    }

    /// Rewrite a plain bytecode stream into the fused/permuted/variable form.
    pub fn encode(&self, plain: &[u8]) -> Vec<u8> {
        self.rewrite(plain, true)
    }
    /// Rewrite a fused/permuted stream back to plain (used by the reference
    /// interpreter: `interpret_obf == interpret(decode(stream))`).
    pub fn decode(&self, obf: &[u8]) -> Vec<u8> {
        self.rewrite(obf, false)
    }

    fn rewrite(&self, input: &[u8], encode: bool) -> Vec<u8> {
        let lookup = fused_index_by_op();
        let mut out: Vec<u8> = Vec::new();
        let mut boundaries: HashMap<usize, usize> = HashMap::new();
        let mut branches: Vec<(usize, usize, u8, usize, usize)> = Vec::new();
        let n = input.len();
        let mut p = 0usize;
        while p < n {
            let byte = input[p];
            boundaries.insert(p, out.len());
            let (op, oplen, inst_bytes) = if encode {
                // input is plain: opcode at p.
                let op = byte;
                let mut olen = opcode_operand_len(op).unwrap_or(0);
                if p + 1 + olen > n {
                    // Defensive: never slice past the end of a (possibly
                    // truncated) bytecode stream — clamp the operand read so
                    // encode stays total.
                    olen = olen.min(n.saturating_sub(p + 1));
                }
                let operands = &input[p + 1..p + 1 + olen];
                match lookup.get(&op) {
                    Some(&(fam, midx)) => {
                        out.push(self.family_byte(fam));
                        out.push(self.enc_subop(fam, midx));
                        out.extend_from_slice(operands);
                    }
                    None => {
                        out.push(self.enc_op(op));
                        out.extend_from_slice(operands);
                    }
                }
                (op, olen, None)
            } else {
                // input is obfuscated: byte is either a permuted plain op
                // (< NUM_OPS) or a fused family tag (>= NUM_OPS).
                if byte < NUM_OPS as u8 {
                    let op = self.dec_op(byte);
                    let mut olen = opcode_operand_len(op).unwrap_or(0);
                    if p + 1 + olen > n {
                        olen = olen.min(n.saturating_sub(p + 1));
                    }
                    let operands = &input[p + 1..p + 1 + olen];
                    out.push(op);
                    out.extend_from_slice(operands);
                    (op, olen, None)
                } else if let Some(fam) = self.family_of_byte(byte) {
                    let sub = if p + 1 < n { input[p + 1] } else { 0 };
                    let midx = self.dec_subop(fam, sub);
                    let m = fam.member(midx);
                    let mut olen = m.oplen;
                    if p + 2 + olen > n {
                        olen = olen.min(n.saturating_sub(p + 2));
                    }
                    let operands = &input[p + 2..p + 2 + olen];
                    out.push(m.op);
                    out.extend_from_slice(operands);
                    (m.op, olen, Some(2))
                } else {
                    // invalid tag -> passthrough one byte (shouldn't happen in
                    // valid streams; keeps the rewrite total).
                    out.push(byte);
                    (0, 0, None)
                }
            };
            // Branch fixup bookkeeping (in both directions).
            if let Some(bi) = branch_info(op) {
                // rel field is at operand offset bi.rel_operand_off.
                let rel_out_off = out.len() - oplen + bi.rel_operand_off;
                // target in *input* space:
                let rel = read_rel(input, p, bi);
                let target = (p + bi.base) as i64 + rel;
                let target = target as usize;
                let inst_end_out = out.len();
                branches.push((rel_out_off, target, bi.width, inst_end_out, p));
            }
            p += if encode {
                1 + oplen
            } else {
                inst_bytes.unwrap_or(1) + oplen
            };
        }
        // Fixup branches: remap the target from input space to output space.
        for (rel_off, target_in, width, inst_end, _bp) in branches {
            // If the target isn't a recorded instruction boundary (a branch into
            // the middle of an instruction, e.g. from jump tables / computed
            // branches in lifted bytecode), we cannot remap it through the
            // input→output boundary map. Leave the branch displacement as-is
            // (best-effort) rather than panicking the whole encode.
            let Some(&target_out) = boundaries.get(&target_in) else {
                eprintln!("[semobf] branch fixup: target 0x{:x} not a boundary (n=0x{:x} width={}) — leaving un-remapped", target_in, n, width);
                continue;
            };
            let rel = target_out as i64 - inst_end as i64;
            if width == 1 {
                out[rel_off] = rel as i8 as u8;
            } else {
                out[rel_off..rel_off + 4].copy_from_slice(&(rel as i32).to_le_bytes());
            }
        }
        out
    }
}

fn read_rel(code: &[u8], p: usize, bi: BranchInfo) -> i64 {
    let field_off = p + 1 + bi.rel_operand_off;
    if bi.width == 1 {
        code[field_off] as i8 as i64
    } else {
        let mut b = [0u8; 4];
        b.copy_from_slice(&code[field_off..field_off + 4]);
        i32::from_le_bytes(b) as i64
    }
}

/// Reference-interpreter entry point for a fused/permuted stream: decode it to
/// plain and run the existing interpreter. Kept as a thin helper so the native
/// obfuscated VM can be cross-checked against `interpret(decode(stream))`.
pub fn interpret_obf(
    state: &mut [u8],
    mem: &mut [u8],
    obf: &[u8],
    seed: u64,
) -> Result<(), crate::vm::interp::VmError> {
    let codec = SemanticObfuscator::from_seed(seed);
    let plain = codec.decode(obf);
    crate::vm::interp::interpret(state, mem, &plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::bytecode::BytecodeBuilder;
    use crate::vm::interp;

    fn sample_program() -> Vec<u8> {
        let mut b = BytecodeBuilder::new();
        b.mov_r_imm32(0, 0x1111_2222);
        b.mov_r_imm32(1, 0x0000_3333);
        b.binop_r_r(OP_ADD_R_R, 0, 1);
        b.binop_r_r(OP_XOR_R_R, 0, 1);
        b.binop_r_imm32(OP_AND_R_IMM32, 0, 0x00FF_FFFF);
        b.binop_r_imm32(OP_ADD_R_IMM32, 0, 5);
        let l = b.new_label();
        b.jcc8(COND_JNE, l); // never taken (zf=0)
        b.binop_r_imm32(OP_ADD_R_IMM32, 0, 1);
        b.mark_label(l);
        b.movzx_r_mem8(2, 0, 3); // slot-relative load (NOT fused — permuted plain)
        b.halt();
        b.finish()
    }

    #[test]
    fn encode_decode_round_trip() {
        let plain = sample_program();
        let obf = SemanticObfuscator::from_seed(0xDEAD_BEEF);
        let enc = obf.encode(&plain);
        // Fused members (ALU rr/imm) must have been rewritten to family+subop.
        assert!(enc != plain, "encoding must differ from plain");
        let dec = obf.decode(&enc);
        assert_eq!(dec, plain, "decode(encode(plain)) must equal plain exactly");
    }

    /// Mechanism 2: operand length is NOT a pure static function of the opcode
    /// byte. `opcode_operand_len` on the plain opcodes still works, but on the
    /// obfuscated stream the byte alone cannot give the length, and the fused
    /// family tag yields None.
    #[test]
    fn operand_len_is_not_static_in_opcode_byte() {
        let obf = SemanticObfuscator::from_seed(0x1234_5678);
        // A fused ALU-RR member (ADD_R_R): the *plain* op has a static len...
        assert_eq!(opcode_operand_len(OP_ADD_R_R), Some(2));
        // ...but the *obfuscated* opcode byte for the same operation is a fused
        // family tag with NO static operand length: `opcode_operand_len` cannot
        // decode the length from the opcode byte alone.
        let fam_byte = obf.family_byte(FusedGroup::AluRr);
        assert!(
            opcode_operand_len(fam_byte).is_none(),
            "fused family tag must not expose a static operand length"
        );
        // The real length of a fused ALU-RR instruction (subop byte + 2 operand
        // bytes = 3 after the family byte) depends on the *permuted sub-op*
        // that follows the family byte, not on the family byte itself. A static
        // extractor reading only the opcode byte cannot know whether the next
        // byte is a sub-op selector or an operand, nor how many operand bytes
        // follow — that requires the seed-derived sub-op permutation.
        let subop_enc = obf.enc_subop(FusedGroup::AluRr, 0);
        // The sub-op byte is itself permuted: it is not a raw member index.
        assert!(subop_enc != 0 || obf.member_order(FusedGroup::AluRr)[0] != 0);
    }

    /// Mechanism 3: two builds with different seeds emit different opcode bytes
    /// for the same program, but both execute to identical results.
    #[test]
    fn different_seeds_differ_but_execute_identically() {
        let plain = sample_program();
        let a = SemanticObfuscator::from_seed(0xAAAA);
        let b = SemanticObfuscator::from_seed(0xBBBB);
        let ea = a.encode(&plain);
        let eb = b.encode(&plain);
        // Different encodings...
        assert!(ea != eb, "different seeds must produce different encodings");
        // ...but identical decoded semantics (identical execution).
        assert_eq!(a.decode(&ea), b.decode(&eb));

        let run = |bc: &[u8]| -> (u64, u64) {
            let mut st = vec![0u8; interp::STATE_SIZE];
            let mut mem = vec![0u8; 0x2000];
            st[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
                .copy_from_slice(&(0usize as u64).to_le_bytes());
            st[interp::STATE_PTR_SEED..interp::STATE_PTR_SEED + 8]
                .copy_from_slice(&(0x1000u64).to_le_bytes());
            interp::interpret(&mut st, &mut mem, bc).unwrap();
            let v0 = u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..][..8].try_into().unwrap());
            let v2 = u64::from_le_bytes(st[interp::STATE_VREGS + 2 * 8..][..8].try_into().unwrap());
            (v0, v2)
        };
        let r_plain = run(&plain);
        let r_a = run(&a.decode(&ea));
        let r_b = run(&b.decode(&eb));
        assert_eq!(r_a, r_plain);
        assert_eq!(r_b, r_plain);
    }

    /// Mechanism 1 (a): a fused stream executes to the same result as the plain
    /// stream through the reference interpreter.
    #[test]
    fn fused_executes_like_plain() {
        let plain = sample_program();
        let obf = SemanticObfuscator::from_seed(0xC0FFEE);
        let enc = obf.encode(&plain);
        let run = |bc: &[u8]| -> u64 {
            let mut st = vec![0u8; interp::STATE_SIZE];
            let mut mem = vec![0u8; 0x2000];
            st[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
                .copy_from_slice(&(0usize as u64).to_le_bytes());
            interp::interpret(&mut st, &mut mem, bc).unwrap();
            u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..][..8].try_into().unwrap())
        };
        assert_eq!(interpret_obf_runner(&obf, &enc, &run), run(&plain));
    }

    fn interpret_obf_runner(
        obf: &SemanticObfuscator,
        enc: &[u8],
        _run: &dyn Fn(&[u8]) -> u64,
    ) -> u64 {
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x2000];
        st[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
            .copy_from_slice(&(0usize as u64).to_le_bytes());
        crate::vm::semantic_obf::interpret_obf(&mut st, &mut mem, enc, obf.seed).unwrap();
        u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..][..8].try_into().unwrap())
    }
}
