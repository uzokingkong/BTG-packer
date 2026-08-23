// ==============================================================================
// BTG v3 - VM Handler Codegen: FUSED / multi-op handlers (audit weakness #6)
// ==============================================================================
// Mechanism 1: families of related single-op handlers are folded into ONE fused
// handler block. The handler reads a fused *sub-op* byte from the bytecode
// (at r9) and performs the right operation via an internal, per-build-randomized
// sub-dispatch (a compare-and-jump chain whose constants are the seed-permuted
// sub-op encodings, emitted in a seed-shuffled case order). Decompiling one
// fused handler reveals MANY semantics, not one native instruction.
//
// A fused instruction in the obfuscated stream is:
//     [ family_byte ][ subop_byte ][ operands... ]
// At fused-handler entry r9 already points past family_byte (the dispatcher
// consumed it), so r9 = subop byte, operands at r9+1.. .
//
// The bodies are inline and mirror the single-op handlers exactly (same
// registers, same cap_flags capture), so the CPU-like flags storage behavior
// (STATE_FLAGS / FLAG_MASK / cap_flags_incdec / cap_flags_shift /
// cap_flags_cf_of) is preserved.
//
// This module emits the fused region as its own independent block (local labels
// only), which the obfuscated module builder appends after the plain handler
// code. The plain path never calls this and stays byte-identical.
// ==============================================================================

use super::*;
use crate::vm::semantic_obf::{FusedGroup, FusedMember, SemanticObfuscator};
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

/// Result of emitting the fused handler region.
pub(crate) struct FusedEmit {
    /// encoded machine code (relative to `code_base_va`).
    pub code: Vec<u8>,
    /// (family_byte, offset within `code`) for each fused handler entry.
    pub entries: Vec<(u8, usize)>,
}

/// Build every fused handler for the given codec, encoded as one contiguous
/// block. `code_base_va` is the VA of the block's first byte (used to size
/// branch displacements; values only affect imm sizing).
pub(crate) fn emit_fused_handlers(
    obf: &SemanticObfuscator,
    code_base_va: u64,
) -> Result<FusedEmit> {
    let mut seq: Vec<(Instruction, Option<usize>)> = Vec::new();
    // (family_byte, seq-index) where each family's handler begins.
    let mut entry_idx: Vec<(u8, usize)> = Vec::new();

    for fam in crate::vm::semantic_obf::ALL_FAMILIES {
        entry_idx.push((obf.family_byte(fam), seq.len()));
        emit_fused_handler(&mut seq, obf, fam);
    }

    // ── Two-pass layout: measure, assign label IPs, resolve je targets ─────
    let mut ip = code_base_va;
    let mut label_ips: Vec<Option<u64>> = Vec::new();
    for (_, lbl) in &seq {
        if let Some(l) = lbl {
            while label_ips.len() <= *l {
                label_ips.push(None);
            }
        }
    }
    for (inst, lbl) in &seq {
        let m2 = if let Some(l) = lbl {
            if is_branch_code(inst.code()) {
                Instruction::with_branch(inst.code(), ip).unwrap()
            } else {
                label_ips[*l] = Some(ip);
                *inst
            }
        } else {
            *inst
        };
        ip += measure(&m2, ip) as u64;
    }

    // ── Resolve branches and encode ─────────────────────────────────────────
    let mut insts: Vec<Instruction> = Vec::with_capacity(seq.len());
    for (inst, lbl) in &seq {
        let m2 = if let Some(l) = lbl {
            if is_branch_code(inst.code()) {
                Instruction::with_branch(inst.code(), label_ips[*l].unwrap()).unwrap()
            } else {
                *inst
            }
        } else {
            *inst
        };
        insts.push(m2);
    }
    let block = InstructionBlock::new(&insts, code_base_va);
    let enc = BlockEncoder::encode(64, block, BlockEncoderOptions::DONT_FIX_BRANCHES)
        .map_err(|e| anyhow!("fused handler block encode failed: {}", e))?;
    let code = enc.code_buffer;

    // ── Per-family entry byte offsets: seq index -> byte offset ─────────────
    let mut seq_off = vec![0usize; seq.len()];
    let mut off = 0usize;
    for (i, (inst, _)) in seq.iter().enumerate() {
        seq_off[i] = off;
        off += measure(inst, code_base_va + off as u64) as usize;
    }
    let entries = entry_idx
        .into_iter()
        .map(|(b, idx)| (b, seq_off[idx]))
        .collect();

    Ok(FusedEmit { code, entries })
}

/// Emit one fused handler (entry + sub-dispatch + inline case bodies).
/// `seq` holds the whole fused region; `fam_start_idx` records the seq index
/// where this family's handler begins so the caller can compute its offset.
fn emit_fused_handler(
    seq: &mut Vec<(Instruction, Option<usize>)>,
    obf: &SemanticObfuscator,
    fam: FusedGroup,
) {
    // Reserve a label id for each case.
    let n = fam.n_members();
    let label_base = reserve_labels(seq);
    // Extra labels for shift count==0 skip targets (skip labels at skip_base + m,
    // skipping label_base+n which is the entry marker).
    let skip_base = label_base + n + 1;

    // Entry: read the sub-op byte into r11d (r9 = subop byte at fused entry).
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R11D,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        Some(label_base + n), // entry label (unused for branching; marks position)
    ));

    // Sub-dispatch chain in seed-shuffled case order.
    for &m in obf.member_order(fam) {
        let sub_enc = obf.enc_subop(fam, m);
        seq.push((
            Instruction::with2(Code::Cmp_rm32_imm32, Register::R11D, sub_enc as i32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(label_base + m),
        ));
    }
    // Invalid sub-op -> trap.
    seq.push((Instruction::with(Code::Ud2), None));

    // Case bodies, each ending in the threaded-dispatch epilogue.
    for m in 0..n {
        let member = fam.member(m);
        let body = case_body(fam, member, obf, m, skip_base);
        let mut it = body.into_iter();
        // label the case's first instruction (the je target).
        seq.push((it.next().unwrap().0, Some(label_base + m)));
        for i in it {
            seq.push(i);
        }
        emit_dispatch_raw(seq);
    }
}

/// The threaded-dispatch epilogue (same 5 instructions as `emit_dispatch` in
/// mod.rs, but in the usize-label vector used by the fused region).
fn emit_dispatch_raw(seq: &mut Vec<(Instruction, Option<usize>)>) {
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base_index_scale(Register::R10, Register::RAX, 8),
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R15).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap(),
        None,
    ));
}

/// Reserve `n` label ids, returning the base id.
fn reserve_labels(seq: &mut Vec<(Instruction, Option<usize>)>) -> usize {
    // Count existing labels.
    let mut max = 0usize;
    for (_, l) in seq.iter() {
        if let Some(l) = l {
            max = max.max(l + 1);
        }
    }
    max
}

/// Build the inline native body for one fused member. r9 points at the sub-op
/// byte; operands follow at r9+1. The body performs the semantic, advances r9
/// past the whole instruction, and returns the instruction list plus optional
/// labels (used for the shift count==0 RFLAGS-preservation skip). (No dispatch
/// epilogue — the caller appends it.)
///
/// `midx` is the member index within the family; `skip_base` is the label base
/// for the shift count==0 skip targets (`skip_base + midx`).
fn case_body(
    _fam: FusedGroup,
    member: &FusedMember,
    _obf: &SemanticObfuscator,
    midx: usize,
    skip_base: usize,
) -> Vec<(Instruction, Option<usize>)> {
    use crate::vm::bytecode::*;
    use crate::vm::semantic_obf::FusedGroup as FG;

    let op = member.op;
    let mut v: Vec<(Instruction, Option<usize>)> = Vec::new();
    // Macro (not a closure) so `v` can also be borrowed mutably by `v.extend`.
    macro_rules! push {
        ($i:expr) => {
            v.push(($i, None));
        };
    }

    match member.fam {
        FG::AluRr => {
            // operands [dst, src] at r9+1, r9+2. Determine width + flag mode.
            let (is64, code32, code64, fmod) = match op {
                OP_ADD_R_R => (false, Code::Add_rm32_r32, Code::Add_rm64_r64, true),
                OP_SUB_R_R => (false, Code::Sub_rm32_r32, Code::Sub_rm64_r64, true),
                OP_XOR_R_R => (false, Code::Xor_rm32_r32, Code::Xor_rm64_r64, false),
                OP_AND_R_R => (false, Code::And_rm32_r32, Code::And_rm64_r64, false),
                OP_OR_R_R => (false, Code::Or_rm32_r32, Code::Or_rm64_r64, false),
                OP_IMUL_R_R => (false, Code::Imul_r32_rm32, Code::Imul_r64_rm64, false),
                OP_ADD_R_R64 => (true, Code::Add_rm32_r32, Code::Add_rm64_r64, true),
                OP_SUB_R_R64 => (true, Code::Sub_rm32_r32, Code::Sub_rm64_r64, true),
                OP_XOR_R_R64 => (true, Code::Xor_rm32_r32, Code::Xor_rm64_r64, false),
                OP_AND_R_R64 => (true, Code::And_rm32_r32, Code::And_rm64_r64, false),
                OP_OR_R_R64 => (true, Code::Or_rm32_r32, Code::Or_rm64_r64, false),
                OP_IMUL_R_R64 => (true, Code::Imul_r32_rm32, Code::Imul_r64_rm64, false),
                _ => unreachable!(),
            };
            push!(
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, m(Register::R9, 1)).unwrap()
            );
            push!(
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 2)).unwrap()
            );
            if is64 {
                push!(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX))
                        .unwrap()
                );
                push!(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RDX, vreg(Register::RDX))
                        .unwrap()
                );
                push!(Instruction::with2(code64, Register::RAX, Register::RDX).unwrap());
            } else {
                push!(
                    Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX))
                        .unwrap()
                );
                push!(
                    Instruction::with2(Code::Mov_r32_rm32, Register::EDX, vreg(Register::RDX))
                        .unwrap()
                );
                push!(Instruction::with2(code32, Register::EAX, Register::EDX).unwrap());
            }
            push!(
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap()
            );
            if op == OP_IMUL_R_R || op == OP_IMUL_R_R64 {
                v.extend(cap_flags_cf_of().into_iter().map(|i| (i, None)));
            } else if fmod {
                v.extend(cap_flags(true).into_iter().map(|i| (i, None)));
            } else {
                v.extend(cap_flags(false).into_iter().map(|i| (i, None)));
            }
            push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap());
        }
        FG::AluImm => {
            // operands [r, imm32] at r9+1, r9+2.
            let (is64, code32, code64, fmod) = match op {
                OP_ADD_R_IMM32 => (false, Code::Add_rm32_r32, Code::Add_rm64_r64, true),
                OP_XOR_R_IMM32 => (false, Code::Xor_rm32_r32, Code::Xor_rm64_r64, false),
                OP_AND_R_IMM32 => (false, Code::And_rm32_r32, Code::And_rm64_r64, false),
                OP_OR_R_IMM32 => (false, Code::Or_rm32_r32, Code::Or_rm64_r64, false),
                OP_ADD_R_IMM64 => (true, Code::Add_rm32_r32, Code::Add_rm64_r64, true),
                OP_XOR_R_IMM64 => (true, Code::Xor_rm32_r32, Code::Xor_rm64_r64, false),
                OP_AND_R_IMM64 => (true, Code::And_rm32_r32, Code::And_rm64_r64, false),
                OP_OR_R_IMM64 => (true, Code::Or_rm32_r32, Code::Or_rm64_r64, false),
                _ => unreachable!(),
            };
            push!(
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, m(Register::R9, 1)).unwrap()
            );
            if is64 {
                push!(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX))
                        .unwrap()
                );
                push!(
                    Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 2))
                        .unwrap()
                );
                push!(
                    Instruction::with2(Code::Movsxd_r64_rm32, Register::RDX, Register::EDX)
                        .unwrap()
                );
                push!(Instruction::with2(code64, Register::RAX, Register::RDX).unwrap());
            } else {
                push!(
                    Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX))
                        .unwrap()
                );
                push!(
                    Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 2))
                        .unwrap()
                );
                push!(Instruction::with2(code32, Register::EAX, Register::EDX).unwrap());
            }
            push!(
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap()
            );
            if fmod {
                v.extend(cap_flags(true).into_iter().map(|i| (i, None)));
            } else {
                v.extend(cap_flags(false).into_iter().map(|i| (i, None)));
            }
            push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 6).unwrap());
        }
        FG::LoadAbs => {
            // operands [dst, addr] at r9+1, r9+2.
            let (code, dst_reg) = match op {
                OP_MOVZX_R_MEM8_A => (Code::Movzx_r32_rm8, Register::EAX),
                OP_MOVZX_R_MEM16_A => (Code::Movzx_r32_rm16, Register::EAX),
                OP_MOVZX_R_MEM32_A => (Code::Mov_r32_rm32, Register::EAX),
                OP_MOVSX_R_MEM8_A => (Code::Movsx_r64_rm8, Register::RAX),
                OP_MOVSX_R_MEM16_A => (Code::Movsx_r64_rm16, Register::RAX),
                OP_MOV_R_MEM64_A => (Code::Mov_r64_rm64, Register::RAX),
                _ => unreachable!(),
            };
            push!(
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, m(Register::R9, 1)).unwrap()
            );
            push!(
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 2)).unwrap()
            );
            push!(
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RDX)).unwrap()
            );
            push!(
                Instruction::with2(code, dst_reg, MemoryOperand::with_base(Register::R11)).unwrap()
            );
            push!(
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap()
            );
            push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap());
        }
        FG::StoreAbs => {
            // operands [addr, src] at r9+1, r9+2.
            let (store_code, src_reg, load_code) = match op {
                OP_MOV_MEM8_A => (Code::Mov_rm8_r8, Register::AL, Code::Mov_r8_rm8),
                OP_MOV_MEM16_A => (Code::Mov_rm16_r16, Register::AX, Code::Mov_r16_rm16),
                OP_MOV_MEM32_A => (Code::Mov_rm32_r32, Register::EAX, Code::Mov_r32_rm32),
                OP_MOV_MEM64_A => (Code::Mov_rm64_r64, Register::RAX, Code::Mov_r64_rm64),
                _ => unreachable!(),
            };
            push!(
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, m(Register::R9, 1)).unwrap()
            );
            push!(
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 2)).unwrap()
            );
            push!(
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap()
            );
            push!(Instruction::with2(load_code, src_reg, vreg(Register::RDX)).unwrap());
            push!(
                Instruction::with2(store_code, MemoryOperand::with_base(Register::R11), src_reg)
                    .unwrap()
            );
            push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap());
        }
        FG::MulDiv => {
            // operands [src] at r9+1.
            push!(
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, m(Register::R9, 1)).unwrap()
            );
            match op {
                OP_MUL_R_R64 => {
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        m(Register::R8, 0)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::R11,
                        vreg(Register::RCX)
                    )
                    .unwrap());
                    push!(Instruction::with1(Code::Mul_rm64, Register::R11).unwrap());
                    v.extend(cap_flags_cf_of().into_iter().map(|i| (i, None)));
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 0),
                        Register::RAX
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 16),
                        Register::RDX
                    )
                    .unwrap());
                }
                OP_MUL_R_R32 => {
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EAX,
                        m(Register::R8, 0)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::R11D,
                        vreg(Register::RCX)
                    )
                    .unwrap());
                    push!(Instruction::with1(Code::Mul_rm32, Register::R11D).unwrap());
                    v.extend(cap_flags_cf_of().into_iter().map(|i| (i, None)));
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 0),
                        Register::RAX
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 16),
                        Register::RDX
                    )
                    .unwrap());
                }
                OP_IMUL1_R_R64 => {
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        m(Register::R8, 0)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::R11,
                        vreg(Register::RCX)
                    )
                    .unwrap());
                    push!(Instruction::with1(Code::Imul_rm64, Register::R11).unwrap());
                    v.extend(cap_flags_cf_of().into_iter().map(|i| (i, None)));
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 0),
                        Register::RAX
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 16),
                        Register::RDX
                    )
                    .unwrap());
                }
                OP_IMUL1_R_R32 => {
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EAX,
                        m(Register::R8, 0)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::R11D,
                        vreg(Register::RCX)
                    )
                    .unwrap());
                    push!(Instruction::with1(Code::Imul_rm32, Register::R11D).unwrap());
                    v.extend(cap_flags_cf_of().into_iter().map(|i| (i, None)));
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 0),
                        Register::RAX
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 16),
                        Register::RDX
                    )
                    .unwrap());
                }
                OP_DIV_R_R64 => {
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        m(Register::R8, 0)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RDX,
                        m(Register::R8, 16)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::R11,
                        vreg(Register::RCX)
                    )
                    .unwrap());
                    push!(Instruction::with1(Code::Div_rm64, Register::R11).unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 0),
                        Register::RAX
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 16),
                        Register::RDX
                    )
                    .unwrap());
                }
                OP_DIV_R_R32 => {
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EAX,
                        m(Register::R8, 0)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EDX,
                        m(Register::R8, 16)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::R11D,
                        vreg(Register::RCX)
                    )
                    .unwrap());
                    push!(Instruction::with1(Code::Div_rm32, Register::R11D).unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 0),
                        Register::RAX
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 16),
                        Register::RDX
                    )
                    .unwrap());
                }
                OP_IDIV_R_R64 => {
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        m(Register::R8, 0)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RDX,
                        m(Register::R8, 16)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::R11,
                        vreg(Register::RCX)
                    )
                    .unwrap());
                    push!(Instruction::with1(Code::Idiv_rm64, Register::R11).unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 0),
                        Register::RAX
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 16),
                        Register::RDX
                    )
                    .unwrap());
                }
                OP_IDIV_R_R32 => {
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EAX,
                        m(Register::R8, 0)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EDX,
                        m(Register::R8, 16)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::R11D,
                        vreg(Register::RCX)
                    )
                    .unwrap());
                    push!(Instruction::with1(Code::Idiv_rm32, Register::R11D).unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 0),
                        Register::RAX
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        m(Register::R8, 16),
                        Register::RDX
                    )
                    .unwrap());
                }
                _ => unreachable!(),
            }
            push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        }
        FG::MovRr => {
            // Register moves, no flag writes. [dst,src] or [r,imm].
            match op {
                OP_MOV_R_R => {
                    push!(Instruction::with2(
                        Code::Movzx_r32_rm8,
                        Register::ECX,
                        m(Register::R9, 1)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Movzx_r32_rm8,
                        Register::EDX,
                        m(Register::R9, 2)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EAX,
                        vreg(Register::RDX)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        vreg(Register::RCX),
                        Register::RAX
                    )
                    .unwrap());
                    push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap());
                }
                OP_MOV_R_R64 => {
                    push!(Instruction::with2(
                        Code::Movzx_r32_rm8,
                        Register::ECX,
                        m(Register::R9, 1)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Movzx_r32_rm8,
                        Register::EDX,
                        m(Register::R9, 2)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        vreg(Register::RDX)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        vreg(Register::RCX),
                        Register::RAX
                    )
                    .unwrap());
                    push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap());
                }
                OP_MOV_R_IMM32 => {
                    push!(Instruction::with2(
                        Code::Movzx_r32_rm8,
                        Register::ECX,
                        m(Register::R9, 1)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EDX,
                        m(Register::R9, 2)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        vreg(Register::RCX),
                        Register::RDX
                    )
                    .unwrap());
                    push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 6).unwrap());
                }
                OP_MOV_R_IMM64 => {
                    push!(Instruction::with2(
                        Code::Movzx_r32_rm8,
                        Register::ECX,
                        m(Register::R9, 1)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RDX,
                        m(Register::R9, 2)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_rm64_r64,
                        vreg(Register::RCX),
                        Register::RDX
                    )
                    .unwrap());
                    push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 10).unwrap());
                }
                _ => unreachable!(),
            }
        }
        FG::Shift => {
            // Mirrors the standalone shift handlers exactly, including the
            // count==0 -> RFLAGS preservation path (skip cap_flags_shift).
            // imm8 forms: operands [r, imm8] (r9+1, r9+2), advance 2.
            // CL forms:   operand  [r]       (r9+1),         advance 1.
            let (is64, count_is_imm, code, val_reg) = match op {
                OP_SHL_R_IMM8 => (false, true, Code::Shl_rm32_CL, Register::EAX),
                OP_SHR_R_IMM8 => (false, true, Code::Shr_rm32_CL, Register::EAX),
                OP_SAR_R_IMM8 => (false, true, Code::Sar_rm32_CL, Register::EAX),
                OP_SHL_R_CL => (false, false, Code::Shl_rm32_CL, Register::EAX),
                OP_SHR_R_CL => (false, false, Code::Shr_rm32_CL, Register::EAX),
                OP_SAR_R_CL => (false, false, Code::Sar_rm32_CL, Register::EAX),
                OP_SHL64_R_IMM8 => (true, true, Code::Shl_rm64_CL, Register::RAX),
                OP_SHR64_R_IMM8 => (true, true, Code::Shr_rm64_CL, Register::RAX),
                OP_SAR64_R_IMM8 => (true, true, Code::Sar_rm64_CL, Register::RAX),
                OP_SHL64_R_CL => (true, false, Code::Shl_rm64_CL, Register::RAX),
                OP_SHR64_R_CL => (true, false, Code::Shr_rm64_CL, Register::RAX),
                OP_SAR64_R_CL => (true, false, Code::Sar_rm64_CL, Register::RAX),
                _ => unreachable!(),
            };
            let width_mask: i32 = if is64 { 63 } else { 31 };
            let adv: i32 = if count_is_imm { 3 } else { 2 };
            let skip = Some(skip_base + midx);

            // dst index byte at r9+1.
            push!(
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, m(Register::R9, 1)).unwrap()
            );
            // R11 = dst index (copy, so vreg[R11] indexes correctly).
            if is64 {
                push!(
                    Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RCX).unwrap()
                );
            } else {
                push!(
                    Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::ECX).unwrap()
                );
            }
            if count_is_imm {
                // count = imm8 at r9+2, masked to the operand width.
                push!(
                    Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 2))
                        .unwrap()
                );
                push!(
                    Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap()
                );
                push!(Instruction::with2(Code::And_rm32_imm32, Register::ECX, width_mask).unwrap());
            } else {
                // count = vreg[1], masked to the operand width.
                push!(Instruction::with2(Code::Mov_r32_imm32, Register::EDX, 1).unwrap());
                push!(
                    Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RDX))
                        .unwrap()
                );
                push!(Instruction::with2(Code::And_rm32_imm32, Register::ECX, width_mask).unwrap());
            }
            // dst value into EAX/RAX. 32-bit shifts must zero-extend the loaded
            // vreg (Mov_r32 zeroes the upper 32 bits of RAX) so the final
            // 64-bit store is a zero-extended 32-bit result — matching the
            // standalone 32-bit shift handlers exactly.
            if is64 {
                push!(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::R11))
                        .unwrap()
                );
            } else {
                push!(
                    Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::R11))
                        .unwrap()
                );
            }
            // count==0 -> RFLAGS preserved: skip the shift + capture entirely.
            push!(Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX).unwrap());
            v.push((
                Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
                skip,
            ));
            push!(Instruction::with2(code, val_reg, Register::CL).unwrap());
            push!(
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap()
            );
            v.extend(cap_flags_shift().into_iter().map(|i| (i, None)));
            v.push((
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, adv).unwrap(),
                skip,
            ));
        }
        FG::Unary => {
            // operands [r] at r9+1.
            push!(
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, m(Register::R9, 1)).unwrap()
            );
            match op {
                OP_INC_R => {
                    push!(Instruction::with1(Code::Inc_rm32, vreg(Register::RCX)).unwrap());
                    v.extend(cap_flags_incdec().into_iter().map(|i| (i, None)));
                }
                OP_DEC_R => {
                    push!(Instruction::with1(Code::Dec_rm32, vreg(Register::RCX)).unwrap());
                    v.extend(cap_flags_incdec().into_iter().map(|i| (i, None)));
                }
                OP_INC_R64 => {
                    push!(Instruction::with1(Code::Inc_rm64, vreg(Register::RCX)).unwrap());
                    v.extend(cap_flags_incdec().into_iter().map(|i| (i, None)));
                }
                OP_DEC_R64 => {
                    push!(Instruction::with1(Code::Dec_rm64, vreg(Register::RCX)).unwrap());
                    v.extend(cap_flags_incdec().into_iter().map(|i| (i, None)));
                }
                OP_NEG_R => {
                    push!(Instruction::with1(Code::Neg_rm32, vreg(Register::RCX)).unwrap());
                    v.extend(cap_flags(true).into_iter().map(|i| (i, None)));
                }
                OP_NEG_R64 => {
                    push!(Instruction::with1(Code::Neg_rm64, vreg(Register::RCX)).unwrap());
                    v.extend(cap_flags(true).into_iter().map(|i| (i, None)));
                }
                OP_NOT_R => {
                    // NOT does not modify flags: no cap_flags.
                    push!(Instruction::with1(Code::Not_rm32, vreg(Register::RCX)).unwrap());
                }
                OP_NOT_R64 => {
                    push!(Instruction::with1(Code::Not_rm64, vreg(Register::RCX)).unwrap());
                }
                _ => unreachable!(),
            }
            push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        }
        FG::CmpTest => {
            match op {
                OP_CMP_R_IMM32 => {
                    // operands [r, imm32] at r9+1, r9+2; full flags, no write.
                    push!(Instruction::with2(
                        Code::Movzx_r32_rm8,
                        Register::ECX,
                        m(Register::R9, 1)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EAX,
                        vreg(Register::RCX)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EDX,
                        m(Register::R9, 2)
                    )
                    .unwrap());
                    push!(
                        Instruction::with2(Code::Cmp_rm32_r32, Register::EAX, Register::EDX)
                            .unwrap()
                    );
                    v.extend(cap_flags(true).into_iter().map(|i| (i, None)));
                    push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 6).unwrap());
                }
                OP_TEST_R_R32 => {
                    // operands [r, src] at r9+1, r9+2; logical flags, no write.
                    push!(Instruction::with2(
                        Code::Movzx_r32_rm8,
                        Register::EAX,
                        m(Register::R9, 1)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Movzx_r32_rm8,
                        Register::EDX,
                        m(Register::R9, 2)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EAX,
                        vreg(Register::RAX)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EDX,
                        vreg(Register::RDX)
                    )
                    .unwrap());
                    push!(
                        Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EDX)
                            .unwrap()
                    );
                    v.extend(cap_flags(false).into_iter().map(|i| (i, None)));
                    push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap());
                }
                OP_TEST_R_IMM32 => {
                    // operands [r, imm32] at r9+1, r9+2; logical flags, no write.
                    push!(Instruction::with2(
                        Code::Movzx_r32_rm8,
                        Register::EAX,
                        m(Register::R9, 1)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EAX,
                        vreg(Register::RAX)
                    )
                    .unwrap());
                    push!(Instruction::with2(
                        Code::Mov_r32_rm32,
                        Register::EDX,
                        m(Register::R9, 2)
                    )
                    .unwrap());
                    push!(
                        Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EDX)
                            .unwrap()
                    );
                    v.extend(cap_flags(false).into_iter().map(|i| (i, None)));
                    push!(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 6).unwrap());
                }
                _ => unreachable!(),
            }
        }
    }
    v
}
