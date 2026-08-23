// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: lightweight IR (Phase 2.3)
// ==============================================================================
// `lift_one` keeps its 1:1 x86→bytecode instruction mapping. This module
// promotes the assembled byte stream to a small structured IR (`VInstr`),
// runs the optimization passes on it, then re-encodes to VM bytecode:
//
//   x86 → lift_one → BytecodeBuilder bytes → parse() → VProg (VInstr[])
//        → opt passes → emit() → VM bytecode (branch fixups re-resolved)
//
// VInstr mirrors the registry: `(opcode, operand bytes)` + attached label and
// branch-fixup metadata, so parse/emit are faithful (a no-op pass yields
// byte-identical output).
//
// Pass-safety model: the VM models rflags; most arithmetic ops SET them and
// Jcc/SETcc/bridges READ them. Every pass here is *mov-only*: it runs inside
// straight-line spans bounded by flag-writers, flag-readers, labels, branches,
// calls, returns and memory ops, and rewrites/removes only flag-free,
// memory-free instructions. That makes the transforms conservative but exact.
// ==============================================================================

use crate::vm::bytecode::*;
use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};

/// A branch fixup attached to its instruction: the rel field sits at
/// `rel_off` inside the instruction, is `width` bytes long (1 or 4), and must
/// point at the instruction labelled `label` at emit time.
#[derive(Debug, Clone, Copy)]
pub struct VBranch {
    pub rel_off: u8,
    pub width: u8,
    pub label: u32,
}

/// One IR instruction: `(opcode, operand bytes)` + optional label marker.
#[derive(Debug, Clone)]
pub struct VInstr {
    pub op: u8,
    /// Operand bytes (first `olen` bytes valid; max operand width is 9).
    pub operands: [u8; 9],
    pub olen: usize,
    /// A label pointing at this instruction's start, if any.
    pub label: Option<u32>,
    pub branch: Option<VBranch>,
}

/// The IR program: the instruction list + label->instruction-index map.
pub struct VProg {
    pub instrs: Vec<VInstr>,
    label_to_idx: HashMap<u32, usize>,
}

impl VInstr {
    /// Total encoded length in bytes (opcode + operands).
    pub fn byte_len(&self) -> usize {
        1 + self.olen
    }
}

/// Parse raw builder output (pre-fixup: branch rel fields are 0) into a
/// VProg. `branches` is the builder's `(rel_off, label, width)` fixup list;
/// `labels` maps builder label ids to byte offsets.
pub fn parse(
    bytes: &[u8],
    branches: &[(usize, u32, u8)],
    labels: &HashMap<u32, usize>,
) -> Result<VProg> {
    let mut instrs = Vec::new();
    let mut starts = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let op = bytes[off];
        let olen = opcode_operand_len(op)
            .ok_or_else(|| anyhow!("ir::parse: unknown opcode 0x{op:02X}"))?;
        if off + 1 + olen > bytes.len() {
            return Err(anyhow!("ir::parse: truncated operands at 0x{off:X}"));
        }
        let mut operands = [0u8; 9];
        operands[..olen].copy_from_slice(&bytes[off + 1..off + 1 + olen]);
        starts.push(off);
        instrs.push(VInstr {
            op,
            operands,
            olen,
            label: None,
            branch: None,
        });
        off += 1 + olen;
    }
    // Attach branch metadata: the rel field offset falls inside the owning
    // instruction (rel_off > instruction start always).
    for &(rel_off, label, width) in branches {
        let idx = starts
            .iter()
            .rposition(|&s| s < rel_off)
            .ok_or_else(|| anyhow!("ir::parse: branch rel_off 0x{rel_off:X} before first instr"))?;
        instrs[idx].branch = Some(VBranch {
            rel_off: (rel_off - starts[idx]) as u8,
            width,
            label,
        });
    }
    // Build the label->instr index map (labels sit on instruction boundaries).
    let mut label_to_idx = HashMap::new();
    for (&label, &off) in labels {
        let idx = starts
            .iter()
            .rposition(|&s| s <= off)
            .ok_or_else(|| anyhow!("ir::parse: label {label} at 0x{off:X} before first instr"))?;
        if starts[idx] != off {
            return Err(anyhow!(
                "ir::parse: label {label} at 0x{off:X} is not an instruction boundary"
            ));
        }
        instrs[idx].label = Some(label);
        label_to_idx.insert(label, idx);
    }
    Ok(VProg {
        instrs,
        label_to_idx,
    })
}

/// Encode the VProg back to bytecode, resolving branch offsets. Any rel8
/// branch whose range is exceeded is widened to its rel32 sibling (same rule
/// as BytecodeBuilder::widen_branch).
pub fn emit(prog: &VProg) -> Result<Vec<u8>> {
    // (op, operands, rel_off_in_ins, width, label)
    let mut ops: Vec<(u8, Vec<u8>, u8, u8, u32)> = prog
        .instrs
        .iter()
        .map(|ins| {
            let (rel_off, width, label) = ins
                .branch
                .map(|b| (b.rel_off, b.width, b.label))
                .unwrap_or((0, 0, 0));
            (
                ins.op,
                ins.operands[..ins.olen].to_vec(),
                rel_off,
                width,
                label,
            )
        })
        .collect();

    let compute_offsets = |ops: &[(u8, Vec<u8>, u8, u8, u32)]| -> Vec<usize> {
        let mut out = Vec::with_capacity(ops.len());
        let mut o = 0usize;
        for (_, operands, _, _, _) in ops {
            out.push(o);
            o += 1 + operands.len();
        }
        out
    };

    // Fixpoint widening for out-of-range rel8 branches.
    loop {
        let offsets = compute_offsets(&ops);
        let mut widened = false;
        for i in 0..ops.len() {
            if ops[i].3 != 1 {
                continue;
            }
            let label = ops[i].4;
            let &tidx = prog
                .label_to_idx
                .get(&label)
                .ok_or_else(|| anyhow!("ir::emit: unresolved label {label}"))?;
            let rel = offsets[tidx] as i64 - (offsets[i] as i64 + 1 + ops[i].1.len() as i64);
            if (-128..=127).contains(&rel) {
                continue;
            }
            ops[i] = match ops[i].0 {
                OP_JMP8 => (OP_JMP32, vec![0, 0, 0, 0], 1, 4, label),
                OP_CALL8 => (OP_CALL32, vec![0, 0, 0, 0], 1, 4, label),
                OP_JB8 => (OP_JCC32, vec![COND_JB, 0, 0, 0, 0], 2, 4, label),
                OP_JCC8 => (OP_JCC32, vec![ops[i].1[0], 0, 0, 0, 0], 2, 4, label),
                other => {
                    return Err(anyhow!(
                        "ir::emit: cannot widen branch opcode 0x{other:02X}"
                    ))
                }
            };
            widened = true;
            break;
        }
        if !widened {
            break;
        }
    }

    // final encode with resolved rel fields
    let offsets = compute_offsets(&ops);
    let mut out = Vec::new();
    for (op, operands, _, _, _) in &ops {
        out.push(*op);
        out.extend_from_slice(operands);
    }
    for (i, (_, operands, rel_off, width, label)) in ops.iter().enumerate() {
        if *width == 0 {
            continue;
        }
        let tidx = prog.label_to_idx[label];
        let rel = offsets[tidx] as i64 - (offsets[i] as i64 + 1 + operands.len() as i64);
        // rel_off is measured from the INSTRUCTION start (the opcode is included),
        // matching the builder's convention (jmp8: rel field at start+1).
        let istart = offsets[i] + *rel_off as usize;
        if *width == 1 {
            assert!(
                (-128..=127).contains(&rel),
                "ir::emit: branch out of rel8 range (rel={rel})"
            );
            out[istart] = rel as i8 as u8;
        } else {
            out[istart..istart + 4].copy_from_slice(&(rel as i32).to_le_bytes());
        }
    }
    Ok(out)
}

// ── optimization passes ──────────────────────────────────────────────────────

/// Flag-free, memory-free instructions the passes may reason about, reported
/// as value arrays: (reads, read_len, writes, write_len). Anything NOT in this
/// table is a *span barrier* for the passes (flag writer/reader, memory op,
/// call/ret/halt, branch, label — spans restart there).
fn mov_family_rw(ins: &VInstr) -> Option<([u8; 2], usize, [u8; 2], usize)> {
    let (dst, src) = (ins.operands[0], ins.operands[1]);
    let rw = match ins.op {
        OP_MOV_R_IMM32 | OP_MOV_R_IMM64 => ([0; 2], 0, [dst, 0], 1),
        OP_MOV_R_R | OP_MOV_R_R64 => ([src, 0], 1, [dst, 0], 1),
        OP_LEA => {
            // [dst, base, idx, scale, disp32]; idx==0xFF = no index
            let idx = ins.operands[2];
            if idx == ADDR_NO_INDEX {
                ([ins.operands[1], 0], 1, [dst, 0], 1)
            } else {
                ([ins.operands[1], idx], 2, [dst, 0], 1)
            }
        }
        OP_LEA_RIP | OP_LEA_GS => ([0; 2], 0, [dst, 0], 1),
        OP_MOVQ_GPR_XMM => ([src, 0], 1, [0; 2], 0),
        OP_MOVQ_XMM_GPR => ([0; 2], 0, [dst, 0], 1),
        OP_PEXTRD_XMM => ([0; 2], 0, [dst, 0], 1),
        OP_PINSRD_XMM => ([src, 0], 1, [0; 2], 0),
        OP_CVTSI2SD_XMM | OP_CVTSI2SS_XMM => ([src, 0], 1, [0; 2], 0),
        OP_CVTTSS2SI | OP_CVTTSD2SI | OP_CVTSS2SI | OP_CVTSD2SI => ([0; 2], 0, [dst, 0], 1),
        // vreg-free (XMM-only or no-op instructions)
        OP_SET_RIP | OP_NOP | OP_PSHUFLW_XMM | OP_PSHUFHW_XMM | OP_PSHUFD_XMM
        | OP_PSRLQ_XMM_IMM8 | OP_PSLLQ_XMM_IMM8 | OP_XORPS_XMM | OP_UNPCKLPD_XMM
        | OP_UNPCKLPS_XMM | OP_PAND_XMM | OP_POR_XMM | OP_PANDN_XMM | OP_ADDSS_XMM
        | OP_ADDSD_XMM | OP_SUBSS_XMM | OP_SUBSD_XMM | OP_MULSS_XMM | OP_MULSD_XMM
        | OP_DIVSS_XMM | OP_DIVSD_XMM | OP_CVTSS2SD_XMM | OP_CVTSD2SS_XMM => ([0; 2], 0, [0; 2], 0),
        _ => return None,
    };
    Some(rw)
}

/// Compute the straight-line spans: maximal runs of mov-family instructions
/// with no labels/branches attached.
fn spans(prog: &VProg) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for i in 0..prog.instrs.len() {
        let ins = &prog.instrs[i];
        if ins.label.is_some() || ins.branch.is_some() || mov_family_rw(ins).is_none() {
            if start < i {
                out.push((start, i));
            }
            start = i + 1;
        }
    }
    if start < prog.instrs.len() {
        out.push((start, prog.instrs.len()));
    }
    out
}

/// Pass 1: constant copy propagation. Track known-constant vregs through MOV
/// instructions; when a `mov dst, src` reads a constant src, rewrite it to a
/// `mov dst, imm` (imm32 when the value fits 32 bits, else imm64). MOV writes
/// no flags, so the transform is exact.
fn const_copy_prop(prog: &mut VProg) {
    for (s, e) in spans(prog) {
        let mut konst: HashMap<u8, u64> = HashMap::new();
        for i in s..e {
            match prog.instrs[i].op {
                OP_MOV_R_IMM32 => {
                    let v = u32::from_le_bytes(prog.instrs[i].operands[1..5].try_into().unwrap())
                        as u64;
                    konst.insert(prog.instrs[i].operands[0], v);
                }
                OP_MOV_R_IMM64 => {
                    let v = u64::from_le_bytes(prog.instrs[i].operands[1..9].try_into().unwrap());
                    konst.insert(prog.instrs[i].operands[0], v);
                }
                OP_MOV_R_R | OP_MOV_R_R64 => {
                    let (d, src) = (prog.instrs[i].operands[0], prog.instrs[i].operands[1]);
                    let is64 = prog.instrs[i].op == OP_MOV_R_R64;
                    match konst.get(&src).copied() {
                        Some(v0) => {
                            let v = if is64 { v0 } else { v0 & 0xFFFF_FFFF };
                            // rewrite to an immediate move (flags-free)
                            let ins = &mut prog.instrs[i];
                            if v <= 0xFFFF_FFFF && !is64 {
                                ins.op = OP_MOV_R_IMM32;
                                ins.operands[..5].fill(0);
                                ins.operands[0] = d;
                                ins.operands[1..5].copy_from_slice(&(v as u32).to_le_bytes());
                                ins.olen = 5;
                            } else {
                                ins.op = OP_MOV_R_IMM64;
                                ins.operands[..9].fill(0);
                                ins.operands[0] = d;
                                ins.operands[1..9].copy_from_slice(&v.to_le_bytes());
                                ins.olen = 9;
                            }
                            konst.insert(d, v);
                        }
                        None => {
                            konst.remove(&d);
                        }
                    }
                }
                _ => {
                    // any other write target becomes unknown
                    let (_, _, writes, wlen) = mov_family_rw(&prog.instrs[i]).unwrap();
                    for &w in &writes[..wlen] {
                        konst.remove(&w);
                    }
                }
            }
        }
    }
}

/// Pass 2: dead-mov elimination. Within a span, a mov writing vreg R whose
/// value is overwritten by a later mov to R (with no read of R in between) is
/// tombstoned (shrunk to a 1-byte NOP so byte distances only shrink — rel8
/// ranges can never be invalidated by this pass). MOV writes no flags, so
/// removing it is exact. Instructions carrying labels are never removed.
fn dead_mov_elim(prog: &mut VProg) {
    for (s, e) in spans(prog) {
        let mut last_write: HashMap<u8, usize> = HashMap::new();
        let mut dead: Vec<usize> = Vec::new();
        for i in s..e {
            let (reads, rlen, writes, wlen) = mov_family_rw(&prog.instrs[i]).unwrap();
            for &r in &reads[..rlen] {
                last_write.remove(&r);
            }
            for &w in &writes[..wlen] {
                if let Some(&j) = last_write.get(&w) {
                    if prog.instrs[j].label.is_none()
                        && matches!(
                            prog.instrs[j].op,
                            OP_MOV_R_IMM32 | OP_MOV_R_IMM64 | OP_MOV_R_R | OP_MOV_R_R64
                        )
                    {
                        dead.push(j);
                    }
                }
                last_write.insert(w, i);
            }
        }
        for j in dead {
            prog.instrs[j].op = OP_NOP;
            prog.instrs[j].olen = 0;
        }
    }
}

/// Pass 3: peephole — drop true no-op full-register self-moves
/// (`OP_MOV_R_R64 d, d`). (32-bit self-moves are kept: they zero-extend the
/// upper half and thus are NOT no-ops.)
fn selfmov64_elim(prog: &mut VProg) {
    for ins in &mut prog.instrs {
        if ins.label.is_some() {
            continue;
        }
        if ins.op == OP_MOV_R_R64 && ins.operands[0] == ins.operands[1] {
            ins.op = OP_NOP;
            ins.olen = 0;
        }
    }
}

/// Run all optimization passes (in-place).
pub fn optimize(prog: &mut VProg) {
    const_copy_prop(prog);
    dead_mov_elim(prog);
    selfmov64_elim(prog);
}

/// Convenience: parse → optimize → emit (the full IR pipeline).
pub fn run_ir_pipeline(
    bytes: &[u8],
    branches: &[(usize, u32, u8)],
    labels: &HashMap<u32, usize>,
) -> Result<Vec<u8>> {
    let mut prog = parse(bytes, branches, labels)?;
    optimize(&mut prog);
    emit(&prog)
}

/// Count instructions still alive after the passes (for diagnostics/tests).
pub fn live_count(prog: &VProg) -> usize {
    prog.instrs
        .iter()
        .filter(|i| i.op != OP_NOP || i.olen != 0)
        .count()
}

/// The set of vregs read/written by an instruction — exposed for the IR
/// self-test / diagnostics.
pub fn rw_sets(ins: &VInstr) -> Option<(HashSet<u8>, HashSet<u8>)> {
    let (r, rlen, w, wlen) = mov_family_rw(ins)?;
    Some((
        r[..rlen].iter().copied().collect(),
        w[..wlen].iter().copied().collect(),
    ))
}
