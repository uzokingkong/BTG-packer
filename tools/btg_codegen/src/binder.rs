//! Operand binder (Priority 2).
//!
//! The coverage DB records, per instruction, the iced-x86 `OpCodeOperandKind`
//! of every operand slot as a debug string — e.g. `["r64_or_mem", "r64_reg"]`
//! for `ADD r/m64, r64`, `["r64_reg", "imm32"]` for `ADD r64, imm32`,
//! `["ymm_reg", "ymm_vvvv", "ymm_or_mem"]` for a VEX 3-operand form.
//!
//! This module turns those raw strings into *bound operands* carrying:
//!   - a register/value **class** (GPR / XMM / YMM / ZMM / MMX / mask / tile /
//!     immediate / memory / implicit / branch),
//!   - a **width** in bits,
//!   - the **encoding slot** (modrm.reg / modrm.rm / VEX.vvvv / imm / is4 /
//!     opcode / implicit / memory),
//!   - whether the slot is **memory-capable** (a `reg/mem` operand),
//!   - a structural **role** (dst / src / imm) assigned from x86 operand
//!     convention for the instruction's family.
//!
//! The binder answers the question the old skeletons punted on: *which concrete
//! operand goes where*. It is the bridge between iced metadata and the real BTG
//! operand model; the flag/value SEMANTICS remain the SemanticTemplate's job,
//! and whether a lowering is correct remains the oracle's (Priority 3).

use crate::family::Family;
use crate::template::{Operand, OperandRole, SemanticTemplate, SimdShape};
use serde::Serialize;

/// The class of a bound operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OperandClass {
    Gpr,
    Mmx,
    Xmm,
    Ymm,
    Zmm,
    Mask,
    Tile,
    Imm,
    /// A pure memory operand (no register alternative), e.g. `mem`, `mem_mib`.
    Mem,
    /// A fixed/implicit register or memory (AL/AX/.../seg:RSI) encoded by the op.
    Implicit,
    /// A relative/far branch target.
    Branch,
    /// Unrecognised slot kind.
    Unknown,
}

impl OperandClass {
    pub fn as_str(self) -> &'static str {
        match self {
            OperandClass::Gpr => "gpr",
            OperandClass::Mmx => "mmx",
            OperandClass::Xmm => "xmm",
            OperandClass::Ymm => "ymm",
            OperandClass::Zmm => "zmm",
            OperandClass::Mask => "mask",
            OperandClass::Tile => "tile",
            OperandClass::Imm => "imm",
            OperandClass::Mem => "mem",
            OperandClass::Implicit => "implicit",
            OperandClass::Branch => "branch",
            OperandClass::Unknown => "unknown",
        }
    }

    pub fn is_vector(self) -> bool {
        matches!(self, OperandClass::Xmm | OperandClass::Ymm | OperandClass::Zmm)
    }

    /// Vector length in bits for a vector class, else 0.
    pub fn vector_len(self) -> u16 {
        match self {
            OperandClass::Xmm => 128,
            OperandClass::Ymm => 256,
            OperandClass::Zmm => 512,
            _ => 0,
        }
    }
}

/// Where in the encoding the operand lives. Drives which BTG operand source the
/// lifter must read (register file slot vs effective-address lowering vs imm).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EncodingSlot {
    /// modrm.reg (or EVEX modrm.reg).
    ModrmReg,
    /// modrm.rm — a register-or-memory slot.
    ModrmRm,
    /// VEX/EVEX.vvvv (a non-destructive source register).
    Vvvv,
    /// Register encoded in the opcode byte (e.g. `PUSH r64`).
    OpcodeReg,
    /// Register encoded in an immediate (is4/is5).
    ImmReg,
    /// An immediate value.
    Immediate,
    /// A memory operand (effective address).
    Memory,
    /// Fixed/implicit operand.
    Implicit,
    /// A branch displacement.
    Branch,
}

/// One operand bound from an iced `OpCodeOperandKind` string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundOperand {
    /// 0-based operand index as it appears in the encoding.
    pub index: usize,
    /// Original iced op-kind string (kept for traceability).
    pub op_kind: String,
    pub class: OperandClass,
    /// Width in bits; 0 when size-unknown (e.g. bare `mem`).
    pub width_bits: u16,
    pub slot: EncodingSlot,
    /// Whether the slot can be memory (a `reg/mem` operand).
    pub mem_capable: bool,
    /// Structural role from x86 convention (refined by the template's semantics).
    pub role: OperandRole,
}

/// Parse a single iced `OpCodeOperandKind` debug string into class/width/slot.
///
/// Returns `None` only for an empty string. Unrecognised-but-nonempty kinds map
/// to `OperandClass::Unknown` so the caller can still surface them.
pub fn parse_op_kind(raw: &str) -> Option<(OperandClass, u16, EncodingSlot, bool)> {
    if raw.is_empty() {
        return None;
    }
    let s = raw.to_ascii_lowercase();

    // Immediates (imm8 / imm16 / imm32 / imm64 / imm8sex32 / ...).
    if s.starts_with("imm") {
        let width = if s.contains("64") {
            64
        } else if s.contains("32") {
            32
        } else if s.contains("16") {
            16
        } else if s.contains('8') {
            8
        } else {
            0
        };
        return Some((OperandClass::Imm, width, EncodingSlot::Immediate, false));
    }

    // Branch targets.
    if s.starts_with("br") || s.starts_with("farbr") || s.starts_with("xbegin") {
        let width = if s.contains("64") {
            64
        } else if s.contains("32") {
            32
        } else {
            16
        };
        return Some((OperandClass::Branch, width, EncodingSlot::Branch, false));
    }

    // Pure memory operands (no register alternative): mem, mem_mib, mem_vsib*,
    // and the implicit string-op addresses (seg_rSI / es_rDI / seg_rDI).
    if s.starts_with("mem") || s.starts_with("seg_") || s.starts_with("es_") {
        return Some((OperandClass::Mem, 0, EncodingSlot::Memory, true));
    }

    let mem_capable = s.contains("_or_mem") || s.contains("_rm") || s.contains("reg_mem");
    let slot = slot_of(&s, mem_capable);

    // Vector / mask / tile classes (checked before GPR so `xmm`/`ymm` win).
    if s.starts_with("zmm") {
        return Some((OperandClass::Zmm, 512, slot, mem_capable));
    }
    if s.starts_with("ymm") {
        return Some((OperandClass::Ymm, 256, slot, mem_capable));
    }
    if s.starts_with("xmm") {
        return Some((OperandClass::Xmm, 128, slot, mem_capable));
    }
    if s.starts_with("mm") {
        // MMX register (mm_reg / mm_rm / mm_or_mem). 64-bit.
        return Some((OperandClass::Mmx, 64, slot, mem_capable));
    }
    if s.starts_with("tmm") {
        return Some((OperandClass::Tile, 0, slot, mem_capable));
    }
    if s.starts_with('k') && (s.contains("_reg") || s.contains("_rm") || s.contains("_vvvv")
        || s.contains("_or_mem") || s == "kp1_reg")
    {
        // Opmask register (k_reg / kp1_reg / k_rm / k_vvvv / k_or_mem). 64-bit.
        return Some((OperandClass::Mask, 64, slot, mem_capable));
    }

    // General-purpose registers (r8 / r16 / r32 / r64 variants).
    if s.starts_with("r8") {
        return Some((OperandClass::Gpr, 8, slot, mem_capable));
    }
    if s.starts_with("r16") {
        return Some((OperandClass::Gpr, 16, slot, mem_capable));
    }
    if s.starts_with("r32") {
        return Some((OperandClass::Gpr, 32, slot, mem_capable));
    }
    if s.starts_with("r64") {
        return Some((OperandClass::Gpr, 64, slot, mem_capable));
    }

    // Fixed byte/word/dword/qword accumulators and the like (al/ax/eax/rax/cl…).
    if matches!(s.as_str(), "al" | "cl" | "dl" | "bl") {
        return Some((OperandClass::Implicit, 8, EncodingSlot::Implicit, false));
    }
    if matches!(s.as_str(), "ax" | "dx") {
        return Some((OperandClass::Implicit, 16, EncodingSlot::Implicit, false));
    }
    if s == "eax" || s == "edx" {
        return Some((OperandClass::Implicit, 32, EncodingSlot::Implicit, false));
    }
    if s == "rax" || s == "rdx" {
        return Some((OperandClass::Implicit, 64, EncodingSlot::Implicit, false));
    }

    Some((OperandClass::Unknown, 0, EncodingSlot::Implicit, mem_capable))
}

fn slot_of(s: &str, mem_capable: bool) -> EncodingSlot {
    if s.contains("vvvv") {
        EncodingSlot::Vvvv
    } else if s.contains("is4") || s.contains("is5") {
        EncodingSlot::ImmReg
    } else if s.contains("opcode") {
        EncodingSlot::OpcodeReg
    } else if mem_capable || s.contains("_rm") {
        EncodingSlot::ModrmRm
    } else if s.ends_with("_reg") {
        EncodingSlot::ModrmReg
    } else {
        EncodingSlot::Implicit
    }
}

/// Assign a structural role to each operand from x86 operand convention for the
/// family. This is deliberately conservative — it describes operand *shape*, not
/// read/write access, which the SemanticTemplate owns (e.g. CMP's "dst" is in
/// fact read-only; the template marks that).
fn role_for(family: Family, index: usize, class: OperandClass, non_imm_slots: usize) -> OperandRole {
    match class {
        OperandClass::Imm => OperandRole::Imm,
        OperandClass::Mem => OperandRole::Mem,
        OperandClass::Implicit | OperandClass::Branch => OperandRole::Implicit,
        _ => {
            // The first non-immediate slot is the modifiable destination for the
            // families we auto-lower. 2-operand ALU/data-move: idx0 = dst, rest =
            // src. 3-operand VEX/EVEX (dst, vvvv, rm): idx0 = dst, others = src.
            if index == 0 && non_imm_slots >= 1 {
                match family {
                    // Pure writes (no read of dst value needed at the shape level).
                    Family::DataMove => OperandRole::Dst,
                    // ALU / shift / SIMD: destination is read-modify-write.
                    _ => OperandRole::ReadWrite,
                }
            } else {
                OperandRole::Src
            }
        }
    }
}

/// Bind every operand slot of an instruction from its `op_kinds` strings.
pub fn bind_operands(family: Family, op_kinds: &[String]) -> Vec<BoundOperand> {
    let non_imm_slots = op_kinds
        .iter()
        .filter(|k| !k.to_ascii_lowercase().starts_with("imm"))
        .count();

    let mut out = Vec::with_capacity(op_kinds.len());
    for (index, raw) in op_kinds.iter().enumerate() {
        let Some((class, width_bits, slot, mem_capable)) = parse_op_kind(raw) else {
            continue;
        };
        let role = role_for(family, index, class, non_imm_slots);
        out.push(BoundOperand {
            index,
            op_kind: raw.clone(),
            class,
            width_bits,
            slot,
            mem_capable,
            role,
        });
    }
    out
}

/// Fold bound operands into an existing SemanticTemplate: populate inputs/
/// outputs with concrete widths, set the primary operation width, and fill the
/// vector length of the SIMD shape when the operands are vector-class. (Element
/// width / mask / broadcast / rounding stay for the SIMD engine, Priority 4.)
pub fn bind_into_template(template: &mut SemanticTemplate, bound: &[BoundOperand]) {
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut primary_width = 0u16;
    let mut vector_len = 0u16;

    for b in bound {
        let op = Operand::labeled(b.role, b.width_bits, &b.op_kind);
        match b.role {
            OperandRole::Dst => outputs.push(op),
            OperandRole::ReadWrite => {
                outputs.push(op.clone());
                inputs.push(op);
            }
            _ => inputs.push(op),
        }
        // Primary width = widest non-immediate GPR/vector operand.
        if !matches!(b.class, OperandClass::Imm) && b.width_bits > primary_width {
            primary_width = b.width_bits;
        }
        if b.class.is_vector() {
            vector_len = vector_len.max(b.class.vector_len());
        }
    }

    template.inputs = inputs;
    template.outputs = outputs;
    if primary_width != 0 {
        template.width_bits = primary_width;
    }
    if vector_len != 0 {
        template.simd = SimdShape { vector_len, ..template.simd };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gpr_reg_and_rm() {
        let (c, w, slot, mem) = parse_op_kind("r64_reg").unwrap();
        assert_eq!((c, w, slot, mem), (OperandClass::Gpr, 64, EncodingSlot::ModrmReg, false));

        let (c, w, slot, mem) = parse_op_kind("r64_or_mem").unwrap();
        assert_eq!(c, OperandClass::Gpr);
        assert_eq!(w, 64);
        assert_eq!(slot, EncodingSlot::ModrmRm);
        assert!(mem, "_or_mem must be memory-capable");
    }

    #[test]
    fn parses_immediate_widths() {
        assert_eq!(parse_op_kind("imm8").unwrap().1, 8);
        assert_eq!(parse_op_kind("imm32").unwrap().1, 32);
        assert_eq!(parse_op_kind("imm8sex64").unwrap().0, OperandClass::Imm);
    }

    #[test]
    fn parses_vector_and_mask_classes() {
        assert_eq!(parse_op_kind("xmm_reg").unwrap().0, OperandClass::Xmm);
        assert_eq!(parse_op_kind("ymm_vvvv").unwrap().2, EncodingSlot::Vvvv);
        assert_eq!(parse_op_kind("zmm_or_mem").unwrap().1, 512);
        assert_eq!(parse_op_kind("k_reg").unwrap().0, OperandClass::Mask);
        assert_eq!(parse_op_kind("mm_or_mem").unwrap().0, OperandClass::Mmx);
    }

    #[test]
    fn parses_pure_memory() {
        let (c, _w, slot, mem) = parse_op_kind("mem").unwrap();
        assert_eq!(c, OperandClass::Mem);
        assert_eq!(slot, EncodingSlot::Memory);
        assert!(mem);
    }

    #[test]
    fn binds_add_rm64_r64_as_dst_then_src() {
        // ADD r/m64, r64  -> op0 is the read-modify-write destination.
        let ops = vec!["r64_or_mem".to_string(), "r64_reg".to_string()];
        let bound = bind_operands(Family::IntegerAlu, &ops);
        assert_eq!(bound.len(), 2);
        assert_eq!(bound[0].role, OperandRole::ReadWrite);
        assert!(bound[0].mem_capable, "dst slot is reg/mem");
        assert_eq!(bound[1].role, OperandRole::Src);
        assert_eq!(bound[1].width_bits, 64);
    }

    #[test]
    fn binds_add_r64_imm32() {
        let ops = vec!["r64_reg".to_string(), "imm32".to_string()];
        let bound = bind_operands(Family::IntegerAlu, &ops);
        assert_eq!(bound[0].role, OperandRole::ReadWrite);
        assert_eq!(bound[1].role, OperandRole::Imm);
    }

    #[test]
    fn binds_mov_dst_is_write_only() {
        let ops = vec!["r64_or_mem".to_string(), "r64_reg".to_string()];
        let bound = bind_operands(Family::DataMove, &ops);
        assert_eq!(bound[0].role, OperandRole::Dst, "MOV dst is write-only at shape level");
    }

    #[test]
    fn binds_vex_three_operand() {
        // VADDPS ymm, ymm(vvvv), ymm/mem  -> dst, src, src.
        let ops = vec!["ymm_reg".to_string(), "ymm_vvvv".to_string(), "ymm_or_mem".to_string()];
        let bound = bind_operands(Family::AvxVex, &ops);
        assert_eq!(bound[0].role, OperandRole::ReadWrite);
        assert_eq!(bound[1].role, OperandRole::Src);
        assert_eq!(bound[1].slot, EncodingSlot::Vvvv);
        assert_eq!(bound[2].role, OperandRole::Src);
        assert!(bound[2].mem_capable);
    }

    #[test]
    fn bind_into_template_sets_width_and_vector_len() {
        use crate::template::{Confidence, SemanticTemplate};
        let ops = vec!["ymm_reg".to_string(), "ymm_vvvv".to_string(), "ymm_or_mem".to_string()];
        let bound = bind_operands(Family::AvxVex, &ops);
        let mut t = SemanticTemplate::scalar("VADDPS", 0, Confidence::AutoValueOnly);
        bind_into_template(&mut t, &bound);
        assert_eq!(t.width_bits, 256);
        assert_eq!(t.simd.vector_len, 256);
        // dst is read-modify-write -> appears in both inputs and outputs.
        assert_eq!(t.outputs.len(), 1);
        assert_eq!(t.inputs.len(), 3);
    }
}
