//! SIMD / EVEX semantic parameter engine (Priority 4).
//!
//! Turns the coverage DB's vector metadata into explicit `SemanticTemplate`
//! parameters: vector length (128/256/512 from the operand class), element
//! width and lane count (from the mnemonic suffix), and the EVEX decorations
//! the auditor records — opmask / zeroing / broadcast. Rounding-control and SAE
//! are NOT in the coverage DB yet, so they are left unset and surfaced as a gap
//! rather than guessed.
//!
//! It also defines a `SemanticSignature`: the full identity of an instruction
//! form (encoding + vector length + element width + decorations + CPUID) that
//! the family/confidence logic consults instead of the mnemonic alone, since the
//! same mnemonic (ADD vs VADDPS vs EVEX VADDPS) can mean very different things.

use crate::binder::{BoundOperand, OperandClass};
use crate::template::SimdShape;

/// Element width in bits inferred from an uppercased mnemonic suffix.
///
/// Packed-float suffixes win over the single-letter integer suffixes: `...PS`
/// / `...SS` are 32-bit, `...PD` / `...SD` are 64-bit; otherwise a trailing
/// `B`/`W`/`D`/`Q` is 8/16/32/64. Returns 0 when the element width cannot be
/// determined from the mnemonic alone.
pub fn element_bits_for(mnemonic_upper: &str) -> u16 {
    let m = mnemonic_upper;
    if m.ends_with("PS") || m.ends_with("SS") {
        return 32;
    }
    if m.ends_with("PD") || m.ends_with("SD") {
        return 64;
    }
    match m.chars().last() {
        Some('B') => 8,
        Some('W') => 16,
        Some('D') => 32,
        Some('Q') => 64,
        _ => 0,
    }
}

/// The widest vector operand class present (xmm/ymm/zmm), as a vector length in
/// bits, else 0.
fn vector_len_of(operands: &[BoundOperand]) -> u16 {
    operands
        .iter()
        .filter(|b| b.class.is_vector())
        .map(|b| b.class.vector_len())
        .max()
        .unwrap_or(0)
}

/// Build the full SIMD shape for an instruction form from its bound operands,
/// mnemonic, and the EVEX decorations recorded in the coverage DB.
pub fn build_simd_shape(
    operands: &[BoundOperand],
    mnemonic_upper: &str,
    opmask: &str,
    zeroing: bool,
    broadcast: bool,
) -> SimdShape {
    let vector_len = vector_len_of(operands);
    if vector_len == 0 {
        // Not a vector form; nothing to parameterise.
        return SimdShape::default();
    }
    let element_bits = element_bits_for(mnemonic_upper);
    // Scalar SS/SD forms operate on a single (low) lane, not the full vector.
    let is_scalar = mnemonic_upper.ends_with("SS") || mnemonic_upper.ends_with("SD");
    let lanes = if is_scalar {
        1
    } else if element_bits != 0 {
        vector_len / element_bits
    } else {
        0
    };
    let masked = opmask.eq_ignore_ascii_case("K1") || operands.iter().any(|b| b.class == OperandClass::Mask);
    SimdShape {
        vector_len,
        element_bits,
        lanes,
        masked,
        zeroing,
        broadcast,
        // Rounding/SAE are not represented in the coverage DB; see module note.
        rounding_sae: false,
    }
}

/// Instruction encoding, as a coarse bucket for the semantic signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Legacy,
    Vex,
    Evex,
    Other,
}

impl Encoding {
    pub fn parse(s: &str) -> Encoding {
        match s.to_ascii_uppercase().as_str() {
            "LEGACY" => Encoding::Legacy,
            "VEX" => Encoding::Vex,
            "EVEX" => Encoding::Evex,
            _ => Encoding::Other,
        }
    }
}

/// The full identity of an instruction form. The family/confidence logic keys on
/// this rather than the mnemonic alone, so EVEX-with-mask is never conflated
/// with its legacy namesake.
#[derive(Debug, Clone)]
pub struct SemanticSignature {
    pub mnemonic: String,
    pub encoding: Encoding,
    pub simd: SimdShape,
    pub cpuid: Vec<String>,
}

impl SemanticSignature {
    pub fn new(
        mnemonic_upper: &str,
        encoding: &str,
        operands: &[BoundOperand],
        opmask: &str,
        zeroing: bool,
        broadcast: bool,
        cpuid: &[String],
    ) -> Self {
        SemanticSignature {
            mnemonic: mnemonic_upper.to_string(),
            encoding: Encoding::parse(encoding),
            simd: build_simd_shape(operands, mnemonic_upper, opmask, zeroing, broadcast),
            cpuid: cpuid.to_vec(),
        }
    }

    /// Whether the form carries EVEX features that the current Packed* RiscOps
    /// cannot represent (mask / zeroing / broadcast / 512-bit / rounding-SAE),
    /// so it must NOT be auto-lowered onto the 128-bit slot ops.
    pub fn needs_parameterized_vector_op(&self) -> bool {
        self.encoding == Encoding::Evex
            && (self.simd.masked
                || self.simd.zeroing
                || self.simd.broadcast
                || self.simd.rounding_sae
                || self.simd.vector_len > 128)
    }

    /// Whether the form is a wider-than-128 VEX/EVEX vector (256/512) — the
    /// existing Packed* ops are 128-bit slot based, so these need lane fan-out.
    pub fn is_wide_vector(&self) -> bool {
        self.simd.vector_len > 128
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binder::bind_operands;
    use crate::family::Family;

    #[test]
    fn element_width_from_suffix() {
        assert_eq!(element_bits_for("PADDB"), 8);
        assert_eq!(element_bits_for("PADDW"), 16);
        assert_eq!(element_bits_for("PADDD"), 32);
        assert_eq!(element_bits_for("PADDQ"), 64);
        assert_eq!(element_bits_for("VADDPS"), 32);
        assert_eq!(element_bits_for("VADDPD"), 64);
        assert_eq!(element_bits_for("ADDSS"), 32);
    }

    #[test]
    fn xmm_paddd_has_four_32bit_lanes() {
        let ops = bind_operands(Family::SsePackedInt, &["xmm_reg".into(), "xmm_or_mem".into()]);
        let shape = build_simd_shape(&ops, "PADDD", "none", false, false);
        assert_eq!(shape.vector_len, 128);
        assert_eq!(shape.element_bits, 32);
        assert_eq!(shape.lanes, 4);
        assert!(!shape.masked);
    }

    #[test]
    fn evex_zmm_vaddps_is_wide_and_masked() {
        let ops = bind_operands(
            Family::Avx512Evex,
            &["zmm_reg".into(), "k_reg".into(), "zmm_vvvv".into(), "zmm_or_mem".into()],
        );
        let sig = SemanticSignature::new(
            "VADDPS", "EVEX", &ops, "K1", true, false, &["AVX512F".into()],
        );
        assert_eq!(sig.simd.vector_len, 512);
        assert_eq!(sig.simd.element_bits, 32);
        assert_eq!(sig.simd.lanes, 16);
        assert!(sig.simd.masked);
        assert!(sig.simd.zeroing);
        assert!(sig.is_wide_vector());
        assert!(
            sig.needs_parameterized_vector_op(),
            "EVEX masked 512-bit must not auto-lower onto 128-bit slot ops"
        );
    }

    #[test]
    fn legacy_xmm_does_not_need_parameterized_op() {
        let ops = bind_operands(Family::SsePackedInt, &["xmm_reg".into(), "xmm_or_mem".into()]);
        let sig = SemanticSignature::new("PADDD", "Legacy", &ops, "none", false, false, &[]);
        assert!(!sig.needs_parameterized_vector_op());
        assert!(!sig.is_wide_vector());
    }
}
