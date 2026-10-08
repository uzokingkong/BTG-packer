//! Semantic IR (Priority 1).
//!
//! A `SemanticTemplate` is the generator's *honest model* of what an x86
//! instruction does, independent of how (or whether) we can lower it onto the
//! BTG RiscOp vocabulary. It separates two things the old `Lowering` conflated:
//!
//!   1. the **intended semantics** of the instruction (which registers/flags it
//!      reads and writes, operand widths, lane count, memory effects, faults);
//!   2. how **confident** we are that a proposed RiscOp lowering actually
//!      reproduces those semantics.
//!
//! The confidence tier is the mechanism the design note asks for: pseudo
//! lowerings such as `AND(a,b) = NOR(NOT a, NOT b)` or `NEG = sub_with_borrow`
//! are *value*-correct but do not reproduce x86 flag semantics, so they are
//! pinned at `AutoValueOnly` and can never be promoted to an auto-emittable
//! tier until a differential oracle (Priority 3) proves equality. Nothing in
//! this module decides to emit anything; it only records what is true and how
//! strongly we can back it.

use serde::Serialize;

/// Confidence that a proposed lowering reproduces the instruction's semantics.
///
/// Ordering is meaningful: a higher tier subsumes every guarantee below it, and
/// the closed-loop CI (Priority 5) compares against a threshold
/// (`>= AutoSemanticExact`) before it will auto-wire anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Confidence {
    /// A hand-written semantic rule is required; the generator will not emit a
    /// lowering. (Also the resting state for anything unproven and unclassified.)
    Manual,
    /// Intentionally kept on the native path (mirrors the core's `is_encodable`
    /// exclusions): x87, crypto accelerators, RNG, privileged, large state save.
    NativeFallback,
    /// The lowering computes the correct destination *value* but does NOT
    /// reproduce x86 flag results (e.g. AND via NOR, NEG via sub). Never
    /// auto-emittable as-is.
    AutoValueOnly,
    /// Value AND all written RFLAGS bits match x86 for the modelled widths.
    AutoFlagExact,
    /// Flag-exact AND memory read/write effects (addresses, widths, ordering)
    /// match x86.
    AutoMemoryExact,
    /// Fully semantically exact: value, flags, memory, and any SIMD lane / mask
    /// / rounding behaviour match x86. The only tier CI may auto-wire.
    AutoSemanticExact,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Manual => "MANUAL",
            Confidence::NativeFallback => "NATIVE_FALLBACK",
            Confidence::AutoValueOnly => "AUTO_VALUE_ONLY",
            Confidence::AutoFlagExact => "AUTO_FLAG_EXACT",
            Confidence::AutoMemoryExact => "AUTO_MEMORY_EXACT",
            Confidence::AutoSemanticExact => "AUTO_SEMANTIC_EXACT",
        }
    }

    /// Whether this tier, once *proven*, is allowed to be auto-wired into the
    /// core by the closed loop. (Proof is a separate axis — see
    /// [`SemanticTemplate::proven`].)
    pub fn is_auto_wireable(self) -> bool {
        matches!(self, Confidence::AutoSemanticExact)
    }
}

/// An x86 RFLAGS status bit the reference model tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Flag {
    Cf,
    Pf,
    Af,
    Zf,
    Sf,
    Of,
    Df,
}

impl Flag {
    pub fn as_str(self) -> &'static str {
        match self {
            Flag::Cf => "CF",
            Flag::Pf => "PF",
            Flag::Af => "AF",
            Flag::Zf => "ZF",
            Flag::Sf => "SF",
            Flag::Of => "OF",
            Flag::Df => "DF",
        }
    }

    /// The six arithmetic status flags (everything except DF).
    pub const ARITH: &'static [Flag] =
        &[Flag::Cf, Flag::Pf, Flag::Af, Flag::Zf, Flag::Sf, Flag::Of];
}

/// The role an operand plays in an instruction. Populated by the operand binder
/// (Priority 2) from iced-x86 operand metadata; declared here so the IR is
/// stable before the binder lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OperandRole {
    /// Written-only destination (iced Op0 for most 2-operand forms).
    Dst,
    /// Read source.
    Src,
    /// Read+written in place (e.g. the memory/reg operand of ADD r/m, r).
    ReadWrite,
    /// Immediate.
    Imm,
    /// Memory operand (effective address); `mem_*` on the template says the
    /// access direction.
    Mem,
    /// Implicit register operand (e.g. RAX/RDX for MUL/DIV, RCX for shifts).
    Implicit,
}

/// One operand slot of the instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Operand {
    pub role: OperandRole,
    /// Width in bits (8/16/32/64/128/256/512). `0` = not yet bound.
    pub width_bits: u16,
    /// Optional human label for the slot (e.g. "RAX", "imm8", "xmm/m128").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Operand {
    pub fn new(role: OperandRole, width_bits: u16) -> Self {
        Operand { role, width_bits, label: None }
    }
    pub fn labeled(role: OperandRole, width_bits: u16, label: &str) -> Self {
        Operand { role, width_bits, label: Some(label.to_string()) }
    }
}

/// The exception / fault class an instruction can raise, so the reference
/// executor (Priority 3) knows which traps are in-scope to compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ExceptionClass {
    /// Cannot fault from its own semantics (register-only ALU, NOP).
    None,
    /// #DE on divide overflow / div-by-zero.
    DivideError,
    /// #GP / #SS / #PF from a memory operand.
    MemoryFault,
    /// #UD when the feature/mode is unavailable.
    InvalidOpcode,
    /// #PF-style control transfer fault (bad branch target).
    ControlFault,
}

/// SIMD shape parameters. All default to the scalar/absent case so integer
/// templates need not mention them; the SIMD engine (Priority 4) fills them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct SimdShape {
    /// Vector length in bits: 0 (not SIMD), 128, 256, or 512.
    pub vector_len: u16,
    /// Element width in bits (8/16/32/64) for packed ops; 0 if scalar.
    pub element_bits: u16,
    /// Number of lanes (vector_len / element_bits) when packed.
    pub lanes: u16,
    /// EVEX masking in effect (k-register merge/zero).
    pub masked: bool,
    /// Zeroing (`{z}`) vs merge masking.
    pub zeroing: bool,
    /// Embedded broadcast (`{1toN}`).
    pub broadcast: bool,
    /// Embedded rounding control / SAE (`{er}` / `{sae}`).
    pub rounding_sae: bool,
}

impl SimdShape {
    pub fn is_simd(&self) -> bool {
        self.vector_len != 0
    }
}

/// The honest semantic model of one instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticTemplate {
    /// Uppercased mnemonic this template models.
    pub mnemonic: String,
    /// Operands that are read.
    pub inputs: Vec<Operand>,
    /// Operands that are written.
    pub outputs: Vec<Operand>,
    /// Primary operation width in bits (the width flags are computed at).
    pub width_bits: u16,
    /// SIMD shape (absent for scalar integer).
    pub simd: SimdShape,
    /// RFLAGS bits the instruction reads (consumes), e.g. CF for ADC.
    pub flags_read: Vec<Flag>,
    /// RFLAGS bits the instruction defines (writes to a defined value).
    pub flags_write: Vec<Flag>,
    /// Instruction reads memory.
    pub mem_read: bool,
    /// Instruction writes memory.
    pub mem_write: bool,
    /// Fault class.
    pub exception: ExceptionClass,
    /// Free-form notes on implicit effects not captured above (e.g. "RDX:RAX",
    /// "advances RSI/RDI by DF", "sets RCX=0").
    pub side_effects: Vec<String>,
    /// The confidence tier we *claim* for a lowering of this instruction.
    pub confidence: Confidence,
    /// Whether that claim has been **proven** by the differential oracle
    /// (Priority 3). Always `false` until the oracle runs. CI auto-wiring
    /// requires `proven && confidence.is_auto_wireable()`.
    pub proven: bool,
}

impl SemanticTemplate {
    /// Start a template for `mnemonic` at the given scalar width. Everything
    /// else defaults to the empty/absent case; builder methods fill in the rest.
    pub fn scalar(mnemonic: &str, width_bits: u16, confidence: Confidence) -> Self {
        SemanticTemplate {
            mnemonic: mnemonic.to_string(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            width_bits,
            simd: SimdShape::default(),
            flags_read: Vec::new(),
            flags_write: Vec::new(),
            mem_read: false,
            mem_write: false,
            exception: ExceptionClass::None,
            side_effects: Vec::new(),
            confidence,
            proven: false,
        }
    }

    pub fn with_inputs(mut self, ops: Vec<Operand>) -> Self {
        self.inputs = ops;
        self
    }
    pub fn with_outputs(mut self, ops: Vec<Operand>) -> Self {
        self.outputs = ops;
        self
    }
    pub fn reads_flags(mut self, flags: &[Flag]) -> Self {
        self.flags_read = flags.to_vec();
        self
    }
    pub fn writes_flags(mut self, flags: &[Flag]) -> Self {
        self.flags_write = flags.to_vec();
        self
    }
    pub fn reads_mem(mut self, yes: bool) -> Self {
        self.mem_read = yes;
        self
    }
    pub fn writes_mem(mut self, yes: bool) -> Self {
        self.mem_write = yes;
        self
    }
    pub fn faults(mut self, class: ExceptionClass) -> Self {
        self.exception = class;
        self
    }
    pub fn side_effect(mut self, note: &str) -> Self {
        self.side_effects.push(note.to_string());
        self
    }
    pub fn with_simd(mut self, simd: SimdShape) -> Self {
        self.simd = simd;
        self
    }

    /// Mark the claim as proven (only the oracle should call this).
    pub fn mark_proven(mut self) -> Self {
        self.proven = true;
        self
    }

    /// Whether the closed loop may auto-wire this template: the claimed tier is
    /// auto-wireable AND the claim has been proven.
    pub fn is_auto_emittable(&self) -> bool {
        self.proven && self.confidence.is_auto_wireable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_orders_value_below_semantic() {
        assert!(Confidence::AutoValueOnly < Confidence::AutoFlagExact);
        assert!(Confidence::AutoFlagExact < Confidence::AutoMemoryExact);
        assert!(Confidence::AutoMemoryExact < Confidence::AutoSemanticExact);
        // Only the top tier is auto-wireable.
        assert!(Confidence::AutoSemanticExact.is_auto_wireable());
        assert!(!Confidence::AutoValueOnly.is_auto_wireable());
        assert!(!Confidence::AutoFlagExact.is_auto_wireable());
    }

    #[test]
    fn pseudo_lowering_is_never_auto_emittable() {
        // AND via NOR: value-correct, flags NOT modelled -> AutoValueOnly.
        let and = SemanticTemplate::scalar("AND", 32, Confidence::AutoValueOnly)
            .with_inputs(vec![
                Operand::new(OperandRole::ReadWrite, 32),
                Operand::new(OperandRole::Src, 32),
            ])
            .with_outputs(vec![Operand::new(OperandRole::Dst, 32)])
            // x86 AND defines all six arithmetic flags; our NOR tree does not,
            // which is exactly why it stays AutoValueOnly.
            .writes_flags(Flag::ARITH);
        assert!(!and.is_auto_emittable(), "value-only pseudo lowering must not auto-emit");
        // Even if someone wrongly flips `proven`, the tier still blocks it.
        assert!(!and.mark_proven().is_auto_emittable());
    }

    #[test]
    fn semantic_exact_requires_proof() {
        let add = SemanticTemplate::scalar("ADD", 64, Confidence::AutoSemanticExact)
            .writes_flags(Flag::ARITH);
        // Claimed top tier, but unproven -> still not auto-emittable.
        assert!(!add.is_auto_emittable());
        assert!(add.mark_proven().is_auto_emittable());
    }

    #[test]
    fn adc_reads_and_writes_carry() {
        let adc = SemanticTemplate::scalar("ADC", 32, Confidence::AutoValueOnly)
            .reads_flags(&[Flag::Cf])
            .writes_flags(Flag::ARITH);
        assert!(adc.flags_read.contains(&Flag::Cf));
        assert!(adc.flags_write.contains(&Flag::Of));
    }

    #[test]
    fn simd_shape_defaults_scalar() {
        let t = SemanticTemplate::scalar("ADD", 32, Confidence::AutoValueOnly);
        assert!(!t.simd.is_simd());
        let packed = SimdShape { vector_len: 256, element_bits: 32, lanes: 8, ..Default::default() };
        assert!(packed.is_simd());
        assert_eq!(packed.lanes, 8);
    }
}
