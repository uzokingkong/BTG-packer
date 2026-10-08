//! Semantic rule engine.
//!
//! A rule maps a concrete instruction (via its family + mnemonic) to a
//! *lowering strategy* expressed in terms of the real BTG `RiscOp` vocabulary.
//!
//! The rule table is intentionally honest about the boundary the design note
//! calls out: iced-x86 metadata tells us an instruction *exists* and its
//! operand shape, but not its exact semantics. So the engine emits auto
//! lowerings only where a faithful template over existing RiscOps exists, and
//! otherwise classifies the instruction as needing manual semantics or as an
//! intentional native fallback (the same policy the core uses when it refuses
//! to register an op in `VirtualIsaSpec::is_encodable`).

use crate::family::Family;
use crate::template::{Confidence, ExceptionClass, Flag, SemanticTemplate};

/// Canonical RiscOp stable-names that already exist in the core VM. Kept in sync
/// with `src/vm/risc/op_registry.rs`. Used to validate that every template only
/// references ops the core actually implements.
pub const KNOWN_RISC_OPS: &[&str] = &[
    "nor",
    "add_with_carry",
    "shift_right",
    "arithmetic_shift_right",
    "shift_left",
    "rotate_left",
    "virtual_push",
    "virtual_pop",
    "memory_read",
    "memory_write",
    "virtual_branch",
    "virtual_indirect_call",
    "virtual_indirect_jump",
    "native_call_bridge",
    "vm_call_bridge",
    "set_flag",
    "halt",
    "trap",
    "virtual_ret",
    "mov",
    "sub_with_borrow",
    "add",
    "adc",
    "sbb",
    "inc",
    "dec",
    "not",
    "multiply",
    "multiply_low",
    "divide",
    "bswap",
    "bit_scan_forward",
    "bit_scan_reverse",
    "count_trailing_zeros",
    "count_leading_zeros",
    "pop_count",
    "setcc",
    "conditional_move",
    "compare_exchange",
    "lifetime_acquire",
    "lifetime_release",
    "atomic_exchange",
    "atomic_add",
    "float_add",
    "float_sub",
    "float_mul",
    "float_div",
    "int_to_float",
    "float_to_int",
    "float_to_float",
    "set_native_fp_return",
    "packed_move",
    "packed_add",
    "packed_sub",
    "packed_xor",
    "packed_and",
    "packed_or",
    "packed_and_not",
    "packed_cmp_eq",
    "packed_cmp_gt",
    "packed_unpack",
    "packed_shift_right_q",
    "packed_shift_left_logical",
    "packed_shuffle",
    "double_shift_left",
    "bit_test",
    "packed_mov_mask_bytes",
    "packed_mov_mask_ps",
    "packed_insert_word",
    "cpuid",
    "xgetbv",
    "read_segment_base",
];

/// How the generator proposes to lower an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// A faithful lowering template over existing RiscOps can be emitted
    /// automatically for review. High confidence.
    AutoTemplate,
    /// A plausible lowering exists but needs a hand-written semantic rule
    /// (operand/flag/lane parameterization the metadata cannot supply).
    ManualSemantics,
    /// Intentionally left native — virtualizing it is out of scope for the RISC
    /// core (mirrors the core's `is_encodable` exclusions).
    NativeFallback,
}

impl Strategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Strategy::AutoTemplate => "AUTO_TEMPLATE",
            Strategy::ManualSemantics => "MANUAL_SEMANTICS",
            Strategy::NativeFallback => "NATIVE_FALLBACK",
        }
    }
}

/// The resolved lowering plan for one instruction.
#[derive(Debug, Clone)]
pub struct Lowering {
    pub family: Family,
    pub strategy: Strategy,
    /// RiscOp stable-names this lowering would emit (empty for native fallback).
    pub risc_ops: Vec<&'static str>,
    /// Human-readable rationale / template summary.
    pub notes: &'static str,
}

impl Lowering {
    fn auto(family: Family, risc_ops: &[&'static str], notes: &'static str) -> Self {
        Lowering { family, strategy: Strategy::AutoTemplate, risc_ops: risc_ops.to_vec(), notes }
    }
    fn manual(family: Family, notes: &'static str) -> Self {
        Lowering { family, strategy: Strategy::ManualSemantics, risc_ops: Vec::new(), notes }
    }
    fn native(family: Family, notes: &'static str) -> Self {
        Lowering { family, strategy: Strategy::NativeFallback, risc_ops: Vec::new(), notes }
    }
}

/// Resolve the lowering plan for a given family + uppercased mnemonic.
pub fn resolve(family: Family, mnemonic_upper: &str) -> Lowering {
    use Family::*;
    match family {
        IntegerAlu => match mnemonic_upper {
            "ADD" => Lowering::auto(family, &["add"], "dst = src1 + src2, width-exact flags"),
            "SUB" | "CMP" => {
                Lowering::auto(family, &["sub_with_borrow"], "dst = src1 - src2 (CMP discards dst)")
            }
            "ADC" => Lowering::auto(family, &["adc"], "dst = src1 + src2 + CF"),
            "SBB" => Lowering::auto(family, &["sbb"], "dst = src1 - src2 - CF"),
            "INC" => Lowering::auto(family, &["inc"], "dst = src1 + 1, CF preserved"),
            "DEC" => Lowering::auto(family, &["dec"], "dst = src1 - 1, CF preserved"),
            "NOT" => Lowering::auto(family, &["not"], "dst = ~src1, flags unchanged"),
            "NEG" => Lowering::auto(
                family,
                &["sub_with_borrow"],
                "dst = 0 - src1 via sub_with_borrow(0, src1)",
            ),
            "AND" | "TEST" => Lowering::auto(
                family,
                &["nor"],
                "AND(a,b) = NOR(NOT a, NOT b); TEST discards dst, keeps flags",
            ),
            "OR" => Lowering::auto(family, &["nor"], "OR(a,b) = NOT(NOR(a,b))"),
            "XOR" => Lowering::auto(family, &["nor"], "XOR via NOR tree (De Morgan)"),
            _ => Lowering::manual(family, "integer ALU variant without a mapped template"),
        },

        DataMove => match mnemonic_upper {
            "MOV" | "MOVZX" | "MOVSX" | "MOVSXD" => {
                Lowering::auto(family, &["mov", "memory_read", "memory_write"], "flag-transparent copy / width extend")
            }
            "XCHG" => Lowering::auto(
                family,
                &["mov", "atomic_exchange"],
                "reg<->reg = 3x mov; reg<->mem = atomic_exchange (implicit LOCK)",
            ),
            "LEA" => Lowering::manual(family, "effective-address compute; reuse lifter lower_effective_address"),
            _ => Lowering::manual(family, "data-move variant without a mapped template"),
        },

        ShiftRotate => match mnemonic_upper {
            "SHL" | "SAL" => Lowering::auto(family, &["shift_left"], "logical left shift"),
            "SHR" => Lowering::auto(family, &["shift_right"], "logical right shift"),
            "SAR" => Lowering::auto(family, &["arithmetic_shift_right"], "arithmetic right shift"),
            "ROL" => Lowering::auto(family, &["rotate_left"], "rotate left at operand width"),
            "ROR" => Lowering::auto(family, &["rotate_left"], "ROR(n) = ROL(width-n)"),
            "SHLD" => Lowering::auto(family, &["double_shift_left"], "double-precision left shift"),
            "SHRD" => Lowering::manual(family, "double-precision right shift; needs SHRD op or decomposition"),
            "RCL" | "RCR" => Lowering::manual(family, "rotate-through-carry; CF participates, no direct op"),
            _ => Lowering::manual(family, "shift/rotate variant without a mapped template"),
        },

        BitManip => match mnemonic_upper {
            "BSWAP" => Lowering::auto(family, &["bswap"], "byte-order reverse (width 4/8)"),
            "BSF" => Lowering::auto(family, &["bit_scan_forward"], "index of lowest set bit, ZF on zero"),
            "BSR" => Lowering::auto(family, &["bit_scan_reverse"], "index of highest set bit, ZF on zero"),
            "POPCNT" => Lowering::auto(family, &["pop_count"], "set-bit count"),
            "TZCNT" => Lowering::auto(family, &["count_trailing_zeros"], "ctz with width/CF semantics"),
            "LZCNT" => Lowering::auto(family, &["count_leading_zeros"], "clz with width/CF semantics"),
            "BT" => Lowering::auto(family, &["bit_test"], "bit test, modify=0"),
            "BTS" => Lowering::auto(family, &["bit_test"], "bit test+set, modify=2"),
            "BTR" => Lowering::auto(family, &["bit_test"], "bit test+reset, modify=1"),
            "BTC" => Lowering::manual(family, "bit test+complement; needs modify=complement variant"),
            _ => Lowering::manual(family, "bit-manip variant without a mapped template"),
        },

        MulDiv => match mnemonic_upper {
            "MUL" => Lowering::auto(family, &["multiply"], "unsigned RDX:RAX = RAX * r/m"),
            "IMUL" => Lowering::auto(
                family,
                &["multiply", "multiply_low"],
                "1-op -> multiply(signed); 2/3-op -> multiply_low(signed)",
            ),
            "DIV" => Lowering::auto(family, &["divide"], "unsigned divide, quotient->RAX rem->RDX"),
            "IDIV" => Lowering::auto(family, &["divide"], "signed divide"),
            _ => Lowering::manual(family, "mul/div variant without a mapped template"),
        },

        Convert => Lowering::auto(
            family,
            &["mov", "shift_left", "arithmetic_shift_right", "set_flag"],
            "sign/zero extension via shl/sar pair preserving flags (cf. CDQE in lifter)",
        ),

        ControlFlow => match mnemonic_upper {
            m if m.starts_with('J') => {
                Lowering::auto(family, &["virtual_branch"], "conditional/unconditional branch")
            }
            "CALL" => Lowering::auto(
                family,
                &["virtual_push", "virtual_branch", "virtual_indirect_call"],
                "push ret_ip; branch(target) | indirect -> virtual_indirect_call",
            ),
            "RET" | "RETF" => Lowering::auto(family, &["virtual_ret"], "pop+branch-map return"),
            m if m.starts_with("SET") => {
                Lowering::auto(family, &["setcc"], "dst(8) = cond ? 1 : 0")
            }
            m if m.starts_with("CMOV") => {
                Lowering::auto(family, &["conditional_move"], "dst = cond ? src1 : dst")
            }
            "LOOP" | "LOOPE" | "LOOPNE" => {
                Lowering::auto(family, &["dec", "virtual_branch"], "dec RCX; branch on cond")
            }
            _ => Lowering::manual(family, "control-flow variant without a mapped template"),
        },

        Stack => match mnemonic_upper {
            "PUSH" => Lowering::auto(family, &["virtual_push"], "VSP -= 8; [VSP] = val"),
            "POP" => Lowering::auto(family, &["virtual_pop"], "val = [VSP]; VSP += 8"),
            "LEAVE" => Lowering::auto(family, &["mov", "virtual_pop"], "RSP=RBP; pop RBP"),
            "ENTER" => Lowering::manual(family, "framed prologue; nesting level needs manual rule"),
            "PUSHF" | "PUSHFQ" | "POPF" | "POPFQ" => {
                Lowering::manual(family, "RFLAGS push/pop; virtual-flags marshalling needed")
            }
            _ => Lowering::manual(family, "stack variant without a mapped template"),
        },

        Atomic => match mnemonic_upper {
            "XADD" => Lowering::auto(family, &["atomic_add"], "atomic [mem] += src; dst = old"),
            "CMPXCHG" => Lowering::auto(family, &["compare_exchange"], "CAS against RAX"),
            "CMPXCHG8B" | "CMPXCHG16B" => {
                Lowering::manual(family, "double-width CAS (EDX:EAX / RDX:RAX); needs wide-CAS rule")
            }
            _ => Lowering::manual(family, "atomic variant without a mapped template"),
        },

        StringOp => Lowering::manual(
            family,
            "REP-prefixed string op: loop + direction-flag + RCX counter; needs manual lowering",
        ),

        SsePackedInt => match mnemonic_upper {
            "MOVDQA" | "MOVDQU" | "MOVAPS" | "MOVUPS" | "MOVQ" | "MOVD" => {
                Lowering::auto(family, &["packed_move", "memory_read", "memory_write"], "16-byte slot copy")
            }
            "PADDB" | "PADDW" | "PADDD" | "PADDQ" => {
                Lowering::auto(family, &["packed_add"], "element-wise add (elem_width/lanes)")
            }
            "PSUBB" | "PSUBW" | "PSUBD" | "PSUBQ" => {
                Lowering::auto(family, &["packed_sub"], "element-wise sub")
            }
            "PXOR" => Lowering::auto(family, &["packed_xor"], "128-bit xor"),
            "PAND" => Lowering::auto(family, &["packed_and"], "128-bit and"),
            "POR" => Lowering::auto(family, &["packed_or"], "128-bit or"),
            "PANDN" => Lowering::auto(family, &["packed_and_not"], "128-bit (a & ~b)"),
            "PCMPEQB" | "PCMPEQW" | "PCMPEQD" | "PCMPEQQ" => {
                Lowering::auto(family, &["packed_cmp_eq"], "element equality mask")
            }
            "PCMPGTB" | "PCMPGTW" | "PCMPGTD" | "PCMPGTQ" => {
                Lowering::auto(family, &["packed_cmp_gt"], "signed element greater-than mask")
            }
            "PUNPCKLBW" | "PUNPCKLWD" | "PUNPCKLDQ" | "PUNPCKLQDQ" | "PUNPCKHBW" | "PUNPCKHWD"
            | "PUNPCKHDQ" | "PUNPCKHQDQ" => {
                Lowering::auto(family, &["packed_unpack"], "interleave low/high halves")
            }
            "PSRLQ" => Lowering::auto(family, &["packed_shift_right_q"], "per-lane 64-bit logical shift"),
            "PSHUFD" | "PSHUFLW" => Lowering::auto(family, &["packed_shuffle"], "lane shuffle by imm8"),
            "PMOVMSKB" => Lowering::auto(family, &["packed_mov_mask_bytes"], "byte sign-bit mask"),
            "PINSRW" => Lowering::auto(family, &["packed_insert_word"], "insert 16-bit lane"),
            _ => Lowering::manual(family, "packed-int variant without a mapped 128-bit template"),
        },

        SseFloat => match mnemonic_upper {
            "ADDSS" | "ADDSD" | "ADDPS" | "ADDPD" => {
                Lowering::auto(family, &["float_add"], "scalar add; packed needs lane fan-out")
            }
            "SUBSS" | "SUBSD" => Lowering::auto(family, &["float_sub"], "scalar sub"),
            "MULSS" | "MULSD" => Lowering::auto(family, &["float_mul"], "scalar mul"),
            "DIVSS" | "DIVSD" => Lowering::auto(family, &["float_div"], "scalar div"),
            "CVTSI2SS" | "CVTSI2SD" => Lowering::auto(family, &["int_to_float"], "int->float"),
            "CVTTSS2SI" | "CVTTSD2SI" | "CVTSS2SI" | "CVTSD2SI" => {
                Lowering::auto(family, &["float_to_int"], "float->int (truncate flag)")
            }
            "CVTSS2SD" | "CVTSD2SS" => Lowering::auto(family, &["float_to_float"], "float width convert"),
            "MOVSS" | "MOVSD" | "MOVAPS" | "MOVUPS" | "MOVAPD" | "MOVUPD" => {
                Lowering::auto(family, &["packed_move"], "scalar/packed float move")
            }
            _ => Lowering::manual(family, "SSE-float variant without a mapped scalar template"),
        },

        // Vector extensions whose parameterization (lanes/mask/broadcast) the
        // metadata cannot supply: route to manual semantics so a human authors
        // the lane/mask rule rather than the generator guessing.
        AvxVex => Lowering::manual(
            family,
            "VEX 3-operand / 256-bit lanes; existing Packed* ops are 128-bit slot based",
        ),
        Avx512Evex => Lowering::manual(
            family,
            "EVEX masking/zeroing/broadcast/512-bit; needs parameterized packed-op family",
        ),
        Bmi => Lowering::manual(family, "BMI1/BMI2 bit-field ops; most need dedicated RiscOps"),

        // Intentional native fallbacks (mirror core is_encodable exclusions).
        Amx => Lowering::native(family, "AMX tile state; not virtualized by the RISC core"),
        Crypto => Lowering::native(family, "AES/SHA/PCLMUL: keep native accelerated path"),
        Random => Lowering::native(family, "RDRAND/RDSEED: non-deterministic, keep native"),
        X87 => Lowering::native(family, "x87 FPU stack model out of RISC-core scope"),
        StateSave => Lowering::native(family, "XSAVE/FXSAVE family: large arch state, keep native"),
        SystemPrivileged => Lowering::native(family, "privileged/ring-0/IO: not virtualizable"),
        NopFence => Lowering::auto(family, &[], "no micro-op (NOP) / fence hint"),

        Unknown => Lowering::manual(family, "unclassified instruction; inspect manually"),
    }
}

/// Validate that a lowering references only real RiscOps.
pub fn template_ops_are_known(l: &Lowering) -> bool {
    l.risc_ops.iter().all(|op| KNOWN_RISC_OPS.contains(op))
}

// ── Semantic IR bridge (Priority 1) ──────────────────────────────────────────
//
// `confidence_ceiling` is the *maximum* tier a lowering could ever reach given
// how it is constructed — an honest static upper bound, NOT a claim that the
// lowering is already correct. A template's `proven` flag (set only by the
// differential oracle, Priority 3) stays false until measured, so nothing is
// auto-emittable yet regardless of ceiling. The one guarantee we make here is
// the design note's requirement: a pseudo lowering (value-correct but not
// flag/semantic-exact — AND/OR/XOR/TEST via NOR, NEG via sub, and anything we
// are not yet confident about) can never exceed `AutoValueOnly`.

/// Mnemonics whose auto-template is flag-faithful by construction: each maps to
/// a dedicated flag-aware core RiscOp (or writes no flags at all, like MOV).
/// Everything else that auto-lowers is capped at `AutoValueOnly` until the
/// oracle proves otherwise.
fn is_flag_faithful_auto(mnemonic_upper: &str) -> bool {
    matches!(
        mnemonic_upper,
        // Integer ALU mapping 1:1 onto flag-aware ops (add/sub_with_borrow/adc/
        // sbb/inc/dec/not). NOT writes no flags, so it is trivially flag-exact.
        "ADD" | "SUB" | "CMP" | "ADC" | "SBB" | "INC" | "DEC" | "NOT"
        // Flag-transparent data moves (define no flags).
        | "MOV" | "MOVZX" | "MOVSX" | "MOVSXD"
    )
}

/// The honest upper bound on a lowering's confidence tier.
pub fn confidence_ceiling(l: &Lowering, mnemonic_upper: &str) -> Confidence {
    match l.strategy {
        Strategy::NativeFallback => Confidence::NativeFallback,
        Strategy::ManualSemantics => Confidence::Manual,
        Strategy::AutoTemplate => {
            // An effect-free hint/fence that lowers to no micro-op is a provable
            // no-op in the single-threaded reference model (see family.rs): there
            // is nothing to get wrong, so it is semantically exact.
            if l.family == Family::NopFence && l.risc_ops.is_empty() {
                Confidence::AutoSemanticExact
            } else if is_flag_faithful_auto(mnemonic_upper) {
                // Flag-exact ceiling; memory/SIMD exactness still unproven, so we
                // do not claim AutoMemoryExact/AutoSemanticExact yet.
                Confidence::AutoFlagExact
            } else {
                // Pseudo lowering or anything not yet confidence-classified.
                Confidence::AutoValueOnly
            }
        }
    }
}

/// x86 flag *definedness* for the common scalar families, so the report and the
/// future oracle know which bits a faithful lowering must reproduce. This is the
/// instruction's spec, independent of whether the lowering achieves it.
fn flags_for(family: Family, mnemonic_upper: &str) -> (Vec<Flag>, Vec<Flag>) {
    use Family::*;
    let all = Flag::ARITH.to_vec();
    match (family, mnemonic_upper) {
        // Reads CF, defines all six.
        (IntegerAlu, "ADC") | (IntegerAlu, "SBB") => (vec![Flag::Cf], all),
        // INC/DEC define all arithmetic flags EXCEPT CF.
        (IntegerAlu, "INC") | (IntegerAlu, "DEC") => {
            (vec![], vec![Flag::Pf, Flag::Af, Flag::Zf, Flag::Sf, Flag::Of])
        }
        // NOT writes no flags.
        (IntegerAlu, "NOT") => (vec![], vec![]),
        // ADD/SUB/CMP/AND/OR/XOR/TEST/NEG define all six.
        (IntegerAlu, _) => (vec![], all),
        // Shifts define CF/OF (and SF/ZF/PF); count-dependent — oracle territory.
        (ShiftRotate, _) => (vec![], all),
        // MUL/IMUL define CF/OF; DIV/IDIV leave flags undefined.
        (MulDiv, "MUL") | (MulDiv, "IMUL") => (vec![], vec![Flag::Cf, Flag::Of]),
        // Data moves are flag-transparent.
        (DataMove, _) => (vec![], vec![]),
        _ => (vec![], vec![]),
    }
}

/// Build the semantic template for a resolved lowering. Operand widths/lanes are
/// left unbound (width 0) until the operand binder (Priority 2); SIMD shape is
/// scalar until the SIMD engine (Priority 4). This records what we know now:
/// the mnemonic, flag spec, memory/fault class, and the confidence ceiling.
pub fn semantic_template(l: &Lowering, mnemonic_upper: &str) -> SemanticTemplate {
    let ceiling = confidence_ceiling(l, mnemonic_upper);
    let (flags_read, flags_write) = flags_for(l.family, mnemonic_upper);

    let mem_read = l.risc_ops.iter().any(|op| *op == "memory_read")
        || l.risc_ops.iter().any(|op| *op == "virtual_pop");
    let mem_write = l.risc_ops.iter().any(|op| *op == "memory_write")
        || l.risc_ops.iter().any(|op| *op == "virtual_push");

    let exception = match l.family {
        Family::MulDiv if matches!(mnemonic_upper, "DIV" | "IDIV") => ExceptionClass::DivideError,
        _ if mem_read || mem_write => ExceptionClass::MemoryFault,
        Family::ControlFlow => ExceptionClass::ControlFault,
        _ => ExceptionClass::None,
    };

    let mut t = SemanticTemplate::scalar(mnemonic_upper, 0, ceiling)
        .reads_flags(&flags_read)
        .writes_flags(&flags_write)
        .reads_mem(mem_read)
        .writes_mem(mem_write)
        .faults(exception);

    // Record the lowering rationale as a side-effect note so the IR carries the
    // same human context the old report did.
    t = t.side_effect(l.notes);
    t
}

/// Build the semantic template and bind concrete operands onto it (Priority 2).
/// `op_kinds` are the iced `OpCodeOperandKind` strings from the coverage DB.
pub fn semantic_template_bound(
    l: &Lowering,
    mnemonic_upper: &str,
    op_kinds: &[String],
) -> SemanticTemplate {
    let mut t = semantic_template(l, mnemonic_upper);
    if !op_kinds.is_empty() {
        let bound = crate::binder::bind_operands(l.family, op_kinds);
        crate::binder::bind_into_template(&mut t, &bound);
    }
    t
}
