//! Canonical, parameter-independent registry for RISC micro-operations.
//!
//! This module deliberately reports only capabilities backed by current execution
//! paths. In particular, codec/interpreter/native-threaded support follows the
//! commercial allow-list in `VirtualIsaSpec::is_encodable`.

use super::MicroInstr;
use super::RiscOp;
use thiserror::Error;

macro_rules! kinds {
    ($( $kind:ident => $name:literal ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum RiscOpKind { $( $kind ),+ }

        impl RiscOpKind {
            /// Stable, parameter-independent identifier suitable for manifests.
            pub const fn stable_name(self) -> &'static str {
                match self { $( Self::$kind => $name ),+ }
            }

            pub const ALL: &'static [Self] = &[$( Self::$kind ),+];
        }
    };
}

kinds! {
    Nor => "nor", AddWithCarry => "add_with_carry", ShiftRight => "shift_right",
    ArithmeticShiftRight => "arithmetic_shift_right", ShiftLeft => "shift_left",
    RotateLeft => "rotate_left", VirtualPush => "virtual_push", VirtualPop => "virtual_pop",
    MemoryRead => "memory_read", MemoryWrite => "memory_write", VirtualBranch => "virtual_branch",
    VirtualIndirectCall => "virtual_indirect_call", VirtualIndirectJump => "virtual_indirect_jump",
    NativeCallBridge => "native_call_bridge", VmCallBridge => "vm_call_bridge", SetFlag => "set_flag",
    Halt => "halt", Trap => "trap", VirtualRet => "virtual_ret", Mov => "mov",
    SubWithBorrow => "sub_with_borrow", Add => "add", Adc => "adc", Sbb => "sbb",
    Inc => "inc", Dec => "dec", Not => "not", Multiply => "multiply",
    MultiplyLow => "multiply_low", Divide => "divide", BSwap => "bswap",
    BitScanForward => "bit_scan_forward", BitScanReverse => "bit_scan_reverse",
    CountTrailingZeros => "count_trailing_zeros", CountLeadingZeros => "count_leading_zeros",
    PopCount => "pop_count", Setcc => "setcc", ConditionalMove => "conditional_move",
    CompareExchange => "compare_exchange", LifetimeAcquire => "lifetime_acquire",
    LifetimeRelease => "lifetime_release", AtomicExchange => "atomic_exchange", AtomicAdd => "atomic_add",
    FloatAdd => "float_add", FloatSub => "float_sub", FloatMul => "float_mul", FloatDiv => "float_div",
    IntToFloat => "int_to_float", FloatToInt => "float_to_int", FloatToFloat => "float_to_float",
    SetNativeFpReturn => "set_native_fp_return", PackedMove => "packed_move", PackedAdd => "packed_add",
    PackedSub => "packed_sub", PackedXor => "packed_xor", PackedAnd => "packed_and",
    PackedOr => "packed_or", PackedAndNot => "packed_and_not", PackedCmpEq => "packed_cmp_eq",
    PackedCmpGt => "packed_cmp_gt", PackedUnpack => "packed_unpack",
    PackedShiftRightQ => "packed_shift_right_q", PackedShuffle => "packed_shuffle",
    DoubleShiftLeft => "double_shift_left", BitTest => "bit_test",
    PackedMovMaskBytes => "packed_mov_mask_bytes", PackedMovMaskPs => "packed_mov_mask_ps",
    PackedInsertWord => "packed_insert_word", CpuId => "cpuid", XGetBv => "xgetbv",
    ReadSegmentBase => "read_segment_base"
}

impl RiscOp {
    /// Normalize an operation by discarding widths, conditions, and other operands.
    pub const fn kind(self) -> RiscOpKind {
        use RiscOp::*;
        match self {
            Nor => RiscOpKind::Nor,
            AddWithCarry => RiscOpKind::AddWithCarry,
            ShiftRight => RiscOpKind::ShiftRight,
            ArithmeticShiftRight => RiscOpKind::ArithmeticShiftRight,
            ShiftLeft => RiscOpKind::ShiftLeft,
            RotateLeft { .. } => RiscOpKind::RotateLeft,
            VirtualPush => RiscOpKind::VirtualPush,
            VirtualPop => RiscOpKind::VirtualPop,
            MemoryRead { .. } => RiscOpKind::MemoryRead,
            MemoryWrite { .. } => RiscOpKind::MemoryWrite,
            VirtualBranch { .. } => RiscOpKind::VirtualBranch,
            VirtualIndirectCall => RiscOpKind::VirtualIndirectCall,
            VirtualIndirectJump => RiscOpKind::VirtualIndirectJump,
            NativeCallBridge => RiscOpKind::NativeCallBridge,
            VmCallBridge => RiscOpKind::VmCallBridge,
            SetFlag => RiscOpKind::SetFlag,
            Halt => RiscOpKind::Halt,
            Trap => RiscOpKind::Trap,
            VirtualRet => RiscOpKind::VirtualRet,
            Mov => RiscOpKind::Mov,
            SubWithBorrow { .. } => RiscOpKind::SubWithBorrow,
            Add { .. } => RiscOpKind::Add,
            Adc { .. } => RiscOpKind::Adc,
            Sbb { .. } => RiscOpKind::Sbb,
            Inc { .. } => RiscOpKind::Inc,
            Dec { .. } => RiscOpKind::Dec,
            Not { .. } => RiscOpKind::Not,
            Multiply { .. } => RiscOpKind::Multiply,
            MultiplyLow { .. } => RiscOpKind::MultiplyLow,
            Divide { .. } => RiscOpKind::Divide,
            BSwap { .. } => RiscOpKind::BSwap,
            BitScanForward => RiscOpKind::BitScanForward,
            BitScanReverse => RiscOpKind::BitScanReverse,
            CountTrailingZeros { .. } => RiscOpKind::CountTrailingZeros,
            CountLeadingZeros { .. } => RiscOpKind::CountLeadingZeros,
            PopCount => RiscOpKind::PopCount,
            Setcc { .. } => RiscOpKind::Setcc,
            ConditionalMove { .. } => RiscOpKind::ConditionalMove,
            CompareExchange { .. } => RiscOpKind::CompareExchange,
            LifetimeAcquire => RiscOpKind::LifetimeAcquire,
            LifetimeRelease => RiscOpKind::LifetimeRelease,
            AtomicExchange { .. } => RiscOpKind::AtomicExchange,
            AtomicAdd { .. } => RiscOpKind::AtomicAdd,
            FloatAdd { .. } => RiscOpKind::FloatAdd,
            FloatSub { .. } => RiscOpKind::FloatSub,
            FloatMul { .. } => RiscOpKind::FloatMul,
            FloatDiv { .. } => RiscOpKind::FloatDiv,
            IntToFloat { .. } => RiscOpKind::IntToFloat,
            FloatToInt { .. } => RiscOpKind::FloatToInt,
            FloatToFloat { .. } => RiscOpKind::FloatToFloat,
            SetNativeFpReturn { .. } => RiscOpKind::SetNativeFpReturn,
            PackedMove => RiscOpKind::PackedMove,
            PackedAdd { .. } => RiscOpKind::PackedAdd,
            PackedSub { .. } => RiscOpKind::PackedSub,
            PackedXor => RiscOpKind::PackedXor,
            PackedAnd => RiscOpKind::PackedAnd,
            PackedOr => RiscOpKind::PackedOr,
            PackedAndNot => RiscOpKind::PackedAndNot,
            PackedCmpEq { .. } => RiscOpKind::PackedCmpEq,
            PackedCmpGt { .. } => RiscOpKind::PackedCmpGt,
            PackedUnpack { .. } => RiscOpKind::PackedUnpack,
            PackedShiftRightQ => RiscOpKind::PackedShiftRightQ,
            PackedShuffle { .. } => RiscOpKind::PackedShuffle,
            DoubleShiftLeft { .. } => RiscOpKind::DoubleShiftLeft,
            BitTest { .. } => RiscOpKind::BitTest,
            PackedMovMaskBytes => RiscOpKind::PackedMovMaskBytes,
            PackedMovMaskPs => RiscOpKind::PackedMovMaskPs,
            PackedInsertWord => RiscOpKind::PackedInsertWord,
            CpuId => RiscOpKind::CpuId,
            XGetBv => RiscOpKind::XGetBv,
            ReadSegmentBase { .. } => RiscOpKind::ReadSegmentBase,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiscOpCapabilities {
    pub evaluator: bool,
    pub poly_codec: bool,
    pub poly_interpreter: bool,
    pub production_threaded: bool,
    pub reads_flags: bool,
    pub writes_flags: bool,
    pub may_fault: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommercialCapability {
    Evaluator,
    PolyCodec,
    PolyInterpreter,
    ProductionThreaded,
}

impl CommercialCapability {
    pub const fn stable_name(self) -> &'static str {
        match self {
            Self::Evaluator => "evaluator",
            Self::PolyCodec => "poly_codec",
            Self::PolyInterpreter => "poly_interpreter",
            Self::ProductionThreaded => "production_threaded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "commercial opcode capability mismatch at micro-op {instruction_index}: {op_name} missing {missing_names}",
    missing_names = .missing.iter().map(|cap| cap.stable_name()).collect::<Vec<_>>().join(",")
)]
pub struct CommercialCapabilityError {
    pub instruction_index: usize,
    pub op_name: &'static str,
    pub missing: Vec<CommercialCapability>,
}

/// Assert the complete capability contract required by commercial poly/native
/// production. This is intentionally fail-closed: every instruction must be
/// supported by all four execution stages before any output is emitted.
pub fn assert_commercial_capabilities(
    instrs: &[MicroInstr],
) -> Result<(), CommercialCapabilityError> {
    for (instruction_index, instr) in instrs.iter().enumerate() {
        let caps = capabilities(instr.op);
        let mut missing = Vec::new();
        if !caps.evaluator {
            missing.push(CommercialCapability::Evaluator);
        }
        if !caps.poly_codec {
            missing.push(CommercialCapability::PolyCodec);
        }
        if !caps.poly_interpreter {
            missing.push(CommercialCapability::PolyInterpreter);
        }
        if !caps.production_threaded {
            missing.push(CommercialCapability::ProductionThreaded);
        }
        if !missing.is_empty() {
            return Err(CommercialCapabilityError {
                instruction_index,
                op_name: instr.op.kind().stable_name(),
                missing,
            });
        }
    }
    Ok(())
}

/// Return capabilities for this concrete operation (including width validity in
/// the codec allow-list). `evaluator` means an implementation exists, not that an
/// ill-formed instruction is guaranteed to execute successfully.
pub fn capabilities(op: RiscOp) -> RiscOpCapabilities {
    use RiscOpKind::*;
    let kind = op.kind();
    let commercial = crate::vm::poly::VirtualIsaSpec::is_encodable(op);
    let reads_flags = matches!(kind, Adc | Sbb | VirtualBranch | Setcc | ConditionalMove);
    let writes_flags = matches!(
        kind,
        Nor | AddWithCarry
            | ShiftRight
            | ArithmeticShiftRight
            | ShiftLeft
            | RotateLeft
            | SetFlag
            | SubWithBorrow
            | Add
            | Adc
            | Sbb
            | Inc
            | Dec
            | Multiply
            | MultiplyLow
            | BitScanForward
            | BitScanReverse
            | CountTrailingZeros
            | CountLeadingZeros
            | PopCount
            | CompareExchange
            | AtomicAdd
            | DoubleShiftLeft
            | BitTest
    );
    let may_fault = matches!(
        kind,
        VirtualPush
            | VirtualPop
            | MemoryRead
            | MemoryWrite
            | VirtualBranch
            | VirtualIndirectCall
            | VirtualIndirectJump
            | NativeCallBridge
            | VmCallBridge
            | Trap
            | VirtualRet
            | Divide
            | CompareExchange
            | LifetimeAcquire
            | LifetimeRelease
            | AtomicExchange
            | AtomicAdd
            | PackedMove
            | PackedAdd
            | PackedSub
            | PackedXor
            | PackedAnd
            | PackedOr
            | PackedAndNot
            | PackedCmpEq
            | PackedCmpGt
            | PackedUnpack
            | PackedShiftRightQ
            | PackedShuffle
            | PackedMovMaskBytes
            | PackedMovMaskPs
            | PackedInsertWord
            | ReadSegmentBase
    );
    RiscOpCapabilities {
        evaluator: true,
        poly_codec: commercial,
        poly_interpreter: commercial,
        production_threaded: commercial,
        reads_flags,
        writes_flags,
        may_fault,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::risc::BranchCondition;
    use std::collections::HashSet;

    #[test]
    fn stable_names_are_unique_and_registry_is_complete() {
        let names: HashSet<_> = RiscOpKind::ALL.iter().map(|k| k.stable_name()).collect();
        assert_eq!(names.len(), RiscOpKind::ALL.len());
        assert_eq!(
            RiscOpKind::ALL.len(),
            71,
            "update registry when RiscOp changes"
        );
    }

    #[test]
    fn normalization_discards_parameters() {
        assert_eq!(
            RiscOp::MemoryRead { width: 1 }.kind(),
            RiscOp::MemoryRead { width: 8 }.kind()
        );
        assert_eq!(
            RiscOp::VirtualBranch {
                cond: BranchCondition::Zero
            }
            .kind(),
            RiscOp::VirtualBranch {
                cond: BranchCondition::Always
            }
            .kind()
        );
    }

    #[test]
    fn stable_serialization_identifiers_do_not_depend_on_debug_format() {
        assert_eq!(
            RiscOp::MemoryWrite { width: 8 }.kind().stable_name(),
            "memory_write"
        );
        assert_eq!(
            RiscOp::VirtualIndirectCall.kind().stable_name(),
            "virtual_indirect_call"
        );
        assert_eq!(
            RiscOp::ReadSegmentBase { gs: true }.kind().stable_name(),
            "read_segment_base"
        );
    }

    #[test]
    fn commercial_capabilities_follow_actual_allow_list() {
        for op in [RiscOp::Nor, RiscOp::Halt, RiscOp::MemoryRead { width: 8 }] {
            let c = capabilities(op);
            assert_eq!(
                c.poly_codec,
                crate::vm::poly::VirtualIsaSpec::is_encodable(op)
            );
            assert_eq!(c.poly_interpreter, c.poly_codec);
            assert_eq!(c.production_threaded, c.poly_codec);
        }
        let nested = capabilities(RiscOp::VmCallBridge);
        assert!(!nested.poly_codec);
        assert!(nested.evaluator);
    }

    #[test]
    fn commercial_assertion_is_typed_and_names_missing_capabilities() {
        let err = assert_commercial_capabilities(&[
            MicroInstr::new(RiscOp::Halt),
            MicroInstr::new(RiscOp::VmCallBridge),
        ])
        .unwrap_err();
        assert_eq!(err.instruction_index, 1);
        assert_eq!(err.op_name, "vm_call_bridge");
        assert_eq!(
            err.missing,
            vec![
                CommercialCapability::PolyCodec,
                CommercialCapability::PolyInterpreter,
                CommercialCapability::ProductionThreaded,
            ]
        );
        let rendered = err.to_string();
        assert!(rendered.contains("vm_call_bridge"));
        assert!(rendered.contains("production_threaded"));
    }
}
