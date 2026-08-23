// ==============================================================================
// BTG - Polymorphic Bytecode Decoder Errors (Domit §29, §80)
// ==============================================================================
// Provides strongly typed, descriptive errors for malformed or truncated
// polymorphic bytecode streams, eliminating silent truncation failures.
// ==============================================================================

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    #[error("truncated opcode header at offset 0x{at:X}")]
    TruncatedOpcode { at: usize },

    #[error("truncated operand specifier at offset 0x{at:X}")]
    TruncatedOperand { at: usize },

    #[error("truncated immediate value at offset 0x{at:X}")]
    TruncatedImmediate { at: usize },

    #[error("truncated branch target at offset 0x{at:X}")]
    TruncatedBranchTarget { at: usize },

    #[error("invalid or unmapped opcode 0x{byte:02X} at offset 0x{at:X}")]
    InvalidOpcode { byte: u8, at: usize },

    #[error("invalid condition code 0x{byte:02X} at offset 0x{at:X}")]
    InvalidCondition { byte: u8, at: usize },

    #[error("decoded instruction limit exceeded ({limit}) at offset 0x{at:X}")]
    InstructionLimitExceeded { limit: usize, at: usize },
}

/// Fail-closed faults raised while executing decoded guest instructions.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum GuestFault {
    #[error("unknown opcode 0x{byte:02X} at guest VIP 0x{vip:X}")]
    UnknownOpcode { vip: usize, byte: u8 },

    #[error("unknown condition 0x{byte:02X} for {op} at guest VIP 0x{vip:X}")]
    UnknownCondition { vip: usize, op: String, byte: u8 },

    #[error("guest trap ({op}) at VIP 0x{vip:X}")]
    Trap { vip: usize, op: String },

    #[error("guest divide by zero ({op}) at VIP 0x{vip:X}")]
    DivideByZero { vip: usize, op: String },

    #[error("guest divide overflow ({op}) at VIP 0x{vip:X}")]
    DivideOverflow { vip: usize, op: String },

    #[error("unresolved guest route target {target:#x} ({op}) at VIP 0x{vip:X}")]
    RouteMiss { vip: usize, op: String, target: u64 },

    #[error("guest route target {target:#x} maps outside program at index {target_index} ({op}) at VIP 0x{vip:X}")]
    RouteOutsideProgram {
        vip: usize,
        op: String,
        target: u64,
        target_index: usize,
    },
}
