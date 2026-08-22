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
