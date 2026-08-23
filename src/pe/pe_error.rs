// ==============================================================================
// BTG - PE Parser & Builder Error Types (Domit §70, §74)
// ==============================================================================
// Replaces unchecked panics and raw unwrap() calls in PE parsing/reconstruction
// with structured, strongly-typed errors.
// ==============================================================================

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    #[error("truncated section '{section}' at offset 0x{at:X}")]
    TruncatedSection { section: String, at: usize },

    #[error("invalid or missing PE directory: {dir}")]
    InvalidDirectory { dir: &'static str },

    #[error("malformed import entry: {name}")]
    MalformedImport { name: String },

    #[error("out of bounds access at offset 0x{offset:X} (expected {size} bytes)")]
    OutOfBounds { offset: usize, size: usize },

    #[error("invalid PE header: {reason}")]
    InvalidPeHeader { reason: String },
}
