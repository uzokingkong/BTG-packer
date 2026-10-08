//! BTG Codegen library surface.
//!
//! Exposes the pipeline modules so both the `btg_codegen` binary and the
//! integration tests can use them. See `main.rs` for the end-to-end flow.

pub mod coverage;
pub mod emit;
pub mod family;
pub mod rules;
pub mod template;
