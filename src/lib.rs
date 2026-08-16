// ==============================================================================
// BTG Packer - library API (review P2-9).
//
// Previously the whole packer lived behind main() with no lib.rs, so it could
// not be used as a programmatic API. This file turns every module into a
// library surface: `btg-packer` is now a lib + a thin bin (main.rs just parses
// CLI args and calls into here).
// ==============================================================================

pub mod analysis;
pub mod assembler;
pub mod cli;
pub mod core;
pub mod crypto;
pub mod debug;
pub mod dispatcher;
pub mod error;
pub mod graph;
pub mod mba;
pub mod obfuscation;
pub mod pe;
pub mod pipeline;
pub mod qa;
pub mod sdk;
pub mod util;
pub mod vm;

pub use error::{BtgError, Result};
pub use pe::TargetPeInfo;
pub use pipeline::PipelineContext;

/// Programmatic pack entrypoint: run the full protection pipeline over an input
/// PE and return the protected PE bytes (in-memory — no output file is written).
/// See `pipeline` / `main` for the CLI equivalent.
pub fn pack(input_pe: &[u8]) -> Result<Vec<u8>> {
    crate::pipeline::pack::run_full(input_pe, 3, 100, None).map_err(BtgError::Anyhow)
}

