// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Dispatcher Shellcode Generator
// ==============================================================================
//
// mod.rs = orchestration + re-export layer. The concrete builders / validators /
// tests live in the submodules below. Public API (build_dispatcher,
// build_dispatcher_reencrypt, validate_dispatcher, RING_* constants) is
// re-exported here so existing `dispatcher::...` callers keep resolving.

pub mod antidebug;

mod build;
mod reencrypt;
mod validate;

pub use build::{
    RING_ENTRIES, RING_REGION, RING_INDEX_OFF, RING_META_OFF, build_dispatcher,
};
pub use reencrypt::build_dispatcher_reencrypt;
pub use validate::validate_dispatcher;

#[cfg(test)]
mod tests;
