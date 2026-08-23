// ==============================================================================
// Boot-stub machine-code generation (RC4 boot stub for the composite VM layer)
// ==============================================================================
// Split into:
//   ctx.rs   - BootStubCtx + Label + base_bind_byte (shared data contract)
//   emit.rs  - RC4 emitter functions (KSA init / code / run / rest decrypt,
//              self-wipe, dispatcher entry, base-bind loop, trashformer junk)
//   build.rs - build_anti_debug_raw_block + build_boot_block orchestrators
// ==============================================================================

mod build;
mod ctx;
mod emit;

pub(crate) use build::{build_anti_debug_raw_block, build_boot_block};
pub(crate) use ctx::{base_bind_byte, BootStubCtx, Label};
