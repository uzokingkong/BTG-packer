// ==============================================================================
// BTG v3 - VM Bytecode Format (MVP)
// ==============================================================================
//
// The composite-VM MVP defines a tiny register-based bytecode that is the
// *virtualized* form of a routine. The boot stub (or the VM test harness)
// executes it through generated x86-64 handlers (see handlers.rs).
//
// Encoding: opcode u8, then operands (little-endian). All register operands
// are u8 virtual-register indices (0..=15, mapping RAX..R15 by number()).
//
// Memory operands address one of the VM's pointer slots: the state buffer
// holds native pointers to the arrays the virtualized routine reads/writes.
//   memslot 0 = S-box   (ptr stored at STATE_PTR_SBOX)
//   memslot 1 = seed    (ptr stored at STATE_PTR_SEED)
//   memslot 2 = buffer  (ptr stored at STATE_PTR_BUF)
//   memslot 3 = runs    (ptr stored at STATE_PTR_RUNS)
//
// All arithmetic is 32-bit (matching the x86 r32 forms used by the
// virtualized boot-stub code); results are zero-extended into 64-bit vregs.
// Only the flags actually consumed by the virtualized code are modelled:
// CF (carry/unsigned-below from the last CMP), stored at STATE_FLAGS.
// ==============================================================================
//
// Module layout (v13.5 refactor): this file was split from a single ~1200-line
// monolith into submodules so each concern is small and independently testable:
//   registry.rs  - opcodes! macro, opcode constants, flag/condition/memslot consts
//   builder.rs   - BytecodeBuilder (emitter + branch fixup)
//   disasm.rs    - disassemble() (bytecode -> human-readable text)
//   tests.rs     - unit tests
// `mod.rs` is a re-export layer; external callers use `bytecode::*` unchanged.
// ==============================================================================

pub mod registry;
pub mod builder;
pub mod disasm;
#[cfg(test)]
mod tests;

pub use builder::BytecodeBuilder;
pub use disasm::disassemble;
pub use registry::*;
