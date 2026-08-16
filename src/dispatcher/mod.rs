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
mod m7;
mod m7_c1;
mod reencrypt;
mod reencrypt_c1;
mod validate;

pub use build::{
    RING_ENTRIES, RING_REGION, RING_INDEX_OFF, RING_META_OFF, build_dispatcher,
};
pub use m7::build_dispatcher_m7;
pub use m7_c1::build_dispatcher_m7_c1;
pub use reencrypt::build_dispatcher_reencrypt;
pub use reencrypt_c1::build_dispatcher_reencrypt_c1;
pub use validate::validate_dispatcher;

/// Marker for an 8-byte stack push that needs no register restore (pushfq,
/// volatile-GPR push, or immediate push). Modelled as `UWOP_ALLOC_SMALL(8)`.
pub const UNWIND_ALLOC8: u8 = 0xFF;

/// One stack-modifying op in a dispatcher prologue, in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindCodeSpec {
    /// Byte offset of the op relative to the start of the dispatcher code.
    pub offset: u8,
    /// Win64 UWOP_PUSH_NONVOL register index (0-15) for nonvolatile GPR
    /// pushes, or [`UNWIND_ALLOC8`] for an 8-byte stack push that only needs
    /// RSP accounting.
    pub reg: u8,
}

/// Decode the leading prologue of a generated dispatcher (`pushfq` /
/// `push r64`, tolerating `int3`/`nop` from trace mode) and return the
/// unwind-code specs in prologue order plus the total prologue length in
/// bytes. Scanning stops at the first instruction that does not touch the
/// stack, so the emitted `.pdata` UNWIND_INFO always matches the code the
/// loader actually runs.
pub fn dispatcher_unwind_codes(code: &[u8]) -> (Vec<UnwindCodeSpec>, u8) {
    use iced_x86::{Code, Decoder, DecoderOptions, Register};
    let mut codes = Vec::new();
    let mut off = 0usize;
    let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
    loop {
        if off >= code.len() {
            break;
        }
        let inst = decoder.decode();
        if inst.is_invalid() {
            break;
        }
        let len = inst.len() as usize;
        if len == 0 || off + len > code.len() {
            break;
        }
        match inst.code() {
            Code::Pushfq => {
                codes.push(UnwindCodeSpec { offset: off as u8, reg: UNWIND_ALLOC8 });
            }
            Code::Push_r64 => {
                let reg = inst.op0_register();
                let nonvol = matches!(
                    reg,
                    Register::RBX
                        | Register::RBP
                        | Register::RSI
                        | Register::RDI
                        | Register::R12
                        | Register::R13
                        | Register::R14
                        | Register::R15
                );
                let spec = if nonvol {
                    reg.number() as u8
                } else {
                    UNWIND_ALLOC8
                };
                codes.push(UnwindCodeSpec { offset: off as u8, reg: spec });
            }
            // Trace mode prepends `int3`; tolerate harmless no-ops.
            Code::Int3 | Code::Nopd | Code::Nopw | Code::Nopq => {}
            _ => break,
        }
        off += len;
    }
    (codes, off as u8)
}

#[cfg(test)]
mod tests;
