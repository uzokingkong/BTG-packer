// ==============================================================================
// VM self-test submodule: util.rs
// ==============================================================================
//
// Shared helpers for the Phase 2.1 coverage self-tests: run a bytecode program
// through BOTH the reference interpreter and the native VM (executable Arena),
// so a new opcode group is verified in interp == native lock-step. Modeled on
// the [31] atomic XCHG/XADD test's native-execution setup.

use crate::vm::arena::Arena;
use crate::vm::encode::encode_trampoline;
use crate::vm::{build_vm_module, handlers, interp};
use anyhow::Result;

/// Execute `prog` through the native VM (EntryMode::Ksa). `data` is copied to
/// the native data arena at `data_off` (absolute VA = vdata + data_off, where
/// vdata = arena.base + 0x9000); pass empty `data` for programs that need none.
/// `seed` mutates the native state buffer; it receives the buffer and the arena
/// base so it can embed absolute addresses into address vregs / pointer slots.
/// Returns the final state buffer and the arena base (so callers can turn
/// absolute vregs back into base-relative offsets).
pub fn run_native(
    prog: &[u8],
    data: &[u8],
    data_off: usize,
    seed: impl Fn(&mut [u8], u64),
) -> Result<(Vec<u8>, u64)> {
    let mut arena = Arena::new(0x40000)?;
    let (vc, vt, vb, vs, vtr, vdata) = (
        arena.base + 0x1000,
        // NOTE: the code region (0x1000..vt) must comfortably fit the growing
        // handler set; it is ~14.3KB today and grows with every opcode.
        arena.base + 0x5800,
        arena.base + 0x6000,
        arena.base + 0x6800,
        arena.base + 0x8000,
        arena.base + 0x9000,
    );
    let module = build_vm_module(
        vc as u64,
        vt as u64,
        vb as u64,
        prog.to_vec(),
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vs as u64, vdata as u64, vdata as u64, vc as u64, vtr as u64)?;
    let vbase = arena.base as u64;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x5800..0x5800 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
        b[0x6000..0x6000 + prog.len()].copy_from_slice(prog);
        b[0x6800..0x6800 + interp::STATE_SIZE].fill(0);
        if !data.is_empty() {
            b[0x9000 + data_off..0x9000 + data_off + data.len()].copy_from_slice(data);
        }
        seed(&mut b[0x6800..0x6800 + interp::STATE_SIZE], vbase);
    }
    arena.call(0x8000);
    let b = arena.bytes();
    Ok((b[0x6800..0x6800 + interp::STATE_SIZE].to_vec(), vbase))
}

/// Like `run_native`, but also returns the data region (vdata..vdata+cap) after
/// execution, so tests can assert on memory the program wrote (e.g. LOCK RMW).
pub fn run_native_with_data(
    prog: &[u8],
    data: &[u8],
    data_off: usize,
    data_cap: usize,
    seed: impl Fn(&mut [u8], u64),
) -> Result<(Vec<u8>, u64, Vec<u8>)> {
    let mut arena = Arena::new(0x40000)?;
    let (vc, vt, vb, vs, vtr, vdata) = (
        arena.base + 0x1000,
        arena.base + 0x5800,
        arena.base + 0x6000,
        arena.base + 0x6800,
        arena.base + 0x8000,
        arena.base + 0x9000,
    );
    let module = build_vm_module(
        vc as u64,
        vt as u64,
        vb as u64,
        prog.to_vec(),
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vs as u64, vdata as u64, vdata as u64, vc as u64, vtr as u64)?;
    let vbase = arena.base as u64;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x5800..0x5800 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
        b[0x6000..0x6000 + prog.len()].copy_from_slice(prog);
        b[0x6800..0x6800 + interp::STATE_SIZE].fill(0);
        if !data.is_empty() {
            b[0x9000 + data_off..0x9000 + data_off + data.len()].copy_from_slice(data);
        }
        seed(&mut b[0x6800..0x6800 + interp::STATE_SIZE], vbase);
    }
    arena.call(0x8000);
    let b = arena.bytes();
    Ok((
        b[0x6800..0x6800 + interp::STATE_SIZE].to_vec(),
        vbase,
        b[0x9000..0x9000 + data_cap].to_vec(),
    ))
}

/// Read a 64-bit vreg from an interpreter/native state buffer.
pub fn vreg(state: &[u8], r: usize) -> u64 {
    u64::from_le_bytes(
        state[interp::STATE_VREGS + r * 8..interp::STATE_VREGS + r * 8 + 8]
            .try_into()
            .unwrap(),
    )
}

/// Write a 64-bit vreg into a state buffer.
pub fn set_vreg(state: &mut [u8], r: usize, v: u64) {
    state[interp::STATE_VREGS + r * 8..interp::STATE_VREGS + r * 8 + 8]
        .copy_from_slice(&v.to_le_bytes());
}

/// Read the 16-byte XMM register `r` from a state buffer.
pub fn xmm(state: &[u8], r: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    let base = interp::STATE_XMM + r * 16;
    out.copy_from_slice(&state[base..base + 16]);
    out
}

/// Write the 16-byte XMM register `r` into a state buffer.
pub fn set_xmm(state: &mut [u8], r: usize, v: &[u8; 16]) {
    let base = interp::STATE_XMM + r * 16;
    state[base..base + 16].copy_from_slice(v);
}

/// Fresh zeroed interpreter state + memory arena.
pub fn interp_state() -> (Vec<u8>, Vec<u8>) {
    (vec![0u8; interp::STATE_SIZE], vec![0u8; 0x10000])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::bytecode::BytecodeBuilder;

    #[test]
    fn util_native_runner_executes_mov_halt() {
        let mut b = BytecodeBuilder::new();
        b.mov_r_imm64(3, 0x1122_3344_5566_7788u64);
        b.halt();
        let prog = b.finish();
        let (st, _base) = run_native(&prog, &[], 0, |_s, _| {}).unwrap();
        assert_eq!(vreg(&st, 3), 0x1122_3344_5566_7788u64);
    }
}
