// ==============================================================================
// BTG v21 - VM Interpreter: VM state layout + low-level state accessors
// ==============================================================================
//
// The interpreter models the runtime memory as two regions:
//   * `state` — the VM state buffer (layout below). Pointer slots hold
//     *offsets into `mem`* (the addressable arena). The real generated VM
//     instead holds absolute VAs in the slots; semantics are identical.
//   * `mem`   — the memory arena the virtualized routine reads/writes
//     (e.g. the S-box and masked seed arrays).
//
// This file owns the state-layout constants and every byte-buffer accessor.
// All handlers (and the mod.rs dispatch) read/write the VM state exclusively
// through these helpers so the layout stays defined in one place.
//
// State layout (matches handlers.rs / the packer integration) — v64 동기화:
//   [0x000] vregs[NREG=20] x u64   (16 GPR RAX..R15 + lifter SCRATCH/SCRATCH2/TMP/TMP4)
//   [0x0A0] (예약 패딩)
//   [0x100] flags u64             (x86 RFLAGS: CF/PF/AF/ZF/SF/OF)
//   [0x108] sp u64                (M3 legacy — vreg[4]=RSP 가 단일 스택 포인터)
//   [0x110] ptr_sbox u64          (offset into mem / native는 절대 VA)
//   [0x118] ptr_seed u64
//   [0x120] ptr_buf u64
//   [0x128] ptr_runs u64
//   [0x130] ptr_stack u64         (M3 legacy)
//   [0x138] rip u64               (v24: 현재 lift 명령의 기준 VA)
//   [0x140] xmm[16] x 16B         (0x100 바이트)
//   [0x240] seg_gs u64            (v43: GS base = TEB)
//   [0x248] call_sp u64           (VM 바이트코드 return-IP 스택 오프셋)
//   [0x250] ptr_call_stack u64    (VM 바이트코드 return-IP 스택 base)
//   [0x258] STATE_SIZE (end)      (call stack buffer는 state 버퍼 밖)
// ==============================================================================

use crate::vm::bytecode::*;

pub const STATE_VREGS: usize = 0x000;
/// Number of valid virtual registers (indices 0..NREG).
/// 0..=15 = the 16 program GPRs (RAX..R15), 16/17 = lifter SCRATCH/SCRATCH2,
/// 18/19 = lifter TMP/TMP4. Anything >= NREG would overrun into the control slots
/// (STATE_FLAGS at offset 0x100) or past the state buffer.
pub const NREG: usize = 20;
pub const STATE_FLAGS: usize = 0x100;
pub const STATE_SP: usize = 0x108;      // M3: stack pointer (offset from stack base)
pub const STATE_PTR_SBOX: usize = 0x110;
pub const STATE_PTR_SEED: usize = 0x118;
pub const STATE_PTR_BUF: usize = 0x120;
pub const STATE_PTR_RUNS: usize = 0x128;
pub const STATE_PTR_STACK: usize = 0x130; // M3: stack base pointer
pub const STATE_RIP: usize = 0x138;       // v24: base VA of current lifted instruction (RIP-rel)
pub const STATE_XMM: usize = 0x140;       // v29: XMM register file (16 regs x 16 bytes = 0x100)
pub const STATE_SEG_GS: usize = 0x240;    // v43: GS segment base (= TEB). M6 Phase-2 PEB/TEB 접근.
// ── Two-stack model (v13.4e): the VM keeps the *architectural* program stack on
//    vreg[4] (RSP) and a SEPARATE VM bytecode return-IP stack here. CALL/RET no
//    longer conflate the bytecode IP with the program's observed return address:
//    CALL stores the program's original return VA on [v4] (RSP) and the bytecode
//    return IP on this dedicated stack; RET pops the bytecode IP for control flow
//    and advances v4 past the return VA. STATE_SP/STATE_PTR_STACK (0x108/0x130)
//    are legacy M3 slots no longer used by call/ret/push/pop.
pub const STATE_CALL_SP: usize = 0x248;          // VM bytecode return-IP stack offset (from base)
pub const STATE_PTR_CALL_STACK: usize = 0x250;   // VM bytecode return-IP stack base
// Dedicated bytecode return-IP stack buffer lives OUTSIDE the state buffer (the
// boot stub reserves CALL_STACK_SIZE right after it and points STATE_PTR_CALL_STACK
// at STATE_CALL_STACK_BUF). Kept out of STATE_SIZE so the small KSA/PRGA VMs (which
// never call) don't balloon their state buffer.
pub const CALL_STACK_SIZE: usize = 0x2000;       // 8 KiB = 1024 nested calls
pub const STATE_SIZE: usize = 0x258;
/// Offset from the VM state base where the dedicated return-IP stack buffer begins.
pub const STATE_CALL_STACK_BUF: usize = STATE_SIZE;

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    #[error("Unknown opcode: 0x{0:02X}")]
    UnknownOpcode(u8),
    #[error("Instruction pointer out of bounds: ip = {0}")]
    OobIp(usize),
    #[error("Memory access out of bounds")]
    OobMem,
    #[error("Division by zero")]
    DivByZero,
    #[error("Virtual register index out of bounds: r = {0}")]
    OobReg(u8),
    #[error("Bytecode return-IP stack overflow: call depth exceeded {0}")]
    CallStackOverflow(i64),
    #[error("Bytecode return-IP stack underflow: RET without a matching CALL")]
    CallStackUnderflow,
    #[error("Bytecode build failed: unresolved branch label {0}")]
    UnresolvedLabel(u32),
    #[error("Bytecode build failed: branch rel range overflow for label {0}")]
    BranchRelOverflow(u32),
}

/// Read a 64-bit virtual register slot (byte-copy — alignment-agnostic, bounds-checked).
///
/// v64: 이전 구현은 `&mut [u8]` 의 원시 포인터를 `*mut u64` 로 캐스팅해
/// `&mut u64` 를 반환했다. `u8` 슬라이스는 8바이트 정렬을 보장하지 않으므로
/// 이는 UB 였고, 경계 검증도 없었다. 지금은 `from_le_bytes`/`to_le_bytes` 바이트
/// 복사로 정렬 요구 없이 안전하게 읽고 쓴다.
#[inline]
pub(crate) fn vreg64(state: &[u8], r: usize) -> Result<u64, VmError> {
    if r >= NREG {
        return Err(VmError::OobReg(r as u8));
    }
    let off = STATE_VREGS + r * 8;
    let end = off.checked_add(8).ok_or(VmError::OobReg(r as u8))?;
    if end > state.len() {
        return Err(VmError::OobReg(r as u8));
    }
    Ok(u64::from_le_bytes(state[off..end].try_into().unwrap()))
}

/// Write a 64-bit virtual register slot (byte-copy, alignment-agnostic, bounds-checked).
#[inline]
pub(crate) fn set_vreg64(state: &mut [u8], r: usize, v: u64) -> Result<(), VmError> {
    if r >= NREG {
        return Err(VmError::OobReg(r as u8));
    }
    let off = STATE_VREGS + r * 8;
    let end = off.checked_add(8).ok_or(VmError::OobReg(r as u8))?;
    if end > state.len() {
        return Err(VmError::OobReg(r as u8));
    }
    state[off..end].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// Read the low 32 bits of a virtual register.
#[inline]
pub(crate) fn vreg32(state: &[u8], r: usize) -> Result<u32, VmError> {
    if r >= NREG {
        return Err(VmError::OobReg(r as u8));
    }
    let off = STATE_VREGS + r * 8;
    let end = off.checked_add(4).ok_or(VmError::OobReg(r as u8))?;
    if end > state.len() {
        return Err(VmError::OobReg(r as u8));
    }
    Ok(u32::from_le_bytes(state[off..end].try_into().unwrap()))
}

/// Read the current flags word (low 64-bit slot at STATE_FLAGS).
#[inline]
pub(crate) fn flags_of(state: &[u8]) -> u64 {
    u64::from_le_bytes(state[STATE_FLAGS..STATE_FLAGS + 8].try_into().unwrap())
}

/// Write the flags word (masked to the modelled flag bits, DF preserved).
///
/// Arithmetic/logic ops recompute only the six status bits (CF/PF/AF/ZF/SF/OF);
/// DF (bit 10) is a *control* flag that x86 arithmetic never touches, so it is
/// carried through unchanged. Only OP_CLD/OP_STD ([`set_df`]) change it.
#[inline]
pub(crate) fn set_flags(state: &mut [u8], v: u64) {
    let df = flags_of(state) & F_DF;
    let v = (v & FLAG_MASK) | df;
    state[STATE_FLAGS..STATE_FLAGS + 8].copy_from_slice(&v.to_le_bytes());
}

/// Set or clear the DF bit (CLD/STD). The six status flags are untouched.
#[inline]
pub(crate) fn set_df(state: &mut [u8], on: bool) {
    let cur = flags_of(state);
    let v = if on { cur | F_DF } else { cur & !F_DF };
    state[STATE_FLAGS..STATE_FLAGS + 8].copy_from_slice(&v.to_le_bytes());
}

/// Read a pointer slot (offset into `mem` for the interpreter).
pub(crate) fn ptr_slot(state: &[u8], slot: usize) -> Result<usize, VmError> {
    let off = match slot as u8 {
        MEM_SBOX => STATE_PTR_SBOX,
        MEM_SEED => STATE_PTR_SEED,
        MEM_BUF => STATE_PTR_BUF,
        MEM_RUNS => STATE_PTR_RUNS,
        MEM_STACK => STATE_PTR_STACK,
        _ => return Err(VmError::OobMem),
    };
    Ok(u64::from_le_bytes(state[off..off + 8].try_into().unwrap()) as usize)
}

/// Read the VM stack pointer (vreg[4] = the real RSP). Single-stack model:
/// call/ret/push/pop and `[rsp+disp]` addressing all share this one pointer,
/// matching real x86. See the fix note in handlers.rs (vreg4-as-single-stack).
#[inline]
pub(crate) fn sp_of(state: &[u8]) -> u64 {
    u64::from_le_bytes(state[STATE_VREGS + 4 * 8..STATE_VREGS + 4 * 8 + 8].try_into().unwrap())
}

/// Write the VM stack pointer (vreg[4]).
#[inline]
pub(crate) fn set_sp(state: &mut [u8], sp: u64) {
    state[STATE_VREGS + 4 * 8..STATE_VREGS + 4 * 8 + 8].copy_from_slice(&sp.to_le_bytes());
}

/// Read the VM bytecode return-IP stack offset (STATE_CALL_SP). This is an offset
/// from STATE_PTR_CALL_STACK base (a mem-offset in the interpreter, an absolute VA
/// in the native handlers), growing downward as the return-IP stack fills.
#[inline]
pub(crate) fn call_sp_of(state: &[u8]) -> u64 {
    u64::from_le_bytes(state[STATE_CALL_SP..STATE_CALL_SP + 8].try_into().unwrap())
}

/// Write the VM bytecode return-IP stack offset.
#[inline]
pub(crate) fn set_call_sp(state: &mut [u8], csp: u64) {
    state[STATE_CALL_SP..STATE_CALL_SP + 8].copy_from_slice(&csp.to_le_bytes());
}

/// Absolute (mem-space) address of the VM bytecode return-IP stack slot at the
/// given offset: STATE_PTR_CALL_STACK (base) + csp.
#[inline]
pub(crate) fn call_stack_addr(state: &[u8], csp: u64) -> usize {
    let base = u64::from_le_bytes(state[STATE_PTR_CALL_STACK..STATE_PTR_CALL_STACK + 8].try_into().unwrap());
    base.wrapping_add(csp) as usize
}

/// Read `n` bytes from the arena at `addr` (n = 1..=8).
pub(crate) fn mem_get(mem: &[u8], addr: usize, n: usize) -> Option<[u8; 8]> {
    let mut out = [0u8; 8];
    // `addr + n` can wrap for a crafted address; use checked_add so malformed
    // bytecode is rejected instead of reading a wrong (wrapped) window.
    let end = addr.checked_add(n)?;
    let s = mem.get(addr..end)?;
    out[..n].copy_from_slice(s);
    Some(out)
}

/// Write `bytes` (LE, 1..=8) to the arena at `addr`.
pub(crate) fn mem_put(mem: &mut [u8], addr: usize, bytes: &[u8]) -> Result<(), VmError> {
    let end = addr.checked_add(bytes.len()).ok_or(VmError::OobMem)?;
    let dst = mem.get_mut(addr..end).ok_or(VmError::OobMem)?;
    dst.copy_from_slice(bytes);
    Ok(())
}
