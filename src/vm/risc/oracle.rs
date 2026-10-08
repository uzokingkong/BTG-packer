//! Silicon reference oracle (Priority 3) — test-only.
//!
//! Executes a single x86-64 instruction on the host CPU from a controlled
//! register/flag state and captures the resulting registers and RFLAGS. This is
//! the authoritative ground truth the differential validator compares the BTG
//! RISC evaluator against: flags and values come from the real silicon, not a
//! hand-written model, so a confidence tier can be *proven* rather than asserted.
//!
//! Gated to `#[cfg(all(test, windows, target_arch = "x86_64"))]`: it is unsafe
//! JIT execution and must never compile into the shipped protector.
//!
//! ## Increment 1 scope
//! The 14 non-stack GPRs and the status flags are the guest's; RSP and RBP are
//! host-reserved (not loaded as guest inputs, not captured), so memory/stack
//! operands are out of scope until a later increment adds a guest stack.

use std::arch::global_asm;

/// x86-64 GPR index order (matches iced-x86 Register numbering of the 16 GPRs,
/// and BTG `RiscEvalState.regs`).
#[allow(dead_code)]
pub mod reg {
    pub const RAX: usize = 0;
    pub const RCX: usize = 1;
    pub const RDX: usize = 2;
    pub const RBX: usize = 3;
    pub const RSP: usize = 4;
    pub const RBP: usize = 5;
    pub const RSI: usize = 6;
    pub const RDI: usize = 7;
}

/// Registers that are host-reserved in increment 1 (not guest-controlled).
pub const HOST_RESERVED: [usize; 2] = [reg::RSP, reg::RBP];

/// Context exchanged with the asm trampoline. `repr(C)`; offsets are baked into
/// the trampoline (regs at 0, flags at 128).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OracleCtx {
    pub regs: [u64; 16],
    pub flags: u64,
}

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

unsafe extern "system" {
    fn VirtualAlloc(
        addr: *mut core::ffi::c_void,
        size: usize,
        typ: u32,
        protect: u32,
    ) -> *mut core::ffi::c_void;
    fn VirtualFree(addr: *mut core::ffi::c_void, size: usize, free_type: u32) -> i32;
}

unsafe extern "C" {
    fn btg_oracle_run(ctx: *mut OracleCtx, code: *const u8);
}

// win64: rcx = ctx*, rdx = code*. RSP/RBP stay the host's; the other 14 GPRs and
// the status flags are the guest's. The code page is `[instruction][ret]`, so it
// is entered with `call`; flags are captured immediately on return before any
// flag-affecting instruction runs.
global_asm!(
    r#"
.globl btg_oracle_run
btg_oracle_run:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 72
    mov     [rbp-64], rcx
    mov     [rbp-72], rdx

    mov     rax, [rcx+128]
    push    rax
    popfq

    mov     rax, [rcx+0]
    mov     rdx, [rcx+16]
    mov     rbx, [rcx+24]
    mov     rsi, [rcx+48]
    mov     rdi, [rcx+56]
    mov     r8,  [rcx+64]
    mov     r9,  [rcx+72]
    mov     r10, [rcx+80]
    mov     r11, [rcx+88]
    mov     r12, [rcx+96]
    mov     r13, [rcx+104]
    mov     r14, [rcx+112]
    mov     r15, [rcx+120]
    mov     rcx, [rcx+8]

    call    qword ptr [rbp-72]

    pushfq
    push    rax
    mov     rax, [rbp-64]
    mov     [rax+8],   rcx
    mov     [rax+16],  rdx
    mov     [rax+24],  rbx
    mov     [rax+48],  rsi
    mov     [rax+56],  rdi
    mov     [rax+64],  r8
    mov     [rax+72],  r9
    mov     [rax+80],  r10
    mov     [rax+88],  r11
    mov     [rax+96],  r12
    mov     [rax+104], r13
    mov     [rax+112], r14
    mov     [rax+120], r15
    pop     rcx
    mov     [rax+0], rcx
    pop     rcx
    mov     [rax+128], rcx

    lea     rsp, [rbp-56]
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
"#
);

use super::flags::{VFLAG_DF, VFLAG_STATUS_MASK};

/// Execute a single instruction (`code_bytes`, no trailing `ret`) from `input`
/// and return the resulting context. Maps an RWX page, appends `ret`, runs.
pub fn run_instruction(code_bytes: &[u8], input: &OracleCtx) -> OracleCtx {
    let mut page_code = code_bytes.to_vec();
    page_code.push(0xC3); // ret

    unsafe {
        let page = VirtualAlloc(
            core::ptr::null_mut(),
            page_code.len().max(16),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        assert!(!page.is_null(), "VirtualAlloc RWX failed");
        core::ptr::copy_nonoverlapping(page_code.as_ptr(), page as *mut u8, page_code.len());

        let mut ctx = *input;
        ctx.flags &= VFLAG_STATUS_MASK | VFLAG_DF;
        btg_oracle_run(&mut ctx as *mut OracleCtx, page as *const u8);

        VirtualFree(page, 0, MEM_RELEASE);
        ctx
    }
}

// ── Differential validator (Priority 3, increment 2) ─────────────────────────

/// Outcome of comparing the real BTG lifter+evaluator against the silicon
/// oracle for one instruction.
#[derive(Debug, Clone, Default)]
pub struct DiffResult {
    /// All guest GPRs (excluding host-reserved RSP/RBP) matched.
    pub value_match: bool,
    /// Status flags (CF/PF/AF/ZF/SF/OF) matched.
    pub flags_match: bool,
    /// Human-readable per-field mismatches.
    pub mismatches: Vec<String>,
}

impl DiffResult {
    /// Semantically exact: value AND flags both match.
    pub fn exact(&self) -> bool {
        self.value_match && self.flags_match
    }
}

/// Lift `code_bytes` with the real `RiscLifter`, evaluate it, run the silicon
/// oracle from the same GPR state (both sides start with flags = 0, matching the
/// evaluator's initial state), and compare GPRs (excluding host-reserved
/// RSP/RBP) and status flags. This is the measurement that turns a confidence
/// *claim* into a *proof*.
pub fn differential(code_bytes: &[u8], init: [u64; 16]) -> DiffResult {
    use super::lifter::RiscLifter;
    use super::RiscProgram;
    use iced_x86::{Decoder, DecoderOptions};
    use std::collections::HashMap;

    // BTG side: lift every instruction in the buffer, then evaluate.
    let ip = 0x1_0000u64;
    let mut decoder = Decoder::with_ip(64, code_bytes, ip, DecoderOptions::NONE);
    let mut lifter = RiscLifter::new();
    let mut ip_map = HashMap::new();
    while decoder.can_decode() {
        let inst = decoder.decode();
        ip_map.insert(inst.ip(), lifter.desynth.instrs.len());
        lifter.lift_instruction(&inst).expect("lift");
    }
    let prog = RiscProgram::with_ip_map(lifter.desynth.instrs, ip_map);
    let btg = prog.eval_state(&init);

    // Silicon side.
    let inctx = OracleCtx { regs: init, flags: 0 };
    let sil = run_instruction(code_bytes, &inctx);

    let mut res = DiffResult { value_match: true, flags_match: true, mismatches: Vec::new() };
    for i in 0..16 {
        if HOST_RESERVED.contains(&i) {
            continue;
        }
        if btg.regs[i] != sil.regs[i] {
            res.value_match = false;
            res.mismatches.push(format!(
                "reg[{i}]: btg=0x{:X} silicon=0x{:X}",
                btg.regs[i], sil.regs[i]
            ));
        }
    }
    let bm = btg.flags & VFLAG_STATUS_MASK;
    let sm = sil.flags & VFLAG_STATUS_MASK;
    if bm != sm {
        res.flags_match = false;
        res.mismatches.push(format!(
            "flags: btg=0x{bm:X} silicon=0x{sm:X} (differing bits 0x{:X})",
            bm ^ sm
        ));
    }
    res
}

#[cfg(test)]
mod tests {
    use super::reg::*;
    use super::*;
    use crate::vm::risc::flags::{VFLAG_CF, VFLAG_SF, VFLAG_ZF};

    fn init_with(regs: &[(usize, u64)]) -> [u64; 16] {
        let mut r = [0u64; 16];
        for &(i, v) in regs {
            r[i] = v;
        }
        r
    }

    #[test]
    fn differential_add_r64_is_flag_exact() {
        // ADD rax, rbx: the BTG `add` lowering should match silicon on value AND
        // flags across ordinary, carry-out, and zero-result inputs. This is the
        // first PROVEN AUTO_FLAG_EXACT result.
        for (a, b) in [(5u64, 7u64), (u64::MAX, 1), (0x8000_0000_0000_0000, 0x8000_0000_0000_0000)] {
            let d = differential(&[0x48, 0x01, 0xD8], init_with(&[(RAX, a), (RBX, b)]));
            assert!(d.exact(), "ADD {a:#x}+{b:#x} not exact: {:?}", d.mismatches);
        }
    }

    #[test]
    fn differential_sub_r64_is_flag_exact() {
        for (a, b) in [(10u64, 3u64), (3, 5), (0, 0)] {
            let d = differential(&[0x48, 0x29, 0xD8], init_with(&[(RAX, a), (RBX, b)]));
            assert!(d.exact(), "SUB {a:#x}-{b:#x} not exact: {:?}", d.mismatches);
        }
    }

    #[test]
    fn differential_harness_runs_over_alu_set() {
        // Exercise the comparison over several ALU ops; every one must at least
        // be value-correct (the weakest tier). Flag exactness is reported, not
        // asserted here, so the harness surfaces any flag gaps for triage.
        let cases: &[(&str, &[u8])] = &[
            ("add rax,rbx", &[0x48, 0x01, 0xD8]),
            ("sub rax,rbx", &[0x48, 0x29, 0xD8]),
            ("xor rax,rbx", &[0x48, 0x31, 0xD8]),
            ("and rax,rbx", &[0x48, 0x21, 0xD8]),
            ("or rax,rbx", &[0x48, 0x09, 0xD8]),
            ("inc rax", &[0x48, 0xFF, 0xC0]),
        ];
        for (name, bytes) in cases {
            let d = differential(bytes, init_with(&[(RAX, 0x1234), (RBX, 0x00FF)]));
            assert!(d.value_match, "{name}: value mismatch {:?}", d.mismatches);
            if !d.flags_match {
                eprintln!("[oracle] {name}: value-exact but FLAG gap -> {:?}", d.mismatches);
            }
        }
    }

    fn ctx_with(regs: &[(usize, u64)], flags: u64) -> OracleCtx {
        let mut c = OracleCtx::default();
        for &(i, v) in regs {
            c.regs[i] = v;
        }
        c.flags = flags;
        c
    }

    #[test]
    fn oracle_add_value_and_flags() {
        let out = run_instruction(&[0x48, 0x01, 0xD8], &ctx_with(&[(RAX, 5), (RBX, 7)], 0));
        assert_eq!(out.regs[RAX], 12);
        assert_eq!(out.flags & VFLAG_ZF, 0);
        assert_eq!(out.flags & VFLAG_CF, 0);
    }

    #[test]
    fn oracle_add_carry_and_zero() {
        let out =
            run_instruction(&[0x48, 0x01, 0xD8], &ctx_with(&[(RAX, u64::MAX), (RBX, 1)], 0));
        assert_eq!(out.regs[RAX], 0);
        assert_ne!(out.flags & VFLAG_CF, 0);
        assert_ne!(out.flags & VFLAG_ZF, 0);
    }

    #[test]
    fn oracle_adc_consumes_carry() {
        let out = run_instruction(&[0x48, 0x11, 0xD8], &ctx_with(&[(RAX, 0), (RBX, 0)], VFLAG_CF));
        assert_eq!(out.regs[RAX], 1);
    }

    #[test]
    fn oracle_sub_sign_and_borrow() {
        let out = run_instruction(&[0x48, 0x29, 0xD8], &ctx_with(&[(RAX, 3), (RBX, 5)], 0));
        assert_eq!(out.regs[RAX], (-2i64) as u64);
        assert_ne!(out.flags & VFLAG_SF, 0);
        assert_ne!(out.flags & VFLAG_CF, 0);
    }

    #[test]
    fn oracle_preserves_unrelated_regs() {
        let out = run_instruction(
            &[0x48, 0x01, 0xD8],
            &ctx_with(&[(RAX, 1), (RBX, 2), (RSI, 0xdead), (RDI, 0xbeef), (12, 0x1234)], 0),
        );
        assert_eq!(out.regs[RSI], 0xdead);
        assert_eq!(out.regs[RDI], 0xbeef);
        assert_eq!(out.regs[12], 0x1234);
    }
}
