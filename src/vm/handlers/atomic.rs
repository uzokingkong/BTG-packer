// ==============================================================================
// BTG v3 - VM Handler Codegen: atomic family
// ==============================================================================
// Atomic memory handlers for the lifted Rust `Once`/`AtomicUsize` paths:
// cmpxchg (v46), xchg and xadd (v48) at absolute addresses. Shared helpers
// (`hdr`, `m`, `vreg`, `cap_flags`, `state_flags_mem`, ...) and the `Cl` label
// enum live in `super` (mod.rs).
// ==============================================================================

use super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

// ── v46: atomic memory compare-exchange (Once/futex CAS) ────────────────
// OP_CMPXCHG_MEM32_A / OP_CMPXCHG_MEM64_A: [addr_vreg, src_vreg].
//   RAX(v0)=expected; does a real `lock cmpxchg [addr], src` at the absolute
//   address. On success [addr]=src and ZF=1; on failure RAX=[addr] and ZF=0.
//   Preserves the atomicity/ordering the lifted Rust `Once` (futex CAS)
//   requires; previously emulated non-atomically so COMPLETE was not durable
//   and a 2nd call_once re-ran the closure -> panic.
pub(super) fn emit_cmpxchg(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, cmp_code, src_r, acc_r, load_code, store_code) in [
        // FIX(v47): 32-bit variant must commit the result to the 64-bit v0 slot
        // with a 64-bit store (`Mov_rm64_r64 [R8], RAX`) so that on a FAILED cmpxchg
        // the upper 32 bits of v0 are zero (hardware zero-extends EAX on the rm32
        // write) instead of leaving stale high bits from the previous expected value.
        // A 32-bit store (`Mov_rm32_r32 [R8], EAX`) does NOT clear the slot's upper
        // 32 bits because the destination is memory, not a register, so x64's
        // implicit upper-half zeroing does not apply. This violated the codebase
        // convention that 32-bit results are zero-extended when committed (cf. every
        // OP_*_R_R / OP_MUL_R_R32 handler, which store RAX into the 64-bit vreg).
        (OP_CMPXCHG_MEM32_A, Code::Cmpxchg_rm32_r32, Register::ECX, Register::RAX, Code::Mov_r32_rm32, Code::Mov_rm64_r64),
        (OP_CMPXCHG_MEM64_A, Code::Cmpxchg_rm64_r64, Register::RCX, Register::RAX, Code::Mov_r64_rm64, Code::Mov_rm64_r64),
        // v49: 8/16-bit variants. Hardware compares only AL/AX; on a failed cmpxchg
        // the CPU writes the byte/word into AL/AX and leaves the rest of RAX
        // untouched, so committing the full RAX to the v0 slot matches x86 exactly.
        // src is loaded as the low byte/word of the src vreg (CL/CX).
        (OP_CMPXCHG_MEM8_A, Code::Cmpxchg_rm8_r8, Register::CL, Register::RAX, Code::Mov_r8_rm8, Code::Mov_rm64_r64),
        (OP_CMPXCHG_MEM16_A, Code::Cmpxchg_rm16_r16, Register::CX, Register::RAX, Code::Mov_r16_rm16, Code::Mov_rm64_r64),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base(Register::R8)).unwrap(),
            Instruction::with2(load_code, src_r, vreg(Register::RDX)).unwrap(),
        ];
        let mut ci = Instruction::with2(cmp_code, MemoryOperand::with_base(Register::R11), src_r).unwrap();
        ci.set_has_lock_prefix(true);
        body.push(ci);
        body.push(Instruction::with2(store_code, MemoryOperand::with_base(Register::R8), acc_r).unwrap());
        // Deterministic ZF-only capture (cmpxchg defines ZF; other flags are
        // undefined). IMPORTANT: capture the flags with pushfq IMMEDIATELY after
        // the cmpxchg -- the `and rdx,~F_ZF` below would otherwise clobber ZF and
        // the captured "ZF" would be garbage, so the lifted `jne`/`setne` after
        // the Once CAS would misread success/failure and the Rust `Once` state
        // machine would break (closure runs twice -> panic at once.rs:166).
        body.push(Instruction::with(Code::Pushfq));
        body.push(Instruction::with1(Code::Pop_r64, Register::R11).unwrap());
        body.push(Instruction::with2(Code::And_rm64_imm32, Register::R11, F_ZF as i32).unwrap());
        body.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, state_flags_mem()).unwrap());
        body.push(Instruction::with2(Code::And_rm64_imm32, Register::RDX, (F_ZF as u32).wrapping_neg() as i32).unwrap());
        body.push(Instruction::with2(Code::Or_rm64_r64, Register::RDX, Register::R11).unwrap());
        body.push(Instruction::with2(Code::Mov_rm64_r64, state_flags_mem(), Register::RDX).unwrap());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// ── v48: atomic memory XCHG / XADD (Once CompletionGuard swap / fetch-add) ─
// OP_XCHG_MEM*_A / OP_XADD_MEM*_A: [addr_vreg, src_vreg].
//   XCHG: real `xchg [addr], reg` — x86 memory XCHG is IMPLICITLY atomic (no
//   LOCK prefix needed). This fixes the Rust `Once` CompletionGuard::drop()
//   `xchg [state], COMPLETE`: the previous non-atomic load+store lift let a
//   2nd call_once read the still-RUNNING state and re-run the closure, ending
//   in `f.take().unwrap()` -> panic at once.rs:166. Register upper bits are
//   preserved for 8/16-bit and zero-extended for 32-bit, exactly like x86.
//   XADD: real `lock xadd [addr], reg` — atomic fetch-add (the Rust
//   `AtomicUsize::fetch_add` refcount path). XADD needs LOCK for atomicity.
//   [addr] becomes old+src, src becomes old [addr]; ADD flags are captured.
pub(super) fn emit_xchg(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, xchg_code, xreg) in [
        (OP_XCHG_MEM8_A, Code::Xchg_rm8_r8, Register::AL),
        (OP_XCHG_MEM16_A, Code::Xchg_rm16_r16, Register::AX),
        (OP_XCHG_MEM32_A, Code::Xchg_rm32_r32, Register::EAX),
        (OP_XCHG_MEM64_A, Code::Xchg_rm64_r64, Register::RAX),
    ] {
        hdr(
            seq,
            op,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
                // atomic swap: [addr] <-> reg  (implicitly atomic for memory xchg)
                Instruction::with2(xchg_code, MemoryOperand::with_base(Register::R11), xreg).unwrap(),
                // reg = old [addr]; upper bits already correct (see lift_xchg)
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RDX), Register::RAX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
            ],
        );
    }
}

pub(super) fn emit_xadd(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, xadd_code, xreg) in [
        (OP_XADD_MEM8_A, Code::Xadd_rm8_r8, Register::AL),
        (OP_XADD_MEM16_A, Code::Xadd_rm16_r16, Register::AX),
        (OP_XADD_MEM32_A, Code::Xadd_rm32_r32, Register::EAX),
        (OP_XADD_MEM64_A, Code::Xadd_rm64_r64, Register::RAX),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
        ];
        // LOCK is mandatory for XADD atomicity (unlike XCHG).
        let mut ci = Instruction::with2(xadd_code, MemoryOperand::with_base(Register::R11), xreg).unwrap();
        ci.set_has_lock_prefix(true);
        body.push(ci);
        // src = old [addr] (upper bits per x86: preserved for 8/16, zeroed for 32)
        body.push(Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RDX), Register::RAX).unwrap());
        // xadd sets ADD flags (OF/SF/ZF/AF/PF/CF)
        body.extend(cap_flags(true));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}
