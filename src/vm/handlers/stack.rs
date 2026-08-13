// ==============================================================================
// BTG v3 - VM Handler Codegen: stack family
// ==============================================================================
// Stack / call-return handlers: PUSH_R, POP_R, CALL8, RET, RET_IMM16, and the
// Win64 NATIVE_CALL bridge. Shared helpers (`hdr`, `m`, `vreg`, `jmp_disp`,
// `cap_flags`, ...) and the `Cl` label enum live in `super` (mod.rs).
// ==============================================================================

use super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

// ── M3 (v23): stack + call/ret ───────────────────────────────────────────
// 0x30 PUSH_R (r): sp -= 8; *(stackbase+sp) = vreg[r]
pub(super) fn emit_push_r(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_PUSH_R,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, 0x20)).unwrap(),
            Instruction::with2(Code::Sub_rm64_imm32, Register::R11, 8).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x20), Register::R11).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base(Register::R11), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// 0x31 POP_R (r): vreg[r] = *(stackbase+sp); sp += 8
pub(super) fn emit_pop_r(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_POP_R,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, 0x20)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base(Register::R11)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R11, 8).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x20), Register::R11).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// 0x32 CALL8 (rel8): push r9+1 (bytecode return IP) onto the VM return-IP
// stack (STATE_CALL_SP); r9 += 1 + rel. The program's observed return VA is
// pushed to [v4] separately by the lifter before the call (two-stack model).
pub(super) fn emit_call8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    seq.push((
        Instruction::with2(Code::Movsx_r64_rm8, Register::RAX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Some(Cl::Handler(OP_CALL8)),
    ));
    seq.push((Instruction::with2(Code::Lea_r64_m, Register::RDX, MemoryOperand::with_base_displ(Register::R9, 1)).unwrap(), None));
    // VM return-IP stack: csp -= 8; addr = base + csp; [addr] = bytecode return ip
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, STATE_CALL_SP as i32)).unwrap(), None));
    seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::R11, 8).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, STATE_CALL_SP as i32), Register::R11).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::R8, STATE_PTR_CALL_STACK as i32)).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::R11).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base(Register::RCX), Register::RDX).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::RAX).unwrap(), None));
    seq.push((jmp_disp(), Some(Cl::Dispatch)));
}

// 0x33 RET: pop bytecode return IP from the VM return-IP stack (STATE_CALL_SP)
// into r9; advance the architectural RSP (v4) past the caller's return VA.
pub(super) fn emit_ret(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    seq.push((
        Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, STATE_CALL_SP as i32)).unwrap(),
        Some(Cl::Handler(OP_RET)),
    ));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, STATE_PTR_CALL_STACK as i32)).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R11).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, MemoryOperand::with_base(Register::RAX)).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R11, 8).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, STATE_CALL_SP as i32), Register::R11).unwrap(), None));
    // architectural RSP (v4) += 8
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, 0x20)).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R11, 8).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x20), Register::R11).unwrap(), None));
    seq.push((jmp_disp(), Some(Cl::Dispatch)));
}

// ── M3 follow-up (v24): native API bridge ─────────────────────────────────
// 0x41 OP_NATIVE_CALL (target_vreg)
//   Win64 call to vreg[target]; args v1->rcx, v2->rdx, v3->r8, v4->r9; ret->v0.
//   The bridge saves the VM infra (state/ip/table) into callee-saved regs,
//   loads args, calls, stores the return, then restores infra and dispatches.
pub(super) fn emit_native_call(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, MemoryOperand::with_base(Register::R9)).unwrap(), Some(Cl::Handler(OP_NATIVE_CALL))));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RAX)).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Cl::Bridge)));
    // Bridge entry: r8=state, r9=ip, r10=table, r11=target.
    seq.push((Instruction::with1(Code::Push_r64, Register::R12).unwrap(), Some(Cl::Bridge)));
    seq.push((Instruction::with1(Code::Push_r64, Register::R13).unwrap(), None));
    seq.push((Instruction::with1(Code::Push_r64, Register::R14).unwrap(), None));
    seq.push((Instruction::with1(Code::Push_r64, Register::R15).unwrap(), None));
    // keep state/ip/table in callee-saved regs across the native call
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R12, Register::R8).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R13, Register::R9).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::R10).unwrap(), None));
    // args (Win64 ABI): v1->rcx, v2->rdx, v8->r8, v9->r9.
    // FIX(C-1 runtime integration, --vm-oep): the bridge previously read the
    // 3rd/4th call args from v3/v4 (= RBX/RSP), but the LIFTED program places
    // call arguments in the real x64 argument registers rcx(v1)/rdx(v2)/
    // r8(v8)/r9(v9). So every native call with >=3 args (e.g. CRT __getmainargs,
    // __set_app_type, _initterm_e) received garbage in arg3/arg4, corrupting
    // CRT env/argv/static-init setup and leaving global/thread function pointers
    // at 0 -> later `call 0` / INVALID_POINTER_EXECUTE. Read v8/v9 for r8/r9.
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::R12, 8)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R12, 16)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R8, m(Register::R12, 64)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, m(Register::R12, 72)).unwrap(), None));
    // FIX(C-1 stack alignment): Win64 ABI requires RSP ≡ 0 (mod 16) at the
    // point of the `call` instruction (before the hardware push of ret addr).
    //
    // The required alignment offset at the bridge depends on the VM entry path:
    //   • Self-test  (call→trampoline→call→entry): entry stub sees RSP%16=8
    //   • vm_oep mode (boot stub jmp→entry):       entry stub sees RSP%16=0
    // In both cases, the bridge cannot know which alignment state it received.
    //
    // Solution: save the current RSP in R15 (already callee-saved; we restore
    // it before returning), explicitly align to 16 bytes, allocate shadow space,
    // call, then restore RSP from R15. This is safe because:
    //   • R12–R15 are callee-saved across the native call.
    //   • The 0x20 shadow space sits below the aligned RSP, satisfying Win64.
    //   • After the call, we restore RSP to exactly where we left it (from R15).
    //
    // This replaces the previous sub 0x28 heuristic which only worked correctly
    // for one entry path and crashed (GetStartupInfoA→RtlUnicodeStringToAnsiString
    // XMM misalignment → heap struct corruption) on the other.
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R15, Register::RSP).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RSP, -16i32).unwrap(), None));
    // FIX(C-1): reserve 0x20 shadow + 4*8 = 0x40 for the forwarded 5th+ stack args.
    // sub 0x20 alone would place them at [rsp+0x20..0x38] = the slots where r12-r15
    // were pushed (when entry RSP is 16-aligned), clobbering the saved state/ip/table
    // and corrupting r10 (handler table) on the restore -> dispatcher `jmp 0`. Use 0x60.
    seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, 0x60).unwrap(), None));
    // FIX(C-1 runtime integration, --vm-oep): forward the 5th+ stack arguments
    // from the VM's logical stack onto the native stack so native callees with
    // >4 args (e.g. CRT __getmainargs, CreateWindowExA) see them. The lifted
    // program stored them at [v4 + 0x20 ..] (v4 = the RSP vreg at STATE_VREGS+32);
    // the native callee reads the 5th arg at [rsp + 0x20]. Copy a 4-qword window.
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R12, 0x20)).unwrap(), None));
    // FIX(C-1): forward up to 8 stack args (args 5..12) so >8-arg native calls
    // (e.g. CreateWindowExA has 12) see all their arguments; the 0x60 frame below
    // already reserves 0x20 shadow + 8*8=0x40 for them.
    for i in 0..8 {
        seq.push((Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RCX,
            MemoryOperand::with_base_displ(Register::RAX, 0x20 + i * 8),
        ).unwrap(), None));
        seq.push((Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base_displ(Register::RSP, 0x20 + i * 8),
            Register::RCX,
        ).unwrap(), None));
    }
    // re-load register args (rcx/rdx/r8/r9) AND non-volatile/general registers (rbx/rbp/rsi/rdi)
    // so internal closures (e.g. 0x3790) see valid state pointers and sync updates back.
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::R12, 8)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R12, 16)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RBX, m(Register::R12, 24)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RBP, m(Register::R12, 40)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RSI, m(Register::R12, 48)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDI, m(Register::R12, 56)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R8, m(Register::R12, 64)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, m(Register::R12, 72)).unwrap(), None));
    seq.push((Instruction::with1(Code::Call_rm64, Register::R11).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::R15).unwrap(), None));
    // Bug-4 fix: sync the VM logical flags (state[STATE_FLAGS]) from the native
    // callee's physical RFLAGS, so a Jcc emitted right after a native call
    // (without an intervening test/cmp) reads the callee's actual flags — matching
    // native x86 semantics where flags after a `call` are whatever the callee left.
    // Must capture before the infra-restore `mov`/`pop` sequence that follows.
    seq.push((Instruction::with(Code::Pushfq), None));
    seq.push((Instruction::with1(Code::Pop_r64, Register::R11).unwrap(), None));
    seq.push((
        Instruction::with2(Code::And_rm64_imm32, Register::R11, (FLAG_MASK as u32) as i32).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_rm64_r64,
            m(Register::R12, STATE_FLAGS as i32),
            Register::R11,
        )
        .unwrap(),
        None,
    ));
    // store return -> vreg[0] and sync back updated rbx/rbp/rsi/rdi
    seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R12, 0), Register::RAX).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R12, 24), Register::RBX).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R12, 40), Register::RBP).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R12, 48), Register::RSI).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R12, 56), Register::RDI).unwrap(), None));
    // restore VM infra
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::R12).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::R13).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::R14).unwrap(), None));
    seq.push((Instruction::with1(Code::Pop_r64, Register::R15).unwrap(), None));
    seq.push((Instruction::with1(Code::Pop_r64, Register::R14).unwrap(), None));
    seq.push((Instruction::with1(Code::Pop_r64, Register::R13).unwrap(), None));
    seq.push((Instruction::with1(Code::Pop_r64, Register::R12).unwrap(), None));
    seq.push((jmp_disp(), Some(Cl::Dispatch)));
}

// 0x7C ret imm16 (operands: imm16): pop bytecode return IP from the VM
// return-IP stack into r9, then v4(RSP) += 8 + imm16 (cdecl arg cleanup).
pub(super) fn emit_ret_imm16(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    seq.push((
        Instruction::with2(Code::Movzx_r32_rm16, Register::EDI, MemoryOperand::with_base(Register::R9)).unwrap(),
        Some(Cl::Handler(OP_RET_IMM16)),
    ));
    // bytecode return IP = [base + csp]; csp += 8
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, STATE_CALL_SP as i32)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, STATE_PTR_CALL_STACK as i32)).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R11).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, MemoryOperand::with_base(Register::RAX)).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R11, 8).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, STATE_CALL_SP as i32), Register::R11).unwrap(), None));
    // architectural RSP (v4) += 8 + imm16
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, 0x20)).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R11, 8).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm64_r64, Register::R11, Register::RDI).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x20), Register::R11).unwrap(), None));
    seq.push((jmp_disp(), Some(Cl::Dispatch)));
}
