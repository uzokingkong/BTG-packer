// ==============================================================================
// VM self-test submodule: stack.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use anyhow::{Result, anyhow};
use crate::vm::{bytecode, handlers, interp, lifter};
use crate::vm::{build_vm_module};
use crate::vm::arena::{Arena};
use crate::vm::encode::{encode_trampoline};


/// M3 self-test: stack (push/pop) + subroutine call/ret. Cross-checks the
/// interpreter against the native x86-64 handlers.
pub(crate) fn run_m3_stack_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut arena = Arena::new(0x30000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x5800;
    let bc_va = arena.base + 0x5000;
    let state_va = arena.base + 0x6000;
    let stack_va = arena.base + 0x9000; // stack region
    let tramp_va = arena.base + 0xA000;
    let module = build_vm_module(
        code_va as u64,
        table_va as u64,
        bc_va as u64,
        vec![0u8; 128],
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(
        state_va as u64,
        stack_va as u64,
        stack_va as u64,
        code_va as u64,
        tramp_va as u64,
    )?;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x5800..0x5800 + module.table.len()].copy_from_slice(&module.table);
        b[0xA000..0xA000 + tramp.len()].copy_from_slice(&tramp);
    }

    // Program: main pushes a,b then calls ADDSUB (which pops a,b, computes a+b
    // into v2, restores the return address, rets). Then main pushes the result
    // and pops it into v6. v4 = RSP is the single stack pointer (vreg4-as-single-stack).
    let mut bc = BytecodeBuilder::new();
    bc.mov_r_imm32(0, 5); // a
    bc.mov_r_imm32(1, 7); // b
    bc.push_r(1); // push b
    bc.push_r(0); // push a
    let sub = bc.new_label();
    // Two-stack model: push the program-visible return VA to [v4] before the
    // internal call (the bytecode return IP is handled on the VM return-IP stack
    // by call8, NOT written to the architectural stack).
    bc.mov_r_imm64(crate::vm::lifter::SCRATCH, 0x1234_5678_0000_0000);
    bc.push_r(crate::vm::lifter::SCRATCH);
    bc.call8(sub);
    bc.push_r(2); // push result
    bc.pop_r(6); // v6 = result
    bc.halt();
    bc.mark_label(sub);
    bc.pop_r(3); // return addr
    bc.pop_r(10); // a  (NOT v4 — v4 is the RSP stack pointer)
    bc.pop_r(5); // b
    bc.mov_r_imm32(2, 0);
    bc.binop_r_r(OP_ADD_R_R, 2, 10);
    bc.binop_r_r(OP_ADD_R_R, 2, 5);
    bc.push_r(3); // restore return addr
    bc.ret();
    let prog = bc.finish();

    const STACK_SIZE: u64 = 0x1000;
    let call_stack_va = arena.base + 0xB000; // dedicated VM bytecode return-IP stack (two-stack)

    // Interpreter
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x8000];
    // vreg4 = RSP points at the architectural stack TOP in mem space.
    st[interp::STATE_VREGS + 4 * 8..interp::STATE_VREGS + 4 * 8 + 8].copy_from_slice(&0x4000u64.to_le_bytes());
    // Two-stack model: init the dedicated VM bytecode return-IP stack.
    st[interp::STATE_PTR_CALL_STACK..interp::STATE_PTR_CALL_STACK + 8].copy_from_slice(&0x1000u64.to_le_bytes());
    st[interp::STATE_CALL_SP..interp::STATE_CALL_SP + 8].copy_from_slice(&(interp::CALL_STACK_SIZE as u64).to_le_bytes());
    interp::interpret(&mut st, &mut mem, &prog).map_err(|e| anyhow!("M3 stack interp failed: {:?}", e))?;
    let mut vi = [0u64; 16];
    for i in 0..16 {
        vi[i] = u64::from_le_bytes(st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }

    // Native
    {
        let b = arena.bytes();
        b[0x5000..0x5000 + prog.len()].copy_from_slice(&prog);
        b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
        // vreg4 = RSP points at the stack TOP (stack_va + STACK_SIZE).
        b[0x6000 + interp::STATE_VREGS + 4 * 8..0x6000 + interp::STATE_VREGS + 4 * 8 + 8]
            .copy_from_slice(&((stack_va as u64) + STACK_SIZE).to_le_bytes());
        // Two-stack model: init the dedicated VM bytecode return-IP stack (base at
        // a free arena region, empty offset = CALL_STACK_SIZE).
        b[0x6000 + interp::STATE_PTR_CALL_STACK..0x6000 + interp::STATE_PTR_CALL_STACK + 8]
            .copy_from_slice(&(call_stack_va as u64).to_le_bytes());
        b[0x6000 + interp::STATE_CALL_SP..0x6000 + interp::STATE_CALL_SP + 8]
            .copy_from_slice(&(interp::CALL_STACK_SIZE as u64).to_le_bytes());
        b[0x8000..0x8000 + 0x1000].fill(0); // clear stack region
    }
    arena.call(0xA000);
    let b = arena.bytes();
    let mut vn = [0u64; 16];
    for i in 0..16 {
        vn[i] = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS + i * 8..0x6000 + interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }
    // Compare data vregs. Skip index 3 (return address — bytecode index in interp,
    // VA in native) and index 4 (RSP stack pointer — mem-offset in interp, absolute
    // VA in native); both are correct for their model.
    for i in 0..16 {
        if i == 3 || i == 4 {
            continue;
        }
        assert_eq!(vi[i], vn[i], "M3 stack/call/ret: interp vs native vreg {} mismatch (interp=0x{:X} native=0x{:X})", i, vi[i], vn[i]);
    }
    // Expected: a+b=12 in v2 and v6
    assert_eq!(vi[2], 12, "M3 subroutine result v2 wrong");
    assert_eq!(vi[6], 12, "M3 pop result v6 wrong");
    Ok(())
}
