// ==============================================================================
// VM self-test submodule: bridge.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use anyhow::{Result, anyhow};
use crate::vm::{handlers, interp};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};
use crate::vm::{build_vm_module};
use crate::vm::arena::{Arena};
use crate::vm::encode::{encode_trampoline};


/// M3 follow-up self-test: native API bridge. The VM calls a native helper via
/// OP_NATIVE_CALL (vreg[target] -> RAX, args v1->rcx, v2->rdx, v8->r8, v9->r9,
/// 5th+ stack args copied from [v4+0x20..] -> native [rsp+0x20..], ret -> v0).
/// Verified through the native arena (the interpreter cannot call native code).
pub(crate) fn run_m3_bridge_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut arena = Arena::new(0x40000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x4000;
    let bc_va = arena.base + 0x5000;
    let state_va = arena.base + 0x6000;
    let stack_va = arena.base + 0x7000;
    let tramp_va = arena.base + 0x8000;
    let native_va = arena.base + 0xB000; // the native helper we call (0xA000 is free; 0x8000 would overlap the VM module code which ends at 0x1000+0x7310=0x8310)
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

    // Native helper: uint64 add4(a,b,c,d) = a + 2b + 4c + 8d.
    // Win64: rcx=a, rdx=b, r8=c, [rsp+0x28]=d (5th arg on the stack).
    let helper = [
        Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RCX).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RDX).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RDX).unwrap(),
        Instruction::with2(Code::Shl_rm64_imm8, Register::R8, 2).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R8).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, Register::RCX, MemoryOperand::with_base_displ(Register::RSP, 0x28)).unwrap(),
        Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 3).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(),
        Instruction::with(Code::Retnq),
    ];
    let hblk = InstructionBlock::new(&helper, native_va as u64);
    let henc = BlockEncoder::encode(64, hblk, BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("native helper encode failed: {}", e))?;

    // VM bytecode: load args + target, native_call, halt.
    //   v1 = a; v2 = b; v8 = c (r8); v0 = target helper.
    //   v4 (RSP reg) is set in arena init so the bridge can forward the 5th stack
    //   arg d from [v4+0x20].
    let mut bc = BytecodeBuilder::new();
    bc.mov_r_imm64(0, native_va as u64);
    bc.mov_r_imm32(1, 10);
    bc.mov_r_imm32(2, 20);
    bc.mov_r_imm32(8, 30);
    bc.native_call(0); // target = vreg[0]
    bc.halt();
    let prog = bc.finish();

    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x4000..0x4000 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
        b[0xB000..0xB000 + henc.code_buffer.len()].copy_from_slice(&henc.code_buffer);
        b[0x5000..0x5000 + prog.len()].copy_from_slice(&prog);
        b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
        b[0x6000 + interp::STATE_PTR_STACK..0x6000 + interp::STATE_PTR_STACK + 8]
            .copy_from_slice(&(stack_va as u64).to_le_bytes());
        b[0x6000 + interp::STATE_SP..0x6000 + interp::STATE_SP + 8].copy_from_slice(&0x1000u64.to_le_bytes());
        b[0x7000..0x7000 + 0x1000].fill(0);
        // v4 (RSP register) = stack_va so the bridge finds the 5th stack arg at [v4+0x20].
        b[0x6000 + interp::STATE_VREGS + 4 * 8..0x6000 + interp::STATE_VREGS + 5 * 8]
            .copy_from_slice(&(stack_va as u64).to_le_bytes());
        // 5th arg d = 40 at [stack_va + 0x20]
        b[0x7000 + 0x20..0x7000 + 0x28].copy_from_slice(&40u64.to_le_bytes());
    }
    arena.call(0x8000);
    let b = arena.bytes();
    let ret = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS + 0 * 8..0x6000 + interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    // add4(10,20,30,40) = 10 + 2*20 + 4*30 + 8*40 = 10+40+120+320 = 490
    assert_eq!(ret, 490, "M3 native bridge returned {} (want 490)", ret);
    // v1/v2/v8 must be preserved (args), v0 clobbered by return value
    let v1 = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS + 1 * 8..0x6000 + interp::STATE_VREGS + 2 * 8].try_into().unwrap());
    let v2 = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS + 2 * 8..0x6000 + interp::STATE_VREGS + 3 * 8].try_into().unwrap());
    let v8 = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS + 8 * 8..0x6000 + interp::STATE_VREGS + 9 * 8].try_into().unwrap());
    assert_eq!((v1, v2, v8), (10, 20, 30), "M3 native bridge clobbered arg vregs");
    Ok(())
}
