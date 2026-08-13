// ==============================================================================
// VM self-test submodule: lift.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use anyhow::{Result, anyhow};
use crate::vm::{bytecode, handlers, interp};
use crate::vm::lifter::{LiftedInstr};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};
use crate::vm::{build_vm_module};
use crate::vm::arena::{Arena};
use crate::vm::encode::{encode_trampoline, is_branch_code, measure};


/// M4 self-test: block lift (1:1 x86→VM table) + dummy_fn equivalence.
/// Lifts a small dummy function to bytecode, executes it through the interpreter
/// AND the native VM, and compares both against a native x86 execution of the
/// same instruction sequence. The dummy_fn exercises reg moves, arithmetic,
/// shifts, LEA (base+index*scale+disp), absolute-address loads/stores and a
/// CALL/RET subroutine. (Control-flow lift — loops/jcc — is M5.)
pub(crate) fn run_m4_lift_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::lifter::{LiftedInstr, lift_block};

    // RSI (v6) = data base is supplied by the caller from VM state / native stub.
    // Dummy (deterministic, straight-line):
    //   eax = a (ecx)
    //   eax += b (edx)
    //   eax <<= 2
    //   eax ^= c (r8d)
    //   [rsi+0x40] = eax            (store, disp)
    //   r9d = [rsi+0x40]            (load, disp)
    //   r10d = r9d << 2             (index)
    //   lea r11, [rsi + r10*4 + 8]  (base+index*scale+disp)
    //   [r11] = r9d                 (absolute store)
    //   call helper                 (CALL/RET subroutine)
    //   ret
    // helper: eax += 1 ; ret
    let helper_label = 10u32;
    let mut seq: Vec<LiftedInstr> = Vec::new();
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::ECX).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Add_r32_rm32, Register::EAX, Register::EDX).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 2).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::R8D).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base_displ(Register::RSI, 0x40), Register::EAX).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_r32_rm32, Register::R9D, MemoryOperand::with_base_displ(Register::RSI, 0x40)).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_r32_rm32, Register::R10D, Register::R9D).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Shl_rm32_imm8, Register::R10D, 2).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Lea_r64_m, Register::R11, MemoryOperand::with_base_index_scale_displ_size(Register::RSI, Register::R10, 4, 8, 1)).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base(Register::R11), Register::R9D).unwrap()));
    seq.push(LiftedInstr::branch(Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), helper_label));
    seq.push(LiftedInstr::plain(Instruction::with(Code::Retnq)));
    seq.push(LiftedInstr::labeled(Instruction::with2(Code::Add_rm32_imm32, Register::EAX, 1).unwrap(), helper_label));
    seq.push(LiftedInstr::plain(Instruction::with(Code::Retnq)));

    // args: a=3, b=5, c=2  ->  eax = ((3+5)<<2)^2 = 34 ; helper: +1 -> 35
    let (a, argb, c) = (3u32, 5u32, 2u32);
    let expected = ((a.wrapping_add(argb).wrapping_shl(2)) ^ c).wrapping_add(1);

    // 1) Native x86 reference
    let native = encode_dummy_native(&seq, 0)?;
    let mut native_arena = Arena::new(0x8000)?;
    let native_va = native_arena.base + 0x1000;
    let native_data = native_arena.base + 0x2000;
    let native_tramp = native_arena.base + 0x3000;
    let native_stub = encode_dummy_call_stub(native_va as u64, native_data as u64, a, argb, c, native_tramp as u64)?;
    {
        let b = native_arena.bytes();
        b[0x1000..0x1000 + native.len()].copy_from_slice(&native);
        b[0x3000..0x3000 + native_stub.len()].copy_from_slice(&native_stub);
        b[0x2000..0x2000 + 0x100].fill(0);
    }
    let expected = native_arena.call_u64(0x3000);
    assert_eq!(expected, ((a.wrapping_add(argb).wrapping_shl(2) ^ c).wrapping_add(1)) as u64, "M4 native reference self-consistency");

    // 2) Lift to VM bytecode and run through the interpreter.
    let bc = lift_block(&seq, 0)?;
    // lift_block appends a trailing HALT; the dummy's main `ret` pops a return
    // address we pre-place on the VM stack that points at that HALT.
    let halt_off = (bc.len() - 1) as u64; // bytecode index of the trailing HALT
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x4000];
    let data_off = 0x2000usize;
    st[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].copy_from_slice(&0u64.to_le_bytes()); // rax
    st[interp::STATE_VREGS + 1 * 8..interp::STATE_VREGS + 2 * 8].copy_from_slice(&(a as u64).to_le_bytes()); // rcx = a
    st[interp::STATE_VREGS + 2 * 8..interp::STATE_VREGS + 3 * 8].copy_from_slice(&(argb as u64).to_le_bytes()); // rdx = b
    st[interp::STATE_VREGS + 8 * 8..interp::STATE_VREGS + 9 * 8].copy_from_slice(&(c as u64).to_le_bytes()); // r8 = c
    st[interp::STATE_VREGS + 6 * 8..interp::STATE_VREGS + 7 * 8].copy_from_slice(&(data_off as u64).to_le_bytes()); // rsi
    st[interp::STATE_VREGS + 4 * 8..interp::STATE_VREGS + 5 * 8].copy_from_slice(&0x3FF8u64.to_le_bytes()); // vreg4 = RSP (stack top)
    // Two-stack model: init the dedicated VM return-IP stack and pre-place the
    // outermost function's return ip (-> trailing HALT) on it, since `ret` pops
    // the bytecode IP from this stack (not from [v4]).
    st[interp::STATE_PTR_CALL_STACK..interp::STATE_PTR_CALL_STACK + 8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_CALL_SP..interp::STATE_CALL_SP + 8].copy_from_slice(&((interp::CALL_STACK_SIZE - 8) as u64).to_le_bytes());
    mem[(interp::CALL_STACK_SIZE - 8) as usize..interp::CALL_STACK_SIZE].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("M4 lift interp failed: {:?}", e))?;
    let interp_rax = u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    assert_eq!(interp_rax, expected, "M4 lift interpreter: rax mismatch (interp=0x{:X} native=0x{:X})", interp_rax, expected);

    // 3) Native VM execution.
    let mut vm_arena = Arena::new(0x40000)?;
    let vm_code_va = vm_arena.base + 0x1000;
    let vm_table_va = vm_arena.base + 0x4000;
    let vm_bc_va = vm_arena.base + 0x5000;
    let vm_state_va = vm_arena.base + 0x6000;
    let vm_stack_va = vm_arena.base + 0x7000;
    let vm_tramp_va = vm_arena.base + 0x8000;
    let vm_data_va = vm_arena.base + 0x9000;
    let module = build_vm_module(vm_code_va as u64, vm_table_va as u64, vm_bc_va as u64, bc.clone(), handlers::EntryMode::Ksa)?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vm_state_va as u64, vm_data_va as u64, vm_data_va as u64, vm_code_va as u64, vm_tramp_va as u64)?;
    let call_stack_va = vm_arena.base + 0xA000; // dedicated VM bytecode return-IP stack (two-stack)
    {
        let b = vm_arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x4000..0x4000 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
        b[0x5000..0x5000 + bc.len()].copy_from_slice(&bc);
        b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
        b[0x6000 + interp::STATE_VREGS + 0 * 8..0x6000 + interp::STATE_VREGS + 1 * 8].copy_from_slice(&0u64.to_le_bytes()); // rax
        b[0x6000 + interp::STATE_VREGS + 1 * 8..0x6000 + interp::STATE_VREGS + 2 * 8].copy_from_slice(&(a as u64).to_le_bytes()); // rcx = a
        b[0x6000 + interp::STATE_VREGS + 2 * 8..0x6000 + interp::STATE_VREGS + 3 * 8].copy_from_slice(&(argb as u64).to_le_bytes()); // rdx = b
        b[0x6000 + interp::STATE_VREGS + 8 * 8..0x6000 + interp::STATE_VREGS + 9 * 8].copy_from_slice(&(c as u64).to_le_bytes()); // r8 = c
        b[0x6000 + interp::STATE_VREGS + 6 * 8..0x6000 + interp::STATE_VREGS + 7 * 8].copy_from_slice(&(vm_data_va as u64).to_le_bytes());
        b[0x6000 + interp::STATE_VREGS + 4 * 8..0x6000 + interp::STATE_VREGS + 5 * 8].copy_from_slice(&((vm_stack_va as u64) + 0xFF8).to_le_bytes());
        b[0x7000..0x7000 + 0x1000].fill(0);
        // Two-stack model: init the dedicated VM return-IP stack and pre-place the
        // outermost return ip (absolute VA of trailing HALT) on it.
        b[0x6000 + interp::STATE_PTR_CALL_STACK..0x6000 + interp::STATE_PTR_CALL_STACK + 8]
            .copy_from_slice(&(call_stack_va as u64).to_le_bytes());
        b[0x6000 + interp::STATE_CALL_SP..0x6000 + interp::STATE_CALL_SP + 8]
            .copy_from_slice(&((interp::CALL_STACK_SIZE - 8) as u64).to_le_bytes());
        b[(0xA000 + (interp::CALL_STACK_SIZE - 8)) as usize..0xA000 + interp::CALL_STACK_SIZE]
            .copy_from_slice(&((vm_bc_va as u64) + halt_off).to_le_bytes());
        b[0x9000..0x9000 + 0x100].fill(0);
    }
    vm_arena.call(0x8000);
    let b = vm_arena.bytes();
    let vm_rax = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS + 0 * 8..0x6000 + interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    assert_eq!(vm_rax, expected, "M4 lift native VM: rax mismatch (vm=0x{:X} native=0x{:X})", vm_rax, expected);
    Ok(())
}


/// Encode a labeled block (LiftedInstr) to native x86 with two-pass branch
/// resolution (mirrors `encode_labeled_block`).
pub(crate) fn encode_dummy_native(seq: &[LiftedInstr], base_va: u64) -> Result<Vec<u8>> {
    use iced_x86::{BlockEncoder, BlockEncoderOptions, InstructionBlock};
    let mut label_idx: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for (i, it) in seq.iter().enumerate() {
        if let Some(l) = it.label {
            label_idx.insert(l, i);
        }
    }
    let mut ip = base_va;
    let mut label_ips: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    for it in seq.iter() {
        let mut m = it.inst;
        if it.label.is_some() && is_branch_code(it.inst.code()) {
            m = Instruction::with_branch(it.inst.code(), ip).unwrap();
        }
        if let Some(l) = it.label {
            if !is_branch_code(it.inst.code()) {
                label_ips.insert(l, ip);
            }
        }
        ip += measure(&m, ip) as u64;
    }
    let mut insts: Vec<Instruction> = Vec::with_capacity(seq.len());
    for it in seq.iter() {
        let mut m = it.inst;
        if let Some(t) = it.target {
            let tva = label_ips[&t];
            m = Instruction::with_branch(it.inst.code(), tva).unwrap();
        }
        insts.push(m);
    }
    let block = InstructionBlock::new(&insts, base_va);
    let enc = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("dummy native encode failed: {}", e))?;
    Ok(enc.code_buffer)
}


/// Call stub for the native dummy: sets rcx/rdx/r8 (args) and rsi (data base),
/// then calls the dummy fn; returns rax via call_u64.
pub(crate) fn encode_dummy_call_stub(fn_va: u64, data_va: u64, a: u32, b: u32, c: u32, base_va: u64) -> Result<Vec<u8>> {
    use iced_x86::{BlockEncoder, BlockEncoderOptions, InstructionBlock};
    let insts = [
        Instruction::with2(Code::Mov_r32_imm32, Register::ECX, a as i32).unwrap(),
        Instruction::with2(Code::Mov_r32_imm32, Register::EDX, b as i32).unwrap(),
        Instruction::with2(Code::Mov_r32_imm32, Register::R8D, c as i32).unwrap(),
        Instruction::with2(Code::Mov_r64_imm64, Register::RSI, data_va).unwrap(),
        Instruction::with_branch(Code::Call_rel32_64, fn_va).unwrap(),
        Instruction::with(Code::Retnq),
    ];
    let block = InstructionBlock::new(&insts, base_va);
    let enc = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("dummy call stub encode failed: {}", e))?;
    Ok(enc.code_buffer)
}
