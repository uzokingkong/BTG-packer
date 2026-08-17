// ==============================================================================
// VM self-test submodule: text.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use anyhow::{Result, anyhow};
use crate::vm::{bytecode, handlers, interp};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};
use crate::vm::{build_vm_module};
use crate::vm::arena::{Arena};
use crate::vm::encode::{encode_trampoline};


/// M6 (v26) self-test: lift a *real* x86 `.text` block (decoded from raw bytes)
/// to VM bytecode and prove interpreter == native execution. Unlike the M4
/// dummy_fn (hand-built LiftedInstr), this feeds an actual raw-code buffer
/// through CfgExtractor → analyze_text_lift → lift, then runs the lifted
/// bytecode through the reference interpreter AND the native VM, comparing both
/// to a native x86 execution of the same bytes. This validates the M6
/// "원본 .text lift" path end-to-end.
// cross-submodule helper (defined in lift.rs)
use super::lift::encode_dummy_call_stub;

pub(crate) fn run_text_lift_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::text_lift::analyze_text_lift;

    // Build a real x86-64 function as raw bytes (BlockEncoder), representing a
    // straight-line .text block: eax = (ecx + edx) << 2; eax ^= r8d;
    // [rsi+0x40] = eax; r9d = [rsi+0x40]; ret.
    // (No r10/index-based addressing — the native reference stub only sets
    // rcx/rdx/r8/rsi, and an uninitialized r10 would fault the store.)
    let insts = [
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::ECX).unwrap(),
        Instruction::with2(Code::Add_r32_rm32, Register::EAX, Register::EDX).unwrap(),
        Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 2).unwrap(),
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::R8D).unwrap(),
        Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base_displ(Register::RSI, 0x40), Register::EAX).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::R9D, MemoryOperand::with_base_displ(Register::RSI, 0x40)).unwrap(),
        Instruction::with(Code::Retnq),
    ];
    let base_va = 0x140001000u64;
    let blk = InstructionBlock::new(&insts, base_va);
    let enc = BlockEncoder::encode(64, blk, BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("M6 text encode failed: {}", e))?;
    let text = enc.code_buffer;

    // Arguments + expected: a=3, b=5, c=2 -> ((3+5)<<2)^2 = 34
    let (a, b, c) = (3u32, 5u32, 2u32);
    let expected = ((a.wrapping_add(b).wrapping_shl(2)) ^ c) as u64;

    // 1) Native x86 reference execution
    let native = { use crate::graph::CfgExtractor; };
    // (the raw bytes ARE the native reference — run them directly)
    let mut narena = Arena::new(0x8000)?;
    let ndata = narena.base + 0x2000;
    let ncode = narena.base + 0x3000;
    let ncall = narena.base + 0x4000;
    {
        let b = narena.bytes();
        b[0x3000..0x3000 + text.len()].copy_from_slice(&text);
        b[0x2000..0x2000 + 0x100].fill(0);
    }
    // native stub: set rcx/rdx/r8/rsi then call the block
    let nstub = encode_dummy_call_stub(ncode as u64, ndata as u64, a, b, c, ncall as u64)?;
    {
        let b = narena.bytes();
        b[0x4000..0x4000 + nstub.len()].copy_from_slice(&nstub);
    }
    let native_rax = narena.call_u64(0x4000);
    assert_eq!(native_rax, expected, "M6 native reference self-consistency");

    // 2) Lifting pipeline: CfgExtractor on the raw bytes -> analyze_text_lift.
    // The block is straight-line (ends in ret) so it should lift fully.
    let report = analyze_text_lift(
        &text,
        base_va,
        base_va,
        &[],
        0,
    )?;
    assert!(!report.blocks.is_empty(), "M6 CFG should find the block");
    // The ret-terminated straight-line block must lift.
    let lifted = report
        .blocks
        .iter()
        .find(|bl| bl.start_va == base_va)
        .expect("M6 CFG did not produce a block at base_va");
    assert!(
        lifted.liftable_block,
        "M6 block should be liftable (unsupported={:?})",
        lifted.unsupported
    );

    // 3) Run the lifted bytecode through the interpreter.
    let bc = report.blocks[0].bytecode_len;
    assert!(bc > 0, "M6 lifted bytecode should be non-empty");
    // Obtain the actual bytecode: re-run CfgExtractor + lift_text_block.
    use crate::graph::CfgExtractor;
    let (blocks, _g) = CfgExtractor::extract(&text, base_va, base_va, &[], 0)?;
    let bb = blocks
        .iter()
        .find(|b| b.start_va == base_va)
        .expect("M6 CFG produced no block at base_va");
    let lifted_bc = crate::vm::text_lift::lift_text_block(bb)?;
    assert!(!lifted_bc.is_empty(), "M6 lift_text_block returned empty");

    // Run the lifted bytecode through the interpreter. Memory operands use vreg
    // addresses (rsi = data_off into the mem arena), and there are no RIP-relative
    // operands, so base_va does not affect the bytecode semantics.
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x4000];
    let data_off = 0x2000usize;
    st[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_VREGS + 1 * 8..interp::STATE_VREGS + 2 * 8].copy_from_slice(&(a as u64).to_le_bytes());
    st[interp::STATE_VREGS + 2 * 8..interp::STATE_VREGS + 3 * 8].copy_from_slice(&(b as u64).to_le_bytes());
    st[interp::STATE_VREGS + 8 * 8..interp::STATE_VREGS + 9 * 8].copy_from_slice(&(c as u64).to_le_bytes());
    st[interp::STATE_VREGS + 6 * 8..interp::STATE_VREGS + 7 * 8].copy_from_slice(&(data_off as u64).to_le_bytes()); // rsi
    st[interp::STATE_VREGS + 4 * 8..interp::STATE_VREGS + 5 * 8].copy_from_slice(&0x3FF8u64.to_le_bytes()); // vreg4 = RSP (stack top)
    // Two-stack model: init the dedicated VM return-IP stack and pre-place the
    // outermost return ip (-> trailing HALT) on it (ret pops this stack, not [v4]).
    let halt_off = (lifted_bc.len() - 1) as u64; // index of trailing HALT
    st[interp::STATE_PTR_CALL_STACK..interp::STATE_PTR_CALL_STACK + 8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_CALL_SP..interp::STATE_CALL_SP + 8].copy_from_slice(&((interp::CALL_STACK_SIZE - 8) as u64).to_le_bytes());
    mem[(interp::CALL_STACK_SIZE - 8) as usize..interp::CALL_STACK_SIZE].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &lifted_bc)
        .map_err(|e| anyhow!("M6 lift interp failed: {:?}", e))?;
    let interp_rax = u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    assert_eq!(interp_rax, expected, "M6 lifted interpreter: rax mismatch");

    // 4) Native VM execution of the same lifted bytecode.
    let mut vm_arena = Arena::new(0x40000)?;
    let vm_code_va = vm_arena.base + 0x1000;
    let vm_table_va = vm_arena.base + 0x5800;
    let vm_bc_va = vm_arena.base + 0x5000;
    let vm_state_va = vm_arena.base + 0x6000;
    let vm_stack_va = vm_arena.base + 0x7000;
    let vm_tramp_va = vm_arena.base + 0x8000;
    let vm_data_va = vm_arena.base + 0x9000;
    let module = build_vm_module(vm_code_va as u64, vm_table_va as u64, vm_bc_va as u64, lifted_bc.clone(), handlers::EntryMode::Ksa)?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vm_state_va as u64, vm_data_va as u64, vm_data_va as u64, vm_code_va as u64, vm_tramp_va as u64)?;
    let b_arg = b; // keep the b argument across the arena-shadowing block below
    let call_stack_va = vm_arena.base + 0xA000; // dedicated VM bytecode return-IP stack (two-stack)
    {
        let b = vm_arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x5800..0x5800 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
        b[0x5000..0x5000 + lifted_bc.len()].copy_from_slice(&lifted_bc);
        b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
        b[0x6000 + interp::STATE_VREGS + 0 * 8..0x6000 + interp::STATE_VREGS + 1 * 8].copy_from_slice(&0u64.to_le_bytes());
        b[0x6000 + interp::STATE_VREGS + 1 * 8..0x6000 + interp::STATE_VREGS + 2 * 8].copy_from_slice(&(a as u64).to_le_bytes());
        b[0x6000 + interp::STATE_VREGS + 2 * 8..0x6000 + interp::STATE_VREGS + 3 * 8].copy_from_slice(&(b_arg as u64).to_le_bytes());
        b[0x6000 + interp::STATE_VREGS + 8 * 8..0x6000 + interp::STATE_VREGS + 9 * 8].copy_from_slice(&(c as u64).to_le_bytes());
        b[0x6000 + interp::STATE_VREGS + 6 * 8..0x6000 + interp::STATE_VREGS + 7 * 8].copy_from_slice(&(vm_data_va as u64).to_le_bytes()); // rsi
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
    assert_eq!(vm_rax, expected, "M6 lifted native VM: rax mismatch (vm=0x{:X} native=0x{:X})", vm_rax, expected);

    Ok(())
}


/// [23] M6 Phase-2 (v34): OEP→VM entry 전환 데이터 경로 — 원본 .text의 도달 가능한
/// CFG 전체를 하나의 VM 프로그램(lift_cfg)으로 lift 해 interpreter가 네이티브 x86
/// 참조 실행과 동일한 결과를 내는지 검증한다.
///
/// f(rcx=n, rbx=incr): rax = sum of incr over n iterations (loop with jcc/jmp),
/// then 8/16-bit arith and a JCXZ skip. This exercises the *whole-CFG* path that the
/// boot integration (OEP→VM entry) will consume: multi-block control flow, 8/16-bit
/// arithmetic, and JCXZ are all lifted as one connected VM program.
pub(crate) fn run_m6_phase2_lift_test() -> Result<()> {
    use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};
    use crate::graph::CfgExtractor;
    use crate::vm::lifter::lift_cfg;
    use crate::vm::text_lift::lift_program_cfg;

    // f(rcx=n, rbx=incr): 
    //   mov eax,0         ; sum = 0
    //   xor r8d,r8d       ; i = 0
    // loop:
    //   cmp r8, rcx       ; i < n
    //   jge done
    //   add eax, ebx      ; sum += incr
    //   add r8d, 1        ; i++
    //   jmp loop
    // done:
    //   add al, 0x05      ; 8-bit arith
    //   xor cx, cx        ; rcx=0
    //   jrcxz skip        ; JCXZ: taken
    //   add eax, 0x01     ; skipped
    // skip:
    //   ret
    let base = 0x1000u64;
    let mut insts: Vec<Instruction> = Vec::new();
    insts.push(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0).unwrap());
    insts.push(Instruction::with2(Code::Xor_r32_rm32, Register::R8D, Register::R8D).unwrap());
    insts.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R8, Register::RCX).unwrap());
    insts.push(Instruction::with_branch(Code::Jge_rel8_64, base).unwrap());   // done, patched
    insts.push(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::EBX).unwrap());
    insts.push(Instruction::with2(Code::Add_rm32_imm8, Register::R8D, 1).unwrap());
    insts.push(Instruction::with_branch(Code::Jmp_rel8_64, base).unwrap());   // loop, patched
    insts.push(Instruction::with2(Code::Add_rm8_imm8, Register::AL, 0x05).unwrap()); // done:
    insts.push(Instruction::with2(Code::Xor_r32_rm32, Register::ECX, Register::ECX).unwrap()); // rcx=0
    insts.push(Instruction::with_branch(Code::Jrcxz_rel8_64, base).unwrap()); // skip, patched
    insts.push(Instruction::with2(Code::Add_rm32_imm8, Register::EAX, 1).unwrap()); // skipped
    insts.push(Instruction::with(Code::Retnq));

    // Probe-encode to discover real IPs (Instruction::len() is 0 before encoding).
    let probe = BlockEncoder::encode(64, InstructionBlock::new(&insts, base), BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("M6-2 probe encode failed: {}", e))?;
    let mut dec = iced_x86::Decoder::with_ip(64, &probe.code_buffer, base, iced_x86::DecoderOptions::NONE);
    let mut loop_start = base;
    let mut done_start = base;
    let mut skip_target = base;
    while dec.can_decode() {
        let i = dec.decode();
        if i.code() == Code::Cmp_rm64_r64 { loop_start = i.ip(); }
        if i.code() == Code::Add_rm8_imm8 { done_start = i.ip(); }
        if i.code() == Code::Retnq { skip_target = i.ip(); } // jcxz target = ret (skips add eax,1)
    }
    insts[3] = Instruction::with_branch(Code::Jge_rel8_64, done_start).unwrap();
    insts[6] = Instruction::with_branch(Code::Jmp_rel8_64, loop_start).unwrap();
    insts[9] = Instruction::with_branch(Code::Jrcxz_rel8_64, skip_target).unwrap();
    let enc = BlockEncoder::encode(64, InstructionBlock::new(&insts, base), BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("M6-2 encode failed: {}", e))?;
    let native = enc.code_buffer;

    let n = 5u32;
    let incr = 3u64;
    let want = (incr * n as u64) + 5; // loop sum + add al,5 ; jcxz skips +1

    // 1) Native x86 reference — custom stub sets rcx=n, rbx=incr (the fn args).
    let mut narena = Arena::new(0x8000)?;
    let ncode = narena.base + 0x3000;
    let ncall = narena.base + 0x4000;
    let ndata = narena.base + 0x2000;
    {
        let b = narena.bytes();
        b[0x3000..0x3000 + native.len()].copy_from_slice(&native);
    }
    let stub = {
        use iced_x86::{BlockEncoder, BlockEncoderOptions, InstructionBlock};
        let insts = [
            Instruction::with2(Code::Mov_r64_imm64, Register::RCX, n as u64).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, Register::RBX, incr).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, Register::RSI, ndata as u64).unwrap(),
            Instruction::with_branch(Code::Call_rel32_64, ncode as u64).unwrap(),
            Instruction::with(Code::Retnq),
        ];
        let blk = InstructionBlock::new(&insts, ncall as u64);
        BlockEncoder::encode(64, blk, BlockEncoderOptions::NONE)
            .map_err(|e| anyhow!("M6-2 native stub encode failed: {}", e))?.code_buffer
    };
    {
        let b = narena.bytes();
        b[0x4000..0x4000 + stub.len()].copy_from_slice(&stub);
    }
    let native_rax = narena.call_u64(0x4000);
    assert_eq!(native_rax, want, "[23] native reference self-consistency (got {} want {})", native_rax, want);

    // 2) Whole-CFG lift via lift_program_cfg
    let lift = lift_program_cfg(&native, base, base, &[], 0, &[])?;
    assert!(!lift.bytecode.is_empty(), "[23] whole-CFG lift empty");
    assert!(lift.unsupported.is_empty(), "[23] unexpected unsupported {:?}", lift.unsupported);
    assert_eq!(lift.entry_va, base, "[23] entry block should be at base");

    // 3) Interpreter run
    let bc = &lift.bytecode;
    let halt_off = (bc.len() - 1) as u64;
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x4000];
    st[interp::STATE_VREGS + 1*8..][..8].copy_from_slice(&(n as u64).to_le_bytes()); // rcx=n
    st[interp::STATE_VREGS + 3*8..][..8].copy_from_slice(&incr.to_le_bytes());        // rbx=incr
    st[interp::STATE_VREGS + 4*8..][..8].copy_from_slice(&0x3FF8u64.to_le_bytes());   // v4 = RSP (arch stack top)
    // Two-stack model: init the dedicated VM return-IP stack and pre-place the
    // outermost return ip (-> trailing HALT) on it.
    st[interp::STATE_PTR_CALL_STACK..interp::STATE_PTR_CALL_STACK + 8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_CALL_SP..interp::STATE_CALL_SP + 8].copy_from_slice(&((interp::CALL_STACK_SIZE - 8) as u64).to_le_bytes());
    mem[(interp::CALL_STACK_SIZE - 8) as usize..interp::CALL_STACK_SIZE].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, bc).map_err(|e| anyhow!("[23] interp failed: {:?}", e))?;
    let rax = u64::from_le_bytes(st[interp::STATE_VREGS+0*8..][..8].try_into().unwrap());
    assert_eq!(rax, want, "[23] whole-CFG lifted interpreter: rax got {} want {}", rax, want);

    Ok(())
}


/// [26] M6 Phase-2 (v38): 마지막 배선의 실행 코어 — 원본 프로그램을 lift 한 **단일 VM 프로그램**을
/// **네이티브 VM**(build_vm_module + trampoline + arena)으로 실행해, interpreter·네이티브 VM·네이티브
/// x86 참조 세 경로가 모두 동일한 결과를 내는지 검증한다. 이것이 부트 스텁이 디스패치할 정확한
/// 코드 경로다 (OEP→VM entry 전환의 실행 증명).
pub(crate) fn run_m6_phase2_native_program_test() -> Result<()> {
    use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};
    use crate::graph::CfgExtractor;
    use crate::vm::text_lift::lift_program_cfg;

    // Representative original-program entry: loop + branch + 8/16-bit arith + JCXZ.
    let base = 0x1000u64;
    let mut insts: Vec<Instruction> = Vec::new();
    insts.push(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0).unwrap());
    insts.push(Instruction::with2(Code::Xor_r32_rm32, Register::R8D, Register::R8D).unwrap());
    insts.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R8, Register::RCX).unwrap());
    insts.push(Instruction::with_branch(Code::Jge_rel8_64, base).unwrap());
    insts.push(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::EBX).unwrap());
    insts.push(Instruction::with2(Code::Add_rm32_imm8, Register::R8D, 1).unwrap());
    insts.push(Instruction::with_branch(Code::Jmp_rel8_64, base).unwrap());
    insts.push(Instruction::with2(Code::Add_rm8_imm8, Register::AL, 0x05).unwrap());
    insts.push(Instruction::with2(Code::Xor_r32_rm32, Register::ECX, Register::ECX).unwrap());
    insts.push(Instruction::with_branch(Code::Jrcxz_rel8_64, base).unwrap());
    insts.push(Instruction::with2(Code::Add_rm32_imm8, Register::EAX, 1).unwrap());
    insts.push(Instruction::with(Code::Retnq));

    let probe = BlockEncoder::encode(64, InstructionBlock::new(&insts, base), BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("[26] probe encode failed: {}", e))?;
    let mut dec = iced_x86::Decoder::with_ip(64, &probe.code_buffer, base, iced_x86::DecoderOptions::NONE);
    let (mut loop_start, mut done_start, mut skip_target) = (base, base, base);
    while dec.can_decode() {
        let i = dec.decode();
        if i.code() == Code::Cmp_rm64_r64 { loop_start = i.ip(); }
        if i.code() == Code::Add_rm8_imm8 { done_start = i.ip(); }
        if i.code() == Code::Retnq { skip_target = i.ip(); }
    }
    insts[3] = Instruction::with_branch(Code::Jge_rel8_64, done_start).unwrap();
    insts[6] = Instruction::with_branch(Code::Jmp_rel8_64, loop_start).unwrap();
    insts[9] = Instruction::with_branch(Code::Jrcxz_rel8_64, skip_target).unwrap();
    let enc = BlockEncoder::encode(64, InstructionBlock::new(&insts, base), BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("[26] encode failed: {}", e))?;
    let native = enc.code_buffer;

    let n = 5u32;
    let incr = 3u64;
    let want = (incr * n as u64) + 5;

    // 1) Native x86 reference.
    let mut narena = Arena::new(0x8000)?;
    let ncode = narena.base + 0x3000;
    let ncall = narena.base + 0x4000;
    let ndata = narena.base + 0x2000;
    { let b = narena.bytes(); b[0x3000..0x3000 + native.len()].copy_from_slice(&native); }
    let stub = {
        use iced_x86::{BlockEncoder, BlockEncoderOptions, InstructionBlock};
        let s = [
            Instruction::with2(Code::Mov_r64_imm64, Register::RCX, n as u64).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, Register::RBX, incr).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, Register::RSI, ndata as u64).unwrap(),
            Instruction::with_branch(Code::Call_rel32_64, ncode as u64).unwrap(),
            Instruction::with(Code::Retnq),
        ];
        BlockEncoder::encode(64, InstructionBlock::new(&s, ncall as u64), BlockEncoderOptions::NONE)
            .map_err(|e| anyhow!("[26] stub encode failed: {}", e))?.code_buffer
    };
    { let b = narena.bytes(); b[0x4000..0x4000 + stub.len()].copy_from_slice(&stub); }
    let native_rax = narena.call_u64(0x4000);
    assert_eq!(native_rax, want, "[26] native reference self-consistency (got {} want {})", native_rax, want);

    // 2) Lift the whole reachable CFG to a single VM program.
    let lift = lift_program_cfg(&native, base, base, &[], 0, &[])?;
    let bc = &lift.bytecode;
    assert!(!bc.is_empty(), "[26] whole-CFG lift empty");
    assert!(lift.unsupported.is_empty(), "[26] unexpected unsupported {:?}", lift.unsupported);
    let halt_off = (bc.len() - 1) as u64;

    // 3) Interpreter run.
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x4000];
    st[interp::STATE_VREGS + 1*8..][..8].copy_from_slice(&(n as u64).to_le_bytes());
    st[interp::STATE_VREGS + 3*8..][..8].copy_from_slice(&incr.to_le_bytes());
    st[interp::STATE_VREGS + 4*8..][..8].copy_from_slice(&0x3FF8u64.to_le_bytes()); // v4 = RSP (arch stack top)
    // Two-stack model: init the dedicated VM return-IP stack and pre-place the
    // outermost return ip (-> trailing HALT) on it.
    st[interp::STATE_PTR_CALL_STACK..interp::STATE_PTR_CALL_STACK + 8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_CALL_SP..interp::STATE_CALL_SP + 8].copy_from_slice(&((interp::CALL_STACK_SIZE - 8) as u64).to_le_bytes());
    mem[(interp::CALL_STACK_SIZE - 8) as usize..interp::CALL_STACK_SIZE].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, bc).map_err(|e| anyhow!("[26] interp failed: {:?}", e))?;
    let interp_rax = u64::from_le_bytes(st[interp::STATE_VREGS+0*8..][..8].try_into().unwrap());
    assert_eq!(interp_rax, want, "[26] lifted interpreter: rax got {} want {}", interp_rax, want);

    // 4) Native VM execution of the lifted program (the M6 Phase-2 dispatch path).
    let mut varena = Arena::new(0x40000)?;
    let (vc, vt, vb, vs, vsz, vtr, vdata) = (
        varena.base + 0x1000, varena.base + 0x5800, varena.base + 0x5000,
        varena.base + 0x6000, varena.base + 0x7000, varena.base + 0x8000, varena.base + 0x9000,
    );
    let module = build_vm_module(vc as u64, vt as u64, vb as u64, bc.clone(), handlers::EntryMode::Ksa)?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vs as u64, vdata as u64, vdata as u64, vc as u64, vtr as u64)?;
    let call_stack_va = varena.base + 0xA000; // dedicated VM bytecode return-IP stack (two-stack)
    {
        let b = varena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x5800..0x5800 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
        b[0x5000..0x5000 + bc.len()].copy_from_slice(bc);
        b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
        b[0x6000 + interp::STATE_VREGS + 1*8..][..8].copy_from_slice(&(n as u64).to_le_bytes());
        b[0x6000 + interp::STATE_VREGS + 3*8..][..8].copy_from_slice(&incr.to_le_bytes());
        b[0x6000 + interp::STATE_VREGS + 4*8..][..8].copy_from_slice(&((vsz as u64) + 0xFF8).to_le_bytes());
        b[0x7000..0x7000 + 0x1000].fill(0);
        // Two-stack model: init the dedicated VM return-IP stack and pre-place the
        // outermost return ip (absolute VA of trailing HALT) on it.
        b[0x6000 + interp::STATE_PTR_CALL_STACK..0x6000 + interp::STATE_PTR_CALL_STACK + 8]
            .copy_from_slice(&(call_stack_va as u64).to_le_bytes());
        b[0x6000 + interp::STATE_CALL_SP..0x6000 + interp::STATE_CALL_SP + 8]
            .copy_from_slice(&((interp::CALL_STACK_SIZE - 8) as u64).to_le_bytes());
        b[(0xA000 + (interp::CALL_STACK_SIZE - 8)) as usize..0xA000 + interp::CALL_STACK_SIZE]
            .copy_from_slice(&((vb as u64) + halt_off).to_le_bytes());
        b[0x9000..0x9000 + 0x100].fill(0);
    }
    varena.call(0x8000);
    let b = varena.bytes();
    let vm_rax = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS + 0*8..][..8].try_into().unwrap());
    assert_eq!(vm_rax, want, "[26] native VM program execution: rax got {} want {}", vm_rax, want);

    Ok(())
}
