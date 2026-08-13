// ==============================================================================
// VM self-test submodule: multiblock.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use anyhow::{Result, anyhow};
use crate::vm::{bytecode, interp, lifter};
use crate::vm::lifter::{LiftedInstr};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};



/// [19] M5 multi-block control-flow lift.
/// Builds a loop function, extracts its CFG, lifts with `lift_cfg` (which emits
/// rel32 cross-block branches + block connection), and verifies the interpreter
/// result matches the Rust reference. (Native-harness path is exercised by [14].
/// Here we validate the *multi-block* driver itself through the interpreter.)
pub(crate) fn run_m5_multiblock_test() -> Result<()> {
    use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};
    use crate::graph::CfgExtractor;
    use crate::vm::lifter::lift_cfg;

    // f(): rcx=n, rbx=incr. rax=0; rdx=0 (i).
    //   loop: cmp rdx, rcx ; jge done ; add rax,rbx ; inc rdx ; jmp loop
    //   done: ret
    let base = 0x1000u64;

    // Build the 8 instructions first (branch targets filled below).
    let mut insts: Vec<Instruction> = Vec::new();
    insts.push(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0).unwrap());
    insts.push(Instruction::with2(Code::Mov_r32_imm32, Register::EDX, 0).unwrap());
    insts.push(Instruction::with2(Code::Cmp_rm64_r64, Register::RDX, Register::RCX).unwrap());
    insts.push(Instruction::with_branch(Code::Jge_rel8_64, base).unwrap());   // patched below
    insts.push(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RBX).unwrap());
    insts.push(Instruction::with1(Code::Inc_rm64, Register::RDX).unwrap());
    insts.push(Instruction::with_branch(Code::Jmp_rel8_64, base).unwrap());   // patched below
    insts.push(Instruction::with(Code::Retnq));

    // Instruction::len() returns 0 until an instruction is encoded, so we can't
    // derive the branch targets from it (both used to come out as `base`, which
    // made every back-edge point at the function entry -> the lifted loop reset
    // v0/v2 every iteration and hung). Encode once (the rel8/rel32 encodings and
    // layout are independent of the target value) and decode to discover the real
    // IP of every instruction. That yields the true loop head and done addresses.
    let probe = BlockEncoder::encode(
        64,
        InstructionBlock::new(&insts, base),
        BlockEncoderOptions::NONE,
    )
    .map_err(|e| anyhow!("M5 probe encode failed: {}", e))?;
    let mut dec = iced_x86::Decoder::with_ip(64, &probe.code_buffer, base, iced_x86::DecoderOptions::NONE);
    let mut loop_start = base;
    let mut done_start = base;
    while dec.can_decode() {
        let i = dec.decode();
        if i.code() == Code::Cmp_rm64_r64 { loop_start = i.ip(); }
        if i.code() == Code::Retnq { done_start = i.ip(); }
    }

    // Re-encode with the correct absolute branch targets.
    insts[3] = Instruction::with_branch(Code::Jge_rel8_64, done_start).unwrap();
    insts[6] = Instruction::with_branch(Code::Jmp_rel8_64, loop_start).unwrap();
    let enc = BlockEncoder::encode(64, InstructionBlock::new(&insts, base), BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("M5 native encode failed: {}", e))?;
    let native = enc.code_buffer;


    let n = 7u32;
    let incr = 3u64;
    let want = incr * n as u64;

    // CFG extract + lift_cfg
    let (blocks, _g) = CfgExtractor::extract(&native, base, base, &[], 0)?;
    eprintln!("[19] blocks={} starts={:?}", blocks.len(), blocks.iter().map(|b| b.start_va).collect::<Vec<_>>());
    assert!(blocks.len() >= 3, "M5 CFG expected >=3 blocks, got {}", blocks.len());
    let bc = lift_cfg(&blocks)?;
    eprintln!("[19] lift_cfg len={}", bc.len());
    for line in crate::vm::bytecode::disassemble(&bc).lines() {
        eprintln!("[19]   {}", line);
    }
    assert!(!bc.is_empty(), "M5 lift_cfg returned empty");

    // Interpreter run with rcx=n, rbx=incr.
    let halt_off = (bc.len() - 1) as u64;
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x4000];
    st[interp::STATE_VREGS + 0*8..][..8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_VREGS + 1*8..][..8].copy_from_slice(&(n as u64).to_le_bytes());
    st[interp::STATE_VREGS + 2*8..][..8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_VREGS + 3*8..][..8].copy_from_slice(&incr.to_le_bytes());
    st[interp::STATE_VREGS + 4*8..][..8].copy_from_slice(&0x3FF8u64.to_le_bytes()); // v4 = RSP (arch stack top)
    // Two-stack model: init the dedicated VM return-IP stack and pre-place the
    // outermost return ip (-> trailing HALT) on it.
    st[interp::STATE_PTR_CALL_STACK..interp::STATE_PTR_CALL_STACK + 8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_CALL_SP..interp::STATE_CALL_SP + 8].copy_from_slice(&((interp::CALL_STACK_SIZE - 8) as u64).to_le_bytes());
    mem[(interp::CALL_STACK_SIZE - 8) as usize..interp::CALL_STACK_SIZE].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("M5 interp failed: {:?}", e))?;
    let rax = u64::from_le_bytes(st[interp::STATE_VREGS + 0*8..][..8].try_into().unwrap());
    assert_eq!(rax, want, "M5 lifted interpreter: rax got {} want {}", rax, want);

    Ok(())
}


/// [24] B-3 (v35): switch/테이블 점프 → VM 내부 디스패치.
/// A compiler switch jump table `jmp [rax*8 + table]` (Jmp_rm64, memory target) is
/// resolved to (case_value, target_block_va) pairs and dispatched *inside the VM* via
/// a compare-and-jump chain (lift_cfg_switch). Runs the interpreter for each case value
/// and verifies it reaches the correct case block — proving switch jumps no longer leave
/// the VM through the native bridge. The chain uses only mov/cmp/jcc32 (all proven native),
/// so interpreter correctness implies the native VM path.
pub(crate) fn run_switch_lift_test() -> Result<()> {
    use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};
    use crate::graph::CfgExtractor;
    use crate::vm::lifter::lift_cfg_switch;

    // f(edi=index): jmp [rax*8 + table] dispatch to one of the case blocks.
    let base = 0x1000u64;
    let mut insts: Vec<Instruction> = Vec::new();
    insts.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EDI).unwrap()); // index
    insts.push(Instruction::with1(Code::Jmp_rm64, MemoryOperand::with_base_index_scale_displ_size(Register::None, Register::RAX, 8, 0x1000, 8)).unwrap()); // switch jmp
    // case blocks (distinct results)
    insts.push(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0x100).unwrap()); // case0
    insts.push(Instruction::with(Code::Retnq));
    insts.push(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0x200).unwrap()); // case1
    insts.push(Instruction::with(Code::Retnq));
    insts.push(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0x300).unwrap()); // case2
    insts.push(Instruction::with(Code::Retnq));
    insts.push(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0x999).unwrap()); // default
    insts.push(Instruction::with(Code::Retnq));

    let probe = BlockEncoder::encode(64, InstructionBlock::new(&insts, base), BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("[24] probe encode failed: {}", e))?;
    let mut dec = iced_x86::Decoder::with_ip(64, &probe.code_buffer, base, iced_x86::DecoderOptions::NONE);
    let mut jmp_va = 0u64;
    let mut case_vas = [0u64; 4];
    while dec.can_decode() {
        let i = dec.decode();
        if i.code() == Code::Jmp_rm64 { jmp_va = i.ip(); }
        if i.code() == Code::Mov_r32_imm32 {
            let idx = i.immediate32();
            match idx {
                0x100 => case_vas[0] = i.ip(),
                0x200 => case_vas[1] = i.ip(),
                0x300 => case_vas[2] = i.ip(),
                0x999 => case_vas[3] = i.ip(),
                _ => {}
            }
        }
    }
    let native = probe.code_buffer;
    assert_ne!(jmp_va, 0, "[24] switch jmp not found");
    assert!(case_vas.iter().all(|&v| v != 0), "[24] case blocks not found: {:?}", case_vas);

    // Lift the whole CFG with resolved switch cases.
    let (blocks, _g) = CfgExtractor::extract(&native, base, base, &[], 0)?;
    let switch_cases = vec![(jmp_va, vec![
        (0i64, case_vas[0]),
        (1i64, case_vas[1]),
        (2i64, case_vas[2]),
        (3i64, case_vas[3]), // default case block
    ])];
    let bc = lift_cfg_switch(&blocks, &switch_cases, &std::collections::HashMap::new(), None, &Default::default())?;
    let bad = crate::vm::lifter::diagnose_unsupported(&{
        use crate::vm::{bytecode, handlers, import_key, interp, ksa, lifter, prga};
use crate::vm::lifter::LiftedInstr;
        blocks.iter()
            .flat_map(|b| b.instructions.iter().map(|i| LiftedInstr::plain(*i)))
            .collect::<Vec<_>>()
    });
    // Jmp_rm64 is intentionally lowered (bridge/switch), not "unsupported".
    let bad = bad.into_iter().filter(|(_, c)| *c != Code::Jmp_rm64).collect::<Vec<_>>();
    assert!(bad.is_empty(), "[24] unexpected unsupported {:?}", bad);

    // Run interpreter for each case value.
    let expect = [0x100u64, 0x200, 0x300, 0x999]; // index 0,1,2, default(3+)
    for (idx, want) in expect.iter().enumerate() {
        let halt_off = (bc.len() - 1) as u64;
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x4000];
        st[interp::STATE_VREGS + 7*8..][..8].copy_from_slice(&(idx as u64).to_le_bytes()); // edi=index
        // Two-stack model: init the dedicated VM return-IP stack and pre-place the
        // outermost return ip (-> trailing HALT) on it.
        st[interp::STATE_VREGS + 4*8..][..8].copy_from_slice(&0x3FF8u64.to_le_bytes()); // v4 = RSP (arch stack top)
        st[interp::STATE_PTR_CALL_STACK..interp::STATE_PTR_CALL_STACK+8].copy_from_slice(&0u64.to_le_bytes());
        st[interp::STATE_CALL_SP..interp::STATE_CALL_SP+8].copy_from_slice(&((interp::CALL_STACK_SIZE - 8) as u64).to_le_bytes());
        mem[(interp::CALL_STACK_SIZE - 8) as usize..interp::CALL_STACK_SIZE].copy_from_slice(&halt_off.to_le_bytes());
        interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("[24] interp idx={} failed: {:?}", idx, e))?;
        let rax = u64::from_le_bytes(st[interp::STATE_VREGS+0*8..][..8].try_into().unwrap());
        assert_eq!(rax, *want, "[24] switch dispatch idx={}: rax got 0x{:X} want 0x{:X}", idx, rax, want);
    }

    Ok(())
}
