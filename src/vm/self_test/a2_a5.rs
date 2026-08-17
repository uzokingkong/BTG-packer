// ==============================================================================
// VM self-test submodule: a2_a5.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use rand::RngCore;
use anyhow::{Result, anyhow};
use crate::vm::{bytecode, handlers, interp};
use crate::vm::lifter::{LiftedInstr};
use iced_x86::{Code, Instruction, MemoryOperand, Register};
use crate::vm::{build_vm_module};
use crate::vm::arena::{Arena};
use crate::vm::encode::{encode_trampoline};



/// A-2/A-5 self-test: OR/NEG/NOT, 64-bit shifts, NOP (v25 opcodes).
/// Cross-checks the Rust interpreter against the native x86-64 handlers for
/// every new opcode, and exercises the lifter's diagnose_unsupported (A-5).
pub(crate) fn run_a2_a5_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::flags;

    let mut rng = rand::thread_rng();
    let pairs32: Vec<(u32, u32)> = (0..24).map(|_| (rng.next_u32(), rng.next_u32())).collect();
    let pairs64: Vec<(u64, u64)> = (0..12).map(|_| (rng.next_u64(), rng.next_u64())).collect();

    let mut arena = Arena::new(0x30000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x5800;
    let bc_va = arena.base + 0x5000;
    let state_va = arena.base + 0x6000;
    let tramp_va = arena.base + 0x7000;
    let module = build_vm_module(
        code_va as u64,
        table_va as u64,
        bc_va as u64,
        vec![0u8; 128],
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(
        state_va as u64, code_va as u64, code_va as u64, code_va as u64, tramp_va as u64,
    )?;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x5800..0x5800 + module.table.len()].copy_from_slice(&module.table);
        b[0x7000..0x7000 + tramp.len()].copy_from_slice(&tramp);
    }

    let mut run_prog = |prog: &[u8]| -> (u64, [u64; 16]) {
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 16];
        interp::interpret(&mut st, &mut mem, prog).unwrap();
        let flags_i = u64::from_le_bytes(st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8].try_into().unwrap());
        let mut vregs_i = [0u64; 16];
        for i in 0..16 {
            vregs_i[i] = u64::from_le_bytes(st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
        }
        {
            let b = arena.bytes();
            b[0x5000..0x5000 + prog.len()].copy_from_slice(prog);
            b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
        }
        arena.call(0x7000);
        let b = arena.bytes();
        let sf = 0x6000usize;
        let flags_n = u64::from_le_bytes(b[sf + interp::STATE_FLAGS..sf + interp::STATE_FLAGS + 8].try_into().unwrap());
        let mut vregs_n = [0u64; 16];
        for i in 0..16 {
            vregs_n[i] = u64::from_le_bytes(b[sf + interp::STATE_VREGS + i * 8..sf + interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
        }
        assert_eq!(flags_i, flags_n, "A2 interp vs native flags mismatch\n{}", crate::vm::bytecode::disassemble(prog));
        assert_eq!(vregs_i, vregs_n, "A2 interp vs native vregs mismatch\n{}", crate::vm::bytecode::disassemble(prog));
        (flags_i, vregs_i)
    };

    for &(a, b) in &pairs32 {
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(0, a);
        bc.mov_r_imm32(1, b);
        bc.binop_r_r(OP_OR_R_R, 0, 1);
        bc.halt();
        let (got, v) = run_prog(&bc.finish());
        assert_eq!(got & FLAG_MASK, flags::logical_flags(a | b) & FLAG_MASK, "OR32 flags a=0x{:X} b=0x{:X}", a, b);
        assert_eq!(v[0], (a | b) as u64, "OR32 result");
    }
    for &(a, b) in &pairs32 {
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(0, a);
        bc.binop_r_imm32(OP_OR_R_IMM32, 0, b);
        bc.halt();
        let (got, v) = run_prog(&bc.finish());
        assert_eq!(got & FLAG_MASK, flags::logical_flags(a | b) & FLAG_MASK, "ORI32 flags");
        assert_eq!(v[0], (a | b) as u64, "ORI32 result");
    }
    for &(a, b) in &pairs64 {
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(0, a);
        bc.mov_r_imm64(1, b);
        bc.binop_r_r64(OP_OR_R_R64, 0, 1);
        bc.halt();
        let (got, v) = run_prog(&bc.finish());
        assert_eq!(got & FLAG_MASK, flags::logical_flags64(a | b) & FLAG_MASK, "OR64 flags");
        assert_eq!(v[0], a | b, "OR64 result");
    }
    for &(a, b) in &pairs64 {
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(0, a);
        bc.binop_r_imm64(OP_OR_R_IMM64, 0, (b as u32).wrapping_add(0x1111_2222));
        bc.halt();
        let (_, v) = run_prog(&bc.finish());
        let imm = ((b as u32).wrapping_add(0x1111_2222) as i32) as i64 as u64;
        assert_eq!(v[0], a | imm, "ORI64 result a=0x{:X} i=0x{:X}", a, imm);
    }

    for &(a, _) in &pairs32 {
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(0, a);
        bc.neg_r(0);
        bc.halt();
        let (got, v) = run_prog(&bc.finish());
        let res = 0u32.wrapping_sub(a);
        assert_eq!(v[0], res as u64, "NEG32 result a=0x{:X}", a);
        assert_eq!(got & FLAG_MASK, flags::sub_flags(0, a) & FLAG_MASK, "NEG32 flags a=0x{:X}", a);
    }
    for &(a, _) in &pairs64 {
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(0, a);
        bc.neg_r64(0);
        bc.halt();
        let (got, v) = run_prog(&bc.finish());
        let res = 0u64.wrapping_sub(a);
        assert_eq!(v[0], res, "NEG64 result a=0x{:X}", a);
        assert_eq!(got & FLAG_MASK, flags::sub_flags64(0, a) & FLAG_MASK, "NEG64 flags a=0x{:X}", a);
    }

    for &(a, _) in &pairs32 {
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(0, a);
        bc.not_r(0);
        bc.halt();
        let (_, v) = run_prog(&bc.finish());
        assert_eq!(v[0], (!a) as u64, "NOT32 a=0x{:X}", a);
    }
    for &(a, _) in &pairs64 {
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(0, a);
        bc.not_r64(0);
        bc.halt();
        let (_, v) = run_prog(&bc.finish());
        assert_eq!(v[0], !a, "NOT64 a=0x{:X}", a);
    }

    for _ in 0..24 {
        let x = rng.next_u64();
        let n = 1 + (rng.next_u64() & 62);
        for (op, ev, ef) in [
            (OP_SHL64_R_IMM8, x.wrapping_shl(n as u32) as u64, flags::shift_flags64(flags::ShiftKind::Shl, x, n as u32, x.wrapping_shl(n as u32))),
            (OP_SHR64_R_IMM8, x.wrapping_shr(n as u32) as u64, flags::shift_flags64(flags::ShiftKind::Shr, x, n as u32, x.wrapping_shr(n as u32))),
            (OP_SAR64_R_IMM8, ((x as i64) >> n) as u64, flags::shift_flags64(flags::ShiftKind::Sar, x, n as u32, ((x as i64) >> n) as u64)),
        ] {
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm64(0, x);
            bc.shift64_r_imm8(op, 0, n as u8);
            bc.halt();
            let (got, v) = run_prog(&bc.finish());
            assert_eq!(v[0], ev, "SHL64 imm8 op=0x{:02X} x=0x{:X} n={}", op, x, n);
            assert_eq!(got & FLAG_MASK, ef & FLAG_MASK, "SHL64 imm8 flags op=0x{:02X} x=0x{:X} n={}", op, x, n);
        }
        for (op, ev, ef) in [
            (OP_SHL64_R_CL, x.wrapping_shl(n as u32) as u64, flags::shift_flags64(flags::ShiftKind::Shl, x, n as u32, x.wrapping_shl(n as u32))),
            (OP_SHR64_R_CL, x.wrapping_shr(n as u32) as u64, flags::shift_flags64(flags::ShiftKind::Shr, x, n as u32, x.wrapping_shr(n as u32))),
            (OP_SAR64_R_CL, ((x as i64) >> n) as u64, flags::shift_flags64(flags::ShiftKind::Sar, x, n as u32, ((x as i64) >> n) as u64)),
        ] {
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm64(0, x);
            bc.mov_r_imm32(1, n as u32);
            bc.shift64_r_cl(op, 0);
            bc.halt();
            let (got, v) = run_prog(&bc.finish());
            assert_eq!(v[0], ev, "SHL64 CL op=0x{:02X} x=0x{:X} n={}", op, x, n);
            assert_eq!(got & FLAG_MASK, ef & FLAG_MASK, "SHL64 CL flags op=0x{:02X} x=0x{:X} n={}", op, x, n);
        }
    }

    {
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(0, 0x1234_5678);
        bc.nop();
        bc.nop();
        bc.mov_r_imm32(1, 0x9ABC_DEF0);
        bc.halt();
        let (_, v) = run_prog(&bc.finish());
        assert_eq!((v[0], v[1]), (0x1234_5678u64, 0x9ABC_DEF0u64), "NOP skipped ops");
    }

    {
        use crate::vm::lifter::{LiftedInstr, lift_block, diagnose_unsupported};
        let mut seq: Vec<LiftedInstr> = Vec::new();
        seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::ECX).unwrap()));
        seq.push(LiftedInstr::plain(Instruction::with2(Code::Or_rm32_r32, Register::EAX, Register::EDX).unwrap()));
        seq.push(LiftedInstr::plain(Instruction::with1(Code::Neg_rm32, Register::EAX).unwrap()));
        seq.push(LiftedInstr::plain(Instruction::with2(Code::Shl_rm64_imm8, Register::RAX, 3).unwrap()));
        seq.push(LiftedInstr::plain(Instruction::with(Code::Nopw)));
        seq.push(LiftedInstr::plain(Instruction::with(Code::Retnq)));
        let bad = diagnose_unsupported(&seq);
        assert!(bad.is_empty(), "A5 diagnose: unexpected unsupported {:?}", bad);
        let bc = lift_block(&seq, 0)?;
        assert!(!bc.is_empty(), "A5 lift produced empty bytecode");

        // ADDSS became supported in v54 (Group A), so the negative-diagnostic
        // probe uses SQRTSS — an SSE FP op still outside the lift table.
        let mut bad_seq: Vec<LiftedInstr> = Vec::new();
        bad_seq.push(LiftedInstr::plain(Instruction::with2(Code::Sqrtss_xmm_xmmm32, Register::XMM0, Register::XMM1).unwrap()));
        let bad2 = diagnose_unsupported(&bad_seq);
        assert!(!bad2.is_empty(), "A5 diagnose should flag FP op");
        let lift_err = lift_block(&bad_seq, 0);
        assert!(lift_err.is_err(), "A5 lift of FP op should fail loudly");
    }

    Ok(())
}


/// v26 (A-2/A-5): self-test for the completed 1:1 lift table.
/// Exercises the newly-supported common forms (reg-reg MOV via the r/m opcodes,
/// imm arithmetic 8/32/64, CMP reg-reg/imm with full SUB flags, TEST 64/16/8,
/// LEA32, MOVZX-reg, MOVSXD, CDQE, PUSH/POP) by lifting a straight-line + one-Jcc
/// function and verifying the interpreter result against a Rust reference. The
/// emulations reuse only already-native-proven opcodes, so the interpreter result
/// implies the native VM path is correct too.
pub(crate) fn run_a2_lift_completion_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::lifter::{LiftedInstr, lift_block, diagnose_unsupported};

    const SKIP: u32 = 99;
    let mut seq: Vec<LiftedInstr> = Vec::new();
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::ECX).unwrap())); // eax = a
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Add_rm32_imm8, Register::EAX, 0x20).unwrap()));          // eax += 0x20 (imm8)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Movsxd_r64_rm32, Register::RDX, Register::EAX).unwrap())); // rdx = sext(eax)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Sub_rm64_imm8, Register::RDX, 0x10).unwrap()));           // rdx -= 0x10 (imm8 -> add -0x10)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::And_rm64_imm8, Register::RDX, 0x3F).unwrap()));           // rdx &= 0x3F (imm8)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Lea_r32_m, Register::R8D, MemoryOperand::with_base_displ(Register::RCX, -1)).unwrap())); // r8 = rcx - 1
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Movzx_r32_rm8, Register::EDI, Register::CL).unwrap()));   // edi = cl (movzx reg)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Cmp_rm64_r64, Register::RAX, Register::RDX).unwrap()));   // cmp rax, rdx (full flags)
    seq.push(LiftedInstr::branch(Instruction::with_branch(Code::Jg_rel32_64, 0).unwrap(), SKIP));                  // jg SKIP (taken: rax>rdx)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0).unwrap()));              // eax = 0 (skipped)
    seq.push(LiftedInstr::labeled(Instruction::with1(Code::Push_r64, Register::RDX).unwrap(), SKIP));              // SKIP: push rdx
    seq.push(LiftedInstr::plain(Instruction::with1(Code::Pop_r64, Register::R9).unwrap()));                        // pop r9 (r9 = rdx)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Test_rm64_r64, Register::RBX, Register::RBX).unwrap()));  // test rbx, rbx
    seq.push(LiftedInstr::plain(Instruction::with(Code::Cdqe)));                                                   // rax = sext(eax)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Add_rm32_imm8, Register::EAX, 5).unwrap()));              // eax += 5
    seq.push(LiftedInstr::plain(Instruction::with(Code::Retnq)));

    // All of these must now be liftable (diagnose must be empty).
    let bad = diagnose_unsupported(&seq);
    assert!(bad.is_empty(), "A2-lift-completion: unexpected unsupported {:?}", bad);

    let a = 3u32;
    // eax = a + 0x20 = 0x23 ; rdx = sext(0x23)=0x23 -0x10 =0x13 &0xFF =0x13
    // jg taken (rax=0x23 > rdx=0x13) -> mov eax,0 skipped ; push/pop r9=rdx=0x13
    // cdqe rax=sext(0x23)=0x23 ; +5 -> 0x28
    let expected_rax = (a.wrapping_add(0x20)).wrapping_add(5) as u64; // 0x28
    let expected_r9 = ((a.wrapping_add(0x20)).wrapping_sub(0x10) & 0xFF) as u64; // 0x13

    let bc = lift_block(&seq, 0)?;
    let halt_off = (bc.len() - 1) as u64;
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x4000];
    st[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].copy_from_slice(&0u64.to_le_bytes()); // rax
    st[interp::STATE_VREGS + 1 * 8..interp::STATE_VREGS + 2 * 8].copy_from_slice(&(a as u64).to_le_bytes()); // rcx = a
    st[interp::STATE_VREGS + 3 * 8..interp::STATE_VREGS + 4 * 8].copy_from_slice(&0u64.to_le_bytes()); // rbx = 0
    st[interp::STATE_VREGS + 4 * 8..interp::STATE_VREGS + 5 * 8].copy_from_slice(&0x3FF8u64.to_le_bytes()); // vreg4 = RSP (stack top)
    // Two-stack model: init the dedicated VM return-IP stack and pre-place the
    // outermost return ip (-> trailing HALT) on it.
    st[interp::STATE_PTR_CALL_STACK..interp::STATE_PTR_CALL_STACK + 8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_CALL_SP..interp::STATE_CALL_SP + 8].copy_from_slice(&((interp::CALL_STACK_SIZE - 8) as u64).to_le_bytes());
    mem[(interp::CALL_STACK_SIZE - 8) as usize..interp::CALL_STACK_SIZE].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("A2-lift-completion interp failed: {:?}", e))?;
    let rax = u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    let r9 = u64::from_le_bytes(st[interp::STATE_VREGS + 9 * 8..interp::STATE_VREGS + 10 * 8].try_into().unwrap());
    assert_eq!(rax, expected_rax, "A2-lift-completion: rax mismatch (got 0x{:X} want 0x{:X})", rax, expected_rax);
    assert_eq!(r9, expected_r9, "A2-lift-completion: r9 mismatch (got 0x{:X} want 0x{:X})", r9, expected_r9);
    Ok(())
}


/// [21] A-2/A-5 잔여 (v32): 8/16-bit arithmetic + JCXZ/JECXZ + rep movs/cmps.
/// Lifts a block exercising the new narrow-arith lowerings and a JCXZ branch, runs
/// it through the reference interpreter, and compares against a Rust reference.
/// Then lifts and runs `rep movsd`/`rep cmpsd` against memory and verifies the
/// copy / compare result. Because all new lowerings reuse already-native-proven
/// opcodes (ADD/SUB/XOR/AND/OR + movzx/mov + jcc), interpreter correctness implies
/// the native VM path is correct too.
pub(crate) fn run_a2a5_lift_residual_test() -> Result<()> {
    use iced_x86::{Code, Instruction, Register};
    use crate::vm::bytecode::*;
    use crate::vm::lifter::{LiftedInstr, lift_block, diagnose_unsupported};

    // ── Part A: 8/16-bit arithmetic + JCXZ ─────────────────────────────────
    let mut seq: Vec<LiftedInstr> = Vec::new();
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0x10).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Add_rm8_imm8, Register::AL, 0x05).unwrap()));      // al=0x15
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_r32_imm32, Register::EBX, 0x0F).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Add_rm8_r8, Register::AL, Register::BL).unwrap())); // al=0x24
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Sub_rm8_imm8, Register::AL, 0x01).unwrap()));       // al=0x23
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0x1234).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Add_rm16_imm16, Register::CX, 0x0021).unwrap()));   // cx=0x1255
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_r32_imm32, Register::EDX, 0x0100).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Sub_rm16_r16, Register::CX, Register::DX).unwrap()));// cx=0x1155
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Xor_rm8_imm8, Register::AL, 0x0F).unwrap()));       // al=0x2C
    seq.push(LiftedInstr::plain(Instruction::with2(Code::And_rm16_imm16, Register::CX, 0x00FF).unwrap()));  // cx=0x0055
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Or_rm8_imm8, Register::AL, 0x80).unwrap()));        // al=0xAC
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 0x00FF).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Or_rm16_imm16, Register::R8W, 0x0F00).unwrap()));   // r8w=0x0FFF
    // JCXZ: rcx=0 → branch taken, skip the add
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Xor_r32_rm32, Register::ECX, Register::ECX).unwrap())); // rcx=0
    let skip = 50u32;
    seq.push(LiftedInstr::branch(Instruction::with_branch(Code::Jrcxz_rel8_64, 0).unwrap(), skip));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Add_rm32_imm8, Register::EAX, 1).unwrap()));          // skipped
    seq.push(LiftedInstr::labeled(Instruction::with(Code::Retnq), skip));
    let bad = diagnose_unsupported(&seq);
    assert!(bad.is_empty(), "[21] unexpected unsupported {:?}", bad);
    let bc = lift_block(&seq, 0)?;
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x4000];
    st[interp::STATE_VREGS + 4*8..][..8].copy_from_slice(&0x3FF8u64.to_le_bytes()); // v4 = RSP (arch stack top)
    // Two-stack model: init the dedicated VM return-IP stack and pre-place the
    // outermost return ip (-> trailing HALT) on it.
    let halt_off = (bc.len() - 1) as u64;
    st[interp::STATE_PTR_CALL_STACK..interp::STATE_PTR_CALL_STACK + 8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_CALL_SP..interp::STATE_CALL_SP + 8].copy_from_slice(&((interp::CALL_STACK_SIZE - 8) as u64).to_le_bytes());
    mem[(interp::CALL_STACK_SIZE - 8) as usize..interp::CALL_STACK_SIZE].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("[21] interp failed: {:?}", e))?;
    let rax = u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..][..8].try_into().unwrap());
    let rcx = u64::from_le_bytes(st[interp::STATE_VREGS + 1 * 8..][..8].try_into().unwrap());
    let r8 = u64::from_le_bytes(st[interp::STATE_VREGS + 8 * 8..][..8].try_into().unwrap());
    assert_eq!(rax & 0xFF, 0xAC, "[21] 8-bit arithmetic al mismatch (got 0x{:X})", rax & 0xFF);
    assert_eq!(rax & 0xFFFF_FFFF, 0xAC, "[21] jcxz should skip the add (rax=0x{:X})", rax);
    assert_eq!(rcx & 0xFFFF, 0x00, "[21] rcx should be 0 after jcxz (got 0x{:X})", rcx);
    assert_eq!(r8 & 0xFFFF, 0x0FFF, "[21] 16-bit or mismatch (r8w=0x{:X})", r8 & 0xFFFF);

    // ── Part B: rep movsd (mem copy) ───────────────────────────────────────
    // iced-x86 does not support Instruction::with() for MOVS/CMPS (implicit [rdi]/[rsi]
    // operands). Decode from the raw opcode bytes instead (F3 = REP prefix;
    // a bare MOVSD without REP copies a single dword).
    let mseq = {
        use iced_x86::{Decoder, DecoderOptions};
        let raw = [0xF3u8, 0xA5]; // REP MOVSD m32, m32 (64-bit mode)
        let mut dec = Decoder::with_ip(64, &raw, 0, DecoderOptions::NONE);
        [LiftedInstr::plain(dec.decode())]
    };
    let mbc = lift_block(&mseq, 0)?;
    let src = 0x1000usize;
    let dst = 0x2000usize;
    let count = 4u64;
    let mut stm = vec![0u8; interp::STATE_SIZE];
    let mut mm = vec![0u8; 0x4000];
    for i in 0..count {
        mm[src + (i as usize) * 4..src + (i as usize) * 4 + 4].copy_from_slice(&((i as u32) * 0x11223344).to_le_bytes());
    }
    stm[interp::STATE_VREGS + 6 * 8..][..8].copy_from_slice(&(src as u64).to_le_bytes()); // rsi
    stm[interp::STATE_VREGS + 7 * 8..][..8].copy_from_slice(&(dst as u64).to_le_bytes()); // rdi
    stm[interp::STATE_VREGS + 1 * 8..][..8].copy_from_slice(&count.to_le_bytes());        // rcx
    stm[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK + 8].copy_from_slice(&0x3000u64.to_le_bytes());
    stm[interp::STATE_SP..interp::STATE_SP + 8].copy_from_slice(&0xFF8u64.to_le_bytes());
    mm[0x3000 + 0xFF8..0x3000 + 0x1000].copy_from_slice(&((mbc.len() - 1) as u64).to_le_bytes());
    interp::interpret(&mut stm, &mut mm, &mbc).map_err(|e| anyhow!("[21] rep movsd interp failed: {:?}", e))?;
    for i in 0..count {
        let expect = (i as u32) * 0x11223344;
        let got = u32::from_le_bytes(mm[dst + (i as usize) * 4..dst + (i as usize) * 4 + 4].try_into().unwrap());
        assert_eq!(got, expect, "[21] rep movsd copy[{}] mismatch (got 0x{:X})", i, got);
    }

    // ── Part C: rep cmpsd (matching → rcx=0; mismatch → stops early) ───────
    let cseq = {
        use iced_x86::{Decoder, DecoderOptions};
        let raw = [0xF3u8, 0xA7]; // REPE CMPSD m32, m32 (64-bit mode)
        let mut dec = Decoder::with_ip(64, &raw, 0, DecoderOptions::NONE);
        [LiftedInstr::plain(dec.decode())]
    };
    let cbc = lift_block(&cseq, 0)?;
    let run_cmps = |a_off: usize, b_off: usize, n: u64, mut mem_data: &mut [u8]| -> u64 {
        let mut stc = vec![0u8; interp::STATE_SIZE];
        stc[interp::STATE_VREGS + 6 * 8..][..8].copy_from_slice(&(a_off as u64).to_le_bytes());
        stc[interp::STATE_VREGS + 7 * 8..][..8].copy_from_slice(&(b_off as u64).to_le_bytes());
        stc[interp::STATE_VREGS + 1 * 8..][..8].copy_from_slice(&n.to_le_bytes());
        stc[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK + 8].copy_from_slice(&0x3000u64.to_le_bytes());
        stc[interp::STATE_SP..interp::STATE_SP + 8].copy_from_slice(&0xFF8u64.to_le_bytes());
        mem_data[0x3000 + 0xFF8..0x3000 + 0x1000].copy_from_slice(&((cbc.len() - 1) as u64).to_le_bytes());
        interp::interpret(&mut stc, &mut mem_data, &cbc).unwrap();
        u64::from_le_bytes(stc[interp::STATE_VREGS + 1 * 8..][..8].try_into().unwrap())
    };
    let mut mc = vec![0u8; 0x4000];
    for i in 0..4usize {
        mc[0x3000 + i * 4..0x3000 + i * 4 + 4].copy_from_slice(&((i as u32) * 0x11111111).to_le_bytes());
        mc[0x3100 + i * 4..0x3100 + i * 4 + 4].copy_from_slice(&((i as u32) * 0x11111111).to_le_bytes());
    }
    let rem_match = run_cmps(0x3000, 0x3100, 4, &mut mc);
    assert_eq!(rem_match, 0, "[21] rep cmpsd match: rcx should reach 0 (got {})", rem_match);
    // mismatch at element 1
    mc[0x3100 + 1 * 4..0x3100 + 1 * 4 + 4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
    let rem_mis = run_cmps(0x3000, 0x3100, 4, &mut mc);
    assert_eq!(rem_mis, 2, "[21] rep cmpsd mismatch at elem1: rcx should be 2 (got {})", rem_mis);

    Ok(())
}
