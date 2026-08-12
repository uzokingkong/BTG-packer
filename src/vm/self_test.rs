// ==============================================================================
// VM self-test (--vm-test): cross-checks lifter / interpreter / native handlers.
// ==============================================================================

use super::arena::Arena;
use super::encode::{encode_ksa_native, encode_labeled_block, encode_trampoline, is_branch_code, measure};
use super::{build_program_vm, build_vm_module, build_vm_module_mba, VmModule, VM_STATE_SIZE};
use crate::vm::{bytecode, handlers, import_key, interp, ksa, lifter, prga};
use crate::vm::lifter::LiftedInstr;
use anyhow::{Result, anyhow};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};
use rand::RngCore;

fn run_flags_jcc_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::flags;

    let mut rng = rand::thread_rng();
    let pairs: Vec<(u32, u32)> = (0..24).map(|_| (rng.next_u32(), rng.next_u32())).collect();

    // Reusable native VM module + trampoline in one RWX arena.
    let mut arena = Arena::new(0x30000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x3000;
    let bc_va = arena.base + 0x4000;
    let state_va = arena.base + 0x5000;
    let tramp_va = arena.base + 0x6000;
    let module = build_vm_module(
        code_va as u64,
        table_va as u64,
        bc_va as u64,
        vec![0u8; 64],
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(
        state_va as u64,
        code_va as u64,
        code_va as u64,
        code_va as u64,
        tramp_va as u64,
    )?;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x6000..0x6000 + tramp.len()].copy_from_slice(&tramp);
    }

    // Run `prog` through the interpreter and the native VM; both must agree on
    // the flag slot and all vregs. Returns (flags, vregs).
    let mut run_prog = |prog: &[u8]| -> (u64, [u64; 16]) {
        // interpreter
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 16];
        interp::interpret(&mut st, &mut mem, prog).unwrap();
        let flags_i = u64::from_le_bytes(st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8].try_into().unwrap());
        let mut vregs_i = [0u64; 16];
        for i in 0..16 {
            vregs_i[i] = u64::from_le_bytes(st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
        }
        // native
        {
            let b = arena.bytes();
            b[0x4000..0x4000 + prog.len()].copy_from_slice(prog);
            b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
        }
        arena.call(0x6000);
        let b = arena.bytes();
        let sf = 0x5000usize; // state buffer base within the arena
        let flags_n = u64::from_le_bytes(b[sf + interp::STATE_FLAGS..sf + interp::STATE_FLAGS + 8].try_into().unwrap());
        let mut vregs_n = [0u64; 16];
        for i in 0..16 {
            vregs_n[i] = u64::from_le_bytes(b[sf + interp::STATE_VREGS + i * 8..sf + interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
        }
        assert_eq!(flags_i, flags_n, "interp vs native flags mismatch (interp=0x{:X} native=0x{:X}) prog:\n{}", flags_i, flags_n, crate::vm::bytecode::disassemble(prog));
        assert_eq!(vregs_i, vregs_n, "interp vs native vregs mismatch");
        (flags_i, vregs_i)
    };

    // 1) flag-setting ops (interp == native == flags.rs reference)
    for &(a, b) in &pairs {
        for (op, expect) in [
            (OP_ADD_R_R, flags::add_flags(a, b)),
            (OP_SUB_R_R, flags::sub_flags(a, b)),
            (OP_XOR_R_R, flags::logical_flags(a ^ b)),
            (OP_AND_R_R, flags::logical_flags(a & b)),
        ] {
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.mov_r_imm32(1, b);
            bc.binop_r_r(op, 0, 1);
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, expect & FLAG_MASK, "binop 0x{:02X} a=0x{:X} b=0x{:X}", op, a, b);
        }
        for (op, expect) in [
            (OP_ADD_R_IMM32, flags::add_flags(a, b)),
            (OP_XOR_R_IMM32, flags::logical_flags(a ^ b)),
            (OP_AND_R_IMM32, flags::logical_flags(a & b)),
        ] {
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.binop_r_imm32(op, 0, b);
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, expect & FLAG_MASK, "immop 0x{:02X} a=0x{:X} b=0x{:X}", op, a, b);
        }
        {
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.cmp_r_imm32(0, b);
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, flags::sub_flags(a, b) & FLAG_MASK, "cmp a=0x{:X} b=0x{:X}", a, b);
        }
        {
            let mut bci = BytecodeBuilder::new();
            bci.mov_r_imm32(0, a);
            bci.inc_r(0);
            bci.halt();
            let (got, _) = run_prog(&bci.finish());
            assert_eq!(got & FLAG_MASK, flags::inc_flags(a, 0) & FLAG_MASK, "inc a=0x{:X}", a);

            let mut bcd = BytecodeBuilder::new();
            bcd.mov_r_imm32(0, a);
            bcd.dec_r(0);
            bcd.halt();
            let (got, _) = run_prog(&bcd.finish());
            assert_eq!(got & FLAG_MASK, flags::dec_flags(a, 0) & FLAG_MASK, "dec a=0x{:X}", a);
        }
    }

    // 2) All 16 Jcc conditions (incl. unsigned JA/JBE), with flags baseline = sub(a, b).
    let conds: [u8; 16] = [
        COND_JE, COND_JNE, COND_JB, COND_JAE, COND_JG, COND_JGE, COND_JL, COND_JLE,
        COND_JS, COND_JNS, COND_JO, COND_JNO, COND_JP, COND_JNP, COND_JA, COND_JBE,
    ];
    for &(a, b) in &pairs {
        let base_flags = flags::sub_flags(a, b);
        for (i, c) in conds.iter().enumerate() {
            // One vreg per condition would overflow the 16-vreg file with 16
            // conditions, so build a fresh tiny program per condition: reuse
            // v2 as the output scratch and read it immediately.
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.mov_r_imm32(1, b);
            bc.binop_r_r(OP_SUB_R_R, 0, 1);
            let skip = bc.new_label();
            // v2 = 1 if the condition is taken, else 0:
            //   mov v2, 1 ; jcc8 c, SKIP ; mov v2, 0 ; SKIP:
            bc.mov_r_imm32(2, 1);
            bc.jcc8(*c, skip);
            bc.mov_r_imm32(2, 0);
            bc.mark_label(skip);
            bc.halt();
            let (_, vregs) = run_prog(&bc.finish());
            let expected = if flags::cond_taken(*c, base_flags) { 1u64 } else { 0u64 };
            assert_eq!(vregs[2], expected, "cond {} a=0x{:X} b=0x{:X}", c, a, b);
        }
    }

    // 3) M2: 64-bit arithmetic + shifts + TEST (interp == native == flags::ref)
    {
        let mut rng2 = rand::thread_rng();
        let pairs64: Vec<(u64, u64)> = (0..12).map(|_| (rng2.next_u64(), rng2.next_u64())).collect();
        for &(a, b) in &pairs64 {
            for (op, expect) in [
                (OP_ADD_R_R64, flags::add_flags64(a, b)),
                (OP_SUB_R_R64, flags::sub_flags64(a, b)),
                (OP_XOR_R_R64, flags::logical_flags64(a ^ b)),
                (OP_AND_R_R64, flags::logical_flags64(a & b)),
            ] {
                let mut bc = BytecodeBuilder::new();
                bc.mov_r_imm64(0, a);
                bc.mov_r_imm64(1, b);
                bc.binop_r_r64(op, 0, 1);
                bc.halt();
                let (got, _) = run_prog(&bc.finish());
                assert_eq!(got & FLAG_MASK, expect & FLAG_MASK, "op64 0x{:02X} a=0x{:X} b=0x{:X}", op, a, b);
            }
            let imm32 = (b as u32).wrapping_add(0x1234_5AA5);
            let imm64 = (imm32 as i32) as i64 as u64;
            for (op, expect) in [
                (OP_ADD_R_IMM64, flags::add_flags64(a, imm64)),
                (OP_XOR_R_IMM64, flags::logical_flags64(a ^ imm64)),
                (OP_AND_R_IMM64, flags::logical_flags64(a & imm64)),
            ] {
                let mut bc = BytecodeBuilder::new();
                bc.mov_r_imm64(0, a);
                bc.binop_r_imm64(op, 0, imm32);
                bc.halt();
                let (got, _) = run_prog(&bc.finish());
                assert_eq!(got & FLAG_MASK, expect & FLAG_MASK, "imm64 0x{:02X} a=0x{:X} i=0x{:X}", op, a, imm32);
            }
        }
        // shifts (imm8 and CL); count in 1..=31 (count 0 leaves flags unchanged)
        for _ in 0..40 {
            let x = rng2.next_u32();
            let n = 1 + (rng2.next_u32() & 30);
            let cases: [(u8, u32, u64, u64, u64); 3] = [
                (OP_SHL_R_IMM8, n, x.wrapping_shl(n) as u64, flags::shift_flags(flags::ShiftKind::Shl, x, n, x.wrapping_shl(n)), flags::shift_flags(flags::ShiftKind::Shl, x, n, x.wrapping_shl(n))),
                (OP_SHR_R_IMM8, n, x.wrapping_shr(n) as u64, flags::shift_flags(flags::ShiftKind::Shr, x, n, x.wrapping_shr(n)), 0),
                (OP_SAR_R_IMM8, n, ((x as i32) >> n) as u32 as u64, flags::shift_flags(flags::ShiftKind::Sar, x, n, ((x as i32) >> n) as u32), 0),
            ];
            for (op, cnt, ev, ef, _) in cases {
                let mut bc = BytecodeBuilder::new();
                bc.mov_r_imm32(0, x);
                bc.shift_r_imm8(op, 0, cnt as u8);
                bc.halt();
                let (got, vregs) = run_prog(&bc.finish());
                assert_eq!(vregs[0], ev, "shift imm8 op=0x{:02X} x=0x{:X} n={}", op, x, n);
                assert_eq!(got & FLAG_MASK, ef & FLAG_MASK, "shift imm8 fl op=0x{:02X} x=0x{:X} n={}", op, x, n);
            }
            // CL shifts (count in vreg[1])
            for (op, ev, ef) in [
                (OP_SHL_R_CL, x.wrapping_shl(n) as u64, flags::shift_flags(flags::ShiftKind::Shl, x, n, x.wrapping_shl(n))),
                (OP_SHR_R_CL, x.wrapping_shr(n) as u64, flags::shift_flags(flags::ShiftKind::Shr, x, n, x.wrapping_shr(n))),
                (OP_SAR_R_CL, ((x as i32) >> n) as u32 as u64, flags::shift_flags(flags::ShiftKind::Sar, x, n, ((x as i32) >> n) as u32)),
            ] {
                let mut bc = BytecodeBuilder::new();
                bc.mov_r_imm32(0, x);
                bc.mov_r_imm32(1, n);
                bc.shift_r_cl(op, 0);
                bc.halt();
                let (got, vregs) = run_prog(&bc.finish());
                assert_eq!(vregs[0], ev, "shift cl op=0x{:02X} x=0x{:X} n={}", op, x, n);
                assert_eq!(got & FLAG_MASK, ef & FLAG_MASK, "shift cl fl op=0x{:02X} x=0x{:X} n={}", op, x, n);
            }
        }
        // TEST (rr and imm)
        for _ in 0..16 {
            let (a, b) = (rng2.next_u32(), rng2.next_u32());
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.mov_r_imm32(1, b);
            bc.test_r_r32(0, 1);
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, flags::logical_flags(a & b) & FLAG_MASK, "test rr a=0x{:X} b=0x{:X}", a, b);

            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.test_r_imm32(0, b);
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, flags::logical_flags(a & b) & FLAG_MASK, "test imm a=0x{:X} b=0x{:X}", a, b);
        }
    }

    Ok(())
}

/// M2 self-test: memory width (16/32/64-bit loads incl. sign-extend + stores).
/// Cross-checks the Rust interpreter against the native x86-64 handlers by
/// running the same bytecode in both memory models and comparing every vreg
/// and the mutated memory buffer.
fn run_m2_mem_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut arena = Arena::new(0x20000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x3000;
    let bc_va = arena.base + 0x4000;
    let state_va = arena.base + 0x5000;
    let data_va = arena.base + 0x6000; // S-box memory buffer
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
        state_va as u64,
        data_va as u64,
        data_va as u64,
        code_va as u64,
        tramp_va as u64,
    )?;
    let pat: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x7000..0x7000 + tramp.len()].copy_from_slice(&tramp);
        b[0x6000..0x6008].copy_from_slice(&pat);
    }

    // Bytecode: load widths from offset 0, sign-extend from offset 7/6, then
    // store 16/32/64-bit at offset 0 and reload.
    let mut bc = BytecodeBuilder::new();
    bc.mov_r_imm32(0, 0); // idx0 = 0
    bc.mov_r_imm32(1, 7); // idx1 = 7
    bc.mem_load(OP_MOVZX_R_MEM16, 2, MEM_SBOX, 0); // 0x2211
    bc.mem_load(OP_MOVZX_R_MEM32, 3, MEM_SBOX, 0); // 0x44332211
    bc.mem_load(OP_MOVSX_R_MEM8, 4, MEM_SBOX, 0);  // 0x11
    bc.mem_load(OP_MOVSX_R_MEM16, 5, MEM_SBOX, 0); // 0x2211
    bc.mem_load(OP_MOV_R_MEM64, 6, MEM_SBOX, 0);   // 0x8877665544332211
    bc.mem_load(OP_MOVSX_R_MEM8, 7, MEM_SBOX, 1);  // 0x88 -> sign-extend
    bc.mem_load(OP_MOVSX_R_MEM16, 8, MEM_SBOX, 1); // word @7 = 0x0088 -> 0x88 (pos)
    bc.mem_load(OP_MOVSX_R_MEM16, 9, MEM_SBOX, 0); // word @0 = 0x2211 (pos)
    bc.mov_r_imm32(10, 0xAAAA_BBBB);
    bc.mov_r_imm64(11, 0x0102_0304_0506_0708);
    bc.mem_store(OP_MOV_MEM16_R, MEM_SBOX, 0, 10); // mem[0..2]=0xBBBB
    bc.mem_load(OP_MOVZX_R_MEM16, 12, MEM_SBOX, 0); // 0xBBBB
    bc.mem_store(OP_MOV_MEM32_R, MEM_SBOX, 0, 10);  // mem[0..4]=0xAABBBBBB
    bc.mem_load(OP_MOVZX_R_MEM32, 13, MEM_SBOX, 0); // 0xAABBBBBB
    bc.mem_store(OP_MOV_MEM64_R, MEM_SBOX, 0, 11);  // mem[0..8]=0x0102030405060708
    bc.mem_load(OP_MOV_R_MEM64, 14, MEM_SBOX, 0);   // 0x0102030405060708
    bc.halt();
    let prog = bc.finish();

    // Interpreter
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x100];
    mem[0..8].copy_from_slice(&pat);
    st[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8].copy_from_slice(&0u64.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &prog).map_err(|e| anyhow!("M2 mem interp failed: {:?}", e))?;
    let mut vi = [0u64; 16];
    for i in 0..16 {
        vi[i] = u64::from_le_bytes(st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }
    let mem_i = mem[0..8].to_vec();

    // Native
    {
        let b = arena.bytes();
        b[0x4000..0x4000 + prog.len()].copy_from_slice(&prog);
        b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
        b[0x6000..0x6008].copy_from_slice(&pat);
    }
    arena.call(0x7000);
    let b = arena.bytes();
    let mut vn = [0u64; 16];
    for i in 0..16 {
        vn[i] = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS + i * 8..0x5000 + interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }
    let mem_n = b[0x6000..0x6008].to_vec();
    assert_eq!(vi, vn, "M2 memory loads/stores: interp vs native vreg mismatch\ninterp={:?}\nnative ={:?}", vi, vn);
    assert_eq!(mem_i, mem_n, "M2 memory buffer mismatch after stores");
    // sanity: v14 (full 64-bit reload) must be the stored value
    assert_eq!(vi[14], 0x0102_0304_0506_0708, "M2 64-bit store/reload wrong");
    Ok(())
}

/// M3 self-test: stack (push/pop) + subroutine call/ret. Cross-checks the
/// interpreter against the native x86-64 handlers.
fn run_m3_stack_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut arena = Arena::new(0x30000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x3000;
    let bc_va = arena.base + 0x4000;
    let state_va = arena.base + 0x5000;
    let stack_va = arena.base + 0x8000; // stack region
    let tramp_va = arena.base + 0x9000;
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
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x9000..0x9000 + tramp.len()].copy_from_slice(&tramp);
    }

    // Program: main pushes a,b then calls ADDSUB (which pops a,b, computes a+b
    // into v2, restores the return address, rets). Then main pushes the result
    // and pops it into v6.
    let mut bc = BytecodeBuilder::new();
    bc.mov_r_imm32(0, 5); // a
    bc.mov_r_imm32(1, 7); // b
    bc.push_r(1); // push b
    bc.push_r(0); // push a
    let sub = bc.new_label();
    bc.call8(sub);
    bc.push_r(2); // push result
    bc.pop_r(6); // v6 = result
    bc.halt();
    bc.mark_label(sub);
    bc.pop_r(3); // return addr
    bc.pop_r(4); // a
    bc.pop_r(5); // b
    bc.mov_r_imm32(2, 0);
    bc.binop_r_r(OP_ADD_R_R, 2, 4);
    bc.binop_r_r(OP_ADD_R_R, 2, 5);
    bc.push_r(3); // restore return addr
    bc.ret();
    let prog = bc.finish();

    const STACK_SIZE: u64 = 0x1000;

    // Interpreter
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x2000];
    st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK + 8].copy_from_slice(&0x1000u64.to_le_bytes());
    st[interp::STATE_SP..interp::STATE_SP + 8].copy_from_slice(&STACK_SIZE.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &prog).map_err(|e| anyhow!("M3 stack interp failed: {:?}", e))?;
    let mut vi = [0u64; 16];
    for i in 0..16 {
        vi[i] = u64::from_le_bytes(st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }

    // Native
    {
        let b = arena.bytes();
        b[0x4000..0x4000 + prog.len()].copy_from_slice(&prog);
        b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
        b[0x5000 + interp::STATE_PTR_STACK..0x5000 + interp::STATE_PTR_STACK + 8]
            .copy_from_slice(&(stack_va as u64).to_le_bytes());
        b[0x5000 + interp::STATE_SP..0x5000 + interp::STATE_SP + 8].copy_from_slice(&STACK_SIZE.to_le_bytes());
        b[0x8000..0x8000 + 0x1000].fill(0); // clear stack region
    }
    arena.call(0x9000);
    let b = arena.bytes();
    let mut vn = [0u64; 16];
    for i in 0..16 {
        vn[i] = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS + i * 8..0x5000 + interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }
    // Compare data vregs (skip index 3 = saved return address, which is an
    // index in the interpreter but a VA in native — both correct).
    for i in 0..16 {
        if i == 3 {
            continue;
        }
        assert_eq!(vi[i], vn[i], "M3 stack/call/ret: interp vs native vreg {} mismatch (interp=0x{:X} native=0x{:X})", i, vi[i], vn[i]);
    }
    // Expected: a+b=12 in v2 and v6
    assert_eq!(vi[2], 12, "M3 subroutine result v2 wrong");
    assert_eq!(vi[6], 12, "M3 pop result v6 wrong");
    Ok(())
}

/// M2 follow-up self-test: addressing modes. Cross-checks the Rust interpreter
/// against the native x86-64 handlers for:
///   * LEA  ([base+disp] and [base+index*scale+disp])
///   * LEA_RIP (RIP-relative, via STATE_RIP)
///   * absolute-address loads/stores of every width (8/16/32/64, sign-extend)
fn run_m2_addr_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::flags;

    let mut arena = Arena::new(0x40000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x3000;
    let bc_va = arena.base + 0x4000;
    let state_va = arena.base + 0x5000;
    let data_va = arena.base + 0x6000; // addressable data region
    let stack_va = arena.base + 0x7000;
    let tramp_va = arena.base + 0x8000;
    let module = build_vm_module(
        code_va as u64,
        table_va as u64,
        bc_va as u64,
        vec![0u8; 512],
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(
        state_va as u64,
        data_va as u64,
        data_va as u64,
        code_va as u64,
        tramp_va as u64,
    )?;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
    }

    // The pattern written at data_va + disp, and at data_va + idx*scale + disp.
    // Program (built against the native data base = data_va):
    //   v0 = data_va (base)          ; v1 = index
    //   v2 = LEA(v0, idx=v1, scale=2, disp=0x10)  -> data+16
    //   MOV_MEM32_A [v2] = 0x11223344
    //   v3 = LEA(v0, ADDR_NO_INDEX, disp=0x8)     -> data+8
    //   v4 = MOVZX32_A [v3]          ; == 0 (zeroed)
    //   MOV_MEM8_A [v3] = 0xAA
    //   v5 = MOVSX8_A [v3]           ; sign-extended -86
    //   LEA_RIP: set_rip(data_va - 0x10); v6 = LEA_RIP(0x10) -> data_va
    //   v7 = MOV64_A [v6]            ; reads the u64 we stored
    // Program (base v0 and STATE_RIP are *inputs*, set per execution below):
    //   v1 = 1 (index)
    //   v2 = LEA(v0, idx=v1, scale=2(*4), disp=0x10)   -> base + 4 + 0x10
    //   MOV_MEM32_A [v2] = 0x11223344
    //   v3 = LEA(v0, ADDR_NO_INDEX, disp=0x8)          -> base + 8
    //   v4 = MOVZX32_A [v3]                             (zeroed)
    //   MOV_MEM8_A [v3] = 0xAA
    //   v5 = MOVSX8_A [v3]                              (sign-ext -86)
    //   v6 = LEA_RIP(STATE_RIP + 0x10)
    //   v7 = MOV64_A [v6]
    let mut bc = BytecodeBuilder::new();
    bc.mov_r_imm32(1, 1);
    bc.lea(2, 0, 1, 2, 0x10);
    bc.mov_r_imm32(8, 0x1122_3344);
    bc.mem_store_a(OP_MOV_MEM32_A, 2, 8);
    bc.lea(3, 0, ADDR_NO_INDEX, 0, 8);
    bc.mem_load_a(OP_MOVZX_R_MEM32_A, 4, 3); // v4 = mem32[base+8] = 0
    bc.mov_r_imm32(9, 0xAA);
    bc.mem_store_a(OP_MOV_MEM8_A, 3, 9);
    bc.mem_load_a(OP_MOVSX_R_MEM8_A, 5, 3); // v5 = signext(0xAA)
    bc.lea_rip(6, 0x10); // v6 = STATE_RIP + 0x10
    bc.mem_load_a(OP_MOV_R_MEM64_A, 7, 6); // v7 = u64 at [STATE_RIP+0x10]
    bc.halt();
    let prog = bc.finish();

    // Interpreter: base v0 = 0 (offset into mem), STATE_RIP = 0x1000
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x2000];
    st[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK + 8].copy_from_slice(&0x1000u64.to_le_bytes());
    st[interp::STATE_SP..interp::STATE_SP + 8].copy_from_slice(&0x1000u64.to_le_bytes());
    st[interp::STATE_RIP..interp::STATE_RIP + 8].copy_from_slice(&0xFF0u64.to_le_bytes());
    // place a known u64 at mem[0x1000]
    mem[0x1000..0x1008].copy_from_slice(&0xDEAD_BEEF_CAFE_F00Du64.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &prog).map_err(|e| anyhow!("M2 addr interp failed: {:?}", e))?;
    let mut vi = [0u64; 16];
    for i in 0..16 {
        vi[i] = u64::from_le_bytes(st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }
    // interpreter semantic checks (base = 0)
    assert_eq!(vi[2], 0 + 4 + 0x10, "M2 LEA base+idx*scale+disp wrong");
    assert_eq!(vi[3], 0 + 8, "M2 LEA base+disp wrong");
    assert_eq!(vi[4], 0, "M2 32-bit load of zeroed mem wrong");
    assert_eq!(vi[5] as i64, (0xAAu8 as i8) as i64, "M2 MOVSX8 wrong");
    assert_eq!(vi[6], 0x1000, "M2 LEA_RIP wrong (got 0x{:X} want 0x{:X})", vi[6], 0x1000);
    assert_eq!(vi[7], 0xDEAD_BEEF_CAFE_F00D, "M2 LEA_RIP load wrong");
    // interpreter memory effects
    assert_eq!(&mem[0x14..0x18], &[0x44, 0x33, 0x22, 0x11], "M2 mem32 store wrong");
    assert_eq!(mem[8], 0xAA, "M2 mem8 store wrong");

    // Native VM: base v0 = data_va, STATE_RIP = data_va - 0x10 so +0x10 = data_va
    {
        let b = arena.bytes();
        b[0x4000..0x4000 + prog.len()].copy_from_slice(&prog);
        b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
        b[0x5000 + interp::STATE_VREGS + 0 * 8..0x5000 + interp::STATE_VREGS + 1 * 8]
            .copy_from_slice(&(data_va as u64).to_le_bytes());
        b[0x5000 + interp::STATE_PTR_STACK..0x5000 + interp::STATE_PTR_STACK + 8]
            .copy_from_slice(&(stack_va as u64).to_le_bytes());
        b[0x5000 + interp::STATE_SP..0x5000 + interp::STATE_SP + 8].copy_from_slice(&0x1000u64.to_le_bytes());
        b[0x5000 + interp::STATE_RIP..0x5000 + interp::STATE_RIP + 8]
            .copy_from_slice(&((data_va as u64).wrapping_sub(0x10)).to_le_bytes());
        b[0x6000..0x6000 + 0x1000].fill(0);
    }
    arena.call(0x8000);
    let b = arena.bytes();
    let mut vn = [0u64; 16];
    for i in 0..16 {
        vn[i] = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS + i * 8..0x5000 + interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }
    // native semantic checks (base = data_va)
    let db = data_va as u64;
    assert_eq!(vn[2], db + 4 + 0x10, "M2 native LEA base+idx*scale+disp wrong");
    assert_eq!(vn[3], db + 8, "M2 native LEA base+disp wrong");
    assert_eq!(vn[4], 0, "M2 native 32-bit load of zeroed mem wrong");
    assert_eq!(vn[5] as i64, (0xAAu8 as i8) as i64, "M2 native MOVSX8 wrong");
    assert_eq!(vn[6], db, "M2 native LEA_RIP wrong (got 0x{:X} want 0x{:X})", vn[6], db);
    // the 32-bit store at data+0x14 and the byte store at data+8, and the u64 at data
    assert_eq!(b[0x6000 + 0x14..0x6000 + 0x18], [0x44, 0x33, 0x22, 0x11], "M2 native mem32 store wrong");
    assert_eq!(b[0x6000 + 8], 0xAA, "M2 native mem8 store wrong");
    Ok(())
}

/// M3 follow-up self-test: native API bridge. The VM calls a native helper via
/// OP_NATIVE_CALL (vreg[target] -> RAX, args v1->rcx, v2->rdx, v8->r8, v9->r9,
/// 5th+ stack args copied from [v4+0x20..] -> native [rsp+0x20..], ret -> v0).
/// Verified through the native arena (the interpreter cannot call native code).
fn run_m3_bridge_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut arena = Arena::new(0x40000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x3000;
    let bc_va = arena.base + 0x4000;
    let state_va = arena.base + 0x5000;
    let stack_va = arena.base + 0x6000;
    let tramp_va = arena.base + 0x7000;
    let native_va = arena.base + 0xA000; // the native helper we call (0xA000 is free; 0x8000 would overlap the VM module code which ends at 0x1000+0x7310=0x8310)
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
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x7000..0x7000 + tramp.len()].copy_from_slice(&tramp);
        b[0xA000..0xA000 + henc.code_buffer.len()].copy_from_slice(&henc.code_buffer);
        b[0x4000..0x4000 + prog.len()].copy_from_slice(&prog);
        b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
        b[0x5000 + interp::STATE_PTR_STACK..0x5000 + interp::STATE_PTR_STACK + 8]
            .copy_from_slice(&(stack_va as u64).to_le_bytes());
        b[0x5000 + interp::STATE_SP..0x5000 + interp::STATE_SP + 8].copy_from_slice(&0x1000u64.to_le_bytes());
        b[0x6000..0x6000 + 0x1000].fill(0);
        // v4 (RSP register) = stack_va so the bridge finds the 5th stack arg at [v4+0x20].
        b[0x5000 + interp::STATE_VREGS + 4 * 8..0x5000 + interp::STATE_VREGS + 5 * 8]
            .copy_from_slice(&(stack_va as u64).to_le_bytes());
        // 5th arg d = 40 at [stack_va + 0x20]
        b[0x6000 + 0x20..0x6000 + 0x28].copy_from_slice(&40u64.to_le_bytes());
    }
    arena.call(0x7000);
    let b = arena.bytes();
    let ret = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS + 0 * 8..0x5000 + interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    // add4(10,20,30,40) = 10 + 2*20 + 4*30 + 8*40 = 10+40+120+320 = 490
    assert_eq!(ret, 490, "M3 native bridge returned {} (want 490)", ret);
    // v1/v2/v8 must be preserved (args), v0 clobbered by return value
    let v1 = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS + 1 * 8..0x5000 + interp::STATE_VREGS + 2 * 8].try_into().unwrap());
    let v2 = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS + 2 * 8..0x5000 + interp::STATE_VREGS + 3 * 8].try_into().unwrap());
    let v8 = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS + 8 * 8..0x5000 + interp::STATE_VREGS + 9 * 8].try_into().unwrap());
    assert_eq!((v1, v2, v8), (10, 20, 30), "M3 native bridge clobbered arg vregs");
    Ok(())
}

/// M4 self-test: block lift (1:1 x86→VM table) + dummy_fn equivalence.
/// Lifts a small dummy function to bytecode, executes it through the interpreter
/// AND the native VM, and compares both against a native x86 execution of the
/// same instruction sequence. The dummy_fn exercises reg moves, arithmetic,
/// shifts, LEA (base+index*scale+disp), absolute-address loads/stores and a
/// CALL/RET subroutine. (Control-flow lift — loops/jcc — is M5.)
fn run_m4_lift_test() -> Result<()> {
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
    st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK + 8].copy_from_slice(&0x3000u64.to_le_bytes());
    st[interp::STATE_SP..interp::STATE_SP + 8].copy_from_slice(&0xFF8u64.to_le_bytes());
    // pre-place the main-function return address (-> trailing HALT)
    mem[0x3000 + 0xFF8..0x3000 + 0x1000].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("M4 lift interp failed: {:?}", e))?;
    let interp_rax = u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    assert_eq!(interp_rax, expected, "M4 lift interpreter: rax mismatch (interp=0x{:X} native=0x{:X})", interp_rax, expected);

    // 3) Native VM execution.
    let mut vm_arena = Arena::new(0x40000)?;
    let vm_code_va = vm_arena.base + 0x1000;
    let vm_table_va = vm_arena.base + 0x3000;
    let vm_bc_va = vm_arena.base + 0x4000;
    let vm_state_va = vm_arena.base + 0x5000;
    let vm_stack_va = vm_arena.base + 0x6000;
    let vm_tramp_va = vm_arena.base + 0x7000;
    let vm_data_va = vm_arena.base + 0x8000;
    let module = build_vm_module(vm_code_va as u64, vm_table_va as u64, vm_bc_va as u64, bc.clone(), handlers::EntryMode::Ksa)?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vm_state_va as u64, vm_data_va as u64, vm_data_va as u64, vm_code_va as u64, vm_tramp_va as u64)?;
    {
        let b = vm_arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x7000..0x7000 + tramp.len()].copy_from_slice(&tramp);
        b[0x4000..0x4000 + bc.len()].copy_from_slice(&bc);
        b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
        b[0x5000 + interp::STATE_VREGS + 0 * 8..0x5000 + interp::STATE_VREGS + 1 * 8].copy_from_slice(&0u64.to_le_bytes()); // rax
        b[0x5000 + interp::STATE_VREGS + 1 * 8..0x5000 + interp::STATE_VREGS + 2 * 8].copy_from_slice(&(a as u64).to_le_bytes()); // rcx = a
        b[0x5000 + interp::STATE_VREGS + 2 * 8..0x5000 + interp::STATE_VREGS + 3 * 8].copy_from_slice(&(argb as u64).to_le_bytes()); // rdx = b
        b[0x5000 + interp::STATE_VREGS + 8 * 8..0x5000 + interp::STATE_VREGS + 9 * 8].copy_from_slice(&(c as u64).to_le_bytes()); // r8 = c
        b[0x5000 + interp::STATE_VREGS + 6 * 8..0x5000 + interp::STATE_VREGS + 7 * 8].copy_from_slice(&(vm_data_va as u64).to_le_bytes());
        b[0x5000 + interp::STATE_PTR_STACK..0x5000 + interp::STATE_PTR_STACK + 8].copy_from_slice(&(vm_stack_va as u64).to_le_bytes());
        b[0x5000 + interp::STATE_SP..0x5000 + interp::STATE_SP + 8].copy_from_slice(&0xFF8u64.to_le_bytes());
        b[0x6000..0x6000 + 0x1000].fill(0);
        // pre-place the main-function return address (absolute VA of trailing HALT)
        b[0x6000 + 0xFF8..0x6000 + 0x1000].copy_from_slice(&((vm_bc_va as u64) + halt_off).to_le_bytes());
        b[0x8000..0x8000 + 0x100].fill(0);
    }
    vm_arena.call(0x7000);
    let b = vm_arena.bytes();
    let vm_rax = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS + 0 * 8..0x5000 + interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    assert_eq!(vm_rax, expected, "M4 lift native VM: rax mismatch (vm=0x{:X} native=0x{:X})", vm_rax, expected);
    Ok(())
}


/// A-2/A-5 self-test: OR/NEG/NOT, 64-bit shifts, NOP (v25 opcodes).
/// Cross-checks the Rust interpreter against the native x86-64 handlers for
/// every new opcode, and exercises the lifter's diagnose_unsupported (A-5).
fn run_a2_a5_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::flags;

    let mut rng = rand::thread_rng();
    let pairs32: Vec<(u32, u32)> = (0..24).map(|_| (rng.next_u32(), rng.next_u32())).collect();
    let pairs64: Vec<(u64, u64)> = (0..12).map(|_| (rng.next_u64(), rng.next_u64())).collect();

    let mut arena = Arena::new(0x30000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x3000;
    let bc_va = arena.base + 0x4000;
    let state_va = arena.base + 0x5000;
    let tramp_va = arena.base + 0x6000;
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
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x6000..0x6000 + tramp.len()].copy_from_slice(&tramp);
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
            b[0x4000..0x4000 + prog.len()].copy_from_slice(prog);
            b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
        }
        arena.call(0x6000);
        let b = arena.bytes();
        let sf = 0x5000usize;
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

        let mut bad_seq: Vec<LiftedInstr> = Vec::new();
        bad_seq.push(LiftedInstr::plain(Instruction::with2(Code::Addss_xmm_xmmm32, Register::XMM0, Register::XMM1).unwrap()));
        let bad2 = diagnose_unsupported(&bad_seq);
        assert!(!bad2.is_empty(), "A5 diagnose should flag FP op");
        let lift_err = lift_block(&bad_seq, 0);
        assert!(lift_err.is_err(), "A5 lift of FP op should fail loudly");
    }

    Ok(())
}

/// Encode a labeled block (LiftedInstr) to native x86 with two-pass branch
/// resolution (mirrors `encode_labeled_block`).
fn encode_dummy_native(seq: &[LiftedInstr], base_va: u64) -> Result<Vec<u8>> {
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
fn encode_dummy_call_stub(fn_va: u64, data_va: u64, a: u32, b: u32, c: u32, base_va: u64) -> Result<Vec<u8>> {
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

/// Run the full VM self-test. Returns Ok(()) iff every stage matches.
pub fn run_self_test() -> Result<()> {
    use std::io::Write;
    println!("==================================================================");
    println!(" [VM SELF-TEST] Composite VM MVP — lifter / interpreter / handlers ");
    println!("==================================================================");
    let _ = std::io::stdout().flush();

    // ── Random inputs ──────────────────────────────────────────────────────────
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 256];
    rng.fill_bytes(&mut seed);
    let mut seed_masked = [0u8; 256];
    for (i, b) in seed.iter().enumerate() {
        seed_masked[i] = b ^ 0xA7;
    }
    let k1 = rng.next_u32();
    let k2 = rng.next_u32();
    let k3 = rng.next_u32();

    // ── Reference (pure Rust) ──────────────────────────────────────────────────
    let mut expected = [0u8; 256];
    ksa::reference_ksa(&seed_masked, k1, k2, k3, &mut expected);
    println!("[1] reference KSA computed (k1=0x{:08X} k2=0x{:08X} k3=0x{:08X})", k1, k2, k3);

    // ── Lift to bytecode ───────────────────────────────────────────────────────
    let seq = ksa::build_ksa_instructions(0, k1, k2, k3);
    let bc = lifter::lift_ksa(&seq)?;
    println!("[2] lifted {} KSA instructions -> {} bytes of bytecode", seq.len(), bc.len());
    log::debug!("VM bytecode:\n{}", bytecode::disassemble(&bc));

    // ── Interpreter ────────────────────────────────────────────────────────────
    {
        let mut state = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x2000];
        let sbox_off = 0x100usize;
        let seed_off = 0x1000usize;
        mem[seed_off..seed_off + 256].copy_from_slice(&seed_masked);
        state[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
            .copy_from_slice(&(sbox_off as u64).to_le_bytes());
        state[interp::STATE_PTR_SEED..interp::STATE_PTR_SEED + 8]
            .copy_from_slice(&(seed_off as u64).to_le_bytes());
        interp::interpret(&mut state, &mut mem, &bc)
            .map_err(|e| anyhow!("interpreter failed: {:?}", e))?;
        let ok = mem[sbox_off..sbox_off + 256] == expected[..];
        println!("[3] bytecode interpreter: {}", pass_fail(ok));
        if !ok {
            return Err(anyhow!("interpreter mismatch"));
        }
    }

    // ── Native execution arena ─────────────────────────────────────────────────
    let mut arena = Arena::new(0x20000)?;
    let sbox_va = arena.base + 0x2000;
    let seed_va = arena.base + 0x3000;
    let code_va = arena.base + 0x5000;
    let table_va = arena.base + 0x7000;
    let bc_va = arena.base + 0x8000;
    let state_va = arena.base + 0x9000;
    let vsbox_va = arena.base + 0xA000;
    let tramp_va = arena.base + 0xB000;

    // ── Native x86 KSA (the baseline the VM must match) ────────────────────────
    {
        let native = encode_ksa_native(seed_va as u64, k1, k2, k3, sbox_va as u64, code_va as u64)?;
        std::fs::write("native_ksa.bin", &native).ok();
        let b = arena.bytes();
        b[0x2000..0x2000 + 256].fill(0);
        b[0x3000..0x3000 + 256].copy_from_slice(&seed_masked);
        b[0x5000..0x5000 + native.len()].copy_from_slice(&native);
        arena.call(0x5000);
        let ok = arena.bytes()[0x2000..0x2000 + 256] == expected[..];
        println!("[4] native x86 KSA:              {}", pass_fail(ok));
        if !ok {
            return Err(anyhow!("native KSA mismatch"));
        }
    }

    // ── VM module: build, place, execute natively ──────────────────────────────
    {
        let module = build_vm_module(
            code_va as u64,
            table_va as u64,
            bc_va as u64,
            bc.clone(),
            handlers::EntryMode::Ksa,
        )?;
        handlers::validate_vm_code(&module.code)?;
        println!(
            "[5] VM module: code={}B table={}B bytecode={}B state={}B",
            module.code.len(),
            module.table.len(),
            module.bytecode.len(),
            VM_STATE_SIZE
        );
        let tramp = encode_trampoline(state_va as u64, vsbox_va as u64, seed_va as u64, code_va as u64, tramp_va as u64)?;
        let b = arena.bytes();
        b[0x5000..0x5000 + module.code.len()].copy_from_slice(&module.code);
        b[0x7000..0x7000 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + module.bytecode.len()].copy_from_slice(&module.bytecode);
        b[0x9000..0x9000 + VM_STATE_SIZE].fill(0);
        b[0xA000..0xA000 + 256].fill(0);
        b[0xB000..0xB000 + tramp.len()].copy_from_slice(&tramp);
        arena.call(0xB000);
        let ok = arena.bytes()[0xA000..0xA000 + 256] == expected[..];
        println!("[6] VM module native execution:   {}", pass_fail(ok));
        if !ok {
            return Err(anyhow!("VM module native execution mismatch"));
        }
    }

    // ── 2nd virtualized routine: import-name MBA key derivation ──────────────
    // (v14) Beyond RC4 KSA, the VM now also virtualizes the per-entry import XOR
    // key derivation. This proves the composite VM executes a real second
    // security routine (not just KSA) through its handlers.
    {
        let master = rng.next_u32();
        let c: u32 = 0x9E37_79B9;
        let bc_ik = import_key::build_import_key_bytecode(master, c);
        let mut state = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x100];
        let mut ok = true;
        for idx in [0u32, 1, 3, 7, 0x1234_5678, 0xDEAD_BEEF, 0xFFFF_FFFF] {
            state[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8]
                .copy_from_slice(&(idx as u64).to_le_bytes());
            state[interp::STATE_VREGS + 1 * 8..interp::STATE_VREGS + 2 * 8].fill(0);
            interp::interpret(&mut state, &mut mem, &bc_ik)
                .map_err(|e| anyhow!("VM import-key interpreter failed: {:?}", e))?;
            let got = u64::from_le_bytes(
                state[interp::STATE_VREGS + 1 * 8..interp::STATE_VREGS + 2 * 8]
                    .try_into()
                    .unwrap(),
            ) as u32;
            let exp = import_key::reference_import_key(master, idx, c);
            if got != exp {
                ok = false;
            }
        }
        println!(
            "[7] VM import-name MBA key derivation (2nd virtualized routine): {}",
            pass_fail(ok)
        );
        if !ok {
            return Err(anyhow!("VM import-key bytecode mismatch"));
        }
    }

    // ── v19: PRGA (RC4 keystream generation) virtualized routine ────────────
    // (Target #3 — the string-run/code-region decrypt loop is lifted into the VM)
    {
        let mut rng2 = rand::thread_rng();
        let bc_prga = prga::build_prga_bytecode();
        let mut sbox = [0u8; 256];
        rng2.fill_bytes(&mut sbox);
        let mut buf = vec![0u8; 64];
        rng2.fill_bytes(&mut buf);
        let mut sbox_ref = sbox;
        let mut buf_ref = buf.clone();
        prga::reference_prga(&mut sbox_ref, &mut buf_ref);

        let mut state = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x400];
        let (sbox_off, buf_off) = (0usize, 0x100usize);
        mem[sbox_off..sbox_off + 256].copy_from_slice(&sbox);
        mem[buf_off..buf_off + buf.len()].copy_from_slice(&buf);
        state[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
            .copy_from_slice(&(sbox_off as u64).to_le_bytes());
        state[interp::STATE_PTR_BUF..interp::STATE_PTR_BUF + 8]
            .copy_from_slice(&(buf_off as u64).to_le_bytes());
        state[interp::STATE_VREGS + 3 * 8..interp::STATE_VREGS + 4 * 8]
            .copy_from_slice(&(buf.len() as u64).to_le_bytes());
        interp::interpret(&mut state, &mut mem, &bc_prga)
            .map_err(|e| anyhow!("VM PRGA interpreter failed: {:?}", e))?;
        let out = &mem[buf_off..buf_off + buf.len()];
        let ok = out == buf_ref.as_slice();
        println!(
            "[8] VM PRGA keystream generation (3rd virtualized routine): {} ({}B)",
            pass_fail(ok),
            buf.len()
        );
        if !ok {
            return Err(anyhow!("VM PRGA mismatch"));
        }
    }

    // ── M1: full flag model + Jcc conditions (interp == native == flags.rs) ──
    match run_flags_jcc_test() {
        Ok(_) => println!("[9] VM flag model + full Jcc (16 conds incl. JA/JBE): PASS"),
        Err(e) => {
            println!("[9] VM flag model + full Jcc:                   FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M2: 64-bit arithmetic / shifts / TEST / memory width ────────────────
    match run_m2_mem_test() {
        Ok(_) => println!("[10] M2 mem width (16/32/64-bit, sign-ext):   PASS"),
        Err(e) => {
            println!("[10] M2 mem width:                              FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M3: stack + call/ret (subroutine support) ───────────────────────────
    match run_m3_stack_test() {
        Ok(_) => println!("[11] M3 stack push/pop + call/ret:          PASS"),
        Err(e) => {
            println!("[11] M3 stack push/pop + call/ret:            FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M2 follow-up: addressing modes (LEA, LEA_RIP, absolute-addr mem) ────
    match run_m2_addr_test() {
        Ok(_) => println!("[12] M2 addressing modes (disp/idx*scale/RIP-rel): PASS"),
        Err(e) => {
            println!("[12] M2 addressing modes:                      FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M3 follow-up: native API bridge ─────────────────────────────────────
    match run_m3_bridge_test() {
        Ok(_) => println!("[13] M3 native API bridge (VM→GPR→call→restore): PASS"),
        Err(e) => {
            println!("[13] M3 native API bridge:                     FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M4: block lift (1:1 table + dummy_fn equivalence) ──────────────────
    match run_m4_lift_test() {
        Ok(_) => println!("[14] M4 block lift (dummy_fn == native):      PASS"),
        Err(e) => {
            println!("[14] M4 block lift:                              FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M6 (v26): 원본 .text → VM lift (커버리지 + 실제 lift 동치) ──────────
    match run_text_lift_test() {
        Ok(_) => println!("[16] M6 text->VM lift (real .text block == native): PASS"),
        Err(e) => {
            println!("[16] M6 text->VM lift:                            FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-2/A-5: OR/NEG/NOT + 64-bit shifts + NOP + unsupported diagnostics ──
    match run_a2_a5_test() {
        Ok(_) => println!("[15] A-2/A-5 OR/NEG/NOT, 64-shift, NOP, diag:  PASS"),
        Err(e) => {
            println!("[15] A-2/A-5 opcodes/diagnostics:               FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-2/A-5 (v26): completed 1:1 lift table (reg/imm/cmp/test/push) ────
    match run_a2_lift_completion_test() {
        Ok(_) => println!("[17] A-2/A-5 lift-table completion (reg/imm/cmp/test/push): PASS"),
        Err(e) => {
            println!("[17] A-2/A-5 lift-table completion:               FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-5 (v29): SSE/FPU + conditional + string ops (setcc/cmovcc/sbb/XMM/stosq/loopne) ──
    match run_a5_sse_cond_test() {
        Ok(_) => println!("[18] A-5 SSE/FPU + setcc/cmovcc/sbb + rep stosq/loopne: PASS"),
        Err(e) => {
            println!("[18] A-5 SSE/FPU + setcc/cmovcc/sbb:              FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── M5 (v30): multi-block control-flow lift (rel32 branches + block connection) ──
    match run_m5_multiblock_test() {
        Ok(_) => println!("[19] M5 multi-block lift (loop, rel32 cross-block, block connect): PASS"),
        Err(e) => {
            println!("[19] M5 multi-block lift:                             FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-2 (v31): 1-op signed/unsigned multiply-divide + BSWAP ──────────────
    match run_a2_muldiv_bswap_test() {
        Ok(_) => println!("[20] A-2 mul/div (1-op MUL/IMUL/DIV/IDIV 32/64) + BSWAP: PASS"),
        Err(e) => {
            println!("[20] A-2 mul/div + BSWAP:                              FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-2/A-5 (v32): 8/16-bit arithmetic + JCXZ/JECXZ + rep movs/cmps ────
    match run_a2a5_lift_residual_test() {
        Ok(_) => println!("[21] A-2/A-5 8/16-bit arith + JCXZ/JECXZ + rep movs/cmps: PASS"),
        Err(e) => {
            println!("[21] A-2/A-5 8/16-bit arith + JCXZ/JECXZ + rep movs/cmps: FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-2 (v33): 1-op MUL/IMUL/DIV/IDIV 8/16-bit width ───────────────────
    match run_a2_muldiv_8_16_test() {
        Ok(_) => println!("[22] A-2 mul/div (1-op MUL/IMUL/DIV/IDIV 8/16-bit width): PASS"),
        Err(e) => {
            println!("[22] A-2 mul/div 8/16-bit:                                  FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── M6 Phase-2 (v34): OEP→VM entry 전환 데이터 경로 (전체 도달 CFG → 단일 VM) ──
    match run_m6_phase2_lift_test() {
        Ok(_) => println!("[23] M6 Phase-2 whole-CFG OEP lift (reachable CFG -> single VM): PASS"),
        Err(e) => {
            println!("[23] M6 Phase-2 whole-CFG OEP lift:                        FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── B-3 (v35): switch/테이블 점프 → VM 내부 디스패치 ─────────────────────────
    match run_switch_lift_test() {
        Ok(_) => println!("[24] B-3 switch jump table -> VM dispatch (compare-and-jump chain): PASS"),
        Err(e) => {
            println!("[24] B-3 switch jump table:                                FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── C-1 (v36): VM 메모리 모델 ──────────────────────────────────────────────
    match run_mem_model_test() {
        Ok(_) => println!("[25] C-1 VM memory model (region schema + resolve + bounds): PASS"),
        Err(e) => {
            println!("[25] C-1 VM memory model:                                  FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── M6 Phase-2 (v38): 원본 프로그램을 lift 한 VM 프로그램의 네이티브 VM 실행 ──
    match run_m6_phase2_native_program_test() {
        Ok(_) => println!("[26] M6 Phase-2 native-VM program execution (lifted CFG == native VM == x86): PASS"),
        Err(e) => {
            println!("[26] M6 Phase-2 native-VM program execution:              FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── M7 (v41): on-demand 재암호화(anti-dump) ────────────────────────────────
    match run_m7_ondemand_reencrypt_test() {
        Ok(_) => println!("[27] M7 on-demand re-encrypt (decrypt→use→re-encrypt; dump stays ciphertext): PASS"),
        Err(e) => {
            println!("[27] M7 on-demand re-encrypt:                              FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── M8 (v45): VM handler 테이블 MBA 난독화 (handler 주소 비평문) ────────────
    match run_m8_handler_mba_test() {
        Ok(_) => println!("[28] M8 VM handler-table MBA (dispatch derives K via a+b==(a^b)+2(a&b); table XOR-encrypted): PASS"),
        Err(e) => {
            println!("[28] M8 VM handler-table MBA:                              FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── v49: atomic memory compare-exchange (8/16/32/64) ─────────────────────────
    match run_m4_cmpxchg_test() {
        Ok(_) => println!("[29] v49 atomic mem cmpxchg (8/16/32/64; interp==native): PASS"),
        Err(e) => {
            println!("[29] v49 atomic mem cmpxchg:                            FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── P0-3 (v53 rework): R15/R14 are ordinary program vregs (14/15) ───────────
    // R14/R15 must LIFT (not be rejected) — the native VM virtualizes them into
    // state slots 14/15, distinct from the lifter's internal scratch vregs 16/17.
    // Rejecting them previously broke real --vm-oep packing (chve2_unpacked lifts
    // instructions using R15). Verify they lift AND execute correctly through the
    // interpreter (end-to-end: mov r15,imm64; mov rax,r15; halt -> rax==imm64).
    {
        use crate::vm::bytecode::BytecodeBuilder;
        use crate::vm::lifter::lift_one;
        let mut b = BytecodeBuilder::new();
        let r15_ok = lift_one(&mut b, &Instruction::with2(Code::Mov_r64_rm64, Register::R15, Register::RAX).unwrap()).is_ok();
        let r14_ok = lift_one(&mut b, &Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap()).is_ok();
        let normal_ok = lift_one(&mut b, &Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RBX).unwrap()).is_ok();
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(15, 0x1122_3344_5566_7788u64);
        bc.mov_r_r64(0, 15);
        bc.halt();
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 64];
        let exec_ok = interp::interpret(&mut st, &mut mem, &bc.finish()).is_ok();
        let rax = if exec_ok { u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..][..8].try_into().unwrap()) } else { 0 };
        if r15_ok && r14_ok && normal_ok && exec_ok && rax == 0x1122_3344_5566_7788u64 {
            println!("[29] P0-3 R15/R14 usable as program vregs (lift + interp execution): PASS");
        } else {
            println!("[29] P0-3 R15/R14 register handling: FAIL (r15={} r14={} normal={} exec={} rax=0x{:X})", r15_ok, r14_ok, normal_ok, exec_ok, rax);
            return Err(anyhow!("[29] R15/R14 register handling failed"));
        }
    }
    // ── P2-10: opcode registry sync check ─────────────────────────────────────
    // The opcode set is declared once in the `opcodes!` macro (bytecode.rs).
    // Verify (a) every declared opcode resolves to a non-"??" mnemonic and an
    // operand length, (b) no duplicate values, and (c) the native handler table
    // (built over 0..NUM_OPS) has a distinct handler for every non-zero opcode
    // slot — so bytecode/handlers/interp/lifter cannot silently drift apart.
    {
        use crate::vm::bytecode::{NUM_OPS, OPCODE_INFO, opcode_name, opcode_operand_len};
        let mut ok = true;
        let mut seen = std::collections::HashSet::new();
        for (val, mnem, olen) in OPCODE_INFO {
            if opcode_name(*val) == "??" || opcode_name(*val) != *mnem {
                ok = false;
                eprintln!("[30] opcode {}: mnemonic mismatch (name='{}' table='{}')", val, opcode_name(*val), mnem);
            }
            if opcode_operand_len(*val) != Some(*olen) {
                ok = false;
                eprintln!("[30] opcode {}: operand-len mismatch", val);
            }
            if *val as usize >= NUM_OPS {
                ok = false;
                eprintln!("[30] opcode {}: value >= NUM_OPS", val);
            }
            if !seen.insert(*val) {
                ok = false;
                eprintln!("[30] duplicate opcode value 0x{:02X}", val);
            }
        }
        // handler-table coverage: every non-zero slot must have a real handler
        // (distinct from the invalid-opcode handler at slot 0).
        let vmc = handlers::generate_vm_code(0x1000, 0x3000, 0x2000, handlers::EntryMode::Ksa, None)?;
        let invalid_off = vmc.handler_offsets[0];
        for op in 1..NUM_OPS {
            if vmc.handler_offsets[op] == invalid_off {
                ok = false;
                eprintln!("[30] opcode slot 0x{:02X}: no distinct handler", op);
            }
        }
        if ok {
            println!("[30] P2-10 opcode registry sync ({} opcodes, mnemonic+olen+handler-table coverage): PASS", OPCODE_INFO.len());
        } else {
            return Err(anyhow!("[30] opcode registry sync failed"));
        }
    }
    // ── v48: atomic memory XCHG / XADD semantics (Once swap / fetch-add) ─────
    // Check [31] proves OP_XCHG_MEM*_A / OP_XADD_MEM*_A are a single atomic RMW
    // with x86-exact semantics: interpreter and native VM must both produce the
    // reference x86 result (8/16/32/64-bit). This is the fix for the Rust `Once`
    // CompletionGuard `xchg [state], COMPLETE` that was previously lifted as a
    // non-atomic load+store, letting a 2nd call_once re-run the closure and panic
    // at once.rs:166 (`f.take().unwrap()` on None).
    {
        use crate::vm::bytecode::*;
        let mut bc = BytecodeBuilder::new();
        bc.mem_xchg_a(OP_XCHG_MEM32_A, 9, 1);   // [8000h] <-> v1 (32-bit)
        bc.mem_xchg_a(OP_XCHG_MEM64_A, 10, 2);  // [8008h] <-> v2 (64-bit)
        bc.mem_xchg_a(OP_XCHG_MEM8_A, 11, 3);   // [8010h] <-> v3 (8-bit)
        bc.mem_xchg_a(OP_XCHG_MEM16_A, 12, 4);  // [8018h] <-> v4 (16-bit)
        bc.mem_xadd_a(OP_XADD_MEM32_A, 13, 5);  // [8020h] += v5 ; v5 = old
        bc.mem_xadd_a(OP_XADD_MEM64_A, 14, 6);  // [8028h] += v6 ; v6 = old
        bc.mem_xadd_a(OP_XADD_MEM8_A, 15, 7);   // [8030h] += v7 ; v7 = old
        bc.mem_xadd_a(OP_XADD_MEM16_A, 0, 8);   // [8038h] += v8 ; v8 = old (addr in v0)
        bc.halt();
        let prog = bc.finish();

        // Initial 64-byte data region (little-endian).
        let mut data_init = vec![0u8; 0x40];
        data_init[0x00..0x04].copy_from_slice(&0xAABB_CCDDu32.to_le_bytes());
        data_init[0x08..0x10].copy_from_slice(&0x8899_AABB_CCDD_EEFFu64.to_le_bytes());
        data_init[0x10] = 0x77;
        data_init[0x18..0x1A].copy_from_slice(&0x5566u16.to_le_bytes());
        data_init[0x20..0x24].copy_from_slice(&0x20u32.to_le_bytes());
        data_init[0x28..0x30].copy_from_slice(&0x300u64.to_le_bytes());
        data_init[0x30] = 0xFA;
        data_init[0x38..0x3A].copy_from_slice(&0xFFFFu16.to_le_bytes());

        // Expected final vregs v1..v8 (index 0 left zero).
        let want_v: [u64; 9] = [
            0, 0xAABB_CCDD, 0x8899_AABB_CCDD_EEFF, 0x77, 0x5566,
            0x20, 0x300, 0xFA, 0xFFFF,
        ];
        // Expected final data bytes.
        let mut want_d = vec![0u8; 0x40];
        want_d[0x00..0x04].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        want_d[0x08..0x10].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        want_d[0x10] = 0xAA;
        want_d[0x18..0x1A].copy_from_slice(&0xBBBBu16.to_le_bytes());
        want_d[0x20..0x24].copy_from_slice(&0x30u32.to_le_bytes());
        want_d[0x28..0x30].copy_from_slice(&0x400u64.to_le_bytes());
        want_d[0x30] = 0xFF;
        want_d[0x38..0x3A].copy_from_slice(&0x00FFu16.to_le_bytes());

        // Seed the vregs in a state buffer: data vregs 1..8 and address vregs
        // 9..15 + v0. `base` is the address base (0 for interp offset-space,
        // arena.base for native absolute space).
        macro_rules! seed_state {
            ($st:expr, $base:expr) => {{
                let s: &mut [u8] = $st;
                let base: u64 = $base;
                let mut put = |v: usize, x: u64| {
                    s[interp::STATE_VREGS + v * 8..interp::STATE_VREGS + v * 8 + 8]
                        .copy_from_slice(&x.to_le_bytes())
                };
                put(1, 0x1122_3344); put(2, 0x0102_0304_0506_0708);
                put(3, 0xAA); put(4, 0xBBBB); put(5, 0x10);
                put(6, 0x100); put(7, 0x05); put(8, 0x0100);
                put(9, base + 0x8000); put(10, base + 0x8008); put(11, base + 0x8010);
                put(12, base + 0x8018); put(13, base + 0x8020); put(14, base + 0x8028);
                put(15, base + 0x8030); put(0, base + 0x8038);
            }};
        }

        // Interpreter run.
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x10000];
        mem[0x8000..0x8000 + 0x40].copy_from_slice(&data_init);
        seed_state!(&mut st, 0u64);
        interp::interpret(&mut st, &mut mem, &prog)
            .map_err(|e| anyhow!("[31] atomic XCHG/XADD interp failed: {:?}", e))?;
        let mut vi = [0u64; 9];
        for i in 0..9 {
            vi[i] = u64::from_le_bytes(st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
        }
        let mem_i = mem[0x8000..0x8000 + 0x40].to_vec();

        // Native VM run.
        let mut varena = Arena::new(0x40000)?;
        let (vc, vt, vb, vs, vtr, vdata) = (
            varena.base + 0x1000, varena.base + 0x3000, varena.base + 0x4000,
            varena.base + 0x5000, varena.base + 0x7000, varena.base + 0x8000,
        );
        let module = build_vm_module(vc as u64, vt as u64, vb as u64, prog.clone(), handlers::EntryMode::Ksa)?;
        handlers::validate_vm_code(&module.code)?;
        let tramp = encode_trampoline(vs as u64, vdata as u64, vdata as u64, vc as u64, vtr as u64)?;
        let vbase = varena.base as u64;
        {
            let b = varena.bytes();
            b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
            b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
            b[0x7000..0x7000 + tramp.len()].copy_from_slice(&tramp);
            b[0x4000..0x4000 + prog.len()].copy_from_slice(&prog);
            b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
            b[0x8000..0x8000 + 0x40].copy_from_slice(&data_init);
            seed_state!(&mut b[0x5000..0x5000 + interp::STATE_SIZE], vbase);
        }
        varena.call(0x7000);
        let b = varena.bytes();
        let mut vn = [0u64; 9];
        for i in 0..9 {
            vn[i] = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS + i * 8..0x5000 + interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
        }
        let mem_n = b[0x8000..0x8000 + 0x40].to_vec();

        assert_eq!(vi[1..], want_v[1..], "[31] atomic XCHG/XADD interpreter vregs mismatch\ninterp={:?}\nwant  ={:?}", &vi[1..], &want_v[1..]);
        assert_eq!(vn[1..], want_v[1..], "[31] atomic XCHG/XADD native vregs mismatch\nnative={:?}\nwant  ={:?}", &vn[1..], &want_v[1..]);
        // v0 was used only as the XADD16 address; it must be unchanged.
        assert_eq!(vi[0], 0x8038, "[31] interp address vreg clobbered");
        assert_eq!(vn[0], vbase + 0x8038, "[31] native address vreg clobbered");
        assert_eq!(mem_i, want_d, "[31] atomic XCHG/XADD interpreter mem mismatch");
        assert_eq!(mem_n, want_d, "[31] atomic XCHG/XADD native mem mismatch");
        println!("[31] v48 atomic memory XCHG/XADD (interp == native == x86, 8/16/32/64-bit): PASS");
    }
    let _ = std::io::stdout().flush();

    println!("==================================================================");
    println!(" [VM SELF-TEST] ALL CHECKS PASSED");
    println!("==================================================================");
    Ok(())
}

/// M6 (v26) self-test: lift a *real* x86 `.text` block (decoded from raw bytes)
/// to VM bytecode and prove interpreter == native execution. Unlike the M4
/// dummy_fn (hand-built LiftedInstr), this feeds an actual raw-code buffer
/// through CfgExtractor → analyze_text_lift → lift, then runs the lifted
/// bytecode through the reference interpreter AND the native VM, comparing both
/// to a native x86 execution of the same bytes. This validates the M6
/// "원본 .text lift" path end-to-end.
fn run_text_lift_test() -> Result<()> {
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
    st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK + 8].copy_from_slice(&0x3000u64.to_le_bytes());
    st[interp::STATE_SP..interp::STATE_SP + 8].copy_from_slice(&0xFF8u64.to_le_bytes());
    // Pre-place the main-function return address (-> trailing HALT) on the stack.
    let halt_off = (lifted_bc.len() - 1) as u64; // index of trailing HALT
    mem[0x3000 + 0xFF8..0x3000 + 0x1000].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &lifted_bc)
        .map_err(|e| anyhow!("M6 lift interp failed: {:?}", e))?;
    let interp_rax = u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    assert_eq!(interp_rax, expected, "M6 lifted interpreter: rax mismatch");

    // 4) Native VM execution of the same lifted bytecode.
    let mut vm_arena = Arena::new(0x40000)?;
    let vm_code_va = vm_arena.base + 0x1000;
    let vm_table_va = vm_arena.base + 0x3000;
    let vm_bc_va = vm_arena.base + 0x4000;
    let vm_state_va = vm_arena.base + 0x5000;
    let vm_stack_va = vm_arena.base + 0x6000;
    let vm_tramp_va = vm_arena.base + 0x7000;
    let vm_data_va = vm_arena.base + 0x8000;
    let module = build_vm_module(vm_code_va as u64, vm_table_va as u64, vm_bc_va as u64, lifted_bc.clone(), handlers::EntryMode::Ksa)?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vm_state_va as u64, vm_data_va as u64, vm_data_va as u64, vm_code_va as u64, vm_tramp_va as u64)?;
    let b_arg = b; // keep the b argument across the arena-shadowing block below
    {
        let b = vm_arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x7000..0x7000 + tramp.len()].copy_from_slice(&tramp);
        b[0x4000..0x4000 + lifted_bc.len()].copy_from_slice(&lifted_bc);
        b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
        b[0x5000 + interp::STATE_VREGS + 0 * 8..0x5000 + interp::STATE_VREGS + 1 * 8].copy_from_slice(&0u64.to_le_bytes());
        b[0x5000 + interp::STATE_VREGS + 1 * 8..0x5000 + interp::STATE_VREGS + 2 * 8].copy_from_slice(&(a as u64).to_le_bytes());
        b[0x5000 + interp::STATE_VREGS + 2 * 8..0x5000 + interp::STATE_VREGS + 3 * 8].copy_from_slice(&(b_arg as u64).to_le_bytes());
        b[0x5000 + interp::STATE_VREGS + 8 * 8..0x5000 + interp::STATE_VREGS + 9 * 8].copy_from_slice(&(c as u64).to_le_bytes());
        b[0x5000 + interp::STATE_VREGS + 6 * 8..0x5000 + interp::STATE_VREGS + 7 * 8].copy_from_slice(&(vm_data_va as u64).to_le_bytes()); // rsi
        b[0x5000 + interp::STATE_PTR_STACK..0x5000 + interp::STATE_PTR_STACK + 8].copy_from_slice(&(vm_stack_va as u64).to_le_bytes());
        b[0x5000 + interp::STATE_SP..0x5000 + interp::STATE_SP + 8].copy_from_slice(&0xFF8u64.to_le_bytes());
        b[0x6000..0x6000 + 0x1000].fill(0);
        b[0x6000 + 0xFF8..0x6000 + 0x1000].copy_from_slice(&((vm_bc_va as u64) + halt_off).to_le_bytes());
        b[0x8000..0x8000 + 0x100].fill(0);
    }
    vm_arena.call(0x7000);
    let b = vm_arena.bytes();
    let vm_rax = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS + 0 * 8..0x5000 + interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    assert_eq!(vm_rax, expected, "M6 lifted native VM: rax mismatch (vm=0x{:X} native=0x{:X})", vm_rax, expected);

    Ok(())
}

/// v26 (A-2/A-5): self-test for the completed 1:1 lift table.
/// Exercises the newly-supported common forms (reg-reg MOV via the r/m opcodes,
/// imm arithmetic 8/32/64, CMP reg-reg/imm with full SUB flags, TEST 64/16/8,
/// LEA32, MOVZX-reg, MOVSXD, CDQE, PUSH/POP) by lifting a straight-line + one-Jcc
/// function and verifying the interpreter result against a Rust reference. The
/// emulations reuse only already-native-proven opcodes, so the interpreter result
/// implies the native VM path is correct too.
fn run_a2_lift_completion_test() -> Result<()> {
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
    st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK + 8].copy_from_slice(&0x3000u64.to_le_bytes());
    st[interp::STATE_SP..interp::STATE_SP + 8].copy_from_slice(&0xFF8u64.to_le_bytes());
    mem[0x3000 + 0xFF8..0x3000 + 0x1000].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("A2-lift-completion interp failed: {:?}", e))?;
    let rax = u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    let r9 = u64::from_le_bytes(st[interp::STATE_VREGS + 9 * 8..interp::STATE_VREGS + 10 * 8].try_into().unwrap());
    assert_eq!(rax, expected_rax, "A2-lift-completion: rax mismatch (got 0x{:X} want 0x{:X})", rax, expected_rax);
    assert_eq!(r9, expected_r9, "A2-lift-completion: r9 mismatch (got 0x{:X} want 0x{:X})", r9, expected_r9);
    Ok(())
}

fn pass_fail(ok: bool) -> String {
    if ok {
        "PASS".to_string()
    } else {
        "FAIL".to_string()
    }
}


/// [18] A-5 SSE/FPU + conditional + string ops through the interpreter.
/// Lifts a block exercising setcc, cmovcc, sbb, movsd/movups/unpcklpd (XMM file),
/// rep stosq and loopne, then verifies the VM state/memory.
fn run_a5_sse_cond_test() -> Result<()> {
    use crate::vm::lifter::{LiftedInstr, lift_block, diagnose_unsupported};
    use iced_x86::{Instruction, Code, Register, MemoryOperand};
    use crate::vm::interp::STATE_XMM;

    let mut seq: Vec<LiftedInstr> = Vec::new();
    // setcc: al = (ZF) ? 1 : 0  — seed ZF via cmp rax,rax (equal)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Cmp_rm64_r64, Register::RAX, Register::RAX).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with1(Code::Sete_rm8, Register::AL).unwrap()));
    // cmovcc: cmove ecx, edx  (ZF set -> rcx = rdx)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Cmove_r64_rm64, Register::R10, Register::RDX).unwrap()));
    // sbb: r9d = r9d - r8d - CF  (CF=0 from cmp equal)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Sbb_rm32_r32, Register::R9D, Register::R8D).unwrap()));
    // movsd xmm0, [rsi+0x80] ; movsd [rsi+0x40], xmm0
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Movsd_xmm_xmmm64, Register::XMM0, MemoryOperand::with_base_displ(Register::RSI, 0x80)).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Movsd_xmmm64_xmm, MemoryOperand::with_base_displ(Register::RSI, 0x40), Register::XMM0).unwrap()));
    // movups xmm6, [rsi+0x60] ; movups [rsi+0x20], xmm6
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Movups_xmm_xmmm128, Register::XMM6, MemoryOperand::with_base_displ(Register::RSI, 0x60)).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Movups_xmmm128_xmm, MemoryOperand::with_base_displ(Register::RSI, 0x20), Register::XMM6).unwrap()));
    // rep stosq: [rdi] = rax ; rdi += 8 ; rcx-- ... (rcx iterations)
    seq.push(LiftedInstr::plain(Instruction::with_stosq(64, iced_x86::RepPrefixKind::Repe).unwrap()));
    // loopne: rcx-- ; if rcx!=0 && ZF==0 jump to label
    let loop_lbl = 77u32;
    seq.push(LiftedInstr::branch(Instruction::with_branch(Code::Loopne_rel8_64_RCX, 0).unwrap(), loop_lbl));
    seq.push(LiftedInstr::labeled(Instruction::with(Code::Nopd), loop_lbl));
    seq.push(LiftedInstr::plain(Instruction::with(Code::Retnq)));

    // everything must be liftable now
    let bad = diagnose_unsupported(&seq);
    assert!(bad.is_empty(), "A5-sse: unexpected unsupported {:?}", bad);

    let bc = lift_block(&seq, 0)?;
    let halt_off = (bc.len() - 1) as u64;

    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x4000];
    let rsi = 0x1000usize;
    let rdi = 0x2000usize;
    // args
    st[interp::STATE_VREGS + 0*8..][..8].copy_from_slice(&0xAAu64.to_le_bytes()); // rax
    st[interp::STATE_VREGS + 1*8..][..8].copy_from_slice(&2u64.to_le_bytes());    // rcx count
    st[interp::STATE_VREGS + 2*8..][..8].copy_from_slice(&0u64.to_le_bytes());    // rdx
    st[interp::STATE_VREGS + 3*8..][..8].copy_from_slice(&0u64.to_le_bytes());    // rbx
    st[interp::STATE_VREGS + 6*8..][..8].copy_from_slice(&(rsi as u64).to_le_bytes()); // rsi
    st[interp::STATE_VREGS + 7*8..][..8].copy_from_slice(&(rdi as u64).to_le_bytes()); // rdi
    st[interp::STATE_VREGS + 8*8..][..8].copy_from_slice(&5u64.to_le_bytes());    // r8
    st[interp::STATE_VREGS + 10*8..][..8].copy_from_slice(&0xEEu64.to_le_bytes()); // r10
    st[interp::STATE_VREGS + 9*8..][..8].copy_from_slice(&0x20u64.to_le_bytes()); // r9
    // memory: [rsi+0x80] = 8-byte double value ; [rsi+0x60] = 16-byte
    mem[rsi + 0x80..rsi + 0x88].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
    mem[rsi + 0x60..rsi + 0x70].copy_from_slice(&[0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18]);
    // stack for ret
    st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK+8].copy_from_slice(&0x3000u64.to_le_bytes());
    st[interp::STATE_SP..interp::STATE_SP+8].copy_from_slice(&0xFF8u64.to_le_bytes());
    mem[0x3000+0xFF8..0x3000+0x1000].copy_from_slice(&halt_off.to_le_bytes());

    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("A5-sse interp failed: {:?}", e))?;

    // setcc: al should be 1 (ZF set by cmp equal)
    let al = st[interp::STATE_VREGS + 0*8];
    assert_eq!(al, 1, "A5-sse: sete al expected 1 got {}", al);
    // cmovcc: r10 = rdx = 0 (ZF set by cmp rax,rax)
    let r10 = u64::from_le_bytes(st[interp::STATE_VREGS + 10*8..][..8].try_into().unwrap());
    assert_eq!(r10, 0, "A5-sse: cmove r10 expected 0 got {}", r10);
    // sbb r9 = r9 - r8 - 0 = 0x20 - 5 = 0x1B
    let r9 = u64::from_le_bytes(st[interp::STATE_VREGS + 9*8..][..8].try_into().unwrap());
    assert_eq!(r9, 0x1B, "A5-sse: sbb r9 expected 0x1B got 0x{:X}", r9);
    // movsd copy: [rsi+0x40] should now hold the 8-byte value
    let m = u64::from_le_bytes(mem[rsi+0x40..rsi+0x48].try_into().unwrap());
    assert_eq!(m, 0x1122334455667788, "A5-sse: movsd mem copy wrong 0x{:X}", m);
    // movups copy: [rsi+0x20] holds 16 bytes
    assert_eq!(&mem[rsi+0x20..rsi+0x30], &[0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18], "A5-sse: movups mem copy wrong");
    // rep stosq: stores rax (which sete set to 1) twice at rdi, rdi advanced 16
    let w0 = u64::from_le_bytes(mem[rdi..rdi+8].try_into().unwrap());
    let w1 = u64::from_le_bytes(mem[rdi+8..rdi+16].try_into().unwrap());
    assert_eq!(w0, 1, "A5-sse: stosq[0] wrong 0x{:X}", w0);
    assert_eq!(w1, 1, "A5-sse: stosq[1] wrong 0x{:X}", w1);
    let rdi_after = u64::from_le_bytes(st[interp::STATE_VREGS + 7*8..][..8].try_into().unwrap());
    assert_eq!(rdi_after, (rdi + 16) as u64, "A5-sse: stosq rdi advance wrong {}", rdi_after);
    // loopne: rep stosq consumed rcx (2->0); loopne then dec'd it to -1 (u64 wrap).
    // Verifying rcx reflects the loop decrement proves loopne executed.
    let rcx2 = u64::from_le_bytes(st[interp::STATE_VREGS + 1*8..][..8].try_into().unwrap());
    assert_eq!(rcx2, 0xFFFF_FFFF, "A5-sse: loopne left rcx={:X} expected 0xFFFFFFFF", rcx2);
    Ok(())
}


/// [19] M5 multi-block control-flow lift.
/// Builds a loop function, extracts its CFG, lifts with `lift_cfg` (which emits
/// rel32 cross-block branches + block connection), and verifies the interpreter
/// result matches the Rust reference. (Native-harness path is exercised by [14].
/// Here we validate the *multi-block* driver itself through the interpreter.)
fn run_m5_multiblock_test() -> Result<()> {
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
    st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK+8].copy_from_slice(&0x3000u64.to_le_bytes());
    st[interp::STATE_SP..interp::STATE_SP+8].copy_from_slice(&0xFF8u64.to_le_bytes());
    mem[0x3000+0xFF8..0x3000+0x1000].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("M5 interp failed: {:?}", e))?;
    let rax = u64::from_le_bytes(st[interp::STATE_VREGS + 0*8..][..8].try_into().unwrap());
    assert_eq!(rax, want, "M5 lifted interpreter: rax got {} want {}", rax, want);

    Ok(())
}

/// [20] A-2 (v31): 1-operand signed/unsigned multiply-divide + BSWAP.
/// Cross-checks the Rust interpreter against the native x86-64 handlers for the
/// new accumulator-pair opcodes (MUL/IMUL/DIV/IDIV 32/64) and BSWAP (32/64),
/// over random inputs. (div-by-zero is deliberately avoided.)
fn run_a2_muldiv_bswap_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut rng = rand::thread_rng();
    let mut arena = Arena::new(0x30000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x3000;
    let bc_va = arena.base + 0x4000;
    let state_va = arena.base + 0x5000;
    let tramp_va = arena.base + 0x6000;
    let module = build_vm_module(
        code_va as u64, table_va as u64, bc_va as u64, vec![0u8; 128],
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(state_va as u64, code_va as u64, code_va as u64, code_va as u64, tramp_va as u64)?;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x6000..0x6000 + tramp.len()].copy_from_slice(&tramp);
    }

    // run prog: set v0=rax(low), v2=rdx(high) and src vreg, run, compare interp vs native.
    let mut run_prog = |prog: &[u8], rax: u64, rdx: u64, src: u8, sval: u64| -> (u64, u64, u64) {
        // interpreter
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 64];
        st[interp::STATE_VREGS + 0*8..][..8].copy_from_slice(&rax.to_le_bytes());
        st[interp::STATE_VREGS + 2*8..][..8].copy_from_slice(&rdx.to_le_bytes());
        st[interp::STATE_VREGS + (src as usize)*8..][..8].copy_from_slice(&sval.to_le_bytes());
        interp::interpret(&mut st, &mut mem, prog).unwrap();
        let i = (
            u64::from_le_bytes(st[interp::STATE_VREGS+0*8..][..8].try_into().unwrap()),
            u64::from_le_bytes(st[interp::STATE_VREGS+2*8..][..8].try_into().unwrap()),
            u64::from_le_bytes(st[interp::STATE_VREGS+(src as usize)*8..][..8].try_into().unwrap()),
        );
        // native
        {
            let b = arena.bytes();
            b[0x4000..0x4000 + prog.len()].copy_from_slice(prog);
            b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
            b[0x5000 + interp::STATE_VREGS + 0*8..][..8].copy_from_slice(&rax.to_le_bytes());
            b[0x5000 + interp::STATE_VREGS + 2*8..][..8].copy_from_slice(&rdx.to_le_bytes());
            b[0x5000 + interp::STATE_VREGS + (src as usize)*8..][..8].copy_from_slice(&sval.to_le_bytes());
        }
        arena.call(0x6000);
        let b = arena.bytes();
        let sf = 0x5000usize;
        let n = (
            u64::from_le_bytes(b[sf + interp::STATE_VREGS+0*8..][..8].try_into().unwrap()),
            u64::from_le_bytes(b[sf + interp::STATE_VREGS+2*8..][..8].try_into().unwrap()),
            u64::from_le_bytes(b[sf + interp::STATE_VREGS+(src as usize)*8..][..8].try_into().unwrap()),
        );
        assert_eq!(i, n, "[20] interp vs native mismatch\n{}", crate::vm::bytecode::disassemble(prog));
        i
    };

    // MUL32: EDX:EAX = EAX * src32. src = v1.
    for _ in 0..20 {
        let (a, b) = (rng.next_u32(), rng.next_u32());
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, b);
        bc.mul_r(OP_MUL_R_R32, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a as u64, 0, 1, b as u64);
        let p = (a as u64) * (b as u64);
        assert_eq!((lo, hi), (p as u32 as u64, (p >> 32) as u64), "[20] MUL32 a={:X} b={:X}", a, b);
    }
    // MUL64
    for _ in 0..20 {
        let (a, b) = (rng.next_u64(), rng.next_u64());
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(1, b);
        bc.mul_r(OP_MUL_R_R64, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a, 0, 1, b);
        let p = (a as u128) * (b as u128);
        assert_eq!((lo, hi), (p as u64, (p >> 64) as u64), "[20] MUL64 a={:X} b={:X}", a, b);
    }
    // IMUL32 (signed): product = (i32)a * (i32)b, low32 in EAX, high32 in EDX
    for _ in 0..20 {
        let (a, b) = (rng.next_u32(), rng.next_u32());
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, b);
        bc.mul_r(OP_IMUL1_R_R32, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a as u64, 0, 1, b as u64);
        let p = (a as i32 as i64) * (b as i32 as i64);
        assert_eq!((lo, hi), (p as u32 as u64, (p >> 32) as u32 as u64), "[20] IMUL32 a={:X} b={:X}", a, b);
    }
    // IMUL64 (signed)
    for _ in 0..20 {
        let (a, b) = (rng.next_u64(), rng.next_u64());
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(1, b);
        bc.mul_r(OP_IMUL1_R_R64, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a, 0, 1, b);
        let p = (a as i64 as i128) * (b as i64 as i128);
        assert_eq!((lo, hi), (p as u64, (p >> 64) as u64), "[20] IMUL64 a={:X} b={:X}", a, b);
    }
    // DIV32: EAX = EDX:EAX / src32, EDX = remainder. Constrain hi (EDX) small and
    // divisor top-bit-set so the quotient always fits 32 bits (no x86 #DE trap).
    for _ in 0..20 {
        let lo = rng.next_u32();
        let hi = rng.next_u32() & 0xFFFF; // small high half
        let d = rng.next_u32() | 0x8000_0000; // d >= 2^31 > hi
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, d);
        bc.mul_r(OP_DIV_R_R32, 1);
        bc.halt();
        let dividend = ((hi as u64) << 32) | (lo as u64);
        let (q, r, _) = run_prog(&bc.finish(), lo as u64, hi as u64, 1, d as u64);
        assert_eq!((q, r), ((dividend / d as u64) as u32 as u64, (dividend % d as u64) as u32 as u64), "[20] DIV32 hi={:X} d={:X}", hi, d);
    }
    // DIV64: same constraint — hi small, divisor top-bit-set -> quotient fits 64 bits.
    for _ in 0..20 {
        let lo = rng.next_u64();
        let hi = rng.next_u64() & 0xFFFF; // small high half
        let d = rng.next_u64() | (1u64 << 63); // d >= 2^63 > hi
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(1, d);
        bc.mul_r(OP_DIV_R_R64, 1);
        bc.halt();
        let dividend = ((hi as u128) << 64) | (lo as u128);
        let (q, r, _) = run_prog(&bc.finish(), lo, hi, 1, d);
        assert_eq!((q, r), ((dividend / d as u128) as u64, (dividend % d as u128) as u64), "[20] DIV64 hi={:X} d={:X}", hi, d);
    }
    // IDIV32 (signed): keep the dividend a small sign-extended value so the
    // quotient always fits i32 (no #DE). dv = small signed; hi:lo = sign-extend.
    for _ in 0..20 {
        let dv = (rng.next_u32() & 0xFFFF) as i16 as i32; // small signed
        let lo = dv as u32;
        let hi = ((dv as i64) >> 32) as u32; // sign extension into high half
        let d = (rng.next_u32() as i32) | 1; // nonzero, any sign
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, d as u32);
        bc.mul_r(OP_IDIV_R_R32, 1);
        bc.halt();
        let dividend = (((hi as u64) << 32) | (lo as u64)) as i64;
        let (q, r, _) = run_prog(&bc.finish(), lo as u64, hi as u64, 1, d as u32 as u64);
        let qe = (dividend / d as i64) as u32 as u64;
        let re = (dividend % d as i64) as u32 as u64;
        assert_eq!((q, r), (qe, re), "[20] IDIV32 dividend={:X} d={:X}", dividend as u64, d);
    }
    // IDIV64 (signed): small sign-extended dividend -> quotient fits i64.
    for _ in 0..20 {
        let dv = (rng.next_u64() & 0xFFFF) as i16 as i64; // small signed
        let lo = dv as u64;
        let hi = ((dv as i128) >> 64) as u64; // sign extension into high half
        let d = (rng.next_u64() as i64) | 1; // nonzero, any sign
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(1, d as u64);
        bc.mul_r(OP_IDIV_R_R64, 1);
        bc.halt();
        let dividend = (((hi as u128) << 64) | (lo as u128)) as i128;
        let (q, r, _) = run_prog(&bc.finish(), lo, hi, 1, d as u64);
        let qe = (dividend / d as i128) as u64;
        let re = (dividend % d as i128) as u64;
        assert_eq!((q, r), (qe, re), "[20] IDIV64 dividend={:X} d={:X}", dividend as u64, d);
    }
    // BSWAP32 / BSWAP64 (src = the register itself)
    for _ in 0..20 {
        let v = rng.next_u32();
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, v);
        bc.bswap_r(OP_BSWAP_R32, 1);
        bc.halt();
        let (_, _, s) = run_prog(&bc.finish(), 0, 0, 1, v as u64);
        assert_eq!(s, v.swap_bytes() as u64, "[20] BSWAP32 v={:X}", v);
    }
    for _ in 0..20 {
        let v = rng.next_u64();
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(1, v);
        bc.bswap_r(OP_BSWAP_R64, 1);
        bc.halt();
        let (_, _, s) = run_prog(&bc.finish(), 0, 0, 1, v);
        assert_eq!(s, v.swap_bytes(), "[20] BSWAP64 v={:X}", v);
    }
    Ok(())
}

/// [21] A-2/A-5 잔여 (v32): 8/16-bit arithmetic + JCXZ/JECXZ + rep movs/cmps.
/// Lifts a block exercising the new narrow-arith lowerings and a JCXZ branch, runs
/// it through the reference interpreter, and compares against a Rust reference.
/// Then lifts and runs `rep movsd`/`rep cmpsd` against memory and verifies the
/// copy / compare result. Because all new lowerings reuse already-native-proven
/// opcodes (ADD/SUB/XOR/AND/OR + movzx/mov + jcc), interpreter correctness implies
/// the native VM path is correct too.
fn run_a2a5_lift_residual_test() -> Result<()> {
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
    st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK + 8].copy_from_slice(&0x3000u64.to_le_bytes());
    st[interp::STATE_SP..interp::STATE_SP + 8].copy_from_slice(&0xFF8u64.to_le_bytes());
    let halt_off = (bc.len() - 1) as u64;
    mem[0x3000 + 0xFF8..0x3000 + 0x1000].copy_from_slice(&halt_off.to_le_bytes());
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
    // operands). Decode from the raw opcode byte instead.
    let mseq = {
        use iced_x86::{Decoder, DecoderOptions};
        let raw = [0xA5u8]; // MOVSD m32, m32 (64-bit mode)
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
        let raw = [0xA7u8]; // CMPSD m32, m32 (64-bit mode)
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

/// [22] A-2 (v33): 1-op MUL/IMUL/DIV/IDIV 8/16-bit width.
/// Cross-checks the Rust interpreter against the native x86-64 handlers for the new
/// byte/word accumulator-pair opcodes (MUL8/16, IMUL8/16, DIV8/16, IDIV8/16) over
/// random inputs. The harness builds the VM module once and runs each tiny program
/// through both the interpreter and the native handler loop, asserting identical
/// (rax, rdx, src) state. Division inputs are constrained so the quotient fits the
/// destination width (no x86 #DE trap).
fn run_a2_muldiv_8_16_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut rng = rand::thread_rng();
    let mut arena = Arena::new(0x30000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x3000;
    let bc_va = arena.base + 0x4000;
    let state_va = arena.base + 0x5000;
    let tramp_va = arena.base + 0x6000;
    let module = build_vm_module(
        code_va as u64, table_va as u64, bc_va as u64, vec![0u8; 128],
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(state_va as u64, code_va as u64, code_va as u64, code_va as u64, tramp_va as u64)?;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x6000..0x6000 + tramp.len()].copy_from_slice(&tramp);
    }

    let mut run_prog = |prog: &[u8], rax: u64, rdx: u64, src: u8, sval: u64| -> (u64, u64, u64) {
        // interpreter
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 64];
        st[interp::STATE_VREGS + 0*8..][..8].copy_from_slice(&rax.to_le_bytes());
        st[interp::STATE_VREGS + 2*8..][..8].copy_from_slice(&rdx.to_le_bytes());
        st[interp::STATE_VREGS + (src as usize)*8..][..8].copy_from_slice(&sval.to_le_bytes());
        interp::interpret(&mut st, &mut mem, prog).unwrap();
        let i = (
            u64::from_le_bytes(st[interp::STATE_VREGS+0*8..][..8].try_into().unwrap()),
            u64::from_le_bytes(st[interp::STATE_VREGS+2*8..][..8].try_into().unwrap()),
            u64::from_le_bytes(st[interp::STATE_VREGS+(src as usize)*8..][..8].try_into().unwrap()),
        );
        // native
        {
            let b = arena.bytes();
            b[0x4000..0x4000 + prog.len()].copy_from_slice(prog);
            b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
            b[0x5000 + interp::STATE_VREGS + 0*8..][..8].copy_from_slice(&rax.to_le_bytes());
            b[0x5000 + interp::STATE_VREGS + 2*8..][..8].copy_from_slice(&rdx.to_le_bytes());
            b[0x5000 + interp::STATE_VREGS + (src as usize)*8..][..8].copy_from_slice(&sval.to_le_bytes());
        }
        arena.call(0x6000);
        let b = arena.bytes();
        let sf = 0x5000usize;
        let n = (
            u64::from_le_bytes(b[sf + interp::STATE_VREGS+0*8..][..8].try_into().unwrap()),
            u64::from_le_bytes(b[sf + interp::STATE_VREGS+2*8..][..8].try_into().unwrap()),
            u64::from_le_bytes(b[sf + interp::STATE_VREGS+(src as usize)*8..][..8].try_into().unwrap()),
        );
        assert_eq!(i, n, "[22] interp vs native mismatch\n{}", crate::vm::bytecode::disassemble(prog));
        i
    };

    // MUL8: AX = AL * src8 (unsigned), zero-extended into v0; v2 unchanged.
    for _ in 0..25 {
        let (a, s) = (rng.next_u64() & 0xFF, rng.next_u64() & 0xFF);
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, s as u32);
        bc.mul_r(OP_MUL_R_R8, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a, 0xAAAA_AAAA_AAAA_AAAA, 1, s);
        let expect = ((a as u16) * (s as u16)) as u64;
        assert_eq!(lo, expect, "[22] MUL8 a={:X} s={:X}", a, s);
        assert_eq!(hi, 0xAAAA_AAAA_AAAA_AAAA, "[22] MUL8 must not touch RDX");
    }
    // IMUL8 (signed)
    for _ in 0..25 {
        let (a, s) = (rng.next_u64() & 0xFF, rng.next_u64() & 0xFF);
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, s as u32);
        bc.mul_r(OP_IMUL1_R_R8, 1);
        bc.halt();
        let (lo, _, _) = run_prog(&bc.finish(), a, 0, 1, s);
        let expect = ((a as u8 as i8 as i16) * (s as u8 as i8 as i16)) as u16 as u64;
        assert_eq!(lo, expect, "[22] IMUL8 a={:X} s={:X}", a, s);
    }
    // MUL16: DX:AX = AX * src16; v0=low16, v2=high16 (zero-extended).
    for _ in 0..25 {
        let (a, s) = (rng.next_u64() & 0xFFFF, rng.next_u64() & 0xFFFF);
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, s as u32);
        bc.mul_r(OP_MUL_R_R16, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a, 0, 1, s);
        let p = ((a as u32) * (s as u32)) as u64;
        assert_eq!((lo, hi), (p & 0xFFFF, (p >> 16) & 0xFFFF), "[22] MUL16 a={:X} s={:X}", a, s);
    }
    // IMUL16 (signed)
    for _ in 0..25 {
        let (a, s) = (rng.next_u64() & 0xFFFF, rng.next_u64() & 0xFFFF);
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, s as u32);
        bc.mul_r(OP_IMUL1_R_R16, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a, 0, 1, s);
        let p = (a as u16 as i16 as i32) * (s as u16 as i16 as i32);
        let pu = p as u32 as u64;
        assert_eq!((lo, hi), (pu & 0xFFFF, (pu >> 16) & 0xFFFF), "[22] IMUL16 a={:X} s={:X}", a, s);
    }
    // DIV8: AL = AX / src8; AH = rem. Constrain divisor high so quotient fits 8 bits.
    for _ in 0..25 {
        let ax = rng.next_u64() & 0xFFFF;         // AX dividend
        let d = rng.next_u64() & 0xFF;            // src8
        if d == 0 { continue; }
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, d as u32);
        bc.mul_r(OP_DIV_R_R8, 1);
        bc.halt();
        let q = (ax as u16) / (d as u8 as u16);
        if q > 0xFF { continue; }                  // would #DE; skip
        let r = (ax as u16) % (d as u8 as u16);
        let expect = ((q & 0xFF) as u64) | (((r & 0xFF) as u64) << 8);
        let (lo, _, _) = run_prog(&bc.finish(), ax, 0, 1, d);
        assert_eq!(lo, expect, "[22] DIV8 ax={:X} d={:X}", ax, d);
    }
    // DIV16: AX = DX:AX / src16; DX = rem. Constrain dividend high so quotient fits 16.
    for _ in 0..25 {
        let lo = rng.next_u64() & 0xFFFF;
        let hi = rng.next_u64() & 0xFF;            // small high half
        let d = rng.next_u64() & 0xFFFF;
        if d == 0 { continue; }
        let dividend = (hi << 16) | lo;
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, d as u32);
        bc.mul_r(OP_DIV_R_R16, 1);
        bc.halt();
        let q = dividend / d;
        if q > 0xFFFF { continue; }
        let r = dividend % d;
        let (got_lo, got_hi, _) = run_prog(&bc.finish(), lo, hi, 1, d);
        assert_eq!((got_lo, got_hi), (q, r), "[22] DIV16 lo={:X} hi={:X} d={:X}", lo, hi, d);
    }
    // IDIV8 (signed): AL = AX / src8; AH = rem, where AX is a signed i16.
    for _ in 0..25 {
        let a = rng.next_u64() & 0xFFFF;
        let d = rng.next_u64() & 0xFF;
        if d == 0 { continue; }
        let a16 = a as u16 as i16;
        let d8 = d as u8 as i8 as i16;
        let q = a16 / d8;
        if q < -128 || q > 127 { continue; }
        let r = a16 % d8;
        let expect = ((q as i8 as u8) as u64) | (((r as i8 as u8) as u64) << 8);
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, d as u32);
        bc.mul_r(OP_IDIV_R_R8, 1);
        bc.halt();
        let (lo, _, _) = run_prog(&bc.finish(), a, 0, 1, d);
        assert_eq!(lo, expect, "[22] IDIV8 a={:X} d={:X}", a, d);
    }
    // IDIV16 (signed): AX = DX:AX / src16; DX = rem (32-bit signed dividend).
    for _ in 0..25 {
        let lo = rng.next_u64() & 0xFFFF;
        let hi = rng.next_u64() & 0xFFFF;
        let d = rng.next_u64() & 0xFFFF;
        if d == 0 { continue; }
        let dividend = (hi << 16 | lo) as u32 as i32;
        let ds = d as u16 as i16 as i32;
        if dividend == i32::MIN && ds == -1 { continue; }
        let q = dividend / ds;
        if q < -32768 || q > 32767 { continue; }
        let r = dividend % ds;
        let (got_lo, got_hi, _) = run_prog(&bc_mk(d as u32), lo, hi, 1, d);
        assert_eq!((got_lo, got_hi),
            ((q as i16 as u16) as u64, (r as i16 as u16) as u64),
            "[22] IDIV16 lo={:X} hi={:X} d={:X}", lo, hi, d);
    }

    Ok(())
}

fn bc_mk(d: u32) -> Vec<u8> {
    use crate::vm::bytecode::*;
    let mut b = BytecodeBuilder::new();
    b.mov_r_imm32(1, d);
    b.mul_r(OP_IDIV_R_R16, 1);
    b.halt();
    b.finish()
}

/// [23] M6 Phase-2 (v34): OEP→VM entry 전환 데이터 경로 — 원본 .text의 도달 가능한
/// CFG 전체를 하나의 VM 프로그램(lift_cfg)으로 lift 해 interpreter가 네이티브 x86
/// 참조 실행과 동일한 결과를 내는지 검증한다.
///
/// f(rcx=n, rbx=incr): rax = sum of incr over n iterations (loop with jcc/jmp),
/// then 8/16-bit arith and a JCXZ skip. This exercises the *whole-CFG* path that the
/// boot integration (OEP→VM entry) will consume: multi-block control flow, 8/16-bit
/// arithmetic, and JCXZ are all lifted as one connected VM program.
fn run_m6_phase2_lift_test() -> Result<()> {
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
    let lift = lift_program_cfg(&native, base, base, &[], 0)?;
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
    st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK+8].copy_from_slice(&0x3000u64.to_le_bytes());
    st[interp::STATE_SP..interp::STATE_SP+8].copy_from_slice(&0xFF8u64.to_le_bytes());
    mem[0x3000+0xFF8..0x3000+0x1000].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, bc).map_err(|e| anyhow!("[23] interp failed: {:?}", e))?;
    let rax = u64::from_le_bytes(st[interp::STATE_VREGS+0*8..][..8].try_into().unwrap());
    assert_eq!(rax, want, "[23] whole-CFG lifted interpreter: rax got {} want {}", rax, want);

    Ok(())
}

/// [24] B-3 (v35): switch/테이블 점프 → VM 내부 디스패치.
/// A compiler switch jump table `jmp [rax*8 + table]` (Jmp_rm64, memory target) is
/// resolved to (case_value, target_block_va) pairs and dispatched *inside the VM* via
/// a compare-and-jump chain (lift_cfg_switch). Runs the interpreter for each case value
/// and verifies it reaches the correct case block — proving switch jumps no longer leave
/// the VM through the native bridge. The chain uses only mov/cmp/jcc32 (all proven native),
/// so interpreter correctness implies the native VM path.
fn run_switch_lift_test() -> Result<()> {
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
        st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK+8].copy_from_slice(&0x3000u64.to_le_bytes());
        st[interp::STATE_SP..interp::STATE_SP+8].copy_from_slice(&0xFF8u64.to_le_bytes());
        mem[0x3000+0xFF8..0x3000+0x1000].copy_from_slice(&halt_off.to_le_bytes());
        interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("[24] interp idx={} failed: {:?}", idx, e))?;
        let rax = u64::from_le_bytes(st[interp::STATE_VREGS+0*8..][..8].try_into().unwrap());
        assert_eq!(rax, *want, "[24] switch dispatch idx={}: rax got 0x{:X} want 0x{:X}", idx, rax, want);
    }

    Ok(())
}

/// [25] C-1 (v36): VM 메모리 모델 — region 스키마, address→region 해석, bounds 검증.
fn run_mem_model_test() -> Result<()> {
    use crate::vm::mem_model::{MemKind, MemRegion, VmMemoryModel};

    let mut m = VmMemoryModel::new();
    m.add(MemRegion::new(0x140001000, 0x2000, MemKind::Code, 0b111));
    m.add(MemRegion::new(0x140003000, 0x1000, MemKind::ReadOnly, 0b101));
    m.add(MemRegion::new(0x140004000, 0x1000, MemKind::Data, 0b011));
    m.add(MemRegion::new(0x70000000, 0x10000, MemKind::Stack, 0b011));
    m.add(MemRegion::new(0x80000000, 0x100000, MemKind::Heap, 0b011));
    m.add(MemRegion::new(0x7FFE0000, 0x1000, MemKind::System, 0b101)); // PEB/TEB area

    // resolve in/out
    assert_eq!(m.resolve(0x140001000).map(|r| r.kind), Some(MemKind::Code));
    assert_eq!(m.resolve(0x140002FFF).map(|r| r.kind), Some(MemKind::Code));
    assert_eq!(m.resolve(0x140003000).map(|r| r.kind), Some(MemKind::ReadOnly));
    assert!(m.resolve(0x140005000).is_none()); // gap after .data
    assert_eq!(m.resolve(0x7FFE0100).map(|r| r.kind), Some(MemKind::System));
    assert!(!m.is_mapped(0x1_0000_0000));

    // region-relative -> absolute
    assert_eq!(m.abs(0x140001000, 0x20), Some(0x140001020));
    assert_eq!(m.abs(0x140001000, 0x2000), None); // OOB

    // access bounds
    assert!(m.access_ok(0x140001000, 0x100));
    assert!(!m.access_ok(0x140002FF0, 0x20));

    // kind_at
    assert_eq!(m.kind_at(0x140004000), Some(MemKind::Data));
    Ok(())
}

/// [26] M6 Phase-2 (v38): 마지막 배선의 실행 코어 — 원본 프로그램을 lift 한 **단일 VM 프로그램**을
/// **네이티브 VM**(build_vm_module + trampoline + arena)으로 실행해, interpreter·네이티브 VM·네이티브
/// x86 참조 세 경로가 모두 동일한 결과를 내는지 검증한다. 이것이 부트 스텁이 디스패치할 정확한
/// 코드 경로다 (OEP→VM entry 전환의 실행 증명).
fn run_m6_phase2_native_program_test() -> Result<()> {
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
    let lift = lift_program_cfg(&native, base, base, &[], 0)?;
    let bc = &lift.bytecode;
    assert!(!bc.is_empty(), "[26] whole-CFG lift empty");
    assert!(lift.unsupported.is_empty(), "[26] unexpected unsupported {:?}", lift.unsupported);
    let halt_off = (bc.len() - 1) as u64;

    // 3) Interpreter run.
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x4000];
    st[interp::STATE_VREGS + 1*8..][..8].copy_from_slice(&(n as u64).to_le_bytes());
    st[interp::STATE_VREGS + 3*8..][..8].copy_from_slice(&incr.to_le_bytes());
    st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK+8].copy_from_slice(&0x3000u64.to_le_bytes());
    st[interp::STATE_SP..interp::STATE_SP+8].copy_from_slice(&0xFF8u64.to_le_bytes());
    mem[0x3000+0xFF8..0x3000+0x1000].copy_from_slice(&halt_off.to_le_bytes());
    interp::interpret(&mut st, &mut mem, bc).map_err(|e| anyhow!("[26] interp failed: {:?}", e))?;
    let interp_rax = u64::from_le_bytes(st[interp::STATE_VREGS+0*8..][..8].try_into().unwrap());
    assert_eq!(interp_rax, want, "[26] lifted interpreter: rax got {} want {}", interp_rax, want);

    // 4) Native VM execution of the lifted program (the M6 Phase-2 dispatch path).
    let mut varena = Arena::new(0x40000)?;
    let (vc, vt, vb, vs, vsz, vtr, vdata) = (
        varena.base + 0x1000, varena.base + 0x3000, varena.base + 0x4000,
        varena.base + 0x5000, varena.base + 0x6000, varena.base + 0x7000, varena.base + 0x8000,
    );
    let module = build_vm_module(vc as u64, vt as u64, vb as u64, bc.clone(), handlers::EntryMode::Ksa)?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vs as u64, vdata as u64, vdata as u64, vc as u64, vtr as u64)?;
    {
        let b = varena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x7000..0x7000 + tramp.len()].copy_from_slice(&tramp);
        b[0x4000..0x4000 + bc.len()].copy_from_slice(bc);
        b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
        b[0x5000 + interp::STATE_VREGS + 1*8..][..8].copy_from_slice(&(n as u64).to_le_bytes());
        b[0x5000 + interp::STATE_VREGS + 3*8..][..8].copy_from_slice(&incr.to_le_bytes());
        b[0x5000 + interp::STATE_PTR_STACK..0x5000 + interp::STATE_PTR_STACK+8].copy_from_slice(&(vsz as u64).to_le_bytes());
        b[0x5000 + interp::STATE_SP..0x5000 + interp::STATE_SP+8].copy_from_slice(&0xFF8u64.to_le_bytes());
        b[0x6000..0x6000 + 0x1000].fill(0);
        b[0x6000 + 0xFF8..0x6000 + 0x1000].copy_from_slice(&((vb as u64) + halt_off).to_le_bytes());
        b[0x8000..0x8000 + 0x100].fill(0);
    }
    varena.call(0x7000);
    let b = varena.bytes();
    let vm_rax = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS + 0*8..][..8].try_into().unwrap());
    assert_eq!(vm_rax, want, "[26] native VM program execution: rax got {} want {}", vm_rax, want);

    Ok(())
}

/// [27] M7 (v41): on-demand 재암호화(anti-dump) — RC4 청크를 복호화→사용→재암호화하여
/// 반환 시점에 다시 암호문이 되고, "사용 직후 덤프"가 평문을 노출하지 않는지 검증한다.
fn run_m7_ondemand_reencrypt_test() -> Result<()> {
    use crate::pipeline::ondemand::{Rc4, process_on_demand, simulate_dump};

    let key = b"m7-ondemand-key-0x9E3779B9";
    let plain: &[u8] = b"The original .text must not be plaintext at dump time. 0123456789abcdef";
    // file-state ciphertext
    let mut cipher = plain.to_vec();
    let mut rc4 = Rc4::new(key);
    rc4.crypt(&mut cipher);
    assert_ne!(cipher, plain, "[27] cipher should differ from plain");

    // on-demand: decrypt→use→re-encrypt leaves it encrypted (anti-dump)
    assert!(simulate_dump(plain, &cipher, key), "[27] after use, dump must be encrypted");

    // use callback sees plaintext; after on-demand the buffer is ciphertext again
    let mut buf = cipher.clone();
    let mut seen = Vec::new();
    let blen = buf.len();
    process_on_demand(&mut buf, blen, key, |p| seen.extend_from_slice(p));
    assert_eq!(seen, plain, "[27] use callback must observe plaintext");
    assert_ne!(buf, plain, "[27] buffer must be re-encrypted after on-demand");

    // round-trip: decrypt again recovers plaintext (functional correctness kept)
    let mut rc4b = Rc4::new(key);
    rc4b.crypt(&mut buf);
    assert_eq!(buf, plain, "[27] re-decrypt must recover plaintext");

    Ok(())
}

/// [28] M8 (v45): VM handler-table MBA 난독화 검증.
///
/// 동일한 KSA 바이트코드를 (a) reference interpreter, (b) **plaintext** 네이티브 VM,
/// (c) **MBA-obfuscated** 네이티브 VM 세 경로로 실행해 결과가 모두 동일함을 검증한다.
/// 또한 MBA 모듈의 handler 테이블이 plaintext 모듈과 달라야 하고(주소가 XOR-암호화됨),
/// MBA 디스패치가 임베디드된 `a`, `b`에서 MBA 항등식 `a+b==(a^b)+2·(a&b)`로 K를 유도해
/// 정확히 복호화함으로써 프로그램이 오작동 없이 동작함을 증명한다.
fn run_m8_handler_mba_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut rng = rand::thread_rng();
    let mut seed_masked = [0u8; 256];
    rng.fill_bytes(&mut seed_masked);
    let (k1, k2, k3) = (rng.next_u32(), rng.next_u32(), rng.next_u32());

    // Reference KSA (pure Rust).
    let mut expected = [0u8; 256];
    ksa::reference_ksa(&seed_masked, k1, k2, k3, &mut expected);

    // Lift the KSA to bytecode.
    let seq = ksa::build_ksa_instructions(0, k1, k2, k3);
    let bc = lifter::lift_ksa(&seq)?;

    // (a) Interpreter.
    {
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x2000];
        mem[0x1000..0x1000 + 256].copy_from_slice(&seed_masked);
        st[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
            .copy_from_slice(&(0x100usize as u64).to_le_bytes());
        st[interp::STATE_PTR_SEED..interp::STATE_PTR_SEED + 8]
            .copy_from_slice(&(0x1000usize as u64).to_le_bytes());
        interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("[28] interp failed: {:?}", e))?;
        assert_eq!(&mem[0x100..0x100 + 256], &expected[..], "[28] interpreter mismatch");
    }

    // Helper: run `bc` through a native VM module. `use_mba` selects the MBA-obfuscated
    // handler-table builder (which derives K at runtime and XOR-decrypts handler entries)
    // vs the plaintext builder. The module is built with the *real* arena VAs so the entry
    // stub's r9/r10 point at the actual bytecode/table. Returns S-box match.
    let run_module = |use_mba: bool| -> Result<bool> {
        let mut arena = Arena::new(0x20000)?;
        let sbox_va = arena.base + 0x2000;
        let seed_va = arena.base + 0x3000;
        let code_va = arena.base + 0x5000;
        let table_va = arena.base + 0x7000;
        let bc_va = arena.base + 0x8000;
        let state_va = arena.base + 0x9000;
        let vsbox_va = arena.base + 0xA000;
        let tramp_va = arena.base + 0xB000;
        let module = if use_mba {
            build_vm_module_mba(code_va as u64, table_va as u64, bc_va as u64, bc.clone(), handlers::EntryMode::Ksa)?
        } else {
            build_vm_module(code_va as u64, table_va as u64, bc_va as u64, bc.clone(), handlers::EntryMode::Ksa)?
        };
        handlers::validate_vm_code(&module.code)?;
        let tramp = encode_trampoline(state_va as u64, vsbox_va as u64, seed_va as u64, code_va as u64, tramp_va as u64)?;
        {
            let b = arena.bytes();
            b[0x2000..0x2000 + 256].fill(0);
            b[0x3000..0x3000 + 256].copy_from_slice(&seed_masked);
            b[0x5000..0x5000 + module.code.len()].copy_from_slice(&module.code);
            b[0x7000..0x7000 + module.table.len()].copy_from_slice(&module.table);
            b[0x8000..0x8000 + module.bytecode.len()].copy_from_slice(&module.bytecode);
            b[0x9000..0x9000 + VM_STATE_SIZE].fill(0);
            b[0xA000..0xA000 + 256].fill(0);
            b[0xB000..0xB000 + tramp.len()].copy_from_slice(&tramp);
        }
        arena.call(0xB000);
        Ok(arena.bytes()[0xA000..0xA000 + 256] == expected[..])
    };

    // (b) Plaintext native VM.
    assert!(run_module(false)?, "[28] plaintext native VM mismatch");

    // (c) MBA-obfuscated native VM.
    assert!(run_module(true)?, "[28] MBA native VM mismatch");

    // Handler table must actually be obfuscated: build both modules at the same
    // fixed VAs and confirm the MBA table differs from the plaintext table (handler
    // absolute addresses are XOR-encrypted, not stored in the clear).
    let (pc, pt, pb) = (0x1000u64, 0x3000u64, 0x4000u64);
    let plain = build_vm_module(pc, pt, pb, bc.clone(), handlers::EntryMode::Ksa)?;
    let mba = build_vm_module_mba(pc, pt, pb, bc.clone(), handlers::EntryMode::Ksa)?;
    assert_ne!(mba.table, plain.table, "[28] MBA table must differ from plaintext table");
    assert_ne!(
        &mba.table[0..8],
        &plain.table[0..8],
        "[28] MBA first handler entry must be XOR-masked"
    );

    Ok(())
}


/// v49: 8/16/32/64-bit atomic memory cmpxchg round-trip (interp == native).
/// Exercises OP_CMPXCHG_MEM8/16/32/64_A. For each width: init [addr], expected in
/// RAX (v0), new value in a src vreg. Verifies the success case writes mem + sets
/// ZF, and the stale-expected case leaves mem unchanged and loads [addr] into the
/// operand-width bytes of v0. Includes a byte-width case where RAX has dirty upper
/// bits and the low byte matches — under the old emulation that always took the
/// "not equal" branch; the fixed handler compares only AL.

/// v49: 8/16/32/64-bit atomic memory cmpxchg — interpreter round-trip.
/// Exercises OP_CMPXCHG_MEM8/16/32/64_A in the reference interpreter (pure Rust,
/// no native harness): for each width init [addr], expected in RAX (v0), new value
/// in a src vreg; verifies the success case writes mem + sets ZF, the stale-
/// expected case leaves mem unchanged and loads [addr] into the operand-width
/// bytes of v0, and a byte CAS with dirty upper RAX bits still succeeds (the old
/// 8/16 emulation compared the full 32-bit register and always failed). Also
/// guards the 64-bit path (previously truncated expected/cur to u32).
///
/// NOTE: the native handler path is not exercised here — the project's self-test
/// native VM harness cannot run cmpxchg handlers at all (the pre-existing 32-bit
/// cmpxchg also faults there), so this validates the interpreter semantics and
/// the fix's logic; the native 8/16 handlers mirror the working 32/64 handlers.

/// v49: 8/16/32/64-bit atomic memory cmpxchg — interp == native round-trip.
/// Exercises OP_CMPXCHG_MEM8/16/32/64_A through BOTH the reference interpreter and
/// the native VM (handler table placed in the arena, state vregs seeded), mirroring
/// the v48 XCHG/XADD self-test. Verifies the success case writes mem + sets ZF, the
/// stale-expected case leaves mem unchanged and loads [addr] into the operand-width
/// bytes of v0, and a byte CAS with dirty upper RAX bits still succeeds (the old
/// 8/16 emulation compared the full 32-bit register and always failed -> the Rust
/// Once byte flag never reached COMPLETE -> `f.take().unwrap()` panic). Also guards
/// the 64-bit path (previously truncated expected/cur to u32).
fn run_m4_cmpxchg_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut varena = Arena::new(0x40000)?;
    let (vc, vt, vb, vs, vtr, vdata) = (
        varena.base + 0x1000,
        varena.base + 0x3000,
        varena.base + 0x4000,
        varena.base + 0x5000,
        varena.base + 0x7000,
        varena.base + 0x8000,
    );
    let module = build_vm_module(
        vc as u64,
        vt as u64,
        vb as u64,
        vec![0u8; 128],
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vs as u64, vdata as u64, vdata as u64, vc as u64, vtr as u64)?;
    {
        let b = varena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x3000..0x3000 + module.table.len()].copy_from_slice(&module.table);
        b[0x7000..0x7000 + tramp.len()].copy_from_slice(&tramp);
    }
    let vbase = varena.base as u64;

    // (op, width, mem_init, expected(RAX), new(src), mem_after)
    let cases: &[(u8, usize, u64, u64, u64, u64)] = &[
        (OP_CMPXCHG_MEM8_A, 1, 0x11, 0x11, 0x22, 0x22), // clean success
        // byte CAS with DIRTY upper RAX bits, low byte matches -> must still succeed
        (OP_CMPXCHG_MEM8_A, 1, 0x11, 0x1122_3311, 0x22, 0x22),
        (OP_CMPXCHG_MEM8_A, 1, 0x11, 0x99, 0x22, 0x11), // stale expected -> no write
        (OP_CMPXCHG_MEM16_A, 2, 0x1122, 0x1122, 0x3344, 0x3344),
        (OP_CMPXCHG_MEM32_A, 4, 0x1122_3344, 0x1122_3344, 0x5566_7788, 0x5566_7788),
        (OP_CMPXCHG_MEM64_A, 8, 0x0102_0304_0506_0708, 0x0102_0304_0506_0708, 0x0a0b_0c0d_0e0f_1011, 0x0a0b_0c0d_0e0f_1011),
        (OP_CMPXCHG_MEM64_A, 8, 0x0102_0304_0506_0708, 0x0102_0304_0506_0709, 0x0a0b_0c0d_0e0f_1011, 0x0102_0304_0506_0708),
    ];

    for (op, width, mem_init, expected, new, mem_after) in cases {
        let mask: u64 = if *width == 8 { u64::MAX } else { (1u64 << (*width * 8)) - 1 };
        // bytecode: cmpxchg [v15], v14; halt  (addr/expected/new seeded in the state).
        let mut b = BytecodeBuilder::new();
        b.mem_cmpxchg_a(*op, 15, 14);
        b.halt();
        let prog = b.finish();
        let init_bytes: [u8; 8] = mem_init.to_le_bytes();

        // ---- interpreter (addr v15 = 0x8000 in the flat mem buffer) ----
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x10000];
        mem[0x8000..0x8000 + *width].copy_from_slice(&init_bytes[..*width]);
        for (v, x) in [(15usize, 0x8000u64), (0usize, *expected), (14usize, *new)] {
            let off = interp::STATE_VREGS + v * 8;
            st[off..off + 8].copy_from_slice(&x.to_le_bytes());
        }
        interp::interpret(&mut st, &mut mem, &prog)
            .map_err(|e| anyhow!("cmpxchg interp failed (op={}): {:?}", op, e))?;
        let v0_i = u64::from_le_bytes(st[interp::STATE_VREGS..interp::STATE_VREGS + 8].try_into().unwrap());
        let zf_i = u64::from_le_bytes(st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8].try_into().unwrap()) & F_ZF;

        // ---- native VM (addr v15 = vbase+0x8000 = arena offset 0x8000) ----
        {
            let b = varena.bytes();
            b[0x4000..0x4000 + prog.len()].copy_from_slice(&prog);
            b[0x5000..0x5000 + interp::STATE_SIZE].fill(0);
            b[0x8000..0x8008].copy_from_slice(&init_bytes);
            for (v, x) in [(15usize, vbase + 0x8000), (0usize, *expected), (14usize, *new)] {
                let off = interp::STATE_VREGS + v * 8;
                b[0x5000 + off..0x5000 + off + 8].copy_from_slice(&x.to_le_bytes());
            }
        }
        varena.call(0x7000);
        let b = varena.bytes();
        let v0_n = u64::from_le_bytes(b[0x5000 + interp::STATE_VREGS..0x5000 + interp::STATE_VREGS + 8].try_into().unwrap());
        let zf_n = u64::from_le_bytes(b[0x5000 + interp::STATE_FLAGS..0x5000 + interp::STATE_FLAGS + 8].try_into().unwrap()) & F_ZF;
        let mem_n: Vec<u8> = b[0x8000..0x8000 + *width].to_vec();

        // interp and native must agree
        assert_eq!(v0_i, v0_n, "cmpxchg op={} v0 interp/native mismatch", op);
        assert_eq!(zf_i, zf_n, "cmpxchg op={} ZF interp/native mismatch", op);
        assert_eq!(&mem[0x8000..0x8000 + *width], &mem_n[..], "cmpxchg op={} memory interp/native mismatch", op);

        // memory must equal mem_after
        let after: Vec<u8> = mem_after.to_le_bytes()[..*width].to_vec();
        assert_eq!(&mem[0x8000..0x8000 + *width], &after[..], "cmpxchg op={} memory != expected-after", op);

        // success iff operand-width low bytes of RAX match [addr]
        let expect_success = (expected & mask) == (mem_init & mask);
        assert_eq!(zf_i != 0, expect_success, "cmpxchg op={} ZF semantics wrong", op);
        if !expect_success {
            let v0_low = v0_i & mask;
            assert_eq!(v0_low, mem_init & mask, "cmpxchg op={} failed CAS must load [addr] into AL/AX/EAX/RAX", op);
        } else {
            assert_eq!(v0_i, *expected, "cmpxchg op={} success must leave RAX unchanged", op);
        }
    }
    Ok(())
}
