// ==============================================================================
// BTG - Direct-Threaded Native Harness: tests - split from harness.rs
// ==============================================================================
use super::*;
use crate::vm::risc::{MicroInstr, MicroOperand, RiscDesynthesizer, RiscOp};

#[test]
fn test_native_harness_matches_reference_state() {
    let mut d = RiscDesynthesizer::new();
    // R0 = 0x200, R1 = 5
    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0x200),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(1),
        MicroOperand::Imm64(5),
        MicroOperand::Imm64(0),
    );
    // R2 = R0 >> R1  (0x10)
    d.instrs.push(
        MicroInstr::new(RiscOp::ShiftRight)
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::VReg(1)),
    );
    // R3 = R0 << 2  (0x800)
    d.instrs.push(
        MicroInstr::new(RiscOp::ShiftLeft)
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::Imm64(2)),
    );
    // R7 = R0 - R1  (0x1FB)  via AddWithCarry cin=1 (SUB de-synthesis)
    d.emit_sub(
        MicroOperand::VReg(7),
        MicroOperand::VReg(0),
        MicroOperand::VReg(1),
    );
    d.emit_push(MicroOperand::VReg(3));
    d.emit_push(MicroOperand::VReg(0));
    d.emit_pop(MicroOperand::VReg(4));
    // NOR: R5 = ~(R2 | R1)
    d.instrs.push(
        MicroInstr::new(RiscOp::Nor)
            .with_dst(MicroOperand::VReg(5))
            .with_src1(MicroOperand::VReg(2))
            .with_src2(MicroOperand::VReg(1)),
    );
    d.instrs
        .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)));
    // Halt
    d.instrs.push(MicroInstr::new(RiscOp::Halt));

    let prog = RiscProgram::new(d.instrs);
    let init = [0u64; 16];

    // 참조
    let ref_st = prog.eval_state(&init);
    let nat = run_native_risc(&prog, &init).unwrap();

    assert_eq!(nat.regs, ref_st.regs, "regs mismatch");
    assert_eq!(nat.temps, ref_st.temps, "temps mismatch");
    assert_eq!(
        nat.flags, ref_st.flags,
        "flags mismatch (ref={:#x} native={:#x})",
        ref_st.flags, nat.flags
    );
    assert_eq!(nat.vsp, ref_st.vsp, "vsp mismatch");
    assert_eq!(nat.stack, ref_st.stack, "stack mismatch");
}

#[test]
fn test_native_harness_add_value() {
    let mut d = RiscDesynthesizer::new();
    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(1200),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(1),
        MicroOperand::Imm64(450),
        MicroOperand::Imm64(0),
    );
    d.emit_sub(
        MicroOperand::VReg(0),
        MicroOperand::VReg(0),
        MicroOperand::VReg(1),
    );
    d.emit_xor(
        MicroOperand::VReg(0),
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0x55),
    );
    d.instrs.push(MicroInstr::new(RiscOp::Halt));
    let prog = RiscProgram::new(d.instrs);

    let nat = run_native_risc(&prog, &[0u64; 16]).unwrap();
    assert_eq!(nat.regs[0], (1200 - 450) ^ 0x55);
    assert_eq!(nat.regs[1], 450);
}

///
#[test]
fn test_native_poly_matches_interpreter_and_reference() {
    use crate::vm::poly::{PolymorphicEncoder, PolymorphicInterpreter};

    let mut d = RiscDesynthesizer::new();
    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0x200),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(1),
        MicroOperand::Imm64(5),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::ShiftRight)
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::VReg(1)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::ShiftLeft)
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::Imm64(2)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::AddWithCarry)
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::VReg(1))
            .with_imm(0),
    );
    d.emit_push(MicroOperand::VReg(3));
    d.emit_push(MicroOperand::VReg(0));
    d.emit_pop(MicroOperand::VReg(4));
    d.instrs.push(
        MicroInstr::new(RiscOp::Nor)
            .with_dst(MicroOperand::VReg(5))
            .with_src1(MicroOperand::VReg(2))
            .with_src2(MicroOperand::VReg(1)),
    );
    d.instrs
        .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)));
    d.instrs.push(MicroInstr::new(RiscOp::Halt));
    let prog = RiscProgram::new(d.instrs);

    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();

        let nat = run_native_poly(&bytecode, seed, &[0u64; 16]).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.run(&bytecode).unwrap();
        // (3) 참조
        let ref_st = prog.eval_state(&[0u64; 16]);

        assert_eq!(
            nat.regs, ref_st.regs,
            "seed {seed:#x}: native regs != reference"
        );
        assert_eq!(
            interp.regs, ref_st.regs,
            "seed {seed:#x}: interp regs != reference"
        );
        assert_eq!(
            nat.temps, ref_st.temps,
            "seed {seed:#x}: native temps != reference"
        );
        assert_eq!(
            nat.flags, ref_st.flags,
            "seed {seed:#x}: native flags != reference"
        );
        assert_eq!(
            interp.flags.raw, ref_st.flags,
            "seed {seed:#x}: interp flags != reference"
        );
        assert_eq!(
            nat.vsp, ref_st.vsp,
            "seed {seed:#x}: native vsp != reference"
        );
        assert_eq!(
            nat.stack, ref_st.stack,
            "seed {seed:#x}: native stack != reference"
        );
        assert_eq!(nat.regs[2], 0x10);
        assert_eq!(nat.regs[3], 0x800);
        assert_eq!(nat.regs[5], !(0x10 | 5));
    }
}


/// TEMP isolated static branch.
#[test]
fn temp_static_branch_only() {
    let mut d = RiscDesynthesizer::new();
    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::VirtualBranch {
            cond: BranchCondition::Zero,
        })
        .with_imm(3),
    );
    d.emit_add(
        MicroOperand::VReg(7),
        MicroOperand::Imm64(111),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(6),
        MicroOperand::Imm64(222),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(MicroInstr::new(RiscOp::Halt));
    let prog = RiscProgram::new(d.instrs);
    let ref_st = prog.eval_state(&[0u64; 16]);
    let nat = run_native_risc(&prog, &[0u64; 16]).unwrap();
    assert_eq!(nat.regs, ref_st.regs);
    assert_eq!(nat.regs[6], 222);
    assert_eq!(nat.regs[7], 0);
}

#[test]
fn test_native_new_ops_matches_reference() {
    use crate::vm::risc::BranchCondition;

    let mut d = RiscDesynthesizer::new();
    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0x0102_0304_0506_0708),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::VReg(1))
            .with_src1(MicroOperand::VReg(0)),
    );
    d.emit_add(
        MicroOperand::VReg(2),
        MicroOperand::Imm64((-16i64) as u64),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::ArithmeticShiftRight)
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::VReg(2))
            .with_src2(MicroOperand::Imm64(2)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::BSwap { width: 8 })
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(0)),
    );
    d.emit_add(
        MicroOperand::VReg(4),
        MicroOperand::Imm64(0x1000),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::BitScanForward)
            .with_dst(MicroOperand::VReg(5))
            .with_src1(MicroOperand::VReg(4)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::BitScanReverse)
            .with_dst(MicroOperand::VReg(6))
            .with_src1(MicroOperand::VReg(4)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::BitScanForward)
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::Imm64(0)),
    );
    d.emit_add(
        MicroOperand::VReg(1),
        MicroOperand::Imm64(0x8000_0000_0000_1000),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::CountTrailingZeros { width: 8 })
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::VReg(1)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::CountLeadingZeros { width: 8 })
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(1)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::PopCount)
            .with_dst(MicroOperand::VReg(4))
            .with_src1(MicroOperand::Imm64(0xFF)),
    );
    d.emit_add(
        MicroOperand::VReg(5),
        MicroOperand::Imm64(0x1_0000_0001),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(6),
        MicroOperand::Imm64(3),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::Multiply {
            signed: false,
            width: 8,
        })
        .with_dst(MicroOperand::VReg(5))
        .with_src1(MicroOperand::VReg(5))
        .with_src2(MicroOperand::VReg(6)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::MultiplyLow {
            signed: true,
            width: 4,
        })
        .with_dst(MicroOperand::VReg(6))
        .with_src1(MicroOperand::VReg(6))
        .with_src2(MicroOperand::Imm64(2)),
    );
    d.emit_add(
        MicroOperand::VReg(1),
        MicroOperand::Imm64(1000),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(2),
        MicroOperand::Imm64(0),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(3),
        MicroOperand::Imm64(7),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::Divide {
            signed: false,
            width: 8,
        })
        .with_dst(MicroOperand::VReg(1))
        .with_src1(MicroOperand::VReg(3)),
    );
    d.instrs
        .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x44)));
    d.instrs.push(
        MicroInstr::new(RiscOp::Setcc {
            cond: BranchCondition::Zero,
        })
        .with_dst(MicroOperand::VReg(4)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::Setcc {
            cond: BranchCondition::NotZero,
        })
        .with_dst(MicroOperand::VReg(5)),
    );
    d.emit_add(
        MicroOperand::VReg(6),
        MicroOperand::Imm64(7),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::ConditionalMove {
            cond: BranchCondition::Zero,
        })
        .with_dst(MicroOperand::VReg(7))
        .with_src1(MicroOperand::VReg(6)),
    );
    d.instrs.push(MicroInstr::new(RiscOp::Halt));

    let prog = RiscProgram::new(d.instrs);
    let init = [0u64; 16];
    let ref_st = prog.eval_state(&init);
    let nat = run_native_risc(&prog, &init).unwrap();
    assert_eq!(nat.regs, ref_st.regs, "regs mismatch");
    assert_eq!(nat.temps, ref_st.temps, "temps mismatch");
    assert_eq!(
        nat.flags, ref_st.flags,
        "flags mismatch (ref={:#x} nat={:#x})",
        ref_st.flags, nat.flags
    );
    assert_eq!(nat.vsp, ref_st.vsp, "vsp mismatch");
    assert_eq!(nat.stack, ref_st.stack, "stack mismatch");
}

#[test]
fn test_native_branch_static_and_dynamic_matches_reference() {
    use std::collections::HashMap;

    let mut d = RiscDesynthesizer::new();
    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0),
        MicroOperand::Imm64(0),
    ); // ZF=1
    d.instrs.push(
        MicroInstr::new(RiscOp::VirtualBranch {
            cond: BranchCondition::Zero,
        })
        .with_imm(3),
    ); // index1
    d.emit_add(
        MicroOperand::VReg(7),
        MicroOperand::Imm64(111),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(6),
        MicroOperand::Imm64(222),
        MicroOperand::Imm64(0),
    ); // index3
    d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
    let prog = RiscProgram::new(d.instrs);
    let ref_st = prog.eval_state(&[0u64; 16]);
    let nat = run_native_risc(&prog, &[0u64; 16]).unwrap();
    assert_eq!(nat.regs, ref_st.regs, "static branch regs");
    assert_eq!(nat.regs[6], 222, "static branch taken target");
    assert_eq!(nat.regs[7], 0, "static branch skipped block");

    let mut ip_map = HashMap::new();
    for i in 0..5u64 {
        ip_map.insert(0x1000 + i, i as usize);
    }
    let mut d = RiscDesynthesizer::new();
    d.emit_add(
        MicroOperand::VReg(5),
        MicroOperand::Imm64(0x1003),
        MicroOperand::Imm64(0),
    ); // index0
    d.instrs.push(
        MicroInstr::new(RiscOp::VirtualBranch {
            cond: BranchCondition::Always,
        })
        .with_src1(MicroOperand::VReg(5)),
    );
    d.emit_add(
        MicroOperand::VReg(7),
        MicroOperand::Imm64(111),
        MicroOperand::Imm64(0),
    ); // index2
    d.emit_add(
        MicroOperand::VReg(6),
        MicroOperand::Imm64(222),
        MicroOperand::Imm64(0),
    ); // index3
    d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
    let prog = RiscProgram::with_ip_map(d.instrs, ip_map);
    let ref_st = prog.eval_state(&[0u64; 16]);
    let nat = run_native_risc(&prog, &[0u64; 16]).unwrap();
    assert_eq!(nat.regs, ref_st.regs, "dynamic branch regs");
    assert_eq!(
        nat.regs[6], 222,
        "dynamic branch target resolved via helper"
    );
}

#[test]
fn test_native_memory_and_cmpxchg_matches_reference() {
    use std::collections::HashMap;

    let mut d = RiscDesynthesizer::new();
    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0xCAFE_F00D),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
            .with_src1(MicroOperand::VReg(1))
            .with_src2(MicroOperand::VReg(0)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::MemoryRead { width: 8 })
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::VReg(1)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::MemoryRead { width: 4 })
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(1)),
    );
    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0xCAFE_F00D),
        MicroOperand::Imm64(0),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::CompareExchange { width: 8 })
            .with_src1(MicroOperand::VReg(1))
            .with_src2(MicroOperand::Imm64(0x1234)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::MemoryRead { width: 8 })
            .with_dst(MicroOperand::VReg(4))
            .with_src1(MicroOperand::VReg(1)),
    );
    d.instrs.push(MicroInstr::new(RiscOp::Halt));

    let prog = RiscProgram::new(d.instrs);
    let mut vm = NativeVmHarness::compile(&prog, 0x5A).unwrap();
    let addr = (vm.arena.base + 0x18000) as u64;

    let mut init = [0u64; 16];
    init[1] = addr;
    let seed_mem: HashMap<u64, u8> = HashMap::new();
    let ref_st = prog.eval_state_with_mem(&init, seed_mem);

    {
        let buf = vm.arena.bytes();
        for i in 0..16u64 {
            assert_eq!(
                buf[0x18000 + i as usize],
                0,
                "arena window must start zeroed"
            );
        }
    }
    let nat = vm.run(&init).unwrap();

    assert_eq!(nat.regs, ref_st.regs, "regs mismatch (mem/cmpxchg)");
    assert_eq!(
        nat.flags, ref_st.flags,
        "flags mismatch (ref={:#x} nat={:#x})",
        ref_st.flags, nat.flags
    );
    let buf = vm.arena.bytes();
    let mut stored = 0u64;
    for i in 0..8u64 {
        stored |= (buf[0x18000 + i as usize] as u64) << (i * 8);
    }
    assert_eq!(stored, 0x1234, "cmpxchg wrote new value");
}

#[test]
fn test_native_mba_add_matches_reference_state() {
    let mut d = RiscDesynthesizer::new();
    // R0 = 0xFFFF_FFFF_FFFF_FFFF
    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0xFFFF_FFFF_FFFF_FFFF),
        MicroOperand::Imm64(0),
    );
    // R1 = 1
    d.emit_add(
        MicroOperand::VReg(1),
        MicroOperand::Imm64(1),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(2),
        MicroOperand::VReg(0),
        MicroOperand::VReg(1),
    );
    d.emit_add(
        MicroOperand::VReg(3),
        MicroOperand::Imm64(0x7FFF_FFFF_FFFF_FFFF),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(4),
        MicroOperand::Imm64(1),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(5),
        MicroOperand::VReg(3),
        MicroOperand::VReg(4),
    );
    // R6 = 0x1234_5678 + 0x8765_4321 = 0x9999_9999 (ZF=0, SF=1)
    d.emit_add(
        MicroOperand::VReg(6),
        MicroOperand::Imm64(0x1234_5678_0000_0000),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(7),
        MicroOperand::Imm64(0x8765_4321_0000_0000),
        MicroOperand::Imm64(0),
    );
    d.emit_add(
        MicroOperand::VReg(8),
        MicroOperand::VReg(6),
        MicroOperand::VReg(7),
    );
    d.instrs.push(MicroInstr::new(RiscOp::Halt));
    let prog = RiscProgram::new(d.instrs);

    let mut vm = NativeVmHarness::compile_with_mba(&prog, 0x5A, 100).unwrap();
    let nat = vm.run(&[0u64; 16]).unwrap();
    let ref_st = prog.eval_state(&[0u64; 16]);

    assert_eq!(nat.regs, ref_st.regs, "MBA add regs mismatch");
    assert_eq!(nat.temps, ref_st.temps, "MBA add temps mismatch");
    assert_eq!(
        nat.flags, ref_st.flags,
        "MBA add flags mismatch (ref={:#x} nat={:#x})",
        ref_st.flags, nat.flags
    );
    assert_eq!(nat.vsp, ref_st.vsp, "MBA add vsp mismatch");
    assert_eq!(nat.stack, ref_st.stack, "MBA add stack mismatch");
    assert_eq!(nat.regs[2], 0, "0xFFFF.. + 1 must wrap to 0");
    assert_eq!(nat.regs[5], 0x8000_0000_0000_0000, "sign-overflow sum");
    assert_eq!(nat.regs[8], 0x9999_9999_0000_0000, "partial add");
}

#[test]
fn test_native_mba_add_prob_0_vs_100_equivalent() {
    let mut d = RiscDesynthesizer::new();
    let vals: [u64; 8] = [
        0,
        1,
        0xFFFFFFFF,
        0x8000_0000_0000_0000,
        0xDEAD_BEEF,
        0x7FFF_FFFF_FFFF_FFFF,
        0x0000_0001_0000_0000,
        0xAAAA_BBBB_CCCC_DDDD,
    ];
    for (i, v) in vals.iter().enumerate() {
        d.emit_add(
            MicroOperand::VReg(i as u8),
            MicroOperand::Imm64(*v),
            MicroOperand::Imm64(0),
        );
    }
    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::VReg(0),
        MicroOperand::VReg(1),
    );
    d.emit_add(
        MicroOperand::VReg(2),
        MicroOperand::VReg(2),
        MicroOperand::VReg(3),
    );
    d.emit_add(
        MicroOperand::VReg(4),
        MicroOperand::VReg(4),
        MicroOperand::VReg(5),
    );
    d.emit_add(
        MicroOperand::VReg(6),
        MicroOperand::VReg(6),
        MicroOperand::VReg(7),
    );
    d.instrs.push(MicroInstr::new(RiscOp::Halt));
    let prog = RiscProgram::new(d.instrs);

    let mut nat_plain = NativeVmHarness::compile_with_mba(&prog, 0x5A, 0).unwrap();
    let mut nat_mba = NativeVmHarness::compile_with_mba(&prog, 0x5A, 100).unwrap();
    let a = nat_plain.run(&[0u64; 16]).unwrap();
    let b = nat_mba.run(&[0u64; 16]).unwrap();
    assert_eq!(a.regs, b.regs, "MBA vs plain add regs differ");
    assert_eq!(
        a.flags, b.flags,
        "MBA vs plain add flags differ (plain={:#x} mba={:#x})",
        a.flags, b.flags
    );
}

///
#[test]
fn test_mba_add_handler_diversified_per_key() {
    use crate::vm::threaded::harness::OFF_CODE;
    let mut instrs = Vec::new();
    let vals: [u64; 8] = [
        0xFFFF_FFFF_FFFF_FFFF,
        1,
        0x7FFF_FFFF_FFFF_FFFF,
        1,
        0x1234_5678_0000_0000,
        0x8765_4321_0000_0000,
        0,
        0x8000_0000_0000_0000,
    ];
    for i in 0..8 {
        instrs.push(
            MicroInstr::new(RiscOp::Add { width: 8 })
                .with_dst(MicroOperand::VReg(i))
                .with_src1(MicroOperand::Imm64(vals[i as usize]))
                .with_src2(MicroOperand::VReg((i + 1) % 8)),
        );
    }
    instrs.push(MicroInstr::new(RiscOp::Halt));
    let prog = RiscProgram::new(instrs);

    let mut vm_a = NativeVmHarness::compile_with_mba(&prog, 0x11, 100).unwrap();
    let mut vm_b = NativeVmHarness::compile_with_mba(&prog, 0x22, 100).unwrap();
    let ref_st = prog.eval_state(&[0u64; 16]);
    let na = vm_a.run(&[0u64; 16]).unwrap();
    let nb = vm_b.run(&[0u64; 16]).unwrap();
    assert_eq!(na.regs, ref_st.regs, "key=0x11 MBA add regs mismatch");
    assert_eq!(na.flags, ref_st.flags, "key=0x11 MBA add flags mismatch");
    assert_eq!(nb.regs, ref_st.regs, "key=0x22 MBA add regs mismatch");
    assert_eq!(nb.flags, ref_st.flags, "key=0x22 MBA add flags mismatch");

    //     variant 0: `xor r9, r11` = 4D 33 CB (Xor_r64_rm64, opcode 33 /r),
    //     variant 1: `or  r9, r11` = 4D 0B CB (Or_r64_rm64,  opcode 0B /r).
    let signature = |vm: &mut NativeVmHarness| -> String {
        let bytes = vm.arena.bytes().to_vec();
        let mut s = String::new();
        let mut i = 0;
        while i + 3 <= bytes.len() {
            if bytes[i..i + 3] == [0x4D, 0x33, 0xCB] {
                s.push('X');
                i += 3;
            } else if bytes[i..i + 3] == [0x4D, 0x0B, 0xCB] {
                s.push('O');
                i += 3;
            } else {
                i += 1;
            }
        }
        s
    };
    let sa = signature(&mut vm_a);
    let sb = signature(&mut vm_b);
    assert!(
        sa.len() >= 8,
        "key=0x11: all 8 ADD blocks must use an MBA variant ({sa})"
    );
    assert!(
        sb.len() >= 8,
        "key=0x22: all 8 ADD blocks must use an MBA variant ({sb})"
    );
    assert!(
        sa != sb,
        "different build keys must diversify ADD handler code (a={sa} b={sb})"
    );
}

#[test]
fn p0_randomized_three_path_differential() {
    use crate::vm::poly::{PolymorphicEncoder, PolymorphicInterpreter};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_5EED_1234);
    for trial in 0..64 {
        let mut d = RiscDesynthesizer::new();
        let n = 6 + (rng.gen::<u32>() % 18) as usize;
        let mut depth = 0i32;
        for _ in 0..n {
            let ra = (rng.gen::<u8>() % 16) as u8;
            let rb = (rng.gen::<u8>() % 16) as u8;
            let rc = (rng.gen::<u8>() % 16) as u8;
            let mut choice = rng.gen_range(0..16u32);
            if choice == 11 && depth <= 0 {
                choice = 10;
            }
            match choice {
                0 => d.emit_add(
                    MicroOperand::VReg(ra),
                    MicroOperand::Imm64(rng.gen::<u64>()),
                    MicroOperand::Imm64(0),
                ),
                1 => d.emit_add(
                    MicroOperand::VReg(ra),
                    MicroOperand::VReg(rb),
                    MicroOperand::VReg(rc),
                ),
                2 => d.emit_sub(
                    MicroOperand::VReg(ra),
                    MicroOperand::VReg(rb),
                    MicroOperand::VReg(rc),
                ),
                3 => d.emit_xor(
                    MicroOperand::VReg(ra),
                    MicroOperand::VReg(rb),
                    MicroOperand::VReg(rc),
                ),
                4 => d.emit_and(
                    MicroOperand::VReg(ra),
                    MicroOperand::VReg(rb),
                    MicroOperand::VReg(rc),
                ),
                5 => d.emit_or(
                    MicroOperand::VReg(ra),
                    MicroOperand::VReg(rb),
                    MicroOperand::VReg(rc),
                ),
                6 => d.instrs.push(
                    MicroInstr::new(RiscOp::Nor)
                        .with_dst(MicroOperand::VReg(ra))
                        .with_src1(MicroOperand::VReg(rb))
                        .with_src2(MicroOperand::VReg(rc)),
                ),
                7 => d.instrs.push(
                    MicroInstr::new(RiscOp::ShiftLeft)
                        .with_dst(MicroOperand::VReg(ra))
                        .with_src1(MicroOperand::VReg(rb))
                        .with_src2(MicroOperand::Imm64((rng.gen::<u8>() % 63 + 1) as u64)),
                ),
                8 => d.instrs.push(
                    MicroInstr::new(RiscOp::ShiftRight)
                        .with_dst(MicroOperand::VReg(ra))
                        .with_src1(MicroOperand::VReg(rb))
                        .with_src2(MicroOperand::Imm64((rng.gen::<u8>() % 63 + 1) as u64)),
                ),
                9 => d.instrs.push(
                    MicroInstr::new(RiscOp::ArithmeticShiftRight)
                        .with_dst(MicroOperand::VReg(ra))
                        .with_src1(MicroOperand::VReg(rb))
                        .with_src2(MicroOperand::Imm64((rng.gen::<u8>() % 63 + 1) as u64)),
                ),
                10 => {
                    d.emit_push(MicroOperand::VReg(ra));
                    depth += 1;
                }
                11 => {
                    d.emit_pop(MicroOperand::VReg(ra));
                    depth -= 1;
                }
                12 => d.instrs.push(
                    MicroInstr::new(RiscOp::SetFlag)
                        .with_src1(MicroOperand::Imm64(rng.gen::<u64>() & 0x8D5)),
                ),
                13 => d.instrs.push(
                    MicroInstr::new(RiscOp::Add { width: 4 })
                        .with_dst(MicroOperand::VReg(ra))
                        .with_src1(MicroOperand::VReg(rb))
                        .with_src2(MicroOperand::VReg(rc)),
                ),
                14 => d.instrs.push(
                    MicroInstr::new(RiscOp::Add { width: 1 })
                        .with_dst(MicroOperand::VReg(ra))
                        .with_src1(MicroOperand::VReg(rb))
                        .with_src2(MicroOperand::VReg(rc)),
                ),
                15 => d.instrs.push(
                    MicroInstr::new(RiscOp::Not { width: 8 })
                        .with_dst(MicroOperand::VReg(ra))
                        .with_src1(MicroOperand::VReg(rb)),
                ),
                _ => unreachable!("gen_range(0..16)"),
            }
        }
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);

        let seed = rng.gen::<u64>();
        let init: [u64; 16] = std::array::from_fn(|_| rng.gen());

        // (1) 참조
        let ref_st = prog.eval_state(&init);
        let mut enc = PolymorphicEncoder::new(seed);
        let bc = enc
            .encode(&prog)
            .expect("all random ops must be poly-encodable");
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.regs = init;
        interp.run(&bc).unwrap();
        let mut vm = NativeVmHarness::compile_with_mba(&prog, 0x5A, 100).unwrap();
        let nat = vm.run(&init).unwrap();

        assert_eq!(
            interp.regs, ref_st.regs,
            "trial={trial} poly regs != ref\nprog:\n{:?}",
            prog.instrs
        );
        assert_eq!(
            interp.temps, ref_st.temps,
            "trial={trial} poly temps != ref"
        );
        assert_eq!(
            interp.flags.raw, ref_st.flags,
            "trial={trial} poly flags != ref (ref={:#x} poly={:#x})",
            ref_st.flags, interp.flags.raw
        );
        assert_eq!(interp.vsp, ref_st.vsp, "trial={trial} poly vsp != ref");
        assert_eq!(
            interp.stack, ref_st.stack,
            "trial={trial} poly stack != ref"
        );
        assert_eq!(nat.regs, ref_st.regs, "trial={trial} native regs != ref");
        assert_eq!(nat.temps, ref_st.temps, "trial={trial} native temps != ref");
        assert_eq!(
            nat.flags, ref_st.flags,
            "trial={trial} native flags != ref (ref={:#x} nat={:#x})\nprog:\n{:?}",
            ref_st.flags, nat.flags, prog.instrs
        );
        assert_eq!(
            nat.vsp, ref_st.vsp,
            "trial={trial} native vsp != ref (ref={:#x} nat={:#x})\nprog:\n{:?}",
            ref_st.vsp, nat.vsp, prog.instrs
        );
        assert_eq!(nat.stack, ref_st.stack, "trial={trial} native stack != ref");
    }
}
