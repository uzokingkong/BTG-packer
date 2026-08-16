// ==============================================================================
// BTG - Direct-Threaded Native Harness: tests - split from harness.rs
// ==============================================================================
    use super::*;
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscDesynthesizer, RiscOp};

    /// ?�양??op(NOR/ADD/SHR/SHL/PUSH/POP/SET_FLAG)�??��? ?�로그램??
    /// ?�이?�브 ?�행�?참조 ?��??�이?�에 각각 ?�려 결과 ?�태가 ?�치?�는지 검�?
    #[test]
    fn test_native_harness_matches_reference_state() {
        let mut d = RiscDesynthesizer::new();
        // R0 = 0x200, R1 = 5
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x200), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(5), MicroOperand::Imm64(0));
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
        d.emit_sub(MicroOperand::VReg(7), MicroOperand::VReg(0), MicroOperand::VReg(1));
        // push R3, push R0, pop R4  ???��? push 1�?(R3)
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
        // SET_FLAG: ?�래�?= 0x8C1
        d.instrs.push(
            MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)),
        );
        // Halt
        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);
        let init = [0u64; 16];

        // 참조
        let ref_st = prog.eval_state(&init);
        // ?�이?�브
        let nat = run_native_risc(&prog, &init).unwrap();

        assert_eq!(nat.regs, ref_st.regs, "regs mismatch");
        assert_eq!(nat.temps, ref_st.temps, "temps mismatch");
        assert_eq!(nat.flags, ref_st.flags, "flags mismatch (ref={:#x} native={:#x})", ref_st.flags, nat.flags);
        assert_eq!(nat.vsp, ref_st.vsp, "vsp mismatch");
        assert_eq!(nat.stack, ref_st.stack, "stack mismatch");
    }

    /// ?�순 ADD ?�로그램??최종 ?��??�터 �?직접 ?�인.
    #[test]
    fn test_native_harness_add_value() {
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(1200), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(450), MicroOperand::Imm64(0));
        d.emit_sub(MicroOperand::VReg(0), MicroOperand::VReg(0), MicroOperand::VReg(1));
        d.emit_xor(MicroOperand::VReg(0), MicroOperand::VReg(0), MicroOperand::Imm64(0x55));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);

        let nat = run_native_risc(&prog, &[0u64; 16]).unwrap();
        assert_eq!(nat.regs[0], (1200 - 450) ^ 0x55);
        assert_eq!(nat.regs[1], 450);
    }

    /// T1-4 차등 검�? **?�호?�된** ?�리모픽 바이?�코???�트림을
    /// (1) ?�이?�브 ?�네??`run_native_poly`), (2) ?�리모픽 ?�터?�리??
    /// (3) 참조 ?��??�이??`eval_state`)??각각 ?�행?????�태가 ?�전???�치?�는지 검�?
    ///
    /// ?�는 "?�베?�된 .btgvm ?�텁??rolling-key ?�트림을 ?�이?�브�??�석·?�행?�는
    /// ?�계"??검�?기�??�다 ???�이?�브 ?�행???�터?�리?�·참조�? ?�치?�야 ?�다.
    #[test]
    fn test_native_poly_matches_interpreter_and_reference() {
        use crate::vm::poly::{PolymorphicEncoder, PolymorphicInterpreter};

        // ?�터?�리???�스?��? 같�? ?�로그램 (shift/push/pop/nor/flags ?�합).
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x200), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(5), MicroOperand::Imm64(0));
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
        d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);

        // ?�러 ?�드???�??각각 ?�리모픽 ?�코??????경로 비교.
        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();

            // (1) ?�이?�브
            let nat = run_native_poly(&bytecode, seed, &[0u64; 16]).unwrap();
            // (2) ?�터?�리??
            let mut interp = PolymorphicInterpreter::new(seed);
            interp.run(&bytecode).unwrap();
            // (3) 참조
            let ref_st = prog.eval_state(&[0u64; 16]);

            assert_eq!(nat.regs, ref_st.regs, "seed {seed:#x}: native regs != reference");
            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: interp regs != reference");
            assert_eq!(nat.temps, ref_st.temps, "seed {seed:#x}: native temps != reference");
            assert_eq!(nat.flags, ref_st.flags, "seed {seed:#x}: native flags != reference");
            assert_eq!(interp.flags.raw, ref_st.flags, "seed {seed:#x}: interp flags != reference");
            assert_eq!(nat.vsp, ref_st.vsp, "seed {seed:#x}: native vsp != reference");
            assert_eq!(nat.stack, ref_st.stack, "seed {seed:#x}: native stack != reference");
            assert_eq!(nat.regs[2], 0x10);
            assert_eq!(nat.regs[3], 0x800);
            assert_eq!(nat.regs[5], !(0x10 | 5));
        }
    }

    // ?�?� P2: ?�규 ?�수/비트/?�어 op ?�이?�브 차등 (native == eval_state) ?�?�?�?�?�?�?�?�?�?�

    /// ?�규 ?�산 ??계열 (Mov/ArithmeticShiftRight/Multiply/Divide/BSwap/BitScan/
    /// Count/PopCount/Setcc/ConditionalMove) ???�이?�브 ?�행??참조?� ?�전 ?�치 검�?
    /// TEMP isolated static branch.
    #[test]
    fn temp_static_branch_only() {
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0), MicroOperand::Imm64(0));
        d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::Zero }).with_imm(3));
        d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(111), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(222), MicroOperand::Imm64(0));
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
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x0102_0304_0506_0708), MicroOperand::Imm64(0));
        d.instrs.push(MicroInstr::new(RiscOp::Mov).with_dst(MicroOperand::VReg(1)).with_src1(MicroOperand::VReg(0)));
        d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64((-16i64) as u64), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::ArithmeticShiftRight)
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::Imm64(2)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::BSwap { width: 8 }).with_dst(MicroOperand::VReg(3)).with_src1(MicroOperand::VReg(0)));
        d.emit_add(MicroOperand::VReg(4), MicroOperand::Imm64(0x1000), MicroOperand::Imm64(0));
        d.instrs.push(MicroInstr::new(RiscOp::BitScanForward).with_dst(MicroOperand::VReg(5)).with_src1(MicroOperand::VReg(4)));
        d.instrs.push(MicroInstr::new(RiscOp::BitScanReverse).with_dst(MicroOperand::VReg(6)).with_src1(MicroOperand::VReg(4)));
        d.instrs.push(MicroInstr::new(RiscOp::BitScanForward).with_dst(MicroOperand::VReg(7)).with_src1(MicroOperand::Imm64(0)));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(0x8000_0000_0000_1000), MicroOperand::Imm64(0));
        d.instrs.push(MicroInstr::new(RiscOp::CountTrailingZeros { width: 8 }).with_dst(MicroOperand::VReg(2)).with_src1(MicroOperand::VReg(1)));
        d.instrs.push(MicroInstr::new(RiscOp::CountLeadingZeros { width: 8 }).with_dst(MicroOperand::VReg(3)).with_src1(MicroOperand::VReg(1)));
        d.instrs.push(MicroInstr::new(RiscOp::PopCount).with_dst(MicroOperand::VReg(4)).with_src1(MicroOperand::Imm64(0xFF)));
        d.emit_add(MicroOperand::VReg(5), MicroOperand::Imm64(0x1_0000_0001), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(3), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::Multiply { signed: false, width: 8 })
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(5))
                .with_src2(MicroOperand::VReg(6)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MultiplyLow { signed: true, width: 4 })
                .with_dst(MicroOperand::VReg(6))
                .with_src1(MicroOperand::VReg(6))
                .with_src2(MicroOperand::Imm64(2)),
        );
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(1000), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64(0), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(3), MicroOperand::Imm64(7), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::Divide { signed: false, width: 8 })
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::VReg(3)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x44)));
        d.instrs.push(MicroInstr::new(RiscOp::Setcc { cond: BranchCondition::Zero }).with_dst(MicroOperand::VReg(4)));
        d.instrs.push(MicroInstr::new(RiscOp::Setcc { cond: BranchCondition::NotZero }).with_dst(MicroOperand::VReg(5)));
        d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(7), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::Zero })
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
        assert_eq!(nat.flags, ref_st.flags, "flags mismatch (ref={:#x} nat={:#x})", ref_st.flags, nat.flags);
        assert_eq!(nat.vsp, ref_st.vsp, "vsp mismatch");
        assert_eq!(nat.stack, ref_st.stack, "stack mismatch");
    }

    /// ?�적/?�적 VirtualBranch ?�이?�브 ??branch-free ?�이�??�프 + ip_map ?�캔 ?�퍼.
    #[test]
    fn test_native_branch_static_and_dynamic_matches_reference() {
        use std::collections::HashMap;

        // ?�적 분기: imm=?��??�덱??(ip_map ?�음 ??resolve_target ??imm ???�덱?�로).
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0), MicroOperand::Imm64(0)); // ZF=1
        d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::Zero }).with_imm(3)); // index1
        d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(111), MicroOperand::Imm64(0)); // index2: 건너?�
        d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(222), MicroOperand::Imm64(0)); // index3
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
        let prog = RiscProgram::new(d.instrs);
        let ref_st = prog.eval_state(&[0u64; 16]);
        let nat = run_native_risc(&prog, &[0u64; 16]).unwrap();
        assert_eq!(nat.regs, ref_st.regs, "static branch regs");
        assert_eq!(nat.regs[6], 222, "static branch taken target");
        assert_eq!(nat.regs[7], 0, "static branch skipped block");

        // ?�적 분기: src1=VReg(?��?IP) ??ip_map ?�캔 ?�퍼�??�덱???�석.
        let mut ip_map = HashMap::new();
        for i in 0..5u64 {
            ip_map.insert(0x1000 + i, i as usize);
        }
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(5), MicroOperand::Imm64(0x1003), MicroOperand::Imm64(0)); // index0
        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::Always })
                .with_src1(MicroOperand::VReg(5)),
        ); // index1: ?�적 분기 ??0x1003 ??index3
        d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(111), MicroOperand::Imm64(0)); // index2
        d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(222), MicroOperand::Imm64(0)); // index3
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
        let prog = RiscProgram::with_ip_map(d.instrs, ip_map);
        let ref_st = prog.eval_state(&[0u64; 16]);
        let nat = run_native_risc(&prog, &[0u64; 16]).unwrap();
        assert_eq!(nat.regs, ref_st.regs, "dynamic branch regs");
        assert_eq!(nat.regs[6], 222, "dynamic branch target resolved via helper");
    }

    /// MemoryRead/Write + CompareExchange ?�이?�브 ??arena 창을 게스??메모리로 ?�용.
    #[test]
    fn test_native_memory_and_cmpxchg_matches_reference() {
        use std::collections::HashMap;

        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0xCAFE_F00D), MicroOperand::Imm64(0));
        d.instrs.push(MicroInstr::new(RiscOp::MemoryWrite { width: 8 }).with_src1(MicroOperand::VReg(1)).with_src2(MicroOperand::VReg(0)));
        d.instrs.push(MicroInstr::new(RiscOp::MemoryRead { width: 8 }).with_dst(MicroOperand::VReg(2)).with_src1(MicroOperand::VReg(1)));
        d.instrs.push(MicroInstr::new(RiscOp::MemoryRead { width: 4 }).with_dst(MicroOperand::VReg(3)).with_src1(MicroOperand::VReg(1)));
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0xCAFE_F00D), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::CompareExchange { width: 8 })
                .with_src1(MicroOperand::VReg(1))
                .with_src2(MicroOperand::Imm64(0x1234)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::MemoryRead { width: 8 }).with_dst(MicroOperand::VReg(4)).with_src1(MicroOperand::VReg(1)));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);
        let mut vm = NativeVmHarness::compile(&prog, 0x5A).unwrap();
        let addr = (vm.arena.base + 0x18000) as u64;

        let mut init = [0u64; 16];
        init[1] = addr;
        // 참조??arena 창이 0 ?�로 ?�작?�다�?가????0xCAFE_F00D 기록 경로�?검�?
        let seed_mem: HashMap<u64, u8> = HashMap::new();
        let ref_st = prog.eval_state_with_mem(&init, seed_mem);

        {
            let buf = vm.arena.bytes();
            for i in 0..16u64 {
                assert_eq!(buf[0x18000 + i as usize], 0, "arena window must start zeroed");
            }
        }
        let nat = vm.run(&init).unwrap();

        assert_eq!(nat.regs, ref_st.regs, "regs mismatch (mem/cmpxchg)");
        assert_eq!(nat.flags, ref_st.flags, "flags mismatch (ref={:#x} nat={:#x})", ref_st.flags, nat.flags);
        let buf = vm.arena.bytes();
        let mut stored = 0u64;
        for i in 0..8u64 {
            stored |= (buf[0x18000 + i as usize] as u64) << (i * 8);
        }
        assert_eq!(stored, 0x1234, "cmpxchg wrote new value");
    }
