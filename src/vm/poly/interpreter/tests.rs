use super::*;
use crate::vm::poly::PolymorphicEncoder;
use crate::vm::risc::{
    MicroInstr, MicroOperand, RiscDesynthesizer, RiscEvalState, RiscOp, RiscProgram,
};

#[test]
fn test_polymorphic_encoder_and_interpreter_roundtrip() {
    let seed = 0x8899AABBCCDDEEFF;
    let mut d = RiscDesynthesizer::new();

    // R0 = 1200
    // R1 = 450
    // R0 = R0 - R1  (750)
    // R0 = R0 ^ 0x55 (750 ^ 85 = 795)
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

    let prog = RiscProgram::new(d.instrs);

    // 1. Encode with polymorphic randomized ISA & rolling key
    let mut enc = PolymorphicEncoder::new(seed);
    let bytecode = enc.encode(&prog).unwrap();

    // 2. Execute on polymorphic interpreter
    let mut interp = PolymorphicInterpreter::new(seed);
    interp.run(&bytecode).unwrap();

    assert_eq!(interp.regs[0], (1200 - 450) ^ 0x55);
    assert_eq!(interp.regs[1], 450);
}

/// T1-4 차등 검증: 인터프리터(폴리모픽) == 참조 시뮬레이터(eval_state).
/// 두 구현이 같은 프로그램에 대해 동일한 레지스터/스택/플래그 상태를 내야 한다.
#[test]
fn test_poly_interp_matches_reference_state() {
    let seed = 0x1122334455667788;
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
    // R3 = R0 << 2 (0x800)
    d.instrs.push(
        MicroInstr::new(RiscOp::ShiftLeft)
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::Imm64(2)),
    );
    // push R3, pop R4
    d.emit_push(MicroOperand::VReg(3));
    d.emit_pop(MicroOperand::VReg(4));
    // NOR: R5 = ~(R2 | R1)
    d.instrs.push(
        MicroInstr::new(RiscOp::Nor)
            .with_dst(MicroOperand::VReg(5))
            .with_src1(MicroOperand::VReg(2))
            .with_src2(MicroOperand::VReg(1)),
    );
    // Halt
    d.instrs.push(MicroInstr::new(RiscOp::Halt));

    let prog = RiscProgram::new(d.instrs);

    // 참조 시뮬레이터
    let ref_st = prog.eval_state(&[0u64; 16]);

    // 폴리모픽 인코딩 + 인터프리터
    let mut enc = PolymorphicEncoder::new(seed);
    let bytecode = enc.encode(&prog).unwrap();
    let mut interp = PolymorphicInterpreter::new(seed);
    interp.run(&bytecode).unwrap();

    assert_eq!(interp.regs[0], ref_st.regs[0]);
    assert_eq!(interp.regs[1], ref_st.regs[1]);
    assert_eq!(interp.regs[2], ref_st.regs[2], "shift right");
    assert_eq!(interp.regs[3], ref_st.regs[3], "shift left");
    assert_eq!(interp.regs[4], ref_st.regs[4], "pop");
    assert_eq!(interp.regs[5], ref_st.regs[5], "nor");
    assert_eq!(interp.flags.raw, ref_st.flags, "flags");
    assert_eq!(interp.vsp, ref_st.vsp, "vsp");
    assert_eq!(interp.stack.len(), ref_st.stack.len(), "stack depth");
    assert_eq!(interp.regs[2], 0x10);
    assert_eq!(interp.regs[3], 0x800);
    assert_eq!(interp.regs[5], !(0x10 | 5));
}

// ---- 신규 연산 (P1) 차등 검증 -------------------------------------------------

const DIFF_SEEDS: [u64; 3] = [
    0x1111_2222_3333_4444,
    0xCAFE_F00D_DEAD_BEEF,
    0x8899_AABB_CCDD_EEFF,
];

/// 인터프리터 전체 상태 == eval_state 전체 상태 (regs/temps/flags/vsp/stack/mem).
fn assert_full_state_eq(interp: &PolymorphicInterpreter, ref_st: &RiscEvalState) {
    assert_eq!(interp.regs, ref_st.regs, "regs");
    assert_eq!(interp.temps, ref_st.temps, "temps");
    assert_eq!(interp.flags.raw, ref_st.flags, "flags");
    assert_eq!(interp.vsp, ref_st.vsp, "vsp");
    assert_eq!(interp.stack, ref_st.stack, "stack");
    assert_eq!(interp.mem, ref_st.mem, "mem");
}

fn run_diff(seed: u64, prog: &RiscProgram, init_regs: &[u64; 16]) {
    let ref_st = prog.eval_state(init_regs);

    let mut enc = PolymorphicEncoder::new(seed);
    let bytecode = enc.encode(prog).unwrap();
    let mut interp = PolymorphicInterpreter::new(seed);
    interp.regs = *init_regs;
    interp.run(&bytecode).unwrap();

    assert_full_state_eq(&interp, &ref_st);
}

/// ArithmeticShiftRight 차등 (SAR, 논리 플래그 갱신 포함).
#[test]
fn test_poly_diff_arithmetic_shift_right() {
    for seed in DIFF_SEEDS {
        let mut d = RiscDesynthesizer::new();
        // R1 = 음수 값 (SF=1 확인용)
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(0x8000_0000_0000_000F),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(4),
            MicroOperand::Imm64(0),
        );
        // R3 = R1 >> R2 (산술) → 부호 비트 유지
        d.instrs.push(
            MicroInstr::new(RiscOp::ArithmeticShiftRight)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(1))
                .with_src2(MicroOperand::VReg(2)),
        );
        // R4 = R1 >> 63 (전부 부호 비트)
        d.instrs.push(
            MicroInstr::new(RiscOp::ArithmeticShiftRight)
                .with_dst(MicroOperand::VReg(4))
                .with_src1(MicroOperand::VReg(1))
                .with_src2(MicroOperand::Imm64(63)),
        );
        // R5 = R1 >> 0 (cnt==0 → 그대로)
        d.instrs.push(
            MicroInstr::new(RiscOp::ArithmeticShiftRight)
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(1))
                .with_src2(MicroOperand::Imm64(0)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff(seed, &prog, &[0u64; 16]);
    }
}

/// MemoryRead/MemoryWrite (폭 1/2/4/8) 차등 — 메모리 상태 전체 비교.
#[test]
fn test_poly_diff_memory_read_write_all_widths() {
    for seed in DIFF_SEEDS {
        let mut d = RiscDesynthesizer::new();
        // R0 = 기준 주소
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x1000),
            MicroOperand::Imm64(0),
        );
        // T0 = 기준 주소 + 8
        d.emit_add(
            MicroOperand::Temp(0),
            MicroOperand::Imm64(0x1008),
            MicroOperand::Imm64(0),
        );
        // 각 폭으로 Write (중첩/비중첩)
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 1 })
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(0xAB)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 2 })
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(0xCDEF)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 4 })
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(0x11223344)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
                .with_src1(MicroOperand::Temp(0))
                .with_src2(MicroOperand::Imm64(0xDEADBEEFCAFEF00D)),
        );
        // 각 폭으로 Read back
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width: 1 })
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::VReg(0)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width: 2 })
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::VReg(0)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width: 4 })
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(0)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width: 8 })
                .with_dst(MicroOperand::VReg(4))
                .with_src1(MicroOperand::Temp(0)),
        );
        // 폭 초과 읽기 (8바이트 폭, 4바이트만 기입된 영역 → 상위 0)
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width: 8 })
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(0)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff(seed, &prog, &[0u64; 16]);
    }
}

/// NativeCallBridge — 인지된 no-op 스텁 차등 (상태 불변).
#[test]
fn test_poly_diff_native_call_bridge() {
    for seed in DIFF_SEEDS {
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x1234),
            MicroOperand::Imm64(0),
        );
        // 즉시 인자와 dst 를 가진 브리지 — VM 상태 변화 없이 스트림만 소비.
        d.instrs.push(
            MicroInstr::new(RiscOp::NativeCallBridge)
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::Imm64(0x9999)),
        );
        // 뒤따르는 연산이 정상 실행되어야 한다 (스트림 sync 유지).
        d.emit_add(
            MicroOperand::VReg(6),
            MicroOperand::VReg(0),
            MicroOperand::Imm64(1),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff(seed, &prog, &[0u64; 16]);
    }
}

/// VirtualBranch 차등 — 모든 조건(포함 CounterZero 폭)을 **미충족(not-taken)** 상태로
/// 배치해 롤링 키 스트림을 선형으로 유지하면서 분기 판정이 eval_state 와 일치하는지 검증.
/// (taken 분기의 VIP 점프 자체는 아래 `branch_taken_with_state` 단위 테스트가 담당.)
#[test]
fn test_poly_diff_virtual_branch_not_taken_all_conditions() {
    // 롤링 키 스트림은 선형 실행만 동기를 유지하므로, 분기 **미충족(not-taken)** 조건들을
    // 배치해 분기 판정이 eval_state 와 일치하는지 차등 검증한다 (잘못 taken 되면 키가
    // desync 되어 실패). taken 판정 자체는 아래 `test_branch_taken_with_state_all_conditions`
    // 가 모든 조건(포함 CounterZero 폭)을 단위 검증한다.
    for seed in DIFF_SEEDS {
        let mut d = RiscDesynthesizer::new();
        // R0=10, R1=5 (CounterZero 검증: RCX=reg1=5 != 0 → not taken)
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(10),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(5),
            MicroOperand::Imm64(0),
        );
        // 플래그를 ZF=1|PF=1 (0x44) 로 명시 설정
        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x44)));

        // ZF=1, PF=1, CF=0, SF=0, OF=0, reg1=5 에서 반드시 **not-taken** 인 조건들
        let not_taken: &[BranchCondition] = &[
            BranchCondition::NotZero,        // !ZF → false
            BranchCondition::Carry,          // CF=0 → false
            BranchCondition::Sign,           // SF=0 → false
            BranchCondition::Overflow,       // OF=0 → false
            BranchCondition::Greater,        // ZF=1 → false
            BranchCondition::Less,           // SF==OF → false
            BranchCondition::Above,          // ZF=1 → false
            BranchCondition::Below,          // CF=0 → false
            BranchCondition::NotParity,      // PF=1 → false
            BranchCondition::CounterZero(2), // reg1=5 != 0 → false
            BranchCondition::CounterZero(4),
            BranchCondition::CounterZero(8),
        ];

        for cond in not_taken {
            // 절대-인덱스 타깃 (src1 없음, imm=타깃) — not-taken 이므로 무시됨
            d.instrs
                .push(MicroInstr::new(RiscOp::VirtualBranch { cond: *cond }).with_imm(99));
            // 간접(src1 동적) 타깃 — 역시 not-taken
            d.instrs.push(
                MicroInstr::new(RiscOp::VirtualBranch { cond: *cond })
                    .with_src1(MicroOperand::VReg(0))
                    .with_imm(99),
            );
        }

        // 이후 연산이 정상 실행되어야 한다 (분기 미충족 → 선형 진행).
        d.emit_add(
            MicroOperand::VReg(6),
            MicroOperand::VReg(0),
            MicroOperand::Imm64(1),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff(seed, &prog, &[0u64; 16]);
    }
}

/// branch_taken_with_state — 모든 조건의 taken/not-taken 판정을 단위 검증
/// (CounterZero 폭별 RCX 하위 바이트 검사 포함).
#[test]
fn test_branch_taken_with_state_all_conditions() {
    let mut flags = VirtualFlags::default();
    // ZF=1, SF=0, OF=0, CF=0, PF=1
    flags.raw = crate::vm::risc::flags::VFLAG_ZF | crate::vm::risc::flags::VFLAG_PF;
    let mut regs = [0u64; 16];
    regs[1] = 0x1234_5678_9ABC_0000; // low16 == 0, low32 != 0, full != 0

    let check = |cond: BranchCondition, flags: &VirtualFlags, regs: &[u64; 16], expect: bool| {
        assert_eq!(
            branch_taken_with_state(cond, flags, regs),
            expect,
            "cond {cond:?}",
        );
    };

    check(BranchCondition::Always, &flags, &regs, true);
    check(BranchCondition::Zero, &flags, &regs, true);
    check(BranchCondition::NotZero, &flags, &regs, false);
    check(BranchCondition::Carry, &flags, &regs, false);
    check(BranchCondition::NotCarry, &flags, &regs, true);
    check(BranchCondition::Sign, &flags, &regs, false);
    check(BranchCondition::NotSign, &flags, &regs, true);
    check(BranchCondition::Overflow, &flags, &regs, false);
    check(BranchCondition::NotOverflow, &flags, &regs, true);
    check(BranchCondition::Greater, &flags, &regs, false); // ZF=1
    check(BranchCondition::Less, &flags, &regs, false); // SF==OF
    check(BranchCondition::GreaterOrEqual, &flags, &regs, true); // SF==OF
    check(BranchCondition::LessOrEqual, &flags, &regs, true); // ZF=1
    check(BranchCondition::Above, &flags, &regs, false); // ZF=1
    check(BranchCondition::AboveOrEqual, &flags, &regs, true); // CF=0
    check(BranchCondition::Below, &flags, &regs, false); // CF=0
    check(BranchCondition::BelowOrEqual, &flags, &regs, true); // ZF=1
    check(BranchCondition::Parity, &flags, &regs, true); // PF=1
    check(BranchCondition::NotParity, &flags, &regs, false);

    // CounterZero: RCX(reg1) low bytes
    check(BranchCondition::CounterZero(2), &flags, &regs, true); // low16 = 0x0000 == 0
    check(BranchCondition::CounterZero(4), &flags, &regs, false); // low32 = 0x9ABC0000 != 0
    check(BranchCondition::CounterZero(8), &flags, &regs, false); // full != 0
    regs[1] = 0;
    check(BranchCondition::CounterZero(2), &flags, &regs, true);
    check(BranchCondition::CounterZero(4), &flags, &regs, true);
    check(BranchCondition::CounterZero(8), &flags, &regs, true);
}
// ---- 요구되는 명명 차등 테스트 (PolymorphicInterpreter == eval_state, >=3 seeds) ----

/// `run_diff` 의 시드된 메모리 버전 — 인터프리터 `with_mem` 과 참조 `eval_state_with_mem`
/// 에 동일한 초기 메모리를 주입하고 전체 상태(regs/temps/flags/vsp/stack/mem)를 비교한다.
fn run_diff_mem(seed: u64, prog: &RiscProgram, init_regs: &[u64; 16], mem: HashMap<u64, u8>) {
    let ref_st = prog.eval_state_with_mem(init_regs, mem.clone());

    let mut enc = PolymorphicEncoder::new(seed);
    let bytecode = enc.encode(prog).unwrap();
    let mut interp = PolymorphicInterpreter::new(seed);
    interp.regs = *init_regs;
    let mut interp = interp.with_mem(mem);
    interp.run(&bytecode).unwrap();

    assert_full_state_eq(&interp, &ref_st);
}

/// ArithmeticShiftRight 차등 — 음수/양수 소스, 즉시+레지스터 카운트, 시프트 수 0..63 전부.
#[test]
fn test_poly_arith_shift_matches_reference() {
    for seed in DIFF_SEEDS {
        let mut d = RiscDesynthesizer::new();
        // R0 = 음수 소스 (부호 비트 유지 확인), R1 = 양수 소스
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0xFFFF_FFFF_FFFF_FFF0),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(0x1234_5678_9ABC_DEF0),
            MicroOperand::Imm64(0),
        );
        // R2 = 레지스터 카운트 (register-count SAR)
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(7),
            MicroOperand::Imm64(0),
        );
        // 즉시 카운트 0..63 전부
        for cnt in 0u64..64 {
            d.instrs.push(
                MicroInstr::new(RiscOp::ArithmeticShiftRight)
                    .with_dst(MicroOperand::VReg(3))
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::Imm64(cnt)),
            );
        }
        // 레지스터 카운트 SAR (R1 >> R2)
        d.instrs.push(
            MicroInstr::new(RiscOp::ArithmeticShiftRight)
                .with_dst(MicroOperand::VReg(4))
                .with_src1(MicroOperand::VReg(1))
                .with_src2(MicroOperand::VReg(2)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff(seed, &prog, &[0u64; 16]);
    }
}

/// MemoryRead/MemoryWrite (폭 1/2/4/8) 차등 — **시드된 초기 메모리**를 인터프리터
/// (`with_mem`)와 참조 (`eval_state_with_mem`) 양쪽에 주입하고, 특히 mem 전체 상태를 비교.
#[test]
fn test_poly_mem_rw_matches_reference() {
    for seed in DIFF_SEEDS {
        // 초기 메모리 시드: 0x2000 영역 16바이트 패턴
        let mut seed_mem = HashMap::new();
        for i in 0u64..16 {
            seed_mem.insert(0x2000 + i, ((i * 7 + 3) & 0xFF) as u8);
        }
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x2000),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::Temp(0),
            MicroOperand::Imm64(0x3000),
            MicroOperand::Imm64(0),
        );
        // 시드 메모리에서 폭별 읽기 (R1/R2/R4/R8)
        for w in [1u8, 2, 4, 8] {
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width: w })
                    .with_dst(MicroOperand::VReg(w))
                    .with_src1(MicroOperand::VReg(0)),
            );
        }
        // 폭별 쓰기 (0x3000 에 8/2, 0x2000 에 4/1 — 일부 중첩)
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
                .with_src1(MicroOperand::Temp(0))
                .with_src2(MicroOperand::Imm64(0xDEAD_BEEF_CAFE_F00D)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 4 })
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(0x1122_3344)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 2 })
                .with_src1(MicroOperand::Temp(0))
                .with_src2(MicroOperand::Imm64(0xABCD)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 1 })
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(0x5A)),
        );
        // 쓴 영역을 다시 읽어 확인
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width: 8 })
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::Temp(0)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width: 4 })
                .with_dst(MicroOperand::VReg(6))
                .with_src1(MicroOperand::VReg(0)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff_mem(seed, &prog, &[0u64; 16], seed_mem);
    }
}

/// VirtualBranch 차등 — **taken AND not-taken**, CounterZero(2/4/8) 포함.
/// taken 분기는 인스트럭션-인덱스 타깃을 `instr_starts`로 바이트 오프셋으로 변환해
/// 점프하며, 건너뛴 영역의 롤링 키스트림을 `fast_forward_roll`로 동기화한다.
#[test]
fn test_poly_branch_matches_reference() {
    for seed in DIFF_SEEDS {
        // (1) taken(forward) — ZF=1 이면 index1 의 분기가 index3 으로 점프, index2 는 건너뜀
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0),
            MicroOperand::Imm64(0),
        ); // index0: ZF=1
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
        ); // index2: 건너뜀
        d.emit_add(
            MicroOperand::VReg(6),
            MicroOperand::Imm64(222),
            MicroOperand::Imm64(0),
        ); // index3: 실작업
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
        run_diff(seed, &RiscProgram::new(d.instrs), &[0u64; 16]);

        // (2) not-taken — ZF=0 이면 fall-through
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(5),
            MicroOperand::Imm64(0),
        ); // index0: ZF=0
        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Zero,
            })
            .with_imm(4),
        ); // index1
        d.emit_add(
            MicroOperand::VReg(6),
            MicroOperand::Imm64(222),
            MicroOperand::Imm64(0),
        ); // index2
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index3
        d.emit_add(
            MicroOperand::VReg(7),
            MicroOperand::Imm64(999),
            MicroOperand::Imm64(0),
        ); // index4: 미도달
        run_diff(seed, &RiscProgram::new(d.instrs), &[0u64; 16]);

        // (3) taken(간접, src1 동적 타깃) — R5=4 가 타깃 인덱스, index3 으로 점프해 index2 건너뜀
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0),
            MicroOperand::Imm64(0),
        ); // index0: ZF=1
        d.emit_add(
            MicroOperand::VReg(5),
            MicroOperand::Imm64(4),
            MicroOperand::Imm64(0),
        ); // index1: R5=4 (동적 타깃)
        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Zero,
            })
            .with_src1(MicroOperand::VReg(5)),
        ); // index2
        d.emit_add(
            MicroOperand::VReg(7),
            MicroOperand::Imm64(111),
            MicroOperand::Imm64(0),
        ); // index3: 건너뜀
        d.emit_add(
            MicroOperand::VReg(6),
            MicroOperand::Imm64(222),
            MicroOperand::Imm64(0),
        ); // index4: 실작업(타깃)
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index5
        run_diff(seed, &RiscProgram::new(d.instrs), &[0u64; 16]);

        // (4) CounterZero 폭별 taken(reg[1]=0) & not-taken(reg[1] 전 폭 nonzero)
        for w in [2u8, 4, 8] {
            // taken
            let mut d = RiscDesynthesizer::new();
            d.instrs.push(
                MicroInstr::new(RiscOp::VirtualBranch {
                    cond: BranchCondition::CounterZero(w),
                })
                .with_imm(3),
            ); // index0
            d.emit_add(
                MicroOperand::VReg(7),
                MicroOperand::Imm64(111),
                MicroOperand::Imm64(0),
            ); // index1: 건너뜀
            d.emit_add(
                MicroOperand::VReg(8),
                MicroOperand::Imm64(55),
                MicroOperand::Imm64(0),
            ); // index2: 건너뜀
            d.emit_add(
                MicroOperand::VReg(6),
                MicroOperand::Imm64(222),
                MicroOperand::Imm64(0),
            ); // index3: 실작업
            d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
            run_diff(seed, &RiscProgram::new(d.instrs), &[0u64; 16]);

            // not-taken
            let mut d = RiscDesynthesizer::new();
            d.instrs.push(
                MicroInstr::new(RiscOp::VirtualBranch {
                    cond: BranchCondition::CounterZero(w),
                })
                .with_imm(3),
            ); // index0
            d.emit_add(
                MicroOperand::VReg(7),
                MicroOperand::Imm64(111),
                MicroOperand::Imm64(0),
            ); // index1
            d.emit_add(
                MicroOperand::VReg(8),
                MicroOperand::Imm64(55),
                MicroOperand::Imm64(0),
            ); // index2
            d.emit_add(
                MicroOperand::VReg(6),
                MicroOperand::Imm64(222),
                MicroOperand::Imm64(0),
            ); // index3
            d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
            let mut regs = [0u64; 16];
            regs[1] = 0x1234_5678_9ABC_DEF0; // 모든 폭에서 0 이 아님
            run_diff(seed, &RiscProgram::new(d.instrs), &regs);
        }
    }
}

/// backward 분기(루프) 차등 — 리뷰 지적 #2 검증. backward 점프에서 타깃 위치의
/// 롤링 키가 복원되지 않으면 두 번째 loop부터 스트림이 desync 되어(오류/잘못된
/// 실행) reference 와 어긋나야 한다. 수정 후에는 N회 루프를 돌아도 전체 상태가
/// eval_state 와 일치해야 한다.
#[test]
fn test_poly_backward_branch_loop_matches_reference() {
    for seed in DIFF_SEEDS {
        // R1 = 카운터(5) → 루프 헤드에서 10씩 더하고 1씩 감소.
        // ZF=0(카운터 != 0) 동안 backward 분기(NotZero -> index1)로 반복.
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(5),
            MicroOperand::Imm64(0),
        ); // index0
           // ── loop head (index1) ──
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::VReg(0),
            MicroOperand::Imm64(10),
        ); // index1: R0 += 10
        d.emit_sub(
            MicroOperand::VReg(1),
            MicroOperand::VReg(1),
            MicroOperand::Imm64(1),
        ); // index2(NOT)+index3(SUB): R1 -= 1
        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::NotZero,
            })
            .with_imm(1), // index4: ZF=0 → loop
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index5

        let prog = RiscProgram::new(d.instrs);
        let ref_st = prog.eval_state(&[0u64; 16]);
        assert_eq!(ref_st.regs[0], 50, "R0 must be 5 iterations x 10");
        assert_eq!(ref_st.regs[1], 0, "R1 counter must hit 0");

        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.run(&bytecode).unwrap();
        assert_full_state_eq(&interp, &ref_st);

        // 추가: backward 분기가 여러 개 연속(중첩 감소 루프)일 때도 동일.
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(3),
            MicroOperand::Imm64(0),
        ); // outer=3
        let outer_head = d.instrs.len(); // ── outer 루프 헤드 ──
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(4),
            MicroOperand::Imm64(0),
        ); // inner=4 (외부 반복마다 리셋)
        let inner_head = d.instrs.len(); // ── inner 루프 헤드 ──
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::VReg(0),
            MicroOperand::Imm64(100),
        ); // R0 += 100 (3x4회)
        d.emit_sub(
            MicroOperand::VReg(2),
            MicroOperand::VReg(2),
            MicroOperand::Imm64(1),
        ); // inner -= 1
        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::NotZero,
            })
            .with_imm(inner_head as u64), // inner 루프 (backward)
        );
        d.emit_sub(
            MicroOperand::VReg(1),
            MicroOperand::VReg(1),
            MicroOperand::Imm64(1),
        ); // outer -= 1
        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::NotZero,
            })
            .with_imm(outer_head as u64), // outer 루프 (backward)
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);
        let ref_st = prog.eval_state(&[0u64; 16]);
        assert_eq!(ref_st.regs[0], 3 * 4 * 100, "nested loop iterations");

        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.run(&bytecode).unwrap();
        assert_full_state_eq(&interp, &ref_st);
    }
}

/// NativeCallBridge no-op 스텁 차등 — 브리지 양쪽(즉시/레지스터 인자 포함)에서 상태 불변,
/// 이후 연산이 스트림 동기를 유지하며 정상 실행됨을 전체 상태로 확인.
#[test]
fn test_poly_native_call_bridge_stub() {
    for seed in DIFF_SEEDS {
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x1234),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::NativeCallBridge)
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::Imm64(0x9999)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::NativeCallBridge)
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
        );
        d.emit_add(
            MicroOperand::VReg(6),
            MicroOperand::VReg(0),
            MicroOperand::Imm64(1),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff(seed, &prog, &[0u64; 16]);
    }
}

/// 전체 도달 가능한 RiscOp 집합(메모리 폭별 + VirtualBranch 포함)의 opcode 맵
/// 유일성/일관성 검증 — 전 opcode 바이트 유일, forward/reverse 맵 일치, 충돌 없음,
/// VirtualBranch 조건 부호화도 전 조건 유일 라운드트립.
#[test]
fn test_poly_opcode_map_uniqueness_complete_isa() {
    use crate::vm::poly::VirtualIsaSpec;
    for seed in DIFF_SEEDS {
        let spec = VirtualIsaSpec::from_seed(seed);

        let full: Vec<RiscOp> = vec![
            RiscOp::Nor,
            RiscOp::AddWithCarry,
            RiscOp::ShiftRight,
            RiscOp::ArithmeticShiftRight,
            RiscOp::ShiftLeft,
            RiscOp::VirtualPush,
            RiscOp::VirtualPop,
            RiscOp::MemoryRead { width: 1 },
            RiscOp::MemoryRead { width: 2 },
            RiscOp::MemoryRead { width: 4 },
            RiscOp::MemoryRead { width: 8 },
            RiscOp::MemoryWrite { width: 1 },
            RiscOp::MemoryWrite { width: 2 },
            RiscOp::MemoryWrite { width: 4 },
            RiscOp::MemoryWrite { width: 8 },
            RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            },
            RiscOp::NativeCallBridge,
            RiscOp::SetFlag,
            RiscOp::Halt,
            RiscOp::Mov,
            RiscOp::Multiply {
                signed: false,
                width: 8,
            },
            RiscOp::Multiply {
                signed: true,
                width: 4,
            },
            RiscOp::MultiplyLow {
                signed: true,
                width: 8,
            },
            RiscOp::Divide {
                signed: false,
                width: 8,
            },
            RiscOp::Divide {
                signed: true,
                width: 4,
            },
            RiscOp::BSwap { width: 4 },
            RiscOp::BSwap { width: 8 },
            RiscOp::BitScanForward,
            RiscOp::BitScanReverse,
            RiscOp::CountTrailingZeros { width: 8 },
            RiscOp::CountLeadingZeros { width: 8 },
            RiscOp::PopCount,
            RiscOp::Setcc {
                cond: BranchCondition::Always,
            },
            RiscOp::ConditionalMove {
                cond: BranchCondition::Always,
            },
            RiscOp::CompareExchange { width: 8 },
        ];

        // 전 opcode 존재
        for op in &full {
            assert!(spec.opcode_for(*op).is_some(), "missing opcode for {op:?}");
        }
        // 유일성
        let mut bytes: Vec<u8> = full
            .iter()
            .map(|op| spec.opcode_for(*op).unwrap())
            .collect();
        bytes.sort_unstable();
        bytes.dedup();
        assert_eq!(bytes.len(), full.len(), "opcode collision in complete ISA");
        // forward/reverse 일치
        for op in &full {
            let b = spec.opcode_for(*op).unwrap();
            assert_eq!(
                spec.reverse_opcode_map.get(&b),
                Some(op),
                "reverse map inconsistent for {op:?}"
            );
        }
        assert_eq!(spec.opcode_map.len(), spec.reverse_opcode_map.len());

        // 모든 VirtualBranch 조건 유일 부호화 라운드트립
        let conds = [
            BranchCondition::Always,
            BranchCondition::Zero,
            BranchCondition::NotZero,
            BranchCondition::Carry,
            BranchCondition::NotCarry,
            BranchCondition::Sign,
            BranchCondition::NotSign,
            BranchCondition::Overflow,
            BranchCondition::NotOverflow,
            BranchCondition::Greater,
            BranchCondition::Less,
            BranchCondition::GreaterOrEqual,
            BranchCondition::LessOrEqual,
            BranchCondition::Above,
            BranchCondition::AboveOrEqual,
            BranchCondition::Below,
            BranchCondition::BelowOrEqual,
            BranchCondition::Parity,
            BranchCondition::NotParity,
            BranchCondition::CounterZero(2),
            BranchCondition::CounterZero(4),
            BranchCondition::CounterZero(8),
        ];
        let mut cond_bytes: Vec<u8> = Vec::new();
        for cond in conds {
            let b = spec.encode_cond(cond);
            cond_bytes.push(b);
            assert_eq!(spec.decode_cond(b), Some(cond), "cond roundtrip {cond:?}");
        }
        cond_bytes.sort_unstable();
        cond_bytes.dedup();
        assert_eq!(cond_bytes.len(), 22, "branch cond byte collision");
    }
}

// ── P2: 신규 정수/비트/제어 연산 차등 검증 (인터프리터 == eval_state) ──────────

/// Mov — 플래그를 변경하지 않는 순수 복사 (MOV 뒤 Jcc 의 플래그 보존 핵심).
#[test]
fn test_poly_diff_mov_preserves_flags() {
    for seed in DIFF_SEEDS {
        let mut d = RiscDesynthesizer::new();
        // ZF=1 설정 (플래그)
        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x40)));
        // R0 = 0x1234 ; R1 = R0 (Mov — 플래그 무변경)
        d.instrs.push(
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::VReg(0))
                .with_src1(MicroOperand::Imm64(0x1234)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::VReg(0)),
        );
        // ZF=1 인 상태에서 NotZero 분기가 not-taken 이어야 한다 (Mov 가 ZF 를 깨지 않음).
        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::NotZero,
            })
            .with_imm(6),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
        d.emit_add(
            MicroOperand::VReg(7),
            MicroOperand::Imm64(999),
            MicroOperand::Imm64(0),
        ); // index5: 도달 안 함
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index6
        let prog = RiscProgram::new(d.instrs);
        run_diff(seed, &prog, &[0u64; 16]);
    }
}

/// Multiply / MultiplyLow (부호·폭별) — RDX(=reg2) 고/저 결과 + CF|OF.
#[test]
fn test_poly_diff_multiply() {
    for seed in DIFF_SEEDS {
        let mut d = RiscDesynthesizer::new();
        // R0 = 0x1_0000_0001 (고/저 분리 확인), R1 = 3
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x1_0000_0001),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(3),
            MicroOperand::Imm64(0),
        );
        // unsigned MUL r64: RDX:RAX = R0 * R1
        d.instrs.push(
            MicroInstr::new(RiscOp::Multiply {
                signed: false,
                width: 8,
            })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::VReg(1)),
        );
        // signed IMUL r32 (32비트 폭)
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(0x7FFF_FFFF),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MultiplyLow {
                signed: true,
                width: 4,
            })
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(2))
            .with_src2(MicroOperand::Imm64(2)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff(seed, &prog, &[0u64; 16]);
    }
}

/// Divide / IDivide (부호·폭별) — RDX:RAX 피제수, RAX 몫, RDX 나머지.
#[test]
fn test_poly_diff_divide() {
    for seed in DIFF_SEEDS {
        let mut d = RiscDesynthesizer::new();
        // 64비트 unsigned: R2(RDX)=0, R0(RAX)=1000 ; divisor R1=7
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(1000),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(0),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(7),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::Divide {
                signed: false,
                width: 8,
            })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::VReg(1)),
        );
        // 32비트 signed IDIV: EDX:EAX = -1000 (0xFFFFFFFF:0xFFFFFC18) / 7 → q=-142, r=-6.
        // (첫 64비트 DIV 가 R0/R2 를 덮어쓰므로 IDIV 전에 피제수를 정확히 재세팅한다.)
        d.emit_add(
            MicroOperand::VReg(3),
            MicroOperand::Imm64(0),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::VReg(0))
                .with_src1(MicroOperand::Imm64(0xFFFF_FC18)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::Imm64(0xFFFF_FFFF)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::Divide {
                signed: true,
                width: 4,
            })
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(1)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff(seed, &prog, &[0u64; 16]);
    }
}

/// BSwap / BitScan / Count* / PopCount — 비트 연산 전 계열.
#[test]
fn test_poly_diff_bitscan_and_count() {
    for seed in DIFF_SEEDS {
        let mut d = RiscDesynthesizer::new();
        // R0 = 0x0102030405060708
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x0102_0304_0506_0708),
            MicroOperand::Imm64(0),
        );
        // BSWAP r64
        d.instrs.push(
            MicroInstr::new(RiscOp::BSwap { width: 8 })
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::VReg(0)),
        );
        // BSF / BSR
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(0x1000),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::BitScanForward)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(2)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::BitScanReverse)
                .with_dst(MicroOperand::VReg(4))
                .with_src1(MicroOperand::VReg(2)),
        );
        // BSF src==0 → ZF=1, dst=0
        d.instrs.push(
            MicroInstr::new(RiscOp::BitScanForward)
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::Imm64(0)),
        );
        // TZCNT / LZCNT (64비트 폭)
        d.instrs.push(
            MicroInstr::new(RiscOp::CountTrailingZeros { width: 8 })
                .with_dst(MicroOperand::VReg(6))
                .with_src1(MicroOperand::Imm64(0x1000)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::CountLeadingZeros { width: 8 })
                .with_dst(MicroOperand::VReg(7))
                .with_src1(MicroOperand::Imm64(0x8000_0000_0000_0000)),
        );
        // POPCNT
        d.emit_add(
            MicroOperand::VReg(4),
            MicroOperand::Imm64(0xFF),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::PopCount)
                .with_dst(MicroOperand::Temp(0))
                .with_src1(MicroOperand::VReg(4)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff(seed, &prog, &[0u64; 16]);
    }
}

/// Setcc / ConditionalMove — 조건 평가 (하드웨어 setcc/cmovcc 와 동치).
#[test]
fn test_poly_diff_setcc_cmov() {
    for seed in DIFF_SEEDS {
        let mut d = RiscDesynthesizer::new();
        // ZF=1|CF=0|SF=0|OF=0 → Equal/AboveOrEqual/Parity(짝수 패리티는 보장 안 됨)
        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x44)));
        // SETcc: Zero → 1, NotZero → 0
        d.instrs.push(
            MicroInstr::new(RiscOp::Setcc {
                cond: BranchCondition::Zero,
            })
            .with_dst(MicroOperand::VReg(1)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::Setcc {
                cond: BranchCondition::NotZero,
            })
            .with_dst(MicroOperand::VReg(2)),
        );
        // CMOVcc: R3 = ZF ? R4 : R3 (R3=0, R4=7 → 7)
        d.emit_add(
            MicroOperand::VReg(4),
            MicroOperand::Imm64(7),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::Zero,
            })
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(4)),
        );
        // CMOVcc not-taken: R5 = NotZero ? 9 : R5 → 그대로 0
        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::NotZero,
            })
            .with_dst(MicroOperand::VReg(5))
            .with_src1(MicroOperand::Imm64(9)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff(seed, &prog, &[0u64; 16]);
    }
}

/// CompareExchange — 시드된 메모리에서 일치/불일치 두 경로 (전 상태 비교).
#[test]
fn test_poly_diff_compare_exchange() {
    for seed in DIFF_SEEDS {
        let mut seed_mem = HashMap::new();
        // 0x2000: 8바이트 0x1122334455667788 (acc 와 불일치)
        for (i, b) in 0x1122_3344_5566_7788u64.to_le_bytes().iter().enumerate() {
            seed_mem.insert(0x2000 + i as u64, *b);
        }
        // 0x3000: 8바이트 0x00000000DEADBEEF (acc 와 일치)
        for (i, b) in 0x0000_0000_DEAD_BEEFu64.to_le_bytes().iter().enumerate() {
            seed_mem.insert(0x3000 + i as u64, *b);
        }
        let mut d = RiscDesynthesizer::new();
        // R0 = acc = 0xDEADBEEF (일치 케이스); R1 = 0x2000 주소; R2 = 0x3000 주소; R3 = new
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0xDEAD_BEEF),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(0x2000),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(0x3000),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(3),
            MicroOperand::Imm64(0xCAFE_F00D),
            MicroOperand::Imm64(0),
        );
        // 일치 케이스: [0x3000]==acc → [0x3000]=new, ZF=1
        d.instrs.push(
            MicroInstr::new(RiscOp::CompareExchange { width: 8 })
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::VReg(3)),
        );
        // acc(RAX) 을 불일치 값으로: R0 = 0x9999
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x9999),
            MicroOperand::Imm64(0),
        );
        // 불일치 케이스: [0x2000] != acc → RAX = [0x2000], ZF=0
        d.instrs.push(
            MicroInstr::new(RiscOp::CompareExchange { width: 8 })
                .with_src1(MicroOperand::VReg(1))
                .with_src2(MicroOperand::VReg(3)),
        );
        // 다시 일치 케이스 (불일치 후 RAX 가 [0x2000] 값으로 바뀜)
        d.instrs.push(
            MicroInstr::new(RiscOp::CompareExchange { width: 8 })
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::Imm64(0x1234)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        run_diff_mem(seed, &prog, &[0u64; 16], seed_mem);
    }
}

// ── v64: 결정적 랜덤 차등 퍼즈 ────────────────────────────────────────────
// 산술/비트/시프트(count 0 포함)/메모리/유계 루프(backward 분기)를 무작위로
// 조합한 프로그램을 다수 생성해 `eval_state`(참조)와 폴리 인터프리터의 전체
// 상태를 비교한다. 리뷰 #2(backward 분기 키 복원)·#3/#4(shift count=0 플래그)를
// 같은 시드로 반복해 되짚는다. PRNG 는 결정적이므로 실패 시 재현 가능.
/// 실패 시 프로그램 전체를 출력하기 위한 간단한 포매터.
fn format_prog(prog: &RiscProgram) -> String {
    use crate::vm::risc::MicroOperand;
    let mo = |o: &Option<MicroOperand>| match o {
        Some(MicroOperand::VReg(i)) => format!("v{i}"),
        Some(MicroOperand::Temp(i)) => format!("t{i}"),
        Some(MicroOperand::Imm64(v)) => format!("0x{v:X}"),
        Some(MicroOperand::Vflags) => "fl".into(),
        Some(MicroOperand::Vsp) => "sp".into(),
        None => "-".into(),
    };
    let mut s = String::new();
    for (i, ins) in prog.instrs.iter().enumerate() {
        s.push_str(&format!(
            "  {i:04}: {:?} dst={} src1={} src2={} imm=0x{:X}\n",
            ins.op,
            mo(&ins.dst),
            mo(&ins.src1),
            mo(&ins.src2),
            ins.imm
        ));
    }
    s
}

#[test]
fn test_poly_fuzz_random_programs_match_reference() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    use crate::vm::risc::{BranchCondition, MicroInstr, MicroOperand, RiscDesynthesizer, RiscOp};

    fn rand_operand(rng: &mut Rng, max_reg: u8) -> MicroOperand {
        if rng.below(3) == 0 {
            MicroOperand::Imm64(rng.next())
        } else {
            MicroOperand::VReg(rng.below(max_reg as u64) as u8)
        }
    }

    fn emit_random_op(rng: &mut Rng, d: &mut RiscDesynthesizer) {
        let dst = MicroOperand::VReg(rng.below(8) as u8);
        let a = rand_operand(rng, 8);
        let b = rand_operand(rng, 8);
        match rng.below(8) {
            0 => d.emit_add(dst, a, b),
            1 => d.emit_sub(dst, a, b),
            2 => d.emit_xor(dst, a, b),
            3 => {
                // count 0..63 — 0 을 자주 포함해 count==0 플래그 보존 검증.
                let cnt = if rng.below(4) == 0 {
                    MicroOperand::Imm64(0)
                } else {
                    MicroOperand::Imm64(rng.below(64))
                };
                let op = match rng.below(3) {
                    0 => RiscOp::ShiftRight,
                    1 => RiscOp::ShiftLeft,
                    _ => RiscOp::ArithmeticShiftRight,
                };
                d.instrs.push(
                    MicroInstr::new(op)
                        .with_dst(dst)
                        .with_src1(a)
                        .with_src2(cnt),
                );
            }
            4 => d.emit_and(dst, a, b),
            5 => d.emit_or(dst, a, b),
            6 => {
                let addr = MicroOperand::VReg(rng.below(4) as u8);
                d.instrs.push(
                    MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
                        .with_src1(addr)
                        .with_src2(a),
                );
            }
            _ => {
                let addr = MicroOperand::VReg(rng.below(4) as u8);
                d.instrs.push(
                    MicroInstr::new(RiscOp::MemoryRead { width: 8 })
                        .with_dst(dst)
                        .with_src1(addr),
                );
            }
        }
    }

    fn gen_random_prog(rng: &mut Rng) -> RiscProgram {
        let mut d = RiscDesynthesizer::new();
        let chunks = 2 + rng.below(4); // 2..5 청크
        for _ in 0..chunks {
            if rng.below(2) == 0 {
                // 유계 루프 (backward 분기): 반복 종료가 보장되어 퍼즈가 안전.
                // 카운터는 바디가 절대 쓰지 않는 VReg(15) 사용 (바디는 0..8만 접근).
                let iters = 1 + rng.below(4);
                d.emit_add(
                    MicroOperand::VReg(15),
                    MicroOperand::Imm64(iters),
                    MicroOperand::Imm64(0),
                );
                let head = d.instrs.len();
                let body = 2 + rng.below(4);
                for _ in 0..body {
                    emit_random_op(rng, &mut d);
                }
                d.emit_sub(
                    MicroOperand::VReg(15),
                    MicroOperand::VReg(15),
                    MicroOperand::Imm64(1),
                );
                d.instrs.push(
                    MicroInstr::new(RiscOp::VirtualBranch {
                        cond: BranchCondition::NotZero,
                    })
                    .with_imm(head as u64),
                );
            } else {
                let body = 2 + rng.below(4);
                for _ in 0..body {
                    emit_random_op(rng, &mut d);
                }
            }
        }
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        RiscProgram::new(d.instrs)
    }

    let mut rng = Rng(0x9E3779B97F4A7C15);
    for seed in DIFF_SEEDS {
        for case in 0..80usize {
            let prog = gen_random_prog(&mut rng);
            let ref_st = prog.eval_state(&[0u64; 16]);
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();
            // 인코더/디코더 라운드트립도 동시에 검증 (문제 소스 분리용).
            let mut dec = super::super::decoder::PolymorphicDecoder::new(seed);
            let decoded = dec.decode(&bytecode).unwrap();
            assert_eq!(
                decoded.instrs.len(),
                prog.instrs.len(),
                "seed={seed:#X} case={case}: decoder lost instructions"
            );
            for (a, b) in decoded.instrs.iter().zip(prog.instrs.iter()) {
                assert_eq!(
                    (a.op, a.dst, a.src1, a.src2, a.imm),
                    (b.op, b.dst, b.src1, b.src2, b.imm),
                    "seed={seed:#X} case={case}: decode round-trip mismatch"
                );
            }
            let mut interp = PolymorphicInterpreter::new(seed);
            interp
                .run(&bytecode)
                .unwrap_or_else(|e| panic!("seed={seed:#X} case={case}: poly run failed: {e:?}"));
            let mut ok = true;
            let mut where_fail = String::new();
            if interp.regs != ref_st.regs {
                ok = false;
                where_fail.push_str(&format!(
                    "regs:\n  interp={:#X?}\n  ref={:#X?}\n",
                    interp.regs, ref_st.regs
                ));
            }
            if interp.temps != ref_st.temps {
                ok = false;
                where_fail.push_str(&format!(
                    "temps: {:#X?} vs {:#X?}\n",
                    interp.temps, ref_st.temps
                ));
            }
            if interp.flags.raw != ref_st.flags {
                ok = false;
                where_fail.push_str(&format!(
                    "flags: {:#X} vs {:#X}\n",
                    interp.flags.raw, ref_st.flags
                ));
            }
            if interp.vsp != ref_st.vsp {
                ok = false;
                where_fail.push_str(&format!("vsp: {:#X} vs {:#X}\n", interp.vsp, ref_st.vsp));
            }
            if interp.stack != ref_st.stack {
                ok = false;
                where_fail.push_str(&format!(
                    "stack: {:#X?} vs {:#X?}\n",
                    interp.stack, ref_st.stack
                ));
            }
            if interp.mem != ref_st.mem {
                ok = false;
                where_fail.push_str(&format!(
                    "mem:\n  interp={:#X?}\n  ref={:#X?}\n",
                    interp.mem, ref_st.mem
                ));
            }
            assert!(
                ok,
                "seed={seed:#X} case={case}: poly != reference\n{where_fail}prog:\n{}",
                format_prog(&prog)
            );
        }
    }
}
