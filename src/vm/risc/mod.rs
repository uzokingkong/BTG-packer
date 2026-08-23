pub mod desynth;
pub mod eval;
pub mod flags;
pub mod high_byte;
pub mod lifter;
pub mod math_util;
pub mod native_abi;
pub mod op_registry;
pub mod opcodes;
pub mod opt;
pub mod semantic_splice;
pub mod unsupported_report;
pub mod virtual_cfg_explosion;

pub(crate) use math_util::*;
use std::collections::HashMap;

pub use desynth::RiscDesynthesizer;
pub use eval::{MemoryPolicy, MemoryRegion, VmFault, VmFaultKind};
pub use flags::VirtualFlags;
pub use flags::{mask_for_width, VFLAG_CF, VFLAG_DF};
pub use high_byte::{
    certify_high_byte_instruction, has_rex_prefix, HighByteCertificationError,
    HighByteInstructionCertification, LegacyHighByte,
};
pub use lifter::RiscLifter;
pub use op_registry::{
    assert_commercial_capabilities, capabilities, CommercialCapability, CommercialCapabilityError,
    RiscOpCapabilities, RiscOpKind,
};
pub use opcodes::{BranchCondition, MicroInstr, MicroOperand, RiscOp};
pub use opt::RiscOptimizer;
pub use semantic_splice::{
    SemanticSplicer, SplicedAluOp, SplicedFlagKind, SplicedMicroOp, SplicedNoiseKind,
};
pub use unsupported_report::{
    UnsupportedInstruction, UnsupportedInstructionReport, UnsupportedReportError, UnsupportedStage,
};
pub use virtual_cfg_explosion::{
    BranchlessVipResolver, OpaqueInvariantKind, OpaquePredicateForest, PhantomBasicBlock,
};

/// RISC ?띠럾????熬곣뫁夷?윜諛몄굡?????쳜??????
#[derive(Debug, Clone)]
pub struct RiscProgram {
    pub instrs: Vec<MicroInstr>,
    /// ??ルㅎ臾?????裕?IP ???筌뤾퍓???嶺? `VirtualBranch`????濚???? x86 IP)??
    /// `instrs` ?뺢껴?㎬땻?????戮곗굚 ?筌뤾퍓????댁Ŧ ?곌떠???臾먰돵 `eval_state`?띠럾? ?釉뚯뫅?깃퀋紐????덈뺄???우벟 ??類ｋ펲.
    /// `None`?????`VirtualBranch.imm`??嶺뚯쉳????筌뤾퍓????댁Ŧ ??怨댄맍??類ｋ펲(??ル쪇援????덈뺄 ?곌랜???.
    ip_map: Option<HashMap<u64, usize>>,
    /// P1 (③): VM→VM 콜 브릿지 서브 VM 레지스트리 — `VmCallBridge.imm` 프로그램
    /// id → 서브 `RiscProgram`. 각 리전(별도 시드/bytecode VM 인스턴스)이 여기
    /// 등록되고, 참조 `eval_state` 는 VmCallBridge 실행 시 호출자 상태를 스냅샷한
    /// 뒤 서브 VM 을 실행·복귀한다.
    sub_vms: HashMap<u64, RiscProgram>,
}

/// `RiscProgram::eval_state` ???덈뺄 ?롪퍒???앹뿉?????사뛾?녿즴???띠럾????誘⑹굣????⑤객臾?
/// ?筌뤿굛??熬곣뱿遊??`PolymorphicInterpreter`)????**嶺뚢뼰維甕?differential) ?롪틵?嶺?*???熬곥굥由?
/// 嶺뚯쉳?????띠럾??繞③뇡?嶺뚣볦굣????⑤객臾????ш껑????? T1-4 ?リ옇?? ??ｌ뫒??
///
/// * `regs`  ??16???띠럾????뺢퀡?????????꾩댉
/// * `temps` ??8?????꾩씩??瑜귣뭵 ?熬곣뫖六???????꾩댉
/// * `flags` ???띠럾???RFLAGS (VFLAG_* ?????
/// * `vsp`   ???띠럾??????꾨Ц ?????(?熬곣뫁?뗥슖??繹먮냱?? ?꾩룆??????關留????덈뒆??
/// * `stack` ???띠럾??????꾨Ц (index 0 = 嶺뚣끉裕? ?낅슣??? 嶺???= 嶺뚣끉裕???낅슣???嶺뚣끉裕??push)
/// * `mem`   ???띠럾???嶺뚮∥???꾨뎨?(?낅슣??????꾩룆???? `MemoryRead`/`MemoryWrite` ????
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiscEvalState {
    pub regs: [u64; 16],
    pub temps: [u64; 8],
    pub flags: u64,
    pub vsp: u64,
    pub stack: Vec<u64>,
    pub mem: HashMap<u64, u8>,
}

impl Default for RiscEvalState {
    fn default() -> Self {
        Self {
            regs: [0; 16],
            temps: [0; 8],
            flags: 0,
            vsp: 0,
            stack: Vec::new(),
            mem: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod bridge_abi_tests;

#[cfg(test)]
mod fault_parity_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// ?熬곣뫗逾??7: ??⑤객臾???됀???嶺뚣볦굣??????リ옇?? ??寃?eval_state ?? ???됰뎄??嶺뚣끉裕뉏펺???⑤객臾??
    /// ???????? ?롪틵?嶺뚯빘鍮쒒뇡??(?β뼯?뉐퐲????댁Ŧ ??됀???븐뼔彛?vreg/flags ??handler(exec_one) ???고뱺??類ㅼ떳
    /// ?곌랜踰???됀???嶺뚮ㅄ維??. ??類ｌ몓 ??類ｊ덧 ??????類ｌ몓 ?熬곣뫁夷?윜諛몄굡?????놁졑??怨쀬Ŧ 嶺뚢뼰維甕??筌먦끉逾?
    #[test]
    fn eval_state_encrypted_matches_plaintext() {
        use rand::rngs::StdRng;
        use rand::{Rng, RngCore, SeedableRng};
        let mut rng = StdRng::seed_from_u64(0x51A7E_5EED);

        for trial in 0..10 {
            let a = rng.next_u64();
            let b = rng.next_u64();
            let mut d = RiscDesynthesizer::new();
            d.emit_add(
                MicroOperand::VReg(0),
                MicroOperand::Imm64(a),
                MicroOperand::Imm64(0),
            );
            d.emit_add(
                MicroOperand::VReg(1),
                MicroOperand::Imm64(b),
                MicroOperand::Imm64(0),
            );
            d.emit_add(
                MicroOperand::VReg(2),
                MicroOperand::VReg(0),
                MicroOperand::VReg(1),
            );
            d.emit_xor(
                MicroOperand::VReg(3),
                MicroOperand::VReg(0),
                MicroOperand::VReg(1),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::ShiftLeft)
                    .with_dst(MicroOperand::VReg(4))
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::VReg(1)),
            );
            d.emit_neg(MicroOperand::VReg(5), MicroOperand::VReg(0));
            d.emit_sub(
                MicroOperand::VReg(6),
                MicroOperand::VReg(0),
                MicroOperand::VReg(1),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::BSwap { width: 8 })
                    .with_dst(MicroOperand::VReg(7))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::PopCount)
                    .with_dst(MicroOperand::VReg(8))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::CountTrailingZeros { width: 8 })
                    .with_dst(MicroOperand::VReg(9))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.emit_sub(
                MicroOperand::Temp(0),
                MicroOperand::VReg(0),
                MicroOperand::VReg(0),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::ConditionalMove {
                    cond: BranchCondition::Zero,
                })
                .with_dst(MicroOperand::VReg(10))
                .with_src1(MicroOperand::VReg(1)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MultiplyLow {
                    signed: false,
                    width: 8,
                })
                .with_dst(MicroOperand::VReg(11))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
            );
            // push/pop (stack) ??branch paths are covered by the existing tests
            d.emit_push(MicroOperand::VReg(2));
            d.emit_pop(MicroOperand::VReg(12));
            d.instrs.push(MicroInstr::new(RiscOp::Halt));

            let prog = RiscProgram::new(d.instrs);
            let regs = [0u64; 16];
            let plain = prog.eval_state(&regs);
            for _ in 0..4 {
                let key = rng.next_u64();
                let enc = prog.eval_state_encrypted(&regs, key);
                assert_eq!(
                    enc.regs, plain.regs,
                    "trial {trial} key 0x{key:X}: regs mismatch"
                );
                assert_eq!(
                    enc.flags, plain.flags,
                    "trial {trial} key 0x{key:X}: flags 0x{:X} != 0x{:X}",
                    enc.flags, plain.flags
                );
                assert_eq!(enc.vsp, plain.vsp, "trial {trial}: vsp mismatch");
                assert_eq!(enc.stack, plain.stack, "trial {trial}: stack mismatch");
            }
        }
    }

    #[test]
    fn test_risc_desynth_not() {
        let mut d = RiscDesynthesizer::new();
        d.emit_not(MicroOperand::VReg(0), MicroOperand::VReg(1));
        let prog = RiscProgram::new(d.instrs);

        let mut regs = [0u64; 16];
        regs[1] = 0x123456789ABCDEF0;
        let out = prog.eval_registers(&regs);
        assert_eq!(out[0], !0x123456789ABCDEF0);
    }

    #[test]
    fn test_risc_desynth_and() {
        let mut d = RiscDesynthesizer::new();
        d.emit_and(
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
            MicroOperand::VReg(2),
        );
        let prog = RiscProgram::new(d.instrs);

        let mut regs = [0u64; 16];
        regs[1] = 0xF0F0F0F0AAAAAAAA;
        regs[2] = 0x0F0FFFFF55555555;
        let out = prog.eval_registers(&regs);
        assert_eq!(out[0], regs[1] & regs[2]);
    }

    #[test]
    fn test_risc_desynth_or() {
        let mut d = RiscDesynthesizer::new();
        d.emit_or(
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
            MicroOperand::VReg(2),
        );
        let prog = RiscProgram::new(d.instrs);

        let mut regs = [0u64; 16];
        regs[1] = 0x12340000A5A50000;
        regs[2] = 0x0000567800005A5A;
        let out = prog.eval_registers(&regs);
        assert_eq!(out[0], regs[1] | regs[2]);
    }

    #[test]
    fn test_risc_desynth_xor() {
        let mut d = RiscDesynthesizer::new();
        d.emit_xor(
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
            MicroOperand::VReg(2),
        );
        let prog = RiscProgram::new(d.instrs);

        let mut regs = [0u64; 16];
        regs[1] = 0xDEADBEEFCAFE0011;
        regs[2] = 0x123456789ABCDEF0;
        let out = prog.eval_registers(&regs);
        assert_eq!(out[0], regs[1] ^ regs[2]);
    }

    #[test]
    fn test_risc_desynth_sub() {
        let mut d = RiscDesynthesizer::new();
        d.emit_sub(
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
            MicroOperand::VReg(2),
        );
        let prog = RiscProgram::new(d.instrs);

        let mut regs = [0u64; 16];
        regs[1] = 1000;
        regs[2] = 300;
        let out = prog.eval_registers(&regs);
        assert_eq!(out[0], 700);
    }

    #[test]
    fn test_risc_eval_state_full_op_coverage() {
        // 嶺뚮ㅄ維獄?嶺뚳퐣瑗?怨⑹쾸???op???브퀗?ч뜮???嶺뚣볦굣????????깅턄??? ?筌먐쇰꼪?????덈뺄??濡ル츎嶺뚯솘? ?롪틵?嶺?
        let mut d = RiscDesynthesizer::new();
        // R0 = 10, R1 = 3
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(10),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(3),
            MicroOperand::Imm64(0),
        );
        // R2 = R0 >> R1 = 1
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftRight)
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
        );
        // R3 = R0 << 1 = 20
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftLeft)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(1)),
        );
        // push R3 (???꾨Ц 1??, pop R4
        d.emit_push(MicroOperand::VReg(3));
        d.emit_pop(MicroOperand::VReg(4));
        // Halt
        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);
        let st = prog.eval_state(&[0u64; 16]);

        assert_eq!(st.regs[2], 1, "shift right");
        assert_eq!(st.regs[3], 20, "shift left");
        assert_eq!(st.regs[4], 20, "pop returns pushed value");
        assert_eq!(st.stack.len(), 0, "push+pop balanced");
        assert_eq!(st.vsp, 0, "vsp balanced");
    }

    #[test]
    fn test_eval_state_memory_read_write() {
        let mut d = RiscDesynthesizer::new();
        // T0 = 0x1000 (addr), R0 = 0x1234 (val), write 8 bytes, read back to R1
        d.emit_add(
            MicroOperand::Temp(0),
            MicroOperand::Imm64(0x1000),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x12345678),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
                .with_src1(MicroOperand::Temp(0))
                .with_src2(MicroOperand::VReg(0)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width: 4 })
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::Temp(0)),
        );
        let prog = RiscProgram::new(d.instrs);
        let st = prog.eval_state(&[0u64; 16]);
        assert_eq!(st.regs[1], 0x12345678, "read back low 4 bytes");
        assert_eq!(st.mem.get(&0x1000), Some(&0x78));
        assert_eq!(st.mem.get(&0x1007), Some(&0x00));
    }

    #[test]
    fn test_eval_state_virtual_branch_taken_and_not() {
        // R0=10, R1=10 -> sub sets ZF. branch{Zero} target 1 (direct index).
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(10),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(10),
            MicroOperand::Imm64(0),
        );
        d.emit_sub(
            MicroOperand::Temp(0),
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
        );
        // index 4 = VirtualBranch{Zero -> 7} ; then Halt at 5 (not reached), Halt at 6
        // Use direct index target 7.
        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Zero,
            })
            .with_imm(7),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // 5
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // 6
        d.emit_add(
            MicroOperand::VReg(7),
            MicroOperand::Imm64(99),
            MicroOperand::Imm64(0),
        ); // 7
        let prog = RiscProgram::new(d.instrs);
        let st = prog.eval_state(&[0u64; 16]);
        assert_eq!(st.regs[7], 99, "branch taken (ZF set)");
    }

    #[test]
    fn test_cvt_f64_int_x86_indefinite() {
        // 32-bit dst: NaN / 筌??/ out-of-range -> 0x8000_0000 (x86 indefinite),
        // NOT Rust's saturating cast (NaN->0, +??>i64::MAX).
        assert_eq!(cvt_f64_int(f64::NAN, 4, true), 0x8000_0000);
        assert_eq!(cvt_f64_int(f64::INFINITY, 4, true), 0x8000_0000);
        assert_eq!(cvt_f64_int(f64::NEG_INFINITY, 4, true), 0x8000_0000);
        assert_eq!(cvt_f64_int(2147483648.0, 4, true), 0x8000_0000); // 2^31
        assert_eq!(cvt_f64_int(-2147483649.0, 4, true), 0x8000_0000);
        assert_eq!(cvt_f64_int(-1.9, 4, true), (-1i32 as u32) as u64); // trunc toward 0
        assert_eq!(cvt_f64_int(1.9, 4, true), 1);
        assert_eq!(cvt_f64_int(2.5, 4, false), 2); // ties-to-even
        assert_eq!(cvt_f64_int(3.5, 4, false), 4); // ties-to-even
                                                   // 64-bit dst: indefinite is 0x8000_0000_0000_0000.
        assert_eq!(cvt_f64_int(f64::NAN, 8, true), 0x8000_0000_0000_0000);
        assert_eq!(
            cvt_f64_int(9_223_372_036_854_775_808.0, 8, true),
            0x8000_0000_0000_0000
        );
        assert_eq!(
            cvt_f64_int(-9_223_372_036_854_775_809.0, 8, true),
            0x8000_0000_0000_0000
        );
        assert_eq!(cvt_f64_int(-1.9, 8, true), (-1i64) as u64);
    }

    /// P1-3 (exception-adjacent): x86 DIV/IDIV divisor-0(#DE)는 evaluator에서
    /// typed guest fault로 관측되며 fault-before-commit을 지킨다.
    #[test]
    fn div_by_zero_is_typed_and_does_not_commit() {
        // RDX:RAX = 0x... : 100, divisor = 0 (reg[5]) → 몫/나머지 0
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(100),
            MicroOperand::Imm64(0),
        ); // RAX = 100
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(0),
            MicroOperand::Imm64(0),
        ); // RDX = 0
        d.instrs.push(
            MicroInstr::new(RiscOp::Divide {
                signed: false,
                width: 8,
            })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::VReg(5)), // divisor = reg[5] = 0
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);

        let regs = [0u64; 16];
        let fault = prog.try_eval_state(&regs).unwrap_err();
        assert_eq!(fault.kind, VmFaultKind::DivideByZero);
        assert_eq!(fault.state.regs[0], 100, "fault must not commit quotient");
        assert_eq!(fault.state.regs[2], 0, "fault must not commit remainder");

        // 기존 poly backend 완화 계약은 별도로 유지한다.
        use crate::vm::poly::{PolymorphicEncoder, PolymorphicInterpreter};
        let seed = 0x12345678u64;
        let mut enc = PolymorphicEncoder::new(seed);
        let bc = enc.encode(&prog).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        assert!(interp.run(&bc).is_err(), "poly backend must surface #DE");
    }

    /// P1-7: x86 DIV/IDIV 몫이 destination 폭을 초과하면 #DE — 참조 eval_state 는
    /// 조용히 잘라 저장하지 않고 typed guest fault를 반환해야 한다.
    #[test]
    fn div_quotient_overflow_is_typed_reference_fault() {
        // 64비트 unsigned DIV: RDX:RAX = 0x1_0000_0000 (2^32), divisor = 1.
        // 몫 = 0x1_0000_0000 > 0xFFFF_FFFF → 32비트 폭엔 안 맞음 → #DE.
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0),
            MicroOperand::Imm64(0),
        ); // RAX = 0
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(1),
            MicroOperand::Imm64(0),
        ); // RDX = 1
        d.instrs.push(
            MicroInstr::new(RiscOp::Divide {
                signed: false,
                width: 4,
            })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::Imm64(1)), // divisor = 1
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        let fault = prog.try_eval_state(&[0u64; 16]).unwrap_err();
        assert_eq!(fault.kind, VmFaultKind::QuotientOverflow);
    }

    // ── P1 (③): VM→VM 콜 브릿지 — 서브 VM 레지스트리 기반 nested-VM 참조 의미론 ──

    /// VmCallBridge 가 (a) 호출자 상태(regs/temps/flags/vsp/stack)를 보존하고,
    /// (b) 서브 VM을 현재 regs/mem 위에서 실행해 RAX 반환값을 가져오며,
    /// (c) 서브 VM이 쓴 메모리를 보존하는지 검증한다.
    #[test]
    fn vm_call_bridge_runs_sub_vm_and_restores_caller() {
        use std::collections::HashMap;
        // 서브 VM (id=7): callee(a, b) → RAX = a + b, mem[0x3000] = a ^ b.
        // 인자는 레지스터로 전달 (RCX=1, RDX=2), 반환은 RAX(vreg 0).
        let mut sub = RiscDesynthesizer::new();
        sub.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
            MicroOperand::VReg(2),
        ); // RAX = RCX + RDX
        sub.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
                .with_src1(MicroOperand::Imm64(0x3000))
                .with_src2(MicroOperand::VReg(0)),
        );
        sub.instrs.push(MicroInstr::new(RiscOp::Halt));
        let sub_prog = RiscProgram::new(sub.instrs);

        // 호출자: R3 = 0x777 (보존 확인), VmCallBridge(id=7), R4 = R0 (반환값 복사).
        let mut caller = RiscDesynthesizer::new();
        caller.emit_add(
            MicroOperand::VReg(3),
            MicroOperand::Imm64(0x777),
            MicroOperand::Imm64(0),
        );
        caller
            .instrs
            .push(MicroInstr::new(RiscOp::VmCallBridge).with_imm(7));
        caller.emit_add(
            MicroOperand::VReg(4),
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0),
        );
        caller.instrs.push(MicroInstr::new(RiscOp::Halt));

        let mut sub_vms = HashMap::new();
        sub_vms.insert(7, sub_prog);
        let prog = RiscProgram::with_sub_vms(caller.instrs, sub_vms);

        // 인자: RCX(vreg1) = 30, RDX(vreg2) = 12 → RAX = 42, mem[0x3000] = 42.
        let mut init = [0u64; 16];
        init[1] = 30;
        init[2] = 12;
        let st = prog.eval_state(&init);

        assert_eq!(st.regs[0], 42, "RAX = callee return value (30+12)");
        assert_eq!(st.regs[4], 42, "caller copied return value after bridge");
        assert_eq!(st.regs[3], 0x777, "caller register preserved across bridge");
        assert_eq!(
            st.mem.get(&0x3000),
            Some(&42),
            "callee memory write propagated"
        );
    }

    /// VmCallBridge 가 호출자의 스택/플래그/temps 를 보존하는지 + 미등록 id 는
    /// no-op 인지 검증한다.
    #[test]
    fn vm_call_bridge_preserves_stack_flags_temps() {
        use std::collections::HashMap;
        // 서브 VM (id=1): RAX = 5 (단순 반환).
        let mut sub = RiscDesynthesizer::new();
        sub.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(5),
            MicroOperand::Imm64(0),
        );
        sub.instrs.push(MicroInstr::new(RiscOp::Halt));
        let sub_prog = RiscProgram::new(sub.instrs);

        // 호출자: push R1 (스택), SetFlag, VmCallBridge(id=1), pop R2.
        // VmCallBridge 사이에 스택/플래그가 보존되어야 한다.
        let mut caller = RiscDesynthesizer::new();
        caller.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(0xCAFE),
            MicroOperand::Imm64(0),
        );
        caller.emit_push(MicroOperand::VReg(1));
        caller
            .instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)));
        caller
            .instrs
            .push(MicroInstr::new(RiscOp::VmCallBridge).with_imm(1));
        caller.emit_pop(MicroOperand::VReg(2));
        caller.instrs.push(MicroInstr::new(RiscOp::Halt));

        let mut sub_vms = HashMap::new();
        sub_vms.insert(1, sub_prog);
        let prog = RiscProgram::with_sub_vms(caller.instrs, sub_vms);

        let st = prog.eval_state(&[0u64; 16]);
        assert_eq!(st.regs[0], 5, "RAX = callee return");
        assert_eq!(
            st.regs[2], 0xCAFE,
            "caller stack (push/pop across bridge) preserved"
        );
        assert_eq!(
            st.flags & 0x8D5,
            0x8C1 & 0x8D5,
            "caller flags preserved across bridge"
        );

        // 미등록 id → no-op (NativeCallBridge 계약): RAX 는 그대로 유지.
        let mut d2 = RiscDesynthesizer::new();
        d2.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(99),
            MicroOperand::Imm64(0),
        );
        d2.instrs
            .push(MicroInstr::new(RiscOp::VmCallBridge).with_imm(0xDEAD));
        d2.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog2 = RiscProgram::new(d2.instrs);
        let st2 = prog2.eval_state(&[0u64; 16]);
        assert_eq!(st2.regs[0], 99, "unregistered VmCallBridge id is a no-op");
    }
}
