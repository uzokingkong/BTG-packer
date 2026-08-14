// ==============================================================================
// BTG - Commercial-Grade VM: CISC -> RISC De-synthesis Engine
// ==============================================================================
// x86 복합 명령어들을 단 12개의 원시 RISC 마이크로 연산으로 분해(De-synthesis)한다.
// 원본 연산의 구조적 패턴이 완전히 파괴되어 리버스 엔지니어링 도구가 원본 명령어를
// 유추할 수 없도록 만든다.
// ==============================================================================

use super::opcodes::{BranchCondition, MicroInstr, MicroOperand, RiscOp};
use anyhow::Result;

pub struct RiscDesynthesizer {
    pub instrs: Vec<MicroInstr>,
}

impl RiscDesynthesizer {
    pub fn new() -> Self {
        Self {
            instrs: Vec::new(),
        }
    }

    /// NOT(x) -> NOR(x, x)
    pub fn emit_not(&mut self, dst: MicroOperand, src: MicroOperand) {
        self.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(dst)
                .with_src1(src)
                .with_src2(src),
        );
    }

    /// OR(a, b) -> NOT(NOR(a, b))
    /// 1. T0 = NOR(a, b)
    /// 2. dst = NOR(T0, T0)
    pub fn emit_or(&mut self, dst: MicroOperand, a: MicroOperand, b: MicroOperand) {
        let t0 = MicroOperand::Temp(0);
        self.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(t0)
                .with_src1(a)
                .with_src2(b),
        );
        self.emit_not(dst, t0);
    }

    /// AND(a, b) -> NOR(NOT(a), NOT(b))
    /// 1. T0 = NOT(a)  -> NOR(a, a)
    /// 2. T1 = NOT(b)  -> NOR(b, b)
    /// 3. dst = NOR(T0, T1)
    pub fn emit_and(&mut self, dst: MicroOperand, a: MicroOperand, b: MicroOperand) {
        let t0 = MicroOperand::Temp(0);
        let t1 = MicroOperand::Temp(1);
        self.emit_not(t0, a);
        self.emit_not(t1, b);
        self.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(dst)
                .with_src1(t0)
                .with_src2(t1),
        );
    }

    /// XOR(a, b) -> NOR(NOR(a, b), AND(a, b))
    /// 1. T0 = NOR(a, b)
    /// 2. T1 = AND(a, b)
    /// 3. dst = NOR(T0, T1)
    pub fn emit_xor(&mut self, dst: MicroOperand, a: MicroOperand, b: MicroOperand) {
        let t0 = MicroOperand::Temp(0);
        let t1 = MicroOperand::Temp(1);
        // T0 = NOR(a, b)
        self.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(t0)
                .with_src1(a)
                .with_src2(b),
        );
        // T1 = AND(a, b) -> NOR(NOT(a), NOT(b))
        let t2 = MicroOperand::Temp(2);
        self.emit_not(t1, a);
        self.emit_not(t2, b);
        let t1_and = MicroOperand::Temp(1);
        self.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(t1_and)
                .with_src1(t1)
                .with_src2(t2),
        );
        // dst = NOR(T0, T1_and)
        self.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(dst)
                .with_src1(t0)
                .with_src2(t1_and),
        );
    }

    /// SUB(a, b) -> a + NOT(b) + 1
    /// 1. T0 = NOT(b) -> NOR(b, b)
    /// 2. dst = AddWithCarry(a, T0, cin=1)
    pub fn emit_sub(&mut self, dst: MicroOperand, a: MicroOperand, b: MicroOperand) {
        let t0 = MicroOperand::Temp(0);
        self.emit_not(t0, b);
        self.instrs.push(
            MicroInstr::new(RiscOp::AddWithCarry)
                .with_dst(dst)
                .with_src1(a)
                .with_src2(t0)
                .with_imm(1), // Carry in = 1 for two's complement subtraction
        );
    }

    /// ADD(a, b) -> AddWithCarry(a, b, cin=0)
    pub fn emit_add(&mut self, dst: MicroOperand, a: MicroOperand, b: MicroOperand) {
        self.instrs.push(
            MicroInstr::new(RiscOp::AddWithCarry)
                .with_dst(dst)
                .with_src1(a)
                .with_src2(b)
                .with_imm(0),
        );
    }

    /// NEG(a) -> NOT(a) + 1
    pub fn emit_neg(&mut self, dst: MicroOperand, a: MicroOperand) {
        let t0 = MicroOperand::Temp(0);
        self.emit_not(t0, a);
        self.instrs.push(
            MicroInstr::new(RiscOp::AddWithCarry)
                .with_dst(dst)
                .with_src1(MicroOperand::Imm64(0))
                .with_src2(t0)
                .with_imm(1),
        );
    }

    /// PUSH(val)
    pub fn emit_push(&mut self, val: MicroOperand) {
        self.instrs.push(
            MicroInstr::new(RiscOp::VirtualPush).with_src1(val),
        );
    }

    /// POP(dst)
    pub fn emit_pop(&mut self, dst: MicroOperand) {
        self.instrs.push(
            MicroInstr::new(RiscOp::VirtualPop).with_dst(dst),
        );
    }

    /// JMP(target)
    pub fn emit_jmp(&mut self, target_vip: u64) {
        self.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            })
            .with_imm(target_vip),
        );
    }
}
