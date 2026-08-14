// ==============================================================================
// BTG - Commercial-Grade VM: Super-Operator Fusion Synthesizer
// ==============================================================================
// 빈번하게 연속 실행되는 마이크로 연산 패턴(예: POP + ADD + PUSH, READ + XOR + WRITE)을
// 감지하여 단 하나의 거대한 네이티브 복합 핸들러(Super-Operator)로 융합한다.
// 디스패치 경계를 완전히 지워 분석 도구의 슬라이싱을 무력화한다.
// ==============================================================================

use crate::vm::risc::{MicroInstr, MicroOperand, RiscOp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FusedPattern {
    /// Pop -> AddWithCarry -> Push
    PopAddPush,
    /// MemoryRead -> Nor -> MemoryWrite
    ReadNorWrite,
    /// Pop -> Nor -> Push
    PopNorPush,
}

pub struct SuperOperatorSynthesizer;

impl SuperOperatorSynthesizer {
    /// 마이크로 연산 시퀀스에서 슈퍼 오퍼레이터 패턴 매칭 및 융합
    pub fn find_patterns(instrs: &[MicroInstr]) -> Vec<(usize, FusedPattern)> {
        let mut matches = Vec::new();
        let mut i = 0;
        while i + 2 < instrs.len() {
            let i1 = &instrs[i];
            let i2 = &instrs[i + 1];
            let i3 = &instrs[i + 2];

            // Match Pop -> AddWithCarry -> Push
            if i1.op == RiscOp::VirtualPop
                && i2.op == RiscOp::AddWithCarry
                && i3.op == RiscOp::VirtualPush
            {
                matches.push((i, FusedPattern::PopAddPush));
                i += 3;
                continue;
            }

            // Match Pop -> Nor -> Push
            if i1.op == RiscOp::VirtualPop
                && i2.op == RiscOp::Nor
                && i3.op == RiscOp::VirtualPush
            {
                matches.push((i, FusedPattern::PopNorPush));
                i += 3;
                continue;
            }

            i += 1;
        }

        matches
    }
}
