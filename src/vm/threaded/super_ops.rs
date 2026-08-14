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

    /// 융합된 Super-Operator 네이티브 x86-64 핸들러 생성
    pub fn emit_fused_handler(pattern: &FusedPattern, target_va: u64) -> anyhow::Result<Vec<u8>> {
        use iced_x86::{Code, Instruction, Register, MemoryOperand};
        use super::direct_tail::DirectTailEmitter;

        let mut instrs = Vec::new();

        match pattern {
            FusedPattern::PopAddPush => {
                // Pop R10 from virtual stack (RSP), Pop R11, Add R10, R11, Push R10
                // pop r10
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R10).map_err(|e| anyhow::anyhow!("{e}"))?);
                // pop r11
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R11).map_err(|e| anyhow::anyhow!("{e}"))?);
                // add r10, r11
                instrs.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow::anyhow!("{e}"))?);
                // push r10
                instrs.push(Instruction::with1(Code::Push_r64, Register::R10).map_err(|e| anyhow::anyhow!("{e}"))?);
            }
            FusedPattern::PopNorPush => {
                // pop r10
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R10).map_err(|e| anyhow::anyhow!("{e}"))?);
                // pop r11
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R11).map_err(|e| anyhow::anyhow!("{e}"))?);
                // or r10, r11
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow::anyhow!("{e}"))?);
                // not r10
                instrs.push(Instruction::with1(Code::Not_rm64, Register::R10).map_err(|e| anyhow::anyhow!("{e}"))?);
                // push r10
                instrs.push(Instruction::with1(Code::Push_r64, Register::R10).map_err(|e| anyhow::anyhow!("{e}"))?);
            }
            FusedPattern::ReadNorWrite => {
                // Read from [R10], NOR with R11, Write to [R10]
                let mem_op = MemoryOperand::with_base(Register::R10);
                // mov rax, [r10]
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, mem_op).map_err(|e| anyhow::anyhow!("{e}"))?);
                // or rax, r11
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::R11).map_err(|e| anyhow::anyhow!("{e}"))?);
                // not rax
                instrs.push(Instruction::with1(Code::Not_rm64, Register::RAX).map_err(|e| anyhow::anyhow!("{e}"))?);
                // mov [r10], rax
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem_op, Register::RAX).map_err(|e| anyhow::anyhow!("{e}"))?);
            }
        }

        // Direct tail-call epilogue
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fused_handler_emission() {
        let pop_add_push = SuperOperatorSynthesizer::emit_fused_handler(&FusedPattern::PopAddPush, 0x140001000).unwrap();
        let pop_nor_push = SuperOperatorSynthesizer::emit_fused_handler(&FusedPattern::PopNorPush, 0x140001050).unwrap();
        let read_nor_write = SuperOperatorSynthesizer::emit_fused_handler(&FusedPattern::ReadNorWrite, 0x1400010A0).unwrap();

        assert!(!pop_add_push.is_empty());
        assert!(!pop_nor_push.is_empty());
        assert!(!read_nor_write.is_empty());
    }
}

