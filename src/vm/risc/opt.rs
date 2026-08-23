// ==============================================================================
// BTG - Commercial-Grade VM: RISC Micro-Op Optimizer
// ==============================================================================
// De-synthesis 과정에서 생성된 마이크로 연산 스트림의 불필요한 중복을 제거하고
// 난독화 효과를 극대화하는 최적화 패스.
// ==============================================================================

use super::opcodes::{MicroInstr, MicroOperand, RiscOp};

pub struct RiscOptimizer;

impl RiscOptimizer {
    /// 이중 부정 및 중복 연산 최적화
    pub fn optimize(instrs: &[MicroInstr]) -> Vec<MicroInstr> {
        let mut out = Vec::with_capacity(instrs.len());
        let mut i = 0;
        while i < instrs.len() {
            // Pattern: T0 = NOR(A, A) followed by dst = NOR(T0, T0) -> dst = A (이중 NOT 제거)
            if i + 1 < instrs.len() {
                let ins1 = &instrs[i];
                let ins2 = &instrs[i + 1];
                if ins1.op == RiscOp::Nor
                    && ins2.op == RiscOp::Nor
                    && ins1.src1 == ins1.src2
                    && ins2.src1 == ins2.src2
                    && ins1.dst == ins2.src1
                {
                    // If ins1.dst is a Temp, we can bypass to a simple move or direct wire
                    if let (Some(dst), Some(src)) = (ins2.dst, ins1.src1) {
                        out.push(
                            MicroInstr::new(RiscOp::AddWithCarry)
                                .with_dst(dst)
                                .with_src1(src)
                                .with_src2(MicroOperand::Imm64(0))
                                .with_imm(0),
                        );
                        i += 2;
                        continue;
                    }
                }
            }

            out.push(instrs[i].clone());
            i += 1;
        }
        out
    }
}
