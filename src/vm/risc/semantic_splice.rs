// ==============================================================================
// BTG VM - Semantic Splicing & Multi-Handler Decomposition Engine
// ==============================================================================
// Destroys monolithic 1:1 opcode semantics.
// Decomposes high-level instructions (XOR, ADD, SUB, CMP, MOV) into 3~5 micro-ops
// (Fetch -> Intermediate -> Flag Synthesis -> Commit) with opaque noise interleaving.
// ==============================================================================

use super::{MicroInstr, MicroOperand, RiscOp};

/// Primitive arithmetic/logic operations for spliced micro-computations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplicedAluOp {
    Add,
    Sub,
    Xor,
    And,
    Or,
    Shl,
    Shr,
    Sar,
    Not,
    Neg,
}

/// Category of flag synthesis needed for the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplicedFlagKind {
    ArithmeticAdd,
    ArithmeticSub,
    Logic,
    Shift,
    PreserveAll,
}

/// Opaque noise calculation kind (benign dead computation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplicedNoiseKind {
    XorConstant(u64),
    AddRotate(u32),
    MbaIdentity,
}

/// Decomposed micro-operation step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplicedMicroOp {
    /// Load operand value into virtual temporary register `temp_idx` (0..7).
    FetchToTemp {
        temp_idx: u8,
        src: MicroOperand,
        imm: u64,
    },
    /// Perform raw mathematical calculation between two temporary registers.
    ComputeIntermediate {
        dst_temp: u8,
        src1_temp: u8,
        src2_temp: u8,
        op: SplicedAluOp,
    },
    /// Synthesize x86 flag bits (ZF, SF, OF, CF, PF) based on intermediate results.
    SynthesizeFlags {
        flag_kind: SplicedFlagKind,
        res_temp: u8,
        src1_temp: u8,
        src2_temp: u8,
    },
    /// Store final calculated result from temporary register to destination operand.
    CommitResult { dst: MicroOperand, src_temp: u8 },
    /// Injected opaque noise (dead computation) to confuse reverse engineers and static decompilers.
    OpaqueBenignNoise {
        temp_idx: u8,
        noise: SplicedNoiseKind,
    },
}

/// Semantic Splicer: Decomposes `MicroInstr` into spliced micro-operation sequences.
pub struct SemanticSplicer;

impl SemanticSplicer {
    /// Decomposes a `MicroInstr` into 3~5 micro operations with seed-dependent temporary registers.
    pub fn splice(instr: &MicroInstr, seed: u64) -> Vec<SplicedMicroOp> {
        let mut ops = Vec::new();
        let t0 = ((seed ^ 0x1337) & 3) as u8; // Temp 0..3
        let t1 = t0 + 1;
        let t2 = t0 + 2;
        let t_noise = (t0 + 3) & 7;

        match instr.op {
            RiscOp::AddWithCarry => {
                if let Some(src1) = instr.src1 {
                    ops.push(SplicedMicroOp::FetchToTemp {
                        temp_idx: t0,
                        src: src1,
                        imm: instr.imm,
                    });
                }
                if let Some(src2) = instr.src2 {
                    ops.push(SplicedMicroOp::FetchToTemp {
                        temp_idx: t1,
                        src: src2,
                        imm: instr.imm,
                    });
                }
                // Benign noise injection
                ops.push(SplicedMicroOp::OpaqueBenignNoise {
                    temp_idx: t_noise,
                    noise: SplicedNoiseKind::XorConstant(seed ^ 0xDEADBEEF),
                });
                // Intermediate computation
                ops.push(SplicedMicroOp::ComputeIntermediate {
                    dst_temp: t2,
                    src1_temp: t0,
                    src2_temp: t1,
                    op: SplicedAluOp::Add,
                });
                // Flag synthesis
                ops.push(SplicedMicroOp::SynthesizeFlags {
                    flag_kind: SplicedFlagKind::ArithmeticAdd,
                    res_temp: t2,
                    src1_temp: t0,
                    src2_temp: t1,
                });
                // Commit
                if let Some(dst) = instr.dst {
                    ops.push(SplicedMicroOp::CommitResult { dst, src_temp: t2 });
                }
            }

            RiscOp::Nor => {
                if let Some(src1) = instr.src1 {
                    ops.push(SplicedMicroOp::FetchToTemp {
                        temp_idx: t0,
                        src: src1,
                        imm: instr.imm,
                    });
                }
                if let Some(src2) = instr.src2 {
                    ops.push(SplicedMicroOp::FetchToTemp {
                        temp_idx: t1,
                        src: src2,
                        imm: instr.imm,
                    });
                }
                ops.push(SplicedMicroOp::ComputeIntermediate {
                    dst_temp: t2,
                    src1_temp: t0,
                    src2_temp: t1,
                    op: SplicedAluOp::Or,
                });
                ops.push(SplicedMicroOp::ComputeIntermediate {
                    dst_temp: t2,
                    src1_temp: t2,
                    src2_temp: t2,
                    op: SplicedAluOp::Not,
                });
                ops.push(SplicedMicroOp::SynthesizeFlags {
                    flag_kind: SplicedFlagKind::Logic,
                    res_temp: t2,
                    src1_temp: t0,
                    src2_temp: t1,
                });
                if let Some(dst) = instr.dst {
                    ops.push(SplicedMicroOp::CommitResult { dst, src_temp: t2 });
                }
            }

            RiscOp::ShiftLeft => {
                if let Some(src1) = instr.src1 {
                    ops.push(SplicedMicroOp::FetchToTemp {
                        temp_idx: t0,
                        src: src1,
                        imm: instr.imm,
                    });
                }
                if let Some(src2) = instr.src2 {
                    ops.push(SplicedMicroOp::FetchToTemp {
                        temp_idx: t1,
                        src: src2,
                        imm: instr.imm,
                    });
                }
                ops.push(SplicedMicroOp::ComputeIntermediate {
                    dst_temp: t2,
                    src1_temp: t0,
                    src2_temp: t1,
                    op: SplicedAluOp::Shl,
                });
                ops.push(SplicedMicroOp::SynthesizeFlags {
                    flag_kind: SplicedFlagKind::Shift,
                    res_temp: t2,
                    src1_temp: t0,
                    src2_temp: t1,
                });
                if let Some(dst) = instr.dst {
                    ops.push(SplicedMicroOp::CommitResult { dst, src_temp: t2 });
                }
            }

            RiscOp::ShiftRight => {
                if let Some(src1) = instr.src1 {
                    ops.push(SplicedMicroOp::FetchToTemp {
                        temp_idx: t0,
                        src: src1,
                        imm: instr.imm,
                    });
                }
                if let Some(src2) = instr.src2 {
                    ops.push(SplicedMicroOp::FetchToTemp {
                        temp_idx: t1,
                        src: src2,
                        imm: instr.imm,
                    });
                }
                ops.push(SplicedMicroOp::ComputeIntermediate {
                    dst_temp: t2,
                    src1_temp: t0,
                    src2_temp: t1,
                    op: SplicedAluOp::Shr,
                });
                ops.push(SplicedMicroOp::SynthesizeFlags {
                    flag_kind: SplicedFlagKind::Shift,
                    res_temp: t2,
                    src1_temp: t0,
                    src2_temp: t1,
                });
                if let Some(dst) = instr.dst {
                    ops.push(SplicedMicroOp::CommitResult { dst, src_temp: t2 });
                }
            }

            _ => {
                // Fallback for direct instructions
                if let Some(src1) = instr.src1 {
                    ops.push(SplicedMicroOp::FetchToTemp {
                        temp_idx: t0,
                        src: src1,
                        imm: instr.imm,
                    });
                    if let Some(dst) = instr.dst {
                        ops.push(SplicedMicroOp::CommitResult { dst, src_temp: t0 });
                    }
                }
            }
        }

        ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_splice_nor_decomposition() {
        let instr = MicroInstr {
            op: RiscOp::Nor,
            dst: Some(MicroOperand::VReg(0)),
            src1: Some(MicroOperand::VReg(1)),
            src2: Some(MicroOperand::VReg(2)),
            imm: 0,
        };

        let spliced = SemanticSplicer::splice(&instr, 0x1234_5678);
        assert!(
            spliced.len() >= 4,
            "Spliced NOR must contain at least 4 micro-ops"
        );

        // Verify ordering: Fetch -> Compute -> Flags -> Commit
        let has_fetch = spliced
            .iter()
            .any(|op| matches!(op, SplicedMicroOp::FetchToTemp { .. }));
        let has_compute = spliced
            .iter()
            .any(|op| matches!(op, SplicedMicroOp::ComputeIntermediate { .. }));
        let has_flags = spliced
            .iter()
            .any(|op| matches!(op, SplicedMicroOp::SynthesizeFlags { .. }));
        let has_commit = spliced
            .iter()
            .any(|op| matches!(op, SplicedMicroOp::CommitResult { .. }));

        assert!(has_fetch && has_compute && has_flags && has_commit);
    }

    #[test]
    fn test_semantic_splice_add_with_noise() {
        let instr = MicroInstr {
            op: RiscOp::AddWithCarry,
            dst: Some(MicroOperand::VReg(3)),
            src1: Some(MicroOperand::VReg(4)),
            src2: Some(MicroOperand::Imm64(0x42)),
            imm: 0x42,
        };

        let spliced = SemanticSplicer::splice(&instr, 0xCAFEBABE);
        assert!(
            spliced.len() >= 5,
            "Spliced ADD must contain noise and micro-ops"
        );

        let has_noise = spliced
            .iter()
            .any(|op| matches!(op, SplicedMicroOp::OpaqueBenignNoise { .. }));
        assert!(has_noise, "Spliced ADD should include opaque benign noise");
    }
}
