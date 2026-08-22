// ==============================================================================
// BTG - Commercial-Grade VM: Phase 3 Direct Threading & Super-Ops Module
// ==============================================================================

pub mod direct_tail;
pub mod harness;
pub mod inline_mba;
pub mod micro_dispatcher;
pub mod native_runner;
pub mod poly_direct;
pub mod reg_permutation;
pub mod runtime_layout;
pub mod super_ops;

pub use direct_tail::DirectTailEmitter;
pub use inline_mba::InlineMbaObfuscator;
pub use micro_dispatcher::{MicroDispatchStrategy, MicroDispatcher};
pub use native_runner::DirectThreadedNativeRunner;
pub use poly_direct::run_native_poly_direct;
pub use reg_permutation::{ContextOffsetScrambler, RegisterAssignment, VmRole};
pub use runtime_layout::VmRuntimeLayout;
pub use super_ops::{
    AssignedSuperOp, FusedPattern, PreparedSuperOpProgram, SuperOpBuildMetadata, SuperOpCandidate,
    SuperOpIndexMap, SuperOpOccurrence, SuperOpPlan, SuperOpRewrite, SuperOpStreamInstr,
    SuperOperatorSynthesizer,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscOp};
    use iced_x86::{Code, Instruction, Register};

    #[test]
    fn test_direct_tail_assembly() {
        let mut instrs = Vec::new();
        // Add a dummy handler instruction: xor r10, r11
        instrs.push(Instruction::with2(Code::Xor_r64_rm64, Register::R10, Register::R11).unwrap());
        // Append tail dispatch
        DirectTailEmitter::emit_tail_dispatch(&mut instrs).unwrap();

        let bytes = DirectTailEmitter::assemble(instrs, 0x140001000).unwrap();
        assert!(!bytes.is_empty());
        // Should contain tail jmp rax (0xFF, 0xE0) at the end
        assert_eq!(&bytes[bytes.len() - 2..], &[0xFF, 0xE0]);
    }

    #[test]
    fn test_super_operator_fusion_detection() {
        let instrs = vec![
            MicroInstr::new(RiscOp::VirtualPop).with_dst(MicroOperand::VReg(0)),
            MicroInstr::new(RiscOp::AddWithCarry)
                .with_dst(MicroOperand::VReg(0))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
            MicroInstr::new(RiscOp::VirtualPush).with_src1(MicroOperand::VReg(0)),
        ];

        let matches = SuperOperatorSynthesizer::find_patterns(&instrs);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], (0, FusedPattern::PopAddPush));
    }
}
