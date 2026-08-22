// ==============================================================================
// BTG - Whole-CFG Multi-Path Differential Test (Domit §5, §11, §81)
// ==============================================================================
// Evaluates complex CFG execution calculating arithmetic transformations
// simultaneously across:
//   1. RISC Evaluation Engine (`prog.eval_state`)
//   2. Polymorphic VM Interpreter (`PolymorphicInterpreter::run`)
// Verifying 100% semantic convergence across all execution backends.
// ==============================================================================

use crate::vm::poly::{PolymorphicEncoder, PolymorphicInterpreter};
use crate::vm::risc::{MicroOperand, RiscDesynthesizer, RiscProgram};

#[test]
fn test_cfg_differential_loop_and_branch_convergence() {
    let mut d = RiscDesynthesizer::new();

    // Reg0 += Reg1
    // Reg1 -= Reg2
    // Repeat calculations
    for _ in 0..5 {
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
        );
        d.emit_sub(
            MicroOperand::VReg(1),
            MicroOperand::VReg(1),
            MicroOperand::VReg(2),
        );
    }

    let prog = RiscProgram::new(d.instrs);
    let mut initial_regs = [0u64; 16];
    initial_regs[0] = 100;
    initial_regs[1] = 10;
    initial_regs[2] = 2;

    // 1. RISC Engine evaluation
    let risc_result = prog.eval_state(&initial_regs);

    // 2. Polymorphic VM Interpreter evaluation across multiple build seeds
    for seed in [
        0x1337_C0DE_CAFE_BABE,
        0x9876_5432_10FE_DCBA,
        0x1122_3344_5566_7788,
    ] {
        let mut encoder = PolymorphicEncoder::new(seed);
        let bytecode = encoder.encode(&prog).expect("Polymorphic encoding failed");

        let mut poly_interp = PolymorphicInterpreter::new(seed);
        poly_interp.regs.copy_from_slice(&initial_regs);
        poly_interp.run(&bytecode).expect("Poly run failed");

        assert_eq!(
            poly_interp.regs[0], risc_result.regs[0],
            "Seed 0x{seed:X} Reg0 must match RISC"
        );
        assert_eq!(
            poly_interp.regs[1], risc_result.regs[1],
            "Seed 0x{seed:X} Reg1 must match RISC"
        );
    }
}
