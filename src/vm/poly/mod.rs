// ==============================================================================
// BTG - Commercial-Grade VM: Phase 2 Polymorphic ISA Module
// ==============================================================================

pub mod decoder;
pub mod encoder;
pub mod interpreter;
pub mod isa_spec;
pub mod rolling_key;

pub use decoder::PolymorphicDecoder;
pub use encoder::PolymorphicEncoder;
pub use interpreter::PolymorphicInterpreter;
pub use isa_spec::VirtualIsaSpec;
pub use rolling_key::RollingKeyEngine;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::risc::{MicroOperand, RiscDesynthesizer, RiscProgram};

    #[test]
    fn test_polymorphic_isa_diversity() {
        let spec1 = VirtualIsaSpec::from_seed(0x1111222233334444);
        let spec2 = VirtualIsaSpec::from_seed(0xAAAABBBBCCCCDDDD);

        // Different seeds must generate different opcode maps and register permutations
        assert_ne!(spec1.register_permutation, spec2.register_permutation);
        assert_ne!(spec1.operand_mask, spec2.operand_mask);
    }

    #[test]
    fn test_polymorphic_encoding_diversity() {
        let mut d = RiscDesynthesizer::new();
        d.emit_xor(
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
            MicroOperand::VReg(2),
        );
        let prog = RiscProgram::new(d.instrs);

        let mut enc1 = PolymorphicEncoder::new(0x123456789);
        let mut enc2 = PolymorphicEncoder::new(0x987654321);

        let bytes1 = enc1.encode(&prog).unwrap();
        let bytes2 = enc2.encode(&prog).unwrap();

        // Exactly the same logic encoded with different seeds must produce completely different byte streams
        assert_ne!(bytes1, bytes2);
        assert_eq!(bytes1.len(), bytes2.len());
    }
}
