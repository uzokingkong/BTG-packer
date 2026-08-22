// ==============================================================================
// BTG VM - Context State-Machine Opcode Mapping
// ==============================================================================
// Destroys static 1:1 opcode-to-handler mappings.
// The real operational opcode is a non-linear function of the raw bytecode byte
// AND the dynamic execution history state variable (S_k). Identical raw bytes
// resolve to different handlers across execution paths.
// ==============================================================================

/// Dynamic execution state machine for polymorphic opcode resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateMachineDecoder {
    /// Internal 32-bit execution state variable (S_k).
    state: u32,
    /// Seed-dependent multiplier A.
    mult_a: u32,
    /// Seed-dependent additive constant B.
    add_b: u32,
    /// Total reachable opcode count for modular wrapping.
    num_ops: u8,
}

impl StateMachineDecoder {
    /// Initializes state machine from the build master seed.
    pub fn from_seed(seed: u64, num_ops: u8) -> Self {
        let state = (seed ^ 0x517C_C1B7) as u32 | 1;
        let mult_a = ((seed >> 32) as u32 | 1).wrapping_mul(0x41C6_4E6D);
        let add_b = (seed.rotate_left(13) as u32) | 0x3039;

        Self {
            state,
            mult_a,
            add_b,
            num_ops: if num_ops == 0 { 255 } else { num_ops },
        }
    }

    /// Resolves the real semantic opcode index from a raw stream byte given current state S_k.
    pub fn resolve_real_opcode(&self, raw_byte: u8) -> u8 {
        let mask = (self.state.rotate_right(8) ^ (self.state >> 16)) as u8;
        let unmasked = raw_byte ^ mask;
        unmasked % self.num_ops
    }

    /// Encodes a real semantic opcode into a raw stream byte for current state S_k.
    pub fn encode_raw_opcode(&self, real_opcode: u8) -> u8 {
        let mask = (self.state.rotate_right(8) ^ (self.state >> 16)) as u8;
        real_opcode ^ mask
    }

    /// Advances the state variable S_k to S_{k+1} following an instruction dispatch.
    pub fn advance(&mut self, consumed_raw_byte: u8) {
        self.state = self
            .state
            .wrapping_mul(self.mult_a)
            .wrapping_add(self.add_b)
            ^ (consumed_raw_byte as u32).rotate_left(11);
    }

    /// Returns the current state variable value.
    pub fn current_state(&self) -> u32 {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_machine_dynamic_opcode_evolution() {
        let mut sm = StateMachineDecoder::from_seed(0x1337_C0DE_CAFE_BABE, 32);
        let raw_byte = 0x05;

        // Resolve opcode with same raw byte over consecutive steps
        let op1 = sm.resolve_real_opcode(raw_byte);
        sm.advance(raw_byte);

        let op2 = sm.resolve_real_opcode(raw_byte);
        sm.advance(raw_byte);

        let op3 = sm.resolve_real_opcode(raw_byte);

        // Due to dynamic state evolution, identical raw bytes must not all resolve identically
        assert!(
            op1 != op2 || op2 != op3,
            "State machine must evolve opcode resolution across steps (op1={}, op2={}, op3={})",
            op1,
            op2,
            op3
        );
    }

    #[test]
    fn test_state_machine_encode_decode_roundtrip() {
        let mut encoder_sm = StateMachineDecoder::from_seed(0x9876_5432_10FE_DCBA, 64);
        let mut decoder_sm = StateMachineDecoder::from_seed(0x9876_5432_10FE_DCBA, 64);

        let test_ops = [0u8, 5, 12, 27, 31, 48, 63, 10, 2];

        for &real_op in &test_ops {
            let raw_byte = encoder_sm.encode_raw_opcode(real_op);
            let decoded_real = decoder_sm.resolve_real_opcode(raw_byte);

            assert_eq!(
                decoded_real, real_op,
                "Decoded opcode must match encoded opcode"
            );

            encoder_sm.advance(raw_byte);
            decoder_sm.advance(raw_byte);

            assert_eq!(encoder_sm.current_state(), decoder_sm.current_state());
        }
    }
}
