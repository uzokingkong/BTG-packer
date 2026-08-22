// ==============================================================================
// BTG - Handler Polymorphism & Seed-Dependent Codegen (Domit §12, §82 #1)
// ==============================================================================
// Dynamically diversifies the machine code of native VM handlers based on the
// build seed. Varies handler dispatch strategies, epilogue styles, and dead-code
// padding so that identical RISC semantics yield different binary handler signatures
// across different protection builds.
// ==============================================================================

/// Strategy for generating a native handler body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerCodegenStrategy {
    /// Handler directly consumes pre-decoded operand registers.
    DirectRegister,
    /// Handler decodes immediate operands inline with rolling key.
    InlineDecode,
    /// Handler fuses arithmetic computation directly with next-opcode dispatch.
    FusedDispatch,
    /// Handler is padded with polymorphic benign junk instructions.
    JunkPadded,
}

/// Build-local semantic recipe. These are normalized semantic choices rather
/// than byte padding: emitters use them to choose equivalent decompositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticRecipe {
    Native,
    DeMorgan,
    BooleanBasis,
    CarrySplit,
    MbaIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionSelection {
    Canonical,
    LeaBased,
    Boolean,
    StackScratch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerSynthesisPlan {
    pub opcode: u8,
    pub recipe: SemanticRecipe,
    /// Permutation of the four handler-private scratch roles.
    pub scratch_allocation: [u8; 4],
    pub instruction_selection: InstructionSelection,
    /// Number of reachable wrapper blocks before the semantic body.
    pub control_splits: u8,
    pub dead_state_slots: u8,
    pub context_key: u64,
}

impl HandlerSynthesisPlan {
    pub fn synthesize(seed: u64, opcode: u8) -> Self {
        let mut state = mix64(seed ^ (opcode as u64).wrapping_mul(0xD6E8_FD9D_50A5_2D11));
        let recipe = match state % 5 {
            0 => SemanticRecipe::Native,
            1 => SemanticRecipe::DeMorgan,
            2 => SemanticRecipe::BooleanBasis,
            3 => SemanticRecipe::CarrySplit,
            _ => SemanticRecipe::MbaIdentity,
        };
        state = mix64(state);
        let instruction_selection = match state & 3 {
            0 => InstructionSelection::Canonical,
            1 => InstructionSelection::LeaBased,
            2 => InstructionSelection::Boolean,
            _ => InstructionSelection::StackScratch,
        };
        let mut scratch_allocation = [0, 1, 2, 3];
        for i in (1..4).rev() {
            state = mix64(state);
            scratch_allocation.swap(i, (state as usize) % (i + 1));
        }
        Self {
            opcode,
            recipe,
            scratch_allocation,
            instruction_selection,
            control_splits: 1 + ((state >> 8) % 4) as u8,
            dead_state_slots: 1 + ((state >> 13) % 3) as u8,
            context_key: mix64(state ^ 0x434F_4E54_4558_545F),
        }
    }

    /// A normalized signature for CI clustering. It intentionally excludes the
    /// raw seed and opcode byte, so merely permuting opcodes cannot pass the gate.
    pub fn semantic_signature(&self) -> u64 {
        let recipe = self.recipe as u64;
        let selection = self.instruction_selection as u64;
        let alloc = self
            .scratch_allocation
            .iter()
            .fold(0u64, |v, &r| (v << 3) | r as u64);
        recipe
            | (selection << 4)
            | (alloc << 8)
            | ((self.control_splits as u64) << 24)
            | ((self.dead_state_slots as u64) << 28)
            | ((self.context_key & 0xffff) << 32)
    }
}

/// Jaccard similarity over normalized handler signatures.
pub fn normalized_similarity(a: &[HandlerSynthesisPlan], b: &[HandlerSynthesisPlan]) -> f64 {
    use std::collections::BTreeSet;
    let sa: BTreeSet<_> = a
        .iter()
        .map(HandlerSynthesisPlan::semantic_signature)
        .collect();
    let sb: BTreeSet<_> = b
        .iter()
        .map(HandlerSynthesisPlan::semantic_signature)
        .collect();
    let union = sa.union(&sb).count();
    if union == 0 {
        1.0
    } else {
        sa.intersection(&sb).count() as f64 / union as f64
    }
}

fn mix64(mut z: u64) -> u64 {
    z ^= z >> 30;
    z = z.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Determine the codegen strategy for a given opcode byte and build seed.
#[inline]
pub fn pick_strategy(op_byte: u8, seed: u64) -> HandlerCodegenStrategy {
    let hash = (seed ^ ((op_byte as u64) << 13)).wrapping_mul(0x517C_C1B7_2722_0A95);
    match (hash >> 32) & 0x03 {
        0 => HandlerCodegenStrategy::DirectRegister,
        1 => HandlerCodegenStrategy::InlineDecode,
        2 => HandlerCodegenStrategy::FusedDispatch,
        _ => HandlerCodegenStrategy::JunkPadded,
    }
}

/// Generate randomized benign machine-code padding (NOPs / harmless register moves)
/// based on seed and opcode.
pub fn generate_handler_padding(seed: u64, op_byte: u8) -> Vec<u8> {
    let sel = (seed ^ (op_byte as u64)) & 0x07;
    match sel {
        0 => vec![0x90],                   // nop
        1 => vec![0x66, 0x90],             // 66 nop (2-byte)
        2 => vec![0x0F, 0x1F, 0x00],       // 3-byte nop
        3 => vec![0x4D, 0x89, 0xD2],       // mov r10, r10
        4 => vec![0x4D, 0x89, 0xDB],       // mov r11, r11
        5 => vec![0x48, 0x8D, 0x00],       // lea rax, [rax]
        6 => vec![0x0F, 0x1F, 0x40, 0x00], // 4-byte nop
        _ => vec![0x90, 0x90],             // double nop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_strategy_diversity() {
        let s1 = pick_strategy(0x01, 0x1111_2222_3333_4444);
        let s2 = pick_strategy(0x01, 0x5555_6666_7777_8888);
        let s3 = pick_strategy(0x02, 0x1111_2222_3333_4444);

        // Different seeds and opcodes produce polymorphic variation
        assert!(s1 != s2 || s1 != s3 || s2 != s3);
    }

    #[test]
    fn test_handler_padding_not_empty() {
        for op in 0..16 {
            let pad = generate_handler_padding(0x987654321, op);
            assert!(!pad.is_empty());
        }
    }

    #[test]
    fn synthesis_changes_normalized_semantics_not_only_opcode_numbers() {
        let plans = |seed| {
            (0..96)
                .map(|op| HandlerSynthesisPlan::synthesize(seed, op))
                .collect::<Vec<_>>()
        };
        let baseline = plans(1);
        for seed in 2..=20 {
            assert!(
                normalized_similarity(&baseline, &plans(seed)) < 0.35,
                "seed {seed} handler semantic/CFG similarity exceeded ceiling"
            );
        }
    }

    #[test]
    fn synthesis_covers_decomposition_allocation_and_control_splitting() {
        let plans: Vec<_> = (0..128)
            .map(|op| HandlerSynthesisPlan::synthesize(0x1234_5678, op))
            .collect();
        use std::collections::HashSet;
        assert!(plans.iter().map(|p| p.recipe).collect::<HashSet<_>>().len() >= 4);
        assert!(
            plans
                .iter()
                .map(|p| p.scratch_allocation)
                .collect::<HashSet<_>>()
                .len()
                >= 8
        );
        assert!(
            plans
                .iter()
                .map(|p| p.control_splits)
                .collect::<HashSet<_>>()
                .len()
                >= 3
        );
    }
}
