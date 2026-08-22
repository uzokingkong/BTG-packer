// ==============================================================================
// BTG VM - Virtual CFG Explosion & Arithmetic VIP Resolution
// ==============================================================================
// Destroys linear conditional branch patterns in VM bytecode.
// Transforms control-flow jumps into branchless arithmetic VIP updates
// and inflates the virtual control flow graph with opaque predicate forests.
// ==============================================================================

use iced_x86::{Code, Instruction, Register};

/// Arithmetic branchless VIP resolution engine.
pub struct BranchlessVipResolver;

impl BranchlessVipResolver {
    /// Pure mathematical VIP resolution: VIP_next = VIP_fallthrough + (CondBit * Delta).
    pub fn resolve_vip_pure(vip_fallthrough: u64, delta: i64, cond_taken: bool) -> u64 {
        let cond_bit = if cond_taken { 1u64 } else { 0u64 };
        vip_fallthrough.wrapping_add((delta as u64).wrapping_mul(cond_bit))
    }

    /// Emits branchless x86-64 machine instructions to compute next VIP into `vip_reg`.
    /// `cond_reg` holds the boolean condition (0 or 1), `vip_reg` is updated branchlessly.
    pub fn emit_branchless_vip_update(
        vip_reg: Register,
        cond_reg: Register,
        scratch_reg: Register,
        delta: i64,
    ) -> Vec<Instruction> {
        let mut instrs = Vec::new();

        // 1. mov scratch_reg, delta
        if let Ok(ins) = Instruction::with2(Code::Mov_r64_imm64, scratch_reg, delta as u64) {
            instrs.push(ins);
        }
        // 2. imul scratch_reg, cond_reg (scratch = delta * cond_bit)
        if let Ok(ins) = Instruction::with2(Code::Imul_r64_rm64, scratch_reg, cond_reg) {
            instrs.push(ins);
        }
        // 3. add vip_reg, scratch_reg
        if let Ok(ins) = Instruction::with2(Code::Add_rm64_r64, vip_reg, scratch_reg) {
            instrs.push(ins);
        }

        instrs
    }
}

/// Opaque Predicate Forest: Mathematical invariant generator for phantom CFG nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpaqueInvariantKind {
    /// n * (n + 1) is always even (n * (n + 1) % 2 == 0)
    ParityProduct,
    /// n^2 % 4 is always 0 or 1 (never 2 or 3)
    SquareMod4,
    /// (x | y) - (x ^ y) == (x & y)
    MbaLogicIdentity,
}

/// Phantom / decoy virtual basic block descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhantomBasicBlock {
    pub block_id: u32,
    pub invariant: OpaqueInvariantKind,
    pub phantom_vip: u64,
    pub real_target_vip: u64,
}

pub struct OpaquePredicateForest;

impl OpaquePredicateForest {
    /// Generates a set of phantom basic blocks to inflate CFG complexity.
    pub fn generate_phantom_blocks(
        seed: u64,
        real_block_count: usize,
        inflation_factor: usize,
    ) -> Vec<PhantomBasicBlock> {
        let mut phantoms = Vec::new();
        let total_phantoms = real_block_count * inflation_factor.clamp(1, 10);
        let mut st = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x517C_C1B7;

        for i in 0..total_phantoms {
            st = st
                .wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0x1405_7B7E_F767_814F);
            let invariant = match (st >> 28) % 3 {
                0 => OpaqueInvariantKind::ParityProduct,
                1 => OpaqueInvariantKind::SquareMod4,
                _ => OpaqueInvariantKind::MbaLogicIdentity,
            };

            phantoms.push(PhantomBasicBlock {
                block_id: 0x10000 + (i as u32),
                invariant,
                phantom_vip: (st & 0x00FF_FFFF) | 0x8000_0000,
                real_target_vip: (st.rotate_right(16) & 0x00FF_FFFF) + 0x1000,
            });
        }

        phantoms
    }

    /// Evaluates an opaque invariant condition to prove mathematical truth.
    pub fn evaluate_invariant(kind: OpaqueInvariantKind, n: u64, x: u64, y: u64) -> bool {
        match kind {
            OpaqueInvariantKind::ParityProduct => {
                let prod = n.wrapping_mul(n.wrapping_add(1));
                prod % 2 == 0
            }
            OpaqueInvariantKind::SquareMod4 => {
                let sq_mod = (n.wrapping_mul(n)) % 4;
                sq_mod == 0 || sq_mod == 1
            }
            OpaqueInvariantKind::MbaLogicIdentity => {
                let lhs = (x | y).wrapping_sub(x ^ y);
                let rhs = x & y;
                lhs == rhs
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branchless_vip_resolution_correctness() {
        let base_vip = 0x14000;
        let delta = 0x250i64;

        // When taken: VIP = base + delta
        let taken_vip = BranchlessVipResolver::resolve_vip_pure(base_vip, delta, true);
        assert_eq!(taken_vip, 0x14250);

        // When not taken: VIP = base
        let not_taken_vip = BranchlessVipResolver::resolve_vip_pure(base_vip, delta, false);
        assert_eq!(not_taken_vip, 0x14000);
    }

    #[test]
    fn test_branchless_vip_emission() {
        let instrs = BranchlessVipResolver::emit_branchless_vip_update(
            Register::R12,
            Register::RAX,
            Register::RCX,
            0x180,
        );
        assert_eq!(
            instrs.len(),
            3,
            "Branchless VIP update must emit 3 instructions"
        );
    }

    #[test]
    fn test_opaque_predicates_all_hold_true() {
        for n in [
            0u64,
            1,
            2,
            3,
            4,
            7,
            42,
            1337,
            0xDEADBEEF,
            0xFFFF_FFFF_FFFF_FFFF,
        ] {
            for x in [0u64, 5, 0xAA, 0x5555, 0x12345678] {
                for y in [0u64, 9, 0x55, 0xAAAA, 0x87654321] {
                    assert!(
                        OpaquePredicateForest::evaluate_invariant(
                            OpaqueInvariantKind::ParityProduct,
                            n,
                            x,
                            y
                        ),
                        "ParityProduct invariant failed for n={}",
                        n
                    );
                    assert!(
                        OpaquePredicateForest::evaluate_invariant(
                            OpaqueInvariantKind::SquareMod4,
                            n,
                            x,
                            y
                        ),
                        "SquareMod4 invariant failed for n={}",
                        n
                    );
                    assert!(
                        OpaquePredicateForest::evaluate_invariant(
                            OpaqueInvariantKind::MbaLogicIdentity,
                            n,
                            x,
                            y
                        ),
                        "MbaLogicIdentity invariant failed for x={}, y={}",
                        x,
                        y
                    );
                }
            }
        }
    }

    #[test]
    fn test_phantom_block_generation() {
        let phantoms = OpaquePredicateForest::generate_phantom_blocks(0x1337, 10, 3);
        assert_eq!(phantoms.len(), 30);
    }
}
