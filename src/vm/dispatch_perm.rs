// ==============================================================================
// WS3.3 (t2-hardening-polymorphism follow-ups): dispatcher metadata minimization
// ==============================================================================
// Goal: reduce static recoverability of the opcode→handler identity — no stable
// opcode→handler identifier exposed across builds — while keeping build-to-build
// polymorphism.
//
// This module provides a per-build / per-seed permutation of the opcode→handler
// slot mapping. The bytecode opcode is no longer a direct, stable handler index:
// a `DispatchPermutation` (derived from the same per-build RNG seed that drives
// the poly VM) remaps opcodes onto handler slots, so two builds of the same
// program with different seeds expose different handler identities. The mapping
// is a bijection, so the runtime dispatcher can decode it exactly.
//
// Differential discipline: this is a pure, seed-keyed transform — the tests
// assert (a) bijectivity, (b) round-trip exactness, and (c) build-to-build
// divergence (no stable opcode→handler exposure).
// ==============================================================================

/// Per-build opcode→handler-slot permutation (a bijection over `n` handlers).
#[derive(Debug, Clone)]
pub struct DispatchPermutation {
    n: usize,
    /// slot[i] = the handler slot assigned to opcode i.
    slot: Vec<usize>,
    /// inverse[slot] = the opcode that maps to that slot.
    inverse: Vec<usize>,
}

impl DispatchPermutation {
    /// Build a permutation over `n` handler slots from a seed, using a simple
    /// deterministic Fisher–Yates shuffle over the ordered handler slots.
    pub fn from_seed(seed: u64, n: usize) -> Self {
        assert!(n > 0, "DispatchPermutation requires at least one handler");
        // Deterministic LCG (SplitMix-style) so the permutation is a pure
        // function of (seed, n) — reproducible, per-build, no global state.
        let mut state = seed;
        let mut next = move || {
            state = state.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            (z ^ (z >> 31)) as usize
        };
        // start with identity slot[i] = i
        let mut slot: Vec<usize> = (0..n).collect();
        // Fisher–Yates (backward) using the seed-derived LCG
        for i in (1..n).rev() {
            let j = next() % (i + 1);
            slot.swap(i, j);
        }
        let mut inverse = vec![0usize; n];
        for (op, &s) in slot.iter().enumerate() {
            inverse[s] = op;
        }
        Self { n, slot, inverse }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    /// Map an opcode to its per-build handler slot.
    pub fn slot_for_opcode(&self, opcode: usize) -> usize {
        self.slot[opcode % self.n]
    }

    /// Recover the opcode that owns a handler slot (runtime decode / dispatch).
    pub fn opcode_for_slot(&self, slot: usize) -> usize {
        self.inverse[slot % self.n]
    }

    /// True iff the mapping is a bijection (every slot used exactly once).
    pub fn is_bijection(&self) -> bool {
        let mut seen = vec![false; self.n];
        for &s in &self.slot {
            if s >= self.n || seen[s] {
                return false;
            }
            seen[s] = true;
        }
        seen.iter().all(|&b| b)
    }

    /// Exact round-trip: slot_for_opcode(opcode_for_slot(s)) == s for all slots.
    pub fn round_trips(&self) -> bool {
        (0..self.n).all(|s| self.slot_for_opcode(self.opcode_for_slot(s)) == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_is_a_bijection() {
        for n in [1usize, 2, 4, 8, 16, 64] {
            let p = DispatchPermutation::from_seed(0x1234_5678, n);
            assert!(p.is_bijection(), "n={} must be a bijection", n);
            assert!(p.round_trips(), "n={} must round-trip", n);
        }
    }

    #[test]
    fn dispatch_is_exact_round_trip() {
        let p = DispatchPermutation::from_seed(0xDEAD_BEEF, 16);
        for op in 0..16 {
            let slot = p.slot_for_opcode(op);
            assert_eq!(p.opcode_for_slot(slot), op, "opcode {op} must round-trip");
        }
    }

    /// Two builds with different seeds must expose different handler identities:
    /// no stable opcode→handler mapping across builds.
    #[test]
    fn build_to_build_polymorphism_no_stable_exposure() {
        let a = DispatchPermutation::from_seed(0x1111_1111, 16);
        let b = DispatchPermutation::from_seed(0x2222_2222, 16);
        // At least one opcode must map to a different slot between builds.
        let diverged = (0..16).any(|op| a.slot_for_opcode(op) != b.slot_for_opcode(op));
        assert!(diverged, "different seeds must produce different mappings");
        // And no opcode is identically mapped for the *entire* table (identity
        // table would expose stable opcode==handler, defeating the purpose).
        let not_identity = (0..16).any(|op| a.slot_for_opcode(op) != op);
        assert!(not_identity, "mapping must not be the identity (opcode==handler)");
    }

    /// Same seed → same mapping (determinism / reproducibility).
    #[test]
    fn same_seed_is_deterministic() {
        let a = DispatchPermutation::from_seed(0xCAFE_0000, 32);
        let b = DispatchPermutation::from_seed(0xCAFE_0000, 32);
        for op in 0..32 {
            assert_eq!(a.slot_for_opcode(op), b.slot_for_opcode(op));
        }
    }
}
