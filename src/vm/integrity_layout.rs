//! Build-local physical layout for distributed-integrity descriptors.
//!
//! The runtime only needs the nonce and the physical record sequence.  Logical
//! region order deliberately does not survive serialization.

use crate::vm::seed_lifecycle::derive_seed;

pub const HEADER_SIZE: usize = 16;
pub const RECORD_SIZE: usize = 40;
pub const HEADER_GUARD_DOMAIN: u32 = 0x6D31_A7C5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityLayoutPlan {
    pub nonce: u64,
    pub order: Vec<usize>,
}

impl IntegrityLayoutPlan {
    pub fn derive(record_domains: &[u64]) -> Self {
        let mut nonce = derive_seed(
            record_domains.len() as u64 ^ 0xD17A_9E5C_42B8_6103,
            record_domains
                .iter()
                .enumerate()
                .fold(0u64, |acc, (i, value)| {
                    derive_seed(acc ^ value.rotate_left((i as u32) & 63), i as u64)
                }),
        );
        if nonce == 0 {
            nonce = 0xA36F_19C8_5B72_E40D;
        }

        let mut order: Vec<usize> = (0..record_domains.len()).collect();
        let mut state = nonce;
        for i in (1..order.len()).rev() {
            state = next_record_mask(state);
            order.swap(i, (state as usize) % (i + 1));
        }
        Self { nonce, order }
    }

    pub fn encoded_count(&self) -> u32 {
        self.order.len() as u32 ^ self.nonce as u32
    }

    pub fn header_guard(&self) -> u32 {
        (self.encoded_count() ^ (self.nonce >> 32) as u32 ^ HEADER_GUARD_DOMAIN).rotate_left(11)
    }
}

/// Must remain in lockstep with the native boot verifier.
pub const fn next_record_mask(mask: u64) -> u64 {
    mask.rotate_left(13).wrapping_mul(0x1E35_A7BD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_reproducible_and_domain_sensitive() {
        let a = IntegrityLayoutPlan::derive(&[1, 2, 3, 4, 5, 6]);
        let b = IntegrityLayoutPlan::derive(&[1, 2, 3, 4, 5, 6]);
        let c = IntegrityLayoutPlan::derive(&[1, 2, 3, 4, 5, 7]);
        assert_eq!(a, b);
        assert_ne!(a.nonce, c.nonce);
        assert_ne!(a.order, c.order);
        assert_ne!(a.nonce, 0);
    }

    #[test]
    fn order_is_a_permutation() {
        let plan = IntegrityLayoutPlan::derive(&[11, 22, 33, 44, 55]);
        let mut order = plan.order.clone();
        order.sort_unstable();
        assert_eq!(order, vec![0, 1, 2, 3, 4]);
    }
}
