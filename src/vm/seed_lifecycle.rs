// ==============================================================================
// BTG - VM Seed Lifecycle & Domain Key Derivation (Domit §22, §82)
// ==============================================================================
// Conceals VM seeds from static PE analysis. Rather than embedding the plaintext
// rolling-key seed directly in PE descriptors, each region records a per-region
// `RegionSalt` (random nonce), and the runtime derives the operational seed
// `PolySeed` from `VmDomainKey ^ RegionSalt` via a non-linear mixing function.
// ==============================================================================

/// 64-bit master domain key for the VM instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmDomainKey(pub u64);

/// Per-region randomized salt (embedded in the binary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionSalt(pub u64);

impl VmDomainKey {
    #[inline]
    pub const fn new(key: u64) -> Self {
        Self(key)
    }

    #[inline]
    pub fn derive_region_seed(&self, salt: RegionSalt) -> u64 {
        derive_seed(self.0, salt.0)
    }
}

impl RegionSalt {
    #[inline]
    pub const fn new(salt: u64) -> Self {
        Self(salt)
    }
}

/// Robust non-linear seed derivation function.
/// Produces a uniform 64-bit rolling-key initial seed from the master domain key
/// and the region salt.
pub fn derive_seed(domain_key: u64, region_salt: u64) -> u64 {
    let mut h = domain_key ^ region_salt.rotate_left(17);
    h = h.wrapping_mul(0x517C_C1B7_2722_0A95);
    h ^= h >> 31;
    h = h.wrapping_mul(0x4A55_816D_97C6_D67B);
    h ^= h >> 27;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_seed_deterministic_and_dispersed() {
        let k = VmDomainKey::new(0x1234_5678_9ABC_DEF0);
        let s1 = RegionSalt::new(0x1);
        let s2 = RegionSalt::new(0x2);

        let seed1 = k.derive_region_seed(s1);
        let seed2 = k.derive_region_seed(s2);

        assert_ne!(seed1, seed2);
        assert_eq!(seed1, k.derive_region_seed(s1)); // deterministic
        assert_ne!(seed1, 0);
    }
}
