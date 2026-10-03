//! VM key hierarchy based on HKDF-SHA-256 with explicit domain separation.

use sha2::{Digest, Sha256};

const HKDF_SALT: &[u8] = b"BTG/VM/HKDF-SHA256/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmKeyDomain {
    Rolling,
    IsaLayout,
    HandlerTable,
    BranchTarget,
    BranchOffset,
    FamilyState,
    BytecodeEpoch,
    CrossFamilyChild,
}

impl VmKeyDomain {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Rolling => b"rolling-key",
            Self::IsaLayout => b"isa-layout",
            Self::HandlerTable => b"handler-table",
            Self::BranchTarget => b"branch-target-map",
            Self::BranchOffset => b"branch-offset-map",
            Self::FamilyState => b"family-state",
            Self::BytecodeEpoch => b"bytecode-key-epoch",
            Self::CrossFamilyChild => b"cross-family-child",
        }
    }
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        inner_pad[i] ^= normalized[i];
        outer_pad[i] ^= normalized[i];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

/// HKDF-Extract(master) followed by one HKDF-Expand block.
pub fn derive_bytes(master: u64, domain: VmKeyDomain, context: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(HKDF_SALT, &master.to_le_bytes());
    let mut info = Vec::with_capacity(20 + domain.label().len() + context.len());
    info.extend_from_slice(b"BTG/VM/v1/");
    info.extend_from_slice(domain.label());
    info.push(0);
    info.extend_from_slice(context);
    info.push(1); // HKDF expand block counter
    hmac_sha256(&prk, &info)
}

pub fn derive_u64(master: u64, domain: VmKeyDomain, context: &[u8]) -> u64 {
    let output = derive_bytes(master, domain, context);
    u64::from_le_bytes(output[..8].try_into().expect("fixed HKDF output"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_case_one() {
        let expected = [0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
            0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7];
        assert_eq!(hmac_sha256(&[0x0b;20], b"Hi There"), expected);
    }

    #[test]
    fn domains_and_contexts_are_independent() {
        let seed = 0x1122_3344_5566_7788;
        assert_ne!(
            derive_u64(seed, VmKeyDomain::Rolling, b""),
            derive_u64(seed, VmKeyDomain::IsaLayout, b"")
        );
        assert_ne!(
            derive_u64(seed, VmKeyDomain::BytecodeEpoch, &0u64.to_le_bytes()),
            derive_u64(seed, VmKeyDomain::BytecodeEpoch, &1u64.to_le_bytes())
        );
    }

    #[test]
    fn rolling_key_is_not_the_old_invertible_formula() {
        let seed: u64 = 0x8899_aabb_ccdd_eeff;
        let old = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x517C_C1B7_2722_0A95;
        assert_ne!(derive_u64(seed, VmKeyDomain::Rolling, b"stream-0"), old);
    }
}
