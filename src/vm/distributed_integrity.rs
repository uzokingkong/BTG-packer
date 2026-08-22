//! Keyed, per-region integrity checks used beyond the boot-time monolithic CRC.

use crate::vm::seed_lifecycle::derive_seed;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectedRegionKind {
    FileImage,
    MappedImage,
    VmBytecode,
    HandlerCode,
    HandlerTable,
    NativeBridge,
    ResolvedApiPointers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityFailurePolicy {
    FailClosed,
    DelayedPoison,
    Telemetry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityDescriptor {
    pub kind: ProtectedRegionKind,
    pub offset: u64,
    pub len: u64,
    pub tag: u64,
    pub policy: IntegrityFailurePolicy,
    domain_key: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityOutcome {
    Valid,
    FailClosed,
    Poison(u64),
    Telemetry(ProtectedRegionKind),
}

impl IntegrityDescriptor {
    pub fn seal(
        kind: ProtectedRegionKind,
        offset: u64,
        bytes: &[u8],
        build_key: u64,
        policy: IntegrityFailurePolicy,
    ) -> Self {
        let domain_key = derive_seed(
            build_key,
            0x494E_5445_4752_0000 ^ kind as u64 ^ offset.rotate_left(17),
        );
        Self {
            kind,
            offset,
            len: bytes.len() as u64,
            tag: keyed_tag(bytes, domain_key),
            policy,
            domain_key,
        }
    }

    pub fn verify(&self, bytes: &[u8]) -> IntegrityOutcome {
        let valid = bytes.len() as u64 == self.len
            && constant_time_eq(self.tag, keyed_tag(bytes, self.domain_key));
        if valid {
            return IntegrityOutcome::Valid;
        }
        match self.policy {
            IntegrityFailurePolicy::FailClosed => IntegrityOutcome::FailClosed,
            IntegrityFailurePolicy::DelayedPoison => {
                IntegrityOutcome::Poison(derive_seed(self.domain_key, self.tag))
            }
            IntegrityFailurePolicy::Telemetry => IntegrityOutcome::Telemetry(self.kind),
        }
    }
}

fn keyed_tag(bytes: &[u8], key: u64) -> u64 {
    crate::crypto::mac::BtgKeyedMac::mac(&key.to_le_bytes(), bytes)
}

fn constant_time_eq(a: u64, b: u64) -> bool {
    let mut x = a ^ b;
    x |= x >> 32;
    x |= x >> 16;
    x |= x >> 8;
    x |= x >> 4;
    x |= x >> 2;
    x |= x >> 1;
    x & 1 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_protected_region_detects_each_single_bit_mutation_without_false_positive() {
        let kinds = [
            ProtectedRegionKind::FileImage,
            ProtectedRegionKind::MappedImage,
            ProtectedRegionKind::VmBytecode,
            ProtectedRegionKind::HandlerCode,
            ProtectedRegionKind::HandlerTable,
            ProtectedRegionKind::NativeBridge,
            ProtectedRegionKind::ResolvedApiPointers,
        ];
        let original: Vec<u8> = (0..64).map(|i| (i * 37) as u8).collect();
        for kind in kinds {
            let d = IntegrityDescriptor::seal(
                kind,
                0x1000,
                &original,
                0x1234,
                IntegrityFailurePolicy::FailClosed,
            );
            assert_eq!(d.verify(&original), IntegrityOutcome::Valid);
            for bit in 0..original.len() * 8 {
                let mut changed = original.clone();
                changed[bit / 8] ^= 1 << (bit % 8);
                assert_eq!(
                    d.verify(&changed),
                    IntegrityOutcome::FailClosed,
                    "{kind:?} bit {bit}"
                );
            }
        }
    }

    #[test]
    fn failure_policy_is_not_a_fixed_trap() {
        let bytes = b"handler";
        for (policy, expected) in [
            (IntegrityFailurePolicy::FailClosed, 0),
            (IntegrityFailurePolicy::DelayedPoison, 1),
            (IntegrityFailurePolicy::Telemetry, 2),
        ] {
            let d =
                IntegrityDescriptor::seal(ProtectedRegionKind::HandlerCode, 0, bytes, 7, policy);
            let outcome = d.verify(b"xandler");
            assert_eq!(
                match outcome {
                    IntegrityOutcome::FailClosed => 0,
                    IntegrityOutcome::Poison(_) => 1,
                    IntegrityOutcome::Telemetry(_) => 2,
                    IntegrityOutcome::Valid => 3,
                },
                expected
            );
        }
    }
}
