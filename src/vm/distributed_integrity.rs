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

pub const SERIALIZED_DESCRIPTOR_SIZE: usize = 40;
pub const SERIALIZED_TABLE_HEADER_SIZE: usize = 8;
pub const SERIALIZED_TABLE_MAGIC: u32 = u32::from_le_bytes(*b"BTGI");

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

    pub(crate) fn domain_key(&self) -> u64 {
        self.domain_key
    }
}

pub fn serialize_table(descriptors: &[IntegrityDescriptor]) -> anyhow::Result<Vec<u8>> {
    let count = u32::try_from(descriptors.len())?;
    let mut out = Vec::with_capacity(
        SERIALIZED_TABLE_HEADER_SIZE + descriptors.len() * SERIALIZED_DESCRIPTOR_SIZE,
    );
    out.extend_from_slice(&SERIALIZED_TABLE_MAGIC.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    for descriptor in descriptors {
        out.push(descriptor.kind as u8);
        out.push(descriptor.policy as u8);
        out.extend_from_slice(&[0u8; 6]);
        out.extend_from_slice(&descriptor.offset.to_le_bytes());
        out.extend_from_slice(&descriptor.len.to_le_bytes());
        out.extend_from_slice(&descriptor.tag.to_le_bytes());
        out.extend_from_slice(&descriptor.domain_key().to_le_bytes());
    }
    Ok(out)
}

/// Seal non-overlapping region slices from the exact image representation that
/// will exist when runtime verification executes.
pub fn seal_region_set(
    image: &[u8],
    regions: &[(ProtectedRegionKind, usize, usize)],
    image_rva: u64,
    build_key: u64,
) -> anyhow::Result<Vec<IntegrityDescriptor>> {
    let mut ordered = regions.to_vec();
    ordered.sort_by_key(|(_, offset, _)| *offset);
    let mut previous_end = 0usize;
    let mut descriptors = Vec::with_capacity(ordered.len());
    for (kind, offset, len) in ordered {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("distributed integrity region overflow"))?;
        if len == 0 || end > image.len() {
            return Err(anyhow::anyhow!(
                "distributed integrity {:?} region {}..{} outside image length {}",
                kind,
                offset,
                end,
                image.len()
            ));
        }
        if !descriptors.is_empty() && offset < previous_end {
            return Err(anyhow::anyhow!(
                "distributed integrity region overlap at {}..{}",
                offset,
                end
            ));
        }
        descriptors.push(IntegrityDescriptor::seal(
            kind,
            image_rva + offset as u64,
            &image[offset..end],
            build_key,
            IntegrityFailurePolicy::FailClosed,
        ));
        previous_end = end;
    }
    Ok(descriptors)
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

    #[test]
    fn production_region_set_rejects_overlap_and_oob() {
        let image = [0x5Au8; 96];
        let valid = seal_region_set(
            &image,
            &[
                (ProtectedRegionKind::HandlerCode, 0, 32),
                (ProtectedRegionKind::HandlerTable, 32, 16),
                (ProtectedRegionKind::VmBytecode, 48, 48),
            ],
            0x7000,
            9,
        )
        .unwrap();
        assert_eq!(valid.len(), 3);
        assert!(seal_region_set(
            &image,
            &[
                (ProtectedRegionKind::HandlerCode, 0, 40),
                (ProtectedRegionKind::HandlerTable, 32, 16),
            ],
            0,
            9,
        )
        .is_err());
        assert!(
            seal_region_set(&image, &[(ProtectedRegionKind::VmBytecode, 80, 32)], 0, 9,).is_err()
        );
    }

    #[test]
    fn serialized_table_has_stable_runtime_abi() {
        let descriptors = seal_region_set(
            &[0xA5; 32],
            &[(ProtectedRegionKind::HandlerCode, 0, 32)],
            0x9000,
            7,
        )
        .unwrap();
        let table = serialize_table(&descriptors).unwrap();
        assert_eq!(
            table.len(),
            SERIALIZED_TABLE_HEADER_SIZE + SERIALIZED_DESCRIPTOR_SIZE
        );
        assert_eq!(
            u32::from_le_bytes(table[0..4].try_into().unwrap()),
            SERIALIZED_TABLE_MAGIC
        );
        assert_eq!(u32::from_le_bytes(table[4..8].try_into().unwrap()), 1);
        assert_eq!(table[8], ProtectedRegionKind::HandlerCode as u8);
        assert_eq!(
            u64::from_le_bytes(table[16..24].try_into().unwrap()),
            0x9000
        );
        assert_eq!(u64::from_le_bytes(table[24..32].try_into().unwrap()), 32);
    }
}
