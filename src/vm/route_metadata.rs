//! Stable byte representation of a materialized VM route table.
//!
//! The format is deliberately fixed-width and canonical so generated code can
//! consume it without Rust layout assumptions. Decoding is bounded and rejects
//! alternate encodings, unsorted/duplicate keys, and payload corruption.

use crate::analysis::program_model::FunctionId;
use crate::vm::poly::VmArchitectureFamily;
use crate::vm::route_table::{
    EntryVip, FunctionRoute, GatewayKind, MaterializedRouteTable, OriginalTargetRva,
};
use std::collections::{BTreeMap, BTreeSet};

const MAGIC: &[u8; 8] = b"VMROUTE\0";
const VERSION: u16 = 1;
pub const ROUTE_METADATA_HEADER_SIZE: usize = 24;
pub const ROUTE_METADATA_RECORD_SIZE: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteMetadataDescriptor {
    pub version: u16,
    pub record_count: u32,
    pub records_offset: u32,
    pub record_size: u16,
    pub byte_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMetadata {
    pub descriptor: RouteMetadataDescriptor,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteMetadataError {
    RouteLimitExceeded {
        count: usize,
        limit: usize,
    },
    ByteLimitExceeded {
        count: usize,
        limit: usize,
    },
    CountOverflow,
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidLayout,
    ChecksumMismatch,
    InvalidFamily(u8),
    InvalidGateway(u8),
    NonZeroReserved,
    NonCanonicalOrder,
    MetadataSectionNotReadable,
    MetadataSectionExecutable,
    MetadataSectionWritable,
    MissingOriginalTarget(OriginalTargetRva),
    UnexpectedOriginalTarget(OriginalTargetRva),
    MissingGeneratedDestination(OriginalTargetRva),
    DuplicateGeneratedDestination(OriginalTargetRva),
    GeneratedDestinationNotExecutable {
        original: OriginalTargetRva,
        destination_rva: u32,
    },
}

/// Final-image facts required to validate a placed route image.  Keeping this
/// independent of the PE builder makes it usable both immediately after
/// placement and by post-build validators that re-parse the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RvaSpan {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratedRouteDestination {
    pub original: OriginalTargetRva,
    pub destination_rva: u32,
}

pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Validate the serialized bytes and the structural facts that serialization
/// alone cannot prove: RO/NX placement, complete original-target coverage, and
/// generated executable destinations for every route.
pub fn validate_placed_route_metadata(
    bytes: &[u8],
    section_characteristics: u32,
    required_original_targets: &[OriginalTargetRva],
    generated_destinations: &[GeneratedRouteDestination],
    generated_executable_ranges: &[RvaSpan],
    max_routes: usize,
    max_bytes: usize,
) -> Result<MaterializedRouteTable, RouteMetadataError> {
    if section_characteristics & IMAGE_SCN_MEM_READ == 0 {
        return Err(RouteMetadataError::MetadataSectionNotReadable);
    }
    if section_characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
        return Err(RouteMetadataError::MetadataSectionExecutable);
    }
    if section_characteristics & IMAGE_SCN_MEM_WRITE != 0 {
        return Err(RouteMetadataError::MetadataSectionWritable);
    }

    let table = MaterializedRouteTable::from_metadata(bytes, max_routes, max_bytes)?;
    let required: BTreeSet<_> = required_original_targets.iter().copied().collect();
    for &(original, _) in table.entries() {
        if !required.contains(&original) {
            return Err(RouteMetadataError::UnexpectedOriginalTarget(original));
        }
    }
    for &original in &required {
        if table.lookup(original).is_err() {
            return Err(RouteMetadataError::MissingOriginalTarget(original));
        }
    }

    let mut destinations = BTreeMap::new();
    for destination in generated_destinations {
        if destinations
            .insert(destination.original, destination.destination_rva)
            .is_some()
        {
            return Err(RouteMetadataError::DuplicateGeneratedDestination(
                destination.original,
            ));
        }
    }
    for &(original, _) in table.entries() {
        let destination_rva = *destinations
            .get(&original)
            .ok_or(RouteMetadataError::MissingGeneratedDestination(original))?;
        let executable = generated_executable_ranges.iter().any(|range| {
            range.start < range.end && destination_rva >= range.start && destination_rva < range.end
        });
        if !executable {
            return Err(RouteMetadataError::GeneratedDestinationNotExecutable {
                original,
                destination_rva,
            });
        }
    }
    Ok(table)
}

impl std::fmt::Display for RouteMetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VM route metadata rejected: {self:?}")
    }
}

impl std::error::Error for RouteMetadataError {}

impl MaterializedRouteTable {
    pub fn to_metadata(&self) -> Result<RouteMetadata, RouteMetadataError> {
        let count = u32::try_from(self.len()).map_err(|_| RouteMetadataError::CountOverflow)?;
        let byte_len = ROUTE_METADATA_HEADER_SIZE
            .checked_add(
                self.len()
                    .checked_mul(ROUTE_METADATA_RECORD_SIZE)
                    .ok_or(RouteMetadataError::CountOverflow)?,
            )
            .ok_or(RouteMetadataError::CountOverflow)?;
        let byte_len_u32 =
            u32::try_from(byte_len).map_err(|_| RouteMetadataError::CountOverflow)?;
        let mut bytes = vec![0u8; ROUTE_METADATA_HEADER_SIZE];
        for (rva, route) in self.entries() {
            bytes.extend_from_slice(&rva.0.to_le_bytes());
            bytes.extend_from_slice(&route.function_id.0.to_le_bytes());
            bytes.push(route.family as u8);
            bytes.push(match route.gateway {
                GatewayKind::VmEntry => 0,
                GatewayKind::CrossFamily => 1,
                GatewayKind::NativeEntry => 2,
            });
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&route.entry_vip.0.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(ROUTE_METADATA_HEADER_SIZE as u16).to_le_bytes());
        bytes[12..14].copy_from_slice(&(ROUTE_METADATA_RECORD_SIZE as u16).to_le_bytes());
        bytes[16..20].copy_from_slice(&count.to_le_bytes());
        let checksum = crc32(&bytes[ROUTE_METADATA_HEADER_SIZE..]);
        bytes[20..24].copy_from_slice(&checksum.to_le_bytes());
        Ok(RouteMetadata {
            descriptor: RouteMetadataDescriptor {
                version: VERSION,
                record_count: count,
                records_offset: ROUTE_METADATA_HEADER_SIZE as u32,
                record_size: ROUTE_METADATA_RECORD_SIZE as u16,
                byte_len: byte_len_u32,
            },
            bytes,
        })
    }

    pub fn from_metadata(
        bytes: &[u8],
        max_routes: usize,
        max_bytes: usize,
    ) -> Result<Self, RouteMetadataError> {
        if bytes.len() > max_bytes {
            return Err(RouteMetadataError::ByteLimitExceeded {
                count: bytes.len(),
                limit: max_bytes,
            });
        }
        if bytes.len() < ROUTE_METADATA_HEADER_SIZE {
            return Err(RouteMetadataError::Truncated);
        }
        if &bytes[0..8] != MAGIC {
            return Err(RouteMetadataError::InvalidMagic);
        }
        let version = le_u16(bytes, 8);
        if version != VERSION {
            return Err(RouteMetadataError::UnsupportedVersion(version));
        }
        if le_u16(bytes, 10) as usize != ROUTE_METADATA_HEADER_SIZE
            || le_u16(bytes, 12) as usize != ROUTE_METADATA_RECORD_SIZE
            || le_u16(bytes, 14) != 0
        {
            return Err(RouteMetadataError::InvalidLayout);
        }
        let count = le_u32(bytes, 16) as usize;
        if count > max_routes {
            return Err(RouteMetadataError::RouteLimitExceeded {
                count,
                limit: max_routes,
            });
        }
        let expected = ROUTE_METADATA_HEADER_SIZE
            .checked_add(
                count
                    .checked_mul(ROUTE_METADATA_RECORD_SIZE)
                    .ok_or(RouteMetadataError::CountOverflow)?,
            )
            .ok_or(RouteMetadataError::CountOverflow)?;
        if bytes.len() != expected {
            return Err(RouteMetadataError::InvalidLayout);
        }
        if crc32(&bytes[ROUTE_METADATA_HEADER_SIZE..]) != le_u32(bytes, 20) {
            return Err(RouteMetadataError::ChecksumMismatch);
        }
        let mut entries = Vec::with_capacity(count);
        let mut previous = None;
        for record in bytes[ROUTE_METADATA_HEADER_SIZE..].chunks_exact(ROUTE_METADATA_RECORD_SIZE) {
            let rva = OriginalTargetRva(le_u32(record, 0));
            if previous.is_some_and(|old| old >= rva) {
                return Err(RouteMetadataError::NonCanonicalOrder);
            }
            previous = Some(rva);
            let family = match record[8] {
                0 => VmArchitectureFamily::Stack,
                1 => VmArchitectureFamily::Register,
                2 => VmArchitectureFamily::MixedRisc,
                3 => VmArchitectureFamily::FusedCisc,
                value => return Err(RouteMetadataError::InvalidFamily(value)),
            };
            let gateway = match record[9] {
                0 => GatewayKind::VmEntry,
                1 => GatewayKind::CrossFamily,
                2 => GatewayKind::NativeEntry,
                value => return Err(RouteMetadataError::InvalidGateway(value)),
            };
            if le_u16(record, 10) != 0 || le_u32(record, 20) != 0 {
                return Err(RouteMetadataError::NonZeroReserved);
            }
            entries.push((
                rva,
                FunctionRoute {
                    function_id: FunctionId(le_u32(record, 4)),
                    family,
                    entry_vip: EntryVip(le_u64(record, 12)),
                    gateway,
                },
            ));
        }
        Ok(Self::from_sorted_entries(entries))
    }
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn le_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> MaterializedRouteTable {
        MaterializedRouteTable::from_sorted_entries(vec![
            (
                OriginalTargetRva(0x1000),
                FunctionRoute {
                    function_id: FunctionId(7),
                    family: VmArchitectureFamily::MixedRisc,
                    entry_vip: EntryVip(23),
                    gateway: GatewayKind::CrossFamily,
                },
            ),
            (
                OriginalTargetRva(0x1080),
                FunctionRoute {
                    function_id: FunctionId(7),
                    family: VmArchitectureFamily::MixedRisc,
                    entry_vip: EntryVip(23),
                    gateway: GatewayKind::CrossFamily,
                },
            ),
        ])
    }

    #[test]
    fn deterministic_roundtrip_and_descriptor() {
        let encoded = table().to_metadata().unwrap();
        assert_eq!(encoded, table().to_metadata().unwrap());
        assert_eq!(encoded.descriptor.record_count, 2);
        assert_eq!(encoded.descriptor.byte_len as usize, encoded.bytes.len());
        assert_eq!(
            MaterializedRouteTable::from_metadata(&encoded.bytes, 2, encoded.bytes.len()).unwrap(),
            table()
        );
    }

    #[test]
    fn rejects_tampering_and_bounds() {
        let mut encoded = table().to_metadata().unwrap().bytes;
        encoded[ROUTE_METADATA_HEADER_SIZE + 12] ^= 1;
        assert_eq!(
            MaterializedRouteTable::from_metadata(&encoded, 2, encoded.len()).unwrap_err(),
            RouteMetadataError::ChecksumMismatch
        );
        let clean = table().to_metadata().unwrap().bytes;
        assert!(matches!(
            MaterializedRouteTable::from_metadata(&clean, 1, clean.len()),
            Err(RouteMetadataError::RouteLimitExceeded { .. })
        ));
        assert!(matches!(
            MaterializedRouteTable::from_metadata(&clean, 2, clean.len() - 1),
            Err(RouteMetadataError::ByteLimitExceeded { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_records_even_with_valid_checksum() {
        let mut encoded = table().to_metadata().unwrap().bytes;
        let first_rva =
            encoded[ROUTE_METADATA_HEADER_SIZE..ROUTE_METADATA_HEADER_SIZE + 4].to_vec();
        encoded[ROUTE_METADATA_HEADER_SIZE + ROUTE_METADATA_RECORD_SIZE
            ..ROUTE_METADATA_HEADER_SIZE + ROUTE_METADATA_RECORD_SIZE + 4]
            .copy_from_slice(&first_rva);
        let checksum = crc32(&encoded[ROUTE_METADATA_HEADER_SIZE..]);
        encoded[20..24].copy_from_slice(&checksum.to_le_bytes());
        assert_eq!(
            MaterializedRouteTable::from_metadata(&encoded, 2, encoded.len()).unwrap_err(),
            RouteMetadataError::NonCanonicalOrder
        );
    }

    #[test]
    fn placed_metadata_requires_ro_nx_and_complete_executable_destinations() {
        let encoded = table().to_metadata().unwrap().bytes;
        let required = [OriginalTargetRva(0x1000), OriginalTargetRva(0x1080)];
        let destinations = [
            GeneratedRouteDestination {
                original: required[0],
                destination_rva: 0x5000,
            },
            GeneratedRouteDestination {
                original: required[1],
                destination_rva: 0x5010,
            },
        ];
        let ranges = [RvaSpan {
            start: 0x5000,
            end: 0x5100,
        }];
        let validated = validate_placed_route_metadata(
            &encoded,
            IMAGE_SCN_MEM_READ,
            &required,
            &destinations,
            &ranges,
            2,
            encoded.len(),
        )
        .unwrap();
        assert_eq!(validated, table());

        assert_eq!(
            validate_placed_route_metadata(
                &encoded,
                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
                &required,
                &destinations,
                &ranges,
                2,
                encoded.len(),
            )
            .unwrap_err(),
            RouteMetadataError::MetadataSectionExecutable
        );
        assert_eq!(
            validate_placed_route_metadata(
                &encoded,
                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
                &required,
                &destinations,
                &ranges,
                2,
                encoded.len(),
            )
            .unwrap_err(),
            RouteMetadataError::MetadataSectionWritable
        );
    }

    #[test]
    fn placed_metadata_rejects_incomplete_mapping_and_non_exec_destination() {
        let encoded = table().to_metadata().unwrap().bytes;
        let both = [OriginalTargetRva(0x1000), OriginalTargetRva(0x1080)];
        let one_destination = [GeneratedRouteDestination {
            original: both[0],
            destination_rva: 0x5000,
        }];
        assert_eq!(
            validate_placed_route_metadata(
                &encoded,
                IMAGE_SCN_MEM_READ,
                &both,
                &one_destination,
                &[RvaSpan {
                    start: 0x5000,
                    end: 0x5100
                }],
                2,
                encoded.len(),
            )
            .unwrap_err(),
            RouteMetadataError::MissingGeneratedDestination(both[1])
        );

        let destinations = [
            one_destination[0],
            GeneratedRouteDestination {
                original: both[1],
                destination_rva: 0x6000,
            },
        ];
        assert!(matches!(
            validate_placed_route_metadata(
                &encoded,
                IMAGE_SCN_MEM_READ,
                &both,
                &destinations,
                &[RvaSpan {
                    start: 0x5000,
                    end: 0x5100
                }],
                2,
                encoded.len(),
            ),
            Err(RouteMetadataError::GeneratedDestinationNotExecutable {
                original: OriginalTargetRva(0x1080),
                destination_rva: 0x6000
            })
        ));

        assert_eq!(
            validate_placed_route_metadata(
                &encoded,
                IMAGE_SCN_MEM_READ,
                &[both[0]],
                &destinations,
                &[RvaSpan {
                    start: 0x5000,
                    end: 0x6100
                }],
                2,
                encoded.len(),
            )
            .unwrap_err(),
            RouteMetadataError::UnexpectedOriginalTarget(both[1])
        );
    }
}
