//! Program-VM bytecode chunk planning and domain-separated key derivation.
//!
//! Chunks end only at encoded instruction boundaries. The runtime counterpart
//! can therefore decrypt one complete instruction window without exposing an
//! adjacent chunk or handling a cross-chunk operand fetch.

use crate::vm::seed_lifecycle::derive_seed;

pub const DEFAULT_CHUNK_BYTES: usize = 4096;
const MODULE_DOMAIN: u64 = 0x4254_472D_5056_4D37; // "BTG-PVM7"
const CHUNK_DOMAIN: u64 = 0x4348_554E_4B2D_4B31; // "CHUNK-K1"

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChunkLookupTopology {
    ForwardEnds,
    ReverseStarts,
    BinaryEnds,
}

impl ChunkLookupTopology {
    pub fn from_seed(build_seed: u64) -> Self {
        match derive_seed(build_seed, 0x5032_2D39_2D54_4F50) % 3 {
            0 => Self::ForwardEnds,
            1 => Self::ReverseStarts,
            _ => Self::BinaryEnds,
        }
    }

    pub const fn normalized_signature(self) -> u64 {
        match self {
            Self::ForwardEnds => 0x4657_442D_454E_4453,
            Self::ReverseStarts => 0x5245_562D_5354_4152,
            Self::BinaryEnds => 0x4249_4E2D_454E_4453,
        }
    }
}

pub fn module_key(build_seed: u64) -> u64 {
    derive_seed(build_seed, MODULE_DOMAIN)
}

pub fn chunk_key_from_module(module_key: u64, chunk_index: u64) -> u64 {
    derive_seed(module_key, CHUNK_DOMAIN ^ chunk_index)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytecodeChunk {
    pub offset: u32,
    pub len: u32,
    pub key: u64,
}

pub fn plan_chunks(
    bytecode_len: usize,
    instruction_offsets: &[usize],
    build_seed: u64,
    max_chunk_bytes: usize,
) -> Vec<BytecodeChunk> {
    if bytecode_len == 0 {
        return Vec::new();
    }
    let max_chunk_bytes = max_chunk_bytes.max(1);
    let mut boundaries: Vec<usize> = instruction_offsets
        .iter()
        .copied()
        .filter(|offset| *offset <= bytecode_len)
        .collect();
    boundaries.extend([0, bytecode_len]);
    boundaries.sort_unstable();
    boundaries.dedup();

    let module_key = module_key(build_seed);
    let mut chunks = Vec::new();
    let mut start = 0usize;
    while start < bytecode_len {
        let limit = start.saturating_add(max_chunk_bytes).min(bytecode_len);
        let end = boundaries
            .iter()
            .copied()
            .take_while(|boundary| *boundary <= limit)
            .filter(|boundary| *boundary > start)
            .last()
            .unwrap_or_else(|| {
                boundaries
                    .iter()
                    .copied()
                    .find(|boundary| *boundary > start)
                    .unwrap_or(bytecode_len)
            });
        let index = chunks.len() as u64;
        chunks.push(BytecodeChunk {
            offset: start as u32,
            len: (end - start) as u32,
            key: chunk_key_from_module(module_key, index),
        });
        start = end;
    }
    chunks
}

/// Symmetric prototype stream used by pack-time tests and the forthcoming
/// native dispatcher emitter. Key material is passed by value and never stored
/// in the bytecode buffer.
pub fn byte_mask(key: u64, local_offset: u64) -> u8 {
    let mut state = key ^ local_offset.wrapping_mul(0x9E37_79B1_85EB_CA87);
    state ^= state >> 33;
    state = state.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    state ^= state >> 29;
    (state >> 56) as u8
}

pub fn crypt_chunk(bytes: &mut [u8], key: u64) {
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte ^= byte_mask(key, offset as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_are_instruction_aligned_gapless_and_domain_separated() {
        let offsets: Vec<usize> = (0..10_000).step_by(7).collect();
        let chunks = plan_chunks(10_000, &offsets, 0x1234, 4096);
        assert_eq!(chunks.first().unwrap().offset, 0);
        assert_eq!(
            chunks.last().unwrap().offset + chunks.last().unwrap().len,
            10_000
        );
        for pair in chunks.windows(2) {
            assert_eq!(pair[0].offset + pair[0].len, pair[1].offset);
            assert_ne!(pair[0].key, pair[1].key);
        }
        assert!(chunks
            .iter()
            .all(|chunk| { chunk.offset == 0 || offsets.contains(&(chunk.offset as usize)) }));
    }

    #[test]
    fn one_chunk_roundtrip_does_not_expose_neighbors() {
        let mut bytes: Vec<u8> = (0..96).collect();
        let original = bytes.clone();
        let chunks = plan_chunks(bytes.len(), &[0, 32, 64], 7, 32);
        for chunk in &chunks {
            let range = chunk.offset as usize..(chunk.offset + chunk.len) as usize;
            crypt_chunk(&mut bytes[range], chunk.key);
        }
        assert_ne!(bytes, original);
        let middle = &chunks[1];
        let range = middle.offset as usize..(middle.offset + middle.len) as usize;
        crypt_chunk(&mut bytes[range.clone()], middle.key);
        assert_eq!(&bytes[range], &original[32..64]);
        assert_ne!(&bytes[..32], &original[..32]);
        assert_ne!(&bytes[64..], &original[64..]);
    }

    #[test]
    fn chunk_keys_are_derived_from_one_module_secret() {
        let seed = 0x1234_5678_9ABC_DEF0;
        let module = module_key(seed);
        let chunks = plan_chunks(96, &[0, 32, 64], seed, 32);
        for (index, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.key, chunk_key_from_module(module, index as u64));
        }
    }

    #[test]
    fn n20_lookup_topology_does_not_collapse_to_one_template() {
        use std::collections::BTreeMap;

        let mut counts = BTreeMap::new();
        for seed in 1..=20 {
            *counts
                .entry(ChunkLookupTopology::from_seed(seed).normalized_signature())
                .or_insert(0usize) += 1;
        }
        assert_eq!(
            counts.len(),
            3,
            "N=20 did not exercise all lookup topologies"
        );
        assert!(
            counts.values().copied().max().unwrap_or_default() < 10,
            "one normalized lookup template dominates N=20: {counts:?}"
        );
    }
}
