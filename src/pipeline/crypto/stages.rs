//! Boot cipher ABI v64. Domain-separated ChaCha20 PRF keys, per-record
//! nonces and verify-before-decrypt tags. Embedded bootstrap material remains
//! recoverable; these properties do not establish an external trust root.
use crate::crypto::{chacha20, poly1305};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum Stage {
    Payload,
    Data,
    NativeText,
    Bytecode,
    Metadata,
    Resolver,
}
pub(crate) const STAGES: [Stage; 6] = [
    Stage::Payload,
    Stage::Data,
    Stage::NativeText,
    Stage::Bytecode,
    Stage::Metadata,
    Stage::Resolver,
];
pub(crate) const MATERIAL_STRIDE: usize = 64;
pub(crate) const MATERIAL_SIZE: usize = MATERIAL_STRIDE * STAGES.len();
pub(crate) const ENTRY_SIZE: usize = 32;
impl Stage {
    pub(crate) fn domain(self) -> u32 {
        0x4254_4700 | (self as u32 + 1)
    }
    pub(crate) fn offset(self) -> usize {
        self as usize * MATERIAL_STRIDE
    }
}

pub(crate) fn material(seed: &[u8], stage: Stage) -> [u8; 64] {
    let (key, mut nonce) = super::cipher::derive_chacha_key_nonce_raw(seed);
    let domain = stage.domain().to_le_bytes();
    for i in 0..4 {
        nonce[i] ^= domain[i];
    }
    chacha20::chacha20_block(&key, 0, &nonce)
}
pub(crate) fn key_nonce(seed: &[u8], stage: Stage, record: u64) -> ([u8; 32], [u8; 12]) {
    let block = material(seed, stage);
    let key = block[..32].try_into().unwrap();
    let mut nonce: [u8; 12] = block[32..44].try_into().unwrap();
    for (byte, index) in nonce.iter_mut().zip(record.to_le_bytes()) {
        *byte ^= index;
    }
    (key, nonce)
}
pub(crate) fn authenticate(seed: &[u8], stage: Stage, record: u64, bytes: &[u8]) -> [u8; 16] {
    let (key, nonce) = key_nonce(seed, stage, record);
    let poly =
        poly1305::chacha_poly1305_key_from_block0(&chacha20::chacha20_block(&key, 0, &nonce));
    poly1305::poly1305_aead_tag(&poly1305::POLY1305_AEAD_AAD, bytes, &poly)
}
pub(crate) fn seal(seed: &[u8], stage: Stage, record: u64, bytes: &mut [u8]) -> [u8; 16] {
    let (key, nonce) = key_nonce(seed, stage, record);
    let mut state = [0; chacha20::CHA_STATE_SIZE];
    chacha20::chacha_init_state(&mut state, &key, &nonce);
    state[chacha20::CHA_OFF_CTR..chacha20::CHA_OFF_CTR + 8].copy_from_slice(&1u64.to_le_bytes());
    chacha20::chacha_apply(&mut state, bytes);
    authenticate(seed, stage, record, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{
        aead::{Aead, Payload},
        ChaCha20Poly1305, KeyInit,
    };
    #[test]
    fn stages_records_and_reference_aead_agree() {
        let seed = [0x93; 256];
        let mut identities = std::collections::HashSet::new();
        for stage in STAGES {
            for index in [0, 1, 3600, u64::MAX] {
                let (key, nonce) = key_nonce(&seed, stage, index);
                assert!(identities.insert((key, nonce)));
                for size in [0, 1, 15, 16, 17, 63, 64, 65, 257] {
                    let plain = vec![0x53; size];
                    let mut cipher = plain.clone();
                    let tag = seal(&seed, stage, index, &mut cipher);
                    let reference = ChaCha20Poly1305::new((&key).into())
                        .encrypt(
                            (&nonce).into(),
                            Payload {
                                msg: &plain,
                                aad: &poly1305::POLY1305_AEAD_AAD,
                            },
                        )
                        .unwrap();
                    assert_eq!(cipher, reference[..size]);
                    assert_eq!(tag, reference[size..]);
                    assert_ne!(
                        tag,
                        authenticate(&seed, stage, index.wrapping_add(1), &cipher)
                    );
                }
            }
        }
    }
}
