// ==============================================================================
// BTG crypto abstraction (plan.txt 1~6?④퀎)
//
//
//
// ==============================================================================

pub mod provider;

pub mod key_schedule;
pub mod mac;
pub mod native;
pub mod nonlinear;
pub mod permutation;
pub mod round;
pub mod state;

// T3-1: ChaCha20 (RFC 8439) — reference + boot-stub native crypt blob.
pub mod chacha20;
pub mod chacha20_native;

// T3-1 Phase D: Poly1305 (RFC 8439 §2.5) reference + boot-stub native verify blob.
pub mod poly1305;
pub mod poly1305_native;
pub mod region_cipher;

/// T3-1 Phase B: 부트 스텁/패커가 공유하는 crypto primitive 모드.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMode {
    /// RC4-256 (레거시 — chained/--vm-oep 폴백).
    Rc4,
    /// BTG-C1 커스텀 512-bit 스트림 사이퍼 (v60+, 기본).
    C1,
    /// ChaCha20 (RFC 8439) — T3-1.
    ChaCha20,
}

pub use mac::BtgKeyedMac;
pub use provider::{
    chain_encrypt, chain_encrypt_c1, chain_encrypt_with, BlockCryptoMeta, CryptoError,
    CryptoProvider, RegionCipherProvider,
};
pub use state::{BtgCipher, BtgState};

#[cfg(test)]
mod cipher_tests;

#[cfg(test)]
mod chacha20_tests;

// T3-1 Phase D: Poly1305 AEAD tag (RFC 8439 §2.8) differential tests.
#[cfg(test)]
mod poly1305_aead_tests;
