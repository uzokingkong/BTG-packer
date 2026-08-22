//! BTG-RC1 region-context cipher ABI.
//!
//! RC1 is not a novel cryptographic primitive. It is a domain-separated
//! execution-context construction over the audited RFC 8439 ChaCha20 core.
//! Every independently encrypted region receives a distinct key/nonce derived
//! from its identity and the control-flow/integrity context required to enter it.

use super::chacha20::{chacha_apply, chacha_init_state, CHA_STATE_SIZE};
use chacha20poly1305::{
    aead::{AeadInPlace, Error as AeadError},
    ChaCha20Poly1305, KeyInit, Tag,
};
use sha2::{Digest, Sha256};

pub const REGION_CIPHER_ABI_VERSION: u16 = 1;
pub const REGION_CIPHER_DOMAIN: &[u8] = b"BTG-RC1-region-context-v1";
pub const REGION_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RegionKind {
    NativeText = 1,
    VmBytecode = 2,
    ImportName = 3,
    Metadata = 4,
    DataLifetime = 5,
}

/// Inputs which make a region decryptable only in its intended execution
/// context. `predecessor_token` changes across incoming control-flow edges;
/// `integrity_epoch` is advanced when the owning integrity anchor is renewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegionContext {
    pub region_id: u64,
    pub family_id: u32,
    pub function_id: u64,
    pub predecessor_token: u64,
    pub integrity_epoch: u64,
    pub kind: RegionKind,
}

impl RegionContext {
    pub const SERIALIZED_LEN: usize = 40;

    pub fn encode(self) -> [u8; Self::SERIALIZED_LEN] {
        let mut out = [0u8; Self::SERIALIZED_LEN];
        out[0..2].copy_from_slice(&REGION_CIPHER_ABI_VERSION.to_le_bytes());
        out[2] = self.kind as u8;
        out[3] = 0;
        out[4..12].copy_from_slice(&self.region_id.to_le_bytes());
        out[12..16].copy_from_slice(&self.family_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.function_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.predecessor_token.to_le_bytes());
        out[32..40].copy_from_slice(&self.integrity_epoch.to_le_bytes());
        out
    }
}

/// Derive an independent RFC 8439 key and nonce. The root secret is never used
/// directly as a stream key and no state is shared between regions.
pub fn derive_region_key_nonce(
    root_secret: &[u8; 32],
    context: RegionContext,
) -> ([u8; 32], [u8; 12]) {
    let encoded = context.encode();
    let mut key_hash = Sha256::new();
    key_hash.update(REGION_CIPHER_DOMAIN);
    key_hash.update(b"/key");
    key_hash.update(root_secret);
    key_hash.update(encoded);
    let key: [u8; 32] = key_hash.finalize().into();

    let mut nonce_hash = Sha256::new();
    nonce_hash.update(REGION_CIPHER_DOMAIN);
    nonce_hash.update(b"/nonce");
    nonce_hash.update(root_secret);
    nonce_hash.update(encoded);
    let digest: [u8; 32] = nonce_hash.finalize().into();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    (key, nonce)
}

/// Collapse the 256-byte bootstrap entropy into the RC1 root secret. Keeping
/// this operation explicit prevents legacy consumers from treating the entire
/// seed buffer as a stream-cipher key.
pub fn derive_root_secret(seed: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(REGION_CIPHER_DOMAIN);
    hash.update(b"/root");
    hash.update((seed.len() as u64).to_le_bytes());
    hash.update(seed);
    hash.finalize().into()
}

/// Symmetric in-place region transform used by pack-time encryption and the
/// reference validator. Runtime consumers must implement this exact ABI.
pub fn crypt_region(root_secret: &[u8; 32], context: RegionContext, bytes: &mut [u8]) {
    let (key, nonce) = derive_region_key_nonce(root_secret, context);
    let mut state = [0u8; CHA_STATE_SIZE];
    chacha_init_state(&mut state, &key, &nonce);
    chacha_apply(&mut state, bytes);
    state.fill(0);
}

/// Authenticated at-rest representation. The context is authenticated as AAD,
/// so changing a family/function/edge/epoch is rejected before plaintext is
/// made executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRegion {
    pub ciphertext: Vec<u8>,
    pub tag: [u8; REGION_TAG_LEN],
}

pub fn seal_region(
    root_secret: &[u8; 32],
    context: RegionContext,
    plaintext: &[u8],
) -> SealedRegion {
    let (key, nonce) = derive_region_key_nonce(root_secret, context);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached((&nonce).into(), &context.encode(), &mut ciphertext)
        .expect("fixed-size RC1 key/nonce are valid");
    SealedRegion {
        ciphertext,
        tag: tag.into(),
    }
}

pub fn open_region(
    root_secret: &[u8; 32],
    context: RegionContext,
    sealed: &SealedRegion,
) -> Result<Vec<u8>, AeadError> {
    let (key, nonce) = derive_region_key_nonce(root_secret, context);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let mut plaintext = sealed.ciphertext.clone();
    cipher.decrypt_in_place_detached(
        (&nonce).into(),
        &context.encode(),
        &mut plaintext,
        Tag::from_slice(&sealed.tag),
    )?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(region_id: u64) -> RegionContext {
        RegionContext {
            region_id,
            family_id: 3,
            function_id: 0x1400_1020,
            predecessor_token: 0xA55A_1133_7799_BBDD,
            integrity_epoch: 7,
            kind: RegionKind::NativeText,
        }
    }

    #[test]
    fn region_cipher_roundtrips() {
        let root = [0xA5; 32];
        let mut data = b"one region is never a whole-image plaintext dump".to_vec();
        let plain = data.clone();
        crypt_region(&root, context(11), &mut data);
        assert_ne!(data, plain);
        crypt_region(&root, context(11), &mut data);
        assert_eq!(data, plain);
    }

    #[test]
    fn every_execution_context_is_domain_separated() {
        let root = [0x3C; 32];
        let base = context(9);
        let variants = [
            base,
            RegionContext {
                region_id: 10,
                ..base
            },
            RegionContext {
                family_id: 4,
                ..base
            },
            RegionContext {
                function_id: base.function_id + 1,
                ..base
            },
            RegionContext {
                predecessor_token: base.predecessor_token ^ 1,
                ..base
            },
            RegionContext {
                integrity_epoch: 8,
                ..base
            },
            RegionContext {
                kind: RegionKind::VmBytecode,
                ..base
            },
        ];
        let derived: std::collections::HashSet<_> = variants
            .into_iter()
            .map(|ctx| derive_region_key_nonce(&root, ctx))
            .collect();
        assert_eq!(derived.len(), variants.len());
    }

    #[test]
    fn wrong_predecessor_does_not_recover_plaintext() {
        let root = [0x71; 32];
        let mut encrypted = b"edge-bound region".to_vec();
        let plain = encrypted.clone();
        crypt_region(&root, context(1), &mut encrypted);
        let mut wrong = encrypted.clone();
        crypt_region(
            &root,
            RegionContext {
                predecessor_token: context(1).predecessor_token ^ 0x100,
                ..context(1)
            },
            &mut wrong,
        );
        assert_ne!(wrong, plain);
    }

    #[test]
    fn sealed_region_rejects_ciphertext_tag_and_context_tampering() {
        let root = derive_root_secret(&[0x42; 256]);
        let ctx = context(0x18);
        let sealed = seal_region(&root, ctx, b"authenticated region body");
        assert_eq!(
            open_region(&root, ctx, &sealed).unwrap(),
            b"authenticated region body"
        );

        let mut bad_ciphertext = sealed.clone();
        bad_ciphertext.ciphertext[0] ^= 1;
        assert!(open_region(&root, ctx, &bad_ciphertext).is_err());

        let mut bad_tag = sealed.clone();
        bad_tag.tag[0] ^= 1;
        assert!(open_region(&root, ctx, &bad_tag).is_err());

        assert!(open_region(
            &root,
            RegionContext {
                predecessor_token: ctx.predecessor_token ^ 1,
                ..ctx
            },
            &sealed
        )
        .is_err());
    }
}
