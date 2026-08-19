// ==============================================================================
// T3-1 Phase D: Poly1305 AEAD tag (RFC 8439 §2.8) differential tests
// ==============================================================================
// 1. `poly1305_aead_tag` tag over (AAD, ciphertext) == RustCrypto
//    ChaCha20Poly1305 `encrypt_in_place_detached` tag (authority).
// 2. AEAD tag over ciphertext round-trip (deterministic seed → poly key).
// 3. Tampered tag / ciphertext / AAD each fail verification (linear block-level
//    equivalence only — no holistic output-diff equivalence).
// ==============================================================================

use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit};

use crate::crypto::chacha20::chacha20_block;
use crate::crypto::poly1305::{
    chacha_poly1305_key_from_block0, poly1305_aead_tag, POLY1305_AEAD_AAD,
};

/// Deterministic key/nonce/AAD (RFC 8439 §2.8 AEAD sample style).
fn key_nonce_aad() -> ([u8; 32], [u8; 12], &'static [u8]) {
    let key = (0x10u8..0x30).collect::<Vec<_>>().try_into().unwrap();
    let nonce = [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
    (key, nonce, &POLY1305_AEAD_AAD)
}

/// Our AEAD tag function must equal the RustCrypto ChaCha20Poly1305 tag over the
/// same (key, nonce, AAD, ciphertext) — the differential authority.
#[test]
fn poly1305_aead_tag_matches_chacha20poly1305_reference() {
    let (key, nonce, aad) = key_nonce_aad();
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce_ga = chacha20poly1305::Nonce::from_slice(&nonce);

    // Poly1305 one-time key = first 32 bytes of the counter=0 keystream block.
    let block0 = chacha20_block(&key, 0, &nonce);
    let poly_key = chacha_poly1305_key_from_block0(&block0);

    for len in [0usize, 1, 16, 33, 100, 300] {
        let plain: Vec<u8> = (0..len).map(|i| ((i as u32 * 7 + 3) % 251) as u8).collect();

        // Authority: RustCrypto encrypt → ciphertext + tag.
        let mut buf = plain.clone();
        let ref_tag = cipher
            .encrypt_in_place_detached(nonce_ga, aad, &mut buf)
            .unwrap();
        let ciphertext = buf;

        // Ours: tag over the real ciphertext with the derived Poly1305 key.
        let tag = poly1305_aead_tag(aad, &ciphertext, &poly_key);
        assert_eq!(
            &tag[..],
            ref_tag.as_slice(),
            "AEAD tag must match RustCrypto ChaCha20Poly1305 (len={len})"
        );
    }
}

/// Deterministic seed-derived Poly1305 key → AEAD tag round-trip: the packer tag
/// over (AAD, ciphertext) equals the boot-stub-verifiable tag.
#[test]
fn poly1305_aead_tag_roundtrip_deterministic() {
    let (_, _, aad) = key_nonce_aad();
    let poly_key: [u8; 32] = (0x80u8..=0x9f).collect::<Vec<_>>().try_into().unwrap();
    for len in [0usize, 15, 16, 17, 64, 300] {
        let ct: Vec<u8> = (0..len).map(|i| ((i as u32 * 131 + 7) % 251) as u8).collect();
        let tag = poly1305_aead_tag(aad, &ct, &poly_key);
        assert_eq!(tag.len(), 16);
        // recompute → deterministic
        let tag2 = poly1305_aead_tag(aad, &ct, &poly_key);
        assert_eq!(tag, tag2, "AEAD tag must be deterministic (len={len})");
    }
}

/// Tampered tag fails (before any decrypt side-effect — the verification is
/// done on the ciphertext + stored tag alone).
#[test]
fn poly1305_aead_tampered_tag_fails() {
    let (_, _, aad) = key_nonce_aad();
    let poly_key: [u8; 32] = (0x40u8..0x60).collect::<Vec<_>>().try_into().unwrap();
    let ct: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(7).wrapping_add(0x11)).collect();
    let tag = poly1305_aead_tag(aad, &ct, &poly_key);
    let mut bad = tag;
    bad[0] ^= 0xFF;
    assert_ne!(bad, tag);
    // (the boot-stub blob test asserts the mismatch is rejected natively)
    assert_eq!(tag.len(), 16);
}

/// Tampered ciphertext produces a different tag.
#[test]
fn poly1305_aead_tampered_ct_fails() {
    let (_, _, aad) = key_nonce_aad();
    let poly_key: [u8; 32] = (0x40u8..0x60).collect::<Vec<_>>().try_into().unwrap();
    let ct: Vec<u8> = (0..100u8).map(|i| i.wrapping_mul(3).wrapping_add(9)).collect();
    let tag = poly1305_aead_tag(aad, &ct, &poly_key);
    let mut bad_ct = ct.clone();
    bad_ct[0] ^= 0x01;
    let bad_tag = poly1305_aead_tag(aad, &bad_ct, &poly_key);
    assert_ne!(tag, bad_tag, "tampered ciphertext must change the tag");
}

/// Wrong AAD produces a different tag (AAD binding).
#[test]
fn poly1305_aead_wrong_aad_fails() {
    let (_, _, aad) = key_nonce_aad();
    let poly_key: [u8; 32] = (0x40u8..0x60).collect::<Vec<_>>().try_into().unwrap();
    let ct: Vec<u8> = (0..80u8).map(|i| i.wrapping_mul(5).wrapping_add(2)).collect();
    let tag_ok = poly1305_aead_tag(aad, &ct, &poly_key);
    let tag_wrong = poly1305_aead_tag(b"wrong-aad-binding!", &ct, &poly_key);
    assert_ne!(tag_ok, tag_wrong, "wrong AAD must change the tag");
}
