// ==============================================================================
// BTG-C1 custom cipher - unit tests (reference verification)
//
// - S-box / permutation bijectivity
// - encrypt == decrypt roundtrip
// - avalanche (1-bit input change -> ~50% output bit change)
// - key / counter / nonce sensitivity
// - determinism
// ==============================================================================

use super::nonlinear;
use super::permutation;
use super::state::{BtgCipher, STATE_WORDS};
use std::collections::HashSet;

#[test]
fn sbox_is_bijective() {
    let sb = nonlinear::sbox();
    let set: HashSet<u8> = sb.iter().copied().collect();
    assert_eq!(set.len(), 256, "S-box must be a bijection (256 distinct values)");
}

#[test]
fn permutation_is_bijective() {
    let p = permutation::PERM;
    let set: HashSet<usize> = p.iter().copied().collect();
    assert_eq!(set.len(), STATE_WORDS, "permutation must be a bijection");
    // column-scattering: old column {0,4,8,12} must NOT stay in one new column
    let mut new_cols = HashSet::new();
    for &i in &[0usize, 4, 8, 12] {
        new_cols.insert(p[i] % 4);
    }
    assert!(new_cols.len() >= 2, "permutation must scatter a column across columns");
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = b"btg-c1-custom-cipher-key-0123456";
    for len in [1usize, 37, 64, 65, 1000] {
        let mut data: Vec<u8> = (0..len).map(|i| (i * 131 + 7) as u8).collect();
        let orig = data.clone();
        let mut enc = BtgCipher::new(key, 0x1234_5678);
        let mut dec = BtgCipher::new(key, 0x1234_5678);
        enc.crypt(&mut data);
        assert_ne!(data, orig, "cipher must change bytes (len={})", len);
        dec.crypt(&mut data);
        assert_eq!(data, orig, "roundtrip (len={})", len);
    }
}

#[test]
fn keystream_deterministic() {
    let key = b"deterministic-test-key-012345678";
    let mut a = BtgCipher::new(key, 0xABCD);
    let mut b = BtgCipher::new(key, 0xABCD);
    let mut buf_a = [0u8; 256];
    let mut buf_b = [0u8; 256];
    a.crypt(&mut buf_a);
    b.crypt(&mut buf_b);
    assert_eq!(buf_a, buf_b, "same key/nonce must give identical keystream");
}

#[test]
fn keystream_differs_by_key_and_nonce() {
    let mut a = BtgCipher::new(b"key-aaaaaaaaaaaaaaaaaaaaaaaaaa", 1);
    let mut b = BtgCipher::new(b"key-bbbbbbbbbbbbbbbbbbbbbbbbbb", 1);
    let mut c = BtgCipher::new(b"key-aaaaaaaaaaaaaaaaaaaaaaaaaa", 2);
    let mut buf_a = [0u8; 64];
    let mut buf_b = [0u8; 64];
    let mut buf_c = [0u8; 64];
    a.crypt(&mut buf_a);
    b.crypt(&mut buf_b);
    c.crypt(&mut buf_c);
    assert_ne!(buf_a, buf_b, "different key must differ");
    assert_ne!(buf_a, buf_c, "different nonce must differ");
}

#[test]
fn keystream_differs_by_counter() {
    let key = b"counter-test-key-012345678901234";
    let mut c = BtgCipher::new(key, 0x42);
    let mut out = [0u8; 128];
    c.crypt(&mut out);
    // first 64B block and second 64B block (different counter) must differ
    assert_ne!(&out[..64], &out[64..], "consecutive keystream blocks must differ");
}

#[test]
fn avalanche_diffusion() {
    // two states differing in one bit; after rounds the output bit-diff ratio
    // must be high (diffusion). ~50% is ideal; require > 25%.
    let mut a = [0u32; STATE_WORDS];
    let mut b = [0u32; STATE_WORDS];
    a[5] = 0x12345678;
    b[5] = 0x12345679; // 1-bit difference
    let mut ra = a;
    let mut rb = b;
    super::state::BtgCipher::round_words(&mut ra);
    super::state::BtgCipher::round_words(&mut rb);
    let mut diff_bits = 0u32;
    for i in 0..STATE_WORDS {
        diff_bits += (ra[i] ^ rb[i]).count_ones();
    }
    let ratio = diff_bits as f64 / (STATE_WORDS as f64 * 32.0);
    assert!(
        ratio > 0.25,
        "avalanche ratio too low: {:.2}% (diffusion too weak)",
        ratio * 100.0
    );
}
