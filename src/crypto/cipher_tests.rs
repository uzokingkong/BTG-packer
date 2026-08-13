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

#[test]
fn native_keystream_matches_reference() {
    // plan.txt 6단계: native(셸코드) == reference 정본 동치.
    use super::native;
    use super::state::BtgState;
    use crate::vm::arena::Arena;

    let code = native::emit_keystream_block();
    let sbox = super::nonlinear::sbox();
    let key = [0x13u8, 0x57, 0x9A, 0xE4, 0x28, 0x6B, 0xD3, 0x0F, 0x91, 0x4C, 0xE7, 0x52, 0xBA, 0x39, 0x86, 0xD1, 0x05, 0xEF, 0x77, 0x20, 0xCB, 0x58, 0x43, 0xF6, 0x2E, 0xAD, 0x64, 0x91, 0x3C, 0xF5, 0x08, 0x1B];
    // code / sbox / key / out must not overlap (fully-unrolled 16-round code is ~30KB).
    let code_off = 0x0000;
    let sbox_off = 0x9000;
    let key_off = 0x9100;
    let out_off = 0x9200;
    assert!(code.len() <= sbox_off, "native code ({}B) overlaps sbox", code.len());

    let mut arena = Arena::new(0x40000).unwrap();
    {
        let b = arena.bytes();
        b[code_off..code_off + code.len()].copy_from_slice(&code);
        b[sbox_off..sbox_off + 0x100].copy_from_slice(&sbox);
        b[key_off..key_off + 0x20].copy_from_slice(&key);
    }

    for ctr in [0u64, 1, 7, 42] {
        let nonce = 0xA5B6_C7D8u32;
        arena.call5(
            code_off,
            arena.base + key_off,
            ctr,
            nonce,
            arena.base + sbox_off,
            arena.base + out_off,
        );
        let mut native_out = [0u8; 64];
        native_out.copy_from_slice(&arena.bytes()[out_off..out_off + 64]);
        let ref_out = BtgState::absorb(&key, ctr, nonce).to_keystream_bytes();
        assert_eq!(
            native_out,
            ref_out,
            "native keystream block must match reference (ctr={})",
            ctr
        );
    }
}


