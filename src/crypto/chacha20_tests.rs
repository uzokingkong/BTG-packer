// ==============================================================================
// T3-1: ChaCha20 (RFC 8439) — reference / native-blob differential tests
// ==============================================================================
// 1. RFC 8439 §2.3.2 block-function test vector (standard compliance).
// 2. `emit_chacha20_blob` native == reference keystream (다중 호출 연속성).
// 3. 패커측 키 유도(derive_chacha_key_nonce) + reference 스트림 암호화
//    == 네이티브 blob 복호화 (부트 스텁 복호화 계약).
// ==============================================================================

use crate::crypto::chacha20::{chacha20_block, chacha_apply, chacha_init_state};
use crate::vm::arena::Arena;

/// RFC 8439 §2.3.2 test vector.
#[test]
fn chacha20_block_matches_rfc8439_test_vector() {
    let key: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
    let nonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let ks = chacha20_block(&key, 1, &nonce);
    let expected = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    ];
    assert_eq!(ks, expected, "RFC 8439 block vector mismatch");
}

/// RFC 8439 §2.4.2: 256-byte plaintext encryption (first block of the AEAD
/// sample — 공식 spec과의 스트림 정합을 한 번 더 확인).
#[test]
fn chacha20_keystream_matches_rfc8439_sample_256b() {
    let key: [u8; 32] = (0x80u8..=0x9f).collect::<Vec<_>>().try_into().unwrap();
    // RFC 8439 §2.4.2 AEAD example nonce: 07:00:00:00:40:41:42:43:44:45:46:47
    let nonce = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    // The first 64 bytes of the RFC 8439 §2.4.2 keystream (counter = 1),
    // derived from the RFC's documented ciphertext XOR plaintext
    // ("Ladies and Gentlemen...", key 0x80..0x9f, nonce 07:00:00:00:40:41:42:43:44:45:46:47).
    let ks1 = chacha20_block(&key, 1, &nonce);
    let expected_first_block = [
        0x9f, 0x7b, 0xe9, 0x5d, 0x01, 0xfd, 0x40, 0xba, 0x15, 0xe2, 0x8f, 0xfb, 0x36, 0x81, 0x0a, 0xae,
        0xc1, 0xc0, 0x88, 0x3f, 0x09, 0x01, 0x6e, 0xde, 0xdd, 0x8a, 0xd0, 0x87, 0x55, 0x82, 0x03, 0xa5,
        0x4e, 0x9e, 0xcb, 0x38, 0xac, 0x8e, 0x5e, 0x2b, 0xb8, 0xda, 0xb2, 0x0f, 0xfa, 0xdb, 0x52, 0xe8,
        0x75, 0x04, 0xb2, 0x6e, 0xbe, 0x69, 0x6d, 0x4f, 0x60, 0xa4, 0x85, 0xcf, 0x11, 0xb8, 0x1b, 0x59,
    ];
    assert_eq!(&ks1[..], &expected_first_block[..], "RFC 8439 §2.4.2 first block mismatch");
}

/// 네이티브 crypt blob의 다중 호출 연속 키스트림 == reference `chacha_apply`.
/// (부트 스텁은 코드 영역 → 문자열 런 → IAT 리졸브 run을 같은 blob으로
///  연속 호출한다 — C1 blob 테스트와 동일한 계약.)
#[test]
fn chacha_native_blob_multi_call_matches_reference() {
    let blob_off = 0x0000usize;
    let state_off = 0x9000usize;
    let buf1_off = 0x9100usize;
    let buf2_off = 0x9200usize;

    let mut arena = Arena::new(0x40000).unwrap();
    let state_va = (arena.base + state_off) as u64;
    let code = crate::crypto::chacha20_native::emit_chacha20_blob(state_va);
    assert!(code.len() <= state_off, "chacha blob ({}B) overlaps state", code.len());
    {
        let b = arena.bytes();
        b[blob_off..blob_off + code.len()].copy_from_slice(&code);
    }

    // key/nonce (deterministic)
    let key: [u8; 32] = (0u8..32).map(|i| i.wrapping_mul(7).wrapping_add(0x13)).collect::<Vec<_>>().try_into().unwrap();
    let nonce: [u8; 12] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc];
    {
        let b = arena.bytes();
        chacha_init_state(
            (&mut b[state_off..state_off + 0x80]).try_into().unwrap(),
            &key,
            &nonce,
        );
        // zero buffers -> native output = pure keystream
        b[buf1_off..buf1_off + 100].fill(0);
        b[buf2_off..buf2_off + 37].fill(0);
    }

    arena.call2(blob_off, arena.base + buf1_off, 100);
    arena.call2(blob_off, arena.base + buf2_off, 37);

    // reference: same key/nonce, two successive applications
    let mut st = [0u8; 0x80];
    chacha_init_state(&mut st, &key, &nonce);
    let mut ref1 = vec![0u8; 100];
    chacha_apply(&mut st, &mut ref1);
    let mut ref2 = vec![0u8; 37];
    chacha_apply(&mut st, &mut ref2);

    let b = arena.bytes();
    let native1: Vec<u8> = b[buf1_off..buf1_off + 100].to_vec();
    let native2: Vec<u8> = b[buf2_off..buf2_off + 37].to_vec();
    assert_eq!(native1, ref1, "chacha blob call 1 must match reference keystream");
    assert_eq!(native2, ref2, "chacha blob call 2 (continuation) must match reference keystream");
    assert_ne!(native1, vec![0u8; 100], "keystream must be non-zero");
}

/// 패커측 키 유도(derive_chacha_key_nonce) + reference 스트림 암호화의 암호문을
/// 네이티브 blob으로 복호화하면 원문이 복원된다. (부트 스텁 at-rest 복호화 계약)
#[test]
fn chacha_packer_key_native_decrypt_equivalence() {
    use crate::pipeline::crypto::chacha::derive_chacha_key_nonce;

    let blob_off = 0x0000usize;
    let state_off = 0x9000usize;
    let buf_off = 0x9100usize;

    let mut arena = Arena::new(0x40000).unwrap();
    let state_va = (arena.base + state_off) as u64;
    let code = crate::crypto::chacha20_native::emit_chacha20_blob(state_va);
    assert!(code.len() <= state_off, "chacha blob ({}B) overlaps state", code.len());
    {
        let b = arena.bytes();
        b[blob_off..blob_off + code.len()].copy_from_slice(&code);
    }

    // deterministic 256B seed -> (key, nonce)
    let seed: Vec<u8> = (0u8..=255).map(|i| i.wrapping_mul(3).wrapping_add(7)).collect();
    let (key, nonce) = derive_chacha_key_nonce(&seed);

    for len in [1usize, 63, 64, 65, 130, 300] {
        let plain: Vec<u8> = (0..len).map(|i| ((i as u32 * 131 + 7) % 251) as u8).collect();

        // packer: reference stream encrypt
        let mut st = [0u8; 0x80];
        chacha_init_state(&mut st, &key, &nonce);
        let mut ct = plain.clone();
        chacha_apply(&mut st, &mut ct);
        assert_ne!(ct, plain, "stream must change bytes (len={len})");

        // native: state init + blob 1 call -> decrypt back to plain
        {
            let b = arena.bytes();
            chacha_init_state(
                (&mut b[state_off..state_off + 0x80]).try_into().unwrap(),
                &key,
                &nonce,
            );
            b[buf_off..buf_off + len].copy_from_slice(&ct);
        }
        arena.call2(blob_off, arena.base + buf_off, len as u64);
        let b = arena.bytes();
        assert_eq!(
            &b[buf_off..buf_off + len],
            plain.as_slice(),
            "native chacha blob must decrypt packer key-derived ciphertext (len={len})"
        );
    }
}
