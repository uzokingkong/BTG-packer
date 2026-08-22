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
    assert_eq!(
        set.len(),
        256,
        "S-box must be a bijection (256 distinct values)"
    );
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
    assert!(
        new_cols.len() >= 2,
        "permutation must scatter a column across columns"
    );
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
    assert_ne!(
        &out[..64],
        &out[64..],
        "consecutive keystream blocks must differ"
    );
}

#[test]
fn avalanche_diffusion() {
    // 1-bit difference in input word; after rounds the output bit-diff ratio
    // must reach cryptographic avalanche standard (~50%). Require >= 45%.
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
        ratio >= 0.45 && ratio <= 0.55,
        "avalanche ratio out of bounds: {:.2}% (expected 45%..55%)",
        ratio * 100.0
    );
}

#[test]
fn counter_avalanche_diffusion() {
    // 0 -> 1 counter change (1-bit diff) must achieve >= 45% bit diffusion in the 512-bit output block
    let key = [0x42u8; 32];
    let st0 = super::state::BtgState::absorb(&key, 0, 0x1234).to_keystream_bytes();
    let st1 = super::state::BtgState::absorb(&key, 1, 0x1234).to_keystream_bytes();
    let mut diff_bits = 0u32;
    for i in 0..64 {
        diff_bits += (st0[i] ^ st1[i]).count_ones();
    }
    let ratio = diff_bits as f64 / 512.0;
    assert!(
        ratio >= 0.45 && ratio <= 0.55,
        "counter avalanche ratio out of bounds: {:.2}% (expected 45%..55%)",
        ratio * 100.0
    );
}

#[test]
fn long_key_entropy_diffusion() {
    // Keys > 32 bytes: changing 1 bit in key bytes beyond 32 must diffuse across >= 45% bits
    let mut key1 = vec![0x33u8; 64];
    let mut key2 = vec![0x33u8; 64];
    key2[45] ^= 0x01; // 1-bit change in extended key area

    let mut c1 = BtgCipher::new(&key1, 0x99);
    let mut c2 = BtgCipher::new(&key2, 0x99);
    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];
    c1.crypt(&mut buf1);
    c2.crypt(&mut buf2);

    let mut diff_bits = 0u32;
    for i in 0..64 {
        diff_bits += (buf1[i] ^ buf2[i]).count_ones();
    }
    let ratio = diff_bits as f64 / 512.0;
    assert!(
        ratio >= 0.45 && ratio <= 0.55,
        "long key avalanche ratio out of bounds: {:.2}% (expected 45%..55%)",
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
    let key = [
        0x13u8, 0x57, 0x9A, 0xE4, 0x28, 0x6B, 0xD3, 0x0F, 0x91, 0x4C, 0xE7, 0x52, 0xBA, 0x39, 0x86,
        0xD1, 0x05, 0xEF, 0x77, 0x20, 0xCB, 0x58, 0x43, 0xF6, 0x2E, 0xAD, 0x64, 0x91, 0x3C, 0xF5,
        0x08, 0x1B,
    ];
    // code / sbox / key / out must not overlap (fully-unrolled 16-round code is ~30KB).
    let code_off = 0x0000;
    let sbox_off = 0x9000;
    let key_off = 0x9100;
    let out_off = 0x9200;
    assert!(
        code.len() <= sbox_off,
        "native code ({}B) overlaps sbox",
        code.len()
    );

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
            native_out, ref_out,
            "native keystream block must match reference (ctr={})",
            ctr
        );
    }
}

/// v60 (--custom-cipher): 상태형 `emit_btg_crypt_blob`의 **다중 호출 연속성** —
/// 부트 스텁은 코드 영역 → 문자열 런 → (IAT 리졸브) run을 같은 blob을 반복 호출해
/// 하나의 연속 키스트림으로 복호화한다. 이 테스트는 blob을 두 번(서로 다른 길이)
/// 호출했을 때의 결과가 reference `BtgCipher::crypt`(동일 key/nonce, 연속 호출)와
/// 비트 동일한지 검증한다 — plan.txt 6단계 native == reference 동치의 실행 형태.
#[test]
fn native_stateful_crypt_blob_multi_call_matches_reference() {
    use super::native;
    use super::state::BtgCipher;
    use crate::vm::arena::Arena;

    // layout: [blob][sbox 0x100][state 0x80][buf1][buf2]
    let blob_off = 0x0000usize;
    let sbox_off = 0x9000usize;
    let state_off = 0x9100usize;
    let buf1_off = 0x9200usize;
    let buf2_off = 0x9300usize;

    let mut arena = Arena::new(0x40000).unwrap();
    // blob은 절대 VA(c1_state_va/c1_sbox_va)를 내장하므로 arena base를 확보한 뒤 생성.
    let state_va = (arena.base + state_off) as u64;
    let sbox_va = (arena.base + sbox_off) as u64;
    let code = native::emit_btg_crypt_blob(state_va, sbox_va);
    assert!(
        code.len() <= sbox_off,
        "crypt blob ({}B) overlaps sbox",
        code.len()
    );
    {
        let b = arena.bytes();
        b[blob_off..blob_off + code.len()].copy_from_slice(&code);
        b[sbox_off..sbox_off + 0x100].copy_from_slice(&super::nonlinear::sbox());
    }

    // 부트 스텁 emit_c1_init과 동일한 상태 초기화:
    //   key[32]@+0x00, ctr=0@+0x20, nonce@+0x28, ks_off=0x40@+0x70
    let key = [
        0x13u8, 0x57, 0x9A, 0xE4, 0x28, 0x6B, 0xD3, 0x0F, 0x91, 0x4C, 0xE7, 0x52, 0xBA, 0x39, 0x86,
        0xD1, 0x05, 0xEF, 0x77, 0x20, 0xCB, 0x58, 0x43, 0xF6, 0x2E, 0xAD, 0x64, 0x91, 0x3C, 0xF5,
        0x08, 0x1B,
    ];
    let nonce = 0x5A6B_7C8Du32;
    {
        let b = arena.bytes();
        b[state_off..state_off + 32].copy_from_slice(&key);
        b[state_off + 0x28..state_off + 0x2C].copy_from_slice(&nonce.to_le_bytes());
        b[state_off + 0x70..state_off + 0x74].copy_from_slice(&0x40u32.to_le_bytes());
        // ctr(+0x20)와 ks(+0x30)는 0으로 남는다 — 첫 호출에서 gen_block이 덮어씀
    }

    // 서로 다른 길이의 두 버퍼 (64B 경계를 걸치는 케이스 포함)
    let len1 = 100usize;
    let len2 = 37usize;
    {
        let b = arena.bytes();
        // zero buffers → native 출력 = 순수 키스트림 (레퍼런스와 직접 비교)
        for i in 0..len1 {
            b[buf1_off + i] = 0;
        }
        for i in 0..len2 {
            b[buf2_off + i] = 0;
        }
    }

    // native: blob을 두 번 호출 (연속 키스트림) — 버퍼를 0으로 두면 출력이
    // 순수 키스트림이 되어 레퍼런스와 직접 비교할 수 있다 (encrypt == decrypt).
    arena.call2(blob_off, arena.base + buf1_off, len1 as u64);
    arena.call2(blob_off, arena.base + buf2_off, len2 as u64);

    // reference: 같은 key/nonce로 연속 crypt
    let b = arena.bytes();
    let native_ks1: Vec<u8> = b[buf1_off..buf1_off + len1].to_vec();
    let native_ks2: Vec<u8> = b[buf2_off..buf2_off + len2].to_vec();
    let mut c = BtgCipher::new(&key, nonce);
    let mut ref_ks1 = vec![0u8; len1];
    let mut ref_ks2 = vec![0u8; len2];
    c.crypt(&mut ref_ks1);
    c.crypt(&mut ref_ks2);

    assert_eq!(
        native_ks1, ref_ks1,
        "crypt blob call 1 must match reference keystream"
    );
    assert_eq!(
        native_ks2, ref_ks2,
        "crypt blob call 2 (continuation) must match reference keystream"
    );

    // 암호화 후 버퍼가 원본(0)과 달라야 하고, 두 호출이 연속 키스트림이어야 한다.
    assert_ne!(native_ks1, vec![0u8; len1], "keystream must be non-zero");
}

/// v61 (--custom-cipher + --m7): per-block 키 동치 — 패커 `BtgCipher::new(repeat4(key4),0)`
/// 암호화 == 네이티브 C1 blob(`C1Init` 상태 초기화 후 1회 호출) 복호화.
/// (M7/reencrypt C1 디스패처가 정확히 이 계약으로 블록을 복호화한다.)
#[test]
fn c1_per_block_packer_native_equivalence() {
    use super::native;
    use super::state::BtgCipher;
    use crate::vm::arena::Arena;

    let blob_off = 0x0000usize;
    let sbox_off = 0x9000usize;
    let state_off = 0x9100usize;
    let buf_off = 0x9200usize;

    let mut arena = Arena::new(0x40000).unwrap();
    let state_va = (arena.base + state_off) as u64;
    let sbox_va = (arena.base + sbox_off) as u64;
    let code = native::emit_btg_crypt_blob(state_va, sbox_va);
    assert!(
        code.len() <= sbox_off,
        "crypt blob ({}B) overlaps sbox",
        code.len()
    );
    {
        let b = arena.bytes();
        b[blob_off..blob_off + code.len()].copy_from_slice(&code);
        b[sbox_off..sbox_off + 0x100].copy_from_slice(&super::nonlinear::sbox());
    }

    // 여러 키/길이 케이스 (64B 경계 + 다양한 블록 길이)
    for (key4, len) in [
        (0x12345678u32, 29usize),
        (0xDEADBEEF, 64),
        (0xA5A5_5A5A, 130),
    ] {
        // 패커: repeat4(key4) → BtgCipher
        let key32 = {
            let mut k = [0u8; 32];
            for i in 0..8usize {
                k[i * 4..i * 4 + 4].copy_from_slice(&key4.to_le_bytes());
            }
            k
        };
        let mut plain: Vec<u8> = (0..len)
            .map(|i| ((i as u32 * 131 + key4) % 251) as u8)
            .collect();
        let orig = plain.clone();
        let mut enc = BtgCipher::new(&key32, 0);
        enc.crypt(&mut plain); // → ciphertext (파일 상태)

        // 네이티브: C1Init 상태 초기화 (key4 8회, ctr=0, nonce=0, ks_off=0x40) 후 blob 1회
        {
            let b = arena.bytes();
            b[state_off..state_off + 32].copy_from_slice(&key32);
            b[state_off + 0x20..state_off + 0x28].fill(0); // ctr = 0
            b[state_off + 0x28..state_off + 0x2C].fill(0); // nonce = 0
            b[state_off + 0x70..state_off + 0x74].copy_from_slice(&0x40u32.to_le_bytes());
            b[buf_off..buf_off + len].copy_from_slice(&plain); // 암호문 → 복호화 대상
        }
        arena.call2(blob_off, arena.base + buf_off, len as u64);
        let b = arena.bytes();
        assert_eq!(
            &b[buf_off..buf_off + len],
            orig.as_slice(),
            "native C1 blob must decrypt packer's repeat4(key4) ciphertext (key4={key4:#X}, len={len})"
        );
    }
}
