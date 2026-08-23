// ==============================================================================
// BTG Packer — T3-1: ChaCha20-Poly1305 (AEAD) 암호화 엔진
// ==============================================================================
//
// 목적: 기존 RC4(스트림 암호, 인증 없음) 대신 ChaCha20-Poly1305(AEAD)로 교체 가능한
//       고수준 암호화 인터페이스를 제공한다. Themida 수준의 보호를 위해:
//   - ChaCha20: 현대적 스트림 암호 (RC4 대비 암호학적 강도 대폭 향상)
//   - Poly1305: 인증 태그 → 부트 스텁이 복호화 전 무결성 검증 가능
//   - HKDF-SHA256: 패커 랜덤 시드 → ChaCha20 키/논스 안전한 파생
//
// 현재 통합 전략 (단계적 마이그레이션):
//   Phase A (완료): 패커 측 암호화 엔진 구현 + 단위 테스트
//   Phase B (완료): BootStubCtx `CryptoMode` variant + `--crypto-mode chacha20` 배선 +
//       코드/문자열 영역 at-rest 암호화 전환 (RFC 8439 원시 스트림 — 패커 reference
//       `chacha20::chacha_apply` ↔ 부트 스텁 네이티브 blob, seed 원시 파생 계약).
//       `repro/test_prog.exe` pack→run 16-test + FINAL CHECKSUM baseline 무회귀.
//   Phase C (완료): boot-stub용 네이티브 ChaCha20 crypt blob
//       `crypto::chacha20_native::emit_chacha20_blob` (RFC 8439 reference와 차등
//       검증 — src/crypto/chacha20_tests.rs).
//   Phase D (예정): ChaCha20-Poly1305 AEAD 무결성 검증 (Poly1305 태그 — 부트 스텁
//       복호화 전 인증). 아래 AEAD API는 Phase-D/E 통합 전까지 예약.
//
// 참조: chacha20poly1305 crate (RustCrypto, MIT/Apache-2.0)
// ==============================================================================

use anyhow::Result;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use sha2::{Digest, Sha256};

/// T3-1: ChaCha20-Poly1305 암호화 결과.
///
/// 복호화 시 `key`(32B) + `nonce`(12B) + `tag`(16B) 를 부트 스텁이 알아야 한다.
/// 현재 설계: `key`/`nonce`는 seed에서 HKDF로 파생하므로 따로 저장하지 않음.
/// `tag`는 `ciphertext` 끝에 16바이트로 인라인 됨 (`encrypt_in_place_detached` 사용).
pub struct ChaEncryptResult {
    /// 암호문 (원문과 동일한 길이 — 스트림 암호라 팽창 없음)
    pub ciphertext: Vec<u8>,
    /// Poly1305 인증 태그 (16바이트)
    pub tag: [u8; 16],
    /// ChaCha20 논스 (12바이트) — 부트 스텁이 복호화 시 필요
    pub nonce: [u8; 12],
    /// 파생 키 (32바이트) — 부트 스텁이 시드에서 동일하게 파생
    pub key: [u8; 32],
}

/// T3-1: 시드(256B) + AAD(additional authenticated data)에서 ChaCha20-Poly1305 키/논스 파생.
///
/// HKDF 대신 단순 SHA-256 기반 파생 (부트 스텁 셸코드 구현 단순화):
///   key  = SHA-256(seed[0..128] || "btg-cha-key")
///   nonce = SHA-256(seed[128..256] || "btg-cha-nonce")[0..12]
///
/// 두 입력을 분리해 key/nonce가 독립적 엔트로피를 가지도록 한다.
pub fn derive_chacha_key_nonce(seed: &[u8]) -> ([u8; 32], [u8; 12]) {
    debug_assert!(seed.len() >= 256, "seed must be 256+ bytes");
    let half = seed.len().min(256) / 2;

    // key: SHA-256(seed[0..half] || domain-tag)
    let mut h_key = Sha256::new();
    h_key.update(&seed[..half]);
    h_key.update(b"btg-cha-key-v1");
    let key_bytes: [u8; 32] = h_key.finalize().into();

    // nonce: SHA-256(seed[half..] || domain-tag)[0..12]
    let mut h_nonce = Sha256::new();
    h_nonce.update(&seed[half..seed.len().min(256)]);
    h_nonce.update(b"btg-cha-nonce-v1");
    let nonce_hash: [u8; 32] = h_nonce.finalize().into();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_hash[..12]);

    (key_bytes, nonce)
}

/// T3-1: ChaCha20-Poly1305 패커측 암호화.
///
/// - `plaintext`: 암호화할 원문 (코드 블록 or VM bytecode)
/// - `seed`: 256B 패커 랜덤 시드 (부트 스텁에도 저장됨)
/// - `aad`: Additional Authenticated Data (선택적 — 변조 방지 범위 확장)
///
/// 반환: `ChaEncryptResult` (ciphertext, tag, nonce, key 포함)
pub fn cha_encrypt(plaintext: &[u8], seed: &[u8], aad: &[u8]) -> Result<ChaEncryptResult> {
    let (key, nonce) = derive_chacha_key_nonce(seed);

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("T3-1: ChaCha20Poly1305 key init failed: {e}"))?;

    let nonce_ga = chacha20poly1305::Nonce::from_slice(&nonce);

    // Encrypt with associated data
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce_ga, aad, &mut buf)
        .map_err(|e| anyhow::anyhow!("T3-1: ChaCha20-Poly1305 encrypt failed: {e}"))?;

    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(tag.as_slice());

    Ok(ChaEncryptResult {
        ciphertext: buf,
        tag: tag_bytes,
        nonce,
        key,
    })
}

/// T3-1: ChaCha20-Poly1305 패커측 복호화 (검증용).
///
/// `cha_encrypt`의 역연산 — 태그 검증 포함. 태그 불일치 시 `Err` 반환.
pub fn cha_decrypt(
    ciphertext: &[u8],
    tag: &[u8; 16],
    nonce: &[u8; 12],
    key: &[u8; 32],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::Tag;

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("T3-1: ChaCha20Poly1305 decrypt key init failed: {e}"))?;

    let nonce_ga = chacha20poly1305::Nonce::from_slice(nonce);
    let tag_ga = Tag::<ChaCha20Poly1305>::from_slice(tag);

    let mut buf = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(nonce_ga, aad, &mut buf, tag_ga)
        .map_err(|_| {
            anyhow::anyhow!("T3-1: ChaCha20-Poly1305 tag verification FAILED — ciphertext tampered")
        })?;

    Ok(buf)
}

/// T3-1: 호환성 래퍼 — `ChaEncryptResult`를 부트 스텁 바이너리 포맷으로 직렬화.
///
/// 포맷: [nonce(12B)] [tag(16B)] [ciphertext(N B)]
/// 부트 스텁은 이 순서로 읽어 `nonce` + `tag`를 추출한 뒤 복호화/검증한다.
pub fn cha_pack(result: &ChaEncryptResult) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + 16 + result.ciphertext.len());
    out.extend_from_slice(&result.nonce);
    out.extend_from_slice(&result.tag);
    out.extend_from_slice(&result.ciphertext);
    out
}

/// T3-1: `cha_pack` 역연산 — [nonce(12B)][tag(16B)][ciphertext] → 복호화.
pub fn cha_unpack_decrypt(packed: &[u8], seed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if packed.len() < 28 {
        anyhow::bail!(
            "T3-1: packed ChaCha20 blob too short ({} < 28)",
            packed.len()
        );
    }
    let (key, _) = derive_chacha_key_nonce(seed);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&packed[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&packed[12..28]);
    let ciphertext = &packed[28..];
    cha_decrypt(ciphertext, &tag, &nonce, &key, aad)
}

// ==============================================================================
// 단위 테스트
// ==============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn make_seed() -> Vec<u8> {
        // 결정론적 테스트 시드 (랜덤 없이 재현 가능)
        let mut seed = vec![0u8; 256];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i * 3 + 7) as u8;
        }
        seed
    }

    /// T3-1-A: derive_chacha_key_nonce는 결정론적이어야 한다.
    #[test]
    fn chacha_key_nonce_derivation_is_deterministic() {
        let seed = make_seed();
        let (k1, n1) = derive_chacha_key_nonce(&seed);
        let (k2, n2) = derive_chacha_key_nonce(&seed);
        assert_eq!(k1, k2, "key must be deterministic");
        assert_eq!(n1, n2, "nonce must be deterministic");
        // key와 nonce는 달라야 함 (독립적 파생)
        assert_ne!(&k1[..12], &n1[..], "key prefix must differ from nonce");
    }

    /// T3-1-B: 암호화 → 복호화 왕복 검증.
    #[test]
    fn chacha_encrypt_decrypt_roundtrip() {
        let seed = make_seed();
        let plaintext = b"BTG Packer T3-1: ChaCha20-Poly1305 roundtrip test payload";
        let aad = b"btg-section-textb";

        let result = cha_encrypt(plaintext, &seed, aad).expect("encrypt must succeed");
        assert_eq!(
            result.ciphertext.len(),
            plaintext.len(),
            "ciphertext same length as plaintext"
        );
        assert_ne!(
            result.ciphertext, plaintext,
            "ciphertext must differ from plaintext"
        );

        let decrypted = cha_decrypt(
            &result.ciphertext,
            &result.tag,
            &result.nonce,
            &result.key,
            aad,
        )
        .expect("decrypt must succeed");
        assert_eq!(decrypted, plaintext, "decrypted must equal original");
    }

    /// T3-1-C: 태그 변조 시 복호화 실패.
    #[test]
    fn chacha_tampered_tag_fails_verification() {
        let seed = make_seed();
        let plaintext = b"integrity check payload";
        let aad = b"";

        let result = cha_encrypt(plaintext, &seed, aad).expect("encrypt");
        let mut bad_tag = result.tag;
        bad_tag[0] ^= 0xFF; // 태그 1바이트 반전

        let res = cha_decrypt(
            &result.ciphertext,
            &bad_tag,
            &result.nonce,
            &result.key,
            aad,
        );
        assert!(res.is_err(), "tampered tag must cause decrypt failure");
    }

    /// T3-1-D: 암호문 변조 시 복호화 실패 (Poly1305 인증).
    #[test]
    fn chacha_tampered_ciphertext_fails_verification() {
        let seed = make_seed();
        let plaintext = b"integrity check ciphertext";
        let aad = b"";

        let result = cha_encrypt(plaintext, &seed, aad).expect("encrypt");
        let mut bad_ct = result.ciphertext.clone();
        bad_ct[0] ^= 0x01; // 암호문 1비트 반전

        let res = cha_decrypt(&bad_ct, &result.tag, &result.nonce, &result.key, aad);
        assert!(res.is_err(), "tampered ciphertext must cause auth failure");
    }

    /// T3-1-E: cha_pack / cha_unpack_decrypt 포맷 왕복.
    #[test]
    fn chacha_pack_unpack_roundtrip() {
        let seed = make_seed();
        let plaintext = b"packed format roundtrip";
        let aad = b"btg-pack-test";

        let result = cha_encrypt(plaintext, &seed, aad).expect("encrypt");
        let packed = cha_pack(&result);
        assert_eq!(packed.len(), 12 + 16 + plaintext.len());

        let recovered = cha_unpack_decrypt(&packed, &seed, aad).expect("unpack decrypt");
        assert_eq!(recovered, plaintext);
    }

    /// T3-1-F: AAD가 다르면 복호화 실패.
    #[test]
    fn chacha_wrong_aad_fails() {
        let seed = make_seed();
        let plaintext = b"aad binding test";
        let aad_correct = b"correct-aad";
        let aad_wrong = b"wrong-aad";

        let result = cha_encrypt(plaintext, &seed, aad_correct).expect("encrypt");
        let res = cha_decrypt(
            &result.ciphertext,
            &result.tag,
            &result.nonce,
            &result.key,
            aad_wrong,
        );
        assert!(res.is_err(), "wrong AAD must cause auth failure");
    }

    /// T3-1-G: 대용량 (1MB) 암호화 성능 — panic 없이 완료.
    #[test]
    fn chacha_large_payload_no_panic() {
        let seed = make_seed();
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1MB
        let result = cha_encrypt(&plaintext, &seed, b"").expect("1MB encrypt");
        assert_eq!(result.ciphertext.len(), plaintext.len());
    }
}
