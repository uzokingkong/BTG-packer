// ==============================================================================
// Crypto abstraction layer (plan.txt 1~3단계 — CryptoProvider / BlockCrypto /
// RuntimeCrypto 결합 분리)
//
// 목표: RC4가 pipeline / dispatcher / bootstub / VM 곳곳에 직접 박혀 있는
// 결합을 끊고,
//
//     CryptoProvider
//        ├── BlockCrypto   (block 단위 stream 암호: encrypt_block/decrypt_block)
//        └── RuntimeCrypto (부트 스텁 / 디스패처 / VM 런타임 경로)
//
// 형태로 통일한다. pipeline 외부 코드는 `CryptoProvider` 트레이트가 제공하는
// `derive_block_key` / `from_key` / `apply` / `encrypt_block` / `decrypt_block`
// API만 사용하고, cipher 내부 구현은 절대 알지 못한다.
//
// 현재 구현체는 기존 RC4-256을 그대로 `impl CryptoProvider for Rc4`로 감싼다.
// 부트 스텁 셸코드(KSA/PRGA 서브루틴)와 VM KSA/PRGA 바이트코드가 RC4에
// 결합되어 있으므로, 알고리즘을 교체(custom 512-bit cipher)할 때까지는
// **동작 동치를 그대로 유지**한다. 알고리즘 교체는 이 트레이트 경계 뒤에서만
// 이루어진다 (plan.txt 4~6단계).
// ==============================================================================

use crate::crypto::state::BtgCipher;
use crate::pipeline::crypto::cipher::Rc4;
use std::fmt;

/// 블록 단위 암호 메타데이터 — dispatcher가 암호 내부를 알 필요 없이
/// (block_id, offset, length, nonce, epoch)만으로 블록 키를 유도/검증한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockCryptoMeta {
    pub block_id: u32,
    /// 섹션/영역 내 물리 오프셋 (VA 또는 바이트 오프셋; provider가 해석).
    pub offset: u64,
    /// 블록 길이 (바이트).
    pub length: u32,
    /// 블록별 nonce (기본: block_id ^ offset 하위 워드).
    pub nonce: u32,
    /// 키 유도 세대/에포크 (키 회전용).
    pub epoch: u32,
}

impl BlockCryptoMeta {
    pub fn new(block_id: u32, offset: u64, length: u32) -> Self {
        Self {
            block_id,
            offset,
            length,
            nonce: block_id ^ (offset as u32),
            epoch: 0,
        }
    }

    /// (block_id, offset, length, nonce, epoch)를 직렬화 — 4+8+4+4+4 = 24B.
    /// 키 유도/디버그 출력/검증용.
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0..4].copy_from_slice(&self.block_id.to_le_bytes());
        out[4..12].copy_from_slice(&self.offset.to_le_bytes());
        out[12..16].copy_from_slice(&self.length.to_le_bytes());
        out[16..20].copy_from_slice(&self.nonce.to_le_bytes());
        out[20..24].copy_from_slice(&self.epoch.to_le_bytes());
        out
    }
}

/// 암호 계층 오류.
#[derive(Debug)]
pub struct CryptoError(pub String);

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crypto: {}", self.0)
    }
}

impl std::error::Error for CryptoError {}

/// 스트림 암호 추상화. 독립 블록 키(plan.txt 3단계) 설계 —
/// `derive_block_key(master, meta)`로 블록 키를 유도하고
/// `from_key`로 provider를 만들어 `encrypt_block`/`decrypt_block`로 처리한다.
///
/// RC4 구현에서 `derive_block_key`는 기존 MBA per-block 키
/// (`MbaGenerator::compute_key(seed_for(c,id), id, c, 2)`)를 그대로 재현한다 —
/// reencrypt 디스패처 셸코드가 런타임에 유도하는 키와 정확히 일치해야 하므로
/// 동작을 바꾸지 않는다. `master_key`는 4바이트 `mba_constant` LE 바이트이다.
pub trait CryptoProvider: Sized {
    /// (master_key, meta) → 독립 블록 키.
    fn derive_block_key(master_key: &[u8], meta: &BlockCryptoMeta) -> Vec<u8>;

    /// 유도된 키로 provider 인스턴스 생성.
    fn from_key(key: &[u8]) -> Self;

    /// 키스트림을 buf에 XOR 적용 (스트림 암호는 encrypt == decrypt).
    fn apply(&mut self, buf: &mut [u8]);

    /// 블록 전체를 암호화 (길이 무결성 검사 포함).
    fn encrypt_block(&mut self, meta: &BlockCryptoMeta, buf: &mut [u8]) -> Result<(), CryptoError> {
        if buf.len() as u32 != meta.length {
            return Err(CryptoError(format!(
                "encrypt_block length mismatch: buf={} meta.length={} (block_id={})",
                buf.len(),
                meta.length,
                meta.block_id
            )));
        }
        self.apply(buf);
        Ok(())
    }

    /// 블록 전체를 복호화 (스트림 암호에서 encrypt와 동일).
    fn decrypt_block(&mut self, meta: &BlockCryptoMeta, buf: &mut [u8]) -> Result<(), CryptoError> {
        self.encrypt_block(meta, buf)
    }
}

impl CryptoProvider for Rc4 {
    fn derive_block_key(master_key: &[u8], meta: &BlockCryptoMeta) -> Vec<u8> {
        let c = if master_key.len() >= 4 {
            u32::from_le_bytes(master_key[..4].try_into().unwrap())
        } else if let Some(&b) = master_key.first() {
            u32::from(b)
        } else {
            0
        };
        let seed = crate::mba::MbaGenerator::seed_for(c, meta.block_id);
        let key = crate::mba::MbaGenerator::compute_key(seed, meta.block_id, c, 2);
        key.to_le_bytes().to_vec()
    }

    fn from_key(key: &[u8]) -> Self {
        Rc4::new(key)
    }

    fn apply(&mut self, buf: &mut [u8]) {
        self.crypt(buf);
    }
}

impl CryptoProvider for BtgCipher {
    fn derive_block_key(master_key: &[u8], meta: &BlockCryptoMeta) -> Vec<u8> {
        let mut key = [0u8; 32];
        let n = master_key.len().min(32);
        key[..n].copy_from_slice(&master_key[..n]);
        let meta_bytes = meta.to_bytes();
        for (i, &b) in meta_bytes.iter().enumerate() {
            key[i % 32] ^= b.wrapping_add((i as u8).wrapping_mul(0x5A));
        }
        key.to_vec()
    }

    fn from_key(key: &[u8]) -> Self {
        BtgCipher::new(key, 0)
    }

    fn apply(&mut self, buf: &mut [u8]) {
        self.crypt(buf);
    }
}

/// 제네릭 청크 체이닝: 임의의 `CryptoProvider`를 사용하여 256B 청크마다
/// 이전 청크 평문으로 재키잉 암호화한다.
pub fn chain_encrypt_with<P: CryptoProvider>(buf: &mut [u8], anchor: &[u8; 256]) -> [u8; 256] {
    let plain = buf.to_vec();
    let mut prev: [u8; 256] = *anchor;
    let mut off = 0usize;
    while off < buf.len() {
        let n = (buf.len() - off).min(256);
        let mut cipher = P::from_key(&prev);
        cipher.apply(&mut buf[off..off + n]);
        if off + n >= 256 {
            prev.copy_from_slice(&plain[off + n - 256..off + n]);
        } else {
            prev = [0u8; 256];
            prev[..off + n].copy_from_slice(&plain[..off + n]);
        }
        off += n;
    }
    prev
}

/// v7 청크 체이닝 (기본 Rc4 provider 호환):
/// 부트 스텁의 체인 복호화 셸코드와 정확히 동일한 동작을 유지한다.
pub fn chain_encrypt(buf: &mut [u8], anchor: &[u8; 256]) -> [u8; 256] {
    chain_encrypt_with::<Rc4>(buf, anchor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_crypto_meta_roundtrip_bytes() {
        let m = BlockCryptoMeta::new(0x1234, 0x5678, 0x100);
        let b = m.to_bytes();
        let (id, off, len, nonce, ep) = (
            u32::from_le_bytes(b[0..4].try_into().unwrap()),
            u64::from_le_bytes(b[4..12].try_into().unwrap()),
            u32::from_le_bytes(b[12..16].try_into().unwrap()),
            u32::from_le_bytes(b[16..20].try_into().unwrap()),
            u32::from_le_bytes(b[20..24].try_into().unwrap()),
        );
        assert_eq!(id, m.block_id);
        assert_eq!(off, m.offset);
        assert_eq!(len, m.length);
        assert_eq!(nonce, m.nonce);
        assert_eq!(ep, m.epoch);
    }

    #[test]
    fn rc4_provider_roundtrip() {
        let key = b"provider-test-key-0123456789abcdef";
        let mut data = vec![0x11u8; 512];
        let orig = data.clone();
        let mut enc = Rc4::from_key(key);
        let mut dec = Rc4::from_key(key);
        enc.apply(&mut data);
        assert_ne!(data, orig, "stream cipher must change the bytes");
        dec.apply(&mut data);
        assert_eq!(data, orig, "encrypt then decrypt must roundtrip");
    }

    #[test]
    fn rc4_derive_block_key_matches_mba() {
        // reencrypt per-block 키 유도가 기존 MBA key와 동일한지 (디스패처 셸코드
        // 호환성 — 패커/디스패처/VM이 같은 키를 써야 한다).
        let c: u32 = 0x1234_5678;
        let id: u32 = 0xABCD;
        let meta = BlockCryptoMeta::new(id, 0, 64);
        let k = <Rc4 as CryptoProvider>::derive_block_key(&c.to_le_bytes(), &meta);
        let seed = crate::mba::MbaGenerator::seed_for(c, id);
        let expect = crate::mba::MbaGenerator::compute_key(seed, id, c, 2);
        assert_eq!(k, expect.to_le_bytes().to_vec());
    }

    #[test]
    fn chain_encrypt_roundtrip() {
        let anchor = [0x5Au8; 256];
        let mut data = vec![0u8; 700];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let orig = data.clone();
        let last_key = chain_encrypt(&mut data, &anchor);
        assert_ne!(data, orig);
        // 체인 복호화: chunk0 = anchor, 이후 이전 평문 윈도우
        let mut prev = anchor;
        let mut off = 0usize;
        while off < orig.len() {
            let n = (orig.len() - off).min(256);
            let mut rc4 = Rc4::new(&prev);
            rc4.crypt(&mut data[off..off + n]);
            if off + n >= 256 {
                prev.copy_from_slice(&orig[off + n - 256..off + n]);
            } else {
                prev = [0u8; 256];
                prev[..off + n].copy_from_slice(&orig[..off + n]);
            }
            off += n;
        }
        assert_eq!(data, orig, "chain decrypt must restore plaintext");
        assert_eq!(last_key, prev);
    }

    #[test]
    fn btg_cipher_provider_roundtrip() {
        let key = b"btg-cipher-provider-key-01234567";
        let meta = BlockCryptoMeta::new(42, 0x1000, 512);
        let block_key = <BtgCipher as CryptoProvider>::derive_block_key(key, &meta);
        let mut data = vec![0xAAu8; 512];
        let orig = data.clone();
        let mut enc = <BtgCipher as CryptoProvider>::from_key(&block_key);
        let mut dec = <BtgCipher as CryptoProvider>::from_key(&block_key);
        enc.encrypt_block(&meta, &mut data).unwrap();
        assert_ne!(data, orig);
        dec.decrypt_block(&meta, &mut data).unwrap();
        assert_eq!(data, orig);
    }

    #[test]
    fn btg_cipher_chain_encrypt_roundtrip() {
        let anchor = [0x7Eu8; 256];
        let mut data = vec![0u8; 600];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 37 + 13) as u8;
        }
        let orig = data.clone();
        let last_key = chain_encrypt_with::<BtgCipher>(&mut data, &anchor);
        assert_ne!(data, orig);

        // 체인 복호화
        let mut prev = anchor;
        let mut off = 0usize;
        while off < orig.len() {
            let n = (orig.len() - off).min(256);
            let mut cipher = <BtgCipher as CryptoProvider>::from_key(&prev);
            cipher.apply(&mut data[off..off + n]);
            if off + n >= 256 {
                prev.copy_from_slice(&orig[off + n - 256..off + n]);
            } else {
                prev = [0u8; 256];
                prev[..off + n].copy_from_slice(&orig[..off + n]);
            }
            off += n;
        }
        assert_eq!(data, orig, "BtgCipher chain decrypt must restore plaintext");
        assert_eq!(last_key, prev);
    }
}
