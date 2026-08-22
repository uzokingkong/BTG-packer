// ==============================================================================
// BTG v41 - M7 on-demand 재암호화 (anti-dump)
// ==============================================================================
//
// M7 목표: 원본 `.text`/`.data`/`.rdata` 런을 **파일에는 암호문으로** 저장하고,
// 실행 중 필요할 때만 청크를 임시 복호화 → 사용 → **즉시 재암호화**하여, 어느 시점에
// 덤프를 떠도 원본 평문이 최소한만(또는 전혀) 노출되지 않게 한다.
//
// 이 모듈은 그 코어 로직을 순수 Rust로 제공한다:
//   - 각 청크는 BTG-RC1 DataLifetime 실행 문맥으로 독립 암호화.
//   - `process_on_demand(...)`: 주어진 바이트 범위를 (복호화→callback 사용→재암호화)
//     한 번에 처리해, 함수 반환 시점에 버퍼는 다시 **암호문**이 되도록 한다.
//   - `simulate_dump(...)`: "사용 직후 덤프"를 흉내내, 재암호화가 끝난 상태가
//     평문이 아닌지 검증하는 데 쓰인다.
//
// 부트 스텁(또는 패커의 --m7 배선)이 이 로직을 region table의 각 런에 적용하면
// on-demand 재암호화가 동작한다. 회귀 안전: 기본 경로(--full/--vm)는 이 모듈을
// 호출하지 않으므로 무변경.
// ==============================================================================

use crate::crypto::region_cipher::{crypt_region, derive_root_secret, RegionContext, RegionKind};

fn transform(buf: &mut [u8], key_material: &[u8], region_id: u64) {
    let root = derive_root_secret(key_material);
    crypt_region(
        &root,
        RegionContext {
            region_id,
            family_id: 0,
            function_id: 0,
            predecessor_token: 0,
            integrity_epoch: 0,
            kind: RegionKind::DataLifetime,
        },
        buf,
    );
}

/// Produce or consume the file-state ciphertext for one independently keyed
/// data-lifetime region.
pub fn crypt_on_demand_region(buf: &mut [u8], key_material: &[u8], region_id: u64) {
    transform(buf, key_material, region_id);
}

/// on-demand 청크 처리기.
/// `buf[..len]`을 `key`로 복호화 → `use_it(&mut buf[..len])` 호출 → 같은 키로 재암호화.
/// 반환 시점에 `buf[..len]`은 **암호문** (anti-dump).
pub fn process_on_demand<F: FnOnce(&mut [u8])>(buf: &mut [u8], len: usize, key: &[u8], use_it: F) {
    process_on_demand_region(buf, len, key, 0, use_it)
}

pub fn process_on_demand_region<F: FnOnce(&mut [u8])>(
    buf: &mut [u8],
    len: usize,
    key: &[u8],
    region_id: u64,
    use_it: F,
) {
    transform(&mut buf[..len], key, region_id);
    use_it(&mut buf[..len]); // use the plaintext
    transform(&mut buf[..len], key, region_id);
}

/// "사용 직후 덤프"를 흉내낸다: on-demand 처리 후 버퍼가 평문이 아닌지 검증.
/// `plain` = 원본 평문, `cipher` = 원본 암호문(파일에 저장된 상태).
/// 반환: `true` = 덤프가 평문을 노출하지 않음 (buf == cipher, 평문과 다름).
pub fn simulate_dump(plain: &[u8], cipher: &[u8], key: &[u8]) -> bool {
    let mut buf = cipher.to_vec();
    let len = buf.len();
    process_on_demand(&mut buf, len, key, |_| {
        // 사용 중: 평문 상태 (여기서는 아무것도 안 함)
    });
    // 반환 후: buf는 재암호화된 상태. 평문과 달라야 anti-dump 충족.
    buf != plain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ondemand_roundtrip_leaves_encrypted() {
        let key = b"m7-on-demand-key";
        let plain = b"The quick brown fox jumps over the lazy dog. 0123456789";
        let mut cipher = plain.to_vec();
        crypt_on_demand_region(&mut cipher, key, 7);
        assert_ne!(cipher, plain, "cipher should differ from plain");

        // on-demand: decrypt -> use -> re-encrypt leaves it encrypted.
        assert!(
            {
                let mut buf = cipher.clone();
                let len = buf.len();
                process_on_demand_region(&mut buf, len, key, 7, |_| {});
                buf != plain
            },
            "after use, dump must be encrypted"
        );

        // And a second decrypt recovers plaintext (round-trip intact).
        let mut buf = cipher.clone();
        crypt_on_demand_region(&mut buf, key, 7);
        assert_eq!(buf, plain, "decrypt after on-demand must recover plaintext");
    }

    #[test]
    fn ondemand_use_sees_plaintext() {
        let key = b"k";
        let mut buf = b"secret".to_vec();
        // encrypt first
        crypt_on_demand_region(&mut buf, key, 0);
        let mut seen = Vec::new();
        let blen = buf.len();
        process_on_demand(&mut buf, blen, key, |p| {
            seen.extend_from_slice(p); // during use, we see plaintext
        });
        assert_eq!(seen, b"secret", "use callback must observe plaintext");
        assert_ne!(
            buf,
            b"secret".to_vec(),
            "after on-demand, buffer must be re-encrypted"
        );
    }

    #[test]
    fn region_ids_do_not_share_keystreams() {
        let key = b"m7-root";
        let plain = b"same bytes";
        let mut a = plain.to_vec();
        let mut b = plain.to_vec();
        crypt_on_demand_region(&mut a, key, 1);
        crypt_on_demand_region(&mut b, key, 2);
        assert_ne!(a, b);
    }
}
