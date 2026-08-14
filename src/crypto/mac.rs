// ==============================================================================
// BTG - Keyed-MAC (T2-3)
// ==============================================================================
// 기존 `--integrity`는 CRC32(키 없음)만 써서, 공격자가 데이터를 바꾸고 4바이트
// CRC를 함께 패치하면 우회된다(손상검출만 가능, 변조방어 불가). 이 모듈은
// 시드/키에 결합된 비선형 폴리노미얼 MAC을 제공한다.
//
// 설계 목표:
//   - 키 없이는 검증 불가 (CRC32와 달리 4바이트를 함께 변조해도 통과 불가).
//   - 64비트 출력 — 무차별 2^-64. native(부트 스텁 셸코드)로 이식 가능한
//     단순 산술(ADD/XOR/SHL/ROL)만 사용한다.
//   - 초기 상태가 키 의존 → 데이터 길이/내용 변화는 물론, 키를 모르면
//     예측 불가.
//
// 알고리즘: 키로 초기화된 128비트 상태(두 64비트 워드 h0, h1)를 비선형
// 폴리노미얼 갱신으로 데이터 바이트마다 진화시킨다.
//   for each byte b (각 i=바이트 인덱스):
//     h1 ^= (b ^ key_rot[i]) as u64
//     h1 = h1.rotate_left((i & 63) as u32) * PHI + h0
//     h0 = h0.rotate_left(17) ^ h1
//   out = h0 ^ h1.rotate_left(32)   (2개 64비트 워드 접어 64비트 출력)
// encrypt/decrypt 방향성 없음 — 단방향 MAC.
// ==============================================================================

/// 골든 레이트 (2^64 * (√5−1)/2) — 확산 상수.
const PHI: u64 = 0x9E37_79B9_7F4A_7C15;

/// 시드 → keyed-MAC 상태 초기화. 시드는 파이프라인 seed_masked 계열에서 유도된다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtgKeyedMac {
    h0: u64,
    h1: u64,
}

impl BtgKeyedMac {
    pub fn new(seed: &[u8]) -> Self {
        // 키를 128비트 상태로 흡수 (길이 무관, 반복 키도 상이한 초기 상태 생성).
        let mut h0 = 0x6A09_E667_F3BC_C909u64;
        let mut h1 = 0xBB67_AE85_84CA_A73Bu64;
        for (i, &b) in seed.iter().enumerate() {
            let i = i as u64;
            h1 ^= (b as u64)
                .wrapping_mul(PHI)
                .wrapping_add(h0.rotate_left((i & 63) as u32))
                .wrapping_add(i.wrapping_mul(0x100_0000_01B3));
            h1 = h1.rotate_left(23).wrapping_mul(PHI).wrapping_add(h0);
            h0 = h0.rotate_left(17) ^ h1;
        }
        Self { h0, h1 }
    }

    /// 데이터를 MAC 상태에 흡수 (증분 사용 가능).
    pub fn update(&mut self, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            let i = i as u64;
            self.h1 ^= (b as u64)
                .wrapping_mul(PHI)
                .wrapping_add(self.h0.rotate_left((i & 63) as u32))
                .wrapping_add(i.wrapping_mul(0x9E37_79B9));
            self.h1 = self.h1.rotate_left(17).wrapping_mul(PHI).wrapping_add(self.h0);
            self.h0 = self.h0.rotate_left(31) ^ self.h1;
        }
    }

    /// 최종 64비트 MAC 값.
    pub fn finish(&self) -> u64 {
        self.h0 ^ self.h1.rotate_left(32) ^ self.h0.rotate_left(47)
    }

    /// 한 번에 계산 (data 전체 + seed).
    pub fn mac(seed: &[u8], data: &[u8]) -> u64 {
        let mut m = BtgKeyedMac::new(seed);
        m.update(data);
        m.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_mac_deterministic() {
        let seed = b"deterministic-seed-123456";
        let data = b"BTG protected code region payload";
        assert_eq!(BtgKeyedMac::mac(seed, data), BtgKeyedMac::mac(seed, data));
    }

    #[test]
    fn keyed_mac_differs_without_key() {
        // 같은 데이터를 다른 키로 MAC한 값이 달라야 한다 (키 없이 위조 불가).
        let data = b"same data";
        let a = BtgKeyedMac::mac(b"key-aaa", data);
        let b = BtgKeyedMac::mac(b"key-bbb", data);
        assert_ne!(a, b);
    }

    #[test]
    fn keyed_mac_detects_tamper() {
        // 데이터의 단 1비트/1바이트 변화가 MAC을 바꿔야 한다 (변조 시 실행 거부).
        let seed = b"integrity-seed";
        let data = vec![0x5Au8; 64];
        let base = BtgKeyedMac::mac(seed, &data);
        // 1바이트 변경
        let mut d1 = data.clone();
        d1[37] ^= 0x01;
        assert_ne!(base, BtgKeyedMac::mac(seed, &d1));
        // 길이 변화
        let mut d2 = data.clone();
        d2.push(0x00);
        assert_ne!(base, BtgKeyedMac::mac(seed, &d2));
    }

    #[test]
    fn keyed_mac_sensitivity_to_leading_zero() {
        // 앞쪽 0 패딩도 결과에 반영되어야 한다.
        let seed = b"s";
        let a = BtgKeyedMac::mac(seed, b"\x00hello");
        let b = BtgKeyedMac::mac(seed, b"hello");
        assert_ne!(a, b);
    }
}
