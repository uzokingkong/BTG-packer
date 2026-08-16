// ==============================================================================
// BTG-C1 nonlinear — 커스텀 256B S-box (AES S-box 아님).
//
// GF(2^8) 곱셈역(커스텀 비-AES 모듈러스 0x11D) 위에 커스텀 아핀을 얹는다.
// 아핀 회전 계수는 {3,5,7} + 상수 0x9A (AES의 {1,2,3,4}+0x63과 다름).
// S-box는 전단사(bijection)이어야 하며 그 사실은 단위 테스트가 강제한다.
// ==============================================================================

/// 커스텀 비-AES 기약 다항식 (x^8 + x^4 + x^3 + x^2 + 1).
const POLY: u32 = 0x11D;
/// 커스텀 아핀 상수 (AES의 0x63과 다름).
const AFFINE_C: u8 = 0x9A;

/// GF(2^8) 곱 (russian peasant, mod POLY).
fn gf_mul(mut a: u32, mut b: u32) -> u8 {
    let mut r: u32 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            r ^= a;
        }
        b >>= 1;
        let carry = a & 0x80 != 0;
        a = (a << 1) & 0xFF;
        if carry {
            a ^= POLY & 0xFF; // POLY - 0x100 (x^8 자리 제거)
        }
    }
    r as u8
}

/// GF(2^8) 곱셈역 (brute-force — 테이블 1회 생성이라 충분히 빠름).
fn gf_inv(x: u8) -> u8 {
    if x == 0 {
        return 0;
    }
    for y in 1..=255u8 {
        if gf_mul(x as u32, y as u32) == 1 {
            return y;
        }
    }
    0 // 기약 다항식이면 도달 불가
}

/// 8비트 좌회전.
#[inline]
fn rotl8(x: u8, n: u32) -> u8 {
    x.rotate_left(n)
}

/// 커스텀 256B S-box (1회 생성 후 캐시).
///
/// 리뷰 지적 #19: 매 호출마다 GF(2^8) 곱셈역을 전탐색(256×~128 gf_mul)하던 것을
/// `OnceLock` 으로 캐시한다. S-box 는 결정적(상수 POLY/AFFINE_C)이므로 첫 호출
/// 이후 결과는 불변이다. 공개 반환형은 그대로 `[u8; 256]`(사본)이라 기존 호출부
/// (native/VM 삽입 테이블)와 호환된다.
///
/// 아핀은 **홀수 개**의 항(identity + 회전 2개)을 쓴다 — 항 수가 짝수면
/// x=1에서 다항식이 0이 되어 x^8+1과 공약수(x+1)를 갖고 비가역이 된다.
/// (AES 아핀은 {1,2,3,4} 4개 회전 + 0x63이지만 GF역이 비선형성을 제공해
///  여전히 가역 — 여기서는 3항 아핀으로 전단사를 보장한다.)
pub fn sbox() -> [u8; 256] {
    use std::sync::OnceLock;
    static SBOX: OnceLock<[u8; 256]> = OnceLock::new();
    *SBOX.get_or_init(build_sbox)
}

fn build_sbox() -> [u8; 256] {
    let mut t = [0u8; 256];
    for x in 0..256u32 {
        let inv = gf_inv(x as u8);
        let s = inv ^ rotl8(inv, 2) ^ rotl8(inv, 5) ^ AFFINE_C;
        t[x as usize] = s;
    }
    t
}

/// 상태의 각 바이트에 S-box 적용 (비선형 치환).
pub fn sub_bytes(words: &mut [u32; crate::crypto::state::STATE_WORDS]) {
    let sb = sbox();
    for w in words.iter_mut() {
        let b = w.to_le_bytes();
        *w = u32::from_le_bytes([sb[b[0] as usize], sb[b[1] as usize], sb[b[2] as usize], sb[b[3] as usize]]);
    }
}
