// ==============================================================================
// BTG-C1 key schedule — (key, counter, nonce, block_index) → 초기 상태.
// ==============================================================================

use crate::crypto::state::STATE_WORDS;

/// 커스텀 도메인 상수 (알려진 상수와 구분; 4개는 murmur3 finalizer 계열).
/// ChaCha의 "expand 32-byte k" (0x61707865…) 나 BLAKE2의 pi 상수를 쓰지 않는다.
const C0: u32 = 0xA5A5_5A5A ^ 0x1B87_3593; // 사용자 정의 마법 상수
const C1: u32 = 0x3C6E_F372 ^ 0x85EB_CA6B;
const C2: u32 = 0x9E37_79B9 ^ 0xC2B2_AE35;
const C3: u32 = 0x27D4_EB2F ^ 0xE654_6B64;

/// 초기 상태 레이아웃 (ChaCha와 다른 배치):
///   [0..4]   도메인 상수 C0..C3
///   [4..12]  key 8 워드
///   [12]     counter_lo
///   [13]     counter_hi
///   [14]     nonce
///   [15]     domain = "BTGC" 블록 구분자 XOR block_index
pub fn initial_state(key: &[u8; 32], counter: u64, nonce: u32, block_index: u32) -> [u32; STATE_WORDS] {
    let mut st = [0u32; STATE_WORDS];
    st[0] = C0;
    st[1] = C1;
    st[2] = C2;
    st[3] = C3;
    for i in 0..8 {
        st[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    st[12] = counter as u32;
    st[13] = (counter >> 32) as u32;
    st[14] = nonce;
    st[15] = u32::from_le_bytes(*b"BTGC") ^ block_index;
    st
}
