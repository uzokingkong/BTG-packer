// ==============================================================================
// BTG-C1 permutation — 커스텀 워드 단순치환 (ChaCha 행/열 시프트 아님).
//
// σ(i) = 4비트 인덱스 비트역전(bit-reversal). 전단사이고, 한 컬럼(같은 하위
// 2비트)의 워드들을 **서로 다른 컬럼**으로 흩어 확산이 컬럼을 가로지른다.
// (이전 σ(i)=(5i+3)%16은 컬럼 k → 컬럼 (k+1)%4 매핑이라 diff가 한 컬럼에
//  갇혀 확산이 14%에 머물렀다 — debug_avalanche_per_round로 확인 후 교체.)
// ==============================================================================

use crate::crypto::state::STATE_WORDS;

/// 순열 테이블: new[i] = old[PERM[i]].
pub const PERM: [usize; STATE_WORDS] = compute_perm();

const fn compute_perm() -> [usize; STATE_WORDS] {
    let mut p = [0usize; STATE_WORDS];
    let mut i = 0;
    while i < STATE_WORDS {
        // 4비트 비트역전: bit3→bit0, bit2→bit1, bit1→bit2, bit0→bit3
        let b = i as u32;
        let rev = ((b & 1) << 3) | ((b & 2) << 1) | ((b & 4) >> 1) | ((b & 8) >> 3);
        p[i] = rev as usize;
        i += 1;
    }
    p
}

/// 상태 워드에 순열 적용.
pub fn permute(words: &mut [u32; STATE_WORDS]) {
    let old = *words;
    for i in 0..STATE_WORDS {
        words[i] = old[PERM[i]];
    }
}
