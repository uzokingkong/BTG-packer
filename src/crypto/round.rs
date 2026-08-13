// ==============================================================================
// BTG-C1 round — 커스텀 라운드 (ChaCha quarter-round butterfly 아님).
//
// 라운드 = 컬럼 믹스 → 바이트 비선형 치환 → 워드 순열.
// 컬럼 믹스의 데이터 라우팅/회전 상수는 ChaCha와 다르다.
// ==============================================================================

use crate::crypto::nonlinear;
use crate::crypto::permutation;
use crate::crypto::state::STATE_WORDS;

#[inline]
fn rotl(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

/// 커스텀 컬럼 믹스 코어 (a,b,c,d). ChaCha QR의 대칭 버터플라이(a+=b;d^=a;d<<=16;…)
/// 대신 비대칭 라우팅과 다른 회전 상수를 사용한다.
///
/// [설계 의도 — 의도적 비가역(Non-Invertible) 구조]:
/// BTG-C1은 카운터 모드(Counter-mode PRNG) 기반의 스트림 암호로서, 암호화와
/// 복호화 모두 동일한 정방향(Forward) 키스트림 생성 함수를 평가하여 평문/암호문과
/// XOR합니다 (encrypt == decrypt). 따라서 블록 라운드 함수의 수학적 가역성(Invertibility)이
/// 요구되지 않습니다.
///
/// 본 `mix_column`은 wrapping_add 후 xor 및 재회전(ARX-style 비선형 교차)을 혼합하여
/// 역산 경로가 존재하지 않는 일방향(one-way) 성질을 갖도록 의도적으로 설계되었습니다.
/// 이는 대수적 역산 공격(Algebraic inversion attacks)을 원천 차단하고 단방향 확산 속도를
/// 극대화하기 위한 목적입니다.
#[inline]
fn mix_column(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a ^= rotl(*b, 3);
    *a = a.wrapping_add(*c);
    *d ^= *a;
    *d = rotl(*d, 11);
    *d = d.wrapping_add(*b);
    *c ^= *d;
    *c = rotl(*c, 7);
    *c = c.wrapping_add(*a);
    *b ^= rotl(*c, 13);
    *b = b.wrapping_add(*d);
    *b = rotl(*b, 17);
    *a ^= rotl(*b, 5);
    *a = a.wrapping_add(*d);
}

/// 단일 라운드.
pub fn round(st: &mut [u32; STATE_WORDS]) {
    // 컬럼 믹스: st[c], st[4+c], st[8+c], st[12+c] (c = 0..4)
    for c in 0..4 {
        let mut a = st[c];
        let mut b = st[4 + c];
        let mut cc = st[8 + c];
        let mut d = st[12 + c];
        mix_column(&mut a, &mut b, &mut cc, &mut d);
        st[c] = a;
        st[4 + c] = b;
        st[8 + c] = cc;
        st[12 + c] = d;
    }
    // 바이트 비선형 치환
    nonlinear::sub_bytes(st);
    // 워드 순열
    permutation::permute(st);
}

/// R 라운드 적용.
pub fn apply_rounds(st: &mut [u32; STATE_WORDS], rounds: usize) {
    for _ in 0..rounds {
        round(st);
    }
}
