// ==============================================================================
// BTG-C1 custom stream cipher — 512-bit state (plan.txt 5단계)
//
// 독자적인 state/round/permutation/key schedule. AES round도 ChaCha
// quarter-round도 그대로 쓰지 않는다:
//   - state: 16 × u32 (512-bit)
//   - key schedule: 256-bit key + 64-bit counter + 32-bit nonce + 도메인 상수
//   - nonlinear: 커스텀 256B S-box (nonlinear.rs — GF(2^8) 곱셈역 + 아핀, AES
//     모듈러스/아핀 아님)
//   - round: 커스텀 컬럼 믹스 (라우팅/회전이 ChaCha butterfly와 다름)
//   - permutation: 커스텀 워드 단순치환 (σ(i)=(5i+3) mod 16)
//   - stream: 카운터 모드 키스트림, in-place XOR (encrypt == decrypt)
//
// 이 파일의 구현이 단일 정본(reference)이다. native(부트 스텁 셸코드)와 VM
// (바이트코드) 버전은 반드시 이 정본과 비트 동일해야 한다 (3방향 테스트).
// ==============================================================================

use crate::crypto::key_schedule;
use crate::crypto::nonlinear;
use crate::crypto::permutation;
use crate::crypto::round;

/// 상태 크기 (16 × u32 = 512-bit).
pub const STATE_WORDS: usize = 16;
/// 라운드 수 (확산을 위한 고정 상수).
pub const ROUNDS: usize = 16;

/// BTG-C1 512-bit 상태.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtgState(pub [u32; STATE_WORDS]);

impl BtgState {
    /// (key, counter, nonce) → 초기 상태 흡수 후 라운드+피드포워드.
    /// counter는 64B 키스트림 블록 카운터 (0,1,2,…) — native/VM과 정본 동일.
    pub fn absorb(key: &[u8; 32], counter: u64, nonce: u32) -> Self {
        let init = key_schedule::initial_state(key, counter, nonce);
        let mut st = init;
        round::apply_rounds(&mut st, ROUNDS);
        // feed-forward: 최종 상태 = 라운드 결과 + 초기 상태 (wrapping_add)
        for i in 0..STATE_WORDS {
            st[i] = st[i].wrapping_add(init[i]);
        }
        BtgState(st)
    }

    /// 상태를 64바이트 키스트림으로 출력.
    pub fn to_keystream_bytes(&self) -> [u8; STATE_WORDS * 4] {
        let mut out = [0u8; STATE_WORDS * 4];
        for (i, w) in self.0.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// 키스트림 생성기 (counter 모드). RC4와 동일하게 `crypt`는 in-place XOR이다.
pub struct BtgCipher {
    key: [u8; 32],
    nonce: u32,
    ctr: u64,
    /// 현재 키스트림 블록(64B)과 그 안의 오프셋.
    ks: [u8; STATE_WORDS * 4],
    ks_off: usize,
}

impl BtgCipher {
    pub fn new(key: &[u8], nonce: u32) -> Self {
        let mut key32 = [0u8; 32];
        let n = key.len().min(32);
        key32[..n].copy_from_slice(&key[..n]);
        if key.len() > 32 {
            // 32바이트를 넘는 키는 다시 섞어 32바이트로 압축 (도메인별).
            for (i, &b) in key[32..].iter().enumerate() {
                key32[(i + 1) % 32] = key32[(i + 1) % 32].wrapping_add(b ^ (i as u8));
            }
        }
        BtgCipher {
            key: key32,
            nonce,
            ctr: 0,
            ks: [0u8; STATE_WORDS * 4],
            ks_off: STATE_WORDS * 4, // 첫 사용 시 새 블록 생성
        }
    }

    fn refill(&mut self) {
        let st = BtgState::absorb(&self.key, self.ctr, self.nonce);
        self.ks = st.to_keystream_bytes();
        self.ks_off = 0;
        self.ctr = self.ctr.wrapping_add(1);
    }

    /// RC4.crypt와 동일 시그니처: in-place XOR 키스트림.
    pub fn crypt(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            if self.ks_off >= self.ks.len() {
                self.refill();
            }
            *byte ^= self.ks[self.ks_off];
            self.ks_off += 1;
        }
    }

    /// 저수준 변환 단위를 외부(native/VM)와 비교하기 위한 공개 인터페이스.
    /// (3방향 동치 테스트에서 사용.)
    pub fn round_words(words: &mut [u32; STATE_WORDS]) {
        round::apply_rounds(words, ROUNDS);
    }

    /// S-box 테이블 (256B) — native 셸코드와 VM 바이트코드에 그대로 삽입된다.
    pub fn sbox_table() -> [u8; 256] {
        nonlinear::sbox()
    }

    /// 워드 순열 — native/VM과 동일 정본.
    pub fn word_permutation() -> [usize; STATE_WORDS] {
        permutation::PERM
    }
}
