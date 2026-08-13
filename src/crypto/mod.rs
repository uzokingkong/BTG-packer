// ==============================================================================
// BTG crypto abstraction (plan.txt 1~6단계)
//
// `provider` — CryptoProvider / BlockCryptoMeta 추상화 계층 (현재 구현체 RC4).
// 이후 단계(plan.txt 4~5)에서 RC4를 custom 512-bit cipher로 교체할 때, 새
// primitive(state/nonlinear/round/permutation/stream)를 이 트레이트의 구현체로
// 추가하면 pipeline/부트스텁/VM 쪽은 API만 바꾸면 된다.
//
// `state/key_schedule/nonlinear/round/permutation/stream` — BTG-C1 커스텀
// 스트림 사이퍼의 **reference(정본) 구현** (512-bit 상태, AES/ChaCha 아님).
// native(부트 스텁 셸코드)와 VM(바이트코드) 버전은 이 정본과 비트 동일해야 하며,
// 그 동치는 3방향 단위 테스트가 강제한다.
// ==============================================================================

pub mod provider;

// BTG-C1 커스텀 사이퍼 reference 모듈 (plan.txt 5단계).
pub mod key_schedule;
pub mod nonlinear;
pub mod permutation;
pub mod round;
pub mod state;

pub use provider::{chain_encrypt, BlockCryptoMeta, CryptoError, CryptoProvider};
pub use state::{BtgCipher, BtgState};

#[cfg(test)]
mod cipher_tests;
