// ==============================================================================
// BTG crypto abstraction (plan.txt 1~6단계)
//
// `provider` — CryptoProvider / BlockCryptoMeta 추상화 계층 (현재 구현체 RC4).
// 이후 단계(plan.txt 4~5)에서 RC4를 custom 512-bit cipher로 교체할 때, 새
// primitive(state/nonlinear/round/permutation/stream)를 이 트레이트의 구현체로
// 추가하면 pipeline/부트스텁/VM 쪽은 API만 바꾸면 된다.
// ==============================================================================

pub mod provider;

pub use provider::{chain_encrypt, BlockCryptoMeta, CryptoError, CryptoProvider};
