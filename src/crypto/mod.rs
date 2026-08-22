// ==============================================================================
// BTG crypto abstraction (plan.txt 1~6?④퀎)
//
// `provider` ??CryptoProvider / BlockCryptoMeta 異붿긽??怨꾩링 (?꾩옱 援ы쁽泥?RC4).
// ?댄썑 ?④퀎(plan.txt 4~5)?먯꽌 RC4瑜?custom 512-bit cipher濡?援먯껜???? ??
// primitive(state/nonlinear/round/permutation/stream)瑜????몃젅?댄듃??援ы쁽泥대줈
// 異붽??섎㈃ pipeline/遺?몄뒪??VM 履쎌? API留?諛붽씀硫??쒕떎.
//
// `state/key_schedule/nonlinear/round/permutation/stream` ??BTG-C1 而ㅼ뒪?
// ?ㅽ듃由??ъ씠?쇱쓽 **reference(?뺣낯) 援ы쁽** (512-bit ?곹깭, AES/ChaCha ?꾨떂).
// native(遺???ㅽ뀅 ?몄퐫??? VM(諛붿씠?몄퐫?? 踰꾩쟾? ???뺣낯怨?鍮꾪듃 ?숈씪?댁빞 ?섎ŉ,
// 洹??숈튂??3諛⑺뼢 ?⑥쐞 ?뚯뒪?멸? 媛뺤젣?쒕떎.
//
// `mac` ??keyed-MAC (T2-3). 湲곗〈 CRC32?????녿뒗 ?먯긽寃異쒖슜?대씪 怨듦꺽?먭?
// 4諛붿씠?몃? ?④퍡 蹂議고븯硫??고쉶?????덈떎. ?ш린?쒕뒗 ?쒕뱶(????寃고빀??鍮꾩꽑??
// ?대━?몃???MAC???뷀빐 **蹂議????ㅽ뻾 嫄곕?**媛 媛?ν븯?꾨줉 ?쒕떎.
// ==============================================================================

pub mod provider;

// BTG-C1 而ㅼ뒪? ?ъ씠??reference 紐⑤뱢 (plan.txt 5?④퀎).
pub mod key_schedule;
pub mod mac;
pub mod native;
pub mod nonlinear;
pub mod permutation;
pub mod round;
pub mod state;

// T3-1: ChaCha20 (RFC 8439) — reference + boot-stub native crypt blob.
pub mod chacha20;
pub mod chacha20_native;

// T3-1 Phase D: Poly1305 (RFC 8439 §2.5) reference + boot-stub native verify blob.
pub mod poly1305;
pub mod poly1305_native;

/// T3-1 Phase B: 부트 스텁/패커가 공유하는 crypto primitive 모드.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMode {
    /// RC4-256 (레거시 — chained/--vm-oep 폴백).
    Rc4,
    /// BTG-C1 커스텀 512-bit 스트림 사이퍼 (v60+, 기본).
    C1,
    /// ChaCha20 (RFC 8439) — T3-1.
    ChaCha20,
}

pub use mac::BtgKeyedMac;
pub use provider::{
    chain_encrypt, chain_encrypt_with, BlockCryptoMeta, CryptoError, CryptoProvider,
};
pub use state::{BtgCipher, BtgState};

#[cfg(test)]
mod cipher_tests;

#[cfg(test)]
mod chacha20_tests;

// T3-1 Phase D: Poly1305 AEAD tag (RFC 8439 §2.8) differential tests.
#[cfg(test)]
mod poly1305_aead_tests;
