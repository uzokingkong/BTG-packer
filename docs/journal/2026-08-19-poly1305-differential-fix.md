# 2026-08-19 — Poly1305 differential test fix (T3-1 Phase D)

## 요청
`cargo test --release --lib poly1305` 에서 `poly1305_differential_vs_rustcrypto` 실패
(`src/crypto/poly1305.rs:285`, len=1에서 `Poly1305 mismatch vs RustCrypto`).

## 원인 분석 (root cause)
구현 `poly1305_mac`/`poly1305_blocks`는 **RFC 8439 §2.5.1 standalone Poly1305 MAC**이며
RustCrypto `poly1305` crate 의 `compute_unpadded` 와 **완전히 일치** — RFC 8439 테스트 벡터와도 일치.

문제는 **차등 테스트가 잘못된 기준 API**를 쓴 것:

- 테스트가 사용한 `update_padded` 는 **AEAD universal-hash 모드**(tail을 zero-pad, hibit=1<<24, 0x01 종료 바이트 없음)이다.
  ChaCha20Poly1305 의 AAD/ciphertext padding 용. standalone MAC 이 아니다.
- standalone Poly1305 MAC (RFC 8439)은 **0x01 종료 바이트 + hibit=0** 을 쓴다.

실측(scratch test) 결과 — RFC 8439 메시지(33B)에 대해:
- RFC 기대값        : `a8061dc1305136c6c22b8baf0c0127a9`
- `update_padded`   : `c88886f51af32a75f0fdf57c4a7defdd` (불일치)
- `compute_unpadded`: `a8061dc1305136c6c22b8baf0c0127a9` (일치)

→ 구현을 `update_padded` 기준으로 바꾸면 **RFC 테스트 벡터가 깨진다**. 구현이 이미 RFC/`compute_unpadded`와
일치하므로 구현은 옳고, **테스트의 기준 참조를 올바른 standalone MAC(`compute_unpadded`)로 교정**하는 것이 정답.

## 변경 사항
`src/crypto/poly1305.rs` — `tests::poly1305_differential_vs_rustcrypto` 만 수정 (구현 코드 무변경):
- `use poly1305::universal_hash::{KeyInit, UniversalHash};` → `use poly1305::universal_hash::KeyInit;`
- `rc.update_padded(&msg); let rc_tag = rc.finalize()...;`
  → `let rc_tag = rc.compute_unpadded(&msg).as_slice().to_vec();`

## 결과
```
running 3 tests
test crypto::poly1305::tests::poly1305_chunked_matches_single ... ok
test crypto::poly1305::tests::poly1305_rfc8439_test_vector ... ok
test crypto::poly1305::tests::poly1305_differential_vs_rustcrypto ... ok
test result: ok. 3 passed; 0 failed
```
