# 2026-08-19 — T3-1 Phase D: ChaCha20-Poly1305 AEAD 태그 부트 스텁 복호화-전 인증

## 요청
T3-1 Phase D("예정"): Poly1305 AEAD 태그를 부트 스텁에 연결해, chacha 경로가 at-rest
암호문을 **복호화하기 전에** 태그로 인증하게 한다. 태그 불일치 시 fail-safe(ud2), decrypt-and-run 금지.
패커 MAC == 런타임 스텁 MAC이 보장되어야 한다. RC4/C1 경로는 무회귀.

## 구현
### 네이티브 Poly1305 verify blob (`src/crypto/poly1305_native.rs`)
- `emit_poly1305_verify_blob(_state_va)` — RFC 8439 §2.8 AEAD Poly1305를 26-bit limb
  (donna soft backend)로 완전 전개해 계산하는 자립형 셸코드:
  `rcx=region, rdx=len, r8=key(32B), r9=tag(16B)` → `rax=0(매치)/≠0(불일치)`.
- mac_data = `pad16(AAD) || pad16(CT) || le64(len(AAD)) || le64(len(CT))`, AAD = 고정
  도메인 태그 `btg-aead-p1305v1` (16B). rel32 분기 → VA 무관(길이 불변), 3-pass sizing 안정.

### 패커 AEAD surface (`src/crypto/poly1305.rs`)
- `POLY1305_AEAD_AAD` (16B), `poly1305_aead_tag(aad, ct, key)`, `chacha_poly1305_key_from_block0`.

### 부트 스텁 연결 (`src/pipeline/crypto/{bootstub/build.rs,ctx.rs,place.rs}`, `mod.rs`)
- ctx: `chacha_aead / poly_blob_va / poly_key_va / poly_tag_va`.
- build.rs: payload copy 후·code_decrypt 전에 `emit_poly1305_verify` (poly blob 호출 →
  `test rax; jnz → ud2`). chacha_mode && chacha_aead일 때만.
- place.rs: chacha 상태 뒤에 poly blob + 32B one-time 키 + 16B 태그 배치.
- mod.rs(run): chacha 암호화 직후 암호문+AAD로 `poly1305_aead_tag` 계산, place에 전달.

## 디버깅 이력 (AV → 잘못된 태그 → 정상)
1. 테스트 Arena 버퍼가 blob(4003B)과 겹침 → offset 0x10000로 분리.
2. `LEN_OFF` 스토어가 `sub rsp,0x100` 전이라 caller 스택 파괴 → 프레임 할당 후로 이동.
3. **byte-copy 루프의 `movzx/mov [mem],al`이 iced로 인코딩 불가 → nop 폴백** → `with_base_index_scale`
   (rsp+idx+disp 대신 BLK base를 `lea rcx,[rsp+0x60]`로 선계산) 사용.
4. **finish `carry_up`가 `w(H_OFF+src)`(limb 인덱스를 바이트 오프셋으로 오용) → [rsp+1] 가비지** →
   `w(H_OFF+src*4)`로 수정.
5. `emit_mac_add` carry가 32-bit add로 소실 → 64-bit add로 수정.

## 차등/단위 테스트
- RFC 8439 Poly1305 벡터, RustCrypto `compute_unpadded` 차등.
- `poly1305_aead_tag` == RustCrypto `ChaCha20Poly1305::encrypt_in_place_detached` 태그 (AEAD 권위).
- 네이티브 blob == reference AEAD 태그 (len 0..4096), 태그/암호문/잘못된 AAD 변조 거부, VA 길이 불변.
- chacha20+AEAD 부트 스텁 생성·길이 불변 테스트.

## 결과
`cargo build --release` exit 0 · `cargo test --release --lib` **398 passed; 0 failed** (기준 384 → +14).
