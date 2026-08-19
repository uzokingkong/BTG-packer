# BTG Packer — W^X 메모리 계약 설계서 (readccc §4.4)

> 기준: 2026-08-19 · repo `asdfsadfecwecc` (btg-packer)
> 근거: `readccc.md` §4.4 (W^X/ASLR 보호 옵션 충돌), §7 Phase 0 (W^X architectural plan)
> 상태: ⬜ 미착수 · 🔶 진행 중 · ✅ 완료

---

## 1. 현재 메모리 권한 모델 (실측)

| 영역 | 섹션 | 파일 특성 | 런타임 | 쓰기 | 실행 |
|---|---|---|---|---|---|
| 부트 스텁 + CFG 블록 + 디스패처 | `.textb` | `0xE0000020` (CODE\|EXECUTE\|READ\|WRITE) | **RWX** | ✅ | ✅ |
| 암호화 코드 페이로드 (at-rest) | `.vdata` (--payload-relocate) | `0x40000040` (INITIALIZED_DATA\|READ) | **R** | ❌ | ❌ |
| 문자열/리졸브 테이블 (복호화 후) | 원본 섹션 | WRITE 추가 | **RW** | ✅ | ❌ |
| Program VM 상태/바이트코드 | `.textb` boot area | `.textb` 특성 상속 | **RWX** | ✅ | ✅ |

**핵심 문제:** 부트 스텁의 in-place 복호화 때문에 `.textb`가 파일에서 RWX로 매핑되고,
`--mem-harden`이 켜지지 않으면 **지속 RWX**가 유지된다. (readccc §4.4 표 1행·2행)

---

## 2. 원칙

1. **decrypt → verify → execute** 라이프사이클을 region 단위로 고정한다.
   - 부트 스텁: `KSA/init → 복호화 → CRC/MAC 검증 → (RX 전환) → 디스패치`
   - 전환 전에는 코드가 실행되지 않고, 전환 후에는 쓰기가 불가능해야 한다.
2. **code / data / state를 서로 다른 page group으로 분리**한다.
   - 코드·핸들러 테이블·바이트코드 = RX 페이지
   - 시드·S-box·런 테이블·VM 상태·복호화된 문자열 = RW 페이지 (비실행)
3. **옵션 상충을 silent suppression으로 끝내지 않는다.** capability manifest와
   validate가 effective memory contract를 출력·검증한다. (✅ 구현)

---

## 3. 프로파일별 메모리 계약 (capability manifest `wx_contract`)

| 프로파일 | 조합 | `wx_contract` | 실행 중 최종 권한 |
|---|---|---|---|
| Compatibility | crypto만 (mem-harden 꺼짐) | `rwx-at-rest` | `.textb` RWX 유지 |
| Balanced | + `--mem-harden` | `rwx-at-rest,rx-after-verify` | `.textb` → **RX** (복호화+검증 후) |
| Sensitive | + `--mem-harden` + `--payload-relocate` | `rwx-at-rest,rx-after-verify,code-data-split` | 암호문은 `.vdata`(R), 실행 영역은 **RX** |
| Diagnostic | + `--anti-debug-policy warn` | `rwx-at-rest,diagnostic` | 검사는 위험 신호로만 동작 |

- `rx-after-verify` = `memharden::emit_mem_harden`의 `NtProtectVirtualMemory(PAGE_EXECUTE_READ)`.
- `code-data-split` = `--payload-relocate`로 암호화 페이로드가 비실행 `.vdata`에 보관.
- ASLR과의 상충: at-rest 암호화가 켜지면 `.reloc` 재배치가 암호문을 파괴하므로
  `aslr_preserved=false`를 manifest에 기록 (✅ 구현).

---

## 4. 구현 상태

### ✅ 4.1 capability manifest (`src/manifest.rs`, `src/main.rs`)
- `wx_contract` 필드: `rwx-at-rest` / `rx-after-verify` / `code-data-split` /
  `at-rest-ciphertext` 조합을 빌드 산출물에 기록.
- `anti_debug_policy` 필드: graceful failure 정책 기록 (readccc §4.5).

### ✅ 4.2 validate 게이트 (`src/pipeline/validate.rs`)
- crypto 활성 시 `.textb` WRITE 필수 (in-place 복호화 전제) + W^X 계약 로그.
- mem_harden 유효 여부를 파싱된 PE와 함께 출력.

### 🔶 4.3 부트 스텁 RX 전환 (`src/pipeline/crypto/memharden.rs`)
- `--mem-harden`: 복호화+검증 후 `NtProtectVirtualMemory(PAGE_EXECUTE_READ)`.
- S3: fail-open 제거됨 — NTSTATUS != 0이면 명시적 거부.
- 제약: `--dispatcher-reencrypt` / `--vm-oep`와 배타 (resolve가 경고+비활성).
  → reencrypt/vm-oep 프로파일은 `rwx-at-rest` 유지 (런타임 쓰기 필요).

### ⬜ 4.4 다음 단계 (후속)
- `.textb` 내부를 `[코드+핸들러테이블]` / `[시드·런테이블·VM상태]` 영역으로 분리해
  데이터 영역을 별도 RW 섹션으로 분리 (현재는 같은 섹션에 공존).
- `--payload-relocate`와 결합 시 `.textb`를 파일에서 RX로 만들고 암호문만 `.vdata`에
  두는 완전한 W^X 프로파일.
- native test arena / QA 코퍼스의 RWX 사용을 release gate에서 검증.

---

## 5. 검증

- `cargo build --release` green · `cargo test --release --lib` green
- `--full --mem-harden` pack→run 16-test + FINAL CHECKSUM `0x2cdc0e4511d84a64` 무회귀
- manifest에 `wx_contract` / `anti_debug_policy` 기록 확인.