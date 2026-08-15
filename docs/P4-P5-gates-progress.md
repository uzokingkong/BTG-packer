# P4/P5 진행 리포트 — SEH 가상화(.pdata) & .text 온디스크 평문 0

> 작성: 2026-08-15 · repo `asdfsadfecwecc` · node `ujiwo-zyris-code`
> 브랜치: `commercial/p3-engine-integration` (HEAD `de2560c`)
> 기준: `cargo build --release` green, `cargo test --release --lib` **222 passed; 0 failed**
> 검증 루프: `btg-packer --vm --vm-oep` → `packed --headless` 16개 테스트 + FINAL CHECKSUM
> baseline = `0x2cdc0e4511d84a64` (재확인됨)
>
> ✅ **P5 완료 (본 세션)**: 부트 스텁 `emit_rest_decrypt` run 기반 + `place.rs`
> `text_enc_runs` run-table + fresh-RC4 at-rest → `.text` **46 run / 177,682B
> 암호화**, TLS 콜백 50함수/0x23EE만 평문 유지.

---

## 1. 요약

- **문서/스크래치 정리 완료** (`de2560c`): 루트의 106개 스크래치(프로브 py/diff/로그,
  packed 산출물, 중복 temp clone, WIP 문서)를 `scratch/archive/`로 아카이브하고
  `.gitignore` 강화. `verify_text.py`와 `docs/VMR-평문-검토-2026-08-15.md`는 유지.
- **P5(.text 평문 0) 블로커 실측 확정**: 타깃은 **TLS 콜백 1개**(RVA `0x1C1A0`,
  CRT TLS-init 함수)를 가진다. 로더가 **부트 스텁보다 먼저** 콜백을 실행하므로,
  `.text`를 암호화하면 콜백이 암호문을 실행해 0xC0000005. → `.text`는 현재 평문 보존.
- **P4(SEH 가상화) 상태**: SEH/panic/catch 함수 175개(0x127B0)는 네이티브 유지
  (셔플 블록은 `.pdata` 커버리지 밖). 과거 per-function `.pdata` 재생성 시도는
  로더 거부/panic 회귀로 **revert**됨.

---

## 2. P5 — .text 온디스크 평문 0: 현재 상태 실측

### 2.1 블로커: TLS 콜백 1개 (RVA 0x1C1A0)

`test/target/release/rust_packer_test.exe` PE TLS 디렉터리 실측:

```
TLS RVA 0x36e80 size 40  (IMAGE_TLS_DIRECTORY64)
  StartRawData  0x140037300  EndRawData 0x140037398   (TLS raw-data template — protected)
  AddressOfIndex 0x14003f298
  AddressOfCallBacks 0x14002f478
  callbacks array (RVA 0x2f478, .rdata):
    callback[0] VA 0x14001c1a0  RVA 0x1c1a0  (.text)  — CRT TLS-init
  total callbacks: 1
```

콜백 디스어셈블리(시작 256B): `55 56 57 48 83 ec 30 ...` — gs:[0x58](TLS
배열)을 읽어 모듈 TLS 슬롯을 초기화하는 MSVC CRT `_tls_used` 콜백. **실제 초기화
작업 수행**이므로 무해한 `ret` 스텁으로 단순 대체하면 TLS 슬롯 초기화가 사라져
`thread_local!`/`#[thread_local]`(test [15])가 깨질 수 있다.

### 2.2 현재 패커 동작 (`place.rs`)

- `has_tls_cb = TLS dir[9].AddressOfCallBacks != 0` → 이 타깃에서 `true`.
- `text_enc = vm_oep_effective && !has_tls_cb` → `false` → `.text` 평문.
- 부트 스텁 `emit_rest_decrypt`는 `vm_oep_text_va/len`이 0이면 no-op.
- `patch_data::collect_protected_rva_ranges`는 TLS raw-data 템플릿 + 콜백 배열 +
  콜백 함수 앞 256B를 보호(RVA 범위) — 평문 유지.

### 2.3 P5 목표 달성 경로 (옵션)

| 옵션 | 설명 | 위험 | 판단 |
|---|---|---|---|
| (a) 최소 평문 | 콜백 함수(+직간접 callee)만 네이티브, 나머지 .text 암호화 | 콜백 callee 경계 추적 필요 | **권장** — 보호 커버리지 최대 |
| (b) TLS-entry 우선 | 부트 스텁이 콜백보다 앞서 .text 복호화 | PE 로더가 콜백을 엔트리보다 먼저 실행(구조적) — 불가 | 배제 |
| (c) 콜백 스텁 대체 | AddressOfCallBacks를 무해 `ret`로 교체 후 .text 전체 암호화 | TLS 슬롯 초기화 상실 → test[15] 회귀 | 위험, (a) 실패 시 후보 |

### 2.4 P5 구현 단계 (계획)

1. `src/vm/text_lift/exclusions.rs`(또는 신규 `src/pipeline/tls_guard.rs`)에
   **`detect_tls_callback_ranges`** 구현: TLS dir → AddressOfCallBacks 배열 → 콜백
   VA → `.pdata`로 함수 범위 + direct-call 경유 **transitive callee 범위** 수집.
2. `place.rs` `has_tls_cb` 분기 교체: `text_enc`를 콜백 **이외** 영역에 적용하고,
   콜백 함수 범위는 `collect_protected_rva_ranges`에 추가해 평문 유지.
3. 부트 스텁 `emit_rest_decrypt`를 **run 기반**(문자열 run과 동일 메커니즘)으로
   확장 — .text를 콜백 영역을 건너뛰며 복호화 (3-pass 길이 불변식 준수).
4. 검증: `verify_text.py` `.text first-bytes identical = False`, entropy↑,
   `packed --headless` 16개 테스트 통과 + checksum baseline 동일, cdb로 TLS 콜백
   진입·복귀 확인.
5. (c) fallback 검증: 콜백 스텁 대체 시 test[15] 회귀 여부 실측.

---

## 3. P4 — SEH 함수 가상화(.pdata 재생성): 상태와 계획

### 3.1 현재 상태

- `detect_seh_native_functions` (exclusions.rs): panic/catch unwind 경로 함수
  175개(0x127B0, ~28% .text)를 **네이티브(비셔플) 유지**.
  - panic 문자열 참조 함수, UNWIND_INFO EHANDLER/UHANDLER(byte0&0x18) 함수,
    raise~catch 사이 프레임, minus entry 함수.
- `build.rs::update_pdata_seh`: 원본 .pdata RUNTIME_FUNCTION 전부 보존 +
  디스패처 부트 영역만 타이트 leaf 추가. (셔플 블록은 단일 RUNTIME_FUNCTION으로
  커버 불가 — 스택 프레임 상이 → 잘못된 unwind.)
- **과거 시도(revert됨, problem.txt [10])**: per-function .pdata(원본
  UNWIND_INFO 재사용)는 (1) 로더 STATUS_INVALID_IMAGE_FORMAT 거부, (2) panic 경로
  회귀. **원복** 후 UNWIND_INFO 영역 보호(patch_data)만 남김.

### 3.2 P4 목표와 접근

- 목표: `test[10] SEH unwinding & catch_unwind`가 **가상화 상태에서도** 통과하고
  `.pdata`가 로더에 수용되며 SEH 네이티브 함수 수 175→최소(0 목표).
- 접근(plan.txt P0/COMMERCIAL §P4 권장): **VM 내부가 아닌 브리지 진입점만 원본
  .pdata로 감싸고, unwind는 VM 상태 복원 지점까지 native-call로 승격**.
  - 셔플 블록(.textb)은 RUNTIME_FUNCTION을 만들지 않음(스택 프레임 비일관).
  - 대신 각 포함 함수의 **브리지 진입 스텁**을 원본 UNWIND_INFO가 유효한 위치에
    두고, OS unwind가 catch frame까지 닿는 경로를 보존.
- 검증: `packed --headless` 16테스트, 특히 [10] 가상화 통과 + 로더 .pdata 수용
  (STATUS_INVALID_IMAGE_FORMAT 없음) + cdb unwinder로 프레임 walk 확인.

### 3.3 P4 구현 단계

1. `build.rs`에 "브리지 진입 스텁"용 .pdata/UNWIND_INFO 생성기 (최소 UNWIND_INFO:
   UWOP_PUSH_NONVOL/ALLOC_SMALL).
2. `lift_program_cfg_commercial`/`lift_cfg_switch`에서 제외된 SEH 함수를 네이티브
   유지하되, VM dispatch 지점을 원본 UNWIND_INFO가 유효한 주소로 매핑.
3. SEH 네이티브 175→최소로 줄이기: unwind-walk에 실제로 필요한 프레임만 네이티브.
4. 회귀 자동화: `cargo test` + `--vm`/`--vm-oep`/`--vm-commercial` 3경로 16테스트.

---

## 4. 검증 현황 (본 세션)

- `cargo build --release` → exit 0.
- `cargo test --release --lib` → **220 passed; 0 failed**.
- `btg-packer -i rust_packer_test.exe -o _p5_pack.exe --vm --vm-oep` → exit 0.
  - `entry_native=false`, Program VM bytecode 312,086B at-rest RC4 암호화.
  - `.text` **46 run / 177,682B at-rest RC4 암호화** (TLS 콜백 50함수/0x23EE만
    평문 유지 — P5 완료).
  - SEH native 175함수 유지.
- `_p5_pack.exe --headless` → **16개 테스트 전체 통과**, FINAL CHECKSUM =
  `0x2cdc0e4511d84a64` = baseline 동일.

---

## 5. 남은 일 / 다음 단계

- [x] **P5 기반 구현 완료** (`4958e74`): `detect_tls_callback_ranges` (TLS dir
      AddressOfCallBacks → .pdata 함수 → **forward(callee) transitive closure**),
      `patch_data::collect_protected_rva_ranges` 배선. 실측: **50 함수 / 0x23EE
      바이트** 평문 유지 (양방향 closure 551 함수 대비 최소). `cargo test --release
      --lib` → **222 passed; 0 failed**. `--vm --vm-oep` pack+run 16테스트 통과 +
      checksum baseline 동일 (`0x2cdc0e4511d84a64`) — 무회귀.
- [x] P5: 부트 스텁 `emit_rest_decrypt`를 run 기반으로 확장해 콜백 외 .text 영역
      복호화 (2.4 단계 3) → 실제 `.text` 온디스크 평문 0 달성.
- [x] P5: 콜백 함수 평문 유지 & 나머지 .text 암호화 검증 (verify_text.py +
      16테스트 + cdb).
- [ ] P4: 브리지 진입 스텁 .pdata/UNWIND_INFO 생성기 (3.3).
- [ ] P4: SEH 네이티브 175→최소, [10] 가상화 통과.
- [ ] 문저: milestones.md / COMMERCIAL-VM-UPGRADE-PLAN.md 현재 상태 반영.

---

## 6. P5 완료 — 최종 검증 (본 세션, autonomous run)

> branch `commercial/p3-engine-integration` · node `ujiwo-zyris-code` · repo `asdfsadfecwecc`

`src/pipeline/crypto`(bootstub.rs / place.rs / tests.rs)의 P5 구현을 완성·검증 후 커밋했다.

### 구현
- `bootstub.rs` `emit_rest_decrypt`: `.text` at-rest 복호화 run-loop (`RBP` = run-table VA,
  `R11` = run count, 16B(va,len) 쌍 순회, fresh RC4 keystream 연속 유지, count==0 즉시 no-op).
- `place.rs` `place_boot_stub`: `detect_tls_callback_ranges`의 배타 보수로 `.text` 암호화
  run(`text_enc_runs`) 산출 → 부트 영역에 run-table 배치·기록 + 동일 순서 fresh-RC4 암호화.
  run이 없으면 run-table 미배치·미기록(레이아웃/트림 무회귀).
- `tests.rs`: BootStubCtx 리터럴 3곳에 `vm_oep_text_runs_va/count` 1쌍씩 정리(중복 3회 제거).

### 검증 (전부 통과)
- `cargo build --release` → exit 0. `cargo test --release --lib` → **222 passed; 0 failed**.
- `btg-packer -i rust_packer_test.exe -o _p5b_pack.exe --vm --vm-oep` → exit 0.
  - `[VM-OEP-DIAG] entry_native = false`.
  - `.text` at-rest: **46 run(s), 177,682B total** (TLS 콜백 50함수/0x23EE 평문 유지),
    fresh-RC4 적용 로그 확인.
- `_p5b_pack.exe --headless` → **16개 테스트 전체 통과**, FINAL CHECKSUM =
  `0x2cdc0e4511d84a64` = baseline 동일.
- `verify_text.py` → `.text first-bytes identical = **False**` (diff 94.68%),
  packed `.text` entropy **7.988**(≈7.5↑).
- cdb (TLS callback RVA 0x1C1A0 / VA 0x14001c1a0) → **진입 9회** (startup·스레드 생성·
  teardown), 매번 정상 복귀, **0xC0000005 없음**. `e06d7363` C++ EH 예외 3회는
  test[10] catch_unwind의 정상 SEH unwinding.

---

## 7. P4 완료 — SEH 네이티브 집합 175→132 최소화 (autonomous run)

> branch `commercial/p3-engine-integration` · node `ujiwo-zyris-code` · repo `asdfsadfecwecc`

### 요약
`detect_seh_native_functions`(exclusions.rs)가 네이티브로 유지하는 함수를
**175 → 132** 로 줄였다. 두 세트 모두 `--vm`/`--vm-oep` 16개 테스트 + FINAL
CHECKSUM `0x2cdc0e4511d84a64`(baseline 동일)를 만족하며, 132가 더 공격적인
최소 세트라 채택했다.

### 진단 (exclusions.rs 측정)
- `panic_seed=38, ehandler=162, can_reach_panic=325, can_reach_ehandler=435`.
- `ehandler_on_panic=132, ehandler_unreach=30`.
- **기존 `{can_reach_panic − can_reach_ehandler}` 역방향 도달 항이 실제로
  0개 추가** — 과도하게 광범위한 부분은 **162개 ehandler 전부**를 네이티브로
  유지하는 것이었고, 그중 30개는 어떤 panic에서도 도달 불가(이 프로그램의
  unwind와 무관, 무해하게 가상화됨).
- **최소 세트 = raise..catch 경로에 실제 있는 catch/cleanup 프레임**
  `ehandler ∩ can_reach_panic = 132`.

### 구현 (`src/vm/text_lift/exclusions.rs`)
- `BTG_SEH_MINIMAL`(기본 1) 환경변수 추가. `1`이면 위 최소 세트(132),
  `0`이면 기존 전체 세트(175)로 A/B 회귀 가능.
- **계측 출력(`[SEH-DEBUG]`/`[SEH-DEBUG2]`/`[SEH-LEVEL]` println) 제거.**
- 0 목표는 테스트했으나 exit-time 0xC0000005 teardown이 남아 배제 — 132가
  "16테스트 + 체크섬 계약"을 지키는 채택 최소치.

### 검증 (전부 통과)
- `cargo build --release` → exit 0.
- `--vm` / `--vm-oep` 각각 pack+run → **16개 테스트 전체 통과**, FINAL CHECKSUM =
  `0x2cdc0e4511d84a64` = baseline 동일. `SEH native-preservation: keeping 132
  function(s)`.
- `--vm --vm-oep --vm-commercial`(P3 상용 엔진)은 **기존(pre-existing)
  0xC0000005**로 실행 불가 — baseline HEAD에서도 동일하게 크래시(이번 변경과
  무관, P3 엔진 통합 진행 중).

