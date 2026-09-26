# BTG 상용 VM 전환 심화 계획서

작성 기준일: 2026-09-05
대상 저장소: `C:\Users\uzoki\Desktop\asdfsadfecwecc`
분석 범위: `src/**/*.rs` 295개 파일, 약 124,655 LOC, 테스트/기존 산출물/증거 CSV 포함

## 0. 실행 현황

| 작업 | 상태 | 변경/검증 |
|---|---|---|
| 기준선 측정 | 완료 | 2026-09-05 `cargo test --lib`: 765 통과, 7 실패 |
| P0 route fail-closed 복구 | 완료 | missing entry VIP를 build error로 변경; 집중 회귀 1/1 통과 |
| P0 bridge stack ABI | 완료 | guest RSP 전환 canonical MOV encoding 복구; 집중 회귀 1/1 통과 |
| P0 lifetime cleanup | 완료 | count 슬롯을 독립 ABI 주소에서 로드하도록 수정; native 집중 회귀 1/1 통과 |
| P0 payload relocation | 완료 | native/Program-VM 목적 범위 검증 분리; 대표 deterministic 회귀 통과 |
| manifest/전체 test green | 완료 | manifest version을 Cargo 버전과 동기화; `cargo test --lib` 772/772 통과 |
| P1 native exclusion 집계 | 완료 | summary CSV 및 manifest/ownership 일치 gate 추가; 신규 테스트 포함 전체 775/775 통과 |
| P1 SEH/panic 제외 해소 | 진행 중 | 기본 Guarded 정책의 computed-jump/shared-state 33개를 세부 원인별 분리 예정 |

이 표는 구현과 테스트 결과가 나올 때마다 갱신한다. 상세 계획은 아래 절을 기준으로 한다.

### 0.1 2026-09-05 Phase 1 작업 로그

1. `src/pipeline/crypto/place/route_orchestration.rs`
   - Complete indirect target 또는 pointer-table target이 VM family 소유인데 정확한 entry VIP가 없을 때 `continue`하던 경로를 제거했다.
   - 누락된 materialization proof를 명시적 build error로 바꿨다.
   - 집중 테스트 `no_indirect_proof_emits_no_route_section_and_missing_vip_fails_closed` 통과.
2. `src/vm/threaded/poly_direct/builder.rs` native bridge
   - guest architectural RSP 전환을 구조 검증기가 식별하는 canonical `r/m64 <- r64` MOV encoding으로 고정했다.
   - 집중 테스트 `cross_family_child_call_stays_on_host_stack_while_native_keeps_guest_stack` 통과.
3. `src/vm/threaded/poly_direct/builder.rs` lifetime cleanup
   - `LIFETIME_SYNC_COUNT_STATE_OFFSET(0x50A8)`과 `LIFETIME_SYNC_PTR_STATE_OFFSET(0x50C0)`가 비연속인데 count를 `[ptr+8]`에서 읽던 결함을 수정했다.
   - 두 슬롯을 각각 authoritative ABI 주소에서 RIP-relative로 로드한다.
   - 집중 테스트 `lifetime_cleanup_handler_reencrypts_and_releases_owned_scope` 통과.
4. `src/pipeline/crypto/place/mod.rs`
   - native block payload에 Program-VM `vm_prog_off` 하한을 잘못 적용하던 검사를 제거했다.
   - native는 `code_start/code_len`, Program-VM은 `vm_prog_bc_off/vm_prog_bc_len`과 정확히 일치하는지 모드별로 검증한다.
   - deterministic 대표 회귀와 전체 관련 3개 테스트 통과.
5. `src/manifest.rs`
   - 테스트의 `1.0.0` 하드코딩을 `CARGO_PKG_VERSION` 계약으로 교체했다.
6. 전체 검증
   - `cargo test --lib`: **772 passed / 0 failed / 0 ignored**.
   - `cargo fmt --check`: 이번 변경 파일이 아닌 기존 `src/pipeline/crypto/place/lift.rs:89` 포맷 차이 1건으로 실패. 기능 수정과 분리하여 P1 시작 전에 정리할 항목으로 기록한다.

### 0.2 2026-09-05 P1 ownership evidence 작업 로그

1. `src/pipeline/ownership.rs`
   - original/native record만 reason별 함수·블록·명령 수로 집계하는 `render_native_exclusion_summary_csv()`를 추가했다.
   - 기존 legacy adapter가 최신 상용 제외 사유를 전부 `analysis-failure`로 잃던 문제를 수정했다.
   - `coverage_consistency_evidence()`를 추가하여 manifest coverage와 authoritative ownership map의 함수·블록·명령 수를 교차 검증한다.
2. `src/pipeline/validate.rs`
   - commercial full-coverage 판정에 ownership/coverage 일치 조건을 추가했다. 두 증거가 다르면 수치상 100%라도 `vm_commercial` effective 판정을 받을 수 없다.
3. `src/main.rs`
   - 상용 빌드에서 `<output>.ownership-summary.csv`를 자동 기록한다.
4. 기존 산출물 재집계
   - `crackme_packed.exe.btgmanifest`: VM 함수 435/464, native 29.
   - `crackme_packed.exe.ownership.csv`: VM 함수 432, native 33, 전체 465.
   - native 33개는 모두 `seh-or-panic-policy`이며 1,056블록/3,667명령이다.
   - 이 불일치를 `docs/commercial-vm-review/crackme_packed.native-exclusion-baseline.csv`에 동결했다.
5. 검증
   - 신규 집계/legacy reason/coverage drift 테스트 3개 추가.
   - `cargo test --lib`: **775 passed / 0 failed / 0 ignored**.

다음 병목은 `src/vm/text_lift/exclusions/seh.rs:16-38`이다. `commercial.rs:1044-1048`은 상용 소유권이 기본 full이라고 선언하지만 실제 `seh_ownership_mode()` 기본값은 `Guarded`이며, computed-jump EH frame과 runtime shared-global frame을 native로 유지한다. 이 정책/주석 불일치와 33개 coarse bucket을 해소하기 전에는 100% 소유권을 주장할 수 없다.

## 1. 결론

현재 구현은 단순 더미 VM은 아니다. `x86-64 -> RISC micro-op -> polymorphic ISA -> threaded native runtime` 경로, 다중 VM family, 네이티브 브리지, M7 bytecode chunk 재암호화, 무결성 descriptor, 소유권 보고서 및 fail-closed 검증이 실제 코드로 존재한다.

다만 **실제 상용 배포 가능 상태는 아니다.** 가장 큰 이유는 다음 네 가지다.

1. 현재 전체 라이브러리 테스트가 `765 passed / 7 failed`이며, 실패 중 3개가 상용 런타임 계약(route, native bridge stack, lifetime cleanup)을 직접 깨뜨린다.
2. 기존 실전 산출물 `crackme_packed.exe.btgmanifest`는 실행 검증에는 성공했지만 VM 커버리지가 함수 `435/464`(93.75%), 블록 `5980/7036`(84.99%), 명령 `23552/27219`(86.53%)이고 원본 실행 바이트 `98,302`가 남아 있다. 매니페스트 스스로 `vm_commercial:incomplete-coverage`라고 기록한다.
3. 기본 라이브러리 API `src/lib.rs::pack()`과 `src/pipeline/pack.rs::run_full()`은 상용 VM을 선택할 수 없고, 현재 payload relocation 회귀로 기본 경로 자체도 실패한다.
4. 실제 고객 바이너리/컴파일러/Windows 버전/보안 기능 조합을 장기간 검증하는 CI·코퍼스·성능·크래시 텔레메트리·릴리스 게이트가 충분하지 않다.

따라서 목표를 아래처럼 정의해야 한다.

> 상용 VM = “상용” 이름의 플래그가 존재하는 상태가 아니라, 지원 대상으로 선언한 PE에서 원본 실행 코드 소유권이 0바이트이고, 모든 VM/네이티브 경계의 ABI·예외·메모리 수명 계약이 검증되며, 같은 입력에 대해 기능 동등성·재현성·보안 속성·성능 예산을 자동으로 증명하는 상태.

## 2. 현재 실제 실행 구조

### 2.1 CLI에서 산출 PE까지

```text
src/main.rs
  -> protection_profile::resolve()
  -> pass1_slice::run()               CFG/ProgramModel/TriggerBlock
  -> pass2_shuffle::run()             블록 레이아웃
  -> pass3_encode::run()              RIP/branch fixup
  -> pass4_section::run()             .btg/.textb 조립
  -> patch_data::run()                원본 section/reference 패치
  -> iat_hide::run()                  선택적 IAT 재구성
  -> pipeline::crypto::run()
       -> crypto/place/lift.rs         commercial whole-program lift
       -> crypto/place/vm_build.rs     family별 VM materialization
       -> commercial_build.rs
       -> threaded/poly_direct/*       native runtime 생성
       -> crypto/place/mod.rs          VM/boot/metadata 배치
  -> poly_embed                        SDK marker 경로
  -> build::run()                      최종 PE 합성
  -> validate::run()
  -> validate_effective_profile()
  -> 파일/manifest/evidence CSV 기록
```

상용 경로 선택 조건은 `src/protection_profile.rs:195-210`과 `src/main.rs:484-517`에 분산돼 있다. 실질적으로 crypto가 켜진 상태에서 `--vm-oep --vm-commercial`이 필요하고, `--m7`, `--m8`, `--integrity`, `--iat-hide`, `--mem-harden` 등이 추가 계약을 형성한다.

### 2.2 상용 VM 내부 데이터 경로

```text
ProgramModel
  -> function-atomic ownership/exclusion
  -> RiscLifter / capability registry
  -> RiscProgram + original-IP map
  -> family partition / cross-family route
  -> polymorphic encoder / super-op preparation
  -> Direct threaded native handlers
  -> generated entry, state, table, bytecode, bridges
  -> PE sections (.textb/.vmroute/mutable state 등)
```

관련 핵심 파일:

| 책임 | 코드 위치 | 상용화 관점 |
|---|---|---|
| 원본 프로그램 권위 모델 | `src/analysis/program_model.rs`, `program_model_builder.rs` | 함수/블록/edge 완전성의 출발점 |
| 간접 분기 복원 | `src/analysis/indirect_resolver.rs`, `pointer_tables.rs`, `switch_*` | unresolved edge가 1개라도 있으면 100% 소유권 불가 |
| 상용 소유권/제외 | `src/vm/text_lift/commercial.rs` | 함수 단위 원자성, SEH/TLS/unsupported/quarantine 판정 |
| RISC 변환 | `src/vm/risc/lifter/*`, `op_registry.rs` | 지원 명령과 runtime capability의 단일 진실 공급원 필요 |
| 다중 family | `src/vm/multi_family.rs`, `src/pipeline/crypto/place/vm_build.rs` | cross-family call/route/state ABI 위험 |
| 상용 런타임 생성 | `src/vm/commercial_build.rs`, `src/vm/threaded/poly_direct/builder.rs` | 가장 큰 신뢰 경계; builder 파일이 약 7.9K LOC |
| runtime route | `src/vm/route_table.rs`, `route_metadata.rs`, `crypto/place/route_orchestration.rs` | indirect call/jump fail-closed 보장 |
| 수명/재암호화 | `src/vm/data_lifetime.rs`, `chunk_crypto.rs`, `distributed_integrity.rs` | 평문 노출 시간과 cleanup의 정확성 |
| PE 합성/검증 | `src/pipeline/build.rs`, `validate.rs`, `src/pe/*` | Windows loader 계약, W^X, ASLR, CFG, unwind |
| 증거 산출 | `src/manifest.rs`, `pipeline/reports.rs`, `pipeline/ownership.rs` | 릴리스 판정의 기계 판독 근거 |

## 3. 현재 기준선과 확인된 결함

### 3.1 자동 테스트 기준선

실행 명령:

```powershell
cargo test --lib
```

결과: `765 passed; 7 failed`.

| 우선순위 | 실패 | 코드 위치 | 의미 |
|---|---|---|---|
| P0 | route proof 부재 시 missing VIP가 `Ok(None)` | `src/pipeline/crypto/place/route_orchestration.rs:312` | indirect route miss가 fail-closed라는 상용 계약이 회귀함 |
| P0 | cross-family/native call의 guest stack 설치 검증 실패 | `src/vm/threaded/poly_direct/poly_direct_tests.rs:423-430` | Win64 호출 시 architectural guest RSP와 host VM stack 분리가 깨질 가능성 |
| P0 | lifetime cleanup 후 object 재암호화 실패 | `src/vm/threaded/poly_direct/poly_direct_tests.rs:598-611` | native bridge/예외 복귀 후 민감 데이터가 평문으로 남을 수 있음 |
| P0 | payload relocation destination 검증 실패 | `src/pipeline/pack.rs:132`, `:147`, `:208`; 오류 발생지는 crypto placement | 기본 API와 deterministic build 계약이 실행 불가 |
| P1 | manifest 버전 테스트 stale | `src/manifest.rs:665` vs `cargo.toml:3` | 릴리스 메타데이터 계약과 테스트 동기화 부재 |

세 deterministic test는 동일 원인의 중복 실패이므로 결함 수로는 5개 범주지만 테스트 실패는 7개다.

### 3.2 기존 상용 산출물 기준선

`crackme_packed.exe.btgmanifest`:

| 항목 | 현재 값 | 상용 판정 |
|---|---:|---|
| execution verification | 성공, exit 0 | 긍정적이나 단일 실행만으로 불충분 |
| VM functions | 435 / 464 | 실패 |
| VM blocks | 5980 / 7036 | 실패 |
| VM instructions | 23552 / 27219 | 실패 |
| unresolved internal edges | 0 | 통과 |
| unsupported instructions | 0 | 통과 |
| capability mismatches | 0 | 통과 |
| native original functions | 29 | 실패 |
| original executable bytes | 98,302 | 실패 |
| hot-path profile | unprofiled | 실패/근거 부재 |
| ASLR | false | 상용 기본값으로 부적합 |
| ineffective feature | `vm_commercial:incomplete-coverage` | 명시적 실패 |

중요한 해석: `unsupported_instructions=0`은 100% VM화를 뜻하지 않는다. 현재 미소유 함수는 instruction opcode가 아니라 semantic dependency closure, SEH/panic 정책, integration quarantine, ambiguous boundary 등 다른 제외 사유로 빠질 수 있다. 따라서 opcode 추가만으로 100%가 되지 않는다.

### 3.3 입력/제품 범위 제한

`src/pe/parser.rs:105-140` 기준으로 현재 지원 입력은 AMD64 PE32+ EXE다.

- DLL은 명시적으로 거부한다 (`parser.rs:114-118`).
- x86/ARM64/PE32는 거부한다 (`parser.rs:108-133`).
- OEP가 정확히 `.text`에 있어야 하고 이미 BTG-packed인 입력은 거부한다 (`parser.rs:145-177`).
- SDK marker 경로는 rolling-key polymorphic bytecode를 native runner가 소비하지 못해 현재 비활성화된다 (`src/pipeline/poly_embed.rs:312-320`).
- BMI memory-source form 등 lifter 미지원 형태가 남아 있다 (`src/vm/lifter/mod.rs:971`).

초기 상용 범위는 무리하게 넓히지 말고 **Windows 10/11 x64, PE32+ EXE, MSVC/clang-cl/Rust, 정상적인 `.text` OEP, 비관리(native) 코드**로 고정한 뒤 지원 매트릭스를 확대해야 한다.

## 4. P0 — 상용화를 막는 즉시 수정 항목

### 4.1 route orchestration의 fail-closed 계약 복구

대상:

- `src/pipeline/crypto/place/route_orchestration.rs:1-180`: proof와 route identity 생성
- `src/pipeline/crypto/place/route_orchestration.rs:180-330`: no-proof/missing-VIP 테스트
- `src/vm/route_table.rs`: runtime key와 destination 검증
- `src/vm/route_metadata.rs`: 최종 PE의 route metadata 검증
- `src/vm/poly/interpreter/mod.rs`: reference interpreter의 route miss 동작
- `src/vm/threaded/poly_direct/builder.rs`: native runtime route lookup/trap

수정 방향:

1. `no indirect proof`와 `indirect edge가 있으나 proof 누락`을 다른 타입으로 표현한다. `Option<RouteSection>` 하나로 두 상태를 표현하지 않는다.
2. ProgramModel에 indirect edge/VIP가 한 건이라도 있으면 route section 부재는 즉시 오류로 한다.
3. route key는 `(source family, source VIP, edge kind, target identity)`를 포함하는 typed key로 고정하고 중복/충돌을 materialization 전에 거부한다.
4. interpreter와 native handler가 동일한 `RouteResolutionError` 의미론을 따르도록 공통 test vector를 만든다.
5. 잘못된 VIP, 삭제된 entry, 중복 target, out-of-range RVA, NX destination을 모두 mutation test로 검증한다.

완료 조건:

- 현재 실패 테스트 통과.
- route metadata 한 바이트 변조 시 protected process가 원본 주소로 fall back하지 않고 정해진 fail-closed 정책으로 종료.
- `unresolved_internal_edges=0`이 단순 카운트가 아니라 “필요 route 전부 materialized + native lookup 검증 완료”를 의미.

### 4.2 native/cross-family bridge의 stack ABI 재정립

대상:

- `src/vm/threaded/poly_direct/builder.rs`: native bridge/child family bridge 생성부
- `src/pipeline/crypto/place/vm_build.rs:885` 전후: placeholder 기반 cross-family 주소 패치
- `src/vm/commercial_build.rs:26-60`: 진입 ABI 설명과 구현
- `src/vm/abi.rs`: VM-visible register/stack 계약
- `src/vm/threaded/poly_direct/poly_direct_tests.rs:380-430`: 실패한 구조 검증
- `src/pe/unwind.rs`, `src/pipeline/build.rs`: 생성 bridge의 RUNTIME_FUNCTION/UNWIND_INFO

수정 방향:

1. VM host stack, guest architectural RSP, native callee stack을 명시적인 세 상태로 문서화하고 코드의 고정 offset을 named layout struct로 대체한다.
2. ordinary native call 직전에 guest RSP 설치, 32-byte shadow space, 16-byte alignment, stack argument 5+ 보존을 하나의 emitter helper로 통합한다.
3. cross-family child call은 host stack에 남되 child state pointer 전달과 return value/flags merge를 별도 ABI 함수로 만든다.
4. volatile/nonvolatile GPR, XMM6-XMM15, MXCSR, DF, RFLAGS 보존 범위를 Windows x64 ABI 기준으로 테스트한다.
5. bridge마다 정확한 prologue와 unwind code를 생성하고 `RtlVirtualUnwind` 기반 실제 검증을 추가한다.

완료 조건:

- 실패 테스트와 기존 fifth-stack-argument/FP-argument 테스트 모두 통과.
- 0~12개 정수/부동소수 인자, varargs, 구조체 반환, tail call, 재귀, 깊은 cross-family call을 native/reference/VM 3-way differential로 통과.
- bridge 내부 예외가 SEH handler까지 정상 unwind되고 cleanup handler가 정확히 한 번 실행.

### 4.3 lifetime cleanup 재암호화 및 예외 안전성 복구

대상:

- `src/vm/data_lifetime.rs`: object key, owner, sync table, mask
- `src/vm/threaded/poly_direct/builder.rs`: cleanup handler machine code
- `src/vm/threaded/poly_direct/poly_direct_tests.rs:570-611`: 현재 실패 재현
- `src/pipeline/crypto/place/lift.rs`: lifetime object 분석 결과 생성
- `src/pipeline/crypto/place/mod.rs`: mutable state와 metadata 배치
- `src/pipeline/build.rs`: section 권한

수정 방향:

1. Rust reference cleanup과 native emitted cleanup에 같은 serialized descriptor를 입력하고 byte-for-byte 결과를 비교한다.
2. descriptor의 `owner thread`, `refcount`, `object RVA/len`, `derived key`, `state`를 versioned layout으로 만들고 offset 상수를 한 모듈에서만 정의한다.
3. cleanup 순서를 `validate -> reencrypt -> zero key/material -> clear ownership`으로 고정한다. 중간 오류 시 평문 상태로 ownership만 지우는 경로가 없어야 한다.
4. 정상 return, SEH unwind, nested native call, reentrant call, 두 thread 경합을 각각 테스트한다.
5. 평문 window의 최대 시간/동시 평문 object 수를 측정해 manifest에 기록한다.

완료 조건:

- 실패 테스트가 통과하고 plaintext pattern이 call 종료 후 executable/read-only image 어디에도 남지 않음.
- 예외/timeout/강제 실패 injection에서도 key scratch와 owner row가 정리됨.
- ThreadSanitizer 대체가 어려운 Windows native 경로는 반복 stress + Application Verifier로 경쟁 조건을 검증.

### 4.4 payload relocation 및 section 좌표계 수정

현재 `run_full()`은 `.textb` trimming 후 destination `[0x100, 0x186)`을 section-relative로 잘못 검증해 실패한다. 로그상 pass4가 약 288MiB 임시 section을 만든 뒤 `0x3000`으로 trim하는 구조도 비정상적이다.

대상:

- `src/pipeline/pack.rs:28-113`: 기본 API staged pipeline
- `src/pipeline/pass4_section.rs`: 초기 section 예약 크기
- `src/pipeline/crypto/place/mod.rs`: payload destination 및 trim
- `src/pipeline/crypto/payload.rs`: relocated payload descriptor
- `src/pipeline/build.rs`: 최종 section RVA/raw offset 변환
- `src/pipeline/artifacts.rs`: typed artifact 경계

수정 방향:

1. 모든 범위를 `FileOffset`, `Rva`, `Va`, `SectionOffset` newtype으로 분리한다. 현재의 `u32/u64/usize` 혼용을 상용 경로부터 제거한다.
2. trim 전/후 relocation descriptor를 재기반화(rebase)하고 검증도 동일 좌표계로 수행한다.
3. sizing pass가 실제 최대 크기를 계산하게 하고 288MiB 선예약 후 축소하는 방식을 없앤다.
4. empty/minimal PE, 큰 `.text`, 큰 alignment, payload가 section 경계를 넘는 입력에 property test를 추가한다.

완료 조건:

- deterministic 3개 테스트 통과.
- 동일 seed는 byte-identical, 다른 seed는 구조적으로 유효한 상이 산출물.
- peak memory/임시 section 크기가 입력 크기에 선형 비례하며 10MiB 입력에서 비정상 수백 MiB 예약이 없음.

### 4.5 테스트 녹색화와 릴리스 즉시 차단

대상:

- `cargo.toml:3` 및 `src/manifest.rs:665`: 1.0.1/1.0.0 불일치
- 신규 `.github/workflows/ci.yml` 또는 조직 CI 설정
- `src/qa_runner.rs`, `src/qa.rs`

조치:

1. manifest test는 하드코딩 `1.0.0` 대신 `env!("CARGO_PKG_VERSION")`과 비교한다.
2. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --lib`, release build, QA smoke를 필수 게이트로 둔다.
3. 상용 플래그가 포함된 빌드는 test failure, partial coverage, execution verification 미실행 중 하나라도 있으면 파일을 final path에 기록하지 않는다.
4. `--allow-partial-vm`은 dev/debug build에서만 컴파일되게 feature gate하거나 산출물에 눈에 띄는 `NON_PRODUCTION` marker를 넣는다.

## 5. P1 — 100% 소유권에 도달하기 위한 분석/리프팅 보강

### 5.1 제외 29개 함수를 이유별로 닫기

`src/vm/text_lift/commercial.rs:32-83`의 typed exclusion reason과 `.ownership.csv`를 기준으로 자동 backlog를 만든다.

각 reason별 담당 코드:

| 제외 사유 | 주 수정 위치 | 필요한 작업 |
|---|---|---|
| unsupported instruction | `src/vm/risc/lifter/*`, `op_registry.rs`, `threaded/poly_direct/builder.rs` | lifter/registry/encoder/native handler/reference eval을 한 PR에서 함께 추가 |
| unsupported VM opcode | `src/vm/risc/op_registry.rs`, `vm/poly/*`, `threaded/poly_direct/*` | capability mismatch가 생기지 않는 end-to-end 등록 |
| legacy high-byte register | `commercial.rs:684-727`, register mapping | AH/BH/CH/DH + REX 제약을 명시적으로 lower하거나 해당 함수 native policy를 제품 범위에 명시 |
| semantic dependency closure | `commercial.rs:1040-1210`, `analysis/*` | caller/callee/address-taken closure 정확도 개선 |
| integration quarantine | `commercial.rs:1120-1478` | quarantine 근거를 개별 invariant/test로 치환 후 제거 |
| ambiguous function boundary | `program_model_builder.rs`, `crt.rs`, `.pdata` 분석 | symbols 없이 함수 경계 복원, interior target 처리 |
| SEH/panic/unwind | `text_lift/exclusions/seh.rs`, `setjmp.rs`, `panic_unwind.rs` | VM frame unwind/handler dispatch 검증 후 단계적 허용 |

중요 원칙:

- 함수 일부만 VM화하여 숫자를 올리지 않는다. 현재 function-atomic 정책은 유지한다.
- `unknown -> native`는 개발 호환 모드에서만 허용하고 production은 `unknown -> build error`로 한다.
- 각 신규 명령은 `iced decode -> RISC lift -> reference eval -> polymorphic encode/decode -> native handler -> flag/memory differential`의 6단계 테스트가 있어야 한다.

### 5.2 ProgramModel 완전성 강화

대상:

- `src/analysis/cfg_seed.rs`
- `src/analysis/program_model_builder.rs`
- `src/analysis/indirect_resolver.rs`
- `src/analysis/pointer_tables.rs`
- `src/analysis/code_pointers.rs`
- `src/analysis/switch_producer.rs`, `switch_targets.rs`
- `src/analysis/crt.rs`

필요 보강:

1. entry, `.pdata`, TLS callback, export, relocation-backed code pointer, CRT init array, vtable, jump table을 seed source로 통합한다.
2. seed마다 provenance를 남겨 어떤 분석 근거로 함수/edge가 생성됐는지 ownership CSV에 연결한다.
3. executable byte ownership bitmap을 만들고 모든 executable input byte를 `instruction / padding / data-in-code / unknown` 중 하나로 분류한다.
4. overlapping decode, interior branch, tail call, thunk, hotpatch prefix, alignment island를 명시적으로 처리한다.
5. unresolved indirect edge는 단순 개수가 아니라 source RVA, abstract value set, 실패 reason을 보고한다.

완료 조건:

- 지원 코퍼스에서 `unknown executable bytes = 0`.
- `unresolved_internal_edges = Some(0)`의 생성 근거가 CSV/manifest에 추적 가능.
- IDA/Ghidra/DbgHelp symbol 기반 외부 oracle과 함수/edge 차이를 비교하는 offline 검증 도구 보유.

### 5.3 상용 capability의 단일 registry화

현재 capability가 RISC op registry, polymorphic encoder, interpreter, native builder 곳곳에 존재한다.

대상:

- `src/vm/risc/op_registry.rs`
- `src/vm/poly/isa_spec.rs`, `encoder.rs`, `interpreter/*`
- `src/vm/threaded/poly_direct/builder.rs`
- `src/pipeline/reports.rs`

계획:

1. opcode별 operand width, flag read/write, memory effect, fault behavior, family 지원 여부를 declarative spec으로 만든다.
2. interpreter/native emitter/coverage check를 spec에서 생성하거나 최소한 동일 registry를 소비하게 한다.
3. `capability_mismatches=0`을 검증하는 테스트를 전체 opcode/operand 조합으로 확장한다.
4. 거대한 `builder.rs`를 dispatch, entry, bridge, integer, branch, memory, SIMD/FP, atomic, integrity/lifetime emitter로 분할한다.

## 6. P1 — Windows 로더/ABI/보안 호환성

### 6.1 ASLR 복구

기존 상용 산출물은 `aslr_preserved=false`다. 상용 보안 제품이 자체 보호 때문에 ASLR을 끄는 것은 기본 정책으로 받아들이기 어렵다.

대상:

- `src/pe/reloc.rs`
- `src/pipeline/build.rs:63-80`의 원본 `.text` 제거/소유권 판단
- `src/pipeline/crypto/place/mod.rs`
- `src/pipeline/validate/pe_dirs.rs`

계획:

1. runtime absolute VA를 image-base-relative RVA 또는 relocation-backed slot으로 전환한다.
2. 암호문 영역에 loader relocation이 적용되지 않도록 plaintext relocation island 또는 boot-time fixup descriptor를 둔다.
3. `/DYNAMICBASE`, `HIGH_ENTROPY_VA`, base relocation directory를 보존하고 강제 relocation 실행 테스트를 한다.
4. 100회 무작위 base 실행에서 동일 동작을 검증한다.

### 6.2 CFG/CET/DEP/W^X

대상:

- `src/pe/load_config.rs`, `src/pe/builder.rs`
- `src/pipeline/validate/pe_dirs.rs`
- `src/vm/route_metadata.rs`
- `src/pipeline/crypto/bootstub/*`

계획:

1. 원본 Guard CF table과 생성 VM/bridge valid call target을 병합한다.
2. CET/IBT 대상에 ENDBR64 필요 여부와 shadow stack 호환을 Windows 버전별 검증한다.
3. `.textb`는 초기 RX, 필요한 짧은 구간만 RW로 전환 후 즉시 RX 복귀하도록 한다. mutable state는 처음부터 RW/NX 분리한다.
4. 최종 PE validation이 RWX section, writable executable metadata, executable state page를 하드 실패시킨다.

### 6.3 SEH/TLS/CRT/setjmp

대상:

- `src/vm/text_lift/exclusions/seh.rs`, `tls_guard.rs`, `setjmp.rs`, `panic_unwind.rs`
- `src/pe/unwind.rs`, `tls.rs`
- `src/pipeline/build.rs`의 `.pdata/.xdata` 합성

계획:

1. generated function/bridge/handler마다 정확한 `RUNTIME_FUNCTION`을 만들고 sorted/non-overlap을 검증한다.
2. TLS callback은 OEP 전 실행된다는 사실을 기준으로 보호 가능/불가능 정책을 문서화한다.
3. C++ EH, Rust panic unwind/abort, `__try/__except`, `setjmp/longjmp`를 각각 독립 코퍼스로 만든다.
4. exception 발생 지점별로 native vs protected stack trace/handler 결과를 비교한다.

## 7. P2 — 암호/키/무결성 제품화

### 7.1 키 생명주기

현재 표준 crypto는 ChaCha20-Poly1305이나 동일 프로세스 안에 복호화 코드와 파생 재료가 존재하므로 “강한 알고리즘 사용”만으로 보호 강도가 완성되지 않는다.

대상:

- `src/crypto/provider.rs`, `key_schedule.rs`, `state.rs`
- `src/vm/key_domains.rs`, `seed_lifecycle.rs`, `conceal.rs`
- `src/pipeline/crypto/bootstub/*`

계획:

1. build seed, payload key, VM family key, chunk key, integrity key를 domain-separated KDF tree로 명세한다.
2. manifest의 seed는 재현 ID와 실제 secret을 분리한다. production artifact에 secret seed를 평문 기록하지 않는다.
3. key scratch를 고정 RW state에 오래 두지 말고 사용 직후 volatile zeroization을 검증한다.
4. nonce/counter 재사용 방지를 artifact ID + region identity로 증명한다.
5. production key provisioning이 필요하면 offline signing/HSM 경계를 별도 설계한다.

### 7.2 무결성 범위와 fail policy

`crackme_cff.exe.btgmanifest`에는 `integrity:runtime-integrity-descriptors-absent`가 이미 기록돼 있다. 요청 플래그와 실제 효력의 차이를 상용에서는 허용하면 안 된다.

대상:

- `src/vm/distributed_integrity.rs`
- `src/pipeline/crypto/integrity.rs`
- `src/crypto/poly1305_native.rs`
- `src/pipeline/validate.rs`

계획:

1. code, table, route metadata, encrypted bytecode, immutable descriptor 각각을 어떤 key/시점에 검증하는지 threat model에 명시한다.
2. effective feature가 없으면 `--integrity` 요청 자체를 실패시킨다. “요청했지만 ineffective” 산출물을 만들지 않는다.
3. descriptor/tag/table/bytecode/handler별 single-bit tamper matrix를 자동 실행한다.
4. anti-debug/integrity 실패 정책은 trap만이 아니라 deterministic exit code와 고객 crash diagnostics 모드를 구분한다.

## 8. P2 — API와 설정 구조 정리

### 8.1 CLI와 라이브러리 경로 통합

현재 설정 타입이 `src/pipeline/config.rs`와 `src/protection_profile.rs`에 중복되고, `src/lib.rs::pack()`은 상용 설정을 받을 수 없다.

수정 대상:

- `src/lib.rs:35-42`
- `src/pipeline/pack.rs:28-113`
- `src/pipeline/config.rs`
- `src/protection_profile.rs`
- `src/main.rs:321-622`

제안 API:

```rust
pub struct PackRequest<'a> {
    pub input: &'a [u8],
    pub profile: ProtectionProfile,
    pub seed: SeedPolicy,
    pub verification: VerificationPolicy,
}

pub struct PackResult {
    pub image: Vec<u8>,
    pub manifest: BuildManifest,
    pub evidence: EvidenceBundle,
}
```

단일 `resolve -> staged pipeline -> validate -> emit` 경로를 CLI와 library가 공유하게 한다. `run_full()`의 하드코딩된 `vm_commercial:false`를 제거하고, boolean 조합 대신 `DevelopmentPartialVm`과 `ProductionCommercialVm` 같은 명시적 profile enum을 사용한다.

### 8.2 typestate 확대

현재 `StagedPipeline` 방향은 좋지만 artifact 좌표/증거 완전성까지 타입으로 표현하지 못한다.

단계 제안:

```text
Parsed -> Modeled -> OwnershipProven -> Materialized -> PeBuilt
       -> StructurallyValidated -> SemanticallyVerified -> Releasable
```

`Releasable`만 파일 저장과 production manifest 생성을 허용한다. partial VM은 `DevelopmentArtifact`로만 반환한다.

## 9. P2 — QA/CI/성능/관측성

### 9.1 코퍼스 확장

현재 `src/qa.rs`는 dummy, Rust test payload, 사용자 제공 `BTG_QA_CORPUS` 중심이며 시스템 GUI 바이너리는 제외한다. 다음 축을 고정 코퍼스로 추가한다.

| 축 | 필수 변형 |
|---|---|
| 컴파일러 | MSVC 2019/2022, clang-cl, Rust stable 3개 버전 |
| 최적화 | O0/O1/O2/Ox, LTO on/off, debug/release |
| 런타임 | static/dynamic CRT, console/GUI, subsystem variants |
| 언어 기능 | C++ EH/RTTI/templates, Rust panic/unwind, TLS, atomics, SIMD/AVX2 |
| PE 기능 | ASLR, CFG, CET, resources, delay import, exports, TLS callbacks |
| 제어 흐름 | switch/jump table, vtable, function pointer arrays, tail calls, recursion |
| 규모 | tiny, 1MiB, 10MiB, 100MiB `.text` |

고객/제3자 바이너리는 라이선스상 재배포 가능한 것만 CI fixture로 고정하고, 비공개 코퍼스는 hash/version만 기록한다.

### 9.2 동등성 검증

`src/differential.rs`의 단일 프로세스 실행 비교를 확장한다.

1. stdin/args/env/filesystem fixture를 동일하게 제공한다.
2. exit code, stdout/stderr뿐 아니라 생성 파일 hash, registry/network mock event, exception code를 비교한다.
3. timeout/crash 시 minidump, failing seed, input hash, flags, last VM route/block ring을 보존한다.
4. nondeterministic 프로그램은 normalization plugin을 통해 비교한다.

### 9.3 성능 예산

현재 `vm_hot_path=unprofiled`이므로 상용 성능 판단 근거가 없다.

추가 지표:

- startup latency p50/p95/p99
- VM instruction/native instruction ratio
- protected function별 slowdown
- working set/private bytes/peak commit
- output size 증가율
- VM handler/table/bytecode cache miss
- M7 decrypt/re-encrypt 횟수 및 plaintext dwell time

초기 release gate 예시:

- 시작 시간: 원본 대비 p95 2배 이하 또는 +100ms 이하 중 큰 값
- steady-state 보호 함수: p95 10배 이하(프로필별 별도 SLA)
- 산출물 크기: 원본 대비 3배 이하
- peak memory: 원본 + 128MiB 이하

수치는 실제 고객 workload 측정 후 확정한다. 초기에 무조건 100% VM화를 강제하면 성능이 제품 불가 수준이 될 수 있으므로, 보안상 100% 소유권과 “모든 함수를 고비용 동일 handler로 실행”을 구분하고 family/super-op 최적화로 해결해야 한다.

### 9.4 CI 단계

```text
PR fast gate
  format + clippy + unit + reference/native differential

Windows x64 gate
  debug/release + corpus pack + execute + PE structural validation

Commercial strict gate
  100% ownership + no unresolved edge + no mismatch + original exec bytes 0
  + ASLR/CFG/W^X + tamper + SEH/unwind + deterministic build

Nightly stress
  randomized seeds + fault injection + concurrency + large corpus + performance

Release qualification
  signed reproducible tool build + artifact SBOM + known-answer corpus + soak test
```

## 10. P3 — 제품/운영 준비

코드만 완성돼도 상용 제품은 아니다.

필요 산출물:

1. 지원/비지원 PE 매트릭스와 명확한 오류 코드.
2. semantic versioning: tool version, VM ISA version, crypto format version, manifest schema version을 독립 관리.
3. backward compatibility 정책: 구버전 protected artifact를 새 runtime이 실행하는 구조인지, artifact self-contained인지 명시.
4. SBOM, dependency audit, license inventory, reproducible release build, code signing.
5. crash dump privacy 정책과 고객 진단 bundle 생성기.
6. fuzzing: hostile PE parser, lifter, bytecode decoder, route metadata, manifest parser.
7. 보안 검토: 내부 threat model 후 외부 reverse-engineering/crypto/Windows ABI 리뷰.
8. 긴급 kill switch/denylist: 특정 tool/VM version의 산출을 차단하고 고객이 식별할 수 있게 manifest에 build provenance 기록.

## 11. 권장 구현 순서와 예상 산출물

### Phase 0 — 기준선 고정 (1주)

- 현재 7개 실패를 issue ID와 failing seed/output으로 동결.
- CI fast gate 생성.
- 기존 `crackme_packed` manifest/ownership/unsupported/mismatch를 baseline artifact로 보존.
- 상용 지원 범위 문서화.

산출물: `baseline.json`, CI, known-failure 목록, 지원 매트릭스.

### Phase 1 — 런타임 정확성 복구 (2~4주)

- route fail-closed.
- stack/native/cross-family ABI.
- lifetime cleanup.
- payload relocation/typed address.
- 전체 unit test green.

Exit gate: `cargo test --lib` 100% 통과, sanitizer/verifier stress 통과.

### Phase 2 — 분석과 100% 소유권 (4~8주)

- 29개 native 함수 exclusion을 reason별 제거.
- ProgramModel seed/edge/byte ownership 강화.
- capability registry 단일화.
- strict profile에서 original executable bytes 0.

Exit gate: 지정 코퍼스 전부 함수/블록/명령 100%, unresolved/mismatch/unsupported 0.

### Phase 3 — Windows security contract (3~6주, Phase 2와 병행 가능)

- ASLR, CFG/CET, W^X, unwind/SEH/TLS.
- 실제 Windows 10/11 VM matrix.
- tamper/fault injection.

Exit gate: 강제 relocation, CFG on, DEP on, verifier on에서 전체 corpus 동작.

### Phase 4 — 제품 API/성능/운영 (3~6주)

- PackRequest/PackResult와 CLI 통합.
- profiler와 성능 budget.
- evidence schema/versioning/SBOM/signing.
- crash diagnostics와 nightly soak.

Exit gate: release qualification checklist 자동 통과.

### Phase 5 — 외부 검증/파일럿 (4주 이상)

- 내부 red-team 및 외부 ABI/crypto 리뷰.
- 제한된 고객 workload 파일럿.
- crash/performance/false-rejection 피드백 반영.

## 12. 릴리스 판정 체크리스트

다음 조건을 **모두** 충족하기 전에는 “상용 VM”으로 표시하지 않는다.

- [ ] 전체 unit/integration/differential 테스트 통과, ignored flaky test 0.
- [ ] 지원 코퍼스의 VM 함수/블록/명령 커버리지 100%.
- [ ] `original_text_exec_bytes = 0`.
- [ ] `unresolved_internal_edges = 0`이며 route materialization 증거 존재.
- [ ] `unsupported_instructions = 0`, `capability_mismatches = 0`.
- [ ] ownership exclusion 0. 정책상 native thunk가 필요하다면 “원본 실행 코드”가 아닌 검증된 generated bridge만 허용.
- [ ] entry부터 종료까지 reference/native/protected 동등성 검증.
- [ ] native/cross-family bridge ABI, unwind, SEH 검증.
- [ ] lifetime/chunk cleanup 후 민감 평문과 key scratch 잔존 0.
- [ ] ASLR 유지 및 강제 relocation 실행 성공.
- [ ] CFG/DEP/W^X 계약 통과, RWX section 0.
- [ ] integrity requested 시 ineffective feature 0, tamper matrix 100% fail-closed.
- [ ] 동일 input/config/seed reproducible; secret seed는 artifact에 노출되지 않음.
- [ ] 성능/크기/메모리 SLA 통과.
- [ ] Windows/컴파일러/최적화 지원 매트릭스 통과.
- [ ] manifest schema, SBOM, signing, dependency/license audit 완료.
- [ ] 외부 보안 검토의 critical/high 미해결 0.

## 13. 첫 번째 실제 작업 묶음

바로 구현을 시작한다면 다음 순서가 가장 안전하다.

1. `route_orchestration.rs:312` 실패를 최소 재현하고 no-proof/required-route 상태 타입을 분리한다.
2. `poly_direct_tests.rs:423`에 대응하는 bridge emitter를 찾아 stack layout을 named struct로 추출한다.
3. `poly_direct_tests.rs:607`의 cleanup machine code와 `data_lifetime.rs::scoped_mask_byte` reference를 instruction 단위로 비교한다.
4. crypto placement의 section offset/RVA 혼용을 newtype으로 바꾸고 `run_full()` 3개 회귀를 복구한다.
5. version test를 고친 뒤 전체 772 tests green을 CI 첫 mandatory gate로 만든다.
6. `.ownership.csv`에서 native 29개를 reason별 집계하는 도구를 `pipeline/reports.rs`에 추가하고 가장 빈도가 큰 exclusion부터 닫는다.

이 여섯 작업이 끝나야 이후 100% 커버리지 확대가 의미가 있다. 지금 상태에서 opcode나 난독화 기능을 더 추가하면, 이미 깨진 런타임 경계와 검증 부채 위에 복잡도만 늘어난다.

## 14. 최종 판단

현재 프로젝트는 연구용 더미에서 상당히 진전된 **상용 후보 엔진**이다. 특히 typed ownership, capability mismatch, route metadata, multi-family, distributed integrity, deterministic evidence라는 방향은 좋다. 그러나 현재 증거가 보여주는 상태는 “실행되는 부분 VM prototype”이지 “100% whole-program commercial VM”은 아니다.

상용 단계로 가는 최단 경로는 새 난독화 기법 추가가 아니라 다음 세 축이다.

1. 실패 중인 runtime boundary의 정확성 복구.
2. ProgramModel/ownership의 완전성을 높여 원본 실행 바이트를 실제 0으로 만들기.
3. Windows 보안 계약과 광범위한 자동 증거를 release gate로 강제하기.

이 계획의 최우선 성공 지표는 기능 개수나 코드량이 아니라, strict production profile에서 생성된 manifest가 `effective vm_commercial`, `100%/100%/100%`, `original_text_exec_bytes=0`, `ASLR=true`, `execution_verified=true`를 동시에 기록하고 그 값이 CI에서 재현되는 것이다.

## 15. 구현 진행 기록

### 완료 — P0 런타임/검증 기준선 복구

- `src/pipeline/crypto/place/route_orchestration.rs`: VM 소유 타깃의 entry VIP가 없으면 조용히 건너뛰지 않고 빌드를 실패시키도록 route materialization을 fail-closed로 변경했다.
- `src/vm/threaded/poly_direct/builder.rs`: guest stack 설정 MOV 방향을 바로잡고, lifetime cleanup의 count/포인터 RIP anchor를 독립적으로 읽도록 수정했다.
- `src/pipeline/crypto/place/mod.rs`: native payload와 Program-VM bytecode의 relocation 유효 범위를 각 모드의 실제 section 범위로 분리했다.
- `src/manifest.rs`: 패키지 버전 검증을 하드코딩 대신 `CARGO_PKG_VERSION` 기준으로 변경했다.
- 검증 결과: `cargo test --lib` 기준 **775 passed / 0 failed / 0 ignored**.

### 완료 — ownership 증거 강화

- `src/pipeline/ownership.rs`: 네이티브 제외 사유별 함수/블록/명령 수와 최초 blocker를 집계하는 summary CSV를 추가했다.
- `src/main.rs`: 기존 `.ownership.csv`와 함께 `.ownership-summary.csv`를 생성한다.
- `src/pipeline/validate.rs`: manifest 커버리지와 실제 ownership map의 함수/블록/명령 카운트가 다르면 commercial effective 판정을 거부한다.
- `src/vm/text_lift/exclusions/seh.rs`: guarded SEH 보존 결과에 `computed_jump_func_ranges`, `shared_state_func_ranges` provenance를 보존한다.
- `src/vm/text_lift/commercial.rs`: 기존의 포괄적인 `seh-or-panic-policy`를 `seh-computed-jump-policy`, `seh-shared-state-policy`로 세분화했다. computed-jump는 최초 간접 분기 명령도 blocker로 기록한다.

### 다음 구현 순서

1. shared-state 제외에도 실제 전역 상태 참조 명령 RVA와 대상 section/RVA를 blocker detail로 연결한다.
2. commercial strict 기본값과 `seh_ownership_mode()`의 guarded 기본값 불일치를 제거하고, strict에서는 fallback native 함수가 하나라도 있으면 명시적으로 실패시킨다.
3. 새 `.ownership-summary.csv`로 실제 crackme를 재패킹하여 33개 네이티브 함수를 세부 사유별로 재산정한다.
4. computed-jump 타깃의 ProgramModel/IP map 완전성을 증명한 뒤 해당 exclusion을 단계적으로 제거한다.
5. shared runtime state를 guest-frame/personality bridge의 명시적 슬롯으로 옮기고 shared-state exclusion을 제거한다.

### 완료 — commercial SEH strict 기본 계약 고정

- `src/vm/text_lift/exclusions/seh.rs`: 환경변수 기반 진단 정책과 분리된 `detect_seh_native_functions_strict()` 진입점을 추가했다.
- `src/vm/text_lift/commercial.rs`: 상용 리프터가 `BTG_SEH_OWNERSHIP`의 ambient 값에 의해 guarded/preserve로 약화되지 않고 항상 strict/full SEH ownership을 사용하도록 변경했다.
- 일반 block-shuffle 및 legacy VM 경로는 기존 환경변수 기반 진단 동작을 유지하므로 호환성 범위를 상용 경로로 제한했다.
- 검증 결과: commercial 리프터 단위/통합 테스트 **10 passed / 0 failed**.

### 2026-09-05 strict 실산출물 검증 결과

- `test/target/release/crackme.exe`를 `--vm --vm-oep --vm-commercial --strict-profile --verify-output --seed 20260905`로 실제 패킹했다.
- 리프터 측 측정값은 blocks `7036/7036`, instructions `27219/27219`, unresolved/unsupported/capability mismatch 모두 0, `original_text_exec_bytes=0`에 도달했다.
- canonical function range 밖의 315개 leaf/unknown CFG 블록이 ownership CSV에서 빠져 있던 모집단 불일치를 발견했다. `src/vm/text_lift/commercial.rs`에서 이를 synthetic original leaf ownership unit으로 기록하여 authoritative map이 blocks `7036/7036`, instructions `27219/27219`, functions `780/780`을 정확히 분할하도록 수정했다.
- `src/differential.rs`는 Windows가 종료 직후 executable image mapping을 잠시 유지할 때 실패 산출물 rename이 본래 검증 오류를 가리는 문제를 2초 bounded retry로 수정했다.
- 실제 실행 검증에서는 아직 두 결함이 남는다. fixed-base full-SEH 산출물은 Rust panic/Once 경로에서 stack corruption으로 `0xC0000005`, ASLR 실험 산출물은 실제 load base가 `0x7ff7...`임에도 preferred-base 주소 `0x1400EB40A`로 분기하여 `0xC0000005`가 발생했다.
- 따라서 단순 `.reloc`/`DYNAMIC_BASE` 보존 실험은 되돌렸고, strict commercial validation에는 ASLR이 없으면 실패하는 gate를 유지한다. 완료 조건은 encrypted VM operand를 RVA로 정규화하고 runtime image delta를 적용한 뒤 forced-rebase 실행 검증이 통과하는 것이다.

### 2026-09-05 ASLR handler-table 계약 회귀 정리

- native direct-threaded handler table은 ASLR을 위해 절대 handler VA 대신 code-relative handler offset을 암호화해 저장한다. dispatch는 loader-mapped table anchor에서 실제 code base를 복원한 뒤 offset을 더한다.
- `SelfDecodingParts::validate()`는 이미 이 offset 계약을 검증했지만, 구조 회귀 테스트 4개가 여전히 복호화 결과를 절대 VA로 해석하여 전체 테스트가 `772 passed / 4 failed`로 깨져 있었다.
- `src/vm/threaded/poly_direct/poly_direct_tests.rs`의 handler shape, super-op registration, single-XOR resistance, unused-op trap 검사를 code-relative 계약에 맞게 수정했다.
- `SelfDecodingParts::table` 문서도 `handler VA`에서 `code-relative handler offset`으로 바로잡았다.
- 검증 결과: 집중 회귀 4/4 통과, `cargo test --lib --quiet` **776 passed / 0 failed / 0 ignored**.

### 2026-09-05 ASLR strict 코퍼스 재검증

- 최신 release 빌드로 `corpus/o0.exe`를 `--vm --vm-oep --vm-commercial --strict-profile --verify-output --seed 20260905` 조건에서 재검증했다.
- canonical 분석은 1,885 functions / 17,775 blocks / 30,254 edges를 복원했고 unresolved analysis edge 없이 commercial lift까지 진입했다.
- ASLR 실행 검증 전에 RISC capability gate가 먼저 fail-closed 했다. 미지원 명령은 `Ror_rm32_CL`, `Ror_rm64_CL`, `Shrd_rm64_r64_CL` 각 1건이며, 이로 인해 3 functions / 12 blocks / 105 instructions가 native exclusion으로 남았다.
- 제외된 함수에 속한 pointer-table target RVA `0x26821`에 materialized entry VIP가 없어 route orchestration이 빌드를 중단했다. 원본 주소 fallback은 발생하지 않았으므로 fail-closed 계약은 유지됐다.
- 다음 구현 단위는 `RotateRight { width }`와 `DoubleShiftRight { width }` canonical RISC op이다. evaluator, polymorphic codec/interpreter, production threaded handler, capability registry를 동시에 추가하고 `CL` count의 x86 masking 및 count 0/1 RFLAGS 계약을 differential test로 고정해야 한다. 단순히 ROL/SHLD로 치환하면 CF/OF 의미가 달라지므로 허용하지 않는다.
- 이 세 opcode가 닫혀 full ownership과 route materialization이 완료된 뒤 동일 명령으로 forced-ASLR 실행 검증을 재개한다.

### 2026-09-05 ROR/SHRD 및 NOP pointer-entry route 복구

- canonical RISC에 `RotateRight { width }`, `DoubleShiftRight { width }`를 추가하고 lifter, reference evaluator, polymorphic ISA/interpreter, production threaded handler, harness capability를 함께 연결했다.
- `Ror_rm32_CL`, `Ror_rm64_CL`, `Shrd_rm64_r64_CL` 회귀와 native/reference differential을 추가했다. 최신 corpus 측정은 unsupported 0, ownership exclusion 0, blocks/instructions/functions `100%/100%/100%`다.
- pointer-table RVA `0x26821`은 실제 명령 엔트리가 아니라 다음 함수 직전의 15-byte multi-prefix NOP alias였다. route orchestration은 exact VIP를 우선하고, decoded gap 전체가 연속 NOP일 때만 다음 materialized VIP로 alias하며 semantic instruction/undecoded gap은 계속 fail-closed 한다.
- alias가 함수/VM-family 경계를 넘을 때 원래 canonical RVA/function identity는 route 검증용으로 유지하고 실제 실행 family/VIP만 fall-through 엔트리를 사용한다. route 단위 테스트 3/3이 통과했다.
- 동일 strict 명령은 canonical routes 883개를 생성하고 PE 구조, ASLR reloc, W^X/state split, lifetime, SEH/unwind 검증까지 모두 통과했다.
- 남은 차단점은 실행 differential이다. 원본은 exit 0/stdout 1460B이나 보호본은 `0xC0000005`/stdout 0B이며 실패 산출물은 `aslr-strict-o0.failed.exe`로 격리됐다. 다음 작업은 최초 예외 VA와 load-base delta를 수집해 boot→Program-VM 진입 전/후를 분리하는 것이다.
## 2026-09-05 ASLR lifetime/local indirect-route follow-up

- P2-5 synthesized lifetime byte toggles now emit `RebaseImageAddress` before every
  memory access. This removes the preferred `.rdata` dereference at `0x140051cf3`;
  a focused regression test covers the required `Mov -> Rebase -> MemoryRead` order.
- Local branch-map scans now accept both canonical preferred VAs and their
  loader-mapped ASLR equivalents. This prevents a mapped pointer for RVA `0x16BA0`
  from falling through to native `.text`; indirect-call tests pass 3/3.
- Strict differential now advances without either access violation, but times out
  while emitting a corrupted first banner literal. Current blocker is therefore
  P2-5 lifetime plaintext/key/scope parity, not routing or structural coverage.
- Lifetime toggling has now been moved into the synchronization handlers: acquire
  decrypts only on depth `0 -> 1`, release re-encrypts only on `1 -> 0`, and nested
  scopes only adjust depth. Lifetime tests pass 4/4 and Program-VM bytecode shrank
  from roughly 2.87 MB to 1.72 MB by removing per-byte toggle micro-ops.
- The next strict run no longer hangs or prints ciphertext, but reaches a deliberate
  `UD2` after a protected pointer resolves to RVA-like value `0x5D52A` (source
  continuation near `0x140016BC0`). Cross-family depth is only 4, so this is not
  the depth-limit trap; the next task is validating lifetime handler mask/address
  parity for pointer-class objects and the subsequent indirect-target guard.
- Native transition coverage now executes nested acquire/read/release directly and
  passes. A later strict run exposed the actual ciphertext cause: synchronization
  operands were assigned against 136 planned objects while the final applied set
  compacted to 134, shifting table indices. The lift now remaps every emitted
  acquire/release operand by object RVA to the final compact table and rejects any
  surviving scope for an object removed after lift. Lifetime tests pass 5/5.
- Exact family-stream EOF is recognized as an implicit terminal sentinel while
  offsets beyond EOF still fail closed in chunk lookup. This removed the terminal
  chunk `UD2`; validation after the stable-index rebuild remains pending.
- The remaining 136-to-134 mismatch was a proof-accounting bug: when one literal
  object was passed in multiple argument registers to one call, toggle emission
  correctly deduplicated the object but also discarded the extra LEA references.
  Toggle deduplication and reference evidence are now separate; the strict build
  retains all 136 objects and completes every PE/ASLR/W^X/SEH structural gate.
- Large bytecode epoch tables now select the logarithmic `BinaryEnds` lookup
  topology (over 32 chunks); small tables retain the three seed-selected lookup
  grammars. A regression test fixes that bounded-cost contract.
- Execution differential still does not finish within 60 seconds. Direct runtime
  observation for over 120 seconds shows one core continuously active after the
  correct plaintext banner. Debugger samples land in valid byte decode/dispatch
  code rather than the lifetime lock or a fail-closed trap, but guest progress is
  not yet proven. The next diagnostic is repeated VIP/source-map sampling to
  distinguish an incorrectly virtualized guest loop from excessive dispatcher
  cost before changing the 60-second release gate.
- Fixed-seed (`20260906`) reproduction converted the apparent long-running case
  into a deterministic access violation. Disabling all data-lifetime sealing in
  a debug-only differential build reproduces the identical invalid address, so
  P2-5 is no longer the active cause.
- Runtime VIP-to-source tracing maps the fault to the path ending at
  `0x1400323D5: mov rax,[rax]`. An any-dispatch entry trap shows that
  `0x140032390` is reached within the same FusedCisc family, not through a
  cross-family child entry. Its guest RCX points at a stack slot containing an
  ntdll address with tag bits `01`, while the original execution's normal call
  carries tag bits `10` and returns immediately.
- The guest return address identifies caller continuation `0x14003F680`; the
  direct call is at `0x14003F67B`. The preceding branch depends on the low-byte
  result of the call at `0x14003F652` (target `0x1400498C0`). Next isolate that
  return value at `0x14003F658` in original and VM execution; the evidence now
  points to call-return/AL propagation or its consuming flags, not lifetime data.
- Original/VM comparison at `0x14003F658` disproved the return-value hypothesis:
  the preceding call returns `RAX=0` in the original too. The decisive difference
  is caller local `[rbp-0x18]`: original is zero, whereas the VM slot contains an
  ntdll code address. That nonzero stale value alone sends the VM into the drop
  call at `0x14003F67B`.
- An any-dispatch target trap now accepts a canonical source VA and resolves its
  family-local VIP automatically. Full guest-state capture at `0x140032390`
  confirms RCX is correctly `RBP-0x18`; the bad value is already present in the
  real guest stack. The next boundary to classify is the preceding call target
  `0x1400498C0`: determine whether its route is same-family, generated child, or
  native bridge, then add a stack-local sentinel regression around that exact
  transition and repair guest-RSP/host-stack restoration.
- Correct route tracing identifies `0x1400498C0` as a Register-family target
  entered from FusedCisc through a generated cross-family child route. At child
  entry, the future bad slot is still zero and lies at guest entry RSP `+0x20`
  (the last Win64 shadow-space qword); it changes only while the child executes.
  A hardware write-watch experiment also exposed that the current dispatcher
  diagnostic trap clobbers physical scratch registers, so simply skipping its
  UD2 cannot safely resume. The trace hook must save/restore its scratch set,
  then the watchpoint can identify the exact first writer without perturbing VM
  execution.
- Resumable child-entry and parent-dispatch traps in one process disproved a
  direct stack-slot write. The suspended Fused caller entered the child with
  `RBP=...ec00` and `[RBP-0x18]=0`, but resumed with `RBP=...eac0`. A hardware
  watchpoint on the Fused RBP state slot caught a nested cross-family state-copy
  loop overwriting that exact slot.
- The alias was caused by native-entry roots and their internal cross-family
  children both allocating the next consecutive lane. The runtime lane space is
  now partitioned per thread bucket into four native-root windows of sixteen
  family-depth lanes; each gateway root resets internal depth to zero and the
  router fails closed before depth 16. This stays within the existing boot-area
  size limit, unlike a naive full 64x64 reservation.
- Cross-family CALL regression coverage now verifies every Win64 nonvolatile
  guest register plus architectural RSP restoration. Focused route and invocation
  layout tests pass. With lifetime disabled for isolation, fixed seed `20260906`
  no longer crashes at `0x1400323D5`; it reaches the 60-second differential
  timeout, so the next step is renewed VIP/CPU progress sampling rather than
  further RBP/stack-local debugging.
- Runtime sampling showed the apparent stall repeatedly traversing finite formatter
  loops whose every back-edge performed a full linear scan of the family branch
  map. The hot resolver now performs an encrypted-table binary search for both the
  canonical target and its ASLR-normalized equivalent, while unmatched targets
  retain the existing cross-family/native fail-closed fallback. Focused forward,
  reverse, and `ip_map` branch tests pass. Full fixed-seed verification also caught
  two scratch-register contract mistakes in the first implementation; the resolver
  now preserves physical R8 in a dedicated control-state slot and never borrows the
  persistent RSI/RDI interpreter context. A fresh end-to-end timing run is pending.
- The remaining dominant cost was not branch-map lookup itself: every backward
  branch called `sub_resync`, reset the rolling cipher to VIP zero, and replayed
  hundreds of kilobytes to reconstruct the target key. The sorted branch metadata
  now carries a parallel, independently masked rolling-key checkpoint array. A
  resolved branch restores `(VIP, rolling-key)` directly; unresolved/direct-offset
  fallback retains the conservative replay path. Forward/reverse, `ip_map`, and all
  outer-chunk topology tests pass.
- The checkpoint build replaces the previous 60-second stall with deterministic
  progress to a later fault in roughly 20 seconds, proving the replay bottleneck is
  removed. An experiment that pre-unmasked the outer chunk layer while constructing
  checkpoints failed immediately with `UD2`; placement applies that layer only after
  module construction, so checkpoint generation correctly uses the builder's inner
  ciphertext and the experiment was reverted. The next task is mapping the newly
  exposed access violation at module RVA `0x565140` / guest VIP near `0x56ED3` back
  to its canonical source instruction and classifying its preceding transition.
- VIP mapping identifies the new fault as the Stack-family UTF-16 formatter loop:
  canonical `0x140047129: movzx r13d, word ptr [rdi]` (VIP `0x56ECA`), immediately
  after the `0x140047123` end-pointer branch. At failure the guest RDI input cursor
  is `0x149...`, outside the process mapping. The loop's checkpointed back-edge is
  therefore fast and decrypts correctly; the next correctness boundary is where
  guest RDI changes from the valid input slice pointer to that native-stack-window
  address. Trace the RDI state slot across the preceding native/cross-family return
  before changing formatter or memory-read semantics.
- Resumable boundary traps disproved RDI corruption and call-return ABI damage.
  At formatter entry `R8=RBX=0x21`; RBX remains correct across both calls, then
  `lea rbx,[rdi+rbx*2]` produces exactly `rdi*3`. The RISC effective-address
  lowering overwrote an aliased destination/index before consuming the index.
  It now snapshots an aliased index first, with a regression for that exact LEA.
- Fixed-seed execution passes the former formatter access violation and reaches
  the next fail-closed guard: cross-family depth 15 while routing to
  `0x14001EFE0`. This is a valid non-recursive helper reached through a deeper
  commercial call/tail-transfer chain, not the previous memory fault. Re-entry
  windows are expanded coherently from 16 to 32 lanes per native root; the
  depth guard remains in place at 31 to prevent adjacent-root state aliasing.
- The larger sparse state layout exceeds the old temporary `0x12000000` boot
  placement window even though unused bytes are trimmed from the final PE. The
  placement reserve is raised to `0x1A000000`, covering the measured
  `0x194782D8` end while preserving the existing post-placement size trimming.
- The 32-lane/reserve build completes structural validation with a 15.5MB file
  (`.vstate` remains sparse/NX) and passes the former depth-15 guard. Execution
  advances to a new opcode-fetch access violation: the permuted VIP carrier is
  `0x186C8C44`, and `bytecode_base + VIP` equals the mapped image end exactly.
  This classifies the next defect as an out-of-range branch/return VIP published
  by the deeper cross-family path, not insufficient state reservation. Add an
  explicit `VIP > bytecode_len` diagnostic guard before decrypt/fetch and trace
  the last route/RET writer that produces the image-end delta.

### 2026-09-17 — 실행 정합성 재검증: 1~9 단계 일치, SEH 미완료

- ASLR 보정은 원본 DIR64 슬롯을 보존하고 생성 코드의 실제 VA immediate만
  추가하도록 수정했다. 숨김 IAT 테이블은 RVA를 기록하고 런타임 이미지 베이스를
  더한다. 원본 relocation과 겹치는 데이터는 lifetime 변환에서 제외한다.
- 과거 추적 기록의 일부 canonical VA에는 잘못된 +0x20000 보정이 들어 있었다.
  원본 PDB/디스어셈블리 기준 main은 0x140007EF0, `_print`는 0x1400197A0이다.
- 출력 손상 원인은 좁은 TEST의 SF였다. NOR 기반 합성은 64비트 SF를 만들므로
  TEST AL/AX/EAX 결과에 폭별 플래그를 재계산한다. Rust formatter의 제어 바이트
  0xC3이 양수 문자열 길이로 오인되던 문제가 해결됐다.
- AES 오류는 `TEST CL,CL; MOVZX EAX,AL; CMOVNS EAX,EDX`에서 MOVZX가
  TEST 플래그를 지우는 문제로 재현했다. 수정 전 mul2(0x80)=0, 기대값=0x1B.
  MOVZX/MOVSX 합성 전후에 플래그를 보존하도록 수정했다.
- 검증: AES byte 입력 256개, 네 VM family의 경계값 native 실행, MOVZX/MOVSX/
  MOVSXD 플래그 보존 테스트 통과. `cargo test --lib vm::risc::lifter::tests`
  결과 95 passed / 0 failed. 로그: verify-galois-before.log,
  verify-galois-native.log, verify-extension-flags.log, verify-lifter-suite.log.
- seed 20260906, `--vm --vm-oep --vm-commercial --allow-partial-vm --full
  --verify-output --verify-timeout-secs 60`의 최신 산출물은 구조 검사를 통과하고
  실제 실행의 1~9 단계가 원본과 일치한다. crypto=0xb92581012793b943,
  multithreading=0x0d08669804097863. 전체 differential 검증은 아직 실패다.
- 10번 catch_unwind에서 0xE06D7363 second-chance로 종료한다.
  verify-movzx-eh.log에서 native bridge(+0x3E1292) 이후 unwinder가
  데이터 RVA 0x3F050을 반환 주소로 해석하며 스택을 잘못 걷는 것을 확인했다.
  builder.rs의 native bridge는 host-only 0xC0 프레임/XMM15 carrier와 guest
  stack 전환을 사용하지만 build_native_call_bridge_unwind_info는 과거의
  0xB8 allocation + 8 nonvolatile push 모델을 기록한다. 이 불일치와 가상
  guest continuation/원본 personality 연결을 함께 수정·실행 검증해야 한다.
  단순히 SEH 함수를 native 제외로 돌리거나 구조 검사 통과를 완료로 간주하지 않는다.
- 최신 실패 산출물: verify-movzx-flags.failed.exe. 10~16 및 최종 checksum은
  통과하지 않았으므로 전체 완료/완벽 수정 상태가 아니다.

### 2026-09-18 — SEH catch/소멸자 진입 해결, catch 이후 VM 재개 미완료

- Native bridge `.pdata`를 실제 guest-stack return anchor(NOP)에 한정하고
  EHANDLER/UHANDLER를 연결했다. 존재하지 않는 guest 0xB8 allocation/push
  unwind 코드를 제거했다. 일반 VM entry의 unwind code offset/slot count도 수정했다.
- 브리지는 원래 guest return PC와 pre-call RSP를 host +0x60/+0x68에 보존한다.
  실제 CALL은 R11을 사용한다. 반환 시 빌린 guest return slot을 원상 복구하며,
  CALL lifter는 architectural return PC에 ASLR delta를 적용한다.
- Carrier permutation 이후 native ABI 목적지 R12~R15를 고정했다. 기존에는
  C++ personality 복귀 시 Windows의 nonvolatile context가 뒤섞였다.
- Search에서는 DISPATCHER_CONTEXT의 walking context를 원래 guest 프레임으로
  연결하고, phase 2에서는 collided unwind로 Windows의 별도 context도 갱신한다.
  collided 재통지 시 이미 복원된 XMM15를 host pointer로 다시 해석하지 않는다.
- FH3 FuncInfo의 typed cleanup/catch RVA 슬롯을 gateway로 연결한다.
  IP-to-state table은 원본 guest PC 의미를 유지한다.
- 새 `exception_bridge.rs`는 실제 `_CxxThrowException` IAT 대상과 일치할 때만
  writable 원본 section 범위 안의 ThrowInfo destructor / CatchableType copy
  RVA를 gateway RVA로 변환한다. 일반 데이터 값, type descriptor RVA는 보존한다.
  런타임 초기화되는 Rust 예외 메타데이터가 정적 inventory에서 빠지던 문제를 해결했다.
  읽기 전용 메타데이터를 강제로 쓰거나 원본 `.text`를 실행 가능하게 하지 않는다.
- 검증: `runtime_throw_metadata_rewrites_only_typed_writable_callbacks` native 실행
  통과(정상, 다른 API, 범위 제한, null, 과대 count, null type; 반복 호출 포함).
  로그 `verify-seh-throw-metadata-test.log`. 앞선 SEH adapter/return slot/ASLR CALL/
  FH3 inventory/unwind-info 개별 회귀 테스트도 통과했다.
- 최신 seed 20260906 전체 실행은 구조 검사를 통과하나 differential은 실패한다.
  로그 `verify-seh-throw-rva.log`, 실패 산출물 `verify-seh-throw-rva.failed.exe`.
  `verify-seh-throw-rva-debug.log`에서 1~9 정상 출력 후 10번의 catch 처리와
  예외 destructor 호출을 통과하고, catch continuation 원본 RVA **0xABE9**를
  실행하려다 NX fault(0xC0000005, execute)로 종료함을 확인했다.
- 다음 필수 작업: catch continuation을 일반 함수-entry gateway로 취급하지 말고,
  원래 guest frame/virtual call stack/host routing 상태를 복구하는 VM resume 경로를
  구현해야 한다. 현재 native-entry gateway는 진입 RSP를 저장하고 RET하므로
  함수 중간으로 복귀하는 continuation에 그대로 사용할 수 없다.
- 별도 남은 위험: native re-entry의 `(TID & 15, depth & 3)` counter 방식은
  충돌 thread의 비-LIFO 반환에서 살아 있는 lane을 재사용할 수 있다. 반복 디버깅 중
  9번에서 간헐적 host state 훼손도 관찰됐다. 성공한 한 번의 1~9 결과만으로
  동시성 문제가 완전히 해결됐다고 간주하지 않는다.
- **10~16 / 최종 checksum 미통과. 전체 완료 아님.**

### 2026-09-21 — catch continuation gateway 구현 진행

- Rust/MSVC catch funclet(0xAC70/0xACB0)이 `lea rax,[0xABE9]`로 부모 함수의
  중간 continuation을 반환함을 원본 디스어셈블리와 FH3 table로 확인했다.
- 실행 코드에서 명시적으로 주소를 취한 VM instruction boundary를 gateway inventory에
  포함하고, catch continuation 소유 함수의 direct caller return site(0x84DE)를
  역방향으로 추적한다. 일반 vtable callback과 resume continuation을 별도 집합으로
  분류해 callback에 JMP-style resume epilogue가 적용되지 않도록 했다.
- native gateway의 RAX code-pointer 반환값을 gateway로 바꾸는 공통 lookup을 추가했다.
  1,452개 gateway 각각에 전체 비교 코드를 복제했을 때 boot reserve를 초과했으므로,
  공유 helper + 16-byte mapping table로 선형화했다. 테이블은 DIR64 relocation에
  의존하지 않는 RVA 쌍이며 helper가 PEB ImageBase를 적용한다.
- resume gateway는 Windows가 CALL 없이 context restore로 진입한다는 점을 반영해,
  VM top-level RET 뒤 물리 RET를 중복 실행하지 않는다. RET lifter의 Temp6 반환
  주소를 state+0x50A0에 명시적으로 게시하고 해당 주소로 JMP한다. catch 0xABE9와
  stage caller 0x84DE까지 실제 실행이 전진했다.
- Windows TID의 하위 2비트 정렬 때문에 `(TID & 15)`가 4개 버킷만 사용하던 문제를
  할당/해제 양쪽의 `(TID >> 2) & 15`로 수정했다. stage 9 간헐 충돌 빈도는 줄었으나
  counter wrap/non-LIFO 재사용 자체를 제거하는 bitmap allocator는 아직 필요하다.
- 최신 산출물 `verify-seh-resume-target.failed.exe`는 구조 검사를 통과하고 1~9가
  일치하며 10번에서 세 번의 의도된 C++ exception/catch를 처리한다. 그러나 0x84DE
  이후 main continuation이 top-level VirtualRet가 아닌 stream Halt로 조기 종료되어
  게시된 resume target이 0이고 access violation으로 종료한다. 로그:
  `verify-seh-resume-target.log`, `verify-seh-resume-target-debug*.log`.
- 다음 작업은 0x84DE fresh resume의 cross-family call/return 경로에서 module-end Halt로
  빠지는 source route를 식별하고, suspended parent state를 복구하거나 resume root의
  virtual-return ownership을 끝까지 유지하는 것이다. 원본 `.text` 실행 권한 복원이나
  data 주소를 return PC로 추정하는 fallback은 사용하지 않는다.
- focused gateway/inventory tests는 통과. 전체 differential은 아직 실패하므로
  **완료 상태가 아니다.**
