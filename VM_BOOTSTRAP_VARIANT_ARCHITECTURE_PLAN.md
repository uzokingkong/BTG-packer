# 보호 부트로더 가상화 · 빌드별 VM 변형 · 다중 VM 아키텍처 계획

작성일: 2026-10-03 (Asia/Seoul)
상태: 설계 제안. 이 문서 작성은 신규 기능 구현이나 실행 검증 완료를 뜻하지 않는다.
범위: 직접 소유하거나 보호 권한이 있는 소프트웨어의 오프라인 IP 보호와 실행 의미 보존.

## 1. 세 가지 목표

| 축 | 만들려는 기능 | 완료를 판단하는 증거 |
|---|---|---|
| 보호 부트로더 가상화 | 원본 프로그램뿐 아니라 실행 준비 단계의 선정된 로직도 Boot VM에서 실행 | 단계별 소유권, 실제 VM 실행 경로, native 잔존 목록, 부팅 동등성 |
| 빌드별 VM 변형 | register/state layout, handler 구성, opcode encoding을 하나의 불변 VariantPlan으로 생성 | 동일 seed 재현, 다른 seed 간 구조 차이, encoder/runtime 계약 일치 |
| 여러 VM 아키텍처 | stack/register/mixed/fused 계열의 실제 상태·명령 의미·호출 규약 차이를 구현 | 계열별 reference/native 동등성, 교차 호출·예외 테스트, 실제 구조 차이 |

목표는 분석 결과의 재사용 범위를 줄이는 것이다. VM 종류나 파일 크기의 증가 자체를 성공 조건으로 삼지 않는다. 오프라인 실행에 필요한 키·평문·주소가 실행 관찰로 회수될 수 있다는 한계도 유지한다.

신규 debugger/보안 제품 회피, 환경별 실행 방해, 분석 도구 공격은 이 계획의 범위가 아니다. MBA 추가 역시 암호학적 키 보호나 독립 아키텍처 구현을 대신하지 않는다.

## 2. 현재 작업 트리와 출발점

이번 문서 작성 중 확인한 사실:

- `src/vm/poly/architecture_family.rs`에 Stack/Register/MixedRisc/FusedCisc 네 계열, dispatch topology, flag model, call convention의 profile이 선언돼 있다.
- `src/vm/multi_family.rs`에 family별 partition, gateway, cross-family route 구조가 있다.
- `src/pipeline/crypto/bootstub/stages.rs`에는 native stage 준비·초기화 코드가 있다. VM으로 감싼 진입점과 native helper 자체의 가상화는 구분해야 한다.
- `HANDLER_CODEC.md`와 기존 hardening 문서는 opt-in PRF/private key와 MBA 변형을 기록한다. `BOOT_STAGE_AEAD.md`는 stage 인증·복호화와 bootstrap root의 잔존 한계를 별도로 설명한다.

문서에 기록된 이전 테스트 수치는 이번 계획서 작성 과정에서 재실행하지 않았다. 문서별 version·테스트 수치가 다를 수 있으므로 P0에서 실제 소스 revision, 실행 파일 hash, ABI version으로 baseline을 다시 묶는다.

네 enum 값이 존재한다는 사실만으로 네 개의 독립적인 VM 아키텍처가 완성됐다고 판단하지 않는다. 실제 emitter·state·decoder·bridge가 profile을 소비하는지 확인해야 한다.

## 3. 유지할 확정 정책

- seed-only 기본 유지. private build key는 명시적 선택 기능이다.
- 같은 입력·seed·옵션·private key·보호기 버전이면 같은 VariantPlan을 만든다.
- literal 보호는 map/catalog의 승인 경계를 유지한다. heuristic 후보는 자동 승인하지 않는다.
- pre-boot/TLS에서 접근하는 literal과 loader metadata는 일반 OEP 복호화 대상으로 편입하지 않는다.
- dispatch hot path 최우선. PRF·해시·KDF·할당은 초기화/빌드 단계에 둔다.
- GUI/message loop, MPSC, spin/backoff, wait/polling, allocator·문자열 hot path의 native 유지 정책을 보존한다.
- private key/map/catalog/cache는 release whitelist 밖에 둔다. public manifest에는 필요한 version·집계만 포함한다.

## 4. 전체 실행 경계

```text
Windows loader / 기존 TLS
          ↓
최소 Native Bootstrap
          ↓
인증·검증된 Boot VM 프로그램
          ↓
Program VM 초기화 및 native bridge 준비
          ↓
Program VM / 승인된 native 경로
```

### 4.1 순환 의존성을 끊는 원칙

Boot VM을 실행하려면 VM core, 초기 state, 필요한 bytecode를 먼저 준비해야 한다. 그 준비 전체가 아직 실행할 수 없는 Boot VM에 의존하면 부팅할 수 없다.

따라서 최소 native bootstrap은 명시적으로 남긴다. 고정 형식의 초기 descriptor bounds 확인, 필요한 state 확보, Boot VM 진입 계약 등 최소 기능을 담당한다. loader가 이미 소비하는 metadata와 Windows 호출 경계도 임의로 제거하지 않는다.

정확히 무엇이 native로 남는지 private inventory와 public 집계로 보고한다. bootstrap root가 남았는데 “부트로더 전체가 VM으로만 보호된다”고 표시하지 않는다.

### 4.2 인증과 해석 순서

각 단계의 입력은 bounds 검증 → 해당 범위의 인증 → 의미 해석/복호화 → state 공개 순서로 처리한다. stage 인증과 가상화는 별개 기능이며, 가상화 때문에 기존 인증을 제거하거나 실패를 무시하지 않는다.

준비되지 않은 state로 dispatch하지 않는다. 실패 상태는 정상 Program VM 진입으로 연결하지 않으며, 부분 초기화 자원과 소유권을 명확히 정리한다.

## 5. 축 A — 보호 부트로더 자체 가상화

### A1. 먼저 native boot inventory를 만든다

`bootstub/build.rs`, `emit.rs`, `stages.rs`, `ctx.rs`와 연결 helper를 아래 역할로 분류한다.

| 역할 | 초기 정책 | 반드시 확인할 것 |
|---|---|---|
| loader/TLS/최초 진입 계약 | 최소 native 유지 | 실행 시점, Win64 ABI, relocation |
| descriptor·stage 순서 관리 | Boot VM 이전 후보 | 인증 이전/이후 접근, 범위·오류 처리 |
| stage 인증·복호화 orchestration | Boot VM 이전 후보 | key/state 소유권, 인증 실패 경로 |
| 표준 crypto primitive helper | native 기준 경로 유지 후 opt-in 연구 | 실제 crypto 연산이 native에 남는지, 성능·동등성 |
| memory protection·OS 호출 | 제한된 native bridge | 호출 인자, stack alignment, nonvolatile 보존 |
| Program VM table/state 준비 | Boot VM 이전 후보 | PRF 초기화 완료와 ready publication |

단순히 native crypto helper 호출 앞뒤를 VM으로 감싸는 단계는 **orchestration 가상화**라고 표시한다. native crypto 분석 경로 자체가 사라졌다는 주장을 하지 않는다.

### A2. BootProgram IR과 stage contract

신규 제안: `src/vm/boot/program.rs`, `contract.rs`, `reference.rs`.

- stage 입력/출력, 읽기·쓰기 span, scratch ownership, 완료 조건을 표현한다.
- branch·loop·실패·정리 경로를 reference interpreter에서 먼저 검증한다.
- host pointer를 무제한으로 조작하는 명령 대신 승인된 bootstrap buffer/descriptor 범위를 사용한다.
- 반복 실행·재진입·실패 후 재사용 가능 여부를 stage마다 정의한다.
- native helper와 Boot VM state 사이의 인자/결과 ABI를 version으로 구분한다.

기존 Program VM의 모든 명령·bridge 기능을 그대로 Boot VM에 가져오지 않는다. 부팅에 필요한 제한된 의미부터 시작하며 지원하지 않는 stage는 명시적으로 native에 남긴다.

### A3. 단계별 이전 정책

1. 기존 native boot를 reference baseline으로 고정한다.
2. descriptor 순회와 stage 순서 제어부터 Boot VM으로 이전한다.
3. stage별 상태 준비·검증·정리 경로를 이전한다.
4. 표준 crypto 연산의 VM 실행은 별도 opt-in 실험으로 진행한다. 결과·태그·nonce/counter 계약 및 native 대비 비용을 먼저 확인한다.
5. 실제 이전된 로직과 남은 helper의 측정을 통해 정책을 승격한다.

초기화 중 PRF를 VM에서 실행해도 Program VM dispatch마다 PRF를 다시 계산하지 않는다. crypto primitive를 이전할 때 표준 알고리즘을 독자 cipher로 바꾸지 않는다.

### A4. 완료 기준

- 각 stage의 정상·오류·변조 입력에서 native baseline과 Boot VM 결과가 일치한다.
- 실행되지 않는 VM wrapper만 추가한 것은 보호율에 포함하지 않는다.
- Boot VM이 Program VM의 아직 초기화되지 않은 state/table에 의존하지 않는다.
- native 잔존 기능과 root·key·평문 관찰 한계를 명시한다.
- loader/TLS·예외·relocation·memory protection 계약을 유지한다.

## 6. 축 B — 빌드마다 VM 변형

### B1. 한 번만 생성하는 불변 VariantPlan

신규 제안: `src/vm/poly/variant_plan.rs`, `variant_validate.rs`.

```text
VariantPlan
  schema/version + module identity + family
  register/state layout
  opcode/operand encoding
  handler implementation selection
  table/dispatch layout
  bridge/flag/call ABI identity
```

plan은 canonical module identity, seed, 명시적 정책과 version에서 생성한다. 크기 예측, provisional placement, final placement가 같은 plan을 소비해야 한다. 각 emitter가 별도 RNG를 호출해 계약이 달라지는 구조를 금지한다.

공개 seed 기반 변화는 비밀이 아니다. private key를 쓰더라도 runtime에 필요한 state가 관찰될 수 있다. 구조 다양성과 키 비밀성을 별도로 평가한다.

### B2. 변형 대상과 불변 계약

| 변형 대상 | 바꿀 수 있는 부분 | 바꾸면 안 되는 의미 |
|---|---|---|
| register 위치 | physical state slot과 native register assignment | guest register 값, 호출 보존 규칙 |
| handler | 검증된 동등 구현 recipe, family별 lowering | 결과·flags·메모리·예외 동작 |
| opcode table | opcode 값·table layout·encoding 선택 | encoder와 fetch/decoder의 대응 |
| operand | 검증된 encoding 및 길이 형식 | 폭·부호 확장·주소 계산 |
| state layout | 정렬·slot 배치·scratch 구획 | buffer bounds·lane ownership·ready 계약 |

reserved opcode, unsupported encoding, 잘못된 table entry는 validation에서 거부한다. 변형 실패를 legacy로 조용히 바꿔 성공으로 보고하지 않는다.

### B3. handler 다양성과 MBA

MBA recipe는 여러 handler 구현 후보 중 하나로 취급한다. 현재 64-bit ADD recipe를 다른 폭·연산에 그대로 적용하지 않는다. carry-in, borrow, shift count, overflow와 flags가 다르므로 별도의 의미·차등 테스트를 요구한다.

단순 동등식 이름만 바뀌었는데 독립 구조 변형으로 집계하지 않는다. optimizer 결과도 확인하고, dispatch에 새 key derivation이나 무거운 계산을 추가하지 않는다.

### B4. 재현성과 cache

- 동일 조건의 plan serialization/digest가 같아야 한다.
- 다른 seed의 표본에서 layout/opcode/handler 선택이 실제로 달라졌는지 검사한다. 매번 모든 필드가 다르다는 보장은 하지 않는다.
- cache identity에 variant schema, family ABI, 실제 plan identity와 관련 key identity를 포함한다.
- 다른 version/family/plan의 module checkpoint는 거부한다.
- 중단·재개가 plan을 새로 추첨하지 않도록 한다.
- private diagnostics에는 세부 plan, public manifest에는 version·정책·집계만 둔다.

## 7. 축 C — 여러 VM 아키텍처 제공

### C1. 이름이 아니라 실행 모델을 구분한다

| 계열 | 목표 실행 모델 | 검증할 차이 |
|---|---|---|
| Stack | stack 중심 operand 전달·frame | stack effect, frame 경계, flags 보존 |
| Register | explicit virtual register 중심 | register liveness, call preservation, packed flags |
| MixedRisc | 제한된 primitive와 명시적 폭 변환 | lowering 의미, narrow width·sign extension |
| FusedCisc | 검증된 복합 명령과 continuation | fusion 내부 flags·fault order·resume 위치 |

현재 profile의 dispatch/flag/call convention 값과 실제 emitter를 대응시킨다. profile만 다르고 공통 decoder/상태/호출 모델을 그대로 쓰는 영역은 공유 구조로 보고한다.

### C2. 공통 semantics, 분리된 lowering

canonical instruction semantics와 guest memory contract는 공유한다. family별 encoding, lowering, state와 dispatch 구현은 명시적으로 분리한다. 공유 reference interpreter를 family 구현의 동등성 기준으로 사용하되, reference 하나와 비교한 사실만으로 구조 독립성을 증명하지 않는다.

처음에는 동일 테스트 함수 전체를 한 family로 실행한다. 그 다음 함수 단위 partition을 적용한다. 명령마다 family를 바꾸는 정책은 초기 범위에서 제외한다. bridge 비용과 오류 지점을 과도하게 늘리지 않는다.

### C3. CrossVmBridge ABI

기존 canonical register image/RFLAGS 경계를 검토하여 다음 계약을 version으로 고정한다.

- guest registers·flags·stack/memory view의 전달.
- call/return/tail-call과 continuation의 의미.
- exception/unwind와 원래 caller로의 복귀.
- nested call, recursion, reentry, state lane의 독점 소유권.
- 실패 시 어느 family가 자원을 소유하고 정리하는지.

route는 임의 family state offset을 직접 넘기지 않고 검증된 gateway/ABI를 사용한다. 서로 다른 family layout을 같은 buffer로 해석하지 않는다.

### C4. 적용 정책

Boot VM과 Program VM의 family 선택을 별도 정책으로 둔다. Boot VM에는 부팅 기능을 검증한 family만 허용한다. Program VM 지원 family라고 해서 Boot VM 사용도 자동으로 허용하지 않는다.

각 family별로 지원 명령·native 유지 사유·검증 상태를 capability matrix로 제공한다. 사용자가 요구한 family/보호 범위를 충족하지 못하면 명확히 실패하거나 승인된 partial 정책을 표시한다.

## 8. 구체적인 코드 작업 위치

신규 경로는 제안이며 이 문서 작성으로 생성하지 않는다.

| 코드 | 작업 |
|---|---|
| `pipeline/crypto/bootstub/{build,emit,stages,ctx}.rs` | native boot inventory, stage ABI, Boot VM 진입/복귀 연결 |
| `pipeline/crypto/stages.rs` | 기존 stage 도메인·인증 계약과 BootProgram의 대응 검증 |
| 신규 `vm/boot/{program,contract,reference,emit}.rs` | Boot IR, bounded buffer 계약, reference와 native 실행 경로 |
| 신규 `vm/poly/{variant_plan,variant_validate}.rs` | 불변 plan 생성·검증·serialization |
| `vm/poly/architecture_family.rs` | 선언 profile과 실제 기능의 capability 연결 |
| `vm/poly/isa_spec.rs` | encoder/runtime의 opcode·operand 계약 소비 |
| `vm/threaded/runtime_layout.rs` | family/variant별 state 구획·bounds·scratch validation |
| `vm/threaded/poly_direct/builder.rs` | plan 기반 handler/dispatch 소비, sizing/final 동일성 |
| `vm/threaded/poly_direct/handler_codec_emit.rs` | 기존 초기화 PRF와 variant/state ABI의 충돌 검사 |
| `vm/handler_table_codec.rs`, `vm/key_domains.rs` | version/context 정합성, 독립 도메인 유지 |
| `vm/multi_family.rs` | partition/gateway/bridge contract와 실제 runtime 검증 |
| `build_cache.rs` | plan/family/ABI 변화에 따른 checkpoint 분리 |
| `manifest.rs`, `release_export.rs` | public 집계와 private plan 분리, whitelist 유지 |
| `cli.rs`, `main.rs` | 명시적 opt-in, capability 실패, 일관된 진행률 |

CLI 제안: `--boot-vm-policy native|orchestration|selected-stages`, `--vm-variant-policy stable|seeded`, `--vm-family-policy single|function-partition`. 구체적인 이름과 기존 옵션과의 충돌 규칙은 구현 전에 확정한다. 현재 사용 가능한 옵션이라고 안내하지 않는다.

## 9. 검증과 성능 gate

### 9.1 기능 검증

1. native boot/reference BootProgram/native Boot VM의 stage별 결과·메모리 차등 비교.
2. seed-only/private-key, 같은 seed/다른 seed, fresh build/cache resume 조합.
3. 각 family와 모든 승인된 family bridge 쌍의 call/return/tail-call·중첩 호출.
4. integer width·flags·FP/SIMD의 지원 범위, memory fault·exception/unwind 순서.
5. 인증된 단계의 정상·변조·범위 초과·불완전 초기화 실패 경로.
6. TLS/pre-boot literal 제외, GUI/native hot path, ASLR/relocation/W^X 유지.
7. private map/key/cache/variant plan의 release 혼입 음성 테스트.

실행 fixture는 직접 생성한 controlled PE부터 사용한다. 사용자 EXE는 실행 권한과 부작용을 별도로 확인한다. 특히 실행이 금지된 `pb2.exe`는 사용하지 않는다.

### 9.2 구조 차이 검증

register slot, opcode/operand schema, handler 선택, state/dispatch 구조의 차이를 각각 기록한다. 한 계열의 decoder/state 가정을 다른 계열 표본에 적용했을 때 필요한 재작업을 통제된 평가로 비교한다. 단순 opcode 치환 차이는 architecture 차이와 별도로 집계한다.

공통 bridge·crypto helper·canonical metadata가 남아 있을 때의 재사용 가능한 분석 경로도 기록한다. 분석 도구가 실패했다는 사실만으로 보안을 증명하지 않는다.

### 9.3 성능 우선순위

- dispatch에 PRF/해시/KDF/할당이 없는지 구조적으로 검사한다.
- 동등 기능 기준으로 native 유지 baseline, orchestration Boot VM, selected-stage Boot VM을 비교한다.
- cold start, initialization p50/p95, dispatch steady-state, bridge 횟수/비용, peak memory, 파일 크기를 따로 측정한다.
- 초기 목표: dispatch median 회귀 5% 이내, 시작 시간 p95 회귀 10% 이내. 아직 달성한 수치가 아니며 실제 제품의 허용치로 조정한다.
- full crypto VM 실험이 예산을 초과하면 opt-in 상태로 남기고 성능 지향 native helper 정책을 유지한다.

## 10. 구현 순서와 승인 조건

| 단계 | 산출물 | 다음 단계 gate |
|---|---|---|
| P0 | revision/hash/ABI baseline, native boot·family 실제 소비 inventory | 문서와 실제 source/build 상태 정합성 |
| P1 | VariantPlan schema와 reference validation | seed 재현·plan 불변·cache 분리 |
| P2 | BootProgram IR와 native reference stage adapter | 정상·오류·정리 동등성, 순환 의존 없음 |
| P3 | orchestration Boot VM opt-in | 실제 VM 실행, native helper 잔존 보고, TLS/ABI 유지 |
| P4 | register/opcode/handler 변형 연결 | host/runtime 차등 검증, dispatch 예산 |
| P5 | family별 실제 lowering·state 계약 및 bridge 보강 | capability matrix와 모든 승인 bridge 쌍 검증 |
| P6 | selected-stage/crypto VM 실험 | 표준 crypto 동등성, 인증 순서·초기화 비용 gate |
| P7 | 제품 정책·release·통합 회귀 | 보호 범위·예외·성능·관찰 한계를 포함한 완료 보고 |

기본 배포 정책을 한 번에 바꾸지 않는다. native baseline과 이전 ABI를 비교 경로로 유지하고, 검증된 단계만 opt-in 승격 후 default 변경을 검토한다.

## 11. 최종 완료 보고 형식

“부트로더 VM 보호 완료” 대신 아래를 함께 보고한다.

- Boot VM에서 실제 실행한 stage와 native 잔존 기능.
- variant plan version, 재현 조건과 실제 구조 변형 지표.
- family별 실제 지원·미지원·native 유지 범위.
- bridge·예외·초기화·dispatch 검증 결과와 성능.
- private 자료의 배포 제외 검사 결과.
- 아직 관찰 가능한 bootstrap root, crypto helper, 평문과 공통 대응관계.

이 계획의 성공은 세 축이 각각 검증 가능한 계약과 실행 증거를 갖추는 것이다. 단순히 VM 안에서 native helper를 호출하거나 계열 이름·상수만 바꾼 상태를 동일한 완료 수준으로 취급하지 않는다.
