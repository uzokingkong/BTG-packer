# BTG VM 최상위 난독화·복원저항 강화 계획

## 0. 문서 목적과 기준

### 구현 진행 상태 (2026-09-27)

- [x] Phase 0 기초 측정기: semantic anchor, 연속 executable pointer table,
  recoverable entry, state displacement peak 측정 및 manifest 기록
- [x] Phase 1-A: 고정 `BTGI` magic 제거
- [x] Phase 1-B: build-local nonce header, descriptor field masking, 물리 순서 permutation
- [ ] Phase 1-C: 고정 40-byte record를 variable-width shard/tree grammar로 전환
- [ ] Phase 2 이후: 아래 의존 순서에 따라 진행

이 문서는 SHA-256 `257b5787ad6244ed5e052ad9dc6765c3704b6eed902208d3c38b1085084e7284`
산출물에 대한 실제 dispatcher/table/fetch/handler 분석 결과를 현재 소스 구조와 대조한
구현 계획이다. 목표는 단순히 정적 시그니처를 더 추가하는 것이 아니라, 공격자가 한 번
만든 devirtualizer를 다음 빌드·다른 함수·다른 경로에 재사용하기 어렵게 만드는 것이다.

보호의 현실적인 목표는 “복원 불가능”이 아니다. 다음 비용을 동시에 높이는 것이 목표다.

1. VM runtime과 메타데이터의 자동 식별 비용
2. opcode/operand/fetch 문법 복원 비용
3. handler semantic 정규화 비용
4. 한 family 분석 결과를 다른 family와 다음 빌드에 재사용하는 비용
5. native island만 분석해 핵심 로직을 우회 복원하는 비용
6. 정적 분석 결과를 동적 trace와 결합하는 비용

성능, unwind 정확성, Win64 ABI, TLS/CRT 안정성은 보안 강도보다 우선하는 절대 게이트다.

---

## 1. 현재 구현의 강점과 실제로 노출된 경계

### 이미 존재하므로 보존·확장해야 하는 기능

- 4개 architecture family와 family별 ISA domain
- build seed 기반 opcode/register/condition permutation
- variable-width typed operand encoding
- rolling bytecode state와 instruction-aligned crypto epoch
- encoded handler table과 family별 integrity topology
- super-operator 선정 및 multi-family route
- Program-VM bytecode의 at-rest 암호화
- native island relocation, 원본 `.text` 폐기, 원본 `.pdata` 제거
- 분산 integrity descriptor
- section-name camouflage

### 분석문이 증명한 핵심 약점

| 약점 | 공격자가 얻는 것 | 근본 원인 |
|---|---|---|
| 256-entry table을 정적으로 전부 복원 가능 | opcode → handler 전역 map | table entry 복호화가 opcode와 build-local 상수만의 함수 |
| handler body가 정상적인 x64 semantic | 자동 semantic classifier | handler가 크고 단일 의미를 직접 구현 |
| family architecture가 상당 부분 동일 | family 0 lifter를 1~3에 재사용 | 공통 dispatcher/operand/state ABI |
| state offset이 고정 | virtual register와 control slot mapping | 컴파일 타임 상수 `STATE_*`, `OFF_*`가 native code에 반복 노출 |
| fetch transition이 결정론적 | offline bytecode decoder | 초기 상태와 전이식이 executable에 완결되어 있음 |
| BTGI descriptor가 연속 영역 지도를 제공 | family/partition 경계 자동 식별 | 고정 magic, 고정 record 크기, 정렬된 연속 descriptor |
| `.nisland`에 597 unwind range | native call graph anchor | 성능 우선 ownership 정책이 민감도와 무관하게 대량 demotion |
| ASLR 비활성 | VA와 의미의 빌드 간 안정성 | ciphertext relocation 회피를 위해 reloc directory 제거 |
| 거대한 state bank가 규칙적 | 노이즈 제거 후 lane 구조 복원 | 고정 stride와 대규모 zero-fill 예약 |

---

## 2. 최종 목표 아키텍처

최종형은 다음 불변식을 만족해야 한다.

```text
Function/region
  └─ ISA epoch N
       ├─ epoch-local opcode alphabet
       ├─ epoch-local operand grammar
       ├─ epoch-local state layout view
       ├─ path-derived decode state
       └─ multiple equivalent semantic fragments

dispatcher site
  └─ site-local topology/table encoding
       ├─ no globally reusable 256-entry map
       ├─ handler fragments selected by state/path
       └─ authenticated transition checkpoint
```

VM의 canonical semantic과 ABI는 빌드 내부 IR에만 존재하고, 최종 native runtime에는 전역
고정 mapping이 없어야 한다.

---

## 3. 단계별 구현 계획

## Phase 0 — 공격자 관점 측정기와 회귀 게이트

### 목적

강화 기능을 먼저 추가하기 전에 현재 샘플에서 성공한 분석 절차를 자동화해 회귀 테스트로
고정한다. “코드가 복잡해 보인다”가 아니라 실제 추출 성공률을 측정한다.

### 신규 파일

- `src/analysis/vm_exposure.rs`
  - dispatcher 후보 탐지
  - 256-entry table 후보와 유효 target 비율 측정
  - state displacement 빈도 histogram
  - 연속 integrity descriptor 탐지
  - native island 함수/바이트/민감 함수 비율 측정
- `src/pipeline/reports/vm_resistance.rs`
  - JSON/텍스트 보고서
  - 빌드 간 signature 재사용률
- `tests/adversarial_vm_exposure.rs`
  - 알려진 정적 extractor가 새 산출물에서 실패하는지 검증

### 수정 파일

- `src/pipeline/validate.rs`
  - 구조 검증과 별도로 exposure budget 검증 추가
- `src/manifest.rs`
  - 아래 지표 기록

```text
recoverable_handler_entries
dispatcher_signature_reuse
state_offset_peak_frequency
integrity_partition_leak_count
native_sensitive_functions
aslr_preserved
```

### 완료 기준

- 현재 샘플에서 첫 family table 복원 가능 항목이 180개 이상으로 측정돼야 한다.
- 이후 단계마다 동일 측정기의 수치가 감소해야 한다.
- 측정기 자체는 debug/private artifact에서만 활성화하고 production image에는 포함하지 않는다.

---

## Phase 1 — 고정 magic과 연속 partition 지도 제거

### 문제

`src/vm/distributed_integrity.rs`의 `BTGI` magic, 고정 40바이트 descriptor, 정렬된
`offset/len` 배열이 VM family와 보호 영역의 지도를 제공한다.

### 신규 파일

- `src/vm/integrity_layout.rs`
  - `IntegrityLayoutPlan`
  - build별 record permutation
  - field permutation
  - variable-width delta/length encoding
  - descriptor chaining topology
- `src/vm/integrity_codec.rs`
  - 생성기와 runtime emitter가 공유하는 명세

### 수정 파일

- `src/vm/distributed_integrity.rs`
  - `SERIALIZED_TABLE_MAGIC` 제거
  - 고정 `SERIALIZED_DESCRIPTOR_SIZE` 제거
  - offset 순 정렬 금지
  - descriptor를 family code/table/state metadata 사이에 분산
- `src/pipeline/crypto/place/vm_build.rs`
  - 하나의 연속 table RVA 대신 shard RVA 목록 전달
- `src/vm/threaded/poly_direct/builder.rs`
  - 선형 descriptor loop를 build별 traversal grammar로 변경
- `src/pipeline/validate.rs`
  - 고정 magic이 아니라 build-time `IntegrityLayoutPlan`으로 재검증

### 설계

- descriptor의 실제 offset/len은 직접 저장하지 않고 이전 노드와 runtime anchor에서 파생한다.
- descriptor node 순서는 물리 주소 순서와 무관하게 permutation한다.
- 각 family는 자기 shard만 알고, root는 모든 descriptor를 직접 나열하지 않는다.
- 최소 두 개의 layout grammar를 구현한다.
  - keyed linked walk
  - balanced tree walk
- production 파일에서 `BTGI` 문자열과 고정 record stride가 없어야 한다.

### 완료 기준

- 파일 전체에서 `BTGI` magic 0회.
- descriptor raw scan만으로 family 시작/끝을 연속 복원할 수 없어야 한다.
- descriptor 하나 변조 시 관련 family 진입 전에 fail-closed.

---

## Phase 2 — ASLR 복원과 절대 VA 의미 제거

### 문제

고정 ImageBase와 대량의 `mov reg, imm64`가 state/code/table 주소를 분석가에게 안정적으로
제공한다. 현재 relocation builder가 존재하지만 ciphertext와 생성 코드의 모든 absolute VA를
안전하게 분리하지 못해 production profile에서 ASLR이 꺼진다.

### 신규 파일

- `src/pe/reloc_audit.rs`
  - 생성 코드의 모든 image-relative absolute slot inventory
  - encrypted range와 loader-relocated range의 교집합 fail-closed
- `src/vm/address_materialization.rs`
  - RIP-relative anchor + encoded RVA 기반 주소 생성 emitter

### 수정 파일

- `src/pe/reloc.rs`
  - 단순 imm64 pattern scan을 typed fixup registry 중심으로 전환
- `src/pipeline/build.rs`
  - production VM profile에서 `.reloc`과 `DYNAMIC_BASE/HIGH_ENTROPY_VA` 필수화
- `src/pipeline/crypto/place/vm_build.rs`
  - family code/state/table absolute VA 전달을 RVA 또는 anchor-relative delta로 변경
- `src/vm/threaded/poly_direct/builder.rs`
  - 반복되는 state/table/bytecode `imm64`를 module anchor에서 복원
- `src/pipeline/crypto/bootstub/*`
  - module base 획득을 PEB ImageBase 또는 RIP-relative anchor로 통일
- `src/pipeline/validate.rs`
  - production VM에서 ASLR이 꺼지면 실패

### 완료 기준

- 같은 파일을 서로 다른 base에 강제 매핑해 20회 실행 성공.
- 생성 코드의 loader-mutated slot이 ciphertext 내부에 0개.
- static disassembly에서 canonical state VA가 반복 상수로 나타나지 않음.

---

## Phase 3 — build별 State ABI와 lane layout 합성

### 문제

`src/vm/threaded/poly_direct/builder.rs`, `types.rs`, `codegen_util.rs`에 고정된
`0x5000~0x5198` control slot과 고정 GPR/XMM offset이 반복 노출된다.

### 신규 파일

- `src/vm/state_layout_plan.rs`
  - `StateField` enum
  - build/family/epoch별 `StateLayoutPlan`
  - alignment, alias 금지, lifetime 검증
- `src/vm/state_access.rs`
  - 모든 handler가 사용하는 typed load/store emitter
  - raw displacement 직접 사용 금지

### 수정 파일

- `src/vm/threaded/runtime_layout.rs`
  - 고정 ABI 구조체를 `StateLayoutPlan` 소비 구조로 변경
- `src/vm/threaded/poly_direct/types.rs`
  - `STATE_*` 상수를 논리 field ID로 교체
- `src/vm/threaded/poly_direct/codegen_util.rs`
  - `OFF_*`, `REGS_OFF`, `XMM_OFF` 직접 참조 제거
- `src/vm/threaded/poly_direct/builder.rs`
  - 모든 state access를 `StateAccessEmitter`로 이동
- `src/pipeline/crypto/place/vm_build.rs`
  - 고정 `MULTI_FAMILY_STATE_STRIDE=0x8000` 제거
  - family/lane별 randomized stride와 sparse placement 사용
- `src/vm/data_lifetime.rs`
  - lifetime sync field를 plan에서 할당

### 설계 제약

- GPR/XMM/control/call-stack/cache 영역은 서로 겹치지 않아야 한다.
- Win64 unwind 및 native bridge가 접근하는 최소 필드는 별도 ABI view로 export한다.
- 한 family 내부에서도 모든 lane이 동일 offset을 쓸 필요는 없지만, hot-path 비용을 고려해
  `family layout + lane delta` 2단계로 시작한다.
- 774 MiB zero-fill state bank는 보안 효과 대비 fingerprint가 강하므로, 실제 동시성 상한에서
  계산된 compact reservation으로 축소한다.

### 완료 기준

- 두 seed 산출물의 state displacement 상위 20개 교집합이 20% 미만.
- 특정 displacement 하나가 모든 handler에서 동일 virtual register를 의미하지 않음.
- state reservation 크기가 계산된 lane 상한의 1.5배 이내.
- MPSC/GUI/native hot path 성능 저하 5% 이내.

---

## Phase 4 — 전역 256-entry handler map 제거

### 문제

현재 table entry key가 opcode/build 상수의 결정론적 함수라 dispatcher 하나를 역산하면
256개 target을 전부 복원할 수 있다.

### 신규 파일

- `src/vm/dispatch_topology.rs`
  - `Tableless`, `TwoLevel`, `Bucketed`, `ThreadedDelta` topology
- `src/vm/handler_selector.rs`
  - site/epoch/path state를 포함한 target derivation

### 수정 파일

- `src/vm/dispatch_perm.rs`
  - family 단위 plan에서 dispatcher-site 단위 plan으로 확장
- `src/vm/table_layout.rs`
  - 256×8 고정 table 전제 제거
- `src/vm/threaded/poly_direct/checksum.rs`
  - 새 topology별 integrity 계산
- `src/vm/threaded/poly_direct/builder.rs`
  - dispatcher site마다 다른 lookup grammar emitter
- `src/vm/threaded/poly_direct/metadata.rs`
  - table 위치/크기 고정 offset 제거
- `src/vm/commercial_build.rs`
  - function/region별 dispatcher plan 전달

### 단계적 구현

1. 256 table을 16×16 keyed two-level table로 분리한다.
2. first-level bucket permutation은 epoch state에서 파생한다.
3. second-level entry는 handler absolute pointer 대신 signed delta + selector tag를 저장한다.
4. 동일 semantic에 최소 2개 handler variant를 두고 path state로 선택한다.
5. 일부 epoch는 tableless compare/tree 또는 computed delta topology를 사용한다.

### 완료 기준

- dispatcher 한 개를 완전히 분석해도 다른 function/epoch의 map 복원률 10% 미만.
- 파일 어디에도 256개의 executable pointer/delta가 일정 stride로 존재하지 않음.
- invalid/trap slot 비율과 위치가 epoch마다 달라야 함.

---

## Phase 5 — Handler semantic body 분할·다형화

### 문제

handler routing은 복잡하지만 실제 body는 정상적인 x64로 한 semantic을 직접 수행한다.
분석가는 trampoline을 정규화한 뒤 symbolic execution으로 `SAR`, load/store 등을 분류할 수 있다.

### 신규 파일

- `src/vm/handler_templates.rs`
  - semantic별 3개 이상의 동치 template
- `src/vm/handler_fragments.rs`
  - fetch/decode/execute/flags/writeback fragment graph
- `src/vm/semantic_mba.rs`
  - 폭/flags 정확성을 보존하는 검증된 MBA rewrite

### 수정 파일

- `src/vm/threaded/poly_direct/builder.rs`
  - monolithic handler 생성 대신 fragment graph materialization
- `src/vm/threaded/super_ops.rs`
  - 단순 opcode fusion을 넘어 fragment interleaving 지원
- `src/vm/risc/semantic_splice.rs`
  - semantic-preserving split point 생성
- `src/vm/canonical_semantics.rs`
  - template별 differential oracle 제공
- `src/vm/flags.rs`, `src/vm/risc/flags.rs`
  - flags MBA의 정확성 검증 API

### 구현 원칙

- 모든 handler에 무차별 MBA를 적용하지 않는다. hot handler에는 작은 variant를, 민감 semantic에는
  split + opaque dependency + variant를 적용한다.
- decode와 execute를 항상 분리된 함수로 두지 않는다. 일부 variant는 operand decode를 semantic
  중간에 섞는다.
- writeback과 flags update 순서를 dependency가 허용하는 범위에서 변형한다.
- 동일 semantic의 handler entry가 여러 개 존재하고, entry 선택은 opcode만으로 정해지지 않아야 한다.
- 단순 junk branch는 제거하기 쉬우므로 실제 state/path dependency를 사용한다.

### 완료 기준

- semantic classifier가 handler entry 하나만 보고 canonical RiscOp를 맞히는 비율 40% 미만.
- 동일 RiscOp 두 seed의 normalized CFG hash 일치율 15% 미만.
- 전체 differential/fuzz suite에서 flags, fault, memory side effect 완전 일치.

---

## Phase 6 — Function/region별 ISA epoch

### 문제

현재 `VirtualIsaSpec`은 family/build seed 중심이다. family 하나를 복원하면 해당 family의 전체
프로그램에 opcode/operand 문법을 재사용할 수 있다.

### 신규 파일

- `src/vm/poly/isa_epoch.rs`
  - `IsaEpochId`, `IsaEpochSpec`, transition contract
- `src/vm/poly/epoch_planner.rs`
  - function size, CFG, hotness에 따른 epoch 경계 선정

### 수정 파일

- `src/vm/poly/isa_spec.rs`
  - seed domain에 function/region/epoch ID 포함
  - operand marker order와 descriptor grammar도 epoch별 생성
- `src/vm/poly/encoder.rs`, `decoder.rs`
  - instruction stream 중 epoch transition 지원
- `src/vm/multi_family.rs`
  - family partition 안에 여러 epoch 포함
- `src/vm/threaded/poly_direct/builder.rs`
  - epoch-local dispatcher/table/state view 로딩
- `src/vm/chunk_crypto.rs`
  - crypto epoch와 ISA epoch를 반드시 1:1로 고정하지 않고 독립 domain으로 관리

### 정책

- 최소 단위는 function이며 민감 함수는 basic-block cluster 단위로 세분한다.
- 모든 basic block마다 ISA를 바꾸는 것은 code size와 branch cost가 과도하므로 초기 목표는
  16~64 instruction/epoch이다.
- branch target은 target epoch 인증 token을 포함한다.
- cross-epoch transition은 opcode map, operand grammar, rolling state를 동시에 갱신한다.

### 완료 기준

- 한 family에 최소 16개 이상의 실제 ISA epoch.
- epoch A의 opcode map으로 epoch B를 decode할 때 유효 instruction 비율 5% 미만.
- epoch transition metadata만으로 전체 opcode map을 복원할 수 없어야 함.

---

## Phase 7 — Path-dependent bytecode control-flow encryption

### 문제

rolling fetch는 선형 분석 비용을 높이지만 초기 key와 transition을 복원하면 offline decoder로
전체 stream을 순회할 수 있다. branch resync 정보도 metadata에 존재한다.

### 신규 파일

- `src/vm/path_crypto.rs`
  - predecessor edge, branch outcome, call depth를 포함한 decode-state 전이
- `src/vm/checkpoint_graph.rs`
  - 인증된 최소 checkpoint와 join policy

### 수정 파일

- `src/vm/poly/rolling_key.rs`
  - `(ciphertext, ip, state)` 외에 edge token과 epoch domain 포함
- `src/vm/poly/state_machine.rs`
  - branch/call/return별 state transition 분리
- `src/vm/poly/encoder.rs`
  - CFG edge별 target entry state 생성
- `src/vm/threaded/poly_direct/builder.rs`
  - branch taken/not-taken와 call/return에 서로 다른 state commit
- `src/vm/multi_family.rs`
  - cross-family route token에 source edge identity 포함
- `src/vm/route_metadata.rs`
  - plaintext target/VIP mapping 제거, authenticated encoded edge record 사용

### join 처리

CFG join마다 predecessor별로 서로 다른 ciphertext를 복제하면 크기가 폭증한다. 다음 순서로 구현한다.

1. 민감 함수에만 predecessor-specific entry capsule 적용
2. capsule이 canonical block-local key를 unwrap
3. capsule은 source edge state가 없으면 유효 key를 만들 수 없음
4. indirect branch는 complete target set별 capsule table을 사용

### 완료 기준

- entry initial state 하나만으로 전체 bytecode를 선형 복호화할 수 없음.
- 잘못된 predecessor에서 target block decode 시 첫 1~3 instruction 안에 인증 실패.
- branch trace 없이 recovered CFG coverage 30% 미만.

---

## Phase 8 — Superoperator와 semantic fusion 확대

### 문제

현재 super-op가 존재하지만 보고된 build에서는 4개 build-local super-op로 제한된다. canonical
handler 분류 후에는 많은 stream이 다시 원래 semantic sequence로 정규화될 수 있다.

### 수정 파일

- `src/vm/threaded/super_ops.rs`
  - 빈도뿐 아니라 민감도·CFG 경계·data dependency 기반 후보 선정
- `src/vm/risc/opt.rs`
  - reversible optimization과 protection fusion 분리
- `src/vm/risc/semantic_splice.rs`
  - 여러 원본 instruction을 하나의 fused semantic DAG로 변환
- `src/vm/threaded/poly_direct/builder.rs`
  - build-local fused handler fragment 생성

### 정책

- hot path: 2~4 op fusion
- 민감 cold path: 4~12 op fusion
- compare+branch, address calculation+load, crypto round fragment 같은 의미 단위를 우선한다.
- 같은 sequence라도 context에 따라 서로 다른 fusion boundary를 사용한다.

### 완료 기준

- 민감 함수 VM dispatch 수 40% 이상 감소.
- canonical single-op handler만으로 복원 가능한 instruction 비율 50% 미만.
- code size 증가는 전체 산출물의 20% 이하.

---

## Phase 9 — Native island 정보 누출 축소

### 문제

597개의 unwind function과 약 119 KiB 실제 함수 본문이 call graph와 semantic anchor를 제공한다.
단순히 전부 VM화하면 성능과 Win64 unwind/TLS 안정성이 깨질 수 있으므로 정책 개선이 필요하다.

### 신규 파일

- `src/pipeline/sensitivity.rs`
  - 상수 비교, crypto, license/validation, final decision, UI sink까지의 backward slice
- `src/pipeline/native_budget.rs`
  - hotness·SEH·ABI·민감도를 함께 고려한 native budget

### 수정 파일

- `src/vm/text_lift/commercial.rs`
  - `performance-critical-native` 결정을 함수 전체가 아니라 loop/SCC region 단위로 축소
- `src/pipeline/ownership.rs`
  - `SensitiveMustVm`, `NativeLeafAllowed`, `NativeRuntimeRequired` 추가
- `src/pipeline/native_island.rs`
  - 함수 순서 randomization
  - alignment/padding diversity
  - direct edge를 gateway/call-token으로 선택적 분리
- `src/pipeline/build.rs`
  - `.pdata`가 native semantic 순서를 그대로 드러내지 않도록 island 배치 순서와 독립 정렬

### 정책

- GUI/MPSC/spin/wait/allocator/string hot path는 native 유지 가능.
- 결과 판정, 핵심 알고리즘, secret-dependent branch는 성능보다 VM ownership 우선.
- 큰 native 함수는 hot loop만 native helper로 추출하고 orchestration은 VM에 둔다.
- unwind 때문에 native인 함수는 가능한 경우 generated cleanup/unwind bridge로 대체한다.

### 완료 기준

- native island 함수 수를 597에서 250 이하로 단계적 축소.
- 민감도 상위 함수의 native 잔존 0개.
- GUI/MPSC benchmark 저하 10% 이내.
- panic/catch/TLS/정상 종료 반복 100회 성공.

---

## Phase 10 — Family architecture 실질적 비대칭화

### 문제

현재 family는 opcode/register/operand order가 다르지만 전체 direct-threaded architecture와 state ABI가
공유된다. family 0 분석 결과가 나머지 family에 빠르게 전이된다.

### 수정 파일

- `src/vm/poly/architecture_family.rs`
  - 단순 profile 상수에서 실행 모델 contract로 확장
- `src/vm/threaded/poly_direct/builder.rs`
  - family별 fetch/dispatch/operand pipeline 분리
- `src/vm/poly/operand_packing.rs`
  - family별 descriptor 문법 차등화
- `src/vm/threaded/runtime_layout.rs`
  - family별 state view

### family 목표

- Stack: stack-threaded, implicit operands 중심
- Register: direct-threaded, explicit register descriptors
- MixedRisc: token-threaded micro-op packets
- FusedCisc: variable-length fused instruction records

family 간 공유하는 것은 canonical semantic oracle와 native bridge ABI뿐이어야 한다.

### 완료 기준

- family 0용 decoder/lifter가 다른 family에서 유효 opcode 10% 이상 생성하지 못함.
- dispatcher normalized CFG hash의 family 간 유사도 30% 미만.
- 각 family별 독립 differential suite 통과.

---

## Phase 11 — Metadata·섹션·layout 외형 최소화

### 현재 완료된 부분

- `--section-name-mode semantic|seeded|random`
- 원본 `.text` decoy 폐기
- 의미형 VM 섹션명 제거 가능

### 추가 수정

- `src/pe/builder.rs`
  - 생성 섹션 순서 build별 permutation
  - 단, RVA를 사전에 사용하는 codegen과 2-pass layout 계약 필요
- `src/pipeline/section_names.rs`
  - 이름뿐 아니라 role별 plausible characteristic/name pairing 검증
- `src/pipeline/crypto/place/mod.rs`
  - 작은 `.vmeta`/`.vmroute` shard를 일반 read-only data section에 병합하는 옵션
- `src/pipeline/rsrc_register.rs`
  - payload 전체를 연속 resource chunk로 노출하지 않고 authenticated scatter layout 적용

### 완료 기준

- section name만으로 VM role을 분류할 수 없음.
- section 순서와 개수가 seed에 따라 달라짐.
- DataDirectory와 권한만으로도 route/integrity metadata의 정확한 경계를 바로 얻을 수 없음.

---

## Phase 12 — Anti-analysis는 보조 계층으로 제한

안티디버깅을 과도하게 강화하면 정상 환경 오탐과 지원 비용이 급증한다. 구조적 복원저항을 먼저
완료하고 다음은 선택적 정책으로 둔다.

### 수정 후보

- `src/dispatcher/antidebug.rs`
  - 단일 startup check가 아니라 VM epoch transition에 저빈도 integrity challenge 삽입
- `src/vm/seed_lifecycle.rs`
  - debug detection 결과를 직접 종료가 아닌 key-domain poison에 제한적으로 혼합

### 금지 사항

- 정상 시스템에서 불안정한 undocumented kernel behavior 의존
- 무조건적인 timing threshold
- 사용자 데이터·시스템을 손상시키는 대응
- 분석 저항과 무관한 대량 junk/무한 loop 남발

---

## 4. 공통 설정과 신규 CLI

### 신규 파일

- `src/vm/hardening_profile.rs`

### 제안 옵션

```text
--vm-hardening balanced|strong|max
--vm-isa-epoch function|region
--vm-dispatch-topology mixed
--vm-state-layout seeded
--vm-sensitive-native-budget 0
--vm-path-crypto
--vm-metadata-scatter
```

`--vm-hardening max`는 개별 boolean을 단순히 켜는 방식이 아니라 상호 호환되는 profile을 resolve해야
한다. `src/protection_profile.rs`가 유일한 정책 결정 지점이어야 한다.

### profile별 기본값

| 항목 | balanced | strong | max |
|---|---:|---:|---:|
| ISA epoch | function | 32~64 ops | 16~32 ops |
| handler variants | 2 | 3 | 4+ |
| path crypto | 민감 함수 | 대부분 | 전체 VM CFG |
| state layout | family별 | epoch view | epoch+lane view |
| native island | 성능 우선 | 민감도 우선 | 최소 runtime만 |
| metadata scatter | 2 shards | family shards | epoch tree |

---

## 5. 테스트 전략

## 5.1 의미 정확성

- canonical interpreter vs generated native VM differential test
- flags 전체 조합 fuzz
- memory fault 주소/예외 유형 parity
- signed/unsigned mul/div, shift count, high-byte register
- SSE/FPU NaN, rounding, conversion edge cases
- cross-family call/tail-call/return
- panic/catch_unwind/TLS destructor/Once poisoning

관련 기존 테스트:

- `src/vm/self_test/*`
- `src/vm/risc/fault_parity_tests.rs`
- `src/vm/risc/bridge_abi_tests.rs`
- `src/vm/threaded/poly_direct/poly_direct_tests.rs`

## 5.2 보안 회귀

- handler table linear recovery test
- normalized handler CFG similarity test
- fixed state displacement frequency test
- BTGI/fixed magic scan
- build-to-build opcode/operand grammar reuse test
- entry seed만으로 full bytecode linear decode 가능한지 테스트
- sensitive function native ownership audit
- semantic string/constant/plain `.text` scan

## 5.3 성능

- GUI message loop
- MPSC `recv`/`try_recv`
- spin/backoff
- `Sleep`/`WaitForSingleObject`
- event/timer polling
- allocator/string hot path
- VM/native transition rate
- dispatch/op, decode byte/op, cross-family transition latency

## 5.4 빌드 품질

- 동일 seed reproducibility
- random mode diversity
- 20개 seed pack+execute matrix
- ASLR forced-base matrix
- Windows 10/11 loader validation
- release artifact에 private map/symbol/evidence 0개

---

## 6. 구현 순서와 의존성

```text
Phase 0 exposure metrics
    ↓
Phase 1 metadata opacity ─────────────┐
Phase 2 ASLR/address materialization ├─ 기반 계층
Phase 3 state-layout plan ────────────┘
    ↓
Phase 4 dispatch topology
    ↓
Phase 5 handler polymorphism
    ↓
Phase 6 ISA epochs
    ↓
Phase 7 path crypto
    ↓
Phase 8 superoperator expansion
    ↓
Phase 9 native-island reduction
    ↓
Phase 10 family asymmetry
    ↓
Phase 11 layout/metadata finishing
```

Phase 2와 Phase 3을 먼저 끝내지 않고 Phase 6/7부터 구현하면 새 epoch마다 고정 VA와 고정 state
offset을 더 많이 노출하게 되므로 순서를 바꾸지 않는다.

---

## 7. 우선순위별 실전 마일스톤

### Milestone A — 분석 지도 제거

- Phase 0, 1, 2
- BTGI 제거
- ASLR 복원
- absolute VA 반복 제거
- 예상 효과: 자동 fingerprint와 partition recovery 비용 상승

### Milestone B — 한 family 분석 결과의 재사용 차단

- Phase 3, 4, 6
- state ABI permutation
- site-local dispatcher topology
- function/region ISA epoch
- 예상 효과: 첫 family 256 map 복원 성공이 전체 lifter로 바로 이어지지 않음

### Milestone C — semantic classifier 무력화

- Phase 5, 7, 8
- handler fragment/variant
- path-dependent entry capsule
- context-sensitive super-op
- 예상 효과: handler body symbolic classification과 offline linear decode 비용 상승

### Milestone D — 우회 분석 경로 축소

- Phase 9, 10, 11
- 민감 native 함수 0
- family 실행 모델 비대칭화
- metadata/layout scatter

---

## 8. 릴리스 게이트

다음 조건을 모두 만족하기 전에는 “최상위” profile을 production-ready로 표시하지 않는다.

1. `original_text_exec_bytes = 0`
2. `original_text_plain_bytes = 0`
3. 원본 `.text`를 가리키는 `.pdata` entry = 0
4. production VM profile에서 ASLR 활성
5. 의미형 VM section name/magic = 0
6. 민감 함수 native ownership = 0
7. 단일 dispatcher 분석으로 전체 handler map 복원 불가
8. entry key 하나로 전체 bytecode 선형 복호화 불가
9. 서로 다른 seed의 normalized handler CFG 재사용률 목표 이하
10. 20-seed 실행 동등성 100%
11. panic/TLS/멀티스레드/종료 반복 검증 100%
12. GUI/MPSC 핵심 workload 성능 예산 준수

---

## 9. 가장 먼저 구현할 구체적 작업

첫 구현 배치는 다음 4개로 제한한다.

1. `vm_exposure.rs`와 manifest 측정치 추가
2. BTGI 고정 magic/고정 descriptor record 제거
3. `StateLayoutPlan` 도입과 control slot 접근 abstraction
4. handler table을 2-level epoch-local topology로 전환

이 네 작업이 완료되면 첨부 분석자가 실제로 사용한 자동화 경로인
“magic으로 family 경계 탐색 → dispatcher 상수 역산 → 256 table 복원 → 고정 state offset으로
semantic 분류”가 한 번에 끊어진다. 이후 handler polymorphism과 path crypto를 추가해야 투자 대비
효과를 정확히 측정할 수 있다.
