# VM Semantic Leakage Hardening Plan

## 1. 목표와 위협 모델

이 계획의 목표는 VM handler 자체를 더 복잡하게 만드는 것이 아니라, 보호본에서
원본 프로그램의 의미 공간과 VM 실행 공간을 자동으로 다시 연결하지 못하게 하는
것이다. 공격자는 PE 정적 분석, 런타임 디버깅, 메모리 덤프, 원본/보호본 diff를 할
수 있으며, 빌드 seed와 비공개 evidence 파일은 모른다고 가정한다.

반드시 차단해야 하는 경로는 다음과 같다.

1. 원본 `.text` 함수에서 native/VM 경계를 따라 핵심 로직에 접근하는 경로.
2. 원본 VA와 VM VIP/bytecode offset을 대응시키는 branch/fixup/route metadata.
3. `.rdata` 문자열, stage 이름, format string, magic immediate를 의미 anchor로 쓰는 경로.
4. GUI ABI 인자에서 핵심 계산 결과를 역방향으로 추적하는 경로.
5. `.map`, `.sym`, ownership/evidence 파일이 배포물에 섞이는 경로.

## 2. 현재 확인된 P0 문제

### 2.1 원본 `.text`의 실행 및 평문 잔존

`src/pipeline/build.rs`는 commercial VM이 함수/블록/명령어 100%를 소유할 때만
원본 `.text`의 실행 속성을 제거한다. partial VM에서는 원본 함수가 실행 가능한
옆문으로 남는다. 완전 소유 빌드에서도 기존 구현은 NX만 적용하고 원본 바이트는
그대로 보존하므로 원본/보호본 diff와 함수 signature 복구가 가능하다.

### 2.2 원본 source IP가 runtime route identity

`src/vm/threaded/poly_direct/builder.rs`의 branch map은 원본 source IP와 bytecode
offset을 같은 레코드에 저장한다. 두 값은 XOR domain key로 가려지지만 key를 읽는
handler도 같은 이미지에 있으므로 자동 복구가 가능하다.

### 2.3 VM-OEP 데이터 평문 정책

`src/pipeline/crypto/scan.rs`는 lifted VM이 원본 데이터 포인터를 직접 사용한다는
이유로 `--vm-oep`에서 `.rdata/.rodata` 전체 보호를 건너뛴다. 그 결과 stage 이름,
`FINAL CHECKSUM`, format string, vtable, 상수 pool이 원본 의미 anchor로 남는다.

### 2.4 raw 결과의 GUI 전달

테스트 GUI는 `final_checksum: u64`를 native formatter까지 그대로 전달한다. 화면에
값을 표시하는 것 자체는 숨길 수 없지만, 숫자형 결과에서 VM 계산 경계까지 직접
이어지는 ABI 데이터 흐름은 끊어야 한다.

## 3. 구현 단계

### Phase A — 원본 코드 폐기와 누출 계측 (즉시)

- 100% commercial VM 소유 빌드에서 원본 `.text`를 NX로만 바꾸지 말고, 파일의 원본
  코드 바이트를 build-seed 기반 deterministic decoy로 덮는다.
- 출력 PE의 원본 `.text` RVA에서 원본과 동일하게 남은 바이트 수를 측정한다.
- strict commercial 완료 조건을 `original_text_exec_bytes == 0`과
  `original_text_plain_bytes == 0`으로 확장한다.
- 원본 코드가 필요한 partial VM에서는 삭제하지 않고 명시적으로 incomplete로 보고한다.

완료 기준:

- 완전 소유 빌드에서 원본 `.text` 동일 바이트가 0.
- 원본 함수 16/32-byte rolling signature가 출력 어디에도 완전한 함수 형태로 남지 않음.
- differential 실행과 PE loader 검증 통과.

### Phase B — Native island relocation

새 `NativeIslandPlan`을 만든다.

```text
NativeIslandPlan
  function ranges
  RIP-relative references
  direct call/jump edges
  unwind records
  DIR64 relocations
  callbacks and address-taken entries
```

- SEH, TLS, GUI/wait, allocator처럼 native 유지가 필요한 함수를 generated native island로
  재배치한다.
- `.pdata`, TLS callback, vtable/function pointer, load-config 포인터를 새 gateway/island로
  다시 쓴다.
- VM과 native island가 모두 준비된 뒤 원본 `.text` 전체를 폐기한다.
- 원본 RVA로의 fallback은 fail-closed 처리한다.

완료 기준:

- partial VM에서도 `original_text_exec_bytes == 0` 및 `original_text_plain_bytes == 0`.
- native 함수의 RIP-relative/SEH/TLS differential corpus 전부 통과.

### Phase C — RouteToken lowering

- 분석 중에만 `OriginalVA -> FunctionId/BlockId`를 유지한다.
- lowering 경계에서 모든 내부 branch/call/return을 per-build random `RouteToken`으로 바꾼다.
- 정적 분기는 family-local relative VIP로 직접 lower한다.
- 동적 분기만 token lookup을 사용한다.
- CALL continuation과 virtual stack에는 원본 `next_ip` 대신 continuation token을 저장한다.
- runtime branch map과 bytecode operand에서 원본 VA를 제거한다.

완료 기준:

- handler/table/bytecode를 전부 추출해도 원본 RVA 집합과 직접 join 불가능.
- 보호본의 생성 영역에서 원본 `.text` VA literal이 0.

### Phase D — Branch map 분산

- 전역 선형 `(target, offset)` 테이블을 제거한다.
- 정적 route는 bytecode-relative delta로 바꾼다.
- 동적 route는 family/cluster별 keyed table로 분산한다.
- target token과 destination offset을 동일 레코드에 두지 않는다.
- 단일 immediate key만으로 전체 table을 복호화할 수 없게 runtime rolling state를 결합한다.

### Phase E — Typed data object relocation

새 `DataObjectPlan`을 도입한다.

```text
DataObjectPlan
  object id
  original range
  kind: string/constant/vtable/pointer-table/loader-critical/mutable
  reference sites
  relocation and encryption policy
```

- loader-critical 데이터만 별도 평문 island에 둔다.
- 문자열과 constant pool은 `.vconst`로 이동하고 암호화한다.
- VM load/store는 원본 `.rdata` VA가 아니라 relocated object handle을 사용한다.
- 직접 읽기 constant pool을 평문 예외로 두는 현재 정책을 제거한다.
- 사용 직전 복호화, 사용 후 zeroize/reseal을 적용한다.

### Phase F — Constant blinding

- RISC normalization 이후 모든 의미 있는 Imm32/Imm64에 mandatory constant blinding을 적용한다.
- 동일 상수라도 site별로 다른 share와 runtime derivation을 사용한다.
- 원본 상수와 복원 key가 동일 정적 영역에 함께 존재하지 않게 한다.
- super-op 최적화가 blinded expression을 다시 상수로 접지 못하게 barrier metadata를 둔다.

### Phase G — GUI/presentation boundary

- checksum 계산, 검증, 문자열 변환을 protected 영역에서 수행한다.
- GUI에는 raw `u64` 결과 대신 opaque `PresentationHandle` 또는 단기 render buffer만 전달한다.
- stage 이름은 random stage ID로 전달하고 encrypted resource에서 render 직전에 복호화한다.
- draw 이후 presentation buffer를 zeroize한다.

### Phase H — Evidence 격리

- `.map`, `.sym`, `.risc.csv`, ownership/unsupported/capability CSV를 공개 산출물과 분리한다.
- `--evidence-dir`이 지정된 개발 빌드에서만 상세 mapping을 생성한다.
- public manifest에서 정확한 native bridge RVA/range를 제거한다.
- release/strict profile과 `--map`, `--sym-map`의 동시 사용을 금지한다.

## 4. 자동 검증 게이트

1. 원본 `.text` same-RVA byte equality.
2. 원본 함수 16/32-byte rolling signature 재출현.
3. 원본 `.text` VA/RVA literal의 generated section 출현 횟수.
4. 원본 문자열 및 magic constant 재출현.
5. branch-map 자동 복구 시뮬레이션과 mapping recovery ratio.
6. GUI 진입 시 GPR/stack에서 raw protected result 노출 여부.
7. 부트 직후, VM 실행 중, render 직전 runtime dump 누출 검사.
8. 공개 배포 디렉터리 evidence 파일 allowlist 검사.

## 5. 우선순위와 종료 조건

| 우선순위 | 작업 | 종료 조건 |
|---|---|---|
| P0 | Phase A | full VM 원본 `.text` 실행/평문 0 |
| P0 | Phase B | partial VM도 원본 `.text` 실행/평문 0 |
| P0 | Phase C/D | 원본 VA 기반 runtime mapping 0 |
| P1 | Phase E/F | 의미 문자열·상수 정적 anchor 제거 |
| P1 | Phase G | GUI raw 결과 ABI 흐름 제거 |
| P1 | Phase H | 공개 산출물에 mapping evidence 0 |

최종 strict production gate는 다음 조건을 동시에 만족해야 한다.

```text
execution_verified = true
original_text_exec_bytes = 0
original_text_plain_bytes = 0
generated_original_va_literals = 0
static_mapping_recovery_ratio = 0
public_evidence_files = 0
```

## 6. 구현 진행 기록

### 2026-09-24 — Phase A 착수

- 완전 commercial VM 소유 빌드에서 원본 `.text`의 실행 속성 제거 후 동일 RVA의
  원본 코드 바이트를 build-seed 기반 deterministic decoy로 덮도록 구현했다.
- decoy가 우연히 같은 원본 바이트가 되는 경우까지 제거하여 virtual-size 범위의
  same-RVA 동일 바이트가 정확히 0이 되도록 했다.
- 최종 PE 재파싱 검증에 `original_text_plain_bytes`를 추가했다.
- strict commercial 판정은 full coverage, 원본 실행 바이트 0, 원본 평문 바이트 0을
  모두 요구한다.
- manifest에 `original_text_plain_bytes` evidence를 추가했다.
- `.map`/`.sym`은 `--strict-profile`과 함께 사용할 수 없게 했다.
- ownership/unsupported/capability evidence는 일반 출력 옆에 기본 생성하지 않고,
  debug/map/sym 또는 `BTG_EMIT_PRIVATE_EVIDENCE=1`에서만 생성하도록 격리했다.
- partial VM의 원본 `.text` 제거는 Phase B native island가 선행되어야 하므로 아직
  완료되지 않았다.
- 전체 라이브러리 테스트 776개, binary check, format check를 통과했다.
- 실제 GUI 대상 seed 2 패킹에서 원본/보호본 실행 동등성 검증을 통과했다.
- 기본 production 출력에서 private CSV 3종이 생성되지 않음을 확인했다.
- 해당 GUI 대상은 현재 `807/861` 함수만 VM 소유이므로 원본 `.text` 실행/평문이
  각각 `186872`바이트 남는다. 새 gate는 이를 `incomplete-coverage`로 정확히 거부한다.
  이 수치를 0으로 만드는 작업은 Phase B의 첫 번째 통합 목표다.

### 2026-09-24 — Phase B inventory 구현

- canonical ProgramModel과 ownership report를 결합하는 `NativeIslandPlan`을 추가했다.
- 각 native 함수에 대해 relocation 범위, RIP-relative 참조, direct edge, unwind,
  함수 내부 DIR64 slot, TLS/CRT/export/address-taken entry를 한 inventory에 모은다.
- 누락된 canonical 함수·block과 unknown executable range는 blocker로 기록하며,
  blocker가 있으면 island emission 준비 완료로 인정하지 않는 fail-closed 정책을 넣었다.
- 분리된 cold/landing-pad provenance range는 누락으로 오판하지 않고 ownership의
  연속 함수 범위를 실제 relocation 단위로 사용한다.
- effective profile과 manifest에 `native_island_functions`, `native_island_bytes`,
  `native_island_blockers` 계측을 추가했다.
- 실제 GUI 대상에서는 native 함수 `64`개, 이동 대상 `37492`바이트, blocker `0`으로
  inventory가 완성됐고 원본/보호본 실행 동등성도 통과했다.
- 다음 구현은 이 plan을 소비해 generated RX island를 배치하고 RIP/direct edge 및
  외부 code-pointer/unwind/TLS/load-config 참조를 새 RVA로 재작성하는 emitter다.

### 2026-09-24 — Phase B emitter core 구현

- native 함수 배치를 build seed별로 섞고 함수 사이에 가변 padding을 넣는 emitter를
  구현했다. 원본 함수 순서와 island offset의 단순 대응을 유지하지 않는다.
- canonical instruction span만 다시 decode하여 이동한 모든 RIP-relative disp32를
  새 instruction/target VA 기준으로 재작성한다.
- native island 안쪽을 대상으로 하는 CALL/JMP/Jcc rel8/rel32도 새 배치 기준으로
  재작성한다. rel8 범위를 벗어나 확장 인코딩이 필요하거나 알 수 없는 displacement
  폭을 만나면 원본 주소로 fallback하지 않고 emission을 중단한다.
- 실제 GUI 대상 dry-run 결과: island `41090`바이트, 함수 placement `64`개,
  RIP fixup `545`개, direct-edge fixup `1339`개가 모두 성공했다.
- 보호본 실행 동등성 검증도 계속 통과했다.
- 다음 commit 단계는 이 image를 정식 RX section으로 넣고 외부 code pointer,
  `.pdata`/unwind, TLS/CRT/export/load-config 소비자를 새 placement로 전환하는 것이다.

### 2026-09-24 — Phase B PE staging 구현

- `.nisland`를 PE builder의 정식 RX/CODE section으로 추가했다.
- builder의 실제 section ordering으로 계산한 RVA와 emitter fixup RVA가 다르면 빌드를
  거부하는 layout-drift gate를 추가했다.
- relocation-aware 구성에서는 `.reloc`을 island 뒤에 배치하고 island도 relocation
  scan 입력에 포함시켰다.
- 실제 출력 PE에서 `.nisland` RVA `0x31498000`, virtual size `0xA082`, raw size
  `0xA200`으로 재파싱 및 loader 구조 검증을 통과했다.
- 모든 `data-va64/data-rva32/dir64` 분석 seed를 rewrite 증거로 잘못 사용하면 종료 시
  `0xC000001D`가 발생함을 differential 검증으로 발견했다. 이 휴리스틱 항목은 rewrite
  대상에서 제외했다.
- 외부 pointer rewrite는 typed `tls-callback`, `crt-callback-table`, `guard-cf-table`,
  `guard-eh-continuation` provenance만 허용하고 슬롯에 저장된 정확한 원래 target RVA의
  함수 내부 offset을 보존한다.
- 현재 GUI 대상의 TLS 슬롯은 기존 VM lifecycle gateway가 먼저 소유하므로 추가 island
  pointer rewrite는 0개이며, staging 보호본의 실행 동등성은 통과했다.
- `.nisland` 게시는 아직 `BTG_EMIT_NATIVE_ISLAND=1` opt-in이다. `.pdata`와 VM↔native
  bridge 전환이 끝나기 전에는 원본 `.text` 폐기 gate를 열지 않는다.

### 2026-09-24 — Phase B unwind publication 구현

- island placement가 확정된 뒤 각 native 함수의 relocated begin/end를 사용하는
  `RUNTIME_FUNCTION` 레코드를 `.pdata` 재구성 입력에 추가한다.
- 함수의 검증된 기존 unwind-info RVA는 재사용하되 원본 `RUNTIME_FUNCTION`도 병행
  유지하여 staging 중 원본/island 양쪽 경로가 모두 unwind 가능하게 했다.
- 실제 대상에서 relocated `RUNTIME_FUNCTION` 64개를 추가했고 exception directory가
  758개/`0x2388`에서 822개/`0x2688`로 확장됐다.
- 출력 PE 재파싱, exception directory 구조 검사, loader 검사와 실행 동등성을 통과했다.
- 다음 단계는 VM native-call bridge가 보관한 원본 target VA를 island placement로
  치환하는 runtime rewrite table 연결이다. 이 전환 뒤 원본 `.pdata`와 `.text` 제거를
  단계적으로 활성화한다.

### 2026-09-24 — Phase B native-call rewrite channel 구현

- 기존 `native_pointer_rewrites`는 VM-owned callback 주소를 gateway로 바꾸는 ABI 인자용
  테이블임을 실제 검증했다. 이를 call target에 재사용하면 gateway 재진입 루프가 생겨
  실행이 timeout되므로 해당 결합을 제거했다.
- native 함수의 canonical/alternate entry를 정확한 함수 내부 offset으로 보존하는
  원본 VA→island VA inventory를 추가했다. 실제 대상은 325개 entry rewrite를 갖는다.
- commercial builder에 ABI pointer rewrite와 분리된 `native_call_rewrites` 채널을 추가했다.
- native-call bridge는 `call R11` 직전에 이 전용 테이블만 비교·치환한다.
- multi-family sizing pass에는 동일 entry 수의 dummy pair를 넣고 final pass에는 실제
  pair를 받도록 API와 code-size 안정성 경로를 연결했다.
- 현재 place 단계는 이 새 채널에 빈 배열을 전달한다. 다음 작업은 최종 state/payload/
  route 크기로 island RVA를 예측하고 325개 실제 pair를 final rebuild에 공급하는 것이다.
- 전용 채널을 빈 상태로 둔 실제 GUI 보호본은 PE/exception/loader 검증과 실행 동등성을
  다시 통과했다. ABI pointer table을 call target에 적용했던 timeout 회귀가 제거됐음을
  확인했다.

### 2026-09-24 — Phase B native-call activation 및 relocation 수정

- sizing/final build 모두에 325개 고정 reservation pair를 공급해 VM 코드와 state offset을
  안정화하고, island RVA 확정 뒤 reservation immediate를 실제 원본 VA→island VA pair로
  교체하는 activation commit을 추가했다.
- `BTG_ACTIVATE_NATIVE_ISLAND_CALLS=1`로 전체 activation을 opt-in할 수 있고,
  `BTG_NATIVE_ISLAND_REWRITE_LIMIT`로 entry prefix를 제한해 회귀 경계를 이진 탐색할 수
  있게 했다.
- 10번째 entry(`0x140002F40`) 활성화에서 스택 오버플로가 재현됐고, relocated 함수에서
  island 밖 원본 함수를 향하는 direct CALL/JMP의 기존 rel32를 그대로 복사한 것이
  원인이었다. 소스 주소가 이동하면 외부 target도 반드시 새 displacement로 다시
  인코딩해야 한다.
- emitter가 모든 direct CALL/JMP/Jcc를 재인코딩하도록 수정했다. island 소유 target은
  relocated RVA를, 외부 target은 원본 RVA를 목적지로 사용하며 rel8/rel32 범위 초과는
  계속 fail-closed 처리한다.
- canonical 함수에 연결된 cold/disjoint block이 다른 ownership range의 bytes를 덮지
  않도록 instruction/edge inventory를 현재 relocation range 내부 block으로 제한했다.
- 실제 GUI 대상에서 325개 entry 전체(4개 family module의 2600개 immediate site)를
  활성화한 결과 PE/exception/loader 검증과 원본/보호본 실행 동등성(exit 0,
  stdout 1343B, stderr 0B)을 통과했다.
- `.nisland`와 call activation은 아직 명시적 환경 변수 opt-in이다. 다음 단계는 typed
  indirect target/jump-table 소비자까지 전환 증거를 완성한 뒤 기본 활성화하고, 마지막에
  원본 `.text` 및 원본 unwind publication을 제거하는 것이다.

### 2026-09-24 — Phase B typed indirect-table 전환

- canonical indirect-site의 `TableDescriptor::Jump`를 소비하는 native-island table
  redirector를 추가했다. rel32(base RVA 기준), VA64 및 RVA32 scalar entry를 처리한다.
- 테이블 값은 이미 후속 패치가 적용된 출력 section이 아니라 원본 PE section에서
  해석하고, 쓰기만 출력 section에 적용하도록 분리했다.
- indirect site의 `Complete` 상태는 runtime-route fallback에 의해 승격될 수 있으므로
  그 값만 신뢰하지 않는다. descriptor 전체를 사전 순회해 모든 엔트리가 실제
  `JumpTable` provenance target 집합과 정확히 일치할 때만 원자적으로 rewrite한다.
- partial/stale descriptor, 범위 밖 값, 혼합 provenance는 수정하지 않는다. 따라서
  휴리스틱 code-pointer를 일괄 치환했던 과거 `0xC000001D` 회귀 경로를 다시 열지 않는다.
- 실제 GUI 대상에서 native island를 가리키는 typed indirect-table entry 129개를
  전환했다. 325개 native-call entry 전환과 동시에 활성화한 보호본이 구조 검증 및
  실행 동등성(exit 0, stdout 1343B, stderr 0B)을 통과했다.
- table redirect는 현재 `BTG_REDIRECT_NATIVE_ISLAND_TABLES=1` opt-in이다. 다음 단계는
  address-taken pointer/vtable의 container별 typed rewrite 증거와 미전환 원본 native RVA
  참조 계측을 추가하는 것이다.

### 2026-09-24 — Phase B Rust vtable container 증거 보존

- Rust vtable resolution이 target 집합만 반환하고 실제 method-slot RVA를 버리던 구조를
  수정했다. resolution producer가 소비한 정확한 slot 집합을 함께 반환한다.
- canonical `ProgramModel`에 `typed_pointer_slots`를 추가해 vtable/container provenance를
  후속 relocation 단계까지 보존한다. 일반 relocation/code-pointer 후보와 명시적으로
  분리해 휴리스틱 포인터가 rewrite 권한을 얻지 못하게 했다.
- native-island pointer redirect는 typed PE directory 슬롯, complete direct-memory 소비
  슬롯, canonical typed container 슬롯만 허용한다.
- 실제 GUI 대상에서 이전에는 위치 증거가 없어 0개였던 vtable/address-taken 포인터 중
  6개를 island 주소로 전환했다. native-call 325개 및 typed jump-table 129개 전환과
  함께 실행 동등성(exit 0, stdout 1343B, stderr 0B)을 통과했다.
- 다음 단계는 출력 전체에서 원본 native RVA/VA를 참조하는 typed 잔존 항목을 계측하고,
  원본 `.text` 제거 gate가 정확히 어떤 consumer 때문에 닫혀 있는지 수치화하는 것이다.

### 2026-09-24 — Phase B typed native-reference audit

- raw byte-pattern 검색과 분리된 `NativeReferenceAudit`을 추가했다. canonical
  `CodePointerModel` 슬롯만 출력 section에서 다시 읽어 island target, 원본 native target,
  다른 값, 미지원 encoding으로 분류한다.
- VA64, RVA32, directory RVA 및 rel32 슬롯을 각 encoding 의미대로 역산한다. file-backed가
  아니거나 후속 pipeline에서 다른 권위 있는 값으로 전환된 슬롯은 `other`로 분리한다.
- 실제 GUI 대상에서 native 함수에 연결된 canonical 슬롯 328개를 감사한 결과는 island
  6개, 원본 native 47개, other 275개, unsupported 0개다.
- native-call 325개, typed jump-table 129개, vtable pointer 6개를 활성화한 동일 출력은
  실행 동등성(exit 0, stdout 1343B, stderr 0B)을 계속 통과했다.
- 따라서 원본 `.text` 제거 gate를 막는 typed code-pointer consumer는 현재 47개로
  정량화됐다. 다음 단계는 이 47개를 provenance/container별로 분해하고, 실제 소비가
  증명된 그룹부터 추가 전환하는 것이다.

### 2026-09-25 — Phase B residual pointer provenance 분해

- 원본 native target을 유지하는 canonical 슬롯을 provenance별로 집계하고, 상세 슬롯
  RVA/encoding은 `BTG_TRACE_NATIVE_ISLAND=1`에서만 출력하도록 감사기를 확장했다.
- 잔존 47개는 `data-rva32` 45개와 `dir64-relocation` 2개로 분해됐다.
- loader relocation이 정확한 VA slot임을 증명하는 DIR64 2개만 별도 opt-in으로
  전환했다. 포인터 rewrite 수는 6개에서 8개로 증가했고 실행 동등성을 통과했다.
- 현재 잔존은 `data-rva32` 45개뿐이다. 이 중 6개는 typed UNWIND_INFO 시작점의 0x40-byte
  보존 범위와 겹친다. 나머지는 단순 data scan 후보와 language-specific EH scope data를
  추가로 구분해야 하므로 일괄 rewrite하지 않는다.
- 원본 `.text` 제거 gate의 다음 선행 작업은 relocated native 함수별 UNWIND_INFO/EH
  metadata 복제 및 handler/scope RVA 재작성이다.

### 2026-09-25 — DIR64 전환 및 EH metadata 경계 확인

- `BTG_REDIRECT_NATIVE_ISLAND_DIR64_POINTERS=1` opt-in을 추가해 relocation-backed VA
  pointer만 별도로 활성화할 수 있게 했다. 실제 대상의 2개 슬롯을 전환한 결과 pointer
  rewrite는 8개, 원본 잔존은 45개가 됐고 실행 동등성을 통과했다.
- 남은 45개는 모두 `.rdata`의 `data-rva32` 후보다. typed UNWIND_INFO 시작점 주변과 직접
  겹치는 항목은 6개로 계측됐다.
- Microsoft PE unwind dump와 교차 확인한 결과 해당 `.rdata` 구간에는
  `__CxxFrameHandler3`의 EH Handler Data, unwind map, catch-handler array 및 catch-handler
  RVA가 연쇄적으로 배치돼 있다. 따라서 단순 0x40-byte UNWIND_INFO 복사만으로는 부족하다.
- 이 45개를 일괄 치환하면 unrelated scalar와 공유 EH graph를 손상할 수 있으므로 현재
  fail-closed로 유지한다. 다음 구현 단위는 language-specific handler data의 typed graph
  parser와 graph 단위 복제/재작성이다.

### 2026-09-25 — typed MSVC C++ EH graph 전환

- x64 `UNWIND_INFO` handler trailer에 language-data RVA를 보존하도록 typed unwind 모델을
  확장했다.
- RVA-based MSVC EH3 `FuncInfo` magic과 count/bounds를 검증하고 `UnwindMap`,
  `TryBlockMap`/`HandlerType`, `IP-to-State` graph를 따라가는 parser를 추가했다.
- trailer의 language-data가 inline FuncInfo가 아니라 FuncInfo RVA를 담는 간접 슬롯인
  경우도 검증 후 따라간다.
- graph 안에서 실행 주소 의미가 확정된 `UnwindMapEntry::action`,
  `HandlerType::addressOfHandler`, `IPtoStateMapEntry::Ip` 슬롯만 수집한다.
- parser가 기존 잔존 `data-rva32` 45개 전부를 typed C++ EH code slot으로 증명했다.
- `BTG_REDIRECT_NATIVE_ISLAND_CXX_EH=1` opt-in에서 이 graph를 전환한 결과 감사 수치는
  island 53개, original 0개, other 275개, unsupported 0개가 됐다. 실제 보호본은
  원본/보호본 실행 동등성(exit 0, stdout 1343B, stderr 0B)을 통과했다.
- canonical typed code-pointer 관점의 원본 native 주소 잔존은 이제 0이다. 다음 단계는
  opt-in 묶음을 production gate로 통합한 뒤 원본 `.text` 실행 권한 제거를 시험하는 것이다.

### 2026-09-25 — 원본 `.text` NX 전환 실험과 동적 호출 경계

- `BTG_RETIRE_ORIGINAL_TEXT=1`을 추가했다. native island emission/call activation,
  pointer/table/DIR64/C++ EH redirect가 모두 켜지고 typed audit가
  `original=0, unsupported=0`일 때만 원본 `.text`의 EXECUTE/CODE 비트를 제거한다.
- 최초 실행은 `RVA 0x7EF0`에서 `0xC0000005`로 실패했다. WinDbg로 확인한 결과
  canonical pointer audit 밖의 VM native-call bridge가 VM-owned 함수 주소를 물리적인
  원본 `.text` 주소로 호출하고 있었다.
- native island 함수의 내부 직접 분기/낙하 진입점까지 callable rewrite inventory를
  325개에서 2667개로 확장했고, relocated native→VM direct/RIP 경계를 추가해 callable
  gateway inventory를 497개에서 581개로 확장했다.
- VM-owned 주소도 `CALL r11` 변환 체인에서 callable gateway로 바꾸자 원본 `.text`
  접근 위반은 제거됐다. 다만 pre-entry 단계에서 callable-VM gateway가 재진입을 반복해
  lane bitmap을 소진하고 명시적 `ud2`(RVA `0x5B1313`, `0xC000001D`)에 도달했다.
  따라서 NX gate는 현재 fail-closed 실험 단계이며 기본값은 OFF다.
- 다음 수정은 VM native-call lowering에서 대상이 VM-owned entry일 때 native ABI
  bridge/callable gateway로 보내지 않고 family-local 또는 cross-family child route로
  직접 분기하는 것이다. unresolved indirect call도 runtime target classifier가 VM-owned
  map을 먼저 조회한 후에만 native bridge로 내려가야 한다.
- 후속 수정에서 branch-map count가 0일 때 dynamic route scan을 건너뛰던 분기를
  바로잡았고, address-taken same-family target도 child route 대상으로 포함했다.
- ownership의 VM 함수 807개와 family `ip_map` entry가 797개로 불일치하던 원인은
  함수 시작 VA alias가 partition 과정에서 누락된 것이었다. 각 함수 region의 첫 local
  micro-op를 함수 시작 VA에 연결해 NX 빌드의 gateway inventory가 807개 전부가 되게 했다.
- 이 결과 `0x7EF0` 원본 실행 접근은 사라지고 generated child entry까지 진입하지만,
  초기 dispatch에서 trap handler `ud2`(RVA `0x525E32`)로 종료한다. 남은 문제는 alias가
  가리키는 byte offset의 rolling-key/entry-resync 계약이며, 다음 단계에서 function-entry
  offset을 encoder가 직접 산출한 canonical source-IP offset과 교차 검증해야 한다.

### 2026-09-25 — callable 경계 재검증 결과

- 함수 시작 VA를 cold fragment의 첫 micro-op에 강제로 붙이는 alias는 의미적으로 틀린
  매핑임을 실행 추적으로 확인해 제거했다. `0x7EF0` alias가 실제로 가리킨 source IP는
  `0x2BF00`이었으며, 이 잘못된 entry가 앞선 `0x525E32` trap의 원인이었다.
- 원본 실행권 제거 전 native-reference 감사와 재작성의 신뢰 경계를 통일했다. 타입이 없는
  `data-rva32` 발견 힌트는 더 이상 authoritative 잔존 포인터로 세지 않으며, 최신 감사는
  `301 canonical / 53 island / 0 original / 248 other / 0 unsupported`다.
- 정확한 callable entry가 없는 VM ownership record 2개는 native island로 fail-closed
  demotion한다. 원본 `.text` 186872바이트의 EXECUTE/CODE 제거와 모든 구조 검사는 통과한다.
- 그러나 런타임 indirect target `0x7EF0`은 canonical complete indirect-target 집합과 실제
  materialized `ip_map` 양쪽에 없어 VM gateway와 native island 어느 쪽에도 속하지 않는다.
  결과적으로 native-call bridge가 원본 NX 주소를 호출해 `0xC0000005`가 발생한다.
- 모든 heuristic code-pointer 후보를 일괄 demotion하는 실험은 30개 함수가 VM/native 양쪽에
  중복 materialize되어 lane exhaustion 또는 초기 실행 정지를 만들었으므로 채택하지 않는다.
  다음 구현은 lift 전에 address-taken alternate entry를 ownership 입력으로 승격하거나,
  materializer가 해당 범위를 제외한 뒤 native island에 단일 소유권으로 넘기는 방식이어야 한다.
- 따라서 `BTG_RETIRE_ORIGINAL_TEXT`는 계속 opt-in/fail-closed이며 기본 활성화하거나 원본
  `.text` 바이트를 지우지 않는다.

### 2026-09-25 — NX 실행 복구 및 처리량 진단

- 코드에 물질화된 함수 주소(`LEA RIP+target`, `MOV r64, imm64`)를 canonical seed로
  승격해 Rust `lang_start`가 전달하는 `0x7EF0` main entry를 정확한 VM gateway로 연결했다.
  최종 native-call 재작성도 materialized gateway map을 포함하며, 이전의 원본 `.text`
  `0xC0000005`와 lane-exhaustion `0xC000001D`는 재현되지 않는다.
- seed 2에서 상용 VM이 멈춘 것처럼 보인 직접 원인은 267개 bytecode epoch에 대해 매
  디코드 바이트마다 O(N) reverse chunk lookup을 수행한 것이었다. 32개 초과 inventory는
  masked binary lookup을 사용하고, 현재 epoch의 start/end/key를 family state에 캐시해
  순차 fetch를 O(1)로 만들었다. 관련 outer-chunk native differential test를 통과했다.
- 캐시 전 8초 stdout은 74바이트였고 캐시 후에는 214바이트까지 진행하며 RIP도 정상
  opcode decoder를 순환한다. 다만 120초 안에 stage 1을 완료하지 못해 최종 execution
  equivalence gate는 아직 미통과다.
- 요청된 native hot-path 계약에 맞춰 기본 보존 class에 `allocator,string`을 추가했다.
  이 두 class는 직접 import 함수뿐 아니라 SCC dependency closure를 native island로
  넘기므로, 다음 full build에서 VM coverage/섬 크기/실행시간을 함께 재검증한다.

### 2026-09-25 — allocator/string 경계 실험 결과

- allocator/string dependency closure는 VM bytecode를 1.10MB에서 0.58MB로 줄였지만
  native island가 363개 함수로 커지면서 원본의 함수 간 `rel8` edge를 seed-shuffle
  배치에서 보존할 수 없어 `RVA 0x2835`에서 fail-closed되었다.
- 직접 import 호출 함수 34개만 보존하는 축소안은 구조/NX/reference 검사를 모두
  통과했지만 실행 초기에 guest pointer가 손상되어 `RVA 0x39368A` VM load에서 AV가
  발생했다. allocator/string은 호출자 의존성 없이 ABI 경계를 자르면 안 된다는
  실행 증거이므로 기본 활성화는 철회하고 opt-in class로 유지한다.
- 다음 구현은 이 class를 포기하는 것이 아니라, rel8-connected native 함수들을 하나의
  placement cluster로 묶어 cluster 내부 원본 delta를 보존한 뒤 closure 전체를 다시
  활성화하는 것이다. cluster 간 순서는 계속 seed-dependent하게 섞어 원본↔섬의 단순
  전역 additive mapping이 생기지 않게 해야 한다.
