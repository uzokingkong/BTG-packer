# BTG 최대 VM 보호 실측 분석 및 Themida 대비 개선 계획

작성일: 2026-08-22 (Asia/Seoul)

## 진행 기록

### 2026-08-22 — 현재 기준선 갱신 (`main` 9931adb 이후)

- 아래의 “미완료” 문구 중 이 항목보다 오래된 P2-9/P2-10/P2-11/P2-5 기록은 당시 단계의 역사적 스냅샷이며 현재 상태 판정으로 사용하지 않는다.
- P2-9는 family별 active-register-only M7으로 확대됐다. `corpus/o1.exe`, seed 31010 최대 조합에서 4개 family stream과 254개 독립 instruction-aligned chunk가 생성되고 실행 동치가 통과했다.
- P2-10은 4개 독립 code/handler-table/bytecode/state module, canonical cross-family CALL/tail-JUMP/return routing, family별 unwind range까지 production 배치 완료다.
- P2-11은 canonical ISA와 super-op extension의 모든 최종 handler-table target에 seed/opcode-derived synthesis wrapper를 적용했다. 전체 ISA production reachability는 완료됐지만 handler 본체의 micro-op decomposition/MBA/register allocation/control split 다양성은 추가 강화 대상으로 유지한다.
- P2-5는 helper-only 상태를 종료했다. PE literal reference graph와 strict `LEA literal → Win64 argument → call` proof를 production에 연결하고, VM 소유권까지 재검증된 45개 객체를 at-rest ciphertext로 저장한다. call 직전 RISC toggle로 복호화하고 복귀 직후 재암호화하며 flags를 복원한다. 일부 참조/native 참조/loader-critical 객체는 fail-closed 제외한다.
- 최신 검증: library 559/559, `corpus/o1.exe` 일반 및 `--m7 --m8 --integrity` 실행 동치 exit 0/stdout 1,460B/stderr 0B. 최신 data-lifetime/handler-body 변경 이후 20-seed/전체 hostile corpus는 다시 수행해야 한다.
- 다음 구현 순서: (1) data-lifetime 직접 메모리·wide/format·동시성 확대, (2) P2-11 handler 본체 synthesis 강화, (3) distributed integrity production descriptor/runtime wiring, (4) P2-12 runtime anchor 분산, P2-13 grammar polymorphism, P2-14 state splitting/lazy flags, P2-15 bridge oracle 감소, (5) 최신 20-seed 및 hostile/tamper release gate.

### 2026-08-22 — P2-5 direct-access lifetime 확대

- strict scope proof가 `LEA→call`뿐 아니라 VM instruction의 RIP-relative direct literal/constant read를 포함한다. direct access는 해당 instruction 직전 복호화하고 직후 재암호화한다.
- 객체의 모든 참조가 call/direct-access scope로 증명되고 모든 참조 block이 VM 소유일 때만 at-rest ciphertext로 승격한다. `corpus/o1.exe` 최대 조합에서 보호 객체가 45개에서 46개로 증가했고 실행 동치가 통과했다.

### 2026-08-22 — P2-5 UTF-16 production object scanner 확대

- byte-oriented NUL scanner가 UTF-16LE를 한 글자씩 분절하던 결함을 제거했다. wide literal을 ASCII보다 먼저 검사하고 2-byte terminator까지 단일 객체로 reference graph에 등록한다.
- `corpus/o1.exe`에서 후보 객체 170→172, strict scope 객체 104→106으로 증가했다. 추가 wide 객체는 최종 VM 소유권 gate에서 제외되어 활성 ciphertext 객체는 46개로 유지됐고 최대 조합 실행 동치는 통과했다.
- 동일 객체를 여러 thread/family가 동시에 toggle하는 race는 전역 lock/state storage가 필요하므로 P2-14 shared-state splitting과 함께 닫는다. lock 없는 공유 `.rdata` mutation을 억지로 활성화하지 않는다.

### 2026-08-22 — P2-11 실제 handler 본문 synthesis 확대

- 기존 NOR 본문 등가식 선택에 더해 `MOV`와 `NOT{8,16,32,64}`가 build seed/opcode별 실제 의미 동치 명령열을 선택한다. MOV는 native self-move, 이중 NOT, seed-mask 이중 XOR 중 하나를 사용하고 NOT은 native NOT 또는 폭별 all-one XOR을 사용한다.
- 모든 변형은 guest flag state를 갱신하지 않으며, 폭별 NOT의 상위 비트 보존 계약도 유지한다. 단순 NOP 수 변화가 아니라 production handler의 도달 가능한 본문 바이트와 instruction grammar가 실제로 달라진다.
- 다중 jump-island wrapper 시도는 native 실행에서 `STATUS_ILLEGAL_INSTRUCTION` 회귀를 검출해 폐기했다. 검증된 기존 단일 wrapper를 유지하고 불안정 코드는 커밋하지 않았다.
- 전체 library 559/559와 `corpus/o1.exe --vm --vm-oep --vm-commercial --m7 --m8 --integrity --verify-output --seed 31010` 최대 조합이 통과했다. production 결과는 4 family/255 M7 chunk, data-lifetime ciphertext 46개이며 실행 차등검증이 일치했다.

### 2026-08-22 — Distributed integrity family descriptor production materialization

- multi-family builder가 합친 module 안에서도 family별 code/table/bytecode 경계를 끝까지 보존한다. descriptor 생성기는 empty/OOB/overflow/overlap 범위를 fail-closed한다.
- `--integrity` production placement가 M7 persistent bytecode layer 적용 직후, transient boot RC4 적용 직전에 실제 런타임 표현을 seal한다. 각 family의 handler code, handler table, VM bytecode에 독립 domain-derived keyed tag와 RVA/length 계약을 생성해 pipeline context에 보존한다.
- `corpus/o1.exe` seed 31010 최대 조합에서 4 family × 3 region = 12 descriptor가 생성됐고 실행 차등검증이 통과했다. 전체 library는 신규 범위 회귀 테스트를 포함해 560/560 통과했다.
- 이 단계는 production region/tag materialization까지다. 다음은 12 descriptor serialization과 boot/runtime consumer를 연결해 변조 시 실제 fail-closed/poison 경로를 실행하고 tamper corpus로 닫는다.

### 2026-08-22 — Distributed integrity runtime-table serialization

- 고정 BTGI ABI를 추가했다. 8B header(`magic`,`count`) 뒤에 40B descriptor entries가 이어지며 각 entry는 kind/policy, RVA, length, keyed tag, domain key를 담는다.
- production placer가 4 family × 3 region의 최대 12-entry 공간을 mutable Program-VM state 뒤에 별도로 예약한다. 최종 M7 runtime 표현을 seal한 뒤 488B 테이블을 실제 `.textb`에 기록하고 RVA/size를 pipeline context에 보존한다. 예약 초과와 table write OOB는 fail-closed한다.
- `corpus/o1.exe` seed 31010 최대 조합에서 BTGI table RVA `0x293000`, size 488B, count 12를 확인했고 실행 차등검증이 통과했다. 다음은 boot/runtime verifier가 이 ABI를 순회하며 tag를 재계산하고 tamper를 차단하도록 연결하는 작업이다.

### 2026-08-22 — P2-10 실제 multi-family module/state/table 및 call/return routing 완료

- production placer가 entry family를 첫 module로 정렬하고 4개 family의 code, handler/operand/condition/branch table, bytecode를 각각 독립 생성한다. mutable state, virtual stack, cross-family control slots, return-IP stack은 family마다 `0x8000` stride로 격리한다.
- cross-family branch-map miss는 target VA별 native route를 조회한다. caller의 seed-permuted GPR/RFLAGS/VSP/XMM state를 target family layout으로 변환하고, target module의 로컬 bytecode VIP에서 rolling key를 resync해 진입한다. CALL은 기존 canonical native-call ABI로 child RAX와 memory side effect를 반환하고 caller continuation을 재개한다. tail JUMP는 family별 전용 Halt continuation으로 종료 의미를 보존한다. 같은-family edge는 기존 로컬 branch-map fast path만 사용한다.
- entry module은 VIP 0이 아니라 실제 OEP function의 local byte offset에서 시작한다. target-only family도 routed entry를 활성화하며, op partition이 없는 초소형 프로그램은 검증된 단일-module 경로로 fail-safe fallback한다.
- family 전용 stream의 branch-map 검증 decoder/re-encoder가 기본 family를 쓰던 결함을 수정해 명시된 family ISA를 일관되게 소비한다. route 제어 슬롯과 return-IP stack의 `state+0x258` 충돌도 독립 `state+0x5000` 영역으로 제거했다.
- `.pdata` 생성기는 모든 family module의 native bridge range를 개별 RUNTIME_FUNCTION 구간으로 분할하고 동일한 private-frame UNWIND_INFO를 연결한다. 첫 module만 unwind 처리되던 단일-range 계약을 제거했다.
- native 2-family call→return→parent-resume 회귀 테스트와 전체 library 555/555가 통과했다. `corpus/o1.exe`, seed 31010 production 실측은 621 VM 함수, 4 실제 module, 513 canonical runtime route, 771,534B aggregate bytecode이며 일반/M7 최대 조합 모두 exit 0, stdout 1,460B, stderr 0B 동치 및 PE 구조 검증을 통과했다. SHA-256은 `de559ee06eb8953a505b58e249a393a247c11275fd9bb649eba8419ee1acd415`다.

### 2026-08-22 — P2-10 independent bytecode 및 canonical route table materialization

- `MultiFamilyProgramPlan`이 검증된 function-op partition을 family별 독립 `RiscProgram`/로컬 `ip_map`으로 절단한다. 중복 op ownership과 누락된 source/target ownership은 fail-closed한다.
- 각 partition은 family 분리 domain seed로 독립 polymorphic bytecode와 instruction-offset table을 생성한다. pipeline context에는 기존 ownership partition과 별도로 materialized module 입력을 보존한다.
- cross-family direct edge는 source/target family, source local op, target local entry op, call resume local op을 가진 canonical route table로 확정한다. 같은-family edge는 route table에 들어가지 않는다.
- 신규 materialization/route 회귀 테스트를 포함한 전체 library 테스트는 554/554 통과했다.
- 아직 완료되지 않은 부분: PE placer가 각 materialized 입력을 실제 독립 code/handler-table/state 영역으로 배치하고, native dispatcher가 route table을 소비하여 state 전환 및 call/return을 수행해야 한다. 현재 실행 산출물은 기존 entry-family module을 유지하므로 P2-10 전체 완료로 판정하지 않는다.

### 2026-08-22 — P2-10 function micro-op family partition 완료

- commercial RISC lift가 각 완전 VM 소유 `.pdata` 함수에 대해 stable function start VA와 contiguous `[start_op,end_op)` ownership range를 생성한다. synthetic entry branch와 `.pdata` 밖의 orphan block은 함수 소유 범위에 거짓 포함하지 않는다.
- `ProductionFamilyPlan::partition_regions`가 함수 range를 Stack/Register/MixedRisc/FusedCisc backend별로 그룹화한다. invalid/OOB/overlap range와 family assignment가 없는 range는 typed build error로 거부한다.
- partition 결과를 `PipelineContext.vm_family_partitions`에 저장해 sizing/final placement 이후 단계가 같은 immutable ownership 계약을 소비할 수 있게 했다.
- unit gate에서 모든 함수 range가 정확히 한 family partition에 속하고 overlap mutation이 거부됨을 검증했다. 전체 library는 553/553 통과했다.
- `corpus/o1.exe` seed 31010 production 실측: VM 소유 621함수, 4 family, 4 backend partition, 621 function region, 총 97,909 RISC op를 분할했다. 189-chunk M7 구조 검증과 differential 실행은 exit 0/stdout 1,460B/stderr 0B로 통과했다. SHA-256 `4728f4467f46dbe136e5ea807aaa3ad0959830cc3aa579ed4e00aba4ce825db5`.
- 이 단계는 다음 multi-module emitter의 입력 계약을 완료한 것이다. 아직 단일 entry-family module만 PE에 배치되므로 binary hash는 직전 단계와 동일하다. 다음은 각 partition을 독립 bytecode/module/state/table로 materialize하고 cross-family call/return routing을 연결한다.

### 2026-08-22 — SHLD correctness 종료 및 P2-10 production family wiring 1차

- SHLD count>0에서 architecturally undefined인 AF를 host `pushfq` 결과에서 그대로 VM flags에 저장하던 비결정성을 제거했다. native handler가 SHLD 전 guest AF를 별도로 보존하고 실행 후 정의된 flag mask에 다시 합성하므로 reference/poly/native가 일치한다.
- 전체 library 회귀는 552/552로 복구됐다.
- commercial lift가 완전 VM 소유 `.pdata` 함수의 stable start VA 목록과 entry function id를 산출한다. `ProductionFamilyPlan`은 traversal order가 아니라 이 ID로 함수별 Stack/Register/MixedRisc/FusedCisc assignment와 cross-family bridge 요구를 생성하고 pipeline context에 보존한다.
- entry 함수에 실제 배정된 family가 production `PolymorphicEncoder`, super-op extension opcode allocation, `VirtualIsaSpec`, native decoder/handler table에서 동일하게 소비되도록 end-to-end 연결했다. 즉 build-level `for_build(seed)` 고정 경로 대신 ownership에서 유도된 entry-family backend가 실제 실행된다.
- `corpus/o1.exe` seed 31010 실측에서 VM 소유 함수 621개가 4 family로 분포했고 cross-family bridge 요구 474개, entry family MixedRisc가 보고됐다. 189-chunk M7 최대 Program-VM 구조 검증 및 differential 실행은 exit 0/stdout 1,460B/stderr 0B로 통과했다. SHA-256은 `4728f4467f46dbe136e5ea807aaa3ad0959830cc3aa579ed4e00aba4ce825db5`다.
- 주의: 이번 단계는 함수 ownership→family planning과 **entry-family 실행 backend**의 production wiring까지다. 하나의 EXE 안에서 여러 family module을 동시에 실행하고 474개 cross-family edge에 canonical bridge를 emit하는 단계는 아직 남아 있으므로 P2-10 전체 완료로 판정하지 않는다. 다음 구현은 function micro-op ranges partition → family별 독립 module/state/table → cross-family call/return routing 순서다.

### 2026-08-22 — P2-9 M7 chunk metadata/key 노출 제거 완료

- `ChunkLookupTopology::{ForwardEnds, ReverseStarts, BinaryEnds}`를 추가하고 build seed로 실제 native fetch CFG를 선택한다. forward는 masked end scan, reverse는 masked start scan, binary는 masked end decision tree를 사용해 하나의 선형 `sub_decrypt` template으로 수렴하지 않는다.
- 모든 topology가 boundary/start를 seed-domain mask로 register에서만 복원한다. `cmp VIP, imm32`는 생성하지 않으며 leaf에서는 chunk index와 masked start만 복원하고 공통 out-of-line tail에서 module secret + chunk domain + index로 operational key를 파생한다.
- `SelfDecodingParts.chunk_lookup_topology`에 실제 선택 결과를 남기고, host native runner에 pack pipeline과 동일하게 outer chunk encryption을 적용하는 실행 경로를 추가했다.
- N=20 gate에서 세 normalized topology가 모두 출현하고 단일 template이 10/20 이상을 점유하지 않음을 확인한다. 세 topology 각각에 대해 multi-instruction stream을 2개 이상 chunk로 나눠 reference evaluator와 native register/temp/flags 동치를 검증했다.
- 실제 `corpus/o1.exe`를 189개 instruction-aligned chunk로 최대 Program-VM 조합(`--vm --vm-oep --vm-commercial --m7 --m8 --integrity`) 패킹했다. 구조 검증과 differential 실행이 통과했으며 exit 0, stdout 1,460B, stderr 0B가 원본과 일치했다. SHA-256은 `12e4903c243babc4ded33f90c9bd7f40a652d74b0d61a1ebe10163e9bdf02e17`이다.
- 전체 library는 550/551이며 유일한 실패는 기존 SHLD AF flags 불일치다. P2-9 완료 기준(raw per-chunk key 0, `cmp VIP, imm` boundary oracle 제거, N=20 topology 비수렴, active-register-only differential 유지)을 충족했다. 다음 우선순위는 P2-10 실제 per-function/per-region multi-VM production wiring이다.

### 2026-08-22 — P2-9 chunk boundary/key 정적 oracle 제거 1차

- Program-VM `sub_decrypt`의 `cmp VIP, imm32` O(N) 경계 ladder를 제거하고, build seed에서 독립 파생한 mask로 chunk end/start descriptor를 각각 인코딩하도록 변경했다. 런타임은 descriptor를 register에서만 복원해 비교하므로 단순 VIP-immediate scanner로 평문 chunk map을 열거할 수 없다.
- descriptor 선택과 key derivation을 분리했다. 선택 leaf는 chunk index와 masked start만 복원하고, 공통 derivation tail이 단일 module secret + chunk domain + index에서 operational key를 파생한다. raw per-chunk key 목록은 code에 저장하지 않는다.
- 정적 회귀 gate를 추가해 생성된 dispatcher code에 `cmp R12, imm32`가 없고 모든 계획 chunk key의 8-byte 평문이 포함되지 않음을 검사한다.
- 검증: P2-9 focused test와 chunk crypto 3건 통과. 전체 library는 548/549이며 유일한 실패는 기존에 기록된 `test_shld_native_poly_and_reference_are_identical`의 AF flags 불일치(`0x91` vs `0x81`)다.
- P2-9 전체 완료 기준 중 raw key immediate 목록 0과 단순 `cmp VIP, imm` boundary recovery 차단을 닫았다. 남은 범위는 lookup topology 자체의 family/seed별 복수 형태와 N=20 normalized CFG clustering gate, 실제 최대 VM differential corpus다.

### 2026-08-22 — P0-4~P0-8 correctness blocker 구현 진행

- P0-4: ChaCha20-Poly1305 payload stream을 RFC 8439 계약대로 counter 1부터 시작하도록 변경했다. Poly1305 one-time key의 on-disk 저장을 제거하고, native boot stub이 counter 0 block을 32B volatile scratch에 생성해 인증한 직후 zeroize한 다음 counter 1/`ks_off=64`로 payload 복호화를 시작한다.
- manifest에 `crypto_construction=rfc8439-chacha20-poly1305`, `payload_initial_counter=1`, `poly_key_embedded=false`를 기록한다. `dummy_target.exe`를 seed 8439로 `--crypto-mode chacha20 --verify-output` 패킹해 실행 동치와 출력 PE의 key scratch 32B all-zero를 확인했다. counter 분리, RFC tag/native mutation 기존 테스트도 통과했다. 완료 기준의 `--verify-seeds 20`과 실제 출력 mutation corpus 자동화는 후속 gate로 남긴다.
- P0-5: RIP-relative disp32 계산을 `i128`로 수행하고 범위 초과를 `RipFixupError::DisplacementOverflow` typed hard error로 전환했다. 기존 `OVERFLOW SKIP + Ok(())` 경로를 제거하고 정확한 ±2GB 경계 및 경계 밖 양방향 테스트를 추가했다.
- P0-6: CFG decode에서 invalid gap과 `INT3`를 분리했다. entry/direct branch target의 `INT3`는 실제 instruction으로 보존하고, return/unconditional terminal 뒤 비표적 연속 `0xCC`만 alignment padding으로 분류한다. reachable/branch-target/alignment 세 회귀 테스트가 통과했다. `.pdata`/data function-pointer target과 실제 exception RVA differential은 후속 corpus gate로 남긴다.
- P0-7: parser가 AMD64 machine, PE32+ optional header(최소 240B), EXE-only, section-count 계약을 build 전에 강제한다. x86 PE32와 DLL은 silent x64 EXE 변환 대신 명시적으로 거부한다. builder는 최종 section 수로 `required_header_end`를 checked 계산하고 file alignment된 `SizeOfHeaders`를 확장하며 section-table write 전 invariant를 재검증한다.
- P0-8: non-unconditional block의 fallthrough를 TriggerBlock으로 해석하지 못할 때 원본에 없는 `RET`를 합성하던 경로를 제거했다. 이제 RVA와 text 범위를 포함한 `UnresolvedFallthrough` hard error로 pack을 중단한다. 이 gate가 `.text` VirtualSize 뒤의 raw zero-padding을 가짜 instruction/block으로 디코드하던 root cause를 드러내 CFG decode 범위를 executable virtual span으로 제한했다. full-pipeline 회귀는 synthetic RET 없이 통과한다. external/native thunk의 증명 기반 bridge와 function-atomic fallback/provenance는 후속 확장 범위다.
- 검증: graph 15/15, PE 15/15, P0-4 focused crypto/manifest 및 ChaCha E2E 실행 동치 통과. 전체 lib는 540/541이며 남은 1건은 기존 `test_shld_native_poly_and_reference_are_identical` flags 불일치로 재현된다.

### 2026-08-22 — 제공 packed.exe VM 복원 저항성 정적 감사 및 상용 VM 기준 재평가

- 제공 `packed.exe`는 실행하지 않고 PE 구조/문자열/정적 디스어셈블리만 분석했다. SHA-256은 `beaf7a8bcece899986b763849f36f9468147bec2cda98a0faabf57223a984050`이다.
- x64 PE32+, 6 sections, entry RVA `0x8A900`, 파일 크기 1,969,664B다. import는 `kernel32!LoadLibraryA/GetProcAddress` 2개로 축소돼 IAT 노출은 강하게 줄었다. `.text` entropy는 약 7.999, `.textb`는 약 7.459 bits/byte다.
- Program-VM dispatcher는 정적으로 `0x1400987A4` 부근에서 확인된다. 해당 지점에서 bytecode base `0x140122220`, VM state `0x1401E1000`, virtual stack `0x1401E3100`, handler-table 계열 base `0x14009E841`가 절대 VA immediate로 드러난다.
- handler table은 256-entry runtime integrity loop와 per-opcode key derivation을 거쳐 indirect dispatch되므로 단순 table XOR/dump 공격에는 강하다. 반면 key derivation 코드와 상수는 동일 dispatcher 안에서 관찰 가능해 black-box 분석기가 해당 로직을 에뮬레이션하면 table 복원은 원리상 가능하다.
- Program-VM M7의 active-register-only bytecode fetch는 평문 bytecode를 메모리에 장기 기록하지 않는 점이 강점이다. 그러나 현재 `sub_decrypt`는 VIP에 대한 긴 chunk-boundary compare ladder와 chunk별 64-bit key immediate를 코드에 직접 포함한다. 따라서 보호된 bytecode 자체는 ciphertext여도 **chunk map + key material의 정적 복원 비용이 예상보다 낮다**.
- 소스의 `VmArchitectureFamily::{Stack, Register, MixedRisc, FusedCisc}`와 `assign_function_families`/`CrossVmBridge` 기반은 존재하지만 production encoder/decoder 기본 경로는 `VmArchitectureFamily::for_build(seed)`를 사용한다. 함수별 family assignment는 현재 family 모듈/테스트 밖의 commercial pipeline에서 실질적으로 소비되지 않아, 현 산출물은 “빌드당 1개 family + build-level topology”에 더 가깝다.
- `HandlerSynthesisPlan`의 production 적용은 현재 self-decoding builder의 `NOR` handler 중심이다. 나머지 주요 handler는 공통 canonical RISC 의미론과 비교적 안정적인 native template을 공유하므로 seed 간 semantic normalization이 가능하다.
- 반대로 `DispatcherPlan::from_seed(seed)`의 Direct/Indirect/SwitchSplit/CallRet/Distributed 5종 topology는 commercial builder에 실제 연결돼 있어 dispatcher byte/CFG 다양성은 실효성이 있다.
- `distributed_integrity.rs`와 `data_lifetime.rs`는 현재 독립 구현/테스트는 존재하지만 production call-site가 확인되지 않았다. 실제 `packed.exe`에서도 Rust runtime 경로, stage label, `RUST_BACKTRACE` 등 다수 평문 문자열이 남아 data-lifetime 보호의 전역 통합은 미완료로 판정한다.
- PE 관점에서는 reloc directory가 0이고 `DYNAMIC_BASE`/CFG 계열 플래그가 보이지 않으며, OEP와 VM entry에 절대 VA가 다수 존재한다. 이는 VM 상태/dispatcher anchor 탐색을 쉽게 하고 ASLR 측면에서도 상용 기준에 불리하다.
- 종합하면 현재 샘플은 **naive dump 및 단순 opcode/table 복원에는 중상 수준 저항성**을 보이지만, **전용 devirtualizer를 한 번 만든 뒤 동일 계열 빌드에 분석 모델을 재사용하는 공격**에는 아직 Themida급 상용 기준보다 명확한 격차가 있다. 핵심 격차는 (1) 실제 다중 VM family 미통합, (2) canonical bytecode grammar/RISC 의미층, (3) chunk map/key immediate 노출, (4) 단일 전역 runtime anchor, (5) handler synthesis 적용 폭이다.

### 2026-08-22 — P2-1~P2-5 VM 다양성·런타임 보호 기반 구현

- P2-1: `src/vm/poly/architecture_family.rs`에 Stack, Register, Mixed-RISC, Fused-CISC 4개 VM family와 family별 register 수/폭, flag model, operand-width 정책, dispatch topology, call convention을 정의했다.
- build seed와 안정적인 function id로 함수별 family를 결정하고, family가 다를 때 canonical 16×u64 register image와 packed flags를 보존하는 `CrossVmBridge` 계약을 생성한다. family domain separator는 실제 opcode/register/condition ISA 생성에 반영되며 family별 encoder/decoder 진입점을 제공한다.
- N=20 seed에서 architecture signature가 단일 family로 수렴하지 않고 최소 3개 family가 표현되는 회귀 gate를 추가했다. 단, family별 독립 네이티브 dispatcher/handler backend와 전체 프로그램의 실제 함수 단위 multi-VM 배치는 후속 통합 범위다.
- P2-2: `src/vm/handler_poly.rs`에 build-time `HandlerSynthesisPlan`을 추가했다. opcode별 semantic recipe(Native/DeMorgan/BooleanBasis/CarrySplit/MBA), scratch allocation, instruction selection, control split, dead-state slot, context key를 seed로 합성한다.
- 상용 NOR handler가 합성 recipe를 실제 machine-code decomposition 선택에 사용하도록 연결했다. normalized semantic/CFG signature의 seed 간 similarity 상한을 0.35로 검증한다. 나머지 모든 opcode의 recipe 직접 적용 확대는 후속 범위다.
- P2-3: `src/vm/dispatch_perm.rs`와 commercial poly builder에 Direct-threaded, Indirect-threaded, Switch-split, push/ret Call-ret, out-of-line Distributed 5개 실제 terminal topology를 연결했다.
- dispatcher마다 reachable NOP instruction-selection prelude, split selector, island 구성을 seed별로 바꾸며 기존 per-opcode 암호화 handler table/checksum과 함께 사용한다. 선택 결과는 `SelfDecodingParts.dispatcher_plan`에 기록하고 N=20 단일 signature 성공률 <10% gate를 추가했다. CET shadow-stack 호환성은 P2-8 검증 범위다.
- P2-4: `src/vm/distributed_integrity.rs`에 FileImage, MappedImage, VmBytecode, HandlerCode, HandlerTable, NativeBridge, ResolvedApiPointers용 domain-separated keyed-MAC descriptor를 추가했다. 실패 정책은 FailClosed, DelayedPoison, Telemetry를 지원한다.
- 위 7개 보호 영역에 대해 모든 단일-bit 변조가 탐지되고 정상 입력 false positive가 없는 테스트를 추가했다. 기존 startup CRC4 및 handler-table checksum과 별도로 사용할 공통 계층이며, 모든 descriptor의 native runtime/packer 자동 배치는 후속 pipeline 통합 범위다.
- P2-5: `src/vm/data_lifetime.rs`에 ASCII/UTF-8/UTF-16 literal 분류와 FormatTable/VTable/RTTI/ConstantPool 데이터 분류, 객체별 key/nonce 암호화, callback scope 복호화, scope 종료 volatile zeroize를 구현했다.
- 지정 secret이 at-rest ciphertext에 나타나지 않고 scope 밖에서 다시 노출되지 않는 테스트를 추가했다. PE 전체 참조 분석과 객체 자동 재배치는 후속 pipeline 통합 범위다.
- 전체 Rust library 회귀 결과: 540 passed, 0 failed.

### 2026-08-22 — P0 첫 수정 완료

- 최대 VM 실행 실패의 Windows fault RVA를 `0x8B17F/0x8B170`으로 확인하고 부트 스텁 CRC4 `UD2`에 역매핑했다.
- `CRC3 → self-wipe → CRC4` 순서 때문에 `w32_slot`이 검증 전에 지워지는 결함을 수정했다.
- pack-time CRC4가 64-bit rotate 후 truncate하고 runtime은 `rol r11d,13`을 수행하던 폭 불일치를 32-bit 공유 함수로 단일화했다.
- 수정 파일: `src/pipeline/crypto/bootstub/build.rs`, `src/pipeline/crypto/integrity.rs`, `src/pipeline/crypto/place/mod.rs`, `src/pipeline/crypto/tests.rs`.
- 수정 산출물: `test/src/target/release/rust_packer_test.btg.vmmax.fixed2.exe`.
- 수정 산출물 SHA-256: `cde06c9e17b9fca8ab0cd2e2714d3c55a32f9af68f0b7712604b9b38b7a6bb89`.
- 원본과 같은 최종 체크섬 `0x2cdc0e4511d84a64`, exit 0을 확인했고 10회 반복에서 실패 0건이었다.
- `--strict-profile`을 추가했다. 현재 충돌 조합에 적용하면 세 downgrade(re-encryption, IAT hide, mem-harden)를 보고하고 출력 생성 전에 exit 1로 거부한다.
- 남은 P0: 보호본 differential 실행을 CLI/QA의 자동 gate로 제품화하고 cold-boot/다중 seed 검증을 추가한다.

### 2026-08-22 — P0 differential 실행 gate 완료

- `src/differential.rs`에 원본/보호본 실행 snapshot과 byte-for-byte 비교기를 추가했다.
- `--verify-output`과 `--verify-timeout-secs <초>` CLI 옵션을 추가했다.
- stdout/stderr를 별도 thread에서 실행 중 계속 drain해 pipe 포화 교착을 방지한다.
- 프로세스별 timeout을 적용하고, exit code/stdout/stderr 중 하나라도 다르면 pack 명령을 실패시킨다.
- 최대 VM 명령에 `--verify-output`을 결합한 end-to-end 검증을 통과했다: exit 0, stdout 1,460B 동일, stderr 0B 동일.
- 검증 산출물: `test/src/target/release/rust_packer_test.btg.vmmax.verified.exe`.
- 검증 산출물 SHA-256: `2a34cf6a404a23d52e2e7565de1df20956b5b7904487cbbfbf400eecb155e7ba`.
- 남은 P0: 실패 산출물 격리/manifest 검증 결과 기록, cold-boot 및 multi-seed 반복 gate.

### 2026-08-22 — P0 검증 provenance 및 실패 격리 완료

- differential 검증을 manifest 생성보다 앞으로 이동해 검증된 사실만 정상 manifest에 기록하도록 변경했다.
- manifest 필드 추가: `execution_verification_attempted`, `execution_verified`, `verified_exit_code`, `verified_stdout_len`, `verified_stderr_len`.
- 실행 비교 실패/timeout 시 정상 출력 경로의 파일을 `.failed.exe`로 이동한 뒤 pack 명령을 실패시킨다.
- 기존 실패 파일이 있으면 `.failed.1.exe`, `.failed.2.exe`처럼 증가시켜 덮어쓰지 않는다.
- 격리 동작 단위 테스트와 manifest 테스트를 통과했다.
- end-to-end 검증 산출물: `test/src/target/release/rust_packer_test.btg.vmmax.verified-manifest.exe`.
- SHA-256: `1ce7c87188fb8a48c8194f839a5d14aaf0994237ff1f79d3049f934fc7b100fe`.
- manifest 실측: attempted=true, verified=true, exit=0, stdout=1,460B, stderr=0B.
- 남은 P0: multi-seed pack+execution 반복 gate와 결과 집계.

### 2026-08-22 — P0 multi-seed gate 완료

- `--verify-seeds <N>`을 추가했다. 부모 프로세스가 seed별 독립 자식 pack을 실행하며 각 자식에 `--verify-output`을 강제한다.
- `--seed <S>`가 있으면 `S..S+N-1`, 없으면 `1..N`을 사용한다.
- 산출물은 `.seed-<ordinal>-<seed>.exe`로 분리하고 각 자식이 독립 manifest와 실행 검증 결과를 기록한다.
- 하나라도 pack/구조검증/실행동치에 실패하면 전체 seed gate가 실패한다.
- 전체 성공 시 seed, SHA-256, 절대 산출물 경로를 `<base>.seedgate.txt`에 기록한다.
- seed 1001~1003 최대 VM end-to-end 결과: 3/3 성공, 모두 exit 0/stdout 1,460B/stderr 0B 동치.
- SHA-256은 각각 `87ecc3b3...532e3`, `9dce286e...4b606`, `c52c90ee...31a46`으로 서로 달라 seed별 binary diversity도 확인했다.
- 집계 리포트: `test/src/target/release/rust_packer_test.btg.vmmax.seedgate.exe.seedgate.txt`.
- P0의 기본 실행 신뢰성 gate는 완료. 다음 우선순위는 P1 RISC unsupported 2,114개를 opcode histogram으로 분해하고 VM 커버리지를 높이는 작업이다.

### 2026-08-22 — P1 RIP-relative LEA 지원 및 영향도 진단 완료

- unsupported opcode 집계에 실제 lift 오류 사유와 오류가 영향을 주는 `.pdata` 함수 수를 추가했다. 이제 단순 opcode 미지원과 주소/피연산자 제약을 구분할 수 있다.
- RIP-relative 메모리 읽기/쓰기는 기존 안전 게이트를 유지하고, 메모리를 역참조하지 않는 `LEA r64/r32,[rip+disp32]`만 `ip_rel_memory_address()` 절대 VA로 안전하게 lower한다.
- `LEA r32`는 EAX류 쓰기 의미에 맞게 상위 32비트를 0으로 확장한다. 64/32비트 RIP-relative 합성 회귀 테스트를 추가했고 통과했다.
- 동일 타깃 실측: VM 블록 `1,859 → 2,371`(+512, 전체 12,418개 기준 약 `14.97% → 19.09%`), RISC-unliftable 블록 `1,429 → 1,106`(-323), unsupported 명령 `2,114 → 1,656`(-458).
- 고정 seed 1001 보호본은 differential gate를 통과했다: exit 0, stdout 1,460B, stderr 0B. 산출물 SHA-256은 `491a95ff626516423e83782cda61bcdf70acf54691c9ae38b1c0f155044ae04b`다.
- seed 2001~2003 gate도 3/3 통과했으며 SHA-256은 각각 `c8633e94...e88a2`, `8b9a3a20...953f9`, `e62e102e...63b7e`로 서로 달랐다.
- 다음 P1 우선순위: 여전히 게이트된 RIP-relative 실제 메모리 접근 343건/138함수는 경계·dispatcher 검증 없이 일괄 활성화하지 않는다. 먼저 독립 opcode 중 영향 함수가 큰 rotate/ADC/SBB와 SSE 이동·shuffle 계열을 네이티브/RISC 차등 테스트로 확장한다.

### 2026-08-22 — P1 ADC/SBB 전체 실행 계층 지원 완료

- 폭별 `Adc { width }`/`Sbb { width }` RISC op를 추가하고 8/16/32/64비트 결과와 입력 CF, CF/OF/AF/ZF/SF/PF를 구현했다.
- RISC evaluator, polymorphic ISA/encoder/interpreter, threaded harness, self-decoding native handler에 동일 의미론을 연결했다.
- 레지스터·즉시값·메모리 목적지를 lift하며 8/16비트 GPR 부분 쓰기는 산술 플래그를 보존한 채 상위 비트를 합성한다.
- 네이티브 차등 테스트 중 self-decoding 런타임의 공용 `FLAG_MASK`가 AF를 누락한 기존 결함(`0x8C5`)을 발견해 `0x8D5`로 수정했다.
- 두 seed에서 reference evaluator = poly interpreter = native self-decoding 결과/플래그 동치를 통과했다.
- 타깃 재패킹 실측: VM 블록 `2,371 → 2,418`(+47), native `10,047 → 10,000`, RISC-unliftable `1,106 → 1,075`(-31), unsupported `1,656 → 1,605`(-51). ADC/SBB 실패 사유는 0건이다.
- 보호본 differential gate 통과: exit 0, stdout 1,460B, stderr 0B. SHA-256 `9fba1154a8ba34872d958763eab407e5c3e0225672a81d05b635044b236a0eb2`.
- 다음 제거 대상은 rotate 계열과 SSE 이동/shuffle이며, 최종 게이트는 `unsupported=0`, `unexplained-native=0`으로 유지한다.

### 2026-08-22 — P1 ROL 전체 실행 계층 지원 완료

- `RotateLeft { width }` RISC op를 추가하고 8/16/32/64비트, 즉시값/CL count, 레지스터·메모리 목적지를 지원했다.
- x86 count 마스킹, 폭 내부 rotate, count=0 플래그 보존, CF 및 count=1 OF 의미론을 참조 evaluator에 구현했다.
- polymorphic ISA/interpreter, threaded harness, self-decoding native handler를 연결하고 guest RFLAGS를 실제 `ROL` 직전에 복원한다.
- 두 seed에서 reference evaluator = poly interpreter = native self-decoding 결과/플래그 동치를 통과했다.
- 타깃 재패킹 실측: VM 블록 `2,418 → 2,524`(+106), native `10,000 → 9,894`, RISC-unliftable `1,075 → 1,042`(-33), unsupported `1,605 → 1,522`(-83). ROL 실패 사유는 0건이다.
- differential 실행 gate 통과: exit 0, stdout 1,460B, stderr 0B. SHA-256 `0653bf75bb09d82a6f98fe5942ddf873a9326693d741ce59485e6436ff849744`.
- 다음은 SSE `MOVD/MOVQ`, packed compare, shuffle/unpack 계열을 XMM 상·하위 lane 보존 규칙과 함께 제거한다.

### 2026-08-22 — P1 SSE MOVD/MOVQ 및 XMM backing-store 연결 완료

- `MOVD/MOVQ`의 GPR/메모리↔XMM 양방향을 lift하고 XMM 목적지의 상위 96/64비트 zeroing, 32비트 GPR zero-extension, RFLAGS 불변을 구현했다.
- 기존 RISC XMM 모델의 합성 주소 `0xF000... + index*16`를 self-decoding 런타임의 실제 VM state `XMM_OFF` 저장소로 변환하는 read/write 경로를 추가했다. XMM0~15 전체 256바이트 창을 지원한다.
- 두 seed native backing-store 테스트에서 주소 변환 중 write 값 RAX가 덮이는 결함을 발견해, 값을 R11에 보존한 후 변환하도록 1/2/4/8바이트 write 핸들러를 수정했다.
- 타깃 재패킹에서 `MOVD/MOVQ` 실패 사유는 0건, unsupported `1,522 → 1,472`(-50). 같은 함수에 shuffle/compare 미지원이 함께 있어 VM 블록 수는 2,524로 유지됐다.
- differential gate 통과: exit 0, stdout 1,460B, stderr 0B. SHA-256 `648a5180951974f732cb7b44b46141e7199bb8facf2e5a2877e58ef25ab9bdb9`.
- 다음은 packed compare와 shuffle/unpack을 폴리 ISA 및 native XMM backing store 위에 올려 해당 함수 전체를 VM화한다.

### 2026-08-22 — Packed SSE native 활성화 보류 (안정성 게이트)

- 기존 packed RISC op를 폴리 ISA/native handler에 임시 연결해 16-byte lane compare 차등 테스트를 수행했다.
- native 실행에서 `STATUS_ILLEGAL_INSTRUCTION`이 재현되어 packed opcode dispatch/stream 경계를 추가 분리하기 전에는 ISA 등록을 철회했다. 안정 경로에 미검증 handler를 남기지 않는 것이 우선이다.
- XMM synthetic-address → VM backing-store 변환 단독 테스트는 2 seed에서 계속 통과한다. packed SSE는 native handler table 매핑·decoded operand 보존을 독립 테스트로 고친 뒤에만 재활성화한다.

### 2026-08-22 — Packed SSE native 재활성화 완료

- `PackedMove`, `PackedAdd/Sub`(8/16/32/64-bit lane), `PXOR/PAND/POR/PANDN`, `PCMPEQ`(8/16/32/64-bit lane)를 polymorphic ISA와 self-decoding native handler table에 다시 등록했다.
- 이전 `STATUS_ILLEGAL_INSTRUCTION`의 원인은 packed handler가 bytecode-base 전용 레지스터 `R8`을 소스 주소 임시값으로 덮어 다음 opcode 복호화를 깨뜨린 것이었다. 소스 주소를 물리 스택에 보존하고 모든 operand resolve가 끝난 뒤 `R9/R11`로 복원하도록 수정했다.
- 두 seed에서 연속 `PackedAdd → PackedCmpEq → PackedXor`를 실행해 reference evaluator = poly interpreter = native self-decoding 결과 및 RFLAGS 불변을 확인했다. poly-direct 회귀 37/37 통과.
- 전체 라이브러리 테스트는 521/522 통과. 유일한 실패는 기존 Windows invalid-filename 임시 경로 테스트(`differential::tests::failed_output_is_renamed_without_overwriting_existing_artifact`)로 packed SSE와 무관하다.
- 실제 타깃 재패킹: VM 블록 `2,524 → 2,801`(+277), native `9,894 → 9,617`, RISC-unliftable `1,042 → 842`(-200), unsupported `1,472 → 1,235`(-237). 실행 differential gate 통과(exit 0, stdout 1,460B, stderr 0B).
- 다음 packed SSE 범위는 `PCMPGTB/D`, `PSHUFD/PSHUFLW`, `PUNPCK*`, `PSRLQ`, `PMOVMSKB/MOVMSKPS`, `PINSRW`이다.

### 2026-08-22 — Packed signed compare 및 unpack 활성화 완료

- `PCMPGTB/W/D/Q`를 signed lane 비교로 reference evaluator, poly interpreter, native self-decoding handler에 연결했다. 실제 타깃 실패 사유에서 `PCMPGTB` 34건이 제거됐다(`PCMPGTD` 1건은 동일 함수의 다른 미지원 opcode 때문에 함수 단위 native 유지).
- `PUNPCKLBW/LWD/LDQ/LQDQ`와 `PUNPCKHBW/HWD/HDQ/HQDQ`를 추가했다. in-place 목적지에서도 원본 lane을 보존하도록 reference/poly 경로는 입력 16바이트를 먼저 snapshot하고 native 경로는 하드웨어 packed opcode를 사용한다.
- 실제 타깃에서 unpack 미지원 44건(`PUNPCKLBW` 36, `PUNPCKLQDQ` 4, `PUNPCKHQDQ` 4)이 모두 제거됐다. unsupported `1,235 → 1,157`(-78 누적: PCMPGT -34, PUNPCK -44), 실행 differential gate 통과(exit 0, stdout 1,460B, stderr 0B).
- poly-direct 회귀 37/37 통과. ISA 확장으로 unused opcode가 정확히 100개가 되어 과거의 `>100` cardinality 고정 테스트를 보안상 유효한 최소 trap reserve `>=64`로 수정했다. 모든 unused slot이 동일 trap VA를 가리키고 등록 handler와 겹치지 않는 검증은 유지한다.
- 다음은 즉시값을 decoded operand로 보존해야 하는 `PSHUFD/PSHUFLW`와 `PSRLQ`, 이후 GPR 결과형 `PMOVMSKB/MOVMSKPS` 및 `PINSRW`다.

### 2026-08-22 — Packed shift 및 shuffle 활성화 완료

- `PSRLQ xmm, imm8`을 `PackedShiftRightQ`로 추가했다. poly record의 src2 immediate를 native handler가 복원하고, XMM count operand를 구성해 두 64-bit lane을 독립적으로 shift한다. count>=64는 두 lane 모두 0이며 RFLAGS는 보존된다.
- `PSHUFD`와 `PSHUFLW`를 `PackedShuffle { low_words }`로 추가했다. imm8의 네 2-bit selector를 동적으로 적용하며, native handler는 입력 16바이트를 물리 스택에 snapshot한 뒤 scalar lane 선택을 수행해 dst==src in-place 케이스도 안전하다. `PSHUFLW`는 상위 64비트를 그대로 보존한다.
- reference evaluator = poly interpreter = native self-decoding 차등 테스트를 두 seed에서 통과했고 poly-direct 회귀 37/37도 통과했다.
- 실제 타깃에서 `PSRLQ` 20건과 `PSHUFD` 49건, `PSHUFLW` 36건이 모두 실패 사유에서 제거됐다. unsupported `1,157 → 1,052`(-105), RISC-unliftable 함수 `842 → 826`, VM 블록 `2,801 → 2,803`, native 블록 `9,617 → 9,615`. 실행 differential gate 통과(exit 0, stdout 1,460B, stderr 0B).
- 다음은 XMM→GPR 결과형 `PMOVMSKB/MOVMSKPS`와 즉시 lane 삽입 `PINSRW`, 그리고 legacy alias `XORPS`를 처리한다.

### 2026-08-22 — Unsupported 500 미만 대량 축소 완료

- `operand_value`의 공통 immediate lowering에 iced-x86 `Immediate8to16`과 `Immediate8to32`를 추가했다. 기존 산술/논리 opcode 지원을 그대로 활용하면서 실패 사유 477건(`Immediate8to32` 473 + `Immediate8to16` 4)을 한 번에 제거했다.
- `UD2`를 `Trap` RISC op로 추가하고 randomized poly ISA 및 self-decoding native handler table에 등록했다. native handler는 실제 `UD2`를 실행해 architecturally guaranteed invalid-instruction 의미를 유지하며, reference/poly 호스트 테스트 경로에서는 안전하게 실행 종료로 모델링한다. 이로써 미지원 174건을 제거했다.
- 실제 타깃 재패킹 결과: unsupported `1,052 → 401`(-651), VM 블록 `2,803 → 5,653`(+2,850), native 블록 `9,615 → 6,765`(-2,850), RISC-unliftable 함수 `826 → 307`(-519). 목표 `unsupported < 500` 달성.
- release 보호본 differential gate 통과: exit 0, stdout 1,460B, stderr 0B. Program VM bytecode는 551,224B이며 보호본 크기는 1,595,392B다.
- poly-direct 37/37, RISC lifter 80/80 통과. 전체 lib는 521/522 통과했으며 유일한 실패는 기존 Windows invalid-filename 테스트(`differential::tests::failed_output_is_renamed_without_overwriting_existing_artifact`)다.
- 남은 401건의 주축은 안정성 게이트된 RIP-relative 301건이다. 그 외 bit-test 32건, SHLD 29건, system/trap 계열과 SSE mask/insert/alias가 남아 있다.

### 2026-08-22 — P1-1 non-SEH unsupported 0 완료

- RIP-relative memory 301건을 resolved absolute target lowering으로 재활성화했고 release differential 실행을 통과했다.
- `SHLD`, `BT/BTR/BTS`를 width-aware RISC op, poly ISA, native hardware handler로 구현했다. 단독 차등은 통과하지만 해당 함수의 VM 소유권 전환은 whole-program AV를 재현해, 구현 지원과 소유권 정책을 분리하고 포함 함수만 atomic native integration quarantine으로 유지한다.
- `PMOVMSKB`, `MOVMSKPS`, `PINSRW`, `XORPS`, `CPUID`, `XGETBV`, `INT`, FS/GS segment-base lowering, AH/BH/CH/DH high-byte memory store를 구현했다.
- 실제 타깃 최종 결과: VM blocks 7,004, native 5,414(SEH/integration policy), RISC-unliftable 0, unsupported 0. 실행 differential gate 통과(exit 0, stdout 1,460B, stderr 0B).
- 전체 라이브러리 회귀 523/523 통과. XGETBV 지원 전제를 반영해 과거 unsupported fixture를 `SYSCALL`로 교체했고 Windows test thread name의 `::` 때문에 잘못된 임시 경로가 만들어지던 differential 테스트도 수정했다.
- P1-1 완료 기준(non-SEH RISC-unliftable 0, unsupported 0)을 달성했다. 다음 작업은 P1-2 SEH/Rust panic 완전 소유이며 현재 native policy 블록 5,414개를 guest unwind/personality fixture부터 단계적으로 줄인다.

### 2026-08-22 — P1-2 strict ownership 기준선 구축

- 기존 `BTG_SEH_NONE=1`은 이름과 달리 computed-jump EHANDLER와 Once/panic 공유상태 함수 68개를 계속 네이티브로 남기는 guarded 모드였음을 확인했다.
- `BTG_SEH_OWNERSHIP=full` strict 모드를 추가했다. 이 모드에서는 SEH/panic native allowlist를 0으로 만들며, 기존 `BTG_SEH_NONE=1` 동작은 호환성을 위해 guarded 모드로 유지한다.
- commercial Program-VM 진입 조건까지 strict 모드를 배선했고 text-lift 회귀 11/11과 release 빌드를 통과했다.
- 실제 타깃 strict 기준선: SEH/panic allowlist 0, VM blocks `7,004 → 11,603`. 별도 SHLD/BT integration quarantine 및 function-atomic fallback 815 blocks는 SEH와 분리해 집계하도록 진단을 수정했다.
- strict 보호본은 구조 검증을 통과하지만 실행 시 exit 0/stdout 0B로 조기 종료한다. 다음 단계는 computed indirect branch의 guest-frame 진입과 panic raise→catch personality 경로를 독립 fixture로 분리해 최초 의미 불일치 지점을 찾는 것이다.

### 2026-08-22 — P1-2 panic/unwind 독립 fixture 1차 분리

- `test/src/src/bin/panic_unwind_fixture.rs`를 추가했다. marker마다 stdout을 flush하며 `catch_unwind`, cleanup `Drop`, nested catch, `resume_unwind` rethrow를 독립 검증한다.
- 원본 fixture는 `fixture-start → inner-caught → outer-caught → cleanup-ok`, exit 0을 통과한다.
- guarded ownership은 5,145 VM / 1,574 native(SEH 939 + integration quarantine 635), strict full ownership은 6,051 VM / 668 native(SEH 0 + integration/atomic 668)까지 구조 검증을 통과했다.
- 두 보호본 모두 첫 marker 이전 `0xC0000005`, WER `ntdll.dll+0xDC86`에서 실패한다. 전체 개별 보호 옵션 프로필에서도 동일하다.
- 따라서 최초 blocker는 panic payload/cleanup 의미론이 아니라 CRT startup → Program-VM → native return/unwind 경계다. 이 공통 bootstrap 경계를 고치기 전에는 catch personality 결과를 판정할 수 없다.

### 2026-08-22 — P1-2 Program-VM unwind frame 1차 수정 및 실측

- commercial dispatcher가 모듈 시작의 JMP 뒤에서 R12/R13/R14/R15/RDI/RSI/RBX/RBP 8개 nonvolatile register를 push하면서도 `.pdata`에는 leaf로 등록되던 결함을 수정했다. 8 push를 RVA 0의 연속 프롤로그로 이동했다.
- 생성 UNWIND_INFO가 `prolog_len=0xC`, unwind code 8개를 포함하는 것을 실제 guarded/full 산출물에서 확인했다. poly-direct 38/38, `.pdata` build 6/6 통과.
- panic fixture 재검증 결과 guarded/full 모두 여전히 첫 marker 이전 `0xC0000005`. `--keep-pdata`에서도 동일해 exception-directory 재작성 자체는 배제했다.
- 남은 직접 원인: native-call bridge가 `and rsp,-16; sub rsp,0xB0` private frame을 만든 상태에서 native callee를 호출하지만, 현재 모듈 UNWIND_INFO는 entry 8-push만 기술한다. native callee에서 unwind가 시작되면 bridge의 동적 정렬 + 0xB0을 복원할 수 없다.
- 다음 수정: bridge 정렬을 고정 크기 프레임으로 전환하고, native-call bridge machine-code 범위를 별도 RUNTIME_FUNCTION으로 노출해 `ALLOC_LARGE + entry nonvolatile saves`를 기술한다.

### 2026-08-22 — P1-2 native-call bridge 전용 unwind metadata 구현

- native-call bridge의 동적 `and rsp,-16; sub rsp,0xB0`를 동일 정렬의 고정 `sub rsp,0xB8`로 전환해 x64 unwind로 표현 가능하게 만들었다.
- commercial codegen이 bridge machine-code begin/end를 `SelfDecodingParts → VmModule → PipelineContext`로 전달한다.
- Program-VM RUNTIME_FUNCTION을 entry recipe / native bridge recipe / post-bridge recipe 세 구간으로 분할했다. bridge recipe는 `UWOP_ALLOC_LARGE(0xB8)`와 entry nonvolatile save 8개를 함께 복원한다.
- ownership validator가 gap 없는 복수 RUNTIME_FUNCTION 커버리지를 인정하도록 확장했다. gap 허용/거부 회귀를 포함해 ownership 10/10, poly-direct 38/38, `.pdata` build 6/6 통과.
- 구조 검증 실측: Program-VM 3구간 포함 381 RUNTIME_FUNCTION, ownership clean. 그러나 panic fixture와 panic 없는 `vm_startup_fixture` 모두 첫 stdout 이전 AV가 계속된다.
- 결론: panic/unwind 이전의 OEP/CRT 첫 VM→native 호출에서 guest RSP 또는 인자/return target 상태가 잘못된다. 다음 진단은 첫 bridge target, guest RSP, RCX/RDX/R8/R9를 런타임 snapshot으로 수집한다.

### 2026-08-22 — P1-2 native bridge ABI 수정 및 strict-full 실행 통과

- 런타임 snapshot으로 첫 native target이 정상 CPUID 초기화 함수임을 확인했고, 첫 실패 write는 원본 `mov [rsp+0x20], sil`에 대응하지만 guest effective address가 `0x4A`로 붕괴한 것을 추적했다.
- 원인은 native-call bridge가 production의 seed-derived `VmRuntimeLayout` 대신 legacy 고정 state offset으로 guest RSP/GPR/flags/FP-return 슬롯을 읽고 쓰던 것이었다. 모든 bridge state access를 runtime-layout translator로 전환했다.
- 실제 native FP callee 실행 테스트를 seed-derived layout으로 강화했다. 이 테스트가 추가로 찾아낸 FP-return hint 고정 offset도 수정했으며 randomized layout에서 Win64 FP 인자 전달과 반환 동기화를 통과한다.
- 실제 panic fixture guarded/full 재패킹 및 `--verify-output` 실행을 모두 통과했다. full은 `catch_unwind`, cleanup `Drop`, nested catch, `resume_unwind` rethrow를 보존하면서 SEH/panic native 함수 0, ownership clean(381 RUNTIME_FUNCTION)을 달성했다.
- 같은 fixture에 worker-thread panic, thread-local cleanup, `JoinHandle::join` 오류 전파를 추가했다. `BTG_SEH_NONE=1` strict-full 재검증에서 SEH/panic native 0, ownership clean(504 RUNTIME_FUNCTION), execution_verified=true, exit 0, stdout 68B, stderr 0B를 통과했다.
- `vectored_exception_fixture`를 추가해 VEH 등록, continuable `RaiseException`, handler 복귀, handler 해제를 검증했다. strict-full에서 SEH/panic native 0, ownership clean(356 RUNTIME_FUNCTION), execution_verified=true, exit 0을 통과했다.
- MSVC C `setjmp_longjmp_fixture`를 추가했다. MSVC x64가 setjmp/longjmp를 IAT import가 아닌 정적 vcruntime intrinsic으로 링크하는 경우를 위해 context save/restore prefix 탐지를 추가하고, 누락돼 있던 commercial whole-program 경로에도 non-local-jump native boundary를 적용했다.
- setjmp/longjmp fixture strict-full은 1,397-function direct-call closure를 의도된 non-local-jump 경계로 보존하며 ownership clean(1,590 RUNTIME_FUNCTION), execution_verified=true, exit 0, stdout 26B, stderr 0B를 통과했다. 이 경계는 SEH/panic 0 집계와 별도로 보고한다.
- `BTG_SEH_NONE=1`을 이름과 완료 기준에 맞게 strict-full로 전환했다. 이전 안전망 동작은 명시적 `BTG_SEH_OWNERSHIP=guarded`로만 선택한다.
- 실제 본체 `rust_packer_test.exe`도 `BTG_SEH_NONE=1`, `--vm --vm-oep --vm-commercial --m8 --integrity --payload-relocate --rsrc-register --anti-debug --verify-output` 프로필에서 재패킹·ownership·실행 차등검증 exit 0을 통과했다.

### 2026-08-22 — P1-2 완료 및 P1-3 coverage gate 착수

- P1-2의 독립 fixture(`catch_unwind`, cleanup, nested/rethrow, VEH, setjmp/longjmp, thread unwind), strict `BTG_SEH_NONE=1`, generated Program-VM/bridge `.pdata/.xdata`, 실제 본체 차등실행 기준을 모두 통과해 P1-2를 완료로 확정했다.
- commercial lift 결과에 block/instruction/function coverage의 분자·분모를 추가하고 `[VM-COVERAGE]` 단일행 JSON 진단을 출력한다. 실행 프로파일 입력이 없는 hot-path 축은 거짓 수치 대신 `unprofiled`로 명시한다.
- `BTG_MIN_VM_INSTRUCTION_COVERAGE=<0..100>` gate를 추가했다. 실제 본체 기준선은 block `11,603/12,419 = 93.4294%`, instruction `47,971/51,256 = 93.5910%`, function `764/778 = 98.2005%`, strict-full 실행 차등 exit 0이다.
- 95% instruction gate가 `actual 93.591% < required 95.000%`로 pack을 exit 1 처리하는 것을 실측했다. 남은 병목은 SEH/panic 0이 아니라 integration quarantine 782 blocks이므로 다음 단계는 SHLD/BT 계열 quarantine을 family별 whole-program gate로 재활성화해 instruction coverage를 95% 이상으로 올리는 것이다.
- SHLD와 BT/BTR/BTS quarantine을 family별로 해제해 실제 본체를 bisect했다. SHLD 단독은 instruction 94.2309%, BT family 단독은 99.1669%였고 둘 다 strict-full 차등 exit 0을 통과했다.
- 두 family 동시 활성화도 block `12,385/12,419 = 99.7262%`, instruction `51,157/51,256 = 99.8069%`, function `777/778 = 99.8715%`, integration quarantine 0, 95% gate, ownership clean, 실행 차등 exit 0을 통과했다.
- 검증된 두 family를 기본 VM ownership으로 승격했다. 과거 경계 재현은 `BTG_VM_INTEGRATION_QUARANTINE=shld,bt` 진단 스위치로만 opt-in 한다.
- P1-3 sensitive gate를 구현했다. SDK marker가 있으면 commercial Program-VM의 CFG block ownership과 대조해 지정 영역에 native block이 하나라도 있거나 CFG에서 사라지면 pack을 실패시킨다. commercial 경로에서는 미완성 selective marker backend로 중복 전달하지 않고 Program-VM gate가 직접 소유한다.
- inline marker payload를 선형 CFG가 명령으로 오인하던 문제를 분석용 NOP 정규화로 해결했다(원본 실행 바이트는 불변). `sensitive_marker_fixture` panic-abort corpus에서 marker 1개 100% VM ownership, ownership clean(330 RUNTIME_FUNCTION), execution_verified=true, exit 0을 통과했다.
- weighted hot-path gate `BTG_VM_HOT_PATH=RVA[:hits],...`를 추가했다. 실제 본체 OEP `0x2CCBC:1000`은 hot ratio 1.0 및 차등 exit 0을 통과했고, 미소유 RVA 입력은 `VM-owned weight 0/1`로 pack exit 1을 확인했다.
- release panic-unwind marker fixture에서는 generated unwind 추가로 원본 `.pdata` virtual span이 다음 `.reloc` 정렬 경계를 8바이트 침범하는 별도 섹션-growth 회귀를 발견했다. panic-abort fixture로 marker gate 의미 검증은 완료했으며, `.pdata` 성장 시 후속 section 재배치/별도 exception section 처리는 구조 후속 항목으로 남긴다.
- coverage 결과를 `PipelineContext`에서 build manifest까지 전달해 `vm_blocks`, `vm_instructions`, `vm_functions`, `vm_hot_path`, `vm_sensitive_regions`를 분자/분모로 기록한다. generated VM→native bridge의 실제 output RVA half-open range도 `native_bridge_ranges`에 기록한다.
- 실제 본체 hot-profile/95% gate/strict-full 산출물 manifest 실측: blocks `12385/12419`, instructions `51157/51256`, functions `777/778`, hot path `1000/1000`, sensitive regions `0`, native bridge `0x96EE9..0x97182`, execution_verified=true/exit 0.
- 이로써 P1-3 완료 기준(instruction ≥95%, 지정 marker 100% gate, hot-path ownership 입력/gate, generated native bridge manifest 기록)을 충족했다. 다음 작업은 P1-4 Program-VM bytecode on-demand chunk encryption과 M7 충돌 제거다.


### 2026-08-22 — 추가 심층 코드 감사: 출시 차단급 correctness/crypto/PE 항목 등록

- 기존 P0~P2 진행 기록과 별개로 현재 소스 스냅샷을 다시 전수 정적 감사해, 대표 코퍼스 실행 성공만으로는 드러나지 않는 fail-open/PE edge case/암호 신뢰모델 문제를 별도 release gate로 등록했다.
- 신규 P0 핵심은 ChaCha20-Poly1305의 block-0 재사용 및 Poly1305 one-time key 평문 배치, RIP-relative fixup overflow의 `Ok(())` fail-open, 모든 `INT3` 제거, PE section-table header capacity 미계산, unresolved fallthrough의 synthetic `RET`이다.
- 신규 P1 핵심은 PE raw-range/.pdata strict parsing, BTG-C1/자체 MAC 보안 주장 정리, CLI/SDK config 단일화, dormant native ABI emitter의 stack-balance 결함과 commercial virtual-stack bounds 명시화다.
- 이 항목들은 strict-full differential 실행 성공 및 99%대 VM coverage와 모순되지 않는다. 현재 코퍼스가 해당 edge case를 밟지 않았다는 뜻일 뿐이며, 상용 release gate는 **실행 동치 + hostile/malformed PE + crypto construction + semantic preservation**을 동시에 통과해야 한다.
- 아래 신규 항목의 `파일:라인`은 이번 감사에 사용한 제공 소스 스냅샷 기준이다. 수정 후 line drift가 생기므로 향후 항목 ID와 테스트명을 함께 유지한다.

## 1. 결론

현재 BTG는 `--vm-commercial` 경로에서 OEP를 Program VM으로 넘기고, RISC lift → polymorphic ISA → threaded dispatcher → 암호화된 VM bytecode까지 실제로 생성한다. 초기 최대 VM 산출물은 CRC4 구현 결함으로 `0xC000001D`가 났지만 이를 수정했고, 현재 보호본은 원본과 byte-for-byte 실행 동등성을 통과하며 multi-seed 3/3도 성공한다. 다만 P1 개선 후에도 VM 블록 비율은 약 19.09%라서 Themida급 가상화 범위에 도달했다고 볼 수 없으며, 옵션 충돌로 일부 `--full` 보호가 비활성화되는 문제도 남아 있다.

초기 감사 당시 옵션 해석기는 `--vm-oep`가 켜지면 dispatcher re-encryption, IAT hiding, memory hardening을 끄고 `--m7`도 VM과 충돌했다. 이 관측은 아래 P1-4/P1-5/P1-6 작업으로 해소됐으며, 현재는 Program-VM M7, IAT hide, mem-harden을 함께 적용할 수 있다. 네이티브 block dispatcher re-encryption만 Program-VM dispatcher와 구조적으로 배타적이다.

Themida 실물로 같은 EXE를 보호한 비교 바이너리는 제공되지 않았으므로, Themida 쪽 비교는 Oreans 공식 기능표·도움말·변경 이력을 기준으로 한 **기능/아키텍처 비교**다. Themida 바이너리와의 바이트·CFG·동적 트레이스 직접 비교는 별도 라이선스와 동일 입력으로 만든 비교 산출물이 있어야 완료할 수 있다.

## 2. 실험 대상과 산출물

### 입력

- 실제 입력: `test/src/target/release/rust_packer_test.exe`
- 사용자가 적은 `_packer/_test.exe`는 실제 파일명이 아니었고, 디스크상의 파일명은 `rust_packer_test.exe`였다.
- 크기: 268,288 bytes
- SHA-256: `cd6616712a69de660b6529aac0721ca6f22eca0512f8465bab726eea64e7cf64`
- 원본 실행: 정상 종료(0), 최종 체크섬 `0x2cdc0e4511d84a64`

### 최대 공격적 VM 산출물

- 파일: `test/src/target/release/rust_packer_test.btg.max.exe`
- 명령 개념: `--full --vm --vm-oep --vm-commercial --m7 --m8`, `BTG_SEH_NONE=1`
- 크기: 896,512 bytes (원본 대비 3.34배)
- SHA-256: `3228e2d24d7f454068c8b378702ad1d18ecf1a8e136b21268e1253bbda00a197`
- 패킹/PE 검증: 성공
- 실행: 실패, `0xC000001D`
- 초기 측정 주의(해결됨): 당시 `--m7`과 VM-OEP 조합, IAT hide, mem-harden이 profile resolver에서 비활성화됐다. 현재 결합 동작은 P1-4/P1-5/P1-6 완료 근거를 따른다.

### 호환성 우선 최대 VM 산출물

- 파일: `test/src/target/release/rust_packer_test.btg.vmmax.exe`
- 명령 개념: `--full --vm --vm-oep --vm-commercial --m8 --anti-debug-policy warn`, 기본 SEH 보존
- 크기: 887,296 bytes (원본 대비 3.31배)
- SHA-256: `63e9c8be4314cd0643ee0c5248bd11c8d2b997564f379722142557989ff56c6f`
- 패킹/PE 검증: 성공
- 실행: 실패, `0xC000001D`
- 로그: `test/src/target/release/rust_packer_test.btg.vmmax.pack.log`
- manifest: `test/src/target/release/rust_packer_test.btg.vmmax.exe.btgmanifest`
- ownership map: `test/src/target/release/rust_packer_test.btg.vmmax.exe.ownership.csv`

`anti-debug-policy=warn`에서도 같은 예외가 발생하므로 첫 실패를 단순 anti-debug 탐지로 볼 수 없다. VM entry stub, VM bytecode 복호화, handler dispatch, native bridge 또는 잘못 virtualize된 trap/UD2 경로 중 하나가 더 유력하다. 정확한 fault RVA와 첫 분기 트레이스가 없으므로 현 단계에서 단일 원인으로 단정하지 않는다.

## 3. 실제 정적/구조 분석 결과

### 3.1 보호 커버리지

- 원본 CFG: 12,419 basic blocks.
- shuffle 단계: 7,621 blocks 처리, 4,798 blocks는 SEH 이유로 native 유지.
- commercial RISC VM 단계: 1,859 blocks virtualized, 10,559 blocks native.
- native 세부: SEH 9,130 blocks + RISC-unliftable 1,429 blocks.
- RISC lift unsupported instruction: 2,114개.
- 블록 기준 VM 커버리지: `1,859 / 12,418 ≈ 14.97%`.
- native 비율: 약 85.03%.
- ownership 검증: 781 functions 중 VM owner는 Program VM module 1개, native owner 780개. 이것은 모듈 소유권 표기이지 원본 함수 780개가 모두 VM화됐다는 뜻이 아니다.
- Program VM bytecode: 130,334 bytes, at-rest 암호화됨.
- 원본 `.text`: 보존된 190,464-byte run이 존재하며 at-rest 암호화 대상으로 기록됨.
- 출력 section entropy: `.text` 7.999, `.textb` 7.237 bits/byte. 암호문 은닉은 강하지만 고엔트로피 section 자체가 packer/암호화 payload의 강한 정적 표식이 된다.

핵심 부족점은 “OEP가 VM에 들어간다”와 “프로그램 의미의 대부분이 VM에 있다”가 다르다는 점이다. OEP 전환은 성공 로그가 있지만 실제 원본 블록의 약 15%만 VM화됐고 나머지는 native bridge를 통해 실행된다. 정적 분석자는 native island와 bridge graph를 우선 복구하면 된다.

### 3.2 옵션 합성 결함

실제 경고와 `src/protection_profile.rs`의 조건이 일치한다.

- `src/protection_profile.rs:169`: VM-OEP가 dispatcher re-encryption을 비활성화.
- `src/protection_profile.rs:177-180`: VM-OEP가 IAT hiding을 비활성화.
- `src/protection_profile.rs:187-194`: VM-OEP/reencryption이 memory hardening을 비활성화.
- `src/protection_profile.rs:268`: M7 on-demand re-encryption이 VM/VM-OEP와 충돌해 무시됨.
- `src/protection_profile.rs:408-409` 테스트도 이 비활성화를 기대값으로 고정한다.

즉 결함은 사용법 문제가 아니라 설계·테스트에 명시된 현재 동작이다. `--full`이라는 이름과 실제 effective profile이 다르며 manifest의 feature flags만 봐도 사용자가 요청한 보호의 일부가 빠진다.

### 3.3 W^X/메모리 보호

초기 감사 산출물의 manifest `wx_contract`는 `rwx-at-rest,code-data-split,at-rest-ciphertext`였고 code/state가 같은 writable+executable arena에 남았다. P1-5 이후 계약은 `transient-rw-to-rx,rx-after-verify,rw-state,...`이며 bootstrap 뒤 immutable 영역 RX와 mutable state RW를 분리한다.

### 3.4 ASLR/PE 메타데이터

manifest에 `aslr_preserved = false`가 기록됐다. 이는 재배치/절대주소 결합 때문에 로드 주소 다양성을 포기한 상태다. 최신 Windows 보호기에서 ASLR 상실은 방어 심층성과 호환성 모두에 불리하다. `.pdata` ownership 사후 검증은 통과했지만 실행은 실패했으므로 PE 구조 정합성 검사만으로 ABI/의미 정합성을 보장하지 못한다.

### 3.5 VM 다형성

현재 구현에는 seed 기반 opcode map과 register permutation이 있다(`src/vm/poly/isa_spec.rs:212`, 여러 encoder/decoder/interpreter의 `VirtualIsaSpec::from_seed`). 그러나 같은 공통 RISC 의미 집합과 공통 dispatcher/builder 계열을 유지한다. 이것은 인코딩·레지스터 배치 다형성에는 해당하지만, 서로 다른 VM family/architecture, handler semantic decomposition, dispatcher topology를 빌드마다 독립 생성하는 수준과는 다르다.

이번 manifest는 `seed_id = none`, `build_id` seed 부분이 0이다. 내부 RNG가 일부 랜덤이어도 외부 감사 관점에서는 ISA/레이아웃 다양성의 provenance와 재현 정보가 부족하다. seed를 명시한 N-build 차분 실험을 자동화해야 한다.

### 3.6 암호화·무결성·덤프 저항

- VM bytecode at-rest 암호화와 integrity flag는 존재한다.
- 그러나 VM-OEP 조합에서는 dispatcher re-encryption과 M7이 빠진다. 실행 중 필요한 VM bytecode/handler/state가 지속적으로 관찰 가능한 창이 생긴다.
- `src/vm/embed_hardening.rs`와 `src/vm/threaded/poly_direct/builder.rs:837` 근처에 handler-table integrity가 있으나, 전체 VM state·bytecode page·native bridge·IAT를 지속 검증하는 통합 런타임 무결성 계층은 확인되지 않는다.
- manifest의 `crypto_mode = c1`은 자체 설계 암호다. 소프트웨어 보호에서 암호 강도만으로 덤프를 막을 수 없고, 실제 핵심은 plaintext lifetime/keys/state의 관찰 창을 줄이는 것이다.

### 3.7 안티 분석

`src/antidebug/mod.rs`는 PEB `BeingDebugged`, `NtGlobalFlag`, heap flags 중심의 PIC bootstrap이다. 정적 패턴화하기 쉽고, monitor/sandbox/hardware-breakpoint/VEH instrumentation/DBI/API-hook/time anomaly 등의 신호를 분산·상호검증하는 subsystem은 부족하다. 탐지 정책도 trap/hang/warn/poison이 있으나 이번처럼 정상 환경에서 illegal instruction이 발생하면 제품 신뢰성을 훼손한다. 보호 신호와 VM 오류를 구분해 진단할 수 있어야 한다.

### 3.8 진단 가능성

장점은 manifest, layout log, ownership CSV, post-build PE validation이 이미 있다는 점이다. 반면 현재 기본 로그가 수 MB의 disassembly/debug dump를 생성해 핵심 진단을 묻고, 실행 실패 시 fault RVA/VM VIP/handler id/native bridge target을 자동 수집하지 않는다. “생성 성공”과 “동작 성공”이 분리돼 있다.

## 4. Themida 대비 부족한 점

Oreans 공식 비교표는 Themida에 code virtualization/mutation, runtime string encryption 및 재암호화, anti-debug, API wrapping, whole-application encryption/compression, integrity checks, multiple startup checks, monitor detection이 별도 계층으로 함께 존재한다고 설명한다. 공식 보호 옵션 문서는 API wrapping, boot loader/resource 암호화·압축, VM macro 문자열의 사용 시점 복호화 및 재암호화, anti-file-patching, anti-sandbox, VM macro별 protection checks를 명시한다.

2026-08-11의 3.2.6.0 변경 이력은 VM register randomization, VM instruction reordering, virtualization return-address 보존, anti-sandbox, relocation, x64 exception handling을 계속 개선했다고 기록한다. 따라서 비교에서 중요한 것은 기능 이름의 유무가 아니라 다년간 축적된 VM/예외/재배치/호환성의 결합 완성도다.

공식 근거:

- https://www.oreans.com/CompareProducts.php
- https://www.oreans.com/Themida.php
- https://www.oreans.com/help/tm/hm_protection-options.htm
- https://www.oreans.com/ThemidaAllWhatsNew.php
- https://www.oreans.com/help/tm/hm_faq_i-see-that-themida-detects-if_.htm

BTG의 구체적 격차는 다음과 같다.

1. **조합 가능성**: Themida의 기능표는 보호 계층을 병렬 기능으로 제공하지만 BTG는 VM-OEP가 re-encrypt/IAT hide/mem harden/M7을 제거한다.
2. **실행 신뢰성**: 이번 대표 Rust 코퍼스에서 최대 VM 산출물이 시작조차 못 한다.
3. **실질 VM 커버리지**: OEP는 VM이지만 블록의 약 15%만 VM화되고 85%는 native다.
4. **예외/언와인드 소유권**: Rust panic/SEH 때문에 9,130 blocks가 native로 남는다. full-SEH 실험은 크래시했다.
5. **ISA 다양성**: seed 기반 opcode/register permutation은 있으나 여러 독립 VM architecture/family와 build-time handler semantics 생성이 부족하다.
6. **실행 중 재암호화**: VM과 M7/dispatcher re-encryption이 통합되지 않았다.
7. **API 보호**: 최대 VM에서 IAT hide가 꺼지므로 원본 import가 정적으로 노출된다.
8. **메모리 정책**: RWX arena와 ASLR 비보존이 남는다.
9. **안티 분석 폭**: 기본 PEB/heap 신호 중심이며 monitor/sandbox/DBI/hardware breakpoint/anti-tracing 계층이 얕다.
10. **문자열/데이터 수명**: VM macro 단위 on-use decrypt/re-encrypt와 같은 객체별 lifetime 정책이 명확히 통합되지 않았다.
11. **무결성 범위**: 파일/초기 코드 CRC와 handler table 체크를 넘어 VM state, bytecode pages, bridge, import resolution의 지속적 분산 검증이 부족하다.
12. **재배치/ASLR**: ASLR이 보존되지 않는다.
13. **제품 수준 호환성**: compiler/optimization/Windows/microcode별 광범위한 회귀 게이트와 crash triage 자동화가 부족하다.
14. **보호 프로필 진실성**: requested flags와 effective flags가 크게 다르며 `--full` 명칭이 이를 숨긴다.

## 5. 구현 계획

### P0 — 정상 동작과 프로필 진실성 (출시 차단)

#### P0-1. illegal-instruction 최초 원인 확정

- VM entry 직전/직후에 최소 crash telemetry를 넣는다: stage id, guest RIP/VIP, handler id, rolling key state hash, native bridge target, last 32 transitions.
- `0xC000001D`의 fault RVA를 자동 수집하고 layout/map/ownership과 역매핑한다.
- anti-debug trap, 원본의 의도된 `ud2/int 29h`, VM decode 오류, 잘못된 native transfer를 서로 다른 exception code/telemetry로 구분한다.
- 다음 프로필을 하나씩 bisect한다: `vm+vm-oep`, `+vm-commercial`, `+m8`, `+integrity`, `+payload-relocate`, `+anti-debug`, `BTG_SEH_NONE=1`.
- 동일 seed로 재현되는 최소 failing block/function을 추출해 unit fixture로 만든다.

완료 기준: 원본과 동일한 16개 결과 및 최종 체크섬을 출력하고 exit 0. 100회 반복과 cold boot 20회에서 실패 0건.

#### P0-2. pack 성공 조건 강화

- pack 후 원본/보호본 differential execution을 기본 gate로 제공한다.
- 실행 실패 시 출력물을 `.failed.exe`로 표시하고 성공 산출물로 보고하지 않는다.
- stdout/stderr/exit code/selected files/GUI initialization 결과를 비교한다.
- timeout, child process, GUI 프로그램을 위한 harness를 분리한다.

완료 기준: `--qa-commercial`이 이 테스트를 통과하지 못하면 release build가 실패.

#### P0-3. requested/effective profile 분리

- CLI 종료 전에 requested flags, effective flags, disabled flags와 정확한 이유를 표로 출력한다.
- `--strict-profile`을 추가해 요청된 보호 하나라도 비활성화되면 pack을 실패시킨다.
- manifest에 `requested_feature_flags`, `effective_feature_flags`, `disabled_features`, `disable_reasons`를 기록한다.
- `--full --vm-oep`처럼 이름과 결과가 다른 조합은 별도 `vm-max`/`native-max` 프로필로 명시한다.

완료 기준: “max/full” 프로필에서 조용히 무시되는 옵션 0개.


#### P0-4. ChaCha20-Poly1305 통합을 표준 AEAD 계약으로 교정

**현재 코드 연결**

- `src/pipeline/crypto/mod.rs:343-346`: `derive_chacha_key_nonce_raw()`로 키/nonce를 얻은 뒤 `chacha_init_state()` 직후 payload 암호화를 시작한다.
- `src/crypto/chacha20.rs:74-80`: `chacha_init_state()`가 counter를 0으로 초기화한다.
- `src/crypto/chacha20.rs:90-107`: 첫 keystream block 생성 시 현재 counter를 그대로 사용하므로 payload 첫 블록은 `counter=0`을 소비한다.
- `src/pipeline/crypto/mod.rs:347-357`: 동일 `(key, nonce)`의 `chacha20_block(..., 0, ...)`에서 Poly1305 one-time key를 다시 파생한다.
- `src/pipeline/crypto/place/mod.rs:411-424`: Poly1305 verify blob 뒤에 32B key + 16B tag 공간을 예약한다.
- `src/pipeline/crypto/place/mod.rs:1032-1053`: pack-time에 계산한 Poly1305 32B key를 출력 PE에 그대로 기록한다.
- `src/pipeline/crypto/bootstub/build.rs:141-149`: boot stub이 그 key VA와 tag VA를 verify routine에 직접 넘긴다.

**문제**

1. RFC 8439 계열 AEAD에서는 block 0을 Poly1305 one-time key 생성용으로 분리하고 payload encryption은 counter 1부터 시작해야 한다. 현재 구현은 payload stream과 Poly1305 key derivation이 block 0 material을 공유한다.
2. Poly1305 one-time key가 보호 PE에 평문으로 존재하므로, 파일을 패치할 수 있는 공격자는 암호문을 바꾼 뒤 같은 key로 새 tag를 계산할 수 있다. 현재 구조는 accidental corruption 검출에는 의미가 있어도 강한 anti-tamper root-of-trust로 볼 수 없다.
3. `src/crypto/chacha20_tests.rs:31-55`는 RFC counter=1 block vector를 확인하지만 실제 packer 통합 경로의 “block0=MAC key / block1+=payload” 계약은 검증하지 않는다.

**수정**

- AEAD payload state는 initial counter=1을 명시한다.
- `chacha_aead_key: Option<[u8;32]>`를 placement API에서 제거하고 runtime이 ChaCha state로 block0 key를 일시 생성한 뒤 verify 직후 zeroize한다.
- pack-time tag 계산과 native boot verify가 동일한 construction helper/명세를 공유하게 한다.
- publisher authenticity까지 주장하려면 offline private key + executable public verify key 또는 Authenticode 같은 별도 신뢰 경계를 둔다.
- manifest에 `crypto_construction`, `payload_initial_counter`, `poly_key_embedded`를 기록한다.

**필수 테스트**

- RFC 8439 AEAD 전체 vector에서 ciphertext + tag byte-for-byte 일치.
- packer reference ↔ native boot verify/decrypt differential.
- 첫 64B known-plaintext corpus에서 block0과 payload keystream 분리 확인.
- 출력 PE scan에서 raw Poly1305 one-time key 0건.
- ciphertext/tag 각각 1-bit mutation 100% fail-closed.
- `--crypto-mode chacha20 --verify-output --verify-seeds 20` 전부 동치.

완료 기준: payload counter 1, on-disk Poly1305 key 0건, RFC AEAD/native differential 통과, mutation corpus 100% 거부.

#### P0-5. RIP-relative fixup overflow를 fail-open에서 fail-closed로 전환

**현재 코드 연결**

- `src/pipeline/pass3_encode.rs:89-100`: RIP-relative target resolve 뒤 `RipFixupEngine::process_fixup()` 결과를 `?`로 전달한다.
- `src/graph/fixup.rs:76-90`: signed disp32 범위를 벗어나면 error log만 남기고 `return Ok(())` 한다.
- `src/graph/fixup.rs:159-169`: overflow 테스트 역시 현재 `result.is_ok()`를 기대한다.

**문제**

- caller는 정상 fixup으로 간주하므로 이전 displacement/target 의미가 남을 수 있다.
- 이는 단순 보호 약화가 아니라 잘못된 memory address/LEA target으로 원본 의미를 바꾸는 correctness bug가 될 수 있다.
- 테스트가 fail-open을 회귀 동작으로 고정한다.

**수정**

- 1차 release-safe 수정은 overflow를 typed hard error로 승격한다.
- 2차로 opcode별 safe lowering을 분리한다. `LEA`는 flags 불변 absolute-address materialization, 실제 memory load/store는 scratch-register liveness가 증명될 때만 rewrite한다.
- 증명 불가 시 해당 function을 atomic native fallback으로 되돌리고 manifest에 RVA/이유를 기록한다.
- 결과 타입을 `Fixed | Lowered | NativeFallback | Error`처럼 만들어 silent skip을 없앤다.

**필수 테스트**

- ±2GB 경계 성공/실패.
- LEA overflow native differential.
- memory read/write overflow fixture에서 잘못된 address access 생성 0.
- output disassembly에 unresolved RIP displacement 잔존 0.

완료 기준: `OVERFLOW SKIP + Ok(())` 경로 0개.

#### P0-6. CFG에서 모든 `INT3`를 padding으로 제거하는 정책 폐기

**현재 코드 연결**

- `src/graph/cfg.rs:36-54`: `inst.is_invalid() || inst.code() == Code::Int3`이면 동일 padding/non-code 경로로 들어가 instruction 목록에서 제거한다.
- `src/graph/cfg.rs:30-33`, `56-63`: 해당 구간을 `pad_runs`로 기록한다.

**문제**

- `INT3`는 실제 trap/assertion/debugger contract로 쓰일 수 있는 유효 x86 instruction이다.
- reachability 없이 모든 `INT3`를 제거하면 control-flow/exception 의미가 바뀔 수 있다.
- invalid decode와 valid trap을 같은 분기로 처리해 진단도 흐려진다.

**수정**

- `INT3` 자체는 정상 instruction으로 보존한다.
- padding은 **도달 불가능 + terminal 뒤 연속 0xCC + entry/branch/data-reference target 아님**일 때만 별도 classifier가 제거한다.
- entry point, `.pdata` begin, direct branch/call target, data-section function pointer target의 0xCC는 자동 삭제하지 않는다.
- invalid bytes는 `DecodeGap`으로 별도 기록하고 hard error/native-preserve 정책을 둔다.

**필수 테스트**

- 실제 `int3; ret` 함수가 CFG→TriggerBlock→output까지 보존.
- `ret` 뒤 alignment 0xCC run은 계속 padding으로 분류.
- branch target이 0xCC인 fixture 제거 금지.
- intentional trap fixture의 exception code/RVA가 원본과 동일.

완료 기준: reachable `INT3` 보존 100%.

#### P0-7. PE header capacity와 입력 아키텍처/이미지 타입을 build 전에 강제 검증

**현재 코드 연결**

- `src/pe/parser.rs:45-47`: `PE::parse()`만 호출하며 이 지점에서 AMD64/PE32+를 명시적으로 거부하지 않는다.
- `src/pe/builder.rs:137-143`: 새 section 수는 계산하지만 `header_size`는 `original_headers_bytes.len().max(0x400)`만 사용한다.
- `src/pe/builder.rs:235-275`: `sec_table_offset + i*40` 위치에 기존 section + `.textb` + optional payload + `.reloc` header를 쓴다.
- `src/pe/builder.rs:166-177`: 출력 COFF machine/characteristics를 x64 `0x8664`, `0x0022/0x0023`으로 재생성한다.
- `src/pe/builder.rs:333-336`: optional header magic도 `0x20B` PE32+로 강제한다.

**문제**

1. 원본 `SizeOfHeaders`에 section-table 여유가 거의 없는 정상 PE는 신규 40-byte header들이 header boundary를 넘을 수 있다.
2. x86 PE32/미지원 image type을 parser에서 거부하지 않으면 후단 builder가 x64 PE32+로 재작성할 위험이 있다.
3. COFF characteristics를 새 값으로 만들기 때문에 DLL 등 미지원 타입은 silent conversion이 아니라 explicit reject가 필요하다.

**수정**

- `required_header_end = sec_table_offset + num_sections * 40`을 계산하고 `header_size = max(original_headers_len, required_header_end)` 후 file-align한다.
- raw section pointer 배치 전 `required_header_end <= size_of_headers` invariant를 강제한다.
- input validator에서 `Machine == AMD64`, optional magic `PE32+`, optional-header size, section count를 명시 검증한다.
- EXE-only라면 `IMAGE_FILE_DLL` 등을 조기 거부하고, DLL 지원 시 원본 COFF characteristics를 보존한다.

**필수 테스트**

- section table 끝이 `SizeOfHeaders`에 딱 붙은 PE + 1/2/3 신규 section.
- PE32 x86 입력 조기 reject.
- DLL 입력은 정책에 따라 명확한 reject 또는 characteristics 보존.
- section-count/optional-header-size hostile corpus에서 panic 0.

완료 기준: header write/raw-data overlap 0, unsupported architecture/type silent conversion 0.

#### P0-8. unresolved fallthrough에 synthetic `RET`를 삽입하는 semantic fail-open 제거

**현재 코드 연결**

- `src/graph/slicer.rs:367-370`: non-unconditional-jump block의 fallthrough target을 내부 TriggerBlock으로 resolve하지 못하면 `Retnq`를 합성한다.

**문제**

- 원본이 return하지 않았는데 protector가 `RET`를 만드는 것은 control-flow semantic 변경이다.
- 잘못된 CFG boundary/embedded data/외부 thunk/누락 entry target 같은 root cause가 숨겨진다.

**수정**

- 기본 정책을 `UnresolvedFallthrough` hard error로 전환한다.
- metadata로 외부 thunk/native edge임이 증명되는 경우에만 명시적 bridge를 만든다.
- 함수 단위 atomic fallback이 가능하면 함수 전체를 native로 되돌리고 `native_reason=unresolved_fallthrough`와 RVA를 manifest에 기록한다.
- 원본에 없는 synthetic control-flow instruction은 semantics proof/test가 있는 경우에만 허용한다.

**필수 테스트**

- intentionally missing CFG target fixture는 pack 실패.
- 합법적 external/native thunk fixture는 bridge로 보존.
- 원본/output CFG terminal-kind differential 검사.

완료 기준: 원본에 없는 synthetic `RET` 0개.


### P1 — VM 커버리지와 의미 정확성

#### P1-1. RISC unsupported 2,114개 제거

- pack 로그의 opcode histogram을 machine-readable JSON으로 저장한다.
- 빈도 × native island 확대도 × 보안 영향으로 우선순위를 정한다.
- indirect call/jump, complex addressing, SSE/FP conversion, BMI, segmented addressing, string/atomic 계열을 corpus-driven으로 구현한다.
- 한 unsupported instruction 때문에 전체 function/closure가 native가 되는 정책을 block-local safe fallback 또는 helper microcode로 바꾼다.

완료 기준: 이 코퍼스의 non-SEH RISC-unliftable 1,429 blocks → 0, unsupported 2,114 → 0.

#### P1-2. SEH/Rust panic 완전 소유

- Windows x64 unwind metadata와 VM guest stack을 연결하는 VM-aware personality/bridge를 설계한다.
- `catch_unwind`, panic cleanup, nested exceptions, rethrow, vectored exceptions, `setjmp/longjmp`, thread unwind를 독립 fixture로 만든다.
- native-preservation allowlist가 아니라 VM이 unwind semantics를 소유하도록 전환한다.
- `.pdata/.xdata`를 guest range와 generated thunk 모두에 대해 검증한다.

완료 기준: `BTG_SEH_NONE=1`에서 테스트 정상 종료, SEH native blocks가 의도된 OS/runtime thunk 외 0개.

#### P1-3. 커버리지 목표와 gate

- block/instruction/function/hot-path 네 축의 coverage를 동시에 측정한다.
- OEP만 VM이면 성공으로 보지 않는다.
- sensitive marker 또는 정책 대상 함수는 100% VM ownership이 아니면 pack 실패.

완료 기준: 전체 instruction coverage ≥95%, 보호 지정 함수 100%, native bridge 목록이 manifest에 모두 기록.

### P1 — 보호 계층 통합

### 2026-08-22 — P1-4 Program-VM M7 결합 및 chunk planner 착수

- profile resolver에서 native shuffled-block M7과 commercial Program-VM M7을 분리했다. `--vm --vm-oep --vm-commercial --m7`은 M7 요청을 유지하되 native `reencrypt` 경로를 선택하지 않아 Program-VM이 비활성화되지 않는다.
- 실제 panic/thread unwind fixture에서 M7 feature가 manifest에 활성화된 상태로 기존 bulk-RC4 기준 실행 차등 exit 0을 통과했다. 이 기준선은 아직 718,220B bytecode 전체를 부트 시 복호화하므로 최종 P1-4 완료 상태는 아니다.
- instruction offset 경계를 보존하는 최대 4,096B chunk planner와 module/chunk domain-separated 64-bit key derivation을 구현했다. gapless/alignment/key-diversity 및 단일 chunk decrypt 시 이웃 chunk 암호문 유지 roundtrip 테스트를 추가했다.
- 실제 startup fixture M7 빌드에서 154개 instruction-aligned chunk(max 4,096B)를 생성하고 manifest에 `vm_bytecode_chunks=154`, `vm_bytecode_chunk_max=4096`, `vm_bytecode_chunk_encryption=planned`를 기록했으며 실행 차등 exit 0을 유지했다.
- 전체 라이브러리 회귀 528/528 통과. 다음 단계는 descriptor를 Program-VM 모듈에 배치하고 dispatcher fetch 앞 decrypt / handler 완료 뒤 re-encrypt를 연결한 후 manifest 상태를 `active`로 승격하는 것이다.
- Program-VM decoder의 `sub_decrypt`에 실제 outer chunk unmask를 연결했다. VIP에 해당하는 instruction-aligned chunk를 선택하고 fetched ciphertext byte 하나만 register에서 stateless mask 해제한 뒤 기존 polymorphic rolling-key decode로 넘긴다. bytecode 메모리에는 decrypt/re-encrypt write를 전혀 하지 않으므로 현재 chunk를 포함해 모든 chunk가 계속 ciphertext다.
- 최종 모듈 복사 후 각 chunk에 outer cipher를 적용하고, 기존 부트 RC4는 이 outer ciphertext를 감싸는 파일 at-rest 계층으로 유지한다. 부트 후에는 outer ciphertext만 메모리에 남는다.
- startup fixture(154 chunks), panic/thread unwind fixture(176 chunks), 실제 본체(297 chunks)에서 ACTIVE M7 차등실행 exit 0을 모두 통과했다. 실제 본체 manifest는 `vm_bytecode_chunk_encryption=active-register-only`, execution_verified=true다.
- fetched byte 처리 직후 chunk key/mix scratch `R9/R10/R11`을 XOR-zeroize한다. zeroize 추가 후 전체 회귀 528/528와 startup ACTIVE 실행을 다시 통과했다.
- 다음 검증은 런타임 park/snapshot으로 Program-VM bytecode 메모리에 평문 chunk가 생기지 않음을 외부 관측하고 P1-4 완료를 확정하는 것이다.
- 첫 native bridge park 상태에서 실제 프로세스의 Program-VM bytecode RVA `0xC634D`, 길이 `625,706B`를 `ReadProcessMemory`로 전량 snapshot했다. runtime SHA-256 `572965fc7d99e0db09e5f7d86461a570437a4b5ccb2c163dd296aaa727820a27`이 pack-time outer-ciphertext manifest 해시와 byte-for-byte 일치(`hash_match=true`)했다.
- 따라서 실행 중에도 bytecode memory 전체가 outer ciphertext이며 현재 실행 chunk조차 평문으로 쓰이지 않는 `active-register-only` 계약을 외부 관측으로 확인했다. P1-4 완료 기준인 VM-OEP+M7 결합, 현재 fetch 외 평문 bytecode 0, module/chunk domain separation, runtime key scratch zeroize를 모두 충족해 P1-4를 완료로 확정한다.

#### P1-4. VM-native on-demand encryption

- M7을 native dispatcher 전용에서 Program VM bytecode page/chunk 단위로 재설계한다.
- 각 chunk는 실행 직전 decrypt, handler 완료 직후 re-encrypt하며 writable window를 최소화한다.
- rolling key를 build seed 하나로 직접 파생하지 말고 per-module/per-function/per-chunk domain separation으로 파생한다.
- key/state는 사용 후 zeroize하고 crash dump에 장기 평문이 남지 않게 한다.

완료 기준: VM-OEP + M7이 더 이상 충돌하지 않고, 임의 시점 dump에서 현재 실행 chunk 외 평문 bytecode 0개.

#### P1-5. W^X와 mem-harden 통합

완료(2026-08-22): Program-VM mutable state를 code/table/bytecode 뒤의 독립 page boundary로 이동했다. mem-harden은 bootstrap 후 immutable prefix를 RX로, state/call-stack/bootstrap tail을 RW로 각각 전환하며 두 `NtProtectVirtualMemory` 호출 중 하나라도 실패하면 fail-closed한다. `--vm --vm-oep --vm-commercial --iat-hide --mem-harden --verify-output --seed 5605`로 `vm_startup_fixture`의 exit 0, stdout 11B, stderr 0B 동등성을 확인했다. 산출물 manifest의 `wx_contract`는 `transient-rw-to-rx,rx-after-verify,rw-state,at-rest-ciphertext`이며 RWX 계약 문자열을 포함하지 않는다.

- code, immutable tables, mutable state, bytecode를 별도 pages로 분리한다.
- code는 RX, tables/bytecode는 R 또는 transient R/RW, state는 RW로 두고 영구 RWX를 제거한다.
- self-modifying handler가 필요하면 dual mapping 또는 짧은 `RW -> RX` 전환과 CFG/ACG 호환 경로를 사용한다.

완료 기준: manifest `wx_contract`에 RWX 없음, VM-OEP + mem-harden 동시 사용 가능.

#### P1-6. IAT/API wrapping 통합

완료(2026-08-22): VM-OEP가 IAT hide를 끄던 profile downgrade를 제거했다. 원본 import 이름/descriptor/IAT를 지우고 bootstrap에는 `kernel32!LoadLibraryA`와 `GetProcAddress`만 남기며, 암호화된 resolve table이 원래 slot을 복원한다. `GetProcAddress`가 처리하는 forwarded export/API-set resolution을 그대로 사용하고 TLS callback target은 Program-VM 밖 native-owned thunk로 유지한다. mem-harden 단독 경로는 원본 loader-owned IAT를 보존해 TLS-before-OEP lifecycle을 깨지 않는다. 위 결합 fixture에서 정적 import 2개, `feature_flags = vm,vm_oep,vm_commercial,iat_hide,mem_harden,...`, `execution_verified = true`를 확인했다.

- native TLS/callback target 문제를 thunk ownership으로 해결한다.
- VM native-call bridge가 API id/hash를 받아 resolver를 통과하도록 하고 원본 IAT 이름을 제거한다.
- forwarded exports, API sets, delay imports, bound imports, CFG call targets를 지원한다.

완료 기준: VM-OEP + IAT hide 동시 사용, 정적 import에는 최소 bootstrap API만 존재.


#### P1-7. PE raw range와 `.pdata` parsing을 strict directory 기반으로 변경

**현재 코드 연결**

- `src/pe/parser.rs:89-107`: `.text` declared raw end가 EOF를 넘으면 `min(pe_bytes.len())`으로 잘라 bytes를 만든다.
- `src/pe/parser.rs:202-218`: 다른 section도 raw pointer/size가 이상하면 EOF까지 truncate하거나 `Vec::new()`로 degrade한다.
- `src/pe/parser.rs:238-266`: Exception Data Directory RVA/size가 아니라 이름이 `.pdata*`인 section의 전체 raw data를 12B `RUNTIME_FUNCTION`으로 순회한다.

**문제/수정**

- malformed 입력을 partial recovery하지 말고 declared raw range 전체를 checked validation해 fail-closed한다.
- Data Directory의 `RVA -> file offset`을 공용 checked helper로 통일한다.
- `.pdata`는 `IMAGE_DIRECTORY_ENTRY_EXCEPTION` RVA/Size만 parse하고 size%12, begin/end, unwind RVA를 검증한다.
- section name은 authoritative boundary가 아니라 진단 보조로만 쓴다.

완료 기준: truncated/overflow/overlap PE corpus가 panic 없이 explicit error, `.pdata` padding 오인 0.

#### P1-8. BTG-C1/자체 MAC을 암호학적 보안과 난독화 primitive로 분리

**현재 코드 연결**

- `src/protection_profile.rs:213-223`: crypto mode 미지정 + `--rc4` 없음이면 BTG-C1이 기본값이다.
- `src/crypto/round.rs:20-29`: `mix_column`을 “의도적 비가역”, “one-way”, “대수적 역산 공격 원천 차단”으로 설명한다.
- `src/crypto/round.rs:31-44`: 실제 round는 XOR/rotate/wrapping-add 조합이다.
- `src/crypto/mac.rs:4-22`: 자체 64-bit keyed MAC을 변조 방어 primitive로 설명한다.

**문제/수정**

- 현재 구현/테스트만으로 custom construction의 one-way/위조저항성을 입증할 수 없다.
- 기본 crypto는 검증된 표준 construction으로 두고 C1은 `experimental-custom`/`obfuscation-stream`으로 격리한다.
- 주석/CLI/manifest에서 입증되지 않은 “one-way/원천 차단” 표현을 제거한다.
- `BtgKeyedMac`은 분산 anti-tamper 신호로만 쓰고 authenticity/security boundary는 표준 AEAD/MAC/public-key signature에 둔다.

완료 기준: 기본 profile에 검증되지 않은 custom primitive 단독 신뢰 경계 0.

#### P1-9. CLI/SDK configuration을 하나의 resolver와 하나의 pack entrypoint로 통합

**현재 코드 연결**

- `src/pipeline/config.rs:14-108`: 별도 `RequestedConfig/ResolvedConfig`와 resolver가 있고 seed 미지정 시 `0x1337_C0DE_CAFE_BABE`를 기본값으로 쓴다.
- `src/pipeline/mod.rs:24-26`: 위 타입을 public re-export한다.
- `src/protection_profile.rs:33-150`, `157+`: 또 다른 `RequestedConfig/ResolvedConfig`와 실제 feature resolver가 존재한다.
- `src/main.rs:39-49`: CLI는 `protection_profile::resolve()`를 source-of-truth로 사용한다.
- `src/lib.rs:37-42`: public `pack()`은 `pipeline::pack::run_full(...)`을 직접 호출한다.
- `src/pipeline/pack.rs:1-8`, `30-98`: `run_full`은 CLI `--full`의 library twin이라고 설명하지만 실제 일부 보호를 제외한 고정 파이프라인이다.

**수정**

- `protection_profile::{RequestedConfig, ResolvedConfig}`를 유일 public policy 타입으로 승격한다.
- `pack_with_config(input, &ResolvedConfig)`를 canonical entrypoint로 만들고 CLI/SDK 모두 이를 호출한다.
- `pack(input)`은 explicit default profile resolve 후 canonical path로 위임한다.
- seed 정책과 manifest provenance도 동일 resolver에서 결정한다.

완료 기준: resolver 1개, canonical pack path 1개, 동일 input+resolved-config+seed의 CLI/SDK SHA-256 동일.

#### P1-10. dormant native ABI dead-path 제거와 commercial virtual-stack bounds 명시화

**현재 코드 연결**

- `src/vm/risc/native_abi.rs:140-169`: `emit_native_call_site()`가 8개 nonvolatile push 후 `sub rsp,32`로 shadow space를 잡지만 call 뒤 `add rsp,32` 없이 바로 pop한다.
- `src/vm/risc/native_abi.rs:197-267`: verifier는 push/pop/shadow 개수는 확인하지만 return 전 stack delta=0은 검증하지 않는다.
- production commercial bridge는 별도 `src/vm/threaded/poly_direct/...` 경로라 이 코드는 dormant 재사용 위험으로 분류한다.
- `src/vm/threaded/poly_direct/builder.rs:1313-1340`: commercial `VirtualPush/Pop`은 R13/VSP를 ±8 조정하지만 lower/upper bound check가 없다.
- `src/pipeline/crypto/place/mod.rs:491-497`: Program VM 뒤에 `CALL_STACK_SIZE`를 별도 예약하므로 현재 layout에 공간은 있지만 bounds invariant는 runtime에서 강제하지 않는다.

**수정**

- 미사용 emitter는 삭제하거나 shadow-space 회수 + stack-delta verifier를 추가한다.
- verifier에 RSP symbolic delta를 넣어 call 직전 alignment와 resume 직전 원복을 검증한다.
- commercial VM state에 stack base/limit를 명시하고 `VirtualPush/Pop` underflow/overflow를 deterministic trap/telemetry로 처리한다.
- return-IP stack과 guest virtual stack 범위를 타입/manifest에서 분리한다.

완료 기준: dormant ABI bug 0, generated bridge RSP delta=0 검증, stack under/overflow가 인접 state를 손상하지 않음.


### P2 — Themida급 VM 다양성

#### P2-1. architecture-polymorphic VM family

- 동일 `VirtualIsaSpec`의 opcode permutation을 넘어 stack VM, register VM, mixed-width RISC, CISC-like/fused family를 최소 3개 구현한다.
- virtual register count/width, flag model, operand encoding, dispatch topology, call convention을 family별로 다르게 한다.
- 함수별로 다른 VM family를 선택하고 교차-VM bridge를 생성한다.

완료 기준: N=20 seed 빌드에서 normalized handler CFG/semantic signature 군집이 단일 family로 수렴하지 않음.

#### P2-2. build-time semantic handler synthesis

- 한 opcode당 고정 handler template 대신 micro-op decomposition, algebraic substitution, register allocation, instruction selection, control splitting을 매 빌드 생성한다.
- super-op을 단순 fusion뿐 아니라 의미적으로 다른 decomposition으로 만든다.
- dead state, opaque dependency, context-dependent opcode meaning을 안전한 범위에서 도입한다.

완료 기준: seed 간 handler byte similarity와 normalized CFG similarity에 상한을 두고 CI에서 측정.

#### P2-3. dispatcher 다양화

- direct-threaded, indirect-threaded, switch, call/ret, distributed dispatcher를 혼합한다.
- 중앙 opcode table/단일 decode loop라는 정적 anchor를 제거한다.
- handler 주소 테이블 보호(M8)를 dispatcher topology와 결합한다.

완료 기준: 단일 signature로 모든 빌드의 dispatcher entry/table을 찾는 내부 analyzer 성공률 <10%.

### P2 — 런타임 보호 확장

#### P2-4. 분산 무결성

- startup CRC 하나가 아니라 VM macro/function/chunk별 keyed integrity check를 분산한다.
- file image, mapped image, VM bytecode, handler code/table, native bridge, resolved API pointers를 각기 검증한다.
- 검사 실패는 즉시 고정 `ud2`가 아니라 profile에 따라 fail-closed, delayed poison, telemetry를 사용한다.

완료 기준: 각 보호 영역 단일-bit 변조 테스트가 100% 탐지되고 정상 실행 false positive 0.

#### P2-5. 문자열/데이터 수명 보호

- 문자열 참조를 분석해 객체별 encrypted storage로 이동한다.
- 사용 직전 decrypt, scope 종료 즉시 re-encrypt/zeroize한다.
- wide/UTF-8/format tables/vtables/RTTI/constant pools를 별도 분류한다.

완료 기준: 정적 strings와 idle-time memory scan에서 지정 secret 0건.

#### P2-6. anti-analysis 신호망

- anti-debug를 단일 bootstrap에서 분산 risk-signal framework로 바꾼다.
- debugger/monitor/sandbox/DBI/hardware breakpoint/API hook/time anomaly를 독립 신호로 수집하고 다중 신호 정책을 적용한다.
- Windows 버전과 보안 제품에 대한 false-positive matrix를 운영한다.
- 모든 detector는 feature flag와 compatibility kill-switch를 가져야 한다.

완료 기준: 정상 Windows/VM/보안제품 matrix false positive 0; 각 detector에 deterministic test seam 존재.

### P2 — ASLR, PE, 플랫폼 호환성

#### P2-7. ASLR 완전 보존

- 절대 VA를 image-relative RVA 또는 runtime base-derived encoding으로 전환한다.
- VM tables/handlers/native bridges/TLS/pdata의 relocation을 통합 관리한다.
- relocation stripping은 선택 기능으로만 두고 기본은 `DYNAMIC_BASE` 보존.

완료 기준: 100개 랜덤 base에서 동일 결과, manifest `aslr_preserved=true`.

#### P2-8. Windows 보호 기능 호환

- CFG, CET shadow stack/IBT, DEP, High Entropy VA, signed binary, Authenticode 재서명 흐름을 검증한다.
- x64 unwind와 guard function tables를 생성 산출물에 맞춰 재작성한다.

완료 기준: Application Verifier/WinDbg unwind/CFG/CET 테스트 통과.

### P3 — 품질·분석·제품화

#### P3-1. N-build 차분 분석

- 동일 입력을 20개 seed로 보호한다.
- section layout, entropy, imports, strings, normalized CFG, handler similarity, opcode frequency, bytecode similarity를 비교한다.
- seed provenance와 RNG domain을 manifest에 기록한다.

완료 기준: 정적 fingerprint 안정 지점을 자동 보고하고 release마다 회귀 추적.

#### P3-2. 공격자 관점 내부 analyzer

- PE에서 VM entry, dispatcher, handler table, bytecode, native islands, bridge target을 자동 추출하는 red-team 도구를 만든다.
- 보호기 소스의 secret metadata는 사용하지 않는 black-box 모드를 기본으로 한다.
- symbolic execution으로 virtual opcode semantics를 군집화해 난독화 효과를 정량화한다.

완료 기준: 내부 analyzer가 쉬워진 회귀는 CI 실패; 난독화 지표가 단순 엔트로피가 아니라 복구 비용을 반영.

#### P3-3. 동일 Themida 산출물 직접 비교

- 동일 입력, 동일 플랫폼, 공개적으로 기록 가능한 옵션으로 Themida 비교본을 만든다.
- 원본/BTG/Themida 각각에 대해 크기, startup, runtime, memory, import/string leakage, VM coverage, dump recovery, normalized CFG를 동일 도구로 측정한다.
- 제품 비밀 추측은 배제하고 관찰 가능한 결과만 기록한다.

완료 기준: 재현 스크립트, tool versions, hashes, raw reports가 함께 보관됨.

#### P3-4. 로그와 진단 정리

- 기본 pack 로그에서 수 MB 전체 disassembly를 제거하고 `--dump-disasm`으로 이동한다.
- summary JSON에 requested/effective config, coverage, exclusions, unsupported histogram, PE validation, execution validation을 기록한다.
- crash report에 fault RVA → generated code → VM VIP → original VA 연결을 자동 제공한다.

완료 기준: 기본 로그 <1 MB, 실패 원인의 첫 actionable frame이 한 화면에 표시.


#### P3-5. 재현 가능한 상용 소스 패키지/CI provenance

**현재 제공 스냅샷 관측**

- 이번 감사용 ZIP에는 `Cargo.toml`, `Cargo.lock`, README/LICENSE, `.github`/CI 정의가 포함되지 않았다.
- 소스 내부 진행 기록에는 수백 개 테스트 통과와 release 실행 결과가 남아 있지만 이 ZIP 단독으로 dependency/toolchain/feature set을 재현할 수 없다.

**수정**

- release source archive 필수 구성물을 정의한다: `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, license/third-party notices, CI workflow, test corpus version, build script.
- manifest에 rustc/cargo/LLVM/Windows SDK, target triple, enabled features, git commit/dirty state, seed, dependency lock hash를 기록한다.
- CI는 `cargo test`, `cargo clippy -D warnings`, format, Windows x64 release build, pack→validate→differential, multi-seed, malformed PE corpus를 수행한다.
- source archive를 clean runner에서 unpack→rebuild하는 검증 job을 둔다.

완료 기준: 신규 PC/CI runner에서 archive 하나만으로 동일 commit의 release QA를 재현할 수 있음.


## 6. 우선순위별 실행 순서

현재 P0 differential/strict-profile, P1 unsupported/SEH/coverage, P1-4~P1-6의 상당 부분은 상단 진행 기록상 완료됐다. 따라서 **이 시점 이후 실제 release-blocker 순서**는 다음처럼 재정렬한다.

1. **P0-4 ChaCha20-Poly1305 construction 교정** — payload counter 1, on-disk Poly key 제거, 표준 AEAD differential.
2. **P0-5 RIP fixup fail-closed** — overflow `Ok(())` 제거, hard error 또는 검증된 lowering.
3. **P0-6 reachable INT3 보존** — padding classifier와 실제 trap instruction 분리.
4. **P0-7 PE header/input contract** — section-table capacity, AMD64/PE32+, EXE/DLL 정책 강제.
5. **P0-8 synthetic RET 제거** — unresolved CFG edge를 semantic mutation으로 숨기지 않음.
6. P1-7 strict PE parser/Exception Directory 기반 `.pdata` parsing.
7. P1-8 crypto trust-model 정리 — C1/custom MAC을 난독화 계층으로 격리하고 보안 주장 교정.
8. P1-9 CLI/SDK resolver와 canonical pack path 단일화.
9. P1-10 dormant native ABI와 virtual-stack bounds 정리.
10. P2-7/P2-8 ASLR/CFG/CET/Authenticode 등 Windows 플랫폼 완성도.
11. P2-1~P2-6 VM family/handler/dispatcher/무결성/데이터 수명/anti-analysis의 미완 통합부 완료.
12. P3-1~P3-5 N-build red-team, 동일 Themida 산출물 비교, 진단, clean-room reproducible release.

### 릴리스 차단 원칙

- 위 1~5는 대표 코퍼스가 정상 실행되더라도 미해결이면 release sign-off를 하지 않는다.
- 이유는 이 항목들이 “보호가 약함”이 아니라 **암호 construction 또는 원본 semantic/PE correctness를 바꿀 수 있는 경로**이기 때문이다.
- 새 기능은 P0 correctness/security blocker를 닫은 뒤에만 기본 `--full`/commercial profile에 승격한다.

## 7. 최종 출시 게이트

다음 조건을 모두 만족하기 전에는 “Themida급”, “최대 VM + 최대 보호”, “cryptographically authenticated” 같은 표현을 release 문서에 사용하지 않는다.

### 실행/VM 의미 보존

- 대표 Rust EXE와 C/C++/GUI/지원 image-type corpus가 원본과 동일 출력/부작용/exit code로 100회 통과.
- cold boot/새 프로세스/worker thread/SEH/panic/VEH/setjmp-longjmp fixture 통과.
- 보호 지정 함수 VM coverage 100%, 전체 instruction coverage 목표 ≥95%; 현재 99%대 수치가 release corpus에서도 유지.
- unsupported instruction 0 또는 명시적·감사 가능한 native allowlist만 존재.
- VM-OEP + M7 + M8 + IAT hide + mem harden + integrity가 요청 시 동시에 effective.
- generated native bridge와 guest stack의 Win64 ABI/RSP alignment/unwind contract 자동 검증.

### CFG/재배치/PE correctness

- reachable `INT3` 제거 0.
- unresolved fallthrough를 synthetic `RET`로 바꾸는 경로 0.
- RIP-relative overflow silent skip 0; hard error/검증된 lowering/native fallback 중 하나로 provenance 기록.
- 모든 section table entry가 `SizeOfHeaders` 안에 위치.
- input AMD64/PE32+/지원 image-type contract를 build 전에 검증.
- truncated/overlapping/malformed raw range는 panic 없이 fail-closed.
- `.pdata`는 Exception Data Directory authoritative range만 사용.
- 영구 RWX page 없음, ASLR/CFG/CET 정책이 manifest와 실제 PE에서 일치.

### 암호/무결성

- ChaCha20-Poly1305 payload initial counter=1.
- Poly1305 one-time key가 출력 PE에 평문 저장되지 않음.
- RFC 8439 AEAD vector + packer/native differential 통과.
- ciphertext/tag/보호 metadata 단일-bit mutation corpus 100% 탐지.
- custom C1/BtgKeyedMac은 표준 cryptographic trust boundary와 명확히 분리되고 입증되지 않은 one-way/위조불가 주장을 하지 않음.
- publisher authenticity를 주장하면 private signing key가 보호 실행 파일에 존재하지 않는 public-key 검증 체계를 사용.

### 다양성/덤프 저항

- N=20 빌드에서 opcode뿐 아니라 normalized handler CFG/dispatcher topology도 유의미하게 변화.
- 임의 시점 dump에서 비실행 VM chunk와 지정 secret 평문 노출 0.
- native island/bridge/handler table을 내부 black-box analyzer가 복구하는 비용을 release마다 정량 추적.

### 제품/재현성

- requested/effective profile과 모든 downgrade가 manifest에 완전 기록.
- CLI/SDK가 동일 `ResolvedConfig`와 canonical pipeline을 사용.
- 동일 input+config+seed의 CLI/SDK 산출물 hash 동일.
- `Cargo.toml`/`Cargo.lock`/toolchain/CI/test corpus를 포함한 release source package가 clean runner에서 재현 가능.
- execution verification=false인 artifact는 release 채널 승격 불가.

## 8. 현재 상태 판정 — 최신 진행 기록 반영

기존 하단의 “실행 실패, VM 약 15%”는 초기 감사 기준선으로, 상단 최신 진행 기록과 맞지 않아 아래처럼 갱신한다.

### 현재 확인된 강점

- 초기 `0xC000001D` 부트 CRC 계열 결함은 수정됐고 differential execution gate, 실패 산출물 격리, manifest provenance, multi-seed gate가 구현됐다.
- 진행 기록상 RISC unsupported는 0까지 줄었고 strict SEH/panic ownership, native bridge ABI/unwind 수정 뒤 panic/VEH/setjmp-longjmp/worker-thread fixture가 실행 동치를 통과했다.
- 실제 본체 기준 coverage는 block `12,385/12,419`, instruction `51,157/51,256 = 99.8069%`, function `777/778 = 99.8715%`까지 상승했다.
- Program-VM M7 active-register-only 경로는 runtime snapshot에서 bytecode memory가 outer ciphertext와 일치하는 검증까지 진행됐다.
- VM-OEP + IAT hide + mem-harden 조합도 별도 fixture에서 실행 동치가 확인됐다.
- architecture family, handler synthesis plan, dispatcher topology, distributed integrity/data-lifetime 기반 코드가 추가돼 VM 코어의 기술적 잠재력은 높다.

### 아직 release sign-off를 막는 신규 감사 항목

1. `src/pipeline/crypto/mod.rs` + `src/crypto/chacha20.rs` + `src/pipeline/crypto/place/mod.rs`: payload counter 0과 Poly-key block0 재사용, Poly key의 PE 저장.
2. `src/graph/fixup.rs:81-90`: RIP overflow가 `Ok(())`로 빠지는 fail-open.
3. `src/graph/cfg.rs:39-53`: reachable 여부와 무관하게 모든 `INT3`를 padding으로 제거.
4. `src/pe/builder.rs:137-143`: 추가 section header가 요구하는 header end를 `SizeOfHeaders` 계산에 포함하지 않음.
5. `src/graph/slicer.rs:367-370`: unresolved fallthrough에 원본에 없던 `RET` 합성.
6. PE raw-range/`.pdata` parsing, custom crypto 보안 주장, config/API 이중화, dormant native ABI/stack bounds도 상용 장기 유지보수 관점에서 닫아야 한다.
7. 이번 제공 ZIP에는 Cargo manifest/lock/CI가 없어 **이 archive만으로 clean-room 재현 빌드가 불가능**하다.

### 최종 판단

현재 BTG를 더 이상 “VM 15% 수준에서 시작도 못 하는 초기 상태”로 평가하면 부정확하다. VM coverage, SEH ownership, native bridge, M7/IAT/W^X 결합은 큰 폭으로 발전했다.

하지만 **상용 release 승인은 아직 보류**가 맞다. 남은 핵심 이유는 VM 기능 부족보다 `crypto construction + CFG semantic preservation + RIP fixup + PE builder/input strictness`다. 이들은 특정 대표 EXE에서 differential 실행이 성공해도 다른 정상 PE/edge case에서 잘못된 산출물을 만들 수 있는 종류다.

따라서 다음 milestone은 새 난독화 기능 추가보다 P0-4~P0-8을 모두 닫고 hostile/edge-case corpus를 release gate에 편입하는 것이다. 이 단계가 끝난 뒤에 “상용 VM protector release candidate” 판정을 다시 한다.

## 9. 2026-08-22 — packed.exe VM 복원 저항성 비교 및 추가 업그레이드 계획

### 9.1 분석 범위와 비교의 한계

이번 평가는 제공된 `src (2).zip`, `packed.exe`, 기존 계획을 기준으로 한다. `packed.exe`는 안전상 실행하지 않고 PE parsing, strings, section entropy, 정적 disassembly만 사용했다.

- source ZIP SHA-256: `5536d264b8f5a98cae9c75dfafc0500fb1c9496f50780dd9464bcce71963bc92`
- packed EXE SHA-256: `beaf7a8bcece899986b763849f36f9468147bec2cda98a0faabf57223a984050`
- 원본 plan SHA-256: `0a9281270d6b22c35d60d1114301140d64d0aaa78700b00e53561fed3328a457`
- source archive: 268 files, Rust 약 103,463 lines. 현재 ZIP에는 이전 감사와 동일하게 Cargo manifest/lock/CI가 없어 clean-room rebuild는 이 archive만으로 재현할 수 없다.

동일 입력을 Themida로 직접 보호한 비교 EXE는 제공되지 않았다. 따라서 Themida 쪽 평가는 **Oreans가 공개한 3.2.6.0 기능/VM 구조를 상용 기준선으로 사용한 간접 비교**다. 직접적인 “BTG가 Themida보다 몇 배 어렵다/쉽다” 같은 정량 결론은 동일 입력·동일 성능 예산의 Themida 비교본이 생길 때만 낸다.

공식 비교 기준(2026-08-22 확인):

- `https://www.oreans.com/ThemidaWhatsNew.php` — Themida 3.2.6.0, 2026-08-11; VM instruction reordering, virtualization return-address 보존, relocation/x64 exception 개선.
- `https://www.oreans.com/help/tm/hm_which-macros-should-i-use_.htm` — FISH/TIGER 및 FISH_BLACK/PUMA/SHARK 등 서로 다른 VM 선택과 성능/보호 trade-off.
- `https://www.oreans.com/help/tm/hm_protection-macros.htm` — 선택한 함수/매크로별 특정 VM 배정.
- `https://www.oreans.com/CompareProducts.php` — code virtualization/mutation, string decrypt/re-encrypt, API wrapping, whole-app encryption/compression, integrity 등 결합 보호.

### 9.2 제공 packed.exe 정적 실측

| 항목 | 실측 | 복원 관점 판정 |
|---|---|---|
| PE | x64 PE32+, 6 sections, 1,969,664B | 정상적인 상용형 packer 형태 |
| OEP | RVA `0x8A900` / VA `0x14008A900` | PEB 기반 anti-debug와 VM state 초기화가 한 지점에 모여 초기 anchor가 됨 |
| imports | `LoadLibraryA`, `GetProcAddress`만 노출 | 정적 API leakage는 강하게 감소 |
| `.text` | 190,464B, entropy ≈ `7.999` | 원본 code-at-rest 은닉은 강함 |
| `.textb` | 1,701,376B raw, entropy ≈ `7.459` | 대형 VM/code/ciphertext container 자체는 쉽게 식별 가능 |
| relocation | Base Relocation Directory = 0, COFF `relocations stripped` | ASLR/PIC 및 anchor 제거 측면 약점 |
| signing | Security Directory = 0 | Authenticode 없음 |
| plaintext data | Rust runtime path, stage label, `RUST_BACKTRACE`, UI/test strings 다수 | 전역 data-lifetime/strings 보호 미완료 |

#### 확인된 commercial VM anchor

- dispatcher 진입: `0x1400987A4` 부근.
- bytecode base: `0x140122220`.
- VM state: `0x1401E1000`.
- virtual stack: `0x1401E3100`.
- handler table/metadata base: `0x14009E841`.
- dispatcher는 256-entry integrity loop 뒤 bytecode opcode를 fetch하고, per-opcode key로 handler pointer를 복원한 뒤 indirect jump한다.

이 구조는 단순 signature/one-XOR table restore를 상당히 어렵게 만든다. 그러나 위 base들이 절대 immediate로 한 dispatcher에 모이고, handler table decrypt 식과 상수가 같은 코드 안에서 계산되므로 **한 빌드에서 runtime model을 복원한 뒤 전체 handler를 자동 추출하기 위한 seed point가 충분하다**.

#### M7 active-register-only의 강점과 새 병목

현재 bytecode fetch helper(`0x140096579` 부근)는 bytecode를 메모리에 평문으로 재작성하지 않고 register 안에서 mask를 해제한다. 이는 일반적인 “프로세스 dump → VM bytecode 평문 획득” 경로를 차단하는 유효한 강점이다.

하지만 같은 helper에 다음 정보가 정적으로 모인다.

1. `VIP < boundary` 형태의 긴 chunk boundary ladder.
2. 각 chunk 경계에 대응하는 64-bit key immediate.
3. `VIP - chunk_start`를 만든 뒤 공용 mixer로 합류하는 동일한 구조.

즉 공격자는 plaintext dump 없이도 helper만 분석해 chunk map을 만들고 key schedule을 복제할 수 있다. **ciphertext lifetime은 강하지만 key/map representation이 devirtualizer-friendly한 형태**인 것이 현재 P2에서 가장 큰 복원성 병목이다.

### 9.3 소스 구현과 실제 복원 난이도의 차이

#### VM family: 기반 구현은 있으나 실제 multi-VM은 아직 아님

- `src/vm/poly/architecture_family.rs:118`에 함수 기반 family 선택, `:159`에 `assign_function_families()`와 cross-VM bridge 계약이 있다.
- 그러나 `src/vm/poly/encoder.rs:18-26`, decoder/ISA 기본 생성자는 `VmArchitectureFamily::for_build(seed)`를 사용한다.
- repository-wide call-site 기준 `assign_function_families()`와 `CrossVmBridge::between()`은 production commercial pipeline에서 소비되지 않는다.

따라서 현 상태의 “4 family”는 **family profile/codec infrastructure**로는 유효하지만, 상용 Themida 문서에서 보이는 서로 다른 VM을 한 애플리케이션의 서로 다른 보호 영역에 실제 배치하는 수준과 동일하다고 보기는 어렵다.

#### handler synthesis: NOR에서 실제 연결, 전체 ISA는 미완

- `src/vm/handler_poly.rs`의 recipe/scratch/control-split 계획은 잘 구성돼 있다.
- 실제 native self-decoding builder의 production use는 `src/vm/threaded/poly_direct/builder.rs:1130` 부근 `NOR` handler에 집중돼 있다.
- 주요 ALU/memory/branch/SSE handler는 canonical RISC op와 상대적으로 안정적인 handler template을 공유한다.

따라서 opcode 번호가 seed마다 달라도 black-box analyzer가 handler semantics를 canonical RISC op로 normalize한 뒤 **다음 seed에 semantic classifier를 재사용**할 여지가 크다.

#### dispatcher topology: 실제 통합된 강점

`src/vm/threaded/poly_direct/builder.rs:994-1095`는 `DispatcherPlan::from_seed(seed)`를 실제 production codegen에 사용하며 DirectThreaded, IndirectThreaded, SwitchSplit, CallRet, Distributed를 emission한다. 이 항목은 현재 P2 중 “계획 타입만 존재하는 기능”이 아니라 실산출물 다양성으로 이어지는 강점으로 판정한다.

#### distributed integrity / data lifetime: production 통합 미확인

- `src/vm/distributed_integrity.rs`는 module 및 자체 테스트 외 call-site가 확인되지 않았다.
- `src/vm/data_lifetime.rs`도 module 및 자체 테스트 외 production call-site가 확인되지 않았다.
- 실제 `packed.exe`의 plaintext strings가 이 판정을 뒷받침한다.

기존 P2-4/P2-5는 새 ID를 만들지 않고 **“implementation complete”가 아니라 “pipeline/runtime integration complete”를 완료 기준으로 승격**한다.

### 9.4 Themida/상용 VM 기준 복원성 비교

아래 Themida 열은 동일 바이너리 직접 분석값이 아니라 Oreans 공개 기능/구조에서 추론한 상용 기준선이다.

| 복원 단계 | 현재 BTG 샘플 | Themida/상용 기준선 | 격차 |
|---|---|---|---|
| VM 영역/entry 탐색 | **중간** — OEP 및 절대 VA runtime anchors가 선명 | **중상~높음** — 다중 VM/매크로/지속적 구조 변형을 전제로 함 | 큼 |
| bytecode 위치 식별 | **중간 이하** — 큰 `.textb`와 명시 bytecode base | **중상** | 중간 |
| 단순 dump 공격 | **높은 저항** — active-register-only ciphertext | **높음 목표** | 작음~중간 |
| chunk map/key 복원 | **중간 이하** — boundary ladder + key immediates | **높음 목표** | 큼 |
| handler table 단순 복원 | **중상** — integrity + per-op key | **높음** | 중간 |
| handler semantic 복원 | **중간** — canonical RISC + 다수 고정 template | **높음 목표** — 다중 architecture/handler mutation 공개 | 큼 |
| cross-seed analyzer 재사용 | **중간** — opcode/register/topology는 변하지만 grammar/runtime model은 안정 | **높은 저항 목표** | 큼 |
| 한 바이너리 내부 multi-VM | **낮음~중간** — family infra는 있으나 production per-function wiring 미완 | **높음** — VM 종류를 보호 영역별 선택 가능 | 큼 |
| API import 은닉 | **높음** — 2개 resolver import만 노출 | **높음** | 작음 |
| 문자열/데이터 lifetime | **낮음~중간** — 다수 평문 string 잔존 | **중상~높음** — runtime decrypt/re-encrypt 공개 기능 | 큼 |
| platform/relocation | **낮음** — reloc stripped, no DynamicBase 관측 | **상용 성숙도 높음** — relocation/x64 EH를 지속 개선 | 큼 |

**현재 종합 판정:** BTG는 “단순 VM 보호기” 수준은 이미 넘어섰고, naive dump/table-XOR/정적 opcode map 공격에는 의미 있는 저항성이 있다. 그러나 상용 VM devirtualizer 관점에서는 **한 번 복원한 runtime/fetch/semantic model을 다음 seed에 얼마나 재사용할 수 있는가**가 핵심이며, 이 지표에서는 아직 Themida급이라고 부르기 어렵다.

### 9.5 신규 P2 업그레이드 — 복원 모델 재사용 비용을 직접 올리는 항목

> 아래 P2-9 이후는 기존 P2-1~P2-8을 대체하지 않는다. 특히 P0-4~P0-8 correctness blocker를 먼저 닫은 뒤 상용 profile에 승격한다.

#### P2-9. M7 chunk metadata/key 노출 제거

**현재 병목**

- fetch helper의 O(N) VIP boundary compare ladder가 전체 chunk map을 그대로 노출한다.
- chunk별 64-bit key가 native immediate로 존재한다.
- 한 helper를 lift하면 bytecode 전체의 chunk 시작점과 key material을 일괄 추출할 수 있다.

**수정**

- chunk lookup을 긴 literal compare ladder가 아닌 family/instance별 서로 다른 descriptor representation으로 바꾼다.
- raw per-chunk key immediate를 제거하고, module secret + instance id + chunk id + build domain에서 runtime 파생한다. executable 안에 모든 chunk key의 독립 plaintext 목록을 두지 않는다.
- descriptor가 필요하면 boundary/key material을 같은 native basic block에 함께 노출하지 않고, descriptor integrity와 key derivation을 분리한다.
- fetch CFG/lookup grammar 자체도 build/family별로 바뀌게 하며 “하나의 sub_decrypt signature”를 고정 anchor로 만들지 않는다.
- 성능 때문에 고정-size chunk를 사용할 경우 instruction boundary mapping은 별도 compressed/encoded index로 두고 raw boundary array를 피한다.

**완료 기준**

- static scanner가 `cmp VIP, imm` 패턴만으로 전체 chunk boundary의 10% 이상을 복구하지 못함.
- output code에서 raw per-chunk key immediate 목록 0개.
- N=20에서 normalized fetch-helper CFG가 하나의 template cluster로 수렴하지 않음.
- 기존 active-register-only 계약과 differential execution은 그대로 유지.

#### P2-10. 실제 per-function/per-region multi-VM backend 통합

**현재 병목**

- family assignment API는 있지만 commercial production pipeline은 사실상 `for_build(seed)` 중심이다.
- 한 빌드에서 runtime state/fetch/operand model 하나를 복원하면 대부분의 VM code에 적용 가능하다.

**수정**

- `assign_function_families()`를 commercial lift→encode→module build의 실제 ownership 단계에 연결한다.
- Stack/Register/MixedRisc/FusedCisc 각각이 단순 opcode domain만 다른 것이 아니라 다음을 실제로 달리한다: VM state shape, operand decoder, bytecode grammar, flags model, dispatcher ABI, call/return convention, native handler backend.
- cross-family edge에서만 `CrossVmBridge`를 emit하고 같은-family edge에는 bridge를 만들지 않는다.
- sensitive marker는 하나의 family에 고정하지 않고 policy에 따라 2개 이상의 family/instance로 분산할 수 있게 한다.
- manifest에는 함수별 family id를 raw secret metadata가 아니라 QA용 별도 protected provenance로 기록한다.

**완료 기준**

- 하나의 보호 EXE 안에 최소 3개 실질적으로 다른 VM family가 동시에 실행됨.
- 각 family에 대해 distinct decoder/state/handler backend가 존재하고 하나의 decoder로 다른 family bytecode를 정상 해석할 수 없음.
- cross-family fixture, SEH/panic/VEH/thread/native bridge differential 모두 통과.
- black-box analyzer가 한 family에서 학습한 semantic model을 다른 family에 그대로 적용했을 때 성공률 <30%를 초기 목표로 둔다.

#### P2-11. handler synthesis를 전체 고빈도 ISA로 확대

**현재 병목**

- semantic synthesis가 `NOR`에 실제 연결돼 있지만 전체 handler set의 대표성이 부족하다.
- canonical RISC op → 고정 native handler template 매핑이 많이 남아 semantic clustering이 쉽다.

**수정**

- 우선순위: integer ALU/logic → shifts/rotates → compare/branch → load/store/addressing → packed/SSE → call/return/control.
- handler마다 micro-op decomposition, scratch allocation, equivalent boolean/MBA recipe, native instruction selection, control split을 실제 machine-code emission에 반영한다.
- 동일 RISC op도 family/width/context에 따라 operand decode 순서와 flag materialization을 바꾼다.
- super-op 생성은 단순 인접 opcode fusion이 아니라 기본 block context에서 2~5 micro-op의 fused semantic handler를 합성한다.
- opaque/dead state는 correctness proof 가능한 local invariant에 한정하고 예외/flags/partial-register semantics를 절대 희생하지 않는다.

**완료 기준**

- execution-weight 상위 80% VM opcode가 최소 3개 이상의 의미 동치 native recipe를 가짐.
- N=20 seed에서 동일 opcode handler normalized CFG similarity의 p95 상한을 CI로 관리.
- internal semantic classifier의 cross-seed top-1 정확도를 baseline 대비 절반 이하로 낮추되 differential corpus 100% 통과.

#### P2-12. 단일 전역 dispatcher/runtime anchor 제거

**현재 병목**

- 현재 샘플은 한 dispatcher에서 bytecode base/state/vstack/table base를 동시에 초기화한다.
- 256-entry integrity loop와 dispatch tail이 강한 signature anchor다.

**수정**

- 프로그램을 3개 이상 VM instance로 partition하고 instance마다 독립 state/layout/table/fetch/topology/key domain을 사용한다.
- hot/sensitive 영역은 서로 다른 instance로 배치하고, 하나의 dispatcher가 전체 VM instruction의 과반을 처리하지 않게 한다.
- table integrity도 모든 instance가 동일 256-entry loop를 공유하지 않도록 descriptor/tree/rolling verification 등 서로 다른 검증 형태를 선택한다.
- instance entry는 absolute VA bundle 대신 RIP-relative/RVA-derived materialization을 사용해 하나의 immediate scan으로 runtime object를 열거하지 못하게 한다.

**완료 기준**

- release profile에서 최소 3개 independent VM runtime instance.
- 최대 단일 instance의 VM instruction ownership <50%.
- black-box dispatcher signature 하나로 찾을 수 있는 instance 비율 <25%.
- ASLR/CFG/CET gate와 동시에 통과.

#### P2-13. bytecode grammar/operand representation polymorphism

**현재 병목**

`src/vm/poly/encoder.rs:32-44`의 canonical record는 기본적으로 `opcode + dst/src1/src2 + imm64` 구조를 공유한다. opcode map이 달라도 grammar가 안정적이면 dynamic trace 몇 개로 operand decoder를 복원하기 쉽다.

**수정**

- family별로 variable-length record grammar를 둔다.
- operand order, implicit operand, immediate width, signed/unsigned compact encoding, register-vs-stack addressing, branch target representation을 family별로 달리한다.
- branch/control opcode는 고정 8-byte absolute index를 피하고 block-local delta, table indirection, continuation token 등 서로 다른 표현을 선택한다.
- super-op은 자체 grammar를 사용하고 canonical nested operand record를 그대로 재사용하지 않는 variant를 추가한다.

**완료 기준**

- 한 family용 bytecode parser가 다른 family stream을 정상적으로 instruction boundary까지 recover하지 못함.
- N=20 seed의 동일 RISC program에 대해 boundary/operand grammar classifier가 build/family 정보를 모르고 90% 이상 normalize하지 못하도록 red-team gate를 둔다.
- malformed stream/trap/SEH 의미 보존 테스트 통과.

#### P2-14. VM state representation 분할 및 lazy flags

**현재 병목**

seed-jittered offset은 유효하지만 한 VM state base를 알아내면 같은 빌드의 GPR/flags/stack metadata를 대부분 하나의 memory model로 복원할 수 있다.

**수정**

- family/instance마다 state 일부를 register-resident, stack-window, split memory bank로 분할한다.
- flags는 가능한 op에서 즉시 canonical RFLAGS로 저장하지 않고 lazy condition token/producer state로 유지하다 branch/native boundary에서 materialize한다.
- return stack, guest data stack, canonical bridge image를 서로 다른 state domain으로 분리한다.
- cross-VM bridge에서만 canonical image를 순간 생성하고 bridge 종료 즉시 zeroize한다.

**완료 기준**

- 정상 handler 실행 중 단일 contiguous memory region에서 canonical `16×u64 + flags + VIP` 전체가 동시에 관찰되지 않음.
- family별 state recovery script가 다른 family에 그대로 적용되지 않음.
- native bridge/SEH/unwind/FP/SIMD differential 100% 통과.

#### P2-15. native bridge를 복원 oracle로 쓰기 어렵게 만들기

**현재 병목**

native island/bridge target은 VM semantics를 직접 보여주는 oracle이 될 수 있다. coverage가 높아도 반복되는 bridge ABI/target pattern은 devirtualizer가 VM block 의미를 라벨링하는 데 활용할 수 있다.

**수정**

- small pure helper/leaf arithmetic는 가능한 경우 VM 안으로 완전 lift한다.
- OS/API boundary는 기존 IAT/API wrapping 계층과 결합하고, instance별 bridge ABI/layout variant를 둔다.
- bridge call-site에서 canonical full-register image를 항상 materialize하지 말고 실제 live-in/live-out subset만 marshaling한다.
- sensitive marker 내부는 bridge-out 0을 기본 gate로 유지한다.

**완료 기준**

- bridge 수를 `per 10k VM instructions`로 정량 추적하고 release마다 감소/증가 이유를 기록.
- sensitive region bridge-out 0.
- bridge ABI signature 하나로 전체 bridge의 25% 이상을 자동 분류할 수 없도록 instance별 변형.

### 9.6 기존 P2-4/P2-5 완료 기준 강화

#### P2-4 distributed integrity — “타입/테스트 존재”에서 “runtime coverage”로 승격

- `FileImage/MappedImage/VmBytecode/HandlerCode/HandlerTable/NativeBridge/ResolvedApiPointers` descriptor가 실제 pack pipeline에서 모두 생성되고 runtime verification site에 연결되어야 완료로 본다.
- 각 region마다 manifest에 `planned/placed/runtime-verified` 상태를 구분한다.
- descriptor 자체가 한 중앙 table에 모여 새로운 anchor가 되지 않도록 instance/domain별로 분산한다.
- tamper test는 단순 library unit test가 아니라 실제 protected EXE 변조 corpus로 수행한다.

완료 기준: 7개 보호 domain 각각 실제 PE mutation 100% 탐지, 정상 false positive 0, descriptor orphan 0.

#### P2-5 data lifetime — 실제 PE string/reference relocation까지 완료해야 종료

- 현재 `ProtectedDataObject` helper가 존재하는 것만으로 완료하지 않는다.
- PE 전체 reference analysis로 application-owned literal/format table/selected RTTI/constant pool을 실제 encrypted storage로 재배치한다.
- Rust/CRT runtime string까지 무리하게 전부 숨기는 것이 아니라, policy marker와 secret classification으로 사용자 민감 데이터와 protector metadata를 우선한다.
- `strings` 및 idle-memory scan을 CI artifact로 저장한다.

완료 기준: 지정 secret corpus static plaintext 0, idle-time plaintext 0, use-scope 종료 후 재노출 0.

### 9.7 신규 P3 — 실제 “VM 복원 비용”을 CI 지표로 만들기

#### P3-6. black-box devirtualization benchmark

기존 P3-2 internal analyzer를 다음 6단계로 세분해 release마다 시간을 측정한다.

1. VM region/instance discovery.
2. dispatcher/fetch/table discovery.
3. chunk map 및 bytecode extraction/decode.
4. handler semantic clustering.
5. dynamic trace → normalized IR 변환.
6. normalized IR → 원본 CFG/고수준 의미 복원 coverage.

보호기 source symbol/manifest/seed를 읽는 white-box 모드는 개발 진단용으로만 두고, release score는 **packed.exe만 입력하는 black-box mode**로 계산한다.

추가로 cross-build transfer를 반드시 측정한다.

- Build A에서 만든 signatures/parsers/semantic classifier를 Build B에 수정 없이 적용.
- Build B에서 recover 가능한 VM instruction/function 비율을 `cross_seed_reuse_ratio`로 기록.
- 같은 family/다른 family, 같은 compiler/다른 compiler corpus를 분리한다.

초기 gate는 절대 숫자를 제품 주장으로 고정하지 않고 20-seed baseline을 먼저 만든다. baseline 이후에는 `cross_seed_reuse_ratio`, 자동 handler classification rate, 자동 CFG recovery rate가 악화되면 CI를 실패시킨다.

#### P3-7. 동일 입력 Themida A/B 직접 benchmark

Themida 라이선스와 동일 입력 비교본이 확보되면 다음 조건으로 직접 비교한다.

- 동일 원본 EXE/hash, 동일 Windows/CPU, 동일 compiler build.
- `fast/balanced/hardened` 3개 성능 예산을 맞추고 size/startup/runtime overhead를 함께 기록한다.
- BTG와 Themida 모두 공개 UI/문서로 재현 가능한 옵션만 사용한다.
- proprietary VM internals를 추측하지 않고 **관찰 가능한 산출물**만 비교한다.
- VM instance discovery, handler clustering, cross-build signature reuse, static/dynamic string leakage, bytecode lifetime, native bridge/island recovery, PE relocation/CFG/CET, startup/runtime overhead를 동일 harness로 측정한다.

완료 기준: tool versions, project options, hashes, raw traces, analyzer version을 함께 보관하고 제3자가 같은 산출물에서 결과를 재계산 가능.

#### P3-8. 보호 강도 profile을 성능/크기 예산과 연결

다중 family/instance와 full handler synthesis는 보호 강도를 올리지만 size/runtime 비용도 커진다. 상용 VM과 비교하려면 강도만이 아니라 비용 곡선을 관리해야 한다.

- `fast`: 1~2 lightweight instance/family, hot path 최소 virtualization.
- `balanced`: 3+ instance, mixed family, 상위 빈도 handler synthesis, M7/M8/IAT/W^X 기본.
- `hardened`: sensitive region 100% multi-family, aggressive super-op/handler synthesis, strongest metadata/state splitting.
- 각 profile에서 file size, startup, steady-state, peak RSS, VM instruction당 overhead를 기록한다.

완료 기준: 보호 강도 지표와 성능/크기 지표를 한 release report에서 함께 제시하고, “강함”을 기능 개수만으로 주장하지 않음.

### 9.8 새 우선순위

기존 P0 correctness/security blocker는 그대로 최우선이다. 그 뒤 VM 복원 저항성 개선은 다음 순서가 가장 효과적이다.

1. P0-4~P0-8 모두 종료.
2. P2-9 M7 chunk metadata/key exposure 제거.
3. P2-10 실제 multi-VM family production wiring.
4. P2-11 full handler semantic synthesis.
5. P2-12 multi-instance runtime + P2-13 grammar polymorphism.
6. P2-14 state splitting + P2-15 bridge oracle 감소.
7. 기존 P2-4/P2-5 production integration 완료.
8. P3-6 black-box devirtualization benchmark를 release gate로 승격.
9. P3-7 동일 Themida A/B가 확보되면 직접 비교.
10. P3-8 성능/크기 profile을 고정해 보호 강도와 비용을 동시에 관리.

### 9.9 상용 VM protector 판정 기준 갱신

향후 “Themida급” 또는 “상용 VM compiler 수준” 표현은 아래를 모두 통과한 경우에만 사용한다.

- correctness/PE/crypto P0 blocker 0.
- 한 protected EXE 안에 실질적으로 다른 VM family 최소 3개.
- build/family별 bytecode grammar와 state representation이 달라 하나의 parser/state model로 전체를 복원할 수 없음.
- raw chunk key list, O(N) chunk-boundary ladder, 단일 global state/table/bytecode absolute-VA bundle 같은 고정 restore anchor 0.
- execution-weight 상위 80% VM handler에 multi-recipe semantic synthesis 적용.
- N=20 black-box benchmark에서 cross-seed analyzer reuse가 release baseline 이하이고 회귀 시 CI 실패.
- sensitive marker 100% VM ownership, bridge-out 0.
- 지정 secret static/idle plaintext 0.
- ASLR/CFG/CET/W^X/SEH/unwind 및 differential execution corpus 동시 통과.
- 동일 입력 Themida 비교본이 없는 상태에서는 “Themida보다 강함/동급” 같은 직접 우열 표현을 사용하지 않고 “상용 VM 기준 목표 달성 여부”로만 보고.

### 9.10 최종 재평가

현재 BTG의 가장 강한 부분은 **높은 VM coverage를 달성한 Program-VM, active-register-only bytecode ciphertext, per-opcode handler pointer protection, 실제 dispatcher topology 다양화, strict unwind/native bridge 검증 기반**이다.

반대로 상용 devirtualizer 입장에서 가장 재사용하기 쉬운 부분은 **build당 사실상 하나인 runtime/family, canonical operand record/RISC semantics, M7 chunk boundary/key ladder, 단일 VM object base bundle, 일부 handler에 국한된 semantic synthesis**다.

따라서 다음 세대의 목표는 더 많은 난독화 instruction을 추가하는 것이 아니라 다음 질문에 대한 답을 바꾸는 것이다.

> “한 샘플을 분석해서 만든 decoder/state/handler model이 다음 seed 또는 같은 바이너리의 다른 보호 함수에도 그대로 먹히는가?”

이 답이 “대부분 그렇다”에서 “family/instance마다 새 모델이 필요하다”로 바뀔 때, 현재 구현은 단순 기능 비교를 넘어 상용 VM protector와 같은 축에서 복원 비용을 경쟁할 수 있다.
