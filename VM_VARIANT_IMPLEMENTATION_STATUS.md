# 최신 구현 및 검증 (2026-10-04)

요청한 독립 4종 lowering, 전체 Boot stage orchestration, full crypto VM 구현을 완료했다. 아래 기존 기록은 이전 단계의 검증 이력이다.

- Stack은 bounded operand stack, Register는 명시적 register operands, Mixed는 두 accumulator, Fused는 실제 compound super-op lowering을 사용한다. 가족별 dispatch와 flags 계약, memory lowering 및 cross-family bridge를 검증했다. Family ABI는 2, canonical module identity는 3이다. 공통 guest semantics와 정규화된 host bridge는 공유한다.
- Boot의 12개 단계는 인증된 stage bytecode와 검증된 PC/count/lifecycle로 orchestration된다. 단계 사이 native branch도 VM continuation으로 연결한다. Metadata 인증 root와 OS/loader 작업 및 최종 보호/진입은 native bridge로 남는다.
- `--boot-vm-policy full-crypto`는 ChaCha20과 Poly1305의 전체 native instruction sequence를 bounded instruction VM으로 실행한다. 인증 root는 native이며 이 모드는 명시적으로 선택한다. RFC 결과, 경계 길이, 이어서 처리, state cleanup과 bytecode 변조 거부를 검증했다.
- 테스트에는 4종 실제 native 실행, flags/폭/memory/cross-family, 32개 helper가 모든 family를 사용하는 controlled PE packing, full crypto cache resume 및 인증 변조 거부가 포함된다. 최종 기본 구성과 all-features 구성은 각각 922개 통과, 실패 0이며 패킹 통합 테스트 10개를 포함한다. 최종 테스트 수와 source hash는 `artifacts/full-architecture-default-result.json`과 최종 로그에 기록한다.
- 제품 성능 기준의 독립 startup/dispatch 측정 및 전체 계획 P0–P7 인증은 별도의 검증 범위다. 전체 프로세스 실행 시간 측정을 해당 성능 기준의 통과로 간주하지 않는다.

네 Boot 정책 모두 최신 바이너리로 패킹과 실행 검증을 통과했다. 정책별 warmup 2회와 측정 21회의 결과는 `artifacts/vm-performance-579931e958b044fb9bfd482fb4cd0af8/report.json`에 있다. 전체 프로세스 p50은 native 179.64ms, orchestration 191.65ms, selected-stages 177.59ms, full-crypto 187.11ms였다.

---

# VM bootstrap / variant 구현 및 검증 현황

기준일: 2026-10-03 (Asia/Seoul). **전체 아키텍처 계획의 완료 보고가 아니다.**

## 기준 상태

- 시작 HEAD: 65bea4daa80a8ca29e5967930c099bc2b9d6eb78.
- 시작 당시 작업 트리에 다수의 기존 변경이 있었으며 이를 보존했다.
- 시작 당시 debug EXE SHA-256:
  83c7f29029b0a51199b5a28d0592223b238adc9a0ffb346cc981b8c333e7ed63.
  당시 EXE가 해당 소스로 빌드됐다는 검증은 없었다.
- Boot crypto ABI v64, handler codec ABI v2, VariantPlan schema v3,
  variant family contract v1, material Boot VM bytecode v1.

## VariantPlan과 Program VM

- 불변 plan에 opcode/condition map, operand mask, register permutation,
  runtime state layout, table layout, native persistent register 역할 배치,
  handler wrapper padding을 저장한다.
- encoder/decoder/interpreter는 같은 plan을 받는 API를 제공한다. Family 모듈은
  Arc<VariantPlan>을 보관하며 sizing/provisional/final commercial build와 모든
  cross-family route/entry/gateway가 그 plan의 layout을 사용한다. Native core는
  전달된 실제 snapshot을 decoder/re-encoder, table, native register remapping 및
  wrapper padding에 사용한다. Legacy API는 compatibility adapter로 남아 있다.
- 모듈 family/domain이 보관된 plan과 다르면 배치 전에 거부한다. Canonical family
  identity v2는 typed instruction JSON과 정렬된 고정 폭 IP map을 해싱한다.
- Commercial checkpoint는 전달받은 실제 plan을 저장하고 digest로 캐시를 구분한다.
  ISA seed와 독립적으로 선택한 state/table layout의 snapshot을 복원한 뒤 native
  실행 결과를 reference와 비교하는 회귀 테스트를 추가했다.
- schema v3의 typed JSON snapshot은 opcode token 순서로 정렬한다. restore는
  digest/version/ABI/canonical representation 및 의미·범위·역함수 계약을 검증하고
  저장된 필드를 복원한다. 손상된 map, duplicate entry, state/table overflow,
  잘못된 register 배치와 padding은 거부한다.
- --vm-variant-policy stable|seeded: stable은 기존 seed/family ISA를 유지한다.
  seeded는 canonical family module 내용과 seed로 module domain을 분리하고
  encoder와 이후 native state/bridge 생성에 그 domain을 전달한다. 활성화된
  private handler key 설정의 identity도 seeded domain에 반영한다.
- 상용 VM module cache에 actual contract snapshot과 generated module을 함께
  저장한다. plan digest/version/family/module context 및 private handler key
  identity가 cache 경계에 반영된다. 다른 plan과 잘린 package는 거부한다.
- Prepared super-op checkpoint 재사용은 기존처럼 비활성이다.
- --vm-family-policy single|function-partition을 연결했다. 기본은 기존 동작인
  function-partition이다. 이 옵션이 네 독립 아키텍처의 완성을 의미하지 않는다.
- wrapper의 NOP 차이는 semantic handler 다양성으로 집계하지 않는다.
- hashing/serialization/plan validation은 빌드 단계에 있다. 이 변경으로
  Program VM dispatch에 PRF/hash/KDF/할당을 추가하지 않았다.

## Boot reference와 실제 material orchestration VM

- vm/boot/{contract,program,reference}.rs: 승인된 buffer span, scratch budget,
  crypto counter 한계, stage/record identity, 인증→복호화→Ready publication 계약.
- reference는 모든 stage 성공 전까지 평문을 owned scratch에 유지한다.
  실패하면 ciphertext를 보존하고 scratch를 지우며 Failed를 공개한다.
  Ready/Failed 이후 반복 실행과 재진입은 거부한다.
- --boot-vm-policy native|orchestration|selected-stages를 추가했다.
  기본은 native이다. orchestration은 인증된 ChaCha20 단계에서만 허용한다.
  selected-stages는 ChaCha20 round arithmetic VM의 opt-in 실험이다. CLI와
  library placement는 인증된 ChaCha20 모드만 허용하며 조용한 fallback이 없다.
- orchestration의 실제 PE 부트 경로는 metadata material을 native root에서
  준비하고, 독립 Metadata record (u64::MAX - 1)로 Boot VM bytecode 전체를
  인증한 뒤 fetch/dispatch한다. opcode/operand 의미 해석은 인증 이후다.
- Boot VM은 Payload/Data/NativeText/Bytecode/Resolver의 domain 선택과 material
  slot 순회를 실행한다. PC/remaining-length 및 material offset/domain bounds를
  검사하고 HALT를 처리한다. Program VM의 초기 state에 의존하지 않는다.
- crypto primitive, 최초 metadata key 준비, program authentication, OS 호출,
  나머지 stage authenticate/decrypt, descriptor/IAT/메모리 보호는 native 잔존이다.
  **stage-material orchestration 가상화**이며 crypto 연산의 VM화나 부트로더 전체
  VM화를 주장하지 않는다.
- program-relative CALL/pop으로 bytecode 주소를 얻고 native nonvolatile을
  보존한다. 변조 인증 실패는 기존 boot authentication과 같은 UD2 실패 경로다.
- private plan/cache/key는 public manifest/release에 넣지 않는다. private build
  manifest에는 schema/policy와 native 잔존 분류 이름만 추가했다.

## 검증

- 최초 관련 회귀: polymorphic 64개, native self-decoding 54개 통과.
- Boot reference 5개: 표준 ChaCha20-Poly1305와 모든 stage 및 block 경계 길이 비교,
  잘못된 seed/tag/domain/record/ciphertext, late failure, guard bytes,
  buffer/resource 한계, repeated execution 검증.
- Native boot harness: native와 orchestration 각각 모든 6 stage × 4 record ×
  4 길이에서 material/nonce/MAC/decrypt 결과 및 scratch 정리를 비교한다.
- 기존 native cross-family call/return 검증을 서로 다른 12 family pair로 확장했다.
  이것만으로 tail-call/중첩/예외/모든 reentry 조합을 완료했다고 판단하지 않는다.
- tests/vm_variant_packing_cli.rs의 controlled PE는 backward arithmetic loop와
  내부 CALL/RET를 실행하고 exit code 13을 반환한다. stable/seeded, single/
  function-partition, 다른 seed/private key, module cache/완료 package 복원,
  release whitelist 및 original/protected 실행 동등성을 검증한다.
- 실제 PE의 Boot VM opcode/domain/slot/tag를 각각 변조하면 Program VM 진입
  이전에 authentication UD2로 종료하는 것도 검증한다.
- fixture/output/log는 artifacts/vm-variant-packing-*에 보존한다.
  사용자 EXE 및 실행 금지된 pb2.exe는 실행하지 않았다.
- 전체 검증 로그: artifacts/vm-final-all-target-tests.log,
  artifacts/vm-final-all-features-tests.log. 최종 결과는 아래에 기록한다.

## 아직 완료하지 않은 계획 요구 사항

- semantic handler recipe 전체를 plan에 고정하고 optimizer 결과까지 검증하는 작업.
- 일반 branch/loop/failure-cleanup BootProgram IR와 전체 stage orchestration 이전.
  material VM의 한정된 loop와 reference IR를 동일한 범용 backend로 합치는 작업.
- 네 family 각각의 실제 독립 state/operand/flag/call lowering. 기존 backend는
  상당한 canonical decoder/state/emitter를 공유한다.
- 모든 bridge pair의 tail-call, nested recursion, exception/unwind, reentry와
  stage별 OS memory protection/TLS/relocation의 확장 fixture 인증.
- selected-stage/full crypto VM 실험 및 해당 capability 승격.
- 제품 수준 dispatch median 5%, startup p95 10% 성능 gate, peak memory 등.
  controlled process benchmark는 dispatch를 분리하지 않으므로 이를 인증하지 못한다.

이 미완료 사항 때문에 P0–P7 전부 완료 또는 부트로더 전체 보호 완료로 표시할 수 없다.
Bootstrap root, native crypto helper, 실행 중 key/state/평문 및 공유 대응관계의
관찰 한계는 남아 있다.

## 이전 검증 결과 (공유 plan API 전환 전)

- cargo test --all-targets: 883 library + 22 CLI integration = **905 통과, 0 실패**.
- cargo test --all-targets --all-features: **905 통과, 0 실패**.
- 새 packing integration 4개에는 정상 original/protected 실행 비교, cache 복원,
  private key/release whitelist, Boot program 변조 거부 및 unsupported policy
  조기 실패가 포함된다. Native bridge의 12 directed pair도 최종 library 회귀에 포함된다.
- 최종 기본 feature debug packer SHA-256:
  FF3B6461268E88F942044E1FEB3D72F0BBA126B586462B6DDB8A806E6DDBAA17.
- src/tests + Cargo.toml/Cargo.lock source snapshot SHA-256:
  0122E4FA7764E60A192748913DB475BFBC4F0A9187A59D95CCD71BF35FC04061.
- machine-readable 검증: artifacts/vm-bootstrap-verification.json.
- 30000 guest loop, alternating 21회/정책의 whole-process 측정:
  native boot p50 355.0321 ms / p95 729.0554 ms;
  orchestration p50 296.9491 ms / p95 619.2454 ms.
  보호 파일은 각각 115200 bytes. 프로세스 생성과 VM 실행 전체를 포함한
  단일 controlled fixture 관측이며 순수 startup/dispatch 또는 제품 gate의 인증이 아니다.
  측정은 all-features debug EXE hash 09455A8F8903F180352C1D7D8CE6EBB295671BDE695C82737934D829BAE3B1EA로 수행했다.
- 재현 script: artifacts/measure-controlled-vm.ps1. 원자료 및 packing 로그:
  artifacts/vm-performance-26a754c2bd6143dcbc1fa013168d1577/report.json.
- 기존 compiler warning은 남아 있다. 관련 수정 파일의 diff whitespace 검사는 통과했다.
  기존 다른 변경의 whitespace까지 임의 수정하지 않았다.

## 공유 plan API 전환 검증

- 전체 회귀 첫 실행은 882 통과/1 실패. qa::run_and_verify fixture가 병렬 부하에서
  9초 제한 내 종료하지 못했다. 이를 통과로 집계하지 않았다.
- 복원된 독립 state/table layout native 동등성 테스트: 1 통과.
- 최종 cargo test --all-targets -- --test-threads=2: **907 통과, 0 실패**.
- 최종 cargo test --all-targets --all-features -- --test-threads=2: **907 통과, 0 실패**.
- 각 실행은 885 library + 22 CLI integration이며 controlled packing 4개를 포함한다.
- 최종 로그: artifacts/vm-shared-plan-final-default.log,
  artifacts/vm-shared-plan-final-features.log. EXE 교체 시 Windows 파일 잠금이 발생한
  중간 검증은 성공으로 집계하지 않고 직렬 실행으로 다시 검증했다.
- Source snapshot: ECA9B15ACBCC3493EA800D6F9A32361DC003EEC09D5CBDB352070AD299958429.
- 기본 debug EXE: FA55399E95F59D101892054605CF19C198D4981F591A86E037DEF4403590C8B2.
- 자세한 해시/경계/검증 기록: artifacts/vm-bootstrap-verification.json.

## 2026-10-04 selected-stage crypto VM 구현

- ChaCha20의 20 rounds를 960개의 실제 ADD32/XOR32/ROTATE32 bytecode로 실행한다.
  별도 bounded interpreter는 16-word work state만 읽고 쓰며 opcode/operand/count,
  fetch budget 및 최종 HALT를 검사한다. Native quarter-round helper를 호출하지 않는다.
- --boot-vm-policy selected-stages가 sizing/final placement에서 해당 backend를 사용한다.
  최초 Metadata material/프로그램 인증에는 별도 native ChaCha root가 남는다.
  암호 round 프로그램은 Metadata record max-2로 인증한 뒤 첫 VM dispatch를 한다.
  material orchestration 프로그램의 record max-1과 분리되어 있다.
- 표준 Poly1305, initial state absorption, feedforward, byte stream XOR, OS bridge는
  native 잔존이다. 따라서 **full crypto VM 완료로 집계하지 않는다**.
- Boot reference IR에 cursor 기반 authenticated record loop, bounded back edge,
  조기 Ready/미완료 record advance 거부 및 explicit failure 의미를 추가했다.
  plaintext scratch의 transactional publication/실패 cleanup 계약을 유지한다.
  이는 reference IR 확대이며 전체 native Boot stage 이전 완료가 아니다.
- 실제 native arithmetic VM의 연속 호출 keystream은 reference와 일치했다.
  controlled PE selected-stage 패킹·실행·캐시 복원도 통과했다.
- 첫 packing 시 sizing용 root call의 null target을 발견해 인접 synthetic target으로
  수정했고 다시 검증했다. 실패를 통과로 집계하지 않았다.
- 최종 기본/all-features 각각 **911 통과, 0 실패** (887 library + 24 CLI integration).
  Packing integration 6개 모두 통과: 정상 native/selected-stage 실행 비교,
  cache 복원, Boot material/crypto round bytecode의 변조 거부, private release whitelist.
- 로그: artifacts/selected-crypto-vm-final-default.log,
  artifacts/selected-crypto-vm-final-features.log. 최신 해시와 범위는
  artifacts/vm-bootstrap-verification.json의 selected_crypto_vm 항목에 기록한다.
- 독립 4종 Program VM lowering, 전체 Boot orchestration, full crypto VM은 미완료다.

- 최신 성능 실험: 정책별 21회 + 2 warmups, 30000 guest loop의 whole-process 측정.
  native: p50 221.3577 ms / p95 540.9349 ms / 115200 bytes.
  orchestration: p50 199.5684 ms / p95 392.5346 ms / 115200 bytes.
  selected-stages: p50 195.4070 ms / p95 284.6346 ms / 120320 bytes.
  startup/dispatch를 분리하지 않으므로 제품 성능 gate를 인증하지 않는다.
  원자료: artifacts/vm-performance-7eaff3180c3a4360bfc7ad83704a4763/report.json.
