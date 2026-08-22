# BTG Packer 현재 구현 계획

이 문서는 현재 `main`에서 앞으로 구현할 작업만 관리합니다. 완료된 작업의 긴 진행
기록과 과거 감사 원문은
[`docs/history/plan_vmrestore_upgraded-2026-08-22-full.md`](docs/history/plan_vmrestore_upgraded-2026-08-22-full.md)에
보존합니다. 구현 상태 판정은 [`docs/current-status.md`](docs/current-status.md)가
단일 기준입니다.

기준일: 2026-08-23

기준 구현 커밋: `c4b64c5` 이후 현재 변경

진척도: 기능 구현 약 82%, release 완료도 약 75%

## 완료된 큰 단계

| 단계 | 상태 | 완료 범위 |
|---|---|---|
| P0/P1 correctness | 완료 | differential gate, SHLD 수정, 주요 RISC/native 의미 보존 |
| P2-9 M7 | 완료 | family별 instruction-aligned chunk와 runtime key 파생 |
| P2-10 multi-VM | 완료 | 4개 독립 module/state/table/bytecode와 cross-family call/return |
| P2-13 grammar | 완료 | family operand 순서, compact immediate/branch, control token, super-op grammar |
| Distributed integrity 기반 | 완료 | 12개 BTGI region descriptor와 boot/runtime 검증 |
| P2-14 핵심 | 완료 | u16 metadata, split banks, spill/XMM/stack 분리, RSI/RDI lazy flags |
| Data-lifetime 기반 | 완료 | 문자열·exact-width constant, 전역 owner/depth/lock 동기화 |

## 남은 구현 순서

### 1. Data-lifetime exception/unwind cleanup

완료: sync entry를 48바이트 cleanup descriptor(lock/depth/owner/object VA/len/key)로
확장하고, 모든 family native-call RUNTIME_FUNCTION에 `UNW_FLAG_UHANDLER`와 생성 handler
RVA를 연결했습니다. handler는 현재 TEB owner의 활성 객체를 동일 mask로 재암호화한 뒤
depth/owner/lock을 원자적으로 정리합니다. validator는 4개 bridge record의 flag와 RVA를
출력 PE에서 다시 검사합니다.

- nested/cross-family/native exception corpus를 release matrix에서 계속 확대한다.
- 복합 table access는 모든 참조와 폭이 증명되는 경우에만 활성화하고 나머지는
  fail-closed 제외한다.

완료 기준:

- 정상·예외·중첩 경로에서 lock/depth/owner가 항상 원상 복구됨;
- 다른 thread가 영구 spin하지 않음;
- representative production differential 및 lifetime stress 통과.

### 2. P2-11 handler synthesis 확대

- execution-weight 상위 80% opcode에 최소 3개 의미 동치 native body recipe를 둔다.
- integer/shift/compare/load-store/SSE/control 순으로 micro-op decomposition, scratch
  allocation, MBA, instruction selection을 실제 handler body에 반영한다.
- N=20 handler CFG similarity와 differential corpus를 release gate에 추가한다.

### 3. P2-12 runtime anchor 마무리

- runtime base/state/table/bytecode bundle을 RIP-relative 또는 RVA-derived 방식으로
  materialize한다.
- 단일 signature로 여러 instance를 찾는 비율을 측정하는 N=20 scanner gate를 둔다.
- ASLR/CFG/CET 조합에서 4개 instance와 family별 integrity topology를 재검증한다.

### 4. P2-15 native bridge oracle 감소

- 실제 live-in/live-out subset만 marshaling한다.
- canonical bridge image는 필요한 순간에만 만들고 복귀 직후 zeroize한다.
- instance별 bridge ABI/layout variant를 추가하고 sensitive region bridge-out 0을
  fail-closed gate로 유지한다.

### 5. Release gate

- 최신 전체 hostile/compiler corpus;
- 실제 20-seed pack + execute;
- malformed bytecode/BTGI/tamper corpus;
- ASLR/CFG/CET, SEH/unwind, multi-thread lifetime matrix.

## 현재 검증 기준

- `cargo test --lib`: 578 passed, 0 failed.
- `corpus/o1.exe`, seed 31010 대표 최대 조합: exit 0, stdout 1,460B,
  stderr 0B 동치.
- cleanup-backed lifetime 적용 시 최종 보호 객체 54개. 후보 182개/strict scope 116개이며
  최종 all-reference proof에서 미증명 cross-boundary 객체 54개를 제외했습니다.
- 4개 native bridge UHANDLER → cleanup RVA `0xAFB03`, structural/execution differential 통과.
- 위 결과는 대표 기준이며 최신 전체 release matrix 통과를 의미하지 않습니다.

## 문서 갱신 규칙

1. 구현 변경은 이 문서와 `docs/current-status.md`를 함께 갱신합니다.
2. 완료 판정은 코드 연결, 회귀 테스트, production 검증이 모두 있을 때만 합니다.
3. 실험 과정은 `docs/journal/`에 기록하고 현재 계획에 과거 로그를 누적하지 않습니다.
4. 테스트 수와 production 수치는 실제 종료 결과만 기록합니다.
