# P3 --vm-commercial: Verified Self-Decoding Dispatcher Integration (2026-08-15)

> 작성: 2026-08-15 (autonomous run) · repo `asdfsadfecwecc` · node `ujiwo-zyris-code`
> 브랜치: `commercial/p3-engine-integration` · 커밋: `935c42f` (origin push 완료)

## 요약

`src/vm/commercial_build.rs::build_program_vm_commercial`이 방출하던 **broken generic 10-handler
모듈**이 `--vm-commercial` 부트 크래시(`0xC0000005`)의 근본 원인이었음을 진단·해소했다.
그 모듈의 tail-dispatch는 rolling-key 폴리 바이트코드를 **full-64-bit seed**로 XOR하고
**operand 디코딩이 전혀 없어** `mov rax,[r15+rax*8]`가 가비지 인덱스로 폭발했다.
(`docs/P4-P5-gates-progress.md` §8의 기존 진단과 일치.)

## 변경 내용

### `src/vm/threaded/poly_direct.rs`
- **`build_self_decoding_parts` 추출**: 검증된(T1-4) self-decoding rolling-key dispatcher의
  machine code + handler table + operand-offset/kind table을 **임의 VA**에 임베드할 수 있게 분리.
- `run_native_poly_direct`는 동일한 parts를 호스트 RWX arena에 배치·실행하는 runner로 유지
  (기존 차등 테스트 그대로 통과).
- **핸들러 셋 8 → 17 op 확장**: `Mov`, `ArithmeticShiftRight`, `MemoryRead{1,2,4,8}`,
  `MemoryWrite{1,2,4,8}` 추가.

### `src/vm/commercial_build.rs`
- module table blob = `[256×8 handler][256 op-offset][256 op-kind]` (0xA00 bytes) —
  dispatcher의 R15-relative(+0x800 / +0x900) operand-table 읽기와 정합.
- 가상 스택을 state 버퍼 아래 별도 영역(`VIRTUAL_STACK_SIZE`)으로 분리해 push/pop 충돌 방지.
- `build_program_vm_commercial`이 검증된 self-decoding dispatcher 모듈을 생성하도록 재작성.

### 신규 차등 테스트 (`commercial_build.rs::tests`)
- `test_commercial_module_executes_matches_reference`: `build_program_vm_commercial` 산출물을
  built VA에 임베드해 dispatch 실행 → `RiscProgram::eval_state`와
  **regs / temps / flags / vsp / stack 완전 동치** (선형 블록 단위 동치 계약).

## 검증 결과

| 항목 | 결과 |
|---|---|
| `cargo build --release` | exit 0 |
| `cargo test --release --lib` | **226 passed; 0 failed** |
| 레거시 `--vm` / `--vm --vm-oep` pack+run | **16개 테스트 전체 통과**, FINAL CHECKSUM `0x2cdc0e4511d84a64` baseline 동일 (무회귀) |
| `--vm --vm-oep --vm-commercial` pack | exit 0 (상용 모듈 생성 성공) |

## 남은 P3 갭 (다음 작업)

whole-program 16-test run은 아직 green이 **아님**. self-decoding dispatcher에 아직 네이티브
핸들러가 없는 op들이 **안전한 NOP landing**으로 매핑되어 실행이 멈춘다:

- **VirtualBranch (실제 taken 제어흐름 / branch resolution)** — 가장 중요
- Multiply / MultiplyLow / Divide
- Setcc (조건별)
- ConditionalMove (조건별)
- CompareExchange
- CountTrailingZeros
- NativeCallBridge

다음 단계: 위 op들의 네이티브 핸들러 + branch map(ip_map) 기반 분기 해석을 self-decoding
dispatcher에 구현하고, whole-program 16-test + checksum gate를 노린다.
