# 2026-08-19 — WS2: Function atomicity / bridge ABI (spec §6 explicit follow-ups)

> 태스크: `docs/architecture/function-atomicity-bridge-spec.md` §6의 명시적 후속 작업 4건.

## 2.1 function-ownership ↔ .pdata consistency AUTO-CHECK ✅

**구현**: 새 모듈 `src/pipeline/ownership.rs` (+ `src/pipeline/validate.rs` 확장, `src/main.rs` CSV 배선).

- `FunctionOwnership { start_rva, end_rva, owned_by_vm, enforce_entry_begin, reason }` +
  `RuntimeFunction { begin_rva, end_rva }`.
- `check_ownership(model, runtime_functions)` 검증:
  1. VM 함수가 RUNTIME_FUNCTION에 **완전 포함** (`Begin <= start && end <= End`).
  2. VM 함수의 네이티브 엔트리가 해당 RUNTIME_FUNCTION의 **BeginAddress**인지
     (프롤로그 우회 금지) — 실제 가상화된 원본 함수에만 적용
     (`enforce_entry_begin=true`). 패커 삽입 리전(프로그램-VM 모듈)은 원본 함수가
     아니므로 엔트리-Begin 불일치는 유효하지 않음 → `false`.
  3. VM 함수 간 오버랩 금지.
- CSV 매핑 파일: `--vm-oep` 경로에서 `<output>.ownership.csv`로 소유권 결정 기록
  (`render_csv`).
- validate 패스에 `validate_function_ownership` 연결 — 프로그램-VM 경로
  (`ctx.vm_oep`)에서 빌드 후 자동 실행.
- **게이트**: `--vm --vm-oep` 및 `--vm --vm-oep --vm-commercial` 빌드에서 검사
  clean 통과 (이 두 경로로 test_prog pack → exit 0, FINAL CHECKSUM 유지).
- **호출법 문서**: `btg-packer --input X --output Y --vm --vm-oep ...` → 콘솔에
  `[VALIDATE] OK function-ownership ↔ .pdata: N fn (...)` 출력 + `Y.ownership.csv`.
- 테스트: `ownership` 모듈 8개 (bijection/엔트리-Begin/모듈-리전 등).

## 2.2 reentrant callback / vtable dispatch TEST MATRIX ✅

**구현**: `src/vm/risc/bridge_abi_tests.rs` 확장.

- `reentrant_callback_preserves_outer_vm_state` — native→callback→VM 재진입 시
  외부 VM 상태(stack/flags/vsp/regs) 보존 (콜백 유무 블록 동치).
- `doubly_nested_callback_preserves_outer_state` — 2중 중첩 콜백 체인
  (outer→mid→inner) 외부 상태 보존.
- `vtable_indirect_dispatch_at_boundary` — 레지스터-간접 디스패치가 소유권 경계
  엔트리(ip2/ip5)로 착지, carry-free 검증.
- 차등 규율: 선형 블록 단위 동치만.

## 2.3 실제 host-call NativeCallBridge ABI 구현 🔶(부분: ABI emission 계층 구현·검증)

**구현**: 새 모듈 `src/vm/risc/native_abi.rs` (+ `src/vm/risc/mod.rs` 등록).

- §2.3 PRE-CALL/CALL/POST-CALL Win64 시퀀스를 emit하는 **검증된 ABI emission
  계층**: `pop ret_ip→r11; RCX/RDX/R8/R9 아규먼트 실장; callee-saved
  (RBX,RBP,RDI,RSI,R12–R15) 보존; 32B shadow space + 16B 정렬; call;
  RAX→가상 RAX 동기화; callee-saved 역순 복원; `jmp r11` 재개`.
- `verify_call_site` + `validate_win64_abi`(기존 `src/vm/abi.rs`)로 emit된 바이트의
  ABI 준수(callee-saved 보존, shadow, 정렬, call/동기화/재개)를 iced_x86 디코드로
  검증.
- **차등 guard 유지**: reference `eval_state` / poly interpreter / threaded native는
  `NativeCallBridge` no-op으로 그대로 둠 (기존 bridge_abi_tests no-op 동치 통과).
  레거시 `OP_NATIVE_CALL` bridge(`poly_direct.rs`) **무수정**.
- 테스트: `native_abi` 4개 (Win64 계약, 16B 정렬, 4-arg 실장, unsaved-write 탐지).
- **열린 항목**: 실제 런타임 dispatch 계층에서 이 ABI를 호출해 네이티브 호스트 콜을
  실행하는 통합은 아직 배선 안 됨 (reference/interpreter는 의도적으로 no-op 유지).
  실제 실행 콜은 상용/런타임 계층 책임 — 별도 항목으로 문서화.

## 2.4 상용 엔진 T5 전체 SEH 가상화 DIFFERENTIAL 🔶(조사 완료·블로커 문서화)

**조사 결과** (`src/vm/text_lift/commercial.rs` `lift_program_cfg_commercial`):

- 상용 경로는 `detect_seh_native_functions(..., full_seh_virtualize=false)`로 **SEH
  최소(132) 세트를 네이티브 유지**. `BTG_SEH_NONE=1` 전 SEH 가상화는 **레거시
  `--vm --vm-oep` 경로에서만 검증됨** (주석 lines 173–176).
- test_prog 상용 pack 로그: `excluded 7339 block(s) (SEH minimal +
  RISC-unliftable-instruction functions)`, `SEH 5455 + RISC-unliftable 1884`.
- **T5 블로커 (정확한 근거)**:
  1. 상용 RISC 엔진은 SEH 함수를 VM화하지 않음 (함수 원자성 + 무한정 fallback 원칙).
  2. SEH 세트를 teardown-guard(49)로 줄이면 가상화된 Once/panic 경로에 **RISC-lift
     fidelity gap** 발생 → 16-test + FINAL CHECKSUM baseline 회귀 위험.
  3. 알려진 **함수 원자성 갭** (lines 196–201): SEH func_ranges 밖의 unliftable
     블록으로 VM↔네이티브 경계가 함수 중간에 생길 수 있고, 가상화된 jmp/call이
     네이티브 함수 꼬리를 호출하면 스택 프레임 파괴. 함수 원자성 + 경계-브리지
     재설계는 P2 후속.
- **결정**: baseline 회귀 위험 때문에 상용 전체 SEH 가상화를 강제하지 않음.
  differential 결과와 블로커를 열린 항목으로 기록 (⚠). 구현 시
  `full_seh_virtualize=true` (+`BTG_SEH_NONE=1`) + 함수 원자성 경계 브리지 필요.

## 테스트/빌드

- `cargo build --release`: exit 0.
- `cargo test --release --lib`: WS2 추가분 green.
  `ownership` 8 + `bridge_abi` 5 + `native_abi` 4 = **17 테스트**.
- baseline 회귀 없음: `--vm --vm-oep`·`--vm-commercial` pack→run 출력 SHA가
  baseline과 동일, `FINAL CHECKSUM = 0x2cdc0e4511d84a64`.
