# 2026-08-19 — readccc §4.6: 함수 원자성 + Win64 네이티브 콜 브리지 명세 (WS2)

## 요청
`readccc.md` §4.6 (P0): whole-program VM의 함수 경계 원자성과 네이티브 call/callback/return/
unwind 정확성 명세. `NativeCallBridge`가 reference 경로에서 no-op. VM→네이티브 경계가 함수
중간에 진입할 위험. → 명세 문서(markdown) + 현재 baseline을 깨지 않는 안전 구현 + 후속 작업 명시.

## 산출물
### 명세 문서
`docs/architecture/function-atomicity-bridge-spec.md` — v1 명세:
- §1 `.pdata`/UNWIND_INFO 기반 function-ownership 모델 (`FUNCTION-OWNERSHIP` 계약).
- §2 Win64 브리지 ABI 계약 (caller/callee-saved, 32B shadow, 16B 정렬, return, unwind,
  PRE/POST-CALL 가상 상태 동기화). callback/vtable/reentrancy 매트릭스.
- §3 EH/SEH/C++EH/Rust panic 지원 계층(Tier T0..T5) 정책.
- §4 TLS 콜백 순서·crossing 계약.
- §5 요구 ↔ 모듈 매핑, §6 수용 기준 + 명시적 후속 작업.

### 안전 구현 (baseline 무회귀)
- `src/vm/risc/bridge_abi_tests.rs` — `eval_state`에서 `NativeCallBridge` no-op이
  **전체 가상 상태(regs/temps/flags/vsp/stack/mem)를 보존**하는지 검증하는 차등 가드:
  - `bridge_noop_preserves_full_state`: 빈 프로그램 == bridge-only 프로그램.
  - `bridge_mid_program_is_transparent`: register-mutating op 사이에 bridge 주입 == 무주입.

## 결과
`cargo test --release --lib bridge` 11 passed (신규 2 포함) · 전체 398 passed; 0 failed.
후속 작업(명세 §6): function-ownership↔.pdata 자동 검사, reentrant callback/vtable 매트릭스,
실제 host-call ABI 구현, 상용 엔진 T5 SEH differential — **명시적으로 미구현**.
