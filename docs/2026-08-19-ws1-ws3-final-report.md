# BTG-Packer — 2026-08-19 WS1/WS2/WS3 Final Report

> 날짜: 2026-08-19 · 노드: `C:\Users\uzoki\Desktop\asdfsadfecwecc` · 브랜치: `main` (작업 트리)
> 범위: T3-1 chacha20 AEAD e2e + function-atomicity/bridge ABI + nested VM/state concealment.
> 모든 변경은 커밋하지 않고 작업 트리에 남김 (지시대로, 회귀-green인 경우만 선택 커밋).

---

## GATE (최종)

| 항목 | 결과 |
|---|---|
| `cargo build --release` exit | **0** |
| `cargo test --release --lib` | **423 passed; 0 failed** (기준 398 → **+25**) |
| `--vm --vm-oep` pack→run | exit 0 · 출력 SHA baseline 동일 · FINAL CHECKSUM `0x2cdc0e4511d84a64` |
| `--vm --vm-oep --vm-commercial` pack→run | exit 0 · 출력 SHA baseline 동일 · FINAL CHECKSUM `0x2cdc0e4511d84a64` |
| 차등 규율 | 선형 블록 단위 동치만 |

---

## WS1 — ChaCha20-Poly1305 AEAD end-to-end ✅

- **실행**: `btg-packer --input repro/test_prog.exe --output repro/chacha20_packed.exe --crypto-mode chacha20`
- pack exit 0 · manifest `crypto_mode = chacha20`, `crypto_version = 63`, `at_rest_encryption = true`.
- packed run exit 0 · 출력 1460 B · SHA `4366e2530f32a088306efe497d1762e5a087c54ac6c114b44f3ee13d422dcfe5` == baseline.
- **테스트 추가**: 없음 (실행 검증). lib 테스트는 기존 chacha/poly1305가 통과.
- **열린 항목**: 없음.
- **gate**: chacha20은 평문 bulk at-rest 경로 전용. VM/chained/reencrypt 조합은 RC4/BTG-C1 폴백 (문서화됨).

## WS2 — Function atomicity / bridge ABI 🔶 (3/4 완료)

### 2.1 function-ownership ↔ .pdata AUTO-CHECK ✅
- **테스트 추가**: `ownership` 모듈 8개.
- **파일**: `src/pipeline/ownership.rs` (신규), `src/pipeline/validate.rs`, `src/pipeline/mod.rs`, `src/main.rs`.
- 빌드 후 프로그램-VM 경로에서 clean 통과, `<output>.ownership.csv` 생성 (gate_vmoep/commercial 둘 다 확인).
- **호출법**: `btg-packer --input X --output Y --vm --vm-oep ...` → 콘솔 `[VALIDATE] OK function-ownership ↔ .pdata: N fn`.

### 2.2 reentrant callback / vtable dispatch TEST MATRIX ✅
- **테스트 추가**: `bridge_abi_tests` +3 (`reentrant_callback_preserves_outer_vm_state`, `doubly_nested_callback_preserves_outer_state`, `vtable_indirect_dispatch_at_boundary`).
- **파일**: `src/vm/risc/bridge_abi_tests.rs`.

### 2.3 NativeCallBridge Win64 ABI 🔶 (부분)
- **테스트 추가**: `native_abi` 4개.
- **파일**: `src/vm/risc/native_abi.rs` (신규), `src/vm/risc/mod.rs`.
- 검증된 ABI emission 계층 구현(PRE/CALL/POST, shadow/정렬/callee-saved/ret_ip 재개), iced_x86 + `validate_win64_abi`로 검증.
- reference/poly/threaded no-op 유지 · legacy `OP_NATIVE_CALL` bridge 무수정.
- **open**: 실제 런타임 호스트-콜 통합 미배선 (런타임 계층 책임).

### 2.4 상용 T5 전체 SEH 가상화 differential 🔶 (조사·블로커 문서화)
- 상용 엔진은 SEH 최소(132) 네이티브 유지; `BTG_SEH_NONE=1`은 레거시 `--vm --vm-oep` 전용.
- **open**: RISC-lift fidelity gap(가상화된 Once/panic 경로) + 함수 원자성 갭(경계-브리지 미구현) → 구현 시 baseline 회귀 위험. `commercial.rs` 주석 lines 173–176, 196–201.

## WS3 — Nested VM / state concealment 🔶 (2/3 완료)

### 3.1 Nested VM runtime layer (VmCallBridge) 🔶
- **테스트 추가**: `nested` 2개 (외부 상태 저장/복원 동치, reference VmCallBridge와 블록 동치).
- **파일**: `src/vm/nested.rs` (신규), `src/vm/mod.rs`.
- **open**: poly/threaded 호스트 계층에서 중첩 VM 실제 실행 통합 미배선 (`is_encodable` 미등록 → `--vm-commercial`은 네이티브 유지).

### 3.2 State concealment auto-verification ✅
- **테스트 추가**: `conceal` 4개.
- **파일**: `src/vm/conceal.rs` (신규), `src/vm/mod.rs`.

### 3.3 Dispatcher metadata minimization ✅
- **테스트 추가**: `dispatch_perm` 4개.
- **파일**: `src/vm/dispatch_perm.rs` (신규), `src/vm/mod.rs`.

---

## 신규 테스트 요약 (기준 398 → 423, +25)

| 모듈 | 추가 | 총 |
|---|---|---|
| `pipeline::ownership` | 8 | 8 |
| `vm::risc::bridge_abi_tests` | 3 | 5 |
| `vm::risc::native_abi` | 4 | 4 |
| `vm::conceal` | 4 | 4 |
| `vm::dispatch_perm` | 4 | 4 |
| `vm::nested` | 2 | 2 |
| **합계** | **25** | — |

## 변경/생성 파일 (src)

- `src/pipeline/ownership.rs` (신규) · `src/pipeline/mod.rs` · `src/pipeline/validate.rs` · `src/main.rs`
- `src/vm/mod.rs` · `src/vm/conceal.rs` (신규) · `src/vm/dispatch_perm.rs` (신규) · `src/vm/nested.rs` (신규)
- `src/vm/risc/mod.rs` · `src/vm/risc/native_abi.rs` (신규) · `src/vm/risc/bridge_abi_tests.rs`

## 문서 (노드)

- `docs/journal/2026-08-19-ws1-chacha20-e2e.md`
- `docs/journal/2026-08-19-ws2-function-atomicity-bridge.md`
- `docs/journal/2026-08-19-ws3-nested-vm-state-concealment.md`
- `docs/roadmap/milestones.md` (상태 업데이트)
- 본 리포트 `docs/2026-08-19-ws1-ws3-final-report.md`

## 로그 (repro/)

- `chacha20_pack_console.txt` · `chacha20_packed_run.txt` · `baseline_ws1.txt`
- `gate_vmoep_pack.txt` · `gate_vmoep_run.txt` · `gate_commercial_pack.txt` · `gate_commercial_run.txt`
- `gate_vmoep.exe.ownership.csv` · `gate_commercial.exe.ownership.csv`
- `test_final.txt` (최종 `cargo test --release --lib` 423 passed)

## 열린 항목 (open)

1. **WS2.3** NativeCallBridge 실제 런타임 호스트-콜 통합 (ABI emission은 구현·검증됨).
2. **WS2.4** 상용 `--vm-commercial` T5 전체 SEH 가상화 — RISC-lift fidelity gap + 함수 원자성 갭 블로커.
3. **WS3.1** 중첩 VM 호스트 계층 실제 실행 통합 (reference 계층 + 차등 테스트는 완료).
