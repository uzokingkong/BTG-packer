# 2026-08-17 — nowaction 🔴 #1 해소: poly backward-branch rolling-key 복원

## 개요
nowaction.txt 🔴 #1 (Critical correctness) — `src/vm/poly/decoder.rs` + `src/vm/poly/interpreter.rs`에서
backward jump(loop) 시 target VIP의 rolling-key 상태가 복구되지 않아 두 번째 loop부터
스트림이 desync 되는 버그를 코드로 해소하고 상태 마커를 ✅로 갱신했다.

## 변경
- `src/vm/poly/interpreter.rs`:
  - `PolymorphicInterpreter::run`이 각 인스트럭션 시작 바이트 오프셋의 롤링 키 스냅샷을
    `instr_starts()`(offset→key 캐시)로 선형 스캔해 미리 캡처.
  - taken 분기(forward·backward 모두)에서 `self.rolling.current_key = target_key`로
    타깃 위치의 **선형 실행 키 상태**를 복원. 기존 `fast_forward_roll`은 forward만
    동기화해 backward에서 키가 desync 되는 문제를 해소.
  - `test_poly_backward_branch_loop_matches_reference`: 단일/중첩(outer/inner) backward
    루프가 `eval_state`와 전체 상태(regs/temps/flags/vsp/stack/mem) 일치.
  - `test_poly_fuzz_random_programs_match_reference`: 유계 루프 포함 결정적 퍼즈(80 case × 3 seed).
- `src/vm/poly/decoder.rs`: `decode_full`는 선형 스트림만 복호화(분기 실행 없음) → 키 복원 불필요 확인.
- `nowaction.txt`: 🔴 즉시수정 #1 항목 + 상세 섹션(#2 backward branch) 상태 마커 → ✅ 해소.

## 검증
- `cargo build --release`: green
- `cargo test --release --lib poly::`: 34 passed; 0 failed
- `cargo test --release --lib`: 300 passed; 0 failed

## 상태
- nowaction #1 ✅. backward 분기 후 해석 상태가 원본(선형 블록 단위 동치)과 동일함을 차등 검증.
