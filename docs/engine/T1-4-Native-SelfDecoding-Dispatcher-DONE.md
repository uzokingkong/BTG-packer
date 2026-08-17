# T1-4 완료 보고 — 네이티브 자가복호화 폴리모픽 디스패처

> 작업일: 2026-08-14 · 대상: `vm-obf` repo on node `ujiwo-zyris-code` (Windows)
> 상태: **완료** — 차등 테스트 전부 green, 커밋 `7d8e2ee` pushed to origin/main

## 1. 배경

이전 세션(`5cde398`)의 보고서 최우선 잔여 항목:
> **"순수 네이티브 디스패처가 rolling-key 를 스스로 풀며 실행"**

구현(`src/vm/threaded/poly_direct.rs`의 `run_native_poly_direct`)은 이미 컴파일/실행은
됐으나 **잘못된 결과값**(예: `regs[0]` 기대 `512`, 실제 쓰레기 값)을 내는 상태였다.

## 2. 근본 원인 (Root cause)

`emit_read_imm8` — 8바이트 즉시값(imm64)을 스트림에서 읽는 헬퍼에서,
**64비트 누산기로 `R9`를 사용**했는데 `sub_decrypt` 서브루틴이 **매 호출마다 R9를
clobber** 했다.

- 원래 코드: `R9`에 누적 → 0번째 바이트는 `mov R9,RAX`로 저장되지만,
  1~7번째 바이트는 `call sub_decrypt`가 R9를 덮어쓴 뒤 `or R9,RAX`로 누적 → 부분합 소실.
- 결과: 모든 imm64 피연산자(및 AddWithCarry의 cin)가 첫 바이트 이후 쓰레기가 됨.
  첫 명령 `reg0 = 0x200`이 곧바로 잘못된 값을 낳아 보고서의 증상과 일치.

## 3. 수정

`emit_read_imm8`의 누산기를 **RBX로 교체**. `sub_decrypt`는
`RAX/RCX/R9/R10/R11/R12/R14`를 clobber하지만 `RBX/R13/R15/RDX`는 보존한다.
모든 호출자(`sub_dec_ops`의 IMM1/IMM2, ADD 핸들러의 CIN)에서 RBX가 안전함을
대조 확인.

## 4. 검증

- `cargo test --release poly_direct` → **2 passed**
  - `test_native_poly_direct_matches_interpreter_and_reference` (3 seeds × native == interp == eval_state)
  - `test_native_poly_direct_matches_decoder_path`
- `cargo test --release` 전체 → **126 passed** (기존 124 + 신규 2), 0 failed.
- Rolling-key 엔진(`key_byte`/`step`), ADD carry/flag, 피연산자 해석, 핸들러 테이블
  VA 매칭을 Rust 참조(`rolling_key.rs`, `interpreter.rs`, `risc/flags.rs`)와 대조 — 전부 일치.
  유일한 결함이 R9 누산기였음을 확인.

## 5. 커밋/푸시

```
7d8e2ee feat(vm): T1-4 pure-native self-decoding rolling-key dispatcher
```
- 변경: `src/vm/threaded/poly_direct.rs` (신규), `src/vm/threaded/mod.rs` (배선)
- `git push origin main` 완료.

## 6. 미완/후속

- **스모크 패킹 미실행**: `btg-packer -i real_win_calc.exe -o smoke_t15.exe --vm`
  은 입력 PE(`real_win_calc.exe`)가 이 환경에 없어 실행하지 못함. CLI(`--vm`)는
  `--help`로 확인됨. 검증 PE가 있으면 회귀 확인 권장.
- 중기 잔여(이번 작업 범위 아님): T2-2 RC4→BTG-C1 전환, keyed-MAC 부트 스텁
  네이티브 검증, T1-2 리프터 커버리지 확장.
