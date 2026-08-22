# 검증 기준

## 검증 층

### 1. Library tests

```powershell
cargo test --lib
```

encoder/decoder roundtrip, interpreter/reference differential, native runtime, PE placement,
cross-family routing, integrity serialization과 QA 경로를 포함합니다. 2026-08-22 기준
최근 실행은 564 passed / 0 failed입니다.

### 2. Structural validation

패킹 뒤 출력 PE를 다시 parse하여 section bounds, entry point, `.pdata`, ownership,
runtime ranges와 protection metadata를 검사합니다. 구조 검증 통과가 실행 동치를
의미하지는 않습니다.

### 3. Execution differential

`--verify-output`은 원본과 보호본을 각각 실행해 다음을 비교합니다.

- process exit code;
- stdout bytes;
- stderr bytes;
- timeout.

대표 profile:

```powershell
btg-packer.exe -i corpus\o1.exe -o protected.exe `
  --vm --vm-oep --vm-commercial --m7 --m8 --integrity `
  --verify-output --seed 31010
```

최근 결과: exit 0, stdout 1,460B, stderr 0B 동일.

### 4. Tamper checks

BTGI table이 가리키는 첫 VM bytecode, handler code, handler table 영역을 각각
1 bit 변경한 산출물이 boot에서 `STATUS_ILLEGAL_INSTRUCTION (0xC000001D)`로
차단되고 stdout/stderr를 생성하지 않는 것을 확인했습니다.

## 아직 다시 실행해야 하는 gate

- 최신 모든 변경을 포함한 20-seed `--verify-seeds` gate;
- 전체 hostile/compiler corpus;
- malformed bytecode/descriptor 확대 corpus;
- ASLR/CFG/CET profile matrix;
- multi-thread/shared lifetime stress.

따라서 대표 profile 통과를 범용 production readiness로 해석하면 안 됩니다.

## 문서 수치 갱신 규칙

- 테스트 수는 실제 `cargo test --lib` 종료 줄에서만 갱신합니다.
- corpus 수치는 입력 파일, seed, 전체 CLI를 함께 기록합니다.
- 실패한 실험은 완료 상태로 올리지 않고 journal 또는 계획 문서에 남깁니다.
- 오래된 보고서와 현재 수치가 충돌하면 `docs/current-status.md`가 우선합니다.
