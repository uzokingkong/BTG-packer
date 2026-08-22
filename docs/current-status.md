# 현재 구현 상태

이 문서는 BTG Packer의 현재 `main` 상태를 분류하는 기준 문서입니다. 날짜가 붙은
분석, journal, audit 보고서는 역사 기록이며 이 문서보다 우선하지 않습니다.

기준일: 2026-08-22

## 구현 완료

### Multi-family Program VM

- 함수 단위 ownership을 Stack, Register, MixedRisc, FusedCisc family로 고정합니다.
- family마다 native runtime code, handler table, polymorphic bytecode, mutable state,
  virtual stack, call stack을 독립 배치합니다.
- cross-family direct CALL, tail-JUMP, return/resume를 canonical route record로
  materialize하고 runtime bridge가 family layout을 변환합니다.
- production 대형 프로그램은 최소 3개 instance와 최대 단일 instruction ownership
  50% 미만을 fail-closed gate로 검사합니다.

관련 코드:

- `src/vm/poly/architecture_family.rs`
- `src/vm/multi_family.rs`
- `src/pipeline/crypto/place/vm_build.rs`
- `src/vm/threaded/poly_direct/builder.rs`

### Polymorphic bytecode/runtime

- family/seed별 opcode, register, condition map과 rolling-key ciphertext를 생성합니다.
- family별 operand descriptor 물리 순서가 다릅니다.
- absolute branch target은 family별 marker→width 순열과 최소 1/2/4/8-byte masked
  payload로 표현하며 고정 8-byte tail을 사용하지 않습니다.
- ordinary immediate는 값에 맞는 최소 unsigned/signed 1/2/4/8-byte payload를
  사용하고, 네 family는 서로 다른 marker→width 순열을 사용합니다.
- static decoder, interpreter, production native self-decoder가 같은 grammar를
  공유합니다.
- M7은 각 family stream을 instruction boundary에 맞춘 독립 chunk로 보호합니다.

### Handler runtime hardening

- handler table entry는 opcode별 파생 키로 conceal합니다.
- master material은 runtime MBA identity로 조합합니다.
- 미등록 opcode는 trap handler로 연결합니다.
- family마다 forward/reverse와 single/pair가 조합된 서로 다른 table integrity
  traversal을 사용합니다.
- 일부 MOV/NOT/NOR handler는 seed/opcode에 따라 실제 의미 동치 body recipe가
  달라집니다.

### Distributed integrity

- 4 family × handler code/table/bytecode = 최대 12개 region을 독립 sealing합니다.
- `BTGI` header와 40-byte descriptor entry ABI를 `.textb`에 serialize합니다.
- boot runtime이 transient decrypt 뒤 모든 descriptor를 순회해 keyed FNV lockstep
  tag를 재계산하며 magic/count/tag 오류를 `UD2`로 차단합니다.
- code, table, bytecode 각각의 실제 1-bit mutation 차단을 검증했습니다.

### Data lifetime

- PE literal reference graph와 strict scope/ownership proof를 통과한 ASCII/UTF-16
  객체를 at-rest ciphertext로 저장합니다.
- call 또는 direct access 직전에 decrypt하고 사용 직후 re-encrypt합니다.
- proof가 불완전하거나 native/loader가 공유하는 객체는 보호 대상에서 제외합니다.

## 부분 구현

| 항목 | 완료된 범위 | 남은 범위 |
|---|---|---|
| P2-11 handler synthesis | full ISA target wrapper, 일부 실제 body recipe | execution-weight 80%에 3개 이상 body recipe |
| P2-12 anchor 분산 | 4 instance, 4 integrity topology, ownership gate | RIP-relative runtime bundle materialization, N=20 signature gate |
| P2-13 grammar | operand order, compact immediate/absolute branch marker ABI | block-local delta/table-indirection/continuation grammar |
| Data lifetime | strict single-owner ASCII/UTF-16 | 공유 객체 동시성, wider format/direct-memory cases |
| Release gate | 567 library tests, 대표 production/tamper | 최신 전체 hostile corpus와 20-seed 재실행 |

## 미구현 또는 다음 단계

- P2-13 block-local delta/table indirection/continuation control grammar.
- P2-14 split state bank와 lazy flag producer token.
- shared lifetime object의 thread-safe state/locking.
- P2-15 native bridge canonical-image lifetime 축소와 oracle 감소.
- 최신 전체 hostile corpus/20-seed release gate.

## 현재 측정 기준

대표 명령:

```powershell
btg-packer.exe -i corpus\o1.exe -o protected.exe `
  --vm --vm-oep --vm-commercial --m7 --m8 --integrity `
  --verify-output --seed 31010
```

- library tests: 567 passed, 0 failed.
- family runtime instances: 4.
- 최대 family instruction ownership: 37,117 / 130,685 = 28.40%.
- cross-family routes: 513.
- M7 chunks: 255 across 4 streams.
- BTGI descriptors: 12.
- differential execution: exit 0, stdout 1,460B, stderr 0B.

이 수치는 `corpus/o1.exe`, seed 31010의 측정값이며 모든 입력에 대한 보장은 아닙니다.
