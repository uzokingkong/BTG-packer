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
- compact branch marker가 family ABI의 `0x10..0x13` domain을 벗어나면 static
  decoder는 오류를 반환하고 production native handler는 `UD2`로 fail-closed합니다.
- branch payload는 Stack direct index, Register keyed selector, MixedRisc
  complemented table selector, FusedCisc continuation token으로 family별 변환됩니다.
- fused super-op은 build/opcode-local tag와 descriptor mask를 갖는 독립 grammar를
  사용합니다. native extension entry는 tag 불일치 시 operand fetch 전에 `UD2`로
  종료하고 dispatch는 transient mask를 매 opcode마다 초기화합니다.
- M7은 각 family stream을 instruction boundary에 맞춘 독립 chunk로 보호합니다.

### Handler runtime hardening

- handler table entry는 opcode별 파생 키로 conceal합니다.
- master material은 runtime MBA identity로 조합합니다.
- 미등록 opcode는 trap handler로 연결합니다.
- family마다 forward/reverse와 single/pair가 조합된 서로 다른 table integrity
  traversal을 사용합니다.
- 일부 MOV/NOT/NOR handler는 seed/opcode에 따라 실제 의미 동치 body recipe가
  달라집니다.

### Split state ABI (P2-14)

- production `VmRuntimeLayout::from_seed`는 GPR을 `+0x000` 및 `+0x400` 두 bank에
  분산하고 transient temp는 독립 `+0x800` spill window에서 별도 순열합니다.
  flags/decode scratch와 XMM window도 서로 다른 범위에 둡니다.
- operand-offset metadata는 `256 × u16 little-endian`이며 native resolver/store와
  compact reader가 2배 index scale의 16-bit load를 사용합니다.
- state allocation은 layout 전체 `0x1060`을 예약하고 virtual stack은 그 뒤에서
  시작하므로 GPR banks, temp spill window 및 `0x1000` XMM window와 겹치지 않습니다.
- cross-family router는 source/target의 독립 layout offset으로 GPR/flags/VSP/XMM을
  변환하며 production validator가 모든 register descriptor의 정렬과 범위를 검사합니다.
- 일반 산술/논리 producer는 status snapshot과 validity를 비휘발 `RSI/RDI`에 보관합니다.
  memory layout에는 lazy snapshot/token slot이 없습니다. 다음 producer는 분기 없는
  `CMOVNE`로 register snapshot의 비상태 비트를 계승하며,
  condition 평가, VM→native bridge, HALT에서 canonical flags로 materialize합니다.
- canonical FLAGS를 직접 쓰는 specialized producer는 `RDI`를 중앙에서 즉시
  무효화합니다. module entry는 clean 상태로 초기화되고 native/condition/HALT 경계만
  canonical memory flags를 관찰합니다.

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
- entry-family state의 `+0x4000..+0x5000`에는 RVA 정렬된 16-byte
  `(atomic lock u32, depth u32, owner thread-id u64)` 항목 최대 256개를 위한 전역 sync table을 둡니다.
  모든 family가 같은 절대 VA를 사용하도록 table ownership은 entry state에만 있으며,
  validator가 `+0x5000` continuation metadata와 `+0x6000` call stack 충돌을 차단합니다.
- lifetime scope 앞뒤에는 canonical `LifetimeAcquire/LifetimeRelease` op를 삽입합니다.
  모든 family handler는 state `+0x5010`의 공통 table pointer를 읽고 acquire에서
  `lock cmpxchg` spin을 수행합니다. 같은 `GS:[0x48]` thread owner의 중첩 acquire는
  atomic depth만 증가시키고 release는 owner/depth를 검증해 마지막 scope에서만 owner와
  lock을 해제합니다. 잘못된 owner/underflow는 trap으로 fail-closed하며 virtual GPR/FLAGS를 보존합니다.

## 부분 구현

| 항목 | 완료된 범위 | 남은 범위 |
|---|---|---|
| P2-11 handler synthesis | full ISA target wrapper, 일부 실제 body recipe | execution-weight 80%에 3개 이상 body recipe |
| P2-12 anchor 분산 | 4 instance, 4 integrity topology, ownership gate | RIP-relative runtime bundle materialization, N=20 signature gate |
| P2-13 grammar | family operand/compact immediate/control token, super-op tag+descriptor-mask ABI | 완료 |
| P2-14 state/lazy flags | u16 metadata, split GPR banks, temp spill/XMM/stack 분리, RSI/RDI lazy hot state, cross-family/native materialization | shared lifetime 동시성 및 추가 hot-state 후보 |
| Data lifetime | strict ASCII/UTF-16 scope, global relocation, owner-aware atomic 재진입/depth | wider format/direct-memory 및 unwind cleanup cases |
| Release gate | 574 library tests, P2-13 20-seed grammar gate, 대표 production/tamper | 최신 전체 hostile corpus와 20-seed pack+execute 재실행 |

## 미구현 또는 다음 단계

- shared lifetime scope의 exception/unwind cleanup과 wider object proof.
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

- library tests: 568 passed, 0 failed.
- P2-13 uninformed grammar normalization: 20 seeds × 4 families, 허용률 ≤10% 통과.
- family runtime instances: 4.
- 최대 family instruction ownership: 37,117 / 130,685 = 28.40%.
- cross-family routes: 513.
- M7 chunks: 255 across 4 streams.
- BTGI descriptors: 12.
- differential execution: exit 0, stdout 1,460B, stderr 0B.

이 수치는 `corpus/o1.exe`, seed 31010의 측정값이며 모든 입력에 대한 보장은 아닙니다.
