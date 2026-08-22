# 현재 구현 상태

이 문서는 BTG Packer의 현재 `main` 상태를 분류하는 기준 문서입니다. 날짜가 붙은
분석, journal, audit 보고서는 역사 기록이며 이 문서보다 우선하지 않습니다.

기준일: 2026-08-22

요약 진척도는 기능 구현 약 82%, 전체 release 완료도 약 75%입니다. 이 백분율은
아래 완료 기준을 묶은 계획 추정치이며 테스트 커버리지 비율을 뜻하지 않습니다.

## 구현 완료

### Native CFG/PE packer 기반

- PE parse, CFG extraction, trigger-block slicing, layout shuffle, RIP/branch fixup,
  dispatcher/table emission과 moved section/data patch를 production pipeline에 연결했습니다.
- standard dispatcher와 native per-block reencrypt/M7 variant, anti-debug policy,
  payload relocation/resource registration, IAT runtime resolution과 memory hardening을
  effective profile에 따라 합성합니다.
- PE builder는 relayed section, entry, imports/resources/relocs/load-config/`.pdata`를
  재구성하고 output을 다시 parse하는 structural validator를 실행합니다.

### Crypto와 integrity 기반

- 기본 C1, legacy RC4, 지원되는 bulk 경로의 ChaCha20과 Poly1305/AEAD helper/native
  emitter가 있습니다.
- boot bulk/chained/per-block crypto, CRC/multisite checks, seed/state zeroization과
  Program-VM BTGI distributed integrity가 각각 profile별 경로에 연결됩니다.
- `protection_profile` resolver가 cipher 우선순위, crypto 전제, reencrypt/mem-harden
  충돌과 strict-profile 오류 승격을 단일 정책으로 관리합니다.

### Selective VM, QA와 진단

- SDK marker scan → region lift → polymorphic VM section embed → marker trampoline patch의
  selective VM 경로가 있습니다.
- multi-compiler corpus 생성/QA, byte-exact execution differential, multi-seed child gate,
  실패 artifact 격리와 구조/tamper 검증 계층을 제공합니다.
- `.btgmanifest`, ownership CSV, instruction/block/RISC maps, crash diagnostic와 entropy/
  layout report를 생성할 수 있습니다.

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

production family 하나는 `0x8000` stride를 소유합니다. 그 안에서 core split state는
`0x0000..0x1060`, lifetime sync table은 entry family의 `0x4000..0x5000`, cross-family
continuation/sync pointer metadata는 `0x5000..0x5018`, return call stack은 stride 끝쪽에
배치됩니다. core state 크기와 family allocation stride는 서로 다른 개념입니다.

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
- 문자열 외에는 register destination의 순수 MOV 계열 RIP-relative 4/8/16-byte read만
  `ConstantPool`로 추가합니다. RMW/XCHG/memory destination과 폭이 모호한 접근은 제외하고,
  해당 단일 instruction 앞뒤에서 동일 owner-aware scope로 toggle합니다.
- entry-family state의 `+0x2000..+0x5000`에는 RVA 정렬된 48-byte
  `(atomic lock, depth, owner, object VA, length/RVA, object key)` cleanup descriptor
  최대 256개를 위한 전역 sync table을 둡니다.
  모든 family가 같은 절대 VA를 사용하도록 table ownership은 entry state에만 있으며,
  validator가 `+0x5000` continuation metadata와 `+0x6000` call stack 충돌을 차단합니다.
- lifetime scope 앞뒤에는 canonical `LifetimeAcquire/LifetimeRelease` op를 삽입합니다.
  모든 family handler는 state `+0x5020`의 공통 table pointer와 `+0x5028` count를 읽고 acquire에서
  `lock cmpxchg` spin을 수행합니다. 같은 `GS:[0x48]` thread owner의 중첩 acquire는
  atomic depth만 증가시키고 release는 owner/depth를 검증해 마지막 scope에서만 owner와
  lock을 해제합니다. 잘못된 owner/underflow는 trap으로 fail-closed하며 virtual GPR/FLAGS를 보존합니다.
- native-call bridge의 UHANDLER는 phase-2 unwind에서 `GS:[0x48]` owner가 일치하는
  활성 descriptor만 순회해 객체를 재암호화하고 sync word를 0으로 복구합니다.

## 부분 구현

| 항목 | 완료된 범위 | 남은 범위 |
|---|---|---|
| P2-11 handler synthesis | full ISA target wrapper, MOV/NOR/NOT·shift·load/store·width integer 실제 body recipe, 대표 10-op N=20 body-shape gate | execution profile 계측으로 80% 기준 확정, SSE/control 확대 |
| P2-12 anchor 분산 | 4 instance, 4 integrity topology, RIP-relative seed-permuted runtime bundle, absolute-anchor regression, N=20 signature ≤10% gate | ASLR/CFG/CET 재검증 |
| P2-13 grammar | family operand/compact immediate/control token, super-op tag+descriptor-mask ABI | 완료; 추가 grammar는 선택적 hardening |
| P2-14 state/lazy flags | u16 metadata, split GPR banks, temp spill/XMM/stack 분리, RSI/RDI lazy hot state, cross-family/native materialization | 완료된 bridge private-frame zeroization 이후 live-set 축소는 P2-15에서 진행 |
| Data lifetime | exact 4/8/16B direct read와 LEA→call scope, global owner-aware sync, bridge UHANDLER cleanup | wider format와 복합 table/memory proof |
| Release gate | 581 library tests, P2-13 grammar/P2-12 anchor/P2-11 actual-body 20-seed gate, 대표 production/tamper | 최신 전체 hostile corpus와 20-seed pack+execute 재실행 |
| Library API | 기본 CFG+crypto in-memory `pack/run_full` | CLI effective profile 전체를 노출하는 typed API |
| Platform/PE matrix | 대표 Windows x64 PE, `.pdata`/reloc/IAT/resource 구조 검증 | 전체 ASLR/CFG/CET/TLS/compiler matrix 최신 재실행 |

## 미구현 또는 다음 단계

- data-lifetime wider object/table reference proof와 실제 exception corpus 확대.
- P2-15 native bridge live-in/live-out 계산, mask 소비, instance별 frame layout.
- 최신 전체 hostile corpus/20-seed release gate.
- CLI와 동등한 full-profile library API 및 capability introspection.

## 현재 측정 기준

대표 명령:

```powershell
btg-packer.exe -i corpus\o1.exe -o protected.exe `
  --vm --vm-oep --vm-commercial --m7 --m8 --integrity `
  --verify-output --seed 31010
```

- library tests: 578 passed, 0 failed.
- P2-13 uninformed grammar normalization: 20 seeds × 4 families, 허용률 ≤10% 통과.
- family runtime instances: 4.
- 최대 family instruction ownership: 37,117 / 130,685 = 28.40%.
- cross-family routes: 513.
- M7 chunks: 대표 측정 254~255 across 4 streams (빌드 시점의 lift 결과에 따라 변동).
- BTGI descriptors: 12.
- cleanup-backed lifetime final protected objects: 54 (182 candidate / 116 strict-scope,
  최종 all-reference proof에서 미증명 cross-boundary 객체 54개 제외).
- native bridge lifetime cleanup: 4 UHANDLER records → cleanup RVA `0xAFB03`.
- differential execution: exit 0, stdout 1,460B, stderr 0B.

이 수치는 `corpus/o1.exe`, seed 31010의 측정값이며 모든 입력에 대한 보장은 아닙니다.
