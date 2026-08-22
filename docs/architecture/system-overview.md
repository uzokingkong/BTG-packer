# 시스템 아키텍처

이 문서는 BTG Packer 전체 제품 구조를 설명합니다. Commercial Program-VM은 여러
선택 가능한 보호 backend 중 하나입니다.

## 전체 계층

```text
CLI / library API
        │
requested profile ──► resolver ──► effective profile
        │
PE parser / CFG graph / trigger-block compiler
        │
        ├─ native shuffled dispatcher path
        ├─ selective SDK marker VM path
        ├─ legacy KSA / Program-VM path
        └─ commercial RISC/poly multi-family Program-VM path
        │
crypto / integrity / IAT / memory / payload-resource layers
        │
PE builder (.textb, relayed sections, directories, .pdata, .reloc)
        │
structural validation / execution differential
        │
manifest / ownership / maps / debug / QA artifacts
```

## 제어면

`src/cli.rs`는 요청을 받지만 실제 적용 기능은 `src/protection_profile.rs`가 정합니다.
resolver는 `--full` 확장, crypto 전제, VM backend, reencrypt/mem-harden 충돌과 cipher
우선순위를 정한 뒤 `PipelineContext`에 effective 값만 전달합니다.

패킹 외에도 VM self-test, benchmark, lift diagnostics, corpus QA, multi-seed gate라는
독립 실행 모드가 있습니다. 전체 옵션은 [CLI 레퍼런스](../cli-reference.md)를 봅니다.

## 공통 native CFG compiler

모든 정상 패킹은 먼저 다음 공통 단계를 거칩니다.

1. PE headers/sections/directories/imports/relocations/`.pdata` parse;
2. x86 `.text` CFG와 basic block 추출;
3. trigger block slicing과 state-key 부여;
4. seed 기반 physical layout shuffle;
5. branch/RIP-relative fixup과 block encode;
6. dispatcher/table/boot reservation을 포함한 `.textb` 조립;
7. moved section/data/code pointer patch.

Program-VM은 이 공통 PE/CFG 패커를 대체하지 않고 crypto placement 단계에서 추가되는
backend입니다.

## 네 가지 실행 backend

### Native shuffled dispatcher

기본 경로입니다. 원본 x86 block은 shuffled trigger block으로 실행되며 standard,
dispatcher-reencrypt, native M7 중 effective profile에 맞는 dispatcher를 사용합니다.

### Selective SDK marker VM

원본 `.text`의 marker region만 polymorphic bytecode로 lift하여 별도 `.btgvm` module에
넣고 시작 위치를 trampoline으로 patch합니다. marker가 없거나 proof가 실패하면 no-op
또는 보수적 reject입니다.

### Legacy VM

`--vm`은 boot crypto KSA/PRGA를 기존 bytecode/handler VM으로 실행할 수 있습니다.
`--vm-oep`에서 commercial flag가 없으면 legacy 1:1 Program-VM backend를 유지합니다.

### Commercial multi-family Program-VM

OEP reachable 함수 중 안전하게 소유 가능한 범위를 RISC micro-op으로 lift하고,
function-stable하게 Stack/Register/MixedRisc/FusedCisc family로 나눕니다. 각 family는
독립 native code, handler table, bytecode, state, stack, ISA/grammar/key domain을 갖고
cross-family CALL/tail-JUMP/return만 canonical route를 사용합니다.

## Commercial family 내부

```text
x86 function regions
  → canonical RISC program
  → ownership/exclusion proof
  → ProductionFamilyPlan
  → family-local RiscProgram
  → family ISA + variable grammar + rolling key
  → native self-decoding runtime/handlers
  → route relocation + state allocation + unwind ranges
```

TLS, panic/unwind, setjmp/longjmp, loader-critical 또는 proof 불완전 함수는 native로
유지합니다. 대형 partition은 최소 instance 수와 최대 단일 ownership을 fail-closed로
검사합니다.

## Family bytecode와 state

family별 physical operand 순서, signed/unsigned compact immediate, compact branch marker,
control token과 super-op grammar가 다릅니다. static decoder, interpreter, native reader가
동일 family 계약을 공유합니다.

각 production family는 `0x8000` stride로 격리됩니다.

| Family-relative 범위 | 용도 |
|---|---|
| `0x0000..0x0400` | split persistent/control bank A |
| `0x0400..0x0800` | split persistent/control bank B |
| `0x0800..0x1000` | transient spill window |
| `0x1000..0x1060` | XMM backing; core state 끝 |
| `0x4000..0x5000` | entry family의 256×16B lifetime sync table |
| `0x5000..0x5018` | continuation/shared table pointer metadata |
| stride 끝쪽 | return call stack |

`0x1060` core state와 `0x8000` allocation stride는 서로 다른 크기입니다. lazy flag
snapshot/validity는 정상 handler 동안 비휘발 `RSI/RDI`에 있고 boundary에서만 canonical
flags로 materialize됩니다.

## Crypto와 integrity 합성

profile에 따라 다음 계층을 조합합니다.

- bulk at-rest cipher: C1 기본, RC4 또는 지원 범위의 ChaCha20;
- chained RC4 또는 per-block native reencrypt;
- payload `.vdata` relocation과 RT_RCDATA registration;
- import hiding/runtime resolution;
- immutable RX / mutable RW memory transition;
- boot CRC/multisite integrity;
- commercial family code/table/bytecode의 BTGI distributed integrity;
- Program-VM M7 instruction chunks와 object-level data lifetime. Lifetime은 현재 모든 참조가
  exact-width direct read이고 native call/unwind 경계를 넘지 않는 객체만 fail-closed로 활성화합니다.

Boot stub은 anti-debug, base/key setup, decrypt, integrity, IAT, memory transition과 선택된
entry transfer를 profile별로 합성합니다. 따라서 모든 빌드의 section 이름이나 boot 순서가
완전히 같다고 가정하면 안 됩니다.

## PE와 unwind

PE builder는 relayed original sections, `.textb`, optional payload/resource/selective VM
section, imports/resources/relocs/load-config와 새 entry를 합성합니다. `.pdata`는 원본
runtime functions를 보존하면서 dispatcher/VM bridge range의 unwind metadata를 추가하며
`--keep-pdata`는 이 추가를 건너뛰는 호환 진단 옵션입니다.

## 검증과 관측성

- structural validator: section/directory/bounds/entry/dispatcher/ownership/`.pdata`/VM range;
- execution differential: exit/stdout/stderr/timeout;
- QA: compiler profile corpus pack+execute;
- multi-seed: 독립 child build/execute summary;
- tamper: crypto/integrity region mutation 차단;
- support: build manifest, ownership CSV, instruction/block/RISC maps, crash diagnostics;
- analysis: section entropy, graph/coverage metrics, layout debug log.

## 안전 경계와 남은 작업

- 불완전한 function/object ownership은 native 또는 unprotected로 남깁니다.
- descriptor OOB/overlap/overflow/capacity와 profile hard error는 pack을 실패시킵니다.
- P2-11 handler recipe coverage, P2-12 anchor signature, call-scoped lifetime cleanup handler,
  P2-15 bridge oracle 감소와 최신 release matrix가 남아 있습니다.

전체 파일별 책임은 [전체 소스 지도](source-map.md), 현재 완료 판정은
[현재 구현 상태](../current-status.md)를 기준으로 합니다.
