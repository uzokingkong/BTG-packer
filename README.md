# BTG Packer

Windows x86-64 PE를 대상으로 하는 연구용 코드 가상화·난독화 패커입니다. 현재의
주력 경로는 x86 함수를 RISC micro-op으로 lift하고, 서로 다른 네 VM family로
partition한 뒤 독립 bytecode/module/state/table과 native self-decoding runtime을
생성하는 Program-VM 파이프라인입니다.

> 이 저장소는 연구용 프로토타입입니다. 검증된 범위 밖의 PE, 드라이버, 다른
> 아키텍처 또는 적대적인 입력에 대한 범용 호환성을 보장하지 않습니다.

## 현재 상태

기준: `main` · 2026-08-22

| 영역 | 상태 | 실제 구현 |
|---|---|---|
| Program VM | 구현됨 | x86 → RISC → family ISA → native threaded runtime |
| Multi-family | 구현됨 | Stack/Register/MixedRisc/FusedCisc 4개 독립 module/state/table/bytecode |
| Cross-family control | 구현됨 | CALL, tail-JUMP, return/resume canonical routing |
| Bytecode 보호 | 구현됨 | rolling-key stream, family별 ISA, M7 instruction-aligned chunk 암호화 |
| Handler table | 구현됨 | per-opcode key, MBA key derivation, family별 integrity traversal |
| Distributed integrity | 구현됨 | family별 code/table/bytecode 12개 BTGI descriptor와 boot verifier |
| Data lifetime | 부분 구현 | strict proof가 가능한 ASCII/UTF-16 literal을 사용 직전 복호화 후 재암호화 |
| P2-13 grammar | 완료 | family operand/compact immediate/control token 및 독립 super-op grammar production 연결 |
| P2-14 state/lazy flags | 부분 완료 | split GPR banks, 독립 temp spill/XMM/stack domain, lazy boundary materialization 연결 |
| Release gate | 부분 완료 | library 571/571 및 P2-13 20-seed grammar gate 통과; 전체 pack gate 재실행 필요 |

완료/부분/계획의 상세 근거는 [현재 구현 상태](docs/current-status.md)를 기준으로
합니다. 오래된 journal·audit 문서의 상태 문구는 당시 시점의 기록이며 현재 상태를
대체하지 않습니다.

## 아키텍처 한눈에 보기

```text
input PE
  │
  ├─ parse / CFG / function ownership
  ├─ native-safe exclusions (TLS, unwind, setjmp, loader-critical)
  ├─ x86 → RISC micro-op lift
  ├─ function-stable family partition
  │    ├─ Stack
  │    ├─ Register
  │    ├─ MixedRisc
  │    └─ FusedCisc
  ├─ independent polymorphic bytecode + native runtime per family
  ├─ canonical cross-family routing
  ├─ M7 / data-lifetime / BTGI integrity sealing
  ├─ boot stub + PE sections + .pdata/.reloc policy
  └─ structural validation + optional execution differential
output PE
```

구성요소와 소유권, 데이터 배치, 부트 순서는
[시스템 아키텍처](docs/architecture/system-overview.md)에 정리되어 있습니다.

## 핵심 소스 지도

| 경로 | 역할 |
|---|---|
| `src/pipeline/` | 패킹 pass, 설정 정규화, crypto placement, PE 검증 |
| `src/pipeline/crypto/place/` | Program-VM module/state/table/bytecode 실제 배치 |
| `src/pipeline/crypto/bootstub/` | 부트 복호화, integrity, runtime 진입 코드 |
| `src/vm/text_lift/` | PE 함수/CFG lift와 native 제외 판정 |
| `src/vm/risc/` | canonical micro-op IR, lifter, 의미 참조 모델 |
| `src/vm/poly/` | family ISA, rolling key, encoder/decoder/interpreter |
| `src/vm/threaded/poly_direct/` | production native self-decoding runtime과 handlers |
| `src/vm/multi_family.rs` | family partition materialization과 route records |
| `src/vm/distributed_integrity.rs` | BTGI descriptor sealing/serialization ABI |
| `src/vm/data_lifetime.rs` | lifetime object proof와 toggle metadata |
| `src/vm/bytecode/`, `handlers/`, `interp/` | 레거시 1:1 VM 경로 |

## 빌드와 검증

```powershell
cargo build --release
cargo test --lib
```

대표 production 검증:

```powershell
target\release\btg-packer.exe `
  -i corpus\o1.exe `
  -o protected.exe `
  --vm --vm-oep --vm-commercial `
  --m7 --m8 --integrity `
  --verify-output --seed 31010
```

`--verify-output`은 원본과 보호본의 exit code/stdout/stderr를 byte 단위로
비교합니다. 현재 기록된 기준은 library 571/571, 대표 최대 조합 exit 0,
stdout 1,460B, stderr 0B입니다. 검증 범위와 재현 명령은
[검증 기준](docs/verification.md)을 참고하세요.

## 주요 CLI

정확한 전체 목록은 항상 `btg-packer.exe --help`와 `src/cli.rs`가 기준입니다.

| 옵션 | 의미 |
|---|---|
| `--strict-profile` | 요청 기능의 silent downgrade를 오류로 처리 |
| `--verify-output` | 원본/보호본 실행 차등검증 |
| `--verify-seeds N` | N개 seed pack+execution gate |
| `--seed N` | 결정적 빌드 seed |
| `--vm --vm-oep --vm-commercial` | multi-family commercial Program-VM 경로 |
| `--m7` | instruction-aligned bytecode chunk 보호 및 lifetime 보호 |
| `--m8` | handler table MBA/per-opcode concealment |
| `--integrity` | boot multisite + distributed VM integrity |
| `--iat-hide` | runtime import resolution |
| `--mem-harden` | runtime memory-protection 전환 |
| `--anti-debug` | 부트 안티디버그 검사 |
| `--map --sym-map` | VM/source 진단 매핑 생성 |
| `--crypto-mode` | `rc4`, `c1`, `chacha20` 선택 |

옵션은 조합에 따라 effective profile이 달라질 수 있으므로 배포 검증에서는
`--strict-profile` 사용을 권장합니다.

## 알려진 한계

- P2-13 control grammar는 family별 compact direct/keyed/table-selector/continuation token과 super-op tag/descriptor-mask ABI까지 production 연결됐습니다.
- P2-14 split state와 lazy flag 경계 물질화는 연결됐고 register-resident/stack-window
  확대 및 공유 lifetime 객체 동시성은 남아 있습니다.
- P2-15 native bridge oracle 감소는 미완료입니다.
- 일부 TLS, unwind, panic, setjmp/longjmp, loader-critical 함수는 안전을 위해
  native로 유지됩니다.
- at-rest 암호화와 relocation/ASLR 정책은 선택한 profile에 따라 제한됩니다.
- BTG-C1은 자체 연구용 cipher이며 독립적인 암호학 감사를 받지 않았습니다.
- 최신 변경 전체에 대한 hostile corpus/20-seed release gate는 다시 수행해야 합니다.

## 문서 읽는 순서

1. [현재 구현 상태](docs/current-status.md)
2. [시스템 아키텍처](docs/architecture/system-overview.md)
3. [실제 production 파이프라인](docs/architecture/actual-pipeline.md)
4. [검증 기준](docs/verification.md)
5. [문서 인덱스](docs/README.md)
6. [개선 계획](plan_vmrestore_upgraded.md)

`docs/journal/`, 날짜가 붙은 분석·audit·engine 보고서는 변경 당시의 증거와
디버깅 기록을 보존하는 역사 문서입니다.

## 보안

취약점 제보와 안전한 사용 범위는 [SECURITY.md](SECURITY.md)를 참고하세요.
