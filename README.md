# BTG Packer

Windows x86-64 PE를 대상으로 하는 연구용 패커입니다. native CFG slicing/shuffle,
PE 재배치, boot crypto, integrity, import/memory hardening, selective SDK VM, legacy VM,
whole-program multi-family Program-VM, QA·재현·진단 산출물을 하나의 파이프라인에서
제공합니다. Commercial Program-VM은 주력 고보호 경로이지만 프로젝트 전체는 아닙니다.

> 이 저장소는 연구용 프로토타입입니다. 검증된 범위 밖의 PE, 드라이버, 다른
> 아키텍처 또는 적대적인 입력에 대한 범용 호환성을 보장하지 않습니다.

## 현재 상태

기준: `main` · 2026-08-22

| 영역 | 상태 | 실제 구현 |
|---|---|---|
| Native CFG packer | 구현됨 | CFG slicing, shuffle, RIP fixup, dispatcher와 PE section 재합성 |
| PE/platform | 구현됨 | parse/build, import/resource/reloc/`.pdata`, structural validator |
| Crypto/runtime | 구현됨 | C1/RC4/ChaCha20, boot/chained/per-block 경로, IAT/memory hardening |
| Selective SDK VM | 구현됨 | marker scan, poly VM embed, entry trampoline patch |
| Program VM | 구현됨 | x86 → RISC → family ISA → native threaded runtime |
| Multi-family | 구현됨 | Stack/Register/MixedRisc/FusedCisc 4개 독립 module/state/table/bytecode |
| Cross-family control | 구현됨 | CALL, tail-JUMP, return/resume canonical routing |
| Bytecode 보호 | 구현됨 | rolling-key stream, family별 ISA, M7 instruction-aligned chunk 암호화 |
| Handler table | 구현됨 | per-opcode key, MBA key derivation, family별 integrity traversal |
| Distributed integrity | 구현됨 | family별 code/table/bytecode 12개 BTGI descriptor와 boot verifier |
| Data lifetime | 부분 구현 | ASCII/UTF-16 및 exact-width constant pool에 owner-aware scoped 보호 연결 |
| P2-13 grammar | 완료 | family operand/compact immediate/control token 및 독립 super-op grammar production 연결 |
| P2-14 state/lazy flags | 핵심 완료 | split domains와 RSI/RDI hot lazy state, branch/native/HALT materialization 연결 |
| Release gate | 부분 완료 | library 575/575 및 P2-13 20-seed grammar gate 통과; 전체 pack gate 재실행 필요 |
| QA/diagnostics | 구현됨 | compiler corpus, differential/multi-seed, manifest, ownership와 VM maps |

완료/부분/계획의 상세 근거는 [현재 구현 상태](docs/current-status.md)를 기준으로
합니다. 오래된 journal·audit 문서의 상태 문구는 당시 시점의 기록이며 현재 상태를
대체하지 않습니다.

## 아키텍처 한눈에 보기

```text
input PE
  │
  ├─ PE parse / CFG extraction / trigger-block slicing
  ├─ layout shuffle / RIP fixup / dispatcher generation
  ├─ optional selective SDK marker VM
  ├─ optional legacy boot/program VM
  ├─ optional commercial Program-VM
  │    └─ RISC lift → 4-family partition → independent runtimes/routes
  ├─ crypto / integrity / IAT hide / memory hardening / payload relocation
  ├─ PE sections + resources + .pdata/.reloc reconstruction
  └─ structural validation + optional execution differential
output PE
  └─ manifest / ownership / maps / diagnostics
```

구성요소와 소유권, 데이터 배치, 부트 순서는
[시스템 아키텍처](docs/architecture/system-overview.md)에 정리되어 있습니다.
모든 269개 Rust 파일의 책임 지도는 [전체 소스 지도](docs/architecture/source-map.md)를
참고하세요.

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
비교합니다. 현재 기록된 기준은 library 575/575, 대표 최대 조합 exit 0,
stdout 1,460B, stderr 0B입니다. 검증 범위와 재현 명령은
[검증 기준](docs/verification.md)을 참고하세요.

## 주요 CLI

전체 42개 option과 resolver 충돌 규칙은 [CLI 전체 레퍼런스](docs/cli-reference.md)에
정리되어 있습니다. 실제 이름은 `btg-packer.exe --help`, effective 적용은
`src/protection_profile.rs`가 최종 기준입니다.

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

`--full`은 native CFG 보호 bundle이며 commercial Program-VM을 자동으로 켜지 않습니다.
Commercial 경로는 `--vm --vm-oep --vm-commercial`을 명시하세요.

옵션은 조합에 따라 effective profile이 달라질 수 있으므로 배포 검증에서는
`--strict-profile` 사용을 권장합니다.

## 알려진 한계

- P2-13 control grammar는 family별 compact direct/keyed/table-selector/continuation token과 super-op tag/descriptor-mask ABI까지 production 연결됐습니다.
- P2-14 split state, temp spill window, register-resident lazy flag와 경계 물질화가
  연결됐습니다. 공유 lifetime 객체도 전역 owner/depth/atomic lock으로 동기화되며,
  예외/unwind cleanup이 남아 있습니다.
- P2-15 native bridge oracle 감소는 미완료입니다.
- 일부 TLS, unwind, panic, setjmp/longjmp, loader-critical 함수는 안전을 위해
  native로 유지됩니다.
- at-rest 암호화와 relocation/ASLR 정책은 선택한 profile에 따라 제한됩니다.
- BTG-C1은 자체 연구용 cipher이며 독립적인 암호학 감사를 받지 않았습니다.
- 최신 변경 전체에 대한 hostile corpus/20-seed release gate는 다시 수행해야 합니다.

## 문서 읽는 순서

1. [현재 구현 상태](docs/current-status.md)
2. [시스템 아키텍처](docs/architecture/system-overview.md)
3. [전체 소스 지도](docs/architecture/source-map.md)
4. [CLI 전체 레퍼런스](docs/cli-reference.md)
5. [실제 production 파이프라인](docs/architecture/actual-pipeline.md)
6. [검증 기준](docs/verification.md)
7. [문서 인덱스](docs/README.md)
8. [현재 구현 계획](plan_vmrestore_upgraded.md)

`docs/journal/`, 날짜가 붙은 분석·audit·engine 보고서는 변경 당시의 증거와
디버깅 기록을 보존하는 역사 문서입니다.

## 보안

취약점 제보와 안전한 사용 범위는 [SECURITY.md](SECURITY.md)를 참고하세요.
