# BTG Packer

BTG Packer는 Windows x86-64 PE 실행 파일을 변환하는 Rust 기반 연구용 바이너리 보호 도구입니다. 입력 PE의 제어 흐름을 재구성하고, 선택한 프로파일에 따라 코드 가상화, 암호화, 무결성 검사, import 은닉, 메모리 권한 강화와 실행 결과 검증을 적용한 새 PE를 생성합니다.

> 보안 연구용 프로토타입입니다. Windows x86-64 사용자 모드 PE만 대상으로 하며, 자신이 소유하거나 분석 권한이 있는 바이너리에만 사용하세요.

## 실제 동작

일반 경로는 PE header와 section, import, resource, relocation, exception directory를 읽고 `.text` 명령을 디코딩합니다. basic block과 CFG를 만들고 블록을 분할·섞은 뒤 RIP-relative 참조와 분기를 다시 계산합니다. 보호 계층, boot stub, dispatcher와 payload를 새 section에 배치하고 PE directory/relocation을 재구성한 다음 구조를 검증합니다. 요청하면 원본과 결과물을 실제 실행해 exit code, stdout, stderr도 바이트 단위로 비교합니다.

Program-VM 경로는 x86-64를 내부 RISC IR로 lift하고 Stack, Register, Mixed-RISC, Fused-CISC 계열로 분할합니다. 계열별 ISA, rolling key, handler table과 native threaded runtime을 만들며 CALL/JUMP/RET는 canonical route로 연결합니다. lift 또는 unwind 안전성을 증명하기 어려운 함수는 native로 유지합니다.

| 경로 | 역할 |
|---|---|
| `src/pe` | PE 파싱·생성, section/directory/relocation 처리 |
| `src/graph`, `src/core`, `src/assembler` | CFG, block slicing/shuffle, fixup과 코드 생성 |
| `src/pipeline` | protection profile을 적용하는 전체 패킹 pass와 결과 검증 |
| `src/pipeline/crypto` | boot stub, 암호 영역, 무결성, payload와 Program-VM 배치 |
| `src/vm/lifter`, `src/vm/risc` | x86-64 → RISC IR 변환과 의미 모델 |
| `src/vm/poly`, `src/vm/threaded` | 다중 ISA 인코딩과 native self-decoding dispatcher |
| `src/vm/text_lift` | 전체 프로그램 가상화 범위 분석과 예외 경계 보존 |
| `src/crypto` | BTG-C1, ChaCha20, Poly1305, SHA-256과 provider ABI |
| `src/qa`, `src/differential`, `src/multi_seed` | corpus, 실행 차등검증, seed 반복 검증 |
| `test`, `tests` | QA 대상 프로그램과 통합 테스트 |

## 적용 기술

- Rust 2021, Cargo, rustup 고정 toolchain, GitHub Actions
- `clap` derive CLI와 protection-profile resolver
- `goblin` PE/COFF 파싱
- `iced-x86` decoder, encoder, block encoder, NASM formatter
- x86-64 CFG 분석, basic-block slicing, layout shuffle, branch/RIP fixup
- x86-64 → RISC IR → polymorphic multi-family ISA
- direct-threaded/self-decoding VM, handler permutation, MBA 변환
- BTG-C1 region-context cipher, RFC 8439 ChaCha20/Poly1305, SHA-256
- rolling-key bytecode, on-demand encryption, distributed integrity
- Windows import/resource/relocation/`.pdata` 재구성과 W^X 메모리 모델
- deterministic `StdRng`, multi-seed gate, execution differential testing
- `log`/`env_logger`, `anyhow`/`thiserror`

## 빌드

Windows x86-64와 rustup/Cargo가 필요합니다. QA corpus 생성에는 MSVC Windows target과 C/C++ 빌드 도구도 필요합니다.

```powershell
cargo build --release
cargo test --all-targets
```

결과는 `target\release\btg-packer.exe`입니다.

## 사용법

```powershell
target\release\btg-packer.exe --input .\app.exe --output .\app.protected.exe
```

결정적 Program-VM 패킹과 실제 동작 검증 예시:

```powershell
target\release\btg-packer.exe `
  --input .\app.exe `
  --output .\app.protected.exe `
  --vm --vm-oep --vm-commercial `
  --m7 --m8 --integrity --iat-hide --mem-harden `
  --strict-profile --verify-output --seed 31010
```

`--full`은 native CFG 보호 묶음이며 Program-VM을 자동 선택하지 않습니다. 전체 프로그램 가상화에는 `--vm --vm-oep --vm-commercial`을 명시하세요.

## 전체 CLI

다음은 `src/cli.rs`에 정의된 모든 사용자 옵션입니다.

| 옵션 | 기본값 | 설명 |
|---|---:|---|
| `-i, --input <PATH>` | `dummy_target.exe` | 입력 Windows PE |
| `-o, --output <PATH>` | `protected_btg.exe` | 출력 PE |
| `--strict-profile` | off | 충돌에 따른 downgrade/비활성화를 오류 처리 |
| `--verify-output` | off | 원본/결과의 exit code, stdout, stderr 비교 |
| `--verify-timeout-secs <N>` | `30` | 실행 검증 제한 시간(초) |
| `--verify-seeds <N>` | `0` | N개 seed로 패킹 및 실행 검증 |
| `--seed <U64>` | random | 모든 RNG를 고정하는 결정적 build seed |
| `-l, --obf-level <N>` | `3` | 1 basic, 2 MBA, 3 overlapping+MBA |
| `-a, --anti-debug` | off | anti-debug 활성화 |
| `--anti-debug-policy <MODE>` | `trap` | `trap`, `hang`, `warn`, `poison` |
| `-t, --test-qa` | off | multi-compiler QA 실행 |
| `--qa-commercial` | off | commercial Program-VM으로 QA 및 차등검증 |
| `--qa-gen-corpus` | off | 여러 최적화 profile의 QA corpus 생성 후 종료 |
| `-d, --debug` | off | 상세 logging |
| `-g, --log-file <PATH>` | 없음 | log 파일 경로 |
| `--trace-blocks` | off | block 실행 tracer 삽입 |
| `--no-crypto` | off | 기본 암호 계층 비활성화 |
| `--vm` | off | boot crypto/선택 VM 경로 활성화 |
| `--vm-test` | off | VM self-test 후 종료 |
| `--text-vm` | off | 패킹 없이 block별 lift 가능 여부 보고 |
| `--text-vm-oep` | off | 패킹 없이 OEP 도달 CFG lift 범위 보고 |
| `--payload-relocate` | off | payload를 비실행 `.vdata`로 이동 |
| `--rsrc-register` | off | payload를 `RT_RCDATA`로 등록 |
| `--crypto-coverage <0..100>` | `100` | 코드 영역 암호화 비율 |
| `--chained-crypto` | off | chunk chaining과 복호화 후 key material 소거 |
| `--integrity` | off | boot CRC와 VM distributed integrity |
| `--iat-hide` | off | 최소 loader import 외 API를 runtime 해석 |
| `--mem-harden` | off | immutable RX와 mutable RW 영역 분리 |
| `--dispatcher-reencrypt` | off | 현재 block만 복호화하고 직전 block 재암호화 |
| `--full` | off | native CFG 최대 보호 bundle |
| `--vm-oep` | off | OEP를 Program-VM entry로 전환; `--vm` 함의 |
| `--vm-commercial` | off | RISC→poly→threaded backend 선택 |
| `--m7` | off | on-demand 암호화와 data lifetime 보호 |
| `--m8` | off | VM handler table key/MBA concealment |
| `--vm-bench` | off | interpreter/native VM benchmark 후 종료 |
| `--map` | off | `<output>.map` 명령 mapping 생성 |
| `--sym-map` | off | `<output>.sym` block/function mapping 생성 |
| `--keep-pdata` | off | dispatcher unwind leaf 없이 원본 `.pdata` 유지 |
| `--block-ring` | off | 최근 32개 logical block 진단 ring 삽입 |
| `--custom-cipher` | off | 기본 BTG-C1 경로를 명시 |
| `--rc4` | 오류 | 구형 script 감지용이며 지정하면 실패 |
| `--crypto-mode <MODE>` | `c1` | `c1` 또는 지원되는 bulk 경로의 `chacha20` |
| `-h, --help` | - | 도움말 |
| `-V, --version` | - | 버전 |

```powershell
target\release\btg-packer.exe --help
```

## 옵션 조합

- `--rsrc-register`는 `--payload-relocate`가 필요합니다.
- `--dispatcher-reencrypt`와 `--no-crypto`는 함께 쓸 수 없습니다.
- native `--dispatcher-reencrypt`는 쓰기 가능한 code page가 필요하므로 `--mem-harden`보다 우선합니다.
- `--vm-oep`는 `--vm`을 함의하며 native dispatcher 재암호화보다 우선합니다.
- selective `--vm --m7`은 지원하지 않습니다. Program-VM에서는 `--vm --vm-oep --vm-commercial --m7`을 사용합니다.
- `--m8`은 VM이 활성화된 경우에만 적용됩니다.
- `--crypto-mode chacha20`은 bulk 경로용입니다. chained/reencryption/일부 VM 조합은 resolver가 지원 경로로 조정할 수 있습니다.
- `--rc4`와 `--crypto-mode rc4`는 지원하지 않습니다.
- 조정을 허용하지 않으려면 `--strict-profile`을 사용합니다.

## 생성 파일과 테스트

기본 결과는 `--output` PE입니다. 옵션에 따라 `.btgmanifest`, `.ownership.csv`, `.btg_layout.log`, `.map`, `.sym`, `.riscmap.csv`가 생성될 수 있으며 Git에는 포함하지 않습니다.

```powershell
cargo test --lib
cargo test --all-targets
target\release\btg-packer.exe --vm-test
target\release\btg-packer.exe --vm-bench
target\release\btg-packer.exe --qa-gen-corpus
target\release\btg-packer.exe --test-qa --qa-commercial
```

## 제한 사항

- lift 불가 명령이나 SEH/TLS/panic/unwind/setjmp 경계는 native로 남을 수 있습니다.
- 자체 설계 BTG-C1은 독립적인 암호학 감사를 받은 표준 암호가 아닙니다.
- 진단 map/manifest는 보호 구조를 노출할 수 있으므로 배포물에서 제외하세요.
- 호환성과 보호 강도는 입력, compiler와 option 조합에 따라 달라집니다.

MIT License는 `LICENSE`, 취약점 제보 방법은 `SECURITY.md`를 참고하세요.
