# BTG Packer

**Windows x86-64 PE Transformation, Program Virtualization & Runtime Hardening Framework — written in Rust**

[🇺🇸 English](README.md) | [🇰🇷 한국어](README.ko.md)

Ouroboros는 Windows PE32+ 실행 파일을 대상으로 **제어 흐름 재구성, 프로그램 가상화, 코드 암호화, import 은닉, 무결성 검사, 메모리 권한 강화, PE 재구성 및 실행 차등 검증**을 수행하는 연구용 바이너리 보호 프레임워크입니다.

단순히 원본 코드를 암호화한 뒤 시작 시 복호화하는 형태의 packer가 아니라, 입력 프로그램을 분석해 CFG와 함수 ownership을 구성하고 선택한 protection profile에 따라 **native transformation pipeline** 또는 **x86-64 → RISC IR → polymorphic Program-VM pipeline**으로 변환합니다.

> **Research prototype.**
> Windows x86-64 user-mode PE를 대상으로 하며, 자신이 소유하거나 분석 권한이 있는 바이너리에만 사용하세요.

---

## Highlights

### PE Transformation Engine

* PE32+ header / section / directory 분석
* x86-64 instruction decoding with `iced-x86`
* basic-block CFG extraction
* control-flow target validation
* block slicing and layout shuffling
* RIP-relative reference reconstruction
* direct branch fixup
* relocation reconstruction
* import/resource/exception metadata 처리
* `.pdata` / unwind metadata 보존 및 재구성
* TLS / load-config / code-pointer 분석 지원
* 출력 PE 재파싱 및 구조 검증

### Whole-Program Virtualization

* x86-64 → internal RISC micro-IR lifter
* function-level VM ownership analysis
* unsupported instruction evidence tracking
* SEH / panic / setjmp / longjmp boundary policy
* native / VM function separation
* function-scoped VM family assignment
* cross-family canonical routing
* native-call and VM-call bridge
* polymorphic build-local virtual ISA
* native self-decoding threaded runtime

### Runtime Protection

* BTG-C1 custom stream-cipher path
* ChaCha20 / Poly1305 authenticated bulk protection path
* rolling-key VM bytecode encoding
* build-local opcode permutation
* virtual-register permutation
* branch-condition encoding
* operand encoding / masking
* VM handler synthesis
* super-operator fusion
* distributed integrity descriptors
* M7 runtime bytecode/block lifecycle protection
* M8 handler-table concealment
* runtime IAT reconstruction
* W^X-oriented memory hardening
* payload relocation into non-executable storage
* `RT_RCDATA` payload registration
* anti-debug policies

### Verification & Reproducibility

* deterministic `--seed` builds
* post-build PE structural validation
* requested-vs-effective protection validation
* whole-program VM coverage gate
* original/protected execution differential testing
* multi-seed build + execution gate
* SHA-256 build manifest
* VM ownership reports
* bytecode/source mapping
* symbolic function/block mapping

---

# Architecture

```text
                         Input PE32+
                             │
                             ▼
                    ┌─────────────────┐
                    │   PE Analyzer   │
                    │ sections / dirs │
                    │ imports / TLS   │
                    │ pdata / reloc   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Program Model   │
                    │ CFG + functions │
                    │ code pointers   │
                    │ switch targets  │
                    └────────┬────────┘
                             │
                 ┌───────────┴────────────┐
                 │                        │
                 ▼                        ▼
        Native CFG Pipeline        Program-VM Pipeline
                 │                        │
          block slicing             x86-64 decode
                 │                        │
          layout shuffle                  ▼
                 │                   RISC Lifter
          RIP/branch fixup                │
                 │                        ▼
            MBA transform          Ownership Analysis
                 │                        │
                 │                VM / Native decision
                 │                        │
                 │                        ▼
                 │                Multi-Family Plan
                 │                        │
                 │                        ▼
                 │                Polymorphic ISA
                 │                        │
                 │                        ▼
                 │                Rolling-Key Encode
                 │                        │
                 │                        ▼
                 │              Native Threaded Runtime
                 │                        │
                 └────────────┬───────────┘
                              │
                              ▼
                    Runtime Protection
                              │
                ┌─────────────┼─────────────┐
                │             │             │
             Crypto       Integrity     IAT / Memory
                │             │             │
                └─────────────┼─────────────┘
                              │
                              ▼
                       PE Reconstruction
                              │
                              ▼
                      Structural Validation
                              │
                              ▼
                     Effective-Profile Gate
                              │
                              ▼
                    Execution Differential
                              │
                              ▼
                        Protected PE
```

---

# Program-VM

`--vm --vm-oep --vm-commercial`은 BTG의 whole-program virtualization 경로를 활성화합니다.

```text
x86-64 machine code
        │
        ▼
   CFG / function model
        │
        ▼
   Commercial RISC Lifter
        │
        ▼
      RISC IR
        │
        ▼
 Function Ownership Gate
        │
        ├── unsupported / unsafe ──► Native
        │
        ▼
 Multi-Family Partition
        │
        ▼
 Polymorphic Virtual ISA
        │
        ▼
 Rolling-Key Bytecode
        │
        ▼
 Self-Decoding Native Runtime
        │
        ▼
 VM / Native Bridge
```

## RISC Intermediate Representation

Program-VM은 원본 x86 instruction을 그대로 `VM_MOV`, `VM_ADD` 같은 1:1 opcode로 복사하는 구조가 아닙니다.

먼저 x86-64 instruction semantics를 내부 RISC micro-operation으로 변환합니다.

지원 IR에는 산술/논리뿐 아니라 다음 계열이 포함됩니다.

```text
Arithmetic / Carry / Borrow
Shift / Rotate
Memory Read / Write
Virtual Stack
Virtual Branch / Return
Conditional Move / Setcc
Multiply / Divide
Atomic Operations
Bit Operations
Packed SIMD Operations
Native / VM Bridge Operations
```

이 중 현재 polymorphic backend가 안전하게 실행할 수 있는 operation만 Program-VM ownership을 받을 수 있습니다.

---

# Function Ownership & Coverage

Program-VM은 lift 실패를 무시하고 잘못된 bytecode를 생성하지 않습니다.

함수에 안전성을 증명하기 어려운 instruction이나 runtime boundary가 존재하면 해당 함수는 native ownership으로 분류할 수 있습니다.

대표적인 exclusion reason은 다음과 같습니다.

```text
seh-or-panic-policy
setjmp-longjmp-policy
legacy-high-byte-register
semantic-dependency-closure
integration-quarantine
ambiguous-function-boundary
unsupported-instruction
unsupported-vm-opcode
analysis-failure
```

`--vm-commercial` production build는 기본적으로 **전체 VM coverage를 검증**합니다.

VM bytecode가 존재하더라도:

* 원본 executable `.text`가 여전히 실행 가능하거나
* 함수/block/instruction VM coverage가 완전하지 않으면

기본 production gate에서 실패합니다.

개발 목적으로만 부분 virtualization을 허용하려면:

```powershell
--allow-partial-vm
```

을 명시해야 합니다.

`--allow-partial-vm`과 `--strict-profile`은 동시에 사용할 수 없습니다.

---

# Multi-Family VM

Program-VM에는 다음 architecture family domain이 구현되어 있습니다.

```text
Stack
Register
MixedRisc
FusedCisc
```

함수는 build seed와 안정적인 function identifier를 기반으로 family에 결정적으로 할당됩니다.

각 family는 별도의 ISA domain을 사용하며 build 과정에서 family-scoped opcode/operand encoding이 생성됩니다.

```text
Function A ──► Stack family
Function B ──► MixedRisc family
Function C ──► Register family
Function D ──► FusedCisc family
```

family가 다른 함수 사이의 제어 이동은 canonical VM state를 사용하는 cross-family bridge를 통해 연결됩니다.

```text
VM Family A
    │
    │ canonical registers / flags
    ▼
Cross-VM Bridge
    │
    ▼
VM Family B
```

---

# Per-Build Polymorphic ISA

Program-VM의 bytecode format은 하나의 고정 opcode table만 사용하는 구조가 아닙니다.

build seed에서 다음 값들이 파생됩니다.

```text
opcode mapping
register permutation
branch-condition mapping
operand mask
family ISA domain
rolling-key state
handler synthesis decisions
```

따라서 서로 다른 seed를 사용한 build는 동일한 원본 프로그램에서도 다른 virtual encoding을 생성할 수 있습니다.

```powershell
btg-packer.exe ... --seed 31010
```

동일한 input + 동일한 configuration + 동일한 seed는 재현 가능한 build를 목표로 합니다.

---

# Rolling-Key Self-Decoding VM

Program-VM bytecode는 build-local rolling key를 사용합니다.

각 byte의 decode state가 stream position과 이전 state에 종속되므로 VM runtime은 현재 virtual instruction 위치와 key state를 함께 유지합니다.

native runtime은 bytecode를 decode한 뒤 virtual opcode에 대응하는 handler로 제어를 전달합니다.

branch가 발생하면 branch map을 통해 대상 bytecode offset을 계산하고 rolling-key state를 해당 위치에 맞게 재동기화합니다.

---

# Super-Operator Fusion

반복되는 RISC sequence 중 production allow-list에 포함된 패턴은 build-local super-operation으로 fusion될 수 있습니다.

예:

```text
primitive A
primitive B
primitive C

        ↓

build-local fused handler
```

이를 통해 일부 연산 sequence에서 VM dispatch boundary 자체를 줄일 수 있습니다.

control-flow target이나 bridge boundary를 가로지르는 fusion은 허용하지 않습니다.

---

# Protection Layers

| Feature                  | Implementation                                                                |
| ------------------------ | ----------------------------------------------------------------------------- |
| `--integrity`            | boot/runtime integrity checks 및 Program-VM protected-region descriptors       |
| `--iat-hide`             | loader-visible import를 최소 resolver set으로 줄이고 나머지 API를 runtime에 복원             |
| `--mem-harden`           | immutable code/table과 mutable VM state의 권한 분리 및 runtime protection transition |
| `--payload-relocate`     | protected payload를 non-executable `.vdata` storage로 이동                        |
| `--rsrc-register`        | relocated payload를 `RT_RCDATA` resource로 등록                                   |
| `--m7`                   | native 또는 commercial Program-VM의 runtime re-encryption/chunk lifecycle 보호     |
| `--m8`                   | VM handler table address concealment                                          |
| `--anti-debug`           | runtime debugger checks + selectable failure policy                           |
| `--dispatcher-reencrypt` | native CFG block 단위 runtime decrypt/re-encrypt                                |
| `--crypto-coverage`      | bulk encryption 적용 범위 제어                                                      |

---

# Cryptography

BTG에는 두 production crypto path가 존재합니다.

## ChaCha20 / Poly1305

bulk at-rest encryption 경로에서는 RFC 8439 기반 ChaCha20과 Poly1305 verification logic이 구현되어 있습니다.

```powershell
--crypto-mode chacha20
```

현재 protection-profile resolver의 기본 crypto mode는 `chacha20`입니다.

단, VM / VM-OEP / runtime re-encryption 계열은 현재 별도의 C1 runtime path를 사용합니다.

## BTG-C1

```powershell
--crypto-mode c1
```

BTG-C1은 프로젝트 내부에서 설계한 custom 512-bit-state stream cipher입니다.

reference implementation, native runtime implementation 및 protection pipeline 연결이 존재하지만 **독립적인 암호학적 감사를 받은 표준 암호가 아닙니다.**

따라서 BTG-C1은 cryptographic standard가 아니라 binary-protection research primitive로 취급해야 합니다.

RC4 production mode는 제거되었습니다.

```text
--rc4             → explicit error
--crypto-mode rc4 → invalid CLI value
```

---

# IAT Hiding

`--iat-hide`는 원본 import metadata를 그대로 노출하는 대신 runtime API resolution을 사용합니다.

출력 PE의 loader-visible import는 최소 resolver API로 축소되고, boot runtime이 원본 import table 정보를 이용해 필요한 API 주소를 다시 채웁니다.

```text
PE Loader
   │
   ▼
LoadLibraryA / GetProcAddress
   │
   ▼
BTG Runtime Resolver
   │
   ▼
Original IAT Slots
```

DLL/function name metadata는 runtime resolve table에 별도로 저장됩니다.

---

# Memory Hardening

`--mem-harden`은 bootstrap 이후 immutable executable region과 mutable runtime state의 권한을 분리합니다.

목표 runtime contract는 다음과 같습니다.

```text
bootstrap/decrypt
      │
      ▼
integrity verification
      │
      ▼
immutable executable data ──► RX
mutable VM state          ──► RW
```

runtime protection transition 실패는 fail-closed 처리됩니다.

`--dispatcher-reencrypt`는 native code page에 계속 쓰기 권한이 필요하므로 `--mem-harden`보다 우선합니다.

---

# Payload Relocation & Resource Registration

```powershell
--payload-relocate --rsrc-register
```

를 사용하면 protected payload를 executable section에서 분리해 non-executable `.vdata` 영역으로 이동하고 resource directory에 `RT_RCDATA`로 등록할 수 있습니다.

기존 icon/version/manifest 등의 resource tree를 보존하면서 BTG payload resource를 추가하는 경로가 구현되어 있습니다.

`--rsrc-register`는 반드시 `--payload-relocate`와 함께 사용해야 합니다.

---

# Integrity

`--integrity`는 단일 checksum 하나만 사용하는 구조가 아닙니다.

boot pipeline에는 여러 integrity verification site가 존재하며 Program-VM 경로에서는 별도의 protected-region descriptor를 생성할 수 있습니다.

보호 대상 종류에는 다음과 같은 domain이 정의되어 있습니다.

```text
FileImage
MappedImage
VmBytecode
HandlerCode
HandlerTable
NativeBridge
ResolvedApiPointers
```

---

# Anti-Debug Policies

```powershell
--anti-debug
--anti-debug-policy <MODE>
```

지원 policy:

| Mode     | Behavior                |
| -------- | ----------------------- |
| `trap`   | 탐지 시 trap               |
| `hang`   | 탐지 시 execution stall    |
| `warn`   | 탐지 후 정상 경로 진행           |
| `poison` | runtime state를 오염시키는 경로 |

기본 policy는 `trap`입니다.

---

# Build Validation

BTG는 PE를 생성하고 끝내지 않습니다.

생성된 PE를 다시 파싱하여 section range, directory, relocation, VM metadata 및 요청한 protection capability가 실제 결과물에 materialize됐는지 검사합니다.

```text
Build
  │
  ▼
Output PE
  │
  ▼
Re-parse
  │
  ├─ structural validation
  ├─ PE directory validation
  ├─ relocation validation
  ├─ VM metadata validation
  └─ effective protection validation
```

`--strict-profile`을 사용하면 요청한 protection이 충돌 때문에 비활성화되거나 build 결과에서 유효하지 않은 경우 오류로 처리합니다.

---

# Execution Differential Verification

```powershell
--verify-output
```

은 원본과 보호된 실행 파일을 실제로 실행하고 다음 결과를 비교합니다.

```text
exit code
stdout bytes
stderr bytes
```

세 항목 중 하나라도 다르면 verification이 실패합니다.

실패한 결과물은 정상 output 이름으로 남기지 않고 별도의 failed artifact로 격리합니다.

timeout은 다음 옵션으로 조절할 수 있습니다.

```powershell
--verify-timeout-secs 30
```

---

# Multi-Seed Gate

```powershell
--verify-seeds N
```

은 서로 다른 build seed로 N개의 independent packing job을 실행합니다.

각 build는 자동으로 execution differential verification을 수행하며 하나라도 실패하면 전체 gate가 실패합니다.

각 결과물의 SHA-256과 seed는 별도 report에 기록됩니다.

---

# Diagnostic Artifacts

build configuration에 따라 다음 artifact를 생성합니다.

```text
<output>.btgmanifest
<output>.ownership.csv
<output>.map
<output>.sym
<output>.riscmap.csv
unsupported-instruction evidence
multi-seed verification report
```

### `.btgmanifest`

다음과 같은 build evidence를 기록합니다.

```text
input/output SHA-256
build seed
feature flags
effective crypto primitive
VM ownership metrics
VM bytecode information
runtime cipher hash
integrity state
ASLR state
W^X contract
execution verification result
```

### `.map`

VM bytecode offset과 원본 instruction VA를 연결합니다.

### `.sym`

VM block 범위와 원본 block/function ownership을 연결합니다.

### `.ownership.csv`

원본 함수가 VM/native 중 어느 쪽에 귀속되었는지와 exclusion reason을 기록합니다.

---

# Build

Windows x86-64와 Rust/Cargo toolchain이 필요합니다.

```powershell
cargo build --release
cargo test --all-targets
```

결과:

```text
target\release\btg-packer.exe
```

---

# Basic Usage

```powershell
target\release\btg-packer.exe `
    --input .\app.exe `
    --output .\app.protected.exe
```

---

# Recommended Program-VM Profile

```powershell
target\release\btg-packer.exe `
  --input .\app.exe `
  --output .\app.protected.exe `
  --vm `
  --vm-oep `
  --vm-commercial `
  --m7 `
  --m8 `
  --mem-harden `
  --iat-hide `
  --integrity `
  --payload-relocate `
  --rsrc-register `
  --crypto-mode c1 `
  --crypto-coverage 100 `
  --obf-level 3 `
  --anti-debug `
  --strict-profile `
  --verify-output `
  --seed 31010
```

이 profile은 다음 protection들을 동시에 요청합니다.

```text
whole-program Program-VM
RISC lifting
multi-family VM partitioning
polymorphic ISA generation
rolling-key bytecode
M7 runtime protection
M8 handler-table concealment
IAT hiding
integrity verification
W^X memory hardening
payload relocation
resource registration
BTG-C1 runtime crypto
anti-debugging
strict capability validation
execution differential verification
deterministic build
```

---

# `--full`

`--full`은 **native CFG protection bundle**입니다.

Program-VM을 자동으로 활성화하지 않습니다.

```text
--full
    ├─ obf-level 3
    ├─ anti-debug
    ├─ dispatcher-reencrypt
    ├─ integrity
    ├─ payload-relocate
    ├─ rsrc-register
    ├─ iat-hide
    └─ mem-harden request
```

단, native `dispatcher-reencrypt`는 runtime code write가 필요하기 때문에 `mem-harden`의 RX transition과 충돌합니다.

resolver는 dispatcher re-encryption을 우선하며 이와 같은 profile adjustment를 허용하지 않으려면 `--strict-profile`을 사용하세요.

전체 프로그램 virtualization을 원한다면 명시적으로:

```powershell
--vm --vm-oep --vm-commercial
```

을 사용해야 합니다.

---

# Important CLI

| Option                   | Description                                      |
| ------------------------ | ------------------------------------------------ |
| `--strict-profile`       | protection downgrade/비활성화를 오류 처리                 |
| `--allow-partial-vm`     | 개발용 partial commercial VM coverage 허용            |
| `--verify-output`        | 원본/보호본 실행 결과 byte-for-byte 비교                    |
| `--verify-seeds N`       | 여러 seed의 pack + execution gate                   |
| `--seed U64`             | deterministic build                              |
| `--vm`                   | VM/crypto infrastructure 활성화                     |
| `--vm-oep`               | OEP를 Program-VM entry로 전환                        |
| `--vm-commercial`        | RISC/poly/threaded Program-VM backend            |
| `--m7`                   | runtime re-encryption/chunk lifecycle protection |
| `--m8`                   | VM handler table concealment                     |
| `--integrity`            | runtime integrity protection                     |
| `--iat-hide`             | runtime import resolution                        |
| `--mem-harden`           | executable/state memory permission 분리            |
| `--payload-relocate`     | payload를 non-executable storage로 이동              |
| `--rsrc-register`        | payload를 `RT_RCDATA`로 등록                         |
| `--dispatcher-reencrypt` | native block runtime re-encryption               |
| `--crypto-mode`          | `c1` 또는 `chacha20`                               |
| `--map`                  | VM instruction mapping 생성                        |
| `--sym-map`              | block/function symbolic mapping 생성               |

전체 목록:

```powershell
target\release\btg-packer.exe --help
```

---

# QA & Self-Test

```powershell
cargo test --lib
cargo test --all-targets

target\release\btg-packer.exe --vm-test
target\release\btg-packer.exe --vm-bench
target\release\btg-packer.exe --qa-gen-corpus
target\release\btg-packer.exe --test-qa
target\release\btg-packer.exe --test-qa --qa-commercial
```

QA infrastructure에는 VM interpreter/native execution 비교, RISC semantics, branch/flags, memory, atomics, SSE 계열, bridge ABI, malformed bytecode 및 deterministic-build 관련 테스트가 포함되어 있습니다.

---

# Current Limitations

BTG Packer는 연구용 prototype이며 모든 Windows PE를 지원하는 범용 commercial protector를 목표로 완성된 제품은 아닙니다.

* Windows x86-64 PE32+ 중심
* kernel-mode binary 미지원
* unsupported x86 semantics는 VM ownership을 받을 수 없음
* SEH/panic/setjmp/longjmp와 같은 runtime boundary는 보수적으로 처리
* 일부 특수 PE/TLS/layout 조합은 추가 호환성 작업이 필요할 수 있음
* Program-VM coverage는 입력 compiler와 생성 코드에 영향을 받음
* BTG-C1은 독립적인 cryptographic audit를 받은 표준 암호가 아님
* diagnostic map/manifest는 내부 보호 구조를 노출하므로 release artifact에서 제외 권장

---

# Project Structure

```text
analysis/
    canonical program model
    indirect target analysis
    code-pointer / CRT / switch analysis

pe/
    PE parsing and reconstruction
    reloc / TLS / unwind / load-config

graph/
    CFG extraction
    slicing / shuffle / fixup

pipeline/
    transformation passes
    PE reconstruction
    capability validation

pipeline/crypto/
    boot runtime
    encryption
    integrity
    IAT / memory hardening
    Program-VM placement

vm/lifter/
    x86-64 → RISC

vm/risc/
    RISC semantics
    optimizer
    evaluator

vm/poly/
    polymorphic ISA
    family-specific encoding
    rolling key

vm/threaded/
    native self-decoding runtime
    handler generation
    super-operators

vm/text_lift/
    whole-program virtualization analysis

crypto/
    BTG-C1
    ChaCha20
    Poly1305
    keyed MAC

qa.rs
differential.rs
multi_seed.rs
manifest.rs
```

---

## Security Research Only

BTG Packer is intended for binary-protection research, compiler/virtual-machine experimentation, PE transformation research and authorized reverse-engineering studies.

Do not use it to protect or distribute software you do not own or have permission to modify.

Apache 2.0 License는 `LICENSE`, 보안 관련 제보 방법은 `SECURITY.md`를 참고하세요.
