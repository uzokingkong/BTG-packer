# BTG Packer

**Windows x86-64 PE Transformation & Program Virtualization Framework — Rust**

[🇺🇸 English](README.md) · [상세 문서](docs/README.md)

BTG Packer는 Windows x86-64 PE32+ 실행 파일을 분석하고 변환하는 연구용 바이너리 보호 프레임워크입니다.

단순히 원본 실행 파일 전체를 하나의 payload로 취급하지 않고, PE 구조와 프로그램 제어 흐름을 분석한 뒤 native CFG 변환 또는 x86-64 → RISC → polymorphic Program-VM 경로를 구성하고, 런타임 보호 계층과 PE 재구성 및 검증을 수행합니다.

> **Research prototype.** 자신이 소유하거나 명시적으로 분석·변환 권한을 받은 바이너리에만 사용하세요.

## 현재 구현 영역

- PE32+ 파싱/재구성, relocation, TLS, load config, resource, x64 unwind 처리
- 함수/CFG, code pointer, pointer table, switch, indirect target 분석
- native basic-block slicing, layout shuffle, branch/RIP-relative fixup
- arithmetic/control-flow/memory/string/일부 SIMD를 포함한 x86-64 → RISC semantic lifting
- 함수 단위 VM ownership과 function/block/instruction coverage 측정
- polymorphic Program-VM, build별 table layout, rolling-key bytecode, native threaded runtime
- multi-family VM 계획과 cross-family route/state 전환
- VM/native bridge와 generated unwind/lifetime metadata
- ChaCha20 / BTG-C1, integrity, payload relocation, resource registration
- IAT hiding, anti-debug, W^X memory hardening, dispatcher re-encryption
- M7 lifetime protection, M8 VM table concealment
- deterministic seed build, QA, structural validation, differential execution verification
- VM instruction/block map 및 crash diagnostic 기능

세부 구현 설명은 [docs 문서 인덱스](docs/README.md)에서 확인할 수 있습니다.

## 전체 구조

```mermaid
flowchart LR
    A["Input PE32+"] --> B["PE + Program Analysis"]
    B --> C["ProgramModel / CFG / Functions"]
    C --> D{"Transformation path"}

    D -->|Native| E["Native CFG\nSlice · Shuffle · Fixups"]
    D -->|Program-VM| F["x86-64 → RISC IR"]

    F --> G["Ownership + VM Family Planning"]
    G --> H["Polymorphic ISA + Rolling-Key Bytecode"]

    E --> I["Runtime Protection"]
    H --> I
    I --> J["PE Reconstruction"]
    J --> K["Structural + Coverage Validation"]
    K --> L["Protected PE32+"]
```

Program-VM 경로는 단순한 `x86 opcode → 고정 VM opcode` 변환기가 아닙니다. 지원되는 x86-64 의미를 내부 RISC 계층으로 lift하고, ownership/family planning을 거쳐 build별 VM 표현으로 인코딩한 뒤 생성된 native runtime으로 실행합니다.

자세한 구조: [docs/architecture.md](docs/architecture.md) · [Program-VM 내부 구조](docs/program-vm.md)

> [!NOTE]
> 기존 multi-family 기반을 확장하는 **graph-driven cooperative VM**은 현재 차세대 실험 설계로 분리해 문서화하고 있습니다. 현재 production 동작이라고 과장하지 않고 `Planned / Experimental design`으로 명확히 구분합니다: [Bidirectional Trigger Graph VM 설계](docs/design/btg-trigger-graph.md).

## 빌드

```powershell
cargo build --release
```

기본 사용:

```powershell
cargo run --release -- --input app.exe --output app.protected.exe
```

동일한 변환 결정을 재현하려면:

```powershell
cargo run --release -- --input app.exe --output app.protected.exe --seed 31010
```

## 자주 사용하는 프로필

Native 보호 예시:

```powershell
cargo run --release -- \
  --input app.exe \
  --output app.protected.exe \
  -l 3 --integrity --iat-hide --mem-harden
```

Full preset:

```powershell
cargo run --release -- --input app.exe --output app.protected.exe --full
```

Commercial Program-VM:

```powershell
cargo run --release -- \
  --input app.exe \
  --output app.protected.exe \
  --vm --vm-oep --vm-commercial
```

Commercial 경로는 기본적으로 측정된 VM coverage 정책을 통과해야 합니다. 개발 중 부분 coverage를 허용하려면 `--allow-partial-vm`을 명시할 수 있으며 `--strict-profile`과는 함께 사용할 수 없습니다.

## 주요 진단 옵션

```text
--verify-output   원본/보호본의 exit code, stdout, stderr 비교
--verify-seeds N  여러 seed로 pack + 실행 검증 반복
--vm-test         VM self-test
--vm-bench        VM benchmark
--text-vm         .text lift coverage 진단
--text-vm-oep     OEP reachable CFG -> VM 변환 진단
--map             instruction-level VM map 생성
--sym-map         block/ownership map 생성
--trace-blocks    runtime block tracing
--block-ring      최근 dispatch block ID 기록
```

## 상세 문서

| 주제 | 문서 |
| --- | --- |
| 설치, CLI, 사용 예시 | [Getting Started](docs/getting-started.md) |
| 코드베이스와 파이프라인 구조 | [Architecture](docs/architecture.md) |
| RISC lifter, ownership, polymorphic VM | [Program-VM](docs/program-vm.md) |
| PE 파싱/재구성, relocation, TLS, unwind | [PE Transformation Pipeline](docs/pe-pipeline.md) |
| Crypto 및 runtime hardening | [Runtime Protection](docs/runtime-protection.md) |
| Coverage, QA, 검증, 디버깅 | [Validation and Development](docs/validation-development.md) |
| 차세대 graph-driven VM 정체성 | [Bidirectional Trigger Graph 설계](docs/design/btg-trigger-graph.md) |

## Library API

`src/lib.rs`를 통해 주요 모듈이 library surface로 공개되어 있으며, 간단한 in-memory entry point도 제공합니다.

```rust
let protected: Vec<u8> = btg_packer::pack(&input_pe_bytes)?;
```

## 상태

BTG는 계속 개발 중인 연구 프로젝트입니다. 요청한 변환을 안전하게 표현하지 못하는 경우 단순히 보호 코드가 생성되었다는 이유로 성공 처리하기보다 coverage/validation 단계에서 불완전 상태를 드러내는 방향을 사용합니다.

버그 리포트와 기여는 언제든 환영합니다.

## License

Apache License 2.0 — [LICENSE](LICENSE)
