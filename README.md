# BTG Packer

### Windows x86-64 PE Transformation & Program Virtualization Framework

[🇰🇷 한국어 문서 보기](README.ko.md) · [Detailed documentation](docs/README.md)

![Language](https://img.shields.io/badge/language-Rust-orange)
![Platform](https://img.shields.io/badge/platform-Windows%20x86--64-blue)
![Binary Format](https://img.shields.io/badge/format-PE32%2B-informational)
![Architecture](https://img.shields.io/badge/architecture-x86--64-lightgrey)
![Status](https://img.shields.io/badge/status-research%20prototype-yellow)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

**BTG Packer** is a Rust research framework for analyzing, transforming and virtualizing Windows x86-64 PE32+ executables.

It combines PE reconstruction, control-flow transformation, x86-64 → RISC lifting, polymorphic Program-VM generation, runtime protection and post-build validation in one pipeline.

> [!WARNING]
> BTG Packer is a **security research prototype**, not a production commercial protector. Use it only on software you own or are explicitly authorized to transform or analyze.

## Implemented areas

The current codebase includes:

- PE32+ parsing and reconstruction, relocations, TLS, load config, resources and x64 unwind metadata;
- CFG/function discovery, code-pointer, pointer-table, switch and indirect-target analysis;
- native basic-block slicing, randomized layout, branch rewriting and RIP-relative repair;
- x86-64 → internal RISC semantic lifting across arithmetic, control flow, memory, string and selected SIMD operations;
- function-level VM ownership and measured function/block/instruction coverage;
- polymorphic Program-VM encoding, build-specific table layouts, rolling-key bytecode and native threaded execution;
- multi-family VM planning and canonical cross-family routing;
- VM/native bridge and generated unwind/lifetime metadata;
- ChaCha20 and BTG-C1 crypto paths, integrity, payload relocation and resource registration;
- IAT hiding, anti-debugging, W^X-oriented memory hardening and dispatcher re-encryption;
- M7 runtime lifetime protection and M8 VM table concealment;
- deterministic seeded builds, structural validation, QA and differential execution verification;
- instruction/block mapping and crash-diagnostic tooling.

For the implementation-level explanation, see the [documentation index](docs/README.md).

## Architecture at a glance

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

The Program-VM path is deliberately not just a fixed `x86 opcode → VM opcode` translator. Supported native semantics are lifted into an internal RISC layer, assigned through ownership/family planning, encoded into build-local VM representations, and executed by generated native runtime components.

Detailed architecture: [docs/architecture.md](docs/architecture.md) · [Program-VM internals](docs/program-vm.md)

> [!NOTE]
> BTG's next experimental design direction is a graph-driven cooperative VM execution model built on top of the existing multi-family infrastructure. It is documented separately as a **planned design**, not as a claim about current production behavior: [Bidirectional Trigger Graph VM design](docs/design/btg-trigger-graph.md).

## Build

The repository includes a pinned Rust toolchain configuration.

```powershell
cargo build --release
```

Basic packing:

```powershell
cargo run --release -- --input app.exe --output app.protected.exe
```

Deterministic build:

```powershell
cargo run --release -- --input app.exe --output app.protected.exe --seed 31010
```

## Common profiles

Native protection example:

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

Commercial Program-VM path:

```powershell
cargo run --release -- \
  --input app.exe \
  --output app.protected.exe \
  --vm --vm-oep --vm-commercial
```

The commercial path normally requires measured full VM coverage. `--allow-partial-vm` is a development-only escape hatch and conflicts with `--strict-profile`.

## Useful diagnostics

```text
--verify-output   compare original/protected exit code, stdout and stderr
--verify-seeds N  repeat seeded pack + execution verification
--vm-test         run VM self-tests
--vm-bench        benchmark VM execution paths
--text-vm         inspect .text lift coverage
--text-vm-oep     inspect reachable OEP CFG -> VM conversion
--map             emit instruction-level VM mapping
--sym-map         emit block/ownership mapping
--trace-blocks    inject runtime block tracing
--block-ring      keep recent dispatched block IDs for crash triage
```

## Documentation

| Topic | Document |
| --- | --- |
| Installation, CLI and common workflows | [Getting Started](docs/getting-started.md) |
| Repository and pipeline architecture | [Architecture](docs/architecture.md) |
| RISC lifter, ownership, polymorphic VM and runtime | [Program-VM](docs/program-vm.md) |
| PE parsing, rewriting, relocations, TLS and unwind | [PE Transformation Pipeline](docs/pe-pipeline.md) |
| Crypto and runtime hardening features | [Runtime Protection](docs/runtime-protection.md) |
| Coverage gates, QA, verification and debugging | [Validation and Development](docs/validation-development.md) |
| Planned graph-driven VM identity | [Bidirectional Trigger Graph design](docs/design/btg-trigger-graph.md) |

## Library use

The crate exposes its major subsystems through `src/lib.rs`. A convenience in-memory entry point is available:

```rust
let protected: Vec<u8> = btg_packer::pack(&input_pe_bytes)?;
```

Lower-level public modules expose analysis, PE, pipeline, crypto, SDK and VM components for tests and research tooling.

## Project status

BTG is actively evolving as a research codebase. The implementation intentionally fails or reports incomplete coverage when a requested transformation cannot be represented safely instead of treating the presence of generated protection code as proof of complete protection.

Bug reports and contributions are welcome.

## License

Apache License 2.0. See [LICENSE](LICENSE).
