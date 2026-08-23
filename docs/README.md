# BTG Packer Documentation

This directory contains the detailed technical documentation for BTG Packer.

The repository root `README.md` is intentionally kept short: project summary, implemented feature overview, build instructions, common commands, and links into this documentation set.

## Documentation map

- [Getting Started](getting-started.md) — requirements, build, command-line usage, presets, diagnostics and common workflows.
- [Architecture](architecture.md) — repository layout, analysis model, native CFG path, Program-VM path, pipeline state and data flow.
- [Program-VM](program-vm.md) — x86-64 lifting, RISC semantics, ownership, multi-family planning, polymorphic encoding, rolling-key runtime and VM/native bridges.
- [PE Transformation Pipeline](pe-pipeline.md) — parsing, CFG reconstruction, block rewriting, PE rebuilding, relocations, TLS, exception metadata, resources and import handling.
- [Runtime Protection](runtime-protection.md) — crypto modes, payload relocation, integrity, anti-debugging, IAT hiding, memory hardening, M7/M8 and dispatcher re-encryption.
- [Validation and Development](validation-development.md) — coverage gates, deterministic builds, differential execution verification, QA, VM diagnostics and debugging artifacts.
- [Bidirectional Trigger Graph VM Design](design/btg-trigger-graph.md) — **planned/experimental** graph-driven cooperative multi-family execution identity.

## Source-oriented map

The main public modules are exported from `src/lib.rs`:

```text
analysis      program discovery and semantic analysis
assembler     generated native payload helpers
cli           command-line interface
core          trigger graph/block primitives
crypto        stream ciphers, MACs and crypto providers
dispatcher    generated native dispatch/runtime components
graph         CFG/basic-block structures
manifest      protection/build metadata
mba           mixed boolean-arithmetic transforms
obfuscation   code transformation utilities
pe            PE32+ parsing and reconstruction
pipeline      end-to-end packing/transformation pipeline
qa            regression and compiler-corpus QA
sdk           selective virtualization interfaces
vm            lifter, RISC IR, polymorphic VM and runtimes
```

The binary front-end in `src/main.rs` parses CLI arguments, resolves the protection profile, enters diagnostic modes when requested, constructs the pipeline context and runs the transformation/validation path. The library entry point also exposes `btg_packer::pack()` for in-memory use.

## Reading order

For a first pass, read `getting-started.md`, then `architecture.md`. If you are interested primarily in virtualization, continue with `program-vm.md`. If you are working on executable compatibility, PE reconstruction or Windows loader behavior, continue with `pe-pipeline.md` and `validation-development.md`.

The design document under `design/` is intentionally separated from current implementation documentation so future architectural ideas are not confused with validated production behavior.

> BTG Packer is a security-research prototype. Use it only on software you own or are explicitly authorized to transform or analyze.
