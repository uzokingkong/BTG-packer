# Validation and Development

## Validation philosophy

BTG separates “a protected image was generated” from “the generated image satisfies the requested transformation contract.”

Validation therefore covers both PE structure and protection-specific evidence.

## Commercial VM coverage evidence

`PipelineContext` records `VmCoverageMetrics` containing:

```text
vm_functions / total_functions
vm_blocks / total_blocks
vm_instructions / total_instructions
unresolved_internal_edges
unsupported_instructions
capability_mismatches
```

The last three fields are optional evidence values because “not measured” must not be confused with measured zero.

For a full commercial Program-VM build, validation expects authoritative ownership and capability evidence rather than inferring success from the existence of a VM section.

## Why function, block and instruction coverage all exist

Instruction-only coverage can hide ownership problems. A function may contain mostly liftable instructions but still be unsafe as a whole because of unresolved control flow, unwind behavior, semantic dependencies or a boundary ambiguity.

Function coverage therefore answers a different question from instruction coverage, while block coverage provides a useful middle level for CFG ownership.

## Partial VM development mode

`--allow-partial-vm` explicitly allows development builds below the normal commercial coverage requirement.

It is intentionally incompatible with `--strict-profile`: one asks to tolerate incomplete VM ownership while the other asks to reject protection downgrades.

## Structural PE validation

The validation path checks that reconstructed PE metadata agrees with generated layout. Areas of concern include:

```text
section layout and permissions
entry-point placement
data directories
relocations
exception/unwind coverage
resource metadata
imports/bootstrap slots
generated executable ranges
ciphertext provenance
VM/runtime placement
```

The goal is to catch images that are syntactically parseable but inconsistent with Windows loader/runtime expectations.

## Original executable text provenance

Commercial whole-program virtualization needs to distinguish generated VM runtime code from original program text that remains executable.

Validation can therefore reason about the overlap between original executable-text RVA provenance and executable sections in the final image. This is stronger evidence than simply checking that a `.vdata` or VM section exists.

## Differential execution verification

`--verify-output` runs the original and protected programs and compares externally observable process results:

```text
exit code
stdout bytes
stderr bytes
```

The default timeout is 30 seconds per process and is configurable with `--verify-timeout-secs`.

This is not a proof of semantic equivalence for every possible input, but it is a strong regression signal for deterministic test programs and QA corpus cases.

## Multi-seed verification

`--verify-seeds N` runs independent seeded pack + execution-verification jobs and writes distinct seed-suffixed artifacts.

This is important for randomized transforms: a path that succeeds for one layout or VM encoding may fail for another seed if a fixup, table layout or generated-runtime assumption is incomplete.

## Deterministic reproduction

When a seed exposes a crash, preserve it:

```powershell
--seed <value>
```

The same input/configuration/seed is intended to reproduce the same randomized transformation decisions, making debugging significantly easier than investigating a different layout on every run.

## VM self-test

`--vm-test` exercises VM components such as lifter/interpreter/native handlers and exits without normal packing.

Use it when changing VM semantics or runtime generation before debugging a complete PE image.

## VM benchmark

`--vm-bench` runs the VM performance benchmark path. It is intended for comparing VM execution implementations without requiring a full application packing workflow.

## Lift diagnostics

`--text-vm` decodes the input `.text` and reports lift coverage/unsupported instructions without packing.

`--text-vm-oep` follows the reachable CFG from the original entry point and attempts to construct a single VM program, reporting block/instruction coverage, bytecode size and VM memory-model information.

These modes isolate lifting/analysis problems from PE reconstruction problems.

## Mapping artifacts

`--map` writes an instruction-level mapping from generated VM bytecode offsets to original virtual addresses/disassembly.

`--sym-map` writes block-oriented symbolic mapping including original block addresses and ownership information.

These files are intended for crash triage and debugger correlation; they should not be treated as runtime requirements.

## Runtime diagnostics

`--trace-blocks` injects block execution tracing into the packed binary.

`--block-ring` injects a fixed-size ring buffer recording recently dispatched logical block IDs for post-crash diagnosis on the supported dispatcher path.

`--debug` increases logging verbosity and `--log-file` redirects logs to a file. The CLI keeps an explicit flush guard so buffered log output is synchronized on exit paths.

## QA corpus

The QA subsystem can build and run generated test programs across multiple compiler profiles. The CLI exposes:

```text
--test-qa
--qa-commercial
--qa-gen-corpus
```

The corpus path is useful for exercising behavior that changes with optimization, code generation, panic strategy, overflow checks, LTO and codegen-unit choices.

Commercial QA combines this with the Program-VM backend and treats behavior mismatch as a failure.

## Recommended development workflow

For a VM change:

```text
1. cargo test
2. --vm-test
3. --text-vm / --text-vm-oep on a representative binary
4. deterministic commercial pack with --seed
5. --verify-output
6. repeat with --verify-seeds
7. inspect structural/coverage report and map artifacts if anything fails
```

For a PE reconstruction change, focus first on deterministic native builds and structural validation, then test crypto/runtime features and finally Program-VM because the latter combines the largest number of subsystems.

## Keeping documentation synchronized

When adding a CLI flag, update `docs/getting-started.md`. When changing profile compatibility, update `docs/runtime-protection.md`. VM ABI/lifter/ownership changes belong in `docs/program-vm.md`, while PE-directory/loader behavior belongs in `docs/pe-pipeline.md`.

This division keeps the root README stable while allowing implementation documentation to evolve with the code.
