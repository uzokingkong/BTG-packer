# btg_codegen

Standalone generator that turns the BTG **CPU coverage DB** into **RiscOp
lowering candidates** and Rust source skeletons. It is the "Code Generator" half
of the coverage pipeline described in the design note: coverage/matrix tells us
*what is unsupported*; this tool proposes *how to close each gap*.

```
coverage DB (vm_coverage.json / cpu-coverage json)
       │  load + keep only gap records
       ▼
Instruction Family Classifier        (src/family.rs)
       ▼
Semantic Rule Engine                 (src/rules.rs)
       │   AUTO_TEMPLATE | MANUAL_SEMANTICS | NATIVE_FALLBACK
       ▼
Rust Source / Report Generator       (src/emit.rs)
       ├── generated/lifter_rules.generated.rs    candidate match-arms (skeletons)
       ├── generated/semantic_tests.generated.rs  lift-assertion test skeletons
       ├── generated/codegen_report.md            gap analysis + backlog
       └── generated/rule_coverage.json           machine-readable plan
```

## Design boundaries

* **It does not modify the core.** This crate has no `[workspace]` tie to
  `btg-packer` and does not depend on it. Everything it writes lands in
  `generated/`. Wiring a reviewed arm into `src/vm/risc/lifter/mod.rs` is a
  deliberate human step.
* **It is honest about semantics.** iced-x86 metadata gives operand/encoding
  shape, not meaning. So the rule engine emits an auto template only where a
  faithful lowering over *existing* RiscOps exists (ALU, shift, bit, mul/div,
  set/cmov, atomics, 128-bit packed int, scalar SSE float, …). AVX/AVX-512/AMX/
  crypto/RNG/x87/privileged are routed to manual-semantics or kept native,
  matching the core's `VirtualIsaSpec::is_encodable` exclusion policy.
* **Template integrity is gated.** `--strict` fails if any auto template
  references a RiscOp the core does not implement (`KNOWN_RISC_OPS` is kept in
  sync with `src/vm/risc/op_registry.rs`).

## Usage

```bash
# 1) produce a coverage DB with the core auditor (Windows CI)
cargo run --release --bin vm-coverage -- --out-dir coverage

# 2) run the generator on it
cargo run --release --manifest-path tools/btg_codegen/Cargo.toml -- \
    --coverage coverage/vm_coverage.json \
    --out-dir  tools/btg_codegen/generated \
    --strict
```

For local development without a full coverage run, a representative fixture is
committed at `fixtures/sample_vm_coverage.json` and drives the test suite.

## Next steps (not yet implemented)

The closed loop from the design note — *generate → cargo test → re-coverage →
PASS feeds DB / FAIL feeds generator* — is future work. v1 stops at reviewable
candidate emission; it never auto-commits lifter changes.
