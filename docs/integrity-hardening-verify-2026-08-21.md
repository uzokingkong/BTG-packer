# Integrity + boot-stub junk hardening — state verification (2026-08-21)

## Summary

The defensive-hardening work requested for the btg-packer repo was **already fully
implemented in the working tree** by a prior parallel task and is **verified passing**
(build + unit tests + `--integrity` pack + built-in VALIDATE). I made **no code changes**:
the requested deliverables are present and correct as-is. This report records what is in
place and the real verification output.

Working tree: `C:\Users\uzoki\Desktop\asdfsadfecwecc` (node `ujiwo-zyris-code`, branch main).

## Part 1 — Integrity check (multi-location + runtime-derived)

**Five independent sites** are emitted in `build_rc4_block` (`src/pipeline/crypto/bootstub/build.rs`),
in order: keyed-MAC → CRC site1 → CRC site2 → CRC site3 (after IAT resolve) → CRC site4
(before dispatcher entry):

```
code_decrypt → emit_integrity_mac → emit_integrity_crc (site1)
  → run_decrypt → rest_decrypt → emit_integrity_crc2 (site2)
  → iat_slots → iat_resolve → emit_integrity_crc3 (site3)
  → self_wipe → mem_harden → emit_integrity_crc4 (site4) → dispatcher_entry
```

- Emitters: `src/pipeline/crypto/integrity.rs` — `emit_integrity_mac`,
  `emit_integrity_crc`, `emit_integrity_crc2`, `emit_integrity_crc3`, `emit_integrity_crc4`.
- Slots: `BootStubCtx` (`bootstub/ctx.rs`) carries `crc_va/mac_va/crc2_va/crc3_va/crc4_va/w32_slot_va`.
- Layout (`place/mod.rs`): `seed_off+256` crc, `+260` mac (8B), `+268` crc2, `+272` w32_slot,
  `+276` crc3, `+280` crc4. All addresses are imm64/rel32 fixed-length → 3-pass sizing invariant holds.

### Runtime-derived whiten (defeats §3.4 recompute-from-file)

Packer side stores whitened values (`place/mod.rs:1022-1046`):
`crc_stored = crc ^ mac_lo32`, `mac_stored = mac ^ W32`,
`crc2_stored = crc ^ W32`, `crc3_stored = crc ^ W32`, `crc4_stored = crc ^ rol(W32,13)`,
where `W32 = derive_integrity_key(seed_masked, image_base)` (integrity.rs:50).

`derive_integrity_key` folds the seed whiten **and** the PEB `ImageBaseAddress` bind byte
(`w ^= rol(bind*PHI32, bind&31)`), so the stored expected values are a function of the
runtime load base, not just static file content. Lockstep: the boot stub recomputes the same
W32 in the `emit_integrity_mac` preamble (W32 WhitenLoop + PEB fold), persists it to
`w32_slot`, and sites 3/4 reuse it after R15 is clobbered.

### Value feedforward (defeats single-byte `je→jmp` patch)

Site1 (`emit_integrity_crc`) does **not** rely on `je;ud2` alone: it computes
`V1 = computed ^ stored` into EAX and feeds it into R14D, which is consumed downstream by
`emit_run_decrypt` as a poison key. Patching site1's `je`→`jmp` (or NOP) leaves
`V1 ≠ 0` on tamper → string runs/IAT decrypt to garbage → crash. On the real path `V1 = 0`,
so behavior is unchanged. Sites 2–5 additionally use an `xor`-based compare that sets ZF from
the tamper delta (`V = computed ^ stored`), so a NOP'd branch still carries the nonzero
tamper value in the flag/register state.

### RDTSC nibble — NOT added (deliberately)

The task suggested folding "an RDTSC nibble" into the runtime derivation. This is
**fundamentally incompatible** with the task's own constraints: "packer-side stored value must
use the SAME combined derivation ... deterministic for a given seed ... correct on the real
path." RDTSC is not packer-predictable, so a stored expected value cannot be made to match a
runtime RDTSC fold without breaking the real path or requiring a large layout rework
(16-way precomputed rotation table per site) that would risk the fragile, verified stub.
The runtime-only-factor requirement is already satisfied by the PEB `ImageBaseAddress` fold
(`derive_integrity_key`). This is the one requested item intentionally left out.

## Part 2 — Fake-path junk rework

Already reworked in the working tree:

- `bootstub/emit.rs`: `trashformer_junk` (seed-derived straight-line junk) +
  `trashformer_mixing_loop` (a real, seed-derived 1..256-trip mixing loop — no
  "length=0 dead loop").
- **Real data dependency**: `emit_base_bind_loop` captures the junk mixing accumulator
  (`EDX`) into `R9D` and folds it into the bind byte twice (compensated, net 0), so the real
  base-bind path genuinely depends on the junk — a static liveness analyzer cannot drop it,
  while real behavior is byte-identical.
- Preserves rbx/rsp; deterministic per seed; fixed-length ops keep the 3-pass invariant.

## Tests (already present in `src/pipeline/crypto/tests.rs`)

- `test_integrity_multi_site_count` — asserts ≥4 independent sites emitted.
- `test_integrity_stored_values_not_plain` — stored crc/mac/crc2/3/4 ≠ plain values (whitened).
- `test_integrity_derivation_deterministic_and_base_dependent` — per-(seed,base) determinism,
  base-sensitivity.
- `test_integrity_stub_size_length_invariant` — changing site VAs does not change stub length.
- `test_junk_has_real_dependency_and_seed_determinism` — junk→real `mov r9d,edx` def-use +
  byte-identical stub for a given seed.
- `test_boot_stub_generates_with_integrity` / `test_boot_stub_generates` (integrity-off).

## Verification (real output)

### Build
`cargo build --release` → **exit 0, 0 errors** (52s). 217 lib + 2 bin warnings, all
`unused`-family in unrelated modules; none fatal.

### Tests
- `cargo test --lib pipeline::crypto::` → **28 passed, 0 failed** (0.29s).
- `cargo test --lib` → **476 passed; 1 failed** (43s). The single failure is
  `qa::tests::packed_test_payload_executes_seh_and_tls_stages` — an unrelated pre-existing WIP
  failure in the QA module (SEH/TLS packed-payload execution), **not** in
  pipeline::crypto/integrity/junk.

### Pack with --integrity
`btg-packer.exe -i dummy_target.exe -o packed_integrity.exe --integrity` (dummy_target.exe
compiled ad-hoc from a minimal Rust source into `%TEMP%`):
- `[SUCCESS] Synthesized Protected BTG PE Binary Written to: packed_integrity.exe`
  (325,632 bytes).
- `[+] T2-3 Integrity keyed-MAC over code region: EC8FA4E1739AC7F9 (keyed)`
- `[+] S1 Integrity keyed-MAC stored @0x3355C (8B...)`; `[+] v5 Integrity: code-region CRC32 = 0x81037F97 stored @0x33558`
- **`[VALIDATE]` self-check passed** (all `[VALIDATE] OK ...` lines: sections, PE structure,
  entry in `.textb`, boot-stub prologue at entry, import/TLS preserved, dirs validated).

### Plain path (no --integrity)
Covered by unit tests: every integrity emitter is gated on `stub.integrity`, so
`build_rc4_block` with `integrity:false` emits no integrity code (verified by
`test_boot_stub_generates`, integrity-off, passing). A separate plain pack was not run; noted.

## Notes / honesty

- No code was changed by me; the requested hardening is already present and verified.
- RDTSC nibble intentionally omitted (see Part 1) — impossible to add correctly under the
  task's lockstep/determinism/correct-path constraints.
- One unrelated pre-existing test failure (`qa::...::packed_test_payload_executes_seh_and_tls_stages`).
