# Getting Started

## Requirements

BTG Packer targets Windows x86-64 PE32+ executables and is written in Rust. Build the repository with the pinned Rust toolchain in `rust-toolchain.toml`.

```powershell
cargo build --release
```

The resulting CLI is the `btg-packer` binary.

## Basic packing

```powershell
cargo run --release -- --input app.exe --output app.protected.exe
```

The CLI defaults to `dummy_target.exe` as input and `protected_btg.exe` as output. If the default input does not exist, the front-end can generate the built-in dummy target for development paths.

## Deterministic builds

```powershell
cargo run --release -- --input app.exe --output packed.exe --seed 31010
```

The seed is the root of deterministic transformation randomness: block layout, MBA constants, crypto/poly seeds and layout decisions derive from seeded state. The intent is that the same input, effective configuration and seed reproduce the same transformation decisions.

## Native protection profile

A typical native CFG build is:

```powershell
cargo run --release -- --input app.exe --output packed.exe -l 3 --integrity --iat-hide --mem-harden
```

Obfuscation levels exposed by the CLI are:

```text
1  basic
2  MBA
3  overlapping + MBA
```

## Full preset

```powershell
cargo run --release -- --input app.exe --output packed.exe --full
```

`--full` requests the maximum native protection stack represented by the profile resolver: level 3 obfuscation, anti-debugging, dispatcher re-encryption, integrity, payload relocation, resource registration, IAT hiding and memory hardening. Some requested features are mutually exclusive at runtime; the profile resolver applies precedence rules before the pipeline starts.

Important examples:

- `--vm-oep` takes precedence over native dispatcher re-encryption.
- dispatcher re-encryption takes precedence over `--mem-harden` because the transformed native block area must remain writable for runtime decrypt/re-encrypt.
- `--rsrc-register` requires payload relocation.
- VM modes require the crypto layer.
- RC4 is retired and explicitly rejected rather than silently replaced.

Use `--strict-profile` when a requested protection downgrade should be treated as an error rather than a warning.

## Program-VM

The commercial Program-VM path is selected with:

```powershell
cargo run --release -- \
  --input app.exe \
  --output packed.exe \
  --vm --vm-oep --vm-commercial
```

This path analyzes the program, lifts supported x86-64 semantics into the internal RISC representation, performs ownership/capability checks, assigns VM-family state, generates polymorphic bytecode and embeds a native threaded runtime.

Commercial builds normally enforce the measured VM coverage policy. For development-only partial coverage:

```powershell
--allow-partial-vm
```

This option conflicts with `--strict-profile` by design.

## Crypto selection

The current selectable primitives are:

```powershell
--crypto-mode chacha20
--crypto-mode c1
```

ChaCha20 is the default. The legacy `--rc4` flag remains parseable only so old scripts receive an explicit retirement error.

The crypto layer is enabled by default. Disable it with:

```powershell
--no-crypto
```

Disabling crypto also makes crypto-dependent VM/protection requests ineffective or invalid according to the profile resolver.

## Runtime-protection options

Common switches include:

```text
--anti-debug
--anti-debug-policy trap|hang|warn
--integrity
--payload-relocate
--rsrc-register
--iat-hide
--mem-harden
--dispatcher-reencrypt
--chained-crypto
--crypto-coverage <0..100>
--m7
--m8
```

See [Runtime Protection](runtime-protection.md) for their implementation roles and interactions.

## Validation and differential execution

To execute the original and packed programs and compare exit status, stdout and stderr:

```powershell
--verify-output
```

The per-process timeout defaults to 30 seconds and can be changed with:

```powershell
--verify-timeout-secs 60
```

To perform independent seeded pack-and-verify runs:

```powershell
--verify-seeds 20
```

## VM diagnostics

The CLI includes several development modes:

```text
--vm-test       lifter/interpreter/native-handler self-test
--vm-bench      VM throughput benchmark
--text-vm       diagnose .text lift coverage without packing
--text-vm-oep   diagnose reachable OEP CFG → VM program conversion
```

For crash triage and mapping:

```text
--map           instruction-level bytecode map
--sym-map       block-level symbolic map
--block-ring    runtime ring buffer of recently dispatched block IDs
--trace-blocks  inject runtime block execution tracing
--debug         verbose logging
--log-file      write logs to a file
```

## QA

The repository contains an automated QA path and compiler corpus support:

```text
--test-qa
--qa-commercial
--qa-gen-corpus
```

The QA path is intended to exercise transformation compatibility across generated test programs and compiler profiles. See [Validation and Development](validation-development.md).

## Library API

BTG is also exported as a Rust library. The top-level convenience entry point is:

```rust
pub fn pack(input_pe: &[u8]) -> Result<Vec<u8>>
```

It runs the full in-memory packing pipeline and returns the resulting PE bytes. Lower-level modules are public through `src/lib.rs` for tooling and tests that need direct access to analysis, PE, pipeline, crypto or VM components.
