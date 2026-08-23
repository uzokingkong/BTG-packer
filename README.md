# BTG Packer

### Windows x86-64 PE Transformation & Program Virtualization Framework
<span style="color:red">**Bug reports are very welcome!**</span>
[🇰🇷 한국어 문서 보기](README.ko.md)

![Language](https://img.shields.io/badge/language-Rust-orange)
![Platform](https://img.shields.io/badge/platform-Windows%20x86--64-blue)
![Binary Format](https://img.shields.io/badge/format-PE32%2B-informational)
![Architecture](https://img.shields.io/badge/architecture-x86--64-lightgrey)
![Status](https://img.shields.io/badge/status-research%20prototype-yellow)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

**BTG Packer** is a research-oriented Windows x86-64 binary protection framework written in Rust.

Instead of treating a PE file as a single opaque payload, BTG analyzes the executable, reconstructs a program model, transforms native control flow, optionally lifts supported x86-64 code into an internal RISC representation, builds a polymorphic Program-VM, applies runtime protection layers, reconstructs the PE image, and validates the resulting executable.

The project combines several areas that are usually implemented independently:

* PE32+ parsing and reconstruction
* x86-64 decoding and control-flow analysis
* basic-block transformation
* RIP-relative and branch fixups
* x86-64 → RISC lifting
* function-level virtualization ownership
* polymorphic virtual instruction sets
* multi-family VM profiles
* rolling-key bytecode encoding
* native threaded VM execution
* runtime code/data protection
* import hiding
* integrity verification
* deterministic builds
* post-build structural validation
* execution differential testing

> [!WARNING]
> BTG Packer is a **security research prototype**, not a production commercial protector.
>
> It is intended for binaries you own or are explicitly authorized to analyze or transform.

---

## Repository Description

> **Windows x86-64 binary protection framework implementing x86→RISC lifting, polymorphic Program-VMs, rolling-key bytecode, PE reconstruction, runtime hardening, and differential execution verification.**

Suggested GitHub topics:

```text
rust
windows
x86-64
pe
pe32-plus
binary-protection
program-virtualization
virtual-machine
reverse-engineering
binary-analysis
obfuscation
risc
cryptography
security-research
```

---

# Overview

BTG contains two major transformation paths.

### Native CFG Protection

The original x86-64 program remains native code, but BTG reconstructs its control-flow graph, transforms basic blocks, rewrites branches and RIP-relative references, and applies runtime protection around the transformed program.

### Program Virtualization

Supported x86-64 program regions are lifted into an internal RISC representation and compiled into a generated virtual instruction set executed by a native VM runtime.

The Program-VM pipeline is approximately:

```text
Original PE32+
      │
      ▼
PE / Program Analysis
      │
      ▼
Function + CFG Reconstruction
      │
      ▼
x86-64 Decoder
      │
      ▼
RISC Lifter
      │
      ▼
Ownership / Safety Analysis
      │
      ├──────────────► Native fallback
      │
      ▼
Multi-Family VM Planning
      │
      ▼
Polymorphic ISA Generation
      │
      ▼
RISC → Virtual Instruction Encoding
      │
      ▼
Rolling-Key Bytecode
      │
      ▼
Native Threaded VM Runtime
      │
      ▼
VM / Native Bridge
      │
      ▼
Runtime Protection Layer
      │
      ▼
PE Reconstruction
      │
      ▼
Structural + Capability Validation
      │
      ▼
Optional Execution Differential Test
```

---

# Design Goals

BTG is primarily an experimental platform for studying how binary transformation, virtualization and PE reconstruction interact.

The implementation is designed around several principles.

### Preserve observable program behavior

Transformations should not intentionally change:

```text
exit status
stdout
stderr
program control flow
required imports
runtime state
```

The `--verify-output` mode can execute both binaries and compare their externally observable results.

### Fail instead of silently producing incomplete virtualization

Commercial Program-VM builds normally require measured virtualization coverage to satisfy the production coverage gate.

Partial VM coverage can only be explicitly enabled for development with:

```powershell
--allow-partial-vm
```

### Separate analysis from transformation

BTG constructs program information before rewriting the image.

This includes information about:

* executable regions
* functions
* basic blocks
* direct branches
* indirect targets
* pointer tables
* code pointers
* CRT-related structures
* exception metadata
* relocation information
* imports
* resources

### Keep builds reproducible when requested

A user-supplied seed controls the deterministic random sources used by transformation passes.

```powershell
--seed 31010
```

The same input, configuration and seed are intended to produce reproducible transformation decisions.

---

# High-Level Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                         Input PE32+                          │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                         PE Analysis                          │
│                                                              │
│  Sections      Imports       Relocations      Resources      │
│  Exception     TLS           Load Config      Code Pointers  │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                     Program Reconstruction                   │
│                                                              │
│      CFG → Functions → Basic Blocks → Indirect Targets      │
└──────────────────────────────┬───────────────────────────────┘
                               │
                 ┌─────────────┴──────────────┐
                 │                            │
                 ▼                            ▼
┌────────────────────────┐       ┌────────────────────────────┐
│ Native CFG Pipeline    │       │ Program-VM Pipeline        │
│                        │       │                            │
│ Block slicing          │       │ x86 → RISC                │
│ Layout shuffle         │       │ Ownership analysis         │
│ Branch rewriting       │       │ Family partitioning        │
│ RIP fixups             │       │ Polymorphic ISA            │
│ MBA transforms         │       │ Bytecode generation        │
└───────────┬────────────┘       │ Native VM runtime          │
            │                    └──────────────┬─────────────┘
            │                                   │
            └───────────────────┬───────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────┐
│                    Runtime Protection Layer                  │
│                                                              │
│   Crypto      Integrity      IAT Hiding      Memory Policy   │
│   M7/M8       Anti-Debug     Payload Storage Resource Data   │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                       PE Reconstruction                      │
│                                                              │
│ Sections → Directories → Relocations → pdata → Entry Point  │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                           Validation                         │
│                                                              │
│ Structural PE Validation                                    │
│ Protection Capability Validation                            │
│ VM Coverage Validation                                      │
│ Optional Runtime Differential Verification                  │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
                         Protected PE
```

---

# PE Analysis and Reconstruction

BTG does not simply append a loader to an existing executable.

The PE subsystem analyzes and later reconstructs information required by the transformed image.

Relevant code is primarily located under:

```text
src/pe/
src/analysis/
src/pipeline/validate/
```

The implementation handles or analyzes structures including:

```text
DOS / NT headers
PE32+ optional header
section table
imports
base relocations
resource directory
exception directory
.pdata / RUNTIME_FUNCTION
TLS metadata
load configuration
code pointers
image layout
entry point
```

BTG also contains dedicated analysis for less direct control-flow information.

Examples include:

```text
analysis/code_pointers.rs
analysis/indirect_targets.rs
analysis/indirect_resolver.rs
analysis/pointer_tables.rs
analysis/switch_targets.rs
analysis/switch_producer.rs
analysis/crt.rs
```

This information is important because rewriting executable code without tracking non-obvious references to that code can produce a structurally valid PE that crashes at runtime.

---

# Native CFG Transformation

The native protection pipeline operates on decoded x86-64 basic blocks.

Its responsibilities include:

```text
instruction decoding
basic-block discovery
CFG construction
block slicing
block layout randomization
branch reconstruction
RIP-relative fixups
encoded output generation
dispatcher integration
```

A simplified native transformation is:

```text
Original .text
     │
     ▼
x86-64 Decode
     │
     ▼
Basic Blocks
     │
     ▼
CFG
     │
     ▼
Block Slicing
     │
     ▼
Block Shuffle
     │
     ▼
Branch / RIP Reconstruction
     │
     ▼
Dispatcher / Runtime Integration
     │
     ▼
Transformed Native Code
```

Block relocation requires BTG to recalculate references whose original displacement depended on instruction location.

Examples include:

```asm
call rel32
jmp rel32
jcc rel32

mov rax, [rip + displacement]
lea rcx, [rip + displacement]
```

The transformation pipeline therefore maintains layout and fixup information instead of blindly copying instruction bytes.

---

# Program-VM

The Program-VM backend is enabled with:

```powershell
--vm --vm-oep --vm-commercial
```

The commercial Program-VM path is built around an intermediate RISC representation rather than directly assigning one virtual opcode to every original x86 instruction.

```text
x86-64
   │
   ▼
RISC semantic operations
   │
   ▼
optimization / transformation
   │
   ▼
polymorphic virtual ISA
   │
   ▼
encoded VM bytecode
   │
   ▼
native threaded runtime
```

This separation allows the original x86 encoding and the final VM bytecode encoding to be different abstraction layers.

---

# x86-64 → RISC Lifting

The lifter translates supported native instructions into internal semantic operations.

Relevant implementation areas include:

```text
src/vm/lifter/
src/vm/risc/
src/vm/canonical_semantics.rs
src/vm/semantics.rs
```

The RISC layer contains semantics for substantially more than basic `MOV`, `ADD` and `XOR` operations.

Implemented areas include operations related to:

```text
integer arithmetic
carry / borrow
logical operations
shifts
rotates
comparisons
condition evaluation
memory loads
memory stores
virtual stack operations
branches
returns
multiplication
division
bit scanning
bit manipulation
atomic operations
conditional moves
selected SIMD semantics
register state
flag state
VM/native transitions
```

The important architectural distinction is:

```text
x86 instruction != final VM opcode
```

For example, the pipeline is conceptually allowed to transform:

```text
x86 ADD
   │
   ▼
RISC semantic representation
   │
   ▼
transformed RISC sequence
   │
   ▼
build-local virtual instruction encoding
```

instead of requiring:

```text
x86 ADD → VM_ADD
```

---

# Function Ownership

Not every decoded function is automatically considered safe to virtualize.

BTG tracks function ownership and determines whether a function can be placed in the Program-VM or must remain native.

Conceptually:

```text
                 Function
                    │
                    ▼
             Decode + Analyze
                    │
          ┌─────────┴─────────┐
          │                   │
        Safe               Unsafe /
          │               Unsupported
          ▼                   │
       VM-owned               ▼
                           Native-owned
```

Ownership decisions can be affected by conditions such as:

```text
unsupported instructions
unsupported VM semantics
ambiguous function boundaries
SEH / unwind constraints
panic-related boundaries
setjmp / longjmp behavior
semantic dependency closure
analysis failures
explicit integration quarantine
```

The ownership system prevents the virtualizer from claiming coverage over code it cannot safely represent.

---

# Production VM Coverage Gate

A Program-VM image existing in the output file does not automatically mean that the original executable has actually been virtualized completely.

BTG therefore measures coverage.

The validation pipeline checks coverage at multiple levels, including:

```text
functions
basic blocks
instructions
```

For normal commercial Program-VM builds, incomplete measured coverage causes the build to fail.

Development builds may explicitly bypass this requirement:

```powershell
--allow-partial-vm
```

This option is intentionally incompatible with:

```powershell
--strict-profile
```

This distinction is useful because it separates:

```text
"the VM backend successfully generated something"
```

from:

```text
"the requested program virtualization actually covers the program"
```

---

# Multi-Family VM Model

BTG defines four Program-VM architecture families:

```text
Stack
Register
MixedRisc
FusedCisc
```

The architecture-family layer is separate from simple opcode permutation.

A family profile contains parameters such as:

```text
virtual register count
native operand width
variable-width operand behavior
flag model
dispatch topology
VM calling convention
ISA domain separator
```

The currently defined profiles are:

| Family    | Registers | Native Width | Flag Model     | Dispatch Profile  | Call Convention |
| --------- | --------: | -----------: | -------------- | ----------------- | --------------- |
| Stack     |         8 |       64-bit | Lazy stack     | Call/return       | Stack frame     |
| Register  |        16 |       64-bit | Packed         | Direct threaded   | Register window |
| MixedRisc |        24 |       32-bit | Split          | Indirect threaded | Descriptor      |
| FusedCisc |        12 |       64-bit | Producer token | Distributed       | Continuation    |

These family descriptions act as part of the VM ABI/profile contract.

Function-family selection is deterministic from the build seed and a stable function identifier.

Conceptually:

```text
Program
 │
 ├── Function A ──► Stack
 │
 ├── Function B ──► Register
 │
 ├── Function C ──► MixedRisc
 │
 └── Function D ──► FusedCisc
```

---

# Cross-Family VM Bridge

When control moves between functions assigned to different VM families, BTG defines a canonical state representation for the transition.

The cross-family bridge uses a canonical register image and packed flags as an interchange ABI.

```text
Family A private state
        │
        ▼
Canonical VM State
        │
        ├── registers
        └── flags
        │
        ▼
Family B private state
```

This prevents a VM family from directly assuming that another family's private register layout or calling convention is identical.

---

# Polymorphic Virtual ISA

The Program-VM does not rely only on one permanently fixed opcode mapping.

The polymorphic layer generates build-dependent encoding information.

This includes mechanisms around:

```text
opcode mapping
virtual register mapping
condition encoding
operand encoding
family-specific domains
handler generation choices
rolling-key state
```

A different build seed can therefore alter the virtual representation even when the original native code is unchanged.

Conceptually:

```text
same input program
       │
       ├──── seed A ───► VM encoding A
       │
       ├──── seed B ───► VM encoding B
       │
       └──── seed C ───► VM encoding C
```

while the same deterministic seed can reproduce the same transformation decisions.

---

# Family-Scoped ISA Encoding

Each architecture family receives a separate ISA domain.

This allows family-local transformations to use different encoding behavior without accidentally mixing VM ABIs.

The family-specific ISA layer includes differing policies for areas such as:

```text
operand ordering
condition token representation
branch target representation
register encoding
domain separation
```

This is more than a single global:

```text
opcode → shuffled opcode
```

mapping.

The family identity participates in how VM data is represented.

---

# Native Threaded Runtime

The generated bytecode is consumed by native x86-64 VM runtime code.

Relevant implementation is primarily located under:

```text
src/vm/threaded/
src/vm/threaded/poly_direct/
```

The threaded VM layer contains infrastructure for:

```text
handler generation
handler layout
dispatch
VM context access
operand decoding
branch handling
native bridges
fault isolation tests
runtime integrity interaction
super-operation handling
```

The production Program-VM path therefore ultimately executes:

```text
VM bytecode
    │
    ▼
native decoder / dispatcher
    │
    ▼
generated native handlers
    │
    ▼
VM state mutation
    │
    ▼
next virtual instruction
```

rather than using a Rust interpreter inside the protected executable.

---

# Rolling-Key Bytecode

BTG contains rolling-key encoding for VM bytecode.

The decoding state evolves while bytecode is consumed rather than treating the entire bytecode stream as an independently XORed static array.

Conceptually:

```text
bytecode[n]
    +
state[n]
    │
    ▼
decode
    │
    ▼
instruction[n]
    │
    ▼
state[n + 1]
```

Control-flow changes require the VM to preserve or reconstruct the state associated with the target bytecode location.

This is integrated with VM branch metadata rather than assuming all virtual code executes linearly.

---

# Handler Polymorphism

Handler generation also contains code-generation strategy selection.

Defined strategies include:

```text
DirectRegister
InlineDecode
FusedDispatch
JunkPadded
```

The strategy can be selected from build-specific information rather than forcing every handler to use exactly one native implementation shape.

This provides an additional transformation layer beyond opcode permutation alone.

---

# Super-Operator / Fusion Infrastructure

The VM contains infrastructure for combining eligible operation sequences.

Instead of always executing:

```text
OP_A
dispatch

OP_B
dispatch

OP_C
dispatch
```

an eligible sequence can conceptually become:

```text
OP_ABC
dispatch
```

Fusion must respect semantic and control-flow boundaries.

The goal is to allow some RISC sequences to be represented by generated compound behavior rather than requiring a dispatcher transition for every primitive semantic operation.

---

# M7 — Runtime Re-Encryption

`--m7` enables the M7 protection path.

M7 has separate applicability rules depending on the selected execution mode.

The profile resolver supports M7 for:

```text
native mode
```

or:

```text
--vm --vm-oep --vm-commercial
```

It is not treated as a generic flag that can be meaningfully attached to every VM configuration.

In the runtime re-encryption path, protected units are stored encrypted and decrypted around their execution lifecycle.

The design goal is to reduce the amount of protected executable content simultaneously available as plaintext in memory.

For Program-VM configurations, M7 is integrated with the bytecode/runtime lifecycle rather than simply applying the native dispatcher implementation unchanged.

---

# M8 — Handler Table Concealment

`--m8` applies when VM functionality is active.

M8 protects VM handler table entries so that the table does not directly contain plainly readable native handler addresses.

The implementation combines keyed transformation with MBA-style reconstruction logic.

Conceptually:

```text
plain handler VA
       │
       ▼
keyed table representation
       │
       ▼
runtime key reconstruction
       │
       ▼
handler target
```

M8 is therefore focused specifically on VM runtime metadata rather than general PE encryption.

---

# Runtime Cryptography

BTG currently contains two main cryptographic paths:

```text
BTG-C1
ChaCha20
```

with Poly1305 support also present in the cryptographic subsystem.

## ChaCha20

The profile resolver currently selects:

```text
ChaCha20
```

when no explicit `--crypto-mode` is supplied.

For compatible bulk at-rest encryption configurations, the native boot path uses ChaCha20-compatible code and seed-derived key/nonce material.

```powershell
--crypto-mode chacha20
```

## BTG-C1

BTG-C1 is the project's custom stream-cipher-oriented protection primitive.

```powershell
--crypto-mode c1
```

The C1 implementation includes:

```text
state representation
key scheduling
round/permutation components
native implementation support
region encryption support
runtime integration
```

BTG-C1 is used by VM and runtime protection configurations that require the C1 native runtime ABI.

### Requested Mode vs Effective Mode

This distinction is important.

The resolver may request:

```text
ChaCha20
```

but some protection modes are not compatible with the current ChaCha20 boot/runtime implementation.

Current VM and runtime re-encryption paths therefore select the C1 runtime path when necessary.

Conceptually:

```text
Requested Crypto Mode
        │
        ▼
Protection Profile
        │
        ▼
Compatibility Resolution
        │
        ▼
Effective Runtime Crypto Mode
```

The build manifest records the effective protection state.

## RC4

RC4 is retired as a selectable production crypto mode.

```powershell
--crypto-mode rc4
```

is rejected by the CLI.

The legacy:

```powershell
--rc4
```

flag remains parseable only so old build scripts fail explicitly instead of silently selecting a different primitive.

---

# Integrity Protection

`--integrity` enables runtime integrity-related protection.

The VM integrity system defines protected-region classes including:

```text
FileImage
MappedImage
VmBytecode
HandlerCode
HandlerTable
NativeBridge
ResolvedApiPointers
```

This allows integrity metadata to describe different runtime objects instead of treating the complete binary as one undifferentiated checksum region.

Program-VM placement code can create integrity descriptors for VM components such as:

```text
handler code
handler tables
bytecode
```

The boot/runtime pipeline also performs integrity checks before transferring execution into protected program state.

---

# Import Hiding

```powershell
--iat-hide
```

enables runtime import resolution.

Instead of exposing the complete original API set through a conventional loader-visible import table, BTG can preserve only the bootstrap resolver requirements and reconstruct additional imports at runtime.

Conceptually:

```text
Windows Loader
      │
      ▼
minimal bootstrap imports
      │
      ▼
BTG import resolver
      │
      ▼
LoadLibraryA / GetProcAddress
      │
      ▼
original API addresses
      │
      ▼
reconstructed runtime IAT slots
```

This feature is designed to remain compatible with Program-VM ownership because the native/VM bridge and import resolver can reference the same reconstructed original IAT slots.

---

# Memory Hardening

```powershell
--mem-harden
```

separates memory that should remain immutable after initialization from memory that must stay writable.

The intended runtime transition is approximately:

```text
bootstrapping
     │
     ▼
decrypt / initialize
     │
     ▼
integrity verification
     │
     ├──────── executable immutable regions ─────► RX
     │
     └──────── mutable VM/runtime state ─────────► RW
```

This is especially important for Program-VM mode because VM bytecode and handler-related data have different mutability requirements from VM context and call-stack state.

Runtime memory-protection failures are designed to fail closed.

---

# `--mem-harden` vs `--dispatcher-reencrypt`

Native dispatcher re-encryption requires transformed native code pages to remain writable because blocks are repeatedly decrypted and re-encrypted.

That conflicts with sealing those pages RX.

The resolver therefore gives:

```text
--dispatcher-reencrypt
```

precedence over:

```text
--mem-harden
```

for that native configuration.

A warning is generated when the requested profile must be adjusted.

With:

```powershell
--strict-profile
```

such a downgrade becomes an error instead of being silently accepted.

---

# Payload Relocation

```powershell
--payload-relocate
```

moves protected payload storage away from the normal executable-code layout into non-executable data storage.

The boot/runtime layer is responsible for obtaining the payload from its storage location and preparing its runtime form.

This reduces the need to store the protected payload directly as ordinary executable section content.

---

# Resource Registration

```powershell
--rsrc-register
```

registers the relocated payload as an `RT_RCDATA` resource.

This requires:

```powershell
--payload-relocate
```

The profile resolver treats:

```text
--rsrc-register without --payload-relocate
```

as an invalid configuration.

BTG reconstructs the resource tree rather than simply replacing every existing resource with the payload.

---

# Anti-Debugging

```powershell
--anti-debug
```

enables generated anti-debug checks.

The current native anti-debug implementation includes checks based on:

```text
PEB.BeingDebugged
PEB.NtGlobalFlag
ProcessHeap.Flags
```

Detection behavior is controlled with:

```powershell
--anti-debug-policy <MODE>
```

Supported modes are:

| Policy   | Behavior                                |
| -------- | --------------------------------------- |
| `trap`   | Execute an invalid-instruction trap     |
| `hang`   | Enter an intentional loop               |
| `warn`   | Continue normally                       |
| `poison` | Continue through a state-poisoning path |

Default:

```text
trap
```

---

# Protection Profile Resolver

BTG does not apply every CLI flag independently.

The requested options are first converted into an **effective protection profile**.

This layer resolves:

```text
dependencies
incompatible combinations
implicit options
runtime requirements
feature precedence
effective crypto mode
VM applicability
```

For example:

```text
--vm-oep
```

implies the VM infrastructure.

Meanwhile:

```text
--dispatcher-reencrypt + --mem-harden
```

requires a policy decision because writable native code conflicts with final RX sealing.

And:

```text
--rsrc-register
```

requires:

```text
--payload-relocate
```

---

# Strict Profile Validation

Use:

```powershell
--strict-profile
```

when the command should fail instead of accepting a profile downgrade.

Without strict mode:

```text
requested configuration
        │
        ▼
resolver
        │
        ├── valid ─────► use feature
        │
        └── conflict ──► warning / adjustment
```

With strict mode:

```text
requested configuration
        │
        ▼
resolver
        │
        ├── exact ─────► continue
        │
        └── warning ───► fail
```

This is especially useful for automated experiments where silently disabling one protection would make the resulting sample invalid for comparison.

---

# `--full`

`--full` is the high-protection **native CFG bundle**.

It does **not** automatically select whole-program virtualization.

The bundle requests the equivalent of:

```text
obfuscation level 3
anti-debug
dispatcher re-encryption
integrity
payload relocation
resource registration
IAT hiding
memory hardening
```

However, the effective profile still follows compatibility rules.

For example:

```text
dispatcher re-encryption
```

takes precedence over native:

```text
memory hardening
```

because the former requires writable transformed code.

To request Program-VM virtualization, use:

```powershell
--vm --vm-oep --vm-commercial
```

explicitly.

---

# Dispatcher Re-Encryption

The native:

```powershell
--dispatcher-reencrypt
```

path encrypts transformed basic-block storage individually.

The dispatcher participates in the block lifecycle so that blocks can be decrypted around execution and re-encrypted afterward.

The option requires the cryptographic layer.

Therefore:

```powershell
--dispatcher-reencrypt --no-crypto
```

is rejected.

Dispatcher re-encryption also forces effective code encryption coverage to 100%.

---

# Obfuscation Levels

```powershell
--obf-level <N>
```

controls native transformation intensity.

Current CLI levels are:

| Level | Description                                       |
| ----: | ------------------------------------------------- |
|   `1` | Basic transformation                              |
|   `2` | MBA-oriented transformation                       |
|   `3` | Overlapping/MBA-oriented maximum configured level |

Default:

```text
3
```

`--full` also forces level 3.

---

# Deterministic Builds

BTG uses deterministic random generation when a build seed is supplied.

```powershell
--seed 31010
```

The seed is used across transformation components such as:

```text
layout randomization
block shuffling
MBA constants
VM polymorphism
crypto-derived values
padding/layout choices
```

This is valuable for:

```text
debugging
regression testing
VM comparison
multi-seed experiments
reproducible crash analysis
```

---

# Output Verification

BTG can execute the original and protected binaries after packing.

Enable it with:

```powershell
--verify-output
```

The differential verifier captures:

```text
exit code
stdout bytes
stderr bytes
```

from both processes.

The protected program passes only if all three are equivalent.

Conceptually:

```text
             ┌──► Original PE ───► Result A
Input ───────┤
             └──► Protected PE ──► Result B

Result A
   │
   ▼
exit / stdout / stderr
   │
   ▼
byte-for-byte comparison
   │
   ├── identical ──► PASS
   └── different ──► FAIL
```

Process timeout is configurable:

```powershell
--verify-timeout-secs 30
```

---

# Multi-Seed Verification

```powershell
--verify-seeds N
```

runs multiple independent seeded pack-and-verification jobs.

Each generated build receives its own deterministic seed and performs output verification.

This is useful for detecting transformation bugs that only occur under certain randomized layouts or virtual-ISA configurations.

Conceptually:

```text
Input
 │
 ├── Seed 1 ──► Pack ──► Execute ──► Verify
 │
 ├── Seed 2 ──► Pack ──► Execute ──► Verify
 │
 ├── Seed 3 ──► Pack ──► Execute ──► Verify
 │
 └── Seed N ──► Pack ──► Execute ──► Verify
```

A single failed child build causes the multi-seed gate to fail.

---

# Post-Build Validation

BTG reparses and validates the image it creates.

Validation is not limited to checking whether the output file exists.

The validation layer checks areas including:

```text
PE layout
section ranges
directories
relocations
resource layout
Program-VM metadata
ownership information
requested protection capabilities
measured virtualization coverage
```

This allows BTG to catch cases where a transformation pass completed but the final PE does not actually contain the protection state that was requested.

---

# Build Manifest

BTG can generate a:

```text
.btgmanifest
```

artifact containing information about the build.

Manifest-related data includes areas such as:

```text
input hash
output hash
build seed
build identity
enabled protection features
effective crypto information
Program-VM information
runtime cipher information
integrity state
execution verification result
```

SHA-256 is used for build artifact hashing.

---

# Diagnostic Mapping

BTG contains several optional mapping/report outputs for debugging transformed binaries.

## Instruction Map

```powershell
--map
```

produces:

```text
<output>.map
```

containing VM bytecode/source mapping information.

It is intended to help translate a VM-side fault location back to an original native instruction.

---

## Symbolic Map

```powershell
--sym-map
```

produces:

```text
<output>.sym
```

and enables instruction mapping as well.

It tracks higher-level relationships such as:

```text
VM block range
original basic block
function ownership
original instruction range
```

---

## Ownership Report

Commercial Program-VM builds can generate:

```text
<output>.ownership.csv
```

describing VM/native ownership decisions.

This is useful when investigating why a particular function was not virtualized.

---

## RISC Map

The Program-VM pipeline can also emit:

```text
<output>.riscmap.csv
```

for analysis of native-to-RISC transformation relationships.

---

# Build

BTG targets Windows x86-64.

Required development environment:

```text
Windows x86-64
Rust
Cargo
rustup
MSVC-compatible Windows toolchain
```

Build:

```powershell
cargo build --release
```

Run the full test targets:

```powershell
cargo test --all-targets
```

Release binary:

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

Short form:

```powershell
target\release\btg-packer.exe `
    -i .\app.exe `
    -o .\app.protected.exe
```

---

# Recommended Program-VM Example

A high-feature Program-VM configuration:

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

This configuration requests:

```text
Program-VM OEP transfer
commercial RISC/poly/threaded backend
full Program-VM coverage validation
multi-family VM planning
polymorphic virtual ISA
rolling-key bytecode
M7 runtime protection
M8 handler-table concealment
memory hardening
runtime import reconstruction
integrity verification
payload relocation
RT_RCDATA registration
BTG-C1 runtime protection
anti-debug checks
strict protection-profile resolution
post-build execution verification
deterministic transformation seed
```

---

# Important Option Relationships

Some options have explicit dependencies or precedence rules.

### Resource registration

```text
--rsrc-register
        │
        └── requires ──► --payload-relocate
```

### Program VM

```text
--vm-oep
   │
   └── implies VM infrastructure
```

Commercial backend:

```text
--vm
--vm-oep
--vm-commercial
```

### M7

Supported effective configurations include:

```text
native + crypto + M7
```

or:

```text
VM + VM-OEP + VM-commercial + crypto + M7
```

### M8

```text
M8 requires VM to be active.
```

### Native dispatcher re-encryption

```text
--dispatcher-reencrypt
        │
        ├── requires crypto
        │
        ├── overrides partial crypto coverage
        │
        └── conflicts with final native RX sealing
```

### Strict mode

```text
--strict-profile
```

turns profile adjustment warnings into build failures.

### Partial VM

```text
--allow-partial-vm
```

is development-only and conflicts with:

```text
--strict-profile
```

---

# CLI Reference

| Option                       |             Default | Description                                               |
| ---------------------------- | ------------------: | --------------------------------------------------------- |
| `-i, --input <PATH>`         |  `dummy_target.exe` | Input PE32+ executable                                    |
| `-o, --output <PATH>`        | `protected_btg.exe` | Output protected executable                               |
| `--strict-profile`           |                 off | Reject requested protection downgrades                    |
| `--allow-partial-vm`         |                 off | Allow incomplete commercial VM coverage for development   |
| `--verify-output`            |                 off | Execute and compare original/protected binaries           |
| `--verify-timeout-secs <N>`  |                `30` | Verification process timeout                              |
| `--verify-seeds <N>`         |                 `0` | Run N seeded build/verification jobs                      |
| `--seed <U64>`               |              random | Deterministic transformation seed                         |
| `-l, --obf-level <N>`        |                 `3` | Native obfuscation level                                  |
| `-a, --anti-debug`           |                 off | Enable anti-debug runtime checks                          |
| `--anti-debug-policy <MODE>` |              `trap` | `trap`, `hang`, `warn`, or `poison`                       |
| `-t, --test-qa`              |                 off | Run automated QA suite                                    |
| `--qa-commercial`            |                 off | Run QA through commercial Program-VM                      |
| `--qa-gen-corpus`            |                 off | Generate compiler-profile QA corpus                       |
| `-d, --debug`                |                 off | Enable detailed logging                                   |
| `-g, --log-file <PATH>`      |                none | Write log output to a file                                |
| `--trace-blocks`             |                 off | Inject runtime block tracing                              |
| `--no-crypto`                |                 off | Disable normal crypto layer                               |
| `--vm`                       |                 off | Enable VM/crypto infrastructure                           |
| `--vm-test`                  |                 off | Run VM self-tests                                         |
| `--text-vm`                  |                 off | Report block-level lift capability                        |
| `--text-vm-oep`              |                 off | Analyze OEP-reachable VM lift coverage                    |
| `--payload-relocate`         |                 off | Relocate protected payload into non-executable data       |
| `--rsrc-register`            |                 off | Register relocated payload as `RT_RCDATA`                 |
| `--crypto-coverage <N>`      |               `100` | Requested protected code percentage                       |
| `--chained-crypto`           |                 off | Enable chained legacy crypto lifecycle path               |
| `--integrity`                |                 off | Enable integrity protection                               |
| `--iat-hide`                 |                 off | Reconstruct original API imports at runtime               |
| `--mem-harden`               |                 off | Apply post-bootstrap memory permission separation         |
| `--dispatcher-reencrypt`     |                 off | Native block decrypt/re-encrypt lifecycle                 |
| `--full`                     |                 off | Enable native maximum-protection bundle                   |
| `--vm-oep`                   |                 off | Transfer original entry execution into Program-VM         |
| `--vm-commercial`            |                 off | Select RISC → poly → threaded Program-VM backend          |
| `--m7`                       |                 off | Runtime encrypted lifecycle protection                    |
| `--m8`                       |                 off | VM handler-table concealment                              |
| `--vm-bench`                 |                 off | Run VM interpreter/native benchmark                       |
| `--map`                      |                 off | Generate VM instruction map                               |
| `--sym-map`                  |                 off | Generate symbolic block/function map                      |
| `--keep-pdata`               |                 off | Preserve original `.pdata` without dispatcher unwind leaf |
| `--block-ring`               |                 off | Add recent-dispatch diagnostic ring buffer                |
| `--custom-cipher`            |                 off | Explicitly request BTG custom cipher compatibility path   |
| `--rc4`                      |               error | Retired compatibility flag                                |
| `--crypto-mode <MODE>`       |         `chacha20`* | Request `c1` or `chacha20`                                |

`*` The profile resolver currently defaults to ChaCha20 when no mode is supplied. Some VM/runtime protection configurations use the C1 native runtime as their effective cryptographic path.

Full CLI help:

```powershell
target\release\btg-packer.exe --help
```

---

# QA Infrastructure

BTG contains a substantial internal testing and QA layer.

The supplied source snapshot contains approximately:

```text
294 Rust source files
123,000+ lines of Rust
700+ #[test] annotations
```

These numbers describe the current source snapshot and are not intended as a measure of security quality.

Testing covers areas such as:

```text
PE transformation
RISC semantics
virtual registers
flags
branches
memory operations
atomic operations
VM encoding
native handlers
fault isolation
crypto primitives
integrity descriptors
protection-profile resolution
PE validation
deterministic behavior
execution differential testing
```

Useful commands include:

```powershell
cargo test --lib
```

```powershell
cargo test --all-targets
```

```powershell
target\release\btg-packer.exe --vm-test
```

```powershell
target\release\btg-packer.exe --vm-bench
```

```powershell
target\release\btg-packer.exe --qa-gen-corpus
```

```powershell
target\release\btg-packer.exe --test-qa
```

Commercial Program-VM QA:

```powershell
target\release\btg-packer.exe `
    --test-qa `
    --qa-commercial
```

---

# Project Layout

```text
src/
│
├── analysis/
│   ├── program model construction
│   ├── indirect target analysis
│   ├── code-pointer analysis
│   ├── switch analysis
│   ├── CRT analysis
│   └── pointer-table analysis
│
├── pe/
│   ├── PE parsing
│   ├── PE building
│   ├── relocation handling
│   ├── TLS handling
│   ├── load configuration
│   ├── exports
│   └── unwind / exception metadata
│
├── graph/
│   └── CFG-related analysis and transformation
│
├── assembler/
│   └── native code generation / encoding support
│
├── dispatcher/
│   ├── dispatcher generation
│   ├── validation
│   ├── anti-debug integration
│   ├── re-encryption
│   └── M7 runtime support
│
├── pipeline/
│   ├── pass1_slice
│   ├── pass2_shuffle
│   ├── pass3_encode
│   ├── pass4_section
│   ├── ownership
│   ├── IAT hiding
│   ├── resource registration
│   ├── validation
│   └── crypto/
│       ├── boot stub
│       ├── payload placement
│       ├── encryption
│       ├── integrity
│       ├── IAT reconstruction
│       ├── memory hardening
│       └── Program-VM embedding
│
├── vm/
│   ├── lifter/
│   │   └── x86-64 → RISC
│   │
│   ├── risc/
│   │   ├── semantic IR
│   │   ├── optimizer
│   │   └── evaluation
│   │
│   ├── poly/
│   │   ├── architecture families
│   │   ├── ISA generation
│   │   ├── operand encoding
│   │   └── polymorphic mapping
│   │
│   ├── threaded/
│   │   ├── native runtime
│   │   ├── handler generation
│   │   ├── poly-direct backend
│   │   └── native fault testing
│   │
│   ├── multi_family.rs
│   ├── distributed_integrity.rs
│   ├── handler_poly.rs
│   ├── data_lifetime.rs
│   ├── ownership_verifier.rs
│   └── route metadata / VM bridges
│
├── crypto/
│   ├── BTG-C1 components
│   ├── ChaCha20
│   ├── Poly1305
│   ├── key scheduling
│   ├── native crypto support
│   └── region encryption
│
├── differential.rs
│   └── original/protected execution comparison
│
├── multi_seed.rs
│   └── seeded verification jobs
│
├── manifest.rs
│   └── build manifest / SHA-256 metadata
│
├── protection_profile.rs
│   └── requested → effective protection resolution
│
└── main.rs
    └── CLI orchestration
```

---

# Current Limitations

BTG Packer is still a research prototype.

It should not be described as having universal PE compatibility.

Current limitations include:

* Windows x86-64 PE32+ is the primary target.
* Kernel-mode binaries are outside the current target model.
* Unsupported x86 semantics cannot safely receive VM ownership.
* Complex SEH, panic and non-local-control-flow boundaries require conservative handling.
* VM coverage depends on the instruction patterns generated by the source compiler.
* Some unusual PE layouts can still expose parser/reconstruction edge cases.
* TLS structures whose runtime storage resides in zero-filled virtual section tails require careful RVA handling.
* PE metadata generated by unusual toolchains may require additional compatibility work.
* Program-VM support should be evaluated with execution verification for each target compiler/profile.
* BTG-C1 is a custom research primitive and has not received independent cryptographic review.
* A successful transformation does not imply resistance against a skilled reverse engineer.
* Diagnostic artifacts such as maps and ownership reports expose internal transformation information and should not normally accompany distributed protected binaries.

---

# Security Model

BTG attempts to increase the amount of work required to reconstruct transformed program logic.

It does **not** claim that protected code becomes impossible to reverse engineer.

A local attacker that can execute the program can ultimately observe some form of runtime state.

The project therefore treats protection as layered transformation rather than absolute secrecy:

```text
program analysis
      +
control-flow transformation
      +
program virtualization
      +
build polymorphism
      +
runtime encryption
      +
metadata concealment
      +
integrity checking
      +
memory policy
```

The purpose of these layers is to increase analysis cost while preserving executable behavior.

---

# What BTG Is Not

BTG is not intended to claim:

* mathematically unbreakable software protection
* guaranteed malware-analysis resistance
* universal x86-64 virtualization
* compatibility with every Windows PE
* equivalence to mature commercial protectors
* audited cryptographic security for BTG-C1

The repository should be treated as an experimental binary-transformation and virtualization framework.

---

# Research Areas

BTG can be useful for experimentation involving:

```text
binary rewriting
PE internals
control-flow reconstruction
program virtualization
virtual instruction-set design
compiler-generated x86 analysis
RISC intermediate representations
runtime code generation
VM dispatch strategies
software-protection research
binary hardening
differential testing
deterministic randomized builds
```

---

# Development Workflow

A useful development cycle is:

```text
1. Build
2. Run unit tests
3. Analyze target lift coverage
4. Pack with a deterministic seed
5. Enable output verification
6. Inspect ownership and mapping artifacts
7. Repeat with multiple seeds
```

Example:

```powershell
cargo test --all-targets
```

```powershell
btg-packer.exe `
    -i .\target.exe `
    -o .\target.protected.exe `
    --text-vm-oep
```

Then:

```powershell
btg-packer.exe `
    -i .\target.exe `
    -o .\target.protected.exe `
    --vm `
    --vm-oep `
    --vm-commercial `
    --integrity `
    --iat-hide `
    --mem-harden `
    --seed 31010 `
    --verify-output
```

Finally, after one deterministic build is stable:

```powershell
btg-packer.exe `
    -i .\target.exe `
    -o .\target.protected.exe `
    --vm `
    --vm-oep `
    --vm-commercial `
    --verify-seeds 10
```

This workflow is generally more useful for development than immediately enabling every protection option at once.

---

# Responsible Use

BTG Packer is intended for:

* software-protection research
* compiler and VM experimentation
* PE transformation research
* authorized reverse-engineering research
* CTF and educational environments
* testing software that you own or are permitted to modify

Do not use the project to modify, conceal, distribute or protect software without authorization.

---

# License

BTG Packer is distributed under the **Apache License, Version 2.0**.

See:

```text
LICENSE
```

for the complete license text.

Security-related reports should follow the process documented in:

```text
SECURITY.md
```

---

<p align="center">
  <b>BTG Packer</b><br>
  x86-64 → RISC → Polymorphic Program-VM → Native Threaded Runtime
</p>
