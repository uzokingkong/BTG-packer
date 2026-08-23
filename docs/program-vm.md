# Program-VM

## Purpose

BTG's Program-VM path virtualizes supported program semantics rather than mapping every original x86 instruction directly to one permanent VM opcode.

```text
x86-64
  -> decode
  -> RISC semantic IR
  -> validation / transformation
  -> VM-family representation
  -> polymorphic ISA
  -> rolling-key bytecode
  -> native threaded execution
```

The commercial path is enabled by the effective combination of `--vm`, `--vm-oep` and `--vm-commercial` with the crypto layer available.

## Lifter organization

The x86-64 lifter is split by semantic area under `src/vm/lifter/` rather than implemented as one monolithic opcode switch. Current source areas include:

```text
arith.rs      arithmetic/logical semantics
shift.rs      shifts/rotates
muldiv.rs     multiply/divide families
mem.rs        memory operations
control.rs    control transfer
cfg.rs        CFG-aware lifting
sse.rs        selected SIMD/SSE semantics
string.rs     string-instruction semantics
ir.rs         lifter IR structures
mod.rs        dispatch/coordination and additional semantics
```

The VM directory also contains canonical semantics and runtime/state helpers so that the interpreter, encoder and native runtime can share a common semantic contract.

## RISC intermediate representation

The key design rule is:

```text
original x86 encoding != final VM encoding
```

An x86 instruction is decoded into semantic operations. Those operations can then be transformed, assigned to a family-specific backend and encoded using build-local opcode/register/operand mappings.

This provides a clean boundary between x86 decoding correctness and VM representation diversity.

## Capability checking

A decoded instruction being recognized is not enough to claim that it can execute in the production VM. The pipeline tracks evidence across decode, semantic registry, lift and encode/runtime capability layers.

Commercial coverage metrics explicitly include:

```text
unsupported_instructions
capability_mismatches
unresolved_internal_edges
```

`None` is deliberately different from measured zero for these evidence fields. Full commercial policy requires positive evidence that the relevant failure count was actually measured as zero.

## Function ownership

Functions are assigned an authoritative ownership decision. Typical reasons for native ownership include semantic or control-flow conditions that prevent safe whole-function virtualization.

The ownership layer exists to prevent a partial or ambiguous function from being counted as fully virtualized merely because some of its blocks could be lifted.

Ownership also propagates through semantic dependencies where required: a function can become native-owned because a dependency cannot be represented safely even if the function's local instructions appear individually liftable.

## Commercial coverage

The pipeline records:

```text
vm_functions / total_functions
vm_blocks / total_blocks
vm_instructions / total_instructions
unresolved_internal_edges
unsupported_instructions
capability_mismatches
```

The normal commercial contract is intentionally fail-closed. A generated VM module is not sufficient proof of complete virtualization; measured original-program ownership must satisfy the configured coverage gate.

`--allow-partial-vm` is the explicit development escape hatch for incomplete coverage and is incompatible with strict-profile operation.

## Multi-family architecture

The Program-VM contains architecture-family support rather than relying only on a single VM with shuffled opcode numbers. Family planning assigns stable function ownership to backend families, creates family-specific operation partitions and materializes cross-family routes.

The source-level architecture includes family planning/partition artifacts in `PipelineContext`:

```text
vm_family_plan
vm_family_partitions
vm_multi_family
```

The purpose is to make family selection part of the VM ABI and execution plan, not just cosmetic opcode permutation.

## Canonical cross-family state

Different VM families may use different private state layouts. Cross-family transfer therefore needs an interchange representation rather than allowing one family to assume another family's private register layout.

Conceptually:

```text
Family A private state
        |
        v
canonical register/flag state
        |
        v
Family B private state
```

Generated route metadata records destinations needed for these transitions and is emitted separately from mutable VM state.

## Polymorphic encoding

The polymorphic layer can vary build-local representation such as opcode assignment, operand/register mapping, condition encoding, table layout and runtime decode state.

A seed therefore participates in the VM representation:

```text
same program + seed A -> encoding A
same program + seed B -> encoding B
same program + seed A -> reproducible encoding A
```

## Commercial module layout

`commercial_build.rs` wraps the encoded program in a `VmModule` with three principal blobs:

```text
code      native self-decoding dispatcher, handlers and bridge logic
table     handler/operand/condition/branch metadata
bytecode  polymorphic rolling-key encoded instruction stream
```

The table layout is itself seed-derived. The runtime and table builder share the same `TableLayout`, making layout part of the build ABI rather than a permanently fixed file signature.

## Rolling-key runtime

The commercial native runtime uses a self-decoding execution path. Conceptually each dispatch step:

```text
read encoded byte at VIP
  -> derive current rolling-key byte
  -> recover opcode/operand data
  -> advance decode state
  -> resolve generated handler metadata
  -> execute semantic handler
  -> continue dispatch
```

The embedded runtime initializes dedicated native registers for bytecode base, VIP, virtual stack, rolling-key state, handler-table base and VM state. Callee-saved registers used by the runtime are preserved around VM entry/exit.

## VM state and virtual stack

Commercial state uses a fixed runtime state area plus a separately reserved virtual stack region. The virtual stack is placed so that VM push/pop activity does not collide with state or bytecode storage.

The pipeline also supports splitting mutable VM state from executable generated code so PE section permissions can represent W^X policy more accurately.

## VM/native bridge

Whole-program virtualization still needs a defined transition when execution must interact with native-owned code or native ABI behavior. BTG records generated native bridge ranges and associated unwind/lifetime-cleanup metadata.

Bridge ranges are treated as generated runtime code. They are not evidence that an original function remained native-owned.

## M7 bytecode lifetime

Commercial Program-VM mode can use instruction-aligned bytecode chunks for M7 runtime lifetime protection. Chunk metadata is carried through the pipeline and can be sealed by integrity descriptors over the exact runtime representation.

## M8 concealment

M8 is enabled only when VM support is effective. It is intended to conceal VM handler-table addressing using MBA-derived representation rather than leaving straightforward table addresses as the only lookup representation.

## Diagnostics

Useful Program-VM development commands are:

```text
--vm-test
--vm-bench
--text-vm
--text-vm-oep
--map
--sym-map
```

The map outputs are especially useful for relating generated bytecode offsets and blocks back to original virtual addresses during crash triage.
