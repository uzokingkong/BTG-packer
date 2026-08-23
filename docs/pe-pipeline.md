# PE Transformation Pipeline

## Why PE reconstruction matters

Moving or virtualizing code changes more than instruction bytes. Windows PE metadata can contain addresses or ranges that refer back into executable code, and the Windows loader can modify selected regions before the entry point runs.

BTG therefore parses and reconstructs PE structures as part of the transformation rather than treating them as unrelated metadata.

## PE subsystem

`src/pe/` contains dedicated components for:

```text
parser.rs       PE32+ parsing and TargetPeInfo
builder.rs      final image/section construction
reloc.rs        base-relocation handling
unwind.rs       x64 unwind / exception metadata
load_config.rs  load-configuration handling
exports.rs      export metadata
tls.rs          TLS metadata and callbacks
dummy_gen.rs    development dummy target generation
```

The parser extracts the original image information consumed by both analysis and reconstruction.

## Analysis before rewriting

The analysis subsystem extends basic PE parsing with program-oriented discovery. Important examples are code pointers, pointer tables, indirect targets, switch targets/producers, CRT structures and value flow.

This is required because not every reference to executable code appears as a direct `call rel32` or `jmp rel32` in `.text`.

## Native CFG passes

The native transformation pipeline is split into explicit passes:

```text
Pass 1  discover and slice transformable blocks
Pass 2  shuffle physical layout
Pass 3  encode blocks and repair control transfers
Pass 4  assemble generated section data
Patch   update affected references/data
Build   reconstruct final PE and runtime regions
```

The pass separation lets each stage consume structured results from the previous one rather than repeatedly rediscovering the program.

## Branch relocation

Moving native blocks requires rebuilding location-dependent control transfers, including direct calls, jumps and conditional branches.

Conceptually:

```text
old source VA + old displacement = old target
new source VA + new displacement = intended target
```

The encoder computes the new displacement from the transformed layout rather than preserving the old immediate bytes.

## RIP-relative operands

x86-64 commonly addresses static data through RIP-relative operands. Relocating an instruction without repairing the displacement changes the referenced object.

BTG therefore tracks and patches these references during transformed native encoding/data repair.

## Generated sections

Depending on the selected profile, the final image can include generated regions for:

```text
transformed native code / dispatcher
boot/runtime code
Program-VM code, tables and bytecode
mutable VM state
relocated encrypted payload
bootstrap IAT data
route metadata
rebuilt resources
```

The pipeline stores these as explicit artifacts in `PipelineContext` before final image assembly.

## Payload relocation

`--payload-relocate` moves encrypted code payload material into a non-executable data-oriented region rather than requiring the original executable code area to remain the at-rest payload container.

`--rsrc-register` can additionally expose that relocated payload as formal `RT_RCDATA`; it therefore requires payload relocation to be active.

## Imports and bootstrap IAT

When IAT hiding is requested, BTG preserves enough bootstrap import capability to resolve required APIs while replacing the original import exposure used by the application.

Loader-populated bootstrap IAT slots are tracked separately because Windows writes import slots before OEP. They must not be accidentally placed inside immutable ciphertext or an executable region whose at-rest integrity assumes the loader will not mutate it.

## Relocations and ciphertext

The pipeline tracks exact at-rest ciphertext RVA ranges. This matters because the Windows loader applies base relocations before OEP. A relocation entry targeting ciphertext would mutate encrypted bytes and invalidate decryption/integrity assumptions.

Conversely, generated plain runtime address operands outside ciphertext still need correct DIR64 relocation support when ASLR changes the image base.

## TLS

TLS metadata and callbacks can execute before the normal application entry point. PE transformation therefore needs to preserve or rebuild TLS information rather than assuming OEP is always the first application-controlled execution point.

## x64 exception metadata

Windows x64 exception handling uses `.pdata` `RUNTIME_FUNCTION` records and associated unwind information. Generated VM/runtime regions and native-call bridges can require their own unwind representation, while original entries may need preservation.

`--keep-pdata` requests byte-preservation of the original `.pdata` behavior; otherwise the normal pipeline can preserve original entries while adding generated runtime coverage where required.

For Program-VM, the context records VM program ranges, native bridge ranges and a generated cleanup-handler RVA used by bridge unwind/lifetime handling.

## Load configuration

The load-configuration directory can contain security-related metadata whose addresses and tables must remain consistent with the rebuilt image. BTG has a dedicated `load_config.rs` path rather than leaving this structure as an opaque copy.

## Resources

Resource reconstruction is used by the relocated-payload registration path. The final resource directory RVA/size are persisted in the pipeline context and written into the resulting PE directories.

## Entry point

The final entry point depends on the effective profile. Native protected builds enter generated bootstrap/dispatcher logic before reaching transformed application code. Program-VM OEP mode instead redirects startup into the embedded program VM execution path.

The final PE builder is responsible for making the entry point agree with the generated section layout and runtime contract.

## Validation boundary

A PE that parses successfully is not necessarily correct. After reconstruction BTG performs structural/capability checks that connect final PE layout back to transformation intent—for example executable-range ownership, relocation behavior, VM coverage and protection metadata.

See [Validation and Development](validation-development.md) for the validation contract.
