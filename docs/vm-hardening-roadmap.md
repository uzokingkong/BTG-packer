# Commercial VM correctness and hardening roadmap

## Objective

Raise the cost of reusable static devirtualization without weakening execution
correctness. The security target is correlation resistance and extraction-cost
amplification; an offline executable cannot provide absolute key secrecy when it
contains everything required to run.

## Non-negotiable gates

Every implementation phase must preserve all of the following:

- `cargo test commercial --lib` passes.
- The protected test program produces the same 16 stage values and final checksum
  as the original program for seeds 1, 2, and 3 in headless mode.
- All protected headless runs exit with code 0.
- GUI mode reaches initialization and exits normally after its automatic close.
- `git diff --check` passes and diagnostic artifacts are not committed.

The canonical checksum is `0x2cdc0e4511d84a64`. Stage 8 is now bit-exact after
excluding direct constant-pool loads from call-scoped lifetime encryption. The
remaining C0 gate is GUI lifecycle verification across seeds 1, 2, and 3.

### C0 findings fixed in the working tree

- Cross-family CALL return publication now preserves guest nonvolatile GPRs;
  tail-JUMPs still publish them as architectural continuation state.
- Cross-family tail-JUMPs inherit an existing negative VSP continuation instead
  of inserting a family-exit sentinel ahead of it. A sentinel is synthesized
  only for top-level tail transfers with an empty VSP.
- This fixes the seed-2 `String::write_char` failure where `__rust_alloc` tail-
  jumped from FusedCisc to Stack and skipped the caller's post-allocation code.
- Commercial module tests and the focused lifetime/stack-argument regressions
  pass. Seed 2 no longer faults at the previous GUI AV site; normal automatic
  GUI exit is still being timed because this seed runs substantially slower.

## Ordered work

### C0 — Restore bit-exact execution equivalence

1. Add a reusable verifier that compares each stage value, checksum, exit code,
   and GUI lifecycle against the unprotected executable.
2. Trace the first stage-8 divergence through CRT CPU-feature initialization,
   CPUID/native-call bridges, and cross-family state publication.
3. Validate guest GPR, RFLAGS, XMM, RSP, and unwind state at every child/parent
   boundary; distinguish CALL from tail-JUMP semantics.
4. Fix the first proven state divergence and rerun seeds 1, 2, and 3.

Exit criterion: all values and process exit behavior match the original.

### H1 — Remove original-VA identity from direct VM branches

1. Assign unpredictable build-local block tokens after lifting.
2. Rewrite same-family direct branches to local tokens or encoded relative
   bytecode offsets.
3. Rewrite cross-family direct branches to opaque route IDs.
4. Stop serializing every `ip_map` entry into the runtime branch map.
5. Retain a separate sparse translation structure only for proven dynamic
   indirect and native-bridge targets.

Exit criterion: a static extractor cannot recover the complete
`original VA -> VM offset` relation from branch metadata.

### H2 — Remove the original `.text` semantic oracle

1. Classify the remaining native functions by relocation constraints.
2. Relocate supported native functions, unwind records, RIP-relative references,
   function pointers, and jump tables into dedicated islands.
3. Replace VM-owned original code bytes with trap/randomized non-code data.
4. Make the original VM-owned `.text` pages non-executable.
5. Keep only narrowly scoped islands for functions that cannot yet be moved.

Exit criterion: no VM-owned function retains executable original x64 bytes.

### H3 — Make bulk chunk-key extraction stateful

1. Replace colocated XOR key shares with a per-chunk authenticated key chain.
2. Bind derivation to mutable invocation state and the preceding authenticated
   chunk state.
3. Split lookup, reconstruction, and byte-unmasking across independently
   generated fragments.
4. Erase operational key material after each byte/instruction use.

Exit criterion: normalizing one decoder path does not reveal every chunk key.

### H4 — Reduce handler semantic fingerprints

1. Generate build-specific superhandlers for frequent micro-op sequences.
2. Provide multiple equivalent implementations per semantic operation.
3. Vary operand framing and decoder grammar per family.
4. Mix sparse, two-level, and direct-threaded dispatch layouts.
5. Remove stable wrapper-to-common-body shapes.

Exit criterion: handler clustering from one build/family transfers poorly to
another build/family.

### H5 — Add attacker-oriented regression metrics

Record and gate:

- recoverable original-VA mappings;
- executable original bytes belonging to VM-owned functions;
- statically recoverable chunk keys;
- handler-body clustering success;
- opcode/VReg matcher transfer rate across seeds;
- statically reconnectable cross-family edges.

## Immediate implementation order

1. C0 verifier and baseline capture.
2. C0 first-divergence diagnosis and fix.
3. H1 direct-branch token model and unit tests.
4. H1 sparse indirect map integration.
5. H2 native-island feasibility slice.
6. H3 and H4 only after C0/H1/H2 gates remain stable.
