# Runtime Protection

## Protection profile resolution

Runtime features are not independent booleans. `src/protection_profile.rs` resolves requested CLI options into the configuration actually consumed by the pipeline.

The important model is:

```text
requested options -> policy resolution -> effective protection profile
```

This avoids spreading feature-conflict logic throughout PE building and VM code.

## Crypto layer

The crypto layer is enabled by default. The current selectable primitives are:

```text
chacha20  default modern stream-cipher path
c1        BTG-C1 custom research cipher path
```

RC4 has been retired. `--rc4` is retained only as a compatibility input that produces a hard migration error.

Crypto-related source is under `src/crypto/`, including ChaCha20, Poly1305/MAC support, key scheduling, native generated implementations, provider selection, region encryption and tests.

## At-rest protection

The pipeline distinguishes the generated runtime needed to start the process from regions that are ciphertext at rest. Exact ciphertext ranges are recorded so PE relocation and integrity logic can avoid loader-induced mutation.

`--crypto-coverage` controls code-region encryption coverage for the applicable native path. Lower coverage deliberately leaves some transformed code plaintext; chained/dispatcher modes impose additional constraints.

## Chained crypto

`--chained-crypto` requests chunk-oriented encryption where subsequent chunk state derives from earlier plaintext/state and sensitive seed/S-box/payload material can be destroyed after use.

The resolver warns when chained crypto is combined with partial crypto coverage because that intentionally leaves code plaintext.

## Dispatcher re-encryption

`--dispatcher-reencrypt` protects transformed native blocks with runtime decrypt/execute/re-encrypt behavior.

This mode needs the transformed block region to remain writable. Therefore it takes precedence over `--mem-harden` RX sealing for that native region.

It is also a different execution model from whole-program `--vm-oep`; VM-OEP takes precedence and native dispatcher re-encryption is disabled for that combination.

## Integrity

`--integrity` enables boot/runtime integrity verification over protected representation. Commercial Program-VM mode additionally carries family-scoped integrity descriptors for immutable runtime representation, including the persistent bytecode layer used by VM lifetime protection.

Integrity depends on the crypto/runtime layer and is disabled with a warning when crypto itself is disabled.

## Payload relocation

`--payload-relocate` places encrypted payload material into a non-executable data section. This separates at-rest payload storage from executable runtime code.

`--rsrc-register` rebuilds PE resource metadata so the relocated payload is represented as `RT_RCDATA`. It is invalid without payload relocation.

## IAT hiding

`--iat-hide` removes/replaces normal import exposure and uses generated resolver/bootstrap state to reconstruct required slots at runtime.

The Program-VM bridge and native startup paths can share resolver-populated slots, so IAT hiding remains meaningful in VM-OEP mode rather than being automatically disabled.

## Memory hardening

`--mem-harden` applies W^X-oriented post-bootstrap permissions. Immutable generated code/tables can be sealed executable/read-only while mutable VM state is kept in a separately owned writable, non-executable region.

Native dispatcher re-encryption is the major conflict because that mode needs to write code blocks repeatedly.

## Anti-debugging

`--anti-debug` enables the generated anti-debug layer. Detection behavior is selected with:

```text
--anti-debug-policy trap
--anti-debug-policy hang
--anti-debug-policy warn
```

`trap` is fail-closed, `hang` stalls execution, and `warn` is a fail-open research/debug policy.

## M7: lifetime protection

M7 represents on-demand lifetime/re-encryption protection.

The effective implementation depends on the execution profile:

- native mode can reuse native runtime re-encryption machinery;
- commercial Program-VM mode can protect instruction-aligned bytecode chunks and associated data-lifetime objects.

The resolver only enables M7 when its prerequisites are satisfied.

## M8: VM table concealment

M8 is VM-specific and only becomes effective when VM support is active. It conceals handler-table addressing using MBA-derived representation/lookup logic so handler addresses are not represented only as straightforward static table pointers.

## `--full`

`--full` is a request for the broad protection preset, not a promise that every raw flag can remain simultaneously active.

It requests:

```text
obfuscation level 3
anti-debugging
dispatcher re-encryption
integrity
payload relocation
resource registration
IAT hiding
memory hardening
```

The profile resolver then applies compatibility rules. For example, the native dispatcher re-encryption implied by `--full` suppresses memory RX sealing for the writable native block region; adding `--vm-oep` instead gives VM-OEP precedence over that dispatcher mode.

Use `--strict-profile` when such a downgrade should abort the command.

## Protection metadata

The pipeline persists effective protection and runtime artifacts into context/manifest structures rather than relying only on CLI history. This allows validators and diagnostics to ask what was actually emitted into the final PE.
