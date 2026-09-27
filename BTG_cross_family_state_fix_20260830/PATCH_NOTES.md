# BTG cross-family guest-state sync fix

Target: current `uzokingkong/BTG-packer` `main` around 2026-08-30.

## Why this patch exists

The failing differential crash reaches a `MemoryRead{width:8}` with its effective
address Temp resolving to zero. The dump shows that Temp was correctly produced
from guest RBX; guest RBX itself had already become zero after several
cross-family transitions (`STATE_CROSS_FAMILY_DEPTH = 5`).

The existing generated-child return plumbing restores:
- RAX through `STATE_CROSS_FAMILY_RETURN_PTR`
- RCX/RDX/R8/R9/R10/R11 through `STATE_CROSS_FAMILY_VOLATILE_PTRS`

but it does not restore guest RBX/RSP/RBP/RSI/RDI/R12/R13/R14/R15 from the
child VM state. That is unsafe because a family transition is an internal VM
implementation boundary, not necessarily a native Win64 ABI call boundary.
Tail-jumps and nested family routes can carry authoritative nonvolatile guest
state in the child.

## Fix

1. Adds dedicated child-state pointer slots for the missing guest GPRs.
2. Arms those pointers when routing to a generated child.
3. Syncs the authoritative child values back on generated-child return.
4. Clears the new pointer slots on fresh native-entry gateway invocations so
   reused lanes cannot inherit stale child-state pointers.

## Apply

From the root of a current `BTG-packer` checkout:

```powershell
git apply --check .\BTG_cross_family_state_fix.patch
git apply .\BTG_cross_family_state_fix.patch
cargo fmt --all
cargo check --lib
cargo test --lib
cargo build --release
```

Then regenerate the exact differential target; do not reuse an old packed EXE.

Suggested exact QA seed:

```text
0xBADC0FFE
```

This bundle is a source patch against the current GitHub `main`; it is not the
old expiring GitHub/Azure artifact URL.
