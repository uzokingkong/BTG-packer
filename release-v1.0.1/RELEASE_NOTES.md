# BTG-packer v1.0.1

This maintenance release stabilizes commercial multi-family Program-VM execution and substantially reduces the on-disk size of protected images.

## Changes

- Fixed cross-family guest-state, stack, return, exception, and native-bridge synchronization.
- Added family-specific route layout propagation for commercial multi-family transitions.
- Moved large VM state and host-stack reservations to loader-backed zero-fill `.vstate` storage.
- Split file-backed bootstrap metadata into `.vmeta`, preserving ChaCha20/Poly1305 tags and integrity state.
- Reduced the full commercial test image from approximately 211.5 MiB to 7.37 MiB.
- Removed plaintext canonical route records from final images. `.vmroute` now contains only a per-build keyed 32-byte commitment.
- Added final-image validation that rejects plaintext route records, modified commitments, and inconsistent route inventories.

## Validation

- Windows x86-64 release build completed successfully.
- Full commercial test profile packed successfully with ChaCha20, integrity, payload relocation, IAT hiding, M8, and multi-family Program-VM enabled.
- Protected test executable completed 10/10 repeated runs with exit code `0` and checksum `0x68a0a62af7498e1`.
- Confirmed the final image contains no `VMROUTE` magic or serialized route records.

## Known limitation

The commercial pre-entry TLS lifecycle gateway is currently attach-neutral and does not yet virtualize arbitrary original TLS callback bodies. Targets that depend on custom TLS callback side effects require additional compatibility work.

BTG-packer is intended for software you own or are authorized to transform and analyze.
