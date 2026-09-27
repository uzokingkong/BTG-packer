# BTG-packer v1.0.2

This release introduces comprehensive anti-recovery hardening, retires original executable code and exception unwind records, and expands VM exposure metrics and section camouflage.

## Changes

- Completely retired original `.text` executable bytes and `.pdata` unwind records from protected PE outputs.
- Added at-rest encryption and dynamic boot-stub decryption for string literals referenced by virtualized entrypoints.
- Added configurable section name camouflage (`--camouflage`) supporting standard PE, benign compiler, and randomized naming schemes.
- Hardened commercial VM native island transitions, ABI bridges, and Win64 SEH / C++ exception unwind handling.
- Hardened distributed integrity metadata by removing fixed `BTGI` magic, adding build-local nonce headers, masking descriptor fields, and permuting record order.
- Added automated VM exposure and reverse-engineering risk metrics (`src/analysis/vm_exposure.rs`) to quantify dispatcher leakage and recoverable entrypoints.
- Synchronized CLI version reporting and runtime startup banners with `CARGO_PKG_VERSION`.
- Updated English and Korean documentation to align with current implementation and configuration options.

## Validation

- Windows x86-64 release build completed successfully.
- Full library test suite completed with 789/789 tests passing (0 failed, 0 ignored).
- Verified protected PE execution with ChaCha20-Poly1305 encryption, IAT hiding, payload relocation, and W^X memory hardening.
- Confirmed output binaries contain no original plaintext `.text` bytes and preserve valid loader structures across all data directories.

## Known limitation

The commercial whole-program VM mode (`--vm-commercial`) with complex re-entrant C++ exception catch continuation unwinding remains under active optimization. Standard and intermediate VM protection profiles (`--vm`, `--vm-oep`) are fully supported for production usage.

BTG-packer is intended for software you own or are authorized to transform and analyze.
