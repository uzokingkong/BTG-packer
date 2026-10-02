# Local build packages

The working runtime fixes were published to `main` as `b9fa2b6` before this feature was added.

Append `--build-cache` (alias: `--resume`) to a normal packing command with a fixed `--seed`.
Default storage is `.btg-cache`; choose another directory with `--cache-dir PATH`.
Use `--build-cache --rebuild` to bypass reads and refresh packages.

## Reuse boundaries

- Completed builds restore the EXE and `.btgmanifest` without repeating the packing pipeline.
- Interrupted commercial VM builds reuse individually completed module-generation checkpoints, including placement-specific addresses and route inputs. The unfinished module is generated again.
- Front-end PE/CFG analysis and lifting are still repeated after an interrupted build. This is **not** arbitrary-instruction or full-pipeline checkpointing.
- Prepared super-op modules currently bypass module caching because their metadata does not yet have a canonical cache representation.
- Execution verification, mapping files, debug output, log files, or `BTG_*` environment settings bypass completed-package reuse to preserve diagnostics and fresh verification. Module reuse remains available.

## Invalidation and safety

Input contents, CLI configuration, the exact packer executable, and `BTG_*` environment values identify a package. Input/output paths and progress display settings do not invalidate it. Random section naming cannot be combined with caching; use seeded naming instead.

Entries are checksummed and published by an atomic rename only after a complete write. Truncated or corrupt entries are treated as misses. Concurrent writers use separate temporary files. Interrupted writes may leave temporary files, which are never used as checkpoints.

The directory contains build artifacts and metadata. Treat it as trusted local storage, like Cargo's `target` directory; checksums are not authentication against malicious local modifications. It may be deleted to reclaim space when no build is using it. It is not uploaded to GitHub by default.
