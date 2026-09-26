# BTG cross-family state fix v2

The previous patch was malformed because it was hand-written without valid
unified-diff hunk headers.

This v2 patch is generated as a real unified diff and was verified with:

    git apply --check BTG_cross_family_state_fix_v2.patch

Recommended from the BTG-packer repo root:

    git apply --check .\BTG_cross_family_state_fix_v2.patch
    git apply .\BTG_cross_family_state_fix_v2.patch
    cargo fmt --all
    cargo check --lib

If your checkout has context drift, use the included source-anchor editor:

    python .\apply_fix.py
    cargo fmt --all
    cargo check --lib

`apply_fix.py` makes `*.btgfix.bak` backups before changing files.

After applying, rebuild the packer and regenerate the exact differential target.
Do not reuse an old `packed.exe`.
