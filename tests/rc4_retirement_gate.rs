//! RC4 retirement source gate.
//!
//! RC4 still exists behind a small number of legacy implementation seams while
//! their consumers are migrated.  New production dependencies must not spread
//! beyond that reviewed set.  Entries may disappear from the allow-list without
//! updating this test; adding a new source file requires an explicit review.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const LEGACY_RC4_ALLOWLIST: &[&str] = &[
    // Legacy native dispatchers awaiting region-context state-layout migration.
    "src/dispatcher/reencrypt.rs",
    // Policy/display sentinel only: RC4 is rejected before pipeline execution.
    "src/main.rs",
    // Compatibility provider retained until all legacy consumers are migrated.
    "src/crypto/provider.rs",
    // Production configuration rejection sentinel.
    "src/pipeline/config.rs",
    // Legacy pack-time and boot-stub consumers awaiting migration.
    "src/pipeline/crypto/bootstub/emit.rs",
    "src/pipeline/crypto/mod.rs",
    "src/pipeline/crypto/perblock.rs",
    "src/pipeline/crypto/place/mod.rs",
];

const HIGH_SIGNAL_RC4_USES: &[&str] = &[
    "Rc4::",
    "CryptoMode::Rc4",
    "BootStreamCipher::Rc4",
    "cipher::Rc4",
    "<Rc4",
];

fn rust_sources(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("read source directory") {
        let path = entry.expect("read source entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn production_rc4_dependencies_cannot_escape_reviewed_allowlist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    rust_sources(&root.join("src"), &mut sources);

    let mut offenders = BTreeSet::new();
    for path in sources {
        let body = fs::read_to_string(&path).expect("read Rust source");
        if HIGH_SIGNAL_RC4_USES
            .iter()
            .any(|needle| body.contains(needle))
        {
            let relative = path
                .strip_prefix(root)
                .expect("source belongs to project")
                .to_string_lossy()
                .replace('\\', "/");
            // Unit-test vectors exercise the legacy implementation but are not
            // production consumers and therefore are intentionally excluded.
            if !relative.ends_with("/tests.rs") {
                offenders.insert(relative);
            }
        }
    }

    let allowed: BTreeSet<String> = LEGACY_RC4_ALLOWLIST
        .iter()
        .map(|path| (*path).to_owned())
        .collect();
    let unexpected: Vec<_> = offenders.difference(&allowed).cloned().collect();

    assert!(
        unexpected.is_empty(),
        "new production RC4 dependency found outside the retirement allow-list: {unexpected:#?}"
    );
}

#[test]
fn production_selection_surfaces_do_not_advertise_rc4() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cli = fs::read_to_string(root.join("src/cli.rs")).expect("read CLI source");
    let manifest = fs::read_to_string(root.join("src/manifest.rs")).expect("read manifest source");

    assert!(
        !cli.contains("#[value(name = \"rc4\")]"),
        "RC4 must not reappear as a selectable clap value"
    );
    assert!(
        manifest.contains("matches!(crypto_mode, \"c1\" | \"chacha20\" | \"region-context-v1\")"),
        "manifest crypto allow-list changed; review retirement policy before accepting new modes"
    );
}
