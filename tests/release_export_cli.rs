//! Executes only the exporter; it never executes the fixture PE.
use std::{fs, path::PathBuf, process::Command};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "btg-release-cli-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cli_exports_only_whitelisted_artifacts_without_packing_or_logging() {
    let f = Fixture::new();
    let input = btg_packer::pe::generate_dummy_target_pe().unwrap();
    fs::write(f.0.join("final.exe"), &input).unwrap();
    fs::write(
        f.0.join("final.exe.ownership.csv"),
        b"private-original-mapping",
    )
    .unwrap();
    fs::write(f.0.join("final.exe.btgmanifest"), b"private-key-marker").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_btg-packer"))
        .current_dir(&f.0)
        .args([
            "-i",
            "final.exe",
            "--release-export-only",
            "--release-dir",
            "release",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    let release = f.0.join("release");
    assert_eq!(fs::read_dir(&release).unwrap().count(), 2);
    assert_eq!(fs::read(release.join("program.exe")).unwrap(), input);
    let manifest = fs::read_to_string(release.join("manifest.json")).unwrap();
    assert!(!manifest.contains("private-key-marker"));
    assert_eq!(fs::read_dir(&f.0).unwrap().count(), 4);
    assert!(!f.0.join(".btg-cache").exists());
    assert!(!f.0.join("protected_btg.exe").exists());
}

#[test]
fn cli_excludes_default_cache_and_preserves_existing_release() {
    let f = Fixture::new();
    fs::create_dir(f.0.join(".btg-cache")).unwrap();
    fs::write(
        f.0.join(".btg-cache/final.exe"),
        btg_packer::pe::generate_dummy_target_pe().unwrap(),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_btg-packer"))
        .current_dir(&f.0)
        .args([
            "-i",
            ".btg-cache/final.exe",
            "--release-export-only",
            "--release-dir",
            "release",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("private root"));
    assert!(!f.0.join("release").exists());
    fs::copy(f.0.join(".btg-cache/final.exe"), f.0.join("final.exe")).unwrap();
    fs::create_dir(f.0.join("release")).unwrap();
    fs::write(f.0.join("release/sentinel"), b"user-owned").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_btg-packer"))
        .current_dir(&f.0)
        .args([
            "-i",
            "final.exe",
            "--release-export-only",
            "--release-dir",
            "release",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(
        fs::read(f.0.join("release/sentinel")).unwrap(),
        b"user-owned"
    );
    assert_eq!(fs::read_dir(f.0.join("release")).unwrap().count(), 1);
}

fn normal_command(fixture: &Fixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_btg-packer"));
    command.current_dir(&fixture.0);
    // Completed package reuse is deliberately disabled by diagnostic BTG env.
    // Make this fixture independent of the user's diagnostic environment.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("BTG_") {
            command.env_remove(key);
        }
    }
    command
}

#[test]
fn normal_build_and_cached_restore_both_export_the_same_whitelist() {
    let f = Fixture::new();
    let input = btg_packer::pe::generate_dummy_target_pe().unwrap();
    fs::write(f.0.join("input.exe"), &input).unwrap();
    let common = [
        "-i",
        "input.exe",
        "--seed",
        "2",
        "--build-cache",
        "--no-crypto",
        "--obf-level",
        "0",
        "--no-progress",
    ];
    let first = normal_command(&f)
        .args(common)
        .args([
            "-o",
            "first.exe",
            "--release-dir",
            "release-first",
            "--private-root",
            "keys",
        ])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(String::from_utf8_lossy(&first.stdout).contains("Target .text RVA"));
    assert_eq!(fs::read_dir(f.0.join("release-first")).unwrap().count(), 2);
    fs::write(
        f.0.join(".btg-cache/private-map.json"),
        b"do-not-export-private-map",
    )
    .unwrap();
    let second = normal_command(&f)
        .args(common)
        .args([
            "-o",
            "second.exe",
            "--release-dir",
            "release-second",
            "--private-root",
            "maps",
        ])
        .output()
        .unwrap();
    assert!(
        second.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    // The restored-package return occurs before TargetPeInfo/CFG processing.
    assert!(!String::from_utf8_lossy(&second.stdout).contains("Target .text RVA"));
    assert_eq!(fs::read_dir(f.0.join("release-second")).unwrap().count(), 2);
    assert_eq!(
        fs::read(f.0.join("first.exe")).unwrap(),
        fs::read(f.0.join("second.exe")).unwrap()
    );
    for name in ["program.exe", "manifest.json"] {
        assert_eq!(
            fs::read(f.0.join("release-first").join(name)).unwrap(),
            fs::read(f.0.join("release-second").join(name)).unwrap()
        );
    }
    assert_eq!(fs::read(f.0.join("input.exe")).unwrap(), input);
    assert_eq!(
        fs::read(f.0.join(".btg-cache/private-map.json")).unwrap(),
        b"do-not-export-private-map"
    );
}

#[test]
fn normal_build_rejects_release_collisions_before_any_input_or_log_write() {
    let f = Fixture::new();
    fs::create_dir(f.0.join("release")).unwrap();
    fs::write(f.0.join("release/sentinel"), b"user-owned").unwrap();
    let result = normal_command(&f)
        .args([
            "-i",
            "missing.exe",
            "-o",
            "output.exe",
            "--release-dir",
            "release",
            "--log-file",
            "build.log",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!f.0.join("missing.exe").exists());
    assert!(!f.0.join("build.log").exists());
    assert!(!f.0.join("output.exe").exists());
    assert_eq!(
        fs::read(f.0.join("release/sentinel")).unwrap(),
        b"user-owned"
    );

    let result = normal_command(&f)
        .args([
            "-i",
            "missing.exe",
            "--release-dir",
            "release-new",
            "--log-file",
            "release-new/private.log",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!f.0.join("release-new").exists());
    assert!(!f.0.join("missing.exe").exists());
    let result = normal_command(&f)
        .args([
            "-i",
            "missing.exe",
            "-o",
            ".btg-cache/output.exe",
            "--release-dir",
            "release-new",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!f.0.join(".btg-cache").exists());
    assert!(!f.0.join("missing.exe").exists());
}
