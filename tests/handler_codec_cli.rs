//! Packer-only integration checks; fixture/output executables are never run.
use std::{fs, path::PathBuf, process::Command};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "btg-handler-codec-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("input.exe"),
            btg_packer::pe::generate_dummy_target_pe().unwrap(),
        )
        .unwrap();
        Self(root)
    }
    fn command(&self) -> Command {
        self.command_output("output.exe")
    }
    fn command_output(&self, output: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_btg-packer"));
        cmd.current_dir(&self.0).args([
            "-i",
            "input.exe",
            "-o",
            output,
            "--vm",
            "--vm-oep",
            "--vm-commercial",
            "--handler-prf",
            "--private-build-key",
            "key.bin",
            "--seed",
            "7",
            "--build-cache",
            "--cache-dir",
            "cache",
            "--no-progress",
        ]);
        cmd
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn malformed_private_key_fails_before_artifact_creation() {
    let fixture = Fixture::new();
    let key = b"private-secret-marker-too-short";
    fs::write(fixture.0.join("key.bin"), key).unwrap();
    let result = fixture
        .command()
        .args(["--log-file", "log.txt"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("exactly 32 binary bytes"), "{stderr}");
    assert!(!stderr.contains("private-secret-marker"));
    assert_eq!(fs::read(fixture.0.join("key.bin")).unwrap(), key);
    for artifact in ["output.exe", "log.txt", "cache"] {
        assert!(!fixture.0.join(artifact).exists());
    }
}

#[test]
fn private_key_cannot_be_overwritten_by_output_or_log() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("key.bin"), [0x51; 32]).unwrap();
    let mut log_command = fixture.command();
    log_command.args(["--log-file", "key.bin"]);
    for mut command in [fixture.command_output("key.bin"), log_command] {
        let result = command.output().unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("private build key must not be used"));
        assert_eq!(fs::read(fixture.0.join("key.bin")).unwrap(), vec![0x51; 32]);
        assert!(!fixture.0.join("cache").exists());
    }
}

#[test]
fn private_key_changes_cache_identity_and_cached_output_restores() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("key.bin"), [0x35; 32]).unwrap();
    let first = fixture.command().output().unwrap();
    assert!(
        first.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let original = fs::read(fixture.0.join("output.exe")).unwrap();
    fs::remove_file(fixture.0.join("output.exe")).unwrap();
    let restored = fixture.command().output().unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_eq!(fs::read(fixture.0.join("output.exe")).unwrap(), original);
    assert_eq!(fs::read_dir(fixture.0.join("cache")).unwrap().count(), 1);
    let manifest = fs::read_to_string(fixture.0.join("output.exe.btgmanifest")).unwrap();
    assert!(manifest.contains("handler-codec-v2-prf-init"));
    assert!(manifest.contains("private-build-key"));
    assert!(!manifest.contains("key.bin"));
    fs::write(fixture.0.join("key.bin"), [0x36; 32]).unwrap();
    let changed = fixture.command().output().unwrap();
    assert!(
        changed.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&changed.stdout),
        String::from_utf8_lossy(&changed.stderr)
    );
    assert_ne!(fs::read(fixture.0.join("output.exe")).unwrap(), original);
    assert_eq!(fs::read_dir(fixture.0.join("cache")).unwrap().count(), 2);
    assert_eq!(fs::read(fixture.0.join("key.bin")).unwrap(), vec![0x36; 32]);
}
