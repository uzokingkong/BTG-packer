//! Executes only the packer's audit CLI, never the fixture PE.
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "btg-literal-audit-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Exact test-owned directory created above, never a workspace root.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn audit_cli_does_not_create_outputs_or_modify_inputs() {
    let fixture = Fixture::new();
    let bytes = btg_packer::pe::generate_dummy_target_pe().unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let map = format!(r#"{{"schema_version":1,"input_sha256":"{digest}","spans":[]}}"#);
    std::fs::write(fixture.0.join("input.exe"), &bytes).unwrap();
    std::fs::write(fixture.0.join("private.json"), &map).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_btg-packer"))
        .current_dir(&fixture.0)
        .args([
            "-i",
            "input.exe",
            "-o",
            "must-not-exist.exe",
            "--literal-map",
            "private.json",
            "--literal-audit-only",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("candidates=0"));
    assert!(stdout.contains("encrypted=0"));
    assert!(!stdout.contains(&digest));
    assert!(result.stderr.is_empty());
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 2);
    assert_eq!(std::fs::read(fixture.0.join("input.exe")).unwrap(), bytes);
    assert_eq!(
        std::fs::read_to_string(fixture.0.join("private.json")).unwrap(),
        map
    );
}

#[test]
fn audit_cli_rejects_malformed_map_without_private_value_leak() {
    let fixture = Fixture::new();
    std::fs::write(
        fixture.0.join("private.json"),
        br#"{"private_key":"do-not-echo-this-private-value"}"#,
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_btg-packer"))
        .current_dir(&fixture.0)
        .args([
            "-i",
            "missing.exe",
            "--literal-map",
            "private.json",
            "--literal-audit-only",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("invalid literal map JSON schema"));
    assert!(!stderr.contains("do-not-echo-this-private-value"));
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
}

#[test]
fn candidate_catalog_is_read_only_and_does_not_auto_generate_missing_input() {
    let fixture = Fixture::new();
    let input = btg_packer::pe::generate_dummy_target_pe().unwrap();
    std::fs::write(fixture.0.join("input.exe"), &input).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_btg-packer"))
        .current_dir(&fixture.0)
        .args(["-i", "input.exe", "--literal-catalog-only"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("eligible=0 encrypted=0"));
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    assert_eq!(std::fs::read(fixture.0.join("input.exe")).unwrap(), input);
    let missing = Command::new(env!("CARGO_BIN_EXE_btg-packer"))
        .current_dir(&fixture.0)
        .args(["-i", "missing.exe", "--literal-catalog-only"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(!fixture.0.join("missing.exe").exists());
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
}
