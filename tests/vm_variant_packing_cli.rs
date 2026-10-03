//! Only locally generated controlled PEs are executed. Keep evidence in artifacts.
#![cfg(all(windows, target_arch = "x86_64"))]
use std::{fs, path::PathBuf, process::Command};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts").join(format!(
            "vm-variant-packing-{}-{:016x}", std::process::id(), rand::random::<u64>()));
        fs::create_dir_all(&root).unwrap();
        // Sum 3+2+1 in a backward loop, then call a second function to add 7.
        // Both original and packed programs must return 13, with empty streams.
        let mut code = vec![0x48,0x83,0xec,0x28, 0xb9,3,0,0,0, 0x31,0xc0,
            0x01,0xc8, 0x83,0xe9,1, 0x75,0xf9, 0xe8,0x19,0,0,0,
            0x48,0x83,0xc4,0x28, 0xc3];
        code.resize(0x30, 0xcc);
        code.extend([0x83,0xc0,7,0xc3]);
        fs::write(root.join("input.exe"), btg_packer::pe::PeBuilder::new(0x140000000, 0x1000, code).build().unwrap()).unwrap();
        Self(root)
    }
    fn command(&self, output: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_btg-packer"));
        command.current_dir(&self.0).args(["-i", "input.exe", "-o", output,
            "--vm", "--vm-oep", "--vm-commercial", "--no-progress"]);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("BTG_") { command.env_remove(key); }
        }
        command
    }
    fn pack(&self, name: &str, seed: &str, policy: &str, family: &str, private: bool, verify: bool) -> Vec<u8> {
        let mut command = self.command(name);
        command.args(["--seed",seed,"--vm-variant-policy",policy,"--vm-family-policy",family,
            "--build-cache","--cache-dir","cache"]);
        if policy == "seeded" { command.args(["--boot-vm-policy","orchestration"]); }
        if private { command.args(["--handler-prf","--private-build-key","key.bin"]); }
        if verify { command.args(["--verify-output","--verify-timeout-secs","10"]); }
        let result = command.output().unwrap();
        fs::write(self.0.join(format!("{name}.pack.stdout")), &result.stdout).unwrap();
        fs::write(self.0.join(format!("{name}.pack.stderr")), &result.stderr).unwrap();
        assert!(result.status.success(), "{}\n{}\nfixture {}",
            String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr), self.0.display());
        fs::read(self.0.join(name)).unwrap()
    }
}

#[test]
fn controlled_seeded_variants_pack_execute_and_resume() {
    let fixture = Fixture::new();
    let baseline = Command::new(fixture.0.join("input.exe")).output().unwrap();
    assert_eq!(baseline.status.code(), Some(13));
    assert!(baseline.stdout.is_empty() && baseline.stderr.is_empty());
    let stable = fixture.pack("stable.exe", "7", "stable", "single", false, true);
    let seeded = fixture.pack("seeded.exe", "7", "seeded", "single", false, true);
    assert_ne!(seeded, stable);
    let changed = fixture.pack("seeded-19.exe", "19", "seeded", "function-partition", false, true);
    assert_ne!(changed, seeded);
    // Module cache resume with verification, then completed-package restore.
    assert_eq!(fixture.pack("seeded-rebuilt.exe", "7", "seeded", "single", false, true), seeded);
    assert_eq!(fixture.pack("seeded-restored.exe", "7", "seeded", "single", false, false), seeded);
    let report = btg_packer::differential::verify_equivalent(&fixture.0.join("input.exe"),
        &fixture.0.join("seeded-restored.exe"), std::time::Duration::from_secs(10)).unwrap();
    fs::write(fixture.0.join("execution-report.txt"), format!("{report:#?}")).unwrap();
}

#[test]
fn private_key_seeded_variants_execute_and_export_whitelist() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("key.bin"), [0x31; 32]).unwrap();
    let first = fixture.pack("private.exe", "7", "seeded", "function-partition", true, true);
    fs::write(fixture.0.join("key.bin"), [0x32; 32]).unwrap();
    let second = fixture.pack("private-second.exe", "7", "seeded", "function-partition", true, true);
    assert_ne!(first, second);
    let export = Command::new(env!("CARGO_BIN_EXE_btg-packer"))
        .current_dir(&fixture.0).args(["-i","private-second.exe","--release-export-only","--release-dir","release"])
        .output().unwrap();
    assert!(export.status.success(), "{}", String::from_utf8_lossy(&export.stderr));
    assert_eq!(fs::read_dir(fixture.0.join("release")).unwrap().count(), 2);
    assert_eq!(fs::read(fixture.0.join("release/program.exe")).unwrap(), second);
    let manifest = fs::read_to_string(fixture.0.join("release/manifest.json")).unwrap();
    assert!(!manifest.contains("key.bin") && !manifest.contains("VariantPlan"));
}

#[test]
fn unsupported_seeded_configuration_fails_before_output() {
    let fixture = Fixture::new();
    let result = fixture.command("bad.exe").args(["--vm-variant-policy","seeded"]).output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("requires --seed"));
    assert!(!fixture.0.join("bad.exe").exists());
    let result = fixture.command("selected.exe").args(["--seed","7","--boot-vm-policy","selected-stages","--no-crypto"]).output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("requires enabled ChaCha20"));
    assert!(!fixture.0.join("selected.exe").exists());
}

#[test]
fn authenticated_boot_program_tampering_fails_before_program_entry() {
    let fixture = Fixture::new();
    let bytes = fixture.pack("boot.exe", "7", "seeded", "single", false, true);
    let mut program = Vec::new();
    for index in [0u32,1,2,3,5] {
        program.push(1);
        program.extend((0x42544701u32 + index).to_le_bytes());
        program.extend((index * 64).to_le_bytes());
    }
    program.push(0);
    let matches: Vec<_> = bytes.windows(program.len()).enumerate().filter_map(|(index, chunk)| (chunk == program).then_some(index)).collect();
    assert_eq!(matches.len(), 1, "actual Boot VM program must appear once");
    for (name, offset) in [("opcode", 0), ("domain", 1), ("slot", 5), ("tag", program.len())] {
        let mut corrupt = bytes.clone();
        corrupt[matches[0] + offset] ^= 1;
        let path = fixture.0.join(format!("boot-tampered-{name}.exe"));
        fs::write(&path, corrupt).unwrap();
        let mut child = Command::new(&path).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(0xc000001du32 as i32), "boot authentication must trap for {name}");
                break;
            }
            if std::time::Instant::now() >= deadline { child.kill().unwrap(); let _ = child.wait(); panic!("boot failure timed out: {name}"); }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[test]
fn controlled_selected_stage_crypto_vm_packs_executes_and_resumes() {
    let fixture = Fixture::new();
    for name in ["selected.exe", "selected-restored.exe"] {
        let result = fixture.command(name).args(["--seed","7",
            "--boot-vm-policy","selected-stages", "--vm-variant-policy","seeded",
            "--vm-family-policy","single", "--build-cache","--cache-dir","cache",
            "--verify-output", "--verify-timeout-secs","20"]).output().unwrap();
        fs::write(fixture.0.join(format!("{name}.log")), &result.stderr).unwrap();
        assert!(result.status.success(), "{}\n{}", String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr));
    }
    assert_eq!(fs::read(fixture.0.join("selected.exe")).unwrap(),
        fs::read(fixture.0.join("selected-restored.exe")).unwrap());
}

#[test]
fn crypto_vm_program_is_authenticated_before_round_dispatch() {
    let fixture = Fixture::new();
    let result = fixture.command("selected.exe").args(["--seed","7",
        "--boot-vm-policy","selected-stages", "--vm-family-policy","single",
        "--verify-output", "--verify-timeout-secs","20"]).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let original = fs::read(fixture.0.join("selected.exe")).unwrap();
    let program = btg_packer::crypto::chacha20_native::chacha20_vm_program();
    let matches: Vec<_> = original.windows(program.len()).enumerate()
        .filter_map(|(index, bytes)| (bytes == program).then_some(index)).collect();
    assert_eq!(matches.len(), 1);
    // Use valid instructions/operand indices: rejection must come from the MAC,
    // rather than the interpreter's unsupported-opcode or bounds trap.
    for (name, offset, value) in [("opcode",0,2), ("operand",1,1), ("rotate",11,15)] {
        let mut corrupt = original.clone();
        corrupt[matches[0] + offset] = value;
        let path = fixture.0.join(format!("crypto-tampered-{name}.exe"));
        fs::write(&path, corrupt).unwrap();
        let mut child = Command::new(&path).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(0xc000001du32 as i32));
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap(); let _ = child.wait();
                panic!("crypto VM auth failure timed out: {name}");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[test]
fn authenticated_stage_schedule_rejects_valid_phase_reordering() {
    let fixture = Fixture::new();
    let original = fixture.pack("schedule.exe","7","seeded","single",false,true);
    let program: Vec<_> = (1u8..=12).chain(std::iter::once(0)).collect();
    let matches: Vec<_> = original.windows(program.len()).enumerate()
        .filter_map(|(offset,bytes)| (bytes == program).then_some(offset)).collect();
    assert_eq!(matches.len(),1);
    let mut corrupt = original;
    corrupt.swap(matches[0],matches[0]+1);
    let path = fixture.0.join("schedule-tampered.exe");
    fs::write(&path,corrupt).unwrap();
    let mut child = Command::new(&path).spawn().unwrap();
    let deadline = std::time::Instant::now()+std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(),Some(0xc000001du32 as i32));
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap(); let _ = child.wait();
            panic!("stage schedule authentication failure timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn controlled_full_crypto_vm_packs_executes_and_resumes() {
    let fixture = Fixture::new();
    let mut expected = None;
    for name in ["full.exe","full-resume.exe"] {
        let result = fixture.command(name).args(["--seed","7", "--boot-vm-policy","full-crypto",
            "--vm-variant-policy","seeded", "--vm-family-policy","function-partition",
            "--build-cache","--cache-dir","cache", "--verify-output","--verify-timeout-secs","30"])
            .output().unwrap();
        fs::write(fixture.0.join(format!("{name}.pack.stdout")), &result.stdout).unwrap();
        fs::write(fixture.0.join(format!("{name}.pack.stderr")), &result.stderr).unwrap();
        assert!(result.status.success(),"{}\n{}\nfixture {}",String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr),fixture.0.display());
        let bytes = fs::read(fixture.0.join(name)).unwrap();
        if let Some(previous) = &expected { assert_eq!(previous,&bytes); } else { expected=Some(bytes); }
    }
}

#[test]
fn full_crypto_vm_tables_are_authenticated_before_dispatch() {
    let fixture = Fixture::new();
    let result = fixture.command("full-auth.exe").args(["--seed","7", "--boot-vm-policy","full-crypto",
        "--vm-family-policy","single", "--verify-output","--verify-timeout-secs","30"])
        .output().unwrap();
    assert!(result.status.success(),"{}\n{}",String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));
    let original = fs::read(fixture.0.join("full-auth.exe")).unwrap();
    for (name, program) in [
        ("chacha",btg_packer::crypto::chacha20_native::chacha20_full_vm_program().unwrap()),
        ("poly",btg_packer::crypto::poly1305_native::poly1305_vm_program().unwrap())] {
        let matches: Vec<_> = original.windows(program.len()).enumerate()
            .filter_map(|(offset, bytes)| (bytes == program).then_some(offset)).collect();
        assert_eq!(matches.len(),1,"{name}");
        let mut corrupt = original.clone();
        // Swap two valid handler offsets: bounds validation alone cannot detect this.
        for i in 0..4 { corrupt.swap(matches[0]+i,matches[0]+4+i); }
        let path = fixture.0.join(format!("full-tampered-{name}.exe"));
        fs::write(&path,corrupt).unwrap();
        let mut child = Command::new(&path).spawn().unwrap();
        let deadline = std::time::Instant::now()+std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.code(),Some(0xc000001du32 as i32)); break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap(); let _ = child.wait(); panic!("{name} authentication timed out");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[test]
fn controlled_four_family_image_packs_and_executes_full_crypto() {
    let fixture=Fixture::new();
    let offsets:Vec<_>=(0..32).map(|index|0x100usize+index*0x30).collect();
    let seed=7u64;
    let mut code=vec![0x48,0x83,0xEC,0x28,0x31,0xC0];
    for &target in &offsets {
        let displacement=(target as i32)-(code.len() as i32+5);
        code.push(0xE8); code.extend(displacement.to_le_bytes());
    }
    code.extend([0x48,0x83,0xC4,0x28,0xC3]);
    for (index,&offset) in offsets.iter().enumerate() {
        code.resize(offset,0xCC);
        // Sum 3+2+1 and a distinct immediate in each function.
        code.extend([0xB9,3,0,0,0,0x01,0xC8,0x83,0xE9,1,0x75,0xF9,0x83,0xC0,index as u8+1,0xC3]);
    }
    fs::write(fixture.0.join("input.exe"),btg_packer::pe::PeBuilder::new(0x140000000,0x1000,code).build().unwrap()).unwrap();
    assert_eq!(Command::new(fixture.0.join("input.exe")).status().unwrap().code(),Some(720));
    let result=fixture.command("four-family.exe").args(["--seed",&seed.to_string(),
        "--vm-variant-policy","seeded","--vm-family-policy","function-partition",
        "--boot-vm-policy","full-crypto","--verify-output","--verify-timeout-secs","30"])
        .output().unwrap();
    fs::write(fixture.0.join("four-family.pack.stdout"),&result.stdout).unwrap();
    fs::write(fixture.0.join("four-family.pack.stderr"),&result.stderr).unwrap();
    assert!(result.status.success(),"{}\n{}\nfixture {}",String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),fixture.0.display());
    assert!(String::from_utf8_lossy(&result.stdout).contains("4 represented family/families"),
        "fixture must materialize all four actual runtime families: {}",String::from_utf8_lossy(&result.stdout));
    let output=Command::new(fixture.0.join("four-family.exe")).output().unwrap();
    assert_eq!(output.status.code(),Some(720));
    assert!(output.stdout.is_empty()&&output.stderr.is_empty());
}
