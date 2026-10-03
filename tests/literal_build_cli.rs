//! Controlled PE fixture for literal build/export tests. No user EXE is executed.
use btg_packer::pe::builder::{DataDirectory, PeMultiSectionBuilder, SectionData};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct Fixture {
    root: PathBuf,
    input: Vec<u8>,
    data: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_extra(&[])
    }
    fn with_extra(extra: &[u8]) -> Self {
        Self::configured(extra, false)
    }
    fn configured(extra: &[u8], imports: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "btg-literal-build-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("private")).unwrap();
        let mut data = vec![b'A', 0, 0xed, 0x95, 0x9c, 0, 0x3d, 0xd8, 0, 0xde, 0, 0];
        data.extend(b"UNDECLARED-UNCHANGED");
        data.extend_from_slice(extra);
        // Check every data byte via RIP-relative loads, returning 0 or 41.
        let fail = data.len() * 18 + 3;
        let mut code = Vec::new();
        for (index, byte) in data.iter().enumerate() {
            let ip = 0x1000 + code.len();
            code.extend([0x0f, 0xb6, 0x05]);
            code.extend(((0x2000 + index) as i32 - (ip + 7) as i32).to_le_bytes());
            code.push(0x3d);
            code.extend((*byte as u32).to_le_bytes());
            code.extend([0x0f, 0x85]);
            code.extend((fail as i32 - (code.len() + 4) as i32).to_le_bytes());
        }
        code.extend([0x31, 0xc0, 0xc3, 0xb8, 41, 0, 0, 0, 0xc3]);
        let text = SectionData {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: code.len() as u32,
            characteristics: 0x60000020,
            bytes: code,
        };
        let rdata = SectionData {
            name: ".rdata".into(),
            virtual_address: 0x2000,
            virtual_size: data.len() as u32,
            characteristics: 0x40000040,
            bytes: data.clone(),
        };
        let (directories, relayed, last) = if imports {
            let mut bytes = vec![0;0x100];
            for (off,value) in [(0,0x3060u32),(12,0x30a0),(16,0x3040)] {
                bytes[off..off+4].copy_from_slice(&value.to_le_bytes());
            }
            for off in [0x40,0x60] {bytes[off..off+8].copy_from_slice(&0x3080u64.to_le_bytes());}
            let function = b"GetCurrentProcessId\0";
            bytes[0x82..0x82+function.len()].copy_from_slice(function);
            bytes[0xa0..0xad].copy_from_slice(b"kernel32.dll\0");
            let mut dirs = vec![DataDirectory {virtual_address:0,size:0};16];
            dirs[1] = DataDirectory {virtual_address:0x3000,size:40};
            dirs[12] = DataDirectory {virtual_address:0x3040,size:16};
            (dirs,vec![text,rdata],SectionData {name:".idata".into(),virtual_address:0x3000,
                virtual_size:bytes.len() as u32,characteristics:0xc0000040,bytes})
        } else {(vec![],vec![text],rdata)};
        let input = PeMultiSectionBuilder::new(
            0x140000000,
            0x1000,
            3,
            0,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0x200,
            0x1000,
            directories,
            relayed,
            last,
            None,
            vec![],
        )
        .build()
        .unwrap();
        fs::write(root.join("input.exe"), &input).unwrap();
        let fixture = Self { root, input, data };
        fixture.write_map("post_boot");
        fixture
    }
    fn write_map(&self, ascii_phase: &str) {
        let map = serde_json::json!({"schema_version":1,"input_sha256":format!("{:x}",Sha256::digest(&self.input)),"spans":[
            {"id":1,"rva":8192,"byte_len":1,"terminator_len":1,"encoding":"ascii","access_phase":ascii_phase},
            {"id":2,"rva":8194,"byte_len":3,"terminator_len":1,"encoding":"utf8","access_phase":"post_boot"},
            {"id":3,"rva":8198,"byte_len":4,"terminator_len":2,"encoding":"utf16_le","access_phase":"post_boot"}
        ]});
        fs::write(
            self.root.join("private/map.json"),
            serde_json::to_vec(&map).unwrap(),
        )
        .unwrap();
    }
    fn pack(&self, output: &str, release: &str) -> std::process::Output {
        self.pack_configured(output, release, &[])
    }
    fn pack_configured(&self, output: &str, release: &str, options: &[&str]) -> std::process::Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_btg-packer"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("BTG_") {
                cmd.env_remove(key);
            }
        }
        cmd.current_dir(&self.root)
            .args([
                "-i",
                "input.exe",
                "-o",
                output,
                "--literal-map",
                "private/map.json",
                "--seed",
                "7",
                "--build-cache",
                "--no-progress",
                "--release-dir",
                release,
                "--private-root",
                "private",
            ])
            .args(options)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn data_bytes(image: &[u8], len: usize) -> &[u8] {
    let pe = goblin::pe::PE::parse(image).unwrap();
    let section = pe
        .sections
        .iter()
        .find(|s| s.virtual_address == 0x2000)
        .unwrap();
    let start = section.pointer_to_raw_data as usize;
    &image[start..start + len]
}
fn assert_packed(result: &std::process::Output) {
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn mapped_short_unicode_build_cache_and_release_preserve_exact_ownership() {
    let fixture = Fixture::new();
    let first = fixture.pack("first.exe", "release-first");
    assert_packed(&first);
    let image = fs::read(fixture.root.join("first.exe")).unwrap();
    let encrypted = data_bytes(&image, fixture.data.len());
    assert_ne!(&encrypted[..12], &fixture.data[..12]);
    for index in [1, 5, 10, 11] {
        assert_eq!(encrypted[index], 0);
    }
    assert_eq!(&encrypted[12..], &fixture.data[12..]);
    let restored = fixture.pack("second.exe", "release-second");
    assert_packed(&restored);
    assert!(!String::from_utf8_lossy(&restored.stdout).contains("Target .text RVA"));
    assert_eq!(image, fs::read(fixture.root.join("second.exe")).unwrap());
    for release in ["release-first", "release-second"] {
        let path = fixture.root.join(release);
        assert_eq!(fs::read_dir(&path).unwrap().count(), 2);
        assert_eq!(fs::read(path.join("program.exe")).unwrap(), image);
        let manifest = fs::read_to_string(path.join("manifest.json")).unwrap();
        assert!(!manifest.contains("map.json"));
    }
    fixture.write_map("pre_boot_tls");
    assert_packed(&fixture.pack("excluded.exe", "release-excluded"));
    let excluded = fs::read(fixture.root.join("excluded.exe")).unwrap();
    assert_eq!(data_bytes(&excluded, fixture.data.len())[0], b'A');
    assert_ne!(image, excluded);
    assert_eq!(
        fs::read_dir(fixture.root.join(".btg-cache"))
            .unwrap()
            .count(),
        2
    );
    assert_eq!(
        fs::read(fixture.root.join("input.exe")).unwrap(),
        fixture.input
    );
}

#[test]
fn validated_input_snapshot_does_not_reread_modified_files() {
    use btg_packer::{
        build_cache::BuildCache, cli::CliArgs, pipeline::literal_audit::LiteralBuildInput,
    };
    use clap::Parser;
    let fixture = Fixture::new();
    let mut snapshot = LiteralBuildInput::read(
        &fixture.root.join("input.exe"),
        &fixture.root.join("private/map.json"),
    )
    .unwrap();
    fs::write(fixture.root.join("input.exe"), b"replaced-input").unwrap();
    fs::write(fixture.root.join("private/map.json"), b"replaced-map").unwrap();
    let mut args = CliArgs::try_parse_from([
        "btg",
        "--seed",
        "7",
        "--build-cache",
        "--literal-map",
        "unused.json",
    ])
    .unwrap();
    args.cache_dir = fixture.root.join("cache");
    let bytes = snapshot.take_input();
    assert_eq!(bytes, fixture.input);
    assert_eq!(snapshot.catalog().summary().eligible, 3);
    assert_eq!(snapshot.payload_hashes().len(), 3);
    assert!(
        BuildCache::open_with_literal_identity(&args, &bytes, Some(snapshot.map_identity()))
            .is_ok()
    );
    assert!(BuildCache::open(&args, &bytes).is_err());
}

#[test]
fn literal_map_cannot_be_overwritten_by_output_or_log() {
    let fixture = Fixture::new();
    let original = fs::read(fixture.root.join("private/map.json")).unwrap();
    for pair in [
        ["-o", "private/map.json"],
        ["--log-file", "private/map.json"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_btg-packer"))
            .current_dir(&fixture.root)
            .args([
                "-i",
                "input.exe",
                "--literal-map",
                "private/map.json",
                "--no-progress",
            ])
            .args(pair)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr)
            .contains("private literal map must not be used"));
        assert_eq!(
            fs::read(fixture.root.join("private/map.json")).unwrap(),
            original
        );
        assert!(!fixture.root.join("protected_btg.exe").exists());
        assert!(!fixture.root.join(".btg-cache").exists());
    }
}

#[cfg(windows)]
fn run_controlled(path: &Path) {
    let mut child = Command::new(path).spawn().unwrap();
    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(0), "{path:?}");
            return;
        }
        if start.elapsed() > std::time::Duration::from_secs(10) {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("controlled fixture timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(windows)]
fn run_rejected(path: &Path) {
    let mut child = Command::new(path).spawn().unwrap();
    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(0xc000001du32 as i32),
                "authentication must trap before executing {path:?}");
            return;
        }
        if start.elapsed() > std::time::Duration::from_secs(10) {
            child.kill().unwrap(); let _ = child.wait();
            panic!("tampered controlled fixture timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(windows)]
#[test]
fn boot_aead_rejects_data_descriptor_code_bytecode_and_resolver_tampering() {
    let fixture = Fixture::configured(&[], true);
    run_controlled(&fixture.root.join("input.exe"));
    let result = fixture.pack_configured("sealed.exe","release-sealed",
        &["--vm","--vm-oep","--vm-commercial","--handler-prf","--integrity",
          "--m8","--payload-relocate","--iat-hide"]);
    assert_packed(&result);
    run_controlled(&fixture.root.join("sealed.exe"));
    run_controlled(&fixture.root.join("release-sealed/program.exe"));
    let packed = fs::read(fixture.root.join("sealed.exe")).unwrap();
    let pe = goblin::pe::PE::parse(&packed).unwrap();
    let file_offset = |rva: u32| -> usize {
        let s = pe.sections.iter().find(|s| rva>=s.virtual_address && rva<s.virtual_address+s.size_of_raw_data).unwrap();
        (s.pointer_to_raw_data+rva-s.virtual_address) as usize
    };
    let manifest = fs::read_to_string(fixture.root.join("sealed.exe.btgmanifest")).unwrap();
    let bytecode_rva = manifest.lines().find_map(|line| line.strip_prefix("vm_bytecode_rva = 0x"))
        .map(|value| u32::from_str_radix(value,16).unwrap()).unwrap();
    let bytecode_len: usize = manifest.lines().find_map(|line| line.strip_prefix("vm_bytecode_len = "))
        .unwrap().parse().unwrap();
    let mut bytecode_file = file_offset(bytecode_rva);
    if packed[bytecode_file..bytecode_file+bytecode_len].iter().all(|byte| *byte==0) {
        bytecode_file = pe.sections.iter().find(|s| s.name().unwrap()==".vdata").unwrap().pointer_to_raw_data as usize;
    }
    let mut pattern = 0x140002000u64.to_le_bytes().to_vec();
    pattern.extend_from_slice(&1u64.to_le_bytes());
    let descriptors: Vec<_> = packed.windows(16).enumerate().filter(|(_, w)| *w==pattern.as_slice()).map(|(i,_)|i).collect();
    assert_eq!(descriptors.len(),1);
    let descriptor = descriptors[0];
    let output = String::from_utf8_lossy(&result.stdout);
    let resolver_line = output.lines().find(|line| line.contains("v6 IAT/Mem data placed:")).unwrap();
    let resolver_off = usize::from_str_radix(resolver_line.split("table@0x").nth(1).unwrap().split('/').next().unwrap(),16).unwrap();
    let boot = pe.sections.iter().find(|s| s.name().unwrap()==".textb").unwrap();
    let resolver_file = boot.pointer_to_raw_data as usize+resolver_off;
    for (name,offset) in [("data",file_offset(0x2000)),("descriptor-va",descriptor),
        ("descriptor-len",descriptor+8),("descriptor-tag",descriptor+16),
        ("native-text",file_offset(0x1000)+3),("bytecode",bytecode_file),
        ("resolver",resolver_file)] {
        let mut altered = packed.clone(); altered[offset]^=1;
        let path = fixture.root.join(format!("tampered-{name}.exe"));
        fs::write(&path,altered).unwrap(); run_rejected(&path);
    }
    // A metadata-table header and its record order are also authenticated.
    let mut altered = packed.clone(); altered[descriptor-8]^=1;
    let path = fixture.root.join("tampered-header.exe");
    fs::write(&path,altered).unwrap(); run_rejected(&path);
    let mut altered = packed.clone();
    for i in 0..32 {altered.swap(descriptor+i,descriptor+32+i);}
    let path = fixture.root.join("tampered-record-order.exe");
    fs::write(&path,altered).unwrap(); run_rejected(&path);
}

#[cfg(windows)]
#[test]
fn boot_aead_rejects_relocated_payload_and_encrypted_native_text_tampering() {
    let fixture = Fixture::new();
    assert_packed(&fixture.pack_configured("native.exe","release-native", &["--integrity","--payload-relocate"]));
    run_controlled(&fixture.root.join("native.exe"));
    let mut packed = fs::read(fixture.root.join("native.exe")).unwrap();
    let pe = goblin::pe::PE::parse(&packed).unwrap();
    let payload = pe.sections.iter().find(|s| s.name().unwrap()==".vdata").unwrap().pointer_to_raw_data as usize;
    packed[payload]^=1;
    let path = fixture.root.join("tampered-payload.exe");
    fs::write(&path,packed).unwrap(); run_rejected(&path);

    let mut classic = Fixture::new();
    // The classic VM fixture exercises a bounded constant return; commercial
    // byte-wise data access is covered by the other runtime tests.
    let source = goblin::pe::PE::parse(&classic.input).unwrap();
    let text = source.sections.iter().find(|s| s.virtual_address==0x1000).unwrap();
    let text_offset=text.pointer_to_raw_data as usize; let raw_len=text.size_of_raw_data as usize;
    classic.input[text_offset..text_offset+raw_len].fill(0);
    classic.input[text_offset..text_offset+3].copy_from_slice(&[0x31,0xc0,0xc3]);
    let pe_offset=u32::from_le_bytes(classic.input[0x3c..0x40].try_into().unwrap()) as usize;
    let section_offset=pe_offset+24+u16::from_le_bytes(classic.input[pe_offset+20..pe_offset+22].try_into().unwrap()) as usize;
    classic.input[section_offset+8..section_offset+12].copy_from_slice(&3u32.to_le_bytes());
    fs::write(classic.root.join("input.exe"),&classic.input).unwrap(); classic.write_map("post_boot");
    run_controlled(&classic.root.join("input.exe"));
    assert_packed(&classic.pack_configured("classic.exe","release-classic", &["--vm","--vm-oep","--integrity"]));
    run_controlled(&classic.root.join("classic.exe"));
    let mut packed = fs::read(classic.root.join("classic.exe")).unwrap();
    let pe = goblin::pe::PE::parse(&packed).unwrap();
    let text = pe.sections.iter().find(|s| s.virtual_address==0x1000).unwrap().pointer_to_raw_data as usize;
    packed[text+3]^=1;
    let path = classic.root.join("tampered-encrypted-text.exe");
    fs::write(&path,packed).unwrap(); run_rejected(&path);
}

#[cfg(windows)]
#[test]
fn controlled_pe_reads_restored_short_unicode_literals_at_runtime() {
    let fixture = Fixture::new();
    run_controlled(&fixture.root.join("input.exe"));
    assert_packed(&fixture.pack("protected.exe", "release"));
    run_controlled(&fixture.root.join("protected.exe"));
    run_controlled(&fixture.root.join("release/program.exe"));
}

#[cfg(windows)]
#[test]
fn automatic_short_literals_are_ciphertext_and_restored_with_commercial_vm() {
    let fixture = Fixture::with_extra(b"\0os.nim\0IOError\0OSError\0comnim\0H\0e\0l\0p\0\0\0");
    run_controlled(&fixture.root.join("input.exe"));
    let result = Command::new(env!("CARGO_BIN_EXE_btg-packer"))
        .current_dir(&fixture.root)
        .args(["-i", "input.exe", "-o", "auto.exe", "--seed", "2",
            "--vm", "--vm-oep", "--vm-commercial", "--allow-partial-vm",
            "--m8", "--integrity", "--payload-relocate", "--rsrc-register",
            "--iat-hide", "--mem-harden", "--section-name-mode", "seeded", "--no-progress"])
        .output().unwrap();
    assert_packed(&result);
    let packed = fs::read(fixture.root.join("auto.exe")).unwrap();
    for literal in [&b"os.nim"[..], &b"IOError"[..], &b"OSError"[..], &b"comnim"[..], &b"H\0e\0l\0p\0"[..]] {
        assert!(!packed.windows(literal.len()).any(|w| w == literal));
    }
    run_controlled(&fixture.root.join("auto.exe"));
}

#[cfg(windows)]
#[test]
fn controlled_prf_private_key_map_and_cached_release_execute_together() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("private/key.bin"),[0x7b;32]).unwrap();
    let options = ["--vm","--vm-oep","--vm-commercial","--handler-prf","--private-build-key","private/key.bin"];
    assert_packed(&fixture.pack_configured("prf.exe","release-prf",&options));
    run_controlled(&fixture.root.join("prf.exe"));
    let original = fs::read(fixture.root.join("prf.exe")).unwrap();
    assert_eq!(fs::read_dir(fixture.root.join("release-prf")).unwrap().count(),2);
    let restored = fixture.pack_configured("restored.exe","release-restored",&options);
    assert_packed(&restored);
    assert!(!String::from_utf8_lossy(&restored.stdout).contains("Target .text RVA"));
    assert_eq!(fs::read(fixture.root.join("restored.exe")).unwrap(),original);
    run_controlled(&fixture.root.join("release-restored/program.exe"));
    assert_eq!(fs::read(fixture.root.join("private/key.bin")).unwrap(),vec![0x7b;32]);
}
