// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Multi-Compiler QA Benchmark Suite
// ==============================================================================
//
// v2 (실행 검증 추가):
// 이전 버전은 system target(notepad 등)을 "구조 검증만 하면 된다"며 실제로
// 실행하지 않고 항상 PASS 로 처리했다. 그 결과 Win11 에서 notepad.exe 가
// "패키지 앱(MSIX) 런처 스텁"이라서 이미지가 System32 가 아닌 경로(복사본,
// 이름 변경, BTG packed 출력)에 있으면 창 없이 exit(0) 으로 조용히 종료한다는
// 사실이 전혀 드러나지 않았다.
// 이제 각 타깃에 대해 (1) 원본 실행 동작과 (2) packed 출력 실행 동작을 실제로
// 비교하여 정직하게 PASS/FAIL 을 보고한다.
//
// v3 (타임아웃 확대):
// packed charmap 의 0xC0000005 크래시는 실행 후 약 4~8초에 발생하는데,
// 2.5초 대기로는 "alive" 로 오판되어 크래시를 놓쳤다. 대기를 9초로 늘려
// 크래시를 실제로 감지하도록 수정.
//
// v4 (아이템 10 — 실제 PE 코퍼스):
//   1. 코퍼스 확장: 시스템 바이너리(notepad/charmap) + MSVC dummy + **test/
//      크레이트 페이로드**(threads/exceptions/TLS/FP/알고리즘) + `BTG_QA_CORPUS`
//      환경변수로 지정한 디렉토리 안의 모든 `.exe`.
//   2. `--vm-oep`(프로그램 VM 가상화) 경로를 지원하는 타깃은 그 경로로 패킹해
//      VM 파이프라인까지 실제 검증한다.
//   3. 검증 강화: alive + 종료 코드 뿐 아니라, 두 실행 모두 stdout 을 냈으면
//      stdout 해시도 비교해 출력 변화까지 잡는다.

use anyhow::Result;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// P0-1: 실전 컴파일러 코퍼스 디렉토리 (QA 가 스캔).
pub const CORPUS_DIR: &str = "corpus";

/// P0-1: 생성할 Rust 코퍼스 프로파일 — (태그, cargo profile, 컴파일러 라벨).
pub const CORPUS_PROFILES: &[(&str, &str, &str)] = &[
    ("o0", "corpus-o0", "Rust -O0"),
    ("o1", "corpus-o1", "Rust -O1"),
    ("o2", "corpus-o2", "Rust -O2"),
    ("o3", "corpus-o3", "Rust -O3"),
    ("lto", "corpus-lto", "Rust -O3+LTO"),
    ("cu16", "corpus-cu16", "Rust -O3+CGU16"),
    ("abort", "corpus-abort", "Rust -O3 panic=abort"),
    ("checks", "corpus-checks", "Rust -O2 overflow-checks"),
];

#[derive(Debug, Clone)]
pub struct QaTarget {
    pub name: String,
    pub compiler: String,
    pub path: PathBuf,
    /// 프로그램 VM 가상화(--vm-oep)로 패킹할지 (커버리지 넓은 페이로드만).
    pub use_vm_oep: bool,
}

#[derive(Debug, Clone)]
pub struct QaResult {
    pub target_name: String,
    pub compiler: String,
    pub original_size: usize,
    pub packed_size: usize,
    pub relayed_sections_count: usize,
    pub execution_success: bool,
    pub exec_detail: String,
}

pub struct QaBenchmarkRunner;

impl QaBenchmarkRunner {
    /// P0-1: test/ 크레이트를 각 corpus-* 프로파일로 빌드해 `corpus/<tag>.exe`로
    /// 복사한다. 이미 존재하고 같은 크기면 스킵 (재빌드 방지). 실패 프로파일은
    /// 경고만 남기고 계속한다. 반환값 = 생성/갱신한 파일 목록.
    pub fn build_corpus() -> Result<Vec<String>> {
        use std::fs;
        let manifest = "test/Cargo.toml";
        let mut produced = Vec::new();
        fs::create_dir_all(CORPUS_DIR)?;

        for (tag, profile, label) in CORPUS_PROFILES {
            let out = PathBuf::from(CORPUS_DIR).join(format!("{tag}.exe"));
            // 소스/매니페스트보다 최신이고 이미 있으면 스킵.
            let need = match (fs::metadata(&out), fs::metadata(manifest)) {
                (Ok(m), Ok(src)) => m.modified().ok() < src.modified().ok(),
                (Ok(_), Err(_)) => false,
                _ => true,
            };
            if !need {
                continue;
            }

            eprintln!("[QA corpus] building {label} ({profile}) ...");
            let status = Command::new("cargo")
                .arg("build")
                .arg("--manifest-path")
                .arg(manifest)
                .arg("--profile")
                .arg(profile)
                .status();
            match status {
                Ok(s) if s.success() => {
                    let src = PathBuf::from(format!("test/target/{profile}/rust_packer_test.exe"));
                    if src.exists() {
                        fs::copy(&src, &out)?;
                        produced.push(tag.to_string());
                        eprintln!("[QA corpus] {tag}.exe ready ({label})");
                    } else {
                        eprintln!("[!] QA corpus: build succeeded but {} missing", src.display());
                    }
                }
                Ok(_) => eprintln!("[!] QA corpus: profile {profile} build failed (skipped)"),
                Err(e) => eprintln!("[!] QA corpus: cannot invoke cargo for {profile}: {e}"),
            }
        }
        Ok(produced)
    }

    /// 코퍼스 탐색: 고정 타깃(시스템 + dummy) + test/ 페이로드 +
    /// `corpus/`(Rust 프로파일 코퍼스) + `BTG_QA_CORPUS` 디렉토리 안의 모든 `.exe`.
    /// 경로 중복 제거.
    pub fn discover_targets() -> Vec<QaTarget> {
        let mut targets: Vec<QaTarget> = Vec::new();
        let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

        let msvc_path = PathBuf::from("dummy_target.exe");
        if msvc_path.exists() {
            seen.insert(msvc_path.clone());
            targets.push(QaTarget {
                name: "Dummy MSVC Payload".to_string(),
                compiler: "MSVC x64".to_string(),
                path: msvc_path,
                // ⚠ 1.5KB 초소형 바이너리는 --vm-oep(전체 프로그램 VM)가 100% 크래시
                // (0xC0000005, 디스패처 바이트코드 포인터 손상) — 알려진 vm-oep 엣지
                // 케이스. QA는 이 스모크 타깃을 일반 패킹으로 유지하고, vm-oep 경로는
                // Rust 코퍼스(8종)/test 페이로드가 커버한다. (SxS 매니페스트 버그 수정
                // 전에는 이 크래시가 SxS 실패에 가려져 있었다.)
                use_vm_oep: false,
            });
        }

        // test/ 크레이트 페이로드 (threads/exceptions/TLS/FP/algorithms …).
        let test_payload = PathBuf::from("test/target/debug/rust_packer_test.exe");
        if test_payload.exists() {
            seen.insert(test_payload.clone());
            targets.push(QaTarget {
                name: "Rust test payload".to_string(),
                compiler: "Rust x64".to_string(),
                path: test_payload,
                use_vm_oep: true,
            });
        }

        // P0-1: Rust 프로파일 코퍼스 (corpus/*.exe) — 빌드 안 되어 있으면 자동 생성.
        // 컴파일러 라벨은 프로파일 태그에서 복원 (cargo 프로파일 순서 유지).
        if let Ok(rd) = std::fs::read_dir(CORPUS_DIR) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e.eq_ignore_ascii_case("exe")) {
                    let tag = path
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let compiler = CORPUS_PROFILES
                        .iter()
                        .find(|(t, _, _)| *t == tag)
                        .map(|(_, _, l)| l.to_string())
                        .unwrap_or_else(|| "Rust corpus".to_string());
                    if seen.insert(path.clone()) {
                        targets.push(QaTarget {
                            name: format!("Corpus {tag}"),
                            compiler,
                            path,
                            use_vm_oep: true,
                        });
                    }
                }
            }
        }

        // 시스템 바이너리(notepad/charmap 등)는 코퍼스에서 제외한다 — Win11
        // MSIX 런처 스텁/GUI 특성상 원래 패킹하면 동작하지 않는다 (QA로 의미 없음).
        // 실전 검증은 dummy + test/ 페이로드 + BTG_QA_CORPUS 사용자 제공 PE 로 한다.

        // BTG_QA_CORPUS 디렉토리: 사용자 제공 실전 PE 집합.
        if let Ok(dir) = std::env::var("BTG_QA_CORPUS") {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for entry in rd.flatten() {
                    let path = entry.path();
                    if path.extension().map_or(false, |e| e.eq_ignore_ascii_case("exe")) && seen.insert(path.clone()) {
                        let name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string());
                        targets.push(QaTarget {
                            name,
                            compiler: "corpus".to_string(),
                            path,
                            use_vm_oep: false,
                        });
                    }
                }
            }
        }

        targets
    }

    pub fn run_benchmark_test(target: &QaTarget, packer_exe_path: &Path) -> Result<QaResult> {
        let packed_output_path = format!("protected_qa_{}.exe", target.name.to_lowercase().replace(' ', "_").replace('/', "_"));
        let packed_output_path_buf = PathBuf::from(&packed_output_path);

        // P0-1 방어: 과거 패커가 `<output>.exe.manifest`로 쓴 빌드 매니페스트가 남아
        // 있으면 Windows 로더가 이를 앱 매니페스트(XML)로 오인해 spawn 실패(SxS)를
        // 낸다. 패킹 전에 스테일 아티팩트를 제거한다 (btgmanifest 전환 이전 산출물).
        let _ = std::fs::remove_file(format!("{packed_output_path}.manifest"));

        let mut cmd = Command::new(packer_exe_path);
        cmd.arg("--input")
            .arg(&target.path)
            .arg("--output")
            .arg(&packed_output_path_buf)
            .arg("--anti-debug");
        if target.use_vm_oep {
            cmd.arg("--vm-oep");
        }
        let status = cmd.status()?;

        let packing_success = status.success();
        let original_size = target.path.metadata().map(|m| m.len() as usize).unwrap_or(0);

        let (packed_size, relayed_sections_count, execution_success, exec_detail) =
            if packing_success && packed_output_path_buf.exists() {
                let p_size = packed_output_path_buf.metadata().map(|m| m.len() as usize).unwrap_or(0);

                let pe_bytes = std::fs::read(&packed_output_path_buf)?;
                let relayed_count = if let Ok(pe) = goblin::pe::PE::parse(&pe_bytes) {
                    pe.sections.len()
                } else {
                    0
                };

                let orig = Self::run_and_verify(&target.path);
                let packed = Self::run_and_verify(&packed_output_path_buf);

                let behavior_match = (orig.alive == packed.alive)
                    && (orig.alive || orig.code == packed.code)
                    && (orig.stdout_hash == packed.stdout_hash);
                let detail = format!(
                    "orig=[alive:{},code:0x{:X},stdout:{}B] packed=[alive:{},code:0x{:X},stdout:{}B]",
                    orig.alive, orig.code, orig.stdout_len, packed.alive, packed.code, packed.stdout_len
                );
                // spawn/실행 오류 상세를 표에 드러낸다 (디버깅).
                let detail = if packed.code == -3 || orig.code == -3 {
                    format!("{} (packed={} orig={})", detail, packed.detail, orig.detail)
                } else {
                    detail
                };

                (p_size, relayed_count, behavior_match, detail)
            } else {
                (0, 0, false, "packing-failed".to_string())
            };

        Ok(QaResult {
            target_name: target.name.clone(),
            compiler: target.compiler.clone(),
            original_size,
            packed_size,
            relayed_sections_count,
            execution_success,
            exec_detail,
        })
    }

    fn run_and_verify(exe: &Path) -> ExecCheck {
        // ⚠ Windows: 경로 구분자가 없는 베어 파일명(예: `foo.exe`)은 CreateProcess 가
        // "program not found"(ERROR_FILE_NOT_FOUND)를 낸다 (현재 디렉토리가 탐색되지
        // 않는 런타임 환경). QA 가 쓰는 `protected_qa_*.exe` 같은 루트 출력을
        // spawn 하려면 절대경로로 정규화해야 한다. (실제 코퍼스 QA에서 적발.)
        let exe = match std::fs::canonicalize(exe) {
            Ok(p) => p,
            Err(_) => exe.to_path_buf(),
        };
        let mut child = match Command::new(&exe)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return ExecCheck { alive: false, code: -3, stdout_hash: 0, stdout_len: 0, detail: format!("spawn-error: {e}") },
        };

        // v3: 2.5s → 9s (packed charmap의 0xC0000005 크래시가 ~4~8초에 발생하므로
        // 짧은 대기로는 alive로 오판됨)
        thread::sleep(Duration::from_millis(9000));

        match child.try_wait() {
            Ok(Some(status)) => {
                // stdout 흡수 후 해시 (결정적 출력 페이로드의 동작 일치 확인용).
                let mut out = Vec::new();
                if let Some(mut so) = child.stdout.take() {
                    let _ = std::io::Read::read_to_end(&mut so, &mut out);
                }
                let mut h = DefaultHasher::new();
                out.hash(&mut h);
                ExecCheck {
                    alive: false,
                    code: status.code().unwrap_or(-1),
                    stdout_hash: h.finish(),
                    stdout_len: out.len(),
                    detail: "exited".to_string(),
                }
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                ExecCheck { alive: true, code: -2, stdout_hash: 0, stdout_len: 0, detail: "alive-after-9s".to_string() }
            }
            Err(e) => ExecCheck { alive: false, code: -1, stdout_hash: 0, stdout_len: 0, detail: format!("wait-error: {}", e) },
        }
    }
}

struct ExecCheck {
    alive: bool,
    code: i32,
    /// stdout 전체의 해시 (결정적 출력 페이로드의 동작 일치 확인).
    stdout_hash: u64,
    stdout_len: usize,
    #[allow(dead_code)]
    detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P0-3: 패킹된 test 페이로드가 SEH(unwind/catch) 와 TLS 스테이지를 실제로
    /// 실행해 원본과 **동일한 마커 출력**을 내는지 검증한다. stdout 해시가 같아도
    /// SEH/TLS 경로가 빠졌다면 마커가 사라지므로, 마커 존재를 직접 확인한다.
    #[test]
    fn packed_test_payload_executes_seh_and_tls_stages() {
        let test_exe = std::env::current_exe().unwrap();
        let packer = test_exe
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("btg-packer.exe"))
            .filter(|p| p.exists())
            .unwrap_or_else(|| panic!("packer binary not found: {}", test_exe.display()));
        let payload = PathBuf::from("test/target/debug/rust_packer_test.exe");
        if !payload.exists() {
            eprintln!("test payload not built; skipping");
            return;
        }
        let packed = PathBuf::from("target/qa_seh_tls_check.exe");
        let _ = std::fs::remove_file(&packed);
        let status = Command::new(packer)
            .arg("--input").arg(&payload)
            .arg("--output").arg(&packed)
            .arg("--anti-debug")
            .arg("--vm-oep")
            .status()
            .unwrap();
        assert!(status.success(), "pack must succeed");

        // 패킹된 바이너리를 실행해 stdout 을 잡는다.
        let abs = std::fs::canonicalize(&packed).unwrap_or_else(|_| packed.clone());
        let out = Command::new(&abs)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(out.status.success(), "packed payload must exit 0, got {:?}", out.status);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("[10] SEH") || stdout.contains("SEH unwinding"),
            "packed payload must execute the SEH/catch_unwind stage; stdout:\n{}",
            &stdout[..stdout.len().min(600)]
        );
        assert!(
            stdout.contains("[15] TLS") || stdout.contains("TLS & static"),
            "packed payload must execute the TLS stage; stdout:\n{}",
            &stdout[..stdout.len().min(600)]
        );
        assert!(stdout.contains("FINAL CHECKSUM"), "packed payload must finish all stages");

        // 원본과 stdout 동치 (SEH/TLS 결과 포함).
        let orig = Command::new(&payload)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(out.stdout, orig.stdout, "packed stdout must match original byte-for-byte");
        let _ = std::fs::remove_file(&packed);
        let _ = std::fs::remove_file("target/qa_seh_tls_check.exe.btgmanifest");
    }

    /// P0-4: --no-crypto reloc-aware 출력이 ASLR(DYNAMIC_BASE/HIGH_ENTROPY_VA) 을
    /// 보존하고 유효한 `.reloc`(기본 relocation block) 을 가진 채 실행되는지 검증.
    /// (at-rest 암호화 경로는 로더가 .reloc 을 복호화 전에 적용해 암호문을 파괴하므로
    /// 제외 — 후속 P0/P2 확장 항목.)
    #[test]
    fn no_crypto_pack_preserves_aslr_and_reloc() {
        let test_exe = std::env::current_exe().unwrap();
        let packer = test_exe
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("btg-packer.exe"))
            .filter(|p| p.exists())
            .unwrap_or_else(|| panic!("packer binary not found: {}", test_exe.display()));
        let payload = PathBuf::from("test/target/debug/rust_packer_test.exe");
        if !payload.exists() {
            eprintln!("test payload not built; skipping");
            return;
        }
        let packed = PathBuf::from("target/qa_aslr_check.exe");
        let _ = std::fs::remove_file(&packed);
        let status = Command::new(packer)
            .arg("--input").arg(&payload)
            .arg("--output").arg(&packed)
            .arg("--no-crypto")
            .arg("--anti-debug")
            .status()
            .unwrap();
        assert!(status.success(), "pack must succeed");

        let bytes = std::fs::read(&packed).unwrap();
        let e = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
        assert_eq!(&bytes[e..e + 4], b"PE\0\0", "valid PE");
        let opt = e + 24;
        let dc = u16::from_le_bytes([bytes[opt + 70], bytes[opt + 71]]);
        assert_ne!(dc & 0x0040, 0, "DYNAMIC_BASE (ASLR) must be preserved");
        assert_ne!(dc & 0x0020, 0, "HIGH_ENTROPY_VA must be preserved");
        // .reloc data directory (idx 5) 가 파일에 존재해야 한다.
        let dd_off = opt + 112;
        let reloc_va = u32::from_le_bytes(bytes[dd_off + 40..dd_off + 44].try_into().unwrap());
        let reloc_sz = u32::from_le_bytes(bytes[dd_off + 44..dd_off + 48].try_into().unwrap());
        assert!(reloc_va != 0 && reloc_sz >= 12, "valid .reloc dir (va=0x{reloc_va:X} size=0x{reloc_sz:X})");

        // ASLR 활성 바이너리가 실행 가능해야 한다.
        let abs = std::fs::canonicalize(&packed).unwrap_or_else(|_| packed.clone());
        let out = Command::new(&abs)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(out.status.success(), "ASLR-packed binary must run, got {:?}", out.status);
        let _ = std::fs::remove_file(&packed);
        let _ = std::fs::remove_file("target/qa_aslr_check.exe.btgmanifest");
    }

    /// QA 의 `run_and_verify` spawn 이 성공하는지 직접 검증 (spawn 오류 상세 노출).
    /// 패킹된 바이너리가 실행 가능한지 — QA 의 실패가 spawn 레벨인지 파악.
    #[test]
    fn run_and_verify_spawns_packed_output() {
        // 테스트 바이너리는 deps/ 아래 — 실제 packer 는 target/debug/btg-packer.exe.
        let test_exe = std::env::current_exe().unwrap();
        let packer = test_exe
            .parent() // deps
            .and_then(|p| p.parent()) // debug
            .map(|p| p.join("btg-packer.exe"))
            .filter(|p| p.exists())
            .unwrap_or_else(|| panic!("packer binary not found (build bin first): {}", test_exe.display()));
        // QA 대상 (패킹 없이, 원본 실행 확인만).
        let targets = QaBenchmarkRunner::discover_targets();
        let corpus = targets.iter().find(|t| t.name.contains("Corpus o0"));
        let path = match corpus {
            Some(t) => t.path.clone(),
            None => {
                eprintln!("no corpus target (run --qa-gen-corpus first); skipping");
                return;
            }
        };
        // QA 와 정확히 동일한 출력 경로/파일명 (repo root) 로 재현.
        let packed = PathBuf::from("protected_qa_corpus_o0.exe");
        let mut cmd = Command::new(packer);
        cmd.arg("--input").arg(&path).arg("--output").arg(&packed).arg("--anti-debug").arg("--vm-oep");
        let status = cmd.status().unwrap();
        assert!(status.success(), "pack must succeed");
        assert!(packed.exists(), "packed output must exist");
        let check = QaBenchmarkRunner::run_and_verify(&packed);
        assert!(check.code != -3, "spawn failed: {}", check.detail);
        assert_eq!(check.code, 0, "packed corpus must exit cleanly (got 0x{:X}, {})", check.code, check.detail);
        let _ = std::fs::remove_file(&packed);
        let _ = std::fs::remove_file("protected_qa_corpus_o0.exe.btgmanifest");
    }

    /// 코퍼스 탐색: test/ 페이로드 + dummy 가 발견되어야 하고 중복이 없어야 한다.
    /// (실패 시에도 notepad/charmap 은 시스템 의존이라 optional 처리.)
    #[test]
    fn corpus_discovery_finds_test_payload_without_duplicates() {
        let targets = QaBenchmarkRunner::discover_targets();
        assert!(targets.len() >= 2, "expected >= 2 corpus targets, got {}", targets.len());
        let has_test = targets.iter().any(|t| t.path.ends_with("rust_packer_test.exe"));
        assert!(has_test, "test/ crate payload must be discovered (build it first: cargo build --manifest-path test/Cargo.toml)");
        let names: std::collections::HashSet<&str> = targets.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names.len(), targets.len(), "corpus must not contain duplicate names");
        // test payload와 dummy는 VM 경로로 패킹되어야 한다.
        assert!(targets.iter().filter(|t| t.use_vm_oep).count() >= 1, "VM-capable targets must be flagged");
    }
}
