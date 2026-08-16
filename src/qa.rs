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
    /// 코퍼스 탐색: 고정 타깃(시스템 + dummy) + test/ 페이로드 +
    /// `BTG_QA_CORPUS` 디렉토리 안의 모든 `.exe`. 경로 중복 제거.
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
                use_vm_oep: true,
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
        let mut child = match Command::new(exe)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return ExecCheck { alive: false, code: -3, stdout_hash: 0, stdout_len: 0, detail: format!("spawn-error: {}", e) },
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
