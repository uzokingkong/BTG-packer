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

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct QaTarget {
    pub name: String,
    pub compiler: String,
    pub path: PathBuf,
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
    pub fn discover_targets() -> Vec<QaTarget> {
        let mut targets = Vec::new();

        let msvc_path = PathBuf::from("dummy_target.exe");
        targets.push(QaTarget {
            name: "Dummy MSVC Payload".to_string(),
            compiler: "MSVC x64".to_string(),
            path: msvc_path,
        });

        let sys_notepad = PathBuf::from(r"C:\Windows\System32\notepad.exe");
        if sys_notepad.exists() {
            targets.push(QaTarget {
                name: "Windows System Notepad".to_string(),
                compiler: "MSVC / Windows System".to_string(),
                path: sys_notepad,
            });
        }

        let sys_charmap = PathBuf::from(r"C:\Windows\System32\charmap.exe");
        if sys_charmap.exists() {
            targets.push(QaTarget {
                name: "Windows System CharMap".to_string(),
                compiler: "MSVC / Windows System".to_string(),
                path: sys_charmap,
            });
        }

        targets
    }

    pub fn run_benchmark_test(target: &QaTarget, packer_exe_path: &Path) -> Result<QaResult> {
        let packed_output_path = format!("protected_qa_{}.exe", target.name.to_lowercase().replace(' ', "_"));
        let packed_output_path_buf = PathBuf::from(&packed_output_path);

        let status = Command::new(packer_exe_path)
            .arg("--input")
            .arg(&target.path)
            .arg("--output")
            .arg(&packed_output_path_buf)
            .arg("--anti-debug")
            .status()?;

        let packing_success = status.success();
        let original_size = target.path.metadata()?.len() as usize;

        let (packed_size, relayed_sections_count, execution_success, exec_detail) =
            if packing_success && packed_output_path_buf.exists() {
                let p_size = packed_output_path_buf.metadata()?.len() as usize;

                let pe_bytes = std::fs::read(&packed_output_path_buf)?;
                let relayed_count = if let Ok(pe) = goblin::pe::PE::parse(&pe_bytes) {
                    pe.sections.len()
                } else {
                    0
                };

                let orig = Self::run_and_verify(&target.path);
                let packed = Self::run_and_verify(&packed_output_path_buf);

                let behavior_match = (orig.alive == packed.alive)
                    && (orig.alive || orig.code == packed.code);
                let detail = format!(
                    "orig=[alive:{},code:0x{:X}] packed=[alive:{},code:0x{:X}]",
                    orig.alive, orig.code, packed.alive, packed.code
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
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return ExecCheck { alive: false, code: -3, detail: format!("spawn-error: {}", e) },
        };

        // v3: 2.5s → 9s (packed charmap의 0xC0000005 크래시가 ~4~8초에 발생하므로
        // 짧은 대기로는 alive로 오판됨)
        thread::sleep(Duration::from_millis(9000));

        match child.try_wait() {
            Ok(Some(status)) => ExecCheck {
                alive: false,
                code: status.code().unwrap_or(-1),
                detail: "exited".to_string(),
            },
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                ExecCheck { alive: true, code: -2, detail: "alive-after-9s".to_string() }
            }
            Err(e) => ExecCheck { alive: false, code: -1, detail: format!("wait-error: {}", e) },
        }
    }
}

struct ExecCheck {
    alive: bool,
    code: i32,
    #[allow(dead_code)]
    detail: String,
}
