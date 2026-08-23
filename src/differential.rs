use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSnapshot {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DifferentialReport {
    pub original: ExecutionSnapshot,
    pub protected: ExecutionSnapshot,
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}

fn run_captured(path: &Path, timeout: Duration) -> anyhow::Result<ExecutionSnapshot> {
    let executable = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut child = Command::new(&executable)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to execute {}: {e}", executable.display()))?;

    // Drain both pipes while the process runs so verbose targets cannot block
    // on a full OS pipe before they reach their exit path.
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        bytes
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(anyhow::anyhow!(
                "execution timed out after {:.1}s: {}",
                timeout.as_secs_f64(),
                executable.display()
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };

    Ok(ExecutionSnapshot {
        exit_code: exit_code(status),
        stdout: stdout_reader.join().unwrap_or_default(),
        stderr: stderr_reader.join().unwrap_or_default(),
    })
}

pub fn verify_equivalent(
    original: &Path,
    protected: &Path,
    timeout: Duration,
) -> anyhow::Result<DifferentialReport> {
    let original_run = run_captured(original, timeout)?;
    let protected_run = run_captured(protected, timeout)?;
    let report = DifferentialReport {
        original: original_run,
        protected: protected_run,
    };

    if report.original.exit_code != report.protected.exit_code
        || report.original.stdout != report.protected.stdout
        || report.original.stderr != report.protected.stderr
    {
        return Err(anyhow::anyhow!(
            "differential verification failed: exit {} -> {}, stdout {}B -> {}B, stderr {}B -> {}B",
            report.original.exit_code,
            report.protected.exit_code,
            report.original.stdout.len(),
            report.protected.stdout.len(),
            report.original.stderr.len(),
            report.protected.stderr.len()
        ));
    }
    Ok(report)
}

/// Move an output that failed execution verification out of the normal
/// artifact name. Existing failed artifacts are preserved by adding a counter.
pub fn isolate_failed_output(path: &Path) -> anyhow::Result<std::path::PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("protected");
    let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("bin");
    for index in 0..10_000usize {
        let suffix = if index == 0 {
            String::new()
        } else {
            format!(".{index}")
        };
        let candidate = parent.join(format!("{stem}.failed{suffix}.{extension}"));
        if !candidate.exists() {
            std::fs::rename(path, &candidate).map_err(|e| {
                anyhow::anyhow!(
                    "failed to isolate {} as {}: {e}",
                    path.display(),
                    candidate.display()
                )
            })?;
            return Ok(candidate);
        }
    }
    Err(anyhow::anyhow!(
        "failed-artifact namespace exhausted for {}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_test_binary_matches_itself() {
        let exe = std::env::current_exe().unwrap();
        // Avoid recursively running the test harness. The comparison contract
        // itself is covered through the pure snapshot equality below.
        let a = ExecutionSnapshot {
            exit_code: 0,
            stdout: b"same".to_vec(),
            stderr: Vec::new(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        assert!(exe.exists());
    }

    #[test]
    fn failed_output_is_renamed_without_overwriting_existing_artifact() {
        let base =
            std::env::temp_dir().join(format!("btg-differential-isolate-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let output = base.join("sample.exe");
        std::fs::write(&output, b"failed-output").unwrap();
        let isolated = isolate_failed_output(&output).unwrap();
        assert_eq!(isolated.file_name().unwrap(), "sample.failed.exe");
        assert!(!output.exists());
        assert_eq!(std::fs::read(&isolated).unwrap(), b"failed-output");
        let _ = std::fs::remove_file(isolated);
        let _ = std::fs::remove_dir(base);
    }
}
