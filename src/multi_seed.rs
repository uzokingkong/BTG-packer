use crate::cli::CliArgs;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

fn seeded_output(base: &Path, ordinal: u32, seed: u64) -> PathBuf {
    let parent = base.parent().unwrap_or_else(|| Path::new("."));
    let stem = base
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("protected");
    let ext = base.extension().and_then(|s| s.to_str()).unwrap_or("exe");
    parent.join(format!("{stem}.seed-{ordinal:04}-{seed:016x}.{ext}"))
}

fn child_base_args() -> Vec<OsString> {
    let source: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut out = Vec::with_capacity(source.len());
    let mut i = 0usize;
    while i < source.len() {
        let text = source[i].to_string_lossy();
        let takes_value = matches!(
            text.as_ref(),
            "--verify-seeds" | "--seed" | "--output" | "-o"
        );
        if takes_value {
            i += 2;
            continue;
        }
        if text.starts_with("--verify-seeds=")
            || text.starts_with("--seed=")
            || text.starts_with("--output=")
        {
            i += 1;
            continue;
        }
        // The gate always enables execution verification for every child.
        if text == "--verify-output" {
            i += 1;
            continue;
        }
        out.push(source[i].clone());
        i += 1;
    }
    out
}

pub fn run(args: &CliArgs) -> anyhow::Result<()> {
    if args.verify_seeds == 0 {
        return Ok(());
    }
    let executable = std::env::current_exe()?;
    let base_args = child_base_args();
    let first_seed = args.seed.unwrap_or(1);
    let mut report = String::from("BTG multi-seed execution gate\n");
    report.push_str(&format!("count = {}\n", args.verify_seeds));

    for ordinal in 0..args.verify_seeds {
        let seed = first_seed.wrapping_add(ordinal as u64);
        let output = seeded_output(&args.output, ordinal + 1, seed);
        println!(
            "[SEED-GATE] {}/{} seed=0x{:016X} output={}",
            ordinal + 1,
            args.verify_seeds,
            seed,
            output.display()
        );
        let status = Command::new(&executable)
            .args(&base_args)
            .arg("--seed")
            .arg(seed.to_string())
            .arg("--output")
            .arg(&output)
            .arg("--verify-output")
            .status()
            .map_err(|e| anyhow::anyhow!("failed to start seed gate child: {e}"))?;
        if !status.success() {
            return Err(anyhow::anyhow!(
                "multi-seed gate failed at ordinal {} seed=0x{:016X} (status={})",
                ordinal + 1,
                seed,
                status
            ));
        }
        let bytes = std::fs::read(&output)?;
        let hash = crate::manifest::sha256_hex(&bytes);
        report.push_str(&format!(
            "seed_{:04} = 0x{:016X}, {}, {}\n",
            ordinal + 1,
            seed,
            hash,
            output.display()
        ));
    }

    let mut report_path = args.output.clone();
    report_path.set_extension(
        args.output
            .extension()
            .map(|e| format!("{}.seedgate.txt", e.to_string_lossy()))
            .unwrap_or_else(|| "seedgate.txt".to_string()),
    );
    std::fs::write(&report_path, report)?;
    println!(
        "[SEED-GATE] OK {} independently seeded build(s), report={}",
        args.verify_seeds,
        report_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_names_are_unique_and_keep_extension() {
        let base = Path::new("out/protected.exe");
        assert_eq!(
            seeded_output(base, 1, 0x2A),
            PathBuf::from("out/protected.seed-0001-000000000000002a.exe")
        );
        assert_ne!(seeded_output(base, 1, 42), seeded_output(base, 2, 43));
    }
}
