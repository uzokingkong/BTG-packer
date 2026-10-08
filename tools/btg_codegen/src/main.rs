//! BTG Codegen — coverage DB → semantic rule engine → RiscOp lowering /
//! Rust-source generator.
//!
//! Pipeline (mirrors the design note):
//!
//! ```text
//! coverage DB (vm_coverage.json)
//!        │  load + filter gaps
//!        ▼
//! Instruction Family Classifier   (family.rs)
//!        ▼
//! Semantic Rule Engine            (rules.rs)  → AUTO_TEMPLATE / MANUAL / NATIVE
//!        ▼
//! Rust Source Generator           (emit.rs)
//!        ├── generated/lifter_rules.generated.rs   (candidate match-arms)
//!        ├── generated/semantic_tests.generated.rs (test skeletons)
//!        ├── generated/codegen_report.md           (gap analysis)
//!        └── generated/rule_coverage.json          (machine-readable plan)
//! ```
//!
//! The generator is standalone (no dependency on the core crate) and writes
//! only into its output directory — it never patches the production VM.

use anyhow::{Context, Result};
use btg_codegen::coverage::CoverageReport;
use btg_codegen::emit;
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "btg_codegen")]
#[command(about = "Generate RiscOp lowering candidates from the BTG coverage DB")]
struct Args {
    /// Path to a coverage DB JSON (from `vm-coverage` / `btg-cpu-coverage-db`).
    #[arg(long)]
    coverage: PathBuf,

    /// Output directory for generated artifacts.
    #[arg(long, default_value = "tools/btg_codegen/generated")]
    out_dir: PathBuf,

    /// Exit non-zero if any auto-template candidate references an unknown RiscOp
    /// (template-integrity gate for CI).
    #[arg(long)]
    strict: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let report = CoverageReport::load(&args.coverage)?;
    let plan = emit::build_plan(&report);

    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("creating out dir: {}", args.out_dir.display()))?;

    let report_md = emit::render_report_md(&plan);
    let plan_json = serde_json::to_string_pretty(&plan)?;
    let lifter_rs = emit::render_lifter_rules_rs(&plan);
    let tests_rs = emit::render_semantic_tests_rs(&plan);
    let fallback_rs = emit::render_fallback_rs(&plan);

    write(&args.out_dir, "codegen_report.md", &report_md)?;
    write(&args.out_dir, "rule_coverage.json", &plan_json)?;
    write(&args.out_dir, "lifter_rules.generated.rs", &lifter_rs)?;
    write(&args.out_dir, "semantic_tests.generated.rs", &tests_rs)?;
    write(&args.out_dir, "generated_fallback.candidate.rs", &fallback_rs)?;

    let s = &plan.summary;
    println!("BTG codegen plan complete");
    println!("  instructions        : {}", s.instructions);
    println!("  supported           : {}", s.supported);
    println!("  gaps                : {}", s.gaps);
    println!("  auto-template       : {}", s.auto_template);
    println!("  manual-semantics    : {}", s.manual_semantics);
    println!("  native-fallback     : {}", s.native_fallback);
    println!("  output              : {}", args.out_dir.display());

    if args.strict {
        let bad: Vec<&emit::PlanEntry> = plan
            .entries
            .iter()
            .filter(|e| e.strategy == "AUTO_TEMPLATE" && !e.ops_known)
            .collect();
        if !bad.is_empty() {
            for e in &bad {
                eprintln!(
                    "unknown RiscOp in template for {} ({}): {:?}",
                    e.code, e.mnemonic, e.risc_ops
                );
            }
            anyhow::bail!("{} auto-template(s) reference unknown RiscOps", bad.len());
        }
    }

    Ok(())
}

fn write(dir: &std::path::Path, name: &str, body: &str) -> Result<()> {
    let path = dir.join(name);
    fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
