// ==============================================================================
// BTG QA Benchmark Suite
// ==============================================================================

use btg_packer::error;
use btg_packer::qa::QaBenchmarkRunner;
use std::env;

pub fn run_qa_suite(commercial_vm: bool) -> error::Result<()> {
    println!("==================================================================");
    println!(
        " [QA BENCHMARK SUITE] Running Multi-Compiler PE Compatibility Suite {}",
        if commercial_vm {
            "(commercial Program-VM, strict)"
        } else {
            ""
        }
    );
    println!("==================================================================");

    let current_exe = env::current_exe()?;
    let targets = QaBenchmarkRunner::discover_targets();
    println!("[+] Discovered {} PE benchmark targets.", targets.len());

    println!("\n---------------------------------------------------------------------------------------------");
    println!(" Target Name              | Compiler Environment | Orig Size | Packed Size | Sections | Exec ");
    println!("---------------------------------------------------------------------------------------------");

    let mut failures = 0usize;
    for target in &targets {
        if let Ok(res) = QaBenchmarkRunner::run_benchmark_test(target, &current_exe, commercial_vm)
        {
            // stdout 으로 출력 (env_logger 가 120자에서 로그를 잘라 PASS/FAIL 이
            // 사라지는 문제 방지).
            println!(
                " {:<24} | {:<20} | {:<9} | {:<11} | {:<8} | {}",
                res.target_name,
                res.compiler,
                res.original_size,
                res.packed_size,
                res.relayed_sections_count,
                if res.execution_success {
                    "PASS [OK]"
                } else {
                    "FAIL"
                }
            );
            if !res.execution_success {
                failures += 1;
                println!("      -> {}", res.exec_detail);
            }
        } else {
            failures += 1;
        }
    }
    println!("---------------------------------------------------------------------------------------------\n");
    if commercial_vm && failures != 0 {
        return Err(anyhow::anyhow!(
            "commercial Program-VM QA gate failed for {failures} target(s)"
        )
        .into());
    }
    println!("[SUCCESS] QA Benchmark Testing Suite Completed.");
    Ok(())
}
