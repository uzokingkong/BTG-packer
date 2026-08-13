// ==============================================================================
// BTG - section/file entropy reporting (moved from main.rs)
// ==============================================================================

/// Shannon entropy (bits/byte) — 8.0 = 완전 랜덤, 낮을수록 탐지에 안전.
pub(crate) fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .map(|&c| {
            if c == 0 {
                0.0
            } else {
                let p = c as f64 / n;
                -p * p.log2()
            }
        })
        .sum()
}

/// 출력 PE의 섹션별 엔트로피를 출력한다 (v4).
pub fn print_entropy_report(output_pe_bytes: &[u8]) {
    use goblin::pe::PE;
    let Ok(pe) = PE::parse(output_pe_bytes) else { return };
    println!("\n[ENTROPY] per-section Shannon entropy (bits/byte):");
    for sec in &pe.sections {
        let name = sec.name().unwrap_or("?");
        let raw_ptr = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        let end = (raw_ptr + raw_size).min(output_pe_bytes.len());
        let data = if raw_ptr < output_pe_bytes.len() {
            &output_pe_bytes[raw_ptr..end]
        } else {
            &[][..]
        };
        println!(
            "  {:<10} {:5.3} bits/byte  ({} bytes)",
            name,
            shannon_entropy(data),
            data.len()
        );
    }
    println!(
        "  file-total {:5.3} bits/byte",
        shannon_entropy(output_pe_bytes)
    );
}
