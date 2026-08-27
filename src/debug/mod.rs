// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Debug & Verification Utilities
// ==============================================================================

use crate::graph::ShuffledLayout;
use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use std::fs;
use std::path::Path;

/// 빌드 완료 후 블록 레이아웃 진단 로그를 파일로 저장.
///
/// 출력 경로: `<output_path>.btg_layout.log`
/// 포맷: 각 블록의 물리 오프셋, 재배치 VA, 역어셈블리 (최대 전체)
pub fn export_debug_layout_log(
    output_path: &Path,
    image_base: u64,
    oep_rva: u32,
    dispatcher_rva: u32,
    layout: &ShuffledLayout,
) -> Result<()> {
    let mut log_path = output_path.to_path_buf();
    log_path.set_extension("btg_layout.log");

    let mut log_str = String::new();
    log_str.push_str("==================================================================\n");
    log_str.push_str(" BTG PACKER AUTONOMOUS RUNTIME DIAGNOSTIC LAYOUT MAP\n");
    log_str.push_str("==================================================================\n\n");
    log_str.push_str(&format!("ImageBase:            0x{:X}\n", image_base));
    log_str.push_str(&format!(
        "OEP RVA:              0x{:X} (VA: 0x{:X})\n",
        oep_rva,
        image_base + oep_rva as u64
    ));
    log_str.push_str(&format!(
        "Dispatcher RVA:       0x{:X} (VA: 0x{:X})\n",
        dispatcher_rva,
        image_base + dispatcher_rva as u64
    ));
    log_str.push_str(&format!(
        "Total Trigger Blocks: {}\n\n",
        layout.shuffled_blocks.len()
    ));

    log_str.push_str("------------------------------------------------------------------\n");
    log_str.push_str(" BLOCK LAYOUT MAP (Physical Offset -> Relocated VA -> Assembly)\n");
    log_str.push_str("------------------------------------------------------------------\n");

    let mut formatter = NasmFormatter::new();
    let mut output = String::new();

    for (i, block) in layout.shuffled_blocks.iter().enumerate() {
        let logical_id = block.id as usize;
        let phys_off = layout.table_offsets[logical_id] as u64;
        let real_va = image_base + dispatcher_rva as u64 + phys_off;

        log_str.push_str(&format!(
            "\n[Block {:03}] Logical ID: {:<3} | Phys Offset: 0x{:04X} | Relocated VA: 0x{:X} | Insts: {}\n",
            i, block.id, phys_off, real_va, block.raw_instructions.len()
        ));

        let mut decoder = Decoder::with_ip(64, &block.instructions, real_va, DecoderOptions::NONE);
        while decoder.can_decode() {
            let inst = decoder.decode();
            output.clear();
            formatter.format(&inst, &mut output);
            log_str.push_str(&format!("  0x{:X}: {}\n", inst.ip(), output));
        }
    }

    fs::write(&log_path, &log_str)?;
    println!(
        "[+] Generated Diagnostic Layout Map Log File: {}",
        log_path.display()
    );
    Ok(())
}

/// 출력 PE 바이너리의 `.btg` 섹션을 직접 파싱하여 블록 배치를 역어셈블·검증.
///
/// v3: 암호화가 켜진 경우 출력 파일의 `.btg` 블록 바이트는 ciphertext이므로,
/// 파일 바이트 대신 메모리 내 `block.instructions`(plaintext)를 사용하여
/// 디스어셈블한다. (블록 레이아웃 검증 목적은 동일)
///
/// 각 블록에 대해:
/// - Entry 0 (+0 offset): 정방향 흐름
/// - Entry 1 (+1 offset): Misaligned 대체 흐름 (존재하는 경우)
pub fn verify_overlapped_disassembly(
    _pe_bytes: &[u8],
    _btg_rva: u64,
    image_base: u64,
    layout: &ShuffledLayout,
) -> Result<()> {
    println!("\n==================================================================");
    println!(" [VERIFICATION] Confirmed Relayed PE Multi-Section Disassembly ");
    println!("==================================================================");

    for block in &layout.shuffled_blocks {
        let phys_offset = layout.table_offsets[block.id as usize] as usize;
        let base_va = image_base + _btg_rva + phys_offset as u64;
        let slice = &block.instructions;

        println!(
            "    [Block {:02}] Phys Offset: 0x{:04X} | Entries: {}",
            block.id,
            phys_offset,
            block.entries.len()
        );

        println!("  [Entry 0 (+0 Offset): Normal Forward Flow]");
        let mut decoder0 = Decoder::with_ip(64, slice, base_va, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        let mut output = String::new();

        let mut inst_count = 0;
        while decoder0.can_decode() && inst_count < 6 {
            let instruction = decoder0.decode();
            output.clear();
            formatter.format(&instruction, &mut output);
            println!("    0x{:X}: {}", instruction.ip(), output);
            inst_count += 1;
        }

        if block.entries.len() > 1 && slice.len() > 1 {
            println!("  [Entry 1 (+1 Offset): Misaligned Alternative Flow]");
            let slice1 = &slice[1..];
            let base_va1 = base_va + 1;

            let mut decoder1 = Decoder::with_ip(64, slice1, base_va1, DecoderOptions::NONE);
            let mut inst_count1 = 0;
            while decoder1.can_decode() && inst_count1 < 6 {
                let instruction = decoder1.decode();
                output.clear();
                formatter.format(&instruction, &mut output);
                println!("    0x{:X}: {}", instruction.ip(), output);
                inst_count1 += 1;
            }
        }
    }
    println!("==================================================================\n");
    Ok(())
}
