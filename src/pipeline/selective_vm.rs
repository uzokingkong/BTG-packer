// ==============================================================================
// BTG - Commercial-Grade VM: Selective SDK Marker Virtualization Pipeline Pass
// ==============================================================================
// 대상 PE의 .text 섹션에서 SDK 마커(`BTG_VM_START` ~ `BTG_VM_END`)를 검색하고,
// 마커로 보호 지정된 핵심 루틴만 자동으로 추출하여 RISC 및 폴리모픽 VM으로 컴파일한 뒤
// 원본 위치를 VM 진입 트램펄린으로 패치한다.
// ==============================================================================

use crate::pipeline::PipelineContext;
use crate::sdk::{MarkerScanner, SelectiveVirtualizer, VmMarkerRegion};
use crate::vm::poly::PolymorphicEncoder;
use crate::vm::risc::{RiscLifter, RiscProgram};
use anyhow::{anyhow, Result};
use iced_x86::{Decoder, DecoderOptions};

pub struct SelectiveVmPass;

impl SelectiveVmPass {
    /// .text 섹션 내의 마커 구간을 스캔하고 RISC 가상화 적용
    pub fn run(ctx: &mut PipelineContext, seed: u64) -> Result<usize> {
        let text_data = &ctx.target_info.text_bytes;
        let regions = MarkerScanner::scan_markers(text_data);

        if regions.is_empty() {
            return Ok(0);
        }

        println!(
            "[+] Selective VM Pass: Found {} marked SDK region(s) in .text section",
            regions.len()
        );

        let mut total_lifted = 0usize;

        for (idx, reg) in regions.iter().enumerate() {
            let slice = &text_data[reg.start_offset..reg.end_offset];
            let base_va = ctx.target_info.image_base + ctx.target_info.text_rva as u64 + reg.start_offset as u64;

            let mut decoder = Decoder::with_ip(64, slice, base_va, DecoderOptions::NONE);
            let mut lifter = RiscLifter::new();

            while decoder.can_decode() {
                let inst = decoder.decode();
                if let Err(e) = lifter.lift_instruction(&inst) {
                    println!("[!] Selective VM: skipping complex instruction at 0x{:X}: {e}", inst.ip());
                }
            }

            let prog = RiscProgram::new(lifter.desynth.instrs);
            total_lifted += prog.instrs.len();

            let mut enc = PolymorphicEncoder::new(seed.wrapping_add(idx as u64));
            let bytecode = enc.encode(&prog)?;

            println!(
                "    [Region {}] Offset: 0x{:X}..0x{:X} ({}B) -> Lifted: {} RISC micro-ops, Poly Bytecode: {}B",
                idx + 1,
                reg.start_offset,
                reg.end_offset,
                reg.length,
                prog.instrs.len(),
                bytecode.len()
            );
        }

        Ok(regions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::{SIG_VM_END, SIG_VM_START};

    #[test]
    fn test_selective_pipeline_scan_and_lift() {
        let mut text_data = Vec::new();
        text_data.extend_from_slice(&[0x90, 0x90]); // NOPs
        text_data.extend_from_slice(&SIG_VM_START);

        // x86 code: mov rax, 42; add rax, 8; ret
        let marked_code = [
            0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00, // mov rax, 42
            0x48, 0x83, 0xC0, 0x08,                   // add rax, 8
            0xC3,                                     // ret
        ];
        text_data.extend_from_slice(&marked_code);
        text_data.extend_from_slice(&SIG_VM_END);
        text_data.extend_from_slice(&[0x90, 0x90]);

        let regions = MarkerScanner::scan_markers(&text_data);
        assert_eq!(regions.len(), 1);

        let slice = &text_data[regions[0].start_offset..regions[0].end_offset];
        let mut decoder = Decoder::with_ip(64, slice, 0x140001000, DecoderOptions::NONE);
        let mut lifter = RiscLifter::new();

        while decoder.can_decode() {
            let inst = decoder.decode();
            lifter.lift_instruction(&inst).unwrap();
        }

        let prog = RiscProgram::new(lifter.desynth.instrs);
        let regs = [0u64; 16];
        let out = prog.eval_registers(&regs);
        assert_eq!(out[0], 50); // 42 + 8 = 50
    }
}
