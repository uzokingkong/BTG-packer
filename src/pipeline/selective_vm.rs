// ==============================================================================
// BTG - Commercial-Grade VM: Selective SDK Marker Virtualization Pipeline Pass
// ==============================================================================
// 대상 PE의 .text 섹션에서 SDK 마커(`BTG_VM_START` ~ `BTG_VM_END`)를 검색하고,
// 마커로 보호 지정된 핵심 루틴만 자동으로 추출하여 RISC 및 폴리모픽 VM으로 컴파일한 뒤
// 원본 위치를 VM 진입 트램펄린으로 패치한다.
//
// T1-2 (치명적 갭 A): 이전엔 `RiscLifter`가 지원하지 못하는 명령을 조용히 skip해
//   잘못된 코드(의미론 파괴)를 생성했다. 이제 리프트 불가 명령이 하나라도 발견되면
//   해당 리전 **전체를 안전하게 거부**하고(부분 lift 금지), 어느 리전도 의미가
//   훼손된 채로 통과하지 않는다.
//
// T1-3: 이전엔 lift→encode 결과 바이트코드를 버려 출력 PE에 VM 런타임/트램펄린이
//   전혀 심어지지 않았다. 이제 각 리전의 폴리모픽 바이트코드 + 시드 + 마커 오프셋을
//   PipelineContext에 저장(더 이상 버리지 않음)하고, 후속 embed 단계가
//   `emit_poly_vm_section`으로 출력 PE에 해석기 스텁과 함께 심는다.
// ==============================================================================

use crate::pipeline::PipelineContext;
use crate::sdk::{MarkerScanner, PolyConsumptionRuntime, SelectiveVirtualizer};
use crate::vm::poly::PolymorphicEncoder;
use crate::vm::risc::{RiscLifter, RiscProgram};
use anyhow::{anyhow, Result};
use iced_x86::{Decoder, DecoderOptions};

/// 마커 리전 하나를 가상화한 결과 — T1-3 embed 단계가 소비한다.
#[derive(Debug, Clone)]
pub struct PolyVmRegion {
    /// .text 내 리전 시작 오프셋 (마커 본문 시작).
    pub start_offset: usize,
    /// .text 내 리전 끝 오프셋.
    pub end_offset: usize,
    /// lift된 RISC 마이크로연산 수.
    pub lifted_ops: usize,
    /// 폴리모픽 바이트코드 (롤링키 암호화).
    pub bytecode: Vec<u8>,
    /// 이 리전에 사용된 폴리모픽 시드 (마커마다 고유).
    pub seed: u64,
    /// 리전 시작 VA (트램펄린 대상).
    pub region_va: u64,
}

pub struct SelectiveVmPass;

impl SelectiveVmPass {
    /// .text 섹션 내의 마커 구간을 스캔하고 RISC 가상화 적용.
    ///
    /// T1-2: 리프트 불가 명령이 있는 리전은 통째로 거부하고 `rejected`에 기록하며
    /// 바이트코드를 생성하지 않는다(잘못된 코드 생성 금지). 반환값은 성공 리전 수.
    pub fn run(ctx: &mut PipelineContext, base_seed: u64) -> Result<usize> {
        let text_data = &ctx.target_info.text_bytes;
        let regions = MarkerScanner::scan_markers(text_data);

        if regions.is_empty() {
            return Ok(0);
        }

        println!(
            "[+] Selective VM Pass: Found {} marked SDK region(s) in .text section",
            regions.len()
        );

        let mut embedded: Vec<PolyVmRegion> = Vec::new();
        let mut rejected: Vec<(usize, String)> = Vec::new();

        for (idx, reg) in regions.iter().enumerate() {
            let slice = &text_data[reg.start_offset..reg.end_offset];
            let base_va = ctx.target_info.image_base + ctx.target_info.text_rva as u64 + reg.start_offset as u64;

            let mut decoder = Decoder::with_ip(64, slice, base_va, DecoderOptions::NONE);
            let mut lifter = RiscLifter::new();
            let mut rejected_inst = None;

            // ── T1-2: 전체를 lift해야만 통과. 하나라도 실패하면 리전 거부 ──────
            while decoder.can_decode() {
                let inst = decoder.decode();
                if let Err(e) = lifter.lift_instruction(&inst) {
                    rejected_inst = Some(format!(
                        "unsupported instruction 0x{:X}: {e}",
                        inst.ip()
                    ));
                    break;
                }
            }

            if let Some(reason) = rejected_inst {
                println!(
                    "    [Region {}] REJECTED (0x{:X}..0x{:X}, {}B): {reason} — region left native, NOT virtualized",
                    idx + 1,
                    reg.start_offset,
                    reg.end_offset,
                    reg.length
                );
                rejected.push((reg.start_offset, reason));
                continue;
            }

            let prog = RiscProgram::new(lifter.desynth.instrs);

            // ── 마커마다 고유 시드 (기본 시드 + 리전 인덱스) ──────────────────
            let seed = base_seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(idx as u64 * 0x9E37_79B9);
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog)?;

            // ── S5: rolling-key 소비 런타임 검증 (데이터 임베드에 그치지 않고 실행 정합) ──
            if let Err(e) = PolyConsumptionRuntime::verify_region(&bytecode, seed, &prog) {
                println!(
                    "    [Region {}] REJECTED (consumption runtime verification failed): {e} — region left native, NOT virtualized",
                    idx + 1
                );
                rejected.push((reg.start_offset, format!("consumption-verify: {e}")));
                continue;
            }

            let region = PolyVmRegion {
                start_offset: reg.start_offset,
                end_offset: reg.end_offset,
                lifted_ops: prog.instrs.len(),
                bytecode,
                seed,
                region_va: base_va,
            };

            println!(
                "    [Region {}] Offset: 0x{:X}..0x{:X} ({}B) -> Lifted: {} RISC micro-ops, Poly Bytecode: {}B (seed=0x{:016X})",
                idx + 1,
                reg.start_offset,
                reg.end_offset,
                reg.length,
                prog.instrs.len(),
                region.bytecode.len(),
                seed
            );
            embedded.push(region);
        }

        if !rejected.is_empty() {
            println!(
                "[!] Selective VM: {} region(s) rejected (unsupported instruction) — left as native to preserve semantics.",
                rejected.len()
            );
        }

        // ── T1-3: 결과를 컨텍스트에 저장 (바이트코드 버리지 않음) ──────────────
        ctx.poly_vm_regions = embedded;
        ctx.poly_vm_regions_rejected = rejected.len();

        Ok(ctx.poly_vm_regions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::{SIG_VM_END, SIG_VM_START};

    /// 마커로 감싼 lift-가능 코드를 스캔해 바이트코드로 저장하는지 검증.
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

    /// T1-2: lift 불가 명령이 포함된 리전은 거부(바이트코드 생성 안 함)되어야 한다.
    #[test]
    fn test_selective_rejects_unsupported_region() {
        let mut text_data = Vec::new();
        text_data.extend_from_slice(&SIG_VM_START);
        // xgetbv (unsupported by the RISC lifter) — must trigger full-region rejection.
        text_data.extend_from_slice(&[0x0F, 0x01, 0xD0]);
        text_data.extend_from_slice(&SIG_VM_END);

        let regions = MarkerScanner::scan_markers(&text_data);
        assert_eq!(regions.len(), 1);
        let slice = &text_data[regions[0].start_offset..regions[0].end_offset];
        let mut decoder = Decoder::with_ip(64, slice, 0x140001000, DecoderOptions::NONE);
        let mut lifter = RiscLifter::new();
        let mut any_err = false;
        while decoder.can_decode() {
            let inst = decoder.decode();
            if lifter.lift_instruction(&inst).is_err() {
                any_err = true;
                break;
            }
        }
        assert!(any_err, "xgetbv must be unsupported so the region is rejected");
    }

    /// S5: SDK 마커 타깃 pack→run 테스트.
    ///
    /// 마커로 감싼 리프트 가능 x86 코드를 lift → rolling-key 폴리모픽 encode 한 뒤
    /// `PolyConsumptionRuntime`(같은 시드로 복호화·실행)로 소비해 원본 프로그램과
    /// **실행 정합**인지 검증한다. 이는 `selective_vm.rs::run` 이 실제로 각 리전을
    /// 임베드하기 전에 거치는 바로 그 경로다 — 데이터 임베드에 그치지 않고
    /// 소비 런타임이 실행 결과를 검증함을 확인한다.
    #[test]
    fn test_sdk_marker_pack_run_consumption_verify() {
        let mut text_data = Vec::new();
        text_data.extend_from_slice(&[0x90, 0x90]); // NOPs
        text_data.extend_from_slice(&SIG_VM_START);

        // x86 code: mov rax, 42; add rax, 8; ret  →  RAX == 50
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
        let base_va = 0x140001000u64;
        let mut decoder = Decoder::with_ip(64, slice, base_va, DecoderOptions::NONE);
        let mut lifter = RiscLifter::new();
        while decoder.can_decode() {
            let inst = decoder.decode();
            lifter.lift_instruction(&inst).unwrap();
        }
        let prog = RiscProgram::new(lifter.desynth.instrs);

        // pack: rolling-key 폴리모픽 encode (seed 0x8899AABBCCDDEEFF)
        let seed = 0x8899AABBCCDDEEFFu64;
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();

        // run: 같은 시드로 소비(복호화) → 원본과 실행 정합 검증.
        PolyConsumptionRuntime::verify_region(&bytecode, seed, &prog).unwrap();

        // 소비된 바이트코드가 실제로 50 을 산출하는지도 확인 (pack→run 동치).
        let consumed = PolyConsumptionRuntime::decode(&bytecode, seed).unwrap();
        let out = consumed.eval_registers(&[0u64; 16]);
        assert_eq!(out[0], 50);
    }

    /// S5: 잘못된 시드(롤링키 desync)로 소비하면 검증이 실패해야 한다 —
    /// 임베드 전 거부 경로가 실제로 동작함을 확인.
    #[test]
    fn test_sdk_marker_consumption_rejects_wrong_seed() {
        let mut text_data = Vec::new();
        text_data.extend_from_slice(&SIG_VM_START);
        text_data.extend_from_slice(&[0x48, 0x31, 0xC0, 0x48, 0x83, 0xC0, 0x07, 0xC3]); // xor rax,rax; add rax,7; ret
        text_data.extend_from_slice(&SIG_VM_END);

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

        let seed = 0x1122334455667788u64;
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();

        // 원본 시드로는 통과, 잘못된 시드로는 실패.
        PolyConsumptionRuntime::verify_region(&bytecode, seed, &prog).unwrap();
        assert!(PolyConsumptionRuntime::verify_region(&bytecode, seed ^ 1, &prog).is_err());
    }
}
