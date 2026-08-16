// ==============================================================================
// BTG Pipeline - Pass 1: CFG Extraction & Micro-Slicing
// ==============================================================================

use crate::analysis::MetricsAnalyzer;
use crate::graph::{CfgExtractor, MicroSlicer};
use crate::pipeline::PipelineContext;
use anyhow::Result;

/// Pass 1: 원본 `.text` 섹션에서 기본 블록(CFG)을 추출하고 Trigger Block으로 슬라이싱.
///
/// 완료 후 `ctx`에 설정되는 필드:
/// - `ctx.basic_blocks`
/// - `ctx.trigger_blocks`
/// - `ctx.va_to_trigger_id`
pub fn run(ctx: &mut PipelineContext) -> Result<()> {
    let target_base_va = ctx.target_info.image_base + ctx.target_info.text_rva as u64;
    let target_ep_va = ctx.target_info.image_base + ctx.target_info.entry_point_rva as u64;

    let (basic_blocks, mut bi_graph) = CfgExtractor::extract(
        &ctx.target_info.text_bytes,
        target_base_va,
        target_ep_va,
        &ctx.target_info.relayed_sections,
        ctx.target_info.image_base,
    )?;

    println!("[+] Extracted {} Basic Blocks from target CFG.", basic_blocks.len());

    bi_graph
        .validate_bidirectionality()
        .map_err(|e| anyhow::anyhow!("Bidirectionality check failed: {}", e))?;

    println!("[+] Bidirectional Graph Validation Passed.");

    // ── SEH 함수 비셔플 (plan.txt P0 "SEH 안정화", option A) ──────────────────
    // x64 SEH unwind (panic → catch_unwind)는 raise 지점부터 catch 프레임까지
    // 모든 프레임의 .pdata/UNWIND_INFO가 실제 네이티브 프레임과 일치해야 한다.
    // 블록 셔플된 코드(.textb)는 .pdata 커버리지가 없으므로 test [10]
    // catch_unwind가 0xE06D7363 미처리로 죽는다. 여기서 panic/catch 경로에
    // 속하는 함수(panic 문자열 참조 + EHANDLER/UHANDLER 함수 + raise~catch
    // 사이 프레임)를 원본 .text에 남기고 셔플에서 제외한다. 원본 .text는
    // plaintext로 보존되므로 이 함수들은 원래 주소·원래 .pdata로 실행되어
    // OS unwind가 온전하다. entry 함수는 항상 셔플 유지(디스패처 진입 보존).
    let seh_native = crate::vm::text_lift::detect_seh_native_functions(
        &ctx.target_info.text_bytes,
        target_base_va,
        ctx.target_info.image_base,
        &ctx.target_info.relayed_sections,
        target_ep_va,
    );
    let total_before = basic_blocks.len();
    let basic_blocks: Vec<_> = basic_blocks
        .into_iter()
        .filter(|bb| {
            !seh_native
                .func_ranges
                .iter()
                .any(|&(s, e)| s <= bb.start_va && bb.start_va < e)
        })
        .collect();
    if basic_blocks.len() != total_before {
        println!(
            "[+] Pass 1: {} of {} basic blocks kept native (SEH), {} blocks sliced/shuffled.",
            total_before - basic_blocks.len(),
            total_before,
            basic_blocks.len()
        );
    }

    // MicroSlicer: max_chunk_size = usize::MAX → 원자 기본 블록 경계 유지.
    // 블록 내부에서 자르면 SSE(movaps) 등에서 요구하는 16-byte RSP 정렬이 깨질 수 있음.
    // v10: 디스패처 스택 규약 선택을 전달 (2-푸시 일반 / 3-푸시 재암호화).
    let slicer = MicroSlicer::new(usize::MAX, ctx.obf_complexity, ctx.mba_constant, ctx.reencrypt);
    let (text_start_va, text_end_va) = ctx.text_va_range();

    // dispatcher_va + 0x20 = 실제 셸코드 시작점 (OEP Stub 0x00~0x1F 이후)
    let (trigger_blocks, va_to_trigger_id, mut call_target_block_ids) = slicer.slice_blocks(
        &basic_blocks,
        ctx.dispatcher_va + 0x20,
        text_start_va,
        text_end_va,
    )?;

    // v13: 데이터/코드 **직접 참조** 블록도 평문 유지 대상에 추가한다.
    // 디스패처를 거치지 않고 직접 실행되는 경로:
    //   - .rdata/.data 함수 포인터 (CRT init 테이블, vtable, SEH 핸들러, 점프 테이블)
    //   - .pdata Begin/End (함수 경계)
    //   - .text rip-relative LEA/로드·mov imm64 함수 주소 재료화 (콜백 등록 등)
    // v11은 직접 `call` 명령만 커버해, CRT 초기화 포인터로 호출되는 블록이
    // 암호문 상태로 남아 0xC000001D 크래시가 발생했다 (pack_orig.exe Block
    // 1646 @0x54F6E, initterm_e → .rdata 0x23438). Pass 4(길이 테이블 센티널)와
    // Crypto(암호화 제외)보다 먼저 수집해야 하므로 여기(Pass 1)에서 수행한다.
    {
        let cookie_rva = crate::pipeline::patch_data::locate_security_cookie(
            ctx,
            &ctx.target_info.relayed_sections,
        );
        let protected = crate::pipeline::patch_data::collect_protected_rva_ranges(
            ctx,
            &ctx.target_info.relayed_sections,
            cookie_rva,
        );
        let text_rva_end =
            ctx.target_info.text_rva.saturating_add(ctx.target_info.text_vsize as u32);
        let data_refs = crate::pipeline::patch_data::collect_data_reference_target_ids(
            &ctx.target_info.relayed_sections,
            ctx.target_info.image_base,
            text_start_va,
            text_end_va,
            ctx.target_info.text_rva,
            text_rva_end,
            &va_to_trigger_id,
            &protected,
        );
        let code_refs = crate::pipeline::patch_data::collect_code_materialized_target_ids(
            &ctx.target_info.text_bytes,
            ctx.target_info.image_base + ctx.target_info.text_rva as u64,
            text_start_va,
            text_end_va,
            &va_to_trigger_id,
        );
        let added = data_refs.len() + code_refs.len();
        call_target_block_ids.extend(data_refs.iter().copied());
        call_target_block_ids.extend(code_refs.iter().copied());
        println!(
            "[+] v13 Direct-reference scan: {} data-ptr + {} code-materialized block(s) → plaintext call-target set (total {})",
            data_refs.len(),
            code_refs.len(),
            call_target_block_ids.len()
        );
        let _ = added;
    }

    // ── v13.2-검증: .text 전체를 선형 디코드해 모든 직접 참조 형태가 평문 집합에 있는지 전수 확인 ──
    // v13.1까지는 (a) CFG 기본블록의 call, (b) rip-relative, (c) mov imm64 만 수집했다.
    // CFG가 놓친 코드 영역의 direct call / tail-call jmp, index 레지스터를 쓴
    // rip-relative(점프 테이블 산술) 등이 빠지면 해당 타깃 블록이 암호문으로 남아
    // 0xC000001D 크래시가 난다. 여기서 .text 전체를 독립 디코드해 검증하고,
    // 누락이 발견되면 평문 집합에 추가한다.
    if ctx.reencrypt {
        let mut dec = iced_x86::Decoder::with_ip(
            64,
            &ctx.target_info.text_bytes,
            ctx.target_info.image_base + ctx.target_info.text_rva as u64,
            iced_x86::DecoderOptions::NONE,
        );
        let mut added_v132: std::collections::HashSet<u32> = std::collections::HashSet::new();
        while dec.can_decode() {
            let inst = dec.decode();
            if inst.is_invalid() { continue; }
            // 1) 직접 분기: call / jmp / jcc — 타깃이 블록이면 평문이어야 함
            let is_near = matches!(
                inst.op0_kind(),
                iced_x86::OpKind::NearBranch16
                    | iced_x86::OpKind::NearBranch32
                    | iced_x86::OpKind::NearBranch64
            );
            if is_near {
                let tgt = inst.near_branch_target();
                if let Some(id) = crate::pipeline::patch_data::resolve_block_id(
                    &va_to_trigger_id, tgt, text_start_va, text_end_va,
                ) {
                    if !call_target_block_ids.contains(&id) {
                        added_v132.insert(id);
                    }
                }
            }
            // 2) rip-relative 메모리 피연산자 (index 레지스터 포함 전부)
            if inst.memory_base() == iced_x86::Register::RIP {
                let tgt = inst.ip_rel_memory_address();
                if let Some(id) = crate::pipeline::patch_data::resolve_block_id(
                    &va_to_trigger_id, tgt, text_start_va, text_end_va,
                ) {
                    if !call_target_block_ids.contains(&id) {
                        added_v132.insert(id);
                    }
                }
            }
            // 3) mov r64, imm64 (정확 블록 시작점)
            if inst.code() == iced_x86::Code::Mov_r64_imm64 {
                let tgt = inst.immediate64();
                if tgt >= text_start_va && tgt < text_end_va {
                    if let Some(&id) = va_to_trigger_id.get(&tgt) {
                        if crate::util::is_block_entry(&va_to_trigger_id, tgt, id)
                            && !call_target_block_ids.contains(&id)
                        {
                            added_v132.insert(id);
                        }
                    }
                }
            }
        }
        if !added_v132.is_empty() {
            call_target_block_ids.extend(added_v132.iter().copied());
            println!(
                "[+] v13.2-GAP: {} additional directly-referenced block(s) added to plaintext set (CFG-missed call/jmp/rip-indexed) — total {}",
                added_v132.len(),
                call_target_block_ids.len()
            );
        } else {
            println!("[+] v13.2-VERIFY: all direct references in .text resolve to plaintext blocks. ✓");
        }
    }

    println!(
        "[+] Pass 1 Complete: Micro-Slicer created {} Trigger Blocks.",
        trigger_blocks.len()
    );

    // 난독화 지표 출력
    let metrics = MetricsAnalyzer::analyze(&trigger_blocks);
    println!("\n------------------------------------------------------------------");
    println!(" [METRICS] BTG Protection Intensity Evaluation ");
    println!("------------------------------------------------------------------");
    println!("  Total Trigger Blocks:        {}", metrics.total_trigger_blocks);
    println!("  Overlapped Blocks:           {}", metrics.overlapped_blocks);
    println!("  Instruction Overlap Density: {:.2}%", metrics.overlap_density);
    println!("  Control Flow Flattening:     {:.2}% (design constant — all transitions route via dispatcher)", metrics.flattening_ratio);
    println!("  MBA Key Entropy Score:       {:.0}-bit (theoretical upper bound = key size)", metrics.mba_entropy_score);
    println!("------------------------------------------------------------------\n");

    ctx.basic_blocks = basic_blocks;
    ctx.trigger_blocks = trigger_blocks;
    ctx.va_to_trigger_id = va_to_trigger_id;
    ctx.call_target_block_ids = call_target_block_ids;

    if !ctx.call_target_block_ids.is_empty() {
        println!(
            "[+] Re-Encrypt: {} call-target block(s) — kept plaintext (direct call + data-pointer + code-materialized destinations)",
            ctx.call_target_block_ids.len()
        );
    }

    Ok(())
}
