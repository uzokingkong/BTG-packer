// ==============================================================================
// BTG Pipeline - Pass 1: CFG Extraction & Micro-Slicing
// ==============================================================================

use crate::analysis::{CfgEdgeCounts, MetricsAnalyzer};
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
    run_with_indirect_resolutions(ctx, &[])
}

/// Pass-1 entry point for analysis drivers that have proven indirect targets.
/// The canonical model is not installed in `ctx` unless the entire batch maps
/// successfully.
pub fn run_with_indirect_resolutions(
    ctx: &mut PipelineContext,
    indirect_resolutions: &[crate::analysis::indirect_resolver::IndirectResolution],
) -> Result<()> {
    let target_base_va = ctx.target_info.image_base + ctx.target_info.text_rva as u64;
    let target_ep_va = ctx.target_info.image_base + ctx.target_info.entry_point_rva as u64;

    let (mut basic_blocks, mut bi_graph) = CfgExtractor::extract(
        &ctx.target_info.text_bytes,
        target_base_va,
        target_ep_va,
        &ctx.target_info.relayed_sections,
        ctx.target_info.image_base,
    )?;

    let mut program_model =
        crate::analysis::program_model_builder::ProgramModelBuilder::new(&ctx.target_info)
            .build_with_basic_blocks_and_auto_indirect_resolutions(
                &basic_blocks,
                indirect_resolutions,
            )
            .map_err(|error| anyhow::anyhow!(error))?;
    let existing_starts = basic_blocks
        .iter()
        .map(|block| block.start_va)
        .collect::<std::collections::BTreeSet<_>>();
    let discovered_starts = program_model
        .discovered_indirect_code_targets
        .iter()
        .map(|rva| ctx.target_info.image_base + u64::from(*rva))
        .filter(|target| !existing_starts.contains(target))
        .collect::<std::collections::BTreeSet<_>>();
    if !discovered_starts.is_empty() {
        let starts = discovered_starts.iter().copied().collect::<Vec<_>>();
        (basic_blocks, bi_graph) = CfgExtractor::extract_with_additional_starts(
            &ctx.target_info.text_bytes,
            target_base_va,
            target_ep_va,
            &ctx.target_info.relayed_sections,
            ctx.target_info.image_base,
            &starts,
        )?;
        program_model =
            crate::analysis::program_model_builder::ProgramModelBuilder::new(&ctx.target_info)
                .build_with_basic_blocks_and_auto_indirect_resolutions(
                    &basic_blocks,
                    indirect_resolutions,
                )
                .map_err(|error| anyhow::anyhow!(error))?;
        println!(
            "[+] Canonical CFG refinement: {} indirect target boundary(s) materialized.",
            discovered_starts.len()
        );
    }
    println!(
        "[+] Canonical ProgramModel: {} executable range(s), {} function(s), {} block(s), {} edge(s), {} unknown range(s).",
        program_model.executable_ranges.len(),
        program_model.functions.len(),
        program_model.blocks.len(),
        program_model.edges.len(),
        program_model.unknown_ranges.len()
    );
    ctx.program_model = Some(program_model);
    if let Some(model) = ctx.program_model.as_ref() {
        use crate::analysis::indirect_targets::ResolutionStatus;
        use iced_x86::{OpKind, Register};
        let mut shapes = std::collections::BTreeMap::<&'static str, usize>::new();
        let mut patterns = std::collections::BTreeMap::<String, usize>::new();
        for site in model
            .indirect_targets
            .sites
            .values()
            .filter(|site| site.status != ResolutionStatus::Complete)
        {
            let instruction = model.blocks.get(&site.source_block).and_then(|block| {
                block.instructions.iter().find(|instruction| {
                    instruction
                        .ip()
                        .checked_sub(ctx.target_info.image_base)
                        .and_then(|rva| u32::try_from(rva).ok())
                        == Some(site.instruction_rva)
                })
            });
            let transfer = match site.kind {
                crate::analysis::indirect_targets::IndirectKind::Call => "call",
                crate::analysis::indirect_targets::IndirectKind::Jump => "jump",
            };
            let shape = match instruction.map(|i| i.op0_kind()) {
                Some(OpKind::Register) if transfer == "call" => "call-register",
                Some(OpKind::Register) => "jump-register",
                Some(OpKind::Memory)
                    if instruction.is_some_and(|i| i.memory_index() != Register::None) =>
                {
                    if transfer == "call" { "call-indexed-memory" } else { "jump-indexed-memory" }
                }
                Some(OpKind::Memory) if transfer == "call" => "call-direct-memory",
                Some(OpKind::Memory) => "jump-direct-memory",
                _ => "other",
            };
            *shapes.entry(shape).or_default() += 1;
            if let Some(instruction) = instruction {
                let pattern = match instruction.op0_kind() {
                    OpKind::Register => format!("{transfer} {:?}", instruction.op0_register()),
                    OpKind::Memory => format!(
                        "{transfer} [{:?}+{:?}*{}+{:#x}]",
                        instruction.memory_base(),
                        instruction.memory_index(),
                        instruction.memory_index_scale(),
                        instruction.memory_displacement64()
                    ),
                    kind => format!("{:?}:{kind:?}", instruction.code()),
                };
                *patterns.entry(pattern).or_default() += 1;
            }
        }
        if !shapes.is_empty() {
            println!("[+] Canonical unresolved indirect shapes: {shapes:?}");
            let mut top = patterns.into_iter().collect::<Vec<_>>();
            top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            println!(
                "[+] Canonical unresolved top patterns: {:?}",
                top.into_iter().take(16).collect::<Vec<_>>()
            );
            if std::env::var("BTG_DIAG_INDIRECT").is_ok_and(|value| value != "0") {
                for site in model.indirect_targets.sites.values().filter(|site| {
                    site.status
                        != crate::analysis::indirect_targets::ResolutionStatus::Complete
                }) {
                    if let Some(block) = model.blocks.get(&site.source_block) {
                        let mut context = model
                            .edges
                            .iter()
                            .filter_map(|edge| match edge.target {
                                crate::analysis::program_model::EdgeTarget::Block(target)
                                    if target == site.source_block => model.blocks.get(&edge.source),
                                _ => None,
                            })
                            .flat_map(|predecessor| predecessor.instructions.iter().rev().take(8))
                            .map(|instruction| format!("{:#x}:{}", instruction.ip(), instruction))
                            .collect::<Vec<_>>();
                        context.reverse();
                        context.extend(block
                            .instructions
                            .iter()
                            .map(|instruction| format!("{:#x}:{}", instruction.ip(), instruction))
                        );
                        eprintln!(
                            "[INDIRECT-DIAG] rva={:#x} kind={:?} status={:?} block={}",
                            site.instruction_rva, site.kind, site.status, site.source_block.0
                        );
                        for instruction in context {
                            eprintln!("[INDIRECT-CONTEXT] rva={:#x} {instruction}", site.instruction_rva);
                        }
                    }
                }
            }
        }
    }

    println!(
        "[+] Extracted {} Basic Blocks from target CFG.",
        basic_blocks.len()
    );

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
        // full-SEH virtualization (BTG_SEH_NONE) is only verified on the legacy
        // whole-program VM (--vm --vm-oep). The commercial RISC engine keeps the
        // 132 minimal SEH set.
        ctx.vm_oep && !ctx.vm_commercial,
    );
    // ── 실측 플래트닝 지표용: SEH 필터 이전의 원본 CFG 엣지와 시작 주소 스냅샷 ──
    let total_cfg_edges: usize = basic_blocks.iter().map(|bb| bb.successor_vas.len()).sum();
    let pre_filter_edges: Vec<(u64, Vec<u64>)> = basic_blocks
        .iter()
        .map(|bb| (bb.start_va, bb.successor_vas.clone()))
        .collect();
    let all_cfg_starts: std::collections::HashSet<u64> =
        basic_blocks.iter().map(|bb| bb.start_va).collect();
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
    // 양 끝점이 모두 셔플(디스패처 라우팅) 집합에 속하는 엣지만 플래트닝된다.
    // SEH/native 유지 함수와 닿는 엣지(또는 .text 밖/패딩 타깃)는 직접 분기 → 미포함.
    let shuffled_starts: std::collections::HashSet<u64> =
        basic_blocks.iter().map(|bb| bb.start_va).collect();
    let native_starts: std::collections::HashSet<u64> = all_cfg_starts
        .difference(&shuffled_starts)
        .copied()
        .collect();
    let flattened_cfg_edges = pre_filter_edges
        .iter()
        .map(|(src, succs)| {
            succs
                .iter()
                .filter(|dst| shuffled_starts.contains(src) && shuffled_starts.contains(dst))
                .count()
        })
        .sum();
    let cfg_edges = CfgEdgeCounts {
        total: total_cfg_edges,
        flattened: flattened_cfg_edges,
    };

    // MicroSlicer: max_chunk_size = usize::MAX → 원자 기본 블록 경계 유지.
    // 블록 내부에서 자르면 SSE(movaps) 등에서 요구하는 16-byte RSP 정렬이 깨질 수 있음.
    // v10: 디스패처 스택 규약 선택을 전달 (2-푸시 일반 / 3-푸시 재암호화).
    let slicer = MicroSlicer::new(
        usize::MAX,
        ctx.obf_complexity,
        ctx.mba_constant,
        ctx.reencrypt,
    );
    let (text_start_va, text_end_va) = ctx.text_va_range();

    // dispatcher_va + 0x20 = 실제 셸코드 시작점 (OEP Stub 0x00~0x1F 이후)
    let (trigger_blocks, va_to_trigger_id, mut call_target_block_ids) = slicer.slice_blocks(
        &basic_blocks,
        ctx.dispatcher_va + 0x20,
        text_start_va,
        text_end_va,
        &native_starts,
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
        let text_rva_end = ctx
            .target_info
            .text_rva
            .saturating_add(ctx.target_info.text_vsize as u32);
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

    // Canonical ProgramModel is the only additional authority for entries that
    // can bypass the dispatcher. Do not independently re-decode `.text` here:
    // that used to create a second, subtly different call-target policy.
    if ctx.reencrypt {
        let model = ctx
            .program_model
            .as_ref()
            .expect("ProgramModel installed above");
        let mut added = 0usize;
        for rva in model.direct_entry_rvas() {
            let va = ctx.target_info.image_base + rva as u64;
            if let Some(id) = crate::pipeline::patch_data::resolve_block_id(
                &va_to_trigger_id,
                va,
                text_start_va,
                text_end_va,
            ) {
                added += usize::from(call_target_block_ids.insert(id));
            }
        }
        println!(
            "[+] Canonical direct-entry inventory: {added} additional plaintext block(s), {} total",
            call_target_block_ids.len()
        );
    }

    println!(
        "[+] Pass 1 Complete: Micro-Slicer created {} Trigger Blocks.",
        trigger_blocks.len()
    );

    // 난독화 지표 출력 (실측 기반 — flattening/MBA 엔트로피는 상수가 아님)
    let metrics = MetricsAnalyzer::analyze(
        &trigger_blocks,
        ctx.mba_constant,
        ctx.obf_complexity,
        cfg_edges,
    );
    println!("\n------------------------------------------------------------------");
    println!(" [METRICS] BTG Protection Intensity Evaluation ");
    println!("------------------------------------------------------------------");
    println!(
        "  Total Trigger Blocks:        {}",
        metrics.total_trigger_blocks
    );
    println!(
        "  Overlapped Blocks:           {}",
        metrics.overlapped_blocks
    );
    println!(
        "  Instruction Overlap Density: {:.2}%",
        metrics.overlap_density
    );
    println!(
        "  Control Flow Flattening:     {:.2}% (measured: {} / {} CFG edges routed via dispatcher)",
        metrics.flattening_ratio, metrics.flattened_cfg_edges, metrics.total_cfg_edges
    );
    println!("  MBA Key Entropy Score:       {:.2} bits/byte (measured Shannon over {} per-block MBA keys; theoretical bound {} bits)", metrics.mba_entropy_score, metrics.total_trigger_blocks, metrics.mba_entropy_bits);
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
