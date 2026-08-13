// ==============================================================================
// BTG Pipeline - Patch: Section Data Relocation & CFG Fixup
// ==============================================================================

use crate::pe::builder::SectionData;
use crate::pipeline::PipelineContext;
use crate::util::{resolve_va_to_real_va, is_block_entry};
use anyhow::Result;
use std::collections::{BTreeMap, HashSet};

/// 섹션 데이터 재배치 및 CFG 포인터 패치.
///
/// 처리 순서:
/// 1. GS Cookie (`__security_cookie`) 사전 초기화 (.data/.rdata)
/// 2. `.pdata` RuntimeFunction 항목 재배치
/// 3. 실행 가능 코드 섹션 분기 타깃 재배치
/// 4. `.rdata` / `.data` 64-bit VA 재배치
/// 5. LoadConfig CFG 포인터 리다이렉션 & Guard Flags 제거
///
/// 완료 후 `ctx.patched_sections`에 결과가 저장된다.
pub fn run(ctx: &mut PipelineContext, mut relayed_sections: Vec<SectionData>) -> Result<()> {
    let dispatcher_va = ctx.dispatcher_va;
    let layout = ctx.shuffled_layout.as_ref()
        .ok_or_else(|| anyhow::anyhow!("ShuffledLayout not built"))?;
    let table_offsets = &layout.table_offsets;
    let va_to_trigger_id = &ctx.va_to_trigger_id;
    let (text_start_va, text_end_va) = ctx.text_va_range();
    let image_base = ctx.target_info.image_base;

    // ── 1. GS Cookie 위치 탐색 및 보호 RVA 범위 수집 ────────────────────────────
    let cookie_rva = locate_security_cookie(ctx, &relayed_sections);
    let protected_ranges = collect_protected_rva_ranges(ctx, &relayed_sections, cookie_rva);
    println!(
        "[+] Protected {} RVA ranges (Import Directory, DLL names, INT/IAT, LoadConfig, etc.) from data fixup.",
        protected_ranges.len()
    );

    // ── 1.1 __security_cookie 사전 안전 할당 ─────────────────────────────────────
    // cookie_rva 위치의 __security_cookie가 0으로 남아 있으면 MSVC __security_check_cookie
    // 검사 시 0 == 0xFFFF... 식의 미초기화 비호환으로 __fastfail(7) 0xC0000409가 발생한다.
    // 0이면 기본 MSVC 시드(0x00002B992DDFA232)를 미리 써준다.
    if cookie_rva > 0 {
        for sec in &mut relayed_sections {
            if cookie_rva >= sec.virtual_address && cookie_rva + 8 <= sec.virtual_address + sec.virtual_size {
                let off = (cookie_rva - sec.virtual_address) as usize;
                if off + 8 <= sec.bytes.len() {
                    let cur_val = u64::from_le_bytes(sec.bytes[off..off + 8].try_into().unwrap_or([0; 8]));
                    if cur_val == 0 {
                        sec.bytes[off..off + 8].copy_from_slice(&0x00002B992DDFA232u64.to_le_bytes());
                        println!("[+] Pre-initialized unset __security_cookie @ RVA 0x{:X} with default MSVC seed.", cookie_rva);
                    }
                }
            }
        }
    }

    // ── 2. .pdata RuntimeFunction 재배치 제거 (v13.4c) ──────────────────────────
    // 원래 여기서 각 .pdata 엔트리의 Begin/End RVA 를 `resolve_va_to_real_va`로
    // 각각 독립 remap 했는데, 전역 블록 shuffle 후에는 원본 함수의 Begin 과 End 가
    // 물리적으로 분리·재배치되어 [new_begin, new_end) 범위 안에 그 함수가 아닌 수많은
    // 다른 블록이 섞인다. 그런 잘못된 RUNTIME_FUNCTION 범위를 OS 언와인더가 읽으면
    // 잘못된 UNWIND_INFO → 잘못된 RSP → 0xC0000005 가 된다.
    //
    // 블록 shuffle된 함수는 단일 연속 RUNTIME_FUNCTION 으로 표현할 수 없으므로
    // 여기서 재배치하지 않는다. 원본 `.text`는 TLS/CRT/native bridge에서 계속
    // 실행되므로 build.rs(update_pdata_seh)는 원본 엔트리를 모두 보존하고
    // 디스패처 부트 영역의 leaf만 추가한다. (.pdata 입력은 여기서 수정하지 않는다.)
    let mut patched_ptrs_count = 0usize;

    for sec in &mut relayed_sections {
        if sec.name == ".pdata" {
            println!("[+] .pdata: skipped Begin/End relocation (block-shuffled functions are non-contiguous; handled in build.rs).");
            continue;
        }

        // ── 3. 실행 가능 코드 섹션 분기 재배치 ───────────────────────────────────
        // fothk = IAT Forwarder Thunk 섹션: CODE 비트가 있지만 jmp [mem] 형태의
        // 간접 점프만 있어 near branch가 없으므로 재배치 대상에서 제외.
        // 이 섹션을 재배치하면 모든 API 호출이 잘못된 주소로 분기된다.
        // FIX(크래시): 원본 .text 섹션의 분기 재배치는 수행하지 않는다.
        // .text는 로더가 이미지 로드 시점(부트 스텁 실행 전)에 실행하는 TLS 콜백이
        // 있는 코드이며, 재배치로 인해 short 분기(2B)가 rel32(6B)로 확장되어 다음
        // 명령을 덮어쓰면서 .text 전체와 TLS 콜백이 파괴되고 0xC0000005가 발생했다.
        // .text는 원본 그대로(실행 가능한 안전 복사본) 유지하고, 실제 실행은
        // .btg 블록(Pass 3 재인코딩)이 담당하므로 보호 커버리지 손실이 없다.
        if (sec.characteristics & 0x20000000) != 0
            && sec.name != ".btg"
            && sec.name != "fothk"
            && sec.name != ".text"
        {
            let sec_start_va = image_base + sec.virtual_address as u64;
            let mut patches = Vec::new();
            let mut decoder = iced_x86::Decoder::with_ip(64, &sec.bytes, sec_start_va, iced_x86::DecoderOptions::NONE);

            while decoder.can_decode() {
                let mut inst = decoder.decode();
                if !inst.is_invalid() && inst.code() != iced_x86::Code::Int3 {
                    if matches!(
                        inst.flow_control(),
                        iced_x86::FlowControl::UnconditionalBranch
                            | iced_x86::FlowControl::ConditionalBranch
                            | iced_x86::FlowControl::Call
                    ) && matches!(
                        inst.op0_kind(),
                        iced_x86::OpKind::NearBranch16
                            | iced_x86::OpKind::NearBranch32
                            | iced_x86::OpKind::NearBranch64
                    ) {
                        let orig_target_va = inst.near_branch_target();
                        if orig_target_va >= text_start_va && orig_target_va < text_end_va {
                            // FIX: 오직 **블록 시작점(block entry)** 타깃만 .btg로 재배치한다.
                            // 블록 중간 타깃을 `range(..=).next_back()` + `offset_within_block`으로
                            // 매핑하면 Pass 3 재인코딩으로 명령어 길이가 바뀐 블록에서
                            // 명령어 중간으로 점프하여 0xC0000005 크래시가 발생할 수 있다.
                            // 매칭되지 않는 타깃은 원본 .text 주소를 그대로 유지한다(안전).
                            if let Some(real_target_va) = resolve_va_to_real_va(
                                orig_target_va,
                                text_start_va,
                                text_end_va,
                                va_to_trigger_id,
                                table_offsets,
                                dispatcher_va,
                            ) {
                                let target_block_id =
                                    va_to_trigger_id.get(&orig_target_va).copied().unwrap_or(u32::MAX);
                                inst.set_near_branch64(real_target_va);
                                let offset_in_sec = (inst.ip() - sec_start_va) as usize;
                                let inst_arr = [inst];
                                let single_block = iced_x86::InstructionBlock::new(&inst_arr, inst.ip());
                                if let Ok(encoded) = iced_x86::BlockEncoder::encode(
                                    64, single_block, iced_x86::BlockEncoderOptions::NONE
                                ) {
                                    // FIX(안전): 재인코딩된 분기 길이가 원본보다 길어지면
                                    // in-place 패치는 다음 명령을 덮어쓴다(중첩 손상).
                                    // 길이가 같거나 짧을 때만 적용한다.
                                    if encoded.code_buffer.len() <= inst.len() {
                                        patches.push((
                                            offset_in_sec, encoded.code_buffer,
                                            orig_target_va, real_target_va, target_block_id,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for (offset_in_sec, code_buf, orig_target_va, real_target_va, target_block_id) in patches {
                if offset_in_sec + code_buf.len() <= sec.bytes.len() {
                    sec.bytes[offset_in_sec..offset_in_sec + code_buf.len()].copy_from_slice(&code_buf);
                    println!(
                        "[+] Executable Section Fixup: Sec {} Offset 0x{:X} | Target 0x{:X} -> 0x{:X} (Block {})",
                        sec.name, offset_in_sec, orig_target_va, real_target_va, target_block_id
                    );
                }
            }
            continue;
        }

        // ── 4. .rdata / .data 64-bit VA 및 32-bit RVA 재배치 ────────────────────
        // RTTI, 상수 테이블 데이터 오염을 방지하기 위해, 정확히 Trigger Block의 시작점(Exact Entry VA)을
        // 가리키는 진성 함수 포인터 / SEH 핸들러 / vtable 엔트리만 패치한다.
        if sec.name != ".rdata" && sec.name != ".data" {
            continue;
        }

        let text_rva_start = ctx.target_info.text_rva;
        let text_rva_end = ctx.target_info.text_rva + ctx.target_info.text_vsize as u32;

        if sec.bytes.len() >= 4 {
            // 4바이트 정렬 오프셋으로 32-bit RVA 및 64-bit VA 스캔
            // ── v15 FIX: 32-bit RVA 후보 사전 스캔 (원본 바이트 기준) ─────────────
            // (sr_ko2.exe 0xC0000409 @ 0x7DFC3 크래시 근본 원인)
            // .rdata/.data의 4바이트 값이 우연히 원본 .text 블록 시작 RVA와 일치하면
            // (예: CRT 와이드 문자 DFA 테이블 .rdata @0x2B680의 값 0x00010000),
            // 진성 32-bit RVA 포인터로 오인되어 재배치되어 테이블이 손상된다. 손상된
            // 테이블을 읽은 CRT 스캐너가 오류 상태(>=8)에 진입 → _invalid_parameter
            // → _invalid_parameter_noinfo_noreturn → __fastfail(FAST_FAIL_INVALID_ARG)
            // → 0xC0000409. 진성 32-bit RVA 함수 포인터 테이블(SEH ScopeTable/RTTI/
            // CRT)은 인접 슬롯도 포인터인 밀집 배열로 존재하므로, 아래 메인 루프에서
            // "인접 슬롯(±4)도 유효 후보"일 때만 재배치한다. 고립된 우연 일치는 원본
            // .text 주소를 유지 — 패커 출력에 원본 .text가 실행 가능하게 보존되므로
            // 안전하다 (보호 커버리지만 감소).
            let mut rva32_candidates: HashSet<usize> = HashSet::new();
            for offset in (0..sec.bytes.len().saturating_sub(3)).step_by(4) {
                let current_rva = sec.virtual_address + offset as u32;
                if is_rva_range_protected(current_rva, 4, &protected_ranges) {
                    continue;
                }
                let val32 = u32::from_le_bytes(sec.bytes[offset..offset + 4].try_into().unwrap_or([0; 4]));
                if val32 >= text_rva_start && val32 < text_rva_end {
                    let orig_va = image_base + val32 as u64;
                    if let Some(&_tid) = va_to_trigger_id.get(&orig_va) {
                        if is_block_entry(va_to_trigger_id, orig_va, _tid) {
                            rva32_candidates.insert(offset);
                        }
                    }
                }
            }

            for offset in (0..sec.bytes.len().saturating_sub(3)).step_by(4) {
                let current_rva = sec.virtual_address + offset as u32;

                // 1. 64-bit VA 재배치 (8바이트 정렬 오프셋일 때)
                if offset % 8 == 0 && offset + 8 <= sec.bytes.len() {
                    if !is_rva_range_protected(current_rva, 8, &protected_ranges) {
                        let val64 = u64::from_le_bytes(sec.bytes[offset..offset + 8].try_into().unwrap_or([0; 8]));
                        if val64 >= text_start_va && val64 < text_end_va {
                            // FIX: va_to_trigger_id는 모든 인스트럭션 IP를 키로 갖는다.
                            // 블록 중간 인스트럭션을 가리키는 데이터 상수를 블록 시작점으로
                            // 오버패치하지 않도록 **블록 시작점(block entry)일 때만** 재배치한다.
                            // (블록 중간 포인터는 원본 .text 주소를 유지 → 원본 코드가 그대로
                            //  실행되므로 안전)
                            if let Some(&target_block_id) = va_to_trigger_id.get(&val64) {
                                if is_block_entry(va_to_trigger_id, val64, target_block_id) {
                                    let real_target_va = dispatcher_va + table_offsets[target_block_id as usize] as u64;
                                    sec.bytes[offset..offset + 8].copy_from_slice(&real_target_va.to_le_bytes());
                                    patched_ptrs_count += 1;
                                    log::debug!(
                                        "[+] Section Data Fixup (64-bit Exact VA): Sec {} Offset 0x{:X} | Old VA: 0x{:X} -> New VA: 0x{:X}",
                                        sec.name, offset, val64, real_target_va
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                }

                // 2. 32-bit RVA 재배치 (SEH ScopeTable, RTTI, CRT Function Pointer Tables)
                // v15: 사전 스캔된 후보 중 인접 슬롯(±4)도 유효 후보인 "밀집 배열"
                // 슬롯만 재배치한다. 테이블 데이터의 우연 일치(고립)는 원본 그대로.
                if rva32_candidates.contains(&offset)
                    && ((offset >= 4 && rva32_candidates.contains(&(offset - 4)))
                        || rva32_candidates.contains(&(offset + 4)))
                    && !is_rva_range_protected(current_rva, 4, &protected_ranges)
                {
                    let val32 = u32::from_le_bytes(sec.bytes[offset..offset + 4].try_into().unwrap_or([0; 4]));
                    if val32 >= text_rva_start && val32 < text_rva_end {
                        let orig_va = image_base + val32 as u64;
                        // FIX: 위 64-bit 경로와 동일하게 **블록 시작점(block entry)일 때만** 재배치.
                        if let Some(&target_block_id) = va_to_trigger_id.get(&orig_va) {
                            if is_block_entry(va_to_trigger_id, orig_va, target_block_id) {
                                let real_target_va = dispatcher_va + table_offsets[target_block_id as usize] as u64;
                                let real_rva = (real_target_va - image_base) as u32;
                                sec.bytes[offset..offset + 4].copy_from_slice(&real_rva.to_le_bytes());
                                patched_ptrs_count += 1;
                                log::debug!(
                                    "[+] Section Data Fixup (32-bit Exact RVA): Sec {} Offset 0x{:X} | Old RVA: 0x{:X} -> New RVA: 0x{:X}",
                                    sec.name, offset, val32, real_rva
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    println!(
        "[+] Section Data Fixup Complete: Relocated {} function pointers (VA & RVA) in data sections to .btg",
        patched_ptrs_count
    );

    // ── 5. LoadConfig CFG 포인터 리다이렉션 (Win11 24H2 CFG BEX64 0xC0000409 크래시 방지) ──
    // Win11 24H2 로더는 LoadConfig.GuardFlags를 보고 CFG를 강제하므로(DllCharacteristics의
    // GUARD_CF 비트 제거만으로는 부족), GuardCFCheck/DispatchFunctionPointer를 .btg 내
    // no-op 스텁(ret / jmp rax)으로 리다이렉트하고 GuardCFFunctionTable/Count/Flags를
    // 0으로 만들어 로더가 CFG 계측으로 인식하지 못하게 한다. (원본 real_win_calc.exe는
    // /guard:cf 빌드라 .btg로 옮겨진 간접 호출 타깃이 CFG 비트맵에 없어 RtlFailFast 발생)
    let check_stub_va = dispatcher_va + 0x1F;   // RET stub
    let dispatch_stub_va = dispatcher_va + 0x1D; // JMP RAX stub

    if let Some(lc_dir) = ctx.target_info.data_directories.get(10) {
        if lc_dir.virtual_address > 0 && lc_dir.size > 0 {
            let lc_rva = lc_dir.virtual_address;
            let lc_size = lc_dir.size as usize;

            for sec_idx in 0..relayed_sections.len() {
                let sec_va = relayed_sections[sec_idx].virtual_address;
                let sec_vsize = relayed_sections[sec_idx].virtual_size;

                if lc_rva >= sec_va && lc_rva < sec_va + sec_vsize {
                    let offset_in_sec = (lc_rva - sec_va) as usize;
                    let lc_end = (offset_in_sec + lc_size).min(relayed_sections[sec_idx].bytes.len());

                    // GuardCFCheckFunctionPointer (offset 0x70)
                    patch_cfg_ptr(
                        &mut relayed_sections, sec_idx, offset_in_sec, lc_end,
                        0x70, check_stub_va, image_base, "GuardCFCheckFunctionPointer",
                    );

                    // GuardCFDispatchFunctionPointer (offset 0x78)
                    patch_cfg_ptr(
                        &mut relayed_sections, sec_idx, offset_in_sec, lc_end,
                        0x78, dispatch_stub_va, image_base, "GuardCFDispatchFunctionPointer",
                    );

                    // GuardCFFunctionTable / Count / Flags 제거
                    if offset_in_sec + 0x94 <= lc_end {
                        relayed_sections[sec_idx].bytes[offset_in_sec + 0x80..offset_in_sec + 0x88].fill(0);
                        relayed_sections[sec_idx].bytes[offset_in_sec + 0x88..offset_in_sec + 0x90].fill(0);
                        relayed_sections[sec_idx].bytes[offset_in_sec + 0x90..offset_in_sec + 0x94]
                            .copy_from_slice(&0u32.to_le_bytes());
                        println!(
                            "[+] Disabled OS Control Flow Guard: Zeroed GuardCFFunctionTable/Count/Flags in section {}",
                            relayed_sections[sec_idx].name
                        );
                    }
                    break;
                }
            }
        }
    }

    // 원본 런타임 코드는 바이트 패턴으로 수정하지 않는다. Rust thread-guard의
    // 상태 분기나 `int 29h` fast-fail을 바꾸면 정상 teardown 상태 머신이 깨지고,
    // noreturn 경로에서 `ret`하여 손상된 스택으로 실행을 계속하게 된다. -2 주소나
    // fast-fail이 관찰되면 그 앞의 변환 버그를 고쳐야 하며 트랩을 지워서는 안 된다.

    ctx.patched_sections = relayed_sections;
    Ok(())
}

/// LoadConfig 내 CFG 함수 포인터를 stub VA로 리다이렉트한다.
fn patch_cfg_ptr(
    sections: &mut Vec<SectionData>,
    lc_sec_idx: usize,
    offset_in_sec: usize,
    lc_end: usize,
    field_offset: usize,
    stub_va: u64,
    image_base: u64,
    field_name: &str,
) {
    if offset_in_sec + field_offset + 8 > lc_end {
        return;
    }
    let ptr_va = u64::from_le_bytes(
        sections[lc_sec_idx].bytes[offset_in_sec + field_offset..offset_in_sec + field_offset + 8]
            .try_into()
            .unwrap_or([0; 8]),
    );
    if ptr_va == 0 {
        return;
    }
    let ptr_rva = (ptr_va.saturating_sub(image_base)) as u32;
    for psec in sections.iter_mut() {
        if ptr_rva >= psec.virtual_address
            && ptr_rva + 8 <= psec.virtual_address + psec.bytes.len() as u32
        {
            let poff = (ptr_rva - psec.virtual_address) as usize;
            psec.bytes[poff..poff + 8].copy_from_slice(&stub_va.to_le_bytes());
            println!(
                "[+] Dynamic CFG Redirect: {} (Sec {} Offset 0x{:X}) -> 0x{:X}",
                field_name, psec.name, poff, stub_va
            );
        }
    }
}

/// LoadConfig 내 SecurityCookie VA를 읽어 RVA를 반환한다.
/// 실패 시 `.data`/`.rdata`에서 기본 시드값(`0x00002B992DDFA232`)으로 스캔한다.
pub(crate) fn locate_security_cookie(ctx: &PipelineContext, sections: &[SectionData]) -> u32 {
    let image_base = ctx.target_info.image_base;

    // LoadConfig (DataDirectory[10]) 에서 SecurityCookie 오프셋 0x58
    // (IMAGE_LOAD_CONFIG_DIRECTORY64: SecurityCookie = 0x58, GuardFlags = 0x90)
    if let Some(lc_dir) = ctx.target_info.data_directories.get(10) {
        if lc_dir.virtual_address > 0 && lc_dir.size >= 0x60 {
            let lc_rva = lc_dir.virtual_address;
            for s in sections {
                if lc_rva >= s.virtual_address && lc_rva + 0x60 <= s.virtual_address + s.virtual_size {
                    let off = (lc_rva - s.virtual_address) as usize;
                    if off + 0x60 <= s.bytes.len() {
                        let cookie_va = u64::from_le_bytes(
                            s.bytes[off + 0x58..off + 0x60].try_into().unwrap_or([0; 8]),
                        );
                        if cookie_va > image_base {
                            return (cookie_va - image_base) as u32;
                        }
                    }
                }
            }
        }
    }

    // Fallback: MSVC 기본 시드값 스캔
    for s in sections {
        if s.name == ".data" || s.name == ".rdata" {
            for off in (0..s.bytes.len().saturating_sub(7)).step_by(8) {
                let val = u64::from_le_bytes(s.bytes[off..off + 8].try_into().unwrap_or([0; 8]));
                if val == 0x00002B992DDFA232u64 {
                    return s.virtual_address + off as u32;
                }
            }
        }
    }

    0
}

/// 오프셋 `start_rva`부터 `len` 바이트 영역이 `protected_ranges`와 중복되는지 체크한다.

mod imports;

pub(crate) use imports::{is_rva_range_protected, rva_to_slice, get_ascii_string_rva_range, collect_import_directory_ranges, collect_delay_import_directory_ranges};

/// PE 데이터 섹션 내의 재배치 보호 RVA 범위 목록을 수집하여 정렬 및 병합한다.
pub(crate) fn collect_protected_rva_ranges(
    ctx: &PipelineContext,
    sections: &[SectionData],
    cookie_rva: u32,
) -> Vec<(u32, u32)> {
    let mut raw_ranges = Vec::new();

    // DataDirectory 0: Export Directory
    if let Some(dir) = ctx.target_info.data_directories.get(0) {
        if dir.virtual_address > 0 && dir.size > 0 {
            raw_ranges.push((dir.virtual_address, dir.virtual_address.saturating_add(dir.size)));
        }
    }

    // DataDirectory 1: Import Directory
    let import_dir = ctx.target_info.data_directories.get(1);
    let import_rva = import_dir.map(|d| d.virtual_address).unwrap_or(0);
    let import_size = import_dir.map(|d| d.size).unwrap_or(0);
    collect_import_directory_ranges(sections, import_rva, import_size, &mut raw_ranges);

    // DataDirectory 10: Load Config Directory
    if let Some(dir) = ctx.target_info.data_directories.get(10) {
        if dir.virtual_address > 0 && dir.size > 0 {
            raw_ranges.push((dir.virtual_address, dir.virtual_address.saturating_add(dir.size)));
        }
    }

    // DataDirectory 12: IAT
    if let Some(dir) = ctx.target_info.data_directories.get(12) {
        if dir.virtual_address > 0 && dir.size > 0 {
            raw_ranges.push((dir.virtual_address, dir.virtual_address.saturating_add(dir.size)));
        }
    }

    // DataDirectory 13: Delay Import Directory
    let delay_dir = ctx.target_info.data_directories.get(13);
    let delay_rva = delay_dir.map(|d| d.virtual_address).unwrap_or(0);
    let delay_size = delay_dir.map(|d| d.size).unwrap_or(0);
    collect_delay_import_directory_ranges(sections, delay_rva, delay_size, &mut raw_ranges);

    // DataDirectory 9: TLS Directory
    if let Some(dir) = ctx.target_info.data_directories.get(9) {
        if dir.virtual_address > 0 && dir.size > 0 {
            raw_ranges.push((dir.virtual_address, dir.virtual_address.saturating_add(dir.size)));

            // IMAGE_TLS_DIRECTORY64: AddressOfCallBacks is at offset 0x18 (24)
            let tls_rva = dir.virtual_address;
            for s in sections {
                if tls_rva >= s.virtual_address && tls_rva + 0x28 <= s.virtual_address + s.virtual_size {
                    let off = (tls_rva - s.virtual_address) as usize;
                    if off + 0x20 <= s.bytes.len() {
                        // v58 (Phase 2.5-fix): protect the TLS RAW DATA TEMPLATE
                        // [StartAddressOfRawData .. EndAddressOfRawData). The loader
                        // copies this template into every thread's TLS slots at
                        // process start (BEFORE the boot stub runs), so
                        // `#[thread_local]` statics — including std's TLS-destructor
                        // list `DTORS` (a RefCell<Vec>, borrow counter at offset 8) —
                        // are initialized from it. Encrypting the template leaves the
                        // DTORS borrow field as garbage, so the first
                        // `thread_local!`-with-destructor registration at runtime
                        // (e.g. mpsc/thread::spawn in test [9]) hits a corrupted
                        // borrow state and aborts with "the System allocator may not
                        // use TLS with destructors". Keep the template plaintext.
                        let start_va = u64::from_le_bytes(
                            s.bytes[off..off + 8].try_into().unwrap_or([0; 8]),
                        );
                        let end_va = u64::from_le_bytes(
                            s.bytes[off + 8..off + 16].try_into().unwrap_or([0; 8]),
                        );
                        if start_va > ctx.target_info.image_base && end_va > start_va {
                            let ts = (start_va - ctx.target_info.image_base) as u32;
                            let te = (end_va - ctx.target_info.image_base) as u32;
                            raw_ranges.push((ts, te));
                        }
                        let callbacks_va = u64::from_le_bytes(
                            s.bytes[off + 0x18..off + 0x20].try_into().unwrap_or([0; 8]),
                        );
                        if callbacks_va > ctx.target_info.image_base {
                            let cb_rva = (callbacks_va - ctx.target_info.image_base) as u32;
                            // Protect the Callbacks pointer array (up to null terminator, max 256 bytes)
                            raw_ranges.push((cb_rva, cb_rva.saturating_add(256)));

                            // Scan individual TLS Callback function VAs and protect their target functions
                            for s2 in sections {
                                if cb_rva >= s2.virtual_address && cb_rva < s2.virtual_address + s2.virtual_size {
                                    let mut cb_off = (cb_rva - s2.virtual_address) as usize;
                                    while cb_off + 8 <= s2.bytes.len() {
                                        let func_va = u64::from_le_bytes(
                                            s2.bytes[cb_off..cb_off + 8].try_into().unwrap_or([0; 8]),
                                        );
                                        if func_va == 0 {
                                            break;
                                        }
                                        if func_va > ctx.target_info.image_base {
                                            let func_rva = (func_va - ctx.target_info.image_base) as u32;
                                            raw_ranges.push((func_rva, func_rva.saturating_add(256)));
                                        }
                                        cb_off += 8;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Security Cookie
    if cookie_rva > 0 {
        raw_ranges.push((cookie_rva, cookie_rva.saturating_add(32)));
    }

    // Sort & Merge
    raw_ranges.retain(|&(s, e)| s < e);
    raw_ranges.sort_by_key(|&(s, _)| s);

    let mut merged: Vec<(u32, u32)> = Vec::new();
    for (s, e) in raw_ranges {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        merged.push((s, e));
    }

    merged
}

// ==============================================================================
// v13: 데이터/코드 직접 참조 블록 수집 — 재암호화 모드 평문 유지 대상 확장
// ==============================================================================

/// `va`가 Trigger Block 시작점이면 그 블록 ID를 `out`에 추가한다.
fn mark_block_entry(
    out: &mut HashSet<u32>,
    va_to_trigger_id: &BTreeMap<u64, u32>,
    va: u64,
    text_start_va: u64,
    text_end_va: u64,
) {
    if va < text_start_va || va >= text_end_va {
        return;
    }
    if let Some(&id) = va_to_trigger_id.get(&va) {
        if is_block_entry(va_to_trigger_id, va, id) {
            out.insert(id);
        }
    }
}

/// 정확 일치(블록 시작) → 포함 관계 순으로 VA를 블록 ID로 해석한다.
pub(crate) fn resolve_block_id(
    map: &BTreeMap<u64, u32>,
    va: u64,
    text_start_va: u64,
    text_end_va: u64,
) -> Option<u32> {
    if va < text_start_va || va >= text_end_va {
        return None;
    }
    if let Some(&id) = map.get(&va) {
        return Some(id);
    }
    map.range(..=va).next_back().map(|(_, &id)| id)
}

/// v13: **데이터 섹션에 저장된 코드 포인터**가 가리키는 블록을 수집한다.
///
/// v11은 직접 `call` 명령의 타깃만 평문으로 유지했지만, CRT 초기화 테이블(.CRT),
/// vtable, SEH 핸들러, 점프 테이블 등 **데이터로 저장된 함수 포인터**를 통한 간접
/// 호출은 디스패처를 거치지 않는다. 대상 블록이 암호문 상태로 남으면 ciphertext가
/// 그대로 실행되어 0xC000001D (illegal instruction) 크래시가 발생한다.
/// (실측: pack_orig.exe — ucrtbase!initterm_e가 .rdata 0x23438의 CRT 초기화
///  포인터로 Block 1646 @0x140054F6E를 직접 호출 → WER 0xC000001D @0x54F6E)
///
/// `patch_data::run`이 .btg로 재배치하는 포인터와 동일한 기준(블록 시작점 정확
/// 일치)으로 스캔하므로, 수집 결과는 "재배치되어 런타임에 직접 실행되는 블록"
/// 집합과 정확히 일치한다. 반드시 Pass 4(길이 테이블 센티널)와 Crypto(암호화
/// 제외)보다 **먼저** 실행되어야 한다.
pub(crate) fn collect_data_reference_target_ids(
    sections: &[SectionData],
    image_base: u64,
    text_start_va: u64,
    text_end_va: u64,
    text_rva_start: u32,
    text_rva_end: u32,
    va_to_trigger_id: &BTreeMap<u64, u32>,
    protected_ranges: &[(u32, u32)],
) -> HashSet<u32> {
    let mut out = HashSet::new();

    for sec in sections {
        // .pdata RUNTIME_FUNCTION: Begin/End RVA (함수 경계 — SEH 언와인드/핸들러)
        if sec.name == ".pdata" {
            for off in (0..sec.bytes.len().saturating_sub(11)).step_by(12) {
                let begin_rva =
                    u32::from_le_bytes(sec.bytes[off..off + 4].try_into().unwrap_or([0; 4]));
                let end_rva =
                    u32::from_le_bytes(sec.bytes[off + 4..off + 8].try_into().unwrap_or([0; 4]));
                for rva in [begin_rva, end_rva] {
                    if rva >= text_rva_start && rva < text_rva_end {
                        if let Some(id) = resolve_block_id(
                            va_to_trigger_id,
                            image_base + rva as u64,
                            text_start_va,
                            text_end_va,
                        ) {
                            out.insert(id);
                        }
                    }
                }
            }
            continue;
        }

        // 실행 섹션 / .reloc 제외 (분기 타깃·재배치 테이블은 별도 경로)
        if (sec.characteristics & 0x2000_0000) != 0 || sec.name == ".reloc" {
            continue;
        }
        if sec.bytes.len() < 4 {
            continue;
        }

        for offset in (0..sec.bytes.len().saturating_sub(3)).step_by(4) {
            let current_rva = sec.virtual_address + offset as u32;

            // 1. 64-bit 절대 VA 포인터 (8바이트 정렬)
            if offset % 8 == 0
                && offset + 8 <= sec.bytes.len()
                && !is_rva_range_protected(current_rva, 8, protected_ranges)
            {
                let val64 = u64::from_le_bytes(
                    sec.bytes[offset..offset + 8].try_into().unwrap_or([0; 8]),
                );
                mark_block_entry(&mut out, va_to_trigger_id, val64, text_start_va, text_end_va);
            }

            // 2. 32-bit RVA 포인터 (SEH ScopeTable, RTTI, CRT 함수 포인터 테이블,
            //    x64 MSVC 점프 테이블)
            if !is_rva_range_protected(current_rva, 4, protected_ranges) {
                let val32 = u32::from_le_bytes(
                    sec.bytes[offset..offset + 4].try_into().unwrap_or([0; 4]),
                );
                if val32 >= text_rva_start && val32 < text_rva_end {
                    mark_block_entry(
                        &mut out,
                        va_to_trigger_id,
                        image_base + val32 as u64,
                        text_start_va,
                        text_end_va,
                    );
                }
            }
        }
    }

    out
}

/// v13: .text 코드에서 **함수 포인터를 재료화**하는 명령의 타깃 블록을 수집한다.
///
/// x64에서 `lea reg,[rip+func]` / `mov reg, imm64(func)`로 함수 주소를 만든 뒤
/// 간접 `call`하면 디스패처를 거치지 않는다. (콜백 등록, vtable 간접 호출,
/// atexit 등록 등) rip-relative 메모리 피연산자 대상은 블록 **내부** 데이터/상수
/// 참조일 수도 있으므로 포함 관계로 해석해 블록 전체를 평문으로 유지한다.
pub(crate) fn collect_code_materialized_target_ids(
    text_bytes: &[u8],
    text_base_va: u64,
    text_start_va: u64,
    text_end_va: u64,
    va_to_trigger_id: &BTreeMap<u64, u32>,
) -> HashSet<u32> {
    let mut out = HashSet::new();
    let mut decoder =
        iced_x86::Decoder::with_ip(64, text_bytes, text_base_va, iced_x86::DecoderOptions::NONE);

    while decoder.can_decode() {
        let inst = decoder.decode();
        if inst.is_invalid() {
            continue;
        }

        // RIP-relative 메모리 피연산자: lea reg,[rip+disp] / mov reg,[rip+disp]
        if inst.memory_base() == iced_x86::Register::RIP
            && inst.memory_index() == iced_x86::Register::None
        {
            let target = inst.ip() + inst.len() as u64 + inst.memory_displacement64();
            if let Some(id) =
                resolve_block_id(va_to_trigger_id, target, text_start_va, text_end_va)
            {
                out.insert(id);
            }
        }

        // mov reg, imm64 — 절대 함수 주소 직접 재료화
        if inst.code() == iced_x86::Code::Mov_r64_imm64 {
            let target = inst.immediate64();
            mark_block_entry(&mut out, va_to_trigger_id, target, text_start_va, text_end_va);
        }
    }

    out
}
