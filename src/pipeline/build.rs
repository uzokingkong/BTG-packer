// ==============================================================================
// BTG Pipeline - Build: PE Synthesis & Output
// ==============================================================================

use crate::pe::builder::{DataDirectory, PeMultiSectionBuilder, SectionData};
use crate::pe::parser::RuntimeFunction;
use crate::pipeline::PipelineContext;
use anyhow::Result;
use std::fs;
use std::path::Path;

/// 최종 PE 이진 파일을 합성하고 디스크에 기록한다.
///
/// 처리 순서:
/// 1. DataDirectory 정리 (Debug, Security, Relocations 제거)
/// 2. `.pdata` SEH 테이블 갱신 (.btg 커버리지는 디스패처 부트 영역만 타이트하게)
/// 3. `PeMultiSectionBuilder::build()` 호출
/// 4. 파일 기록
///
/// # 반환
/// 빌드된 PE 바이너리 바이트열.
pub fn run(ctx: &PipelineContext, output_path: &Path) -> Result<Vec<u8>> {
    ctx.layout()?;
    let btg_section = ctx
        .btg_section_data
        .clone()
        .ok_or_else(|| anyhow::anyhow!("btg_section_data not set — run Pass 4 first"))?;

    let dispatcher_rva = ctx.dispatcher_rva;
    let unwind_info_rva = dispatcher_rva + 0x18;
    // 디스패처/부트 스텁 영역 길이: [dispatcher .. dispatcher+first_block_offset)
    // 까지만이 실제 연속적인 "부트 함수"(고유 prologue + UNWIND_INFO). 그 뒤의
    // shuffled 블록 영역은 각기 다른 stack frame 의 무수한 블록이므로 단일
    // RUNTIME_FUNCTION 으로 커버하면 안 된다 (잘못된 unwind → 잘못된 RSP →
    // 0xC0000005).
    let boot_area_len = ctx.first_block_offset as u32;
    let (text_start_rva, text_end_rva) = {
        let (s_va, e_va) = ctx.text_va_range();
        ((s_va - ctx.target_info.image_base) as u32, (e_va - ctx.target_info.image_base) as u32)
    };

    // ── DataDirectory 정리 ────────────────────────────────────────────────────────
    let mut clean_data_dirs = ctx.target_info.data_directories.clone();
    // idx=4 Security, idx=5 .reloc, idx=6 Debug 제거
    for idx in &[4usize, 5, 6] {
        if clean_data_dirs.len() > *idx {
            clean_data_dirs[*idx] = DataDirectory { virtual_address: 0, size: 0 };
        }
    }
    // v4: --rsrc-register — 리소스 디렉터리를 재구성된 트리로 교체
    if ctx.rsrc_dir_rva > 0 && clean_data_dirs.len() > 2 {
        clean_data_dirs[2] = DataDirectory {
            virtual_address: ctx.rsrc_dir_rva,
            size: ctx.rsrc_dir_size,
        };
    }
    // v6: --iat-hide — import 디렉터리를 더미(LoadLibraryA/GetProcAddress)로 교체
    if ctx.iat_dir_rva > 0 && clean_data_dirs.len() > 1 {
        clean_data_dirs[1] = DataDirectory {
            virtual_address: ctx.iat_dir_rva,
            size: ctx.iat_dir_size,
        };
    }

    // ── DLL Characteristics: DYNAMIC_BASE(0x0040), HIGH_ENTROPY_VA(0x0020), GUARD_CF(0x4000) 제거 ──
    let clean_dll_characteristics = ctx.target_info.dll_characteristics & !(0x0020 | 0x0040 | 0x4000);

    // ── 패치된 섹션에서 .pdata SEH 테이블 재구성 ────────────────────────────────
    let mut relayed_sections = ctx.patched_sections.clone();
    update_pdata_seh(
        &mut relayed_sections,
        &mut clean_data_dirs,
        &ctx.target_info.original_pdata_entries,
        dispatcher_rva,
        boot_area_len,
        unwind_info_rva,
        text_start_rva,
        text_end_rva,
    );

    // ── PE 빌드 ───────────────────────────────────────────────────────────────────
    // v3: 암호화가 켜져 있으면 부트 스텁(boot stub)이 새 진입점이 된다.
    // ctx.boot_entry_offset = 부트 스텁의 섹션 내 오프셋 (0이면 기존 OEP = 섹션 시작)
    let entry_point_rva = dispatcher_rva + ctx.boot_entry_offset;

    let multi_builder = PeMultiSectionBuilder::new(
        ctx.target_info.image_base,
        entry_point_rva,
        ctx.target_info.subsystem,
        clean_dll_characteristics,
        ctx.target_info.stack_reserve,
        ctx.target_info.stack_commit,
        ctx.target_info.heap_reserve,
        ctx.target_info.heap_commit,
        ctx.target_info.file_alignment,
        ctx.target_info.section_alignment,
        clean_data_dirs,
        relayed_sections,
        btg_section,
        ctx.payload_section_data.clone(),
        ctx.target_info.original_headers_bytes.clone(),
    );

    let mut output_pe_bytes = multi_builder.build()?;
    neutralize_tls_callbacks(ctx, &mut output_pe_bytes);

    fs::write(output_path, &output_pe_bytes)?;

    println!("==================================================================");
    println!("[SUCCESS] Synthesized Protected BTG PE Binary Written to: {}", output_path.display());
    println!("[INFO] Size of Output Protected Binary: {} bytes", output_pe_bytes.len());
    println!("[INFO] Protected Entry Point (OEP) RVA: 0x{:X}", entry_point_rva);
    println!("==================================================================");

    Ok(output_pe_bytes)
}

/// IAT-hiding이 원본 import 슬롯을 비우면, 로더가 엔트리포인트(부트 스텁)보다 먼저
/// 실행하는 TLS 콜백이 숨겨진 IAT(0으로 채워진 슬롯)를 경유해 0x0 을 호출해
/// 크래시한다. → 출력의 TLS 디렉터리 AddressOfCallBacks 를 NULL 로 만들어
/// ntdll 이 TLS 콜백을 건너뛰게 한다. (부트 스텁의 CRT 재초기화가 원래 콜백이
/// 했을 일을 대체한다.) --iat-hide 가 켜진 경우에만 적용.
fn neutralize_tls_callbacks(ctx: &PipelineContext, out: &mut [u8]) {
    if !ctx.iat_hide && !ctx.crypto_enabled {
        return;
    }
    let Some(tls) = ctx.target_info.data_directories.get(9).copied() else { return };
    if tls.virtual_address == 0 || tls.size == 0 || out.len() < 0x40 {
        return;
    }
    let e_lfanew = u32::from_le_bytes([out[0x3C], out[0x3D], out[0x3E], out[0x3F]]) as usize;
    if e_lfanew + 24 > out.len() {
        return;
    }
    let num_sections = u16::from_le_bytes([out[e_lfanew + 6], out[e_lfanew + 7]]) as usize;
    let opt_size = u16::from_le_bytes([out[e_lfanew + 20], out[e_lfanew + 21]]) as usize;
    let sec_off = e_lfanew + 24 + opt_size as usize;
    let rva = tls.virtual_address;
    let mut file_off: Option<usize> = None;
    for i in 0..num_sections {
        let o = sec_off + i * 40;
        if o + 40 > out.len() {
            break;
        }
        let vs = u32::from_le_bytes([out[o + 8], out[o + 9], out[o + 10], out[o + 11]]);
        let va = u32::from_le_bytes([out[o + 12], out[o + 13], out[o + 14], out[o + 15]]);
        let rp = u32::from_le_bytes([out[o + 20], out[o + 21], out[o + 22], out[o + 23]]);
        if rva >= va && rva < va.saturating_add(vs) {
            file_off = Some(rp as usize + (rva - va) as usize);
            break;
        }
    }
    let Some(fo) = file_off else { return };
    if fo + 0x20 > out.len() {
        return;
    }
    let cb = u64::from_le_bytes(out[fo + 0x18..fo + 0x20].try_into().unwrap_or([0; 8]));
    if cb != 0 {
        out[fo + 0x18..fo + 0x20].fill(0);
        println!(
            "[+] IAT-hide + TLS callbacks: AddressOfCallBacks @RVA 0x{:X} zeroed (TLS callbacks run pre-boot and would call hidden IAT)",
            rva
        );
    }
}

/// `.pdata` SEH 테이블을 재구성한다 (v13.4c).
///
/// 블록 shuffle된 `.text` 함수는 물리적으로 분리·비연속이므로 단일 RUNTIME_FUNCTION
/// 으로 표현할 수 없다. 따라서:
///   1. 원본 `.text`(shuffle 대상) 범위를 가리키는 엔트리는 **제거**한다 — 이를
///      Begin/End 로 remap 하면 [new_begin, new_end) 가 엉뚱한 블록들을 포함해
///      OS 언와인더가 잘못된 UNWIND_INFO 를 읽고 잘못된 RSP 로 0xC0000005 를 낸다.
///   2. `.text` 밖의 원본 엔트리(변하지 않는 함수)는 그대로 보존한다.
///   3. 디스패처/부트 스텁 영역만 타이트하게 커버하는 RUNTIME_FUNCTION 하나를 추가
///      한다 ([dispatcher .. dispatcher+boot_area_len), 자신의 UNWIND_INFO 사용).
///      예전처럼 `.btg` 전체를 하나의 RUNTIME_FUNCTION 로 등록하면 서로 다른 stack
///      frame 을 가진 수천 블록을 하나의 UNWIND_INFO 로 처리하려다 잘못된 unwind 가
///      된다.
fn update_pdata_seh(
    relayed_sections: &mut Vec<SectionData>,
    clean_data_dirs: &mut Vec<DataDirectory>,
    original_pdata_entries: &[RuntimeFunction],
    dispatcher_rva: u32,
    boot_area_len: u32,
    unwind_info_rva: u32,
    text_start_rva: u32,
    text_end_rva: u32,
) {
    if let Some(pdata_sec) = relayed_sections.iter_mut().find(|s| s.name == ".pdata") {
        // 원본 엔트리 중 .text(shuffle 대상) 를 가리키지 않는 것만 보존.
        // .text 범위 밖의 함수는 재배치되지 않아 원본 RUNTIME_FUNCTION 이 그대로 유효하다.
        let mut rf_list: Vec<RuntimeFunction> = original_pdata_entries
            .iter()
            .filter(|rf| {
                rf.begin_address > 0
                    && rf.end_address > rf.begin_address
                    && !(rf.begin_address >= text_start_rva && rf.begin_address < text_end_rva)
            })
            .copied()
            .collect();

        // 디스패처 부트 영역만 커버하는 타이트 leaf 추가 (.btg 전체가 아님).
        // 기존 엔트리와 Begin 이 충돌하지 않을 때만.
        if !rf_list.iter().any(|rf| rf.begin_address == dispatcher_rva) {
            rf_list.push(RuntimeFunction {
                begin_address: dispatcher_rva,
                end_address: dispatcher_rva + boot_area_len,
                unwind_info_address: unwind_info_rva,
            });
        }

        rf_list.sort_by_key(|rf| rf.begin_address);
        rf_list.dedup_by_key(|rf| rf.begin_address);

        let mut rf_bytes = Vec::new();
        for rf in &rf_list {
            rf_bytes.extend_from_slice(&rf.begin_address.to_le_bytes());
            rf_bytes.extend_from_slice(&rf.end_address.to_le_bytes());
            rf_bytes.extend_from_slice(&rf.unwind_info_address.to_le_bytes());
        }

        pdata_sec.bytes = rf_bytes.clone();
        pdata_sec.virtual_size = rf_bytes.len() as u32;

        if clean_data_dirs.len() > 3 {
            clean_data_dirs[3] = DataDirectory {
                virtual_address: pdata_sec.virtual_address,
                size: rf_bytes.len() as u32,
            };
            println!(
                "[+] Rebuilt SEH Table (.pdata): RVA 0x{:X}, {} entries (Size 0x{:X}) [text-shuffled entries dropped; dispatcher boot leaf {}..0x{:X} only]",
                pdata_sec.virtual_address, rf_list.len(), rf_bytes.len(),
                dispatcher_rva, dispatcher_rva + boot_area_len
            );
        }
    }
}
