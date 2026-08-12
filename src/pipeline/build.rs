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
    // 원본 `.text`는 TLS 콜백, VM native bridge, 그리고 entry_native 경로에서 계속
    // 실행된다. 따라서 원본 RUNTIME_FUNCTION 항목을 반드시 유지하고, 새 디스패처
    // 영역의 leaf 항목만 추가한다. `--keep-pdata`는 진단 호환성을 위해 새 항목까지
    // 추가하지 않는 완전 원본 유지 모드로 남긴다.
    let mut relayed_sections = ctx.patched_sections.clone();
    if ctx.keep_pdata {
        println!("[+] .pdata: KEPT original (--keep-pdata) — build.rs SEH rebuild skipped; original RUNTIME_FUNCTION table left verbatim");
    } else {
        update_pdata_seh(
            &mut relayed_sections,
            &mut clean_data_dirs,
            &ctx.target_info.original_pdata_entries,
            dispatcher_rva,
            boot_area_len,
            unwind_info_rva,
        );
    }

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

    let output_pe_bytes = multi_builder.build()?;

    fs::write(output_path, &output_pe_bytes)?;

    println!("==================================================================");
    println!("[SUCCESS] Synthesized Protected BTG PE Binary Written to: {}", output_path.display());
    println!("[INFO] Size of Output Protected Binary: {} bytes", output_pe_bytes.len());
    println!("[INFO] Protected Entry Point (OEP) RVA: 0x{:X}", entry_point_rva);
    println!("==================================================================");

    Ok(output_pe_bytes)
}

/// `.pdata` SEH 테이블을 재구성한다 (v13.4c).
///
/// 블록 shuffle 결과는 새 `.textb` 주소에 있으므로 원본 `.text`의 RUNTIME_FUNCTION
/// 범위와 겹치지 않는다. 원본 `.text` 자체도 그대로 보존되며 네이티브 경로에서
/// 실행되므로 기존 항목을 삭제하면 Rust panic/TLS teardown의 OS unwind가 깨진다.
/// 따라서:
///   1. 유효한 원본 항목을 주소 변경 없이 모두 보존한다.
///   2. 디스패처/부트 영역만 타이트하게 커버하는 RUNTIME_FUNCTION 하나를 추가
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
) {
    if let Some(pdata_sec) = relayed_sections.iter_mut().find(|s| s.name == ".pdata") {
        // 원본 `.text`는 그대로 존재하고 네이티브 경로에서 실행되므로 전부 보존한다.
        let mut rf_list: Vec<RuntimeFunction> = original_pdata_entries
            .iter()
            .filter(|rf| {
                rf.begin_address > 0
                    && rf.end_address > rf.begin_address
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
                "[+] Rebuilt SEH Table (.pdata): RVA 0x{:X}, {} entries (Size 0x{:X}) [original native entries preserved; dispatcher leaf {}..0x{:X} added]",
                pdata_sec.virtual_address, rf_list.len(), rf_bytes.len(),
                dispatcher_rva, dispatcher_rva + boot_area_len
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdata_rebuild_preserves_native_entries_and_adds_dispatcher_leaf() {
        let originals = vec![
            RuntimeFunction {
                begin_address: 0x1000,
                end_address: 0x1100,
                unwind_info_address: 0x3000,
            },
            RuntimeFunction {
                begin_address: 0x1200,
                end_address: 0x1300,
                unwind_info_address: 0x3010,
            },
        ];
        let mut sections = vec![SectionData {
            name: ".pdata".to_string(),
            virtual_address: 0x4000,
            virtual_size: 24,
            characteristics: 0x4000_0040,
            bytes: vec![0; 24],
        }];
        let mut directories = vec![
            DataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ];

        update_pdata_seh(
            &mut sections,
            &mut directories,
            &originals,
            0x5000,
            0x80,
            0x5018,
        );

        let words: Vec<u32> = sections[0]
            .bytes
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect();
        assert_eq!(
            words,
            vec![
                0x1000, 0x1100, 0x3000, 0x1200, 0x1300, 0x3010, 0x5000, 0x5080, 0x5018
            ]
        );
        assert_eq!(sections[0].virtual_size, 36);
        assert_eq!(directories[3].virtual_address, 0x4000);
        assert_eq!(directories[3].size, 36);
    }
}
