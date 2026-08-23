// ==============================================================================
// BTG - cookie / protected-RVA-range collection - split from patch_data.rs
// ==============================================================================
use super::imports::{collect_delay_import_directory_ranges, collect_import_directory_ranges};
use crate::pe::builder::SectionData;
use crate::pipeline::PipelineContext;

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
                if lc_rva >= s.virtual_address
                    && lc_rva + 0x60 <= s.virtual_address + s.virtual_size
                {
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
            raw_ranges.push((
                dir.virtual_address,
                dir.virtual_address.saturating_add(dir.size),
            ));
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
            raw_ranges.push((
                dir.virtual_address,
                dir.virtual_address.saturating_add(dir.size),
            ));
        }
    }

    // DataDirectory 12: IAT
    if let Some(dir) = ctx.target_info.data_directories.get(12) {
        if dir.virtual_address > 0 && dir.size > 0 {
            raw_ranges.push((
                dir.virtual_address,
                dir.virtual_address.saturating_add(dir.size),
            ));
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
            raw_ranges.push((
                dir.virtual_address,
                dir.virtual_address.saturating_add(dir.size),
            ));

            // IMAGE_TLS_DIRECTORY64: AddressOfCallBacks is at offset 0x18 (24)
            let tls_rva = dir.virtual_address;
            for s in sections {
                if tls_rva >= s.virtual_address
                    && tls_rva + 0x28 <= s.virtual_address + s.virtual_size
                {
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
                        let start_va =
                            u64::from_le_bytes(s.bytes[off..off + 8].try_into().unwrap_or([0; 8]));
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
                                if cb_rva >= s2.virtual_address
                                    && cb_rva < s2.virtual_address + s2.virtual_size
                                {
                                    let mut cb_off = (cb_rva - s2.virtual_address) as usize;
                                    while cb_off + 8 <= s2.bytes.len() {
                                        let func_va = u64::from_le_bytes(
                                            s2.bytes[cb_off..cb_off + 8]
                                                .try_into()
                                                .unwrap_or([0; 8]),
                                        );
                                        if func_va == 0 {
                                            break;
                                        }
                                        if func_va > ctx.target_info.image_base {
                                            let func_rva =
                                                (func_va - ctx.target_info.image_base) as u32;
                                            raw_ranges
                                                .push((func_rva, func_rva.saturating_add(256)));
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

    // P5 (.text on-disk plaintext 0): protect the full TLS-callback-reachable
    // function ranges. The loader runs these before the boot stub, so they must
    // never be encrypted even when a future at-rest `.text` encryptor is enabled.
    // (collect_protected_rva_ranges is the single "must stay plaintext" registry
    // that both patch_data fixup and the at-rest encryptor consult.)
    {
        use crate::vm::text_lift::detect_tls_callback_ranges;
        let base_va = ctx.target_info.image_base + ctx.target_info.text_rva as u64;
        let excl = detect_tls_callback_ranges(
            &ctx.target_info.text_bytes,
            base_va,
            ctx.target_info.image_base,
            sections,
            &ctx.target_info.data_directories,
        );
        for (s, e) in excl.func_ranges {
            let s_rva = (s.saturating_sub(ctx.target_info.image_base)) as u32;
            let e_rva = (e.saturating_sub(ctx.target_info.image_base)) as u32;
            if e_rva > s_rva {
                raw_ranges.push((s_rva, e_rva));
            }
        }
    }

    // v58 (Phase 2.5 SEH): 원본 .pdata의 UNWIND_INFO 주소를 보호한다. 로더가
    // 예외 디스패치(panic/catch_unwind) 시 런타임에 .pdata → UNWIND_INFO → EHANDLER
    // 를 읽는다. UNWIND_INFO가 v14 .rdata run에 포함돼 부트-복호화가 부분적으로
    // 어긋나면(keystream 정렬) UI 바이트가 손상되어 EHANDLER를 인식하지 못하고
    // catch_unwind가 panic을 못 잡는다. 메타데이터이므로 평문 유지가 안전하다.
    for rf in &ctx.target_info.original_pdata_entries {
        let ui = rf.unwind_info_address;
        if ui > 0 {
            // 각 UNWIND_INFO 블록을 보호 (평균 ~16-32B; 여유 0x40)
            raw_ranges.push((ui, ui.saturating_add(0x40)));
        }
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
