// ==============================================================================
// BTG (Bidirectional Trigger Graph) - PE Parser & Section Relayer
// ==============================================================================


use crate::pe::builder::{DataDirectory, SectionData};
use anyhow::{Context, Result};
use goblin::pe::PE;

#[derive(Debug, Clone)]
pub struct TargetPeInfo {
    pub image_base: u64,
    pub text_rva: u32,
    pub text_raw_ptr: usize,
    /// 원본 .text raw 바이트 크기 (섹션 raw data 크기; 바이트 읽기에 사용)
    pub text_size: usize,
    /// 원본 .text **가상** 크기 (VirtualSize). 코드 영역 경계 판정(text_va_range,
    /// .rdata/.data 32-bit RVA 재배치 범위)은 이 값을 사용해야 한다.
    /// raw 크기(보통 0x1000, 패딩 포함)를 쓰면 .rdata 안의 값(예: CRT init 테이블
    /// 경계 0x1C60)이 [text_rva, text_rva+raw) 범위에 걸려 잘못 재배치되어
    /// _initterm이 쓰레기 테이블을 읽고 0x0을 호출 → 0xC0000005 크래시가 난다.
    pub text_vsize: usize,
    pub text_bytes: Vec<u8>,
    pub entry_point_rva: u32,
    pub subsystem: u16,
    /// P0-⑦: 원본 DLL characteristics (ASLR/CFG 비트 포함) — 출력에서 보존할 수 있도록
    /// 스트리핑 전 원본을 그대로 보존한다. `dll_characteristics`는 필요 시 스트리핑된
    /// 값을 담을 수 있지만, 이 필드는 항상 원본을 유지한다.
    pub original_dll_characteristics: u16,
    pub dll_characteristics: u16,
    pub stack_reserve: u64,
    pub stack_commit: u64,
    pub heap_reserve: u64,
    pub heap_commit: u64,
    pub file_alignment: u32,
    pub section_alignment: u32,
    pub data_directories: Vec<DataDirectory>,
    pub relayed_sections: Vec<SectionData>,
    pub original_headers_bytes: Vec<u8>,
    pub original_pdata_entries: Vec<RuntimeFunction>,
    /// 원본 입력 PE 바이트 전체 (import-name 기반 검출 — setjmp/longjmp 경계 등).
    pub original_pe_bytes: Vec<u8>,
}

impl TargetPeInfo {
    pub fn parse(pe_bytes: &[u8]) -> Result<Self> {
        let pe = PE::parse(pe_bytes).context("Failed to parse target binary as PE32+")?;

        // BTG marker section names produced by our own pass4_section.rs. A binary
        // that already contains one of these is a previously BTG-packed binary.
        const BTG_SECTIONS: [&str; 2] = [".textb", ".btg"];
        let has_packed_marker = pe.sections.iter().any(|s| {
            let n = s.name().unwrap_or("");
            BTG_SECTIONS.iter().any(|m| n == *m)
        });

        // Use an EXACT ".text" match, NOT starts_with(".text") — the latter would
        // match ".textb" (our own packed section) and wrongly slice ciphertext as
        // the program source when re-packing an already-packed binary.
        let text_sec = pe
            .sections
            .iter()
            .find(|s| s.name().unwrap_or("") == ".text")
            .context("Target PE has no .text section")?;

        let entry_rva = pe.entry as u32;
        let text_rva_for_ep = text_sec.virtual_address;
        let text_vsize_for_ep = text_sec.virtual_size as u64;
        let ep_in_text =
            (entry_rva as u64) >= text_rva_for_ep as u64
            && (entry_rva as u64) < (text_rva_for_ep as u64 + text_vsize_for_ep);

        // Re-packing an already BTG-packed binary is fundamentally unsupported:
        // its .text is RC4 ciphertext and its real entry point lives in .textb, so
        // slicing "the program" out of .text yields garbage blocks that execute
        // invalid opcodes at runtime (0xC0000096). Detect it up-front and give a
        // clear error instead of producing a valid-looking but crashing binary.
        if has_packed_marker || !ep_in_text {
            return Err(anyhow::anyhow!(
                "input appears to be an already-packed BTG binary (found {} marker, entry 0x{:X} not in .text); re-packing is unsupported — pack the clean/unpacked binary (e.g. chve2_unpacked.exe) instead",
                if has_packed_marker { "BTG section" } else { "no BTG section" },
                entry_rva
            ));
        }

        let text_raw_ptr = text_sec.pointer_to_raw_data as usize;
        let text_size = text_sec.size_of_raw_data as usize;
        let text_vsize = text_sec.virtual_size as usize;
        let text_rva = text_sec.virtual_address;

        let end_ptr = (text_raw_ptr + text_size).min(pe_bytes.len());
        let text_bytes = pe_bytes[text_raw_ptr..end_ptr].to_vec();

        let image_base = pe.image_base as u64;
        let entry_point_rva = pe.entry as u32;

        // Extract Subsystem, DllCharacteristics, Alignments, Stack/Heap & Data Directories from optional_header
        let (
            subsystem,
            dll_characteristics_raw,
            dll_characteristics,
            stack_reserve,
            stack_commit,
            heap_reserve,
            heap_commit,
            file_alignment,
            section_alignment,
            data_directories,
        ) = if let Some(opt) = pe.header.optional_header {
            let sub = opt.windows_fields.subsystem;
            let orig_dll_char = opt.windows_fields.dll_characteristics;
            // P0-⑦: 원본 ASLR/CFG 비트를 보존하되, `dll_characteristics`는 기존
            // 소비처(build.rs 등)가 여전히 안전한 기본값을 쓰도록 스트리핑된 값을
            // 담는다. relocation-aware 경로(build.rs)는 `original_dll_characteristics`
            // 를 기준으로 ASLR 비트를 복원한다.
            let dll_char = orig_dll_char & !(0x0020 | 0x0040 | 0x4000); // Disable ASLR & CFG for fixed BaseVA stability
            let s_res = opt.windows_fields.size_of_stack_reserve;
            let s_com = opt.windows_fields.size_of_stack_commit;
            let h_res = opt.windows_fields.size_of_heap_reserve;
            let h_com = opt.windows_fields.size_of_heap_commit;
            let f_align = opt.windows_fields.file_alignment as u32;
            let sec_align = opt.windows_fields.section_alignment as u32;

            let mut dirs = vec![DataDirectory { virtual_address: 0, size: 0 }; 16];
            for (idx, dir_opt) in opt.data_directories.data_directories.iter().enumerate() {
                if idx < 16 {
                    // idx=3: Exception Directory (.pdata) — cleared because .pdata entries reference
                    //        original .text VAs that are no longer the execution path after BTG transform.
                    // idx=4: Security / Digital Signature — invalid after binary modification.
                    // idx=5: Base Relocations (.reloc) — cleared to prevent OS loader from patching
                    //        shuffled .btg code bytes when DYNAMIC_BASE is stripped.
                    //        (P0-⑦: relocation-aware 경로는 build.rs가 재생성한 .reloc 으로 채운다.)
                    // Note: idx=10 (LoadConfig) MUST BE PRESERVED so OS loader populates __security_cookie
                    //       and Control Flow Guard (CFG) function pointers like __guard_check_icall_fptr.
                    if idx == 4 || idx == 5 {
                        dirs[idx] = DataDirectory { virtual_address: 0, size: 0 };
                    } else if let Some((_, d)) = dir_opt {
                        dirs[idx] = DataDirectory {
                            virtual_address: d.virtual_address,
                            size: d.size,
                        };
                    }
                }
            }
            (sub, orig_dll_char, dll_char, s_res, s_com, h_res, h_com, f_align, sec_align, dirs)
        } else {
            (3, 0x8120, 0x8120, 0x100000, 0x1000, 0x100000, 0x1000, 0x200, 0x1000, vec![DataDirectory { virtual_address: 0, size: 0 }; 16])
        };

        let mut relayed_sections = Vec::new();
        for sec in &pe.sections {
            let name = sec.name().unwrap_or("").to_string();
            let s_raw_ptr = sec.pointer_to_raw_data as usize;
            let s_raw_size = sec.size_of_raw_data as usize;
            let s_end_ptr = (s_raw_ptr + s_raw_size).min(pe_bytes.len());

            let bytes = if s_raw_ptr < pe_bytes.len() {
                pe_bytes[s_raw_ptr..s_end_ptr].to_vec()
            } else {
                Vec::new()
            };

            relayed_sections.push(SectionData {
                name,
                virtual_address: sec.virtual_address,
                virtual_size: sec.virtual_size,
                characteristics: sec.characteristics,
                bytes,
            });
        }

        let size_of_headers = if let Some(opt) = pe.header.optional_header {
            opt.windows_fields.size_of_headers as usize
        } else {
            0x400
        };

        let headers_end = size_of_headers.min(pe_bytes.len());
        let original_headers_bytes = pe_bytes[..headers_end].to_vec();

        // Extract original .pdata RUNTIME_FUNCTION entries
        let mut original_pdata_entries = Vec::new();
        if let Some(pdata_sec) = pe.sections.iter().find(|s| s.name().unwrap_or("").starts_with(".pdata")) {
            let p_raw = pdata_sec.pointer_to_raw_data as usize;
            let p_size = pdata_sec.size_of_raw_data as usize;
            let p_end = (p_raw + p_size).min(pe_bytes.len());

            if p_raw < pe_bytes.len() {
                let pdata_bytes = &pe_bytes[p_raw..p_end];
                for chunk in pdata_bytes.chunks_exact(12) {
                    let b = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
                    let e = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
                    let u = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
                    if b > 0 && e > b {
                        original_pdata_entries.push(RuntimeFunction {
                            begin_address: b,
                            end_address: e,
                            unwind_info_address: u,
                        });
                    }
                }
            }
        }

        Ok(Self {
            image_base,
            text_rva,
            text_raw_ptr,
            text_size,
            text_vsize,
            text_bytes,
            entry_point_rva,
            subsystem,
            original_dll_characteristics: dll_characteristics_raw,
            dll_characteristics,
            stack_reserve,
            stack_commit,
            heap_reserve,
            heap_commit,
            file_alignment,
            section_alignment,
            data_directories,
            relayed_sections,
            original_headers_bytes,
            original_pdata_entries,
            original_pe_bytes: pe_bytes.to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}
