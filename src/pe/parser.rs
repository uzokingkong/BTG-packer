// ==============================================================================
// BTG (Bidirectional Trigger Graph) - PE Parser & Section Relayer
// ==============================================================================

use crate::pe::builder::{DataDirectory, SectionData};
use crate::pe::{exports::ExportDirectory, load_config::LoadConfig64, tls::TlsDirectory64, unwind};
use anyhow::{Context, Result};
use goblin::pe::PE;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// A file-backed section that the PE loader maps executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
    pub bytes: Vec<u8>,
}

/// One exception-directory function together with its decoded unwind chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUnwindFunction {
    pub function: unwind::RuntimeFunction,
    /// `(unwind-info RVA, decoded record)` from the function outward.
    pub chain: Vec<(u32, unwind::UnwindInfo)>,
}

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
    /// Every section carrying IMAGE_SCN_MEM_EXECUTE, in input section order.
    pub executable_sections: Vec<ExecutableSection>,
    /// Typed x64 exception-directory records and their complete unwind chains.
    pub unwind_functions: Vec<ParsedUnwindFunction>,
    /// Typed PE32+ TLS metadata, when the TLS directory is present.
    pub tls: Option<TlsDirectory64>,
    /// Typed PE32+ load-config metadata, when the directory is present.
    pub load_config: Option<LoadConfig64>,
    /// Typed PE export metadata, including forwarded and executable exports.
    pub exports: Option<ExportDirectory>,
    /// Exact RVAs of input IMAGE_REL_BASED_DIR64 slots.
    pub dir64_relocations: Vec<u32>,
    pub original_headers_bytes: Vec<u8>,
    pub original_pdata_entries: Vec<RuntimeFunction>,
    /// 원본 입력 PE 바이트 전체 (import-name 기반 검출 — setjmp/longjmp 경계 등).
    pub original_pe_bytes: Vec<u8>,
}

impl TargetPeInfo {
    pub fn executable_sections(&self) -> &[ExecutableSection] {
        &self.executable_sections
    }

    pub fn unwind_functions(&self) -> &[ParsedUnwindFunction] {
        &self.unwind_functions
    }

    pub fn tls(&self) -> Option<&TlsDirectory64> {
        self.tls.as_ref()
    }

    pub fn load_config(&self) -> Option<&LoadConfig64> {
        self.load_config.as_ref()
    }

    pub fn exports(&self) -> Option<&ExportDirectory> {
        self.exports.as_ref()
    }

    pub fn dir64_relocations(&self) -> &[u32] {
        &self.dir64_relocations
    }

    pub fn parse(pe_bytes: &[u8]) -> Result<Self> {
        let pe = PE::parse(pe_bytes).context("Failed to parse target binary as PE32+")?;

        const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
        const IMAGE_FILE_DLL: u16 = 0x2000;
        const PE32_PLUS_MAGIC: u16 = 0x20B;
        if pe.header.coff_header.machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(anyhow::anyhow!(
                "unsupported PE machine 0x{:04X}: BTG currently accepts AMD64 (0x8664) only",
                pe.header.coff_header.machine
            ));
        }
        if pe.header.coff_header.characteristics & IMAGE_FILE_DLL != 0 {
            return Err(anyhow::anyhow!(
                "unsupported PE image type: DLL inputs require a DLL-preserving build path"
            ));
        }
        if pe.header.coff_header.size_of_optional_header < 240 {
            return Err(anyhow::anyhow!(
                "invalid AMD64 optional-header size {}: expected at least 240 bytes",
                pe.header.coff_header.size_of_optional_header
            ));
        }
        let optional = pe
            .header
            .optional_header
            .as_ref()
            .context("AMD64 input is missing its PE32+ optional header")?;
        if optional.standard_fields.magic != PE32_PLUS_MAGIC {
            return Err(anyhow::anyhow!(
                "unsupported optional-header magic 0x{:04X}: expected PE32+ (0x20B)",
                optional.standard_fields.magic
            ));
        }
        if pe.header.coff_header.number_of_sections == 0 || pe.sections.len() > 96 {
            return Err(anyhow::anyhow!(
                "unsupported PE section count {}",
                pe.header.coff_header.number_of_sections
            ));
        }

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
        let ep_in_text = (entry_rva as u64) >= text_rva_for_ep as u64
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

        // Hardened PE input boundary (S6): a malicious/truncated PE can report a
        // .text raw pointer/size beyond EOF (or wrapping when added). The raw slice
        // below used to be `pe_bytes[text_raw_ptr..end_ptr]`, which panics on such
        // input. Compute a checked [start, end) and return a clear error instead of
        // crashing on hostile input.
        let text_start = text_raw_ptr;
        let text_end = match text_start.checked_add(text_size) {
            Some(e) => e.min(pe_bytes.len()),
            None => pe_bytes.len(),
        };
        if text_start > text_end {
            return Err(anyhow::anyhow!(
                "invalid .text raw range: ptr=0x{:X} size=0x{:X} (file len 0x{:X})",
                text_start,
                text_size,
                pe_bytes.len()
            ));
        }
        let text_bytes = pe_bytes[text_start..text_end].to_vec();

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

            let mut dirs = vec![
                DataDirectory {
                    virtual_address: 0,
                    size: 0
                };
                16
            ];
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
                        dirs[idx] = DataDirectory {
                            virtual_address: 0,
                            size: 0,
                        };
                    } else if let Some((_, d)) = dir_opt {
                        dirs[idx] = DataDirectory {
                            virtual_address: d.virtual_address,
                            size: d.size,
                        };
                    }
                }
            }
            (
                sub,
                orig_dll_char,
                dll_char,
                s_res,
                s_com,
                h_res,
                h_com,
                f_align,
                sec_align,
                dirs,
            )
        } else {
            (
                3,
                0x8120,
                0x8120,
                0x100000,
                0x1000,
                0x100000,
                0x1000,
                0x200,
                0x1000,
                vec![
                    DataDirectory {
                        virtual_address: 0,
                        size: 0
                    };
                    16
                ],
            )
        };

        let mut relayed_sections = Vec::new();
        for sec in &pe.sections {
            let name = sec.name().unwrap_or("").to_string();
            let s_raw_ptr = sec.pointer_to_raw_data as usize;
            let s_raw_size = sec.size_of_raw_data as usize;
            let s_end_ptr = match s_raw_ptr.checked_add(s_raw_size) {
                Some(e) => e.min(pe_bytes.len()),
                None => pe_bytes.len(),
            };

            // Guard against malicious raw pointers that fall past EOF (would panic on
            // direct slicing). Non-.text sections degrade to empty rather than crash.
            let bytes = if s_raw_ptr <= s_end_ptr && s_raw_ptr <= pe_bytes.len() {
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

        let executable_sections = relayed_sections
            .iter()
            .filter(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            .map(|section| ExecutableSection {
                name: section.name.clone(),
                virtual_address: section.virtual_address,
                virtual_size: section.virtual_size,
                characteristics: section.characteristics,
                bytes: section.bytes.clone(),
            })
            .collect::<Vec<_>>();

        // `data_directories` intentionally clears the security/relocation
        // entries for legacy output building. Typed input metadata must instead
        // use the untouched source directories (notably TLS relocation proof).
        let mut source_directories = vec![
            DataDirectory {
                virtual_address: 0,
                size: 0
            };
            16
        ];
        for (index, entry) in optional
            .data_directories
            .data_directories
            .iter()
            .enumerate()
        {
            if index < source_directories.len() {
                if let Some((_, directory)) = entry {
                    source_directories[index] = DataDirectory {
                        virtual_address: directory.virtual_address,
                        size: directory.size,
                    };
                }
            }
        }

        let unwind_sections = relayed_sections
            .iter()
            .map(|section| unwind::RvaSection {
                virtual_address: section.virtual_address,
                virtual_size: section.virtual_size,
                bytes: &section.bytes,
            })
            .collect::<Vec<_>>();
        let exception_bytes = directory_bytes(&relayed_sections, source_directories[3])?;
        let typed_runtime_functions = unwind::parse_runtime_functions(exception_bytes)
            .context("invalid x64 exception directory")?;
        let mut unwind_functions = Vec::with_capacity(typed_runtime_functions.len());
        for function in typed_runtime_functions {
            let chain = if function.unwind_info_address == 0 {
                Vec::new()
            } else {
                unwind::parse_unwind_chain(function.unwind_info_address, &unwind_sections, 64)
                    .context("invalid x64 unwind chain")?
            };
            unwind_functions.push(ParsedUnwindFunction { function, chain });
        }

        let dir64_relocations =
            parse_dir64_relocations(directory_bytes(&relayed_sections, source_directories[5])?)?;
        let tls = crate::pe::tls::parse_tls_directory64(
            image_base,
            source_directories[9],
            &relayed_sections,
            &dir64_relocations,
        )
        .context("invalid PE32+ TLS directory")?;
        let load_config_bytes = directory_bytes(&relayed_sections, source_directories[10])?;
        let load_config = if load_config_bytes.is_empty() {
            None
        } else {
            Some(
                LoadConfig64::parse(
                    load_config_bytes,
                    image_base,
                    optional.windows_fields.size_of_image,
                )
                .context("invalid PE32+ load-config directory")?,
            )
        };
        let exports =
            crate::pe::exports::parse_export_directory(source_directories[0], &relayed_sections)
                .context("invalid PE export directory")?;

        let size_of_headers = if let Some(opt) = pe.header.optional_header {
            opt.windows_fields.size_of_headers as usize
        } else {
            0x400
        };

        let headers_end = size_of_headers.min(pe_bytes.len());
        let original_headers_bytes = pe_bytes[..headers_end].to_vec();

        // Extract original .pdata RUNTIME_FUNCTION entries
        let mut original_pdata_entries = Vec::new();
        if let Some(pdata_sec) = pe
            .sections
            .iter()
            .find(|s| s.name().unwrap_or("").starts_with(".pdata"))
        {
            let p_raw = pdata_sec.pointer_to_raw_data as usize;
            let p_size = pdata_sec.size_of_raw_data as usize;
            let p_end = match p_raw.checked_add(p_size) {
                Some(e) => e.min(pe_bytes.len()),
                None => pe_bytes.len(),
            };

            if p_raw <= p_end && p_raw <= pe_bytes.len() {
                let pdata_bytes = &pe_bytes[p_raw..p_end];
                for chunk in pdata_bytes.chunks_exact(12) {
                    let b = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let e = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                    let u = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);
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
            executable_sections,
            unwind_functions,
            tls,
            load_config,
            exports,
            dir64_relocations,
            original_headers_bytes,
            original_pdata_entries,
            original_pe_bytes: pe_bytes.to_vec(),
        })
    }
}

fn directory_bytes<'a>(sections: &'a [SectionData], directory: DataDirectory) -> Result<&'a [u8]> {
    if directory.virtual_address == 0 && directory.size == 0 {
        return Ok(&[]);
    }
    let size = usize::try_from(directory.size).context("PE directory size does not fit usize")?;
    for section in sections {
        let Some(offset) = directory
            .virtual_address
            .checked_sub(section.virtual_address)
        else {
            continue;
        };
        let offset = offset as usize;
        let Some(end) = offset.checked_add(size) else {
            continue;
        };
        if end <= section.bytes.len() {
            return Ok(&section.bytes[offset..end]);
        }
    }
    Err(anyhow::anyhow!(
        "PE directory RVA 0x{:X} size 0x{:X} is not file-backed",
        directory.virtual_address,
        directory.size
    ))
}

fn parse_dir64_relocations(bytes: &[u8]) -> Result<Vec<u32>> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes[offset..].iter().all(|&byte| byte == 0) {
            break;
        }
        if bytes.len() - offset < 8 {
            return Err(anyhow::anyhow!("truncated base-relocation block"));
        }
        let page = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let block_size =
            u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if block_size < 8
            || block_size % 2 != 0
            || offset
                .checked_add(block_size)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(anyhow::anyhow!(
                "invalid base-relocation block size 0x{block_size:X}"
            ));
        }
        for entry in bytes[offset + 8..offset + block_size].chunks_exact(2) {
            let entry = u16::from_le_bytes(entry.try_into().unwrap());
            if entry >> 12 == 10 {
                result.push(
                    page.checked_add((entry & 0x0fff) as u32)
                        .context("base-relocation RVA overflow")?,
                );
            }
        }
        offset += block_size;
    }
    Ok(result)
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Craft a hostile PE32+ where the .text section's raw pointer/size point far
    /// past EOF (or wrap). parse() must return Err instead of panicking on the raw
    /// slice that previously was `pe_bytes[text_raw_ptr..end_ptr]` (S6).
    fn hostile_pe(raw_ptr: u32, raw_size: u32, truncate_to: usize) -> Vec<u8> {
        // Minimal valid-looking PE32+ with a single .text section whose raw fields
        // are controlled. goblin will accept the DOS/NT/COFF/optional structure;
        // the hostile .text raw range is what used to panic.
        let mut b = vec![0u8; 0x1000];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        // COFF file header at 0x84: machine x64, 1 section
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // number_of_sections
        b[0x8C..0x8E].copy_from_slice(&240u16.to_le_bytes()); // size of optional header
                                                              // Optional header at 0x8E
        b[0x8E..0x90].copy_from_slice(&0x20Bu16.to_le_bytes()); // magic PE32+
        b[0x9E..0xA2].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint (inside .text)
        b[0xA2..0xA6].copy_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
        b[0xA6..0xAE].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase
        b[0xAE..0xB2].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        b[0xB2..0xB6].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
                                                                // Section table at 0x8E + 240 = 0x17E
        let sec = 0x17Eusize;
        b[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        b[sec + 16..sec + 20].copy_from_slice(&raw_size.to_le_bytes()); // SizeOfRawData
        b[sec + 20..sec + 24].copy_from_slice(&raw_ptr.to_le_bytes()); // PointerToRawData
        if truncate_to < b.len() {
            b.truncate(truncate_to);
        }
        b
    }

    #[test]
    fn malicious_text_raw_past_eof_returns_err_not_panic() {
        // .text raw pointer beyond EOF: the old `pe_bytes[ptr..end]` slice would panic.
        let pe = hostile_pe(0x10_0000, 0x1000, 0x1000);
        let r = std::panic::catch_unwind(|| TargetPeInfo::parse(&pe));
        match r {
            Ok(Ok(_)) => panic!("hostile PE unexpectedly parsed"),
            Ok(Err(_)) => { /* rejected cleanly */ }
            Err(_) => panic!("hostile PE caused a panic (unchecked slice)"),
        }
    }

    #[test]
    fn malicious_text_raw_wraps_returns_err_not_panic() {
        // raw_ptr + raw_size wraps to a huge value; must not panic.
        let pe = hostile_pe(0xFFFF_FF00, 0x1000, 0x1000);
        let r = std::panic::catch_unwind(|| TargetPeInfo::parse(&pe));
        match r {
            Ok(Ok(_)) => { /* may parse if ptr resolves within file; fine */ }
            Ok(Err(_)) => { /* rejected */ }
            Err(_) => panic!("hostile PE caused a panic (checked_add missed)"),
        }
    }

    #[test]
    fn truncated_file_returns_err_not_panic() {
        // Sub-DOS-header input.
        let r = std::panic::catch_unwind(|| TargetPeInfo::parse(&[0u8; 8]));
        match r {
            Ok(Ok(_)) => panic!("truncated input unexpectedly parsed"),
            Ok(Err(_)) => { /* rejected */ }
            Err(_) => panic!("truncated input caused a panic"),
        }
    }

    #[test]
    fn x86_pe32_is_rejected_before_rewrite() {
        let mut pe = hostile_pe(0x400, 0x200, 0x1000);
        pe[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        pe[0x8E..0x90].copy_from_slice(&0x10Bu16.to_le_bytes());
        let err = TargetPeInfo::parse(&pe).unwrap_err().to_string();
        assert!(err.contains("AMD64"), "{err}");
    }

    #[test]
    fn dll_input_is_explicitly_rejected() {
        let mut pe = hostile_pe(0x400, 0x200, 0x1000);
        pe[0x96..0x98].copy_from_slice(&0x2022u16.to_le_bytes());
        let err = TargetPeInfo::parse(&pe).unwrap_err().to_string();
        assert!(err.contains("DLL"), "{err}");
    }

    #[test]
    fn dir64_relocations_are_decoded_from_typed_blocks() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x3000u32.to_le_bytes());
        bytes.extend_from_slice(&12u32.to_le_bytes());
        bytes.extend_from_slice(&(0xA000u16 | 0x120).to_le_bytes());
        bytes.extend_from_slice(&(0x3000u16 | 0x220).to_le_bytes());
        assert_eq!(parse_dir64_relocations(&bytes).unwrap(), vec![0x3120]);
    }

    #[test]
    fn executable_section_api_preserves_all_loader_executable_sections() {
        let pe = crate::pe::dummy_gen::generate_dummy_target_pe().unwrap();
        let info = TargetPeInfo::parse(&pe).unwrap();
        assert!(!info.executable_sections().is_empty());
        assert!(info
            .executable_sections()
            .iter()
            .any(|section| section.name == ".text"));
        assert!(info
            .executable_sections()
            .iter()
            .all(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0));
        for typed in info.unwind_functions() {
            assert!(info.original_pdata_entries.iter().any(|legacy| {
                legacy.begin_address == typed.function.begin_address
                    && legacy.end_address == typed.function.end_address
                    && legacy.unwind_info_address == typed.function.unwind_info_address
            }));
        }
    }
}
