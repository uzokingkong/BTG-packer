// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Multi-Section PE Synthesizer (Relay Engine)
// ==============================================================================

use anyhow::Result;
use goblin::pe::header::Header;
use goblin::pe::section_table::{
    SectionTable, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
};

#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct SectionData {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PeAlignmentConfig {
    pub file_alignment: u32,
    pub section_alignment: u32,
}

pub enum AlignmentType {
    File,
    Section,
}

impl PeAlignmentConfig {
    pub fn new() -> Self {
        Self {
            file_alignment: 0x200,
            section_alignment: 0x1000,
        }
    }

    pub fn align_size(&self, size: u32, alignment_type: AlignmentType) -> u32 {
        let align = match alignment_type {
            AlignmentType::File => self.file_alignment,
            AlignmentType::Section => self.section_alignment,
        };
        (size.div_ceil(align)) * align
    }
}

pub struct PeMultiSectionBuilder {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub stack_reserve: u64,
    pub stack_commit: u64,
    pub heap_reserve: u64,
    pub heap_commit: u64,
    pub file_alignment: u32,
    pub section_alignment: u32,
    pub data_directories: Vec<DataDirectory>,
    pub relayed_sections: Vec<SectionData>,
    pub btg_section: SectionData,
    pub payload_section: Option<SectionData>,
    pub bootstrap_iat_section: Option<SectionData>,
    pub mutable_state_section: Option<SectionData>,
    pub mutable_state_metadata_section: Option<SectionData>,
    pub route_metadata_section: Option<SectionData>,
    pub original_headers_bytes: Vec<u8>,
    /// P0-⑦: relocation-aware 출력 — `.reloc` data directory(idx 5)가 제공되면
    /// ASLR(DYNAMIC_BASE 0x0040)/HIGH_ENTROPY_VA(0x0020) 비트를 보존한다.
    /// (오프셋: [dispatcher .. dispatcher+first_block_offset) 부트 영역의 절대
    /// VA 슬롯이 .reloc으로 커버되므로 로더가 리베이스해도 안전.)
    pub preserve_aslr_bits: bool,
    /// P0-⑦: 별도로 생성된 `.reloc` 섹션 — relayed 섹션에 추가하면 `.textb`(부트
    /// 영역, entry point/절대 VA의 기준)의 위치가 밀려 깨지므로, payload 뒤에
    /// 별도로 배치한다.
    pub reloc_section: Option<SectionData>,
}

impl PeMultiSectionBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        image_base: u64,
        entry_point_rva: u32,
        subsystem: u16,
        dll_characteristics: u16,
        stack_reserve: u64,
        stack_commit: u64,
        heap_reserve: u64,
        heap_commit: u64,
        file_alignment: u32,
        section_alignment: u32,
        data_directories: Vec<DataDirectory>,
        relayed_sections: Vec<SectionData>,
        btg_section: SectionData,
        payload_section: Option<SectionData>,
        original_headers_bytes: Vec<u8>,
    ) -> Self {
        Self {
            image_base,
            entry_point_rva,
            subsystem,
            dll_characteristics,
            stack_reserve,
            stack_commit,
            heap_reserve,
            heap_commit,
            file_alignment,
            section_alignment,
            data_directories,
            relayed_sections,
            btg_section,
            payload_section,
            bootstrap_iat_section: None,
            mutable_state_section: None,
            mutable_state_metadata_section: None,
            route_metadata_section: None,
            original_headers_bytes,
            // P0-⑦: 기본값은 기존 동작(ASLR 스트립) 유지. relocation-aware 경로가
            // .reloc data directory를 채우고 이 플래그를 켠다.
            preserve_aslr_bits: false,
            reloc_section: None,
        }
    }

    pub fn build(self) -> Result<Vec<u8>> {
        let align_config = PeAlignmentConfig {
            file_alignment: if self.file_alignment == 0 {
                0x200
            } else {
                self.file_alignment
            },
            section_alignment: if self.section_alignment == 0 {
                0x1000
            } else {
                self.section_alignment
            },
        };

        let num_sections = (self.relayed_sections.len()
            + 1
            + usize::from(self.bootstrap_iat_section.is_some())
            + usize::from(self.mutable_state_section.is_some())
            + usize::from(self.mutable_state_metadata_section.is_some())
            + usize::from(self.route_metadata_section.is_some())
            + usize::from(self.payload_section.is_some())
            + usize::from(self.reloc_section.is_some())) as u16;
        let original_e_lfanew = self
            .original_headers_bytes
            .get(0x3C..0x40)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_le_bytes)
            .map(|v| v as usize)
            .filter(|&v| v >= 0x40)
            .unwrap_or(0x80);
        let sec_table_offset = original_e_lfanew
            .checked_add(4 + 20 + 240)
            .ok_or_else(|| anyhow::anyhow!("PE section-table offset overflow"))?;
        let required_header_end = sec_table_offset
            .checked_add(num_sections as usize * 40)
            .ok_or_else(|| anyhow::anyhow!("PE section-table size overflow"))?;
        let header_size = self
            .original_headers_bytes
            .len()
            .max(required_header_end)
            .max(0x400);
        let size_of_headers = align_config.align_size(header_size as u32, AlignmentType::File);

        let mut pe_bytes = vec![0u8; size_of_headers as usize];

        // 1:1 Relayed Copy of Original Target Binary Headers & Rich Stub
        if !self.original_headers_bytes.is_empty() {
            let copy_len = self.original_headers_bytes.len().min(pe_bytes.len());
            pe_bytes[..copy_len].copy_from_slice(&self.original_headers_bytes[..copy_len]);
        } else {
            pe_bytes[0..2].copy_from_slice(b"MZ");
            let pe_offset: u32 = 0x80;
            pe_bytes[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
            let nt_pos = pe_offset as usize;
            pe_bytes[nt_pos..nt_pos + 4].copy_from_slice(b"PE\0\0");
        }

        let e_lfanew =
            u32::from_le_bytes(pe_bytes[0x3C..0x40].try_into().unwrap_or([0x80, 0, 0, 0])) as usize;
        let nt_pos = if e_lfanew > 0 && e_lfanew < pe_bytes.len() - 0x100 {
            e_lfanew
        } else {
            0x80
        };

        // COFF File Header
        let mut header = Header::default();
        header.coff_header.machine = 0x8664; // x64
        header.coff_header.number_of_sections = num_sections;
        header.coff_header.size_of_optional_header = 240;
        // P0-⑦: relocation-aware 경로는 RELOCS_STRIPPED(0x0001)를 끈다 — 정식 .reloc
        // data directory가 존재하므로 이미지에 재배치 정보가 있다는 뜻이다.
        header.coff_header.characteristics = if self.preserve_aslr_bits {
            0x0022 // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE (no RELOCS_STRIPPED)
        } else {
            0x0023 // RELOCS_STRIPPED | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        };

        // Calculate max Virtual Address for btg_section placement
        // v9 FIX: relayed 섹션이 하나도 없는 경우(자체 생성 dummy 타깃) 기본값을
        // 0x2000이 아닌 0으로 잡아 .text(0x1000)가 0x2000으로 밀려 EP와 어긋나는
        // 문제를 제거한다. 실제 패커 경로는 항상 relayed 섹션이 있어 영향 없음.
        let max_existing_va = self
            .relayed_sections
            .iter()
            .map(|s| {
                s.virtual_address
                    + align_config.align_size(
                        s.virtual_size.max(s.bytes.len() as u32),
                        AlignmentType::Section,
                    )
            })
            .max()
            .unwrap_or(0x1000);

        let mut adjusted_btg_section = self.btg_section;
        if adjusted_btg_section.virtual_address < max_existing_va {
            adjusted_btg_section.virtual_address =
                align_config.align_size(max_existing_va, AlignmentType::Section);
        }

        // Keep loader-written bootstrap IAT data out of executable `.textb`.
        let mut adjusted_bootstrap_iat_section = self.bootstrap_iat_section;
        let btg_end_va = adjusted_btg_section.virtual_address
            + align_config.align_size(
                adjusted_btg_section
                    .virtual_size
                    .max(adjusted_btg_section.bytes.len() as u32),
                AlignmentType::Section,
            );
        let after_iat_va = if let Some(ref mut isec) = adjusted_bootstrap_iat_section {
            isec.virtual_address = isec
                .virtual_address
                .max(align_config.align_size(btg_end_va, AlignmentType::Section));
            isec.virtual_address
                + align_config.align_size(
                    isec.virtual_size.max(isec.bytes.len() as u32),
                    AlignmentType::Section,
                )
        } else {
            btg_end_va
        };

        // `.vstate` has a generated-code-owned fixed RVA. Account for it when
        // placing subsequent automatically positioned data sections.
        let after_state_va = self
            .mutable_state_section
            .as_ref()
            .map(|state| {
                state.virtual_address
                    + align_config.align_size(
                        state.virtual_size.max(state.bytes.len() as u32),
                        AlignmentType::Section,
                    )
            })
            .unwrap_or(after_iat_va)
            .max(after_iat_va);

        let after_state_metadata_va = self
            .mutable_state_metadata_section
            .as_ref()
            .map(|metadata| {
                metadata.virtual_address
                    + align_config.align_size(
                        metadata.virtual_size.max(metadata.bytes.len() as u32),
                        AlignmentType::Section,
                    )
            })
            .unwrap_or(after_state_va)
            .max(after_state_va);

        // v4: --payload-relocate — 암호화된 코드 페이로드 섹션(.vdata)을 뒤에 배치
        let mut adjusted_payload_section = self.payload_section;
        let payload_end_va = if let Some(ref mut psec) = adjusted_payload_section {
            let p_va = align_config.align_size(after_state_metadata_va, AlignmentType::Section);
            psec.virtual_address = p_va;
            p_va + align_config.align_size(
                psec.virtual_size.max(psec.bytes.len() as u32),
                AlignmentType::Section,
            )
        } else {
            after_state_metadata_va
        };

        // Canonical route metadata is always placed after other VM data and
        // before relocations. Its caller-supplied RVA is intentionally ignored.
        let mut adjusted_route_metadata_section = self.route_metadata_section;
        let route_end_va = if let Some(ref mut route) = adjusted_route_metadata_section {
            route.virtual_address = align_config.align_size(payload_end_va, AlignmentType::Section);
            route.virtual_address
                + align_config.align_size(
                    route.virtual_size.max(route.bytes.len() as u32),
                    AlignmentType::Section,
                )
        } else {
            payload_end_va
        };

        // P0-⑦: 별도 .reloc 섹션을 payload/btg 뒤에 배치 (relayed에 넣으면 .textb가
        // 밀려 entry point/절대 VA 기준이 깨지므로 여기서 붙인다).
        let mut adjusted_reloc_section = self.reloc_section;
        if let Some(ref mut rsec) = adjusted_reloc_section {
            rsec.virtual_address = align_config.align_size(route_end_va, AlignmentType::Section);
        }

        // Write Section Headers
        let sec_table_offset = nt_pos + 4 + 20 + 240;
        let required_header_end = sec_table_offset + num_sections as usize * 40;
        if required_header_end > size_of_headers as usize {
            return Err(anyhow::anyhow!(
                "section table exceeds SizeOfHeaders: required=0x{:X}, SizeOfHeaders=0x{:X}",
                required_header_end,
                size_of_headers
            ));
        }
        let mut current_file_ptr = size_of_headers;
        let mut max_va = 0u32;

        let mut all_sections = self.relayed_sections.clone();
        all_sections.push(adjusted_btg_section);
        if let Some(state) = self.mutable_state_section {
            all_sections.push(state);
        }
        if let Some(metadata) = self.mutable_state_metadata_section {
            all_sections.push(metadata);
        }
        if let Some(is) = adjusted_bootstrap_iat_section {
            all_sections.push(is);
        }
        if let Some(ps) = adjusted_payload_section {
            all_sections.push(ps);
        }
        if let Some(route) = adjusted_route_metadata_section {
            all_sections.push(route);
        }
        if let Some(rs) = adjusted_reloc_section {
            all_sections.push(rs);
        }
        all_sections.sort_by_key(|s| s.virtual_address);

        for (i, sec_data) in all_sections.iter().enumerate() {
            let mut sec_entry = SectionTable::default();

            let mut name_bytes = [0u8; 8];
            let name_src = sec_data.name.as_bytes();
            let copy_len = name_src.len().min(8);
            name_bytes[..copy_len].copy_from_slice(&name_src[..copy_len]);

            sec_entry.name = name_bytes;
            let actual_virtual_size = sec_data.virtual_size.max(sec_data.bytes.len() as u32);
            sec_entry.virtual_size = actual_virtual_size;
            sec_entry.virtual_address = sec_data.virtual_address;

            let raw_size =
                align_config.align_size(sec_data.bytes.len() as u32, AlignmentType::File);
            sec_entry.size_of_raw_data = raw_size;
            sec_entry.pointer_to_raw_data = if sec_data.bytes.is_empty() {
                0
            } else {
                current_file_ptr
            };
            sec_entry.characteristics = sec_data.characteristics;

            // Write Section Table Header Entry
            let entry_pos = sec_table_offset + i * 40;
            pe_bytes[entry_pos..entry_pos + 8].copy_from_slice(&sec_entry.name);
            pe_bytes[entry_pos + 8..entry_pos + 12]
                .copy_from_slice(&sec_entry.virtual_size.to_le_bytes());
            pe_bytes[entry_pos + 12..entry_pos + 16]
                .copy_from_slice(&sec_entry.virtual_address.to_le_bytes());
            pe_bytes[entry_pos + 16..entry_pos + 20]
                .copy_from_slice(&sec_entry.size_of_raw_data.to_le_bytes());
            pe_bytes[entry_pos + 20..entry_pos + 24]
                .copy_from_slice(&sec_entry.pointer_to_raw_data.to_le_bytes());
            pe_bytes[entry_pos + 36..entry_pos + 40]
                .copy_from_slice(&sec_entry.characteristics.to_le_bytes());

            // Append Raw Section Bytes to PE Buffer if present
            if !sec_data.bytes.is_empty() {
                let needed_len = (current_file_ptr + raw_size) as usize;
                if pe_bytes.len() < needed_len {
                    pe_bytes.resize(needed_len, 0);
                }
                pe_bytes
                    [current_file_ptr as usize..current_file_ptr as usize + sec_data.bytes.len()]
                    .copy_from_slice(&sec_data.bytes);

                current_file_ptr += raw_size;
            }

            max_va = max_va.max(
                sec_data.virtual_address
                    + align_config.align_size(actual_virtual_size, AlignmentType::Section),
            );
        }

        let size_of_image = max_va;

        // Write Final NT File Header
        let file_hdr_pos = nt_pos + 4;
        pe_bytes[file_hdr_pos..file_hdr_pos + 2]
            .copy_from_slice(&header.coff_header.machine.to_le_bytes());
        pe_bytes[file_hdr_pos + 2..file_hdr_pos + 4]
            .copy_from_slice(&header.coff_header.number_of_sections.to_le_bytes());
        pe_bytes[file_hdr_pos + 16..file_hdr_pos + 18]
            .copy_from_slice(&header.coff_header.size_of_optional_header.to_le_bytes());
        pe_bytes[file_hdr_pos + 18..file_hdr_pos + 20]
            .copy_from_slice(&header.coff_header.characteristics.to_le_bytes());

        // Calculate total SizeOfCode and BaseOfCode across all executable code sections
        let total_code_size: u32 = all_sections
            .iter()
            .filter(|s| (s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0)
            .map(|s| align_config.align_size(s.bytes.len() as u32, AlignmentType::File))
            .sum();

        let base_of_code: u32 = all_sections
            .iter()
            .filter(|s| (s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0)
            .map(|s| s.virtual_address)
            .min()
            .unwrap_or(0x1000);

        // Write Complete PE32+ Optional Header Fields
        let opt_pos = file_hdr_pos + 20;
        let magic: u16 = 0x20B; // PE32+ (64-bit)
        pe_bytes[opt_pos..opt_pos + 2].copy_from_slice(&magic.to_le_bytes());
        pe_bytes[opt_pos + 2] = 14; // MajorLinkerVersion
        pe_bytes[opt_pos + 3] = 0; // MinorLinkerVersion
        pe_bytes[opt_pos + 4..opt_pos + 8].copy_from_slice(&total_code_size.to_le_bytes()); // SizeOfCode
        pe_bytes[opt_pos + 16..opt_pos + 20].copy_from_slice(&self.entry_point_rva.to_le_bytes());
        pe_bytes[opt_pos + 20..opt_pos + 24].copy_from_slice(&base_of_code.to_le_bytes()); // BaseOfCode
        pe_bytes[opt_pos + 24..opt_pos + 32].copy_from_slice(&self.image_base.to_le_bytes());
        pe_bytes[opt_pos + 32..opt_pos + 36]
            .copy_from_slice(&align_config.section_alignment.to_le_bytes());
        pe_bytes[opt_pos + 36..opt_pos + 40]
            .copy_from_slice(&align_config.file_alignment.to_le_bytes());

        // OS & Subsystem Versions
        pe_bytes[opt_pos + 40..opt_pos + 42].copy_from_slice(&6u16.to_le_bytes()); // MajorOSVersion
        pe_bytes[opt_pos + 42..opt_pos + 44].copy_from_slice(&0u16.to_le_bytes()); // MinorOSVersion
        pe_bytes[opt_pos + 48..opt_pos + 50].copy_from_slice(&6u16.to_le_bytes()); // MajorSubsystemVersion
        pe_bytes[opt_pos + 50..opt_pos + 52].copy_from_slice(&0u16.to_le_bytes()); // MinorSubsystemVersion

        pe_bytes[opt_pos + 56..opt_pos + 60].copy_from_slice(&size_of_image.to_le_bytes());
        pe_bytes[opt_pos + 60..opt_pos + 64].copy_from_slice(&size_of_headers.to_le_bytes());

        // Target-preserved Subsystem (GUI=2, CUI=3) & DllCharacteristics
        // CRITICAL FIX: Strip DYNAMIC_BASE (0x0040), HIGH_ENTROPY_VA (0x0020), and GUARD_CF (0x4000).
        // Since .reloc is stripped for shuffled .btg code, disabling ASLR forces the OS loader to
        // always load the executable at fixed preferred ImageBase (0x140000000), preventing random VA offset crashes.
        // P0-⑦: relocation-aware 경로(preserve_aslr_bits)는 .reloc data directory가 채워진
        // 상태에서 DYNAMIC_BASE/HIGH_ENTROPY_VA를 보존한다 (로더가 리베이스 시 .reloc으로
        // 부트 영역 절대 VA 슬롯을 패치 → 안전). GUARD_CF는 여전히 스트립 — CFG 함수
        // 테이블/비트맵이 패커 변환과 무결하지 않아 켜면 로더 거부/크래시 위험이 있다.
        let sanitized_dll_characteristics = if self.preserve_aslr_bits {
            self.dll_characteristics & !0x4000
        } else {
            self.dll_characteristics & !(0x0020 | 0x0040 | 0x4000)
        };
        pe_bytes[opt_pos + 68..opt_pos + 70].copy_from_slice(&self.subsystem.to_le_bytes());
        pe_bytes[opt_pos + 70..opt_pos + 72]
            .copy_from_slice(&sanitized_dll_characteristics.to_le_bytes());

        // Stack & Heap Reserves
        pe_bytes[opt_pos + 72..opt_pos + 80].copy_from_slice(&self.stack_reserve.to_le_bytes());
        pe_bytes[opt_pos + 80..opt_pos + 88].copy_from_slice(&self.stack_commit.to_le_bytes());
        pe_bytes[opt_pos + 88..opt_pos + 96].copy_from_slice(&self.heap_reserve.to_le_bytes());
        pe_bytes[opt_pos + 96..opt_pos + 104].copy_from_slice(&self.heap_commit.to_le_bytes());

        // Number of Data Directories = 16
        pe_bytes[opt_pos + 108..opt_pos + 112].copy_from_slice(&16u32.to_le_bytes());

        // Relay Target PE Data Directories (Export, Import, Resource, Exception .pdata, IAT, etc.)
        let data_dir_pos = opt_pos + 112;
        for (i, dir) in self.data_directories.iter().take(16).enumerate() {
            let pos = data_dir_pos + i * 8;
            if pos + 8 <= pe_bytes.len() {
                pe_bytes[pos..pos + 4].copy_from_slice(&dir.virtual_address.to_le_bytes());
                pe_bytes[pos + 4..pos + 8].copy_from_slice(&dir.size.to_le_bytes());
            }
        }

        // H4: Standard PE CheckSum calculation (Windows CheckSumMappedFile algorithm)
        let checksum_offset = opt_pos + 64;
        let calculated_checksum = calculate_pe_checksum(&pe_bytes, checksum_offset);
        pe_bytes[checksum_offset..checksum_offset + 4]
            .copy_from_slice(&calculated_checksum.to_le_bytes());

        Ok(pe_bytes)
    }
}

/// Calculate standard Microsoft PE image checksum (CheckSumMappedFile algorithm).
///
/// 1. Sums all 16-bit little-endian words with carry folding into a 32-bit accumulator.
/// 2. Skips the 4-byte CheckSum field at `checksum_offset`.
/// 3. Adds the total file length to the folded 16-bit sum.
pub fn calculate_pe_checksum(pe_bytes: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let len = pe_bytes.len();
    let num_words = len / 2;

    for i in 0..num_words {
        let byte_idx = i * 2;
        if byte_idx == checksum_offset || byte_idx == checksum_offset + 2 {
            continue;
        }
        let word = u16::from_le_bytes([pe_bytes[byte_idx], pe_bytes[byte_idx + 1]]) as u64;
        sum += word;
        if sum > 0xFFFF_FFFF {
            sum = (sum & 0xFFFF_FFFF) + (sum >> 32);
        }
    }

    if len % 2 != 0 {
        let word = pe_bytes[len - 1] as u64;
        sum += word;
        if sum > 0xFFFF_FFFF {
            sum = (sum & 0xFFFF_FFFF) + (sum >> 32);
        }
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    (sum + len as u64) as u32
}

// Preserve existing PeBuilder compatibility
pub struct PeBuilder {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub section_data: Vec<u8>,
}

impl PeBuilder {
    pub fn new(image_base: u64, entry_point_rva: u32, section_data: Vec<u8>) -> Self {
        Self {
            image_base,
            entry_point_rva,
            section_data,
        }
    }

    pub fn build(self) -> Result<Vec<u8>> {
        let text_sec = SectionData {
            name: ".text".to_string(),
            virtual_address: 0x1000,
            virtual_size: self.section_data.len() as u32,
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            bytes: self.section_data,
        };

        let builder = PeMultiSectionBuilder::new(
            self.image_base,
            self.entry_point_rva,
            3,
            0x8160,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0x200,
            0x1000,
            vec![],
            vec![],
            text_sec,
            None,
            Vec::new(),
        );
        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_checksum_calculation() {
        let dummy = vec![0x4Du8, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let csum = calculate_pe_checksum(&dummy, 0x40);
        assert!(csum > 0, "checksum must be non-zero");

        // Building minimal PE should produce non-zero CheckSum at opt_pos + 64
        let builder = PeBuilder::new(0x140000000, 0x1000, vec![0x90, 0xC3]);
        let pe_bytes = builder.build().unwrap();
        let e_lfanew = u32::from_le_bytes(pe_bytes[0x3C..0x40].try_into().unwrap()) as usize;
        let opt_pos = e_lfanew + 24;
        let checksum = u32::from_le_bytes(pe_bytes[opt_pos + 64..opt_pos + 68].try_into().unwrap());
        assert!(
            checksum > 0,
            "PE OptionalHeader.CheckSum must be populated and > 0"
        );
    }

    #[test]
    fn route_metadata_is_placed_read_only_after_vm_data() {
        let text = SectionData {
            name: ".textb".into(),
            virtual_address: 0x1000,
            virtual_size: 1,
            characteristics: 0x6000_0020,
            bytes: vec![0xC3],
        };
        let mut builder = PeMultiSectionBuilder::new(
            0x140000000,
            0x1000,
            3,
            0,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0x200,
            0x1000,
            vec![],
            vec![],
            text,
            None,
            Vec::new(),
        );
        builder.mutable_state_section = Some(SectionData {
            name: ".vstate".into(),
            virtual_address: 0x3000,
            virtual_size: 1,
            characteristics: 0xC000_0040,
            bytes: vec![0],
        });
        builder.route_metadata_section = Some(SectionData {
            name: ".vmroute".into(),
            virtual_address: 0,
            virtual_size: 4,
            characteristics: 0x4000_0040,
            bytes: vec![1, 2, 3, 4],
        });
        let pe = builder.build().unwrap();
        let nt = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
        let count = u16::from_le_bytes(pe[nt + 6..nt + 8].try_into().unwrap()) as usize;
        let table = nt + 4 + 20 + 240;
        let route = (0..count)
            .map(|i| &pe[table + i * 40..table + (i + 1) * 40])
            .find(|header| &header[..8] == b".vmroute")
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(route[12..16].try_into().unwrap()),
            0x4000
        );
        let characteristics = u32::from_le_bytes(route[36..40].try_into().unwrap());
        assert_eq!(characteristics, 0x4000_0040);
        assert_eq!(characteristics & IMAGE_SCN_MEM_EXECUTE, 0);
    }
}
