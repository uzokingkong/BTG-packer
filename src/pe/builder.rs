// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Multi-Section PE Synthesizer (Relay Engine)
// ==============================================================================

use anyhow::Result;
use goblin::pe::header::Header;
use goblin::pe::section_table::{
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, SectionTable,
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
    pub original_headers_bytes: Vec<u8>,
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
            original_headers_bytes,
        }
    }

    pub fn build(self) -> Result<Vec<u8>> {
        let align_config = PeAlignmentConfig {
            file_alignment: if self.file_alignment == 0 { 0x200 } else { self.file_alignment },
            section_alignment: if self.section_alignment == 0 { 0x1000 } else { self.section_alignment },
        };

        let num_sections = (self.relayed_sections.len() + 1 + usize::from(self.payload_section.is_some())) as u16;
        let header_size = self.original_headers_bytes.len().max(0x400);
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

        let e_lfanew = u32::from_le_bytes(pe_bytes[0x3C..0x40].try_into().unwrap_or([0x80, 0, 0, 0])) as usize;
        let nt_pos = if e_lfanew > 0 && e_lfanew < pe_bytes.len() - 0x100 { e_lfanew } else { 0x80 };

        // COFF File Header
        let mut header = Header::default();
        header.coff_header.machine = 0x8664; // x64
        header.coff_header.number_of_sections = num_sections;
        header.coff_header.size_of_optional_header = 240;
        header.coff_header.characteristics = 0x0023; // RELOCS_STRIPPED | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

        // Calculate max Virtual Address for btg_section placement
        // v9 FIX: relayed 섹션이 하나도 없는 경우(자체 생성 dummy 타깃) 기본값을
        // 0x2000이 아닌 0으로 잡아 .text(0x1000)가 0x2000으로 밀려 EP와 어긋나는
        // 문제를 제거한다. 실제 패커 경로는 항상 relayed 섹션이 있어 영향 없음.
        let max_existing_va = self
            .relayed_sections
            .iter()
            .map(|s| s.virtual_address + align_config.align_size(s.virtual_size.max(s.bytes.len() as u32), AlignmentType::Section))
            .max()
            .unwrap_or(0x1000);

        let mut adjusted_btg_section = self.btg_section;
        if adjusted_btg_section.virtual_address < max_existing_va {
            adjusted_btg_section.virtual_address = align_config.align_size(max_existing_va, AlignmentType::Section);
        }

        // v4: --payload-relocate — 암호화된 코드 페이로드 섹션(.vdata)을 .textb 직후에 배치
        let mut adjusted_payload_section = self.payload_section;
        if let Some(ref mut psec) = adjusted_payload_section {
            let btg_end = adjusted_btg_section.virtual_address
                + align_config.align_size(
                    adjusted_btg_section.virtual_size.max(adjusted_btg_section.bytes.len() as u32),
                    AlignmentType::Section,
                );
            psec.virtual_address = align_config.align_size(btg_end, AlignmentType::Section);
        }

        // Write Section Headers
        let sec_table_offset = nt_pos + 4 + 20 + 240;
        let mut current_file_ptr = size_of_headers;
        let mut max_va = 0u32;

        let mut all_sections = self.relayed_sections.clone();
        all_sections.push(adjusted_btg_section);
        if let Some(ps) = adjusted_payload_section {
            all_sections.push(ps);
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

            let raw_size = align_config.align_size(sec_data.bytes.len() as u32, AlignmentType::File);
            sec_entry.size_of_raw_data = raw_size;
            sec_entry.pointer_to_raw_data = if sec_data.bytes.is_empty() { 0 } else { current_file_ptr };
            sec_entry.characteristics = sec_data.characteristics;

            // Write Section Table Header Entry
            let entry_pos = sec_table_offset + i * 40;
            pe_bytes[entry_pos..entry_pos + 8].copy_from_slice(&sec_entry.name);
            pe_bytes[entry_pos + 8..entry_pos + 12].copy_from_slice(&sec_entry.virtual_size.to_le_bytes());
            pe_bytes[entry_pos + 12..entry_pos + 16].copy_from_slice(&sec_entry.virtual_address.to_le_bytes());
            pe_bytes[entry_pos + 16..entry_pos + 20].copy_from_slice(&sec_entry.size_of_raw_data.to_le_bytes());
            pe_bytes[entry_pos + 20..entry_pos + 24].copy_from_slice(&sec_entry.pointer_to_raw_data.to_le_bytes());
            pe_bytes[entry_pos + 36..entry_pos + 40].copy_from_slice(&sec_entry.characteristics.to_le_bytes());

            // Append Raw Section Bytes to PE Buffer if present
            if !sec_data.bytes.is_empty() {
                let needed_len = (current_file_ptr + raw_size) as usize;
                if pe_bytes.len() < needed_len {
                    pe_bytes.resize(needed_len, 0);
                }
                pe_bytes[current_file_ptr as usize..current_file_ptr as usize + sec_data.bytes.len()]
                    .copy_from_slice(&sec_data.bytes);

                current_file_ptr += raw_size;
            }

            max_va = max_va.max(sec_data.virtual_address + align_config.align_size(actual_virtual_size, AlignmentType::Section));
        }

        let size_of_image = max_va;

        // Write Final NT File Header
        let file_hdr_pos = nt_pos + 4;
        pe_bytes[file_hdr_pos..file_hdr_pos + 2].copy_from_slice(&header.coff_header.machine.to_le_bytes());
        pe_bytes[file_hdr_pos + 2..file_hdr_pos + 4].copy_from_slice(&header.coff_header.number_of_sections.to_le_bytes());
        pe_bytes[file_hdr_pos + 16..file_hdr_pos + 18].copy_from_slice(&header.coff_header.size_of_optional_header.to_le_bytes());
        pe_bytes[file_hdr_pos + 18..file_hdr_pos + 20].copy_from_slice(&header.coff_header.characteristics.to_le_bytes());

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
        pe_bytes[opt_pos + 3] = 0;  // MinorLinkerVersion
        pe_bytes[opt_pos + 4..opt_pos + 8].copy_from_slice(&total_code_size.to_le_bytes()); // SizeOfCode
        pe_bytes[opt_pos + 16..opt_pos + 20].copy_from_slice(&self.entry_point_rva.to_le_bytes());
        pe_bytes[opt_pos + 20..opt_pos + 24].copy_from_slice(&base_of_code.to_le_bytes()); // BaseOfCode
        pe_bytes[opt_pos + 24..opt_pos + 32].copy_from_slice(&self.image_base.to_le_bytes());
        pe_bytes[opt_pos + 32..opt_pos + 36].copy_from_slice(&align_config.section_alignment.to_le_bytes());
        pe_bytes[opt_pos + 36..opt_pos + 40].copy_from_slice(&align_config.file_alignment.to_le_bytes());

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
        let sanitized_dll_characteristics = self.dll_characteristics & !(0x0020 | 0x0040 | 0x4000);
        pe_bytes[opt_pos + 68..opt_pos + 70].copy_from_slice(&self.subsystem.to_le_bytes());
        pe_bytes[opt_pos + 70..opt_pos + 72].copy_from_slice(&sanitized_dll_characteristics.to_le_bytes());

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

        Ok(pe_bytes)
    }
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
