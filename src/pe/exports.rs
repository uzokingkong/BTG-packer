//! Typed, bounds-checked parser for the PE export directory.

use crate::pe::builder::{DataDirectory, SectionData};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeMap;

const EXPORT_DIRECTORY_SIZE: usize = 40;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    /// Public ordinal (`OrdinalBase + function-table index`).
    pub ordinal: u32,
    /// Export name, when the name pointer table assigns one to this ordinal.
    pub name: Option<String>,
    /// Address-table RVA. Forwarders retain the RVA of their forwarder string.
    pub address_rva: u32,
    /// Forwarder string such as `KERNEL32.Sleep`, when this address points back
    /// into the export directory.
    pub forwarder: Option<String>,
    /// True only for a non-forwarded RVA backed by an executable section.
    pub internal_executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDirectory {
    pub directory_rva: u32,
    pub ordinal_base: u32,
    pub dll_name: Option<String>,
    /// Non-null entries in address-table order, including forwarded exports.
    pub entries: Vec<ExportEntry>,
}

impl ExportDirectory {
    pub fn executable_entries(&self) -> impl Iterator<Item = &ExportEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.internal_executable)
    }
}

pub fn parse_export_directory(
    directory: DataDirectory,
    sections: &[SectionData],
) -> Result<Option<ExportDirectory>> {
    if directory.virtual_address == 0 && directory.size == 0 {
        return Ok(None);
    }
    if directory.virtual_address == 0 || directory.size < EXPORT_DIRECTORY_SIZE as u32 {
        bail!("invalid export directory RVA/size");
    }
    let header = bytes_at(sections, directory.virtual_address, EXPORT_DIRECTORY_SIZE)
        .context("export directory header is not file-backed")?;
    let name_rva = u32_at(header, 12);
    let ordinal_base = u32_at(header, 16);
    let function_count = u32_at(header, 20);
    let name_count = u32_at(header, 24);
    let functions_rva = u32_at(header, 28);
    let names_rva = u32_at(header, 32);
    let ordinals_rva = u32_at(header, 36);

    let function_bytes = table_bytes(sections, functions_rva, function_count, 4, "export address")?;
    let name_bytes = table_bytes(sections, names_rva, name_count, 4, "export name pointer")?;
    let ordinal_bytes = table_bytes(sections, ordinals_rva, name_count, 2, "export ordinal")?;

    let mut names = BTreeMap::<u32, String>::new();
    for index in 0..name_count as usize {
        let ordinal_index = u16_at(ordinal_bytes, index * 2) as u32;
        if ordinal_index >= function_count {
            bail!(
                "export name ordinal index {} exceeds function count {}",
                ordinal_index,
                function_count
            );
        }
        let export_name_rva = u32_at(name_bytes, index * 4);
        let export_name = c_string_at(sections, export_name_rva, None)
            .with_context(|| format!("invalid export name at RVA 0x{export_name_rva:X}"))?;
        if names.insert(ordinal_index, export_name).is_some() {
            bail!("duplicate named export ordinal index {ordinal_index}");
        }
    }

    let directory_end = directory
        .virtual_address
        .checked_add(directory.size)
        .ok_or_else(|| anyhow!("export directory range overflows RVA space"))?;
    let mut entries = Vec::new();
    for index in 0..function_count as usize {
        let address_rva = u32_at(function_bytes, index * 4);
        if address_rva == 0 {
            continue; // an unused ordinal slot, not an export target
        }
        let forwarded = address_rva >= directory.virtual_address && address_rva < directory_end;
        let forwarder = if forwarded {
            Some(
                c_string_at(sections, address_rva, Some(directory_end)).with_context(|| {
                    format!("invalid export forwarder at RVA 0x{address_rva:X}")
                })?,
            )
        } else {
            None
        };
        let internal_executable = !forwarded && is_executable_rva(sections, address_rva);
        entries.push(ExportEntry {
            ordinal: ordinal_base
                .checked_add(index as u32)
                .ok_or_else(|| anyhow!("export ordinal overflows u32"))?,
            name: names.remove(&(index as u32)),
            address_rva,
            forwarder,
            internal_executable,
        });
    }

    let dll_name = (name_rva != 0)
        .then(|| c_string_at(sections, name_rva, None))
        .transpose()
        .context("invalid export DLL name")?;
    Ok(Some(ExportDirectory {
        directory_rva: directory.virtual_address,
        ordinal_base,
        dll_name,
        entries,
    }))
}

fn table_bytes<'a>(
    sections: &'a [SectionData],
    rva: u32,
    count: u32,
    width: usize,
    label: &str,
) -> Result<&'a [u8]> {
    if count == 0 {
        return Ok(&[]);
    }
    if rva == 0 {
        bail!("{label} table is null with non-zero count");
    }
    let len = usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(width))
        .ok_or_else(|| anyhow!("{label} table size overflows"))?;
    bytes_at(sections, rva, len).with_context(|| format!("{label} table is not file-backed"))
}

fn is_executable_rva(sections: &[SectionData], rva: u32) -> bool {
    sections.iter().any(|section| {
        section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            && rva
                .checked_sub(section.virtual_address)
                .is_some_and(|offset| {
                    offset < section.virtual_size && (offset as usize) < section.bytes.len()
                })
    })
}

fn c_string_at(
    sections: &[SectionData],
    rva: u32,
    exclusive_end_rva: Option<u32>,
) -> Result<String> {
    let (section, offset) =
        locate(sections, rva).ok_or_else(|| anyhow!("RVA is not file-backed"))?;
    let max_by_directory = exclusive_end_rva
        .map(|end| end.checked_sub(rva).map(|v| v as usize).unwrap_or(0))
        .unwrap_or(usize::MAX);
    let tail =
        &section.bytes[offset..offset + (section.bytes.len() - offset).min(max_by_directory)];
    let nul = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| anyhow!("unterminated string"))?;
    String::from_utf8(tail[..nul].to_vec()).context("export string is not UTF-8")
}

fn locate(sections: &[SectionData], rva: u32) -> Option<(&SectionData, usize)> {
    sections.iter().find_map(|section| {
        let offset = rva.checked_sub(section.virtual_address)? as usize;
        (offset < section.bytes.len()).then_some((section, offset))
    })
}

fn bytes_at(sections: &[SectionData], rva: u32, len: usize) -> Result<&[u8]> {
    let (section, offset) =
        locate(sections, rva).ok_or_else(|| anyhow!("RVA 0x{rva:X} is not file-backed"))?;
    let end = offset
        .checked_add(len)
        .ok_or_else(|| anyhow!("RVA range overflows"))?;
    section
        .bytes
        .get(offset..end)
        .ok_or_else(|| anyhow!("RVA 0x{rva:X} length 0x{len:X} is not file-backed"))
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (DataDirectory, Vec<SectionData>) {
        let mut rdata = vec![0u8; 0x200];
        // IMAGE_EXPORT_DIRECTORY @ 0x2000; tables @ 0x2040/50/60.
        rdata[12..16].copy_from_slice(&0x2070u32.to_le_bytes());
        rdata[16..20].copy_from_slice(&7u32.to_le_bytes());
        rdata[20..24].copy_from_slice(&3u32.to_le_bytes());
        rdata[24..28].copy_from_slice(&2u32.to_le_bytes());
        rdata[28..32].copy_from_slice(&0x2040u32.to_le_bytes());
        rdata[32..36].copy_from_slice(&0x2050u32.to_le_bytes());
        rdata[36..40].copy_from_slice(&0x2060u32.to_le_bytes());
        rdata[0x40..0x44].copy_from_slice(&0x1000u32.to_le_bytes());
        rdata[0x44..0x48].copy_from_slice(&0x2080u32.to_le_bytes());
        rdata[0x48..0x4c].copy_from_slice(&0u32.to_le_bytes());
        rdata[0x50..0x54].copy_from_slice(&0x2090u32.to_le_bytes());
        rdata[0x54..0x58].copy_from_slice(&0x2096u32.to_le_bytes());
        rdata[0x60..0x62].copy_from_slice(&0u16.to_le_bytes());
        rdata[0x62..0x64].copy_from_slice(&1u16.to_le_bytes());
        rdata[0x70..0x78].copy_from_slice(b"demo.dll");
        rdata[0x78] = 0;
        rdata[0x80..0x8b].copy_from_slice(b"OTHER.Func\0");
        rdata[0x90..0x96].copy_from_slice(b"Start\0");
        rdata[0x96..0x9c].copy_from_slice(b"Alias\0");
        (
            DataDirectory {
                virtual_address: 0x2000,
                size: 0x100,
            },
            vec![
                SectionData {
                    name: ".text".into(),
                    virtual_address: 0x1000,
                    virtual_size: 0x100,
                    characteristics: IMAGE_SCN_MEM_EXECUTE,
                    bytes: vec![0xC3; 0x100],
                },
                SectionData {
                    name: ".rdata".into(),
                    virtual_address: 0x2000,
                    virtual_size: 0x200,
                    characteristics: 0x4000_0040,
                    bytes: rdata,
                },
            ],
        )
    }

    #[test]
    fn parses_named_ordinal_and_forwarded_exports() {
        let (directory, sections) = fixture();
        let exports = parse_export_directory(directory, &sections)
            .unwrap()
            .unwrap();
        assert_eq!(exports.dll_name.as_deref(), Some("demo.dll"));
        assert_eq!(exports.entries.len(), 2); // null EAT slot omitted
        assert_eq!(
            (
                exports.entries[0].ordinal,
                exports.entries[0].name.as_deref()
            ),
            (7, Some("Start"))
        );
        assert!(exports.entries[0].internal_executable);
        assert_eq!(exports.entries[1].forwarder.as_deref(), Some("OTHER.Func"));
        assert!(!exports.entries[1].internal_executable);
        assert_eq!(exports.executable_entries().count(), 1);
    }

    #[test]
    fn rejects_out_of_range_name_ordinal_and_unterminated_forwarder() {
        let (directory, mut sections) = fixture();
        sections[1].bytes[0x60..0x62].copy_from_slice(&3u16.to_le_bytes());
        assert!(parse_export_directory(directory, &sections)
            .unwrap_err()
            .to_string()
            .contains("exceeds function count"));
        let (directory, mut sections) = fixture();
        sections[1].bytes[0x80..0x100].fill(b'X');
        assert!(parse_export_directory(directory, &sections)
            .unwrap_err()
            .to_string()
            .contains("invalid export forwarder"));
    }
}
