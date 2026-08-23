//! Typed PE32+ thread-local storage directory parser.
//!
//! The TLS directory contains virtual addresses (not RVAs).  Keeping that
//! distinction here prevents consumers from accidentally treating loader-owned
//! TLS metadata as ordinary section offsets.  The parser also records whether
//! every non-null VA field is backed by an IMAGE_REL_BASED_DIR64 relocation.

use crate::pe::builder::{DataDirectory, SectionData};
use anyhow::{anyhow, bail, Result};

const TLS_DIRECTORY64_SIZE: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationProvenance {
    /// The field is null and therefore needs no base relocation.
    NotApplicable,
    /// A DIR64 relocation exists at this field's RVA.
    Dir64 { slot_rva: u32 },
    /// The image contains an absolute VA but no matching DIR64 relocation.
    Missing { slot_rva: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsVa {
    pub va: u64,
    pub rva: Option<u32>,
    pub relocation: RelocationProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRawTemplate {
    pub start: TlsVa,
    pub end: TlsVa,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsIndex {
    pub address: TlsVa,
    /// Initial on-disk value. The Windows loader replaces this with the module's
    /// allocated TLS index.
    pub initial_value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCallback {
    pub address: TlsVa,
    /// RVA of this callback-array element (the relocation applies to the slot,
    /// rather than to the callback function itself).
    pub slot_rva: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDirectory64 {
    pub directory_rva: u32,
    pub raw_template: Option<TlsRawTemplate>,
    pub index: Option<TlsIndex>,
    pub callbacks_address: TlsVa,
    pub callbacks: Vec<TlsCallback>,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

/// Parse IMAGE_TLS_DIRECTORY64 and all directly referenced file-backed data.
///
/// `dir64_relocations` contains the RVAs of IMAGE_REL_BASED_DIR64 slots parsed
/// from the image's base-relocation directory. Callback slots are included in
/// provenance reporting because each array element is itself an absolute VA.
pub fn parse_tls_directory64(
    image_base: u64,
    directory: DataDirectory,
    sections: &[SectionData],
    dir64_relocations: &[u32],
) -> Result<Option<TlsDirectory64>> {
    if directory.virtual_address == 0 && directory.size == 0 {
        return Ok(None);
    }
    if directory.size < TLS_DIRECTORY64_SIZE as u32 {
        bail!(
            "PE32+ TLS directory is {} bytes; expected at least 40",
            directory.size
        );
    }
    let bytes = bytes_at(sections, directory.virtual_address, TLS_DIRECTORY64_SIZE)?;
    let start = read_u64(bytes, 0);
    let end = read_u64(bytes, 8);
    let index = read_u64(bytes, 16);
    let callbacks_va = read_u64(bytes, 24);

    let field = |va, offset| {
        tls_va(
            va,
            image_base,
            directory.virtual_address + offset,
            dir64_relocations,
        )
    };
    let start_typed = field(start, 0);
    let end_typed = field(end, 8);
    let index_typed = field(index, 16);
    let callbacks_address = field(callbacks_va, 24);

    let raw_template = match (start, end) {
        (0, 0) => None,
        (0, _) | (_, 0) => bail!("TLS raw template has only one null boundary"),
        _ if end < start => bail!("TLS raw template end VA precedes start VA"),
        _ => {
            let start_rva = va_to_rva(start, image_base)?;
            let len =
                usize::try_from(end - start).map_err(|_| anyhow!("TLS template is too large"))?;
            Some(TlsRawTemplate {
                start: start_typed,
                end: end_typed,
                bytes: bytes_at(sections, start_rva, len)?.to_vec(),
            })
        }
    };

    let index = if index == 0 {
        None
    } else {
        let rva = va_to_rva(index, image_base)?;
        let b = bytes_at(sections, rva, 4)?;
        Some(TlsIndex {
            address: index_typed,
            initial_value: read_u32(b, 0),
        })
    };

    let mut callbacks = Vec::new();
    if callbacks_va != 0 {
        let array_rva = va_to_rva(callbacks_va, image_base)?;
        // A callback array is loader metadata and must terminate within a
        // file-backed section. This also provides a strict, finite scan bound.
        for n in 0u32.. {
            let delta = n
                .checked_mul(8)
                .ok_or_else(|| anyhow!("TLS callback array overflows"))?;
            let slot_rva = array_rva
                .checked_add(delta)
                .ok_or_else(|| anyhow!("TLS callback RVA overflows"))?;
            let callback_va = read_u64(bytes_at(sections, slot_rva, 8)?, 0);
            if callback_va == 0 {
                break;
            }
            let address = tls_va(callback_va, image_base, slot_rva, dir64_relocations);
            // Reject external callback addresses: the loader will call these as
            // module entry points, so an out-of-image VA is malformed here.
            let callback_rva = address
                .rva
                .ok_or_else(|| anyhow!("TLS callback VA 0x{callback_va:X} is below image base"))?;
            bytes_at(sections, callback_rva, 1)?;
            callbacks.push(TlsCallback { address, slot_rva });
        }
    }

    Ok(Some(TlsDirectory64 {
        directory_rva: directory.virtual_address,
        raw_template,
        index,
        callbacks_address,
        callbacks,
        size_of_zero_fill: read_u32(bytes, 32),
        characteristics: read_u32(bytes, 36),
    }))
}

fn tls_va(va: u64, image_base: u64, slot_rva: u32, relocs: &[u32]) -> TlsVa {
    let relocation = if va == 0 {
        RelocationProvenance::NotApplicable
    } else if relocs.contains(&slot_rva) {
        RelocationProvenance::Dir64 { slot_rva }
    } else {
        RelocationProvenance::Missing { slot_rva }
    };
    TlsVa {
        va,
        rva: va
            .checked_sub(image_base)
            .and_then(|v| u32::try_from(v).ok()),
        relocation,
    }
}

fn va_to_rva(va: u64, image_base: u64) -> Result<u32> {
    let value = va
        .checked_sub(image_base)
        .ok_or_else(|| anyhow!("VA 0x{va:X} is below image base 0x{image_base:X}"))?;
    u32::try_from(value).map_err(|_| anyhow!("VA 0x{va:X} does not fit a PE32+ RVA"))
}

fn bytes_at(sections: &[SectionData], rva: u32, len: usize) -> Result<&[u8]> {
    for section in sections {
        let Some(offset) = rva.checked_sub(section.virtual_address) else {
            continue;
        };
        let offset = offset as usize;
        let Some(end) = offset.checked_add(len) else {
            break;
        };
        if end <= section.bytes.len() {
            return Ok(&section.bytes[offset..end]);
        }
    }
    bail!("RVA 0x{rva:X} length 0x{len:X} is not file-backed")
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x140000000;

    fn put64(b: &mut [u8], o: usize, v: u64) {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn fixture() -> (DataDirectory, Vec<SectionData>) {
        let mut b = vec![0u8; 0x300];
        // Directory @ RVA 0x2000, template @ 0x2080, index @ 0x2090,
        // callback array @ 0x20A0, and callback code @ 0x2100.
        put64(&mut b, 0x00, BASE + 0x2080);
        put64(&mut b, 0x08, BASE + 0x2084);
        put64(&mut b, 0x10, BASE + 0x2090);
        put64(&mut b, 0x18, BASE + 0x20A0);
        b[0x20..0x24].copy_from_slice(&12u32.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&0xA00000u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(&[1, 2, 3, 4]);
        b[0x90..0x94].copy_from_slice(&7u32.to_le_bytes());
        put64(&mut b, 0xA0, BASE + 0x2100);
        put64(&mut b, 0xA8, BASE + 0x2110);
        put64(&mut b, 0xB0, 0);
        b[0x100] = 0xC3;
        b[0x110] = 0xC3;
        (
            DataDirectory {
                virtual_address: 0x2000,
                size: 40,
            },
            vec![SectionData {
                name: ".rdata".into(),
                virtual_address: 0x2000,
                virtual_size: 0x300,
                characteristics: 0x40000040,
                bytes: b,
            }],
        )
    }

    #[test]
    fn parses_complete_pe32_plus_tls_graph_and_provenance() {
        let (dir, sections) = fixture();
        let tls = parse_tls_directory64(
            BASE,
            dir,
            &sections,
            &[0x2000, 0x2008, 0x2010, 0x2018, 0x20A0],
        )
        .unwrap()
        .unwrap();
        assert_eq!(tls.raw_template.unwrap().bytes, [1, 2, 3, 4]);
        assert_eq!(tls.index.unwrap().initial_value, 7);
        assert_eq!(tls.callbacks.len(), 2);
        assert_eq!(tls.callbacks[0].address.rva, Some(0x2100));
        assert_eq!(
            tls.callbacks[0].address.relocation,
            RelocationProvenance::Dir64 { slot_rva: 0x20A0 }
        );
        assert_eq!(
            tls.callbacks[1].address.relocation,
            RelocationProvenance::Missing { slot_rva: 0x20A8 }
        );
        assert_eq!(tls.size_of_zero_fill, 12);
    }

    #[test]
    fn absent_directory_and_truncated_callback_array_are_distinct() {
        assert!(parse_tls_directory64(
            BASE,
            DataDirectory {
                virtual_address: 0,
                size: 0
            },
            &[],
            &[]
        )
        .unwrap()
        .is_none());
        let (dir, mut sections) = fixture();
        sections[0].bytes.truncate(0xA8); // first entry present, terminator absent
        let err = parse_tls_directory64(BASE, dir, &sections, &[]).unwrap_err();
        assert!(err.to_string().contains("not file-backed"));
    }

    #[test]
    fn rejects_reversed_raw_template() {
        let (dir, mut sections) = fixture();
        put64(&mut sections[0].bytes, 0, BASE + 0x2088);
        put64(&mut sections[0].bytes, 8, BASE + 0x2084);
        assert!(parse_tls_directory64(BASE, dir, &sections, &[])
            .unwrap_err()
            .to_string()
            .contains("precedes"));
    }
}
