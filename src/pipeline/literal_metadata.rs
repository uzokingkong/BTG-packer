//! Conservative read-only loader ownership index for literal map auditing.
//! Not a replacement for full PE metadata/reference analysis.
use anyhow::{bail, Context, Result};
use goblin::pe::PE;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default)]
pub(super) struct MetadataIndex {
    ranges: Vec<(u64, u64)>,
    strings: BTreeSet<(u64, u64)>,
    tables: BTreeMap<(u64, bool), u64>,
}

impl MetadataIndex {
    pub(super) fn build(input: &[u8], pe: &PE<'_>) -> Result<Self> {
        if !pe.is_64 {
            bail!("literal metadata audit currently requires PE32+");
        }
        let reader = Reader { input, pe };
        let mut index = Self::default();
        let header = pe
            .header
            .optional_header
            .as_ref()
            .context("missing PE optional header")?;
        for (number, directory) in header.data_directories.data_directories.iter().enumerate() {
            if number == 4 {
                continue;
            } // certificate directory uses file offsets
            if let Some((_, directory)) = directory {
                if directory.size != 0 {
                    if directory.virtual_address == 0 {
                        bail!("null metadata directory RVA");
                    }
                    index.add(
                        u64::from(directory.virtual_address),
                        u64::from(directory.size),
                    )?;
                }
            }
        }
        if let Some((rva, size)) = reader.directory(1) {
            index.imports(&reader, rva, size, false)?;
        }
        if let Some((rva, size)) = reader.directory(13) {
            index.imports(&reader, rva, size, true)?;
        }
        if let Some((rva, size)) = reader.directory(9) {
            if size < 40 {
                bail!("truncated TLS directory");
            }
            let bytes = reader.bytes(rva, 40)?;
            let start = read64(bytes, 0);
            let end = read64(bytes, 8);
            match (start, end) {
                (0, 0) => {}
                (0, _) | (_, 0) => bail!("incomplete TLS template boundaries"),
                _ => {
                    if end < start {
                        bail!("reversed TLS template boundaries");
                    }
                    let template = reader.va(start)?;
                    if end != start {
                        reader.bytes(template, end - start)?;
                    }
                    index.add(template, end - start)?;
                }
            }
            let tls_index = read64(bytes, 16);
            if tls_index != 0 {
                index.add(reader.va(tls_index)?, 4)?;
            }
            let callbacks = read64(bytes, 24);
            if callbacks != 0 {
                index.thunks(&reader, reader.va(callbacks)?, false)?;
            }
        }
        if let Some((rva, size)) = reader.directory(10) {
            // The structure's Size field governs availability of SecurityCookie.
            let declared = read32(reader.bytes(rva, 4)?, 0);
            if size >= 96 && declared >= 96 {
                let cookie = read64(reader.bytes(rva, 96)?, 88);
                if cookie != 0 {
                    index.add(reader.va(cookie)?, 8)?;
                }
            }
        }
        index.ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in index.ranges {
            if let Some(last) = merged.last_mut() {
                if start <= last.1 {
                    last.1 = last.1.max(end);
                    continue;
                }
            }
            merged.push((start, end));
        }
        index.ranges = merged;
        Ok(index)
    }

    pub(super) fn overlaps(&self, start: u64, end: u64) -> bool {
        let next = self.ranges.partition_point(|(_, limit)| *limit <= start);
        self.ranges.get(next).is_some_and(|(base, _)| *base < end)
    }

    fn add(&mut self, start: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let end = start.checked_add(len).context("metadata range overflow")?;
        if end > u64::from(u32::MAX) + 1 {
            bail!("metadata range exceeds RVA space");
        }
        self.ranges.push((start, end));
        Ok(())
    }

    fn string(&mut self, reader: &Reader<'_, '_>, rva: u64, prefix: u64) -> Result<()> {
        if self.strings.contains(&(rva, prefix)) {
            return Ok(());
        }
        let text = rva
            .checked_add(prefix)
            .context("metadata string RVA overflow")?;
        let tail = reader.tail(text)?;
        let length = tail
            .iter()
            .position(|b| *b == 0)
            .context("unterminated metadata string")?;
        reader.bytes(rva, prefix + length as u64 + 1)?;
        self.add(rva, prefix + length as u64 + 1)?;
        self.strings.insert((rva, prefix));
        Ok(())
    }

    fn thunks(&mut self, reader: &Reader<'_, '_>, rva: u64, names: bool) -> Result<u64> {
        if rva == 0 {
            return Ok(0);
        }
        if let Some(length) = self.tables.get(&(rva, names)) {
            return Ok(*length);
        }
        let tail = reader.tail(rva)?;
        for (n, slot) in tail.chunks_exact(8).enumerate() {
            let value = read64(slot, 0);
            if value == 0 {
                let length = (n as u64 + 1) * 8;
                self.add(rva, length)?;
                self.tables.insert((rva, names), length);
                return Ok(length);
            }
            if names && value & (1u64 << 63) == 0 {
                if value > u64::from(u32::MAX) {
                    bail!("invalid import name RVA");
                }
                self.string(reader, value, 2)?; // hint WORD + NUL terminated name
            }
        }
        bail!("unterminated loader pointer array")
    }

    fn imports(&mut self, reader: &Reader<'_, '_>, rva: u64, size: u32, delay: bool) -> Result<()> {
        let width = if delay { 32 } else { 20 };
        let bytes = reader.bytes(rva, u64::from(size))?;
        for descriptor in bytes.chunks_exact(width) {
            if descriptor.iter().all(|b| *b == 0) {
                return Ok(());
            }
            if delay {
                let attributes = read32(descriptor, 0);
                if attributes & !1 != 0 {
                    bail!("unsupported delay import attributes");
                }
                let pointer = |offset| -> Result<u64> {
                    let p = u64::from(read32(descriptor, offset));
                    if p == 0 || attributes & 1 != 0 {
                        Ok(p)
                    } else {
                        reader.va(p)
                    }
                };
                let name = pointer(4)?;
                let iat = pointer(12)?;
                let lookup = pointer(16)?;
                if name == 0 || iat == 0 || lookup == 0 {
                    bail!("incomplete delay import descriptor");
                }
                self.string(reader, name, 0)?;
                let handle = pointer(8)?;
                if handle != 0 {
                    self.add(handle, 8)?;
                }
                let length = self.thunks(reader, lookup, true)?;
                for table in [iat, pointer(20)?, pointer(24)?] {
                    if table != 0 {
                        reader.bytes(table, length)?;
                        self.add(table, length)?;
                    }
                }
            } else {
                let lookup = u64::from(read32(descriptor, 0));
                let name = u64::from(read32(descriptor, 12));
                let iat = u64::from(read32(descriptor, 16));
                if name == 0 || iat == 0 {
                    bail!("incomplete import descriptor");
                }
                self.string(reader, name, 0)?;
                let length = self.thunks(reader, if lookup == 0 { iat } else { lookup }, true)?;
                reader.bytes(iat, length)?;
                self.add(iat, length)?;
            }
        }
        bail!("unterminated import descriptor array")
    }
}

struct Reader<'a, 'b> {
    input: &'a [u8],
    pe: &'b PE<'a>,
}

impl Reader<'_, '_> {
    fn directory(&self, number: usize) -> Option<(u64, u32)> {
        let (_, directory) = self
            .pe
            .header
            .optional_header
            .as_ref()?
            .data_directories
            .data_directories
            .get(number)?
            .as_ref()?;
        if directory.size == 0 {
            None
        } else {
            Some((u64::from(directory.virtual_address), directory.size))
        }
    }

    fn va(&self, va: u64) -> Result<u64> {
        let rva = va
            .checked_sub(self.pe.image_base as u64)
            .context("metadata VA below image base")?;
        if rva > u64::from(u32::MAX) {
            bail!("metadata VA exceeds RVA space");
        }
        Ok(rva)
    }

    fn tail(&self, rva: u64) -> Result<&[u8]> {
        let mut result = None;
        for section in &self.pe.sections {
            let base = u64::from(section.virtual_address);
            let len = u64::from(section.virtual_size).min(u64::from(section.size_of_raw_data));
            if rva >= base && rva < base + len {
                if result.is_some() {
                    bail!("ambiguous metadata RVA mapping");
                }
                let raw = u64::from(section.pointer_to_raw_data);
                let start =
                    usize::try_from(raw + rva - base).context("metadata file offset overflow")?;
                let end = usize::try_from(raw + len).context("metadata file end overflow")?;
                result = Some(
                    self.input
                        .get(start..end)
                        .context("metadata extends past file")?,
                );
            }
        }
        result.context("metadata RVA is not file-backed")
    }

    fn bytes(&self, rva: u64, len: u64) -> Result<&[u8]> {
        let len = usize::try_from(len).context("metadata length overflow")?;
        self.tail(rva)?
            .get(..len)
            .context("metadata span exceeds file-backed section")
    }
}

fn read32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn read64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        bytes: Vec<u8>,
        raw: usize,
        base: u32,
        directory_offset: usize,
        image_base: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let mut bytes = crate::pe::generate_dummy_target_pe().unwrap();
            let pe = PE::parse(&bytes).unwrap();
            let raw = pe.sections[0].pointer_to_raw_data as usize;
            let base = pe.sections[0].virtual_address;
            let image_base = pe.image_base as u64;
            let pe_offset = read32(&bytes, 0x3c) as usize;
            let opt_size =
                u16::from_le_bytes(bytes[pe_offset + 20..pe_offset + 22].try_into().unwrap())
                    as usize;
            let section_offset = pe_offset + 24 + opt_size;
            // Reserve the existing raw padding as mapped fixture data.
            bytes[section_offset + 8..section_offset + 12].copy_from_slice(&512u32.to_le_bytes());
            bytes[raw..raw + 512].fill(0);
            Self {
                bytes,
                raw,
                base,
                directory_offset: pe_offset + 24 + 112,
                image_base,
            }
        }

        fn put32(&mut self, offset: usize, value: u32) {
            self.bytes[self.raw + offset..self.raw + offset + 4]
                .copy_from_slice(&value.to_le_bytes());
        }
        fn put64(&mut self, offset: usize, value: u64) {
            self.bytes[self.raw + offset..self.raw + offset + 8]
                .copy_from_slice(&value.to_le_bytes());
        }
        fn directory(&mut self, index: usize, offset: u32, size: u32) {
            let slot = self.directory_offset + index * 8;
            self.bytes[slot..slot + 4].copy_from_slice(&(self.base + offset).to_le_bytes());
            self.bytes[slot + 4..slot + 8].copy_from_slice(&size.to_le_bytes());
        }
        fn index(&self) -> Result<MetadataIndex> {
            let pe = PE::parse(&self.bytes)?;
            MetadataIndex::build(&self.bytes, &pe)
        }
    }

    #[test]
    fn import_names_hint_and_full_iat_are_owned() {
        let mut f = Fixture::new();
        f.directory(1, 0x40, 40);
        f.put32(0x40, f.base + 0xa0);
        f.put32(0x4c, f.base + 0x90);
        f.put32(0x50, f.base + 0xb0);
        f.bytes[f.raw + 0x90..f.raw + 0x96].copy_from_slice(b"a.dll\0");
        f.put64(0xa0, u64::from(f.base + 0xc0));
        f.bytes[f.raw + 0xc2..f.raw + 0xc6].copy_from_slice(b"Foo\0");
        // IAT is initially zero; both slots must nevertheless be owned.
        let index = f.index().unwrap();
        for (offset, length) in [(0x90, 6), (0xa0, 16), (0xb0, 16), (0xc0, 6)] {
            let start = u64::from(f.base) + offset;
            assert!(index.overlaps(start, start + length));
            assert!(index.overlaps(start + length - 1, start + length));
        }
        assert!(!index.overlaps(u64::from(f.base) + 0xc6, u64::from(f.base) + 0xc8));
        let map = super::super::literal_map::LiteralMap {
            schema_version: 1,
            input_sha256: {
                use sha2::{Digest, Sha256};
                Sha256::digest(&f.bytes).into()
            },
            spans: vec![super::super::literal_catalog::LiteralSpan {
                id: 1,
                rva: f.base + 0xc2,
                byte_len: 3,
                terminator_len: 1,
                encoding: super::super::literal_catalog::Encoding::Ascii,
                phase: super::super::literal_catalog::AccessPhase::PostBoot,
                evidence: super::super::literal_catalog::Evidence::ExplicitMap,
            }],
        };
        assert!(map
            .validate(&f.bytes)
            .unwrap_err()
            .to_string()
            .contains("loader-owned"));
    }

    #[test]
    fn tls_template_index_and_callback_null_slot_are_owned() {
        let mut f = Fixture::new();
        f.directory(9, 0x40, 40);
        f.put64(0x40, f.image_base + u64::from(f.base) + 0x90);
        f.put64(0x48, f.image_base + u64::from(f.base) + 0x98);
        f.put64(0x50, f.image_base + u64::from(f.base) + 0xa0);
        f.put64(0x58, f.image_base + u64::from(f.base) + 0xb0);
        f.put64(0xb0, f.image_base + u64::from(f.base));
        let index = f.index().unwrap();
        for (offset, length) in [(0x90, 8), (0xa0, 4), (0xb0, 16)] {
            let start = u64::from(f.base) + offset;
            assert!(index.overlaps(start, start + length));
            assert!(index.overlaps(start + length - 1, start + length));
        }
        f.put64(0x48, f.image_base - 1);
        assert!(f.index().is_err());
    }

    #[test]
    fn delay_import_tables_and_module_handle_are_owned() {
        let mut f = Fixture::new();
        f.directory(13, 0x40, 64);
        for (offset, value) in [
            (0x40, 1),
            (0x44, f.base + 0x90),
            (0x48, f.base + 0x98),
            (0x4c, f.base + 0xb0),
            (0x50, f.base + 0xa0),
            (0x54, f.base + 0xd0),
            (0x58, f.base + 0xe0),
        ] {
            f.put32(offset, value);
        }
        f.bytes[f.raw + 0x90..f.raw + 0x96].copy_from_slice(b"a.dll\0");
        f.put64(0xa0, u64::from(f.base + 0xc0));
        f.bytes[f.raw + 0xc2..f.raw + 0xc6].copy_from_slice(b"Foo\0");
        let index = f.index().unwrap();
        for (offset, length) in [
            (0x90, 6),
            (0x98, 8),
            (0xa0, 16),
            (0xb0, 16),
            (0xc0, 6),
            (0xd0, 16),
            (0xe0, 16),
        ] {
            let start = u64::from(f.base) + offset;
            assert!(index.overlaps(start + length - 1, start + length));
        }
        f.put32(0x40, 3);
        assert!(f.index().is_err());
    }

    #[test]
    fn load_config_cookie_is_owned() {
        let mut f = Fixture::new();
        f.directory(10, 0x40, 96);
        f.put32(0x40, 96);
        f.put64(0x98, f.image_base + u64::from(f.base) + 0xc0);
        let index = f.index().unwrap();
        assert!(index.overlaps(u64::from(f.base) + 0xc7, u64::from(f.base) + 0xc8));
    }

    #[test]
    fn unterminated_tls_callback_array_is_rejected() {
        let mut f = Fixture::new();
        f.directory(9, 0x40, 40);
        f.put64(0x58, f.image_base + u64::from(f.base) + 0x100);
        for offset in (0x100..0x200).step_by(8) {
            f.put64(offset, f.image_base + u64::from(f.base));
        }
        assert!(f.index().is_err());
    }

    #[test]
    fn shared_tables_and_strings_are_indexed_once() {
        let f = Fixture::new();
        let pe = PE::parse(&f.bytes).unwrap();
        let reader = Reader {
            input: &f.bytes,
            pe: &pe,
        };
        let mut index = MetadataIndex::default();
        let rva = u64::from(f.base) + 0x80;
        // All fixture bytes are zero: a terminated empty string / null table.
        index.string(&reader, rva, 0).unwrap();
        index.string(&reader, rva, 0).unwrap();
        assert_eq!(index.strings.len(), 1);
        assert_eq!(index.thunks(&reader, rva, true).unwrap(), 8);
        assert_eq!(index.thunks(&reader, rva, true).unwrap(), 8);
        assert_eq!(index.tables.len(), 1);
        assert_eq!(index.ranges.len(), 2);
    }

    #[test]
    fn ownership_ranges_merge_and_queries_respect_half_open_bounds() {
        let index = MetadataIndex {
            ranges: vec![(10, 20), (30, 40)],
            ..Default::default()
        };
        assert!(!index.overlaps(0, 10));
        assert!(!index.overlaps(20, 30));
        assert!(index.overlaps(19, 21));
        assert!(index.overlaps(39, 41));
        assert!(!index.overlaps(40, 41));
    }
}
