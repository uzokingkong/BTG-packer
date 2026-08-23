// ==============================================================================
// BTG - post-build resource (.rsrc) validation - split from validate.rs
// ==============================================================================
use super::{section_for_rva, SectionInfo, CHUNK_SIZE, MAX_CHUNKS};
use crate::pipeline::PipelineContext;
use anyhow::{anyhow, bail, Result};
use goblin::pe::PE;
use std::collections::HashSet;

/// A leaf IMAGE_RESOURCE_DATA_ENTRY found in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResDataEntry {
    pub(crate) offset_rva: u32,
    pub(crate) size: u32,
}

/// Walk one resource directory (header + entries) at section-relative `off`.
///
/// Directory/data-entry offsets stored in the tree are relative to the
/// resource base (= the tree root, DataDirectory[2]), per the PE spec. Since
/// `sec_bytes` is the section's byte range, `base` is the section offset of
/// that root, and every child pointer is resolved as `base + tree_local`.
/// All offsets are bounds-checked against the section's file-backed bytes; a
/// `visited` set guards against cycles in a malformed tree.
#[allow(clippy::too_many_arguments)]
pub(crate) fn walk_dir(
    sec_bytes: &[u8],
    off: usize,
    base: usize,
    visited: &mut HashSet<usize>,
    out: &mut Vec<ResDataEntry>,
    sections: &[SectionInfo],
) -> Result<()> {
    if !visited.insert(off) {
        return Ok(());
    }
    if off + 16 > sec_bytes.len() {
        bail!("resource directory header out of bounds @0x{:X}", off);
    }
    let u16at = |o: usize| u16::from_le_bytes([sec_bytes[o], sec_bytes[o + 1]]);
    let u32at = |o: usize| {
        u32::from_le_bytes([
            sec_bytes[o],
            sec_bytes[o + 1],
            sec_bytes[o + 2],
            sec_bytes[o + 3],
        ])
    };

    let named = u16at(off + 12) as usize;
    let ids = u16at(off + 14) as usize;

    for i in 0..(named + ids) {
        let e = off + 16 + i * 8;
        if e + 8 > sec_bytes.len() {
            bail!("resource directory entry out of bounds @0x{:X}", e);
        }
        let data_off_raw = u32at(e + 4);
        if data_off_raw & 0x8000_0000 != 0 {
            // subdirectory (high bit set → tree-relative offset to another dir)
            let sub = base + (data_off_raw & 0x7FFF_FFFF) as usize;
            if sub + 16 > sec_bytes.len() {
                bail!("resource subdirectory offset 0x{:X} out of bounds", sub);
            }
            walk_dir(sec_bytes, sub, base, visited, out, sections)?;
        } else {
            // IMAGE_RESOURCE_DATA_ENTRY (tree-relative offset)
            let de = base + data_off_raw as usize;
            if de + 16 > sec_bytes.len() {
                bail!("resource data entry offset 0x{:X} out of bounds", de);
            }
            let rva = u32at(de);
            let size = u32at(de + 4);
            // OffsetToData is an RVA; [rva, rva+size) must sit inside a section.
            let in_section = sections.iter().any(|s| {
                let end = s.rva.saturating_add(s.virtual_size);
                rva >= s.rva && rva < end && size <= end - rva
            });
            if !in_section {
                bail!(
                    "resource data @RVA 0x{:X} size 0x{:X} outside all sections",
                    rva,
                    size
                );
            }
            out.push(ResDataEntry {
                offset_rva: rva,
                size,
            });
        }
    }
    Ok(())
}

/// Walk the whole resource tree rooted at `dir_rva` (inside `tree_sec`) and
/// return every IMAGE_RESOURCE_DATA_ENTRY found.
pub(crate) fn walk_resource_tree(
    tree_sec: &SectionInfo,
    file_bytes: &[u8],
    dir_rva: u32,
    dir_size: u32,
    sections: &[SectionInfo],
) -> Result<Vec<ResDataEntry>> {
    let sec_local = dir_rva
        .checked_sub(tree_sec.rva)
        .ok_or_else(|| anyhow!("resource dir RVA 0x{:X} below section start", dir_rva))?;
    let base = (tree_sec.raw_ptr as usize)
        .checked_add(sec_local as usize)
        .ok_or_else(|| anyhow!("resource dir base overflow"))?;
    let raw_end = ((tree_sec.raw_ptr as usize).saturating_add(tree_sec.raw_size as usize))
        .min(file_bytes.len());
    if base >= raw_end {
        bail!(
            "resource dir RVA 0x{:X} not backed by file data (raw 0x{:X}..0x{:X})",
            dir_rva,
            tree_sec.raw_ptr,
            raw_end
        );
    }
    if raw_end - base < dir_size as usize {
        bail!(
            "resource dir size 0x{:X} exceeds section raw tail (0x{:X} bytes left)",
            dir_size,
            raw_end - base
        );
    }
    // `sec_bytes` is the section's own byte range; tree pointers are relative
    // to the resource base (tree root), handled by passing root_off as `base`.
    let sec_bytes = &file_bytes[tree_sec.raw_ptr as usize..raw_end];
    let root_off = sec_local as usize;

    let mut entries = Vec::new();
    let mut visited = HashSet::new();
    // Tree pointers are relative to the resource base == root_off within the
    // section, so pass root_off as `base`.
    walk_dir(
        sec_bytes,
        root_off,
        root_off,
        &mut visited,
        &mut entries,
        sections,
    )?;
    Ok(entries)
}

/// Expected RT_RCDATA chunk list — byte-for-byte mirror of
/// rsrc_register::chunk_payload (kept local so validate is self-contained).
pub(crate) fn expected_chunks(payload_rva: u32, payload_len: u32) -> Vec<(u32, u32)> {
    let mut chunks = Vec::new();
    let mut off = 0u32;
    let mut remaining = payload_len;
    while remaining > 0 && chunks.len() < MAX_CHUNKS {
        let sz = remaining.min(CHUNK_SIZE);
        chunks.push((payload_rva + off, sz));
        off += sz;
        remaining -= sz;
    }
    if remaining > 0 {
        if let Some(last) = chunks.last_mut() {
            last.1 += remaining;
        }
    }
    chunks
}

pub(crate) fn validate_rsrc(
    ctx: &PipelineContext,
    pe: &PE,
    sections: &[SectionInfo],
    out: &[u8],
) -> Result<()> {
    // a. DataDirectory[2] must point at exactly what we registered.
    let dd = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|oh| oh.data_directories.get_resource_table())
        .ok_or_else(|| anyhow!("resource DataDirectory[2] missing from output"))?;
    if dd.virtual_address != ctx.rsrc_dir_rva || dd.size != ctx.rsrc_dir_size {
        bail!(
            "DataDirectory[2] = 0x{:X}/0x{:X} but packer registered 0x{:X}/0x{:X}",
            dd.virtual_address,
            dd.size,
            ctx.rsrc_dir_rva,
            ctx.rsrc_dir_size
        );
    }
    println!(
        "[VALIDATE] OK  DataDirectory[2] -> RVA 0x{:X} size 0x{:X}",
        dd.virtual_address, dd.size
    );

    // b+c. Tree walk + data-entry section coverage.
    let tree_sec = section_for_rva(sections, ctx.rsrc_dir_rva).ok_or_else(|| {
        anyhow!(
            "resource dir RVA 0x{:X} outside all sections",
            ctx.rsrc_dir_rva
        )
    })?;
    let entries = walk_resource_tree(tree_sec, out, ctx.rsrc_dir_rva, ctx.rsrc_dir_size, sections)?;
    println!(
        "[VALIDATE] OK  resource tree walk: {} data entries in section '{}'",
        entries.len(),
        tree_sec.name
    );

    // d. Every expected RT_RCDATA chunk must be registered.
    let expected = expected_chunks(ctx.payload_rva, ctx.payload_len);
    for (rva, size) in &expected {
        if !entries
            .iter()
            .any(|e| e.offset_rva == *rva && e.size == *size)
        {
            bail!(
                "RT_RCDATA chunk @RVA 0x{:X} size 0x{:X} missing from resource tree",
                rva,
                size
            );
        }
    }
    if !expected.is_empty() {
        println!(
            "[VALIDATE] OK  all {} RT_RCDATA chunk(s) registered in tree",
            expected.len()
        );
    }
    Ok(())
}
