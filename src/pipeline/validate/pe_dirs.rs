// ==============================================================================
// BTG - post-build data-directory CONTENT re-parsing validation (상용 1-4)
// ==============================================================================
// `validate_pe_structure` (pe.rs) only checks each data directory's RVA/size
// against section virtual/raw bounds. This module goes one level deeper: for
// every directory that is present in the output PE it re-parses the *contents*
// (export/import/exception/reloc/debug/TLS/load-config tables) and verifies the
// internal pointers, counts, terminators and plausibility. Any malformed content
// bails (Err) so the packer refuses to ship a broken output.
//
// Also contains the original<->protected PE structural diff report: it re-parses
// the ORIGINAL input bytes (`ctx.target_info.original_pe_bytes`) with goblin and
// prints a per-directory `orig RVA/size -> protected RVA/size` table plus
// section-count/entry/alignment changes, flagging any directory that existed in
// the original but is missing (0) in the output EXCEPT the ones the packer
// intentionally strips (idx 4 Security; idx 5 BaseReloc when ASLR is stripped).
// It must NOT fail on those intentional differences, but SHOULD Err if an
// originally-present non-stripped directory is missing in the output.
// ==============================================================================

use super::{SectionInfo, section_for_rva};
use crate::pipeline::PipelineContext;
use anyhow::{Result, anyhow, bail};
use goblin::pe::PE;

/// 16 data-directory names (PE spec order).
const DIR_NAMES: [&str; 16] = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Security",
    "BaseReloc",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLS",
    "LoadConfig",
    "BoundImport",
    "IAT",
    "DelayImport",
    "COM_DESCRIPTOR",
    "Reserved",
];

// ──────────────────────────────────────────────────────────────────────────────
// RVA -> raw file offset mapping (bounds-checked against `out` and the owning
// section's raw range).
// ──────────────────────────────────────────────────────────────────────────────

/// Read `n` bytes at `rva` from `out`, mapping the RVA to a raw file offset via
/// `SectionInfo` and verifying the whole range is file-backed and inside the
/// owning section's raw data.
fn raw_at<'a>(out: &'a [u8], sections: &[SectionInfo], rva: u32, n: usize) -> Result<&'a [u8]> {
    let sec = section_for_rva(sections, rva)
        .ok_or_else(|| anyhow!("dir content RVA 0x{rva:X} outside all sections"))?;
    let local = rva
        .checked_sub(sec.rva)
        .ok_or_else(|| anyhow!("dir content RVA 0x{rva:X} below section '{}' start", sec.name))? as usize;
    if sec.raw_size == 0 {
        bail!(
            "dir content @RVA 0x{rva:X} in section '{}' has no file-backed raw data",
            sec.name
        );
    }
    if local + n > sec.raw_size as usize {
        bail!(
            "dir content @RVA 0x{rva:X} + {n} exceeds section '{}' raw data (0x{:X})",
            sec.name,
            sec.raw_size
        );
    }
    let start = sec.raw_ptr as usize + local;
    let end = start + n;
    if end > out.len() {
        bail!("dir content @RVA 0x{rva:X} + {n} beyond EOF");
    }
    Ok(&out[start..end])
}

fn u16at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-directory content parsers
// ──────────────────────────────────────────────────────────────────────────────

/// idx 0 — Export: IMAGE_EXPORT_DIRECTORY (40 B).
fn val_export(out: &[u8], sections: &[SectionInfo], rva: u32, size: u32) -> Result<()> {
    if size < 40 {
        bail!("Export: directory size 0x{size:X} < 40");
    }
    let b = raw_at(out, sections, rva, 40)?;
    let name = u32at(b, 12);
    let nfunc = u32at(b, 20);
    let nnames = u32at(b, 24);
    let addrf = u32at(b, 28);
    let addrn = u32at(b, 32);
    let addrono = u32at(b, 36);

    let _ = section_for_rva(sections, name)
        .ok_or_else(|| anyhow!("Export: Name RVA 0x{name:X} outside all sections"))?;
    // AddressOfFunctions: N * u32 entries (N = NumberOfFunctions)
    if addrf != 0 {
        let nbytes = (nfunc as usize)
            .checked_mul(4)
            .ok_or_else(|| anyhow!("Export: AddressOfFunctions size overflow"))?;
        raw_at(out, sections, addrf, nbytes)?;
    } else if nfunc != 0 {
        bail!("Export: AddressOfFunctions 0 but NumberOfFunctions {nfunc}");
    }
    // AddressOfNames: NumberOfNames * u32 entries
    if addrn != 0 {
        let nbytes = (nnames as usize)
            .checked_mul(4)
            .ok_or_else(|| anyhow!("Export: AddressOfNames size overflow"))?;
        raw_at(out, sections, addrn, nbytes)?;
    } else if nnames != 0 {
        bail!("Export: AddressOfNames 0 but NumberOfNames {nnames}");
    }
    // AddressOfNameOrdinals: NumberOfNames * u16 entries
    if addrono != 0 {
        let nbytes = (nnames as usize)
            .checked_mul(2)
            .ok_or_else(|| anyhow!("Export: AddressOfNameOrdinals size overflow"))?;
        raw_at(out, sections, addrono, nbytes)?;
    }
    // Ordinals must be < NumberOfFunctions
    if addrono != 0 && nnames != 0 {
        let ord = raw_at(out, sections, addrono, (nnames as usize) * 2)?;
        for i in 0..nnames as usize {
            let o = u16at(ord, i * 2) as u32;
            if o >= nfunc {
                bail!("Export: name ordinal {o} >= NumberOfFunctions {nfunc}");
            }
        }
    }
    println!(
        "[VALIDATE] OK  Export: {nfunc} functions / {nnames} names (Name RVA 0x{name:X})"
    );
    Ok(())
}

/// idx 1 — Import: walk IMAGE_IMPORT_DESCRIPTOR (20 B) array to all-zero
/// terminator (capped against runaway and dir size).
fn val_import(out: &[u8], sections: &[SectionInfo], rva: u32, size: u32) -> Result<()> {
    const DESC: usize = 20;
    const MAX_DESCS: usize = 0x1000;
    let max_descs = ((size as usize / DESC) + 1).min(MAX_DESCS + 1); // +1 for terminator
    let mut dlls = 0usize;
    for i in 0..max_descs {
        let off = (i as u32)
            .checked_mul(DESC as u32)
            .and_then(|v| rva.checked_add(v))
            .ok_or_else(|| anyhow!("Import: descriptor offset overflow"))?;
        let b = raw_at(out, sections, off, DESC)?;
        let oft = u32at(b, 0);
        let _ts = u32at(b, 4);
        let name = u32at(b, 12);
        let first = u32at(b, 16);
        if oft == 0 && name == 0 && first == 0 {
            break; // all-zero terminator
        }
        if i + 1 >= max_descs {
            bail!("Import: descriptor array has no all-zero terminator within dir size 0x{size:X}");
        }
        // DLL name RVA must land in a section
        let _ = section_for_rva(sections, name)
            .ok_or_else(|| anyhow!("Import: DLL #{dlls} Name RVA 0x{name:X} outside all sections"))?;
        // thunk array: OriginalFirstThunk, else FirstThunk; must terminate with 0.
        let thunk = if oft != 0 { oft } else { first };
        let _ = section_for_rva(sections, thunk)
            .ok_or_else(|| anyhow!("Import: DLL #{dlls} thunk RVA 0x{thunk:X} outside all sections"))?;
        let mut thunks = 0u32;
        loop {
            if thunks >= 0x10000 {
                bail!("Import: DLL #{dlls} thunk array has no 0 terminator (runaway)");
            }
            let trva = thunk
                .checked_add(thunks.wrapping_mul(8))
                .ok_or_else(|| anyhow!("Import: thunk offset overflow"))?;
            let tb = raw_at(out, sections, trva, 8)?;
            let entry = u64at(tb, 0);
            if entry == 0 {
                break;
            }
            // Plausibility: ordinal (bit63 set) or VA. Any nonzero is accepted
            // here; exact import resolution is the loader's job.
            if entry == u64::MAX {
                bail!("Import: DLL #{dlls} thunk entry 0xFFFFFFFFFFFFFFFF implausible");
            }
            thunks += 1;
        }
        dlls += 1;
    }
    if dlls == 0 {
        // An import directory that is present but has zero DLLs and no
        // terminator right away is malformed.
        bail!("Import: directory present but no IMAGE_IMPORT_DESCRIPTOR found");
    }
    println!("[VALIDATE] OK  Import: {dlls} DLL(s), descriptors + thunk arrays terminated");
    Ok(())
}

/// idx 3 — Exception: IMAGE_RUNTIME_FUNCTION_ENTRY (12 B each).
fn val_exception(out: &[u8], sections: &[SectionInfo], rva: u32, size: u32) -> Result<()> {
    let n = size as usize / 12;
    for i in 0..n {
        let b = raw_at(out, sections, rva + (i as u32) * 12, 12)?;
        let begin = u32at(b, 0);
        let end = u32at(b, 4);
        if begin >= end {
            bail!("Exception: RUNTIME_FUNCTION[{i}] begin 0x{begin:X} >= end 0x{end:X}");
        }
        let _ = section_for_rva(sections, begin)
            .ok_or_else(|| anyhow!("Exception: RUNTIME_FUNCTION[{i}] begin 0x{begin:X} outside all sections"))?;
        // end may sit exactly on a section's virtual end; allow that.
        let in_sec = section_for_rva(sections, end).is_some()
            || section_for_rva(sections, begin)
                .map(|s| end == s.rva.saturating_add(s.virtual_size))
                .unwrap_or(false);
        if !in_sec {
            bail!("Exception: RUNTIME_FUNCTION[{i}] end 0x{end:X} outside all sections");
        }
    }
    println!("[VALIDATE] OK  Exception: {n} RUNTIME_FUNCTION entries (begin<end, in-section)");
    Ok(())
}

/// idx 5 — Reloc: walk IMAGE_BASE_RELOCATION blocks.
fn val_reloc(out: &[u8], sections: &[SectionInfo], rva: u32, size: u32) -> Result<()> {
    let mut off = 0u32;
    let mut blocks = 0u32;
    loop {
        if off + 8 > size {
            if off == size {
                break;
            }
            bail!("Reloc: trailing {size} bytes with no full block header");
        }
        let b = raw_at(out, sections, rva + off, 8)?;
        let page = u32at(b, 0);
        let bsize = u32at(b, 4);
        if page == 0 && bsize == 0 {
            break; // end-of-table terminator
        }
        if bsize < 8 || bsize % 2 != 0 {
            bail!("Reloc: BlockSize 0x{bsize:X} invalid (<8 or odd)");
        }
        if bsize > size - off {
            bail!("Reloc: block size 0x{bsize:X} exceeds dir size");
        }
        let _ = section_for_rva(sections, page)
            .ok_or_else(|| anyhow!("Reloc: PageRVA 0x{page:X} outside all sections"))?;
        let entries = (bsize - 8) / 2;
        for e in 0..entries {
            let eb = raw_at(out, sections, rva + off + 8 + e * 2, 2)?;
            let v = u16at(eb, 0);
            let ty = v >> 12;
            if ty > 0xA {
                bail!("Reloc: block entry type {ty} > 0xA");
            }
        }
        off += bsize;
        blocks += 1;
        if blocks > 0x10000 {
            bail!("Reloc: runaway (>{0x10000} blocks)");
        }
    }
    println!("[VALIDATE] OK  Reloc: {blocks} base-reloc block(s) (PageRVA in-section, entry types <= 0xA)");
    Ok(())
}

/// idx 6 — Debug: IMAGE_DEBUG_DIRECTORY (28 B each).
fn val_debug(out: &[u8], sections: &[SectionInfo], rva: u32, size: u32) -> Result<()> {
    const KNOWN: [u32; 14] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16];
    let n = size as usize / 28;
    for i in 0..n {
        let b = raw_at(out, sections, rva + (i as u32) * 28, 28)?;
        let ty = u32at(b, 12);
        if !KNOWN.contains(&ty) {
            bail!("Debug: entry[{i}] unknown Type {ty}");
        }
        let size_of_data = u32at(b, 16);
        let ptr_raw = u32at(b, 24);
        if ptr_raw != 0 && size_of_data != 0 {
            let end = (ptr_raw as usize)
                .checked_add(size_of_data as usize)
                .ok_or_else(|| anyhow!("Debug: entry[{i}] raw range overflow"))?;
            if end > out.len() {
                bail!("Debug: entry[{i}] raw [0x{ptr_raw:X},0x{end:X}) exceeds file 0x{:X}", out.len());
            }
        }
    }
    println!("[VALIDATE] OK  Debug: {n} IMAGE_DEBUG_DIRECTORY entrie(s) (known type, raw in file)");
    Ok(())
}

/// idx 9 — TLS: IMAGE_TLS_DIRECTORY (40 B for 64-bit).
fn val_tls(out: &[u8], sections: &[SectionInfo], image_base: u64, rva: u32, size: u32) -> Result<()> {
    if size < 40 {
        bail!("TLS: directory size 0x{size:X} < 40");
    }
    let b = raw_at(out, sections, rva, 40)?;
    let start = u64at(b, 0);
    let end = u64at(b, 8);
    let idx = u64at(b, 16);
    let cbs = u64at(b, 24);

    for (name, v) in [
        ("StartAddressOfRawData", start),
        ("EndAddressOfRawData", end),
        ("AddressOfIndex", idx),
        ("AddressOfCallBacks", cbs),
    ] {
        if v == 0 {
            continue;
        }
        if v < image_base || v.saturating_sub(image_base) > 0x1_0000_0000 {
            bail!("TLS: {name} VA 0x{v:X} outside image (base 0x{image_base:X})");
        }
    }
    if start != 0 && end != 0 && end <= start {
        bail!("TLS: EndAddressOfRawData 0x{end:X} <= StartAddressOfRawData 0x{start:X}");
    }
    // callbacks array: VAs terminated by 0
    if cbs != 0 {
        let cb_rva = (cbs - image_base) as u32;
        for t in 0..0x1000u32 {
            let tb = raw_at(out, sections, cb_rva + t * 8, 8)?;
            let v = u64at(tb, 0);
            if v == 0 {
                break;
            }
            if t == 0xFFF {
                bail!("TLS: callbacks array has no 0 terminator");
            }
            if v < image_base || v.saturating_sub(image_base) > 0x1_0000_0000 {
                bail!("TLS: callback VA 0x{v:X} outside image");
            }
        }
    }
    println!("[VALIDATE] OK  TLS: 64-bit directory valid (start/end/index/callbacks in image)");
    Ok(())
}

/// idx 10 — LoadConfig: IMAGE_LOAD_CONFIG_DIRECTORY64.
fn val_load_config(
    out: &[u8],
    sections: &[SectionInfo],
    image_base: u64,
    rva: u32,
    size: u32,
) -> Result<()> {
    if size < 0x60 {
        bail!("LoadConfig: directory size 0x{size:X} < 0x60");
    }
    let hdr = raw_at(out, sections, rva, 4)?;
    let size_field = u32at(hdr, 0) as usize;
    if size_field < 0x60 {
        bail!("LoadConfig: Size field 0x{size_field:X} < 0x60");
    }
    if size_field as u32 > size {
        bail!("LoadConfig: Size field 0x{size_field:X} > directory size 0x{size:X}");
    }
    let readable = size_field.min(size as usize);

    // SecurityCookie @ 0x5C (needs 0x60 bytes)
    let cookie = u64at(raw_at(out, sections, rva, readable.min(0x60))?, 0x5C);
    if cookie != 0 && (cookie < image_base || cookie.saturating_sub(image_base) > 0x1_0000_0000) {
        bail!("LoadConfig: SecurityCookie VA 0x{cookie:X} outside image");
    }
    // GuardCF fields @ 0x70/0x80/0x88 (needs 0x90 bytes)
    if readable >= 0x90 {
        let guard_check = u64at(raw_at(out, sections, rva, 0x90)?, 0x70);
        let guard_table = u64at(raw_at(out, sections, rva, 0x90)?, 0x80);
        let guard_count = u32at(raw_at(out, sections, rva, 0x90)?, 0x88);
        for (name, v) in [
            ("GuardCFCheckFunctionPointer", guard_check),
            ("GuardCFFunctionTable", guard_table),
        ] {
            if v != 0 && (v < image_base || v.saturating_sub(image_base) > 0x1_0000_0000) {
                bail!("LoadConfig: {name} VA 0x{v:X} outside image");
            }
        }
        if guard_table != 0 {
            let table_rva = (guard_table - image_base) as u32;
            let nbytes = (guard_count as usize)
                .checked_mul(4)
                .ok_or_else(|| anyhow!("LoadConfig: GuardCFFunctionTable size overflow"))?;
            raw_at(out, sections, table_rva, nbytes)?;
        } else if guard_count != 0 {
            bail!(
                "LoadConfig: GuardCFFunctionTable 0 but GuardCFFunctionCount {guard_count}"
            );
        }
    }
    println!(
        "[VALIDATE] OK  LoadConfig: Size 0x{size_field:X} >= 0x60, cookie/guard CFG pointers valid"
    );
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Entry point: iterate the 16 directories and re-parse each present one.
// ──────────────────────────────────────────────────────────────────────────────

/// `dirs` is a 16-length `(virtual_address, size)` slice (one per data-directory
/// index). Returns the number of directories actually content-parsed.
pub(crate) fn validate_data_directories(
    out: &[u8],
    image_base: u64,
    dirs: &[(u32, u32)],
    sections: &[SectionInfo],
) -> Result<usize> {
    let mut parsed = 0usize;
    for (i, &(rva, size)) in dirs.iter().enumerate() {
        if rva == 0 {
            continue; // not present
        }
        match i {
            0 => val_export(out, sections, rva, size)?,
            1 => val_import(out, sections, rva, size)?,
            3 => val_exception(out, sections, rva, size)?,
            5 => val_reloc(out, sections, rva, size)?,
            6 => val_debug(out, sections, rva, size)?,
            9 => val_tls(out, sections, image_base, rva, size)?,
            10 => val_load_config(out, sections, image_base, rva, size)?,
            // 2 Resource: deep-validated in rsrc.rs when --rsrc-register; skip here.
            // 4 Security / 5 Reloc(policy) / 12 IAT / 13 DelayImport / 0/1/3/6/9/10 handled.
            _ => {
                // Any other present directory must already have had its RVA
                // section-membership enforced by validate_pe_structure. Report it.
                let _ = section_for_rva(sections, rva).ok_or_else(|| {
                    anyhow!(
                        "data directory[{}] ({}) RVA 0x{rva:X} outside all sections",
                        i,
                        DIR_NAMES[i]
                    )
                })?;
                println!(
                    "[VALIDATE] OK  {} dir @RVA 0x{rva:X} (generic; RVA in section)",
                    DIR_NAMES[i]
                );
            }
        }
        parsed += 1;
    }
    println!("[VALIDATE] OK  data-directory content re-parse: {parsed}/16 directories validated");
    Ok(parsed)
}

// ──────────────────────────────────────────────────────────────────────────────
// Original <-> protected structural diff
// ──────────────────────────────────────────────────────────────────────────────

/// Re-parse the ORIGINAL input PE bytes and print a per-directory diff against
/// the protected output, plus section-count/entry/alignment changes. Fails only
/// when an originally-present directory that is NOT intentionally stripped
/// (Security idx 4, BaseReloc idx 5) is missing from the output.
pub(crate) fn diff_orig_protected(
    pe: &PE,
    sections: &[SectionInfo],
    ctx: &PipelineContext,
) -> Result<()> {
    let orig_pe = PE::parse(&ctx.target_info.original_pe_bytes)
        .map_err(|e| anyhow!("diff: original PE re-parse failed: {e}"))?;
    let orig_oh = orig_pe
        .header
        .optional_header
        .as_ref()
        .ok_or_else(|| anyhow!("diff: original PE has no optional header"))?;
    let prot_oh = pe
        .header
        .optional_header
        .as_ref()
        .ok_or_else(|| anyhow!("diff: protected PE has no optional header"))?;

    println!(
        "[VALIDATE] diff  sections: orig {} -> protected {}",
        orig_pe.sections.len(),
        sections.len()
    );
    println!(
        "[VALIDATE] diff  entry RVA: orig 0x{:X} -> protected 0x{:X}",
        orig_pe.entry, pe.entry
    );
    println!(
        "[VALIDATE] diff  image base: 0x{:X} -> 0x{:X}",
        orig_pe.image_base, pe.image_base
    );
    println!(
        "[VALIDATE] diff  section alignment: 0x{:X} -> 0x{:X}",
        orig_oh.windows_fields.section_alignment,
        prot_oh.windows_fields.section_alignment
    );
    println!(
        "[VALIDATE] diff  file alignment: 0x{:X} -> 0x{:X}",
        orig_oh.windows_fields.file_alignment,
        prot_oh.windows_fields.file_alignment
    );

    let mut missing = Vec::new();
    for i in 0..16 {
        let orig_dd = orig_oh.data_directories.data_directories[i]
            .as_ref()
            .map(|(_, d)| (d.virtual_address, d.size))
            .unwrap_or((0, 0));
        let prot_dd = prot_oh.data_directories.data_directories[i]
            .as_ref()
            .map(|(_, d)| (d.virtual_address, d.size))
            .unwrap_or((0, 0));
        if orig_dd == (0, 0) && prot_dd == (0, 0) {
            continue;
        }
        println!(
            "[VALIDATE] diff  {:<12} orig RVA 0x{:08X}/0x{:X} -> protected RVA 0x{:08X}/0x{:X}",
            DIR_NAMES[i], orig_dd.0, orig_dd.1, prot_dd.0, prot_dd.1
        );
        // Directory existed in original but is missing (0) in output.
        if orig_dd.0 != 0 && prot_dd.0 == 0 {
            let intentional = matches!(i, 4 | 5); // Security / BaseReloc (ASLR stripped)
            if !intentional {
                missing.push((i, DIR_NAMES[i], orig_dd.0));
            }
        }
    }

    if !missing.is_empty() {
        let list = missing
            .iter()
            .map(|(i, n, r)| format!("[{}]({n}) @0x{r:X}"))
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "diff: originally-present non-stripped data director{} missing from protected output: {}",
            if missing.len() == 1 { "y" } else { "ies" },
            list
        );
    }
    println!(
        "[VALIDATE] OK  orig<->protected diff clean (import/TLS preserved; security idx4/reloc idx5 stripped as policy)"
    );
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::validate::SectionInfo;

    fn sec(name: &str, rva: u32, vsize: u32, raw: u32, rsize: u32) -> SectionInfo {
        SectionInfo {
            name: name.into(),
            rva,
            virtual_size: vsize,
            raw_ptr: raw,
            raw_size: rsize,
            characteristics: 0x40000040,
        }
    }

    /// Build a synthetic file + sections: `.text` @RVA 0x1000 (raw 0x200),
    /// `.rdata` @RVA 0x2000 (raw 0x400). `place` returns (file_len, section list).
    fn synth() -> (Vec<u8>, Vec<SectionInfo>) {
        let mut file = vec![0u8; 0x800];
        let sections = vec![
            sec(".text", 0x1000, 0x1000, 0x200, 0x1000),
            sec(".rdata", 0x2000, 0x1000, 0x400, 0x1000),
        ];
        (file, sections)
    }

    /// Malformed import: a single descriptor with a Name RVA outside all
    /// sections must be rejected by content re-parsing.
    #[test]
    fn malformed_import_bad_name_rva_fails() {
        let (mut file, sections) = synth();
        // One IMAGE_IMPORT_DESCRIPTOR at RVA 0x2000 (file 0x400):
        // OFT=0, TimeDateStamp=0, ForwarderChain=0, Name=0x9999 (out of section),
        // FirstThunk=0.
        let d = 0x2000u32;
        let off = 0x400usize;
        let mut desc = [0u8; 20];
        desc[12..16].copy_from_slice(&0x9999u32.to_le_bytes());
        file[off..off + 20].copy_from_slice(&desc);
        let mut dirs = [(0u32, 0u32); 16];
        dirs[1] = (d, 0x100);
        let e = validate_data_directories(&file, 0x140000000, &dirs, &sections).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("Name RVA 0x9999 outside all sections"),
            "expected bad Name RVA error, got: {msg}"
        );
    }

    /// Export with AddressOfFunctions pointing outside all sections must fail.
    #[test]
    fn export_oob_address_of_functions_fails() {
        let (mut file, sections) = synth();
        // IMAGE_EXPORT_DIRECTORY at RVA 0x2000 (file 0x400): 40 bytes.
        let off = 0x400usize;
        // offset 12: Name RVA = 0x1000 (.text) — valid.
        file[off + 12..off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        // offset 20: NumberOfFunctions = 4
        file[off + 20..off + 24].copy_from_slice(&4u32.to_le_bytes());
        // offset 24: NumberOfNames = 0
        // offset 28: AddressOfFunctions = 0x9000 (outside all sections)
        file[off + 28..off + 32].copy_from_slice(&0x9000u32.to_le_bytes());
        let mut dirs = [(0u32, 0u32); 16];
        dirs[0] = (0x2000, 0x100);
        let e = validate_data_directories(&file, 0x140000000, &dirs, &sections).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("outside all sections"),
            "expected OOB AddressOfFunctions error, got: {msg}"
        );
    }

    /// A well-formed export (functions table in .text) must pass.
    #[test]
    fn valid_export_passes() {
        let (mut file, sections) = synth();
        let off = 0x400usize;
        file[off + 12..off + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // Name
        file[off + 20..off + 24].copy_from_slice(&2u32.to_le_bytes()); // NumberOfFunctions
        file[off + 24..off + 28].copy_from_slice(&1u32.to_le_bytes()); // NumberOfNames
        file[off + 28..off + 32].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfFunctions
        file[off + 32..off + 36].copy_from_slice(&0x1010u32.to_le_bytes()); // AddressOfNames
        file[off + 36..off + 40].copy_from_slice(&0x1020u32.to_le_bytes()); // AddressOfNameOrdinals
        file[0x200..0x20C].copy_from_slice(&[0u8; 12]); // 2 funcs *4 + slack (raw)
        let mut dirs = [(0u32, 0u32); 16];
        dirs[0] = (0x2000, 0x100);
        validate_data_directories(&file, 0x140000000, &dirs, &sections).unwrap();
    }

    /// An import table that is terminated immediately (no DLLs) is present but
    /// must be rejected as malformed (no descriptors found).
    #[test]
    fn import_present_but_empty_fails() {
        let (file, sections) = synth();
        let mut dirs = [(0u32, 0u32); 16];
        dirs[1] = (0x2000, 0x100); // content is all zero at file 0x400
        let e = validate_data_directories(&file, 0x140000000, &dirs, &sections).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("no IMAGE_IMPORT_DESCRIPTOR"),
            "expected empty-import error, got: {msg}"
        );
    }
}
