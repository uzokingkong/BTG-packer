// ==============================================================================
// BTG Pipeline - Post-Build Self-Validation (자체검증)
// ==============================================================================
//
// `validate::run` re-parses the synthesized output PE (in memory, right after
// build) and verifies the structural invariants the packer claims to produce.
// Hard failures return Err, so the packer refuses to report success on a
// broken output.
//
// Checks (always):
//   1. Output re-parses as a PE; every section's raw range fits the file.
//   2. Entry point RVA lies inside a section, and that section is executable.
//   3. The packed section `.textb` is present.
//
// Checks (feature-gated):
//   4. `--payload-relocate` (ctx.payload_len > 0): a *non-executable* section
//      covers the whole payload range [payload_rva, payload_rva+payload_len).
//   5. `--rsrc-register` (ctx.rsrc_dir_rva > 0):
//        a. DataDirectory[2] == (rsrc_dir_rva, rsrc_dir_size).
//        b. The resource directory tree walks cleanly (section-relative
//           offsets, bounds-checked, cycle-guarded).
//        c. Every IMAGE_RESOURCE_DATA_ENTRY points into a valid section range.
//        d. Every expected RT_RCDATA payload chunk (rva,size) computed from
//           ctx.payload_* is present among the tree's data entries.
//
// This closes the loop that previously required an *external* byte-dump
// script (whose offset bug once produced a false "tree is empty" result):
// the packer now verifies its own resource directory from inside.
// ==============================================================================

use crate::mba::MbaGenerator;
use crate::pipeline::PipelineContext;
use anyhow::{Result, anyhow, bail};
use goblin::pe::PE;
use std::collections::HashSet;

/// IMAGE_SCN_MEM_EXECUTE (section characteristics)
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// RT_RCDATA resource type id (mirrors rsrc_register.rs)
const RT_RCDATA: u32 = 10;
/// fallback type id when the target already uses type 10 (mirrors rsrc_register.rs)
const ALT_TYPE_ID: u32 = 0x40;
/// per-resource chunk size (mirrors rsrc_register.rs)
const CHUNK_SIZE: u32 = 0x10000;
/// max number of RT_RCDATA resources (mirrors rsrc_register.rs)
const MAX_CHUNKS: usize = 64;

/// One section of the synthesized output, in the form the validator needs.
#[derive(Debug, Clone)]
struct SectionInfo {
    name: String,
    rva: u32,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
    characteristics: u32,
}

impl SectionInfo {
    fn contains_rva(&self, rva: u32) -> bool {
        let end = self.rva.saturating_add(self.virtual_size);
        rva >= self.rva && rva < end
    }

    fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
}

fn collect_sections(pe: &PE) -> Vec<SectionInfo> {
    pe.sections
        .iter()
        .map(|s| SectionInfo {
            name: s.name().unwrap_or("?").to_string(),
            rva: s.virtual_address,
            virtual_size: s.virtual_size,
            raw_ptr: s.pointer_to_raw_data,
            raw_size: s.size_of_raw_data,
            characteristics: s.characteristics,
        })
        .collect()
}

fn section_for_rva<'a>(sections: &'a [SectionInfo], rva: u32) -> Option<&'a SectionInfo> {
    sections.iter().find(|s| s.contains_rva(rva))
}

/// A leaf IMAGE_RESOURCE_DATA_ENTRY found in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResDataEntry {
    offset_rva: u32,
    size: u32,
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
fn walk_dir(
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
            out.push(ResDataEntry { offset_rva: rva, size });
        }
    }
    Ok(())
}

/// Walk the whole resource tree rooted at `dir_rva` (inside `tree_sec`) and
/// return every IMAGE_RESOURCE_DATA_ENTRY found.
fn walk_resource_tree(
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
    walk_dir(sec_bytes, root_off, root_off, &mut visited, &mut entries, sections)?;
    Ok(entries)
}

/// Expected RT_RCDATA chunk list — byte-for-byte mirror of
/// rsrc_register::chunk_payload (kept local so validate is self-contained).
fn expected_chunks(payload_rva: u32, payload_len: u32) -> Vec<(u32, u32)> {
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

fn validate_rsrc(
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
    let tree_sec = section_for_rva(sections, ctx.rsrc_dir_rva)
        .ok_or_else(|| anyhow!("resource dir RVA 0x{:X} outside all sections", ctx.rsrc_dir_rva))?;
    let entries = walk_resource_tree(tree_sec, out, ctx.rsrc_dir_rva, ctx.rsrc_dir_size, sections)?;
    println!(
        "[VALIDATE] OK  resource tree walk: {} data entries in section '{}'",
        entries.len(),
        tree_sec.name
    );

    // d. Every expected RT_RCDATA chunk must be registered.
    let expected = expected_chunks(ctx.payload_rva, ctx.payload_len);
    for (rva, size) in &expected {
        if !entries.iter().any(|e| e.offset_rva == *rva && e.size == *size) {
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

/// Post-build structural self-validation of the synthesized output PE.
pub fn run(ctx: &PipelineContext, out: &[u8]) -> Result<()> {
    let pe = PE::parse(out).map_err(|e| anyhow!("validate: output PE re-parse failed: {e}"))?;
    let sections = collect_sections(&pe);

    println!(
        "\n[VALIDATE] post-build self-check (re-parsed output: {} sections, {} bytes)",
        sections.len(),
        out.len()
    );

    // 1. Every section's raw range must fit inside the file.
    for s in &sections {
        if s.raw_size == 0 {
            continue;
        }
        let raw_end = (s.raw_ptr as usize).saturating_add(s.raw_size as usize);
        if (s.raw_ptr as usize) >= out.len() {
            bail!("section '{}' raw data starts beyond EOF", s.name);
        }
        if raw_end > out.len() {
            bail!(
                "section '{}' raw data [0x{:X},0x{:X}) exceeds file size 0x{:X}",
                s.name,
                s.raw_ptr,
                raw_end,
                out.len()
            );
        }
    }
    println!("[VALIDATE] OK  all section raw ranges within file");

    // 2. Entry point inside an executable section.
    let entry_rva = if (pe.entry as u64) >= pe.image_base as u64 {
        (pe.entry as u64 - pe.image_base as u64) as u32
    } else {
        pe.entry as u32
    };
    let ep_sec = section_for_rva(&sections, entry_rva)
        .ok_or_else(|| anyhow!("entry point RVA 0x{:X} outside all sections", entry_rva))?;
    if !ep_sec.is_executable() {
        bail!("entry point section '{}' is not executable", ep_sec.name);
    }
    println!(
        "[VALIDATE] OK  entry point 0x{:X} in '{}' (executable)",
        entry_rva, ep_sec.name
    );

    // 2b. v5 (안정성): crypto 활성 시 EP가 실제 부트 스텁 프롤로그를 가리키는지 확인.
    //     anti_debug → `mov rax, gs:[0x60]` (65 48 8B 04 25 60 00 00 00),
    //     --vm-oep → `mov rax, imm64` (48 B8 ?? ?? ?? ?? ?? ?? ??) [OEP 레지스터 캡처],
    //     그 외 → `sub rsp, imm32` (48 81 EC ?? ?? ?? ??).
    if ctx.crypto_enabled {
        let ep_local = (entry_rva - ep_sec.rva) as usize;
        let file_off = ep_sec.raw_ptr as usize + ep_local;
        let raw_avail = ep_sec.raw_ptr as usize + ep_sec.raw_size as usize;
        if file_off + 12 <= out.len() && file_off + 12 <= raw_avail {
            let b = &out[file_off..];
            let prologue_ok = if ctx.anti_debug {
                b.len() >= 9 && b[0..9] == [0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]
            } else if ctx.vm_oep {
                // --vm-oep: 부트 스텁 첫 명령이 OEP 캡처 `mov rax, imm64` (48 B8 ..).
                b.len() >= 3 && b[0] == 0x48 && b[1] == 0xB8
            } else {
                b.len() >= 3 && b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xEC
            };
            if !prologue_ok {
                bail!(
                    "entry point bytes 0x{:02X} 0x{:02X} 0x{:02X} ... do not match boot stub prologue",
                    b.first().copied().unwrap_or(0),
                    b.get(1).copied().unwrap_or(0),
                    b.get(2).copied().unwrap_or(0)
                );
            }
            println!("[VALIDATE] OK  boot stub prologue at entry point");
        }
    }

    // 2c. v5 (안정성): crypto 활성 시 .textb는 쓰기 가능이어야 한다 (in-place 복호화).
    if ctx.crypto_enabled {
        let tb = sections
            .iter()
            .rev().find(|s| s.name == ".textb")
            .ok_or_else(|| anyhow!("packed section '.textb' missing from output"))?;
        if tb.characteristics & 0x8000_0000 == 0 {
            bail!("packed section '.textb' missing WRITE (needed for in-place decryption)");
        }
    }

    // 3. `.textb` packed section present.
    if !sections.iter().any(|s| s.name == ".textb") {
        bail!("packed section '.textb' missing from output");
    }
    println!("[VALIDATE] OK  packed section '.textb' present");

    // 3b. v5 (안정성): 원본이 보유한 Import/TLS 디렉터리가 출력에서도 유효한
    //     섹션을 가리키는지 확인 (손실 시 로더 초기화 단계에서 크래시 가능).
    //     v6: --iat-hide면 Import는 더미로 의도적으로 교체되므로 별도 검증.
    if ctx.iat_hide {
        let dd = pe
            .header
            .optional_header
            .as_ref()
            .and_then(|oh| oh.data_directories.get_import_table())
            .ok_or_else(|| anyhow!("dummy import directory missing from output"))?;
        if dd.virtual_address == 0 {
            bail!("dummy import directory zeroed in output");
        }
        let sec = section_for_rva(&sections, dd.virtual_address).ok_or_else(|| {
            anyhow!("dummy import RVA 0x{:X} outside all sections", dd.virtual_address)
        })?;
        println!(
            "[VALIDATE] OK  dummy import dir @0x{:X} in '{}' (LoadLibraryA/GetProcAddress only)",
            dd.virtual_address, sec.name
        );
    }
    for (idx, name) in if ctx.iat_hide { vec![(9usize, "TLS")] } else { vec![(1usize, "Import"), (9, "TLS")] } {
        let orig = ctx
            .target_info
            .data_directories
            .get(idx)
            .copied()
            .unwrap_or(crate::pe::builder::DataDirectory { virtual_address: 0, size: 0 });
        if orig.virtual_address == 0 {
            continue; // 원본에 없으면 검사할 것 없음
        }
        let dd = pe
            .header
            .optional_header
            .as_ref()
            .and_then(|oh| oh.data_directories.data_directories[idx].as_ref().map(|(_, d)| *d))
            .ok_or_else(|| {
                anyhow!(
                    "original {} table @0x{:X} was dropped from output",
                    name,
                    orig.virtual_address
                )
            })?;
        if dd.virtual_address == 0 {
            bail!("original {} table @0x{:X} zeroed in output", name, orig.virtual_address);
        }
        let sec = section_for_rva(&sections, dd.virtual_address).ok_or_else(|| {
            anyhow!("{} table RVA 0x{:X} outside all sections", name, dd.virtual_address)
        })?;
        println!(
            "[VALIDATE] OK  {} table @0x{:X} preserved in '{}'",
            name, dd.virtual_address, sec.name
        );
    }

    // 3c. v8 (Phase 0.3): --dispatcher-reencrypt — 파일의 각 블록이 블록별 MBA
    //     키로 개별 RC4 암호화되어 있고, 길이 테이블이 같은 키로 복호화되면
    //     실제 길이와 일치하는지 검증한다. (패커 암호화 ↔ 디스패처 복호화 동치성)
    if ctx.reencrypt {
        let tb = sections
            .iter()
            .rev().find(|s| s.name == ".textb")
            .ok_or_else(|| anyhow!("packed section '.textb' missing from output"))?;
        let layout = ctx
            .layout()
            .map_err(|e| anyhow!("reencrypt validation needs layout: {e}"))?;
        let num_blocks = layout.shuffled_blocks.len();
        let len_table_off = tb.raw_ptr as usize + ctx.table_offset + num_blocks * 4;
        let mut call_target_count = 0usize;
        for block in &layout.shuffled_blocks {
            let id = block.id;
            let off = layout.table_offsets[id as usize] as usize;
            let len = block.instructions.len();
            let seed = MbaGenerator::seed_for(ctx.mba_constant, id);
            let key = MbaGenerator::compute_key(seed, id, ctx.mba_constant, 2);
            let is_call_target = ctx.call_target_block_ids.contains(&id);
            // 3c-1: 길이 테이블 엔트리
            //   일반 블록:     len_enc ^ key == len
            //   call-target 블록 (v11): len_enc == key → 복호화 길이 0 (센티널)
            let entry_off = len_table_off + (id as usize) * 4;
            if entry_off + 4 > out.len() {
                bail!("Phase 0.3: length table entry for block {} beyond EOF", id);
            }
            let len_enc = u32::from_le_bytes(out[entry_off..entry_off + 4].try_into().unwrap());
            let decoded_len = len_enc ^ key;
            if decoded_len != (if is_call_target {0} else {len as u32}) {
            }
            if is_call_target {
                if decoded_len != 0 {
                    bail!(
                        "Phase 0.3: call-target block {} length sentinel mismatch (decoded 0x{:X}, expected 0)",
                        id,
                        decoded_len
                    );
                }
                call_target_count += 1;
            } else if decoded_len != len as u32 {
                bail!(
                    "Phase 0.3: length table mismatch for block {} (decoded 0x{:X}, expected 0x{:X})",
                    id,
                    decoded_len,
                    len
                );
            }
            // 3c-2: 블록 바이트 검증
            //   일반 블록: per-block 키로 복호화 → 평문 복원
            //   call-target 블록 (v11): **평문 그대로** 저장되어 있어야 한다.
            //       (--payload-relocate 시 평문은 .vdata에 있고 .textb는
            //        0으로 스테이징되므로, .vdata에서 읽어야 한다)
            let file_off = if ctx.payload_len > 0 {
                let vsec = section_for_rva(&sections, ctx.payload_rva).ok_or_else(|| {
                    anyhow!("payload RVA 0x{:X} outside all sections", ctx.payload_rva)
                })?;
                let local = off
                    .checked_sub(ctx.first_block_offset)
                    .ok_or_else(|| anyhow!("block {} offset below code region", id))?;
                vsec.raw_ptr as usize + local
            } else {
                tb.raw_ptr as usize + off
            };
            if file_off + len > out.len() {
                bail!(
                    "Phase 0.3: block {} range [0x{:X},0x{:X}) beyond EOF",
                    id,
                    file_off,
                    file_off + len
                );
            }
            if is_call_target {
                if &out[file_off..file_off + len] != block.instructions.as_slice() {
                    bail!(
                        "Phase 0.3: call-target block {} must be stored plaintext (dispatcher skips crypt)",
                        id
                    );
                }
            } else {
                let mut rc4 = crate::pipeline::crypto::Rc4::new(&key.to_le_bytes());
                let mut dec = out[file_off..file_off + len].to_vec();
                rc4.crypt(&mut dec);
                if dec != block.instructions {
                    bail!(
                        "Phase 0.3: block {} per-block decrypt roundtrip mismatch (dispatcher would execute garbage)",
                        id
                    );
                }
            }
        }
        println!(
            "[VALIDATE] OK  Phase 0.3: {} blocks individually encrypted, length table verified (per-block keys, {} call-target plaintext)",
            num_blocks, call_target_count
        );
    }

    // 4. --payload-relocate: payload fully covered by a non-executable section.
    if ctx.payload_len > 0 {
        let psec = section_for_rva(&sections, ctx.payload_rva)
            .ok_or_else(|| anyhow!("payload RVA 0x{:X} outside all sections", ctx.payload_rva))?;
        let p_end = ctx.payload_rva.saturating_add(ctx.payload_len);
        if p_end <= ctx.payload_rva || !psec.contains_rva(p_end - 1) {
            bail!(
                "payload [0x{:X},0x{:X}) not fully covered by section '{}'",
                ctx.payload_rva,
                p_end,
                psec.name
            );
        }
        if psec.is_executable() {
            bail!("payload section '{}' is executable (must be non-exec data)", psec.name);
        }
        println!(
            "[VALIDATE] OK  payload {} bytes @RVA 0x{:X} in '{}' (non-exec)",
            ctx.payload_len, ctx.payload_rva, psec.name
        );
    }

    // 5. --rsrc-register: full resource directory re-verification.
    if ctx.rsrc_dir_rva > 0 {
        validate_rsrc(ctx, &pe, &sections, out)?;
    }

    println!("[VALIDATE] all structural checks passed ✔");
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// 단위 테스트
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_chunks_basic() {
        // 545 bytes -> single chunk (fits in 0x10000)
        let c = expected_chunks(0x8000, 545);
        assert_eq!(c, vec![(0x8000, 545)]);
    }

    #[test]
    fn test_expected_chunks_split_and_overflow_absorb() {
        // 0x20001 bytes -> 0x10000 + 0x10000 + 1 -> three chunks
        let c = expected_chunks(0x8000, 0x20001);
        assert_eq!(c.len(), 3);
        assert_eq!(c[0], (0x8000, 0x10000));
        assert_eq!(c[1], (0x18000, 0x10000));
        assert_eq!(c[2], (0x28000, 1));
        // zero payload -> no chunks
        assert!(expected_chunks(0x8000, 0).is_empty());
    }

    /// Build a minimal RT_RCDATA resource tree identical in layout to
    /// rsrc_register::build_tree (k = 1 chunk), placed at `base_off` inside a
    /// section. Returns the tree bytes (already section-relative).
    fn build_synthetic_tree(base_off: usize, chunk: (u32, u32)) -> Vec<u8> {
        let k = 1usize;
        // tree-local offsets (base_off added exactly once via `abs`, matching
        // rsrc_register::build_tree — locals are relative to the tree start)
        let type_dir_off = 16 + 8;
        let name_dirs_off = type_dir_off + 16 + k * 8;
        let data_entries_off = name_dirs_off + k * 24;
        // Tree pointers are relative to the tree root (resource base), matching
        // rsrc_register::build_tree — NOT relative to the section start.
        let _ = base_off;
        let abs = |local: usize| local as u32;

        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // NumberOfNamedEntries
        out.extend_from_slice(&1u16.to_le_bytes()); // NumberOfIdEntries
        out.extend_from_slice(&RT_RCDATA.to_le_bytes());
        out.extend_from_slice(&(abs(type_dir_off) | 0x8000_0000).to_le_bytes());

        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(k as u16).to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(abs(name_dirs_off) | 0x8000_0000).to_le_bytes());

        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // lang id
        out.extend_from_slice(&abs(data_entries_off).to_le_bytes());

        out.extend_from_slice(&chunk.0.to_le_bytes());
        out.extend_from_slice(&chunk.1.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    #[test]
    fn test_walk_resource_tree_synthetic() {
        // payload section: RVA 0x8000, virtual 0x100, raw at file 0x200
        let payload_sec = SectionInfo {
            name: ".vdata".to_string(),
            rva: 0x8000,
            virtual_size: 0x100,
            raw_ptr: 0x200,
            raw_size: 0x100,
            characteristics: 0x4000_0040,
        };
        // resource section: RVA 0x9000, virtual 0x200, raw at file 0x300
        let rsrc_sec = SectionInfo {
            name: ".rsrc".to_string(),
            rva: 0x9000,
            virtual_size: 0x200,
            raw_ptr: 0x300,
            raw_size: 0x200,
            characteristics: 0x4000_0040,
        };
        let sections = vec![payload_sec, rsrc_sec.clone()];

        // tree at base_off 0x40 of the .rsrc section (file 0x340, section off 0x40);
        // chunk = payload 0x40 bytes. dir_rva = 0x9000 + 0x40.
        let tree = build_synthetic_tree(0x40, (0x8000, 0x40));
        assert_eq!(tree.len(), 0x58);

        // compose a fake file: [..0x340 = zeroes][tree][..]
        let mut file = vec![0u8; 0x500];
        file[0x340..0x340 + tree.len()].copy_from_slice(&tree);

        let entries = walk_resource_tree(&rsrc_sec, &file, 0x9000 + 0x40, 0x58, &sections).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], ResDataEntry { offset_rva: 0x8000, size: 0x40 });
    }

    #[test]
    fn test_walk_resource_tree_rejects_oob_entry() {
        let rsrc_sec = SectionInfo {
            name: ".rsrc".to_string(),
            rva: 0x9000,
            virtual_size: 0x200,
            raw_ptr: 0x300,
            raw_size: 0x200,
            characteristics: 0x4000_0040,
        };
        let payload_sec = SectionInfo {
            name: ".vdata".to_string(),
            rva: 0x8000,
            virtual_size: 0x100,
            raw_ptr: 0x200,
            raw_size: 0x100,
            characteristics: 0x4000_0040,
        };
        let sections = vec![payload_sec, rsrc_sec.clone()];

        // Corrupt tree: data entry points at RVA 0x7000 (outside any section).
        // Data entry sits at tree-relative 0x48 (section offset 0x88).
        let mut tree = build_synthetic_tree(0x40, (0x8000, 0x40));
        tree[0x48..0x4C].copy_from_slice(&0x7000u32.to_le_bytes());

        let mut file = vec![0u8; 0x500];
        file[0x340..0x340 + tree.len()].copy_from_slice(&tree);

        let res = walk_resource_tree(&rsrc_sec, &file, 0x9000 + 0x40, 0x58, &sections);
        assert!(res.is_err(), "data entry outside all sections must fail validation");
    }
}
