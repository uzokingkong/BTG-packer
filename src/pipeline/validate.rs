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

use crate::crypto::{BlockCryptoMeta, CryptoProvider, RegionCipherProvider};
use crate::mba::MbaGenerator;
use crate::pipeline::PipelineContext;
use anyhow::{anyhow, bail, Result};
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

/// Decrypt one dispatcher block exactly as the production consumer does.
///
/// The legacy length-table mask remains the 32-bit MBA value because it is a
/// compact metadata sentinel, not cipher key material.  Payload bytes use the
/// 44-byte BTG-RC1 provider ABI (`key[32] || nonce[12]`).  The independently
/// deployed BTG-C1 dispatcher remains supported while that production mode is
/// active; importantly, there is no RC4 validation fallback here.
fn decrypt_dispatcher_block(
    mba_constant: u32,
    custom_cipher: bool,
    id: u32,
    offset: u64,
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    let mut plain = encrypted.to_vec();
    let meta = BlockCryptoMeta::new(id, offset, plain.len() as u32);
    if custom_cipher {
        let seed = MbaGenerator::seed_for(mba_constant, id);
        let key = MbaGenerator::compute_key(seed, id, mba_constant, 2);
        let key32 = crate::pipeline::crypto::cipher::repeat4(key);
        let mut provider = crate::crypto::BtgCipher::new(&key32, 0);
        provider
            .decrypt_block(&meta, &mut plain)
            .map_err(|e| anyhow!("BTG-C1 block {id} validation failed: {e}"))?;
    } else {
        let material = RegionCipherProvider::derive_block_key(&mba_constant.to_le_bytes(), &meta);
        if material.len() != 44 {
            bail!(
                "BTG-RC1 block {id} provider ABI drift: {} bytes, expected 44",
                material.len()
            );
        }
        let mut provider = RegionCipherProvider::from_key(&material);
        provider
            .decrypt_block(&meta, &mut plain)
            .map_err(|e| anyhow!("BTG-RC1 block {id} validation failed: {e}"))?;
    }
    Ok(plain)
}
/// max number of RT_RCDATA resources (mirrors rsrc_register.rs)
const MAX_CHUNKS: usize = 64;

/// One section of the synthesized output, in the form the validator needs.
#[derive(Debug, Clone)]
pub(crate) struct SectionInfo {
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

fn validate_route_metadata(
    ctx: &PipelineContext,
    out: &[u8],
    sections: &[SectionInfo],
) -> Result<()> {
    validate_route_metadata_inventory(
        ctx.route_metadata_section_data
            .as_ref()
            .map(|metadata| metadata.bytes.as_slice()),
        &ctx.route_required_original_targets,
        &ctx.route_generated_destinations,
        &ctx.route_generated_executable_ranges,
        out,
        sections,
    )
}

fn validate_route_metadata_inventory(
    staged_bytes: Option<&[u8]>,
    required_original_targets: &[crate::vm::route_table::OriginalTargetRva],
    generated_destinations: &[crate::vm::route_metadata::GeneratedRouteDestination],
    generated_executable_ranges: &[crate::vm::route_metadata::RvaSpan],
    out: &[u8],
    sections: &[SectionInfo],
) -> Result<()> {
    let placed = sections.iter().find(|section| section.name == ".vmroute");
    if staged_bytes.is_none() {
        if placed.is_some()
            || !required_original_targets.is_empty()
            || !generated_destinations.is_empty()
            || !generated_executable_ranges.is_empty()
        {
            bail!("VM route metadata placement/inventory exists without staged metadata");
        }
        return Ok(());
    }
    let section =
        placed.ok_or_else(|| anyhow!("staged VM route metadata is absent from final PE"))?;
    let start = section.raw_ptr as usize;
    let staged_bytes = staged_bytes.unwrap_or_default();
    let staged_len = staged_bytes.len();
    let end = start
        .checked_add(staged_len)
        .ok_or_else(|| anyhow!("VM route metadata raw range overflow"))?;
    if staged_len == 0 || end > out.len() || staged_len > section.raw_size as usize {
        bail!("VM route metadata bytes are absent or truncated in final PE");
    }
    if required_original_targets.is_empty()
        || generated_destinations.is_empty()
        || generated_executable_ranges.is_empty()
    {
        bail!("VM route metadata authoritative placement inventory is incomplete");
    }
    if section.characteristics & crate::vm::route_metadata::IMAGE_SCN_MEM_READ == 0
        || section.characteristics & crate::vm::route_metadata::IMAGE_SCN_MEM_EXECUTE != 0
        || section.characteristics & crate::vm::route_metadata::IMAGE_SCN_MEM_WRITE != 0
    {
        bail!("sealed VM route commitment must be read-only and non-executable");
    }
    if out[start..end] != *staged_bytes {
        bail!("sealed VM route commitment differs from staged bytes");
    }
    if staged_len != 32 || staged_bytes.starts_with(b"VMROUTE\0") {
        bail!("VM route records were not replaced by an opaque commitment");
    }
    let required: std::collections::BTreeSet<_> =
        required_original_targets.iter().copied().collect();
    let mut destinations = std::collections::BTreeMap::new();
    for destination in generated_destinations {
        if !required.contains(&destination.original)
            || destinations
                .insert(destination.original, destination.destination_rva)
                .is_some()
        {
            bail!("VM route generated-destination inventory is inconsistent");
        }
    }
    if destinations.len() != required.len() {
        bail!("VM route generated-destination inventory is incomplete");
    }
    for destination_rva in destinations.values() {
        if !generated_executable_ranges.iter().any(|range| {
            range.start < range.end
                && *destination_rva >= range.start
                && *destination_rva < range.end
        }) {
            bail!("VM route generated destination is not executable");
        }
    }
    Ok(())
}

pub(crate) fn section_for_rva<'a>(
    sections: &'a [SectionInfo],
    rva: u32,
) -> Option<&'a SectionInfo> {
    sections.iter().find(|s| s.contains_rva(rva))
}

mod dirs;
mod pe;
mod rsrc;
#[cfg(test)]
mod tests;

pub(crate) use crate::pipeline::ownership::{
    check_ownership, render_csv, FunctionOwnership, OwnershipReport, RuntimeFunction,
};
pub(crate) use dirs::{report_pe_diff, validate_all_directories};
pub(crate) use pe::validate_pe_structure;
pub(crate) use rsrc::{expected_chunks, validate_rsrc, walk_dir, walk_resource_tree, ResDataEntry};

/// Materialized protection facts derived from the final PE and pipeline state.
/// This deliberately lives after policy resolution: a requested/resolved flag
/// is not considered effective until its output invariant is observable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveProfileReport {
    pub effective_features: Vec<String>,
    pub ineffective_features: Vec<String>,
    pub aslr_preserved: bool,
    /// True only when every measured original function, block, and instruction
    /// is owned by the commercial Program-VM.
    pub vm_full_coverage: bool,
    /// Stable, human-readable coverage evidence for diagnostics/manifests.
    pub vm_coverage_evidence: Option<String>,
    /// Executable bytes still covered by the original application's `.text`
    /// RVA interval. `Some(0)` is required by the strict 100% VM contract.
    pub original_text_exec_bytes: Option<u64>,
}

impl EffectiveProfileReport {
    fn effective(&mut self, feature: &str) {
        self.effective_features.push(feature.to_string());
    }

    fn ineffective(&mut self, feature: &str, reason: impl AsRef<str>) {
        self.ineffective_features
            .push(format!("{}:{}", feature, reason.as_ref()));
    }

    pub fn ensure_strict(&self) -> Result<()> {
        if self.ineffective_features.is_empty() {
            Ok(())
        } else {
            bail!(
                "strict-profile effective protection check failed ({}): {}",
                self.ineffective_features.len(),
                self.ineffective_features.join("; ")
            )
        }
    }

    pub fn ensure_vm_full_coverage(&self) -> Result<()> {
        if self.vm_full_coverage && self.original_text_exec_bytes == Some(0) {
            Ok(())
        } else {
            bail!(
                "commercial Program-VM requires 100% measured coverage; {} (use --allow-partial-vm only for development builds)",
                self.vm_coverage_evidence
                    .as_deref()
                    .unwrap_or("coverage evidence is absent")
            )
        }
    }
}

fn complete_vm_coverage(coverage: Option<&crate::pipeline::VmCoverageMetrics>) -> (bool, String) {
    let Some(coverage) = coverage else {
        return (false, "coverage evidence is absent".to_string());
    };
    let complete = coverage.total_functions > 0
        && coverage.total_blocks > 0
        && coverage.total_instructions > 0
        && coverage.vm_functions == coverage.total_functions
        && coverage.vm_blocks == coverage.total_blocks
        && coverage.vm_instructions == coverage.total_instructions
        && coverage.unresolved_internal_edges == Some(0)
        && coverage.unsupported_instructions == Some(0)
        && coverage.capability_mismatches == Some(0);
    (
        complete,
        format!(
            "functions={}/{},blocks={}/{},instructions={}/{},unresolved_internal_edges={},unsupported_instructions={},capability_mismatches={}",
            coverage.vm_functions,
            coverage.total_functions,
            coverage.vm_blocks,
            coverage.total_blocks,
            coverage.vm_instructions,
            coverage.total_instructions,
            coverage
                .unresolved_internal_edges
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unmeasured".to_string()),
            coverage
                .unsupported_instructions
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unmeasured".to_string()),
            coverage
                .capability_mismatches
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unmeasured".to_string())
        ),
    )
}

/// Measure how much of the original `.text` RVA interval is still mapped by an
/// executable output section. This uses section provenance, not byte matching.
pub fn original_text_exec_bytes(ctx: &PipelineContext, out: &[u8]) -> Result<u64> {
    let pe = PE::parse(out).map_err(|e| anyhow!("original .text measurement: {e}"))?;
    let original_start = ctx.target_info.text_rva as u64;
    let original_end = original_start.saturating_add(ctx.target_info.text_vsize as u64);
    let mut covered = 0u64;
    for section in pe
        .sections
        .iter()
        .filter(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
    {
        let section_start = section.virtual_address as u64;
        let section_end = section_start.saturating_add(section.virtual_size as u64);
        covered = covered.saturating_add(
            original_end
                .min(section_end)
                .saturating_sub(original_start.max(section_start)),
        );
    }
    Ok(covered)
}

/// Validate that resolved protection capabilities were actually materialized.
/// Unlike `run`, this checks feature semantics rather than generic PE shape.
pub fn validate_effective_profile(
    ctx: &PipelineContext,
    cfg: &crate::protection_profile::ResolvedConfig,
    out: &[u8],
) -> Result<EffectiveProfileReport> {
    let pe = PE::parse(out).map_err(|e| anyhow!("effective profile: PE parse failed: {e}"))?;
    let sections = collect_sections(&pe);
    let mut report = EffectiveProfileReport::default();
    report.aslr_preserved = pe.header.optional_header.as_ref().is_some_and(|optional| {
        let dll = optional.windows_fields.dll_characteristics;
        let reloc = optional
            .data_directories
            .get_base_relocation_table()
            .is_some_and(|directory| directory.virtual_address > 0 && directory.size > 0);
        dll & 0x0040 != 0 && reloc
    });

    if cfg.crypto_enabled {
        // `--crypto-mode c1` explicitly requests the C1 protection layer; it
        // does not request AEAD. Strict mode must validate the selected
        // primitive instead of treating every enabled crypto path as an AEAD
        // claim. Authentication for C1 is independently materialized by the
        // `integrity` capability below.
        match cfg.crypto_mode {
            crate::crypto::CryptoMode::ChaCha20 => report.effective("aead"),
            crate::crypto::CryptoMode::C1 => report.effective("c1"),
            crate::crypto::CryptoMode::Rc4 => report.ineffective("crypto", "retired-rc4-selected"),
        }
    }

    if cfg.vm_commercial {
        let (coverage_complete, evidence) = complete_vm_coverage(ctx.vm_coverage.as_ref());
        let original_exec = original_text_exec_bytes(ctx, out)?;
        report.vm_full_coverage = coverage_complete;
        report.original_text_exec_bytes = Some(original_exec);
        let evidence = format!("{evidence},original_text_exec_bytes={original_exec}");
        report.vm_coverage_evidence = Some(evidence.clone());
        if ctx.vm_prog_bytecode_len > 0 && coverage_complete && original_exec == 0 {
            report.effective("vm_commercial");
        } else {
            report.ineffective(
                "vm_commercial",
                if ctx.vm_prog_bytecode_len == 0 {
                    format!("missing-bytecode;{evidence}")
                } else if !coverage_complete {
                    format!("incomplete-coverage;{evidence}")
                } else {
                    format!("original-text-still-executable;{evidence}")
                },
            );
        }
    }

    if cfg.m7 {
        if cfg.vm_commercial {
            let covered = ctx
                .vm_prog_chunks
                .iter()
                .try_fold(0u32, |end, chunk| {
                    (chunk.offset == end && chunk.len > 0).then_some(end.saturating_add(chunk.len))
                })
                .is_some_and(|end| end == ctx.vm_prog_bytecode_len);
            if !ctx.vm_prog_chunks.is_empty() && covered {
                report.effective("m7");
            } else {
                report.ineffective("m7", "program-vm-bytecode-chunks-absent-or-not-covering");
            }
        } else if ctx.reencrypt {
            report.effective("m7");
        } else {
            report.ineffective("m7", "no-runtime-reencryption-path");
        }
    }

    if cfg.payload_relocate {
        let payload_ok = ctx.payload_len > 0
            && ctx.payload_rva > 0
            && sections.iter().any(|section| {
                section.contains_rva(ctx.payload_rva)
                    && section.contains_rva(
                        ctx.payload_rva
                            .saturating_add(ctx.payload_len)
                            .saturating_sub(1),
                    )
                    && !section.is_executable()
            });
        if payload_ok {
            report.effective("payload_relocate");
        } else {
            report.ineffective("payload_relocate", "non-executable-payload-section-absent");
        }
    }

    if cfg.rsrc_register {
        let resource_dir = pe.header.optional_header.as_ref().and_then(|optional| {
            optional
                .data_directories
                .get_resource_table()
                .map(|directory| (directory.virtual_address, directory.size))
        });
        let rsrc_ok = ctx.rsrc_dir_rva > 0
            && ctx.rsrc_dir_size > 0
            && resource_dir.is_some_and(|(rva, size)| rva == ctx.rsrc_dir_rva && size > 0);
        if rsrc_ok {
            report.effective("rsrc_register");
        } else {
            report.ineffective("rsrc_register", "resource-directory-or-rcdata-absent");
        }
    }

    if cfg.iat_hide {
        if ctx.iat_dir_rva > 0 && ctx.iat_dir_size > 0 && ctx.iat_table_len > 0 {
            report.effective("iat_hide");
        } else {
            report.ineffective("iat_hide", "resolver-import-or-runtime-table-absent");
        }
    }

    if cfg.integrity {
        if !ctx.vm_integrity_descriptors.is_empty() && ctx.vm_integrity_table_len > 0 {
            report.effective("integrity");
        } else {
            report.ineffective("integrity", "runtime-integrity-descriptors-absent");
        }
    }

    if cfg.mem_harden {
        let rwx = sections
            .iter()
            .filter(|section| {
                section.characteristics & 0x2000_0000 != 0
                    && section.characteristics & 0x8000_0000 != 0
            })
            .map(|section| section.name.clone())
            .collect::<Vec<_>>();
        if rwx.is_empty() {
            report.effective("mem_harden");
        } else {
            report.ineffective(
                "mem_harden",
                format!("static-rwx-sections={}", rwx.join("+")),
            );
        }
    }

    if cfg.anti_debug {
        if ctx.anti_debug {
            report.effective("anti_debug");
        } else {
            report.ineffective("anti_debug", "boot-check-not-materialized");
        }
    }

    Ok(report)
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

    // 1b. P0-4: PE 구조적/로더 호환 전수 검증 (Notes #4)
    //     DOS/NT/Optional 헤더, 정렬, 섹션 RVA/raw 경계·겹침, 16개 데이터
    //     디렉터리 RVA/size, SizeOfImage, 보안 디렉터리 정책.
    validate_pe_structure(out, &pe, ctx, &sections)?;
    println!(
        "[VALIDATE] OK  PE structural/loader-compat (headers, alignments, sections, 16 data dirs)"
    );

    validate_route_metadata(ctx, out, &sections)?;
    println!("[VALIDATE] OK  canonical VM route metadata placement");

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
    //     anti_debug → `pushfq; push rax; mov rax, gs:[0x60]` (9C 50 65 ...),
    //     --vm-oep native → `pushfq; push rax; push rcx` (9C 50 51 ...),
    //     --vm-oep VM → `mov rax, imm64` (48 B8 ...),
    if ctx.crypto_enabled {
        let ep_local = (entry_rva - ep_sec.rva) as usize;
        let file_off = ep_sec.raw_ptr as usize + ep_local;
        let raw_avail = ep_sec.raw_ptr as usize + ep_sec.raw_size as usize;
        if file_off + 12 <= out.len() && file_off + 12 <= raw_avail {
            let b = &out[file_off..];
            let prologue_ok = if ctx.anti_debug {
                b.len() >= 5
                    && (b[0..5] == [0x9C, 0x50, 0x65, 0x48, 0x8B]
                        || b[0..5] == [0x9C, 0x50, 0x31, 0xC0, 0x90])
            } else if ctx.vm_oep {
                // Native fallback saves the exact loader context; a fully lifted
                // entry starts by loading the VM state address into RAX.
                (b.len() >= 3 && b[0..3] == [0x9C, 0x50, 0x51])
                    || (b.len() >= 2 && b[0..2] == [0x48, 0xB8])
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

    // 2c. Crypto normally needs writable staging. mem-harden images instead
    // start RX and open a fail-closed transient write window in the boot stub.
    if ctx.crypto_enabled {
        let tb = sections
            .iter()
            .rev()
            .find(|s| s.name == ".textb")
            .ok_or_else(|| anyhow!("packed section '.textb' missing from output"))?;
        if !ctx.mem_harden && tb.characteristics & 0x8000_0000 == 0 {
            bail!("packed section '.textb' missing WRITE (needed for in-place decryption)");
        }
        if ctx.mem_harden && tb.characteristics & 0x8000_0000 != 0 {
            bail!("mem-harden contract violated: '.textb' is statically writable+executable");
        }
        // readccc §4.4: W^X 메모리 계약 — .textb는 파일에서 RWX(in-place 부트
        // 복호화용)로 매핑되지만, --mem-harden이 유효하면 부트 스텁이 복호화+
        // 무결성 검증 후 NtProtectVirtualMemory로 RX 전환한다. 이 라이프사이클을
        // 검증으로 고정한다 (게이트: mem_harden 활성이면 프로파일 해석도 mem_harden
        // 유효해야 하며 — reencrypt/vm-oep와의 상충은 resolve가 이미 제거).
        let wx_contract = if ctx.mem_harden {
            "transient-rw-to-rx,rx-immutable,rw-state"
        } else {
            "rwx-at-rest"
        };
        println!(
            "[VALIDATE] OK  W^X memory contract: {} (.textb {} — runtime split {})",
            wx_contract,
            "RWX in-file",
            if ctx.mem_harden {
                "ENABLED (immutable RX / mutable RW)"
            } else {
                "disabled (stays RWX)"
            }
        );
    }

    // P2-5 data-lifetime objects are decrypted/re-encrypted in place by the
    // Program-VM runtime. Their backing section therefore has a strict RW/NX
    // contract. Missing WRITE used to pass structural validation and then fault
    // at the first MemoryWrite8 into .rdata/.rodata.
    if !ctx.vm_data_lifetime_objects.is_empty() {
        for object in &ctx.vm_data_lifetime_objects {
            let object_end = object
                .rva
                .checked_add(object.len)
                .ok_or_else(|| anyhow!("P2-5 lifetime object RVA range overflow"))?;
            let sec = section_for_rva(&sections, object.rva).ok_or_else(|| {
                anyhow!(
                    "P2-5 lifetime object RVA 0x{:X} is outside all output sections",
                    object.rva
                )
            })?;
            let sec_end = sec.rva.saturating_add(sec.virtual_size.max(sec.raw_size));
            if object_end > sec_end {
                bail!(
                    "P2-5 lifetime object RVA 0x{:X}..0x{:X} crosses section '{}' boundary",
                    object.rva,
                    object_end,
                    sec.name
                );
            }
            if sec.characteristics & 0x4000_0000 == 0
                || sec.characteristics & 0x8000_0000 == 0
                || sec.characteristics & 0x2000_0000 != 0
            {
                bail!(
                    "P2-5 lifetime section '{}' must be RW/NX, got characteristics 0x{:08X}",
                    sec.name,
                    sec.characteristics
                );
            }
        }
        println!(
            "[VALIDATE] OK  P2-5 lifetime backing: {} object(s) in RW/NX section(s)",
            ctx.vm_data_lifetime_objects.len()
        );
    }

    if ctx.mem_harden && ctx.vm_oep {
        let textb = sections
            .iter()
            .find(|section| section.name == ".textb")
            .ok_or_else(|| anyhow!("mem-harden Program-VM missing .textb"))?;
        let state = sections
            .iter()
            .find(|section| section.name == ".vstate")
            .ok_or_else(|| anyhow!("mem-harden Program-VM missing RW/NX .vstate"))?;
        if state.characteristics & 0x2000_0000 != 0
            || state.characteristics & 0x8000_0000 == 0
            || state.characteristics & 0x4000_0000 == 0
        {
            bail!(
                "Program-VM state section must be RW/NX, got characteristics 0x{:08X}",
                state.characteristics
            );
        }
        if textb.rva.saturating_add(textb.virtual_size) != state.rva {
            bail!(
                "Program-VM W^X split is not contiguous: .textb end=0x{:X}, .vstate=0x{:X}",
                textb.rva.saturating_add(textb.virtual_size),
                state.rva
            );
        }
        println!(
            "[VALIDATE] OK  Program-VM state split: .textb RX -> .vstate RW/NX @0x{:X}",
            state.rva
        );
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
            anyhow!(
                "dummy import RVA 0x{:X} outside all sections",
                dd.virtual_address
            )
        })?;
        if sec.characteristics & 0x2000_0000 != 0 {
            bail!(
                "loader-written dummy import/IAT is in executable section '{}'",
                sec.name
            );
        }
        if sec.characteristics & 0x8000_0000 == 0 {
            bail!(
                "loader-written dummy import/IAT section '{}' is not writable",
                sec.name
            );
        }
        let iat = pe
            .header
            .optional_header
            .as_ref()
            .and_then(|oh| {
                oh.data_directories.data_directories[12]
                    .as_ref()
                    .map(|(_, directory)| *directory)
            })
            .ok_or_else(|| anyhow!("dummy IAT directory missing from output"))?;
        if iat.virtual_address != ctx.iat_ll_slot_rva || iat.size < 24 {
            bail!(
                "dummy IAT directory mismatch: got RVA 0x{:X}/{}B, expected 0x{:X}/24B",
                iat.virtual_address,
                iat.size,
                ctx.iat_ll_slot_rva
            );
        }
        println!(
            "[VALIDATE] OK  dummy import/IAT @0x{:X} in RW/non-exec '{}' (LoadLibraryA/GetProcAddress only)",
            dd.virtual_address, sec.name
        );
    }
    for (idx, name) in if ctx.iat_hide {
        vec![(9usize, "TLS")]
    } else {
        vec![(1usize, "Import"), (9, "TLS")]
    } {
        let orig = ctx
            .target_info
            .data_directories
            .get(idx)
            .copied()
            .unwrap_or(crate::pe::builder::DataDirectory {
                virtual_address: 0,
                size: 0,
            });
        if orig.virtual_address == 0 {
            continue; // 원본에 없으면 검사할 것 없음
        }
        let dd = pe
            .header
            .optional_header
            .as_ref()
            .and_then(|oh| {
                oh.data_directories.data_directories[idx]
                    .as_ref()
                    .map(|(_, d)| *d)
            })
            .ok_or_else(|| {
                anyhow!(
                    "original {} table @0x{:X} was dropped from output",
                    name,
                    orig.virtual_address
                )
            })?;
        if dd.virtual_address == 0 {
            bail!(
                "original {} table @0x{:X} zeroed in output",
                name,
                orig.virtual_address
            );
        }
        let sec = section_for_rva(&sections, dd.virtual_address).ok_or_else(|| {
            anyhow!(
                "{} table RVA 0x{:X} outside all sections",
                name,
                dd.virtual_address
            )
        })?;
        println!(
            "[VALIDATE] OK  {} table @0x{:X} preserved in '{}'",
            name, dd.virtual_address, sec.name
        );
    }

    // 3c. v8 (Phase 0.3): --dispatcher-reencrypt — each non-call-target
    //     block is independently encrypted with BTG-RC1's 44-byte provider
    //     record (or BTG-C1 when that explicit production mode is selected).
    //     The compact length metadata continues to use the MBA mask.
    if ctx.reencrypt {
        let tb = sections
            .iter()
            .rev()
            .find(|s| s.name == ".textb")
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
            let len_enc = u32::from_le_bytes(
                out[entry_off..entry_off + 4]
                    .try_into()
                    .expect("T3-3: 4-byte slice for length table entry (bounds checked above)"),
            );
            let decoded_len = len_enc ^ key;
            if decoded_len != (if is_call_target { 0 } else { len as u32 }) {}
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
                let c1 = ctx.custom_cipher && ctx.reencrypt;
                let dec = decrypt_dispatcher_block(
                    ctx.mba_constant,
                    c1,
                    id,
                    off as u64,
                    &out[file_off..file_off + len],
                )?;
                if dec != block.instructions {
                    bail!(
                        "Phase 0.3: block {} per-block decrypt roundtrip mismatch ({}) (dispatcher would execute garbage)",
                        id,
                        if c1 { "BTG-C1" } else { "BTG-RC1/44B" }
                    );
                }
            }
        }
        println!(
            "[VALIDATE] OK  Phase 0.3: {} blocks individually encrypted, length table verified (per-block keys, {} call-target plaintext)",
            num_blocks, call_target_count
        );
    }

    // 3d. v61 (--m7): on-demand 상태 테이블 — 일반 블록은 0xFFFFFFFF(암호화),
    //     call-target 블록은 0(평문 유지)으로 초기화되어야 디스패처 상태 머신이
    //     올바르게 시작한다. (점프 테이블 + 길이 테이블 뒤 = table_offset + 2*N*4)
    if ctx.reencrypt {
        let tb = sections
            .iter()
            .rev()
            .find(|s| s.name == ".textb")
            .ok_or_else(|| anyhow!("packed section '.textb' missing from output"))?;
        let layout = ctx
            .layout()
            .map_err(|e| anyhow!("m7 validation needs layout: {e}"))?;
        let num_blocks = layout.shuffled_blocks.len();
        let state_table_off = tb.raw_ptr as usize + ctx.table_offset + num_blocks * 8;
        let mut call_target_count = 0usize;
        for block in &layout.shuffled_blocks {
            let id = block.id as usize;
            let entry_off = state_table_off + id * 4;
            if entry_off + 4 > out.len() {
                bail!("v61 m7: state table entry for block {} beyond EOF", id);
            }
            let st = u32::from_le_bytes(
                out[entry_off..entry_off + 4]
                    .try_into()
                    .expect("T3-3: 4-byte slice for state table entry (bounds checked above)"),
            );
            let is_call_target = ctx.call_target_block_ids.contains(&block.id);
            if is_call_target {
                call_target_count += 1;
                if st != 0 {
                    bail!(
                        "v61 m7: call-target block {} state must be 0 (plaintext), got 0x{:X}",
                        id,
                        st
                    );
                }
            } else if st != 0xFFFF_FFFF {
                bail!(
                    "v61 m7: block {} state must be 0xFFFFFFFF (encrypted) at rest, got 0x{:X}",
                    id,
                    st
                );
            }
        }
        println!(
            "[VALIDATE] OK  v61 m7: state table verified ({} encrypted, {} call-target plaintext)",
            num_blocks - call_target_count,
            call_target_count
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
            bail!(
                "payload section '{}' is executable (must be non-exec data)",
                psec.name
            );
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

    // 5b. 상용 1-4: 데이터 디렉터리 전수 재파싱 검증 + 원본↔보호 구조 diff.
    validate_all_directories(out, &pe, &sections, ctx)?;
    report_pe_diff(ctx.target_info.original_pe_bytes.as_slice(), &pe, out)?;

    // WS2.1: function-ownership ↔ .pdata consistency auto-check.
    // Runs on program-VM paths; derives the ownership model from the
    // program-VM module region and verifies it against .pdata.
    if ctx.vm_oep {
        validate_function_ownership(ctx, out)?;
    }

    println!("[VALIDATE] all structural checks passed ✔");
    Ok(())
}

/// WS2.1 (readccc §4.6): verify every function claimed "∈ VM" by the
/// function-ownership model is fully covered by its .pdata RUNTIME_FUNCTION
/// and that no VM function's native entry bypasses its prologue.
fn derive_ownership_model(
    ctx: &PipelineContext,
    out: &[u8],
) -> Result<(Vec<FunctionOwnership>, Vec<RuntimeFunction>)> {
    let pe = PE::parse(out).map_err(|e| anyhow!("validate: output PE re-parse failed: {e}"))?;
    let sections = collect_sections(&pe);

    // Parse .pdata RUNTIME_FUNCTION entries: 12-byte [BeginRVA, EndRVA, UnwindInfoRVA].
    // Use the PE Exception data directory (index 3) size to determine the exact
    // length of the RUNTIME_FUNCTION array. The .pdata section's raw_size includes
    // UNWIND_INFO blobs appended after the array; parsing those bytes as 12-byte
    // RUNTIME_FUNCTION entries produces bogus entries that shadow real ones.
    let mut runtime_functions: Vec<RuntimeFunction> = Vec::new();
    let exception_dir_size = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|oh| {
            oh.data_directories.data_directories[3]
                .as_ref()
                .map(|(_, dd)| dd.size as usize)
        })
        .unwrap_or(0);
    if let Some(pd) = sections.iter().find(|s| s.name == ".pdata") {
        let start = pd.raw_ptr as usize;
        // Prefer the data directory size (RF array only) over raw_size (includes UNWIND_INFO).
        let len = if exception_dir_size > 0 {
            exception_dir_size
        } else {
            pd.raw_size as usize
        };
        let avail = (start + len).min(out.len());
        if start < out.len() {
            for chunk in out[start..avail].chunks_exact(12) {
                let b = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let e = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                if b > 0 && e > b {
                    runtime_functions.push(RuntimeFunction {
                        begin_rva: b,
                        end_rva: e,
                    });
                }
            }
        }
    }

    // If the binary has no SEH (.pdata is empty), ownership consistency check is not applicable.
    if runtime_functions.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    // Ownership model: the program-VM module region (which build.rs wraps in a
    // bridge UNWIND_INFO) is the VM-owned set; the region must be fully covered.
    let mut model: Vec<FunctionOwnership> = Vec::new();
    if ctx.vm_prog_rva > 0 && ctx.vm_prog_total > 0 {
        model.push(FunctionOwnership {
            start_rva: ctx.vm_prog_rva,
            end_rva: ctx.vm_prog_rva.saturating_add(ctx.vm_prog_total),
            owned_by_vm: true,
            enforce_entry_begin: false,
            reason: "program-vm-module",
        });
    }
    for rf in &runtime_functions {
        let in_vm = ctx.vm_prog_rva > 0
            && rf.begin_rva >= ctx.vm_prog_rva
            && rf.begin_rva < ctx.vm_prog_rva.saturating_add(ctx.vm_prog_total);
        if !in_vm && !model.iter().any(|m| m.start_rva == rf.begin_rva) {
            model.push(FunctionOwnership {
                start_rva: rf.begin_rva,
                end_rva: rf.end_rva,
                owned_by_vm: false,
                enforce_entry_begin: false,
                // Until the lift analysis supplies a more specific typed
                // blocker, fail closed as an explicit analysis failure. Never
                // collapse unrelated causes into the historical catch-all.
                reason: "analysis-failure",
            });
        }
    }
    Ok((model, runtime_functions))
}

/// WS2.1: run the function-ownership ↔ .pdata consistency check. Bails on the
/// first inconsistency (validate becomes a hard gate on program-VM paths).
pub(crate) fn validate_function_ownership(ctx: &PipelineContext, out: &[u8]) -> Result<()> {
    if ctx.target_info.original_pdata_entries.is_empty() {
        println!(
            "[VALIDATE] OK  no-SEH image: canonical ownership has no .pdata coverage obligation"
        );
        return Ok(());
    }
    let (derived_model, runtime_functions) = derive_ownership_model(ctx, out)?;
    let authoritative = !ctx.ownership_report.is_empty();
    let mut model = if !authoritative {
        derived_model
    } else {
        // VM-owned original functions have been virtualized into the program-VM
        // module at a different RVA range. Their original RVAs no longer have
        // individual .pdata coverage in the output PE — the VM module's
        // RUNTIME_FUNCTION entry covers them collectively. Only native functions
        // retain their original .pdata entries and need individual validation.
        ctx.ownership_report
            .iter()
            .filter(|record| !record.function.owned_by_vm)
            .map(|record| record.function)
            .collect::<Vec<_>>()
    };
    if authoritative && ctx.vm_prog_rva > 0 && ctx.vm_prog_total > 0 {
        model.push(FunctionOwnership {
            start_rva: ctx.vm_prog_rva,
            end_rva: ctx.vm_prog_rva.saturating_add(ctx.vm_prog_total),
            owned_by_vm: true,
            enforce_entry_begin: false,
            reason: "program-vm-module",
        });
    }
    let report = check_ownership(&model, &runtime_functions).map_err(|e| anyhow!("{}", e))?;
    println!(
        "[VALIDATE] OK  function-ownership ↔ .pdata: {} fn ({} VM, {} native), {} RUNTIME_FUNCTION — clean",
        report.total_functions,
        report.vm_functions,
        report.native_functions,
        runtime_functions.len()
    );
    println!(
        "           program-VM module 0x{:X}..0x{:X} fully covered by RUNTIME_FUNCTION",
        ctx.vm_prog_rva,
        ctx.vm_prog_rva.saturating_add(ctx.vm_prog_total)
    );
    if !ctx.vm_prog_native_bridges.is_empty() && !ctx.target_info.original_pdata_entries.is_empty()
    {
        let handler = ctx.vm_prog_lifetime_cleanup_handler_rva;
        let vm_end = ctx.vm_prog_rva.saturating_add(ctx.vm_prog_total);
        if handler < ctx.vm_prog_rva || handler >= vm_end {
            bail!(
                "lifetime cleanup handler RVA 0x{handler:X} outside Program-VM 0x{:X}..0x{vm_end:X}",
                ctx.vm_prog_rva
            );
        }
        let pe = PE::parse(out).map_err(|e| anyhow!("validate: output PE re-parse failed: {e}"))?;
        let sections = collect_sections(&pe);
        let pdata = sections
            .iter()
            .find(|section| section.name == ".pdata")
            .ok_or_else(|| anyhow!("native bridges require .pdata"))?;
        let pdata_start = pdata.raw_ptr as usize;
        // Use Exception data directory size (RF array only) to avoid scanning
        // UNWIND_INFO bytes appended after the RUNTIME_FUNCTION array.
        let exception_array_size = pe
            .header
            .optional_header
            .as_ref()
            .and_then(|oh| {
                oh.data_directories.data_directories[3]
                    .as_ref()
                    .map(|(_, dd)| dd.size as usize)
            })
            .unwrap_or(pdata.raw_size as usize);
        let pdata_end = pdata_start
            .saturating_add(exception_array_size)
            .min(out.len());
        let rva_bytes = |rva: u32, len: usize| -> Result<&[u8]> {
            let section = sections
                .iter()
                .find(|section| section.contains_rva(rva))
                .ok_or_else(|| anyhow!("RVA 0x{rva:X} outside sections"))?;
            let offset = section.raw_ptr as usize + (rva - section.rva) as usize;
            out.get(offset..offset.saturating_add(len))
                .ok_or_else(|| anyhow!("RVA 0x{rva:X} truncated"))
        };
        for &(start, _) in &ctx.vm_prog_native_bridges {
            let begin = ctx.vm_prog_rva.saturating_add(start);
            let record = out[pdata_start..pdata_end]
                .chunks_exact(12)
                .find(|record| u32::from_le_bytes(record[0..4].try_into().unwrap()) == begin)
                .ok_or_else(|| anyhow!("native bridge 0x{begin:X} missing RUNTIME_FUNCTION"))?;
            let unwind_rva = u32::from_le_bytes(record[8..12].try_into().unwrap());
            let header = rva_bytes(unwind_rva, 4)?;
            if header[0] & 0x18 != 0x10 {
                bail!("native bridge 0x{begin:X} lacks UNW_FLAG_UHANDLER");
            }
            let handler_offset = (4 + header[2] as usize * 2 + 3) & !3;
            let raw_handler = rva_bytes(unwind_rva, handler_offset + 4)?;
            let recorded = u32::from_le_bytes(
                raw_handler[handler_offset..handler_offset + 4]
                    .try_into()
                    .unwrap(),
            );
            if recorded != handler {
                bail!(
                    "native bridge 0x{begin:X} cleanup handler drift: 0x{recorded:X} != 0x{handler:X}"
                );
            }
        }
        println!(
            "[VALIDATE] OK  {} native bridge UHANDLER record(s) → lifetime cleanup RVA 0x{:X}",
            ctx.vm_prog_native_bridges.len(),
            handler
        );
    } else if !ctx.vm_prog_native_bridges.is_empty() {
        println!(
            "[VALIDATE] OK  tiny/no-SEH image: {} native bridge(s) use leaf unwind semantics",
            ctx.vm_prog_native_bridges.len()
        );
    }
    Ok(())
}

/// WS2.1: render the ownership model as a CSV mapping file (per the project's
/// mapping-file convention). Returns None when not on a program-VM path.
pub fn ownership_csv(ctx: &PipelineContext, out: &[u8]) -> Result<Option<String>> {
    if !ctx.vm_oep {
        return Ok(None);
    }
    if !ctx.ownership_report.is_empty() {
        return Ok(Some(crate::pipeline::ownership::render_diagnostic_csv(
            &ctx.ownership_report,
        )));
    }
    let (model, _) = derive_ownership_model(ctx, out)?;
    Ok(Some(render_csv(&model)))
}

// ──────────────────────────────────────────────────────────────────────────────
// 단위 테스트
// ──────────────────────────────────────────────────────────────────────────────
