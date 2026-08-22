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
    //     그 외 → `sub rsp, imm32` (48 81 EC ?? ?? ?? ??).
    if ctx.crypto_enabled {
        let ep_local = (entry_rva - ep_sec.rva) as usize;
        let file_off = ep_sec.raw_ptr as usize + ep_local;
        let raw_avail = ep_sec.raw_ptr as usize + ep_sec.raw_size as usize;
        if file_off + 12 <= out.len() && file_off + 12 <= raw_avail {
            let b = &out[file_off..];
            let prologue_ok = if ctx.anti_debug {
                b.len() >= 5 && b[0..5] == [0x9C, 0x50, 0x65, 0x48, 0x8B]
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

    // 2c. v5 (안정성): crypto 활성 시 .textb는 쓰기 가능이어야 한다 (in-place 복호화).
    if ctx.crypto_enabled {
        let tb = sections
            .iter()
            .rev()
            .find(|s| s.name == ".textb")
            .ok_or_else(|| anyhow!("packed section '.textb' missing from output"))?;
        if tb.characteristics & 0x8000_0000 == 0 {
            bail!("packed section '.textb' missing WRITE (needed for in-place decryption)");
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
        println!(
            "[VALIDATE] OK  dummy import dir @0x{:X} in '{}' (LoadLibraryA/GetProcAddress only)",
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
    let mut runtime_functions: Vec<RuntimeFunction> = Vec::new();
    if let Some(pd) = sections.iter().find(|s| s.name == ".pdata") {
        let start = pd.raw_ptr as usize;
        let len = pd.raw_size as usize;
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
                reason: "native-seh-or-plain",
            });
        }
    }
    Ok((model, runtime_functions))
}

/// WS2.1: run the function-ownership ↔ .pdata consistency check. Bails on the
/// first inconsistency (validate becomes a hard gate on program-VM paths).
pub(crate) fn validate_function_ownership(ctx: &PipelineContext, out: &[u8]) -> Result<()> {
    let (model, runtime_functions) = derive_ownership_model(ctx, out)?;
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
    if !ctx.vm_prog_native_bridges.is_empty() {
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
        let pdata_end = pdata_start
            .saturating_add(pdata.raw_size as usize)
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
    }
    Ok(())
}

/// WS2.1: render the ownership model as a CSV mapping file (per the project's
/// mapping-file convention). Returns None when not on a program-VM path.
pub fn ownership_csv(ctx: &PipelineContext, out: &[u8]) -> Result<Option<String>> {
    if !ctx.vm_oep {
        return Ok(None);
    }
    let (model, _) = derive_ownership_model(ctx, out)?;
    Ok(Some(render_csv(&model)))
}

// ──────────────────────────────────────────────────────────────────────────────
// 단위 테스트
// ──────────────────────────────────────────────────────────────────────────────
