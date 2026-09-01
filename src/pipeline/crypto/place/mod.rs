// ==============================================================================
// Boot-stub placement: stub building (3 passes), VM module embed, boot-data writes
// ==============================================================================

use super::bootstub::{build_anti_debug_raw_block, build_boot_block, BootStubCtx};
use super::integrity::crc32;
use super::scan::StringRun;
use super::{BootStreamCipher, IMPORT_MBA_C};
use crate::pipeline::pass4_section::BOOT_AREA_RESERVE;
use crate::pipeline::PipelineContext;
use crate::vm;
use anyhow::Result;
use rand::RngCore;

mod lift;
mod route_orchestration;
mod vm_build;

use lift::lift_program;
use vm_build::{
    build_multi_family_prog_mod, build_prog_vm_mod, build_vm_mod, MULTI_FAMILY_STATE_STRIDE,
    VM_HOST_STACK_SIZE, VM_HOST_STACK_SLOTS, VM_INVOCATION_LANES, VM_THREAD_BUCKETS,
};

/// BTG-C1 상태 버퍼 크기 (key[32] + ctr[8] + nonce[4] + pad + ks[64] + ks_off[4] = 0x80).
const C1_STATE_SIZE: usize = 0x80;

/// Serialize and stage the canonical route table for final PE synthesis.
/// The PE builder owns the final RVA so this remains deterministic even when
/// optional payload/state sections change size.
pub(crate) fn stage_route_metadata(
    ctx: &mut PipelineContext,
    routes: &crate::vm::route_table::MaterializedRouteTable,
) -> Result<()> {
    ctx.route_metadata_section_data = Some(route_metadata_section(routes)?);
    ctx.route_required_original_targets = routes.entries().iter().map(|(rva, _)| *rva).collect();
    Ok(())
}

fn route_metadata_section(
    routes: &crate::vm::route_table::MaterializedRouteTable,
) -> Result<crate::pe::builder::SectionData> {
    let metadata = routes.to_metadata()?;
    Ok(crate::pe::builder::SectionData {
        name: ".vmroute".to_string(),
        virtual_address: 0,
        virtual_size: metadata.bytes.len() as u32,
        characteristics: 0x4000_0040, // INITIALIZED_DATA | READ
        bytes: metadata.bytes,
    })
}

fn collect_native_gateway_targets(
    sections: &[crate::pe::builder::SectionData],
    image_base: u64,
    multi: &crate::vm::multi_family::MaterializedMultiFamilyProgram,
    required_original_targets: &[crate::vm::route_table::OriginalTargetRva],
) -> Vec<u64> {
    // Native code can re-enter VM-owned code through address-taken callbacks
    // that never appear in the static cross-family route table. Inventory both
    // full pointers stored in non-executable data and code materialization such
    // as `lea rdx,[rip+callback]` before module sizing.
    //
    // Only exact VM-owned function entries qualify, so ordinary RIP-relative
    // constants/data references cannot inflate the gateway set.
    let vm_entries: std::collections::HashSet<u64> = multi
        .modules
        .iter()
        .flat_map(|module| {
            module
                .function_ids
                .iter()
                .copied()
                .filter(|entry| module.ip_map.contains_key(entry))
        })
        .collect();
    let mut targets: std::collections::BTreeSet<u64> = required_original_targets
        .iter()
        .map(|target| image_base + u64::from(target.0))
        .filter(|target| vm_entries.contains(target))
        .collect();

    for section in sections {
        if section.characteristics & 0x2000_0000 != 0 {
            let section_va = image_base + u64::from(section.virtual_address);
            let mut decoder = iced_x86::Decoder::with_ip(
                64,
                &section.bytes,
                section_va,
                iced_x86::DecoderOptions::NONE,
            );
            while decoder.can_decode() {
                let instruction = decoder.decode();
                let candidate = match instruction.code() {
                    iced_x86::Code::Lea_r64_m if instruction.is_ip_rel_memory_operand() => {
                        Some(instruction.ip_rel_memory_address())
                    }
                    iced_x86::Code::Mov_r64_imm64 => Some(instruction.immediate64()),
                    _ => None,
                };
                if let Some(candidate) = candidate {
                    if vm_entries.contains(&candidate) {
                        targets.insert(candidate);
                    }
                }
            }
            continue;
        }

        if section.bytes.len() < 8 {
            continue;
        }
        let mut cursor = 0usize;
        while cursor + 8 <= section.bytes.len() {
            let candidate = u64::from_le_bytes(
                section.bytes[cursor..cursor + 8]
                    .try_into()
                    .expect("8-byte PE pointer window"),
            );
            if vm_entries.contains(&candidate) {
                targets.insert(candidate);
                cursor += 8;
            } else {
                cursor += 1;
            }
        }
    }

    targets.into_iter().collect()
}

#[cfg(test)]
mod native_gateway_target_tests {
    use super::collect_native_gateway_targets;
    use crate::pe::builder::SectionData;
    use crate::vm::multi_family::{EncodedFamilyPartition, MaterializedMultiFamilyProgram};
    use crate::vm::poly::VmArchitectureFamily;
    use std::collections::HashMap;

    #[test]
    fn required_native_target_without_vm_entry_is_not_rewritten() {
        let image_base = 0x0000_0001_4000_0000u64;
        let native_target = image_base + 0x3000;
        let multi = MaterializedMultiFamilyProgram {
            modules: vec![EncodedFamilyPartition {
                family: VmArchitectureFamily::Stack,
                function_ids: Vec::new(),
                bytecode: Vec::new(),
                instruction_offsets: Vec::new(),
                ip_map: HashMap::new(),
                module_domain: 1,
                exit_byte_offset: 0,
            }],
            route_table: Vec::new(),
        };
        let targets = collect_native_gateway_targets(
            &[],
            image_base,
            &multi,
            &[crate::vm::route_table::OriginalTargetRva(0x3000)],
        );
        assert!(!targets.contains(&native_target));
    }

    #[test]
    fn rip_relative_lea_of_vm_function_is_gateway_target() {
        let image_base = 0x0000_0001_4000_0000u64;
        let section_rva = 0x1000u32;
        let target = image_base + 0x3000;
        let next_ip = image_base + u64::from(section_rva) + 7;
        let disp = i32::try_from(target as i64 - next_ip as i64).unwrap();

        // lea rdx,[rip+disp32] ; ret
        let mut bytes = vec![0x48, 0x8D, 0x15];
        bytes.extend_from_slice(&disp.to_le_bytes());
        bytes.push(0xC3);

        let sections = vec![SectionData {
            name: ".text".to_string(),
            virtual_address: section_rva,
            virtual_size: bytes.len() as u32,
            characteristics: 0x6000_0020,
            bytes,
        }];
        let multi = MaterializedMultiFamilyProgram {
            modules: vec![EncodedFamilyPartition {
                family: VmArchitectureFamily::Stack,
                function_ids: vec![target],
                bytecode: Vec::new(),
                instruction_offsets: vec![0],
                ip_map: HashMap::from([(target, 0)]),
                module_domain: 1,
                exit_byte_offset: 0,
            }],
            route_table: Vec::new(),
        };

        assert_eq!(
            collect_native_gateway_targets(&sections, image_base, &multi, &[]),
            vec![target],
        );
    }
}

fn rewrite_native_gateway_pointers(
    sections: &mut [crate::pe::builder::SectionData],
    _image_base: u64,
    program_vm_va: u64,
    gateways: &std::collections::BTreeMap<u64, usize>,
) -> usize {
    // Build a direct replacement map once. The old gateway-major scan was
    // O(gateways * data bytes), which became prohibitively expensive once
    // address-taken callbacks were included in the gateway inventory.
    let replacements: std::collections::HashMap<u64, u64> = gateways
        .iter()
        .map(|(&original_va, &gateway_off)| {
            (original_va, program_vm_va + gateway_off as u64)
        })
        .collect();

    let mut rewritten = 0usize;
    for section in sections {
        // Code immediates are VM-owned and must not be mechanically rewritten;
        // callback/vtable/function-pointer storage lives in non-executable data.
        if section.characteristics & 0x2000_0000 != 0 || section.bytes.len() < 8 {
            continue;
        }
        let mut cursor = 0usize;
        while cursor + 8 <= section.bytes.len() {
            let candidate = u64::from_le_bytes(
                section.bytes[cursor..cursor + 8]
                    .try_into()
                    .expect("8-byte PE pointer window"),
            );
            if let Some(&replacement) = replacements.get(&candidate) {
                section.bytes[cursor..cursor + 8]
                    .copy_from_slice(&replacement.to_le_bytes());
                rewritten += 1;
                cursor += 8;
            } else {
                cursor += 1;
            }
        }
        // Do not byte-scan arbitrary 32-bit RVA values here. They are not
        // self-describing pointers and collide with ordinary constants,
        // relocation metadata and packed structures. Canonical RVA-table
        // rewrites belong to the typed table provenance path; PE32+ native
        // callback/vtable slots are full image VAs.
    }
    rewritten
}

pub(crate) fn place_boot_stub(
    ctx: &mut PipelineContext,
    stream: &mut BootStreamCipher,
    runs: &[StringRun],
    seed_masked: &[u8],
    seed_stored: &[u8],
    crc_source: Option<Vec<u8>>,
    mut payload_bytes: Vec<u8>,
    no_crypto: bool,
    anti_debug: bool,
    anti_debug_policy: crate::dispatcher::antidebug::AntiDebugPolicy,
    vm_effective: bool,
    vm_oep_effective: bool,
    vm_commercial: bool,
    chained_effective: bool,
    reencrypt: bool,
    integrity_effective: bool,
    payload_relocate: bool,
    image_base: u64,
    dispatcher_va: u64,
    dispatcher_rva: u32,
    boot_off: usize,
    code_start: usize,
    code_len: u32,
    k1: u32,
    k2: u32,
    k3: u32,
    m8_mod: bool,
    crypto_mode: crate::crypto::CryptoMode,
    // T3-1 Phase D: the one-time key is derived into this scratch area at runtime.
    // Only the tag is persisted in the image.
    chacha_aead_tag: Option<[u8; 16]>,
    rng: &mut impl RngCore,
) -> Result<()> {
    let boot_va = dispatcher_va + boot_off as u64;
    let c1_mode = !no_crypto && crypto_mode == crate::crypto::CryptoMode::C1;
    let chacha_mode = !no_crypto && crypto_mode == crate::crypto::CryptoMode::ChaCha20;

    // M8: VM module builders live in `vm_build` (MBA-variant vs plain routing).
    // P3 (G1): 상용 프로그램 리프트의 ip_map (source-IP -> micro-op index) — the
    // VirtualBranch native handler uses it to resolve branch targets to bytecode
    // byte offsets. Populated in the lift below and passed to build_prog_vm_mod.
    let (
        vm_prog_bytecode,
        vm_oep_native_entry,
        oep_va,
        vm_prog_ip_map,
        vm_prog_superops,
        vm_coverage,
        ownership_report,
        vm_prog_chunks,
        vm_family_plan,
        vm_family_partitions,
        vm_multi_family,
        data_lifetime_objects,
        unsupported_instructions,
    ) = lift_program(ctx, image_base, vm_oep_effective, vm_commercial)?;
    ctx.vm_coverage = vm_coverage;
    ctx.ownership_report = ownership_report;
    ctx.vm_prog_chunks = vm_prog_chunks;
    ctx.vm_family_plan = vm_family_plan;
    ctx.vm_family_partitions = vm_family_partitions;
    ctx.vm_multi_family = vm_multi_family;
    ctx.unsupported_instructions = unsupported_instructions;

    // Route metadata is rebuilt from the current commercial-VM analysis below.
    // Keep all authoritative placement/inventory state in the same lifecycle:
    // a previous/sizing pass must never leave route facts behind after the
    // serialized `.vmroute` payload has been cleared.
    ctx.route_metadata_section_data = None;
    ctx.route_required_original_targets.clear();
    ctx.route_generated_destinations.clear();
    ctx.route_generated_executable_ranges.clear();

    if vm_commercial {
        if let (Some(program), Some(plan), Some(multi)) = (
            ctx.program_model.as_ref(),
            ctx.vm_family_plan.as_ref(),
            ctx.vm_multi_family.as_ref(),
        ) {
            if let Some(routes) =
                route_orchestration::build_commercial_routes(program, plan, multi, image_base)?
            {
                println!(
                    "[+] Canonical indirect routing: {} proven target(s) staged in .vmroute",
                    routes.len()
                );
                stage_route_metadata(ctx, &routes)?;
            }
        }
    }
    // P2-5 runtime lifetime toggles decrypt/re-encrypt selected literal objects
    // in place.  The scanner deliberately selects objects from read-only
    // .rdata/.rodata, so the final PE must grant those backing pages WRITE or
    // the first MemoryWrite8 in emit_lifetime_toggle faults with 0xC0000005.
    // Keep them non-executable: this is mutable data, never runtime code.
    for object in &data_lifetime_objects {
        let object_end = object
            .rva
            .checked_add(object.len)
            .ok_or_else(|| anyhow::anyhow!("P2-5 lifetime object RVA range overflow"))?;
        let section = ctx
            .patched_sections
            .iter_mut()
            .find(|section| {
                let section_end = section
                    .virtual_address
                    .saturating_add(section.bytes.len() as u32);
                object.rva >= section.virtual_address && object_end <= section_end
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "P2-5 lifetime object RVA 0x{:X} is outside relayed sections",
                    object.rva
                )
            })?;
        if section.characteristics & 0x2000_0000 != 0 {
            anyhow::bail!(
                "P2-5 lifetime object RVA 0x{:X} unexpectedly resides in executable section '{}'",
                object.rva,
                section.name
            );
        }
        section.characteristics |= 0x8000_0000; // IMAGE_SCN_MEM_WRITE
    }

    for object in &data_lifetime_objects {
        let plaintext =
            crate::vm::data_lifetime::section_object_bytes(&ctx.patched_sections, object)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "P2-5 lifetime object RVA 0x{:X} is outside relayed sections",
                        object.rva
                    )
                })?
                .to_vec();
        if !crate::vm::data_lifetime::toggle_section_object(
            &mut ctx.patched_sections,
            object,
            ctx.poly_vm_seed,
        ) {
            anyhow::bail!(
                "P2-5 lifetime object RVA 0x{:X} is outside relayed sections",
                object.rva
            );
        }
        let ciphertext =
            crate::vm::data_lifetime::section_object_bytes(&ctx.patched_sections, object)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "P2-5 lifetime object RVA 0x{:X} disappeared after encryption",
                        object.rva
                    )
                })?;
        if ciphertext == plaintext.as_slice() {
            anyhow::bail!(
                "P2-5 lifetime object RVA 0x{:X} remained plaintext",
                object.rva
            );
        }
    }
    if !data_lifetime_objects.is_empty() {
        println!(
            "[+] P2-5 data lifetime active: {} object(s) encrypted at rest with scoped VM toggles",
            data_lifetime_objects.len()
        );
    }
    ctx.vm_data_lifetime_objects = data_lifetime_objects;

    let btg = ctx
        .btg_section_data
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("btg_section_data not set — run Pass 4 first"))?;

    // ── 6. 부트 스텁 배치 ────────────────────────────────────────────────────
    // v6: --iat-hide 리졸브 테이블.
    // v9: crypto-off에서는 **런으로 등록하지 않고** 평문으로 둔다 (스텁이 직접 읽음).
    let iat_table_blob: Vec<u8> = if ctx.iat_hide && !ctx.original_imports.is_empty() {
        // v10: slot은 절대 VA (image_base + RVA) — 부트 스텁이 [slot]에 기록
        crate::pipeline::iat_hide::build_resolve_table(
            &ctx.original_imports,
            image_base,
            ctx.mba_constant,
            IMPORT_MBA_C,
        )
    } else {
        Vec::new()
    };
    // The IAT blob is already canonically sealed record-by-record by
    // iat_hide. Do not layer it onto the payload cipher's continuous stream:
    // that coupled import resolution to unrelated code/run stream position.
    let table_is_run = false;
    let total_num_runs = runs.len() + usize::from(table_is_run);
    let num_runs_u32 = total_num_runs as u32;

    // ── M6 Phase-2 (--vm-oep): 프로그램 리프트를 1회 수행 ──────────────────────
    // 프로그램 VM 바이트코드와 함께, 원본 entry 블록이 제외(네이티브)인지 여부를
    // 여기서 확정해 부트 스텁의 clean-native-entry 분기(아래)와 프로그램 VM 모듈
    // 양쪽에 동일한 값을 준다. 1st/2nd 패스 스텁이 같은 값을 쓰므로
    // `assert_eq!(stub_code.len(), stub_code_len)` 불변식이 유지된다.
    // (리프트 본체는 `lift::lift_program` — 위에서 호출됨)
    if vm_oep_effective {
        println!(
            "[+] --vm-oep: program entry block {}virtualized ({} bytes bytecode)",
            if vm_oep_native_entry { "NOT " } else { "" },
            vm_prog_bytecode.len()
        );
        // ── [VM-OEP-DIAG] 실제 타깃의 진단 (once.rs:166 원인 판별) ────────────
        //   entry_native=true  : OEP(mainCRTStartup)가 VM화 제외 → clean native OEP
        //                        점프. Program VM은 OEP를 실행하지 않는다.
        //   entry_native=false : OEP가 VM화됨 → Program VM이 OEP를 실행 → native_call
        //                        bridge가 CRT entry를 호출 → once.rs:166 크래시 가능.
        //   → 이 값이 곧 1순위 가설(entry_native)의 정답이다.
        println!("[VM-OEP-DIAG] EP             = 0x{:X}", oep_va);
        println!("[VM-OEP-DIAG] entry_native   = {}", vm_oep_native_entry);
        println!(
            "[VM-OEP-DIAG] bytecode       = {} bytes (blocks={})",
            vm_prog_bytecode.len(),
            if vm_oep_native_entry {
                "n/a (OEP native)"
            } else {
                "n/a"
            }
        );
        println!(
            "[VM-OEP-DIAG] route          = {}",
            if vm_oep_native_entry {
                "boot → native OEP → CRT → Once (Program VM 실행 안 함)"
            } else {
                "boot → Program VM → native_call → CRT → Once"
            }
        );
        // STATE_SP 진단 (single-stack fix): boot stub는 vreg[4]=RSP를 스택 포인터로
        // 쓴다. 이제 CALL32/RET/PUSH/POP가 vreg[4]로 실제 스택을 공유하므로, 과거
        // STATE_SP=0 + STATE_PTR_STACK=RSP가 별도 오프셋 스택을 만들어 OEP 프레임과
        // 겹치던 (스택 오염) 문제가 제거되었다. [VM-OEP-DIAG] STATE_SP/PTR_STACK 미사용 (vreg[4]=RSP).
    }

    // The retired descriptor cipher is disabled; C1/ChaCha use their native
    // state and the existing immediate-backed target metadata.
    let desc_used = false;
    let stub = BootStubCtx {
        desc_va: 0,
        desc_size: 0,
        desc_used,
        boot_va,
        anti_debug,
        dispatcher_va: dispatcher_va + 0x20,
        code_va: dispatcher_va + code_start as u64,
        code_len,
        runs_va: 0, // 아래에서 채움
        num_runs: num_runs_u32,
        seed_va: 0, // 아래에서 채움
        k1,
        k2,
        k3,
        entry_block_id: ctx.entry_block_id as u32,
        entry_seed: ctx.entry_seed,
        vm: vm_effective,
        chained: chained_effective,
        reencrypt,
        no_crypto,
        // 1st pass: VM 엔트리 타깃은 rel32 범위 안의 자리표시자 사용
        // (dispatcher_va는 부트 영역과 같은 섹션 — 거리 항상 i32 범위).
        vm_entry_va: if vm_effective { dispatcher_va } else { 0 },
        vm_state_va: 0, // imm64 라 길이 불변 — 0으로 두고 아래에서 채움
        vm_prga: vm_effective,
        vm_prga_entry_va: if vm_effective { dispatcher_va } else { 0 },
        vm_prga_state_va: 0, // imm64 라 길이 불변 — 0으로 두고 아래에서 채움
        // M6 Phase-2: 프로그램 VM (OEP→VM entry)
        vm_oep: vm_oep_effective,
        vm_prog_entry_va: if vm_oep_effective { dispatcher_va } else { 0 },
        vm_prog_state_va: 0, // imm64 라 길이 불변 — 0으로 두고 아래에서 채움
        vm_prog_runtime_layout_seed: vm_commercial.then_some(
            ctx.vm_multi_family
                .as_ref()
                .and_then(|multi| {
                    let entry = ctx.vm_family_plan.as_ref()?.entry_family;
                    multi
                        .modules
                        .iter()
                        .find(|module| module.family == entry)
                        .map(|module| module.module_domain)
                })
                .unwrap_or(ctx.poly_vm_seed),
        ),
        vm_oep_native_entry: vm_oep_native_entry,
        vm_oep_native_va: oep_va,
        // M6 Phase-2.3 at-rest: VM bytecode VA/길이 (imm — 최종 패스에서 채움)
        vm_oep_bc_va: 0,
        vm_oep_bc_len: 0,
        vm_oep_text_runs_va: 0,
        vm_oep_text_runs_count: 0,
        // payload_va/crc_va는 imm64라 길이 불변 — 최종 패스(stub3)에서 채운다.
        payload_va: 0,
        payload_len: if payload_relocate && (code_len > 0 || !vm_prog_bytecode.is_empty()) {
            code_len.max(1)
        } else {
            0
        },
        integrity: integrity_effective,
        crc_va: 0,
        mac_va: 0,
        crc2_va: 0,
        crc3_va: 0,
        crc4_va: 0,
        w32_slot_va: 0,
        iat_enabled: !iat_table_blob.is_empty(),
        mba_master: ctx.mba_constant,
        mba_c: IMPORT_MBA_C,
        iat_table_va: 0,
        iat_ll_slot_va: 0,
        iat_gpa_slot_va: 0,
        mem_harden: ctx.mem_harden,
        mem_ntdll_name_va: 0,
        mem_ntprot_name_va: 0,
        mem_code_base: 0,
        mem_code_size: 0,
        mem_state_base: 0,
        mem_state_size: 0,
        // Win64 entry에서 RSP는 16-byte 경계보다 8만큼 어긋나 있다. 8 mod 16인
        // 프레임을 빼야 VM/native helper CALL 직전 RSP가 16-byte 정렬된다.
        stack_frame: if ctx.iat_hide || ctx.mem_harden {
            0x138
        } else {
            0x118
        },
        // v60/v63 (--custom-cipher / --crypto-mode): 선택된 crypto primitive
        // (1st pass 자리표시자 — stub2/3에서 확정)
        crypto_mode,
        // c1_blob_va는 rel32 `call` 타깃이라 패스1에서 유효한 in-range 자리표시자
        // (dispatcher_va)를 써야 BlockEncoder가 측정/인코딩에 실패하지 않는다.
        // (0이면 diff가 i32를 벗어나 "Branch distance is too far away" — VM 엔트리와 동일 방침)
        c1_blob_va: if c1_mode { dispatcher_va } else { 0 },
        c1_state_va: 0,
        // v63: ChaCha20 blob도 rel32 call 타깃 — 동일한 자리표시자 방침.
        chacha_blob_va: if chacha_mode { dispatcher_va } else { 0 },
        chacha_state_va: 0,
        // ── T3-1 Phase D: Poly1305 AEAD (chacha 경로) — 1st pass 자리표시자 ──
        chacha_aead: chacha_mode && chacha_aead_tag.is_some(),
        poly_blob_va: if chacha_mode { dispatcher_va } else { 0 },
        poly_key_va: 0,
        poly_tag_va: if integrity_effective && vm_oep_effective && !chacha_mode {
            dispatcher_va
        } else {
            0
        },
    };

    // 1st pass: stub 길이 측정 (runs_va/seed_va/vm_* = 0)
    let stub_code_len = build_boot_block(&stub)?.len();

    // FIX(v3): 안티디버그 블록은 RC4 코드 **앞**에 붙는다. 과거 코드는
    // cursor = boot_off + stub_code_len (RC4 코드 길이만) 로 잡아서, --anti-debug 사용 시
    // 런 테이블/시드가 RC4 코드 꼬리(PRGA 루프 + ret 포함)를 덮어써 부트 스텁이
    // 쓰레기를 실행하고 0xC0000005로 크래시했다. 실제 스텁 전체 길이를 반영한다.
    let ad_bytes = if anti_debug {
        build_anti_debug_raw_block(anti_debug_policy)
    } else {
        Vec::new()
    };

    // ── v3-composite VM 모듈 (부트 스텁 직후 배치) ────────────────────────────
    // 바이트코드는 VA 독립적이므로 1차 sizing(VA=0)으로 크기를 확정한 뒤,
    // 최종 VA로 재생성한다. 모듈 레이아웃: [code][table][bytecode][state]
    // v61: --custom-cipher + --vm — RC4 KSA 대신 C1 상태 초기화 VM(C1Init 모드).
    let vm_plain_bc: Option<Vec<u8>> = if vm_effective && !chacha_mode {
        if c1_mode {
            Some(vm::c1::build_c1_init_bytecode())
        } else {
            Some(vm::lifter::lift_ksa(&vm::ksa::build_ksa_instructions(
                0, k1, k2, k3,
            ))?)
        }
    } else {
        None
    };
    let vm_mod: Option<vm::VmModule> = if let Some(ref bc) = vm_plain_bc {
        let mode = if c1_mode {
            vm::handlers::EntryMode::C1Init
        } else {
            vm::handlers::EntryMode::Ksa
        };
        Some(build_vm_mod(m8_mod, 0, 0, 0, bc.clone(), mode, rng)?)
    } else {
        None
    };
    // v19: PRGA VM (RC4 키스트림 생성/복호화 루프) — vm과 함께 배치.
    // 바이트코드는 VA 독립이므로 1차 sizing(VA=0)으로 크기 확정 후 최종 VA 재생성.
    // v61: --custom-cipher + --vm — 키스트림은 C1 blob이 생성하므로 PRGA VM 생략.
    let vm_prga_plain_bc: Option<Vec<u8>> = if vm_effective && !c1_mode && !chacha_mode {
        Some(vm::prga::build_prga_bytecode())
    } else {
        None
    };
    let vm_prga_mod: Option<vm::VmModule> = if let Some(ref bc) = vm_prga_plain_bc {
        Some(build_vm_mod(
            m8_mod,
            0,
            0,
            0,
            bc.clone(),
            vm::handlers::EntryMode::Prga,
            rng,
        )?)
    } else {
        None
    };
    // ── M6 Phase-2: 프로그램 VM — 원본 .text를 평문 복호화하지 않고 전체 lift된
    //    프로그램을 VM으로 실행. (OEP→VM entry 전환, --vm-oep)
    let vm_prog_plain_bc: Option<Vec<u8>> = if vm_oep_effective {
        Some(vm_prog_bytecode)
    } else {
        None
    };
    let vm_multi_family_active = vm_commercial
        && ctx
            .vm_multi_family
            .as_ref()
            .is_some_and(|multi| !multi.modules.is_empty());
    if vm_multi_family_active && !ctx.vm_prog_chunks.is_empty() {
        println!(
            "[+] P2-10 multi-family modules use independent bytecode domains; disabling the legacy single-stream M7 chunk plan"
        );
        ctx.vm_prog_chunks.clear();
    }
    let native_gateway_targets = if vm_multi_family_active {
        let targets = collect_native_gateway_targets(
            &ctx.patched_sections,
            image_base,
            ctx.vm_multi_family.as_ref().unwrap(),
            &ctx.route_required_original_targets,
        );
        println!(
            "[+] Canonical native gateway inventory: {} route/address-taken target(s)",
            targets.len()
        );
        targets
    } else {
        Vec::new()
    };
    let vm_multi_family_sizing = if vm_multi_family_active {
        let plan = ctx.vm_family_plan.as_ref().ok_or_else(|| {
            anyhow::anyhow!("multi-family materialization is missing its family plan")
        })?;
        Some(build_multi_family_prog_mod(
            ctx.vm_multi_family.as_ref().unwrap(),
            plan.entry_family,
            plan.entry_function,
            0,
            0,
            ctx.m7,
            image_base,
            ctx.poly_vm_seed,
            &ctx.vm_data_lifetime_objects,
            &native_gateway_targets,
        )?)
    } else {
        None
    };
    let vm_prog_mod: Option<vm::VmModule> = if let Some(multi) = &vm_multi_family_sizing {
        Some(multi.module.clone())
    } else if let Some(ref bc) = vm_prog_plain_bc {
        // use the lift computed above (before the 1st-pass stub) so the entry
        // decision and the module bytecode come from the same single lift.
        let m = build_prog_vm_mod(
            vm_commercial,
            ctx.poly_vm_seed,
            0,
            0,
            0,
            bc.clone(),
            0,
            vm_prog_ip_map.as_ref(),
            vm_prog_superops.as_ref(),
            &ctx.vm_prog_chunks,
            ctx.vm_family_plan.as_ref().map(|plan| plan.entry_family),
            m8_mod,
            rng,
        )?;
        println!(
            "[DEBUG pass1 vm_prog_mod] code={} table={} bc={} total={}",
            m.code.len(),
            m.table.len(),
            m.bytecode.len(),
            m.total_len()
        );
        Some(m)
    } else {
        None
    };

    let mut cursor = boot_off + stub_code_len + ad_bytes.len();
    if vm_mod.is_some() {
        cursor = (cursor + 15) & !15; // align 16 (VM 모듈 시작)
    } else {
        cursor = (cursor + 7) & !7; // align 8 (원래 레이아웃 유지)
    }

    // ── v60 (--custom-cipher): BTG-C1 blob + S-box + 상태 영역 배치 ────────────
    // BTG-C1 crypt blob(완전 전개 네이티브 라운드)을 스텁 직후에 두고, 그 뒤에
    // 256B S-box 상수 테이블(패커가 기록)과 0x80B 상태 버퍼(스텁이 초기화)를 붙인다.
    // blob 길이는 imm64/rel32만 써서 VA와 무관(고정) — 1차 sizing에서 확정 가능.
    let mut c1_blob_off = 0usize;
    let mut c1_sbox_off = 0usize;
    let mut c1_state_off = 0usize;
    let c1_blob_len = if c1_mode {
        let len = crate::crypto::native::emit_btg_crypt_blob(0, 0).len();
        c1_blob_off = cursor;
        c1_sbox_off = c1_blob_off + len;
        c1_state_off = c1_sbox_off + 256;
        len
    } else {
        0
    };
    let c1_blob_va = if c1_mode {
        dispatcher_va + c1_blob_off as u64
    } else {
        0
    };
    let c1_sbox_va = if c1_mode {
        dispatcher_va + c1_sbox_off as u64
    } else {
        0
    };
    let c1_state_va = if c1_mode {
        dispatcher_va + c1_state_off as u64
    } else {
        0
    };
    let c1_end = if c1_mode {
        c1_state_off + C1_STATE_SIZE
    } else {
        cursor
    };
    cursor = c1_end;

    // ── v63 (--crypto-mode chacha20): ChaCha20 crypt blob + 상태 영역 배치 ──────
    // RFC 8439 네이티브 blob(완전 전개 20 라운드)을 스텁 직후에 두고, 그 뒤에
    // 0x80B 상태 버퍼(key/ctr/nonce/ks/ks_off — 스텁 emit_chacha_init이 초기화)를
    // 붙인다. blob 길이는 imm64/rel32만 써서 VA와 무관(고정) — 1차 sizing 확정.
    let mut chacha_blob_off = 0usize;
    let mut chacha_state_off = 0usize;
    let chacha_blob_len = if chacha_mode {
        let len = crate::crypto::chacha20_native::emit_chacha20_blob(0).len();
        chacha_blob_off = cursor;
        chacha_state_off = chacha_blob_off + len;
        len
    } else {
        0
    };
    let chacha_blob_va = if chacha_mode {
        dispatcher_va + chacha_blob_off as u64
    } else {
        0
    };
    let chacha_state_va = if chacha_mode {
        dispatcher_va + chacha_state_off as u64
    } else {
        0
    };
    let chacha_end = if chacha_mode {
        chacha_state_off + crate::crypto::chacha20::CHA_STATE_SIZE
    } else {
        cursor
    };
    cursor = chacha_end;

    // ── T3-1 Phase D (--crypto-mode chacha20 + AEAD): Poly1305 blob + 키/태그 ──
    // RFC 8439 네이티브 Poly1305 verify blob을 chacha 상태 버퍼 뒤에 배치하고,
    // 그 뒤에 32B runtime key scratch와 16B AEAD 태그를 붙인다. scratch는 파일에서
    // zero이며 런타임 block 0 파생 직후 검증에만 사용하고 즉시 소거한다.
    // VA 무관(고정) — 1차 sizing에서 확정 가능.
    let mut poly_blob_off = 0usize;
    let mut poly_key_off = 0usize;
    let mut poly_tag_off = 0usize;
    let poly_blob_len = if chacha_mode {
        let len = crate::crypto::poly1305_native::emit_poly1305_verify_blob(0).len();
        poly_blob_off = cursor;
        poly_key_off = poly_blob_off + len;
        poly_tag_off = poly_key_off + 32;
        len
    } else {
        0
    };
    let poly_blob_va = if chacha_mode {
        dispatcher_va + poly_blob_off as u64
    } else {
        0
    };
    let poly_key_va = if chacha_mode {
        dispatcher_va + poly_key_off as u64
    } else {
        0
    };
    let poly_tag_va = if chacha_mode {
        dispatcher_va + poly_tag_off as u64
    } else if integrity_effective && vm_oep_effective {
        dispatcher_va
    } else {
        0
    };
    let poly_end = if chacha_mode {
        poly_tag_off + 16
    } else {
        cursor
    };
    cursor = poly_end;

    let vm_off = cursor;
    let (vm_entry_va, vm_state_va, vm_total) = if let Some(m) = &vm_mod {
        let state_va =
            dispatcher_va + (vm_off + m.code.len() + m.table.len() + m.bytecode.len()) as u64;
        (dispatcher_va + vm_off as u64, state_va, m.total_len())
    } else {
        (0, 0, 0)
    };
    cursor += vm_total;
    cursor = (cursor + 7) & !7; // align 8

    // v19: PRGA VM을 KSA VM 바로 뒤에 배치 (각각 독립 state 버퍼)
    let vm_prga_off = cursor;
    let (vm_prga_entry_va, vm_prga_state_va, vm_prga_total) = if let Some(m) = &vm_prga_mod {
        let sva =
            dispatcher_va + (vm_prga_off + m.code.len() + m.table.len() + m.bytecode.len()) as u64;
        (dispatcher_va + vm_prga_off as u64, sva, m.total_len())
    } else {
        (0, 0, 0)
    };
    cursor += vm_prga_total;
    cursor = (cursor + 7) & !7; // align 8

    // Windows invokes TLS callbacks before the PE entry point.  Under complete
    // commercial ownership the original `.text` is deliberately NX from the
    // loader's first mapping, so leaving callback-array entries pointed at the
    // original functions would fault before the boot stub can run.  Keep a
    // generated pre-entry lifecycle gateway in the executable immutable area.
    //
    // Rust's TLS callback is attach-neutral (PROCESS_ATTACH/THREAD_ATTACH take
    // the immediate return path); its detach path only drains process/thread
    // destructor bookkeeping.  The OS is already tearing the corresponding
    // lifetime down, so the pre-entry gateway is intentionally a leaf `ret`.
    // This removes native `.text` execution without weakening the static W^X
    // contract.  A future callable-VM TLS ABI can replace the leaf while
    // retaining the same typed callback-slot relocation point.
    let tls_gateway_slots: Vec<u32> = if vm_oep_effective && vm_commercial {
        ctx.target_info
            .tls
            .as_ref()
            .map(|tls| tls.callbacks.iter().map(|cb| cb.slot_rva).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let tls_gateway_off = if tls_gateway_slots.is_empty() {
        None
    } else {
        let off = cursor;
        cursor += 1; // RET
        cursor = (cursor + 7) & !7;
        Some(off)
    };

    // ── M6 Phase-2: 프로그램 VM을 KSA/PRGA VM 뒤에 배치 (각각 독립 state) ──────
    let vm_prog_off = cursor;
    let (vm_prog_entry_va, vm_prog_state_va, vm_prog_total) = if let Some(m) = &vm_prog_mod {
        // P1-5: keep mutable Program-VM state on a page that does not overlap
        // generated code, immutable tables, or ciphertext bytecode.  This lets
        // mem-harden seal the preceding pages RX without making state writes
        // fault.  The zero-filled alignment gap is intentional.
        let immutable_end = vm_prog_off + m.code.len() + m.table.len() + m.bytecode.len();
        let state_off = (immutable_end + 0xFFF) & !0xFFF;
        let sva = dispatcher_va + state_off as u64;
        let entry_gateway_off = vm_multi_family_sizing
            .as_ref()
            .map(|multi| multi.canonical_entry_gateway_offset)
            .unwrap_or(0);
        (
            dispatcher_va + vm_prog_off as u64 + entry_gateway_off as u64,
            sva,
            state_off - vm_prog_off
                + if let Some(multi) = &vm_multi_family_sizing {
                    multi.invocation_layout.reserve_size
                } else {
                    vm::VM_STATE_SIZE
                },
        )
    } else {
        (0, 0, 0)
    };
    // reserve the dedicated bytecode return-IP stack (CALL_STACK_SIZE) for the program VM
    cursor += vm_prog_total
        + if vm_prog_mod.is_some() && !vm_multi_family_active {
            crate::vm::interp::CALL_STACK_SIZE
        } else {
            0
        };
    cursor = (cursor + 7) & !7; // align 8

    // Reserve a stable in-image ABI for 4 families × code/table/bytecode.
    // The exact count is written after final M7 bytes have been sealed.
    const MAX_VM_INTEGRITY_DESCRIPTORS: usize = 12;
    let vm_integrity_table_off = cursor;
    let vm_integrity_table_capacity = if integrity_effective && vm_multi_family_active {
        vm::distributed_integrity::SERIALIZED_TABLE_HEADER_SIZE
            + MAX_VM_INTEGRITY_DESCRIPTORS * vm::distributed_integrity::SERIALIZED_DESCRIPTOR_SIZE
    } else {
        0
    };
    cursor += vm_integrity_table_capacity;
    cursor = (cursor + 7) & !7;
    ctx.vm_integrity_table_rva = if vm_integrity_table_capacity > 0 {
        dispatcher_rva + vm_integrity_table_off as u32
    } else {
        0
    };
    ctx.vm_integrity_table_len = 0;

    // ── P4 (전체 SEH 가상화): Program VM 모듈 위치를 ctx에 기록 — build.rs가
    // .pdata 브리지 UNWIND_INFO로 이 영역을 커버해 OS unwinder가 VM 내부 프레임을
    // (더미 핸들러 대신) 결정적으로 걷게 한다. ---------------------------------
    ctx.vm_prog_rva = if vm_prog_mod.is_some() {
        dispatcher_rva.saturating_add(vm_prog_off as u32)
    } else {
        0
    };
    ctx.vm_prog_total = vm_prog_total as u32;

    // Executable-route inventory only exists when a `.vmroute` image was
    // actually staged. A commercial VM can legitimately have no proven
    // indirect targets, in which case `build_commercial_routes()` returns
    // `None` and no route metadata section should exist at all.
    let route_metadata_active = ctx.route_metadata_section_data.is_some();
    if route_metadata_active != !ctx.route_required_original_targets.is_empty() {
        anyhow::bail!(
            "canonical route metadata staging/inventory lifecycle mismatch"
        );
    }
    ctx.route_generated_executable_ranges =
        if route_metadata_active && ctx.vm_prog_rva != 0 && ctx.vm_prog_total != 0 {
            vec![crate::vm::route_metadata::RvaSpan {
                start: ctx.vm_prog_rva,
                end: ctx.vm_prog_rva.saturating_add(ctx.vm_prog_total),
            }]
        } else {
            Vec::new()
        };
    ctx.route_generated_destinations.clear();
    if route_metadata_active {
        let sizing = vm_multi_family_sizing.as_ref().ok_or_else(|| {
            anyhow::anyhow!("canonical route metadata has no placed multi-family VM module")
        })?;
        let program = ctx.vm_multi_family.as_ref().ok_or_else(|| {
            anyhow::anyhow!("canonical route metadata has no materialized multi-family program")
        })?;
        let metadata = ctx.route_metadata_section_data.as_ref().ok_or_else(|| {
            anyhow::anyhow!("canonical route inventory exists without serialized metadata")
        })?;
        let routes = crate::vm::route_table::MaterializedRouteTable::from_metadata(
            &metadata.bytes,
            ctx.route_required_original_targets.len(),
            metadata.bytes.len(),
        )?;
        for original in &ctx.route_required_original_targets {
            let route = routes.lookup(*original)?;
            let family_index = sizing
                .families
                .iter()
                .position(|family| *family == route.family)
                .ok_or_else(|| {
                    anyhow::anyhow!("route target {:?} has no placed family", original)
                })?;
            let module = program
                .modules
                .iter()
                .find(|module| module.family == route.family)
                .ok_or_else(|| {
                    anyhow::anyhow!("route target {:?} has no encoded family", original)
                })?;
            let local_op = usize::try_from(route.entry_vip.0).map_err(|_| {
                anyhow::anyhow!("route target {:?} entry VIP overflows usize", original)
            })?;
            let byte_offset = *module.instruction_offsets.get(local_op).ok_or_else(|| {
                anyhow::anyhow!(
                    "route target {:?} entry VIP is outside encoded family",
                    original
                )
            })?;
            let destination_rva = ctx
                .vm_prog_rva
                .checked_add(sizing.code_ranges[family_index].0 as u32)
                .and_then(|rva| rva.checked_add(byte_offset as u32))
                .ok_or_else(|| {
                    anyhow::anyhow!("route target {:?} destination RVA overflow", original)
                })?;
            ctx.route_generated_destinations.push(
                crate::vm::route_metadata::GeneratedRouteDestination {
                    original: *original,
                    destination_rva,
                },
            );
        }
    }
    ctx.vm_prog_native_bridge = vm_prog_mod
        .as_ref()
        .and_then(|m| m.native_bridge_range.map(|(s, e)| (s as u32, e as u32)));
    ctx.vm_prog_native_bridges = if let Some(multi) = &vm_multi_family_sizing {
        multi
            .native_bridge_ranges
            .iter()
            .map(|(start, end)| (*start as u32, *end as u32))
            .collect()
    } else {
        ctx.vm_prog_native_bridge.into_iter().collect()
    };
    ctx.vm_prog_lifetime_cleanup_handler_rva = if let Some(multi) = &vm_multi_family_sizing {
        multi
            .lifetime_cleanup_handler_offset
            .map(|offset| ctx.vm_prog_rva.saturating_add(offset as u32))
            .unwrap_or(0)
    } else {
        vm_prog_mod
            .as_ref()
            .and_then(|module| module.lifetime_cleanup_handler_offset)
            .map(|offset| ctx.vm_prog_rva.saturating_add(offset as u32))
            .unwrap_or(0)
    };

    // ── M6 Phase-2.3: at-rest 암호화 대상 확정 ──────────────────────────────
    // Program VM bytecode offset/len (boot area — .textb는 이미 RWX라 in-place 복호화 가능)
    let vm_prog_bc_len = if vm_oep_effective {
        vm_prog_mod
            .as_ref()
            .map(|m| m.bytecode.len() as u32)
            .unwrap_or(0)
    } else {
        0
    };
    let vm_prog_bc_off = if vm_prog_bc_len > 0 {
        let m = vm_prog_mod
            .as_ref()
            .expect("T3-3: vm_prog_bc_len > 0 implies vm_prog_mod is Some (checked above)");
        vm_prog_off + m.code.len() + m.table.len()
    } else {
        0
    };
    let vm_prog_bc_va = if vm_prog_bc_len > 0 {
        dispatcher_va + vm_prog_bc_off as u64
    } else {
        0
    };

    // T3-3 layout invariant: the relocated Program-VM bytecode destination is
    // inside the generated .textb image and must not overlap the bootstrap data
    // that is appended after the VM module.  The old code relied on truncate()
    // sizing alone, which could hide a bad cursor calculation until runtime.
    if vm_prog_bc_len > 0 {
        let bc_end = vm_prog_bc_off
            .checked_add(vm_prog_bc_len as usize)
            .ok_or_else(|| anyhow::anyhow!("Program-VM bytecode destination overflow"))?;
        let btg_capacity_end = btg.bytes.len();
        if vm_prog_bc_off < vm_prog_off || bc_end > btg_capacity_end {
            anyhow::bail!(
                "Program-VM bytecode layout invalid: bc=[0x{:X},0x{:X}) vm=[0x{:X},0x{:X}) section=0x{:X}",
                vm_prog_bc_off, bc_end, vm_prog_off, vm_prog_off + vm_prog_total, btg_capacity_end
            );
        }
        // The bytecode itself is allowed to sit inside the VM module, but it
        // must not run beyond the module's immutable payload portion.
        let immutable_end = vm_prog_off
            .checked_add(
                vm_prog_mod
                    .as_ref()
                    .map(|m| m.code.len() + m.table.len() + m.bytecode.len())
                    .unwrap_or(0),
            )
            .ok_or_else(|| anyhow::anyhow!("Program-VM immutable layout overflow"))?;
        if bc_end > immutable_end {
            anyhow::bail!(
                "Program-VM bytecode exceeds module immutable payload: bc_end=0x{:X} immutable_end=0x{:X}",
                bc_end, immutable_end
            );
        }
    }
    ctx.vm_prog_bytecode_rva = vm_prog_bc_va.saturating_sub(image_base) as u32;
    ctx.vm_prog_bytecode_len = vm_prog_bc_len;
    // 보존 원본 .text at-rest 암호화는 실제 실행되는 TLS 콜백이 없는 타깃에서 활성화.
    // TLS 디렉터리 내 AddressOfCallBacks가 가리키는 콜백 배열이 존재하지 않으면
    // 로더가 사전 실행하는 콜백이 없으므로 .text 전체를 안전하게 100% 암호화한다.
    let has_tls_cb = ctx
        .target_info
        .data_directories
        .get(9)
        .map(|dir| {
            if dir.virtual_address == 0 || dir.size < 0x20 {
                return false;
            }
            ctx.patched_sections.iter().any(|sec| {
                if dir.virtual_address < sec.virtual_address {
                    return false;
                }
                let off = (dir.virtual_address - sec.virtual_address) as usize;
                off + 0x20 <= sec.bytes.len()
                    && sec.bytes[off + 0x18..off + 0x20]
                        .try_into()
                        .ok()
                        .map(|b: [u8; 8]| u64::from_le_bytes(b) != 0)
                        .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    // P5: partial .text at-rest encryption — encrypt every `.text` region EXCEPT
    // the TLS-callback-reachable function ranges (the loader runs those before
    // the boot stub, so they must stay plaintext on disk). The complement of
    // `detect_tls_callback_ranges` within `.text` becomes the encryptable runs,
    // decrypted by the boot stub (fresh RC4(seed)) in the same order before the
    // program-VM bytecode. No TLS callbacks -> a single run over the whole
    // `.text` (identical to the previous whole-region behaviour).
    let mut text_enc_runs: Vec<(u64, u32)> = Vec::new(); // (VA, len)
    // A PE with TLS callbacks must not have its original .text encrypted at rest: the
    // Windows loader invokes TLS callbacks before our boot stub has a chance to decrypt
    // anything.  Keep the whole .text plaintext for this case; VM-OEP still protects
    // the actual OEP path through the Program VM, while native TLS/CRT startup remains
    // loader-safe.  The previous code computed `has_tls_cb` but did not use it to gate
    // the encryption pass, so `--crypto-coverage 100` could encrypt loader-reachable
    // code and trigger an immediate c0000005 before OEP.
    if vm_oep_effective && !ctx.mem_harden && !has_tls_cb {
        let base_va = image_base + ctx.target_info.text_rva as u64;
        let excl = crate::vm::text_lift::detect_tls_callback_ranges(
            &ctx.target_info.text_bytes,
            base_va,
            image_base,
            &ctx.patched_sections,
            &ctx.target_info.data_directories,
        );
        if let Some(sec) = ctx.patched_sections.iter().find(|s| s.name == ".text") {
            let sec_start = image_base + sec.virtual_address as u64;
            let sec_end = sec_start + sec.bytes.len() as u64;
            let mut ranges = excl.func_ranges.clone();
            ranges.sort_by_key(|r| r.0);
            let mut cursor = sec_start;
            for (s, e) in ranges {
                let s = s.max(sec_start);
                let e = e.min(sec_end);
                if s >= e {
                    continue;
                }
                if s > cursor {
                    text_enc_runs.push((cursor, (s - cursor) as u32));
                }
                cursor = cursor.max(e);
            }
            if cursor < sec_end {
                text_enc_runs.push((cursor, (sec_end - cursor) as u32));
            }
        }
    }
    let text_enc = vm_oep_effective && !text_enc_runs.is_empty();
    let text_enc_total: u64 = text_enc_runs.iter().map(|&(_, l)| l as u64).sum();
    if vm_oep_effective {
        println!(
            "[+] --vm-oep at-rest: Program VM bytecode {}",
            if vm_prog_bc_len > 0 {
                format!("encrypted ({}B)", vm_prog_bc_len)
            } else {
                "(no bytecode)".to_string()
            }
        );
        if text_enc && !text_enc_runs.is_empty() {
            println!(
                "[+] --vm-oep at-rest: preserved .text encrypted in {} run(s), {}B total (TLS-callback funcs kept plaintext)",
                text_enc_runs.len(), text_enc_total
            );
        } else if ctx.mem_harden {
            println!("[+] --mem-harden: preserved .text remains RX; at-rest encryption is confined to relocated Program-VM payload");
        } else if has_tls_cb {
            println!("[!] --vm-oep at-rest: TLS callbacks present; preserving the entire .text plaintext for loader safety");
        }
    }
    // v16: 패킹당 레이아웃 난독화 — 부트 스텁/시드/문자열/리졸브 테이블의 절대
    // VMA를 빌드마다 랜덤 이동시켜, 정적 분석 스크립트가 하드코딩한 오프셋을
    // (0x1400143b0 등) 매 빌드 무력화한다. rng는 이 함수에서 이미 생성됨.
    let layout_pad = (rng.next_u32() as usize) & 0x3FF; // 0..1023 바이트
    cursor += layout_pad;
    cursor = (cursor + 7) & !7; // align 8
    let runs_off = cursor;
    let runs_va = dispatcher_va + (runs_off + 8) as u64;
    cursor += 8 + total_num_runs * 16; // header(8) + entries (v6: 리졸브 테이블 run 포함)
    cursor = (cursor + 7) & !7; // align 8
    let seed_off = cursor;
    let seed_va = dispatcher_va + seed_off as u64;

    // ── P5: .text at-rest decrypt run-table (va,len u64 pairs) ────────────────
    // P5: .text at-rest decrypt run-table is only emitted when there is >=1 at-rest
    // run; otherwise the boot stub sees count==0 and no-ops (no file table written).
    let text_runs_block = if text_enc_runs.is_empty() {
        0
    } else {
        8 + text_enc_runs.len() * 16
    };
    // ── M12 Decrypt-Descriptor: 정적 RC4 decrypt target/size/bytecode/table 주소를
    // 부트 스텁 imm으로 노출하지 않고, 파생 키(RC4 keystream — 키 유도 계층)로 암호화한
    // 작은 디스크립터를 부트 데이터 영역에 저장한다. 부트 스텁이 KSA(키 유도) 직후 이
    // 디스크립터를 PRGA로 복호화하고, 이어지는 코드/런/바이트코드 복호화가 그 값들을
    // 메모리([R13+off])에서 읽는다 → 정적 분석으로 target/size가 노출되지 않는다.
    // 레이아웃 (전부 u64, little-endian):
    //   +0x00 code_va, +0x08 code_len, +0x10 runs_va, +0x18 num_runs,
    //   +0x20 vm_oep_bc_va, +0x28 vm_oep_bc_len, +0x30 vm_oep_text_runs_va,
    //   +0x38 vm_oep_text_runs_count.
    const DESC_OFF_CODE_VA: usize = 0x00;
    const DESC_OFF_CODE_LEN: usize = 0x08;
    const DESC_OFF_RUNS_VA: usize = 0x10;
    const DESC_OFF_NUM_RUNS: usize = 0x18;
    const DESC_OFF_BC_VA: usize = 0x20;
    const DESC_OFF_BC_LEN: usize = 0x28;
    const DESC_OFF_TEXT_RUNS_VA: usize = 0x30;
    const DESC_OFF_TEXT_RUNS_COUNT: usize = 0x38;
    const DESC_SIZE: usize = 0x40;
    let desc_off = (seed_off
        + 256
        + if integrity_effective {
            4 + 8 + 4 + 4 + 4 + 4
        } else {
            0
        }
        + 7)
        & !7;
    let desc_size = DESC_SIZE as u32;
    let desc_va = dispatcher_va + desc_off as u64;
    let text_runs_off = (desc_off + DESC_SIZE + 7) & !7;
    let text_runs_va = if text_enc_runs.is_empty() {
        0
    } else {
        dispatcher_va + (text_runs_off + 8) as u64
    };
    let text_runs_count = text_enc_runs.len() as u32;

    // ── v6: 더미 import / 리졸브 테이블 / mem 문자열 배치 (crc 뒤) ───────────
    let iat_start = text_runs_off + text_runs_block;
    let mut iat_cursor = iat_start;
    let original_bootstrap_slot = |wanted: &str| {
        ctx.original_imports.iter().find_map(|imp| match &imp.func {
            crate::pipeline::iat_hide::FuncRef::Name(name) if name.eq_ignore_ascii_case(wanted) => {
                Some(imp.slot_rva)
            }
            _ => None,
        })
    };
    let original_ll = original_bootstrap_slot("LoadLibraryA");
    let original_gpa = original_bootstrap_slot("GetProcAddress");
    // Synthetic/unit-test images may have no import directory at all. Keep the
    // self-contained dummy bootstrap for those; real mem-only images retain
    // their original loader-owned import directory.
    if ctx.mem_harden
        && !ctx.iat_hide
        && !ctx.original_imports.is_empty()
        && (original_ll.is_none() || original_gpa.is_none())
    {
        anyhow::bail!("--mem-harden requires LoadLibraryA and GetProcAddress bootstrap imports when preserving the original IAT");
    }
    // An empty cached import inventory is not proof that the target has no
    // imports. main populates original_imports only when IAT hiding or
    // mem-harden actually needs it. Installing a dummy directory merely because
    // this cache is empty replaces the target's loader-owned Import Directory;
    // the original IAT then remains full of IMAGE_IMPORT_BY_NAME RVAs.
    let needs_dummy_bootstrap =
        ctx.iat_hide || (ctx.mem_harden && ctx.original_imports.is_empty());
    // The dummy directory belongs exclusively to IAT hiding.  Mem-harden by
    // itself must retain the loader-populated original IAT (notably for TLS
    // callbacks that run before OEP).
    let (dummy_blob0, _, _, _, _) = if needs_dummy_bootstrap {
        crate::pipeline::iat_hide::build_dummy_import_block(0)
    } else {
        (Vec::new(), 0, 0, 0, 0)
    };
    // The Windows loader populates the bootstrap IAT before OEP.  Put it in a
    // dedicated RW, non-executable section instead of the RX `.textb` image.
    let dummy_off = 0usize;
    let section_alignment = ctx.target_info.section_alignment.max(0x1000);
    let align_section = |value: u32| value.div_ceil(section_alignment) * section_alignment;
    let dummy_base_rva =
        align_section(dispatcher_rva.saturating_add(btg.bytes.len().max(1) as u32));
    let (dummy_blob, dummy_dir_rva, dummy_dir_size, iat_ll_slot_rva, iat_gpa_slot_rva) =
        if needs_dummy_bootstrap {
            crate::pipeline::iat_hide::build_dummy_import_block(dummy_base_rva)
        } else if ctx.mem_harden {
            let ll = original_ll.expect("bootstrap presence checked above");
            let gpa = original_gpa.expect("bootstrap presence checked above");
            (Vec::new(), 0, 0, ll, gpa)
        } else {
            // Ordinary Program-VM builds do not own import resolution. Leave
            // the target's Import Directory/IAT entirely loader-owned.
            (Vec::new(), 0, 0, 0, 0)
        };
    debug_assert_eq!(dummy_blob.len(), dummy_blob0.len());
    ctx.bootstrap_iat_section_data = if dummy_blob.is_empty() {
        None
    } else {
        Some(crate::pe::builder::SectionData {
            name: ".idata".to_string(),
            virtual_address: dummy_base_rva,
            virtual_size: dummy_blob.len() as u32,
            characteristics: 0xC000_0040, // INITIALIZED_DATA | READ | WRITE
            bytes: dummy_blob.clone(),
        })
    };
    let table_off = if !iat_table_blob.is_empty() {
        let off = iat_cursor;
        iat_cursor += iat_table_blob.len();
        off
    } else {
        0
    };
    let mut mem_ntdll_va = 0u64;
    let mut mem_ntprot_va = 0u64;
    let mut mem_off = 0usize;
    if ctx.mem_harden {
        mem_off = iat_cursor;
        mem_ntdll_va = dispatcher_va + iat_cursor as u64;
        iat_cursor += b"ntdll.dll\0".len();
        mem_ntprot_va = dispatcher_va + iat_cursor as u64;
        iat_cursor += b"NtProtectVirtualMemory\0".len();
    }
    let iat_end = iat_cursor;

    // v6: 더미 import 디렉터리/슬롯/테이블/문자열 RVA·VA 기록 (build.rs/validate가 사용)
    if ctx.iat_hide || ctx.mem_harden {
        if ctx.iat_hide {
            ctx.iat_dir_rva = dummy_dir_rva;
            ctx.iat_dir_size = dummy_dir_size;
        }
        ctx.iat_ll_slot_rva = iat_ll_slot_rva;
        ctx.iat_gpa_slot_rva = iat_gpa_slot_rva;
        if !iat_table_blob.is_empty() {
            ctx.iat_table_rva = dispatcher_rva + table_off as u32;
            ctx.iat_table_len = iat_table_blob.len() as u32;
        }
        if ctx.mem_harden {
            ctx.mem_ntdll_name_va = mem_ntdll_va;
            ctx.mem_ntprot_name_va = mem_ntprot_va;
        }
    }

    // 2nd pass: 최종 VA 반영 (payload_va/crc_va는 imm64라 길이 불변 — 아래에서 재생성)
    let stub2 = BootStubCtx {
        runs_va,
        seed_va,
        desc_va,
        desc_size,
        vm_entry_va,
        vm_state_va,
        vm_prga_entry_va,
        vm_prga_state_va,
        vm_prog_entry_va,
        vm_prog_state_va,
        // v60: BTG-C1 blob/상태 VA (imm64/rel32 — 길이 불변)
        c1_blob_va,
        c1_state_va,
        // v63: ChaCha20 blob/상태 VA (rel32/imm64 — 길이 불변)
        chacha_blob_va,
        chacha_state_va,
        // T3-1 Phase D: Poly1305 blob/키/태그 VA (rel32/imm64 — 길이 불변)
        poly_blob_va,
        poly_key_va,
        poly_tag_va,
        ..stub
    };
    let stub_code = build_boot_block(&stub2)?;
    if stub_code.len() != stub_code_len {
        anyhow::bail!(
            "boot stub size changed after VA fixup: {} vs {}",
            stub_code.len(),
            stub_code_len
        );
    }

    // 안티디버그 블록 + RC4 블록 결합 (길이 확정용)
    let mut full_stub = Vec::with_capacity(ad_bytes.len() + stub_code.len());
    full_stub.extend_from_slice(&ad_bytes);
    full_stub.extend_from_slice(&stub_code);

    // 부트 스텁 길이 가드
    let stub_end = boot_off + full_stub.len();
    if stub_end > boot_off + BOOT_AREA_RESERVE {
        return Err(anyhow::anyhow!(
            "Boot stub too large: {} bytes (reserve {})",
            full_stub.len(),
            BOOT_AREA_RESERVE
        ));
    }

    // FIX(v3): 런 테이블/시드가 스텁 영역과 겹치지 않아야 한다 (위 cursor 수정의 방어 검사).
    // v5: --integrity 시 seed 뒤 4바이트(CRC32)까지 포함.
    let boot_data_end = if ctx.iat_hide || ctx.mem_harden {
        iat_end
    } else {
        seed_off
            + 256
            + if integrity_effective {
                4 + 8 + 4 + 4 + 4 + 4
            } else {
                0
            }
    };
    if runs_off < stub_end || boot_data_end > boot_off + BOOT_AREA_RESERVE {
        return Err(anyhow::anyhow!(
            "Boot area layout overlap: stub_end=0x{:X} runs_off=0x{:X} seed_off=0x{:X} (reserve 0x{:X})",
            stub_end, runs_off, seed_off, BOOT_AREA_RESERVE
        ));
    }

    // ── v5 용량 제어: 실제 사용분만 남기고 섹션 tail을 자른다 ──────────────────
    // (pass4가 여유 있게 예약한 BOOT_AREA_RESERVE 중 사용하지 않은 영역 제거 →
    //   raw 섹션 크기가 줄어 파일 크기 감소. .vdata도 잘린 .textb 직후에 붙는다.)
    //
    // T0-1 FIX ①: Program VM 모듈 전체(vm_prog_off + vm_prog_total + CALL_STACK_SIZE)를
    // boot_end에 포함. 기존 코드는 KSA/PRGA VM만 포함해 truncate()가 Program VM 영역을
    // 잘라버려 vm_prog_bc_off 이후가 모두 0x00이 되는 silent corruption이 발생했다.
    // CALL_STACK_SIZE(0x2000): 부트 스텁 vm_embed.rs가 Program VM state 직후에 예약하는
    // return-IP 스택 영역 — truncate가 이를 포함해야 한다.
    let vm_prog_call_stack = if vm_prog_mod.is_some() && !vm_multi_family_active {
        crate::vm::interp::CALL_STACK_SIZE
    } else {
        0
    };
    let boot_end = stub_end
        .max(c1_end)
        .max(chacha_end)
        .max(poly_end)
        .max(vm_off + vm_total)
        .max(vm_prga_off + vm_prga_total)
        .max(vm_prog_off + vm_prog_total + vm_prog_call_stack)
        .max(vm_integrity_table_off + vm_integrity_table_capacity)
        .max(runs_off + 8 + total_num_runs * 16)
        .max(text_runs_off + text_runs_block)
        .max(boot_data_end);
    let old_section_len = btg.bytes.len();
    let new_section_len = (boot_end + 0xFF) & !0xFF;
    if new_section_len < old_section_len {
        btg.bytes.truncate(new_section_len);
        btg.virtual_size = new_section_len as u32;
    }
    println!(
        "[+] v5 Size control: .textb 0x{:X} -> 0x{:X} bytes (boot area trimmed, saved {} bytes)",
        old_section_len,
        new_section_len,
        old_section_len.saturating_sub(new_section_len)
    );

    // Finalize the loader-owned import section only after `.textb` trimming.
    // Basing this RVA on pass4's large reservation left a ~63 MiB virtual gap;
    // Windows rejected that synthesized image before OEP with ERROR_BAD_EXE_FORMAT.
    let final_dummy_base_rva =
        align_section(dispatcher_rva.saturating_add(btg.bytes.len().max(1) as u32));
    let (dummy_blob, dummy_dir_rva, dummy_dir_size, iat_ll_slot_rva, iat_gpa_slot_rva) =
        if needs_dummy_bootstrap {
            crate::pipeline::iat_hide::build_dummy_import_block(final_dummy_base_rva)
        } else {
            (
                dummy_blob,
                dummy_dir_rva,
                dummy_dir_size,
                iat_ll_slot_rva,
                iat_gpa_slot_rva,
            )
        };
    if needs_dummy_bootstrap {
        ctx.iat_dir_rva = dummy_dir_rva;
        ctx.iat_dir_size = dummy_dir_size;
        ctx.iat_ll_slot_rva = iat_ll_slot_rva;
        ctx.iat_gpa_slot_rva = iat_gpa_slot_rva;
        ctx.bootstrap_iat_section_data = Some(crate::pe::builder::SectionData {
            name: ".idata".to_string(),
            virtual_address: final_dummy_base_rva,
            virtual_size: dummy_blob.len() as u32,
            characteristics: 0xC000_0040, // INITIALIZED_DATA | READ | WRITE
            bytes: dummy_blob.clone(),
        });
    }

    // `.textb`의 Rust TLS guard와 fast-fail 바이트도 그대로 둔다. 조건 분기를
    // 삭제하거나 noreturn fast-fail을 `ret`으로 바꾸면 종료 상태가 손상된다.

    // ── ud2 (0x0F 0x0B) 은 절대 NOP으로 바꾸지 않는다 ────────────────────────────
    // (v13.4c: removed the previous whole-section .textb ud2 -> nop nop sweep.)
    //
    // WHY: `ud2` is a *guaranteed* hard trap — the CPU never falls through past it.
    // Converting it to `nop nop` (0x90 0x90) silently *enables* fall-through. In a
    // block-shuffled .textb the bytes after any given ud2 belong to a completely
    // unrelated block, so `call ...; ud2; <next function>` becomes
    // `call ...; nop; nop; <next function>` — control now falls straight into the
    // next (shuffled) function, executing garbage instead of trapping. That wrong
    // instruction path is what then triggers a panic, a bogus OS unwind, a wrong
    // RSP and finally 0xC0000005.
    //
    // Leaving ud2 as-is keeps the "no fall-through" contract: if it is ever reached
    // (only on a genuine unreachable-path bug), the process faults *cleanly* at that
    // exact instruction instead of silently corrupting control flow. Any reachable
    // ud2 is a separate bug to fix at its source, not by erasing the trap.
    // (The per-block ud2 neutralization in pass4_section.rs is removed likewise.)

    // ── v4: .vdata 페이로드 섹션 VA (빌더와 동일한 정렬 규칙 — 잘린 .textb 직후) ──
    let relocated_payload_len = if code_len > 0 {
        code_len
    } else {
        vm_prog_bc_len
    };
    let payload_va: u64 = if payload_relocate && relocated_payload_len > 0 {
        let sa = if ctx.target_info.section_alignment == 0 {
            0x1000
        } else {
            ctx.target_info.section_alignment
        } as u64;
        let align = |x: u64| ((x + sa - 1) / sa) * sa;
        if !dummy_blob.is_empty() {
            image_base + align(final_dummy_base_rva as u64 + dummy_blob.len() as u64)
        } else {
            dispatcher_va + align(btg.bytes.len() as u64)
        }
    } else {
        0
    };

    // ── 3rd pass: 최종 스텁 (payload_va + crc_va 반영) ─────────────────────────
    let crc_va = dispatcher_va + (seed_off + 256) as u64;
    let mac_va = dispatcher_va + (seed_off + 260) as u64;
    let crc2_va = dispatcher_va + (seed_off + 268) as u64;
    // Dedicated integrity scratch directly follows CRC2.  It remains live
    // through CRC4 and is wiped only afterwards; unlike an arbitrary offset in
    // Program-VM state it cannot alias ChaCha or family runtime state.
    let w32_slot_va = dispatcher_va + (seed_off + 272) as u64;
    let crc3_va = dispatcher_va + (seed_off + 276) as u64;
    let crc4_va = dispatcher_va + (seed_off + 280) as u64;
    let stub3 = BootStubCtx {
        payload_va,
        payload_len: if payload_relocate {
            relocated_payload_len
        } else {
            0
        },
        crc_va,
        mac_va,
        crc2_va,
        crc3_va,
        crc4_va,
        w32_slot_va,
        // RC4 Program-VM mode reuses the otherwise inactive Poly1305 tag
        // pointer as the BTGI runtime-table carrier.
        poly_tag_va: if vm_integrity_table_capacity > 0 && !chacha_mode {
            dispatcher_va + vm_integrity_table_off as u64
        } else {
            stub2.poly_tag_va
        },
        // M6 Phase-2.3: at-rest 암호화 대상 VA/길이 확정 (imm64/imm32 — 길이 불변)
        vm_oep_bc_va: vm_prog_bc_va,
        vm_oep_bc_len: vm_prog_bc_len,
        vm_oep_text_runs_va: text_runs_va,
        vm_oep_text_runs_count: text_runs_count,
        // v6: 배치 확정 후 반영 (모두 imm64 — 길이 불변)
        iat_table_va: if !iat_table_blob.is_empty() {
            dispatcher_va + table_off as u64
        } else {
            0
        },
        iat_ll_slot_va: if ctx.iat_hide || ctx.mem_harden {
            image_base + ctx.iat_ll_slot_rva as u64
        } else {
            0
        },
        iat_gpa_slot_va: if ctx.iat_hide || ctx.mem_harden {
            image_base + ctx.iat_gpa_slot_rva as u64
        } else {
            0
        },
        mba_master: ctx.mba_constant,
        mba_c: IMPORT_MBA_C,
        mem_ntdll_name_va: mem_ntdll_va,
        mem_ntprot_name_va: mem_ntprot_va,
        mem_code_base: dispatcher_va,
        // Program-VM state starts on its own page.  Seal only the immutable
        // prefix; state/call-stack/import slots remain writable.
        mem_code_size: if vm_prog_state_va > dispatcher_va {
            vm_prog_state_va - dispatcher_va
        } else {
            ((new_section_len as u64) + 0xFFF) & !0xFFF
        },
        mem_state_base: if vm_prog_state_va > dispatcher_va {
            vm_prog_state_va
        } else {
            0
        },
        mem_state_size: if vm_prog_state_va > dispatcher_va {
            ((dispatcher_va + new_section_len as u64 + 0xFFF) & !0xFFF)
                .saturating_sub(vm_prog_state_va)
        } else {
            0
        },
        ..stub2
    };
    let stub_code_final = build_boot_block(&stub3)?;
    if stub_code_final.len() != stub_code_len {
        anyhow::bail!(
            "boot stub size changed after payload/crc VA fixup: {} vs {}",
            stub_code_final.len(),
            stub_code_len
        );
    }
    let mut full_stub_final = Vec::with_capacity(ad_bytes.len() + stub_code_final.len());
    full_stub_final.extend_from_slice(&ad_bytes);
    full_stub_final.extend_from_slice(&stub_code_final);
    if full_stub_final.len() != full_stub.len() {
        anyhow::bail!(
            "boot stub final length mismatch: {} vs {}",
            full_stub_final.len(),
            full_stub.len()
        );
    }

    // 부트 스텁 복사
    btg.bytes[boot_off..stub_end].copy_from_slice(&full_stub_final);

    // ── v60 (--custom-cipher): BTG-C1 blob + S-box + 상태 영역 기록 ───────────
    if c1_mode {
        // blob은 최종 VA(c1_state_va/c1_sbox_va)로 재생성 — 길이는 1차와 동일.
        let blob = crate::crypto::native::emit_btg_crypt_blob(c1_state_va, c1_sbox_va);
        debug_assert_eq!(
            blob.len(),
            c1_blob_len,
            "BTG-C1 blob length must be VA-independent"
        );
        btg.bytes[c1_blob_off..c1_blob_off + blob.len()].copy_from_slice(&blob);
        // S-box 상수 테이블 (패커가 기록 — 스텁 emit_c1_init은 상태만 초기화)
        let sbox = crate::crypto::nonlinear::sbox();
        btg.bytes[c1_sbox_off..c1_sbox_off + 256].copy_from_slice(&sbox);
        // 상태 버퍼는 0으로 초기화 (스텁이 런타임에 key/ctr/nonce/ks_off 기록)
        btg.bytes[c1_state_off..c1_state_off + C1_STATE_SIZE].fill(0);
        println!(
            "[+] v60 BTG-C1: crypt blob @0x{:X} ({}B), sbox @0x{:X}, state @0x{:X}",
            c1_blob_off,
            blob.len(),
            c1_sbox_off,
            c1_state_off
        );
    }

    // ── v63 (--crypto-mode chacha20): ChaCha20 blob + 상태 영역 기록 ──────────
    if chacha_mode {
        // blob은 최종 VA(chacha_state_va)로 재생성 — 길이는 1차와 동일.
        let blob = crate::crypto::chacha20_native::emit_chacha20_blob(chacha_state_va);
        debug_assert_eq!(
            blob.len(),
            chacha_blob_len,
            "ChaCha20 blob length must be VA-independent"
        );
        btg.bytes[chacha_blob_off..chacha_blob_off + blob.len()].copy_from_slice(&blob);
        // 상태 버퍼는 0으로 초기화 (스텁 emit_chacha_init이 런타임에 key/ctr/nonce/ks_off 기록)
        let st_size = crate::crypto::chacha20::CHA_STATE_SIZE;
        btg.bytes[chacha_state_off..chacha_state_off + st_size].fill(0);
        println!(
            "[+] v63 ChaCha20: crypt blob @0x{:X} ({}B), state @0x{:X}",
            chacha_blob_off,
            blob.len(),
            chacha_state_off
        );
    }

    // ── T3-1 Phase D: Poly1305 verify blob + 키/태그 기록 (chacha 경로) ────────
    if chacha_mode {
        let blob = crate::crypto::poly1305_native::emit_poly1305_verify_blob(0);
        debug_assert_eq!(
            blob.len(),
            poly_blob_len,
            "Poly1305 blob length must be VA-independent"
        );
        btg.bytes[poly_blob_off..poly_blob_off + blob.len()].copy_from_slice(&blob);
        btg.bytes[poly_key_off..poly_key_off + 32].fill(0);
        if let Some(t) = chacha_aead_tag {
            btg.bytes[poly_tag_off..poly_tag_off + 16].copy_from_slice(&t);
        }
        println!(
            "[+] T3-1 Phase D: Poly1305 verify blob @0x{:X} ({}B), runtime key scratch @0x{:X}, tag @0x{:X}",
            poly_blob_off,
            blob.len(),
            poly_key_off,
            poly_tag_off
        );
    }

    // ── VM 모듈 배치 (최종 VA로 재생성 후 복사) ───────────────────────────────
    if let Some(m) = vm_mod {
        let vm_va = dispatcher_va + vm_off as u64;
        let mode = if c1_mode {
            vm::handlers::EntryMode::C1Init
        } else {
            vm::handlers::EntryMode::Ksa
        };
        let plain_bc = vm_plain_bc.expect("vm_plain_bc must be present when vm_mod is Some");
        let module = build_vm_mod(
            m8_mod,
            vm_va,
            vm_va + m.code.len() as u64,
            vm_va + (m.code.len() + m.table.len()) as u64,
            plain_bc,
            mode,
            rng,
        )?;
        let vm_end = vm_off + module.total_len();
        if vm_end > boot_off + BOOT_AREA_RESERVE {
            return Err(anyhow::anyhow!(
                "VM module too large: {} bytes at 0x{:X} (reserve 0x{:X})",
                module.total_len(),
                vm_off,
                BOOT_AREA_RESERVE
            ));
        }
        btg.bytes[vm_off..vm_off + module.code.len()].copy_from_slice(&module.code);
        let t = vm_off + module.code.len();
        btg.bytes[t..t + module.table.len()].copy_from_slice(&module.table);
        let b = t + module.table.len();
        btg.bytes[b..b + module.bytecode.len()].copy_from_slice(&module.bytecode);
        println!(
            "[+] Composite VM: module @0x{:X} (code {}B table {}B bytecode {}B state {}B) entry_va=0x{:X} state_va=0x{:X}",
            vm_off,
            module.code.len(),
            module.table.len(),
            module.bytecode.len(),
            vm::VM_STATE_SIZE,
            vm_entry_va,
            vm_state_va
        );
    }
    // v19: PRGA VM 모듈 배치 (최종 VA로 재생성 후 복사)
    if let Some(m) = vm_prga_mod {
        let pva = dispatcher_va + vm_prga_off as u64;
        let plain_bc =
            vm_prga_plain_bc.expect("vm_prga_plain_bc must be present when vm_prga_mod is Some");
        let pmod = build_vm_mod(
            m8_mod,
            pva,
            pva + m.code.len() as u64,
            pva + (m.code.len() + m.table.len()) as u64,
            plain_bc,
            vm::handlers::EntryMode::Prga,
            rng,
        )?;
        let pend = vm_prga_off + pmod.total_len();
        if pend > boot_off + BOOT_AREA_RESERVE {
            return Err(anyhow::anyhow!(
                "PRGA VM module too large: {} bytes at 0x{:X}",
                pmod.total_len(),
                vm_prga_off
            ));
        }
        btg.bytes[vm_prga_off..vm_prga_off + pmod.code.len()].copy_from_slice(&pmod.code);
        let t = vm_prga_off + pmod.code.len();
        btg.bytes[t..t + pmod.table.len()].copy_from_slice(&pmod.table);
        let b = t + pmod.table.len();
        btg.bytes[b..b + pmod.bytecode.len()].copy_from_slice(&pmod.bytecode);
        println!(
            "[+] Composite VM PRGA: module @0x{:X} (code {}B table {}B bytecode {}B state {}B) entry_va=0x{:X} state_va=0x{:X}",
            vm_prga_off,
            pmod.code.len(),
            pmod.table.len(),
            pmod.bytecode.len(),
            vm::VM_STATE_SIZE,
            vm_prga_entry_va,
            vm_prga_state_va
        );
    }
    // ── M6 Phase-2: 프로그램 VM 모듈 배치 (최종 VA로 재생성 후 복사) ──────────
    let mut vm_multi_family_chunks = Vec::new();
    let mut vm_multi_family_regions: Option<(
        Vec<(usize, usize)>,
        Vec<(usize, usize)>,
        Vec<(usize, usize)>,
    )> = None;
    if let Some(m) = vm_prog_mod {
        let prva = dispatcher_va + vm_prog_off as u64;
        let multi_built = if vm_multi_family_active {
            Some(build_multi_family_prog_mod(
                ctx.vm_multi_family.as_ref().unwrap(),
                ctx.vm_family_plan.as_ref().unwrap().entry_family,
                ctx.vm_family_plan.as_ref().unwrap().entry_function,
                prva,
                vm_prog_state_va,
                ctx.m7,
                image_base,
                ctx.poly_vm_seed,
                &ctx.vm_data_lifetime_objects,
                &native_gateway_targets,
            )?)
        } else {
            None
        };
        if let Some(multi) = &multi_built {
            let expected_entry_va = prva + multi.canonical_entry_gateway_offset as u64;
            if expected_entry_va != vm_prog_entry_va {
                anyhow::bail!(
                    "canonical OEP gateway placement drift: sized=0x{:X} final=0x{:X}",
                    vm_prog_entry_va,
                    expected_entry_va
                );
            }
            let rewritten = rewrite_native_gateway_pointers(
                &mut ctx.patched_sections,
                image_base,
                prva,
                &multi.native_entry_gateways,
            );
            println!(
                "[+] Canonical native gateways: {} gateway(s), {} function-pointer slot(s) rewritten",
                multi.native_entry_gateways.len(),
                rewritten
            );
        }
        let prmod = if let Some(multi) = &multi_built {
            vm_multi_family_chunks = multi.chunks.clone();
            multi.module.clone()
        } else {
            let plain_bc = vm_prog_plain_bc
                .expect("vm_prog_plain_bc must be present when vm_prog_mod is Some");
            build_prog_vm_mod(
                vm_commercial,
                ctx.poly_vm_seed,
                prva,
                prva + m.code.len() as u64,
                prva + (m.code.len() + m.table.len()) as u64,
                plain_bc,
                vm_prog_state_va,
                vm_prog_ip_map.as_ref(),
                vm_prog_superops.as_ref(),
                &ctx.vm_prog_chunks,
                ctx.vm_family_plan.as_ref().map(|plan| plan.entry_family),
                m8_mod,
                rng,
            )?
        };
        let prend = vm_prog_off + prmod.total_len();
        println!(
            "[DEBUG pass2 prmod] code={} table={} bc={} total={} prend={} btg_len={}",
            prmod.code.len(),
            prmod.table.len(),
            prmod.bytecode.len(),
            prmod.total_len(),
            prend,
            btg.bytes.len()
        );
        if prend > boot_off + BOOT_AREA_RESERVE {
            return Err(anyhow::anyhow!(
                "Program VM module too large: {} bytes at 0x{:X}",
                prmod.total_len(),
                vm_prog_off
            ));
        }
        btg.bytes[vm_prog_off..vm_prog_off + prmod.code.len()].copy_from_slice(&prmod.code);
        let t = vm_prog_off + prmod.code.len();
        btg.bytes[t..t + prmod.table.len()].copy_from_slice(&prmod.table);
        let b = t + prmod.table.len();
        println!(
            "[DEBUG copy bc] b={} bc_len={} b+bc_len={} btg_len={}",
            b,
            prmod.bytecode.len(),
            b + prmod.bytecode.len(),
            btg.bytes.len()
        );
        btg.bytes[b..b + prmod.bytecode.len()].copy_from_slice(&prmod.bytecode);
        if let Some(multi) = &multi_built {
            vm_multi_family_regions = Some((
                multi.code_ranges.clone(),
                multi.table_ranges.clone(),
                multi.bytecode_ranges.clone(),
            ));
            for (index, state_delta) in multi.state_offsets.iter().copied().enumerate() {
                let state_off = (vm_prog_state_va - dispatcher_va) as usize + state_delta;
                let call_stack_va = vm_prog_state_va
                    + state_delta as u64
                    + (MULTI_FAMILY_STATE_STRIDE - crate::vm::interp::CALL_STACK_SIZE) as u64;
                btg.bytes[state_off
                    ..state_off + crate::vm::commercial_build::COMMERCIAL_STATE_SIZE as usize]
                    .fill(0);
                btg.bytes[state_off + 0x5000..state_off + 0x5030].fill(0);
                let sync_ptr_off =
                    state_off + crate::vm::data_lifetime::LIFETIME_SYNC_PTR_STATE_OFFSET;
                btg.bytes[sync_ptr_off..sync_ptr_off + 8]
                    .copy_from_slice(&multi.lifetime_sync.base_va.to_le_bytes());
                let sync_count_off =
                    state_off + crate::vm::data_lifetime::LIFETIME_SYNC_COUNT_STATE_OFFSET;
                btg.bytes[sync_count_off..sync_count_off + 8]
                    .copy_from_slice(&(multi.lifetime_sync.entries.len() as u64).to_le_bytes());
                if index == 0 {
                    btg.bytes[state_off + 0x5000..state_off + 0x5008]
                        .copy_from_slice(&(multi.entry_byte_offset as u64).to_le_bytes());
                }
                let ptr = state_off + crate::vm::interp::STATE_PTR_CALL_STACK;
                btg.bytes[ptr..ptr + 8].copy_from_slice(&call_stack_va.to_le_bytes());
                println!(
                    "[+] P2-10 family module #{index} {:?}: state_va=0x{:X} call_stack_va=0x{:X}",
                    multi.families[index],
                    vm_prog_state_va + state_delta as u64,
                    call_stack_va,
                );
            }

            // Global `.vstate` tail: bucket counters, one process-shared
            // lifetime table, then 128 lane-private native runtime stacks.
            // Keeping this table outside every 0x8000 family stride removes the
            // previous 0x2000..0x3060 overlap with the commercial virtual stack.
            let lane_control_off = (multi.invocation_layout.lane_control_va - dispatcher_va) as usize;
            let lane_control_end = lane_control_off + VM_THREAD_BUCKETS * 4;
            if lane_control_end > btg.bytes.len() {
                anyhow::bail!("multi-family lane-control tail exceeds .textb/.vstate backing");
            }
            btg.bytes[lane_control_off..lane_control_end].fill(0);

            let sync_start = (multi.lifetime_sync.base_va - dispatcher_va) as usize;
            let sync_end = sync_start + crate::vm::data_lifetime::LIFETIME_SYNC_TABLE_SIZE;
            if sync_end > btg.bytes.len() {
                anyhow::bail!("P2-14 global lifetime sync table exceeds .vstate backing");
            }
            btg.bytes[sync_start..sync_end].fill(0);
            for (entry_index, entry) in multi.lifetime_sync.entries.iter().enumerate() {
                let entry_off = sync_start
                    + entry_index * crate::vm::data_lifetime::LIFETIME_SYNC_ENTRY_SIZE;
                btg.bytes[entry_off + 16..entry_off + 24]
                    .copy_from_slice(&entry.object_va.to_le_bytes());
                btg.bytes[entry_off + 24..entry_off + 28]
                    .copy_from_slice(&entry.object_len.to_le_bytes());
                btg.bytes[entry_off + 28..entry_off + 32]
                    .copy_from_slice(&entry.object_rva.to_le_bytes());
                btg.bytes[entry_off + 32..entry_off + 40]
                    .copy_from_slice(&entry.object_key.to_le_bytes());
            }
            if !multi.lifetime_sync.entries.is_empty() {
                println!(
                    "[+] P2-14 shared lifetime sync: {} global lock/depth/owner entry(s) @0x{:X}",
                    multi.lifetime_sync.entries.len(),
                    multi.lifetime_sync.base_va,
                );
            }

            let host_pool_off = (multi.invocation_layout.host_stack_pool_va - dispatcher_va) as usize;
            let host_pool_len = VM_HOST_STACK_SLOTS * VM_HOST_STACK_SIZE;
            let host_pool_end = host_pool_off
                .checked_add(host_pool_len)
                .ok_or_else(|| anyhow::anyhow!("native host-stack pool range overflow"))?;
            if host_pool_end > btg.bytes.len() {
                anyhow::bail!("native host-stack pool exceeds .vstate backing");
            }
            btg.bytes[host_pool_off..host_pool_end].fill(0);
            println!(
                "[+] native gateway host stacks: {} slot(s) (canonical + {} lanes) x 0x{:X} bytes @0x{:X}",
                VM_HOST_STACK_SLOTS,
                VM_INVOCATION_LANES,
                VM_HOST_STACK_SIZE,
                multi.invocation_layout.host_stack_pool_va,
            );

            // Initialize every gateway invocation lane. Lifetime coordination
            // remains process-shared, while architectural state and call stacks
            // are lane-private.
            let lane_group_stride = multi.invocation_layout.lane_group_stride;
            for lane in 1..=VM_INVOCATION_LANES {
                for state_delta in multi.state_offsets.iter().copied() {
                    let lane_delta = lane * lane_group_stride + state_delta;
                    let state_off = (vm_prog_state_va - dispatcher_va) as usize + lane_delta;
                    btg.bytes[state_off..state_off + MULTI_FAMILY_STATE_STRIDE].fill(0);
                    let sync_ptr_off = state_off
                        + crate::vm::data_lifetime::LIFETIME_SYNC_PTR_STATE_OFFSET;
                    btg.bytes[sync_ptr_off..sync_ptr_off + 8]
                        .copy_from_slice(&multi.lifetime_sync.base_va.to_le_bytes());
                    let sync_count_off = state_off
                        + crate::vm::data_lifetime::LIFETIME_SYNC_COUNT_STATE_OFFSET;
                    btg.bytes[sync_count_off..sync_count_off + 8]
                        .copy_from_slice(&(multi.lifetime_sync.entries.len() as u64).to_le_bytes());
                    let call_stack_va = vm_prog_state_va + lane_delta as u64
                        + (MULTI_FAMILY_STATE_STRIDE - crate::vm::interp::CALL_STACK_SIZE) as u64;
                    let ptr = state_off + crate::vm::interp::STATE_PTR_CALL_STACK;
                    btg.bytes[ptr..ptr + 8].copy_from_slice(&call_stack_va.to_le_bytes());
                }
            }
        }
        let placed_state_bytes = multi_built
            .as_ref()
            .map(|multi| multi.invocation_layout.reserve_size)
            .unwrap_or(vm::VM_STATE_SIZE);
        println!(
            "[+] M6 Phase-2 Program VM: module @0x{:X} (code {}B table {}B bytecode {}B state {}B) entry_va=0x{:X} state_va=0x{:X}",
            vm_prog_off,
            prmod.code.len(),
            prmod.table.len(),
            prmod.bytecode.len(),
            placed_state_bytes,
            vm_prog_entry_va,
            vm_prog_state_va
        );
    }

    // ── M6 Phase-2.3: at-rest 암호화 적용 ───────────────────────────────────
    if ctx.m7 && !vm_multi_family_chunks.is_empty() && vm_prog_bc_len > 0 {
        for (module_bytecode_start, chunk) in &vm_multi_family_chunks {
            let start = vm_prog_bc_off + module_bytecode_start + chunk.offset as usize;
            let end = start + chunk.len as usize;
            if end > btg.bytes.len() {
                return Err(anyhow::anyhow!(
                    "P2-10 family M7 chunk encryption OOB: {}..{} > {}",
                    start,
                    end,
                    btg.bytes.len()
                ));
            }
            vm::chunk_crypto::crypt_chunk(&mut btg.bytes[start..end], chunk.key);
        }
        let runtime_cipher = &btg.bytes[vm_prog_bc_off..vm_prog_bc_off + vm_prog_bc_len as usize];
        ctx.vm_prog_runtime_cipher_hash = Some(crate::manifest::sha256_hex(runtime_cipher));
        println!(
            "[+] P2-10 family M7: {} independent instruction-aligned chunk(s) encrypted across {} family stream(s)",
            vm_multi_family_chunks.len(),
            vm_multi_family_sizing
                .as_ref()
                .map(|multi| multi.families.len())
                .unwrap_or(0),
        );
    }
    // P1-4 M7 outer layer. The boot RC4 below wraps these bytes for at-rest
    // transport and removes only that wrapper at startup; the per-chunk layer
    // remains in memory and is unmasked byte-by-byte by the Program-VM decoder.
    if ctx.m7 && !ctx.vm_prog_chunks.is_empty() && vm_prog_bc_len > 0 {
        for chunk in &ctx.vm_prog_chunks {
            let start = vm_prog_bc_off + chunk.offset as usize;
            let end = start + chunk.len as usize;
            if end > btg.bytes.len() {
                return Err(anyhow::anyhow!(
                    "P1-4 Program-VM chunk encryption OOB: {}..{} > {}",
                    start,
                    end,
                    btg.bytes.len()
                ));
            }
            vm::chunk_crypto::crypt_chunk(&mut btg.bytes[start..end], chunk.key);
        }
        let runtime_cipher = &btg.bytes[vm_prog_bc_off..vm_prog_bc_off + vm_prog_bc_len as usize];
        ctx.vm_prog_runtime_cipher_hash = Some(crate::manifest::sha256_hex(runtime_cipher));
        println!(
            "[+] P1-4 Program-VM M7: outer encryption ACTIVE for {} chunk(s); runtime decoder unmasks fetched bytes only",
            ctx.vm_prog_chunks.len()
        );
    }
    // Multi-family chunks use offsets local to each family stream while the
    // manifest/strict-profile contract describes the concatenated bytecode
    // region. Publish a flattened, ordered view only after encryption so it
    // cannot accidentally enter the legacy single-stream encryption path.
    if ctx.m7 && !vm_multi_family_chunks.is_empty() {
        ctx.vm_prog_chunks = vm_multi_family_chunks
            .iter()
            .map(
                |(module_bytecode_start, chunk)| vm::chunk_crypto::BytecodeChunk {
                    offset: (*module_bytecode_start as u32).saturating_add(chunk.offset),
                    len: chunk.len,
                    key: chunk.key,
                },
            )
            .collect();
        ctx.vm_prog_chunks.sort_by_key(|chunk| chunk.offset);
    }

    // Distributed integrity is sealed after the persistent M7 layer is in its
    // final runtime representation, but before the transient boot RC4 wrapper.
    // The boot decrypt restores these exact bytes before Program-VM entry.
    ctx.vm_integrity_descriptors.clear();
    if integrity_effective {
        if let Some((code_ranges, table_ranges, bytecode_ranges)) = &vm_multi_family_regions {
            let code_total = code_ranges.iter().map(|(_, len)| *len).sum::<usize>();
            let table_base = vm_prog_off + code_total;
            let table_total = table_ranges.iter().map(|(_, len)| *len).sum::<usize>();
            let bytecode_base = table_base + table_total;
            let mut regions = Vec::with_capacity(code_ranges.len() * 3);
            for &(offset, len) in code_ranges {
                regions.push((
                    vm::distributed_integrity::ProtectedRegionKind::HandlerCode,
                    vm_prog_off + offset,
                    len,
                ));
            }
            for &(offset, len) in table_ranges {
                regions.push((
                    vm::distributed_integrity::ProtectedRegionKind::HandlerTable,
                    table_base + offset,
                    len,
                ));
            }
            for &(offset, len) in bytecode_ranges {
                regions.push((
                    vm::distributed_integrity::ProtectedRegionKind::VmBytecode,
                    bytecode_base + offset,
                    len,
                ));
            }
            ctx.vm_integrity_descriptors = vm::distributed_integrity::seal_region_set(
                &btg.bytes,
                &regions,
                dispatcher_va,
                ctx.poly_vm_seed,
            )?;
            let serialized =
                vm::distributed_integrity::serialize_table(&ctx.vm_integrity_descriptors)?;
            if serialized.len() > vm_integrity_table_capacity {
                return Err(anyhow::anyhow!(
                    "distributed integrity table {}B exceeds reserved {}B",
                    serialized.len(),
                    vm_integrity_table_capacity
                ));
            }
            let table_end = vm_integrity_table_off + serialized.len();
            if table_end > btg.bytes.len() {
                return Err(anyhow::anyhow!(
                    "distributed integrity table write OOB: {}..{} > {}",
                    vm_integrity_table_off,
                    table_end,
                    btg.bytes.len()
                ));
            }
            btg.bytes[vm_integrity_table_off..table_end].copy_from_slice(&serialized);
            ctx.vm_integrity_table_len = serialized.len() as u32;
            println!(
                "[+] Distributed integrity: sealed {} family-scoped descriptor(s), runtime table RVA=0x{:X} size={}B",
                ctx.vm_integrity_descriptors.len(),
                ctx.vm_integrity_table_rva,
                ctx.vm_integrity_table_len
            );
        }
    }

    // fresh production stream 하나로 .text → bytecode 순 연속 암호화. 부트 스텁의
    // emit_rest_decrypt가 같은 순서로 복호화한다. (.textb는 RWX, .text는 WRITE
    // 비트 추가로 in-place 복호화를 허용한다.)
    if vm_oep_effective && (!text_enc_runs.is_empty() || vm_prog_bc_len > 0) {
        if !text_enc_runs.is_empty() {
            if let Some(sec) = ctx.patched_sections.iter_mut().find(|s| s.name == ".text") {
                sec.characteristics |= 0x8000_0000; // IMAGE_SCN_MEM_WRITE (boot in-place decrypt)
            }
        }
        let mut rest_c1 = if chacha_mode {
            None
        } else {
            let (key, nonce) = super::cipher::derive_c1_key_nonce(seed_masked);
            Some(crate::crypto::BtgCipher::new(&key, nonce))
        };
        let mut rest_chacha = if chacha_mode {
            let (key, nonce) = super::cipher::derive_chacha_key_nonce_raw(seed_masked);
            let mut state = [0u8; crate::crypto::chacha20::CHA_STATE_SIZE];
            crate::crypto::chacha20::chacha_init_state(&mut state, &key, &nonce);
            state[crate::crypto::chacha20::CHA_OFF_CTR..crate::crypto::chacha20::CHA_OFF_CTR + 8]
                .copy_from_slice(&1u64.to_le_bytes());
            Some(state)
        } else {
            None
        };
        let mut crypt_rest = |bytes: &mut [u8]| {
            if let Some(state) = rest_chacha.as_mut() {
                crate::crypto::chacha20::chacha_apply(state, bytes);
            } else if let Some(cipher) = rest_c1.as_mut() {
                cipher.crypt(bytes);
            }
        };
        if !text_enc_runs.is_empty() {
            if let Some(sec) = ctx.patched_sections.iter_mut().find(|s| s.name == ".text") {
                let sec_start = image_base + sec.virtual_address as u64;
                for &(va, len) in &text_enc_runs {
                    let off = (va - sec_start) as usize;
                    crypt_rest(&mut sec.bytes[off..off + len as usize]);
                }
            }
        }
        if vm_prog_bc_len > 0 {
            // T0-1 FIX ②: at-rest 암호화 슬라이스 전 bound 검사.
            // boot_end FIX ① 이후에도 vm_prog_bc_off 계산 오류(code/table len 잘못
            // 참조)가 있으면 여기서 OOB panic이 발생할 수 있다. truncate 후 섹션
            // 경계를 초과하는 경우를 명시적 Err로 전환해 silent OOB를 방어한다.
            let bc_end = vm_prog_bc_off + vm_prog_bc_len as usize;
            if bc_end > btg.bytes.len() {
                return Err(anyhow::anyhow!(
                    "T0-1: Program VM bytecode at-rest encrypt OOB: \
                     vm_prog_bc_off=0x{:X} len=0x{:X} but section is only 0x{:X}B \
                     (boot_end=0x{:X} new_section_len=0x{:X}). \
                     Likely vm_prog_off/vm_prog_total mismatch.",
                    vm_prog_bc_off,
                    vm_prog_bc_len,
                    btg.bytes.len(),
                    boot_end,
                    new_section_len
                ));
            }
            crypt_rest(&mut btg.bytes[vm_prog_bc_off..bc_end]);
        }
        println!(
            "[+] --vm-oep at-rest: fresh-{}(seed) encryption applied (preserved .text {} run(s)/{}B + Program VM bytecode {}B)",
            if chacha_mode { "ChaCha20" } else { "C1" }, text_enc_runs.len(), text_enc_total, vm_prog_bc_len
        );
        // P0-⑦: .text 보존 런(원본 절대 VA 포함)이 at-rest 암호화됨 → 로더 .reloc
        // 적용 시 암호문 파괴 → relocation-aware(ASLR) 비활성화.
        ctx.at_rest_encrypted = true;
    }

    // 런 테이블 헤더 + 엔트리 (절대 VA) — 문자열 런 + v6 리졸브 테이블 run
    btg.bytes[runs_off..runs_off + 4].copy_from_slice(&num_runs_u32.to_le_bytes());
    for (i, run) in runs.iter().enumerate() {
        let e = runs_off + 8 + i * 16;
        btg.bytes[e..e + 8].copy_from_slice(&run.va.to_le_bytes());
        btg.bytes[e + 8..e + 16].copy_from_slice(&(run.len as u64).to_le_bytes());
    }
    if table_is_run {
        let e = runs_off + 8 + runs.len() * 16;
        btg.bytes[e..e + 8].copy_from_slice(&(dispatcher_va + table_off as u64).to_le_bytes());
        btg.bytes[e + 8..e + 16].copy_from_slice(&(iat_table_blob.len() as u64).to_le_bytes());
    }

    // 시드 (masked)
    // v19: base-bound — 파일에는 seed_stored(=seed_masked ^ bind(preferred_base)) 저장.
    btg.bytes[seed_off..seed_off + 256].copy_from_slice(&seed_stored);

    // ── M12 Decrypt-Descriptor: 정적 decrypt target/size/bytecode/table 주소를
    // 부트 스텁 imm으로 노출하지 않고, 파생 키(RC4 keystream — 키 유도 계층)로 암호화해
    // 이 디스크립터에 저장한다. 부트 스텁 emit_desc_decrypt가 KSA(키 유도) 직후 이
    // 디스크립터를 PRGA로 복호화하고, 이어지는 코드/런/바이트코드 복호화가 그 값들을
    // 메모리에서 읽는다 → 정적 분석으로 target/size가 노출되지 않는다.
    let payload_target_off = if code_len > 0 {
        code_start
    } else {
        vm_prog_bc_off
    };
    let code_va = dispatcher_va + payload_target_off as u64;
    let mut desc = [0u8; DESC_SIZE];
    desc[DESC_OFF_CODE_VA..DESC_OFF_CODE_VA + 8].copy_from_slice(&code_va.to_le_bytes());
    desc[DESC_OFF_CODE_LEN..DESC_OFF_CODE_LEN + 8]
        .copy_from_slice(&(code_len as u64).to_le_bytes());
    desc[DESC_OFF_RUNS_VA..DESC_OFF_RUNS_VA + 8].copy_from_slice(&runs_va.to_le_bytes());
    desc[DESC_OFF_NUM_RUNS..DESC_OFF_NUM_RUNS + 8]
        .copy_from_slice(&(num_runs_u32 as u64).to_le_bytes());
    desc[DESC_OFF_BC_VA..DESC_OFF_BC_VA + 8].copy_from_slice(&vm_prog_bc_va.to_le_bytes());
    desc[DESC_OFF_BC_LEN..DESC_OFF_BC_LEN + 8]
        .copy_from_slice(&(vm_prog_bc_len as u64).to_le_bytes());
    desc[DESC_OFF_TEXT_RUNS_VA..DESC_OFF_TEXT_RUNS_VA + 8]
        .copy_from_slice(&text_runs_va.to_le_bytes());
    desc[DESC_OFF_TEXT_RUNS_COUNT..DESC_OFF_TEXT_RUNS_COUNT + 8]
        .copy_from_slice(&(text_runs_count as u64).to_le_bytes());
    btg.bytes[desc_off..desc_off + DESC_SIZE].copy_from_slice(&desc);
    // crypto-on에서만 암호화 (부트 스텁 emit_desc_decrypt가 복호화). no_crypto는 평문으로
    // 남기되 부트 스텁이 디스크립터를 읽지 않으므로 소비자는 imm64를 그대로 쓴다.
    // [A/B] descriptor written plaintext (no encryption) for testing
    // if !no_crypto {
    //     legacy descriptor encryption was performed here.
    //     rc.crypt(&mut btg.bytes[desc_off..desc_off + DESC_SIZE]);
    // }

    // ── P5: .text at-rest decrypt run-table 기록 (부트 스텁 emit_rest_decrypt가 소비) ──
    if !text_enc_runs.is_empty() {
        btg.bytes[text_runs_off..text_runs_off + 4].copy_from_slice(&text_runs_count.to_le_bytes());
        for (i, &(va, len)) in text_enc_runs.iter().enumerate() {
            let e = text_runs_off + 8 + i * 16;
            btg.bytes[e..e + 8].copy_from_slice(&va.to_le_bytes());
            btg.bytes[e + 8..e + 16].copy_from_slice(&(len as u64).to_le_bytes());
        }
    }

    // ── v5 --integrity: 코드 영역 CRC32 저장 (부트 스텁이 비교) ──────────────
    // v9: chained/plain = 평문 CRC, reencrypt = 파일 암호문 CRC. crypto-off는 없음.
    if integrity_effective {
        let crc_val = crc32(crc_source.as_deref().unwrap_or(&[]));
        // T2-3: 키 결합 MAC — CRC32는 키 없는 손상검출용이라 변조 시 4바이트를 함께
        // 바꾸면 우회된다. seed_stored를 키로 코드 영역 keyed-MAC을 계산해 로그로
        // 남긴다 (변조 시 실행 거부용 — 부트 스텁 네이티브 검증은 별도 계층으로 확장).
        let mac_val =
            crate::crypto::BtgKeyedMac::mac(seed_stored, crc_source.as_deref().unwrap_or(&[]));
        println!(
            "[+] T2-3 Integrity keyed-MAC over code region: {:016X} (keyed)",
            mac_val
        );
        // S-hardening (multi-site + runtime-derived whiten): 저장값은 평문이 아니라
        //   crc_stored = crc ^ mac_lo32 (CRC↔MAC 결합) / mac_stored = mac ^ W32 /
        //   crc2_stored = crc ^ W32 (사이트 2). W32 = derive_integrity_key(seed_masked,
        //   image_base) — runtime-derived multi-factor whiten (seed_masked 256B +
        //   PEB ImageBaseAddress low/high bytes). 사이트 3/4는 W32 / rol(W32,13)로 결합.
        // base-bind uses the canonical preferred-base identity (zero XOR), so
        // the immutable bytes captured by the boot preamble are seed_stored.
        let mac_w32 = super::integrity::derive_whiten_key(seed_stored) as u64;
        // One authoritative W32 feeds MAC and every CRC site.  Re-deriving a
        // second value here previously drifted from the base-bound runtime
        // preamble and made untouched commercial images fail CRC2.
        let crc_w32 = mac_w32 as u32;
        let crc_stored = crc_val ^ (mac_val as u32);
        let mac_stored = mac_val ^ mac_w32;
        let crc2_stored = crc_val ^ crc_w32;
        // S3/S4 확장: 사이트별로 다른 runtime-derived whiten 결합 —
        //   crc3_stored = crc ^ W32 / crc4_stored = crc ^ rol(W32,13).
        let crc3_stored = crc_val ^ crc_w32;
        // The native CRC4 verifier loads only the low dword into R11D and
        // executes `rol r11d, 13`.  Rotate that same 32-bit value here.  A
        // 64-bit rotate followed by truncation folds different high bits into
        // the result and made every untouched image fail CRC4 at runtime.
        let crc4_stored = super::integrity::crc4_stored_value(crc_val, crc_w32);
        btg.bytes[seed_off + 256..seed_off + 260].copy_from_slice(&crc_stored.to_le_bytes());
        // S1: keyed-MAC(8B)를 crc 뒤 seed_off+260에 저장 — 부트 스텁이 런타임에
        // 재계산·비교 (불일치 시 ud2). 키 = seed_stored.
        btg.bytes[seed_off + 260..seed_off + 268].copy_from_slice(&mac_stored.to_le_bytes());
        btg.bytes[seed_off + 268..seed_off + 272].copy_from_slice(&crc2_stored.to_le_bytes());
        // w32_slot(seed_off+272)은 런타임이 W32를 저장하는 스크래치 — 파일에는 0.
        btg.bytes[seed_off + 272..seed_off + 276].fill(0);
        btg.bytes[seed_off + 276..seed_off + 280].copy_from_slice(&crc3_stored.to_le_bytes());
        btg.bytes[seed_off + 280..seed_off + 284].copy_from_slice(&crc4_stored.to_le_bytes());
        println!(
            "[+] S1 Integrity keyed-MAC stored @0x{:X} (8B, keyed=seed_stored; boot stub re-verifies -> ud2 on mismatch)",
            seed_off + 260
        );
        println!(
            "[+] v5 Integrity: code-region CRC32 = 0x{:08X} stored @0x{:X} (stub traps on mismatch)",
            crc_val,
            seed_off + 256
        );
    }

    // ── v6: 더미 import / 리졸브 테이블 / mem 문자열 기록 ────────────────────
    if ctx.iat_hide || ctx.mem_harden {
        // dummy_blob lives in the dedicated bootstrap IAT section.
        if !iat_table_blob.is_empty() {
            btg.bytes[table_off..table_off + iat_table_blob.len()].copy_from_slice(&iat_table_blob);
            // v9: crypto-on에서만 리졸브 테이블을 마지막 run으로 암호화한다.
            //     crypto-off에서는 평문으로 두고 스텁이 직접 읽는다.
            // v60: BTG-C1 경로도 코드/런과 같은 연속 키스트림으로 이어 암호화.
            if table_is_run {
                stream.crypt(&mut btg.bytes[table_off..table_off + iat_table_blob.len()]);
            }
        }
        if ctx.mem_harden {
            let dll = b"ntdll.dll\0";
            let fname = b"NtProtectVirtualMemory\0";
            btg.bytes[mem_off..mem_off + dll.len()].copy_from_slice(dll);
            btg.bytes[mem_off + dll.len()..mem_off + dll.len() + fname.len()]
                .copy_from_slice(fname);
        }
        println!(
            "[+] v6 IAT/Mem data placed: dummy_import@0x{:X} (dir_rva=0x{:X}), table@0x{:X}/{}B, mem_str@0x{:X}",
            dummy_off,
            ctx.iat_dir_rva,
            table_off,
            iat_table_blob.len(),
            mem_off
        );
    }

    // ── 7. 문자열 섹션을 쓰기 가능으로 (부트 스텁이 복호화) ───────────────────
    for run in runs {
        let sec = &mut ctx.patched_sections[run.sec_idx];
        sec.characteristics |= 0x8000_0000; // IMAGE_SCN_MEM_WRITE
    }

    // Publish the exact on-disk ciphertext ownership map for PE relocation.
    // The previous build stage excluded everything from the first encrypted
    // block through the end of .textb, which also excluded the later plaintext
    // boot stub and caused its absolute operands to miss DIR64 fixups.
    ctx.at_rest_cipher_ranges.clear();
    if !no_crypto {
        if code_len > 0 {
            ctx.at_rest_cipher_ranges
                .push((ctx.dispatcher_rva + code_start as u32, code_len));
        }
        for run in runs {
            if run.len > 0 && run.va >= image_base {
                ctx.at_rest_cipher_ranges
                    .push(((run.va - image_base) as u32, run.len as u32));
            }
        }
        if table_is_run && !iat_table_blob.is_empty() {
            ctx.at_rest_cipher_ranges.push((
                ctx.dispatcher_rva + table_off as u32,
                iat_table_blob.len() as u32,
            ));
        }
        if ctx.vm_oep && vm_prog_bc_len > 0 {
            ctx.at_rest_cipher_ranges
                .push((ctx.dispatcher_rva + vm_prog_bc_off as u32, vm_prog_bc_len));
        }
        for &(va, len) in &text_enc_runs {
            if len > 0 && va >= image_base {
                ctx.at_rest_cipher_ranges
                    .push(((va - image_base) as u32, len as u32));
            }
        }
        ctx.at_rest_cipher_ranges.sort_unstable();
        ctx.at_rest_cipher_ranges.dedup();
    }

    println!(
        "[+] v3 Crypto: boot stub @0x{:X} ({} bytes), runs @0x{:X}, seed @0x{:X}, entry=0x{:X}",
        boot_off,
        full_stub.len(),
        runs_off,
        seed_off,
        ctx.boot_entry_offset
    );

    // ── v4: .vdata 페이로드 섹션 등록 (빌더가 .textb 직후 배치) ───────────────
    if payload_relocate && payload_bytes.is_empty() && vm_prog_bc_len > 0 {
        let start = vm_prog_bc_off;
        let end = start + vm_prog_bc_len as usize;
        if end > btg.bytes.len() {
            anyhow::bail!("Program-VM payload relocation source exceeds .textb");
        }
        payload_bytes = btg.bytes[start..end].to_vec();
        btg.bytes[start..end].fill(0);
        println!(
            "[+] Program-VM payload relocate: {} byte ciphertext moved out of executable section",
            vm_prog_bc_len
        );
    }
    if payload_relocate && !payload_bytes.is_empty() {
        // Source and destination must describe two disjoint, valid ranges.
        // In particular, never let a malformed cursor cause the boot stub to
        // copy the payload into .vdata or bootstrap metadata.
        let dst_off = payload_target_off;
        let dst_end = dst_off
            .checked_add(payload_bytes.len())
            .ok_or_else(|| anyhow::anyhow!("relocated payload destination overflow"))?;
        if dst_off < vm_prog_off || dst_end > btg.bytes.len() {
            anyhow::bail!(
                "relocated payload destination outside .textb: dst=[0x{:X},0x{:X}) section=0x{:X}",
                dst_off, dst_end, btg.bytes.len()
            );
        }
        let payload_rva = (payload_va - image_base) as u32;
        ctx.payload_rva = payload_rva;
        ctx.payload_len = payload_bytes.len() as u32;
        ctx.at_rest_cipher_ranges.retain(|&(rva, len)| {
            !(rva == ctx.dispatcher_rva + payload_target_off as u32 && len == ctx.payload_len)
        });
        ctx.at_rest_cipher_ranges
            .push((payload_rva, ctx.payload_len));
        ctx.payload_section_data = Some(crate::pe::builder::SectionData {
            name: ".vdata".to_string(),
            virtual_address: payload_rva,
            virtual_size: payload_bytes.len() as u32,
            characteristics: 0x4000_0040, // INITIALIZED_DATA | READ
            bytes: payload_bytes,
        });
        println!(
            "[+] v4 Payload Relocate: .vdata section @RVA 0x{:X} ({} bytes) registered",
            payload_rva, ctx.payload_len
        );
    }

    if let Some(gateway_off) = tls_gateway_off {
        if gateway_off >= btg.bytes.len() {
            anyhow::bail!("TLS lifecycle gateway exceeds generated executable section");
        }
        btg.bytes[gateway_off] = 0xC3; // ret
        let gateway_va = dispatcher_va + gateway_off as u64;
        for slot_rva in &tls_gateway_slots {
            let section = ctx
                .patched_sections
                .iter_mut()
                .find(|section| {
                    *slot_rva >= section.virtual_address
                        && (*slot_rva as u64 + 8)
                            <= section.virtual_address as u64 + section.bytes.len() as u64
                })
                .ok_or_else(|| anyhow::anyhow!("TLS callback slot RVA {slot_rva:#x} is not file-backed"))?;
            let offset = (*slot_rva - section.virtual_address) as usize;
            section.bytes[offset..offset + 8].copy_from_slice(&gateway_va.to_le_bytes());
        }
        println!(
            "[+] TLS pre-entry ownership: redirected {} callback slot(s) to generated lifecycle gateway RVA {:#X}",
            tls_gateway_slots.len(),
            dispatcher_rva + gateway_off as u32
        );
    }

    // The Program-VM state is written at the very first boot instructions,
    // before the transient NtProtect window can be opened.  Materialize its
    // page-aligned tail as a separate RW/NX PE section while preserving every
    // generated absolute VA.  The split RVA is unchanged; only section
    // ownership and loader permissions differ.
    if ctx.mem_harden && vm_prog_state_va > dispatcher_va {
        let split_off = (vm_prog_state_va - dispatcher_va) as usize;
        if split_off == 0 || split_off >= btg.bytes.len() || split_off & 0xFFF != 0 {
            anyhow::bail!(
                "invalid Program-VM state split: offset=0x{:X}, textb_len=0x{:X}",
                split_off,
                btg.bytes.len()
            );
        }
        let state_bytes = btg.bytes.split_off(split_off);
        btg.virtual_size = btg.bytes.len() as u32;
        ctx.mutable_state_section_data = Some(crate::pe::builder::SectionData {
            name: ".vstate".to_string(),
            virtual_address: ctx.dispatcher_rva + split_off as u32,
            virtual_size: state_bytes.len() as u32,
            characteristics: 0xC000_0040, // INITIALIZED_DATA | READ | WRITE
            bytes: state_bytes,
        });
    }

    Ok(())
}
