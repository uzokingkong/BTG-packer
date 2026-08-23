// ==============================================================================
// BTG Pipeline - Pass 4: .btg Section Assembly (with Anti-Debug injection)
// ==============================================================================
//
// ==============================================================================

use crate::dispatcher;
use crate::mba::MbaGenerator;
use crate::pe::builder::SectionData;
use crate::pipeline::PipelineContext;
use crate::util::MAX_PADDING_SIZE;
use anyhow::Result;

pub const BOOT_AREA_RESERVE: usize = 0x4000000;
                                                //          crypto.rs truncates the section to actual boot_end, so final file size
                                                //          is unaffected.

///
pub fn run(
    ctx: &mut PipelineContext,
    anti_debug: bool,
    anti_debug_policy: crate::dispatcher::antidebug::AntiDebugPolicy,
    needs_boot_stub: bool,
    trace_blocks: bool,
) -> Result<()> {
    let layout = ctx
        .shuffled_layout
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ShuffledLayout not yet built ??run Pass 2 first"))?;
    let table_offset = ctx.table_offset;
    let first_block_offset = ctx.first_block_offset;
    let dispatcher_va = ctx.dispatcher_va;
    let dispatcher_rva = ctx.dispatcher_rva;
    let num_blocks = layout.shuffled_blocks.len();
    let block_ring = ctx.block_ring;

    let mut max_phys_offset = first_block_offset;
    for block in &layout.shuffled_blocks {
        let logical_id = block.id as usize;
        let off = layout.table_offsets[logical_id] as usize;
        let end = off + block.instructions.len();
        if end > max_phys_offset {
            max_phys_offset = end;
        }
    }

    // S2: 상태 테이블 예약도 `ctx.m7` 대신 `ctx.reencrypt` 기준으로 통일 —
    //     --dispatcher-reencrypt도 M7식 디스패처/상태 테이블을 쓴다.
    let c1_reserve = if ctx.reencrypt && ctx.custom_cipher {
        0x180
    } else {
        0
    };
    let required_table_end = table_offset
        + num_blocks * 4
        + if ctx.reencrypt { num_blocks * 4 } else { 0 }
        + if ctx.reencrypt { num_blocks * 4 } else { 0 }
        + c1_reserve;
    let min_section_size = max_phys_offset.max(required_table_end);
    let mut total_section_size = ((min_section_size + 0xFF) & !0xFF) + 0x100;

    if needs_boot_stub {
        total_section_size += BOOT_AREA_RESERVE;
        ctx.crypto_enabled = true;
        ctx.boot_entry_offset = (total_section_size - BOOT_AREA_RESERVE) as u32;
    }

    let ring_va: u64 = if block_ring {
        let ring_off = if needs_boot_stub {
            total_section_size - BOOT_AREA_RESERVE - dispatcher::RING_REGION
        } else {
            total_section_size
        };
        total_section_size += dispatcher::RING_REGION;
        if needs_boot_stub {
            ctx.boot_entry_offset = (total_section_size - BOOT_AREA_RESERVE) as u32;
        }
        dispatcher_va + ring_off as u64
    } else {
        0
    };

    // S2: --dispatcher-reencrypt도 M7식 refcount 재암호화 디스패처로 승격 — per-block
    //     (reencrypt) 경로는 항상 m7/m7_c1 디스패처를 쓴다.
    //     (build_dispatcher_reencrypt(_c1)은 unit-test용으로만 남겨 두고 패킹 경로에서는
    //     더 이상 호출하지 않는다.)
    let (c1_state_va, c1_sbox_va) = if ctx.reencrypt && ctx.custom_cipher {
        (
            dispatcher_va + (first_block_offset - 0x180) as u64,
            dispatcher_va + (first_block_offset - 0x100) as u64,
        )
    } else {
        (0, 0)
    };
    let dispatcher_bytes = (if ctx.reencrypt {
        if block_ring {
            println!("[!] --block-ring: m7/reencrypt dispatcher is not instrumented (standard-dispatcher only); ignored for this build.");
        }
        if ctx.custom_cipher {
            dispatcher::build_dispatcher_m7_c1(
                dispatcher_va,
                table_offset,
                num_blocks,
                ctx.mba_constant,
                trace_blocks,
                c1_state_va,
                c1_sbox_va,
            )
        } else {
            dispatcher::build_dispatcher_m7(
                dispatcher_va,
                table_offset,
                num_blocks,
                ctx.mba_constant,
                trace_blocks,
            )
        }
    } else {
        Ok(dispatcher::build_dispatcher(
            dispatcher_va,
            table_offset,
            num_blocks,
            trace_blocks,
            ctx.mba_constant,
            block_ring,
            ring_va,
            ctx.effective_obf_level(),
        ))
    })?;
    dispatcher::validate_dispatcher(&dispatcher_bytes)?;
    // 상용 1-3 (Notes #3): RIP-relative 오프셋이 실제 .btg 테이블/영역을
    // 가리키는지 + 점프 테이블 인덱스 바운드 체크(cmp idx, num_blocks; cmovae)
    // 존재 여부를 dispatcher_va/레이아웃을 알고 검증한다.
    dispatcher::validate_dispatcher_with_base(
        &dispatcher_bytes,
        dispatcher_va,
        total_section_size,
        num_blocks,
    )?;
    let abi_violations =
        crate::vm::abi::validate_win64_abi(&dispatcher_bytes, dispatcher_va + 0x20)?;
    if !abi_violations.is_empty() {
        return Err(anyhow::anyhow!(
            "Win64 ABI violation in generated dispatcher:\n  {}",
            abi_violations.join("\n  ")
        ));
    }

    println!(
        "[+] Dispatcher: table_offset=0x{:X}, shellcode_len={} bytes, available={} bytes, anti_debug={}, block_ring={}",
        table_offset,
        dispatcher_bytes.len(),
        table_offset.saturating_sub(0x20),
        anti_debug,
        block_ring
    );

    let disp_end = 0x20 + dispatcher_bytes.len();
    if disp_end > table_offset {
        return Err(anyhow::anyhow!(
            "Dispatcher shellcode ({} bytes) overflows into jump table at offset 0x{:X}! (max {} bytes)",
            dispatcher_bytes.len(), table_offset, table_offset - 0x20
        ).into());
    }
    if block_ring {
        println!(
            "[+] Diag ring-buffer: {} entries x4B @VA 0x{:X} (next-index u32 @0x{:X}), region [0x{:X}..0x{:X})",
            dispatcher::RING_ENTRIES,
            ring_va,
            ring_va + dispatcher::RING_ENTRIES as u64 * 4,
            ring_va,
            ring_va + dispatcher::RING_REGION as u64
        );
    }

    let (anti_debug_bytes, ad_offset) = if anti_debug && !needs_boot_stub {
        if block_ring {
            println!("[!] Anti-Debug shellcode skipped: overlaps --block-ring ring region without a boot stub (use a boot-stub config).");
            (Vec::new(), 0)
        } else {
            let off =
                total_section_size.saturating_sub(dispatcher::antidebug::ANTI_DEBUG_SIZE + 16);
            let ad = dispatcher::antidebug::build_anti_debug_shellcode(
                dispatcher_va + off as u64,
                dispatcher_va + 0x20,
                anti_debug_policy,
            );
            println!(
                "[+] Anti-Debug: Generated {} bytes of anti-debugging shellcode (policy={}).",
                ad.len(),
                anti_debug_policy.as_str()
            );
            (ad, off)
        }
    } else {
        (Vec::new(), 0)
    };

    let mut btg_bytes = vec![0u8; total_section_size];

    let entry_block_id = resolve_entry_block_id(ctx)?;
    let entry_seed = MbaGenerator::seed_for(ctx.mba_constant, entry_block_id as u32);

    ctx.entry_block_id = entry_block_id;
    ctx.entry_seed = entry_seed;

    let mut oep_stub = Vec::new();
    if ctx.reencrypt {
        oep_stub.extend_from_slice(&[0x68]); // push imm32 (current_id = sentinel)
        oep_stub.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        oep_stub.extend_from_slice(&[0x68]); // push imm32 (entry_block_id)
        oep_stub.extend_from_slice(&(entry_block_id as u32).to_le_bytes());
        oep_stub.extend_from_slice(&[0x68]); // push imm32 (entry_seed)
        oep_stub.extend_from_slice(&entry_seed.to_le_bytes());
        oep_stub.extend_from_slice(&[0xEB, 0x0F]); // jmp short +0x0F ??0x20
    } else {
        oep_stub.extend_from_slice(&[0x68]); // push imm32 (entry_block_id)
        oep_stub.extend_from_slice(&(entry_block_id as u32).to_le_bytes());
        oep_stub.extend_from_slice(&[0x68]); // push imm32 (entry_seed)
        oep_stub.extend_from_slice(&entry_seed.to_le_bytes());
        if !anti_debug_bytes.is_empty() {
            let disp = (ad_offset as i64) - 15;
            oep_stub.extend_from_slice(&[0xE9]);
            oep_stub.extend_from_slice(&(disp as i32).to_le_bytes());
        } else {
            oep_stub.extend_from_slice(&[0xEB, 0x14]); // jmp short +0x14 ??0x20
        }
    }

    btg_bytes[0..oep_stub.len()].copy_from_slice(&oep_stub);

    btg_bytes[0x18..0x1C].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // UNWIND_INFO
    btg_bytes[0x1D..0x1F].copy_from_slice(&[0xFF, 0xE0]); // jmp rax
    btg_bytes[0x1F] = 0xC3; // ret

    if !anti_debug_bytes.is_empty() {
        btg_bytes[ad_offset..ad_offset + anti_debug_bytes.len()].copy_from_slice(&anti_debug_bytes);
        println!("[+] Anti-Debug: Placed at section offset 0x{:X}", ad_offset);
    }

    btg_bytes[0x20..disp_end].copy_from_slice(&dispatcher_bytes);

    let layout = ctx
        .shuffled_layout
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("T3-3: shuffled_layout not set — run pass3 before pass4"))?;
    for (logical_id, &encrypted_entry) in layout.encrypted_table_entries.iter().enumerate() {
        let tbl_pos = table_offset + logical_id * 4;
        if tbl_pos + 4 <= btg_bytes.len() {
            btg_bytes[tbl_pos..tbl_pos + 4].copy_from_slice(&encrypted_entry.to_le_bytes());
        }
    }

    if ctx.reencrypt {
        let length_table_offset = table_offset + num_blocks * 4;
        let mut call_target_count = 0usize;
        for block in &layout.shuffled_blocks {
            let id = block.id as usize;
            let seed = MbaGenerator::seed_for(ctx.mba_constant, block.id);
            let key = MbaGenerator::compute_key(seed, block.id, ctx.mba_constant, 2);
            let len_enc = if ctx.call_target_block_ids.contains(&block.id) {
                call_target_count += 1;
                key
            } else {
                (block.instructions.len() as u32) ^ key
            };
            if len_enc == 0xFFFF_FFFEu32 {
                return Err(anyhow::anyhow!(
                    "v14: block {} length entry 0xFFFFFFFE collides with dispatcher claim marker - rebuild (shuffle/seed re-randomizes)",
                    id
                ));
            }
            let tbl_pos = length_table_offset + id * 4;
            if tbl_pos + 4 <= btg_bytes.len() {
                btg_bytes[tbl_pos..tbl_pos + 4].copy_from_slice(&len_enc.to_le_bytes());
            }
        }
        println!(
            "[+] v8 Dispatcher Re-Encrypt: length table ({} entries, key-XORed) @0x{:X} ({} call-target plaintext sentinels)",
            num_blocks, length_table_offset, call_target_count
        );
    }

    // S2: --dispatcher-reencrypt도 M7식 상태 테이블을 쓰므로 ctx.reencrypt 기준.
    if ctx.reencrypt {
        let state_table_offset = table_offset + num_blocks * 8;
        let mut call_target_count = 0usize;
        for block in &layout.shuffled_blocks {
            let id = block.id as usize;
            let state: u32 = if ctx.call_target_block_ids.contains(&block.id) {
                call_target_count += 1;
                0
            } else {
                0xFFFF_FFFF
            };
            let tbl_pos = state_table_offset + id * 4;
            if tbl_pos + 4 <= btg_bytes.len() {
                btg_bytes[tbl_pos..tbl_pos + 4].copy_from_slice(&state.to_le_bytes());
            }
        }
        println!(
            "[+] v61 M7/reencrypt: on-demand state table ({} entries: ENC/call-target) @0x{:X} ({} call-target plaintext)",
            num_blocks, state_table_offset, call_target_count
        );
    }

    if ctx.reencrypt && ctx.custom_cipher {
        let sbox_off = first_block_offset - 0x100;
        let sbox = crate::crypto::nonlinear::sbox();
        if sbox_off + 0x100 <= btg_bytes.len() {
            btg_bytes[sbox_off..sbox_off + 0x100].copy_from_slice(&sbox);
        }
        let state_off = first_block_offset - 0x180;
        if state_off + 0x80 <= btg_bytes.len() {
            btg_bytes[state_off..state_off + 0x80].fill(0);
        }
        println!(
            "[+] v61 C1: sbox @0x{:X} (256B), state @0x{:X} (0x80B) reserved before first_block 0x{:X}",
            sbox_off, state_off, first_block_offset
        );
    }

    for (i, block) in layout.shuffled_blocks.iter().enumerate() {
        let logical_id = block.id as usize;
        let phys_offset = layout.table_offsets[logical_id] as usize;
        let encrypted_offset = layout.encrypted_table_entries[logical_id];
        let block_len = block.instructions.len();

        let ct_mark = if ctx.call_target_block_ids.contains(&block.id) {
            " | CALL-TARGET (plaintext)"
        } else {
            ""
        };
        println!(
            "    [Block {:02}] Logical ID: {} | Phys Offset: 0x{:04X} | Encrypted Entry: 0x{:08X} | Entries: {} | Len: {}{}",
            i, block.id, phys_offset, encrypted_offset, block.entries.len(), block_len, ct_mark
        );

        if phys_offset + block_len > btg_bytes.len() {
            return Err(anyhow::anyhow!(
                "Block {} at offset 0x{:X} + len {} exceeds section size 0x{:X}!",
                block.id,
                phys_offset,
                block_len,
                btg_bytes.len()
            )
            .into());
        }

        if i + 1 < layout.shuffled_blocks.len() {
            let next_id = layout.shuffled_blocks[i + 1].id;
            let next_phys = layout.table_offsets[next_id as usize] as usize;
            if phys_offset + block_len > next_phys {
                return Err(anyhow::anyhow!(
                    "Block {} (0x{:X}..0x{:X}) overflows into next block {} slot at 0x{:X}! block_len={}",
                    block.id, phys_offset, phys_offset + block_len, next_id, next_phys, block_len
                ).into());
            }
        }

        btg_bytes[phys_offset..phys_offset + block_len].copy_from_slice(&block.instructions);
    }

    {
        let mut original_ud2 = 0usize;
        for block in &layout.shuffled_blocks {
            let n = block.instructions.len();
            let mut j = 0usize;
            while j + 1 < n {
                if block.instructions[j] == 0x0f && block.instructions[j + 1] == 0x0b {
                    original_ud2 += 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
        }
        if original_ud2 > 0 {
            println!("[+] Pass4: Preserved {} ud2 trap(s) verbatim across {} code blocks in .textb (no NOP conversion ??fall-through safety).",
                original_ud2, layout.shuffled_blocks.len());
        }
    }

    let characteristics = if needs_boot_stub && !ctx.mem_harden {
        0xE0000020u32
    } else {
        0x60000020u32
    };

    ctx.btg_section_data = Some(SectionData {
        name: ".textb".to_string(), // decoy section name (was .btg)
        virtual_address: dispatcher_rva,
        virtual_size: btg_bytes.len() as u32,
        characteristics, // CODE | EXECUTE | READ (+ WRITE if crypto)
        bytes: btg_bytes,
    });

    println!(
        "[+] Pass 4 Complete: .btg section assembled ({} bytes, entry_block_id={}, OEP_RVA=0x{:X}, boot_stub={}).",
        total_section_size, entry_block_id, dispatcher_rva, needs_boot_stub
    );

    Ok(())
}

fn resolve_entry_block_id(ctx: &PipelineContext) -> Result<usize> {
    let target_ep_va = ctx.target_info.image_base + ctx.target_info.entry_point_rva as u64;
    let va_map = &ctx.va_to_trigger_id;

    if let Some(&id) = va_map.get(&target_ep_va) {
        println!(
            "[INFO] Entry Block ID resolved to {} for OEP VA 0x{:X}",
            id, target_ep_va
        );
        return Ok(id as usize);
    }

    if let Some((&next_va, &next_id)) = va_map.range((target_ep_va + 1)..).next() {
        if next_va - target_ep_va <= MAX_PADDING_SIZE {
            println!(
                "[INFO] Entry Block ID resolved to {} (next after padding) for OEP VA 0x{:X}",
                next_id, target_ep_va
            );
            return Ok(next_id as usize);
        }
    }

    if let Some((_, &id)) = va_map.range(..=target_ep_va).next_back() {
        eprintln!(
            "[WARN] OEP VA 0x{:X} is inside block ID {}. Using that block.",
            target_ep_va, id
        );
        return Ok(id as usize);
    }

    eprintln!(
        "[WARN] Could not find entry block for OEP VA 0x{:X}! Defaulting to block 0.",
        target_ep_va
    );
    Ok(0)
}
