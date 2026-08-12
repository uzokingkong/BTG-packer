// ==============================================================================
// BTG Pipeline - Pass 3: RIP Fixup & Final Block Encoding
// ==============================================================================
// v2 변경: 블록 밀집 패킹(dense packing)
//   - pass2가 배정한 여유 있는 슬롯 오프셋에서 각 블록의 정확한 인코딩 길이를 측정한 뒤,
//   - 각 블록을 "직전 블록의 실제 끝 + 16B 정렬" 위치에 연속 배치하여
//     블록 사이 여유 마진(과거 256B / v1 192~384B)을 제거한다.
//   - 오프셋이 수렴할 때까지 재인코딩을 반복하고, 최종 오프셋으로
//     `table_offsets` / `encrypted_table_entries`(offset ^ MBA키)를 갱신한다.
// ==============================================================================

use crate::core::trigger_block::TriggerBlock;
use crate::graph::RipFixupEngine;
use crate::pipeline::PipelineContext;
use crate::util::resolve_va_to_real_va;
use anyhow::Result;
use iced_x86::{BlockEncoder, BlockEncoderOptions, InstructionBlock, OpKind};
use std::collections::{BTreeMap, HashMap};

/// 단일 트리거 블록을 `phys_offset`(섹션 내 물리 오프셋)에 인코딩한다.
///
/// RIP fixup · 분기 타깃 재작성 · Batch BlockEncoder를 수행하고,
/// 최종 기계어 바이트(선택적 misaligned prefix 포함)를 `block.instructions`에 저장한다.
///
/// 반환: (실제 코드 시작 물리 오프셋, MBA 키로 암호화된 테이블 엔트리 값)
fn encode_block_at(
    block: &mut TriggerBlock,
    phys_offset: usize,
    dispatcher_va: u64,
    text_start_va: u64,
    text_end_va: u64,
    va_to_trigger_id: &BTreeMap<u64, u32>,
    table_offsets: &[u32],
    obf_complexity: usize,
    mba_constant: u32,
) -> Result<(u32, u32)> {
    let real_block_va = dispatcher_va + phys_offset as u64;

    if block.entries.len() > 1 {
        block.validate_polymorphism()
            .map_err(|e| anyhow::anyhow!("Polymorphism validation failed: {}", e))?;
    }

    // Misaligned entry가 있으면 4-byte prefix stub 삽입
    let mut prefix_bytes = Vec::new();
    let mut entry_offset: u64 = 0;
    for entry in block.entries.values() {
        if let crate::core::trigger_block::EntryPointType::Misaligned(offset) = entry.entry_type {
            if offset > 0 {
                // Normal entry (+0):     0xEB 0x02 → jmp short +2 (→ code_start_va)
                // Misaligned entry (+1): 0x02 0xC0 (add al,al) + 0x90 (nop) — 레지스터 연산만
                prefix_bytes.extend_from_slice(&[0xEB, 0x02, 0xC0, 0x90]);
                entry_offset = 4;
                break;
            }
        }
    }

    let code_start_va = real_block_va + entry_offset;

    // ── 1. 준비 루프: target_va 수집 & fixup 사전 처리 ───────────────────────
    let mut rip_target_vas: HashMap<usize, u64> = HashMap::new();
    let mut branch_target_vas: HashMap<usize, u64> = HashMap::new();

    for (idx, inst) in block.raw_instructions.iter_mut().enumerate() {
        if let Some(fixup) = RipFixupEngine::scan_instruction(inst) {
            rip_target_vas.insert(idx, fixup.target_va);
        } else if matches!(
            inst.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ) {
            let is_jcc = if let Some((jcc_idx, _)) = block.jcc_info { idx == jcc_idx } else { false };
            if !is_jcc {
                branch_target_vas.insert(idx, inst.near_branch_target());
            }
        }
    }

    // ── 2. Fixup & Branch target 적용 ─────────────────────────────────────────
    let mut temp_ip = code_start_va;
    for (idx, inst) in block.raw_instructions.iter_mut().enumerate() {
        inst.set_ip(temp_ip);

        if let Some(&target_va) = rip_target_vas.get(&idx) {
            let effective_target_va = resolve_va_to_real_va(
                target_va,
                text_start_va,
                text_end_va,
                va_to_trigger_id,
                table_offsets,
                dispatcher_va,
            ).unwrap_or(target_va);

            RipFixupEngine::process_fixup(inst, temp_ip, effective_target_va)?;
        } else if let Some(&orig_target_va) = branch_target_vas.get(&idx) {
            let effective_target_va = resolve_va_to_real_va(
                orig_target_va,
                text_start_va,
                text_end_va,
                va_to_trigger_id,
                table_offsets,
                dispatcher_va,
            ).unwrap_or(orig_target_va);

            inst.set_near_branch64(effective_target_va);
        }

        // 명령어 길이 측정: 새로 생성된 스텁 명령어(len == 0)는 1-instruction BlockEncoder로 정확한 바이트 크기를 구함
        let inst_arr = [*inst];
        let single_block = InstructionBlock::new(&inst_arr, temp_ip);
        let inst_len = match BlockEncoder::encode(64, single_block, BlockEncoderOptions::NONE) {
            Ok(res) => res.code_buffer.len(),
            Err(_) => if inst.len() > 0 { inst.len() } else { 5 },
        };

        temp_ip += inst_len as u64;
    }

    // ── 3. Jcc Taken Stub Target 오프셋 연결 ───────────────────────────────────
    if let Some((jcc_idx, taken_idx)) = block.jcc_info {
        let taken_stub_ip = block.raw_instructions[taken_idx].ip();
        if let Some(jcc_inst) = block.raw_instructions.get_mut(jcc_idx) {
            jcc_inst.set_near_branch64(taken_stub_ip);
        }
    }

    // ── 4. 전체 블록 일괄 인코딩 (Batch BlockEncoder) ─────────────────────────
    let enc_block = InstructionBlock::new(&block.raw_instructions, code_start_va);
    let encoded_result = BlockEncoder::encode(64, enc_block, BlockEncoderOptions::NONE)
        .map_err(|e| anyhow::anyhow!(
            "Batch BlockEncoder error for block {}: {:?}",
            block.id, e
        ))?;

    let mut final_bytes = Vec::new();
    if !prefix_bytes.is_empty() {
        final_bytes.extend_from_slice(&prefix_bytes);
    }
    final_bytes.extend_from_slice(&encoded_result.code_buffer);

    block.instructions = final_bytes;

    // v6: MBA 키로 테이블 엔트리 암호화 — 디스패처가 런타임에 동일 항등식으로 재도출.
    //     key = ((seed ^ id) + 2*(seed & id)) ^ C, seed = seed_for(C, id)
    let _ = obf_complexity; // 키 스케줄은 항상 레벨 2 항등식을 사용 (v6)
    let seed = crate::mba::MbaGenerator::seed_for(mba_constant, block.id);
    let dynamic_table_key = crate::mba::MbaGenerator::compute_key(seed, block.id, mba_constant, 2);

    let real_code_phys_offset = (phys_offset as u32) + (entry_offset as u32);
    Ok((real_code_phys_offset, dynamic_table_key))
}


/// 16바이트 정렬이 실제로 필요한 블록인지 검사한다.
/// 정렬된 SIMD 메모리 접근(movaps/movapd/movdqa 등)을 포함한 블록만 16B
/// 정렬을 유지하고, 나머지는 1바이트 밀집 배치하여 섹션 크기를 줄인다.
fn block_needs_align(block: &TriggerBlock) -> bool {
    block.raw_instructions.iter().any(|inst| {
        matches!(
            inst.mnemonic(),
            iced_x86::Mnemonic::Movaps
                | iced_x86::Mnemonic::Movapd
                | iced_x86::Mnemonic::Movdqa
                | iced_x86::Mnemonic::Vmovaps
                | iced_x86::Mnemonic::Vmovapd
                | iced_x86::Mnemonic::Vmovdqa
                | iced_x86::Mnemonic::Movntps
                | iced_x86::Mnemonic::Movntpd
                | iced_x86::Mnemonic::Movntdq
        ) && (inst.op0_kind() == OpKind::Memory || inst.op1_kind() == OpKind::Memory)
    })
}

pub fn run(ctx: &mut PipelineContext) -> Result<()> {
    println!("[+] Pass 3 Starting: Applying IP Drift Corrected RipFixupEngine & final encoding (dense packing)...");

    let (text_start_va, text_end_va) = ctx.text_va_range();
    let dispatcher_va = ctx.dispatcher_va;
    let obf_complexity = ctx.obf_complexity;

    // ── 블록별 처리 ──────────────────────────────────────────────────────────────
    let layout = ctx.shuffled_layout.as_mut()
        .ok_or_else(|| anyhow::anyhow!("ShuffledLayout not yet built — run Pass 2 first"))?;

    let num_blocks = layout.shuffled_blocks.len();
    if num_blocks == 0 {
        return Ok(());
    }

    // ── v2: 블록 밀집 패킹 (fixed-point re-layout) ───────────────────────────────
    // 1) 현재(pass2 슬롯) 오프셋에서 정확한 인코딩 길이 측정 (사본 인코딩 — 원본 보존)
    // 2) 측정 길이로 밀집 오프셋 계산: 첫 블록은 기존 시작점 유지, 이후 블록은
    //    "직전 블록의 실제 끝 + 16B 정렬"에 배치 (여유 마진 제거)
    // 3) 밀집 오프셋에서 재인코딩 → 오프셋이 수렴할 때까지 반복
    // 마지막 반복 결과가 최종 레이아웃이며 table_offsets/encrypted_table_entries에 기록된다.
    const MAX_ITERS: usize = 8;
    let mut dense_offsets = layout.table_offsets.clone();

    for _iter in 0..MAX_ITERS {
        // (a) 현재 오프셋 기준 모든 블록 인코딩 길이 측정
        let mut lens: Vec<usize> = Vec::with_capacity(num_blocks);

        for block in layout.shuffled_blocks.iter() {
            let logical_id = block.id as usize;
            let phys_offset = dense_offsets[logical_id] as usize;
            let mut wb = block.clone();
            encode_block_at(
                &mut wb,
                phys_offset,
                dispatcher_va,
                text_start_va,
                text_end_va,
                &ctx.va_to_trigger_id,
                &dense_offsets,
                obf_complexity,
                ctx.mba_constant,
            )?;
            lens.push(wb.instructions.len());
        }

        // (b) 밀집 배치: 첫 블록은 기존 시작 오프셋(최소 오프셋) 유지
        // v4: 크기 최적화 — 16B 정렬은 실제로 정렬된 SIMD 메모리 접근을 포함한
        // 블록에만 적용하고, 나머지 블록은 1바이트 밀집 배치한다.
        // (스택/데이터 정렬은 디스패처의 RSP 보존과 원본 데이터 섹션 유지로 보장됨)
        let first_off = *dense_offsets.iter().min().unwrap_or(&0) as u64;
        let mut cursor = first_off;
        let mut new_offsets = vec![0u32; num_blocks];
        for (i, block) in layout.shuffled_blocks.iter().enumerate() {
            let id = block.id as usize;
            new_offsets[id] = cursor as u32;
            cursor = if block_needs_align(block) {
                ((cursor + lens[i] as u64) + 15) & !15
            } else {
                cursor + lens[i] as u64
            };
        }

        if new_offsets == dense_offsets {
            dense_offsets = new_offsets;
            break;
        }
        dense_offsets = new_offsets;
    }

    // ── 최종 인코딩 & 테이블 갱신 ────────────────────────────────────────────────
    for block in layout.shuffled_blocks.iter_mut() {
        let logical_id = block.id as usize;
        let phys_offset = dense_offsets[logical_id] as usize;
        let mut wb = block.clone();
        let (real_off, key) = encode_block_at(
            &mut wb,
            phys_offset,
            dispatcher_va,
            text_start_va,
            text_end_va,
            &ctx.va_to_trigger_id,
            &dense_offsets,
            obf_complexity,
            ctx.mba_constant,
        )?;

        block.instructions = wb.instructions;
        layout.table_offsets[logical_id] = real_off;
        layout.encrypted_table_entries[logical_id] = real_off ^ key;
    }

    println!("[+] Pass 3 Complete: {} blocks densely packed; table entries encrypted.", num_blocks);

    // ── v13.1-검증: 인코딩 완료 블록이 암호문(비-평문) 블록을 직접 참조하면 안 된다 ──
    // 재암호화 모드에서 디스패처를 거치지 않는 직접 참조(call/jmp/jcc/rip-relative/imm64)가
    // 평문 유지 집합(call_target_block_ids)에 없는 블록을 가리키면, 런타임에 그 블록은
    // 암호문 상태로 실행되어 0xC000001D 크래시가 발생한다. 여기서 전수 검사한다.
    if ctx.reencrypt {
        let dispatcher = ctx.dispatcher_va;
        let sec_start = dispatcher;
        let sec_end = dispatcher + 0x80000u64; // .btg 영역 상한 (대략)
        let mut refs_bad = Vec::new();
        for block in &layout.shuffled_blocks {
            let id = block.id;
            let off = layout.table_offsets[id as usize] as usize;
            let bva = dispatcher + off as u64;
            let plain = ctx.call_target_block_ids.contains(&id);
            let mut dec = iced_x86::Decoder::with_ip(64, &block.instructions, bva, iced_x86::DecoderOptions::NONE);
            while dec.can_decode() {
                let inst = dec.decode();
                if inst.is_invalid() { continue; }
                // 1) near branch target
                if matches!(inst.op0_kind(), iced_x86::OpKind::NearBranch16 | iced_x86::OpKind::NearBranch32 | iced_x86::OpKind::NearBranch64) {
                    let tgt = inst.near_branch_target();
                    if tgt >= sec_start && tgt < sec_end {
                        let tid_opt = ctx.va_to_trigger_id.iter()
                            .filter(|(_, &v)| v == id) // same block self-ref ok
                            .map(|(k,_)| *k).next();
                        let _ = tid_opt;
                        // find which logical block owns this relocated VA
                        let target_id = layout.shuffled_blocks.iter()
                            .find(|b| {
                                let o = layout.table_offsets[b.id as usize] as u64;
                                tgt >= dispatcher + o && tgt < dispatcher + o + b.instructions.len() as u64
                            })
                            .map(|b| b.id);
                        if let Some(tid) = target_id {
                            if tid != id && !ctx.call_target_block_ids.contains(&tid) {
                                refs_bad.push((id, inst.ip()-bva, tgt, tid, "branch", plain));
                            }
                        }
                    }
                }
                // 2) RIP-relative memory operand
                if inst.memory_base() == iced_x86::Register::RIP {
                    let tgt = inst.ip_rel_memory_address();
                    if tgt >= sec_start && tgt < sec_end {
                        let target_id = layout.shuffled_blocks.iter()
                            .find(|b| {
                                let o = layout.table_offsets[b.id as usize] as u64;
                                tgt >= dispatcher + o && tgt < dispatcher + o + b.instructions.len() as u64
                            })
                            .map(|b| b.id);
                        if let Some(tid) = target_id {
                            if tid != id && !ctx.call_target_block_ids.contains(&tid) {
                                refs_bad.push((id, inst.ip()-bva, tgt, tid, "rip", plain));
                            }
                        }
                    }
                }
                // 3) mov r64, imm64
                if inst.code() == iced_x86::Code::Mov_r64_imm64 {
                    let tgt = inst.immediate64();
                    if tgt >= sec_start && tgt < sec_end {
                        let target_id = layout.shuffled_blocks.iter()
                            .find(|b| {
                                let o = layout.table_offsets[b.id as usize] as u64;
                                tgt >= dispatcher + o && tgt < dispatcher + o + b.instructions.len() as u64
                            })
                            .map(|b| b.id);
                        if let Some(tid) = target_id {
                            if tid != id && !ctx.call_target_block_ids.contains(&tid) {
                                refs_bad.push((id, inst.ip()-bva, tgt, tid, "imm64", plain));
                            }
                        }
                    }
                }
            }
        }
        if !refs_bad.is_empty() {
            println!("[!] v13.1-VALIDATE: {} direct reference(s) from blocks to ENCRYPTED blocks found:", refs_bad.len());
            for (frm, foff, tgt, tid, kind, plain) in refs_bad.iter().take(40) {
                println!("    block {} [{}] @+0x{:x} -> 0x{:x} block {} ({}) [src_plain={}]", frm, kind, foff, tgt, tid, if ctx.call_target_block_ids.contains(tid) {"plain"} else {"ENCRYPTED"}, plain);
            }
        } else {
            println!("[+] v13.1-VALIDATE: no block-to-block direct reference targets an encrypted block. ✓");
        }
    }
    Ok(())
}
