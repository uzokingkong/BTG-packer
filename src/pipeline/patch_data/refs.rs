// ==============================================================================
// BTG - v13 data/code direct-reference block collection - split from patch_data.rs
// ==============================================================================
use crate::pe::builder::SectionData;
use crate::util::is_block_entry;
use std::collections::{BTreeMap, HashSet};

use super::imports::is_rva_range_protected;

/// `va`가 Trigger Block 시작점이면 그 블록 ID를 `out`에 추가한다.
fn mark_block_entry(
    out: &mut HashSet<u32>,
    va_to_trigger_id: &BTreeMap<u64, u32>,
    va: u64,
    text_start_va: u64,
    text_end_va: u64,
) {
    if va < text_start_va || va >= text_end_va {
        return;
    }
    if let Some(&id) = va_to_trigger_id.get(&va) {
        if is_block_entry(va_to_trigger_id, va, id) {
            out.insert(id);
        }
    }
}

/// 정확 일치(블록 시작) → 포함 관계 순으로 VA를 블록 ID로 해석한다.
pub(crate) fn resolve_block_id(
    map: &BTreeMap<u64, u32>,
    va: u64,
    text_start_va: u64,
    text_end_va: u64,
) -> Option<u32> {
    if va < text_start_va || va >= text_end_va {
        return None;
    }
    if let Some(&id) = map.get(&va) {
        return Some(id);
    }
    map.range(..=va).next_back().map(|(_, &id)| id)
}

/// v13: **데이터 섹션에 저장된 코드 포인터**가 가리키는 블록을 수집한다.
///
/// v11은 직접 `call` 명령의 타깃만 평문으로 유지했지만, CRT 초기화 테이블(.CRT),
/// vtable, SEH 핸들러, 점프 테이블 등 **데이터로 저장된 함수 포인터**를 통한 간접
/// 호출은 디스패처를 거치지 않는다. 대상 블록이 암호문 상태로 남으면 ciphertext가
/// 그대로 실행되어 0xC000001D (illegal instruction) 크래시가 발생한다.
/// (실측: pack_orig.exe — ucrtbase!initterm_e가 .rdata 0x23438의 CRT 초기화
///  포인터로 Block 1646 @0x140054F6E를 직접 호출 → WER 0xC000001D @0x54F6E)
///
/// `patch_data::run`이 .btg로 재배치하는 포인터와 동일한 기준(블록 시작점 정확
/// 일치)으로 스캔하므로, 수집 결과는 "재배치되어 런타임에 직접 실행되는 블록"
/// 집합과 정확히 일치한다. 반드시 Pass 4(길이 테이블 센티널)와 Crypto(암호화
/// 제외)보다 **먼저** 실행되어야 한다.
pub(crate) fn collect_data_reference_target_ids(
    sections: &[SectionData],
    image_base: u64,
    text_start_va: u64,
    text_end_va: u64,
    text_rva_start: u32,
    text_rva_end: u32,
    va_to_trigger_id: &BTreeMap<u64, u32>,
    protected_ranges: &[(u32, u32)],
) -> HashSet<u32> {
    let mut out = HashSet::new();

    for sec in sections {
        // .pdata RUNTIME_FUNCTION: Begin/End RVA (함수 경계 — SEH 언와인드/핸들러)
        if sec.name == ".pdata" {
            for off in (0..sec.bytes.len().saturating_sub(11)).step_by(12) {
                let begin_rva =
                    u32::from_le_bytes(sec.bytes[off..off + 4].try_into().unwrap_or([0; 4]));
                let end_rva =
                    u32::from_le_bytes(sec.bytes[off + 4..off + 8].try_into().unwrap_or([0; 4]));
                for rva in [begin_rva, end_rva] {
                    if rva >= text_rva_start && rva < text_rva_end {
                        if let Some(id) = resolve_block_id(
                            va_to_trigger_id,
                            image_base + rva as u64,
                            text_start_va,
                            text_end_va,
                        ) {
                            out.insert(id);
                        }
                    }
                }
            }
            continue;
        }

        // 실행 섹션 / .reloc 제외 (분기 타깃·재배치 테이블은 별도 경로)
        if (sec.characteristics & 0x2000_0000) != 0 || sec.name == ".reloc" {
            continue;
        }
        if sec.bytes.len() < 4 {
            continue;
        }

        for offset in (0..sec.bytes.len().saturating_sub(3)).step_by(4) {
            let current_rva = sec.virtual_address + offset as u32;

            // 1. 64-bit 절대 VA 포인터 (8바이트 정렬)
            if offset % 8 == 0
                && offset + 8 <= sec.bytes.len()
                && !is_rva_range_protected(current_rva, 8, protected_ranges)
            {
                let val64 = u64::from_le_bytes(
                    sec.bytes[offset..offset + 8].try_into().unwrap_or([0; 8]),
                );
                mark_block_entry(&mut out, va_to_trigger_id, val64, text_start_va, text_end_va);
            }

            // 2. 32-bit RVA 포인터 (SEH ScopeTable, RTTI, CRT 함수 포인터 테이블,
            //    x64 MSVC 점프 테이블)
            if !is_rva_range_protected(current_rva, 4, protected_ranges) {
                let val32 = u32::from_le_bytes(
                    sec.bytes[offset..offset + 4].try_into().unwrap_or([0; 4]),
                );
                if val32 >= text_rva_start && val32 < text_rva_end {
                    mark_block_entry(
                        &mut out,
                        va_to_trigger_id,
                        image_base + val32 as u64,
                        text_start_va,
                        text_end_va,
                    );
                }
            }
        }
    }

    out
}

/// v13: .text 코드에서 **함수 포인터를 재료화**하는 명령의 타깃 블록을 수집한다.
///
/// x64에서 `lea reg,[rip+func]` / `mov reg, imm64(func)`로 함수 주소를 만든 뒤
/// 간접 `call`하면 디스패처를 거치지 않는다. (콜백 등록, vtable 간접 호출,
/// atexit 등록 등) rip-relative 메모리 피연산자 대상은 블록 **내부** 데이터/상수
/// 참조일 수도 있으므로 포함 관계로 해석해 블록 전체를 평문으로 유지한다.
pub(crate) fn collect_code_materialized_target_ids(
    text_bytes: &[u8],
    text_base_va: u64,
    text_start_va: u64,
    text_end_va: u64,
    va_to_trigger_id: &BTreeMap<u64, u32>,
) -> HashSet<u32> {
    let mut out = HashSet::new();
    let mut decoder =
        iced_x86::Decoder::with_ip(64, text_bytes, text_base_va, iced_x86::DecoderOptions::NONE);

    while decoder.can_decode() {
        let inst = decoder.decode();
        if inst.is_invalid() {
            continue;
        }

        // RIP-relative 메모리 피연산자: lea reg,[rip+disp] / mov reg,[rip+disp]
        if inst.memory_base() == iced_x86::Register::RIP
            && inst.memory_index() == iced_x86::Register::None
        {
            let target = inst.ip() + inst.len() as u64 + inst.memory_displacement64();
            if let Some(id) =
                resolve_block_id(va_to_trigger_id, target, text_start_va, text_end_va)
            {
                out.insert(id);
            }
        }

        // mov reg, imm64 — 절대 함수 주소 직접 재료화
        if inst.code() == iced_x86::Code::Mov_r64_imm64 {
            let target = inst.immediate64();
            mark_block_entry(&mut out, va_to_trigger_id, target, text_start_va, text_end_va);
        }
    }

    out
}