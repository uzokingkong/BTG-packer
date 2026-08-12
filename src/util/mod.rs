// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Utility Functions & Constants
// ==============================================================================

use std::collections::BTreeMap;

/// 블록 경계 탐색 시 padding 영역으로 허용하는 최대 바이트 수.
/// `resolve_va_to_real_va` 에서 "다음 블록 시작까지의 거리" 판단에 사용.
pub const MAX_PADDING_SIZE: u64 = 16;

/// 사전 초기화용 __security_cookie 시드값 (고정 상수, 랜덤화는 별도 PR로 처리).
/// Windows CRT가 기본값(`0x00002B992DDFA232`)을 감지하면 재초기화를 건너뛴다.
pub const COOKIE_INIT_VALUE: u64 = 0x12347F9E3B4C5D6E;

/// `va`가 Trigger Block의 **진짜 시작점(block entry)** 인지 판별한다.
///
/// `va_to_trigger_id`는 MicroSlicer가 **모든 인스트럭션의 IP**를 키로 등록하므로
/// (블록 시작점뿐 아니라 블록 중간의 각 명령어 주소까지) 단순히 `get(&va)`가
/// `Some`이라고 해서 블록 시작점이라는 뜻이 아니다. 값(block id)이 **직전 키의 값과
/// 달라지는 지점**이 곧 블록 시작점이다. 이 판별을 사용하지 않으면 블록 중간 주소를
/// 가리키는 데이터 포인터/분기 타깃이 블록 **시작점**(테이블 오프셋 + 0)으로 잘못
/// 재배치되어 엉뚱한 코드가 실행된다.
pub fn is_block_entry(va_to_trigger_id: &BTreeMap<u64, u32>, va: u64, block_id: u32) -> bool {
    if let Some((&prev_va, _)) = va_to_trigger_id.range(..va).next_back() {
        va_to_trigger_id.get(&prev_va) != Some(&block_id)
    } else {
        // 첫 번째 키는 블록 시작점
        true
    }
}

/// 원본 `.text` VA → 재배치된 `.btg` 섹션 내 실제 VA 변환.
///
/// 탐색 순서:
/// 1. `va_to_trigger_id`에서 **블록 시작점** 정확 일치 (오직 block entry만 재배치)
/// 2. `target_va + 1 .. + MAX_PADDING_SIZE` 범위 내 다음 블록 (padding 영역)
/// 3. 그 외(블록 중간 주소 등) → `None` 반환. 호출 측은 원본 `.text` 주소를 유지한다.
///
/// # 왜 블록 중간 주소를 재배치하지 않는가
/// Pass 3는 각 블록의 명령어를 개별 BlockEncoder로 재인코딩하므로(RIP fixup, 분기
/// 스텁 등) 블록 내 명령어 길이가 원본과 달라질 수 있다. 이 경우 `원본 VA + 오프셋`
/// 으로 계산한 .btg 내 위치는 실제 명령어 경계와 어긋나 **명령어 중간으로 점프**하게
/// 되어 0xC0000005 크래시로 이어진다. 패커 출력에는 원본 `.text` 섹션이 그대로
/// 보존·실행 가능하므로, 정확히 매칭되지 않는 타깃은 원본 주소를 유지하는 것이
/// 안전하다(보호 커버리지가 줄어드는 대신 정확성이 보장됨).
pub fn resolve_va_to_real_va(
    target_va: u64,
    text_start_va: u64,
    text_end_va: u64,
    va_to_trigger_id: &BTreeMap<u64, u32>,
    table_offsets: &[u32],
    dispatcher_va: u64,
) -> Option<u64> {
    if target_va < text_start_va || target_va >= text_end_va {
        return None;
    }

    // 1. 블록 시작점 정확 일치
    if let Some(&block_id) = va_to_trigger_id.get(&target_va) {
        if is_block_entry(va_to_trigger_id, target_va, block_id) {
            let real_va = dispatcher_va + table_offsets[block_id as usize] as u64;
            return Some(real_va);
        }
        // 블록 중간 주소: 원본 .text 유지
        return None;
    }

    // 2. Padding gap: 다음 블록 시작이 MAX_PADDING_SIZE 이내이면 그 블록 시작점으로
    if let Some((&next_va, &next_block_id)) = va_to_trigger_id.range((target_va + 1)..).next() {
        if next_va - target_va <= MAX_PADDING_SIZE && is_block_entry(va_to_trigger_id, next_va, next_block_id) {
            let real_va = dispatcher_va + table_offsets[next_block_id as usize] as u64;
            return Some(real_va);
        }
    }

    // 3. 내부 오프셋 매핑은 제거 (오프셋이 재인코딩 길이 변화로 어긋날 수 있음)
    None
}
