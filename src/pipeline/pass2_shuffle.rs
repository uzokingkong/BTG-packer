// ==============================================================================
// BTG Pipeline - Pass 2: Physical Layout Shuffling
// ==============================================================================

use crate::graph::LayoutShuffler;
use crate::pipeline::PipelineContext;
use anyhow::Result;

/// Pass 2: 트리거 블록을 물리 레이아웃에서 무작위 배치(shuffle)하고
/// 점프 테이블 오프셋과 블록 시작 오프셋을 동적으로 계산한다.
///
/// # table_offset 자동 계산
/// 기존 하드코딩 `0x80` 대신:
/// 1. 임시 dispatcher_bytes 길이를 추정 (`DISPATCHER_APPROX_SIZE`)
/// 2. `table_offset = align(0x20 + dispatcher_size, 0x10)` 으로 결정
/// 3. `first_block_offset = align(table_offset + num_blocks * 4, 0x100)`
///
/// 이 계산은 `dispatcher::build()` 호출 전에 실행되므로 실제 dispatcher 크기를
/// 아직 모른다. 따라서 보수적 상한(96바이트)을 사용하고, Pass 3 이후
/// `validate_dispatcher` 에서 overflow 여부를 최종 확인한다.
///
/// 완료 후 `ctx`에 설정되는 필드:
/// - `ctx.table_offset`
/// - `ctx.first_block_offset`
/// - `ctx.shuffled_layout`
pub fn run(ctx: &mut PipelineContext) -> Result<()> {
    let num_blocks = ctx.trigger_blocks.len();

    // 디스패처 셸코드 최대 크기 상한 (OEP Stub 이후 확보 영역)
    // v10: 일반 디스패처가 실제 XOR/AND MBA 키 도출로 93B까지 커졌으므로
    // 상한을 0x80(128B)으로 늘려 여유를 둔다. (실제 셸코드가 이보다 짧으면
    // 나머지는 0x00 패딩으로 채워짐)
    const DISPATCHER_MAX_SIZE: usize = 0x80;

    // v8(Phase 0.3): 재암호화 디스패처는 RC4 KSA/PRGA 서브루틴을 포함해 커졌다.
    // 실제 빌더로 정확한 길이를 측정한다 (모든 참조는 disp32/rel32라 길이가
    // VA·테이블 오프셋과 무관하다). trace(INT3 1B)는 항상 포함해 측정 —
    // 실제 디스패처가 더 길어지는 일이 없도록 보수적으로 잡는다.
    // v61: --m7 디스패처는 재암호화 + refcount 상태 머신 + seed_for 재계산이
    // 더해져 더 크다 — 실제 빌더로 측정한다. --m7 + --custom-cipher면 BTG-C1
    // per-block blob(30KB)이 append되어 더욱 크다.
    // S2: --dispatcher-reencrypt도 M7식 refcount 재암호화 디스패처로 승격 —
    //     per-block(reencrypt) 경로는 항상 m7/m7_c1 빌더로 측정한다.
    //     (build_dispatcher_reencrypt(_c1)은 unit-test용으로만 남겨 둔다.)
    let dispatcher_size = if ctx.reencrypt {
        if ctx.custom_cipher {
            crate::dispatcher::build_dispatcher_m7_c1(0, 0, num_blocks, ctx.mba_constant, true, 0, 0)?.len()
        } else {
            crate::dispatcher::build_dispatcher_m7(0, 0, num_blocks, ctx.mba_constant, true)?.len()
        }
    } else if ctx.block_ring {
        // v13.4d diag: --block-ring 은 표준 디스패처에 ring-write ~24B 를 더한다.
        // 실제 셸코드가 0x80을 넘지 않도록 여유(+0x40)를 둔다. (테이블 앞 공간만 더
        // 예약하며, ring 저장소 자체는 pass4에서 섹션 tail에 별도로 잡는다.)
        DISPATCHER_MAX_SIZE + 0x40
    } else {
        DISPATCHER_MAX_SIZE
    };

    // table_offset: 0x20(dispatcher 시작) + dispatcher_size, 16-byte 정렬
    let raw_table_offset = 0x20 + dispatcher_size;
    let table_offset = (raw_table_offset + 0x0F) & !0x0F; // align to 16

    // first_block_offset: 테이블 끝 이후, 256-byte 정렬
    // v8: 재암호화 시 점프 테이블 뒤에 블록 길이 테이블(num_blocks*4)이 붙는다.
    // v61: M7/재암호화는 상태 테이블(num_blocks*4)까지 추가한다 (점프 + 길이 + 상태).
    // S2: 상태 테이블 예약도 `ctx.m7` 대신 `ctx.reencrypt` 기준으로 통일.
    // v61(+custom-cipher): C1 상태 버퍼(0x80) + S-box 상수 테이블(0x100)을
    // 테이블 직후(first_block_offset 직전)에 예약한다 (reencrypt/m7 per-block).
    let c1_reserve = if ctx.reencrypt && ctx.custom_cipher { 0x180 } else { 0 };
    let required_table_end = table_offset
        + num_blocks * 4
        + if ctx.reencrypt { num_blocks * 4 } else { 0 }
        + if ctx.reencrypt { num_blocks * 4 } else { 0 }
        + c1_reserve;
    let first_block_offset = (required_table_end + 0xFF) & !0xFF;

    debug_assert!(
        first_block_offset > table_offset,
        "first_block_offset (0x{:X}) must exceed table_offset (0x{:X})",
        first_block_offset, table_offset
    );
    debug_assert!(
        table_offset > 0x20,
        "table_offset (0x{:X}) must be > 0x20 (dispatcher region end)",
        table_offset
    );

    let shuffled_layout = LayoutShuffler::shuffle(ctx.trigger_blocks.clone(), first_block_offset, &mut ctx.rng);

    println!(
        "[+] Pass 2 Complete: table_offset=0x{:X}, first_block_offset=0x{:X}, {} blocks shuffled.",
        table_offset, first_block_offset, num_blocks
    );

    ctx.table_offset = table_offset;
    ctx.first_block_offset = first_block_offset;
    ctx.shuffled_layout = Some(shuffled_layout);

    Ok(())
}
