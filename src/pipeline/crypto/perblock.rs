// ==============================================================================
// Dispatcher re-encryption (--dispatcher-reencrypt): per-block MBA-key collection
// ==============================================================================

use crate::crypto::{BlockCryptoMeta, CryptoProvider};
use crate::graph::ShuffledLayout;
use crate::pipeline::PipelineContext;

pub(crate) fn collect_block_keys(
    ctx: &PipelineContext,
    layout: &ShuffledLayout,
    reencrypt: bool,
) -> (Vec<(usize, usize, u32)>, usize) {
    let block_keys: Vec<(usize, usize, u32)> = if reencrypt {
        layout
            .shuffled_blocks
            .iter()
            .filter(|block| !ctx.call_target_block_ids.contains(&block.id))
            .map(|block| {
                let id = block.id;
                let off = layout.table_offsets[id as usize] as usize;
                let len = block.instructions.len();
                // plan.txt 3단계: 블록 메타데이터 → CryptoProvider::derive_block_key.
                // RC4 구현 = 기존 MBA per-block 키 (디스패처 셸코드와 동일).
                let meta = BlockCryptoMeta::new(id, off as u64, len as u32);
                let k = <crate::pipeline::crypto::cipher::Rc4 as CryptoProvider>::derive_block_key(
                    &ctx.mba_constant.to_le_bytes(),
                    &meta,
                );
                let key = u32::from_le_bytes(k[..4].try_into().unwrap());
                (off, len, key)
            })
            .collect()
    } else {
        Vec::new()
    };
    let total_blocks = layout.shuffled_blocks.len();
    (block_keys, total_blocks)
}

/// Build full BTG-RC1 key+nonce material for each independently encrypted
/// dispatcher block.  This is intentionally separate from `collect_block_keys`:
/// the legacy native dispatcher table only has a 32-bit key slot and must be
/// widened before it can consume RC1's 44-byte provider ABI without truncation.
pub(crate) fn collect_region_block_keys(
    ctx: &PipelineContext,
    layout: &ShuffledLayout,
    reencrypt: bool,
) -> (Vec<(usize, usize, [u8; 44])>, usize) {
    let block_keys = if reencrypt {
        layout
            .shuffled_blocks
            .iter()
            .filter(|block| !ctx.call_target_block_ids.contains(&block.id))
            .map(|block| {
                let id = block.id;
                let off = layout.table_offsets[id as usize] as usize;
                let len = block.instructions.len();
                let meta = BlockCryptoMeta::new(id, off as u64, len as u32);
                let derived =
                    <crate::crypto::RegionCipherProvider as CryptoProvider>::derive_block_key(
                        &ctx.mba_constant.to_le_bytes(),
                        &meta,
                    );
                let material: [u8; 44] = derived
                    .try_into()
                    .expect("BTG-RC1 provider key ABI is fixed at 44 bytes");
                (off, len, material)
            })
            .collect()
    } else {
        Vec::new()
    };
    (block_keys, layout.shuffled_blocks.len())
}
