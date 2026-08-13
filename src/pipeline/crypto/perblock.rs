// ==============================================================================
// Dispatcher re-encryption (--dispatcher-reencrypt): per-block MBA-key collection
// ==============================================================================

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
                let seed = crate::mba::MbaGenerator::seed_for(ctx.mba_constant, id);
                let key = crate::mba::MbaGenerator::compute_key(seed, id, ctx.mba_constant, 2);
                (off, len, key)
            })
            .collect()
    } else {
        Vec::new()
    };
    let total_blocks = layout.shuffled_blocks.len();
    (block_keys, total_blocks)
}
