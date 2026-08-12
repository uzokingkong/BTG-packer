// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Dynamic Encrypted Layout Shuffler
// ==============================================================================
// v2 변경: v1의 블록별 가변 마진(192~384B, 32/16B 교대 정렬)을 원본으로 롤백.
// 실제 최종 레이아웃은 pass3의 블록 밀집 패킹이 결정하므로,
// 여기의 슬롯 마진은 pass3 길이 측정용 안전 여유 역할만 한다.
// ==============================================================================

use crate::core::trigger_block::TriggerBlock;
use iced_x86::{BlockEncoder, BlockEncoderOptions, InstructionBlock};
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct BlockLayout {
    pub physical_offset: u32,
    pub encrypted_entry: u32,
}

#[derive(Debug, Clone)]
pub struct ShuffledLayout {
    pub blocks_by_id: HashMap<u32, TriggerBlock>,
    pub layout_map: HashMap<u32, BlockLayout>,
    pub shuffled_blocks: Vec<TriggerBlock>,
    pub table_offsets: Vec<u32>,
    pub encrypted_table_entries: Vec<u32>,
}

impl ShuffledLayout {
    pub fn get_layout(&self, logical_id: u32) -> anyhow::Result<&BlockLayout> {
        self.layout_map.get(&logical_id)
            .ok_or_else(|| anyhow::anyhow!("Invalid block ID: {}", logical_id))
    }
}

pub struct LayoutShuffler;

impl LayoutShuffler {
    /// Shuffles physical block placement and computes encrypted jump table entries.
    /// Uses Dummy BlockEncoder Pass to determine exact machine byte length,
    /// accounting for potential branch instruction expansion (rel8 -> rel32 promotion).
    pub fn shuffle(
        trigger_blocks: Vec<TriggerBlock>,
        first_block_physical_offset: usize,
    ) -> ShuffledLayout {
        let mut physical_order: Vec<usize> = (0..trigger_blocks.len()).collect();
        let mut rng = thread_rng();
        physical_order.shuffle(&mut rng);

        let mut shuffled_blocks = Vec::with_capacity(trigger_blocks.len());
        let mut table_offsets = vec![0u32; trigger_blocks.len()];
        let mut blocks_by_id = HashMap::new();
        let mut layout_map = HashMap::new();

        let mut current_offset = first_block_physical_offset;

        for &logical_idx in &physical_order {
            let block = trigger_blocks[logical_idx].clone();
            let logical_id = block.id as usize;

            table_offsets[logical_id] = current_offset as u32;

            // Dummy BlockEncoder Pass: Measure exact maximum encoded length at dummy address
            let dummy_va = 0x140002000;
            let dummy_block = InstructionBlock::new(&block.raw_instructions, dummy_va);
            let raw_len = match BlockEncoder::encode(64, dummy_block, BlockEncoderOptions::NONE) {
                Ok(result) => result.code_buffer.len(),
                Err(_) => {
                    // Fallback safety estimation if dummy encoding is not fully bound yet
                    block.raw_instructions.iter().map(|i| i.len()).sum::<usize>() + 32
                }
            };

            let prefix_len = if block.entries.len() > 1 { 4 } else { 0 };
            // Safety margin breakdown:
            //   +256: worst-case RIP-relative re-encoding expansion (disp8→disp32 = +3 bytes each,
            //         up to ~80 such operands per block = 240 bytes)
            //   + Jcc near promotion (short→near = +4 bytes)
            //   + stub bytes: push_id(5) + push_key(5) + jmp_rel32(5) = 15 bytes * 2 paths = 30 bytes
            //   256 bytes covers all of the above with a conservative margin.
            let total_len = raw_len + prefix_len + 256;

            current_offset += total_len;
            // Pad to 32-byte alignment (SSE-safe and avoids off-by-one boundary issues)
            current_offset = (current_offset + 31) & !31;

            blocks_by_id.insert(block.id, block.clone());
            layout_map.insert(block.id, BlockLayout {
                physical_offset: table_offsets[logical_id],
                encrypted_entry: table_offsets[logical_id], // encrypted later in pass3
            });
            shuffled_blocks.push(block);
        }

        let encrypted_table_entries = table_offsets.clone();

        ShuffledLayout {
            blocks_by_id,
            layout_map,
            shuffled_blocks,
            table_offsets,
            encrypted_table_entries,
        }
    }
}
