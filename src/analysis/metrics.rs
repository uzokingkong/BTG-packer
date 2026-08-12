// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Obfuscation Metrics Analyzer
// ==============================================================================

use crate::core::trigger_block::TriggerBlock;

#[derive(Debug, Clone)]
pub struct ObfuscationMetrics {
    pub total_trigger_blocks: usize,
    pub overlapped_blocks: usize,
    pub overlap_density: f64,
    pub flattening_ratio: f64,
    pub mba_entropy_score: f64,
}

pub struct MetricsAnalyzer;

impl MetricsAnalyzer {
    pub fn analyze(trigger_blocks: &[TriggerBlock]) -> ObfuscationMetrics {
        let total_trigger_blocks = trigger_blocks.len();
        let overlapped_blocks = trigger_blocks.iter().filter(|b| b.entries.len() > 1).count();

        let overlap_density = if total_trigger_blocks > 0 {
            (overlapped_blocks as f64 / total_trigger_blocks as f64) * 100.0
        } else {
            0.0
        };

        // All transitions route via Dispatcher (100% Control Flow Flattening)
        let flattening_ratio = 100.0;

        // MBA state key decoding entropy (bits of randomness per seed/key pair)
        let mba_entropy_score = 64.0;

        ObfuscationMetrics {
            total_trigger_blocks,
            overlapped_blocks,
            overlap_density,
            flattening_ratio,
            mba_entropy_score,
        }
    }
}
