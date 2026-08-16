// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Obfuscation Metrics Analyzer
// ==============================================================================

use crate::core::trigger_block::TriggerBlock;

#[derive(Debug, Clone)]
pub struct ObfuscationMetrics {
    pub total_trigger_blocks: usize,
    pub overlapped_blocks: usize,
    pub overlap_density: f64,
    /// 트랜지션이 디스패처를 경유하는 비율. **측정값이 아니라 설계(constructed)
    /// 상수**다 — 이 패커는 설계상 모든 블록 전이를 디스패처를 통해 라우팅하므로
    /// 항상 100% 로 설정된다. (리뷰 지적 #16: 실제 측정처럼 보이지 않도록 CLI 에서
    /// `(design constant)` 로 표기한다.)
    pub flattening_ratio: f64,
    /// MBA 상태 키의 **이론적 엔트로피 상한**(= 키 비트 폭, 64). 실제로 측정된
    /// 엔트로피가 아니다. (리뷰 지적 #16: CLI 에서 `(key size)` 로 표기.)
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

        // 설계(constructed) 상수 — 측정값 아님. 문서 참조.
        let flattening_ratio = 100.0;
        let mba_entropy_score = u64::BITS as f64;

        ObfuscationMetrics {
            total_trigger_blocks,
            overlapped_blocks,
            overlap_density,
            flattening_ratio,
            mba_entropy_score,
        }
    }
}
