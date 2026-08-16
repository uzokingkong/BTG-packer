// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Obfuscation Metrics Analyzer
// ==============================================================================
//
// 리뷰 지적 #16 해소: `flattening_ratio`와 `mba_entropy_score`를 설계(constructed)
// 상수로 두지 않고 **실측(measured)** 값으로 교체한다.
//
//   - flattening_ratio: 원본 CFG의 제어흐름 엣지 중 양 끝점이 모두 셔플(디스패처
//     라우팅) 집합에 속하는 엣지의 비율. SEH/native 유지 함수와 닿는 엣지는
//     네이티브(직접) 분기이므로 이 비율은 실제 보호 커버리지를 반영한다.
//   - mba_entropy_score: 실제 per-block MBA 키(seed_for + compute_key, obf_level
//     반영)를 직렬화한 바이트 스트림의 Shannon 엔트로피(bits/byte). 키 스케줄이
//     블록 ID를 얼마나 잘 분산/스크램블하는지 실측한다. 잘 스크램블되면 ≈8.0.
// ==============================================================================

use crate::core::trigger_block::TriggerBlock;

#[derive(Debug, Clone, Copy, Default)]
pub struct CfgEdgeCounts {
    /// 원본 CFG의 총 제어흐름 엣지 수 (SEH 필터 이전, .text 외부/패딩 타깃 포함).
    pub total: usize,
    /// 양 끝점이 모두 셔플(디스패처 라우팅) 집합에 속하는 엣지 수.
    pub flattened: usize,
}

#[derive(Debug, Clone)]
pub struct ObfuscationMetrics {
    pub total_trigger_blocks: usize,
    pub overlapped_blocks: usize,
    pub overlap_density: f64,
    /// 실측: 디스패처 라우팅 엣지 비율 (%).
    pub flattening_ratio: f64,
    /// 실측: per-block MBA 키 스트림의 Shannon 엔트로피 (bits/byte, 최대 8.0).
    pub mba_entropy_score: f64,
    /// 이론적 상한(키 비트 폭) — 실측값과의 거리를 판단하는 기준용.
    pub mba_entropy_bits: u32,
    pub total_cfg_edges: usize,
    pub flattened_cfg_edges: usize,
}

pub struct MetricsAnalyzer;

impl MetricsAnalyzer {
    pub fn analyze(
        trigger_blocks: &[TriggerBlock],
        mba_constant: u32,
        obf_level: usize,
        edges: CfgEdgeCounts,
    ) -> ObfuscationMetrics {
        let total_trigger_blocks = trigger_blocks.len();
        let overlapped_blocks = trigger_blocks.iter().filter(|b| b.entries.len() > 1).count();

        let overlap_density = if total_trigger_blocks > 0 {
            (overlapped_blocks as f64 / total_trigger_blocks as f64) * 100.0
        } else {
            0.0
        };

        // ── 실측 1: 제어흐름 플래트닝 비율 ─────────────────────────────────────
        let flattening_ratio = if edges.total > 0 {
            (edges.flattened as f64 / edges.total as f64) * 100.0
        } else {
            0.0
        };

        // ── 실측 2: per-block MBA 키 스트림의 Shannon 엔트로피 ────────────────
        // 디스패처가 실제 런타임에 유도하는 키(MbaGenerator::compute_key, level
        // = obf_level)를 패커도 동일하게 계산해, 그 바이트 분포가 얼마나 균일하게
        // 스크램블되는지 측정한다. (동일 키 반복 → 0, 완전 분산 → ~8.0)
        let level = obf_level.clamp(1, 3);
        let mut key_bytes: Vec<u8> = Vec::with_capacity(trigger_blocks.len() * 4);
        for tb in trigger_blocks {
            let seed = crate::mba::MbaGenerator::seed_for(mba_constant, tb.id);
            let key = crate::mba::MbaGenerator::compute_key(seed, tb.id, mba_constant, level);
            key_bytes.extend_from_slice(&key.to_le_bytes());
        }
        let mba_entropy_score = crate::analysis::entropy::shannon_entropy(&key_bytes);

        ObfuscationMetrics {
            total_trigger_blocks,
            overlapped_blocks,
            overlap_density,
            flattening_ratio,
            mba_entropy_score,
            mba_entropy_bits: u32::BITS,
            total_cfg_edges: edges.total,
            flattened_cfg_edges: edges.flattened,
        }
    }
}
