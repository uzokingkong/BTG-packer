use super::*;
use crate::pe::generate_dummy_target_pe;
use crate::pe::TargetPeInfo;

#[test]
fn analyze_text_lift_dummy_target_reports_coverage() {
    // 더미 타깃 PE의 원본 .text 에 대해 커버리지 리포트가 생성되고,
    // 구조 필드가 일관된지 검증한다. (lift 가능/불가 여부는 명령 세트에 따라
    // 달라지므로 0개 블록이 아니고 coverage 가 0.0..=1.0 인지만 확인)
    let dummy = generate_dummy_target_pe().unwrap();
    let info = TargetPeInfo::parse(&dummy).unwrap();
    let base_va = info.image_base + info.text_rva as u64;
    let ep_va = info.image_base + info.entry_point_rva as u64;
    let report = analyze_text_lift(
        &info.text_bytes,
        base_va,
        ep_va,
        &info.relayed_sections,
        info.image_base,
    )
    .unwrap();
    if info.text_bytes.is_empty() {
        return;
    }
    assert!(
        report.total_blocks > 0,
        "CFG should find at least one block"
    );
    assert_eq!(
        report.total_instructions,
        report.liftable_instructions + report.unsupported_instructions
    );
    assert!((0.0..=1.0).contains(&report.coverage()));
    // 각 블록 합이 총 명령 수와 일치
    let block_sum: usize = report.blocks.iter().map(|b| b.instructions).sum();
    assert_eq!(block_sum, report.total_instructions);
}
