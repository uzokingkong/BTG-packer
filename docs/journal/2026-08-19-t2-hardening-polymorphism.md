# 2026-08-19 — T2 계열 hardening: per-seed 핸들러/opcode 다형화 검증 (WS3)

## 요청
기존 P6/P6-1..P6-3(디스패치 테이블 암호화, NOR-handler de-signaturing, per-op MBA 키,
handler-restore 방지)과 일관되게, T2 hardening을 전진시킨다 (nested VM / handler 다형화 /
state concealment / metadata 최소화). 의미 보존 + 차등/블록-동치 규율 준수.

## 구현
### `src/vm/poly/polymorphism_hardening_tests.rs`
- `per_seed_opcode_map_polymorphism`: 서로 다른 ISA seed가 같은 논리 RISC op에 **다른 opcode**를
  할당하는지 검증 (build-to-build handler/opcode 다형화 + dispatch-table 메타데이터 최소화 —
  빌드 간 안정적인 opcode→handler 식별자 노출 방지).
- `opcode_map_is_injective_per_build`: 단일 빌드 내 opcode 맵이 전단사(주입) — 두 op가 같은
  opcode를 공유하지 않아 디스패처가 의미를 복구할 수 있음.

이 테스트는 하드닝 **속성 검증**이며 전체 출력 차이 동치가 아니다(기존 P6 테스트와 동일 규율).
기존 런타임 시맨틱은 변경하지 않는다(순수 추가 테스트).

## 결과
`cargo test --release --lib polymorphism_hardening` 2 passed · 전체 398 passed; 0 failed.

## 후속 (이번 작업은 검증층 강화 — 다음 전진 지점)
- nested VM(`VmCallBridge`) 런타임 계층 + reentrant callback 매트릭스.
- state concealment(런타임 민감 버퍼 wipe)의 자동 검증 확장.
- dispatcher 메타데이터 최소화: opcode→핸들러 identity의 정적 복구 난이도 상승 추가 계획.
