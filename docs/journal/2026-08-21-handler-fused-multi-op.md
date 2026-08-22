# 2026-08-21 — Handler Fused/Multi-Op + Variable Operand + Per-VM Semantic Permutation

## 작업
task/0bd6049682914fdf8a62e1cfeaca9f9d — 레거시 1:1 VM의 handler 구조를 분리.

## 변경 (노드 소스, main working tree)
- `src/vm/semantic_obf.rs` (new), `src/vm/handlers/fused.rs` (new),
  `src/vm/dispatch_perm.rs` (mod), `src/vm/handlers/mod.rs`, `src/vm/mod.rs`,
  `src/vm/self_test/semobf.rs` (new), `src/vm/self_test/mod.rs`,
  `src/pipeline/crypto/place/vm_build.rs`.

## 검증
- `cargo build --release` → 0 errors (exit 0)
- `cargo test --lib vm::` → 285 passed / 0 failed
- `cargo run --release -- --vm-test` → ALL CHECKS PASSED
  ([41] A-6 fused/permuted/variable VM encoding PASS, [9] flag model + full Jcc PASS)

## 상태
완료. (상세: docs/handler-fused-multi-op-semantic-permutation-2026-08-21.md)
