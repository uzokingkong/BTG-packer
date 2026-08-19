# 2026-08-19 — WS3: Nested VM / state concealment (t2-hardening-polymorphism follow-ups)

> 태스크: `docs/journal/2026-08-19-t2-hardening-polymorphism.md` 후속 3건
> (dispatch-table 암호화 / NOR-handler de-signaturing / per-op MBA 키와 일관).

## 3.1 Nested VM runtime layer (VmCallBridge) 🔶(reference 계층 구현·차등 테스트 ✅, 호스트 실행 통합은 open)

**구현**: 새 모듈 `src/vm/nested.rs` (+ `src/vm/mod.rs` 등록).

- `NestedVmFrame` — 중첩 VM 호출 시 외부 VM 상태(regs/temps/flags/vsp/stack/mem)를
  스냅샷하고, 중첩 리전 완료 후 복원하는 **runtime save/restore 컨텍스트**.
- `run_nested(sub, outer)` — VmCallBridge 경계에서 외부 상태 저장 → 서브 VM 실행 →
  callee RAX 반환 + mem 쓰기 반영 후 외부 상태 복원.
- reference `RiscProgram::eval_state_impl`의 VmCallBridge 핸들러와 동일 의미론.
- **차등 테스트**:
  - `nested_layer_preserves_outer_state_except_return` — 외부 GPR/temps/flags/vsp/
    stack이 중첩 콜 후 bit 단위 보존 (RAX만 callee 반환값).
  - `nested_layer_matches_reference_vm_call_bridge` — runtime 계층 결과 == reference
    VmCallBridge 결과 (블록 동치).
- **열린 항목**: poly/threaded **호스트** 계층에서 중첩 VM을 실제 실행하는 통합은
  아직 배선 안 됨 (spec §2.4/opcodes 주석: VmCallBridge는 `is_encodable` 미등록 →
  `--vm-commercial`은 해당 함수를 네이티브 유지). runtime 계층 계약은 reference +
  신규 차등 테스트로 고정.

## 3.2 State concealment auto-verification 확장 ✅

**구현**: 새 모듈 `src/vm/conceal.rs` (+ `src/vm/mod.rs` 등록).

- `wipe_sensitive(&mut [u8])` — 민감 버퍼(key material/keystream state/seed)를 0으로
  wipe (컴파일러 배리어로 dead-store 제거 방지).
- `SensitiveWipeGuard<'a>` — RAII guard: 범위 이탈/조기 return/panic 경로에서도
  자동 wipe.
- 기존 at-rest 상태 버퍼 zero-init (`src/pipeline/crypto/place.rs` `chacha_state_off`/
  `c1_state_off` `.fill(0)`)과 일관되는 **post-use wipe 계약**을 단위 테스트로 고정.
- 테스트: `conceal` 4개 (key wipe, keystream/seed wipe, guard on-drop wipe,
  idempotent).

## 3.3 Dispatcher metadata minimization ✅

**구현**: 새 모듈 `src/vm/dispatch_perm.rs` (+ `src/vm/mod.rs` 등록).

- `DispatchPermutation::from_seed(seed, n)` — per-build/per-seed **opcode→handler
  슬롯 순열** (SplitMix LCG + Fisher–Yates). opcode가 더 이상 안정적 handler 인덱스가
  아니므로 두 빌드가 다른 seed를 쓰면 handler identity가 다르게 노출.
- `slot_for_opcode` / `opcode_for_slot` — bijection이라 런타임 디스패처가 정확히 복호화.
- 테스트: `dispatch_perm` 4개 (bijection, exact round-trip, build-to-build
  다형성/비-identity, 동일-seed 결정성).

## 테스트/빌드

- `cargo build --release`: exit 0.
- `cargo test --release --lib`: WS3 추가분 green. `nested` 2 + `conceal` 4 +
  `dispatch_perm` 4 = **10 테스트**.
- baseline 회귀 없음 (`--vm --vm-oep`·`--vm-commercial` FINAL CHECKSUM 유지).

## 통합 검증

- WS2/WS3 신규 테스트 포함 전체 `cargo test --release --lib` = **423 passed, 0 failed**
  (baseline 398 → +25).
