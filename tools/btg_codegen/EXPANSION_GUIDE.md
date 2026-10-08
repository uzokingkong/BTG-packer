# VM op 확장 가이드 (Windows 로컬 워크플로)

벡터/신규 명령 가상화를 **op 하나씩, 검증하며** 늘리는 절차. CI(`.github/workflows/ci.yml`,
windows-latest)를 로컬에서 그대로 재현한다. 메타데이터 자동생성으로는 벡터 의미론을
못 만들므로, 제너레이터가 **뼈대 + 차등검증**을 돕고 사람이 각 layer를 손으로 채운다.

## 0. 한 번만: 환경 세팅 (PowerShell)
```powershell
# Rust (MSVC 타깃) + VS Build Tools(링커) 필요
# https://rustup.rs 설치 후:
rustup default stable
rustup component add clippy rustfmt
# 레포 클론 (feat/btg-codegen 브랜치)
git clone -b feat/btg-codegen https://github.com/uzokingkong/BTG-packer.git
cd BTG-packer
cargo build --release --locked      # 베이스라인 빌드 확인
```

## 1. 커버리지 베이스라인 + 타깃 선정
```powershell
cargo run --release --bin vm-coverage -- --out-dir coverage
cargo run --release --manifest-path tools/btg_codegen/Cargo.toml -- `
  --coverage coverage/vm_coverage.json --out-dir tools/btg_codegen/generated --strict
# 리포트에서 다음에 칠 패밀리/op 선택
notepad tools/btg_codegen/generated/codegen_report.md
```

## 2. 신규 op 하나 추가 — 8파일 체크리스트
예: `PMULLW`(패킹 16비트 곱 하위) → `RiscOp::PackedMulLow { elem_width, lanes }`.
기존 `PackedAdd`를 템플릿으로 각 파일에서 같은 자리를 복제한다(`grep -rn PackedAdd src/`).

1. `src/vm/risc/opcodes.rs` — `RiscOp` enum 변종 + `kind()` arm.
2. `src/vm/risc/op_registry.rs` — 매크로 stable-name + `capabilities()` (처음엔 evaluator만 true).
3. `src/vm/risc/eval.rs` — **참조 의미론**(ground truth) eval arm. ★ 차등검증의 기준.
4. `src/vm/risc/lifter/sse.rs` — iced `Code` → op 매핑(`packed_op_for` 확장 또는 전용 lowering).
5. `src/vm/poly/isa_spec.rs` — `VirtualIsaSpec::is_encodable`에 operand 인코드/디코드 등록.
6. `src/vm/poly/interpreter/mod.rs` — 인터프리터 핸들러.
7. `src/vm/threaded/poly_direct/builder.rs` (+ `harness/emit_block.rs`) — **op의 실제 x86 기계어 방출**. ★ 가장 어렵고, 정확성은 패킹 QA로만 검증됨.
8. 7까지 끝나면 `capabilities()`의 poly/interp/threaded를 commercial로 → FULL_PIPELINE.

> 팁: **evaluator(3)+lifter(4)+차등테스트부터** 하면 `unsupported`가 내려가고 의미가
> 검증된다(단, 5~7 전까지는 `--vm-commercial`에서 네이티브 유지 = 완전 가상화 아님).

## 3. 로컬 검증 게이트 (빠른 것 → 느린 것)
```powershell
cargo test  --release --lib                                   # 유닛/리프터/eval
cargo test  --release --features codegen_fallback --lib generated_fallback  # 차등검증
cargo clippy --all-targets --all-features --locked            # 컴파일+린트
cargo run   --release --bin vm-coverage -- --out-dir coverage2   # 재-coverage: UNSUPPORTED 감소 확인
```
**threaded 방출의 정답 검증 = 패킹 Exact QA**(CI의 그 스텝):
```powershell
New-Item -ItemType Directory -Force qa | Out-Null
$b64 = (Get-Content ".ci/rust_packer_test.exe.b64" -Raw) -replace "\s+",""
[IO.File]::WriteAllBytes("qa/rust_packer_test.exe",[Convert]::FromBase64String($b64))
& ".\target\release\btg-packer.exe" --input qa/rust_packer_test.exe --output qa-packed.exe `
  --vm --vm-oep --vm-commercial --allow-partial-vm --verify-output --verify-timeout-secs 45 --seed 3134984190
# 추가: cargo build --release --manifest-path test/Cargo.toml ; cargo run --release -- --test-qa
#       cargo test --release --lib self_test::fuzz
```
`--verify-output`가 패킹본 실행 동치를 확인한다 → 새 op의 x86 방출이 틀리면 여기서 깨진다.

## 4. 차등검증 테스트 작성 패턴 (op마다)
실제 바이트를 디코드 → fallback/lifter로 lift → `eval_state`로 실행 → Rust ground-truth와 대조.
`src/vm/risc/lifter/generated_fallback.rs`의 `#[cfg(test)] mod tests`가 예시.

## 5. 반복
op 하나 = (구현 → 위 게이트 전부 green → 커밋). 제너레이터로 다음 타깃 뼈대를 뽑아 반복.

## 하이브리드 (권장)
- 코드 편집·멀티파일 diff·eval/lifter/차등/clippy/재coverage는 **CI 또는 Claude로 위임**(여기까지 CI가 검증 가능).
- **threaded 방출의 정확성만 로컬 Exact QA로** 빠르게 돌려 확정. 패커 베이스라인이 green이면 CI의 Exact QA가 그 역할을 대신한다.
