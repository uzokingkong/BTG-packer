# Milestones — 완전한 VM 컴파일러 진행 체크리스트

> 상태 마커: ✅ 완료 · 🔶 진행 중 · ⬜ 미착수 · ⚠️ 부분/리스크
> 업데이트: 2026-08-13 (v13.5)

## Phase 0 — 기준점 & 저장소 정리 ✅
- [x] baseline 커밋 (`4406b77`): v13.4e 두-스택 VM 상태의 미커밋 17개 소스 +
      미추적 CHANGES.md/리포트/test 픽스처를 정리해 커밋.
- [x] `.gitignore` 추가 (빌드 산출물 / packed*.exe / 디버그 스크래치 / 로그).
- [x] `cargo build --release` green (68 경고, 기준과 동일).
- [x] `--vm-test` [1..34] ALL PASS 기록.

## Phase 1 — 긴 .rs 파일 분해 (동작 변경 0, 순수 코드 이동)

| 파일 | 라인 | 상태 | 산출 |
|---|---|---|---|
| `vm/bytecode.rs` | 1216 | ✅ 완료 | `vm/bytecode/{mod,registry,builder,disasm,tests}.rs`, 커밋 `bb706f4` |
| `vm/handlers.rs` | 2438 | ⬜ | §architecture 3.1 |
| `vm/lifter.rs` | 2690 | ⬜ | §architecture 3.2 |
| `vm/interp.rs` | 1294 | ⬜ | §architecture 3.3 |
| `vm/self_test.rs` | 4285 | ⬜ | §architecture 3.4 |
| `pipeline/crypto.rs` | 2793 | ⬜ | §architecture 3.5 |
| `vm/text_lift.rs` | 1100 | ⬜ | §architecture 3.7 (⚠️ UTF-8 한글 주석 — 인코딩 안전 수단 필수) |
| `dispatcher/mod.rs` | 1218 | ⬜ | §architecture 3.8 |

**검증 룰 (각 파일마다)**: `cargo build --release` green + `cargo test` green +
`--vm-test` ALL PASS + 분해 전후 pack 출력 바이트 동일(회귀 0).

### 진행 노트
- 2026-08-13: `text_lift.rs` 분해를 PowerShell `Set-Content`로 시도했으나
  UTF-8 한글 주석이 깨져 **리버트**(`git checkout HEAD --`). 교훈: 한글 포함
  파일은 code_edit / `-Encoding UTF8` 읽기+쓰기로만 편집. 아키텍처 문서에
  주의로 기록.

## Phase 2 — 컴파일러 프론트엔드 (IR + 커버리지 + 전체 가상화)

### 2.1 명령 커버리지 완결 ⬜
- [ ] `--text-vm` 진단이 출력하는 미지원 명령 목록을 `coverage.md`로 고정.
- [ ] SSE/FPU, BMI1/2(tzcnt/lzcnt/popcnt), 문자열 ops(movs/stos/scas),
      CMOVcc를 그룹별(opcode+핸들러+리프터+인터프리터+테스트) 한 벌로 추가.
- [ ] 시스템/특권 명령은 명시적 제외로 문서화.

### 2.2 제외 블록 제거 ⬜
- [ ] lock-atomic RMW / panic-unwind 블록을 네이티브로 남기는 휴리스틱을
      VM opcode로 대체 → 프로그램 본문 100% VM.

### 2.3 IR 프론트엔드 ⬜
- [ ] `lift_one` 1:1 매칭을 경량 IR(`VInstr`)로 승격.
- [ ] 레지스터 맵핑(16 vreg) + 상수 폴딩 + 죽은 코드 제거 + peephole.
- [ ] M4 검증(dummy_fn 동치) 유지.

### 2.4 전체 프로그램 가상화 + 부트 정합 ⬜
- [ ] `lift_program_cfg`를 전체 .text로 확장.
- [ ] `entry_native` 브랜치 제거, 부트스텁이 항상 프로그램 VM으로 진입.
- [ ] 종료 teardown 패닉(`once.rs:166`) 해결.

### 2.5 핸들러 성능 ⬜
- [ ] threaded-dispatch / 핸들러 퓨전, `--vm-bench` 2x 목표.

## Phase 3 — 문서 & 마무리
- [x] `docs/vm-compiler-architecture.md` — 모듈 지도 + 절단 지점.
- [x] `docs/coverage.md` — 명령 커버리지 베이스라인.
- [x] `docs/milestones.md` — 이 체크리스트.
- [ ] 전체 `--vm-test` + `--full` pack 회귀 + 샘플 타깃 실행 확인.
