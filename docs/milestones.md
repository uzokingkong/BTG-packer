# Milestones — 완전한 VM 컴파일러 진행 체크리스트

> 상태 마커: ✅ 완료 · 🔶 진행 중 · ⬜ 미착수 · ⚠️ 부분/리스크  
> 업데이트: 2026-08-14 (v60, Phase 1~4 상용급 가상화 엔진 구현 및 검증 완료)

---

## Phase 0 — 기준점 & 저장소 정리 ✅
- [x] baseline 커밋 (`4406b77`): v13.4e 두-스택 VM 상태의 미커밋 17개 소스 + 미추적 CHANGES.md/리포트/test 픽스처를 정리해 커밋.
- [x] `.gitignore` 추가 (빌드 산출물 / packed*.exe / 디버그 스크래치 / 로그).
- [x] `cargo build --release` green.
- [x] `--vm-test` [1..34] ALL PASS 기록.

---

## Phase 1 — 긴 .rs 파일 분해 ✅ (동작 변경 0, 순수 코드 이동)

| 파일 | 라인 | 상태 | 산출 커밋 |
|---|---|---|---|
| `vm/bytecode.rs` | 1216 | ✅ | `vm/bytecode/{mod,registry,builder,disasm,tests}.rs` (`bb706f4`) |
| `vm/handlers.rs` | 2438 | ✅ | `vm/handlers/` (`1988057`) |
| `vm/lifter.rs` | 2690 | ✅ | `vm/lifter/` (`dd3ee48`) |
| `vm/interp.rs` | 1294 | ✅ | `vm/interp/` (`194bb64`) |
| `vm/self_test.rs` | 4285 | ✅ | `vm/self_test/` (`33daba2`) |
| `vm/text_lift.rs` | 1100 | ✅ | `vm/text_lift/` (`02a3acc`) |
| `pipeline/crypto.rs` | 2793 | ✅ | `pipeline/crypto/` (`819b11a`) |
| `dispatcher/mod.rs` | 1218 | ✅ | `dispatcher/{mod,build,validate,reencrypt,tests}.rs` (`633cfaa`) |
| `pipeline/validate.rs` | 718 | ✅ | `pipeline/validate/{mod,rsrc,tests}.rs` (`e5178ae`) |
| `pipeline/patch_data.rs` | 896 | ✅ | `pipeline/patch_data/{mod,imports}.rs` (`a3d6795`) |
| `obfuscation/mba.rs` | 571 | ✅ | `obfuscation/mba/{mod,codegen,tests}.rs` (`c7a4f2b`) |
| `pipeline/text_lift.rs` | 1009 | ✅ 삭제 | 고아 중복 (선언 없음, 호출부 전부 `vm::text_lift`) (`9b7ec0d`) |
| `main.rs` 엔트로피 | — | ✅ | → `analysis/entropy.rs` (`9b7ec0d`) |

---

## Phase 2 — 레거시 컴파일러 프론트엔드 (IR + 커버리지 + 전체 가상화) ✅

### 2.1 명령 커버리지 완결 ✅
- [x] `--text-vm` 진단 커버리지 100.00% 달성 (`coverage.md`).
- [x] SSE/FPU, BMI1/2, 문자열 ops, CMOVcc, LOCK inc/dec 지원.

### 2.2 제외 블록 최소화 및 SEH 안정성 ✅
- [x] CMPXCHG/XCHG/XADD (v46-v49) + LOCK INC/DEC (v55) 가상화.
- [x] Panic/SEH 안전 분리 및 TLS 콜백 부트 안정성 확보.

### 2.3 IR 프론트엔드 (`lifter/ir.rs`) ✅
- [x] 1:1 매칭을 경량 IR(`VInstr`)로 승격. 상수 폴딩, Dead-Code Elimination, Peephole 최적화.
- [x] M4 검증 및 self-test [40] PASS.

### 2.4 핸들러 성능 & 벤치마크 ✅
- [x] **threaded-dispatch**: 핸들러 epilogue에 인라인 디스패치 내장 (`jmp Dispatch` 왕복 제거).
- [x] **MBA 키 1회 유도**: r15 레지스터에 K=a+b 1회 유도 (`xor rax, r15` 최적화).
- [x] `--vm-bench` 4.3x Native 처리 속도 달성.

---

## Phase 3 — Themida / VMProtect 급 상용 가상화 엔진 (Phase 1 ~ 4) ✅

- [x] **[Phase 1] Micro-IR & RISCification** (`src/vm/risc/`): 12개 원시 마이크로 연산자, CISC-to-NOR/ADC de-synthesis, 가상 플래그 모델, peephole 최적화기.
- [x] **[Phase 2] 빌드별 무작위 가상머신 엔진** (`src/vm/poly/`): 시드 기반 가변 Opcode/레지스터 셔플링 ISA, VIP 연동 비선형 롤링 키 스트림 암호, 인터프리터/인코더.
- [x] **[Phase 3] 핸들러 난독화 & 직접 스레딩** (`src/vm/threaded/`): 중앙 루프 없는 Tail-Call 다이렉트 점프, 빈출 패턴 슈퍼 오퍼레이터 합성, 핸들러 인라인 MBA.
- [x] **[Phase 4] C/C++/Rust SDK & 선택적 가상화** (`src/sdk/`, `src/pipeline/selective_vm.rs`): `BTG_VM_START` / `BTG_VM_END` 마커 스캐너, 선택적 가상화 파이프라인 패스, LLVM IR 플러그인 인터페이스.
- [x] **BTG-C1 512-bit 스트림 사이퍼**: 512비트 상태 행렬, 16라운드 ARX/비트반전 순열, 카운터 분산 스캐터 및 SplitMix64 키 유도.
- [x] **단위 테스트 & 실환경 검증**: `cargo test --lib` (105/105 PASS) + CLI 10개 조합 & VM-OEP 7개 조합 실환경 실행 (Windows Event Log 0 Crash).

---

## Phase 4 — 문서화 및 유지보수 ✅
- [x] `docs/vm-compiler-architecture.md` — 모듈 지도 및 엔진 아키텍처 개요.
- [x] `docs/commercial-vm-engine.md` — Themida/VMProtect급 4단계 상용 가상화 엔진 심층 설계서.
- [x] `docs/coverage.md` — 명령어 커버리지 베이스라인.
- [x] `docs/milestones.md` — 전체 마일스톤 체크리스트.

---

## Phase 5 — 상용 VM 컴파일러 업그레이드 플랜 (P0 / P1) 🔶

> 상세: `docs/COMMERCIAL-VM-UPGRADE-PLAN.md` · 대상 브랜치: `commercial/p1-poly-complete`
> (기준 `cc6b973` = `origin/main`).

### P0 — 저장소 정리 (Repo Consolidation) ✅
- [x] 상위 repo `asdfsadfecwecc`를 **canonical**로 확정 (`cc6b973`, RISC 32-bit 최신).
- [x] 중첩 `vm-obf/` 스테일 clone(HEAD `0df672a`)이 **unique/unpushed 커밋 0개**임을 확인
      (`merge-base --is-ancestor 0df672a cc6b973` → exit 0) 후 **삭제** → 단일 Cargo workspace.
- [x] `cargo build --release` green.

### P1 — 폴리모픽 ISA / 인터프리터 완성 (Complete Polymorphic Semantics) ✅
- [x] `vm/poly/isa_spec.rs` opcode_map에 `ArithmeticShiftRight`, `VirtualBranch`(BranchCondition),
      `MemoryRead/Write{1,2,4,8}`, `NativeCallBridge` 추가 → **전체 reachable opcode 인코딩**.
- [x] `vm/poly/encoder.rs` 신규 op 인코딩 (즉시값 8B·width·분기 타깃·BranchCondition).
- [x] `vm/poly/interpreter.rs`에서 5개 op 핸들러 구현 — `RiscProgram::eval_state`(참조)와
      **완전 상태 동치**(regs/temps/flags/vsp/stack/mem). taken VirtualBranch의
      인스트럭션-인덱스→바이트오프셋 변환 + rolling-key 동기화.
- [x] 메모리 모델 `mem` 도입 — `eval_state`와 동일 계약.
- [x] **차등 테스트 (≥3 seeds)** green: `test_poly_arith_shift_matches_reference`,
      `test_poly_mem_rw_matches_reference`(1/2/4/8), `test_poly_branch_matches_reference`
      (taken/not-taken + `CounterZero` 2/4/8), `test_poly_native_call_bridge_stub`,
      `test_poly_opcode_map_uniqueness_complete_isa`.
- [x] **`cargo build --release` green (exit 0)** · **`cargo test --release` → 162 passed; 0 failed**.
- [x] 커밋: `2a3d6c8`(인터프리터) · `ece32c9`(인코더) · `20af238`(차등 테스트+분기 수정), pushed to `origin/commercial/p1-poly-complete`.

> 진행: **P2 — RISC 리프터 커버리지 100%** (미착수, 다음 게이트).

### P4 — SEH 네이티브 집합 175→132 최소화 ✅ (2026-08-15)
- [x] `detect_seh_native_functions`가 `BTG_SEH_MINIMAL`(기본 1) 환경변수로 최소 세트
      `ehandler ∩ can_reach_panic = 132`만 네이티브 유지 (175→132).
- [x] 진단: panic_seed=38, ehandler=162, `{can_reach_panic − can_reach_ehandler}` 역방향
      항 0개 추가, 30개 ehandler panic 도달 불가 → 무해 가상화.
- [x] 계측 출력(`[SEH-DEBUG]`/`[SEH-DEBUG2]`/`[SEH-LEVEL]`) 제거.
- [x] `--vm`/`--vm-oep` 16테스트 전체 통과 + FINAL CHECKSUM `0x2cdc0e4511d84a64`
      (baseline 동일).
- [ ] 0 목표는 exit-time 0xC0000005 teardown으로 배제(132가 채택 최소치).
- [ ] `.pdata` 재생성(브리지 UNWIND_INFO) 통한 전체 SEH 가상화 — 후속.
