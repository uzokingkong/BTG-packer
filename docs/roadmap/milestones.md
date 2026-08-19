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
- [x] `--text-vm` 진단 커버리지 100.00% 달성 (`../architecture/coverage.md`).
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
- [x] `docs/architecture/vm-compiler-architecture.md` — 모듈 지도 및 엔진 아키텍처 개요.
- [x] `docs/architecture/commercial-vm-engine.md` — Themida/VMProtect급 4단계 상용 가상화 엔진 심층 설계서.
- [x] `docs/architecture/coverage.md` — 명령어 커버리지 베이스라인.
- [x] `docs/roadmap/milestones.md` — 전체 마일스톤 체크리스트.

---

## Phase 5 — 상용 VM 컴파일러 업그레이드 플랜 (P0 / P1) 🔶

> 상세: `docs/roadmap/COMMERCIAL-VM-UPGRADE-PLAN.md` · 대상 브랜치: `commercial/p1-poly-complete`
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

### P4 — SEH 네이티브 집합 175→132→49 최소화 ✅ (2026-08-15 / 2026-08-17)
- [x] `detect_seh_native_functions`가 `BTG_SEH_MINIMAL`(기본 1) 환경변수로 최소 세트
      `ehandler ∩ can_reach_panic = 132`만 네이티브 유지 (175→132).
- [x] 진단: panic_seed=38, ehandler=162, `{can_reach_panic − can_reach_ehandler}` 역방향
      항 0개 추가, 30개 ehandler panic 도달 불가 → 무해 가상화.
- [x] 계측 출력(`[SEH-DEBUG]`/`[SEH-DEBUG2]`/`[SEH-LEVEL]`) 제거.
- [x] **전체 SEH 가상화 + 브리지 UNWIND_INFO (2026-08-17, P4 최종)**: `BTG_SEH_NONE=1`
      환경변수로 SEH 네이티브 집합을 **132 → 49** 로 최소화 (legacy whole-program VM
      `--vm --vm-oep` 경로). 49 = 전부 가상화하되 (a) computed-jump(switch-dispatch)
      EHANDLER 함수 — 블록 단위 VM 디스패치가 switch 타깃을 프로로그 없이 진입해
      프레임 로컬이 낡은 값(-2)을 읽는 것을 방지, (b) Once/panic 공유-state(.data/.bss)
      함수 — teardown 원자 완료 경로 보존. 두 가드는 SEH가 아니라 teardown 안전망.
- [x] **`.pdata` 재생성(브리지 UNWIND_INFO)**: Program-VM 모듈 영역 전체
      `[vm_prog_rva .. vm_prog_rva+vm_prog_total)`을 RUNTIME_FUNCTION으로 커버하고,
      실제 Program-VM 엔트리 프로로그(sub rsp,0xA0 + 15 push)에서 유도한 UNWIND_INFO
      (UWOP_ALLOC_LARGE 160 + PUSH_NONVOL, **CodeOffset 내림차순** = PE/COFF 스펙)를
      `.pdata` 뒤에 배치. VM 내부 예외 시 OS unwinder가 더미 핸들러 없이 결정적으로
      VM 프레임 밖으로 unwind.
- [x] 검증: `BTG_SEH_NONE=1` + `--vm --vm-oep` → 16테스트 전체 통과 + FINAL CHECKSUM
      `0x2cdc0e4511d84a64`(baseline 동일), **exit 0** (exit-time teardown 0xC0000005
      해소), 5회 연속 안정, cdb clean exit. `--vm`/`--vm-commercial`은 132 유지(게이트).
- [x] 0 목표는 (a) switch-dispatch EHANDLER, (b) Once/panic shared-state 두 안전망까지
      포함한 49가 채택 최소치 — 0으로 하면 exit-time teardown 0xC0000005 (VM이
      Once 완료 경로의 낡은 프레임 로컬 -2를 xchg 주소로 씀).
- [x] `.pdata` 재생성(브리지 UNWIND_INFO) 통한 전체 SEH 가상화 — 달성 (legacy VM 경로).
- [x] `--vm-commercial`(RISC 엔진)은 전체 SEH 가상화 미검증 → 게이트로 132 유지.

### P5 — .text 온디스크 평문 0 (TLS-first-callback Decryptor) ✅ (2026-08-15)
- [x] **블로커 실측**: 타깃은 TLS 콜백 1개(RVA `0x1C1A0`, CRT TLS-init) 보유 — 로더가
      부트 스텁보다 먼저 콜백 실행 → `.text` 전체 암호화 시 0xC0000005.
- [x] `src/vm/text_lift/tls_guard.rs` `detect_tls_callback_ranges` — TLS dir → `.pdata`
      함수 → **forward(callee) transitive closure**로 평문 유지 범위 산출.
      실측: **50 함수 / 0x23EE 바이트** 평문 유지 (양방향 closure 551 대비 최소).
- [x] 부트 스텁 `emit_rest_decrypt` **run 기반 확장** — 콜백 외 `.text` 영역만 at-rest
      fresh-RC4(seed)로 암호화·부트 시 복호화 (run-table `{va,len}`).
- [x] `place.rs` `text_enc_runs` — `.text` 배타 보수 run 산출 + 부트 영역 run-table 배치
      + 동일 순서 fresh-RC4 암호화. (run 없으면 run-table 미배치 — 레이아웃/트림 무회귀)
- [x] **검증 (신선 회귀 2026-08-15)**: `verify_text.py` → `.text first-bytes identical
      = **False** (186,880B 중 176,988B diff, 94.71%), packed `.text` entropy **7.988**
      (≈7.5↑), `.textb` 7.539.
- [x] `packed --headless` **16개 테스트 전체 통과** + FINAL CHECKSUM `0x2cdc0e4511d84a64`
      (baseline 동일), test[15] TLS & statics `0x6599ff7a6e4706f4`.
- [x] **cdb TLS 콜백 진입·복귀 확인** (VA `0x14001c1a0`): startup·스레드 생성(test[9])·
      teardown 진입 전부 정상 복귀, **0xC0000005 없음**.
- [x] `.text` 온디스크 평문 0 달성 (콜백 함수만 최소 평문 유지).

### 회귀 — 3경로 최종 신선 실행 (2026-08-15, 최종 상태)
- [x] `cargo build --release` green (exit 0) · `cargo test --release --lib`
      → **236 passed; 0 failed** (VirtualBranch/Setcc/CMOV/div 검증 완료 포함).
- [x] `--vm` pack→run → **16개 테스트 전체 통과** + FINAL CHECKSUM
      `0x2cdc0e4511d84a64` (baseline 동일).
- [x] `--vm --vm-oep` pack→run → **16개 테스트 전체 통과** + FINAL CHECKSUM
      `0x2cdc0e4511d84a64`, cdb clean exit (0xC0000005 없음), TLS 콜백 진입 확인.
- [x] `--vm --vm-oep --vm-commercial` → **pack exit 0** + **run green**: self-decoding
      디스패처에 **네이티브 콜 브리지**(레거시 `OP_NATIVE_CALL`급 — not-found 타깃에서
      ret_ip pop → GPR 실장 → Win64 콜 → 동기화 → ret_ip 재개) + 상용 리프트 **OEP
      entry-jump** 추가로 0xC0000005 해소. **16개 테스트 전체 통과 + FINAL CHECKSUM
      `0x2cdc0e4511d84a64`** (= baseline, 3회 반복 안정). (기록:
      `docs/engine/P3-handlers-wired-and-verified.md` §5, `docs/engine/VirtualBranch-Native-Handler-DONE.md`.)

### P3 — 상용 self-decoding 핸들러 전수 구현·와이어·검증 ✅ (2026-08-15)
- [x] VirtualBranch (taken/not-taken, ip_map 분기 해석, rolling-key 재동기화) — 차등 2개 green.
- [x] Setcc / ConditionalMove (22 조건, CounterZero 포함) — 차등 green.
- [x] Multiply / MultiplyLow / Divide (signed×width, 오버플로 CF/OF) — 차등 green.
- [x] BSwap / BitScanForward/Reverse / TZCNT / LZCNT / PopCount — 차등 green.
- [x] CompareExchange {1,2,4,8} — 차등 green.
- [x] NativeCallBridge no-op (스트림 소비, 상태 불변) — 차등 green.
- [x] DEC_COND 상태 슬롯 + cond 바이트 디코딩 (`sub_dec_ops_cond`, OFF_COND_CODES) — green.
- [x] 와이어: 256-entry 핸들러 테이블 + operand-offset/kind + cond-code + branch_map 배선,
      `build_program_vm_commercial` 테이블 0xB00 + branch_map, `place.rs` ip_map 전달.
- [x] **네이티브 콜 브리지** (h_branch not-found 경로 → 레거시 OP_NATIVE_CALL급) + 상용
      리프트 **OEP entry-jump** — `--vm-commercial` whole-program run 16-test + checksum
      `0x2cdc0e4511d84a64` green (0xC0000005 해소).
- [x] `cargo test --release --lib` → **236 passed; 0 failed**; `--vm`/`--vm-oep` 16-test + checksum 무회귀.

---

## 2026-08-19 — T3-1 Phase D + readccc §4.6 명세 + T2 hardening (작업 트리)

### T3-1 Phase D — ChaCha20-Poly1305 AEAD 부트 스텁 복호화-전 인증 ✅ (코드 + 차등 테스트)
- [x] 네이티브 Poly1305 verify blob (`src/crypto/poly1305_native.rs`): RFC 8439 §2.8 AEAD 태그를
      26-bit limb로 완전 전개, `rcx/rdx/r8/r9 → rax` 자립형 셸코드. rel32 분기 → VA 길이 불변.
- [x] 패커 AEAD surface (`poly1305_aead_tag` / `POLY1305_AEAD_AAD` / `chacha_poly1305_key_from_block0`).
- [x] 부트 스텁 연결: chacha 경로가 at-rest 암호문을 복호화 **전에** 태그 검증, 불일치 시 ud2
      (fail-safe). RC4/C1 무회귀.
- [x] 차등 테스트: RFC 벡터, RustCrypto AEAD 권위, 네이티브==reference (len 0..4096),
      변조(태그/암호문/AAD) 거부, boot-stub AEAD 길이 불변.

### readccc §4.6 — 함수 원자성 + Win64 콜 브리지 명세 ✅ (명세 문서 + 안전 구현)
- [x] `docs/architecture/function-atomicity-bridge-spec.md` (function-ownership, bridge ABI,
      EH/SEH/TLS tier, 요구↔모듈 매핑, 명시적 후속 작업).
- [x] `src/vm/risc/bridge_abi_tests.rs` — NativeCallBridge no-op 전체 가상 상태 보존 차등 가드.

### T2 hardening — per-seed 핸들러/opcode 다형화 검증 ✅ (P6 계열과 일관)
- [x] `src/vm/poly/polymorphism_hardening_tests.rs` — seed별 opcode 맵 다형화 + 단일 빌드 주입성.

### 게이트 (2026-08-19)
- [x] `cargo build --release` exit 0 · `cargo test --release --lib` → **398 passed; 0 failed**
      (기준 384 → +14: WS1 10 · WS2 2 · WS3 2).
---

## 2026-08-19 - WS1/WS2/WS3 execution (shared tree)

### WS1 - ChaCha20-Poly1305 AEAD end-to-end execution [OK]
- [x] `--crypto-mode chacha20` plain bulk path pack->run - packed exe output byte-identical to baseline
      (1460 B, SHA `4366e2530f32a088306efe497d1762e5a087c54ac6c114b44f3ee13d422dcfe5`, exit 0).
- [x] manifest `crypto_mode = chacha20` / `crypto_version = 63` / `at_rest_encryption = true`.
- [x] chacha20 gate documented: plain bulk at-rest only; chained/reencrypt/`--vm`/`--vm-oep`/`--vm-commercial` fall back to RC4/BTG-C1. No open item.

### WS2 - Function atomicity / bridge ABI (spec section 6)
- [x] **2.1 function-ownership <-> .pdata AUTO-CHECK** (`src/pipeline/ownership.rs` + `validate.rs` + `main.rs` CSV wiring). Clean on program-VM builds, emits `<output>.ownership.csv`. DONE
- [x] **2.2 reentrant callback / vtable dispatch test matrix** (`src/vm/risc/bridge_abi_tests.rs` +3, linear block equivalence). DONE
- [~~] **2.3 NativeCallBridge Win64 ABI** - `src/vm/risc/native_abi.rs` verified ABI emission layer (PRE/CALL/POST, shadow/align/callee-saved/ret_ip resume) implemented+verified; reference/poly/threaded stay no-op. Real runtime host-call integration open. OPEN
- [~~] **2.4 commercial T5 full SEH virtualization differential** - commercial keeps SEH-minimal(132) native; `BTG_SEH_NONE=1` is legacy `--vm --vm-oep` only. RISC-lift fidelity gap + function-atomicity gap -> blockers documented, not forced. OPEN

### WS3 - Nested VM / state concealment (t2-hardening follow-ups)
- [~~] **3.1 Nested VM runtime layer (VmCallBridge)** - `src/vm/nested.rs` `NestedVmFrame`/`run_nested` + 2 differential tests (outer-state save/restore equivalence). Host-layer real execution integration open. OPEN
- [x] **3.2 State concealment auto-verification** - `src/vm/conceal.rs` `wipe_sensitive`/`SensitiveWipeGuard` + 4 tests. DONE
- [x] **3.3 Dispatcher metadata minimization** - `src/vm/dispatch_perm.rs` per-seed opcode->handler permutation + 4 tests (bijection/round-trip/polymorphism). DONE

### Gate (2026-08-19 final)
- [x] `cargo build --release` **exit 0**.
- [x] `cargo test --release --lib` -> **423 passed; 0 failed** (baseline 398 -> +25: ownership 8 / bridge_abi 5 / native_abi 4 / conceal 4 / dispatch_perm 4 / nested 2).
- [x] `--vm --vm-oep` and `--vm --vm-oep --vm-commercial` pack->run SHA matches baseline, **FINAL CHECKSUM `0x2cdc0e4511d84a64` no regression**, exit 0.
