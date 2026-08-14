# Commercial-Grade VM Compiler — 상용 VM 컴파일러(Themida/VMProtect급) 업그레이드 마스터플랜

> 작성일: 2026-08-15 · 대상 repo: `asdfsadfecwecc` (BTG Packer) · node `ujiwo-zyris-code`
> 기준 HEAD: `cc6b973` (RISC 32-bit zero-extension / shift-count masking, 2026-08-15)
> 근거: `problem.txt`, `docs/milestones.md`, `docs/vm-compiler-architecture.md`,
> `docs/commercial-vm-engine.md`, `docs/coverage.md`, `docs/T1-2-*/`, `docs/T1-4-*/`,
> 소스 실측(`src/vm/risc|poly|threaded`, `src/pipeline/selective_vm|poly_embed`, `src/main.rs`),
> 이전 실행의 패킹 실측(packed_vmoep.exe, .text 평문 확인).

---

## 0. 지금까지 구현된 것 (현황 요약)

### 0.1 두 개의 병렬 VM 엔진이 공존한다 (핵심 구조)

| | **레거시 VM core** | **상용 엔진 (Commercial-grade)** |
|---|---|---|
| 모듈 | `vm/bytecode`, `vm/handlers`, `vm/lifter`, `vm/interp`, `vm/text_lift` | `vm/risc/`, `vm/poly/`, `vm/threaded/`, `sdk/`, `pipeline/selective_vm.rs`, `pipeline/poly_embed.rs` |
| 방식 | 1:1 CISC→VM 바이트코드 (171–187 opcode) | RISC De-synthesis(12 micro-op) → 폴리모픽 ISA → 다이렉트 스레딩 |
| 명령 커버리지 | **100%** (실측 26,956/26,956) | **부분** (mov/lea/shift/arith/cmp/call/jcc/mem-operand + 32비트 정밀화) |
| **실제 역할** | **`--vm-oep` 프로그램 전체 가상화를 실제 담당** | **SDK 마커(`BTG_VM_START/END`) 선택 가상화 + T1-3 폴리 스텁 임베드만 담당** |
| 탈가상화 저항 | 약함 (1:1 매핑 — `commercial-vm-engine.md §1`이 스스로 "정적 패턴/심볼릭 탈가상화에 취약" 명시) | 강함(목표) |

**⇒ 가장 중요한 갭: 상용 엔진이 아직 "전체 프로그램 가상화"의 백엔드가 아니다.** `--vm-oep`는 여전히 레거시 1:1 VM으로 프로그램을 돌린다. 이는 문서상 "상용급 완료"라는 표기와 실제 코드가 어긋나는 지점이다.

### 0.2 소스 실측으로 확인한 상용 엔진의 미완성 지점

1. **`vm/poly/isa_spec.rs` opcode_map이 11개 op만 매핑** — `ArithmeticShiftRight`, `VirtualBranch`, `MemoryRead{1,2,4}`, `MemoryWrite{1,2,4}`가 **ISA 스펙에 아예 없음**. 즉 분기·메모리 폭별 op를 폴리모픽 인코딩할 수 없다.
2. **`vm/poly/interpreter.rs` 실행은 8개 op만** (Nor/AddWithCarry/ShiftRight/ShiftLeft/VirtualPush/VirtualPop/SetFlag/Halt). `ArithmeticShiftRight`, `MemoryRead`, `MemoryWrite`, `VirtualBranch`, `NativeCallBridge`는 `_ => {}`로 **조용히 무시**된다. → 참조 시뮬레이터(eval_state)와 폴리 인터프리터가 **차등 불일치** 상태 (T1-2 문서도 "폴리 계층 확장 과제로 남김"이라 명시).
3. **`vm/risc/lifter.rs` 명령 커버리지가 부분** — mov 계열/movzx/movsx/lea/shift/arith ALU/cmp/call/jcc/mem-operand + 32비트 정밀화. mul/div, 문자열 ops, SSE/FPU, BMI1/2, CMOVcc, lock/atomic, 다수 push/pop/스택 형태는 미커버(레거시 171 opcode와 대비).
4. **`vm/threaded/` 네이티브 러너는 검증 테스트만** — `DirectThreadedNativeRunner::build_all_handlers`가 폴리 스텁 임베드에 쓰이고, 전체 프로그램 경로에는 미배선.

### 0.3 패킹 산출물 실측 (이전 실행)
- `packed_vmoep.exe`가 16개 테스트 전체 통과 + checksum baseline 동일(0x2cdc0e4511d84a64), GUI 정상 기동.
- **그러나 `.text`가 원본과 byte-identical 평문 유지** (TLS 콜백 존재 → `TLS-first-callback decryptor = Phase-2`로 유보). `.textb`(630KB, entropy 7.551)만 셔플+암호화.

### 0.4 문제.txt 잔여 (부트/SEH 구조 이슈)
- H1~H4: native-call 브리지 ABI / 스택 정렬 / 제외 넷 / Once teardown.
- [10] SEH × 블록셔플 충돌: catch_unwind 프레임이 .pdata 커버리지 밖 → 175함수(0x127B0, ~28% .text)를 네이티브로 유지.
- Phase 2.4 전체 .text 가상화 + `entry_native` 제거는 미완(일부는 --vm-oep로 해소됐으나 SEH/TLS 때문에 평문 유지).

---

## 1. 목표 (Definition of "Commercial-Grade")

Themida/VMProtect급 VM 컴파일러가 갖춰야 할 최소 역량을 아래 6축으로 정의하고, 각 축의 **현재 등급**과 **목표 등급**을 매핑한다.

| 축 | 현재 | 목표 |
|---|---|---|
| **A. 전체 프로그램 가상화 백엔드** | 레거시 1:1 VM (`--vm-oep`) | 상용 엔진(risc→poly→threaded)이 전체 .text 가상화 담당 |
| **B. .text 온디스크 평문 0** | `.text` byte-identical 평문 | `.text` at-rest 암호화 + TLS-first-callback decryptor |
| **C. 명령 커버리지 100%** | 레거시 100% / RISC 부분 | **RISC 리프터 100%** (시스템 명령 제외) |
| **D. 탈가상화 저항** | 1:1(취약) / RISC는 미통합 | 다형성 ISA + 핸들러 MBA + opaque predicate + rolling key 전역 적용 |
| **E. 실행 정합(부트/SEH/안정성)** | 16테스트 통과 / SEH 28% 네이티브 | SEH 함수도 가상화(.pdata 재생성), 부트 크래시 0, 임의 타깃 회귀 |
| **F. 성능** | `--vm-bench` (레거시) | 핸들러 퓨전/슈퍼-op, 네이티브 대비 실용 오버헤드 |

---

## 2. 핵심 갭 분석 (Gap → Phase 매핑)

| # | 갭 | 설명 | 해결 Phase |
|---|---|---|---|
| G1 | **상용 엔진 미통합** | risc/poly/threaded가 전체 프로그램 경로에 안 쓰임 | **P3** |
| G2 | **폴리 ISA/인터프리터 불완전** | branch/mem/arith-shift/native-call op 누락 | **P1** |
| G3 | **RISC 리프터 커버리지 부족** | 레거시 100% vs RISC 부분 | **P2** |
| G4 | **.text 평문 유지** | TLS 콜백 때문에 at-rest 암호화 불가 | **P5** |
| G5 | **SEH 네이티브 28%** | 셔플 블록 .pdata 부재 | **P4** |
| G6 | **탈가상화 저항 미성숙** | 1:1 경로 취약, 핸들러 MBA/opaque 미전역화 | **P6** |
| G7 | **리포 중복** | 상위 repo + 중첩 `vm-obf/`(스테일) 공존 | **P0** |
| G8 | **검증/회귀 자동화 부족** | 샘플 타깃(real_win_calc 등) 부재, T1-4 스모크 미실행 | **P7** |

---

## 3. 업그레이드 계획 (Phase별 상세)

> 각 Phase = 목표 / 작업 항목 / 검증 / 산출물. 순차 의존(P1→P2→P3)이 우선이고,
> P0/P7은 병렬 진행 가능. 각 Phase는 `cargo build --release` green + `cargo test --release` green + `--vm-test` ALL PASS를 유지해야 진행.

### P0 — 저장소 정리 (Repo Consolidation)  [하루]  ✅ 완료 (2026-08-15)
**상태**: **✅ 완료** — 상위 repo `asdfsadfecwecc`를 canonical로 확정(cc6b973, RISC 32-bit 최신).
중첩 `vm-obf/` 스테일 clone(HEAD `0df672a`, upstream 조상)이 **unique/unpushed 커밋 0개임을
`merge-base --is-ancestor`로 확인 후 삭제** → 단일 Cargo workspace. `git status` clean,
`cargo build --release` green.

**목표**: 작업 기준을 단일 repo로 확정.
- 상위 repo `asdfsadfecwecc`를 **canonical**로 확정 (cc6b973이 RISC 32비트 최신 포함).
- 중첩 `vm-obf/`가 스테일 copy임을 확인 후 **제거 또는 동기화 결정** — 현재 vm-obf HEAD(0df672a)는 상위보다 뒤처짐. 제거 권장(또는 `.gitignore`로 배제).
- **검증**: `git status` clean, 단일 Cargo workspace, `cargo build --release` green.

### P1 — 폴리모픽 ISA / 인터프리터 완성 (Complete Polymorphic Semantics)  [2–3일]  ✅ 완료 (2026-08-15)
**상태**: **✅ 완료** — G2 해소. `vm/poly/isa_spec.rs` opcode_map에 `ArithmeticShiftRight`,
`VirtualBranch`(BranchCondition 인코딩), `MemoryRead/Write{1,2,4,8}`, `NativeCallBridge`를 추가해
**전체 reachable opcode set을 폴리모픽 인코딩**하고, `vm/poly/interpreter.rs`가 이 op들을
`RiscProgram::eval_state`(참조)와 **완전 상태 동치**(regs/temps/flags/vsp/stack/mem)로 실행.
차등 테스트(`>=3 seeds`): `test_poly_arith_shift_matches_reference`,
`test_poly_mem_rw_matches_reference`(width 1/2/4/8), `test_poly_branch_matches_reference`
(taken/not-taken + `CounterZero` 2/4/8), `test_poly_native_call_bridge_stub`,
`test_poly_opcode_map_uniqueness_complete_isa`. `cargo test --release` → **162 passed; 0 failed**.
커밋: `2a3d6c8`(인터프리터 구현), `ece32c9`(인코더), `20af238`(차등 테스트+분기 인덱스 수정).

**목표**: G2 해소 — 폴리 계층이 **전체 RiscOp를 인코딩·실행**하도록.

**작업 항목**:
1. `vm/poly/isa_spec.rs`: opcode_map에 다음을 추가
   - `ArithmeticShiftRight`
   - `VirtualBranch` (BranchCondition을 인코딩에 포함)
   - `MemoryRead{1,2,4,8}` / `MemoryWrite{1,2,4,8}` (width를 opcode/피연산자에 반영)
   - `NativeCallBridge`
2. `vm/poly/encoder.rs`: 위 op의 인코딩 지원 (즉시값 8바이트·피연산자·width·분기 타깃).
3. `vm/poly/interpreter.rs`: `ArithmeticShiftRight`, `MemoryRead`, `MemoryWrite`, `VirtualBranch`, `NativeCallBridge` 핸들러 구현 — `vm/risc/mod.rs::eval_state`(참조)와 **차등 동치**를 테스트로 고정.
4. **메모리 모델**: 인터프리터에 `mem: HashMap<u64,u8>`(또는 arena)를 도입, `eval_state`와 동일 계약.

**검증**: `cargo test --release` 에 다음 차등 테스트 추가 —
`test_poly_mem_rw_matches_reference`, `test_poly_branch_matches_reference`,
`test_poly_arith_shift_matches_reference`, `test_poly_native_call_bridge_stub`.
폴리 인터프리터 == eval_state == (가능하면) 네이티브 하네스, 3 seeds × 각 시나리오.

### P2 — RISC 리프터 명령 커버리지 100% (Full RISC Lifting)  [5–7일]
**목표**: G3 해소 — `vm/risc/lifter.rs`가 레거시 171-opcode 커버리지와 동등해지도록 확장.

**작업 항목** (레거시 `vm/lifter/` + `vm/text_lift/` 커버리지와 대조하며):
1. **산술/논리 전 계열**: MUL/IMUL(1/2/3-op), DIV/IDIV(8/16/32/64, RAX:RDX), BSWAP, NEG/NOT 전 폭.
2. **비트**: BSR/BSF, TZCNT/LZCNT/POPCNT, SETcc, TEST, BMI1/2(ANDN/BLSR/BLSMSK/BLSI).
3. **문자열 ops**: MOVS/STOS/LODS/SCAS/CMPS + REP/REPE/REPNE (명시적 루프 lowering).
4. **CMOVcc**: 16 조건 (Jcc+MOV lowering).
5. **SSE/FPU 스칼라**: MOVSD/MOVUPS/XORPS, ADDSS/SD, SUB, MUL, DIV, CVTSI2SD/CVTSS2SD/CVTTSD2SI 등 (실측 타깃에 나타난 것부터).
6. **원자적**: CMPXCHG/XCHG/XADD, LOCK INC/DEC (메모리 RMW 원자 op로).
7. **스택/제어**: PUSH/POP 전 폭, RET/RET_IMM16, CALL direct/indirect, Jcc/JMP 전 조건·전 폭.
8. **32비트 의미론 일관성**: 이미 해소된 zero-extension/시프트 마스크를 **64비트까지 확장** 검증.
9. **레거시 커버리지 진단 재사용**: `--text-vm`이 뽑는 미지원 목록을 RISC 리프터 기준으로 재측정해 100% 달성.

**검증**: `--text-vm`/`--text-vm-oep` 진단이 RISC 리프터 기준 **100%** 리포트. 리프트된 프로그램이 `eval_state`에서 원본과 동작 동치(M4 dummy_fn 패턴 유지).

### P3 — 상용 엔진을 전체 프로그램 가상화 백엔드로 통합 (Engine Integration)  [7–10일]
**목표**: G1 해소 — `--vm-oep`가 **레거시 1:1 VM 대신 risc→poly→threaded 파이프라인**으로 프로그램을 virtualize.

**작업 항목**:
1. `src/pipeline/crypto/place.rs`·`vm_embed.rs`·`bootstub.rs`의 Program VM 생성 경로를
   `build_program_vm`(레거시 `text_lift` 바이트코드) → **`selective_vm`식 RISC 리프트 + 폴리 인코딩 + 다이렉트 스레디드 핸들러**로 교체하는 새 `build_program_vm_commercial` 작성.
2. **CFG 유지**: `vm/text_lift/lift_program_cfg`가 만드는 **기본 블록/CFG/제외 결정**을 그대로 재사용하고, 각 블록 본문만 RISC로 lift → 폴리 encode → 핸들러 dispatch.
3. **네이티브 브리지**: 제외(SEH/CRT) 블록과 `NativeCallBridge`가 기존 boot stub 상태 계약(r8=state 등)과 호환되게.
4. **엔트리 정합**: `entry_native=false`, 부트 스텁이 폴리 VM으로 OEP dispatch. 기존 2026-08-14 부트 크래시 수정(원본 .text 주소 유지) 원칙 유지.
5. **토글 플래그**: `--vm-commercial`(또는 기존 `--vm-oep` 내 전환)로 회귀 안전하게.

**검증**: `btg-packer -i rust_packer_test.exe -o packed_commercial.exe --vm --vm-oep --vm-commercial`
→ 실행 시 **16개 테스트 전체 통과 + checksum baseline 동일**. `.map/.sym`이 RISC 바이트코드↔원본 VA 매핑을 기록. 기존 레거시 경로는 무회귀.

### P4 — SEH 함수 가상화 (.pdata 재생성)  [5–7일]
**목표**: G5 해소 — panic/catch unwind 경로를 셔플/가상화하면서 OS unwind가 동작하게.

**작업 항목**:
1. 셔플 블록(.textb) 또는 RISC VM 블록용 **`.pdata` RUNTIME_FUNCTION/UNWIND_INFO 재생성**.
   - 문제.txt [10]에서 시도했던 "함수 연속 레이아웃 + per-function .pdata"와
     "블록 셔플 × SEH"의 근본 충돌을 **RISC VM 경로에서는 회피**할 방법 검토
     (예: VM 내부가 아닌 **브리지 진입점만 원본 .pdata로 감싸고**, unwind는
     VM 상태 복원 지점까지 native-call로 승격).
2. SEH 네이티브 보존 함수 수를 **175→최소(0 목표)** 로 줄여 `.text` 평문 영역 축소.

**검증**: `test [10] SEH unwinding & catch_unwind`가 **가상화 상태에서도** 통과(현재는 네이티브 유지로만 통과). unpack된 `.pdata`가 로더에 의해 수용(STATUS_INVALID_IMAGE_FORMAT 없음).

### P5 — .text 온디스크 평문 0 (TLS-first-callback Decryptor)  [4–6일]
**목표**: G4 해소 — `.text`를 at-rest 암호화하고, TLS 콜백이 평문이어야 하는 문제를 해소.

**작업 항목**:
1. **TLS 콜백 우회/복호화 전략**:
   - (a) TLS 콜백이 참조하는 함수만 네이티브로 남기고 나머지 .text 암호화 (최소 평문),
   - (b) TLS 디렉터리에서 콜백을 **부트 스텁이 먼저 복호화한 뒤 실행**하도록 부트 스텁을 TLS-entry보다 앞서게 하거나,
   - (c) `.text`를 암호문으로 저장하되 로더가 매핑 후 부트 스텁이 자기 몫을 복호화 (콜백은 무해한 스텁으로 대체).
2. 부트 스텁에 **TLS-first decryptor** 추가(패커 로그가 이미 `Phase-2`로 유보한 항목).
3. 복호화 후 `.textb`/프로그램 VM과 동일한 rolling-key/MBA 보호를 `.text`에도 적용.

**검증**: `verify_text.py` 재실행 → **`.text` first-bytes identical = False**, entropy 7.5 근접. 16개 테스트 + TLS/static-init(test [15]) 통과. 덤프(온디스크)에서 원본 x86 복원 불가.

### P6 — 탈가상화 저항 강화 (Anti-De-virtualization)  [5–8일]
**목표**: G6 해소 — 1:1 취약성 제거 + 핸들러/데이터 난독화 전역화.

**작업 항목**:
1. **1:1 레거시 경로 폐기/후퇴**: P3 통합 후 기본이 RISC+poly+threaded가 되도록 하고, 레거시는 진단/벤치만 남김.
2. **핸들러 MBA 전역화**: `--m8`(핸들러 테이블 MBA 키)를 상용 엔진 핸들러 테이블에도 적용.
3. **Opaque Predicate / 컨트롤 플로우 난독화**: RISC lift 전·후에 거짓 분기·더미 블록 주입.
4. **롤링 키 강화**: 단일 선형 다항식→**비선형/멀티라운드 키 스트림**, VIP 연동 유지.
5. **슈퍼 오퍼레이터 패턴 다양화**: 고정 패턴 대신 빌드 시드별 패턴 분포 변화.
6. (선택) 심볼릭 실행 방해: 정수 나눗셈/메모리 인덱싱에 불투명 상수 삽입.

**검증**: `cargo test` 차등 전부 유지 + `--vm-bench` 실행. 임의 빌드 2개가 **서로 다른 바이트코드/핸들러**를 생성(시드 다양성 테스트). 알려진 탈가상화 기법(패턴 매칭/슬라이딩 윈도우) 시나리오 체크리스트 작성.

### P7 — 검증·회귀·QA 자동화 (Hardening & QA)  [병렬, 3–5일]
**목표**: G8 해소 — 상용 신뢰도 확보.

**작업 항목**:
1. **샘플 타깃 확보**: `real_win_calc.exe`(메모장/계산기 등 Win32 GUI) 1~3개 추가, `--vm-commercial` 회귀.
2. **자동 회귀 스크립트**: `cargo test` + `--vm-test` + 5개 CLI 조합(`plain / --vm / --vm-oep / --full / --chained`) pack→run→checksum 비교를 한 번에.
3. **크래시/Event Log 모니터링**: packed 실행 후 Windows Event Log 0 Crash 검증.
4. **문서 동기화**: `commercial-vm-engine.md`·`milestones.md`가 "실제 통합 여부"를 솔직히 반영(현재 "완료" 표기는 G1 때문에 과장).
5. **성능 벤치**: `--vm-bench`로 상용 경로 오버헤드 측정, P6 후 목표치 설정.

**검증**: 전 샘플 타깃 × 전 조합 green. 문서가 코드와 일치.

### P8 — (선택·후속) SDK/LLVM IR 실용화  [추후]
- `sdk/llvm_interface.rs`가 현재 스텁 수준 → 실제 Clang/Rustc 플러그인 또는 LLVM IR 파싱으로 **소스 레벨 선택 가상화**를 실용화.
- C/C++/Rust `BTG_VM_START/END` 마커가 P3 상용 엔진과 연동.

---

## 4. 우선순위·의존성·일정 요약

```
P0(저장소) → P1(폴리 완성) → P2(RISC 100%) → P3(엔진 통합) → P4(SEH) → P5(.text 0) → P6(탈가상화)
                                  └─────────────────────────────┘
P7(QA)  =================== 병렬 진행 =====================
P8      ============ 선택/후속 ============
```

| Phase | 핵심 산출물 | 예상일 | 게이트 |
|---|---|---|---|
| P0 | 단일 repo | 1d | build green |
| P1 | 폴리 ISA/인터프리터 완성 | 2–3d | 차등 테스트 green |
| P2 | RISC 리프터 100% | 5–7d | `--text-vm` 100% |
| P3 | 상용 백엔드 통합 | 7–10d | 16테스트+checksum 동일 |
| P4 | SEH 가상화 | 5–7d | test[10] 가상화 통과 |
| P5 | .text 평문 0 | 4–6d | verify_text entropy |
| P6 | 탈가상화 강화 | 5–8d | 시드 다양성+벤치 |
| P7 | QA 자동화 | 병렬 3–5d | 전 조합 green |

**총 예상: 약 3–4주 (인력 1명 기준, 병렬 P7 포함).**
**우선순위**: G1·G2·G3(P1→P3)가 상용화의 **핵심 게이트**. G4·G5(P4→P5)는 "실제 온디스크 보호 수준"을 결정. G6은 이후 차별화.

---

## 5. 리스크

| 리스크 | 영향 | 완화 |
|---|---|---|
| RISC 리프터 100% 달성 시 성능 저하 | 실행 속도 | P6 슈퍼-op/핸들러 퓨전, `--vm-bench` 기준 설정 |
| P3 통합 시 기존 부트 크래시 재발 | 실행 불가 | 2026-08-14 수정 원칙(원본 주소 유지, native 브리지 계약) 보존 + 단계 토글 |
| SEH 가상화가 블록셔플과 재충돌 | test[10] 회귀 | P4의 "브리지 진입점만 원본 .pdata" 대안 우선 |
| 폴리 ISA 확장이 인코더/인터프리터/참조 3중 동치 유지 실패 | 차등 불일치 | P1에서 차등 테스트를 3 seeds로 고정 |
| TLS decryptor가 로더 동작과 충돌 | 부트 실패 | P5에서 TLS 콜백 스텁 대체 + cdb 검증 |
| 리포 중복으로 작업 분산 | 혼선 | P0에서 즉시 해소 |

---

## 6. 결론 (한 줄)

**현재는 "RISC·폴리·스레디드 상용 엔진을 구현했지만 실제 프로그램 가상화는 여전히 1:1 레거시 VM이고 `.text`는 평문"인 중간 단계다.** P1→P3(상용 엔진을 전체 가상화 백엔드로) + P4→P5(.text 온디스크 평문 0)가 "Themida/VMProtect급"으로 가는 결정적 게이트이며, P6(탈가상화)·P7(QA)이 상용 신뢰도를 완성한다.
