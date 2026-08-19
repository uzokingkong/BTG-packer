# BTG Packer — Whole-Program VM: Function Atomicity & Win64 Native-Call Bridge Spec

> 작성: 2026-08-19 · 드라이버: `readccc.md` §4.6 (P0) · 상태: **명세 v1 — 설계 완료, 일부 구현됨, 명시적 후속 작업 있음**
>
> 이 문서는 `--vm-oep --vm-commercial`(전체 프로그램 RISC VM)의 함수 경계 원자성과
> VM↔네이티브 콜 브리지의 정확성 계약을 명세한다. "보호 강도"가 아니라 **"의미 보존 +
> 100% 정확한 fallback"** 을 우선한다 (readccc §4.6 결론).

---

## 0. 목표

| 요구 (readccc §4.6) | 이 명세의 산출물 |
|---|---|
| 함수 원자성 | `.pdata` / UNWIND_INFO 기반 function-ownership 모델 (§1) |
| 네이티브 콜 브리지 | Win64 ABI 계약 명세 (caller/callee-saved, 32B shadow, 16B 정렬, return, unwind) (§2) |
| callbacks / vtable | reentrant callback & 동적 디스패치 테스트 매트릭스 (§2.4) |
| EH / SEH / C++ EH / Rust panic | 지원 계층(tier) 정책 (§3) |
| TLS / initializers | TLS 콜백 순서와 VM 경계 crossing 계약 (§4) |
| Fallback 정확성 | 지원 불가 함수는 **네이티브로 유지** (all-or-nothing, 미지원 시 silent skip 금지) (§5) |

수용 기준: 모든 계층에서 `original`/`packed`의 관찰 가능한 동작이 일치하고, 브리지·unwind·TLS
경계의 차등 테스트가 통과해야 한다.

---

## 1. Function-Ownership 모델 (`.pdata` / UNWIND_INFO 기반)

### 1.1 원칙

VM↔네이티브 crossing은 **함수 경계(prologue/epilogue 또는 call-ret 쌍)에서만** 발생해야 한다.
함수 중간에서 VM이 네이티브로 진입하거나, 네이티브가 함수 중간으로 점프해 스택 프레임을 깨는
경우는 금지 (readccc §4.6: "분기가 epilogue/tail로 진입해 stack frame을 깨뜨릴 위험").

### 1.2 구현 근거 (현재 상태)

- **`.pdata` 재생성 + 브리지 UNWIND_INFO**: `src/pipeline/build.rs` — Program-VM 모듈 영역
  `[vm_prog_rva .. vm_prog_rva+vm_prog_total)`을 RUNTIME_FUNCTION으로 커버하고, Program-VM
  엔트리 프로로그(`sub rsp,0xA0` + 15 push)에서 유도한 UNWIND_INFO(UWOP_ALLOC_LARGE 160 +
  PUSH_NONVOL, CodeOffset 내림차순)를 `.pdata` 뒤에 배치한다. → OS unwinder가 VM 내부 예외 시
  결정적으로 VM 프레임 밖으로 unwind (기존 P4 달성, legacy `--vm --vm-oep` 경로).
- **함수 경계 소유권**: `src/vm/text_lift/exclusions.rs` `detect_seh_native_functions` /
  `can_reach_panic` — SEH 함수 경계와 panic 도달 함수를 네이티브 유지 세트로 결정.
- **상용 리프트 fallback**: `src/vm/text_lift/commercial.rs` — 지원 불가 블록이 SEH 함수 경계
  바깥에서 발견되면 해당 함수를 네이티브로 남긴다 (함수 원자성 보장).

### 1.3 명세 계약

```
FUNCTION-OWNERSHIP("F ∈ VM"): F의 모든 블록이 lift 가능하고, F가 .pdata RUNTIME_FUNCTION의
  Begin/End에 완전히 포함된다. F의 어떤 네이티브 진입점도 F의 프롤로그를 통과해야 한다.
FUNCTION-OWNERSHIP("F ∈ NATIVE"): F의 어떤 블록도 VM화하지 않는다. VM이 F의 mid-function
  주소로 분기하는 것을 금지한다 (crossing은 F의 entry 또는 call-site에서만).
```

- 소유권 결정은 빌드 시 고정되어 manifest/map에 기록되어야 한다 (진단 시 `--map`/RISC map CSV로
  역추적).
- **후속 작업 (명시적)**: 소유권 결정과 `.pdata` 경계를 빌드 후 검증하는 자동 검사
  (`validate` 패스에 function-ownership consistency check 추가) — 현재 `validate.rs`는
  구조적 PE 검증만 수행하며 소유권 일관성은 미검증.

---

## 2. Native-Call Bridge — Win64 ABI 계약

### 2.1 상태

`RiscOp::NativeCallBridge`는 reference(`src/vm/risc/mod.rs` `eval_state`),
poly 인터프리터(`src/vm/poly/interpreter.rs`), threaded 네이티브 하네스
(`src/vm/threaded/harness/emit_block.rs`) 모두에서 **인지된 no-op 스텁**이다
(스트림 소비 + 상태 불변). 실제 호스트 콜은 별도 런타임/브리지 계층에 있다
(상용 `--vm-commercial`은 이 op를 포함한 함수를 네이티브로 유지 —
`is_encodable=false`). 상용 self-decoding 디스패처(`src/vm/threaded/poly_direct.rs`)는
레거시 `OP_NATIVE_CALL`급 네이티브 콜 브리지를 갖는다 (not-found 타깃에서 ret_ip pop →
GPR 실장 → Win64 콜 → 동기화 → ret_ip 재개).

### 2.2 Win64 호출 규약 (콜 사이트)

| 항목 | 규칙 | 비고 |
|---|---|---|
| 인자 | RCX, RDX, R8, R9 (정수/포인터); 5번째부터 스택 | 첫 4개는 32B shadow space 위 |
| shadow space | 호출자가 피호출자 진입 직전 RSP 위에 32B 할당 | |
| 스택 정렬 | **call 직전 RSP ≡ 0 (mod 16)** | 8 mod 16일 땐 8B push 후 call |
| 반환 | RAX (정수/포인터); XMM0 (FP/벡터) | |
| callee-saved | RBX, RBP, RDI, RSI, RSP, R12–R15 | 복원 의무 |
| caller-saved | RAX, RCX, RDX, R8–R11 | 자유 clobber |
| RFLAGS | 방향 플래그(DF)는 0이어야 함 | |

> 레지스터 세트 상수: `src/vm/abi.rs` `WIN64_NONVOL_GPRS`.

### 2.3 VM 상태 동기화 계약 (브리지 실행 시)

VM virtual 레지스터는 물리 레지스터가 아니므로, 네이티브 콜 전에 콜 아규먼트를 Win64 레지스터로
실장하고, 콜 후 반환값을 virtual RAX로 회수해야 한다.

```
PRE-CALL   : [virtual args → RCX,RDX,R8,R9 (+stack)];  VM 스택(vreg[4]=RSP)에 ret_ip 기록;
             물리 callee-saved 보존(push), 16B 정렬 보장.
CALL       : call target; (돌아오면 RAX/XMM0 = 반환값)
POST-CALL  : [RAX → virtual RAX]; callee-saved 복원(pop); VM 스택에서 ret_ip pop → dispatch 재개.
```

**차등 계약**: reference `eval_state` / poly interpreter / threaded 네이티브는 NativeCallBridge를
no-op으로 처리하므로 상태가 완전히 동일해야 한다. 즉 브리지가 **VM 가상 상태를 변경하지 않는다**
(스트림만 소비). 실제 콜을 수행하는 계층은 동일한 가상 상태 계약을 만족해야 한다.

### 2.4 Callback / vtable / reentrancy 매트릭스

| 시나리오 | 요구사항 | 현재 |
|---|---|---|
| 네이티브 → 콜백 → VM (reentrant) | 콜백 재진입 시 VM 상태를 스택에 보존/복원 | 미검증 |
| vtable 동적 디스패치 | 간접 call 타깃이 VM 함수 or 네이티브 함수 — 소유권 경계에서만 진입 | 부분 |
| 콜백이 teardown/panic 경로 | Once/panic 공유-state 함수 네이티브 유지 (기존 P4 안전망) | 구현됨 |

**후속 작업 (명시적)**: reentrant callback 및 vtable 디스패치 테스트 매트릭스 — 현재 자동
테스트가 부족.

### 2.5 구현 근거

- threaded native emission: `src/vm/threaded/harness/emit_block.rs` (브랜치 브리지 헬퍼,
  shadow/정렬 규약 준수).
- self-decoding 디스패처 브리지: `src/vm/threaded/poly_direct.rs`.
- reference no-op 계약: `src/vm/risc/mod.rs` (`NativeCallBridge => {}`), `src/vm/poly/interpreter.rs`.

---

## 3. EH / SEH / C++ EH / TLS — 지원 계층(Tier) 정책

### 3.1 Tier 정의

| Tier | 지원 | 동작 | 현재 상태 |
|---|---|---|---|
| **T0** | SEH 없는 평문 코드 | 전부 VM화 | ✅ |
| **T1** | SEH 함수 — panic 도달 불가 | VM화 (무해) | ✅ (`BTG_SEH_MINIMAL`, 175→132) |
| **T2** | SEH 함수 — panic 도달 가능(ehandler∩panic) | 네이티브 유지 (최소 set) | ✅ (기본 132) |
| **T3** | switch-dispatch EHANDLER / Once·panic 공유-state | 네이티브 유지 (안전망) | ✅ (`BTG_SEH_NONE=1` → 49) |
| **T4** | C++ EH / Rust panic .pdata 심층 | 계약 명세 후 differential | 🔶 부분 (legacy VM 경로) |
| **T5** | 상용 엔진 전체 SEH 가상화 | gate로 132 유지 | ⬜ (미검증) |

구현: `src/vm/text_lift/exclusions.rs` `detect_seh_native_functions` +
`can_reach_panic` + `BTG_SEH_MINIMAL`/`BTG_SEH_NONE` 환경변수. 종료 시 panic-safe.

### 3.2 Fallback 원칙

지원하지 않는 명령/함수는 **절대 조용히 skip하지 않는다.** 해당 함수를 통째로 네이티브로
유지하고, manifest에 fallback 이유를 기록한다 (`commercial.rs`의 all-or-nothing lift 정책).

---

## 4. TLS / 초기화자 — 순서와 crossing 계약

- TLS 콜백은 로더가 부트 스텁 **이전에** 실행한다. `.text` at-rest 암호화 시 콜백 도달 함수는
  평문 유지해야 한다.
- 구현: `src/vm/text_lift/tls_guard.rs` `detect_tls_callback_ranges` — TLS dir → `.pdata` 함수 →
  forward(callee) transitive closure로 평문 유지 범위 산출. (기존 P5 달성)
- 계약: TLS 콜백 진입·복귀는 네이티브; 부트 스텁 디스패치 후에만 VM 경계가 활성화된다.
  스레드 생성 시 TLS 콜백(test[9])과 teardown 진입이 검증됨.

---

## 5. 구현 근거 — 요구 ↔ 모듈 매핑

| 요구사항 | 모듈/함수 |
|---|---|
| `.pdata` 브리지 UNWIND_INFO | `src/pipeline/build.rs` (unwind_rva, UWOP 재생성) |
| SEH 네이티브 최소 세트 | `src/vm/text_lift/exclusions.rs` |
| TLS 콜백 평문 유지 | `src/vm/text_lift/tls_guard.rs` |
| 상용 리프트 all-or-nothing fallback | `src/vm/text_lift/commercial.rs` |
| reference NativeCallBridge no-op | `src/vm/risc/mod.rs` `eval_state` |
| poly 인터프리터 bridge no-op | `src/vm/poly/interpreter.rs` |
| threaded native emission | `src/vm/threaded/harness/emit_block.rs` |
| self-decoding 디스패처 브리지 | `src/vm/threaded/poly_direct.rs` |
| Win64 레지스터 상수 | `src/vm/abi.rs` |

---

## 6. 수용 기준 & 후속 작업

**수용 기준 (이 명세의 게이트)**:
1. `cargo build --release` exit 0 · `cargo test --release --lib` 전부 통과.
2. 기존 16-test + FINAL CHECKSUM `0x2cdc0e4511d84a64` 무회귀.
3. NativeCallBridge no-op이 reference/interpreter/threaded에서 상태 완전 동치 (기존 차등 테스트).

**명시적 후속 작업 (미구현 — 이 명세가 만든 다음 게이트)**:
- [ ] function-ownership ↔ `.pdata` 일관성 자동 검사 (`validate.rs` 확장).
- [ ] reentrant callback / vtable 동적 디스패치 테스트 매트릭스.
- [ ] 실제 호스트 콜을 수행하는 NativeCallBridge ABI 구현 (Win64 shadow/정렬/unwind).
- [ ] 상용 엔진(`--vm-commercial`)의 T5 전체 SEH 가상화 differential.
