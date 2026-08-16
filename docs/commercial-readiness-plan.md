# BTG Packer — 상용화 준비 실행 계획 (Commercial Readiness Plan)

> 기준: `Notes_260817_030438.txt` 리뷰(24개 항목) + 이전 로드맵 통합.
> 상태 마커: ✅ 완료 · 🔶 진행 중 · ⬜ 미착수
> 갱신: 2026-08-17

---

## 0. 완료된 항목 (이 계획 작성 시점)

| 항목 | 상태 | 커밋/근거 |
|---|---|---|
| BTG-C1 기본 암호화 (RC4 퇴출 진행) | ✅ | `4203e43` — `--rc4`로만 RC4 복귀 |
| C1 배선: plain / reencrypt / m7 / VM | ✅ | `1013010`, `3d8d4b9`, `e75f1bf` |
| M7 refcount-safe on-demand 재암호화 | ✅ | `1013010` |
| metrics 실측화 (flattening/MBA 엔트로피) | ✅ | `1013010` |
| dispatcher CFG 검증 강화 | ✅ | `5e7bd40` |
| 기저 버그: encode_with_labels, probe_bsr/bsf | ✅ | `1013010` |

---

## 1. 🔴 P0 — VM 정확성 / ABI (상용의 기반)

### 1-1. Canonical VM semantics 단일화 (Notes #1)
- **목표**: 하나의 x86 명령이 모든 백엔드(lifter→IR→RISC→poly→threaded→handlers→interp)에서 동일 의미론.
- **작업**: `docs/vm-compiler-architecture.md`에 semantic contract 명문화 → 각 백엔드가 참조하는 단일 `vm/semantics.rs`(상수/함수)로 통합. BSR/BSF/TZCNT/LZCNT, ADC/SBB, shift count, partial register, RFLAGS 규칙을 전수 대조.
- **검증**: 명령 × 백엔드 차등 테스트 행렬 자동 생성.
- **상태**: 🔶 진행 중 — ✅ (f7578b5) ADD/SUB/CMP/INC/DEC/NEG/NOT/SHIFT의 x86 정확 플래그를 전용 micro-op으로 canonical화, RISC 참조·poly 인터프리터·harness 동기화, cross-path 플래그 drift **0**(하드 게이트). ⬜ BSR/BSF/TZCNT/LZCNT 폭·ZF 정책 전수 대조, ADC/SBB 전용 op, partial register(AH/BH) 정책, poly_direct 네이티브 핸들러의 AF 캡처 정합.

### 1-2. VM ABI 명세 + 검증기 (Notes #2)
- **목표**: Win64 ABI 계약(volatile/nonvolatile GPR, XMM, RSP 정렬, shadow space, RFLAGS 정책)을 코드로 명문화.
- **작업**: `VmAbi` 구조체 + `vm/abi.rs`, 모든 native handler/arena 호출(`extern "C"` transmute)을 이 명세로 검증. 특히 `vm/arena.rs`의 transmute 호출부와 `handlers/`의 레지스터 클로버 전수 점검.
- **검증**: handler별 "클로버하는 레지스터 ⊆ volatile ∪ 자신의 인자" 자동 검증 테스트.

### 1-3. dispatcher CFG 검증 추가 확장 (Notes #3, 부분 완료)
- ✅ 분기 타깃/경계/self-loop/call-ret (5e7bd40).
- ⬜ stack-delta 검증 (각 분기 지점 간 RSP 변화), RIP-relative 오프셋이 실제 테이블/영역을 가리키는지, 간접 분기 타깃(점프 테이블) 유효성.

### 1-4. PE 구조/런타임 검증 강화 (Notes #4)
- **작업**: `pipeline/validate.rs`에 DOS/NT/Optional 헤더, 섹션 정렬, RVA/raw/virtual 경계, import/export/reloc/TLS/exception/LoadConfig/resource/debug/security 디렉터리 전수 검증 추가. "원본 PE ↔ 보호 PE 구조 diff" 리포트.
- **검증**: `validate::run`이 모든 디렉터리/섹션을 재파싱해 검증 (현재는 일부만).

---

## 2. 🔴 P1 — 안정성 / 런타임

### 2-1. unwrap() 제거 (Notes #16)
- **대상**: dispatcher(m7/m7_c1/reencrypt/reencrypt_c1)의 `Instruction::with*(...).unwrap()` ≈ 400+건을 `map_err`로, PE builder 등 나머지도. 입력에 따라 instruction 생성이 실패하면 패커가 크래시하지 않도록.
- **검증**: `cargo build` 후 `.unwrap()` 경고/사용처 전수 감소.

### 2-2. W^X 실행 메모리 (Notes #6, #7)
- **작업**: `vm/arena.rs`를 RW(쓰기)→instruction-cache flush→RX(실행)로. `CodeRegion { base,size,perms,owner,generation,checksum }` 메타데이터. (self-test용 arena는 제품과 구분 유지.)
- **검증**: `--vm-test`가 RX 상태에서 통과.

### 2-3. Exception/reentrancy safety (Notes #10, #23)
- **작업**: M7 상태 머신의 실패 경로(claim 중 예외, reencrypt 실패 시 평문 유출) 문서화 + 복구 정책. VM 실행 중 예외/SEH/Vectored/TLS 콜백 시 상태 무결성 테스트.
- **검증**: test[10] SEH + M7 조합, 예외 발생 후 상태 일관성.

### 2-4. Thread safety 명세 (Notes #22)
- **작업**: VM 런타임 전역 상태(rolling key, dispatcher state, IAT cache, decrypt state)가 thread-local vs process-global인지 명시 + 멀티스레드 보호 테스트.
- **검증**: 멀티스레드 타깃(threads.rs) × VM 조합 실행.

### 2-5. unsupported instruction → native fallback 전수 감사 (Notes #15)
- **작업**: RISC 리프터(현재 Err→블록 폴백) 외에 레거시 lifter/poly/text_lift의 unsupported 처리 경로 감사. "VM 지원→virtualize / 미지원→네이티브 / 불가→명시적 거부" 정책 + 빌드 로그(Function,VA,Instruction,Reason,Fallback) 출력.

---

## 3. 🟠 P1 — 빌드 / crypto / 진단

### 3-1. Deterministic build seed (Notes #18)
- **작업**: mba_constant/seed/poly_vm_seed/셔플/디스패처/문자열 랜덤을 **단일 `BuildSeed`**에서 파생 (`build_seed.rs`), 각 서브시스템이 자체 `random()` 호출 금지. 같은 input+seed+config → 동일 output.
- **검증**: 동일 시드 2회 빌드 바이트 동일 테스트.

### 3-2. Build manifest (Notes #19)
- **작업**: `BuildManifest { version, build_id, seed_id, vm_version, crypto_version, feature_flags, input_hash, output_hash }`를 출력/로그에 기록. 크래시 지원 재현용.
- **검증**: 패킹 로그 + `.manifest` 파일 생성.

### 3-3. Crash diagnostics + map 승격 (Notes #20, #21)
- **작업**: 개발/QA 빌드에서 크래시 시 (VM region, block, instruction, native/original VA, handler ID, dispatcher state) 기록. `.map`에 original VA→protected VA→block→VM type→handler→crypto region 매핑 확장.
- **검증**: 크래시 덤프에서 주소 역추적 데모.

### 3-4. Crypto boundary / key hierarchy (Notes #8, #9)
- **작업**: RC4 잔존(폴백) 정리, KDF domain separation: `KDF(master, domain||build_id||region_id)`로 VM/Code/String/IAT/Dispatcher/Metadata 키 분리. 난독화 transform과 보안 primitive 경계 명시.
- **검증**: 영역별 키 분리 + 한 영역 키 노출 시 타 영역 비침해 테스트.

### 3-5. Full-pipeline fuzzing (Notes #17)
- **작업**: `random PE → pack → rebuild → validate → execute → compare` 파이프라인 fuzz + 크래시 시 (seed, build config, VM seed, instruction, VA, block/handler ID) 저장. (현재 fuzz는 VM semantics만.)
- **검증**: 코퍼스 PE × 조합 무작위 회귀.

---

## 4. 🟡 P2 — 보호 강화 / 확장

### 4-1. Instruction coverage matrix 자동화 (Notes #14)
- **작업**: 명령 × (interpreter/RISC/poly/native/flags/memory/differential) 행렬을 테스트에서 자동 생성·출력.
- **검증**: `cargo test` 산출물로 행렬 리포트.

### 4-2. Super-op / polymorphic build-varied architecture (Notes #11, #12)
- **작업**: `super_ops.rs` 배선(IR 패턴→hot sequence→super-op), poly ISA가 build seed에 따라 인코딩/핸들러 세분도/상태 레이아웃까지 변화.
- **검증**: 시드 다양성 + `--vm-bench` 오버헤드.

### 4-3. SDK / 선택 가상화 실용화 (P8)
- **작업**: `sdk/llvm_interface.rs` 실구현, C/C++/Rust `BTG_VM_START/END` 헤더 + 빌드 통합, 선택적 가상화 트램펄린 전 레지스터 보존.
- **검증**: SDK 마커 타깃 pack→run.

### 4-4. 라이선스 / 워터마크 / 32-bit·ARM (선택)
- per-license 키·도메인 바인딩·워터마킹, 32비트/ARM 지원 여부 결정.

### 4-5. Anti-debug 강화 (Notes #24 — 마지막)
- 1-3-1까지 안정화된 뒤: DR0-7, 주기 재검사, HideFromDebugger, 부트스텁 자체 암호화(TLS-first 자가복호화).

---

## 5. 우선순위 실행 순서

```
P0-1 canonical semantics → P0-2 VM ABI 검증기 → P0-4 PE 검증 강화
        ↓
P1-1 unwrap 제거 → P1-2 W^X → P1-3 exception safety → P1-5 unsupported 감사
        ↓
P1-4 thread safety 명세
        ↓
P3-1 deterministic seed → P3-2 build manifest → P3-4 키 계층 → P3-3 진단/map
        ↓
P3-5 full-pipeline fuzz (병렬로 조기 착수 권장)
        ↓
P2-1 coverage matrix → P2-2 super-op/poly → P2-3 SDK → P2-4 선택 → P2-5 anti-debug
```

**총 예상: P0(1~2주) → P1(1~2주) → P3(1~2주) → P2(2~3주)** (인력 1명, fuzz/QA는 병렬).

---

## 6. 검증 게이트 (모든 항목 공통)

- `cargo build --release` green
- `cargo test --release --lib` green (신규 차등/회귀 포함)
- `--vm-test` ALL PASS
- pack→run 16-test + FINAL CHECKSUM = baseline `0x2cdc0e4511d84a64` 무회귀 (전 조합)
