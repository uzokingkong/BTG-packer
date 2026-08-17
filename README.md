# BTG Packer (vm-obf)

**Bidirectional Trigger Graph (BTG) — x86-64 이진 가상화 / 보호 / 난독화 패커 (연구용 프로토타입)**

Rust로 작성된 x86-64 PE 패커 겸 코드 가상화(VM) 엔진입니다. 원본 `.text`의
일부 또는 전체를 VM 바이트코드로 lift 하고, 선택적으로 코드/데이터 암호화,
임포트 은닉, 안티디버그, 실행 후 재암호화 등을 조합해 출력 PE를 만들어냅니다.

> 이 프로젝트는 **연구·개발용 프로토타입**입니다. "상용급
> (VMProtect/Themida 급) 상용 제품"은 **아직 아닙니다** — 그 방향을 지향하며
> 진행 중이지만 아래 한계에 있는 구조적 제약(특히 원본 `.text`의
> 평문 유지, VM/native 경계, 예외/멀티스레드)이 해소되지 않았습니다. 

> 크레이트: `btg-packer` v1.0.0 · Rust edition 2021 · Windows x64 대상

---

## 목차

- [실제 상태 요약](#실제-상태-요약)
- [구현된 것 (코드 기준)](#구현된-것-코드-기준)
- [아키텍처](#아키텍처)
- [빌드 / 테스트](#빌드--테스트)
- [사용법 (CLI)](#사용법-cli)
- [알려진 한계 (구조적)](#알려진-한계-구조적)
- [검증 상태](#검증-상태)
- [문서](#문서)
- [라이선스](#라이선스)
---

## 구현된 것 (코드 기준)

### 두 개의 VM 엔진

| | 레거시 VM 코어 | 상용 엔진 (Commercial-grade) |
|---|---|---|
| 모듈 | `vm/bytecode`, `vm/handlers`, `vm/lifter`, `vm/interp`, `vm/text_lift` | `vm/risc/`, `vm/poly/`, `vm/threaded/`, `sdk/`, `pipeline/selective_vm.rs`, `pipeline/poly_embed.rs` |
| 방식 | x86 → 1:1 VM 바이트코드 | x86 → RISC(마이크로-op) → 폴리모픽 ISA → 다이렉트 스레딩 |
| opcode 수 | **193개** | **38개 RISC 마이크로-op** |
| 커버리지 | 리프터가 지원하는 명령 범위는 넓음 (진단 수치 아래 참고) | RISC로 lift 불가 명령은 **함수 단위로 네이티브 유지(fallback)** |
| 역할 | `--vm-oep` (레거시 프로그램 가상화) | `--vm-oep --vm-commercial` (risc→poly→threaded) |

### 레거시 VM (193 opcode)

- opcode 단일 진실 공급원: `vm/bytecode/registry.rs`의 `opcodes!` 매크로
- 16 GPR + XMM + 6비트 RFLAGS + DF(방향) 모델, 두-스택(CALL/RET) 모델
- 그룹: MOV/MOVZX/MOVSX, ADD/SUB/IMUL/AND/OR/XOR/INC/DEC/NEG/NOT/CMP/TEST,
  SHL/SHR/SAR/ROL/ROR, MUL/IMUL/DIV/IDIV(8/16/32/64)·BSWAP, BSR/BSF/TZCNT/LZCNT/
  POPCNT, BMI1/2(BLSR/BLSMSK/BLSI/ANDN), SETcc, CMOVcc, 문자열 ops(MOVS/STOS/
  LODS/SCAS/CMPS + REP/REPE/REPNE + DF), PUSH/POP/CALL/RET, LEA/LEA_RIP/LEA_GS,
  절대주소 mem, 원자적(CMPXCHG/XCHG/XADD/LOCK INC-DEC), SSE/FPU 스칼라·변환,
  CPUID/XGETBV, native_call 브리지.
- 인터프리터(`vm/interp/`)와 네이티브 핸들러(`vm/handlers/`)가 거의 전부 동형.
  **예외: `OP_NATIVE_CALL`은 인터프리터에서 no-op** (실제 네이티브 브리지는
  생성된 핸들러가 담당 — `interp/mod.rs:157`).

### 상용 가상화 파이프라인 (risc→poly→threaded)

```text
[Source x86 Machine Code]
        ▼
[Phase 1] RISCification — 38개 마이크로-op (NOR/ADC de-synthesis 포함)
        ▼
[Phase 2] Build-Seed Polymorphic ISA — randomized opcode map, rolling-key stream
        ▼
[Phase 3] Direct Threading — tail-call direct jump, handler MBA, super-op fusion
        ▼
[Phase 4] Selective SDK Markers — BTG_VM_START / BTG_VM_END
```

- **RISC 리프터** (`vm/risc/`) — CISC → 마이크로-op 분해, 가상 플래그 모델,
  peephole 최적화(`vm/risc/opt.rs`, 현재는 주로 peephole 수준).
- **폴리모픽 ISA** (`vm/poly/`) — 빌드 시드 기반 opcode/레지스터 셔플, VIP 연동
  롤링 키. `RiscProgram::eval_state`(참조) == 폴리 인터프리터 == 네이티브
  하네스가 **선형 블록 단위로 동치** 검증됨.
- **직접 스레딩** (`vm/threaded/`) — 중앙 디스패처 루프 없이 핸들러가 다음
  핸들러로 직접 점프, self-decoding 네이티브 핸들러(`poly_direct.rs`).
  `run_native_poly_direct`가 실제 x86-64 기계어를 생성·실행 (순수 인터프리터 아님).
- **SDK** (`sdk/`) — `BTG_VM_START/END` 마커 선택 가상화.

### PE 패커 / 프로텍터

- CFG 추출 → 마이크로 슬라이싱 → 블록 셔플 → 재배치 픽스업 → 밀집 패킹 →
  섹션 합성 → 부트 스텁 설치 (`pipeline/pass1~4`, `patch_data`, `build`)
- 코드/데이터/문자열 암호화: **BTG-C1 512-bit 스트림 사이퍼**(기본, `crypto/`
  의 독자 ARX/S-box 구성 — RC4가 아니라 별도 구현. 다만 **암호학적 안전성은
  감사되지 않은 홈메이드 암호**), RC4는 `--rc4`로 복귀 가능
- chained-crypto, dispatcher per-block 재암호화(`--dispatcher-reencrypt`),
  M7 refcount-safe on-demand 재암호화(`--m7`)
- IAT 은닉/재구성(`--iat-hide`), 메모리 하드닝 W^X(`--mem-harden`),
  `--integrity`(CRC32, keyed-MAC은 **패킹 시 계산만 하고 런타임 미검증**),
  `--payload-relocate`, 리소스 등록(`--rsrc-register`), 안티디버그 부트 스텁
- `.pdata` SEH 재생성(브리지 UNWIND_INFO), `--keep-pdata` 원본 유지 옵션
- 프로그램 VM(`--vm-oep`)의 네이티브 제외 집합(`src/vm/text_lift/exclusions.rs`):
  Rust panic/unwind/Once 런타임, setjmp/longjmp 함수, SEH(catch/unwind) 함수를
  `.pdata` 함수 단위로 네이티브 유지. SEH 전체 가상화는 `BTG_SEH_NONE=1`
  (기본: `BTG_SEH_MINIMAL=1` — 최소 catch/cleanup 집합만 네이티브).
  (v56부터 LOCK 메모리 RMW는 별도 격리하지 않고 VM opcode로 처리)
- **결정적 빌드** (`--seed`): 같은 input+seed+config → 같은 출력 (SHA256 동일,
  2026-08-17 실측)

---

## 아키텍처

```text
x86-64 PE
  │
  ├── graph/          CFG 추출 / 슬라이서 / 셔플 / RIP 픽스업
  ├── pipeline/       Pass1→Pass2→Pass3→Pass4 → patch_data → crypto → build
  │                    ├── dispatcher/      static + reencrypt + m7 디스패처
  │                    ├── crypto/          BTG-C1 / RC4 / chained / bootstub / integrity
  │                    └── validate/        PE 구조·로더 호환 검증
  ├── vm/
  │    ├── risc/       RISC 마이크로-op · lifter · desynth · opt · flags
  │    ├── poly/       polymorphic ISA · rolling-key · encoder · interpreter
  │    ├── threaded/   direct tail-call · super-ops · native self-decoding handlers
  │    ├── bytecode/   opcode registry · builder
  │    ├── handlers/   native x86-64 handler codegen
  │    ├── interp/     reference interpreter
  │    ├── lifter/     legacy 1:1 lifter + IR pipeline
  │    ├── text_lift/  프로그램 CFG lift · switch · SEH/panic 제외
  │    ├── self_test/  --vm-test 스위트
  │    └── semantics.rs canonical x86 flag semantics (ground truth)
  ├── pe/             parser / multi-section builder / reloc
  ├── crypto/         BTG-C1 프리미티브 (state/key_schedule/nonlinear/round/permutation)
  ├── obfuscation/    MBA 폴리노미얼 생성 + x86-64 코드젠
  ├── sdk/            BTG_VM_START/END 마커 · selective virtualizer
  └── qa/             멀티 컴파일러 QA 벤치마크
```

자세한 실제 파이프라인: [`docs/architecture/actual-pipeline.md`](docs/architecture/actual-pipeline.md)

---

## 빌드 / 테스트

```bash
# 릴리스 빌드
cargo build --release

# 전체 단위/차등 테스트 (285개, 2026-08-17 실측 green)
cargo test --release --lib

# VM 셀프 테스트 (lifter/interpreter/native handler cross-check)
cargo run --release -- --vm-test

# 커버리지 진단 (특정 대상 PE 기준 — 보편 커버리지 보장이 아님)
cargo run --release -- --text-vm  --input <target.exe>
cargo run --release -- --text-vm-oep --input <target.exe>

# 성능 벤치마크
cargo run --release -- --vm-bench
```

QA 페이로드 빌드:

```bash
cargo build --release --manifest-path test/Cargo.toml
cargo run --release -- -t            # 멀티 컴파일러 QA 스위트
```

---

## 사용법 (CLI)

```bash
btg-packer.exe -i <input.exe> -o <packed.exe> [옵션]
```

`src/cli.rs`에 실제 정의된 옵션만 나열합니다.

| 옵션 | 설명 |
|---|---|
| `-i, --input <PATH>` | 입력 PE (기본 `dummy_target.exe`) |
| `-o, --output <PATH>` | 출력 PE (기본 `protected_btg.exe`) |
| `--seed <u64>` | 결정적 빌드 (모든 RNG 단일 시드) |
| `-l, --obf-level <N>` | 난독화 레벨 (clamp 1..=3, 기본 3) |
| `-a, --anti-debug` | 안티디버그 부트 스텁 |
| `-t, --test-qa` | QA 벤치마크 스위트 |
| `-d, --debug` | verbose 로그 |
| `-g, --log-file <PATH>` | 로그 파일 출력 |
| `--trace-blocks` | 런타임 블록 실행 트레이서 주입 |
| `--no-crypto` | 암호화 끄기 (P0-7 relocation-aware/ASLR 보존 활성 경로) |
| `--vm` | KSA/PRGA VM 가상화 |
| `--vm-test` | VM 셀프 테스트 후 종료 |
| `--text-vm` | `.text`→VM lift 커버리지 진단 |
| `--text-vm-oep` | 도달 CFG→단일 VM 프로그램 lift 진단 |
| `--payload-relocate` | 코드 페이로드를 실행 불가 `.vdata`로 이동 |
| `--rsrc-register` | 페이로드를 RT_RCDATA 리소스로 등록 (`--payload-relocate` 필요) |
| `--crypto-coverage <N>` | 코드 영역 암호화 커버리지(%) (기본 100) |
| `--chained-crypto` | 256B 청크 체이닝 RC4 + 자기파괴 |
| `--integrity` | 코드 영역 CRC32 (안티-패치) |
| `--iat-hide` | import 은닉/재구성 (TLS 콜백 대상은 하드-에러) |
| `--mem-harden` | 복호화 후 .textb RWX→RX (fail-open, 재암호화와 배타) |
| `--dispatcher-reencrypt` | 블록별 개별 암호화 + 실행 후 재암호화 |
| `--full` | 최대 보호 스택 단일 플래그 |
| `--vm-oep` | OEP→VM entry 전환 (`--vm` 필요) |
| `--vm-commercial` | 상용 엔진 백엔드 (`--vm --vm-oep` 필요) |
| `--m7` | M7 on-demand 재암호화 (anti-dump) |
| `--m8` | VM handler 테이블 MBA 난독화 |
| `--vm-bench` | VM 성능 벤치마크 |
| `--map` | VM 바이트코드 매퍼(`<output>.map`) |
| `--sym-map` | 블록 단위 심볼릭 맵(`<output>.sym`, `--map` 필요) |
| `--keep-pdata` | 원본 .pdata 바이트 유지 |
| `--block-ring` | 디스패처 ring-buffer 진단 (표준 디스패처만) |
| `--custom-cipher` | BTG-C1 (기본값) |
| `--rc4` | RC4 강제 |

대표 조합:

```bash
# 상용 프로그램 가상화 경로 (선형 블록 단위 동치로 검증)
btg-packer.exe -i test.exe -o packed.exe --vm --vm-oep --vm-commercial --seed 1234

# 최대 보호
btg-packer.exe -i test.exe -o packed.exe --full

# ASLR 보존 + relocation-aware (암호화 없는 경로만)
btg-packer.exe -i test.exe -o packed.exe --no-crypto
```

---

## 알려진 한계 (구조적)

냉정하게 현재 코드 기준으로 남아 있는 제약입니다. 상용 보호기로 쓰기엔
다음이 먼저 해소되어야 합니다.

1. **원본 `.text`가 대부분의 모드에서 평문으로 남는다.** TLS 콜백/CRT/네이티브
   브리지가 정상 동작하도록 "안전 사본"을 평문으로 유지
   (`patch_data.rs`, `pipeline/crypto/mod.rs`). "원본 코드의 평문 존재 제거"는
   **미달성** 목표입니다.
2. **VM↔네이티브 경계가 함수 단위로 원자적이지 않다.** lift 불가 블록은
   네이티브로 남는데, 함수 중간에서 VM/native 경계가 생겨 스택 프레임이 깨질 수
   있음 (P2 후속 과제 — `text_lift/commercial.rs:181-196`). panic/unwind/Once·
   setjmp/longjmp·SEH 함수는 함수 단위로 네이티브 유지해 이 경계를 완화하지만,
   그 외 unliftable 명령이 섞인 함수는 여전히 경계가 존재한다.
3. **RIP-relative 리프트는 크래시(0xC0000005, keystream desync)로 비활성(gate).**
   → "6040 블록 가상화"는 RIP-relative 포함 진단값으로, **실제 활성 경로에서는
   그보다 적음** (`docs/journal/2026-08-17-commercial-p2-risc-lift.md`).
4. **멀티스레드 재진입 취약.** 프로그램 VM state가 단일 정적 상태 — 멀티스레드
   동시 진입 시 깨질 수 있음 (`vm/interp/state.rs`).
5. **차등 검증이 "선형 블록 단위 동치"로 한정.** taken-분기(실제 제어흐름 이동)의
   VM vs native 동치는 별도 테스트로만 다루고, 전체 프로그램 동치를 보장하지 않음.
6. **플래그 의미론이 부분적.** PF/AF가 폴리 경로에서 제외되고(FLAG_MASK), RISC
   분해가 x86 per-instruction 플래그를 완전히 재현하지 못하는 경우 있음
   (`self_test/cross_path.rs:74-77`).
7. **`--mem-harden`은 fail-open**, `--dispatcher-reencrypt`와 배타.
   **`--integrity`의 keyed-MAC은 패킹 시 계산만 하고 런타임 미검증**(CRC32만 강제).
8. **`--dispatcher-reencrypt`는 실제로 "decrypt-once"** — 첫 디스패치 후 평문 유지
   (`reencrypt.rs:193-195`). 실행 후 **재암호화**는 `--m7`만 수행.
9. **SDK 마커 경로(`poly_embed`)는 데이터 임베드만 배선** — 그것을 소비하는
   롤링키 런타임은 별도 항목(T1-4)이며 실행 정합은 검증되지 않음.
   `sdk/llvm_interface.rs`는 실질 stub.
10. **BTG-C1은 홈메이드 암호** — 독자 설계(비표준 ARX/S-box)이고 암호학적 안전성
    감사/표준화는 안 됨.
11. **플래그셋/다중 백엔드로 인한 의미론 divergence 위험** — 같은 의미론을 여러
    곳(interp/handlers/risc/poly/semantics)에서 재구현.
12. 소스에 `unwrap()` 약 3000회 — PE 입력 검증 계층과 컴파일러 내부 불변식이
    섞여 있어 악성 입력에 크래시할 수 있음.

> "커버리지 100% (26,956/26,956)"·"6040 블록 가상화"는 **진단 도구(`--text-vm` /
> `--text-vm-oep` / P2-RISC-GAP)가 특정 테스트 대상 1개(`test/target/debug/
> rust_packer_test.exe`)에 대해 출력한 측정값**입니다. 이는 리프터가 *해당
> 바이너리*에서 처리한 명령/블록 비율을 뜻하며, 임의의 PE에 대한 커버리지 보장
> 또는 "상용 제품 수준 완성도"를 의미하지 않습니다.

---

## 검증 상태

**실제 실행으로 확인한 것 (2026-08-17):**
- `cargo build --release` → 성공
- `cargo test --release --lib` → **285 passed; 0 failed**
- `--seed` 결정적 빌드 → 동일 seed 2회 패킹 SHA256 동일

**문서/자체 개발 기록에만 존재 (커밋 산출물로 재현 안 됨):**
- "FINAL CHECKSUM `0x2cdc0e4511d84a64` baseline 무회귀" — 개발 메모(`docs/`)와
  테스트 하네스 소스(`test/src/main.rs:269`)에만 기록. 자동화 게이트가 아님.

---

## 문서

| 문서 | 내용 |
|---|---|
| [`docs/README.md`](docs/README.md) | 전체 문서 인덱스 |
| [`docs/architecture/actual-pipeline.md`](docs/architecture/actual-pipeline.md) | **실제 패킹 파이프라인 (냉정 기술)** |
| [`docs/architecture/vm-compiler-architecture.md`](docs/architecture/vm-compiler-architecture.md) | 모듈 지도, 컴파일러 프론트엔드 |
| [`docs/architecture/commercial-vm-engine.md`](docs/architecture/commercial-vm-engine.md) | 상용 가상화 엔진 설계 |
| [`docs/architecture/coverage.md`](docs/architecture/coverage.md) | 명령 커버리지 베이스라인 (진단 수치) |
| [`docs/roadmap/`](docs/roadmap/) | 로드맵 / 현황 |
| [`docs/engine/`](docs/engine/) | 기능 구현·검증 리포트 |
| [`docs/vault/`](docs/vault/) | btg_vault 챌린지 |
| [`docs/journal/`](docs/journal/) | 일일 작업 기록 |

---

## 라이선스

연구/보안 교육 목적. BTG Security Research Team.
