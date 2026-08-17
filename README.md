# BTG Packer (vm-obf)

**Bidirectional Trigger Graph (BTG) — x86-64 Binary Virtualization / Protection / Obfuscation Packer**

Rust로 구현된 상용급(VMProtect/Themida급 지향) VM 컴파일러 겸 PE 패커입니다.
원본 `.text`를 평문으로 존재시키지 않고, CISC x86을 RISC 마이크로 연산자로 분해한 뒤
빌드별 다형성 ISA(Polymorphic ISA) + 롤링 키 스트림 암호로 **전체 프로그램을
가상화**합니다.

> 크레이트: `btg-packer` v1.0.0 · Rust edition 2021 · Windows x64 대상

---

## 목차

- [구현된 것](#구현된-것)
- [아키텍처](#아키텍처)
- [빌드 / 테스트](#빌드--테스트)
- [사용법 (CLI)](#사용법-cli)
- [검증 게이트](#검증-게이트)
- [상용화 진행 (P0~P3)](#상용화-진행-p0p3)
- [문서](#문서)

---

## 구현된 것

### 두 개의 병렬 VM 엔진

| | 레거시 VM 코어 | 상용 엔진 (Commercial-grade) |
|---|---|---|
| 모듈 | `vm/bytecode`, `vm/handlers`, `vm/lifter`, `vm/interp`, `vm/text_lift` | `vm/risc/`, `vm/poly/`, `vm/threaded/`, `sdk/`, `pipeline/selective_vm.rs`, `pipeline/poly_embed.rs` |
| 방식 | 1:1 CISC → VM 바이트코드 | RISC De-synthesis(12 micro-op) → 폴리모픽 ISA → 다이렉트 스레딩 |
| 명령 커버리지 | **100%** (실측 26,956/26,956) | mov/lea/shift/arith/cmp/call/jcc/mem + 8/16-bit 정밀화 (6040블록 가상화) |
| 역할 | `--vm-oep` 프로그램 전체 가상화 | `--vm-commercial` 전체 프로그램 가상화 (risc→poly→threaded) |

### 상용 가상화 파이프라인 (Phase 1~4)

```text
[Source x86 Machine Code]
          │
          ▼
[Phase 1] Micro-IR & RISCification — 12 primitive micro-ops (NOR/ADC de-synthesis)
          │
          ▼
[Phase 2] Build-Seed Polymorphic ISA — randomized opcode map, register permutation,
          non-linear rolling-key stream cipher
          │
          ▼
[Phase 3] Direct Threading & Super-Operators — tail-call direct jump, handler MBA,
          super-op fusion
          │
          ▼
[Phase 4] Selective SDK Markers — BTG_VM_START / BTG_VM_END (C/C++/Rust), native
          dispatch trampoline, .btgvm embedding
```

- **RISC 리프터** (`vm/risc/`) — CISC → NOR/ADC 분해, 가상 플래그 모델, peephole 최적화.
  최근(2026-08-17) 8/16-bit CMP/TEST/ADD/SUB(부분-쓰기 상위 비트 보존), NOP/Pause,
  간접 JMP, 폭별 ALU 네이티브 핸들러 추가로 **가상화 4513→6040 블록(+34%),
  RISC-unliftable 3210→1683(-48%)**.
- **폴리모픽 ISA** (`vm/poly/`) — 빌드 시드 기반 opcode/레지스터 셔플, VIP 연동
  롤링 키. `RiscProgram::eval_state` 참조와 인터프리터/네이티브가 **완전 상태 동치**.
- **직접 스레딩** (`vm/threaded/`) — 중앙 디스패처 루프 없이 각 핸들러가 다음
  핸들러로 직접 점프, super-op 합성, self-decoding 네이티브 핸들러.
- **SDK** (`sdk/`) — `BTG_VM_START/END` 마커 선택 가상화, LLVM IR 인터페이스.

### 레거시 VM (171+ opcode, 명령 커버리지 100%)

- opcode 단일 진실 공급원: `vm/bytecode/registry.rs`의 `opcodes!` 매크로
- 16 GPR + XMM + 6비트 RFLAGS + DF(방향 플래그) 모델, 두-스택(CALL/RET) 모델
- 그룹별 지원: MOV/MOVZX/MOVSX, ADD/SUB/IMUL/AND/OR/XOR/INC/DEC/NEG/NOT/CMP/TEST,
  SHL/SHR/SAR/ROL/ROR, **MUL/IMUL/DIV/IDIV(8/16/32/64)**·BSWAP, BSR/BSF/TZCNT/LZCNT/
  POPCNT, **BMI1/2**(BLSR/BLSMSK/BLSI/ANDN), SETcc, CMOVcc, **문자열 ops**
  (MOVS/STOS/LODS/SCAS/CMPS + REP/REPE/REPNE + DF), PUSH/POP/CALL/RET, LEA/LEA_RIP/
  LEA_GS, 절대주소 mem, **원자적**(CMPXCHG/XCHG/XADD/LOCK INC-DEC), SSE/FPU 스칼라·
  변환, CPUID/XGETBV, native_call 브리지.

### PE 패커 / 프로텍터

- CFG 추출 → 마이크로 슬라이싱 → 블록 셔플 → 재배치 픽스업 → 밀집 패킹 → 섹션
  합성 → 부트 스텁 설치
- 코드/데이터/문자열 런 암호화: **BTG-C1 512-bit 스트림 사이퍼**(기본, RC4는
  `--rc4`로만), chained-crypto, dispatcher per-block 재암호화(`--dispatcher-reencrypt`),
  M7 refcount-safe on-demand 재암호화
- IAT 은닉/재구성, 메모리 하드닝(W^X, `--mem-harden`), `--integrity` CRC + keyed-MAC,
  `--payload-relocate`, 리소스 등록, 안티디버그 부트 스텁
- `.pdata` SEH 재생성(브리지 UNWIND_INFO), TLS-first-callback at-rest 복호화,
  `--keep-pdata` 원본 유지 옵션
- **결정적 빌드** (`--seed`): 같은 input+seed+config → 같은 출력 (SHA256 동일)

### P0 상용화 수정 (2026-08-17, 리뷰 반영)

| 항목 | 내용 |
|---|---|
| **P0-1 VM/native 경계 원자성** | 상용 리프트의 직접 분기가 제외 함수 범위 안에 있으면 **함수 진입(프롤로그) 주소로 리다이렉트** — 네이티브 브리지가 함수 중간(에필로그)이 아니라 처음부터 실행 |
| **P0-5 MUL/IMUL CF/OF** | legacy VM이 flagless로 취급하던 MUL/IMUL이 x86 upper-half overflow CF/OF를 interp/native/RISC 전 경로에서 정확히 설정 (`semantics.rs` flag_contract + 차등 fuzz) |
| **P0-7 ASLR 보존** | relocation-aware 출력 — 정식 `.reloc` DIR64 디렉터리를 생성해 DYNAMIC_BASE / HIGH_ENTROPY_VA 보존. `--no-crypto` 경로는 **cdb로 실제 리베이스(0x140000000→0x7ff6...) 확인**. at-rest 암호화 경로는 게이트로 비활성화 |

---

## 아키텍처

```text
x86-64 PE
  │
  ├── graph/          CFG 추출 / 슬라이서 / 셔플 / RIP 픽스업
  ├── pipeline/       Pass1→Pass2→Pass3→Pass4 → patch_data → crypto → build
  │                    ├── dispatcher/      static + reencrypt + m7 디스패처
  │                    ├── crypto/          BTG-C1 / RC4 / chained / bootstub / integrity
  │                    └── validate/        PE 구조·로더 호환 전수 검증
  ├── vm/
  │    ├── risc/       RISC micro-op · lifter · desynth · opt · flags
  │    ├── poly/       polymorphic ISA · rolling-key · encoder · interpreter
  │    ├── threaded/   direct tail-call · super-ops · native self-decoding handlers
  │    ├── bytecode/   opcode registry · builder(rel8→rel32 widening)
  │    ├── handlers/   native x86-64 handler codegen (threaded dispatch)
  │    ├── interp/     reference interpreter (interp == native 차등)
  │    ├── lifter/     legacy 1:1 lifter + IR pipeline
  │    ├── text_lift/  프로그램 CFG lift · switch · SEH/panic 제외
  │    ├── self_test/  --vm-test 스위트
  │    └── semantics.rs canonical x86 flag semantics (ground truth)
  ├── pe/             parser / multi-section builder / **reloc.rs (P0-7)**
  ├── crypto/         BTG-C1 프리미티브 (state/key_schedule/nonlinear/round/permutation)
  ├── obfuscation/    MBA 폴리노미얼 생성 + x86-64 코드젠
  ├── sdk/            BTG_VM_START/END 마커 · selective virtualizer
  └── qa/             멀티 컴파일러 QA 벤치마크
```

핵심 설계 문서: [`docs/architecture/vm-compiler-architecture.md`](docs/architecture/vm-compiler-architecture.md) ·
[`docs/architecture/commercial-vm-engine.md`](docs/architecture/commercial-vm-engine.md) ·
[`docs/README.md`](docs/README.md) (전체 문서 인덱스)

---

## 빌드 / 테스트

```bash
# 릴리스 빌드
cargo build --release

# 전체 단위/차등 테스트 (285개)
cargo test --release --lib

# VM 셀프 테스트 (lifter/interpreter/native handler cross-check)
cargo run --release -- --vm-test

# 커버리지 진단
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

| 옵션 | 설명 |
|---|---|
| `-l, --obf-level <N>` | 난독화 레벨 0~3 |
| `-a, --anti-debug` | 안티디버그 부트 스텁 |
| `--seed <u64>` | 결정적 빌드 (모든 RNG 단일 시드) |
| `--no-crypto` | 암호화 끄기 (P0-7 relocation-aware/ASLR 보존 활성 경로) |
| `--vm` | KSA/PRGA VM 가상화 |
| `--vm-oep` | 프로그램 전체 → 프로그램 VM (`--vm` 필요) |
| `--vm-commercial` | 상용 엔진 백엔드 (risc→poly→threaded, `--vm --vm-oep` 필요) |
| `--dispatcher-reencrypt` | 블록별 개별 암호화 + 실행 후 재암호화 |
| `--m7` | M7 on-demand 재암호화 (anti-dump, refcount-safe) |
| `--m8` | VM handler 테이블 MBA 난독화 |
| `--full` | 최대 보호 스택 단일 플래그 |
| `--chained-crypto` | 256B 청크 체이닝 암호화 |
| `--integrity` | 코드 영역 CRC32 + keyed-MAC |
| `--custom-cipher` | BTG-C1 (기본값) |
| `--rc4` | RC4 강제 (레거시) |
| `--iat-hide` | import 은닉/재구성 |
| `--mem-harden` | 복호화 후 .textb RWX→RX |
| `--payload-relocate` | 코드 페이로드 .vdata 이동 |
| `--rsrc-register` | 리소스 디렉터리 재구성 |
| `--keep-pdata` | 원본 .pdata 바이트 유지 |
| `--map / --sym-map` | VM 바이트코드 매퍼 덤프 |
| `-t, --test-qa` | QA 벤치마크 |
| `--vm-test` | VM 셀프 테스트 |

대표 조합:

```bash
# 상용 프로그램 가상화 (권장 검증 경로)
btg-packer.exe -i test.exe -o packed.exe --vm --vm-oep --vm-commercial --seed 1234

# 최대 보호
btg-packer.exe -i test.exe -o packed.exe --full

# ASLR 보존 + relocation-aware
btg-packer.exe -i test.exe -o packed.exe --no-crypto
```

---

## 검증 게이트

모든 패킹 경로는 이 게이트를 통과해야 합니다:

- `cargo build --release` green
- `cargo test --release --lib` → **285 passed; 0 failed**
- `--vm-test` ALL PASS
- pack→run 16-test + **FINAL CHECKSUM `0x2cdc0e4511d84a64`** baseline 무회귀
  (`--vm` / `--vm-oep` / `--vm-commercial` / `--no-crypto` / `--dispatcher-reencrypt`)
- P0-7: cdb로 ASLR 리베이스 후에도 checksum 정상 확인

---

## 상용화 진행 (P0~P3)

상세 로드맵: [`docs/roadmap/commercial-readiness-plan.md`](docs/roadmap/commercial-readiness-plan.md) ·
[`docs/roadmap/COMMERCIAL-VM-UPGRADE-PLAN.md`](docs/roadmap/COMMERCIAL-VM-UPGRADE-PLAN.md) ·
[`docs/roadmap/milestones.md`](docs/roadmap/milestones.md)

- **P0-1** canonical semantics 단일화 · **P0-2** Win64 ABI 검증기 · **P0-4** PE 구조
  전수 검증 · **P0-5** MUL/IMUL CF/OF · **P0-7** ASLR 보존 → 완료
- **P1-1** unwrap 제거 · **P1-2** W^X · **P1-3** exception safety · **P1-4** 스레드
  안전 · **P3-1** 결정적 seed → 완료
- **P2** RISC 리프터 커버리지 → 진행 중 (가상화 6040블록, RIP-relative 게이트)
- 재암호화/m7 at-rest 암호화 경로의 런타임 post-decrypt relocation → 후속 P0-7 확장

---

## 문서

| 문서 | 내용 |
|---|---|
| [`docs/README.md`](docs/README.md) | 전체 문서 인덱스 (카테고리별) |
| [`docs/architecture/vm-compiler-architecture.md`](docs/architecture/vm-compiler-architecture.md) | 모듈 지도, 컴파일러 프론트엔드/부트 정합 |
| [`docs/architecture/commercial-vm-engine.md`](docs/architecture/commercial-vm-engine.md) | Phase 1~4 상용 가상화 엔진 심층 설계 |
| [`docs/architecture/coverage.md`](docs/architecture/coverage.md) | 명령 커버리지 베이스라인 |
| [`docs/roadmap/COMMERCIAL-VM-UPGRADE-PLAN.md`](docs/roadmap/COMMERCIAL-VM-UPGRADE-PLAN.md) | 상용화 마스터플랜 (갭 분석) |
| [`docs/roadmap/commercial-readiness-plan.md`](docs/roadmap/commercial-readiness-plan.md) | P0~P3 실행 로드맵 (상태 마커) |
| [`docs/roadmap/milestones.md`](docs/roadmap/milestones.md) | 마일스톤 체크리스트 |
| [`docs/engine/P3-handlers-wired-and-verified.md`](docs/engine/P3-handlers-wired-and-verified.md) | 상용 self-decoding 핸들러 검증 |
| [`docs/engine/T1-2-RISC-Lifter-Coverage-DONE.md`](docs/engine/T1-2-RISC-Lifter-Coverage-DONE.md) | RISC 리프터 커버리지 |
| [`docs/engine/T1-4-Native-SelfDecoding-Dispatcher-DONE.md`](docs/engine/T1-4-Native-SelfDecoding-Dispatcher-DONE.md) | 네이티브 self-decoding 디스패처 |
| [`docs/journal/`](docs/journal/) | 일일 작업 기록 |

---

## 라이선스

연구/보안 교육 목적. BTG Security Research Team.