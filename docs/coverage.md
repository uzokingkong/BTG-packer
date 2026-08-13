# 명령 커버리지 베이스라인

> 업데이트: 2026-08-13 (v13.5). 이 문서는 "완전한 VM 컴파일러"의 명령
> 커버리지 측정 기준을 기록한다. 실측 커버리지 숫자는 `--text-vm` /
> `--text-vm-oep` 진단이 특정 타깃에 대해 출력하는 값으로 갱신한다.

## 1. 커버리지를 어떻게 측정하나

- `analyze_text_lift` (src/vm/text_lift.rs) — 원본 `.text`를 기본 블록으로
  디코드해, 각 블록의 모든 명령이 `lift_one`/`lift_block`으로 lift 가능한지
  리포트한다. `diagnose_unsupported`가 lift 불가 명령을 `(mnemonic, Code)`로
  나열한다.
- `TextLiftReport::coverage()` = liftable / total instructions.
- CLI: `--text-vm`(커버리지 리포트), `--text-vm-oep`(프로그램 CFG lift 커버리지).
- `ProgramLift::coverage()` = (total - unsupported) / total.

## 2. VM ISA — 지원되는 opcode (v54)

`src/vm/bytecode/registry.rs`의 `opcodes!` 레지스트리(현재 **171 opcode**,
0x01..0xAB)가 단일 진실 공급원. `--vm-test` [30] P2-10이 레지스트리/핸들러/
인터프리터 sync를 검증한다.

### 지원 그룹
- **이동**: MOV r,imm32/imm64/r·r, MOVZX/SX(8/16/32), MOV(64), 메모리 폭별.
- **산술/논리**: ADD/SUB/IMUL/AND/OR/XOR(32/64), INC/DEC, NEG/NOT, CMP/TEST.
- **시프트/회전**: SHL/SHR/SAR(32/64, imm/CL), ROL/ROR.
- **1-op 곱셈/나눗셈**: MUL/IMUL/DIV/IDIV(8/16/32/64, RAX:RDX 누산기), BSWAP.
- **비트**: BSR/BSF(32/64), TZCNT, SETcc, TEST.
- **BMI1/2 (v52)**: LZCNT/POPCNT/BLSR/BLSMSK/BLSI/ANDN (32/64) — v54 self-test [37].
- **문자열 ops (v52)**: MOVS/STOS/LODS/SCAS/CMPS 모든 폭, REP/REPE/REPNE —
  명시적 VM 루프로 lowering(카운트 소모/포인터 전진/종료 플래그 x86-exact) —
  self-test [36].
- **CMOVcc (v49)**: 16개 조건 패밀리, JCC+MOV lowering — self-test [35].
- **스택/호출**: PUSH/POP, CALL8/32, RET/RET_IMM16(두-스택 모델), JMP/Jcc(rel8/32).
- **어드레싱**: LEA(disp/idx/scale), LEA_RIP, LEA_GS(PEB/TEB), 절대주소 mem.
- **원자적**: CMPXCHG(8/16/32/64), XCHG(8/16/32/64), XADD(8/16/32/64),
  LOCK INC/DEC(8/16/32/64, v55) — Rust `Once`/refcount/teardown용.
- **SSE 이동/shuffle**: MOVSD/MOVUPS/XORPS(=PXOR)/UNPCKLPD/UNPCKLPS/
  PSHUFLW/HW/D/PSRLQ/PSLLQ/PINSRW.
- **SSE/FPU 산술·변환 (v54)**: ADDSS/ADDSD/SUBSS/SUBSD/MULSS/MULSD/
  DIVSS/DIVSD, PAND/POR/PANDN, CVTSI2SD/CVTSI2SS, CVTSS2SD/CVTSD2SS,
  CVTTSS2SI/CVTTSD2SI(절삭)/CVTSS2SI/CVTSD2SI(짝수 반올림), PEXTRD/PINSRD —
  self-test [38].
- **기타**: CPUID, XGETBV, NOP, native_call 브리지, HALT.

## 3. 실측 고정 (2026-08-13, v55)

`--text-vm --input test/target/debug/rust_packer_test.exe`:
- 기본 블록 6,738 / 총 명령 26,956 / **lift 가능 26,956 (100.00%) / lift 불가 0**.
- lift 바이트코드 45,109 bytes.

이전 잔여 15개(전부 해소됨):
- `lock dec rm64 ×12`, `lock inc rm32 ×2`, `lock inc rm64 ×1`
  → OP_LOCK_INC/DEC_MEM8/16/32/64_A (v55, self-test [39]).
- `xor rax, imm32` (`Xor_RAX_imm32 ×1`)
  → `lift_arith_imm` 라우팅 누락분 보완 (`Add/Or/And/Xor/Sub_RAX_imm32`).

### 알려진 미지원 잔여 (구조적)
- **SSE/FPU 잔여**: SQRT, MIN/MAX, CMPSS/COMISS, PMIN/PMAX/PMULLW 등
  lift 표만 있는 패킹드 연산 다수 — 실측 타깃에서는 미출현.
- **x87 FPU 스택 명령** (FLD/FSTP/FADD/…/FNSTSW) — VM은 x87 스택 미모델
  (SSE 스칼라 경로만 커버; 실측 타깃 미출현).

### 명시적 제외 — 시스템/특권 명령 (가상화 불가, 설계상 제외)
- **특권/시스템 콜**: `SYSCALL`/`SYSENTER`/`SYSRET`, `SYSRET`, `IRET*`,
  `HLT`, `STI`/`CLI`, `LGDT`/`LIDT`/`LLDT`/`LTR`, `MOV CRn/DRn`,
  `INVD`/`WBINVD`/`INVLPG`, `RDMSR`/`WRMSR`, `RDTSC`/`RDPMC`, `XSETBV`,
  `IN`/`OUT` — 사용자 모드 앱의 .text에는 출현하지 않으며, 출현 시
  `diagnose_unsupported`가 명시적으로 보고한다.
- **`INT n` / `INT3`**: 부트·외부 호출 경계로 `HALT` 취급 (특권 제외와 무관).
- **DF=1(하향) 문자열 연산**: DF 클리어(순방향) 가정 — `STD` 출현 코드는
  미지원(문서화된 한계).
- 참고: `CPUID`/`XGETBV`는 VM opcode로 **지원**(0x79/0x7A).

### 네이티브 제외 (프로그램 VM에서 평문으로 남는 블록 — Phase 2.2 대상)
- Rust panic/unwind/Once 런타임 함수 (`detect_panic_unwind_ranges`).
- `lock` 원자적 메모리 RMW 블록 (`block_has_lock_atomic_on_global` /
  `block_has_lock_memory_rmw`) — VM에 원자 opcode가 있으나 함수 경계 보존 위해
  네이티브 유지.
- 이들은 OEP→VM 진입 시 native-call 브리지로 실행된다.

## 4. 목표

- Phase 2.1: 지원 명령 그룹을 실제 리프터/핸들러/인터프리터/테스트 한 벌로
  추가해 `--text-vm` 커버리지를 100%로(시스템 명령 제외).
- Phase 2.2: 네이티브 제외 블록을 0으로 → 프로그램 본문 100% VM.
- 각 그룹 추가 후 `--vm-test`(새 self-test 포함) + `--text-vm` 커버리지 상승을
  기록.
