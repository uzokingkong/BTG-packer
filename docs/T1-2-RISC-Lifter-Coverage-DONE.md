# T1-2 완료 보고 — RISC 리프터 커버리지 확장 (call / full Jcc / CMP / 메모리 피연산자 / 시프트)

> 작업일: 2026-08-14 · 대상: `vm-obf` repo on node `ujiwo-zyris-code` (Windows)
> 대상 브랜치: `main` (이전 HEAD `4a6dffd`) · 상태: **완료** — 전체 `cargo test --release` green
> 코드 커밋: `87703a0` (`feat(vm/risc): T1-2 extend RISC lifter coverage …`)

## 1. 요약

`src/vm/risc/lifter.rs`의 상용 RISC 리프터가 미처 다루지 못하던 x86 부분집합을 확장했다.
핵심 마이크로 연산 어휘(`src/vm/risc/opcodes.rs`)는 신규 op 추가 없이 **기존 12개 op로만**
구현했다. 동시에 참조 시뮬레이터 `RiscProgram::eval_state`(`src/vm/risc/mod.rs`)가
`VirtualBranch`와 `MemoryRead`/`MemoryWrite`를 실제로 시뮬레이션하도록 완성해, 리프트된
코드를 참조 시뮬레이터에서 실행·차등 검증할 수 있게 했다.

## 2. 구현 (A–F)

- **A. CALL** — `Call_rel32_64`: `VirtualPush(next_ip)` 후 `VirtualBranch{Always, target}`.
  `Call_rm64`/`Call_rm32`(간접, 레지스터·메모리): 복귀 주소 push 후 `VirtualBranch{Always}`의
  `src1`에 동적 타깃을 담아 간접 분기.
- **B. 전체 Jcc** — `Je→Zero, Jne→NotZero, Jg→Greater, Jl→Less, Jge→GreaterOrEqual,
  Jle→LessOrEqual, Ja/Jae→NotCarry, Jb/Jbe→Carry, Js→Sign, Jns→NotSign,
  Jo→Overflow, Jno→NotOverflow` (rel8_64 + rel32_64 전부). 각 조건은 `eval_state`의
  `branch_taken`이 VFLAG 비트(CF/ZF/SF/OF)로 평가.
- **C. CMP** — `Cmp_*`(r64/r32, rm↔r, imm8/imm32, RAX/EAX 누산기 형태) → 스크래치
  `Temp(7)`에 `emit_sub`하여 결과는 버리고 `AddWithCarry`의 CF/ZF/SF/OF 갱신만 활용.
- **D. 메모리 피연산자 산술** — `Add/Sub/Xor/And/Or`의 `rm`/`r/m` 즉시 전 계열에서
  `lower_effective_address` + `MemoryRead{width}` → 연산 → (dest가 메모리면) `MemoryWrite{width}`
  read-modify-write. 기존 레지스터 전용 처리도 동일 경로로 통합.
- **E. 시프트** — `Shl_*`→`ShiftLeft`, `Shr_*`→`ShiftRight` (32/64-bit, count imm8 / 1 / CL).
- **F. MOVZX** — 8/16-bit 소스 → 0-확장(AND 마스크). iced 1.21은 `Movzx_r64_rm32`가 없고
  (32→64는 보통 mov가 이미 확장) 8/16 소스 형태만 존재하므로 그 형태를 모두 처리.
- **부가**: `LEAVE`(mov rsp,rbp; pop rbp) → `push rbp; mov rbp,rsp … leave; ret` 프로/에필로그 패턴이
  Push/Pop/Mov/Leave로 정확히 lift됨을 검증.

## 3. 참조 시뮬레이터 완성 (`eval_state`)

- `RiscEvalState`에 `mem: HashMap<u64,u8>`(바이트 단위 메모리 모델) 추가.
- 실행을 선형 `for`에서 **VIP 기반 while 루프**로 전환.
- `VirtualBranch{cond}`: `branch_taken`으로 조건 평가 후, 타깃을 `src1`(동적) 또는 `imm`(절대 IP)로
  결정하고, `RiscProgram`의 선택적 `ip_map`(소스 IP→인덱스)으로 실제 분기 인덱스로 변환해 실행.
- `MemoryRead{width}`/`MemoryWrite{width}` 리틀엔디언 구현. `eval_state_with_mem`로 초기 메모리 주입 가능.
- `PolymorphicInterpreter`(폴리모픽 바이트코드 해석기)와는 기존 지원 op(Nor/Add/Shift/Push/Pop/Halt)에
  대해 동일 의미를 유지. 폴리 엔코더가 메모리·분기 op를 표현하지 않으므로 해당 op의 차등 테스트는
  `eval_state` 참조로만 수행(추후 폴리 계층 확장 과제로 남김).
  → **P1(2026-08-15)에서 해소**: 폴리 인코더/인터프리터가 `ArithmeticShiftRight`, `VirtualBranch`,
  `MemoryRead/Write{1,2,4,8}`, `NativeCallBridge`를 인코딩·실행하며 `PolymorphicInterpreter` ==
  `eval_state` **완전 상태 동치**(regs/temps/flags/vsp/stack/mem) 차등 테스트(≥3 seeds)가 green.
  상세: `docs/COMMERCIAL-VM-UPGRADE-PLAN.md` §P1, `docs/milestones.md` Phase 5, `docs/journal/2026-08-15.md`.

## 4. 검증

- `cargo build --release` 성공.
- `cargo test --release` 전체 → **136 passed; 0 failed** (기존 126 + 신규 10).
- 신규 단위/차등 테스트 (`src/vm/risc/lifter.rs`, `src/vm/risc/mod.rs`):
  1. CALL→RET 왕복(복귀 주소 push + callee 분기) — `test_lift_call_ret_roundtrip`
  2. 간접 CALL(레지스터) — `test_lift_call_indirect_register`
  3. JE taken / JE not-taken / JNE taken — `test_lift_jcc_je_jne`
  4. CMP→JG signed taken / not-taken — `test_lift_cmp_then_jg`
  5. 메모리 피연산자 산술(read-modify-write + reg←mem) — `test_lift_memory_operand_arith`
  6. SHL/SHR 시프트 — `test_lift_shifts`
  7. MOVZX 0-확장 — `test_lift_movzx`
  8. 프로/에필로그(LEAVE) — `test_lift_prologue_epilogue_leave`
  9. `eval_state` 메모리 R/W — `test_eval_state_memory_read_write`
  10. `eval_state` 가상 분기 taken — `test_eval_state_virtual_branch_taken_and_not`

## 5. 변경 파일

- `src/vm/risc/lifter.rs` (+583/−81) — CALL, Jcc, CMP, 메모리 산술, 시프트, MOVZX, LEAVE, 테스트
- `src/vm/risc/mod.rs` (+164) — `RiscEvalState.mem`, `RiscProgram.ip_map`/`with_ip_map`,
  `eval_state` VIP/분기/메모리 실행, `branch_taken`/`mem_read`/`mem_write`, 테스트
- (커밋 범위: 위 2개 소스 파일만. boot-stub·패킹 파이프라인·crypto·native threaded harness 비접촉.)

## 6. 미지원 → 후속 확장 완료 (2026-08-14 저녁, 이어지는 작업)

아래 항목들은 이 문서의 초기 버전에서 "미지원(의도적 제외)"이었다. 이후 자동 Job에서
**모두 구현·검증**(전체 테스트 141 passed)했다.

- **SAR(산술 우측 시프트)** ✅: `RiscOp::ArithmeticShiftRight` op 추가. `eval_state`에서
  `(a as i64) >> cnt`(부호 비트 유지)로 구현하고, 리프터가 `Sar_rm*/imm8·1·CL` 전 계열을 매핑.
- **MOVSX(부호 확장)** ✅: `ArithmeticShiftRight`를 이용해 `(src << (64-w)) >> (64-w)`로
  부호 비트를 복제(8/16/32-bit 소스, `Movsx_*`·`Movsxd_*`). MOVZX와 대칭.
- **Jp/Jnp(패리티)** ✅: `VirtualFlags`가 `update_logic64`/`update_add64`에서 PF(bit 2, low byte
  짝수 패리티)를 계산하도록 확장하고 `BranchCondition::Parity/NotParity` 추가. 네이티브 하네스의
  `FLAG_MASK`도 PF를 포함하도록 동기화(참조↔네이티브 차등 유지).
- **Jcxz/Jecxz/Jrcxz(카운터 분기)** ✅: `BranchCondition::CounterZero(width)` 추가 —
  `regs[1]`(RCX) 하위 2/4/8 바이트가 0이면 분기. `eval_state`가 레지스터 상태로 평가.
- **Ja/Jae/Jb/Jbe(부호없는 above/below, 정밀)** ✅: 단순 `NotCarry`/`Carry` 근사를
  `Above`(CF=0∧ZF=0), `AboveOrEqual`(CF=0), `Below`(CF=1), `BelowOrEqual`(CF=1∨ZF=1)로
  정밀 분리해 Ja≠Jae, Jb≠Jbe 경계를 올바르게 구분.

### 남은 모델 한계 (의도적 유지)
- **32-bit 레지스터 쓰기 시 상위 32비트 0-확장** 및 32-bit 시프트 카운트 31 마스크: ✅ **해결됨 (2026-08-15)**.
  `src/vm/risc/lifter.rs`가 32비트 목적지(EAX..R15D)를 쓰는 모든 연산(산술/논리/NEG/NOT/이동/시프트/MOVSX)
  결과를 `AND dst, 0xFFFFFFFF`로 0-확장하고, 32비트(`rm32`) 시프트는 시프트 횟수를 mod 32(31 마스크)로
  제한한다(즉시는 리프트 시점, CL 레지스터는 Temp(2)에서 마스크). 64비트 의미론이 남던 두 모델 한계 중
  하나를 제거. 상세: `docs/journal/2026-08-15.md`.
- **RET**: 기존대로 `Halt`로 리프트(실제 복귀 분기/스택 복원은 런타임 네이티브 브리지 책임).
  CALL→RET 왕복 테스트는 push된 복귀 주소가 스택에 남음을 검증.

## 7. 후속 커밋

```
<COMMIT_HASH_PLACEHOLDER> feat(vm/risc): T1-2 remainder — SAR, MOVSX, JP/JNP, Jcxz/Jecxz, precise unsigned Jcc
```
- 변경 파일: `src/vm/risc/opcodes.rs`, `src/vm/risc/flags.rs`, `src/vm/risc/mod.rs`,
  `src/vm/risc/lifter.rs`, `src/vm/threaded/harness.rs`(PF 동기화), `docs/T1-2-RISC-Lifter-Coverage-DONE.md`.

### 후속 — P1 폴리 계층 완성 (2026-08-15, §3 과제 해소)
- `vm/poly/isa_spec.rs`·`encoder.rs`·`interpreter.rs`가 메모리/분기/SAR/NativeCallBridge op를
  인코딩·실행 → `PolymorphicInterpreter` == `RiscProgram::eval_state` 차등 검증 (≥3 seeds).
- 커밋: `2a3d6c8`, `ece32c9`, `20af238` (feature branch `commercial/p1-poly-complete`).
