# 네이티브 threaded harness VirtualBranch 크래시 (0xC0000005) 수정 보고서

> 대상: `asdfsadfecwecc` (BTG Packer) · node `ujiwo-zyris-code` (Windows)
> 파일: `src/vm/threaded/harness.rs` · 수정일: 2026-08-15
> 트리거: `cargo test --release --lib vm::threaded::harness::tests::temp_static_branch_only`

---

## 1. 증상

TEMP 고립 정적 분기 테스트가 `STATUS_ACCESS_VIOLATION (0xc0000005)` 로 즉사.

cdb 폴트 지점:
```
movzx eax, byte ptr [r12]   ; ds:0x4 = ??
```
→ R12(가상 VIP)가 `4`(raw 인덱스)로 세팅되어 bytecode 배열이 아니라 주소 4 근처를 읽음.

---

## 2. 원인 (두 겹)

### 원인 1 — 분기 점프가 VIP(R12)를 raw 인덱스로 설정 (off-by-base)

`emit_branch_jump`가 `mov r12, rax`로 **raw 블록 인덱스**를 VIP에 기록.

- tail-dispatch(`emit_tail_dispatch`)는 `movzx eax, [r12]` 로 R12를 **bytecode 배열 절대 포인터**로 읽는다.
  (엔트리에서 `R12 = bytecode_base`, 이후 매 디스패치 `inc r12` → 선형 경로는 `bytecode_base + i`.)
- 그런데 분기 경로만 `R12 = i`(raw) → 분기 타깃 블록의 디스패치가 주소 `i`(예: 4)를 읽어 AV.

**수정**: `emit_block`에 `bytecode_base` 파라미터 추가 →
`mov r12, imm64(bytecode_base); add r12, rax` (VIP = bytecode_base + (타깃+1)).

### 원인 2 — 동적 분기 helper `call rel32` 블록의 길이 측정 불일치 (table off-by-9)

원인 1을 고치자 정적/동적 결합 테스트(`test_native_branch_static_and_dynamic_matches_reference`)가 여전히 AV.

cdb 레지스터: `rcx=3`(타깃 인덱스 정확), `r12=bytecode_base+4`(정확),
`rax=0x…11f0` = `jmp rax` 타깃인데 실제 블록3 시작은 `0x…11e7` → **블록 중간(imm 바이트)으로 점프**.

원인:
- `compile()`이 블록 길이를 `assemble(lst, 0)` (**base 0**) 로 측정.
- 동적 분기 블록은 `Call_rel32_64`(타깃 = helper 절대 VA ≈ `arena.base + 0x1000`)를 포함.
  base 0 에서는 rel32 변위가 32비트 범위를 넘어 **iced가 14B 확장 폼(+9B)** 으로 인코딩.
- 실제 블록 VA(base = `arena.base`, helper 와 수 KB 거리)에서는 정상 **5B**.
- → 측정 길이(104) ≠ 실제 길이(95) → `block_vas`/`table[3]` 이 9B 뒤로 밀려 블록 중간을 가리킴.

**수정**: 길이 측정을 `assemble(lst.clone(), arena.base as u64)` 로 변경해
helper call rel32 가 범위 내에 들어 측정 = 실제 길이 일치.

---

## 3. 변경 요약 (`src/vm/threaded/harness.rs`)

| 지점 | 기존 | 변경 |
|---|---|---|
| `emit_block` 시그니처 | `state_base` | `state_base, bytecode_base` 추가 |
| `emit_branch_jump` | `mov r12, rax` (raw) | `mov r12, imm64(bytecode_base); add r12, rax` |
| 블록 길이 측정 | `assemble(lst.clone(), 0)` | `assemble(lst.clone(), arena.base as u64)` |

---

## 4. 검증

- `cargo test --release --lib vm::threaded` → **16 passed; 0 failed** (`temp_static_branch_only` 포함).
- `cargo test --release --lib vm::` → **97 passed; 0 failed** (전체 VM 계층 무회귀).
- 정적/동적 분기 모두 이제 참조 `RiscProgram::eval_state` 와 동치.

> 참고: 수정 전 두 버그가 순차로 가려져 있었다. 원인 1(분기 VIP)이 항상 먼저 크래시 → 원인 2(길이 측정)는
> 원인 1 을 고친 뒤에야 드러났다.
