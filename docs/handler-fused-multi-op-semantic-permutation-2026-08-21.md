# BTG-Packer — Handler Fused/Multi-Op + Variable Operand + Per-VM Semantic Permutation

> 작성일: 2026-08-21 · 작업 단위 task/0bd6049682914fdf8a62e1cfeaca9f9d
> 대상: Zyris 노드 `C:\Users\uzoki\Desktop\asdfsadfecwecc` (btg-packer / vm-obf, Rust)
> 과제: handler가 native instruction과 1:1에 가까운 구조를 분리해,
> ChatGPT식 정적 추출기가 `opcode → semantic` 분류표를 한 번에 만들 수 없게 한다.
> (fused/multi-op handler · 가변 operand 인코딩 · VM별 semantic permutation. CPU-like flags 저장 동작 유지.)

## 목표

레거시 1:1 VM은 "opcode 1바이트 → native handler 1개 → semantic 1개"라서,
정적 추출기가 dispatcher → handler table → opcode-semantic → bytecode emulator
경로를 한 번에 잡을 수 있었다. 본 과제는 이 1:1 구조를 깨는 세 가지 메커니즘을
도입하고, VM의 CPU-like flags 저장 동작이 그대로 동작함을 차등 검증한다.

## 세 가지 메커니즘 (모두 seed-keyed, 빌드마다 변화)

### 1. FUSED / MULTI-OP HANDLERS — `src/vm/semantic_obf.rs` + `src/vm/handlers/fused.rs`

관련 단일-op 핸들러 집합을 **하나의 opcode(fused family)로 접는다.** fused handler는
bytecode의 sub-op 바이트를 읽고 내부의 per-build-randomized sub-dispatch
(compare-and-jump chain, seed-shuffled case 순서)로 올바른 연산을 수행한다.
하나의 fused handler를 디컴파일하면 하나의 native instruction이 아니라 **여러 semantic**이 나온다.

접히는 family (`FusedGroup`, 5개):
- `AluRr`   — rr ALU: ADD/SUB/XOR/AND/OR/IMUL (32 + 64-bit) → 12 members
- `AluImm`  — ALU+imm32: ADD/XOR/AND/OR (32-bit + sign-ext imm32) → 8 members
- `LoadAbs` — 절대주소 load 폭 family: movzx8/16/32, movsx8/16, mov64 → 6 members
- `StoreAbs`— 절대주소 store 폭 family: mov8/16/32/64 → 4 members
- `MulDiv`  — 1-op mul/imul/div/idiv (32+64) → 8 members

총 **38개 단일-op를 5개 fused handler**로 접음. 그 밖의 opcode는 permuted plain opcode로 유지.

### 2. VARIABLE OPERAND ENCODING — `src/vm/semantic_obf.rs`

fused instruction 형식: `[ family_byte ][ subop_byte ][ operands... ]`
operand 개수/폭은 **family(opcode) 바이트의 정적 함수가 아니라** permuted sub-op 바이트의
속성이다. `opcode_operand_len(family_byte)`는 `None` — 정적 추출기는 opcode 바이트만으로
명령어 길이를 계산할 수 없고, sub-op 바이트 자체도 seed permutation으로 뒤섞여 있어
seed 없이는 디코드 불가. branch rel-fixup은 인코딩/디코딩 양방향에서 교정된다.

### 3. VM별 SEMANTIC PERMUTATION — `src/vm/dispatch_perm.rs` (+ `semantic_obf`)

모든 plain opcode 바이트는 seed-keyed 전단사(`DispatchPermutation`, Fisher–Yates +
SplitMix LCG)로 remap되고, fused family tag/sub-op 순서도 seed-permute된다.
`build_vm_mod`/`build_prog_vm_mod`(`src/pipeline/crypto/place/vm_build.rs`)는 매
모듈 빌드마다 `rng.next_u64()`로 시드를 뽑아 `SemanticObfuscator::from_seed(seed)`를
만든다 → **VM별로 다른 opcode 바이트와 다른 sub-dispatch 순서.** 한 바이너리에서 만든
정적 표는 다른 빌드로 전이되지 않는다. (기본 경로로 on: `BTG_NO_SEMOBF=1`이면 legacy
plain byte-identical 경로로 폴백 — 기존 차등/네이티브 테스트 불변.)

## CPU-like flags 저장 동작 유지

fused handler body는 단일-op 핸들러와 **동일한 flags capture 코드**를 인라인으로 재사용한다
(`handlers/mod.rs`의 `cap_flags`/`cap_flags_incdec`/`cap_flags_shift`/`cap_flags_cf_of`,
STATE_FLAGS 슬롯, FLAG_MASK). ADD/SUB는 ZF/SF/PF(또는 full), IMUL/MUL은 CF/OF,
시프트는 OF/AF 제외 마스크 등 — 원래 semantics와 동일. 셀프테스트 [9] flag model + full
Jcc(16 conds) PASS로 보장된다.

## 변경 파일 (소스, 노드에 있음)

- `src/vm/semantic_obf.rs`  — (new) SemanticObfuscator codec: fused rewrite(encode/decode),
  variable operand len, VM별 op/family/sub-op permutation, branch fixup
- `src/vm/handlers/fused.rs` — (new) fused/multi-op handler codegen (sub-dispatch + inline bodies)
- `src/vm/dispatch_perm.rs`  — (mod) seed-keyed opcode→slot bijection
- `src/vm/handlers/mod.rs`   — (mod) `pub(crate) mod fused;`
- `src/vm/mod.rs`            — (mod) `build_vm_module_obf` (256-entry table + fused region emit)
- `src/vm/self_test/semobf.rs` — (new) end-to-end 차등 테스트 (fused native == interp(decode))
- `src/vm/self_test/mod.rs`    — (mod) `[41] A-6` 셀프테스트 배선
- `src/pipeline/crypto/place/vm_build.rs` — (mod) 기본 경로에 semobf 배선 (`BTG_NO_SEMOBF`)

## 검증 (노드에서 실행)

- `cargo build --release` → **성공 (0 errors)**, exit 0
- `cargo test --lib vm::` → **285 passed / 0 failed**
- `cargo run --release -- --vm-test` → **ALL CHECKS PASSED**, 특히
  - `[41] A-6 fused/permuted/variable VM encoding (fused handlers == interp == native; per-seed permutation; variable operand len): PASS`
  - `[9] VM flag model + full Jcc (16 conds incl. JA/JBE): PASS`

차등 검증은 **선형 블록 단위 동치**로 한정: `run_semobf_test`가 fused 스트림을
(1) reference interpreter로, (2) `interpret(decode(obf))`로, (3) native fused-handler
실행(arena)으로 각각 실행해 세 결과가 일치함을 확인 (v0/v4/memv). 두 시드가 같은
프로그램을 다르게 인코딩하되 동일하게 실행함도 확인.

## 정적 추출 방해 효과

- 1:1 `opcode → native handler → semantic` 분해 불가: 한 fused handler가 여러 semantic.
- 명령어 길이가 opcode 바이트만으로 결정 불가 (가변 operand encoding).
- opcode→semantic 표가 seed permutation 없이는 작성 불가 + 빌드별로 전이 불가.
- 디스패처 → handler table → opcode-semantic → emulator 단계에서 정적 추출기 실패.

## 남은 것 / 참고

- `.rdata` 문자열 힌트 제거 / 단일 바이트 패치 integrity 우회 불가 / decrypt target
  static 복원 실패 등은 작업 단위의 **다른 태스크 범위**(본 태스크는 handler 구조 분리에 한정).
- 상용 `poly_direct` 엔진의 self-decoding rolling-key 디스패처는 기존 유지.
