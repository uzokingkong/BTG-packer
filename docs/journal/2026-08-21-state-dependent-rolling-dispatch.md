# 2026-08-21 — State-Dependent Rolling Dispatch (static-extractor defeat)

## 과제
ChatGPT식 정적 추출기가 한 번에 잡는
`opcode = *ip; target = table[opcode] ^ dispatch_key; goto target` 구조를 제거하고,
dispatch 키를 state-dependent / rolling 으로 만들어 단순 `handler[opcode]` 한 줄 추출 불가.

## 수행 (소스 변경)
- `src/vm/handlers/mod.rs`
  - `DISPATCH_C1`/`DISPATCH_C4` 상수 + `per_op_dispatch_key(op, master)`
    = `(op*C1) ^ (op<<17) ^ C4 ^ master` (패커·런타임 공유 → 항상 동기화)
  - `thread_local MBA_ROLLING` 코드젠 플래그: `generate_vm_code` 진입 시
    `mba_key.is_some()` 설정. plain 경로는 기존 `xor rax,r15` 바이트 그대로.
  - `emit_dispatch`(모든 핸들러 꼬리) MBA 경로에서 opcode로 key(op)를 런타임 계산해
    `table[op] ^ key(op)` 복호화 후 jmp.
- `src/vm/mod.rs` `build_vm_module_mba`
  - 테이블 각 항목을 `per_op_dispatch_key(op, master)` (master=a+b)로 암호화.
    런타임 r15 = (a^b)+2*(a&b) = a+b 와 정확히 일치 확인.

## 검증 (노드)
- `cargo build --release` clean (0 errors)
- `cargo test --lib vm::` → 285 passed / 0 failed (MBA 경로 실행 테스트 포함)

## 참고
- 상용 poly_direct rolling-key self-decoding 디스패처는 기존 유지.
- rdata 힌트 제거/단일바이트 패치 integrity 는 다른 태스크 범위.
