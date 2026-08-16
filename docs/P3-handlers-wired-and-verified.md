# P3 — Self-Decoding 핸들러 전수 구현·와이어·검증 (REPORT)

> 작성: 2026-08-15 · branch `commercial/p3-engine-integration` · repo `asdfsadfecwecc`
> 노드: `ujiwo-zyris-code` (Windows) · 세션: VirtualBranch 검증 완료 + 상용 전체 프로그램 pack 복구

---

## 요약

상용(risc→poly→threaded) self-decoding rolling-key 디스패처의 **전체 네이티브 핸들러 셋**이
구현·와이어되었고, 각각 **선형 블록 단위 동치 차이 테스트**로 검증되었다. 직전 세션에서
동시 에이전트가 워킹 트리를 롤백(비커밋)해 컴파일 불가였던 것을 HEAD(전체 P2/P3 ISA)로
복원하고, VirtualBranch의 미해결 AV를 해결해 **`vm::threaded::poly_direct` 11/11 green**,
전체 **`cargo test --release --lib` 236 passed; 0 failed** 달성. 레거시 `--vm` / `--vm --vm-oep`
경로는 16-test + FINAL CHECKSUM `0x2cdc0e4511d84a64` 무회귀. 상용 `--vm-commercial`은
**pack 단계 해소** (이전엔 branch_map 미구현 → desync → pack 도중 실패), run은 여전히
네이티브 콜 브리지 부재로 0xC0000005 (아래 §5).

---

## 1. 구현·와이어된 네이티브 핸들러 (`src/vm/threaded/poly_direct.rs`)

| 핸들러 | 동작 | 검증 테스트 |
|---|---|---|
| `h_branch` VirtualBranch | DEC_COND(cond 바이트) → taken/not-taken → branch_map(ip_map) 해석 → rolling-key 재동기화(순방향/역방향) → dispatch | `test_poly_direct_virtual_branch_forward_reverse_matches_reference`, `..._ipmap_resolution_matches_reference` |
| `emit_setcc_cmov_handler` Setcc/ConditionalMove | DEC_COND → 22 조건 분기 평가 → 0/1 또는 조건부 store | `test_native_poly_direct_setcc_cmov_diff` |
| Multiply / MultiplyLow / Divide | `mul`/`mul rdx`/`div` + 폭 마스크 + 오버플로 CF/OF | `test_poly_direct_multiply_matches_reference`, `test_poly_direct_divide_matches_reference` |
| BSwap / BitScanForward/Reverse / TZCNT / LZCNT / PopCount | 하드웨어 + 폭 절단 + ZF/CF/PF 플래그 헬퍼 | `test_native_poly_direct_bitscan_count_popcnt_matches_reference` |
| CompareExchange {1,2,4,8} | CMPXCHG 성공/실패, 전 폭 | `test_poly_direct_compare_exchange_all_widths_matches_reference` |
| NativeCallBridge | no-op (스트림 소비, 상태 불변) | `test_native_poly_direct_native_call_bridge_noop` |
| DEC_COND 상태 슬롯 + `sub_dec_ops_cond` | cond 바이트 → canonical COND_* (OFF_COND_CODES 테이블) | `test_cond_codes_table_matches_branch_cond_map` |

핸들러 테이블(256×u8→VA) + operand-offset/kind + cond-code + **branch_map** 배선 완료.

---

## 2. 이번 세션 수정 (6 파일)

1. **ISA 롤백 복원** — HEAD 복원 + `poly_direct`/`commercial_build` 신규 작업 보존.
2. **VirtualBranch AV 해결**: `sub_eval_cond`가 `R8L`(setcc 결과)을 clobber → `R8`
   (bytecode_base) 손상 → `sub_decrypt`가 `[R8+R12]` 잘못 읽음 → AV. 결과를 `AL`로 변경.
3. **ADD stale-cin**: `emit_sub`가 남긴 DEC_CIN=1이 즉시 add에 더해짐 → ADD 핸들러가 DEC_CIN
   초기화.
4. **ADD PF**: 참조 `update_add64`는 결과 parity로 PF 갱신 — 네이티브도 `test` 후 0xC4 캡처 +
   `FLAG_MASK` 0x8C1→0x8C5.
5. **divide 차등 테스트**: RDX(regs[2])를 IDIV 피제수 상위로 셋업 (HW `#DE` 방지).
6. **encoder/decoder 스트림 비대칭**: `imm != 0` op(스케일 쉬프트) trailing 8B 제거
   (AddWithCarry cin만).
7. **`decode_full`**: Halt에서 중단하지 않아 전체 프로그램 op 오프셋 확보 (branch_map이
   ip_map 18,303개 전부 포함).
8. **ip_map 배선** (`place.rs`): `lift_program_cfg_commercial`의 ip_map →
   `build_program_vm_commercial`.
9. **commercial table blob** = 0xB00 + branch_map; **BOOT_AREA_RESERVE** 0x80000→0x120000
   (branch_map 293KB + bytecode 335KB 수용; crypto.rs가 실제 boot_end로 트림).

---

## 3. 검증 결과 (신선 재실행)

- `cargo build --release` → **exit 0**
- `cargo test --release --lib` → **236 passed; 0 failed**
- `--vm` pack→run → **16개 테스트 전체 통과**, FINAL CHECKSUM `0x2cdc0e4511d84a64`
- `--vm --vm-oep` pack→run → **16개 테스트 전체 통과**, FINAL CHECKSUM `0x2cdc0e4511d84a64`
- `--vm --vm-oep --vm-commercial` → **pack exit 0** (branch_map/ip_map/레저브 수정으로 pack
  실패 해소)

---

## 4. 아티팩트

- `docs/VirtualBranch-Native-Handler-DONE.md` (세션 2 갱신)
- `docs/journal/2026-08-15.md` (본 세션 저널)
- 본 보고서 (P3 핸들러 구현·와이어·검증)

---

## 5. 남은 것 — 상용 whole-program run gate ✅ (네이티브 콜 브리지 구현 완료)

> **해소 (후속 세션)**: self-decoding 디스패처에 레거시 `OP_NATIVE_CALL`급 **네이티브
> 콜 브리지**를 구현하고, 상용 리프트에 OEP **entry-jump**를 추가해 `--vm-commercial`
> run을 green으로 돌렸다. 상세: `docs/VirtualBranch-Native-Handler-DONE.md` §"남은 것 →
> 해소", `docs/P3-commercial-selfdecoding-fix.md`.

### 5.1 문제 (이전)

`--vm --vm-oep --vm-commercial`의 전체 프로그램 **run**은 여전히 0xC0000005:
`lift_program_cfg_commercial`이 제외(SEH/RISC-unliftable) 함수를 네이티브로 유지하는데,
lift된 OEP가 그런 함수를 `call`하면 RISC `push ret_ip; jmp target`의 target(source-IP)이
branch-map에 없어 바이트 오프셋 폴백으로 잘못 점프 → 바이트코드 끝을 넘어 AV.
(cdb: `sub_decrypt`의 `[R8+R12]` AV — `R12=0x551B8` > bytecode len `0x51D2B`.)

### 5.2 해소 — 2가지 수정

1. **entry-jump** (`src/vm/text_lift/commercial.rs`): CfgExtractor가 블록을 주소 순으로
   나열해 OEP가 바이트코드[0]이 아니다 → OEP가 VM화되면 프로그램 맨 앞에
   `VirtualBranch(Always) → OEP`를 prepend (레거시 `lift_cfg_switch(.., Some(entry_va))`
   와 동일 계약). 그 전에는 VM이 .text 시작부(0x140001000) 블록부터 실행해 첫
   분기부터 가비지 타깃으로 폭발했다.
2. **네이티브 콜 브리지** (`src/vm/threaded/poly_direct.rs` `h_branch` not-found 경로):
   branch-map에서 타깃을 못 찾으면(배제 함수) 바이트 오프셋 폴백 대신 —
   (a) 가상 스택에서 ret_ip pop, (b) state_base/bytecode_base를 callee-saved
   (R12/R14)에 스테이지, (c) state 버퍼의 실제 GPR(RAX/RCX/RDX/R8/R9/R10/R11)을
   Win64 콜 인자로 실장, (d) RSP 16B 정렬 + 0x70 프레임(홈+스택 인자 5..12, 가상
   스택에서 전달), (e) `call target`, (f) 휘발성 GPR+RFLAGS 동기화, (g) 인프라 복원
   후 ret_ip를 branch-map으로 해석해 rolling-key 재동기화 → dispatch.

### 5.3 검증 (신선 재실행)

- `cargo build --release` → exit 0.
- `cargo test --release --lib` → **236 passed; 0 failed**.
- `--vm` pack→run → **16개 테스트 전체 통과**, FINAL CHECKSUM `0x2cdc0e4511d84a64`.
- `--vm --vm-oep` pack→run → **16개 테스트 전체 통과**, FINAL CHECKSUM `0x2cdc0e4511d84a64`.
- **`--vm --vm-oep --vm-commercial` pack→run → 16개 테스트 전체 통과 + FINAL CHECKSUM
  `0x2cdc0e4511d84a64`** (= baseline, 3회 반복 안정). **0xC0000005 해소.**
- 기록: `docs/P3-commercial-selfdecoding-fix.md` · milestones "pre-existing P3 gap → 해소".