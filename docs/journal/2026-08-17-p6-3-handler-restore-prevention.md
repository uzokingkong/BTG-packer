# 2026-08-17 — P6-3 핸들러 복원 방지 (Handler Restore Prevention, Themida급)

> repo `asdfsadfecwecc` · branch `main` (working tree)

## 요청
"핸들러 복원 방지 기능좀 더 — 진지하게 더미다급으로"

## baseline
- `cargo build --release` green · `cargo test --release --lib` → **296 passed**.
- P6-1(테이블 단일 XOR) / P6-2(NOR De Morgan) 상태.

## 진행 (전부 실측)
`--vm-commercial`(poly_direct self-decoding rolling-key dispatcher)의 handler
테이블 보호를 P6-1의 단일 `table_key` XOR 에서 **Themida식 다층 하드닝**으로 승격:

1. **per-opcode 파생 키**: `K(op) = (op*C1) ^ (op<<17) ^ C4 ^ master`
   - 항목마다 opcode byte 에 의존하는 서로 다른 키 → 단일 상수 XOR 로는 256개
     항목을 일괄 복호화 불가 (P6-1은 하나의 `table_key` 였음).
   - dispatch loop 가 복호화된 opcode byte 로 동일 파생식을 재현 (R9 에 보존).
   - C4 상수를 섞어 **opcode 0 의 키도 master 와 달라지게** 함 (master 단독
     XOR 로 특정 항목이 복원되는 경로 차단).
2. **MBA 마스터 키 분할**: `master = mba_a + mba_b` — dispatch loop 가 항등식
   `a+b == (a^b) + 2*(a&b)` 로 런타임 복원.
   - **마스터 K 자체는 어떤 단일 상수로도 코드에 존재하지 않음** (P6-1의
     `movi rcx, table_key` 평문 임베드를 제거).
3. **미등록 opcode byte → 트랩(ud2)**: 테이블에서 handler 가 없는 byte 는
   `h_trap`(ud2) 을 가리킴 — 테이블 프로브/바이트코드 조작이 조용히 통과하지
   못하고 즉시 fault (P6-1의 h_nop no-op 폴백 대체).
4. **엔트리 무결성 셀프체크**: VM 진입 시 암호화된 256 항목의 checksum 을
   재계산해 빌드 시 값과 비교 — 불일치(덤프 재배치 / 패치 / 복원) 시 ud2.
   - checksum 은 테이블 VA(→ 핸들러 VA)가 조립 후에만 알려지므로, 엔트리에
     `mov r11, imm64` placeholder 를 임베드하고 조립 후 imm64 를 실값으로 패치.

## 검증 (신선, seed 1234)
| 항목 | 결과 |
|---|---|
| `cargo build --release` | green |
| `cargo test --release --lib` | **300 passed; 0 failed** (296 + P6-3 테스트 4개) |
| `--vm-commercial` pack→run 16테스트 | exit 0, **FINAL CHECKSUM `0x2cdc0e4511d84a64` 무회귀** |
| `--vm` pack→run | exit 0, checksum 동일 |
| plain pack→run | exit 0, checksum 동일 |
| poly_direct 차등 (native==interp==reference) | 18/18 green |

## 추가 테스트 (P6-3 회귀)
- `test_table_not_restorable_by_single_xor` — per-op 키로만 핸들러 VA 복원, master
  단독 XOR 로는 코드 영역에 도달 불가.
- `test_unused_opcode_slots_decode_to_trap` — 미등록 슬롯이 공유 트랩 VA 로
  수렴 + 등록 핸들러 VA 와 상이.
- `test_table_checksum_matches_builtin` — 엔트리 임베드 checksum == 실테이블
  checksum (placeholder 미패치 아님).
- `test_per_opcode_keys_injective` — 256개 opcode 키 전부 상이 (충돌 시 단일-XOR
  공격에 노출).

## 변경 파일
- `src/vm/threaded/poly_direct.rs` — per-op 키 파생, MBA 마스터, h_trap, 엔트리
  무결성 셀프체크, 테이블 build/checksum 패치, `SelfDecodingParts.table_checksum`.
- `src/vm/threaded/poly_direct/poly_direct_tests.rs` — P6-3 회귀 테스트 4개.
- `README.md` — "핸들러 복원 방지 (P6-3)" 항목.

## 참고
- `--vm-test` [6] "VM module native execution" 는 이번 WIP의 `self_test/mod.rs`
  arena-offset sizing fix 로 **PASS 확정** — 레거시 모듈 code/table/bytecode가
  고정 0x3800 간격을 넘어서며 발생하던 code→table overflow(0xC0000005)를,
  실제 모듈 크기로 non-overlap offset을 재계산해 해소했다.

## 기준선 고정 (2026-08-17, HEAD 669d253 + P6-3 WIP)
| 단계 | 결과 |
|---|---|
| `cargo build --release` | green |
| `cargo test --release --lib` | **300 passed; 0 failed** |
| `--vm-test` | **[1..40] ALL PASS** (incl. [6] arena fix) |
| `--vm` pack→run | 16-test PASS · **FINAL CHECKSUM `0x2cdc0e4511d84a64`** · exit 0 |
| `--vm --vm-oep` pack→run | 16-test PASS · **FINAL CHECKSUM `0x2cdc0e4511d84a64`** · exit 0 |
| `--vm --vm-oep --vm-commercial` pack→run | 16-test PASS · **FINAL CHECKSUM `0x2cdc0e4511d84a64`** · exit 0 |

README.md 는 이번 WIP에서 중복 삽입된 "결정적 빌드 (--seed)" bullet 을 정리해
단일 유지.
