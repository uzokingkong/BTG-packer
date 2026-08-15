# BSwap / BitScanFwd/Rev / TZCNT / LZCNT / PopCount 네이티브 핸들러 구현 보고서

> 작성: 2026-08-15 · repo `asdfsadfecwecc` · node `ujiwo-zyris-code` · 브랜치 `commercial/p3-engine-integration`

## 요약

상용 VM의 롤링키 자체복호 디스패처(`src/vm/threaded/poly_direct.rs`)에 다음 네이티브 핸들러를
구현·와이어링했다:

| RiscOp | 네이티브 구현 | 플래그 |
|---|---|---|
| `BSwap { width: 4 }` | `bswap r32d` | 없음 |
| `BSwap { width: 8 }` | `bswap r64` | 없음 |
| `BitScanForward` | `bsf r64` | ZF만 (= src==0) |
| `BitScanReverse` | `bsr r64` | ZF만 (= src==0) |
| `CountTrailingZeros { 2/4/8 }` | `tzcnt r16/32/64` | CF·ZF (ZF=ZF\|CF) |
| `CountLeadingZeros { 2/4/8 }` | `lzcnt r16/32/64` | CF·ZF (ZF=ZF\|CF) |
| `PopCount` | `popcnt r64` + `test` | CF·PF·ZF·SF·OF (=update_logic64) |

## 주요 설계 포인트

- **TZCNT/LZCNT ZF 규약**: 참조(`eval_state`/폴리 인터프리터)는 폭-절단 소스가 0일 때 ZF=1로
  설정하지만 하드웨어 `tzcnt`/`lzcnt`는 이때 ZF=0(결과=폭). 그래서 `emit_store_cf_zf_tz`가
  CF|ZF를 캡처한 뒤 `ZF = ZF | CF`로 보정해 참조와 정확히 일치시킨다. 폭 2는 `movzx r32d,r16w`
  로 결과 상위 비트를 정리한다.
- **PopCount 플래그**: 참조 `update_logic64`는 PF를 설정한다. `popcnt` 후 `test r10,r10`가
  CF=0·OF=0·ZF·SF·PF를 결정론적으로 생성하고, `emit_store_flags_popcnt`가 0x8C5(CF|PF|ZF|SF|OF)
  를 슬롯에 병합하며 AF는 슬롯 값으로 보존한다.
- **BSF/BSR**: ZF를 스캔 명령 직후 캡처하고(src==0 표시를 R9L로 저장), 이후 dst-fix AND가
  플래그를 오염시키기 전에 슬롯에 ZF만 병합한다. src==0이면 (정의되지 않은) BSF 결과를 0으로
  만든다 — 참조와 동일.

## 참조(레퍼런스) 버그 수정

`eval_state`(src/vm/risc/mod.rs)와 폴리 인터프리터(src/vm/poly/interpreter.rs)의 `BSwap{4}`
구현이 `(a.swap_bytes() as u32)`로 되어 있어 zero-extended 32비트 값에 대해 항상 0을 반환했다.
네이티브 `bswap r32`와 일치하도록 `((a as u32).swap_bytes()) as u64`로 수정해 3계층
(참조·폴리·네이티브) 동치를 복원했다.

## 검증

- `cargo build --release` — green (exit 0)
- `test_native_poly_direct_bitscan_count_popcnt_matches_reference` — **PASS**
  (3 시드, native == `RiscProgram::eval_state`, regs/temps/flags/vsp/stack 전부 비교,
  BSwap64/32, BSF/BSR, BSF(0), TZCNT/LZCNT 전 폭 포함 폭-절단 0, PopCount(0xFF)·PopCount(0) 포함)

## 비고

본 작업이 속한 병렬 워크(동일 디스패처 파일을 다른 태스크들도 동시 편집) 때문에 전체
`cargo test --release --lib` green은 다른 태스크(VirtualBranch `ip_map` 배선 등)의 편집이
완료된 뒤 판정된다. 본 태스크의 핸들러는 자체 차등 테스트로 이미 검증됨.
