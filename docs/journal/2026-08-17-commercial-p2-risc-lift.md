# 2026-08-17 — 상용 엔진 P2 강화: RISC 리프터 커버리지 + P2-RISC-GAP 진단

> repo `asdfsadfecwecc` · `--seed`(P3-1) 배선 완료 후속 세션
> 대상: `--vm --vm-oep --vm-commercial` 상용 엔진(risc→poly→threaded)

## 목적
COMMERCIAL-VM-UPGRADE-PLAN의 **P2(G3) — RISC 리프터 커버리지** 게이트 강화.
남은 과정 문서(마스터플랜·P4/P5 리포트·P3 핸들러 보고서)를 읽고, 상용 엔진이
가상화하는 블록 비율을 실측·측정 가능하게 만든 뒤 실제 리프터를 확장했다.

## 1. P2-RISC-GAP 진단 추가 (`src/vm/text_lift/commercial.rs`)
- 기존 `unsupported` 수집은 **전체 블록**(SEH 네이티브 포함)의 실패를 집계해
  실제 갭을 과대 보고했다.
- **SEH/panic-unwind 네이티브 블록을 제외**하고, RISC-unliftable 만으로 밀려난
  블록의 실패 명령(Code) 히스토그램을 출력하도록 정제.
- 산출: `[P2-RISC-GAP] blocks: N virtualized, M native (SEH A + RISC-unliftable B), K unsupported`.
  → 남은 리프터 확장 항목이 한눈에 보인다 (후속 P2 게이트 지표).

## 2. RISC 리프터 확장 (`src/vm/risc/lifter.rs`, `lifter/arith.rs`)
실측 갭 히스토그램 기반으로 안전한 항목부터 구현:

| 항목 | 설명 | 검증 |
|---|---|---|
| **8/16-bit CMP** | `Cmp_AL_imm8`·`Cmp_r8_rm8`·`Cmp_rm8_imm8`·`Cmp_rm8_r8`·`Cmp_rm16_*` 추가. `lift_cmp`가 **레지스터 피연산자를 폭으로 마스크**(low-byte/word만 비교) — 기존엔 64비트 전체를 비교해 플래그가 틀렸다 | 값 단언 테스트 |
| **8/16-bit TEST** | `Test_rm8_r8`·`Test_rm8_imm8` 추가. **기존 잠재 버그 수정**: `mask_operand`가 공용 Temp(3)를 써 두 피연산자 마스크가 서로 clobber(16/32비트 TEST가 `v0&v1` 대신 `v1&v1` 계산) → `mask_operand_into`로 Temp(3)/Temp(2) 분리 | 값 단언 테스트 |
| **8-bit ADD/SUB** | `Add_AL_imm8`·`Add_r8_rm8`·`Add_rm8_imm8`·`Add_rm8_r8`·`Sub_*` 추가. **부분-쓰기 상위 비트 보존**: `Add{width}`가 결과를 마스크해 상위를 0으로 밀므로, 원본 상위를 Temp(0)에 저장해 `(orig & ~mask) | masked`로 합성 (`preserve_upper`) — 호출 순서 버그(덮어쓴 뒤 복원) 수정 | 값 단언 테스트 |
| **NOP/Pause no-op** | `Nopw/Nopd/Nop_rm16/32/64/Pause` → micro-op 0개 (의미 무연산) | 전체 회귀 |
| **간접 JMP** | `Jmp_rm64`·`Jmp_rm32` → `VirtualBranch(Always).with_src1(target)` (Call_rm64와 동일 계약) | 전체 회귀 |
| **RIP-relative addressing** | `[rip+disp32]` → `inst.ip()+len+disp` 절대 주소를 즉시값으로. **현재 run gate에서 비활성**(아래 §4) | — |

## 3. 결과 (실측, seed=1234, `rust_packer_test.exe`)
- **가상화 블록: 4513 → 6040 (+34%)**
- **RISC-unliftable 블록: 3210 → 1683 (-48%)** (SEH 네이티브 4446은 구조적 유지)
- 가상화된 프로그램 VM 바이트코드: 302KB → 454KB (더 많은 코드가 VM 안)

## 4. RIP-relative — BISECT 결과 (남은 P2 항목)
RIP-relative lift로 새로 가상화된 블록이 현재 타깃에서 **디스패처 keystream
desync(0xC0000005)**를 일으켜 실행 초기(startup, test[1] 이전)에 크래시했다.
- cdb: fault `@ .textb+0x93954` (핸들러 코드 영역 내, 잘못된 handler index로
  데이터를 코드로 실행) · r12(VIP)=0x66d37, r14(roll key) 불일치.
- NOP·8-bit·간접 JMP·preserve_upper 순으로 bisect → **RIP-relative가 유일한
  크래시 원인**으로 확정 (비활성 시 전 조합 PASS + baseline checksum 동일).
- 가설: 패치 데이터(점프 테이블/.rdata 함수 포인터) 재배치와 ip_map(source VA)
  해석의 상호작용으로 잘못된 바이트코드 오프셋 분기 → keystream desync.
- **판단**: 정확한 원인 규명은 패치 데이터 재배치 경로 추적이 필요해 이번 세션에선
  게이트(비활성)로 두고, [P2-RISC-GAP] 진단이 갭을 계속 노출하도록 유지.
  → **후속 P2 작업 항목: RIP-relative 리프트 + 패치 데이터 연동 검증.**

## 5. 검증 (전부 통과)
- `cargo test --release --lib` → **279 passed; 0 failed** (+ 신규
  `test_commercial_8bit_partial_write_and_cmp_test_matches_reference`).
- 3경로 pack→run, FINAL CHECKSUM `0x2cdc0e4511d84a64` = baseline 동일:
  - `--vm` / `--vm --vm-oep` / `--vm --vm-oep --vm-commercial` 모두 16개 테스트
    전체 통과, exit 0.
- P3-1 결정적 빌드: `--seed 1234` 재패킹 → SHA256 동일 (상용 경로 포함).

---

## 6. 후속 — "오류난거 전부 고쳐야함": 남은 오류 2건 실해결 + BISECT

### 6.1 오류 1: 하네스 8/16-bit Add/Sub 어셈블 실패 (수정 완료)
`run_native_poly`가 8비트 op를 어셈블하지 못했다:
`direct_tail assemble error: Register 63 ... movzx r10,r10b`.
- 원인: `harness/emit_block.rs`의 `Add/SubWithBorrow {width:1/2}` 핸들러가
  `Movzx_r32_rm8`의 dst를 **64비트 R10**(유효 32비트 레지스터가 아님)으로 주고,
  movzx가 상위 비트를 0으로 밀었다(8/16비트 부분-쓰기 의미론 오류).
- 수정: movzx 제거 — x86 `add r10l, r11l`가 이미 부분-쓰기 상위 비트 보존 +
  폭별 하드웨어 플래그를 정확히 준다.
- 검증: `test_commercial_8bit_partial_write_and_cmp_test_matches_reference`가
  **네이티브(`run_native_poly`) 차등** 포함 통과.

### 6.2 오류 2 (핵심): poly_direct 핸들러 테이블에 폭별 ALU 핸들러 미등록 → h_nop no-op
- **증명**: h_nop을 임시 `ud2`로 바꾸자 전체 프로그램 실행이 **0xC000001D(illegal
  instruction)**로 트랩 → `Add {width}`/`SubWithBorrow {width}`/`Inc`/`Dec`/
  `Not {width}`가 실제로 h_nop(의미 no-op)으로 디스패치됨을 확인.
- 즉 전체 프로그램 리프트가 내는 폭별 ALU op(실측 `Add` 376 + `SubWithBorrow` 440 +
  `Inc/Dec/Not` ~101)가 런타임에서 **조용히 아무것도 하지 않았다** — 이번 타깃은
  checksum이 우연히 무관한 경로라 통과했지만, 새로 가상화된 블록(RIP-relative)에서
  `sub rsp`/`cmp`/`test`가 무시되어 스택/플래그가 틀어져 0xC0000005로 재현.
- **수정**: `poly_direct.rs`에 `emit_width_alu_handler` + `WidthAluOp` 추가 —
  폭별(1/2/4/8) Add/SubWithBorrow/Inc/Dec/Not 네이티브 핸들러 20개를 생성·등록.
  - Add/Sub: 폭별 하드웨어 플래그(CF|PF|ZF|SF|OF) + 부분-쓰기 상위 비트 보존.
  - Inc/Dec: `emit_store_flags_incdec` — **CF 보존**(x86 INC/DEC는 CF 불변),
    ZF/SF/OF/PF는 하드웨어.
  - Not: 플래그 불변 (x86 NOT).
- 검증: 전 경로(`--vm`/`--vm-oep`/`--vm-commercial`) 16테스트 + FINAL CHECKSUM
  `0x2cdc0e4511d84a64` 동일, `cargo test` 279 green.

### 6.3 RIP-relative keystream desync — 최종 BISECT 결과 (게이트 유지)
- h_nop 핸들러 수정 후에도 RIP-relative lift로 재현 (0xC0000005, MemoryRead 핸들러가
  가비지 주소 `0x28006b46d` deref, VIP=0x1FF4D = `mov rbx,imm` 직전 RIP-relative
  load의 MemoryRead op).
- 규명: 인코더/디코더/인터프리터는 양-즉시 `AddWithCarry(Imm64,Imm64,cin=0)` 포함
  전부 byte-일치(재인코딩 검증 통과). 폴트 0x93954는 핸들러 시작이 아닌 중간 —
  네이티브 디스패처의 **keystream 불일치**로 잘못된 handler entry로 분기.
- 함수-원자성(.pdata로 unliftable 함수 전체 제외) 시도 — 크래시 해소 안 됨 + 커버리지
  절반 이하로 하락 → **revert**.
- **결론**: RIP-relative 리프트는 게이트(비활성) 유지. 정확한 keystream 불일치 지점
  추적(네이티브 sub_decrypt의 `step(orig,vip)` vs 인터프리터 비교)은 후속 P2 과제.
  `[P2-RISC-GAP]` 진단이 갭을 계속 노출.

### 6.4 최종 상태
- 확정 수정: 8/16-bit CMP/TEST(폭 마스킹), 8-bit ADD/SUB(부분-쓰기 보존), NOP/Pause,
  간접 JMP, **폭별 ALU 네이티브 핸들러(h_nop no-op 버그)**, 하네스 8비트 어셈블 버그.
- `cargo test --release --lib` → **279 passed; 0 failed**.
- 3경로 16테스트 + FINAL CHECKSUM baseline 동일, `--seed` 결정적 빌드 유지.
- 가상화 6040 블록(+34%), RISC-unliftable 1683(-48%) — RIP-relative는 후속.

---

## 7. 후속 2 — 전수 감사: h_nop fallback 全op + 인터프리터 커버리지 (모두 해소)

### 7.1 [P2-HANDLER-GAP] 전수 감사 (poly_direct.rs)
`build_self_decoding_parts_with`에 **인코딩 가능 op vs 네이티브 핸들러 전수 감사**를
추가해, 핸들러 테이블에 없는 op(h_nop no-op fallback)를 즉시 노출한다.
- 결과: `Add/SubWithBorrow/Inc/Dec/Not {width}` 수정 후 남은 미등록 op는
  **`NativeCallBridge` 1개뿐** — 참조/인터프리터가 no-op(스트림 소비)이므로 h_nop과
  동일 의미. h_nop으로 **명시 등록** → 감사가 `all encodable ops have native
  handlers`로 깨끗.
- 인터프리터(`poly/interpreter.rs`)는 `Add{width}`/`SubWithBorrow`/`Inc`/`Dec`/`Not`/
  `NativeCallBridge` 전부 처리 확인 — 런타임과 동치 유지.

### 7.2 RIP-relative keystream — 최종 BISECT (게이트 확정 유지)
- 핸들러 수정 후 재진행. 크래시는 **결정적 가비지 주소 `0x28006b46d`**(seed 고정 시
  atomicity 유무와 무관 동일) → 단순 무작위 desync가 아닌 결정적 오계산.
- 양-즉시 `AddWithCarry(Imm64,Imm64,cin=0)`(RIP 주소 계산의 핵심 op)는 **신규 차등
  테스트 `test_native_poly_direct_both_imm_addwithcarry_matches_reference`**로
  네이티브==인터프리터==참조 정상 확인 → 해당 op는 무죄.
- 함수 원자성(.pdata로 unliftable 함수 전체 제외) 재시도 — 크래시 미해소 + 커버리지
  4513→2317 절반 하락 → **revert** (잠재 리스크로 문서화).
- 남은 원인 후보: 가상화 블록이 제외 함수 **꼬리**(`add rsp; pop; ret`)를 네이티브
  브리지로 호출하는 경계 문제, 또는 네이티브 디스패처 특정 op의 keystream 소비 차이.
  → 후속 P2 항목. `[P2-RISC-GAP]` 진단이 갭을 계속 노출.

### 7.3 최종 상태 (확정)
- **수정**: h_nop no-op 버그(폭별 ALU 핸들러 20개), NativeCallBridge 명시 등록,
  하네스 8비트 어셈블 버그, 8/16-bit CMP/TEST(폭 마스킹), 8-bit ADD/SUB(부분-쓰기),
  NOP/Pause, 간접 JMP, P2-RISC-GAP/P2-HANDLER-GAP 진단.
- **게이트**: RIP-relative (크래시, 후속 P2).
- `cargo test --release --lib` → **280 passed; 0 failed** (+ 양-즉시 AddWithCarry
  차등 테스트).
- 3경로(`--vm`/`--vm-oep`/`--vm-commercial`) 16테스트 + FINAL CHECKSUM
  `0x2cdc0e4511d84a64` 동일, `--seed` 결정적, 가상화 6040(+34%).