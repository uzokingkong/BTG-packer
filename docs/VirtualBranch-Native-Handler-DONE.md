# VirtualBranch Native Handler — ip_map 분기 해결 + 롤링 키 재동기화 (DONE)

> 작업일: 2026-08-15 · node `ujiwo-zyris-code` (Windows) · branch `commercial/p3-engine-integration`
> 과업: ip_map 기반 분기 해결과 롤링 키 재동기화(순방향/역방향)를 수행하는 VirtualBranch
> 네이티브 핸들러 구현. DEC_COND 상태 슬롯으로 조건 분기 실행/미실행을 처리.

## 구현 요약 (`src/vm/threaded/poly_direct.rs`)

상용 self-decoding 디스패처(`build_self_decoding_parts`)에 **VirtualBranch 네이티브
핸들러**를 추가했다. 한 줄 실행마다 복호화 키가 변하는 롤링 키 스트림에서 taken 분기는
바이트코드 위치가 점프하므로 키를 해당 위치로 재동기화해야 한다.

### 구성 요소
1. **`OFF_BRANCH_MAP` (0x8B00) 분기-해결 테이블** — `SelfDecodingParts.branch_map`
   (u32 count + count×(u64 target_value, u64 byte_offset)). 빌드 시 바이트코드를
   `PolymorphicDecoder`로 디코드 → `encode_with_offsets`로 재인코딩해 각 micro-op의
   바이트 오프셋을 얻고, 모든 절대-인덱스 VirtualBranch 타깃과 모든 ip_map 항목
   (source-IP→바이트 오프셋)을 테이블로 내보낸다. `ip_map`이 있으면 source-IP→오프셋,
   없으면 micro-op 인덱스→오프셋 폴백(=`resolve_target`와 동일 계약).

2. **`sub_eval_cond`** — DEC_COND(canonical COND_* 코드)를 22개 조건(Always..NotParity +
   CounterZero 2/4/8)으로 분기 평가해 AL=1/0(taken/not-taken) 반환. 플래그 조건은
   FLAGS 슬롯(x86 RFLAGS 비트 레이아웃)을 `push rax; popfq`로 RFLAGS에 실어 setcc로 평가,
   CounterZero는 가상 RCX(regs[1]) 하위 폭을 시프트로 격리해 zero 검사.

3. **`sub_resync`** — `RBX=타깃 바이트 오프셋` 기준으로 키를 재동기화.
   - 순방향(target>현재): 현재 키에서 타깃까지 중간 바이트들을 `sub_decrypt`로 복호화해
     키 상태를 전진(롤링 키의 선형 확장 성질 이용).
   - 역방향(target<현재): 키를 init_key로 리셋하고 R12=0부터 타깃까지 복호화해 재생성.
   - 완료 후 R12=타깃, R14=타깃 위치의 키.

4. **`h_branch`** — VirtualBranch 핸들러:
   - `sub_dec_ops_cond`(cond→DEC_COND) → `sub_dec_ops`(dst/src1/src2+imm) →
     (src1==0x00이면 8B 절대 타깃을 `emit_read_imm8`로 DEC_IMM1에 소비).
   - `sub_eval_cond`로 taken/not-taken 결정.
   - taken: DEC_IMM1 타깃 → 브랜치 맵 선형 탐색 → 타깃 바이트 오프셋 → `sub_resync`
     → dispatch. 미발견 시 타깃 값을 그대로 오프셋으로 폴백.
   - not-taken: 스트림이 이미 다음 명령을 가리키므로 그대로 dispatch.

5. **ip_map 배선** — `build_self_decoding_parts_with`/`run_native_poly_direct_with`
   (ip_map 파라미터 추가), 기존 `build_self_decoding_parts`/`run_native_poly_direct`는
   ip_map=None 위임(하위 호환). `build_program_vm_commercial`(commercial_build.rs)과
   `place.rs` 상용 경로에 ip_map을 전달.

## 검증 상태

- `cargo check --lib` → exit 0 (구현 완료 시점).
- `cargo test --release --lib vm::threaded::poly_direct` → **11/11 green** (세션 2 완료 시점):
  기존 linear-block/native-call-bridge/bitscan/compare-exchange/multiply/setcc-cmov/
  divide + VirtualBranch 차등 2개 전부 통과.
- VirtualBranch 차등 테스트 2개(`test_poly_direct_virtual_branch_forward_reverse_*`,
  `test_poly_direct_virtual_branch_ipmap_resolution_*`) **green**:
  - 미해결 AV의 근본 원인 = **`sub_eval_cond`가 R8L을 setcc 결과로 clobber** — R8은
    bytecode_base인데 taken 분기 직후 `sub_resync`→`sub_decrypt`가 `[R8+R12]`를 읽어
    키가 깨지고 가비지 디스패치 → AV. setcc 결과를 `AL`로 변경해 해결.
  - 순방향+역방향 rolling-key 재동기화, ip_map→바이트오프셋 분기 해석 모두 참조
    `eval_state`와 전 상태(regs/temps/flags/vsp/stack) 동치.

## 세션 2 (continuation) — 추가 수정

롤백 복원 후 전체 회귀 green을 위해 아래를 함께 수정했다:

1. **`sub_eval_cond` R8 clobber** — 위 AV 해결 (AL 사용).
2. **ADD stale-cin** — `emit_sub`가 DEC_CIN에 cin=1을 남기는데 즉시 피연산자 add가
   그것을 더해 777→778 오류. ADD 핸들러가 DEC_CIN을 0으로 초기화.
3. **ADD PF** — 참조 `update_add64`가 결과 parity로 PF를 갱신하나 네이티브가 보존만 함.
   `test` 후 0xC4(ZF|SF|PF) 캡처 + `FLAG_MASK`에 PF(0x4) 포함(0x8C5).
4. **divide 차등 테스트 operand 설정** — RDX(regs[2])를 IDIV 피제수 상위로 셋업하지
   않아 하드웨어 `#DE`(STATUS_INTEGER_OVERFLOW) → 테스트가 RAX/RDX를 재설정.
5. **encoder/decoder 스트림 비대칭** — 인코더가 `imm != 0` op(스케일 쉬프트
   `ShiftLeft with_imm(1/2/3)`)에 trailing 8B를 썼으나 decoder/interpreter/native가
   소비하지 않아 상용 전체 프로그램 스트림이 첫 스케일 쉬프트에서 desync → 인코더를
   AddWithCarry cin에만 trailing 8B로 제한.
6. **`decode_full` (Halt 미중단)** — `PolymorphicDecoder::decode`가 첫 Halt에서
   중단해 전체 프로그램(448개 Halt)의 branch-map이 첫 블록만 커버 → `decode_full`
   추가로 전체 바이트코드의 op 오프셋 확보. branch_map이 ip_map 18,303개 전부 포함.
7. **ip_map 배선** — `place.rs`가 `lift_program_cfg_commercial`의 ip_map을
   `build_program_vm_commercial`에 전달(기존 None) → 상용 모듈 branch-map에 source-IP
   해석 포함.
8. **commercial table blob + branch_map** — `build_program_vm_commercial`의 테이블이
   0xB00 + branch_map으로 확장(VirtualBranch 핸들러가 `[R15+(OFF_BRANCH_MAP-OFF_TABLE)]`
   에서 맵을 읽음). 테스트 단언 0xB00→0xB00+4 갱신.
9. **BOOT_AREA_RESERVE 0x80000→0x120000** — branch_map 293KB + bytecode 335KB가
   0x80000 예약 초과("Boot area layout overlap") → 상한 확대 (crypto.rs가 실제
   boot_end로 트림하므로 최종 파일 크기 영향 없음).

## 최종 회귀 (세션 2 완료 시점)

- `cargo build --release` → exit 0.
- `cargo test --release --lib` → **236 passed; 0 failed** (11 poly_direct 포함).
- `--vm` / `--vm --vm-oep` pack→run → **16개 테스트 전체 통과**, FINAL CHECKSUM
  `0x2cdc0e4511d84a64` = baseline 동일 (무회귀).
- `--vm --vm-oep --vm-commercial` → **pack exit 0** (기존 pack 단계에서 상용 모듈
  branch_map 미구현→desync→AV가 pack 도중 실패하던 것이 해소). **run은 여전히
  0xC0000005** — whole-program 실행이 배제(native/SEH) 함수 호출을 네이티브 브리지로
  전환하지 못함 (아래 "남은 것").

## 남은 것 → 해소 (네이티브 콜 브리지 구현)

상용 whole-program run의 0xC0000005(배제 함수 콜)가 **네이티브 콜 브리지** 구현으로
해소되었다 (후속 세션):

- `src/vm/threaded/poly_direct.rs` `h_branch`의 branch-map **not-found 경로**가
  바이트 오프셋 폴백 대신 레거시 `OP_NATIVE_CALL`급 네이티브 콜 브리지를 수행한다:
  1. 가상 스택에서 ret_ip pop,
  2. state_base/bytecode_base를 callee-saved(R12/R14)에 스테이지,
  3. state 버퍼의 GPR(RAX/RCX/RDX/R8/R9/R10/R11)을 Win64 인자로 실장,
  4. RSP 16B 정렬 + 0x70 프레임(홈 0x20 + 스택 인자 5..12, 가상 스택에서 전달),
  5. `call target`, 휘발성 GPR+RFLAGS를 state로 동기화,
  6. 인프라(RDX/R8) 복원 후 ret_ip를 branch-map으로 해석 → rolling-key 재동기화
     (`sub_resync`, R12=0·R14=init_key에서 순방향) → dispatch.
- `src/vm/text_lift/commercial.rs`에 **OEP entry-jump** 추가: CfgExtractor 주소순 블록
  나열에서 OEP가 바이트코드[0]이 아니므로 `VirtualBranch(Always) → OEP`를 프로그램
  맨 앞에 prepend (레거시 `lift_cfg_switch(.., Some(entry_va))`와 동일). 그 전엔 VM이
  .text 시작부부터 실행해 첫 분기에서 가비지 타깃으로 AV.
- **검증**: `--vm --vm-oep --vm-commercial` pack→run → **16개 테스트 전체 통과 +
  FINAL CHECKSUM `0x2cdc0e4511d84a64`** (= baseline, 3회 반복 안정). `cargo test
  --release --lib` → 236 passed; 0 failed. `--vm`/`--vm-oep` 무회귀.
- 기록: `docs/P3-handlers-wired-and-verified.md` §5, `docs/P3-commercial-selfdecoding-fix.md`.
