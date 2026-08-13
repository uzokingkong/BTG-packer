# Milestones — 완전한 VM 컴파일러 진행 체크리스트

> 상태 마커: ✅ 완료 · 🔶 진행 중 · ⬜ 미착수 · ⚠️ 부분/리스크
> 업데이트: 2026-08-13 (v13.5, Phase 1 완료)

## Phase 0 — 기준점 & 저장소 정리 ✅
- [x] baseline 커밋 (`4406b77`): v13.4e 두-스택 VM 상태의 미커밋 17개 소스 +
      미추적 CHANGES.md/리포트/test 픽스처를 정리해 커밋.
- [x] `.gitignore` 추가 (빌드 산출물 / packed*.exe / 디버그 스크래치 / 로그).
- [x] `cargo build --release` green.
- [x] `--vm-test` [1..34] ALL PASS 기록.

## Phase 1 — 긴 .rs 파일 분해 ✅ (동작 변경 0, 순수 코드 이동)

| 파일 | 라인 | 상태 | 산출 커밋 |
|---|---|---|---|
| `vm/bytecode.rs` | 1216 | ✅ | `vm/bytecode/{mod,registry,builder,disasm,tests}.rs` (`bb706f4`) |
| `vm/handlers.rs` | 2438 | ✅ | `vm/handlers/` (`1988057`) |
| `vm/lifter.rs` | 2690 | ✅ | `vm/lifter/` (`dd3ee48`) |
| `vm/interp.rs` | 1294 | ✅ | `vm/interp/` (`194bb64`) |
| `vm/self_test.rs` | 4285 | ✅ | `vm/self_test/` (`33daba2`) |
| `vm/text_lift.rs` | 1100 | ✅ | `vm/text_lift/` (`02a3acc`) |
| `pipeline/crypto.rs` | 2793 | ✅ | `pipeline/crypto/` (`819b11a`) |
| `dispatcher/mod.rs` | 1218 | ✅ | `dispatcher/{mod,build,validate,reencrypt,tests}.rs` (`633cfaa`) |
| `pipeline/validate.rs` | 718 | ✅ | `pipeline/validate/{mod,rsrc,tests}.rs` (`e5178ae`) |
| `pipeline/patch_data.rs` | 896 | ✅ | `pipeline/patch_data/{mod,imports}.rs` (`a3d6795`) |
| `obfuscation/mba.rs` | 571 | ✅ | `obfuscation/mba/{mod,codegen,tests}.rs` (`c7a4f2b`) |
| `pipeline/text_lift.rs` | 1009 | ✅ 삭제 | 고아 중복 (선언 없음, 호출부 전부 `vm::text_lift`) (`9b7ec0d`) |
| `main.rs` 엔트로피 | — | ✅ | → `analysis/entropy.rs` (`9b7ec0d`) |

**검증 룰 (각 파일마다)**: `cargo build --release` green + `cargo test` green +
`--vm-test` ALL PASS + 문자열/hex 리터럴 회귀 0.

### 진행 노트
- 2026-08-13: `text_lift.rs` 분해를 PowerShell `Set-Content`로 시도했으나
  UTF-8 한글 주석이 깨져 **리버트**(`git checkout HEAD --`). 교훈: 한글 포함
  파일은 code_edit / python io(utf-8) 로만 편집.
- 2026-08-13: Phase 1 완료. 각 분해 후 `cargo build --release` green +
  `cargo test`(68) + `--vm-test` ALL PASS + 리터럴 회귀 0 확인.
  분해 시 주의점: (1) `mod tests`를 별도 파일로 뺄 때 이중 `mod tests` 중첩 방지
  (mod.rs가 이미 `mod tests;` 선언), (2) 함수 앞 doc-comment가 절단 경계에 걸려
  dangling이 되지 않게 이동, (3) `pub(crate)` 필드/타입 접근, (4) `pub`과
  `pub(crate)`의 bin/lib 가시성 차이.

## Phase 2 — 컴파일러 프론트엔드 (IR + 커버리지 + 전체 가상화) ⬜

### 2.1 명령 커버리지 완결 ✅ (2026-08-13, v55)
- [x] `--text-vm` 진단이 출력하는 미지원 명령 목록을 `coverage.md`로 고정
      (2026-08-13, rust_packer_test.exe: 26,956/26,956 = **100.00%**;
      잔여 lock inc/dec→v55 opcode + `Xor_RAX_imm32` 라우팅으로 해소).
- [x] SSE/FPU, BMI1/2(tzcnt/lzcnt/popcnt), 문자열 ops(movs/stos/scas),
      CMOVcc를 그룹별(opcode+핸들러+리프터+인터프리터+테스트) 한 벌로 추가
      (self-test [35] CMOVcc, [36] 문자열, [37] BMI1/2, [38] SSE/FPU,
      [39] LOCK inc/dec — 2026-08-13).
- [x] 시스템/특권 명령은 명시적 제외로 문서화 (`coverage.md` §3).

### 2.2 제외 블록 제거 ✅
- [x] lock-atomic RMW 휴리스틱(`block_has_lock_atomic_on_global`,
      `block_has_lock_memory_rmw`, LOCK-RMW 함수 격리)을 VM opcode로 대체
      (CMPXCHG/XCHG/XADD v46-v49 + LOCK INC/DEC v55) → lock 블록은 이제
      정확한 원자 VM opcode로 가상화. 제외 필터에서 두 넷 제거 (2026-08-13).
- 잔여 제외 = SEH 구조적 제외(panic/unwind 런타임 함수 + shared-state
  global 참조 블록) — SEH 메타데이터 정합 때문에 설계상 네이티브 유지
  (휴리스틱이 아닌 정확성 요건; `exclusions.rs` 주석 참조).
- ⚠️ 기존 결함(베이스라인 0cb48c6에서도 재현): `--full --vm --vm-oep`
  packed rust_packer_test.exe가 즉시 0xC0000005 크래시(출력 없음).
  Phase 2.4(부트 정합)/Phase 3(샘플 실행 회귀)에서 추적 예정.
  `--full --vm`(no --vm-oep)은 이 타깃에서 --iat-hide+TLS callback 충돌로
  패킹 자체 불가 (의도된 거부).

### 2.3 IR 프론트엔드 ✅ (2026-08-13, v56)
- [x] `lift_one` 1:1 매칭을 경량 IR(`VInstr`)로 승격: `lifter/ir.rs` —
      assemble된 바이트스트림을 parse→(op+label+분기 메타 보존)→passes→
      emit(분기 재해결, rel8→rel32 확장 포함)하는 파이프라인.
      `lift_block`/`lift_cfg_switch`는 IR 경유(--map/--sym-map 진단 모드는
      오프셋 보존을 위해 레거시 경로 유지).
- [x] 레지스터 맵핑(vreg 0..19 = 16 프로그램 GPR + lifter scratch) + 상수
      폴딩(mov-family 상수 전파) + 죽은 코드 제거(dead-mov elim) + peephole
      (self-mov64 제거). 플래그/메모리/라벨/분기를 span 경계로 한 보수적
      mov-only 패스 → 정확성 보장(self-test [40]).
- [x] M4 검증(dummy_fn 동치) 유지 — [14] PASS, 전체 --vm-test ALL PASS.
      (부수 수정: 레거시 `BytecodeBuilder::widen_branch`가 JCC8 확장 시 cond
      바이트를 opcode로 오독하던 잠복 버그 수정 — [A2] 테스트가 발동.)

### 2.4 전체 프로그램 가상화 + 부트 정합 ⬜
- [ ] `lift_program_cfg`를 전체 .text로 확장.
- [ ] `entry_native` 브랜치 제거, 부트스텁이 항상 프로그램 VM으로 진입.
- [ ] 종료 teardown 패닉(`once.rs:166`) 해결.

### 2.5 핸들러 성능 🔶 (2026-08-13, threaded-dispatch 완료 / 퓨전 잔여)
- [x] **threaded-dispatch**(v58): 핸들러마다 `jmp Dispatch` 왕복 제거 —
      `emit_dispatch`(movzx/inc/table-load/xor/jmp)를 각 핸들러 epilogue에
      인라인. VM 명령당 간접 점프 1회로 감소.
- [x] **MBA 키 1회 유도**: 디스패치마다 13개 명령으로 K=a+b를 재유도하던 것을
      VM 엔트리에서 r15에 1회 유도 + 매 디스패치 `xor rax,r15`. 동일 보안 속성
      (a/b 평문 비노출, 테이블 XOR-mask 유지). plain 경로는 r15=0.
- [x] `--vm-bench` 측정: main ~23.4µs/iter → crypto-refactor ~14-17µs/iter
      (**~1.5x**, 교차 실행 기준). 2x 목표는 **핸들러 퓨전으로 잔여**.
- [x] 부수 픽스: f0f56eb가 아레나 테이블 복사를 0x4800으로 옮기면서
      `run_bridge_abi_check`의 `vt`(0x4000)를 안 바꿔 디스패치가 가비지를
      읽던 크래시(0xC0000005) 해소 → **--vm-test [1..40] ALL CHECKS PASSED**
      복구 (`494af70`).
- [ ] 핸들러 퓨전 (슈퍼인스트럭션: movzx+alu 등) — 2x 목표 도달용.
- ⚠️ `--vm`(non-OEP) 패킹 산출물 실행 크래시(ntdll!_chkstk)는 main에서도
      재현되는 기존 부트/VM 통합 결함 계열 — `problem.txt`에 기록.

## Phase 3 — 문서 & 마무리
- [x] `docs/vm-compiler-architecture.md` — 모듈 지도 + 절단 지점.
- [x] `docs/coverage.md` — 명령 커버리지 베이스라인.
- [x] `docs/milestones.md` — 이 체크리스트.
- [ ] 전체 `--vm-test` + `--full` pack 회귀 + 샘플 타깃 실행 확인 (Windows 호스트 필요).
