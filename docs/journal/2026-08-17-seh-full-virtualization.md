# 2026-08-17 — P4 최종: 전체 SEH 가상화 + .pdata 브리지 UNWIND_INFO

> repo `asdfsadfecwecc` · branch `main` (working tree) · node `ujiwo-zyris-code`

## 요청
".pdata 재생성(브리지 UNWIND_INFO) 통한 전체 SEH 가상화하고 SEH 네이티브 집합을 최소화해보자"

## baseline
- `cargo build --release` green · `cargo test --release --lib` → **285 passed; 0 failed**.
- `--vm --vm-oep` 16테스트 + FINAL CHECKSUM `0x2cdc0e4511d84a64` (SEH native 132).

## 진행 (전부 실측)
1. **`BTG_SEH_NONE=1` (0 native) 실험**: SEH/panic/catch 전부 가상화 → **16테스트 전부
   통과 + checksum 동일**, 그러나 **exit-time teardown 0xC0000005**.
   cdb: `_seh0_pack+0xbd208: xchg eax,dword ptr [r11]` with `r11=0xfffffffffffffffe`.
   → 가상화된 Rust `Once` 완료 경로가 `mov rcx,[rbp-0x18]`로 **낡은 프레임 로컬 -2**를
   읽어(block 단위 디스패치가 switch 타깃을 프로로그 없이 진입), 그 -2를 xchg 주소로 사용.
2. **원인 분류**: 피해 함수 `0x14002daf0` (Once::call_once) = EHANDLER(UHANDLER 포함) +
   **computed-jump(jmp table switch)**. VM의 블록 단위 디스패치로는 이 클래스의
   프레임-로컬 정합을 보장할 수 없음(프로로그가 실행된 뒤의 프레임 저장이 선행 보장 안 됨).
3. **해결 — SEH는 전부 가상화 + teardown 안전망만 네이티브 (132 → 49)**:
   - `detect_seh_native_functions`에 `full_seh_virtualize` 파라미터 추가
     (`BTG_SEH_NONE=1`은 legacy `--vm --vm-oep` 경로에서만 유효).
   - `seh_none` 브랜치: native = (a) **computed-jump EHANDLER ∩ can_reach_panic**
     (`fn_has_computed_jump` — switch-dispatch 프레임 보호),
     (b) **Once/panic shared-state `.data/.bss` 함수**
     (`detect_runtime_shared_global_functions` — teardown 완료 경로 보호).
   - 결과: **49 함수 / 0x5932B 테두리**, 16테스트 + checksum + **exit 0**, 5회 안정, cdb clean.
4. **`.pdata` 재생성(브리지 UNWIND_INFO) — Program-VM 영역 전체 커버**:
   - `ctx.vm_prog_rva/vm_prog_total` 추가 (place.rs에서 기록).
   - `build.rs` `update_pdata_seh`: Program-VM 모듈 `[vm_prog_rva .. +total)`을
     RUNTIME_FUNCTION으로 등록하고, **실제 엔트리 프로로그(sub rsp,0xA0; cld;
     movdqu xmm6..15; push rax..r11,r15..r12)** 를 디코드해 유도한 UNWIND_INFO
     (`vm_entry_unwind_ops` + `build_vm_entry_unwind_info` — UWOP_ALLOC_LARGE(160),
     PUSH_NONVOL, **CodeOffset 내림차순** = PE/COFF 스펙)를 `.pdata` 뒤에 배치.
   - VM 내부 예외 시 OS unwinder가 더미 핸들러 없이 결정적으로 VM 프레임 밖으로 unwind.
   - 부트 스텁은 Program-VM으로 **tail-jmp**하므로(중간 프레임 없음), 엔트리 프레임
     하나만 커버하면 충분.
5. **게이트**: `--vm`(block-shuffle)은 이질적 블록 프레임이라 단일 UNWIND_INFO 불가 →
   132 유지. `--vm-commercial`(RISC 엔진)도 전체 SEH 가상화 미검증 → 132 유지
   (pass1_slice는 `ctx.vm_oep && !ctx.vm_commercial`로 게이트).

## 검증 (신선, seed 1234)
| 경로 | native | pack | run | checksum |
|---|---|---|---|---|
| `--vm --vm-oep` (기본) | 132 | exit 0 | 16테스트 + exit 0 | `0x2cdc0e4511d84a64` |
| `--vm --vm-oep` + `BTG_SEH_NONE=1` | **49** | exit 0 | 16테스트 + exit 0 | `0x2cdc0e4511d84a64` |
| `--vm` (게이트) | 132 | exit 0 | 16테스트 + exit 0 | `0x2cdc0e4511d84a64` |
| `--vm --vm-oep --vm-commercial` + `BTG_SEH_NONE=1` (게이트) | 132 | exit 0 | 16테스트 + exit 0 | `0x2cdc0e4511d84a64` |

`.pdata`: 750 entries(원본 748 + bridge leaf + Program-VM bridge), UNWIND_INFO
`ver=1 SizeOfProlog=105 CountOfCodes=16` — ALLOC_LARGE(160) + PUSH_NONVOL(rbx/rbp/
rsi/rdi/r12..r15) 내림차순, 로더 수용 확인(STATUS_INVALID_IMAGE_FORMAT 없음).

## 변경 파일
- `src/vm/text_lift/exclusions.rs` — `BTG_SEH_NONE` + `fn_has_computed_jump` +
  `detect_runtime_shared_global_functions` + `full_seh_virtualize` 파라미터.
- `src/vm/text_lift/mod.rs` / `commercial.rs` / `src/pipeline/pass1_slice.rs` — 게이트 배선.
- `src/pipeline/build.rs` — `vm_entry_unwind_ops`/`build_vm_entry_unwind_info` +
  `update_pdata_seh` Program-VM 브리지 커버.
- `src/pipeline/place.rs` / `mod.rs` — `vm_prog_rva/vm_prog_total` 기록.
- `docs/roadmap/milestones.md`, `docs/roadmap/COMMERCIAL-VM-UPGRADE-PLAN.md`, `README.md`.

## 남은 것
- `--vm-commercial`(RISC 엔진)에서도 전체 SEH 가상화(49) 검증 — RISC 리프트 퓨전리티
  갭 해소 후.
- computed-jump EHANDLER가 아닌 다른 프레임-로컬 취약 함수가 타깃/컴파일러에 따라
  추가될 수 있음 → `BTG_SEH_NONE` 계측으로 재검증 필요.
