# VM Compiler Architecture

> 문서 상태: v13.5 정리 시작점. 작성: 2026-08-13.
> 저장소: `vm-obf` (BTG Packer). 이 문서는 "완전한 VM 컴파일러"로 가는
> 모듈 지도입니다. 실제 리팩터 진행 상황은 `milestones.md`를 보세요.

## 1. 목표

원본 `.text` 를 평문으로 존재시키지 않고, 프로그램 전체를 VM 바이트코드로만
실행하게 만든다. 지금은 "x86 → VM 1:1 리프터 + 네이티브 폴백" 단계이고,
목표는 "컴파일러급 프론트엔드(IR + 레지스터 할당 + 최적화) + 100% 커버리지
+ 전체 .text 가상화 + 부트 정합"이다.

## 2. 현재 모듈 지도 (v13.4e)

### 진입 / 파이프라인
- `src/main.rs` — CLI 플래그 정규화 (`--full`/`--vm-oep` 우선순위, 566줄).
- `src/cli.rs` — clap 인자 정의 (172줄).
- `src/lib.rs` — 라이브러리 API `pack()` (37줄).
- `src/pipeline/` — Pass1(CFG 슬라이스) → Pass2(셔플) → Pass3(인코드) →
  Pass4(섹션) → patch_data → crypto(부트스텁+암호화+VM 임베드) → build.
  - `crypto.rs` (2793줄, 최대 단일 기능 파일), `text_lift.rs`(993),
    `patch_data.rs`(872), `validate.rs`(712), `iat_hide.rs`(464),
    `rsrc_register.rs`(427), `pass4_section.rs`(384), `pass3_encode.rs`(361),
    `build.rs`(242), `pass1_slice.rs`(198), `mod.rs`(190), `pass2_shuffle.rs`(79),
    `ondemand.rs`(114), `pack.rs`(58).

### VM 컴파일러 코어 (`src/vm/`)
- `bytecode.rs` → **v13.5 분해 완료** → `src/vm/bytecode/` 디렉터리:
  - `mod.rs`(재수출 레이어), `registry.rs`(opcodes! 매크로 + 상수 + 플래그),
    `builder.rs`(BytecodeBuilder 에미터 + 브랜치 픽스업),
    `disasm.rs`(디스어셈블러), `tests.rs`.
- `handlers.rs` (2438줄) — `generate_vm_code`가 단일 함수로 ~2200줄.
  섹션 마커(`// ──`)를 따라 opcode 그룹별로 쪼갤 수 있음(아래 §3).
- `interp.rs` (1294줄) — `interpret()` 단일 match ~1100줄.
- `lifter.rs` (2690줄) — `lift_one`(225~576)이 큰 `Code::` match.
- `text_lift.rs` (1100줄) — 프로그램 CFG lift(`lift_program_cfg`),
  switch 해석(`resolve_switch_cases`), panic/unwind 제외
  (`detect_panic_unwind_ranges`).
- `self_test.rs` (4285줄) — `--vm-test` 스위트.
- 보조: `mapper.rs`, `mem_model.rs`, `flags.rs`, `arena.rs`, `encode.rs`,
  `bench.rs`, `ksa.rs`, `prga.rs`, `import_key.rs`.

### 기타
- `dispatcher/mod.rs` (1218줄) — static 디스패처 + 재암호화 디스패처.
- `graph/` — CFG 추출/슬라이서/셔플/픽스업. `pe/`, `assembler/`, `mba/`,
  `obfuscation/`, `btg/`, `core/`, `antidebug/`, `analysis/`, `debug/`,
  `qa/`, `util/`, `error.rs`.

## 3. 분해 대상과 절단 지점 (Phase 1 로드맵)

순수 코드 이동(`pub use`로 공개면 유지 → 외부 API 불변). 각 파일 완료 후
`cargo build --release` green + `cargo test` green + `--vm-test` ALL PASS.

### 3.1 `handlers.rs` → `src/vm/handlers/`
`generate_vm_code`의 `// ── 0x.. / M.. / v..` 섹션 경계를 절단 지점으로:
- `mod.rs` — 엔트리 스텁, 디스패치 루프, invalid-opcode, 2-pass 레이아웃/인코딩,
  `validate_vm_code`, `Cl` enum, `hdr()` 헬퍼.
- `alu.rs` — 0x01~0x0E 산술/논리/imm, ROL/ROR, INC/DEC, CMP, TEST, 시프트,
  A-2(OR/NEG/NOT, 64비트 시프트), M2 64비트 산술.
- `mov.rs` — MOV 계열, MOVZX/MOVSX, 폭별 메모리 load/store.
- `mem.rs` — 어드레싱(LEA/LEA_RIP/LEA_GS, `mem_a`).
- `branch.rs` — JMP/JCC/JB(rel8/rel32), SETCC(v50), HALT.
- `stack.rs` — PUSH/POP/CALL/RET/RET_IMM16(두-스택), 네이티브 브리지.
- `xmm.rs` — XMM 이동/unpckl/xorps/pshuf/psrlq/psllq/pinsrw.
- `atomic.rs` — cmpxchg(v46/v49), xchg/xadd(v48).
- `muldiv.rs` — MUL/DIV/IMUL/IDIV/BSWAP(v31/v33, 8/16/32/64).

### 3.2 `lifter.rs` → `src/vm/lifter/`
- `mod.rs` — `LiftedInstr`, `lift_one` 디스패치 프레임, `lift_ksa`,
  `lift_block`, `lift_cfg`, `lift_cfg_switch`.
- `arith.rs` / `mov.rs` / `mem.rs` / `xmm.rs` / `control.rs` / `atomic.rs` /
  `diag.rs`(`diagnose_unsupported`) — `lift_one`의 `Code::` 팔을 그룹별로.

### 3.3 `interp.rs` → `src/vm/interp/`
- `mod.rs` — `interpret` 루프 + 디스패치.
- 그룹별 팔 파일 + `state.rs`(vreg/flags/ptr_slot/sp 헬퍼).

### 3.4 `self_test.rs`(4285줄) → `src/vm/self_test/`
- `mod.rs` — `run_self_test` 오케스트레이터.
- 테스트 그룹별: `flags.rs`/`mem.rs`/`stack.rs`/`addr.rs`/`bridge.rs`/
  `lift.rs`/`a2_a5.rs`/`abi.rs`/`text.rs`/`multiblock.rs`/`muldiv.rs`/`sse.rs`.

### 3.5 `pipeline/crypto.rs`(2793줄) → `src/pipeline/crypto/`
- `mod.rs`(오케스트레이션), `rc4.rs`(RC4/chained), `bootstub.rs`(부트스텁),
  `vm_embed.rs`(VM 임베드), `iat.rs`/`memharden.rs`/`integrity.rs`/
  `payload.rs`/`reencrypt.rs`.

### 3.6 `bytecode.rs` — ✅ v13.5 완료 (위 §2 참조)

### 3.7 `text_lift.rs`(1100줄) → `src/vm/text_lift/`
- `mod.rs` — `lift_program_cfg`/`analyze_text_lift`.
- `exclusions.rs` — panic/unwind/lock-atomic 제외 휴리스틱.
- `switch.rs` — `resolve_switch_cases`.
- 주의: 이 파일은 UTF-8 한글 주석이 많아, PowerShell `Set-Content`로
  슬라이싱하면 인코딩이 깨질 수 있음(이미 1회 경험). 반드시 UTF-8-safe
  수단(code_edit / `-Encoding UTF8` 읽고 쓰기)으로만 편집할 것.

### 3.8 `dispatcher/mod.rs`(1218줄)
- `mod.rs`(`build_dispatcher`/static/validate), `reencrypt.rs`, `tests.rs`.

## 4. 컴파일러 프론트엔드 (Phase 2 로드맵)

1. **IR 승격**: `lift_one`의 1:1 매칭을 경량 IR(`VInstr`)로 승격.
   레지스터 맵핑(16 vreg) + 상수 폴딩 + 죽은 코드 제거 + peephole.
   M4 검증(dummy_fn 동치) 유지.
2. **커버리지 완결**: `--text-vm` 진단이 뽑는 미지원 명령을 그룹별로
   opcode+핸들러+리프터+인터프리터+테스트 한 벌로 추가.
3. **제외 블록 제거**: lock-atomic RMW / panic-unwind 블록을 VM opcode로.
4. **전체 .text 가상화 + 부트 정합**: `entry_native` 브랜치 제거,
   OEP→VM 진입 고정, `once.rs:166` 종료 패닉 해소.
5. **핸들러 성능**: threaded-dispatch/핸들러 퓨전, `--vm-bench` 2x.

세부 우선순위/검증 기준은 `milestones.md` 참조.
