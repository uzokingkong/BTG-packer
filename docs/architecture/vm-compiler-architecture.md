# VM Compiler Architecture

> 문서 상태: v60 — **Phase 1~4 상용급 폴리모픽 VM 엔진 & SDK 통합 완료**. 갱신: 2026-08-14.
> 저장소: `vm-obf` (BTG Packer). 이 문서는 "완전한 VM 컴파일러"로 가는
> 모듈 지도입니다. 세부 상용 아키텍처는 `commercial-vm-engine.md`를 보세요.

## 1. 목표

원본 `.text` 를 평문으로 존재시키지 않고, 프로그램 전체를 VM 바이트코드로만
실행하게 만든다. 현재는 CISC x86을 12개 원시 연산자(NOR, ADC)로 분해하는
RISC De-synthesis, 빌드별 시드 기반 다형성(Polymorphic ISA), 롤링 키(Rolling Key)
동적 복호화, 직접 스레딩(Direct Threading) 및 C/C++/Rust SDK 선택적 가상화
엔진(Phase 1~4)이 구현되었습니다.

## 2. 현재 모듈 지도 (v60, Phase 1~4 완료)

### 진입 / 파이프라인
- `src/main.rs` — CLI 플래그 정규화 (`--full`/`--vm-oep` 우선순위).
- `src/cli.rs` — clap 인자 정의.
- `src/lib.rs` — 라이브러리 API `pack()`.
- `src/pipeline/` — Pass1(CFG 슬라이스) → Pass2(셔플) → Pass3(인코드) →
  Pass4(섹션) → patch_data → selective_vm → crypto → build.
  - `selective_vm.rs` — [NEW] C/C++/Rust SDK 마커 스캔 및 선택적 가상화 컴파일 패스.

### 상용급 폴리모픽 VM 엔진 (Phase 1~4)
- `src/vm/risc/` — [Phase 1] 12개 원시 마이크로 연산자, CISC-to-NOR/ADC De-synthesis 리프터, 가상 플래그 시뮬레이터, 최적화기.
- `src/vm/poly/` — [Phase 2] 빌드 시드 기반 가변 Opcode/레지스터 셔플링 ISA 명세, 롤링 키 스트림 암호 엔진, 인코더/인터프리터.
- `src/vm/threaded/` — [Phase 3] 중앙 루프 없는 직접 Tail-Call 점프 생성기, 슈퍼 오퍼레이터 합성기, 핸들러 인라인 MBA, 네이티브 실행기.
- `src/sdk/` — [Phase 4] `BTG_VM_START` / `BTG_VM_END` 마커 인터페이스, 선택적 가상화기, LLVM IR 인제스천 인터페이스.

### 레거시/기본 VM 컴파일러 코어 (`src/vm/`)
- `bytecode/` — `{mod,registry,builder,disasm,tests}.rs`. `registry.rs`의
  `opcodes!` 매크로가 opcode 집합의 단일 진실 공급원 (현재 138 opcode).
- `handlers/` — `{mod,alu,mov,mem,branch,stack,xmm,atomic,muldiv}.rs`.
- `interp/` — `{mod,state,arith,mov,mem,branch,stack,xmm,atomic,muldiv}.rs`.
- `lifter/` — `{mod,arith,mov,mem,control,cfg,muldiv,shift,sse,string}.rs`.
- `text_lift/` — `{mod,switch,exclusions,tests}.rs` (프로그램 CFG lift,
  switch 해석, panic/unwind/lock-atomic 제외).
- `self_test/` — `{mod,flags,mem,stack,addr,bridge,lift,a2_a5,abi,text,
  multiblock,muldiv,sse,exit}.rs` (`--vm-test` 스위트 [1..34]).
- 보조: `mapper.rs`, `mem_model.rs`, `flags.rs`, `arena.rs`, `encode.rs`,
  `bench.rs`, `ksa.rs`, `prga.rs`, `import_key.rs`.

### 기타
- `dispatcher/` — `{mod,build,validate,reencrypt,tests,antidebug}.rs`
  (static 디스패처 + 재암호화 디스패처, 분해 완료).
- `obfuscation/mba/` — `{mod,codegen,tests}.rs` (MbaPolynomial 생성 +
  `to_x86_64_code` 코드젠 분리, 분해 완료).
- `graph/` — CFG 추출/슬라이서/셔플/픽스업. `pe/`, `assembler/`, `btg/`,
  `core/`, `antidebug/`, `analysis/`(`metrics.rs`+`entropy.rs`), `debug/`,
  `qa/`, `util/`, `error.rs`.

## 3. Phase 1 분해 — 완료 ✅

모든 긴 단일 파일이 디렉터리 모듈로 분해됨 (`../roadmap/milestones.md`의 표 참조).
순수 코드 이동 원칙: 공개 API 불변, `cargo build --release` green +
`cargo test`(68) + `--vm-test` ALL PASS + 문자열/hex 리터럴 회귀 0.

각 파일의 절단 구조 (참고):
- `handlers/` — `generate_vm_code`의 `// ── 0x.. / M.. / v..` 섹션 경계.
- `lifter/` — `lift_one`의 `Code::` 팔 그룹별.
- `interp/` — `interpret` 루프의 팔 그룹별 + `state.rs`.
- `self_test/` — 테스트 그룹별.
- `crypto/` — RC4/채널/부트스텁/문자열 런/테스트.
- `validate/` — 리소스 트리 검증(`rsrc.rs`) 분리.
- `patch_data/` — import/delay-import RVA 범위 수집(`imports.rs`) 분리.
- `mba/` — `to_x86_64_code`를 별도 `impl` 블록(`codegen.rs`)으로 분리.

## 4. 컴파일러 프론트엔드 (Phase 2 로드맵)

1. **IR 승격**: `lift_one`의 1:1 매칭을 경량 IR(`VInstr`)로 승격.
   레지스터 맵핑(16 vreg) + 상수 폴딩 + 죽은 코드 제거 + peephole.
   M4 검증(dummy_fn 동치) 유지.
2. **커버리지 완결**: `--text-vm` 진단이 뽑는 미지원 명령을 그룹별로
   opcode+핸들러+리프터+인터프리터+테스트 한 벌로 추가.
3. **제외 블록 제거**: lock-atomic RMW / panic-unwind 블록을 VM opcode로.
4. **전체 .text 가상화 + 부트 정합**: `entry_native` 브랜치 제거,
   OEP→VM 진입 고정, `once.rs:166` 종료 패닉 해소.
5. **핸들러 성능**: threaded-dispatch(`emit_dispatch`를 각 핸들러 epilogue에
   인라인 → `jmp Dispatch` 왕복 제거) + MBA 테이블 키를 VM 엔트리에서 r15에
   1회 유도(`xor rax,r15`로 디스패치당 13→1 명령) 완료 (v58, 2026-08-13).
   `--vm-bench` ~1.5x (23.4→14-17µs). 2x 목표는 핸들러 퓨전으로 잔여.
   레지스터 계약: r8=state, r9=bytecode ip, r10=table, **r15=MBA 키 K(또는 0)**,
   rax/rcx/rdx/r11=scratch.

## 5. 패킹 산출물 부트/실행 정합 (2026-08-13~14 조사 결과)

BTG 패커는 실제 실행 코드를 `.textb` 블록(셔플+RC4)으로 옮기고, 부트 스텁이
진입점에서 복호화 후 디스패처로 제어를 이관한다. 이 경로의 크래시 3건을 추적:

- **TLS 콜백 부트 크래시 (해소, `31522f0`)**: v14가 원본 `.text` 전체를
  boot-decrypt run으로 암호화했는데, PE 로더는 TLS 콜백을 **엔트리보다 먼저**
  실행하므로 콜백이 암호문을 실행. 수정: `.text` run 제거(평문 안전 복사본
  유지) → `--vm` 패킹 exe가 테스트 [1..8] 통과.
- **test [9] System-allocator TLS abort (해소, `4a97696`)**: TLS raw-data 템플릿
  `[StartAddressOfRawData..EndAddressOfRawData)`이 protected에 없어 암호화 →
  로더가 부트 전에 모든 스레드의 TLS 슬롯(`#[thread_local]` 정적, std의 DTORS
  RefCell 포함)을 암호문으로 초기화 → 첫 `thread_local!`-with-dtor 등록에서
  `DTORS.try_borrow_mut()` 실패 → `std::rt` abort. 수정: `collect_protected_rva_ranges`
  에 TLS 템플릿 범위 추가 → --vm/--chained [1..9] 통과.
- **test [10] SEH catch_unwind (해소, SEH 함수 비셔플)**: 셔플 블록이 `.pdata`
  커버리지 밖이라 OS unwind가 catch frame에 도달 못했음. .pdata 수정 2회 시도
  (per-block virtual-Begin → 로더 거부, 함수 연속 레이아웃 + per-function .pdata
  + FuncInfo/CHAININFO 재작성 → panic 경로 회귀)는 모두 원복. **해결책**:
  `pass1_slice`가 panic/catch unwind 경로 함수를 셔플에서 제외해 원본 `.text`
  (평문 안전 복사본)에 유지 — `.pdata`/UNWIND_INFO/FuncInfo가 원본 주소 그대로
  유효하므로 OS unwind가 온전. 선택 규칙(`exclusions.rs::detect_seh_native_functions`):
  panic 문자열 참조 함수 ∪ EHANDLER/UHANDLER 함수 ∪ (direct call로 panic 함수에
  도달 가능 + EHANDLER 함수에 도달 불가 = raise~catch 사이 프레임) − entry 함수.
  셔플 블록 → 네이티브 분기는 pass3 `resolve_va_to_real_va`가 원본 주소를 유지하고,
  `slicer.rs`의 jcc는 네이티브 타깃에 원본 분기를 유지한다. 이 타깃에서 .text의
  ~28%(175 함수)가 네이티브 유지되며 --vm/--chained/plain 패킹 [1..16] 전체 통과.

세부 우선순위/검증 기준은 `../roadmap/milestones.md` 참조.
