# VM Compiler Architecture

> 문서 상태: v13.5 — **Phase 1 분해 완료**. 작성: 2026-08-13.
> 저장소: `vm-obf` (BTG Packer). 이 문서는 "완전한 VM 컴파일러"로 가는
> 모듈 지도입니다. 실제 리팩터 진행 상황은 `milestones.md`를 보세요.

## 1. 목표

원본 `.text` 를 평문으로 존재시키지 않고, 프로그램 전체를 VM 바이트코드로만
실행하게 만든다. 지금은 "x86 → VM 1:1 리프터 + 네이티브 폴백" 단계이고,
목표는 "컴파일러급 프론트엔드(IR + 레지스터 할당 + 최적화) + 100% 커버리지
+ 전체 .text 가상화 + 부트 정합"이다.

## 2. 현재 모듈 지도 (v13.5, Phase 1 분해 완료)

### 진입 / 파이프라인
- `src/main.rs` — CLI 플래그 정규화 (`--full`/`--vm-oep` 우선순위). 엔트로피
  리포트는 `analysis/entropy.rs`로 이동됨.
- `src/cli.rs` — clap 인자 정의.
- `src/lib.rs` — 라이브러리 API `pack()`.
- `src/pipeline/` — Pass1(CFG 슬라이스) → Pass2(셔플) → Pass3(인코드) →
  Pass4(섹션) → patch_data → crypto(부트스텁+암호화+VM 임베드) → build.
  - `crypto/` — `{mod,rc4,bootstub,strings,vm_embed,scan,...}.rs` (분해 완료).
  - `patch_data/` — `{mod,imports}.rs` (분해 완료: import-range 수집 분리).
  - `validate/` — `{mod,rsrc,tests}.rs` (분해 완료: 리소스 검증 분리).
  - `iat_hide.rs`, `rsrc_register.rs`, `pass4_section.rs`, `pass3_encode.rs`,
    `build.rs`, `pass1_slice.rs`, `mod.rs`, `pass2_shuffle.rs`, `ondemand.rs`,
    `pack.rs`.
  - ~~`text_lift.rs`~~ — **삭제됨** (고아 중복; 실사용은 `vm::text_lift`).

### VM 컴파일러 코어 (`src/vm/`) — 전부 디렉터리 모듈로 분해 완료
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

모든 긴 단일 파일이 디렉터리 모듈로 분해됨 (`milestones.md`의 표 참조).
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

세부 우선순위/검증 기준은 `milestones.md` 참조.
