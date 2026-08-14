# P3 (G1) — place.rs 상용 엔진 Program VM 경로

> 문서화: 2026-08-15 · 베이스 HEAD: `ccd0317` · 브랜치: `commercial/p3-engine-integration`

## 개요

`src/pipeline/crypto/place.rs`의 Program VM(`--vm-oep`) 생성 경로에, 레거시 1:1 바이트코드
(`text_lift::lift_program_cfg`)를 대체하는 **상용 엔진(risc→poly→threaded) 경로**를 추가했다.

`--vm --vm-oep --vm-commercial` 세 토글을 모두 켜면 상용 경로를 쓰고, 레거시 `--vm-oep` 단독 경로는
바이트 동일하게 유지된다(회귀 안전).

## 경로 파이프라인

```
원본 .text --(CfgExtractor, lift_program_cfg와 동일한 블록/CFG/제외/switch 결정)
        --> lift_program_cfg_commercial (RISC lift, 각 블록 본문)
        --> PolymorphicEncoder.encode   (폴리모픽 롤링키 바이트코드)
        --> build_program_vm_commercial (DirectThreadedNativeRunner 핸들러 모듈)
        --> place.rs 기존 VmModule{code,table,bytecode} 임베드 경로
```

## 핵심 결정 재사용 (task 요구사항)

`lift_program_cfg_commercial`(`src/vm/text_lift/commercial.rs`)은 `lift_program_cfg`와 **동일한**
`CfgExtractor` 기본 블록 분할, `detect_seh_native_functions` 제외 넷, `entry_native`(OEP-force) 판정,
switch jump-table 해석을 그대로 재사용한다. 차이는 각 포함 블록의 명령을 1:1 레거시 바이트코드 대신
`RiscLifter`로 lift해 `RiscProgram`(+ ip_map, `VirtualBranch` 타깃 해석)을 만든다는 점뿐이다.

**전량-거부(selective_vm T1-2 원칙)**: RISC 리프터가 처리 못 하는 명령을 포함한 블록은 (그 함수 전체를)
기존 제외 net으로 네이티브 유지한다 — 절대 절반 lift/잘못된 코드를 만들지 않는다.

## 변경 파일

- 신규: `src/vm/text_lift/commercial.rs` (`lift_program_cfg_commercial`, `ProgramLiftCommercial`)
- 신규: `src/vm/commercial_build.rs` (`build_program_vm_commercial`, `COMMERCIAL_STATE_SIZE`)
- 변경: `src/pipeline/crypto/place.rs` (상용 분기 삽입 — 본 task의 중심)
- 배선: `src/vm/mod.rs`, `src/vm/risc/mod.rs`(`resolve_target`), `src/vm/text_lift/mod.rs`,
  `src/vm/threaded/harness.rs`, `src/cli.rs`(`--vm-commercial`), `src/main.rs`,
  `src/pipeline/mod.rs`(`PipelineContext.vm_commercial`), `src/pipeline/crypto/mod.rs`

## 검증

- `cargo build --release` → **exit 0**
- `cargo test --release` → **165 passed; 0 failed** (162 베이스 + 신규 P3 4개 green)
  - `test_lift_commercial_covers_same_blocks_and_keeps_unliftable_native`
  - `test_commercial_lift_encode_native_matches_reference_linear_block`
    (x86 → RISC → 폴리 롤링키 → DirectThreadedNativeRunner 네이티브 실행 == `RiscProgram::eval_state` 참조,
    다중 시드)
  - `test_commercial_extended_linear_block_matches_reference`
    (더 긴 선형 블록, flags 갱신 포함 — 선형 블록 단위 동치)
  - `test_commercial_program_lift_integration_execution_equivalence`
    (**`lift_program_cfg_commercial` OEP/프로그램 경로** → 폴리 → 네이티브 == `eval_state`,
     OEP VM화 + 전 상태 동치, 다중 시드)
- 레거시 `--vm-oep` 단독 경로 무회귀 (상용 분기는 `vm_commercial`이 켜졌을 때만 선택)

## 알려진 사항

`crypto::cipher_tests::native_keystream_matches_reference`는 이 Linux 호스트에서 SIGSEGV. 순수
`src/crypto`/`src/vm/arena.rs`(이번 변경 미수정)의 네이티브 셸코드 실행 테스트로, `git stash`로 베이스
그대로 재현해 **기존(pre-existing) 호스트 이슈**임을 확인했다. 상용 경로와 무관.
