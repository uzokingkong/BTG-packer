# 전체 소스 지도

이 문서는 특정 VM 기능이 아니라 저장소 전체를 구성요소와 실행 책임으로 나눈 코드
지도입니다. 2026-08-23 기준 `src/`는 269개 Rust 파일, 약 102,635줄입니다.

## 크기와 책임

| 영역 | 파일/LOC | 책임 |
|---|---:|---|
| `src/vm/` | 156 / 약 66.8K | legacy VM, RISC/poly commercial VM, interpreter, native handlers, lift, state, tests |
| `src/pipeline/` | 45 / 약 18.5K | pass orchestration, patching, crypto placement, PE build/validation, artifacts |
| `src/crypto/` | 16 / 약 5.0K | C1, RC4 provider, ChaCha20, Poly1305, native emitters, key/MAC primitives |
| `src/dispatcher/` | 9 / 약 4.3K | standard/reencrypt/M7 dispatcher, anti-debug shellcode, validation |
| root modules | 11 / 약 3.6K | CLI, main, manifest, QA, differential, multi-seed, errors |
| `src/pe/` | 6 / 약 1.4K | PE parse/build/reloc/dummy generation |
| `src/graph/` | 5 / 약 1.0K | CFG extraction, slicing, shuffling, RIP fixup |
| 나머지 | 21 / 약 1.6K | SDK, analysis, debug, MBA, assembler, core graph, utilities |

LOC는 방향을 보여주는 인벤토리이며 API 안정성이나 구현 완료도를 뜻하지 않습니다.

## Entry와 제품 제어면

| 파일 | 역할 |
|---|---|
| `src/main.rs` | CLI mode dispatch, profile resolve, full pack orchestration, sidecar emission |
| `src/cli.rs` | 42개 CLI field와 clap help/value enum |
| `src/protection_profile.rs` | raw CLI → effective profile, 충돌/경고/하드 오류 |
| `src/lib.rs` | library module export와 단순 `pack()` API |
| `src/pipeline/pack.rs` | in-memory/file 선택 가능한 programmatic basic pack path |
| `src/error.rs` | stage별 typed error surface |

`src/antidebug/mod.rs`는 현재 `lib.rs`나 `main.rs`에서 module로 선언되지 않은 과거
실험 코드입니다. 실제 anti-debug production 경로는 `src/dispatcher/antidebug.rs`입니다.
파일이 존재한다는 사실과 production wiring을 구분해야 합니다.

주의: library `pack()`/`run_full()`은 CLI의 모든 feature를 노출하는 동등 API가 아닙니다.
현재는 기본 CFG+crypto pack 경로를 위한 제한된 API입니다.

## Native CFG packer

- `src/graph/cfg.rs`: x86 basic CFG extraction;
- `src/graph/slicer.rs`: basic block을 trigger block/micro-slice로 분해;
- `src/graph/shuffler.rs`: physical block order와 layout randomization;
- `src/graph/fixup.rs`: RIP-relative/branch target 재계산;
- `src/core/`: trigger graph/block data model;
- `src/assembler/payload.rs`: dispatcher bridge를 포함한 block payload emission;
- `src/dispatcher/`: standard, block reencrypt, M7/C1 dispatcher 생성과 검증.

이 계층은 Program-VM을 사용하지 않는 기본 패킹에서도 항상 핵심입니다.

## PE 입출력과 합성

- `src/pe/parser.rs`: PE headers, sections, imports/relocs/.pdata 입력 정보;
- `src/pe/builder.rs`: 새 section/directory/entry/checksum을 포함한 PE 합성;
- `src/pe/reloc.rs`: relocation directory 생성;
- `src/pe/dummy_gen.rs`: 입력이 없을 때 사용하는 test PE;
- `src/pipeline/patch_data*`: moved code/data reference, CFG pointer, cookie와 보호 범위 patch;
- `src/pipeline/build.rs`: 최종 section과 data directory를 PE로 직렬화;
- `src/pipeline/validate*`: bounds, directory, `.pdata`, ownership, protection 구조 검증;
- `src/pipeline/rsrc_register.rs`: relocated payload의 resource tree 등록;
- `src/pipeline/iat_hide.rs`: import 수집, dummy import, runtime resolver table.

## Pipeline pass와 공유 context

`PipelineContext`는 원본 PE, CFG/trigger blocks, shuffled layout, `.textb`, crypto/boot,
VM ownership, mapping, integrity, lifetime, IAT와 PE sidecar metadata를 pass 사이에
전달합니다.

```text
pass1_slice
  → pass2_shuffle
  → pass3_encode
  → pass4_section
  → patch_data / iat_hide
  → crypto placement / boot / VM embed
  → resource registration / selective VM embed
  → PE build
  → structural + optional execution validation
  → manifest/maps/ownership/debug artifacts
```

세부 순서는 [실제 production 파이프라인](actual-pipeline.md)을 기준으로 합니다.

## Crypto와 runtime protection

| 영역 | 구성 |
|---|---|
| Bulk cipher | RC4 (`pipeline/crypto/cipher.rs`), C1 (`crypto/state.rs`), ChaCha20 (`crypto/chacha20.rs`) |
| Authentication/integrity | CRC/multisite boot checks, Poly1305/AEAD helpers, Program-VM BTGI descriptors |
| Boot | `pipeline/crypto/bootstub*`: decrypt/verify/IAT/memory transition/VM entry emission |
| Per-block | dispatcher reencrypt, native M7, C1 variants |
| Program-VM | family M7 bytecode chunks, data-lifetime objects, distributed code/table/bytecode integrity |
| Memory policy | payload relocation, IAT hiding, RX/RW transitions, seed/state zeroization paths |

`BTG-C1`은 연구용 자체 cipher이고 ChaCha20/Poly1305 지원과 동일한 보증을 의미하지
않습니다. profile마다 실제 적용 가능한 primitive와 fallback이 다릅니다.

## VM 계층 전체

### Legacy VM

- `vm/bytecode`, `vm/handlers`, `vm/interp`, `vm/lifter`;
- KSA/PRGA/composite boot VM과 legacy Program-VM;
- fixed opcode registry, interpreter, native handlers와 self-tests.

### Commercial RISC/poly VM

- `vm/risc`: canonical micro-op, x86 lifter, eval/flags/optimizer/native ABI;
- `vm/poly`: family ISA, grammar, rolling key, encoder/decoder/interpreter;
- `vm/threaded/poly_direct`: production native self-decoder와 handler codegen;
- `vm/multi_family`: function-stable partition과 cross-family route;
- `vm/commercial_build`: module/state/stack ABI와 build entry;
- `vm/text_lift`: CFG/function discovery, exclusions, commercial ownership lift.

### Hardening과 runtime metadata

- `vm/chunk_crypto`: instruction-aligned M7 chunk/key domain;
- `vm/data_lifetime`: literal/constant object proof와 acquire/release ABI;
- `vm/distributed_integrity`: BTGI region descriptor;
- `vm/table_layout`, `dispatch_perm`, `handler_poly`, `semantic_obf`;
- `vm/mapper`, `ownership_verifier`, `mem_model`, `seed_lifecycle`.

### 검증 구현

- legacy interpreter/native/self-test;
- RISC reference evaluator;
- poly static decoder/interpreter;
- native arena runner와 differential fixtures;
- `vm/self_test` 및 각 모듈의 unit/property/regression tests.

## Selective SDK VM

- `sdk/markers.rs`: SDK marker region scan;
- `pipeline/selective_vm.rs`: marked region lift/accept/reject;
- `pipeline/poly_embed.rs`: `.btgvm` module과 original marker trampoline patch;
- `sdk/selective.rs`: entry trampoline;
- `sdk/llvm_interface.rs`: 제한된 LLVM-like IR parse/synthesize/verification surface.

Selective marker VM은 whole-program commercial Program-VM과 별도 경로이며, marker가
없으면 embed 단계는 no-op입니다.

## QA, 재현, 분석과 지원 산출물

- `qa.rs`, `qa_runner.rs`: compiler corpus build/discovery/pack/execute matrix;
- `differential.rs`: timeout 포함 stdout/stderr/exit 동치와 실패 artifact 격리;
- `multi_seed.rs`: 자식 프로세스 기반 N-seed gate와 summary;
- `manifest.rs`: hashes, build id, capabilities, ownership, execution result;
- `vm/mapper.rs`: instruction/block/function/RISC mapping;
- `crash_diag.rs`: map 기반 crash site 진단;
- `debug/mod.rs`: layout log와 overlapped-disassembly 확인;
- `analysis/entropy.rs`, `metrics.rs`: PE entropy와 graph metrics.

## 현재 문서의 경계

- 현재 기능 판정: [`../current-status.md`](../current-status.md)
- 모든 CLI와 profile 규칙: [`../cli-reference.md`](../cli-reference.md)
- pass/boot 순서: [`actual-pipeline.md`](actual-pipeline.md)
- 실행 검증 범위: [`../verification.md`](../verification.md)
- 과거 설계/실험: `docs/history`, `docs/journal`, `docs/engine`, `docs/roadmap`

## 최상위 module 빠짐없는 색인

| Module | 현재 역할 |
|---|---|
| `analysis` | entropy/graph metrics |
| `assembler` | trigger payload x64 emission helper |
| `core` | graph와 trigger-block model |
| `crypto` | cipher/MAC/AEAD와 native crypto code emit |
| `debug` | layout/disassembly diagnostics |
| `dispatcher` | runtime dispatcher/anti-debug/validation |
| `graph` | CFG/slice/shuffle/fixup |
| `mba`, `obfuscation` | expression generation과 native MBA codegen |
| `pe` | parser/builder/relocation/dummy target |
| `pipeline` | 전체 pass orchestration와 artifacts |
| `sdk` | markers/selective/LLVM-like interface |
| `util` | shared addressing/padding/cookie helpers |
| `vm` | 모든 legacy/commercial VM compiler/runtime/test |
| root `cli/error/manifest/qa/...` | 제품 entry, 검증, provenance와 지원 도구 |
| unexported `antidebug` | 과거 실험; production은 `dispatcher/antidebug` |
