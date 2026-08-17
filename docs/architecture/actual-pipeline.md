# BTG Packer — 실제 패킹 파이프라인 (냉정 기술)

> 갱신: 2026-08-17. 이 문서는 README/설계 문서의 광고 문구를 걷어내고 **실제
> 코드 기준으로** 패커가 입력 PE를 어떻게 처리하는지 기술한다. 모든 지점은
> `src/` 파일 경로를 명시한다.

---

## 1. 처리 순서 (실제 코드 경로)

`src/main.rs`가 `PipelineContext`를 만들어 아래 순서로 파이프라인을 실행합니다.

```text
[입력 PE]
  1. TargetPeInfo::parse          (src/pe/parser.rs, goblin)
  2. selective_vm::SelectiveVmPass (--vm 시, src/pipeline/selective_vm.rs)
  3. pass1_slice::run             (CFG 추출 + 마이크로 슬라이싱, src/pipeline/pass1_slice.rs)
  4. pass2_shuffle::run           (블록 셔플, src/pipeline/pass2_shuffle.rs)
  5. pass3_encode::run            (RIP 픽스업 + 재인코딩, src/pipeline/pass3_encode.rs)
  6. pass4_section::run           (.btg 섹션 조립, src/pipeline/pass4_section.rs)
  7. patch_data::run              (섹션 재배치 + 포인터 픽스업, src/pipeline/patch_data.rs)
  8. iat_hide::run                (--iat-hide 시, src/pipeline/iat_hide.rs)
  9. crypto::run                  (암호화 + 부트 스텁 설치, src/pipeline/crypto/mod.rs)
 10. rsrc_register::run           (--rsrc-register 시, src/pipeline/rsrc_register.rs)
 11. poly_embed                   (--vm 시 SDK 마커 임베드, src/pipeline/poly_embed.rs)
 12. build::run                   (PE 합성 + .reloc 생성, src/pipeline/build.rs)
 13. validate::run                (출력 재파싱 검증, src/pipeline/validate.rs)
[출력 PE]
```

`--vm-test` / `--text-vm` / `--text-vm-oep` / `--vm-bench` / `-t`(QA)는 패킹을
하지 않고 진단·테스트·벤치마크만 수행하고 종료합니다 (`src/main.rs`).

---

## 2. 실제로 이루어지는 일 (기능별)

### 2.1 CFG 슬라이싱 / 셔플
- `pass1_slice.rs`가 원본 `.text`를 기본 블록으로 디코드하고 마이크로 슬라이싱.
  SEH 함수는 네이티브로 남기고, direct-call/data-ref/코드-실체화 타깃을
  "keep-plaintext" 집합으로 수집.
- `pass2_shuffle.rs`가 블록 물리 배치를 섞고 디스패처 크기를 추정.
- `pass3_encode.rs`가 RIP fixup + iced-x86 `BlockEncoder`로 재인코딩, 밀집 패킹,
  MBA-keyed 점프 테이블 엔트리 생성.

### 2.2 암호화 (`pipeline/crypto/`)
- 기본 암호 **BTG-C1** (독자 512-bit 스트림 사이퍼, `src/crypto/`). RC4는
  `--rc4`로만 복귀. **암호학적 안전성은 감사되지 않은 홈메이드 구현**.
- 부트 스텁(x86-64 셸코드)이 복호화·기동을 담당 (`bootstub/build.rs`, `place.rs`).
- `--dispatcher-reencrypt`는 블록별 개별 암호화. **주의**: 실제로는 첫 디스패치
  시 복호화 후 평문 유지(decrypt-once) — `reencrypt.rs:193-195`.
- `--m7`만 실행 후 재암호화(anti-dump)를 수행 (refcount-safe state machine).
- at-rest 암호화 적용 시(`ctx.at_rest_encrypted`) build.rs는 relocation-aware/
  ASLR 보존 출력을 **비활성화**한다 (로더가 암호문에 .reloc을 적용하면 깨짐).

### 2.3 부트 스텁 / 디스패처
- `dispatcher/build.rs` (일반 MBA 점프 테이블), `reencrypt.rs`, `m7.rs`.
- 안티디버그: PEB.BeingDebugged / NtGlobalFlag / Heap.Flags 검사 → `ud2` 또는
  행(hang) 루프 (`dispatcher/antidebug.rs`, `antidebug/mod.rs`).

### 2.4 VM 가상화
- **레거시 1:1 VM** (`--vm-oep`): `text_lift::lift_program_cfg` → VM 바이트코드 →
  `build_program_vm` → 부트 스텁이 디스패치.
- **상용 엔진** (`--vm-oep --vm-commercial`): `lift_program_cfg_commercial`(RISC) →
  `PolymorphicEncoder` → `build_program_vm_commercial` → `poly_direct` 네이티브
  self-decoding 디스패처.
- 차등 검증은 **선형 블록 단위 동치**로 한정 (taken-분기 제어흐름은 계약 밖).

#### 2.4.1 프로그램 VM의 네이티브 유지(제외) 집합 (`src/vm/text_lift/exclusions.rs`)
프로그램(전체 OEP) 가상화는 `.pdata` 함수 단위로 아래를 네이티브로 남긴 뒤
native-call 브리지로 실행한다:
- **Rust panic/unwind/Once 런타임** (`detect_panic_unwind_ranges`) — panic 문자열
  참조·`_CxxThrowException`/`__CxxFrameHandler3` 임포트·양방향 호출+전역상태 폐포.
  (이를 VM으로 옮기면 `once.rs:166 f.take().unwrap()` teardown 크래시.)
- **setjmp/longjmp** (`detect_setjmp_longjmp_functions`) — setjmp/longjmp IAT 슬롯
  사용 함수 + 폐포. (비지역 점프가 VM 가상 레지스터를 우회.)
- **SEH 함수** (`detect_seh_native_functions`) — panic·catch/unwind 프레임.
  `BTG_SEH_MINIMAL=1`(기본)은 최소 집합만, `BTG_SEH_NONE=1`은 SEH 전체를 VM화
  (teardown-guard만 네이티브).
- v56: LOCK 메모리 RMW 격리 망은 제거됨 — LOCK 원자 RMW는 VM opcode로 처리.

### 2.5 출력 합성 / 검증
- `build.rs`: PE32+ 다중 섹션 합성, `.pdata` SEH 재생성(브리지 UNWIND_INFO),
  `--no-crypto` 경로에 한해 `.reloc` 디렉터리 생성 + ASLR(DYNAMIC_BASE/HEVA) 비트
  보존. **at-rest 암호화 경로에서는 ASLR 비트가 스트립**되고 `.reloc` 미생성
  (`build.rs:66-68, 115-129`).
- `validate.rs`: 출력 PE 재파싱해 섹션 경계/EP/부트 프롤로그/재암호화 roundtrip/
  리소스 트리 등 하드 검증.

---

## 3. 실제로 미달성 / 주의할 지점

| 항목 | 실제 상태 | 위치 |
|---|---|---|
| 원본 `.text` 평문 제거 | **미달성** — 대부분의 모드에서 `.text`를 평문으로 유지 (TLS/CRT/브리지용) | `patch_data.rs`, `crypto/mod.rs` |
| RIP-relative 리프트 | **비활성(gate)** — keystream desync 크래시 | `docs/journal/2026-08-17-*` |
| SDK 마커 경로 실행 정합 | **미검증** — `.btgvm` 데이터 임베드만 배선 | `poly_embed.rs`, `sdk/llvm_interface.rs`(stub) |
| keyed-MAC 런타임 검증 | **미구현** — 패킹 시 계산만, 런타임은 CRC32만 | `crypto/mac.rs`, `crypto/place.rs` |
| 멀티스레드 VM 재진입 | **미지원** — 단일 정적 state | `vm/interp/state.rs` |
| `--mem-harden` | **fail-open** + `--dispatcher-reencrypt`와 배타 | `crypto/memharden.rs` |
| `--integrity` | CRC32 강제, **keyed-MAC은 미강제** | `crypto/integrity.rs` |
| SEH 함수 네이티브 유지 | 기본 모드에서 **최소 집합만** 유지; 전체 VM화는 `BTG_SEH_NONE=1`(미기본) | `text_lift/exclusions.rs` |

---

## 4. 측정 가능한 사실 (2026-08-17 실측)

- `cargo build --release` → 성공.
- `cargo test --release --lib` → **285 passed / 0 failed**.
- 레거시 VM opcode **193개** (`src/vm/bytecode/registry.rs`, `NUM_OPS=0xC2` 슬롯).
- RISC 마이크로-op **38개** (`src/vm/risc/opcodes.rs`).
- `--seed` 결정적 빌드 → 동일 시드 2회 패킹 SHA256 동일.
- "26,956/26,956 (100%)"·"6040 블록"은 **특정 테스트 바이너리 1개**에 대한
  `--text-vm` / P2-RISC-GAP **진단 수치**이며, 일반 커버리지 보장이 아님.
