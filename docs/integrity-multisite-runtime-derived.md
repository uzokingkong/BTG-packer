# BTG-Packer — Integrity/Value Check: Multi-Location Checksum + Runtime-Derived Poison

> 작성일: 2026-08-21 · 작업 단위 task/0a7814fac57a4897a86affb4a9c5d19d
> 대상: 이 저장소 (btg-packer / vm-obf, Rust)
> 과제: 단일 바이트 패치로 우회 가능한 CRC32/value check를
> **다중 위치 체크섬 + 런타임 파생**으로 강화하고, '길이=0으로 들어가는 dead mixing
> loop'처럼 fake path로 읽히는 junk를 재작업해 fake/real 경로를 정적으로 분리하기
> 어렵게 만든다.

## 목표

감사(`docs/audit-2026-08-21-chatgpt-6-weaknesses.md` §3.4/§2 #4)에서 지적한 대로, 기존
integrity는 부트 스텁에서 복호화 직후 한 곳에 몰린 `cmp; je ok; ud2` 3개(CRC1/CRC2/
keyed-MAC)뿐이라, 각 사이트의 `je`를 단일 바이트로 무력화하면 우회가 가능했다. 본
태스크는:

- **다중 위치 체크섬**: 검증 지점을 부트 전체(MAC → CRC1 → CRC2 → IAT 후 CRC3 →
  디스패처 직전 CRC4)로 분산해 한 지점/한 영역의 패치로 무력화 불가.
- **런타임 파생(poison interlock)**: 검증 값을 단순 분기 대신 **런타임에 소비되는
  파생 키**로 사용 — 분기를 패치해도 tamper 값이 이후 복호화를 파괴.
- **junk 재작업**: 단순 데드-레지스터 op를 실작동 ARX mixing loop(카운트 시드 유도
  1..256, 항상 비영)로 보강해 "길이=0 dead path / fake path"로 읽히지 않게 함.

## 변경 요약 (소스)

### 1. `src/pipeline/crypto/integrity.rs`

- **site 1 (`emit_integrity_crc`)** — `cmp eax,[stored]`를 **`xor eax,[stored]`**로
  교체. 결과 `V1 = computed ^ stored`가 EAX에 남고 ZF는 `je`의 조건 그대로.
  `mov r14d, eax`로 **R14 = poison key**로 보존 (zero-extend, mov는 ZF 비파괴).
  - legit: V1=0 → `je` 통과 + 런 바이트 불변.
  - tamper: V1≠0 → `je`는 ud2로 트랩. **설령 `je`를 단일 바이트로 패치해도** R14=V1≠0
    → 문자열 런/리졸브 테이블이 쓰레기로 복호화되어 크래시. (단일 바이트 패치 우회 불가)
- **MAC 프리엠블**: runtime-derived whiten **W32(R15)를 w32_slot에 저장** — IAT
  리졸브가 R15를 클로버한 뒤에도 site 3/4가 같은 W32를 재사용.
- **S3 (`emit_integrity_crc3`)** — IAT 리졸브 직후 실행, whiten = `W32`,
  저장값 `crc3_stored = crc ^ W32`, `xor` 기반 비교 + `je/ud2`.
- **S4 (`emit_integrity_crc4`)** — 디스패처 진입 직전 실행, whiten = `rol(W32,13)`,
  저장값 `crc4_stored = crc ^ rol(W32,13)`, `xor` 기반 비교 + `je/ud2`.
  → 사이트별 저장값이 전부 달라 한 상수 스캔으로 일괄 무력화 불가.

### 2. `src/pipeline/crypto/bootstub/emit.rs`

- **`emit_run_decrypt` poison loop** — 각 런 `Prga` 뒤에, R14 4바이트를 `ror 8`로
  순환하며 런 바이트를 XOR. legit(V1=0)는 no-op, tamper는 **모든 런/리졸브 손상**.
- **`trashformer_mixing_loop(seed)` 신규** — S-box 프레임 `[RSP..RSP+count)` 위의
  ARX mixing 루프(`xor [rdi],al; rol eax,5; add eax,ecx; inc/dec; jnz`). 카운트는
  `1 + seed % 0x100` → **항상 비영(1..256)**, 프레임 내 안전(KSA가 초기화).
  실제 checksum/복호화 루프와 구조적으로 동일 → fake/real 경로를 정적으로 분리 불가.

### 3. `src/pipeline/crypto/bootstub/ctx.rs`

- 필드: `crc3_va`, `crc4_va`, `w32_slot_va`.
- 라벨: `Crc3Done/Crc3Ok`, `Crc4Done/Crc4Ok`, `PoisonLoop/PoisonDone`, `JunkMixLoop`.

### 4. `src/pipeline/crypto/bootstub/build.rs`

- IAT 리졸브 후 `emit_integrity_crc3`, 디스패처 직전 `emit_integrity_crc4`.
- 서문에서 `trashformer_junk` 뒤에 `trashformer_mixing_loop` 삽입.

### 5. `src/pipeline/crypto/place/mod.rs`

- 레이아웃: `w32_slot_va=seed_off+272`, `crc3_va=seed_off+276`, `crc4_va=seed_off+280`.
- 저장값: `crc3_stored = crc ^ W32`, `crc4_stored = crc ^ rol(W32,13)`, w32_slot은 0.
  (legit 런타임이 W32를 그 슬롯에 기록, site 3/4가 재사용.)

### 6. `src/pipeline/crypto/tests.rs`

- BootStubCtx 리터럴에 새 필드 추가 (기존 WIP `desc_used` 누락도 보완).

## 길이 불변성 / 회귀 안전

- 새로 추가된 명령은 전부 고정 길이 형태(imm64/imm32/rel32)이며 루프 경계는
  런 메모리에서 읽어 인코딩 길이가 값과 무관 — 부트 스텁 3-pass sizing 계약 유지.
- plain / non-integrity 경로는 `stub.integrity` 가드로 무영향 (poison loop도 동일 가드).
- R14는 서문~site1~run_decrypt 구간에서 다른 경로가 쓰지 않음을 확인 (Prga가
  R14를 건드리지 않음).

## 검증 (노드에서 실행)

- `cargo build --release` → **clean (0 errors)**.
- `cargo test --lib pipeline::crypto::` → **22 passed / 0 failed**
  (`test_boot_stub_generates_with_integrity`, `test_crc32_known_vector` 등 포함).
- `cargo test --lib vm::` → **285 passed / 0 failed** (무회귀).
- `dummy_target.exe --integrity` 패킹 → **정상 실행(exit 0)** — poison no-op, junk
  mixing loop, 5개 사이트 전부 통과. boot stub 1828B (기존 대비 증가).
- 패킹된 boot stub 바이트 스캔 → **ud2 트랩 5곳** = 5개 검증 사이트 (기존 3곳 → 5곳).
- 페이로드 1바이트 변조(`^0xFF`) → 실행 **크래시(0xC0000005)** — integrity가 tamper 검출.

## 남은 것 / 참고

- `pipeline::pack::tests::deterministic_seed_vm_m8_same_bytes` 1개가 **기존 결함**으로
  실패 — untracked WIP `src/vm/semantic_obf.rs:376`의 slice OOB
  (`range end index 113 … slice of length 112`). 본 태스크는 그 파일을 건드리지 않았고
  integrity 경로와 무관 (사전 결함으로 보고).
- 본 태스크는 integrity/value check 강화 + fake/real junk 분리 방지에 한정. `.rdata`
  문자열 힌트 제거 / ChatGPT식 정적 추출기 실패 / 결과·플래그 검증 통과는 해당 작업
  단위의 다른 태스크 범위.
