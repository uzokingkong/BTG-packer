# P3 (G1) — 상용 엔진 RISC→폴리 매핑 산출물 (.map / .sym / .riscmap.csv)

> 대상: `vm-obf` repo · branch `commercial/p3-engine-integration` · P3 상용 VM 업그레이드
> 작업일: 2026-08-15

## 요청
패킹(`--vm --vm-oep --vm-commercial`) 시 원본 명령(VA) → RISC micro-op 인덱스 → 폴리
바이트코드 오프셋 체인을 `.map` / `.sym`(또는 CSV) 산출물로 기록한다. 기존 emit 인프라
(`vm::mapper`, M9/M10)는 레거시 1:1 리프트 경로만 다뤄서 상용(risc→poly) 경로는 빈 맵만
남겼으므로, 상용 경로를 매퍼에 연결하고 per-micro-op 폴리 오프셋을 함께 기록한다.

## 구현 (변경 파일)

### `src/vm/mapper.rs` — 상용 RISC 매핑 기록/렌더/CSV
- `RiscMapEntry` 신규: `src_va`(원본 명령 VA) · `len` · `disasm` ·
  `risc_op_start`/`risc_op_count`(프로그램 `RiscProgram.instrs` 기준 micro-op 구간) ·
  `poly_bc_offset`(첫 micro-op의 폴리 바이트코드 오프셋, 인코딩 후 채움).
- `VmMapper` 필드 추가: `risc_entries`, `risc_op_src`(micro-op 인덱스 → 원본 VA),
  `risc_offsets`(micro-op 인덱스 → 폴리 바이트코드 오프셋).
- `record_risc_entry(src_va, len, disasm, risc_op_start, risc_op_count)` — 리프트 시점 기록.
- `fill_risc_poly_offsets(offsets)` — `PolymorphicEncoder::encode_with_offsets` 결과를 반영.
- `render`(.map): `; ----- commercial RISC lift (src_va -> micro-op -> poly bc offset) -----`
  섹션, 행 `0x<poly> RiscProg 0x<va> <len> op=<start>..<end> <disasm>`.
- `render_sym`(.sym): 동일한 상용 RISC reverse index 섹션.
- `write_risc_csv_to` — per-micro-op CSV `src_va,risc_op_index,poly_bc_offset`.

### `src/vm/poly/encoder.rs`
- `encode` → `encode_with_offsets` 위임. `encode_with_offsets`는 각 micro-op이 시작하는
  바이트코드 오프셋 벡터를 함께 반환(`offsets.len() == instrs.len()`, 단조 증가).

### `src/vm/text_lift/commercial.rs`
- 2nd-pass lift 루프에서 성공한 블록마다 각 원본 명령을
  `mapper::record_risc_entry(ip, len, disasm, base+idx, count)`로 기록
  (mapper 활성 시).

### `src/pipeline/crypto/place.rs`
- 상용 경로 `enc.encode(...)` → `enc.encode_with_offsets(...)` 후
  `mapper::fill_risc_poly_offsets(&offsets)` 호출.

### `src/main.rs`
- 매퍼 덤프 블록에 `.riscmap.csv` 쓰기 추가(`P3 commercial RISC map CSV written`).

## 검증
- `cargo build --release` → exit 0.
- `cargo test --release` → **165 passed; 0 failed** (162 베이스 + P3 상용 차등/통합 2 +
  신규 `vm::mapper::tests::risc_entry_render_and_csv` 1).
- 실제 패킹: `btg-packer -i test\target\release\rust_packer_test.exe -o packed_commercial.exe
  --vm --vm-oep --vm-commercial --map --sym-map` → exit 0.
  - `packed_commercial.exe.map` : KSA + **commercial RISC lift 섹션**(poly 오프셋·VA·micro-op
    구간·디스어셈블리).
  - `packed_commercial.exe.sym` : 상용 RISC reverse index 섹션.
  - `packed_commercial.exe.riscmap.csv` : **23,661 micro-op 행**(`src_va,risc_op_index,poly_bc_offset`).

## 커밋/푸시
- `Co-authored-by: Attacca <attacca@walruslab.org>` 트레일러 커밋, origin 푸시.
