# BTG Packer — 구현 격차 해소 대규모 개선 계획 (Implementation Gap Plan)

> 기준: 2026-08-17 · repo `asdfsadfecwecc` (btg-packer)
> 근거: `COMMERCIAL-VM-UPGRADE-PLAN.md`, `commercial-readiness-plan.md`,
> `README.md`(알려진 한계), 소스 실측 (RISC/poly/threaded, pipeline, crypto, pe).
> 상태 마커: ⬜ 미착수 · 🔶 진행 중 · ✅ 완료 · ⚠️ 게이트/리스크

---

## 0. 기준 (2026-08-17 실측)

- `cargo build --release` green · `cargo test --release --lib` → **286 passed; 0 failed**.
- 문서상 "미완/진행중" 항목 전수 대조 — **코드에서 확인된 것만** 아래 목록으로 확정.

---

## 1. 미구현 실측 요약 (docs ↔ 코드 대조)

### 1.1 RISC 상용 엔진 (P2/P3 잔여)

| # | 갭 | 실측 위치 | 비고 |
|---|---|---|---|
| R1 | RIP-relative addressing **게이트** | `vm/risc/lifter.rs:232-234` | keystream desync → 0xC0000005. 레거시는 지원(`vm/lifter/mem.rs:44-55`) |
| R2 | CMPXCHG 레지스터 폼 거부 | `lifter.rs:1045` | |
| R3 | AH/BH/CH/DH 하이바이트 미지원 | `lifter.rs:164-170` | |
| R4 | Float 7종이 폴리 ISA 미인코딩 | `poly/interpreter.rs:459-465` (`_ => {}`) | lift는 됨, isa_spec 79개에 미포함 |
| R5 | AF 플래그 네이티브 미계산/보존 | `codegen_util.rs:70` FLAG_MASK=0x8C5 | 참조는 0x8D5 포함 (`harness/emit_block.rs:18`) |
| R6 | ADC/SBB, ROL/ROR, SHLD/SHRD, BT/BTS/BTR/BTC 미리프트 | `lifter.rs:1235-1238` `_` 폴백 | |
| R7 | 8/16-bit XOR/AND/OR/SHL/SHR/NEG/NOT 미리프트 | `lifter.rs` (ADD/SUB/CMP/TEST/INC/DEC/SAR만) | |
| R8 | packed SSE/MMX, CDQE/CQO, CPUID/XGETBV/INT/UD2 미리프트 | `lifter.rs:1235-1238` | |

### 1.2 보안 격자 (README 한계 7·8·9·10 + P1/P3)

| # | 갭 | 실측 위치 | 비고 |
|---|---|---|---|
| S1 | keyed-MAC 패킹 시 계산만, 런타임 미검증 | `place.rs:824-825` vs `integrity.rs:25-67` | 런타임은 CRC32만 강제 |
| S2 | `--dispatcher-reencrypt` = decrypt-once | `reencrypt.rs:204-214` | 진짜 재암호화는 `--m7`만 (`m7.rs:244-264`) |
| S3 | `--mem-harden` fail-open | `memharden.rs:10,45` | NTSTATUS 미검사 |
| S4 | 단일 정적 VM state → 멀티스레드 재진입 손상 | `bootstub/ctx.rs:26,33,40` | per-entry state 설계 필요 |
| S5 | SDK 마커 = 데이터 임베드만, 소비 런타임 미검증 | `poly_embed.rs:19-23`, `sdk/llvm_interface.rs`(24줄 스텁) | |
| S6 | unwrap/expect 3070건 | vm 2250 / pipeline 512 / crypto 244 | PE 입력 경계부터 (`parser.rs:92` 언체크 슬라이스) |
| S7 | BTG-C1 홈메이드 암호 미감사 | `crypto/state.rs:1-16`, `nonlinear.rs`, `round.rs:20-29` | |

---

## 2. 실행 계획 (5개 축)

### 축 1 — RISC 리프터 커버리지 100%  [1~2주]  핵심 게이트

| 우선순위 | 작업 | 검증 | 상태 |
|---|---|---|---|
| 🔴 | R1 RIP-relative 활성화 — dispatcher keystream 소비 차이 추적·수정 (`lifter.rs:218-234`) | 리프트 블록 6040 실측, 0xC0000005 0 | ⬜ |
| 🔴 | R4 Float op 폴리 ISA/핸들러 추가 (isa_spec 79→86) | 차등 테스트 (3 seeds) | ⬜ |
| 🟠 | R6 ADC/SBB, ROL/ROR, SHLD/SHRD, BT계열 | `--text-vm` 100% | ⬜ |
| 🟠 | R7 8/16-bit 논리·시프트·NEG/NOT | 차등 테스트 | ⬜ |
| 🟡 | R2 CMPXCHG reg, R3 하이바이트, R8 packed SSE | 커버리지 매트릭스 | ⬜ |

### 축 2 — 런타임 정확성  [1~2주]

| 작업 | 검증 | 상태 |
|---|---|---|
| Canonical semantics: BSR/BSF/TZCNT/LZCNT 폭·ZF, ADC/SBB 전용 op, AH/BH 정책 (`semantics.rs` 단일화) | 명령×백엔드 차등 행렬 | ⬜ |
| R5 AF 캡처 정합: `poly_direct` FLAG_MASK 0x8C5→0x8D5 | cross-path 플래그 drift 0 하드 게이트 | ⬜ |
| ABI 검증 확장: XMM6-15 클로버, `vm/arena.rs` transmute 호출부 | validate_win64_abi 확장 | ⬜ |
| dispatcher CFG: stack-delta, RIP-relative 타깃, 간접 분기 타깃 검증 | CFG 검증 테스트 | ⬜ |

### 축 3 — 보안 격자 완성  [1~2주]  "실제 보호" 가짜표기 제거

| 작업 | 검증 | 상태 |
|---|---|---|
| S1 keyed-MAC 런타임 검증 배선 (bootstub 루프, 실패→UD2) | MAC 불일치 시 터미네이트 | ⬜ |
| S2 `--dispatcher-reencrypt` → M7식 refcount 재암호화 승격 (CLI 정합, `cli.rs:120-125`) | 실행 후 재암호화 실측 | ⬜ |
| S3 `--mem-harden` fail-open → NTSTATUS 검사 + 명시적 거부 | API 실패 시 거부 | ⬜ |
| S4 멀티스레드 VM state: 정적 버퍼 → per-entry (스택 기반) | 멀티스레드 타깃 × VM | ⬜ |
| S7 BTG-C1: ChaCha20/AES 교체 또는 독립 감사 문서화 | (선택) | ⬜ |

### 축 4 — 상용 엔진 통합 완성  [1~2주]

| 작업 | 검증 | 상태 |
|---|---|---|
| `--vm-commercial`에서 `BTG_SEH_NONE=1`(49 함수) 검증 (RISC 퓨전리티 갭 해소 후) | 16테스트 + checksum 동일 | ⬜ |
| S5 SDK 마커 소비 런타임 실검증, `llvm_interface.rs` 실구현 | SDK 마커 pack→run | ⬜ |
| P6 안티-탈가상화: 핸들러 MBA 전역화, opaque predicate, 롤링키 다중라운드, 슈퍼-op 다양화 | 시드 다양성 + `--vm-bench` | ⬜ |

### 축 5 — 견고성·QA  [병렬, 1~2주]

| 작업 | 검증 | 상태 |
|---|---|---|
| S6 unwrap 3070 → 오류 전파 (PE 입력 경계부터: `parser.rs:92`) | 악성 입력 크래시 0 | ⬜ |
| PE 입력 검증 강화 (모든 디렉터리/섹션 재파싱 검증) | validate::run 확장 | ⬜ |
| BuildManifest (`build_id/seed/input_hash/output_hash`), crash diagnostics + `.map` 승격 | 재현 데모 | ⬜ |
| full-pipeline fuzz (random PE→pack→run→compare) | 코퍼스 회귀 | ⬜ |
| P7 QA 자동화: 샘플 타깃(notepad/calc) × 5 CLI 조합 회귀 | 전 조합 green | ⬜ |

---

## 3. 우선순위·일정·게이트

```
축1(RISC 100%) → 축3(보안 격자) → 축2/4(정확성/통합) → 축5(QA, 병렬)
```

| 우선순위 | 예상 | 게이트 |
|---|---|---|
| 축1 | 1~2주 | `--text-vm` 100% · 차등 green · 리프트 블록 6040 |
| 축3 | 1~2주 | MAC/재암호화/harden 실측 · MT 테스트 |
| 축2 | 1~2주 | 플래그 drift 0 · ABI 검증 |
| 축4 | 1~2주 | SEH 49 · SDK pack→run |
| 축5 | 병렬 1~2주 | 크래시 0 · 전 조합 green |

**총 예상: 4~6주 (인력 1명).**

모든 축 공통 게이트:
- `cargo build --release` green · `cargo test --release --lib` green
- `--vm-test` ALL PASS · pack→run 16-test + FINAL CHECKSUM `0x2cdc0e4511d84a64` 무회귀

---

## 4. 진행 로그

| 일자 | 작업 | 상태 |
|---|---|---|
| 2026-08-17 | 계획 수립 + 문서화 | ✅ |
