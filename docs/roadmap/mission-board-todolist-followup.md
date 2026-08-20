# BTG Packer — todolist 후속 미션 보드 (Post-P0 Follow-up Missions)

> 기준: 2026-08-20 · repo `asdfsadfecwecc` (btg-packer)
> 근거: `todolist.txt` P0/P1/P2 판정 + `docs/roadmap/{commercial-readiness-plan,implementation-gap-plan,themida-parity-missions}.md`
> 상태 마커: ⬜ 미착수 · 🔶 진행 중 · ✅ 완료 · ⚠️ 게이트/리스크
> 완료됨: todolist P0 5종(CALL/RET, signed MUL/IMUL, narrow flags, XCHG/XADD, ASLR reloc) + P1 일부(CMPXCHG flags, DIV/IDIV #DE, XMM bridge 슬롯, .pdata) — 커밋 `159c8fa` (main, pushed)

---

## Tier 1 — 상용 VM 실행 정확성 (semantic correctness)

| # | 미션 | 상세 | 상태 |
|---|---|---|---|
| F1 | **네이티브 브릿지 FP 인자 실전 전달** | XMM0-5 슬롯·물질화/동기화는 완료(159c8fa). 남은 것: lifter/ABI 분석이 FP 인자를 XMM 슬롯에 심는 단계 미배선. Win64 FP ABI(double/float/vector 인자 → XMM0-3, 5~7) 정합. `double foo(double,double)` 네이티브 폴백에서 XMM 값 전달 검증. (WS2.3/WS3.1과 동일 "emission 완료, runtime 통합 미완료") | ✅ `b57d001` — 브릿지 positional XMM0-3 미러(regs[1..4]→movq xmmN) + `SetNativeFpReturn{4/8}` op/FP_RET_OFF 슬롯 + XMM0 FP 리턴 동기화 + `detect_fp_return_functions` 보수적 휴리스틱 + `annotate_native_fp_returns` 주입. 테스트 2개(f64/f32 실 callee 실행 + 구조) · 431 passed · 게이트 무회귀. 잔여: f32 리턴은 movd, 함수 서명 명시 분석(자동화 개선) |
| F2 | **--vm-commercial 전체 SEH 가상화** | 현재 132 함수 네이티브 유지. RISC-lift fidelity 갭(가상화된 Once/panic 경로) + 함수 원자성 갭(경계-브리지 미구현) 블로커 해소 후 SEH 네이티브 집합 최소화. `BTG_SEH_NONE=1`은 레거시 `--vm --vm-oep` 전용. (WS2.4) | ⬜ |
| F3 | **RIP-relative 데이터 절대 VA lift 게이트** | `.rdata`/`.data` 코드 포인터 재배치(원본 .text VA → .textb)와 lift 간 불일치 → 데이터 절대 VA lift 시 pack→run 갈라짐. 재배치-인식 lift(패킹 후 주소 맵을 lift에 반영) 필요. 구조적 제한. (implementation-gap R1) | ⬜ |

## Tier 2 — 옵션 실질화 / 보안 강화

| # | 미션 | 상세 | 상태 |
|---|---|---|---|
| O1 | **--obf-level 1/2/3 실질화** | 현재 `Pass3`에서 `let _ = obf_complexity`, key schedule 항상 level 2, BTG dispatcher는 level 2만 사용. 레벨별로 MBA 난이도/엔트로피/인코딩 깊이 차등 적용 + metrics 반영. | 🔶 |
| O2 | **BTG overlap/misaligned/polymorphic entry 활성** | `enable_overlap=false`, MicroSlicer `usize::MAX`(블록 분할 안 함), misaligned/polymorphic entry 생성 코드 없음. 실제 기능화 or 명시적 제거. | ⬜ |
| H1 | **branch_map source-IP 노출 축소** | branch_map에 원본 source-IP → bytecode offset 매핑이 평문 존재 — 정적 devirtualization에 유리. 인코딩/간접화/런타임 생성화. | ⬜ |
| H2 | **M7 plaintext call-target island 축소** | call_target_block_ids가 직접 call/함수 포인터/.pdata/RIP-relative/imm64/terminal을 평문 유지 set에 추가 → island 증가. 실행 중 블록만 평문이 되도록 대상 축소. | ⬜ |
| H3 | **delay/bound import 흔적 제거** | 일반 import만 숨김. DataDirectory[13] Delay Import / Bound Import / IAT 잔존 처리. | ⬜ |
| H4 | **signed PE 서명 정책** | DataDirectory[4] Security(인증서) 무조건 제거. 서명 정책(제거/보존/거부) 명시화. | ⬜ |

---

## 공통 검증 게이트 (모든 미션)

- `cargo build --release` green · `cargo test --release --lib` green
- pack→run 16-test + FINAL CHECKSUM `0x2cdc0e4511d84a64` 무회귀 (해당 경로)
- 미션별 차등 테스트(≥3 seeds) green

## 진행 로그

| 일자 | 미션 | 작업 | 상태 |
|---|---|---|---|
| 2026-08-20 | — | 미션 보드 등록 + F1 시작 | 🔶 |
| 2026-08-20 | F1 | 브릿지 FP 인자/리턴 실전 전달 구현·검증·커밋 `b57d001` (pushed) | ✅ |
| 2026-08-20 | O1 | --obf-level 1/2/3 실질화 시작 | 🔶 |