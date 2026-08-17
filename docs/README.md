# 문서 인덱스 (Docs)

BTG Packer (vm-obf) 프로젝트 문서의 카테고리별 인덱스입니다. 각 문서는 실제 코드 경로와
연결되어 있으며, 아래 표의 **관련 코드** 열이 해당 문서가 설명하는 소스 위치입니다.

> 프로젝트 전체 개요/CLI/검증: 루트 [`README.md`](../README.md)
> 대표 조합: `--vm --vm-oep --vm-commercial` (상용 가상화) · `--full` (최대 보호) · `--no-crypto` (ASLR 보존)

---

## 📐 architecture/ — 설계 · 구조

프로젝트 전반의 아키텍처와 설계 의도를 설명하는 문서입니다.

| 문서 | 내용 | 관련 코드 |
|---|---|---|
| [`architecture/vm-compiler-architecture.md`](architecture/vm-compiler-architecture.md) | 모듈 지도, 컴파일러 프론트엔드, 부트/실행 정합 | `src/vm/`, `src/pipeline/`, `src/main.rs` |
| [`architecture/commercial-vm-engine.md`](architecture/commercial-vm-engine.md) | Phase 1~4 상용 가상화 엔진 (RISC→Poly→Threaded) 심층 설계 | `src/vm/risc/`, `src/vm/poly/`, `src/vm/threaded/`, `src/sdk/` |
| [`architecture/coverage.md`](architecture/coverage.md) | 명령 커버리지 베이스라인, 지원/제외 opcode 그룹 | `src/vm/bytecode/registry.rs`, `src/vm/lifter/` |

## 🗺️ roadmap/ — 로드맵 · 계획 · 현황

상용화 진행 상황과 마일스톤을 관리하는 문서입니다.

| 문서 | 내용 | 관련 코드 |
|---|---|---|
| [`roadmap/COMMERCIAL-VM-UPGRADE-PLAN.md`](roadmap/COMMERCIAL-VM-UPGRADE-PLAN.md) | 상용화 마스터플랜 (갭 분석, 6축 등급) | 전체 `src/vm/*`, `src/pipeline/*` |
| [`roadmap/commercial-readiness-plan.md`](roadmap/commercial-readiness-plan.md) | P0~P3 실행 로드맵 (✅/🔶/⬜ 상태 마커) | P0-1~P3-5 항목별 소스 |
| [`roadmap/milestones.md`](roadmap/milestones.md) | 마일스톤 체크리스트 (Phase 0~5) | 커밋별 소스 |

## ⚙️ engine/ — 엔진 구현 · 검증 리포트

특정 엔진 기능의 구현·와이어·검증을 기록한 보고서입니다 (역사적 기록).

| 문서 | 내용 | 관련 코드 |
|---|---|---|
| [`engine/P3-handlers-wired-and-verified.md`](engine/P3-handlers-wired-and-verified.md) | 상용 self-decoding 핸들러 전수 구현·와이어·검증 | `src/vm/threaded/poly_direct.rs` |
| [`engine/P3-commercial-selfdecoding-fix.md`](engine/P3-commercial-selfdecoding-fix.md) | broken generic 10-handler 진단·해소 | `src/vm/commercial_build.rs`, `src/vm/threaded/poly_direct.rs` |
| [`engine/P3-place-rs-commercial-program-vm.md`](engine/P3-place-rs-commercial-program-vm.md) | place.rs 상용 엔진 Program VM 경로 | `src/pipeline/crypto/place.rs`, `src/vm/text_lift/commercial.rs` |
| [`engine/P3-RISC-map-emit.md`](engine/P3-RISC-map-emit.md) | RISC→폴리 매핑 산출물 (.map/.sym/.riscmap.csv) | `src/vm/mapper.rs`, `src/vm/poly/encoder.rs` |
| [`engine/P4-P5-gates-progress.md`](engine/P4-P5-gates-progress.md) | SEH 가상화(P4) + .text 평문 0(P5) 진행 | `src/vm/text_lift/exclusions.rs`, `src/pipeline/crypto/` |
| [`engine/T1-2-RISC-Lifter-Coverage-DONE.md`](engine/T1-2-RISC-Lifter-Coverage-DONE.md) | RISC 리프터 커버리지 확장 | `src/vm/risc/lifter.rs`, `src/vm/risc/mod.rs` |
| [`engine/T1-4-Native-SelfDecoding-Dispatcher-DONE.md`](engine/T1-4-Native-SelfDecoding-Dispatcher-DONE.md) | 순수 네이티브 self-decoding 디스패처 | `src/vm/threaded/poly_direct.rs` |
| [`engine/T1-4-Native-Threaded-Branch-VIP-Fix.md`](engine/T1-4-Native-Threaded-Branch-VIP-Fix.md) | threaded harness 분기 VIP 크래시 수정 | `src/vm/threaded/harness.rs` |
| [`engine/VirtualBranch-Native-Handler-DONE.md`](engine/VirtualBranch-Native-Handler-DONE.md) | VirtualBranch 네이티브 핸들러 + 롤링키 재동기화 | `src/vm/threaded/poly_direct.rs` |
| [`engine/BSwap-BitScan-Count-PopCnt-native-handlers.md`](engine/BSwap-BitScan-Count-PopCnt-native-handlers.md) | BSwap/BitScan/TZCNT/LZCNT/PopCount 핸들러 | `src/vm/threaded/poly_direct.rs`, `src/vm/risc/mod.rs` |
| [`engine/VMR-text-plaintext-review-2026-08-15.md`](engine/VMR-text-plaintext-review-2026-08-15.md) | VMR 적용 검토 — .text 평문 여부 실측 | `--vm-oep` 패킹 산출물, `src/vm/text_lift/` |

## 🏴 vault/ — btg_vault 챌린지

별도 CTF 챌린지(`btg_vault_v3_3`) 관련 문서입니다 (패커와 독립된 크랙미 프로젝트).

| 문서 | 내용 |
|---|---|
| [`vault/btg_vault_v3_3_solve.md`](vault/btg_vault_v3_3_solve.md) | 솔브 라이트업 (패킹 exe 단독 복구) |
| [`vault/btg_vault_v3_3_solvability_review.md`](vault/btg_vault_v3_3_solvability_review.md) | 해독 가능성 검토 |
| [`vault/btg_vault_v3_3_solvable_redesign.md`](vault/btg_vault_v3_3_solvable_redesign.md) | 가역 비교 재설계 |
| [`vault/btg_vault_v3_3_1_hardened_packed_solvability.md`](vault/btg_vault_v3_3_1_hardened_packed_solvability.md) | hardened 패킹 해독 가능성 |

## 📔 journal/ — 일일 작업 기록

날짜별 진행·디버깅·검증 기록입니다.

| 문서 | 내용 |
|---|---|
| [`journal/2026-08-14.md`](journal/2026-08-14.md) | T1-4 인터프리터 커버리지 + T1-3 네이티브 코드젠 |
| [`journal/2026-08-15.md`](journal/2026-08-15.md) | P3/P4/P5 진행, 폴리 계층 완성, SEH 최소화, .text 평문 0 |
| [`journal/2026-08-16.md`](journal/2026-08-16.md) | btg_vault v3.3 (hardened) 정확한 해법 규명 |
| [`journal/2026-08-17.md`](journal/2026-08-17.md) | btg_vault v3.3 "solvable" 리디자인 |
| [`journal/2026-08-17-commercial-p2-risc-lift.md`](journal/2026-08-17-commercial-p2-risc-lift.md) | 상용 P2 RISC 리프터 커버리지 강화 + 핸들러 버그 수정 |

---

## 문서 유지보수 규칙

- **설계/구조** 문서는 `architecture/`, **로드맵/현황**은 `roadmap/`에 둡니다.
- **기능 구현·검증 리포트**는 `engine/`에, **챌린지**는 `vault/`에 둡니다.
- 날짜별 세부 기록은 `journal/`에 추가합니다.
- 모든 문서는 코드 위치(`file:line` 또는 `src/...`)를 명시해 추적 가능하게 유지합니다.