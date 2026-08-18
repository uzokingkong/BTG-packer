# BTG Packer — Themida급 도달 미션 보드 (Themida-Parity Missions)

> 기준: 2026-08-18 · repo `asdfsadfecwecc` (btg-packer)
> 상태 마커: ⬜ 미착수 · 🔶 진행 중 · ✅ 완료 · ⚠️ 게이트/리스크
> 관련: `implementation-gap-plan.md`(5축), `commercial-readiness-plan.md`(P0~P2),
>       `COMMERCIAL-VM-UPGRADE-PLAN.md` — 본 보드는 그 상위의 **우선순위 통합 미션**.

---

## Tier 0 — 실행 신뢰성 (이게 안 되면 아무것도 의미 없음)

| # | 미션 | 상세 | 상태 |
|---|---|---|---|
| T0-1 | **vm-oep 초소형 크래시 수정** | 1.5KB 바이너리(`dummy_target.exe`, 1536B) `--vm --vm-oep` 패킹 시 100% 크래시. 디스패처 바이트코드 포인터 손상 원인 규명. OEP→프로그램 VM 진입 경로의 버그 | 🔶 |
| T0-2 | **SEH/CRT/TLS 전 경로 검증** | RSP/RIP/UNWIND_INFO/.pdata 일관성. Rust unwind는 커버됐지만 C++ 예외(`__try/__except`)는 C++ 컴파일러 없어 미검증. CRT 초기화/DLL 경로 | ⬜ |
| T0-3 | **암호화 경로 ASLR** | 현재 `--no-crypto`만 reloc 지원. 기본(암호화) 경로는 로더가 `.reloc`을 복호화 전 적용해 암호문 파괴 → 릴로케이션 슬롯을 평문으로 남기거나 런타임 post-decrypt reloc | ⬜ |

## Tier 1 — 실제 컴파일러 매트릭스

| # | 미션 | 상세 | 상태 |
|---|---|---|---|
| T1-1 | **MSVC/MinGW/Clang 실제 빌드** | 현재 코퍼스는 Rust(MSVC 타깃)뿐. cl.exe/gcc/clang-cl 설치 후 C/C++ 페이로드, `-O0`~`-O3`/LTO/CET/CFG, SSE/AVX intrinsics, switch/indirect call, DLL/static·dynamic CRT 추가 | ⬜ |
| T1-2 | **CI 자동화** | 컴파일러 매트릭스 × 패킹 모드(plain/vm/vm-oep/commercial/m7) × 실행 검증을 매 커밋 실행 | ⬜ |

## Tier 2 — VM 아키텍처 고도화

| # | 미션 | 상세 | 상태 |
|---|---|---|---|
| T2-1 | **nested VM 실제 실행** | `VmCallBridge`는 참조 의미론만 있음. 서브 VM 레지스트리 + 폴리/네이티브 러너에 실제 재귀 실행 통합 | ⬜ |
| T2-2 | **handler 코드 본체 다형화** | 현재 같은 시드의 handler는 항상 같은 코드. junk insertion / instruction substitution | ⬜ |
| T2-3 | **VM state concealment** | 런타임에 VM 상태(레지스터/스택/키)를 분산·파편화, 실행 메타데이터 최소화 | ⬜ |
| T2-4 | **runtime metadata 최소화** | 브랜치 맵/키 스냅샷/디스패치 테이블의 평문 노출 축소 | ⬜ |

## Tier 3 — 암호·상용 요구사항

| # | 미션 | 상세 | 상태 |
|---|---|---|---|
| T3-1 | **crypto 교체** | BTG-C1/custom MAC을 검증된 AES-GCM/ChaCha20-Poly1305로 (현재는 obfuscation primitive로 봐야 함) | ⬜ |
| T3-2 | **성능** | VM 오버헤드 측정·튜닝 (handler 인라인화, dispatch 최적화), packer 자체 크기/속도 | ⬜ |
| T3-3 | **안정성/재현** | `unwrap()` 3,205개 정리, malformed PE 파서 하드닝, build_id 기반 크래시 재현 체계 | ⬜ |

---

## 공통 검증 게이트 (모든 미션)

- `cargo build --release` green · `cargo test --release --lib` green
- `--vm-test` ALL PASS
- pack→run 16-test + FINAL CHECKSUM `0x2cdc0e4511d84a64` 무회귀 (해당 경로)

## 진행 로그

| 일자 | 미션 | 작업 | 상태 |
|---|---|---|---|
| 2026-08-18 | — | 미션 보드 등록 | ✅ |
