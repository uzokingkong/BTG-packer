# BTG Packer 문서 인덱스

문서는 현재 기준 문서, 계획, 역사 기록으로 구분합니다. 상태가 충돌할 때는 아래
“현재 기준” 문서가 우선합니다.

## 현재 기준

| 문서 | 용도 |
|---|---|
| [루트 README](../README.md) | 프로젝트 소개, 빠른 시작, 현재 요약 |
| [현재 구현 상태](current-status.md) | 구현/부분 구현/미구현의 단일 기준 |
| [시스템 아키텍처](architecture/system-overview.md) | 전체 CFG/PE/crypto/VM/QA 계층과 backend 관계 |
| [전체 소스 지도](architecture/source-map.md) | 269개 Rust 파일의 제품 계층·책임·API 지도 |
| [CLI 전체 레퍼런스](cli-reference.md) | 42개 option, 실행 모드, resolver 충돌 규칙, 산출물 |
| [실제 패킹 파이프라인](architecture/actual-pipeline.md) | pass와 boot/build 처리 순서 |
| [검증 기준](verification.md) | unit, structural, execution, tamper gate |
| [현재 구현 계획](../plan_vmrestore_upgraded.md) | 앞으로 구현할 작업과 완료 기준 |
| [2026-08-22 전체 계획 기록](history/plan_vmrestore_upgraded-2026-08-22-full.md) | 이전 감사·진행일지·장기 계획 원문 |
| [역사 문서 안내](history/README.md) | 대형 과거 원문과 현재 대체 문서 매핑 |

## 보조 아키텍처 문서

| 문서 | 범위 | 주의 |
|---|---|---|
| [Commercial VM engine](architecture/commercial-vm-engine.md) | RISC/poly/threaded 설계 배경 | 일부 경로·수치는 역사적 |
| [VM compiler architecture](architecture/vm-compiler-architecture.md) | compiler 모듈 설명 | 현재 구조는 system-overview 우선 |
| [Function atomicity/bridge](architecture/function-atomicity-bridge-spec.md) | ownership/bridge 계약 | 구현 상태는 current-status 확인 |
| [W^X memory model](architecture/wx-memory-model.md) | memory protection 설계 | profile별 실제 배치는 코드 기준 |
| [Coverage](architecture/coverage.md) | opcode/리프터 기록 | 특정 corpus 수치를 일반화하지 않음 |

## 계획 문서

`docs/roadmap/`은 제안과 과거 milestone을 보존합니다. 체크박스나 “DONE” 문구가
현재 production 연결을 자동으로 의미하지 않습니다.

- [commercial readiness](roadmap/commercial-readiness-plan.md)
- [commercial VM upgrade](roadmap/COMMERCIAL-VM-UPGRADE-PLAN.md)
- [implementation gaps](roadmap/implementation-gap-plan.md)
- [milestones](roadmap/milestones.md)
- [Themida parity missions](roadmap/themida-parity-missions.md)

## 역사 기록

다음 문서는 당시의 실험, 분석, 오류 수정 근거를 보존하며 현재 상태 문서가 아닙니다.

- `docs/journal/`: 날짜별 작업·디버깅 기록
- `docs/engine/`: 개별 기능 구현 보고서
- `docs/analysis-*.md`, `docs/*report*.md`: 특정 산출물 분석
- `docs/audit-*.md`: 특정 시점의 gap audit
- `docs/vault/`: 별도 CTF/challenge 기록
- `docs/integrity-*.md`: 이전 integrity 단계의 설계·실험 기록
- `docs/history/`: 현재 문서에서 분리한 대형 과거 계획·감사 원문

`docs/journal/2026-08-15.md` 일부에는 과거 저장 과정에서 손상된 문자(U+FFFD)가
남아 있습니다. 실행 계약의 근거로 사용하지 않으며 원문 추정 복원도 하지 않습니다.

## 유지보수 규칙

1. 현재 동작 변경은 `current-status.md`와 해당 canonical architecture 문서를 함께
   갱신합니다.
2. 테스트 수치는 실제 종료 결과가 있을 때만 기록합니다.
3. 계획은 “구현됨”, “부분 구현”, “계획”을 명시적으로 구분합니다.
4. 존재하지 않는 section/module 이름을 production 사실처럼 쓰지 않습니다.
5. 날짜 문서는 수정 당시 사실을 보존하고, 최신 판정은 canonical 문서로 링크합니다.
6. 현재 계획에는 미완료 작업만 두고 완료 과정은 journal/history로 이동합니다.
