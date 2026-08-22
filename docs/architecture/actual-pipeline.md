# 실제 production 파이프라인

현재 `main`의 Program-VM 최대 경로를 코드 처리 순서대로 설명합니다. 상태 판정은
[현재 구현 상태](../current-status.md), 구성요소 관계는
[시스템 아키텍처](system-overview.md)를 함께 참고하세요.

## 1. Profile 정규화

`src/cli.rs`의 요청 옵션을 `src/pipeline/config.rs`가 effective profile로
정규화합니다. 상충 기능은 비활성화되거나 fallback될 수 있으며,
`--strict-profile`은 이 downgrade를 오류로 바꿉니다.

주력 commercial path:

```text
--vm --vm-oep --vm-commercial [--m7] [--m8] [--integrity]
```

## 2. 입력 분석과 native exclusion

1. PE header, section, import, `.pdata`, relocation 정보를 parse합니다.
2. OEP reachable CFG와 함수 범위를 수집합니다.
3. TLS, unwind/panic, setjmp/longjmp, loader-critical 함수와 proof가 불완전한
   범위를 native로 유지합니다.
4. virtualized 함수와 native 함수 ownership overlap을 fail-closed 검사합니다.

핵심 코드: `src/pe/`, `src/vm/text_lift/`, `src/pipeline/crypto/place/lift.rs`.

## 3. RISC lift와 family partition

1. 선택된 x86 함수 body를 canonical RISC micro-op으로 lift합니다.
2. `ProductionFamilyPlan`이 function id/seed로 architecture family를 정합니다.
3. function op range를 family-local `RiscProgram`으로 절단합니다.
4. direct edge 중 family가 다른 CALL/JUMP를 canonical route record로 만듭니다.
5. 대형 production 입력은 instance 3개 이상, 최대 단일 ownership 50% 미만을
   검사합니다.

핵심 코드: `src/vm/risc/`, `src/vm/poly/architecture_family.rs`,
`src/vm/multi_family.rs`.

## 4. Family-local materialization

각 family에 대해 독립적으로 다음을 수행합니다.

1. family/seed domain의 opcode/register/condition map 생성;
2. family별 operand 순서와 branch token grammar로 bytecode encode;
3. rolling-key stream encryption;
4. native self-decoding handlers/runtime 생성;
5. concealed handler table과 family별 integrity traversal 생성;
6. state/stack/control area 할당;
7. cross-family route target VA/state/layout 확정.

두 번의 sizing/final build는 code/table length drift를 검사합니다.

핵심 코드: `src/vm/poly/`, `src/vm/threaded/poly_direct/`,
`src/pipeline/crypto/place/vm_build.rs`.

## 5. 보호 계층과 배치

1. family code/table/bytecode blob을 합치되 각 range metadata를 유지합니다.
2. M7 사용 시 family bytecode를 instruction boundary chunk로 persistent 암호화합니다.
3. strict proof를 통과한 문자열과 exact-width constant-pool lifetime object를
   at-rest ciphertext로 변환하고 공통 owner/depth/lock table을 연결합니다.
4. final runtime representation을 기준으로 family code/table/bytecode를 sealing합니다.
5. 최대 12개 descriptor를 `BTGI` table로 serialize합니다.
6. profile에 따른 transient boot crypto wrapper를 적용합니다.
7. boot stub, run table, seed/state, VM blob을 PE section에 배치합니다.

핵심 코드: `src/pipeline/crypto/place/mod.rs`, `src/vm/chunk_crypto.rs`,
`src/vm/data_lifetime.rs`, `src/vm/distributed_integrity.rs`.

## 6. Boot 순서

RC4 Program-VM/integrity 경로의 주요 순서는 다음과 같습니다.

```text
anti-debug / base bind / key setup
  → code and run decrypt
  → Program-VM transient bytecode decrypt
  → BTGI distributed integrity verification
  → additional multisite integrity checks
  → IAT/memory hardening stages
  → selected family runtime entry
```

BTGI verifier는 magic, 1..12 count, region tag를 fail-closed하고 성공 시 사용한
GPR을 복원하여 이후 integrity stage의 live state를 보존합니다.

핵심 코드: `src/pipeline/crypto/bootstub/build.rs`,
`src/pipeline/crypto/integrity.rs`.

## 7. PE 합성과 unwind

- family runtime/bridge range를 기준으로 `.pdata` `RUNTIME_FUNCTION`을 생성합니다.
- native 원본 entries와 새 bridge unwind contract를 검증합니다.
- relocation/ASLR과 memory protection은 effective crypto profile에 따라 결정됩니다.
- 항상 고정된 `.btgvmx/.btgvmd/.btgvms` 세 section이 생성된다고 가정하지 않습니다.

핵심 코드: `src/pipeline/build.rs`, `src/pipeline/validate.rs`.

## 8. 검증

패킹 후 structural validator가 section/entry/ownership/`.pdata`/VM range를 검사합니다.
`--verify-output`을 사용하면 원본과 보호본의 exit/stdout/stderr도 비교합니다.

현재 대표 실측은 [검증 기준](../verification.md)에 기록합니다.

## 현재 미완료

- lifetime scope의 exception/unwind cleanup과 복합 memory proof;
- P2-11 handler body recipe의 execution-weight 80% 확대;
- RIP-relative runtime bundle과 N=20 anchor signature gate;
- native bridge live-set marshaling 및 canonical image zeroization;
- 최신 전체 hostile corpus와 실제 20-seed pack+execute gate.
