# 시스템 아키텍처

이 문서는 현재 production Program-VM 경로의 소유권과 데이터 흐름을 설명합니다.

## 계층

```text
CLI / resolved profile
        │
PE parse, CFG, function discovery
        │
native exclusion and ownership proof
        │
x86 function regions ──► RISC micro-op program
        │
ProductionFamilyPlan
        │
MultiFamilyProgramPlan
        ├─ Stack partition
        ├─ Register partition
        ├─ MixedRisc partition
        └─ FusedCisc partition
        │
family-local encoder + native runtime builder
        │
PE placement / boot / integrity / validation
```

## 컴파일 단계

1. `text_lift`가 OEP reachable CFG와 함수 범위를 분석합니다.
2. TLS, unwind, panic, setjmp/longjmp, loader-critical 범위는 native exclusion으로
   유지합니다.
3. lift 가능한 함수는 canonical `RiscProgram`으로 변환합니다.
4. `ProductionFamilyPlan`이 function id와 seed로 family ownership을 정합니다.
5. `MultiFamilyProgramPlan`이 family-local program과 cross-family route를 만듭니다.
6. 각 family는 독립 ISA domain으로 bytecode를 encode합니다.
7. `poly_direct`가 family-local native self-decoder와 handlers를 생성합니다.

## Family-local 자산

각 runtime instance는 다음을 공유하지 않습니다.

- native handler/runtime code range;
- 256-entry concealed handler table과 operand/condition metadata;
- polymorphic bytecode stream과 rolling-key domain;
- mutable VM state와 guest stack;
- canonical call/return control slots;
- M7 chunk plan과 distributed-integrity descriptors.

family 간 직접 제어 이동만 canonical bridge contract를 사용합니다. 같은 family의
branch는 local branch map fast path를 유지합니다.

## Bytecode grammar

공통 논리 레코드는 opcode, 선택적 condition, 세 operand descriptor, 선택적 immediate로
구성되지만 물리 표현은 family마다 다릅니다.

| Family | Operand descriptor 순서 | Absolute branch target |
|---|---|---|
| Stack | dst, src1, src2 | Stack-local compact marker |
| Register | src1, src2, dst | Register-local compact marker |
| MixedRisc | src2, dst, src1 | MixedRisc-local compact marker |
| FusedCisc | src1, dst, src2 | FusedCisc-local compact marker |

ordinary immediate는 값에 맞는 최소 unsigned/signed 1/2/4/8-byte masked payload를
사용합니다. unsigned marker `0x01..0x04`와 signed marker `0x05..0x08`의 width 의미는
family마다 순열화되며 encoder, static decoder, interpreter, native self-decoder가 같은
family-local 표를 소비합니다. signed payload는 mask 복원 직후 해당 폭에서 64비트로
sign-extend합니다. 절대 branch target도 별도 family-local marker와 최소 1/2/4/8-byte
masked payload를 사용합니다. AddWithCarry의 별도 carry payload만 고정 8-byte ABI를
유지합니다.

## Runtime entry와 integrity

1. boot stub이 profile에 따른 code/data transient 암호화를 복원합니다.
2. BTGI verifier가 family code/table/bytecode descriptor를 검증합니다.
3. family entry가 state, stack, table, bytecode domain을 초기화합니다.
4. handler-table self-check가 family별 traversal grammar로 실행됩니다.
5. rolling-key resync 뒤 opcode fetch와 per-opcode table key derivation을 수행합니다.
6. handler는 다음 dispatch 또는 cross-family router로 tail transfer합니다.

BTGI ABI:

```text
header: magic u32 | count u32
entry : kind/policy 8B | VA 8B | length 8B | runtime tag 8B | domain key 8B
```

## PE 배치

실제 배치는 `src/pipeline/crypto/place/mod.rs`와 `vm_build.rs`가 결정합니다. 합쳐진
Program-VM blob 안에서도 family별 code/table/bytecode range를 끝까지 보존하며,
mutable state는 `MULTI_FAMILY_STATE_STRIDE`로 격리합니다. `.pdata` builder는 각
family native bridge range를 별도 `RUNTIME_FUNCTION`으로 등록합니다.

문서에서 `.btgvmx/.btgvmd/.btgvms`가 항상 생성된다고 가정하면 안 됩니다. 실제
section 이름과 protection은 선택 profile과 PE builder 결과가 기준입니다.

## Family state 배치

각 production family는 `0x8000` stride로 격리됩니다.

| Family-relative 범위 | 용도 |
|---|---|
| `0x0000..0x0400` | split GPR/control bank A |
| `0x0400..0x0800` | split GPR/control bank B |
| `0x0800..0x1000` | transient spill window |
| `0x1000..0x1060` | XMM backing window; core state 끝 |
| `0x4000..0x5000` | entry family가 소유하는 256×16B lifetime sync table |
| `0x5000..0x5018` | cross-family continuation과 shared table pointer metadata |
| stride 끝쪽 | return call stack |

`0x1060`은 handler가 사용하는 core state의 크기이고 `0x8000`은 sidecar/control 영역을
포함한 family allocation stride입니다. lifetime table은 entry family에 한 번만 있으며
다른 family는 `+0x5010`의 절대 pointer로 같은 table을 참조합니다.

## 안전 경계

- ownership proof가 실패한 함수나 객체는 native/fail-safe로 남깁니다.
- large production partition은 instance 수와 최대 ownership을 fail-closed합니다.
- descriptor OOB, overlap, overflow, table capacity 초과는 패킹을 실패시킵니다.
- execution correctness는 `--verify-output`으로 원본과 비교할 수 있습니다.

## 아직 남은 구조 작업

- RIP-relative runtime bundle materialization;
- handler synthesis recipe coverage 확대;
- data-lifetime exception/unwind cleanup과 복합 access proof;
- native bridge canonical-image zeroization/oracle reduction.
