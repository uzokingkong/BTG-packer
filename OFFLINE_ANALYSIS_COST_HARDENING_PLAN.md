# BTG 오프라인 분석 비용 강화 — 심화 구현 계획

작성일: 2026-10-03 (Asia/Seoul)
상태: catalog/map 감사와 opt-in literal 암호화 연결, release whitelist/캐시 연결 구현. opt-in private build key·초기화 PRF handler codec ABI v2 및 네 가지 64-bit ADD MBA recipe 구현. private 감사 export와 암호학적 table package 인증은 아직 미구현.
범위: 합법적으로 배포하는 소프트웨어의 오프라인 보호, 실행 의미 보존, 측정 가능한 분석 비용 증가.

## 1. 목표와 보장하지 않는 것

### 구현 현황 (2026-10-03)

- 후속 구현: `--literal-map`은 post_boot payload를 기존 부트 복호화 런에 연결하며 heuristic/full-section 데이터 암호화를 대체한다. 짧은 ASCII·UTF-8·UTF-16LE byte length를 유지하고 종결 NUL은 유지한다. metadata/실행 섹션/resource/소유권 충돌 및 호환되지 않는 복호화 경로는 실패한다. map 내용은 cache identity에 포함한다. 접근 시점은 작성자의 선언이며 모든 참조 안전성의 자동 증명은 아니다.
- 후속 구현: `--handler-prf`는 commercial whole-program VM의 opt-in ABI v2이다. `--private-build-key`는 선택적인 32-byte binary 입력이며 생략 시 seed-only를 유지한다. HKDF-SHA-256 context와 ChaCha20 mask를 host/native 양쪽에서 사용한다. invocation 초기화 단계에서 256 mask 생성·전체 상대 offset bounds 검사 후 ready marker를 공개하며 dispatch에서는 PRF/해시/할당을 수행하지 않는다. private key 내용 변경은 완료 package와 module checkpoint를 분리한다. 상세 계약과 한계는 `HANDLER_CODEC.md` 참조.
- 후속 구현: native harness와 commercial width-8 ADD handler에서 네 가지 MBA recipe를 사용한다. 결과 및 CF/PF/AF/ZF/SF/OF를 native ADD와 차등 검증한다. 좁은 폭과 ADC/SBB는 기존 경로를 유지한다.
- 후속 연결: literal map 빌드와 release-dir를 함께 지원한다. 입력/map snapshot을 검증·빌드·cache identity에 공통 사용하고, 암호화 전에 payload 및 owned terminator의 원본 해시를 검사한다. map을 output/manifest/log로 지정하는 경로는 차단한다. fresh build와 cache restore의 두 파일 release whitelist를 동일하게 적용한다.
- 후속 검증: 라이브러리 870개 및 CLI 통합 15개 통과. Windows controlled PE의 원본/packed/release 실행과 literal map + PRF/private key + cached release의 조합 실행을 확인했다. 기존 사용자 EXE는 실행하지 않았다.

- `src/pipeline/literal_catalog.rs`: 객체·접근 시점·증거 모델, 결정적 정렬, span/종결 소유권 충돌 검사, 제외 사유, aggregate-only 집계.
- `src/pipeline/literal_discovery.rs`, CLI: `--literal-catalog-only`는 readable/non-executable file-backed section에서 짧은 ASCII·UTF-8·UTF-16 후보를 read-only 수집한다. loader/resource 제외, 겹침 그룹, 종결 미확정 후보를 보존한다. 후보 타입과 승인 map 타입은 분리하고 자동 승인은 하지 않는다. 사용법·검사 범위·한계는 `LITERAL_CATALOG.md`에 기록한다.
- `src/pipeline/literal_map.rs`: typed map 및 strict JSON v1 parser, schema/입력 SHA-256, PE file-backed 범위, directory-owned 범위 충돌, encoding/종결 검증. 크기·객체 수 제한과 private 값 미노출 오류를 적용한다.
- `src/pipeline/literal_audit.rs`, CLI: `--literal-audit-only --literal-map <JSON>`는 패킹·로그·캐시 초기화 전에 read-only 감사 후 종료한다. 선언된 객체만 aggregate 출력하며 입력 EXE를 실행하거나 출력 파일을 만들지 않는다. 사용법은 `LITERAL_MAP_SCHEMA.md`에 기록한다.
- `src/pipeline/literal_metadata.rs`: normal/delay import 이름과 포인터 테이블, TLS template/index/callback array, security cookie의 간접 소유권 index. 중복 이름·lookup 참조는 캐시하고 병합된 범위에서 이진 검색한다. 해석 실패 시 감사도 실패한다.
- `src/release_export.rs`, CLI: 독립적인 `--release-export-only` 및 일반 빌드/완료 package 복원의 `--release-dir <new-dir>` 경로. EXE와 새 public manifest의 두 파일 whitelist, 명시적 private root 및 cache root 제외, preflight·새 디렉터리 예약·파일 목록/바이트 검증·기존 자료 보존. Windows case/reparse/경로 alias 검사. 배포 경로는 cache identity에서 분리한다. 사용법과 동시 경로 변경·hardlink 등의 한계는 `RELEASE_EXPORT.md`에 기록한다.
- 아직 없음: export/resource/unwind/LoadConfig의 전체 간접 소유권 분석, TLS callback literal 참조 분석, private 감사 export, 인증된 table package. catalog의 `Eligible`은 보호 완료가 아니다.
- 기본 linear codec은 유지하며 opt-in PRF codec의 초기화·dispatch를 추가했다. typed map의 접근 시점 선언만으로 모든 참조 안전성을 증명했다고 간주하지 않는다.
- 검증: 자동 후보 catalog 도입 후 라이브러리 회귀 862개, audit/catalog/export CLI 통합 7개 통과. Unicode/짧은 후보·metadata 제외·겹침·한도 실패·임의 2바이트 입력, read-only catalog의 산출물 미생성, Windows junction 거부, cache/private root 차단, 기존 release 보존, preflight, cache hit와 동일 export를 포함한다. 입력 EXE 자체는 실행하지 않는다.

목표는 한 번의 상수 추출 또는 한 종류의 패턴 매칭으로 전체 문자열·handler 테이블·원본 대응관계를 복구하는 경로를 줄이는 것이다. 성능 저하, 파일 크기 증가, 장애 위험도 함께 측정한다.

다음은 성공 조건으로 삼지 않는다.

- 실행 가능한 오프라인 프로그램에서 키나 평문을 영구적으로 숨긴다는 주장.
- 섹션 이름 변경이나 MBA 표현식 변경을 암호학적 보안으로 간주하는 것.
- 임의 PE 바이트만으로 모든 문자열 literal을 완벽하게 식별한다는 주장.
- 검증기를 완화하거나 실패를 숨겨 보호율을 높이는 것.
- 디버거·보안 제품 회피, 환경별 실행 방해, 분석 도구 공격 등의 신규 기능.

실행 시 필요한 평문과 주소는 관찰될 수 있다. 따라서 정적 복구 비용, 국소 노출의 파급 범위, 보호율과 의미 동등성을 별도로 평가한다.

## 2. 현재 소스에서 확인한 문제

### 2.1 문자열 경로

`src/pipeline/crypto/scan.rs`의 `scan_string_runs`는 현재 ASCII 8바이트 이상, ASCII 기반 UTF-16LE 8자 이상을 수집한다. UTF-8 일반 문자와 비ASCII UTF-16 전체를 처리하는 스캐너는 아니다. 섹션 선택도 이름에 의존한다.

512개 런·총 1MiB 제한은 앞선 수정에서 제거되었다. 그러나 이는 짧은 문자열과 Unicode 누락을 해결한 것이 아니다.

실제 확인한 `scratch/fefefwfwe.exe`에는 `IOError`, `@FAILED`, `@button` 같은 5~7바이트 문자열이 남았다. 비교된 원본 `.rdata`에는 길이 4~7의 변경되지 않은 ASCII 후보가 1,260개 있었다. **후보 수는 실제 literal 수와 같지 않다.** 일부는 바이너리 데이터의 우연한 printable 패턴이다.

`collect_string_protected_rva_ranges`는 로더 메타데이터 제외에 사용된다. 전체 `.rdata`를 암호화하는 방식으로 돌아가면 안 된다.

### 2.2 handler 테이블 키 경로

관련 파일:

- `src/vm/threaded/poly_direct/checksum.rs`: `per_op_key`.
- `src/vm/threaded/poly_direct/builder.rs`: master 분할, dispatch 복원, 테이블 생성.
- `src/vm/threaded/poly_direct/types.rs`: `SelfDecodingParts`와 관련 ABI.
- `src/vm/key_domains.rs`: seed 기반 HKDF 도메인 분리.

현재 식은 다음과 같다.

```text
master = a + b mod 2^64
MBA(a,b) = (a XOR b) + 2*(a AND b)
K(op) = (op*C1) XOR (op<<17) XOR C4 XOR master
encoded_handler(op) = handler_address(op) XOR K(op)
```

따라서 다음과 같은 구조적 약점이 있다.

1. MBA 식을 정규화하면 두 상수의 덧셈이 된다.
2. 알려진 `op`, 테이블 항목, handler 주소 하나로 master를 대수적으로 역산할 수 있다.
3. master는 seed에서 결정적으로 파생된다. 공개 seed와 파생 규칙을 알면 표현식 분석 없이 계산할 수 있다.
4. 코드상 슬롯은 256개다. 실제 사용하는 opcode 개수는 별도 측정해야 하며, “26개”로 고정해서 설계하면 안 된다.

HKDF 자체의 문제가 아니라 **입력의 공개성, 키 공유 범위, 주소 마스킹 방식**이 문제다.

## 3. 위협 모델과 평가 단위

| 관찰 수준 | 공격자가 가진 것 | 평가할 방어 효과 | 피할 과장 |
|---|---|---|---|
| 파일 정적 분석 | EXE, 공개 manifest, 공개 seed, 보호기 구현 지식 | 일괄 패턴 복구를 여러 단계의 모델링으로 바꾸는가 | 알려진 seed가 비밀이라는 가정 |
| 하나의 대응쌍 | opcode와 handler 주소 또는 literal의 평문/암호문 | 다른 모듈까지 대수적으로 전파되는가 | 국소 누출이 없다는 주장 |
| 정상 실행 관찰 | 복호화 전후 메모리, 실제 제어 흐름 | 노출이 어느 범위에 한정되는가 | 실행 관찰이 불가능하다는 주장 |
| 개발 지원 자료 | private map, checkpoint, key package | 배포 경계가 분리되는가 | 파일 이름만 private로 붙이면 안전하다는 가정 |

관측값: 복구한 유효 항목 수, 필요한 가정 수, 국소 대응쌍으로 복구되는 범위, 지원 자료 없이 복구 가능한 원본 RVA 수, 정상 실행 비용. 주관적인 “최상위 난도” 대신 반복 가능한 기준을 사용한다.

## 4. 공통 아키텍처 원칙

1. 원본 주소와 보호 객체의 식별자는 구분한다.
2. 분석 단계와 배치 단계, 암호화 단계와 런타임 접근 정책을 분리한다.
3. 바이트를 변경하는 모든 단계에는 소유권·참조·초기 접근 시점 정보가 있어야 한다.
4. 계획 객체는 sizing/provisional/final 빌드 동안 불변이어야 한다.
5. 모든 ABI 변경은 version으로 구분한다. 암묵적인 상수 변경을 금지한다.
6. 공개 manifest에는 집계 결과만, private evidence에는 구체적인 대응관계를 기록한다.
7. GUI, MPSC, spin/backoff, 대기 API, polling, allocator·문자열 hot path의 네이티브 유지 정책을 보존한다.

## 5. 작업 A — literal catalog와 문자열 보호

### A1. 신규 중간 모델

신규 제안: `src/pipeline/literal_catalog.rs`.

```text
LiteralId
LiteralSpan { rva, byte_len, encoding, terminator_len }
Evidence { direct_reference, pointer_reference, explicit_annotation, heuristic }
AccessPhase { loader, pre_boot_tls, bootstrap, post_boot, unknown }
Decision { protect, exclude(reason), require_annotation(reason) }
LiteralCatalog { objects, references, decisions, overlaps }
```

`byte_len`과 문자 수를 혼용하지 않는다. 종결 NUL의 소유 여부를 별도로 기록한다. 인접 literal, 중복 참조, 부분 문자열 참조는 객체 관계로 표현한다.

완료 조건: 모든 후보가 보호·제외·정보 부족 중 하나로 분류되고, 이유 없는 누락이 없다.

### A2. 식별 규칙

- ASCII: 짧은 후보도 수집하되, 1~3바이트는 참조·명시적 범위 등 추가 증거 없이는 자동 보호하지 않는다.
- 길이 지정 UTF-8: 유효한 디코딩, 정확한 길이, 참조 증거를 사용한다. NUL이 없다는 이유로 제외하지 않는다.
- NUL 종결 UTF-8: 제어 문자 정책을 명시하고 종결 바이트를 다루는 규칙을 고정한다.
- UTF-16LE: Unicode scalar 및 surrogate pair를 검증한다. byte alignment나 “유효 Unicode”만으로 literal이라고 판단하지 않는다.
- 길이 지정 UTF-16: 길이 단위가 byte인지 code unit인지 입력 스키마에서 명시한다.
- 짧은 literal과 Unicode-only literal은 참조가 확인되거나 사용자 제공 literal map으로 범위가 확인되는 경로를 우선한다.

스캔 과정에서 보호 메타데이터와 겹친 후보를 조용히 버리지 않는다. 분할이 정당한지 검증하거나 충돌 사유를 보고한다.

### A3. 정확한 보호 범위 입력

신규 제안: `src/pipeline/literal_map.rs`.

외부 바이너리만 받는 경우 타입 정보가 부족하므로, opt-in literal map을 지원한다. `schema_version`, 입력 SHA-256, RVA, byte length, encoding, 접근 시점 선언을 가진다.

입력 SHA-256 불일치, 범위 초과, 서로 다른 인코딩의 중복 span, 로더 영역 침범, PE에 존재하지 않는 RVA는 거부한다. pointer rewrite를 요청하는 map은 별도 기능으로 분리한다. map 제공만으로 모든 참조가 안전해지는 것은 아니다.

직접 소유한 소프트웨어는 컴파일·링크 단계에서 literal 범위를 내보내는 장기 경로를 둔다. 무조건적인 바이너리 추측보다 이 경로를 우선한다.

### A4. 접근 시점과 예외

수정: `src/pipeline/patch_data/protect.rs`, `src/vm/data_lifetime.rs`.

- import/IAT/delay import, TLS 구조·템플릿, LoadConfig, cookie, unwind·언어별 예외 메타데이터를 유지한다.
- TLS callback에서 읽는 literal은 일반 OEP 부트 복호화보다 먼저 접근될 수 있다. 코드 범위 제외만으로 data 접근 안전성이 증명되지 않는다.
- pre-boot 참조가 확인되면 기본은 제외·보고다. 복호화 순서 변경은 별도 검증된 작업으로만 도입한다.
- `.rsrc`는 일반 literal 데이터와 분리한다. manifest, icon, loader/shell 소비 데이터는 자동 일괄 암호화하지 않는다.
- 참조가 해결되지 않거나 별칭 관계가 불명확하면 안전성을 과장하지 않는다.

### A5. 암호화와 수명

수정: `src/pipeline/crypto/scan.rs`, `mod.rs`, `place/mod.rs`, `bootstub/ctx.rs`, `bootstub/emit.rs`.

catalog가 승인한 객체만 암호화 입력으로 사용한다. 이미 있는 ChaCha20-Poly1305 경로를 활용하고 임의 cipher를 추가하지 않는다. 객체별 독립 nonce/키 도메인과 object ID를 도입할지 먼저 설계·검증한다. nonce의 유일성 범위와 재빌드 정책을 문서화한다.

기본 정책은 post-boot 객체를 부트 시 복호화하는 호환성 경로다. 엄격히 증명된 call-scoped 객체만 별도 lifetime 경로로 처리한다. pointer가 호출 밖으로 탈출하거나 native code가 보관하는 객체에 자동 re-encrypt를 적용하지 않는다.

평문이 언제까지 필요한지 모르면 재암호화하지 않는다. 재암호화는 실제 lifetime과 동시 접근 규칙이 증명된 경우에만 적용한다.

### A6. 보호율 정의와 종료 조건

신규 제안: `src/pipeline/literal_audit.rs`.

세 가지 집계를 분리한다.

1. 승인된 literal 보호율: catalog에서 protect로 결정된 객체 대비 실제 암호화 객체.
2. 의도적 예외: 로더·pre-boot·resource·정보 부족별 객체 수와 바이트 수.
3. 잔존 후보: 승인 객체의 원본 바이트가 다른 파일 위치에 복사되어 남았는지 확인한 결과.

짧고 흔한 문자열이 ciphertext에 우연히 나타날 수 있으므로 단순 전체 파일 문자열 검색만으로 성공·실패를 판정하지 않는다. 원본 참조·소유 span·복사본 관계를 함께 사용한다.

strict 모드의 “완료”는 **선언된 보호 대상 100%, 이유 없는 누락 0**이다. PE 전체에 읽을 수 있는 글자 0이라는 뜻이 아니다. 후보가 완전히 해결되지 않으면 완료로 표시하지 않는다.

## 6. 작업 B — handler 테이블의 단순 환원 경로 축소

### B1. 키 모델을 먼저 확정

기본 가정은 외부 서버 없는 오프라인 동작이다. 다음 두 정책을 구분한다.

- 공개 seed만 사용하는 정책: 재현성 유지. 키도 공개 규칙으로 계산될 수 있다는 제한을 명시한다.
- 선택적 private build key 정책: seed와 독립적인 256-bit build key를 별도 입력으로 받고, 재현성은 같은 입력·seed·key·보호기 버전 조건으로 정의한다. 배포 EXE에서 사용되는 키는 결국 복원될 수 있다는 제한은 그대로다.

확정 정책은 **seed-only 기본 유지, private build key는 명시적 opt-in**이다. 옵션을 생략하면 기존 seed-only 계약을 유지하고 키 파일을 자동 생성하지 않는다. private build key를 생성하는 경우 별도 key package를 먼저 안전하게 저장한다. 중단·재개 시 같은 key를 재사용한다. key package 분실 시 동일 EXE 재현이 불가능할 수 있음을 명시한다. 키 원문은 로그·manifest·오류 메시지에 기록하지 않는다.

### B2. 독립 도메인과 canonical context

수정: `src/vm/key_domains.rs`.
신규 제안: `src/vm/handler_table_codec.rs`.

키 context에는 ABI version, module ID, architecture family, table ID, lane ID 등을 길이 구분 가능한 canonical encoding으로 넣는다. 해시맵 Debug 문자열이나 실제 배치 주소만을 객체 ID로 사용하지 않는다.

handler 주소 마스킹, bytecode 암호화, operand metadata, literal protection, integrity는 서로 다른 도메인을 사용한다. HKDF 출력 길이를 늘리는 것만으로 seed의 엔트로피가 늘어나지는 않는다.

### B3. 비선형 표준 PRF 기반 mask 검토

현재 opcode 선형식 대신 표준 PRF로 도메인별 mask를 만드는 후보를 평가한다. 구현 편의로 독자적인 hash/cipher를 설계하지 않는다.

확정 실행 정책은 **PRF 계산을 초기화 단계에 두고 dispatch에서는 계산하지 않는 것**이다. 아래 비교에서 접근 시 PRF는 초기 구현 범위에서 제외한다.

| 정책 | dispatch 비용 | 중요한 제한 |
|---|---|---|
| 초기화 때 mask 생성 후 사용 | 낮은 hot-path 비용 | 실행 관찰에서 mask 배열을 읽을 수 있음 |
| 접근 때 PRF 계산 | 높은 비용 | 키 입력을 추출하면 다시 계산 가능 |
| 모듈·lane별 독립 초기화 | 초기화·메모리 비용 증가 | 범위를 나누는 효과이지 추출 불가능성이 아님 |

초기화는 context 검증 → mask 생성 → table bounds 검증 → 완성된 immutable state 공개 순서를 따른다. 실패한 state는 dispatch에 공개하지 않는다. 재진입·동시 초기화에서는 state 소유권과 publication 순서를 명시하고, 부분 초기화 배열을 읽을 수 없게 한다. dispatch ABI에는 준비된 table/mask와 검증된 module base만 전달하며 PRF·HKDF·해시·메모리 할당을 hot path에 넣지 않는다. 초기화 이동은 성능 정책이지 메모리의 mask를 비밀로 유지한다는 보장이 아니다.

핵심 완료 조건은 한 개의 주소 대응쌍에서 **단순 대수식만으로 공통 master를 회수하는 기존 경로가 사라지는 것**이다. 알려진 PRF 입력·키를 통한 정상 계산까지 막았다고 주장하지 않는다.

64-bit mask는 주소 가림 수단이다. 그 자체를 인증 태그나 강한 암호문 무결성으로 사용하지 않는다.

### B4. 주소 표현과 배치

가능하면 테이블에는 module-relative offset과 명시적인 handler ID를 저장한다. 최종 주소는 검증된 module base에서 구성한다. 이것은 relocation 안정성과 주소 누출 범위를 관리하는 장점이지 원본 mapping을 완전히 숨기는 기법은 아니다.

수정 대상:

- `poly_direct/builder.rs`: 테이블 생성과 dispatch 소비를 같은 codec ABI로 전환.
- `poly_direct/types.rs`: table codec version, entry format, key context, offset bounds.
- `commercial_build.rs`: 테이블 배치와 길이 계산.
- `table_layout.rs`: version별 위치·정렬·크기.
- `route_metadata.rs`, `route_table.rs`: codec과 route 의미가 섞이지 않도록 경계 점검.

하나의 decoder 정의에서 host reference와 native emitter를 함께 검증한다. 두 경로가 우연히 비슷하게 동작하는 것으로 만족하지 않는다.

### B5. 인증·무결성 경계

기존 checksum은 오류 탐지와 보안 인증을 구분해 이름·문서를 수정한다. 인증된 테이블 패키지와 실행 시 주소 bounds check를 별도로 설계한다.

- version·module ID·entry count·layout을 인증 데이터에 포함하는 방안을 검토한다.
- 복호화·검증이 끝나기 전에 테이블을 dispatch 가능한 상태로 publish하지 않는다.
- 잘못된 opcode, 범위 밖 offset, 다른 모듈의 entry, 잘못된 version, 변조된 패키지는 주소를 사용하기 전에 실패한다.
- 인증 코드·키를 프로그램과 함께 제공하는 오프라인 모델에서는 프로그램 자체의 변경까지 불가능하다고 주장하지 않는다.

### B6. master 복원과 ABI

`a+b` MBA만 다른 항등식으로 교체하는 작업은 제외한다. 초기화·dispatch의 책임을 분리하고, key/context 복원은 명시적인 단계로 둔다.

수정: `threaded/runtime_layout.rs`, `vm_context.rs`, `poly_direct/builder.rs`, `types.rs`, `commercial_build.rs`, VM embed 초기화 코드.

확인 항목:

- Win64 nonvolatile GPR/XMM 보존, stack alignment, flags, VM return value.
- native-call bridge, cross-family call, tail-call, 예외 복귀.
- 재진입·동시 thread와 lane별 상태 소유권.
- 초기화 중 실패·예외에서 partially initialized state를 재사용하지 않는 규칙.
- key/context slot과 lifetime slot이 겹치지 않는 layout validation.

## 7. 작업 C — mapping과 개발 자료의 배포 경계

새로운 은닉 장치를 추가하기 전에 현재 산출물에 어떤 mapping이 필요한지 inventory를 만든다.

공개 EXE에는 실행에 필요한 정보만, private map에는 지원·검증용 원본 대응관계를 둔다. 필요한 runtime-route metadata를 무조건 지우지 않는다. producer별 unresolved target과 원본 entry ownership 규칙을 보존한다.

수정 검토: `vm/mapper.rs`, `pipeline/reports` 관련 코드, `manifest.rs`, `build_cache.rs`.

캐시와 key package는 배포물이 아니다. 문서와 .gitignore, 배포 whitelist에서 이를 명시한다. key를 command-line 인자 값으로 노출하는 설계보다 파일 입력을 우선 검토한다.

## 8. CLI·manifest·캐시 설계

아래 이름은 제안이며 확정 ABI가 아니다.

```text
--literal-policy legacy|catalog|strict
--literal-map PATH
--handler-table-codec legacy|v2
--build-key-file PATH
--emit-private-literal-audit PATH
```

기존 기본 동작을 즉시 깨지 않는다. strict는 보호 가능한 범위를 명확히 선언하고, 보호 요청이 충족되지 않으면 실패하도록 한다. 새 opcode codec은 feature-gated 경로로 시작한다.

공개 manifest: 정책·ABI version, 승인/보호/제외/불명확 객체 집계, 검증 시도 여부, 실제 성공 여부.
private evidence: literal span, 참조 provenance, 원본 대응관계, 정확한 제외 원인. 키 원문은 기록하지 않는다.

캐시 identity에는 literal map 내용 hash, key identity, codec version, 정책, 정확한 패커 바이너리 hash를 포함한다. key fingerprint를 공개 manifest에 실을지는 별도 결정한다. 캐시 hit에서도 필요한 진단·실행 검증을 건너뛰지 않는다.

## 9. 검증 매트릭스

### 문자열

- ASCII 길이 1/2/3/4/7/8, NUL 유무, 부분 문자열 참조.
- 한국어·일본어·emoji UTF-8, 잘못된 UTF-8, 제어 문자 포함 텍스트.
- UTF-16LE surrogate pair, 홀수 길이, unpaired surrogate, 정렬되지 않은 후보.
- 동일 literal 복수 참조, overlapping span, prefix/suffix alias, 인접 literal.
- 700개 이상 객체, 1MiB 초과, 테이블·파일·RVA 산술 overflow.
- import 이름, TLS template, pre-boot 읽기, cookie, unwind, resource 데이터의 보존.
- 포인터 escape, 다중 thread, 재진입, native reader와 VM reader 동시 접근.
- semantic/seeded/random 섹션 이름에서도 catalog와 감사가 RVA·객체 ID 기준으로 동작하는지.

### 테이블·runtime

- 실제 지원되는 모든 family × 여러 seed × 모든 유효 opcode.
- native/reference codec의 단일 항목 및 전체 테이블 동등성.
- 허용 entry 수, 사용되지 않는 opcode, bounds, offset sign/width.
- dispatch scratch register 및 VM 상태 보존.
- call/tail-call, bridge, REP loop, exception/unwind, thread bucket 재진입.
- 잘못된 module/version/lane, truncation, entry 교체, 인증 데이터 변조.
- sizing/provisional/final 길이·layout 불변성.
- 같은 입력·seed·key에서 결과 재현, 다른 key에서 분리, cache 중단·재개.

실제 사용자 EXE의 실행은 별도 동의·안전성 판단 후 수행한다. 우선 직접 만든 무해한 QA corpus로 실행 의미를 검증한다. 정적 패킹 성공을 실행 성공으로 기록하지 않는다.

## 10. 성능 예산과 승격 기준

초기 목표이며 실측으로 조정한다. 절대적인 성능 약속이 아니다.

| 지표 | 초기 gate |
|---|---|
| 보호 OFF 경로 | 의미 변경 0, 통계적으로 유의한 회귀 없음 |
| handler codec hot path | 기준 대비 중앙값 회귀 5% 이내 목표 |
| 초기화·부트 시간 | p95 회귀 10% 이내 목표, 원인별 breakdown |
| 메모리·파일 크기 | 객체/모듈/테이블별 증가량 보고, 상한 초과 시 명시적 실패 |
| 정확성 | 미해결 ABI/loader/exception 불일치 0 |
| 승인 literal 보호율 | 100%, 이유 없는 누락 0 |

동일 머신·전원 설정에서 warm/cold 실행을 분리하고 반복한다. GUI/MPSC/spin/allocator hot path는 VM으로 강제 이동하지 않는다. 목표를 넘으면 PRF를 약화하는 대신 초기화/캐시/경로 선택을 다시 설계한다.

## 11. 구현 순서와 각 단계의 산출물

### P0 — baseline 고정

현재 dirty source를 검토·보존하고 별도 baseline을 정한다. 문자열 잔존 감사, 알려진 MBA 환원 경로, 성능·파일 크기·검증 corpus를 기록한다. 이 문서 자체는 커밋·브랜치 변경을 수행하지 않는다.

### P1 — catalog·감사만 도입

암호화를 바꾸지 않고 후보·증거·제외 원인을 생성한다. 기존 출력과 의미·바이트 차이가 없어야 한다. 검사 가능 범위와 검사 불가능 범위를 먼저 고정한다.

### P2 — 짧은 ASCII·Unicode 보호

명시적 literal map과 참조 증거가 있는 객체부터 적용한다. loader/pre-boot 예외는 유지한다. 최소 문자열 fixture와 Unicode corpus에서 복호화 동등성을 확인한다. fefefwfwe의 확인된 누락 literal을 regression fixture로 포함한다.

### P3 — handler codec host reference

확정된 seed-only/optional private key 정책을 기준으로 codec version·entry schema·canonical context를 확정한다. host encoder/decoder와 알려진 대응쌍 테스트부터 만든다. legacy 경로를 제거하지 않는다. 초기화 전용 PRF와 dispatch 소비 계약을 별도 테스트한다.

### P4 — native emitter·배치·ABI 통합

reference 대비 native decoder 차등 검증, family별 실행, bridge/exception/reentry 검증을 수행한다. 레이아웃과 callback 접근 순서까지 확인한 뒤 승격한다.

### P5 — 국소 노출·감사·배포 경계

한 모듈의 mapping/키 관찰이 다른 모듈에 어떻게 전파되는지 측정한다. private evidence와 cache/key package를 배포 whitelist에서 분리한다. 안전성이 증명된 객체에 한해 lifetime 정책을 확대한다.

### P6 — 성능 검증·strict 정책 승격

전체 회귀, 실측, 잔존 감사, 재현/중단 재개를 통과한 정책만 opt-in strict로 승격한다. 완료 보고에는 예외·미검증 실행·동적 관찰 한계를 반드시 포함한다.

## 12. 사용자 확정 기준과 구현 계약

| 항목 | 확정 기준 |
|---|---|
| 키 정책 | seed-only 기본 유지. private key는 명시적 선택 기능 |
| literal 시작점 | map/catalog부터 도입. compiler/linker 연동은 후속 범위 |
| 초기 접근 | pre-boot/TLS는 보호 대상에서 제외하고 이유를 catalog에 기록 |
| 성능 우선순위 | dispatch hot path 최우선. PRF는 초기화 단계에서만 계산 |
| 배포 경계 | private map/key/cache는 release whitelist 밖의 별도 저장 영역 |

### 12.1 literal 승인 경계

P1은 catalog와 감사만 추가하고, P2는 명시적 map 또는 검증된 참조 증거가 있는 객체에만 적용한다. pre-boot/TLS 제외는 strict에서도 유지한다. 접근 시점을 입증하지 못하는 객체는 보수적으로 제외하거나 annotation을 요구한다. loader metadata 제외를 문자열 보호율 때문에 무시하지 않는다. compiler/linker 연동과 별도 TLS 복호화 경로는 이번 초기 구현에 포함하지 않는다.

### 12.2 release whitelist의 강제 경계

private map, key package, 캐시는 release 출력 디렉터리와 별도 root에 저장한다. `.gitignore` 또는 파일명 blacklist만으로 배포 제외를 보장하지 않는다. exporter는 승인된 artifact 역할과 정확한 경로의 whitelist만으로 새 staging 디렉터리를 구성한다. private 입력을 통째로 복사하는 디렉터리 복사 방식은 금지한다.

경로를 정규화하여 private root와 겹치는 export를 거부하고, symlink/reparse point를 통한 private root 유입도 검사한다. whitelist에 private artifact를 넣으려는 요청은 실패시킨다. 캐시 안의 EXE를 재사용할 때도 승인된 최종 EXE만 export하고 sidecar·키·catalog·중간 산출물은 따라 복사하지 않는다. public manifest는 필요한 버전·옵션·입력 식별 정보만 포함하며 private mapping이나 키 원문을 담지 않는다.

CI는 export 전 검사와 완성된 패키지의 파일 목록 검사를 모두 수행한다. private artifact 혼입, cache sidecar 자동 복사, private root 경로 alias, reparse point, 로그의 키 원문 노출을 음성 테스트로 고정한다. 기존 사용자 자료를 자동 삭제하지 않으며 분리·이관이 필요하면 대상과 정책을 별도로 정한다.

### 12.3 진행 순서와 남은 기술 결정

**P1 catalog/감사 → P2 승인 literal 보호 → P3 초기화 전용 codec reference → P4 native ABI 통합 → P5 배포 경계 검증 → P6 성능·전체 회귀** 순서로 진행한다. release 분리 계약은 P1부터 적용하며 P5까지 미루지 않는다. dispatch 성능 예산을 넘으면 구현을 승격하지 않고 초기화·메모리 비용과 함께 다시 측정한다.

남은 결정은 표준 PRF 선택, canonical context의 구체적 encoding, codec ABI와 초기화 state layout 등 기술 명세다. 위 다섯 정책은 확정되었으며 다시 미결 선택지로 취급하지 않는다. 이 문서 수정은 구현 완료를 뜻하지 않는다.
