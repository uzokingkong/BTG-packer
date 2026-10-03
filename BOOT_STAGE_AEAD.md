# Boot stage AEAD v64 감사 및 수정

현재 수정 범위는 기본 ChaCha20 bulk boot 경로다. legacy RC4/C1, chained crypto, dispatcher reencrypt는 이 보장을 공유하지 않는다. CRYPTO_VERSION=64, VM_VERSION=32, package cache identity=v7로 이전 패키지 복원을 차단한다.

## 우선순위

| 순위 | 문제 | 이번 결과와 한계 |
|---|---|---|
| P0 | 내부에서 복원 가능한 bootstrap root | 미해결. standalone 실행에 필요한 root는 여전히 파일에서 복원 가능하다. seed 기반 빌드는 seed를 아는 공격자에게도 비밀이 아니다. 외부 비밀/신뢰 경계 없이 난독화로 해결할 수 없다. |
| P0 | stage 공유 및 초기화 재사용 | Payload/Data/NativeText/Bytecode/Metadata/Resolver 6개 PRF domain과 레코드별 nonce로 분리했다. 정상적인 연속 스트림 자체가 nonce 재사용인 것은 아니다. 독립 소비·reset 지점의 경계를 명확히 했다. |
| P0 | 인증 없는 데이터와 구조체 사용 | 데이터·코드·바이트코드·resolver는 인증 후 복호화한다. 주소/길이/태그 테이블 전체를 먼저 인증하며 header 및 순서 변경도 거부한다. |
| P1 | 복호화 후 문자열 장기 생존 | 기존 literal map 수명 정책 외 일반 문자열의 수명은 미해결이다. 참조·캐싱 관계 확인 없이 재암호화하거나 삭제하면 프로그램이 깨진다. |
| P1 | 고정 실행 주소 및 규칙적 TLS/EP | 미해결. ASLR/relocation과 TLS 호출 순서의 별도 호환성 작업이 필요하다. |
| P2 | 테이블 식별성, GCC/Nim 흔적 | 테이블은 여전히 구조적이다. entry가 16에서 32바이트로 확장됐다고 은닉 문제가 해결되는 것은 아니다. 예외 처리·runtime metadata를 임의 삭제하지 않는다. |

## 구현

ChaCha20 block 0을 PRF로 사용해 stage마다 64바이트 material을 만든다. 앞 32바이트는 stage key, 다음 12바이트는 nonce base다. domain은 root nonce 앞 4바이트에 XOR한다. 각 stage 내 record index를 nonce 앞 8바이트에 XOR한다. HKDF 구현은 아니다.

레코드마다 block 0에서 Poly1305 일회용 키를 생성하고 ciphertext는 counter 1부터 처리한다. 태그 framing/AAD는 기존 RFC8439 ChaCha20-Poly1305 구현을 사용한다. runtime material pool은 파일에서 0이며 초기화 후 만들고 사용 종료 시 지운다. 루트 키 복원이나 실행 중 관찰에 대한 방어를 보장하지 않는다.

Data/NativeText entry는 `<VA:u64, length:u64, tag:16>`이다. 테이블의 header와 entry 전체는 Metadata domain의 별도 레코드로 인증한다. payload, bytecode, resolver는 각각 독립 domain의 record 0이다. TLS/W^X 때문에 평문으로 유지하는 native text는 NativeText의 예약 record `u64::MAX`로 인증한다. 최종 PE patch 및 VM decoy 변경 이후 태그를 확정한다.

구현 과정에서 기존 integrity dispatcher가 EDX의 seed 대신 EAX를 전달하던 오류와 classic Program VM HALT가 guest RAX 대신 caller RAX를 반환하던 오류도 수정했다. cipher helper 모드의 반환 규약은 유지한다.

## 검증

Host ciphertext/tag를 RustCrypto ChaCha20Poly1305와 비교한다. 6개 domain, 4개 record index, 9개 길이를 검증한다. Windows native stub 실행은 6×4×4 조합에서 material·nonce·인증·복호화 결과와 scratch 정리를 비교한다.

직접 생성한 무해한 PE에서 정상 실행과 release/cache 복원을 확인하고, data·descriptor VA/length/tag·header·record order·native text·실제 relocated bytecode·resolver·payload 변조가 인증 실패로 거부되는지 확인한다. relocation destination은 덮어써지는 staging 공간이므로 실제 파일 저장 source를 변조한다. 이 검증은 bootstrap 코드 자체 패치에 대한 신뢰나 사용자 프로그램 전체 기능의 동등성을 증명하지 않는다.

2026-10-03 검증 결과: 라이브러리 873/873, CLI 통합 18/18 통과, release 빌드 성공. 로그는 `artifacts/stage-all-lib-tests.log`, `artifacts/stage-all-cli-tests.log`, `artifacts/stage-release-build.log`이다. 기존 compiler warnings는 남아 있다.

사용자가 지정한 seed 2 및 anti-debug/VM/commercial/m8/integrity/relocation/IAT/memory-hardening 옵션으로 `C:\Users\uzoki\Downloads\main.exe`를 `packeds.stage64.exe`에 패킹했다. 기존 EXE는 보존했다. 출력 크기 8,306,176바이트, SHA256 `49d73c92cddf0081339e9bea7a16f02049a9d11559635f24ddfeb6c500e6a84f`. 약 2.974초 후 exit 0, stdout/stderr 0바이트이고 새 SystemSettings 프로세스가 응답했다. 기록은 `artifacts/main-stage64-runtime.json`이다.

파일 내 정확한 ASCII substring 횟수는 os.nim 1→0, IOError 6→0, OSError 3→0이다. comnim은 원본부터 0회였다. 기록은 `artifacts/main-stage64-string-scan.json`이다. 이 결과는 모든 명령 문자열이 사라졌거나 실행 후 메모리에도 문자열이 없다는 뜻이 아니다. 출력 manifest의 `aslr_preserved=false`도 확인했다.
