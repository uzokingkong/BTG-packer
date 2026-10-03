# Handler codec ABI v2

기존 seed-only/linear codec은 기본값으로 유지한다. `--vm --vm-oep --vm-commercial --handler-prf`로 초기화 PRF codec을 선택한다.

```powershell
.\target\release\btg-packer.exe -i input.exe -o protected.exe --seed 7 --vm --vm-oep --vm-commercial --handler-prf
# 선택적 32바이트 binary private build key:
.\target\release\btg-packer.exe -i input.exe -o protected.exe --seed 7 --vm --vm-oep --vm-commercial --handler-prf --private-build-key C:\private-build\key.bin --build-cache
```

키를 생략하면 seed-only 입력으로 동작한다. 키 파일은 정확히 32바이트의 binary 값이다. hex/JSON/passphrase 파일은 받지 않으며 자동 생성하지 않는다. 같은 입력·seed·옵션·키·보호기 버전이 재현 조건이다. 키 원문은 로그·manifest·cache identity에 기록하지 않는다. private cache identity에는 domain-separated digest만 사용한다. 키 변경 시 완료 package와 commercial module checkpoint 모두 분리된다. 중단 후 재빌드에는 같은 키를 보관해서 사용해야 한다.

ABI v2는 handler 테이블에 64비트 masked module-relative code offset을 저장한다. canonical context는 codec version, x86-64 architecture label, bytecode SHA-256 module ID, architecture family, table ID, logical table lane ID를 고정 폭으로 인코딩한다. 현재 production table/lane ID는 각각 0이다. 같은 논리 테이블의 invocation lane들은 같은 mask 값을 각자 소유한 state에 초기화한다.

빌드 시 HKDF-SHA-256으로 mask key/nonce를 분리하고 RFC 8439 ChaCha20 block counter 1..32에서 256개 mask를 만든다. native entry는 같은 PRF를 계산해 state의 `0x5200..0x5A00`에 mask를 생성한다. `0x5A00`의 ready marker는 모든 offset bounds 검사 후 2로 publish한다. 작업용 `0x5A10..0x5A90`은 초기화 후 지운다. 이 범위는 기존 virtual stack·cross-family control·return stack과 분리되며 production의 0x8000 state stride 안에 있다. 네이티브 helper는 기존 unwindable nonvolatile frame을 사용하고 별도 host-stack workspace를 만들지 않는다.

dispatch는 ready marker 확인, mask lookup/XOR, offset bounds 검사, RIP-relative module base 추가만 한다. HKDF, PRF, 해시, 할당은 dispatch에 없다. initialization은 invocation마다 수행한다. state lane의 독점 소유권은 기존 native gateway/cross-family depth 계약이 보장하며, 외부 library 호출자는 state를 동시에 공유하면 안 된다. 부분 초기화 state는 dispatch하지 않는다.

mask는 주소 가림 수단이며 인증 태그가 아니다. 기존 unkeyed table checksum은 손상 진단으로 유지한다. 암호학적으로 인증된 table package는 이 변경 범위에 포함하지 않는다. 실행 관찰로 key/mask/address를 추출할 수 있으며 seed-only key는 공개 seed에서 다시 계산할 수 있다. 한 대응쌍에서 기존 선형식의 공통 master를 대수적으로 복원하는 경로를 PRF로 대체한다.

MBA 64-bit ADD는 XOR carry split, OR/AND, De Morgan OR/AND, reversed AND/OR의 네 가지 recipe를 제공한다. native harness와 commercial width-8 ADD handler에서 seed로 선택한다. 마지막 ADD가 CF/PF/AF/ZF/SF/OF를 생성하며, 네 가지 변형을 native ADD와 차등 검증한다. 좁은 폭 및 ADC/SBB는 기존 emitter를 유지한다.

검증: 라이브러리 873개와 CLI 통합 18개 통과. 256개 host/native mask 일치, 네 architecture family의 seed/private-key 실행 동등성, commercial sizing/final placement와 중첩 family 호출, 네 MBA recipe의 native result/flags, 키 변경 시 cache 분리 및 완료 출력 복원을 포함한다. Windows에서 직접 생성한 controlled PE는 짧은 ASCII·한글 UTF-8·UTF-16 surrogate pair와 종결/미선언 데이터의 바이트를 직접 검사한다. literal map + PRF codec + private key 빌드 및 cached release EXE 실행도 통과했다. stage AEAD 실행·변조 검증과 보장 범위는 [BOOT_STAGE_AEAD.md](BOOT_STAGE_AEAD.md)를 참조한다. 사용자의 main.exe 원본 및 패킹본의 별도 실행 관찰도 수행하며, 종료 코드만으로 프로그램 전체 기능의 동등성을 증명하지 않는다.
