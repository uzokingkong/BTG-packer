# Heuristic literal candidate catalog

```powershell
.\target\release\btg-packer.exe -i .\input.exe --literal-catalog-only
```

읽기 전용 후보 발견 모드다. 입력 PE를 실행·패킹·수정하지 않으며 입력이 없을 때 테스트 EXE를 자동 생성하지 않는다. 로그/cache/catalog sidecar도 만들지 않는다. stdout은 집계뿐이며 평문, RVA, 파일 경로를 출력하지 않는다.

PE32+의 읽기 가능하고 실행 불가능한 section의 file-backed 범위를 검사한다. section 이름을 기준으로 고르지 않는다. 코드 section, header, zero-fill tail은 검사 범위 밖이다.

- ASCII는 1바이트부터 수집한다. UTF-8은 엄격하게 scalar를 디코딩한다.
- UTF-16LE는 두 byte alignment를 검사하고 surrogate pair를 검증한다.
- control 문자는 TAB/LF/CR만 허용한다. 공백만으로 된 후보도 참조 증거 없이 literal이라고 단정하지 않는다.
- 종결 NUL이 있는 후보는 종결 바이트의 범위를 포함한다. 종결이 없거나 제어/손상 바이트에서 잘린 run도 미확정 후보로 보존한다. 이는 실제 문자열 길이 증명이 아니다.
- overlapping span은 버리지 않고 connected overlap group의 후보를 `ambiguous`로 표시한다. UTF-8/UTF-16의 겹침과 부분 문자열 소유권은 후속 참조·annotation으로 풀어야 한다.

loader metadata와 겹치면 `excluded_loader`, resource directory를 담는 section의 나머지 후보는 보수적으로 `excluded_resource`로 분류한다. resource directory가 다른 데이터와 section을 공유하면 그 section 전체가 이 정책의 영향을 받는다. 그 외에는 접근 시점과 참조가 미검증이므로 모두 `require_annotation`이다. TLS callback이 실제로 읽는 literal을 자동으로 추적하지는 않는다.

`eligible=0 encrypted=0`이 항상 명시된다. 후보 catalog 타입은 승인된 disjoint literal map과 다르며 암호화 입력으로 자동 변환하지 않는다. 후보 수를 진짜 literal 수나 보호율로 해석하면 안 된다. 임의 PE 전체의 문자열 완전성도 보장하지 않는다.

최대 후보 수는 1,000,000개이며 초과하면 부분 catalog를 완료로 반환하지 않고 실패한다. 순서와 겹침 판정은 결정적이며 overlap 처리는 정렬과 선형 sweep으로 수행한다. metadata index는 입력당 한 번 만든다.

명시적으로 소유 범위·인코딩·접근 시점을 아는 객체는 별도 `--literal-audit-only --literal-map <JSON>` 경로로 검증한다. private catalog/map export와 암호화 연결은 아직 후속 작업이다.
