# Literal map v1 — 감사 및 명시적 빌드 입력

`--literal-map`은 감사 또는 빌드 입력으로 사용한다. `--literal-audit-only`를 함께 지정하면 입력 EXE를 실행하거나 패킹하지 않으며 출력 EXE, 로그, cache, 감사 sidecar를 생성하지 않는다. 원본 map은 private 자료이므로 배포 디렉터리 밖에 보관한다.

빌드에서는 `--literal-map private.json`을 지정한다. 승인된 post_boot payload만 기존 부트 복호화 런에 연결하며 짧은 ASCII, UTF-8, UTF-16LE 길이를 그대로 유지한다. 종결 NUL은 암호화하지 않는다. map 모드는 heuristic 및 전체 데이터 섹션 암호화를 대체한다. 실행 섹션, 리소스, 빌드 메타데이터 충돌, 사라진 범위는 실패한다. no-crypto, chained crypto, dispatcher reencrypt 경로는 지원하지 않는다. 캐시는 map 내용 해시로 분리된다.

입력과 map은 로그·캐시·출력 생성 전에 한 번 캡처하고, 그 snapshot으로 검증·빌드·cache identity를 구성한다. 원본 payload 및 소유한 terminator의 해시를 암호화 직전에 다시 비교한다. 패치·메타데이터 제거 등으로 선언된 바이트가 변경되면 실패하며 다른 바이트를 대신 암호화하지 않는다. map 파일은 출력·manifest·로그 경로로 사용할 수 없다.

`--release-dir <새 디렉터리>`와 동시에 사용할 수 있다. fresh build와 cache restore 모두 `program.exe` + 새 `manifest.json` 두 파일만 export한다. `--private-root`로 map/key 폴더를 명시하면 해당 폴더와 배포 경로의 겹침도 차단한다. map/key 입력 경로가 release 내부를 가리키는 경우에는 preflight가 거부한다. private map 자체를 배포하거나 복사하지 않는다.

```powershell
.\target\release\btg-packer.exe -i "원본.exe" --literal-map "C:\private-build\literal-map.json" --literal-audit-only
```

```json
{
  "schema_version": 1,
  "input_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "spans": [
    {
      "id": 1,
      "rva": 4096,
      "byte_len": 3,
      "terminator_len": 0,
      "encoding": "utf8",
      "access_phase": "post_boot"
    }
  ]
}
```

위 SHA-256과 RVA는 형식 예시이며 실제 입력의 값으로 바꿔야 한다. 입력 SHA-256은 전체 원본 파일의 해시다. RVA는 파일 오프셋이 아니다. 숫자는 JSON 정수로 작성하고 16진수 `0x...` 표기는 사용하지 않는다.

- `id`: 중복 없는 unsigned 64-bit 객체 ID.
- `rva`, `byte_len`: unsigned 32-bit. 길이는 문자 수가 아닌 payload 바이트 수이며 0은 거부한다.
- `terminator_len`: 소유하는 NUL 종결 바이트 수. ASCII/UTF-8은 0 또는 1, UTF-16LE는 0 또는 2. payload 길이에는 포함하지 않는다.
- `encoding`: `ascii`, `utf8`, `utf16_le`. UTF-16LE payload 길이는 짝수여야 한다.
- `access_phase`: `loader`, `pre_boot_tls`, `bootstrap`, `post_boot`, `unknown`.

필드 누락·알 수 없는 필드·중복 필드·잘못된 enum·음수·범위 초과는 거부한다. 최대 JSON 크기는 16 MiB, 객체 수는 100,000개다. 객체의 소유 범위에는 종결 바이트가 포함되며 겹치는 객체를 거부한다. 부분 문자열·공유 literal의 관계 표현은 후속 schema에서 다룬다.

loader/pre-boot/TLS/bootstrap 객체는 제외하고 unknown 객체는 추가 annotation을 요구한다. `post_boot` 선언은 참조 분석으로 검증된 사실이 아니며, `eligible`은 암호화 완료나 실행 안전성 보장이 아니다. 현재 감사 출력은 map에 선언된 객체만 집계하며 파일 전체의 literal 완전성을 검사하지 않는다.

현재 메타데이터 감사는 PE32+만 지원한다. PE의 유일한 file-backed section에 완전히 포함되는지와 loader-owned 영역 충돌을 검사한다. 디렉터리 본체뿐 아니라 normal/delay import DLL 이름·hint/name·lookup/IAT/bound/unload table·delay module handle, TLS template/index/callback pointer array, LoadConfig security cookie도 제외 범위로 수집한다. IAT가 0으로 초기화되어도 lookup 길이에 맞춰 전체 IAT 범위를 수집하며 NUL 종결 slot도 포함한다.

메타데이터 해석이 실패하면 감사도 실패시킨다. 이는 임의 손상·특수 PE의 완전한 호환성을 보장하지 않는다. export/resource/unwind/LoadConfig의 모든 간접 metadata와 TLS callback의 실제 literal 참조 분석은 아직 미구현이다. 빌드 map의 post_boot 선언과 참조 안전성은 map 작성자가 확인해야 한다.

stdout에는 객체 수만 출력한다. 잘못된 JSON의 문자열 값이나 parser source excerpt는 오류에 포함하지 않는다.

map 없는 자동 스캐너는 읽기 전용 데이터 섹션의 ASCII 8바이트 이상 및 ASCII형 UTF-16LE 8문자 이상 런을 처리한다. NUL 종결이 확인되면 ASCII 4~7바이트 및 ASCII형 UTF-16LE 4~7문자도 처리하며 종결 NUL은 보존한다. 1~3문자, 비ASCII Unicode, 쓰기 가능 데이터의 선언된 literal은 명시적 map을 사용해야 한다. 모든 원본 데이터나 TLS 실행 전 참조 안전성을 자동으로 증명하는 기능은 아니다. 현재 build cache identity는 package-v7이며 stage AEAD v64와 VM 반환 규약 v32 이전 완성 패키지를 재사용하지 않는다. 자세한 보장 범위는 [BOOT_STAGE_AEAD.md](BOOT_STAGE_AEAD.md)를 참조한다.

Windows controlled fixture 검증은 원본·packed·release EXE를 실행해 승인된 짧은 ASCII/UTF-8/UTF-16LE의 복원, NUL 종결 및 미선언 인접 바이트 보존을 확인한다. PRF handler codec/private key를 함께 적용한 fresh build 및 cached release 실행도 검사한다. 사용자의 기존 EXE를 실행한 결과는 아니다.
