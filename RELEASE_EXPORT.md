# Release whitelist export

별도 release를 구성하는 선택 기능이다. `--release-export-only`는 기존 최종 EXE를 export만 하며 패킹·입력 EXE 실행·기존 cache/진단 자료 삭제를 수행하지 않는다. 일반 패킹에서도 `--release-dir`을 지정하면 최종 빌드 또는 완료 package 복원 뒤 같은 whitelist로 export한다. seed-only 기본값은 그대로다.

```powershell
.\target\release\btg-packer.exe -i .\packed.exe --release-export-only --release-dir .\release-new --private-root C:\private-build\maps --private-root C:\private-build\keys
```

일반 빌드에 연결하는 예:

```powershell
.\target\release\btg-packer.exe -i .\original.exe -o .\packed.exe --seed 2 --build-cache --release-dir .\release-new --private-root C:\private-build\keys
```

release 경로·private root만 바뀌어도 package identity는 바뀌지 않는다. cache hit에서도 복원된 최종 EXE만 export하고 cache의 sidecar/키/진단 자료는 따라 복사하지 않는다.

일반 빌드는 `--literal-map` 및 `--handler-prf --private-build-key`와 함께 export할 수 있다. map/key 입력이 release 내부를 가리키면 preflight에서 거부한다. `--private-root`로 해당 입력 폴더를 명시하면 폴더와 release 경로의 겹침도 차단한다. literal map 빌드의 입력·map snapshot과 cache identity는 동일한 검증 내용을 사용한다.

`--release-dir`의 부모는 존재해야 하며 지정한 디렉터리 자체는 없어야 한다. 기존 디렉터리는 덮어쓰거나 재사용하지 않는다. export 성공 후에만 이 디렉터리를 배포한다. 원본 EXE와 기존 private 파일은 그대로 보존한다.

일반 빌드에서는 로그·cache·입력 자동 생성·출력 쓰기 전에 경로를 preflight한다. 로그를 release 안에 쓰는 옵션도 거부한다. 빌드/복원 뒤 export 시 경로를 다시 확인한다. 그 사이 destination이 생기면 실패하며 기존 자료를 삭제하지 않는다. export 실패 시 정상 작업 출력 EXE/package는 남을 수 있으며 이는 release 성공을 뜻하지 않는다.

Whitelist는 고정된 두 파일뿐이다.

- `program.exe`: 명시적으로 선택한 PE 파일의 바이트 그대로. 확장자가 EXE이고 PE로 파싱되는지 검사한다. 이것은 실행 정상성 검증이 아니다.
- `manifest.json`: schema version, 고정 artifact 이름, EXE SHA-256, 바이트 크기, `execution_verified: false`만 새로 생성한다. 기존 `.btgmanifest`를 복사하지 않는다.

`--private-root`는 반복 가능한 private 디렉터리 정책이다. `--cache-dir` (기본 `.btg-cache`)은 옵션 생략 여부와 관계없이 항상 private root에 포함한다. private root 안의 EXE도 직접 export하지 않는다. cache 복원으로 얻은 승인된 최종 EXE를 별도 작업 출력 위치에서 선택해야 한다. source 폴더의 map/key/cache/log/sidecar는 어떤 이름이든 따라 복사하지 않는다.

source가 private root 내부이거나 destination이 private root와 상하위 관계이면 거부한다. Windows 대소문자 차이, symbolic link, junction/reparse point, `..`, Windows 경로 component의 trailing dot/space와 ADS 표기를 거부한다. 존재하지 않는 private root도 기존 ancestor 기준으로 검증한다.

Windows component 비교는 `CompareStringOrdinal`의 case-insensitive 비교와 `CSTR_EQUAL = 2` 반환 규약을 사용한다. [Microsoft API 문서](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-comparestringordinal)를 기준으로 검사하고, canonical `\\?\` prefix 단독을 파일 노드로 조회하지 않는다.

export 후 실제 파일 목록과 두 파일의 바이트를 확인한다. 실패하면 이번 export가 생성한 두 파일만 정리하며 예상 밖의 다른 파일은 재귀 삭제하지 않는다. 정상 완료 전 외부 프로세스가 release 디렉터리를 소비하지 않아야 한다.

이 경계는 신뢰된 로컬 빌드 환경의 배포 실수를 막기 위한 것이다. 적대적인 프로세스가 동시에 경로를 바꿔치기하는 상황에 대한 handle-based/atomic publication 방어는 아직 없다. hardlink의 다른 경로까지 역추적하거나 EXE 내부에 private 자료가 포함되어 있는지를 판별하지도 않는다. 경로 정책만으로 모든 비밀의 비노출을 보장하지 않는다.

audit/QA/VM self-test/다중 seed 검증처럼 정상 패킹이 아닌 모드와 release export를 혼용하지 않는다. public manifest의 `execution_verified: false`는 exporter가 실행 검증을 수행·인증하지 않았다는 보수적인 표시이며, 일반 빌드의 기존 실행 검증 보고서를 새 manifest에 전달하는 기능은 아직 없다.

optional private build key 입력과 키별 cache 분리는 구현되어 있다. 자동 key 생성/package 보관 및 private 감사 export는 후속 단계다.
