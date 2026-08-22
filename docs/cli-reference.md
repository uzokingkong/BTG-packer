# CLI 전체 레퍼런스

이 문서는 `src/cli.rs`, `src/protection_profile.rs`, `src/main.rs`를 함께 대조한
현재 CLI 계약입니다. `--help`는 요청 옵션을 설명하지만 실제 적용 여부는 profile
resolver가 결정합니다.

기준일: 2026-08-23

## 실행 모드 우선순위

`btg-packer`는 항상 패킹하는 명령이 아닙니다. `main.rs`는 다음 순서로 조기 종료
모드를 처리합니다.

1. `--verify-seeds N`: 자식 패킹/실행 검증 N개를 실행하고 종료;
2. `--vm-test`: VM self-test 후 종료;
3. `--vm-bench`: interpreter/native VM benchmark 후 종료;
4. `--text-vm`: `.text` lift coverage 진단 후 종료;
5. `--text-vm-oep`: OEP reachable CFG/Program-VM lift 진단 후 종료;
6. `--test-qa`: corpus 생성·QA 실행 후 종료;
7. `--qa-gen-corpus`: corpus 생성 후 종료;
8. 그 외: 정상 PE 패킹 파이프라인.

여러 조기 종료 옵션을 동시에 주지 않는 것이 안전합니다. 위에서 먼저 만나는 모드만
실행됩니다.

## 입력, 출력, 재현과 검증

| 옵션 | 기본값 | 실제 동작 |
|---|---:|---|
| `-i, --input <PATH>` | `dummy_target.exe` | 입력 Windows x86-64 PE. 파일이 없으면 일부 경로에서 dummy PE를 생성합니다. |
| `-o, --output <PATH>` | `protected_btg.exe` | 보호 PE 출력 경로와 sidecar 이름의 기준입니다. |
| `--seed <u64>` | OS entropy | shuffle, MBA, crypto, poly seed와 padding을 결정적으로 파생합니다. |
| `--strict-profile` | off | resolver가 경고할 downgrade/무시/우선순위를 오류로 승격합니다. |
| `--verify-output` | off | 원본/보호본의 exit code, stdout, stderr를 byte 단위 비교합니다. |
| `--verify-timeout-secs <N>` | `30` | 각 differential 실행 제한. 내부에서 최소 1초로 보정됩니다. |
| `--verify-seeds <N>` | `0` | N개 seed-suffixed output을 별도 자식 프로세스로 pack+execute합니다. |

실패한 `--verify-output` 산출물은 정상 이름에 남기지 않고
`<stem>.failed[.N].<ext>`로 격리합니다.

## 기본 CFG 패커와 진단

| 옵션 | 기본값 | 실제 동작 |
|---|---:|---|
| `-l, --obf-level <1..3>` | `3` | 1=basic, 2=MBA, 3=overlap+MBA. 일반 경로는 1..3으로 clamp합니다. native reencrypt/M7은 runtime 계약상 effective level 2입니다. |
| `-a, --anti-debug` | off | boot/dispatcher anti-debug 검사를 활성화합니다. |
| `--anti-debug-policy <trap|hang|warn|poison>` | `trap` | 탐지 후 UD2, 무한루프, fail-open, state poison 중 하나를 선택합니다. |
| `-d, --debug` | off | trace 수준 logging을 활성화합니다. |
| `-g, --log-file <PATH>` | 없음 | logger 출력을 파일로 보내고 종료 시 flush/sync합니다. |
| `--trace-blocks` | off | packed binary에 runtime block trace를 삽입합니다. |
| `--block-ring` | off | 표준 dispatcher에 최근 32개 logical block id ring을 둡니다. reencrypt dispatcher에서는 무시됩니다. |
| `--keep-pdata` | off | 원본 `.pdata`를 byte 그대로 유지하고 기본 dispatcher leaf 추가도 건너뜁니다. |

## VM 경로

| 옵션 | 기본값 | 전제와 경로 |
|---|---:|---|
| `--vm` | off | crypto boot KSA를 legacy VM으로 가상화합니다. crypto가 꺼지면 무시됩니다. |
| `--vm-oep` | off | OEP를 Program-VM entry로 전환하며 `--vm`을 암묵적으로 활성화합니다. crypto 필요. |
| `--vm-commercial` | off | `--vm-oep` backend를 RISC→poly→native threaded multi-family로 전환합니다. effective 조건은 `--vm-oep`와 crypto입니다. |
| `--m7` | off | native non-VM에서는 block on-demand reencrypt, commercial Program-VM에서는 family bytecode chunk와 data-lifetime을 활성화합니다. 다른 VM 조합에서는 무시됩니다. |
| `--m8` | off | VM handler table concealment/MBA runtime key를 활성화합니다. effective VM이 필요합니다. |
| `--vm-test` | off | lifter/interpreter/native handler self-test만 실행합니다. |
| `--vm-bench` | off | VM 처리량 benchmark만 실행합니다. |
| `--text-vm` | off | 패킹 없이 전체 `.text`의 legacy 1:1 lift 가능성을 보고합니다. |
| `--text-vm-oep` | off | 패킹 없이 OEP reachable CFG를 lift하여 Program-VM 크기/coverage를 보고합니다. |

`--vm`, `--vm-oep`, `--vm-commercial`은 같은 옵션의 단계가 아니라 서로 다른 backend
선택입니다. 현재 주력 production 경로는 다음과 같습니다.

```powershell
btg-packer.exe -i app.exe -o app.protected.exe `
  --vm --vm-oep --vm-commercial --m7 --m8 --integrity `
  --verify-output --strict-profile --seed 31010
```

## Crypto, integrity와 runtime hardening

| 옵션 | 기본값 | 실제 동작 |
|---|---:|---|
| `--no-crypto` | off | 기본 활성 crypto layer를 끕니다. VM/M7/chained/integrity 요청도 비활성 또는 오류가 됩니다. |
| `--crypto-mode <rc4|c1|chacha20>` | `c1` | 명시 선택이 `--rc4`/`--custom-cipher`보다 우선합니다. ChaCha20은 지원되는 bulk at-rest 경로에 적용됩니다. |
| `--custom-cipher` | 사실상 기본 | C1 선택을 명시합니다. 현재 기본이 C1이므로 단독으로는 변화가 없습니다. |
| `--rc4` | off | 기본 C1 대신 legacy RC4-256을 강제합니다. |
| `--crypto-coverage <0..100>` | `100` | bulk code 암호화 비율입니다. dispatcher reencrypt는 100으로 덮어씁니다. |
| `--chained-crypto` | off | 256B chained RC4와 seed/S-box/source zeroization 경로입니다. crypto 필요, dispatcher reencrypt보다 우선순위가 낮습니다. |
| `--dispatcher-reencrypt` | off | native shuffled block을 실행 전 decrypt/직후 reencrypt합니다. crypto 필요, writable `.textb` 때문에 mem-harden을 끕니다. |
| `--integrity` | off | boot CRC/multisite 및 적용 가능한 Program-VM BTGI 검증을 활성화합니다. crypto 필요. |
| `--iat-hide` | off | original imports를 runtime LoadLibraryA/GetProcAddress resolver table로 전환합니다. |
| `--mem-harden` | off | bootstrap 후 immutable code/table/bytecode를 RX, state/data를 RW로 분리합니다. 전환 실패는 fail-closed입니다. |
| `--payload-relocate` | off | encrypted payload를 non-executable `.vdata`로 이동해 boot에서 복원합니다. |
| `--rsrc-register` | off | relocated payload를 RT_RCDATA로 등록합니다. `--payload-relocate`가 없으면 하드 오류입니다. |
| `--full` | off | level3, anti-debug, dispatcher-reencrypt, integrity, payload relocate/resource, IAT hide, mem-harden 요청을 묶습니다. resolver에서 reencrypt가 mem-harden보다 우선하므로 최종 mem-harden은 꺼집니다. Program-VM은 자동 활성화하지 않습니다. |

## QA, mapping과 산출물

| 옵션 | 기본값 | 실제 동작 |
|---|---:|---|
| `-t, --test-qa` | off | multi-compiler corpus를 준비하고 compatibility suite를 실행합니다. |
| `--qa-commercial` | off | `--test-qa`의 각 대상을 commercial Program-VM strict differential로 검사합니다. 단독 사용은 효과가 없습니다. |
| `--qa-gen-corpus` | off | O0/O1/O2/O3/LTO/CGU16/panic-abort/overflow-checks corpus를 생성하고 종료합니다. |
| `--map` | off | `<output>.map` instruction-level VM mapping을 생성합니다. |
| `--sym-map` | off | `--map`을 포함하고 `<output>.sym` block/function mapping을 생성합니다. commercial RISC mapping은 CSV도 생성합니다. |

정상 패킹은 profile에 따라 다음 sidecar를 만들 수 있습니다.

- `<output>.btgmanifest`: hash, build id, effective feature/capability, 실행 검증 결과;
- `<output>.ownership.csv`: function ownership과 `.pdata` 대응;
- `<output>.map`, `<output>.sym`, RISC mapping CSV;
- multi-seed `<output>.seedgate.txt`와 seed별 PE/manifest/ownership;
- debug log와 실패 격리 artifact.

## Resolver 충돌 규칙

| 요청 조합 | effective 결과 |
|---|---|
| `--vm-oep --dispatcher-reencrypt` | Program-VM 우선, native dispatcher reencrypt 비활성 + 경고 |
| `--dispatcher-reencrypt --mem-harden` | reencrypt 우선, RX seal 비활성 + 경고 |
| `--no-crypto` + VM/M7/chained/integrity | 해당 기능 무시 또는 reencrypt 하드 오류 |
| `--m7` + commercial Program-VM | Program-VM chunk/data-lifetime M7 유지; native `ctx.reencrypt`로 취급하지 않음 |
| `--m8` without effective VM | 무시 |
| `--rsrc-register` without payload relocation | 하드 오류 |
| `--rc4 --custom-cipher` | RC4 우선 + 경고 |
| explicit `--crypto-mode` + legacy cipher flags | `--crypto-mode` 우선 + 경고 |
| `--strict-profile` + 경고 발생 | 패킹 전 오류 |

CLI 설명과 resolver가 충돌할 경우 `src/protection_profile.rs`의 effective config가 실제
동작의 기준입니다.
