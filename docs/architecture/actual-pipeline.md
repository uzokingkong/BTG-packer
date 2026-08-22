# 실제 production 파이프라인

현재 `src/main.rs`의 정상 패킹 경로를 코드 순서대로 설명합니다. CLI 조기 종료 모드는
[CLI 전체 레퍼런스](../cli-reference.md)에 별도로 정리합니다.

## 1. 요청 profile 해석

1. clap이 42개 CLI field를 `CliArgs`로 parse합니다.
2. `protection_profile::RequestedConfig::from_cli`가 보호 관련 요청을 snapshot합니다.
3. `resolve()`가 `--full`, crypto/VM 전제, M7 backend, 허용된 cipher 선택,
   reencrypt/mem-harden 충돌을 effective config로 정규화합니다.
4. hard error는 즉시 종료하고 warning은 출력합니다.
5. `--strict-profile`은 warning도 오류로 승격합니다.

## 2. 입력 PE와 context

- 입력이 없으면 기본 dummy PE를 생성할 수 있습니다.
- parser가 image base, entry RVA, `.text`, relayed sections, alignment와 directories를
  수집합니다.
- 마지막 original section 이후의 aligned RVA를 dispatcher base로 정합니다.
- `PipelineContext`를 만들고 seed가 있으면 모든 pack RNG를 고정합니다.
- MBA constant, effective crypto/VM/IAT/memory/diagnostic flags를 pass1 전에 기록합니다.

## 3. Optional selective marker 분석

crypto가 켜진 정상 pack에서 SDK marker를 scan합니다. 발견된 region은 selective
polymorphic VM으로 lift해 `poly_vm_regions`에 보존하고, 실패 region은 reject count에
기록합니다. 실제 section embed와 trampoline patch는 crypto placement 뒤 수행됩니다.

## 4. 공통 CFG/PE compiler pass

1. `pass1_slice`: `.text` CFG extraction과 trigger block slicing;
2. `pass2_shuffle`: seed 기반 physical order, table/block offsets;
3. `pass3_encode`: RIP/branch fixup과 native block encode;
4. `pass4_section`: dispatcher, table, boot reservation을 포함한 `.textb` 조립;
5. `patch_data`: moved sections, code/data pointers, security cookie와 CFG reference patch;
6. optional `iat_hide`: original import 수집/삭제, dummy import와 resolver metadata 준비.

이 단계는 native/legacy/commercial backend 모두가 공유합니다.

## 5. Crypto placement와 backend 선택

`pipeline::crypto::run`이 effective profile을 소비해 다음을 선택적으로 합성합니다.

- bulk C1/ChaCha20 encryption과 아직 이전되지 않은 legacy RC4 내부 경로;
- chained crypto 또는 native per-block reencrypt/M7 dispatcher;
- anti-debug and integrity boot stages;
- payload relocation, import resolution, memory hardening metadata;
- legacy KSA/PRGA VM module;
- legacy OEP Program-VM;
- commercial multi-family Program-VM.

### Commercial sub-pipeline

1. OEP reachable CFG/function과 native exclusion 수집;
2. x86 → canonical RISC lift 및 ownership 검증;
3. function-stable 4-family partition과 cross-family route 생성;
4. family별 ISA/grammar/rolling-key bytecode encode;
5. family별 native runtime/handler table/state/stack sizing build;
6. final VA로 route/state/table relocation 후 final build;
7. optional M7 family chunk와 data-lifetime object proof/toggle;
8. code/table/bytecode BTGI descriptor sealing;
9. family bridge `.pdata` range와 manifest ownership metadata 기록.

## 6. Boot 실행 순서

정확한 stage는 profile마다 다르지만 일반적인 순서는 다음과 같습니다.

```text
anti-debug / base bind / key setup
  → bulk or per-block payload preparation
  → code/string/program-bytecode decrypt as selected
  → CRC/multisite/BTGI integrity verification
  → IAT runtime resolution
  → memory protection transition
  → native dispatcher, legacy VM, or selected commercial family entry
```

Program-VM M7의 persistent family chunk와 object-lifetime toggle은 native M7 dispatcher와
다른 runtime입니다.

### RC1 이전 경계

현재 RC1에는 region-context ABI/provider와 M7 data-lifetime simulation이 구현돼 있습니다.
context는 region, family, function, predecessor와 integrity epoch를 분리해 서로 다른
키/nonce 문맥을 만듭니다. 이것은 production boot 경로 전체의 이전 완료를 뜻하지
않습니다. boot/native emitter에는 legacy RC4 KSA/PRGA가 남아 있고 `vm-oep` 및 chained
crypto 소비자도 아직 RC1 production ABI로 완전히 연결되지 않았습니다.

따라서 CLI에서는 새 RC4 선택을 차단하지만, 기존 내부 runtime 코드는 소비자 이전이
끝날 때까지 남아 있습니다. 문서와 manifest에서 이 상태를 "RC4 완전 제거" 또는
"모든 `.text`/VM bytecode가 RC1로 보호됨"으로 표시하지 않습니다.

## 7. 후속 section 처리와 PE build

1. `--rsrc-register`이면 relocated payload용 resource tree를 재구성합니다.
2. selective marker region이 있으면 `.btgvm` module을 embed하고 marker trampoline을
   patch합니다.
3. PE builder가 relayed sections, `.textb`, optional payload/VM sections와 directories,
   entry, checksum을 직렬화합니다.
4. `.pdata`/unwind, relocation/ASLR, load config와 section protection은 effective
   profile 및 실제 생성 range를 기준으로 만듭니다.

## 8. 검증과 sidecar

1. entropy report 출력;
2. structural validator로 새 PE 재parse/검사;
3. `--verify-output`이면 원본/보호본 실행 차등;
4. Program-VM ownership CSV 생성;
5. `.btgmanifest`에 hashes, build id, effective capabilities, ownership, execution 결과;
6. `--map/--sym-map` instruction/block/function/RISC mapping;
7. optional debug layout/disassembly 검증.

실행 차등 실패 산출물은 `.failed` 이름으로 격리됩니다.

## Library API 차이

`btg_packer::pack()`과 `pipeline::pack::run_full()`은 CLI 전체 profile resolver를 통과하는
동등 entry가 아닙니다. 기본 CFG pass와 crypto path를 in-memory로 호출하는 제한된 API로,
commercial VM, QA, maps와 모든 CLI 조합을 직접 노출하지 않습니다.

## 현재 미완료

- boot/native KSA·PRGA 소비자의 RC1 이전과 legacy RC4 구현 삭제;
- `vm-oep` 및 chained crypto production wiring의 RC1 전환;
- lifetime exception/unwind cleanup과 복합 memory proof;
- P2-11 handler body recipe execution-weight 확대;
- P2-12 RIP-relative runtime bundle과 N=20 signature gate;
- P2-15 bridge live-set/zeroization/oracle reduction;
- 최신 hostile/compiler corpus와 실제 20-seed release matrix.
