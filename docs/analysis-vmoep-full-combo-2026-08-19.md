# BTG-Packer `--vm-oep --vm --integrity --anti-debug --chained-crypto --custom-cipher --block-ring --payload-relocate --vm-commercial -l 3` 패킹 실패 분석 (진행 중)

- 일시: 2026-08-19 (KST)
- 대상: 사용자 Zyris 노드(Windows)의 `btg-packer` 리포 작업 디렉토리
- 테스트 프로그램: `repro/test_prog.exe` (SHA-256 `0c978011…`, "Rust Advanced Protection Test & Win32 Cyber Defender Game v3.0" 콘솔 프로그램, 정상 실행 시 ~1460B 출력)
- 상태: **RESOLVED (2026-08-19 후속)** — 아래는 수정 전 실패 분석 기록. 최종 수정·검증은
  `docs/journal/2026-08-19-chained-integrity-fix.md` 참조 (풀 콤보/`--integrity --chained-crypto`
  모두 정상, exit 0 / 1460B / SHA=기준).

---

## 0. 요약 (TL;DR)

주어진 옵션 조합으로 패킹된 `test_prog.exe`는 실행 시 출력 없이 종료된다(실제로는 **0xC0000005 액세스 위반 / 0xC000001D ud2 크래시**; `%ERRORLEVEL%`이 0으로 보이는 건 cmd의 parse-time 확장 때문으로 오인). 이는 **단일 원인이 아니라 2개의 독립된 버그가 겹친 것**이며, 지금까지 다음을 확인했다.

1. **(1차 원인 — 확정·수정 완료) T0-3 "ASLR 보존" 회귀**: 보호 바이너리의 부트 스텁/VM 런타임은 핸드어셈블된 **선호 base(0x140000000) 기준 절대 주소**를 쓰는데, T0-3 변경이 ASLR(DYNAMIC_BASE)을 켜면서 reloc을 부실하게 만들어, 이미지가 선호 base가 아닌 주소로 로드되면 부트 스텁이 낡은 절대 주소에 쓰다 AV. → **보호 출력에서 ASLR을 비활성화**하는 수정을 `src/pipeline/build.rs`에 적용, 이 한 가지만으로 `--vm-oep --vm --vm-commercial`(fix2)과 기본 패킹(fix3)은 정상 출력 확인.
2. **(2차 원인 — 확인·수정 시도 중) `--integrity`의 S1 keyed-MAC 불일치**: ASLR 수정 후에도 **`--integrity`가 포함된 풀 콤보는 ud2 크래시**. MAC을 비활성화하면(CRC만) 정상 동작 → 부트 스텁이 재계산하는 keyed-MAC이 패킹 시 `BtgKeyedMac::mac` 값과 어긋난다. `emit_integrity_mac`의 레지스터 클로버/알고리즘 불일치로 추정, 현재 교정 중(아직 미해결).

---

## 1. 재현

```
btg-packer --vm-oep --vm --integrity --anti-debug --chained-crypto --custom-cipher --block-ring --payload-relocate --vm-commercial -l 3 -i test_prog.exe -o packed1.exe
packed1.exe        → exit 0xC0000005 (AV), 출력 없음
```

- 기존 `repro/packed_repro.exe`(같은 명령으로 생성)도 동일 — 0출력.
- cdb로 잡은 1차 크래시: `packed1+0xe0a2f: mov [rax+r11], r10` → **0x140279576 쓰기 실패(선호 base 절대 주소)**, `rax=0x140279326` = build 로그의 **VM state base** (`state_va=0x140279326`). 즉 **ASLR로 이미지가 rebase됐는데 부트 스텁은 선호 base 주소에 쓰고 있었다**.

## 2. 플래그가 각각 켜는 것 (src/ 기준)

| 플래그 | 기능 |
|---|---|
| `--vm-oep` | 부트 스텁이 원본 .text를 평문 복호화하지 않고, lift된 **전체 프로그램 VM(Program VM)**으로 OEP를 대체 (`ctx.vm_oep`). |
| `--vm` | 부트 스텁의 RC4 KSA(키 스케줄)를 생성된 VM 바이트코드/핸들러로 가상화. |
| `--vm-commercial` | `--vm-oep`의 백엔드를 상용 엔진(risc→poly→threaded)으로 전환 (`--vm --vm-oep --vm-commercial` 셋 다 켜야 활성). |
| `--chained-crypto` | 코드 영역을 256B 청크 체이닝 RC4로 암호화 (Key_i=이전 청크 평문, skip-ahead 차단). **`--vm-oep`/`--vm`을 무력화**하고 우선한다. |
| `--integrity` | 부트 스텁이 복호화 직후 코드 영역 CRC32 + S1 keyed-MAC 검증, 불일치 시 ud2. |
| `--anti-debug` | 부트 스텁의 PEB 3검(BeingDebugged/NtGlobalFlag/Heap.Flags) 안티디버그 블록. |
| `--custom-cipher` | BTG-C1(512-bit 스트림) 기본 암호. 단 chained/`--vm-oep` 경로는 RC4 전용이라 무시·RC4 폴백. |
| `--block-ring` | 디스패처에 "마지막 32개 dispatched logical block id" ring-buffer 주입(진단용). |
| `--payload-relocate` | 암호화된 코드 영역을 실행 불가 데이터 섹션 `.vdata`로 옮기고 `.textb`는 0 스테이징. 부트 스텁이 로드 시 복사+복호화. |

### 중요 상호작용: `--chained-crypto`가 `--vm-oep`를 끈다

`src/pipeline/crypto/mod.rs`에서

```rust
let chained_effective = enabled && chained && !reencrypt;
let vm_effective       = enabled && vm && !chained_effective && !reencrypt;
let vm_oep_effective   = vm_effective && ctx.vm_oep;
let vm_commercial_effective = vm_oep_effective && ctx.vm_commercial;
```

→ **풀 콤보에서 `chained_effective=true` ⇒ `vm_effective=false` ⇒ `vm_oep_effective=false`.** 즉 사용자가 요청한 명령의 결과물은 **VM 가상화가 전혀 쓰이지 않는 "네이티브 블록 + chained RC4 + integrity + anti-debug + payload-relocate + block-ring" 빌드**다. (이 점이 사용자 질문의 "vm-oep+vm-commercial 상호작용"의 핵심.) 추가로 `--custom-cipher`도 chained/`--vm-oep` 경로에선 `c1_mode=false`로 무시된다.

## 3. 1차 원인: T0-3 ASLR 보존 회귀 (확정·수정)

### 증거
- 동작하는 기준 바이너리 `target/packed_p61.exe`: **DllCharacteristics=0x8100 ⇒ ASLR(DYNAMIC_BASE)=OFF, RelocDir 없음** → 선호 base로 로드 → 부트 스텁 절대 주소 유효 → 정상.
- 실패하는 `v1_plain / packed1 / v2_vmoepcom`: 전부 **ASLR=ON(0x8160)**이며, reloc 테이블이 **부트 스텁 영역(entry 0xe0a00)을 전혀 커버하지 못함**.
  - v1_plain(default): 0xe0a74 `xor [rsi],r8b` → 0x1400eab30 쓰기 실패 (선호 base, rebase됐으므로 미매핑).
  - v2 (vm-oep): 0xe0a2f → 0x140279576 쓰기 실패 (VM state).
- `src/pe/reloc.rs`의 스캐너는 **8바이트 정렬 슬롯만** 검사하고, at-rest 경로는 암호화 범위를 보수적으로 `first_block_offset..btg 끝`으로 잡아 **평문인 부트 스텁까지 encrypted_rva_ranges에 포함**해 reloc에서 빠뜨린다. → 부트 스텁 imm64가 reloc 안 됨.
- `git` 상 `src/pipeline/build.rs`의 `let reloc_aware = true;`가 회귀 지점(T0-3).

### 수정 (적용됨, `src/pipeline/build.rs`)
```rust
let reloc_aware = false; // FIX(T0-3): boot stub/VM runtime is not ASLR-safe -> ASLR disabled for protected output
```
→ `preserve_aslr_bits` 미설정 ⇒ 빌더가 `clean_dll_characteristics`(ASLR/CFG 비트 스트립) 사용, `.reloc` 미생성 ⇒ **선호 base 로드**.

### 검증
- `fix2_vmoep.exe` (`--vm-oep --vm --vm-commercial -l 3`): **정상 전체 출력** ✅
- `fix3_plain.exe` (`-l 3` 기본): **정상 전체 출력** ✅

## 4. 2차 원인: `--integrity` S1 keyed-MAC 불일치 (확인, 수정 검증 중)

### 증거
- ASLR 수정 후 풀 콤보(`fix1_full.exe`)는 여전히 **0xC000001D(ud2)**.
- **`--integrity`만 뺀** 동일 조합(`iso_noint.exe`): **정상 출력** ✅ → integrity가 범인.
- **keyed-MAC만 제거**(`emit_integrity_mac` 주석 처리, CRC만 유지)한 빌드(`nomac_full.exe`): **정상 출력** ✅ → ud2는 CRC가 아니라 **keyed-MAC**(T2-3/S1)에서 난다.
- 부트 스텁 순서(`bootstub/build.rs`): `payload_copy → code_decrypt → emit_integrity_mac → emit_integrity_crc → …` — CRC가 통과하므로 데이터(복호화된 코드 영역)는 정상이고, MAC만 어긋남.

### 패킹 시 vs 런타임 MAC
- 패킹: `BtgKeyedMac::mac(seed_stored, crc_source)` (`src/crypto/mac.rs`). `new()`가 256B 시드를 흡수한 뒤 **`processed=0`**으로 시작, `update(data)`는 데이터 인덱스를 0부터 사용.
- 런타임: `emit_integrity_mac`(Phase A=키 흡수 256B, Phase B=데이터 흡수, Phase C=finish). Phase A에서 `seed_va[i] ^ bind_byte`로 seed_stored를 재구성(ASLR off ⇒ actual_base==image_base 성립), 알고리즘/키는 일치해야 함.
- **의심 버그 후보(수정 시도, 아직 미해결)**: Phase A/B의 키 바이트 계산에서
  ```
  imul rcx, r10        ; rcx = b*PHI
  mov  cl, dl          ; ← cl = i&63 가 rcx(==b*PHI)의 하위 바이트를 덮어씀!
  rol  rax, cl
  add  rcx, rax        ; rcx = (b*PHI, 하위바이트 오염) + rol(h0,i&63)
  ```
  즉 `mov cl, dl`이 RCX(=`b*PHI`)의 low byte를 클로버 → MAC 값이 패킹 시와 달라져 ud2.
- 이 지점을 "b를 RDX에 보존 → CL로 `rol(h0,i&63)`를 먼저 → RCX=b*PHI → 합산" 순서로 교정하는 수정을 `src/pipeline/crypto/integrity.rs`에 적용했으나, **여전히 풀 콤보는 ud2** (검증 진행 중). ※ 참고: `new()`가 `processed=0`이라 Phase B 데이터 인덱스가 0부터 시작하는 것이 맞으므로, 이전에 시도한 "Phase B 시작 인덱스=256" 변경은 **오류**여서 되돌렸다.

## 5. 확인된 수정 파일 (현재 작업 트리)

| 파일 | 변경 |
|---|---|
| `src/pipeline/build.rs` | `reloc_aware=false` — 보호 출력 ASLR 비활성화 (T0-3 회귀 수정) |
| `src/pipeline/crypto/integrity.rs` | `emit_integrity_mac` 키 바이트 계산 순서 교정 시도 (미검증) |

## 6. 남은 작업 (미해결)
1. `--integrity` keyed-MAC 불일치의 **정확한 원인 확정** 및 수정 완료(현재 시도 중인 레지스터 클로버 수정이 맞는지, 아니면 또 다른 요인인지 판정).
2. 풀 콤보(`fixmac_full.exe`)가 **정상 전체 출력**하는지 최종 검증.
3. (확인만 됨) `--chained-crypto`가 `--vm-oep`를 끄는 정책 — 사용자가 의도대로 "VM도 함께" 원한다면 별도 설계 판단 필요. 현재로선 풀 콤보가 "native+chained"로 동작하며 그 상태에서 정상 실행되게 하는 것이 목표.
4. 회귀 확인: `--vm-oep --vm --vm-commercial`(fix2)과 기본 패킹(fix3)이 수정 후에도 여전히 정상인지 재확인.
