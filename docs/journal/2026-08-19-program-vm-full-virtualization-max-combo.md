# 2026-08-19 — ① 프로그램 VM 전체 가상화(program-VM full-virtualization) Max 콤보 검증 완료

## 요약

`test_prog.exe`(기준 출력 1460B, SHA256 `4366e2530f32a088306efe497d1762e5a087c54ac6c114b44f3ee13d422dcfe5`)에 대해
**확장 최대 콤보** 전체 가상화 패킹을 수행하고, 산출 EXE가 깨끗하게 실행되어 전체 예상 출력(1460B, 기준 SHA 동일)을
재현함을 확인했다. **드랍된 플래그 없음** — 확장 콤보가 그대로 통과.

## 사용 패킹 명령 (확장 최대 콤보)

```
target\release\btg-packer.exe -i repro\test_prog.exe -o <out>.exe -l 3 -a ^
  --vm --vm-oep --vm-commercial --integrity --chained-crypto ^
  --payload-relocate --rsrc-register --m7 --m8
```

- 빌드: `cargo build --release` exit 0 (증분 — `target/release/btg-packer.exe` 최신, 6,082,560 B)
- 코어 콤보(`--vm-oep --vm --vm-commercial --integrity --chained-crypto`)에 `-a`(anti-debug) +
  `--payload-relocate --rsrc-register` + `--m7 --m8`(on-demand 재암호화 / VM handler MBA)까지 전부 추가한 최대 구성.
- 풀백 불필요 — 확장 콤보가 즉시 통과 (core 콤보 대비 대체 없음).

## 산출물

| 항목 | 값 |
|---|---|
| 최종 EXE 경로 | `C:\Users\uzoki\Desktop\asdfsadfecwecc\scratch\maxvm_full_virtualization.exe` |
| 바이트 크기 | 1,323,008 B |
| SHA256 | `1b324b295352ce7738fffeb8afcdc6b256acafd941447177976181661675801b` |
| 동일 복사본 | `repro\extmax_v1.exe` (검증에 사용한 원본, 동일 바이트) |
| 패킹 콘솔 기록 | `repro\extmax_v1_pack_console.txt` (5,572,443 B) |
| 레이아웃 로그 | `repro\extmax_v1.btg_layout.log` |

## 실행 결과

`repro\extmax_v1_run.txt` (1460 B):

- exit code = **0** (크래시/ud2/AV 없음)
- 출력 바이트 = **1460**
- SHA256 = `4366e2530f32a088306efe497d1762e5a087c54ac6c114b44f3ee13d422dcfe5` = **기준과 일치**
- test[1]~test[16] 전부 PASS (test[14] `system interop & file I/O` = `0x755994c9aff12ef0`),
  FINAL CHECKSUM `0x2cdc0e4511d84a64`, Win32 GUI/Game Loop 초기화까지 정상 출력.

### 출력 샘플 (일부)

```
=========================================================================
   Rust Advanced Protection Test & Win32 Cyber Defender Game v3.0
=========================================================================
[1] arithmetic
    result = 0xf01d255a09780ddf
...
[14] system interop & file I/O
    result = 0x755994c9aff12ef0
...
-------------------------------------------------------------------------
FINAL CHECKSUM = 0x2cdc0e4511d84a64
-------------------------------------------------------------------------
[+] Launching Win32 GUI Window & Cyber Defender Engine...
[+] Win32 GUI Window & Game Loop initialized successfully.
```

## Integrity MAC 확인

패킹 콘솔 (`repro\extmax_v1_pack_console.txt`):

```
[+] T2-3 Integrity keyed-MAC over code region: F738BCE06BE36DFA (keyed)
[+] S1 Integrity keyed-MAC stored @0x73004 (8B, keyed=seed_stored; boot stub re-verifies -> ud2 on mismatch)
```

실행 exit 0이므로 부트 스텁의 저장값 재검증이 통과 (ud2 0xC000001D 발생 안 함) — 패커 MAC = 런타임 MAC 일치 확인.

## 배경/전제

- 작업 트리의 integrity 상수·레지스터 클로버·ASLR 수정(이전 2026-08-19 이슈)이 적용된 상태에서 진행.
- 상세 검증/원인 문서: `docs/analysis-vmoep-full-combo-verify-2026-08-19.md` (이전), 본 콤보 확장 결과는 `docs/analysis-program-vm-full-virtualization-max-combo-2026-08-19.md`.
- git 커밋은 만들지 않음.

## 남은 사항

- 없음 (확장 최대 콤보 정상 동작). 작업 트리에는 T3-1 ChaCha/SHA-256 의존성·T3-3 경고 하드닝 등 무관한 미커밋 변경이 별도 존재.
