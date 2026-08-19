# BTG Packer — ① 프로그램 VM 전체 가상화 Max 콤보 실행/검증 기록 (2026-08-19)

> 대상: `repro/test_prog.exe` (436,224 B) · 기준 출력 1460 B · 기준 SHA256
> `4366e2530f32a088306efe497d1762e5a087c54ac6c114b44f3ee13d422dcfe5`
> 빌드: `cargo build --release` → `target/release/btg-packer.exe` (exit 0, 증분 0.22s)

## 확장 최대 콤보 (성공)

```
target\release\btg-packer.exe -i repro\test_prog.exe -o scratch\maxvm_full_virtualization.exe \
  -l 3 -a --vm --vm-oep --vm-commercial --integrity --chained-crypto \
  --payload-relocate --rsrc-register --m7 --m8
```

이전에 검증된 코어 콤보 `--vm-oep --vm --vm-commercial --integrity --chained-crypto -l 3` 위에
`-a`(anti-debug), `--payload-relocate --rsrc-register`(코드 영역 .vdata 이동 + RT_RCDATA 등록),
`--m7`(on-demand 재암호화), `--m8`(VM handler MBA)을 전부 더한 **프로그램 VM 전체 가상화 최대 구성**.

## 결과 요약

| 항목 | 값 |
|---|---|
| 패킹 exit | 0 |
| 최종 EXE | `scratch\maxvm_full_virtualization.exe` = 1,323,008 B |
| EXE SHA256 | `1b324b295352ce7738fffeb8afcdc6b256acafd941447177976181661675801b` |
| 실행 exit | 0 |
| 출력 바이트 | 1460 |
| 출력 SHA256 | `4366e2530f32a088306efe497d1762e5a087c54ac6c114b44f3ee13d422dcfe5` = **기준 일치** |
| 드랍 플래그 | **없음** |
| 로그 | `repro/extmax_v1_pack_console.txt`, `repro/extmax_v1.btg_layout.log`, `repro/extmax_v1_run.txt` |

## Integrity MAC 값 (패킹 콘솔)

```
[+] T2-3 Integrity keyed-MAC over code region: F738BCE06BE36DFA (keyed)
[+] S1 Integrity keyed-MAC stored @0x73004 (8B, keyed=seed_stored; boot stub re-verifies -> ud2 on mismatch)
```

실행 시 부트 스텁이 저장값을 재계산·비교하는데 exit 0 → 런타임 MAC = 패커 저장 MAC 일치 (ud2 없음).

## 출력 전체 (test[1]~test[16] + 종합)

test[1..16] 전부 PASS, `FINAL CHECKSUM = 0x2cdc0e4511d84a64`,
`[+] Launching Win32 GUI Window & Cyber Defender Engine...` / `[+] Win32 GUI Window & Game Loop initialized successfully.`
까지 1460 B 전체 예상 출력 재현. test[14] `system interop & file I/O = 0x755994c9aff12ef0` (기존 panic 항목 포함 통과).

## 결론

프로그램 VM 전체 가상화(extended max combo)가 **단일 실패 없이** 정상 실행되어 기준 출력과 완전히 일치.
코어 콤보로의 폴백은 필요하지 않았다. git 커밋은 수행하지 않음.
