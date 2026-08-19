# 2026-08-19 — chained-crypto + integrity 결합 실패 수정/검증 완료

## 요약

`btg-packer`의 `--chained-crypto` + `--integrity` 결합이 정상 실행되지 않던 두 실패를 수정하고 전 조합 검증을 통과시켰다.

- `--integrity --chained-crypto` → 0xC0000409, 0B 출력
- 풀 콤보 `--vm-oep --vm --vm-commercial --integrity --chained-crypto` → exit 101, 문자열 손상 출력 + test[14] panic

## 원인 (확정)

부트 스텁 실행 순서 (`src/pipeline/crypto/bootstub/build.rs`): `payload_copy → code_decrypt(chained) → emit_integrity_mac → emit_integrity_crc → run_decrypt(문자열 런)`. `emit_code_decrypt`가 남기는 RC4 PRGA i/j 상태가 ESI/EDI에 있고 `emit_run_decrypt`가 그 스트림을 이어받아 문자열 런을 복호화한다. `--integrity`가 켜진 경우 사이에 끼는 `emit_integrity_mac`가 RSI(시드/코드 포인터)·RDI(h1)를 덮어써 ESI/EDI(PRGA 상태)가 깨졌다 → 문자열 런이 쓰레기로 복호화 → 손상 출력 + test[14] panic.

## 수정

- `src/pipeline/crypto/integrity.rs`: ① MAC Phase A 상수 `0x1000_0000_01B3`(45-bit) → `0x100_0000_01B3`(41-bit, 패커 일치) ② `rol(h0,i&63)`를 CL로 먼저 계산하고 `b*PHI`를 RDX에 보존(레지스터 클로버 교정) ③ MAC 입구 `push rsi;push rdi`, MacOk 성공 경로 `pop rdi;pop rsi`로 PRGA 상태 보존.
- `src/pipeline/build.rs`: `let reloc_aware = !ctx.at_rest_encrypted;` — at-rest 암호화(보호) 경로는 ASLR off(부트 스텁 안전), `--no-crypto` 경로는 ASLR 보존.

## 검증 (test_prog.exe, 기준 SHA256=4366e253…, 출력 1460B)

| 명령 | exit | SHA=기준 |
|---|---|---|
| `-l 3` | 0 | ✓ |
| `--integrity -l 3` | 0 | ✓ |
| `--integrity --custom-cipher -l 3` | 0 | ✓ |
| `--vm-oep --vm --vm-commercial --integrity -l 3` | 0 | ✓ |
| `--chained-crypto -l 3` | 0 | ✓ |
| `--integrity --chained-crypto -l 3` | 0 | ✓ |
| 풀 콤보 `--vm-oep --vm --vm-commercial --integrity --chained-crypto -l 3` | 0 | ✓ |

- 반복 검증: 풀 콤보/`--integrity --chained-crypto` 신선 시드 재패킹+재실행 5회 모두 기준 SHA 동일.
- `--no-crypto --anti-debug`: DLL_CHAR=0x8160(ASLR/HEVA 보존), .reloc 존재, 실행 exit 0.
- 보호 출력: DLL_CHAR=0x8100(ASLR off).
- `cargo test --release` 전체 통과 (exit 0), `qa::tests::no_crypto_pack_preserves_aslr_and_reloc` ok.

## 남은 사항
- 없음. (작업 트리에 T3-1 ChaCha/SHA-256 의존성·T3-3 경고-하드닝 등 무관한 미커밋 변경 별도 존재 — 본 이슈와 무관.)
