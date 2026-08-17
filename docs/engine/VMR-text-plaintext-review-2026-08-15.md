# VMR(Virtual Machine Protection) 적용 검토 보고서 — .text 평문 여부 실측

> 대상: `asdfsadfecwecc` (BTG Packer, node `ujiwo-zyris-code`)
> 검토일: 2026-08-15
> 타깃: `test\target\release\rust_packer_test.exe` (261,632 bytes, Win32 GUI/Rust test harness)
> 패킹 명령: `btg-packer.exe -i test\target\release\rust_packer_test.exe -o packed_vmoep.exe --vm --vm-oep --map --sym-map`

---

## 1. 결론 요약

| 항목 | 결과 |
|---|---|
| **VMR(VM 가상화) 적용 여부** | ✅ **적용됨** — Program VM이 OEP를 dispatch (`entry_native=false`), VM 바이트코드 312,035B가 **at-rest RC4 암호화**됨 |
| **.text 평문 여부** | ⚠️ **평문으로 유지됨** — 원본과 byte-identical (아직 완전한 .text 은닉은 아님) |
| **실행 검증** | ✅ 16개 테스트 전체 통과, FINAL CHECKSUM = baseline 동일 (`0x2cdc0e4511d84a64`), GUI 정상 기동 |

즉, **VMR 가상화는 실제로 동작하고 프로그램 본문의 실행 경로는 VM 바이트코드로 이동했지만, `.text` 섹션은 TLS 콜백 존재로 인해 현재 "평문 안전 복사본"으로 온전히 남아 있다.** `.text`까지 전부 평문이 안 보이게 하는 완전한 상태는 아니다.

---

## 2. 실측 증거

### 2.1 패킹 로그 핵심 (pack_vmoep.log)
```
[+] --vm-oep: OEP virtualized (entry_native=false) -- Program VM now dispatches the program
[VM-OEP-DIAG] EP             = 0x14002C080
[VM-OEP-DIAG] entry_native   = false
[VM-OEP-DIAG] bytecode       = 312035 bytes
[+] --vm-oep at-rest: Program VM bytecode encrypted (312035B)
[!] --vm-oep at-rest: preserved .text kept plaintext (TLS callbacks present; TLS-first-callback decryptor = Phase-2)
[+] M6 Phase-2 Program VM: module @0x479F0 ... bytecode 312035B ... entry_va=0x14008B9F0
[+] Rebuilt SEH Table (.pdata): RVA 0x40000, 749 entries
[SUCCESS] Synthesized Protected BTG PE Binary Written to: packed_vmoep.exe
[INFO] Protected Entry Point (OEP) RVA: 0x83A00
```

핵심 라인: **`preserved .text kept plaintext (TLS callbacks present; TLS-first-callback decryptor = Phase-2)`** — 패커가 직접 `.text`를 평문으로 유지하고 있음을 명시한다. 이유는 이 타깃이 TLS 콜백을 가지며, TLS 콜백은 부트 스텁보다 먼저 실행되므로 암호화하면 크래시가 나기 때문 (문제.txt §3의 알려진 제약).

### 2.2 PE 섹션 바이트 비교 (verify_text.py 실측)

| 섹션 | 원본 size | 패킹 size | 비고 |
|---|---|---|---|
| .text | 186,880 | 186,880 | **byte-identical** (entropy 6.409) |
| .rdata | 62,976 | 62,976 | 5.488 |
| .data | 512 | 512 | 1.969 |
| .pdata | 9,216 | 9,216 | 5.399 |
| .reloc | 1,024 | 1,024 | 4.975 |
| **.textb** | — | **630,272** | **신규 추가**, entropy **7.551** (셔플 + RC4 암호화된 실행 블록) |

`.text` 첫 186,880바이트가 원본과 완전히 동일(`first 186880 bytes identical: True`). 실행 코드는 `.textb`(6973개 Trigger Block, 셔플+암호화)로 옮겨졌고, `.textb` entropy 7.551은 거의 무작위 수준으로 암호화됨을 시사.

### 2.3 실행 검증
```
[1] arithmetic ... [16] CyberDefender game engine simulation
FINAL CHECKSUM = 0x2cdc0e4511d84a64
[+] Launching Win32 GUI Window & Cyber Defender Engine...
[+] Win32 GUI Window & Game Loop initialized successfully.
RUN_EXIT=0
```
패킹 산출물이 **실행 즉시 크래시하지 않고** 전체 16개 테스트 통과. 문제.txt에 기록된 이전 부트 크래시(GetModuleHandleA / RSP 정렬 / .rdata 함수포인터 재배치)는 2026-08-14 수정으로 해소된 상태임을 재확인.

---

## 3. VMR 가상화의 현재 커버리지 (문서와 코드 기준)

- **Program VM (OEP 가상화)**: OEP→VM 진입 고정, `entry_native=false`. VM 바이트코드 312,035B가 at-rest RC4 암호화. (docs/roadmap/milestones.md §2.4, docs/architecture/vm-compiler-architecture.md §5)
- **.textb 셔플**: 6,973/12,170 블록이 셔플+암호화되어 `.textb`로 이동. (pack_vmoep.log)
- **SEH 네이티브 유지**: panic/catch unwind 경로 함수 175개(0x127B0 bytes)는 원본 `.text`에 네이티브로 유지 (SEH unwind가 .pdata 커버리지를 요구하므로). 이들도 평문으로 남는다.
- **VM→네이티브 브리지**: 제외(SEH) 블록과 CRT/런타임 경로는 native-call 브리지로 실행. 이 브리지가 원본 `.text`의 네이티브 함수를 호출하므로, 실행 도중에는 원본 `.text` 코드가 실제로 실행된다.

---

## 4. `.text`가 평문으로 남는 근본 원인

1. **TLS 콜백 (구조적)**: 로더가 부트 스텁보다 먼저 TLS 콜백을 실행. `.text`를 암호화하면 콜백이 암호문을 실행 → 0xC0000005. 패커 로그가 명시적으로 `TLS-first-callback decryptor = Phase-2`로 유보. (문제.txt §3, 2026-08-13 수정)
2. **SEH 네이티브 보존**: panic/catch unwind 함수는 셔플 밖으로 제외되어 원본 `.text`(평문)에 유지. unwinder가 원본 .pdata/UNWIND_INFO로 프레임을 걸어야 하므로 이 함수들은 평문으로 남는 것이 설계상 필요.
3. **VM native-call 브리지**: VM이 제외 함수 / CRT를 호출할 때 원본 `.text` 주소를 사용.

따라서 "전체 프로그램이 VM 바이트코드만으로 실행되고 `.text`가 평문으로 존재하지 않는다"는 **완전한 VMR 목표는 아직 미달**이다. 현재는 "프로그램 본문의 주요 실행 경로가 VM으로 dispatch + `.textb` 블록 암호화 + Program VM 바이트코드 at-rest 암호화"까지는 달성, `.text`(원본 코드 + TLS/SEH)는 평문 보존.

---

## 5. 완전한 `.text` 은닉을 위한 필요 작업 (다음 단계)

1. **TLS-first-callback decryptor (Phase-2)**: TLS 콜백이 먼저 실행되는 문제를 해소해 `.text`를 at-rest 암호화하고 부트 시 복호화. 패커 로그가 이미 이 항목을 명시적으로 유보.
2. **SEH 네이티브 최소화**: panic/catch unwind 함수도 VM화 또는 자체 복호화 경로로 처리해 평문 유지 함수를 0으로. 현재 175함수/0x127B0바이트가 평문.
3. **.pdata/UNWIND_INFO 재작성**: 셔플 블록(.textb)이 .pdata 커버리지를 받도록 해 VM 내부 코드의 unwind를 지원 (문제.txt [10] 항목 — 근본적으로 블록셔플 × x64 SEH 충돌).
4. 이 모든 작업은 "전체 .text 가상화 + 부트 정합"의 구조 문제로 문제.txt에 Critical로 추적 중.

---

## 6. 판단

- **VMR 가상화는 "적용되어 있고, 실제로 실행 경로를 VM으로 dispatch"한다.** 이건 실측으로 확인됨.
- **그러나 `.text` 섹션은 평문으로 남아 있다.** 사용자가 원하는 ".text까지 전부 평문이 안 보이게"는 현재 구현에서 **미달 상태**이며, 이는 (a) TLS 콜백 부트 제약, (b) SEH 네이티브 보존, (c) VM native-call 브리지가 원본 주소를 사용하는 구조적 이유 때문이다.
- 프로그램 코드의 상당 부분(.textb 블록 6,973개)과 Program VM 바이트코드(312KB)는 at-rest 암호화되어 있어 **온디스크 정적 분석을 크게 어렵게 만든다.** 다만 원본 `.text`가 통째로 평문 보존되어 있으므로, 정적 리버서는 `.text`를 직접 디스어셈블하면 원본 로직을 얻을 수 있다.

> ⚠️ 참고: `.map`/`.sym` 산출물은 `packed_vmoep.exe.map`(2.4MB) / `packed_vmoep.exe.sym`(2.6MB)로 생성됨. 이 파일들은 VM 바이트코드 오프셋 ↔ 원본 VA 매핑을 담고 있어, 디버깅/추적에 유용하지만 역시 평문 로직 복원에 도움을 줄 수 있음 (배포 시 제외 권장).
