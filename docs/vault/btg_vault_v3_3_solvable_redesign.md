# btg_vault v3.3 — "solvable" 리디자인 (패킹 exe 만으로 플래그 복구 가능)

> 작성: 2026-08-17 · 대상: `btg_vault_v3` v3.3 (Rust crackme, N=41)
> 플래그: `BTG3{stateful_multi_vm_cross_region_2026}` (41자)
> 패커: `btg-packer` (`-l 3 -a --vm --vm-oep`)
> 핵심 결과: **패킹된 exe 단독으로** `solve_vault_recoverable.py`가 정확한 플래그를 복구한다.

---

## 1. 기존 설계의 문제 (왜 풀 수 없었나)

기존 검증은 **일방향 해시**였다.

```
input(41B) → permute → transform(stateful) → 4×region(FNV류) → native_bridge
           → opaque::gate → vm::execute ×2 → fake_vm → second_bridge
           → vals[8]  vs  TARGETS[8]  (컴파일 타임 상수)
```

- `TARGETS[8]`는 플래그의 **해시**일 뿐이라, 역산(z3/전수조사)이 불가능.
- 플래그 평문/암호문은 빌드 산출물(`build.rs`의 `FLAG_XOR^0xBA`, `build-script-build.exe @0x1D456`)에만 존재.
- 따라서 **배포/패킹 exe 만으로는 정확한 문자열을 얻을 수 없었고**, 실질 해법은
  "Access granted." 경로를 런타임 패치하는 것뿐이었다.

## 2. 리디자인: 가역(역변환 가능) 스트림 암호 비교

검증을 **가역적·상태유지(CFB류) 스트림 변환의 바이트별 비교**로 바꿨다.

배포 이진에 들어가는 상수는 더 이상 해시가 아니라 **플래그의 암호문 `CIPHER[41]`**
(static 배열, `.rdata`)이다. 검증은 입력을 같은 변환으로 암호화해 `CIPHER`와 바이트별로
비교한다. 모든 연산(xor, mod-256 덧셈, 회전)이 **전단사(bijective)**라서 변환 전체가
가역이다.

### 변환 (verifier.rs / build.rs 공통)

```
키스트림:  st = (st*KS_MUL + KS_ADD + fb) & 0xFFFF_FFFF_FFFF_FFFF
           k  = (st>>24 ^ st>>8 ^ st) & 0xFF        // fb = 이전 암호문 바이트(CFB 체이닝)
암호화:    c_i = rol8( (p_i ^ k_i) + ADD[i&7], ROT[i&7] )
복호화:    p_i = ( ror8(c_i, ROT[i&7]) - ADD[i&7] ) ^ k_i
```

| 상수 | 값 |
|---|---|
| `KS0`   | `0x243F6A8885A308D3` |
| `KS_MUL`| `0x5851F42D4C957F2D` |
| `KS_ADD`| `0x14057B7EF767814F` |
| `ADD[8]`| `2B 37 5D 11 83 45 99 77` |
| `ROT[8]`| `3 5 7 1 4 6 2 0` |
| `IV`    | `0xA7` (초기 fb) |

- `KS0/KS_MUL/KS_ADD/ADD/ROT/IV`는 **코드 상수**로, 패킹 시 `--vm-oep`에 의해
  OEP(입력→verify)의 코드와 함께 VM 바이트코드로 lift되어 들어간다.
- `CIPHER`는 static 배열이므로 `.rdata`에 연속 바이트로 존재한다(데이터는 암호화 대상이
  아님 — 아래 §5 오프셋 참조).

### 검증 로직 (src/verifier.rs, 간략화)

```rust
pub fn verify(input: &[u8]) -> bool {
    if input.len() != N || !input.starts_with(b"BTG3{") || input[N-1] != b'}' { return false; }
    let mut st = KS0; let mut fb: u8 = IV;
    for i in 0..N {
        let k = ks_step(&mut st, fb);
        let c = fwd(input[i], k, i);          // rol8((p^k)+ADD[i&7], ROT[i&7])
        if c != CIPHER[i] { return false; }   // 바이트별 비교 (per-character oracle)
        fb = c;
    }
    true
}
```

- **정답 입력** → `c == CIPHER` 전부 일치 → `true` → "Access granted."
- **오답 입력** → 어느 한 바이트에서 즉시 거짓 → "Access denied."
- `build.rs`만 플래그를 알고 있으며, 그 플래그로 `CIPHER`를 계산해 `generated.rs`로
  내보낸다(`pub static CIPHER`). 소스/이진에는 플래그 평문이 없다.

## 3. 왜 이제 가역/복구 가능한가

1. `CIPHER`(암호문)가 배포 이진 `.rdata`에 들어 있다 → exe에서 찾을 수 있다.
2. 변환(키스트림 LCG + ADD/ROT + 체이닝)이 **전단사**라서 정확히 역연산이 존재한다.
3. 변환 상수는 패킹된 코드(VM 영역)에 있지만, 패커를 깨고(언팩/VM 해석) 추출하면
   복호화가 가능하다 → **"패커를 이기는 것 = 플래그를 얻는 것"**이라는 요구 유지.
4. 단일 상수 XOR이나 평문 스트링은 아니다: 키스트림이 바이트마다 달라지고 직전
   암호문에 체이닝되므로, dumb `strings`/단일-XOR 스캔으로는 절대 안 나온다(§6 검증).

## 4. 솔버 방법 (solve_vault_recoverable.py)

1. exe 전체를 읽는다.
2. **모든 41바이트 윈도우**에 대해 위 복호화(`p_i = (ror8(c,ROT)-ADD)^k_i`,
   같은 키스트림)를 적용한다.
3. 결과가 `BTG3{`로 시작하고 41바이트째가 `}`, 내부가 전부 printable(0x20..0x7E)인
   **유일한** 윈도우를 `CIPHER`로 판정한다 (우연 일치 확률은 사실상 0).
4. 그 윈도우의 복호화 결과를 플래그로 출력한다.

솔버는 **입력으로 exe 하나만** 받는다(빌드 산출물/소스/플래그 미사용). 암호문은
파일에서 읽고, 변환 상수는 리버싱으로 얻은 알고리즘(코드 상수)으로서 스크립트에
정의되어 있다.

## 5. 실제 복구 결과와 바이너리 내 위치

### 패킹 구성

```
btg-packer.exe -i vault3_solvable_unpacked.exe -o packed_vault3_solvable_vmoep.exe \
               -l 3 -a --vm --vm-oep
```

- `--vm` : 부트 스텁 RC4 KSA를 VM으로 (복합 VM 암호화 활성)
- `--vm-oep` : 원본 OEP(입력→verify)를 **VM 프로그램으로 lift** — 로그의 블록 lift
  목록(`Block ... test al,al / jne ... jmp 0x140020020` = VM 디스패처)이 이를 확인.
- `-a -l 3` : 안티디버깅 + MBA 난독화.

### 파일/오프셋 (패킹 exe `packed_vault3_solvable_vmoep.exe`, 470,528B)

| 항목 | 값 |
|---|---|
| 암호문 `CIPHER` 파일 오프셋 | **`0x14FB0`** |
| 암호문 `CIPHER` RVA | **`0x163B0`** (섹션 `.rdata`) |
| `CIPHER` 41바이트 | `c8ae2ff851ce6c21395683fea1911974729a50bcd08627f046fb4d4ce1e9dc8e41ed5939363aa67725` |
| 패킹 코드 영역 | `.textb` @ `0x20000` (파일 `0x1C800`.., 원본 .text의 VM/lift) |

> `CIPHER`가 `.rdata`에 **언팩/팩 동일 바이트**로 남는 이유: 패커의 복합 VM 암호화는
> 코드(.text/.textb)와 일부 문자열을 대상으로 하고, 이 static 배열은 데이터로 남는다.
> (그래서 "배포물에 암호문이 있고, 그 암호문을 복호화하려면 VM 영역의 변환을 알아야
> 한다"는 구조가 성립.)

### 솔버 실행 결과 (패킹 exe, exe 단독)

```
$ python solve_vault_recoverable.py packed_vault3_solvable_vmoep.exe
FILE       : packed_vault3_solvable_vmoep.exe
CIPHER @   : 0x14fb0  (85936 bytes into file)
FLAG       : BTG3{stateful_multi_vm_cross_region_2026}

RECOVERED FLAG: BTG3{stateful_multi_vm_cross_region_2026}
```

→ **패킹 exe 만으로 정확한 플래그 복구 성공.**

## 6. "trivial 추출 불가" 검증 (dumb 스캔은 실패)

`solve_vault.py`(기존: 평문/`FLAG_XOR` 테이블/단일-XOR 스캔)를 패킹 exe에 돌리면:

```
FILE: packed_vault3_solvable_vmoep.exe   size: 470528
  FLAG_XOR table (KEY=0xBA): NOT present
  RESULT: flag NOT recoverable ... (no plaintext, no single-XOR)
```

- 평문 `BTG3{...}` 없음, `FLAG_XOR^0xBA` 테이블 없음, 단일 바이트 XOR로도 안 나옴.
- 즉 복구 경로는 오직 가역 변환(리버싱)을 통해서만 가능 → 요구사항 2 충족.

## 7. 런타임 동작 확인 (요구사항 3)

```
$ echo BTG3{stateful_multi_vm_cross_region_2026} | packed_vault3_solvable_vmoep.exe
Enter key: Access granted.
$ echo BTG3{WRONG} | packed_vault3_solvable_vmoep.exe
Enter key: Access denied.
```

## 8. 산출물 경로

| 산출물 | 경로 |
|---|---|
| 리디자인 소스 | `C:\Users\uzoki\Downloads\btg_vault_v3_3_hardened_final\btg_vault_v3_3_hardened\` (`build.rs`, `src\verifier.rs`, `src\main.rs`) |
| 언팩 빌드 | `...\target\release\btg_vault_v3.exe` · 사본 `C:\Users\uzoki\Desktop\asdfsadfecwecc\vault3_solvable_unpacked.exe` |
| **패킹 exe** | `C:\Users\uzoki\Desktop\asdfsadfecwecc\packed_vault3_solvable_vmoep.exe` |
| **솔버** | `C:\Users\uzoki\Desktop\asdfsadfecwecc\solve_vault_recoverable.py` |
| 패킹 로그 | `C:\Users\uzoki\Desktop\asdfsadfecwecc\pack_v3_solvable_vmoep.log` |
| 본 문서 | `C:\Users\uzoki\Desktop\asdfsadfecwecc\docs\btg_vault_v3_3_solvable_redesign.md` |
| 원본 백업 | `C:\Users\uzoki\Downloads\btg_vault_v3_3_hardened_final\btg_vault_v3_3_hardened_orig_backup\` |

## 9. 요약

| 항목 | 결과 |
|---|---|
| exe 단독 복구 가능? | **가능** (가역 스트림 암호, `CIPHER`+변환이 exe에 존재) |
| dumb 스캔으로 추출? | **불가** (키스트림 체이닝, 평문 없음) |
| 정답 인가/오답 거부 | 확인됨 |
| 패커 VM/MBA/안티디버그가 난이도 | 유지 (`--vm --vm-oep`로 verify가 VM 안에 있음) |
| 복구 플래그 | `BTG3{stateful_multi_vm_cross_region_2026}` |
