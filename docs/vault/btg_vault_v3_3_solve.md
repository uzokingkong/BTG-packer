# BTG Vault v3.3 (hardened) — Solve Writeup

> 대상: `packed_vault_vm.exe` / `packed_vault_vmplain.exe` / `packed_vault_fullnoiathide.exe`
> (btg-packer 로 패킹된 Rust crackme, N=41)
> 최종 플래그: `BTG3{stateful_multi_vm_cross_region_2026}`

---

## 결론 (요약)

**패킹된 exe 만으로는 정확한 플래그 문자열을 "추출" 할 수 없다.** 이유는 설계상
플래그가 이진 파일 어디에도 평문/단일-XOR 로 저장되어 있지 않고, 검증이 **일방향
해시**이기 때문이다. `TARGETS:[u64;8]` 8개 값이 곧 "플래그의 해시"이고, 이것만이
배포물에 들어 있다.

플래그가 실제로 존재하는 곳은 **빌드 산출물**(`build.rs` 안의 `FLAG_XOR` 테이블과,
그것을 상수로 갖는 `build-script-build.exe`)뿐이다. 따라서

- **실제로 타인이 "푼" 방법 = 소스/빌드 산출물에서 `FLAG_XOR ^ 0xBA` 를 복원**했거나,
- 배포된 exe 만으로는 **"Access granted" 경로를 트리거하도록 패치**(크랙미의 관례적
  해법) 한 것.

아래에 두 경로를 모두 설명한다.

---

## 1. 검증 파이프라인 분석 (일방향 해시임을 확인)

`src/verifier.rs`의 `verify()`를 따라가면:

```
input (41바이트)
  → permute(i)            // 2차 순열 p=(n*13+9)%41; q=(p*p+7*p+11)%41
  → transform(b, &mut s)  // 이웃 혼합 + rotate + add + xor, 매 스텝 상태 s.mix()
  → 4개 region (q=10바이트씩):
        a  = region(b[0..10])
        bb = region(b[10..20]) ^ rotl(a,7)
        c  = region(b[20..30]) ^ rotr(bb,11)
        e  = region(b[30..40]) ^ a ^ c
  → native_bridge(a^bb^d) → opaque::gate → vm::execute(2회, bytecode는 입력에서 유도)
  → fake_vm(디코이) → second_bridge
  → vals = [8개 u64]  와  TARGETS[8] 비교
```

- 각 `region()`은 `rotate + *0x9e3779b97f4a7c15` 를 반복하는 **FNV류 일방향 해시**.
- 모든 단계가 단일 상태 `State`(epoch/checksum)를 누적하며 서로 얽혀 있음.
- VM 바이트코드 자체가 입력(플래그)에 의존 → 데이터 종속.
- 입력 41바이트(328bit) → 출력 8×64bit. **역산/전수조사 불가**:
  - `z3`: rotate/mul/wrapping_add + 수백 회 상태 혼합 + 데이터 종속 VM 디스패치를
    심볼릭으로 풀 수 없음.
  - 전수조사: `BTG3{` + `}` 를 제외한 35바이트 미지 → `256^35`, 불가능.

**즉 `TARGETS`에서 플래그를 복원하는 것은 불가능하다.**

---

## 2. 경로 A — `FLAG_XOR ^ 0xBA` 추출 (유일하게 "정확한 문자열"을 얻는 방법)

플래그는 `build.rs`에 이렇게 박혀 있다:

```rust
const FLAG_XOR:[u8;41]=[0xF8,0xEE,0xFD,0x89,0xC1,0xC9,0xCE,0xDB,0xCE,0xDF,
  0xDC,0xCF,0xD6,0xE5,0xD7,0xCF,0xD6,0xCE,0xD3,0xE5,0xCC,0xD7,0xE5,0xD9,
  0xC8,0xD5,0xC9,0xC9,0xE5,0xC8,0xDF,0xDD,0xD3,0xD5,0xD4,0xE5,0x88,0x8A,
  0x88,0x8C,0xC7];
const KEY:u8=0xBA;
// raw[i] = FLAG_XOR[i] ^ KEY  == 플래그 바이트
```

**바이트 위치:**
- `build-script-build.exe` 파일 오프셋 **`0x1D456`** 에 `FLAG_XOR` 테이블(41바이트)이 그대로 있다. (검증됨)
- 같은 값은 `target/release/build/btg_vault_v3-*/out/generated.rs`에는 **없다** —
  거기엔 `TARGETS` 8개만 있음.

**추출 스니펫 (Python):**

```python
KEY = 0xBA
FLAG_XOR = bytes([0xF8,0xEE,0xFD,0x89,0xC1,0xC9,0xCE,0xDB,0xCE,0xDF,
  0xDC,0xCF,0xD6,0xE5,0xD7,0xCF,0xD6,0xCE,0xD3,0xE5,0xCC,0xD7,0xE5,0xD9,
  0xC8,0xD5,0xC9,0xC9,0xE5,0xC8,0xDF,0xDD,0xD3,0xD5,0xD4,0xE5,0x88,0x8A,
  0x88,0x8C,0xC7])
flag = bytes(b ^ KEY for b in FLAG_XOR)
print(flag.decode())   # BTG3{stateful_multi_vm_cross_region_2026}
```

또는 바이너리에서 테이블을 찾아내는 자동 스크립트:

```python
import re
data = open("build-script-build.exe","rb").read()
loc = data.find(FLAG_XOR)          # -> 0x1D456
flag = bytes(b ^ KEY for b in data[loc:loc+41])
print(hex(loc), flag.decode())
```

실행 결과 (직접 확인):
```
[FLAG_XOR^0xBA] offset 0x1d456: BTG3{stateful_multi_vm_cross_region_2026}
```

> ⚠️ **이 테이블은 패킹된 exe(`packed_vault_*.exe`)에는 없다.** 전체 검색 결과
> 플래그/FLAG_XOR/`BTG3{`/`stateful` 은 패킹 exe 어디에도 존재하지 않으며, 배포된
> 원본 `btg_vault_v3.exe`/`f.exe`에도 없다. 이는 `FLAG_XOR`이 **build.rs(빌드 시점)** 에만
> 존재하기 때문.

---

## 3. 경로 C — "Access granted" 패치 (패킹 exe 만으로 가능한 실질적 해법)

패킹된 exe만 주어졌을 때, 정확한 플래그 문자열을 얻는 것은 불가능하므로, 크랙미의
"성공 판정"(`Access granted.` 출력)을 트리거하는 **패치**가 실질적 해법이다.

관찰된 사실:
- 판정 문자열은 `.rdata`에 **평문**으로 존재 (파일 오프셋 `0x17E00` 부근):
  - `Access denied.`  @ `0x17E0B`
  - `Access granted.` @ `0x17E19`
- 그러나 그 분기(판정)는 btg-packer의 **VM 가상화 + at-rest 재암호화 + 안티디버그**
  내부에 있으므로 단순 1~2바이트 NOP 패치는 하지 않고, 동적 디버깅으로 `verify()`의
  반환값을 강제로 참(1)로 만들어 그린트 문자열로 흐르게 한다. (즉 **런타임 패치**)

`solve_vault.py`는 배포물에 플래그가 없음을 확인하고, 실질 해법(패치 방향)을 안내한다.

---

## 4. 배포물에 대한 실제 결과 (검증)

`python solve_vault.py` 실행 결과:

```
FILE: packed_vault_vm.exe
  FLAG_XOR table (KEY=0xBA): NOT present
  RESULT: flag NOT recoverable from this file

FILE: build-script-build.exe
  [FLAG_XOR^0xBA] offset 0x1d456: BTG3{stateful_multi_vm_cross_region_2026}
  RESULT: flag recovered.

Expected flag: BTG3{stateful_multi_vm_cross_region_2026}
```

런타임 확인(패킹 exe, 정답 입력 시):
```
Enter key: BTG3{stateful_multi_vm_cross_region_2026}  -> Access granted.
Enter key: BTG3{WRONG...}                             -> Access denied.
```

---

## 정리

| 방법 | 패킹 exe 만으로? | 결과 |
|---|---|---|
| `TARGETS` 해시 역산 (z3/전수조사) | 불가능 | 일방향 해시, 328bit 엔트로피 |
| `FLAG_XOR` 추출 | **패킹 exe에 없음** (빌드 산출물에만) | 빌드 산출물에서 가능 |
| "Access granted" 패치 | 가능 (런타임/디버거) | 정확한 문자열은 아님 |

**따라서: "패킹 exe 만으로 정확한 플래그 문자열을 얻는" 것은 구조적으로 불가능하며,
실제 해법은 (1) 빌드 산출물(`build.rs`/`build-script-build.exe` @`0x1D456`)에서
`FLAG_XOR^0xBA`로 복원하거나, (2) 판정을 패치하는 것이다.**
