# btg_vault v3.3 (hardened) — VM 패킹 후 풀이 가능성 검토

> 작성: 2026-08-17 · 검토 대상: `C:\Users\uzoki\Downloads\btg_vault_v3_3_hardened_final\btg_vault_v3_3_hardened\src`
> 배경: 챌린지 풀이자가 "안 풀린다"고 불만 호출 중. 검증 로직 버그인지, VM 패킹 문제인지 규명.

## 결론 요약
- **검증 로직은 정상.** 의도된 플래그는 미패킹 바이너리와 패커가 실제로 생성할 수 있는 모든 VM 패킹 구성에서 **정상적으로 통과**된다. 챌린지는 원리적으로 풀 수 있다.
- **유일한 실블로커는 패커 자체의 한계**: 최고 보호 스택 `--full`(= `--iat-hide` 포함)이 이 바이너리를 패킹하지 못한다. 원인은 Rust/std 바이너리의 **TLS 콜백**과 `--iat-hide`의 비호환성. 만약 의도된 문제물이 `--full` 빌드였다면, 그 때문에 문제물 자체가 생성 불가/사용 불가 상태다. → 검증 로직 버그가 아니라 **패커 기능(능력) 문제**.

## 의도된 플래그
```
BTG3{stateful_multi_vm_cross_region_2026}   (41자)
```
- `build.rs`에서 `raw[i] = FLAG_XOR[i] ^ KEY(0xBA)` 로 복원, PowerShell 디코드 및 실제 바이너리 실행으로 독립 확정.

## 1. 검증 로직 (Rust crackme — 기존 C++ `*_check.h` 구조 아님)
- `N = 41` (`const N: usize = 41`).
- `build.rs` : `FLAG_XOR[41] ^ 0xBA` → 의도 플래그 복원 → 전체 파이프라인을 수행해 `generated.rs`의 `TARGETS: [u64; 8]`(8개 타깃 해시)를 생성. 빌드타임 코드와 런타임 검증기는 바이트 단위로 동일한 함수 사용.
- `verifier.rs::verify` :
  - 길이 + `BTG3{`/`}` 가드 → `decoy`(State feed) → `transform(permute(raw))`
  - `permute` : 이차 순열 `p=(n*13+9)%41; q=(p*p+7*p+11)%41; o[n]=i[q]`
  - `transform` : 인접 바이트 혼합, `rotate_left(i&7)`, `wrapping_add`, `x ^= (i as u8)*0x3d ^ 0xa7`, `rotate_left((i*5+1)&7)`
  - → 4개 영역 분할 → `region()` (FNV 계열: rotate + `*0x9e3779b97f4a7c15`) → `native_bridge` → `opaque::gate`(술어 항상 참 → gate ≡ `rotate_left(11) ^ 0xa55a5aa51337c0de`) → VM 2회 실행 `vm::execute`(8핸들러 디스패치, 예산 192/224) → `fake_vm` 디코이 → `second_bridge` → 8개 `vals`를 `TARGETS`(전부)와 비교 + 항상 참인 불투명 `decoy_condition`.
- 참고: 이 프로젝트는 Rust crackme이므로 과거 chve(chve2)의 C++ `*_check.h` 설계와 다름.

## 2. 검증 버그로 인해 의도 플래그가 거부되는가? → 아니다
- 빌드/런타임 불일치 없음(과거 chve `17i vs 19i`류 버그 없음). `build.rs`와 `verifier.rs`/`vm.rs`/`bridge.rs`/`state.rs`/`opaque.rs`가 동일한 수식 사용(라인 단위 확인).
- 실증: `target\release\f.exe` 직접 실행
  - `BTG3{stateful_multi_vm_cross_region_2026}` → `Enter key: Access granted.`
  - 오답 → `Access denied.`
- 발견된 유일한 미묘한 불일치: `build.rs`는 종료 op7 반복에서 `s.transitions`를 갱신하나 런타임 `vm::execute`는 먼저 break. 이는 branch-index/`decoy_condition`에만 영향, 비교되는 8개 `vals`에는 무관. `decoy_condition`은 항상 참 불투명 술어라 판정을 뒤집을 수 없음 → 무해 확인.

## 3. VM 패킹이 새로운 실패를 유발하는가?
`C:\Users\uzoki\Desktop\btg-packer.exe`로 `f.exe`를 4가지 구성으로 패킹, 의도 플래그로 실행:
| 구성 | 결과 |
|---|---|
| `--vm --vm-oep` (전체 프로그램 가상화) | 패킹 OK, `Access granted.` (오답은 `Access denied.` → 항상 허용 버그 아님) |
| `--vm` (KSA/PRGA VM) | 패킹 OK, `Access granted.` |
| `-l3 -a --dispatcher-reencrypt --integrity --payload-relocate --rsrc-register --mem-harden` (iat-hide 제외 full) | 패킹 OK, `Access granted.` |
| `--full` (= 위 + `--iat-hide`) | **패킹 실패**, exit 1 |

- `--full` 실패 메시지: `Error: Anyhow(--iat-hide cannot be used on a PE with TLS callbacks: callbacks run before the boot stub, and disabling them corrupts Rust/CRT teardown)` → 출력 exe 생성 안 됨.
- VM은 64비트 wrapping-mul/rotate/xor 검증을 정확히 수행(import bridge, 스택 정렬, 디스패처 모두 이 바이너리에 대해 정상). 과거 보고된 패커 크래시(RSP 정렬, SEH/pdata, TLS 템플릿 손상)는 패킹에 성공한 구성에서는 이 바이너리를 깨뜨리지 않음.

## 4. "안 풀린다"는 불만에 대한 답
- 검증은 정상이고, 패커가 출력 가능한 모든 보호 레벨에서 플래그가 통과된다.
- 진짜 문제는 **패커 자체**: 최고 보호 스택 `--full`이 TLS 콜백(Rust std) 때문에 `--iat-hide`와 비호환하여 이 챌린지를 생성하지 못함. 의도가 `--full` 빌드였다면 그 이유로 문제물이 사용 불가. → **패커 기능 문제이지, 검증 로직 버그가 아님.**

## 검증 산출물 (노드에 남김)
- `C:\Users\uzoki\Desktop\asdfsadfecwecc\packed_vault_vm.exe`, `packed_vault_vmplain.exe`, `packed_vault_fullnoiathide.exe`
- `pack_vault_vm.log`, `pack_vault_vmplain.log`, `pack_vault_fullnoiathide.log`, `pack_vault_full.log`
