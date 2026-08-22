# BTG-Packer (vm-obf) 감사 — ChatGPT 진단 6개 약점 + 아키텍처 매핑 + 추가 발굴

> 작성: 2026-08-21 · 감사 대상: `C:\Users\uzoki\Desktop\asdfsadfecwecc` (btg-packer, Rust)
> 방법: 소스 실제 열람 + `file:line` 근거 인용. 모든 판정은 "대략"이 아니라 읽은 코드 기준.
> 이 문서는 README/로드맵의 광고 문구가 아니라 **실제 코드**를 기준으로 한 냉정 기술이다.

---

## 0. 개요

btg-packer는 입력 PE를 파싱해 블록 셔플→재인코딩→암호화→부트 스텁 설치→PE 합성하는
패커다. "상용 등급 VM"(risc→poly→threaded) 엔진과 레거시 1:1 VM, RC4/ChaCha20/C1 암호화,
안티디버그, integrity(MAC)가 얽혀 있다. 감사 결과를 한 문장으로 요약하면:

- **ChatGPT가 지적한 6개 약점 중 4개(P1)는 레거시 1:1 VM 부트 스텁 경로에서 그대로 재현**된다.
- **상용(`--vm-oep --vm-commercial`) 엔진의 self-decoding 디스패처는 이 중 여러 개를 실질적으로 해소**했지만,
  **운영 단계(차등 검증 계약)가 "선형 블록 단위 동치"로 한정**되어 제어흐름 전체가 계약 밖이다.
- **`poly_embed.rs`(SDK 마커 `.btgvm` 선택적 VM) 경로는 "데이터 임베드만 되고 런타임 해석기는 'wired next'"**라는
  주석이 그대로 남아 있고, **런타임 롤링 키가 `seed as u8`(1바이트)**라 사실상 실행 불능/상징적 구현이다.
- **TLS 콜백/CRT 때문에 보존 원본 `.text`가 평문으로 남는 경로가 여전히 지배적**이다 (전체 가상화 미달성).

---

## 1. 현재 아키텍처 매핑 (실행 파이프라인 · 파일:라인 근거)

### 1.1 파이프라인 오케스트레이션 — `src/main.rs`

`main`이 `PipelineContext`를 만들어 다음 순서로 패스를 실행한다 (`src/main.rs`).

| 순서 | 패스 | 파일:라인 |
|---|---|---|
| 0 | Feature resolver (`protection_profile::resolve`) | `src/main.rs:36-44` |
| 1 | 입력 PE 파싱 `TargetPeInfo::parse` | `src/main.rs:200-206` |
| 2 | SDK 마커 선택적 VM (`SelectiveVmPass`, vm일 때) | `src/main.rs:344-350` |
| 3 | CFG 추출+슬라이싱 `pass1_slice::run` | `src/main.rs:354` |
| 4 | 블록 셔플 `pass2_shuffle::run` | `src/main.rs:358` |
| 5 | RIP 픽스업+재인코딩 `pass3_encode::run` | `src/main.rs:362` |
| 6 | .textb 섹션 조립 `pass4_section::run` | `src/main.rs:368-377` |
| 7 | 섹션 재배치+포인터 픽스업 `patch_data::run` | `src/main.rs:380-381` |
| 8 | IAT 은닉 `iat_hide::run` | `src/main.rs:384-389` |
| 9 | **암호화+부트 스텁 설치 `crypto::run`** | `src/main.rs:412-435` |
| 10 | 리소스 등록 `rsrc_register::run` | `src/main.rs:438-440` |
| 11 | `.btgvm` 폴리 VM 임베드 `embed_poly_vm_into_pipeline` | `src/main.rs:442-451` |
| 12 | PE 합성 `build::run` | `src/main.rs:453-455` |
| 13 | 출력 검증 `validate::run` | `src/main.rs:459` |

`--text-vm`/`--text-vm-oep`/`--vm-test`/`--vm-bench`는 패킹하지 않고 진단만 하고 종료한다
(`src/main.rs:150-275`).

### 1.2 Entry (OEP/스텁 진입점 · 원본 OEP 복원 경로)

- 새 PE의 EP(Entry Point)는 **부트 스텁**(`build_rc4_block`, `src/pipeline/crypto/bootstub/build.rs:56`)으로 옮겨진다.
- 부트 스텁의 어셈블리 순서 (`build.rs:57-181`):
  1. `vm_embed::emit_native_entry_save` (로더가 준 원본 entry GPR 저장) `build.rs:70`
  2. RSP S-box 프레임 할당 `build.rs:74-78`
  3. **TrashFormer-style 데드-레지스터 정크** (빌드별 부트 스텁 바이트 난독) `build.rs:80-88`
  4. `emit_base_bind_loop` (PEB ImageBase로 시드 XOR 바인딩) `build.rs:90-93`
  5. `emit_ksa_init` (RC4 KSA, --vm이면 VM 모듈이 수행) `build.rs:101-110`
  6. `emit_payload_copy` → `emit_code_decrypt` → integrity(MAC/CRC) → `emit_run_decrypt`
     → `emit_rest_decrypt` → IAT 해석 → `emit_self_wipe` → `emit_mem_harden` → `emit_dispatcher_entry`
     (`build.rs:111-181`)
- **원본 OEP 복원 경로** — `emit_dispatcher_entry` (`src/pipeline/crypto/bootstub/emit.rs:530`):
  - `--vm-oep` + **OEP가 VM화됨**(`entry_native=false`): 부트 스텁이 복원 RSP를 vreg[4]에 기록하고
    프로그램 VM 엔트리로 `jmp` (`emit.rs:556-564`).
  - `--vm-oep` + **OEP가 네이티브 유지**(`entry_native=true`): 저장한 15개 GPR을 pop하고
    `popfq` 후 `jmp rel32`로 원본 OEP로 점프 (`emit.rs:568-583`).
  - 그 외(비-vm-oep): 디스패처 3-푸시 규약 `[seed][target_id][current_id]` 후
    `jmp dispatcher_va` (`emit.rs:586-596`).
- **원본 OEP가 네이티브로 남는지 여부는 리프트 시 결정**:
  `lift_program_cfg_commercial`에서 entry 블록이 RISC 폴리 인코딩 가능하면 VM화,
  아니면 네이티브 유지 (`src/vm/text_lift/commercial.rs:309-335`).

### 1.3 Anti-debug (기법 · 단계 · 파일:라인)

두 구현이 존재한다.

1. **디스패처용 72바이트 안티디버그 셸코드** — `src/dispatcher/antidebug.rs:84-151`
   - `build_anti_debug_shellcode`: PEB.BeingDebugged(`gs:[0x60]+0x02`) →
     PEB.NtGlobalFlag(`+0xBC & 0x70`) → ProcessHeap.Flags(`[PEB+0x30]+0x70 & 0x70`).
   - 실패 정책: `Trap`(ud2) / `Hang`(jmp $) / `Warn`(fail-open) / `Poison`(상태 오염).
     enum 정의 `antidebug.rs:36-49`. 기본값 `Trap` (`src/cli.rs:41`).
   - 부트 스텁 앞(프롤로그)에 붙는다 (`src/pipeline/crypto/place/mod.rs:255-256`, `build.rs`).
2. **부트 스텁 내부 인증 게이트** — `src/pipeline/crypto/bootstub/emit.rs` `emit_code_decrypt`
   (chained 경로 `emit.rs:238-260`, 비-chained `emit.rs:328-370`):
   - 동일한 PEB 3검 + **RDTSC 타이밍**(10만회 루프가 5000 사이클 미만이면 실패).
   - 탐지 시 깨끗한 트랩 대신 **시드/S-box를 0x5A로 XOR 변조**(fail-deceptive) —
     이후 복호화를 자연스럽게 쓰레기로 유도.
   - v10 FIX 기록(`dispatcher/antidebug.rs:12-21`): 이전 버전은 GS:[0x30](TEB.Self)을 ProcessHeap으로
     오인하는 3중 버그 + 정상 경로가 ud2로 fall-through + 셸코드가 아무도 점프 안 해 미실행.

### 1.4 Key Derivation (KDF · 키 재료 · 위치)

**단일 소스**: `src/vm/ksa.rs` — `key_mix(i,k1,k2,k3)`.

- `key[i] = seed_masked[i] ^ (key_mix(i,k1,k2,k3) as u8)` (`src/pipeline/crypto/cipher.rs:65-80`).
- `key_mix`(v10 비선형): `a=i^k1; b=a*k2+k3; c=rol(b,5)^(rol(i,9)*k3); mix=ror(c,7)` (`src/vm/ksa.rs:23-28`).
- 재료: `k1=(image_base u32)^salt1, k2=(image_base>>32)+salt2, k3=salt3` (`src/pipeline/crypto/mod.rs:283-286`),
  salt는 패킹마다 랜덤(`ctx.rng`). `--seed` 주면 결정적(`src/main.rs:246-252`).
- 시드: `seed_masked = seed ^ 0xA7`, 파일에는 `seed_stored = seed_masked ^ base_bind(image_base)` 저장
  (`src/pipeline/crypto/cipher.rs:58-64`, `src/pipeline/crypto/mod.rs:296-299`).
  런타임 `emit_base_bind_loop`이 실제 PEB base로 다시 XOR해 `seed_masked` 복원 (`bootstub/emit.rs:22-53`).
- BTG-C1: `key = seed_masked[0..32]`, `nonce = le32(seed_masked[32..36])` (`cipher.rs:86-94`).
- ChaCha20: `key = seed_masked[0..32]`, `nonce = seed_masked[32..44]` (`cipher.rs:101-110`).
- **취약점(정적 복구 가능)**: KSA 상수 k1/k2/k3가 부트 스텁에 imm으로 박히고(v15/v16 랜덤 분해,
  `src/vm/ksa.rs:150-200`), 시드 seed_stored도 파일에 그대로 있다. base_bind는 preferred base의
  결정 함수라 상수로 알려져 있다. → **분석자가 k1/k2/k3(스텁에서 복원)+seed_stored+preferred base만
  알면 RC4 키를 정적으로 재구성할 수 있다.** "정적 파일에서 단순 추출 불가"(`crypto/mod.rs:25`)는 과장.

### 1.5 Integrity Check (방식 · chained 여부 · 위치 · 활성화)

- **CRC32 (키 없음)** + **BtgKeyedMac (키 결합)** 두 개를 부트 스텁이 런타임 재계산·비교, 불일치 시 `ud2`.
  - `emit_integrity_crc` (`src/pipeline/crypto/integrity.rs:25-69`): 표준 반사 CRC-32(poly 0xEDB88320).
  - `emit_integrity_mac` (`integrity.rs:90-250`): 3-단계 스펀지류 MAC(Phi=0x9E3779B97F4A7C15),
    키 = seed, 데이터 = 코드 영역.
  - 패커 측 값 저장: `crc_va = seed_off+256`, `mac_va = seed_off+260` (`place/mod.rs:696-697`).
- 활성화 조건: `--integrity` + crypto 켜짐 (`src/pipeline/crypto/mod.rs:125`,
  `integrity_effective = integrity && enabled`). crypto-off면 무시(`src/main.rs:285-287`).
- **chained integrity**: `chained && integrity` → CRC는 복호화된 평문 기준,
  `reencrypt && integrity` → 파일 암호문 기준 (`mod.rs:104-111`). 이중이 아니라 **모드별 단일** 방식.
- **약점**: CRC는 4바이트 함께 고치면 우회되고, keyed-MAC은 8바이트지만 키(seed)가 파일에 있고
  base-bind가 preferred base 상수라 **분석자도 MAC을 재계산해 값만 교체하면 우회 가능**(패치 시
  seed_off+260의 8바이트를 함께 교체). "우회 불가능 2^-64"(`integrity.rs:9`)는 키가 비밀이라는
  전제에서만 성립 — 여기선 키가 파일에 평문/도출가능 상태.

### 1.6 VM#1 / VM#2 (중첩 VM 여부 · dispatcher/handler 구조)

**"중첩 이중 VM"이 아니다.** `src/vm/nested.rs`는 두 번째 보호 VM이 아니라
**VM→VM 콜 브릿지의 상태 저장/복원 런타임 계층**(`run_nested`, `NestedVmFrame::capture`,
`nested.rs:24-80`)이다. 실제로는 **3개의 독립 VM 모듈**이 부트 영역에 순서대로 배치된다
(`src/pipeline/crypto/place/mod.rs:258-395`):

| 모듈 | 역할 | 생성 | 엔트리 모드 |
|---|---|---|---|
| **VM#1** KSA VM | RC4 S-box 초기화+키 스케줄 가상화 | `build_vm_mod(.. EntryMode::Ksa)` `place/mod.rs:258-266` | `handlers::EntryMode::Ksa` |
| **VM#1b** PRGA VM | RC4 키스트림 생성/복호화 루프 가상화 | `build_vm_mod(.. EntryMode::Prga)` `place/mod.rs:269-278` | `EntryMode::Prga` |
| **VM#2** Program VM (OEP) | 원본 프로그램 전체 리프트 | `build_prog_vm_mod(..)` `place/mod.rs:282-286` | `EntryMode::Program` |

- **레거시 VM#1 디스패처** (KSA/PRGA/프로그램 — `--vm`/`--vm-oep` 비상용):
  `src/vm/handlers/mod.rs`. 진입 스텁 → 공용/스레디드 디스패치 → opcode별 핸들러.
  - 공용 디스패치 블록 `emit_dispatch` (`handlers/mod.rs:154-176`):
    `movzx eax,[r9]; inc r9; mov rax,[r10+rax*8]; xor rax,r15; jmp rax`
  - v58부터 **스레디드**(핸들러 말단에 위 시퀀스 인라인, `hdr` `handlers/mod.rs:178-190`).
  - 핸들러 테이블: `handler_offsets[op]` (`handlers/mod.rs:110-113`, `mod.rs:630-640`),
    테이블 저장 `src/vm/mod.rs:100-103`.
- **상용 VM#2 디스패처** (`--vm-oep --vm-commercial`):
  `src/vm/threaded/poly_direct/builder.rs` `build_self_decoding_parts_with`.
  - **self-decoding 롤링 키 디스패처**: `sub_decrypt`가 VIP별 키스트림 바이트를 계산해
    opcode/operand를 복호화 (`builder.rs:188-246`), 디스패치 루프 `builder.rs:528-560`.
  - 핸들러 테이블: `[256 x u64]` + operand-offset + operand-kind + cond-code + branch-map
    (`src/vm/commercial_build.rs:74-100`).
  - 핸들러 세트: NOR/ADD/SHR/SHL/PUSH/POP/MOV/ASHR/MEM*/MUL/DIV/width-ALU/float/CMPXCHG/XCHG/
    XADD/SETCC/CMOV/BRANCH/RET/HALT 등 (builder.rs 전반).
- **레거시 vs 상용 혼재**: `--vm`(비-oep)은 KSA/PRGA/프로그램 모두 레거시 1:1 VM,
  `--vm-oep --vm-commercial`만 상용 self-decoding 엔진으로 프로그램 VM을 구성
  (`src/pipeline/crypto/mod.rs:120-126`, `place/lift.rs:25-28`).
- **한정 계약**: 차등 검증은 **선형 블록 단위 동치**로 한정 (taken-분기 제어흐름 제외).
  `commercial-vm-engine.md §3`, `src/vm/text_lift/commercial.rs` 테스트 모두 이 계약 하에서만 검증.

### 1.7 RC4 Decrypt (정적 target/size · bytecode 복호화 위치)

- **부트 스텁 bulk 복호화**: `emit_code_decrypt` (`bootstub/emit.rs:227`).
  `Mov rcx, code_va; Mov rdx, code_len` 후 PRGA(C1/ChaCha) 호출 (`emit.rs:287-288`, `301-302`, `387-388`).
- **code_va / code_len은 부트 스텁에 imm64/imm32로 정적으로 박힌다**:
  - `code_va = dispatcher_va + code_start`, `code_len`은 `place/mod.rs:225-228`에서 산정.
  - 부트 스텁 인코딩 시 `stub.code_va`/`stub.code_len` imm 로드 (`bootstub/emit.rs:287-288`).
- **문자열/리졸브 런 테이블**: `runs_va`에 `(va,len)` u64 쌍으로 저장 (`place/mod.rs:727-733`).
  부트 스텁 `emit_run_decrypt`이 순회 (`emit.rs:397-424`).
- **at-rest `.text`/바이트코드**: `emit_rest_decrypt` (`emit.rs:466-512`) —
  `vm_oep_text_runs_va`(va,len 목록) + `vm_oep_bc_va/len`을 imm으로 로드해 복호화.
  해당 VA/길이는 `place/mod.rs:404-414`, `702-706`에서 부트 스텁에 기록.
- **→ RC4 복호화 대상 주소/크기가 부트 스텁 내 imm + 런 테이블로 정적으로 노출** (약점 #4 재현).

---

## 2. ChatGPT 진단 6개 약점 — 파일:라인 재확인

심각도: **P0** 단일 바이트 패치 우회/전체 실패 · **P1** 정적 추출·복구 용이 ·
**P2** 우회 가능하나 노력 필요 · **P3** 경미/정리.

| # | 약점 | 판정 | 심각도 | 근거 (file:line) |
|---|---|---|---|---|
| 1 | **dispatcher 시그니처 과다** | **레거시 1:1 경로 재현 / 상용 경로 일부 해소** | P1(레거시) / P2(상용) | 레거시: `emit_dispatch` 5-명령 시퀀스 `movzx [r9];inc r9;mov [r10+rax*8];xor r15;jmp rax`가 **모든 핸들러 말단에 동일하게 인라인**(`handlers/mod.rs:154-176,178-190`) → 바이너리 전역에서 이 시퀀스가 반복돼 정적 시그니처로 디스패처/핸들러 경계 추출 가능. 상용: `direct_tail.rs:22-45`도 동일 5-명령 tail(`movzx eax,[r12];inc r12;xor r14;mov [r15+rax*8];jmp rax`)이지만 `poly_direct`는 롤링 키 `sub_decrypt`(`builder.rs:188-246`)와 opcode별 테이블 키로 시그니처를 흐림 → P2. |
| 2 | **handler table 구조 노출** | **레거시 재현 / 상용 일부 해소** | P1(레거시) / P2(상용) | 레거시: `handler_offsets: (0..NUM_OPS)`로 opcode→핸들러 순차 테이블 (`handlers/mod.rs:630-640`), 테이블 저장 `vm/mod.rs:100-103`. MBA 키(K=a+b)로 XOR 마스킹되지만(`handlers/mod.rs:559-568`) **K는 스텁에 imm2개로 박혀 복원 가능**. `TableLayout::legacy()`는 고정 오프셋(0x000/0x800/0x900/0xA00/0xB00) (`table_layout.rs:39-46`) — `from_seed`만 사용하면 난독. 상용: `poly_direct`는 per-opcode 테이블 키 `K(op)=(op*C1)^(op<<17)^C4^master`(`builder.rs:551-560`) + 테이블 checksum + unused 슬롯 ud2 trap(`builder.rs:566-571`)로 handler[opcode] 정적 추출을 크게 어렵게 함 → P2. |
| 3 | **opcode/operand 인코딩 규칙성** | **레거시 재현 / 상용 부분 해소** | P1(레거시) / P2(상용) | 레거시: opcode `u8` + 고정 operand, `opcode_operand_len(op)`로 **바이트 단위 정확히 디코드 가능**(`bytecode/registry.rs` opcodes! 매크로, `OPCODE_INFO`), opcode가 0x01..0xC3 순차/준순차. 상용: opcode는 시드 랜덤 맵(`isa_spec.rs:140-160`) + 롤링 키 암호화(`encoder.rs:64-98`)로 무작위화되지만, **operand 포맷은 고정**(`opcode(1B)[cond] dst(1B) src1 src2 imm(8B)`, `encoder.rs:25-27`), operand 종류가 상위 비트로 인코딩(0x80 VReg/0xC0 Temp/0x01 Imm/0x40 Vsp/0x41 Vflags, `encoder.rs:73-78`) → operand 구조는 여전히 추론 가능 → P2. |
| 4 | **정적 RC4 target/size 노출** | **재현** | P1 | `code_va`/`code_len`이 부트 스텁에 imm64/imm32로 박힘(`bootstub/emit.rs:287-288,387-388`), 문자열/리졸브/at-rest 목록이 `(va,len)` 런 테이블로 평문 저장(`place/mod.rs:727-733,508-519`), CRC/MAC 값도 `seed_off+256/260`에 평문(`place/mod.rs:727-733`). + 키 재료(시드·k1..k3)도 파일에 존재(§1.4) → **정적 추출로 복호화 가능**. |
| 5 | **정적 bytecode 위치 노출** | **재현(일부 완화)** | P1 | 프로그램 VM 바이트코드 VA/길이가 부트 스텁 `vm_oep_bc_va/len` imm으로 노출(`place/mod.rs:404-414,702-706`). at-rest 암호화 적용 시 암호문이지만 위치는 정적으로 알려짐. 상용 경로는 바이트코드가 롤링 키 암호화(`encoder.rs`)+at-rest 암호화로 난독화되나 **주소/크기는 노출** → P1. |
| 6 | **handler-semantic 1:1** | **레거시 완전 재현 / 상용 부분 해소** | P1(레거시) / P2(상용) | 레거시: 핸들러 하나 = x86 명령 하나(NOR=`or+not`, ADD=`add`, SHR=`mov ecx;shr`…, `threaded/native_runner.rs:60-140`)이고 1:1이라 **핸들러 하나 디컴파일하면 opcode 의미 전체가 드러남**. 상용 `poly_direct`도 NOR/ADD/SHR/SHL 핸들러는 여전히 원시 x86과 1:1이지만, NOR를 De Morgan `(~a)&(~b)`로 재표현(`builder.rs:588-595`), ADD가 CF/OF/ZF/SF/PF를 소프트웨어로 재합성하는 등 **1:1 표면이 깨졌음** → P2. |

**요약**: 6개 약점 모두 레거시 1:1 VM 부트 스텁(KSA/PRGA/비상용 프로그램 VM) 경로에서
그대로 재현된다. 상용 self-decoding 엔진은 #2/#6을 크게 해소하고 #3/#1을 일부 해소했지만
**#4/#5(정적 주소·크기 노출)와 키 정적 복구는 상용이어도 여전**하다.

---

## 3. 추가 발굴 — "제대로 구현 안 되어 부족한 부분"

### 3.1 SDK 마커 `.btgvm` 선택적 VM 경로는 데이터 임베드만 되고 런타임 미검증 (P1-P2)

- `poly_embed.rs:22-24` 주석: **"Execution correctness of the encrypted stream is wired next"**
  (런타임 해석기 정합은 "다음에 연결" — 미완).
- `.btgvm` 엔트리 스텁의 롤링 키는 `let seed_key = regions[0].seed as u8;` → **1바이트 키**로 R14에 로드
  (`poly_embed.rs:174-175`), `DirectTailEmitter::emit_tail_dispatch`(`poly_embed.rs:178`)가
  `xor rax,r14`로 **opcode만 상수 XOR**. 반면 바이트코드는 `PolymorphicEncoder`가 64비트 **롤링 키**
  스트림으로 인코딩(`encoder.rs:64-98`).
  → **패킹 시 암호화 방식(롤링)과 런타임 해독 방식(1바이트 상수)이 불일치**하므로 이 경로는
  바이트코드를 제대로 실행할 수 없다. 운영 시 크래시/오동작하거나, 아니면 절대 실행되지 않는다.
  (`selective_vm`의 rolling-key 소비 런타임은 별도 `src/pipeline/selective_vm.rs:105`에서 "S5 검증" 주장하나
  실제 배선·검증은 poly_embed 주석과 상충.)
- `actual-pipeline.md §3`: "SDK 마커 경로 실행 정합 **미검증** — `.btgvm` 데이터 임베드만 배선"이 그대로 실재.

### 3.2 dead path / disabled mixing loop — 핸들러 junk·decoy 제거됨 (P3)

- `obfuscate_handler_layout`(`handlers/mod.rs:291-343`): **블록 셔플만** 남기고
  **junk/decoy 삽입은 제거**됨. 주석(`mod.rs:333-340`): "데드코드(junk)를 끼워넣으면 실패 —
  특정 시드에서 런타임이 깨진다(0xC0000005)… 안전한 조합은 **블록 셔플만**."
  → 다형성(폴리모픽 핸들러)을 강화하려던 mixing 루프가 **실행 안정성 때문에 비활성화**.
- 부트 스텁의 TrashFormer 정크(`bootstub/build.rs:80-88`, `emit.rs:63-92`)는 **적용 중**이지만
  데드 레지스터 9개로 제한된 mov/or/xor/cmp/lea뿐이라 분석 난이도를 크게 높이지 못함.
- `src/graph/slicer.rs:150`: "Disabled by default to preserve ASLR .reloc exact instruction boundary alignment"
  (또 다른 비활성화 지점).

### 3.3 TLS 콜백 때문에 .text 평문 잔존 — 전체 가상화 미달성 (P1)

- `--vm-oep`에서 코드 블록을 **평문으로 유지**: `src/pipeline/crypto/mod.rs:206-217`
  ("네이티브 CRT가 함수 포인터로 원본 코드를 직접 호출 → --vm-oep에서는 코드 블록을 평문으로 유지").
- at-rest `.text` 암호화는 **TLS 콜백 도달 함수만 제외**하고 암호화하도록 설계(`tls_guard.rs:1-25`),
  `detect_tls_callback_ranges`(`tls_guard.rs:35-157`)가 TLS-callback-reachable 함수를 평문으로 남김.
- `has_tls_cb` 분기(`place/mod.rs:450-470`): TLS 콜백 배열이 존재하면 `.text`를 **암호화하지 않음**.
- `actual-pipeline.md §3`: "원본 `.text` 평문 제거 **미달성** — 대부분의 모드에서 `.text`를 평문으로 유지".
  → Rust/CRT 타깃은 TLS/CRT 초기화자가 실행돼야 하므로 **원본 .text가 평문/부분 암호화로 잔존**.
  목표(원본 .text 평문 0)와 대비되는 핵심 미달.

### 3.4 무력화 가능한 integrity — 키가 파일에 있어 재계산 가능 (P1)

- CRC32(키 없음) + keyed-MAC(키=seed). 키(seed)가 `seed_off`에 **평문 저장**되고
  base-bind가 preferred base 상수라 도출 가능(`§1.4`, `place/mod.rs:727-733`).
- 공격자가 암호문/데이터를 바꾸고 seed로 MAC/CRC를 **재계산해 seed_off+260/256에 다시 쓰면** ud2 없이 통과.
  "2^-64 우회 불가능"(`integrity.rs:8-9`)은 키가 외부 비밀이란 전제 하에서만 참.
- 또한 `emit_integrity_crc`/`emit_integrity_mac`은 모두 `stub.integrity` 가드(`integrity.rs:31,93`),
  `integrity_effective = integrity && enabled`(`mod.rs:125`) → **--integrity를 안 주면 아예 미장착**.
  기본 프로파일/`--no-crypto`에선 무력화 상태.

### 3.5 약한/정적 복구 가능한 KDF — RC4는 암호학적으로 안전하지 않음 (P1)

- RC4 자체 + 커스텀 키스트림. 키는 시드+스텁 상수로 **정적 복원 가능**(§1.4, §2 #4).
- `--custom-cipher` BTG-C1은 "감사되지 않은 홈메이드 구현"(`actual-pipeline.md §2.2`).
- `--chained-crypto`는 Key_i=이전 256B 평문이라 **복호화 중 메모리에 연쇄 키가 연속 존재**.
- `--crypto-coverage < 100`이면 파일에 평문 코드 잔존(`src/main.rs:218-220`).

### 3.6 적용되지 않거나 부분적으로만 적용되는 옵션/경로 (P3)

- **`--dispatcher-reencrypt`**: "첫 디스패치 시 복호화 후 평문 유지(decrypt-once)" —
  문서(`actual-pipeline.md §2.2`)와 코드(`src/dispatcher/reencrypt.rs` 주석, `src/pipeline/crypto/mod.rs` v8 경로).
  즉 재암호화가 실제로 반복되지 않는 지점 존재.
- **Poly1305 AEAD**(`--crypto-mode chacha20`)는 **chained/reencrypt/--vm/--vm-oep에서 무시**되고
  평문 bulk at-rest 경로에만 적용(`crypto/mod.rs:135-158`) — 즉 프로그램 VM+chacha 조합은 AEAD 미적용.
- **`DirectThreadedNativeRunner`(10개 핸들러)**: `.btgvm`/상용 하네스에 쓰이나
  실제 `poly_direct` self-decoding 엔진과는 별개이며, operand 디코딩을 수행하지 않는 단순 1:1 핸들러
  (`native_runner.rs:60-140`).
- **`table_layout.rs`**: `legacy()` 고정 오프셋이 남아 있고 `from_seed` 사용 여부가 경로별로 상이 —
  legacy 경로는 고정 테이블 시그니처 잔존.

### 3.7 VM state / 핸들러 restore 노출

- 상용 디스패처는 엔트리에서 R12..R15 + RDI/RSI/RBX/RBP를 push, HALT가 역순 pop(`builder.rs:842-850`).
  핸들러 restore는 구현되어 있으나 **레거시 VM은 VM entry 시 callee-saved 전부를 스택에 보존**하므로
  (VM 내부 GPR 상태는 모두 메모리 state buffer에 상주) 메모리 덤프에서 **VM vreg/flags/temps가
  고정 오프셋(state buffer)으로 노출**된다(`interp/state.rs`, `handlers/mod.rs:110` PTR_SLOTS_BASE).
  → VM state 숨김이 없음(평문 state buffer).

### 3.8 import/string 평문

- 문자열 리터럴 런과 import 리졸브 테이블은 암호화 대상(`crypto/mod.rs` 5b, `runs`),
  **암호화된 런은 부트 스텁이 복호화 후 평문 유지**(decrypt-once), self-wipe는 seed/S-box만 지우고
  복호화된 문자열/리졸브/`.vdata`는 평문으로 남음(`bootstub/emit.rs` `emit_self_wipe`, `place/mod.rs` vdata는 R-only라 소거 생략).
  → 런타임 덤프에서 복호화된 문자열이 평문 노출. `payload-relocate`는 암호화 후 `.vdata`로 옮기지만
  R-only라 self-wipe 불가(`place/mod.rs:735-737` 주석).

---

## 4. 우선순위 정리된 수정 권고

| 우선순위 | 항목 | 근거 | 제안 |
|---|---|---|---|
| **P0-1** | `.btgvm` 선택적 VM 런타임 미검증 + 1바이트 롤링 키 | `poly_embed.rs:22-24,174-178` | 이 경로를 실제 실행 배선하거나(롤링 키 일치·operand 디코딩), 아니면 마커 임베드 자체를 끄고 "미지원"으로 명시. 1바이트 키 XOR은 즉시 제거. |
| **P0-2** | `.text` 평문 잔존(전체 가상화 미달성) | `crypto/mod.rs:206-217`, `tls_guard.rs`, `actual-pipeline.md` | TLS 콜백/CRT만 네이티브 브리지로 빼고 나머지 .text를 100% at-rest 암호화. 우선은 `--vm-oep`에서 코드 블록 평문 유지를 브리지 호출로 대체. |
| **P0-3** | integrity 키(seed)가 파일 노출 → 재계산 우회 | `place/mod.rs:727-733`, `integrity.rs` | 키를 OS/런타임 유도(TLS/실행환경)로 분리하거나, MAC에 파일 외부 비밀 결합. 최소한 base-bind를 preferred base가 아닌 동적 값으로. |
| **P1-1** | RC4/키 정적 복구 (target/size + 키 재료 노출) | `bootstub/emit.rs:287-388`, `cipher.rs:58-80` | 부트 스텁 imm을 유지하되 키 스케줄 상수/시드를 분리 암호화하고, 런 테이블 목록을 난독화. ChaCha20/Poly1305 경로를 프로그램 VM까지 확장. |
| **P1-2** | 레거시 1:1 VM의 시그니처/handler 1:1/opcode 규칙 | `handlers/mod.rs:154-190`, `registry.rs` | 레거시 경로를 상용 self-decoding 엔진으로 전면 대체(현재 `--vm`은 레거시 유지). |
| **P2-1** | 핸들러 junk/decoy 비활성화(dead path) | `handlers/mod.rs:333-340` | 실행 안정성을 잃지 않는 범위(셔플+가짜 분기만)에서 다형성 재도입. |
| **P2-2** | 차등 검증이 선형 블록에 한정 → 제어흐름 미검증 | `commercial-vm-engine.md §3` | taken-분기/native-bridge/롤링 키 재동기 경로를 별도 검증 스위트로 확장. |
| **P3** | 미적용 옵션 정리 (reencrypt decrypt-once, chacha+VM AEAD 무시, legacy table_layout) | `crypto/mod.rs:135-158`, `table_layout.rs:39-46` | 문서와 코드 일치시키고 legacy 고정 오프셋 제거. |

---

## 5. 요약 한 줄

실제 코드 기준으로, **ChatGPT 6개 약점은 레거시 1:1 VM 부트 스텁 경로에서 전부 재현**(P1),
**상용 self-decoding 엔진은 #2/#6 해소·#1/#3 일부 해소**했지만 **#4/#5 정적 노출과 키 정적 복구는
여전**하며, **`.btgvm` 선택적 VM은 미완(1바이트 키+런타임 미검증)**, **TLS/CRT 때문에 원본 .text 평문
잔존**, **integrity 키가 파일 노출로 재계산 우회 가능** — "상용 등급" 달성은 아직 아니다.
