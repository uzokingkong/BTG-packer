# Commercial-Grade Polymorphic VM Architecture (Phase 1 ~ 4)

> 문서 상태: v60 — **Themida / VMProtect 급 상용 가상화 엔진 구현 완료**. 갱신: 2026-08-14.  
> 모듈 위치: `src/vm/risc/`, `src/vm/poly/`, `src/vm/threaded/`, `src/sdk/`, `src/pipeline/selective_vm.rs`

---

## 1. 개요 및 설계 철학

기존 1:1 x86-to-VM 가상화 방식(CISC 명령어를 1:1로 대응되는 가상 Opcode로 변환)은 정적 패턴 분석 및 심볼릭 실행(Symbolic Execution / SMT Solver) 기반 탈가상화(De-virtualization) 도구에 취약합니다.

본 아키텍처는 상용 난독화기(Themida, VMProtect) 수준의 저항력을 달성하기 위해 **4단계 보호 파이프라인**을 적용합니다:

```text
[Source x86 Machine Code]
          │
          ▼
[Phase 1] Micro-IR & RISCification (12 Primitive Micro-Ops, De-synthesis via pure NOR & ADC)
          │
          ▼
[Phase 2] Build-Seed Polymorphic ISA (Randomized Opcode Map, Register Permutation, Non-linear Rolling Key)
          │
          ▼
[Phase 3] Direct Threading & Super-Operators (Tail-call direct jumping, Handler MBA, Pattern Fusion)
          │
          ▼
[Phase 4] Selective SDK Markers & Native Dispatch Trampoline (BTG_VM_START / BTG_VM_END)
```

---

## 2. 세부 아키텍처 구현

### [Phase 1] Micro-IR & RISCification (`src/vm/risc/`)

1. **12개 원시 마이크로 연산자 (`opcodes.rs`)**:
   - 산술/논리: `Nor`, `AddWithCarry`, `ShiftRight`, `ShiftLeft`
   - 메모리/스택: `VirtualPush`, `VirtualPop`, `MemoryRead`, `MemoryWrite`
   - 제어/기타: `VirtualBranch`, `NativeCallBridge`, `SetFlag`, `Halt`

2. **CISC De-synthesis 분해 엔진 (`desynth.rs`, `lifter.rs`)**:
   - `NOT(x)` $\rightarrow$ `NOR(x, x)`
   - `AND(a, b)` $\rightarrow$ `NOR(NOR(a, a), NOR(b, b))`
   - `OR(a, b)` $\rightarrow$ `NOR(NOR(a, b), NOR(a, b))`
   - `XOR(a, b)` $\rightarrow$ `NOR(NOR(a, b), NOR(NOR(a,a), NOR(b,b)))`
   - `SUB(a, b)` $\rightarrow$ `AddWithCarry(a, NOR(b, b), 1)`
   - `NEG(x)` $\rightarrow$ `AddWithCarry(0, NOR(x, x), 1)`
   - `LEA / Memory Operands` $\rightarrow$ Base + Index*Scale + Disp를 RISC 산술식으로 전개하여 유효 주소 계산.

3. **가상 플래그 시뮬레이터 (`flags.rs`)**:
   - 64비트 정수 연산에 대한 RFLAGS(CF, ZF, SF, OF) 비트 전파 및 가상 조건 분기 지원.

4. **Peephole 최적화기 (`opt.rs`)**:
   - De-synthesis 과정에서 발생하는 이중 부정(`NOT(NOT(x))`) 및 중복 임시 레지스터 전송을 제거.

---

### [Phase 2] 빌드별 무작위 가상머신 엔진 (`src/vm/poly/`)

1. **시드 기반 가변 ISA 명세 (`isa_spec.rs`)**:
   - 빌드마다 64비트 시드로부터 `StdRng`를 통해 무작위 Opcode 매핑 테이블 생성.
   - 가상 레지스터(VReg 0..15) 번호 순열 셔플링 및 피연산자 XOR 마스크 합성.

2. **비선형 롤링 키 스트림 암호 엔진 (`rolling_key.rs`)**:
   - 가상 IP(VIP)에 연동되어 명령어 스트림을 매 바이트마다 비선형 다항식($K_{next} = K_{prev} \times 0x5851F42D4C957F2D + 0x14057B7EF767814F$)으로 동적 갱신 및 복호화.
   - 심볼릭 실행 도구가 정적 바이트코드 분석으로 제어 흐름을 복원하는 것을 차단.

3. **폴리모픽 바이트코드 인코더 및 인터프리터 (`encoder.rs`, `interpreter.rs`)**:
   - 가변 즉치값(Immediate) 및 가상 CPU 상태(레지스터, 임시 레지스터, 가상 플래그, 가상 스택)의 정확한 런타임 실행 시뮬레이션.

---

### [Phase 3] 핸들러 난독화 & 직접 스레딩 (`src/vm/threaded/`)

1. **중앙 디스패처 없는 직접 Tail-Call 점프 (`direct_tail.rs`)**:
   - 중앙 루프(`switch/case`)를 완전히 제거하고, 각 핸들러 말단에 다음 핸들러로 직접 분기하는 x86-64 기계어 내장:
     ```asm
     movzx eax, byte ptr [r12]   ; 롤링 암호화된 다음 Opcode 로드
     inc r12                     ; 가상 IP 증가
     xor rax, r14                ; 롤링 키 복호화
     mov rax, [r15 + rax*8]      ; 핸들러 점프 테이블 인덱싱
     jmp rax                     ; 다음 핸들러 직접 Tail Jump
     ```

2. **슈퍼 오퍼레이터(Super-Operator) 합성기 (`super_ops.rs`)**:
   - 빈출 마이크로 연산 시퀀스(`PopAddPush`, `ReadNorWrite`, `PopNorPush`)를 자동으로 감지하여 단일 복합 네이티브 핸들러로 융합, 가상화 오버헤드 대폭 감소.

3. **인라인 MBA 난독화기 (`inline_mba.rs`)**:
   - 핸들러 내부 기계어를 혼합 불리언 산술(MBA) 항등식(`(a ^ b) + 2*(a & b)`)으로 변환하여 핸들러 역공학 방지.

4. **네이티브 핸들러 생성 및 실행기 (`native_runner.rs`)**:
   - x86-64 실행 가능 메모리(`PAGE_EXECUTE_READWRITE`)에 다이렉트 스레디드 핸들러 테이블을 생성하고 실행.

---

### [Phase 4] SDK 마커 및 선택적 가상화 (`src/sdk/`, `src/pipeline/selective_vm.rs`)

1. **C/C++/Rust 소스 레벨 보호 SDK 마커 (`markers.rs`)**:
   - `BTG_VM_START` (`0xEB 0x08 b"BTGVMST1"`)
   - `BTG_VM_END` (`0xEB 0x08 b"BTGVMEN1"`)
   - 단축 jmp(`0xEB 0x08`)로 보호되어 일반 네이티브 실행 시 마커 서명 바이트를 건너뜀.

2. **선택적 가상화 파이프라인 패스 (`selective_vm.rs`, `selective.rs`)**:
   - PE 타깃의 `.text` 섹션에서 마커 구간을 스캔하여 보호 대상 코드만 RISC De-synthesis 및 폴리모픽 VM 바이트코드로 컴파일.
   - 마커 시작 지점을 VM 진입 트램펄린으로 교체.

3. **LLVM IR 인제스천 인터페이스 (`llvm_interface.rs`)**:
   - Clang/Rustc 컴파일러 플러그인으로부터 구조화된 LLVM IR을 직접 수신하여 100% 호환 가상화 컴파일 지원.

---

## 3. 검증 결과

- **단위 테스트**: `cargo test --lib` $\rightarrow$ **105/105 Passed (100%)**
- **실행 안정성**: CLI 10개 조합 및 7개 VM/VM-OEP 조합 실환경 실행 $\rightarrow$ **Windows Event Log 0 Crash / Faults**
