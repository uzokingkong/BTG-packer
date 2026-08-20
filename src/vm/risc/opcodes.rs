// ==============================================================================
// BTG - Commercial-Grade VM: Primitive RISC Micro-Op Definitions
// ==============================================================================
// 상용 VM(Themida/VMProtect)의 핵심 원리인 RISCification의 기초 원자 연산 정의.
// 모든 x86 CISC 명령어(ADD, SUB, XOR, AND, OR, CMP 등)를 12개의 최소 원시
// 마이크로 연산으로 분해(De-synthesis)하여 원본 연산의 시그니처를 파괴한다.
// ==============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiscOp {
    /// 비트 단위 NOR 연산: dest = ~(src1 | src2)
    /// 모든 불리언 논리(NOT, AND, OR, XOR, NAND, XNOR)를 단일 원자로 표현
    Nor,

    /// 64비트 캐리 포함 덧셈: (dest, cout) = src1 + src2 + cin
    /// 모든 산술 덧셈/뺄셈/부호반전(NEG)의 기본 원자
    AddWithCarry,

    /// 64비트 비트 쉬프트 (우측 논리)
    ShiftRight,

    /// 64비트 산술 우측 시프트 (부호 비트 유지) — SAR
    ArithmeticShiftRight,

    /// 64비트 비트 쉬프트 (좌측)
    ShiftLeft,

    /// 가상 스택 푸시: VSP -= 8; [VSP] = val
    VirtualPush,

    /// 가상 스택 팝: val = [VSP]; VSP += 8
    VirtualPop,

    /// 가상 메모리 로드: dest = [addr] (1, 2, 4, 8 bytes)
    MemoryRead { width: u8 },

    /// 가상 메모리 스토어: [addr] = src (1, 2, 4, 8 bytes)
    MemoryWrite { width: u8 },

    /// 가상 조건부/무조건 브랜치: if (cond_flag) VIP = target
    VirtualBranch { cond: BranchCondition },

    /// 네이티브 API 및 런타임 콜 브릿지
    NativeCallBridge,

    /// P1 (③): VM→VM 콜 브릿지 — 별도 VM 인스턴스(리전)로 진입해 실행 후 복귀.
    ///
    /// `imm` = 서브 VM 프로그램 id (`RiscProgram.sub_vms` 키). 참조 `eval_state`
    /// 는 호출자 상태(regs/temps/flags/vsp/stack)를 스냅샷하고 서브 VM을 같은
    /// regs/mem 으로 실행한 뒤 복귀 — RAX(vreg 0)만 서브 VM의 반환값으로 대체하고
    /// mem 은 서브 VM 이 쓴 내용을 보존한다 (아웃-파라미터). 같은 VM 내 점프는
    /// `VirtualBranch` 가 처리하므로 여기는 **다른 VM 인스턴스 진입**만 담당한다.
    ///
    /// 폴리 인코딩/네이티브 하네스에서는 인지된 no-op 스텁 (`NativeCallBridge` 와
    /// 동일 계약 — 실제 nested-VM 실행은 런타임 계층, P3 상용 통합은 리전 레지스트리
    /// 확장 필요). `is_encodable` 에 등록하지 않아 상용 `--vm-commercial` 은
    /// VmCallBridge 를 포함한 함수를 네이티브로 유지한다.
    VmCallBridge,

    /// 가상 플래그 레지스터 갱신 (CF, ZF, SF, OF)
    SetFlag,

    /// VM 실행 종료 및 네이티브 컨텍스트 복귀
    Halt,

    /// x86 RET — 가상 스택에서 복귀 주소를 pop 해 VM 내부(ip_map) 타깃이면
    /// 그쪽으로 분기하고, ip_map 에 없으면(빈 스택/네이티브 복귀 주소) **Halt** 로
    /// 종료해 네이티브 호출자에게 돌아간다.
    ///
    /// P0-1: 이전엔 RET 가 그대로 Halt 로 내려가 VM 내부 함수 호출(call foo; ret)의
    /// 복귀를 표현할 수 없었다. `VirtualRet` 는 pop → branch-map 복귀 → 없으면 종료
    /// 의미론으로 VM→VM nested call 과 최상위(프로그램 종료) ret 를 모두 처리한다.
    /// CALL 쪽은 `VirtualPush(ret_ip); VirtualBranch(target)` 이고, 네이티브로 나가는
    /// 콜은 브릿지(h_branch not-found)가 pop+네이티브 호출을 담당하므로 VirtualRet 의
    /// not-found 는 항상 "VM 프로그램 종료"다.
    VirtualRet,

    /// 값 복사 (dst = src1) — **플래그를 변경하지 않는다**.
    /// (MOV/XCHG/XADD/POP 등 플래그 보존이 필요한 복사에 사용.
    /// AddWithCarry(+,0) 로는 플래그를 오염시키므로 전용 op 로 분리.)
    Mov,

    // ── P0-1 (canonical semantics): x86 정확 플래그가 필요한 전용 산술 op ───────
    // desynth의 AddWithCarry(+~b+1)로는 x86 SUB/NEG의 borrow-CF를 재현할 수 없다
    // (a<b일 때 CF=1). 분기(JB/JAE 등)가 플래그를 소비하므로 실질 버그다.
    // 각 op는 x86 폭(1/2/4/8)의 플래그 경계(bit 7/15/31/63)로 계산한다.

    /// x86 SUB/CMP — dst = src1 - src2. CF=borrow(a<b), OF/AF/SF/ZF/PF 정확.
    SubWithBorrow { width: u8 },

    /// x86 ADD — dst = src1 + src2. 폭별(bit 7/15/31/63) CF/OF/AF/SF/ZF/PF 정확.
    Add { width: u8 },

    /// x86 INC — dst = src1 + 1. CF **보존**, OF=res==MIN, AF/ZF/SF/PF 갱신.
    Inc { width: u8 },

    /// x86 DEC — dst = src1 - 1. CF **보존**, OF=res==MAX, AF/ZF/SF/PF 갱신.
    Dec { width: u8 },

    /// x86 NOT — dst = ~src1. **플래그 변경 없음** (x86 NOT은 RFLAGS 불변).
    Not { width: u8 },

    // ── P2: 정수/비트/제어 복합 연산 (x86 hard-to-decompose) ─────────────────────

    /// 1-피연산자 MUL/IMUL (RDX:RAX = RAX * r/m, 폭별).
    /// `dst` = low, `regs[2]`(RDX) = high(폭 ≥ 2), 폭 1 은 AX(=AL + AH) 를 dst 로.
    /// CF = OF = overflow (unsigned: high != 0; signed: high != sign-extend(low)).
    Multiply { signed: bool, width: u8 },

    /// 2/3-피연산자 IMUL (dst = low(src1 * src2), RDX 미기록).
    /// CF = OF = overflow. 폭은 `width`(2/4/8).
    MultiplyLow { signed: bool, width: u8 },

    /// DIV/IDIV — 피제수 = RDX:RAX(폭별), 제수 = src1, 몫 → dst(RAX), 나머지 → RDX.
    /// 폭 1 은 AL=몫, AH=나머지, 결과를 AX(dst) 로.
    Divide { signed: bool, width: u8 },

    /// BSWAP (폭 4/8) — 바이트 순서 반전.
    BSwap { width: u8 },

    /// BSF — src == 0 이면 ZF=1·dst=0, 아니면 ZF=0·dst=최하위 세트 비트 인덱스.
    BitScanForward,

    /// BSR — src == 0 이면 ZF=1·dst=0, 아니면 ZF=0·dst=최상위 세트 비트 인덱스.
    BitScanReverse,

    /// TZCNT — dst = ctz(src); src == 0 이면 dst=폭·CF=1·ZF=1.
    CountTrailingZeros { width: u8 },

    /// LZCNT — dst = clz(src, 폭 한정); src == 0 이면 dst=폭·CF=1·ZF=1.
    CountLeadingZeros { width: u8 },

    /// POPCNT — dst = popcount(src); CF=OF=0, ZF/SF/PF 는 결과 기준.
    PopCount,

    /// SETcc — dst(8비트) = 조건 ? 1 : 0. (조건은 branch_cond_map 으로 부호화)
    Setcc { cond: BranchCondition },

    /// CMOVcc — dst = 조건 ? src1 : dst. (조건은 branch_cond_map 으로 부호화)
    ConditionalMove { cond: BranchCondition },

    /// CMPXCHG — `[src1] == RAX` 이면 `[src1] = src2`·ZF=1, 아니면 `RAX = [src1]`·ZF=0.
    /// (누산기 RAX = regs[0], 폭별 마스크. 폭 8 이면 RAX 전체.)
    CompareExchange { width: u8 },

    /// P0-4: 원자적 XCHG — `dst`(레지스터) ↔ `[src1]`(메모리) 교환.
    ///
    /// x86 `XCHG r, [mem]` 은 memory 피연산자에서 **암시적 LOCK** 이므로
    /// read-modify-write 가 원자적이어야 한다. 일반 MemoryRead/MemoryWrite 분해는
    /// 중간 상태를 노출한다(lock-free/atomic counter/Rust `AtomicUsize` 스핀락 등).
    /// 이 op 는 메모리 상호 교환을 단일 원자로 모델링한다: `old = [src1]; [src1] =
    /// dst; dst = old`. 플래그 불변 (x86 XCHG 는 RFLAGS 무변경). 레지스터↔레지스터
    /// XCHG 는 원자성이 불필요하므로 lifter 는 기존대로 Mov 3개로 분해한다.
    AtomicExchange { width: u8 },

    /// P0-4: 원자적 XADD — `[src1] += src2`, `dst` = 이전 `[src1]`.
    ///
    /// x86 `LOCK XADD [mem], reg` 는 원자 RMW 이며 flags 는 덧셈 기준이다.
    /// `old = [src1]; new = old + src2 (폭별 플래그); [src1] = new; dst = old`.
    /// 레지스터 형태(XADD r/m, r) 는 원자성이 불필요하지만 동일 op 로 표현한다.
    AtomicAdd { width: u8 },

    // P2: SSE/FPU scalar
    FloatAdd { width: u8 },
    FloatSub { width: u8 },
    FloatMul { width: u8 },
    FloatDiv { width: u8 },
    IntToFloat { src_bits: u8, dst_bits: u8 },
    FloatToInt { src_bits: u8, dst_bits: u8, truncate: bool },
    FloatToFloat { src_bits: u8, dst_bits: u8 },

    // ── P1 (보고서 ②): packed SSE — XMM 슬롯(16바이트 가상 메모리) 기반 ────────
    // XMM 슬롯은 XMM_SLOT_BASE + idx*16 의 16바이트 가상 메모리로 모델링된다.
    // packed op 는 슬롯 **주소**(src1/src2/dst)를 피연산자로 받아 내부에서
    // 16바이트를 읽고 요소 단위로 연산한 뒤 16바이트를 기록한다. 요소 경계에서
    // 캐리/보로우가 전파되지 않는다 (PADDD 는 32-bit add 4개와 동치 — 64-bit
    // add 로 분해하면 lane 사이 캐리가 전파되어 틀리므로 전용 op 가 필요).
    // x86 packed 정수 연산은 RFLAGS 를 변경하지 않는다 → 플래그 불변.
    // `is_encodable`에는 **등록하지 않는다** (상용 `--vm-commercial`은 이런 함수를
    // 네이티브로 유지 — XMM_SLOT_BASE 는 네이티브 arena에 매핑되지 않으므로
    // 폴리 인코딩/네이티브 실행을 허용하면 조용히 틀린다).

    /// MOVDQA/MOVDQU/MOVUPS/MOVAPS — 16바이트 슬롯 복사. src1 = 원본 슬롯/메모리
    /// 주소, dst = 대상 슬롯 주소. (메모리 로드/스토어는 lifter 가 2× 8바이트
    /// MemoryRead/MemoryWrite 로 분해한다.)
    PackedMove,

    /// PADDB(1,16)/PADDW(2,8)/PADDD(4,4)/PADDQ(8,2) — 요소 단위 가산(폭 랩).
    PackedAdd { elem_width: u8, lanes: u8 },

    /// PSUBB/PSUBW/PSUBD/PSUBQ — 요소 단위 감산(폭 랩).
    PackedSub { elem_width: u8, lanes: u8 },

    /// PXOR — 16바이트 배타적 논리합 (요소 폭 무관 비트열).
    PackedXor,

    /// PAND — 16바이트 논리곱.
    PackedAnd,

    /// POR — 16바이트 논리합.
    PackedOr,

    /// PANDN — 16바이트 (a & ~b).
    PackedAndNot,

    /// PCMPEQB/W/D/Q — 요소 단위 등가: 같은 요소 = 전-1, 다르면 0.
    PackedCmpEq { elem_width: u8, lanes: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BranchCondition {
    Always,
    Zero,
    NotZero,
    Carry,
    NotCarry,
    Sign,
    NotSign,
    Overflow,
    NotOverflow,
    Greater,
    Less,
    GreaterOrEqual,
    LessOrEqual,
    // unsigned comparisons (precise, not just CF)
    Above,          // JA: CF=0 && ZF=0
    AboveOrEqual,   // JAE: CF=0
    Below,          // JB: CF=1
    BelowOrEqual,   // JBE: CF=1 || ZF=1
    // parity
    Parity,         // JP
    NotParity,      // JNP
    // counter-based (Jcxz/Jecxz/Jrcxz): width in bytes (2/4/8). reg[1](RCX) low bytes == 0
    CounterZero(u8),
}

/// 가상 마이크로 레지스터 / 피연산자
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MicroOperand {
    /// 가상 범용 레지스터 (0 ~ 15)
    VReg(u8),
    /// 64비트 즉시값
    Imm64(u64),
    /// 가상 스택 포인터 (VSP)
    Vsp,
    /// 가상 플래그 레지스터 (VFLAGS)
    Vflags,
    /// 임시 스크래치 레지스터 (T0, T1, T2)
    Temp(u8),
}

/// 단일 RISC 마이크로 인스트럭션
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroInstr {
    pub op: RiscOp,
    pub dst: Option<MicroOperand>,
    pub src1: Option<MicroOperand>,
    pub src2: Option<MicroOperand>,
    pub imm: u64,
}

impl MicroInstr {
    pub fn new(op: RiscOp) -> Self {
        Self {
            op,
            dst: None,
            src1: None,
            src2: None,
            imm: 0,
        }
    }

    pub fn with_dst(mut self, dst: MicroOperand) -> Self {
        self.dst = Some(dst);
        self
    }

    pub fn with_src1(mut self, src1: MicroOperand) -> Self {
        self.src1 = Some(src1);
        self
    }

    pub fn with_src2(mut self, src2: MicroOperand) -> Self {
        self.src2 = Some(src2);
        self
    }

    pub fn with_imm(mut self, imm: u64) -> Self {
        self.imm = imm;
        self
    }
}
