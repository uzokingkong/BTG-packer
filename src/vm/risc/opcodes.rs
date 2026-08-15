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

    /// 가상 플래그 레지스터 갱신 (CF, ZF, SF, OF)
    SetFlag,

    /// VM 실행 종료 및 네이티브 컨텍스트 복귀
    Halt,

    /// 값 복사 (dst = src1) — **플래그를 변경하지 않는다**.
    /// (MOV/XCHG/XADD/POP 등 플래그 보존이 필요한 복사에 사용.
    /// AddWithCarry(+,0) 로는 플래그를 오염시키므로 전용 op 로 분리.)
    Mov,

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
