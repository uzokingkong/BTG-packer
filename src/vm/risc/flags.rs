// ==============================================================================
// BTG - Commercial-Grade VM: Micro-Flag Simulation & Evaluation
// ==============================================================================
// RISC 마이크로 연산 수행 시 발생하는 x86 RFLAGS 상태(CF, ZF, SF, OF)를
// 비트 수준에서 기호적(Symbolic) 및 런타임으로 정밀 계산한다.
// ==============================================================================

pub const VFLAG_CF: u64 = 1 << 0;
pub const VFLAG_PF: u64 = 1 << 2;
pub const VFLAG_AF: u64 = 1 << 4;
pub const VFLAG_ZF: u64 = 1 << 6;
pub const VFLAG_SF: u64 = 1 << 7;
pub const VFLAG_DF: u64 = 1 << 10; // direction (string ops; not a status flag)
pub const VFLAG_OF: u64 = 1 << 11;

/// Status flags mask (arithmetic never touches DF — bit 10).
pub const VFLAG_STATUS_MASK: u64 = VFLAG_CF | VFLAG_PF | VFLAG_AF | VFLAG_ZF | VFLAG_SF | VFLAG_OF;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtualFlags {
    pub raw: u64,
}

impl VirtualFlags {
    pub fn new(raw: u64) -> Self {
        Self { raw }
    }

    #[inline]
    pub fn cf(&self) -> bool {
        (self.raw & VFLAG_CF) != 0
    }

    #[inline]
    pub fn zf(&self) -> bool {
        (self.raw & VFLAG_ZF) != 0
    }

    #[inline]
    pub fn sf(&self) -> bool {
        (self.raw & VFLAG_SF) != 0
    }

    #[inline]
    pub fn of(&self) -> bool {
        (self.raw & VFLAG_OF) != 0
    }

    /// 패리티 플래그 (PF, bit 2) — low 8비트의 1의 개수가 짝수면 1.
    /// 참조 시뮬레이터(eval_state)가 산술/논리 연산 후 `set_parity`로 갱신한다.
    #[inline]
    pub fn pf(&self) -> bool {
        (self.raw & VFLAG_PF) != 0
    }

    /// 결과 low 8비트의 패리티를 계산해 PF 비트를 설정/해제한다.
    pub fn set_parity(&mut self, res: u64) {
        let ones = (res as u8).count_ones();
        if ones % 2 == 0 {
            self.raw |= VFLAG_PF;
        } else {
            self.raw &= !VFLAG_PF;
        }
    }

    /// 64비트 덧셈(a + b + cin)에 대한 RFLAGS 플래그 갱신
    pub fn update_add64(&mut self, a: u64, b: u64, cin: u64) -> (u64, u64) {
        let (sum1, c1) = a.overflowing_add(b);
        let (res, c2) = sum1.overflowing_add(cin);
        let cout = (c1 || c2) as u64;

        let mut flags = 0u64;
        if cout != 0 {
            flags |= VFLAG_CF;
        }
        if res == 0 {
            flags |= VFLAG_ZF;
        }
        if (res as i64) < 0 {
            flags |= VFLAG_SF;
        }
        // OF = ((a ^ res) & (b ^ res)) >> 63
        if ((a ^ res) & (b ^ res) & 0x8000_0000_0000_0000) != 0 {
            flags |= VFLAG_OF;
        }
        // PF = even parity of low byte
        if (res as u8).count_ones() % 2 == 0 {
            flags |= VFLAG_PF;
        }

        self.raw = (self.raw & !(VFLAG_CF | VFLAG_PF | VFLAG_ZF | VFLAG_SF | VFLAG_OF)) | flags;
        (res, cout)
    }

    /// 비트 단위 논리 연산(NOR, AND, OR, XOR) 후 플래그 갱신 (CF=0, OF=0, ZF/SF 갱신)
    pub fn update_logic64(&mut self, res: u64) {
        let mut flags = 0u64;
        if res == 0 {
            flags |= VFLAG_ZF;
        }
        if (res as i64) < 0 {
            flags |= VFLAG_SF;
        }
        if (res as u8).count_ones() % 2 == 0 {
            flags |= VFLAG_PF;
        }
        self.raw = (self.raw & !(VFLAG_CF | VFLAG_PF | VFLAG_OF | VFLAG_ZF | VFLAG_SF)) | flags;
    }

    /// MUL/IMUL·DIV/IDIV 의 CF/OF 만 갱신 (다른 플래그는 보존 — x86 "undefined" 정책).
    pub fn set_cf_of(&mut self, both: bool) {
        self.raw &= !(VFLAG_CF | VFLAG_OF);
        if both {
            self.raw |= VFLAG_CF | VFLAG_OF;
        }
    }

    /// ZF 만 갱신 (CMPXCHG — 다른 플래그는 x86 "undefined" 정책으로 보존).
    pub fn set_zf(&mut self, z: bool) {
        self.raw &= !VFLAG_ZF;
        if z {
            self.raw |= VFLAG_ZF;
        }
    }

    /// CF 만 갱신 (TZCNT/LZCNT — ZF 는 별도). 그 외 플래그 보존.
    pub fn set_cf(&mut self, c: bool) {
        self.raw &= !VFLAG_CF;
        if c {
            self.raw |= VFLAG_CF;
        }
    }
}
