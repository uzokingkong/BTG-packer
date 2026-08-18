// ==============================================================================
// BTG - Commercial-Grade VM: Micro-Flag Simulation & Evaluation
// ==============================================================================
// RISC 留덉씠?щ줈 ?곗궛 ?섑뻾 ??諛쒖깮?섎뒗 x86 RFLAGS ?곹깭(CF, ZF, SF, OF)瑜?
// 鍮꾪듃 ?섏??먯꽌 湲고샇??Symbolic) 諛??고??꾩쑝濡??뺣? 怨꾩궛?쒕떎.
// ==============================================================================

pub const VFLAG_CF: u64 = 1 << 0;
pub const VFLAG_PF: u64 = 1 << 2;
pub const VFLAG_AF: u64 = 1 << 4;
pub const VFLAG_ZF: u64 = 1 << 6;
pub const VFLAG_SF: u64 = 1 << 7;
pub const VFLAG_DF: u64 = 1 << 10; // direction (string ops; not a status flag)
pub const VFLAG_OF: u64 = 1 << 11;

/// Status flags mask (arithmetic never touches DF ??bit 10).
pub const VFLAG_STATUS_MASK: u64 = VFLAG_CF | VFLAG_PF | VFLAG_AF | VFLAG_ZF | VFLAG_SF | VFLAG_OF;

/// 폭(1/2/4/8 바이트)에 따른 비트 마스크.
pub fn mask_for_width(width: u8) -> u64 {
    match width {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => u64::MAX,
    }
}

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

    /// ?⑤━???뚮옒洹?(PF, bit 2) ??low 8鍮꾪듃??1??媛쒖닔媛 吏앹닔硫?1.
    /// 李몄“ ?쒕??덉씠??eval_state)媛 ?곗닠/?쇰━ ?곗궛 ??`set_parity`濡?媛깆떊?쒕떎.
    #[inline]
    pub fn pf(&self) -> bool {
        (self.raw & VFLAG_PF) != 0
    }

    /// 寃곌낵 low 8鍮꾪듃???⑤━?곕? 怨꾩궛??PF 鍮꾪듃瑜??ㅼ젙/?댁젣?쒕떎.
    pub fn set_parity(&mut self, res: u64) {
        let ones = (res as u8).count_ones();
        if ones % 2 == 0 {
            self.raw |= VFLAG_PF;
        } else {
            self.raw &= !VFLAG_PF;
        }
    }

    /// 64鍮꾪듃 ?㏃뀍(a + b + cin)?????RFLAGS ?뚮옒洹?媛깆떊
    /// (P0-1: AF(bit3 carry) ?ы븿 ??x86 ?뺥솗. CF=carry out, OF=signed overflow.)
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
        if ((a ^ res) & (b ^ res) & 0x8000_0000_0000_0000) != 0 {
            flags |= VFLAG_OF;
        }
        // AF = carry from bit 3 (x86: ((a^b^res) & 0x10) != 0)
        if ((a ^ b ^ res) & 0x10) != 0 {
            flags |= VFLAG_AF;
        }
        // PF = even parity of low byte
        if (res as u8).count_ones() % 2 == 0 {
            flags |= VFLAG_PF;
        }

        self.raw = (self.raw & !(VFLAG_CF | VFLAG_PF | VFLAG_AF | VFLAG_ZF | VFLAG_SF | VFLAG_OF)) | flags;
        (res, cout)
    }

    /// x86 ??퀎(1/2/4/8) SUB ??CF=borrow(a<b), OF/AF????寃쎄퀎 湲곗?.
    /// `vm::flags`(canonical)???꾩엫??bytecode/?ㅼ씠?곕툕? ?숈씪 ?섎?濡좎쓣 蹂댁옣?쒕떎.
    /// x86 폭별(1/2/4/8) ADD — CF=carry out, OF/AF는 폭 경계 기준.
    pub fn update_add(&mut self, a: u64, b: u64, width: u8) -> u64 {
        let f = match width {
            1 => crate::vm::flags::add_flags_width(a, b, 8),
            2 => crate::vm::flags::add_flags_width(a, b, 16),
            4 => crate::vm::flags::add_flags_width(a, b, 32),
            _ => crate::vm::flags::add_flags64(a, b),
        };
        self.set_status(f);
        let mask = mask_for_width(width);
        a.wrapping_add(b) & mask
    }

    pub fn update_sub(&mut self, a: u64, b: u64, width: u8) -> u64 {
        let f = match width {
            1 => crate::vm::flags::sub_flags_width(a, b, 8),
            2 => crate::vm::flags::sub_flags_width(a, b, 16),
            4 => crate::vm::flags::sub_flags_width(a, b, 32),
            _ => crate::vm::flags::sub_flags64(a, b),
        };
        self.set_status(f);
        let mask = mask_for_width(width);
        a.wrapping_sub(b) & mask
    }

    /// x86 ??퀎(1/2/4/8) INC ??CF 蹂댁〈.
    pub fn update_inc(&mut self, a: u64, width: u8) -> u64 {
        let f = match width {
            1 => crate::vm::flags::incdec_flags_width(a, 8, true, self.raw),
            2 => crate::vm::flags::incdec_flags_width(a, 16, true, self.raw),
            4 => crate::vm::flags::incdec_flags_width(a, 32, true, self.raw),
            _ => crate::vm::flags::inc_flags64(a, self.raw),
        };
        self.set_status(f);
        let mask = mask_for_width(width);
        a.wrapping_add(1) & mask
    }

    /// x86 ??퀎(1/2/4/8) DEC ??CF 蹂댁〈.
    pub fn update_dec(&mut self, a: u64, width: u8) -> u64 {
        let f = match width {
            1 => crate::vm::flags::incdec_flags_width(a, 8, false, self.raw),
            2 => crate::vm::flags::incdec_flags_width(a, 16, false, self.raw),
            4 => crate::vm::flags::incdec_flags_width(a, 32, false, self.raw),
            _ => crate::vm::flags::dec_flags64(a, self.raw),
        };
        self.set_status(f);
        let mask = mask_for_width(width);
        a.wrapping_sub(1) & mask
    }

    /// status ?뚮옒洹?CF|PF|AF|ZF|SF|OF)留?援먯껜 (DF 蹂댁〈).
    fn set_status(&mut self, f: u64) {
        self.raw = (self.raw & !VFLAG_STATUS_MASK) | (f & VFLAG_STATUS_MASK);
    }

    /// 鍮꾪듃 ?⑥쐞 ?쇰━ ?곗궛(NOR, AND, OR, XOR) ???뚮옒洹?媛깆떊 (CF=0, OF=0, ZF/SF 媛깆떊)
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
        self.raw = (self.raw & !(VFLAG_CF | VFLAG_PF | VFLAG_OF | VFLAG_ZF | VFLAG_SF | VFLAG_AF)) | flags;
    }

    /// MUL/IMUL쨌DIV/IDIV ??CF/OF 留?媛깆떊 (?ㅻⅨ ?뚮옒洹몃뒗 蹂댁〈 ??x86 "undefined" ?뺤콉).
    pub fn set_cf_of(&mut self, both: bool) {
        self.raw &= !(VFLAG_CF | VFLAG_OF);
        if both {
            self.raw |= VFLAG_CF | VFLAG_OF;
        }
    }

    /// ZF 留?媛깆떊 (CMPXCHG ???ㅻⅨ ?뚮옒洹몃뒗 x86 "undefined" ?뺤콉?쇰줈 蹂댁〈).
    pub fn set_zf(&mut self, z: bool) {
        self.raw &= !VFLAG_ZF;
        if z {
            self.raw |= VFLAG_ZF;
        }
    }

    /// CF 留?媛깆떊 (TZCNT/LZCNT ??ZF ??蹂꾨룄). 洹????뚮옒洹?蹂댁〈.
    pub fn set_cf(&mut self, c: bool) {
        self.raw &= !VFLAG_CF;
        if c {
            self.raw |= VFLAG_CF;
        }
    }
}
