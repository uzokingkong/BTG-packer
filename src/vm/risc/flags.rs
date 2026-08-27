// ==============================================================================
// BTG - Commercial-Grade VM: Micro-Flag Simulation & Evaluation
// ==============================================================================
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

    #[inline]
    pub fn pf(&self) -> bool {
        (self.raw & VFLAG_PF) != 0
    }

    pub fn set_parity(&mut self, res: u64) {
        let ones = (res as u8).count_ones();
        if ones % 2 == 0 {
            self.raw |= VFLAG_PF;
        } else {
            self.raw &= !VFLAG_PF;
        }
    }

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

        self.raw =
            (self.raw & !(VFLAG_CF | VFLAG_PF | VFLAG_AF | VFLAG_ZF | VFLAG_SF | VFLAG_OF)) | flags;
        (res, cout)
    }

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

    /// x86 ADC — `a + b + CF`, with all status flags evaluated at `width`.
    pub fn update_adc(&mut self, a: u64, b: u64, width: u8) -> u64 {
        let mask = mask_for_width(width);
        let sign = 1u64 << (width as u32 * 8 - 1);
        let a = a & mask;
        let b = b & mask;
        let cin = u64::from(self.cf());
        let wide = a as u128 + b as u128 + cin as u128;
        let res = wide as u64 & mask;
        let mut f = 0u64;
        if wide > mask as u128 {
            f |= VFLAG_CF;
        }
        if res == 0 {
            f |= VFLAG_ZF;
        }
        if res & sign != 0 {
            f |= VFLAG_SF;
        }
        if (!(a ^ b) & (a ^ res) & sign) != 0 {
            f |= VFLAG_OF;
        }
        if ((a ^ b ^ res) & 0x10) != 0 {
            f |= VFLAG_AF;
        }
        if (res as u8).count_ones() % 2 == 0 {
            f |= VFLAG_PF;
        }
        self.set_status(f);
        res
    }

    /// x86 SBB — `a - b - CF`, with CF representing unsigned borrow-out.
    pub fn update_sbb(&mut self, a: u64, b: u64, width: u8) -> u64 {
        let mask = mask_for_width(width);
        let sign = 1u64 << (width as u32 * 8 - 1);
        let a = a & mask;
        let b = b & mask;
        let bin = u64::from(self.cf());
        let subtrahend = b as u128 + bin as u128;
        let res = a.wrapping_sub(b).wrapping_sub(bin) & mask;
        let mut f = 0u64;
        if (a as u128) < subtrahend {
            f |= VFLAG_CF;
        }
        if res == 0 {
            f |= VFLAG_ZF;
        }
        if res & sign != 0 {
            f |= VFLAG_SF;
        }
        if ((a ^ b) & (a ^ res) & sign) != 0 {
            f |= VFLAG_OF;
        }
        if ((a ^ b ^ res) & 0x10) != 0 {
            f |= VFLAG_AF;
        }
        if (res as u8).count_ones() % 2 == 0 {
            f |= VFLAG_PF;
        }
        self.set_status(f);
        res
    }

    /// x86 ROL. Only CF is defined for non-zero counts; OF is defined for an
    /// effective count of one. Undefined OF for larger counts is preserved by
    /// the reference policy so it cannot introduce a synthetic branch signal.
    pub fn update_rol(&mut self, value: u64, count: u64, width: u8) -> u64 {
        let bits = width as u32 * 8;
        let masked = if width == 8 { count & 63 } else { count & 31 };
        let effective = (masked % bits as u64) as u32;
        let mask = mask_for_width(width);
        let value = value & mask;
        if effective == 0 {
            return value;
        }
        let res = ((value << effective) | (value >> (bits - effective))) & mask;
        self.set_cf((res & 1) != 0);
        if effective == 1 {
            let of = ((res >> (bits - 1)) ^ res) & 1 != 0;
            self.raw &= !VFLAG_OF;
            if of {
                self.raw |= VFLAG_OF;
            }
        }
        res
    }

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

    fn set_status(&mut self, f: u64) {
        self.raw = (self.raw & !VFLAG_STATUS_MASK) | (f & VFLAG_STATUS_MASK);
    }

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
        self.raw =
            (self.raw & !(VFLAG_CF | VFLAG_PF | VFLAG_OF | VFLAG_ZF | VFLAG_SF | VFLAG_AF)) | flags;
    }

    pub fn set_cf_of(&mut self, both: bool) {
        self.raw &= !(VFLAG_CF | VFLAG_OF);
        if both {
            self.raw |= VFLAG_CF | VFLAG_OF;
        }
    }

    pub fn set_zf(&mut self, z: bool) {
        self.raw &= !VFLAG_ZF;
        if z {
            self.raw |= VFLAG_ZF;
        }
    }

    pub fn set_cf(&mut self, c: bool) {
        self.raw &= !VFLAG_CF;
        if c {
            self.raw |= VFLAG_CF;
        }
    }
}

#[cfg(test)]
mod adc_sbb_tests {
    use super::*;

    #[test]
    fn adc_width_boundaries_and_flags() {
        let mut f = VirtualFlags::new(VFLAG_CF | VFLAG_DF);
        assert_eq!(f.update_adc(0xFF, 0, 1), 0);
        assert!(f.cf());
        assert!(f.zf());
        assert_eq!(f.raw & VFLAG_DF, VFLAG_DF, "ADC must preserve DF");

        let mut f = VirtualFlags::default();
        assert_eq!(f.update_adc(0x7FFF_FFFF, 0, 4), 0x7FFF_FFFF);
        assert!(!f.of());
        f.raw = VFLAG_CF;
        assert_eq!(f.update_adc(0x7FFF_FFFF, 0, 4), 0x8000_0000);
        assert!(f.of());
    }

    #[test]
    fn sbb_width_boundaries_and_flags() {
        let mut f = VirtualFlags::new(VFLAG_CF);
        assert_eq!(f.update_sbb(0, 0, 1), 0xFF);
        assert!(f.cf());
        assert!(f.sf());

        let mut f = VirtualFlags::new(VFLAG_CF);
        assert_eq!(f.update_sbb(0x8000_0000, 0, 4), 0x7FFF_FFFF);
        assert!(!f.cf());
        assert!(f.of());
    }
}
