// ==============================================================================
// BTG - Canonical VM Semantics (Single Source of Truth) (Domit §6, §7, §78)
// ==============================================================================
// Pure mathematical specifications and reference implementations for all RISC
// operations, handling exact x86-64 flag edge-cases (e.g. INC/DEC CF preservation,
// shift-out CF, TZCNT/LZCNT/POPCNT/BSF/BSR flag contracts, and wide mul/div).
// Both interpreters and native handlers use this canonical model as the reference.
// ==============================================================================

use crate::vm::flags::*;

/// Flags mask constants (standard EFLAGS / RFLAGS bits).
pub const CF: u64 = 1 << 0;
pub const PF: u64 = 1 << 2;
pub const AF: u64 = 1 << 4;
pub const ZF: u64 = 1 << 6;
pub const SF: u64 = 1 << 7;
pub const OF: u64 = 1 << 11;

/// Add with full arithmetic flag updates.
#[inline]
pub fn sem_add(a: u64, b: u64, flags: &mut u64) -> u64 {
    let res = a.wrapping_add(b);
    *flags = add_flags64(a, b);
    res
}

/// Sub with full arithmetic flag updates.
#[inline]
pub fn sem_sub(a: u64, b: u64, flags: &mut u64) -> u64 {
    let res = a.wrapping_sub(b);
    *flags = sub_flags64(a, b);
    res
}

/// Inc: updates ZF, SF, OF, AF, PF but strictly preserves CF (x86 contract).
#[inline]
pub fn sem_inc(a: u64, flags: &mut u64) -> u64 {
    let res = a.wrapping_add(1);
    *flags = inc_flags64(a, *flags);
    res
}

/// Dec: updates ZF, SF, OF, AF, PF but strictly preserves CF (x86 contract).
#[inline]
pub fn sem_dec(a: u64, flags: &mut u64) -> u64 {
    let res = a.wrapping_sub(1);
    *flags = dec_flags64(a, *flags);
    res
}

/// Bitwise AND: clears CF and OF, updates ZF, SF, PF.
#[inline]
pub fn sem_and(a: u64, b: u64, flags: &mut u64) -> u64 {
    let res = a & b;
    *flags = logical_flags64(res);
    res
}

/// Bitwise OR: clears CF and OF, updates ZF, SF, PF.
#[inline]
pub fn sem_or(a: u64, b: u64, flags: &mut u64) -> u64 {
    let res = a | b;
    *flags = logical_flags64(res);
    res
}

/// Bitwise XOR: clears CF and OF, updates ZF, SF, PF.
#[inline]
pub fn sem_xor(a: u64, b: u64, flags: &mut u64) -> u64 {
    let res = a ^ b;
    *flags = logical_flags64(res);
    res
}

/// Logical Shift Left: updates CF to last bit shifted out.
#[inline]
pub fn sem_shl(a: u64, count: u32, flags: &mut u64) -> u64 {
    let c = count & 63;
    if c == 0 {
        return a;
    }
    let res = a << c;
    *flags = shift_flags64(ShiftKind::Shl, a, c, res);
    res
}

/// Logical Shift Right: updates CF to last bit shifted out.
#[inline]
pub fn sem_shr(a: u64, count: u32, flags: &mut u64) -> u64 {
    let c = count & 63;
    if c == 0 {
        return a;
    }
    let res = a >> c;
    *flags = shift_flags64(ShiftKind::Shr, a, c, res);
    res
}

/// Arithmetic Shift Right (signed): updates CF to last bit shifted out.
#[inline]
pub fn sem_sar(a: u64, count: u32, flags: &mut u64) -> u64 {
    let c = count & 63;
    if c == 0 {
        return a;
    }
    let res = ((a as i64) >> c) as u64;
    *flags = shift_flags64(ShiftKind::Sar, a, c, res);
    res
}

/// Population Count (POPCNT): ZF=1 if src==0, clears CF/OF/SF/AF/PF.
#[inline]
pub fn sem_popcnt(a: u64, flags: &mut u64) -> u64 {
    let count = a.count_ones() as u64;
    *flags = if count == 0 { ZF } else { 0 };
    count
}

/// Trailing Zero Count (TZCNT): CF=1 if src==0, ZF=1 if count==64.
#[inline]
pub fn sem_tzcnt(a: u64, flags: &mut u64) -> u64 {
    let count = a.trailing_zeros() as u64;
    let mut f = 0u64;
    if a == 0 {
        f |= CF;
    }
    if count == 64 {
        f |= ZF;
    }
    *flags = f;
    count
}

/// Leading Zero Count (LZCNT): CF=1 if src==0, ZF=1 if count==64.
#[inline]
pub fn sem_lzcnt(a: u64, flags: &mut u64) -> u64 {
    let count = a.leading_zeros() as u64;
    let mut f = 0u64;
    if a == 0 {
        f |= CF;
    }
    if count == 64 {
        f |= ZF;
    }
    *flags = f;
    count
}

/// Bit Scan Forward (BSF): ZF=1 if src==0.
#[inline]
pub fn sem_bsf(a: u64, flags: &mut u64) -> Option<u64> {
    if a == 0 {
        *flags |= ZF;
        None
    } else {
        *flags &= !ZF;
        Some(a.trailing_zeros() as u64)
    }
}

/// Bit Scan Reverse (BSR): ZF=1 if src==0.
#[inline]
pub fn sem_bsr(a: u64, flags: &mut u64) -> Option<u64> {
    if a == 0 {
        *flags |= ZF;
        None
    } else {
        *flags &= !ZF;
        Some(63 - a.leading_zeros() as u64)
    }
}

/// Byte swap 64-bit value.
#[inline]
pub fn sem_bswap(a: u64) -> u64 {
    a.swap_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sem_inc_preserves_cf() {
        let mut flags = CF;
        let res = sem_inc(10, &mut flags);
        assert_eq!(res, 11);
        assert_eq!(flags & CF, CF); // CF must be preserved
    }

    #[test]
    fn test_sem_dec_preserves_cf() {
        let mut flags = CF;
        let res = sem_dec(10, &mut flags);
        assert_eq!(res, 9);
        assert_eq!(flags & CF, CF); // CF must be preserved
    }

    #[test]
    fn test_sem_tzcnt_and_lzcnt_contracts() {
        let mut flags = 0;
        let c0 = sem_tzcnt(0, &mut flags);
        assert_eq!(c0, 64);
        assert_eq!(flags & (CF | ZF), CF | ZF);

        let mut flags = 0;
        let c1 = sem_lzcnt(0x8000_0000_0000_0000, &mut flags);
        assert_eq!(c1, 0);
        assert_eq!(flags, 0);
    }
}
