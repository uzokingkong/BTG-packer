//! Seed-derived state ABI for the production threaded VM.
//!
//! All offsets are expressed relative to the state-base role.  Keeping this in
//! one value lets the interpreter, native code generator, bridge and unwind
//! metadata consume the same contract instead of duplicating constants.

use anyhow::{anyhow, Result};

const SLOT_SIZE: i32 = 8;
const BANK_SLOTS: usize = 16;
const BANK1_BASE: i32 = 0x400;
pub const SPLIT_STATE_SIZE: usize = 0x860;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmRuntimeLayout {
    pub vregs: [i32; 16],
    pub temps: [i32; 8],
    pub flags: i32,
    pub vsp: i32,
    /// Packed DEC_DST/SRC1/SRC2/COND bytes.
    pub decode_operands: i32,
    pub imm1: i32,
    pub imm2: i32,
    pub carry_in: i32,
    pub fp_return: i32,
    pub xmm: i32,
    pub xmm_slots: usize,
    pub total_size: usize,
}

impl VmRuntimeLayout {
    pub fn legacy() -> Self {
        let mut vregs = [0; 16];
        let mut temps = [0; 8];
        for (i, off) in vregs.iter_mut().enumerate() {
            *off = (i * 8) as i32;
        }
        for (i, off) in temps.iter_mut().enumerate() {
            *off = 0x80 + (i * 8) as i32;
        }
        Self {
            vregs,
            temps,
            flags: 0xC0,
            vsp: 0xC8,
            decode_operands: 0xD0,
            imm1: 0xD8,
            imm2: 0xE0,
            carry_in: 0xE8,
            fp_return: 0xF0,
            xmm: 0x100,
            xmm_slots: 6,
            total_size: 0x160,
        }
    }

    pub fn from_seed(seed: u64) -> Self {
        let mut bank0 = [0usize; BANK_SLOTS];
        let mut bank1 = [0usize; BANK_SLOTS];
        for i in 0..BANK_SLOTS {
            bank0[i] = i;
            bank1[i] = i;
        }
        let mut state = seed ^ 0xD1B5_4A32_D192_ED03;
        for bank in [&mut bank0, &mut bank1] {
            for i in (1..BANK_SLOTS).rev() {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
                bank.swap(i, (state as usize) % (i + 1));
            }
        }
        let off0 = |n: usize| (bank0[n] as i32) * SLOT_SIZE;
        let off1 = |n: usize| BANK1_BASE + (bank1[n] as i32) * SLOT_SIZE;
        let mut vregs = [0; 16];
        let mut temps = [0; 8];
        for i in 0..8 {
            vregs[i] = off0(i);
            vregs[8 + i] = off1(i);
        }
        for i in 0..4 {
            temps[i] = off0(8 + i);
            temps[4 + i] = off1(8 + i);
        }
        let layout = Self {
            vregs,
            temps,
            flags: off1(12),
            vsp: off0(12),
            decode_operands: off1(13),
            imm1: off0(13),
            imm2: off1(14),
            carry_in: off0(14),
            fp_return: off1(15),
            xmm: 0x800,
            xmm_slots: 6,
            total_size: SPLIT_STATE_SIZE,
        };
        debug_assert!(layout.validate().is_ok());
        layout
    }

    pub fn validate(&self) -> Result<()> {
        let mut offsets = Vec::with_capacity(31);
        offsets.extend(self.vregs);
        offsets.extend(self.temps);
        offsets.extend([
            self.flags,
            self.vsp,
            self.decode_operands,
            self.imm1,
            self.imm2,
            self.carry_in,
            self.fp_return,
        ]);
        offsets.sort_unstable();
        offsets.dedup();
        if offsets.len() != 31 {
            return Err(anyhow!("VM runtime layout contains overlapping core slots"));
        }
        if offsets.iter().any(|off| {
            *off < 0
                || *off % SLOT_SIZE != 0
                || (*off as usize).saturating_add(SLOT_SIZE as usize) > self.total_size
                || *off >= self.xmm
        }) {
            return Err(anyhow!("VM runtime layout contains an invalid core offset"));
        }
        let xmm_end = self.xmm as usize + self.xmm_slots * 16;
        if self.xmm < 0 || self.xmm as usize % 16 != 0 || xmm_end > self.total_size {
            return Err(anyhow!("VM runtime XMM area is outside the state buffer"));
        }
        if self.total_size > u16::MAX as usize {
            return Err(anyhow!(
                "VM runtime layout exceeds the u16 operand-offset ABI"
            ));
        }
        Ok(())
    }

    pub fn decoded_byte(&self, index: i32) -> i32 {
        debug_assert!((0..4).contains(&index));
        self.decode_operands + index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_layouts_are_valid_and_diverse() {
        let a = VmRuntimeLayout::from_seed(1);
        let b = VmRuntimeLayout::from_seed(2);
        a.validate().unwrap();
        b.validate().unwrap();
        assert_ne!(a, b);
        assert_ne!(a.vregs, VmRuntimeLayout::legacy().vregs);
        assert!(a.vregs.iter().any(|off| *off < BANK1_BASE));
        assert!(a.vregs.iter().any(|off| *off >= BANK1_BASE));
        assert!(a.flags >= BANK1_BASE);
    }

    #[test]
    fn layout_rejects_overlap() {
        let mut l = VmRuntimeLayout::legacy();
        l.flags = l.vregs[0];
        assert!(l.validate().is_err());
    }
}
