//! Certified semantics for the legacy x86 high-byte registers.
//!
//! AH, CH, DH, and BH are aliases of bits 8..15 of their 64-bit parent GPR.
//! They cannot be encoded by an instruction carrying a REX prefix.  Keeping
//! these rules in a small, side-effect-free module lets the commercial lift
//! gate require an explicit certificate instead of relying on ad-hoc shifts.

use iced_x86::{Instruction, Register};

const HIGH_BYTE_MASK: u64 = 0x0000_0000_0000_ff00;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyHighByte {
    Ah,
    Ch,
    Dh,
    Bh,
}

impl LegacyHighByte {
    pub const ALL: [Self; 4] = [Self::Ah, Self::Ch, Self::Dh, Self::Bh];

    pub const fn from_register(register: Register) -> Option<Self> {
        match register {
            Register::AH => Some(Self::Ah),
            Register::CH => Some(Self::Ch),
            Register::DH => Some(Self::Dh),
            Register::BH => Some(Self::Bh),
            _ => None,
        }
    }

    pub const fn register(self) -> Register {
        match self {
            Self::Ah => Register::AH,
            Self::Ch => Register::CH,
            Self::Dh => Register::DH,
            Self::Bh => Register::BH,
        }
    }

    /// Parent index in the VM's architectural GPR array (RAX..R15).
    pub const fn parent_vreg(self) -> usize {
        match self {
            Self::Ah => 0,
            Self::Ch => 1,
            Self::Dh => 2,
            Self::Bh => 3,
        }
    }

    pub const fn read_parent(self, parent: u64) -> u8 {
        ((parent >> 8) & 0xff) as u8
    }

    /// Replaces bits 8..15 while preserving the other 56 bits exactly.
    /// This alias operation does not read or modify flags.
    pub const fn write_parent(self, parent: u64, value: u8) -> u64 {
        (parent & !HIGH_BYTE_MASK) | ((value as u64) << 8)
    }

    pub fn read_register(self, regs: &[u64; 16]) -> u8 {
        self.read_parent(regs[self.parent_vreg()])
    }

    /// Writes the alias in-place. Flags are deliberately absent from the API,
    /// making the flag-preservation contract structural rather than advisory.
    pub fn write_register(self, regs: &mut [u64; 16], value: u8) {
        let parent = &mut regs[self.parent_vreg()];
        *parent = self.write_parent(*parent, value);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighByteInstructionCertification {
    pub aliases: Vec<LegacyHighByte>,
    pub upper_56_bits_preserved: bool,
    pub flags_preserved: bool,
    pub rex_prefix_absent: bool,
}

impl HighByteInstructionCertification {
    pub fn is_certified(&self) -> bool {
        !self.aliases.is_empty()
            && self.upper_56_bits_preserved
            && self.flags_preserved
            && self.rex_prefix_absent
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighByteCertificationError {
    MissingOriginalEncoding,
    RexPrefixWithLegacyHighByte,
}

/// Certifies every explicit AH/BH/CH/DH operand in a decoded instruction.
///
/// `encoded` must contain the original instruction bytes. Requiring them makes
/// the no-REX property independently checkable before a commercial gate is
/// removed.
pub fn certify_high_byte_instruction(
    instruction: &Instruction,
    encoded: &[u8],
) -> Result<Option<HighByteInstructionCertification>, HighByteCertificationError> {
    let mut aliases = Vec::new();
    for operand in 0..instruction.op_count() {
        if let Some(alias) = LegacyHighByte::from_register(instruction.op_register(operand)) {
            if !aliases.contains(&alias) {
                aliases.push(alias);
            }
        }
    }

    if aliases.is_empty() {
        return Ok(None);
    }
    if encoded.is_empty() {
        return Err(HighByteCertificationError::MissingOriginalEncoding);
    }
    if has_rex_prefix(encoded) {
        return Err(HighByteCertificationError::RexPrefixWithLegacyHighByte);
    }

    Ok(Some(HighByteInstructionCertification {
        aliases,
        upper_56_bits_preserved: true,
        flags_preserved: true,
        rex_prefix_absent: true,
    }))
}

/// Detects a REX prefix after the legacy prefix group in a 64-bit instruction.
pub fn has_rex_prefix(encoded: &[u8]) -> bool {
    let mut offset = 0;
    while let Some(byte) = encoded.get(offset).copied() {
        if matches!(
            byte,
            0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67
        ) {
            offset += 1;
        } else {
            break;
        }
    }
    encoded
        .get(offset)
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
}
