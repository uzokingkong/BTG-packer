// ==============================================================================
// BTG VM - Operand Flattening, Bit-Packing & Immediate Chaining
// ==============================================================================
// Destroys linear `[Opcode][RegA][RegB][Imm64]` byte structures.
// Employs bit-matrix transposition to interleave register indices across bitfields
// and chains 64-bit immediate constants with execution history and VIP.
// ==============================================================================

/// Bit-matrix transposition codec for packing/unpacking operand register pairs.
pub struct BitPackedOperandCodec;

impl BitPackedOperandCodec {
    /// Packs two 8-bit register indices into an interleaved 16-bit word using seed permutations.
    pub fn pack_reg_pair(reg_a: u8, reg_b: u8, seed: u64) -> u16 {
        let rot = (seed & 7) as u32;
        let a = reg_a as u16;
        let b = reg_b as u16;

        let a_lo = a & 0x0F;
        let a_hi = (a >> 4) & 0x0F;
        let b_lo = b & 0x0F;
        let b_hi = (b >> 4) & 0x0F;

        // Interleave nibbles: [a_hi][b_hi][a_lo][b_lo]
        let raw = (a_hi << 12) | (b_hi << 8) | (a_lo << 4) | b_lo;
        raw.rotate_left(rot)
    }

    /// Unpacks an interleaved 16-bit word back into two 8-bit register indices.
    pub fn unpack_reg_pair(packed: u16, seed: u64) -> (u8, u8) {
        let rot = (seed & 7) as u32;
        let raw = packed.rotate_right(rot);

        let a_hi = (raw >> 12) & 0x0F;
        let b_hi = (raw >> 8) & 0x0F;
        let a_lo = (raw >> 4) & 0x0F;
        let b_lo = raw & 0x0F;

        let reg_a = ((a_hi << 4) | a_lo) as u8;
        let reg_b = ((b_hi << 4) | b_lo) as u8;

        (reg_a, reg_b)
    }
}

/// Dynamic immediate chaining codec linking constants with VIP and execution state.
pub struct ChainedImmediateCodec;

impl ChainedImmediateCodec {
    /// Encodes a 64-bit immediate constant chained with the previous ALU result and VIP.
    pub fn encode_immediate(imm: u64, prev_res: u64, vip: u64) -> u64 {
        let vip_mask =
            vip.rotate_left(29).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x517C_C1B7_2722_0A95;
        imm ^ prev_res ^ vip_mask
    }

    /// Decodes a 64-bit stored immediate back to its original value at runtime.
    pub fn decode_immediate(stored: u64, prev_res: u64, vip: u64) -> u64 {
        let vip_mask =
            vip.rotate_left(29).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x517C_C1B7_2722_0A95;
        stored ^ prev_res ^ vip_mask
    }
}

/// Opaque Bytecode Junk: Generates dead junk byte streams seamlessly skipped by the decoder.
pub struct OpaqueBytecodeJunk;

impl OpaqueBytecodeJunk {
    /// Generates `count` dead junk bytes based on seed and position.
    pub fn generate_junk(seed: u64, count: usize) -> Vec<u8> {
        let mut junk = Vec::with_capacity(count);
        let mut st = seed ^ 0xFEED_FACE_CAFE_BEEF;

        for _ in 0..count {
            st = st
                .wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0x1405_7B7E_F767_814F);
            junk.push((st >> 32) as u8);
        }

        junk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_packed_operand_roundtrip_all_pairs() {
        let seed = 0x1234_5678_9ABC_DEF0;

        for reg_a in [0u8, 1, 7, 15, 63, 128, 255] {
            for reg_b in [0u8, 2, 8, 16, 64, 129, 255] {
                let packed = BitPackedOperandCodec::pack_reg_pair(reg_a, reg_b, seed);
                let (unpacked_a, unpacked_b) = BitPackedOperandCodec::unpack_reg_pair(packed, seed);

                assert_eq!(
                    unpacked_a, reg_a,
                    "Reg A roundtrip failed for ({}, {})",
                    reg_a, reg_b
                );
                assert_eq!(
                    unpacked_b, reg_b,
                    "Reg B roundtrip failed for ({}, {})",
                    reg_a, reg_b
                );
            }
        }
    }

    #[test]
    fn test_chained_immediate_roundtrip() {
        let original_imm = 0xDEAD_BEEF_CAFE_BABE;
        let prev_res = 0x1122_3344_5566_7788;
        let vip = 0x1000;

        let encoded = ChainedImmediateCodec::encode_immediate(original_imm, prev_res, vip);
        assert_ne!(encoded, original_imm, "Encoded immediate must be masked");

        let decoded = ChainedImmediateCodec::decode_immediate(encoded, prev_res, vip);
        assert_eq!(
            decoded, original_imm,
            "Decoded immediate must match original"
        );
    }

    #[test]
    fn test_opaque_bytecode_junk_determinism() {
        let j1 = OpaqueBytecodeJunk::generate_junk(0x12345, 16);
        let j2 = OpaqueBytecodeJunk::generate_junk(0x12345, 16);
        let j3 = OpaqueBytecodeJunk::generate_junk(0x67890, 16);

        assert_eq!(
            j1, j2,
            "Junk generation must be deterministic for same seed"
        );
        assert_ne!(j1, j3, "Different seeds must generate distinct junk");
    }
}
