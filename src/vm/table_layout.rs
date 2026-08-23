// ==============================================================================
// BTG - Polymorphic Table Layout & Offset Randomization (Domit §23, §82)
// ==============================================================================
// Breaks fixed-offset table signature (+0x000, +0x800, +0x900, +0xA00, +0xB00).
// Derives randomized, jittered table offsets and junk padding from the build seed,
// preventing static reverse engineering from relying on hardcoded table anchors.
// ==============================================================================

/// Seed-dependent layout for VM dispatcher metadata tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableLayout {
    pub handler_table_off: usize,
    pub operand_offs_off: usize,
    pub operand_flags_off: usize,
    pub cond_codes_off: usize,
    pub branch_map_off: usize,
    pub total_size: usize,
}

impl TableLayout {
    /// Generates a jittered table layout with pseudo-random inter-table padding
    /// based on the seed.
    pub fn from_seed(seed: u64) -> Self {
        let hash = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ seed.rotate_left(29);
        let handler_table_off = 0;
        let mut cursor = 2048;

        // Jitter 1: 16 ~ 143 bytes padding
        let pad1 = 16 + ((hash >> 8) & 0x7F) as usize;
        cursor += pad1;
        let operand_offs_off = cursor; // 256 x u16
        cursor += 512;

        // Jitter 2: 16 ~ 143 bytes padding
        let pad2 = 16 + ((hash >> 20) & 0x7F) as usize;
        cursor += pad2;
        let operand_flags_off = cursor; // 256 bytes
        cursor += 256;

        // Jitter 3: 16 ~ 143 bytes padding
        let pad3 = 16 + ((hash >> 32) & 0x7F) as usize;
        cursor += pad3;
        let cond_codes_off = cursor; // 256 bytes
        cursor += 256;

        // Jitter 4: 16 ~ 143 bytes padding
        let pad4 = 16 + ((hash >> 44) & 0x7F) as usize;
        cursor += pad4;
        let branch_map_off = cursor;

        // Total layout size padded to 16 bytes
        let total_size = (cursor + 1024 + 15) & !15;

        Self {
            handler_table_off,
            operand_offs_off,
            operand_flags_off,
            cond_codes_off,
            branch_map_off,
            total_size,
        }
    }

    /// Legacy fixed-offset layout for backward compatibility with unhardened paths.
    pub fn legacy() -> Self {
        Self {
            handler_table_off: 0x000,
            operand_offs_off: 0x800,
            operand_flags_off: 0xA00,
            cond_codes_off: 0xB00,
            branch_map_off: 0xC00,
            total_size: 0x1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_layout_variability_with_seed() {
        let l1 = TableLayout::from_seed(0x1122_3344_5566_7788);
        let l2 = TableLayout::from_seed(0x99AA_BBCC_DDEE_FF00);

        assert_ne!(l1.operand_offs_off, l2.operand_offs_off);
        assert_ne!(l1.cond_codes_off, l2.cond_codes_off);
        assert_ne!(l1.branch_map_off, l2.branch_map_off);

        // Verification of no overlaps
        assert!(l1.handler_table_off + 2048 <= l1.operand_offs_off);
        assert!(l1.operand_offs_off + 512 <= l1.operand_flags_off);
        assert!(l1.operand_flags_off + 256 <= l1.cond_codes_off);
        assert!(l1.cond_codes_off + 256 <= l1.branch_map_off);
    }
}
