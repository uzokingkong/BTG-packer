// ==============================================================================
// BTG - VM Embedding Hardening & Metadata Concealment (Domit §21, §82)
// ==============================================================================
// Hardens embedded VM artifacts against static PE analysis:
// 1. Trap handlers for unused opcode slots (ud2) instead of jumping back to entry.
// 2. Region descriptor encryption using master domain key.
// 3. Handler table XOR concealment with per-opcode derived keys.
// ==============================================================================

use iced_x86::{Code, Instruction};

/// C1 / C4 constants for per-opcode derived key calculation.
const C1: u64 = 0x9E37_79B9_7F4A_7C15;
const C4: u64 = 0xD1B5_4A32_D192_ED03;

/// Per-opcode derived key: `(op * C1) ^ (op << 17) ^ C4 ^ master`.
#[inline]
pub fn per_op_key(master: u64, op: u8) -> u64 {
    (op as u64).wrapping_mul(C1) ^ ((op as u64) << 17) ^ C4 ^ master
}

/// Compute a 64-bit integrity hash across the handler table.
pub fn table_checksum(table: &[u64]) -> u64 {
    let mut h: u64 = 0x811C_9DC5;
    for &v in table {
        h = h.wrapping_add(v).wrapping_mul(0x0100_0000_01B3);
        h ^= h >> 33;
        h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    }
    h
}

/// Emit native machine code for a trap handler (ud2: 0x0F, 0x0B) to catch illegal opcode dispatch.
pub fn emit_trap_handler() -> Vec<u8> {
    vec![0x0F, 0x0B]
}

/// Conceal a 256-entry handler table in-place using per-opcode derived keys.
pub fn conceal_handler_table(table: &mut [u64; 256], master_key: u64) {
    for (op, entry) in table.iter_mut().enumerate() {
        *entry ^= per_op_key(master_key, op as u8);
    }
}

/// Encrypt a region descriptor byte slice using the master domain key.
pub fn encrypt_region_descriptor_bytes(bytes: &mut [u8], domain_key: u64) {
    let key_bytes = domain_key.to_le_bytes();
    for (i, b) in bytes.iter_mut().enumerate() {
        *b ^= key_bytes[i % 8].wrapping_add(i as u8);
    }
}

/// Decrypt a region descriptor byte slice using the master domain key.
pub fn decrypt_region_descriptor_bytes(bytes: &mut [u8], domain_key: u64) {
    encrypt_region_descriptor_bytes(bytes, domain_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trap_handler_emits_ud2() {
        let trap = emit_trap_handler();
        assert!(!trap.is_empty());
        assert_eq!(&trap[..2], &[0x0F, 0x0B]); // ud2 opcode
    }

    #[test]
    fn test_conceal_handler_table_roundtrip() {
        let mut table = [0x140001000u64; 256];
        let master = 0xFEEDBEEF_12345678;
        let original = table;

        conceal_handler_table(&mut table, master);
        assert_ne!(table, original);

        conceal_handler_table(&mut table, master); // XOR involution
        assert_eq!(table, original);
    }

    #[test]
    fn test_region_descriptor_encryption_roundtrip() {
        let mut data = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
        let original = data.clone();
        let key = 0xA1B2_C3D4_E5F6_0718;

        encrypt_region_descriptor_bytes(&mut data, key);
        assert_ne!(data, original);

        decrypt_region_descriptor_bytes(&mut data, key);
        assert_eq!(data, original);
    }
}
