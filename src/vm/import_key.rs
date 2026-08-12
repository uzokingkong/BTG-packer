// ==============================================================================
// BTG v3 - Virtualization Target #2: import-name MBA key derivation
// ==============================================================================
// (v14) Two distinct routines are now virtualized by the composite VM:
//   1) RC4 KSA        (vm/ksa.rs)      — boot-stub RC4 key schedule
//   2) import MBA key (this file)     — per-entry import-name XOR key
//        key = ((master ^ idx) + 2*(master & idx)) ^ c        (level-2 MBA)
// The bytecode below computes the same value as MbaGenerator::compute_key(m,c,idx,2)
// but executes through the VM handlers, so a static x86 disassembly of the
// boot stub no longer shows the key derivation as plain inline arithmetic.
// ==============================================================================


use crate::vm::bytecode::{
    OP_ADD_R_R, OP_AND_R_R, OP_XOR_R_IMM32, OP_XOR_R_R, BytecodeBuilder,
};

/// Reference implementation (pure Rust) — the value the VM bytecode must produce.
pub fn reference_import_key(master: u32, idx: u32, c: u32) -> u32 {
    (master ^ idx).wrapping_add((master & idx).wrapping_mul(2)) ^ c
}

/// Build VM bytecode for: key = ((m ^ idx) + 2*(m & idx)) ^ c.
/// Virtual registers: v0 = idx (input), v1 = key (output), v2 = temp.
pub fn build_import_key_bytecode(master: u32, c: u32) -> Vec<u8> {
    let mut b = BytecodeBuilder::new();
    // v1 = master
    b.mov_r_imm32(1, master);
    // v1 = master ^ idx
    b.binop_r_r(OP_XOR_R_R, 1, 0);
    // v2 = master
    b.mov_r_imm32(2, master);
    // v2 = master & idx
    b.binop_r_r(OP_AND_R_R, 2, 0);
    // v2 = 2*(master & idx)
    b.binop_r_r(OP_ADD_R_R, 2, 2);
    // v1 = (master ^ idx) + 2*(master & idx)
    b.binop_r_r(OP_ADD_R_R, 1, 2);
    // v1 ^= c
    b.binop_r_imm32(OP_XOR_R_IMM32, 1, c);
    b.halt();
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::interp;
    use crate::mba::MbaGenerator;

    #[test]
    fn import_key_matches_mba() {
        let (m, c) = (0xDEADBEEFu32, 0x9E37_79B9u32);
        for idx in [0u32, 1, 3, 7, 0x1234_5678, 0xFFFF_FFFF] {
            assert_eq!(reference_import_key(m, idx, c), MbaGenerator::compute_key(m, idx, c, 2));
        }
    }

    #[test]
    fn import_key_bytecode_interpreter() {
        let (m, c) = (0xA5A5_A5A5u32, 0x9E37_79B9u32);
        let bc = build_import_key_bytecode(m, c);
        let mut state = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x100];
        for idx in [0u32, 1, 42, 0xDEAD_BEEF] {
            state[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8]
                .copy_from_slice(&(idx as u64).to_le_bytes());
            state[interp::STATE_VREGS + 1 * 8..interp::STATE_VREGS + 2 * 8].fill(0);
            interp::interpret(&mut state, &mut mem, &bc).unwrap();
            let got = u64::from_le_bytes(
                state[interp::STATE_VREGS + 1 * 8..interp::STATE_VREGS + 2 * 8]
                    .try_into()
                    .unwrap(),
            ) as u32;
            assert_eq!(got, reference_import_key(m, idx, c), "idx=0x{:X}", idx);
        }
    }
}
