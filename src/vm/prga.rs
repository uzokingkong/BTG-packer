// ==============================================================================
// BTG v19 - Virtualization Target #3: RC4 PRGA (keystream generation)
// ==============================================================================
// The boot stub decrypts the code region, every string run, and the resolve
// table by running the RC4 PRGA over each buffer. In the native boot stub this
// is an inline x86 subroutine. This module lifts that same PRGA loop into VM
// bytecode so the whole decoder (KSA + PRGA) executes through the composite VM.
//
// PRGA semantics (must match the boot-stub native loop byte-for-byte):
//   i = 0; j = 0
//   for each byte of buf (len bytes, in order):
//       i = (i + 1) & 0xFF
//       j = (j + S[i]) & 0xFF
//       r8 = S[i]; r9 = S[j]; S[i]=r9; S[j]=r8        (swap)
//       K = S[(r8 + r9) & 0xFF]                        (using ORIGINAL S[i],S[j])
//       *bufptr ^= K; bufptr++
//
// Virtual registers:
//   v0 = i, v1 = j   (PERSIST across VM invocations — caller inits v0=v1=0 once)
//   v2 = buffer byte offset (reset to 0 each call)
//   v3 = remaining len      (set by caller each call)
//   v4..v9 = temps
// Memory slots: MEM_SBOX = S-box (the KSA-produced state), MEM_BUF = buffer.
//
// Caller contract (VM state before invoking the PRGA routine):
//   * ptr_sbox -> S-box base            (VM entry snapshots from RBX)
//   * ptr_buf  -> target buffer base    (VM entry snapshots from RDX)
//   * v3       -> buffer length         (VM entry snapshots from R8)
//   * v0/v1    -> i/j (0 on the very first call; carried over afterwards)
// ==============================================================================

use crate::vm::bytecode::{
    BytecodeBuilder, MEM_BUF, MEM_SBOX, OP_ADD_R_IMM32, OP_ADD_R_R, OP_AND_R_IMM32, OP_CMP_R_IMM32,
    OP_DEC_R, OP_JB8, OP_JMP8, OP_MOVZX_R_MEM8, OP_MOV_MEM8_R, OP_MOV_R_IMM32, OP_XOR_R_R,
};

/// Pure-Rust reference PRGA. `sbox` is mutated in place (keystream state) and
/// `buf` is XOR-decrypted in place. Must match the boot-stub native loop.
pub fn reference_prga(sbox: &mut [u8; 256], buf: &mut [u8]) {
    let (mut i, mut j) = (0usize, 0usize);
    for b in buf.iter_mut() {
        i = (i + 1) & 0xFF;
        j = (j + sbox[i] as usize) & 0xFF;
        let si = sbox[i];
        let sj = sbox[j];
        sbox[i] = sj;
        sbox[j] = si;
        let k = sbox[(si as usize + sj as usize) & 0xFF];
        *b ^= k;
    }
}

/// Build VM bytecode for the RC4 PRGA loop. Caller must preload v3 = buffer length.
pub fn build_prga_bytecode() -> Vec<u8> {
    let mut b = BytecodeBuilder::new();
    let loop_l = b.new_label();
    let done_l = b.new_label();

    // v0=i, v1=j persist in VM state (caller inits 0 once). v3=len set by caller.
    // Only v2 (buffer offset) resets to 0 at the start of each invocation.
    b.mov_r_imm32(2, 0);
    // v3 = buffer length is supplied by the caller (not initialized here).

    // loop: if len < 1 -> done
    b.mark_label(loop_l);
    b.cmp_r_imm32(3, 1);
    b.jb8(done_l);

    // i = (i + 1) & 0xFF
    b.binop_r_imm32(OP_ADD_R_IMM32, 0, 1);
    b.binop_r_imm32(OP_AND_R_IMM32, 0, 0xFF);
    // v4 = S[i]
    b.movzx_r_mem8(4, MEM_SBOX, 0);
    // j = (j + S[i]) & 0xFF
    b.binop_r_r(OP_ADD_R_R, 1, 4);
    b.binop_r_imm32(OP_AND_R_IMM32, 1, 0xFF);
    // v5 = S[i] ; v6 = S[j]
    b.movzx_r_mem8(5, MEM_SBOX, 0);
    b.movzx_r_mem8(6, MEM_SBOX, 1);
    // swap: S[i] = v6 ; S[j] = v5
    b.mov_mem8_r(MEM_SBOX, 0, 6);
    b.mov_mem8_r(MEM_SBOX, 1, 5);
    // v7 = (v5 + v6) & 0xFF   (index)
    b.mov_r_imm32(7, 0);
    b.binop_r_r(OP_ADD_R_R, 7, 5);
    b.binop_r_r(OP_ADD_R_R, 7, 6);
    b.binop_r_imm32(OP_AND_R_IMM32, 7, 0xFF);
    // v4 = K = S[ v7 ]
    b.movzx_r_mem8(4, MEM_SBOX, 7);
    // v8 = buf[off] ; v8 ^= K ; buf[off] = v8
    b.movzx_r_mem8(8, MEM_BUF, 2);
    b.binop_r_r(OP_XOR_R_R, 8, 4);
    b.mov_mem8_r(MEM_BUF, 2, 8);
    // off++ ; len--
    b.binop_r_imm32(OP_ADD_R_IMM32, 2, 1);
    b.dec_r(3);
    b.jmp8(loop_l);

    b.mark_label(done_l);
    b.halt();
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::interp;
    use rand::RngCore;

    #[test]
    fn prga_vm_matches_reference() {
        let mut rng = rand::thread_rng();
        let bc = build_prga_bytecode();
        for _ in 0..8 {
            let mut sbox = [0u8; 256];
            rng.fill_bytes(&mut sbox);
            let mut buf = vec![0u8; 64];
            rng.fill_bytes(&mut buf);
            let mut sbox_ref = sbox;
            let mut buf_ref = buf.clone();
            reference_prga(&mut sbox_ref, &mut buf_ref);

            let mut state = vec![0u8; interp::STATE_SIZE];
            let mut mem = vec![0u8; 0x400];
            let (sbox_off, buf_off) = (0usize, 0x100usize);
            mem[sbox_off..sbox_off + 256].copy_from_slice(&sbox);
            mem[buf_off..buf_off + buf.len()].copy_from_slice(&buf);
            state[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
                .copy_from_slice(&(sbox_off as u64).to_le_bytes());
            state[interp::STATE_PTR_BUF..interp::STATE_PTR_BUF + 8]
                .copy_from_slice(&(buf_off as u64).to_le_bytes());
            // v0=i=0, v1=j=0 (first call), v2=off=0, v3=len
            state[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].fill(0);
            state[interp::STATE_VREGS + 1 * 8..interp::STATE_VREGS + 2 * 8].fill(0);
            state[interp::STATE_VREGS + 2 * 8..interp::STATE_VREGS + 3 * 8].fill(0);
            state[interp::STATE_VREGS + 3 * 8..interp::STATE_VREGS + 4 * 8]
                .copy_from_slice(&(buf.len() as u64).to_le_bytes());
            interp::interpret(&mut state, &mut mem, &bc).unwrap();
            let out = &mem[buf_off..buf_off + buf.len()];
            assert_eq!(out, &buf_ref[..], "PRGA VM vs reference mismatch");
        }
    }
}
