// ==============================================================================
// BTG v61 - Virtualization Target: BTG-C1 state initialization (KSA-equivalent)
// ==============================================================================
// `--vm`(composite VM)은 RC4 경로에서 부트 스텁의 KSA(키 스케줄)를 VM 바이트코드로
// virtualize한다. BTG-C1에는 KSA가 없지만, 그 "키 설정"에 해당하는 C1 상태 초기화
// (seed → key32/ctr/nonce/ks_off)를 VM으로 virtualize해 같은 목적(키 재료 유도가
// 네이티브 코드에 노출되지 않음)을 달성한다.
//
// 상태 레이아웃 (crypto::native의 blob 상태와 동일):
//   state+0x00 key[32]  (seed_va[0..32])
//   state+0x20 ctr  u64 (0)
//   state+0x28 nonce u32 (le32(seed_va[32..36]))
//   state+0x70 ks_off u32 (0x40 — 첫 사용 시 gen_block)
//
// 호출 규약 (VM entry C1Init 모드가 스냅샷):
//   RCX = VM 상태 버퍼 VA, RDX = seed VA (→ MEM_SEED), R8 = C1 상태 버퍼 VA (→ MEM_BUF)
//
// VM 바이트코드는 MEM_SEED(seed)에서 바이트를 읽어 MEM_BUF(C1 상태 버퍼)에 기록한다.
// 이후 부트 스텁이 `emit_btg_crypt_blob`(네이티브 C1 blob)을 호출해 이 상태로
// 키스트림을 생성하므로, 키 유도는 VM 안에서만 일어난다.
// ==============================================================================

use crate::vm::bytecode::{BytecodeBuilder, MEM_BUF, MEM_SEED};

/// Pure-Rust reference: seed_masked → C1 상태 버퍼 (native `emit_c1_init`/패커와 동일).
pub fn reference_c1_init(seed: &[u8; 256], state: &mut [u8; 0x80]) {
    state[..32].copy_from_slice(&seed[..32]); // key32
    state[0x20..0x28].fill(0); // ctr = 0
    state[0x28..0x2C].copy_from_slice(&seed[32..36]); // nonce
    state[0x70..0x74].copy_from_slice(&0x40u32.to_le_bytes()); // ks_off
}

/// VM bytecode: MEM_SEED → MEM_BUF(0x80) C1 상태 초기화.
/// (v0=idx, v1=scratch, v2=scratch — KSA VM과 동일한 vreg 공간.)
pub fn build_c1_init_bytecode() -> Vec<u8> {
    let mut b = BytecodeBuilder::new();

    // key32 = seed[0..32]
    for i in 0u32..32 {
        b.mov_r_imm32(0, i);
        b.movzx_r_mem8(1, MEM_SEED, 0);
        b.mov_mem8_r(MEM_BUF, 0, 1);
    }
    // ctr = 0 → state[0x20..0x28]
    for i in 0x20u32..0x28 {
        b.mov_r_imm32(0, i);
        b.mov_r_imm32(1, 0);
        b.mov_mem8_r(MEM_BUF, 0, 1);
    }
    // nonce = le32(seed[32..36]) → state[0x28..0x2C]
    for i in 0u32..4 {
        b.mov_r_imm32(0, 0x28 + i);
        b.mov_r_imm32(1, 32 + i);
        b.movzx_r_mem8(2, MEM_SEED, 1);
        b.mov_mem8_r(MEM_BUF, 0, 2);
    }
    // ks_off = 0x40 (LE: [0x40,0,0,0]) → state[0x70..0x74]
    b.mov_r_imm32(0, 0x70);
    b.mov_r_imm32(1, 0x40);
    b.mov_mem8_r(MEM_BUF, 0, 1);
    for i in 0x71u32..0x74 {
        b.mov_r_imm32(0, i);
        b.mov_r_imm32(1, 0);
        b.mov_mem8_r(MEM_BUF, 0, 1);
    }

    b.halt();
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::interp;
    use rand::RngCore;

    #[test]
    fn c1_init_vm_matches_reference() {
        let bc = build_c1_init_bytecode();
        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            let mut seed = [0u8; 256];
            rng.fill_bytes(&mut seed);

            let mut state_ref = [0u8; 0x80];
            reference_c1_init(&seed, &mut state_ref);

            // VM 실행: MEM_SEED = seed, MEM_BUF = C1 상태 버퍼
            let mut state = vec![0u8; interp::STATE_SIZE];
            let mut mem = vec![0u8; 0x400];
            let (seed_off, buf_off) = (0usize, 0x100usize);
            mem[seed_off..seed_off + 256].copy_from_slice(&seed);
            state[interp::STATE_PTR_SEED..interp::STATE_PTR_SEED + 8]
                .copy_from_slice(&(seed_off as u64).to_le_bytes());
            state[interp::STATE_PTR_BUF..interp::STATE_PTR_BUF + 8]
                .copy_from_slice(&(buf_off as u64).to_le_bytes());
            interp::interpret(&mut state, &mut mem, &bc).unwrap();
            let out = &mem[buf_off..buf_off + 0x80];
            assert_eq!(out, &state_ref[..], "C1-init VM vs reference mismatch");
        }
    }
}
