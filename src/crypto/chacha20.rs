// ==============================================================================
// BTG Packer — T3-1: ChaCha20 (RFC 8439) reference implementation
// ==============================================================================
// boot-stub 네이티브 ChaCha20 blob(`chacha20_native::emit_chacha20_blob`)과 bit
// 동일해야 하는 **reference(권위) 구현**. IETF 변형(RFC 8439)을 사용한다:
//   32B key + 12B nonce + 32-bit counter.
//
// 네이티브 blob과 동일한 state buffer 레이아웃(0x80B)을 유지해, 같은 상태를
// 초기화한 뒤 네이티브==reference를 직접 비교할 수 있다:
//   +0x00 key[32]
//   +0x20 ctr  u64  (하위 32비트만 block counter로 사용)
//   +0x28 nonce[12]
//   +0x38 ks[64]    (생성된 keystream 버퍼)
//   +0x78 ks_off u32 (0x40 = 버퍼 고갈 → 다음 사용 시 gen_block)
//
// T3-1 스트림 계약: `chacha_apply`는 네이티브 blob의 crypt 루프와 동일하게
// 바이트 단위로 XOR한다 (RC4 PRGA/C1 blob과 동일한 부트 스텁 호출 계약).
// ==============================================================================

pub const CHACHA20_CONST_0: u32 = 0x6170_7865; // "expa"
pub const CHACHA20_CONST_1: u32 = 0x3320_646e; // "nd 3"
pub const CHACHA20_CONST_2: u32 = 0x7962_2d32; // "2-by"
pub const CHACHA20_CONST_3: u32 = 0x6b20_6574; // "te k"

/// state buffer 총 크기 (바이트).
pub const CHA_STATE_SIZE: usize = 0x80;
pub const CHA_OFF_KEY: usize = 0x00;
pub const CHA_OFF_CTR: usize = 0x20;
pub const CHA_OFF_NONCE: usize = 0x28;
pub const CHA_OFF_KS: usize = 0x38;
pub const CHA_OFF_KS_OFF: usize = 0x78;

/// RFC 8439 §2.3.2 block function — 64B keystream 블록 생성.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut st = [
        CHACHA20_CONST_0,
        CHACHA20_CONST_1,
        CHACHA20_CONST_2,
        CHACHA20_CONST_3,
        word_le(&key[0..4]),
        word_le(&key[4..8]),
        word_le(&key[8..12]),
        word_le(&key[12..16]),
        word_le(&key[16..20]),
        word_le(&key[20..24]),
        word_le(&key[24..28]),
        word_le(&key[28..32]),
        counter,
        word_le(&nonce[0..4]),
        word_le(&nonce[4..8]),
        word_le(&nonce[8..12]),
    ];
    let initial = st;
    for _ in 0..10 {
        // column rounds
        qr(&mut st, 0, 4, 8, 12);
        qr(&mut st, 1, 5, 9, 13);
        qr(&mut st, 2, 6, 10, 14);
        qr(&mut st, 3, 7, 11, 15);
        // diagonal rounds
        qr(&mut st, 0, 5, 10, 15);
        qr(&mut st, 1, 6, 11, 12);
        qr(&mut st, 2, 7, 8, 13);
        qr(&mut st, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let w = st[i].wrapping_add(initial[i]).to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&w);
    }
    out
}

/// 네이티브 blob과 동일한 state buffer 초기화:
/// key = key, ctr = 0, nonce = nonce, ks_off = 0x40 (첫 사용 시 gen_block).
pub fn chacha_init_state(state: &mut [u8; CHA_STATE_SIZE], key: &[u8; 32], nonce: &[u8; 12]) {
    state[CHA_OFF_KEY..CHA_OFF_KEY + 32].copy_from_slice(key);
    state[CHA_OFF_CTR..CHA_OFF_CTR + 8].fill(0);
    state[CHA_OFF_NONCE..CHA_OFF_NONCE + 12].copy_from_slice(nonce);
    state[CHA_OFF_KS_OFF..CHA_OFF_KS_OFF + 4].copy_from_slice(&0x40u32.to_le_bytes());
}

/// state buffer의 현재 ctr u64를 반환한다 (다중 호출 연속성 검증용).
pub fn chacha_state_ctr(state: &[u8; CHA_STATE_SIZE]) -> u64 {
    le_u64(&state[CHA_OFF_CTR..CHA_OFF_CTR + 8])
}

/// state buffer를 따라 `buf`를 바이트 단위 XOR (네이티브 blob의 crypt 루프와 동일).
/// ks_off >= 0x40 이면 gen_block으로 새 keystream 64B를 채우고 ctr++.
pub fn chacha_apply(state: &mut [u8; CHA_STATE_SIZE], buf: &mut [u8]) {
    for b in buf.iter_mut() {
        let ks_off = le_u32(&state[CHA_OFF_KS_OFF..CHA_OFF_KS_OFF + 4]);
        if ks_off >= 0x40 {
            let key: [u8; 32] = {
                let mut k = [0u8; 32];
                k.copy_from_slice(&state[CHA_OFF_KEY..CHA_OFF_KEY + 32]);
                k
            };
            let nonce: [u8; 12] = {
                let mut n = [0u8; 12];
                n.copy_from_slice(&state[CHA_OFF_NONCE..CHA_OFF_NONCE + 12]);
                n
            };
            let ctr = le_u64(&state[CHA_OFF_CTR..CHA_OFF_CTR + 8]) as u32;
            state[CHA_OFF_KS..CHA_OFF_KS + 64].copy_from_slice(&chacha20_block(&key, ctr, &nonce));
            let next = (ctr as u64) + 1;
            state[CHA_OFF_CTR..CHA_OFF_CTR + 8].copy_from_slice(&next.to_le_bytes());
            state[CHA_OFF_KS_OFF..CHA_OFF_KS_OFF + 4].copy_from_slice(&0u32.to_le_bytes());
        }
        let ks_off = le_u32(&state[CHA_OFF_KS_OFF..CHA_OFF_KS_OFF + 4]) as usize;
        *b ^= state[CHA_OFF_KS + ks_off];
        state[CHA_OFF_KS_OFF..CHA_OFF_KS_OFF + 4]
            .copy_from_slice(&((ks_off as u32 + 1).to_le_bytes()));
    }
}

// ── 내부 헬퍼 ────────────────────────────────────────────────────────────────

#[inline]
fn qr(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

#[inline]
fn word_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
fn le_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}
