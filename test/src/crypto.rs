use std::hint::black_box;

// AES-128 S-Box
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[inline(never)]
fn galois_mul2(b: u8) -> u8 {
    if b & 0x80 != 0 {
        (b << 1) ^ 0x1b
    } else {
        b << 1
    }
}

#[inline(never)]
fn galois_mul3(b: u8) -> u8 {
    galois_mul2(b) ^ b
}

#[inline(never)]
pub fn aes_encrypt_block(state: &mut [u8; 16], key: &[u8; 16]) {
    // AddRoundKey 0
    for i in 0..16 {
        state[i] ^= key[i];
    }

    // 10 rounds simplified transformation
    for round in 1..=10 {
        // SubBytes
        for i in 0..16 {
            state[i] = SBOX[state[i] as usize];
        }

        // ShiftRows
        let temp = *state;
        state[1] = temp[5]; state[5] = temp[9]; state[9] = temp[13]; state[13] = temp[1];
        state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
        state[3] = temp[15]; state[7] = temp[3]; state[11] = temp[7]; state[15] = temp[11];

        // MixColumns (rounds 1..9)
        if round < 10 {
            for c in 0..4 {
                let i = c * 4;
                let s0 = state[i];
                let s1 = state[i + 1];
                let s2 = state[i + 2];
                let s3 = state[i + 3];

                state[i]     = galois_mul2(s0) ^ galois_mul3(s1) ^ s2 ^ s3;
                state[i + 1] = s0 ^ galois_mul2(s1) ^ galois_mul3(s2) ^ s3;
                state[i + 2] = s0 ^ s1 ^ galois_mul2(s2) ^ galois_mul3(s3);
                state[i + 3] = galois_mul3(s0) ^ s1 ^ s2 ^ galois_mul2(s3);
            }
        }

        // AddRoundKey
        let round_key_byte = (round * 0x1d) as u8;
        for i in 0..16 {
            state[i] ^= key[i] ^ round_key_byte;
        }
    }
}

#[inline(never)]
pub fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]); state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]); state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]); state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]); state[b] = (state[b] ^ state[c]).rotate_left(7);
}

#[inline(never)]
pub fn chacha20_block(seed: u64) -> [u32; 16] {
    let mut state: [u32; 16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        seed as u32, (seed >> 32) as u32, 0x01234567, 0x89abcdef,
        0xfedcba98, 0x76543210, 0xdeadbeef, 0xcafebabe,
        1, 0, 0, 0,
    ];

    for _ in 0..10 {
        // Column rounds
        chacha20_quarter_round(&mut state, 0, 4, 8, 12);
        chacha20_quarter_round(&mut state, 1, 5, 9, 13);
        chacha20_quarter_round(&mut state, 2, 6, 10, 14);
        chacha20_quarter_round(&mut state, 3, 7, 11, 15);

        // Diagonal rounds
        chacha20_quarter_round(&mut state, 0, 5, 10, 15);
        chacha20_quarter_round(&mut state, 1, 6, 11, 12);
        chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        chacha20_quarter_round(&mut state, 3, 4, 9, 14);
    }

    state
}

#[inline(never)]
pub fn sha256_compress_step(state: &mut [u32; 8], w: u32, k: u32) {
    let s1 = state[4].rotate_right(6) ^ state[4].rotate_right(11) ^ state[4].rotate_right(25);
    let ch = (state[4] & state[5]) ^ ((!state[4]) & state[6]);
    let temp1 = state[7]
        .wrapping_add(s1)
        .wrapping_add(ch)
        .wrapping_add(k)
        .wrapping_add(w);

    let s0 = state[0].rotate_right(2) ^ state[0].rotate_right(13) ^ state[0].rotate_right(22);
    let maj = (state[0] & state[1]) ^ (state[0] & state[2]) ^ (state[1] & state[2]);
    let temp2 = s0.wrapping_add(maj);

    state[7] = state[6];
    state[6] = state[5];
    state[5] = state[4];
    state[4] = state[3].wrapping_add(temp1);
    state[3] = state[2];
    state[2] = state[1];
    state[1] = state[0];
    state[0] = temp1.wrapping_add(temp2);
}

#[inline(never)]
pub fn stage_crypto(seed: u64) -> u64 {
    // 1. AES Test
    let mut block = [0u8; 16];
    for i in 0..16 {
        block[i] = ((seed >> (i * 4)) & 0xff) as u8;
    }
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];

    aes_encrypt_block(&mut block, &key);

    let mut aes_res = 0u64;
    for &b in &block {
        aes_res = (aes_res << 4) ^ (b as u64);
    }

    // 2. ChaCha20 Test
    let chacha = chacha20_block(seed ^ aes_res);
    let mut chacha_res = 0u64;
    for &w in &chacha {
        chacha_res ^= (w as u64).rotate_left(13);
        chacha_res = chacha_res.wrapping_mul(0x9E3779B1);
    }

    // 3. SHA-256 Step Test
    let mut sha_state = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    for i in 0..16 {
        let w = ((chacha_res >> (i * 2)) & 0xffffffff) as u32;
        let k = 0x428a2f98u32.wrapping_add((i * 0x1337) as u32);
        sha256_compress_step(&mut sha_state, w, k);
    }

    let mut sha_res = 0u64;
    for &val in &sha_state {
        sha_res = (sha_res << 8) ^ (val as u64);
    }

    black_box(aes_res ^ chacha_res ^ sha_res)
}
