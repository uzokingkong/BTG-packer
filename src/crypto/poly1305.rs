// ==============================================================================
// BTG Packer — T3-1 Phase D: Poly1305 (RFC 8439 §2.5) reference implementation
// ==============================================================================
// Dependency-free, compact reference of the RFC 8439 Poly1305 MAC. This is a
// direct port of the poly1305-donna soft backend (RustCrypto `poly1305` crate,
// `backend/soft.rs`) so it is byte-identical to the differential-test
// authority:
//   * r clamped with overlapping shifted loads + per-word masks
//   * h absorbed with the same shifted 26-bit limb decode
//   * donna multiply + carry chain
//   * finalize with full carry + (h + -p) selection + (h + pad) mod 2^128
//
// The boot-stub native blob (`crypto::poly1305_native`) is emitted to match
// this reference exactly and is differential-tested against it.
// ==============================================================================

/// 26-bit limb mask.
const MASK: u64 = 0x3ff_ffff;

/// 5 x 26-bit limbs for the accumulator h and the clamped key r.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly1305State {
    pub h: [u32; 5],
    pub r: [u32; 5],
    /// pad = key[16..32] as four little-endian u32 words.
    pub pad: [u32; 4],
}

/// Load the 32-byte key: clamp r (first 16 bytes) + pad (second 16 bytes).
pub fn poly1305_init(key: &[u8; 32]) -> Poly1305State {
    let le = |i: usize| u32::from_le_bytes([key[i], key[i + 1], key[i + 2], key[i + 3]]);
    // r &= 0xffffffc0ffffffc0ffffffc0fffffff (donna clamp)
    let r = [
        le(0) & 0x3ff_ffff,
        (le(3) >> 2) & 0x3ff_ff03,
        (le(6) >> 4) & 0x3ff_c0ff,
        (le(9) >> 6) & 0x3f0_3fff,
        (le(12) >> 8) & 0x00f_ffff,
    ];
    let pad = [le(16), le(20), le(24), le(28)];
    Poly1305State { h: [0; 5], r, pad }
}

/// Absorb one 16-byte block into h, multiply by r, partial-reduce (donna).
/// `partial` = true for the final padded block (hibit = 0).
pub fn poly1305_compute_block(st: &mut Poly1305State, block: &[u8; 16], partial: bool) {
    let hibit: u32 = if partial { 0 } else { 1 << 24 };

    let r0 = st.r[0];
    let r1 = st.r[1];
    let r2 = st.r[2];
    let r3 = st.r[3];
    let r4 = st.r[4];

    let s1 = r1.wrapping_mul(5);
    let s2 = r2.wrapping_mul(5);
    let s3 = r3.wrapping_mul(5);
    let s4 = r4.wrapping_mul(5);

    let le = |i: usize| u32::from_le_bytes([block[i], block[i + 1], block[i + 2], block[i + 3]]);

    let mut h0 = st.h[0];
    let mut h1 = st.h[1];
    let mut h2 = st.h[2];
    let mut h3 = st.h[3];
    let mut h4 = st.h[4];

    // h += m
    h0 = h0.wrapping_add(le(0) & 0x3ff_ffff);
    h1 = h1.wrapping_add((le(3) >> 2) & 0x3ff_ffff);
    h2 = h2.wrapping_add((le(6) >> 4) & 0x3ff_ffff);
    h3 = h3.wrapping_add((le(9) >> 6) & 0x3ff_ffff);
    h4 = h4.wrapping_add((le(12) >> 8) | hibit);

    // h *= r
    let d0 = (u64::from(h0) * u64::from(r0))
        + (u64::from(h1) * u64::from(s4))
        + (u64::from(h2) * u64::from(s3))
        + (u64::from(h3) * u64::from(s2))
        + (u64::from(h4) * u64::from(s1));

    let mut d1 = (u64::from(h0) * u64::from(r1))
        + (u64::from(h1) * u64::from(r0))
        + (u64::from(h2) * u64::from(s4))
        + (u64::from(h3) * u64::from(s3))
        + (u64::from(h4) * u64::from(s2));

    let mut d2 = (u64::from(h0) * u64::from(r2))
        + (u64::from(h1) * u64::from(r1))
        + (u64::from(h2) * u64::from(r0))
        + (u64::from(h3) * u64::from(s4))
        + (u64::from(h4) * u64::from(s3));

    let mut d3 = (u64::from(h0) * u64::from(r3))
        + (u64::from(h1) * u64::from(r2))
        + (u64::from(h2) * u64::from(r1))
        + (u64::from(h3) * u64::from(r0))
        + (u64::from(h4) * u64::from(s4));

    let mut d4 = (u64::from(h0) * u64::from(r4))
        + (u64::from(h1) * u64::from(r3))
        + (u64::from(h2) * u64::from(r2))
        + (u64::from(h3) * u64::from(r1))
        + (u64::from(h4) * u64::from(r0));

    // (partial) h %= p
    let mut c: u32;
    c = (d0 >> 26) as u32;
    h0 = d0 as u32 & MASK as u32;
    d1 += u64::from(c);

    c = (d1 >> 26) as u32;
    h1 = d1 as u32 & MASK as u32;
    d2 += u64::from(c);

    c = (d2 >> 26) as u32;
    h2 = d2 as u32 & MASK as u32;
    d3 += u64::from(c);

    c = (d3 >> 26) as u32;
    h3 = d3 as u32 & MASK as u32;
    d4 += u64::from(c);

    c = (d4 >> 26) as u32;
    h4 = d4 as u32 & MASK as u32;
    h0 = h0.wrapping_add(c.wrapping_mul(5));

    c = h0 >> 26;
    h0 &= MASK as u32;
    h1 = h1.wrapping_add(c);

    st.h = [h0, h1, h2, h3, h4];
}

/// Process the message. `final_block` = true when `msg` ends with a partial
/// (or empty) final block that carries the terminating 0x01 byte. Full 16-byte
/// blocks are absorbed with hibit = 1<<24; the partial block is padded with a
/// trailing 0x01 and absorbed with hibit = 0.
pub fn poly1305_blocks(st: &mut Poly1305State, msg: &[u8], final_block: bool) {
    let mut rest = msg;
    while rest.len() >= 16 {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&rest[..16]);
        poly1305_compute_block(st, &blk, false);
        rest = &rest[16..];
    }
    if final_block && !rest.is_empty() {
        let mut blk = [0u8; 16];
        blk[..rest.len()].copy_from_slice(rest);
        blk[rest.len()] = 0x01; // terminating byte
        poly1305_compute_block(st, &blk, true);
    }
}

/// Finalize: full carry, select h vs h - p, then (h + pad) mod 2^128 -> tag.
pub fn poly1305_finish(st: &Poly1305State) -> [u8; 16] {
    // fully carry h
    let mut h0 = st.h[0];
    let mut h1 = st.h[1];
    let mut h2 = st.h[2];
    let mut h3 = st.h[3];
    let mut h4 = st.h[4];

    let mut c: u32;
    c = h1 >> 26;
    h1 &= MASK as u32;
    h2 = h2.wrapping_add(c);

    c = h2 >> 26;
    h2 &= MASK as u32;
    h3 = h3.wrapping_add(c);

    c = h3 >> 26;
    h3 &= MASK as u32;
    h4 = h4.wrapping_add(c);

    c = h4 >> 26;
    h4 &= MASK as u32;
    h0 = h0.wrapping_add(c.wrapping_mul(5));

    c = h0 >> 26;
    h0 &= MASK as u32;
    h1 = h1.wrapping_add(c);

    // compute h + -p
    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= MASK as u32;

    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= MASK as u32;

    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= MASK as u32;

    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= MASK as u32;

    let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    // select h if h < p, or h + -p if h >= p
    let mut mask = (g4 >> 31).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = !mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    // h = h % (2^128)
    h0 |= h1 << 26;
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);

    // h = mac = (h + pad) % (2^128)
    let mut f: u64;
    f = u64::from(h0) + u64::from(st.pad[0]);
    let t0 = f as u32;

    f = u64::from(h1) + u64::from(st.pad[1]) + (f >> 32);
    let t1 = f as u32;

    f = u64::from(h2) + u64::from(st.pad[2]) + (f >> 32);
    let t2 = f as u32;

    f = u64::from(h3) + u64::from(st.pad[3]) + (f >> 32);
    let t3 = f as u32;

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&t0.to_le_bytes());
    tag[4..8].copy_from_slice(&t1.to_le_bytes());
    tag[8..12].copy_from_slice(&t2.to_le_bytes());
    tag[12..16].copy_from_slice(&t3.to_le_bytes());
    tag
}

/// Compute the RFC 8439 Poly1305 tag over `msg`.
pub fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let mut st = poly1305_init(key);
    poly1305_blocks(&mut st, msg, true);
    poly1305_finish(&st)
}

// ==============================================================================
// T3-1 Phase D — AEAD (ChaCha20-Poly1305 §2.8) helper surface shared by the
// packer and the boot-stub native verify blob (`crypto::poly1305_native`).
// ==============================================================================

/// Fixed, versioned domain tag bound into the AEAD MAC (AAD). Exactly 16 bytes,
/// so `pad16(AAD)` adds nothing and the boot-stub blob absorbs it as one block.
/// Both the packer tag computation and the native blob embed this exact string,
/// so `packer MAC == runtime stub MAC` holds iff the ciphertext region, the
/// derived Poly1305 key and this AAD all agree.
pub const POLY1305_AEAD_AAD: [u8; 16] = *b"btg-aead-p1305v1";

/// RFC 8439 §2.8 AEAD MAC construction over (AAD, ciphertext):
///   mac_data = pad16(AAD) || pad16(CT) || le64(len(AAD)) || le64(len(CT))
/// then the standalone Poly1305 MAC (§2.5). This is exactly what the boot-stub
/// native verify blob computes over the stored at-rest ciphertext.
pub fn poly1305_aead_tag(aad: &[u8], ct: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let mut mac_data = Vec::with_capacity(aad.len() + ct.len() + 32);
    for s in [aad, ct] {
        mac_data.extend_from_slice(s);
        mac_data.extend(std::iter::repeat(0u8).take((16 - s.len() % 16) % 16));
    }
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    poly1305_mac(&mac_data, key)
}

/// ChaCha20-Poly1305 one-time Poly1305 key = first 32 bytes of the counter=0
/// keystream block (RFC 8439 §2.6: `Poly1305_key = ChaCha20_block(key, 0, nonce)
/// [0..32]`). `block0` is the keystream block generated with counter = 0.
pub fn chacha_poly1305_key_from_block0(block0: &[u8; 64]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&block0[..32]);
    k
}

/// RFC 8439 §2.5.2 Poly1305 test vector.
pub const RFC8439_POLY1305_KEY: [u8; 32] = [
    0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
];
pub const RFC8439_POLY1305_MSG: &[u8] =
    b"Cryptographic Forum Research Group";
pub const RFC8439_POLY1305_TAG: [u8; 16] = [
    0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poly1305_rfc8439_test_vector() {
        let tag = poly1305_mac(RFC8439_POLY1305_MSG, &RFC8439_POLY1305_KEY);
        assert_eq!(tag, RFC8439_POLY1305_TAG, "RFC 8439 §2.5.2 vector mismatch");
    }

    #[test]
    fn poly1305_differential_vs_rustcrypto() {
        use poly1305::universal_hash::KeyInit;
        for len in [0usize, 1, 16, 17, 32, 63, 64, 65, 100, 256, 1024] {
            let msg: Vec<u8> = (0..len).map(|i| ((i as u32 * 131 + 7) % 251) as u8).collect();
            let key = RFC8439_POLY1305_KEY;
            let rc = <poly1305::Poly1305 as KeyInit>::new_from_slice(&key).unwrap();
            let rc_tag = rc.compute_unpadded(&msg).as_slice().to_vec();

            let ours = poly1305_mac(&msg, &key);
            assert_eq!(
                ours.to_vec(),
                rc_tag.to_vec(),
                "Poly1305 mismatch vs RustCrypto for len={len}"
            );
        }
    }

    /// Multiple-chunk processing must equal a single-shot call.
    #[test]
    fn poly1305_chunked_matches_single() {
        let key = RFC8439_POLY1305_KEY;
        let msg: Vec<u8> = (0..200).map(|i| ((i as u32 * 7 + 3) % 249) as u8).collect();
        let single = poly1305_mac(&msg, &key);

        let mut st = poly1305_init(&key);
        poly1305_blocks(&mut st, &msg[..80], false);
        poly1305_blocks(&mut st, &msg[80..], true);
        let chunked = poly1305_finish(&st);
        assert_eq!(chunked.to_vec(), single.to_vec(), "chunked processing must equal single-shot");
    }
}