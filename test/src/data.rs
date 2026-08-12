#[inline(never)]
pub fn test_buffer(seed: u64) -> Vec<u8> {
    let mut result = Vec::with_capacity(128);

    let mut x = seed;

    for i in 0..128 {
        x ^= x.rotate_left(7);
        x = x.wrapping_mul(0x9E3779B185EBCA87);
        x ^= i as u64;

        result.push(
            ((x >> ((i % 8) * 8)) & 0xff) as u8
        );
    }

    result
}