use std::hint::black_box;

#[inline(never)]
pub fn complex_add(a: u64, b: u64) -> u64 {
    let x = a.wrapping_add(b);
    let y = x.wrapping_add(0xA5A5A5A5);
    let z = y ^ 0x5A5A5A5A;

    black_box(z)
}

#[inline(never)]
pub fn complex_mul(a: u64, b: u64) -> u64 {
    let x = a.wrapping_mul(b);
    let y = x ^ x.rotate_left(13);
    let z = y.wrapping_mul(0x9E3779B1);

    black_box(z)
}

#[inline(never)]
pub fn rotate_mix(mut x: u64) -> u64 {
    x = x.rotate_left(17);
    x ^= x.rotate_right(23);
    x = x.wrapping_add(0xD6E8FEB86659FD93);
    x ^= x >> 29;
    x = x.wrapping_mul(0x9E3779B97F4A7C15);
    x ^= x << 17;

    black_box(x)
}

#[inline(never)]
pub fn conditional_transform(x: u64) -> u64 {
    if x & 0x8000_0000 != 0 {
        let a = x.rotate_left(31);
        let b = a.wrapping_mul(11);
        black_box(b ^ 0xCAFEBABE)
    } else if x & 0x4000_0000 != 0 {
        let a = x.rotate_right(7);
        black_box(a.wrapping_add(0x12345678))
    } else {
        black_box(!x ^ 0xDEADC0DE)
    }
}

#[inline(never)]
pub fn final_mix(a: u64, b: u64) -> u64 {
    let mut x = a ^ b;

    for i in 0..12 {
        x ^= x.rotate_left((i * 3 + 7) as u32);
        x = x.wrapping_mul(
            0x9E3779B185EBCA87u64
                .wrapping_add(i as u64),
        );
        x ^= x >> 31;
    }

    black_box(x)
}