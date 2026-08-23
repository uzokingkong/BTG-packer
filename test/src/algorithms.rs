use std::hint::black_box;

#[inline(never)]
pub fn pseudo_random(mut x: u64) -> u64 {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;

    x.wrapping_mul(0x2545F4914F6CDD1D)
}

#[inline(never)]
pub fn checksum(data: &[u64]) -> u64 {
    let mut result = 0x123456789ABCDEF0u64;

    for (i, &value) in data.iter().enumerate() {
        result ^= value.rotate_left(
            ((i * 7) % 63) as u32
        );

        result = result
            .wrapping_mul(0x9E3779B185EBCA87);

        if result & 1 == 0 {
            result ^= result >> 17;
        } else {
            result ^= result << 13;
        }
    }

    black_box(result)
}

#[inline(never)]
pub fn fibonacci_variant(n: u32) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        _ => {
            let mut a = 0u64;
            let mut b = 1u64;

            for i in 2..=n {
                let c = a.wrapping_add(b);

                a = b;
                b = c ^ (i as u64).rotate_left(3);
            }

            b
        }
    }
}