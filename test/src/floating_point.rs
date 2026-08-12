use std::hint::black_box;

// Q32.32 Fixed-Point Representation
#[derive(Clone, Copy)]
struct Fixed64(i64);

impl Fixed64 {
    fn from_int(val: i64) -> Self {
        Self(val << 32)
    }

    fn from_ratio(num: i64, den: i64) -> Self {
        Self((((num as i128) << 32) / (den as i128)) as i64)
    }

    fn add(self, rhs: Self) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }

    fn sub(self, rhs: Self) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }

    fn mul(self, rhs: Self) -> Self {
        let prod = (self.0 as i128).wrapping_mul(rhs.0 as i128);
        Self((prod >> 32) as i64)
    }

    fn to_bits(self) -> u64 {
        self.0 as u64
    }
}

#[inline(never)]
fn taylor_sin_fixed(x: Fixed64) -> Fixed64 {
    let mut term = x;
    let mut sum = x;
    let x2 = x.mul(x);

    for i in 1..=6 {
        let n = (2 * i) * (2 * i + 1);
        let factor = Fixed64::from_ratio(1, n as i64);
        term = Fixed64::from_int(0).sub(term.mul(x2).mul(factor));
        sum = sum.add(term);
    }

    sum
}

#[inline(never)]
fn matrix_3x3_multiply_fixed(a: &[Fixed64; 9], b: &[Fixed64; 9]) -> [Fixed64; 9] {
    let mut out = [Fixed64(0); 9];
    for r in 0..3 {
        for c in 0..3 {
            let mut sum = Fixed64(0);
            for k in 0..3 {
                sum = sum.add(a[r * 3 + k].mul(b[k * 3 + c]));
            }
            out[r * 3 + c] = sum;
        }
    }
    out
}

#[inline(never)]
pub fn stage_floating_point(seed: u64) -> u64 {
    // Q32.32 seed initialization
    let base_val = Fixed64((seed & 0x000F_FFFF_FFFF_FFFF) as i64);
    
    // Taylor Series Fixed-Point Calculation
    let sin_val = taylor_sin_fixed(base_val);
    let exp_approx = Fixed64::from_int(1).add(base_val).add(base_val.mul(base_val).mul(Fixed64::from_ratio(1, 2)));

    // 3x3 Matrix Multiplication
    let m1 = [
        base_val, Fixed64::from_ratio(12, 10), Fixed64::from_ratio(5, 10),
        Fixed64::from_ratio(-4, 10), sin_val, Fixed64::from_ratio(21, 10),
        Fixed64::from_ratio(8, 10), Fixed64::from_ratio(-11, 10), exp_approx,
    ];
    let m2 = [
        Fixed64::from_ratio(9, 10), Fixed64::from_ratio(-3, 10), Fixed64::from_ratio(15, 10),
        Fixed64::from_ratio(20, 10), exp_approx, Fixed64::from_ratio(-8, 10),
        Fixed64::from_ratio(-12, 10), Fixed64::from_ratio(6, 10), Fixed64::from_ratio(4, 10),
    ];

    let m_res = matrix_3x3_multiply_fixed(&m1, &m2);

    let mut bits_acc = sin_val.to_bits() ^ exp_approx.to_bits();
    for &elem in &m_res {
        bits_acc ^= elem.to_bits().rotate_left(7);
        bits_acc = bits_acc.wrapping_mul(0x9E3779B185EBCA87);
    }

    black_box(bits_acc)
}
