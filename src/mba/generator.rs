// ============================================================
// BTG - Runtime MBA Key Derivation Engine
// ============================================================
//
// Implements the Mixed Boolean-Arithmetic (MBA) identity used to
// derive the per-block jump-table XOR key at RUNTIME inside the
// dispatcher. For any 32-bit x, y (mod 232):
// x + y == (x XOR y) + 2 * (x AND y)
//
// Each protected block gets a random 32-bit seed. A block stub
// pushes (block_id, seed) and transfers control to the dispatcher,
// which re-derives key = MBA(seed, block_id) with the same identity
// the packer evaluates at build time via compute_key(). The
// encrypted table entry (offset XOR key) therefore decrypts to the
// correct physical offset, and the key value never appears as a
// plaintext constant in the binary.

use rand::Rng;

pub struct MbaGenerator;

impl MbaGenerator {
    /// Build-time mirror of the dispatcher MBA key schedule.
    /// Level 1 (Basic): K = (seed XOR block_id) XOR C
    /// Level 2 (MBA): K = ((seed XOR block_id) + 2*(seed AND block_id)) XOR C
    /// Level 3 (Overlap + MBA): K = (((seed XOR block_id) + 2*(seed AND block_id)) XOR C) + (seed AND block_id)
    pub fn compute_key(seed: u32, block_id: u32, constant: u32, level: usize) -> u32 {
        let s = seed;
        let b = block_id;
        match level {
            1 => (s ^ b) ^ constant,
            2 => (s ^ b).wrapping_add((s & b).wrapping_mul(2)) ^ constant,
            _ => {
                let base = (s ^ b).wrapping_add((s & b).wrapping_mul(2));
                (base ^ constant).wrapping_add(s & b)
            }
        }
    }

    /// Generates a fresh random per-block seed.

    pub fn random_seed() -> u32 {
        rand::thread_rng().gen()
    }

    /// Deterministic per-block seed derivation (v6).
    ///
    /// `master_seed`는 패킹 1회당 1개 랜덤 값. `seed_for(master, id)`는
    /// 슬라이서/패스3/패스4/디스패처에서 동일하게 계산되므로 별도의 시드
    /// 저장소 없이 패커와 런타임의 키 스케줄이 항상 일치한다.
    pub fn seed_for(master_seed: u32, block_id: u32) -> u32 {
        let mut h = master_seed
            .wrapping_add(block_id.wrapping_mul(0x9E37_79B9))
            .rotate_left(13);
        h ^= master_seed.rotate_right(7);
        h ^= block_id.rotate_left(5).wrapping_mul(0x85EB_CA6B);
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_key_levels() {
        let (s, b, c) = (0xDEADBEEFu32, 0x12345678u32, 0xCAFEBABEu32);
        let k1 = MbaGenerator::compute_key(s, b, c, 1);
        let k2 = MbaGenerator::compute_key(s, b, c, 2);
        let k3 = MbaGenerator::compute_key(s, b, c, 3);
        assert_eq!(k1, (s ^ b) ^ c);
        assert_eq!(k2, (s ^ b).wrapping_add((s & b).wrapping_mul(2)) ^ c);
        assert_ne!(k1, k2);
        assert_ne!(k2, k3);
    }

    #[test]
    fn test_seed_for_deterministic_and_varied() {
        let m = 0xA5A5A5A5u32;
        assert_eq!(MbaGenerator::seed_for(m, 3), MbaGenerator::seed_for(m, 3));
        assert_ne!(MbaGenerator::seed_for(m, 3), MbaGenerator::seed_for(m, 4));
        assert_ne!(
            MbaGenerator::seed_for(m, 3),
            MbaGenerator::seed_for(m ^ 1, 3)
        );
    }
}
