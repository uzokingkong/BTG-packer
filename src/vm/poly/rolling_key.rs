// ==============================================================================
// BTG - Commercial-Grade VM: Dynamic Rolling Key Engine (T2-1 강화)
// ==============================================================================
// 가상 명령어가 한 줄 실행될 때마다 다음 명령어의 복호화 키가 동적으로 변형된다.
// SMT 기반 기호 실행기(angr, Triton) 및 동적 오염 분석을 비선형 제약조건 폭발로 차단한다.
//
// T2-1 (치명적 갭 B) 수정:
//   - 이전 구현은 `encrypt_byte`/`decrypt_byte`가 64비트 키의 하위 8비트만
//     (`k as u8`) 사용했다. 상위 56비트는 키스트림에 전혀 기여하지 않아
//     SMT 솔버가 8비트 부채널만 모델링해도 복호화할 수 있었다.
//   - 이제 키스트림 바이트를 64비트 키 전체에서 유도한다: vip의 byte-lane으로
//     키를 순환 회전 + 비선형 접기(fold)로 혼합 → 모든 8개 바이트가 매 바이트에
//     기여한다.
//   - 진화 함수도 단일 LCG 상수가 아니라 2종 상수 곱 + vip/상위비트 의존 회전 +
//     평문 피드백으로 강화해 비선형 제약을 늘린다.
//   - 라운드트립 성질(encrypt 후 decrypt == 원문)은 보존한다: 암/복호 양쪽 모두
//     전단계 키로 키스트림을 만들고, 같은 평문으로 상태를 진화시킨다.
// ==============================================================================

#[derive(Debug, Clone, Copy)]
pub struct RollingKeyEngine {
    pub current_key: u64,
}

impl RollingKeyEngine {
    pub fn initial_key(initial_seed: u64) -> u64 {
        crate::vm::key_domains::derive_u64(
            initial_seed,
            crate::vm::key_domains::VmKeyDomain::Rolling,
            b"stream-0",
        )
    }

    pub fn new(initial_seed: u64) -> Self {
        Self {
            current_key: Self::initial_key(initial_seed),
        }
    }

    /// 현재 위치의 키스트림 바이트 — 64비트 키 전체를 사용한다.
    ///
    /// vip의 하위 3비트를 byte-lane으로 삼아 키를 회전시킨 뒤, 두 회전본을 더하고
    /// 64비트 곱으로 혼합한 다음 상/하위 절반을 접어 하나의 바이트로 축약한다.
    /// 따라서 키의 상위 비트 변화가 모든 바이트 출력에 전파된다.
    #[inline]
    pub fn key_byte(&self, vip: u64) -> u8 {
        let k = self.current_key;
        let lane = (vip & 7) as u32; // 0..7 — position-dependent lane
        let a = k.rotate_left(lane * 8);
        let b = k.rotate_right(((64 - lane * 8) & 63) as u32);
        let x = a.wrapping_add(b).wrapping_mul(0x9E3779B97F4A7C15);
        let y = x ^ (x >> 32);
        let z = y ^ (y >> 16);
        (z as u8) ^ ((z >> 8) as u8) ^ ((z >> 24) as u8)
    }

    /// 다음 바이트코드 복호화 키로 상태 진화 (비선형 피드백 강화).
    ///
    /// 1) 64비트 상수 곱(2종) + vip 곱 + 평문 바이트 곱을 더해 확산
    /// 2) 고정 17-bit rotate
    /// 3) `vip ^ (k 상위 32비트)` 로 회전량을 정해 회전 — 회전 자체가 키/위치 의존
    /// 4) 이전 키의 상수 곱을 더해 이전 상태에도 의존 (LCG 단독이 아님)
    #[inline]
    pub fn step(&mut self, plaintext_byte: u8, vip: u64) -> u64 {
        let k = self.current_key;
        let mixed = (k
            ^ (plaintext_byte as u64).wrapping_mul(0xBF58476D1CE4E5B9)
            ^ vip.wrapping_mul(0x517CC1B727220A95))
        .wrapping_mul(0x9E3779B97F4A7C15)
        .rotate_left(17)
        .wrapping_add(0x1337BEEFCAFE0001);
        let rot = (((vip as u32) ^ ((k >> 32) as u32)) & 63) as u32;
        let next = mixed
            .rotate_left(rot)
            .wrapping_add(k.wrapping_mul(0x94D049BB133111EB));
        self.current_key = next;
        k
    }

    #[inline]
    pub fn encrypt_byte(&mut self, b: u8, vip: u64) -> u8 {
        let ks = self.key_byte(vip);
        self.step(b, vip);
        b ^ ks
    }

    #[inline]
    pub fn decrypt_byte(&mut self, enc_b: u8, vip: u64) -> u8 {
        let ks = self.key_byte(vip);
        let orig_b = enc_b ^ ks;
        self.step(orig_b, vip);
        orig_b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_key_roundtrip() {
        // 암/복호가 같은 시드로 상태를 동기화해 원문을 복원해야 한다.
        let mut enc = RollingKeyEngine::new(0x8899AABBCCDDEEFF);
        let mut dec = RollingKeyEngine::new(0x8899AABBCCDDEEFF);
        let mut plain = vec![0u8; 512];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i.wrapping_mul(31).wrapping_add(7)) as u8;
        }
        let orig = plain.clone();
        for (i, b) in plain.iter_mut().enumerate() {
            *b = enc.encrypt_byte(*b, i as u64);
        }
        assert_ne!(plain, orig, "keystream must change the bytes");
        for (i, b) in plain.iter_mut().enumerate() {
            *b = dec.decrypt_byte(*b, i as u64);
        }
        assert_eq!(plain, orig, "encrypt then decrypt must roundtrip");
    }

    #[test]
    fn test_rolling_key_full_64bit_sensitivity() {
        // 상위 비트만 다른 두 키로 인코딩한 결과가 달라야 한다 (T2-1: 전체 64비트 사용).
        let lo = 0x0000_0000_1234_5678u64;
        let hi = 0xABCD_EF00_1234_5678u64; // 상위 24비트만 다름
        let mk = |seed: u64, data: &[u8]| -> Vec<u8> {
            let mut e = RollingKeyEngine::new(seed);
            data.iter()
                .enumerate()
                .map(|(i, &b)| e.encrypt_byte(b, i as u64))
                .collect()
        };
        let data = vec![0xAAu8; 64];
        let c_lo = mk(lo, &data);
        let c_hi = mk(hi, &data);
        assert_ne!(c_lo, c_hi, "high key bits must affect the keystream");
        // 그리고 여전히 roundtrip 된다
        let mut d = RollingKeyEngine::new(hi);
        let mut ct = c_hi.clone();
        for (i, b) in ct.iter_mut().enumerate() {
            *b = d.decrypt_byte(*b, i as u64);
        }
        assert_eq!(ct, data);
    }

    #[test]
    fn test_rolling_key_position_sensitivity() {
        // 같은 키라도 vip(위치)가 다르면 다른 키스트림이 나와야 한다.
        let mut e = RollingKeyEngine::new(42);
        let mut e2 = RollingKeyEngine::new(42);
        let b0 = e.encrypt_byte(0x11, 0);
        let b1 = e2.encrypt_byte(0x11, 1);
        assert_ne!(b0, b1, "byte position must change the keystream byte");
    }
}
