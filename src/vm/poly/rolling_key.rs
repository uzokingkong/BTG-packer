// ==============================================================================
// BTG - Commercial-Grade VM: Dynamic Rolling Key Engine
// ==============================================================================
// 가상 명령어가 한 줄 실행될 때마다 다음 명령어의 복호화 키가 동적으로 변형된다.
// SMT 기반 기호 실행기(angr, Triton) 및 동적 오염 분석을 비선형 제약조건 폭발로 차단한다.
// ==============================================================================

#[derive(Debug, Clone, Copy)]
pub struct RollingKeyEngine {
    pub current_key: u64,
}

impl RollingKeyEngine {
    pub fn new(initial_seed: u64) -> Self {
        Self {
            current_key: initial_seed.wrapping_mul(0x9E3779B97F4A7C15) ^ 0x517CC1B727220A95,
        }
    }

    /// 다음 바이트코드 복호화 키로 상태 진화
    #[inline]
    pub fn step(&mut self, opcode: u8, vip: u64) -> u64 {
        let k = self.current_key;
        // Non-linear polynomial evolution
        let next_k = (k ^ (opcode as u64) ^ vip)
            .wrapping_mul(0x9E3779B97F4A7C15)
            .rotate_left(17)
            .wrapping_add(0x1337BEEFCAFE0001);
        self.current_key = next_k;
        k
    }

    #[inline]
    pub fn encrypt_byte(&mut self, b: u8, vip: u64) -> u8 {
        let k = self.step(b, vip);
        b ^ (k as u8)
    }

    #[inline]
    pub fn decrypt_byte(&mut self, enc_b: u8, vip: u64) -> u8 {
        let orig_b = enc_b ^ (self.current_key as u8);
        self.step(orig_b, vip);
        orig_b
    }
}
