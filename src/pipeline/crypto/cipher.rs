// ==============================================================================
// RC4 stream cipher (packer side) + RC4/chain VM subroutines
// ==============================================================================

use super::bootstub::{base_bind_byte, BootStubCtx, Label};
use iced_x86::{Code, Instruction, MemoryOperand, Register};
use rand::RngCore;

/// ── 패커 측 RC4 (부트 스텁과 정확히 동일한 알고리즘) ────────────────────────────
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (k, v) in s.iter_mut().enumerate() {
            *v = k as u8;
        }
        let mut j: u8 = 0;
        let klen = key.len().max(1);
        for i in 0..256usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % klen]);
            s.swap(i, j as usize);
        }
        // Canonical RC4: PRGA는 i=0, j=0에서 시작한다 (KSA의 j를 이어받지 않음)
        Rc4 { s, i: 0, j: 0 }
    }

    /// RC4 PRGA로 keystream을 생성해 버퍼에 XOR한다. (in-place decrypt/encrypt)
    pub fn crypt(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize] as usize + self.s[self.j as usize] as usize) & 0xFF];
            *byte ^= k;
        }
    }

    /// KSA 완료 후 S-box 상태 (테스트/검증용 — 패커 KSA == 부트 스텁 KSA 동치성).
    pub fn sbox(&self) -> &[u8; 256] {
        &self.s
    }
}

/// v7: 청크 체이닝 암호화는 `crate::crypto::provider::chain_encrypt`로 이동
/// (plan.txt 1~3단계 — CryptoProvider 추상화 계층). 부트 스텁 셸코드와 동일
/// 알고리즘을 유지하므로 동작은 그대로다.


/// v19: 시드 생성 + RC4 키 파생 (base-bound). 패커 키 == 부트 스텁/VM 경로와 동일.
pub(crate) fn derive_seed_and_key(
    rng: &mut impl RngCore,
    image_base: u64,
    k1: u32,
    k2: u32,
    k3: u32,
) -> (Vec<u8>, Vec<u8>, [u8; 256]) {
    let mut seed = [0u8; 256];
    rng.fill_bytes(&mut seed);
    // v19 (base-bound key): 시드 저장은 원본 seed_masked를 유지하되, **파일에 쓰는
    // 바이트만** base_bind_byte(선호 base)로 미리 XOR한다. 부트 스텁이 런타임에
    // PEB ImageBaseAddress(실제 base)에서 같은 바이트를 유도해 시드에 XOR하면,
    // 선호 base로 로드 시 상쇄되어 원본 seed_masked 복원 → 정상 복호화.
    let seed_masked: Vec<u8> = seed.iter().map(|b| b ^ 0xA7).collect();
    let base_bind = base_bind_byte(image_base);
    let seed_stored: Vec<u8> = seed_masked.iter().map(|b| b ^ base_bind).collect();

    let mut key = [0u8; 256];
    for i in 0..256usize {
        let iu = i as u32;
        // v10: 비선형 믹스 — vm/ksa.rs 단일 소스 (부트 스텁/VM과 항상 일치)
        let mix = crate::vm::ksa::key_mix(iu, k1, k2, k3);
        key[i] = seed_masked[i] ^ (mix as u8);
    }
    (seed_masked, seed_stored, key)
}

/// v60 (--custom-cipher): BTG-C1 키/논스 유도 (패커 ↔ 부트 스텁 단일 소스).
///
/// seed_masked(256B, 매 패킹 랜덤)의 앞 32바이트를 256-bit 키로, 그 다음
/// 4바이트를 32-bit nonce로 쓴다. 부트 스텁 `emit_c1_init`이 seed_va에서 같은
/// 바이트를 그대로 복사하므로 패커와 런타임이 항상 일치하며, 별도 상수를 코드에
/// 박지 않아도 된다 (키/논스는 전부 시드 엔트로피에서 파생).
pub(crate) fn derive_c1_key_nonce(seed_masked: &[u8]) -> ([u8; 32], u32) {
    debug_assert!(seed_masked.len() >= 36, "seed must be 256 bytes for BTG-C1");
    let mut key = [0u8; 32];
    key.copy_from_slice(&seed_masked[..32]);
    let nonce = u32::from_le_bytes(seed_masked[32..36].try_into().unwrap());
    (key, nonce)
}

/// v63 (--crypto-mode chacha20): ChaCha20 키/논스 원시 파생 (패커 ↔ 부트 스텁
/// 단일 소스). seed_masked 앞 32바이트 = 256-bit key, 다음 12바이트 = 96-bit
/// nonce (RFC 8439 IETF 변형). 부트 스텁 `emit_chacha_init`이 seed_va에서 같은
/// 바이트를 그대로 복사하므로 패커와 런타임이 항상 일치한다.
pub(crate) fn derive_chacha_key_nonce_raw(seed_masked: &[u8]) -> ([u8; 32], [u8; 12]) {
    debug_assert!(seed_masked.len() >= 44, "seed must be 256 bytes for ChaCha20");
    let mut key = [0u8; 32];
    key.copy_from_slice(&seed_masked[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&seed_masked[32..44]);
    (key, nonce)
}

/// v61 (--custom-cipher + reencrypt/m7): 4바이트 MBA per-block 키 → 32바이트
/// BTG-C1 키 (8회 반복). M7/reencrypt C1 디스패처의 C1Init이 같은 확장을
/// 어셈블리로 수행한다 — 패커와 런타임이 항상 일치해야 한다.
pub(crate) fn repeat4(key: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    for i in 0..8usize {
        k[i * 4..i * 4 + 4].copy_from_slice(&key.to_le_bytes());
    }
    k
}

pub(crate) fn emit_prga_sub(seq: &mut Vec<(Instruction, Option<Label>)>, _stub: &BootStubCtx) {
    // ── PRGA 서브루틴: rcx=buf, rdx=len ──
    seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(), Some(Label::Prga)));
    seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::PrgaDone)));
    seq.push((Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), Some(Label::PrgaLoop)));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::ESI, 0xFF).unwrap(), None));
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
        ).unwrap(),
        None,
    ));
    seq.push((Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF).unwrap(), None));
    // swap(S[i], S[j])
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R8D,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
        ).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R9D,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RDI, 1),
        ).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_rm8_r8,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
            Register::R9L,
        ).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_rm8_r8,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RDI, 1),
            Register::R8L,
        ).unwrap(),
        None,
    ));
    // K = S[(S[i]+S[j]) & 0xFF]
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R8D).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::R9D).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0xFF).unwrap(), None));
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RAX, 1),
        ).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Xor_rm8_r8,
            MemoryOperand::with_base(Register::RCX),
            Register::AL,
        ).unwrap(),
        None,
    ));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(), None));
    // FIX: 루프는 매 회차 종료 조건을 다시 검사해야 한다. 과거 코드는
    // `jmp PrgaLoop`(inc esi)로 되돌아가 `test rdx,rdx; je done`을 우회하여
    // 첫 호출(코드 영역 복호화)이 rdx=0에서 끝나지 않고 스텁 자신의 코드를
    // 계속 XOR로 덮어쓰다 0xC0000005로 크래시했다. -> `jmp Prga`(test)로 복귀.
    seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::Prga)));
    seq.push((Instruction::with(Code::Retnq), Some(Label::PrgaDone)));
}

pub(crate) fn emit_ksa_sub(seq: &mut Vec<(Instruction, Option<Label>)>, _stub: &BootStubCtx) {
    // ── v7 chained-crypto: KSA 서브루틴 (rcx=key 256B, rbx=S-box base) ───────
    // 표준 RC4 KSA (key 길이 256 고정 → i%256==i). 청크마다 재호출된다.
    // S[i] = i 초기화
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), Some(Label::Ksa)));
    seq.push((Instruction::with2(
        Code::Mov_rm8_r8,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
        Register::SIL,
    ).unwrap(), Some(Label::KsaInitLoop)));
    seq.push((Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), None));
    seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::KsaInitLoop)));
    // KSA: j = (j + S[i] + key[i]) & 0xFF ; swap(S[i], S[j])
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Movzx_r32_rm8,
        Register::EAX,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
    ).unwrap(), Some(Label::KsaLoopK)));
    seq.push((Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Movzx_r32_rm8,
        Register::EAX,
        MemoryOperand::with_base_index_scale(Register::RCX, Register::RSI, 1),
    ).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Movzx_r32_rm8,
        Register::EAX,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
    ).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Movzx_r32_rm8,
        Register::R8D,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RDI, 1),
    ).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Mov_rm8_r8,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RDI, 1),
        Register::AL,
    ).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Mov_rm8_r8,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
        Register::R8L,
    ).unwrap(), None));
    seq.push((Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), None));
    seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::KsaLoopK)));
    seq.push((Instruction::with(Code::Retnq), None));
}

pub(crate) fn emit_zeromem_sub(seq: &mut Vec<(Instruction, Option<Label>)>, _stub: &BootStubCtx) {
    // ── v7 chained-crypto: ZeroMem 서브루틴 (rcx=buf, rdx=len) ───────────────
    seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(), Some(Label::ZeroMem)));
    seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::ZeroDone)));
    seq.push((Instruction::with2(Code::Mov_rm8_imm8, MemoryOperand::with_base(Register::RCX), 0u32).unwrap(), None));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::ZeroMem)));
    seq.push((Instruction::with(Code::Retnq), Some(Label::ZeroDone)));
}

