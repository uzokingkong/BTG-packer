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

/// v7: 청크 체이닝 암호화 — 256B 청크마다 RC4를 재키잉한다.
/// `Key_i = 이전 청크의 평문` (chunk 0 = `anchor`). 마지막 256B 윈도우를
/// 반환해 문자열/리졸브 테이블 런의 키로 사용한다.

pub(crate) fn chained_encrypt(buf: &mut [u8], anchor: &[u8; 256]) -> [u8; 256] {
    // 평문 사본을 먼저 확보: 다음 청크의 키는 "이전 청크의 평문"이어야 한다.
    // (부트 스텁은 복호화 후 평문 상태에서 prev 윈도우를 갱신하므로, 패커도
    //  암호화 전 평문에서 갱신해야 스텁과 정확히 일치한다.)
    let plain = buf.to_vec();
    let mut prev: [u8; 256] = *anchor;
    let mut off = 0usize;
    while off < buf.len() {
        let n = (buf.len() - off).min(256);
        let mut rc4 = Rc4::new(&prev);
        rc4.crypt(&mut buf[off..off + n]);
        if off + n >= 256 {
            prev.copy_from_slice(&plain[off + n - 256..off + n]);
        } else {
            prev = [0u8; 256];
            prev[..off + n].copy_from_slice(&plain[..off + n]);
        }
        off += n;
    }
    prev
}


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

