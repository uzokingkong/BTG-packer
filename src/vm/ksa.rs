// ==============================================================================
// BTG v3 - Virtualization Target: RC4 KSA (key schedule) routine
// ==============================================================================
//
// This is the *single source of truth* for what the composite VM virtualizes
// in the MVP: the boot stub's RC4 key-schedule (S-box init + KSA) loop that
// derives the per-run RC4 key from the masked seed:
//
//   for i in 0..256 {
//       S[i] = i                       // InitLoop
//   }
//   j = 0
//   for i in 0..256 {                  // KsaLoop
//       j  = (j + S[i]) & 0xFF
//       mix = key_mix(i, k1, k2, k3)   // v10: 비선형 믹스 (아래)
//       key = seed_masked[i] ^ mix
//       j  = (j + key) & 0xFF
//       swap(S[i], S[j])
//   }
//
// v10 key_mix — 이전 선형 `rol(i,3) ^ k1 ^ (i*k2) ^ k3`을 회전/곱셈/덧셈
// 캐스케이드로 교체:
//   a = i ^ k1
//   b = a * k2 + k3            (mod 2^32)
//   c = rol(b, 5) ^ (rol(i, 9) * k3)
//   mix = ror(c, 7)
// → 각 키 바이트가 i/k1/k2/k3 전체에 확산되고, 인접 i에 대한 상관이 약해진다.
//   패커(crypto.rs), 부트 스텁(아래 명령 리스트), VM(lifter)이 모두 이 함수와
//   명령 리스트를 공유하므로 세 경로가 절대 어긋날 수 없다.
//
// The instruction list below is the exact x86-64 sequence the boot stub
// executes natively (crypto.rs build_rc4_block) — it is used to
//   (a) build the native reference (executed in the self-test), and
//   (b) be lifted to VM bytecode (lifter.rs) for the virtualized path.
// Keeping both derived from this one list guarantees equivalence.
//
// Registers used: RBX = S-box base, RDX = seed base (abs VA), ESI = i,
// EDI = j, EAX/ECX temps, R8D=k1, R9D=k2, R10D=k3.
// ==============================================================================


use iced_x86::{Code, Instruction, MemoryOperand, Register};

/// v10: 비선형 RC4 키 믹스 (단일 소스 — 패커/부트 스텁/VM 공유).
pub fn key_mix(i: u32, k1: u32, k2: u32, k3: u32) -> u32 {
    let a = i ^ k1;
    let b = a.wrapping_mul(k2).wrapping_add(k3);
    let c = b.rotate_left(5) ^ i.rotate_left(9).wrapping_mul(k3);
    c.rotate_right(7)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KsaLabel {
    InitLoop,
    KsaLoop,
}

/// One element of the KSA instruction list.
#[derive(Debug, Clone, Copy)]
pub struct KsaInstr {
    pub inst: Instruction,
    /// Set on the instruction that a label *points to* (loop head).
    pub label: Option<KsaLabel>,
    /// Set on a branch instruction: the label it targets.
    pub target: Option<KsaLabel>,
}

impl KsaInstr {
    fn plain(inst: Instruction) -> Self {
        Self { inst, label: None, target: None }
    }
    fn labeled(inst: Instruction, label: KsaLabel) -> Self {
        Self { inst, label: Some(label), target: None }
    }
    fn branch(inst: Instruction, target: KsaLabel) -> Self {
        Self { inst, label: None, target: Some(target) }
    }
}

/// Build the KSA instruction list (S-box init + key schedule loops).
pub fn build_ksa_instructions(seed_va: u64, k1: u32, k2: u32, k3: u32) -> Vec<KsaInstr> {
    let sbox = |idx: Register| MemoryOperand::with_base_index_scale(Register::RBX, idx, 1);
    let seed = |idx: Register| MemoryOperand::with_base_index_scale(Register::RDX, idx, 1);
    let mut v = Vec::new();

    // ── InitLoop: S[i] = i, for i in 0..=255 ─────────────────────────────────
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(),
    ));
    v.push(KsaInstr::labeled(
        Instruction::with2(Code::Mov_rm8_r8, sbox(Register::RSI), Register::SIL).unwrap(),
        KsaLabel::InitLoop,
    ));
    v.push(KsaInstr::plain(Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap()));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100).unwrap(),
    ));
    v.push(KsaInstr::branch(Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), KsaLabel::InitLoop));

    // ── KSA: j=0, key derivation + swap ──────────────────────────────────────
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r64_imm64, Register::RDX, seed_va).unwrap(),
    ));
    // v15: KSA 상수를 평문 immediate로 노출하지 않는다. 각 상수를 랜덤 분해해
    // 런타임 복원한다(Add/Xor/Imul). EAX/ECX는 KsaLoop 진입 전 temp 전용
    // (루프 첫 명령이 ecx=esi로 덮어씀)이라 클로버에 안전. 모든 opcode는
    // VM 라이프터가 지원하므로 --vm 경로와 동치 유지.
    // v16: obfuscation salt를 패킹당 랜덤(k1/k2/k3에서 유도)으로 생성해, 평문
    // immediate 값이 빌드마다 달라지게 한다(이전에는 고정 상수라 한 번 파싱하면
    // 모든 빌드에 재사용 가능). k1/k2/k3는 패킹마다 랜덤이므로 salt도 빌드마다
    // 변하며, 같은 k1/k2/k3로는 항상 동일해 sizing/최종 패스 길이가 일치한다.
    // xorshift32(k1^k2^k3) 결정적 PRNG로 salt 생성.
    let mut xr = k1 ^ k2.rotate_left(7) ^ k3.rotate_left(13);
    xr ^= xr << 13; xr ^= xr >> 17; xr ^= xr << 5;
    let p1a = xr.wrapping_mul(0xA5A5_5A5Au32);
    let mut xr2 = xr.wrapping_add(0x9E37_79B9u32);
    xr2 ^= xr2 << 13; xr2 ^= xr2 >> 17; xr2 ^= xr2 << 5;
    let p1b = xr2 | 1u32;
    let p1x = p1a ^ p1b;
    let p1adj = k1.wrapping_sub(p1x);
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r32_imm32, Register::R8D, p1a).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r32_imm32, Register::ECX, p1b).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Xor_rm32_r32, Register::R8D, Register::ECX).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r32_imm32, Register::ECX, p1adj).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Add_rm32_r32, Register::R8D, Register::ECX).unwrap(),
    ));
    // k2 = (p2a + p2b) ^ p2c
    let mut xr3 = xr2.wrapping_add(0xDEAD_BEEFu32);
    xr3 ^= xr3 << 13; xr3 ^= xr3 >> 17; xr3 ^= xr3 << 5;
    let p2a = xr3 | 1u32;
    let mut xr4 = xr3.wrapping_add(0x0BAD_1234u32);
    xr4 ^= xr4 << 13; xr4 ^= xr4 >> 17; xr4 ^= xr4 << 5;
    let p2b = xr4 | 1u32;
    let p2c = (p2a.wrapping_add(p2b)) ^ k2;
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r32_imm32, Register::R9D, p2a).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r32_imm32, Register::ECX, p2b).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Add_rm32_r32, Register::R9D, Register::ECX).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r32_imm32, Register::ECX, p2c).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Xor_rm32_r32, Register::R9D, Register::ECX).unwrap(),
    ));
    // k3 = (p3a + p3b) + p3adj   (이중 덧셈 분해)
    let mut xr5 = xr4.wrapping_add(0x55AA_55AAu32);
    xr5 ^= xr5 << 13; xr5 ^= xr5 >> 17; xr5 ^= xr5 << 5;
    let p3a = xr5 | 1u32;
    let mut xr6 = xr5.wrapping_add(0xAA55_AA55u32);
    xr6 ^= xr6 << 13; xr6 ^= xr6 >> 17; xr6 ^= xr6 << 5;
    let p3b = xr6 | 1u32;
    let p3adj = k3.wrapping_sub(p3a.wrapping_add(p3b));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r32_imm32, Register::R10D, p3a).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r32_imm32, Register::ECX, p3b).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Add_rm32_r32, Register::R10D, Register::ECX).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r32_imm32, Register::ECX, p3adj).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Add_rm32_r32, Register::R10D, Register::ECX).unwrap(),
    ));
    v.push(KsaInstr::labeled(
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, sbox(Register::RSI)).unwrap(),
        KsaLabel::KsaLoop,
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(),
    ));
    // mix(i) = key_mix(i, k1, k2, k3) — v10 비선형 캐스케이드
    //   a = i ^ k1 ; b = a*k2 + k3 ; c = rol(b,5) ^ (rol(i,9)*k3) ; mix = ror(c,7)
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::ESI).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::R8D).unwrap(),
    )); // ecx = i ^ k1
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Imul_r32_rm32, Register::ECX, Register::R9D).unwrap(),
    )); // ecx = (i^k1)*k2
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Add_rm32_r32, Register::ECX, Register::R10D).unwrap(),
    )); // ecx += k3
    v.push(KsaInstr::plain(Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 5).unwrap()));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::ESI).unwrap(),
    ));
    v.push(KsaInstr::plain(Instruction::with2(Code::Rol_rm32_imm8, Register::EAX, 9).unwrap()));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Imul_r32_rm32, Register::EAX, Register::R10D).unwrap(),
    )); // rol(i,9)*k3
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX).unwrap(),
    ));
    v.push(KsaInstr::plain(Instruction::with2(Code::Ror_rm32_imm8, Register::ECX, 7).unwrap()));
    // key byte = seed_masked[i] ^ mix(i)
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, seed(Register::RSI)).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::ECX).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF).unwrap(),
    ));
    // swap(S[i], S[j])
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, sbox(Register::RSI)).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, sbox(Register::RDI)).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_rm8_r8, sbox(Register::RDI), Register::AL).unwrap(),
    ));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Mov_rm8_r8, sbox(Register::RSI), Register::CL).unwrap(),
    ));
    v.push(KsaInstr::plain(Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap()));
    v.push(KsaInstr::plain(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100).unwrap(),
    ));
    v.push(KsaInstr::branch(
        Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(),
        KsaLabel::KsaLoop,
    ));

    v
}

/// Pure-Rust reference implementation of the same KSA (used by the self-test).
/// Writes the final S-box (after InitLoop + KSA) into `sbox`.
pub fn reference_ksa(seed_masked: &[u8; 256], k1: u32, k2: u32, k3: u32, sbox: &mut [u8; 256]) {
    for i in 0..256usize {
        sbox[i] = i as u8;
    }
    let mut j = 0u32;
    for i in 0..256usize {
        let iu = i as u32;
        j = (j + sbox[i] as u32) & 0xFF;
        let key = seed_masked[i] ^ (key_mix(iu, k1, k2, k3) as u8);
        j = (j + key as u32) & 0xFF;
        sbox.swap(i, j as usize);
    }
}
