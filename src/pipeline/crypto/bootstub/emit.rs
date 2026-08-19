// ==============================================================================
// BTG - boot-stub code emission - split from bootstub.rs
// ==============================================================================
// RC4 boot-stub emitter functions: base-bind loop, trashformer junk, KSA init,
// code/run/rest decrypt, self-wipe, dispatcher entry.
// ==============================================================================

use super::super::{cipher, encode, iat, integrity, memharden, payload, vm_embed};
use super::ctx::{BootStubCtx, Label};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

/// v10: vm/ksa.rs의 KsaLabel → 부트 스텁 Label 매핑 (단일 KSA 소스 공유).

fn map_ksa_label(l: crate::vm::ksa::KsaLabel) -> Label {
    match l {
        crate::vm::ksa::KsaLabel::InitLoop => Label::InitLoop,
        crate::vm::ksa::KsaLabel::KsaLoop => Label::KsaLoop,
    }
}

/// v19: 부트 스텁용 base-XOR 루프 생성. PEB.ImageBaseAddress(실제 로드 base)를 읽어
/// `base_bind_byte`와 같은 바이트를 유도하고, 시드(seed_va, 256B)를 그 바이트로 XOR.
/// 사용 레지스터(rax/rdx/rcx/r8/rsi/rdi)는 이후 KSA/PRGA가 다시 초기화하므로 안전.

pub(crate) fn emit_base_bind_loop(seq: &mut Vec<(Instruction, Option<Label>)>, seed_va: u64) {
    use iced_x86::MemoryOperand as M;
    // rax = PEB (gs:[0x60])
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
        MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None));
    // rax = PEB.ImageBaseAddress (offset 0x10)
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
        M::with_base_displ(Register::RAX, 0x10)).unwrap(), None));
    // r8d = (base>>16) & 0xFF
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(), None));
    seq.push((Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 16).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::EDX).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::R8D, 0xFF).unwrap(), None));
    // ecx = (base>>24) & 0xFF ; r8d ^= ecx
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(), None));
    seq.push((Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 24).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_rm32_r32, Register::R8D, Register::ECX).unwrap(), None));
    // ecx = (base>>32) & 0xFF ; r8d ^= ecx  → r8b = bind byte
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(), None));
    seq.push((Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 32).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_rm32_r32, Register::R8D, Register::ECX).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::R8D, 0xFF).unwrap(), None));
    // rsi = seed_va ; edi = 256 ; loop: xor byte [rsi], r8b ; inc rsi ; dec edi
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RSI, seed_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::EDI, 0x100).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_rm8_r8, M::with_base(Register::RSI), Register::R8L).unwrap(), Some(Label::BaseBindLoop)));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::RSI).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm32, Register::EDI).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::BaseBindLoop)));
}

/// v17: TrashFormer-스타일 데드-레지스터 정크 생성. (1) 오직 프로시저 서문에서
/// 아직 라이브가 아닌 레지스터(rax/rcx/rdx/rsi/rdi/r8..r11)에만 쓰고,
/// (2) mov/or/xor/cmp/lea(reg-reg)만 사용해 rbx/rsp/플래그 의미를 건드리지 않으며,
/// (3) seed는 패킹마다 랜덤인 k1^k2^k3에서 xorshift로 유도 → 빌드마다 다른 정크.

pub(crate) fn trashformer_junk(seed: u32) -> Vec<Instruction> {
    // 결정적 xorshift32 (패킹당 시드)
    let mut st = seed | 1u32;
    let mut next = move || {
        st ^= st << 13;
        st ^= st >> 17;
        st ^= st << 5;
        st
    };
    // 데드 레지스터 풀 (서문 시점에서 안전)
    let pool = [
        Register::RAX, Register::RCX, Register::RDX, Register::RSI,
        Register::RDI, Register::R8, Register::R9, Register::R10, Register::R11,
    ];
    let n = 8 + (next() % 16) as usize; // 8..23 개
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let a = pool[(next() as usize) % pool.len()];
        let b = pool[(next() as usize) % pool.len()];
        match next() % 5 {
            0 => out.push(Instruction::with2(Code::Mov_r64_rm64, a, b).unwrap()),
            1 => out.push(Instruction::with2(Code::Or_rm64_r64, a, b).unwrap()),
            2 => out.push(Instruction::with2(Code::Xor_rm64_r64, a, b).unwrap()),
            3 => out.push(Instruction::with2(Code::Cmp_rm64_r64, a, b).unwrap()),
            _ => out.push(Instruction::with2(Code::Lea_r64_m, a, MemoryOperand::with_base(b)).unwrap()),
        }
    }
    out
}

/// v60 (--custom-cipher): BTG-C1 상태형 키스트림 blob 호출.
/// RCX=buf, RDX=len (Win64 규약) — blob이 c1_state_va의 카운터/키스트림을 유지한다.
/// 길이 불변성: c1_blob_va는 rel32 타깃이라 값과 무관하게 5바이트 고정.
pub(crate) fn emit_c1_call(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    seq.push((
        Instruction::with_branch(Code::Call_rel32_64, stub.c1_blob_va).unwrap(),
        None,
    ));
}

/// v60 (--custom-cipher): BTG-C1 상태 초기화.
///   key[32]   = seed_va[0..32]              → c1_state_va+0x00
///   ctr       = 0                            → c1_state_va+0x20
///   nonce     = le32(seed_va[32..36])        → c1_state_va+0x28
///   ks_off    = 0x40 (첫 사용 시 gen_block)  → c1_state_va+0x70
/// (S-box 256B 상수 테이블은 패커가 c1_sbox_va에 기록 — 스텁은 쓰지 않는다.)
/// 사용 레지스터(rax/rcx/rdx/r8/r9)는 이후 경로에서 덮어쓰므로 안전. RBX는
/// C1 경로에서 S-box base로 쓰지 않지만 RSP 프레임으로 유지한다.
pub(crate) fn emit_c1_init(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    use iced_x86::MemoryOperand as M;
    // rsi = seed_va ; rdi = c1_state_va ; r8d = 32 ; r9 = key byte staging
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.seed_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDI, stub.c1_state_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 32).unwrap(), None));
    // C1KeyLoop: key[rdi] = seed[rsi] ; advance ; loop
    seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, M::with_base(Register::RSI)).unwrap(), Some(Label::C1KeyLoop)));
    seq.push((Instruction::with2(Code::Mov_rm8_r8, M::with_base(Register::RDI), Register::R9L).unwrap(), None));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::RSI).unwrap(), None));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::RDI).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm32, Register::R8D).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::C1KeyLoop)));
    // ctr = 0 → c1_state_va+0x20
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDI, stub.c1_state_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RDI, 0x20), Register::RAX).unwrap(), None));
    // nonce = le32(seed_va[32..36]) → c1_state_va+0x28
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.seed_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::R8D, M::with_base_displ(Register::RSI, 32)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm32_r32, M::with_base_displ(Register::RDI, 0x28), Register::R8D).unwrap(), None));
    // ks_off = 0x40 → c1_state_va+0x70
    seq.push((Instruction::with2(Code::Mov_rm32_imm32, M::with_base_displ(Register::RDI, 0x70), 0x40u32).unwrap(), None));
}

/// v63 (--crypto-mode chacha20): ChaCha20 (RFC 8439) 상태형 키스트림 blob 호출.
/// RCX=buf, RDX=len (Win64 규약) — blob이 chacha_state_va의 ctr/ks/ks_off를 유지한다.
/// 길이 불변성: chacha_blob_va는 rel32 타깃이라 값과 무관하게 5바이트 고정.
pub(crate) fn emit_chacha_call(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    seq.push((
        Instruction::with_branch(Code::Call_rel32_64, stub.chacha_blob_va).unwrap(),
        None,
    ));
}

/// v63 (--crypto-mode chacha20): ChaCha20 상태 초기화.
///   key[32]   = seed_va[0..32]              → chacha_state_va+0x00
///   ctr       = 0                            → chacha_state_va+0x20 (u64)
///   nonce     = seed_va[32..44] (12B)        → chacha_state_va+0x28
///   ks_off    = 0x40 (첫 사용 시 gen_block)  → chacha_state_va+0x78
/// (RFC 8439 IETF 변형: 32B key + 12B nonce + 32-bit counter — 패커
///  `derive_chacha_key_nonce_raw`와 동일한 시드 바이트를 복사한다.)
/// 사용 레지스터(rax/rcx/rdx/rsi/rdi/r8/r9)는 이후 경로에서 덮어쓰므로 안전.
pub(crate) fn emit_chacha_init(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    use iced_x86::MemoryOperand as M;
    // rsi = seed_va ; rdi = chacha_state_va ; r8d = 32 ; r9 = key byte staging
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.seed_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDI, stub.chacha_state_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 32).unwrap(), None));
    // ChaKeyLoop: key[rdi] = seed[rsi] ; advance ; loop (32B)
    seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, M::with_base(Register::RSI)).unwrap(), Some(Label::ChaKeyLoop)));
    seq.push((Instruction::with2(Code::Mov_rm8_r8, M::with_base(Register::RDI), Register::R9L).unwrap(), None));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::RSI).unwrap(), None));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::RDI).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm32, Register::R8D).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::ChaKeyLoop)));
    // ctr = 0 → chacha_state_va+0x20 (u64 8B)
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDI, stub.chacha_state_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RDI, 0x20), Register::RAX).unwrap(), None));
    // nonce = seed_va[32..44] → chacha_state_va+0x28 (3 dwords = 12B)
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.seed_va).unwrap(), None));
    for i in 0..3 {
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::R8D, M::with_base_displ(Register::RSI, 32 + i * 4)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm32_r32, M::with_base_displ(Register::RDI, 0x28 + i * 4), Register::R8D).unwrap(), None));
    }
    // ks_off = 0x40 → chacha_state_va+0x78
    seq.push((Instruction::with2(Code::Mov_rm32_imm32, M::with_base_displ(Register::RDI, 0x78), 0x40u32).unwrap(), None));
}

pub(crate) fn emit_ksa_init(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v9: crypto-off 경량 스텁 — RC4 키 스케줄/복호화 전체 생략 ────────────────
    // (안티디버그 → 페이로드 복사 → [CRC] → IAT 해석 → 메모리 하드닝 → 디스패치)
    if !stub.no_crypto {
    if stub.chained {
        // ── v7 chained-crypto: 초기 KSA 없음 — 아래 체인 루프가 청크별로 KSA 수행 ──
        // (청크 0의 키 = seed anchor, 이후 청크의 키 = 직전 청크 평문)
    } else if stub.chacha_mode() {
        // ── v63 (--crypto-mode chacha20): ChaCha20 상태 초기화 (네이티브) ──────
        // RC4의 KSA-virtualize(vm)는 chacha 경로와 조합하지 않는다 (place.rs가
        // chacha를 비-vm 경로에만 활성화) — seed → key/ctr/nonce/ks_off 유도만.
        emit_chacha_init(seq, stub);
    } else if stub.c1_mode() && stub.vm {
        // ── v61 (--custom-cipher + --vm): C1 상태 초기화를 VM으로 virtualize ────
        // RC4의 KSA-virtualize에 대응: seed → key32/ctr/nonce/ks_off 유도가 VM
        // 바이트코드(C1Init 모드) 안에서만 일어난다.
        // 호출 규약: RCX = VM 상태 버퍼 VA, RDX = seed VA(→MEM_SEED),
        //           R8 = C1 상태 버퍼 VA(→MEM_BUF), call vm_entry_va.
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.seed_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R8, stub.c1_state_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.vm_state_va).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, stub.vm_entry_va).unwrap(), None));
    } else if stub.vm {
        // ── v3-composite VM 경로 ──────────────────────────────────────────────
        // S-box 초기화 + KSA(키 스케줄)는 가상화된 VM 모듈이 수행한다.
        // 호출 규약: RCX = VM 상태 버퍼 VA, RBX = S-box 기반(=RSP), RDX = seed VA.
        // (RBX는 위 `mov rbx, rsp`로 이미 설정됨)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.seed_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.vm_state_va).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, stub.vm_entry_va).unwrap(), None));
    } else {
        // v10: 부트 스텁의 S-box 초기화 + KSA는 vm/ksa.rs의 단일 명령 리스트로
        // 생성한다. (패커 키 유도 / 부트 스텁 / VM 라이프터가 같은 key_mix를
        // 공유 — 이전에는 crypto.rs에 손으로 쓴 복사본이 있어 mix 변경 시
        // 3곳이 어긋날 위험이 있었다.)
        for item in crate::vm::ksa::build_ksa_instructions(stub.seed_va, stub.k1, stub.k2, stub.k3) {
            let lbl = item
                .label
                .map(map_ksa_label)
                .or_else(|| item.target.map(map_ksa_label));
            seq.push((item.inst, lbl));
        }
    }
    } // ── end: !stub.no_crypto (RC4 키 스케줄 생략) ────────────────────────────
}

pub(crate) fn emit_code_decrypt(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v9: crypto-off 스텁은 코드 영역 복호화를 생략한다 ───────────────────────
    if !stub.no_crypto {
    if stub.chained {
        // ── v7 Phase 0.1: 환경 인증 게이트 (정적 에뮬레이터/디버거 차단) ────────
        // PEB 3검(BeingDebugged/NtGlobalFlag/Heap.Flags) + RDTSC 타이밍.
        // 실패 시 **시드를 XOR 변조**해 체인 복호화를 쓰레기로 유도 — "깨끗한 감지"
        // 대신 자연스러운 오류로 동작(fail-deceptive). 정적 에뮬레이터는 gs:[0x60]
        // PEB 컨텍스트가 없어 이 검사에서 실패한다.
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None)); // PEB
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 2)).unwrap(), None)); // BeingDebugged
        seq.push((Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 0xBC)).unwrap(), None)); // NtGlobalFlag
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x70).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ(Register::RAX, 0x30)).unwrap(), None)); // ProcessHeap
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 0x70)).unwrap(), None)); // Heap.Flags
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x70).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        // 타이밍: 10만회 루프가 너무 빠르면(에뮬/튜닝) 실패
        seq.push((Instruction::with(Code::Rdtsc), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ESI, Register::EAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0x186A0).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm32, Register::ECX).unwrap(), Some(Label::AttestTiming)));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestTiming)));
        seq.push((Instruction::with(Code::Rdtsc), None));
        seq.push((Instruction::with2(Code::Sub_rm32_r32, Register::EAX, Register::ESI).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 5000).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::AttestOk)));
        // AttestFail: 시드 256B를 0x5A로 XOR → 체인 anchor 파괴
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDI, stub.seed_va).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0x100).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_rm8_imm8, MemoryOperand::with_base(Register::RDI), 0x5Au32).unwrap(), Some(Label::AttestMutLoop)));
        seq.push((Instruction::with1(Code::Inc_rm64, Register::RDI).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm32, Register::ECX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestMutLoop)));
        seq.push((Instruction::with(Code::Nopd), Some(Label::AttestOk)));

        // ── v7 chained-crypto: 코드 영역 256B 청크 순차 복호화 ────────────────
        // Key_i = 이전 청크 평문 (chunk 0 = seed anchor) → skip-ahead 불가.
        // 레지스터: r12 = 오프셋, r13 = 남은 길이, r14 = 청크 길이
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::R12D, Register::R12D).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R13, stub.code_len as u64).unwrap(), None));
        // ChainLoop: 남은 길이 검사
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::R13, Register::R13).unwrap(), Some(Label::ChainLoop)));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::ChainDone)));
        // 키 포인터 = (off==0 ? seed_va : code_va + off - 0x100)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::R12).unwrap(), None));
        seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::RCX, 0x100).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::R12, Register::R12).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::ChainKeyOk)));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.seed_va).unwrap(), None));
        // ChainKeyOk: KSA(key=[rcx], 256B) → S-box@rbx
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x100).unwrap(), Some(Label::ChainKeyOk)));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Ksa)));
        // 청크 길이 = min(0x100, r13) → r14
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R14, 0x100).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmp_rm64_imm32, Register::R13, 0x100).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmovb_r64_rm64, Register::R14, Register::R13).unwrap(), None));
        // 청크 포인터 = code_va + off
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::R12).unwrap(), None));
        // PRGA i/j 초기화 + 복호화
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R14).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::R12, Register::R14).unwrap(), None));
        seq.push((Instruction::with2(Code::Sub_rm64_r64, Register::R13, Register::R14).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::ChainLoop)));
        // ChainDone: 문자열 런 키 = (code_len >= 256 ? code_va + code_len - 256 : seed_va)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R11, stub.code_len as u64).unwrap(), Some(Label::ChainDone)));
        seq.push((Instruction::with2(Code::Cmp_rm64_imm32, Register::R11, 0x100).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::StrKeyUseWindow)));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::RCX, 0x100).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::StrKeyHave)));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.seed_va).unwrap(), Some(Label::StrKeyUseWindow)));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x100).unwrap(), Some(Label::StrKeyHave)));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Ksa)));
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None));
    } else {
        // v15: 비-chained(재암호화/평문/VM) 경로에도 fail-deceptive 인증 게이트를
        // 적용한다. chained 경로와 동일한 PEB 3검 + RDTSC 타이밍으로 디버거/에뮬레이터를
        // 탐지하고, 실패 시 **S-box(스택 프레임, RBX)를 0x5A로 XOR 변조**해 이후 모든
        // PRGA/문자열/리졸브 복호화를 쓰레기로 만든다. (이 경로는 KSA를 1회만 수행하므로
        // 시드 대신 이미 생성된 S-box를 깨야 한다.) cdb/에뮬레이터로 실행하면 깨끗한
        // 감지 대신 자연스러운 오류로 동작(fail-deceptive).
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None)); // PEB
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 2)).unwrap(), None)); // BeingDebugged
        seq.push((Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 0xBC)).unwrap(), None)); // NtGlobalFlag
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x70).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ(Register::RAX, 0x30)).unwrap(), None)); // ProcessHeap
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 0x70)).unwrap(), None)); // Heap.Flags
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x70).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        // 타이밍: 10만회 루프가 너무 빠르면(에뮬/튜닝) 실패
        seq.push((Instruction::with(Code::Rdtsc), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ESI, Register::EAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0x186A0).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm32, Register::ECX).unwrap(), Some(Label::AttestTiming)));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestTiming)));
        seq.push((Instruction::with(Code::Rdtsc), None));
        seq.push((Instruction::with2(Code::Sub_rm32_r32, Register::EAX, Register::ESI).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 5000).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::AttestOk)));
        // AttestFail: S-box(RBX, 256B)를 0x5A로 XOR → 이후 복호화 전부 쓰레기
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDI, Register::RBX).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0x100).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_rm8_imm8, MemoryOperand::with_base(Register::RDI), 0x5Au32).unwrap(), Some(Label::AttestMutLoop)));
        seq.push((Instruction::with1(Code::Inc_rm64, Register::RDI).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm32, Register::ECX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestMutLoop)));
        seq.push((Instruction::with(Code::Nopd), Some(Label::AttestOk)));

        // PRGA i,j 초기화 (canonical RC4: j=0에서 시작) — 복사 블록 이후에 수행해
        // 어떤 복사 경로가 RSI/RDI를 쓰더라도 RC4 i/j 카운터가 보존되게 한다.
        // (v60 --custom-cipher: BTG-C1 blob은 자체 상태를 쓰므로 RC4 i/j 불필요.
        //  v63 --crypto-mode chacha20: ChaCha20 blob도 자체 상태를 쓴다.)
        if !stub.c1_mode() && !stub.chacha_mode() {
            seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None));
            seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None));
        }

        // ── 코드 영역 복호화 ──
        // v8(Phase 0.3): 재암호화 모드에서는 생략 — 블록이 개별 암호화 상태로
        // 남고 디스패처가 런타임에 복호화/재암호화한다. 문자열 런 키스트림은
        // 패커와 동일하게 "영역 없이 시작"하므로 이 스텁의 런 복호화와 일치한다.
        if !stub.reencrypt {
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.code_len as u64).unwrap(), None));
            if stub.c1_mode() {
                emit_c1_call(seq, stub);
            } else if stub.chacha_mode() {
                emit_chacha_call(seq, stub);
            } else if stub.vm_prga {
                vm_embed::emit_prga_vm_init(seq, stub);
                vm_embed::emit_prga_vm_call(seq, stub);
            } else {
                seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
            }
        }
    }
    } // ── end: !stub.no_crypto (코드 영역 복호화 생략) ──────────────────────────
}

pub(crate) fn emit_run_decrypt(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── 문자열 런 복호화 루프 ──
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RBP, stub.runs_va).unwrap(), Some(Label::CrcOk)));
    seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R11D, stub.num_runs).unwrap(), None));
    seq.push((Instruction::with2(Code::Test_rm64_r64, Register::R11, Register::R11).unwrap(), Some(Label::RunLoop)));
    seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::RunDone)));
    seq.push((
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RCX,
            MemoryOperand::with_base_displ(Register::RBP, 0),
        ).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RDX,
            MemoryOperand::with_base_displ(Register::RBP, 8),
        ).unwrap(),
        None,
    ));
    if stub.c1_mode() {
        emit_c1_call(seq, stub);
    } else if stub.chacha_mode() {
        emit_chacha_call(seq, stub);
    } else if stub.vm_prga {
        vm_embed::emit_prga_vm_call(seq, stub);
    } else {
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
    }
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RBP, 16).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm64, Register::R11).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::RunLoop)));
    // run_done — NOP로 자리만 표시 (실제로는 다음 명령으로 fall-through)
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::R11D, Register::R11D).unwrap(), Some(Label::RunDone)));
}

/// M6 Phase-2.3 (--vm-oep at-rest encryption): Program VM 바이트코드와 (TLS
/// 콜백 없는 경우) 보존된 원본 .text를 부트 스텁이 디스패치 직전에 복호화한다.
/// 두 영역은 패커에서 fresh RC4(seed_stored) 하나로 `.text` → bytecode 순으로
/// 연속 암호화되어 파일에는 평문이 없고, 이 블록이 실행되기 전까지 실행 불가능한
/// 암호문 상태로 남는다.
///
/// 키스트림 동치: 패커 `Rc4::new(seed_stored)`(canonical PRGA i=j=0 시작)와
/// 동일하게 `Ksa(key=seed@seed_va)` 후 ESI/EDI=0 재설정 → `Prga(.text)` →
/// `Prga(bytecode)` 연속 호출로 복호화한다. (S-box base는 RSP — RBX를 재확정.)
///
/// 길이 불변성: 이 블록은 `stub.vm_oep`일 때 항상 전체를 emit한다 (len/va는
/// imm이므로 값이 달라도 인코딩 길이가 동일). 이렇게 해야 부트 스텁 3-pass
/// sizing(초기 len=0 vs 최종 len)이 일치해 `stub size changed` 불변식이 깨지지
/// 않는다. len=0 범위는 `Prga`가 즉시 반환(Test RDX; Je)하므로 no-op이다.
pub(crate) fn emit_rest_decrypt(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    if !stub.vm_oep {
        return;
    }
    // fresh KSA: S-box base(RBX) = RSP, key = seed_va(256B)
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.seed_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x100).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Ksa)));
    // canonical RC4 PRGA: i=0, j=0에서 시작
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None));
    // P5: loop over .text at-rest decrypt run-table (va,len u64 pairs). Fresh
    // keystream is continuous across runs -> same order/lengths as the packer
    // encrypted them. count==0 -> immediate no-op (bytecode-only).
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RBP, stub.vm_oep_text_runs_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R11D, stub.vm_oep_text_runs_count).unwrap(), None));
    seq.push((Instruction::with2(Code::Test_rm64_r64, Register::R11, Register::R11).unwrap(), Some(Label::TextRunLoop)));
    seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::TextRunDone)));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, MemoryOperand::with_base_displ(Register::RBP, 0)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, MemoryOperand::with_base_displ(Register::RBP, 8)).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RBP, 16).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm64, Register::R11).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::TextRunLoop)));
    seq.push((Instruction::with(Code::Nopd), Some(Label::TextRunDone)));
    // bytecode 복호화 (len=0이면 no-op)
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.vm_oep_bc_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.vm_oep_bc_len as u64).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
}

pub(crate) fn emit_self_wipe(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v7 chained-crypto: 자기파괴 (시드/S-box/페이로드 원본 소거) ────────────
    // v18(anti-dump): 복호화가 끝난 뒤 키 재료를 지워 "런타임 덤프 → 재복호화"를
    // 차단한다. 기존엔 chained 경로에만 있었지만, 정적/덤프 분석에서 seed/S-box를
    // 탈취해 RC4를 재구성하는 공격을 막기 위해 **모든 crypto 경로**(chained/reencrypt/
    // vm)로 확장한다. (seed_va/S-box는 문자열 런·리졸브 테이블 복호화에만 쓰이고
    //  디스패처의 블록 키는 entry_seed 기반이라 지워도 안전. reencrypt는 mem-harden과
    //  동시에 안 켜지므로 RX 전환 순서 문제도 없다.)
    // ⚠ mem-harden(RX 전환) **이전에** 수행해야 한다 — RX 페이지에 시드를
    // 소거하면 0xC0000005가 난다 (순서 버그 수정).
    if !stub.no_crypto {
        // seed (256B)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.seed_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x100).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::ZeroMem)));
        // S-box (스택 프레임) — ⚠ RBX는 iat-resolve에서 import-name 인덱스로
        // 재사용되어 더 이상 S-box base가 아니므로, 프레임 base(=RSP, 아직 해제 전)
        // 로 직접 지정한다. (이 지점에선 아직 add rsp가 실행 전이라 RSP == 프레임 base.)
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RSP).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x100).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::ZeroMem)));
        // ⚠ 페이로드 원본(.vdata) 소거는 생략 — .vdata가 read-only(R)로 매핑되어
        //   쓰면 0xC0000005. 어차피 seed/S-box를 지우면 RC4 keystream을 재구성할 수
        //   없어 덤프→재복호화는 불가능하므로, R-only .vdata는 그대로 둔다.
        // v60 (--custom-cipher): BTG-C1 상태 버퍼(key/ctr/nonce/ks)도 소거해
        //   덤프에서 키스트림을 재구성하지 못하게 한다. (S-box 상수 테이블은
        //   고정 상수라 소거 불필요 — 키가 없으면 무의미.)
        if stub.c1_mode() {
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.c1_state_va).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x80).unwrap(), None));
            seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::ZeroMem)));
        }
        // v63 (--crypto-mode chacha20): ChaCha20 상태 버퍼(key/ctr/nonce/ks) 소거 —
        //   덤프에서 키스트림 재구성/재복호화를 차단. (blob은 상태가 없어 소거 불필요.)
        if stub.chacha_mode() {
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.chacha_state_va).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x80).unwrap(), None));
            seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::ZeroMem)));
        }
    }
}

pub(crate) fn emit_dispatcher_entry(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── 스택 정리 + 디스패처 진입 ──
    // v8(Phase 0.3): 디스패처 3-푸시 규약 [seed][target_id][current_id].
    // 첫 디스패치에는 직전 블록이 없으므로 current = 0xFFFFFFFF(센티널)을 push한다.
    // M6 Phase-2(--vm-oep): 부트 스텁이 원본 .text를 평문 복호화하지 않고
    // lift된 프로그램 VM으로 디스패치한다. (RCX=프로그램 VM state, jmp 프로그램 VM entry)
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RSP, stub.stack_frame).unwrap(), None));
    if stub.vm_oep {
        // 프로그램 VM 진입 직전: 복원된 원본 스택(RSP)을 vRSP(v4) 및 STATE_PTR_STACK에 기록.
        use iced_x86::MemoryOperand as M;
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.vm_prog_state_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, (crate::vm::interp::STATE_VREGS as i64) + 4*8), Register::RSP).unwrap(), None));
        // vreg[4] = RSP is the single VM stack pointer (single-stack fix); the
        // call/ret/push/pop handlers read/write it directly, so STATE_SP/PTR_STACK
        // are intentionally left unused.

        if stub.vm_oep_native_entry {
            // 로더가 제공한 entry context를 정확히 복원한다. 임의로 레지스터를 0으로
            // 만드는 것은 Windows entry 계약이 아니며 CRT/TLS 초기 상태를 바꿀 수 있다.
            for r in [
                Register::R15,
                Register::R14,
                Register::R13,
                Register::R12,
                Register::R11,
                Register::R10,
                Register::R9,
                Register::R8,
                Register::RDI,
                Register::RSI,
                Register::RBP,
                Register::RBX,
                Register::RDX,
                Register::RCX,
                Register::RAX,
            ] {
                seq.push((Instruction::with1(Code::Pop_r64, r).unwrap(), None));
            }
            seq.push((Instruction::with(Code::Popfq), None));
            // 상대 tail-jump를 사용해야 복원한 RAX를 포함한 모든 GPR이 그대로 유지된다.
            seq.push((Instruction::with_branch(Code::Jmp_rel32_64, stub.vm_oep_native_va).unwrap(), None));
        } else {
            // 프로그램 VM: state 포인터를 RCX로 전달하고 프로그램 VM 엔트리로 점프.
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.vm_prog_state_va).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.vm_prog_entry_va).unwrap(), None));
            seq.push((Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap(), None));
        }
    } else {
    if stub.reencrypt {
        seq.push((Instruction::with1(Code::Pushq_imm32, -1).unwrap(), None));
    }
    seq.push((Instruction::with1(Code::Pushq_imm32, stub.entry_block_id as i32).unwrap(), None));
    seq.push((Instruction::with1(Code::Pushq_imm32, stub.entry_seed as i32).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.dispatcher_va).unwrap(), None));
    seq.push((Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap(), None));
    }
}