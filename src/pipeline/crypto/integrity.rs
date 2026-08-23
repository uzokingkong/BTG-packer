// ==============================================================================
// Integrity (--integrity): CRC32 + keyed-MAC over the code region (boot-time tamper check)
// ==============================================================================

use super::bootstub::{BootStubCtx, Label};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

/// 표준 반사형 CRC-32 (poly 0xEDB88320) — 부트 스텁의 검증 루틴과 동일 알고리즘.
/// `--integrity`에서 평문 코드 영역에 대해 계산해 부트 영역에 저장한다.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Pack-time value consumed by the native CRC4 verifier.
///
/// The verifier executes `mov r11d, [w32_slot]; rol r11d, 13`, so the rotate
/// is intentionally 32-bit. Keep this helper shared with placement code to
/// prevent packer/runtime width drift.
pub(crate) fn crc4_stored_value(crc: u32, w32: u32) -> u32 {
    crc ^ w32.rotate_left(13)
}

/// per-build 런타임 유도 whiten key. seed_masked(런타임 seed_va 바이트)에 대한
/// 결정적 폴드 — 부트 스텁이 seed_va에서 같은 폴드를 재계산하므로(integ.rs
/// emit_integrity_mac의 W32 프리엠블), 파일에 저장되는 CRC/MAC 값이 평문이
/// 아니라 whiten되어 .rdata 스캔으로는 원값을 노출하지 않는다. 값이 0이면
/// whiten이 없어지므로 시드가 균일한 0인 경우를 배제하기 위해 고정 상수를
/// 마지막에 XOR한다.
pub fn derive_whiten_key(seed: &[u8]) -> u32 {
    let mut w: u32 = 0;
    for (i, &b) in seed.iter().enumerate() {
        w = w.rotate_left(3)
            ^ (b as u32).wrapping_mul(0x9E37_79B9)
            ^ (i as u32).wrapping_mul(0x9E37_79B9);
    }
    w.rotate_left(13) ^ 0xA5A5_5A5A
}

/// runtime-derived **multi-factor** whiten key: folds seed_masked(256B, 런타임
/// seed_va — base_bind_loop 후 실제 상태) **그리고** PEB.ImageBaseAddress low/high
/// bind 바이트를 함께 폴드한다. 패커는 preferred base(`image_base`)를, 부트 스텁은
/// 실행 시 PEB.ImageBaseAddress를 읽는다 — at-rest 암호화가 ASLR(relocation-aware
/// 출력)을 비활성화하므로 두 값은 동일하다. 저장되는 CRC/MAC/사이트3/4 기대값이
/// 정적 파일 시드뿐 아니라 로드 base(런타임 상태)의 함수가 되어, 공격자가 파일만으로
/// 기대값을 재계산·재기록하는 §3.4 재계산 공격을 어렵게 한다. **lockstep**: 부트 스텁
/// W32 프리엠블(emit_integrity_mac WhitenLoop)이 시드 루프 뒤 같은 bind 폴드를 수행
/// (w ^= rol(bind*PHI32, bind&31))한다.
pub fn derive_integrity_key(seed: &[u8], image_base: u64) -> u32 {
    let mut w = derive_whiten_key(seed);
    let bind = super::bootstub::base_bind_byte(image_base);
    w ^= (bind as u32)
        .wrapping_mul(0x9E37_79B9)
        .rotate_left(bind as u32 & 31);
    w
}

pub(crate) fn emit_integrity_crc(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v5 --integrity: 복호화된 코드 영역 CRC32 검증 (불일치 시 ud2) ──────────
    // 표준 반사형 CRC-32 (poly 0xEDB88320). packer가 패킹 시 계산해 seed 뒤에
    // 저장한 값과 비교한다. 파일의 암호화 바이트가 변조되면 복호화 결과가
    // 깨져 CRC 불일치 → ud2로 강제 종료 (안티-패치).
    if stub.integrity {
        // 저장된 CRC32 값 주소 (imm64 — 길이 불변)
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R10, stub.crc_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0xFFFF_FFFFu32).unwrap(),
            None,
        ));
        // M12: 디스크립터에서 code_va/code_len 로드 (EAX는 라이브 CRC — 스크래치 불가,
        // RBP는 여기서 free). no_crypto는 스텁이 디스크립터를 복호화하지 않으므로 imm64 유지.
        if !stub.no_crypto {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RBP, stub.desc_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RCX,
                    MemoryOperand::with_base_displ(Register::RBP, 0x00),
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RDX,
                    MemoryOperand::with_base_displ(Register::RBP, 0x08),
                )
                .unwrap(),
                None,
            ));
        } else {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.code_len as u64)
                    .unwrap(),
                None,
            ));
        }
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::CrcDone),
        ));
        seq.push((
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::R8D,
                MemoryOperand::with_base(Register::RCX),
            )
            .unwrap(),
            Some(Label::CrcLoop),
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm8_r8, Register::AL, Register::R8L).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 8).unwrap(),
            None,
        ));
        // 8회: crc = (crc >> 1) ^ (LSB ? poly : 0)
        seq.push((
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 1).unwrap(),
            Some(Label::CrcBit),
        ));
        seq.push((
            Instruction::with_branch(Code::Jae_rel32_64, 0).unwrap(),
            Some(Label::CrcSkip),
        )); // jnc
        seq.push((
            Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, 0xEDB8_8320u32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Dec_rm32, Register::R9D).unwrap(),
            Some(Label::CrcSkip),
        ));
        seq.push((
            Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
            Some(Label::CrcBit),
        ));
        seq.push((
            Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
            Some(Label::CrcLoop),
        ));
        seq.push((
            Instruction::with1(Code::Not_rm32, Register::EAX).unwrap(),
            Some(Label::CrcDone),
        ));
        // S1-hardening: CRC 저장값은 crc ^ mac_lo32 (MAC이 R11D에 남긴 값). CRC
        // 단독으로 패치해도 MAC 결합 값이 일치하지 않아 통과 불가 (CRC↔MAC 결합).
        seq.push((
            Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::R11D).unwrap(),
            None,
        ));
        // S1-hardening (runtime-derived interlock): `cmp` 대신 `xor`로 저장값을
        // 소비해 tamper 결과 V1 = computed ^ stored 를 EAX에 남기고 ZF를 세운다.
        // `je`는 그대로 검증 분기지만, R14=V1 이 문자열 런/IAT 복호화의 poison
        // key(emit_run_decrypt)로 소비되므로 단일 바이트로 `je`를 패치해도 V1≠0
        // → 런/IAT가 쓰레기로 복호화되어 크래시. (legit: V1=0 → 런 바이트 불변.
        // mov는 ZF를 건드리지 않는다.)
        seq.push((
            Instruction::with2(
                Code::Xor_r32_rm32,
                Register::EAX,
                MemoryOperand::with_base(Register::R10),
            )
            .unwrap(),
            None,
        )); // V1 = computed ^ stored
        seq.push((
            Instruction::with2(Code::Mov_r32_rm32, Register::R14D, Register::EAX).unwrap(),
            None,
        )); // poison key (zero-extended)
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::CrcOk),
        ));
        seq.push((Instruction::with(Code::Ud2), None));
    }
}

/// Verify the serialized BTGI family-region table after the transient boot
/// cipher has restored the Program-VM bytecode to its persistent M7 form.
pub(crate) fn emit_distributed_integrity(
    seq: &mut Vec<(Instruction, Option<Label>)>,
    stub: &BootStubCtx,
) {
    // In VM/RC4 mode Poly1305 is inactive, so poly_tag_va is an available
    // build-context carrier for the BTGI table address without widening the
    // already-stable BootStubCtx ABI used by older modes.
    let table_va = stub.poly_tag_va;
    if !stub.integrity || !stub.vm_oep || table_va == 0 || stub.chacha_mode() {
        return;
    }
    // This verifier runs in the middle of the boot pipeline. Later integrity
    // stages consume several of these registers as live secret/state values,
    // so the descriptor walk must be observationally transparent on success.
    let saved = [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RBP,
        Register::R8,
        Register::R10,
        Register::R11,
        Register::R15,
    ];
    for register in saved {
        seq.push((Instruction::with1(Code::Push_r64, register).unwrap(), None));
    }
    let m = MemoryOperand::with_base_displ;
    seq.push((
        Instruction::with2(Code::Mov_r64_imm64, Register::RBP, table_va).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Cmp_rm32_imm32, m(Register::RBP, 0), 0x4947_5442u32).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(Label::DistMagicOk),
    ));
    seq.push((Instruction::with(Code::Ud2), None));
    seq.push((Instruction::with(Code::Nopd), Some(Label::DistMagicOk)));
    seq.push((
        Instruction::with2(Code::Mov_r32_rm32, Register::R15D, m(Register::RBP, 4)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_imm32, Register::RBP, 8).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Test_rm64_r64, Register::R15, Register::R15).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
        Some(Label::DistCountOk),
    ));
    seq.push((Instruction::with(Code::Ud2), None));
    seq.push((Instruction::with(Code::Nopd), Some(Label::DistCountOk)));
    seq.push((
        Instruction::with2(Code::Cmp_rm32_imm32, Register::R15D, 13).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(),
        Some(Label::DistDescLoop),
    ));
    seq.push((Instruction::with(Code::Ud2), None));
    seq.push((
        Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::RBP, 8)).unwrap(),
        Some(Label::DistDescLoop),
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::RBP, 16)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RDX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::RBP, 32)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R10).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_imm64, Register::R11, 0xCBF2_9CE4_8422_2325u64).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R11).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_imm64, Register::R11, 0x0000_0100_0000_01B3u64).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(Label::DistByteDone),
    ));
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R8D,
            MemoryOperand::with_base(Register::RCX),
        )
        .unwrap(),
        Some(Label::DistByteLoop),
    ));
    seq.push((
        Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R8).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::R11).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
        Some(Label::DistByteLoop),
    ));
    seq.push((Instruction::with(Code::Nopd), Some(Label::DistByteDone)));
    seq.push((
        Instruction::with2(Code::Cmp_r64_rm64, Register::RAX, m(Register::RBP, 24)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(Label::DistDescOk),
    ));
    seq.push((Instruction::with(Code::Ud2), None));
    seq.push((
        Instruction::with2(Code::Add_rm64_imm32, Register::RBP, 40).unwrap(),
        Some(Label::DistDescOk),
    ));
    seq.push((
        Instruction::with1(Code::Dec_rm64, Register::R15).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
        Some(Label::DistDescLoop),
    ));
    seq.push((Instruction::with(Code::Nopd), Some(Label::DistAllOk)));
    for register in saved.into_iter().rev() {
        seq.push((Instruction::with1(Code::Pop_r64, register).unwrap(), None));
    }
}

/// ── S1 (T2-3): keyed-MAC 런타임 검증 (불일치 시 ud2) ───────────────────────────
/// 부트 스텁이 패킹 시 `BtgKeyedMac::mac(seed_stored, crc_source)`로 저장한
/// 8바이트 MAC 값을 런타임에 재계산해 비교한다. CRC32(키 없음)와 달리 키 결합
/// MAC이라 데이터+MAC을 함께 변조해도 통과할 수 없다 (2^-64).
///
/// **키 재구성**: 파일의 seed_stored는 base_bind_loop가 실제 base로 XOR해 메모리
/// 상 seed_masked가 된다. 런타임 MAC 키 = `seed_va[i] ^ bind_byte`로 다시
/// seed_stored와 일치시킨다 (actual_base == image_base 가정 — at-rest 암호화는
/// ASLR을 비활성화하므로 성립). 데이터 = 코드 영역 [code_va, code_va+code_len)
/// — 패킹 시 crc_source와 동일 바이트 (reencrypt=파일 암호문, 그 외=평문).
///
/// **배치**: `emit_integrity_crc` **직전**에 emit된다. CRC의 성공 분기(`je CrcOk`)
/// 는 `emit_run_decrypt` 시작으로 앞으로 점프하므로, CRC 뒤에 두면 성공 경로에서
/// MAC이 통째로 건너뛰어진다. 코드 복호화 직후 + CRC와 같은 시점/영역에서 계산하면
/// 데이터 동치가 유지된다.
///
/// **길이 불변성**: 모든 상수/주소는 imm64/imm32, 분기는 rel32 — 값과 무관 고정
/// 길이. RBX(S-box base)와 RSP는 건드리지 않는다. (나머지 GPR은 이후 경로가 다시
/// 초기화하므로 스크래치로 안전.)
pub(crate) fn emit_integrity_mac(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    use iced_x86::MemoryOperand as M;
    const PHI: u64 = 0x9E37_79B9_7F4A_7C15u64;
    if stub.integrity {
        // FIX(full-combo string corruption): the MAC is emitted between
        // emit_code_decrypt and emit_run_decrypt. emit_code_decrypt leaves the
        // RC4 PRGA i/j state in ESI/EDI (chained: zeroed at ChainDone; non-chained:
        // mid-stream after the code-region Prga), and emit_run_decrypt continues
        // that keystream to decrypt the string literals. The MAC clobbers RSI
        // (seed_va/mac_va pointers) and RDI (h1), so without saving them the
        // string runs decrypt to garbage. Preserve RSI/RDI across the MAC.
        seq.push((
            Instruction::with1(Code::Push_r64, Register::RSI).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Push_r64, Register::RDI).unwrap(),
            None,
        ));
        // ── W32 whiten-key 유도 (R15D): seed_va(런타임 seed_masked)를 폴드해
        //    derive_whiten_key(seed_masked)와 동일 값을 만든다. 저장된 CRC/MAC
        //    값은 이 값으로 whiten되므로 파일에서 평문이 아니다. R15는 여기서부터
        //    site-2(emit_integrity_crc2)까지 생존한다 (run/rest decrypt는 R15를
        //    건드리지 않는다). RSI/R8D/EAX는 이후 Phase A가 재초기화하므로 스크래치.
        //    (imul/rol/cmp/jb — 전부 고정 길이, 값과 무관)
        seq.push((
            Instruction::with2(Code::Xor_r32_rm32, Register::R15D, Register::R15D).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.seed_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Xor_r32_rm32, Register::R8D, Register::R8D).unwrap(),
            None,
        )); // i = 0 (카운터)
        seq.push((
            Instruction::with2(Code::Xor_r32_rm32, Register::ECX, Register::ECX).unwrap(),
            None,
        )); // i*PHI = 0 (누적)
            // WhitenLoop:
        seq.push((
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::EAX,
                M::with_base(Register::RSI),
            )
            .unwrap(),
            Some(Label::WhitenLoop),
        ));
        seq.push((
            Instruction::with3(
                Code::Imul_r32_rm32_imm32,
                Register::EAX,
                Register::EAX,
                0x9E37_79B9u32 as i32,
            )
            .unwrap(),
            None,
        )); // b*PHI32
        seq.push((
            Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::ECX).unwrap(),
            None,
        )); // ^ (i*PHI32)
        seq.push((
            Instruction::with2(Code::Rol_rm32_imm8, Register::R15D, 3).unwrap(),
            None,
        )); // w=rol(w,3)
        seq.push((
            Instruction::with2(Code::Xor_rm32_r32, Register::R15D, Register::EAX).unwrap(),
            None,
        )); // w ^= ...
        seq.push((
            Instruction::with1(Code::Inc_rm64, Register::RSI).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Inc_rm32, Register::R8D).unwrap(),
            None,
        )); // i++
        seq.push((
            Instruction::with2(Code::Add_rm32_imm32, Register::ECX, 0x9E37_79B9u32 as i32).unwrap(),
            None,
        )); // i*PHI += PHI
        seq.push((
            Instruction::with2(Code::Cmp_rm32_imm32, Register::R8D, 256).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(),
            Some(Label::WhitenLoop),
        ));
        seq.push((
            Instruction::with2(Code::Rol_rm32_imm8, Register::R15D, 13).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm32_imm32, Register::R15D, 0xA5A5_5A5Au32).unwrap(),
            None,
        ));
        // Load address is deliberately absent from W32. ASLR changes it before
        // bootstrap, while the authenticated image/region identity is stable.
        // S3/S4 확장: W32(R15)를 스크래치 슬롯(w32_slot)에 저장 — 사이트 3/4가
        // R15가 IAT 리졸브 등에서 클로버된 뒤에도 같은 runtime-derived whiten을
        // 재사용한다. RAX는 직후 bind_byte 유도에서 즉시 덮어쓰므로 안전.
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.w32_slot_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base(Register::RAX),
                Register::R15D,
            )
            .unwrap(),
            None,
        ));
        // R10 = PHI ; RBP = h0 ; RDI = h1 (초기 상태)
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R10, PHI).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RBP, 0x6A09_E667_F3BC_C909u64)
                .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RDI, 0xBB67_AE85_84CA_A73Bu64)
                .unwrap(),
            None,
        ));

        // Cryptographic identity is based on the preferred image identity and
        // therefore remains stable when ASLR changes the runtime load address.
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::R11D, 0).unwrap(),
            None,
        ));

        // ── Phase A: 키(seed_stored) 흡수 — 256바이트 루프 ────────────────────
        // R9 = init i-계수 0x100000001B3 (Phase A — must match packer BtgKeyedMac::new)
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R9, 0x100_0000_01B3u64).unwrap(),
            None,
        ));
        // RSI = seed_va ; R8D = i = 0
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.seed_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Xor_r32_rm32, Register::R8D, Register::R8D).unwrap(),
            None,
        ));
        // MacInitLoop:
        seq.push((
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::EAX,
                M::with_base(Register::RSI),
            )
            .unwrap(),
            Some(Label::MacInitLoop),
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm8_r8, Register::AL, Register::R11L).unwrap(),
            None,
        )); // b = seed ^ bind_byte
            // FIX: compute rol(h0,i&63) into RAX (CL=shift count) BEFORE building
            // RCX=b*PHI, and preserve b in RDX — otherwise `mov cl, dl` clobbers the
            // low byte of RCX holding b*PHI, corrupting the MAC (packer vs runtime mismatch).
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(),
            None,
        )); // rdx = b
        seq.push((
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R8D).unwrap(),
            None,
        )); // ecx = i
        seq.push((
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap(),
            None,
        )); // cl = i&63
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RBP).unwrap(),
            None,
        )); // rax = h0
        seq.push((
            Instruction::with2(Code::Rol_rm64_CL, Register::RAX, Register::CL).unwrap(),
            None,
        )); // rax = rol(h0, i&63)
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RDX).unwrap(),
            None,
        )); // rcx = b
        seq.push((
            Instruction::with2(Code::Imul_r64_rm64, Register::RCX, Register::R10).unwrap(),
            None,
        )); // rcx = b*PHI
        seq.push((
            Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::RAX).unwrap(),
            None,
        )); // rcx = b*PHI + rol(h0,i&63)
            // rcx += i*0x100000001B3
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R8).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::R9).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::RAX).unwrap(),
            None,
        ));
        // h1 ^= rcx
        seq.push((
            Instruction::with2(Code::Xor_rm64_r64, Register::RDI, Register::RCX).unwrap(),
            None,
        ));
        // h1 = rol(h1,23)*PHI + h0
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 23).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Rol_rm64_CL, Register::RDI, Register::CL).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Imul_r64_rm64, Register::RDI, Register::R10).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_r64, Register::RDI, Register::RBP).unwrap(),
            None,
        ));
        // h0 = rol(h0,17) ^ h1
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 17).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Rol_rm64_CL, Register::RBP, Register::CL).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm64_r64, Register::RBP, Register::RDI).unwrap(),
            None,
        ));
        // advance + loop
        seq.push((
            Instruction::with1(Code::Inc_rm64, Register::RSI).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Inc_rm32, Register::R8D).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Cmp_rm32_imm32, Register::R8D, 256).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(),
            Some(Label::MacInitLoop),
        ));

        // ── Phase B: 코드 영역 데이터 흡수 ────────────────────────────────────
        // R9 = update i-계수 0x9E3779B9 (r32 mov는 zero-extend)
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 0x9E37_79B9u32).unwrap(),
            None,
        ));
        // RSI = code_va ; R8D = i = 0 ; RDX = code_len
        if !stub.no_crypto {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.desc_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RSI,
                    MemoryOperand::with_base_displ(Register::RAX, 0x00),
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Xor_r32_rm32, Register::R8D, Register::R8D).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RDX,
                    MemoryOperand::with_base_displ(Register::RAX, 0x08),
                )
                .unwrap(),
                None,
            ));
        } else {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.code_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Xor_r32_rm32, Register::R8D, Register::R8D).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.code_len as u64)
                    .unwrap(),
                None,
            ));
        }
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::MacDone),
        ));
        // MacDataLoop:
        seq.push((
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::EAX,
                M::with_base(Register::RSI),
            )
            .unwrap(),
            Some(Label::MacDataLoop),
        ));
        // FIX: compute rol(h0,i&63) into RAX (CL=shift count) BEFORE building
        // RCX=b*PHI, and preserve b in RDX — otherwise `mov cl, dl` clobbers the
        // low byte of RCX holding b*PHI, corrupting the MAC (packer vs runtime mismatch).
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(),
            None,
        )); // rdx = b
        seq.push((
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R8D).unwrap(),
            None,
        )); // ecx = i
        seq.push((
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap(),
            None,
        )); // cl = i&63
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RBP).unwrap(),
            None,
        )); // rax = h0
        seq.push((
            Instruction::with2(Code::Rol_rm64_CL, Register::RAX, Register::CL).unwrap(),
            None,
        )); // rax = rol(h0, i&63)
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RDX).unwrap(),
            None,
        )); // rcx = b
        seq.push((
            Instruction::with2(Code::Imul_r64_rm64, Register::RCX, Register::R10).unwrap(),
            None,
        )); // rcx = b*PHI
        seq.push((
            Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::RAX).unwrap(),
            None,
        )); // rcx = b*PHI + rol(h0,i&63)
            // rcx += i*0x9E3779B9
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R8).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::R9).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::RAX).unwrap(),
            None,
        ));
        // h1 ^= rcx
        seq.push((
            Instruction::with2(Code::Xor_rm64_r64, Register::RDI, Register::RCX).unwrap(),
            None,
        ));
        // h1 = rol(h1,17)*PHI + h0
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 17).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Rol_rm64_CL, Register::RDI, Register::CL).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Imul_r64_rm64, Register::RDI, Register::R10).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_r64, Register::RDI, Register::RBP).unwrap(),
            None,
        ));
        // h0 = rol(h0,31) ^ h1
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 31).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Rol_rm64_CL, Register::RBP, Register::CL).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm64_r64, Register::RBP, Register::RDI).unwrap(),
            None,
        ));
        // advance + loop
        seq.push((
            Instruction::with1(Code::Inc_rm64, Register::RSI).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Inc_rm32, Register::R8D).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R8).unwrap(),
            None,
        ));
        if !stub.no_crypto {
            // M12: code_len을 디스크립터에서 로드 (RAX는 i — RDX는 루프 내부에서 free)
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.desc_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RDX,
                    MemoryOperand::with_base_displ(Register::RDX, 0x08),
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Cmp_rm64_r64, Register::RAX, Register::RDX).unwrap(),
                None,
            ));
        } else {
            seq.push((
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, stub.code_len as i64)
                    .unwrap(),
                None,
            ));
        }
        seq.push((
            Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(),
            Some(Label::MacDataLoop),
        ));

        // ── Phase C: finish + 저장값 비교 ─────────────────────────────────────
        seq.push((Instruction::with(Code::Nopd), Some(Label::MacDone)));
        // out = rol(h1,32) ^ h0 ^ rol(h0,47)
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RDI).unwrap(),
            None,
        )); // h1
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Rol_rm64_CL, Register::RAX, Register::CL).unwrap(),
            None,
        )); // rol(h1,32)
        seq.push((
            Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RBP).unwrap(),
            None,
        )); // ^ h0
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RBP).unwrap(),
            None,
        )); // h0
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 47).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Rol_rm64_CL, Register::RDX, Register::CL).unwrap(),
            None,
        )); // rol(h0,47)
        seq.push((
            Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RDX).unwrap(),
            None,
        )); // out
            // S1-hardening: out(R8)의 하위 32비트를 R11D로 남겨 CRC와 결합(CRC 저장값 =
            // crc ^ mac_lo32 — CRC 단독 패치로 우회 불가), 이후 W32(R15)로 whiten해
            // 파일 저장값과 비교 (저장값은 평문 MAC이 아니다).
        seq.push((
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::EAX).unwrap(),
            None,
        )); // mac_lo32
        seq.push((
            Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R15).unwrap(),
            None,
        )); // whiten: mac ^ W32
            // mac_va 저장값(8B)과 비교 — 불일치 시 ud2
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.mac_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Cmp_r64_rm64,
                Register::RAX,
                M::with_base(Register::RSI),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::MacOk),
        ));
        seq.push((Instruction::with(Code::Ud2), None));
        // restore the PRGA i/j state saved at MAC entry (success path only —
        // the ud2 failure path never returns here)
        seq.push((
            Instruction::with1(Code::Pop_r64, Register::RDI).unwrap(),
            Some(Label::MacOk),
        ));
        seq.push((
            Instruction::with1(Code::Pop_r64, Register::RSI).unwrap(),
            None,
        ));
    }
}

/// ── S2 (--integrity multi-site hardening): 두 번째 독립 CRC32 검증 사이트 ──────
/// emit_integrity_crc(사이트 1)와 **다른 지점**(run/rest decrypt 직후)에서 코드
/// 영역 CRC32를 다시 계산해, `crc2_stored = crc ^ W32`(R15에 남은 런타임 유도
/// whiten key)와 비교한다. 사이트 1의 `je`→`jmp` 단일 바이트 패치로는 이 사이트를
/// 무력화할 수 없어, 공격자가 사이트 1을 온전히 우회해도 여기서 트랩된다.
///
/// 길이 불변: 전부 고정 길이 형태 (imm64/imm32/rel32). R15(W32)는 emit_integrity_mac
/// 의 프리엠블에서 유도되어 run/rest decrypt를 지나 여기까지 생존한다. RSI/RDI
/// (PRGA i/j — 이어지는 IAT 복호화가 사용)는 건드리지 않는다. RBX/RSP도 보존.
pub(crate) fn emit_integrity_crc2(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    if stub.integrity {
        // 저장된 CRC2 값 주소 (imm64 — 길이 불변)
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R10, stub.crc2_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0xFFFF_FFFFu32).unwrap(),
            None,
        ));
        // M12: 디스크립터에서 code_va/code_len 로드 (EAX 라이브 CRC → RBP 스크래치)
        if !stub.no_crypto {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RBP, stub.desc_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RCX,
                    MemoryOperand::with_base_displ(Register::RBP, 0x00),
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RDX,
                    MemoryOperand::with_base_displ(Register::RBP, 0x08),
                )
                .unwrap(),
                None,
            ));
        } else {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.code_len as u64)
                    .unwrap(),
                None,
            ));
        }
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::Crc2Done),
        ));
        seq.push((
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::R8D,
                MemoryOperand::with_base(Register::RCX),
            )
            .unwrap(),
            Some(Label::Crc2Loop),
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm8_r8, Register::AL, Register::R8L).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 8).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 1).unwrap(),
            Some(Label::Crc2Bit),
        ));
        seq.push((
            Instruction::with_branch(Code::Jae_rel32_64, 0).unwrap(),
            Some(Label::Crc2Skip),
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, 0xEDB8_8320u32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Dec_rm32, Register::R9D).unwrap(),
            Some(Label::Crc2Skip),
        ));
        seq.push((
            Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
            Some(Label::Crc2Bit),
        ));
        seq.push((
            Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
            Some(Label::Crc2Loop),
        ));
        seq.push((
            Instruction::with1(Code::Not_rm32, Register::EAX).unwrap(),
            Some(Label::Crc2Done),
        ));
        // whiten: crc ^ W32 (R15 — 사이트 1 MAC 프리엠블에서 유도). 저장값 = crc ^ W32.
        seq.push((
            Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::R15D).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Cmp_r32_rm32,
                Register::EAX,
                MemoryOperand::with_base(Register::R10),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::Crc2Ok),
        ));
        seq.push((Instruction::with(Code::Ud2), None));
        seq.push((Instruction::with(Code::Nopd), Some(Label::Crc2Ok)));
    }
}

/// ── S3 (--integrity 멀티사이트 확장): IAT 리졸브 직후의 세 번째 독립 CRC32 검증 ──
/// 사이트 1/2와 **다른 시점**(부트 후반, IAT 해석이 끝난 뒤)에 코드 영역 CRC32를
/// 재계산한다. whiten은 w32_slot에 보존된 W32(runtime-derived)를 R15 클로버 뒤에도
/// 재사용한다. 사이트 1의 `je`→`jmp` 단일 바이트 패치로는 이 후반 사이트를 무력화
/// 할 수 없어, 부트 전체에 걸쳐 검증 지점이 분산된다 (다중 위치 체크섬).
/// 길이 불변: 전부 고정 길이 형태. 사이트 3는 self-wipe 직전에 실행되므로 이후
/// 경로가 쓰는 레지스터는 자유롭게 스크래치로 써도 된다.
pub(crate) fn emit_integrity_crc3(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    if stub.integrity {
        // 저장된 CRC3 값 주소 (imm64 — 길이 불변)
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R10, stub.crc3_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0xFFFF_FFFFu32).unwrap(),
            None,
        ));
        // M12: 디스크립터에서 code_va/code_len 로드 (EAX 라이브 CRC → RBP 스크래치)
        if !stub.no_crypto {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RBP, stub.desc_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RCX,
                    MemoryOperand::with_base_displ(Register::RBP, 0x00),
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RDX,
                    MemoryOperand::with_base_displ(Register::RBP, 0x08),
                )
                .unwrap(),
                None,
            ));
        } else {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.code_len as u64)
                    .unwrap(),
                None,
            ));
        }
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::Crc3Done),
        ));
        seq.push((
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::R8D,
                MemoryOperand::with_base(Register::RCX),
            )
            .unwrap(),
            Some(Label::Crc3Loop),
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm8_r8, Register::AL, Register::R8L).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 8).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 1).unwrap(),
            Some(Label::Crc3Bit),
        ));
        seq.push((
            Instruction::with_branch(Code::Jae_rel32_64, 0).unwrap(),
            Some(Label::Crc3Skip),
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, 0xEDB8_8320u32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Dec_rm32, Register::R9D).unwrap(),
            Some(Label::Crc3Skip),
        ));
        seq.push((
            Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
            Some(Label::Crc3Bit),
        ));
        seq.push((
            Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
            Some(Label::Crc3Loop),
        ));
        seq.push((
            Instruction::with1(Code::Not_rm32, Register::EAX).unwrap(),
            Some(Label::Crc3Done),
        ));
        // whiten: crc ^ W32 (w32_slot — MAC 프리엠블이 저장한 runtime-derived 값).
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R9, stub.w32_slot_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Xor_r32_rm32,
                Register::EAX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            None,
        ));
        // tamper 결과 V3 = (crc ^ W32) ^ crc3_stored → EAX + ZF (xor 기반 — 단일
        // 바이트로 분기를 패치해도 이후 디스패처로 이어지는 검증 값이 무효화된다).
        seq.push((
            Instruction::with2(
                Code::Xor_r32_rm32,
                Register::EAX,
                MemoryOperand::with_base(Register::R10),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::Crc3Ok),
        ));
        seq.push((Instruction::with(Code::Ud2), None));
        seq.push((Instruction::with(Code::Nopd), Some(Label::Crc3Ok)));
    }
}

/// ── S4 (--integrity 멀티사이트 확장): 디스패처 진입 직전의 네 번째 독립 CRC32 검증 ──
/// 가장 마지막에 위치해, 앞선 사이트 1~3의 `je`를 전부 패치한 공격자를 다시 트랩한다.
/// whiten은 w32_slot의 W32를 **롤링 변형**(rol 13)해 사이트 3와 다른 값으로 결합 —
/// 사이트별 저장값이 전부 달라 한 상수 스캔으로 일괄 무력화할 수 없다.
/// 길이 불변: 전부 고정 길이 형태. R11/R9/R10/RCX/RDX/EAX/R8는 디스패치 진입 전
/// 스크래치로 안전.
pub(crate) fn emit_integrity_crc4(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    if stub.integrity {
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R10, stub.crc4_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0xFFFF_FFFFu32).unwrap(),
            None,
        ));
        // M12: 디스크립터에서 code_va/code_len 로드 (EAX 라이브 CRC → RBP 스크래치)
        if !stub.no_crypto {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RBP, stub.desc_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RCX,
                    MemoryOperand::with_base_displ(Register::RBP, 0x00),
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RDX,
                    MemoryOperand::with_base_displ(Register::RBP, 0x08),
                )
                .unwrap(),
                None,
            ));
        } else {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.code_len as u64)
                    .unwrap(),
                None,
            ));
        }
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::Crc4Done),
        ));
        seq.push((
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::R8D,
                MemoryOperand::with_base(Register::RCX),
            )
            .unwrap(),
            Some(Label::Crc4Loop),
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm8_r8, Register::AL, Register::R8L).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 8).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 1).unwrap(),
            Some(Label::Crc4Bit),
        ));
        seq.push((
            Instruction::with_branch(Code::Jae_rel32_64, 0).unwrap(),
            Some(Label::Crc4Skip),
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, 0xEDB8_8320u32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Dec_rm32, Register::R9D).unwrap(),
            Some(Label::Crc4Skip),
        ));
        seq.push((
            Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
            Some(Label::Crc4Bit),
        ));
        seq.push((
            Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
            Some(Label::Crc4Loop),
        ));
        seq.push((
            Instruction::with1(Code::Not_rm32, Register::EAX).unwrap(),
            Some(Label::Crc4Done),
        ));
        // whiten: crc ^ rol(W32,13) — w32_slot에서 W32를 로드해 사이트 3와 다른 롤링 결합.
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R9, stub.w32_slot_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::R11D,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Rol_rm32_imm8, Register::R11D, 13).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::R11D).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Xor_r32_rm32,
                Register::EAX,
                MemoryOperand::with_base(Register::R10),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::Crc4Ok),
        ));
        seq.push((Instruction::with(Code::Ud2), None));
        seq.push((Instruction::with(Code::Nopd), Some(Label::Crc4Ok)));
    }
}
