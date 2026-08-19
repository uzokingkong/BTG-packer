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

pub(crate) fn emit_integrity_crc(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v5 --integrity: 복호화된 코드 영역 CRC32 검증 (불일치 시 ud2) ──────────
    // 표준 반사형 CRC-32 (poly 0xEDB88320). packer가 패킹 시 계산해 seed 뒤에
    // 저장한 값과 비교한다. 파일의 암호화 바이트가 변조되면 복호화 결과가
    // 깨져 CRC 불일치 → ud2로 강제 종료 (안티-패치).
    if stub.integrity {
        // 저장된 CRC32 값 주소 (imm64 — 길이 불변)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R10, stub.crc_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0xFFFF_FFFFu32).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.code_len as u64).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::CrcDone)));
        seq.push((
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::R8D,
                MemoryOperand::with_base(Register::RCX),
            ).unwrap(),
            Some(Label::CrcLoop),
        ));
        seq.push((Instruction::with2(Code::Xor_rm8_r8, Register::AL, Register::R8L).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 8).unwrap(), None));
        // 8회: crc = (crc >> 1) ^ (LSB ? poly : 0)
        seq.push((Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 1).unwrap(), Some(Label::CrcBit)));
        seq.push((Instruction::with_branch(Code::Jae_rel32_64, 0).unwrap(), Some(Label::CrcSkip))); // jnc
        seq.push((Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, 0xEDB8_8320u32).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm32, Register::R9D).unwrap(), Some(Label::CrcSkip)));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::CrcBit)));
        seq.push((Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::CrcLoop)));
        seq.push((Instruction::with1(Code::Not_rm32, Register::EAX).unwrap(), Some(Label::CrcDone)));
        seq.push((
            Instruction::with2(
                Code::Cmp_r32_rm32,
                Register::EAX,
                MemoryOperand::with_base(Register::R10),
            ).unwrap(),
            None,
        ));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::CrcOk)));
        seq.push((Instruction::with(Code::Ud2), None));
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
        seq.push((Instruction::with1(Code::Push_r64, Register::RSI).unwrap(), None));
        seq.push((Instruction::with1(Code::Push_r64, Register::RDI).unwrap(), None));
        // R10 = PHI ; RBP = h0 ; RDI = h1 (초기 상태)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R10, PHI).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RBP, 0x6A09_E667_F3BC_C909u64).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDI, 0xBB67_AE85_84CA_A73Bu64).unwrap(), None));

        // ── bind_byte 재계산 (base_bind_loop와 동일 유도) → R11b ──────────────
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            M::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None)); // PEB
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            M::with_base_displ(Register::RAX, 0x10)).unwrap(), None)); // PEB.ImageBaseAddress
        // (base>>16) & 0xFF
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 16).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::EDX).unwrap(), None));
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::R11D, 0xFF).unwrap(), None));
        // ^ (base>>24)
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 24).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_rm32_r32, Register::R11D, Register::ECX).unwrap(), None));
        // ^ (base>>32)
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 32).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_rm32_r32, Register::R11D, Register::ECX).unwrap(), None));
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::R11D, 0xFF).unwrap(), None));
        // R11b = bind_byte

        // ── Phase A: 키(seed_stored) 흡수 — 256바이트 루프 ────────────────────
        // R9 = init i-계수 0x100000001B3 (Phase A — must match packer BtgKeyedMac::new)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R9, 0x100_0000_01B3u64).unwrap(), None));
        // RSI = seed_va ; R8D = i = 0
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.seed_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::R8D, Register::R8D).unwrap(), None));
        // MacInitLoop:
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, M::with_base(Register::RSI)).unwrap(), Some(Label::MacInitLoop)));
        seq.push((Instruction::with2(Code::Xor_rm8_r8, Register::AL, Register::R11L).unwrap(), None)); // b = seed ^ bind_byte
        // FIX: compute rol(h0,i&63) into RAX (CL=shift count) BEFORE building
        // RCX=b*PHI, and preserve b in RDX — otherwise `mov cl, dl` clobbers the
        // low byte of RCX holding b*PHI, corrupting the MAC (packer vs runtime mismatch).
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(), None)); // rdx = b
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R8D).unwrap(), None)); // ecx = i
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap(), None));          // cl = i&63
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RBP).unwrap(), None)); // rax = h0
        seq.push((Instruction::with2(Code::Rol_rm64_CL, Register::RAX, Register::CL).unwrap(), None));   // rax = rol(h0, i&63)
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RDX).unwrap(), None)); // rcx = b
        seq.push((Instruction::with2(Code::Imul_r64_rm64, Register::RCX, Register::R10).unwrap(), None));// rcx = b*PHI
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::RAX).unwrap(), None)); // rcx = b*PHI + rol(h0,i&63)
        // rcx += i*0x100000001B3
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R8).unwrap(), None));
        seq.push((Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::R9).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::RAX).unwrap(), None));
        // h1 ^= rcx
        seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::RDI, Register::RCX).unwrap(), None));
        // h1 = rol(h1,23)*PHI + h0
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 23).unwrap(), None));
        seq.push((Instruction::with2(Code::Rol_rm64_CL, Register::RDI, Register::CL).unwrap(), None));
        seq.push((Instruction::with2(Code::Imul_r64_rm64, Register::RDI, Register::R10).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RDI, Register::RBP).unwrap(), None));
        // h0 = rol(h0,17) ^ h1
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 17).unwrap(), None));
        seq.push((Instruction::with2(Code::Rol_rm64_CL, Register::RBP, Register::CL).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::RBP, Register::RDI).unwrap(), None));
        // advance + loop
        seq.push((Instruction::with1(Code::Inc_rm64, Register::RSI).unwrap(), None));
        seq.push((Instruction::with1(Code::Inc_rm32, Register::R8D).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::R8D, 256).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::MacInitLoop)));

        // ── Phase B: 코드 영역 데이터 흡수 ────────────────────────────────────
        // R9 = update i-계수 0x9E3779B9 (r32 mov는 zero-extend)
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 0x9E37_79B9u32).unwrap(), None));
        // RSI = code_va ; R8D = i = 0 ; RDX = code_len
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.code_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::R8D, Register::R8D).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.code_len as u64).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::MacDone)));
        // MacDataLoop:
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, M::with_base(Register::RSI)).unwrap(), Some(Label::MacDataLoop)));
        // FIX: compute rol(h0,i&63) into RAX (CL=shift count) BEFORE building
        // RCX=b*PHI, and preserve b in RDX — otherwise `mov cl, dl` clobbers the
        // low byte of RCX holding b*PHI, corrupting the MAC (packer vs runtime mismatch).
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(), None)); // rdx = b
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R8D).unwrap(), None)); // ecx = i
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap(), None));          // cl = i&63
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RBP).unwrap(), None)); // rax = h0
        seq.push((Instruction::with2(Code::Rol_rm64_CL, Register::RAX, Register::CL).unwrap(), None));   // rax = rol(h0, i&63)
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RDX).unwrap(), None)); // rcx = b
        seq.push((Instruction::with2(Code::Imul_r64_rm64, Register::RCX, Register::R10).unwrap(), None));// rcx = b*PHI
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::RAX).unwrap(), None)); // rcx = b*PHI + rol(h0,i&63)
        // rcx += i*0x9E3779B9
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R8).unwrap(), None));
        seq.push((Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::R9).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::RAX).unwrap(), None));
        // h1 ^= rcx
        seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::RDI, Register::RCX).unwrap(), None));
        // h1 = rol(h1,17)*PHI + h0
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 17).unwrap(), None));
        seq.push((Instruction::with2(Code::Rol_rm64_CL, Register::RDI, Register::CL).unwrap(), None));
        seq.push((Instruction::with2(Code::Imul_r64_rm64, Register::RDI, Register::R10).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RDI, Register::RBP).unwrap(), None));
        // h0 = rol(h0,31) ^ h1
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 31).unwrap(), None));
        seq.push((Instruction::with2(Code::Rol_rm64_CL, Register::RBP, Register::CL).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::RBP, Register::RDI).unwrap(), None));
        // advance + loop
        seq.push((Instruction::with1(Code::Inc_rm64, Register::RSI).unwrap(), None));
        seq.push((Instruction::with1(Code::Inc_rm32, Register::R8D).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R8).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, stub.code_len as i64).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::MacDataLoop)));

        // ── Phase C: finish + 저장값 비교 ─────────────────────────────────────
        seq.push((Instruction::with(Code::Nopd), Some(Label::MacDone)));
        // out = rol(h1,32) ^ h0 ^ rol(h0,47)
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RDI).unwrap(), None)); // h1
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 32).unwrap(), None));
        seq.push((Instruction::with2(Code::Rol_rm64_CL, Register::RAX, Register::CL).unwrap(), None)); // rol(h1,32)
        seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RBP).unwrap(), None)); // ^ h0
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RBP).unwrap(), None)); // h0
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 47).unwrap(), None));
        seq.push((Instruction::with2(Code::Rol_rm64_CL, Register::RDX, Register::CL).unwrap(), None)); // rol(h0,47)
        seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RDX).unwrap(), None)); // out
        // mac_va 저장값(8B)과 비교 — 불일치 시 ud2
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.mac_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmp_r64_rm64, Register::RAX, M::with_base(Register::RSI)).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::MacOk)));
        seq.push((Instruction::with(Code::Ud2), None));
        // restore the PRGA i/j state saved at MAC entry (success path only —
        // the ud2 failure path never returns here)
        seq.push((Instruction::with1(Code::Pop_r64, Register::RDI).unwrap(), Some(Label::MacOk)));
        seq.push((Instruction::with1(Code::Pop_r64, Register::RSI).unwrap(), None));
    }
}
