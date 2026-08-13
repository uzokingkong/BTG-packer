// ==============================================================================
// Integrity (--integrity): CRC32 over the code region (boot-time tamper check)
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

