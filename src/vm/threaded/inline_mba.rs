// ==============================================================================
// BTG - Commercial-Grade VM: Inline MBA Handler Obfuscator
// ==============================================================================
// 네이티브 핸들러 내부의 산술/논리 명령어를 런타임 다항식 및 MBA(Mixed Boolean Arithmetic)로
// 직접 변환하여 정적/동적 디스어셈블러의 패턴 매칭을 무력화한다.
// ==============================================================================

use iced_x86::{Code, Instruction, Register};
use anyhow::{anyhow, Result};

pub struct InlineMbaObfuscator;

impl InlineMbaObfuscator {
    /// `add reg, imm` -> MBA 변환: `reg = (reg ^ imm) + 2*(reg & imm)`
    pub fn emit_mba_add_reg_imm(
        instructions: &mut Vec<Instruction>,
        reg: Register,
        imm: i32,
        scratch: Register,
    ) -> Result<()> {
        // 1. mov scratch, imm
        instructions.push(
            Instruction::with2(Code::Mov_r64_imm64, scratch, imm as i64 as u64)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 2. push reg (save original)
        instructions.push(
            Instruction::with1(Code::Push_r64, reg)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 3. reg = reg ^ scratch
        instructions.push(
            Instruction::with2(Code::Xor_r64_rm64, reg, scratch)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 4. pop scratch (scratch = original reg)
        instructions.push(
            Instruction::with1(Code::Pop_r64, scratch)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 5. scratch = scratch & imm
        instructions.push(
            Instruction::with2(Code::And_rm64_imm32, scratch, imm)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 6. scratch = scratch * 2 (shl scratch, 1)
        instructions.push(
            Instruction::with2(Code::Shl_rm64_imm8, scratch, 1)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 7. add reg, scratch
        instructions.push(
            Instruction::with2(Code::Add_r64_rm64, reg, scratch)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );

        Ok(())
    }

    /// `add dst, src` -> MBA: `dst = (dst ^ src) + (dst & src)` 후 `+ (dst & src)`
    ///
    /// 64-bit 전용 reg-reg 변환 (보고서 ④ — reg-reg 버전). 의미론적으로 동일한
    /// 값을 여러 스크래치 레지스터(`scratch1`, `scratch2`)를 경유해 산출하므로
    /// 단순 `add r, r` 시그니처가 없어져 정적 디스어셈블러의 ADD 핸들러 패턴
    /// 매칭을 무력화한다.
    ///
    /// ⚠ 플래그 정합성 (수정 — variant 0 의 함정): 이전엔
    /// `(a^b) + 2*(a&b)` 를 한 번의 add 로 냈다. 수치는 `a+b` 와 같지만
    /// **CF/OF 는 틀렸다** — `2*(a&b)` 가 2^64 를 넘어 랩하면 (예: a=0x8000..,
    /// b=0xFFFF..) 마지막 add 의 캐리/오버플로가 원본 `add a, b` 와 달라진다
    /// (차등 테스트로 적발 — "1 bit drift"). 올바른 분해는
    ///
    ///   (a^b) 와 (a&b) 는 비트 소침(disjoint) → `(a^b)+(a&b) = a|b` (무캐리)
    ///   → 마지막 `(a|b) + (a&b) = a+b` 의 add 가 원본과 **동일한 CF/OF/ZF/SF** 를 낸다.
    ///
    /// 플래그 캡처 포인트: 시퀀스 마지막 `add scratch1, scratch2` 직후 `store_flags`.
    ///
    /// 주의: `dst`/`src`/`scratch1`/`scratch2`는 서로 구별되어야 한다
    /// (emit_block.rs 에서는 R10/R11/R9/RCX). 스크래치 레지스터는 clobber 된다.
    pub fn emit_mba_add_reg_reg(
        instructions: &mut Vec<Instruction>,
        dst: Register,
        src: Register,
        scratch1: Register,
        scratch2: Register,
    ) -> Result<()> {
        // 1. scratch1 = dst                       (scratch1 = a)
        instructions.push(
            Instruction::with2(Code::Mov_r64_rm64, scratch1, dst)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 2. scratch1 = scratch1 ^ src            (scratch1 = a ^ b)
        instructions.push(
            Instruction::with2(Code::Xor_r64_rm64, scratch1, src)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 3. scratch2 = dst                       (scratch2 = a)
        instructions.push(
            Instruction::with2(Code::Mov_r64_rm64, scratch2, dst)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 4. scratch2 = scratch2 & src            (scratch2 = a & b)
        instructions.push(
            Instruction::with2(Code::And_r64_rm64, scratch2, src)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 5. scratch1 = scratch1 + scratch2       (scratch1 = (a^b)+(a&b) = a|b — 무캐리)
        instructions.push(
            Instruction::with2(Code::Add_r64_rm64, scratch1, scratch2)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 6. scratch1 = scratch1 + scratch2       (scratch1 = (a|b)+(a&b) = a+b — 플래그 캡처 포인트)
        instructions.push(
            Instruction::with2(Code::Add_r64_rm64, scratch1, scratch2)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 7. dst = scratch1                       (플래그 불변)
        instructions.push(
            Instruction::with2(Code::Mov_r64_rm64, dst, scratch1)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );

        Ok(())
    }

    /// P1 (handler diversification): ADD reg-reg MBA **variant 2** — `dst = (dst|src) + (dst&src)`.
    ///
    /// `a+b == (a|b) + (a&b)` (카운트 보존 항등식 — 각 비트의 합이 그 비트의
    /// OR/AND 합과 같다). variant 1(xor 기반)과 opcode 구성(mov→or→mov→and→add→mov)이
    /// 달라 두 핸들러가 시그니처를 공유하지 않는다. 마지막 `add scratch1, scratch2`
    /// 가 산술 결과를 내므로 그 뒤 `store_flags`를 뽑으면 CF/ZF/SF/OF 가 x86
    /// `add r, r` 과 정확히 일치한다.
    ///
    /// 스크래치 계약은 variant 1과 동일: `dst`/`src`/`scratch1`/`scratch2` 구별 필요.
    pub fn emit_mba_add_reg_reg_orand(
        instructions: &mut Vec<Instruction>,
        dst: Register,
        src: Register,
        scratch1: Register,
        scratch2: Register,
    ) -> Result<()> {
        // 1. scratch1 = dst                       (scratch1 = a)
        instructions.push(
            Instruction::with2(Code::Mov_r64_rm64, scratch1, dst)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 2. scratch1 = scratch1 | src            (scratch1 = a | b)
        instructions.push(
            Instruction::with2(Code::Or_r64_rm64, scratch1, src)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 3. scratch2 = dst                       (scratch2 = a)
        instructions.push(
            Instruction::with2(Code::Mov_r64_rm64, scratch2, dst)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 4. scratch2 = scratch2 & src            (scratch2 = a & b)
        instructions.push(
            Instruction::with2(Code::And_r64_rm64, scratch2, src)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 5. scratch1 = scratch1 + scratch2       (scratch1 = (a|b) + (a&b) = a+b)
        instructions.push(
            Instruction::with2(Code::Add_r64_rm64, scratch1, scratch2)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );
        // 6. dst = scratch1                       (플래그 불변)
        instructions.push(
            Instruction::with2(Code::Mov_r64_rm64, dst, scratch1)
                .map_err(|e| anyhow!("mba: {e}"))?,
        );

        Ok(())
    }

    /// P1 (handler diversification): variant 0/1 을 선택해 emit 한다.
    /// variant 0 = xor 기반 `(a^b)+2*(a&b)`, variant 1 = or/and 기반 `(a|b)+(a&b)`.
    /// 두 variant 는 opcode 순서가 달라 정적 ADD 핸들러 시그니처가 동일하지 않다.
    pub fn emit_mba_add_reg_reg_variant(
        instructions: &mut Vec<Instruction>,
        dst: Register,
        src: Register,
        scratch1: Register,
        scratch2: Register,
        variant: u32,
    ) -> Result<()> {
        if variant & 1 == 0 {
            Self::emit_mba_add_reg_reg(instructions, dst, src, scratch1, scratch2)
        } else {
            Self::emit_mba_add_reg_reg_orand(instructions, dst, src, scratch1, scratch2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{BlockEncoder, BlockEncoderOptions, InstructionBlock};

    fn assemble(instrs: Vec<Instruction>) -> Vec<u8> {
        let block = InstructionBlock::new(&instrs, 0x140001000);
        BlockEncoder::encode(64, block, BlockEncoderOptions::NONE).unwrap().code_buffer
    }

    /// MBA reg-reg 시퀀스가 `add r10, r11`과 같은 opcode 구성인지 확인한다
    /// (xor → mov → and → add → add → mov 순서 + 64-bit 피연산자).
    #[test]
    fn test_mba_reg_reg_sequence_structure() {
        let mut instrs = Vec::new();
        InlineMbaObfuscator::emit_mba_add_reg_reg(
            &mut instrs,
            Register::R10,
            Register::R11,
            Register::R9,
            Register::RCX,
        )
        .unwrap();
        let codes: Vec<_> = instrs.iter().map(|i| i.code()).collect();
        assert_eq!(
            codes,
            vec![
                Code::Mov_r64_rm64, // scratch1 = dst
                Code::Xor_r64_rm64, // scratch1 ^= src
                Code::Mov_r64_rm64, // scratch2 = dst
                Code::And_r64_rm64, // scratch2 &= src
                Code::Add_r64_rm64, // scratch1 = (a^b)+(a&b) = a|b (무캐리)
                Code::Add_r64_rm64, // scratch1 = (a|b)+(a&b) = a+b (플래그 캡처 포인트)
                Code::Mov_r64_rm64, // dst = scratch1
            ]
        );
        // 마지막 산술 op(add)가 결과를 내므로 플래그 캡처 포인트로 안전.
        let bytes = assemble(instrs);
        assert!(!bytes.is_empty());
    }

    /// P1 (handler diversification): variant 2 (or/and 기반 `(a|b)+(a&b)`)가
    /// variant 1 (xor 기반)과 **다른 opcode 시퀀스**를 내는지 확인한다.
    #[test]
    fn test_mba_reg_reg_variant2_structure_differs() {
        let mut v1 = Vec::new();
        InlineMbaObfuscator::emit_mba_add_reg_reg_variant(
            &mut v1,
            Register::R10,
            Register::R11,
            Register::R9,
            Register::RCX,
            0,
        )
        .unwrap();
        let mut v2 = Vec::new();
        InlineMbaObfuscator::emit_mba_add_reg_reg_variant(
            &mut v2,
            Register::R10,
            Register::R11,
            Register::R9,
            Register::RCX,
            1,
        )
        .unwrap();
        let codes1: Vec<_> = v1.iter().map(|i| i.code()).collect();
        let codes2: Vec<_> = v2.iter().map(|i| i.code()).collect();
        assert_ne!(codes1, codes2, "two ADD MBA variants must differ structurally");
        assert_eq!(
            codes2,
            vec![
                Code::Mov_r64_rm64, // scratch1 = dst
                Code::Or_r64_rm64,  // scratch1 |= src
                Code::Mov_r64_rm64, // scratch2 = dst
                Code::And_r64_rm64, // scratch2 &= src
                Code::Add_r64_rm64, // scratch1 = (a|b)+(a&b) — 플래그 캡처 포인트
                Code::Mov_r64_rm64, // dst = scratch1
            ]
        );
        // 두 variant 모두 플래그 캡처 포인트(add) 뒤에 mov(dst)만 있어 안전.
        assert!(!assemble(v1).is_empty() && !assemble(v2).is_empty());
    }
}
