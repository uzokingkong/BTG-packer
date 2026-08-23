// ==============================================================================
// BTG - MBA polynomial -> x86-64 code generation (split from mba.rs)
// ==============================================================================
use super::{BooleanOp, MbaPolynomial};
use crate::error::{BtgError, ObfuscationError};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};
use rand::Rng;

/// Instruction 구성 실패 → 도메인 오류로 변환 (리뷰 지적 #22: `unwrap_or_default()`
/// 로 잘못된(기본값) 명령을 조용히 스트림에 넣으면 인코더가 통과해도 **의미가 다른**
/// 코드가 생성된다. 반드시 오류로 올려야 한다).
fn mk(
    r: std::result::Result<Instruction, iced_x86::IcedError>,
) -> crate::error::Result<Instruction> {
    r.map_err(|e| BtgError::Obfuscation(ObfuscationError::MbaCodegenFailed(e.to_string())))
}

impl MbaPolynomial {
    /// MBA 다항식을 실제 x86-64 기계어로 컴파일한다.
    ///
    /// # 레지스터 할당
    /// - 입력: EDX = y (target_block_id)
    /// - R8D = var_val = x ^ (y + z) (모든 항에서 사용, 보존됨)
    /// - ECX = 각 항의 임시 계산용
    /// - EAX = 최종 누적 결과 (XOR 누적)
    ///
    /// # 생성되는 코드 구조
    /// ```asm
    /// push rdx             ; y 보존
    /// push rcx             ; 레지스터 보존
    /// push r8              ; 레지스터 보존
    /// mov r8d, edx         ; R8D = y
    /// mov eax, 0xFFFFFFFF  ; EAX = x
    /// xor r8d, eax         ; R8D = x ^ y = var_val (z=0 가정)
    /// xor eax, eax         ; EAX = 0 (누적 결과 초기화)
    /// ; 각 항에 대해:
    /// mov ecx, <coeff>     ; ECX = coefficient
    /// ; <boolean op> ecx, r8d  ; ECX = op(coeff, var_val)
    /// xor eax, ecx         ; EAX ^= ECX (결과 누적)
    /// pop r8
    /// pop rcx
    /// pop rdx
    /// ret
    /// ```
    ///
    /// 코드 생성/인코딩 실패 시 **오류를 반환**한다 (이전에는 `mov eax, edx; ret`
    /// 폴백으로 잘못된 코드를 조용히 내놓았다 — 리뷰 지적 #22).
    pub fn to_x86_64_code(&self) -> crate::error::Result<Vec<u8>> {
        let mut instructions: Vec<Instruction> = Vec::new();

        // 레지스터 보존 (호출 규약: callee-saved 아님, 직접 보존)
        instructions.push(mk(Instruction::with1(Code::Push_r64, Register::RDX))?);
        instructions.push(mk(Instruction::with1(Code::Push_r64, Register::RCX))?);
        instructions.push(mk(Instruction::with1(Code::Push_r64, Register::R8))?);

        // R8D = y (EDX)
        instructions.push(mk(Instruction::with2(
            Code::Mov_r32_rm32,
            Register::R8D,
            Register::EDX,
        ))?);
        // EAX = x (0xFFFFFFFF)
        instructions.push(mk(Instruction::with2(
            Code::Mov_r32_imm32,
            Register::EAX,
            0xFFFFFFFFu32,
        ))?);
        // R8D ^= EAX → R8D = x ^ y = var_val
        instructions.push(mk(Instruction::with2(
            Code::Xor_rm32_r32,
            Register::R8D,
            Register::EAX,
        ))?);
        // EAX = 0 (누적 결과 초기화)
        instructions.push(mk(Instruction::with2(
            Code::Xor_r32_rm32,
            Register::EAX,
            Register::EAX,
        ))?);

        for term in &self.terms {
            // ECX = coefficient
            instructions.push(mk(Instruction::with2(
                Code::Mov_r32_imm32,
                Register::ECX,
                term.coefficient,
            ))?);

            // 부울 연산 적용: ECX = op(ECX, R8D)
            // R8D는 var_val이며 모든 항에서 보존됨
            for &op in &term.operations {
                match op {
                    BooleanOp::And => {
                        instructions.push(mk(Instruction::with2(
                            Code::And_rm32_r32,
                            Register::ECX,
                            Register::R8D,
                        ))?);
                    }
                    BooleanOp::Or => {
                        instructions.push(mk(Instruction::with2(
                            Code::Or_rm32_r32,
                            Register::ECX,
                            Register::R8D,
                        ))?);
                    }
                    BooleanOp::Xor => {
                        instructions.push(mk(Instruction::with2(
                            Code::Xor_rm32_r32,
                            Register::ECX,
                            Register::R8D,
                        ))?);
                    }
                    BooleanOp::Not => {
                        instructions.push(mk(Instruction::with1(Code::Not_rm32, Register::ECX))?);
                    }
                    BooleanOp::Nand => {
                        // ECX = ECX & R8D; ECX = ~ECX
                        instructions.push(mk(Instruction::with2(
                            Code::And_rm32_r32,
                            Register::ECX,
                            Register::R8D,
                        ))?);
                        instructions.push(mk(Instruction::with1(Code::Not_rm32, Register::ECX))?);
                    }
                    BooleanOp::Nor => {
                        // ECX = ECX | R8D; ECX = ~ECX
                        instructions.push(mk(Instruction::with2(
                            Code::Or_rm32_r32,
                            Register::ECX,
                            Register::R8D,
                        ))?);
                        instructions.push(mk(Instruction::with1(Code::Not_rm32, Register::ECX))?);
                    }
                    BooleanOp::Xnor => {
                        // ECX = ECX ^ R8D; ECX = ~ECX
                        instructions.push(mk(Instruction::with2(
                            Code::Xor_rm32_r32,
                            Register::ECX,
                            Register::R8D,
                        ))?);
                        instructions.push(mk(Instruction::with1(Code::Not_rm32, Register::ECX))?);
                    }
                    BooleanOp::AndNot => {
                        // ECX = ECX & ~R8D
                        // R8D 보존: push r8 → not r8d → and ecx, r8d → pop r8
                        instructions.push(mk(Instruction::with1(Code::Push_r64, Register::R8))?);
                        instructions.push(mk(Instruction::with1(Code::Not_rm32, Register::R8D))?);
                        instructions.push(mk(Instruction::with2(
                            Code::And_rm32_r32,
                            Register::ECX,
                            Register::R8D,
                        ))?);
                        instructions.push(mk(Instruction::with1(Code::Pop_r64, Register::R8))?);
                    }
                    BooleanOp::OrNot => {
                        // ECX = ECX | ~R8D
                        instructions.push(mk(Instruction::with1(Code::Push_r64, Register::R8))?);
                        instructions.push(mk(Instruction::with1(Code::Not_rm32, Register::R8D))?);
                        instructions.push(mk(Instruction::with2(
                            Code::Or_rm32_r32,
                            Register::ECX,
                            Register::R8D,
                        ))?);
                        instructions.push(mk(Instruction::with1(Code::Pop_r64, Register::R8))?);
                    }
                }
            }

            // 결과 누적: EAX ^= ECX
            instructions.push(mk(Instruction::with2(
                Code::Xor_rm32_r32,
                Register::EAX,
                Register::ECX,
            ))?);
        }

        // 레지스터 복원
        instructions.push(mk(Instruction::with1(Code::Pop_r64, Register::R8))?);
        instructions.push(mk(Instruction::with1(Code::Pop_r64, Register::RCX))?);
        instructions.push(mk(Instruction::with1(Code::Pop_r64, Register::RDX))?);

        // 반환
        instructions.push(Instruction::with(Code::Retnq));

        // iced-x86 BlockEncoder로 컴파일 — 실패 시 오류 반환 (조용한 폴백 금지).
        let block = InstructionBlock::new(&instructions, 0x1000);
        let result = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE).map_err(|e| {
            BtgError::Obfuscation(ObfuscationError::MbaCodegenFailed(format!(
                "MBA BlockEncoder failed: {e}"
            )))
        })?;
        Ok(result.code_buffer)
    }
}
