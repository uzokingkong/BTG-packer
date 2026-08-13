// ==============================================================================
// BTG - MBA polynomial -> x86-64 code generation (split from mba.rs)
// ==============================================================================
use super::{BooleanOp, MbaPolynomial};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};
use rand::Rng;

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
    pub fn to_x86_64_code(&self) -> Vec<u8> {
        let mut instructions: Vec<Instruction> = Vec::new();

        // 레지스터 보존 (호출 규약: callee-saved 아님, 직접 보존)
        instructions.push(Instruction::with1(Code::Push_r64, Register::RDX).unwrap_or_default());
        instructions.push(Instruction::with1(Code::Push_r64, Register::RCX).unwrap_or_default());
        instructions.push(Instruction::with1(Code::Push_r64, Register::R8).unwrap_or_default());

        // R8D = y (EDX)
        instructions.push(
            Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::EDX)
                .unwrap_or_default()
        );
        // EAX = x (0xFFFFFFFF)
        instructions.push(
            Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0xFFFFFFFFu32)
                .unwrap_or_default()
        );
        // R8D ^= EAX → R8D = x ^ y = var_val
        instructions.push(
            Instruction::with2(Code::Xor_rm32_r32, Register::R8D, Register::EAX)
                .unwrap_or_default()
        );
        // EAX = 0 (누적 결과 초기화)
        instructions.push(
            Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX)
                .unwrap_or_default()
        );

        for term in &self.terms {
            // ECX = coefficient
            instructions.push(
                Instruction::with2(Code::Mov_r32_imm32, Register::ECX, term.coefficient)
                    .unwrap_or_default()
            );

            // 부울 연산 적용: ECX = op(ECX, R8D)
            // R8D는 var_val이며 모든 항에서 보존됨
            for &op in &term.operations {
                match op {
                    BooleanOp::And => {
                        instructions.push(
                            Instruction::with2(Code::And_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Or => {
                        instructions.push(
                            Instruction::with2(Code::Or_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Xor => {
                        instructions.push(
                            Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Not => {
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::ECX)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Nand => {
                        // ECX = ECX & R8D; ECX = ~ECX
                        instructions.push(
                            Instruction::with2(Code::And_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::ECX)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Nor => {
                        // ECX = ECX | R8D; ECX = ~ECX
                        instructions.push(
                            Instruction::with2(Code::Or_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::ECX)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Xnor => {
                        // ECX = ECX ^ R8D; ECX = ~ECX
                        instructions.push(
                            Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::ECX)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::AndNot => {
                        // ECX = ECX & ~R8D
                        // R8D 보존: push r8 → not r8d → and ecx, r8d → pop r8
                        instructions.push(
                            Instruction::with1(Code::Push_r64, Register::R8)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with2(Code::And_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Pop_r64, Register::R8)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::OrNot => {
                        // ECX = ECX | ~R8D
                        instructions.push(
                            Instruction::with1(Code::Push_r64, Register::R8)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with2(Code::Or_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Pop_r64, Register::R8)
                                .unwrap_or_default()
                        );
                    }
                }
            }

            // 결과 누적: EAX ^= ECX
            instructions.push(
                Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::ECX)
                    .unwrap_or_default()
            );
        }

        // 레지스터 복원
        instructions.push(Instruction::with1(Code::Pop_r64, Register::R8).unwrap_or_default());
        instructions.push(Instruction::with1(Code::Pop_r64, Register::RCX).unwrap_or_default());
        instructions.push(Instruction::with1(Code::Pop_r64, Register::RDX).unwrap_or_default());

        // 반환
        instructions.push(Instruction::with(Code::Retnq));

        // iced-x86 BlockEncoder로 컴파일
        let block = InstructionBlock::new(&instructions, 0x1000);
        match BlockEncoder::encode(64, block, BlockEncoderOptions::NONE) {
            Ok(result) => result.code_buffer,
            Err(e) => {
                log::error!("[MBA] BlockEncoder failed: {:?}. Falling back to simple XOR stub.", e);
                // 폴백: mov eax, edx; ret (입력 y를 그대로 반환)
                let fallback = vec![
                    Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EDX).unwrap_or_default(),
                    Instruction::with(Code::Retnq),
                ];
                let fb_block = InstructionBlock::new(&fallback, 0x1000);
                BlockEncoder::encode(64, fb_block, BlockEncoderOptions::NONE)
                    .map(|r| r.code_buffer)
                    .unwrap_or_else(|_| vec![0x89, 0xD0, 0xC3]) // mov eax, edx; ret
            }
        }
    }
}

