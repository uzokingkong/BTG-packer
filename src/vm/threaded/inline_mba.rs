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
}
