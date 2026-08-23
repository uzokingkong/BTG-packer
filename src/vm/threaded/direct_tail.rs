// ==============================================================================
// BTG - Commercial-Grade VM: Direct Threading Tail-Call Dispatcher
// ==============================================================================
// 중앙 점프 테이블(Dispatcher Loop)을 완전히 제거하고, 모든 핸들러의 끝부분에
// 다음 핸들러 주소를 롤링 키로 복호화하여 직접 tail-call 점프하는 기계어 방출기.
// ==============================================================================

use anyhow::{anyhow, Result};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};

pub struct DirectTailEmitter;

impl DirectTailEmitter {
    /// 핸들러 끝에 직접 스레디드 디스패치 루틴 주입:
    /// ```asm
    /// movzx eax, byte ptr [r12]     ; fetch next encrypted opcode (r12 = VIP)
    /// inc r12                       ; VIP++
    /// xor rax, r14                  ; decrypt with rolling key (r14 = current_key)
    /// mov rax, [r15 + rax*8]        ; load next handler address from dynamic table (r15 = handler_base)
    /// jmp rax                       ; direct tail-call to next handler
    /// ```
    pub fn emit_tail_dispatch(instructions: &mut Vec<Instruction>) -> Result<()> {
        // movzx eax, byte ptr [r12]
        let op_vip = iced_x86::MemoryOperand::with_base(Register::R12);
        instructions.push(
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, op_vip)
                .map_err(|e| anyhow!("direct_tail: {e}"))?,
        );

        // inc r12
        instructions.push(
            Instruction::with1(Code::Inc_rm64, Register::R12)
                .map_err(|e| anyhow!("direct_tail: {e}"))?,
        );

        // xor rax, r14
        instructions.push(
            Instruction::with2(Code::Xor_r64_rm64, Register::RAX, Register::R14)
                .map_err(|e| anyhow!("direct_tail: {e}"))?,
        );

        // mov rax, [r15 + rax*8]
        let op_table = iced_x86::MemoryOperand::with_base_index_scale_displ_size(
            Register::R15,
            Register::RAX,
            8,
            0,
            8,
        );
        instructions.push(
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, op_table)
                .map_err(|e| anyhow!("direct_tail: {e}"))?,
        );

        // jmp rax
        instructions.push(
            Instruction::with1(Code::Jmp_rm64, Register::RAX)
                .map_err(|e| anyhow!("direct_tail: {e}"))?,
        );

        Ok(())
    }

    /// 인코딩된 기계어 바이트 반환
    pub fn assemble(instructions: Vec<Instruction>, target_rip: u64) -> Result<Vec<u8>> {
        let block = InstructionBlock::new(&instructions, target_rip);
        let encoded = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
            .map_err(|e| anyhow!("direct_tail assemble error: {e}"))?;
        Ok(encoded.code_buffer)
    }
}
