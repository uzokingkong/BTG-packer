// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Payload Assembler using iced-x86
// ==============================================================================

use anyhow::Result;
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};

/// Generates x64 assembly bytes for a Trigger Block with a Dispatcher Bridge JMP at the end.
///
/// `state_key` 는 디스패처가 `push imm32` 로 받는 32비트 값이다. (리뷰 지적 #21:
/// 이전에는 `u64` 로 받아 `Pushq_imm32(state_key as i32)` 로 상위 32비트를 조용히
/// 잘랐다 — 계약과 타입이 모순. `u32` 로 선언해 명시적으로 만든다.)
pub fn assemble_block_with_bridge(
    payload_code: &FnPayload,
    current_block_va: u64,
    next_block_id: u32,
    state_key: u32,
    dispatcher_va: u64,
) -> Result<Vec<u8>> {
    let mut instructions = Vec::new();

    match payload_code {
        FnPayload::BlockA => {
            instructions.push(Instruction::with2(
                Code::Mov_r32_imm32,
                Register::EAX,
                0x11111111u32,
            )?);
            instructions.push(Instruction::with2(
                Code::Add_rm32_imm32,
                Register::EAX,
                0x22222222u32,
            )?);
        }
        FnPayload::BlockB => {
            instructions.push(Instruction::with2(
                Code::Mov_r32_imm32,
                Register::EBX,
                0x99999999u32,
            )?);
            instructions.push(Instruction::with(Code::Retnq));
        }
    }

    if payload_code.has_next() {
        instructions.push(Instruction::with1(Code::Pushq_imm32, next_block_id as i32)?);
        instructions.push(Instruction::with1(Code::Pushq_imm32, state_key as i32)?);
        instructions.push(Instruction::with_branch(Code::Jmp_rel32_64, dispatcher_va)?);
    }

    let block = InstructionBlock::new(&instructions, current_block_va);
    let result = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)?;

    Ok(result.code_buffer)
}

#[derive(Debug, Clone, Copy)]
pub enum FnPayload {
    BlockA,
    BlockB,
}

impl FnPayload {
    pub fn has_next(&self) -> bool {
        match self {
            FnPayload::BlockA => true,
            FnPayload::BlockB => false,
        }
    }
}
