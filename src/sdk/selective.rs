// ==============================================================================
// BTG - Commercial-Grade VM: Selective Region Virtualizer & Trampoline
// ==============================================================================
// 마커로 감싸진 특정 코드 블록만 VM 바이트코드로 컴파일하고,
// 마커 시작 위치에 VM 진입 트램펄린(Call VM), 종료 위치에 네이티브 복귀 트램펄린을 생성.
// ==============================================================================

use super::markers::VmMarkerRegion;
use anyhow::{anyhow, Result};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};

pub struct SelectiveVirtualizer;

impl SelectiveVirtualizer {
    /// 원본 마커 구간에 주입할 VM 진입 트램펄린 생성
    /// ```asm
    /// pushfq
    /// push rax
    /// mov rax, vm_entry_va
    /// jmp rax
    /// ```
    pub fn build_entry_trampoline(vm_entry_va: u64, target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        instrs.push(Instruction::with(Code::Pushfq));
        instrs.push(Instruction::with1(Code::Push_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
        instrs.push(
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, vm_entry_va)
                .map_err(|e| anyhow!("{e}"))?,
        );
        instrs.push(Instruction::with1(Code::Jmp_rm64, Register::RAX).map_err(|e| anyhow!("{e}"))?);

        let block = InstructionBlock::new(&instrs, target_va);
        let encoded = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
            .map_err(|e| anyhow!("selective trampoline encode: {e}"))?;
        Ok(encoded.code_buffer)
    }
}
