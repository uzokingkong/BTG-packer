// ==============================================================================
// BTG - Commercial-Grade VM: Direct-Threaded Native Handler Runner
// ==============================================================================
// 12개 RISC 마이크로 핸들러의 네이티브 x86-64 기계어를 동적으로 생성하고,
// 중앙 디스패처 없는 Direct Tail-Call 스레딩 방식으로 네이티브 실행 및 검증한다.
// ==============================================================================

use super::direct_tail::DirectTailEmitter;
use crate::vm::arena::Arena;
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, Register};

pub struct DirectThreadedNativeRunner {
    pub arena: Arena,
}

impl DirectThreadedNativeRunner {
    pub fn new() -> Result<Self> {
        let arena = Arena::new(0x20000)?;
        Ok(Self { arena })
    }

    /// NOR 핸들러 네이티브 코드 생성:
    /// ```asm
    /// ; R10 = arg1, R11 = arg2
    /// or r10, r11
    /// not r10
    /// ; Tail dispatch:
    /// movzx eax, byte ptr [r12]
    /// inc r12
    /// xor rax, r14
    /// mov rax, [r15 + rax*8]
    /// jmp rax
    /// ```
    pub fn build_nor_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        // or r10, r11
        instrs.push(
            Instruction::with2(Code::Or_rm64_r64, Register::R10, Register::R11)
                .map_err(|e| anyhow!("{e}"))?,
        );
        // not r10
        instrs.push(
            Instruction::with1(Code::Not_rm64, Register::R10)
                .map_err(|e| anyhow!("{e}"))?,
        );
        // tail dispatch
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// ADD_WITH_CARRY 핸들러 네이티브 코드 생성:
    /// ```asm
    /// add r10, r11
    /// ; Tail dispatch
    /// ```
    pub fn build_add_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        // add r10, r11
        instrs.push(
            Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11)
                .map_err(|e| anyhow!("{e}"))?,
        );
        // tail dispatch
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// HALT 핸들러 네이티브 코드 생성:
    /// ```asm
    /// ret
    /// ```
    pub fn build_halt_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        instrs.push(Instruction::with(Code::Retnq));
        DirectTailEmitter::assemble(instrs, target_va)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_native_handlers() {
        let nor_code = DirectThreadedNativeRunner::build_nor_handler(0x140001000).unwrap();
        let add_code = DirectThreadedNativeRunner::build_add_handler(0x140001050).unwrap();
        let halt_code = DirectThreadedNativeRunner::build_halt_handler(0x1400010A0).unwrap();

        assert!(!nor_code.is_empty());
        assert!(!add_code.is_empty());
        assert!(!halt_code.is_empty());

        // Halt handler ends with ret (0xC3)
        assert_eq!(halt_code, vec![0xC3]);
    }
}
