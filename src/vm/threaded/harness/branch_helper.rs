// ==============================================================================
// BTG - Direct-Threaded Native Harness: dynamic-branch lookup helper - split from harness.rs
// ==============================================================================

use super::NativeVmHarness;
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, InstructionBlock, Register};

impl NativeVmHarness {
    /// ?�적 분기 ?��??�스-IP)??블록 ?�덱?�로 ?�석?�는 ?�캔 ?�퍼.
    /// ?�력: R10 = ?��?x86 IP. 출력: RAX = 블록 ?�덱??(찾으�?, �?찾으�?
    /// ?�스?�치 ?�이�?255] (=fallback, ret) �??�프.
    /// ?��? 브랜�?루프)가 ?�으므�????�스 브랜�??�치�?별도 ?�셈블된??
    pub(super) fn emit_branch_lookup_helper(branch_map_va: u64, table_base: u64) -> Result<Vec<u8>> {
        // 맵�? (ip, index) u64 ??배열, ip == 0 종결??
        //   r11 = �??�작
        //   loop:
        //     mov rax, [r11]        ; ip
        //     test rax, rax
        //     jz  not_found         ; 종결??
        //     cmp r10, rax
        //     je  found
        //     add r11, 16
        //     jmp loop
        //   found:
        //     mov rax, [r11 + 8]    ; index
        //     ret
        //   not_found:
        //     mov rax, 255
        //     mov rax, [r15 + rax*8]; fallback (ret)
        //     jmp rax
        let mut instrs: Vec<Instruction> = Vec::new();
        instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::R11, branch_map_va).map_err(|e| anyhow!("{e}"))?);
        let label_loop = instrs.len();
        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, iced_x86::MemoryOperand::with_base(Register::R11)).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).map_err(|e| anyhow!("{e}"))?);
        let i_jz = instrs.len();
        instrs.push(Instruction::with_branch(Code::Je_rel32_64, 0).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R10, Register::RAX).map_err(|e| anyhow!("{e}"))?);
        let i_je = instrs.len();
        instrs.push(Instruction::with_branch(Code::Je_rel32_64, 0).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::R11, 16).map_err(|e| anyhow!("{e}"))?);
        let i_jmp = instrs.len();
        instrs.push(Instruction::with_branch(Code::Jmp_rel32_64, 0).map_err(|e| anyhow!("{e}"))?);
        let label_found = instrs.len();
        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, iced_x86::MemoryOperand::with_base_displ_size(Register::R11, 8, 8)).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with(Code::Retnq));
        let label_not_found = instrs.len();
        instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 255).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, iced_x86::MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::RAX, 8, 0, 8)).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with1(Code::Jmp_rm64, Register::RAX).map_err(|e| anyhow!("{e}"))?);

        // ???�스 브랜�??�치 (BlockEncoder ??rel8/rel32 �??�동 축소 ???��?IP �?
        // 추정 ?�프?�으�?반복 ?�정???�렴?�킨??.
        let base = 0x140000000u64;
        let mut ips: Vec<u64> = (0..instrs.len()).map(|_| base).collect();
        let mut code = Vec::new();
        for _ in 0..16 {
            instrs[i_jz].set_near_branch64(ips[label_not_found]);
            instrs[i_je].set_near_branch64(ips[label_found]);
            instrs[i_jmp].set_near_branch64(ips[label_loop]);
            let blk = InstructionBlock::new(&instrs, base);
            let enc = iced_x86::BlockEncoder::encode(64, blk, iced_x86::BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
                .map_err(|e| anyhow!("branch helper encode: {e:?}"))?;
            let new_ips: Vec<u64> = enc.new_instruction_offsets.iter().map(|o| base + *o as u64).collect();
            code = enc.code_buffer;
            if new_ips == ips {
                ips = new_ips;
                break;
            }
            ips = new_ips;
        }
        let _ = table_base;
        Ok(code)
    }
}
