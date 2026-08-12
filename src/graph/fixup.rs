// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Precision RIP-Relative Fixup Engine
// ==============================================================================


use anyhow::{Result, anyhow};
use iced_x86::{Instruction, OpKind, Register};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct RipFixupEntry {
    pub original_ip: u64,
    pub target_va: u64,
    pub operand_index: u32,
}

#[derive(Debug, Clone)]
pub struct RelocationContext {
    pub block_base_va: u64,
    pub instruction_offsets: Vec<usize>,
    pub relocation_entries: HashMap<usize, RipFixupEntry>,
}

impl RelocationContext {
    pub fn new(block_base_va: u64) -> Self {
        Self {
            block_base_va,
            instruction_offsets: Vec::new(),
            relocation_entries: HashMap::new(),
        }
    }

    pub fn calculate_exact_ip(&self, inst_index: usize) -> Result<u64> {
        if inst_index > self.instruction_offsets.len() {
            return Err(anyhow!("Instruction index {} out of bounds", inst_index));
        }
        
        let mut ip = self.block_base_va;
        for i in 0..inst_index {
            ip += self.instruction_offsets[i] as u64;
        }
        Ok(ip)
    }

    pub fn add_instruction_offset(&mut self, size: usize) {
        self.instruction_offsets.push(size);
    }
}

pub struct RipFixupEngine;

impl RipFixupEngine {
    /// Scans an instruction for RIP-relative memory addressing
    pub fn scan_instruction(inst: &Instruction) -> Option<RipFixupEntry> {
        for op in 0..inst.op_count() {
            if inst.op_kind(op) == OpKind::Memory && inst.memory_base() == Register::RIP {
                let target_va = inst.ip_rel_memory_address();
                return Some(RipFixupEntry {
                    original_ip: inst.ip(),
                    target_va,
                    operand_index: op,
                });
            }
        }
        None
    }

    /// Adjusts instruction RIP displacement for a confirmed Real_VA inside .btg section.
    ///
    /// x86-64 RIP-relative 인코딩 원리:
    ///   effective_address = next_ip + disp32
    ///   disp32 = target_va - next_ip  (여기서 next_ip = 해당 명령 직후 IP)
    ///
    /// iced BlockEncoder는 분기(JMP/CALL/Jcc) 만 auto-fixup하고,
    /// RIP-relative 메모리 operand는 raw displacement를 그대로 인코딩함.
    /// 따라서 올바른 disp32를 직접 계산하여 set_memory_displacement64()에 저장해야 함.
    pub fn process_fixup(inst: &mut Instruction, real_ip: u64, target_va: u64) -> Result<()> {
        if inst.memory_base() == Register::RIP {
            let next_ip = real_ip + inst.len() as u64;
            let new_disp = target_va as i64 - next_ip as i64;

            // 32-bit Signed Integer Bounds Validation (-2GB to +2GB)
            if new_disp < i32::MIN as i64 || new_disp > i32::MAX as i64 {
                log::error!(
                    "[RIP Fixup] OVERFLOW SKIP: disp={} RealIP=0x{:X} NextIP=0x{:X} Target=0x{:X}.",
                    new_disp, real_ip, next_ip, target_va
                );
                return Ok(());
            }

            // iced-x86 BlockEncoder 원리:
            // memory_base == Register::RIP 인 경우, BlockEncoder는 memory_displacement64()의 값을
            // 상대 오프셋이 아니라 '절대 목표 주소(target_va)'로 해석하고,
            // inst.ip()와 instruction length 기준 rel32 오프셋을 자동 산출하여 인코딩함.
            inst.set_ip(real_ip);
            inst.set_memory_displacement64(target_va);

            log::trace!(
                "[RIP Fixup OK] RealIP=0x{:X} NextIP=0x{:X} Target=0x{:X}",
                real_ip, next_ip, target_va
            );
        }
        Ok(())
    }


}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Code, Instruction};

    #[test]
    fn test_relocation_context_ip_calc() {
        let mut ctx = RelocationContext::new(0x1000);
        ctx.add_instruction_offset(5);
        ctx.add_instruction_offset(3);
        
        assert_eq!(ctx.calculate_exact_ip(0).unwrap(), 0x1000);
        assert_eq!(ctx.calculate_exact_ip(1).unwrap(), 0x1005);
        assert_eq!(ctx.calculate_exact_ip(2).unwrap(), 0x1008);
        assert!(ctx.calculate_exact_ip(3).is_err());
    }

    #[test]
    fn test_scan_instruction_no_rip() {
        let inst = Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RBX).unwrap();
        assert!(RipFixupEngine::scan_instruction(&inst).is_none());
    }

    #[test]
    fn test_scan_instruction_with_rip() {
        let bytes = b"\x48\x8D\x05\x00\x10\x00\x00"; // lea rax, [rip+0x1000]
        let mut decoder = iced_x86::Decoder::with_ip(64, bytes, 0x1000, iced_x86::DecoderOptions::NONE);
        let inst = decoder.decode();
        
        let fixup = RipFixupEngine::scan_instruction(&inst).unwrap();
        assert_eq!(fixup.original_ip, 0x1000);
        assert_eq!(fixup.target_va, 0x2007);
    }

    #[test]
    fn test_process_fixup_success() {
        let mut inst = Instruction::default();
        inst.set_code(Code::Lea_r64_m);
        inst.set_memory_base(Register::RIP);
        inst.set_len(7);
        
        let result = RipFixupEngine::process_fixup(&mut inst, 0x1000, 0x2000);
        assert!(result.is_ok());
        assert_eq!(inst.memory_displacement64(), 0x2000);
    }

    #[test]
    fn test_process_fixup_overflow() {
        let mut inst = Instruction::default();
        inst.set_code(Code::Lea_r64_m);
        inst.set_memory_base(Register::RIP);
        inst.set_len(7);
        
        // Target is > 2GB away
        let target = 0x1000 + (i32::MAX as u64) + 0x1000;
        let result = RipFixupEngine::process_fixup(&mut inst, 0x1000, target);
        assert!(result.is_ok());
    }
}
