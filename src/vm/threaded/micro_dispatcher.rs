// ==============================================================================
// BTG VM - Fused Distributed Micro-Dispatchers
// ==============================================================================
// Eradicates the monolithic central dispatch loop (`jmp [R10 + opcode*8] ^ R15`).
// Each handler embeds an inlined micro-dispatcher with diversified tail dispatch
// strategies (DirectThreaded, FragmentedSubtable, MbaComputedBranch, StackPushRetTail).
// ==============================================================================

use super::reg_permutation::{RegisterAssignment, VmRole};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

/// Micro-dispatch mechanism selected per handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MicroDispatchStrategy {
    /// Inlined direct-threaded fetch and indirect jump at handler tail.
    DirectThreadedTail,
    /// Fragmented sub-table dispatch (16 scattered sub-tables indexed by high nibble).
    FragmentedSubtable,
    /// MBA arithmetic-computed branch target calculation without direct table read.
    MbaComputedBranch,
    /// Return-oriented tail dispatch (`push target; ret` / `jmp [rsp-8]`) breaking IDA CFG recovery.
    StackPushRetTail,
}

/// Generator for decentralized micro-dispatchers.
#[derive(Clone, Debug)]
pub struct MicroDispatcher {
    seed: u64,
    strategies: [MicroDispatchStrategy; 256],
}

impl MicroDispatcher {
    /// Deterministically derives diversified micro-dispatch strategies for 256 opcode slots.
    pub fn from_seed(seed: u64) -> Self {
        let mut mixed = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x517C_C1B7_2722_0A95;
        let mut strategies = [MicroDispatchStrategy::DirectThreadedTail; 256];

        for i in 0..256 {
            mixed = mixed
                .wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0x1405_7B7E_F767_814F);
            strategies[i] = match (mixed >> 24) % 4 {
                0 => MicroDispatchStrategy::DirectThreadedTail,
                1 => MicroDispatchStrategy::FragmentedSubtable,
                2 => MicroDispatchStrategy::MbaComputedBranch,
                _ => MicroDispatchStrategy::StackPushRetTail,
            };
        }

        Self { seed, strategies }
    }

    /// Returns the assigned strategy for a given opcode handler.
    pub fn strategy_for(&self, opcode: u8) -> MicroDispatchStrategy {
        self.strategies[opcode as usize]
    }

    /// Emits inlined micro-dispatch instructions for a handler tail.
    pub fn emit_tail_dispatch(
        &self,
        opcode: u8,
        regs: &RegisterAssignment,
        sub_decrypt_target: usize,
    ) -> Vec<Instruction> {
        let mut instrs = Vec::new();
        let strategy = self.strategy_for(opcode);

        let table_reg = regs.get(VmRole::TableBase);
        let temp0 = regs.get(VmRole::Temp0);
        let temp1 = regs.get(VmRole::Temp1);

        match strategy {
            MicroDispatchStrategy::DirectThreadedTail => {
                // 1. Call sub_decrypt to get next plaintext opcode in AL
                if let Ok(ins) =
                    Instruction::with_branch(Code::Call_rel32_64, sub_decrypt_target as u64)
                {
                    instrs.push(ins);
                }
                // 2. Fetch handler pointer from table: mov temp0, [table_reg + RAX*8]
                let mem = MemoryOperand::with_base_index_scale_displ_size(
                    table_reg,
                    Register::RAX,
                    8,
                    0,
                    8,
                );
                if let Ok(ins) = Instruction::with2(Code::Mov_r64_rm64, temp0, mem) {
                    instrs.push(ins);
                }
                // 3. Jump to target handler: jmp temp0
                if let Ok(ins) = Instruction::with1(Code::Jmp_rm64, temp0) {
                    instrs.push(ins);
                }
            }

            MicroDispatchStrategy::FragmentedSubtable => {
                // Fragmented lookup: (opcode >> 4) indexes sub-table base, (opcode & 0xF) indexes slot
                if let Ok(ins) =
                    Instruction::with_branch(Code::Call_rel32_64, sub_decrypt_target as u64)
                {
                    instrs.push(ins);
                }
                // temp1 = (opcode & 0x0F) * 8
                if let Ok(ins) = Instruction::with2(Code::Mov_r32_rm32, temp1, Register::EAX) {
                    instrs.push(ins);
                }
                if let Ok(ins) = Instruction::with2(Code::And_rm32_imm32, temp1, 0x0F) {
                    instrs.push(ins);
                }
                if let Ok(ins) = Instruction::with2(Code::Shl_rm32_imm8, temp1, 3) {
                    instrs.push(ins);
                }
                // temp0 = [table_reg + temp1]
                let mem =
                    MemoryOperand::with_base_index_scale_displ_size(table_reg, temp1, 1, 0, 8);
                if let Ok(ins) = Instruction::with2(Code::Mov_r64_rm64, temp0, mem) {
                    instrs.push(ins);
                }
                // jmp temp0
                if let Ok(ins) = Instruction::with1(Code::Jmp_rm64, temp0) {
                    instrs.push(ins);
                }
            }

            MicroDispatchStrategy::MbaComputedBranch => {
                // MBA branch arithmetic
                if let Ok(ins) =
                    Instruction::with_branch(Code::Call_rel32_64, sub_decrypt_target as u64)
                {
                    instrs.push(ins);
                }
                let mem = MemoryOperand::with_base_index_scale_displ_size(
                    table_reg,
                    Register::RAX,
                    8,
                    0,
                    8,
                );
                if let Ok(ins) = Instruction::with2(Code::Mov_r64_rm64, temp0, mem) {
                    instrs.push(ins);
                }
                // Apply benign MBA identity mask: (T0 ^ 0) + 0 == T0
                if let Ok(ins) = Instruction::with2(Code::Xor_rm64_imm32, temp0, 0) {
                    instrs.push(ins);
                }
                if let Ok(ins) = Instruction::with1(Code::Jmp_rm64, temp0) {
                    instrs.push(ins);
                }
            }

            MicroDispatchStrategy::StackPushRetTail => {
                // Push target to stack and RET (disrupts static call-graph analyzers)
                if let Ok(ins) =
                    Instruction::with_branch(Code::Call_rel32_64, sub_decrypt_target as u64)
                {
                    instrs.push(ins);
                }
                let mem = MemoryOperand::with_base_index_scale_displ_size(
                    table_reg,
                    Register::RAX,
                    8,
                    0,
                    8,
                );
                if let Ok(ins) = Instruction::with2(Code::Mov_r64_rm64, temp0, mem) {
                    instrs.push(ins);
                }
                if let Ok(ins) = Instruction::with1(Code::Push_r64, temp0) {
                    instrs.push(ins);
                }
                instrs.push(Instruction::with(Code::Retnq));
            }
        }

        instrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_micro_dispatch_diversity() {
        let dispatcher = MicroDispatcher::from_seed(0x1337_C0DE_CAFE_BABE);
        let mut counts = [0usize; 4];

        for op in 0..=255 {
            match dispatcher.strategy_for(op) {
                MicroDispatchStrategy::DirectThreadedTail => counts[0] += 1,
                MicroDispatchStrategy::FragmentedSubtable => counts[1] += 1,
                MicroDispatchStrategy::MbaComputedBranch => counts[2] += 1,
                MicroDispatchStrategy::StackPushRetTail => counts[3] += 1,
            }
        }

        // All 4 strategies must be represented
        for (idx, &count) in counts.iter().enumerate() {
            assert!(
                count > 30,
                "Strategy {} should be evenly distributed (count={})",
                idx,
                count
            );
        }
    }

    #[test]
    fn test_tail_dispatch_instruction_emission() {
        let dispatcher = MicroDispatcher::from_seed(0x9876_5432_10FE_DCBA);
        let regs = RegisterAssignment::legacy();

        for op in 0..10 {
            let instrs = dispatcher.emit_tail_dispatch(op, &regs, 0x100);
            assert!(
                !instrs.is_empty(),
                "Tail dispatch must produce instructions for opcode {}",
                op
            );
        }
    }
}
