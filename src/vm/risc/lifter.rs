// ==============================================================================
// BTG - Commercial-Grade VM: Full x86-64 -> RISC Micro-Op Lifter
// ==============================================================================
// iced-x86 Instruction을 단 12개의 원시 RISC 마이크로 연산 시퀀스로 직접 변환.
// 산술/논리/메모리/분기/스택 전반을 순수 RISC 원자로 분해하여 원본 시그니처를 파괴한다.
// ==============================================================================

use super::desynth::RiscDesynthesizer;
use super::opcodes::{BranchCondition, MicroInstr, MicroOperand, RiscOp};
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, OpKind, Register};

pub struct RiscLifter {
    pub desynth: RiscDesynthesizer,
}

impl RiscLifter {
    pub fn new() -> Self {
        Self {
            desynth: RiscDesynthesizer::new(),
        }
    }

    /// x86 Register를 MicroOperand::VReg로 변환 (RAX=0 ... R15=15)
    pub fn reg_to_vreg(reg: Register) -> Option<MicroOperand> {
        let base = match reg {
            Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => 0,
            Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => 1,
            Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => 2,
            Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => 3,
            Register::RSP | Register::ESP | Register::SP | Register::SPL => 4,
            Register::RBP | Register::EBP | Register::BP | Register::BPL => 5,
            Register::RSI | Register::ESI | Register::SI | Register::SIL => 6,
            Register::RDI | Register::EDI | Register::DI | Register::DIL => 7,
            Register::R8 | Register::R8D | Register::R8W | Register::R8L => 8,
            Register::R9 | Register::R9D | Register::R9W | Register::R9L => 9,
            Register::R10 | Register::R10D | Register::R10W | Register::R10L => 10,
            Register::R11 | Register::R11D | Register::R11W | Register::R11L => 11,
            Register::R12 | Register::R12D | Register::R12W | Register::R12L => 12,
            Register::R13 | Register::R13D | Register::R13W | Register::R13L => 13,
            Register::R14 | Register::R14D | Register::R14W | Register::R14L => 14,
            Register::R15 | Register::R15D | Register::R15W | Register::R15L => 15,
            _ => return None,
        };
        Some(MicroOperand::VReg(base))
    }

    /// 메모리 유효 주소 계산을 RISC 마이크로 연산으로 분해
    /// `addr = base + index*scale + disp`
    pub fn lower_effective_address(&mut self, inst: &Instruction, temp_dst: MicroOperand) -> Result<()> {
        let base_reg = inst.memory_base();
        let idx_reg = inst.memory_index();
        let scale = inst.memory_index_scale();
        let disp = inst.memory_displacement64();

        // 1. Start with base or 0
        if base_reg != Register::None {
            let base_v = Self::reg_to_vreg(base_reg).ok_or_else(|| anyhow!("unsupported base reg"))?;
            self.desynth.emit_add(temp_dst, base_v, MicroOperand::Imm64(0));
        } else {
            self.desynth.emit_add(temp_dst, MicroOperand::Imm64(0), MicroOperand::Imm64(0));
        }

        // 2. Add scaled index: index * scale
        if idx_reg != Register::None {
            let idx_v = Self::reg_to_vreg(idx_reg).ok_or_else(|| anyhow!("unsupported index reg"))?;
            let t1 = MicroOperand::Temp(3);
            self.desynth.emit_add(t1, idx_v, MicroOperand::Imm64(0));
            if scale == 2 {
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::ShiftLeft)
                        .with_dst(t1)
                        .with_src1(t1)
                        .with_imm(1),
                );
            } else if scale == 4 {
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::ShiftLeft)
                        .with_dst(t1)
                        .with_src1(t1)
                        .with_imm(2),
                );
            } else if scale == 8 {
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::ShiftLeft)
                        .with_dst(t1)
                        .with_src1(t1)
                        .with_imm(3),
                );
            }
            self.desynth.emit_add(temp_dst, temp_dst, t1);
        }

        // 3. Add displacement
        if disp != 0 {
            self.desynth.emit_add(temp_dst, temp_dst, MicroOperand::Imm64(disp));
        }

        Ok(())
    }

    /// 단일 x86 명령어 리프팅
    pub fn lift_instruction(&mut self, inst: &Instruction) -> Result<()> {
        let code = inst.code();

        match code {
            // ── MOV 계열 ────────────────────────────────────────────────────────
            Code::Mov_r64_rm64 | Code::Mov_r32_rm32 | Code::Mov_r16_rm16 | Code::Mov_r8_rm8 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                if inst.op1_kind() == OpKind::Register {
                    let src = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid src"))?;
                    self.desynth.emit_add(dst, src, MicroOperand::Imm64(0));
                } else if inst.op1_kind() == OpKind::Memory {
                    let t_addr = MicroOperand::Temp(4);
                    self.lower_effective_address(inst, t_addr)?;
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::MemoryRead { width: inst.memory_size().size() as u8 })
                            .with_dst(dst)
                            .with_src1(t_addr),
                    );
                }
            }
            Code::Mov_rm64_r64 | Code::Mov_rm32_r32 | Code::Mov_rm16_r16 | Code::Mov_rm8_r8 => {
                let src = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid src"))?;
                if inst.op0_kind() == OpKind::Register {
                    let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                    self.desynth.emit_add(dst, src, MicroOperand::Imm64(0));
                } else if inst.op0_kind() == OpKind::Memory {
                    let t_addr = MicroOperand::Temp(4);
                    self.lower_effective_address(inst, t_addr)?;
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::MemoryWrite { width: inst.memory_size().size() as u8 })
                            .with_src1(t_addr)
                            .with_src2(src),
                    );
                }
            }
            Code::Mov_r64_imm64
            | Code::Mov_r32_imm32
            | Code::Mov_r16_imm16
            | Code::Mov_r8_imm8
            | Code::Mov_rm64_imm32
            | Code::Mov_rm32_imm32
            | Code::Mov_rm16_imm16
            | Code::Mov_rm8_imm8 => {
                let imm = inst.immediate64();
                if inst.op0_kind() == OpKind::Register {
                    let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                    self.desynth.emit_add(dst, MicroOperand::Imm64(imm), MicroOperand::Imm64(0));
                } else if inst.op0_kind() == OpKind::Memory {
                    let t_addr = MicroOperand::Temp(4);
                    self.lower_effective_address(inst, t_addr)?;
                    let t_val = MicroOperand::Temp(5);
                    self.desynth.emit_add(t_val, MicroOperand::Imm64(imm), MicroOperand::Imm64(0));
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::MemoryWrite { width: inst.memory_size().size() as u8 })
                            .with_src1(t_addr)
                            .with_src2(t_val),
                    );
                }
            }

            // ── LEA ─────────────────────────────────────────────────────────────
            Code::Lea_r64_m | Code::Lea_r32_m => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                self.lower_effective_address(inst, dst)?;
            }

            // ── 산술 덧셈 / 뺄셈 ────────────────────────────────────────────────
            Code::Add_rm64_r64
            | Code::Add_r64_rm64
            | Code::Add_rm32_r32
            | Code::Add_r32_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let src = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid src"))?;
                self.desynth.emit_add(dst, dst, src);
            }
            Code::Add_rm64_imm32
            | Code::Add_rm64_imm8
            | Code::Add_rm32_imm32
            | Code::Add_rm32_imm8
            | Code::Add_RAX_imm32
            | Code::Add_EAX_imm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let imm = inst.immediate64();
                self.desynth.emit_add(dst, dst, MicroOperand::Imm64(imm));
            }
            Code::Sub_rm64_r64
            | Code::Sub_r64_rm64
            | Code::Sub_rm32_r32
            | Code::Sub_r32_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let src = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid src"))?;
                self.desynth.emit_sub(dst, dst, src);
            }
            Code::Sub_rm64_imm32
            | Code::Sub_rm64_imm8
            | Code::Sub_rm32_imm32
            | Code::Sub_rm32_imm8
            | Code::Sub_RAX_imm32
            | Code::Sub_EAX_imm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let imm = inst.immediate64();
                self.desynth.emit_sub(dst, dst, MicroOperand::Imm64(imm));
            }
            Code::Neg_rm64 | Code::Neg_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                self.desynth.emit_neg(dst, dst);
            }

            // ── 논리 연산 (NOR De-synthesis) ────────────────────────────────────
            Code::Xor_rm64_r64
            | Code::Xor_r64_rm64
            | Code::Xor_rm32_r32
            | Code::Xor_r32_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let src = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid src"))?;
                self.desynth.emit_xor(dst, dst, src);
            }
            Code::Xor_rm64_imm32
            | Code::Xor_rm64_imm8
            | Code::Xor_rm32_imm32
            | Code::Xor_rm32_imm8
            | Code::Xor_RAX_imm32
            | Code::Xor_EAX_imm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let imm = inst.immediate64();
                self.desynth.emit_xor(dst, dst, MicroOperand::Imm64(imm));
            }
            Code::And_rm64_r64
            | Code::And_r64_rm64
            | Code::And_rm32_r32
            | Code::And_r32_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let src = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid src"))?;
                self.desynth.emit_and(dst, dst, src);
            }
            Code::And_rm64_imm32
            | Code::And_rm64_imm8
            | Code::And_rm32_imm32
            | Code::And_rm32_imm8
            | Code::And_RAX_imm32
            | Code::And_EAX_imm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let imm = inst.immediate64();
                self.desynth.emit_and(dst, dst, MicroOperand::Imm64(imm));
            }
            Code::Or_rm64_r64
            | Code::Or_r64_rm64
            | Code::Or_rm32_r32
            | Code::Or_r32_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let src = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid src"))?;
                self.desynth.emit_or(dst, dst, src);
            }
            Code::Or_rm64_imm32
            | Code::Or_rm64_imm8
            | Code::Or_rm32_imm32
            | Code::Or_rm32_imm8
            | Code::Or_RAX_imm32
            | Code::Or_EAX_imm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let imm = inst.immediate64();
                self.desynth.emit_or(dst, dst, MicroOperand::Imm64(imm));
            }
            Code::Not_rm64 | Code::Not_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                self.desynth.emit_not(dst, dst);
            }

            // ── 스택 PUSH / POP ─────────────────────────────────────────────────
            Code::Push_r64 | Code::Push_r16 => {
                let src = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid src"))?;
                self.desynth.emit_push(src);
            }
            Code::Pushd_imm32 | Code::Pushq_imm32 | Code::Pushq_imm8 | Code::Pushw_imm8 => {
                let imm = inst.immediate64();
                self.desynth.emit_push(MicroOperand::Imm64(imm));
            }
            Code::Pop_r64 | Code::Pop_r16 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                self.desynth.emit_pop(dst);
            }

            // ── 분기 및 제어 흐름 ────────────────────────────────────────────────
            Code::Jmp_rel32_64 | Code::Jmp_rel8_64 => {
                let target = inst.near_branch_target();
                self.desynth.emit_jmp(target);
            }
            Code::Je_rel32_64 | Code::Je_rel8_64 => {
                let target = inst.near_branch_target();
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::VirtualBranch {
                        cond: BranchCondition::Zero,
                    })
                    .with_imm(target),
                );
            }
            Code::Jne_rel32_64 | Code::Jne_rel8_64 => {
                let target = inst.near_branch_target();
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::VirtualBranch {
                        cond: BranchCondition::NotZero,
                    })
                    .with_imm(target),
                );
            }
            Code::Retnq | Code::Retnw => {
                self.desynth.instrs.push(MicroInstr::new(RiscOp::Halt));
            }
            _ => {
                // Fallback for unsupported complex instruction
                return Err(anyhow!("risc lifter: unsupported opcode {:?}", code));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::risc::RiscProgram;
    use iced_x86::{Decoder, DecoderOptions};

    #[test]
    fn test_lift_x86_to_risc_stream() {
        // x86 machine code:
        // mov rax, 100
        // mov rbx, 50
        // add rax, rbx
        // xor rax, 0x1234
        // ret
        let raw_bytes = [
            0x48, 0xC7, 0xC0, 0x64, 0x00, 0x00, 0x00, // mov rax, 100
            0x48, 0xC7, 0xC3, 0x32, 0x00, 0x00, 0x00, // mov rbx, 50
            0x48, 0x01, 0xD8,                         // add rax, rbx
            0x48, 0x35, 0x34, 0x12, 0x00, 0x00,       // xor rax, 0x1234
            0xC3,                                     // ret
        ];

        let mut decoder = Decoder::with_ip(64, &raw_bytes, 0x140001000, DecoderOptions::NONE);
        let mut lifter = RiscLifter::new();

        while decoder.can_decode() {
            let inst = decoder.decode();
            lifter.lift_instruction(&inst).unwrap();
        }

        let prog = RiscProgram::new(lifter.desynth.instrs);
        let regs = [0u64; 16];
        let out = prog.eval_registers(&regs);

        // (100 + 50) ^ 0x1234 = 150 ^ 4660 = 4734 (0x127E)
        assert_eq!(out[0], (100 + 50) ^ 0x1234);
        assert_eq!(out[3], 50); // rbx = 50
    }
}
