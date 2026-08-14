// ==============================================================================
// BTG - Commercial-Grade VM: Full x86-64 -> RISC Micro-Op Lifter
// ==============================================================================
// iced-x86 Instruction을 단 12개의 원시 RISC 마이크로 연산 시퀀스로 직접 변환.
// 산술/논리/메모리/분기/스택 전반을 순수 RISC 원자로 분해하여 원본 시그니처를 파괴한다.
//
// T1-2 확장: CALL(직/간접), 전체 Jcc 조건, CMP, 메모리 피연산자 산술,
// SHL/SHR 시프트, MOVZX, LEAVE 프로로귀/에필로그.
// ==============================================================================

use super::desynth::RiscDesynthesizer;
use super::opcodes::{BranchCondition, MicroInstr, MicroOperand, RiscOp};
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, OpKind, Register};

/// 산술/논리 2항 연산의 디스패치 종류.
#[derive(Clone, Copy)]
enum Alu {
    Add,
    Sub,
    Xor,
    And,
    Or,
}

impl Alu {
    fn emit(&self, d: &mut RiscDesynthesizer, dst: MicroOperand, a: MicroOperand, b: MicroOperand) {
        match self {
            Alu::Add => d.emit_add(dst, a, b),
            Alu::Sub => d.emit_sub(dst, a, b),
            Alu::Xor => d.emit_xor(dst, a, b),
            Alu::And => d.emit_and(dst, a, b),
            Alu::Or => d.emit_or(dst, a, b),
        }
    }
}

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

    /// x86 32비트 GPR(op0)을 목적지로 쓰는 명령어는 상위 32비트를 0으로 정리한다.
    /// (x86 규칙: 32비트 레지스터 쓰기는 64비트 레지스터의 상위 절반을 0으로 만든다.)
    /// 디서인시스가 산출한 결과 `dst`를 `AND dst, 0xFFFFFFFF` 로 마스크한다.
    fn zero_extend_dst_if32(&mut self, inst: &Instruction, dst: MicroOperand) {
        let reg = inst.op0_register();
        let is32 = matches!(
            reg,
            Register::EAX | Register::ECX | Register::EDX | Register::EBX
            | Register::ESP | Register::EBP | Register::ESI | Register::EDI
            | Register::R8D | Register::R9D | Register::R10D | Register::R11D
            | Register::R12D | Register::R13D | Register::R14D | Register::R15D
        );
        if is32 {
            self.desynth.emit_and(dst, dst, MicroOperand::Imm64(0xFFFF_FFFF));
        }
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

    /// 단일 피연산자를 MicroOperand 값으로 해석. 레지스터->VReg, 즉시->Imm64,
    /// 메모리->유효주소를 Temp(4)에 계산 후 MemoryRead를 Temp(6)에 로드하여 Temp 반환.
    /// (x86은 인스트럭션당 메모리 피연산자가 최대 하나이므로 Temp(4)/Temp(6) 충돌 없음.)
    fn operand_value(&mut self, inst: &Instruction, which: u8) -> Result<MicroOperand> {
        let kind = if which == 0 {
            inst.op0_kind()
        } else {
            inst.op1_kind()
        };
        let reg = if which == 0 {
            inst.op0_register()
        } else {
            inst.op1_register()
        };
        match kind {
            OpKind::Register => Self::reg_to_vreg(reg).ok_or_else(|| anyhow!("invalid operand register")),
            OpKind::Immediate8
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64 => {
                Ok(MicroOperand::Imm64(inst.immediate64()))
            }
            OpKind::Memory => {
                let addr = MicroOperand::Temp(4);
                self.lower_effective_address(inst, addr)?;
                let val = MicroOperand::Temp(6);
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryRead {
                        width: inst.memory_size().size() as u8,
                    })
                    .with_dst(val)
                    .with_src1(addr),
                );
                Ok(val)
            }
            _ => Err(anyhow!("risc lifter: unsupported operand kind {:?}", kind)),
        }
    }

    /// ADD/SUB/XOR/AND/OR 의 레지스터·메모리·즉시 피연산자 공통 처리.
    /// op0가 메모리면 read-modify-write, op0가 레지스터면 op1(메모리 가능)을 더한다.
    fn lift_binary_alu(&mut self, inst: &Instruction, alu: Alu) -> Result<()> {
        match inst.op0_kind() {
            OpKind::Register => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let right = self.operand_value(inst, 1)?;
                alu.emit(&mut self.desynth, dst, dst, right);
                // 32비트 목적지(EAX..R15D)는 상위 32비트를 0으로 정리.
                self.zero_extend_dst_if32(inst, dst);
            }
            OpKind::Memory => {
                let addr = MicroOperand::Temp(4);
                self.lower_effective_address(inst, addr)?;
                let width = inst.memory_size().size() as u8;
                let left = MicroOperand::Temp(5);
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryRead { width })
                        .with_dst(left)
                        .with_src1(addr),
                );
                let right = self.operand_value(inst, 1)?;
                alu.emit(&mut self.desynth, left, left, right);
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryWrite { width })
                        .with_src1(addr)
                        .with_src2(left),
                );
            }
            _ => return Err(anyhow!("risc lifter: invalid op0 kind for ALU")),
        }
        Ok(())
    }

    /// CMP: 플래그만 갱신(CF/ZF/SF/OF)하고 결과를 버리는 SUB. 스크래치로 Temp(7) 사용.
    fn lift_cmp(&mut self, inst: &Instruction) -> Result<()> {
        let left = self.operand_value(inst, 0)?;
        let right = self.operand_value(inst, 1)?;
        let scratch = MicroOperand::Temp(7);
        self.desynth.emit_sub(scratch, left, right);
        Ok(())
    }

    /// SHL/SHR/SAR (32/64-bit, count: imm8 / 1 / CL).
    /// x86 시프트 횟수 마스크: 32비트 피연산자는 mod 32(31), 64비트는 mod 64(63).
    /// 32비트 레지스터 시프트 결과는 상위 32비트를 0으로 정리한다.
    fn lift_shift(&mut self, inst: &Instruction, op: RiscOp) -> Result<()> {
        // 32비트(rm32) 시프트 여부 — `_rm32_` 계열 코드.
        let is32 = matches!(
            inst.code(),
            Code::Shl_rm32_imm8 | Code::Shl_rm32_1 | Code::Shl_rm32_CL
            | Code::Shr_rm32_imm8 | Code::Shr_rm32_1 | Code::Shr_rm32_CL
            | Code::Sar_rm32_imm8 | Code::Sar_rm32_1 | Code::Sar_rm32_CL
        );
        let count = match inst.op1_kind() {
            OpKind::Immediate8
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64 => {
                let v = inst.immediate64();
                // 즉시 시프트 횟수는 리프트 시점에 마스크 (mod 32).
                if is32 { MicroOperand::Imm64(v & 31) } else { MicroOperand::Imm64(v) }
            }
            OpKind::Register => {
                let c = Self::reg_to_vreg(inst.op1_register())
                    .ok_or_else(|| anyhow!("invalid shift count register"))?;
                if is32 {
                    // CL 등 레지스터 시프트 횟수를 31로 마스크해 Temp(2)에 저장.
                    let masked = MicroOperand::Temp(2);
                    self.desynth.emit_and(masked, c, MicroOperand::Imm64(31));
                    masked
                } else {
                    c
                }
            }
            _ => return Err(anyhow!("risc lifter: unsupported shift count")),
        };
        match inst.op0_kind() {
            OpKind::Register => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid shift dst"))?;
                self.desynth
                    .instrs
                    .push(MicroInstr::new(op).with_dst(dst).with_src1(dst).with_src2(count));
                // 32비트 레지스터 시프트 결과는 상위 32비트를 0으로.
                if is32 {
                    self.zero_extend_dst_if32(inst, dst);
                }
            }
            OpKind::Memory => {
                let addr = MicroOperand::Temp(4);
                self.lower_effective_address(inst, addr)?;
                let width = inst.memory_size().size() as u8;
                let left = MicroOperand::Temp(5);
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryRead { width })
                        .with_dst(left)
                        .with_src1(addr),
                );
                self.desynth
                    .instrs
                    .push(MicroInstr::new(op).with_dst(left).with_src1(left).with_src2(count));
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryWrite { width })
                        .with_src1(addr)
                        .with_src2(left),
                );
            }
            _ => return Err(anyhow!("risc lifter: invalid shift op0")),
        }
        Ok(())
    }

    /// MOVZX: 8/16-bit 소스를 0-확장해 64비트 결과로. AND 마스크로 표현.
    fn lift_movzx(&mut self, inst: &Instruction, mask: u64) -> Result<()> {
        let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid movzx dst"))?;
        let src = self.operand_value(inst, 1)?;
        self.desynth.emit_and(dst, src, MicroOperand::Imm64(mask));
        Ok(())
    }

    /// MOVSX: 8/16/32-bit 소스를 부호 확장(sign-extend)해 64비트 결과로.
    /// `ArithmeticShiftRight`를 이용해 `(src << (64-w)) >> (64-w)`(산술 시프트)로
    /// 부호 비트를 복제한다. (MOVSX는 논리 시프트만으로는 표현 불가 — 산술 시프트 필요)
    fn lift_movsx(&mut self, inst: &Instruction, src_bits: u8) -> Result<()> {
        let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid movsx dst"))?;
        let src = self.operand_value(inst, 1)?;
        let shift = 64 - src_bits;
        let t = MicroOperand::Temp(3);
        // t = src << (64-w)
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::ShiftLeft)
                .with_dst(t)
                .with_src1(src)
                .with_src2(MicroOperand::Imm64(shift as u64)),
        );
        // dst = t >> (64-w) (산술 — 부호 비트 복제)
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::ArithmeticShiftRight)
                .with_dst(dst)
                .with_src1(t)
                .with_src2(MicroOperand::Imm64(shift as u64)),
        );
        // 32비트 목적지(Movsx_r32_*/Movsxd_r32_*)는 상위 32비트를 0으로.
        self.zero_extend_dst_if32(inst, dst);
        Ok(())
    }

    /// Jcxz/Jecxz/Jrcxz: RCX(reg[1])의 하위 `width` 바이트가 0이면 분기 (카운터 분기).
    fn emit_jcxz(&mut self, width: u8, target: u64) {
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::CounterZero(width),
            })
            .with_imm(target),
        );
    }

    /// 조건부 분기 emit (타깃 = 절대 x86 IP)
    fn emit_jcc(&mut self, cond: BranchCondition, target: u64) {
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch { cond }).with_imm(target),
        );
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
                    self.zero_extend_dst_if32(inst, dst);
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
                    self.zero_extend_dst_if32(inst, dst);
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
                    self.zero_extend_dst_if32(inst, dst);
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

            // ── MOVZX (0-확장) ──────────────────────────────────────────────────
            Code::Movzx_r64_rm16 | Code::Movzx_r32_rm16 => self.lift_movzx(inst, 0xFFFF)?,
            Code::Movzx_r64_rm8 | Code::Movzx_r32_rm8 | Code::Movzx_r16_rm8 => self.lift_movzx(inst, 0xFF)?,
            Code::Movzx_r16_rm16 => self.lift_movzx(inst, 0xFFFF)?,

            // ── MOVSX (부호 확장) ──────────────────────────────────────────────
            Code::Movsx_r64_rm16 | Code::Movsx_r32_rm16 | Code::Movsx_r16_rm16 => self.lift_movsx(inst, 16)?,
            Code::Movsx_r64_rm8 | Code::Movsx_r32_rm8 | Code::Movsx_r16_rm8 => self.lift_movsx(inst, 8)?,
            Code::Movsxd_r64_rm32 | Code::Movsxd_r32_rm32 | Code::Movsxd_r16_rm16 => self.lift_movsx(inst, 32)?,

            // ── LEA ─────────────────────────────────────────────────────────────
            Code::Lea_r64_m | Code::Lea_r32_m => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                self.lower_effective_address(inst, dst)?;
            }

            // ── 산술 덧셈 / 뺄셈 / 논리 (레지스터·메모리·즉시 공통) ──────────────
            Code::Add_rm64_r64
            | Code::Add_r64_rm64
            | Code::Add_rm32_r32
            | Code::Add_r32_rm32
            | Code::Add_rm64_imm32
            | Code::Add_rm64_imm8
            | Code::Add_rm32_imm32
            | Code::Add_rm32_imm8
            | Code::Add_RAX_imm32
            | Code::Add_EAX_imm32 => self.lift_binary_alu(inst, Alu::Add)?,
            Code::Sub_rm64_r64
            | Code::Sub_r64_rm64
            | Code::Sub_rm32_r32
            | Code::Sub_r32_rm32
            | Code::Sub_rm64_imm32
            | Code::Sub_rm64_imm8
            | Code::Sub_rm32_imm32
            | Code::Sub_rm32_imm8
            | Code::Sub_RAX_imm32
            | Code::Sub_EAX_imm32 => self.lift_binary_alu(inst, Alu::Sub)?,
            Code::Xor_rm64_r64
            | Code::Xor_r64_rm64
            | Code::Xor_rm32_r32
            | Code::Xor_r32_rm32
            | Code::Xor_rm64_imm32
            | Code::Xor_rm64_imm8
            | Code::Xor_rm32_imm32
            | Code::Xor_rm32_imm8
            | Code::Xor_RAX_imm32
            | Code::Xor_EAX_imm32 => self.lift_binary_alu(inst, Alu::Xor)?,
            Code::And_rm64_r64
            | Code::And_r64_rm64
            | Code::And_rm32_r32
            | Code::And_r32_rm32
            | Code::And_rm64_imm32
            | Code::And_rm64_imm8
            | Code::And_rm32_imm32
            | Code::And_rm32_imm8
            | Code::And_RAX_imm32
            | Code::And_EAX_imm32 => self.lift_binary_alu(inst, Alu::And)?,
            Code::Or_rm64_r64
            | Code::Or_r64_rm64
            | Code::Or_rm32_r32
            | Code::Or_r32_rm32
            | Code::Or_rm64_imm32
            | Code::Or_rm64_imm8
            | Code::Or_rm32_imm32
            | Code::Or_rm32_imm8
            | Code::Or_RAX_imm32
            | Code::Or_EAX_imm32 => self.lift_binary_alu(inst, Alu::Or)?,
            Code::Neg_rm64 | Code::Neg_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                self.desynth.emit_neg(dst, dst);
                self.zero_extend_dst_if32(inst, dst);
            }
            Code::Not_rm64 | Code::Not_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                self.desynth.emit_not(dst, dst);
                self.zero_extend_dst_if32(inst, dst);
            }

            // ── CMP (플래그만 갱신) ─────────────────────────────────────────────
            Code::Cmp_r64_rm64
            | Code::Cmp_rm64_r64
            | Code::Cmp_rm64_imm32
            | Code::Cmp_rm64_imm8
            | Code::Cmp_RAX_imm32
            | Code::Cmp_r32_rm32
            | Code::Cmp_rm32_r32
            | Code::Cmp_rm32_imm32
            | Code::Cmp_rm32_imm8
            | Code::Cmp_EAX_imm32 => self.lift_cmp(inst)?,

            // ── 시프트 (SHL / SHR) ──────────────────────────────────────────────
            Code::Shl_rm64_imm8 | Code::Shl_rm64_1 | Code::Shl_rm64_CL
            | Code::Shl_rm32_imm8 | Code::Shl_rm32_1 | Code::Shl_rm32_CL => self.lift_shift(inst, RiscOp::ShiftLeft)?,
            Code::Shr_rm64_imm8 | Code::Shr_rm64_1 | Code::Shr_rm64_CL
            | Code::Shr_rm32_imm8 | Code::Shr_rm32_1 | Code::Shr_rm32_CL => self.lift_shift(inst, RiscOp::ShiftRight)?,
            // SAR (산술 우측 시프트 — 부호 비트 유지)
            Code::Sar_rm64_imm8 | Code::Sar_rm64_1 | Code::Sar_rm64_CL
            | Code::Sar_rm32_imm8 | Code::Sar_rm32_1 | Code::Sar_rm32_CL
            | Code::Sar_rm16_imm8 | Code::Sar_rm16_1 | Code::Sar_rm16_CL
            | Code::Sar_rm8_imm8 | Code::Sar_rm8_1 | Code::Sar_rm8_CL => {
                self.lift_shift(inst, RiscOp::ArithmeticShiftRight)?
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

            // ── LEAVE: mov rsp, rbp; pop rbp ────────────────────────────────────
            Code::Leaveq | Code::Leaved | Code::Leavew => {
                self.desynth.emit_add(MicroOperand::VReg(4), MicroOperand::VReg(5), MicroOperand::Imm64(0));
                self.desynth.emit_pop(MicroOperand::VReg(5));
            }

            // ── CALL (직접/간접) ────────────────────────────────────────────────
            Code::Call_rel32_64 => {
                let target = inst.near_branch_target();
                let ret_ip = inst.next_ip();
                self.desynth.emit_push(MicroOperand::Imm64(ret_ip));
                self.desynth.emit_jmp(target);
            }
            Code::Call_rm64 | Code::Call_rm32 => {
                let ret_ip = inst.next_ip();
                self.desynth.emit_push(MicroOperand::Imm64(ret_ip));
                let target = self.operand_value(inst, 0)?; // 레지스터 또는 메모리 값
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::VirtualBranch {
                        cond: BranchCondition::Always,
                    })
                    .with_src1(target),
                );
            }

            // ── 분기 및 제어 흐름 ────────────────────────────────────────────────
            Code::Jmp_rel32_64 | Code::Jmp_rel8_64 => {
                let target = inst.near_branch_target();
                self.desynth.emit_jmp(target);
            }
            Code::Je_rel32_64 | Code::Je_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::Zero, target);
            }
            Code::Jne_rel32_64 | Code::Jne_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::NotZero, target);
            }
            Code::Jg_rel32_64 | Code::Jg_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::Greater, target);
            }
            Code::Jl_rel32_64 | Code::Jl_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::Less, target);
            }
            Code::Jge_rel32_64 | Code::Jge_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::GreaterOrEqual, target);
            }
            Code::Jle_rel32_64 | Code::Jle_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::LessOrEqual, target);
            }
            Code::Ja_rel32_64 | Code::Ja_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::Above, target);
            }
            Code::Jae_rel32_64 | Code::Jae_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::AboveOrEqual, target);
            }
            Code::Jb_rel32_64 | Code::Jb_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::Below, target);
            }
            Code::Jbe_rel32_64 | Code::Jbe_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::BelowOrEqual, target);
            }
            Code::Js_rel32_64 | Code::Js_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::Sign, target);
            }
            Code::Jns_rel32_64 | Code::Jns_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::NotSign, target);
            }
            Code::Jo_rel32_64 | Code::Jo_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::Overflow, target);
            }
            Code::Jno_rel32_64 | Code::Jno_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::NotOverflow, target);
            }
            Code::Jp_rel32_64 | Code::Jp_rel8_64 | Code::Jp_rel32_32 | Code::Jp_rel8_32 | Code::Jp_rel16 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::Parity, target);
            }
            Code::Jnp_rel32_64 | Code::Jnp_rel8_64 | Code::Jnp_rel32_32 | Code::Jnp_rel8_32 | Code::Jnp_rel16 => {
                let target = inst.near_branch_target();
                self.emit_jcc(BranchCondition::NotParity, target);
            }
            // Jcxz/CX(16) · Jecxz/ECX(32) · Jrcxz/RCX(64): 카운터 분기 (reg[1] 하위 width 바이트==0)
            Code::Jcxz_rel8_16 | Code::Jcxz_rel8_32 => {
                let target = inst.near_branch_target();
                self.emit_jcxz(2, target);
            }
            Code::Jecxz_rel8_16 | Code::Jecxz_rel8_32 | Code::Jecxz_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcxz(4, target);
            }
            Code::Jrcxz_rel8_16 | Code::Jrcxz_rel8_64 => {
                let target = inst.near_branch_target();
                self.emit_jcxz(8, target);
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
    use crate::vm::risc::{RiscEvalState, RiscProgram};
    use iced_x86::{Decoder, DecoderOptions};
    use std::collections::HashMap;

    /// 바이트 버퍼를 리프팅하고 소스-IP → 인덱스 맵을 첨부한 프로그램을 만든다.
    /// (분기 타깃을 eval_state의 VIP 인덱스로 변환하기 위함.)
    fn lift(raw: &[u8], ip: u64) -> RiscProgram {
        let mut decoder = Decoder::with_ip(64, raw, ip, DecoderOptions::NONE);
        let mut lifter = RiscLifter::new();
        let mut ip_map = HashMap::new();
        while decoder.can_decode() {
            let inst = decoder.decode();
            ip_map.insert(inst.ip(), lifter.desynth.instrs.len());
            lifter.lift_instruction(&inst).unwrap();
        }
        RiscProgram::with_ip_map(lifter.desynth.instrs, ip_map)
    }

    fn run(raw: &[u8], ip: u64, init: [u64; 16]) -> RiscEvalState {
        let prog = lift(raw, ip);
        prog.eval_state(&init)
    }

    fn regs(st: &RiscEvalState) -> [u64; 16] {
        st.regs
    }

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

    /// A: CALL → RET 왕복. call이 복귀 주소(next_ip)를 푸시하고 callee로 분기,
    /// callee 실행 후 ret(Halt)가 복귀 주소를 스택에 남긴다.
    #[test]
    fn test_lift_call_ret_roundtrip() {
        // 0x140001000: call 0x140001014  (E8 rel32)
        // 0x140001005: mov rcx, 1        (fallthrough, 미실행)
        // 0x14000100C: mov rdx, 2        (미실행)
        // 0x140001013: ret
        // 0x140001014: mov rbx, 7        (callee)
        // 0x14000101B: ret
        let raw = [
            0xE8, 0x0F, 0x00, 0x00, 0x00, // call 0x140001014
            0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
            0x48, 0xC7, 0xC2, 0x02, 0x00, 0x00, 0x00, // mov rdx, 2
            0xC3,                                     // ret
            0x48, 0xC7, 0xC3, 0x07, 0x00, 0x00, 0x00, // mov rbx, 7
            0xC3,                                     // ret
        ];
        let st = run(&raw, 0x140001000, [0u64; 16]);
        // callee 실행
        assert_eq!(regs(&st)[3], 7, "rbx set in callee");
        // call 이후 fallthrough 미실행
        assert_eq!(regs(&st)[1], 0, "rcx not executed");
        assert_eq!(regs(&st)[2], 0, "rdx not executed");
        // 스택 최상단 = call의 복귀 주소 (0x140001005)
        assert_eq!(st.stack.len(), 1, "one return address pushed");
        assert_eq!(st.stack[0], 0x140001005, "return address = call.next_ip");
    }

    /// A(간접): Call_rm64 → push 복귀 주소 + 간접 분기(레지스터 값).
    #[test]
    fn test_lift_call_indirect_register() {
        // rax = callee 주소로 초기화.
        // 0x140001000: call rax   (FF D0)
        // 0x140001002: mov rcx, 9  (미실행)
        // 0x140001009: ret
        // 0x14000100A: mov rbx, 0x2A  (callee)
        // 0x140001011: ret
        let raw = [
            0xFF, 0xD0,             // call rax
            0x48, 0xC7, 0xC1, 0x09, 0x00, 0x00, 0x00, // mov rcx, 9
            0xC3,                                     // ret
            0x48, 0xC7, 0xC3, 0x2A, 0x00, 0x00, 0x00, // mov rbx, 0x2A
            0xC3,                                     // ret
        ];
        let mut init = [0u64; 16];
        init[0] = 0x14000100A; // rax = callee
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[3], 0x2A, "indirect callee executed");
        assert_eq!(regs(&st)[1], 0, "fallthrough not executed");
        assert_eq!(st.stack[0], 0x140001002, "indirect call return addr");
    }

    /// B: JE taken / JE not-taken / JNE taken.
    #[test]
    fn test_lift_jcc_je_jne() {
        // cmp rax, rbx; je 0x14000100D; mov rcx,1; ret; 0x14000100D: mov rdx,2; ret
        let raw_je = [
            0x48, 0x39, 0xD8, // cmp rax, rbx
            0x74, 0x08,       // je 0x14000100D
            0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
            0xC3,             // ret
            0x48, 0xC7, 0xC2, 0x02, 0x00, 0x00, 0x00, // mov rdx, 2
            0xC3,             // ret
        ];
        // JE taken: rax == rbx
        let mut init = [0u64; 16];
        init[0] = 0x20;
        init[3] = 0x20;
        let st = run(&raw_je, 0x140001000, init);
        assert_eq!(regs(&st)[1], 0, "JE taken: rcx skipped");
        assert_eq!(regs(&st)[2], 2, "JE taken: rdx reached");

        // JE not-taken: rax != rbx
        let mut init2 = [0u64; 16];
        init2[0] = 0x20;
        init2[3] = 0x10;
        let st2 = run(&raw_je, 0x140001000, init2);
        assert_eq!(regs(&st2)[1], 1, "JE not-taken: rcx executed");
        assert_eq!(regs(&st2)[2], 0, "JE not-taken: rdx not reached");

        // JNE taken (opcode 75): rax != rbx → branch taken
        let mut raw_jne = raw_je;
        raw_jne[3] = 0x75;
        let st3 = run(&raw_jne, 0x140001000, init2);
        assert_eq!(regs(&st3)[1], 0, "JNE taken: rcx skipped");
        assert_eq!(regs(&st3)[2], 2, "JNE taken: rdx reached");
    }

    /// B + C: CMP → JG (signed) taken / not-taken.
    #[test]
    fn test_lift_cmp_then_jg() {
        // cmp rax, rbx; jg 0x14000100D; mov rcx,1; ret; 0x14000100D: mov rdx,7; ret
        let raw = [
            0x48, 0x39, 0xD8, // cmp rax, rbx
            0x7F, 0x08,       // jg 0x14000100D
            0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
            0xC3,
            0x48, 0xC7, 0xC2, 0x07, 0x00, 0x00, 0x00, // mov rdx, 7
            0xC3,
        ];
        // JG taken: 5 > 3
        let mut init = [0u64; 16];
        init[0] = 5;
        init[3] = 3;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[1], 0, "JG taken: rcx skipped");
        assert_eq!(regs(&st)[2], 7, "JG taken: rdx reached");

        // JG not-taken: 3 < 5 (negative result → SF=1, OF=0 → not greater)
        let mut init2 = [0u64; 16];
        init2[0] = 3;
        init2[3] = 5;
        let st2 = run(&raw, 0x140001000, init2);
        assert_eq!(regs(&st2)[1], 1, "JG not-taken: rcx executed");
        assert_eq!(regs(&st2)[2], 0, "JG not-taken: rdx not reached");
    }

    /// D: 메모리 피연산자 산술 (read-modify-write + reg←mem).
    #[test]
    fn test_lift_memory_operand_arith() {
        // 0x140001000: mov dword [rbx], 10
        // 0x140001006: add rax, [rbx]        (rax = 0 + 10)
        // 0x140001009: add qword [rbx], 5    ([rbx] = 10 + 5 = 15)
        // 0x14000100D: mov rcx, [rbx]        (rcx = 15)
        // 0x140001010: ret
        let raw = [
            0xC7, 0x03, 0x0A, 0x00, 0x00, 0x00, // mov dword [rbx], 10
            0x48, 0x03, 0x03,                   // add rax, [rbx]
            0x48, 0x83, 0x03, 0x05,             // add qword [rbx], 5
            0x48, 0x8B, 0x0B,                   // mov rcx, [rbx]
            0xC3,                               // ret
        ];
        let mut init = [0u64; 16];
        init[3] = 0x1000; // rbx = addr
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 10, "rax = 0 + mem10");
        assert_eq!(regs(&st)[1], 15, "rcx = 15 after read-modify-write");
        // [0x1000..0x1008] = 15 (qword little-endian)
        let mut memval = 0u64;
        for i in 0..8 {
            memval |= (st.mem.get(&(0x1000 + i)).copied().unwrap_or(0) as u64) << (i * 8);
        }
        assert_eq!(memval, 15, "memory updated by add qword [rbx],5");
    }

    /// E: SHL/SHR 시프트.
    #[test]
    fn test_lift_shifts() {
        // 0x140001000: shl rax, cl   (rax = 16 << 2 = 64)
        // 0x140001003: shr rax, 2    (rax = 64 >> 2 = 16)
        // 0x140001007: ret
        let raw = [
            0x48, 0xD3, 0xE0,       // shl rax, cl
            0x48, 0xC1, 0xE8, 0x02, // shr rax, 2
            0xC3,
        ];
        let mut init = [0u64; 16];
        init[0] = 16;
        init[1] = 2; // cl = 2
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 16, "16 << 2 then >> 2 = 16");
    }

    /// F: MOVZX 0-확장.
    #[test]
    fn test_lift_movzx() {
        // 0x140001000: movzx rax, al   (rax = 0xFF)
        // 0x140001003: movzx rax, bx   (rax = 0xFFFF)
        // 0x140001007: ret
        let raw = [
            0x48, 0x0F, 0xB6, 0xC0, // movzx rax, al
            0x48, 0x0F, 0xB7, 0xC3, // movzx rax, bx
            0xC3,
        ];
        let mut init = [0u64; 16];
        init[0] = 0x1234_FF00_0000_00FF;
        init[3] = 0x0000_0000_0001_FFFF; // bx = 0xFFFF
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0xFFFF, "movzx rax, bx zero-extends");
    }

    /// SAR (산술 우측 시프트): 음수 값은 부호 비트가 유지된다.
    #[test]
    fn test_lift_sar_arithmetic_shift() {
        // 0x140001000: sar rax, 2   (rax = -16 >> 2 = -4)
        // 0x140001003: sar rax, 1   (rax = -4 >> 1 = -2)
        // 0x140001006: ret
        let raw = [
            0x48, 0xC1, 0xF8, 0x02, // sar rax, 2
            0x48, 0xD1, 0xF8,       // sar rax, 1
            0xC3,
        ];
        let mut init = [0u64; 16];
        init[0] = (-16i64) as u64; // 0xFFFFFFFFFFFFFFF0
        let st = run(&raw, 0x140001000, init);
        // -16 >> 2 = -4 ; -4 >> 1 = -2
        assert_eq!(regs(&st)[0] as i64, -2, "SAR preserves sign bit");
    }

    /// MOVSX (부호 확장): 8/16-bit 소스를 부호 확장.
    #[test]
    fn test_lift_movsx_sign_extension() {
        // 0x140001000: movsx rax, al   (al = 0xFF → -1)
        // 0x140001003: movsx rax, bx   (bx = 0x8000 → -32768)
        // 0x140001007: ret
        let raw = [
            0x48, 0x0F, 0xBE, 0xC0, // movsx rax, al
            0x48, 0x0F, 0xBF, 0xC3, // movsx rax, bx
            0xC3,
        ];
        let mut init = [0u64; 16];
        init[0] = 0xFF; // al = 0xFF → sign-extend → -1
        init[3] = 0x8000; // bx = 0x8000 → -32768
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0] as i64, -32768, "movsx sign-extends 16-bit");
    }

    /// JP/JNP: 패리티 플래그에 따른 분기.
    #[test]
    fn test_lift_jp_jnp_parity() {
        // cmp al, 3 (0b11 — 1의 개수 2 → 짝수 → PF=1) ; jp 0x14000100B ; ret
        // 0x14000100B: mov rbx, 7
        // 0x140001000: cmp rax,3 (4B: 48 83 F8 03)  0x140001004: jp +1 → 0x140001007 (mov rbx,7 시작)
        // 3 - 3 = 0 → low byte 0b0 (0 ones, even) → PF=1 → JP taken.
        let raw_jp = [
            0x48, 0x83, 0xF8, 0x03, // cmp rax, 3
            0x7A, 0x01,             // jp +1 → 0x140001007
            0xC3,                   // ret (0x140001006) — 미실행
            0x48, 0xC7, 0xC3, 0x07, 0x00, 0x00, 0x00, // mov rbx, 7 (0x140001007)
            0xC3,
        ];
        let mut init = [0u64; 16];
        init[0] = 3;
        let st = run(&raw_jp, 0x140001000, init);
        assert_eq!(regs(&st)[3], 7, "JP taken when parity even (PF set)");

    }

    /// JECXZ: ECX==0 이면 분기.
    #[test]
    fn test_lift_jrcxz_counter_jump() {
        // 0x140001000: jrcxz +8 → 0x14000100A (mov rbx,7 시작); 0x140001002 mov rbx,1; 0x140001009 ret
        // 64비트 모드에서 E3는 JRCXZ (RCX==0). 카운터 분기 로직 검증용.
        let raw = [
            0xE3, 0x08, // jrcxz +8 → 0x14000100A
            0x48, 0xC7, 0xC3, 0x01, 0x00, 0x00, 0x00, // mov rbx, 1
            0xC3,
            0x48, 0xC7, 0xC3, 0x07, 0x00, 0x00, 0x00, // mov rbx, 7 (0x14000100A)
            0xC3,
        ];
        // RCX == 0 → taken
        let st = run(&raw, 0x140001000, [0u64; 16]);
        assert_eq!(regs(&st)[3], 7, "JRCXZ taken when RCX==0");
        // RCX != 0 → not taken
        let mut init = [0u64; 16];
        init[1] = 5;
        let st2 = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st2)[3], 1, "JRCXZ not taken when RCX!=0");
    }

    /// 정밀 unsigned 분기: JA(CF=0∧ZF=0) vs JAE(CF=0) — 같을 때 차이 검증.
    #[test]
    fn test_lift_ja_jae_unsigned_boundary() {
        // cmp rax, rbx (rax==rbx → ZF=1, CF=0)
        // ja 0x14000100D → not taken (ZF=1)
        // jae 0x14000100D → taken (CF=0)
        let raw = [
            0x48, 0x39, 0xD8, // cmp rax, rbx
            0x77, 0x08,       // ja +8
            0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1 (ja not taken)
            0xC3,
            0x48, 0xC7, 0xC2, 0x02, 0x00, 0x00, 0x00, // mov rdx, 2 (target)
            0xC3,
        ];
        let mut init = [0u64; 16];
        init[0] = 5;
        init[3] = 5;
        let st = run(&raw, 0x140001000, init);
        // JA(Above): ZF=1 이므로 not taken → rcx=1 실행
        assert_eq!(regs(&st)[1], 1, "JA not taken when operands equal (ZF=1)");
        assert_eq!(regs(&st)[2], 0, "JA target not reached");
    }

    /// JBE(CF=1 ∨ ZF=1): 같을 때(CF=0, ZF=1) taken.
    #[test]
    fn test_lift_jbe_unsigned_boundary() {
        // cmp rax, rbx (rax==rbx → ZF=1, CF=0)
        // jbe 0x14000100D → taken (ZF=1)
        let raw = [
            0x48, 0x39, 0xD8, // cmp rax, rbx
            0x76, 0x08,       // jbe +8
            0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1 (not reached)
            0xC3,
            0x48, 0xC7, 0xC2, 0x02, 0x00, 0x00, 0x00, // mov rdx, 2 (target)
            0xC3,
        ];
        let mut init = [0u64; 16];
        init[0] = 5;
        init[3] = 5;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[2], 2, "JBE taken when equal (ZF=1)");
        assert_eq!(regs(&st)[1], 0, "JBE target reached, fallthrough skipped");
    }

    /// 프로로귀/에필로그: push rbp; mov rbp,rsp ... leave; ret.
    #[test]
    fn test_lift_prologue_epilogue_leave() {
        // 0x140001000: push rbp
        // 0x140001001: mov rbp, rsp
        // 0x140001004: mov rax, 5
        // 0x14000100B: leave
        // 0x14000100C: ret
        let raw = [
            0x55,             // push rbp
            0x48, 0x89, 0xE5, // mov rbp, rsp
            0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5
            0xC9,             // leave
            0xC3,             // ret
        ];
        let mut init = [0u64; 16];
        init[5] = 0x200;  // rbp
        init[4] = 0x1000; // rsp
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 5, "rax = 5");
        assert_eq!(regs(&st)[5], 0x200, "rbp restored by leave pop");
        assert_eq!(regs(&st)[4], 0x1000, "rsp = rbp after leave");
        assert_eq!(st.stack.len(), 0, "push/pop balanced");
    }

    /// 32비트 레지스터 쓰기 zero-extension: mov eax + add eax 는 상위 32비트를 0으로.
    /// `add eax, ebx`(ebx=1)는 64비트로는 0x100000000(비트 32 세팅)이 되지만 x86은 0으로 감싼다.
    #[test]
    fn test_lift_32bit_write_zero_extends_upper_bits() {
        // 0x140001000: mov eax, 0xFFFFFFFF   (B8 FF FF FF FF)
        // 0x140001005: add eax, ebx          (01 D8)  — ebx = 1 (레지스터 소스)
        // 0x140001007: ret
        let raw = [
            0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, 0xFFFFFFFF
            0x01, 0xD8,                   // add eax, ebx
            0xC3,                         // ret
        ];
        let mut init = [0u64; 16];
        init[3] = 1; // ebx = 1
        let st = run(&raw, 0x140001000, init);
        assert_eq!(
            regs(&st)[0] & 0xFFFF_FFFF_0000_0000,
            0,
            "32-bit write must zero the upper 32 bits"
        );
        assert_eq!(regs(&st)[0], 0, "0xFFFFFFFF + 1 == 0 (wraps, zero-extended)");
    }

    /// 32비트 레지스터 이동도 zero-extension: mov eax, ebx 는 RBX의 하위 32비트만 취하고
    /// 상위 32비트를 0으로 정리한다.
    #[test]
    fn test_lift_32bit_mov_reg_source_zero_extends() {
        // 0x140001000: mov rbx, 0xFFFFFFFF00000001  (48 BB 01 00 00 00 FF FF FF FF)
        // 0x14000100A: mov eax, ebx                  (89 D8)
        // 0x14000100C: ret
        let raw = [
            0x48, 0xBB, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, // mov rbx, imm64
            0x89, 0xD8, // mov eax, ebx
            0xC3,
        ];
        let st = run(&raw, 0x140001000, [0u64; 16]);
        assert_eq!(regs(&st)[0], 1, "mov eax, ebx takes low 32 bits of rbx");
        assert_eq!(
            regs(&st)[0] & 0xFFFF_FFFF_0000_0000,
            0,
            "mov r32,r32 zero-extends the destination"
        );
    }

    /// 32비트 시프트 횟수는 mod 32(31 마스크): shl eax,32 == shl eax,0, sar eax,32 == sar eax,0.
    /// 레지스터(CL) 카운트 32도 0으로 마스크된다.
    #[test]
    fn test_lift_32bit_shift_count_masked_mod32() {
        let mut init = [0u64; 16];
        init[0] = 0x8000_0000; // bit 31 set

        // shl eax, 32 (C1 E0 20) — count 32 → masked to 0
        let raw_shl = [0xC1, 0xE0, 0x20, 0xC3]; // shl eax,32 ; ret
        let st = run(&raw_shl, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0x8000_0000, "shl eax,32 == shl eax,0");
        assert_eq!(
            regs(&st)[0] & 0xFFFF_FFFF_0000_0000,
            0,
            "32-bit shift result is zero-extended"
        );

        // sar eax, 32 (C1 F8 20) — count 32 → masked to 0
        let raw_sar = [0xC1, 0xF8, 0x20, 0xC3]; // sar eax,32 ; ret
        let st2 = run(&raw_sar, 0x140001000, init);
        assert_eq!(regs(&st2)[0], 0x8000_0000, "sar eax,32 == sar eax,0");

        // 레지스터 카운트: shl eax, cl with cl=32 → masked to 0
        let raw_shl_cl = [0xD3, 0xE0, 0xC3]; // shl eax, cl ; ret
        let mut init2 = [0u64; 16];
        init2[0] = 0x8000_0000;
        init2[1] = 32; // cl = 32 (하위 8비트)
        let st3 = run(&raw_shl_cl, 0x140001000, init2);
        assert_eq!(regs(&st3)[0], 0x8000_0000, "shl eax,cl(32) == shl eax,0");
    }
}
