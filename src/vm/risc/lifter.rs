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


mod arith;
mod sse;
mod string;

/// XMM 레지스터 파일이 위치하는 가상 메모리 영역 기준 주소.
/// 각 XMM(i) 은 `mem[XMM_SLOT_BASE + i*16 .. +16]` 의 128비트 슬롯으로 존재한다.
/// 스칼라 연산은 하위 요소(4/8B)만 접근 — 상위 바이트는 x86 스칼라 의미론대로 보존.
const XMM_SLOT_BASE: u64 = 0xF000_0000_0000_0000;

/// REP / REPE / REPNE 프리픽스 존재 여부 (string ops). `has_rep_prefix()` 는
/// REPNE(0xF2) 에는 false 를 돌려주므로 둘 다 확인해야 한다.
fn has_any_rep(inst: &Instruction) -> bool {
    inst.has_rep_prefix() || inst.has_repne_prefix()
}

/// STOS/LODS 요소 폭 (bytes).
fn stos_lods_width(code: Code) -> u8 {
    use iced_x86::Code::*;
    match code {
        Stosb_m8_AL | Lodsb_AL_m8 => 1,
        Stosw_m16_AX | Lodsw_AX_m16 => 2,
        Stosd_m32_EAX | Lodsd_EAX_m32 => 4,
        _ => 8,
    }
}

/// SCAS/CMPS 요소 폭 (bytes).
fn scas_cmps_width(code: Code) -> u8 {
    use iced_x86::Code::*;
    match code {
        Scasb_AL_m8 | Cmpsb_m8_m8 => 1,
        Scasw_AX_m16 | Cmpsw_m16_m16 => 2,
        Scasd_EAX_m32 | Cmpsd_m32_m32 => 4,
        _ => 8,
    }
}

/// MOVS 요소 폭 (bytes).
fn movs_width(code: Code) -> u8 {
    use iced_x86::Code::*;
    match code {
        Movsb_m8_m8 => 1,
        Movsw_m16_m16 => 2,
        Movsd_m32_m32 => 4,
        _ => 8,
    }
}

/// 폭별 마스크 (0-확장용).
fn width_mask_u64(width: u8) -> u64 {
    match width {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => u64::MAX,
    }
}

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

/// SSE/FPU 스칼라 산술 연산 종류 (ADDSS/SD·SUB·MUL·DIV).
#[derive(Clone, Copy)]
enum FPArith {
    Add,
    Sub,
    Mul,
    Div,
}

pub struct RiscLifter {
    pub desynth: RiscDesynthesizer,
}

/// SETcc 16 조건 → BranchCondition.
fn cond_for_setcc(code: Code) -> Option<BranchCondition> {
    match code {
        Code::Seta_rm8 => Some(BranchCondition::Above),
        Code::Setae_rm8 => Some(BranchCondition::AboveOrEqual),
        Code::Setb_rm8 => Some(BranchCondition::Below),
        Code::Setbe_rm8 => Some(BranchCondition::BelowOrEqual),
        Code::Sete_rm8 => Some(BranchCondition::Zero),
        Code::Setne_rm8 => Some(BranchCondition::NotZero),
        Code::Setg_rm8 => Some(BranchCondition::Greater),
        Code::Setge_rm8 => Some(BranchCondition::GreaterOrEqual),
        Code::Setl_rm8 => Some(BranchCondition::Less),
        Code::Setle_rm8 => Some(BranchCondition::LessOrEqual),
        Code::Seto_rm8 => Some(BranchCondition::Overflow),
        Code::Setno_rm8 => Some(BranchCondition::NotOverflow),
        Code::Setp_rm8 => Some(BranchCondition::Parity),
        Code::Setnp_rm8 => Some(BranchCondition::NotParity),
        Code::Sets_rm8 => Some(BranchCondition::Sign),
        Code::Setns_rm8 => Some(BranchCondition::NotSign),
        _ => None,
    }
}

/// CMOVcc (16 조건 × 16/32/64) → BranchCondition.
fn cond_for_cmov(code: Code) -> Option<BranchCondition> {
    match code {
        Code::Cmova_r16_rm16 | Code::Cmova_r32_rm32 | Code::Cmova_r64_rm64 => Some(BranchCondition::Above),
        Code::Cmovae_r16_rm16 | Code::Cmovae_r32_rm32 | Code::Cmovae_r64_rm64 => Some(BranchCondition::AboveOrEqual),
        Code::Cmovb_r16_rm16 | Code::Cmovb_r32_rm32 | Code::Cmovb_r64_rm64 => Some(BranchCondition::Below),
        Code::Cmovbe_r16_rm16 | Code::Cmovbe_r32_rm32 | Code::Cmovbe_r64_rm64 => Some(BranchCondition::BelowOrEqual),
        Code::Cmove_r16_rm16 | Code::Cmove_r32_rm32 | Code::Cmove_r64_rm64 => Some(BranchCondition::Zero),
        Code::Cmovne_r16_rm16 | Code::Cmovne_r32_rm32 | Code::Cmovne_r64_rm64 => Some(BranchCondition::NotZero),
        Code::Cmovg_r16_rm16 | Code::Cmovg_r32_rm32 | Code::Cmovg_r64_rm64 => Some(BranchCondition::Greater),
        Code::Cmovge_r16_rm16 | Code::Cmovge_r32_rm32 | Code::Cmovge_r64_rm64 => Some(BranchCondition::GreaterOrEqual),
        Code::Cmovl_r16_rm16 | Code::Cmovl_r32_rm32 | Code::Cmovl_r64_rm64 => Some(BranchCondition::Less),
        Code::Cmovle_r16_rm16 | Code::Cmovle_r32_rm32 | Code::Cmovle_r64_rm64 => Some(BranchCondition::LessOrEqual),
        Code::Cmovo_r16_rm16 | Code::Cmovo_r32_rm32 | Code::Cmovo_r64_rm64 => Some(BranchCondition::Overflow),
        Code::Cmovno_r16_rm16 | Code::Cmovno_r32_rm32 | Code::Cmovno_r64_rm64 => Some(BranchCondition::NotOverflow),
        Code::Cmovp_r16_rm16 | Code::Cmovp_r32_rm32 | Code::Cmovp_r64_rm64 => Some(BranchCondition::Parity),
        Code::Cmovnp_r16_rm16 | Code::Cmovnp_r32_rm32 | Code::Cmovnp_r64_rm64 => Some(BranchCondition::NotParity),
        Code::Cmovs_r16_rm16 | Code::Cmovs_r32_rm32 | Code::Cmovs_r64_rm64 => Some(BranchCondition::Sign),
        Code::Cmovns_r16_rm16 | Code::Cmovns_r32_rm32 | Code::Cmovns_r64_rm64 => Some(BranchCondition::NotSign),
        _ => None,
    }
}

impl RiscLifter {
    pub fn new() -> Self {
        Self {
            desynth: RiscDesynthesizer::new(),
        }
    }

    /// x86 Register를 MicroOperand::VReg로 변환 (RAX=0 ... R15=15)
    pub fn reg_to_vreg(reg: Register) -> Option<MicroOperand> {
        // High-byte registers (AH/BH/CH/DH — bits 8..15) are not representable in
        // the 64-bit vreg model: they would alias the full GPR and be read/written
        // as the low byte. Reject them explicitly (None -> lift error).
        if matches!(reg, Register::AH | Register::BH | Register::CH | Register::DH) {
            return None;
        }
        let base = match reg {
            Register::RAX | Register::EAX | Register::AX | Register::AL => 0,
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
        let kind = match which {
            0 => inst.op0_kind(),
            1 => inst.op1_kind(),
            2 => inst.op2_kind(),
            _ => inst.op1_kind(),
        };
        let reg = match which {
            0 => inst.op0_register(),
            1 => inst.op1_register(),
            2 => inst.op2_register(),
            _ => inst.op1_register(),
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

    pub fn lift_instruction(&mut self, inst: &Instruction) -> Result<()> {
        let code = inst.code();

        match code {
            // ── MOV 계열 ────────────────────────────────────────────────────────
            Code::Mov_r64_rm64 | Code::Mov_r32_rm32 | Code::Mov_r16_rm16 | Code::Mov_r8_rm8 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                if inst.op1_kind() == OpKind::Register {
                    let src = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid src"))?;
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov).with_dst(dst).with_src1(src),
                    );
                    self.zero_extend_dst_if32(inst, dst);
                    // 8/16-bit dest: zero-extend into the 64-bit vreg (matches the
                    // bytecode model and MOVZX — a full copy would leak upper bits).
                    self.mask_result(inst.op0_register().size() as u8, inst, dst)?;
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
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov).with_dst(dst).with_src1(src),
                    );
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
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov).with_dst(dst).with_src1(MicroOperand::Imm64(imm)),
                    );
                    self.zero_extend_dst_if32(inst, dst);
                } else if inst.op0_kind() == OpKind::Memory {
                    let t_addr = MicroOperand::Temp(4);
                    self.lower_effective_address(inst, t_addr)?;
                    let t_val = MicroOperand::Temp(5);
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov).with_dst(t_val).with_src1(MicroOperand::Imm64(imm)),
                    );
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
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::Mov).with_dst(MicroOperand::VReg(4)).with_src1(MicroOperand::VReg(5)),
                );
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
            // RET imm16: RSP += imm 후 Halt.
            Code::Retnq_imm16 | Code::Retnw_imm16 => {
                let imm = inst.immediate16() as u64;
                if imm != 0 {
                    self.desynth.emit_add(
                        MicroOperand::VReg(4),
                        MicroOperand::VReg(4),
                        MicroOperand::Imm64(imm),
                    );
                }
                self.desynth.instrs.push(MicroInstr::new(RiscOp::Halt));
            }

            // ── P2: MUL / IMUL (1-피연산자, RAX 암시) ───────────────────────────
            Code::Mul_rm8 | Code::Mul_rm16 | Code::Mul_rm32 | Code::Mul_rm64 => {
                let width = match code {
                    Code::Mul_rm8 => 1,
                    Code::Mul_rm16 => 2,
                    Code::Mul_rm32 => 4,
                    _ => 8,
                };
                let rax = MicroOperand::VReg(0);
                let right = self.operand_value(inst, 0)?;
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::Multiply { signed: false, width })
                        .with_dst(rax)
                        .with_src1(rax)
                        .with_src2(right),
                );
                if width == 4 {
                    self.zero_extend_dst_if32(inst, rax);
                }
            }
            Code::Imul_rm8 | Code::Imul_rm16 | Code::Imul_rm32 | Code::Imul_rm64 => {
                let width = match code {
                    Code::Imul_rm8 => 1,
                    Code::Imul_rm16 => 2,
                    Code::Imul_rm32 => 4,
                    _ => 8,
                };
                let rax = MicroOperand::VReg(0);
                let right = self.operand_value(inst, 0)?;
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::Multiply { signed: true, width })
                        .with_dst(rax)
                        .with_src1(rax)
                        .with_src2(right),
                );
                if width == 4 {
                    self.zero_extend_dst_if32(inst, rax);
                }
            }

            // ── P2: IMUL 2/3-피연산자 (dst = dst·src 또는 dst = src·imm) ────────
            Code::Imul_r16_rm16
            | Code::Imul_r32_rm32
            | Code::Imul_r64_rm64
            | Code::Imul_r16_rm16_imm8
            | Code::Imul_r32_rm32_imm8
            | Code::Imul_r64_rm64_imm8
            | Code::Imul_r32_rm32_imm32
            | Code::Imul_r64_rm64_imm32 => {
                let width = match code {
                    Code::Imul_r16_rm16 | Code::Imul_r16_rm16_imm8 => 2,
                    Code::Imul_r32_rm32
                    | Code::Imul_r32_rm32_imm8
                    | Code::Imul_r32_rm32_imm32 => 4,
                    _ => 8,
                };
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid imul dst"))?;
                let (a, b) = if inst.op_count() == 3 {
                    (self.operand_value(inst, 1)?, MicroOperand::Imm64(inst.immediate64()))
                } else {
                    (dst, self.operand_value(inst, 1)?)
                };
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MultiplyLow { signed: true, width })
                        .with_dst(dst)
                        .with_src1(a)
                        .with_src2(b),
                );
                if width == 4 {
                    self.zero_extend_dst_if32(inst, dst);
                }
            }

            // ── P2: DIV / IDIV (RDX:RAX 피제수, RAX 몫) ─────────────────────────
            Code::Div_rm8 | Code::Div_rm16 | Code::Div_rm32 | Code::Div_rm64 => {
                let width = match code {
                    Code::Div_rm8 => 1,
                    Code::Div_rm16 => 2,
                    Code::Div_rm32 => 4,
                    _ => 8,
                };
                let divisor = self.operand_value(inst, 0)?;
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::Divide { signed: false, width })
                        .with_dst(MicroOperand::VReg(0))
                        .with_src1(divisor),
                );
            }
            Code::Idiv_rm8 | Code::Idiv_rm16 | Code::Idiv_rm32 | Code::Idiv_rm64 => {
                let width = match code {
                    Code::Idiv_rm8 => 1,
                    Code::Idiv_rm16 => 2,
                    Code::Idiv_rm32 => 4,
                    _ => 8,
                };
                let divisor = self.operand_value(inst, 0)?;
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::Divide { signed: true, width })
                        .with_dst(MicroOperand::VReg(0))
                        .with_src1(divisor),
                );
            }

            // ── P2: BSWAP ──────────────────────────────────────────────────────
            Code::Bswap_r32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid bswap dst"))?;
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::BSwap { width: 4 }).with_dst(dst).with_src1(dst),
                );
            }
            Code::Bswap_r64 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid bswap dst"))?;
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::BSwap { width: 8 }).with_dst(dst).with_src1(dst),
                );
            }

            // ── P2: BSF / BSR / TZCNT / LZCNT / POPCNT ─────────────────────────
            Code::Bsf_r16_rm16 | Code::Bsf_r32_rm32 | Code::Bsf_r64_rm64 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid bsf dst"))?;
                let src = self.operand_value(inst, 1)?;
                let w = match code {
                    Code::Bsf_r16_rm16 => 2,
                    Code::Bsf_r32_rm32 => 4,
                    _ => 8,
                };
                let src = self.mask_operand(src, w)?;
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::BitScanForward).with_dst(dst).with_src1(src),
                );
                if w == 4 {
                    self.zero_extend_dst_if32(inst, dst);
                }
            }
            Code::Bsr_r16_rm16 | Code::Bsr_r32_rm32 | Code::Bsr_r64_rm64 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid bsr dst"))?;
                let src = self.operand_value(inst, 1)?;
                let w = match code {
                    Code::Bsr_r16_rm16 => 2,
                    Code::Bsr_r32_rm32 => 4,
                    _ => 8,
                };
                let src = self.mask_operand(src, w)?;
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::BitScanReverse).with_dst(dst).with_src1(src),
                );
                if w == 4 {
                    self.zero_extend_dst_if32(inst, dst);
                }
            }
            Code::Tzcnt_r16_rm16 | Code::Tzcnt_r32_rm32 | Code::Tzcnt_r64_rm64 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid tzcnt dst"))?;
                let src = self.operand_value(inst, 1)?;
                let w = match code {
                    Code::Tzcnt_r16_rm16 => 2,
                    Code::Tzcnt_r32_rm32 => 4,
                    _ => 8,
                };
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::CountTrailingZeros { width: w })
                        .with_dst(dst)
                        .with_src1(src),
                );
                if w == 4 {
                    self.zero_extend_dst_if32(inst, dst);
                }
            }
            Code::Lzcnt_r16_rm16 | Code::Lzcnt_r32_rm32 | Code::Lzcnt_r64_rm64 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid lzcnt dst"))?;
                let src = self.operand_value(inst, 1)?;
                let w = match code {
                    Code::Lzcnt_r16_rm16 => 2,
                    Code::Lzcnt_r32_rm32 => 4,
                    _ => 8,
                };
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::CountLeadingZeros { width: w })
                        .with_dst(dst)
                        .with_src1(src),
                );
                if w == 4 {
                    self.zero_extend_dst_if32(inst, dst);
                }
            }
            Code::Popcnt_r16_rm16 | Code::Popcnt_r32_rm32 | Code::Popcnt_r64_rm64 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid popcnt dst"))?;
                let src = self.operand_value(inst, 1)?;
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::PopCount).with_dst(dst).with_src1(src),
                );
                if matches!(code, Code::Popcnt_r32_rm32) {
                    self.zero_extend_dst_if32(inst, dst);
                }
            }

            // ── P2: SETcc (16 조건) ────────────────────────────────────────────
            Code::Seta_rm8
            | Code::Setae_rm8
            | Code::Setb_rm8
            | Code::Setbe_rm8
            | Code::Sete_rm8
            | Code::Setne_rm8
            | Code::Setg_rm8
            | Code::Setge_rm8
            | Code::Setl_rm8
            | Code::Setle_rm8
            | Code::Seto_rm8
            | Code::Setno_rm8
            | Code::Setp_rm8
            | Code::Setnp_rm8
            | Code::Sets_rm8
            | Code::Setns_rm8 => {
                let cond = cond_for_setcc(code).expect("setcc cond");
                match inst.op0_kind() {
                    OpKind::Register => {
                        let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid setcc dst"))?;
                        self.desynth.instrs.push(
                            MicroInstr::new(RiscOp::Setcc { cond }).with_dst(dst),
                        );
                    }
                    OpKind::Memory => {
                        let addr = MicroOperand::Temp(4);
                        self.lower_effective_address(inst, addr)?;
                        let val = MicroOperand::Temp(5);
                        self.desynth.instrs.push(
                            MicroInstr::new(RiscOp::Setcc { cond }).with_dst(val),
                        );
                        self.desynth.instrs.push(
                            MicroInstr::new(RiscOp::MemoryWrite { width: 1 })
                                .with_src1(addr)
                                .with_src2(val),
                        );
                    }
                    _ => return Err(anyhow!("risc lifter: invalid setcc op0")),
                }
            }

            // ── P2: CMOVcc (16 조건 × 16/32/64) ───────────────────────────────
            Code::Cmova_r16_rm16
            | Code::Cmova_r32_rm32
            | Code::Cmova_r64_rm64
            | Code::Cmovae_r16_rm16
            | Code::Cmovae_r32_rm32
            | Code::Cmovae_r64_rm64
            | Code::Cmovb_r16_rm16
            | Code::Cmovb_r32_rm32
            | Code::Cmovb_r64_rm64
            | Code::Cmovbe_r16_rm16
            | Code::Cmovbe_r32_rm32
            | Code::Cmovbe_r64_rm64
            | Code::Cmove_r16_rm16
            | Code::Cmove_r32_rm32
            | Code::Cmove_r64_rm64
            | Code::Cmovne_r16_rm16
            | Code::Cmovne_r32_rm32
            | Code::Cmovne_r64_rm64
            | Code::Cmovg_r16_rm16
            | Code::Cmovg_r32_rm32
            | Code::Cmovg_r64_rm64
            | Code::Cmovge_r16_rm16
            | Code::Cmovge_r32_rm32
            | Code::Cmovge_r64_rm64
            | Code::Cmovl_r16_rm16
            | Code::Cmovl_r32_rm32
            | Code::Cmovl_r64_rm64
            | Code::Cmovle_r16_rm16
            | Code::Cmovle_r32_rm32
            | Code::Cmovle_r64_rm64
            | Code::Cmovo_r16_rm16
            | Code::Cmovo_r32_rm32
            | Code::Cmovo_r64_rm64
            | Code::Cmovno_r16_rm16
            | Code::Cmovno_r32_rm32
            | Code::Cmovno_r64_rm64
            | Code::Cmovp_r16_rm16
            | Code::Cmovp_r32_rm32
            | Code::Cmovp_r64_rm64
            | Code::Cmovnp_r16_rm16
            | Code::Cmovnp_r32_rm32
            | Code::Cmovnp_r64_rm64
            | Code::Cmovs_r16_rm16
            | Code::Cmovs_r32_rm32
            | Code::Cmovs_r64_rm64
            | Code::Cmovns_r16_rm16
            | Code::Cmovns_r32_rm32
            | Code::Cmovns_r64_rm64 => {
                let cond = cond_for_cmov(code).expect("cmov cond");
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid cmov dst"))?;
                let src = self.operand_value(inst, 1)?;
                let w = inst.op0_register().full_register();
                let is32 = matches!(w, Register::EAX | Register::ECX | Register::EDX | Register::EBX
                    | Register::ESP | Register::EBP | Register::ESI | Register::EDI
                    | Register::R8D | Register::R9D | Register::R10D | Register::R11D
                    | Register::R12D | Register::R13D | Register::R14D | Register::R15D);
                // 32비트: taken 경로만 0-확장해야 하므로 무조건 AND 대신 소스를
                // 미리 마스크해 ConditionalMove 가 쓸 값을 32비트로 제한한다.
                let src = if is32 {
                    self.mask_operand(src, 4)?
                } else {
                    src
                };
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::ConditionalMove { cond })
                        .with_dst(dst)
                        .with_src1(src),
                );
            }

            // ── P2: TEST (AND-플래그, 결과 폐기) ───────────────────────────────
            Code::Test_rm64_r64
            | Code::Test_rm64_imm32
            | Code::Test_RAX_imm32
            | Code::Test_rm32_r32
            | Code::Test_rm32_imm32
            | Code::Test_EAX_imm32
            | Code::Test_rm16_imm16
            | Code::Test_rm16_r16
            | Code::Test_AX_imm16
            | Code::Test_AL_imm8 => self.lift_test(inst)?,

            // ── P2: XCHG ───────────────────────────────────────────────────────
            Code::Xchg_rm64_r64 | Code::Xchg_rm32_r32 | Code::Xchg_rm16_r16 | Code::Xchg_rm8_r8 => {
                self.lift_xchg(inst)?;
            }

            // ── P2: XADD (메모리 RMW + 플래그) ─────────────────────────────────
            Code::Xadd_rm8_r8 | Code::Xadd_rm16_r16 | Code::Xadd_rm32_r32 | Code::Xadd_rm64_r64 => {
                self.lift_xadd(inst)?;
            }

            // ── P2: CMPXCHG (메모리 폼) ────────────────────────────────────────
            Code::Cmpxchg_rm8_r8 | Code::Cmpxchg_rm16_r16 | Code::Cmpxchg_rm32_r32 | Code::Cmpxchg_rm64_r64 => {
                if inst.op0_kind() == OpKind::Memory {
                    let width = match code {
                        Code::Cmpxchg_rm8_r8 => 1,
                        Code::Cmpxchg_rm16_r16 => 2,
                        Code::Cmpxchg_rm32_r32 => 4,
                        _ => 8,
                    };
                    let addr = MicroOperand::Temp(4);
                    self.lower_effective_address(inst, addr)?;
                    let newv = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid cmpxchg src"))?;
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::CompareExchange { width })
                            .with_src1(addr)
                            .with_src2(newv),
                    );
                } else {
                    // CMPXCHG 레지스터 폼(r/m = 레지스터) — 극히 드묾. 네이티브 유지.
                    return Err(anyhow!("risc lifter: CMPXCHG register form kept native"));
                }
            }

            // ── P2: INC / DEC ──────────────────────────────────────────────────
            Code::Inc_rm8 | Code::Inc_rm16 | Code::Inc_rm32 | Code::Inc_rm64
            | Code::Dec_rm8 | Code::Dec_rm16 | Code::Dec_rm32 | Code::Dec_rm64 => {
                let is_dec = matches!(code, Code::Dec_rm8 | Code::Dec_rm16 | Code::Dec_rm32 | Code::Dec_rm64);
                let width = match code {
                    Code::Inc_rm8 | Code::Dec_rm8 => 1,
                    Code::Inc_rm16 | Code::Dec_rm16 => 2,
                    Code::Inc_rm32 | Code::Dec_rm32 => 4,
                    _ => 8,
                };
                let one = MicroOperand::Imm64(1);
                match inst.op0_kind() {
                    OpKind::Register => {
                        let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid inc/dec dst"))?;
                        let a = self.mask_operand(dst, width)?;
                        if is_dec {
                            self.desynth.emit_sub(dst, a, one);
                        } else {
                            self.desynth.emit_add(dst, a, one);
                        }
                        self.mask_result(width, inst, dst)?;
                    }
                    OpKind::Memory => {
                        let addr = MicroOperand::Temp(4);
                        self.lower_effective_address(inst, addr)?;
                        let width_mem = inst.memory_size().size() as u8;
                        let left = MicroOperand::Temp(5);
                        self.desynth.instrs.push(
                            MicroInstr::new(RiscOp::MemoryRead { width: width_mem })
                                .with_dst(left)
                                .with_src1(addr),
                        );
                        let a = self.mask_operand(left, width)?;
                        if is_dec {
                            self.desynth.emit_sub(left, a, one);
                        } else {
                            self.desynth.emit_add(left, a, one);
                        }
                        self.mask_result(width, inst, left)?;
                        self.desynth.instrs.push(
                            MicroInstr::new(RiscOp::MemoryWrite { width: width_mem })
                                .with_src1(addr)
                                .with_src2(left),
                        );
                    }
                    _ => return Err(anyhow!("risc lifter: invalid inc/dec op0")),
                }
            }

            // ── P2: BMI1/2 (ANDN/BLSR/BLSMSK/BLSI/BZHI) ────────────────────────
            Code::VEX_Andn_r64_r64_rm64 | Code::VEX_Andn_r32_r32_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid andn dst"))?;
                let a = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid andn src"))?;
                let b = self.operand_value(inst, 2)?;
                let not = MicroOperand::Temp(0);
                self.desynth.emit_not(not, a);
                self.desynth.emit_and(dst, not, b);
                self.zero_extend_dst_if32(inst, dst);
            }
            Code::VEX_Blsr_r64_rm64 | Code::VEX_Blsr_r32_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid blsr dst"))?;
                let a = self.operand_value(inst, 1)?;
                let t = MicroOperand::Temp(0);
                self.desynth.emit_sub(t, a, MicroOperand::Imm64(1));
                self.desynth.emit_and(dst, t, a);
                self.zero_extend_dst_if32(inst, dst);
            }
            Code::VEX_Blsmsk_r64_rm64 | Code::VEX_Blsmsk_r32_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid blsmsk dst"))?;
                let a = self.operand_value(inst, 1)?;
                // emit_xor 는 내부적으로 Temp(0..2) 를 쓰므로, 그와 별개 Temp(3) 을 사용해
                // a-1 결과를 보존 (Temp(0) 이면 중간에 덮여 XOR 이 깨진다).
                let t = MicroOperand::Temp(3);
                self.desynth.emit_sub(t, a, MicroOperand::Imm64(1));
                self.desynth.emit_xor(dst, t, a);
                self.zero_extend_dst_if32(inst, dst);
            }
            Code::VEX_Blsi_r64_rm64 | Code::VEX_Blsi_r32_rm32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid blsi dst"))?;
                let a = self.operand_value(inst, 1)?;
                let t = MicroOperand::Temp(0);
                self.desynth.emit_neg(t, a);
                self.desynth.emit_and(dst, t, a);
                self.zero_extend_dst_if32(inst, dst);
            }
            Code::VEX_Bzhi_r64_rm64_r64 | Code::VEX_Bzhi_r32_rm32_r32 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid bzhi dst"))?;
                let a = self.operand_value(inst, 1)?;
                let idx = Self::reg_to_vreg(inst.op2_register()).ok_or_else(|| anyhow!("invalid bzhi index"))?;
                let t = MicroOperand::Temp(0);
                let mask = MicroOperand::Temp(1);
                self.desynth.emit_add(t, MicroOperand::Imm64(1), MicroOperand::Imm64(0));
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::ShiftLeft)
                        .with_dst(mask)
                        .with_src1(t)
                        .with_src2(idx),
                );
                self.desynth.emit_sub(mask, mask, MicroOperand::Imm64(1));
                self.desynth.emit_and(dst, a, mask);
                self.zero_extend_dst_if32(inst, dst);
            }

            // ── P2: PUSH/POP 메모리 폼 ────────────────────────────────────────
            Code::Push_rm64 => {
                let v = self.operand_value(inst, 0)?;
                self.desynth.emit_push(v);
            }
            Code::Pop_rm64 => {
                if inst.op0_kind() == OpKind::Register {
                    let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid pop dst"))?;
                    self.desynth.emit_pop(dst);
                } else if inst.op0_kind() == OpKind::Memory {
                    let addr = MicroOperand::Temp(4);
                    self.lower_effective_address(inst, addr)?;
                    let val = MicroOperand::Temp(5);
                    self.desynth.emit_pop(val);
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
                            .with_src1(addr)
                            .with_src2(val),
                    );
                } else {
                    return Err(anyhow!("risc lifter: invalid pop op0"));
                }
            }

            // ── P2: 문자열 ops ────────────────────────────────────────────────
            Code::Movsb_m8_m8 | Code::Movsw_m16_m16 | Code::Movsd_m32_m32 | Code::Movsq_m64_m64 => {
                self.lift_movs(inst)?
            }
            Code::Stosb_m8_AL | Code::Stosw_m16_AX | Code::Stosd_m32_EAX | Code::Stosq_m64_RAX => {
                self.lift_stos(inst)?
            }
            Code::Lodsb_AL_m8 | Code::Lodsw_AX_m16 | Code::Lodsd_EAX_m32 | Code::Lodsq_RAX_m64 => {
                self.lift_lods(inst)?
            }
            Code::Scasb_AL_m8 | Code::Scasw_AX_m16 | Code::Scasd_EAX_m32 | Code::Scasq_RAX_m64 => {
                self.lift_scas(inst)?
            }
            Code::Cmpsb_m8_m8 | Code::Cmpsw_m16_m16 | Code::Cmpsd_m32_m32 | Code::Cmpsq_m64_m64 => {
                self.lift_cmps(inst)?
            }
            // ── v65: Direction Flag — CLD clears DF, STD sets DF ─────────────
            Code::Cld => {
                // flags = flags & ~F_DF (status flags preserved).
                self.desynth.emit_and(
                    MicroOperand::Temp(3),
                    MicroOperand::Vflags,
                    MicroOperand::Imm64(!crate::vm::risc::flags::VFLAG_DF),
                );
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Temp(3)),
                );
            }
            Code::Std => {
                // flags = flags | F_DF (status flags preserved).
                self.desynth.emit_or(
                    MicroOperand::Temp(3),
                    MicroOperand::Vflags,
                    MicroOperand::Imm64(crate::vm::risc::flags::VFLAG_DF),
                );
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Temp(3)),
                );
            }

            // ── P2: SSE/FPU 스칼라 ────────────────────────────────────────────
            Code::Movsd_xmm_xmmm64 | Code::Movss_xmm_xmmm32 => self.lift_sse_mov_load(inst)?,
            Code::Movsd_xmmm64_xmm | Code::Movss_xmmm32_xmm => self.lift_sse_mov_store(inst)?,
            Code::Addsd_xmm_xmmm64 | Code::Addss_xmm_xmmm32 => self.lift_sse_fp_bin(inst, FPArith::Add)?,
            Code::Subsd_xmm_xmmm64 | Code::Subss_xmm_xmmm32 => self.lift_sse_fp_bin(inst, FPArith::Sub)?,
            Code::Mulsd_xmm_xmmm64 | Code::Mulss_xmm_xmmm32 => self.lift_sse_fp_bin(inst, FPArith::Mul)?,
            Code::Divsd_xmm_xmmm64 | Code::Divss_xmm_xmmm32 => self.lift_sse_fp_bin(inst, FPArith::Div)?,
            Code::Cvtsi2sd_xmm_rm32 | Code::Cvtsi2sd_xmm_rm64
            | Code::Cvtsi2ss_xmm_rm32 | Code::Cvtsi2ss_xmm_rm64 => self.lift_cvtsi2fp(inst)?,
            Code::Cvtss2sd_xmm_xmmm32 | Code::Cvtsd2ss_xmm_xmmm64 => self.lift_cvtfp2fp(inst)?,
            Code::Cvttss2si_r32_xmmm32 | Code::Cvttss2si_r64_xmmm32
            | Code::Cvtss2si_r32_xmmm32 | Code::Cvtss2si_r64_xmmm32
            | Code::Cvttsd2si_r32_xmmm64 | Code::Cvttsd2si_r64_xmmm64
            | Code::Cvtsd2si_r32_xmmm64 | Code::Cvtsd2si_r64_xmmm64 => self.lift_cvtfp2si(inst)?,

            _ => {
                // Fallback for unsupported complex instruction
                return Err(anyhow!("risc lifter: unsupported opcode {:?}", code));
            }
        }

        Ok(())
    }
}

mod tests {
    use super::*;
    use crate::vm::risc::{RiscEvalState, RiscProgram};
    use iced_x86::{Decoder, DecoderOptions};
    use iced_x86::{BlockEncoder, BlockEncoderOptions, Instruction, InstructionBlock};
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

    // ── P2: 새로 추가된 리프팅 경로 차등 검증 (선형 블록 단위 동치) ──────────────

    /// MUL r64 — RDX:RAX = RAX * rm (unsigned). low → dst(RAX), high → RDX.
    #[test]
    fn test_lift_mul_rm64() {
        // 0x140001000: mul rbx   (48 F7 E3)
        // 0x140001003: ret
        let raw = [0x48, 0xF7, 0xE3, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x8000_0000_0000_0000; // rax
        init[3] = 2;                      // rbx
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0, "MUL low word = 0x10000000000000000 mod 2^64");
        assert_eq!(regs(&st)[2], 1, "MUL high = 1 (RDX)");
    }

    /// IMUL r64,r64 (2-op) — dst = low(src1*src2).
    #[test]
    fn test_lift_imul_2op() {
        // 0x140001000: imul rax, rbx   (48 0F AF C3)
        // 0x140001004: ret
        let raw = [0x48, 0x0F, 0xAF, 0xC3, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 7;
        init[3] = 6;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 42, "IMUL 2-op product");
    }

    /// IMUL r64,r64,imm8 (3-op) — dst = src*imm.
    #[test]
    fn test_lift_imul_3op_imm() {
        // 0x140001000: imul rax, rbx, 5   (48 6B C3 05)
        // 0x140001004: ret
        let raw = [0x48, 0x6B, 0xC3, 0x05, 0xC3];
        let mut init = [0u64; 16];
        init[3] = 9; // rbx
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 45, "IMUL 3-op imm product");
    }

    /// DIV r64 — RDX:RAX / rm → RAX=quotient, RDX=remainder.
    #[test]
    fn test_lift_div_rm64() {
        // 0x140001000: div rbx   (48 F7 F3)
        // 0x140001003: ret
        let raw = [0x48, 0xF7, 0xF3, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 1000; // rax
        init[2] = 0;    // rdx
        init[3] = 7;    // rbx
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 142, "DIV quotient");
        assert_eq!(regs(&st)[2], 6, "DIV remainder");
    }

    /// IDIV r64 — signed divide.
    #[test]
    fn test_lift_idiv_rm64() {
        // 0x140001000: idiv rbx   (48 F7 FB)
        // 0x140001003: ret
        let raw = [0x48, 0xF7, 0xFB, 0xC3];
        let mut init = [0u64; 16];
        init[0] = (-1000i64) as u64; // rax
        init[2] = (-1i64) as u64;     // rdx = sign-extended
        init[3] = 7;                  // rbx
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0] as i64, -142, "IDIV quotient");
        assert_eq!(regs(&st)[2] as i64, -6, "IDIV remainder");
    }

    /// BSWAP r64 — byte order reversal.
    #[test]
    fn test_lift_bswap() {
        // 0x140001000: bswap rax   (48 0F C8)
        // 0x140001003: ret
        let raw = [0x48, 0x0F, 0xC8, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x0102_0304_0506_0708;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0x0807_0605_0403_0201, "BSWAP reverses bytes");
    }

    /// BSF / BSR — least/most-significant set bit index.
    #[test]
    fn test_lift_bsf_bsr() {
        // 0x140001000: bsf rax, rbx   (48 0F BC C3)
        // 0x140001004: bsr rcx, rbx   (48 0F BD CB)
        // 0x140001008: ret
        let raw = [0x48, 0x0F, 0xBC, 0xC3, 0x48, 0x0F, 0xBD, 0xCB, 0xC3];
        let mut init = [0u64; 16];
        init[3] = 0x1000; // rbx
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 12, "BSF index of bit 12");
        assert_eq!(regs(&st)[1], 12, "BSR index of bit 12");
    }

    /// TZCNT / LZCNT / POPCNT.
    #[test]
    fn test_lift_tzcnt_lzcnt_popcnt() {
        // tzcnt rax, rbx   F3 48 0F BC C3
        // lzcnt rcx, rbx   F3 48 0F BD CB
        // popcnt rdx, rbx  F3 48 0F B8 D3
        let raw = [
            0xF3, 0x48, 0x0F, 0xBC, 0xC3,
            0xF3, 0x48, 0x0F, 0xBD, 0xCB,
            0xF3, 0x48, 0x0F, 0xB8, 0xD3,
            0xC3,
        ];
        let mut init = [0u64; 16];
        init[3] = 0x1000; // rbx
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 12, "TZCNT = ctz(0x1000)");
        assert_eq!(regs(&st)[1], 51, "LZCNT = 63-12");
        assert_eq!(regs(&st)[2], 1, "POPCNT(0x1000) = 1");
    }

    /// SETcc — flag-conditional byte write (equal → SETE=1, SETNE=0).
    #[test]
    fn test_lift_setcc() {
        // cmp rax, rbx (48 39 D8) ; sete al (0F 94 C0) ; setne bl (0F 95 C3) ; ret
        let raw = [0x48, 0x39, 0xD8, 0x0F, 0x94, 0xC0, 0x0F, 0x95, 0xC3, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 5;
        init[3] = 5;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0] & 0xFF, 1, "SETE when equal");
        assert_eq!(regs(&st)[3] & 0xFF, 0, "SETNE when equal → 0");
    }

    /// CMOVcc — conditional move (equal → CMOVE takes).
    #[test]
    fn test_lift_cmovcc() {
        // cmp rax, rbx (48 39 D8) ; cmove rcx, rdx (48 0F 44 CA) ; ret
        let raw = [0x48, 0x39, 0xD8, 0x48, 0x0F, 0x44, 0xCA, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 5;
        init[3] = 5;
        init[2] = 0xDEAD;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[1], 0xDEAD, "CMOVE taken when equal");
    }

    /// TEST — AND flags without writing a destination.
    #[test]
    fn test_lift_test() {
        // test rax, rbx (48 85 D8) ; ret
        let raw = [0x48, 0x85, 0xD8, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0;
        init[3] = 0;
        let st = run(&raw, 0x140001000, init);
        assert_ne!(st.flags & crate::vm::risc::flags::VFLAG_ZF, 0, "TEST 0&0 → ZF");
        // nonzero result → ZF clear
        let mut init2 = [0u64; 16];
        init2[0] = 0xF0;
        init2[3] = 0xF0;
        let st2 = run(&raw, 0x140001000, init2);
        assert_eq!(st2.flags & crate::vm::risc::flags::VFLAG_ZF, 0, "TEST F0&F0 → !ZF");
    }

    /// XCHG r64,r64 — register swap.
    #[test]
    fn test_lift_xchg_reg() {
        // 0x140001000: xchg rax, rbx (48 87 D8) ; ret
        let raw = [0x48, 0x87, 0xD8, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 1;
        init[3] = 2;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 2, "XCHG rax");
        assert_eq!(regs(&st)[3], 1, "XCHG rbx");
    }

    /// XADD r64,r64 — dst += src; src = old dst.
    #[test]
    fn test_lift_xadd_reg() {
        // 0x140001000: xadd rax, rbx (48 0F C1 D8) ; ret
        let raw = [0x48, 0x0F, 0xC1, 0xD8, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 3;
        init[3] = 5;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 8, "XADD dst = 3+5");
        assert_eq!(regs(&st)[3], 3, "XADD src = old dst");
    }

    /// INC / DEC — width-masked register forms (INC preserves CF).
    #[test]
    fn test_lift_inc_dec() {
        // inc eax (FF C0) ; dec rax (48 FF C8) ; ret
        let raw = [0xFF, 0xC0, 0x48, 0xFF, 0xC8, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 5;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 5, "inc eax(5→6) then dec rax(6→5)");
    }

    /// RET imm16 — RSP += imm before Halt.
    #[test]
    fn test_lift_ret_imm16() {
        // 0x140001000: ret 8 (C2 08 00)
        let raw = [0xC2, 0x08, 0x00];
        let st = run(&raw, 0x140001000, [0u64; 16]);
        assert_eq!(regs(&st)[4], 8, "RET imm16 advances RSP by 8");
    }

    /// PUSH r64 / POP r64 — stack roundtrip.
    #[test]
    fn test_lift_push_pop() {
        // push rax (50) ; pop rbx (5B) ; ret
        let raw = [0x50, 0x5B, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0xCAFE;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[3], 0xCAFE, "push rax; pop rbx");
        assert_eq!(st.vsp, 0, "push/pop balanced");
    }

    /// CMPXCHG (mem form) — lift path emits CompareExchange micro-op.
    #[test]
    fn test_lift_cmpxchg_mem() {
        // cmpxchg [rax], rbx (48 0F B1 18) ; ret
        let raw = [0x48, 0x0F, 0xB1, 0x18, 0xC3];
        let prog = lift(&raw, 0x140001000);
        assert!(
            prog.instrs.iter().any(|i| matches!(i.op, RiscOp::CompareExchange { width: 8 })),
            "CMPXCHG mem lifts to CompareExchange"
        );
    }

    /// XCHG mem↔reg — lift path emits memory RMW (read + write).
    #[test]
    fn test_lift_xchg_mem() {
        // xchg [rax], rbx (48 87 18) ; ret
        let raw = [0x48, 0x87, 0x18, 0xC3];
        let prog = lift(&raw, 0x140001000);
        let has_rd = prog.instrs.iter().any(|i| matches!(i.op, RiscOp::MemoryRead { .. }));
        let has_wr = prog.instrs.iter().any(|i| matches!(i.op, RiscOp::MemoryWrite { .. }));
        assert!(has_rd && has_wr, "XCHG mem lifts to memory RMW");
    }

    /// XADD (mem form) — lift path emits memory RMW.
    #[test]
    fn test_lift_xadd_mem() {
        // xadd [rax], rbx (48 0F C1 18) ; ret
        let raw = [0x48, 0x0F, 0xC1, 0x18, 0xC3];
        let prog = lift(&raw, 0x140001000);
        let has_rd = prog.instrs.iter().any(|i| matches!(i.op, RiscOp::MemoryRead { .. }));
        let has_wr = prog.instrs.iter().any(|i| matches!(i.op, RiscOp::MemoryWrite { .. }));
        assert!(has_rd && has_wr, "XADD mem lifts to memory RMW");
    }

    /// BMI1 ANDN — lift path emits NOT+AND (VEX encoding via BlockEncoder).
    #[test]
    fn test_lift_andn() {
        use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};
        let insts = vec![
            Instruction::with3(Code::VEX_Andn_r64_r64_rm64, Register::RAX, Register::RBX, Register::RCX).unwrap(),
            Instruction::with(Code::Retnq),
        ];
        let blk = InstructionBlock::new(&insts, 0x140001000);
        let enc = BlockEncoder::encode(64, blk, BlockEncoderOptions::NONE).unwrap();
        let mut init = [0u64; 16];
        init[3] = 0x0F; // rbx (vreg 3)
        init[1] = 0xFF; // rcx (vreg 1)
        let st = run(&enc.code_buffer, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0xF0, "ANDN = ~rbx & rcx = ~0x0F & 0xFF");
    }

    // ── P2: 문자열 ops 차등 검증 (선형 블록 단위 동치) ──────────────────────────

    /// 테스트 메모리 헬퍼: 리틀엔디언 `width`바이트 기록.
    fn seed_mem(mem: &mut HashMap<u64, u8>, addr: u64, width: u8, val: u64) {
        for i in 0..width {
            mem.insert(addr.wrapping_add(i as u64), (val >> (i as u64 * 8)) as u8);
        }
    }

    /// 테스트 메모리 헬퍼: 리틀엔디언 `width`바이트 읽기.
    fn read_mem(mem: &HashMap<u64, u8>, addr: u64, width: u8) -> u64 {
        let mut v = 0u64;
        for i in 0..width {
            v |= (*mem.get(&addr.wrapping_add(i as u64)).unwrap_or(&0) as u64) << (i as u64 * 8);
        }
        v
    }

    /// lift + `eval_state_with_mem` 실행 헬퍼.
    fn run_mem(raw: &[u8], ip: u64, init: [u64; 16], mem: HashMap<u64, u8>) -> RiscEvalState {
        lift(raw, ip).eval_state_with_mem(&init, mem)
    }

    /// BlockEncoder 로 x86 명령 블록을 바이트로 인코딩.
    fn enc_block(insts: Vec<Instruction>) -> Vec<u8> {
        let blk = InstructionBlock::new(&insts, 0x140001000);
        BlockEncoder::encode(64, blk, BlockEncoderOptions::NONE).unwrap().code_buffer
    }

    /// XMM(i) 슬롯 가상 주소 (리프터와 동일 계약).
    fn xmm_slot(idx: u8) -> u64 {
        super::XMM_SLOT_BASE + (idx as u64) * 16
    }

    /// MOVSB (단일) — [rdi]=[rsi]; rsi/rdi += 1.
    #[test]
    fn test_lift_movsb_single() {
        let raw = [0xA4, 0xC3];
        let mut init = [0u64; 16];
        init[6] = 0x1000;
        init[7] = 0x2000;
        let mut mem = HashMap::new();
        mem.insert(0x1000, 0xAB);
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(st.regs[6], 0x1001, "rsi advanced by 1");
        assert_eq!(st.regs[7], 0x2001, "rdi advanced by 1");
        assert_eq!(st.mem.get(&0x2000), Some(&0xAB), "byte copied");
    }

    /// STOSD (단일) — [rdi]=EAX; rdi+=4.
    #[test]
    fn test_lift_stosd_single() {
        let raw = [0xAB, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0xDEAD_BEEF;
        init[7] = 0x2000;
        let st = run_mem(&raw, 0x140001000, init, HashMap::new());
        assert_eq!(st.regs[7], 0x2004, "rdi advanced by 4");
        assert_eq!(read_mem(&st.mem, 0x2000, 4), 0xDEAD_BEEF, "dword stored");
    }

    /// LODSW (단일) — AX = [rsi] (0-확장); rsi+=2.
    #[test]
    fn test_lift_lodsw_single() {
        let raw = [0x66, 0xAD, 0xC3];
        let mut init = [0u64; 16];
        init[6] = 0x1000;
        let mut mem = HashMap::new();
        seed_mem(&mut mem, 0x1000, 2, 0x7AB9);
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(st.regs[0], 0x7AB9, "AX = [rsi] zero-extended");
        assert_eq!(st.regs[6], 0x1002, "rsi advanced by 2");
    }

    /// SCASB (단일) — flags = AL - [rdi]; rdi+=1.
    #[test]
    fn test_lift_scasb_single() {
        let raw = [0xAE, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x20;
        init[7] = 0x2000;
        let mut mem = HashMap::new();
        mem.insert(0x2000, 0x20);
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(st.regs[7], 0x2001, "rdi advanced");
        assert_ne!(st.flags & crate::vm::risc::flags::VFLAG_ZF, 0, "AL == [rdi] -> ZF");
    }

    /// CMPSQ (단일) — flags = [rsi] - [rdi]; rsi+=8; rdi+=8.
    #[test]
    fn test_lift_cmpsq_single() {
        let raw = [0x48, 0xA7, 0xC3];
        let mut init = [0u64; 16];
        init[6] = 0x1000;
        init[7] = 0x2000;
        let mut mem = HashMap::new();
        seed_mem(&mut mem, 0x1000, 8, 0x1234);
        seed_mem(&mut mem, 0x2000, 8, 0x1234);
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(st.regs[6], 0x1008, "rsi advanced by 8");
        assert_eq!(st.regs[7], 0x2008, "rdi advanced by 8");
        assert_ne!(st.flags & crate::vm::risc::flags::VFLAG_ZF, 0, "equal -> ZF");
    }

    /// REP MOVSB — 카운트-다운 루프: rcx 소비, rsi/rdi += n*count, 메모리 복사.
    #[test]
    fn test_lift_rep_movsb() {
        let raw = [0xF3, 0xA4, 0xC3];
        let mut init = [0u64; 16];
        init[6] = 0x1000;
        init[7] = 0x2000;
        init[1] = 3;
        let mut mem = HashMap::new();
        mem.insert(0x1000, 0x11);
        mem.insert(0x1001, 0x22);
        mem.insert(0x1002, 0x33);
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(st.regs[1], 0, "rcx consumed");
        assert_eq!(st.regs[6], 0x1003, "rsi += 3");
        assert_eq!(st.regs[7], 0x2003, "rdi += 3");
        assert_eq!(st.mem.get(&0x2000), Some(&0x11));
        assert_eq!(st.mem.get(&0x2002), Some(&0x33));
    }

    /// v65: `std; rep movsb` — DF=1 → rsi/rdi DECREMENTED, bytes copied backward.
    #[test]
    fn test_lift_std_rep_movsb_backward() {
        let raw = [0xFD, 0xF3, 0xA4, 0xC3]; // std; rep movsb
        let mut init = [0u64; 16];
        init[6] = 0x1002; // rsi = last byte of source {0x11,0x22,0x33}
        init[7] = 0x2003; // rdi = last byte of dest
        init[1] = 3;
        let mut mem = HashMap::new();
        mem.insert(0x1000, 0x11);
        mem.insert(0x1001, 0x22);
        mem.insert(0x1002, 0x33);
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(st.regs[1], 0, "rcx consumed");
        assert_eq!(st.regs[6], 0x0FFF, "std rsi -= 3");
        assert_eq!(st.regs[7], 0x2000, "std rdi -= 3");
        // iter i writes [rdi] BEFORE decrementing: 0x2003,0x2002,0x2001
        assert_eq!(st.mem.get(&0x2003), Some(&0x33), "backward copy: first iter writes [0x2003]");
        assert_eq!(st.mem.get(&0x2002), Some(&0x22));
        assert_eq!(st.mem.get(&0x2001), Some(&0x11));
        // DF bit must remain set in the modelled flags
        assert_ne!(st.flags & crate::vm::risc::flags::VFLAG_DF, 0, "std leaves DF set");
    }

    /// REP STOSB — 루프로 메모리 채우기.
    #[test]
    fn test_lift_rep_stosb() {
        let raw = [0xF3, 0xAA, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x5A;
        init[7] = 0x2000;
        init[1] = 4;
        let st = run_mem(&raw, 0x140001000, init, HashMap::new());
        assert_eq!(st.regs[1], 0, "rcx consumed");
        assert_eq!(st.regs[7], 0x2004, "rdi += 4");
        for i in 0..4u64 {
            assert_eq!(st.mem.get(&(0x2000 + i)), Some(&0x5A), "byte {i} stored");
        }
    }

    /// REP LODSQ — 루프로 RAX 갱신 (마지막 로드), rsi += 8*count.
    #[test]
    fn test_lift_rep_lodsq() {
        let raw = [0xF3, 0x48, 0xAD, 0xC3];
        let mut init = [0u64; 16];
        init[6] = 0x1000;
        init[1] = 3;
        let mut mem = HashMap::new();
        seed_mem(&mut mem, 0x1000, 8, 111);
        seed_mem(&mut mem, 0x1008, 8, 222);
        seed_mem(&mut mem, 0x1010, 8, 333);
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(st.regs[1], 0, "rcx consumed");
        assert_eq!(st.regs[6], 0x1018, "rsi += 24");
        assert_eq!(st.regs[0], 333, "last loaded qword");
    }

    /// REPE SCASB — 불일치에서 중단; rdi/rcx 는 중단 반복까지 진행, 최종 플래그 = 마지막 비교.
    #[test]
    fn test_lift_repe_scasb_stops_on_mismatch() {
        let raw = [0xF3, 0xAE, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x20;
        init[7] = 0x2000;
        init[1] = 3;
        let mut mem = HashMap::new();
        mem.insert(0x2000, 0x20); // match -> continue
        mem.insert(0x2001, 0x21); // mismatch -> stop
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(st.regs[7], 0x2002, "two iterations advanced rdi");
        assert_eq!(st.regs[1], 1, "rcx = 3-2");
        assert_eq!(st.flags & crate::vm::risc::flags::VFLAG_ZF, 0, "final compare not equal -> ZF clear");
    }

    /// REPNE CMPSW — 일치에서 중단 (REPNE 는 ZF=1 에서 정지).
    #[test]
    fn test_lift_repne_cmpsw_stops_on_match() {
        let raw = [0xF2, 0x66, 0xA7, 0xC3];
        let mut init = [0u64; 16];
        init[6] = 0x1000;
        init[7] = 0x2000;
        init[1] = 4;
        let mut mem = HashMap::new();
        seed_mem(&mut mem, 0x1000, 2, 0x1111);
        seed_mem(&mut mem, 0x2000, 2, 0x2222);
        seed_mem(&mut mem, 0x1002, 2, 0x3333);
        seed_mem(&mut mem, 0x2002, 2, 0x3333);
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(st.regs[6], 0x1004, "two iters advanced rsi");
        assert_eq!(st.regs[7], 0x2004, "two iters advanced rdi");
        assert_eq!(st.regs[1], 2, "rcx = 4-2");
        assert_ne!(st.flags & crate::vm::risc::flags::VFLAG_ZF, 0, "final compare equal -> ZF set");
    }

    // ── P2: SSE/FPU 스칼라 차등 검증 ──────────────────────────────────────────

    /// ADDSD xmm0, xmm1 — 1.5 + 2.25 = 3.75.
    #[test]
    fn test_lift_addsd() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Addsd_xmm_xmmm64, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        seed_mem(&mut mem, xmm_slot(0), 8, 1.5f64.to_bits());
        seed_mem(&mut mem, xmm_slot(1), 8, 2.25f64.to_bits());
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        assert_eq!(f64::from_bits(read_mem(&st.mem, xmm_slot(0), 8)), 3.75, "1.5 + 2.25");
    }

    /// MULSD + DIVSD — (3.0 * 2.0) / 4.0 = 1.5.
    #[test]
    fn test_lift_mulsd_divsd() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Mulsd_xmm_xmmm64, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with2(Code::Divsd_xmm_xmmm64, Register::XMM0, Register::XMM2).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        seed_mem(&mut mem, xmm_slot(0), 8, 3.0f64.to_bits());
        seed_mem(&mut mem, xmm_slot(1), 8, 2.0f64.to_bits());
        seed_mem(&mut mem, xmm_slot(2), 8, 4.0f64.to_bits());
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        assert_eq!(f64::from_bits(read_mem(&st.mem, xmm_slot(0), 8)), 1.5, "mul then div");
    }

    /// SUBSS (f32) — 5.5f32 - 1.25f32 = 4.25f32.
    #[test]
    fn test_lift_subss() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Subss_xmm_xmmm32, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        seed_mem(&mut mem, xmm_slot(0), 4, 5.5f32.to_bits() as u64);
        seed_mem(&mut mem, xmm_slot(1), 4, 1.25f32.to_bits() as u64);
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        assert_eq!(f32::from_bits(read_mem(&st.mem, xmm_slot(0), 4) as u32), 4.25f32);
    }

    /// CVTSI2SD xmm0, rax — 정수 -> double.
    #[test]
    fn test_lift_cvtsi2sd() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Cvtsi2sd_xmm_rm64, Register::XMM0, Register::RAX).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut init = [0u64; 16];
        init[0] = 42;
        let st = run_mem(&raw, 0x140001000, init, HashMap::new());
        assert_eq!(f64::from_bits(read_mem(&st.mem, xmm_slot(0), 8)), 42.0);
    }

    /// CVTSS2SD (f32->f64) + CVTSD2SS (f64->f32).
    #[test]
    fn test_lift_cvtss2sd_cvtsd2ss() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Cvtss2sd_xmm_xmmm32, Register::XMM1, Register::XMM0).unwrap(),
            Instruction::with2(Code::Cvtsd2ss_xmm_xmmm64, Register::XMM2, Register::XMM1).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        seed_mem(&mut mem, xmm_slot(0), 4, 2.5f32.to_bits() as u64);
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        assert_eq!(f64::from_bits(read_mem(&st.mem, xmm_slot(1), 8)), 2.5, "f32->f64");
        assert_eq!(f32::from_bits(read_mem(&st.mem, xmm_slot(2), 4) as u32), 2.5f32, "f64->f32");
    }

    /// CVTTSS2SI(trunc) vs CVTSS2SI(nearest-even) — half-way 반올림 차이.
    #[test]
    fn test_lift_cvttss2si_trunc_vs_cvtss2si_round() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Cvttss2si_r64_xmmm32, Register::RAX, Register::XMM0).unwrap(), // trunc(2.5)=2
            Instruction::with2(Code::Cvtss2si_r64_xmmm32, Register::RBX, Register::XMM0).unwrap(), // rne(2.5)=2
            Instruction::with2(Code::Cvttss2si_r64_xmmm32, Register::RCX, Register::XMM1).unwrap(), // trunc(3.5)=3
            Instruction::with2(Code::Cvtss2si_r64_xmmm32, Register::RDX, Register::XMM1).unwrap(), // rne(3.5)=4
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        seed_mem(&mut mem, xmm_slot(0), 4, 2.5f32.to_bits() as u64);
        seed_mem(&mut mem, xmm_slot(1), 4, 3.5f32.to_bits() as u64);
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        assert_eq!(st.regs[0] as i64, 2, "trunc(2.5)=2 (rax)");
        assert_eq!(st.regs[3] as i64, 2, "rne(2.5)=2 even (rbx)");
        assert_eq!(st.regs[1] as i64, 3, "trunc(3.5)=3 (rcx)");
        assert_eq!(st.regs[2] as i64, 4, "rne(3.5)=4 even (rdx)");
    }

    /// MOVSD xmm0, xmm1 (레지스터 로드 폼) — 하위 8바이트 복사.
    #[test]
    fn test_lift_movsd_reg() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Movsd_xmm_xmmm64, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        seed_mem(&mut mem, xmm_slot(1), 8, 9.75f64.to_bits());
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        assert_eq!(f64::from_bits(read_mem(&st.mem, xmm_slot(0), 8)), 9.75);
    }

    /// MOVSD [rax], xmm0 (메모리 스토어) + MOVSD xmm1, [rax] (메모리 로드).
    #[test]
    fn test_lift_movsd_mem_load_store() {
        let raw = enc_block(vec![
            Instruction::with2(
                Code::Movsd_xmmm64_xmm,
                iced_x86::MemoryOperand::with_base(Register::RAX),
                Register::XMM0,
            )
            .unwrap(),
            Instruction::with2(
                Code::Movsd_xmm_xmmm64,
                Register::XMM1,
                iced_x86::MemoryOperand::with_base(Register::RAX),
            )
            .unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut init = [0u64; 16];
        init[0] = 0x4000;
        let mut mem = HashMap::new();
        seed_mem(&mut mem, xmm_slot(0), 8, 1234.5f64.to_bits());
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(f64::from_bits(read_mem(&st.mem, 0x4000, 8)), 1234.5, "stored to mem");
        assert_eq!(f64::from_bits(read_mem(&st.mem, xmm_slot(1), 8)), 1234.5, "loaded back to xmm1");
    }

    // ── P2: BMI (BLSR/BLSMSK/BLSI/BZHI) 차등 검증 ────────────────────────────

    /// BLSR r64 — x & (x-1) (lowest set bit clear).
    #[test]
    fn test_lift_blsr() {
        let raw = enc_block(vec![
            Instruction::with2(Code::VEX_Blsr_r64_rm64, Register::RAX, Register::RBX).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut init = [0u64; 16];
        init[3] = 0b1110;
        let st = run_mem(&raw, 0x140001000, init, HashMap::new());
        assert_eq!(st.regs[0], 0b1100, "BLSR(0b1110) = 0b1110 & 0b1101");
    }

    /// BLSMSK r64 — x ^ (x-1).
    #[test]
    fn test_lift_blsmsk() {
        let raw = enc_block(vec![
            Instruction::with2(Code::VEX_Blsmsk_r64_rm64, Register::RAX, Register::RBX).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut init = [0u64; 16];
        init[3] = 0b1110;
        let st = run_mem(&raw, 0x140001000, init, HashMap::new());
        assert_eq!(st.regs[0], 0b0011, "BLSMSK(0b1110) = 0b1110 ^ 0b1101");
    }

    /// BLSI r64 — x & -x (lowest set bit).
    #[test]
    fn test_lift_blsi() {
        let raw = enc_block(vec![
            Instruction::with2(Code::VEX_Blsi_r64_rm64, Register::RAX, Register::RBX).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut init = [0u64; 16];
        init[3] = 0x18;
        let st = run_mem(&raw, 0x140001000, init, HashMap::new());
        assert_eq!(st.regs[0], 0b1000, "BLSI(0x18) = lowest set bit");
    }

    /// BZHI r64, r/m64, r64 — dst = x & ((1<<idx)-1).
    #[test]
    fn test_lift_bzhi() {
        let raw = enc_block(vec![
            Instruction::with3(Code::VEX_Bzhi_r64_rm64_r64, Register::RAX, Register::RBX, Register::RCX).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut init = [0u64; 16];
        init[3] = 0xFF;
        init[1] = 4;
        let st = run_mem(&raw, 0x140001000, init, HashMap::new());
        assert_eq!(st.regs[0], 0x0F, "BZHI(0xFF, 4) = 0x0F");
    }
}