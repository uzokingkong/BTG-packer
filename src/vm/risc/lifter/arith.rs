// ==============================================================================
// BTG - RISC Lifter: arith / shift / mask / atomic - split from lifter.rs
// ==============================================================================

use super::*;

impl RiscLifter {
    pub(super) fn lift_binary_alu(&mut self, inst: &Instruction, alu: Alu) -> Result<()> {
        // P0-1: x86 SUB은 borrow-CF(네이티브 플래그 소비 분기 정합)를 위해
        // desynth(AddWithCarry) 대신 전용 SubWithBorrow(width)로 lift한다.
        let width = Self::operand_width(inst);
        match inst.op0_kind() {
            OpKind::Register => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let right = self.operand_value(inst, 1)?;
                // P2 (G3): 8/16비트 레지스터 Add/Sub는 상위 비트 보존이 필요하다.
                // Add/Sub{width}가 dst를 마스크로 덮어쓰므로, **먼저** 원본을 Temp(0)에
                // 저장한 뒤 결과를 합성한다: dst = (orig & ~mask) | masked.
                let preserve = (alu == Alu::Add || alu == Alu::Sub) && (width == 1 || width == 2);
                if preserve {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov).with_dst(MicroOperand::Temp(0)).with_src1(dst),
                    );
                }
                if alu == Alu::Sub {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::SubWithBorrow { width })
                            .with_dst(dst)
                            .with_src1(dst)
                            .with_src2(right),
                    );
                } else if alu == Alu::Add {
                    // P0-1: 폭별(32/64) ADD — bit 31/63 플래그 경계 정확.
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Add { width })
                            .with_dst(dst)
                            .with_src1(dst)
                            .with_src2(right),
                    );
                } else {
                    alu.emit(&mut self.desynth, dst, dst, right);
                }
                // P0-1: Add/Sub{width}는 eval에서 폭별 마스킹+플래그를 처리하므로
                // zero-extend(AND)로 플래그를 클로버하지 않는다. (다른 ALU만 제로확장)
                if alu != Alu::Add && alu != Alu::Sub {
                    self.zero_extend_dst_if32(inst, dst);
                }
                if preserve {
                    self.preserve_upper(dst, width);
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
                let right = self.operand_value(inst, 1)?;
                if alu == Alu::Sub {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::SubWithBorrow { width })
                            .with_dst(left)
                            .with_src1(left)
                            .with_src2(right),
                    );
                } else if alu == Alu::Add {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Add { width })
                            .with_dst(left)
                            .with_src1(left)
                            .with_src2(right),
                    );
                } else {
                    alu.emit(&mut self.desynth, left, left, right);
                }
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
    /// P0-1: borrow-CF 정확 — 전용 SubWithBorrow(width).
    pub(super) fn lift_cmp(&mut self, inst: &Instruction) -> Result<()> {
        let width = Self::operand_width(inst);
        let left = self.operand_value(inst, 0)?;
        let right = self.operand_value(inst, 1)?;
        let scratch = MicroOperand::Temp(7);
        // P2 (G3): 8/16비트 CMP는 low-byte/word만 비교한다. 레지스터 피연산자는
        // 상위 비트(0-확장되지 않음)가 결과/플래그를 오염시키므로 폭으로 마스크한다.
        // (메모리는 MemoryRead{width}가 이미 0-확장, imm은 이미 폭 안.)
        let left = self.mask_reg_operand(left, width, MicroOperand::Temp(3))?;
        let right = self.mask_reg_operand(right, width, MicroOperand::Temp(2))?;
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::SubWithBorrow { width })
                .with_dst(scratch)
                .with_src1(left)
                .with_src2(right),
        );
        Ok(())
    }

    /// P2 (G3): 8/16비트 연산에서 **레지스터** 피연산자만 폭으로 마스크해 지정
    /// temp에 저장한다 (x86은 low-byte/word만 사용). 메모리/즉시 피연산자는 그대로.
    fn mask_reg_operand(&mut self, op: MicroOperand, width: u8, temp: MicroOperand) -> Result<MicroOperand> {
        if width >= 8 {
            return Ok(op);
        }
        let mask = if width == 1 { 0xFF } else { 0xFFFF };
        if matches!(op, MicroOperand::VReg(_)) {
            self.desynth.emit_and(temp, op, MicroOperand::Imm64(mask));
            Ok(temp)
        } else {
            Ok(op)
        }
    }

    /// P2 (G3): op를 `width`로 마스크해 **지정 temp**에 저장한다.
    /// (`mask_operand`의 공용 Temp(3) clobber를 피해 TEST처럼 두 피연산자를 동시에
    /// 마스크할 때 서로 다른 temp를 쓴다.)
    pub(super) fn mask_operand_into(
        &mut self,
        op: MicroOperand,
        width: u8,
        temp: MicroOperand,
    ) -> Result<MicroOperand> {
        let mask = match width {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            _ => return Ok(op),
        };
        self.desynth.emit_and(temp, op, MicroOperand::Imm64(mask));
        Ok(temp)
    }

    /// SHL/SHR/SAR (32/64-bit, count: imm8 / 1 / CL).
    /// x86 시프트 횟수 마스크: 32비트 피연산자는 mod 32(31), 64비트는 mod 64(63).
    /// 32비트 레지스터 시프트 결과는 상위 32비트를 0으로 정리한다.

    pub(super) fn lift_shift(&mut self, inst: &Instruction, op: RiscOp) -> Result<()> {
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

    pub(super) fn lift_movzx(&mut self, inst: &Instruction, mask: u64) -> Result<()> {
        let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid movzx dst"))?;
        let src = self.operand_value(inst, 1)?;
        self.desynth.emit_and(dst, src, MicroOperand::Imm64(mask));
        Ok(())
    }

    /// MOVSX: 8/16/32-bit 소스를 부호 확장(sign-extend)해 64비트 결과로.
    /// `ArithmeticShiftRight`를 이용해 `(src << (64-w)) >> (64-w)`(산술 시프트)로
    /// 부호 비트를 복제한다. (MOVSX는 논리 시프트만으로는 표현 불가 — 산술 시프트 필요)

    pub(super) fn lift_movsx(&mut self, inst: &Instruction, src_bits: u8) -> Result<()> {
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

    pub(super) fn emit_jcxz(&mut self, width: u8, target: u64) {
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::CounterZero(width),
            })
            .with_imm(target),
        );
    }

    /// 조건부 분기 emit (타깃 = 절대 x86 IP)

    pub(super) fn emit_jcc(&mut self, cond: BranchCondition, target: u64) {
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch { cond }).with_imm(target),
        );
    }

    /// P2: 연산 결과를 `width`바이트 폭으로 잘라낸다 (8/16/32비트 INC/DEC 등).
    /// 32비트는 기존 zero-extension 헬퍼, 8/16비트는 AND 마스크로 표현한다.

    pub(super) fn mask_result(&mut self, width: u8, inst: &Instruction, dst: MicroOperand) -> Result<()> {
        let mask = match width {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            _ => return Ok(()),
        };
        self.desynth.emit_and(dst, dst, MicroOperand::Imm64(mask));
        Ok(())
    }

    /// P2: 피연산자 값을 `width`바이트 폭으로 마스크해 Temp 로 돌려준다.
    /// (BSF/BSR/TEST/INC 등에서 16/32비트 피연산자의 상위 비트 영향을 제거.)

    pub(super) fn mask_operand(&mut self, op: MicroOperand, width: u8) -> Result<MicroOperand> {
        let mask = match width {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            _ => return Ok(op),
        };
        let t = MicroOperand::Temp(3);
        self.desynth.emit_and(t, op, MicroOperand::Imm64(mask));
        Ok(t)
    }

    /// P2 (G3): 8/16비트 **레지스터** ALU 결과의 상위 비트 보존.
    ///
    /// x86은 8/16비트 쓰기가 상위 비트를 그대로 둔다 (0-확장은 32/64비트에만 적용).
    /// 그런데 `Add { width }`/`SubWithBorrow { width }`류 op는 결과를 `width`로
    /// 마스크하므로 상위가 0으로 밀린다. 호출자는 Add/Sub op가 dst를 덮어쓰기
    /// **전에** 원본을 Temp(0)에 저장해 두어야 한다. 여기서는 그 원본을 이용해
    /// `dst = (orig & ~mask) | masked`를 합성해 정확한 x86 부분-쓰기 의미론을 복원한다.
    pub(super) fn preserve_upper(&mut self, dst: MicroOperand, width: u8) {
        let mask = match width {
            1 => 0xFFu64,
            2 => 0xFFFFu64,
            _ => return,
        };
        let orig = MicroOperand::Temp(0);
        let keep = MicroOperand::Temp(1);
        self.desynth.emit_and(keep, orig, MicroOperand::Imm64(!mask));
        self.desynth.emit_or(dst, dst, keep);
    }

    /// 산술/논리 명령의 피연산자 폭(바이트) — 플래그 경계(bit 7/15/31/63) 결정.
    /// op0이 레지스터면 그 폭, 메모리면 memory_size, 즉시면 op1에서 유추.
    pub(super) fn operand_width(inst: &Instruction) -> u8 {
        if let OpKind::Register = inst.op0_kind() {
            let reg = inst.op0_register();
            if reg.is_gpr64() {
                return 8;
            }
            if reg.is_gpr32() {
                return 4;
            }
            if reg.is_gpr16() {
                return 2;
            }
            return 1;
        }
        if let OpKind::Memory = inst.op0_kind() {
            let sz = inst.memory_size().size();
            if sz != 0 {
                return sz.min(8) as u8;
            }
        }
        // op0이 즉시(예: 비교에서 즉시가 좌측) — op1 폭 사용
        if let OpKind::Register = inst.op1_kind() {
            let reg = inst.op1_register();
            if reg.is_gpr64() {
                return 8;
            }
            if reg.is_gpr32() {
                return 4;
            }
            if reg.is_gpr16() {
                return 2;
            }
        }
        4 // fallback: 32-bit
    }

    /// P2: TEST — 두 피연산자를 폭별로 마스크한 뒤 AND 의 플래그만 사용한다.
    /// AND 디서인시스의 최종 NOR 가 `update_logic64`로 CF=OF=0·ZF/SF/PF 를 갱신.

    pub(super) fn lift_test(&mut self, inst: &Instruction) -> Result<()> {
        let w = match inst.code() {
            Code::Test_rm64_r64 | Code::Test_rm64_imm32 | Code::Test_RAX_imm32 => 8,
            Code::Test_rm32_r32 | Code::Test_rm32_imm32 | Code::Test_EAX_imm32 => 4,
            Code::Test_rm16_imm16 | Code::Test_rm16_r16 | Code::Test_AX_imm16 => 2,
            _ => 1,
        };
        let v0 = self.operand_value(inst, 0)?;
        let v1 = self.operand_value(inst, 1)?;
        // P2 (G3): 두 피연산자를 폭별로 마스크 — **서로 다른 temp**(Temp(3)/Temp(2))를
        // 써서 기존 `mask_operand`의 공용 Temp(3) clobber 버그를 수정한다.
        // (기존 16/32비트 TEST가 `v0&v1` 대신 `v1&v1`을 계산하던 잠재 버그.)
        let a = self.mask_operand_into(v0, w, MicroOperand::Temp(3))?;
        let b = self.mask_operand_into(v1, w, MicroOperand::Temp(2))?;
        let scratch = MicroOperand::Temp(7);
        self.desynth.emit_and(scratch, a, b);
        Ok(())
    }

    /// P2: XCHG — 레지스터 교환 또는 레지스터↔메모리 교환.

    pub(super) fn lift_xchg(&mut self, inst: &Instruction) -> Result<()> {
        let r0 = inst.op0_kind() == OpKind::Register;
        let r1 = inst.op1_kind() == OpKind::Register;
        if r0 && r1 {
            let a = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid xchg a"))?;
            let b = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid xchg b"))?;
            let ta = MicroOperand::Temp(0);
            let tb = MicroOperand::Temp(1);
            self.desynth.instrs.push(MicroInstr::new(RiscOp::Mov).with_dst(ta).with_src1(a));
            self.desynth.instrs.push(MicroInstr::new(RiscOp::Mov).with_dst(tb).with_src1(b));
            self.desynth.instrs.push(MicroInstr::new(RiscOp::Mov).with_dst(a).with_src1(tb));
            self.desynth.instrs.push(MicroInstr::new(RiscOp::Mov).with_dst(b).with_src1(ta));
            return Ok(());
        }
        // 하나는 메모리, 하나는 레지스터 (x86은 메모리-메모리 XCHG 불가).
        let (reg, addr) = if r0 {
            (Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid xchg reg"))?, inst)
        } else if r1 {
            (Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid xchg reg"))?, inst)
        } else {
            return Err(anyhow!("risc lifter: xchg mem,mem impossible"));
        };
        let t_addr = MicroOperand::Temp(4);
        self.lower_effective_address(inst, t_addr)?;
        let width = inst.memory_size().size() as u8;
        let old = MicroOperand::Temp(5);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width })
                .with_dst(old)
                .with_src1(t_addr),
        );
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width })
                .with_src1(t_addr)
                .with_src2(reg),
        );
        self.desynth.instrs.push(MicroInstr::new(RiscOp::Mov).with_dst(reg).with_src1(old));
        Ok(())
    }

    /// P2: XADD — [op0] += op1, op1 = 이전 [op0]. (플래그는 덧셈 기준 — Mov 로 보존.)

    pub(super) fn lift_xadd(&mut self, inst: &Instruction) -> Result<()> {
        let width = match inst.code() {
            Code::Xadd_rm8_r8 => 1,
            Code::Xadd_rm16_r16 => 2,
            Code::Xadd_rm32_r32 => 4,
            _ => 8,
        };
        let reg = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid xadd reg"))?;
        match inst.op0_kind() {
            OpKind::Register => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid xadd dst"))?;
                let old = MicroOperand::Temp(0);
                self.desynth.instrs.push(MicroInstr::new(RiscOp::Mov).with_dst(old).with_src1(dst));
                // dst = old + reg  (XADD 덧셈 → 플래그)
                self.desynth.emit_add(dst, old, reg);
                self.mask_result(width, inst, dst)?;
                // reg = 이전 dst (폭별 마스크된 값, 플래그 보존)
                let oldm = self.mask_operand(old, width)?;
                self.desynth.instrs.push(MicroInstr::new(RiscOp::Mov).with_dst(reg).with_src1(oldm));
            }
            OpKind::Memory => {
                let addr = MicroOperand::Temp(4);
                self.lower_effective_address(inst, addr)?;
                let old = MicroOperand::Temp(5);
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryRead { width })
                        .with_dst(old)
                        .with_src1(addr),
                );
                // 이전 [addr] 값을 폭별 마스크해 reg 로 옮길 값을 보존 (덧셈 전).
                let oldm = self.mask_operand(old, width)?;
                // [addr] = old + reg (플래그)
                self.desynth.emit_add(old, old, reg);
                self.mask_result(width, inst, old)?;
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryWrite { width })
                        .with_src1(addr)
                        .with_src2(old),
                );
                // reg = 이전 [addr] (플래그 보존)
                self.desynth.instrs.push(MicroInstr::new(RiscOp::Mov).with_dst(reg).with_src1(oldm));
            }
            _ => return Err(anyhow!("risc lifter: invalid xadd op0")),
        }
        Ok(())
    }
}
