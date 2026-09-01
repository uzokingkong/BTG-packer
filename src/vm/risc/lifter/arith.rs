// ==============================================================================
// BTG - RISC Lifter: arith / shift / mask / atomic - split from lifter.rs
// ==============================================================================

use super::*;

impl RiscLifter {
    pub(super) fn lift_carry_alu(&mut self, inst: &Instruction, adc: bool) -> Result<()> {
        let width = Self::operand_width(inst);
        let make_op = || {
            if adc {
                RiscOp::Adc { width }
            } else {
                RiscOp::Sbb { width }
            }
        };
        match inst.op0_kind() {
            OpKind::Register => {
                let dst = Self::reg_to_vreg(inst.op0_register())
                    .ok_or_else(|| anyhow!("invalid carry-ALU dst"))?;
                let right = self.operand_value(inst, 1)?;
                if width <= 2 {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov)
                            .with_dst(MicroOperand::Temp(0))
                            .with_src1(dst),
                    );
                }
                self.desynth.instrs.push(
                    MicroInstr::new(make_op())
                        .with_dst(dst)
                        .with_src1(dst)
                        .with_src2(right),
                );
                if width <= 2 {
                    // Merging the low result back into the original GPR uses
                    // flag-producing primitives, so preserve ADC/SBB flags.
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov)
                            .with_dst(MicroOperand::Temp(7))
                            .with_src1(MicroOperand::Vflags),
                    );
                    self.preserve_upper(dst, width);
                    self.desynth
                        .instrs
                        .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Temp(7)));
                }
            }
            OpKind::Memory => {
                let addr = MicroOperand::Temp(4);
                self.lower_effective_address(inst, addr)?;
                let left = MicroOperand::Temp(5);
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryRead { width })
                        .with_dst(left)
                        .with_src1(addr),
                );
                let right = self.operand_value(inst, 1)?;
                self.desynth.instrs.push(
                    MicroInstr::new(make_op())
                        .with_dst(left)
                        .with_src1(left)
                        .with_src2(right),
                );
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryWrite { width })
                        .with_src1(addr)
                        .with_src2(left),
                );
            }
            _ => return Err(anyhow!("risc lifter: invalid op0 kind for ADC/SBB")),
        }
        Ok(())
    }

    pub(super) fn lift_binary_alu(&mut self, inst: &Instruction, alu: Alu) -> Result<()> {
        // P0-1: x86 SUB은 borrow-CF(네이티브 플래그 소비 분기 정합)를 위해
        // desynth(AddWithCarry) 대신 전용 SubWithBorrow(width)로 lift한다.
        let width = Self::operand_width(inst);
        match inst.op0_kind() {
            OpKind::Register => {
                let dst =
                    Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let right = self.operand_value(inst, 1)?;
                // P2 (G3): 8/16비트 레지스터 Add/Sub는 상위 비트 보존이 필요하다.
                // Add/Sub{width}가 dst를 마스크로 덮어쓰므로, **먼저** 원본을 Temp(0)에
                // 저장한 뒤 결과를 합성한다: dst = (orig & ~mask) | masked.
                let preserve = (alu == Alu::Add || alu == Alu::Sub) && (width == 1 || width == 2);
                // R7: 8/16-bit XOR/AND/OR — desynth(NOR 시퀀스)는 Temp(0..2)를
                // 내부 소모하므로 원본을 Temp(5)에 보존한다.
                let narrow_logic =
                    matches!(alu, Alu::Xor | Alu::And | Alu::Or) && (width == 1 || width == 2);
                if preserve {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov)
                            .with_dst(MicroOperand::Temp(0))
                            .with_src1(dst),
                    );
                } else if narrow_logic {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov)
                            .with_dst(MicroOperand::Temp(5))
                            .with_src1(dst),
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
                } else if narrow_logic {
                    // R7: 8/16-bit 논리 — 피연산자를 폭으로 마스크한 뒤 desynth.
                    // (레지스터 상위 비트가 결과/플래그를 오염시키지 않도록 — CMP와 동일 패턴)
                    let left = self.mask_operand_into(dst, width, MicroOperand::Temp(3))?;
                    let right_m = self.mask_operand_into(right, width, MicroOperand::Temp(2))?;
                    alu.emit(&mut self.desynth, dst, left, right_m);
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
                } else if narrow_logic {
                    self.preserve_upper_from(dst, width, MicroOperand::Temp(5));
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
                    // R7: 8/16-bit 논리 메모리 RMW — left는 MemoryRead{width}로 이미
                    // 0-확장, 레지스터 피연산자만 폭으로 마스크해 결과/플래그를 정화.
                    let right = if width <= 2 {
                        self.mask_operand_into(right, width, MicroOperand::Temp(2))?
                    } else {
                        right
                    };
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

    /// P2 (G3): 8/16/32비트 연산에서 **레지스터** 피연산자만 폭으로 마스크해 지정
    /// temp에 저장한다 (x86은 low-byte/word만 사용). 메모리/즉시 피연산자는 그대로.
    fn mask_reg_operand(
        &mut self,
        op: MicroOperand,
        width: u8,
        temp: MicroOperand,
    ) -> Result<MicroOperand> {
        if width >= 8 {
            return Ok(op);
        }
        let mask = match width {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            _ => return Ok(op),
        };
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

    /// SHL/SHR/SAR (8/16/32/64-bit, count: imm8 / 1 / CL).
    /// x86 시프트 횟수 마스크: 8/16/32비트 피연산자는 mod 32(31), 64비트는 mod 64(63).
    /// 32비트 레지스터 시프트 결과는 상위 32비트를 0으로, 8/16비트 레지스터는
    /// 상위 비트 보존(preserve_upper)을 복원한다.
    ///
    /// R7: 8/16비트 SHR/SHL은 피연산자를 폭으로 마스크한 뒤 시프트한다
    /// (SHR는 상위 비트가 결과 하위 폭으로 내려오는 것을 방지). 8/16비트 SAR은
    /// 피연산자를 **폭만큼 sign-extend**(`movsx`와 동일: `(src<<s)>>s` 산술)한 뒤
    /// 산술 시프트해야 64비트 부호 비트(bit 63)가 아닌 폭 부호 비트가 복제된다.

    pub(super) fn lift_shift(&mut self, inst: &Instruction, op: RiscOp) -> Result<()> {
        let is_sar = op == RiscOp::ArithmeticShiftRight;
        // 피연산자 폭(바이트) — 레지스터면 op0 폭, 메모리면 memory_size.
        let width = match inst.op0_kind() {
            OpKind::Register => inst.op0_register().size() as u8,
            OpKind::Memory => inst.memory_size().size() as u8,
            _ => return Err(anyhow!("risc lifter: invalid shift op0")),
        };
        let narrow = width == 1 || width == 2;
        // P0-3: 8/16비트 시프트의 합성 op(주소 계산·카운트 마스크·sign-extend·
        // mask·preserve_upper — 전부 Nor 시퀀스)는 flags를 덮어쓴다. x86 시프트는
        // flags를 **한 번** 계산하고 count==0 에선 원본 flags를 보존하므로,
        // Temp(7)에 원본 flags를 보존해 (1) 시프트 직전에 복원(count==0 보존),
        // (2) 시프트 후 합성 op 뒤에 시프트 결과 flags를 복원한다.
        let save_flags = |d: &mut Self| {
            d.desynth.instrs.push(
                MicroInstr::new(RiscOp::Mov)
                    .with_dst(MicroOperand::Temp(7))
                    .with_src1(MicroOperand::Vflags),
            );
        };
        let restore_flags = |d: &mut Self| {
            d.desynth
                .instrs
                .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Temp(7)));
        };
        if narrow {
            save_flags(self);
        }
        // x86: 8/16/32비트는 mod 32, 64비트는 mod 64.
        let count = match inst.op1_kind() {
            OpKind::Immediate8
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64 => {
                let v = inst.immediate(1);
                if width == 8 {
                    MicroOperand::Imm64(v)
                } else {
                    MicroOperand::Imm64(v & 31)
                }
            }
            OpKind::Register => {
                let c = Self::reg_to_vreg(inst.op1_register())
                    .ok_or_else(|| anyhow!("invalid shift count register"))?;
                if width == 8 {
                    c
                } else {
                    // CL 등 레지스터 시프트 횟수를 31로 마스크해 Temp(2)에 저장.
                    let masked = MicroOperand::Temp(2);
                    self.desynth.emit_and(masked, c, MicroOperand::Imm64(31));
                    masked
                }
            }
            _ => return Err(anyhow!("risc lifter: unsupported shift count")),
        };
        // R7: 8/16비트 피연산자를 폭으로 **sign-extend**해 Temp(6)에 저장.
        // (movsx와 동일 — 산술 시프트로 부호 비트를 64비트 폭으로 복제.)
        let sign_extend_into = |d: &mut Self, dst: MicroOperand, src: MicroOperand, w: u8| {
            let shift = 64 - w * 8;
            let t = MicroOperand::Temp(3);
            d.desynth.instrs.push(
                MicroInstr::new(RiscOp::ShiftLeft)
                    .with_dst(t)
                    .with_src1(src)
                    .with_src2(MicroOperand::Imm64(shift as u64)),
            );
            d.desynth.instrs.push(
                MicroInstr::new(RiscOp::ArithmeticShiftRight)
                    .with_dst(dst)
                    .with_src1(t)
                    .with_src2(MicroOperand::Imm64(shift as u64)),
            );
        };
        match inst.op0_kind() {
            OpKind::Register => {
                let dst = Self::reg_to_vreg(inst.op0_register())
                    .ok_or_else(|| anyhow!("invalid shift dst"))?;
                if narrow {
                    // 상위 비트 보존용 원본은 desynth(emit_and)가 내부 소모하는
                    // Temp(0)/Temp(1)을 피해 Temp(5)에 저장한다.
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov)
                            .with_dst(MicroOperand::Temp(5))
                            .with_src1(dst),
                    );
                    let src = if is_sar {
                        sign_extend_into(self, MicroOperand::Temp(6), dst, width);
                        MicroOperand::Temp(6)
                    } else {
                        // SHR: 상위 비트가 결과 하위 폭으로 내려오는 것 방지. SHL은
                        // 하위 폭 결과가 상위 비트와 무관하지만 동일 패턴으로 마스크.
                        self.mask_operand_into(dst, width, MicroOperand::Temp(3))?
                    };
                    // P0-3: 합성 op가 flags를 오염시켰으므로 원본 flags 복원
                    // (count==0 에서 x86 flags 보존 의미론).
                    restore_flags(self);
                    self.desynth.instrs.push(
                        MicroInstr::new(op)
                            .with_dst(dst)
                            .with_src1(src)
                            .with_src2(count),
                    );
                    // P0-3: 시프트 결과 flags를 보존했다가 mask/preserve 합성 op
                    // 뒤에 복원한다 (합성 AND/OR 가 시프트 flags를 덮어쓰지 않게).
                    save_flags(self);
                    self.mask_result(width, inst, dst)?;
                    self.preserve_upper_from(dst, width, MicroOperand::Temp(5));
                    restore_flags(self);
                } else if width == 4 {
                    self.desynth.instrs.push(
                        MicroInstr::new(op)
                            .with_dst(dst)
                            .with_src1(dst)
                            .with_src2(count),
                    );
                    // 32비트 레지스터 시프트 결과는 상위 32비트를 0으로.
                    self.zero_extend_dst_if32(inst, dst);
                } else {
                    self.desynth.instrs.push(
                        MicroInstr::new(op)
                            .with_dst(dst)
                            .with_src1(dst)
                            .with_src2(count),
                    );
                }
            }
            OpKind::Memory => {
                let addr = MicroOperand::Temp(4);
                self.lower_effective_address(inst, addr)?;
                let left = MicroOperand::Temp(5);
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryRead { width })
                        .with_dst(left)
                        .with_src1(addr),
                );
                let src = if is_sar && (width == 1 || width == 2) {
                    sign_extend_into(self, MicroOperand::Temp(6), left, width);
                    MicroOperand::Temp(6)
                } else {
                    left
                };
                // P0-3: 주소 계산·카운트 마스크·sign-extend 가 flags를 오염시켰으므로
                // 원본 flags 복원 (count==0 보존). MemoryWrite 는 flags 불변이라
                // 시프트 결과 flags 는 그대로 유지된다.
                if narrow {
                    restore_flags(self);
                }
                self.desynth.instrs.push(
                    MicroInstr::new(op)
                        .with_dst(left)
                        .with_src1(src)
                        .with_src2(count),
                );
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

    pub(super) fn lift_rotate_left(&mut self, inst: &Instruction) -> Result<()> {
        let width = match inst.op0_kind() {
            OpKind::Register => inst.op0_register().size() as u8,
            OpKind::Memory => inst.memory_size().size() as u8,
            _ => return Err(anyhow!("risc lifter: invalid ROL destination")),
        };
        let count = match inst.op1_kind() {
            OpKind::Immediate8 | OpKind::Immediate8to64 => {
                MicroOperand::Imm64(inst.immediate8() as u64)
            }
            OpKind::Register => Self::reg_to_vreg(inst.op1_register())
                .ok_or_else(|| anyhow!("invalid ROL count register"))?,
            _ => return Err(anyhow!("risc lifter: invalid ROL count")),
        };
        let op = RiscOp::RotateLeft { width };
        match inst.op0_kind() {
            OpKind::Register => {
                let dst = Self::reg_to_vreg(inst.op0_register())
                    .ok_or_else(|| anyhow!("invalid ROL dst"))?;
                if width <= 2 {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov)
                            .with_dst(MicroOperand::Temp(5))
                            .with_src1(dst),
                    );
                }
                self.desynth.instrs.push(
                    MicroInstr::new(op)
                        .with_dst(dst)
                        .with_src1(dst)
                        .with_src2(count),
                );
                if width <= 2 {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov)
                            .with_dst(MicroOperand::Temp(7))
                            .with_src1(MicroOperand::Vflags),
                    );
                    self.preserve_upper_from(dst, width, MicroOperand::Temp(5));
                    self.desynth
                        .instrs
                        .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Temp(7)));
                }
            }
            OpKind::Memory => {
                let addr = MicroOperand::Temp(4);
                self.lower_effective_address(inst, addr)?;
                let val = MicroOperand::Temp(5);
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryRead { width })
                        .with_dst(val)
                        .with_src1(addr),
                );
                self.desynth.instrs.push(
                    MicroInstr::new(op)
                        .with_dst(val)
                        .with_src1(val)
                        .with_src2(count),
                );
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryWrite { width })
                        .with_src1(addr)
                        .with_src2(val),
                );
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    /// MOVZX: 8/16-bit 소스를 0-확장해 64비트 결과로. AND 마스크로 표현.

    pub(super) fn lift_movzx(&mut self, inst: &Instruction, mask: u64) -> Result<()> {
        let dst =
            Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid movzx dst"))?;
        let src = self.operand_value(inst, 1)?;
        self.desynth.emit_and(dst, src, MicroOperand::Imm64(mask));
        Ok(())
    }

    /// MOVSX: 8/16/32-bit 소스를 부호 확장(sign-extend)해 64비트 결과로.
    /// `ArithmeticShiftRight`를 이용해 `(src << (64-w)) >> (64-w)`(산술 시프트)로
    /// 부호 비트를 복제한다. (MOVSX는 논리 시프트만으로는 표현 불가 — 산술 시프트 필요)

    pub(super) fn lift_movsx(&mut self, inst: &Instruction, src_bits: u8) -> Result<()> {
        let dst =
            Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid movsx dst"))?;
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
        self.desynth
            .instrs
            .push(MicroInstr::new(RiscOp::VirtualBranch { cond }).with_imm(target));
    }

    /// P2: 연산 결과를 `width`바이트 폭으로 잘라낸다 (8/16/32비트 INC/DEC 등).
    /// 32비트는 기존 zero-extension 헬퍼, 8/16비트는 AND 마스크로 표현한다.

    pub(super) fn mask_result(
        &mut self,
        width: u8,
        inst: &Instruction,
        dst: MicroOperand,
    ) -> Result<()> {
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
        self.preserve_upper_from(dst, width, MicroOperand::Temp(0));
    }

    /// R7: `preserve_upper`의 일반화 — 원본 레지스터가 **지정 temp**에 저장돼 있다.
    /// (8/16-bit XOR/AND/OR는 desynth NOR 시퀀스가 Temp(0..2)를 내부 소모하므로
    /// 원본을 Temp(5)에 보존한 뒤 이 헬퍼로 합성한다.)
    pub(super) fn preserve_upper_from(&mut self, dst: MicroOperand, width: u8, orig: MicroOperand) {
        let mask = match width {
            1 => 0xFFu64,
            2 => 0xFFFFu64,
            _ => return,
        };
        // `emit_or` uses Temp(0..2) internally.  Keeping the preserved upper
        // bits in Temp(1) aliases that scratch space and makes the OR consume
        // a value it has already overwritten (e.g. `mov al, bl` became a full
        // 64-bit register copy).  Temp(6) is reserved for this final operand.
        let keep = MicroOperand::Temp(6);
        self.desynth
            .emit_and(keep, orig, MicroOperand::Imm64(!mask));
        self.desynth.emit_or(dst, dst, keep);
    }

    /// R7: 8/16/32/64-bit NEG / NOT (register + memory).
    /// NEG = 0 - dst (borrow-CF, SubWithBorrow), NOT = ~dst (RFLAGS 불변, Not{width}).
    /// 8/16비트 레지스터 대상은 x86 부분-쓰기(상위 비트 보존)를 복원한다.
    pub(super) fn lift_neg_not(&mut self, inst: &Instruction, is_not: bool) -> Result<()> {
        let width = Self::operand_width(inst);
        let narrow = width == 1 || width == 2;
        match inst.op0_kind() {
            OpKind::Register => {
                let dst =
                    Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                if narrow {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov)
                            .with_dst(MicroOperand::Temp(0))
                            .with_src1(dst),
                    );
                }
                if is_not {
                    // NOT{width}: 플래그 불변, 폭별 마스크.
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Not { width })
                            .with_dst(dst)
                            .with_src1(dst),
                    );
                } else {
                    // NEG: 0 - dst — borrow-CF를 위해 SubWithBorrow{width}.
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::SubWithBorrow { width })
                            .with_dst(dst)
                            .with_src1(MicroOperand::Imm64(0))
                            .with_src2(dst),
                    );
                }
                if narrow {
                    self.preserve_upper(dst, width);
                }
            }
            OpKind::Memory => {
                let addr = MicroOperand::Temp(4);
                self.lower_effective_address(inst, addr)?;
                let w = inst.memory_size().size() as u8;
                let left = MicroOperand::Temp(5);
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryRead { width: w })
                        .with_dst(left)
                        .with_src1(addr),
                );
                if is_not {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Not { width: w })
                            .with_dst(left)
                            .with_src1(left),
                    );
                } else {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::SubWithBorrow { width: w })
                            .with_dst(left)
                            .with_src1(MicroOperand::Imm64(0))
                            .with_src2(left),
                    );
                }
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::MemoryWrite { width: w })
                        .with_src1(addr)
                        .with_src2(left),
                );
            }
            _ => return Err(anyhow!("risc lifter: invalid neg/not op0")),
        }
        Ok(())
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
            let a =
                Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid xchg a"))?;
            let b =
                Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid xchg b"))?;
            let ta = MicroOperand::Temp(0);
            let tb = MicroOperand::Temp(1);
            self.desynth
                .instrs
                .push(MicroInstr::new(RiscOp::Mov).with_dst(ta).with_src1(a));
            self.desynth
                .instrs
                .push(MicroInstr::new(RiscOp::Mov).with_dst(tb).with_src1(b));
            self.desynth
                .instrs
                .push(MicroInstr::new(RiscOp::Mov).with_dst(a).with_src1(tb));
            self.desynth
                .instrs
                .push(MicroInstr::new(RiscOp::Mov).with_dst(b).with_src1(ta));
            return Ok(());
        }
        // 하나는 메모리, 하나는 레지스터 (x86은 메모리-메모리 XCHG 불가).
        let (reg, addr) = if r0 {
            (
                Self::reg_to_vreg(inst.op0_register())
                    .ok_or_else(|| anyhow!("invalid xchg reg"))?,
                inst,
            )
        } else if r1 {
            (
                Self::reg_to_vreg(inst.op1_register())
                    .ok_or_else(|| anyhow!("invalid xchg reg"))?,
                inst,
            )
        } else {
            return Err(anyhow!("risc lifter: xchg mem,mem impossible"));
        };
        let t_addr = MicroOperand::Temp(4);
        self.lower_effective_address(inst, t_addr)?;
        let width = inst.memory_size().size() as u8;
        // P0-4: 메모리 XCHG 는 암시적 LOCK — AtomicExchange 단일 원자로 lift 한다.
        // (기존 MemoryRead/MemoryWrite 분해는 중간 상태를 노출해 lock-free/atomic
        //  코드에서 위험하다.) old = [addr]; [addr] = reg; reg = old, 플래그 불변.
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::AtomicExchange { width })
                .with_dst(reg)
                .with_src1(t_addr),
        );
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
        let reg =
            Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid xadd reg"))?;
        match inst.op0_kind() {
            OpKind::Register => {
                let dst = Self::reg_to_vreg(inst.op0_register())
                    .ok_or_else(|| anyhow!("invalid xadd dst"))?;
                let old = MicroOperand::Temp(0);
                self.desynth
                    .instrs
                    .push(MicroInstr::new(RiscOp::Mov).with_dst(old).with_src1(dst));
                // dst = old + reg  (XADD 덧셈 → 플래그)
                self.desynth.emit_add(dst, old, reg);
                self.mask_result(width, inst, dst)?;
                // reg = 이전 dst (폭별 마스크된 값, 플래그 보존)
                let oldm = self.mask_operand(old, width)?;
                self.desynth
                    .instrs
                    .push(MicroInstr::new(RiscOp::Mov).with_dst(reg).with_src1(oldm));
            }
            OpKind::Memory => {
                let addr = MicroOperand::Temp(4);
                self.lower_effective_address(inst, addr)?;
                let width = inst.memory_size().size() as u8;
                // P0-4: LOCK XADD 는 원자 RMW — AtomicAdd 단일 원자로 lift 한다.
                // old = [addr]; new = old + reg (폭별 플래그); [addr] = new; reg = old.
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::AtomicAdd { width })
                        .with_dst(reg)
                        .with_src1(addr)
                        .with_src2(reg),
                );
            }
            _ => return Err(anyhow!("risc lifter: invalid xadd op0")),
        }
        Ok(())
    }
}
