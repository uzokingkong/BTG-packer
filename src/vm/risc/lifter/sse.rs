// ==============================================================================
// BTG - RISC Lifter: SSE / FPU / XMM - split from lifter.rs
// ==============================================================================

use super::*;

impl RiscLifter {
    /// XMM0-15 레지스터 → XMM 슬롯 인덱스 (0..16). GPR 이면 None.
    pub(super) fn xmm_index(reg: Register) -> Option<u8> {
        match reg {
            Register::XMM0 => Some(0),
            Register::XMM1 => Some(1),
            Register::XMM2 => Some(2),
            Register::XMM3 => Some(3),
            Register::XMM4 => Some(4),
            Register::XMM5 => Some(5),
            Register::XMM6 => Some(6),
            Register::XMM7 => Some(7),
            Register::XMM8 => Some(8),
            Register::XMM9 => Some(9),
            Register::XMM10 => Some(10),
            Register::XMM11 => Some(11),
            Register::XMM12 => Some(12),
            Register::XMM13 => Some(13),
            Register::XMM14 => Some(14),
            Register::XMM15 => Some(15),
            _ => None,
        }
    }

    /// XMM 슬롯 절대 주소(XMM_SLOT_BASE + idx*16)를 `dst`(Temp)에 계산.

    pub(super) fn xmm_slot_addr(&mut self, idx: u8, dst: MicroOperand) {
        let t = MicroOperand::Temp(2);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::Mov).with_dst(t).with_src1(MicroOperand::Imm64(idx as u64)),
        );
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::ShiftLeft)
                .with_dst(t)
                .with_src1(t)
                .with_src2(MicroOperand::Imm64(4)),
        );
        self.desynth.emit_add(dst, MicroOperand::Imm64(XMM_SLOT_BASE), t);
    }

    /// XMM `idx` 슬롯 하위 `width`바이트 요소를 `val`(Temp)로 로드.

    pub(super) fn xmm_load_into(&mut self, idx: u8, width: u8, val: MicroOperand) {
        let addr = MicroOperand::Temp(4);
        self.xmm_slot_addr(idx, addr);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width }).with_dst(val).with_src1(addr),
        );
    }

    /// `val`(하위 요소)을 XMM `idx` 슬롯에 `width`바이트로 기록.

    pub(super) fn xmm_store_from(&mut self, idx: u8, width: u8, val: MicroOperand) {
        let addr = MicroOperand::Temp(4);
        self.xmm_slot_addr(idx, addr);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width }).with_src1(addr).with_src2(val),
        );
    }

    /// MOVSS/MOVSD 로드 폼: dst XMM 슬롯의 상위(미저장) 바이트를 0으로
    /// (x86: 스칼라 로드는 상위 요소를 0으로 만든다).

    pub(super) fn xmm_zero_upper(&mut self, idx: u8, low_width: u8) {
        let base = MicroOperand::Temp(4);
        self.xmm_slot_addr(idx, base);
        let zero = MicroOperand::Imm64(0);
        let mut off = low_width as u64;
        while off < 16 {
            let a = MicroOperand::Temp(2);
            self.desynth.emit_add(a, base, MicroOperand::Imm64(off));
            let w = if 16 - off >= 8 { 8 } else { 4 };
            self.desynth.instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width: w }).with_src1(a).with_src2(zero),
            );
            off += w as u64;
        }
    }

    // ── P2: 문자열 ops (MOVS/STOS/LODS/SCAS/CMPS + REP/REPE/REPNE) ───────────

    /// MOVS: [rdi]=[rsi]; rsi+=n; rdi+=n. REP → 카운트-다운 루프.

    pub(super) fn lift_sse_mov_load(&mut self, inst: &Instruction) -> Result<()> {
        let width = if matches!(inst.code(), Code::Movsd_xmm_xmmm64) { 8 } else { 4 };
        let dst_idx = Self::xmm_index(inst.op0_register())
            .ok_or_else(|| anyhow!("invalid sse mov dst"))?;
        match inst.op1_kind() {
            OpKind::Register => {
                let src_idx = Self::xmm_index(inst.op1_register())
                    .ok_or_else(|| anyhow!("invalid sse mov src"))?;
                let val = MicroOperand::Temp(6);
                self.xmm_load_into(src_idx, width, val);
                self.xmm_store_from(dst_idx, width, val);
            }
            OpKind::Memory => {
                let val = self.operand_value(inst, 1)?;
                self.xmm_store_from(dst_idx, width, val);
            }
            _ => return Err(anyhow!("risc lifter: invalid sse mov op1")),
        }
        self.xmm_zero_upper(dst_idx, width);
        Ok(())
    }

    /// MOVSS/MOVSD 스토어 폼 (m ← xmm).

    pub(super) fn lift_sse_mov_store(&mut self, inst: &Instruction) -> Result<()> {
        let width = if matches!(inst.code(), Code::Movsd_xmmm64_xmm) { 8 } else { 4 };
        let src_idx = Self::xmm_index(inst.op1_register())
            .ok_or_else(|| anyhow!("invalid sse mov src"))?;
        if inst.op0_kind() == OpKind::Register {
            let dst_idx = Self::xmm_index(inst.op0_register())
                .ok_or_else(|| anyhow!("invalid sse mov dst"))?;
            let val = MicroOperand::Temp(6);
            self.xmm_load_into(src_idx, width, val);
            self.xmm_store_from(dst_idx, width, val);
            return Ok(());
        }
        // xmm_load_into 는 내부적으로 Temp(4) 를 주소 스크래치로 쓰므로, 스토어 주소는
        // Temp(5) 에 보존해야 한다 (Temp(4) 면 덮여 XMM 슬롯에 잘못 기록된다).
        let addr = MicroOperand::Temp(5);
        self.lower_effective_address(inst, addr)?;
        let val = MicroOperand::Temp(6);
        self.xmm_load_into(src_idx, width, val);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width }).with_src1(addr).with_src2(val),
        );
        Ok(())
    }

    /// ADDSS/ADDSD/SUBSS/SUBSD/MULSS/MULSD/DIVSS/DIVSD — dst.low OP= src.low.

    pub(super) fn lift_sse_fp_bin(&mut self, inst: &Instruction, arith: FPArith) -> Result<()> {
        let width = if matches!(
            inst.code(),
            Code::Addsd_xmm_xmmm64 | Code::Subsd_xmm_xmmm64
                | Code::Mulsd_xmm_xmmm64 | Code::Divsd_xmm_xmmm64
        ) { 8 } else { 4 };
        let dst_idx = Self::xmm_index(inst.op0_register())
            .ok_or_else(|| anyhow!("invalid sse fp dst"))?;
        let a = MicroOperand::Temp(5);
        self.xmm_load_into(dst_idx, width, a);
        let b = if inst.op1_kind() == OpKind::Register {
            let src_idx = Self::xmm_index(inst.op1_register())
                .ok_or_else(|| anyhow!("invalid sse fp src"))?;
            let t = MicroOperand::Temp(6);
            self.xmm_load_into(src_idx, width, t);
            t
        } else if inst.op1_kind() == OpKind::Memory {
            self.operand_value(inst, 1)?
        } else {
            return Err(anyhow!("risc lifter: invalid sse fp op1"));
        };
        let dst = MicroOperand::Temp(7);
        let op = match arith {
            FPArith::Add => RiscOp::FloatAdd { width },
            FPArith::Sub => RiscOp::FloatSub { width },
            FPArith::Mul => RiscOp::FloatMul { width },
            FPArith::Div => RiscOp::FloatDiv { width },
        };
        self.desynth.instrs.push(MicroInstr::new(op).with_dst(dst).with_src1(a).with_src2(b));
        self.xmm_store_from(dst_idx, width, dst);
        Ok(())
    }

    /// CVTSI2SS/CVTSI2SD — xmm[dst].low = (fp)vreg[src]; 상위 0.

    pub(super) fn lift_cvtsi2fp(&mut self, inst: &Instruction) -> Result<()> {
        let dst_bits = if matches!(inst.code(), Code::Cvtsi2sd_xmm_rm32 | Code::Cvtsi2sd_xmm_rm64) {
            8
        } else {
            4
        };
        let src_bits = if matches!(inst.code(), Code::Cvtsi2ss_xmm_rm64 | Code::Cvtsi2sd_xmm_rm64) {
            8
        } else {
            4
        };
        let dst_idx = Self::xmm_index(inst.op0_register())
            .ok_or_else(|| anyhow!("invalid cvt dst"))?;
        let src = self.operand_value(inst, 1)?;
        let val = MicroOperand::Temp(7);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::IntToFloat { src_bits, dst_bits }).with_dst(val).with_src1(src),
        );
        self.xmm_store_from(dst_idx, dst_bits, val);
        self.xmm_zero_upper(dst_idx, dst_bits);
        Ok(())
    }

    /// CVTSS2SD/CVTSD2SS — xmm[dst].low = convert(xmm[src].low); 상위 0.

    pub(super) fn lift_cvtfp2fp(&mut self, inst: &Instruction) -> Result<()> {
        let (src_bits, dst_bits) =
            if matches!(inst.code(), Code::Cvtss2sd_xmm_xmmm32) { (4u8, 8u8) } else { (8u8, 4u8) };
        let dst_idx = Self::xmm_index(inst.op0_register())
            .ok_or_else(|| anyhow!("invalid cvt dst"))?;
        let src_val = if inst.op1_kind() == OpKind::Register {
            let src_idx = Self::xmm_index(inst.op1_register())
                .ok_or_else(|| anyhow!("invalid cvt src"))?;
            let t = MicroOperand::Temp(6);
            self.xmm_load_into(src_idx, src_bits, t);
            t
        } else if inst.op1_kind() == OpKind::Memory {
            self.operand_value(inst, 1)?
        } else {
            return Err(anyhow!("risc lifter: invalid cvt op1"));
        };
        let val = MicroOperand::Temp(7);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::FloatToFloat { src_bits, dst_bits }).with_dst(val).with_src1(src_val),
        );
        self.xmm_store_from(dst_idx, dst_bits, val);
        self.xmm_zero_upper(dst_idx, dst_bits);
        Ok(())
    }

    /// CVTTSS2SI/CVTSS2SI/CVTTSD2SI/CVTSD2SI — vreg[dst] = (int)xmm[src].low.

    pub(super) fn lift_cvtfp2si(&mut self, inst: &Instruction) -> Result<()> {
        let src_bits = if matches!(
            inst.code(),
            Code::Cvttsd2si_r32_xmmm64 | Code::Cvttsd2si_r64_xmmm64
                | Code::Cvtsd2si_r32_xmmm64 | Code::Cvtsd2si_r64_xmmm64
        ) { 8 } else { 4 };
        let dst_bits = if matches!(
            inst.code(),
            Code::Cvttss2si_r64_xmmm32 | Code::Cvttsd2si_r64_xmmm64
                | Code::Cvtss2si_r64_xmmm32 | Code::Cvtsd2si_r64_xmmm64
        ) { 8 } else { 4 };
        let truncate = matches!(
            inst.code(),
            Code::Cvttss2si_r32_xmmm32 | Code::Cvttss2si_r64_xmmm32
                | Code::Cvttsd2si_r32_xmmm64 | Code::Cvttsd2si_r64_xmmm64
        );
        let dst = Self::reg_to_vreg(inst.op0_register())
            .ok_or_else(|| anyhow!("invalid cvt si dst"))?;
        let src_val = if inst.op1_kind() == OpKind::Register {
            let src_idx = Self::xmm_index(inst.op1_register())
                .ok_or_else(|| anyhow!("invalid cvt si src"))?;
            let t = MicroOperand::Temp(6);
            self.xmm_load_into(src_idx, src_bits, t);
            t
        } else if inst.op1_kind() == OpKind::Memory {
            self.operand_value(inst, 1)?
        } else {
            return Err(anyhow!("risc lifter: invalid cvt si op1"));
        };
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::FloatToInt { src_bits, dst_bits, truncate })
                .with_dst(dst)
                .with_src1(src_val),
        );
        Ok(())
    }

}
