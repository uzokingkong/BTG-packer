// ==============================================================================
// BTG - RISC Lifter: string ops - split from lifter.rs
// ==============================================================================

use super::*;

impl RiscLifter {
    /// v65: compute `delta = DF ? -n : +n` into Temp(3).
    ///
    /// The desynth AND of `Vflags & F_DF` leaves ZF = (DF clear) (its NOR
    /// primitive runs `update_logic64`, which sets ZF from the result). So we
    /// default delta to -n, then a `ConditionalMove{cond: Zero}` overwrites it
    /// with +n when DF is clear. This is branch-free and uses the flag bit
    /// directly, mirroring the bytecode lifter's `emit_dir_delta`.
    ///
    /// Temp(3) survives every string-op loop (MOVS/STOS/LODS use 0/5,
    /// SCAS/CMPS use 0/2/5/6/7); the AND scratch is Temp(4) — free here, and
    /// string ops never lower a memory operand with an EA temp.
    fn emit_dir_delta(&mut self, n: u64) {
        let delta = MicroOperand::Temp(3);
        // delta = -n  (emit_neg uses Temp(0)/Temp(1) as scratch)
        self.desynth.emit_neg(delta, MicroOperand::Imm64(n));
        // t = Vflags & F_DF  → ZF = (t == 0) = (DF clear)
        let t = MicroOperand::Temp(4);
        self.desynth.emit_and(
            t,
            MicroOperand::Vflags,
            MicroOperand::Imm64(crate::vm::risc::flags::VFLAG_DF),
        );
        // if DF clear → delta = +n
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::Zero,
            })
            .with_dst(delta)
            .with_src1(MicroOperand::Imm64(n)),
        );
    }
    pub(super) fn lift_movs(&mut self, inst: &Instruction) -> Result<()> {
        let n = movs_width(inst.code()) as u64;
        let width = n as u8;
        let rsi = MicroOperand::VReg(6);
        let rdi = MicroOperand::VReg(7);
        let rcx = MicroOperand::VReg(1);
        let delta = MicroOperand::Temp(3);
        if !has_any_rep(inst) {
            self.emit_dir_delta(n);
            let val = MicroOperand::Temp(5);
            self.desynth.instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width })
                    .with_dst(val)
                    .with_src1(rsi),
            );
            self.desynth.instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width })
                    .with_src1(rdi)
                    .with_src2(val),
            );
            self.desynth.emit_add(rsi, rsi, delta);
            self.desynth.emit_add(rdi, rdi, delta);
            return Ok(());
        }
        self.emit_dir_delta(n);
        let loop_start = self.desynth.instrs.len();
        let scratch = MicroOperand::Temp(0);
        self.desynth.emit_and(scratch, rcx, rcx); // ZF = (rcx == 0)
        let done_br = self.desynth.instrs.len();
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Zero,
            })
            .with_imm(0),
        );
        let val = MicroOperand::Temp(5);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width })
                .with_dst(val)
                .with_src1(rsi),
        );
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width })
                .with_src1(rdi)
                .with_src2(val),
        );
        self.desynth.emit_add(rsi, rsi, delta);
        self.desynth.emit_add(rdi, rdi, delta);
        self.desynth.emit_sub(rcx, rcx, MicroOperand::Imm64(1));
        self.desynth.emit_jmp(loop_start as u64);
        let done_idx = self.desynth.instrs.len();
        self.desynth.instrs[done_br].imm = done_idx as u64;
        Ok(())
    }

    /// STOS: [rdi]=AL/AX/EAX/RAX(vreg0, 폭별); rdi+=DF ? -n : n. REP → 루프.
    /// v65: bump direction honours DF via `emit_dir_delta` (Temp(3)).

    pub(super) fn lift_stos(&mut self, inst: &Instruction) -> Result<()> {
        let n = stos_lods_width(inst.code()) as u64;
        let width = n as u8;
        let acc = MicroOperand::VReg(0);
        let rdi = MicroOperand::VReg(7);
        let rcx = MicroOperand::VReg(1);
        let delta = MicroOperand::Temp(3);
        if !has_any_rep(inst) {
            self.emit_dir_delta(n);
            self.desynth.instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width })
                    .with_src1(rdi)
                    .with_src2(acc),
            );
            self.desynth.emit_add(rdi, rdi, delta);
            return Ok(());
        }
        self.emit_dir_delta(n);
        let loop_start = self.desynth.instrs.len();
        let scratch = MicroOperand::Temp(0);
        self.desynth.emit_and(scratch, rcx, rcx);
        let done_br = self.desynth.instrs.len();
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Zero,
            })
            .with_imm(0),
        );
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width })
                .with_src1(rdi)
                .with_src2(acc),
        );
        self.desynth.emit_add(rdi, rdi, delta);
        self.desynth.emit_sub(rcx, rcx, MicroOperand::Imm64(1));
        self.desynth.emit_jmp(loop_start as u64);
        let done_idx = self.desynth.instrs.len();
        self.desynth.instrs[done_br].imm = done_idx as u64;
        Ok(())
    }

    /// LODS: AL/AX/EAX/RAX(vreg0) = [rsi] (0-확장); rsi+=DF ? -n : n. REP → 루프.
    /// v65: bump direction honours DF via `emit_dir_delta` (Temp(3)).

    pub(super) fn lift_lods(&mut self, inst: &Instruction) -> Result<()> {
        let n = stos_lods_width(inst.code()) as u64;
        let width = n as u8;
        let acc = MicroOperand::VReg(0);
        let rsi = MicroOperand::VReg(6);
        let rcx = MicroOperand::VReg(1);
        let mask = width_mask_u64(width);
        let delta = MicroOperand::Temp(3);
        if !has_any_rep(inst) {
            self.emit_dir_delta(n);
            let val = MicroOperand::Temp(5);
            self.desynth.instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width })
                    .with_dst(val)
                    .with_src1(rsi),
            );
            if width == 8 {
                self.desynth
                    .instrs
                    .push(MicroInstr::new(RiscOp::Mov).with_dst(acc).with_src1(val));
            } else {
                // x86 LODSB/LODSW: only the low 8/16 bits of RAX are written; the
                // upper bits are PRESERVED. acc = (acc & ~mask) | (val & mask).
                self.desynth.emit_and(acc, acc, MicroOperand::Imm64(!mask));
                self.desynth
                    .emit_and(MicroOperand::Temp(2), val, MicroOperand::Imm64(mask));
                self.desynth.emit_or(acc, acc, MicroOperand::Temp(2));
            }
            self.desynth.emit_add(rsi, rsi, delta);
            return Ok(());
        }
        self.emit_dir_delta(n);
        let loop_start = self.desynth.instrs.len();
        let scratch = MicroOperand::Temp(0);
        self.desynth.emit_and(scratch, rcx, rcx);
        let done_br = self.desynth.instrs.len();
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Zero,
            })
            .with_imm(0),
        );
        let val = MicroOperand::Temp(5);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width })
                .with_dst(val)
                .with_src1(rsi),
        );
        if width == 8 {
            self.desynth
                .instrs
                .push(MicroInstr::new(RiscOp::Mov).with_dst(acc).with_src1(val));
        } else {
            self.desynth.emit_and(acc, acc, MicroOperand::Imm64(!mask));
            self.desynth
                .emit_and(MicroOperand::Temp(2), val, MicroOperand::Imm64(mask));
            self.desynth.emit_or(acc, acc, MicroOperand::Temp(2));
        }
        self.desynth.emit_add(rsi, rsi, delta);
        self.desynth.emit_sub(rcx, rcx, MicroOperand::Imm64(1));
        self.desynth.emit_jmp(loop_start as u64);
        let done_idx = self.desynth.instrs.len();
        self.desynth.instrs[done_br].imm = done_idx as u64;
        Ok(())
    }

    /// SCAS/CMPS 비교 피연산자를 (lhs=Temp6, rhs=Temp7) 로 준비.
    /// SCAS: lhs = acc(폭별 마스크), rhs = [rdi]. CMPS: lhs = [rsi], rhs = [rdi].

    pub(super) fn scas_cmps_operands(&mut self, width: u8, is_cmps: bool) {
        let acc = MicroOperand::VReg(0);
        let rsi = MicroOperand::VReg(6);
        let rdi = MicroOperand::VReg(7);
        let lhs = MicroOperand::Temp(6);
        if is_cmps {
            self.desynth.instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width })
                    .with_dst(lhs)
                    .with_src1(rsi),
            );
        } else if width == 8 {
            self.desynth
                .instrs
                .push(MicroInstr::new(RiscOp::Mov).with_dst(lhs).with_src1(acc));
        } else {
            self.desynth
                .emit_and(lhs, acc, MicroOperand::Imm64(width_mask_u64(width)));
        }
        let rhs = MicroOperand::Temp(7);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width })
                .with_dst(rhs)
                .with_src1(rdi),
        );
    }

    /// SCAS: flags = AL/AX/EAX/RAX - [rdi]; rdi+=DF ? -n : n. REPE/REPNE → ZF 중단.
    /// v65: bump direction honours DF via `emit_dir_delta` (Temp(3)); the compare
    /// SUB is emitted last so the final flags are the compare result.

    pub(super) fn lift_scas(&mut self, inst: &Instruction) -> Result<()> {
        let n = scas_cmps_width(inst.code()) as u64;
        let width = n as u8;
        let rdi = MicroOperand::VReg(7);
        let rcx = MicroOperand::VReg(1);
        let delta = MicroOperand::Temp(3);
        if !has_any_rep(inst) {
            self.emit_dir_delta(n);
            self.scas_cmps_operands(width, false);
            // [rdi] 읽기 후 rdi+=delta (플래그 훼손 가능) — 비교 SUB 를 마지막에 내보내
            // 최종 플래그가 비교 결과가 되도록 한다.
            self.desynth.emit_add(rdi, rdi, delta);
            let scratch = MicroOperand::Temp(5);
            self.desynth.instrs.push(
                MicroInstr::new(RiscOp::SubWithBorrow { width })
                    .with_dst(scratch)
                    .with_src1(MicroOperand::Temp(6))
                    .with_src2(MicroOperand::Temp(7)),
            );
            return Ok(());
        }
        let stop_cond = if inst.has_repne_prefix() {
            BranchCondition::Zero // REPNE: 같으면(ZF) 중단
        } else {
            BranchCondition::NotZero // REPE/REP: 다르면(ZF=0) 중단
        };
        self.emit_dir_delta(n);
        let loop_start = self.desynth.instrs.len();
        let scratch = MicroOperand::Temp(0);
        self.desynth.emit_and(scratch, rcx, rcx);
        let done_br = self.desynth.instrs.len();
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Zero,
            })
            .with_imm(0),
        );
        self.scas_cmps_operands(width, false);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::SubWithBorrow { width })
                .with_dst(scratch)
                .with_src1(MicroOperand::Temp(6))
                .with_src2(MicroOperand::Temp(7)),
        );
        let captured = MicroOperand::Temp(2);
        self.desynth
            .instrs
            .push(MicroInstr::new(RiscOp::Setcc { cond: stop_cond }).with_dst(captured));
        self.desynth.emit_add(rdi, rdi, delta);
        self.desynth.emit_sub(rcx, rcx, MicroOperand::Imm64(1));
        // captured 가 참이면 fix_flags 로 분기 (ZStop 조건 충족)
        let tz = MicroOperand::Temp(0);
        self.desynth.emit_sub(tz, captured, MicroOperand::Imm64(0)); // ZF = (captured==0)
        let fix_br = self.desynth.instrs.len();
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::NotZero,
            })
            .with_imm(0),
        );
        self.desynth.emit_jmp(loop_start as u64);
        // fix_flags: 최종(중단) 비교의 정확한 플래그 재생성 (lhs/rhs 는 Temp6/7 보존)
        let fix_idx = self.desynth.instrs.len();
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::SubWithBorrow { width })
                .with_dst(scratch)
                .with_src1(MicroOperand::Temp(6))
                .with_src2(MicroOperand::Temp(7)),
        );
        let done_idx = self.desynth.instrs.len();
        self.desynth.instrs[done_br].imm = done_idx as u64;
        self.desynth.instrs[fix_br].imm = fix_idx as u64;
        Ok(())
    }

    /// CMPS: flags = [rsi] - [rdi]; rsi+=±n; rdi+=±n. REPE/REPNE → ZF 중단.
    /// v65: bump direction honours DF via `emit_dir_delta` (Temp(3)).

    pub(super) fn lift_cmps(&mut self, inst: &Instruction) -> Result<()> {
        let n = scas_cmps_width(inst.code()) as u64;
        let width = n as u8;
        let rsi = MicroOperand::VReg(6);
        let rdi = MicroOperand::VReg(7);
        let rcx = MicroOperand::VReg(1);
        let delta = MicroOperand::Temp(3);
        if !has_any_rep(inst) {
            self.emit_dir_delta(n);
            self.scas_cmps_operands(width, true);
            self.desynth.emit_add(rsi, rsi, delta);
            self.desynth.emit_add(rdi, rdi, delta);
            let scratch = MicroOperand::Temp(5);
            self.desynth.instrs.push(
                MicroInstr::new(RiscOp::SubWithBorrow { width })
                    .with_dst(scratch)
                    .with_src1(MicroOperand::Temp(6))
                    .with_src2(MicroOperand::Temp(7)),
            );
            return Ok(());
        }
        let stop_cond = if inst.has_repne_prefix() {
            BranchCondition::Zero
        } else {
            BranchCondition::NotZero
        };
        self.emit_dir_delta(n);
        let loop_start = self.desynth.instrs.len();
        let scratch = MicroOperand::Temp(0);
        self.desynth.emit_and(scratch, rcx, rcx);
        let done_br = self.desynth.instrs.len();
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Zero,
            })
            .with_imm(0),
        );
        self.scas_cmps_operands(width, true);
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::SubWithBorrow { width })
                .with_dst(scratch)
                .with_src1(MicroOperand::Temp(6))
                .with_src2(MicroOperand::Temp(7)),
        );
        let captured = MicroOperand::Temp(2);
        self.desynth
            .instrs
            .push(MicroInstr::new(RiscOp::Setcc { cond: stop_cond }).with_dst(captured));
        self.desynth.emit_add(rsi, rsi, delta);
        self.desynth.emit_add(rdi, rdi, delta);
        self.desynth.emit_sub(rcx, rcx, MicroOperand::Imm64(1));
        let tz = MicroOperand::Temp(0);
        self.desynth.emit_sub(tz, captured, MicroOperand::Imm64(0));
        let fix_br = self.desynth.instrs.len();
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::NotZero,
            })
            .with_imm(0),
        );
        self.desynth.emit_jmp(loop_start as u64);
        let fix_idx = self.desynth.instrs.len();
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::SubWithBorrow { width })
                .with_dst(scratch)
                .with_src1(MicroOperand::Temp(6))
                .with_src2(MicroOperand::Temp(7)),
        );
        let done_idx = self.desynth.instrs.len();
        self.desynth.instrs[done_br].imm = done_idx as u64;
        self.desynth.instrs[fix_br].imm = fix_idx as u64;
        Ok(())
    }
}
