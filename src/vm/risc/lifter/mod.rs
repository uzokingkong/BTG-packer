// ==============================================================================
// BTG - Commercial-Grade VM: Full x86-64 -> RISC Micro-Op Lifter
// ==============================================================================
// iced-x86 Instruction????12揶쏆뮇???癒?뻻 RISC 筌띾뜆???以??怨쀪텦 ??쀂???살쨮 筌욊낯??癰궰??
// ?怨쀫떊/??겸봺/筌롫뗀?덄뵳??브쑨由???쎄문 ?袁⑥뺘????뽯땾 RISC ?癒?쁽嚥??브쑵鍮??뤿연 ?癒?궚 ??볥젃??됱퓗?????댘??뺣뼄.
//
// T1-2 ?類ㅼ삢: CALL(筌?揶쏄쑴??, ?袁⑷퍥 Jcc 鈺곌퀗援? CMP, 筌롫뗀?덄뵳???깅염?怨쀬쁽 ?怨쀫떊,
// SHL/SHR ??쀫늄?? MOVZX, LEAVE ?袁⑥쨮嚥≪뮄?/?癒곕툡嚥≪뮄??
// ==============================================================================

use super::desynth::RiscDesynthesizer;
use super::opcodes::{BranchCondition, MicroInstr, MicroOperand, RiscOp};
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, OpKind, Register};

mod arith;
mod sse;
mod string;

/// XMM ?????쎄숲 ???뵬???袁⑺뒄??롫뮉 揶쎛??筌롫뗀?덄뵳??怨몃열 疫꿸퀣? 雅뚯눘??
/// 揶?XMM(i) ?? `mem[XMM_SLOT_BASE + i*16 .. +16]` ??128??쑵???????곗쨮 鈺곕똻???뺣뼄.
/// ??쇰????怨쀪텦?? ??륁맄 ?遺용꺖(4/8B)筌??臾롫젏 ???怨몄맄 獄쏅뗄??紐껊뮉 x86 ??쇰??????嚥≪쥓?嚥?癰귣똻??
const XMM_SLOT_BASE: u64 = 0xF000_0000_0000_0000;

/// REP / REPE / REPNE ?袁ⓥ봺??뚮뮞 鈺곕똻????? (string ops). `has_rep_prefix()` ??
/// REPNE(0xF2) ?癒?뮉 false ?????젻雅뚯눖?嚥??????類ㅼ뵥??곷튊 ??뺣뼄.
fn has_any_rep(inst: &Instruction) -> bool {
    inst.has_rep_prefix() || inst.has_repne_prefix()
}

/// STOS/LODS ?遺용꺖 ??(bytes).
fn stos_lods_width(code: Code) -> u8 {
    use iced_x86::Code::*;
    match code {
        Stosb_m8_AL | Lodsb_AL_m8 => 1,
        Stosw_m16_AX | Lodsw_AX_m16 => 2,
        Stosd_m32_EAX | Lodsd_EAX_m32 => 4,
        _ => 8,
    }
}

/// SCAS/CMPS ?遺용꺖 ??(bytes).
fn scas_cmps_width(code: Code) -> u8 {
    use iced_x86::Code::*;
    match code {
        Scasb_AL_m8 | Cmpsb_m8_m8 => 1,
        Scasw_AX_m16 | Cmpsw_m16_m16 => 2,
        Scasd_EAX_m32 | Cmpsd_m32_m32 => 4,
        _ => 8,
    }
}

/// MOVS ?遺용꺖 ??(bytes).
fn movs_width(code: Code) -> u8 {
    use iced_x86::Code::*;
    match code {
        Movsb_m8_m8 => 1,
        Movsw_m16_m16 => 2,
        Movsd_m32_m32 => 4,
        _ => 8,
    }
}

/// ????筌띾뜆???(0-?類ㅼ삢??.
fn width_mask_u64(width: u8) -> u64 {
    match width {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => u64::MAX,
    }
}

/// ?怨쀫떊/??겸봺 2???怨쀪텦???遺용뮞??ν뒄 ?ル굝履?
#[derive(Clone, Copy, PartialEq)]
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

/// SSE/FPU ??쇰????怨쀫떊 ?怨쀪텦 ?ル굝履?(ADDSS/SD夷똕UB夷똌UL夷똃IV).
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

/// SETcc 16 鈺곌퀗援???BranchCondition.
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

/// CMOVcc (16 鈺곌퀗援???16/32/64) ??BranchCondition.
fn cond_for_cmov(code: Code) -> Option<BranchCondition> {
    match code {
        Code::Cmova_r16_rm16 | Code::Cmova_r32_rm32 | Code::Cmova_r64_rm64 => {
            Some(BranchCondition::Above)
        }
        Code::Cmovae_r16_rm16 | Code::Cmovae_r32_rm32 | Code::Cmovae_r64_rm64 => {
            Some(BranchCondition::AboveOrEqual)
        }
        Code::Cmovb_r16_rm16 | Code::Cmovb_r32_rm32 | Code::Cmovb_r64_rm64 => {
            Some(BranchCondition::Below)
        }
        Code::Cmovbe_r16_rm16 | Code::Cmovbe_r32_rm32 | Code::Cmovbe_r64_rm64 => {
            Some(BranchCondition::BelowOrEqual)
        }
        Code::Cmove_r16_rm16 | Code::Cmove_r32_rm32 | Code::Cmove_r64_rm64 => {
            Some(BranchCondition::Zero)
        }
        Code::Cmovne_r16_rm16 | Code::Cmovne_r32_rm32 | Code::Cmovne_r64_rm64 => {
            Some(BranchCondition::NotZero)
        }
        Code::Cmovg_r16_rm16 | Code::Cmovg_r32_rm32 | Code::Cmovg_r64_rm64 => {
            Some(BranchCondition::Greater)
        }
        Code::Cmovge_r16_rm16 | Code::Cmovge_r32_rm32 | Code::Cmovge_r64_rm64 => {
            Some(BranchCondition::GreaterOrEqual)
        }
        Code::Cmovl_r16_rm16 | Code::Cmovl_r32_rm32 | Code::Cmovl_r64_rm64 => {
            Some(BranchCondition::Less)
        }
        Code::Cmovle_r16_rm16 | Code::Cmovle_r32_rm32 | Code::Cmovle_r64_rm64 => {
            Some(BranchCondition::LessOrEqual)
        }
        Code::Cmovo_r16_rm16 | Code::Cmovo_r32_rm32 | Code::Cmovo_r64_rm64 => {
            Some(BranchCondition::Overflow)
        }
        Code::Cmovno_r16_rm16 | Code::Cmovno_r32_rm32 | Code::Cmovno_r64_rm64 => {
            Some(BranchCondition::NotOverflow)
        }
        Code::Cmovp_r16_rm16 | Code::Cmovp_r32_rm32 | Code::Cmovp_r64_rm64 => {
            Some(BranchCondition::Parity)
        }
        Code::Cmovnp_r16_rm16 | Code::Cmovnp_r32_rm32 | Code::Cmovnp_r64_rm64 => {
            Some(BranchCondition::NotParity)
        }
        Code::Cmovs_r16_rm16 | Code::Cmovs_r32_rm32 | Code::Cmovs_r64_rm64 => {
            Some(BranchCondition::Sign)
        }
        Code::Cmovns_r16_rm16 | Code::Cmovns_r32_rm32 | Code::Cmovns_r64_rm64 => {
            Some(BranchCondition::NotSign)
        }
        _ => None,
    }
}

impl RiscLifter {
    pub fn new() -> Self {
        Self {
            desynth: RiscDesynthesizer::new(),
        }
    }

    /// x86 Register??MicroOperand::VReg嚥?癰궰??(RAX=0 ... R15=15)
    pub fn reg_to_vreg(reg: Register) -> Option<MicroOperand> {
        // High-byte registers (AH/BH/CH/DH ??bits 8..15) are not representable in
        // the 64-bit vreg model: they would alias the full GPR and be read/written
        // as the low byte. Reject them explicitly (None -> lift error).
        if matches!(
            reg,
            Register::AH | Register::BH | Register::CH | Register::DH
        ) {
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

    /// x86 32??쑵??GPR(op0)??筌뤴뫗?삼쭪?嚥??怨뺣뮉 筌뤿굝議?????怨몄맄 32??쑵?껆몴?0??곗쨮 ?類ｂ봺??뺣뼄.
    /// (x86 域뱀뮇?? 32??쑵???????쎄숲 ?怨뚮┛??64??쑵???????쎄숲???怨몄맄 ??덉뺘??0??곗쨮 筌띾슢諭??)
    /// ?遺욧퐣?紐꾨뻻??? ?怨쀭뀱??野껉퀗??`dst`??`AND dst, 0xFFFFFFFF` 嚥?筌띾뜆???釉??
    fn zero_extend_dst_if32(&mut self, inst: &Instruction, dst: MicroOperand) {
        let reg = inst.op0_register();
        let is32 = matches!(
            reg,
            Register::EAX
                | Register::ECX
                | Register::EDX
                | Register::EBX
                | Register::ESP
                | Register::EBP
                | Register::ESI
                | Register::EDI
                | Register::R8D
                | Register::R9D
                | Register::R10D
                | Register::R11D
                | Register::R12D
                | Register::R13D
                | Register::R14D
                | Register::R15D
        );
        if is32 {
            self.desynth
                .emit_and(dst, dst, MicroOperand::Imm64(0xFFFF_FFFF));
        }
    }

    /// Preserve x86 MOV's flag transparency while finalizing a register write.
    /// A 32-bit destination zero-extends its virtual GPR; 8/16-bit destinations
    /// replace only their low part.  The RISC expressions used for masking and
    /// merging are flag-producing, therefore the original flags are explicitly
    /// restored.  This is intentionally separate from ALU narrow-write handling:
    /// MOV itself must never change RFLAGS.
    fn begin_mov_register_write(&mut self, inst: &Instruction, dst: MicroOperand) -> Option<u8> {
        let width = inst.op0_register().size() as u8;
        if width <= 2 {
            self.desynth.instrs.push(
                MicroInstr::new(RiscOp::Mov)
                    .with_dst(MicroOperand::Temp(5))
                    .with_src1(dst),
            );
        }
        self.desynth.instrs.push(
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::Temp(7))
                .with_src1(MicroOperand::Vflags),
        );
        Some(width)
    }

    fn finish_mov_register_write(
        &mut self,
        inst: &Instruction,
        dst: MicroOperand,
        width: Option<u8>,
    ) -> Result<()> {
        let Some(width) = width else {
            return Ok(());
        };
        if width == 4 {
            self.zero_extend_dst_if32(inst, dst);
        } else if width <= 2 {
            self.mask_result(width, inst, dst)?;
            self.preserve_upper_from(dst, width, MicroOperand::Temp(5));
        }
        self.desynth
            .instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Temp(7)));
        Ok(())
    }

    /// 筌롫뗀?덄뵳??醫륁뒞 雅뚯눘???④쑴沅??RISC 筌띾뜆???以??怨쀪텦??곗쨮 ?브쑵鍮?
    /// `addr = base + index*scale + disp`
    pub fn lower_effective_address(
        &mut self,
        inst: &Instruction,
        temp_dst: MicroOperand,
    ) -> Result<()> {
        let base_reg = inst.memory_base();
        let idx_reg = inst.memory_index();
        let scale = inst.memory_index_scale();
        let disp = inst.memory_displacement64();

        // A non-flat segment changes the effective address.  In particular,
        // Rust's Windows environment path walks the TEB/PEB through GS.  The
        // RISC memory model has no segment-base addition in this lowering, so
        // accepting FS/GS here silently dereferences the wrong address rather
        // than failing a lift.  Keep the complete containing function native
        // until segment-aware address lowering is implemented.
        let segment = inst.memory_segment();
        let segmented = matches!(segment, Register::FS | Register::GS);

        // P2 (G3): RIP-relative addressing — x86의 `[rip+disp32]`는 **다음 명령
        // 주소**(inst.ip() + inst.len()) + disp32 가 피연산자의 절대 주소다.
        // 패킹 후 데이터 섹션(.rdata/.data/.rodata)은 원본 RVA를 그대로 유지하므로
        // 소스 절대 VA를 즉시값으로 박으면 런타임 주소와 일치한다.
        //
        // The earlier safety gate was caused by incomplete immediate decoding
        // and missing width-aware native handlers. Both paths are now covered
        // by differential tests, so materialize iced-x86's resolved absolute
        // target directly and avoid re-applying the displacement below.
        if base_reg == Register::RIP {
            self.desynth.emit_add(
                temp_dst,
                MicroOperand::Imm64(inst.ip_rel_memory_address()),
                MicroOperand::Imm64(0),
            );
            return Ok(());
        }

        // 1. Start with base or 0
        if segmented {
            self.desynth.instrs.push(
                MicroInstr::new(RiscOp::ReadSegmentBase {
                    gs: segment == Register::GS,
                })
                .with_dst(temp_dst),
            );
            if base_reg != Register::None {
                let base_v =
                    Self::reg_to_vreg(base_reg).ok_or_else(|| anyhow!("unsupported base reg"))?;
                self.desynth.emit_add(temp_dst, temp_dst, base_v);
            }
        } else if base_reg != Register::None {
            let base_v =
                Self::reg_to_vreg(base_reg).ok_or_else(|| anyhow!("unsupported base reg"))?;
            self.desynth
                .emit_add(temp_dst, base_v, MicroOperand::Imm64(0));
        } else {
            self.desynth
                .emit_add(temp_dst, MicroOperand::Imm64(0), MicroOperand::Imm64(0));
        }

        // 2. Add scaled index: index * scale
        if idx_reg != Register::None {
            let idx_v =
                Self::reg_to_vreg(idx_reg).ok_or_else(|| anyhow!("unsupported index reg"))?;
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
            self.desynth
                .emit_add(temp_dst, temp_dst, MicroOperand::Imm64(disp));
        }

        Ok(())
    }

    /// ??μ뵬 ??깅염?怨쀬쁽??MicroOperand 揶쏅??앮에???곴퐤. ?????쎄숲->VReg, 筌앸맩??>Imm64,
    /// 筌롫뗀?덄뵳?>?醫륁뒞雅뚯눘?쇘몴?Temp(4)???④쑴沅???MemoryRead??Temp(6)??嚥≪뮆諭??뤿연 Temp 獄쏆꼹??
    /// (x86?? ?紐꾨뮞?紐껋쑏??롫뼣 筌롫뗀?덄뵳???깅염?怨쀬쁽揶쎛 筌ㅼ뮆? ??롪돌???嚥?Temp(4)/Temp(6) ?겸뫖猷???곸벉.)
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
            OpKind::Register => {
                Self::reg_to_vreg(reg).ok_or_else(|| anyhow!("invalid operand register"))
            }
            OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64 => Ok(MicroOperand::Imm64(inst.immediate64())),
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

    /// ADD/SUB/XOR/AND/OR ???????쎄숲夷뚳쭖遺얇걟??猷뱀ケ????깅염?怨쀬쁽 ?⑤벏??筌ｌ꼶??
    /// op0揶쎛 筌롫뗀?덄뵳???read-modify-write, op0揶쎛 ?????쎄숲筌?op1(筌롫뗀?덄뵳?揶쎛?????酉釉??

    pub fn lift_instruction(&mut self, inst: &Instruction) -> Result<()> {
        let code = inst.code();

        match code {
            // P2 (G3): NOP / Pause — 무연산. RISC micro-op을 만들지 않아
            // 커버리지를 높이고(코드베이스 NOP/멀티바이트 NOP 다수) 실행 의미도
            // 그대로다. (Pause는 스핀 루프 힌트일 뿐 단일 스레드 의미론 무연산.)
            Code::Nopw | Code::Nopd | Code::Nop_rm16 | Code::Nop_rm32 | Code::Nop_rm64 | Code::Pause => {}
            Code::Ud2 => self.desynth.instrs.push(MicroInstr::new(RiscOp::Trap)),
            Code::Int_imm8 => self.desynth.instrs.push(MicroInstr::new(RiscOp::Trap)),
            Code::Cpuid => self.desynth.instrs.push(MicroInstr::new(RiscOp::CpuId)),
            Code::Xgetbv => self.desynth.instrs.push(MicroInstr::new(RiscOp::XGetBv)),
            // ???? MOV ?④쑴肉?????????????????????????????????????????????????????????????????????????????????????????????????????????????????
            Code::Mov_r64_rm64 | Code::Mov_r32_rm32 | Code::Mov_r16_rm16 | Code::Mov_r8_rm8 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                let mov_width = self.begin_mov_register_write(inst, dst);
                if inst.op1_kind() == OpKind::Register {
                    let src = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid src"))?;
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov).with_dst(dst).with_src1(src),
                    );
                    self.finish_mov_register_write(inst, dst, mov_width)?;
                } else if inst.op1_kind() == OpKind::Memory {
                    let t_addr = MicroOperand::Temp(4);
                    self.lower_effective_address(inst, t_addr)?;
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::MemoryRead { width: inst.memory_size().size() as u8 })
                            .with_dst(dst)
                            .with_src1(t_addr),
                    );
                    self.finish_mov_register_write(inst, dst, mov_width)?;
                }
            }
            Code::Mov_rm64_r64 | Code::Mov_rm32_r32 | Code::Mov_rm16_r16 | Code::Mov_rm8_r8 => {
                let src_reg = inst.op1_register();
                let src = if matches!(src_reg, Register::AH | Register::BH | Register::CH | Register::DH) {
                    let base = match src_reg { Register::AH => 0, Register::CH => 1, Register::DH => 2, _ => 3 };
                    let tmp = MicroOperand::Temp(6);
                    self.desynth.instrs.push(MicroInstr::new(RiscOp::ShiftRight)
                        .with_dst(tmp).with_src1(MicroOperand::VReg(base)).with_src2(MicroOperand::Imm64(8)));
                    tmp
                } else {
                    Self::reg_to_vreg(src_reg).ok_or_else(|| anyhow!("invalid src"))?
                };
                if inst.op0_kind() == OpKind::Register {
                    let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                    let mov_width = self.begin_mov_register_write(inst, dst);
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov).with_dst(dst).with_src1(src),
                    );
                    self.finish_mov_register_write(inst, dst, mov_width)?;
                } else if inst.op0_kind() == OpKind::Memory {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov).with_dst(MicroOperand::Temp(7)).with_src1(MicroOperand::Vflags),
                    );
                    let t_addr = MicroOperand::Temp(4);
                    self.lower_effective_address(inst, t_addr)?;
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::MemoryWrite { width: inst.memory_size().size() as u8 })
                            .with_src1(t_addr)
                            .with_src2(src),
                    );
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Temp(7)),
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
                    let mov_width = self.begin_mov_register_write(inst, dst);
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov).with_dst(dst).with_src1(MicroOperand::Imm64(imm)),
                    );
                    self.finish_mov_register_write(inst, dst, mov_width)?;
                } else if inst.op0_kind() == OpKind::Memory {
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov).with_dst(MicroOperand::Temp(7)).with_src1(MicroOperand::Vflags),
                    );
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
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Temp(7)),
                    );
                }
            }

            // ???? MOVZX (0-?類ㅼ삢) ????????????????????????????????????????????????????????????????????????????????????????????????????
            Code::Movzx_r64_rm16 | Code::Movzx_r32_rm16 => self.lift_movzx(inst, 0xFFFF)?,
            Code::Movzx_r64_rm8 | Code::Movzx_r32_rm8 | Code::Movzx_r16_rm8 => self.lift_movzx(inst, 0xFF)?,
            Code::Movzx_r16_rm16 => self.lift_movzx(inst, 0xFFFF)?,

            // ???? MOVSX (?봔???類ㅼ삢) ????????????????????????????????????????????????????????????????????????????????????????????
            Code::Movsx_r64_rm16 | Code::Movsx_r32_rm16 | Code::Movsx_r16_rm16 => self.lift_movsx(inst, 16)?,
            Code::Movsx_r64_rm8 | Code::Movsx_r32_rm8 | Code::Movsx_r16_rm8 => self.lift_movsx(inst, 8)?,
            Code::Movsxd_r64_rm32 | Code::Movsxd_r32_rm32 | Code::Movsxd_r16_rm16 => self.lift_movsx(inst, 32)?,

            // ???? LEA ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
            Code::Lea_r64_m | Code::Lea_r32_m => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                // LEA only computes an address; it never dereferences memory.  Treat
                // RIP-relative LEA separately from the still-gated RIP-relative
                // MemoryRead/MemoryWrite path. iced-x86 has already resolved the
                // signed disp32 against next-IP for us.
                if inst.memory_base() == Register::RIP {
                    if matches!(inst.memory_segment(), Register::FS | Register::GS) {
                        return Err(anyhow!(
                            "risc lifter: FS/GS segmented addressing is not virtualized"
                        ));
                    }
                    self.desynth.emit_add(
                        dst,
                        MicroOperand::Imm64(inst.ip_rel_memory_address()),
                        MicroOperand::Imm64(0),
                    );
                    if code == Code::Lea_r32_m {
                        self.zero_extend_dst_if32(inst, dst);
                    }
                } else {
                    self.lower_effective_address(inst, dst)?;
                    if code == Code::Lea_r32_m {
                        self.zero_extend_dst_if32(inst, dst);
                    }
                }
            }

            // ???? ?怨쀫떊 ??껊?/ 筌먭쑴??/ ??겸봺 (?????쎄숲夷뚳쭖遺얇걟??猷뱀ケ???⑤벏?? ????????????????????????????
            Code::Add_rm64_r64
            | Code::Add_r64_rm64
            | Code::Add_rm32_r32
            | Code::Add_r32_rm32
            | Code::Add_rm64_imm32
            | Code::Add_rm64_imm8
            | Code::Add_rm32_imm32
            | Code::Add_rm32_imm8
            | Code::Add_RAX_imm32
            | Code::Add_EAX_imm32
            // P2 (G3): 8-bit ADD — Add{width:1}가 폭별 플래그·마스킹을 처리하고
            // preserve_upper가 레지스터 상위 비트를 복원한다 (메모리는 RMW가 정확).
            | Code::Add_AL_imm8
            | Code::Add_r8_rm8
            | Code::Add_rm8_imm8
            | Code::Add_rm8_r8 => self.lift_binary_alu(inst, Alu::Add)?,
            Code::Sub_rm64_r64
            | Code::Sub_r64_rm64
            | Code::Sub_rm32_r32
            | Code::Sub_r32_rm32
            | Code::Sub_rm64_imm32
            | Code::Sub_rm64_imm8
            | Code::Sub_rm32_imm32
            | Code::Sub_rm32_imm8
            | Code::Sub_RAX_imm32
            | Code::Sub_EAX_imm32
            // P2 (G3): 8-bit SUB — SubWithBorrow{width:1} + preserve_upper.
            | Code::Sub_AL_imm8
            | Code::Sub_r8_rm8
            | Code::Sub_rm8_imm8
            | Code::Sub_rm8_r8 => self.lift_binary_alu(inst, Alu::Sub)?,
            Code::Adc_AL_imm8 | Code::Adc_AX_imm16 | Code::Adc_EAX_imm32 | Code::Adc_RAX_imm32
            | Code::Adc_r8_rm8 | Code::Adc_r16_rm16 | Code::Adc_r32_rm32 | Code::Adc_r64_rm64
            | Code::Adc_rm8_r8 | Code::Adc_rm16_r16 | Code::Adc_rm32_r32 | Code::Adc_rm64_r64
            | Code::Adc_rm8_imm8 | Code::Adc_rm16_imm8 | Code::Adc_rm16_imm16
            | Code::Adc_rm32_imm8 | Code::Adc_rm32_imm32 | Code::Adc_rm64_imm8 | Code::Adc_rm64_imm32
                => self.lift_carry_alu(inst, true)?,
            Code::Sbb_AL_imm8 | Code::Sbb_AX_imm16 | Code::Sbb_EAX_imm32 | Code::Sbb_RAX_imm32
            | Code::Sbb_r8_rm8 | Code::Sbb_r16_rm16 | Code::Sbb_r32_rm32 | Code::Sbb_r64_rm64
            | Code::Sbb_rm8_r8 | Code::Sbb_rm16_r16 | Code::Sbb_rm32_r32 | Code::Sbb_rm64_r64
            | Code::Sbb_rm8_imm8 | Code::Sbb_rm16_imm8 | Code::Sbb_rm16_imm16
            | Code::Sbb_rm32_imm8 | Code::Sbb_rm32_imm32 | Code::Sbb_rm64_imm8 | Code::Sbb_rm64_imm32
                => self.lift_carry_alu(inst, false)?,
            Code::Rol_rm8_1 | Code::Rol_rm8_imm8 | Code::Rol_rm8_CL
            | Code::Rol_rm16_1 | Code::Rol_rm16_imm8 | Code::Rol_rm16_CL
            | Code::Rol_rm32_1 | Code::Rol_rm32_imm8 | Code::Rol_rm32_CL
            | Code::Rol_rm64_1 | Code::Rol_rm64_imm8 | Code::Rol_rm64_CL
                => self.lift_rotate_left(inst)?,
            Code::Xor_rm64_r64
            | Code::Xor_r64_rm64
            | Code::Xor_rm32_r32
            | Code::Xor_r32_rm32
            | Code::Xor_rm64_imm32
            | Code::Xor_rm64_imm8
            | Code::Xor_rm32_imm32
            | Code::Xor_rm32_imm8
            | Code::Xor_RAX_imm32
            | Code::Xor_EAX_imm32
            // R7: 8/16-bit XOR — lift_binary_alu가 폭별 마스킹 + preserve_upper.
            | Code::Xor_rm8_r8 | Code::Xor_r8_rm8 | Code::Xor_AL_imm8 | Code::Xor_rm8_imm8
            | Code::Xor_rm16_r16 | Code::Xor_r16_rm16 | Code::Xor_AX_imm16
            | Code::Xor_rm16_imm8 | Code::Xor_rm16_imm16 => self.lift_binary_alu(inst, Alu::Xor)?,
            Code::And_rm64_r64
            | Code::And_r64_rm64
            | Code::And_rm32_r32
            | Code::And_r32_rm32
            | Code::And_rm64_imm32
            | Code::And_rm64_imm8
            | Code::And_rm32_imm32
            | Code::And_rm32_imm8
            | Code::And_RAX_imm32
            | Code::And_EAX_imm32
            // R7: 8/16-bit AND — 폭별 마스킹 + preserve_upper.
            | Code::And_rm8_r8 | Code::And_r8_rm8 | Code::And_AL_imm8 | Code::And_rm8_imm8
            | Code::And_rm16_r16 | Code::And_r16_rm16 | Code::And_AX_imm16
            | Code::And_rm16_imm8 | Code::And_rm16_imm16 => self.lift_binary_alu(inst, Alu::And)?,
            Code::Or_rm64_r64
            | Code::Or_r64_rm64
            | Code::Or_rm32_r32
            | Code::Or_r32_rm32
            | Code::Or_rm64_imm32
            | Code::Or_rm64_imm8
            | Code::Or_rm32_imm32
            | Code::Or_rm32_imm8
            | Code::Or_RAX_imm32
            | Code::Or_EAX_imm32
            // R7: 8/16-bit OR — 폭별 마스킹 + preserve_upper.
            | Code::Or_rm8_r8 | Code::Or_r8_rm8 | Code::Or_AL_imm8 | Code::Or_rm8_imm8
            | Code::Or_rm16_r16 | Code::Or_r16_rm16 | Code::Or_AX_imm16
            | Code::Or_rm16_imm8 | Code::Or_rm16_imm16 => self.lift_binary_alu(inst, Alu::Or)?,
            // R7: 8/16-bit NEG/NOT — SubWithBorrow/Not{width} + preserve_upper.
            Code::Neg_rm8 | Code::Neg_rm16 | Code::Neg_rm64 | Code::Neg_rm32 => {
                self.lift_neg_not(inst, false)?
            }
            Code::Not_rm8 | Code::Not_rm16 | Code::Not_rm64 | Code::Not_rm32 => {
                self.lift_neg_not(inst, true)?
            }

            // ???? CMP (???삋域밸챶彛?揶쏄퉮?? ??????????????????????????????????????????????????????????????????????????????????????????
            Code::Cmp_r64_rm64
            | Code::Cmp_rm64_r64
            | Code::Cmp_rm64_imm32
            | Code::Cmp_rm64_imm8
            | Code::Cmp_RAX_imm32
            | Code::Cmp_r32_rm32
            | Code::Cmp_rm32_r32
            | Code::Cmp_rm32_imm32
            | Code::Cmp_rm32_imm8
            | Code::Cmp_EAX_imm32
            // P2 (G3): 8/16-bit CMP — lift_cmp는 SubWithBorrow{width}로 폭별
            // 플래그를 정확히 계산하고 결과는 버린다 (스크래치 Temp(7)).
            | Code::Cmp_AL_imm8
            | Code::Cmp_r8_rm8
            | Code::Cmp_rm8_imm8
            | Code::Cmp_rm8_r8
            | Code::Cmp_rm16_imm16
            | Code::Cmp_rm16_imm8
            | Code::Cmp_rm16_r16 => self.lift_cmp(inst)?,

            // ???? ??쀫늄??(SHL / SHR) ????????????????????????????????????????????????????????????????????????????????????????????
            Code::Shl_rm64_imm8 | Code::Shl_rm64_1 | Code::Shl_rm64_CL
            | Code::Shl_rm32_imm8 | Code::Shl_rm32_1 | Code::Shl_rm32_CL
            // R7: 8/16-bit SHL — lift_shift가 폭별 마스킹 + preserve_upper.
            | Code::Shl_rm16_imm8 | Code::Shl_rm16_1 | Code::Shl_rm16_CL
            | Code::Shl_rm8_imm8 | Code::Shl_rm8_1 | Code::Shl_rm8_CL => self.lift_shift(inst, RiscOp::ShiftLeft)?,
            Code::Shr_rm64_imm8 | Code::Shr_rm64_1 | Code::Shr_rm64_CL
            | Code::Shr_rm32_imm8 | Code::Shr_rm32_1 | Code::Shr_rm32_CL
            // R7: 8/16-bit SHR — lift_shift가 폭별 마스킹 + preserve_upper.
            | Code::Shr_rm16_imm8 | Code::Shr_rm16_1 | Code::Shr_rm16_CL
            | Code::Shr_rm8_imm8 | Code::Shr_rm8_1 | Code::Shr_rm8_CL => self.lift_shift(inst, RiscOp::ShiftRight)?,
            // SAR (?怨쀫떊 ?怨쀫? ??쀫늄?????봔????쑵???醫?)
            Code::Sar_rm64_imm8 | Code::Sar_rm64_1 | Code::Sar_rm64_CL
            | Code::Sar_rm32_imm8 | Code::Sar_rm32_1 | Code::Sar_rm32_CL
            | Code::Sar_rm16_imm8 | Code::Sar_rm16_1 | Code::Sar_rm16_CL
            | Code::Sar_rm8_imm8 | Code::Sar_rm8_1 | Code::Sar_rm8_CL => {
                self.lift_shift(inst, RiscOp::ArithmeticShiftRight)?
            }
            Code::Shld_rm64_r64_imm8 => {
                let count = MicroOperand::Imm64(inst.immediate8() as u64);
                let src = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid SHLD source"))?;
                if inst.op0_kind() == OpKind::Register {
                    let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid SHLD destination"))?;
                    self.desynth.instrs.push(MicroInstr::new(RiscOp::DoubleShiftLeft { width: 8 })
                        .with_dst(dst).with_src1(src).with_src2(count));
                } else {
                    let addr = MicroOperand::Temp(4);
                    self.lower_effective_address(inst, addr)?;
                    let val = MicroOperand::Temp(5);
                    self.desynth.instrs.push(MicroInstr::new(RiscOp::MemoryRead { width: 8 }).with_dst(val).with_src1(addr));
                    self.desynth.instrs.push(MicroInstr::new(RiscOp::DoubleShiftLeft { width: 8 })
                        .with_dst(val).with_src1(src).with_src2(count));
                    self.desynth.instrs.push(MicroInstr::new(RiscOp::MemoryWrite { width: 8 }).with_src1(addr).with_src2(val));
                }
            }
            Code::Bt_rm32_imm8 | Code::Bt_rm32_r32 | Code::Bt_rm64_imm8 | Code::Bt_rm64_r64
            | Code::Btr_rm64_imm8 | Code::Btr_rm64_r64
            | Code::Bts_rm64_imm8 | Code::Bts_rm64_r64 => {
                let width = if matches!(code, Code::Bt_rm32_imm8 | Code::Bt_rm32_r32) { 4 } else { 8 };
                let modify = if matches!(code, Code::Btr_rm64_imm8 | Code::Btr_rm64_r64) { 1 }
                    else if matches!(code, Code::Bts_rm64_imm8 | Code::Bts_rm64_r64) { 2 } else { 0 };
                let index = self.operand_value(inst, 1)?;
                let memory = inst.op0_kind() == OpKind::Memory;
                if memory {
                    let addr = MicroOperand::Temp(4);
                    self.lower_effective_address(inst, addr)?;
                    self.desynth.instrs.push(MicroInstr::new(RiscOp::BitTest { width, modify, memory: true })
                        .with_src1(addr).with_src2(index));
                } else {
                    let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid bit-test destination"))?;
                    self.desynth.instrs.push(MicroInstr::new(RiscOp::BitTest { width, modify, memory: false })
                        .with_dst(dst).with_src1(dst).with_src2(index));
                }
            }

            // ???? ??쎄문 PUSH / POP ??????????????????????????????????????????????????????????????????????????????????????????????????
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

            // ???? LEAVE: mov rsp, rbp; pop rbp ????????????????????????????????????????????????????????????????????????
            Code::Leaveq | Code::Leaved | Code::Leavew => {
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::Mov).with_dst(MicroOperand::VReg(4)).with_src1(MicroOperand::VReg(5)),
                );
                self.desynth.emit_pop(MicroOperand::VReg(5));
            }

            // ???? CALL (筌욊낯??揶쏄쑴?? ????????????????????????????????????????????????????????????????????????????????????????????????
            Code::Call_rel32_64 => {
                let target = inst.near_branch_target();
                let ret_ip = inst.next_ip();
                self.desynth.emit_push(MicroOperand::Imm64(ret_ip));
                self.desynth.emit_jmp(target);
            }
            Code::Call_rm64 | Code::Call_rm32 => {
                let ret_ip = inst.next_ip();
                self.desynth.emit_push(MicroOperand::Imm64(ret_ip));
                let target = self.operand_value(inst, 0)?; // ?????쎄숲 ?癒?뮉 筌롫뗀?덄뵳?揶?
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::VirtualBranch {
                        cond: BranchCondition::Always,
                    })
                    .with_src1(target),
                );
            }

            // ???? ?브쑨由?獄???뽯선 ?癒?カ ????????????????????????????????????????????????????????????????????????????????????????????????
            Code::Jmp_rel32_64 | Code::Jmp_rel8_64 => {
                let target = inst.near_branch_target();
                self.desynth.emit_jmp(target);
            }
            // P2 (G3): 간접 JMP (`jmp rax` / `jmp [rip+..]` / `jmp qword ptr [rax+...]`).
            // 점프 테이블·가상 함수·switch dispatch 에 쓰인다. 타깃은 런타임 값이므로
            // VirtualBranch(Always)의 src1(계산된 타깃)로 emit한다 — Call_rm64와 동일
            // 계약으로, 타깃이 branch-map(ip_map)에 있으면 VM 내부 dispatch, 없으면
            // h_branch가 native-call 브리지로 처리한다.
            Code::Jmp_rm64 | Code::Jmp_rm32 => {
                let target = self.operand_value(inst, 0)?;
                self.desynth.instrs.push(
                    MicroInstr::new(RiscOp::VirtualBranch {
                        cond: BranchCondition::Always,
                    })
                    .with_src1(target),
                );
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
            // Jcxz/CX(16) 夷?Jecxz/ECX(32) 夷?Jrcxz/RCX(64): 燁삳똻????브쑨由?(reg[1] ??륁맄 width 獄쏅뗄???=0)
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
                // P0-1: RET → VirtualRet — 가상 스택에서 복귀 주소를 pop 해
                // ip_map 안이면 VM 내부 복귀, 아니면 Halt(프로그램 종료)로.
                self.desynth.instrs.push(MicroInstr::new(RiscOp::VirtualRet));
            }
            // RET imm16: RSP += imm ??VirtualRet (복귀 주소는 그대로 스택에서 pop).
            Code::Retnq_imm16 | Code::Retnw_imm16 => {
                let imm = inst.immediate16() as u64;
                if imm != 0 {
                    self.desynth.emit_add(
                        MicroOperand::VReg(4),
                        MicroOperand::VReg(4),
                        MicroOperand::Imm64(imm),
                    );
                }
                self.desynth.instrs.push(MicroInstr::new(RiscOp::VirtualRet));
            }

            // ???? P2: MUL / IMUL (1-??깅염?怨쀬쁽, RAX ?遺용뻻) ??????????????????????????????????????????????????????
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

            // ???? P2: IMUL 2/3-??깅염?怨쀬쁽 (dst = dst夷똲rc ?癒?뮉 dst = src夷똧mm) ????????????????
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

            // ???? P2: DIV / IDIV (RDX:RAX ??깆젫?? RAX 筌? ??????????????????????????????????????????????????
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

            // ???? P2: BSWAP ????????????????????????????????????????????????????????????????????????????????????????????????????????????
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

            // ???? P2: BSF / BSR / TZCNT / LZCNT / POPCNT ??????????????????????????????????????????????????
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

            // ???? P2: SETcc (16 鈺곌퀗援? ????????????????????????????????????????????????????????????????????????????????????????
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

            // ???? P2: CMOVcc (16 鈺곌퀗援???16/32/64) ??????????????????????????????????????????????????????????????
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
                // 32??쑵?? taken 野껋럥以덌쭕?0-?類ㅼ삢??곷튊 ???嚥??얜똻?쒎쳞?AND ???????뮞??
                // 沃섎챶??筌띾뜆???鍮?ConditionalMove 揶쎛 ??揶쏅???32??쑵?껅에???쀫립??뺣뼄.
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

            // ???? P2: TEST (AND-???삋域? 野껉퀗???癒?┛) ??????????????????????????????????????????????????????????????
            Code::Test_rm64_r64
            | Code::Test_rm64_imm32
            | Code::Test_RAX_imm32
            | Code::Test_rm32_r32
            | Code::Test_rm32_imm32
            | Code::Test_EAX_imm32
            | Code::Test_rm16_imm16
            | Code::Test_rm16_r16
            | Code::Test_AX_imm16
            | Code::Test_AL_imm8
            // P2 (G3): 8-bit TEST — lift_test가 `_ => 1`로 8비트 폭을 처리한다.
            | Code::Test_rm8_r8
            | Code::Test_rm8_imm8 => self.lift_test(inst)?,

            // ???? P2: XCHG ??????????????????????????????????????????????????????????????????????????????????????????????????????????????
            Code::Xchg_rm64_r64 | Code::Xchg_rm32_r32 | Code::Xchg_rm16_r16 | Code::Xchg_rm8_r8 => {
                self.lift_xchg(inst)?;
            }

            // ???? P2: XADD (筌롫뗀?덄뵳?RMW + ???삋域? ??????????????????????????????????????????????????????????????????
            Code::Xadd_rm8_r8 | Code::Xadd_rm16_r16 | Code::Xadd_rm32_r32 | Code::Xadd_rm64_r64 => {
                self.lift_xadd(inst)?;
            }

            // ???? P2: CMPXCHG (筌롫뗀?덄뵳??? ????????????????????????????????????????????????????????????????????????????????
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
                    // CMPXCHG ?????쎄숲 ??r/m = ?????쎄숲) ??域밸콅????빿? ??쇱뵠?怨뺥닏 ?醫?.
                    return Err(anyhow!("risc lifter: CMPXCHG register form kept native"));
                }
            }

            // ???? P2: INC / DEC ????????????????????????????????????????????????????????????????????????????????????????????????????
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
                        let op = if is_dec {
                            RiscOp::Dec { width }
                        } else {
                            RiscOp::Inc { width }
                        };
                        self.desynth.instrs.push(
                            MicroInstr::new(op).with_dst(dst).with_src1(dst),
                        );
                        let _ = one;
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
                        let op = if is_dec {
                            RiscOp::Dec { width }
                        } else {
                            RiscOp::Inc { width }
                        };
                        self.desynth.instrs.push(
                            MicroInstr::new(op).with_dst(left).with_src1(left),
                        );
                        let _ = one;
                        self.desynth.instrs.push(
                            MicroInstr::new(RiscOp::MemoryWrite { width: width_mem })
                                .with_src1(addr)
                                .with_src2(left),
                        );
                    }
                    _ => return Err(anyhow!("risc lifter: invalid inc/dec op0")),
                }
            }

            // ???? P2: BMI1/2 (ANDN/BLSR/BLSMSK/BLSI/BZHI) ????????????????????????????????????????????????
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
                // emit_xor ??????怨몄몵嚥?Temp(0..2) ???怨?嚥? 域밸챷? 癰귢쑨而?Temp(3) ???????
                // a-1 野껉퀗?든몴?癰귣똻??(Temp(0) ????餓λ쵌而????肉?XOR ??繹먥뫁彛??.
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

            // ???? P2: PUSH/POP 筌롫뗀?덄뵳???????????????????????????????????????????????????????????????????????????????????
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

            // ???? P2: ?얜챷???ops ????????????????????????????????????????????????????????????????????????????????????????????????
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
            // ???? v65: Direction Flag ??CLD clears DF, STD sets DF ??????????????????????????
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

            // ???? P2: SSE/FPU ??쇰???????????????????????????????????????????????????????????????????????????????????????????
            Code::Movsd_xmm_xmmm64 | Code::Movss_xmm_xmmm32 => self.lift_sse_mov_load(inst)?,
            Code::Movsd_xmmm64_xmm | Code::Movss_xmmm32_xmm => self.lift_sse_mov_store(inst)?,
            Code::Movd_xmm_rm32 | Code::Movd_rm32_xmm
            | Code::Movq_xmm_rm64 | Code::Movq_rm64_xmm => self.lift_movd_movq(inst)?,
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

            // ???? P1 (??: packed SSE — 128-bit XMM 슬롯/메모리 이동 + 요소 단위
            // 정수 연산. MOVDQA/DQU/UPS/APS/UPD/APD(load·store) → PackedMove,
            // PADDB/W/D/Q·PSUBB/W/D/Q·PXOR·PAND·POR·PANDN·PCMPEQB/W/D/Q → Packed*.
            // RFLAGS 불변. (`is_encodable` 비등록 — 폴리 인코딩/네이티브 실행 제외.)
            Code::Movdqa_xmm_xmmm128 | Code::Movdqu_xmm_xmmm128
            | Code::Movups_xmm_xmmm128 | Code::Movaps_xmm_xmmm128
            | Code::Movupd_xmm_xmmm128 | Code::Movapd_xmm_xmmm128
            | Code::Movdqa_xmmm128_xmm | Code::Movdqu_xmmm128_xmm
            | Code::Movups_xmmm128_xmm | Code::Movaps_xmmm128_xmm
            | Code::Movupd_xmmm128_xmm | Code::Movapd_xmmm128_xmm => self.lift_sse_packed_move(inst)?,
            Code::Psrlq_xmm_imm8 => self.lift_packed_shift_right_q(inst)?,
            Code::Pshufd_xmm_xmmm128_imm8 => self.lift_packed_shuffle(inst, false)?,
            Code::Pshuflw_xmm_xmmm128_imm8 => self.lift_packed_shuffle(inst, true)?,
            Code::Pmovmskb_r32_xmm => self.lift_packed_movmask(inst, false)?,
            Code::Movmskps_r32_xmm => self.lift_packed_movmask(inst, true)?,
            Code::Pinsrw_xmm_r32m16_imm8 => self.lift_pinsrw(inst)?,
            Code::Xorps_xmm_xmmm128 => self.lift_sse_packed_bin(inst, RiscOp::PackedXor)?,
            code_packed if Self::packed_op_for(code_packed).is_some() => {
                let op = Self::packed_op_for(code_packed).unwrap();
                self.lift_sse_packed_bin(inst, op)?;
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
mod tests;
