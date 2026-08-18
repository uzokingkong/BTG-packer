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

    /// x86 Register??MicroOperand::VReg嚥?癰궰??(RAX=0 ... R15=15)
    pub fn reg_to_vreg(reg: Register) -> Option<MicroOperand> {
        // High-byte registers (AH/BH/CH/DH ??bits 8..15) are not representable in
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

    /// x86 32??쑵??GPR(op0)??筌뤴뫗?삼쭪?嚥??怨뺣뮉 筌뤿굝議?????怨몄맄 32??쑵?껆몴?0??곗쨮 ?類ｂ봺??뺣뼄.
    /// (x86 域뱀뮇?? 32??쑵???????쎄숲 ?怨뚮┛??64??쑵???????쎄숲???怨몄맄 ??덉뺘??0??곗쨮 筌띾슢諭??)
    /// ?遺욧퐣?紐꾨뻻??? ?怨쀭뀱??野껉퀗??`dst`??`AND dst, 0xFFFFFFFF` 嚥?筌띾뜆???釉??
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

    /// 筌롫뗀?덄뵳??醫륁뒞 雅뚯눘???④쑴沅??RISC 筌띾뜆???以??怨쀪텦??곗쨮 ?브쑵鍮?
    /// `addr = base + index*scale + disp`
    pub fn lower_effective_address(&mut self, inst: &Instruction, temp_dst: MicroOperand) -> Result<()> {
        let base_reg = inst.memory_base();
        let idx_reg = inst.memory_index();
        let scale = inst.memory_index_scale();
        let disp = inst.memory_displacement64();

        // P2 (G3): RIP-relative addressing — x86의 `[rip+disp32]`는 **다음 명령
        // 주소**(inst.ip() + inst.len()) + disp32 가 피연산자의 절대 주소다.
        // 패킹 후 데이터 섹션(.rdata/.data/.rodata)은 원본 RVA를 그대로 유지하므로
        // 소스 절대 VA를 즉시값으로 박으면 런타임 주소와 일치한다.
        //
        // ⚠ P2 (G3) 최종 BISECT: 이 lift로 새로 가상화된 블록이 현재 타깃에서
        // 네이티브 self-decoding 디스패처의 keystream 불일치로 크래시(0xC0000005,
        // MemoryRead 핸들러가 결정적으로 가비지 주소 0x28006b46d deref)를 일으킨다.
        // 규명·수정한 것: (1) h_nop 미등록 폭별 ALU 핸들러 no-op 버그 → 5종 20개
        // 핸들러 구현. (2) 함수 원자성(.pdata) 시도 — 커버리지 절반으로 하락+크래시
        // 미해소로 revert. (3) 양-즉시 AddWithCarry는 차등 테스트로 정상 확인.
        // 남은 원인: 가상화 블록이 제외 함수 **꼬리**를 네이티브 브리지로 호출하는
        // 경계 문제 또는 네이티브 디스패처의 특정 op keystream 소비 차이 — 후속 P2.
        // 안전을 위해 **게이트**한다. (진단 [P2-RISC-GAP]이 갭을 계속 노출.)
        if base_reg == Register::RIP {
            return Err(anyhow!("risc lifter: RIP-relative addressing (P2 gap, gated)"));
        }

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

    /// ADD/SUB/XOR/AND/OR ???????쎄숲夷뚳쭖遺얇걟??猷뱀ケ????깅염?怨쀬쁽 ?⑤벏??筌ｌ꼶??
    /// op0揶쎛 筌롫뗀?덄뵳???read-modify-write, op0揶쎛 ?????쎄숲筌?op1(筌롫뗀?덄뵳?揶쎛?????酉釉??

    pub fn lift_instruction(&mut self, inst: &Instruction) -> Result<()> {
        let code = inst.code();

        match code {
            // P2 (G3): NOP / Pause — 무연산. RISC micro-op을 만들지 않아
            // 커버리지를 높이고(코드베이스 NOP/멀티바이트 NOP 다수) 실행 의미도
            // 그대로다. (Pause는 스핀 루프 힌트일 뿐 단일 스레드 의미론 무연산.)
            Code::Nopw | Code::Nopd | Code::Nop_rm16 | Code::Nop_rm32 | Code::Nop_rm64 | Code::Pause => {}
            // ???? MOV ?④쑴肉?????????????????????????????????????????????????????????????????????????????????????????????????????????????????
            Code::Mov_r64_rm64 | Code::Mov_r32_rm32 | Code::Mov_r16_rm16 | Code::Mov_r8_rm8 => {
                let dst = Self::reg_to_vreg(inst.op0_register()).ok_or_else(|| anyhow!("invalid dst"))?;
                if inst.op1_kind() == OpKind::Register {
                    let src = Self::reg_to_vreg(inst.op1_register()).ok_or_else(|| anyhow!("invalid src"))?;
                    self.desynth.instrs.push(
                        MicroInstr::new(RiscOp::Mov).with_dst(dst).with_src1(src),
                    );
                    self.zero_extend_dst_if32(inst, dst);
                    // 8/16-bit dest: zero-extend into the 64-bit vreg (matches the
                    // bytecode model and MOVZX ??a full copy would leak upper bits).
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
                self.lower_effective_address(inst, dst)?;
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
                self.desynth.instrs.push(MicroInstr::new(RiscOp::Halt));
            }
            // RET imm16: RSP += imm ??Halt.
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

mod tests {
    use super::*;
    use crate::vm::risc::{RiscEvalState, RiscProgram};
    use iced_x86::{Decoder, DecoderOptions};
    use iced_x86::{BlockEncoder, BlockEncoderOptions, Instruction, InstructionBlock};
    use std::collections::HashMap;

    /// 獄쏅뗄???甕곌쑵?곭몴??귐뗫늄??뉖릭?????뮞-IP ???紐껊쑔??筌띾벊??筌ｂ뫀????袁⑥쨮域밸챶???筌띾슢諭??
    /// (?브쑨由???繹먭퍔??eval_state??VIP ?紐껊쑔??살쨮 癰궰??묐릭疫??袁る맙.)
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

    /// A: CALL ??RET ?類ｋ궗. call??癰귣벀? 雅뚯눘??next_ip)???紐꾨뻻??랁?callee嚥??브쑨由?
    /// callee ??쎈뻬 ??ret(Halt)揶쎛 癰귣벀? 雅뚯눘?쇘몴???쎄문????ｋ┸??
    #[test]
    fn test_lift_call_ret_roundtrip() {
        // 0x140001000: call 0x140001014  (E8 rel32)
        // 0x140001005: mov rcx, 1        (fallthrough, 沃섎챷???
        // 0x14000100C: mov rdx, 2        (沃섎챷???
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
        // callee ??쎈뻬
        assert_eq!(regs(&st)[3], 7, "rbx set in callee");
        // call ??꾩뜎 fallthrough 沃섎챷???
        assert_eq!(regs(&st)[1], 0, "rcx not executed");
        assert_eq!(regs(&st)[2], 0, "rdx not executed");
        // ??쎄문 筌ㅼ뮇湲??= call??癰귣벀? 雅뚯눘??(0x140001005)
        assert_eq!(st.stack.len(), 1, "one return address pushed");
        assert_eq!(st.stack[0], 0x140001005, "return address = call.next_ip");
    }

    /// A(揶쏄쑴??: Call_rm64 ??push 癰귣벀? 雅뚯눘??+ 揶쏄쑴???브쑨由??????쎄숲 揶?.
    #[test]
    fn test_lift_call_indirect_register() {
        // rax = callee 雅뚯눘?쇗에??λ뜃由??
        // 0x140001000: call rax   (FF D0)
        // 0x140001002: mov rcx, 9  (沃섎챷???
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

        // JNE taken (opcode 75): rax != rbx ??branch taken
        let mut raw_jne = raw_je;
        raw_jne[3] = 0x75;
        let st3 = run(&raw_jne, 0x140001000, init2);
        assert_eq!(regs(&st3)[1], 0, "JNE taken: rcx skipped");
        assert_eq!(regs(&st3)[2], 2, "JNE taken: rdx reached");
    }

    /// B + C: CMP ??JG (signed) taken / not-taken.
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

        // JG not-taken: 3 < 5 (negative result ??SF=1, OF=0 ??not greater)
        let mut init2 = [0u64; 16];
        init2[0] = 3;
        init2[3] = 5;
        let st2 = run(&raw, 0x140001000, init2);
        assert_eq!(regs(&st2)[1], 1, "JG not-taken: rcx executed");
        assert_eq!(regs(&st2)[2], 0, "JG not-taken: rdx not reached");
    }

    /// D: 筌롫뗀?덄뵳???깅염?怨쀬쁽 ?怨쀫떊 (read-modify-write + reg?由멷m).
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

    /// E: SHL/SHR ??쀫늄??
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

    /// F: MOVZX 0-?類ㅼ삢.
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

    /// SAR (?怨쀫떊 ?怨쀫? ??쀫늄??: ???땾 揶쏅?? ?봔????쑵?껃첎? ?醫???뺣뼄.
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

    /// MOVSX (?봔???類ㅼ삢): 8/16-bit ???뮞???봔???類ㅼ삢.
    #[test]
    fn test_lift_movsx_sign_extension() {
        // 0x140001000: movsx rax, al   (al = 0xFF ??-1)
        // 0x140001003: movsx rax, bx   (bx = 0x8000 ??-32768)
        // 0x140001007: ret
        let raw = [
            0x48, 0x0F, 0xBE, 0xC0, // movsx rax, al
            0x48, 0x0F, 0xBF, 0xC3, // movsx rax, bx
            0xC3,
        ];
        let mut init = [0u64; 16];
        init[0] = 0xFF; // al = 0xFF ??sign-extend ??-1
        init[3] = 0x8000; // bx = 0x8000 ??-32768
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0] as i64, -32768, "movsx sign-extends 16-bit");
    }

    /// JP/JNP: ??ㅲ봺?????삋域밸챷肉??怨뺚뀲 ?브쑨由?
    #[test]
    fn test_lift_jp_jnp_parity() {
        // cmp al, 3 (0b11 ??1??揶쏆뮇??2 ??筌욎빘????PF=1) ; jp 0x14000100B ; ret
        // 0x14000100B: mov rbx, 7
        // 0x140001000: cmp rax,3 (4B: 48 83 F8 03)  0x140001004: jp +1 ??0x140001007 (mov rbx,7 ??뽰삂)
        // 3 - 3 = 0 ??low byte 0b0 (0 ones, even) ??PF=1 ??JP taken.
        let raw_jp = [
            0x48, 0x83, 0xF8, 0x03, // cmp rax, 3
            0x7A, 0x01,             // jp +1 ??0x140001007
            0xC3,                   // ret (0x140001006) ??沃섎챷???
            0x48, 0xC7, 0xC3, 0x07, 0x00, 0x00, 0x00, // mov rbx, 7 (0x140001007)
            0xC3,
        ];
        let mut init = [0u64; 16];
        init[0] = 3;
        let st = run(&raw_jp, 0x140001000, init);
        assert_eq!(regs(&st)[3], 7, "JP taken when parity even (PF set)");

    }

    /// JECXZ: ECX==0 ?????브쑨由?
    #[test]
    fn test_lift_jrcxz_counter_jump() {
        // 0x140001000: jrcxz +8 ??0x14000100A (mov rbx,7 ??뽰삂); 0x140001002 mov rbx,1; 0x140001009 ret
        // 64??쑵??筌뤴뫀諭?癒?퐣 E3??JRCXZ (RCX==0). 燁삳똻????브쑨由?嚥≪뮇彛?野꺜筌앹빘??
        let raw = [
            0xE3, 0x08, // jrcxz +8 ??0x14000100A
            0x48, 0xC7, 0xC3, 0x01, 0x00, 0x00, 0x00, // mov rbx, 1
            0xC3,
            0x48, 0xC7, 0xC3, 0x07, 0x00, 0x00, 0x00, // mov rbx, 7 (0x14000100A)
            0xC3,
        ];
        // RCX == 0 ??taken
        let st = run(&raw, 0x140001000, [0u64; 16]);
        assert_eq!(regs(&st)[3], 7, "JRCXZ taken when RCX==0");
        // RCX != 0 ??not taken
        let mut init = [0u64; 16];
        init[1] = 5;
        let st2 = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st2)[3], 1, "JRCXZ not taken when RCX!=0");
    }

    /// ?類? unsigned ?브쑨由? JA(CF=0?弛쯊=0) vs JAE(CF=0) ??揶쏆늿????筌△뫁??野꺜筌?
    #[test]
    fn test_lift_ja_jae_unsigned_boundary() {
        // cmp rax, rbx (rax==rbx ??ZF=1, CF=0)
        // ja 0x14000100D ??not taken (ZF=1)
        // jae 0x14000100D ??taken (CF=0)
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
        // JA(Above): ZF=1 ???嚥?not taken ??rcx=1 ??쎈뻬
        assert_eq!(regs(&st)[1], 1, "JA not taken when operands equal (ZF=1)");
        assert_eq!(regs(&st)[2], 0, "JA target not reached");
    }

    /// JBE(CF=1 ??ZF=1): 揶쏆늿????CF=0, ZF=1) taken.
    #[test]
    fn test_lift_jbe_unsigned_boundary() {
        // cmp rax, rbx (rax==rbx ??ZF=1, CF=0)
        // jbe 0x14000100D ??taken (ZF=1)
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

    /// ?袁⑥쨮嚥≪뮄?/?癒곕툡嚥≪뮄?? push rbp; mov rbp,rsp ... leave; ret.
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

    /// 32??쑵???????쎄숲 ?怨뚮┛ zero-extension: mov eax + add eax ???怨몄맄 32??쑵?껆몴?0??곗쨮.
    /// `add eax, ebx`(ebx=1)??64??쑵?껅에?뺣뮉 0x100000000(??쑵??32 ?紐낅샒)?????筌?x86?? 0??곗쨮 揶쏅Ŋ???
    #[test]
    fn test_lift_32bit_write_zero_extends_upper_bits() {
        // 0x140001000: mov eax, 0xFFFFFFFF   (B8 FF FF FF FF)
        // 0x140001005: add eax, ebx          (01 D8)  ??ebx = 1 (?????쎄숲 ???뮞)
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

    /// 32??쑵???????쎄숲 ??猷??zero-extension: mov eax, ebx ??RBX????륁맄 32??쑵?껓쭕??띯뫂釉??
    /// ?怨몄맄 32??쑵?껆몴?0??곗쨮 ?類ｂ봺??뺣뼄.
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

    /// 32??쑵????쀫늄????쏅땾??mod 32(31 筌띾뜆???: shl eax,32 == shl eax,0, sar eax,32 == sar eax,0.
    /// ?????쎄숲(CL) 燁삳똻???32??0??곗쨮 筌띾뜆???留??
    #[test]
    fn test_lift_32bit_shift_count_masked_mod32() {
        let mut init = [0u64; 16];
        init[0] = 0x8000_0000; // bit 31 set

        // shl eax, 32 (C1 E0 20) ??count 32 ??masked to 0
        let raw_shl = [0xC1, 0xE0, 0x20, 0xC3]; // shl eax,32 ; ret
        let st = run(&raw_shl, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0x8000_0000, "shl eax,32 == shl eax,0");
        assert_eq!(
            regs(&st)[0] & 0xFFFF_FFFF_0000_0000,
            0,
            "32-bit shift result is zero-extended"
        );

        // sar eax, 32 (C1 F8 20) ??count 32 ??masked to 0
        let raw_sar = [0xC1, 0xF8, 0x20, 0xC3]; // sar eax,32 ; ret
        let st2 = run(&raw_sar, 0x140001000, init);
        assert_eq!(regs(&st2)[0], 0x8000_0000, "sar eax,32 == sar eax,0");

        // ?????쎄숲 燁삳똻??? shl eax, cl with cl=32 ??masked to 0
        let raw_shl_cl = [0xD3, 0xE0, 0xC3]; // shl eax, cl ; ret
        let mut init2 = [0u64; 16];
        init2[0] = 0x8000_0000;
        init2[1] = 32; // cl = 32 (??륁맄 8??쑵??
        let st3 = run(&raw_shl_cl, 0x140001000, init2);
        assert_eq!(regs(&st3)[0], 0x8000_0000, "shl eax,cl(32) == shl eax,0");
    }

    // ???? P2: ??덉쨮 ?곕떽????귐뗫늄??野껋럥以?筌△뫀踰?野꺜筌?(?醫륁굨 ?됰뗀以???μ맄 ??덊뒄) ????????????????????????????

    /// MUL r64 ??RDX:RAX = RAX * rm (unsigned). low ??dst(RAX), high ??RDX.
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

    /// IMUL r64,r64 (2-op) ??dst = low(src1*src2).
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

    /// IMUL r64,r64,imm8 (3-op) ??dst = src*imm.
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

    /// DIV r64 ??RDX:RAX / rm ??RAX=quotient, RDX=remainder.
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

    /// IDIV r64 ??signed divide.
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

    /// BSWAP r64 ??byte order reversal.
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

    /// BSF / BSR ??least/most-significant set bit index.
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

    /// SETcc ??flag-conditional byte write (equal ??SETE=1, SETNE=0).
    #[test]
    fn test_lift_setcc() {
        // cmp rax, rbx (48 39 D8) ; sete al (0F 94 C0) ; setne bl (0F 95 C3) ; ret
        let raw = [0x48, 0x39, 0xD8, 0x0F, 0x94, 0xC0, 0x0F, 0x95, 0xC3, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 5;
        init[3] = 5;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0] & 0xFF, 1, "SETE when equal");
        assert_eq!(regs(&st)[3] & 0xFF, 0, "SETNE when equal ??0");
    }

    /// CMOVcc ??conditional move (equal ??CMOVE takes).
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

    /// TEST ??AND flags without writing a destination.
    #[test]
    fn test_lift_test() {
        // test rax, rbx (48 85 D8) ; ret
        let raw = [0x48, 0x85, 0xD8, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0;
        init[3] = 0;
        let st = run(&raw, 0x140001000, init);
        assert_ne!(st.flags & crate::vm::risc::flags::VFLAG_ZF, 0, "TEST 0&0 ??ZF");
        // nonzero result ??ZF clear
        let mut init2 = [0u64; 16];
        init2[0] = 0xF0;
        init2[3] = 0xF0;
        let st2 = run(&raw, 0x140001000, init2);
        assert_eq!(st2.flags & crate::vm::risc::flags::VFLAG_ZF, 0, "TEST F0&F0 ??!ZF");
    }

    /// XCHG r64,r64 ??register swap.
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

    /// XADD r64,r64 ??dst += src; src = old dst.
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

    /// INC / DEC ??width-masked register forms (INC preserves CF).
    #[test]
    fn test_lift_inc_dec() {
        // inc eax (FF C0) ; dec rax (48 FF C8) ; ret
        let raw = [0xFF, 0xC0, 0x48, 0xFF, 0xC8, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 5;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 5, "inc eax(5??) then dec rax(6??)");
    }

    /// RET imm16 ??RSP += imm before Halt.
    #[test]
    fn test_lift_ret_imm16() {
        // 0x140001000: ret 8 (C2 08 00)
        let raw = [0xC2, 0x08, 0x00];
        let st = run(&raw, 0x140001000, [0u64; 16]);
        assert_eq!(regs(&st)[4], 8, "RET imm16 advances RSP by 8");
    }

    /// PUSH r64 / POP r64 ??stack roundtrip.
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

    /// CMPXCHG (mem form) ??lift path emits CompareExchange micro-op.
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

    /// XCHG mem?遊켩g ??lift path emits memory RMW (read + write).
    #[test]
    fn test_lift_xchg_mem() {
        // xchg [rax], rbx (48 87 18) ; ret
        let raw = [0x48, 0x87, 0x18, 0xC3];
        let prog = lift(&raw, 0x140001000);
        let has_rd = prog.instrs.iter().any(|i| matches!(i.op, RiscOp::MemoryRead { .. }));
        let has_wr = prog.instrs.iter().any(|i| matches!(i.op, RiscOp::MemoryWrite { .. }));
        assert!(has_rd && has_wr, "XCHG mem lifts to memory RMW");
    }

    /// XADD (mem form) ??lift path emits memory RMW.
    #[test]
    fn test_lift_xadd_mem() {
        // xadd [rax], rbx (48 0F C1 18) ; ret
        let raw = [0x48, 0x0F, 0xC1, 0x18, 0xC3];
        let prog = lift(&raw, 0x140001000);
        let has_rd = prog.instrs.iter().any(|i| matches!(i.op, RiscOp::MemoryRead { .. }));
        let has_wr = prog.instrs.iter().any(|i| matches!(i.op, RiscOp::MemoryWrite { .. }));
        assert!(has_rd && has_wr, "XADD mem lifts to memory RMW");
    }

    /// BMI1 ANDN ??lift path emits NOT+AND (VEX encoding via BlockEncoder).
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

    // ???? P2: ?얜챷???ops 筌△뫀踰?野꺜筌?(?醫륁굨 ?됰뗀以???μ맄 ??덊뒄) ????????????????????????????????????????????????????

    /// ???뮞??筌롫뗀?덄뵳????? ?귐??遺얜탵??`width`獄쏅뗄???疫꿸퀡以?
    fn seed_mem(mem: &mut HashMap<u64, u8>, addr: u64, width: u8, val: u64) {
        for i in 0..width {
            mem.insert(addr.wrapping_add(i as u64), (val >> (i as u64 * 8)) as u8);
        }
    }

    /// ???뮞??筌롫뗀?덄뵳????? ?귐??遺얜탵??`width`獄쏅뗄?????꾨┛.
    fn read_mem(mem: &HashMap<u64, u8>, addr: u64, width: u8) -> u64 {
        let mut v = 0u64;
        for i in 0..width {
            v |= (*mem.get(&addr.wrapping_add(i as u64)).unwrap_or(&0) as u64) << (i as u64 * 8);
        }
        v
    }

    /// lift + `eval_state_with_mem` ??쎈뻬 ????
    fn run_mem(raw: &[u8], ip: u64, init: [u64; 16], mem: HashMap<u64, u8>) -> RiscEvalState {
        lift(raw, ip).eval_state_with_mem(&init, mem)
    }

    /// BlockEncoder 嚥?x86 筌뤿굝議??됰뗀以??獄쏅뗄??紐껋쨮 ?紐꾪맜??
    fn enc_block(insts: Vec<Instruction>) -> Vec<u8> {
        let blk = InstructionBlock::new(&insts, 0x140001000);
        BlockEncoder::encode(64, blk, BlockEncoderOptions::NONE).unwrap().code_buffer
    }

    /// XMM(i) ????揶쎛??雅뚯눘??(?귐뗫늄?怨? ??덉뵬 ?④쑴鍮?.
    fn xmm_slot(idx: u8) -> u64 {
        super::XMM_SLOT_BASE + (idx as u64) * 16
    }

    /// MOVSB (??μ뵬) ??[rdi]=[rsi]; rsi/rdi += 1.
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

    /// STOSD (??μ뵬) ??[rdi]=EAX; rdi+=4.
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

    /// LODSW (??μ뵬) ??AX = [rsi] (0-?類ㅼ삢); rsi+=2.
    #[test]
    fn test_lift_lodsw_single() {
        let raw = [0x66, 0xAD, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x1122_3344_5566_7788; // RAX upper bits must be PRESERVED
        init[6] = 0x1000;
        let mut mem = HashMap::new();
        seed_mem(&mut mem, 0x1000, 2, 0x7AB9);
        let st = run_mem(&raw, 0x140001000, init, mem);
        // LODSW writes only AX: upper 48 bits of RAX stay intact.
        assert_eq!(st.regs[0], 0x1122_3344_5566_7AB9, "AX written, upper bits preserved");
        assert_eq!(st.regs[6], 0x1002, "rsi advanced by 2");
    }

    /// SCASB (??μ뵬) ??flags = AL - [rdi]; rdi+=1.
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

    /// CMPSQ (??μ뵬) ??flags = [rsi] - [rdi]; rsi+=8; rdi+=8.
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

    /// REP MOVSB ??燁삳똻?????쇱뒲 ?룐뫂遊? rcx ???돩, rsi/rdi += n*count, 筌롫뗀?덄뵳?癰귣벊沅?
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

    /// v65: `std; rep movsb` ??DF=1 ??rsi/rdi DECREMENTED, bytes copied backward.
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

    /// REP STOSB ???룐뫂遊썸에?筌롫뗀?덄뵳?筌?쑴??묾?
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

    /// REP LODSQ ???룐뫂遊썸에?RAX 揶쏄퉮??(筌띾뜆?筌?嚥≪뮆諭?, rsi += 8*count.
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

    /// REPE SCASB ???븍뜆?ょ㎉?뤿퓠??餓λ쵎?? rdi/rcx ??餓λ쵎??獄쏆꼶?ф틦?? 筌욊쑵六? 筌ㅼ뮇伊????삋域?= 筌띾뜆?筌???쑨??
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

    /// REPNE CMPSW ????깊뒄?癒?퐣 餓λ쵎??(REPNE ??ZF=1 ?癒?퐣 ?類?).
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

    // ???? P2: SSE/FPU ??쇰???筌△뫀踰?野꺜筌?????????????????????????????????????????????????????????????????????????????????????

    /// ADDSD xmm0, xmm1 ??1.5 + 2.25 = 3.75.
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

    /// MULSD + DIVSD ??(3.0 * 2.0) / 4.0 = 1.5.
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

    /// SUBSS (f32) ??5.5f32 - 1.25f32 = 4.25f32.
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

    /// CVTSI2SD xmm0, rax ???類ㅻ땾 -> double.
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

    /// CVTTSS2SI(trunc) vs CVTSS2SI(nearest-even) ??half-way 獄쏆꼷?긺뵳?筌△뫁??
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

    /// MOVSD xmm0, xmm1 (?????쎄숲 嚥≪뮆諭??? ????륁맄 8獄쏅뗄???癰귣벊沅?
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

    /// MOVSD [rax], xmm0 (筌롫뗀?덄뵳???쎈꽅?? + MOVSD xmm1, [rax] (筌롫뗀?덄뵳?嚥≪뮆諭?.
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

    // ???? P2: BMI (BLSR/BLSMSK/BLSI/BZHI) 筌△뫀踰?野꺜筌?????????????????????????????????????????????????????????

    /// BLSR r64 ??x & (x-1) (lowest set bit clear).
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

    /// BLSMSK r64 ??x ^ (x-1).
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

    /// BLSI r64 ??x & -x (lowest set bit).
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

    /// BZHI r64, r/m64, r64 ??dst = x & ((1<<idx)-1).
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

    // ── R7: 8/16-bit 논리(XOR/AND/OR)·시프트(SHL/SHR)·NEG/NOT ────────────────
    // 참조: 레거시 `vm/lifter/arith.rs::lift_narrow_arith`, `vm/lifter/mod.rs`
    // (Xor_rm8/16, And_rm8/16, Or_rm8/16, Shl_rm8/16, Shr_rm8/16, Neg/Not_rm8/16).
    // 검증 포인트: (a) 8/16비트 결과의 상위 비트 보존(레지스터), (b) 플래그 폭.

    /// R7: 8-bit XOR register (상위 비트 보존).
    #[test]
    fn test_lift_8bit_xor_reg_preserve_upper() {
        // xor al, bl   (0x30 0xD8) — AL=0x5A ^ BL=0x0F = 0x55, 상위 56비트 보존.
        let raw = [0x30, 0xD8, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x1122_3344_5566_775A; // RAX 상위 비트 + AL=0x5A
        init[3] = 0x0000_0000_0000_000F; // BL = 0x0F
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0x1122_3344_5566_7755, "XOR AL low byte, upper preserved");
    }

    /// R7: 16-bit AND register (상위 비트 보존).
    #[test]
    fn test_lift_16bit_and_reg_preserve_upper() {
        // and ax, bx  (0x66 0x21 0xD8) — AX = 0x7FFF & 0x0F0F = 0x0F0F.
        let raw = [0x66, 0x21, 0xD8, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x1122_3344_5566_7FFF;
        init[3] = 0x0000_0000_0000_0F0F;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0x1122_3344_5566_0F0F, "AND AX low word, upper preserved");
    }

    /// R7: 8-bit OR immediate (AL = AL | 0x0F).
    #[test]
    fn test_lift_8bit_or_imm() {
        // or al, 0x0F  (0x0C 0x0F) — AL = 0x10 | 0x0F = 0x1F.
        let raw = [0x0C, 0x0F, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x1122_3344_5566_7710;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0x1122_3344_5566_771F, "OR AL imm");
    }

    /// R7: 8/16-bit XOR memory RMW (레지스터 피연산자 마스킹).
    #[test]
    fn test_lift_8bit_xor_mem_rmw() {
        // xor byte ptr [rbx], al  (0x30 0x03) — [0x1000] ^= AL.
        let raw = [0x30, 0x03, 0xC3];
        let mut init = [0u64; 16];
        init[3] = 0x1000;
        init[0] = 0x0000_0000_0000_000F; // AL = 0x0F
        let mut mem = HashMap::new();
        mem.insert(0x1000, 0x51);
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(st.mem.get(&0x1000), Some(&0x5E), "mem byte ^= AL");
    }

    /// R7: 8-bit SHL register (카운트 mod 8 경계 + 상위 보존).
    #[test]
    fn test_lift_8bit_shl_reg() {
        // shl al, 2  (0xC0 0xE0 0x02) — AL = 0x40 << 2 = 0x00 (8-bit wrap).
        let raw = [0xC0, 0xE0, 0x02, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x1122_3344_5566_7740;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0x1122_3344_5566_7700, "SHL AL,2 = 0x00, upper preserved");
    }

    /// R7: 16-bit SHR register (상위 워드 0, 상위 비트 보존).
    #[test]
    fn test_lift_16bit_shr_reg() {
        // shr ax, 4  (0x66 0xC1 0xE8 0x04) — AX = 0x8000 >> 4 = 0x0800.
        let raw = [0x66, 0xC1, 0xE8, 0x04, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x1122_3344_5566_8000;
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0x1122_3344_5566_0800, "SHR AX,4");
    }

    /// R7: 8/16-bit NEG/NOT (플래그 + 상위 보존).
    #[test]
    fn test_lift_8bit_neg_not() {
        // neg al (0xF6 0xD8); not al (0xF6 0xD0)
        let raw = [0xF6, 0xD8, 0xF6, 0xD0, 0xC3];
        let mut init = [0u64; 16];
        init[0] = 0x1122_3344_5566_7701; // AL = 1 → NEG = 0xFF → NOT = 0x00
        let st = run(&raw, 0x140001000, init);
        assert_eq!(regs(&st)[0], 0x1122_3344_5566_7700, "NEG then NOT AL");
    }

    /// R7: 16-bit NEG memory (부호 반전 + 메모리 폭 쓰기).
    #[test]
    fn test_lift_16bit_neg_mem() {
        // neg word ptr [rbx]  (0x66 0xF7 0x1B) — [0x1000] = -0x0010 = 0xFFF0.
        let raw = [0x66, 0xF7, 0x1B, 0xC3];
        let mut init = [0u64; 16];
        init[3] = 0x1000;
        let mut mem = HashMap::new();
        mem.insert(0x1000, 0x10);
        mem.insert(0x1001, 0x00);
        let st = run_mem(&raw, 0x140001000, init, mem);
        let mut v = 0u64;
        for i in 0..2 {
            v |= (*st.mem.get(&(0x1000 + i)).unwrap_or(&0) as u64) << (i * 8);
        }
        assert_eq!(v, 0xFFF0, "NEG word [mem] = 0xFFF0");
    }

    // ── P1 (②): packed SSE — XMM 슬롯 기반 128-bit 정수 연산 ───────────────────
    // lifter → `eval_state`(참조) 실행. 검증 포인트:
    // (a) 요소 단위 연산 (PADDQ 에서 lane 간 캐리 미전파 — 보고서 ② 핵심),
    // (b) RFLAGS 불변 (packed 정수 연산은 x86 에서도 플래그를 안 바꾼다),
    // (c) 메모리 소스/대상 폼.

    /// 16바이트 시드 (하위 8B + 상위 8B).
    fn seed_slot(mem: &mut HashMap<u64, u8>, addr: u64, lo: u64, hi: u64) {
        seed_mem(mem, addr, 8, lo);
        seed_mem(mem, addr + 8, 8, hi);
    }

    fn read_slot(mem: &HashMap<u64, u8>, addr: u64) -> (u64, u64) {
        (read_mem(mem, addr, 8), read_mem(mem, addr + 8, 8))
    }

    /// PADDQ lane 경계 — lane 0 이 캐리를 만들면 lane 1 로 **전파되지 않아야** 한다.
    /// (64-bit add 로 분해했다면 캐리가 전파되어 틀렸을 케이스)
    #[test]
    fn test_lift_paddq_no_lane_carry() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Paddq_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        // xmm0.lane0 = 0xFFFF_FFFF_FFFF_FFFF, xmm0.lane1 = 0x11
        seed_slot(&mut mem, xmm_slot(0), 0xFFFF_FFFF_FFFF_FFFF, 0x11);
        // xmm1.lane0 = 1, xmm1.lane1 = 0x22
        seed_slot(&mut mem, xmm_slot(1), 1, 0x22);
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        let (lo, hi) = read_slot(&st.mem, xmm_slot(0));
        assert_eq!(lo, 0, "lane0 wraps: 0xFFFF.. + 1 = 0");
        assert_eq!(hi, 0x33, "lane1 = 0x11 + 0x22 (no carry from lane0)");
    }

    /// PADDD 4× 32-bit 요소 단위 가산.
    #[test]
    fn test_lift_paddd_lanes() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Paddd_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        // seed_slot 은 little-endian → dword lane0=bytes0-3, lane1=bytes4-7...
        // xmm0: lane0=0x10, lane1=0xFFFF_FFFF, lane2=0x30, lane3=0xFFFF_FFFF
        seed_slot(&mut mem, xmm_slot(0), 0xFFFF_FFFF_0000_0010, 0xFFFF_FFFF_0000_0030);
        // xmm1: lane0=0x20, lane1=0x1, lane2=0x40, lane3=0x2
        seed_slot(&mut mem, xmm_slot(1), 0x0000_0001_0000_0020, 0x0000_0002_0000_0040);
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        let (lo, hi) = read_slot(&st.mem, xmm_slot(0));
        // lane0=0x30, lane1=0xFFFF_FFFF+1=0 (wrap, no carry to lane2)
        assert_eq!(lo, 0x0000_0000_0000_0030, "dword lanes wrap independently");
        // lane2=0x70, lane3=0xFFFF_FFFF+2=1
        assert_eq!(hi, 0x0000_0001_0000_0070, "dword lanes wrap independently");
    }

    /// PADDB — 16× 8-bit 요소 가산 (각 바이트 랩).
    #[test]
    fn test_lift_paddb_lanes() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Paddb_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        seed_slot(&mut mem, xmm_slot(0), 0xFF_FF_FF_FF_FF_FF_FF_FF, 0x01_01_01_01_01_01_01_01);
        seed_slot(&mut mem, xmm_slot(1), 0x01_01_01_01_01_01_01_01, 0x01_01_01_01_01_01_01_01);
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        let (lo, hi) = read_slot(&st.mem, xmm_slot(0));
        assert_eq!(lo, 0, "8-bit lanes wrap: 0xFF+1 = 0");
        assert_eq!(hi, 0x02_02_02_02_02_02_02_02, "8-bit lanes add");
    }

    /// PSUBQ 요소 단위 감산.
    #[test]
    fn test_lift_psubq() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Psubq_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        seed_slot(&mut mem, xmm_slot(0), 0x10, 0xFFFF_FFFF_FFFF_FFFF);
        seed_slot(&mut mem, xmm_slot(1), 0x20, 0x1);
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        let (lo, hi) = read_slot(&st.mem, xmm_slot(0));
        assert_eq!(lo, 0xFFFF_FFFF_FFFF_FFF0, "lane0: 0x10 - 0x20 wraps");
        assert_eq!(hi, 0xFFFF_FFFF_FFFF_FFFE, "lane1: 0xFFFF.. - 1");
    }

    /// PXOR / PAND / POR / PANDN 16바이트 비트열 연산.
    #[test]
    fn test_lift_packed_logic() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Pxor_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with2(Code::Pand_xmm_xmmm128, Register::XMM2, Register::XMM1).unwrap(),
            Instruction::with2(Code::Por_xmm_xmmm128, Register::XMM3, Register::XMM1).unwrap(),
            Instruction::with2(Code::Pandn_xmm_xmmm128, Register::XMM4, Register::XMM1).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        // xmm0 = 0x0F0F..., xmm1 = 0xFF00...
        seed_slot(&mut mem, xmm_slot(0), 0x0F0F_0F0F_0F0F_0F0F, 0x0F0F_0F0F_0F0F_0F0F);
        seed_slot(&mut mem, xmm_slot(1), 0xFF00_FF00_FF00_FF00, 0xFF00_FF00_FF00_FF00);
        // xmm2 = 0xAAAA..., xmm3 = 0x5555..., xmm4 = 0xFFFF...
        seed_slot(&mut mem, xmm_slot(2), 0xAAAA_AAAA_AAAA_AAAA, 0xAAAA_AAAA_AAAA_AAAA);
        seed_slot(&mut mem, xmm_slot(3), 0x5555_5555_5555_5555, 0x5555_5555_5555_5555);
        seed_slot(&mut mem, xmm_slot(4), 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF);
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        let (x0lo, _) = read_slot(&st.mem, xmm_slot(0));
        let (x2lo, _) = read_slot(&st.mem, xmm_slot(2));
        let (x3lo, _) = read_slot(&st.mem, xmm_slot(3));
        let (x4lo, _) = read_slot(&st.mem, xmm_slot(4));
        assert_eq!(x0lo, 0x0F0F_0F0F_0F0F_0F0F ^ 0xFF00_FF00_FF00_FF00, "PXOR bytewise");
        assert_eq!(x2lo, 0xAAAA_AAAA_AAAA_AAAA & 0xFF00_FF00_FF00_FF00, "PAND bytewise");
        assert_eq!(x3lo, 0x5555_5555_5555_5555 | 0xFF00_FF00_FF00_FF00, "POR bytewise");
        assert_eq!(x4lo, 0xFFFF_FFFF_FFFF_FFFF & !0xFF00_FF00_FF00_FF00, "PANDN = a & ~b");
    }

    /// PCMPEQD — 요소 단위 등가: 같으면 전-1, 다르면 0.
    #[test]
    fn test_lift_pcmpeqd() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Pcmpeqd_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut mem = HashMap::new();
        // lane0: 0x11111111 == lane0 of src; lane1: 0x22222222 != 0x33333333
        seed_slot(&mut mem, xmm_slot(0), 0x2222_2222_1111_1111, 0);
        seed_slot(&mut mem, xmm_slot(1), 0x3333_3333_1111_1111, 0x4444_4444_4444_4444);
        let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
        let (lo, _) = read_slot(&st.mem, xmm_slot(0));
        // lane0 == -> 0xFFFF_FFFF, lane1 != -> 0
        assert_eq!(lo, 0x0000_0000_FFFF_FFFF, "PCMPEQD equal lane all-ones, diff lane 0");
    }

    /// MOVDQU — XMM ↔ 메모리 16바이트 이동 (load + store).
    #[test]
    fn test_lift_movdqu_mem_load_store() {
        let raw = enc_block(vec![
            Instruction::with2(
                Code::Movdqu_xmmm128_xmm,
                iced_x86::MemoryOperand::with_base(Register::RAX),
                Register::XMM0,
            )
            .unwrap(),
            Instruction::with2(
                Code::Movdqu_xmm_xmmm128,
                Register::XMM1,
                iced_x86::MemoryOperand::with_base(Register::RAX),
            )
            .unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut init = [0u64; 16];
        init[0] = 0x5000;
        let mut mem = HashMap::new();
        seed_slot(&mut mem, xmm_slot(0), 0xDEAD_BEEF_CAFE_1234, 0x1122_3344_5566_7788);
        let st = run_mem(&raw, 0x140001000, init, mem);
        assert_eq!(read_slot(&st.mem, 0x5000), (0xDEAD_BEEF_CAFE_1234, 0x1122_3344_5566_7788), "stored 16B to mem");
        assert_eq!(read_slot(&st.mem, xmm_slot(1)), (0xDEAD_BEEF_CAFE_1234, 0x1122_3344_5566_7788), "loaded 16B back to xmm1");
    }

    /// PADDD xmm0, [rax] — 메모리 소스 폼 (유효주소에서 16바이트 읽기).
    #[test]
    fn test_lift_paddd_mem_src() {
        let raw = enc_block(vec![
            Instruction::with2(
                Code::Paddd_xmm_xmmm128,
                Register::XMM0,
                iced_x86::MemoryOperand::with_base(Register::RAX),
            )
            .unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let mut init = [0u64; 16];
        init[0] = 0x5000;
        let mut mem = HashMap::new();
        // xmm0: lane0=2, lane1=1, lane2=4, lane3=3
        seed_slot(&mut mem, xmm_slot(0), 0x0000_0001_0000_0002, 0x0000_0003_0000_0004);
        // mem:   lane0=0xB, lane1=0xA, lane2=0xD, lane3=0xC
        seed_slot(&mut mem, 0x5000, 0x0000_000A_0000_000B, 0x0000_000C_0000_000D);
        let st = run_mem(&raw, 0x140001000, init, mem);
        let (lo, hi) = read_slot(&st.mem, xmm_slot(0));
        assert_eq!(lo, 0x0000_000B_0000_000D, "lane0+mem0=0xD, lane1+mem1=0xB");
        assert_eq!(hi, 0x0000_000F_0000_0011, "lane2+mem2=0x11, lane3+mem3=0xF");
    }

    /// packed SSE lift 는 RiscOp::Packed* 를 만들고 SetFlag 를 만들지 않는다.
    #[test]
    fn test_lift_packed_no_flag_write() {
        let raw = enc_block(vec![
            Instruction::with2(Code::Paddd_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with2(Code::Movdqu_xmm_xmmm128, Register::XMM2, Register::XMM3).unwrap(),
            Instruction::with(Code::Retnq),
        ]);
        let prog = lift(&raw, 0x140001000);
        let packed = prog.instrs.iter().filter(|i| matches!(i.op, RiscOp::PackedAdd { .. } | RiscOp::PackedMove)).count();
        let flag_writes = prog.instrs.iter().filter(|i| matches!(i.op, RiscOp::SetFlag)).count();
        assert_eq!(packed, 2, "PADDD + MOVDQU lifted to Packed ops");
        assert_eq!(flag_writes, 0, "packed integer ops never write RFLAGS");
    }
}