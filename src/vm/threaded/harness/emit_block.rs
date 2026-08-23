// ==============================================================================
// BTG - Direct-Threaded Native Harness: per-opcode block emitter - split from harness.rs
// ==============================================================================

use super::cond_helpers::{cond_to_cmov_code, cond_to_setcc_code};
use super::layout::{FLAGS_OFF, FLAG_MASK, REGS_OFF, TEMPS_OFF, VSP_OFF};
use super::NativeVmHarness;
use crate::vm::risc::{BranchCondition, MicroInstr, MicroOperand, RiscOp};
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, Register};

impl NativeVmHarness {
    /// ?占쎌씪 留덉씠?占쎈줈 ?占쎌궛???占쎈Ц???占쎌씠?占쎈툕 釉붾줉???占쎌꽦?占쎈떎.
    /// `block_index` = ??釉붾줉??紐낅졊 ?占쎈뜳??(遺꾧린 fallthrough ?占쏙옙?= index+1).
    /// `static_target` = ?占쎌쟻 VirtualBranch ??紐⑺몴 釉붾줉 ?占쎈뜳??(?占쎌쟻?占쎈㈃ None).
    /// `helper_va` = ?占쎌쟻 遺꾧린 ?占쎌틪 ?占쏀띁 二쇱냼 (?占쎌쟻 遺꾧린媛 ?占쎌쑝占?None).
    pub(super) fn emit_block(
        ins: &MicroInstr,
        instrs: &mut Vec<Instruction>,
        state_base: u64,
        bytecode_base: u64,
        block_index: u64,
        static_target: Option<u64>,
        helper_va: Option<u64>,
        mba_prob: u32,
        diversity_seed: u64,
    ) -> Result<()> {
        // ?占쏀깭 踰꾪띁 ?占쎄렐??硫붾え占??占쏀띁?占쎈뱶 ?占쏀띁.
        let mem = |disp: i64| -> iced_x86::MemoryOperand {
            iced_x86::MemoryOperand::with_base_index_scale_displ_size(
                Register::RDX,
                Register::None,
                1,
                disp,
                8,
            )
        };

        let load = |instrs: &mut Vec<Instruction>,
                    op: Option<MicroOperand>,
                    reg: Register|
         -> Result<()> {
            match op {
                Some(MicroOperand::VReg(i)) => {
                    instrs.push(
                        Instruction::with2(
                            Code::Mov_r64_rm64,
                            reg,
                            mem((REGS_OFF + i as usize * 8) as i64),
                        )
                        .map_err(|e| anyhow!("{e}"))?,
                    );
                }
                Some(MicroOperand::Temp(t)) => {
                    instrs.push(
                        Instruction::with2(
                            Code::Mov_r64_rm64,
                            reg,
                            mem((TEMPS_OFF + t as usize * 8) as i64),
                        )
                        .map_err(|e| anyhow!("{e}"))?,
                    );
                }
                Some(MicroOperand::Imm64(v)) => {
                    instrs.push(
                        Instruction::with2(Code::Mov_r64_imm64, reg, v)
                            .map_err(|e| anyhow!("{e}"))?,
                    );
                }
                Some(MicroOperand::Vsp) => {
                    instrs.push(
                        Instruction::with2(Code::Mov_r64_rm64, reg, mem(VSP_OFF as i64))
                            .map_err(|e| anyhow!("{e}"))?,
                    );
                }
                Some(MicroOperand::Vflags) => {
                    instrs.push(
                        Instruction::with2(Code::Mov_r64_rm64, reg, mem(FLAGS_OFF as i64))
                            .map_err(|e| anyhow!("{e}"))?,
                    );
                }
                _ => {
                    instrs.push(
                        Instruction::with2(Code::Xor_r64_rm64, reg, reg)
                            .map_err(|e| anyhow!("{e}"))?,
                    );
                }
            }
            Ok(())
        };

        let store = |instrs: &mut Vec<Instruction>, dst: Option<MicroOperand>| -> Result<()> {
            match dst {
                Some(MicroOperand::VReg(i)) => {
                    instrs.push(
                        Instruction::with2(
                            Code::Mov_rm64_r64,
                            mem((REGS_OFF + i as usize * 8) as i64),
                            Register::R10,
                        )
                        .map_err(|e| anyhow!("{e}"))?,
                    );
                }
                Some(MicroOperand::Temp(t)) => {
                    instrs.push(
                        Instruction::with2(
                            Code::Mov_rm64_r64,
                            mem((TEMPS_OFF + t as usize * 8) as i64),
                            Register::R10,
                        )
                        .map_err(|e| anyhow!("{e}"))?,
                    );
                }
                _ => {}
            }
            Ok(())
        };

        // ?占쎈옒占??占쎈’???占쎌옱 x86 ?占쎈옒洹몄쓽 CF|ZF|SF|OF 占?蹂묓빀 (PF/AF??蹂댁〈).
        let store_flags = |instrs: &mut Vec<Instruction>| -> Result<()> {
            instrs.push(Instruction::with(Code::Pushfq));
            instrs.push(
                Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::And_rm64_imm32, Register::RAX, FLAG_MASK as u32)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64))
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!FLAG_MASK) as i32)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            Ok(())
        };

        // CF|OF 占??占쎈’??蹂묓빀 (MUL/IMUL ??ZF/SF/PF 蹂댁〈).
        let store_cf_of = |instrs: &mut Vec<Instruction>| -> Result<()> {
            instrs.push(Instruction::with(Code::Pushfq));
            instrs.push(
                Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x801)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64))
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x801i32))
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            Ok(())
        };

        // ZF 占??占쎈’??蹂묓빀 (BSF/BSR).
        let store_zf = |instrs: &mut Vec<Instruction>| -> Result<()> {
            instrs.push(Instruction::with(Code::Pushfq));
            instrs.push(
                Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x40)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64))
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x40i32))
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            Ok(())
        };

        // CF|ZF 蹂묓빀 (TZCNT/LZCNT).
        let store_cf_zf = |instrs: &mut Vec<Instruction>| -> Result<()> {
            instrs.push(Instruction::with(Code::Pushfq));
            instrs.push(
                Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x41)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64))
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x41i32))
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(
                Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX)
                    .map_err(|e| anyhow!("{e}"))?,
            );
            Ok(())
        };

        // ?占쏀깭 ?占쎈’???占쎈옒洹몌옙? ?占쎌젣 x86 ?占쎈옒洹몃줈 蹂듭썝 (setcc/cmovcc/遺꾧린 ?占쎌슜).
        let load_flags_to_hw = |instrs: &mut Vec<Instruction>| -> Result<()> {
            instrs.push(
                Instruction::with1(Code::Push_rm64, mem(FLAGS_OFF as i64))
                    .map_err(|e| anyhow!("{e}"))?,
            );
            instrs.push(Instruction::with(Code::Popfq));
            Ok(())
        };

        // 議곌굔 ?占쏙옙? ??R8L = 0/1. (CounterZero ??regs[1] 寃?? 占????占쎈뱶?占쎌뼱 setcc.)
        let eval_cond = |instrs: &mut Vec<Instruction>, cond: BranchCondition| -> Result<()> {
            if cond == BranchCondition::Always {
                instrs.push(
                    Instruction::with2(Code::Mov_r64_imm64, Register::R8, 1)
                        .map_err(|e| anyhow!("{e}"))?,
                );
                return Ok(());
            }
            load_flags_to_hw(instrs)?;
            if let BranchCondition::CounterZero(width) = cond {
                let mask: u64 = match width {
                    2 => 0xFFFF,
                    4 => 0xFFFF_FFFF,
                    _ => u64::MAX,
                };
                instrs.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::R9,
                        mem((REGS_OFF + 8) as i64),
                    )
                    .map_err(|e| anyhow!("{e}"))?,
                );
                instrs.push(
                    Instruction::with2(Code::And_rm64_imm32, Register::R9, mask as i32)
                        .map_err(|e| anyhow!("{e}"))?,
                );
                instrs.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9)
                        .map_err(|e| anyhow!("{e}"))?,
                );
                instrs.push(
                    Instruction::with1(Code::Sete_rm8, Register::R8L)
                        .map_err(|e| anyhow!("{e}"))?,
                );
            } else {
                let cc = cond_to_setcc_code(cond)
                    .ok_or_else(|| anyhow!("no setcc code for {cond:?}"))?;
                instrs.push(Instruction::with1(cc, Register::R8L).map_err(|e| anyhow!("{e}"))?);
            }
            Ok(())
        };

        match ins.op {
            RiscOp::VirtualIndirectCall | RiscOp::VirtualIndirectJump => {
                return Err(anyhow!(
                    "typed virtual indirect control flow requires route-aware native lowering"
                ));
            }
            RiscOp::Nor => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Not_rm64, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::Mov => {
                load(instrs, ins.src1, Register::R10)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::AddWithCarry => {
                load(instrs, ins.src1, Register::R10)?; // a
                load(instrs, ins.src2, Register::R11)?; // b
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::R11).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with(Code::Pushfq));
                instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                let cin = ins.imm;
                if cin != 0 {
                    if (cin as i8 as u64) == cin {
                        instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::R10, cin as i32).map_err(|e| anyhow!("{e}"))?);
                    } else if (cin as i32 as u64) == cin {
                        instrs.push(Instruction::with2(Code::Add_rm64_imm32, Register::R10, cin as i32).map_err(|e| anyhow!("{e}"))?);
                    } else {
                        instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::R11, cin).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                    }
                    instrs.push(Instruction::with(Code::Pushfq));
                    instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RCX, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                }
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with(Code::Pushfq));
                instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xC4).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                // P0-2: AF(auxiliary carry, bit3 carry) = (a ^ b ^ res) & 0x10 — eval_state
                // update_add64 와 동일. R8=a, R9=b, R10=res; RCX 를 스크래치로 사용.
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Xor_r64_rm64, Register::RCX, Register::R9).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Xor_r64_rm64, Register::RCX, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, 0x10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Xor_rm64_r64, Register::R8, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_r64, Register::R8, Register::R9).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R8, 63).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Shl_rm64_imm8, Register::R8, 11).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::R8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!FLAG_MASK) as i32).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            // P0-1: x86 ?뺥솗 ?뚮옒洹??꾩슜 op ????x86 紐낅졊(??퀎)?쇰줈 emit??李몄“? ?숈튂.
            RiscOp::Add { width } => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                // P1 (④+다양화): ADD 핸들러 MBA — 64-bit 한정, (block_index ^ diversity_seed)
                // 해시로 결정적 확률 선택. variant 0 `(a^b)+(a&b)` 후 `+(a&b)` / variant 1
                // `(a|b)+(a&b)` — 둘 다 플래그(CF/ZF/SF/OF)가 x86 add 와 정확히 동일하다
                // (P0-2 차등 검증: variant 0 의 `(a^b)+2*(a&b)` 는 2*(a&b) 랩 시 CF/OF 가
                // 어긋나 수정). diversity_seed(빌드 키)로 빌드 간 핸들러 코드가 달라진다.
                let mba_hash = (block_index ^ diversity_seed)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32;
                let use_mba = width == 8 && mba_prob > 0
                    && mba_hash % 100 < mba_prob as u64;
                if use_mba {
                    let variant = (mba_hash >> 16) as u32;
                    crate::vm::threaded::inline_mba::InlineMbaObfuscator::emit_mba_add_reg_reg_variant(
                        instrs,
                        Register::R10,
                        Register::R11,
                        Register::R9,
                        Register::RCX,
                        variant,
                    )?;
                    store_flags(instrs)?;
                    store(instrs, ins.dst)?;
                    return Ok(());
                }
                match width {
                    1 => {
                        // RISC op 계약: `Add{width}` 는 eval_state 가 결과를 width 로
                        // 마스킹(상위 제로)한다 (lifter 가 8/16-bit 레지스터 add 에서
                        // 상위 보존을 preserve_upper 로 **별도** 합성). 네이티브 핸들러도
                        // 이 계약을 따라야 하므로 좁은 add 뒤 movzx 로 상위를 제로화한다.
                        // (x86 partial-register 보존은 op 계약이 아니며, P0-2 차등
                        // 테스트가 불일치로 적발.)
                        instrs.push(Instruction::with2(Code::Add_rm8_r8, Register::R10L, Register::R11L).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).map_err(|e| anyhow!("{e}"))?);
                    }
                    2 => {
                        instrs.push(Instruction::with2(Code::Add_rm16_r16, Register::R10W, Register::R11W).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::R10W).map_err(|e| anyhow!("{e}"))?);
                    }
                    4 => {
                        instrs.push(Instruction::with2(Code::Add_rm32_r32, Register::R10D, Register::R11D).map_err(|e| anyhow!("{e}"))?);
                    }
                    _ => {
                        instrs.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                    }
                }
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::SubWithBorrow { width } => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                match width {
                    1 => {
                        // Add{width}와 동일 계약: Sub{width} 는 마스킹 (상위 제로).
                        instrs.push(Instruction::with2(Code::Sub_rm8_r8, Register::R10L, Register::R11L).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).map_err(|e| anyhow!("{e}"))?);
                    }
                    2 => {
                        instrs.push(Instruction::with2(Code::Sub_rm16_r16, Register::R10W, Register::R11W).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::R10W).map_err(|e| anyhow!("{e}"))?);
                    }
                    4 => {
                        instrs.push(Instruction::with2(Code::Sub_rm32_r32, Register::R10D, Register::R11D).map_err(|e| anyhow!("{e}"))?);
                    }
                    _ => {
                        instrs.push(Instruction::with2(Code::Sub_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                    }
                }
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::Adc { width } | RiscOp::Sbb { width } => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                load(instrs, Some(MicroOperand::Vflags), Register::RAX)?;
                instrs.push(Instruction::with2(Code::Bt_rm64_imm8, Register::RAX, 0u32).map_err(|e| anyhow!("{e}"))?);
                let adc = matches!(ins.op, RiscOp::Adc { .. });
                let code = match (adc, width) {
                    (true, 1) => Code::Adc_rm8_r8,
                    (true, 2) => Code::Adc_rm16_r16,
                    (true, 4) => Code::Adc_rm32_r32,
                    (true, _) => Code::Adc_rm64_r64,
                    (false, 1) => Code::Sbb_rm8_r8,
                    (false, 2) => Code::Sbb_rm16_r16,
                    (false, 4) => Code::Sbb_rm32_r32,
                    (false, _) => Code::Sbb_rm64_r64,
                };
                let (dst, src) = match width {
                    1 => (Register::R10L, Register::R11L),
                    2 => (Register::R10W, Register::R11W),
                    4 => (Register::R10D, Register::R11D),
                    _ => (Register::R10, Register::R11),
                };
                instrs.push(Instruction::with2(code, dst, src).map_err(|e| anyhow!("{e}"))?);
                if width == 1 {
                    instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).map_err(|e| anyhow!("{e}"))?);
                } else if width == 2 {
                    instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::R10W).map_err(|e| anyhow!("{e}"))?);
                }
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::Inc { width } => {
                load(instrs, ins.src1, Register::R10)?;
                match width {
                    1 => {
                        instrs.push(Instruction::with1(Code::Inc_rm8, Register::R10L).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10, Register::R10L).map_err(|e| anyhow!("{e}"))?);
                    }
                    2 => {
                        instrs.push(Instruction::with1(Code::Inc_rm16, Register::R10W).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10, Register::R10W).map_err(|e| anyhow!("{e}"))?);
                    }
                    4 => {
                        instrs.push(Instruction::with1(Code::Inc_rm32, Register::R10D).map_err(|e| anyhow!("{e}"))?);
                    }
                    _ => {
                        instrs.push(Instruction::with1(Code::Inc_rm64, Register::R10).map_err(|e| anyhow!("{e}"))?);
                    }
                }
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::Dec { width } => {
                load(instrs, ins.src1, Register::R10)?;
                match width {
                    1 => {
                        instrs.push(Instruction::with1(Code::Dec_rm8, Register::R10L).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10, Register::R10L).map_err(|e| anyhow!("{e}"))?);
                    }
                    2 => {
                        instrs.push(Instruction::with1(Code::Dec_rm16, Register::R10W).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10, Register::R10W).map_err(|e| anyhow!("{e}"))?);
                    }
                    4 => {
                        instrs.push(Instruction::with1(Code::Dec_rm32, Register::R10D).map_err(|e| anyhow!("{e}"))?);
                    }
                    _ => {
                        instrs.push(Instruction::with1(Code::Dec_rm64, Register::R10).map_err(|e| anyhow!("{e}"))?);
                    }
                }
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::Not { width } => {
                load(instrs, ins.src1, Register::R10)?;
                match width {
                    1 => {
                        instrs.push(Instruction::with1(Code::Not_rm8, Register::R10L).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10, Register::R10L).map_err(|e| anyhow!("{e}"))?);
                    }
                    2 => {
                        instrs.push(Instruction::with1(Code::Not_rm16, Register::R10W).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10, Register::R10W).map_err(|e| anyhow!("{e}"))?);
                    }
                    4 => {
                        instrs.push(Instruction::with1(Code::Not_rm32, Register::R10D).map_err(|e| anyhow!("{e}"))?);
                    }
                    _ => {
                        instrs.push(Instruction::with1(Code::Not_rm64, Register::R10).map_err(|e| anyhow!("{e}"))?);
                    }
                }
                // x86 NOT? RFLAGS瑜?蹂寃쏀븯吏 ?딅뒗?????뚮옒洹????????
                store(instrs, ins.dst)?;
            }
            RiscOp::ShiftRight => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Shr_rm64_CL, Register::R10, Register::CL).map_err(|e| anyhow!("{e}"))?);
                // P0-2: `test r10,r10`는 CF/OF 를 클리어하므로, 시프트 직후 CF 를
                // setc(=Setb) 로 보존한 뒤 test(결과 기반 ZF/SF/PF, OF=0 — eval_state 와
                // 동일) 다음 저장 플래그에 CF 를 OR 로 복원한다.
                instrs.push(Instruction::with1(Code::Setb_rm8, Register::R11L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R11D, Register::R11L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, mem(FLAGS_OFF as i64), Register::R11).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::ArithmeticShiftRight => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Sar_rm64_CL, Register::R10, Register::CL).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Setb_rm8, Register::R11L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R11D, Register::R11L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, mem(FLAGS_OFF as i64), Register::R11).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::ShiftLeft => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Shl_rm64_CL, Register::R10, Register::CL).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Setb_rm8, Register::R11L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R11D, Register::R11L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, mem(FLAGS_OFF as i64), Register::R11).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::RotateLeft { width } => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::RCX)?;
                load(instrs, Some(MicroOperand::Vflags), Register::RAX)?;
                instrs.push(Instruction::with1(Code::Push_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with(Code::Popfq));
                let (code, dst) = match width {
                    1 => (Code::Rol_rm8_CL, Register::R10L),
                    2 => (Code::Rol_rm16_CL, Register::R10W),
                    4 => (Code::Rol_rm32_CL, Register::R10D),
                    _ => (Code::Rol_rm64_CL, Register::R10),
                };
                instrs.push(Instruction::with2(code, dst, Register::CL).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                if width == 1 {
                    instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R10L).map_err(|e| anyhow!("{e}"))?);
                } else if width == 2 {
                    instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10D, Register::R10W).map_err(|e| anyhow!("{e}"))?);
                }
                store(instrs, ins.dst)?;
            }
            RiscOp::VirtualPush => {
                load(instrs, ins.src1, Register::R10)?;
                instrs.push(Instruction::with2(Code::Sub_rm64_imm8, Register::R13, 8).map_err(|e| anyhow!("{e}"))?);
                let sp = iced_x86::MemoryOperand::with_base(Register::R13);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, sp, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, mem(VSP_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Sub_rm64_imm8, Register::R10, 8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(VSP_OFF as i64), Register::R10).map_err(|e| anyhow!("{e}"))?);
            }
            RiscOp::VirtualPop => {
                let sp = iced_x86::MemoryOperand::with_base(Register::R13);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, sp).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::R13, 8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, mem(VSP_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::R11, 8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(VSP_OFF as i64), Register::R11).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::SetFlag => {
                load(instrs, ins.src1, Register::R10)?;
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::R10, 0x8D5).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::R10).map_err(|e| anyhow!("{e}"))?);
            }
            RiscOp::MemoryRead { width } => {
                load(instrs, ins.src1, Register::R10)?;
                let addr = iced_x86::MemoryOperand::with_base(Register::R10);
                let (code, vreg) = match width {
                    1 => (Code::Movzx_r32_rm8, Register::R10),
                    2 => (Code::Movzx_r32_rm16, Register::R10),
                    4 => (Code::Mov_r32_rm32, Register::R10D),
                    _ => (Code::Mov_r64_rm64, Register::R10),
                };
                instrs.push(Instruction::with2(code, vreg, addr).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::MemoryWrite { width } => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                let addr = iced_x86::MemoryOperand::with_base(Register::R10);
                let (code, vreg) = match width {
                    1 => (Code::Mov_rm8_r8, Register::R11L),
                    2 => (Code::Mov_rm16_r16, Register::R11W),
                    4 => (Code::Mov_rm32_r32, Register::R11D),
                    _ => (Code::Mov_rm64_r64, Register::R11),
                };
                instrs.push(Instruction::with2(code, addr, vreg).map_err(|e| anyhow!("{e}"))?);
            }
            RiscOp::CompareExchange { width } => {
                load(instrs, ins.src1, Register::R10)?; // addr
                load(instrs, ins.src2, Register::R11)?; // new
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, mem(REGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?); // acc
                // orig acc: RBX 는 Win64 callee-saved — 하네스는 RBX 를 저장하지 않으므로
                // clobber 하면 Rust 호출자(레지스터에 vm 포인터 보관)가 깨진다. volatile
                // R8 을 사용한다 (이 블록에선 R8 를 다른 용도로 쓰지 않음).
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::RAX).map_err(|e| anyhow!("{e}"))?); // orig acc
                if width < 8 {
                    let mask: u64 = match width {
                        1 => 0xFF,
                        2 => 0xFFFF,
                        _ => 0xFFFF_FFFF,
                    };
                    instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, mask as i32).map_err(|e| anyhow!("{e}"))?);
                }
                let addr = iced_x86::MemoryOperand::with_base(Register::R10);
                let (code, vreg) = match width {
                    1 => (Code::Cmpxchg_rm8_r8, Register::R11L),
                    2 => (Code::Cmpxchg_rm16_r16, Register::R11W),
                    4 => (Code::Cmpxchg_rm32_r32, Register::R11D),
                    _ => (Code::Cmpxchg_rm64_r64, Register::R11),
                };
                instrs.push(Instruction::with2(code, addr, vreg).map_err(|e| anyhow!("{e}"))?);
                // P1-6: 성공 시 원본 regs[0] 복원(cmove 는 flags 불변) → 이후 전체
                // CMP(acc-old) 상태 플래그를 캡처한다 (cmpxchg 의 ZF 포함).
                instrs.push(Instruction::with2(Code::Cmove_r64_rm64, Register::RAX, Register::R8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(REGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with(Code::Pushfq));
                instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x8D5).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x8D5i64) as i32).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
            }
            RiscOp::AtomicExchange { width } => {
                // P0-4: x86 XCHG r, [mem] — 하드웨어 xchg 는 원자적. 플래그 불변.
                load(instrs, ins.src1, Register::R10)?; // addr
                load(instrs, ins.dst, Register::R11)?; // reg value
                let addr = iced_x86::MemoryOperand::with_base(Register::R10);
                let (code, vreg) = match width {
                    1 => (Code::Xchg_rm8_r8, Register::R11L),
                    2 => (Code::Xchg_rm16_r16, Register::R11W),
                    4 => (Code::Xchg_rm32_r32, Register::R11D),
                    _ => (Code::Xchg_rm64_r64, Register::R11),
                };
                instrs.push(Instruction::with2(code, addr, vreg).map_err(|e| anyhow!("{e}"))?);
                // 폭별 zero-extend (상위 비트 정화) 후 dst 저장.
                if width < 8 {
                    let zc = match width {
                        1 => Code::Movzx_r64_rm8,
                        2 => Code::Movzx_r64_rm16,
                        _ => Code::Mov_r32_rm32,
                    };
                    instrs.push(Instruction::with2(zc, Register::R11, vreg).map_err(|e| anyhow!("{e}"))?);
                }
                store(instrs, ins.dst)?;
            }
            RiscOp::AtomicAdd { width } => {
                // P0-4: LOCK XADD [mem], reg — 원자 RMW, 폭별 플래그는 하드웨어가 set.
                load(instrs, ins.src1, Register::R10)?; // addr
                load(instrs, ins.src2, Register::R11)?; // addend
                let addr = iced_x86::MemoryOperand::with_base(Register::R10);
                let (code, vreg) = match width {
                    1 => (Code::Xadd_rm8_r8, Register::R11L),
                    2 => (Code::Xadd_rm16_r16, Register::R11W),
                    4 => (Code::Xadd_rm32_r32, Register::R11D),
                    _ => (Code::Xadd_rm64_r64, Register::R11),
                };
                let mut xi = Instruction::with2(code, addr, vreg).map_err(|e| anyhow!("{e}"))?;
                xi.set_has_lock_prefix(true);
                instrs.push(xi);
                // 폭별 zero-extend 후 dst 저장 (R11 = old [addr]).
                if width < 8 {
                    let zc = match width {
                        1 => Code::Movzx_r64_rm8,
                        2 => Code::Movzx_r64_rm16,
                        _ => Code::Mov_r32_rm32,
                    };
                    instrs.push(Instruction::with2(zc, Register::R11, vreg).map_err(|e| anyhow!("{e}"))?);
                }
                store(instrs, ins.dst)?;
                // flags: 하드웨어 xadd 의 폭별 status 를 캡처 (참조 update_add 동치).
                instrs.push(Instruction::with(Code::Pushfq));
                instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x8D5).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x8D5i64) as i32).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
            }
            RiscOp::Multiply { signed, width } => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).map_err(|e| anyhow!("{e}"))?);
                let (code, vreg) = match (signed, width) {
                    (false, 1) => (Code::Mul_rm8, Register::R11L),
                    (false, 2) => (Code::Mul_rm16, Register::R11W),
                    (false, 4) => (Code::Mul_rm32, Register::R11D),
                    (false, _) => (Code::Mul_rm64, Register::R11),
                    (true, 1) => (Code::Imul_rm8, Register::R11L),
                    (true, 2) => (Code::Imul_rm16, Register::R11W),
                    (true, 4) => (Code::Imul_rm32, Register::R11D),
                    (true, _) => (Code::Imul_rm64, Register::R11),
                };
                instrs.push(Instruction::with1(code, vreg).map_err(|e| anyhow!("{e}"))?);
                if width == 1 {
                    instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10, Register::AX).map_err(|e| anyhow!("{e}"))?);
                } else {
                    // high ??R9 (??占쏙옙 留덉뒪??, low ??R10, RDX(state base) 蹂듭썝.
                    match width {
                        2 => instrs.push(Instruction::with2(Code::Movzx_r64_rm16, Register::R9, Register::DX).map_err(|e| anyhow!("{e}"))?),
                        4 => instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::R9D, Register::EDX).map_err(|e| anyhow!("{e}"))?),
                        _ => instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RDX).map_err(|e| anyhow!("{e}"))?),
                    }
                    instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::RDX, state_base).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem((REGS_OFF + 16) as i64), Register::R9).map_err(|e| anyhow!("{e}"))?);
                }
                store_cf_of(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::MultiplyLow { signed, width } => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                let (code, r, v) = match (signed, width) {
                    (false, 2) => (Code::Imul_r16_rm16, Register::R10W, Register::R11W),
                    (false, 4) => (Code::Imul_r32_rm32, Register::R10D, Register::R11D),
                    (false, _) => (Code::Imul_r64_rm64, Register::R10, Register::R11),
                    (true, 2) => (Code::Imul_r16_rm16, Register::R10W, Register::R11W),
                    (true, 4) => (Code::Imul_r32_rm32, Register::R10D, Register::R11D),
                    (true, _) => (Code::Imul_r64_rm64, Register::R10, Register::R11),
                };
                instrs.push(Instruction::with2(code, r, v).map_err(|e| anyhow!("{e}"))?);
                store_cf_of(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::Divide { signed, width } => {
                load(instrs, ins.src1, Register::R11)?; // divisor
                // RDX(state base) 占??占쎈닓?占쎌슜?占쎈줈 ?占쏙옙?占?R8 ??蹂댁〈.
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::RDX).map_err(|e| anyhow!("{e}"))?);
                let r8mem = |disp: i64, sz: u32| -> iced_x86::MemoryOperand {
                    iced_x86::MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::None, 1, disp, sz)
                };
                match width {
                    1 => {
                        instrs.push(Instruction::with2(Code::Mov_r16_rm16, Register::AX, r8mem(REGS_OFF as i64, 2)).map_err(|e| anyhow!("{e}"))?);
                        let c = if signed { Code::Idiv_rm8 } else { Code::Div_rm8 };
                        instrs.push(Instruction::with1(c, Register::R11L).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10, Register::AX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R8).map_err(|e| anyhow!("{e}"))?);
                    }
                    2 => {
                        instrs.push(Instruction::with2(Code::Mov_r16_rm16, Register::DX, r8mem((REGS_OFF + 16) as i64, 2)).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r16_rm16, Register::AX, r8mem(REGS_OFF as i64, 2)).map_err(|e| anyhow!("{e}"))?);
                        let c = if signed { Code::Idiv_rm16 } else { Code::Div_rm16 };
                        instrs.push(Instruction::with1(c, Register::R11W).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10, Register::AX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R9, Register::DX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R8).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem((REGS_OFF + 16) as i64), Register::R9).map_err(|e| anyhow!("{e}"))?);
                    }
                    4 => {
                        instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, r8mem((REGS_OFF + 16) as i64, 4)).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, r8mem(REGS_OFF as i64, 4)).map_err(|e| anyhow!("{e}"))?);
                        let c = if signed { Code::Idiv_rm32 } else { Code::Div_rm32 };
                        instrs.push(Instruction::with1(c, Register::R11D).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::R10D, Register::EAX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::R9D, Register::EDX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R8).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem((REGS_OFF + 16) as i64), Register::R9).map_err(|e| anyhow!("{e}"))?);
                    }
                    _ => {
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, r8mem((REGS_OFF + 16) as i64, 8)).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, r8mem(REGS_OFF as i64, 8)).map_err(|e| anyhow!("{e}"))?);
                        let c = if signed { Code::Idiv_rm64 } else { Code::Div_rm64 };
                        instrs.push(Instruction::with1(c, Register::R11).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RDX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::RDX, state_base).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem((REGS_OFF + 16) as i64), Register::R9).map_err(|e| anyhow!("{e}"))?);
                    }
                }
                store(instrs, ins.dst)?;
            }
            RiscOp::BSwap { width } => {
                load(instrs, ins.src1, Register::R10)?;
                let code = if width == 4 { Code::Bswap_r32 } else { Code::Bswap_r64 };
                instrs.push(Instruction::with1(code, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::BitScanForward => {
                load(instrs, ins.src1, Register::R10)?;
                instrs.push(Instruction::with2(Code::Bsf_r64_rm64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                // src==0 ??ZF=1, dst=0 (branch-free).
                instrs.push(Instruction::with1(Code::Setne_rm8, Register::R9L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::R9L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Neg_rm64, Register::R9).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_r64, Register::R10, Register::R9).map_err(|e| anyhow!("{e}"))?);
                store_zf(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::BitScanReverse => {
                load(instrs, ins.src1, Register::R10)?;
                instrs.push(Instruction::with2(Code::Bsr_r64_rm64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Setne_rm8, Register::R9L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::R9L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Neg_rm64, Register::R9).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_r64, Register::R10, Register::R9).map_err(|e| anyhow!("{e}"))?);
                store_zf(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::CountTrailingZeros { width } => {
                load(instrs, ins.src1, Register::R10)?;
                let (code, r, v) = match width {
                    2 => (Code::Tzcnt_r16_rm16, Register::R10W, Register::R10W),
                    4 => (Code::Tzcnt_r32_rm32, Register::R10D, Register::R10D),
                    _ => (Code::Tzcnt_r64_rm64, Register::R10, Register::R10),
                };
                instrs.push(Instruction::with2(code, r, v).map_err(|e| anyhow!("{e}"))?);
                store_cf_zf(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::CountLeadingZeros { width } => {
                load(instrs, ins.src1, Register::R10)?;
                let (code, r, v) = match width {
                    2 => (Code::Lzcnt_r16_rm16, Register::R10W, Register::R10W),
                    4 => (Code::Lzcnt_r32_rm32, Register::R10D, Register::R10D),
                    _ => (Code::Lzcnt_r64_rm64, Register::R10, Register::R10),
                };
                instrs.push(Instruction::with2(code, r, v).map_err(|e| anyhow!("{e}"))?);
                store_cf_zf(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::PopCount => {
                load(instrs, ins.src1, Register::R10)?;
                instrs.push(Instruction::with2(Code::Popcnt_r64_rm64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::Setcc { cond } => {
                eval_cond(instrs, cond)?;
                instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R8L).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::ConditionalMove { cond } => {
                eval_cond(instrs, cond)?;
                load(instrs, ins.dst, Register::R10)?;
                load(instrs, ins.src1, Register::R11)?;
                let cc = cond_to_cmov_code(cond).ok_or_else(|| anyhow!("no cmov code for {cond:?}"))?;
                instrs.push(Instruction::with2(cc, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::VirtualBranch { cond } => {
                let next_idx = block_index.wrapping_add(1);
                // 遺꾧린 ???源?釉붾줉???ㅽ뻾?섎뒗 ?숈븞 r12(VIP) = ?源??몃뜳??+ 1 ?댁뼱??
                // 洹?釉붾줉??tail dispatch 媛 ?ㅼ쓬 ?몃뜳?ㅻ? ?뺥솗???쎈뒗??(?쒖감? ?숈씪 遺덈???.
                // index 怨꾩궛: rcx = 理쒖쥌 ?몃뜳?? rax = rcx + 1 ??r12; ?먰봽 table[rcx].
                let emit_branch_jump = |instrs: &mut Vec<Instruction>| -> Result<()> {
                    instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 1).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::R12, bytecode_base).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Add_rm64_r64, Register::R12, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, iced_x86::MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::RCX, 8, 0, 8)).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with1(Code::Jmp_rm64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                    Ok(())
                };
                match static_target {
                    Some(target_idx) => {
                        eval_cond(instrs, cond)?;
                        instrs.push(Instruction::with2(Code::Movzx_r64_rm8, Register::RAX, Register::R8L).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::RCX, target_idx).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Sub_rm64_imm32, Register::RCX, next_idx as i32).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Add_rm64_imm32, Register::RAX, next_idx as i32).map_err(|e| anyhow!("{e}"))?);
                        emit_branch_jump(instrs)?;
                    }
                    None => {
                        let helper = helper_va.ok_or_else(|| anyhow!("dynamic branch without helper"))?;
                        eval_cond(instrs, cond)?;
                        load(instrs, ins.src1, Register::R10)?;
                        instrs.push(Instruction::with_branch(Code::Call_rel32_64, helper).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Sub_rm64_imm32, Register::RAX, next_idx as i32).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r64_rm8, Register::RCX, Register::R8L).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Add_rm64_imm32, Register::RAX, next_idx as i32).map_err(|e| anyhow!("{e}"))?);
                        emit_branch_jump(instrs)?;
                    }
                }
            }
RiscOp::NativeCallBridge => {
                // ?占쏙옙???no-op ???占쏀깭 遺덌옙?, tail dispatch 占??占占쎌쓬 紐낅졊 吏꾪뻾.
            }
            // P1 (③): VmCallBridge — VM→VM 콜 브릿지. 네이티브 하네스에서는 인지된
            // no-op (서브 VM 레지스트리 기반 nested-VM 실행은 런타임 계층). 상용
            // `--vm-commercial` 은 is_encodable=false 로 이 op 를 포함한 함수를
            // 네이티브로 유지한다.
            RiscOp::VmCallBridge => {}
RiscOp::Halt => {
                // ret (caller?占占쎌꽌 泥섎━)
            }
            RiscOp::Trap => {
                instrs.push(Instruction::with(Code::Ud2));
            }
            // P0-1: VirtualRet — 블록 단위 하네스에서는 최상위 복귀가 블록 종료와
            // 동일하므로 no-op (상용 self-decoding 디스패처가 pop→branch-map 복귀를
            // 정확히 처리). 참조 eval_state 는 빈 스택/미가상화 복귀에서 Halt 로 종료.
            RiscOp::VirtualRet => {}
            // P2 SSE/FPU scalar - not yet native-compilable (not poly-encodable).
            // Lifter-level diff tests use eval_state (reference); no-op here.
            RiscOp::FloatAdd { .. }
            | RiscOp::FloatSub { .. }
            | RiscOp::FloatMul { .. }
            | RiscOp::FloatDiv { .. }
            | RiscOp::IntToFloat { .. }
            | RiscOp::FloatToInt { .. }
            | RiscOp::FloatToFloat { .. }
            // F1: FP 리턴 힌트 — 블록 단위 하네스엔 네이티브 브릿지가 없으므로 no-op.
            | RiscOp::SetNativeFpReturn { .. }
            // P1 (②): packed SSE — XMM 슬롯(16B 가상 메모리) 기반이라 네이티브
            // arena 에 매핑되지 않는다. emit_block 네이티브 하네스에서는 no-op 으로
            // 두고 (참조 eval_state / poly 인터프리터에서 실행), 상용 `--vm-commercial`
            // 은 is_encodable=false 로 이런 함수를 네이티브로 유지한다.
            | RiscOp::PackedMove
            | RiscOp::PackedAdd { .. }
            | RiscOp::PackedSub { .. }
            | RiscOp::PackedXor
            | RiscOp::PackedAnd
            | RiscOp::PackedOr
            | RiscOp::PackedAndNot
            | RiscOp::PackedCmpEq { .. }
            | RiscOp::PackedCmpGt { .. }
            | RiscOp::PackedUnpack { .. }
            | RiscOp::PackedShiftRightQ
            | RiscOp::PackedShuffle { .. } => {}
            RiscOp::DoubleShiftLeft { .. } => {}
            RiscOp::BitTest { .. } => {}
            RiscOp::PackedMovMaskBytes | RiscOp::PackedMovMaskPs | RiscOp::PackedInsertWord => {}
            RiscOp::CpuId | RiscOp::XGetBv => {}
            RiscOp::ReadSegmentBase { .. }
            | RiscOp::LifetimeAcquire
            | RiscOp::LifetimeRelease => {}
        }
        Ok(())
    }
}
