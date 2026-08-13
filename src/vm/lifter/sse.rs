// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: SSE / XMM family
// ==============================================================================
// XMM moves (reg<->mem, reg<->reg), UNPCKLPS/LPD, PSHUF shuffle, packed 64-bit
// shift by imm8, PINSRW, TZCNT and MOVQ (XMM<->GPR). Shared infra (`vreg`,
// `SCRATCH`, `mem_emit`) lives in `super`.
// ==============================================================================

use super::mem::mem_emit;
use super::{vreg, SCRATCH};
use crate::vm::bytecode::*;
use anyhow::Result;
use iced_x86::{Instruction, OpKind};

/// SSE moves / unpack for the XMM register file.
pub(super) fn lift_sse(b: &mut BytecodeBuilder, inst: &Instruction, kind: u8) -> Result<()> {
    use iced_x86::Code::*;
    let xmm_idx = |reg: iced_x86::Register| -> u8 {
        if reg == iced_x86::Register::None { 0 } else { reg.number() as u8 }
    };
    match kind {
        0 => {
            let xmm = xmm_idx(inst.op0_register());
            if inst.op1_kind() == OpKind::Register {
                let src_xmm = xmm_idx(inst.op1_register());
                if matches!(inst.code(), iced_x86::Code::Xorps_xmm_xmmm128 | iced_x86::Code::Xorpd_xmm_xmmm128) {
                    b.xorps_xmm(xmm, src_xmm);
                } else {
                    b.unpcklpd_xmm(xmm, src_xmm);
                }
                return Ok(());
            }
            let addr = mem_emit(b, inst, 1)?;
            if matches!(
                inst.code(),
                Movups_xmm_xmmm128
                    | Movdqu_xmm_xmmm128
                    | Movdqa_xmm_xmmm128
                    | Movaps_xmm_xmmm128
                    | Movupd_xmm_xmmm128
                    | Movapd_xmm_xmmm128
            ) {
                b.movups_xmm_mem(xmm, addr);
            } else {
                b.movsd_xmm_mem(xmm, addr);
            }
        }
        1 => {
            let xmm = xmm_idx(inst.op1_register());
            let addr = mem_emit(b, inst, 0)?;
            if matches!(
                inst.code(),
                Movups_xmmm128_xmm
                    | Movdqu_xmmm128_xmm
                    | Movdqa_xmmm128_xmm
                    | Movaps_xmmm128_xmm
                    | Movupd_xmmm128_xmm
                    | Movapd_xmmm128_xmm
            ) {
                b.movups_mem_xmm(addr, xmm);
            } else {
                b.movsd_mem_xmm(addr, xmm);
            }
        }
        _ => {
            let dst = xmm_idx(inst.op0_register());
            let src = xmm_idx(inst.op1_register());
            b.unpcklpd_xmm(dst, src);
        }
    }
    Ok(())
}

/// UNPCKLPS.
pub(super) fn lift_unpcklps(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::OpKind;
    let xmm = inst.op0_register();
    let dst = if xmm == iced_x86::Register::None { 0 } else { xmm.number() as u8 };
    if inst.op1_kind() == OpKind::Register {
        let src = inst.op1_register();
        let src_i = if src == iced_x86::Register::None { 0 } else { src.number() as u8 };
        b.unpcklps_xmm(dst, src_i);
    } else {
        let addr = mem_emit(b, inst, 1)?;
        b.movups_xmm_mem(15, addr);
        b.unpcklps_xmm(dst, 15);
    }
    Ok(())
}

/// PSHUFLW / PSHUFHW / PSHUFD.
pub(super) fn lift_sseshuffle(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let xmm = inst.op0_register();
    let xmm_i = if xmm == iced_x86::Register::None { 0 } else { xmm.number() as u8 };
    let imm = inst.immediate8();
    if inst.op1_kind() == OpKind::Register {
        let src = inst.op1_register();
        let src_i = if src == iced_x86::Register::None { 0 } else { src.number() as u8 };
        match inst.code() {
            Pshuflw_xmm_xmmm128_imm8 => b.pshuflw_xmm(xmm_i, src_i, imm),
            Pshufhw_xmm_xmmm128_imm8 => b.pshufhw_xmm(xmm_i, src_i, imm),
            _ => b.pshufd_xmm(xmm_i, src_i, imm),
        }
    } else {
        let addr = mem_emit(b, inst, 1)?;
        b.movups_xmm_mem(xmm_i, addr);
        match inst.code() {
            Pshuflw_xmm_xmmm128_imm8 => b.pshuflw_xmm(xmm_i, xmm_i, imm),
            Pshufhw_xmm_xmmm128_imm8 => b.pshufhw_xmm(xmm_i, xmm_i, imm),
            _ => b.pshufd_xmm(xmm_i, xmm_i, imm),
        }
    }
    Ok(())
}

/// PSRLLQ / PSRLQ by imm8.
pub(super) fn lift_sseshift_imm8(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let xmm = inst.op0_register();
    let xmm_i = if xmm == iced_x86::Register::None { 0 } else { xmm.number() as u8 };
    let imm = inst.immediate8();
    match inst.code() {
        iced_x86::Code::Psrlq_xmm_imm8 => b.psrlq_xmm_imm8(xmm_i, imm),
        iced_x86::Code::Psllq_xmm_imm8 => b.psllq_xmm_imm8(xmm_i, imm),
        _ => return Err(crate::error::VmCompilerError::UnsupportedInstruction {
            instruction: inst.to_string(),
            code: format!("{:?}", inst.code()),
        }.into()),
    }
    Ok(())
}

/// PINSRW.
pub(super) fn lift_pinsrw(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let xmm = inst.op0_register().number() as u8;
    let lane = inst.immediate8() & 7;
    let value;
    if inst.op1_kind() == OpKind::Register {
        value = vreg(inst.op1_register())?;
    } else {
        let addr = mem_emit(b, inst, 1)?;
        b.mem_load_a(OP_MOVZX_R_MEM16_A, SCRATCH, addr);
        value = SCRATCH;
    }
    b.pinsrw_xmm(xmm, value, lane);
    Ok(())
}

/// TZCNT.
pub(super) fn lift_tzcnt(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let d = vreg(inst.op0_register())?;
    let s;
    if inst.op1_kind() == OpKind::Register {
        s = vreg(inst.op1_register())?;
    } else {
        let addr = mem_emit(b, inst, 1)?;
        b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH, addr);
        s = SCRATCH;
    }
    b.tzcnt_r(OP_TZCNT_R32, d, s);
    Ok(())
}

/// MOVQ between XMM and GPR.
pub(super) fn lift_movq(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    if code == Movq_xmm_rm64 {
        let xmm = inst.op0_register().number() as u8;
        if inst.op1_kind() == OpKind::Register {
            b.movq_gpr_xmm(xmm, vreg(inst.op1_register())?);
        } else {
            let addr = mem_emit(b, inst, 1)?;
            b.movsd_xmm_mem(xmm, addr);
        }
    } else {
        let xmm = inst.op1_register().number() as u8;
        if inst.op0_kind() == OpKind::Register {
            b.movq_xmm_gpr(vreg(inst.op0_register())?, xmm);
        } else {
            let addr = mem_emit(b, inst, 0)?;
            b.movsd_mem_xmm(addr, xmm);
        }
    }
    Ok(())
}
