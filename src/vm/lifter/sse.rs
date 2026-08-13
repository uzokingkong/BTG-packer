// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: SSE / XMM family
// ==============================================================================
// XMM moves (reg<->mem, reg<->reg), UNPCKLPS/LPD, PSHUF shuffle, packed 64-bit
// shift by imm8, PINSRW, TZCNT and MOVQ (XMM<->GPR). Shared infra (`vreg`,
// `SCRATCH`, `mem_emit`) lives in `super`.
// ==============================================================================

use super::mem::mem_emit;
use super::{vreg, SCRATCH, SCRATCH2};
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
                // PXOR is bit-identical to XORPS for the 128-bit register file.
                if matches!(inst.code(), iced_x86::Code::Xorps_xmm_xmmm128 | iced_x86::Code::Xorpd_xmm_xmmm128 | iced_x86::Code::Pxor_xmm_xmmm128) {
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

// ── v54: SSE/FPU (Group A, Phase 2.1) ────────────────────────────────────────
// Scalar FP arithmetic, 128-bit logic (PAND/POR/PANDN), the conversion family
// and PEXTRD/PINSRD. Memory-source forms load through the scratch XMM15
// (width-exact loads for m32/m64 scalars, MOVUPS for 128-bit logic).

/// XMM register index helper (None -> 0, matching the other lifts here).
fn xidx(reg: iced_x86::Register) -> u8 {
    if reg == iced_x86::Register::None { 0 } else { reg.number() as u8 }
}

/// Load a m32/m64 scalar FP source into scratch XMM15 (via a GPR for m32 so
/// only 4 bytes are read — MOVUPS would over-read past a page boundary).
fn load_fp_scalar(b: &mut BytecodeBuilder, inst: &Instruction, wide: bool) -> Result<u8> {
    let addr = mem_emit(b, inst, 1)?;
    if wide {
        b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH, addr);
        b.movq_gpr_xmm(15, SCRATCH);
    } else {
        b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH, addr);
        b.movq_gpr_xmm(15, SCRATCH);
    }
    Ok(15)
}

/// SSE scalar FP arithmetic: ADDSS/ADDSD/SUBSS/SUBSD/MULSS/MULSD/DIVSS/DIVSD.
pub(super) fn lift_sse_fp(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let dst = xidx(inst.op0_register());
    let (op, wide) = match inst.code() {
        Addss_xmm_xmmm32 => (OP_ADDSS_XMM, false),
        Addsd_xmm_xmmm64 => (OP_ADDSD_XMM, true),
        Subss_xmm_xmmm32 => (OP_SUBSS_XMM, false),
        Subsd_xmm_xmmm64 => (OP_SUBSD_XMM, true),
        Mulss_xmm_xmmm32 => (OP_MULSS_XMM, false),
        Mulsd_xmm_xmmm64 => (OP_MULSD_XMM, true),
        Divss_xmm_xmmm32 => (OP_DIVSS_XMM, false),
        Divsd_xmm_xmmm64 => (OP_DIVSD_XMM, true),
        _ => return Err(anyhow::anyhow!("lifter: unsupported SSE FP op {:?}", inst.code())),
    };
    let src = if inst.op1_kind() == OpKind::Register {
        xidx(inst.op1_register())
    } else {
        load_fp_scalar(b, inst, wide)?
    };
    b.sse_fp_xmm(op, dst, src);
    Ok(())
}

/// SSE 128-bit logic: PAND / POR / PANDN.
pub(super) fn lift_sse_logic(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let dst = xidx(inst.op0_register());
    let op = match inst.code() {
        Pand_xmm_xmmm128 => OP_PAND_XMM,
        Por_xmm_xmmm128 => OP_POR_XMM,
        _ => OP_PANDN_XMM,
    };
    let src = if inst.op1_kind() == OpKind::Register {
        xidx(inst.op1_register())
    } else {
        let addr = mem_emit(b, inst, 1)?;
        b.movups_xmm_mem(15, addr);
        15
    };
    b.sse_logic_xmm(op, dst, src);
    Ok(())
}

/// Conversion family: CVTSI2SD/CVTSI2SS, CVTSS2SD/CVTSD2SS, and float->int
/// CVTTSS2SI/CVTTSD2SI (trunc) + CVTSS2SI/CVTSD2SI (round-to-nearest-even).
pub(super) fn lift_cvt(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let dst0 = inst.op0_register();
    match inst.code() {
        // int -> float (GPR source: register or memory)
        Cvtsi2sd_xmm_rm32 | Cvtsi2sd_xmm_rm64 | Cvtsi2ss_xmm_rm32 | Cvtsi2ss_xmm_rm64 => {
            let dst = xidx(dst0);
            let s: u8 = if inst.op1_kind() == OpKind::Register {
                super::vreg(inst.op1_register())?
            } else {
                let addr = mem_emit(b, inst, 1)?;
                let lop = if matches!(inst.code(), Cvtsi2sd_xmm_rm64 | Cvtsi2ss_xmm_rm64) {
                    OP_MOV_R_MEM64_A
                } else {
                    OP_MOVZX_R_MEM32_A
                };
                b.mem_load_a(lop, SCRATCH, addr);
                SCRATCH
            };
            match inst.code() {
                Cvtsi2sd_xmm_rm64 => b.cvt_int_fp(OP_CVTSI2SD_XMM, dst, s),
                Cvtsi2ss_xmm_rm32 => b.cvt_int_fp(OP_CVTSI2SS_XMM, dst, s),
                Cvtsi2sd_xmm_rm32 => {
                    // exact: sign-extend the 32-bit int to 64, then convert
                    b.mov_r_r(SCRATCH2, s);
                    b.shift64_r_imm8(OP_SHL64_R_IMM8, SCRATCH2, 32);
                    b.shift64_r_imm8(OP_SAR64_R_IMM8, SCRATCH2, 32);
                    b.cvt_int_fp(OP_CVTSI2SD_XMM, dst, SCRATCH2);
                }
                _ => {
                    // cvtsi2ss with a 64-bit int source: convert via double
                    // (OP_CVTSI2SS takes a 32-bit int; double covers i64).
                    b.cvt_int_fp(OP_CVTSI2SD_XMM, 14, s);
                    b.cvt_fp_fp(OP_CVTSD2SS_XMM, dst, 14);
                }
            }
        }
        // float <-> float
        Cvtss2sd_xmm_xmmm32 | Cvtsd2ss_xmm_xmmm64 => {
            let dst = xidx(dst0);
            let ss2sd = matches!(inst.code(), Cvtss2sd_xmm_xmmm32);
            let src = if inst.op1_kind() == OpKind::Register {
                xidx(inst.op1_register())
            } else if ss2sd {
                load_fp_scalar(b, inst, false)?
            } else {
                let addr = mem_emit(b, inst, 1)?;
                b.movsd_xmm_mem(15, addr);
                15
            };
            b.cvt_fp_fp(if ss2sd { OP_CVTSS2SD_XMM } else { OP_CVTSD2SS_XMM }, dst, src);
        }
        // float -> int
        Cvttss2si_r32_xmmm32 | Cvttss2si_r64_xmmm32
        | Cvttsd2si_r32_xmmm64 | Cvttsd2si_r64_xmmm64
        | Cvtss2si_r32_xmmm32 | Cvtss2si_r64_xmmm32
        | Cvtsd2si_r32_xmmm64 | Cvtsd2si_r64_xmmm64 => {
            let dst = super::vreg(dst0)?;
            let is_ss = matches!(inst.code(), Cvttss2si_r32_xmmm32 | Cvttss2si_r64_xmmm32 | Cvtss2si_r32_xmmm32 | Cvtss2si_r64_xmmm32);
            let src = if inst.op1_kind() == OpKind::Register {
                xidx(inst.op1_register())
            } else {
                load_fp_scalar(b, inst, !is_ss)?
            };
            let op = match inst.code() {
                Cvttss2si_r32_xmmm32 | Cvttss2si_r64_xmmm32 => OP_CVTTSS2SI,
                Cvttsd2si_r32_xmmm64 | Cvttsd2si_r64_xmmm64 => OP_CVTTSD2SI,
                Cvtss2si_r32_xmmm32 | Cvtss2si_r64_xmmm32 => OP_CVTSS2SI,
                _ => OP_CVTSD2SI,
            };
            b.cvt_fp_int(op, dst, src);
            // The r64 destination forms sign-extend the 32-bit result.
            if dst0.size() == 8 {
                b.shift64_r_imm8(OP_SHL64_R_IMM8, dst, 32);
                b.shift64_r_imm8(OP_SAR64_R_IMM8, dst, 32);
            }
        }
        _ => return Err(anyhow::anyhow!("lifter: unsupported CVT op {:?}", inst.code())),
    }
    Ok(())
}

/// PEXTRD (xmm dword lane -> gpr) / PINSRD (gpr low32 -> xmm dword lane).
pub(super) fn lift_pext_pins(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    match inst.code() {
        Pextrd_rm32_xmm_imm8 => {
            let dst = super::vreg(inst.op0_register())?;
            let src = xidx(inst.op1_register());
            b.pextrd_xmm(dst, src, inst.immediate8());
        }
        Pinsrd_xmm_rm32_imm8 => {
            let dst = xidx(inst.op0_register());
            let s = if inst.op1_kind() == OpKind::Register {
                super::vreg(inst.op1_register())?
            } else {
                let addr = mem_emit(b, inst, 1)?;
                b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH, addr);
                SCRATCH
            };
            b.pinsrd_xmm(dst, s, inst.immediate8());
        }
        _ => return Err(anyhow::anyhow!("lifter: unsupported PEXTR/PINSR op {:?}", inst.code())),
    }
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
