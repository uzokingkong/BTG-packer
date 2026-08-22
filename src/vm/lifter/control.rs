// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter: control-flow / conditionals / atomic
// ==============================================================================
// SETcc / CMOVcc / SBB / ADC / CMP / TEST (condition evaluation via the VM cond
// codes), XCHG / CMPXCHG / XADD (atomic RMW forms), indirect call/jmp (native
// bridge), and RET imm16. `map_cond` maps iced ConditionCode → VM cond codes.
// Shared infra (`vreg`, `reg_bits`, `SCRATCH`, `SCRATCH2`, `mem_emit`,
// `is_imm8_op`, `inst_imm`) lives in `super`.
// ==============================================================================

use super::arith::{inst_imm, is_imm8_op};
use super::mem::mem_emit;
use super::{reg_bits, vreg, SCRATCH, SCRATCH2};
use crate::vm::bytecode::*;
use anyhow::{anyhow, Result};
use iced_x86::{Instruction, OpKind};

/// Map an iced ConditionCode to our VM cond code.
fn map_cond(cc: iced_x86::ConditionCode) -> (u8, u8) {
    use iced_x86::ConditionCode::*;
    match cc {
        o => (COND_JO, COND_JNO),
        no => (COND_JNO, COND_JO),
        b => (COND_JB, COND_JAE),
        ae => (COND_JAE, COND_JB),
        e => (COND_JE, COND_JNE),
        ne => (COND_JNE, COND_JE),
        be => (COND_JBE, COND_JA),
        a => (COND_JA, COND_JBE),
        s => (COND_JS, COND_JNS),
        ns => (COND_JNS, COND_JS),
        p => (COND_JP, COND_JNP),
        np => (COND_JNP, COND_JP),
        l => (COND_JL, COND_JGE),
        ge => (COND_JGE, COND_JL),
        le => (COND_JLE, COND_JG),
        g => (COND_JG, COND_JLE),
        _ => (COND_JE, COND_JNE),
    }
}

/// SETcc.
pub(super) fn lift_setcc(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let (cond, _neg) = map_cond(inst.condition_code());
    if inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        b.setcc(SCRATCH2, cond);
        b.mem_store_a(OP_MOV_MEM8_A, addr, SCRATCH2);
        Ok(())
    } else {
        let dst = vreg(inst.op0_register())?;
        b.setcc(dst, cond);
        Ok(())
    }
}

/// CMOVcc.
pub(super) fn lift_cmovcc(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let (c, neg) = map_cond(inst.condition_code());
    let dst = vreg(inst.op0_register())?;
    let skip = b.new_label();
    b.jcc8(neg, skip);
    if inst.op1_kind() == OpKind::Register {
        let src = vreg(inst.op1_register())?;
        if reg_bits(inst.op0_register()) == 64 {
            b.mov_r_r64(dst, src);
        } else {
            b.mov_r_r(dst, src);
        }
    } else {
        let addr = mem_emit(b, inst, 1)?;
        let sz = reg_bits(inst.op0_register());
        let load = match sz {
            32 => OP_MOVZX_R_MEM32_A,
            _ => OP_MOV_R_MEM64_A,
        };
        b.mem_load_a(load, dst, addr);
    }
    b.mark_label(skip);
    let _ = c;
    Ok(())
}

/// SBB.
pub(super) fn lift_sbb(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    if inst.op0_kind() == iced_x86::OpKind::Memory {
        return Err(anyhow!(
            "lift_sbb: memory destination unsupported ({}), keep native",
            inst
        ));
    }
    let dst = vreg(inst.op0_register())?;
    let is64 = reg_bits(inst.op0_register()) == 64;
    let src_vreg: u8 = if inst.op1_kind() == OpKind::Register {
        vreg(inst.op1_register())?
    } else {
        let is8 = is_imm8_op(inst.code());
        let imm = inst_imm(inst, is8) as u64;
        if is64 {
            b.mov_r_imm64(SCRATCH2, imm);
        } else {
            b.mov_r_imm32(SCRATCH2, imm as u32);
        }
        SCRATCH2
    };
    if is64 {
        b.mov_r_r64(SCRATCH, dst);
    } else {
        b.mov_r_r(SCRATCH, dst);
    }
    let has_carry = b.new_label();
    let done = b.new_label();
    b.jcc8(COND_JB, has_carry);
    if is64 {
        b.binop_r_r64(OP_SUB_R_R64, SCRATCH, src_vreg);
    } else {
        b.binop_r_r(OP_SUB_R_R, SCRATCH, src_vreg);
    }
    b.jmp8(done);
    b.mark_label(has_carry);
    if is64 {
        b.binop_r_r64(OP_SUB_R_R64, SCRATCH, src_vreg);
    } else {
        b.binop_r_r(OP_SUB_R_R, SCRATCH, src_vreg);
    }
    if is64 {
        b.binop_r_imm64(OP_ADD_R_IMM64, SCRATCH, 0xFFFF_FFFF);
    } else {
        b.binop_r_imm32(OP_ADD_R_IMM32, SCRATCH, 0xFFFF_FFFF);
    }
    b.mark_label(done);
    if is64 {
        b.mov_r_r64(dst, SCRATCH);
    } else {
        b.mov_r_r(dst, SCRATCH);
    }
    Ok(())
}

/// ADC dst, src.
pub(super) fn lift_adc(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let name = format!("{:?}", code);
    let wbits = if name.contains("rm8_") || name.contains("r8_rm8") || name.contains("AL_") {
        8
    } else if name.contains("rm16_") || name.contains("r16_rm16") || name.contains("AX_") {
        16
    } else if name.contains("rm64_") || name.contains("r64_rm64") || name.contains("RAX_") {
        64
    } else {
        32
    };
    let (load, store, addop, mov_wide) = match wbits {
        8 => (OP_MOVZX_R_MEM8_A, OP_MOV_MEM8_A, OP_ADD_R_R, false),
        16 => (OP_MOVZX_R_MEM16_A, OP_MOV_MEM16_A, OP_ADD_R_R, false),
        64 => (OP_MOV_R_MEM64_A, OP_MOV_MEM64_A, OP_ADD_R_R64, true),
        _ => (OP_MOVZX_R_MEM32_A, OP_MOV_MEM32_A, OP_ADD_R_R, false),
    };
    let mask: u32 = match wbits {
        8 => 0xFF,
        16 => 0xFFFF,
        _ => 0xFFFF_FFFF,
    };
    let src: u8 = if inst.op1_kind() == OpKind::Register {
        vreg(inst.op1_register())?
    } else {
        let is8 = is_imm8_op(code);
        let imm = inst_imm(inst, is8) as u64;
        if wbits == 64 {
            b.mov_r_imm64(SCRATCH2, imm);
        } else {
            b.mov_r_imm32(SCRATCH2, imm as u32);
        }
        if wbits == 8 || wbits == 16 {
            b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, mask);
        }
        SCRATCH2
    };

    if inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        let val = if src == SCRATCH2 { 18u8 } else { SCRATCH2 };
        b.mem_load_a(load, val, addr);
        let has_carry = b.new_label();
        let done = b.new_label();
        b.jcc8(COND_JB, has_carry);
        if mov_wide {
            b.binop_r_r64(addop, val, src);
        } else {
            b.binop_r_r(addop, val, src);
        }
        b.jmp8(done);
        b.mark_label(has_carry);
        if mov_wide {
            b.binop_r_r64(addop, val, src);
        } else {
            b.binop_r_r(addop, val, src);
        }
        if wbits == 64 {
            b.binop_r_imm64(OP_ADD_R_IMM64, val, 1);
        } else {
            b.binop_r_imm32(OP_ADD_R_IMM32, val, 1);
        }
        b.mark_label(done);
        if wbits == 8 || wbits == 16 {
            b.binop_r_imm32(OP_AND_R_IMM32, val, mask);
        }
        b.mem_store_a(store, addr, val);
    } else {
        let dst = vreg(inst.op0_register())?;
        if mov_wide {
            b.mov_r_r64(SCRATCH, dst);
        } else {
            b.mov_r_r(SCRATCH, dst);
        }
        let has_carry = b.new_label();
        let done = b.new_label();
        b.jcc8(COND_JB, has_carry);
        if mov_wide {
            b.binop_r_r64(addop, SCRATCH, src);
        } else {
            b.binop_r_r(addop, SCRATCH, src);
        }
        b.jmp8(done);
        b.mark_label(has_carry);
        if mov_wide {
            b.binop_r_r64(addop, SCRATCH, src);
        } else {
            b.binop_r_r(addop, SCRATCH, src);
        }
        if wbits == 64 {
            b.binop_r_imm64(OP_ADD_R_IMM64, SCRATCH, 1);
        } else {
            b.binop_r_imm32(OP_ADD_R_IMM32, SCRATCH, 1);
        }
        b.mark_label(done);
        if wbits == 8 || wbits == 16 {
            b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, mask);
        }
        if mov_wide {
            b.mov_r_r64(dst, SCRATCH);
        } else {
            b.mov_r_r(dst, SCRATCH);
        }
        if wbits == 8 || wbits == 16 {
            b.binop_r_imm32(OP_AND_R_IMM32, dst, mask);
        }
    }
    Ok(())
}

/// CMP.
pub(super) fn lift_cmp(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();

    if inst.op0_kind() == OpKind::Register {
        let r = vreg(inst.op0_register())?;
        let is64 = reg_bits(inst.op0_register()) == 64;
        if inst.op1_kind() == OpKind::Register {
            let s = vreg(inst.op1_register())?;
            if is64 {
                b.mov_r_r64(SCRATCH, r);
                b.binop_r_r64(OP_SUB_R_R64, SCRATCH, s);
            } else {
                b.mov_r_r(SCRATCH, r);
                b.binop_r_r(OP_SUB_R_R, SCRATCH, s);
            }
        } else if inst.op1_kind() == OpKind::Memory {
            let addr = mem_emit(b, inst, 1)?;
            if is64 {
                b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH2, addr);
                b.mov_r_r64(SCRATCH, r);
                b.binop_r_r64(OP_SUB_R_R64, SCRATCH, SCRATCH2);
            } else {
                b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH2, addr);
                b.mov_r_r(SCRATCH, r);
                b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2);
            }
        } else {
            let is8 = is_imm8_op(code);
            let imm = inst_imm(inst, is8);
            if is64 {
                b.mov_r_r64(SCRATCH, r);
                b.mov_r_imm64(SCRATCH2, imm as u64);
                b.binop_r_r64(OP_SUB_R_R64, SCRATCH, SCRATCH2);
            } else {
                let width = reg_bits(inst.op0_register());
                let mask = match width {
                    8 => 0xFFu32,
                    16 => 0xFFFFu32,
                    _ => 0xFFFF_FFFFu32,
                };
                b.mov_r_r(SCRATCH, r);
                if mask != 0xFFFF_FFFF {
                    b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, mask);
                }
                b.mov_r_imm32(SCRATCH2, imm as u32);
                b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2);
            }
        }
    } else if inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        let mut sz = match code {
            Cmp_rm8_imm8 | Cmp_rm8_r8 => 8,
            Cmp_rm16_imm8 | Cmp_rm16_imm16 | Cmp_rm16_r16 => 16,
            _ => 32,
        };
        if matches!(code, Cmp_rm64_imm8 | Cmp_rm64_imm32) {
            sz = 64;
        }
        let load = match sz {
            8 => OP_MOVZX_R_MEM8_A,
            16 => OP_MOVZX_R_MEM16_A,
            32 => OP_MOVZX_R_MEM32_A,
            _ => OP_MOV_R_MEM64_A,
        };
        b.mem_load_a(load, SCRATCH, addr);
        if inst.op1_kind() == OpKind::Register {
            let s = vreg(inst.op1_register())?;
            if sz == 64 {
                b.binop_r_r64(OP_SUB_R_R64, SCRATCH, s);
            } else {
                b.mov_r_r(SCRATCH2, s);
                b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2);
            }
        } else {
            let is8 = is_imm8_op(code);
            let imm = inst_imm(inst, is8);
            if sz == 64 {
                b.mov_r_imm64(SCRATCH2, imm as u64);
                b.binop_r_r64(OP_SUB_R_R64, SCRATCH, SCRATCH2);
            } else {
                b.mov_r_imm32(SCRATCH2, imm as u32);
                b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2);
            }
        }
    } else {
        return Err(anyhow!("lifter: unsupported cmp operand {}", inst));
    }
    Ok(())
}

/// TEST.
pub(super) fn lift_test(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let is8 = is_imm8_op(code);

    if inst.op0_kind() == OpKind::Register {
        let r = vreg(inst.op0_register())?;
        let width = reg_bits(inst.op0_register());
        let mask = match width {
            8 => 0xFFu32,
            16 => 0xFFFFu32,
            _ => 0xFFFF_FFFFu32,
        };
        if inst.op1_kind() == OpKind::Register {
            let s = vreg(inst.op1_register())?;
            if width == 64 {
                b.mov_r_r64(SCRATCH, r);
                b.binop_r_r64(OP_AND_R_R64, SCRATCH, s);
            } else {
                b.mov_r_r(SCRATCH, r);
                if mask != 0xFFFF_FFFF {
                    b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, mask);
                }
                b.binop_r_r(OP_AND_R_R, SCRATCH, SCRATCH);
            }
        } else {
            let imm = inst_imm(inst, is8);
            if width == 64 {
                b.mov_r_r64(SCRATCH, r);
                b.mov_r_imm64(SCRATCH2, imm as u64);
                b.binop_r_r64(OP_AND_R_R64, SCRATCH, SCRATCH2);
            } else {
                b.mov_r_r(SCRATCH, r);
                if mask != 0xFFFF_FFFF {
                    b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, mask);
                }
                b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, imm as u32);
            }
        }
    } else if inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        let is16 = matches!(code, Test_rm16_imm16);
        if is16 {
            b.mem_load_a(OP_MOVZX_R_MEM16_A, SCRATCH, addr);
        } else {
            b.mem_load_a(OP_MOVZX_R_MEM8_A, SCRATCH, addr);
        }
        let imm = inst_imm(inst, is_imm8_op(code));
        b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, imm as u32);
    } else {
        return Err(anyhow!("lifter: unsupported test operand {}", inst));
    }
    Ok(())
}

/// XCHG.
pub(super) fn lift_xchg(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let mem_op: Option<u32> = (0..inst.op_count()).find(|&i| inst.op_kind(i) == OpKind::Memory);
    let name = format!("{:?}", inst.code());
    let wbits = if name.contains("rm8_") || name.contains("r8_rm8") {
        8
    } else if name.contains("rm16_") || name.contains("r16_rm16") {
        16
    } else if name.contains("rm64_") || name.contains("r64_RAX") {
        64
    } else {
        32
    };
    let is64 = wbits == 64;
    if let Some(mi) = mem_op {
        let addr = mem_emit(b, inst, mi)?;
        let ri = if mi == 0 { 1 } else { 0 };
        let reg = vreg(inst.op_register(ri))?;
        let xop = match wbits {
            8 => OP_XCHG_MEM8_A,
            16 => OP_XCHG_MEM16_A,
            64 => OP_XCHG_MEM64_A,
            _ => OP_XCHG_MEM32_A,
        };
        b.mem_xchg_a(xop, addr, reg);
    } else {
        let a = vreg(inst.op0_register())?;
        let br = vreg(inst.op1_register())?;
        if is64 {
            b.mov_r_r64(SCRATCH, a);
            b.mov_r_r64(a, br);
            b.mov_r_r64(br, SCRATCH);
        } else {
            b.mov_r_r(SCRATCH, a);
            b.mov_r_r(a, br);
            b.mov_r_r(br, SCRATCH);
        }
        if wbits == 8 || wbits == 16 {
            let mask = if wbits == 8 { 0xFFu32 } else { 0xFFFFu32 };
            b.binop_r_imm32(OP_AND_R_IMM32, a, mask);
            b.binop_r_imm32(OP_AND_R_IMM32, br, mask);
        }
    }
    Ok(())
}

/// CMPXCHG.
pub(super) fn lift_cmpxchg(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let name = format!("{:?}", code);
    let wbits = if name.contains("rm8_") {
        8
    } else if name.contains("rm16_") {
        16
    } else if name.contains("rm64_") {
        64
    } else {
        32
    };
    let mov_wide = matches!(wbits, 64);
    let rax = 0u8;
    let src = vreg(inst.op1_register())?;
    let not_equal = b.new_label();
    if inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        let xop = match wbits {
            8 => OP_CMPXCHG_MEM8_A,
            16 => OP_CMPXCHG_MEM16_A,
            64 => OP_CMPXCHG_MEM64_A,
            _ => OP_CMPXCHG_MEM32_A,
        };
        b.mem_cmpxchg_a(xop, addr, src);
        return Ok(());
    } else {
        let dst = vreg(inst.op0_register())?;
        if mov_wide {
            b.mov_r_r64(SCRATCH, dst);
            b.mov_r_r64(SCRATCH2, rax);
            b.binop_r_r64(OP_SUB_R_R64, SCRATCH, SCRATCH2);
        } else {
            b.mov_r_r(SCRATCH, dst);
            b.mov_r_r(SCRATCH2, rax);
            b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2);
        }
        b.jcc8(COND_JNE, not_equal);
        if mov_wide {
            b.mov_r_r64(dst, src);
        } else {
            b.mov_r_r(dst, src);
        }
        let done = b.new_label();
        b.jmp8(done);
        b.mark_label(not_equal);
        if mov_wide {
            b.mov_r_r64(rax, SCRATCH);
        } else {
            b.mov_r_r(rax, SCRATCH);
        }
        b.mark_label(done);
    }
    Ok(())
}

/// XADD dst, src.
pub(super) fn lift_xadd(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let name = format!("{:?}", code);
    let wbits = if name.contains("rm8_") || name.contains("r8_rm8") {
        8
    } else if name.contains("rm16_") || name.contains("r16_rm16") {
        16
    } else if name.contains("rm64_") || name.contains("r64_rm64") {
        64
    } else {
        32
    };
    let (addop, mov_wide) = match wbits {
        64 => (OP_ADD_R_R64, true),
        _ => (OP_ADD_R_R, false),
    };
    let mask: u32 = match wbits {
        8 => 0xFF,
        16 => 0xFFFF,
        _ => 0xFFFF_FFFF,
    };
    let src = vreg(inst.op1_register())?;
    if inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        let xop = match wbits {
            8 => OP_XADD_MEM8_A,
            16 => OP_XADD_MEM16_A,
            64 => OP_XADD_MEM64_A,
            _ => OP_XADD_MEM32_A,
        };
        b.mem_xadd_a(xop, addr, src);
    } else {
        let dst = vreg(inst.op0_register())?;
        if mov_wide {
            b.mov_r_r64(SCRATCH, dst);
        } else {
            b.mov_r_r(SCRATCH, dst);
        }
        b.mov_r_r(SCRATCH2, SCRATCH);
        if wbits == 64 {
            b.binop_r_r64(addop, SCRATCH2, src);
        } else {
            b.binop_r_r(addop, SCRATCH2, src);
        }
        if wbits == 8 || wbits == 16 {
            b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, mask);
        }
        if mov_wide {
            b.mov_r_r64(dst, SCRATCH2);
        } else {
            b.mov_r_r(dst, SCRATCH2);
        }
        if wbits == 8 || wbits == 16 {
            b.binop_r_imm32(OP_AND_R_IMM32, dst, mask);
        }
        if mov_wide {
            b.mov_r_r64(src, SCRATCH);
        } else {
            b.mov_r_r(src, SCRATCH);
        }
        if wbits == 8 || wbits == 16 {
            b.binop_r_imm32(OP_AND_R_IMM32, src, mask);
        }
    }
    Ok(())
}

/// Indirect call/jmp.
pub(super) fn lift_indirect_call(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    if inst.op0_kind() == OpKind::Register {
        let t = vreg(inst.op0_register())?;
        b.native_call(t);
    } else if inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH, addr);
        b.native_call(SCRATCH);
    } else {
        return Err(anyhow!("lifter: unsupported indirect call target {}", inst));
    }
    if matches!(inst.code(), iced_x86::Code::Jmp_rm64) {
        b.ret();
    }
    Ok(())
}

/// RET imm16.
pub(super) fn lift_ret_imm16(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    b.ret_imm16(inst.immediate16());
    Ok(())
}
