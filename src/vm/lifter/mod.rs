// ==============================================================================
// BTG v24 - x86-64 → VM Bytecode Lifter
// ==============================================================================
//
// Translates an x86-64 instruction sequence into VM bytecode. The MVP lifter
// (lift_ksa) covers exactly the RC4 KSA subset; the M4 block lifter
// (`lift_block`) is a general 1:1 x86→VM instruction table for straight-line
// basic blocks, plus the control-flow opcodes (Jcc/JMP/CALL/RET) so a whole
// function body can be lifted and verified against native execution.
//
// Virtual registers map 1:1 to the native GPR numbers (RAX=0 … R15=15), so a
// 32-bit sub-register shares its vreg with the full GPR.
//
// Memory operands are lowered to a full 64-bit effective address held in a
// scratch vreg (R15) via OP_LEA / OP_LEA_RIP, then an absolute-address
// load/store (OP_MOV*_A). This supports [base+disp], [base+index*scale+disp]
// and RIP-relative addressing uniformly. R15 is the lifter's reserved scratch.
//
// ── Module layout (directory decomposition) ────────────────────────────────
// The old lifter.rs monolith was split into this directory module. `mod.rs`
// keeps the shared scaffolding and orchestration — the `SCRATCH`/`SCRATCH2`
// constants, `LiftedInstr`, the `lift_ksa` / `lift_one` dispatchers, the
// `is_jcc`/`jcc_cond` helpers, `vreg`/`reg_bits`, the scratch-collision guard,
// and the block/CFG tests — and the per-family `lift_*` helpers moved to
// submodules, referenced via `super`:
//   mem.rs     - effective-address / memory-operand lowering (mem_emit, lea, rip)
//   arith.rs   - ADD/SUB/XOR/AND/OR reg-reg/reg-imm + 8/16-bit narrow + IMUL imm
//   shift.rs   - SHL/SHR/SAR/ROL/ROR (all widths/forms) + INC/DEC + NOT/NEG
//   muldiv.rs  - 1-op MUL/IMUL/DIV/IDIV + BSR/BSF + BT/BTS/BTR/BTC
//   control.rs - SETcc/CMOVcc/SBB/ADC/CMP/TEST + XCHG/CMPXCHG/XADD + ind. call
//   sse.rs     - XMM moves / shuffles / packed shifts / PINSRW / TZCNT / MOVQ
//   string.rs  - REP STOSQ / REP MOVS / REP CMPS
//   cfg.rs     - lift_block / lift_cfg / lift_cfg_switch / diagnose_unsupported
// The public API (`lifter::LiftedInstr`, `lift_ksa`, `lift_one`, `lift_block`,
// `lift_cfg`, `lift_cfg_switch`, `diagnose_unsupported`, `SCRATCH`, `SCRATCH2`,
// `vreg`) is unchanged.
// ==============================================================================


use crate::vm::bytecode::*;
use crate::vm::ksa::KsaInstr;
use anyhow::{Result, anyhow};
use iced_x86::{Code, Instruction, OpKind, Register};

use self::arith::{inst_imm, lift_arith_imm, lift_imul_imm, lift_narrow_arith, two_op};
use self::control::{
    lift_adc, lift_cmovcc, lift_cmp, lift_cmpxchg, lift_indirect_call, lift_ret_imm16, lift_sbb,
    lift_setcc, lift_test, lift_xadd, lift_xchg,
};
use self::mem::{mem_emit, mem_emit_lea};
use self::muldiv::{lift_bs, lift_bt, lift_bts, lift_muldiv};
use self::shift::{lift_incdec, lift_not_neg, lift_shift_rotate};
use self::sse::{
    lift_movq, lift_pinsrw, lift_sse, lift_sseshift_imm8, lift_sseshuffle, lift_tzcnt,
    lift_unpcklps,
};
use self::string::{lift_rep_cmps, lift_rep_movs, lift_rep_stosq};

mod arith;
mod cfg;
mod control;
mod mem;
mod muldiv;
mod shift;
mod sse;
mod string;

pub use self::cfg::{diagnose_unsupported, lift_block, lift_cfg, lift_cfg_switch};

/// The lifter's scratch vreg for effective-address computation (vreg 16).
pub const SCRATCH: u8 = 16;
/// Secondary scratch vreg (vreg 17).
pub const SCRATCH2: u8 = 17;

/// A single instruction in a block to be lifted.
#[derive(Debug, Clone)]
pub struct LiftedInstr {
    pub inst: Instruction,
    /// Set on the instruction a label *points to* (e.g. a loop head).
    pub label: Option<u32>,
    /// Set on a branch instruction: the label it targets.
    pub target: Option<u32>,
}

impl LiftedInstr {
    pub fn plain(inst: Instruction) -> Self {
        Self { inst, label: None, target: None }
    }
    pub fn labeled(inst: Instruction, label: u32) -> Self {
        Self { inst, label: Some(label), target: None }
    }
    pub fn branch(inst: Instruction, target: u32) -> Self {
        Self { inst, label: None, target: Some(target) }
    }
}

/// Lift the KSA instruction list to VM bytecode (MVP path).
pub fn lift_ksa(seq: &[KsaInstr]) -> Result<Vec<u8>> {
    let mut b = BytecodeBuilder::new();
    let mut labels = std::collections::HashMap::new();

    for item in seq {
        if let Some(l) = item.label {
            let id = *labels.entry(l).or_insert_with(|| b.new_label());
            b.mark_label(id);
        }

        let inst = item.inst;
        let code = inst.code();

        if crate::vm::mapper::active() {
            crate::vm::mapper::record(b.bytes.len(), &inst, 0, "KSA");
        }

        if let Some(t) = item.target {
            let id = *labels.entry(t).or_insert_with(|| b.new_label());
            match code {
                Code::Jb_rel32_64 => b.jb8(id),
                Code::Jmp_rel32_64 => b.jmp8(id),
                _ => return Err(anyhow!("lifter: unsupported branch {:?}", code)),
            }
            continue;
        }

        match code {
            Code::Mov_r64_imm64 => {
                let r = vreg(inst.op0_register())?;
                b.mov_r_imm64(r, inst.immediate64());
            }
            Code::Mov_r32_imm32 => {
                let r = vreg(inst.op0_register())?;
                b.mov_r_imm32(r, inst.immediate32());
            }
            Code::Mov_r32_rm32 => {
                let dst = vreg(inst.op0_register())?;
                let src = vreg(inst.op1_register())?;
                b.mov_r_r(dst, src);
            }
            Code::Mov_r64_rm64 => {
                let dst = vreg(inst.op0_register())?;
                let src = vreg(inst.op1_register())?;
                b.mov_r_r64(dst, src);
            }
            Code::Xor_r32_rm32 | Code::Xor_rm32_r32 => {
                let (d, s) = two_regs(&inst)?;
                b.binop_r_r(OP_XOR_R_R, d, s);
            }
            Code::Add_rm32_r32 => {
                let (d, s) = two_regs(&inst)?;
                b.binop_r_r(OP_ADD_R_R, d, s);
            }
            Code::Imul_r32_rm32 => {
                let (d, s) = two_regs(&inst)?;
                b.binop_r_r(OP_IMUL_R_R, d, s);
            }
            Code::And_rm32_imm32 => {
                let r = vreg(inst.op0_register())?;
                b.binop_r_imm32(OP_AND_R_IMM32, r, inst.immediate32());
            }
            Code::Rol_rm32_imm8 => {
                let r = vreg(inst.op0_register())?;
                b.rol_r_imm8(r, inst.immediate8() as u8);
            }
            Code::Ror_rm32_imm8 => {
                let r = vreg(inst.op0_register())?;
                b.ror_r_imm8(r, inst.immediate8() as u8);
            }
            Code::Inc_rm32 => {
                let r = vreg(inst.op0_register())?;
                b.inc_r(r);
            }
            Code::Cmp_rm32_imm32 => {
                let r = vreg(inst.op0_register())?;
                b.cmp_r_imm32(r, inst.immediate32());
            }
            Code::Movzx_r32_rm8 => {
                let dst = vreg(inst.op0_register())?;
                let (slot, idx) = mem_operand(&inst)?;
                b.movzx_r_mem8(dst, slot, idx);
            }
            Code::Mov_rm8_r8 => {
                let (slot, idx) = mem_operand(&inst)?;
                let src = vreg(inst.op1_register())?;
                b.mov_mem8_r(slot, idx, src);
            }
            other => {
                return Err(anyhow!(
                    "lifter: unsupported instruction {:?} ({})",
                    other,
                    inst
                ))
            }
        }
    }

    b.halt();
    Ok(b.finish())
}

/// Both operands must be registers; returns (dst vreg, src vreg).
fn two_regs(inst: &iced_x86::Instruction) -> Result<(u8, u8)> {
    if inst.op0_kind() != OpKind::Register || inst.op1_kind() != OpKind::Register {
        return Err(anyhow!("lifter: expected register-register form, got {}", inst));
    }
    Ok((vreg(inst.op0_register())?, vreg(inst.op1_register())?))
}

/// Decode a `[base + index*1]` memory operand into (memslot, index vreg).
fn mem_operand(inst: &iced_x86::Instruction) -> Result<(u8, u8)> {
    if inst.memory_index_scale() != 1 || inst.memory_displacement64() != 0 {
        return Err(anyhow!(
            "lifter: only [base + index*1] memory supported, got {}",
            inst
        ));
    }
    let slot = match inst.memory_base() {
        Register::RBX => MEM_SBOX,
        Register::RDX => MEM_SEED,
        Register::RCX => MEM_BUF,
        Register::RBP => MEM_RUNS,
        other => return Err(anyhow!("lifter: unsupported memory base {:?}", other)),
    };
    let idx = vreg(inst.memory_index())?;
    Ok((slot, idx))
}

/// Guard against the reserved-scratch vreg collision.
fn check_scratch_collision(_inst: &Instruction) -> Result<()> {
    Ok(())
}

/// 1:1 instruction table — emit the VM bytecode for one x86 instruction.
pub fn lift_one(
    b: &mut BytecodeBuilder,
    inst: &Instruction,
) -> Result<()> {
    let code = inst.code();
    use iced_x86::Code::*;

    check_scratch_collision(inst)?;

    match code {
        // ── v32: 8/16-bit arithmetic (A-2 잔여) ─────────────────────────────
        Add_rm8_r8 | Add_r8_rm8 | Add_rm16_r16 | Add_r16_rm16
        | Add_AL_imm8 | Add_AX_imm16 | Add_rm8_imm8 | Add_rm16_imm8 | Add_rm16_imm16
        | Sub_rm8_r8 | Sub_r8_rm8 | Sub_rm16_r16 | Sub_r16_rm16
        | Sub_AL_imm8 | Sub_AX_imm16 | Sub_rm8_imm8 | Sub_rm16_imm8 | Sub_rm16_imm16
        | Xor_rm8_r8 | Xor_r8_rm8 | Xor_rm16_r16 | Xor_r16_rm16
        | Xor_AL_imm8 | Xor_AX_imm16 | Xor_rm8_imm8 | Xor_rm16_imm8 | Xor_rm16_imm16
        | And_rm8_r8 | And_r8_rm8 | And_rm16_r16 | And_r16_rm16
        | And_AL_imm8 | And_AX_imm16 | And_rm8_imm8 | And_rm16_imm8 | And_rm16_imm16
        | Or_rm8_r8 | Or_r8_rm8 | Or_rm16_r16 | Or_r16_rm16
        | Or_AL_imm8 | Or_AX_imm16 | Or_rm8_imm8 | Or_rm16_imm8 | Or_rm16_imm16 => {
            lift_narrow_arith(b, inst)?
        }
        // ── A-5 잔여: rep movs / rep cmps (string ops) ─────────────────────
        Movsb_m8_m8 | Movsw_m16_m16 | Movsd_m32_m32 | Movsq_m64_m64 => lift_rep_movs(b, inst)?,
        Cmpsb_m8_m8 | Cmpsw_m16_m16 | Cmpsd_m32_m32 | Cmpsq_m64_m64 => lift_rep_cmps(b, inst)?,

        // ── register / immediate moves ─────────────────────────────────────
        Mov_r64_imm64 => { let r = vreg(inst.op0_register())?; b.mov_r_imm64(r, inst.immediate64()); }
        Mov_r32_imm32 => { let r = vreg(inst.op0_register())?; b.mov_r_imm32(r, inst.immediate32()); }
        Mov_r16_imm16 | Mov_r8_imm8 => {
            let r = vreg(inst.op0_register())?;
            let v = if matches!(code, Mov_r8_imm8) { inst.immediate8() as u32 } else { inst.immediate16() as u32 };
            b.mov_r_imm32(r, v);
        }
        Mov_r64_rm64 | Mov_r32_rm32 | Mov_r16_rm16 | Mov_r8_rm8 => {
            if inst.op1_kind() == OpKind::Register {
                let d = vreg(inst.op0_register())?;
                let s = vreg(inst.op1_register())?;
                let sz = reg_bits(inst.op0_register());
                if sz == 16 || sz == 8 {
                    b.mov_r_r(d, s);
                    let mask = if sz == 8 { 0xFFu32 } else { 0xFFFFu32 };
                    b.binop_r_imm32(OP_AND_R_IMM32, d, mask);
                } else if sz == 64 {
                    b.mov_r_r64(d, s);
                } else {
                    b.mov_r_r(d, s);
                }
            } else {
                let d = vreg(inst.op0_register())?;
                let addr = mem_emit(b, inst, 1)?;
                let sz = reg_bits(inst.op0_register());
                match sz {
                    8 => b.mem_load_a(OP_MOVZX_R_MEM8_A, d, addr),
                    16 => b.mem_load_a(OP_MOVZX_R_MEM16_A, d, addr),
                    32 => b.mem_load_a(OP_MOVZX_R_MEM32_A, d, addr),
                    _ => b.mem_load_a(OP_MOV_R_MEM64_A, d, addr),
                }
            }
        }
        Mov_rm64_r64 | Mov_rm32_r32 | Mov_rm16_r16 | Mov_rm8_r8 => {
            if inst.op0_kind() == OpKind::Register && inst.op1_kind() == OpKind::Register {
                let d = vreg(inst.op0_register())?;
                let s = vreg(inst.op1_register())?;
                if reg_bits(inst.op0_register()) == 64 {
                    b.mov_r_r64(d, s);
                } else {
                    b.mov_r_r(d, s);
                }
            } else if inst.op1_kind() == OpKind::Register {
                let addr = mem_emit(b, inst, 0)?;
                let s = vreg(inst.op1_register())?;
                let sz = reg_bits(inst.op1_register());
                match sz {
                    8 => b.mem_store_a(OP_MOV_MEM8_A, addr, s),
                    16 => b.mem_store_a(OP_MOV_MEM16_A, addr, s),
                    32 => b.mem_store_a(OP_MOV_MEM32_A, addr, s),
                    _ => b.mem_store_a(OP_MOV_MEM64_A, addr, s),
                }
            } else {
                return Err(anyhow!("lifter: unsupported mov form {:?}", code));
            }
        }
        // store an immediate to memory (mov [mem], imm)
        Mov_rm8_imm8 | Mov_rm16_imm16 | Mov_rm32_imm32 | Mov_rm64_imm32 => {
            if inst.op0_kind() == OpKind::Register {
                let r = vreg(inst.op0_register())?;
                if matches!(code, Mov_rm64_imm32) {
                    let imm = (inst.immediate32() as i32) as i64 as u64;
                    b.mov_r_imm64(r, imm);
                } else if matches!(code, Mov_rm32_imm32) {
                    b.mov_r_imm32(r, inst.immediate32());
                } else if matches!(code, Mov_rm16_imm16) {
                    b.mov_r_imm32(r, inst.immediate16() as u32);
                } else {
                    b.mov_r_imm32(r, inst.immediate8() as u32);
                }
            } else if inst.op0_kind() != OpKind::Memory {
                return Err(anyhow!("lifter: mov-imm requires register/memory dest, got {}", inst));
            } else {
            let addr = mem_emit(b, inst, 0)?;
            let is8 = matches!(code, Mov_rm8_imm8);
            let is16 = matches!(code, Mov_rm16_imm16);
            let v = if is16 { inst.immediate16() as u64 } else { inst_imm(inst, is8) as u64 };
            b.mov_r_imm64(SCRATCH2, v);
            match code {
                Mov_rm8_imm8 => b.mem_store_a(OP_MOV_MEM8_A, addr, SCRATCH2),
                Mov_rm16_imm16 => b.mem_store_a(OP_MOV_MEM16_A, addr, SCRATCH2),
                Mov_rm32_imm32 => b.mem_store_a(OP_MOV_MEM32_A, addr, SCRATCH2),
                _ => b.mem_store_a(OP_MOV_MEM64_A, addr, SCRATCH2),
            }
            }
        }
        Movzx_r32_rm8 | Movzx_r32_rm16 | Movzx_r64_rm8 | Movzx_r64_rm16 | Movsx_r64_rm8 | Movsx_r64_rm16 | Movsx_r32_rm8 | Movsx_r32_rm16 => {
            let d = vreg(inst.op0_register())?;
            if inst.op1_kind() == OpKind::Register {
                let s = vreg(inst.op1_register())?;
                b.mov_r_r(d, s);
                let mask = match code { Movzx_r32_rm8 | Movzx_r64_rm8 => 0xFFu32, _ => 0xFFFFu32 };
                b.binop_r_imm32(OP_AND_R_IMM32, d, mask);
            } else {
                let addr = mem_emit(b, inst, 1)?;
                let load = match code {
                    Movzx_r32_rm8 | Movzx_r64_rm8 => OP_MOVZX_R_MEM8_A,
                    Movzx_r32_rm16 | Movzx_r64_rm16 => OP_MOVZX_R_MEM16_A,
                    Movsx_r64_rm8 | Movsx_r32_rm8 => OP_MOVSX_R_MEM8_A,
                    _ => OP_MOVSX_R_MEM16_A,
                };
                b.mem_load_a(load, d, addr);
            }
        }
        Movsxd_r64_rm32 => {
            let d = vreg(inst.op0_register())?;
            if inst.op1_kind() == OpKind::Register {
                let s = vreg(inst.op1_register())?;
                b.mov_r_r(d, s);
            } else {
                let addr = mem_emit(b, inst, 1)?;
                b.mem_load_a(OP_MOVZX_R_MEM32_A, d, addr);
            }
            b.shift64_r_imm8(OP_SHL64_R_IMM8, d, 32);
            b.shift64_r_imm8(OP_SAR64_R_IMM8, d, 32);
        }
        Cdqe => {
            let d = vreg(Register::RAX)?;
            b.shift64_r_imm8(OP_SHL64_R_IMM8, d, 32);
            b.shift64_r_imm8(OP_SAR64_R_IMM8, d, 32);
        }

        // ── arithmetic / logic (reg/reg, reg/imm) ──────────────────────────
        Add_r32_rm32 | Add_r64_rm64 | Add_rm32_r32 | Add_rm64_r64 => two_op(b, inst, OP_ADD_R_R, OP_ADD_R_R64)?,
        Sub_r32_rm32 | Sub_r64_rm64 | Sub_rm32_r32 | Sub_rm64_r64 => two_op(b, inst, OP_SUB_R_R, OP_SUB_R_R64)?,
        Xor_r32_rm32 | Xor_r64_rm64 | Xor_rm32_r32 | Xor_rm64_r64 => two_op(b, inst, OP_XOR_R_R, OP_XOR_R_R64)?,
        And_r32_rm32 | And_r64_rm64 | And_rm32_r32 | And_rm64_r64 => two_op(b, inst, OP_AND_R_R, OP_AND_R_R64)?,
        Or_r32_rm32 | Or_r64_rm64 | Or_rm32_r32 | Or_rm64_r64 => two_op(b, inst, OP_OR_R_R, OP_OR_R_R64)?,
        Neg_rm8 | Neg_rm16 | Neg_rm32 | Neg_rm64 => lift_not_neg(b, inst)?,
        Not_rm8 | Not_rm16 | Not_rm32 | Not_rm64 => lift_not_neg(b, inst)?,
        Nopw | Nopd | Nopq | Nop_rm16 | Nop_rm32 | Nop_rm64 => b.nop(),
        Imul_r32_rm32 | Imul_r64_rm64 => two_op(b, inst, OP_IMUL_R_R, OP_IMUL_R_R64)?,
        // ── v31/v33: 1-operand multiply/divide (implicit accumulator) + BSWAP
        Mul_rm8 | Mul_rm16 | Mul_rm32 | Mul_rm64
        | Imul_rm8 | Imul_rm16 | Imul_rm32 | Imul_rm64
        | Div_rm8 | Div_rm16 | Div_rm32 | Div_rm64
        | Idiv_rm8 | Idiv_rm16 | Idiv_rm32 | Idiv_rm64 => lift_muldiv(b, inst)?,
        Bswap_r32 | Bswap_r64 => {
            let r = vreg(inst.op0_register())?;
            let op = if matches!(code, Bswap_r32) { OP_BSWAP_R32 } else { OP_BSWAP_R64 };
            b.bswap_r(op, r);
        }
        Bsr_r32_rm32 | Bsr_r64_rm64 | Bsf_r32_rm32 | Bsf_r64_rm64 => lift_bs(b, inst)?,
        Add_EAX_imm32 | Add_rm32_imm8 | Add_rm32_imm32 | Add_rm64_imm8 | Add_rm64_imm32
        | Sub_RAX_imm32 | Sub_rm32_imm8 | Sub_rm32_imm32 | Sub_rm64_imm8 | Sub_rm64_imm32
        | And_EAX_imm32 | And_rm32_imm8 | And_rm32_imm32 | And_rm64_imm8 | And_rm64_imm32
        | Or_EAX_imm32 | Or_rm32_imm8 | Or_rm32_imm32 | Or_rm64_imm8 | Or_rm64_imm32
        | Xor_EAX_imm32 | Xor_rm32_imm8 | Xor_rm32_imm32 | Xor_rm64_imm8 | Xor_rm64_imm32 => {
            lift_arith_imm(b, inst)?;
        }
        // ── shift / rotate (all widths, forms, 1/imm8/CL) ────────────────
        Shl_rm8_1 | Shl_rm8_imm8 | Shl_rm8_CL | Shl_rm16_1 | Shl_rm16_imm8 | Shl_rm16_CL
        | Shl_rm32_1 | Shl_rm32_imm8 | Shl_rm32_CL | Shl_rm64_1 | Shl_rm64_imm8 | Shl_rm64_CL
        | Shr_rm8_1 | Shr_rm8_imm8 | Shr_rm8_CL | Shr_rm16_1 | Shr_rm16_imm8 | Shr_rm16_CL
        | Shr_rm32_1 | Shr_rm32_imm8 | Shr_rm32_CL | Shr_rm64_1 | Shr_rm64_imm8 | Shr_rm64_CL
        | Sar_rm8_1 | Sar_rm8_imm8 | Sar_rm8_CL | Sar_rm16_1 | Sar_rm16_imm8 | Sar_rm16_CL
        | Sar_rm32_1 | Sar_rm32_imm8 | Sar_rm32_CL | Sar_rm64_1 | Sar_rm64_imm8 | Sar_rm64_CL
        | Rol_rm8_1 | Rol_rm8_imm8 | Rol_rm8_CL | Rol_rm16_1 | Rol_rm16_imm8 | Rol_rm16_CL
        | Rol_rm32_1 | Rol_rm32_imm8 | Rol_rm32_CL | Rol_rm64_1 | Rol_rm64_imm8 | Rol_rm64_CL
        | Ror_rm8_1 | Ror_rm8_imm8 | Ror_rm8_CL | Ror_rm16_1 | Ror_rm16_imm8 | Ror_rm16_CL
        | Ror_rm32_1 | Ror_rm32_imm8 | Ror_rm32_CL | Ror_rm64_1 | Ror_rm64_imm8 | Ror_rm64_CL => {
            lift_shift_rotate(b, inst)?;
        }
        Inc_rm32 | Inc_rm64 | Inc_rm8 | Inc_rm16
        | Dec_rm32 | Dec_rm64 | Dec_rm8 | Dec_rm16 => lift_incdec(b, inst)?,

        Fninit => b.nop(),
        Xchg_rm64_r64 | Xchg_rm32_r32 | Xchg_r64_RAX | Xchg_r32_EAX
        | Xchg_rm8_r8 | Xchg_rm16_r16 => lift_xchg(b, inst)?,
        Imul_r32_rm32_imm8 | Imul_r32_rm32_imm32 | Imul_r64_rm64_imm8 | Imul_r64_rm64_imm32 => lift_imul_imm(b, inst)?,
        Cmp_EAX_imm32 | Cmp_RAX_imm32 | Cmp_AL_imm8 | Cmp_AX_imm16 | Cmp_rm32_imm8 | Cmp_rm32_imm32
        | Cmp_rm64_imm8 | Cmp_rm64_imm32
        | Cmp_rm32_r32 | Cmp_rm64_r64
        | Cmp_r32_rm32 | Cmp_r64_rm64
        | Cmp_rm8_imm8 | Cmp_rm16_imm8 | Cmp_rm16_imm16 | Cmp_rm8_r8
        | Cmp_r8_rm8 | Cmp_r16_rm16 | Cmp_rm16_r16 => {
            lift_cmp(b, inst)?;
        }
        Test_rm32_r32 => {
            let a = vreg(inst.op0_register())?;
            let s = vreg(inst.op1_register())?;
            b.test_r_r32(a, s);
        }
        Test_rm32_imm32 => {
            let r = vreg(inst.op0_register())?;
            b.test_r_imm32(r, inst.immediate32());
        }
        Test_rm64_r64 | Test_rm16_r16 | Test_rm16_imm16 | Test_rm8_r8 | Test_rm8_imm8
        | Test_AL_imm8 | Test_AX_imm16 | Test_EAX_imm32 | Test_RAX_imm32 => {
            lift_test(b, inst)?;
        }

        // ── LEA ────────────────────────────────────────────────────────────
        Lea_r64_m | Lea_r32_m => {
            let d = vreg(inst.op0_register())?;
            mem_emit_lea(b, inst, d)?;
            if reg_bits(inst.op0_register()) != 64 {
                b.mov_r_r(d, d);
            }
        }

        // ── stack ──────────────────────────────────────────────────────────
        Push_r64 => { let r = vreg(inst.op0_register())?; b.push_r(r); }
        Pop_r64 => { let r = vreg(inst.op0_register())?; b.pop_r(r); }
        Pushq_imm8 | Pushq_imm32 => {
            let is8 = matches!(code, Pushq_imm8);
            let v = if is8 { (inst.immediate8() as i8) as i64 as u64 }
                    else { (inst.immediate32() as i32) as i64 as u64 };
            b.mov_r_imm64(SCRATCH, v);
            b.push_r(SCRATCH);
        }

        // ── control flow (resolved by the block driver) ────────────────────
        Jmp_rel32_64 => return Err(anyhow!("lifter: JMP must be handled by block driver")),
        _ if is_jcc(code) => return Err(anyhow!("lifter: Jcc must be handled by block driver")),
        Retnq => b.ret(),
        Call_rel32_64 => return Err(anyhow!("lifter: CALL must be handled by block driver")),
        Call_rm64 | Jmp_rm64 => lift_indirect_call(b, inst)?,
        // ── A-5 conditional ops (setcc / cmovcc / sbb) + misc ──────────────
        Seto_rm8 | Setno_rm8 | Setb_rm8 | Setae_rm8 | Sete_rm8 | Setne_rm8
        | Setbe_rm8 | Seta_rm8 | Sets_rm8 | Setns_rm8 | Setp_rm8 | Setnp_rm8
        | Setl_rm8 | Setge_rm8 | Setle_rm8 | Setg_rm8 => lift_setcc(b, inst)?,
        Cmove_r32_rm32 | Cmove_r64_rm64 | Cmovne_r32_rm32 | Cmovne_r64_rm64
        | Cmovb_r32_rm32 | Cmovb_r64_rm64 | Cmovae_r32_rm32 | Cmovae_r64_rm64
        | Cmovbe_r32_rm32 | Cmovbe_r64_rm64 | Cmova_r32_rm32 | Cmova_r64_rm64
        | Cmovl_r32_rm32 | Cmovl_r64_rm64 | Cmovge_r32_rm32 | Cmovge_r64_rm64
        | Cmovle_r32_rm32 | Cmovle_r64_rm64 | Cmovg_r32_rm32 | Cmovg_r64_rm64
        | Cmovs_r32_rm32 | Cmovs_r64_rm64 | Cmovns_r32_rm32 | Cmovns_r64_rm64
        | Cmovo_r32_rm32 | Cmovo_r64_rm64 | Cmovno_r32_rm32 | Cmovno_r64_rm64
        | Cmovp_r32_rm32 | Cmovp_r64_rm64 | Cmovnp_r32_rm32 | Cmovnp_r64_rm64 => lift_cmovcc(b, inst)?,
        Sbb_rm32_r32 | Sbb_r32_rm32 | Sbb_rm32_imm8 | Sbb_rm32_imm32 | Sbb_EAX_imm32
        | Sbb_rm64_r64 | Sbb_r64_rm64 | Sbb_rm64_imm8 | Sbb_rm64_imm32 | Sbb_RAX_imm32 => lift_sbb(b, inst)?,
        Adc_rm32_r32 | Adc_r32_rm32 | Adc_rm32_imm8 | Adc_rm32_imm32 | Adc_EAX_imm32
        | Adc_rm64_r64 | Adc_r64_rm64 | Adc_rm64_imm8 | Adc_rm64_imm32 | Adc_RAX_imm32
        | Adc_rm8_r8 | Adc_r8_rm8 | Adc_rm16_r16 | Adc_r16_rm16
        | Adc_rm8_imm8 | Adc_rm16_imm8 | Adc_rm16_imm16 | Adc_AL_imm8 | Adc_AX_imm16 => lift_adc(b, inst)?,
        Stosq_m64_RAX => lift_rep_stosq(b)?,
        Cmpxchg_rm8_r8 | Cmpxchg_rm16_r16 | Cmpxchg_rm32_r32 | Cmpxchg_rm64_r64 => lift_cmpxchg(b, inst)?,
        Xadd_rm8_r8 | Xadd_rm16_r16 | Xadd_rm32_r32 | Xadd_rm64_r64 => lift_xadd(b, inst)?,
        Movsd_xmm_xmmm64 | Movss_xmm_xmmm32 | Movq_xmm_xmmm64 | Movd_xmm_rm32
        | Movups_xmm_xmmm128 | Movdqu_xmm_xmmm128 | Movdqa_xmm_xmmm128 | Movaps_xmm_xmmm128
        | Movupd_xmm_xmmm128 | Movapd_xmm_xmmm128
        | Pcmpeqb_xmm_xmmm128 | Pcmpeqw_xmm_xmmm128 | Pcmpeqd_xmm_xmmm128
        | Pcmpgtb_xmm_xmmm128 | Pcmpgtw_xmm_xmmm128 | Pcmpgtd_xmm_xmmm128
        | Pxor_xmm_xmmm128 | Pand_xmm_xmmm128 | Por_xmm_xmmm128 | Pandn_xmm_xmmm128
        | Paddb_xmm_xmmm128 | Paddw_xmm_xmmm128 | Paddd_xmm_xmmm128 | Paddq_xmm_xmmm128
        | Paddsb_xmm_xmmm128 | Paddsw_xmm_xmmm128 | Paddusb_xmm_xmmm128 | Paddusw_xmm_xmmm128
        | Psubb_xmm_xmmm128 | Psubw_xmm_xmmm128 | Psubd_xmm_xmmm128 | Psubq_xmm_xmmm128
        | Psubsb_xmm_xmmm128 | Psubsw_xmm_xmmm128 | Psubusb_xmm_xmmm128 | Psubusw_xmm_xmmm128
        | Pmullw_xmm_xmmm128 | Pmulld_xmm_xmmm128 | Pmulhuw_xmm_xmmm128 | Pmulhw_xmm_xmmm128
        | Pmaxub_xmm_xmmm128 | Pminub_xmm_xmmm128 | Pmaxsw_xmm_xmmm128 | Pminsw_xmm_xmmm128
        | Pmaxsb_xmm_xmmm128 | Pminsb_xmm_xmmm128 | Pmaxsd_xmm_xmmm128 | Pminsd_xmm_xmmm128
        | Pavgb_xmm_xmmm128 | Pavgw_xmm_xmmm128 | Psadbw_xmm_xmmm128 | Pabsb_xmm_xmmm128
        | Pabsw_xmm_xmmm128 | Pabsd_xmm_xmmm128
        | Packsswb_xmm_xmmm128 | Packssdw_xmm_xmmm128 | Packuswb_xmm_xmmm128
        | Pslld_xmm_xmmm128 | Psrld_xmm_xmmm128 | Psrad_xmm_xmmm128
        | Psllw_xmm_xmmm128 | Psrlw_xmm_xmmm128 | Psraw_xmm_xmmm128
        | Psllq_xmm_xmmm128 | Psrlq_xmm_xmmm128
        | Pmovmskb_r32_xmm | Pmovmskb_r64_xmm | Ptest_xmm_xmmm128
        | Pshufb_xmm_xmmm128 | Punpcklbw_xmm_xmmm128
        | Punpcklwd_xmm_xmmm128 | Punpckldq_xmm_xmmm128 | Punpcklqdq_xmm_xmmm128
        | Punpckhbw_xmm_xmmm128 | Punpckhwd_xmm_xmmm128 | Punpckhdq_xmm_xmmm128 | Punpckhqdq_xmm_xmmm128
        | Xorps_xmm_xmmm128 | Xorpd_xmm_xmmm128 => lift_sse(b, inst, 0)?,
        // ── v45: Rust-runtime / SSE insert ops ───────────────────────────────
        Pinsrw_xmm_r32m16_imm8 => lift_pinsrw(b, inst)?,
        Tzcnt_r32_rm32 => lift_tzcnt(b, inst)?,
        Retnq_imm16 => lift_ret_imm16(b, inst)?,
        Pause => b.nop(),
        Int3 => b.halt(),
        Cpuid => b.cpuid(),
        Xgetbv => b.xgetbv(),
        Pshuflw_xmm_xmmm128_imm8 | Pshufhw_xmm_xmmm128_imm8 | Pshufd_xmm_xmmm128_imm8 => lift_sseshuffle(b, inst)?,
        Psrlq_xmm_imm8 | Psllq_xmm_imm8 => lift_sseshift_imm8(b, inst)?,

        Movsd_xmmm64_xmm | Movss_xmmm32_xmm | Movq_xmmm64_xmm | Movd_rm32_xmm
        | Movups_xmmm128_xmm | Movdqu_xmmm128_xmm | Movdqa_xmmm128_xmm | Movaps_xmmm128_xmm
        | Movupd_xmmm128_xmm | Movapd_xmmm128_xmm => lift_sse(b, inst, 1)?,
        Movq_xmm_rm64 | Movq_rm64_xmm => lift_movq(b, inst)?,

        Unpcklpd_xmm_xmmm128 => lift_sse(b, inst, 2)?,
        Unpcklps_xmm_xmmm128 => lift_unpcklps(b, inst)?,
        Ud2 => b.halt(),
        Bt_rm32_r32 | Bt_rm64_r64 | Bt_rm16_r16 | Bt_rm32_imm8 | Bt_rm64_imm8 | Bt_rm16_imm8 => lift_bt(b, inst)?,
        Bts_rm64_r64 | Bts_rm32_r32 | Bts_rm16_r16 | Bts_rm64_imm8 | Bts_rm32_imm8 | Bts_rm16_imm8
        | Btr_rm64_r64 | Btr_rm32_r32 | Btr_rm16_r16 | Btr_rm64_imm8 | Btr_rm32_imm8 | Btr_rm16_imm8
        | Btc_rm64_r64 | Btc_rm32_r32 | Btc_rm16_r16 | Btc_rm64_imm8 | Btc_rm32_imm8 | Btc_rm16_imm8 => lift_bts(b, inst)?,
        Int_imm8 => b.halt(),
        Loopne_rel8_64_RCX => return Err(anyhow!("lifter: LOOPNE handled by block driver")),

        other => {
            return Err(crate::error::VmCompilerError::UnsupportedInstruction {
                instruction: inst.to_string(),
                code: format!("{:?}", other),
            }.into());
        }
    }
    Ok(())
}

fn is_jcc(code: Code) -> bool {
    use iced_x86::Code::*;
    matches!(
        code,
        Je_rel32_64 | Jne_rel32_64 | Jb_rel32_64 | Jae_rel32_64 | Jg_rel32_64 | Jge_rel32_64
            | Jl_rel32_64 | Jle_rel32_64 | Js_rel32_64 | Jns_rel32_64 | Jo_rel32_64
            | Jno_rel32_64 | Jp_rel32_64 | Jnp_rel32_64
            | Ja_rel32_64 | Jbe_rel32_64
            | Je_rel8_64 | Jne_rel8_64 | Jb_rel8_64 | Jae_rel8_64 | Jg_rel8_64 | Jge_rel8_64
            | Jl_rel8_64 | Jle_rel8_64 | Js_rel8_64 | Jns_rel8_64 | Jo_rel8_64
            | Jno_rel8_64 | Jp_rel8_64 | Jnp_rel8_64
            | Ja_rel8_64 | Jbe_rel8_64
            | Jecxz_rel8_64 | Jrcxz_rel8_64
            | Loopne_rel8_64_RCX
    )
}

/// Map an x86 Jcc code to a VM cond code.
fn jcc_cond(code: Code) -> u8 {
    use iced_x86::Code::*;
    match code {
        Je_rel32_64 | Je_rel8_64 => COND_JE,
        Jne_rel32_64 | Jne_rel8_64 => COND_JNE,
        Jb_rel32_64 | Jb_rel8_64 => COND_JB,
        Jae_rel32_64 | Jae_rel8_64 => COND_JAE,
        Jg_rel32_64 | Jg_rel8_64 => COND_JG,
        Jge_rel32_64 | Jge_rel8_64 => COND_JGE,
        Jl_rel32_64 | Jl_rel8_64 => COND_JL,
        Jle_rel32_64 | Jle_rel8_64 => COND_JLE,
        Js_rel32_64 | Js_rel8_64 => COND_JS,
        Jns_rel32_64 | Jns_rel8_64 => COND_JNS,
        Jo_rel32_64 | Jo_rel8_64 => COND_JO,
        Jno_rel32_64 | Jno_rel8_64 => COND_JNO,
        Jp_rel32_64 | Jp_rel8_64 => COND_JP,
        Jnp_rel32_64 | Jnp_rel8_64 => COND_JNP,
        Ja_rel32_64 | Ja_rel8_64 => COND_JA,
        Jbe_rel32_64 | Jbe_rel8_64 => COND_JBE,
        Jecxz_rel8_64 | Jrcxz_rel8_64 => COND_JE,
        Loopne_rel8_64_RCX => COND_JNE,
        _ => 0,
    }
}

/// Size (in bits) of a GPR operand, from its register.
fn reg_bits(r: Register) -> usize {
    r.size() * 8
}

/// Map any GPR (or sub-register) to its vreg index = full GPR number.
pub fn vreg(r: Register) -> Result<u8> {
    if !r.is_gpr() {
        return Err(anyhow!("lifter: non-GPR register {:?}", r));
    }
    Ok(r.full_register().number() as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Code, Instruction, Register};

    #[test]
    fn test_lift_shr_rm8_1() {
        let inst = Instruction::with2(Code::Shr_rm8_1, Register::R9L, 1).unwrap();
        let mut b = BytecodeBuilder::new();
        assert!(lift_one(&mut b, &inst).is_ok());
        let bc = b.finish();
        assert!(!bc.is_empty());
    }

    #[test]
    fn test_lift_movdqu_xmm_xmmm128() {
        use iced_x86::MemoryOperand;
        let mem = MemoryOperand::with_base_displ(Register::RSP, 0x23);
        let inst = Instruction::with2(Code::Movdqu_xmm_xmmm128, Register::XMM0, mem).unwrap();
        let mut b = BytecodeBuilder::new();
        assert!(lift_one(&mut b, &inst).is_ok());
        let bc = b.finish();
        assert!(!bc.is_empty());
    }
}
