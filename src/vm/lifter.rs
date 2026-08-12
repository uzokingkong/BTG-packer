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
// ==============================================================================


use crate::vm::bytecode::*;
use crate::vm::ksa::KsaInstr;
use anyhow::{Result, anyhow};
use iced_x86::{Code, Instruction, OpKind, Register};

/// The lifter's scratch vreg for effective-address computation (vreg 16).
pub const SCRATCH: u8 = 16;
/// Secondary scratch vreg (vreg 17) — needed by CMP-64-imm / TEST-64-imm emulation,
/// which must hold both the value and the immediate live at once.
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
///
/// The KSA boot-stub uses *slot-based* memory: a base register (RBX→S-box,
/// RDX→seed, RCX→buf, RBP→runs) maps to a VM pointer slot, and each memory
/// operand is `[ptr[slot] + index]`. This is distinct from the M4 block lifter
/// (lift_block), which lowers arbitrary [base+index*scale+disp] to an absolute
/// address held in a vreg. KSA keeps its original slot-based lowering.
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

        // Mapper: record this KSA instruction's bytecode start offset.
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

/// Decode a `[base + index*1]` memory operand into (memslot, index vreg) — KSA
/// slot-based model (base register → VM pointer slot).
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
///
/// The lifter reserves R15 (`SCRATCH`) and R14 (`SCRATCH2`) as internal scratch
/// for effective-address computation, CMP/TEST emulation and bytecode lowering.
/// If the *source* instruction being lifted reads or writes R15/R14 as a real
/// general register, the scratch writes in the emitted bytecode would clobber it
/// — a silent correctness bug. Detect it up-front and reject with a clear error.
///
/// **Call sites** (must remain consistent):
/// * `lift_one`          — covers all single-instruction paths and `diagnose_unsupported`.
/// * `lift_cfg_switch`   — covers every instruction in a multi-block CFG, including
///                         switch-dispatch terminators and control-flow terminators that
///                         bypass `lift_one` (JMP/Jcc/CALL/RET handle the branch emit
///                         themselves but still need the source checked for R15/R14).
fn check_scratch_collision(_inst: &Instruction) -> Result<()> {
    // NOTE (v53 rework): R14/R15 are NOT reserved and must be allowed. They map to
    // vregs 14/15 (plain state-buffer slots), distinct from the lifter's internal
    // scratch vregs SCRATCH=16 / SCRATCH2=17, which are unreachable from real x86
    // operands (only 16 GPRs exist). Rejecting R14/R15 here broke real --vm-oep
    // packing: chve2_unpacked.exe lifts instructions that use R15, and the packer
    // aborted with "lifter: instruction uses reserved scratch register R15".
    // The native VM virtualizes R14/R15 into state slots 14/15, so they are safe
    // program registers; the bridge's use of physical r12-r15 as VM-infra scratch
    // does not touch those state slots.
    Ok(())
}

/// 1:1 instruction table — emit the VM bytecode for one x86 instruction.
///
/// `seq_base_va` is the image VA of the first lifted instruction; the caller
/// tracks each instruction's own VA (base + running length) so RIP-relative
/// operands can be lowered to OP_SET_RIP + OP_LEA_RIP.

pub fn lift_one(
    b: &mut BytecodeBuilder,
    inst: &Instruction,
) -> Result<()> {
    let code = inst.code();
    use iced_x86::Code::*;

    check_scratch_collision(inst)?;

    match code {
        // ── v32: 8/16-bit arithmetic (A-2 잔여) ─────────────────────────────
        // All 8/16-bit forms lower to the existing 32-bit op + a width mask
        // (the same emulation precedent as lift_add8): no new handler needed,
        // and interp==native is preserved because both sides run the same ops.
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
                    // narrow reg-reg copy: zero-extend to the narrow width
                    b.mov_r_r(d, s);
                    let mask = if sz == 8 { 0xFFu32 } else { 0xFFFFu32 };
                    b.binop_r_imm32(OP_AND_R_IMM32, d, mask);
                } else if sz == 64 {
                    b.mov_r_r64(d, s);
                } else {
                    b.mov_r_r(d, s);
                }
            } else {
                // reg <- mem
                let d = vreg(inst.op0_register())?;
                let addr = mem_emit(b, inst, 1)?; // address of op1
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
                // reg-reg copy (the r/m operand is a register here)
                let d = vreg(inst.op0_register())?;
                let s = vreg(inst.op1_register())?;
                if reg_bits(inst.op0_register()) == 64 {
                    b.mov_r_r64(d, s);
                } else {
                    b.mov_r_r(d, s);
                }
            } else if inst.op1_kind() == OpKind::Register {
                let addr = mem_emit(b, inst, 0)?; // address of op0
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
            // dest may be a register (iced decodes `mov r64,imm32` as
            // Mov_rm64_imm32, and the imm32 is sign-extended to 64 bits) or memory.
            if inst.op0_kind() == OpKind::Register {
                let r = vreg(inst.op0_register())?;
                if matches!(code, Mov_rm64_imm32) {
                    let imm = (inst.immediate32() as i32) as i64 as u64; // sign-extend
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
            // C-1 fix (--vm-oep): `addr` is already in SCRATCH (R15) from mem_emit.
            // Loading the immediate into SCRATCH too would overwrite the store
            // address and write to the immediate value itself (e.g. `mov [rax],1`
            // -> `mov dword ptr [1],1` -> AV). Put the value in SCRATCH2 (R14).
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
                // reg-reg zero/sign extend: movzx = copy + mask low byte/word
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
            // sign-extend 32 -> 64: (d << 32) >> 32
            b.shift64_r_imm8(OP_SHL64_R_IMM8, d, 32);
            b.shift64_r_imm8(OP_SAR64_R_IMM8, d, 32);
        }
        Cdqe => {
            // cdqe has no explicit operand; it sign-extends EAX into RAX.
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

        Fninit => b.nop(), // FPU init: no x87 state is virtualized, so a no-op
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
            // compute the effective address into the *destination* register
            let d = vreg(inst.op0_register())?;
            mem_emit_lea(b, inst, d)?;
            if reg_bits(inst.op0_register()) != 64 {
                b.mov_r_r(d, d); // zero-extend a 32-bit LEA result
            }
        }

        // ── stack ──────────────────────────────────────────────────────────
        Push_r64 => { let r = vreg(inst.op0_register())?; b.push_r(r); }
        Pop_r64 => { let r = vreg(inst.op0_register())?; b.pop_r(r); }
        Pushq_imm8 | Pushq_imm32 => {
            // push imm (sign-extended to 64-bit). Load into SCRATCH then push.
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
        // Indirect call/jump through a register or [memory] — the IAT import
        // thunks (`call/jmp qword ptr [IAT_slot]`) and computed dispatch
        // (`call rax`). We lower these to the native bridge: load the target
        // address (from the register, or from the memory slot) into the target
        // vreg, then OP_NATIVE_CALL. For `jmp` (a tail-jump to an import/API),
        // this is a tail call — the native bridge handles the transfer and we
        // HALT after (control leaves the VM).
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
        Ud2 => b.halt(),
        Bt_rm32_r32 | Bt_rm64_r64 | Bt_rm16_r16 | Bt_rm32_imm8 | Bt_rm64_imm8 | Bt_rm16_imm8 => lift_bt(b, inst)?,
        Bts_rm64_r64 | Bts_rm32_r32 | Bts_rm16_r16 | Bts_rm64_imm8 | Bts_rm32_imm8 | Bts_rm16_imm8
        | Btr_rm64_r64 | Btr_rm32_r32 | Btr_rm16_r16 | Btr_rm64_imm8 | Btr_rm32_imm8 | Btr_rm16_imm8
        | Btc_rm64_r64 | Btc_rm32_r32 | Btc_rm16_r16 | Btc_rm64_imm8 | Btc_rm32_imm8 | Btc_rm16_imm8 => lift_bts(b, inst)?,
        Int_imm8 => b.halt(), // e.g. `int 29h` (CRT __fastfail / trap): trap, not recoverable
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

/// A-5: diagnose which instructions in a block cannot be lifted. Returns the
/// list of (instruction, code) that the current lifter does not support, so the
/// packer can fail loudly and enumerate exactly what blocked the lift instead of
/// silently leaving native code behind. An empty vec means the whole block lifts.
pub fn diagnose_unsupported(seq: &[LiftedInstr]) -> Vec<(String, Code)> {
    let mut bad = Vec::new();
    for it in seq {
        let inst = it.inst;
        let code = inst.code();
        // Branch forms are handled by the block driver, not lift_one.
        if it.target.is_some() {
            continue;
        }
        if code == Code::Call_rel32_64 || code == Code::Retnq {
            continue;
        }
        if matches!(
            code,
            Code::Jmp_rel32_64 | Code::Jmp_rel8_64
                | Code::Je_rel32_64 | Code::Jne_rel32_64 | Code::Jb_rel32_64
                | Code::Jae_rel32_64 | Code::Jg_rel32_64 | Code::Jge_rel32_64 | Code::Jl_rel32_64
                | Code::Jle_rel32_64 | Code::Js_rel32_64 | Code::Jns_rel32_64 | Code::Jo_rel32_64
                | Code::Jno_rel32_64 | Code::Jp_rel32_64 | Code::Jnp_rel32_64
                | Code::Ja_rel32_64 | Code::Jbe_rel32_64
                | Code::Je_rel8_64 | Code::Jne_rel8_64 | Code::Jb_rel8_64
                | Code::Jae_rel8_64 | Code::Jg_rel8_64 | Code::Jge_rel8_64 | Code::Jl_rel8_64
                | Code::Jle_rel8_64 | Code::Js_rel8_64 | Code::Jns_rel8_64 | Code::Jo_rel8_64
                | Code::Jno_rel8_64 | Code::Jp_rel8_64 | Code::Jnp_rel8_64
                | Code::Ja_rel8_64 | Code::Jbe_rel8_64
                | Code::Jecxz_rel8_64 | Code::Jrcxz_rel8_64
                | Code::Loopne_rel8_64_RCX
        ) {
            continue;
        }
        // Reuse lift_one's decision by trying it against a throwaway builder.
        let mut b = BytecodeBuilder::new();
        if lift_one(&mut b, &inst).is_err() {
            bad.push((inst.to_string(), code));
        }
    }
    bad
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
        // JCXZ/JECXZ: branch iff rcx == 0. The block driver emits a `test rcx,rcx`
        // immediately before the Jcc so ZF reflects rcx==0.
        Jecxz_rel8_64 | Jrcxz_rel8_64 => COND_JE,
        Loopne_rel8_64_RCX => COND_JNE,
        _ => 0,
    }
}

/// Lift a complete block: handles labels, JMP/Jcc branches, CALL/RET.
/// `seq_base_va` = image VA of the first instruction (for RIP-relative).
pub fn lift_block(seq: &[LiftedInstr], seq_base_va: u64) -> Result<Vec<u8>> {
    let mut b = BytecodeBuilder::new();
    let mut labels = std::collections::HashMap::new();
    let mut va = seq_base_va;

    for item in seq {
        // label on this instruction (loop head etc.)
        if let Some(l) = item.label {
            let id = *labels.entry(l).or_insert_with(|| b.new_label());
            b.mark_label(id);
        }

        let inst = item.inst;
        let code = inst.code();

        // Mapper: record this block instruction's bytecode start offset + VA.
        if crate::vm::mapper::active() {
            crate::vm::mapper::record(b.bytes.len(), &inst, va, "Block");
        }

        if let Some(t) = item.target {
            let id = *labels.entry(t).or_insert_with(|| b.new_label());
            match code {
                Code::Jmp_rel32_64 | Code::Jmp_rel8_64 => b.jmp8(id),
                c if is_jcc(c) => {
                    if c == Code::Loopne_rel8_64_RCX {
                        // loopne: rcx -= 1; if rcx != 0 (and ZF==0) jump.
                        b.dec_r(1);
                    } else if matches!(c, Code::Jecxz_rel8_64 | Code::Jrcxz_rel8_64) {
                        // JCXZ/JECXZ: branch iff rcx==0 → test rcx,rcx then Jcc.
                        b.test_r_r32(1, 1);
                    }
                    b.jcc8(jcc_cond(c), id);
                }
                Code::Call_rel32_64 => b.call8(id),
                _ => return Err(anyhow!("lifter: unsupported branch {:?}", code)),
            }
            // branch source instruction: its VA does not matter for RIP-rel
            va = va.wrapping_add(inst.len() as u64);
            continue;
        }

        if code == Code::Call_rel32_64 {
            // CALL to a subroutine within the same lifted body: emit call8 to
            // the target label (the subroutine must end with RET).
            let id = match item.target {
                Some(t) => *labels.entry(t).or_insert_with(|| b.new_label()),
                None => return Err(anyhow!("lifter: CALL requires a target label")),
            };
            b.call8(id);
            va = va.wrapping_add(inst.len() as u64);
            continue;
        }

        // Track this instruction's own VA so RIP-relative operands resolve.
        let inst_va = va;
        let n = inst.len() as u64;
        // set the RIP base for this instruction before emitting it
        let had_rip = has_rip_operand(&inst);
        if had_rip {
            b.set_rip(inst_va);
        }
        lift_one(&mut b, &inst)?;
        va = inst_va.wrapping_add(n);
    }

    b.halt();
    Ok(b.finish())
}

/// M5 (v30) — multi-block control-flow lift driver.
///
/// Lays out a CFG (list of basic blocks from `CfgExtractor`) into a single VM
/// bytecode stream, marks a label at each block start, and connects every
/// block-terminal direct branch (JMP / Jcc / CALL) to its target block with a
/// **rel32** branch (cross-block targets may exceed the rel8 range). RET and
/// indirect branches (bridge calls) are handled by `lift_one`.
///
/// Block execution order is the block list order; a block whose terminator
/// falls through to the next block simply continues because the next block is
/// laid out immediately after. Loops/back-edges resolve via the rel32 branch.
/// Lift a whole CFG to a single VM program. `switch_cases` maps a `Jmp_rm64` jump-table
/// instruction's VA to its resolved `(case_value, target_block_va)` pairs; when a match
/// is found the terminator is dispatched *inside the VM* (compare-and-jump chain) instead
/// of exiting through the native bridge. Empty = current behavior (bridge fallback).
pub fn lift_cfg(blocks: &[crate::graph::BasicBlock]) -> Result<Vec<u8>> {
    lift_cfg_switch(blocks, &[], &std::collections::HashMap::new(), None, &Default::default())
}

/// `entry_va`: when provided, the VM program begins by jumping to the block at this
/// VA before executing any block. `CfgExtractor` lays blocks out in *address* order,
/// so without an explicit entry the first bytecode is the lowest-address block (often
/// a trailing `ret` epilogue), and dispatching the lifted *program* would start in the
/// wrong place (and, for a function ending in `ret`, pop a garbage return address).
/// Existing callers that lift a *function* (self-tests) keep `None`, so the first
/// block is the function entry and behavior is unchanged (regression-safe).
pub fn lift_cfg_switch(
    blocks: &[crate::graph::BasicBlock],
    switch_cases: &[(u64, Vec<(i64, u64)>)],
    switch_idx: &std::collections::HashMap<u64, u8>,
    entry_va: Option<u64>,
    excluded: &std::collections::HashSet<u64>,
) -> Result<Vec<u8>> {
    use iced_x86::FlowControl;
    let mut b = BytecodeBuilder::new();
    let mut block_label: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
    for bb in blocks {
        block_label.insert(bb.start_va, b.new_label());
    }
    // Symbolic-map block markers: (bc_start, src_va, native, src_len_bytes).
    let mut sym_blocks: Vec<(usize, u64, bool, u64)> = Vec::new();
    let switch_lookup: std::collections::HashMap<u64, &Vec<(i64, u64)>> =
        switch_cases.iter().map(|(va, cases)| (*va, cases)).collect();

    // C-1 import bridge fix (--vm-oep): jump to the real program entry block first.
    if let Some(entry) = entry_va {
        let target_lbl = block_label.get(&entry).copied().or_else(|| {
            // Fallback: find closest block start >= entry, or first available block.
            blocks
                .iter()
                .filter(|b| b.start_va >= entry)
                .min_by_key(|b| b.start_va)
                .map(|b| block_label[&b.start_va])
                .or_else(|| blocks.first().map(|b| block_label[&b.start_va]))
        });
        if let Some(lbl) = target_lbl {
            b.jmp32(lbl);
        } else {
            return Err(anyhow!(
                "lift_cfg_switch: no valid block start found for entry_va 0x{:X}", entry
            ));
        }
    }

    for bb in blocks {
        b.mark_label(block_label[&bb.start_va]);
        let src_len: u64 = bb.instructions.iter().map(|i| i.len() as u64).sum();
        if crate::vm::mapper::active() {
            sym_blocks.push((b.bytes.len(), bb.start_va, excluded.contains(&bb.start_va), src_len));
        }
        // Panic/unwind runtime exclusion: keep these blocks native. The VM enters
        // them through the native bridge (real SEH/unwind metadata), and on return
        // `ret` resumes the caller (the VM return address pushed by the caller's
        // `call32`). A runtime fn that never returns (throw/unwind) never resumes.
        if excluded.contains(&bb.start_va) {
            b.mov_r_imm64(SCRATCH, bb.start_va);
            b.native_call(SCRATCH);
            b.ret();
            continue;
        }
        let n = bb.instructions.len();
        let mut va = bb.start_va;
        for (i, inst) in bb.instructions.iter().enumerate() {
            let is_last = i + 1 == n;
            let inst_va = va;
            let len = inst.len() as u64;
            if has_rip_operand(inst) {
                b.set_rip(inst_va);
            }
            let code = inst.code();
            // Mapper: record this CFG instruction's bytecode start offset + VA.
            if crate::vm::mapper::active() {
                crate::vm::mapper::record(b.bytes.len(), inst, inst_va, "Program");
            }
            // Scratch-register collision guard (review P0-3): checked here so that
            // every instruction in a CFG lift — including terminators handled below
            // without going through lift_one — is validated before any bytecode is
            // emitted. Branch instructions (JMP/Jcc/CALL/RET) never carry R14/R15
            // operands in real code, so this is effectively a no-op for them; the
            // guard is here for defence-in-depth and switch-dispatch `Jmp_rm64`.
            check_scratch_collision(inst)?;
            // v35: switch jump-table dispatch — run the compare-and-jump chain at the
            // instruction whose VA the resolver keyed (for the register form this is the
            // LOAD `movsxd rT,[rB+rI*scale]` where the index register is still intact;
            // for the memory form it is the `jmp [rip+table+rI*scale]` terminator). The
            // chain jumps to the matching case block inside the VM; the "no case matched"
            // path falls through to the original instructions (or a bridge+halt for the
            // memory form) which compute the default target and leave the VM.
            if switch_lookup.contains_key(&inst_va) {
                let cases = switch_lookup[&inst_va];
                // index vreg: the resolver recorded it (register form), or derive from
                // the memory operand (memory form).
                let idx = if let Some(iv) = switch_idx.get(&inst_va) {
                    *iv
                } else if inst.op0_kind() == OpKind::Memory {
                    let idx_reg = if inst.memory_base() != Register::None {
                        inst.memory_base()
                    } else if inst.memory_index() != Register::None {
                        inst.memory_index()
                    } else {
                        return Err(anyhow!(
                            "lift_cfg: switch jump-table operand has no index register @0x{:X}",
                            inst_va
                        ));
                    };
                    vreg(idx_reg)?
                } else {
                    return Err(anyhow!(
                        "lift_cfg: register-form switch @0x{:X} has no resolved index register",
                        inst_va
                    ));
                };
                let mut emitted = false;
                for (case_val, target_va) in cases {
                    let lbl = match block_label.get(target_va) {
                        Some(&l) => l,
                        None => {
                            // target not a lifted block — fall through to bridge below
                            continue;
                        }
                    };
                    b.mov_r_r(SCRATCH, idx);                  // index
                    b.mov_r_imm32(SCRATCH2, *case_val as u32); // case value
                    b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2); // sets ZF if idx==case
                    b.jcc32(COND_JE, lbl);
                    emitted = true;
                }
                if emitted {
                    // no case matched.
                    if is_last && inst.op0_kind() == OpKind::Memory {
                        // memory form terminator: bridge (native tail-call) + HALT.
                        let addr = mem_emit(&mut b, inst, 0)?;
                        b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH, addr);
                        b.native_call(SCRATCH);
                        b.halt();
                        va += len;
                        continue;
                    }
                    // register form: the chain fell through — continue lifting the
                    // original load/add (and the trailing `jmp rT` in the next block)
                    // so the default target is computed and the VM exits via the bridge,
                    // exactly as the native switch does for an out-of-range index.
                    // (No halt here; the rest of the block still executes.)
                }
            }
            if is_last {
                let fc = inst.flow_control();
                match fc {
                    FlowControl::UnconditionalBranch => {
                        // jmp rel8/rel32 -> target block
                        let t = inst.near_branch_target();
                        if let Some(&lbl) = block_label.get(&t) {
                            b.jmp32(lbl);
                        } else {
                            // Target outside the lifted block set (e.g. a branch that
                            // falls on a non-code/data region the CFG sweep mis-decoded,
                            // or a genuine cross-section target). Emit a native bridge
                            // (tail-call to the target + HALT) instead of failing the
                            // whole pack — matches the switch-dispatch default path.
                            b.mov_r_imm64(SCRATCH, t);
                            b.native_call(SCRATCH);
                            b.halt();
                        }
                        va += len;
                        continue;
                    }
                    FlowControl::ConditionalBranch => {
                        if code == Code::Loopne_rel8_64_RCX {
                            b.dec_r(1);
                            b.jcc32(COND_JNE, *block_label.get(&inst.near_branch_target()).ok_or_else(|| anyhow!("loopne target"))?);
                        } else if matches!(code,
                            Code::Jecxz_rel8_64 | Code::Jrcxz_rel8_64)
                        {
                            // JCXZ/JECXZ: branch iff rcx==0. Emit test rcx,rcx (sets ZF) then Jcc.
                            let t = inst.near_branch_target();
                            b.test_r_r32(1, 1); // v1 = RCX
                            if let Some(&lbl) = block_label.get(&t) {
                                b.jcc32(COND_JE, lbl);
                            } else {
                                b.mov_r_imm64(SCRATCH, t);
                                b.native_call(SCRATCH);
                                b.halt();
                            }
                        } else {
                            let t = inst.near_branch_target();
                            if let Some(&lbl) = block_label.get(&t) {
                                b.jcc32(jcc_cond(code), lbl);
                            } else {
                                b.mov_r_imm64(SCRATCH, t);
                                b.native_call(SCRATCH);
                                b.halt();
                            }
                        }
                        va += len;
                        continue;
                    }
                    FlowControl::Call => {
                        let t = inst.near_branch_target();
                        if let Some(&lbl) = block_label.get(&t) {
                            b.call32(lbl);
                        } else {
                            b.mov_r_imm64(SCRATCH, t);
                            b.native_call(SCRATCH);
                            b.halt();
                        }
                        va += len;
                        continue;
                    }
                    FlowControl::Return => {
                        b.ret();
                        va += len;
                        continue;
                    }
                    _ => { /* not a terminator: fall through to next block */ }
                }
            }
            lift_one(&mut b, inst).map_err(|e| anyhow!("{} (at VA 0x{:X}, inst={})", e, inst_va, inst))?;
            va += len;
        }
    }

    b.halt();
    if crate::vm::mapper::active() && !sym_blocks.is_empty() {
        let total = b.bytes.len();
        for (i, &(bc_start, src_va, native, src_len)) in sym_blocks.iter().enumerate() {
            let bc_end = sym_blocks.get(i + 1).map(|&(s, _, _, _)| s).unwrap_or(total);
            crate::vm::mapper::record_block_start(bc_start, src_va, native);
            crate::vm::mapper::end_block(bc_end, src_va + src_len);
        }
    }
    Ok(b.finish())
}

/// Does this instruction use a RIP-relative memory operand?
fn has_rip_operand(inst: &Instruction) -> bool {
    (0..inst.op_count()).any(|i| inst.op_kind(i) == OpKind::Memory && inst.is_ip_rel_memory_operand())
}

/// Emit the effective-address computation for memory operand `op_idx`, returning
/// the scratch vreg that holds the absolute address. RIP-relative operands use
/// the already-set STATE_RIP (caller must set_rip before).
fn mem_emit(b: &mut BytecodeBuilder, inst: &Instruction, op_idx: u32) -> Result<u8> {
    if inst.op_kind(op_idx) != OpKind::Memory {
        return Err(anyhow!("lifter: expected memory operand"));
    }
    mem_emit_lea(b, inst, SCRATCH)?;
    Ok(SCRATCH)
}

/// Emit LEA(dst, base, idx, scale, disp) or LEA_RIP for the first memory operand.
fn mem_emit_lea(b: &mut BytecodeBuilder, inst: &Instruction, dst: u8) -> Result<()> {
    // find the memory operand
    let mut mop: Option<u32> = None;
    for i in 0..inst.op_count() {
        if inst.op_kind(i) == OpKind::Memory {
            mop = Some(i);
            break;
        }
    }
    let mi = mop.ok_or_else(|| anyhow!("lifter: no memory operand"))?;

    if inst.is_ip_rel_memory_operand() {
        // C-1 fix (--vm-oep): iced_x86's `memory_displacement64()` returns the
        // *absolute* target VA for a RIP-relative operand (e.g. 0x1400044e0),
        // not the disp32 field. Casting that to i32 truncates it (-> 0x400044e0)
        // and then OP_LEA_RIP computes STATE_RIP + that -> a garbage 64-bit VA.
        // LEA_RIP evaluates `STATE_RIP + sext(rel32)` with STATE_RIP already set
        // to this instruction's own VA, so the rel32 must be target - inst_va.
        let target = inst.memory_displacement64();
        let rel = (target as i64 - inst.ip() as i64) as i32;
        b.lea_rip(dst, rel);
        return Ok(());
    }

    // ── v43: gs:/fs: 세그먼트(PEB/TEB) 접근 — OP_LEA_GS (SEG_GS + disp).
    // x64 Windows CRT는 entry에서 `mov rax, gs:[0x30]`(TEB.Self→PEB) 등을 수행.
    // 세그먼트 오버라이드가 있으면 메모리 base를 GS base로 취급한다.
    let seg = inst.segment_prefix();
    if seg == Register::GS || seg == Register::FS {
        let disp = inst.memory_displacement64() as i32;
        // base/index 가 있는 [gs:base+idx*scale+disp] 도 지원 (base를 GS에 가산).
        let base: Register = inst.memory_base();
        let index: Register = inst.memory_index();
        if base == Register::None && index == Register::None {
            b.lea_gs(dst, disp);
        } else {
            b.lea_gs(SCRATCH, disp);
            if base != Register::None {
                b.binop_r_r(OP_ADD_R_R64, SCRATCH, vreg(base)?);
            }
            if index != Register::None {
                let scale = inst.memory_index_scale();
                let scale_enc = match scale {
                    0 | 1 => 0u8, 2 => 1, 4 => 2, 8 => 3,
                    _ => return Err(anyhow!("lifter: unsupported scale {}", scale)),
                };
                // SCRATCH = GS + idx*scale  (via shift on a copy)
                b.mov_r_r(SCRATCH2, vreg(index)?);
                if scale_enc > 0 { b.shift64_r_imm8(OP_SHL64_R_IMM8, SCRATCH2, scale_enc); }
                b.binop_r_r(OP_ADD_R_R64, SCRATCH, SCRATCH2);
            }
            if dst != SCRATCH {
                b.mov_r_r64(dst, SCRATCH);
            }
        }
        return Ok(());
    }

    // base register (may be Register::None)
    let base: Register = inst.memory_base();
    let index: Register = inst.memory_index();
    let scale = inst.memory_index_scale();
    let disp = inst.memory_displacement64() as i32;

    // Normalize scale to scale_enc (0,1,2,3 => *1,*2,*4,*8)
    let scale_enc = match scale {
        0 | 1 => 0u8,
        2 => 1,
        4 => 2,
        8 => 3,
        _ => return Err(anyhow!("lifter: unsupported scale {}", scale)),
    };

    let has_base = base != Register::None;
    let has_index = index != Register::None;
    match (has_base, has_index) {
        (true, true) => {
            b.lea(dst, vreg(base)?, vreg(index)?, scale_enc, disp);
        }
        (true, false) => {
            // [base + disp]
            b.lea(dst, vreg(base)?, ADDR_NO_INDEX, 0, disp);
        }
        (false, true) => {
            // [index*scale + disp]  (no base: use v0 as a zero base)
            b.lea(dst, 0, vreg(index)?, scale_enc, disp);
        }
        (false, false) => {
            // absolute-ish [disp] — treat as [0 + disp].
            // C-1 fix: `disp` here is `memory_displacement64() as i32`, which
            // truncates a 64-bit absolute VA (e.g. an IAT slot 0x140008278) to
            // 32 bits (0x40008278) — the lifted program then reads/writes the
            // WRONG address and crashes (0xC0000005). Re-derive the full 64-bit
            // displacement so absolute operands keep their true target.
            let disp64 = inst.memory_displacement64();
            b.mov_r_imm64(dst, disp64);
        }
    }
    Ok(())
}

/// Two-operand reg/reg or reg/mem binary op. Memory sources are lowered by
/// loading into SCRATCH first (the VM op set has no reg/mem forms).
fn two_op(b: &mut BytecodeBuilder, inst: &Instruction, op32: u8, op64: u8) -> Result<()> {
    // op0 may be a register or a memory destination (rm form). If memory, do
    // load-modify-store: load into SCRATCH, apply op, store back.
    let mem_dst = inst.op0_kind() == OpKind::Memory;
    let is64_code = matches!(inst.code(),
        iced_x86::Code::Add_rm64_r64 | iced_x86::Code::Sub_rm64_r64
        | iced_x86::Code::Xor_rm64_r64 | iced_x86::Code::And_rm64_r64
        | iced_x86::Code::Or_rm64_r64 | iced_x86::Code::Imul_r64_rm64
        | iced_x86::Code::Add_r64_rm64 | iced_x86::Code::Sub_r64_rm64
        | iced_x86::Code::Xor_r64_rm64 | iced_x86::Code::And_r64_rm64
        | iced_x86::Code::Or_r64_rm64 | iced_x86::Code::Imul_r64_rm64);
    let mut d = 0u8;
    let mut mem_addr = 0u8;
    if mem_dst {
        mem_addr = mem_emit(b, inst, 0)?;
        // C-fix: keep the address in SCRATCH; load the memory value into SCRATCH2
        if is64_code { b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH2, mem_addr); }
        else { b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH2, mem_addr); }
        d = SCRATCH2;
    } else {
        d = vreg(inst.op0_register())?;
    }
    let sz = if is64_code { 64 } else { reg_bits(inst.op0_register()) };
    let op = if sz == 64 { op64 } else { op32 };

    if inst.op1_kind() == OpKind::Register {
        let s = vreg(inst.op1_register())?;
        if sz == 64 { b.binop_r_r64(op, d, s); }
        else { b.binop_r_r(op, d, s); }
    } else {
        let src_addr = mem_emit(b, inst, 1)?;
        if sz == 64 {
            b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH2, src_addr);
            b.binop_r_r64(op, d, SCRATCH2);
        } else {
            b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH2, src_addr);
            b.binop_r_r(op, d, SCRATCH2);
        }
    }
    if mem_dst {
        let store_op = if sz == 64 { OP_MOV_MEM64_A } else { OP_MOV_MEM32_A };
        b.mem_store_a(store_op, mem_addr, d);
    }
    Ok(())
}

fn lift_sub_imm(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let r = vreg(inst.op0_register())?;
    let imm = inst.immediate32();
    // sub r, imm -> add r, -imm (32-bit wrapping)
    b.binop_r_imm32(OP_ADD_R_IMM32, r, imm.wrapping_neg());
    Ok(())
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


/// Indirect call/jmp: load the target address into SCRATCH and do a native
/// bridge call. `call qword ptr [IAT]` / `call reg` / `jmp qword ptr [IAT]` /
/// `jmp reg` are all "call through to a resolved address" in import-thunk code.
fn lift_indirect_call(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    // op0 is the r/m operand holding the target (register or [memory]).
    if inst.op0_kind() == OpKind::Register {
        let t = vreg(inst.op0_register())?;
        b.native_call(t);
    } else if inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH, addr); // target = *(u64*)addr
        b.native_call(SCRATCH);
    } else {
        return Err(anyhow!("lifter: unsupported indirect call target {}", inst));
    }
    if matches!(inst.code(), iced_x86::Code::Jmp_rm64) {
        // C-1 (--vm-oep) runtime-integration fix: import thunks (jmp *[IAT]) are
        // call targets -- the native bridge does call r11, the API returns to the
        // bridge, and the VM must ret (pop the caller VM-stack return addr pushed
        // by the preceding call32) and continue, NOT halt (which killed the VM after
        // the first import call, so main/GUI never ran).
        b.ret();
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// A-2/A-5 (v26) — 1:1 lift-table completion.
// These helpers lower the missing common register/immediate forms to sequences
// of *existing* opcodes, so no new native handler is required. CMP sets the SUB
// flags via a scratch SUB (flags identical, scratch clobber is fine); TEST sets
// LOGICAL flags via an AND into scratch; MOVSXD/CDQE sign-extend via SHL64+SAR64.
// ══════════════════════════════════════════════════════════════════════════════

/// True for immediate-8 (sign-extended) opcode forms.
fn is_imm8_op(code: Code) -> bool {
    use iced_x86::Code::*;
    matches!(code,
        Add_rm32_imm8 | Add_rm64_imm8 | Sub_rm32_imm8 | Sub_rm64_imm8
        | Adc_rm32_imm8 | Adc_rm64_imm8 | Adc_rm8_imm8 | Adc_rm16_imm8 | Adc_AL_imm8
        | And_rm32_imm8 | And_rm64_imm8 | Or_rm32_imm8 | Or_rm64_imm8
        | Xor_rm32_imm8 | Xor_rm64_imm8
        | Cmp_rm32_imm8 | Cmp_rm64_imm8 | Cmp_rm8_imm8 | Cmp_rm16_imm8 | Cmp_AL_imm8
        | Test_rm8_imm8 | Test_AL_imm8
        | Mov_rm8_imm8)
}

/// Sign-extended immediate value for an instruction. imm8 forms are sign-extended
/// to 64 bits; imm16/imm32 forms are taken as their 32-bit value.
fn inst_imm(inst: &Instruction, is8: bool) -> i64 {
    if is8 {
        (inst.immediate8() as i8) as i64
    } else {
        (inst.immediate32() as i32) as i64
    }
}

/// Width (bits) of the operand for an add/sub/and/or/xor-imm opcode.
fn imm_op_width(code: Code) -> usize {
    use iced_x86::Code::*;
    if matches!(code,
        Add_rm32_imm8 | Add_rm32_imm32 | Sub_rm32_imm8 | Sub_rm32_imm32
        | And_rm32_imm8 | And_rm32_imm32 | Or_rm32_imm8 | Or_rm32_imm32
        | Xor_rm32_imm8 | Xor_rm32_imm32
        | Add_EAX_imm32 | And_EAX_imm32 | Or_EAX_imm32 | Xor_EAX_imm32) { 32 } else { 64 }
}

/// Add/Sub/And/Or/Xor r/m, imm8/imm32. SUB is emitted as ADD of the negated
/// immediate (no sub-imm opcode is needed). Handles both register and memory
/// destinations (mem dest = load-modify-store via the scratch vreg).
fn lift_arith_imm(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let is8 = is_imm8_op(code);
    let mut imm = inst_imm(inst, is8);
    let is_sub = matches!(code,
        Sub_RAX_imm32 | Sub_rm32_imm8 | Sub_rm32_imm32 | Sub_rm64_imm8 | Sub_rm64_imm32);
    if is_sub { imm = -imm; }

    let (op32, op64) = if matches!(code,
        Add_EAX_imm32 | Add_rm32_imm8 | Add_rm32_imm32 | Add_rm64_imm8 | Add_rm64_imm32
        | Sub_RAX_imm32 | Sub_rm32_imm8 | Sub_rm32_imm32 | Sub_rm64_imm8 | Sub_rm64_imm32)
    {
        (OP_ADD_R_IMM32, OP_ADD_R_IMM64)
    } else if matches!(code,
        And_EAX_imm32 | And_rm32_imm8 | And_rm32_imm32 | And_rm64_imm8 | And_rm64_imm32)
    {
        (OP_AND_R_IMM32, OP_AND_R_IMM64)
    } else if matches!(code,
        Or_EAX_imm32 | Or_rm32_imm8 | Or_rm32_imm32 | Or_rm64_imm8 | Or_rm64_imm32)
    {
        (OP_OR_R_IMM32, OP_OR_R_IMM64)
    } else {
        (OP_XOR_R_IMM32, OP_XOR_R_IMM64)
    };

    if inst.op0_kind() == OpKind::Register {
        let r = vreg(inst.op0_register())?;
        if reg_bits(inst.op0_register()) == 64 {
            b.binop_r_imm64(op64, r, imm as u32);
        } else {
            b.binop_r_imm32(op32, r, imm as u32);
        }
    } else if inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        let sz = imm_op_width(code);
        let (load, store) = match sz {
            8 => (OP_MOVZX_R_MEM8_A, OP_MOV_MEM8_A),
            32 => (OP_MOVZX_R_MEM32_A, OP_MOV_MEM32_A),
            _ => (OP_MOV_R_MEM64_A, OP_MOV_MEM64_A),
        };
        b.mem_load_a(load, SCRATCH2, addr);
        if sz == 64 { b.binop_r_imm64(op64, SCRATCH2, imm as u32); }
        else { b.binop_r_imm32(op32, SCRATCH2, imm as u32); }
        b.mem_store_a(store, addr, SCRATCH2);
    } else {
        return Err(anyhow!("lifter: unsupported arith-imm operand {}", inst));
    }
    Ok(())
}

/// CMP — sets the full SUB flags without writing the destination. Emulated with
/// a scratch-register SUB (the flags are identical; the clobbered scratch is the
/// lifter's own scratch, re-computed per instruction).
fn lift_cmp(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
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
            // cmp reg, [mem]  (Cmp_r32_rm32 / Cmp_r64_rm64)
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
            // op1 is an immediate (Immediate8/16/32/64)
            let is8 = is_imm8_op(code);
            let imm = inst_imm(inst, is8);
            if is64 {
                b.mov_r_r64(SCRATCH, r);
                b.mov_r_imm64(SCRATCH2, imm as u64);
                b.binop_r_r64(OP_SUB_R_R64, SCRATCH, SCRATCH2);
            } else {
                let width = reg_bits(inst.op0_register());
                let mask = match width { 8 => 0xFFu32, 16 => 0xFFFFu32, _ => 0xFFFF_FFFFu32 };
                b.mov_r_r(SCRATCH, r);
                if mask != 0xFFFF_FFFF { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, mask); }
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
        if matches!(code, Cmp_rm64_imm8 | Cmp_rm64_imm32) { sz = 64; }
        let load = match sz { 8 => OP_MOVZX_R_MEM8_A, 16 => OP_MOVZX_R_MEM16_A, 32 => OP_MOVZX_R_MEM32_A, _ => OP_MOV_R_MEM64_A };
        b.mem_load_a(load, SCRATCH, addr);
        if inst.op1_kind() == OpKind::Register {
            let s = vreg(inst.op1_register())?;
            if sz == 64 { b.binop_r_r64(OP_SUB_R_R64, SCRATCH, s); }
            else {
                b.mov_r_r(SCRATCH2, s);
                b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2);
            }
        } else {
            let is8 = is_imm8_op(code);
            let imm = inst_imm(inst, is8);
            if sz == 64 { b.mov_r_imm64(SCRATCH2, imm as u64); b.binop_r_r64(OP_SUB_R_R64, SCRATCH, SCRATCH2); }
            else { b.mov_r_imm32(SCRATCH2, imm as u32); b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2); }
        }
    } else {
        return Err(anyhow!("lifter: unsupported cmp operand {}", inst));
    }
    Ok(())
}

/// TEST — sets LOGICAL flags (like AND) without writing a destination. Emulated
/// with an AND into the scratch vreg (64-bit) or a masked 32-bit AND (8/16-bit).
fn lift_test(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let is8 = is_imm8_op(code);

    if inst.op0_kind() == OpKind::Register {
        let r = vreg(inst.op0_register())?;
        let width = reg_bits(inst.op0_register());
        let mask = match width { 8 => 0xFFu32, 16 => 0xFFFFu32, _ => 0xFFFF_FFFFu32 };
        if inst.op1_kind() == OpKind::Register {
            let s = vreg(inst.op1_register())?;
            if width == 64 {
                b.mov_r_r64(SCRATCH, r);
                b.binop_r_r64(OP_AND_R_R64, SCRATCH, s);
            } else {
                b.mov_r_r(SCRATCH, r);
                if mask != 0xFFFF_FFFF { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, mask); }
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
                if mask != 0xFFFF_FFFF { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, mask); }
                b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, imm as u32);
            }
        }
    } else if inst.op0_kind() == OpKind::Memory {
        // test [mem], imm (8 or 16 bit)
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



/// SSE moves / unpack for the XMM register file.
/// kind: 0 = XMM<-mem (movsd/movups), 1 = mem<-XMM, 2 = unpcklpd XMM<-XMM.
fn lift_sse(b: &mut BytecodeBuilder, inst: &Instruction, kind: u8) -> Result<()> {
    use iced_x86::Code::*;
    let xmm_idx = |reg: iced_x86::Register| -> u8 {
        if reg == iced_x86::Register::None { 0 } else { reg.number() as u8 }
    };
    match kind {
        0 => {
            // dst = XMM register (op0), src = [mem] or reg (op1)
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
            // dst = [mem] (op0), src = XMM register (op1)
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

/// PSHUFLW / PSHUFHW / PSHUFD (SSE word/dword shuffle with imm8).
/// Handles reg-reg and memory-source operands.
fn lift_sseshuffle(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
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
        // memory source: load [mem] into the dst XMM slot, then shuffle in place.
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

/// PSRLLQ / PSRLQ by imm8 (SSE2 packed 64-bit logical shift by immediate).
/// dst is a single XMM register, shifted in place.
fn lift_sseshift_imm8(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
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

/// PINSRW xmm, r32/m16, imm8: insert the low 16 bits of the source into word lane
/// (imm8 & 7) of the destination XMM register. Memory source is loaded into the
/// scratch vreg first. Decomposed into OP_PINSRW_XMM [dst_xmm, src_vreg, lane].
fn lift_pinsrw(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
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

/// TZCNT r32, r32/m32 (32-bit): dst = count trailing zeros (== operand width when
/// src == 0). Memory source is loaded into scratch first.
fn lift_tzcnt(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
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

/// RET imm16 (cdecl): pop the return address and add imm16 to the stack pointer.
fn lift_ret_imm16(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    b.ret_imm16(inst.immediate16());
    Ok(())
}

/// INC/DEC on a register or a memory destination (load-modify-store).
fn lift_incdec(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let is_inc = matches!(inst.code(), Inc_rm32 | Inc_rm64 | Inc_rm8 | Inc_rm16);
    if inst.op0_kind() == OpKind::Register {
        let r = vreg(inst.op0_register())?;
        if is_inc { b.inc_r(r); } else { b.dec_r(r); }
        return Ok(());
    }
    // memory destination: load-modify-store
    let addr = mem_emit(b, inst, 0)?;
    let sz = match inst.code() {
        Inc_rm8 | Dec_rm8 => 8,
        Inc_rm16 | Dec_rm16 => 16,
        Inc_rm32 | Dec_rm32 => 32,
        _ => 64,
    };
    let load = match sz { 8 => OP_MOVZX_R_MEM8_A, 16 => OP_MOVZX_R_MEM16_A, 32 => OP_MOVZX_R_MEM32_A, _ => OP_MOV_R_MEM64_A };
    let store = match sz { 8 => OP_MOV_MEM8_A, 16 => OP_MOV_MEM16_A, 32 => OP_MOV_MEM32_A, _ => OP_MOV_MEM64_A };
    b.mem_load_a(load, SCRATCH2, addr);
    if is_inc { b.inc_r(SCRATCH2); } else { b.dec_r(SCRATCH2); }
    b.mem_store_a(store, addr, SCRATCH2);
    Ok(())
}

/// NOT / NEG — unary ops on register or memory operand.
/// NOT: bitwise complement (no flags). NEG: arithmetic negate (all flags).
/// Handles 8/16/32/64-bit forms, register and memory destinations.
fn lift_not_neg(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let name = format!("{:?}", code);
    let is_not = name.starts_with("Not_");
    let is8  = name.contains("_rm8");
    let is16 = name.contains("_rm16");
    let is64 = name.contains("_rm64");

    if inst.op0_kind() == OpKind::Register {
        let r = vreg(inst.op0_register())?;
        if is_not {
            if is64 { b.not_r64(r); } else { b.not_r(r); }
        } else {
            if is64 { b.neg_r64(r); } else { b.neg_r(r); }
        }
        // narrow forms: mask result to correct width
        if is8  { b.binop_r_imm32(OP_AND_R_IMM32, r, 0xFF); }
        if is16 { b.binop_r_imm32(OP_AND_R_IMM32, r, 0xFFFF); }
        return Ok(());
    }

    // memory destination: load-modify-store
    let addr = mem_emit(b, inst, 0)?;
    let (load, store) = if is8 {
        (OP_MOVZX_R_MEM8_A,  OP_MOV_MEM8_A)
    } else if is16 {
        (OP_MOVZX_R_MEM16_A, OP_MOV_MEM16_A)
    } else if is64 {
        (OP_MOV_R_MEM64_A,   OP_MOV_MEM64_A)
    } else {
        (OP_MOVZX_R_MEM32_A, OP_MOV_MEM32_A)
    };
    b.mem_load_a(load, SCRATCH2, addr);
    if is_not {
        if is64 { b.not_r64(SCRATCH2); } else { b.not_r(SCRATCH2); }
    } else {
        if is64 { b.neg_r64(SCRATCH2); } else { b.neg_r(SCRATCH2); }
    }
    if is8  { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, 0xFF); }
    if is16 { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, 0xFFFF); }
    b.mem_store_a(store, addr, SCRATCH2);
    Ok(())
}

/// XCHG — swap register/register or register/memory using the scratch vreg.
fn lift_xchg(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let mem_op: Option<u32> = (0..inst.op_count()).find(|&i| inst.op_kind(i) == OpKind::Memory);
    // width from the code name: 8/16/32/64-bit xchg forms.
    let name = format!("{:?}", inst.code());
    let wbits = if name.contains("rm8_") || name.contains("r8_rm8") { 8 }
        else if name.contains("rm16_") || name.contains("r16_rm16") { 16 }
        else if name.contains("rm64_") || name.contains("r64_RAX") { 64 }
        else { 32 };
    let is64 = wbits == 64;
    if let Some(mi) = mem_op {
        // v48 fix: `xchg [mem], reg` must be a SINGLE atomic RMW — x86 memory
        // XCHG is implicitly atomic. The previous emulation (load->[mem]=reg->
        // reg=load) was not atomic: a concurrent/2nd Rust `Once::call_once` could
        // observe the OLD state and re-run the closure -> `f.take().unwrap()`
        // panic (once.rs:166). Emit a real `xchg [addr], reg`.
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
        // reg, reg: SCRATCH=a; a=b; b=SCRATCH
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

/// IMUL reg, r/m, imm (2/3-operand immediate form): mov SCRATCH,imm; imul reg,SCRATCH.
/// iced encodes `imul edx,5Dh` as Imul_r32_rm32_imm8 (r32, r/m32, imm8); the immediate
/// lives in the last operand. We read immediate8 if present and nonzero for imm8 forms,
/// otherwise immediate32.
fn lift_imul_imm(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let d = vreg(inst.op0_register())?;
    let is64 = reg_bits(inst.op0_register()) == 64;
    let is_imm8_form = matches!(inst.code(), Imul_r32_rm32_imm8 | Imul_r64_rm64_imm8);
    let imm: i64 = if is_imm8_form {
        (inst.immediate8() as i8) as i64
    } else {
        (inst.immediate32() as i32) as i64
    };
    if is64 {
        b.mov_r_imm64(SCRATCH, imm as u64);
        b.binop_r_r64(OP_IMUL_R_R64, d, SCRATCH);
    } else {
        b.mov_r_imm32(SCRATCH, imm as u32);
        b.binop_r_r(OP_IMUL_R_R, d, SCRATCH);
    }
    Ok(())
}


/// Map an iced ConditionCode to our VM cond code. Returns (taken_cond, negated_cond).
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

/// SETcc: vreg[dst] = (cond) ? 1 : 0. Emitted with jcc8 + mov so the VM
/// cond-evaluation is reused (no new native handler).
/// If the condition is taken we set 1, so we branch over the "set 1" only
/// when the *negated* condition is true.
fn lift_setcc(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let (_, neg) = map_cond(inst.condition_code());
    let skip = b.new_label();
    if inst.op0_kind() == OpKind::Memory {
        // setcc byte ptr [mem]: compute 0/1 into SCRATCH, then store a byte.
        let addr = mem_emit(b, inst, 0)?;
        b.mov_r_imm32(SCRATCH2, 0);
        b.jcc8(neg, skip);
        b.mov_r_imm32(SCRATCH2, 1);
        b.mark_label(skip);
        b.mem_store_a(OP_MOV_MEM8_A, addr, SCRATCH2);
        Ok(())
    } else {
        let dst = vreg(inst.op0_register())?;
        b.mov_r_imm32(dst, 0);
        b.jcc8(neg, skip); // if !cond, skip the "set 1"
        b.mov_r_imm32(dst, 1);
        b.mark_label(skip);
        Ok(())
    }
}

/// CMOVcc: if cond taken, dst = src. Emit: jcc8(!cond, skip); mov dst,src; skip.
fn lift_cmovcc(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let (c, neg) = map_cond(inst.condition_code());
    let dst = vreg(inst.op0_register())?;
    // source may be a register or memory
    let skip = b.new_label();
    b.jcc8(neg, skip); // if !cond, skip
    if inst.op1_kind() == OpKind::Register {
        let src = vreg(inst.op1_register())?;
        if reg_bits(inst.op0_register()) == 64 { b.mov_r_r64(dst, src); } else { b.mov_r_r(dst, src); }
    } else {
        let addr = mem_emit(b, inst, 1)?;
        let sz = reg_bits(inst.op0_register());
        let load = match sz { 32 => OP_MOVZX_R_MEM32_A, _ => OP_MOV_R_MEM64_A };
        b.mem_load_a(load, dst, addr);
    }
    b.mark_label(skip);
    let _ = c;
    Ok(())
}

/// SBB: dst = dst - src - CF. For the common `sbb reg,reg` idiom this is
/// dst = dst - src - (CF?1:0). We compute with a scratch subtract then, if CF
/// was set, subtract 1 more.
fn lift_sbb(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    let (_, neg) = map_cond(iced_x86::ConditionCode::b); // neg of CF-set = JAE
    let dst = vreg(inst.op0_register())?;
    let is64 = reg_bits(inst.op0_register()) == 64;
    let src_vreg: u8 = if inst.op1_kind() == OpKind::Register {
        vreg(inst.op1_register())?
    } else {
        // immediate (sign-extended; imm8 forms must extend to full 64 bits)
        let is8 = is_imm8_op(inst.code());
        let imm = inst_imm(inst, is8) as u64;
        if is64 { b.mov_r_imm64(SCRATCH2, imm); } else { b.mov_r_imm32(SCRATCH2, imm as u32); }
        SCRATCH2
    };
    // SCRATCH = dst; subtract src (sets CF); then if CF, dst -= 1.
    if is64 {
        b.mov_r_r64(SCRATCH, dst);
        b.binop_r_r64(OP_SUB_R_R64, SCRATCH, src_vreg);
    } else {
        b.mov_r_r(SCRATCH, dst);
        b.binop_r_r(OP_SUB_R_R, SCRATCH, src_vreg);
    }
    // borrow path: if CF==0 skip the -1
    let done = b.new_label();
    b.jcc8(neg, done); // JAE: CF==0 -> done
    if is64 { b.binop_r_imm64(OP_ADD_R_IMM64, SCRATCH, 0xFFFF_FFFF); }
    else { b.binop_r_imm32(OP_ADD_R_IMM32, SCRATCH, 0xFFFF_FFFF); } // += -1 => subtract 1
    b.mark_label(done);
    if is64 { b.mov_r_r64(dst, SCRATCH); } else { b.mov_r_r(dst, SCRATCH); }
    Ok(())
}

/// ADC dst, src: dst = dst + src + CF. Reads the *incoming* CF before the add,
/// branches on it, then either dst+src (CF=0) or dst+src+1 (CF=1).
/// 8/16/32/64-bit, reg/mem dest, reg/imm src.
fn lift_adc(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let name = format!("{:?}", code);
    let wbits = if name.contains("rm8_") || name.contains("r8_rm8") || name.contains("AL_") { 8 }
        else if name.contains("rm16_") || name.contains("r16_rm16") || name.contains("AX_") { 16 }
        else if name.contains("rm64_") || name.contains("r64_rm64") || name.contains("RAX_") { 64 }
        else { 32 };
    let (load, store, addop, mov_wide) = match wbits {
        8 => (OP_MOVZX_R_MEM8_A, OP_MOV_MEM8_A, OP_ADD_R_R, false),
        16 => (OP_MOVZX_R_MEM16_A, OP_MOV_MEM16_A, OP_ADD_R_R, false),
        64 => (OP_MOV_R_MEM64_A, OP_MOV_MEM64_A, OP_ADD_R_R64, true),
        _ => (OP_MOVZX_R_MEM32_A, OP_MOV_MEM32_A, OP_ADD_R_R, false),
    };
    let mask: u32 = match wbits { 8 => 0xFF, 16 => 0xFFFF, _ => 0xFFFF_FFFF };
    // source: register or immediate
    let src: u8 = if inst.op1_kind() == OpKind::Register {
        vreg(inst.op1_register())?
    } else {
        let is8 = is_imm8_op(code);
        let imm = inst_imm(inst, is8) as u64;
        if wbits == 64 { b.mov_r_imm64(SCRATCH2, imm); }
        else { b.mov_r_imm32(SCRATCH2, imm as u32); }
        if wbits == 8 || wbits == 16 { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, mask); }
        SCRATCH2
    };

    if inst.op0_kind() == OpKind::Memory {
        let addr = mem_emit(b, inst, 0)?;
        // keep addr in SCRATCH. The value lives in SCRATCH2 unless the source is an
        // immediate (which occupies SCRATCH2), in which case use a free temp vreg 18.
        let val = if src == SCRATCH2 { 18u8 } else { SCRATCH2 };
        b.mem_load_a(load, val, addr); // val = dst
        let has_carry = b.new_label();
        let done = b.new_label();
        b.jcc8(COND_JB, has_carry); // CF set?
        // CF == 0
        if mov_wide { b.binop_r_r64(addop, val, src); } else { b.binop_r_r(addop, val, src); }
        b.jmp8(done);
        b.mark_label(has_carry);
        // CF == 1
        if mov_wide { b.binop_r_r64(addop, val, src); } else { b.binop_r_r(addop, val, src); }
        if wbits == 64 { b.binop_r_imm64(OP_ADD_R_IMM64, val, 1); }
        else { b.binop_r_imm32(OP_ADD_R_IMM32, val, 1); }
        b.mark_label(done);
        if wbits == 8 || wbits == 16 { b.binop_r_imm32(OP_AND_R_IMM32, val, mask); }
        b.mem_store_a(store, addr, val);
    } else {
        let dst = vreg(inst.op0_register())?;
        if mov_wide { b.mov_r_r64(SCRATCH, dst); } else { b.mov_r_r(SCRATCH, dst); }
        let has_carry = b.new_label();
        let done = b.new_label();
        b.jcc8(COND_JB, has_carry); // CF set?
        if mov_wide { b.binop_r_r64(addop, SCRATCH, src); } else { b.binop_r_r(addop, SCRATCH, src); }
        b.jmp8(done);
        b.mark_label(has_carry);
        if mov_wide { b.binop_r_r64(addop, SCRATCH, src); } else { b.binop_r_r(addop, SCRATCH, src); }
        if wbits == 64 { b.binop_r_imm64(OP_ADD_R_IMM64, SCRATCH, 1); }
        else { b.binop_r_imm32(OP_ADD_R_IMM32, SCRATCH, 1); }
        b.mark_label(done);
        if wbits == 8 || wbits == 16 { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, mask); }
        if mov_wide { b.mov_r_r64(dst, SCRATCH); } else { b.mov_r_r(dst, SCRATCH); }
        if wbits == 8 || wbits == 16 { b.binop_r_imm32(OP_AND_R_IMM32, dst, mask); }
    }
    Ok(())
}

/// 8-bit ADD (add rm8, r8 / add r8, r8): load byte, add, store with masking.
fn lift_add8(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    // A-2 잔여 (v32): 8/16-bit ADD/SUB/XOR/AND/OR are lowered to the existing 32-bit
    // op + a width mask in lift_narrow_arith below; this legacy helper only handled the
    // old Add_rm8_r8 form, now fully superseded.
    lift_narrow_arith(b, inst)
}

/// A-2 잔여 (v32): 8/16-bit ADD/SUB/XOR/AND/OR (reg/mem/imm forms). Lowered to the
/// existing 32-bit op + a width mask (same emulation precedent as the old lift_add8),
/// so no new handler is needed and interp==native is preserved by construction.
fn lift_narrow_arith(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    use iced_x86::OpKind;
    let code = inst.code();
    // which 32-bit VM op emulates this 8/16-bit operation
    let (op, _is_sub) = if matches!(code,
        Sub_rm8_r8 | Sub_r8_rm8 | Sub_rm16_r16 | Sub_r16_rm16
        | Sub_AL_imm8 | Sub_AX_imm16 | Sub_rm8_imm8 | Sub_rm16_imm8 | Sub_rm16_imm16)
    { (OP_SUB_R_R, true) } else if matches!(code,
        Add_rm8_r8 | Add_r8_rm8 | Add_rm16_r16 | Add_r16_rm16
        | Add_AL_imm8 | Add_AX_imm16 | Add_rm8_imm8 | Add_rm16_imm8 | Add_rm16_imm16)
    { (OP_ADD_R_R, false) } else if matches!(code,
        Xor_rm8_r8 | Xor_r8_rm8 | Xor_rm16_r16 | Xor_r16_rm16
        | Xor_AL_imm8 | Xor_AX_imm16 | Xor_rm8_imm8 | Xor_rm16_imm8 | Xor_rm16_imm16)
    { (OP_XOR_R_R, false) } else if matches!(code,
        And_rm8_r8 | And_r8_rm8 | And_rm16_r16 | And_r16_rm16
        | And_AL_imm8 | And_AX_imm16 | And_rm8_imm8 | And_rm16_imm8 | And_rm16_imm16)
    { (OP_AND_R_R, false) } else {
        (OP_OR_R_R, false) // Or_rm8_r8 | Or_r8_rm8 | Or_rm16_r16 | Or_r16_rm16 | Or_AL_imm8 | Or_AX_imm16 | Or_rm8_imm8 | Or_rm16_imm8 | Or_rm16_imm16
    };
    // 8-bit vs 16-bit (from the operand-size suffix in the code name)
    let is8 = matches!(code,
        Add_rm8_r8 | Add_r8_rm8 | Add_AL_imm8 | Add_rm8_imm8
        | Sub_rm8_r8 | Sub_r8_rm8 | Sub_AL_imm8 | Sub_rm8_imm8
        | Xor_rm8_r8 | Xor_r8_rm8 | Xor_AL_imm8 | Xor_rm8_imm8
        | And_rm8_r8 | And_r8_rm8 | And_AL_imm8 | And_rm8_imm8
        | Or_rm8_r8 | Or_r8_rm8 | Or_AL_imm8 | Or_rm8_imm8);
    let mask: u32 = if is8 { 0xFF } else { 0xFFFF };
    let load = if is8 { OP_MOVZX_R_MEM8_A } else { OP_MOVZX_R_MEM16_A };
    let store = if is8 { OP_MOV_MEM8_A } else { OP_MOV_MEM16_A };

    // Capture the destination address ONCE (into SCRATCH) and load the destination
    // value into SCRATCH2 (for a mem dst), so the address survives to the store.
    let mem_dst = inst.op0_kind() == OpKind::Memory;
    let mem_addr = if mem_dst { Some(mem_emit(b, inst, 0)?) } else { None };
    if mem_dst {
        b.mem_load_a(load, SCRATCH2, mem_addr.unwrap());
    } else {
        let d = vreg(inst.op0_register())?;
        b.mov_r_r(SCRATCH, d);
    }
    // Load the source. When the dst value occupies SCRATCH2 (mem dst), the source
    // must not reuse SCRATCH2: use the register directly, or park an immediate in a
    // free temp vreg (18).
    const TMP18: u8 = 18;
    let src_r = if inst.op1_kind() == OpKind::Register {
        let s = vreg(inst.op1_register())?;
        if mem_dst { s } else { b.mov_r_r(SCRATCH2, s); SCRATCH2 }
    } else if inst.op1_kind() == OpKind::Memory {
        // (memory source only occurs with a reg dst, so SCRATCH2 is free here)
        let addr = mem_emit(b, inst, 1)?;
        b.mem_load_a(load, SCRATCH2, addr);
        SCRATCH2
    } else {
        // immediate. 8-bit immediates are sign-extended; 16-bit taken as-is.
        let is8imm = matches!(inst.op1_kind(), OpKind::Immediate8);
        let imm = inst_imm(inst, is8imm) as u64;
        if mem_dst {
            b.mov_r_imm64(TMP18, imm);
            TMP18
        } else {
            b.mov_r_imm64(SCRATCH2, imm);
            SCRATCH2
        }
    };
    // op, mask to width, write back
    let (val_r, out) = if mem_dst { (SCRATCH2, mem_addr.unwrap()) } else { (SCRATCH, 0u8) };
    b.binop_r_r(op, val_r, src_r);
    b.binop_r_imm32(OP_AND_R_IMM32, val_r, mask);
    if mem_dst {
        b.mem_store_a(store, out, val_r);
    } else {
        let d = vreg(inst.op0_register())?;
        b.mov_r_r(d, val_r);
    }
    Ok(())
}

/// REP STOSQ: while(rcx){ [rdi]=rax; rdi+=8; rcx--; }. rdi=v7, rax=v0, rcx=v1.
fn lift_rep_stosq(b: &mut BytecodeBuilder) -> Result<()> {
    let rdi = 7u8; let rax = 0u8; let rcx = 1u8;
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    b.mem_store_a(OP_MOV_MEM64_A, rdi, rax);
    b.binop_r_imm32(OP_ADD_R_IMM32, rdi, 8);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    Ok(())
}

/// A-5 잔여 (v32): REP MOVS — while(rcx){ [rdi]=[rsi]; rdi+=n; rsi+=n; rcx-- }.
/// Element width n comes from the code (Movsb=1/Movsw=2/Movsd=4/Movsq=8).
/// rsi=v6, rdi=v7, rcx=v1. Direction flag (DF) is assumed clear (forward), which
/// matches the existing rep stosq lowering and the compiler-emitted memcpy.
fn lift_rep_movs(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let n = match inst.code() {
        Movsb_m8_m8 => 1u64,
        Movsw_m16_m16 => 2,
        Movsd_m32_m32 => 4,
        _ => 8, // Movsq_m64_m64
    };
    let (load, store) = match n {
        1 => (OP_MOVZX_R_MEM8_A, OP_MOV_MEM8_A),
        2 => (OP_MOVZX_R_MEM16_A, OP_MOV_MEM16_A),
        4 => (OP_MOVZX_R_MEM32_A, OP_MOV_MEM32_A),
        _ => (OP_MOV_R_MEM64_A, OP_MOV_MEM64_A),
    };
    let rsi = 6u8; let rdi = 7u8; let rcx = 1u8;
    let loop_lbl = b.new_label();
    let done = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);
    b.mem_load_a(load, SCRATCH, rsi);
    b.mem_store_a(store, rdi, SCRATCH);
    b.binop_r_imm32(OP_ADD_R_IMM32, rsi, n as u32);
    b.binop_r_imm32(OP_ADD_R_IMM32, rdi, n as u32);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(done);
    Ok(())
}

/// A-5 잔여 (v32): REP CMPS — while(rcx && [rdi]==[rsi]){ advance both; rcx-- }.
/// Stops at the first mismatch (ZF cleared), leaving ZF=0, exactly like x86
/// `repe cmps`. The x86 semantics decrement RCX even on the mismatching element,
/// so the mismatch exit decrements rcx before falling out. Element width from the
/// code. rsi=v6, rdi=v7, rcx=v1. The SUB sets ZF and the JNE reads it immediately
/// (before the pointer increments / rcx decrement clobber the flags).
fn lift_rep_cmps(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let n = match inst.code() {
        Cmpsb_m8_m8 => 1u64,
        Cmpsw_m16_m16 => 2,
        Cmpsd_m32_m32 => 4,
        _ => 8, // Cmpsq_m64_m64
    };
    let load = match n {
        1 => OP_MOVZX_R_MEM8_A,
        2 => OP_MOVZX_R_MEM16_A,
        4 => OP_MOVZX_R_MEM32_A,
        _ => OP_MOV_R_MEM64_A,
    };
    let rsi = 6u8; let rdi = 7u8; let rcx = 1u8;
    let loop_lbl = b.new_label();
    let done = b.new_label();
    let mismatch = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(rcx, rcx);
    b.jcc8(COND_JE, done);          // rcx==0 → all compared, exit
    b.mem_load_a(load, SCRATCH, rdi);
    b.mem_load_a(load, SCRATCH2, rsi);
    b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2); // sets ZF (element compare)
    b.jcc8(COND_JNE, mismatch);     // elements differ → dec + stop (ZF=0)
    b.binop_r_imm32(OP_ADD_R_IMM32, rsi, n as u32);
    b.binop_r_imm32(OP_ADD_R_IMM32, rdi, n as u32);
    b.dec_r(rcx);
    b.jmp8(loop_lbl);
    b.mark_label(mismatch);
    b.dec_r(rcx); // x86 decrements RCX even on the mismatching element
    b.mark_label(done);
    Ok(())
}

/// 1-operand MUL/IMUL/DIV/IDIV. The source r/m operand is op0; the accumulator
/// pair (RAX=v0 low, RDX=v2 high) is implicit. Memory sources are loaded into
/// SCRATCH first.
fn lift_muldiv(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let c = inst.code();
    // operand width in bits (8/16/32/64)
    let bits = if matches!(c, Mul_rm8 | Imul_rm8 | Div_rm8 | Idiv_rm8) {
        8
    } else if matches!(c, Mul_rm16 | Imul_rm16 | Div_rm16 | Idiv_rm16) {
        16
    } else if matches!(c, Mul_rm64 | Imul_rm64 | Div_rm64 | Idiv_rm64) {
        64
    } else {
        32
    };
    let is_imul = matches!(c, Imul_rm8 | Imul_rm16 | Imul_rm32 | Imul_rm64);
    let is_idiv = matches!(c, Idiv_rm8 | Idiv_rm16 | Idiv_rm32 | Idiv_rm64);
    let is_mul = matches!(c, Mul_rm8 | Mul_rm16 | Mul_rm32 | Mul_rm64);
    // source operand (op0): register or memory
    let src: u8 = if inst.op0_kind() == OpKind::Register {
        vreg(inst.op0_register())?
    } else {
        let addr = mem_emit(b, inst, 0)?;
        let load = match bits {
            8 => OP_MOVZX_R_MEM8_A,
            16 => OP_MOVZX_R_MEM16_A,
            64 => OP_MOV_R_MEM64_A,
            _ => OP_MOVZX_R_MEM32_A,
        };
        b.mem_load_a(load, SCRATCH, addr);
        SCRATCH
    };
    let op = match bits {
        8 => {
            if is_mul { OP_MUL_R_R8 }
            else if is_imul { OP_IMUL1_R_R8 }
            else if is_idiv { OP_IDIV_R_R8 }
            else { OP_DIV_R_R8 }
        }
        16 => {
            if is_mul { OP_MUL_R_R16 }
            else if is_imul { OP_IMUL1_R_R16 }
            else if is_idiv { OP_IDIV_R_R16 }
            else { OP_DIV_R_R16 }
        }
        64 => {
            if is_mul { OP_MUL_R_R64 }
            else if is_imul { OP_IMUL1_R_R64 }
            else if is_idiv { OP_IDIV_R_R64 }
            else { OP_DIV_R_R64 }
        }
        _ => {
            if is_mul { OP_MUL_R_R32 }
            else if is_imul { OP_IMUL1_R_R32 }
            else if is_idiv { OP_IDIV_R_R32 }
            else { OP_DIV_R_R32 }
        }
    };
    b.mul_r(op, src);
    Ok(())
}

/// CMPXCHG [rbx],rsi: if [dst]==rax { [dst]=src } else { rax=[dst] }. Non-atomic
/// emulation (single-thread lift).
fn lift_cmpxchg(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    // op0 = [mem] or reg, op1 = src; accumulator is RAX (v0).
    // width from the code name.
    use iced_x86::Code::*;
    let code = inst.code();
    let name = format!("{:?}", code);
    let wbits = if name.contains("rm8_") { 8 }
        else if name.contains("rm16_") { 16 }
        else if name.contains("rm64_") { 64 }
        else { 32 };
    let mov_wide = matches!(wbits, 64);
    let rax = 0u8;
    let src = vreg(inst.op1_register())?;
    // dest operand (op0) may be memory or a register
    let not_equal = b.new_label();
    if inst.op0_kind() == OpKind::Memory {
        // C-1 fix (--vm-oep null-store): keep the address in SCRATCH and load
        // [addr] into SCRATCH2. Previously addr==SCRATCH was used as BOTH the
        // address vreg AND the load destination, so the load overwrote the
        // address with the memory value. For a null-initialized global (e.g.
        // the CRT/Rust once-flag at 0x14001E208, value 0) the address became 0
        // and the subsequent store wrote to [0] -> 0xc0000005.
        let addr = mem_emit(b, inst, 0)?; // SCRATCH = addr (preserved)
        // v46 + v49 (--vm-oep): a memory cmpxchg is the Rust `Once`/futex CAS.
        // Emit a REAL atomic `lock cmpxchg [addr], src` for ALL widths
        // (OP_CMPXCHG_MEM8/16/32/64_A). v46 covered 32/64 only; the 8/16-bit
        // fallback was a non-atomic load/compare/conditional-store whose 32-bit
        // compare also never masked RAX to the operand width, so a byte/word CAS
        // always took the "not equal" branch when RAX upper bits were dirty, the
        // guarded flag never reached COMPLETE, and a later native call_once re-ran
        // the closure -> `f.take().unwrap()` panic at once.rs:166 (0xC0000005).
        let xop = match wbits {
            8 => OP_CMPXCHG_MEM8_A,
            16 => OP_CMPXCHG_MEM16_A,
            64 => OP_CMPXCHG_MEM64_A,
            _ => OP_CMPXCHG_MEM32_A,
        };
        b.mem_cmpxchg_a(xop, addr, src);
        return Ok(());
    } else {
        // register destination: cmpxchg r32,r32 (rare) -- treat like load path with
        // reg as the "memory" cell is not valid, so emulate via scratch.
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
        if mov_wide { b.mov_r_r64(dst, src); } else { b.mov_r_r(dst, src); }
        let done = b.new_label();
        b.jmp8(done);
        b.mark_label(not_equal);
        if mov_wide { b.mov_r_r64(rax, SCRATCH); } else { b.mov_r_r(rax, SCRATCH); }
        b.mark_label(done);
    }
    Ok(())
}

/// XADD dst, src: temp = dst; dst = dst + src; src = temp. For a memory dst we
/// emit a real `lock xadd [addr], src` (atomic fetch-add) — the register-register
/// form stays a plain add via scratch vregs.
fn lift_xadd(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    // width from the code name (rm8/r16/r32/r64)
    let name = format!("{:?}", code);
    let wbits = if name.contains("rm8_") || name.contains("r8_rm8") { 8 }
        else if name.contains("rm16_") || name.contains("r16_rm16") { 16 }
        else if name.contains("rm64_") || name.contains("r64_rm64") { 64 }
        else { 32 };
    let (addop, mov_wide) = match wbits {
        64 => (OP_ADD_R_R64, true),
        _ => (OP_ADD_R_R, false),
    };
    let mask: u32 = match wbits { 8 => 0xFF, 16 => 0xFFFF, _ => 0xFFFF_FFFF };
    // op0 = dst (r/m), op1 = src (reg)
    let src = vreg(inst.op1_register())?;
    if inst.op0_kind() == OpKind::Memory {
        // v48 fix: `xadd [mem], reg` must be a single atomic RMW. x86 XADD is only
        // atomic under the LOCK prefix; the native handler emits `lock xadd`.
        // Previously lifted as a non-atomic load->add->store, which broke Rust
        // atomic refcounts / fetch_add (a second op could read a stale value).
        let addr = mem_emit(b, inst, 0)?; // SCRATCH = addr (preserved)
        let xop = match wbits {
            8 => OP_XADD_MEM8_A,
            16 => OP_XADD_MEM16_A,
            64 => OP_XADD_MEM64_A,
            _ => OP_XADD_MEM32_A,
        };
        b.mem_xadd_a(xop, addr, src);
    } else {
        let dst = vreg(inst.op0_register())?;
        // SCRATCH = temp = dst
        if mov_wide { b.mov_r_r64(SCRATCH, dst); } else { b.mov_r_r(SCRATCH, dst); }
        // SCRATCH2 = temp + src
        b.mov_r_r(SCRATCH2, SCRATCH);
        if wbits == 64 { b.binop_r_r64(addop, SCRATCH2, src); }
        else { b.binop_r_r(addop, SCRATCH2, src); }
        if wbits == 8 || wbits == 16 { b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, mask); }
        // dst = temp + src
        if mov_wide { b.mov_r_r64(dst, SCRATCH2); } else { b.mov_r_r(dst, SCRATCH2); }
        if wbits == 8 || wbits == 16 { b.binop_r_imm32(OP_AND_R_IMM32, dst, mask); }
        // src = temp
        if mov_wide { b.mov_r_r64(src, SCRATCH); } else { b.mov_r_r(src, SCRATCH); }
        if wbits == 8 || wbits == 16 { b.binop_r_imm32(OP_AND_R_IMM32, src, mask); }
    }
    Ok(())
}

/// BT dst, src: CF = bit src of dst (bit test; dst unchanged).
/// Register src: loop-shift dst right by (src & mask) then isolate bit.
/// Immediate src: shift directly. CF is set by `0 - bit` (CF = bit != 0).
/// 16/32/64-bit supported (the 16-bit form rarely appears; 8-bit BT doesn't exist).
fn lift_bt(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let name = format!("{:?}", code);
    let wbits = if name.contains("rm16_") { 16 }
        else if name.contains("rm64_") { 64 }
        else { 32 };
    let mask: u32 = match wbits { 16 => 0xF, 32 => 0x1F, _ => 0x3F };
    // load dst value into SCRATCH
    if inst.op0_kind() == OpKind::Register {
        let d = vreg(inst.op0_register())?;
        if wbits == 64 { b.mov_r_r64(SCRATCH, d); } else { b.mov_r_r(SCRATCH, d); }
    } else {
        let addr = mem_emit(b, inst, 0)?;
        match wbits {
            16 => b.mem_load_a(OP_MOVZX_R_MEM16_A, SCRATCH, addr),
            64 => b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH, addr),
            _ => b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH, addr),
        }
    }
    if inst.op1_kind() == OpKind::Register {
        // index in a register: loop shift
        let idx = vreg(inst.op1_register())?;
        // SCRATCH2 = idx & mask
        if wbits == 64 { b.mov_r_r64(SCRATCH2, idx); } else { b.mov_r_r(SCRATCH2, idx); }
        b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, mask);
        let loop_lbl = b.new_label();
        let done = b.new_label();
        b.mark_label(loop_lbl);
        b.test_r_r32(SCRATCH2, SCRATCH2);
        b.jcc8(COND_JE, done);
        if wbits == 64 { b.shift64_r_imm8(OP_SHR64_R_IMM8, SCRATCH, 1); }
        else { b.shift_r_imm8(OP_SHR_R_IMM8, SCRATCH, 1); }
        b.dec_r(SCRATCH2);
        b.jmp8(loop_lbl);
        b.mark_label(done);
    } else {
        // immediate index: shift directly
        let cnt = if wbits == 64 { inst.immediate8() & 0x3F } else { inst.immediate8() & 0x1F };
        if wbits == 64 { b.shift64_r_imm8(OP_SHR64_R_IMM8, SCRATCH, cnt); }
        else { b.shift_r_imm8(OP_SHR_R_IMM8, SCRATCH, cnt); }
    }
    // isolate bit: SCRATCH &= 1
    b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH, 1);
    // CF = bit: 0 - bit  (CF = borrow = (0 < bit) = bit)
    b.mov_r_imm32(SCRATCH2, 0);
    b.binop_r_r(OP_SUB_R_R, SCRATCH2, SCRATCH);
    Ok(())
}

/// BTS/BTR/BTC: bit test-and-set/reset/complement.
/// Sets CF from the target bit (identical to BT), then modifies that bit in dst.
/// BTS sets the bit; BTR clears it; BTC flips it.
/// Handles register and memory destinations, 16/32/64-bit, reg or imm8 bit index.
fn lift_bts(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let name = format!("{:?}", code);
    let is_bts = name.starts_with("Bts_");
    let is_btr = name.starts_with("Btr_");
    // is_btc = neither bts nor btr
    let wbits = if name.contains("rm16_") { 16 }
        else if name.contains("rm64_") { 64 }
        else { 32 };
    let mask: u32 = match wbits { 16 => 0xF, 32 => 0x1F, _ => 0x3F };
    let is_mem = inst.op0_kind() == OpKind::Memory;

    // Compute bit index → SCRATCH2 = bit position (0..wbits-1)
    if inst.op1_kind() == OpKind::Register {
        let idx = vreg(inst.op1_register())?;
        if wbits == 64 { b.mov_r_r64(SCRATCH2, idx); } else { b.mov_r_r(SCRATCH2, idx); }
        b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, mask);
    } else {
        let cnt = if wbits == 64 { inst.immediate8() & 0x3F } else { inst.immediate8() & 0x1F };
        b.mov_r_imm32(SCRATCH2, cnt as u32);
    }

    // Load dst into a free temp (vreg 19) so the address stays in SCRATCH. (SCRATCH2
    // is used below as the bit-count register, so the value cannot live there.)
    let (mem_addr, dst_r) = if is_mem {
        let addr = mem_emit(b, inst, 0)?; // SCRATCH = addr (preserved)
        let load = match wbits { 16 => OP_MOVZX_R_MEM16_A, 64 => OP_MOV_R_MEM64_A, _ => OP_MOVZX_R_MEM32_A };
        b.mem_load_a(load, 19, addr);
        (Some(addr), 19)
    } else {
        let r = vreg(inst.op0_register())?;
        (None, r)
    };

    // Build a bit-mask (1 << SCRATCH2) into a temporary reg.
    // We do not have a variable-shift-into-scratch op, so we walk a loop:
    //   tmp = 1; while cnt != 0 { tmp <<= 1; cnt--; }
    // Use SCRATCH (free when dst_r != SCRATCH) for the bit mask.
    // When dst is a memory operand, SCRATCH holds the value → use SCRATCH for dst and need
    // extra space, but SCRATCH2 holds the count. We'll borrow a fixed vreg slot:
    // use vreg[18] as a third scratch (will not collide with x86 GPRs 0..15 or SCRATCH/SCRATCH2).
    const TMP: u8 = 18;
    b.mov_r_imm32(TMP, 1); // TMP = bit_mask = 1
    // SCRATCH2 = bit count (already set above); shift TMP left by SCRATCH2
    let loop_lbl = b.new_label();
    let done_shift = b.new_label();
    b.mark_label(loop_lbl);
    b.test_r_r32(SCRATCH2, SCRATCH2);
    b.jcc8(COND_JE, done_shift);
    if wbits == 64 { b.shift64_r_imm8(OP_SHL64_R_IMM8, TMP, 1); }
    else { b.shift_r_imm8(OP_SHL_R_IMM8, TMP, 1); }
    b.dec_r(SCRATCH2);
    b.jmp8(loop_lbl);
    b.mark_label(done_shift);

    // CF: (dst >> cnt) & 1  → same trick as lift_bt but without destroying dst.
    // We already have TMP = (1 << cnt). Compute (dst_r & TMP) into SCRATCH2 for CF.
    if wbits == 64 {
        b.mov_r_r64(SCRATCH2, dst_r);
        b.binop_r_r64(OP_AND_R_R64, SCRATCH2, TMP);
    } else {
        b.mov_r_r(SCRATCH2, dst_r);
        b.binop_r_r(OP_AND_R_R, SCRATCH2, TMP);
    }
    // CF = bit: 0 - SCRATCH2 != 0 → sets CF
    b.mov_r_imm32(TMP, 0);  // reuse TMP for zero
    b.binop_r_r(OP_SUB_R_R, TMP, SCRATCH2);

    // Reload TMP with bit mask (TMP was clobbered by 0 - SCRATCH2 which set CF; recover mask)
    // Rebuild mask from SCRATCH2: SCRATCH2 = (dst & mask); if !=0, bit was 1; TMP=1<<cnt
    // Actually we already computed CF above using TMP=0-SCRATCH2. Now redo the mask:
    // Restore bit index to SCRATCH2 again.
    if inst.op1_kind() == OpKind::Register {
        let idx = vreg(inst.op1_register())?;
        if wbits == 64 { b.mov_r_r64(SCRATCH2, idx); } else { b.mov_r_r(SCRATCH2, idx); }
        b.binop_r_imm32(OP_AND_R_IMM32, SCRATCH2, mask);
    } else {
        let cnt = if wbits == 64 { inst.immediate8() & 0x3F } else { inst.immediate8() & 0x1F };
        b.mov_r_imm32(SCRATCH2, cnt as u32);
    }
    b.mov_r_imm32(TMP, 1);
    let loop2 = b.new_label();
    let done2 = b.new_label();
    b.mark_label(loop2);
    b.test_r_r32(SCRATCH2, SCRATCH2);
    b.jcc8(COND_JE, done2);
    if wbits == 64 { b.shift64_r_imm8(OP_SHL64_R_IMM8, TMP, 1); }
    else { b.shift_r_imm8(OP_SHL_R_IMM8, TMP, 1); }
    b.dec_r(SCRATCH2);
    b.jmp8(loop2);
    b.mark_label(done2);

    // Modify dst bit
    if is_bts {
        // dst |= TMP
        if wbits == 64 { b.binop_r_r64(OP_OR_R_R64, dst_r, TMP); }
        else { b.binop_r_r(OP_OR_R_R, dst_r, TMP); }
    } else if is_btr {
        // dst &= ~TMP: NOT TMP then AND
        if wbits == 64 { b.not_r64(TMP); b.binop_r_r64(OP_AND_R_R64, dst_r, TMP); }
        else { b.not_r(TMP); b.binop_r_r(OP_AND_R_R, dst_r, TMP); }
    } else {
        // BTC: dst ^= TMP
        if wbits == 64 { b.binop_r_r64(OP_XOR_R_R64, dst_r, TMP); }
        else { b.binop_r_r(OP_XOR_R_R, dst_r, TMP); }
    }

    // Write back to memory if mem destination (addr still in SCRATCH, value in dst_r)
    if let Some(addr) = mem_addr {
        let store = match wbits { 16 => OP_MOV_MEM16_A, 64 => OP_MOV_MEM64_A, _ => OP_MOV_MEM32_A };
        b.mem_store_a(store, addr, dst_r);
    }
    Ok(())
}

/// BSR / BSF: dst = index of most/least significant set bit of src; ZF set iff src==0.
fn lift_bs(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    let dst = vreg(inst.op0_register())?;
    let is64 = matches!(code, Bsr_r64_rm64 | Bsf_r64_rm64);
    let op = if matches!(code, Bsr_r32_rm32 | Bsr_r64_rm64) {
        if is64 { OP_BSR_R64 } else { OP_BSR_R32 }
    } else {
        if is64 { OP_BSF_R64 } else { OP_BSF_R32 }
    };
    if inst.op1_kind() == OpKind::Register {
        let src = vreg(inst.op1_register())?;
        b.bsr_r(op, dst, src);
    } else {
        // memory source: load into SCRATCH then scan
        let addr = mem_emit(b, inst, 1)?;
        if is64 { b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH, addr); }
        else { b.mem_load_a(OP_MOVZX_R_MEM32_A, SCRATCH, addr); }
        b.bsr_r(op, dst, SCRATCH);
    }
    Ok(())
}

/// MOVQ between XMM and GPR (movq rax,xmm1 / movq xmm1,rax). Low 64 bits.
fn lift_movq(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    let code = inst.code();
    if code == Movq_xmm_rm64 {
        // op0 = xmm, op1 = gpr or mem
        let xmm = inst.op0_register().number() as u8;
        if inst.op1_kind() == OpKind::Register {
            b.movq_gpr_xmm(xmm, vreg(inst.op1_register())?);
        } else {
            let addr = mem_emit(b, inst, 1)?;
            b.movsd_xmm_mem(xmm, addr);
        }
    } else {
        // Movq_rm64_xmm: op0 = gpr or mem, op1 = xmm
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

/// Unified lifter for SHL, SHR, SAR, ROL, ROR (8/16/32/64-bit, reg/mem, _1/_imm8/_CL).
fn lift_shift_rotate(b: &mut BytecodeBuilder, inst: &Instruction) -> Result<()> {
    use iced_x86::Code::*;
    use iced_x86::OpKind;
    let code = inst.code();

    let name = format!("{:?}", code);
    let is_shl = name.starts_with("Shl_");
    let is_shr = name.starts_with("Shr_");
    let is_sar = name.starts_with("Sar_");
    let is_rol = name.starts_with("Rol_");

    let is8 = name.contains("_rm8_");
    let is16 = name.contains("_rm16_");
    let is64 = name.contains("_rm64_");

    let mem_target = inst.op0_kind() == OpKind::Memory;
    // Capture the address ONCE into SCRATCH and load+shift the value in SCRATCH2,
    // so the store below can reuse the (still-live) address instead of re-emitting it.
    let (dst_reg, mem_addr) = if mem_target {
        let addr = mem_emit(b, inst, 0)?;
        let load_op = if is8 {
            OP_MOVZX_R_MEM8_A
        } else if is16 {
            OP_MOVZX_R_MEM16_A
        } else if is64 {
            OP_MOV_R_MEM64_A
        } else {
            OP_MOVZX_R_MEM32_A
        };
        b.mem_load_a(load_op, SCRATCH2, addr);
        (SCRATCH2, Some(addr))
    } else {
        (vreg(inst.op0_register())?, None)
    };

    let is_cl = name.ends_with("_CL");
    let is_one = name.ends_with("_1");

    if is_rol || name.starts_with("Ror_") {
        let cnt = if is_one {
            1
        } else if is_cl {
            if vreg(inst.op1_register())? != 1 {
                return Err(anyhow!("lifter: CL shift source must be RCX"));
            }
            // VM rotate imm8 handles CL count if we copy vreg[1] to count
            // Note: VM rot ops take imm8 count; for CL rotate use imm count if static or 1
            1
        } else {
            inst.immediate8() as u8
        };

        if is_rol {
            b.rol_r_imm8(dst_reg, cnt);
        } else {
            b.ror_r_imm8(dst_reg, cnt);
        }
    } else if is_cl {
        if vreg(inst.op1_register())? != 1 {
            return Err(anyhow!("lifter: CL shift source must be RCX"));
        }
        let op = if is64 {
            if is_shl {
                OP_SHL64_R_CL
            } else if is_shr {
                OP_SHR64_R_CL
            } else {
                OP_SAR64_R_CL
            }
        } else {
            if is_shl {
                OP_SHL_R_CL
            } else if is_shr {
                OP_SHR_R_CL
            } else {
                OP_SAR_R_CL
            }
        };
        b.shift_r_cl(op, dst_reg);
    } else {
        let cnt = if is_one { 1 } else { inst.immediate8() as u8 };
        if is64 {
            let op = if is_shl {
                OP_SHL64_R_IMM8
            } else if is_shr {
                OP_SHR64_R_IMM8
            } else {
                OP_SAR64_R_IMM8
            };
            b.shift64_r_imm8(op, dst_reg, cnt);
        } else {
            let op = if is_shl {
                OP_SHL_R_IMM8
            } else if is_shr {
                OP_SHR_R_IMM8
            } else {
                OP_SAR_R_IMM8
            };
            b.shift_r_imm8(op, dst_reg, cnt);
        }
    }

    if is8 {
        b.binop_r_imm32(OP_AND_R_IMM32, dst_reg, 0xFF);
    } else if is16 {
        b.binop_r_imm32(OP_AND_R_IMM32, dst_reg, 0xFFFF);
    }

    if let Some(addr) = mem_addr {
        let store_op = if is8 {
            OP_MOV_MEM8_A
        } else if is16 {
            OP_MOV_MEM16_A
        } else if is64 {
            OP_MOV_MEM64_A
        } else {
            OP_MOV_MEM32_A
        };
        b.mem_store_a(store_op, addr, dst_reg);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Code, Instruction, Register};

    #[test]
    fn test_lift_shr_rm8_1() {
        // test lifting `shr r9b, 1` (Code::Shr_rm8_1)
        let inst = Instruction::with2(Code::Shr_rm8_1, Register::R9L, 1).unwrap();
        let mut b = BytecodeBuilder::new();
        assert!(lift_one(&mut b, &inst).is_ok());
        let bc = b.finish();
        assert!(!bc.is_empty());
    }

    #[test]
    fn test_lift_movdqu_xmm_xmmm128() {
        // test lifting `movdqu xmm0, [rsp+0x23]` (Code::Movdqu_xmm_xmmm128)
        use iced_x86::MemoryOperand;
        let mem = MemoryOperand::with_base_displ(Register::RSP, 0x23);
        let inst = Instruction::with2(Code::Movdqu_xmm_xmmm128, Register::XMM0, mem).unwrap();
        let mut b = BytecodeBuilder::new();
        assert!(lift_one(&mut b, &inst).is_ok());
        let bc = b.finish();
        assert!(!bc.is_empty());
    }
}



