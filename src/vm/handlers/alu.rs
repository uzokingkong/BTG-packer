// ==============================================================================
// BTG v3 - VM Handler Codegen: ALU family
// ==============================================================================
// Arithmetic / logical / bit-manipulation handlers: XOR/ADD/IMUL/SUB/AND/OR,
// ROL/ROR, INC/DEC, CMP, TEST, shifts (imm8 and CL, 32/64-bit), NEG/NOT/NOP,
// and the v45 --vm-oep system instructions (CPUID / XGETBV / TZCNT).
//
// Split into:
//   alu_arith.rs  - XOR/ADD/IMUL/SUB/AND/OR, ROL/ROR, INC/DEC, CMP, TEST, NEG/NOT
//   alu_shift.rs  - SHL/SHR/SAR + SHLD/SHRD (imm8 & CL, 32/64-bit)
//   alu_bmi.rs    - LZCNT/POPCNT/BLSR/BLSMSK/BLSI/ANDN
//   alu_sys.rs    - NOP / CPUID / XGETBV / TZCNT
// Shared helpers (`hdr`, `m`, `vreg`, `cap_flags`, ...) and the `Cl` label enum
// live in `super` (mod.rs).
// ==============================================================================

mod alu_arith;
mod alu_bmi;
mod alu_shift;
mod alu_sys;

pub(super) use alu_arith::{
    emit_alu_imm32, emit_alu_imm64, emit_alu_rr, emit_alu_rr64, emit_alu_sub8_sub16,
    emit_cmp_r_imm32,
    emit_inc_dec, emit_neg, emit_not, emit_or_imm, emit_or_rr, emit_rol_r_imm8,
    emit_ror_r_imm8, emit_test,
};
pub(super) use alu_bmi::{emit_andn, emit_blsi, emit_blsmsk, emit_blsr, emit_lzcnt, emit_popcnt};
pub(super) use alu_shift::{emit_shld_shrd, emit_shift_cl_32, emit_shift_cl_64, emit_shift_imm8_32, emit_shift_imm8_64};
pub(super) use alu_sys::{emit_cpuid, emit_nop, emit_tzcnt, emit_xgetbv};