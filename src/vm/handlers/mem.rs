// ==============================================================================
// BTG v3 - VM Handler Codegen: MEM family
// ==============================================================================
// Memory access handlers: MOVZX/MOVSX/MOV loads & stores (pointer-slot and
// absolute-address forms), and LEA / LEA_RIP / LEA_GS / SET_RIP addressing.
// Shared helpers (`hdr`, `m`, `vreg`, `ptrslot`, ...) and the `Cl` label enum
// live in `super` (mod.rs).
// ==============================================================================

use super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

// ── 0x0F MOVZX r, byte [ptr[slot] + vreg[idx]] (op, dst, slot, idx) ────────
pub(super) fn emit_movzx_r_mem8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOVZX_R_MEM8,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RAX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, ptrslot(Register::RDX)).unwrap(),
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::EAX,
                MemoryOperand::with_base_index_scale(Register::R11, Register::RAX, 1),
            )
            .unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
        ],
    );
}

// ── 0x10 MOV byte [ptr[slot] + vreg[idx]], r8 (op, slot, idx, src) ─────────
pub(super) fn emit_mov_mem8_r(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOV_MEM8_R,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, ptrslot(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RAX)).unwrap(),
            Instruction::with2(
                Code::Mov_rm8_r8,
                MemoryOperand::with_base_index_scale(Register::R11, Register::RCX, 1),
                Register::AL,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
        ],
    );
}

// ── M2 follow-up (v24) 0x34 OP_LEA (dst, base, idx, scale_enc, disp32) ─────
//   vreg[dst] = vreg[base] + (idx==ADDR_NO_INDEX?0 : vreg[idx]<<scale) + sext(disp32)
pub(super) fn emit_lea(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::ESI,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        Some(Cl::Handler(OP_LEA)),
    ));
    seq.push((
        Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, m(Register::R9, 1)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 2)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 3)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Cmp_rm8_imm8, Register::DL, ADDR_NO_INDEX as i32).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(Cl::LeaNoIndex),
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_rm64, Register::RBX, vreg(Register::RDX)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Shl_rm64_CL, Register::RBX, Register::CL).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_r64, Register::R11, Register::RBX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Movsxd_r64_rm32, Register::RAX, m(Register::R9, 4)).unwrap(),
        Some(Cl::LeaNoIndex),
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_r64, Register::R11, Register::RAX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RSI), Register::R11).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 8).unwrap(),
        None,
    ));
    emit_dispatch(seq, None);
}

// ── M2 follow-up (v24) 0x35 OP_SET_RIP (imm64) — STATE_RIP = imm64 ──────────
pub(super) fn emit_set_rip(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    seq.push((
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        Some(Cl::Handler(OP_SET_RIP)),
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_rm64_r64,
            m(Register::R8, STATE_RIP as i32),
            Register::RAX,
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 8).unwrap(),
        None,
    ));
    emit_dispatch(seq, None);
}

// ── M2 follow-up (v24) 0x36 OP_LEA_RIP (dst, rel32) — vreg[dst] = STATE_RIP + sext(rel32) ──
pub(super) fn emit_lea_rip(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::ECX,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        Some(Cl::Handler(OP_LEA_RIP)),
    ));
    seq.push((
        Instruction::with2(Code::Movsxd_r64_rm32, Register::RAX, m(Register::R9, 1)).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::R11,
            m(Register::R8, STATE_RIP as i32),
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R11).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap(),
        None,
    ));
    emit_dispatch(seq, None);
}

// ── 0x6B OP_LEA_GS (dst, disp32) — vreg[dst] = STATE_SEG_GS + sext(disp32) ──
// (gs:/fs: PEB/TEB 세그먼트 접근 — M6 Phase-2)
pub(super) fn emit_lea_gs(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::ECX,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        Some(Cl::Handler(OP_LEA_GS)),
    ));
    seq.push((
        Instruction::with2(Code::Movsxd_r64_rm32, Register::RAX, m(Register::R9, 1)).unwrap(),
        None,
    ));
    // v43/fix: dynamically read live GS:[0x30] (TEB.Self) so both main and worker threads
    // access their active thread's true TEB/TLS structures.
    seq.push((
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::R11,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x30, false, Register::GS),
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R11).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap(),
        None,
    ));
    emit_dispatch(seq, None);
}

// ── M2 follow-up (v24) 0x37-0x3C absolute-address memory loads (dst, addr) ──
// addr = vreg[addr]
pub(super) fn emit_mem_loads_abs(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, dst_reg) in [
        (OP_MOVZX_R_MEM8_A, Code::Movzx_r32_rm8, Register::EAX),
        (OP_MOVZX_R_MEM16_A, Code::Movzx_r32_rm16, Register::EAX),
        (OP_MOVZX_R_MEM32_A, Code::Mov_r32_rm32, Register::EAX),
        (OP_MOVSX_R_MEM8_A, Code::Movsx_r64_rm8, Register::RAX),
        (OP_MOVSX_R_MEM16_A, Code::Movsx_r64_rm16, Register::RAX),
        (OP_MOV_R_MEM64_A, Code::Mov_r64_rm64, Register::RAX),
    ] {
        seq.push((
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Some(Cl::Handler(op)),
        ));
        seq.push((
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RDX)).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(code, dst_reg, MemoryOperand::with_base(Register::R11)).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
            None,
        ));
        emit_dispatch(seq, None);
    }
}

// ── M2 follow-up (v24) 0x3D-0x40 absolute-address memory stores (addr, src) ─
pub(super) fn emit_mem_stores_abs(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, store_code, src_reg, load_code) in [
        (
            OP_MOV_MEM8_A,
            Code::Mov_rm8_r8,
            Register::AL,
            Code::Mov_r8_rm8,
        ),
        (
            OP_MOV_MEM16_A,
            Code::Mov_rm16_r16,
            Register::AX,
            Code::Mov_r16_rm16,
        ),
        (
            OP_MOV_MEM32_A,
            Code::Mov_rm32_r32,
            Register::EAX,
            Code::Mov_r32_rm32,
        ),
        (
            OP_MOV_MEM64_A,
            Code::Mov_rm64_r64,
            Register::RAX,
            Code::Mov_r64_rm64,
        ),
    ] {
        hdr(
            seq,
            op,
            vec![
                Instruction::with2(
                    Code::Movzx_r32_rm8,
                    Register::ECX,
                    MemoryOperand::with_base(Register::R9),
                )
                .unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
                Instruction::with2(load_code, src_reg, vreg(Register::RDX)).unwrap(),
                Instruction::with2(store_code, MemoryOperand::with_base(Register::R11), src_reg)
                    .unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
            ],
        );
    }
}
