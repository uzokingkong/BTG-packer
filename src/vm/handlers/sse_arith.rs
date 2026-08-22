// ==============================================================================
// BTG v3 - VM Handler Codegen: SSE/FPU (Group A, Phase 2.1)
// ==============================================================================
// Scalar FP arithmetic (ADDSS/ADDSD/SUBSS/SUBSD/MULSS/MULSD/DIVSS/DIVSD),
// 128-bit packed logic (PAND/POR/PANDN), and the conversion family
// (CVTSI2SD/CVTSI2SS, CVTSS2SD/CVTSD2SS, CVTTSS2SI/CVTTSD2SI, CVTSS2SI/CVTSD2SI)
// plus packed dword extract/insert (PEXTRD/PINSRD). The XMM register file lives
// in the state buffer as memory: slot base = r8 + STATE_XMM + idx*16. None of
// these ops touch the modelled status flags (x86 SSE scalar FP / logic writes
// no rflags — matching the interpreter, no cap_flags here).
// Shared helpers (`hdr`, `m`, `vreg`, `jmp_disp`, ...) and `Cl` live in `super`.
// ==============================================================================

use super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

/// Compute the XMM slot base address (r8 + STATE_XMM + idx*16) into `dst`,
/// where `idx` is a 64-bit scratch register already holding the XMM index.
/// Clobbers nothing else.
fn xmm_slot(dst: Register, idx: Register) -> Vec<Instruction> {
    vec![
        Instruction::with2(Code::Shl_rm64_imm8, idx, 4).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, dst, Register::R8).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, dst, idx).unwrap(),
        Instruction::with2(Code::Add_rm64_imm32, dst, STATE_XMM as i32).unwrap(),
    ]
}

// ── Scalar FP arithmetic: xmm[dst].low OP= xmm[src].low ─────────────────────
// Encoding [op, dst_xmm, src_xmm]. Loads the low element of both slots into
// xmm0/xmm1, applies the native op, stores the low element back (upper bytes
// of the dst slot preserved — x86 scalar semantics).
pub(super) fn emit_sse_scalar_fp(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code, wide) in [
        (OP_ADDSS_XMM, Code::Addss_xmm_xmmm32, false),
        (OP_ADDSD_XMM, Code::Addsd_xmm_xmmm64, true),
        (OP_SUBSS_XMM, Code::Subss_xmm_xmmm32, false),
        (OP_SUBSD_XMM, Code::Subsd_xmm_xmmm64, true),
        (OP_MULSS_XMM, Code::Mulss_xmm_xmmm32, false),
        (OP_MULSD_XMM, Code::Mulsd_xmm_xmmm64, true),
        (OP_DIVSS_XMM, Code::Divss_xmm_xmmm32, false),
        (OP_DIVSD_XMM, Code::Divsd_xmm_xmmm64, true),
    ] {
        let load = if wide {
            Code::Movsd_xmm_xmmm64
        } else {
            Code::Movss_xmm_xmmm32
        };
        let store = if wide {
            Code::Movsd_xmmm64_xmm
        } else {
            Code::Movss_xmmm32_xmm
        };
        let mut body = vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        ];
        // R11 = dst slot base, RAX = src slot base.
        body.extend(xmm_slot(Register::R11, Register::RCX));
        body.extend(xmm_slot(Register::RAX, Register::RDX));
        body.extend(vec![
            Instruction::with2(
                load,
                Register::XMM0,
                MemoryOperand::with_base(Register::R11),
            )
            .unwrap(),
            Instruction::with2(
                load,
                Register::XMM1,
                MemoryOperand::with_base(Register::RAX),
            )
            .unwrap(),
            Instruction::with2(code, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with2(
                store,
                MemoryOperand::with_base(Register::R11),
                Register::XMM0,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ]);
        hdr(seq, op, body);
    }
}

// ── 128-bit packed logic: PAND / POR / PANDN ────────────────────────────────
// Encoding [op, dst_xmm, src_xmm]. dst OP= src for the full 16 bytes.
pub(super) fn emit_sse_logic(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_PAND_XMM, Code::Pand_xmm_xmmm128),
        (OP_POR_XMM, Code::Por_xmm_xmmm128),
        (OP_PANDN_XMM, Code::Pandn_xmm_xmmm128),
    ] {
        let mut body = vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        ];
        body.extend(xmm_slot(Register::R11, Register::RCX));
        body.extend(xmm_slot(Register::RAX, Register::RDX));
        body.extend(vec![
            Instruction::with2(
                Code::Movdqu_xmm_xmmm128,
                Register::XMM0,
                MemoryOperand::with_base(Register::R11),
            )
            .unwrap(),
            Instruction::with2(
                Code::Movdqu_xmm_xmmm128,
                Register::XMM1,
                MemoryOperand::with_base(Register::RAX),
            )
            .unwrap(),
            Instruction::with2(code, Register::XMM0, Register::XMM1).unwrap(),
            Instruction::with2(
                Code::Movdqu_xmmm128_xmm,
                MemoryOperand::with_base(Register::R11),
                Register::XMM0,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ]);
        hdr(seq, op, body);
    }
}

// ── Integer -> float: CVTSI2SD (64-bit src) / CVTSI2SS (32-bit src) ─────────
// Encoding [op, dst_xmm, src_gpr]. xmm[dst].low = (fp)vreg[src] (signed); the
// rest of the XMM slot is zeroed (pxor before the convert, full 16B store).
pub(super) fn emit_cvt_si2fp(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, load, sreg, cvt) in [
        (
            OP_CVTSI2SD_XMM,
            Code::Mov_r64_rm64,
            Register::RAX,
            Code::Cvtsi2sd_xmm_rm64,
        ),
        (
            OP_CVTSI2SS_XMM,
            Code::Mov_r32_rm32,
            Register::EAX,
            Code::Cvtsi2ss_xmm_rm32,
        ),
    ] {
        let mut body = vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(load, sreg, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Pxor_xmm_xmmm128, Register::XMM0, Register::XMM0).unwrap(),
            Instruction::with2(cvt, Register::XMM0, sreg).unwrap(),
        ];
        // RDX = dst slot base (writing EAX above already zero-extended RAX).
        body.extend(xmm_slot(Register::RDX, Register::RCX));
        body.extend(vec![
            Instruction::with2(
                Code::Movdqu_xmmm128_xmm,
                MemoryOperand::with_base(Register::RDX),
                Register::XMM0,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ]);
        hdr(seq, op, body);
    }
}

// ── Float <-> float: CVTSS2SD / CVTSD2SS ────────────────────────────────────
// Encoding [op, dst_xmm, src_xmm]. xmm[dst].low = convert(xmm[src].low); the
// rest of the dst slot is zeroed.
pub(super) fn emit_cvt_fp2fp(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_CVTSS2SD_XMM, Code::Cvtss2sd_xmm_xmmm32),
        (OP_CVTSD2SS_XMM, Code::Cvtsd2ss_xmm_xmmm64),
    ] {
        let mut body = vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        ];
        // R11 = src slot base; convert its low element into zeroed XMM0.
        body.extend(xmm_slot(Register::R11, Register::RDX));
        body.extend(vec![
            Instruction::with2(Code::Pxor_xmm_xmmm128, Register::XMM0, Register::XMM0).unwrap(),
            Instruction::with2(
                code,
                Register::XMM0,
                MemoryOperand::with_base(Register::R11),
            )
            .unwrap(),
        ]);
        // RDX = dst slot base (src idx already consumed above).
        body.extend(xmm_slot(Register::RDX, Register::RCX));
        body.extend(vec![
            Instruction::with2(
                Code::Movdqu_xmmm128_xmm,
                MemoryOperand::with_base(Register::RDX),
                Register::XMM0,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ]);
        hdr(seq, op, body);
    }
}

// ── Float -> integer: CVTTSS2SI / CVTTSD2SI (trunc) + CVTSS2SI / CVTSD2SI
// (round to nearest even — the hardware default MXCSR RC). Encoding
// [op, dst_gpr, src_xmm]: vreg[dst] = (i32)(xmm[src].low), zero-extended.
pub(super) fn emit_cvt_fp2si(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code) in [
        (OP_CVTTSS2SI, Code::Cvttss2si_r32_xmmm32),
        (OP_CVTTSD2SI, Code::Cvttsd2si_r32_xmmm64),
        (OP_CVTSS2SI, Code::Cvtss2si_r32_xmmm32),
        (OP_CVTSD2SI, Code::Cvtsd2si_r32_xmmm64),
    ] {
        let mut body = vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        ];
        // RAX = src slot base; convert low element into EAX (zero-extends RAX).
        body.extend(xmm_slot(Register::RAX, Register::RDX));
        body.extend(vec![
            Instruction::with2(code, Register::EAX, MemoryOperand::with_base(Register::RAX))
                .unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ]);
        hdr(seq, op, body);
    }
}

// ── PEXTRD: vreg[dst] = xmm[src].dword[imm & 3] (zero-extended) ─────────────
// Encoding [op, dst_gpr, src_xmm, imm8] (3 operands).
pub(super) fn emit_pextrd(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    let mut body = vec![
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::ECX,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
    ];
    // R11 = src slot base; EAX = (lane & 3) * 4 (byte offset).
    body.extend(xmm_slot(Register::R11, Register::RDX));
    body.extend(vec![
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, 3).unwrap(),
        Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 2).unwrap(),
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::EAX,
            MemoryOperand::with_base_index_scale(Register::R11, Register::RAX, 1),
        )
        .unwrap(),
        // EAX write zero-extends into RAX; store the full 64-bit slot.
        Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
    ]);
    hdr(seq, OP_PEXTRD_XMM, body);
}

// ── PINSRD: xmm[dst].dword[imm & 3] = vreg[src].low32 (others kept) ─────────
// Encoding [op, dst_xmm, src_gpr, imm8] (3 operands).
pub(super) fn emit_pinsrd(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    let mut body = vec![
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::ECX,
            MemoryOperand::with_base(Register::R9),
        )
        .unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
        Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RDX)).unwrap(),
    ];
    // RDX = dst slot base; EAX = (lane & 3) * 4 (byte offset).
    body.extend(xmm_slot(Register::RDX, Register::RCX));
    body.extend(vec![
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, 3).unwrap(),
        Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 2).unwrap(),
        Instruction::with2(
            Code::Mov_rm32_r32,
            MemoryOperand::with_base_index_scale(Register::RDX, Register::RAX, 1),
            Register::R11D,
        )
        .unwrap(),
        Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
    ]);
    hdr(seq, OP_PINSRD_XMM, body);
}
