// ==============================================================================
// BTG v3 - VM Handler Codegen: MUL/DIV + bit-scan family
// ==============================================================================
// 1-op multiply / divide (8/16/32/64-bit) on the accumulator pair RAX(v0)/
// RDX(v2), plus BSWAP and BSR/BSF. Shared helpers (`hdr`, `m`, `vreg`,
// `cap_flags`, ...) and the `Cl` label enum live in `super` (mod.rs).
// ==============================================================================

use super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

// ── v31: 1-op multiply/divide + BSWAP ─────────────────────────────────────
// The accumulator pair RAX(v0)/RDX(v2) maps directly to GPRs, so the native
// handler uses the real x86 mul/div/imul/idiv instructions. src is a vreg.
// MUL64: rdx:rax = rax * r11
pub(super) fn emit_mul_rr64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MUL_R_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Mul_rm64, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// MUL32: edx:eax = eax * r11d (zero-extended into vregs)
pub(super) fn emit_mul_rr32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MUL_R_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Mul_rm32, Register::R11D).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// IMUL64 (1-op): rdx:rax = rax * r11 (signed)
pub(super) fn emit_imul1_rr64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_IMUL1_R_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Imul_rm64, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// IMUL32 (1-op, signed)
pub(super) fn emit_imul1_rr32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_IMUL1_R_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Imul_rm32, Register::R11D).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// DIV64: rax = rdx:rax / r11; rdx = remainder (unsigned)
pub(super) fn emit_div_rr64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_DIV_R_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Div_rm64, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// DIV32 (unsigned)
pub(super) fn emit_div_rr32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_DIV_R_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Div_rm32, Register::R11D).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// IDIV64 (signed)
pub(super) fn emit_idiv_rr64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_IDIV_R_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Idiv_rm64, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// IDIV32 (signed)
pub(super) fn emit_idiv_rr32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_IDIV_R_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Idiv_rm32, Register::R11D).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// BSWAP32: r11d = bswap(vreg[r]); store zero-extended (upper 32 cleared)
pub(super) fn emit_bswap32(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_BSWAP_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Bswap_r32, Register::R11D).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// BSWAP64
pub(super) fn emit_bswap64(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_BSWAP_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Bswap_r64, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// BSR/BSF: dst = bit index (most/least significant set bit of src); ZF set if src==0.
// Uses real x86 bsr/bsf; captures flags (cap_flags(false) keeps ZF/SF/PF).
pub(super) fn emit_bsr_bsf(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    for (op, code32, code64, is64) in [
        (OP_BSR_R32, Code::Bsr_r32_rm32, Code::Bsr_r64_rm64, false),
        (OP_BSR_R64, Code::Bsr_r32_rm32, Code::Bsr_r64_rm64, true),
        (OP_BSF_R32, Code::Bsf_r32_rm32, Code::Bsf_r64_rm64, false),
        (OP_BSF_R64, Code::Bsf_r32_rm32, Code::Bsf_r64_rm64, true),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        ];
        if is64 {
            body.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap());
            body.push(Instruction::with2(code64, Register::RAX, Register::RAX).unwrap());
            body.push(Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap());
        } else {
            body.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RDX)).unwrap());
            body.push(Instruction::with2(code32, Register::EAX, Register::EAX).unwrap());
            body.push(Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap());
        }
        body.extend(cap_flags(false));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(seq, op, body);
    }
}

// ── v33: 1-op multiply/divide 8/16-bit width ────────────────────────────
// Uses the real x86 8/16-bit mul/imul/div/idiv on the accumulator AX/DX.
// MUL8: AX = AL * r11b (unsigned); result zero-extended into v0.
pub(super) fn emit_mul_rr8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MUL_R_R8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFF).unwrap(),
            Instruction::with1(Code::Mul_rm8, Register::R11L).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// MUL16: DX:AX = AX * r11w (unsigned); v0=low16, v2=high16.
pub(super) fn emit_mul_rr16(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MUL_R_R16,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFFFF).unwrap(),
            Instruction::with1(Code::Mul_rm16, Register::R11W).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// IMUL8 (signed): AX = AL * r11b, treated as signed bytes.
pub(super) fn emit_imul1_rr8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_IMUL1_R_R8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFF).unwrap(),
            Instruction::with1(Code::Imul_rm8, Register::R11L).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// IMUL16 (signed): DX:AX = AX * r11w, treated as signed words.
pub(super) fn emit_imul1_rr16(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_IMUL1_R_R16,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFFFF).unwrap(),
            Instruction::with1(Code::Imul_rm16, Register::R11W).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// DIV8: AL = AX / r11b; AH = remainder (unsigned). Quotient must fit 8 bits.
pub(super) fn emit_div_rr8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_DIV_R_R8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFF).unwrap(),
            Instruction::with1(Code::Div_rm8, Register::R11L).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// DIV16: AX = DX:AX / r11w; DX = remainder (unsigned).
pub(super) fn emit_div_rr16(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_DIV_R_R16,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RDX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFFFF).unwrap(),
            Instruction::with1(Code::Div_rm16, Register::R11W).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// IDIV8 (signed): AL = AX / r11b; AH = remainder.
pub(super) fn emit_idiv_rr8(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_IDIV_R_R8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFF).unwrap(),
            Instruction::with1(Code::Idiv_rm8, Register::R11L).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}

// IDIV16 (signed): AX = DX:AX / r11w; DX = remainder.
pub(super) fn emit_idiv_rr16(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_IDIV_R_R16,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RDX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFFFF).unwrap(),
            Instruction::with1(Code::Idiv_rm16, Register::R11W).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
}
