// ==============================================================================
// BTG v3 - VM Handler Codegen: XMM family
// ==============================================================================
// SSE data-movement / shuffle handlers that operate on the state XMM file as
// memory: movsd/movups/movq, unpcklpd/unpcklps, xorps, pshuflw/pshufhw/pshufd,
// psrlq/psllq, and pinsrw. Shared helpers (`hdr`, `m`, `vreg`, `jmp_disp`, ...)
// and the `Cl` label enum live in `super` (mod.rs).
// ==============================================================================

use super::*;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

// ── A-5 (v29): XMM moves (operate on the state XMM file as memory) ─────────
// Bytecode operand order: *_XMM_MEM=[xmm,addr] ; *_MEM_XMM=[addr,xmm].
// r9->bytecode. XMM slot address = r8 + STATE_XMM + xmm*16 (computed in RDX).
// 0x51 movsd xmm, [addr]  (8 bytes, zero high)
pub(super) fn emit_movsd_xmm_mem(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOVSD_XMM_MEM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RCX).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                MemoryOperand::with_base(Register::RAX),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
                Register::RCX,
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm32_imm32,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64 + 8,
                    1,
                ),
                0,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// 0x52 movsd [addr], xmm  (8 bytes)
pub(super) fn emit_movsd_mem_xmm(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOVSD_MEM_XMM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base(Register::RAX),
                Register::RCX,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// 0x74 movq xmm[src] -> vreg[dst] (low 64 bits)
pub(super) fn emit_movq_xmm_gpr(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOVQ_XMM_GPR,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// 0x75 movq vreg[src] -> xmm[dst] (low 64 bits, high zeroed)
pub(super) fn emit_movq_gpr_xmm(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOVQ_GPR_XMM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
                Register::RAX,
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm32_imm32,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    STATE_XMM as i64 + 8,
                    1,
                ),
                0,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// 0x53 movups xmm, [addr]  (16 bytes)
pub(super) fn emit_movups_xmm_mem(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOVUPS_XMM_MEM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RCX).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                MemoryOperand::with_base(Register::RAX),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
                Register::RCX,
            )
            .unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::RAX, 8)).unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64 + 8,
                    1,
                ),
                Register::RCX,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// 0x54 movups [addr], xmm  (16 bytes)
pub(super) fn emit_movups_mem_xmm(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_MOVUPS_MEM_XMM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base(Register::RAX),
                Register::RCX,
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64 + 8,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::RAX, 8), Register::RCX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// 0x55 unpcklpd xmm[dst], xmm[src] -> {dst.lo, src.lo}
pub(super) fn emit_unpcklpd(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_UNPCKLPD_XMM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R10,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R11,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
                Register::R10,
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    STATE_XMM as i64 + 8,
                    1,
                ),
                Register::R11,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// 0x8A unpcklps xmm[dst], xmm[src] -> { src.d1, dst.d1, src.d0, dst.d0 }.
// SSE single-precision unpack: interleave the low 2 dwords of dst with the
// low 2 dwords of src. All four dwords are read BEFORE any write so the
// dst==src case is correct. Scratch: rax/rcx/rdx/rsi/rbx/r10/r11 (rsi/rbx
// hold the src/dst slot base pointers; reloaded each dispatch like pshufd).
pub(super) fn emit_unpcklps(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_UNPCKLPS_XMM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            // src slot base in RSI = r8 + src*16 + STATE_XMM
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R8).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, STATE_XMM as i32).unwrap(),
            // dst slot base in RBX = r8 + dst*16 + STATE_XMM
            Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R8).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::RBX, Register::RCX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::RBX, STATE_XMM as i32).unwrap(),
            // read all four dwords before writing
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EAX,
                MemoryOperand::with_base(Register::RSI),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::R10D,
                MemoryOperand::with_base_displ(Register::RSI, 4),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EDX,
                MemoryOperand::with_base(Register::RBX),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::R11D,
                MemoryOperand::with_base_displ(Register::RBX, 4),
            )
            .unwrap(),
            // write { src.d1, dst.d1, src.d0, dst.d0 } to dst slot
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base(Register::RBX),
                Register::EDX,
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base_displ(Register::RBX, 4),
                Register::EAX,
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base_displ(Register::RBX, 8),
                Register::R11D,
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base_displ(Register::RBX, 12),
                Register::R10D,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// 0x6C xorps xmm[dst] ^= xmm[src] (128-bit bitwise XOR). Uses r11/rax scratch
// (preserves r10 = handler-table base). Mirrors the movsd/unpcklpd slot addressing.
pub(super) fn emit_xorps(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_XORPS_XMM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            // lo 64 bits: dst.lo ^= src.lo
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R11,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R11).unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
                Register::RAX,
            )
            .unwrap(),
            // hi 64 bits: dst.hi ^= src.hi
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R11,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64 + 8,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    STATE_XMM as i64 + 8,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R11).unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    STATE_XMM as i64 + 8,
                    1,
                ),
                Register::RAX,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// ── A-5 (v29): 0x6D-0x6F SSE shuffles: pshuflw/pshufhw/pshufd ─────────────
// The imm is a runtime bytecode operand (r9+2), so it cannot be baked into
// a native x86 shuffle immediate. We implement the shuffle with GPR word
// extraction from the state XMM memory. Scratch: rax/rcx/rdx/r11/rbx/rsi
// (all preserved around the VM call / dispatch reloads r10).
// pshuflw: shuffle low 4 words; high 64 bits of dst unchanged.
pub(super) fn emit_pshuflw(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_PSHUFLW_XMM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            // rsi = src slot base
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R8).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, STATE_XMM as i32).unwrap(),
            // rbx = dst slot base
            Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R8).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::RBX, Register::RCX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::RBX, STATE_XMM as i32).unwrap(),
            // r11 = src.low (8 bytes)
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R11,
                MemoryOperand::with_base(Register::RSI),
            )
            .unwrap(),
            // word0: sel=(imm&3); src=(r11>>(sel*16))&0xFFFF -> [rbx]
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
            Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(
                Code::Mov_rm16_r16,
                MemoryOperand::with_base(Register::RBX),
                Register::DX,
            )
            .unwrap(),
            // word1: sel=((imm>>2)&3)
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 2).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
            Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(
                Code::Mov_rm16_r16,
                MemoryOperand::with_base_displ(Register::RBX, 2),
                Register::DX,
            )
            .unwrap(),
            // word2: sel=((imm>>4)&3)
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 4).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
            Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(
                Code::Mov_rm16_r16,
                MemoryOperand::with_base_displ(Register::RBX, 4),
                Register::DX,
            )
            .unwrap(),
            // word3: sel=((imm>>6)&3)
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 6).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
            Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(
                Code::Mov_rm16_r16,
                MemoryOperand::with_base_displ(Register::RBX, 6),
                Register::DX,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
        ],
    );
}

// pshufhw: shuffle high 4 words; low 64 bits of dst unchanged.
pub(super) fn emit_pshufhw(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_PSHUFHW_XMM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R8).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, STATE_XMM as i32).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R8).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::RBX, Register::RCX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::RBX, STATE_XMM as i32).unwrap(),
            // r11 = src.high (bytes 8..15)
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R11,
                MemoryOperand::with_base_displ(Register::RSI, 8),
            )
            .unwrap(),
            // word0 (dst offset 8): sel=(imm&3)
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
            Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(
                Code::Mov_rm16_r16,
                MemoryOperand::with_base_displ(Register::RBX, 8),
                Register::DX,
            )
            .unwrap(),
            // word1 (dst offset 10): sel=((imm>>2)&3)
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 2).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
            Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(
                Code::Mov_rm16_r16,
                MemoryOperand::with_base_displ(Register::RBX, 10),
                Register::DX,
            )
            .unwrap(),
            // word2 (dst offset 12): sel=((imm>>4)&3)
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 4).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
            Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(
                Code::Mov_rm16_r16,
                MemoryOperand::with_base_displ(Register::RBX, 12),
                Register::DX,
            )
            .unwrap(),
            // word3 (dst offset 14): sel=((imm>>6)&3)
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 6).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
            Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(
                Code::Mov_rm16_r16,
                MemoryOperand::with_base_displ(Register::RBX, 14),
                Register::DX,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
        ],
    );
}

// pshufd: shuffle all 4 dwords; source dword offset = sel*4 bytes.
pub(super) fn emit_pshufd(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_PSHUFD_XMM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R8).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, STATE_XMM as i32).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R8).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::RBX, Register::RCX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::RBX, STATE_XMM as i32).unwrap(),
            // dword0 (dst offset 0): sel=(imm&3); src=[rsi+sel*4]
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EDX,
                MemoryOperand::with_base_index_scale(Register::RSI, Register::RCX, 4),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base(Register::RBX),
                Register::EDX,
            )
            .unwrap(),
            // dword1 (dst offset 4): sel=((imm>>2)&3)
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 2).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EDX,
                MemoryOperand::with_base_index_scale(Register::RSI, Register::RCX, 4),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base_displ(Register::RBX, 4),
                Register::EDX,
            )
            .unwrap(),
            // dword2 (dst offset 8): sel=((imm>>4)&3)
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 4).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EDX,
                MemoryOperand::with_base_index_scale(Register::RSI, Register::RCX, 4),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base_displ(Register::RBX, 8),
                Register::EDX,
            )
            .unwrap(),
            // dword3 (dst offset 12): sel=((imm>>6)&3)
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 6).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EDX,
                MemoryOperand::with_base_index_scale(Register::RSI, Register::RCX, 4),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base_displ(Register::RBX, 12),
                Register::EDX,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
        ],
    );
}

// ── A-6 (v50): packed 64-bit shifts by immediate ───────────────────────────
// psrlq/psllq xmm[dst], imm8: shift each of the two 64-bit lanes right/left
// by the bytecode imm count (masked to 6 bits, matching x86 shift-count masking).
// Bytecode: [dst_xmm, imm8]. Slot base = r8 + STATE_XMM + dst*16.
pub(super) fn emit_psrlq(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_PSRLQ_XMM_IMM8,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R11,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    (STATE_XMM + 8) as i64,
                    1,
                ),
            )
            .unwrap(),
            // count into CL (masked to 6 bits by x86 for 64-bit shifts)
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 0x3F).unwrap(),
            Instruction::with2(Code::Shr_rm64_CL, Register::RAX, Register::CL).unwrap(),
            Instruction::with2(Code::Shr_rm64_CL, Register::R11, Register::CL).unwrap(),
            // store back (rcx is now count; recompute slot addr into rdx)
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::EDX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
                Register::RAX,
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    (STATE_XMM + 8) as i64,
                    1,
                ),
                Register::R11,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

pub(super) fn emit_psllq(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_PSLLQ_XMM_IMM8,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R11,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RCX,
                    1,
                    (STATE_XMM + 8) as i64,
                    1,
                ),
            )
            .unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 0x3F).unwrap(),
            Instruction::with2(Code::Shl_rm64_CL, Register::RAX, Register::CL).unwrap(),
            Instruction::with2(Code::Shl_rm64_CL, Register::R11, Register::CL).unwrap(),
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::EDX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    STATE_XMM as i64,
                    1,
                ),
                Register::RAX,
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::R8,
                    Register::RDX,
                    1,
                    (STATE_XMM + 8) as i64,
                    1,
                ),
                Register::R11,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
}

// ── v45: 0x78 pinsrw xmm[dst], vreg[src], lane_imm8: insert low 16 bits of
// vreg[src] into word lane (imm & 7) of XMM[dst]. Lane byte offset = (imm&7)*2.
pub(super) fn emit_pinsrw(seq: &mut Vec<(Instruction, Option<Cl>)>) {
    hdr(
        seq,
        OP_PINSRW_XMM,
        vec![
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::ECX,
                MemoryOperand::with_base(Register::R9),
            )
            .unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R8).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::RDX, STATE_XMM as i32).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::RDX, Register::RCX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EAX, 7).unwrap(),
            Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 1).unwrap(),
            Instruction::with2(
                Code::Mov_rm16_r16,
                MemoryOperand::with_base_index_scale(Register::RDX, Register::RAX, 1),
                Register::R11W,
            )
            .unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
        ],
    );
}
