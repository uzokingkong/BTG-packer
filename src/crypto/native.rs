// ==============================================================================
// BTG-C1 native emission (plan.txt 6??? ??native == reference ???)
//
// reference(state.rs)?? **??? ???**??BTG-C1 ?????? ???????????
// ??? ??? ?????? ?????iced_x86????????. 3??? ??? ?????// (reference == native)?????????Arena??? ???????????? ???????
// ?????? ???????64B ??? ??????????? ??? crypt ???????????.
//
// ??? ??? (Win64): keystream_block(key, ctr, nonce, sbox, out)
//   rcx = key(32B), rdx = ctr u64, r8d = nonce u32, r9 = sbox(256B),
//   [rsp+0x28] = out(64B).
// ==============================================================================

use iced_x86::{Code, Instruction, MemoryOperand, Register};

/// ???????? (key_schedule.rs?? ??? ???).
const C0: u32 = 0xA5A5_5A5A ^ 0x1B87_3593;
const C1: u32 = 0x3C6E_F372 ^ 0x85EB_CA6B;
const C2: u32 = 0x9E37_79B9 ^ 0xC2B2_AE35;
const C3: u32 = 0x27D4_EB2F ^ 0xE654_6B64;

type P = (Instruction, Option<String>);

fn push(s: &mut Vec<P>, i: Instruction) {
    s.push((i, None));
}

fn w(off: i32) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::RSP, off as i64)
}

/// ??? ??? keystream_block ???????????.
/// ??? ?????? (0xD0 ???, 16B ??? ???):
///   [rsp+0x00..0x40] st 16 u32
///   [rsp+0x40..0x80] init ??? 16 u32
///   [rsp+0x80..0xC0] ??? ??? 16 u32
///   [rsp+0xC0..0xC4] nonce ???
pub fn emit_keystream_block() -> Vec<u8> {
    let mut s: Vec<P> = Vec::new();

    // callee-saved ??? ???
    push(&mut s, Instruction::with1(Code::Push_r64, Register::RBX).unwrap());
    push(&mut s, Instruction::with1(Code::Push_r64, Register::RSI).unwrap());
    push(&mut s, Instruction::with1(Code::Push_r64, Register::RDI).unwrap());
    // rsi=key, rdi=sbox, r11=ctr, r10=out(5th arg at [rsp+0x28+0x18])
    push(&mut s, Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::RCX).unwrap());
    push(&mut s, Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RDX).unwrap());
    push(&mut s, Instruction::with2(Code::Mov_r64_rm64, Register::RDI, Register::R9).unwrap());
    push(&mut s, Instruction::with2(Code::Mov_r64_rm64, Register::R10, MemoryOperand::with_base_displ(Register::RSP, 0x28 + 0x18)).unwrap());
    // nonce ??? (r8d??????????? ???????????)
    push(&mut s, Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, 0xD0).unwrap());
    push(&mut s, Instruction::with2(Code::Mov_rm32_r32, w(0xC0), Register::R8D).unwrap());

    // ???? absorb: st[0..16] = (C, key, ctr, nonce, domain) ????
    emit_absorb(&mut s, C0, C1, C2, C3);

    // init ??? ??[rsp+0x40..0x80]
    for i in 0..16 {
        push(&mut s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w((i as i32) * 4)).unwrap());
        push(&mut s, Instruction::with2(Code::Mov_rm32_r32, w(0x40 + (i as i32) * 4), Register::EAX).unwrap());
    }

    // ???? ?????????
    for _ in 0..crate::crypto::state::ROUNDS {
        emit_round(&mut s);
    }

    // ???? ???????? st[i] += init[i] ????
    for i in 0..16 {
        push(&mut s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(0x40 + (i as i32) * 4)).unwrap());
        push(&mut s, Instruction::with2(Code::Add_rm32_r32, w((i as i32) * 4), Register::EAX).unwrap());
    }

    // ???? st ??out (r10) 64B ????
    for i in 0..16 {
        push(&mut s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w((i as i32) * 4)).unwrap());
        push(&mut s, Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base_displ(Register::R10, (i * 4) as i64), Register::EAX).unwrap());
    }

    push(&mut s, Instruction::with2(Code::Add_rm64_imm32, Register::RSP, 0xD0).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::RDI).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::RSI).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::RBX).unwrap());
    push(&mut s, Instruction::with(Code::Retnq));

    // no branches -> direct BlockEncoder encode
    let mut buf: Vec<u8> = Vec::new();
    let mut ip: u64 = 0x140001000;
    for (inst, _lbl) in &s {
        let arr = [*inst];
        let blk = iced_x86::InstructionBlock::new(&arr, ip);
        if let Ok(res) = iced_x86::BlockEncoder::encode(64, blk, iced_x86::BlockEncoderOptions::NONE) {
            buf.extend_from_slice(&res.code_buffer);
            ip += res.code_buffer.len() as u64;
        } else {
            buf.push(0x90);
            ip += 1;
        }
    }
    buf
}

fn emit_absorb(s: &mut Vec<P>, c0: u32, c1: u32, c2: u32, c3: u32) {
    push(s, Instruction::with2(Code::Mov_rm32_imm32, w(0), c0).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_imm32, w(4), c1).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_imm32, w(8), c2).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_imm32, w(12), c3).unwrap());
    // st[4..12] = key 8 ??? (little-endian, rsi=key)
    for i in 0..8 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, MemoryOperand::with_base_displ(Register::RSI, (i * 4) as i64)).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(4 * 4 + (i as i32) * 4), Register::EAX).unwrap());
    }
    // st[12]=ctr_lo, st[13]=ctr_hi
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(12 * 4), Register::R11D).unwrap());
    push(s, Instruction::with2(Code::Shr_rm64_imm8, Register::R11, 32).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(13 * 4), Register::R11D).unwrap());
    // st[14]=nonce
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(0xC0)).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(14 * 4), Register::EAX).unwrap());
    // st[15] = "BTGC" ^ ctr_lo
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(12 * 4)).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, u32::from_le_bytes(*b"BTGC")).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(15 * 4), Register::EAX).unwrap());
}

/// ????? ?????? + S-box ??? + ???. (st??[rsp+0x00..0x40], ??? ??? [rsp+0x80..0xC0])
fn emit_round(s: &mut Vec<P>) {
    // ??? ??? (round.rs mix_column????? ??? ???)
    for c in 0..4 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(c * 4)).unwrap()); // a
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EBX, w(4 * 4 + c * 4)).unwrap()); // b
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, w(8 * 4 + c * 4)).unwrap()); // cc
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EDX, w(12 * 4 + c * 4)).unwrap()); // d
        // a ^= rotl(b,3)
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::EBX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::R8D, 3).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::R8D).unwrap());
        // a += cc
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::ECX).unwrap());
        // d ^= a; d = rotl(d,11)
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EDX, Register::EAX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::EDX, 11).unwrap());
        // d += b
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EDX, Register::EBX).unwrap());
        // cc ^= d; cc = rotl(cc,7)
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EDX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 7).unwrap());
        // cc += a
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::ECX, Register::EAX).unwrap());
        // b ^= rotl(cc,13)
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::ECX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::R8D, 13).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EBX, Register::R8D).unwrap());
        // b += d; b = rotl(b,17)
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EBX, Register::EDX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::EBX, 17).unwrap());
        // a ^= rotl(b,5); a += d
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::EBX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::R8D, 5).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::R8D).unwrap());
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::EDX).unwrap());
        // store back
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(c * 4), Register::EAX).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(4 * 4 + c * 4), Register::EBX).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(8 * 4 + c * 4), Register::ECX).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(12 * 4 + c * 4), Register::EDX).unwrap());
    }
    // S-box: ????? 4???????? (rdi=sbox)
    for i in 0..16 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w((i as i32) * 4)).unwrap());
        // b0
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R8D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R8D, MemoryOperand::with_base_index_scale(Register::RDI, Register::R8, 1)).unwrap());
        // b1
        push(s, Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, MemoryOperand::with_base_index_scale(Register::RDI, Register::R9, 1)).unwrap());
        push(s, Instruction::with2(Code::Shl_rm32_imm8, Register::R9D, 8).unwrap());
        push(s, Instruction::with2(Code::Or_rm32_r32, Register::R8D, Register::R9D).unwrap());
        // b2
        push(s, Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, MemoryOperand::with_base_index_scale(Register::RDI, Register::R9, 1)).unwrap());
        push(s, Instruction::with2(Code::Shl_rm32_imm8, Register::R9D, 16).unwrap());
        push(s, Instruction::with2(Code::Or_rm32_r32, Register::R8D, Register::R9D).unwrap());
        // b3
        push(s, Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, MemoryOperand::with_base_index_scale(Register::RDI, Register::R9, 1)).unwrap());
        push(s, Instruction::with2(Code::Shl_rm32_imm8, Register::R9D, 24).unwrap());
        push(s, Instruction::with2(Code::Or_rm32_r32, Register::R8D, Register::R9D).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w((i as i32) * 4), Register::R8D).unwrap());
    }
    // ???: new[i] = old[bitrev4(i)] ????? [rsp+0x80..0xC0]
    for i in 0..16 {
        let rev = ((i & 1) << 3) | ((i & 2) << 1) | ((i & 4) >> 1) | ((i & 8) >> 3);
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(rev as i32 * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(0x80 + i as i32 * 4), Register::EAX).unwrap());
    }
    for i in 0..16 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(0x80 + i as i32 * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w((i as i32) * 4), Register::EAX).unwrap());
    }
}
