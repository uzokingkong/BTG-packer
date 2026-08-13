// ==============================================================================
// BTG-C1 native "crypt" routine — self-contained blob for the boot stub.
//
// `emit_btg_crypt_blob(state_va, sbox_va)` returns a complete routine:
//
//   rcx = buf, rdx = len   (Win64, callee-saved restored)
//   persistent state at [state_va]:
//     +0x00 key[32], +0x20 ctr u64, +0x28 nonce u32, +0x30 ks[64], +0x70 ks_off
//   S-box table (256B) at [sbox_va]
//
// The routine keeps its own counter state, so multiple calls (code region then
// each string run) continue the same keystream, exactly like the RC4 PRGA.
// All branches are rel32 so the encoding is length-stable and labels resolve in
// two passes. The core block generation is the same unrolled rounds as
// `emit_keystream_block` (native == reference, verified by the unit test).
// ==============================================================================

use iced_x86::{Code, Instruction, MemoryOperand, Register};

const C0: u32 = 0xA5A5_5A5A ^ 0x1B87_3593;
const C1: u32 = 0x3C6E_F372 ^ 0x85EB_CA6B;
const C2: u32 = 0x9E37_79B9 ^ 0xC2B2_AE35;
const C3: u32 = 0x27D4_EB2F ^ 0xE654_6B64;

type P = (Instruction, Option<String>);
type Seq = Vec<P>;

fn push(s: &mut Seq, i: Instruction) {
    s.push((i, None));
}
fn lab(s: &mut Seq, name: &str) {
    s.push((Instruction::with(Code::Nopd), Some(name.to_string())));
}

/// 두 패스 라벨 해석: 1) 더미 타깃으로 길이/IP 수집, 2) rel32 타깃 패치.
/// rel32 분기만 쓰므로 길이가 변하지 않는다.
fn encode_with_labels(seq: &Seq, base: u64) -> Vec<u8> {
    let mut label_ip: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    // pass 1: 길이/IP
    let mut ips = Vec::with_capacity(seq.len());
    let mut lens = Vec::with_capacity(seq.len());
    let mut ip = base;
    for (inst, lbl) in seq {
        if let Some(l) = lbl {
            label_ip.insert(l.clone(), ip);
        }
        let arr = [*inst];
        let blk = iced_x86::InstructionBlock::new(&arr, ip);
        let len = match iced_x86::BlockEncoder::encode(64, blk, iced_x86::BlockEncoderOptions::NONE) {
            Ok(res) => res.code_buffer.len(),
            Err(_) => 5,
        };
        ips.push(ip);
        lens.push(len);
        ip += len as u64;
    }
    // pass 2: 타깃 패치
    let mut out = Vec::new();
    for (i, (inst, _lbl)) in seq.iter().enumerate() {
        let mut ins = *inst;
        // 분기 명령의 라벨 타깃을 설정 (blob 내부 라벨만)
        if let Some(t) = branch_label(seq, i) {
            if let Some(tip) = label_ip.get(t) {
                ins.set_near_branch64(*tip);
            }
        }
        let arr = [ins];
        let blk = iced_x86::InstructionBlock::new(&arr, ips[i]);
        if let Ok(res) = iced_x86::BlockEncoder::encode(64, blk, iced_x86::BlockEncoderOptions::NONE) {
            out.extend_from_slice(&res.code_buffer);
        } else {
            out.extend_from_slice(&[0x90; 1]);
        }
    }
    out
}

/// 명령 i의 분기 라벨 (시퀀스에서 같은 index의 (inst, label) 쌍이 분기라면 그 라벨).
/// 여기서는 분기 명령에 라벨이 붙어 있으면 타깃으로 사용한다는 단순 규약:
/// `branch_target(i)` — 명령이 분기면, seq[i].1 (또는 이전에 정의된) 라벨을 찾는다.
fn branch_label(seq: &Seq, i: usize) -> Option<&str> {
    let inst = seq[i].0;
    let is_branch = inst.flow_control() != iced_x86::FlowControl::Next
        && inst.flow_control() != iced_x86::FlowControl::Return;
    if is_branch {
        // 분기 명령의 라벨 필드는 "점프 목적지 라벨"이다.
        seq[i].1.as_deref()
    } else {
        None
    }
}

/// 워크 스택 (0xD0 예약): st[0x00..0x40], init[0x40..0x80], perm[0x80..0xC0], nonce[0xC0].
fn w(off: i32) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::RSP, off as i64)
}

/// 자립 crypt 블롭 생성.
pub fn emit_btg_crypt_blob(state_va: u64, sbox_va: u64) -> Vec<u8> {
    let mut s: Seq = Vec::new();

    // prologue: callee-saved
    push(&mut s, Instruction::with1(Code::Push_r64, Register::RBX).unwrap());
    push(&mut s, Instruction::with1(Code::Push_r64, Register::RSI).unwrap());
    push(&mut s, Instruction::with1(Code::Push_r64, Register::RDI).unwrap());
    push(&mut s, Instruction::with1(Code::Push_r64, Register::R12).unwrap());
    push(&mut s, Instruction::with1(Code::Push_r64, Register::R13).unwrap());
    push(&mut s, Instruction::with1(Code::Push_r64, Register::R14).unwrap());
    push(&mut s, Instruction::with1(Code::Push_r64, Register::R15).unwrap());
    // r12=buf, r13=len, r14=state, r15=sbox
    push(&mut s, Instruction::with2(Code::Mov_r64_rm64, Register::R12, Register::RCX).unwrap());
    push(&mut s, Instruction::with2(Code::Mov_r64_rm64, Register::R13, Register::RDX).unwrap());
    push(&mut s, Instruction::with2(Code::Mov_r64_imm64, Register::R14, state_va).unwrap());
    push(&mut s, Instruction::with2(Code::Mov_r64_imm64, Register::R15, sbox_va).unwrap());

    // ── crypt loop ──
    lab(&mut s, "crypt_loop");
    push(&mut s, Instruction::with2(Code::Test_rm64_r64, Register::R13, Register::R13).unwrap());
    push(&mut s, Instruction::with_branch(Code::Je_rel32_64, 0).unwrap());
    s.last_mut().unwrap().1 = Some("crypt_done".to_string());
    // ks_off >= 64 → gen block
    push(&mut s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, MemoryOperand::with_base_displ(Register::R14, 0x70)).unwrap());
    push(&mut s, Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 0x40).unwrap());
    push(&mut s, Instruction::with_branch(Code::Jl_rel32_64, 0).unwrap());
    s.last_mut().unwrap().1 = Some("have_byte".to_string());
    push(&mut s, Instruction::with_branch(Code::Call_rel32_64, 0).unwrap());
    s.last_mut().unwrap().1 = Some("gen_block".to_string());
    push(&mut s, Instruction::with2(Code::Mov_rm32_imm32, MemoryOperand::with_base_displ(Register::R14, 0x70), 0).unwrap());
    // have_byte
    lab(&mut s, "have_byte");
    push(&mut s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, MemoryOperand::with_base_displ(Register::R14, 0x70)).unwrap());
    push(&mut s, Instruction::with2(Code::Lea_r64_m, Register::RCX, MemoryOperand::with_base_displ(Register::R14, 0x30)).unwrap());
    push(&mut s, Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::RAX).unwrap());
    push(&mut s, Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, MemoryOperand::with_base(Register::RCX)).unwrap());
    push(&mut s, Instruction::with2(Code::Xor_rm8_r8, MemoryOperand::with_base(Register::R12), Register::AL).unwrap());
    push(&mut s, Instruction::with1(Code::Inc_rm64, Register::R12).unwrap());
    push(&mut s, Instruction::with1(Code::Dec_rm64, Register::R13).unwrap());
    push(&mut s, Instruction::with1(Code::Inc_rm32, MemoryOperand::with_base_displ(Register::R14, 0x70)).unwrap());
    push(&mut s, Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap());
    s.last_mut().unwrap().1 = Some("crypt_loop".to_string());

    // ── crypt_done ──
    lab(&mut s, "crypt_done");
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::R15).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::R14).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::R13).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::R12).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::RDI).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::RSI).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::RBX).unwrap());
    push(&mut s, Instruction::with(Code::Retnq));

    // ── gen_block: 스택 0xD0 예약, absorb+라운드+피드포워드, [r14+0x30]에 ks[64], ctr++ ──
    lab(&mut s, "gen_block");
    push(&mut s, Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, 0xD0).unwrap());
    emit_absorb(&mut s);
    // init 사본 → [rsp+0x40..0x80]
    for i in 0..16 {
        push(&mut s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(i * 4)).unwrap());
        push(&mut s, Instruction::with2(Code::Mov_rm32_r32, w(0x40 + i * 4), Register::EAX).unwrap());
    }
    for _ in 0..crate::crypto::state::ROUNDS {
        emit_round(&mut s);
    }
    // 피드포워드
    for i in 0..16 {
        push(&mut s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(0x40 + i * 4)).unwrap());
        push(&mut s, Instruction::with2(Code::Add_rm32_r32, w(i * 4), Register::EAX).unwrap());
    }
    // ks[64] → [r14+0x30]
    for i in 0..16 {
        push(&mut s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w((i as i32) * 4)).unwrap());
        push(&mut s, Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base_displ(Register::R14, (0x30 + i * 4) as i64), Register::EAX).unwrap());
    }
    // ctr++
    push(&mut s, Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base_displ(Register::R14, 0x20)).unwrap());
    push(&mut s, Instruction::with2(Code::Add_rm64_imm32, Register::RAX, 1).unwrap());
    push(&mut s, Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ(Register::R14, 0x20), Register::RAX).unwrap());
    push(&mut s, Instruction::with2(Code::Add_rm64_imm32, Register::RSP, 0xD0).unwrap());
    push(&mut s, Instruction::with(Code::Retnq));

    encode_with_labels(&s, 0x140001000)
}

fn emit_absorb(s: &mut Seq) {
    // ctr (64-bit) -> RAX (ctr_lo), RDX (ctr_hi)
    push(s, Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base_displ(Register::R14, 0x20)).unwrap());
    push(s, Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap());
    push(s, Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 32).unwrap());
    // nonce -> R8D
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::R8D, MemoryOperand::with_base_displ(Register::R14, 0x28)).unwrap());

    // st[0] = C0 ^ rol(ctr_lo, 7)
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap());
    push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 7).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::ECX, C0).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(0), Register::ECX).unwrap());

    // st[1] = C1 ^ rol(ctr_hi, 19)
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap());
    push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 19).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::ECX, C1).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(4), Register::ECX).unwrap());

    // st[2] = C2 ^ (rol(ctr_lo + 0x9E3779B9, 13) ^ ctr_hi)
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap());
    push(s, Instruction::with2(Code::Add_rm32_imm32, Register::ECX, 0x9E37_79B9u32 as i32).unwrap());
    push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 13).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EDX).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::ECX, C2).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(8), Register::ECX).unwrap());

    // st[3] = C3 ^ rol(nonce, 11)
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R8D).unwrap());
    push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 11).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::ECX, C3).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(12), Register::ECX).unwrap());

    // key 8 words (st[4..12])
    for i in 0..8 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, MemoryOperand::with_base_displ(Register::R14, (i * 4) as i64)).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(4 * 4 + (i as i32) * 4), Register::ECX).unwrap());
    }

    // st[12] = ctr_lo
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(12 * 4), Register::EAX).unwrap());
    // st[13] = ctr_hi
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(13 * 4), Register::EDX).unwrap());
    // st[14] = nonce
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(14 * 4), Register::R8D).unwrap());

    // st[15] = "BTGC" ^ ctr_lo ^ rol(ctr_hi, 13)
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap());
    push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 13).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::ECX, u32::from_le_bytes(*b"BTGC")).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(15 * 4), Register::ECX).unwrap());
}

fn emit_round(s: &mut Seq) {
    for c in 0..4 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(c * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EBX, w(4 * 4 + c * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, w(8 * 4 + c * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EDX, w(12 * 4 + c * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::EBX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::R8D, 3).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::R8D).unwrap());
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::ECX).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EDX, Register::EAX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::EDX, 11).unwrap());
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EDX, Register::EBX).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EDX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 7).unwrap());
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::ECX, Register::EAX).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::ECX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::R8D, 13).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EBX, Register::R8D).unwrap());
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EBX, Register::EDX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::EBX, 17).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::EBX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::R8D, 5).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::R8D).unwrap());
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::EDX).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(c * 4), Register::EAX).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(4 * 4 + c * 4), Register::EBX).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(8 * 4 + c * 4), Register::ECX).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(12 * 4 + c * 4), Register::EDX).unwrap());
    }
    // S-box (r15 = sbox)
    for i in 0..16 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(i * 4)).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R8D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R8D, MemoryOperand::with_base_index_scale(Register::R15, Register::R8, 1)).unwrap());
        push(s, Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, MemoryOperand::with_base_index_scale(Register::R15, Register::R9, 1)).unwrap());
        push(s, Instruction::with2(Code::Shl_rm32_imm8, Register::R9D, 8).unwrap());
        push(s, Instruction::with2(Code::Or_rm32_r32, Register::R8D, Register::R9D).unwrap());
        push(s, Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, MemoryOperand::with_base_index_scale(Register::R15, Register::R9, 1)).unwrap());
        push(s, Instruction::with2(Code::Shl_rm32_imm8, Register::R9D, 16).unwrap());
        push(s, Instruction::with2(Code::Or_rm32_r32, Register::R8D, Register::R9D).unwrap());
        push(s, Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, MemoryOperand::with_base_index_scale(Register::R15, Register::R9, 1)).unwrap());
        push(s, Instruction::with2(Code::Shl_rm32_imm8, Register::R9D, 24).unwrap());
        push(s, Instruction::with2(Code::Or_rm32_r32, Register::R8D, Register::R9D).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(i * 4), Register::R8D).unwrap());
    }
/// 순열 (bit-reversal, 임시 0x80)
    for i in 0..16 {
        let rev = ((i & 1) << 3) | ((i & 2) << 1) | ((i & 4) >> 1) | ((i & 8) >> 3);
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(rev as i32 * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(0x80 + i as i32 * 4), Register::EAX).unwrap());
    }
    for i in 0..16 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(0x80 + i as i32 * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(i * 4), Register::EAX).unwrap());
    }
}

// =============================================================================
// 레지스터 기반 keystream_block — 단위 테스트(native == reference)용.
// (부트 스텁은 위의 절대 VA blob을 쓴다.)
// =============================================================================

/// 분기 없는 keystream_block 루틴 (rcx=key, rdx=ctr, r8d=nonce, r9=sbox, [rsp+0x28]=out).
pub fn emit_keystream_block() -> Vec<u8> {
    let mut s: Seq = Vec::new();
    push(&mut s, Instruction::with1(Code::Push_r64, Register::RBX).unwrap());
    push(&mut s, Instruction::with1(Code::Push_r64, Register::RSI).unwrap());
    push(&mut s, Instruction::with1(Code::Push_r64, Register::RDI).unwrap());
    push(&mut s, Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::RCX).unwrap()); // key
    push(&mut s, Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RDX).unwrap()); // ctr
    push(&mut s, Instruction::with2(Code::Mov_r64_rm64, Register::RDI, Register::R9).unwrap()); // sbox
    push(&mut s, Instruction::with2(Code::Mov_r64_rm64, Register::R10, MemoryOperand::with_base_displ(Register::RSP, 0x28 + 0x18)).unwrap()); // out
    push(&mut s, Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, 0xD0).unwrap());
    push(&mut s, Instruction::with2(Code::Mov_rm32_r32, w(0xC0), Register::R8D).unwrap());
    emit_absorb_reg(&mut s);
    for i in 0..16 {
        push(&mut s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w((i as i32) * 4)).unwrap());
        push(&mut s, Instruction::with2(Code::Mov_rm32_r32, w(0x40 + (i as i32) * 4), Register::EAX).unwrap());
    }
    for _ in 0..crate::crypto::state::ROUNDS {
        emit_round_reg(&mut s);
    }
    for i in 0..16 {
        push(&mut s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(0x40 + (i as i32) * 4)).unwrap());
        push(&mut s, Instruction::with2(Code::Add_rm32_r32, w((i as i32) * 4), Register::EAX).unwrap());
    }
    for i in 0..16 {
        push(&mut s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w((i as i32) * 4)).unwrap());
        push(&mut s, Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base_displ(Register::R10, (i * 4) as i64), Register::EAX).unwrap());
    }
    push(&mut s, Instruction::with2(Code::Add_rm64_imm32, Register::RSP, 0xD0).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::RDI).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::RSI).unwrap());
    push(&mut s, Instruction::with1(Code::Pop_r64, Register::RBX).unwrap());
    push(&mut s, Instruction::with(Code::Retnq));
    encode_with_labels(&s, 0x140001000)
}

fn emit_absorb_reg(s: &mut Seq) {
    // R11 has ctr (64-bit). Copy to RAX (ctr_lo) & RDX (ctr_hi)
    push(s, Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap());
    push(s, Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap());
    push(s, Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 32).unwrap());
    // Load nonce from w(0xC0) into R8D
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::R8D, w(0xC0)).unwrap());

    // st[0] = C0 ^ rol(ctr_lo, 7)
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap());
    push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 7).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::ECX, C0).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(0), Register::ECX).unwrap());

    // st[1] = C1 ^ rol(ctr_hi, 19)
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap());
    push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 19).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::ECX, C1).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(4), Register::ECX).unwrap());

    // st[2] = C2 ^ (rol(ctr_lo + 0x9E3779B9, 13) ^ ctr_hi)
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap());
    push(s, Instruction::with2(Code::Add_rm32_imm32, Register::ECX, 0x9E37_79B9u32 as i32).unwrap());
    push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 13).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EDX).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::ECX, C2).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(8), Register::ECX).unwrap());

    // st[3] = C3 ^ rol(nonce, 11)
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R8D).unwrap());
    push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 11).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::ECX, C3).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(12), Register::ECX).unwrap());

    // key 8 words (st[4..12])
    for i in 0..8 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, MemoryOperand::with_base_displ(Register::RSI, (i * 4) as i64)).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(4 * 4 + (i as i32) * 4), Register::ECX).unwrap());
    }

    // st[12] = ctr_lo
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(12 * 4), Register::EAX).unwrap());
    // st[13] = ctr_hi
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(13 * 4), Register::EDX).unwrap());
    // st[14] = nonce
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(14 * 4), Register::R8D).unwrap());

    // st[15] = "BTGC" ^ ctr_lo ^ rol(ctr_hi, 13)
    push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap());
    push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 13).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::ECX, u32::from_le_bytes(*b"BTGC")).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(15 * 4), Register::ECX).unwrap());
}

fn emit_round_reg(s: &mut Seq) {
    for c in 0..4 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(c * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EBX, w(4 * 4 + c * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::ECX, w(8 * 4 + c * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EDX, w(12 * 4 + c * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::EBX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::R8D, 3).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::R8D).unwrap());
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::ECX).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EDX, Register::EAX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::EDX, 11).unwrap());
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EDX, Register::EBX).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EDX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 7).unwrap());
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::ECX, Register::EAX).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::ECX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::R8D, 13).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EBX, Register::R8D).unwrap());
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EBX, Register::EDX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::EBX, 17).unwrap());
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::EBX).unwrap());
        push(s, Instruction::with2(Code::Rol_rm32_imm8, Register::R8D, 5).unwrap());
        push(s, Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::R8D).unwrap());
        push(s, Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::EDX).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(c * 4), Register::EAX).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(4 * 4 + c * 4), Register::EBX).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(8 * 4 + c * 4), Register::ECX).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(12 * 4 + c * 4), Register::EDX).unwrap());
    }
    for i in 0..16 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(i * 4)).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R8D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R8D, MemoryOperand::with_base_index_scale(Register::RDI, Register::R8, 1)).unwrap());
        push(s, Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, MemoryOperand::with_base_index_scale(Register::RDI, Register::R9, 1)).unwrap());
        push(s, Instruction::with2(Code::Shl_rm32_imm8, Register::R9D, 8).unwrap());
        push(s, Instruction::with2(Code::Or_rm32_r32, Register::R8D, Register::R9D).unwrap());
        push(s, Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, MemoryOperand::with_base_index_scale(Register::RDI, Register::R9, 1)).unwrap());
        push(s, Instruction::with2(Code::Shl_rm32_imm8, Register::R9D, 16).unwrap());
        push(s, Instruction::with2(Code::Or_rm32_r32, Register::R8D, Register::R9D).unwrap());
        push(s, Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::AL).unwrap());
        push(s, Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, MemoryOperand::with_base_index_scale(Register::RDI, Register::R9, 1)).unwrap());
        push(s, Instruction::with2(Code::Shl_rm32_imm8, Register::R9D, 24).unwrap());
        push(s, Instruction::with2(Code::Or_rm32_r32, Register::R8D, Register::R9D).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(i * 4), Register::R8D).unwrap());
    }
    for i in 0..16 {
        let rev = ((i & 1) << 3) | ((i & 2) << 1) | ((i & 4) >> 1) | ((i & 8) >> 3);
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(rev as i32 * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(0x80 + i as i32 * 4), Register::EAX).unwrap());
    }
    for i in 0..16 {
        push(s, Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(0x80 + i as i32 * 4)).unwrap());
        push(s, Instruction::with2(Code::Mov_rm32_r32, w(i * 4), Register::EAX).unwrap());
    }
}
