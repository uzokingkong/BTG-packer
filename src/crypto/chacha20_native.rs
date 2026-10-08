// ==============================================================================
// BTG Packer — T3-1: ChaCha20 (RFC 8439) native "crypt" routine for the boot stub
// ==============================================================================
// `emit_chacha20_blob(state_va)` returns a self-contained routine:
//
//   rcx = buf, rdx = len   (Win64, callee-saved restored)
//   persistent state at [state_va] (0x80B, `crypto::chacha20` layout):
//     +0x00 key[32], +0x20 ctr u64, +0x28 nonce[12],
//     +0x38 ks[64], +0x78 ks_off u32
//
// Same contract as the RC4 PRGA / BTG-C1 blob: successive calls continue the
// same keystream (code region -> string runs -> IAT resolve runs). The keystream
// is produced by the RFC 8439 block function (32B key + 12B nonce + 32-bit
// counter) and must be bit-identical to the reference
// (`crypto::chacha20::chacha20_block`).
//
// All branches are rel32 so the encoding is length-stable and labels resolve in
// two passes. The core block generation uses the same unrolled rounds as the
// reference (unit test: native == reference).
// ==============================================================================

use iced_x86::{Code, Instruction, MemoryOperand, Register};
#[path = "chacha20_vm.rs"]
mod rounds_vm;

use crate::crypto::chacha20::{
    CHACHA20_CONST_0, CHACHA20_CONST_1, CHACHA20_CONST_2, CHACHA20_CONST_3, CHA_OFF_CTR,
    CHA_OFF_KEY, CHA_OFF_KS, CHA_OFF_KS_OFF, CHA_OFF_NONCE,
};

type P = (Instruction, Option<String>);
type Seq = Vec<P>;

fn push(s: &mut Seq, i: Instruction) {
    s.push((i, None));
}
fn lab(s: &mut Seq, name: &str) {
    s.push((Instruction::with(Code::Nopd), Some(name.to_string())));
}

/// Two-pass label resolution: 1) collect lengths/IPs with dummy targets,
/// 2) patch rel32 targets. Only rel32 branches are used, so lengths never change.
/// DONT_FIX_BRANCHES is required: the default would shrink near branches to rel8
/// during pass 2, desyncing measured vs. encoded lengths (crash/infinite loop).
fn encode_with_labels(seq: &Seq, base: u64) -> Vec<u8> {
    let opts = iced_x86::BlockEncoderOptions::DONT_FIX_BRANCHES;
    let is_branch = |inst: &Instruction| {
        inst.flow_control() != iced_x86::FlowControl::Next
            && inst.flow_control() != iced_x86::FlowControl::Return
    };
    let mut label_ip: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut ips = Vec::with_capacity(seq.len());
    let mut lens = Vec::with_capacity(seq.len());
    let mut ip = base;
    for (inst, lbl) in seq {
        if let Some(l) = lbl {
            if !is_branch(inst) {
                label_ip.insert(l.clone(), ip);
            }
        }
        let arr = [*inst];
        let blk = iced_x86::InstructionBlock::new(&arr, ip);
        let len = match iced_x86::BlockEncoder::encode(64, blk, opts) {
            Ok(res) => res.code_buffer.len(),
            Err(_) => 5,
        };
        ips.push(ip);
        lens.push(len);
        ip += len as u64;
    }
    let mut out = Vec::new();
    for (i, (inst, _lbl)) in seq.iter().enumerate() {
        let mut ins = *inst;
        if let Some(t) = branch_label(seq, i) {
            if let Some(tip) = label_ip.get(t) {
                ins.set_near_branch64(*tip);
            }
        }
        let arr = [ins];
        let blk = iced_x86::InstructionBlock::new(&arr, ips[i]);
        if let Ok(res) = iced_x86::BlockEncoder::encode(64, blk, opts) {
            out.extend_from_slice(&res.code_buffer);
        } else {
            out.extend_from_slice(&[0x90; 1]);
        }
    }
    out
}

fn branch_label(seq: &Seq, i: usize) -> Option<&str> {
    let inst = seq[i].0;
    let is_branch = inst.flow_control() != iced_x86::FlowControl::Next
        && inst.flow_control() != iced_x86::FlowControl::Return;
    if is_branch {
        seq[i].1.as_deref()
    } else {
        None
    }
}

/// gen_block work stack (0x80 reserved): state[0x00..0x40], init[0x40..0x80].
fn w(off: i32) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::RSP, off as i64)
}

/// Self-contained ChaCha20 crypt blob.
pub fn emit_chacha20_blob(state_va: u64) -> Vec<u8> {
    emit_chacha20_backend(state_va, false)
}

pub fn chacha20_vm_program() -> Vec<u8> {
    const ADD:u8=1; const XOR:u8=2; const ROT:u8=3;
    let mut bytes = Vec::new();
    for _ in 0..10 {
        for [a, b, c, d] in [
            [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15],
            [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14],
        ] {
            for (op, dst, src, count) in [
                (ADD,a,b,0), (XOR,d,a,0), (ROT,d,0,16),
                (ADD,c,d,0), (XOR,b,c,0), (ROT,b,0,12),
                (ADD,a,b,0), (XOR,d,a,0), (ROT,d,0,8),
                (ADD,c,d,0), (XOR,b,c,0), (ROT,b,0,7),
            ] { bytes.extend([op, dst, src, count]); }
        }
    }
    bytes.extend([0;4]);
    bytes
}

/// Experimental selected-stage VM: all ChaCha round arithmetic is interpreted.
/// Streaming, initial state absorption and feedforward remain native bridges.
pub fn emit_chacha20_vm_blob(state_va: u64) -> Vec<u8> {
    emit_chacha20_backend(state_va, true)
}

fn emit_chacha20_backend(state_va: u64, virtual_rounds: bool) -> Vec<u8> {
    encode_with_labels(&chacha_sequence(state_va, virtual_rounds), 0x140001000)
}

pub(crate) fn emit_chacha20_full_vm_blob(state_va: u64, vm_state_va: u64) -> anyhow::Result<super::instruction_vm::Blob> {
    super::instruction_vm::compile(&chacha_sequence(state_va, false), vm_state_va)
}

pub fn chacha20_full_vm_program() -> anyhow::Result<Vec<u8>> {
    let blob = emit_chacha20_full_vm_blob(0,0)?;
    Ok(blob.code[blob.program_range].to_vec())
}

fn chacha_sequence(state_va: u64, virtual_rounds: bool) -> Seq {
    let mut s: Seq = Vec::new();

    // prologue: callee-saved
    push(
        &mut s,
        Instruction::with1(Code::Push_r64, Register::RBX).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Push_r64, Register::RSI).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Push_r64, Register::RDI).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Push_r64, Register::R12).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Push_r64, Register::R13).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Push_r64, Register::R14).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Push_r64, Register::R15).unwrap(),
    );
    // r12=buf, r13=len, r14=state
    push(
        &mut s,
        Instruction::with2(Code::Mov_r64_rm64, Register::R12, Register::RCX).unwrap(),
    );
    push(
        &mut s,
        Instruction::with2(Code::Mov_r64_rm64, Register::R13, Register::RDX).unwrap(),
    );
    push(
        &mut s,
        Instruction::with2(Code::Mov_r64_imm64, Register::R14, state_va).unwrap(),
    );

    // ---- crypt loop ----
    lab(&mut s, "crypt_loop");
    push(
        &mut s,
        Instruction::with2(Code::Test_rm64_r64, Register::R13, Register::R13).unwrap(),
    );
    push(
        &mut s,
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
    );
    s.last_mut().unwrap().1 = Some("crypt_done".to_string());
    // ks_off >= 0x40 -> gen_block
    push(
        &mut s,
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::EAX,
            stbuf(CHA_OFF_KS_OFF as i32),
        )
        .unwrap(),
    );
    push(
        &mut s,
        Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 0x40).unwrap(),
    );
    push(
        &mut s,
        Instruction::with_branch(Code::Jl_rel32_64, 0).unwrap(),
    );
    s.last_mut().unwrap().1 = Some("have_byte".to_string());
    push(
        &mut s,
        Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(),
    );
    s.last_mut().unwrap().1 = Some("gen_block".to_string());
    push(
        &mut s,
        Instruction::with2(Code::Mov_rm32_imm32, stbuf(CHA_OFF_KS_OFF as i32), 0).unwrap(),
    );
    // have_byte
    lab(&mut s, "have_byte");
    push(
        &mut s,
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::EAX,
            stbuf(CHA_OFF_KS_OFF as i32),
        )
        .unwrap(),
    );
    push(
        &mut s,
        Instruction::with2(Code::Lea_r64_m, Register::RCX, stbuf(CHA_OFF_KS as i32)).unwrap(),
    );
    push(
        &mut s,
        Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::RAX).unwrap(),
    );
    push(
        &mut s,
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            MemoryOperand::with_base(Register::RCX),
        )
        .unwrap(),
    );
    push(
        &mut s,
        Instruction::with2(
            Code::Xor_rm8_r8,
            MemoryOperand::with_base(Register::R12),
            Register::AL,
        )
        .unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Inc_rm64, Register::R12).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Dec_rm64, Register::R13).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Inc_rm32, stbuf(CHA_OFF_KS_OFF as i32)).unwrap(),
    );
    push(
        &mut s,
        Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(),
    );
    s.last_mut().unwrap().1 = Some("crypt_loop".to_string());

    // ---- crypt_done ----
    lab(&mut s, "crypt_done");
    push(
        &mut s,
        Instruction::with1(Code::Pop_r64, Register::R15).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Pop_r64, Register::R14).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Pop_r64, Register::R13).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Pop_r64, Register::R12).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Pop_r64, Register::RDI).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Pop_r64, Register::RSI).unwrap(),
    );
    push(
        &mut s,
        Instruction::with1(Code::Pop_r64, Register::RBX).unwrap(),
    );
    push(&mut s, Instruction::with(Code::Retnq));

    // ---- gen_block: reserve 0x80 on stack, absorb + 20 rounds + feedforward,
    //      write ks[64] at [r14+0x38], ctr++ ----
    lab(&mut s, "gen_block");
    push(
        &mut s,
        Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, 0x80).unwrap(),
    );
    emit_absorb(&mut s);
    // init copy -> [rsp+0x40..0x80]
    for i in 0..16 {
        push(
            &mut s,
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(i * 4)).unwrap(),
        );
        push(
            &mut s,
            Instruction::with2(Code::Mov_rm32_r32, w(0x40 + i * 4), Register::EAX).unwrap(),
        );
    }
    if virtual_rounds {
        rounds_vm::emit(&mut s);
    } else {
        for _ in 0..10 { emit_double_round(&mut s); }
    }
    // feedforward
    for i in 0..16 {
        push(
            &mut s,
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(0x40 + i * 4)).unwrap(),
        );
        push(
            &mut s,
            Instruction::with2(Code::Add_rm32_r32, w(i * 4), Register::EAX).unwrap(),
        );
    }
    // ks[64] -> [r14+0x38]
    for i in 0..16 {
        push(
            &mut s,
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(i * 4)).unwrap(),
        );
        push(
            &mut s,
            Instruction::with2(
                Code::Mov_rm32_r32,
                stbuf(CHA_OFF_KS as i32 + i * 4),
                Register::EAX,
            )
            .unwrap(),
        );
    }
    // ctr++
    push(
        &mut s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RAX, stbuf(CHA_OFF_CTR as i32)).unwrap(),
    );
    push(
        &mut s,
        Instruction::with2(Code::Add_rm64_imm32, Register::RAX, 1).unwrap(),
    );
    push(
        &mut s,
        Instruction::with2(Code::Mov_rm64_r64, stbuf(CHA_OFF_CTR as i32), Register::RAX).unwrap(),
    );
    push(
        &mut s,
        Instruction::with2(Code::Add_rm64_imm32, Register::RSP, 0x80).unwrap(),
    );
    push(&mut s, Instruction::with(Code::Retnq));

    s
}

/// Absorb the initial 16-word state from [r14] into the stack [rsp+0x00..0x40].
fn emit_absorb(s: &mut Seq) {
    // Anti-Findcrypt: scramble ChaCha constants so "expand 32-byte k" never appears
    // as plaintext immediates in the binary.
    const CHA_MASK_0: u32 = 0x5A3C_96E7;
    const CHA_MASK_1: u32 = 0xA749_1B3D;
    const CHA_MASK_2: u32 = 0x3E82_C5F1;
    const CHA_MASK_3: u32 = 0x91F4_D82A;

    // st[0]: 0x61707865
    push(s, Instruction::with2(Code::Mov_r32_imm32, Register::EAX, (CHACHA20_CONST_0 ^ CHA_MASK_0) as i32).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, CHA_MASK_0 as i32).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(0), Register::EAX).unwrap());

    // st[1]: 0x3320646e
    push(s, Instruction::with2(Code::Mov_r32_imm32, Register::EAX, (CHACHA20_CONST_1 ^ CHA_MASK_1) as i32).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, CHA_MASK_1 as i32).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(4), Register::EAX).unwrap());

    // st[2]: 0x79622d32
    push(s, Instruction::with2(Code::Mov_r32_imm32, Register::EAX, (CHACHA20_CONST_2 ^ CHA_MASK_2) as i32).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, CHA_MASK_2 as i32).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(8), Register::EAX).unwrap());

    // st[3]: 0x6b206574
    push(s, Instruction::with2(Code::Mov_r32_imm32, Register::EAX, (CHACHA20_CONST_3 ^ CHA_MASK_3) as i32).unwrap());
    push(s, Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, CHA_MASK_3 as i32).unwrap());
    push(s, Instruction::with2(Code::Mov_rm32_r32, w(12), Register::EAX).unwrap());
    // key words st[4..12] <- [r14+0x00..0x20]
    for i in 0..8 {
        push(
            s,
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EAX,
                stbuf(CHA_OFF_KEY as i32 + i * 4),
            )
            .unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Mov_rm32_r32, w(0x10 + i * 4), Register::EAX).unwrap(),
        );
    }
    // st[12] = ctr low 32 <- [r14+0x20]
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, stbuf(CHA_OFF_CTR as i32)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(0x30), Register::EAX).unwrap(),
    );
    // nonce words st[13..16] <- [r14+0x28..0x34]
    for i in 0..3 {
        push(
            s,
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EAX,
                stbuf(CHA_OFF_NONCE as i32 + i * 4),
            )
            .unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Mov_rm32_r32, w(0x34 + i * 4), Register::EAX).unwrap(),
        );
    }
}

/// One round of the RFC 8439 20 rounds (4 column + 4 diagonal quarter-rounds).
fn emit_double_round(s: &mut Seq) {
    // column
    emit_qr(s, 0, 4, 8, 12);
    emit_qr(s, 1, 5, 9, 13);
    emit_qr(s, 2, 6, 10, 14);
    emit_qr(s, 3, 7, 11, 15);
    // diagonal
    emit_qr(s, 0, 5, 10, 15);
    emit_qr(s, 1, 6, 11, 12);
    emit_qr(s, 2, 7, 8, 13);
    emit_qr(s, 3, 4, 9, 14);
}

/// Quarter-round on (st[a], st[b], st[c], st[d]) — load/operate/store on the
/// stack words. Same operation order as the reference `qr`.
fn emit_qr(s: &mut Seq, a: i32, b: i32, c: i32, d: i32) {
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(a * 4)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EBX, w(b * 4)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, w(c * 4)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, w(d * 4)).unwrap(),
    );
    // a += b; d ^= a; d <<<= 16
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::EBX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Xor_rm32_r32, Register::EDX, Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Rol_rm32_imm8, Register::EDX, 16).unwrap(),
    );
    // c += d; b ^= c; b <<<= 12
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, Register::ECX, Register::EDX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Xor_rm32_r32, Register::EBX, Register::ECX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Rol_rm32_imm8, Register::EBX, 12).unwrap(),
    );
    // a += b; d ^= a; d <<<= 8
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::EBX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Xor_rm32_r32, Register::EDX, Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Rol_rm32_imm8, Register::EDX, 8).unwrap(),
    );
    // c += d; b ^= c; b <<<= 7
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, Register::ECX, Register::EDX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Xor_rm32_r32, Register::EBX, Register::ECX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Rol_rm32_imm8, Register::EBX, 7).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(a * 4), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(b * 4), Register::EBX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(c * 4), Register::ECX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(d * 4), Register::EDX).unwrap(),
    );
}

/// r14-based operand for the persistent state buffer.
fn stbuf(off: i32) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::R14, off as i64)
}
