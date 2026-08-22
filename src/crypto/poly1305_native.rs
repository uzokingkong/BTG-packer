// ==============================================================================
// BTG Packer — T3-1 Phase D: Poly1305 native verification blob (boot stub)
// ==============================================================================
// `emit_poly1305_verify_blob(_state_va)` returns a self-contained routine that
// computes the RFC 8439 Poly1305 AEAD tag over a ciphertext region (+ fixed AAD
// binding) and compares it against a stored tag:
//
//   rcx = region ptr, rdx = region len, r8 = key ptr (32B), r9 = tag ptr (16B)
//   returns rax = 0 (match) or non-zero (mismatch)
//
// The MAC'd data follows RFC 8439 §2.8 (ChaCha20-Poly1305 AEAD) exactly:
//   mac_data = pad16(AAD) || pad16(ciphertext) || le64(len(AAD)) || le64(len(CT))
// where AAD is a fixed, versioned domain tag (`poly1305::POLY1305_AEAD_AAD`).
// The key is the 32-byte ChaCha20-Poly1305 one-time key (first 32 bytes of the
// counter=0 keystream block). The boot stub runs this BEFORE the ChaCha20
// decrypt step and traps (ud2) on mismatch, so tampered ciphertext never reaches
// decryption/execution.
//
// All branches are rel32 so the encoding is length-stable and labels resolve in
// two passes (same discipline as `chacha20_native::emit_chacha20_blob`). The
// 26-bit limb arithmetic replicates `crypto::poly1305` (donna soft backend)
// exactly; the differential test asserts native == reference over a range of
// lengths.
// ==============================================================================

use iced_x86::{Code, Instruction, MemoryOperand, Register};

use crate::crypto::poly1305::POLY1305_AEAD_AAD;

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
/// DONT_FIX_BRANCHES is required (near branches would otherwise shrink to rel8
/// during pass 2, desyncing measured vs. encoded lengths).
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

// ── stack frame layout (all rsp-relative) ─────────────────────────────────────
const H_OFF: i32 = 0x00; //   h[5] x u32  (26-bit limbs)
const R_OFF: i32 = 0x20; //   r[5] x u32  (clamped key limbs)
const PAD_OFF: i32 = 0x40; // pad[4] x u32 (key[16..32])
const BLK_OFF: i32 = 0x60; // 16-byte block staging
const D_OFF: i32 = 0x80; //   d[5]/t[4]/g x u32/u64 scratch
const LEN_OFF: i32 = 0xC0; // u64 original ciphertext length
const MAC_OFF: i32 = 0xD0; // u32 x 4 final tag
const FRAME: i32 = 0x100;

fn w(off: i32) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::RSP, off as i64)
}
fn w_disp(base: Register, disp: i32) -> MemoryOperand {
    MemoryOperand::with_base_displ(base, disp as i64)
}
fn w_disp_idx(base: Register, idx: Register) -> MemoryOperand {
    // base+index+scale (byte access — same form m7.rs uses for Mov_rm8_r8/Movzx_r32_rm8).
    MemoryOperand::with_base_index_scale(base, idx, 1)
}
fn w_disp_idx_rsp(displ: i32, idx: Register) -> MemoryOperand {
    // [rsp + idx + displ]; rsp-relative base so iced can encode the byte operand.
    MemoryOperand::with_base_index_scale_displ_size(Register::RSP, idx, 1, displ as i64, 1)
}

const LIMB_MASK: u32 = 0x3ff_ffff;

/// Emit the Poly1305 verify blob.
pub fn emit_poly1305_verify_blob(_state_va: u64) -> Vec<u8> {
    let mut s: Seq = Vec::new();

    // ---- prologue: callee-saved ----
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
    // r12=region, r13=running len, r14=key, r15=tag
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
        Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::R8).unwrap(),
    );
    push(
        &mut s,
        Instruction::with2(Code::Mov_r64_rm64, Register::R15, Register::R9).unwrap(),
    );
    // frame (must be allocated BEFORE any rsp-relative store — the LEN_OFF store
    // below is inside the frame)
    push(
        &mut s,
        Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, FRAME).unwrap(),
    );
    // save original len (r13 is consumed by the CT loop)
    push(
        &mut s,
        Instruction::with2(Code::Mov_rm64_r64, w(LEN_OFF), Register::RDX).unwrap(),
    );

    emit_init(&mut s);
    emit_absorb_aad(&mut s);
    emit_absorb_ct_loop(&mut s);
    emit_absorb_lengths(&mut s);
    emit_finish_compare(&mut s);

    // ---- epilogue ----
    push(
        &mut s,
        Instruction::with2(Code::Add_rm64_imm32, Register::RSP, FRAME).unwrap(),
    );
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

    encode_with_labels(&s, 0x140001000)
}

/// Poly1305 key init (donna clamp) + zero h.
///  r[0]=dword@0&0x3ffffff, r[1]=(dword@3>>2)&0x3ffff03,
///  r[2]=(dword@6>>4)&0x3ffc0ff, r[3]=(dword@9>>6)&0x3f03fff, r[4]=(dword@12>>8)&0xfffff
///  pad[i]=dword@(16+4i)
fn emit_init(s: &mut Seq) {
    push(
        s,
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap(),
    );
    for i in 0..5 {
        push(
            s,
            Instruction::with2(Code::Mov_rm32_r32, w(H_OFF + (i as i32) * 4), Register::EAX)
                .unwrap(),
        );
    }
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w_disp(Register::R14, 0)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x3ff_ffffu32).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(R_OFF + 0), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w_disp(Register::R14, 3)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 2).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x3ff_ff03u32).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(R_OFF + 4), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w_disp(Register::R14, 6)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 4).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x3ff_c0ffu32).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(R_OFF + 8), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w_disp(Register::R14, 9)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 6).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x3f0_3fffu32).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(R_OFF + 12), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w_disp(Register::R14, 12)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0xf_ffffu32).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(R_OFF + 16), Register::EAX).unwrap(),
    );
    for i in 0..4 {
        push(
            s,
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EAX,
                w_disp(Register::R14, 16 + (i as i32) * 4),
            )
            .unwrap(),
        );
        push(
            s,
            Instruction::with2(
                Code::Mov_rm32_r32,
                w(PAD_OFF + (i as i32) * 4),
                Register::EAX,
            )
            .unwrap(),
        );
    }
}

/// Absorb the fixed 16-byte AAD constant as one full block (hibit = 1<<24).
/// The AAD is exactly `POLY1305_AEAD_AAD` (16 bytes) so pad16 adds nothing.
fn emit_absorb_aad(s: &mut Seq) {
    for i in 0..4 {
        let word = u32::from_le_bytes([
            POLY1305_AEAD_AAD[i * 4],
            POLY1305_AEAD_AAD[i * 4 + 1],
            POLY1305_AEAD_AAD[i * 4 + 2],
            POLY1305_AEAD_AAD[i * 4 + 3],
        ]);
        push(
            s,
            Instruction::with2(Code::Mov_rm32_imm32, w(BLK_OFF + (i as i32) * 4), word).unwrap(),
        );
    }
    emit_absorb(s, false);
}

/// Absorb the block staged in BLK. `partial` selects hibit (1<<24 vs 0) — the
/// final padded block carries the terminating 0x01 byte and hibit=0.
fn emit_absorb(s: &mut Seq, partial: bool) {
    let hibit: u32 = if partial { 0 } else { 1 << 24 };

    // h += m
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(BLK_OFF + 0)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, LIMB_MASK).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, w(H_OFF + 0), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(BLK_OFF + 3)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 2).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, LIMB_MASK).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, w(H_OFF + 4), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(BLK_OFF + 6)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 4).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, LIMB_MASK).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, w(H_OFF + 8), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(BLK_OFF + 9)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 6).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, LIMB_MASK).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, w(H_OFF + 12), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(BLK_OFF + 12)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, LIMB_MASK).unwrap(),
    );
    if hibit != 0 {
        push(
            s,
            Instruction::with2(Code::Or_rm32_imm32, Register::EAX, hibit).unwrap(),
        );
    }
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, w(H_OFF + 16), Register::EAX).unwrap(),
    );

    emit_mul_reduce(s);
}

/// The donna multiply + partial-reduce chain:
///   s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5
///   d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1   ... (5 d's)
///   then carry-reduce each d into h (partial mod p).
fn emit_mul_reduce(s: &mut Seq) {
    let d_terms: [[(i32, i32, bool); 5]; 5] = [
        [
            (0, 0, false),
            (1, 4, true),
            (2, 3, true),
            (3, 2, true),
            (4, 1, true),
        ],
        [
            (0, 1, false),
            (1, 0, false),
            (2, 4, true),
            (3, 3, true),
            (4, 2, true),
        ],
        [
            (0, 2, false),
            (1, 1, false),
            (2, 0, false),
            (3, 4, true),
            (4, 3, true),
        ],
        [
            (0, 3, false),
            (1, 2, false),
            (2, 1, false),
            (3, 0, false),
            (4, 4, true),
        ],
        [
            (0, 4, false),
            (1, 3, false),
            (2, 2, false),
            (3, 1, false),
            (4, 0, false),
        ],
    ];
    for (di, terms) in d_terms.iter().enumerate() {
        push(
            s,
            Instruction::with2(Code::Xor_r32_rm32, Register::R8D, Register::R8D).unwrap(),
        );
        for &(h_idx, r_idx, is_s) in terms {
            push(
                s,
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, w(H_OFF + h_idx * 4))
                    .unwrap(),
            );
            push(
                s,
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, w(R_OFF + r_idx * 4))
                    .unwrap(),
            );
            if is_s {
                push(
                    s,
                    Instruction::with3(Code::Imul_r32_rm32_imm8, Register::EDX, Register::EDX, 5)
                        .unwrap(),
                );
            }
            push(
                s,
                Instruction::with2(Code::Imul_r64_rm64, Register::RCX, Register::RDX).unwrap(),
            );
            push(
                s,
                Instruction::with2(Code::Add_rm64_r64, Register::R8, Register::RCX).unwrap(),
            );
        }
        push(
            s,
            Instruction::with2(Code::Mov_rm64_r64, w(D_OFF + (di as i32) * 8), Register::R8)
                .unwrap(),
        );
    }

    // ---- carry-reduce ----
    // c = d0>>26; h0 = d0 & M; d1 += c
    push(
        s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RAX, w(D_OFF + 0)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm64_imm32, Register::RAX, LIMB_MASK as u64).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(H_OFF + 0), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm64_r64, w(D_OFF + 8), Register::RDX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RAX, w(D_OFF + 8)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm64_imm32, Register::RAX, LIMB_MASK as u64).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(H_OFF + 4), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm64_r64, w(D_OFF + 16), Register::RDX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RAX, w(D_OFF + 16)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm64_imm32, Register::RAX, LIMB_MASK as u64).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(H_OFF + 8), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm64_r64, w(D_OFF + 24), Register::RDX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RAX, w(D_OFF + 24)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm64_imm32, Register::RAX, LIMB_MASK as u64).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(H_OFF + 12), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm64_r64, w(D_OFF + 32), Register::RDX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RAX, w(D_OFF + 32)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm64_imm32, Register::RAX, LIMB_MASK as u64).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(H_OFF + 16), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with3(Code::Imul_r64_rm64_imm8, Register::RDX, Register::RDX, 5).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, w(H_OFF + 0), Register::EDX).unwrap(),
    );
    // c = h0>>26; h0 &= M; h1 += c
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(H_OFF + 0)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EDX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, LIMB_MASK).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(H_OFF + 0), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, w(H_OFF + 4), Register::EDX).unwrap(),
    );
}

/// Stream-absorb the ciphertext region [r12, r12+r13):
/// full 16-byte blocks (hibit=1<<24), then a padded final partial block
/// (0x01 terminating byte, hibit=0) if the region length is not a multiple of 16.
fn emit_absorb_ct_loop(s: &mut Seq) {
    lab(s, "ct_loop");
    push(
        s,
        Instruction::with2(Code::Cmp_rm64_imm32, Register::R13, 16).unwrap(),
    );
    push(s, Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap());
    s.last_mut().unwrap().1 = Some("ct_partial_check".to_string());
    for i in 0..4 {
        push(
            s,
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EAX,
                w_disp(Register::R12, (i as i32) * 4),
            )
            .unwrap(),
        );
        push(
            s,
            Instruction::with2(
                Code::Mov_rm32_r32,
                w(BLK_OFF + (i as i32) * 4),
                Register::EAX,
            )
            .unwrap(),
        );
    }
    emit_absorb(s, false);
    push(
        s,
        Instruction::with2(Code::Add_rm64_imm32, Register::R12, 16).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Sub_rm64_imm32, Register::R13, 16).unwrap(),
    );
    push(s, Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap());
    s.last_mut().unwrap().1 = Some("ct_loop".to_string());
    lab(s, "ct_partial_check");
    push(
        s,
        Instruction::with2(Code::Test_rm64_r64, Register::R13, Register::R13).unwrap(),
    );
    push(s, Instruction::with_branch(Code::Je_rel32_64, 0).unwrap());
    s.last_mut().unwrap().1 = Some("ct_done".to_string());
    push(
        s,
        Instruction::with2(Code::Mov_rm64_imm32, w(BLK_OFF + 0), 0i32).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm64_imm32, w(BLK_OFF + 8), 0i32).unwrap(),
    );
    // rcx = BLK base (byte-indexed store below uses with_base_index_scale, the
    // proven byte-op form — no rsp+disp+index variant, which iced won't encode).
    push(
        s,
        Instruction::with2(Code::Lea_r64_m, Register::RCX, w(BLK_OFF)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Xor_r32_rm32, Register::R8D, Register::R8D).unwrap(),
    );
    lab(s, "ct_partial_copy");
    push(
        s,
        Instruction::with2(Code::Cmp_rm64_r64, Register::R8, Register::R13).unwrap(),
    );
    push(s, Instruction::with_branch(Code::Jae_rel32_64, 0).unwrap());
    s.last_mut().unwrap().1 = Some("ct_partial_byte_done".to_string());
    push(
        s,
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            w_disp_idx(Register::R12, Register::R8),
        )
        .unwrap(),
    );
    push(
        s,
        Instruction::with2(
            Code::Mov_rm8_r8,
            w_disp_idx(Register::RCX, Register::R8),
            Register::AL,
        )
        .unwrap(),
    );
    push(s, Instruction::with1(Code::Inc_rm64, Register::R8).unwrap());
    push(s, Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap());
    s.last_mut().unwrap().1 = Some("ct_partial_copy".to_string());
    lab(s, "ct_partial_byte_done");
    // RFC 8439 §2.8: the partial final ciphertext block is zero-padded to 16
    // bytes and absorbed as a FULL block (hibit=1<<24) — no 0x01 terminator in
    // the AEAD construction (mac_data is always 16-aligned: pad16(aad) ||
    // pad16(ct) || le64(le64) lengths).
    emit_absorb(s, false);
    lab(s, "ct_done");
    push(s, Instruction::with(Code::Nopd));
}

/// Absorb the trailing lengths block: le64(len(AAD)) || le64(len(CT)).
/// AAD length is fixed = POLY1305_AEAD_AAD.len() (16).
fn emit_absorb_lengths(s: &mut Seq) {
    push(
        s,
        Instruction::with2(
            Code::Mov_rm64_imm32,
            w(BLK_OFF + 0),
            POLY1305_AEAD_AAD.len() as i32,
        )
        .unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r64_rm64, Register::RAX, w(LEN_OFF)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm64_r64, w(BLK_OFF + 8), Register::RAX).unwrap(),
    );
    emit_absorb(s, false);
}

/// Finish: full carry, select h vs h-p, add pad, compare 16B tag to [r15].
/// rax = 0 (match) / 1 (mismatch).
fn emit_finish_compare(s: &mut Seq) {
    let carry_up = |s: &mut Seq, src: i32, dst: i32| {
        // src/dst are limb indices (0..4) — each limb is a u32 at H_OFF + idx*4.
        push(
            s,
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(H_OFF + src * 4)).unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Shr_rm32_imm8, Register::EDX, 26).unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::And_rm32_imm32, Register::EAX, LIMB_MASK).unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Mov_rm32_r32, w(H_OFF + src * 4), Register::EAX).unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Add_rm32_r32, w(H_OFF + dst * 4), Register::EDX).unwrap(),
        );
    };
    carry_up(s, 1, 2);
    carry_up(s, 2, 3);
    carry_up(s, 3, 4);
    // c = h4>>26; h4 &= M; h0 += c*5
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(H_OFF + 16)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EDX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, LIMB_MASK).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(H_OFF + 16), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with3(Code::Imul_r32_rm32_imm8, Register::EDX, Register::EDX, 5).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, w(H_OFF + 0), Register::EDX).unwrap(),
    );
    carry_up(s, 0, 1);

    // g = h + -p ; g0..g4 stored in D[0..4]
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(H_OFF + 0)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_imm32, Register::EAX, 5).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EDX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, LIMB_MASK).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(D_OFF + 0), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, w(H_OFF + 4)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, Register::ECX, Register::EDX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::ECX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EDX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::ECX, LIMB_MASK).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(D_OFF + 4), Register::ECX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(H_OFF + 8)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::EDX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EDX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, LIMB_MASK).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(D_OFF + 8), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, w(H_OFF + 12)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, Register::ECX, Register::EDX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::ECX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EDX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::And_rm32_imm32, Register::ECX, LIMB_MASK).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(D_OFF + 12), Register::ECX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(H_OFF + 16)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::EDX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Sub_rm32_imm32, Register::EAX, 1 << 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(D_OFF + 16), Register::EAX).unwrap(),
    );

    // select: mask = (g4 >> 31) - 1 (all-ones if g4 negative)
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, w(D_OFF + 16)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EDX, 31).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Sub_rm32_imm32, Register::EDX, 1).unwrap(),
    );
    for i in 0..5 {
        push(
            s,
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(D_OFF + (i as i32) * 4))
                .unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::And_rm32_r32, Register::EAX, Register::EDX).unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
        );
        push(
            s,
            Instruction::with1(Code::Not_rm32, Register::ECX).unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Mov_r32_rm32, Register::ESI, w(H_OFF + (i as i32) * 4))
                .unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::And_rm32_r32, Register::ESI, Register::ECX).unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Or_rm32_r32, Register::EAX, Register::ESI).unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Mov_rm32_r32, w(H_OFF + (i as i32) * 4), Register::EAX)
                .unwrap(),
        );
    }

    // combine h -> t0..t3 (128-bit)
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(H_OFF + 4)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 26).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Or_r32_rm32, Register::EAX, w(H_OFF + 0)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(D_OFF + 0), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(H_OFF + 4)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 6).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, w(H_OFF + 8)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 20).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Or_rm32_r32, Register::EAX, Register::ECX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(D_OFF + 4), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(H_OFF + 8)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 12).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, w(H_OFF + 12)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 14).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Or_rm32_r32, Register::EAX, Register::ECX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(D_OFF + 8), Register::EAX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(H_OFF + 12)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 18).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, w(H_OFF + 16)).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 8).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Or_rm32_r32, Register::EAX, Register::ECX).unwrap(),
    );
    push(
        s,
        Instruction::with2(Code::Mov_rm32_r32, w(D_OFF + 12), Register::EAX).unwrap(),
    );

    emit_mac_add(s);
}

/// 4-stage (t + pad) mod 2^128 add chain, then compare the 16B tag at [r15].
/// Carry kept in EDX. Returns rax = 0 (match) / 1 (mismatch).
fn emit_mac_add(s: &mut Seq) {
    push(
        s,
        Instruction::with2(Code::Xor_r32_rm32, Register::EDX, Register::EDX).unwrap(),
    );
    for i in 0..4 {
        // sum = t_i + pad_i + carry  (all < 2^32, sum < 2^34) — 64-bit add so the
        // upper-32 carry is preserved for `sum >> 32`.
        push(
            s,
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, w(D_OFF + (i as i32) * 4))
                .unwrap(),
        );
        push(
            s,
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::ECX,
                w(PAD_OFF + (i as i32) * 4),
            )
            .unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RDX).unwrap(),
        );
        push(
            s,
            Instruction::with2(
                Code::Mov_rm32_r32,
                w(MAC_OFF + (i as i32) * 4),
                Register::EAX,
            )
            .unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Shr_rm64_imm8, Register::RAX, 32).unwrap(),
        );
        push(
            s,
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(),
        );
    }

    // compare with [r15]
    push(
        s,
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap(),
    );
    for i in 0..4 {
        push(
            s,
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::ECX,
                w_disp(Register::R15, (i as i32) * 4),
            )
            .unwrap(),
        );
        push(
            s,
            Instruction::with2(
                Code::Cmp_r32_rm32,
                Register::ECX,
                w(MAC_OFF + (i as i32) * 4),
            )
            .unwrap(),
        );
        push(s, Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap());
        s.last_mut().unwrap().1 = Some("mac_fail".to_string());
    }
    push(s, Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap());
    s.last_mut().unwrap().1 = Some("mac_done".to_string());
    lab(s, "mac_fail");
    push(
        s,
        Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 1).unwrap(),
    );
    lab(s, "mac_done");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::poly1305::{poly1305_aead_tag, POLY1305_AEAD_AAD};
    use crate::vm::arena::Arena;

    /// Execute the native verify blob with Win64 args (rcx=region, rdx=len,
    /// r8=key, r9=tag) and return rax (0 = match / nonzero = mismatch).
    fn run_verify(blob: &[u8], region: &[u8], key: &[u8; 32], tag: &[u8; 16]) -> u64 {
        // The blob is a fully-unrolled 26-limb MAC (several KB), so place the
        // data buffers well past its end (64KB region) to avoid overlap.
        assert!(
            blob.len() < 0x10000,
            "poly1305 blob too large: {}B",
            blob.len()
        );
        let mut arena = Arena::new(0x40000).unwrap();
        let blob_off = 0x0usize;
        let region_off = 0x10000usize;
        let key_off = 0x12000usize;
        let tag_off = 0x14000usize;
        {
            let b = arena.bytes();
            b[blob_off..blob_off + blob.len()].copy_from_slice(blob);
            b[region_off..region_off + region.len()].copy_from_slice(region);
            b[key_off..key_off + 32].copy_from_slice(key);
            b[tag_off..tag_off + 16].copy_from_slice(tag);
        }
        let f: extern "C" fn(usize, u64, usize, usize) -> u64 =
            unsafe { std::mem::transmute(arena.base + blob_off) };
        f(
            arena.base + region_off,
            region.len() as u64,
            arena.base + key_off,
            arena.base + tag_off,
        )
    }

    fn key() -> [u8; 32] {
        (0u8..32)
            .map(|i| i.wrapping_mul(11).wrapping_add(3))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// RFC 8439 AEAD round-trip: the packer tag over (AAD, ciphertext) must be
    /// accepted by the native boot-stub blob (differential, linear block-equiv).
    #[test]
    fn poly1305_native_blob_matches_reference_aead() {
        let blob = emit_poly1305_verify_blob(0);
        assert!(
            blob.len() > 100,
            "poly1305 native blob too small: {}",
            blob.len()
        );
        let k = key();
        for len in [0usize, 1, 15, 16, 17, 31, 32, 64, 65, 100, 300, 4096] {
            let ct: Vec<u8> = (0..len)
                .map(|i| ((i as u32 * 131 + 7) % 251) as u8)
                .collect();
            let tag = poly1305_aead_tag(&POLY1305_AEAD_AAD, &ct, &k);
            let res = run_verify(&blob, &ct, &k, &tag);
            assert_eq!(
                res, 0,
                "native verify must MATCH reference AEAD tag (len={len})"
            );
        }
    }

    /// Tampered stored tag: native blob must reject (nonzero) — the boot stub
    /// then fails safe (ud2) instead of decrypt-and-run.
    #[test]
    fn poly1305_native_blob_tampered_tag_fails() {
        let blob = emit_poly1305_verify_blob(0);
        let k = key();
        let ct: Vec<u8> = (0..64u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(0x11))
            .collect();
        let tag = poly1305_aead_tag(&POLY1305_AEAD_AAD, &ct, &k);
        let mut bad = tag;
        bad[0] ^= 0xFF; // flip one tag byte
        let res = run_verify(&blob, &ct, &k, &bad);
        assert_ne!(res, 0, "tampered tag must fail verification");
    }

    /// Tampered ciphertext: native blob must reject.
    #[test]
    fn poly1305_native_blob_tampered_ct_fails() {
        let blob = emit_poly1305_verify_blob(0);
        let k = key();
        let ct: Vec<u8> = (0..100u8)
            .map(|i| i.wrapping_mul(3).wrapping_add(9))
            .collect();
        let tag = poly1305_aead_tag(&POLY1305_AEAD_AAD, &ct, &k);
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01; // flip one ciphertext byte
        let res = run_verify(&blob, &bad_ct, &k, &tag);
        assert_ne!(res, 0, "tampered ciphertext must fail verification");
    }

    /// Wrong AAD binding: the tag was computed over a different AAD, so the
    /// blob (with its fixed domain AAD) must reject.
    #[test]
    fn poly1305_native_blob_wrong_aad_fails() {
        let blob = emit_poly1305_verify_blob(0);
        let k = key();
        let ct: Vec<u8> = (0..80u8)
            .map(|i| i.wrapping_mul(5).wrapping_add(2))
            .collect();
        let wrong_aad = b"wrong-aad-binding!";
        let tag_wrong = poly1305_aead_tag(wrong_aad, &ct, &k);
        // blob computes with POLY1305_AEAD_AAD (correct domain tag) → must reject.
        let res = run_verify(&blob, &ct, &k, &tag_wrong);
        assert_ne!(res, 0, "wrong AAD must fail verification");
        // sanity: the correct-AAD tag is accepted
        let tag_ok = poly1305_aead_tag(&POLY1305_AEAD_AAD, &ct, &k);
        assert_eq!(run_verify(&blob, &ct, &k, &tag_ok), 0);
    }

    /// Length/encoding stability: the blob's byte length is VA-independent
    /// (all branches are rel32), so boot-stub 3-pass sizing is stable.
    #[test]
    fn poly1305_native_blob_len_va_independent() {
        assert_eq!(
            emit_poly1305_verify_blob(0).len(),
            emit_poly1305_verify_blob(0x14000_2000).len(),
            "Poly1305 blob length must be VA-independent"
        );
    }
}
