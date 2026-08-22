// ==============================================================================
// VM native-encoding helpers (self-test / bench): reference x86 encoders.
// ==============================================================================

use crate::vm::ksa;
use anyhow::{anyhow, Result};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};

/// Encode the native x86 KSA reference (mirrors the boot stub's inline loop):
///   push rbx; push rsi; push rdi; mov rbx, sbox_va; <KSA instrs>;
///   pop rdi; pop rsi; pop rbx; ret
///
/// Windows x64 ABI: RBX, RSI, RDI are callee-saved. The KSA code uses all
/// three as persistent registers (RBX=S-box base, RSI=i, RDI=j), so we must
/// save/restore them to avoid corrupting the Rust runtime that calls us.
pub(crate) fn encode_ksa_native(
    seed_va: u64,
    k1: u32,
    k2: u32,
    k3: u32,
    sbox_va: u64,
    base_va: u64,
) -> Result<Vec<u8>> {
    let mut seq: Vec<(Instruction, Option<ksa::KsaLabel>, Option<ksa::KsaLabel>)> = Vec::new();
    seq.push((
        Instruction::with1(Code::Push_r64, Register::RBX).unwrap(),
        None,
        None,
    ));
    seq.push((
        Instruction::with1(Code::Push_r64, Register::RSI).unwrap(),
        None,
        None,
    ));
    seq.push((
        Instruction::with1(Code::Push_r64, Register::RDI).unwrap(),
        None,
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_imm64, Register::RBX, sbox_va).unwrap(),
        None,
        None,
    ));
    for item in ksa::build_ksa_instructions(seed_va, k1, k2, k3) {
        seq.push((item.inst, item.label, item.target));
    }
    seq.push((
        Instruction::with1(Code::Pop_r64, Register::RDI).unwrap(),
        None,
        None,
    ));
    seq.push((
        Instruction::with1(Code::Pop_r64, Register::RSI).unwrap(),
        None,
        None,
    ));
    seq.push((
        Instruction::with1(Code::Pop_r64, Register::RBX).unwrap(),
        None,
        None,
    ));
    seq.push((Instruction::with(Code::Retnq), None, None));

    encode_labeled_block(&seq, base_va)
}

/// Encode a (inst, label, target) sequence with two-pass branch resolution.
pub(crate) fn encode_labeled_block(
    seq: &[(Instruction, Option<ksa::KsaLabel>, Option<ksa::KsaLabel>)],
    base_va: u64,
) -> Result<Vec<u8>> {
    // label -> instruction index
    let mut label_idx: std::collections::HashMap<ksa::KsaLabel, usize> =
        std::collections::HashMap::new();
    for (i, (_, lbl, _)) in seq.iter().enumerate() {
        if let Some(l) = lbl {
            label_idx.insert(*l, i);
        }
    }

    // pass 1: measure -> IP per instruction, label IPs
    let mut ip = base_va;
    let mut label_ips: std::collections::HashMap<ksa::KsaLabel, u64> =
        std::collections::HashMap::new();
    for (inst, lbl, _) in seq.iter() {
        let mut m = *inst;
        if lbl.is_some() && is_branch_code(inst.code()) {
            m = Instruction::with_branch(inst.code(), ip).unwrap();
        }
        if let Some(l) = lbl {
            if !is_branch_code(inst.code()) {
                label_ips.insert(*l, ip);
            }
        }
        ip += measure(&m, ip) as u64;
    }

    // pass 2: resolve branch targets
    let mut insts = Vec::with_capacity(seq.len());
    for (inst, _, target) in seq {
        let mut m = *inst;
        if let Some(t) = target {
            let target_va = label_ips[t];
            m = Instruction::with_branch(inst.code(), target_va).unwrap();
        }
        insts.push(m);
    }

    let block = InstructionBlock::new(&insts, base_va);
    let enc = BlockEncoder::encode(64, block, BlockEncoderOptions::DONT_FIX_BRANCHES)
        .map_err(|e| anyhow!("native block encode failed: {}", e))?;
    let code = enc.code_buffer;
    let expected = (ip - base_va) as usize;
    if code.len() != expected {
        return Err(anyhow!(
            "native block length mismatch: measured {} vs encoded {}",
            expected,
            code.len()
        ));
    }
    Ok(code)
}

/// Encode the VM-call trampoline for the self-test:
///   push rbx; mov rcx, state_va; mov rbx, sbox_va; mov rdx, seed_va;
///   call entry_va; pop rbx; ret
pub(crate) fn encode_trampoline(
    state_va: u64,
    sbox_va: u64,
    seed_va: u64,
    entry_va: u64,
    base_va: u64,
) -> Result<Vec<u8>> {
    let insts = [
        Instruction::with1(Code::Push_r64, Register::RBX).unwrap(),
        Instruction::with2(Code::Mov_r64_imm64, Register::RCX, state_va).unwrap(),
        Instruction::with2(Code::Mov_r64_imm64, Register::RBX, sbox_va).unwrap(),
        Instruction::with2(Code::Mov_r64_imm64, Register::RDX, seed_va).unwrap(),
        Instruction::with_branch(Code::Call_rel32_64, entry_va).unwrap(),
        Instruction::with1(Code::Pop_r64, Register::RBX).unwrap(),
        Instruction::with(Code::Retnq),
    ];
    let block = InstructionBlock::new(&insts, base_va);
    let enc = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("trampoline encode failed: {}", e))?;
    Ok(enc.code_buffer)
}

pub(crate) fn measure(inst: &Instruction, ip: u64) -> usize {
    let arr = [*inst];
    let block = InstructionBlock::new(&arr, ip);
    match BlockEncoder::encode(64, block, BlockEncoderOptions::DONT_FIX_BRANCHES) {
        Ok(res) => res.code_buffer.len(),
        Err(_) => {
            if inst.len() > 0 {
                inst.len()
            } else {
                5
            }
        }
    }
}

pub(crate) fn is_branch_code(code: Code) -> bool {
    matches!(
        code,
        Code::Jmp_rel32_64 | Code::Jne_rel32_64 | Code::Jb_rel32_64 | Code::Je_rel32_64
    )
}
