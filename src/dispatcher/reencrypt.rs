use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};

// ==============================================================================
// ==============================================================================
// ```text
// ```
//   seed   = seed_for(C, id)  = (C + id*0x9E3779B9) rol 13 ^ C ror 7
//                                ^ (id rol 5 * 0x85EBCA6B)
//   key(id) = compute_key(seed, id, C, 2) = ((seed^id) + 2*(seed&id)) ^ C
//     [rsp+0x000..0x0FF] S-box          (rbx = rsp)
//     [rsp+0x100..0x103] key4
//     [rsp+0x180..0x27F] key256
pub fn build_dispatcher_reencrypt(
    dispatcher_va: u64,
    table_offset: usize,
    num_blocks: usize,
    mba_constant: u32,
    trace: bool,
) -> anyhow::Result<Vec<u8>> {
    use std::collections::HashMap;

    const WORKSPACE: u32 = 0x280;

    let disp_base_va = dispatcher_va + 0x20;
    let target_table_va = dispatcher_va + table_offset as u64;
    let length_table_va = dispatcher_va + (table_offset + num_blocks * 4) as u64;
    let section_base_va = dispatcher_va;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum L {
        DecTarget,
        ClaimSpin,
        AfterDecrypt,
        BlockCrypt,
        ExpandLoop,
        Ksa,
        KsaInit,
        KsaLoop,
        Prga,
        PrgaLoop,
        PrgaDone,
        BlockCryptDone,
    }

    fn is_branch(code: iced_x86::Code) -> bool {
        matches!(
            code,
            iced_x86::Code::Jb_rel32_64
                | iced_x86::Code::Je_rel32_64
                | iced_x86::Code::Jne_rel32_64
                | iced_x86::Code::Jmp_rel32_64
                | iced_x86::Code::Call_rel32_64
        )
    }

    fn measure_inst(inst: &Instruction, ip: u64, opts: u32) -> usize {
        let arr = [*inst];
        let block = InstructionBlock::new(&arr, ip);
        match BlockEncoder::encode(64, block, opts) {
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

    let mem = |reg: Register, off: u32| MemoryOperand::with_base_displ(reg, off as i64);
    let mem_idx = |base: Register, idx: Register, scale: u32| {
        MemoryOperand::with_base_index_scale(base, idx, scale)
    };
    let rip_va = |va: u64| MemoryOperand::with_base_displ(Register::RIP, va as i64);

    let mut seq: Vec<(Instruction, Option<L>)> = Vec::new();
    let mut push_seq = |inst: Instruction, lbl: Option<L>| seq.push((inst, lbl));

    if trace {
        push_seq(Instruction::with(Code::Int3), None);
    }

    push_seq(Instruction::with(Code::Pushfq), None);
    for r in [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RBX,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ] {
        push_seq(Instruction::with1(Code::Push_r64, r)?, None);
    }
    //   [rsp+0x00]=r15 [0x08]=r14 [0x10]=r13 [0x18]=r12 [0x20]=r11 [0x28]=r10
    //   [0x30]=r9 [0x38]=r8 [0x40]=rdi [0x48]=rsi [0x50]=rbx [0x58]=rdx
    //   [0x60]=rcx [0x68]=rax [0x70]=eflags [0x78]=seed [0x80]=target [0x88]=current

    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::R10, mem(Register::RSP, 0x80))?,
        None,
    ); // target id
    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::R11, mem(Register::RSP, 0x78))?,
        None,
    ); // seed
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::R12D, mem(Register::RSP, 0x88))?,
        None,
    ); // current id
    push_seq(
        Instruction::with2(Code::Cmp_rm64_imm32, Register::R10, num_blocks as i32)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Cmovae_r64_rm64, Register::R10, Register::RCX)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, num_blocks as i32)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0xFFFF_FFFFu32)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Cmovae_r32_rm32, Register::R12D, Register::ECX)?,
        None,
    );

    push_seq(
        Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, WORKSPACE)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP)?,
        None,
    ); // S-box base

    push_seq(
        Instruction::with2(
            Code::Lea_r32_m,
            Register::EAX,
            mem_idx(Register::R10, Register::R11, 1),
        )?,
        Some(L::DecTarget),
    ); // eax = seed + target (mod 2^32)
    push_seq(
        Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant)?,
        None,
    ); // ^ C
    push_seq(
        Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX)?,
        None,
    ); // key4 = (seed + target) ^ C
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R10D)?,
        None,
    ); // r13 = target id
       // ---- v14: thread/re-entrancy-safe dispatch state machine (decrypt-once) ----
       // v8~v13 "dispatch-time decrypt + return-time re-encrypt" raced when two
       // execution contexts (threads / re-entrant callbacks) dispatched the same
       // block concurrently: in-place RC4 double-crypt left the block in ciphertext
       // state while executing -> 0xC0000005 (0xC18DE class). v14 removes the
       // re-encrypt step and uses the length-table entry as the block state:
       //   - entry == 0xFFFFFFFE : another context is decrypting -> spin
       //   - entry ^ key == 0     : plaintext / already decrypted -> skip
       //   - else (encrypted)     : lock cmpxchg(entry -> 0xFFFFFFFE) claims the
       //     decrypt; the winner RC4-decrypts then writes entry = key (plaintext
       //     marker). The block stays plaintext forever after first execution.
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va))?,
        None,
    ); // rsi = length table base (block state)
    push_seq(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::EAX,
            mem_idx(Register::RSI, Register::R13, 4),
        )?,
        Some(L::ClaimSpin),
    ); // eax = entry
    push_seq(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 0xFFFF_FFFEu32)?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0)?,
        Some(L::ClaimSpin),
    ); // decrypting -> spin
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EDX, mem(Register::RSP, 0x100))?,
        None,
    ); // edx = entry ^ key4 = len
    push_seq(
        Instruction::with2(Code::Test_rm32_r32, Register::EDX, Register::EDX)?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0)?,
        Some(L::AfterDecrypt),
    ); // len==0 -> plaintext/already-decrypted -> skip crypt
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 0xFFFF_FFFEu32)?,
        None,
    );
    let mut cas = Instruction::with2(
        Code::Cmpxchg_rm32_r32,
        mem_idx(Register::RSI, Register::R13, 4),
        Register::R8D,
    )?;
    cas.set_has_lock_prefix(true);
    push_seq(cas, None); // lock cmpxchg [rsi+r13*4], r8d ; expected = eax (entry)
    push_seq(
        Instruction::with_branch(Code::Jne_rel32_64, 0)?,
        Some(L::ClaimSpin),
    ); // claim lost -> retry
       // claim won: eax = original entry, edx = len -> RC4 decrypt
    push_seq(
        Instruction::with_branch(Code::Call_rel32_64, 0)?,
        Some(L::BlockCrypt),
    );
    // mark decrypted: entry = key4 (rsi was clobbered by BlockCrypt -> reload)
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va))?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm32_r32,
            mem_idx(Register::RSI, Register::R13, 4),
            Register::EAX,
        )?,
        None,
    );

    push_seq(
        Instruction::with2(Code::Add_rm64_imm32, Register::RSP, WORKSPACE)?,
        Some(L::AfterDecrypt),
    );

    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va))?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::ECX,
            mem_idx(Register::RAX, Register::R10, 4),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Lea_r32_m,
            Register::EAX,
            mem_idx(Register::R10, Register::R11, 1),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va))?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX)?,
        None,
    ); // target VA
    push_seq(
        Instruction::with2(Code::Mov_rm64_r64, mem(Register::RSP, 0x88), Register::RAX)?,
        None,
    );

    for r in [
        Register::R15,
        Register::R14,
        Register::R13,
        Register::R12,
        Register::R11,
        Register::R10,
        Register::R9,
        Register::R8,
        Register::RDI,
        Register::RSI,
        Register::RBX,
        Register::RDX,
        Register::RCX,
        Register::RAX,
    ] {
        push_seq(Instruction::with1(Code::Pop_r64, r)?, None);
    }
    push_seq(Instruction::with(Code::Popfq), None);
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RSP, mem(Register::RSP, 0x10))?,
        None,
    );
    push_seq(Instruction::with(Code::Retnq), None);

    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem(Register::RSP, 0x108))?,
        Some(L::BlockCrypt),
    );

    // v14: len is passed in edx by the caller (length table doubles as state marker).
    // FIX(2026-08-07): the guard must run BEFORE the ExpandLoop below, because
    // `mov edx, 64` + the fill loop leave edx == 0 here -> KSA/PRGA were dead code
    // and every encrypted block executed as ciphertext (0xC0000005 @ block 8806).
    push_seq(
        Instruction::with2(Code::Test_rm32_r32, Register::EDX, Register::EDX)?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0)?,
        Some(L::BlockCryptDone),
    );
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RCX, mem(Register::RSP, 0x180))?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 64)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_rm32_r32, mem(Register::RCX, 0), Register::EAX)?,
        Some(L::ExpandLoop),
    );
    push_seq(
        Instruction::with2(Code::Add_rm64_imm32, Register::RCX, 4)?,
        None,
    );
    push_seq(Instruction::with1(Code::Dec_rm32, Register::R8D)?, None);
    push_seq(
        Instruction::with_branch(Code::Jne_rel32_64, 0)?,
        Some(L::ExpandLoop),
    );
    // off = table_enc[r13] ^ key
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va))?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::ECX,
            mem_idx(Register::RAX, Register::R13, 4),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::ECX, mem(Register::RSP, 0x108))?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va))?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX)?,
        None,
    ); // block base
       // KSA(key256, sbox)
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RCX, mem(Register::RSP, 0x180))?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Call_rel32_64, 0)?,
        Some(L::Ksa),
    );
    // PRGA(block_base, len) ??i/j = 0
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R14)?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Call_rel32_64, 0)?,
        Some(L::Prga),
    );
    push_seq(Instruction::with(Code::Retnq), Some(L::BlockCryptDone));

    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI)?,
        Some(L::Ksa),
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm8_r8,
            mem_idx(Register::RBX, Register::RSI, 1),
            Register::SIL,
        )?,
        Some(L::KsaInit),
    ); // S[i] = i
    push_seq(Instruction::with1(Code::Inc_rm32, Register::ESI)?, None);
    push_seq(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100)?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Jb_rel32_64, 0)?,
        Some(L::KsaInit),
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI)?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            mem_idx(Register::RBX, Register::RSI, 1),
        )?,
        Some(L::KsaLoop),
    );
    push_seq(
        Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX)?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            mem_idx(Register::RCX, Register::RSI, 1),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF)?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            mem_idx(Register::RBX, Register::RSI, 1),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R8D,
            mem_idx(Register::RBX, Register::RDI, 1),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm8_r8,
            mem_idx(Register::RBX, Register::RDI, 1),
            Register::AL,
        )?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm8_r8,
            mem_idx(Register::RBX, Register::RSI, 1),
            Register::R8L,
        )?,
        None,
    );
    push_seq(Instruction::with1(Code::Inc_rm32, Register::ESI)?, None);
    push_seq(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100)?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Jb_rel32_64, 0)?,
        Some(L::KsaLoop),
    );
    push_seq(Instruction::with(Code::Retnq), None);

    push_seq(
        Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX)?,
        Some(L::Prga),
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0)?,
        Some(L::PrgaDone),
    );
    push_seq(
        Instruction::with1(Code::Inc_rm32, Register::ESI)?,
        Some(L::PrgaLoop),
    );
    push_seq(
        Instruction::with2(Code::And_rm32_imm32, Register::ESI, 0xFF)?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            mem_idx(Register::RBX, Register::RSI, 1),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF)?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R8D,
            mem_idx(Register::RBX, Register::RSI, 1),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R9D,
            mem_idx(Register::RBX, Register::RDI, 1),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm8_r8,
            mem_idx(Register::RBX, Register::RDI, 1),
            Register::R8L,
        )?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm8_r8,
            mem_idx(Register::RBX, Register::RSI, 1),
            Register::R9L,
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R8D)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::R9D)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0xFF)?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            mem_idx(Register::RBX, Register::RAX, 1),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_rm8_r8, mem(Register::RCX, 0), Register::AL)?,
        None,
    );
    push_seq(Instruction::with1(Code::Inc_rm64, Register::RCX)?, None);
    push_seq(Instruction::with1(Code::Dec_rm64, Register::RDX)?, None);
    push_seq(
        Instruction::with_branch(Code::Jmp_rel32_64, 0)?,
        Some(L::Prga),
    );
    push_seq(Instruction::with(Code::Retnq), Some(L::PrgaDone));

    let enc_opts = BlockEncoderOptions::DONT_FIX_BRANCHES;
    let mut ip = disp_base_va;
    let mut label_ips: HashMap<L, u64> = HashMap::new();
    for (inst, lbl) in seq.iter() {
        let mut m = *inst;
        if lbl.is_some() && is_branch(inst.code()) {
            m = Instruction::with_branch(inst.code(), ip)?;
        }
        let len = measure_inst(&m, ip, enc_opts);
        if let Some(l) = lbl {
            if !is_branch(inst.code()) {
                label_ips.insert(*l, ip);
            }
        }
        ip += len as u64;
    }
    for (inst, lbl) in seq.iter_mut() {
        if let Some(l) = lbl {
            if is_branch(inst.code()) {
                let target = *label_ips.get(&l).ok_or_else(|| {
                    anyhow::anyhow!("reencrypt dispatcher: unresolved label {l:?}")
                })?;
                *inst = Instruction::with_branch(inst.code(), target)?;
            }
        }
    }
    let insts: Vec<Instruction> = seq.into_iter().map(|(i, _)| i).collect();
    let block = InstructionBlock::new(&insts, disp_base_va);
    let enc = BlockEncoder::encode(64, block, enc_opts)
        .map_err(|e| anyhow::anyhow!("reencrypt dispatcher BlockEncoder failed: {e}"))?;
    let code = enc.code_buffer;
    let expected = (ip - disp_base_va) as usize;
    if code.len() != expected {
        return Err(anyhow::anyhow!(
            "reencrypt dispatcher length mismatch: measured {expected} vs encoded {}",
            code.len()
        ));
    }
    Ok(code)
}
