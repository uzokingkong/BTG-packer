use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};

// ==============================================================================
// v61 (--m7) - on-demand block decrypt + re-encrypt-after-exec dispatcher (anti-dump)
// ==============================================================================
// M7 restores the "re-encrypt after execution" of v8/v14 in a thread/reentrancy-safe
// way. v14 regressed to "decrypt -> execute -> stay plaintext" (concurrent contexts
// double-crypting in-place -> 0xC0000005). M7 uses per-block refcount + atomic state
// transitions:
//   - decrypt: only the first-entering context claims (0xFFFFFFFE) then RC4-decrypts.
//   - execute: a block always runs as plaintext.
//   - re-encrypt: the last-leaving context claims refcount 0 then RC4 re-encrypts;
//     while refcount > 0 (another context executing) it never re-encrypts.
// Result: "only the executing block is plaintext" at any instant (anti-dump).
//
// ---- P1-3 EXCEPTION POLICY ----
// If an exception (SEH/panic-unwind/Vectored/TLS-callback/AV) fires mid-block:
//   1. that block's refcount is never decremented (no dispatch-out happened) -> the
//      block stays plaintext (refcount leak). While unwinding, re-entering the block
//      makes ENTER see refcount>0 and skip decryption -> no re-encrypt race. Safe.
//   2. the claim window (state=CLAIM during decrypt/re-encrypt) does only pure math
//      on mapped memory, so no exception can fire there -> no permanent claim spin
//      (deadlock) is structurally possible.
//   3. after unwinding, re-calling the same function from catch sees the leaked
//      refcount (block still plaintext) -> normal execution. If the process survives,
//      protection is only "delayed by <=1 block", never a crash. (test[10] SEH +
//      catch_unwind validates this.)
//   Policy summary: exceptions recover by "keeping the block plaintext" (<=1 block
//   security weakening), never deadlock/double-crypt/garbage-execute.
//
// ---- Stack protocol (same as reencrypt; block stubs / OEP / boot stub) ----
// [rsp+0x10] = current_block_id   (first dispatch = 0xFFFFFFFF sentinel)
// [rsp+0x08] = target_block_id
// [rsp+0x00] = seed               (target MBA seed)
// ---- Table layout (3) ----
// [table_offset]          jump table  (num_blocks*4, phys_off ^ key)
// [table_offset +  N*4]   length table (num_blocks*4, len ^ key - read-only)
// [table_offset + 2N*4]   state table  (num_blocks*4, M7 state/refcount)
// [first_block_offset]    blocks
// ---- State table encoding ----
//   0xFFFFFFFE = claim (decrypt/re-encrypt in progress - others spin)
//   0xFFFFFFFF = encrypted (needs decrypt)
//   k (0..)    = decrypted + k contexts executing (refcount)
//   call-target (plaintext) block: length entry = key -> decoded len 0 -> skip
// ---- Block key (same as reencrypt) ----
//   key(id) = ((seed_for(C,id) + id) ^ C); target seed is the pushed value,
//   current seed is recomputed via seed_for in assembly.
// ==============================================================================
pub fn build_dispatcher_m7(
    dispatcher_va: u64,
    table_offset: usize,
    num_blocks: usize,
    mba_constant: u32,
    trace: bool,
) -> anyhow::Result<Vec<u8>> {
    use std::collections::HashMap;

    const WORKSPACE: u32 = 0x280;
    const ENC: i32 = 0xFFFF_FFFFu32 as i32;
    const CLAIM: i32 = 0xFFFF_FFFEu32 as i32;

    let disp_base_va = dispatcher_va + 0x20;
    let target_table_va = dispatcher_va + table_offset as u64;
    let length_table_va = dispatcher_va + (table_offset + num_blocks * 4) as u64;
    let state_table_va = dispatcher_va + (table_offset + num_blocks * 8) as u64;
    let section_base_va = dispatcher_va;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum L {
        EnterLoop,
        EnterDecrypted,
        EnterInc,
        EnterReady,
        ExitDone,
        Reencrypt,
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
    // [rsp+0x00]=r15 [0x08]=r14 [0x10]=r13 [0x18]=r12 [0x20]=r11 [0x28]=r10
    // [0x30]=r9 [0x38]=r8 [0x40]=rdi [0x48]=rsi [0x50]=rbx [0x58]=rdx
    // [0x60]=rcx [0x68]=rax [0x70]=eflags [0x78]=seed [0x80]=target [0x88]=current

    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::R10, mem(Register::RSP, 0x80))?,
        None,
    ); // target
    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::R11, mem(Register::RSP, 0x78))?,
        None,
    ); // seed
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::R12D, mem(Register::RSP, 0x88))?,
        None,
    ); // current
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
    ); // sbox base

    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va))?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va))?,
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
        Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX)?,
        None,
    );

    push_seq(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::EAX,
            mem_idx(Register::RSI, Register::R10, 4),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX)?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0)?,
        Some(L::EnterReady),
    );
    // EnterLoop: st = state[target]
    push_seq(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::ECX,
            mem_idx(Register::RDI, Register::R10, 4),
        )?,
        Some(L::EnterLoop),
    );
    push_seq(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, CLAIM)?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0)?,
        Some(L::EnterLoop),
    ); // claiming ??spin
    push_seq(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, ENC)?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Jne_rel32_64, 0)?,
        Some(L::EnterDecrypted),
    );
    // ENC ??claim (cmpxchg [state+target*4]: ENC -> CLAIM)
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::EAX, ENC)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::R8D, CLAIM)?,
        None,
    );
    let mut cas = Instruction::with2(
        Code::Cmpxchg_rm32_r32,
        mem_idx(Register::RDI, Register::R10, 4),
        Register::R8D,
    )?;
    cas.set_has_lock_prefix(true);
    push_seq(cas, None);
    push_seq(
        Instruction::with_branch(Code::Jne_rel32_64, 0)?,
        Some(L::EnterLoop),
    ); // lost ??spin
       // claim won ??decrypt target (r13=id, edx=len, key4@[rsp+0x100])
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R10D)?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::EAX,
            mem_idx(Register::RSI, Register::R13, 4),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX)?,
        None,
    ); // len
    push_seq(
        Instruction::with_branch(Code::Call_rel32_64, 0)?,
        Some(L::BlockCrypt),
    );
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va))?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va))?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm32_imm32,
            mem_idx(Register::RDI, Register::R10, 4),
            1,
        )?,
        None,
    ); // refcount=1
    push_seq(
        Instruction::with_branch(Code::Jmp_rel32_64, 0)?,
        Some(L::EnterReady),
    );
    push_seq(
        Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX)?,
        Some(L::EnterDecrypted),
    );
    push_seq(
        Instruction::with_branch(Code::Jne_rel32_64, 0)?,
        Some(L::EnterInc),
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX)?,
        None,
    ); // expected 0
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 1)?,
        None,
    );
    let mut cas2 = Instruction::with2(
        Code::Cmpxchg_rm32_r32,
        mem_idx(Register::RDI, Register::R10, 4),
        Register::R8D,
    )?;
    cas2.set_has_lock_prefix(true);
    push_seq(cas2, None);
    push_seq(
        Instruction::with_branch(Code::Jne_rel32_64, 0)?,
        Some(L::EnterLoop),
    );
    push_seq(
        Instruction::with_branch(Code::Jmp_rel32_64, 0)?,
        Some(L::EnterReady),
    );
    let mut inc_inst =
        Instruction::with1(Code::Inc_rm32, mem_idx(Register::RDI, Register::R10, 4))?;
    inc_inst.set_has_lock_prefix(true);
    push_seq(inc_inst, Some(L::EnterInc));
    push_seq(
        Instruction::with_branch(Code::Jmp_rel32_64, 0)?,
        Some(L::EnterReady),
    );

    push_seq(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, 0xFFFF_FFFFu32)?,
        Some(L::EnterReady),
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0)?,
        Some(L::ExitDone),
    ); // sentinel
       // key4_current = (seed_for(C, current) + current) ^ C
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::EAX, mba_constant)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R12D)?,
        None,
    );
    push_seq(
        Instruction::with3(
            Code::Imul_r32_rm32_imm32,
            Register::ECX,
            Register::ECX,
            0x9E37_79B9u32 as i32,
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::ECX)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Rol_rm32_imm8, Register::EAX, 13)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::EDX, mba_constant)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Ror_rm32_imm8, Register::EDX, 7)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::EDX)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R12D)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 5)?,
        None,
    );
    push_seq(
        Instruction::with3(
            Code::Imul_r32_rm32_imm32,
            Register::ECX,
            Register::ECX,
            0x85EB_CA6Bu32 as i32,
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::ECX)?,
        None,
    ); // seed_for
    push_seq(
        Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::R12D)?,
        None,
    ); // + current
    push_seq(
        Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant)?,
        None,
    ); // ^ C ??key4_current
    push_seq(
        Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX)?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::EAX,
            mem_idx(Register::RSI, Register::R12, 4),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX)?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0)?,
        Some(L::ExitDone),
    ); // call-target
       // lock dec [state+current*4] ; ZF=1 if result==0
    let mut dec_inst =
        Instruction::with1(Code::Dec_rm32, mem_idx(Register::RDI, Register::R12, 4))?;
    dec_inst.set_has_lock_prefix(true);
    push_seq(dec_inst, None);
    push_seq(
        Instruction::with_branch(Code::Jne_rel32_64, 0)?,
        Some(L::ExitDone),
    ); // refcount>0 ??leave decrypted
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX)?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::R8D, CLAIM)?,
        None,
    );
    let mut cas3 = Instruction::with2(
        Code::Cmpxchg_rm32_r32,
        mem_idx(Register::RDI, Register::R12, 4),
        Register::R8D,
    )?;
    cas3.set_has_lock_prefix(true);
    push_seq(cas3, None);
    push_seq(
        Instruction::with_branch(Code::Jne_rel32_64, 0)?,
        Some(L::ExitDone),
    ); // someone re-entered ??skip
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R12D)?,
        Some(L::Reencrypt),
    );
    push_seq(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::EAX,
            mem_idx(Register::RSI, Register::R13, 4),
        )?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?,
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX)?,
        None,
    ); // len
    push_seq(
        Instruction::with_branch(Code::Call_rel32_64, 0)?,
        Some(L::BlockCrypt),
    );
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va))?,
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm32_imm32,
            mem_idx(Register::RDI, Register::R12, 4),
            ENC,
        )?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Jmp_rel32_64, 0)?,
        Some(L::ExitDone),
    );

    push_seq(
        Instruction::with2(Code::Add_rm64_imm32, Register::RSP, WORKSPACE)?,
        Some(L::ExitDone),
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
    );
    push_seq(
        Instruction::with2(Code::Mov_rm64_r64, mem(Register::RSP, 0x88), Register::RAX)?,
        None,
    ); // target VA ??current slot

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
    );
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RCX, mem(Register::RSP, 0x180))?,
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Call_rel32_64, 0)?,
        Some(L::Ksa),
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
    );
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
                let target = *label_ips
                    .get(&l)
                    .ok_or_else(|| anyhow::anyhow!("m7 dispatcher: unresolved label {l:?}"))?;
                *inst = Instruction::with_branch(inst.code(), target)?;
            }
        }
    }
    let insts: Vec<Instruction> = seq.into_iter().map(|(i, _)| i).collect();
    let block = InstructionBlock::new(&insts, disp_base_va);
    let enc = BlockEncoder::encode(64, block, enc_opts)
        .map_err(|e| anyhow::anyhow!("m7 dispatcher BlockEncoder failed: {e}"))?;
    let code = enc.code_buffer;
    let expected = (ip - disp_base_va) as usize;
    if code.len() != expected {
        return Err(anyhow::anyhow!(
            "m7 dispatcher length mismatch: measured {expected} vs encoded {}",
            code.len()
        ));
    }
    Ok(code)
}
