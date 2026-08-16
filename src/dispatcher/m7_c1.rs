use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};

// ==============================================================================
// v61 (--custom-cipher + --m7) ??BTG-C1 per-block on-demand ????癲ル슢?뤸뤃?????됰Ŋ?좂뜏?????
// ==============================================================================
// `build_dispatcher_m7`(RC4 per-block)??????怨뺣윞??refcount-safe ????븐뻤???亦껋꼦維쀦뤃???????살퓢??
// ????濚???????????⑤슢?뽫뵓???? RC4 KSA/PRGA ????**BTG-C1 ????븐뻤???crypt blob**????Β??????쑩?쭚??嶺뚮㉡???
//
//   - per-block key: key4 = (seed_for(C,id)+id)^C (???뚯????MBA ?? [rsp+0x100]?????)
//   - key32 = key4 8???熬곣뫖利??? (??潁뺛깿??`repeat4(key4)`?? ????怨뺣윞)
//   - C1 ????븐뻤???筌?????c1_state_va, 0x80B)?? 256B S-box ????쇨덧????????c1_sbox_va)??
//     ??潁뺛깿??紐껋º???쎛 .textb???熬곣뫖利?????野껊뿈?? C1Init ??嶺뚮쮳?노튂??猷매?댚??????????썹땟??key4 ??????븐뻤????潁??용끏???
//   - crypt blob(`crypto::native::emit_btg_crypt_blob`)?? ?????됰Ŋ?좂뜏???????ш끽維???????⑥쥓援?
//     raw bytes??append???野껊뿈??`call c1_blob_va`(??? rel32)???癲ル슢?????嶺뚮㉡???
//
// ????濚???亦껋꼦維?濡㏓섀???潁??용끏????됰씭??죰?녿졁??????됱뎽?????꾩룆?????꿔꺂??袁ㅻ븶?癲???潁뺛깿???`BtgCipher::new(repeat4(key4),0)`
// ?? ?????????怨뺣윞????ㅿ폑????嶺뚮㉡??? crypt blob?? ???? native == reference ?嚥▲굧???꿔꺂?ｉ뜮?뚮쑏筌믩끃異?
// ==============================================================================
pub fn build_dispatcher_m7_c1(
    dispatcher_va: u64,
    table_offset: usize,
    num_blocks: usize,
    mba_constant: u32,
    trace: bool,
    c1_state_va: u64,
    c1_sbox_va: u64,
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
        C1Init,
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
    // push_seq: seq.push((inst, lbl)) 癲ル슢???μ물筌먯쉸肉?(???繞????seq????좊읈??怨뚮뼚? ????? ?????    // emit_c1_crypt! 癲ル슢???μ물筌먯쉸肉?筌믨퀡爰?癲ル슣????seq ???쒋닪????野껊챶爾??????癲ル슢???μ물筌먯쉸肉?筌먦끉큔 ??癲?
    macro_rules! push_seq {
        ($inst:expr, $lbl:expr) => {
            seq.push(($inst, $lbl))
        };
    }

    // c1_blob_va??main ??ш끽維???????⑥쥓援?append???β뼯爰귨㎘?blob??VA (?癲ル슢???몄춹?????癲ル슢캉???.
    // rel32 call?? ???궰?嶺?????곗뵯?? ??placeholder 0????Β???꿔꺂?????????????
    let mut c1_blob_va: u64 = 0;
    let mut c1_blob_call_idxs: Vec<usize> = Vec::new();

    // C1 per-block crypt ???亦낃콛????(??????곗숯????癲ル슢??遺셋????r13=block_id, edx=len,
    // key4@[rsp+0x100] 嚥싳쉶瑗ц짆堉샕??: call C1Init ??????濚??筌??節꾪렭?????影??낟????call c1_blob.
    macro_rules! emit_c1_crypt {
        () => {{
            seq.push((Instruction::with_branch(Code::Call_rel32_64, 0)?, Some(L::C1Init)));
            seq.push((Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va))?, None));
            seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RAX, Register::R13, 4))?, None));
            seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ECX, mem(Register::RSP, 0x100))?, None));
            seq.push((Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va))?, None));
            seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX)?, None));
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX)?, None)); // buf
            // edx(=len)??C1Init/??影??낟????????⑤슢????(C1Init?? eax/ecx/rdi??????
            c1_blob_call_idxs.push(seq.len());
            seq.push((Instruction::with_branch(Code::Call_rel32_64, c1_blob_va)?, None));
        }};
    }

    if trace {
        seq.push((Instruction::with(Code::Int3), None));
    }

    // ???? 1. ?꿔꺂??袁ㅻ븶???GPR + EFLAGS ????(15?癲ル슢???彛? ??????????????????????????????????????????????????????????????????????????????
    push_seq!(Instruction::with(Code::Pushfq), None);
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
        push_seq!(Instruction::with1(Code::Push_r64, r)?, None);
    }

    // ???? 2. ?癲ル슢?????汝??吏??좉텣?+ ?筌??????嚥▲굧????????????????????????????????????????????????????????????????????????????????????????????????????
    push_seq!(Instruction::with2(Code::Mov_r64_rm64, Register::R10, mem(Register::RSP, 0x80))?, None); // target
    push_seq!(Instruction::with2(Code::Mov_r64_rm64, Register::R11, mem(Register::RSP, 0x78))?, None); // seed
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::R12D, mem(Register::RSP, 0x88))?, None); // current
    push_seq!(Instruction::with2(Code::Cmp_rm64_imm32, Register::R10, num_blocks as i32)?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0)?, None);
    push_seq!(Instruction::with2(Code::Cmovae_r64_rm64, Register::R10, Register::RCX)?, None);
    push_seq!(Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, num_blocks as i32)?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0xFFFF_FFFFu32)?, None);
    push_seq!(Instruction::with2(Code::Cmovae_r32_rm32, Register::R12D, Register::ECX)?, None);

    // ???? 3. ????ㅼ뒩??????깅굳????ㅿ폍筌?+ ???????筌??節꾪렭???+ target key4 ????????????????????????????????????????????????????
    push_seq!(Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, WORKSPACE)?, None);
    push_seq!(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP)?, None);
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va))?, None);
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va))?, None);
    push_seq!(Instruction::with2(Code::Lea_r32_m, Register::EAX, mem_idx(Register::R10, Register::R11, 1))?, None);
    push_seq!(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant)?, None);
    push_seq!(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX)?, None);

    // ???? 5. ENTER target: plaintext ?癲ル슢캉??????claim/refcount ????븐뻤???亦껋꼦維쀦뤃????????????????????????????
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R10, 4))?, None);
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?, None);
    push_seq!(Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX)?, None);
    push_seq!(Instruction::with_branch(Code::Je_rel32_64, 0)?, Some(L::EnterReady)); // plaintext
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RDI, Register::R10, 4))?, Some(L::EnterLoop));
    push_seq!(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, CLAIM)?, None);
    push_seq!(Instruction::with_branch(Code::Je_rel32_64, 0)?, Some(L::EnterLoop)); // spin
    push_seq!(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, ENC)?, None);
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::EnterDecrypted));
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, ENC)?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, CLAIM)?, None);
    let mut cas = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R10, 4), Register::R8D)?;
    cas.set_has_lock_prefix(true);
    push_seq!(cas, None);
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::EnterLoop)); // lost ??spin
    // claim won ??C1 decrypt target
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R10D)?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R13, 4))?, None);
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX)?, None); // len
    emit_c1_crypt!();
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va))?, None);
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va))?, None);
    push_seq!(Instruction::with2(Code::Mov_rm32_imm32, mem_idx(Register::RDI, Register::R10, 4), 1)?, None);
    push_seq!(Instruction::with_branch(Code::Jmp_rel32_64, 0)?, Some(L::EnterReady));
    // EnterDecrypted: st == 0 ??cmpxchg(0->1)
    push_seq!(Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX)?, Some(L::EnterDecrypted));
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::EnterInc));
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX)?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 1)?, None);
    let mut cas2 = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R10, 4), Register::R8D)?;
    cas2.set_has_lock_prefix(true);
    push_seq!(cas2, None);
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::EnterLoop));
    push_seq!(Instruction::with_branch(Code::Jmp_rel32_64, 0)?, Some(L::EnterReady));
    let mut inc_inst = Instruction::with1(Code::Inc_rm32, mem_idx(Register::RDI, Register::R10, 4))?;
    inc_inst.set_has_lock_prefix(true);
    push_seq!(inc_inst, Some(L::EnterInc));
    push_seq!(Instruction::with_branch(Code::Jmp_rel32_64, 0)?, Some(L::EnterReady));

    // ???? 6. EXIT current: refcount ??醫딆┫???+ ?꿔꺂????????????????됱뎽 C1 ????癲ル슢?뤸뤃??????????????????????????
    push_seq!(Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, 0xFFFF_FFFFu32)?, Some(L::EnterReady));
    push_seq!(Instruction::with_branch(Code::Je_rel32_64, 0)?, Some(L::ExitDone)); // sentinel
    // key4_current = (seed_for(C, current) + current) ^ C
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, mba_constant)?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R12D)?, None);
    push_seq!(Instruction::with3(Code::Imul_r32_rm32_imm32, Register::ECX, Register::ECX, 0x9E37_79B9u32 as i32)?, None);
    push_seq!(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::ECX)?, None);
    push_seq!(Instruction::with2(Code::Rol_rm32_imm8, Register::EAX, 13)?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::EDX, mba_constant)?, None);
    push_seq!(Instruction::with2(Code::Ror_rm32_imm8, Register::EDX, 7)?, None);
    push_seq!(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::EDX)?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R12D)?, None);
    push_seq!(Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 5)?, None);
    push_seq!(Instruction::with3(Code::Imul_r32_rm32_imm32, Register::ECX, Register::ECX, 0x85EB_CA6Bu32 as i32)?, None);
    push_seq!(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::ECX)?, None); // seed_for
    push_seq!(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::R12D)?, None); // + current
    push_seq!(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant)?, None); // ^ C
    push_seq!(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX)?, None);
    // plaintext(current) ?癲ル슢캉????
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R12, 4))?, None);
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?, None);
    push_seq!(Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX)?, None);
    push_seq!(Instruction::with_branch(Code::Je_rel32_64, 0)?, Some(L::ExitDone)); // call-target
    let mut dec_inst = Instruction::with1(Code::Dec_rm32, mem_idx(Register::RDI, Register::R12, 4))?;
    dec_inst.set_has_lock_prefix(true);
    push_seq!(dec_inst, None);
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::ExitDone)); // refcount>0
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX)?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, CLAIM)?, None);
    let mut cas3 = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R12, 4), Register::R8D)?;
    cas3.set_has_lock_prefix(true);
    push_seq!(cas3, None);
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::ExitDone)); // someone re-entered
    // claim won ??C1 ????癲ル슢?뤸뤃??(r13=current)
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R12D)?, Some(L::Reencrypt));
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R13, 4))?, None);
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX)?, None); // len
    emit_c1_crypt!();
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va))?, None);
    push_seq!(Instruction::with2(Code::Mov_rm32_imm32, mem_idx(Register::RDI, Register::R12, 4), ENC)?, None);
    push_seq!(Instruction::with_branch(Code::Jmp_rel32_64, 0)?, Some(L::ExitDone));

    // ???? 7. ????ㅼ뒩??????깅굳????ㅿ폍筌?????ㅼ굣??+ ??沃섃뫂????????????됰Ŋ?좂뜏??濚????????????????????????????????????????????????????????????
    push_seq!(Instruction::with2(Code::Add_rm64_imm32, Register::RSP, WORKSPACE)?, Some(L::ExitDone));
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va))?, None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RAX, Register::R10, 4))?, None);
    push_seq!(Instruction::with2(Code::Lea_r32_m, Register::EAX, mem_idx(Register::R10, Register::R11, 1))?, None);
    push_seq!(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant)?, None);
    push_seq!(Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX)?, None);
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va))?, None);
    push_seq!(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX)?, None);
    push_seq!(Instruction::with2(Code::Mov_rm64_r64, mem(Register::RSP, 0x88), Register::RAX)?, None);

    // ???? 8. ??⑤슢?뽫뵓??+ ??沃섃뫂???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    for r in [
        Register::R15, Register::R14, Register::R13, Register::R12, Register::R11, Register::R10,
        Register::R9, Register::R8, Register::RDI, Register::RSI, Register::RBX, Register::RDX,
        Register::RCX, Register::RAX,
    ] {
        push_seq!(Instruction::with1(Code::Pop_r64, r)?, None);
    }
    push_seq!(Instruction::with(Code::Popfq), None);
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RSP, mem(Register::RSP, 0x10))?, None);
    push_seq!(Instruction::with(Code::Retnq), None);

    // ???? C1Init: key4@[rsp+0x108] ??c1_state_va ????븐뻤???潁??용끏???????????????????????????????????????????????
    push_seq!(Instruction::with2(Code::Mov_r64_imm64, Register::RDI, c1_state_va)?, Some(L::C1Init));
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem(Register::RSP, 0x108))?, None); // key4
    for i in 0..8u32 {
        push_seq!(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RDI, i * 4), Register::EAX)?, None);
    }
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX)?, None);
    push_seq!(Instruction::with2(Code::Mov_rm64_r64, mem(Register::RDI, 0x20), Register::RAX)?, None);
    push_seq!(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RDI, 0x28), Register::EAX)?, None);
    push_seq!(Instruction::with2(Code::Mov_rm32_imm32, mem(Register::RDI, 0x70), 0x40u32)?, None);
    push_seq!(Instruction::with(Code::Retnq), None);

    // ???? ?癲ル슢???몄춹??(measure ??c1_blob_va ?癲ル슢캉?????label resolve ??batch encode) ??????????
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
    c1_blob_va = ip; // main ??ш끽維?????= blob ??嶺뚮??ｆ뤃?
    for &idx in &c1_blob_call_idxs {
        seq[idx] = (Instruction::with_branch(Code::Call_rel32_64, c1_blob_va)?, None);
    }
    for (inst, lbl) in seq.iter_mut() {
        if let Some(l) = lbl {
            if is_branch(inst.code()) {
                let target = label_ips[&l];
                *inst = Instruction::with_branch(inst.code(), target)?;
            }
        }
    }
    let insts: Vec<Instruction> = seq.into_iter().map(|(i, _)| i).collect();
    let block = InstructionBlock::new(&insts, disp_base_va);
    let enc = BlockEncoder::encode(64, block, enc_opts).expect("m7-c1 dispatcher BlockEncoder failed");
    let mut code = enc.code_buffer;
    let expected = (ip - disp_base_va) as usize;
    assert_eq!(
        code.len(),
        expected,
        "m7-c1 dispatcher length mismatch: measured {} vs encoded {}",
        expected,
        code.len()
    );
    // ???? C1 crypt blob append (state/sbox VA ????ㅼ굣亦? ??????????????????????????????????????????????????????????????
    let blob = crate::crypto::native::emit_btg_crypt_blob(c1_state_va, c1_sbox_va);
    code.extend_from_slice(&blob);
    Ok(code)
}