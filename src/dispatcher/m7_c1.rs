use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};

// ==============================================================================
// v61 (--custom-cipher + --m7) ??BTG-C1 per-block on-demand ??釉?紐낆넅 ?遺용뮞??μ퓗
// ==============================================================================
// `build_dispatcher_m7`(RC4 per-block)????덉뵬??refcount-safe ?怨밴묶 ?믩챷????怨뺣┷,
// ?됰뗀以??酉???癰귣벏??遺? RC4 KSA/PRGA ????**BTG-C1 ?怨밴묶??crypt blob**??곗쨮 ??묐뻬??뺣뼄.
//
//   - per-block key: key4 = (seed_for(C,id)+id)^C (疫꿸퀣??MBA ?? [rsp+0x100]???醫?)
//   - key32 = key4 8??獄쏆꼶?? (??λ묽 `repeat4(key4)`?? ??덉뵬)
//   - C1 ?怨밴묶 甕곌쑵??c1_state_va, 0x80B)?? 256B S-box ?怨몃땾 ???뵠??c1_sbox_va)??
//     ??λ묽揶쎛 .textb??獄쏄퀣???랁? C1Init ??뺥닏?룐뫂????怨??袁⑸퓠 key4 ???怨밴묶???λ뜃由??
//   - crypt blob(`crypto::native::emit_btg_crypt_blob`)?? ???遺용뮞??μ퓗 ?꾨뗀諭???쇰퓠
//     raw bytes嚥?append??랁?`call c1_blob_va`(??? rel32)嚥??紐꾪뀱??뺣뼄.
//
// ?됰뗀以???믩９湲???λ뜃由?遺뗫；沅??쎈뱜????밴쉐??筌뤴뫀紐???λ묽??`BtgCipher::new(repeat4(key4),0)`
// ?? ??쑵????덉뵬??곷튊 ??뺣뼄. crypt blob?? ??? native == reference 野꺜筌앹빖留?
// ==============================================================================
pub fn build_dispatcher_m7_c1(
    dispatcher_va: u64,
    table_offset: usize,
    num_blocks: usize,
    mba_constant: u32,
    trace: bool,
    c1_state_va: u64,
    c1_sbox_va: u64,
) -> Vec<u8> {
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
    // push_seq: seq.push((inst, lbl)) 留ㅽ겕濡?(?대줈???seq??媛蹂 ??щ? ?좎???    // emit_c1_crypt! 留ㅽ겕濡쒖쓽 吏곸젒 seq ?묎렐怨?異⑸룎?섎?濡?留ㅽ겕濡쒕줈 ?泥?
    macro_rules! push_seq {
        ($inst:expr, $lbl:expr) => {
            seq.push(($inst, $lbl))
        };
    }

    // c1_blob_va??main ?꾨뗀諭???쇰퓠 append??롫뮉 blob??VA (?紐꾪맜?????類ㅼ젟).
    // rel32 call?? 疫뀀챷???븍뜄? ??placeholder 0??곗쨮 筌β돦??????苑??
    let mut c1_blob_va: u64 = 0;
    let mut c1_blob_call_idxs: Vec<usize> = Vec::new();

    // C1 per-block crypt ??쀂???(???⑤끃肉???紐껋뵬????r13=block_id, edx=len,
    // key4@[rsp+0x100] 餓Β??: call C1Init ???됰뗀以?甕곗쥙????④쑴沅???call c1_blob.
    macro_rules! emit_c1_crypt {
        () => {{
            seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(L::C1Init)));
            seq.push((Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va)).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RAX, Register::R13, 4)).unwrap(), None));
            seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ECX, mem(Register::RSP, 0x100)).unwrap(), None));
            seq.push((Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va)).unwrap(), None));
            seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).unwrap(), None)); // buf
            // edx(=len)??C1Init/?④쑴沅?癒?퐣 癰귣똻??(C1Init?? eax/ecx/rdi筌?????
            c1_blob_call_idxs.push(seq.len());
            seq.push((Instruction::with_branch(Code::Call_rel32_64, c1_blob_va).unwrap(), None));
        }};
    }

    if trace {
        seq.push((Instruction::with(Code::Int3), None));
    }

    // ???? 1. 筌뤴뫀諭?GPR + EFLAGS ????(15?紐꾨뻻) ??????????????????????????????????????????????????????????????????????????????
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
        push_seq!(Instruction::with1(Code::Push_r64, r).unwrap(), None);
    }

    // ???? 2. ?紐꾩쁽 嚥≪뮆諭?+ 甕곕뗄??野꺜??????????????????????????????????????????????????????????????????????????????????????????????????
    push_seq!(Instruction::with2(Code::Mov_r64_rm64, Register::R10, mem(Register::RSP, 0x80)).unwrap(), None); // target
    push_seq!(Instruction::with2(Code::Mov_r64_rm64, Register::R11, mem(Register::RSP, 0x78)).unwrap(), None); // seed
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::R12D, mem(Register::RSP, 0x88)).unwrap(), None); // current
    push_seq!(Instruction::with2(Code::Cmp_rm64_imm32, Register::R10, num_blocks as i32).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0).unwrap(), None);
    push_seq!(Instruction::with2(Code::Cmovae_r64_rm64, Register::R10, Register::RCX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, num_blocks as i32).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0xFFFF_FFFFu32).unwrap(), None);
    push_seq!(Instruction::with2(Code::Cmovae_r32_rm32, Register::R12D, Register::ECX).unwrap(), None);

    // ???? 3. ??곌쾿??쎈읂??곷뮞 + ???뵠??甕곗쥙???+ target key4 ????????????????????????????????????????????????????
    push_seq!(Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, WORKSPACE).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP).unwrap(), None);
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Lea_r32_m, Register::EAX, mem_idx(Register::R10, Register::R11, 1)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX).unwrap(), None);

    // ???? 5. ENTER target: plaintext ?類ㅼ뵥 ??claim/refcount ?怨밴묶 ?믩챷????????????????????????????
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R10, 4)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap(), None);
    push_seq!(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::EnterReady)); // plaintext
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RDI, Register::R10, 4)).unwrap(), Some(L::EnterLoop));
    push_seq!(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, CLAIM).unwrap(), None);
    push_seq!(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::EnterLoop)); // spin
    push_seq!(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, ENC).unwrap(), None);
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::EnterDecrypted));
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, ENC).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, CLAIM).unwrap(), None);
    let mut cas = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R10, 4), Register::R8D).unwrap();
    cas.set_has_lock_prefix(true);
    push_seq!(cas, None);
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::EnterLoop)); // lost ??spin
    // claim won ??C1 decrypt target
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R10D).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R13, 4)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(), None); // len
    emit_c1_crypt!();
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_rm32_imm32, mem_idx(Register::RDI, Register::R10, 4), 1).unwrap(), None);
    push_seq!(Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(L::EnterReady));
    // EnterDecrypted: st == 0 ??cmpxchg(0->1)
    push_seq!(Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX).unwrap(), Some(L::EnterDecrypted));
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::EnterInc));
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 1).unwrap(), None);
    let mut cas2 = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R10, 4), Register::R8D).unwrap();
    cas2.set_has_lock_prefix(true);
    push_seq!(cas2, None);
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::EnterLoop));
    push_seq!(Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(L::EnterReady));
    let mut inc_inst = Instruction::with1(Code::Inc_rm32, mem_idx(Register::RDI, Register::R10, 4)).unwrap();
    inc_inst.set_has_lock_prefix(true);
    push_seq!(inc_inst, Some(L::EnterInc));
    push_seq!(Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(L::EnterReady));

    // ???? 6. EXIT current: refcount 揶쏅Ŋ??+ 筌띾뜆?筌??뚢뫂???쎈뱜 C1 ??釉?紐낆넅 ????????????????????????
    push_seq!(Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, 0xFFFF_FFFFu32).unwrap(), Some(L::EnterReady));
    push_seq!(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::ExitDone)); // sentinel
    // key4_current = (seed_for(C, current) + current) ^ C
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, mba_constant).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R12D).unwrap(), None);
    push_seq!(Instruction::with3(Code::Imul_r32_rm32_imm32, Register::ECX, Register::ECX, 0x9E37_79B9u32 as i32).unwrap(), None);
    push_seq!(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::ECX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Rol_rm32_imm8, Register::EAX, 13).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::EDX, mba_constant).unwrap(), None);
    push_seq!(Instruction::with2(Code::Ror_rm32_imm8, Register::EDX, 7).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::EDX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R12D).unwrap(), None);
    push_seq!(Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 5).unwrap(), None);
    push_seq!(Instruction::with3(Code::Imul_r32_rm32_imm32, Register::ECX, Register::ECX, 0x85EB_CA6Bu32 as i32).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::ECX).unwrap(), None); // seed_for
    push_seq!(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::R12D).unwrap(), None); // + current
    push_seq!(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant).unwrap(), None); // ^ C
    push_seq!(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX).unwrap(), None);
    // plaintext(current) ?類ㅼ뵥
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R12, 4)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap(), None);
    push_seq!(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::ExitDone)); // call-target
    let mut dec_inst = Instruction::with1(Code::Dec_rm32, mem_idx(Register::RDI, Register::R12, 4)).unwrap();
    dec_inst.set_has_lock_prefix(true);
    push_seq!(dec_inst, None);
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::ExitDone)); // refcount>0
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, CLAIM).unwrap(), None);
    let mut cas3 = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R12, 4), Register::R8D).unwrap();
    cas3.set_has_lock_prefix(true);
    push_seq!(cas3, None);
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::ExitDone)); // someone re-entered
    // claim won ??C1 ??釉?紐낆넅 (r13=current)
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R12D).unwrap(), Some(L::Reencrypt));
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R13, 4)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(), None); // len
    emit_c1_crypt!();
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_rm32_imm32, mem_idx(Register::RDI, Register::R12, 4), ENC).unwrap(), None);
    push_seq!(Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(L::ExitDone));

    // ???? 7. ??곌쾿??쎈읂??곷뮞 ??곸젫 + ?癒곕늄 ???뵠???遺용뮞??ν뒄 ??????????????????????????????????????????????????????????
    push_seq!(Instruction::with2(Code::Add_rm64_imm32, Register::RSP, WORKSPACE).unwrap(), Some(L::ExitDone));
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RAX, Register::R10, 4)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Lea_r32_m, Register::EAX, mem_idx(Register::R10, Register::R11, 1)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_rm64_r64, mem(Register::RSP, 0x88), Register::RAX).unwrap(), None);

    // ???? 8. 癰귣벊??+ ?癒곕늄 ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    for r in [
        Register::R15, Register::R14, Register::R13, Register::R12, Register::R11, Register::R10,
        Register::R9, Register::R8, Register::RDI, Register::RSI, Register::RBX, Register::RDX,
        Register::RCX, Register::RAX,
    ] {
        push_seq!(Instruction::with1(Code::Pop_r64, r).unwrap(), None);
    }
    push_seq!(Instruction::with(Code::Popfq), None);
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RSP, mem(Register::RSP, 0x10)).unwrap(), None);
    push_seq!(Instruction::with(Code::Retnq), None);

    // ???? C1Init: key4@[rsp+0x108] ??c1_state_va ?怨밴묶 ?λ뜃由??????????????????????????????????????????????
    push_seq!(Instruction::with2(Code::Mov_r64_imm64, Register::RDI, c1_state_va).unwrap(), Some(L::C1Init));
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem(Register::RSP, 0x108)).unwrap(), None); // key4
    for i in 0..8u32 {
        push_seq!(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RDI, i * 4), Register::EAX).unwrap(), None);
    }
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_rm64_r64, mem(Register::RDI, 0x20), Register::RAX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RDI, 0x28), Register::EAX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_rm32_imm32, mem(Register::RDI, 0x70), 0x40u32).unwrap(), None);
    push_seq!(Instruction::with(Code::Retnq), None);

    // ???? ?紐꾪맜??(measure ??c1_blob_va ?類ㅼ젟 ??label resolve ??batch encode) ??????????
    let enc_opts = BlockEncoderOptions::DONT_FIX_BRANCHES;
    let mut ip = disp_base_va;
    let mut label_ips: HashMap<L, u64> = HashMap::new();
    for (inst, lbl) in seq.iter() {
        let mut m = *inst;
        if lbl.is_some() && is_branch(inst.code()) {
            m = Instruction::with_branch(inst.code(), ip).unwrap();
        }
        let len = measure_inst(&m, ip, enc_opts);
        if let Some(l) = lbl {
            if !is_branch(inst.code()) {
                label_ips.insert(*l, ip);
            }
        }
        ip += len as u64;
    }
    c1_blob_va = ip; // main ?꾨뗀諭???= blob ??뽰삂
    for &idx in &c1_blob_call_idxs {
        seq[idx] = (Instruction::with_branch(Code::Call_rel32_64, c1_blob_va).unwrap(), None);
    }
    for (inst, lbl) in seq.iter_mut() {
        if let Some(l) = lbl {
            if is_branch(inst.code()) {
                let target = label_ips[&l];
                *inst = Instruction::with_branch(inst.code(), target).unwrap();
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
    // ???? C1 crypt blob append (state/sbox VA ??곸삢) ??????????????????????????????????????????????????????????????
    let blob = crate::crypto::native::emit_btg_crypt_blob(c1_state_va, c1_sbox_va);
    code.extend_from_slice(&blob);
    code
}
