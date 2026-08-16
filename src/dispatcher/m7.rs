use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};

// ==============================================================================
// v61 (--m7) ??on-demand ??곕?餓??곌랜踰???+ ???덈뺄 ??????筌뤿굞????븐슜裕??關??(anti-dump)
// ==============================================================================
// M7?? `--dispatcher-reencrypt`(v8/v14)??"???덈뺄 ??????筌뤿굞????**嶺뚮졋???⑥ル츩???덇덧/??壤??
// ???깆쓧???우벟** ?곌랜踰???類ｋ펲. v14??"?곌랜踰????????덈뺄 ????寃????"????????덈츎?????덈뻣 ???덈뺄
// ???쳜????덈콦?띠럾? in-place RC4 ??怨멥돡 ??됀???븐뼚夷?0xC0000005), M7?? ??곕?餓λ맠??**refcount**??
// ????????⑤객臾??熬곣뫗逾졾슖????깅쾳???곌랜????類ｋ펲:
//
//   - ?곌랜踰??? 嶺?嶺뚯쉳??????쳜????덈콦嶺?claim(0xFFFFFFFE) ??RC4 ?곌랜踰???
//   - ???덈뺄: ??곕?餓?? ??疫???寃???⑤객臾뜹슖?る츊壤????덈뺄??類ｋ펲.
//   - ????筌뤿굞?? 嶺뚮씭??嶺뚮씭留???뿉???ル봽??????쳜????덈콦?띠럾? refcount 0??claim????RC4 ????筌뤿굞??
//     refcount>0?????덊닱(???섎????쳜????덈콦?띠럾? ???덈뺄 繞????裕???? ????筌뤿굞???? ???낅츎??
//
// ?롪퍒??? ???????蹂?뜟???利?"???덈뺄 繞벿살탳????곕?餓λ맮彛???寃? ?????덈뺄 繞????덈뒆?????遊붋????됀??볥닱?
// ???? ???꾨Ц ?잙?裕뉔뜮?(reencrypt?? ???됰뎄 ????곕?餓????댟?OEP/?遊붋?????댟???ㅻ쾹?? ????????????????????????????
// [rsp+0x10] = current_block_id   (嶺???븐슜裕??館??= 0xFFFFFFFF ???몃폃??
// [rsp+0x08] = target_block_id
// [rsp+0x00] = seed               (target MBA ??類ｊ덧)
// ???? ???逾?????깅턄?熬곣뫗??(3?? ??????????????????????????????????????????????????????????????????????????????????????????????????????????
// [table_offset]          jump table  (num_blocks??, phys_off ^ key)
// [table_offset +  N*4]   length table (num_blocks??, len ^ key ????袁ⓥ뵛 ?熬곣뫗??
// [table_offset + 2N*4]   state table  (num_blocks??, M7 ??⑤객臾?refcount)
// [first_block_offset]    blocks
// ???? ??⑤객臾????逾???筌뤾쑵留??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
//   0xFFFFFFFE = claim (?곌랜踰???????筌뤿굞??嶺뚯쉳?듸쭛?繞??????섎????쳜????덈콦??spin)
//   0xFFFFFFFF = ??됀???(?곌랜踰????熬곣뫗??
//   k (0..)    = ?곌랜踰???+ k?????쳜????덈콦 ???덈뺄 繞?(refcount)
//   call-target(??寃? ??곕?餓? length entry = key ??decoded len 0 ????⑤객臾??誘⑹굣?????꾨븕
// ???? ??곕?餓???(reencrypt?? ???됰뎄) ????????????????????????????????????????????????????????????????????????????????????????????????
//   key(id) = ((seed_for(C,id) + id) ^ C); target??seed??push???띠룆???
//   current??seed??seed_for????怨력?븍눀?븐뻹遊뷴슖??????⑥쥓由??
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

    // ???? 1. 嶺뚮ㅄ維獄?GPR + EFLAGS ????(15?筌뤾쑬六? ??????????????????????????????????????????????????????????????????????????????
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

    // ???? 2. ?筌뤾쑴???β돦裕녻キ?+ ?뺢퀡????롪틵???????????????????????????????????????????????????????????????????????????????????????????????????
    push_seq(Instruction::with2(Code::Mov_r64_rm64, Register::R10, mem(Register::RSP, 0x80))?, None); // target
    push_seq(Instruction::with2(Code::Mov_r64_rm64, Register::R11, mem(Register::RSP, 0x78))?, None); // seed
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::R12D, mem(Register::RSP, 0x88))?, None); // current
    push_seq(Instruction::with2(Code::Cmp_rm64_imm32, Register::R10, num_blocks as i32)?, None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0)?, None);
    push_seq(Instruction::with2(Code::Cmovae_r64_rm64, Register::R10, Register::RCX)?, None);
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, num_blocks as i32)?, None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0xFFFF_FFFFu32)?, None);
    push_seq(Instruction::with2(Code::Cmovae_r32_rm32, Register::R12D, Register::ECX)?, None);

    // ???? 3. RC4 ??怨뚯씩???덉쓡??怨룸츩 ????????????????????????????????????????????????????????????????????????????????????????????????????????
    push_seq(Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, WORKSPACE)?, None);
    push_seq(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP)?, None); // sbox base

    // ???? 4. ???逾???뺢퀣伊???+ target key4 ????????????????????????????????????????????????????????????????????????????????????
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va))?, None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va))?, None);
    push_seq(Instruction::with2(Code::Lea_r32_m, Register::EAX, mem_idx(Register::R10, Register::R11, 1))?, None);
    push_seq(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant)?, None);
    push_seq(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX)?, None);

    // ???? 5. ENTER target: plaintext ?筌먦끉逾???claim/refcount ??⑤객臾??誘⑹굣????????????????????????????
    // decoded_len = length[target] ^ key4_target ; 0?????call-target(??寃? ?????꾨븕
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R10, 4))?, None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?, None);
    push_seq(Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX)?, None);
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0)?, Some(L::EnterReady)); // plaintext ??exit ??節띉?
    // EnterLoop: st = state[target]
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RDI, Register::R10, 4))?, Some(L::EnterLoop));
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, CLAIM)?, None);
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0)?, Some(L::EnterLoop)); // claiming ??spin
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, ENC)?, None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::EnterDecrypted));
    // ENC ??claim (cmpxchg [state+target*4]: ENC -> CLAIM)
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, ENC)?, None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, CLAIM)?, None);
    let mut cas = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R10, 4), Register::R8D)?;
    cas.set_has_lock_prefix(true);
    push_seq(cas, None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::EnterLoop)); // lost ??spin
    // claim won ??decrypt target (r13=id, edx=len, key4@[rsp+0x100])
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R10D)?, None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R13, 4))?, None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?, None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX)?, None); // len
    push_seq(Instruction::with_branch(Code::Call_rel32_64, 0)?, Some(L::BlockCrypt));
    // rsi/rdi??BlockCrypt?띠럾? ???餓λ뛿由?????餓??
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va))?, None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va))?, None);
    push_seq(Instruction::with2(Code::Mov_rm32_imm32, mem_idx(Register::RDI, Register::R10, 4), 1)?, None); // refcount=1
    push_seq(Instruction::with_branch(Code::Jmp_rel32_64, 0)?, Some(L::EnterReady));
    // EnterDecrypted: st == 0(dec, 0 exec) ??cmpxchg(0->1) [????筌뤿굞??claim???롪퍔???]
    push_seq(Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX)?, Some(L::EnterDecrypted));
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::EnterInc));
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX)?, None); // expected 0
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 1)?, None);
    let mut cas2 = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R10, 4), Register::R8D)?;
    cas2.set_has_lock_prefix(true);
    push_seq(cas2, None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::EnterLoop));
    push_seq(Instruction::with_branch(Code::Jmp_rel32_64, 0)?, Some(L::EnterReady));
    // EnterInc: refcount++ (??????lock inc)
    let mut inc_inst = Instruction::with1(Code::Inc_rm32, mem_idx(Register::RDI, Register::R10, 4))?;
    inc_inst.set_has_lock_prefix(true);
    push_seq(inc_inst, Some(L::EnterInc));
    push_seq(Instruction::with_branch(Code::Jmp_rel32_64, 0)?, Some(L::EnterReady));

    // ???? 6. EXIT current: refcount ?띠룆흮??+ 嶺뚮씭??嶺????쳜????덈콦 ????筌뤿굞??????????????????????????????????
    // (EnterReady = EXIT ?袁⑤?獄???戮곗굚 ??嶺뚮ㅄ維獄?ENTER ?롪퍔?δ빳?귥쾸? ???깃꼍?????????덈뺄????
    //  ??怨뚯씩???덉쓡??怨룸츩 ??怨몄젷/??븐슜裕??館?꾢슖?嶺뚯쉳?듸쭛??類ｋ펲)
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, 0xFFFF_FFFFu32)?, Some(L::EnterReady));
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0)?, Some(L::ExitDone)); // sentinel
    // key4_current = (seed_for(C, current) + current) ^ C
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, mba_constant)?, None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R12D)?, None);
    push_seq(Instruction::with3(Code::Imul_r32_rm32_imm32, Register::ECX, Register::ECX, 0x9E37_79B9u32 as i32)?, None);
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::ECX)?, None);
    push_seq(Instruction::with2(Code::Rol_rm32_imm8, Register::EAX, 13)?, None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::EDX, mba_constant)?, None);
    push_seq(Instruction::with2(Code::Ror_rm32_imm8, Register::EDX, 7)?, None);
    push_seq(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::EDX)?, None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R12D)?, None);
    push_seq(Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 5)?, None);
    push_seq(Instruction::with3(Code::Imul_r32_rm32_imm32, Register::ECX, Register::ECX, 0x85EB_CA6Bu32 as i32)?, None);
    push_seq(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::ECX)?, None); // seed_for
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::R12D)?, None); // + current
    push_seq(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant)?, None); // ^ C ??key4_current
    push_seq(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX)?, None);
    // plaintext(current) ?筌먦끉逾? length[current] ^ key4_current == 0 ??skip
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R12, 4))?, None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?, None);
    push_seq(Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX)?, None);
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0)?, Some(L::ExitDone)); // call-target
    // lock dec [state+current*4] ; ZF=1 if result==0
    let mut dec_inst = Instruction::with1(Code::Dec_rm32, mem_idx(Register::RDI, Register::R12, 4))?;
    dec_inst.set_has_lock_prefix(true);
    push_seq(dec_inst, None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::ExitDone)); // refcount>0 ??leave decrypted
    // refcount==0 ??claim(0 -> CLAIM) ??嶺뚯쉳??????롪퍔???
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX)?, None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, CLAIM)?, None);
    let mut cas3 = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R12, 4), Register::R8D)?;
    cas3.set_has_lock_prefix(true);
    push_seq(cas3, None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::ExitDone)); // someone re-entered ??skip
    // claim won ??????筌뤿굞??(key4@[rsp+0x100], len, r13=current)
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R12D)?, Some(L::Reencrypt));
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R13, 4))?, None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100))?, None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX)?, None); // len
    push_seq(Instruction::with_branch(Code::Call_rel32_64, 0)?, Some(L::BlockCrypt));
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va))?, None);
    push_seq(Instruction::with2(Code::Mov_rm32_imm32, mem_idx(Register::RDI, Register::R12, 4), ENC)?, None); // ??encrypted
    push_seq(Instruction::with_branch(Code::Jmp_rel32_64, 0)?, Some(L::ExitDone));

    // ???? 7. ??怨뚯씩???덉쓡??怨룸츩 ??怨몄젷 + ??믨퀡?????逾????븐슜裕??館??(reencrypt?? ???됰뎄) ??????????????????
    push_seq(Instruction::with2(Code::Add_rm64_imm32, Register::RSP, WORKSPACE)?, Some(L::ExitDone));
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va))?, None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RAX, Register::R10, 4))?, None);
    push_seq(Instruction::with2(Code::Lea_r32_m, Register::EAX, mem_idx(Register::R10, Register::R11, 1))?, None);
    push_seq(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant)?, None);
    push_seq(Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX)?, None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va))?, None);
    push_seq(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX)?, None);
    push_seq(Instruction::with2(Code::Mov_rm64_r64, mem(Register::RSP, 0x88), Register::RAX)?, None); // target VA ??current slot

    // ???? 8. ?곌랜踰??+ ??믨퀡??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    for r in [
        Register::R15, Register::R14, Register::R13, Register::R12, Register::R11, Register::R10,
        Register::R9, Register::R8, Register::RDI, Register::RSI, Register::RBX, Register::RDX,
        Register::RCX, Register::RAX,
    ] {
        push_seq(Instruction::with1(Code::Pop_r64, r)?, None);
    }
    push_seq(Instruction::with(Code::Popfq), None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RSP, mem(Register::RSP, 0x10))?, None);
    push_seq(Instruction::with(Code::Retnq), None);

    // ???? block_crypt: r13d=block_id, key4@[rsp+0x100], len=edx, sbox@rbx ????????????????
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem(Register::RSP, 0x108))?, Some(L::BlockCrypt));
    push_seq(Instruction::with2(Code::Test_rm32_r32, Register::EDX, Register::EDX)?, None);
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0)?, Some(L::BlockCryptDone));
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RCX, mem(Register::RSP, 0x180))?, None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 64)?, None);
    push_seq(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RCX, 0), Register::EAX)?, Some(L::ExpandLoop));
    push_seq(Instruction::with2(Code::Add_rm64_imm32, Register::RCX, 4)?, None);
    push_seq(Instruction::with1(Code::Dec_rm32, Register::R8D)?, None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0)?, Some(L::ExpandLoop));
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va))?, None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RAX, Register::R13, 4))?, None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::ECX, mem(Register::RSP, 0x108))?, None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va))?, None);
    push_seq(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX)?, None);
    push_seq(Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX)?, None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RCX, mem(Register::RSP, 0x180))?, None);
    push_seq(Instruction::with_branch(Code::Call_rel32_64, 0)?, Some(L::Ksa));
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI)?, None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI)?, None);
    push_seq(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R14)?, None);
    push_seq(Instruction::with_branch(Code::Call_rel32_64, 0)?, Some(L::Prga));
    push_seq(Instruction::with(Code::Retnq), Some(L::BlockCryptDone));

    // ???? KSA / PRGA (reencrypt?? ???됰뎄) ????????????????????????????????????????????????????????????????????????????????????
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI)?, Some(L::Ksa));
    push_seq(Instruction::with2(Code::Mov_rm8_r8, mem_idx(Register::RBX, Register::RSI, 1), Register::SIL)?, Some(L::KsaInit));
    push_seq(Instruction::with1(Code::Inc_rm32, Register::ESI)?, None);
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100)?, None);
    push_seq(Instruction::with_branch(Code::Jb_rel32_64, 0)?, Some(L::KsaInit));
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI)?, None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI)?, None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, mem_idx(Register::RBX, Register::RSI, 1))?, Some(L::KsaLoop));
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX)?, None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, mem_idx(Register::RCX, Register::RSI, 1))?, None);
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX)?, None);
    push_seq(Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF)?, None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, mem_idx(Register::RBX, Register::RSI, 1))?, None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::R8D, mem_idx(Register::RBX, Register::RDI, 1))?, None);
    push_seq(Instruction::with2(Code::Mov_rm8_r8, mem_idx(Register::RBX, Register::RDI, 1), Register::AL)?, None);
    push_seq(Instruction::with2(Code::Mov_rm8_r8, mem_idx(Register::RBX, Register::RSI, 1), Register::R8L)?, None);
    push_seq(Instruction::with1(Code::Inc_rm32, Register::ESI)?, None);
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100)?, None);
    push_seq(Instruction::with_branch(Code::Jb_rel32_64, 0)?, Some(L::KsaLoop));
    push_seq(Instruction::with(Code::Retnq), None);

    push_seq(Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX)?, Some(L::Prga));
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0)?, Some(L::PrgaDone));
    push_seq(Instruction::with1(Code::Inc_rm32, Register::ESI)?, Some(L::PrgaLoop));
    push_seq(Instruction::with2(Code::And_rm32_imm32, Register::ESI, 0xFF)?, None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, mem_idx(Register::RBX, Register::RSI, 1))?, None);
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX)?, None);
    push_seq(Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF)?, None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::R8D, mem_idx(Register::RBX, Register::RSI, 1))?, None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, mem_idx(Register::RBX, Register::RDI, 1))?, None);
    push_seq(Instruction::with2(Code::Mov_rm8_r8, mem_idx(Register::RBX, Register::RDI, 1), Register::R8L)?, None);
    push_seq(Instruction::with2(Code::Mov_rm8_r8, mem_idx(Register::RBX, Register::RSI, 1), Register::R9L)?, None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R8D)?, None);
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::R9D)?, None);
    push_seq(Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0xFF)?, None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, mem_idx(Register::RBX, Register::RAX, 1))?, None);
    push_seq(Instruction::with2(Code::Xor_rm8_r8, mem(Register::RCX, 0), Register::AL)?, None);
    push_seq(Instruction::with1(Code::Inc_rm64, Register::RCX)?, None);
    push_seq(Instruction::with1(Code::Dec_rm64, Register::RDX)?, None);
    push_seq(Instruction::with_branch(Code::Jmp_rel32_64, 0)?, Some(L::Prga));
    push_seq(Instruction::with(Code::Retnq), Some(L::PrgaDone));

    // ???? ?筌뤾쑵留??(measure ??label resolve ??batch encode) ??????????????????????????????????????????????????
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
                let target = label_ips[&l];
                *inst = Instruction::with_branch(inst.code(), target)?;
            }
        }
    }
    let insts: Vec<Instruction> = seq.into_iter().map(|(i, _)| i).collect();
    let block = InstructionBlock::new(&insts, disp_base_va);
    let enc = BlockEncoder::encode(64, block, enc_opts).expect("m7 dispatcher BlockEncoder failed");
    let code = enc.code_buffer;
    let expected = (ip - disp_base_va) as usize;
    assert_eq!(
        code.len(),
        expected,
        "m7 dispatcher length mismatch: measured {} vs encoded {}",
        expected,
        code.len()
    );
    Ok(code)
}