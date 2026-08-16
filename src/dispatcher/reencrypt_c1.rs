use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};

// ==============================================================================
// v61 (--custom-cipher + --dispatcher-reencrypt) — BTG-C1 per-block 디스패처
// ==============================================================================
// `build_dispatcher_reencrypt`(v14, RC4)와 동일한 "decrypt-once" 상태 머신
// (길이 테이블 엔트리 = 블록 상태: 0xFFFFFFFE claim / entry^key==0 평문 / 그 외
// 암호문)을 쓰되, 블록 복호화를 RC4 KSA/PRGA 대신 **BTG-C1 상태형 crypt blob**으로
// 수행한다.
//
//   - per-block key: key4 = (seed+target)^C (기존 MBA 키, [rsp+0x100])
//   - key32 = key4 8회 반복 (패커 `repeat4(key4)`와 동일)
//   - C1 상태(c1_state_va)와 256B S-box(c1_sbox_va)는 패커가 .textb에 배치,
//     C1Init 서브루틴이 key4 → 상태를 초기화.
//   - crypt blob(`crypto::native::emit_btg_crypt_blob`)을 코드 뒤에 append하고
//     `call c1_blob_va`(절대 rel32)로 호출한다.
// ==============================================================================
pub fn build_dispatcher_reencrypt_c1(
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

    let disp_base_va = dispatcher_va + 0x20;
    let target_table_va = dispatcher_va + table_offset as u64;
    let length_table_va = dispatcher_va + (table_offset + num_blocks * 4) as u64;
    let section_base_va = dispatcher_va;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum L {
        DecTarget,
        ClaimSpin,
        AfterDecrypt,
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
    macro_rules! push_seq {
        ($inst:expr, $lbl:expr) => {
            seq.push(($inst, $lbl))
        };
    }

    let mut c1_blob_va: u64 = 0;
    let mut c1_blob_call_idxs: Vec<usize> = Vec::new();

    // C1 per-block decrypt 시퀀스 (r13=target, edx=len, key4@[rsp+0x100])
    macro_rules! emit_c1_crypt {
        () => {{
            seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(L::C1Init)));
            seq.push((Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va)).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RAX, Register::R13, 4)).unwrap(), None));
            seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ECX, mem(Register::RSP, 0x100)).unwrap(), None));
            seq.push((Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va)).unwrap(), None));
            seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).unwrap(), None)); // buf
            c1_blob_call_idxs.push(seq.len());
            seq.push((Instruction::with_branch(Code::Call_rel32_64, c1_blob_va).unwrap(), None));
        }};
    }

    // ── 0. Trace mode ────────────────────────────────────────────────────────────
    if trace {
        push_seq!(Instruction::with(Code::Int3), None);
    }

    // ── 1. 모든 GPR + EFLAGS 저장 (15푸시) ───────────────────────────────────────
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
    // [rsp+0x78]=seed [0x80]=target [0x88]=current

    // ── 2. 인자 로드 + 범위 검사 ────────────────────────────────────────────────
    push_seq!(Instruction::with2(Code::Mov_r64_rm64, Register::R10, mem(Register::RSP, 0x80)).unwrap(), None); // target
    push_seq!(Instruction::with2(Code::Mov_r64_rm64, Register::R11, mem(Register::RSP, 0x78)).unwrap(), None); // seed
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::R12D, mem(Register::RSP, 0x88)).unwrap(), None); // current
    push_seq!(Instruction::with2(Code::Cmp_rm64_imm32, Register::R10, num_blocks as i32).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0).unwrap(), None);
    push_seq!(Instruction::with2(Code::Cmovae_r64_rm64, Register::R10, Register::RCX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, num_blocks as i32).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0xFFFF_FFFFu32).unwrap(), None);
    push_seq!(Instruction::with2(Code::Cmovae_r32_rm32, Register::R12D, Register::ECX).unwrap(), None);

    // ── 3. 워크스페이스 ─────────────────────────────────────────────────────────
    push_seq!(Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, WORKSPACE).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP).unwrap(), None);

    // ── 5. 타깃 블록 복호화 (decrypt-once 상태 머신 + C1) ──────────────────────
    push_seq!(Instruction::with2(Code::Lea_r32_m, Register::EAX, mem_idx(Register::R10, Register::R11, 1)).unwrap(), Some(L::DecTarget));
    push_seq!(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant).unwrap(), None); // key4 = (seed+target)^C
    push_seq!(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R10D).unwrap(), None); // r13 = target
    // 길이 테이블 엔트리 = 블록 상태 (v14와 동일)
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R13, 4)).unwrap(), Some(L::ClaimSpin));
    push_seq!(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 0xFFFF_FFFEu32).unwrap(), None);
    push_seq!(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::ClaimSpin)); // decrypting → spin
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_r32_rm32, Register::EDX, mem(Register::RSP, 0x100)).unwrap(), None); // len
    push_seq!(Instruction::with2(Code::Test_rm32_r32, Register::EDX, Register::EDX).unwrap(), None);
    push_seq!(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::AfterDecrypt)); // len==0 → skip
    push_seq!(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 0xFFFF_FFFEu32).unwrap(), None);
    let mut cas = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RSI, Register::R13, 4), Register::R8D).unwrap();
    cas.set_has_lock_prefix(true);
    push_seq!(cas, None);
    push_seq!(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::ClaimSpin)); // claim lost → retry
    // claim won: r13=target, edx=len, key4@[rsp+0x100] → C1 복호화
    emit_c1_crypt!();
    // mark decrypted: entry = key4 (rsi 재로드)
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem(Register::RSP, 0x100)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_rm32_r32, mem_idx(Register::RSI, Register::R13, 4), Register::EAX).unwrap(), None);

    // ── 6. 워크스페이스 해제 ────────────────────────────────────────────────────
    push_seq!(Instruction::with2(Code::Add_rm64_imm32, Register::RSP, WORKSPACE).unwrap(), Some(L::AfterDecrypt));

    // ── 7. MBA 점프 테이블 디스패치 ─────────────────────────────────────────────
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RAX, Register::R10, 4)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Lea_r32_m, Register::EAX, mem_idx(Register::R10, Register::R11, 1)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant).unwrap(), None);
    push_seq!(Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX).unwrap(), None);
    push_seq!(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va)).unwrap(), None);
    push_seq!(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(), None); // target VA
    push_seq!(Instruction::with2(Code::Mov_rm64_r64, mem(Register::RSP, 0x88), Register::RAX).unwrap(), None);

    // ── 8. 복원 + 점프 ──────────────────────────────────────────────────────────
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

    // ── C1Init: key4@[rsp+0x108] → c1_state_va 상태 초기화 ──────────────────────
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

    // ── 인코딩 (measure → c1_blob_va 확정 → label resolve → batch encode) ─────
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
    c1_blob_va = ip; // main 코드 끝 = blob 시작
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
    let enc = BlockEncoder::encode(64, block, enc_opts).expect("reencrypt-c1 dispatcher BlockEncoder failed");
    let mut code = enc.code_buffer;
    let expected = (ip - disp_base_va) as usize;
    assert_eq!(
        code.len(),
        expected,
        "reencrypt-c1 dispatcher length mismatch: measured {} vs encoded {}",
        expected,
        code.len()
    );
    let blob = crate::crypto::native::emit_btg_crypt_blob(c1_state_va, c1_sbox_va);
    code.extend_from_slice(&blob);
    code
}
