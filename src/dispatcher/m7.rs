use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};

// ==============================================================================
// v61 (--m7) — on-demand 블록 복호화 + 실행 후 재암호화 디스패처 (anti-dump)
// ==============================================================================
// M7은 `--dispatcher-reencrypt`(v8/v14)의 "실행 후 재암호화"를 **멀티스레드/재진입
// 안전하게** 복원한다. v14는 "복호화 → 실행 → 평문 유지"로 회귀했는데(동시 실행
// 컨텍스트가 in-place RC4 이중 암호화로 0xC0000005), M7은 블록별 **refcount**와
// 원자적 상태 전이로 다음을 보장한다:
//
//   - 복호화: 첫 진입 컨텍스트만 claim(0xFFFFFFFE) 후 RC4 복호화.
//   - 실행: 블록은 항상 평문 상태로만 실행된다.
//   - 재암호화: 마지막으로 떠나는 컨텍스트가 refcount 0을 claim한 뒤 RC4 재암호화.
//     refcount>0인 동안(다른 컨텍스트가 실행 중)에는 절대 재암호화하지 않는다.
//
// 결과: 어느 순간에도 "실행 중인 블록만 평문" — 실행 중 덤프는 대부분 암호문.
// ── 스택 규약 (reencrypt와 동일 — 블록 스텁/OEP/부트 스텁 공통) ──────────────
// [rsp+0x10] = current_block_id   (첫 디스패치 = 0xFFFFFFFF 센티널)
// [rsp+0x08] = target_block_id
// [rsp+0x00] = seed               (target MBA 시드)
// ── 테이블 레이아웃 (3개) ─────────────────────────────────────────────────────
// [table_offset]          jump table  (num_blocks×4, phys_off ^ key)
// [table_offset +  N*4]   length table (num_blocks×4, len ^ key — 읽기 전용)
// [table_offset + 2N*4]   state table  (num_blocks×4, M7 상태/refcount)
// [first_block_offset]    blocks
// ── 상태 테이블 인코딩 ────────────────────────────────────────────────────────
//   0xFFFFFFFE = claim (복호화/재암호화 진행 중 — 다른 컨텍스트는 spin)
//   0xFFFFFFFF = 암호화 (복호화 필요)
//   k (0..)    = 복호화 + k개 컨텍스트 실행 중 (refcount)
//   call-target(평문) 블록: length entry = key → decoded len 0 → 상태 머신 스킵
// ── 블록 키 (reencrypt와 동일) ────────────────────────────────────────────────
//   key(id) = ((seed_for(C,id) + id) ^ C); target의 seed는 push된 값을,
//   current의 seed는 seed_for를 어셈블리로 재계산한다.
// ==============================================================================
pub fn build_dispatcher_m7(
    dispatcher_va: u64,
    table_offset: usize,
    num_blocks: usize,
    mba_constant: u32,
    trace: bool,
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

    // ── 1. 모든 GPR + EFLAGS 저장 (15푸시) ───────────────────────────────────────
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
        push_seq(Instruction::with1(Code::Push_r64, r).unwrap(), None);
    }
    // [rsp+0x00]=r15 [0x08]=r14 [0x10]=r13 [0x18]=r12 [0x20]=r11 [0x28]=r10
    // [0x30]=r9 [0x38]=r8 [0x40]=rdi [0x48]=rsi [0x50]=rbx [0x58]=rdx
    // [0x60]=rcx [0x68]=rax [0x70]=eflags [0x78]=seed [0x80]=target [0x88]=current

    // ── 2. 인자 로드 + 범위 검사 ────────────────────────────────────────────────
    push_seq(Instruction::with2(Code::Mov_r64_rm64, Register::R10, mem(Register::RSP, 0x80)).unwrap(), None); // target
    push_seq(Instruction::with2(Code::Mov_r64_rm64, Register::R11, mem(Register::RSP, 0x78)).unwrap(), None); // seed
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::R12D, mem(Register::RSP, 0x88)).unwrap(), None); // current
    push_seq(Instruction::with2(Code::Cmp_rm64_imm32, Register::R10, num_blocks as i32).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0).unwrap(), None);
    push_seq(Instruction::with2(Code::Cmovae_r64_rm64, Register::R10, Register::RCX).unwrap(), None);
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, num_blocks as i32).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0xFFFF_FFFFu32).unwrap(), None);
    push_seq(Instruction::with2(Code::Cmovae_r32_rm32, Register::R12D, Register::ECX).unwrap(), None);

    // ── 3. RC4 워크스페이스 ────────────────────────────────────────────────────
    push_seq(Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, WORKSPACE).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP).unwrap(), None); // sbox base

    // ── 4. 테이블 베이스 + target key4 ──────────────────────────────────────────
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va)).unwrap(), None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va)).unwrap(), None);
    push_seq(Instruction::with2(Code::Lea_r32_m, Register::EAX, mem_idx(Register::R10, Register::R11, 1)).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX).unwrap(), None);

    // ── 5. ENTER target: plaintext 확인 → claim/refcount 상태 머신 ─────────────
    // decoded_len = length[target] ^ key4_target ; 0이면 call-target(평문) → 스킵
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R10, 4)).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100)).unwrap(), None);
    push_seq(Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap(), None);
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::EnterReady)); // plaintext → exit 단계
    // EnterLoop: st = state[target]
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RDI, Register::R10, 4)).unwrap(), Some(L::EnterLoop));
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, CLAIM).unwrap(), None);
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::EnterLoop)); // claiming → spin
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, ENC).unwrap(), None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::EnterDecrypted));
    // ENC → claim (cmpxchg [state+target*4]: ENC -> CLAIM)
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, ENC).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, CLAIM).unwrap(), None);
    let mut cas = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R10, 4), Register::R8D).unwrap();
    cas.set_has_lock_prefix(true);
    push_seq(cas, None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::EnterLoop)); // lost → spin
    // claim won → decrypt target (r13=id, edx=len, key4@[rsp+0x100])
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R10D).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R13, 4)).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100)).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(), None); // len
    push_seq(Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(L::BlockCrypt));
    // rsi/rdi는 BlockCrypt가 클로버 → 재로드
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va)).unwrap(), None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va)).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_rm32_imm32, mem_idx(Register::RDI, Register::R10, 4), 1).unwrap(), None); // refcount=1
    push_seq(Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(L::EnterReady));
    // EnterDecrypted: st == 0(dec, 0 exec) → cmpxchg(0->1) [재암호화 claim과 경합]
    push_seq(Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX).unwrap(), Some(L::EnterDecrypted));
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::EnterInc));
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap(), None); // expected 0
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 1).unwrap(), None);
    let mut cas2 = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R10, 4), Register::R8D).unwrap();
    cas2.set_has_lock_prefix(true);
    push_seq(cas2, None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::EnterLoop));
    push_seq(Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(L::EnterReady));
    // EnterInc: refcount++ (원자적 lock inc)
    let mut inc_inst = Instruction::with1(Code::Inc_rm32, mem_idx(Register::RDI, Register::R10, 4)).unwrap();
    inc_inst.set_has_lock_prefix(true);
    push_seq(inc_inst, Some(L::EnterInc));
    push_seq(Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(L::EnterReady));

    // ── 6. EXIT current: refcount 감소 + 마지막 컨텍스트 재암호화 ────────────────
    // (EnterReady = EXIT 코드 시작 — 모든 ENTER 경로가 여기로 와서 실행한 뒤
    //  워크스페이스 해제/디스패치로 진행한다)
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, 0xFFFF_FFFFu32).unwrap(), Some(L::EnterReady));
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::ExitDone)); // sentinel
    // key4_current = (seed_for(C, current) + current) ^ C
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, mba_constant).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R12D).unwrap(), None);
    push_seq(Instruction::with3(Code::Imul_r32_rm32_imm32, Register::ECX, Register::ECX, 0x9E37_79B9u32 as i32).unwrap(), None);
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::ECX).unwrap(), None);
    push_seq(Instruction::with2(Code::Rol_rm32_imm8, Register::EAX, 13).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::EDX, mba_constant).unwrap(), None);
    push_seq(Instruction::with2(Code::Ror_rm32_imm8, Register::EDX, 7).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::EDX).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R12D).unwrap(), None);
    push_seq(Instruction::with2(Code::Rol_rm32_imm8, Register::ECX, 5).unwrap(), None);
    push_seq(Instruction::with3(Code::Imul_r32_rm32_imm32, Register::ECX, Register::ECX, 0x85EB_CA6Bu32 as i32).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::ECX).unwrap(), None); // seed_for
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::R12D).unwrap(), None); // + current
    push_seq(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant).unwrap(), None); // ^ C → key4_current
    push_seq(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX).unwrap(), None);
    // plaintext(current) 확인: length[current] ^ key4_current == 0 → skip
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R12, 4)).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100)).unwrap(), None);
    push_seq(Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap(), None);
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::ExitDone)); // call-target
    // lock dec [state+current*4] ; ZF=1 if result==0
    let mut dec_inst = Instruction::with1(Code::Dec_rm32, mem_idx(Register::RDI, Register::R12, 4)).unwrap();
    dec_inst.set_has_lock_prefix(true);
    push_seq(dec_inst, None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::ExitDone)); // refcount>0 → leave decrypted
    // refcount==0 → claim(0 -> CLAIM) — 진입과 경합
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, CLAIM).unwrap(), None);
    let mut cas3 = Instruction::with2(Code::Cmpxchg_rm32_r32, mem_idx(Register::RDI, Register::R12, 4), Register::R8D).unwrap();
    cas3.set_has_lock_prefix(true);
    push_seq(cas3, None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::ExitDone)); // someone re-entered → skip
    // claim won → 재암호화 (key4@[rsp+0x100], len, r13=current)
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R12D).unwrap(), Some(L::Reencrypt));
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R13, 4)).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, mem(Register::RSP, 0x100)).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(), None); // len
    push_seq(Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(L::BlockCrypt));
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RDI, rip_va(state_table_va)).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_rm32_imm32, mem_idx(Register::RDI, Register::R12, 4), ENC).unwrap(), None); // → encrypted
    push_seq(Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(L::ExitDone));

    // ── 7. 워크스페이스 해제 + 점프 테이블 디스패치 (reencrypt와 동일) ─────────
    push_seq(Instruction::with2(Code::Add_rm64_imm32, Register::RSP, WORKSPACE).unwrap(), Some(L::ExitDone));
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va)).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RAX, Register::R10, 4)).unwrap(), None);
    push_seq(Instruction::with2(Code::Lea_r32_m, Register::EAX, mem_idx(Register::R10, Register::R11, 1)).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX).unwrap(), None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va)).unwrap(), None);
    push_seq(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_rm64_r64, mem(Register::RSP, 0x88), Register::RAX).unwrap(), None); // target VA → current slot

    // ── 8. 복원 + 점프 ──────────────────────────────────────────────────────────
    for r in [
        Register::R15, Register::R14, Register::R13, Register::R12, Register::R11, Register::R10,
        Register::R9, Register::R8, Register::RDI, Register::RSI, Register::RBX, Register::RDX,
        Register::RCX, Register::RAX,
    ] {
        push_seq(Instruction::with1(Code::Pop_r64, r).unwrap(), None);
    }
    push_seq(Instruction::with(Code::Popfq), None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RSP, mem(Register::RSP, 0x10)).unwrap(), None);
    push_seq(Instruction::with(Code::Retnq), None);

    // ── block_crypt: r13d=block_id, key4@[rsp+0x100], len=edx, sbox@rbx ────────
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem(Register::RSP, 0x108)).unwrap(), Some(L::BlockCrypt));
    push_seq(Instruction::with2(Code::Test_rm32_r32, Register::EDX, Register::EDX).unwrap(), None);
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::BlockCryptDone));
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RCX, mem(Register::RSP, 0x180)).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 64).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_rm32_r32, mem(Register::RCX, 0), Register::EAX).unwrap(), Some(L::ExpandLoop));
    push_seq(Instruction::with2(Code::Add_rm64_imm32, Register::RCX, 4).unwrap(), None);
    push_seq(Instruction::with1(Code::Dec_rm32, Register::R8D).unwrap(), None);
    push_seq(Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(L::ExpandLoop));
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va)).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, mem_idx(Register::RAX, Register::R13, 4)).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::ECX, mem(Register::RSP, 0x108)).unwrap(), None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va)).unwrap(), None);
    push_seq(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap(), None);
    push_seq(Instruction::with2(Code::Lea_r64_m, Register::RCX, mem(Register::RSP, 0x180)).unwrap(), None);
    push_seq(Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(L::Ksa));
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R14).unwrap(), None);
    push_seq(Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(L::Prga));
    push_seq(Instruction::with(Code::Retnq), Some(L::BlockCryptDone));

    // ── KSA / PRGA (reencrypt와 동일) ──────────────────────────────────────────
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), Some(L::Ksa));
    push_seq(Instruction::with2(Code::Mov_rm8_r8, mem_idx(Register::RBX, Register::RSI, 1), Register::SIL).unwrap(), Some(L::KsaInit));
    push_seq(Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), None);
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100).unwrap(), None);
    push_seq(Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(L::KsaInit));
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, mem_idx(Register::RBX, Register::RSI, 1)).unwrap(), Some(L::KsaLoop));
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(), None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, mem_idx(Register::RCX, Register::RSI, 1)).unwrap(), None);
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(), None);
    push_seq(Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF).unwrap(), None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, mem_idx(Register::RBX, Register::RSI, 1)).unwrap(), None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::R8D, mem_idx(Register::RBX, Register::RDI, 1)).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_rm8_r8, mem_idx(Register::RBX, Register::RDI, 1), Register::AL).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_rm8_r8, mem_idx(Register::RBX, Register::RSI, 1), Register::R8L).unwrap(), None);
    push_seq(Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), None);
    push_seq(Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100).unwrap(), None);
    push_seq(Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(L::KsaLoop));
    push_seq(Instruction::with(Code::Retnq), None);

    push_seq(Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(), Some(L::Prga));
    push_seq(Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(L::PrgaDone));
    push_seq(Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), Some(L::PrgaLoop));
    push_seq(Instruction::with2(Code::And_rm32_imm32, Register::ESI, 0xFF).unwrap(), None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, mem_idx(Register::RBX, Register::RSI, 1)).unwrap(), None);
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(), None);
    push_seq(Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF).unwrap(), None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::R8D, mem_idx(Register::RBX, Register::RSI, 1)).unwrap(), None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, mem_idx(Register::RBX, Register::RDI, 1)).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_rm8_r8, mem_idx(Register::RBX, Register::RDI, 1), Register::R8L).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_rm8_r8, mem_idx(Register::RBX, Register::RSI, 1), Register::R9L).unwrap(), None);
    push_seq(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R8D).unwrap(), None);
    push_seq(Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::R9D).unwrap(), None);
    push_seq(Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0xFF).unwrap(), None);
    push_seq(Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, mem_idx(Register::RBX, Register::RAX, 1)).unwrap(), None);
    push_seq(Instruction::with2(Code::Xor_rm8_r8, mem(Register::RCX, 0), Register::AL).unwrap(), None);
    push_seq(Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(), None);
    push_seq(Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(), None);
    push_seq(Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(L::Prga));
    push_seq(Instruction::with(Code::Retnq), Some(L::PrgaDone));

    // ── 인코딩 (measure → label resolve → batch encode) ─────────────────────────
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
    code
}
