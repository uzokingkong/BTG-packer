use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};

// ==============================================================================
// v8 (Phase 0.3) — 디스패처 연동 "실행 후 재암호화" 디스패처
// ==============================================================================
// 로드맵 §0.3 (T3 덤프 저항)의 킬러 기능:
//   모든 블록이 디스패처를 경유하는 구조를 역이용해, 블록을 **개별 RC4 암호화**
//   상태로 파일에 보관한다. 디스패처는 매 디스패치마다
//     1) 방금 실행한 블록(current)을 즉시 **재암호화**하고
//     2) 다음으로 갈 블록(target)을 **복호화**한 뒤
//     3) 기존 MBA 점프 테이블 경유로 target에 점프한다.
//   결과: 어느 순간에도 **실행 중인 블록 1개만 평문**이다. 실행 중간에 덤프하면
//   거의 전부 암호문 → 덤프 기반 원본 재구성(T3)이 구조적으로 불가능해진다.
// ── 스택 규약 (모든 진입 경로: 블록 스텁 / OEP 스텁 / 부트 스텁) ─────────────
// ```text
// [rsp+0x10] = current_block_id   (방금 실행을 마친 블록. 첫 디스패치 = 0xFFFFFFFF)
// [rsp+0x08] = target_block_id    (다음에 실행할 블록)
// [rsp+0x00] = seed               (target 블록의 MBA 시드)
// ```
// current_id는 스택으로 전달되므로 **전역 상태가 없다** — 멀티스레드 디스패치도
// 안전하다. 첫 디스패치(current=0xFFFFFFFF)는 재암호화를 건너뛴다.
// ── 블록 키 스케줄 (패커와 동일) ──────────────────────────────────────────────
//   seed   = seed_for(C, id)  = (C + id*0x9E3779B9) rol 13 ^ C ror 7
//                                ^ (id rol 5 * 0x85EBCA6B)
//   key(id) = compute_key(seed, id, C, 2) = ((seed^id) + 2*(seed&id)) ^ C
//           ≡ (seed + id) ^ C   (mod 2^32, XOR/AND 항등식)
//   → 재암호화(current)는 seed_for를 어셈블리로 재계산하고,
//     복호화(target)는 스택의 seed를 그대로 쓴다 (둘 다 (seed+id)^C).
//   블록 길이 테이블도 같은 key로 암호화되어 디스패처가 in-place 복호화한다.
// ── RC4: key4 4바이트 → key256(key4 64회 반복) → KSA → PRGA ───────────────────
//   워크스페이스: sub rsp,0x280
//     [rsp+0x000..0x0FF] S-box          (rbx = rsp)
//     [rsp+0x100..0x103] key4
//     [rsp+0x180..0x27F] key256
// ── 레지스터 보존 ─────────────────────────────────────────────────────────────
//   모든 GPR(rax/rcx/rdx/rbx/rsi/rdi/r8..r15) + EFLAGS를 push/pop으로 보존.
//   (0xC0000005 RDX 클로버 교훈: 어떤 스크래치도 인자 레지스터를 조용히 덮으면 안 됨)
pub fn build_dispatcher_reencrypt(
    dispatcher_va: u64,
    table_offset: usize,
    num_blocks: usize,
    mba_constant: u32,
    trace: bool,
) -> Vec<u8> {
    use std::collections::HashMap;

    // v14: GOLDEN/KEY_MUL 상수는 재암호화 제거로 더 이상
    // 사용되지 않음 (unused warning 방지를 위해 제거)
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

    // ── 0. Trace mode: INT3 삽입 (디버거가 매 디스패치마다 정지) ──────────────────
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
    // 스택 (진입: [rsp+0x00]=seed [0x08]=target [0x10]=current):
    //   [rsp+0x00]=r15 [0x08]=r14 [0x10]=r13 [0x18]=r12 [0x20]=r11 [0x28]=r10
    //   [0x30]=r9 [0x38]=r8 [0x40]=rdi [0x48]=rsi [0x50]=rbx [0x58]=rdx
    //   [0x60]=rcx [0x68]=rax [0x70]=eflags [0x78]=seed [0x80]=target [0x88]=current

    // ── 2. 인자 로드 + 범위 검사 ────────────────────────────────────────────────
    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::R10, mem(Register::RSP, 0x80)).unwrap(),
        None,
    ); // target id
    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::R11, mem(Register::RSP, 0x78)).unwrap(),
        None,
    ); // seed
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::R12D, mem(Register::RSP, 0x88)).unwrap(),
        None,
    ); // current id
    push_seq(
        Instruction::with2(Code::Cmp_rm64_imm32, Register::R10, num_blocks as i32).unwrap(),
        None,
    );
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0).unwrap(), None);
    push_seq(
        Instruction::with2(Code::Cmovae_r64_rm64, Register::R10, Register::RCX).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::R12D, num_blocks as i32).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0xFFFF_FFFFu32).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Cmovae_r32_rm32, Register::R12D, Register::ECX).unwrap(),
        None,
    );

    // ── 3. RC4 워크스페이스 ────────────────────────────────────────────────────
    push_seq(
        Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, WORKSPACE).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP).unwrap(),
        None,
    ); // S-box base

    // ── 5. 타깃 블록 복호화 ────────────────────────────────────────────────────
    push_seq(
        Instruction::with2(
            Code::Lea_r32_m,
            Register::EAX,
            mem_idx(Register::R10, Register::R11, 1),
        )
        .unwrap(),
        Some(L::DecTarget),
    ); // eax = seed + target (mod 2^32)
    push_seq(
        Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant).unwrap(),
        None,
    ); // ^ C
    push_seq(
        Instruction::with2(Code::Mov_rm32_r32, mem(Register::RSP, 0x100), Register::EAX).unwrap(),
        None,
    ); // key4 = (seed + target) ^ C
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::R13D, Register::R10D).unwrap(),
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
        Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va)).unwrap(),
        None,
    ); // rsi = length table base (block state)
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem_idx(Register::RSI, Register::R13, 4)).unwrap(),
        Some(L::ClaimSpin),
    ); // eax = entry
    push_seq(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 0xFFFF_FFFEu32).unwrap(),
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(L::ClaimSpin),
    ); // decrypting -> spin
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::EDX, Register::EAX).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EDX, mem(Register::RSP, 0x100)).unwrap(),
        None,
    ); // edx = entry ^ key4 = len
    push_seq(
        Instruction::with2(Code::Test_rm32_r32, Register::EDX, Register::EDX).unwrap(),
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(L::AfterDecrypt),
    ); // len==0 -> plaintext/already-decrypted -> skip crypt
    push_seq(
        Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 0xFFFF_FFFEu32).unwrap(),
        None,
    );
    let mut cas = Instruction::with2(
        Code::Cmpxchg_rm32_r32,
        mem_idx(Register::RSI, Register::R13, 4),
        Register::R8D,
    )
    .unwrap();
    cas.set_has_lock_prefix(true);
    push_seq(cas, None); // lock cmpxchg [rsi+r13*4], r8d ; expected = eax (entry)
    push_seq(
        Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
        Some(L::ClaimSpin),
    ); // claim lost -> retry
    // claim won: eax = original entry, edx = len -> RC4 decrypt
    push_seq(
        Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(),
        Some(L::BlockCrypt),
    );
    // mark decrypted: entry = key4 (rsi was clobbered by BlockCrypt -> reload)
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RSI, rip_va(length_table_va)).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem(Register::RSP, 0x100)).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_rm32_r32, mem_idx(Register::RSI, Register::R13, 4), Register::EAX).unwrap(),
        None,
    );

    // ── 6. 워크스페이스 해제 ────────────────────────────────────────────────────
    push_seq(
        Instruction::with2(Code::Add_rm64_imm32, Register::RSP, WORKSPACE).unwrap(),
        Some(L::AfterDecrypt),
    );

    // ── 7. 기존 MBA 점프 테이블 디스패치 ───────────────────────────────────────
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va)).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::ECX,
            mem_idx(Register::RAX, Register::R10, 4),
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Lea_r32_m,
            Register::EAX,
            mem_idx(Register::R10, Register::R11, 1),
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX).unwrap(),
        None,
    ); // 복호화된 오프셋
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va)).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(),
        None,
    ); // target VA
    push_seq(
        Instruction::with2(Code::Mov_rm64_r64, mem(Register::RSP, 0x88), Register::RAX).unwrap(),
        None,
    ); // target VA → current 슬롯 (ret가 이걸 pop)

    // ── 8. 복원 + 점프 ──────────────────────────────────────────────────────────
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
        push_seq(Instruction::with1(Code::Pop_r64, r).unwrap(), None);
    }
    push_seq(Instruction::with(Code::Popfq), None);
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RSP, mem(Register::RSP, 0x10)).unwrap(),
        None,
    ); // seed + target 슬롯 제거 (EFLAGS 비파괴)
    push_seq(Instruction::with(Code::Retnq), None);

    // ── block_crypt: r13d=block_id, key4@[rsp+0x100], sbox@rbx ────────────────
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, mem(Register::RSP, 0x108)).unwrap(),
        Some(L::BlockCrypt),
    );

    // v14: len is passed in edx by the caller (length table doubles as state marker).
    // FIX(2026-08-07): the guard must run BEFORE the ExpandLoop below, because
    // `mov edx, 64` + the fill loop leave edx == 0 here -> KSA/PRGA were dead code
    // and every encrypted block executed as ciphertext (0xC0000005 @ block 8806).
    push_seq(
        Instruction::with2(Code::Test_rm32_r32, Register::EDX, Register::EDX).unwrap(),
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(L::BlockCryptDone),
    );
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RCX, mem(Register::RSP, 0x180)).unwrap(),
        None,
    );
    push_seq(Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 64).unwrap(), None);
    // key256 = key4 64회 반복 (패커 Rc4::new(&key4)의 key[i%4]와 동일)
    push_seq(
        Instruction::with2(Code::Mov_rm32_r32, mem(Register::RCX, 0), Register::EAX).unwrap(),
        Some(L::ExpandLoop),
    );
    push_seq(
        Instruction::with2(Code::Add_rm64_imm32, Register::RCX, 4).unwrap(),
        None,
    );
    push_seq(Instruction::with1(Code::Dec_rm32, Register::R8D).unwrap(), None);
    push_seq(
        Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
        Some(L::ExpandLoop),
    );
    // off = table_enc[r13] ^ key
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(target_table_va)).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::ECX,
            mem_idx(Register::RAX, Register::R13, 4),
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::ECX, mem(Register::RSP, 0x108)).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RAX, rip_va(section_base_va)).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap(),
        None,
    ); // block base
    // KSA(key256, sbox)
    push_seq(
        Instruction::with2(Code::Lea_r64_m, Register::RCX, mem(Register::RSP, 0x180)).unwrap(),
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(),
        Some(L::Ksa),
    );
    // PRGA(block_base, len) — i/j = 0
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R14).unwrap(),
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(),
        Some(L::Prga),
    );
    push_seq(Instruction::with(Code::Retnq), Some(L::BlockCryptDone));

    // ── KSA: rcx=key256(256B), rbx=sbox ────────────────────────────────────────
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(),
        Some(L::Ksa),
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm8_r8,
            mem_idx(Register::RBX, Register::RSI, 1),
            Register::SIL,
        )
        .unwrap(),
        Some(L::KsaInit),
    ); // S[i] = i
    push_seq(Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), None);
    push_seq(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100).unwrap(),
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(),
        Some(L::KsaInit),
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            mem_idx(Register::RBX, Register::RSI, 1),
        )
        .unwrap(),
        Some(L::KsaLoop),
    );
    push_seq(
        Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            mem_idx(Register::RCX, Register::RSI, 1),
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            mem_idx(Register::RBX, Register::RSI, 1),
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R8D,
            mem_idx(Register::RBX, Register::RDI, 1),
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm8_r8,
            mem_idx(Register::RBX, Register::RDI, 1),
            Register::AL,
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm8_r8,
            mem_idx(Register::RBX, Register::RSI, 1),
            Register::R8L,
        )
        .unwrap(),
        None,
    );
    push_seq(Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), None);
    push_seq(
        Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100).unwrap(),
        None,
    );
    push_seq(
        Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(),
        Some(L::KsaLoop),
    );
    push_seq(Instruction::with(Code::Retnq), None);

    // ── PRGA: rcx=buf, rdx=len, rbx=sbox, esi/edi=0 ─────────────────────────────
    push_seq(
        Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(),
        Some(L::Prga),
    );
    push_seq(
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(L::PrgaDone),
    );
    push_seq(Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), Some(L::PrgaLoop));
    push_seq(
        Instruction::with2(Code::And_rm32_imm32, Register::ESI, 0xFF).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            mem_idx(Register::RBX, Register::RSI, 1),
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R8D,
            mem_idx(Register::RBX, Register::RSI, 1),
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R9D,
            mem_idx(Register::RBX, Register::RDI, 1),
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm8_r8,
            mem_idx(Register::RBX, Register::RDI, 1),
            Register::R8L,
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Mov_rm8_r8,
            mem_idx(Register::RBX, Register::RSI, 1),
            Register::R9L,
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R8D).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::R9D).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0xFF).unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            mem_idx(Register::RBX, Register::RAX, 1),
        )
        .unwrap(),
        None,
    );
    push_seq(
        Instruction::with2(Code::Xor_rm8_r8, mem(Register::RCX, 0), Register::AL).unwrap(),
        None,
    );
    push_seq(Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(), None);
    push_seq(Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(), None);
    push_seq(
        Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(),
        Some(L::Prga),
    ); // 다시 test로
    push_seq(Instruction::with(Code::Retnq), Some(L::PrgaDone));

    // ── 인코딩 (부트 스텁과 동일한 measure → label resolve → batch encode) ──────
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
            // 분기 명령어는 타깃 정의가 아니라 참조이므로 label_ips를 덮어쓰지 않는다.
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
    let enc = BlockEncoder::encode(64, block, enc_opts).expect("reencrypt dispatcher BlockEncoder failed");
    let code = enc.code_buffer;
    let expected = (ip - disp_base_va) as usize;
    assert_eq!(
        code.len(),
        expected,
        "reencrypt dispatcher length mismatch: measured {} vs encoded {}",
        expected,
        code.len()
    );
    code
}
