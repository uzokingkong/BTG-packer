// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Dispatcher Shellcode Generator
// ==============================================================================

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction,
    InstructionBlock, MemoryOperand, Register,
};

pub mod antidebug;

// ── v13.4d diag: dispatcher ring-buffer 상수 ───────────────────────────────────
/// 기록할 마지막 logical block id 개수 (종료/패닉 직전 어느 블록들로 디스패치됐는지).
pub const RING_ENTRIES: usize = 32;
/// .btg 섹션에서 ring 영역을 위해 테이블 앞에 예약하는 바이트 수 (entries + index).
pub const RING_REGION: usize = 0x100;
/// ring 영역 내 next-index u32의 오프셋 (entries 뒤).
pub const RING_INDEX_OFF: usize = RING_ENTRIES * 4;
/// 예약 영역 내에서 ring 메타(index) 시작 위치를 보고할 때 사용하는 상수.
pub const RING_META_OFF: usize = 0x80;

/// dispatcher_va 및 table_offset 기반으로 PIC 디스패처 셸코드를 동적으로 생성한다.
///
/// # 스택 레이아웃 (디스패처 진입 직전)
/// OEP Stub(또는 각 블록 종단)에서 push한 값들:
/// ```text
/// [rsp + 0x08] = target_block_id
/// [rsp + 0x00] = seed        ← v6: MBA 시드 (디스패처가 키를 재도출)
/// ```
///
/// 디스패처 내부에서 5개 레지스터/플래그를 추가 push한 뒤:
/// ```text
/// [rsp+0x00] = R11
/// [rsp+0x08] = R10
/// [rsp+0x10] = RCX
/// [rsp+0x18] = RAX
/// [rsp+0x20] = EFLAGS
/// [rsp+0x28] = seed          ← v6: MBA 시드
/// [rsp+0x30] = block_id      ← 테이블 인덱스 (→ 복호화 후 target VA로 덮어씀)
/// ```
///
/// # FIX (0xC0000005 h3_noad 크래시 근본 원인)
/// 기존 코드는 MBA 키 재도출에서 `edx`를 스크래치로 썼지만
/// (`mov edx,r10d; and edx,r11d; lea eax,[rax+rdx*2]`), RDX는 **인자
/// 레지스터**라 push/pop 복원 목록(rax/rcx/r10/r11/flags)에 없어 **모든
/// 디스패치가 RDX를 `(block_id & seed)`로 덮어썼다**. 함수 진입이 디스패처
/// 경유일 때 2번째 인자(RDX)가 파괴되어, 경로→UTF-16 변환 인코더가 쓰레기
/// 포인터를 받고 `core::str::next_code_point`에서 0xc0000005로 크래시했다.
/// → XOR/AND 항등식 `(x^y)+2*(x&y) == x+y`로 단일 `lea eax,[r10+r11]` 대체 —
///   RDX를 아예 사용하지 않아 클로버가 원천적으로 없다. (패커 compute_key와 동일 값)
///
/// v6: 키는 실행 시점에 MBA 항등식으로 재도출된다 —
/// `key = ((seed ^ block_id) + 2*(seed & block_id)) ^ mba_constant` (레벨 2).
/// 패커(패스3)가 동일 식으로 테이블 엔트리를 암호화하므로 상수 키가 파일에
/// 노출되지 않고, 시드만 push된다.
pub fn build_dispatcher(
    dispatcher_va: u64,
    table_offset: usize,
    num_blocks: usize,
    anti_debug_trace: bool,
    mba_constant: u32,
    block_ring: bool,
    ring_va: u64,
) -> Vec<u8> {
    // 디스패처 셸코드는 .btg 섹션 오프셋 0x20에 위치
    let disp_base_va = dispatcher_va + 0x20;
    let target_table_va = dispatcher_va + table_offset as u64;
    let section_base_va = dispatcher_va;

    let mut instructions = Vec::new();

    if anti_debug_trace {
        // Trace Mode: INT3 삽입으로 디버거가 매 블록 디스패치마다 정지
        instructions.push(Instruction::with(Code::Int3));
    }

    // 1. pushfq
    instructions.push(Instruction::with(Code::Pushfq));

    // 2. push rax
    if let Ok(inst) = Instruction::with1(Code::Push_r64, Register::RAX) {
        instructions.push(inst);
    }

    // 3. push rcx
    if let Ok(inst) = Instruction::with1(Code::Push_r64, Register::RCX) {
        instructions.push(inst);
    }

    // 4. push r10
    if let Ok(inst) = Instruction::with1(Code::Push_r64, Register::R10) {
        instructions.push(inst);
    }

    // 5. push r11
    if let Ok(inst) = Instruction::with1(Code::Push_r64, Register::R11) {
        instructions.push(inst);
    }

    // 6. mov r10, [rsp+0x30]  (target_block_id)
    let op_b = MemoryOperand::with_base_displ(Register::RSP, 0x30);
    if let Ok(inst) = Instruction::with2(Code::Mov_r64_rm64, Register::R10, op_b) {
        instructions.push(inst);
    }

    // Bound Check: if R10 >= num_blocks → reset to 0 (OOB 방지)
    let num_blocks_i32 = num_blocks as i32;
    if let Ok(inst) = Instruction::with2(Code::Cmp_rm64_imm32, Register::R10, num_blocks_i32) {
        instructions.push(inst);
    }
    if let Ok(inst) = Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0) {
        instructions.push(inst);
    }
    if let Ok(inst) = Instruction::with2(Code::Cmovae_r64_rm64, Register::R10, Register::RCX) {
        instructions.push(inst);
    }

    // ── v13.4d diag: dispatcher ring-buffer (마지막 RING_ENTRIES 개 dispatched
    //    logical block id 기록). 종료 시점 once.rs:166 패닉이 .pdata/exit-unwind
    //    경로의 어느 블록으로 dispatcher가 되돌아가는지 좁히는 데 쓴다.
    //    영역: .btg 섹션 내 [table_offset - RING_REGION .. table_offset) (패딩).
    //    레이아웃: [0..RING_ENTRIES*4)=u32 entries, [RING_ENTRIES*4..+4)=next index.
    //    스크래치: r11(이후 step7이 seed로 덮음) + eax(이후 step10이 id로 덮음) — 안전.
    if block_ring {
        if let Ok(inst) = Instruction::with2(Code::Mov_r64_imm64, Register::R11, ring_va as i64) {
            instructions.push(inst); // r11 = ring base
        }
        if let Ok(inst) = Instruction::with2(
            Code::Mov_r32_rm32,
            Register::EAX,
            MemoryOperand::with_base_displ(Register::R11, RING_ENTRIES as i64 * 4),
        ) {
            instructions.push(inst); // eax = next index
        }
        if let Ok(inst) = Instruction::with2(
            Code::Mov_rm32_r32,
            MemoryOperand::with_base_index_scale(Register::R11, Register::RAX, 4),
            Register::R10D,
        ) {
            instructions.push(inst); // ring[index] = target block id
        }
        if let Ok(inst) = Instruction::with2(Code::Add_rm32_imm32, Register::EAX, 1) {
            instructions.push(inst);
        }
        if let Ok(inst) = Instruction::with2(Code::And_rm32_imm32, Register::EAX, (RING_ENTRIES - 1) as i32) {
            instructions.push(inst); // wrap
        }
        if let Ok(inst) = Instruction::with2(
            Code::Mov_rm32_r32,
            MemoryOperand::with_base_displ(Register::R11, RING_ENTRIES as i64 * 4),
            Register::EAX,
        ) {
            instructions.push(inst); // store next index
        }
    }

    // 7. mov r11, [rsp+0x28]  (seed — v6)
    let op_k = MemoryOperand::with_base_displ(Register::RSP, 0x28);
    if let Ok(inst) = Instruction::with2(Code::Mov_r64_rm64, Register::R11, op_k) {
        instructions.push(inst);
    }

    // 8. lea rax, [rip + disp_to_table]
    let op_table = MemoryOperand::with_base_displ(Register::RIP, target_table_va as i64);
    if let Ok(inst) = Instruction::with2(Code::Lea_r64_m, Register::RAX, op_table) {
        instructions.push(inst);
    }

    // 9. mov ecx, dword ptr [rax + r10*4]  (암호화된 테이블 엔트리)
    let op_entry = MemoryOperand::with_base_index_scale(Register::RAX, Register::R10, 4);
    if let Ok(inst) = Instruction::with2(Code::Mov_r32_rm32, Register::ECX, op_entry) {
        instructions.push(inst);
    }

    // 10. v6/v10: MBA 항등식으로 키 재도출 후 복호화
    //     key = ((seed ^ id) + 2*(seed & id)) ^ C   (r11=seed, r10=block_id)
    //     ≡ (seed + id) ^ C (mod 2^32) — XOR/AND 항등식
    //
    //     v10: 기존 단일 `lea eax,[r10+r11]`(평범한 덧셈)을 실제 XOR/AND
    //     항등식 4-명령 시퀀스로 교체 — 정적 분석 시 덧셈 패턴이 아니라
    //     (x^y)+2*(x&y) MBA 패턴으로 보인다. 값은 동일하므로 패커
    //     compute_key(level 2)와 여전히 일치한다. RDX는 끝까지 사용하지 않는다.
    //
    //     FIX (0xC0000005 h3_noad 크래시 근본 원인): 과거 구현은
    //     `mov edx,r10d; and edx,r11d; lea eax,[rax+rdx*2]`로 RDX를 스크래치로
    //     썼는데, RDX는 **인자 레지스터**라 push/pop 복원 목록(rax/rcx/r10/r11/
    //     flags)에 없어 **모든 디스패치가 RDX를 (block_id & seed)로 덮어썼다**.
    //     함수 진입이 디스패처 경유일 때 2번째 인자(RDX)가 파괴되어, 경로→UTF-16
    //     인코더가 쓰레기 포인터를 받고 next_code_point에서 0xc0000005 크래시.
    if let Ok(inst) = Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R10D) {
        instructions.push(inst); // eax = id
    }
    if let Ok(inst) = Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::R11D) {
        instructions.push(inst); // eax = id ^ seed
    }
    if let Ok(inst) = Instruction::with2(Code::And_rm32_r32, Register::R11D, Register::R10D) {
        instructions.push(inst); // r11 = seed & id  (r11은 스택에서 복원 — 클로버 OK)
    }
    if let Ok(inst) = Instruction::with2(
        Code::Lea_r32_m,
        Register::EAX,
        MemoryOperand::with_base_index_scale(Register::RAX, Register::R11, 2),
    ) {
        instructions.push(inst); // eax = (id^seed) + 2*(id&seed)
    }
    if let Ok(inst) = Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, mba_constant) {
        instructions.push(inst); // ^ C
    }
    if let Ok(inst) = Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::EAX) {
        instructions.push(inst); // 복호화된 오프셋 = entry ^ key
    }

    // 11. lea rax, [rip + disp_to_section_base]
    let op_sec = MemoryOperand::with_base_displ(Register::RIP, section_base_va as i64);
    if let Ok(inst) = Instruction::with2(Code::Lea_r64_m, Register::RAX, op_sec) {
        instructions.push(inst);
    }

    // 12. add rax, rcx  (rax = section_base + decrypted_offset = target block VA)
    if let Ok(inst) = Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX) {
        instructions.push(inst);
    }

    // 13. mov [rsp+0x30], rax  (block_id 슬롯을 target VA로 덮어씀)
    let op_target = MemoryOperand::with_base_displ(Register::RSP, 0x30);
    if let Ok(inst) = Instruction::with2(Code::Mov_rm64_r64, op_target, Register::RAX) {
        instructions.push(inst);
    }

    // 14-17. GPR 복원
    if let Ok(inst) = Instruction::with1(Code::Pop_r64, Register::R11) { instructions.push(inst); }
    if let Ok(inst) = Instruction::with1(Code::Pop_r64, Register::R10) { instructions.push(inst); }
    if let Ok(inst) = Instruction::with1(Code::Pop_r64, Register::RCX) { instructions.push(inst); }
    if let Ok(inst) = Instruction::with1(Code::Pop_r64, Register::RAX) { instructions.push(inst); }

    // 18. popfq  (저장된 EFLAGS 복원)
    instructions.push(Instruction::with(Code::Popfq));

    // 19. lea rsp, [rsp + 0x08]  (key 슬롯 버림 — LEA는 EFLAGS를 변경하지 않음!)
    let op_skip_key = MemoryOperand::with_base_displ(Register::RSP, 0x08);
    if let Ok(inst) = Instruction::with2(Code::Lea_r64_m, Register::RSP, op_skip_key) {
        instructions.push(inst);
    }

    // 20. ret  (스택 최상위 target VA → RIP)
    instructions.push(Instruction::with(Code::Retnq));

    let enc_block = InstructionBlock::new(&instructions, disp_base_va);
    if let Ok(encoded) = BlockEncoder::encode(64, enc_block, BlockEncoderOptions::NONE) {
        encoded.code_buffer
    } else {
        log::error!("[Dispatcher] iced BlockEncoder failed. Falling back to static bytes.");
        build_dispatcher_static(table_offset, num_blocks)
    }
}

/// 정적 fallback 디스패처 바이트열 (BlockEncoder 실패 시 사용).
fn build_dispatcher_static(table_offset: usize, num_blocks: usize) -> Vec<u8> {
    let table_displ = ((table_offset as i32) - 0x48).to_le_bytes();
    let num_blocks_le = (num_blocks as i32).to_le_bytes();

    vec![
        0x9C,                                                         // pushfq
        0x50,                                                         // push rax
        0x51,                                                         // push rcx
        0x41, 0x52,                                                   // push r10
        0x41, 0x53,                                                   // push r11
        0x4C, 0x8B, 0x54, 0x24, 0x30,                                // mov r10, [rsp+0x30]
        0x49, 0x81, 0xFA,                                             // cmp r10, imm32
            num_blocks_le[0], num_blocks_le[1], num_blocks_le[2], num_blocks_le[3],
        0xB9, 0x00, 0x00, 0x00, 0x00,                                 // mov ecx, 0
        0x4C, 0x0F, 0x43, 0xD1,                                       // cmovae r10, rcx
        0x4C, 0x8B, 0x5C, 0x24, 0x28,                                // mov r11, [rsp+0x28]
        0x48, 0x8D, 0x05, table_displ[0], table_displ[1],
            table_displ[2], table_displ[3],                           // lea rax, [rip+table_displ]
        0x42, 0x8B, 0x0C, 0x90,                                       // mov ecx, [rax+r10*4]
        0x44, 0x31, 0xD9,                                             // xor ecx, r11d
        0x48, 0x8D, 0x05, 0xAA, 0xFF, 0xFF, 0xFF,                    // lea rax, [rip-0x56]
        0x48, 0x01, 0xC8,                                             // add rax, rcx
        0x48, 0x89, 0x44, 0x24, 0x30,                                 // mov [rsp+0x30], rax
        0x41, 0x5B,                                                   // pop r11
        0x41, 0x5A,                                                   // pop r10
        0x59,                                                         // pop rcx
        0x58,                                                         // pop rax
        0x9D,                                                         // popfq
        0x48, 0x8D, 0x64, 0x24, 0x08,                                // lea rsp, [rsp+8]
        0xC3,                                                         // ret
    ]
}

/// 디스패처 바이트열의 유효성 검증.
pub fn validate_dispatcher(bytes: &[u8]) -> crate::error::Result<()> {
    if bytes.is_empty() {
        return Err(anyhow::anyhow!("Dispatcher bytes are empty.").into());
    }

    let mut decoder = Decoder::with_ip(64, bytes, 0x2000, DecoderOptions::NONE);
    let mut valid_insts = 0;
    let mut found_ret_or_jmp = false;

    while decoder.can_decode() {
        let inst = decoder.decode();
        if inst.is_invalid() {
            return Err(anyhow::anyhow!("Found invalid instruction during dispatcher validation.").into());
        }
        valid_insts += 1;
        if inst.code() == Code::Retnq || inst.code() == Code::Jmp_rm64 {
            found_ret_or_jmp = true;
        }
    }

    if valid_insts == 0 {
        return Err(anyhow::anyhow!("No valid instructions decoded in dispatcher.").into());
    }
    if !found_ret_or_jmp {
        return Err(anyhow::anyhow!("Dispatcher does not contain ret or jmp instruction!").into());
    }

    Ok(())
}

// ==============================================================================
// v8 (Phase 0.3) — 디스패처 연동 "실행 후 재암호화" 디스패처
// ==============================================================================
// 로드맵 §0.3 (T3 덤프 저항)의 킬러 기능:
//
//   모든 블록이 디스패처를 경유하는 구조를 역이용해, 블록을 **개별 RC4 암호화**
//   상태로 파일에 보관한다. 디스패처는 매 디스패치마다
//     1) 방금 실행한 블록(current)을 즉시 **재암호화**하고
//     2) 다음으로 갈 블록(target)을 **복호화**한 뒤
//     3) 기존 MBA 점프 테이블 경유로 target에 점프한다.
//   결과: 어느 순간에도 **실행 중인 블록 1개만 평문**이다. 실행 중간에 덤프하면
//   거의 전부 암호문 → 덤프 기반 원본 재구성(T3)이 구조적으로 불가능해진다.
//
// ── 스택 규약 (모든 진입 경로: 블록 스텁 / OEP 스텁 / 부트 스텁) ─────────────
// ```text
// [rsp+0x10] = current_block_id   (방금 실행을 마친 블록. 첫 디스패치 = 0xFFFFFFFF)
// [rsp+0x08] = target_block_id    (다음에 실행할 블록)
// [rsp+0x00] = seed               (target 블록의 MBA 시드)
// ```
// current_id는 스택으로 전달되므로 **전역 상태가 없다** — 멀티스레드 디스패치도
// 안전하다. 첫 디스패치(current=0xFFFFFFFF)는 재암호화를 건너뛴다.
//
// ── 블록 키 스케줄 (패커와 동일) ──────────────────────────────────────────────
//   seed   = seed_for(C, id)  = (C + id*0x9E3779B9) rol 13 ^ C ror 7
//                                ^ (id rol 5 * 0x85EBCA6B)
//   key(id) = compute_key(seed, id, C, 2) = ((seed^id) + 2*(seed&id)) ^ C
//           ≡ (seed + id) ^ C   (mod 2^32, XOR/AND 항등식)
//   → 재암호화(current)는 seed_for를 어셈블리로 재계산하고,
//     복호화(target)는 스택의 seed를 그대로 쓴다 (둘 다 (seed+id)^C).
//   블록 길이 테이블도 같은 key로 암호화되어 디스패처가 in-place 복호화한다.
//
// ── RC4: key4 4바이트 → key256(key4 64회 반복) → KSA → PRGA ───────────────────
//   워크스페이스: sub rsp,0x280
//     [rsp+0x000..0x0FF] S-box          (rbx = rsp)
//     [rsp+0x100..0x103] key4
//     [rsp+0x180..0x27F] key256
//
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reencrypt_dispatcher_builds_and_validates() {
        let code = build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false);
        assert!(!code.is_empty());
        assert!(validate_dispatcher(&code).is_ok());
        // 시작은 pushfq(0x9C), 마지막은 ret(0xC3)
        assert_eq!(code[0], 0x9C);
        assert_eq!(*code.last().unwrap(), 0xC3);
        // 재암호화 디스패처는 수백 바이트 — 할당된 테이블 영역 안에 들어가야 한다
        assert!(code.len() < 0x600 - 0x20, "dispatcher too large: {}", code.len());
    }

    #[test]
    fn test_reencrypt_dispatcher_size_va_independent() {
        let a = build_dispatcher_reencrypt(0x140001000, 0x200, 16, 0xCAFEBABE, false);
        let b = build_dispatcher_reencrypt(0x180000000, 0x999, 64, 0x12345678, false);
        let c = build_dispatcher_reencrypt(0x140001000, 0x200, 16, 0xCAFEBABE, false);
        assert_eq!(a.len(), b.len(), "length must be VA/table/constant independent");
        assert_eq!(a, c, "deterministic for same inputs");
    }

    #[test]
    fn test_reencrypt_dispatcher_rip_references_in_section() {
        // RIP-relative 참조가 모두 .btg 섹션 내부 (섹션베이스/점프테이블/길이테이블)를
        // 가리키는지. iced는 RIP 메모리 피연산자의 memory_displacement64()를 **절대
        // ip-relative 주소**(ip+len+rawdisp)로 반환하므로 그 값 자체를 비교한다.
        let va = 0x140001000u64;
        let table_off = 0x600usize;
        let nb = 16usize;
        let code = build_dispatcher_reencrypt(va, table_off, nb, 0xCAFEBABE, false);
        let len_table_va = va + (table_off + nb * 4) as u64;
        let table_va = va + table_off as u64;
        let mut dec = Decoder::with_ip(64, &code, va + 0x20, DecoderOptions::NONE);
        while dec.can_decode() {
            let inst = dec.decode();
            if matches!(inst.memory_base(), Register::RIP) {
                let target = inst.memory_displacement64(); // 절대 타깃 (iced 규약)
                assert!(
                    target == va || target == table_va || target == len_table_va,
                    "RIP target 0x{:X} not in .btg tables (va=0x{:X} table=0x{:X} len=0x{:X})",
                    target,
                    va,
                    table_va,
                    len_table_va
                );
            }
        }
    }

    /// 디스패처가 진입 스택에서 소비하는 슬롯 수를 역어셈블로 계산한다.
    /// (스텁이 N개를 push → 디스패처가 정확히 N개를 소비해야 타깃 블록의 RSP가
    /// 원본과 일치한다. 소비가 적으면 디스패치마다 스택 누수 → 8B 어긋남.)
    fn net_stack_slots_consumed(code: &[u8], base_va: u64) -> i32 {
        let mut dec = Decoder::with_ip(64, code, base_va, DecoderOptions::NONE);
        let mut pushes = 0i32;
        let mut pops = 0i32;
        let mut lea_rsp_slots = 0i32;
        let mut ret = false;
        while dec.can_decode() {
            let inst = dec.decode();
            if inst.is_invalid() {
                break;
            }
            match inst.code() {
                Code::Push_r64 | Code::Pushfq => pushes += 1,
                Code::Pop_r64 | Code::Popfq => pops += 1,
                Code::Lea_r64_m if inst.op0_register() == Register::RSP => {
                    lea_rsp_slots += (inst.memory_displacement64() as i32) / 8;
                }
                Code::Retnq => ret = true,
                _ => {}
            }
        }
        assert!(ret, "dispatcher must end with ret");
        -pushes + pops + lea_rsp_slots + 1 // +1 = ret가 1슬롯 pop
    }

    #[test]
    fn test_plain_dispatcher_stack_balance_two_slots() {
        // v10 FIX 회귀 (일반 모드 8B 스택 누수):
        // 일반 디스패처는 2-푸시 규약 [seed][target]에 맞춰 정확히 2슬롯만
        // 소비해야 한다. (v8~v9에는 블록 스텁이 3푸시를 했지만 디스패처가
        // 2슬롯만 소비해 디스패치마다 8바이트가 남았음)
        let code = build_dispatcher(0x140001000, 0x80, 16, false, 0xCAFEBABE, false, 0);
        let consumed = net_stack_slots_consumed(&code, 0x140001020);
        assert_eq!(
            consumed, 2,
            "plain dispatcher must consume exactly 2 stack slots (got {})",
            consumed
        );
        // trace 모드(INT3 1B)도 같은 균형
        let code_t = build_dispatcher(0x140001000, 0x80, 16, true, 0xCAFEBABE, false, 0);
        assert_eq!(net_stack_slots_consumed(&code_t, 0x140001020), 2);
    }

    #[test]
    fn test_dispatcher_ring_buffer_injects_and_validates() {
        // v13.4d diag: block_ring=true 일 때 ring write 시퀀스가 들어가고
        // 디스패처는 여전히 validate/stack-balance 를 만족해야 한다.
        let va: u64 = 0x140001000;
        let to: usize = 0x600;
        // ring 영역 VA = dispatcher_va + table_offset - RING_REGION
        let ring_va = va + to as u64 - RING_REGION as u64;
        let code = build_dispatcher(va, to, 16, false, 0xCAFEBABE, true, ring_va);
        assert!(!code.is_empty());
        assert!(validate_dispatcher(&code).is_ok());
        // 디스패처가 ring 영역을 침범하면 안 됨 (disp_base + len <= ring_va)
        assert!(
            (va + 0x20) + code.len() as u64 <= ring_va,
            "dispatcher {} bytes overflows into ring region @0x{:X}",
            code.len(), ring_va
        );
        // disasm 후, ring base(r11 절대주소) 를 계산하는 mov r64,imm64 이 존재해야 한다.
        let mut dec = Decoder::with_ip(64, &code, va + 0x20, DecoderOptions::NONE);
        let mut found_base = false;
        let mut found_store = false;
        for _ in 0..512 {
            if !dec.can_decode() { break; }
            let inst = dec.decode();
            if inst.code() == Code::Mov_r64_imm64
                && inst.op0_register() == Register::R11
                && inst.immediate64() as u64 == ring_va
            {
                found_base = true;
            }
            // [r11 + rax*4] 인덱스 스토어 (ring[index] = block_id)
            if inst.code() == Code::Mov_rm32_r32
                && inst.memory_base() == Register::R11
                && inst.memory_index() == Register::RAX
            {
                found_store = true;
            }
        }
        assert!(found_base, "ring base (mov r11, imm64=ring_va) not found");
        assert!(found_store, "ring indexed store not found");
        // ring off 일 때는 base store 가 없어야 한다.
        let code_off = build_dispatcher(va, to, 16, false, 0xCAFEBABE, false, 0);
        let mut dec2 = Decoder::with_ip(64, &code_off, va + 0x20, DecoderOptions::NONE);
        let mut base_off = false;
        for _ in 0..512 {
            if !dec2.can_decode() { break; }
            let inst = dec2.decode();
            if inst.code() == Code::Mov_r64_imm64
                && inst.op0_register() == Register::R11
                && inst.immediate64() as u64 == ring_va
            {
                base_off = true;
            }
        }
        assert!(!base_off, "ring must be absent when block_ring=false");
    }

    #[test]
    fn test_reencrypt_expand_loop_preserves_len_edx() {
        // v14-2 regression (hello_fix.exe 0xC000001D @ block 3101):
        // block_crypt's key256 ExpandLoop used EDX as its loop counter,
        // clobbering the block length the caller passes in EDX. PRGA then ran
        // with len=0 -> no block was ever decrypted -> every encrypted block
        // executed as ciphertext. The loop counter must use a scratch register
        // (R8D) so EDX keeps the length for the PRGA call.
        let code = build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false);
        let mut dec = Decoder::with_ip(64, &code, 0x140001020, DecoderOptions::NONE);
        let mut dec_edx = 0usize;
        let mut mov_edx_64 = 0usize;
        let mut dec_r8d = 0usize;
        while dec.can_decode() {
            let inst = dec.decode();
            if inst.is_invalid() {
                break;
            }
            match inst.code() {
                Code::Dec_rm32 if inst.op0_register() == Register::EDX => dec_edx += 1,
                Code::Mov_r32_imm32
                    if inst.op0_register() == Register::EDX && inst.immediate32() == 64 =>
                {
                    mov_edx_64 += 1;
                }
                Code::Dec_rm32 if inst.op0_register() == Register::R8D => dec_r8d += 1,
                _ => {}
            }
        }
        assert_eq!(dec_edx, 0, "ExpandLoop must not clobber EDX (block length)");
        assert_eq!(
            mov_edx_64, 0,
            "ExpandLoop counter must not be initialized from EDX"
        );
        assert!(
            dec_r8d > 0,
            "ExpandLoop counter should use a scratch register (R8D)"
        );
    }

    #[test]
    fn test_reencrypt_dispatcher_stack_balance_three_slots() {
        // 재암호화 디스패처는 3-푸시 규약 [seed][target][current]에 맞춰
        // 정확히 3슬롯을 소비해야 한다.
        let code = build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false);
        let consumed = net_stack_slots_consumed(&code, 0x140001020);
        assert_eq!(
            consumed, 3,
            "reencrypt dispatcher must consume exactly 3 stack slots (got {})",
            consumed
        );
    }
}
