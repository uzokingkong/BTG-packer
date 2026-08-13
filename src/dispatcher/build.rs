// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Dispatcher Shellcode Builder
//
// The plain MBA jump-table dispatcher (built for the VM module build / MBA
// handler-table paths). The v8 "re-encrypt" dispatcher lives in reencrypt.rs;
// validation lives in validate.rs.
// ==============================================================================

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock,
    MemoryOperand, Register,
};

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

