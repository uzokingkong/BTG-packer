// ==============================================================================

use crate::pe::PeBuilder;
use anyhow::Result;
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};

/// Generates a complex test PE target executable containing:
/// - Stack frame setup & cleanup
/// - Multi-branch decision tree (conditional jumps: JG / JLE / JNE)
/// - Loop structure
/// - Memory array access via RIP-relative LEA
///
/// v9 FIX: 과거 버전은 분기 타깃을 `text_va + 50`/`text_va + 60` 하드코딩했다.
/// 하지만 iced-x86 실제 인코딩은 (예: `lea r8,[rip+...]`의 addr32 프리픽스,
/// `sub rsp,0x20`의 7바이트 인코딩) 가정한 오프셋과 달라, 분기 타깃이 명령어
/// 중간에 떨어져 실행 시 0xC0000005를 유발했다. 이제 1-pass 측정 → 타깃 재결정 →
/// 2-pass 인코딩으로 실제 IP를 분기에 반영한다.
pub fn generate_dummy_target_pe() -> Result<Vec<u8>> {
    let image_base: u64 = 0x140000000;
    let text_rva: u32 = 0x1000;
    let text_va: u64 = image_base + text_rva as u64;

    // ── 1. 인스트럭션 리스트 구성 (분기 타깃은 잠정 0) ────────────────────────────
    let mut instructions = Vec::new();

    // --- Block 0: Prologue & Initialization ---
    instructions.push(Instruction::with1(Code::Push_r64, Register::RBP)?);
    instructions.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RBP,
        Register::RSP,
    )?);
    instructions.push(Instruction::with2(
        Code::Sub_rm64_imm32,
        Register::RSP,
        0x20u32,
    )?);

    instructions.push(Instruction::with2(
        Code::Mov_r32_imm32,
        Register::EAX,
        0x100u32,
    )?);
    instructions.push(Instruction::with2(
        Code::Mov_r32_imm32,
        Register::ECX,
        0x5u32,
    )?);
    instructions.push(Instruction::with2(
        Code::Mov_r32_imm32,
        Register::EDX,
        0x200u32,
    )?);

    // RIP-relative instruction: lea r8, [rip + 0x1000] (targets data RVA 0x2000)
    // IP-의존 disp32는 1-pass 후 실제 IP로 재계산된다.
    let rip_target_va: u64 = image_base + 0x2000;
    let mem_op = MemoryOperand::with_base_displ(Register::RIP, 0);
    instructions.push(Instruction::with2(Code::Lea_r64_m, Register::R8, mem_op)?);

    // --- Block 1: Arithmetic & Decision Tree ---
    instructions.push(Instruction::with2(
        Code::Add_rm32_r32,
        Register::EAX,
        Register::EDX,
    )?);
    instructions.push(Instruction::with2(
        Code::Sub_rm32_imm32,
        Register::EAX,
        0x10u32,
    )?);
    instructions.push(Instruction::with2(
        Code::Cmp_rm32_imm32,
        Register::EAX,
        0x150u32,
    )?);

    // 분기 타깃 인덱스 기록 (실제 IP는 1-pass 후 결정)
    let jg_idx = instructions.len();
    instructions.push(Instruction::with_branch(Code::Jg_rel32_64, text_va)?);

    // --- Fallthrough Path (Condition False: EAX <= 0x150) ---
    instructions.push(Instruction::with2(
        Code::Xor_rm32_imm32,
        Register::EDX,
        0x55u32,
    )?);
    let jmp_idx = instructions.len();
    instructions.push(Instruction::with_branch(Code::Jmp_rel32_64, text_va)?);

    // --- Branch Taken Path (Condition True: EAX > 0x150) ---
    let add_greater_idx = instructions.len();
    instructions.push(Instruction::with2(
        Code::Add_rm32_imm32,
        Register::EAX,
        0x1000u32,
    )?);

    // --- Common Continuation & Epilogue ---
    let continue_idx = instructions.len();
    instructions.push(Instruction::with1(Code::Dec_rm32, Register::ECX)?);
    instructions.push(Instruction::with2(
        Code::Add_rm32_imm32,
        Register::EAX,
        0x7777u32,
    )?);

    instructions.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RSP,
        Register::RBP,
    )?);
    instructions.push(Instruction::with1(Code::Pop_r64, Register::RBP)?);
    instructions.push(Instruction::with(Code::Retnq));

    // ── 2. 1-pass: 각 인스트럭션의 정확한 인코딩 길이 측정 (최장 형태 강제) ──
    // 분기 = rel32(6B), RIP-relative = disp32(7B) — 타깃 값과 무관하게 고정 길이.
    // 절대 target 값을 넣어도 iced는 같은 길이로 인코딩하므로 측정이 안전하다.
    let mut ips = vec![0u64; instructions.len()];
    let mut ip = text_va;
    for (i, inst) in instructions.iter().enumerate() {
        ips[i] = ip;
        let mut m = *inst;
        m.set_ip(ip);
        if i == jg_idx || i == jmp_idx {
            m.set_near_branch64(ip); // rel32 (자기 자신 = 길이 불변)
        } else if m.memory_base() == Register::RIP {
            m.set_memory_displacement64(ip); // disp32 (길이 불변)
        }
        let arr = [m];
        let blk = InstructionBlock::new(&arr, ip);
        let len = match BlockEncoder::encode(64, blk, BlockEncoderOptions::NONE) {
            Ok(r) => r.code_buffer.len(),
            Err(_) => {
                if m.len() > 0 {
                    m.len()
                } else {
                    5
                }
            }
        };
        ip += len as u64;
    }

    // ── 3. 분기 타깃 + RIP disp를 실제 IP로 재결정 ──────────────────────────────
    instructions[jg_idx].set_near_branch64(ips[add_greater_idx]);
    instructions[jmp_idx].set_near_branch64(ips[continue_idx]);
    for inst in instructions.iter_mut() {
        if inst.memory_base() == Register::RIP {
            // iced BlockEncoder 규약: RIP 메모리 operand의 memory_displacement64()는
            // 상대 오프셋이 아니라 **절대 타깃 VA**로 해석된다 → rip_target_va를 설정.
            inst.set_memory_displacement64(rip_target_va);
        }
    }

    // ── 4. 최종 일괄 인코딩 ──────────────────────────────────────────────────────
    let block = InstructionBlock::new(&instructions, text_va);
    let enc_res = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)?;

    println!(
        "[+] Complex test target payload encoded successfully: {} instructions, {} bytes (v9 two-pass IP fix).",
        instructions.len(),
        enc_res.code_buffer.len()
    );

    let pe_builder = PeBuilder::new(image_base, text_rva, enc_res.code_buffer);
    pe_builder.build()
}
