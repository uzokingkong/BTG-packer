// ==============================================================================
// Memory hardening (--mem-harden): .textb RWX->RX via NtProtectVirtualMemory
// ==============================================================================

use super::bootstub::{BootStubCtx, Label};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

pub(crate) fn emit_mem_harden(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v6 --mem-harden: ntdll!NtProtectVirtualMemory로 .textb RWX->RX ──────
    // fail-open: 슬롯/해석 실패 시 보호 없이 계속 진행.
    // FIX(v12.2): reencrypt(런타임 블록 단위 복호화)와 동시에는 생략 — 디스패처의
    // in-place 복호화가 RX 페이지에 쓰면 0xC0000005 (fault @ PRGA xor [rcx],al).
    if stub.mem_harden && !stub.reencrypt {
        // LoadLibraryA("ntdll.dll")
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.mem_ntdll_name_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base(Register::R13)).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::MemDone)));
        seq.push((Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::MemDone)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap(), None)); // ntdll handle
        // GetProcAddress(ntdll, "NtProtectVirtualMemory")
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.mem_ntprot_name_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R14).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base(Register::R15)).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::MemDone)));
        seq.push((Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::MemDone)));
        // NtProtectVirtualMemory(-1, &base, &size, PAGE_EXECUTE_READ, &old)
        // 스크래치: [rsp+0x100]=base, [rsp+0x108]=size, [rsp+0x110]=old (프레임 0x138)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R11, stub.mem_code_base).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ(Register::RSP, 0x100), Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R11, stub.mem_code_size).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ(Register::RSP, 0x108), Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm32_imm32, MemoryOperand::with_base_displ(Register::RSP, 0x110), 0).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, u64::MAX).unwrap(), None)); // NtCurrentProcess
        seq.push((Instruction::with2(Code::Lea_r64_m, Register::RDX, MemoryOperand::with_base_displ(Register::RSP, 0x100)).unwrap(), None));
        seq.push((Instruction::with2(Code::Lea_r64_m, Register::R8, MemoryOperand::with_base_displ(Register::RSP, 0x108)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 0x20).unwrap(), None)); // PAGE_EXECUTE_READ
        seq.push((Instruction::with2(Code::Lea_r64_m, Register::R10, MemoryOperand::with_base_displ(Register::RSP, 0x110)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ(Register::RSP, 0x20), Register::R10).unwrap(), None)); // 5th arg
        seq.push((Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(), None));
        seq.push((Instruction::with(Code::Nopd), Some(Label::MemDone)));
    }
}

