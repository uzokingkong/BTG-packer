// ==============================================================================
// Memory hardening (--mem-harden): .textb RWX->RX via NtProtectVirtualMemory
// ==============================================================================

use super::bootstub::{BootStubCtx, Label};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

fn emit_mem_protect(
    seq: &mut Vec<(Instruction, Option<Label>)>,
    stub: &BootStubCtx,
    protection: u32,
    seal_state: bool,
    fail_label: Label,
    done_label: Label,
) {
    // ── v6 --mem-harden: ntdll!NtProtectVirtualMemory로 .textb RWX->RX ──────
    // S3: fail-open 제거 — LoadLibraryA("ntdll.dll")/GetProcAddress(
    // "NtProtectVirtualMemory") 해석 실패 및 NtProtectVirtualMemory의
    // NTSTATUS != STATUS_SUCCESS(0) 모두 **명시적 거부(ud2)**로 강제 종료.
    // (보호 없이 계속 실행하는 fail-open은 더 이상 없다.)
    // FIX(v12.2): reencrypt(런타임 블록 단위 복호화)와 동시에는 생략 — 디스패처의
    // in-place 복호화가 RX 페이지에 쓰면 0xC0000005 (fault @ PRGA xor [rcx],al).
    if stub.mem_harden && !stub.reencrypt {
        // LoadLibraryA("ntdll.dll")
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R13, stub.iat_ll_slot_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.mem_ntdll_name_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base(Register::R13),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(fail_label),
        )); // LoadLibraryA 슬롯 없음 → 거부
        seq.push((
            Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(fail_label),
        )); // ntdll 로드 실패 → 거부
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap(),
            None,
        )); // ntdll handle
            // GetProcAddress(ntdll, "NtProtectVirtualMemory")
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R15, stub.iat_gpa_slot_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.mem_ntprot_name_va)
                .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R14).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base(Register::R15),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(fail_label),
        )); // GetProcAddress 슬롯 없음 → 거부
        seq.push((
            Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(fail_label),
        )); // proc 해석 실패 → 거부
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R12, Register::RAX).unwrap(),
            None,
        )); // preserve NtProtectVirtualMemory across both protection calls
            // NtProtectVirtualMemory(-1, &base, &size, PAGE_EXECUTE_READ, &old)
            // 스크래치: [rsp+0x100]=base, [rsp+0x108]=size, [rsp+0x110]=old (프레임 0x138)
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R11, stub.mem_code_base).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ(Register::RSP, 0x100),
                Register::R11,
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R11, stub.mem_code_size).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ(Register::RSP, 0x108),
                Register::R11,
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm32_imm32,
                MemoryOperand::with_base_displ(Register::RSP, 0x110),
                0,
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RCX, u64::MAX).unwrap(),
            None,
        )); // NtCurrentProcess
        seq.push((
            Instruction::with2(
                Code::Lea_r64_m,
                Register::RDX,
                MemoryOperand::with_base_displ(Register::RSP, 0x100),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Lea_r64_m,
                Register::R8,
                MemoryOperand::with_base_displ(Register::RSP, 0x108),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::R9D, protection).unwrap(),
            None,
        )); // PAGE_EXECUTE_READ
        seq.push((
            Instruction::with2(
                Code::Lea_r64_m,
                Register::R10,
                MemoryOperand::with_base_displ(Register::RSP, 0x110),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ(Register::RSP, 0x20),
                Register::R10,
            )
            .unwrap(),
            None,
        )); // 5th arg
        seq.push((
            Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(),
            None,
        ));
        // S3: NTSTATUS 검사 — EAX(=STATUS_SUCCESS 0) 아니면 명시적 거부(ud2)
        seq.push((
            Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
            Some(fail_label),
        )); // NTSTATUS != 0 → 거부

        // P1-5: the remainder of the original RWX section owns mutable VM
        // state/call-stack/bootstrap data. Remove execute permission from that
        // tail explicitly, yielding RX immutable pages + RW mutable pages.
        if seal_state && stub.vm_oep {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::R11, stub.mem_state_base)
                    .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ(Register::RSP, 0x100),
                    Register::R11,
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::R11, stub.mem_state_size)
                    .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ(Register::RSP, 0x108),
                    Register::R11,
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_rm32_imm32,
                    MemoryOperand::with_base_displ(Register::RSP, 0x110),
                    0,
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RCX, u64::MAX).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Lea_r64_m,
                    Register::RDX,
                    MemoryOperand::with_base_displ(Register::RSP, 0x100),
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Lea_r64_m,
                    Register::R8,
                    MemoryOperand::with_base_displ(Register::RSP, 0x108),
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 0x04).unwrap(),
                None,
            )); // PAGE_READWRITE
            seq.push((
                Instruction::with2(
                    Code::Lea_r64_m,
                    Register::R10,
                    MemoryOperand::with_base_displ(Register::RSP, 0x110),
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_displ(Register::RSP, 0x20),
                    Register::R10,
                )
                .unwrap(),
                None,
            ));
            seq.push((
                Instruction::with1(Code::Call_rm64, Register::R12).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
                Some(fail_label),
            ));
        }
        seq.push((
            Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(),
            Some(done_label),
        )); // 성공 → 정상 경로
            // MemFail: 명시적 거부 (ud2 — 절대 fall-through 금지)
        seq.push((Instruction::with(Code::Ud2), Some(fail_label)));
        // MemDone: 정상 경로 종점 (NOP)
        seq.push((Instruction::with(Code::Nopd), Some(done_label)));
    }
}

/// Open the initially RX runtime just long enough for bootstrap copy/decrypt.
pub(crate) fn emit_mem_unseal(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    emit_mem_protect(
        seq,
        stub,
        0x40, // PAGE_EXECUTE_READWRITE
        false,
        Label::MemOpenFail,
        Label::MemOpenDone,
    );
}

/// Close the transient write window and split immutable RX from mutable RW.
pub(crate) fn emit_mem_harden(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    emit_mem_protect(
        seq,
        stub,
        0x20, // PAGE_EXECUTE_READ
        true,
        Label::MemFail,
        Label::MemDone,
    );
}
