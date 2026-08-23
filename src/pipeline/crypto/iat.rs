// ==============================================================================
// IAT hiding (--iat-hide): resolve-table handling in the boot stub
// ==============================================================================

use super::bootstub::{BootStubCtx, Label};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

fn emit_unxor(
    seq: &mut Vec<(Instruction, Option<Label>)>,
    name_reg: Register,
    master: u32,
    c: u32,
    l_main: Label,
    l_tail: Label,
    l_done: Label,
) {
    // key = ((master ^ rbx) + 2*(master & rbx)) ^ c  -> eax
    seq.push((
        Instruction::with2(Code::Mov_r32_imm32, Register::EAX, master).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EBX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r32_imm32, Register::EDX, master).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::And_rm32_r32, Register::EDX, Register::EBX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm32_r32, Register::EDX, Register::EDX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::EDX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, c).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::EAX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_rm64, Register::R8, name_reg).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, 4).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(),
        Some(l_tail),
    ));
    seq.push((
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R11D).unwrap(),
        Some(l_main),
    ));
    seq.push((
        Instruction::with2(
            Code::Xor_rm32_r32,
            MemoryOperand::with_base(Register::R8),
            Register::EAX,
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Add_rm64_imm32, Register::R8, 4).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Sub_rm32_imm32, Register::ECX, 4).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, 4).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Jae_rel32_64, 0).unwrap(),
        Some(l_main),
    ));
    seq.push((
        Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap(),
        Some(l_tail),
    ));
    seq.push((
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(l_done),
    ));
    seq.push((
        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R11D).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Xor_rm8_r8,
            MemoryOperand::with_base(Register::R8),
            Register::AL,
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with1(Code::Inc_rm64, Register::R8).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with1(Code::Dec_rm64, Register::RCX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(l_done),
    ));
    seq.push((
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Xor_rm8_r8,
            MemoryOperand::with_base(Register::R8),
            Register::AL,
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with1(Code::Inc_rm64, Register::R8).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with1(Code::Dec_rm64, Register::RCX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(l_done),
    ));
    seq.push((
        Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Xor_rm8_r8,
            MemoryOperand::with_base(Register::R8),
            Register::AL,
        )
        .unwrap(),
        None,
    ));
    seq.push((Instruction::with(Code::Nopd), Some(l_done)));
}

/// v19: 모듈 base에서 키 바인딩 바이트 유도 (패커 측 — 부트 스텁과 동일 fold).
/// `((base>>16) ^ (base>>24) ^ (base>>32)) & 0xFF` — 0x140000000이면 0x41로 비영.

pub(crate) fn emit_iat_slots(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v6: 더미 import 슬롯 주소 상수 (리졸브/메모리 보호에서 사용) ─────────
    // r13 = LoadLibraryA 슬롯 VA, r15 = GetProcAddress 슬롯 VA (imm64, 길이 불변)
    if stub.iat_enabled || stub.mem_harden {
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R13, stub.iat_ll_slot_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R15, stub.iat_gpa_slot_va).unwrap(),
            None,
        ));
    }
}

pub(crate) fn emit_iat_resolve(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v6 --iat-hide: 리졸브 테이블 처리 ─────────────────────────────────────
    // 테이블 포맷 (build_resolve_table):
    //   u32 dll_count | 각 dll: u32 name_len, name+NUL, u32 func_count,
    //   각 func: u64 slot_va, u32 name_len, name+NUL (ordinal: name_len=0xFFFF0000 + u16)
    // LoadLibraryA/GetProcAddress는 더미 import 슬롯을 통해 호출한다.
    if stub.iat_enabled {
        // FIX(v12): dll_count 카운터는 **callee-saved RBP** 사용 — R8은 volatile이라
        // LoadLibraryA/GetProcAddress 호출이 클로버 → 카운터가 깨져 리졸브 테이블
        // 워크가 unmapped 영역으로 이탈, 0xC0000005 (pack_orig+0x9E30B) 크래시.
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.iat_table_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EBP,
                MemoryOperand::with_base(Register::RSI),
            )
            .unwrap(),
            None,
        )); // dll_count
        seq.push((
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 4).unwrap(),
            None,
        ));
        // v14: RBX = running import-name entry index (각 dll 이름 / named func마다 1씩 증가)
        seq.push((
            Instruction::with2(Code::Xor_r32_rm32, Register::EBX, Register::EBX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RBP, Register::RBP).unwrap(),
            Some(Label::DllLoop),
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::ResolveDone),
        ));
        // dll_loop body: dll 이름 로드
        seq.push((
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::ECX,
                MemoryOperand::with_base(Register::RSI),
            )
            .unwrap(),
            None,
        )); // name_len
        seq.push((
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 4).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RSI).unwrap(),
            None,
        )); // dll name ptr
        seq.push((
            Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RCX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 1).unwrap(),
            None,
        ));
        // v14: dll 이름 per-entry MBA 키로 un-XOR (R9 보존, R8로 진행)
        emit_unxor(
            seq,
            Register::R9,
            stub.mba_master,
            stub.mba_c,
            Label::UxDllMain,
            Label::UxDllTail,
            Label::UxDllDone,
        );
        seq.push((
            Instruction::with1(Code::Inc_rm64, Register::RBX).unwrap(),
            None,
        ));
        // LoadLibraryA(dll_name)
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R9).unwrap(),
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
            Some(Label::ResolveDone),
        ));
        seq.push((
            Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap(),
            None,
        )); // hModule
        seq.push((
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EDI,
                MemoryOperand::with_base(Register::RSI),
            )
            .unwrap(),
            None,
        )); // func_count
        seq.push((
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 4).unwrap(),
            None,
        ));
        // func_loop body
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::RDI, Register::RDI).unwrap(),
            Some(Label::FuncLoop),
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::DllNext),
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R12,
                MemoryOperand::with_base(Register::RSI),
            )
            .unwrap(),
            None,
        )); // slot_va
        seq.push((
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 8).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::ECX,
                MemoryOperand::with_base(Register::RSI),
            )
            .unwrap(),
            None,
        )); // name_len/marker
        seq.push((
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 4).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, 0xFFFF_0000u32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::FuncOrdinal),
        ));
        // named: r10 = name ptr
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RSI).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RCX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 1).unwrap(),
            None,
        ));
        // v14: named func 이름 per-entry MBA 키로 un-XOR (R10 보존, R8로 진행)
        emit_unxor(
            seq,
            Register::R10,
            stub.mba_master,
            stub.mba_c,
            Label::UxFuncMain,
            Label::UxFuncTail,
            Label::UxFuncDone,
        );
        seq.push((
            Instruction::with1(Code::Inc_rm64, Register::RBX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R10).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(),
            Some(Label::FuncCall),
        ));
        // ordinal: rdx = ordinal (MAKEINTRESOURCE)
        seq.push((
            Instruction::with2(
                Code::Movzx_r32_rm16,
                Register::EDX,
                MemoryOperand::with_base(Register::RSI),
            )
            .unwrap(),
            Some(Label::FuncOrdinal),
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 3).unwrap(),
            None,
        ));
        // GetProcAddress(hModule, name/ordinal)
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R14).unwrap(),
            Some(Label::FuncCall),
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
            Some(Label::ResolveDone),
        ));
        seq.push((
            Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base(Register::R12),
                Register::RAX,
            )
            .unwrap(),
            None,
        )); // *slot = addr
        seq.push((
            Instruction::with1(Code::Dec_rm64, Register::RDI).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(),
            Some(Label::FuncLoop),
        ));
        // dll_next
        seq.push((
            Instruction::with1(Code::Dec_rm64, Register::RBP).unwrap(),
            Some(Label::DllNext),
        ));
        seq.push((
            Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(),
            Some(Label::DllLoop),
        ));
        seq.push((Instruction::with(Code::Nopd), Some(Label::ResolveDone)));
    }
}
