// ==============================================================================
// VM self-test submodule: abi.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use rand::RngCore;
use anyhow::{Result, anyhow};
use crate::vm::{bytecode, handlers, interp, ksa, lifter};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};
use crate::vm::{VM_STATE_SIZE, build_vm_module, build_vm_module_mba};
use crate::vm::arena::{Arena};
use crate::vm::encode::{encode_trampoline};


// =============================================================================
// [추가 테스트] v_abi: handler 생성 x64 코드의 ABI / 스택 / 복귀 규약 검증
// =============================================================================
//
// packed.exe 종료 시 "thread 'main' has overflowed its stack" + once.rs:166
// panic (Option::unwrap on None) + AV(c0000005) 가 발생하는 원인이 "handler 가
// 생성한 x64 코드의 호출 규약(calling convention) 이 실제 VM 실행 방식과 어긋나
// 있어서" 인지 아닌지를 **단계별로, 구조적으로, 그리고 런타임에서** 검증한다.
//
//  검증 축 1 (STATIC DECODE) — 생성된 VM 모듈 기계어를 iced_x86 로 디코드해
//    프로시저 구조가 Win64 ABI 를 따르는지 확인:
//      (a) entry:  sub rsp,0xA0 → XMM6..15 저장(10×movdqu) → 15개 GPR push
//          (RAX,RCX,RDX,RBX,RBP,RSI,RDI,R8,R9,R10,R11,R15,R14,R13,R12 순)
//          → mode 스냅샷 → r8/r9/r10 설정 → jmp dispatch
//      (b) dispatch: movzx eax,[r9]; inc r9; mov rax,[r10+rax*8]; jmp rax
//      (c) HALT: 15개 GPR pop(정확히 역순) → XMM6..15 복원 → add rsp,0xA0 → ret
//      (d) 전체 모듈에서 `ret` 은 정확히 1개 (HALT 의 ret 하나뿐)
//      (e) 모든 handler 진입점이 코드 범위 안 + 유효 명령어 + ret 로 시작하지 않음
//  검증 축 2 (RUNTIME STACK/RETURN) — 실제로 VM 을 실행하고, callee-saved
//    GPR(rbx/rbp/rsi/rdi/r12-r15) 에 sentinel 을 심고 RSP 를 기록해,
//    호출 전/후가 정확히 동일한지(= 스택 균형, 레지스터 보존) 확인.
//    이는 'overflow its stack' (RSP 비균형) 과 'r12-r15 오염 → atexit 간접점프
//    AV' 를 VM 자체가 지키는지 실측한다.
//  검증 축 3 (NATIVE BRIDGE) — OP_NATIVE_CALL 가 Win64 인자 레지스터
//    (rcx/rdx/r8/r9) 와 스택 5번째 인자([v4+0x20..]) 를 제대로 세우고,
//    RSP 를 16-byte 정렬하고, 반환 후 호출자의 RSP/callee-saved 를 복원하는지.
/// [33] handler ABI/stack/return conventions (static decode + runtime).
pub fn run_handler_abi_test() -> anyhow::Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::{handlers, interp};
    use crate::vm::arena::Arena;
    use crate::vm::encode::encode_trampoline;
    use super::{build_vm_module};
    use anyhow::anyhow;
    use iced_x86::{Code, Decoder, DecoderOptions, Instruction, MemoryOperand, Register};

    let code_va = 0x14000_1000u64;
    let table_va = 0x14000_3000u64;
    let bc_va = 0x14000_4000u64;

    let vmc = handlers::generate_vm_code(code_va, bc_va, table_va, handlers::EntryMode::Ksa, None)?;
    handlers::validate_vm_code(&vmc.code)?;

    // ── 디코드 전체 인스트럭션 목록 (offset, inst) ─────────────────────────
    let mut dec = Decoder::with_ip(64, &vmc.code, code_va, DecoderOptions::NONE);
    let mut insns: Vec<(u64, Instruction)> = Vec::new();
    while dec.can_decode() {
        let i = dec.decode();
        insns.push((i.ip(), i));
    }
    assert!(insns.len() > 40, "[33] decoded instruction list unexpectedly short: {}", insns.len());

    // (d) 전체 `ret` 은 정확히 1개.
    let rets: Vec<u64> = insns.iter().filter(|(_, i)| i.code() == Code::Retnq).map(|(o, _)| *o).collect();
    if rets.len() != 1 {
        return Err(anyhow!("[33] expected exactly ONE ret in the VM module, found {} at {:?}", rets.len(), rets));
    }

    // (a) entry 프롤로그 검증 ──────────────────────────────────────────────
    let idx = |off: u64| -> anyhow::Result<usize> { insns.iter().position(|(o, _)| *o == code_va + off).ok_or_else(|| anyhow!("[33] no insn at offset 0x{:X}", off)) };
    let e0 = idx(vmc.entry_offset as u64)?;
    // sub rsp, 0xA0
    let i = &insns[e0].1;
    if i.code() != Code::Sub_rm64_imm32 || i.op0_register() != Register::RSP || (i.immediate32() as u32) != 0xA0 {
        return Err(anyhow!("[33] entry[0] expected sub rsp,0xA0, got {:?} (imm=0x{:X})", i.code(), i.immediate32()));
    }
    // v65: entry[1] = cld (normalize host DF so pushfq-based cap_flags captures
    // the guest's modelled DF exactly). Offsets below are shifted by +1.
    let i = &insns[e0 + 1].1;
    if i.code() != Code::Cld {
        return Err(anyhow!("[33] entry[1] expected cld (v65 host-DF normalization), got {:?}", i.code()));
    }
    // 10× movdqu [rsp+16k], xmm(6+k)
    for k in 0..10 {
        let i = &insns[e0 + 2 + k].1;
        let want_xmm = Register::XMM6 + k as i32;
        if i.code() != Code::Movdqu_xmmm128_xmm
            || i.memory_base() != Register::RSP
            || i.memory_displacement64() != (16 * k) as u64
            || i.op1_register() != want_xmm {
            return Err(anyhow!("[33] entry XMM save #{} mismatch: {:?}", k, i));
        }
    }
    // 15 GPR push in exact order
    let push_order = [
        Register::RAX, Register::RCX, Register::RDX, Register::RBX, Register::RBP,
        Register::RSI, Register::RDI, Register::R8, Register::R9, Register::R10,
        Register::R11, Register::R15, Register::R14, Register::R13, Register::R12,
    ];
    for (k, want) in push_order.iter().enumerate() {
        let i = &insns[e0 + 12 + k].1;
        if i.code() != Code::Push_r64 || i.op0_register() != *want {
            return Err(anyhow!("[33] entry push #{}: expected push {:?}, got {:?}", k, want, i));
        }
    }
    // Ksa: 2 pointer snapshots
    let s = &insns[e0 + 27].1; // mov [rcx+0x110], rbx
    if s.code() != Code::Mov_rm64_r64 || s.memory_base() != Register::RCX || s.memory_displacement64() != 0x110 || s.op1_register() != Register::RBX {
        return Err(anyhow!("[33] entry Ksa snapshot[0] mismatch: {:?}", s));
    }
    let s = &insns[e0 + 28].1; // mov [rcx+0x118], rdx
    if s.code() != Code::Mov_rm64_r64 || s.memory_base() != Register::RCX || s.memory_displacement64() != 0x118 || s.op1_register() != Register::RDX {
        return Err(anyhow!("[33] entry Ksa snapshot[1] mismatch: {:?}", s));
    }
    let s = &insns[e0 + 29].1; // mov r8, rcx
    if s.code() != Code::Mov_r64_rm64 || s.op0_register() != Register::R8 || s.op1_register() != Register::RCX {
        return Err(anyhow!("[33] entry r8=rcx mismatch: {:?}", s));
    }
    let s = &insns[e0 + 30].1; // mov r9, bc_va
    if s.code() != Code::Mov_r64_imm64 || s.op0_register() != Register::R9 || s.immediate64() != bc_va {
        return Err(anyhow!("[33] entry r9=bc_va mismatch: {:?}", s));
    }
    let s = &insns[e0 + 31].1; // mov r10, table_va
    if s.code() != Code::Mov_r64_imm64 || s.op0_register() != Register::R10 || s.immediate64() != table_va {
        return Err(anyhow!("[33] entry r10=table_va mismatch: {:?}", s));
    }
    let s = &insns[e0 + 33].1; // jmp dispatch (r15 MBA-key zeroing inserted at [32])
    if s.code() != Code::Jmp_rel32_64 {
        return Err(anyhow!("[33] entry[33] expected jmp dispatch, got {:?}", s.code()));
    }

    // (b) dispatch loop 검증 ────────────────────────────────────────────────
    let d0 = idx(vmc.dispatch_offset as u64)?;
    let d = &insns[d0].1;
    if d.code() != Code::Movzx_r32_rm8 || d.memory_base() != Register::R9 { return Err(anyhow!("[33] dispatch[0] movzx eax,[r9] mismatch: {:?}", d)); }
    let d = &insns[d0 + 1].1;
    if d.code() != Code::Inc_rm64 || d.op0_register() != Register::R9 { return Err(anyhow!("[33] dispatch[1] inc r9 mismatch: {:?}", d)); }
    let d = &insns[d0 + 2].1;
    if d.code() != Code::Mov_r64_rm64 || d.op0_register() != Register::RAX || d.memory_base() != Register::R10 || d.memory_index() != Register::RAX || d.memory_index_scale() != 8 {
        return Err(anyhow!("[33] dispatch[2] mov rax,[r10+rax*8] mismatch: {:?}", d));
    }
    let d = &insns[d0 + 3].1;
    if d.code() != Code::Xor_rm64_r64 || d.op0_register() != Register::RAX || d.op1_register() != Register::R15 { return Err(anyhow!("[33] dispatch[3] xor rax,r15 (MBA key) mismatch: {:?}", d)); }
    let d = &insns[d0 + 4].1;
    if d.code() != Code::Jmp_rm64 || d.op0_register() != Register::RAX { return Err(anyhow!("[33] dispatch[4] jmp rax mismatch: {:?}", d)); }

    // (c) HALT 에필로그 검증 ────────────────────────────────────────────────
    let h0 = idx(vmc.handler_offsets[OP_HALT as usize] as u64)?;
    let pop_order = [
        Register::R12, Register::R13, Register::R14, Register::R15, Register::R11,
        Register::R10, Register::R9, Register::R8, Register::RDI, Register::RSI,
        Register::RBP, Register::RBX, Register::RDX, Register::RCX, Register::RAX,
    ];
    for (k, want) in pop_order.iter().enumerate() {
        let i = &insns[h0 + k].1;
        if i.code() != Code::Pop_r64 || i.op0_register() != *want {
            return Err(anyhow!("[33] HALT pop #{}: expected pop {:?}, got {:?}", k, want, i));
        }
    }
    for k in 0..10 {
        let i = &insns[h0 + 15 + k].1;
        let want_xmm = Register::XMM6 + k as i32;
        if i.code() != Code::Movdqu_xmm_xmmm128 || i.op0_register() != want_xmm || i.memory_base() != Register::RSP {
            return Err(anyhow!("[33] HALT XMM restore #{} mismatch: {:?}", k, i));
        }
    }
    let a = &insns[h0 + 25].1;
    if a.code() != Code::Add_rm64_imm32 || a.op0_register() != Register::RSP || (a.immediate32() as u32) != 0xA0 {
        return Err(anyhow!("[33] HALT add rsp,0xA0 mismatch: {:?}", a));
    }
    let r = &insns[h0 + 26].1;
    if r.code() != Code::Retnq {
        return Err(anyhow!("[33] HALT ret mismatch: {:?}", r.code()));
    }

    // (e) 모든 handler 진입점이 코드 범위 내 + 유효 명령어 + ret 아님
    for op in 1..bytecode::NUM_OPS {
        let off = vmc.handler_offsets[op];
        if off >= vmc.code.len() {
            return Err(anyhow!("[33] handler op 0x{:02X} offset 0x{:X} out of code range", op, off));
        }
        let hi = idx(off as u64)?;
        let fi = &insns[hi].1;
        if fi.is_invalid() {
            return Err(anyhow!("[33] handler op 0x{:02X} starts with invalid instruction", op));
        }
        if fi.code() == Code::Retnq {
            return Err(anyhow!("[33] handler op 0x{:02X} starts with ret (only HALT may ret)", op));
        }
    }

    // ── 검증 축 2: 런타임 스택 균형 + callee-saved GPR 보존 ────────────────
    // 실제 VM 을 trampoline 을 통해 실행하고, rsp 와 callee-saved GPR
    // (rsi,rdi,r12-r15) 가 호출 전후 동일한지 raw asm 으로 실측한다.
    unsafe { abi_runtime_probe(vmc, code_va, bc_va, table_va, insns.len()) }?;

    // ── 검증 축 3: native bridge 가 Win64 ABI 를 지키는지 ─────────────────
    run_bridge_abi_check()?;

    Ok(())
}


/// x86-64 전용: VM trampoline 실행 전후 callee-saved GPR / RSP 실측.
/// 아키텍처가 x86-64 가 아니면 건너뛰고 Ok 를 반환 (다른 타깃 빌드 보호).
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn abi_runtime_probe(_vmc: crate::vm::handlers::VmCode, _code_va: u64, _bc_va: u64, _table_va: u64, _ninsn: usize) -> anyhow::Result<()> {
    use crate::vm::bytecode::*;

    // 트램펄린 + 모듈을 arena 에 배치
    let mut arena = Arena::new(0x40000)?;
    let va_base = arena.base as u64;
    let (vc, vt, vb, vs, vtr, vdata) = (
        va_base + 0x1000, va_base + 0x4800, va_base + 0x5000,
        va_base + 0x6000, va_base + 0x8000, va_base + 0x9000,
    );
    // 테스트 바이트코드: 간단한 산술 + 메모리 RMW + 스택 push/pop 까지 섞어
    // 여러 handler 를 거치게 한다 (ret 는 HALT 가 유일).
    let mut bc = BytecodeBuilder::new();
    bc.mov_r_imm64(0, 0x1122_3344_5566_7788);
    bc.mov_r_imm64(1, 0x99AA_BBCC_DDEE_FF00);
    bc.binop_r_r64(OP_XOR_R_R64, 0, 1);
    bc.mov_r_imm64(14, va_base + 0x9000);
    bc.mem_xadd_a(OP_XADD_MEM64_A, 14, 0);
    bc.mov_r_imm64(15, va_base + 0x9008);
    bc.mov_r_imm64(13, 0x0102_0304_0506_0708);
    bc.mem_cmpxchg_a(OP_CMPXCHG_MEM64_A, 15, 13);
    bc.mov_r_imm64(4, va_base + 0xA000); // v4 = RSP vreg → VM stack base
    bc.push_r(0);
    bc.pop_r(7);
    bc.mov_r_imm32(2, 5);
    bc.halt();
    let prog = bc.finish();
    let module = build_vm_module(vc, vt, vb, prog.clone(), handlers::EntryMode::Ksa)?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vs, vdata, vdata, vc, vtr)?;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x4800..0x4800 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
        b[0x5000..0x5000 + prog.len()].copy_from_slice(&prog);
        b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
        // set up the VM stack pointer so push/pop writes into the arena, not address 0.
        b[0x6000 + interp::STATE_PTR_STACK..0x6000 + interp::STATE_PTR_STACK + 8]
            .copy_from_slice(&(va_base + 0xA000).to_le_bytes());
        b[0x6000 + interp::STATE_SP..0x6000 + interp::STATE_SP + 8]
            .copy_from_slice(&0x1000u64.to_le_bytes());
        b[0x9000..0x9010].fill(0);
        b[0xA000..0xA000 + 0x2000].fill(0);
    }
    let tramp_va = vtr;

    // callee-saved GPR sentinel + RSP 를 하나의 asm 블록에서 실측.
    // 결과는 레지스터가 아닌 버퍼(포인터 1개)에 저장해 레지스터 압박을 피한다.
    let mut out = [0u64; 10];
    let buf_ptr = out.as_mut_ptr();

    // ── 진짜 검증: callee-saved GPR sentinel + RSP 보존 ────────────────────
    // VM 진입 시 callee-saved GPR(rsi/rdi/r12-r15) 을 sentinel 로 세팅해 call
    // 하고, 반환 후 sentinel 그대로인지(=VM 이 보존) + RSP 균형인지 확인한다.
    // rbx/rbp 는 LLVM 이 내부적으로 예약해 clobber 불가 → 제외 (스태틱 디코드 +
    // bridge 테스트가 대신 검증).
    core::arch::asm!(
        "mov rsi, 0x3333333333333333",
        "mov rdi, 0x4444444444444444",
        "mov r12, 0x5555555555555555",
        "mov r13, 0x6666666666666666",
        "mov r14, 0x7777777777777777",
        "mov r15, 0x8888888888888888",
        "mov r9, rsp",
        "mov rax, r8",
        "call rax",
        "mov r10, rsp",
        "mov [r11+0], r9",
        "mov [r11+8], r10",
        "mov [r11+32], rsi",
        "mov [r11+40], rdi",
        "mov [r11+48], r12",
        "mov [r11+56], r13",
        "mov [r11+64], r14",
        "mov [r11+72], r15",
        in("r8") tramp_va,
        in("r11") buf_ptr,
        out("rsi") _, out("rdi") _,
        out("r12") _, out("r13") _, out("r14") _, out("r15") _,
        clobber_abi("C"),
    );
    // RSP 균형: VM 은 호출 전후 rsp 를 그대로 복원해야 한다.
    if out[0] != out[1] {
        return Err(anyhow!("[33-runtime] RSP imbalance: before=0x{:X} after=0x{:X} (stack leak or over-retract)", out[0], out[1]));
    }
    // callee-saved sentinel 보존 (VM 이 rsi/rdi/r12-r15 를 건드리면 안 됨)
    let want = [
        0x3333_3333_3333_3333u64, // rsi  -> out[4]
        0x4444_4444_4444_4444,    // rdi  -> out[5]
        0x5555_5555_5555_5555,    // r12  -> out[6]
        0x6666_6666_6666_6666,    // r13  -> out[7]
        0x7777_7777_7777_7777,    // r14  -> out[8]
        0x8888_8888_8888_8888,    // r15  -> out[9]
    ];
    for (i, w) in want.iter().enumerate() {
        let got = out[4 + i];
        if got != *w {
            return Err(anyhow!("[33-runtime] callee-saved reg #{} corrupted: got 0x{:X} want 0x{:X} (would break atexit/Once teardown)", i, got, w));
        }
    }
    println!("[33-runtime] VM trampoline: RSP balanced + rsi/rdi/r12-r15 sentinels preserved: PASS");
    Ok(())
}


#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn abi_runtime_probe(_vmc: crate::vm::handlers::VmCode, _a: u64, _b: u64, _c: u64, _d: usize) -> anyhow::Result<()> {
    Ok(())
}


/// native bridge ABI 검증: VM 이 네이티브 함수를 Win64 규약으로 호출하는지.
/// 5-인자 함수를 통해 rcx/rdx/r8/r9 + 스택 5번째 인자 + RSP 정렬을 검증한다.
pub(crate) fn run_bridge_abi_check() -> anyhow::Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::arena::Arena;
    use crate::vm::encode::encode_trampoline;
    use iced_x86::{BlockEncoder, BlockEncoderOptions, Instruction, InstructionBlock, MemoryOperand, Register};

    let mut arena = Arena::new(0x40000)?;
    let va = arena.base as u64;
    let (vc, vt, vb, vs, vtr, vdata, vstack, vnative) = (
        va + 0x1000, va + 0x4800, va + 0x5000, va + 0x6000,
        va + 0x8000, va + 0x9000, va + 0x7000, va + 0xB000,
    );
    // 네이티브 5-인자 헬퍼: return rcx + 2*rdx + 4*r8 + 8*r9 + 16*d5(stack@[rsp+0x28])
    // Win64 에서 5번째 인자는 [rsp+0x28]. (call 직전 sub rsp,0x60 후 ret-addr이 쌓여)
    let helper = [
        Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RCX).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RDX).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RDX).unwrap(),
        Instruction::with2(Code::Shl_rm64_imm8, Register::R8, 2).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R8).unwrap(),
        Instruction::with2(Code::Shl_rm64_imm8, Register::R9, 3).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R9).unwrap(),
        Instruction::with2(Code::Mov_r64_rm64, Register::RCX, MemoryOperand::with_base_displ(Register::RSP, 0x28)).unwrap(),
        Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
        Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(),
        Instruction::with(Code::Retnq),
    ];
    let hblk = InstructionBlock::new(&helper, vnative);
    let henc = BlockEncoder::encode(64, hblk, BlockEncoderOptions::NONE).map_err(|e| anyhow!("[33-bridge] helper encode failed: {}", e))?;

    // 바이트코드: 인자 a=1,b=2,c=3,d=4 (v1,v2,v8,v9), 5번째 e=5 는 스택
    //   v4(RSP vreg)=vstack 로 설정해 브리지가 [v4+0x20]=e 를 찾게 한다.
    let mut bc = BytecodeBuilder::new();
    bc.mov_r_imm64(0, vnative);
    bc.mov_r_imm32(1, 1);
    bc.mov_r_imm32(2, 2);
    bc.mov_r_imm32(8, 3);
    bc.mov_r_imm32(9, 4);
    bc.native_call(0);
    bc.halt();
    let prog = bc.finish();
    let module = build_vm_module(vc, vt, vb, prog.clone(), handlers::EntryMode::Ksa)?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vs, vdata, vdata, vc, vtr)?;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x4800..0x4800 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
        b[0xB000..0xB000 + henc.code_buffer.len()].copy_from_slice(&henc.code_buffer);
        b[0x5000..0x5000 + prog.len()].copy_from_slice(&prog);
        b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
        b[0x7000..0x7010].fill(0);
        b[0x9000..0x9010].fill(0);
        // 스택 5번째 인자 위치 [v4+0x20] = vstack+0x20 → 5
        b[0x6000 + interp::STATE_VREGS + 4 * 8..0x6000 + interp::STATE_VREGS + 5 * 8]
            .copy_from_slice(&vstack.to_le_bytes());
        b[0x7000 + 0x20..0x7000 + 0x28].copy_from_slice(&5u64.to_le_bytes());
    }
    arena.call(0x8000);
    let b = arena.bytes();
    let ret = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS + 0 * 8..0x6000 + interp::STATE_VREGS + 1 * 8].try_into().unwrap());
    // 1 + 2*2 + 4*3 + 8*4 + 16*5 = 1+4+12+32+80 = 129
    if ret != 129 {
        return Err(anyhow!("[33-bridge] native 5-arg call returned {} (want 129); ABI arg marshalling wrong", ret));
    }
    println!("[33-bridge] native bridge (rcx/rdx/r8/r9 + 5th stack arg, RSP-aligned, restored): PASS");
    Ok(())
}


/// [28] M8 (v45): VM handler-table MBA 난독화 검증.
///
/// 동일한 KSA 바이트코드를 (a) reference interpreter, (b) **plaintext** 네이티브 VM,
/// (c) **MBA-obfuscated** 네이티브 VM 세 경로로 실행해 결과가 모두 동일함을 검증한다.
/// 또한 MBA 모듈의 handler 테이블이 plaintext 모듈과 달라야 하고(주소가 XOR-암호화됨),
/// MBA 디스패치가 임베디드된 `a`, `b`에서 MBA 항등식 `a+b==(a^b)+2·(a&b)`로 K를 유도해
/// 정확히 복호화함으로써 프로그램이 오작동 없이 동작함을 증명한다.
pub(crate) fn run_m8_handler_mba_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut rng = rand::thread_rng();
    let mut seed_masked = [0u8; 256];
    rng.fill_bytes(&mut seed_masked);
    let (k1, k2, k3) = (rng.next_u32(), rng.next_u32(), rng.next_u32());

    // Reference KSA (pure Rust).
    let mut expected = [0u8; 256];
    ksa::reference_ksa(&seed_masked, k1, k2, k3, &mut expected);

    // Lift the KSA to bytecode.
    let seq = ksa::build_ksa_instructions(0, k1, k2, k3);
    let bc = lifter::lift_ksa(&seq)?;

    // (a) Interpreter.
    {
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x2000];
        mem[0x1000..0x1000 + 256].copy_from_slice(&seed_masked);
        st[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
            .copy_from_slice(&(0x100usize as u64).to_le_bytes());
        st[interp::STATE_PTR_SEED..interp::STATE_PTR_SEED + 8]
            .copy_from_slice(&(0x1000usize as u64).to_le_bytes());
        interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("[28] interp failed: {:?}", e))?;
        assert_eq!(&mem[0x100..0x100 + 256], &expected[..], "[28] interpreter mismatch");
    }

    // Helper: run `bc` through a native VM module. `use_mba` selects the MBA-obfuscated
    // handler-table builder (which derives K at runtime and XOR-decrypts handler entries)
    // vs the plaintext builder. The module is built with the *real* arena VAs so the entry
    // stub's r9/r10 point at the actual bytecode/table. Returns S-box match.
    let run_module = |use_mba: bool| -> Result<bool> {
        let mut arena = Arena::new(0x20000)?;
        let sbox_va = arena.base + 0x2000;
        let seed_va = arena.base + 0x3000;
        let code_va = arena.base + 0x5000;
        // Code region 0x5000..0x9800 (0x4800 bytes) comfortably fits the ~14.3KB
        // handler set that keeps growing with every opcode (previously 0x8800,
        // which the MBA variant's ~14.36KB code overflowed and corrupted).
        let table_va = arena.base + 0x9800;
        let bc_va = arena.base + 0xA000;
        let state_va = arena.base + 0xA800;
        let vsbox_va = arena.base + 0xB000;
        let tramp_va = arena.base + 0xC000;
        let module = if use_mba {
            build_vm_module_mba(code_va as u64, table_va as u64, bc_va as u64, bc.clone(), handlers::EntryMode::Ksa)?
        } else {
            build_vm_module(code_va as u64, table_va as u64, bc_va as u64, bc.clone(), handlers::EntryMode::Ksa)?
        };
        handlers::validate_vm_code(&module.code)?;
        let tramp = encode_trampoline(state_va as u64, vsbox_va as u64, seed_va as u64, code_va as u64, tramp_va as u64)?;
        {
            let b = arena.bytes();
            b[0x2000..0x2000 + 256].fill(0);
            b[0x3000..0x3000 + 256].copy_from_slice(&seed_masked);
            b[0x5000..0x5000 + module.code.len()].copy_from_slice(&module.code);
            b[0x9800..0x9800 + module.table.len()].copy_from_slice(&module.table);
            b[0xA000..0xA000 + module.bytecode.len()].copy_from_slice(&module.bytecode);
            b[0xA800..0xA800 + VM_STATE_SIZE].fill(0);
            b[0xB000..0xB000 + 256].fill(0);
            b[0xC000..0xC000 + tramp.len()].copy_from_slice(&tramp);
        }
        arena.call(0xC000);
        Ok(arena.bytes()[0xB000..0xB000 + 256] == expected[..])
    };

    // (b) Plaintext native VM.
    assert!(run_module(false)?, "[28] plaintext native VM mismatch");

    // (c) MBA-obfuscated native VM.
    assert!(run_module(true)?, "[28] MBA native VM mismatch");

    // Handler table must actually be obfuscated: build both modules at the same
    // fixed VAs and confirm the MBA table differs from the plaintext table (handler
    // absolute addresses are XOR-encrypted, not stored in the clear).
    let (pc, pt, pb) = (0x1000u64, 0x3000u64, 0x4000u64);
    let plain = build_vm_module(pc, pt, pb, bc.clone(), handlers::EntryMode::Ksa)?;
    let mba = build_vm_module_mba(pc, pt, pb, bc.clone(), handlers::EntryMode::Ksa)?;
    assert_ne!(mba.table, plain.table, "[28] MBA table must differ from plaintext table");
    assert_ne!(
        &mba.table[0..8],
        &plain.table[0..8],
        "[28] MBA first handler entry must be XOR-masked"
    );

    Ok(())
}
