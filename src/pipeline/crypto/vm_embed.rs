// ==============================================================================
// VM module embed + program VM state init (boot-stub entry context capture)
// ==============================================================================

use super::bootstub::{BootStubCtx, Label};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

pub(crate) fn emit_native_entry_save(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // Native OEP는 새 함수 호출이 아니라 로더가 제공한 entry context의 연속이다.
    // 부트 스텁이 사용하기 전에 모든 GPR/RFLAGS를 저장하고 tail-jump 직전에 정확히
    // 복원한다. 이로써 원본 RSP도 바이트 단위로 동일하게 유지된다.
    if stub.vm_oep_native_entry {
        seq.push((Instruction::with(Code::Pushfq), None));
        for r in [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::RBX,
            Register::RBP,
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
            seq.push((Instruction::with1(Code::Push_r64, r).unwrap(), None));
        }
    }
}

pub(crate) fn emit_program_vm_state_capture(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── M6 Phase-2 (--vm-oep): 원본 프로그램의 실제 entry 레지스터를 프로그램 VM
    // 상태 버퍼에 캡처한다. 프로그램 VM은 빈 상태로 시작하면 원본 entry 블록이
    // vreg(=0)로 절대주소 접근해 [0] 크래시 → 여기서 로더가 부여한 entry 컨텍스트
    // (RCX=PEB, RSP=스택, R8/R9)를 상태 vregs로 미리 채운다. (junk/clobber 전에 수행)
    if stub.vm_oep {
        use iced_x86::MemoryOperand as M;
        // rax = 프로그램 VM state VA
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.vm_prog_state_va).unwrap(), None));

        // C-1 fix: 프로그램 VM state 버퍼 전체를 0으로 초기화하고 모든 메모리 슬롯
        // 포인터(SBOX/SEED/BUF/RUNS/STACK)를 유효한 주소로 채운다. at-rest 0-fill에
        // 의존하면 부트 스텁 실행 중 슬롯 포인터(특히 BUF/RUNS)가 남은 값/가비지를
        // 가리켜, 리프트된 프로그램이 슬롯 기반 mem-store(OP_MOV_MEM32_R/64_R)를
        // 실행할 때 [가비지] 크래시(0xC0000005)가 난다. state 크기만큼 0으로 채운 뒤
        // 5개 슬롯을 실제 VA로 설정해 실행을 완전 결정적(구조적)으로 만든다.
        let st_size = crate::vm::interp::STATE_SIZE as u32;
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R11, st_size as u64).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R10, 0).unwrap(), None));
        let zero_lbl = Label::StateZeroLoop;
        let zero_done_lbl = Label::StateZeroDone;
        seq.push((Instruction::with(Code::Nopd), Some(zero_lbl)));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::R11, Register::R11).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(zero_done_lbl)));
        seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::R11, 8).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_index_scale(Register::RAX, Register::R11, 1), Register::R10).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(zero_lbl)));
        seq.push((Instruction::with(Code::Nopd), Some(zero_done_lbl)));

        // 슬롯 포인터 초기화 (5개 연속 8B 슬롯, PTR_SLOTS_BASE=0x110):
        //   SBOX → S-box base(=RSP, 부트 스텁이 스택에 할당), SEED → seed_va,
        //   BUF/RUNS → 각각 유효한 스크래치(부트 영역 끝 사용), STACK → RSP(원본 스택).
        // SBOX를 RSP(부트 스텁의 스택 할당)로 두면 리프트 프로그램의 슬롯 접근이
        // 최소한 실행 가능한 매핑된 주소를 향한다.
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, crate::vm::interp::STATE_PTR_SBOX as i64), Register::RSP).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R11, stub.seed_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, crate::vm::interp::STATE_PTR_SEED as i64), Register::R11).unwrap(), None));
        // BUF/RUNS → seed_va 근처 여유 (부트 영역이 매핑된 RW 영역이므로 안전).
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, crate::vm::interp::STATE_PTR_BUF as i64), Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, crate::vm::interp::STATE_PTR_RUNS as i64), Register::R11).unwrap(), None));
        // (state 버퍼 끝 직후, STATE_CALL_STACK_BUF(=STATE_SIZE) 이후
        // CALL_STACK_SIZE 바이트를 별도 예약해 두stack 모델 VM return-IP 스택으로 쓴다).
        seq.push((Instruction::with2(Code::Lea_r64_m, Register::R11, M::with_base_displ(Register::RAX, crate::vm::interp::STATE_CALL_STACK_BUF as i64)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, crate::vm::interp::STATE_PTR_CALL_STACK as i64), Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R11, crate::vm::interp::CALL_STACK_SIZE as u64).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, crate::vm::interp::STATE_CALL_SP as i64), Register::R11).unwrap(), None));

        // vregs: v1=RCX(PEB), v8=R8, v9=R9 (v4=RSP captured right before VM entry below)
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, (crate::vm::interp::STATE_VREGS as i64) + 1*8), Register::RCX).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, (crate::vm::interp::STATE_VREGS as i64) + 8*8), Register::R8).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, (crate::vm::interp::STATE_VREGS as i64) + 9*8), Register::R9).unwrap(), None));
        // NOTE: the program VM's stack pointer is vreg[4] (RSP), captured from the
        // real RSP in the dispatcher entry below (not STATE_SP). STATE_SP/PTR_STACK
        // are NOT used by the call/ret/push/pop handlers anymore (single-stack fix).
        // v43: GS base(=TEB) 캡처 — gs:[0x30]은 NT_TIB.Self(=TEB base)를 가리키므로,
        // STATE_SEG_GS(0x240)에 저장해 PEB/TEB 접근(gs:[...])이 VM에서 동작하게 한다.
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x30, false, Register::GS)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, crate::vm::interp::STATE_SEG_GS as i64), Register::RDX).unwrap(), None));
    }
}

pub(crate) fn emit_prga_vm_call(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    use iced_x86::MemoryOperand as M;
    // RCX=buf, RDX=len  →  RDX=buf, R8=len, RCX=prga_state, call prga_entry
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::RDX).unwrap(), None)); // r8 = len
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RCX).unwrap(), None)); // rdx = buf
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.vm_prga_state_va).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Call_rel32_64, stub.vm_prga_entry_va).unwrap(), None));
}

/// v19: PRGA VM 상태의 i/j (v0/v1) 를 0 으로 초기화 (최초 호출 전 1회).
pub(crate) fn emit_prga_vm_init(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    use iced_x86::MemoryOperand as M;
    // state[0]=v0(i)=0, state[8]=v1(j)=0
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.vm_prga_state_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_imm32, M::with_base(Register::RAX), 0).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_imm32, M::with_base_displ(Register::RAX, 8), 0).unwrap(), None));
}
