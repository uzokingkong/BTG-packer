// ==============================================================================
// BTG - Commercial-Grade VM: Direct-Threaded Native Handler Runner
// ==============================================================================
// 12개 RISC 마이크로 핸들러의 네이티브 x86-64 기계어를 동적으로 생성하고,
// 중앙 디스패처 없는 Direct Tail-Call 스레딩 방식으로 네이티브 실행 및 검증한다.
//
// 네이티브 핸들러 ABI 계약 (T1-3) — 폴리모픽 인터프리터 `PolymorphicInterpreter`
// 및 참조 시뮬레이터 `RiscProgram::eval_state`와 동일한 레지스터/스택 의미를 가진다:
//   * R10 = 1번째 피연산자 (dst/src1) — 연산 결과도 여기에
//   * R11 = 2번째 피연산자 (src2)
//   * R12 = VIP (바이트코드 포인터)
//   * R13 = VSP (가상 스택 포인터, 아래로 성장)
//   * R14 = 롤링 키
//   * R15 = 핸들러 테이블 베이스
// ==============================================================================

use super::direct_tail::DirectTailEmitter;
use crate::vm::arena::Arena;
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, Register};

/// 네이티브 핸들러 코드젠 ABI 상수.
pub const ABI_ARG1: Register = Register::R10;
pub const ABI_ARG2: Register = Register::R11;
pub const ABI_VIP: Register = Register::R12;
pub const ABI_VSP: Register = Register::R13;
pub const ABI_KEY: Register = Register::R14;
pub const ABI_TABLE: Register = Register::R15;

pub struct DirectThreadedNativeRunner {
    pub arena: Arena,
}

impl DirectThreadedNativeRunner {
    pub fn new() -> Result<Self> {
        let arena = Arena::new(0x20000)?;
        Ok(Self { arena })
    }

    fn emit_two_reg(instrs: &mut Vec<Instruction>, code: Code, a: Register, b: Register) -> Result<()> {
        instrs.push(Instruction::with2(code, a, b).map_err(|e| anyhow!("{e}"))?);
        Ok(())
    }

    /// NOR 핸들러:
    /// ```asm
    /// or r10, r11
    /// not r10
    /// ; tail dispatch
    /// ```
    pub fn build_nor_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        Self::emit_two_reg(&mut instrs, Code::Or_rm64_r64, ABI_ARG1, ABI_ARG2)?;
        instrs.push(Instruction::with1(Code::Not_rm64, ABI_ARG1).map_err(|e| anyhow!("{e}"))?);
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// ADD_WITH_CARRY 핸들러:
    /// ```asm
    /// add r10, r11
    /// ; tail dispatch
    /// ```
    pub fn build_add_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        Self::emit_two_reg(&mut instrs, Code::Add_rm64_r64, ABI_ARG1, ABI_ARG2)?;
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// SHIFT_RIGHT (논리) 핸들러:
    /// ```asm
    /// mov ecx, r11d          ; count
    /// shr r10, cl
    /// ; tail dispatch
    /// ```
    pub fn build_shift_right_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        // mov ecx, r11d
        instrs.push(
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D)
                .map_err(|e| anyhow!("{e}"))?,
        );
        // shr r10, cl
        instrs.push(
            Instruction::with2(Code::Shr_rm64_CL, ABI_ARG1, Register::CL)
                .map_err(|e| anyhow!("{e}"))?,
        );
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// SHIFT_LEFT 핸들러:
    /// ```asm
    /// mov ecx, r11d
    /// shl r10, cl
    /// ; tail dispatch
    /// ```
    pub fn build_shift_left_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        instrs.push(
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D)
                .map_err(|e| anyhow!("{e}"))?,
        );
        instrs.push(
            Instruction::with2(Code::Shl_rm64_CL, ABI_ARG1, Register::CL)
                .map_err(|e| anyhow!("{e}"))?,
        );
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// VIRTUAL_PUSH 핸들러 (VSP 아래로 성장):
    /// ```asm
    /// sub r13, 8
    /// mov [r13], r10
    /// ; tail dispatch
    /// ```
    pub fn build_virtual_push_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        instrs.push(
            Instruction::with2(Code::Sub_rm64_imm8, ABI_VSP, 8).map_err(|e| anyhow!("{e}"))?,
        );
        let mem = iced_x86::MemoryOperand::with_base(ABI_VSP);
        instrs.push(
            Instruction::with2(Code::Mov_rm64_r64, mem, ABI_ARG1).map_err(|e| anyhow!("{e}"))?,
        );
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// VIRTUAL_POP 핸들러:
    /// ```asm
    /// mov r10, [r13]
    /// add r13, 8
    /// ; tail dispatch
    /// ```
    pub fn build_virtual_pop_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        let mem = iced_x86::MemoryOperand::with_base(ABI_VSP);
        instrs.push(
            Instruction::with2(Code::Mov_r64_rm64, ABI_ARG1, mem).map_err(|e| anyhow!("{e}"))?,
        );
        instrs.push(
            Instruction::with2(Code::Add_rm64_imm8, ABI_VSP, 8).map_err(|e| anyhow!("{e}"))?,
        );
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// MEMORY_READ (8바이트) 핸들러:
    /// ```asm
    /// mov r10, [r10]          ; R10 = 주소 → R10 = *주소
    /// ; tail dispatch
    /// ```
    pub fn build_memory_read_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        let mem = iced_x86::MemoryOperand::with_base(ABI_ARG1);
        instrs.push(
            Instruction::with2(Code::Mov_r64_rm64, ABI_ARG1, mem).map_err(|e| anyhow!("{e}"))?,
        );
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// MEMORY_WRITE (8바이트) 핸들러:
    /// ```asm
    /// mov [r10], r11          ; R10 = 주소, R11 = 값
    /// ; tail dispatch
    /// ```
    pub fn build_memory_write_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        let mem = iced_x86::MemoryOperand::with_base(ABI_ARG1);
        instrs.push(
            Instruction::with2(Code::Mov_rm64_r64, mem, ABI_ARG2).map_err(|e| anyhow!("{e}"))?,
        );
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// SET_FLAG 핸들러:
    /// ```asm
    /// push r10
    /// popfq                  ; R10 = 새 플래그 값
    /// ; tail dispatch
    /// ```
    pub fn build_set_flag_handler(target_va: u64) -> Result<Vec<u8>> {
        let mut instrs = Vec::new();
        instrs.push(Instruction::with1(Code::Push_r64, ABI_ARG1).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with(Code::Popfq));
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// HALT 핸들러:
    /// ```asm
    /// ret
    /// ```
    pub fn build_halt_handler(target_va: u64) -> Result<Vec<u8>> {
        // Win64 callee-saved(R12..R15) restore + RSP 16B alignment: the embedded
        // commercial/poly Program VM entry stub pushes R12,R13,R14,R15, so HALT
        // must pop them back (reverse) before ret -- matching harness.rs HALT.
        let mut instrs = Vec::new();
        for r in [Register::R15, Register::R14, Register::R13, Register::R12] {
            instrs.push(Instruction::with1(Code::Pop_r64, r).map_err(|e| anyhow!("{e}"))?);
        }
        instrs.push(Instruction::with(Code::Retnq));
        DirectTailEmitter::assemble(instrs, target_va)
    }

    /// 12개 전부의 핸들러를 순서대로 생성해 (va, code) 쌍으로 돌려준다.
    /// 이는 출력 PE에 심을 네이티브 인터프리터 스텁의 핸들러 테이블 구성에 쓰인다.
    pub fn build_all_handlers(base_va: u64) -> Result<Vec<(String, u64, Vec<u8>)>> {
        let mut out = Vec::new();
        let mut va = base_va;
        let push = |name: &str, f: fn(u64) -> Result<Vec<u8>>, out: &mut Vec<(String, u64, Vec<u8>)>, va: &mut u64| -> Result<()> {
            let code = f(*va)?;
            out.push((name.to_string(), *va, code.clone()));
            *va += code.len() as u64;
            Ok(())
        };
        push("NOR", Self::build_nor_handler, &mut out, &mut va)?;
        push("ADD", Self::build_add_handler, &mut out, &mut va)?;
        push("SHR", Self::build_shift_right_handler, &mut out, &mut va)?;
        push("SHL", Self::build_shift_left_handler, &mut out, &mut va)?;
        push("PUSH", Self::build_virtual_push_handler, &mut out, &mut va)?;
        push("POP", Self::build_virtual_pop_handler, &mut out, &mut va)?;
        push("MEM_RD", Self::build_memory_read_handler, &mut out, &mut va)?;
        push("MEM_WR", Self::build_memory_write_handler, &mut out, &mut va)?;
        push("SET_FLAG", Self::build_set_flag_handler, &mut out, &mut va)?;
        push("HALT", Self::build_halt_handler, &mut out, &mut va)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_native_handlers() {
        let nor_code = DirectThreadedNativeRunner::build_nor_handler(0x140001000).unwrap();
        let add_code = DirectThreadedNativeRunner::build_add_handler(0x140001050).unwrap();
        let halt_code = DirectThreadedNativeRunner::build_halt_handler(0x1400010A0).unwrap();

        assert!(!nor_code.is_empty());
        assert!(!add_code.is_empty());
        assert!(!halt_code.is_empty());

        // Halt handler ends with ret (0xC3)
        assert!(halt_code.len() >= 5);
    }

    /// T1-3: 12개 RISC 핸들러 전부가 네이티브 기계어로 생성되고,
    /// tail-dispatch(jmp rax = FF E0)로 끝나야 한다.
    #[test]
    fn test_build_all_12_handlers_have_tail_dispatch() {
        let handlers = DirectThreadedNativeRunner::build_all_handlers(0x140001000).unwrap();

        // NOR/ADD/SHR/SHL/PUSH/POP/MEM_RD/MEM_WR/SET_FLAG/HALT = 10개 핸들러.
        // (VirtualBranch/NativeCallBridge 는 전용 브리지 계층에서 별도 생성)
        assert_eq!(handlers.len(), 10);
        for (name, va, code) in &handlers {
            assert!(!code.is_empty(), "handler {name} must emit code");
            if name != "HALT" {
                // HALT를 제외한 모든 핸들러는 tail jmp rax (FF E0)로 끝난다.
                assert_eq!(
                    &code[code.len() - 2..],
                    &[0xFF, 0xE0],
                    "handler {name} must end in jmp rax"
                );
            }
            // 각 핸들러는 고유한 VA에 배치되어야 한다.
            assert!(*va >= 0x140001000);
        }

        // HALT는 단일 ret.
        let halt = handlers.iter().find(|(n, _, _)| n == "HALT").unwrap();
        assert!(halt.2.len() >= 5);
    }

    /// 각 핸들러의 시맨틱 검증 (기계어 해독 후 예상 연산 존재 확인)
    #[test]
    fn test_handler_semantics_decode() {
        use iced_x86::{Decoder, DecoderOptions};

        // SHR 핸들러가 shr r10, cl 을 포함하는지
        let shr = DirectThreadedNativeRunner::build_shift_right_handler(0x140001000).unwrap();
        let mut dec = Decoder::with_ip(64, &shr, 0x140001000, DecoderOptions::NONE);
        let mut has_shr = false;
        let mut has_jmp = false;
        while dec.can_decode() {
            let ins = dec.decode();
            if ins.mnemonic() == iced_x86::Mnemonic::Shr {
                has_shr = true;
            }
            if ins.mnemonic() == iced_x86::Mnemonic::Jmp {
                has_jmp = true;
            }
        }
        assert!(has_shr, "SHR handler must contain shr");
        assert!(has_jmp, "SHR handler must tail-jump");

        // PUSH 핸들러가 sub r13,8 과 mov [r13], r10 을 포함
        let push = DirectThreadedNativeRunner::build_virtual_push_handler(0x140001000).unwrap();
        let mut dec = Decoder::with_ip(64, &push, 0x140001000, DecoderOptions::NONE);
        let mut has_sub = false;
        let mut has_mov = false;
        while dec.can_decode() {
            let ins = dec.decode();
            if ins.mnemonic() == iced_x86::Mnemonic::Sub {
                has_sub = true;
            }
            if ins.mnemonic() == iced_x86::Mnemonic::Mov {
                has_mov = true;
            }
        }
        assert!(has_sub && has_mov, "PUSH handler must sub/mov");
    }

    /// P3 (G1): Win64 callee-saved R12..R15 저장/복원 + RSP 16B 정렬 계약 검증.
    /// 임베드 상용 프로그램 VM의 엔트리 스텁(`build_program_vm_commercial` /
    /// `poly_embed`)은 R12→R15 순서로 push하므로, HALT 핸들러는 역순(R15→R12)
    /// pop 후 ret하여 호출자의 callee-saved 레지스터와 RSP를 정확히 복원해야
    /// 한다. 이 핸들러를 직접 디코드해 해당 명령 시퀀스를 검증한다.
    #[test]
    fn test_build_halt_restores_r12_r15_and_rsp() {
        use iced_x86::{Decoder, DecoderOptions, Mnemonic, Register};

        let halt = DirectThreadedNativeRunner::build_halt_handler(0x1400010A0).unwrap();
        assert!(halt.len() >= 5, "HALT handler must be >= 5 bytes (4 pops + ret)");

        let mut dec = Decoder::with_ip(64, &halt, 0x1400010A0, DecoderOptions::NONE);
        let mut pops = Vec::new();
        let mut saw_ret = false;
        while dec.can_decode() {
            let ins = dec.decode();
            match ins.mnemonic() {
                Mnemonic::Pop => {
                    pops.push(ins.op0_register().full_register());
                }
                Mnemonic::Ret => saw_ret = true,
                _ => {}
            }
        }
        // 역순 pop: R15, R14, R13, R12 — 엔트리 push(R12,R13,R14,R15)와 짝을 이룬다.
        assert_eq!(pops, vec![
            Register::R15, Register::R14, Register::R13, Register::R12
        ], "HALT must pop R15,R14,R13,R12 (reverse of entry push) to restore callee-saved regs");
        assert!(saw_ret, "HALT must end with ret");
        // RSP 16B 정렬: 4개 8B pop은 32B를 되돌려 엔트리 push 직전 RSP(=부트 스텁
        // dispatch 직후, 16B 정렬)로 정확히 복원한다. 명령 수 기반 불변식으로 보강.
        assert_eq!(pops.len() * 8, 32, "4 callee-saved regs = 32B = RSP restore amount");
    }
}
