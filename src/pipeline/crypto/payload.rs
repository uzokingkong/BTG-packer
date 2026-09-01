// ==============================================================================
// Payload relocation (--payload-relocate): .vdata -> code region copy loop
// ==============================================================================

use super::bootstub::{BootStubCtx, Label};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

pub(crate) fn emit_payload_copy(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v4 payload-relocate: 외부 데이터 섹션(.vdata)에서 코드 영역으로 복사 ──
    // FIX(0xC000001D 크래시): 과거 코드는 `Code::Movsb_m8_m8`(iced)를 그대로 인코딩해
    // REP 프리픽스(F3)가 붙지 않아 1바이트만 복사되었고, RSI/RDI 사용으로 직후 PRGA의
    // RC4 i/j 카운터(ESI/EDI)를 파괴해 복호화 키스트림이 깨져 코드 영역이 쓰레기가 되었다.
    // → R8/R9/R10D만 쓰는 수동 바이트 루프로 교체 (ESI/EDI 비파괴, REP 인코딩 의존 없음).
    if stub.payload_len > 0 {
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::R8, stub.payload_va).unwrap(),
            None,
        ));
        if stub.desc_used {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.desc_va).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::R9,
                    MemoryOperand::with_base_displ(Register::RAX, 0x00),
                )
                .unwrap(),
                None,
            ));
        } else if stub.vm_oep && stub.vm_oep_bc_len > 0 {
            // VM-OEP relocation destination is the Program-VM bytecode slot,
            // not the legacy native code_start.  The packer moves the ciphertext
            // out of [vm_prog_bc_off..] into .vdata and zeroes that original slot;
            // copying back to stub.code_va here would overwrite VM handler code
            // and explains the random instruction stream seen at packed+0x8badc.
            seq.push((
                Instruction::with2(
                    Code::Mov_r64_imm64,
                    Register::R9,
                    stub.vm_oep_bc_va,
                )
                .unwrap(),
                None,
            ));
        } else {
            seq.push((
                Instruction::with2(Code::Mov_r64_imm64, Register::R9, stub.code_va).unwrap(),
                None,
            ));
        }
        seq.push((
            Instruction::with2(Code::Mov_r32_imm32, Register::R10D, stub.payload_len).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
            Some(Label::PayloadCopyDone),
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r8_rm8,
                Register::AL,
                MemoryOperand::with_base(Register::R8),
            )
            .unwrap(),
            Some(Label::PayloadCopyLoop),
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm8_r8,
                MemoryOperand::with_base(Register::R9),
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
            Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with1(Code::Dec_rm32, Register::R10D).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(),
            Some(Label::PayloadCopyLoop),
        ));
        seq.push((Instruction::with(Code::Nopd), Some(Label::PayloadCopyDone)));
    }
}
