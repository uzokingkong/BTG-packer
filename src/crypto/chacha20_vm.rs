//! Restricted ChaCha arithmetic VM. Each instruction touches one of 16 u32
//! words; there are no host pointers, calls, allocations or key derivations.
use super::{lab, push, Seq};
use iced_x86::{Code, Instruction as I, MemoryOperand as M, Register as R};

const ADD: u8 = 1;
const XOR: u8 = 2;
const ROT: u8 = 3;

fn program() -> Vec<u8> {
    super::chacha20_vm_program()
}

/// Inline interpreter. RSP is the caller's bounded 16-word work area. Its
/// initial-state copy at +64 is never addressable by VM operands. R12..R14,
/// the streaming cipher's buffer/length/state anchors, remain untouched.
pub(super) fn emit(s: &mut Seq) {
    let bytes = program();
    let branch = |s: &mut Seq, code, label: &str| {
        s.push((I::with_branch(code, 0).unwrap(), Some(label.to_owned())));
    };
    branch(s, Code::Call_rel32_64, "crypto_vm_entry");
    for chunk in bytes.chunks(16) {
        push(s, I::with_declare_byte(chunk).unwrap());
    }
    lab(s, "crypto_vm_entry");
    push(s, I::with1(Code::Pop_r64, R::RSI).unwrap());
    push(
        s,
        I::with2(Code::Mov_r32_imm32, R::EDI, (bytes.len() / 4) as u32).unwrap(),
    );
    lab(s, "crypto_vm_fetch");
    push(s, I::with2(Code::Test_rm32_r32, R::EDI, R::EDI).unwrap());
    branch(s, Code::Je_rel32_64, "crypto_vm_fail");
    push(s, I::with1(Code::Dec_rm32, R::EDI).unwrap());
    for (register, offset) in [(R::R8D, 0), (R::R9D, 1), (R::R10D, 2), (R::ECX, 3)] {
        push(
            s,
            I::with2(
                Code::Movzx_r32_rm8,
                register,
                M::with_base_displ(R::RSI, offset),
            )
            .unwrap(),
        );
    }
    push(s, I::with2(Code::Add_rm64_imm32, R::RSI, 4).unwrap());
    push(s, I::with2(Code::Test_rm32_r32, R::R8D, R::R8D).unwrap());
    branch(s, Code::Je_rel32_64, "crypto_vm_halt");
    for reg in [R::R9D, R::R10D] {
        push(s, I::with2(Code::Cmp_rm32_imm32, reg, 16).unwrap());
        branch(s, Code::Jae_rel32_64, "crypto_vm_fail");
    }
    let dst = M::new(R::RSP, R::R9, 4, 0, 0, false, R::None);
    let src = M::new(R::RSP, R::R10, 4, 0, 0, false, R::None);
    push(s, I::with2(Code::Mov_r32_rm32, R::EAX, dst).unwrap());
    push(s, I::with2(Code::Mov_r32_rm32, R::EDX, src).unwrap());
    for (token, label) in [
        (ADD, "crypto_vm_add"),
        (XOR, "crypto_vm_xor"),
        (ROT, "crypto_vm_rot"),
    ] {
        push(
            s,
            I::with2(Code::Cmp_rm32_imm32, R::R8D, token as u32).unwrap(),
        );
        branch(s, Code::Je_rel32_64, label);
    }
    branch(s, Code::Jmp_rel32_64, "crypto_vm_fail");
    lab(s, "crypto_vm_add");
    push(s, I::with2(Code::Add_rm32_r32, R::EAX, R::EDX).unwrap());
    branch(s, Code::Jmp_rel32_64, "crypto_vm_store");
    lab(s, "crypto_vm_xor");
    push(s, I::with2(Code::Xor_rm32_r32, R::EAX, R::EDX).unwrap());
    branch(s, Code::Jmp_rel32_64, "crypto_vm_store");
    lab(s, "crypto_vm_rot");
    push(s, I::with2(Code::Cmp_rm32_imm32, R::ECX, 32).unwrap());
    branch(s, Code::Jae_rel32_64, "crypto_vm_fail");
    push(s, I::with2(Code::Rol_rm32_CL, R::EAX, R::CL).unwrap());
    lab(s, "crypto_vm_store");
    push(s, I::with2(Code::Mov_rm32_r32, dst, R::EAX).unwrap());
    branch(s, Code::Jmp_rel32_64, "crypto_vm_fetch");
    lab(s, "crypto_vm_halt");
    push(s, I::with2(Code::Test_rm32_r32, R::EDI, R::EDI).unwrap());
    branch(s, Code::Je_rel32_64, "crypto_vm_done");
    lab(s, "crypto_vm_fail");
    push(s, I::with(Code::Ud2));
    lab(s, "crypto_vm_done");
}
