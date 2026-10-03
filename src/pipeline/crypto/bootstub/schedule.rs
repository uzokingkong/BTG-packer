//! Authenticated stage-control VM. Bridge blocks keep their original native
//! stack and register contracts; dispatch saves/restores its own temporaries.
use super::ctx::{BootStubCtx, Label};
use crate::vm::boot::schedule::{bytecode, AUTH_RECORD, PHASE_COUNT};
use iced_x86::{Code, Instruction as I, MemoryOperand as M, Register as R};
type Seq = Vec<(I, Option<Label>)>;
fn p(s: &mut Seq, i: I) {
    s.push((i, None));
}
fn label(s: &mut Seq, l: Label) {
    s.push((I::with(Code::Nopd), Some(l)));
}
fn branch(s: &mut Seq, code: Code, l: Label) {
    s.push((I::with_branch(code, 0).unwrap(), Some(l)));
}
fn imm(s: &mut Seq, r: R, value: u64) {
    p(s, I::with2(Code::Mov_r64_imm64, r, value).unwrap());
}
fn slot(offset: i64) -> M {
    M::with_base_displ(R::RAX, offset)
}
const SAVED: [R; 15] = [
    R::RAX,
    R::RCX,
    R::RDX,
    R::RBX,
    R::RBP,
    R::RSI,
    R::RDI,
    R::R8,
    R::R9,
    R::R10,
    R::R11,
    R::R12,
    R::R13,
    R::R14,
    R::R15,
];
fn restore_dispatch(s: &mut Seq) {
    for r in [R::RDX, R::RCX, R::RAX] {
        p(s, I::with1(Code::Pop_r64, r).unwrap());
    }
    p(s, I::with(Code::Popfq));
}

pub(super) fn wrap(
    s: &mut Seq,
    start: usize,
    boundaries: &[usize],
    stub: &BootStubCtx,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        boundaries.len() == PHASE_COUNT + 1
            && boundaries[0] == start
            && boundaries.last() == Some(&s.len())
            && boundaries.windows(2).all(|w| w[0] <= w[1]),
        "Boot VM phase/bytecode contract mismatch"
    );
    let (state_va, tag) = stub
        .boot_schedule_auth
        .ok_or_else(|| anyhow::anyhow!("Boot VM stage schedule missing authenticated contract"))?;
    let mut body = s.split_off(start);
    let mut owners = std::collections::HashMap::new();
    for (index, pair) in boundaries.windows(2).enumerate() {
        for (instruction, target) in &body[pair[0] - start..pair[1] - start] {
            if instruction.flow_control() == iced_x86::FlowControl::Next {
                if let Some(target) = target {
                    owners.insert(*target, index);
                }
            }
        }
    }
    let mut edges = Vec::new();
    for (index, pair) in boundaries.windows(2).enumerate() {
        for (instruction, target) in &mut body[pair[0] - start..pair[1] - start] {
            if matches!(
                instruction.flow_control(),
                iced_x86::FlowControl::ConditionalBranch
                    | iced_x86::FlowControl::UnconditionalBranch
            ) {
                if let Some((label, owner)) =
                    target.and_then(|label| owners.get(&label).map(|owner| (label, *owner)))
                {
                    if owner != index {
                        anyhow::ensure!(
                            owner > index,
                            "Boot VM bridge has a cross-stage back edge"
                        );
                        let edge = edges.len() as u16;
                        edges.push((label, owner - index));
                        *target = Some(Label::BootScheduleEdge(edge));
                    }
                }
            }
        }
    }
    let program = bytecode();
    // Save the live bootstrap image around authentication and PC initialization.
    p(s, I::with(Code::Pushfq));
    for r in SAVED {
        p(s, I::with1(Code::Push_r64, r).unwrap());
    }
    branch(s, Code::Call_rel32_64, Label::BootScheduleStart);
    for &byte in &program {
        p(s, I::with_declare_byte_1(byte));
    }
    for byte in tag {
        p(s, I::with_declare_byte_1(byte));
    }
    label(s, Label::BootScheduleStart);
    p(s, I::with1(Code::Pop_r64, R::R13).unwrap());
    let mut root = *stub;
    if let Some((root_va, _, _, _)) = stub.crypto_vm_auth {
        root.chacha_blob_va = root_va;
    }
    if let Some((root_va, _, _, _)) = stub.poly_vm_auth {
        root.poly_blob_va = root_va;
    }
    super::stages::index(s, AUTH_RECORD);
    super::stages::init(s, &root, super::super::stages::Stage::Metadata, true);
    p(s, I::with2(Code::Mov_r64_rm64, R::RCX, R::R13).unwrap());
    imm(s, R::RDX, program.len() as u64);
    p(
        s,
        I::with2(
            Code::Lea_r64_m,
            R::R9,
            M::with_base_displ(R::R13, program.len() as i64),
        )
        .unwrap(),
    );
    super::stages::verify(s, &root, Label::BootScheduleAuthOk, false);
    imm(s, R::RAX, state_va);
    p(s, I::with2(Code::Mov_rm64_r64, slot(0), R::R13).unwrap());
    p(s, I::with2(Code::Mov_rm64_r64, slot(24), R::R13).unwrap());
    p(
        s,
        I::with2(Code::Mov_rm64_imm32, slot(8), program.len() as i32).unwrap(),
    );
    p(s, I::with2(Code::Mov_rm64_imm32, slot(16), 1).unwrap());
    for r in SAVED.into_iter().rev() {
        p(s, I::with1(Code::Pop_r64, r).unwrap());
    }
    p(s, I::with(Code::Popfq));
    label(s, Label::BootScheduleFetch);
    p(s, I::with(Code::Pushfq));
    for r in [R::RAX, R::RCX, R::RDX] {
        p(s, I::with1(Code::Push_r64, r).unwrap());
    }
    imm(s, R::RAX, state_va);
    p(s, I::with2(Code::Cmp_rm64_imm32, slot(16), 1).unwrap());
    branch(s, Code::Jne_rel32_64, Label::BootScheduleFail);
    p(s, I::with2(Code::Cmp_rm64_imm32, slot(8), 0).unwrap());
    branch(s, Code::Je_rel32_64, Label::BootScheduleFail);
    p(
        s,
        I::with2(Code::Cmp_rm64_imm32, slot(8), program.len() as i32).unwrap(),
    );
    branch(s, Code::Jae_rel32_64, Label::BootScheduleCountCheck);
    label(s, Label::BootScheduleCountOk);
    p(s, I::with2(Code::Mov_r64_rm64, R::RCX, slot(0)).unwrap());
    p(s, I::with2(Code::Mov_r64_rm64, R::RDX, slot(24)).unwrap());
    p(
        s,
        I::with2(Code::Add_rm64_imm32, R::RDX, program.len() as i32).unwrap(),
    );
    p(s, I::with2(Code::Sub_r64_rm64, R::RDX, slot(8)).unwrap());
    p(s, I::with2(Code::Cmp_rm64_r64, R::RCX, R::RDX).unwrap());
    branch(s, Code::Jne_rel32_64, Label::BootScheduleFail);
    p(s, I::with1(Code::Inc_rm64, slot(0)).unwrap());
    p(s, I::with1(Code::Dec_rm64, slot(8)).unwrap());
    p(
        s,
        I::with2(Code::Movzx_r32_rm8, R::ECX, M::with_base(R::RCX)).unwrap(),
    );
    p(s, I::with2(Code::Test_rm32_r32, R::ECX, R::ECX).unwrap());
    branch(s, Code::Je_rel32_64, Label::BootScheduleHalt);
    for phase in 1..=PHASE_COUNT as u8 {
        p(
            s,
            I::with2(Code::Cmp_rm32_imm32, R::ECX, phase as u32).unwrap(),
        );
        branch(s, Code::Je_rel32_64, Label::BootScheduleDispatch(phase));
    }
    branch(s, Code::Jmp_rel32_64, Label::BootScheduleFail);
    label(s, Label::BootScheduleCountCheck);
    // Equality permits the initial full count, greater-than is malformed.
    branch(s, Code::Je_rel32_64, Label::BootScheduleCountOk);
    branch(s, Code::Jmp_rel32_64, Label::BootScheduleFail);
    label(s, Label::BootScheduleHalt);
    p(s, I::with2(Code::Cmp_rm64_imm32, slot(8), 0).unwrap());
    branch(s, Code::Jne_rel32_64, Label::BootScheduleFail);
    for offset in [0, 8, 24] {
        p(s, I::with2(Code::Mov_rm64_imm32, slot(offset), 0).unwrap());
    }
    p(s, I::with2(Code::Mov_rm64_imm32, slot(16), 2).unwrap());
    restore_dispatch(s);
    branch(s, Code::Jmp_rel32_64, Label::BootScheduleDone);
    label(s, Label::BootScheduleFail);
    p(s, I::with2(Code::Mov_rm64_imm32, slot(16), 3).unwrap());
    restore_dispatch(s);
    p(s, I::with(Code::Ud2));
    for phase in 1..=PHASE_COUNT as u8 {
        label(s, Label::BootScheduleDispatch(phase));
        restore_dispatch(s);
        branch(s, Code::Jmp_rel32_64, Label::BootPhase(phase));
    }
    for (index, pair) in boundaries.windows(2).enumerate() {
        label(s, Label::BootPhase(index as u8 + 1));
        s.extend_from_slice(&body[pair[0] - start..pair[1] - start]);
        branch(s, Code::Jmp_rel32_64, Label::BootScheduleFetch);
    }
    // Existing approved native branches may skip forward to a later stage.
    // Advance the VM continuation by the same number of stages so that the
    // destination bridge is not executed twice on its next dispatch.
    for (index, (target, advance)) in edges.into_iter().enumerate() {
        label(s, Label::BootScheduleEdge(index as u16));
        p(s, I::with(Code::Pushfq));
        for r in [R::RAX, R::RCX, R::RDX] {
            p(s, I::with1(Code::Push_r64, r).unwrap());
        }
        imm(s, R::RAX, state_va);
        p(
            s,
            I::with2(Code::Add_rm64_imm32, slot(0), advance as i32).unwrap(),
        );
        p(
            s,
            I::with2(Code::Sub_rm64_imm32, slot(8), advance as i32).unwrap(),
        );
        restore_dispatch(s);
        branch(s, Code::Jmp_rel32_64, target);
    }
    label(s, Label::BootScheduleDone);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::crypto::{self, stages};
    use crate::vm::arena::Arena;

    #[test]
    fn native_stage_vm_preserves_registers_flags_and_forward_continuations() {
        for skip in [false, true] {
            let mut arena = Arena::new(0x40000).unwrap();
            let base = arena.base as u64;
            let mut stub = crypto::tests::integrity_stub();
            stub.anti_debug = false;
            stub.chacha_blob_va = base + 0x10000;
            stub.poly_blob_va = base + 0x20000;
            stub.chacha_material_va = base + 0x31000;
            stub.chacha_state_va = base + 0x32000;
            stub.poly_key_va = base + 0x33000;
            let state_va = base + 0x34000;
            let seed = [0x57; 256];
            let cipher = crate::crypto::chacha20_native::emit_chacha20_blob(stub.chacha_state_va);
            let poly = crate::crypto::poly1305_native::emit_poly1305_verify_blob(0);
            arena.bytes()[0x10000..0x10000 + cipher.len()].copy_from_slice(&cipher);
            arena.bytes()[0x20000..0x20000 + poly.len()].copy_from_slice(&poly);
            for stage in stages::STAGES {
                let offset = 0x31000 + stage.offset();
                arena.bytes()[offset..offset + 64].copy_from_slice(&stages::material(&seed, stage));
            }
            let mut results = Vec::new();
            for vm in [false, true] {
                let entry = if vm { 0x4000 } else { 0 };
                stub.boot_va = base + entry as u64;
                stub.boot_schedule_auth = Some((
                    state_va,
                    stages::authenticate(&seed, stages::Stage::Metadata, AUTH_RECORD, &bytecode()),
                ));
                let mut seq = Vec::new();
                for (r, value) in [(R::RAX, 7), (R::RCX, 13), (R::RDX, 23)] {
                    imm(&mut seq, r, value);
                }
                let start = seq.len();
                let mut boundaries = vec![start];
                for phase in 1..=PHASE_COUNT {
                    if phase == 5 {
                        label(&mut seq, Label::PolyOk);
                    }
                    p(
                        &mut seq,
                        I::with2(Code::Add_rm64_imm32, R::RAX, phase as i32).unwrap(),
                    );
                    p(
                        &mut seq,
                        I::with2(Code::Xor_rm64_r64, R::RCX, R::RAX).unwrap(),
                    );
                    p(
                        &mut seq,
                        I::with2(Code::Add_rm64_r64, R::RDX, R::RCX).unwrap(),
                    );
                    if skip && phase == 3 {
                        branch(&mut seq, Code::Jmp_rel32_64, Label::PolyOk);
                    }
                    boundaries.push(seq.len());
                }
                if vm {
                    wrap(&mut seq, start, &boundaries, &stub).unwrap();
                }
                imm(&mut seq, R::R10, base + 0x35000);
                for (r, offset) in [(R::RAX, 0), (R::RCX, 8), (R::RDX, 16)] {
                    p(
                        &mut seq,
                        I::with2(Code::Mov_rm64_r64, M::with_base_displ(R::R10, offset), r)
                            .unwrap(),
                    );
                }
                p(&mut seq, I::with(Code::Pushfq));
                p(&mut seq, I::with1(Code::Pop_r64, R::RAX).unwrap());
                p(
                    &mut seq,
                    I::with2(Code::Mov_rm64_r64, M::with_base_displ(R::R10, 24), R::RAX).unwrap(),
                );
                p(&mut seq, I::with(Code::Retnq));
                let code = crypto::encode::encode_rc4_block(&mut seq, &stub).unwrap();
                assert!(code.len() < 0x4000);
                arena.bytes()[entry..entry + code.len()].copy_from_slice(&code);
                arena.call2(entry, 0, 0);
                results.push(arena.bytes()[0x35000..0x35020].to_vec());
            }
            assert_eq!(
                results[0], results[1],
                "native stage image changed, skip={skip}"
            );
            assert_eq!(
                u64::from_le_bytes(arena.bytes()[0x34010..0x34018].try_into().unwrap()),
                2
            );
            assert!(arena.bytes()[0x34000..0x34010].iter().all(|&b| b == 0));
            assert!(arena.bytes()[0x34018..0x34020].iter().all(|&b| b == 0));
        }
    }
}
