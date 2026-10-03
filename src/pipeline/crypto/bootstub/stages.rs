//! Native counterpart of crypto::stages. No host API or runtime allocation.
use super::super::stages::{Stage, ENTRY_SIZE, MATERIAL_STRIDE, STAGES};
use super::ctx::{BootStubCtx, Label};
use iced_x86::{Code, Instruction as I, MemoryOperand as M, Register as R};
type Seq = Vec<(I, Option<Label>)>;
fn p(s: &mut Seq, i: I) {
    s.push((i, None));
}
fn imm(s: &mut Seq, r: R, value: u64) {
    p(s, I::with2(Code::Mov_r64_imm64, r, value).unwrap());
}
fn reset(s: &mut Seq, stub: &BootStubCtx, counter: i32) {
    imm(s, R::RAX, stub.chacha_state_va);
    p(
        s,
        I::with2(
            Code::Mov_rm64_imm32,
            M::with_base_displ(R::RAX, 0x20),
            counter,
        )
        .unwrap(),
    );
    p(
        s,
        I::with2(Code::Mov_rm32_imm32, M::with_base_displ(R::RAX, 0x78), 64).unwrap(),
    );
}
fn copy_key_nonce(s: &mut Seq, stub: &BootStubCtx, source: u64) {
    imm(s, R::RSI, source);
    imm(s, R::RDI, stub.chacha_state_va);
    for (from, to) in [(0, 0), (8, 8), (16, 16), (24, 24), (32, 0x28)] {
        p(
            s,
            I::with2(Code::Mov_r64_rm64, R::R8, M::with_base_displ(R::RSI, from)).unwrap(),
        );
        p(
            s,
            I::with2(Code::Mov_rm64_r64, M::with_base_displ(R::RDI, to), R::R8).unwrap(),
        );
    }
    p(
        s,
        I::with2(Code::Mov_r32_rm32, R::R8D, M::with_base_displ(R::RSI, 40)).unwrap(),
    );
    p(
        s,
        I::with2(Code::Mov_rm32_r32, M::with_base_displ(R::RDI, 0x30), R::R8D).unwrap(),
    );
    reset(s, stub, 1);
}
pub(crate) fn prepare(s: &mut Seq, stub: &BootStubCtx) {
    if let Some(tag) = stub.boot_vm_tag {
        prepare_vm(s, stub, tag);
        return;
    }
    // Capture all domains before seed scratch is reused by later bootstrap work.
    for stage in STAGES {
        copy_key_nonce(s, stub, stub.seed_va);
        p(
            s,
            I::with2(
                Code::Xor_rm32_imm32,
                M::with_base_displ(R::RDI, 0x28),
                stage.domain(),
            )
            .unwrap(),
        );
        reset(s, stub, 0);
        imm(s, R::RCX, stub.chacha_material_va + stage.offset() as u64);
        // The material buffer starts zero on disk and is writable boot scratch.
        imm(s, R::RDX, MATERIAL_STRIDE as u64);
        super::emit::emit_chacha_call(s, stub);
    }
}

/// Actual bytecode fetch/dispatch for domain and bounded material-slot control.
/// Metadata key derivation and program authentication are the native root.
/// ChaCha/Poly1305 primitives remain native, separate from Program VM state.
fn prepare_vm(s: &mut Seq, stub: &BootStubCtx, tag: [u8; 16]) {
    use crate::vm::boot::material::{bytecode, DERIVE, HALT, MATERIAL_PROGRAM_RECORD};
    let program = bytecode();
    let label = |s: &mut Seq, l| s.push((I::with(Code::Nopd), Some(l)));
    let branch = |s: &mut Seq, code, l| s.push((I::with_branch(code, 0).unwrap(), Some(l)));
    for r in [R::R12, R::R13, R::R14, R::R15] { p(s, I::with1(Code::Push_r64, r).unwrap()); }
    let mut root_stub = *stub;
    if let Some((root_va, _, _, _)) = stub.crypto_vm_auth { root_stub.chacha_blob_va = root_va; }
    if let Some((root_va, _, _, _)) = stub.poly_vm_auth { root_stub.poly_blob_va = root_va; }
    // Native root derives only the metadata authentication domain.
    copy_key_nonce(s, stub, stub.seed_va);
    p(s, I::with2(Code::Xor_rm32_imm32, M::with_base_displ(R::RDI, 0x28), Stage::Metadata.domain()).unwrap());
    reset(s, stub, 0);
    imm(s, R::RCX, stub.chacha_material_va + Stage::Metadata.offset() as u64);
    imm(s, R::RDX, MATERIAL_STRIDE as u64);
    super::emit::emit_chacha_call(s, &root_stub);
    // A local CALL supplies an ASLR-safe pointer to immutable inline bytecode.
    branch(s, Code::Call_rel32_64, Label::BootMaterialStart);
    for &byte in &program { p(s, I::with_declare_byte_1(byte)); }
    for byte in tag { p(s, I::with_declare_byte_1(byte)); }
    label(s, Label::BootMaterialStart);
    p(s, I::with1(Code::Pop_r64, R::R13).unwrap());
    index(s, MATERIAL_PROGRAM_RECORD);
    init(s, stub, Stage::Metadata, true);
    p(s, I::with2(Code::Mov_r64_rm64, R::RCX, R::R13).unwrap());
    imm(s, R::RDX, program.len() as u64);
    p(s, I::with2(Code::Lea_r64_m, R::R9, M::with_base_displ(R::R13, program.len() as i64)).unwrap());
    verify(s, &root_stub, Label::BootMaterialAuthOk, false);
    // Authenticate the exact arithmetic program before any crypto VM dispatch.
    // Domain record max-2 is distinct from material orchestration max-1.
    if let Some((_, program_va, program_len, crypto_tag)) = stub.crypto_vm_auth {
        branch(s, Code::Call_rel32_64, Label::BootCryptoTag);
        for byte in crypto_tag { p(s, I::with_declare_byte_1(byte)); }
        label(s, Label::BootCryptoTag);
        p(s, I::with1(Code::Pop_r64, R::R9).unwrap());
        index(s, u64::MAX - 2);
        init(s, &root_stub, Stage::Metadata, true);
        imm(s, R::RCX, program_va);
        imm(s, R::RDX, program_len);
        verify(s, &root_stub, Label::BootCryptoAuthOk, false);
    }
    if let Some((_, program_va, program_len, crypto_tag)) = stub.poly_vm_auth {
        branch(s, Code::Call_rel32_64, Label::BootPolyTag);
        for byte in crypto_tag { p(s, I::with_declare_byte_1(byte)); }
        label(s, Label::BootPolyTag);
        p(s, I::with1(Code::Pop_r64, R::R9).unwrap());
        index(s, u64::MAX - 3);
        init(s, &root_stub, Stage::Metadata, true);
        imm(s, R::RCX, program_va);
        imm(s, R::RDX, program_len);
        verify(s, &root_stub, Label::BootPolyAuthOk, false);
    }
    imm(s, R::R14, program.len() as u64);
    label(s, Label::BootMaterialLoop);
    p(s, I::with2(Code::Cmp_rm64_imm32, R::R14, 1).unwrap());
    branch(s, Code::Jb_rel32_64, Label::BootMaterialFail);
    p(s, I::with2(Code::Movzx_r32_rm8, R::EAX, M::with_base(R::R13)).unwrap());
    p(s, I::with2(Code::Cmp_rm32_imm32, R::EAX, HALT as u32).unwrap());
    branch(s, Code::Je_rel32_64, Label::BootMaterialHalt);
    p(s, I::with2(Code::Cmp_rm32_imm32, R::EAX, DERIVE as u32).unwrap());
    branch(s, Code::Jne_rel32_64, Label::BootMaterialFail);
    p(s, I::with2(Code::Cmp_rm64_imm32, R::R14, 9).unwrap());
    branch(s, Code::Jb_rel32_64, Label::BootMaterialFail);
    p(s, I::with2(Code::Mov_r32_rm32, R::R12D, M::with_base_displ(R::R13, 1)).unwrap());
    p(s, I::with2(Code::Mov_r32_rm32, R::R15D, M::with_base_displ(R::R13, 5)).unwrap());
    p(s, I::with2(Code::Cmp_rm32_imm32, R::R15D, (STAGES.len() * MATERIAL_STRIDE) as u32).unwrap());
    branch(s, Code::Jae_rel32_64, Label::BootMaterialFail);
    p(s, I::with2(Code::Test_rm32_imm32, R::R15D, (MATERIAL_STRIDE - 1) as u32).unwrap());
    branch(s, Code::Jne_rel32_64, Label::BootMaterialFail);
    p(s, I::with2(Code::Mov_r32_rm32, R::EAX, R::R15D).unwrap());
    p(s, I::with2(Code::Shr_rm32_imm8, R::EAX, 6).unwrap());
    p(s, I::with2(Code::Add_rm32_imm32, R::EAX, 0x4254_4701u32).unwrap());
    p(s, I::with2(Code::Cmp_r32_rm32, R::EAX, R::R12D).unwrap());
    branch(s, Code::Jne_rel32_64, Label::BootMaterialFail);
    // The handler owns only its approved 64-byte material slot.
    copy_key_nonce(s, stub, stub.seed_va);
    p(s, I::with2(Code::Xor_rm32_r32, M::with_base_displ(R::RDI, 0x28), R::R12D).unwrap());
    reset(s, stub, 0);
    imm(s, R::RCX, stub.chacha_material_va);
    p(s, I::with2(Code::Add_rm64_r64, R::RCX, R::R15).unwrap());
    imm(s, R::RDX, MATERIAL_STRIDE as u64);
    super::emit::emit_chacha_call(s, stub);
    p(s, I::with2(Code::Add_rm64_imm32, R::R13, 9).unwrap());
    p(s, I::with2(Code::Sub_rm64_imm32, R::R14, 9).unwrap());
    branch(s, Code::Jmp_rel32_64, Label::BootMaterialLoop);
    label(s, Label::BootMaterialHalt);
    p(s, I::with2(Code::Cmp_rm64_imm32, R::R14, 1).unwrap());
    branch(s, Code::Jne_rel32_64, Label::BootMaterialFail);
    branch(s, Code::Jmp_rel32_64, Label::BootMaterialDone);
    label(s, Label::BootMaterialFail);
    p(s, I::with(Code::Ud2));
    label(s, Label::BootMaterialDone);
    for r in [R::R15, R::R14, R::R13, R::R12] { p(s, I::with1(Code::Pop_r64, r).unwrap()); }
}
pub(crate) fn init(s: &mut Seq, stub: &BootStubCtx, stage: Stage, indexed: bool) {
    copy_key_nonce(s, stub, stub.chacha_material_va + stage.offset() as u64);
    if indexed {
        p(
            s,
            I::with2(Code::Xor_rm64_r64, M::with_base_displ(R::RDI, 0x28), R::R12).unwrap(),
        );
    }
}
pub(crate) fn index(s: &mut Seq, value: u64) {
    imm(s, R::R12, value);
}

/// RCX=bytes, RDX=len, R9=tag. Preserve loop state and input pointers across
/// native MAC calls. Counter 0 derives a unique MAC key; crypt begins at 1.
pub(crate) fn verify(s: &mut Seq, stub: &BootStubCtx, ok: Label, decrypt: bool) {
    p(s, I::with2(Code::Sub_rm64_imm32, R::RSP, 0x40).unwrap());
    for (r, off) in [(R::R11, 32), (R::RCX, 40), (R::RDX, 48), (R::R9, 56)] {
        p(
            s,
            I::with2(Code::Mov_rm64_r64, M::with_base_displ(R::RSP, off), r).unwrap(),
        );
    }
    imm(s, R::RAX, stub.poly_key_va);
    for off in [0, 8, 16, 24] {
        p(
            s,
            I::with2(Code::Mov_rm64_imm32, M::with_base_displ(R::RAX, off), 0).unwrap(),
        );
    }
    reset(s, stub, 0);
    imm(s, R::RCX, stub.poly_key_va);
    imm(s, R::RDX, 32);
    super::emit::emit_chacha_call(s, stub);
    p(
        s,
        I::with2(Code::Mov_r64_rm64, R::RCX, M::with_base_displ(R::RSP, 40)).unwrap(),
    );
    p(
        s,
        I::with2(Code::Mov_r64_rm64, R::RDX, M::with_base_displ(R::RSP, 48)).unwrap(),
    );
    imm(s, R::R8, stub.poly_key_va);
    p(
        s,
        I::with2(Code::Mov_r64_rm64, R::R9, M::with_base_displ(R::RSP, 56)).unwrap(),
    );
    p(
        s,
        I::with_branch(Code::Call_rel32_64, stub.poly_blob_va).unwrap(),
    );
    p(s, I::with2(Code::Test_rm64_r64, R::RAX, R::RAX).unwrap());
    s.push((I::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(ok)));
    p(s, I::with(Code::Ud2));
    s.push((I::with(Code::Nopd), Some(ok)));
    imm(s, R::RAX, stub.poly_key_va);
    for off in [0, 8, 16, 24] {
        p(
            s,
            I::with2(Code::Mov_rm64_imm32, M::with_base_displ(R::RAX, off), 0).unwrap(),
        );
    }
    reset(s, stub, 1);
    for (r, off) in [(R::R11, 32), (R::RCX, 40), (R::RDX, 48)] {
        p(
            s,
            I::with2(Code::Mov_r64_rm64, r, M::with_base_displ(R::RSP, off)).unwrap(),
        );
    }
    p(s, I::with2(Code::Add_rm64_imm32, R::RSP, 0x40).unwrap());
    if decrypt {
        super::emit::emit_chacha_call(s, stub);
    }
}
pub(crate) fn metadata(s: &mut Seq, stub: &BootStubCtx) {
    index(s, 0);
    init(s, stub, Stage::Metadata, true);
    imm(s, R::RCX, stub.runs_va.wrapping_sub(8));
    imm(s, R::RDX, 8 + u64::from(stub.num_runs) * ENTRY_SIZE as u64);
    imm(s, R::R9, stub.poly_runs_tag_va);
    verify(s, stub, Label::RunsMetadataOk, false);
    if stub.vm_oep {
        index(s, 1);
        init(s, stub, Stage::Metadata, true);
        imm(s, R::RCX, stub.vm_oep_text_runs_va.wrapping_sub(8));
        imm(
            s,
            R::RDX,
            if stub.vm_oep_text_runs_count == 0 {
                0
            } else {
                8 + u64::from(stub.vm_oep_text_runs_count) * ENTRY_SIZE as u64
            },
        );
        imm(s, R::R9, stub.poly_text_tag_va);
        verify(s, stub, Label::TextMetadataOk, false);
        // W^X/TLS profiles retain native code plaintext. Check it without
        // changing page permissions or pretending that it is confidential.
        index(s, u64::MAX);
        init(s, stub, Stage::NativeText, true);
        imm(s, R::RCX, stub.native_plain_text_va);
        imm(s, R::RDX, u64::from(stub.native_plain_text_len));
        imm(s, R::R9, stub.poly_plain_text_tag_va);
        verify(s, stub, Label::PlainTextAuthOk, false);
    }
}
pub(crate) fn resolver(s: &mut Seq, stub: &BootStubCtx) {
    if !stub.iat_enabled {
        return;
    }
    init(s, stub, Stage::Resolver, false);
    imm(s, R::RCX, stub.iat_table_va);
    imm(s, R::RDX, u64::from(stub.iat_table_len));
    imm(s, R::R9, stub.poly_resolver_tag_va);
    verify(s, stub, Label::ResolverAuthOk, true);
}

#[cfg(all(test, windows, target_arch = "x86_64"))]
mod tests {
    use super::*;
    #[test]
    fn native_stage_material_nonce_mac_and_decrypt_match_reference() {
        use crate::{
            pipeline::crypto::{self, stages},
            vm::arena::Arena,
        };
        let mut arena = Arena::new(0x40000).unwrap();
        let mut stub = crypto::tests::integrity_stub();
        let base = arena.base as u64;
        stub.boot_va = base;
        stub.anti_debug = false;
        stub.crypto_mode = crate::crypto::CryptoMode::ChaCha20;
        stub.chacha_blob_va = base + 0x10000;
        stub.poly_blob_va = base + 0x20000;
        stub.seed_va = base + 0x30000;
        stub.chacha_material_va = base + 0x31000;
        stub.chacha_state_va = base + 0x32000;
        stub.poly_key_va = base + 0x33000;
        let cipher_blob = crate::crypto::chacha20_native::emit_chacha20_blob(stub.chacha_state_va);
        let poly_blob = crate::crypto::poly1305_native::emit_poly1305_verify_blob(0);
        arena.bytes()[0x10000..0x10000 + cipher_blob.len()].copy_from_slice(&cipher_blob);
        arena.bytes()[0x20000..0x20000 + poly_blob.len()].copy_from_slice(&poly_blob);
        let seed = [0x39; 256];
        arena.bytes()[0x30000..0x30100].copy_from_slice(&seed);
        for vm in [false, true] {
        stub.boot_vm_tag = vm.then(|| stages::authenticate(&seed, Stage::Metadata,
            crate::vm::boot::material::MATERIAL_PROGRAM_RECORD, &crate::vm::boot::material::bytecode()));
        for stage in STAGES {
            for record in [0, 1, 3600, u64::MAX] {
                for len in [0, 1, 64, 65] {
                    arena.bytes()[0x31000..0x31000 + stages::MATERIAL_SIZE].fill(0);
                    let plain = vec![0x57; len];
                    let mut cipher = plain.clone();
                    let tag = stages::seal(&seed, stage, record, &mut cipher);
                    arena.bytes()[0x34000..0x34000 + len].copy_from_slice(&cipher);
                    arena.bytes()[0x35000..0x35010].copy_from_slice(&tag);
                    let mut seq = Vec::new();
                    let saved = [
                        R::RBX,
                        R::RBP,
                        R::RSI,
                        R::RDI,
                        R::R12,
                        R::R13,
                        R::R14,
                        R::R15,
                    ];
                    for r in saved {
                        p(&mut seq, I::with1(Code::Push_r64, r).unwrap());
                    }
                    p(
                        &mut seq,
                        I::with2(Code::Sub_rm64_imm32, R::RSP, 0x28).unwrap(),
                    );
                    prepare(&mut seq, &stub);
                    index(&mut seq, record);
                    init(&mut seq, &stub, stage, true);
                    imm(&mut seq, R::R11, 0x12345);
                    imm(&mut seq, R::RCX, base + 0x34000);
                    imm(&mut seq, R::RDX, len as u64);
                    imm(&mut seq, R::R9, base + 0x35000);
                    verify(&mut seq, &stub, Label::DataAuthOk, true);
                    imm(&mut seq, R::RAX, base + 0x36000);
                    p(
                        &mut seq,
                        I::with2(Code::Mov_rm64_r64, M::with_base(R::RAX), R::R11).unwrap(),
                    );
                    p(
                        &mut seq,
                        I::with2(Code::Add_rm64_imm32, R::RSP, 0x28).unwrap(),
                    );
                    for r in saved.into_iter().rev() {
                        p(&mut seq, I::with1(Code::Pop_r64, r).unwrap());
                    }
                    p(&mut seq, I::with(Code::Retnq));
                    let code = crypto::encode::encode_rc4_block(&mut seq, &stub).unwrap();
                    assert!(code.len() < 0x10000);
                    arena.bytes()[..code.len()].copy_from_slice(&code);
                    let call: extern "system" fn() = unsafe { std::mem::transmute(arena.base) };
                    call();
                    assert_eq!(&arena.bytes()[0x34000..0x34000 + len], plain);
                    assert_eq!(
                        u64::from_le_bytes(arena.bytes()[0x36000..0x36008].try_into().unwrap()),
                        0x12345
                    );
                    assert!(arena.bytes()[0x33000..0x33020]
                        .iter()
                        .all(|byte| *byte == 0));
                    for domain in STAGES {
                        let offset = 0x31000 + domain.offset();
                        assert_eq!(
                            &arena.bytes()[offset..offset + 64],
                            &stages::material(&seed, domain)
                        );
                    }
                }
            }
        }
        }
    }
}
