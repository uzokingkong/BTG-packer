// ==============================================================================
// BTG - boot-stub build orchestrators - split from bootstub.rs
// ==============================================================================
// Public entry points: build_anti_debug_raw_block (static byte blob) and
// build_rc4_block (orchestrates the full RC4 boot stub).
// ==============================================================================

use super::emit::{emit_base_bind_loop, emit_c1_init, emit_code_decrypt, emit_dispatcher_entry,
    emit_ksa_init, emit_rest_decrypt, emit_run_decrypt, emit_self_wipe, trashformer_junk};
use super::ctx::BootStubCtx;
use super::super::{cipher, encode, iat, integrity, memharden, payload, vm_embed};
use iced_x86::{Code, Instruction, Register};

pub(crate) fn build_anti_debug_raw_block() -> Vec<u8> {
    vec![
        0x9C, // pushfq
        0x50, // push rax
        // mov rax, gs:[0x60] (PEB)
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        // movzx eax, byte [rax+2] (BeingDebugged)
        0x0F, 0xB6, 0x40, 0x02,
        // test eax, eax
        0x85, 0xC0,
        // jnz +0x32 → ud2
        0x75, 0x32,
        // mov rax, gs:[0x60]
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        // mov eax, [rax+0xBC] (NtGlobalFlag)
        0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00,
        // and eax, 0x70
        0x25, 0x70, 0x00, 0x00, 0x00,
        // jnz +0x1C → ud2
        0x75, 0x1C,
        // mov rax, gs:[0x60]
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        // mov rax, [rax+0x30] (ProcessHeap)
        0x48, 0x8B, 0x40, 0x30,
        // mov eax, [rax+0x70] (Heap.Flags)
        0x8B, 0x80, 0x70, 0x00, 0x00, 0x00,
        // and eax, 0x70
        0x25, 0x70, 0x00, 0x00, 0x00,
        // jnz +0x02 → ud2
        0x75, 0x02,
        // jmp +0x02 → restore
        0xEB, 0x02,
        // ud2
        0x0F, 0x0B,
        0x58, // pop rax
        0x9D, // popfq
    ]
}

/// v19: VM PRGA 호출 시퀀스. 호출 시점에 RCX=buf, RDX=len (네이티브 규약)이
/// 준비되어 있다고 가정한다. PRGA VM 상태의 ptr_sbox(0x110)는 엔트리 스텁이
/// RBX에서 스냅샷하므로, 여기서는 ptr_buf/RDX와 v3(len)/R8만 세팅해 엔트리 호출.
/// (i/j는 VM 상태 v0/v1에 지속 — 첫 호출 전 emit_prga_vm_init으로 0 초기화)

pub(crate) fn build_rc4_block(stub: &BootStubCtx) -> Vec<u8> {
    // ── 1. 명령어 목록 구성 ────────────────────────────────────────────────────────────────
    // (inst, Option<분기 레이블>)
    let mut seq: Vec<(Instruction, Option<super::ctx::Label>)> = Vec::new();

    // Native OEP register save + M6 Phase-2 program VM state capture.
    vm_embed::emit_native_entry_save(&mut seq, stub);
    vm_embed::emit_program_vm_state_capture(&mut seq, stub);

    // 스택에 S-box 할당 (v6: 외부 API 호출 시 16B 정렬 프레임 사용)
    seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, stub.stack_frame).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP).unwrap(), None));

    // v17 (TrashFormer-기반): 프로시저 서문에 데드 레지스터 정크 명령을 삽입해,
    // 부트 스텁 바이트가 **빌드마다 달라지게** 한다. 이 지점에선 rax/rcx/rdx/rsi/rdi/
    // r8..r11 이 전부 아직 라이브가 아니므로(KSA/복호화가 뒤에서 덮어씀) 마음대로
    // clobber해도 안전하다. rbx/rsp는 보존. 시드는 k1^k2^k3(패킹마다 랜덤)에서
    // 유도한 결정적 PRNG라, 같은 패킹의 sizing/최종 패스는 항상 동일한 정크를 내고
    // 서로 다른 패킹은 다른 바이트를 낸다 → 정적 시그니처/스크립트 재사용 무력화.
    for junk in trashformer_junk(stub.k1 ^ stub.k2 ^ stub.k3) {
        seq.push((junk, None));
    }

    // v19: base-bound key — 시드를 실제 로드 base로 바인딩 (재배치/rehost 방해).
    // no_crypto 경로에는 시드가 없으므로 crypto 경로에서만 수행.
    if !stub.no_crypto {
        emit_base_bind_loop(&mut seq, stub.seed_va);
    }

    // v60 (--custom-cipher): BTG-C1 경로는 RC4 KSA 대신 C1 상태 초기화를 수행한다.
    // (chained/vm-oep는 RC4 전용 — c1_mode는 place.rs가 비활성화해 이 분기에
    //  도달하지 않는다.) v61: --vm과 함께면 C1 상태 초기화를 VM으로 virtualize
    //  (emit_ksa_init의 c1_mode && vm 분기), 아니면 네이티브 emit_c1_init.
    if stub.c1_mode {
        if stub.vm {
            emit_ksa_init(&mut seq, stub);
        } else {
            emit_c1_init(&mut seq, stub);
        }
    } else {
        emit_ksa_init(&mut seq, stub);
    }
    payload::emit_payload_copy(&mut seq, stub);
    emit_code_decrypt(&mut seq, stub);
    integrity::emit_integrity_crc(&mut seq, stub);
    emit_run_decrypt(&mut seq, stub);
    emit_rest_decrypt(&mut seq, stub);
    iat::emit_iat_slots(&mut seq, stub);
    iat::emit_iat_resolve(&mut seq, stub);
    emit_self_wipe(&mut seq, stub);
    memharden::emit_mem_harden(&mut seq, stub);
    emit_dispatcher_entry(&mut seq, stub);
    cipher::emit_prga_sub(&mut seq, stub);
    cipher::emit_ksa_sub(&mut seq, stub);
    cipher::emit_zeromem_sub(&mut seq, stub);
    encode::encode_rc4_block(&mut seq, stub)
}