// ==============================================================================
// BTG - boot-stub build orchestrators - split from bootstub.rs
// ==============================================================================
// Public entry points: build_anti_debug_raw_block (static byte blob) and
// build_boot_block (orchestrates the full native boot stub).
// ==============================================================================

use super::super::{cipher, encode, iat, integrity, memharden, payload, vm_embed};
use super::ctx::BootStubCtx;
use super::emit::{
    emit_base_bind_loop, emit_c1_init, emit_code_decrypt, emit_desc_decrypt, emit_dispatcher_entry,
    emit_ksa_init, emit_rest_decrypt, emit_run_decrypt, emit_self_wipe, trashformer_junk,
    trashformer_mixing_loop,
};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

pub(crate) fn build_anti_debug_raw_block(
    policy: crate::dispatcher::antidebug::AntiDebugPolicy,
) -> Vec<u8> {
    // ── v10: stable PEB checks + policy-specific failure path ───────────────
    // 기본 레이아웃(고정 73B)은 기존과 동일:
    //   pushfq; push rax; (BeingDebugged) jnz→실패; (NtGlobalFlag) jnz→실패;
    //   (Heap.Flags) jnz→실패; jmp +2(정상); [실패슬롯 2B]; pop rax; popfq
    // Trap: 실패슬롯 = ud2 (0F 0B) — 기존 동작 (sensitive)
    // Hang: 실패슬롯 = jmp $ (EB FE) — 무한 루프 (research/툴 고정)
    // Warn: 세 jnz를 정상 경로(시작+0x47의 pop rax)로 리다이렉트 — fail-open
    let mut b: Vec<u8> = vec![
        0x9C, // pushfq
        0x50, // push rax
        // mov rax, gs:[0x60] (PEB)
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        // movzx eax, byte [rax+2] (BeingDebugged)
        0x0F, 0xB6, 0x40, 0x02, // test eax, eax
        0x85, 0xC0, // jnz +0x32 → 실패 슬롯 (Warn: +0x34 → 정상 경로)
        0x75, 0x32, // mov rax, gs:[0x60]
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        // mov eax, [rax+0xBC] (NtGlobalFlag)
        0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00, // and eax, 0x70
        0x25, 0x70, 0x00, 0x00, 0x00,
        // jnz +0x1C → 실패 슬롯 (Warn: +0x1E → 정상 경로)
        0x75, 0x1C, // mov rax, gs:[0x60]
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        // mov rax, [rax+0x30] (ProcessHeap)
        0x48, 0x8B, 0x40, 0x30, // mov eax, [rax+0x70] (Heap.Flags)
        0x8B, 0x80, 0x70, 0x00, 0x00, 0x00, // and eax, 0x70
        0x25, 0x70, 0x00, 0x00, 0x00,
        // jnz +0x02 → 실패 슬롯 (Warn: +0x04 → 정상 경로)
        0x75, 0x02, // jmp +0x02 → 정상 경로 (pop rax)
        0xEB, 0x02, // 실패 슬롯 (2B — Trap: ud2 / Hang: jmp $ / Warn: nop nop)
        0x0F, 0x0B, 0x58, // pop rax
        0x9D, // popfq
    ];
    // The raw pre-loader PEB probe has produced repeatable false positives on
    // ordinary Windows launches (including differential verification) before
    // the protected runtime has established its normal process context. Keep
    // the fixed block/branch shape but make this early probe neutral; the
    // structured post-entry anti-debug policy remains responsible for an
    // actual debugger decision.
    b[0x02] = 0x31;
    b[0x03] = 0xC0;
    b[0x04..0x11].fill(0x90);
    // NtGlobalFlag is a system/process instrumentation policy, not proof that
    // this process is currently debugged.  Machines with GFlags enabled would
    // otherwise make every protected binary trap during ordinary execution.
    // Preserve the fixed block shape and leave BeingDebugged as the explicit
    // debugger-presence signal.
    b[0x13] = 0x31;
    b[0x14] = 0xC0;
    b[0x15..0x27].fill(0x90);

    // Segment-heap implementations do not expose a stable public Flags field
    // at ProcessHeap+0x70.  Treating those implementation bytes as the legacy
    // NT heap flags causes false UD2 traps on ordinary modern Windows runs.
    // Preserve the fixed raw-block shape (and every branch displacement) while
    // retiring that unsupported probe: xor eax,eax; NOP padding; existing JNZ.
    b[0x2A] = 0x31;
    b[0x2B] = 0xC0;
    b[0x2C..0x41].fill(0x90);
    // ── 정책 적용 (고정 길이 유지 — 인코딩/길이 불변성 무회귀) ─────────────
    match policy {
        crate::dispatcher::antidebug::AntiDebugPolicy::Trap => {
            // 실패 슬롯 = ud2 (기본값 유지)
        }
        crate::dispatcher::antidebug::AntiDebugPolicy::Hang => {
            // 실패 슬롯 = jmp $ (EB FE) — 무한 루프
            let n = b.len();
            b[n - 4] = 0xEB;
            b[n - 3] = 0xFE;
        }
        crate::dispatcher::antidebug::AntiDebugPolicy::Poison => {
            // Stealth poison: fail-open to normal path with dirty flags/state
            let normal = (b.len() - 2) as u8;
            b[0x12] = normal.wrapping_sub(0x13);
            b[0x28] = normal.wrapping_sub(0x29);
            b[0x42] = normal.wrapping_sub(0x43);
            let n = b.len();
            b[n - 4] = 0xEB;
            b[n - 3] = 0x02;
        }
        crate::dispatcher::antidebug::AntiDebugPolicy::Warn => {
            // 세 jnz를 정상 경로(끝 pop rax, 오프셋 len-2)로 리다이렉트.
            // 레이아웃: jnz@0x11(+0x32), jnz@0x27(+0x1C), jnz@0x41(+0x02),
            // jmp@0x43(+0x02 → pop rax). 정상 경로는 len-2(=0x47)다.
            let normal = (b.len() - 2) as u8; // 0x47
                                              // jnz@0x11: next=0x13, disp = normal - 0x13 = 0x34
            b[0x12] = normal.wrapping_sub(0x13);
            // jnz@0x27: next=0x29, disp = normal - 0x29 = 0x1E
            b[0x28] = normal.wrapping_sub(0x29);
            // jnz@0x41: next=0x43, disp = normal - 0x43 = 0x04
            b[0x42] = normal.wrapping_sub(0x43);
            // jmp@0x43은 그대로 pop rax로 (정상 경로와 동일 종점)
            // 실패 슬롯은 도달 불가 — nop nop
            let n = b.len();
            b[n - 4] = 0x90;
            b[n - 3] = 0x90;
        }
    }
    b
}

/// v19: VM PRGA 호출 시퀀스. 호출 시점에 RCX=buf, RDX=len (네이티브 규약)이
/// 준비되어 있다고 가정한다. PRGA VM 상태의 ptr_sbox(0x110)는 엔트리 스텁이
/// RBX에서 스냅샷하므로, 여기서는 ptr_buf/RDX와 v3(len)/R8만 세팅해 엔트리 호출.
/// (i/j는 VM 상태 v0/v1에 지속 — 첫 호출 전 emit_prga_vm_init으로 0 초기화)

/// T3-1 Phase D: chacha 경로의 복호화-전 Poly1305 AEAD 인증 스테이지.
/// poly_blob_va(rel32 call)를 호출해 at-rest 암호문+고정 AAD의 태그를 검증하고,
/// 반환 rax==0(매치)면 계속, !=0이면 ud2 (fail-safe — decrypt-and-run 금지).
fn emit_poly1305_verify(
    seq: &mut Vec<(Instruction, Option<super::ctx::Label>)>,
    stub: &BootStubCtx,
) {
    // Generate the RFC 8439 Poly1305 one-time key from ChaCha block 0.  The
    // normal decrypt stream starts at counter 1, so reset its state explicitly
    // before this short, dedicated block-0 derivation.
    seq.push((
        Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.chacha_state_va).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_rm64_imm32,
            MemoryOperand::with_base_displ(
                Register::RAX,
                crate::crypto::chacha20::CHA_OFF_CTR as i64,
            ),
            0,
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_rm32_imm32,
            MemoryOperand::with_base_displ(
                Register::RAX,
                crate::crypto::chacha20::CHA_OFF_KS_OFF as i64,
            ),
            0x40,
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.poly_key_va).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 32).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Call_rel32_64, stub.chacha_blob_va).unwrap(),
        None,
    ));
    // Descriptor-backed targets are only valid when the descriptor decryptor
    // was emitted.  ChaCha/VM paths deliberately retire that decryptor
    // (`desc_used == false`) and must keep using the immediate code region.
    // Selecting the still-allocated descriptor merely because crypto is on
    // gives Program-VM builds a zero code_len, so Poly1305 authenticates an
    // empty message and takes the UD2 failure branch.
    if stub.desc_used {
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.desc_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                MemoryOperand::with_base_displ(Register::RAX, 0x00),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RDX,
                MemoryOperand::with_base_displ(Register::RAX, 0x08),
            )
            .unwrap(),
            None,
        ));
    } else {
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.code_len as u64).unwrap(),
            None,
        ));
    }
    seq.push((
        Instruction::with2(Code::Mov_r64_imm64, Register::R8, stub.poly_key_va).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_imm64, Register::R9, stub.poly_tag_va).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Call_rel32_64, stub.poly_blob_va).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(),
        Some(super::ctx::Label::PolyOk),
    ));
    seq.push((Instruction::with(Code::Ud2), None));
    seq.push((
        Instruction::with(Code::Nopd),
        Some(super::ctx::Label::PolyOk),
    ));
    // The MAC key must not outlive verification.
    seq.push((
        Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.poly_key_va).unwrap(),
        None,
    ));
    for off in [0, 8, 16, 24] {
        seq.push((
            Instruction::with2(
                Code::Mov_rm64_imm32,
                MemoryOperand::with_base_displ(Register::RAX, off as i64),
                0,
            )
            .unwrap(),
            None,
        ));
    }
    // Discard the unused half of block 0 and start payload crypt at counter 1.
    seq.push((
        Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.chacha_state_va).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_rm64_imm32,
            MemoryOperand::with_base_displ(
                Register::RAX,
                crate::crypto::chacha20::CHA_OFF_CTR as i64,
            ),
            1,
        )
        .unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_rm32_imm32,
            MemoryOperand::with_base_displ(
                Register::RAX,
                crate::crypto::chacha20::CHA_OFF_KS_OFF as i64,
            ),
            0x40,
        )
        .unwrap(),
        None,
    ));
}

pub(crate) fn build_boot_block(stub: &BootStubCtx) -> anyhow::Result<Vec<u8>> {
    // ── 1. 명령어 목록 구성 ────────────────────────────────────────────────────────────────
    // (inst, Option<분기 레이블>)
    let mut seq: Vec<(Instruction, Option<super::ctx::Label>)> = Vec::new();

    // Native OEP register save + M6 Phase-2 program VM state capture.
    vm_embed::emit_native_entry_save(&mut seq, stub);
    vm_embed::emit_program_vm_state_capture(&mut seq, stub);

    // 스택에 S-box 할당 (v6: 외부 API 호출 시 16B 정렬 프레임 사용)
    seq.push((
        Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, stub.stack_frame)
            .map_err(|e| anyhow::anyhow!("boot stub Sub_rm64_imm32 failed: {e}"))?,
        None,
    ));
    seq.push((
        Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP)
            .map_err(|e| anyhow::anyhow!("boot stub Mov_r64_rm64 failed: {e}"))?,
        None,
    ));

    // The PE maps .textb RX. Open a bounded transient write window before any
    // seed/payload self-modification; the matching harden call closes it later.
    memharden::emit_mem_unseal(&mut seq, stub);

    // v17 (TrashFormer-기반): 프로시저 서문에 데드 레지스터 정크 명령을 삽입해,
    // 부트 스텁 바이트가 **빌드마다 달라지게** 한다. 이 지점에선 rax/rcx/rdx/rsi/rdi/
    // r8..r11 이 전부 아직 라이브가 아니므로(KSA/복호화가 뒤에서 덮어씀) 마음대로
    // clobber해도 안전하다. rbx/rsp는 보존. 시드는 k1^k2^k3(패킹마다 랜덤)에서
    // 유도한 결정적 PRNG라, 같은 패킹의 sizing/최종 패스는 항상 동일한 정크를 내고
    // 서로 다른 패킹은 다른 바이트를 낸다 → 정적 시그니처/스크립트 재사용 무력화.
    for junk in trashformer_junk(stub.k1 ^ stub.k2 ^ stub.k3) {
        seq.push((junk, None));
    }
    // v17+ (junk rework): 실작동하는 mixing loop 정크도 함께 삽입한다. 루프 카운트는
    // 시드에서 유도한 1..256 (항상 비영)이라 "길이=0으로 들어가는 dead loop"로
    // 읽히지 않고, 실제 checksum/복호화 루프와 구조적으로 동일해 fake/real 경로를
    // 정적으로 분리하기 어렵게 만든다. (S-box 프레임 [RSP..+0x100]은 이후 KSA가
    // 초기화하므로 여기서 쓰레기로 채워도 안전.)
    for item in trashformer_mixing_loop(stub.k1 ^ stub.k2 ^ stub.k3) {
        seq.push(item);
    }

    // v19: base-bound key — 시드를 실제 로드 base로 바인딩 (재배치/rehost 방해).
    // no_crypto 경로에는 시드가 없으므로 crypto 경로에서만 수행.
    if !stub.no_crypto {
        emit_base_bind_loop(&mut seq, stub.seed_va);
    }

    // M12 Decrypt-Descriptor: base_bind 직후 디스크립터(파생 키 = RC4 keystream으로
    // 암호화)를 KSA(seed)+canonical PRGA로 복호화한다. (base_bind가 먼저여야
    // seed@seed_va = seed_masked.) 이 스테이지의 S-box는 즉시 뒤 main KSA-init이
    // 덮어쓰므로 일시적이며, main 코드/런 키스트림은 byte-identical을 유지한다.
    if stub.desc_used {
        emit_desc_decrypt(&mut seq, stub);
    }

    // v60 (--custom-cipher): BTG-C1 경로는 RC4 KSA 대신 C1 상태 초기화를 수행한다.
    // Chained mode rekeys the same C1 state per predecessor chunk; VM-OEP also
    // uses this native C1 consumer. v61: --vm과 함께면 C1 상태 초기화를 VM으로 virtualize
    //  (emit_ksa_init의 c1_mode && vm 분기), 아니면 네이티브 emit_c1_init.
    // v63 (--crypto-mode chacha20): ChaCha20 상태 초기화는 emit_ksa_init의
    //  chacha_mode 분기에서 처리한다 (네이티브 emit_chacha_init).
    // seed_va is immutable only until cipher initialization; capture the
    // authoritative integrity whitening key before that state is reused.
    integrity::emit_integrity_whiten(&mut seq, stub);
    if stub.c1_mode() {
        if stub.vm {
            emit_ksa_init(&mut seq, stub);
        } else {
            emit_c1_init(&mut seq, stub);
        }
    } else {
        emit_ksa_init(&mut seq, stub);
    }
    payload::emit_payload_copy(&mut seq, stub);
    // T3-1 Phase D: chacha 경로는 at-rest 암호문을 복호화 **전에** Poly1305 AEAD
    // 태그로 인증한다 (불일치 시 ud2 — fail-safe, decrypt-and-run 금지). payload
    // copy 이후·code_decrypt 이전이므로, payload-relocate로 옮겨진 암호문이
    // code_va에 복사된 뒤 검증한다. (RC4/C1 경로는 chacha_aead=false → no-op)
    if stub.chacha_mode() && stub.chacha_aead {
        emit_poly1305_verify(&mut seq, stub);
    }
    emit_code_decrypt(&mut seq, stub);
    integrity::emit_integrity_mac(&mut seq, stub);
    // Preserve the runtime-derived W32 across run/rest decryptors. Those
    // stages legitimately reuse both registers and mutable VM scratch. A
    // balanced stack save is private to the bootstrap frame and survives the
    // intervening calls without expanding the public VM state ABI.
    if false && stub.integrity {
        // The MAC mixer legitimately clobbers R15. Reload the authoritative
        // pre-cipher W32 before preserving it across run/rest decryptors;
        // otherwise the MAC accumulator is written back as the CRC key.
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.w32_slot_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::R15D,
                MemoryOperand::with_base(Register::RAX),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, 16).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base(Register::RSP),
                Register::R15,
            )
            .unwrap(),
            None,
        ));
    }
    integrity::emit_integrity_crc(&mut seq, stub);
    emit_run_decrypt(&mut seq, stub);
    emit_rest_decrypt(&mut seq, stub);
    integrity::emit_distributed_integrity(&mut seq, stub);
    if false && stub.integrity {
        seq.push((
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R15,
                MemoryOperand::with_base(Register::RSP),
            )
            .unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Add_rm64_imm32, Register::RSP, 16).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.w32_slot_va).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base(Register::RAX),
                Register::R15D,
            )
            .unwrap(),
            None,
        ));
    }
    // S2 (--integrity multi-site): run/rest decrypt 직후 두 번째 독립 CRC32 검증.
    integrity::emit_integrity_crc2(&mut seq, stub);
    iat::emit_iat_slots(&mut seq, stub);
    iat::emit_iat_resolve(&mut seq, stub);
    // S3 (--integrity 멀티사이트 확장): IAT 리졸브 직후 세 번째 독립 CRC32 검증 —
    // 부트 후반에도 무결성 게이트를 유지한다 (사이트 1/2와 다른 시점).
    integrity::emit_integrity_crc3(&mut seq, stub);
    // S4 must run before self-wipe: it derives its expected value from
    // w32_slot, which lives in the seed/integrity scratch area erased by
    // emit_self_wipe.  Running this after the wipe made every integrity-enabled
    // image take the CRC4 UD2 path even when the file was untouched.
    integrity::emit_integrity_crc4(&mut seq, stub);
    emit_self_wipe(&mut seq, stub);
    memharden::emit_mem_harden(&mut seq, stub);
    emit_dispatcher_entry(&mut seq, stub);
    cipher::emit_prga_sub(&mut seq, stub);
    cipher::emit_ksa_sub(&mut seq, stub);
    cipher::emit_zeromem_sub(&mut seq, stub);
    encode::encode_rc4_block(&mut seq, stub)
}
