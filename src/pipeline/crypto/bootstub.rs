// ==============================================================================
// Boot-stub machine-code generation (RC4 boot stub for the composite VM layer)
// ==============================================================================

use super::{cipher, encode, iat, integrity, memharden, payload, vm_embed};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

#[derive(Clone, Copy)]
pub(crate) struct BootStubCtx {
    pub(crate) boot_va: u64,          // 부트 스텁 시작 VA
    pub(crate) anti_debug: bool,
    pub(crate) dispatcher_va: u64,    // 디스패처 본체 (섹션 + 0x20)
    pub(crate) code_va: u64,
    pub(crate) code_len: u32,
    pub(crate) runs_va: u64,
    pub(crate) num_runs: u32,
    pub(crate) seed_va: u64,
    pub(crate) k1: u32,
    pub(crate) k2: u32,
    pub(crate) k3: u32,
    pub(crate) entry_block_id: u32,
    pub(crate) entry_seed: u32,
    // ── v3-composite VM ──────────────────────────────────────────────────────
    /// true = S-box init + KSA는 VM이 실행 (KSA 루프 대신 VM 엔트리 호출)
    pub(crate) vm: bool,
    /// VM 엔트리 스텁 VA (0이면 미배치)
    pub(crate) vm_entry_va: u64,
    /// VM 상태 버퍼 VA (부트 스텁이 RCX로 전달)
    pub(crate) vm_state_va: u64,
    // ── v19: PRGA VM (RC4 키스트림 생성 루프) ─────────────────────────────
    /// true = 문자열/코드 영역 복호화(PRGA)도 VM으로 lift (vm과 함께)
    pub(crate) vm_prga: bool,
    /// PRGA VM 엔트리 스텁 VA (0이면 미배치)
    pub(crate) vm_prga_entry_va: u64,
    /// PRGA VM 상태 버퍼 VA (i/j가 여기 v0/v1로 유지됨)
    pub(crate) vm_prga_state_va: u64,
    // ── M6 Phase-2: 프로그램 VM (OEP→VM entry 전환) ─────────────────────
    /// true = 부트 스텁이 원본 .text를 평문 복호화하지 않고 lift된 프로그램 VM으로 디스패치
    pub(crate) vm_oep: bool,
    /// 프로그램 VM 엔트리 스텁 VA (0이면 미배치)
    pub(crate) vm_prog_entry_va: u64,
    /// 프로그램 VM 상태 버퍼 VA (부트 스텁이 초기화 후 디스패치)
    pub(crate) vm_prog_state_va: u64,
    /// true = 원본 프로그램 entry 블록이 제외(네이티브 유지)되어, 부트 스텁이
    /// 프로그램 VM 디스패처 대신 로더가 준 레지스터/RFLAGS/RSP를 정확히 복원한 뒤
    /// 네이티브 OEP로 tail-jump한다.
    pub(crate) vm_oep_native_entry: bool,
    /// clean native entry가 사용할 원본 OEP VA (entry_point_rva + image_base).
    pub(crate) vm_oep_native_va: u64,
    // ── M6 Phase-2.3 (--vm-oep at-rest encryption) ────────────────────────
    /// Program VM 바이트코드 VA/길이. 파일에는 at-rest 암호화로 저장되고, 부트
    /// 스텁이 디스패치 직전 fresh RC4(seed)로 복호화한다. (0이면 비활성)
    pub(crate) vm_oep_bc_va: u64,
    pub(crate) vm_oep_bc_len: u32,
    /// 보존된 원본 .text VA/길이. TLS 콜백이 없는 타깃에서만 at-rest 암호화해,
    /// 로더가 부트 전에 실행하는 콜백이 평문을 보게 하지 않으면서 정적 분석에서
    /// 원본 .text 평문 노출을 제거한다. (0이면 비활성)
    pub(crate) vm_oep_text_va: u64,
    pub(crate) vm_oep_text_len: u32,
    /// P5: pointer to the .text at-rest decrypt run-table (array of {va:u64, len:u64} pairs),
    /// covering exactly the non-TLS `.text` regions encrypted at rest. The boot stub decrypts
    /// these runs (fresh RC4 seed keystream) in order, then the program-VM bytecode, so the
    /// TLS-callback functions the loader runs pre-boot stay plaintext. (0 / 0 = no-op.)
    pub(crate) vm_oep_text_runs_va: u64,
    pub(crate) vm_oep_text_runs_count: u32,

    // ── v7 chained-crypto ──────────────────────────────────────────────────
    /// true = RC4를 256B 청크 단위로 재키잉해 순차 복호화
    /// (Key_i = 이전 청크 평문, chunk0 = seed anchor → skip-ahead 불가)
    pub(crate) chained: bool,
    // ── v8 Phase 0.3: 디스패처 재암호화 ─────────────────────────────────────────
    /// true = 코드 영역 일괄 복호화를 생략한다. 블록은 개별 암호화 상태로 남고,
    /// 디스패처가 매 디스패치마다 타깃 블록을 복호화/직전 블록을 재암호화한다.
    /// 문자열 런/리졸브 테이블은 여전히 이 스텁이 복호화한다. 첫 디스패치에
    /// 직전 블록이 없음을 알리는 current=0xFFFFFFFF 센티널을 추가로 push한다.
    pub(crate) reencrypt: bool,
    // ── v9: crypto-off 부트 스텁 ───────────────────────────────────────────────
    /// true = RC4 키 스케줄/코드 영역/문자열 런 복호화를 모두 생략하고,
    /// 안티디버그 + 페이로드 복사 + IAT 해석 + 메모리 하드닝 + 디스패치만 수행한다.
    /// (--no-crypto + --iat-hide/--mem-harden/--payload-relocate 시)
    pub(crate) no_crypto: bool,
    // ── v4 payload-relocate ──────────────────────────────────────────────────
    /// 암호화된 코드 페이로드가 저장된 데이터 섹션 VA (0 = 비활성)
    pub(crate) payload_va: u64,
    /// 복사할 페이로드 길이 (바이트)
    pub(crate) payload_len: u32,
    // ── v5 integrity (--integrity) ───────────────────────────────────────────
    /// true = 복호화 후 코드 영역 CRC32 검증, 불일치 시 ud2
    pub(crate) integrity: bool,
    /// 저장된 CRC32 값의 VA (4바이트, seed 뒤)
    pub(crate) crc_va: u64,
    // ── v6 IAT hiding (--iat-hide) ───────────────────────────────────────────
    /// true = 복호화 후 리졸브 테이블을 따라 원본 IAT 슬롯을 채운다
    pub(crate) iat_enabled: bool,
    /// 리졸브 테이블 VA (RC4 run으로 복호화됨)
    pub(crate) iat_table_va: u64,
    /// 더미 import IAT 슬롯 VA (LoadLibraryA / GetProcAddress 주소)
    pub(crate) iat_ll_slot_va: u64,
    pub(crate) iat_gpa_slot_va: u64,
    // ── v6 memory hardening (--mem-harden) ───────────────────────────────────
    /// true = 복호화 후 .textb를 RWX->RX로 전환 (NtProtectVirtualMemory)
    pub(crate) mem_harden: bool,
    /// "ntdll.dll" / "NtProtectVirtualMemory" 문자열 VA (부트 영역)
    pub(crate) mem_ntdll_name_va: u64,
    pub(crate) mem_ntprot_name_va: u64,
    /// 보호할 .textb 영역 (페이지 정렬 base / 페이지 라운드업 크기)
    pub(crate) mem_code_base: u64,
    pub(crate) mem_code_size: u64,
    /// 스택 프레임 크기 — 외부 API 호출 시 16B 정렬 보장(0x138), 아니면 0x118
    pub(crate) stack_frame: u32,
    // ── v14: import 이름 per-entry MBA 키 (다층 2단계) ─────────────────────
    /// 리졸브 테이블 이름 XOR 키 유도용 마스터 상수 (ctx.mba_constant)
    pub(crate) mba_master: u32,
    /// 리졸브 테이블 이름 XOR 키 유도용 MBA 상수
    pub(crate) mba_c: u32,
}

/// import 이름 XOR용 MBA 상수 (패커/부트 스텁 공유 — mba_xor와 동일)

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]

pub(crate) enum Label {
    // ── C-1 (--vm-oep): 프로그램 VM state 버퍼 0-초기화 ──
    StateZeroLoop,
    StateZeroDone,
    InitLoop,
    KsaLoop,
    RunLoop,
    RunDone,
    Prga,
    PrgaLoop,
    PrgaDone,
    TextRunLoop,
    TextRunDone,

    // ── v19: base-bound key (rebase/rehost 방해) ──
    BaseBindLoop,
    // ── v5 integrity: CRC32 검증 루프 ──
    CrcLoop,
    CrcBit,
    CrcSkip,
    CrcDone,
    CrcOk,
    // ── v6 IAT resolve ──
    DllLoop,
    FuncLoop,
    FuncOrdinal,
    FuncCall,
    DllNext,
    ResolveDone,
    // ── v6 mem-harden ──
    MemDone,
    // ── v4 payload-relocate: .vdata → 코드 영역 복사 루프 ──
    PayloadCopyLoop,
    PayloadCopyDone,
    // ── v7 chained-crypto (256B 청크 순차 복호화) ──
    Ksa,
    KsaInitLoop,
    KsaLoopK,
    ChainLoop,
    ChainDone,
    ChainKeyOk,
    StrKeyUseWindow,
    StrKeyHave,
    ZeroMem,
    ZeroDone,
    // ── v7 Phase 0.1: 환경 인증 (실패 시 시드 변조) ──
    AttestFail,
    AttestMutLoop,
    AttestOk,
    AttestTiming,
    // ── v14: import 이름 per-entry MBA un-XOR 루프 (dll / func 각각) ──
    UxDllMain,
    UxDllTail,
    UxDllDone,
    UxFuncMain,
    UxFuncTail,
    UxFuncDone,
}

/// v10: vm/ksa.rs의 KsaLabel → 부트 스텁 Label 매핑 (단일 KSA 소스 공유).

fn map_ksa_label(l: crate::vm::ksa::KsaLabel) -> Label {
    match l {
        crate::vm::ksa::KsaLabel::InitLoop => Label::InitLoop,
        crate::vm::ksa::KsaLabel::KsaLoop => Label::KsaLoop,
    }
}

/// 단일 Instruction을 어셈블해 정확한 인코딩 길이를 측정한다.
/// 상대 분기는 rel32 형태이므로 타깃 값과 무관하게 길이가 고정된다.

pub(crate) fn base_bind_byte(base: u64) -> u8 {
    (((base >> 16) ^ (base >> 24) ^ (base >> 32)) & 0xFF) as u8
}

/// v19: 부트 스텁용 base-XOR 루프 생성. PEB.ImageBaseAddress(실제 로드 base)를 읽어
/// `base_bind_byte`와 같은 바이트를 유도하고, 시드(seed_va, 256B)를 그 바이트로 XOR.
/// 사용 레지스터(rax/rdx/rcx/r8/rsi/rdi)는 이후 KSA/PRGA가 다시 초기화하므로 안전.

fn emit_base_bind_loop(seq: &mut Vec<(Instruction, Option<Label>)>, seed_va: u64) {
    use iced_x86::MemoryOperand as M;
    // rax = PEB (gs:[0x60])
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
        MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None));
    // rax = PEB.ImageBaseAddress (offset 0x10)
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
        M::with_base_displ(Register::RAX, 0x10)).unwrap(), None));
    // r8d = (base>>16) & 0xFF
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(), None));
    seq.push((Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 16).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::EDX).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::R8D, 0xFF).unwrap(), None));
    // ecx = (base>>24) & 0xFF ; r8d ^= ecx
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(), None));
    seq.push((Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 24).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_rm32_r32, Register::R8D, Register::ECX).unwrap(), None));
    // ecx = (base>>32) & 0xFF ; r8d ^= ecx  → r8b = bind byte
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RAX).unwrap(), None));
    seq.push((Instruction::with2(Code::Shr_rm64_imm8, Register::RDX, 32).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_rm32_r32, Register::R8D, Register::ECX).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::R8D, 0xFF).unwrap(), None));
    // rsi = seed_va ; edi = 256 ; loop: xor byte [rsi], r8b ; inc rsi ; dec edi
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RSI, seed_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::EDI, 0x100).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_rm8_r8, M::with_base(Register::RSI), Register::R8L).unwrap(), Some(Label::BaseBindLoop)));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::RSI).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm32, Register::EDI).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::BaseBindLoop)));
}

/// v17: TrashFormer-스타일 데드-레지스터 정크 생성. (1) 오직 프로시저 서문에서
/// 아직 라이브가 아닌 레지스터(rax/rcx/rdx/rsi/rdi/r8..r11)에만 쓰고,
/// (2) mov/or/xor/cmp/lea(reg-reg)만 사용해 rbx/rsp/플래그 의미를 건드리지 않으며,
/// (3) seed는 패킹마다 랜덤인 k1^k2^k3에서 xorshift로 유도 → 빌드마다 다른 정크.

fn trashformer_junk(seed: u32) -> Vec<Instruction> {
    // 결정적 xorshift32 (패킹당 시드)
    let mut st = seed | 1u32;
    let mut next = move || {
        st ^= st << 13;
        st ^= st >> 17;
        st ^= st << 5;
        st
    };
    // 데드 레지스터 풀 (서문 시점에서 안전)
    let pool = [
        Register::RAX, Register::RCX, Register::RDX, Register::RSI,
        Register::RDI, Register::R8, Register::R9, Register::R10, Register::R11,
    ];
    let n = 8 + (next() % 16) as usize; // 8..23 개
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let a = pool[(next() as usize) % pool.len()];
        let b = pool[(next() as usize) % pool.len()];
        match next() % 5 {
            0 => out.push(Instruction::with2(Code::Mov_r64_rm64, a, b).unwrap()),
            1 => out.push(Instruction::with2(Code::Or_rm64_r64, a, b).unwrap()),
            2 => out.push(Instruction::with2(Code::Xor_rm64_r64, a, b).unwrap()),
            3 => out.push(Instruction::with2(Code::Cmp_rm64_r64, a, b).unwrap()),
            _ => out.push(Instruction::with2(Code::Lea_r64_m, a, MemoryOperand::with_base(b)).unwrap()),
        }
    }
    out
}

/// v19: VM PRGA 호출 시퀀스. 호출 시점에 RCX=buf, RDX=len (네이티브 규약)이
/// 준비되어 있다고 가정한다. PRGA VM 상태의 ptr_sbox(0x110)는 엔트리 스텁이
/// RBX에서 스냅샷하므로, 여기서는 ptr_buf/RDX와 v3(len)/R8만 세팅해 엔트리 호출.
/// (i/j는 VM 상태 v0/v1에 지속 — 첫 호출 전 emit_prga_vm_init으로 0 초기화)

pub(crate) fn build_rc4_block(stub: &BootStubCtx) -> Vec<u8> {
    // ── 1. 명령어 목록 구성 ────────────────────────────────────────────────────────────────
    // (inst, Option<분기 레이블>)
    let mut seq: Vec<(Instruction, Option<Label>)> = Vec::new();

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

    emit_ksa_init(&mut seq, stub);
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

fn emit_ksa_init(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v9: crypto-off 경량 스텁 — RC4 키 스케줄/복호화 전체 생략 ────────────────
    // (안티디버그 → 페이로드 복사 → [CRC] → IAT 해석 → 메모리 하드닝 → 디스패치)
    if !stub.no_crypto {
    if stub.chained {
        // ── v7 chained-crypto: 초기 KSA 없음 — 아래 체인 루프가 청크별로 KSA 수행 ──
        // (청크 0의 키 = seed anchor, 이후 청크의 키 = 직전 청크 평문)
    } else if stub.vm {
        // ── v3-composite VM 경로 ──────────────────────────────────────────────
        // S-box 초기화 + KSA(키 스케줄)는 가상화된 VM 모듈이 수행한다.
        // 호출 규약: RCX = VM 상태 버퍼 VA, RBX = S-box 기반(=RSP), RDX = seed VA.
        // (RBX는 위 `mov rbx, rsp`로 이미 설정됨)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.seed_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.vm_state_va).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, stub.vm_entry_va).unwrap(), None));
    } else {
        // v10: 부트 스텁의 S-box 초기화 + KSA는 vm/ksa.rs의 단일 명령 리스트로
        // 생성한다. (패커 키 유도 / 부트 스텁 / VM 라이프터가 같은 key_mix를
        // 공유 — 이전에는 crypto.rs에 손으로 쓴 복사본이 있어 mix 변경 시
        // 3곳이 어긋날 위험이 있었다.)
        for item in crate::vm::ksa::build_ksa_instructions(stub.seed_va, stub.k1, stub.k2, stub.k3) {
            let lbl = item
                .label
                .map(map_ksa_label)
                .or_else(|| item.target.map(map_ksa_label));
            seq.push((item.inst, lbl));
        }
    }
    } // ── end: !stub.no_crypto (RC4 키 스케줄 생략) ────────────────────────────
}

fn emit_code_decrypt(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v9: crypto-off 스텁은 코드 영역 복호화를 생략한다 ───────────────────────
    if !stub.no_crypto {
    if stub.chained {
        // ── v7 Phase 0.1: 환경 인증 게이트 (정적 에뮬레이터/디버거 차단) ────────
        // PEB 3검(BeingDebugged/NtGlobalFlag/Heap.Flags) + RDTSC 타이밍.
        // 실패 시 **시드를 XOR 변조**해 체인 복호화를 쓰레기로 유도 — "깨끗한 감지"
        // 대신 자연스러운 오류로 동작(fail-deceptive). 정적 에뮬레이터는 gs:[0x60]
        // PEB 컨텍스트가 없어 이 검사에서 실패한다.
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None)); // PEB
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 2)).unwrap(), None)); // BeingDebugged
        seq.push((Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 0xBC)).unwrap(), None)); // NtGlobalFlag
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x70).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ(Register::RAX, 0x30)).unwrap(), None)); // ProcessHeap
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 0x70)).unwrap(), None)); // Heap.Flags
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x70).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        // 타이밍: 10만회 루프가 너무 빠르면(에뮬/튜닝) 실패
        seq.push((Instruction::with(Code::Rdtsc), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ESI, Register::EAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0x186A0).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm32, Register::ECX).unwrap(), Some(Label::AttestTiming)));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestTiming)));
        seq.push((Instruction::with(Code::Rdtsc), None));
        seq.push((Instruction::with2(Code::Sub_rm32_r32, Register::EAX, Register::ESI).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 5000).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::AttestOk)));
        // AttestFail: 시드 256B를 0x5A로 XOR → 체인 anchor 파괴
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDI, stub.seed_va).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0x100).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_rm8_imm8, MemoryOperand::with_base(Register::RDI), 0x5Au32).unwrap(), Some(Label::AttestMutLoop)));
        seq.push((Instruction::with1(Code::Inc_rm64, Register::RDI).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm32, Register::ECX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestMutLoop)));
        seq.push((Instruction::with(Code::Nopd), Some(Label::AttestOk)));

        // ── v7 chained-crypto: 코드 영역 256B 청크 순차 복호화 ────────────────
        // Key_i = 이전 청크 평문 (chunk 0 = seed anchor) → skip-ahead 불가.
        // 레지스터: r12 = 오프셋, r13 = 남은 길이, r14 = 청크 길이
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::R12D, Register::R12D).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R13, stub.code_len as u64).unwrap(), None));
        // ChainLoop: 남은 길이 검사
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::R13, Register::R13).unwrap(), Some(Label::ChainLoop)));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::ChainDone)));
        // 키 포인터 = (off==0 ? seed_va : code_va + off - 0x100)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::R12).unwrap(), None));
        seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::RCX, 0x100).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::R12, Register::R12).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::ChainKeyOk)));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.seed_va).unwrap(), None));
        // ChainKeyOk: KSA(key=[rcx], 256B) → S-box@rbx
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x100).unwrap(), Some(Label::ChainKeyOk)));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Ksa)));
        // 청크 길이 = min(0x100, r13) → r14
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R14, 0x100).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmp_rm64_imm32, Register::R13, 0x100).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmovb_r64_rm64, Register::R14, Register::R13).unwrap(), None));
        // 청크 포인터 = code_va + off
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::R12).unwrap(), None));
        // PRGA i/j 초기화 + 복호화
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R14).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::R12, Register::R14).unwrap(), None));
        seq.push((Instruction::with2(Code::Sub_rm64_r64, Register::R13, Register::R14).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::ChainLoop)));
        // ChainDone: 문자열 런 키 = (code_len >= 256 ? code_va + code_len - 256 : seed_va)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R11, stub.code_len as u64).unwrap(), Some(Label::ChainDone)));
        seq.push((Instruction::with2(Code::Cmp_rm64_imm32, Register::R11, 0x100).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::StrKeyUseWindow)));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::RCX, 0x100).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::StrKeyHave)));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.seed_va).unwrap(), Some(Label::StrKeyUseWindow)));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x100).unwrap(), Some(Label::StrKeyHave)));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Ksa)));
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None));
    } else {
        // v15: 비-chained(재암호화/평문/VM) 경로에도 fail-deceptive 인증 게이트를
        // 적용한다. chained 경로와 동일한 PEB 3검 + RDTSC 타이밍으로 디버거/에뮬레이터를
        // 탐지하고, 실패 시 **S-box(스택 프레임, RBX)를 0x5A로 XOR 변조**해 이후 모든
        // PRGA/문자열/리졸브 복호화를 쓰레기로 만든다. (이 경로는 KSA를 1회만 수행하므로
        // 시드 대신 이미 생성된 S-box를 깨야 한다.) cdb/에뮬레이터로 실행하면 깨끗한
        // 감지 대신 자연스러운 오류로 동작(fail-deceptive).
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None)); // PEB
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 2)).unwrap(), None)); // BeingDebugged
        seq.push((Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 0xBC)).unwrap(), None)); // NtGlobalFlag
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x70).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x60, false, Register::GS)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX,
            MemoryOperand::with_base_displ(Register::RAX, 0x30)).unwrap(), None)); // ProcessHeap
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX,
            MemoryOperand::with_base_displ(Register::RAX, 0x70)).unwrap(), None)); // Heap.Flags
        seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x70).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        // 타이밍: 10만회 루프가 너무 빠르면(에뮬/튜닝) 실패
        seq.push((Instruction::with(Code::Rdtsc), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ESI, Register::EAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0x186A0).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm32, Register::ECX).unwrap(), Some(Label::AttestTiming)));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestTiming)));
        seq.push((Instruction::with(Code::Rdtsc), None));
        seq.push((Instruction::with2(Code::Sub_rm32_r32, Register::EAX, Register::ESI).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 5000).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::AttestOk)));
        // AttestFail: S-box(RBX, 256B)를 0x5A로 XOR → 이후 복호화 전부 쓰레기
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDI, Register::RBX).unwrap(), Some(Label::AttestFail)));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 0x100).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_rm8_imm8, MemoryOperand::with_base(Register::RDI), 0x5Au32).unwrap(), Some(Label::AttestMutLoop)));
        seq.push((Instruction::with1(Code::Inc_rm64, Register::RDI).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm32, Register::ECX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::AttestMutLoop)));
        seq.push((Instruction::with(Code::Nopd), Some(Label::AttestOk)));

        // PRGA i,j 초기화 (canonical RC4: j=0에서 시작) — 복사 블록 이후에 수행해
        // 어떤 복사 경로가 RSI/RDI를 쓰더라도 RC4 i/j 카운터가 보존되게 한다.
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None));
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None));

        // ── 코드 영역 복호화 ──
        // v8(Phase 0.3): 재암호화 모드에서는 생략 — 블록이 개별 암호화 상태로
        // 남고 디스패처가 런타임에 복호화/재암호화한다. 문자열 런 키스트림은
        // 패커와 동일하게 "영역 없이 시작"하므로 이 스텁의 런 복호화와 일치한다.
        if !stub.reencrypt {
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.code_len as u64).unwrap(), None));
            if stub.vm_prga {
                vm_embed::emit_prga_vm_init(seq, stub);
                vm_embed::emit_prga_vm_call(seq, stub);
            } else {
                seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
            }
        }
    }
    } // ── end: !stub.no_crypto (코드 영역 복호화 생략) ──────────────────────────
}

fn emit_run_decrypt(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── 문자열 런 복호화 루프 ──
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RBP, stub.runs_va).unwrap(), Some(Label::CrcOk)));
    seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R11D, stub.num_runs).unwrap(), None));
    seq.push((Instruction::with2(Code::Test_rm64_r64, Register::R11, Register::R11).unwrap(), Some(Label::RunLoop)));
    seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::RunDone)));
    seq.push((
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RCX,
            MemoryOperand::with_base_displ(Register::RBP, 0),
        ).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RDX,
            MemoryOperand::with_base_displ(Register::RBP, 8),
        ).unwrap(),
        None,
    ));
    if stub.vm_prga {
        vm_embed::emit_prga_vm_call(seq, stub);
    } else {
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
    }
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RBP, 16).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm64, Register::R11).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::RunLoop)));
    // run_done — NOP로 자리만 표시 (실제로는 다음 명령으로 fall-through)
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::R11D, Register::R11D).unwrap(), Some(Label::RunDone)));
}

/// M6 Phase-2.3 (--vm-oep at-rest encryption): Program VM 바이트코드와 (TLS
/// 콜백 없는 경우) 보존된 원본 .text를 부트 스텁이 디스패치 직전에 복호화한다.
/// 두 영역은 패커에서 fresh RC4(seed_stored) 하나로 `.text` → bytecode 순으로
/// 연속 암호화되어 파일에는 평문이 없고, 이 블록이 실행되기 전까지 실행 불가능한
/// 암호문 상태로 남는다.
///
/// 키스트림 동치: 패커 `Rc4::new(seed_stored)`(canonical PRGA i=j=0 시작)와
/// 동일하게 `Ksa(key=seed@seed_va)` 후 ESI/EDI=0 재설정 → `Prga(.text)` →
/// `Prga(bytecode)` 연속 호출로 복호화한다. (S-box base는 RSP — RBX를 재확정.)
///
/// 길이 불변성: 이 블록은 `stub.vm_oep`일 때 항상 전체를 emit한다 (len/va는
/// imm이므로 값이 달라도 인코딩 길이가 동일). 이렇게 해야 부트 스텁 3-pass
/// sizing(초기 len=0 vs 최종 len)이 일치해 `stub size changed` 불변식이 깨지지
/// 않는다. len=0 범위는 `Prga`가 즉시 반환(Test RDX; Je)하므로 no-op이다.
fn emit_rest_decrypt(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    if !stub.vm_oep {
        return;
    }
    // fresh KSA: S-box base(RBX) = RSP, key = seed_va(256B)
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.seed_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x100).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Ksa)));
    // canonical RC4 PRGA: i=0, j=0에서 시작
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None));
    // P5: loop over .text at-rest decrypt run-table (va,len u64 pairs). Fresh
    // keystream is continuous across runs -> same order/lengths as the packer
    // encrypted them. count==0 -> immediate no-op (bytecode-only).
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RBP, stub.vm_oep_text_runs_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R11D, stub.vm_oep_text_runs_count).unwrap(), None));
    seq.push((Instruction::with2(Code::Test_rm64_r64, Register::R11, Register::R11).unwrap(), Some(Label::TextRunLoop)));
    seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::TextRunDone)));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, MemoryOperand::with_base_displ(Register::RBP, 0)).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, MemoryOperand::with_base_displ(Register::RBP, 8)).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RBP, 16).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm64, Register::R11).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::TextRunLoop)));
    seq.push((Instruction::with(Code::Nopd), Some(Label::TextRunDone)));
    // bytecode 복호화 (len=0이면 no-op)
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.vm_oep_bc_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.vm_oep_bc_len as u64).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
}

fn emit_self_wipe(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── v7 chained-crypto: 자기파괴 (시드/S-box/페이로드 원본 소거) ────────────
    // v18(anti-dump): 복호화가 끝난 뒤 키 재료를 지워 "런타임 덤프 → 재복호화"를
    // 차단한다. 기존엔 chained 경로에만 있었지만, 정적/덤프 분석에서 seed/S-box를
    // 탈취해 RC4를 재구성하는 공격을 막기 위해 **모든 crypto 경로**(chained/reencrypt/
    // vm)로 확장한다. (seed_va/S-box는 문자열 런·리졸브 테이블 복호화에만 쓰이고
    //  디스패처의 블록 키는 entry_seed 기반이라 지워도 안전. reencrypt는 mem-harden과
    //  동시에 안 켜지므로 RX 전환 순서 문제도 없다.)
    // ⚠ mem-harden(RX 전환) **이전에** 수행해야 한다 — RX 페이지에 시드를
    // 소거하면 0xC0000005가 난다 (순서 버그 수정).
    if !stub.no_crypto {
        // seed (256B)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.seed_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x100).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::ZeroMem)));
        // S-box (스택 프레임) — ⚠ RBX는 iat-resolve에서 import-name 인덱스로
        // 재사용되어 더 이상 S-box base가 아니므로, 프레임 base(=RSP, 아직 해제 전)
        // 로 직접 지정한다. (이 지점에선 아직 add rsp가 실행 전이라 RSP == 프레임 base.)
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RSP).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, 0x100).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::ZeroMem)));
        // ⚠ 페이로드 원본(.vdata) 소거는 생략 — .vdata가 read-only(R)로 매핑되어
        //   쓰면 0xC0000005. 어차피 seed/S-box를 지우면 RC4 keystream을 재구성할 수
        //   없어 덤프→재복호화는 불가능하므로, R-only .vdata는 그대로 둔다.
    }
}

fn emit_dispatcher_entry(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    // ── 스택 정리 + 디스패처 진입 ──
    // v8(Phase 0.3): 디스패처 3-푸시 규약 [seed][target_id][current_id].
    // 첫 디스패치에는 직전 블록이 없으므로 current = 0xFFFFFFFF(센티널)을 push한다.
    // M6 Phase-2(--vm-oep): 부트 스텁이 원본 .text를 평문 복호화하지 않고
    // lift된 프로그램 VM으로 디스패치한다. (RCX=프로그램 VM state, jmp 프로그램 VM entry)
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RSP, stub.stack_frame).unwrap(), None));
    if stub.vm_oep {
        // 프로그램 VM 진입 직전: 복원된 원본 스택(RSP)을 vRSP(v4) 및 STATE_PTR_STACK에 기록.
        use iced_x86::MemoryOperand as M;
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.vm_prog_state_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, M::with_base_displ(Register::RAX, (crate::vm::interp::STATE_VREGS as i64) + 4*8), Register::RSP).unwrap(), None));
        // vreg[4] = RSP is the single VM stack pointer (single-stack fix); the
        // call/ret/push/pop handlers read/write it directly, so STATE_SP/PTR_STACK
        // are intentionally left unused.

        if stub.vm_oep_native_entry {
            // 로더가 제공한 entry context를 정확히 복원한다. 임의로 레지스터를 0으로
            // 만드는 것은 Windows entry 계약이 아니며 CRT/TLS 초기 상태를 바꿀 수 있다.
            for r in [
                Register::R15,
                Register::R14,
                Register::R13,
                Register::R12,
                Register::R11,
                Register::R10,
                Register::R9,
                Register::R8,
                Register::RDI,
                Register::RSI,
                Register::RBP,
                Register::RBX,
                Register::RDX,
                Register::RCX,
                Register::RAX,
            ] {
                seq.push((Instruction::with1(Code::Pop_r64, r).unwrap(), None));
            }
            seq.push((Instruction::with(Code::Popfq), None));
            // 상대 tail-jump를 사용해야 복원한 RAX를 포함한 모든 GPR이 그대로 유지된다.
            seq.push((Instruction::with_branch(Code::Jmp_rel32_64, stub.vm_oep_native_va).unwrap(), None));
        } else {
            // 프로그램 VM: state 포인터를 RCX로 전달하고 프로그램 VM 엔트리로 점프.
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.vm_prog_state_va).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.vm_prog_entry_va).unwrap(), None));
            seq.push((Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap(), None));
        }
    } else {
    if stub.reencrypt {
        seq.push((Instruction::with1(Code::Pushq_imm32, -1).unwrap(), None));
    }
    seq.push((Instruction::with1(Code::Pushq_imm32, stub.entry_block_id as i32).unwrap(), None));
    seq.push((Instruction::with1(Code::Pushq_imm32, stub.entry_seed as i32).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.dispatcher_va).unwrap(), None));
    seq.push((Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap(), None));
    }
}

