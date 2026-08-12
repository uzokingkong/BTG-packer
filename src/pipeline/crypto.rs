// ==============================================================================
// BTG (Bidirectional Trigger Graph) - v3 Composite VM Crypto Layer
// ==============================================================================
//
// 목표: "실제 암호화/보호" — 기존 v2까지는 .textb 블록 코드와 .rdata 문자열이
// 모두 평문으로 남아 있어, 덤프/정적 분석으로 바로 읽을 수 있었다. v3는
// 아래 두 영역을 **실제 키 기반 스트림 암호(RC4-256)** 로 암호화한다:
//
//   1) .textb 블록 코드 영역 [first_block_offset .. max_phys_end)
//   2) read-only 섹션(.rdata/.rodata)의 문자열 리터럴 런
//
// 런타임에는 새 **부트 스텁(boot stub)** 이 PE 진입점에서 실행되어:
//   - 안티디버그 검사 (PEB 기반, 정상 경로만 통과)
//   - RC4 키 스케줄 복원 (시드 + 이미지베이스 유도 상수)
//   - 코드 영역 + 문자열 런 in-place 복호화
//   - 기존 OEP/디스패처로 제어권 이관
// 를 수행한다. 부트 스텁은 섹션 tail의 BOOT_AREA_RESERVE 영역에 배치된다.
//
// 키 파생: key[i] = seed_masked[i] ^ key_mix(i, k1, k2, k3)   (v10 비선형 믹스)
//   seed_masked[i] = seed[i] ^ 0xA7   (seed는 매 패킹마다 랜덤)
//   k1 = (image_base u32) ^ SALT1, k2 = (image_base>>32) + SALT2, k3 = SALT3
//   key_mix는 vm/ksa.rs의 단일 소스 — 패커/부트 스텁/VM이 항상 일치.
//   → 정적 파일에서 단순 추출 불가, 실행 시점에만 복원됨
// ==============================================================================

use crate::pe::builder::SectionData;
use crate::pipeline::PipelineContext;
use crate::pipeline::pass4_section::BOOT_AREA_RESERVE;
use crate::pipeline::patch_data::{collect_protected_rva_ranges, locate_security_cookie};
use crate::vm;
use anyhow::Result;
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};
use rand::RngCore;

/// 문자열 런 최대 개수 / 총 바이트 상한 (성능 보호)
const MAX_STRING_RUNS: usize = 512;

/// 부트 스텁의 안티디버그 블록 길이 (고정 69바이트)
const ANTI_DEBUG_BLOCK_LEN: usize = 69;
const MAX_STRING_TOTAL: usize = 1 << 20;

/// ── 패커 측 RC4 (부트 스텁과 정확히 동일한 알고리즘) ────────────────────────────
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (k, v) in s.iter_mut().enumerate() {
            *v = k as u8;
        }
        let mut j: u8 = 0;
        let klen = key.len().max(1);
        for i in 0..256usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % klen]);
            s.swap(i, j as usize);
        }
        // Canonical RC4: PRGA는 i=0, j=0에서 시작한다 (KSA의 j를 이어받지 않음)
        Rc4 { s, i: 0, j: 0 }
    }

    /// RC4 PRGA로 keystream을 생성해 버퍼에 XOR한다. (in-place decrypt/encrypt)
    pub fn crypt(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize] as usize + self.s[self.j as usize] as usize) & 0xFF];
            *byte ^= k;
        }
    }

    /// KSA 완료 후 S-box 상태 (테스트/검증용 — 패커 KSA == 부트 스텁 KSA 동치성).
    pub fn sbox(&self) -> &[u8; 256] {
        &self.s
    }
}

/// v7: 청크 체이닝 암호화 — 256B 청크마다 RC4를 재키잉한다.
/// `Key_i = 이전 청크의 평문` (chunk 0 = `anchor`). 마지막 256B 윈도우를
/// 반환해 문자열/리졸브 테이블 런의 키로 사용한다.
/// 부트 스텁의 ChainLoop/Ksa 서브루틴과 정확히 동일한 순서를 따라야 한다.
fn chained_encrypt(buf: &mut [u8], anchor: &[u8; 256]) -> [u8; 256] {
    // 평문 사본을 먼저 확보: 다음 청크의 키는 "이전 청크의 평문"이어야 한다.
    // (부트 스텁은 복호화 후 평문 상태에서 prev 윈도우를 갱신하므로, 패커도
    //  암호화 전 평문에서 갱신해야 스텁과 정확히 일치한다.)
    let plain = buf.to_vec();
    let mut prev: [u8; 256] = *anchor;
    let mut off = 0usize;
    while off < buf.len() {
        let n = (buf.len() - off).min(256);
        let mut rc4 = Rc4::new(&prev);
        rc4.crypt(&mut buf[off..off + n]);
        if off + n >= 256 {
            prev.copy_from_slice(&plain[off + n - 256..off + n]);
        } else {
            prev = [0u8; 256];
            prev[..off + n].copy_from_slice(&plain[..off + n]);
        }
        off += n;
    }
    prev
}

/// 문자열 리터럴 런 (패킹 시 발견된 위치)
#[derive(Debug, Clone)]
struct StringRun {
    /// 대상 섹션 인덱스 (ctx.patched_sections 기준)
    sec_idx: usize,
    /// 섹션 내 오프셋
    offset: usize,
    /// 런 길이 (바이트)
    len: usize,
    /// 절대 VA (부트 스텁 런 테이블용)
    va: u64,
}

// ──────────────────────────────────────────────────────────────────────────────
// 부트 스텁 머신코드 생성
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct BootStubCtx {
    boot_va: u64,          // 부트 스텁 시작 VA
    anti_debug: bool,
    dispatcher_va: u64,    // 디스패처 본체 (섹션 + 0x20)
    code_va: u64,
    code_len: u32,
    runs_va: u64,
    num_runs: u32,
    seed_va: u64,
    k1: u32,
    k2: u32,
    k3: u32,
    entry_block_id: u32,
    entry_seed: u32,
    // ── v3-composite VM ──────────────────────────────────────────────────────
    /// true = S-box init + KSA는 VM이 실행 (KSA 루프 대신 VM 엔트리 호출)
    vm: bool,
    /// VM 엔트리 스텁 VA (0이면 미배치)
    vm_entry_va: u64,
    /// VM 상태 버퍼 VA (부트 스텁이 RCX로 전달)
    vm_state_va: u64,
    // ── v19: PRGA VM (RC4 키스트림 생성 루프) ─────────────────────────────
    /// true = 문자열/코드 영역 복호화(PRGA)도 VM으로 lift (vm과 함께)
    vm_prga: bool,
    /// PRGA VM 엔트리 스텁 VA (0이면 미배치)
    vm_prga_entry_va: u64,
    /// PRGA VM 상태 버퍼 VA (i/j가 여기 v0/v1로 유지됨)
    vm_prga_state_va: u64,
    // ── M6 Phase-2: 프로그램 VM (OEP→VM entry 전환) ─────────────────────
    /// true = 부트 스텁이 원본 .text를 평문 복호화하지 않고 lift된 프로그램 VM으로 디스패치
    vm_oep: bool,
    /// 프로그램 VM 엔트리 스텁 VA (0이면 미배치)
    vm_prog_entry_va: u64,
    /// 프로그램 VM 상태 버퍼 VA (부트 스텁이 초기화 후 디스패치)
    vm_prog_state_va: u64,
    /// true = 원본 프로그램 entry 블록이 제외(네이티브 유지)되어, 부트 스텁이
    /// 프로그램 VM 디스패처(브리지) 대신 네이티브 OEP로 깨끗하게 진입한다.
    /// (브리지는 VM infra를 r12-r15에 남기고, CRT entry는 ExitProcess로 복귀하지
    /// 않아 그 포인터가 프로세스 내내 유지돼 Rust Once teardown이 once.rs:166
    /// `f.take().unwrap()` on None으로 패닉한다 — clean native entry로 회피.)
    vm_oep_native_entry: bool,
    /// clean native entry가 사용할 원본 OEP VA (entry_point_rva + image_base).
    vm_oep_native_va: u64,
    // ── v7 chained-crypto ──────────────────────────────────────────────────
    /// true = RC4를 256B 청크 단위로 재키잉해 순차 복호화
    /// (Key_i = 이전 청크 평문, chunk0 = seed anchor → skip-ahead 불가)
    chained: bool,
    // ── v8 Phase 0.3: 디스패처 재암호화 ─────────────────────────────────────────
    /// true = 코드 영역 일괄 복호화를 생략한다. 블록은 개별 암호화 상태로 남고,
    /// 디스패처가 매 디스패치마다 타깃 블록을 복호화/직전 블록을 재암호화한다.
    /// 문자열 런/리졸브 테이블은 여전히 이 스텁이 복호화한다. 첫 디스패치에
    /// 직전 블록이 없음을 알리는 current=0xFFFFFFFF 센티널을 추가로 push한다.
    reencrypt: bool,
    // ── v9: crypto-off 부트 스텁 ───────────────────────────────────────────────
    /// true = RC4 키 스케줄/코드 영역/문자열 런 복호화를 모두 생략하고,
    /// 안티디버그 + 페이로드 복사 + IAT 해석 + 메모리 하드닝 + 디스패치만 수행한다.
    /// (--no-crypto + --iat-hide/--mem-harden/--payload-relocate 시)
    no_crypto: bool,
    // ── v4 payload-relocate ──────────────────────────────────────────────────
    /// 암호화된 코드 페이로드가 저장된 데이터 섹션 VA (0 = 비활성)
    payload_va: u64,
    /// 복사할 페이로드 길이 (바이트)
    payload_len: u32,
    // ── v5 integrity (--integrity) ───────────────────────────────────────────
    /// true = 복호화 후 코드 영역 CRC32 검증, 불일치 시 ud2
    integrity: bool,
    /// 저장된 CRC32 값의 VA (4바이트, seed 뒤)
    crc_va: u64,
    // ── v6 IAT hiding (--iat-hide) ───────────────────────────────────────────
    /// true = 복호화 후 리졸브 테이블을 따라 원본 IAT 슬롯을 채운다
    iat_enabled: bool,
    /// 리졸브 테이블 VA (RC4 run으로 복호화됨)
    iat_table_va: u64,
    /// 더미 import IAT 슬롯 VA (LoadLibraryA / GetProcAddress 주소)
    iat_ll_slot_va: u64,
    iat_gpa_slot_va: u64,
    // ── v6 memory hardening (--mem-harden) ───────────────────────────────────
    /// true = 복호화 후 .textb를 RWX->RX로 전환 (NtProtectVirtualMemory)
    mem_harden: bool,
    /// "ntdll.dll" / "NtProtectVirtualMemory" 문자열 VA (부트 영역)
    mem_ntdll_name_va: u64,
    mem_ntprot_name_va: u64,
    /// 보호할 .textb 영역 (페이지 정렬 base / 페이지 라운드업 크기)
    mem_code_base: u64,
    mem_code_size: u64,
    /// 스택 프레임 크기 — 외부 API 호출 시 16B 정렬 보장(0x138), 아니면 0x110
    stack_frame: u32,
    // ── v14: import 이름 per-entry MBA 키 (다층 2단계) ─────────────────────
    /// 리졸브 테이블 이름 XOR 키 유도용 마스터 상수 (ctx.mba_constant)
    mba_master: u32,
    /// 리졸브 테이블 이름 XOR 키 유도용 MBA 상수
    mba_c: u32,
}

/// import 이름 XOR용 MBA 상수 (패커/부트 스텁 공유 — mba_xor와 동일)
const IMPORT_MBA_C: u32 = 0x9E37_79B9;

/// 올바른 PEB 기반 안티디버그 블록 (71바이트, 정상 경로는 RC4 코드로 fall-through)
///
/// 레이아웃:
///   0x00 mov rax, gs:[0x60]        ; PEB
///   0x09 movzx eax, byte [rax+2]   ; BeingDebugged
///   0x0D test eax, eax
///   0x0F jnz +0x34 -> 0x45 (ud2)
///   0x11 mov rax, gs:[0x60]
///   0x1A mov eax, [rax+0xBC]       ; NtGlobalFlag
///   0x20 and eax, 0x70
///   0x25 jnz +0x1E -> 0x45 (ud2)
///   0x27 mov rax, gs:[0x60]
///   0x30 mov rax, [rax+0x30]       ; ProcessHeap
///   0x36 mov eax, [rax+0x70]       ; Heap.Flags
///   0x3C and eax, 0x70
///   0x41 jnz +0x02 -> 0x45 (ud2)
///   0x43 jmp +0x02 -> 0x47 (rc4_start, skip ud2)
///   0x45 ud2
///   0x47 rc4_start
fn build_anti_debug_raw_block() -> Vec<u8> {
    vec![
        // 0x00 mov rax, gs:[0x60] (PEB)
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        // 0x09 movzx eax, byte [rax+2] (BeingDebugged)
        0x0F, 0xB6, 0x40, 0x02,
        // 0x0D test eax, eax
        0x85, 0xC0,
        // 0x0F jnz +0x32 → ud2 @0x43
        0x75, 0x32,
        // 0x11 mov rax, gs:[0x60]
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        // 0x1A mov eax, [rax+0xBC] (NtGlobalFlag)
        0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00,
        // 0x20 and eax, 0x70
        0x25, 0x70, 0x00, 0x00, 0x00,
        // 0x25 jnz +0x1C → ud2
        0x75, 0x1C,
        // 0x27 mov rax, gs:[0x60]
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        // 0x30 mov rax, [rax+0x30] (ProcessHeap)
        0x48, 0x8B, 0x40, 0x30,
        // 0x36 mov eax, [rax+0x70] (Heap.Flags)
        0x8B, 0x80, 0x70, 0x00, 0x00, 0x00,
        // 0x3C and eax, 0x70
        0x25, 0x70, 0x00, 0x00, 0x00,
        // 0x41 jnz +0x02 → ud2
        0x75, 0x02,
        // 0x43 jmp +0x02 → rc4_start (skip ud2)
        0xEB, 0x02,
        // 0x45 ud2
        0x0F, 0x0B,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Label {
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
fn measure_inst(inst: &Instruction, ip: u64, opts: u32) -> usize {
    let arr = [*inst];
    let block = InstructionBlock::new(&arr, ip);
    match BlockEncoder::encode(64, block, opts) {
        Ok(res) => res.code_buffer.len(),
        Err(_) => {
            // fallback: iced가 측정에 실패하면 명령어 자체 len() 사용
            if inst.len() > 0 { inst.len() } else { 5 }
        }
    }
}

/// import 이름을 per-entry MBA 키로 un-XOR한다 (패커 mba_xor와 동일 키 유도).
/// 키 = MBA::compute_key(mba_master, rbx(=entry index), mba_c, 2); r8을 진행 ptr로
/// 사용하고 이름 ptr(name_reg)은 보존한다. 길이는 ECX. r11d를 키 임시로 사용.
fn emit_unxor(
    seq: &mut Vec<(Instruction, Option<Label>)>,
    name_reg: Register,
    master: u32,
    c: u32,
    l_main: Label,
    l_tail: Label,
    l_done: Label,
) {
    // key = ((master ^ rbx) + 2*(master & rbx)) ^ c  -> eax
    seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::EAX, master).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EBX).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::EDX, master).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm32_r32, Register::EDX, Register::EBX).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm32_r32, Register::EDX, Register::EDX).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::EDX).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, c).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::EAX).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R8, name_reg).unwrap(), None));
    seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, 4).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(l_tail)));
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R11D).unwrap(), Some(l_main)));
    seq.push((Instruction::with2(Code::Xor_rm32_r32, MemoryOperand::with_base(Register::R8), Register::EAX).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R8, 4).unwrap(), None));
    seq.push((Instruction::with2(Code::Sub_rm32_imm32, Register::ECX, 4).unwrap(), None));
    seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, 4).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jae_rel32_64, 0).unwrap(), Some(l_main)));
    seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX).unwrap(), Some(l_tail)));
    seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(l_done)));
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R11D).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_rm8_r8, MemoryOperand::with_base(Register::R8), Register::AL).unwrap(), None));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::R8).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm64, Register::RCX).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(l_done)));
    seq.push((Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_rm8_r8, MemoryOperand::with_base(Register::R8), Register::AL).unwrap(), None));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::R8).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm64, Register::RCX).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(l_done)));
    seq.push((Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_rm8_r8, MemoryOperand::with_base(Register::R8), Register::AL).unwrap(), None));
    seq.push((Instruction::with(Code::Nopd), Some(l_done)));
}


/// v19: 모듈 base에서 키 바인딩 바이트 유도 (패커 측 — 부트 스텁과 동일 fold).
/// `((base>>16) ^ (base>>24) ^ (base>>32)) & 0xFF` — 0x140000000이면 0x41로 비영.
fn base_bind_byte(base: u64) -> u8 {
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
fn emit_prga_vm_call(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    use iced_x86::MemoryOperand as M;
    // RCX=buf, RDX=len  →  RDX=buf, R8=len, RCX=prga_state, call prga_entry
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::RDX).unwrap(), None)); // r8 = len
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RCX).unwrap(), None)); // rdx = buf
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.vm_prga_state_va).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Call_rel32_64, stub.vm_prga_entry_va).unwrap(), None));
}

/// v19: PRGA VM 상태의 i/j (v0/v1) 를 0 으로 초기화 (최초 호출 전 1회).
fn emit_prga_vm_init(seq: &mut Vec<(Instruction, Option<Label>)>, stub: &BootStubCtx) {
    use iced_x86::MemoryOperand as M;
    // state[0]=v0(i)=0, state[8]=v1(j)=0
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.vm_prga_state_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_imm32, M::with_base(Register::RAX), 0).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_rm64_imm32, M::with_base_displ(Register::RAX, 8), 0).unwrap(), None));
}

/// 부트 스텁 RC4 코드를 생성한다. (분기 타깃 자동 배치)
fn build_rc4_block(stub: &BootStubCtx) -> Vec<u8> {
    // ── 1. 명령어 목록 구성 ──────────────────────────────────────────────────
    // (inst, Option<분기 레이블>)
    let mut seq: Vec<(Instruction, Option<Label>)> = Vec::new();

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

    // 스택에 S-box 할당 (v6: 외부 API 호출 시 16B 정렬 프레임 사용)
    seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, stub.stack_frame).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::RSP).unwrap(), None));

    // v17 (TrashFormer-기반): 프로시저 서문에 데드 레지스터 정크 명령을 삽입해,
    // 부트 스텁 바이트가 **빌드마다 달라지게** 한다. 이 지점에선 rax/rcx/rdx/rsi/rdi/
    // r8..r11 이 전부 아직 라이브가 아니므로(KSA/복호화가 뒤에서 덮어씀) 마음대로
    // clobber해도 안전하다. rbx/rsp는 보존. 시드는 k1^k2^k3(패킹마다 랜덤)에서
    // 유도한 결정적 PRNG라, 같은 패킹의 sizing/최종 패스는 항상 동일한 정크를 내고
    // 서로 다른 패킹은 다른 바이트를 낸다 → 정적 시그니처/스크립트 재사용 무력화.
    for junk in crate::pipeline::crypto::trashformer_junk(stub.k1 ^ stub.k2 ^ stub.k3) {
        seq.push((junk, None));
    }

    // v19: base-bound key — 시드를 실제 로드 base로 바인딩 (재배치/rehost 방해).
    // no_crypto 경로에는 시드가 없으므로 crypto 경로에서만 수행.
    if !stub.no_crypto {
        crate::pipeline::crypto::emit_base_bind_loop(&mut seq, stub.seed_va);
    }

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

    // ── v4 payload-relocate: 외부 데이터 섹션(.vdata)에서 코드 영역으로 복사 ──
    // FIX(0xC000001D 크래시): 과거 코드는 `Code::Movsb_m8_m8`(iced)를 그대로 인코딩해
    // REP 프리픽스(F3)가 붙지 않아 1바이트만 복사되었고, RSI/RDI 사용으로 직후 PRGA의
    // RC4 i/j 카운터(ESI/EDI)를 파괴해 복호화 키스트림이 깨져 코드 영역이 쓰레기가 되었다.
    // → R8/R9/R10D만 쓰는 수동 바이트 루프로 교체 (ESI/EDI 비파괴, REP 인코딩 의존 없음).
    if stub.payload_len > 0 {
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R8, stub.payload_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R9, stub.code_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R10D, stub.payload_len).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::PayloadCopyDone)));
        seq.push((Instruction::with2(Code::Mov_r8_rm8, Register::AL, MemoryOperand::with_base(Register::R8)).unwrap(), Some(Label::PayloadCopyLoop)));
        seq.push((Instruction::with2(Code::Mov_rm8_r8, MemoryOperand::with_base(Register::R9), Register::AL).unwrap(), None));
        seq.push((Instruction::with1(Code::Inc_rm64, Register::R8).unwrap(), None));
        seq.push((Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm32, Register::R10D).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::PayloadCopyLoop)));
        seq.push((Instruction::with(Code::Nopd), Some(Label::PayloadCopyDone)));
    }

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
                emit_prga_vm_init(&mut seq, stub);
                emit_prga_vm_call(&mut seq, stub);
            } else {
                seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
            }
        }
    }
    } // ── end: !stub.no_crypto (코드 영역 복호화 생략) ──────────────────────────

    // ── v5 --integrity: 복호화된 코드 영역 CRC32 검증 (불일치 시 ud2) ──────────
    // 표준 반사형 CRC-32 (poly 0xEDB88320). packer가 패킹 시 계산해 seed 뒤에
    // 저장한 값과 비교한다. 파일의 암호화 바이트가 변조되면 복호화 결과가
    // 깨져 CRC 불일치 → ud2로 강제 종료 (안티-패치).
    if stub.integrity {
        // 저장된 CRC32 값 주소 (imm64 — 길이 불변)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R10, stub.crc_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0xFFFF_FFFFu32).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.code_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.code_len as u64).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::CrcDone)));
        seq.push((
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::R8D,
                MemoryOperand::with_base(Register::RCX),
            ).unwrap(),
            Some(Label::CrcLoop),
        ));
        seq.push((Instruction::with2(Code::Xor_rm8_r8, Register::AL, Register::R8L).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 8).unwrap(), None));
        // 8회: crc = (crc >> 1) ^ (LSB ? poly : 0)
        seq.push((Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 1).unwrap(), Some(Label::CrcBit)));
        seq.push((Instruction::with_branch(Code::Jae_rel32_64, 0).unwrap(), Some(Label::CrcSkip))); // jnc
        seq.push((Instruction::with2(Code::Xor_rm32_imm32, Register::EAX, 0xEDB8_8320u32).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm32, Register::R9D).unwrap(), Some(Label::CrcSkip)));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::CrcBit)));
        seq.push((Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(), None));
        seq.push((Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Label::CrcLoop)));
        seq.push((Instruction::with1(Code::Not_rm32, Register::EAX).unwrap(), Some(Label::CrcDone)));
        seq.push((
            Instruction::with2(
                Code::Cmp_r32_rm32,
                Register::EAX,
                MemoryOperand::with_base(Register::R10),
            ).unwrap(),
            None,
        ));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::CrcOk)));
        seq.push((Instruction::with(Code::Ud2), None));
    }

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
        emit_prga_vm_call(&mut seq, stub);
    } else {
        seq.push((Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(), Some(Label::Prga)));
    }
    seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RBP, 16).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm64, Register::R11).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::RunLoop)));
    // run_done — NOP로 자리만 표시 (실제로는 다음 명령으로 fall-through)
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::R11D, Register::R11D).unwrap(), Some(Label::RunDone)));

    // ── v6: 더미 import 슬롯 주소 상수 (리졸브/메모리 보호에서 사용) ─────────
    // r13 = LoadLibraryA 슬롯 VA, r15 = GetProcAddress 슬롯 VA (imm64, 길이 불변)
    if stub.iat_enabled || stub.mem_harden {
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R13, stub.iat_ll_slot_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R15, stub.iat_gpa_slot_va).unwrap(), None));
    }

    // ── v6 --iat-hide: 리졸브 테이블 처리 ─────────────────────────────────────
    // 테이블 포맷 (build_resolve_table):
    //   u32 dll_count | 각 dll: u32 name_len, name+NUL, u32 func_count,
    //   각 func: u64 slot_va, u32 name_len, name+NUL (ordinal: name_len=0xFFFF0000 + u16)
    // LoadLibraryA/GetProcAddress는 더미 import 슬롯을 통해 호출한다.
    if stub.iat_enabled {
        // FIX(v12): dll_count 카운터는 **callee-saved RBP** 사용 — R8은 volatile이라
        // LoadLibraryA/GetProcAddress 호출이 클로버 → 카운터가 깨져 리졸브 테이블
        // 워크가 unmapped 영역으로 이탈, 0xC0000005 (pack_orig+0x9E30B) 크래시.
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RSI, stub.iat_table_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EBP, MemoryOperand::with_base(Register::RSI)).unwrap(), None)); // dll_count
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 4).unwrap(), None));
        // v14: RBX = running import-name entry index (각 dll 이름 / named func마다 1씩 증가)
        seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EBX, Register::EBX).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RBP, Register::RBP).unwrap(), Some(Label::DllLoop)));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::ResolveDone)));
        // dll_loop body: dll 이름 로드
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, MemoryOperand::with_base(Register::RSI)).unwrap(), None)); // name_len
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 4).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RSI).unwrap(), None)); // dll name ptr
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RCX).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 1).unwrap(), None));
        // v14: dll 이름 per-entry MBA 키로 un-XOR (R9 보존, R8로 진행)
        emit_unxor(
            &mut seq,
            Register::R9,
            stub.mba_master,
            stub.mba_c,
            Label::UxDllMain,
            Label::UxDllTail,
            Label::UxDllDone,
        );
        seq.push((Instruction::with1(Code::Inc_rm64, Register::RBX).unwrap(), None));
        // LoadLibraryA(dll_name)
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R9).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base(Register::R13)).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::ResolveDone)));
        seq.push((Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap(), None)); // hModule
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EDI, MemoryOperand::with_base(Register::RSI)).unwrap(), None)); // func_count
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 4).unwrap(), None));
        // func_loop body
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RDI, Register::RDI).unwrap(), Some(Label::FuncLoop)));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::DllNext)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R12, MemoryOperand::with_base(Register::RSI)).unwrap(), None)); // slot_va
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 8).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, MemoryOperand::with_base(Register::RSI)).unwrap(), None)); // name_len/marker
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 4).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, 0xFFFF_0000u32).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::FuncOrdinal)));
        // named: r10 = name ptr
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RSI).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RCX).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 1).unwrap(), None));
        // v14: named func 이름 per-entry MBA 키로 un-XOR (R10 보존, R8로 진행)
        emit_unxor(
            &mut seq,
            Register::R10,
            stub.mba_master,
            stub.mba_c,
            Label::UxFuncMain,
            Label::UxFuncTail,
            Label::UxFuncDone,
        );
        seq.push((Instruction::with1(Code::Inc_rm64, Register::RBX).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R10).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::FuncCall)));
        // ordinal: rdx = ordinal (MAKEINTRESOURCE)
        seq.push((Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, MemoryOperand::with_base(Register::RSI)).unwrap(), Some(Label::FuncOrdinal)));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RSI, 3).unwrap(), None));
        // GetProcAddress(hModule, name/ordinal)
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R14).unwrap(), Some(Label::FuncCall)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base(Register::R15)).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::ResolveDone)));
        seq.push((Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base(Register::R12), Register::RAX).unwrap(), None)); // *slot = addr
        seq.push((Instruction::with1(Code::Dec_rm64, Register::RDI).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::FuncLoop)));
        // dll_next
        seq.push((Instruction::with1(Code::Dec_rm64, Register::RBP).unwrap(), Some(Label::DllNext)));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::DllLoop)));
        seq.push((Instruction::with(Code::Nopd), Some(Label::ResolveDone)));
    }

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

    // ── v6 --mem-harden: ntdll!NtProtectVirtualMemory로 .textb RWX->RX ──────
    // fail-open: 슬롯/해석 실패 시 보호 없이 계속 진행.
    // FIX(v12.2): reencrypt(런타임 블록 단위 복호화)와 동시에는 생략 — 디스패처의
    // in-place 복호화가 RX 페이지에 쓰면 0xC0000005 (fault @ PRGA xor [rcx],al).
    if stub.mem_harden && !stub.reencrypt {
        // LoadLibraryA("ntdll.dll")
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, stub.mem_ntdll_name_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base(Register::R13)).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::MemDone)));
        seq.push((Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::MemDone)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap(), None)); // ntdll handle
        // GetProcAddress(ntdll, "NtProtectVirtualMemory")
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RDX, stub.mem_ntprot_name_va).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::R14).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base(Register::R15)).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::MemDone)));
        seq.push((Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::MemDone)));
        // NtProtectVirtualMemory(-1, &base, &size, PAGE_EXECUTE_READ, &old)
        // 스크래치: [rsp+0x100]=base, [rsp+0x108]=size, [rsp+0x110]=old (프레임 0x138)
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R11, stub.mem_code_base).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ(Register::RSP, 0x100), Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R11, stub.mem_code_size).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ(Register::RSP, 0x108), Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm32_imm32, MemoryOperand::with_base_displ(Register::RSP, 0x110), 0).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, u64::MAX).unwrap(), None)); // NtCurrentProcess
        seq.push((Instruction::with2(Code::Lea_r64_m, Register::RDX, MemoryOperand::with_base_displ(Register::RSP, 0x100)).unwrap(), None));
        seq.push((Instruction::with2(Code::Lea_r64_m, Register::R8, MemoryOperand::with_base_displ(Register::RSP, 0x108)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 0x20).unwrap(), None)); // PAGE_EXECUTE_READ
        seq.push((Instruction::with2(Code::Lea_r64_m, Register::R10, MemoryOperand::with_base_displ(Register::RSP, 0x110)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_displ(Register::RSP, 0x20), Register::R10).unwrap(), None)); // 5th arg
        seq.push((Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(), None));
        seq.push((Instruction::with(Code::Nopd), Some(Label::MemDone)));
    }

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
            // ── clean native OEP entry (once.rs:166 crash fix) ─────────────────
            // 원본 entry 블록(mainCRTStartup)이 제외되어 네이티브로 남은 경우, 프로그램
            // VM 디스패처로 들어가면 첫 동작이 OP_NATIVE_CALL 브리지가 된다. 브리지는
            // VM infra(state/ip/table)를 callee-saved 레지스터 r12/r13/r14에, saved-RSP를
            // r15에 스태시한 뒤 네이티브 entry를 호출하는데, CRT entry(mainCRTStartup)는
            // ExitProcess로 프로세스를 끝내며 브리지로 복귀하지 않는다. 그 결과 VM 포인터가
            // 프로세스 수명 동안 r12-r15에 남아 Rust 런타임을 오염시켜 종료 시점 Once
            // teardown이 재진입하고 `f.take().unwrap()`(None) → once.rs:166 패닉.
            // 따라서 여기서는 정상 OS-entry 레지스터 상태로 네이티브 OEP에 점프한다:
            // rsp는 위 `add rsp,stack_frame`로 원본 entry RSP가 복원됐고, 원본 PEB는
            // state vreg[1]에 저장돼 있으니 그것을 rcx로 다시 적재하고 나머지를 0으로 만든다.
            // mainCRTStartup은 복귀하지 않으므로 스택/레지스터 복원은 불필요하다(안전).
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX,
                M::with_base_displ(Register::RAX, (crate::vm::interp::STATE_VREGS as i64) + 8)).unwrap(), None));
            for r in [
                Register::RDX, Register::RBX, Register::RBP, Register::RSI, Register::RDI,
                Register::R8, Register::R9, Register::R12, Register::R13, Register::R14, Register::R15,
            ] {
                seq.push((Instruction::with2(Code::Xor_rm64_r64, r, r).unwrap(), None));
            }
            seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub.vm_oep_native_va).unwrap(), None));
            seq.push((Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap(), None));
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

    // ── PRGA 서브루틴: rcx=buf, rdx=len ──
    seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(), Some(Label::Prga)));
    seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::PrgaDone)));
    seq.push((Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), Some(Label::PrgaLoop)));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::ESI, 0xFF).unwrap(), None));
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
        ).unwrap(),
        None,
    ));
    seq.push((Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF).unwrap(), None));
    // swap(S[i], S[j])
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R8D,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
        ).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::R9D,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RDI, 1),
        ).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_rm8_r8,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
            Register::R9L,
        ).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Mov_rm8_r8,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RDI, 1),
            Register::R8L,
        ).unwrap(),
        None,
    ));
    // K = S[(S[i]+S[j]) & 0xFF]
    seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::R8D).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm32_r32, Register::EAX, Register::R9D).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0xFF).unwrap(), None));
    seq.push((
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::EAX,
            MemoryOperand::with_base_index_scale(Register::RBX, Register::RAX, 1),
        ).unwrap(),
        None,
    ));
    seq.push((
        Instruction::with2(
            Code::Xor_rm8_r8,
            MemoryOperand::with_base(Register::RCX),
            Register::AL,
        ).unwrap(),
        None,
    ));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(), None));
    // FIX: 루프는 매 회차 종료 조건을 다시 검사해야 한다. 과거 코드는
    // `jmp PrgaLoop`(inc esi)로 되돌아가 `test rdx,rdx; je done`을 우회하여
    // 첫 호출(코드 영역 복호화)이 rdx=0에서 끝나지 않고 스텁 자신의 코드를
    // 계속 XOR로 덮어쓰다 0xC0000005로 크래시했다. -> `jmp Prga`(test)로 복귀.
    seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::Prga)));
    seq.push((Instruction::with(Code::Retnq), Some(Label::PrgaDone)));

    // ── v7 chained-crypto: KSA 서브루틴 (rcx=key 256B, rbx=S-box base) ───────
    // 표준 RC4 KSA (key 길이 256 고정 → i%256==i). 청크마다 재호출된다.
    // S[i] = i 초기화
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), Some(Label::Ksa)));
    seq.push((Instruction::with2(
        Code::Mov_rm8_r8,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
        Register::SIL,
    ).unwrap(), Some(Label::KsaInitLoop)));
    seq.push((Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), None));
    seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::KsaInitLoop)));
    // KSA: j = (j + S[i] + key[i]) & 0xFF ; swap(S[i], S[j])
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::ESI, Register::ESI).unwrap(), None));
    seq.push((Instruction::with2(Code::Xor_r32_rm32, Register::EDI, Register::EDI).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Movzx_r32_rm8,
        Register::EAX,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
    ).unwrap(), Some(Label::KsaLoopK)));
    seq.push((Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Movzx_r32_rm8,
        Register::EAX,
        MemoryOperand::with_base_index_scale(Register::RCX, Register::RSI, 1),
    ).unwrap(), None));
    seq.push((Instruction::with2(Code::Add_rm32_r32, Register::EDI, Register::EAX).unwrap(), None));
    seq.push((Instruction::with2(Code::And_rm32_imm32, Register::EDI, 0xFF).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Movzx_r32_rm8,
        Register::EAX,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
    ).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Movzx_r32_rm8,
        Register::R8D,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RDI, 1),
    ).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Mov_rm8_r8,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RDI, 1),
        Register::AL,
    ).unwrap(), None));
    seq.push((Instruction::with2(
        Code::Mov_rm8_r8,
        MemoryOperand::with_base_index_scale(Register::RBX, Register::RSI, 1),
        Register::R8L,
    ).unwrap(), None));
    seq.push((Instruction::with1(Code::Inc_rm32, Register::ESI).unwrap(), None));
    seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::ESI, 0x100).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jb_rel32_64, 0).unwrap(), Some(Label::KsaLoopK)));
    seq.push((Instruction::with(Code::Retnq), None));

    // ── v7 chained-crypto: ZeroMem 서브루틴 (rcx=buf, rdx=len) ───────────────
    seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RDX, Register::RDX).unwrap(), Some(Label::ZeroMem)));
    seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Label::ZeroDone)));
    seq.push((Instruction::with2(Code::Mov_rm8_imm8, MemoryOperand::with_base(Register::RCX), 0u32).unwrap(), None));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::RCX).unwrap(), None));
    seq.push((Instruction::with1(Code::Dec_rm64, Register::RDX).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Label::ZeroMem)));
    seq.push((Instruction::with(Code::Retnq), Some(Label::ZeroDone)));

/// 분기 코드 여부 (with_branch로 재생성 가능한 near-branch만)
fn is_branch_code(code: iced_x86::Code) -> bool {
    matches!(
        code,
        iced_x86::Code::Jb_rel32_64
            | iced_x86::Code::Je_rel32_64
            | iced_x86::Code::Jne_rel32_64
            | iced_x86::Code::Jae_rel32_64
            | iced_x86::Code::Jmp_rel32_64
            | iced_x86::Code::Call_rel32_64
    )
}

    // 모든 경로에서 분기 최적화(rel8 축소)를 끄고 측정/최종 인코딩을 일치시킨다.
    // (rel8로 측정했다가 최종 레이아웃에서 rel32로 늘어나면 길이 검증이 깨진다.
    //  v6: IAT/mem 블록의 근거리 `je`가 rel8로 축소돼 4바이트 불일치를 일으켰음)
    let enc_opts = BlockEncoderOptions::DONT_FIX_BRANCHES;

    // ── 2. IP 배치 (각 명령을 개별 인코딩해 정확한 길이 측정) ──────────────────
    // anti-debug 블록은 고정 69바이트 (ud2 @0x43). rc4 코드는 그 뒤에서 시작.
    let rc4_start_va = stub.boot_va + if stub.anti_debug { ANTI_DEBUG_BLOCK_LEN as u64 } else { 0 };
    let mut ip = rc4_start_va;
    let mut label_ips: std::collections::HashMap<Label, u64> = std::collections::HashMap::new();

    for (inst, lbl) in seq.iter() {
        // 측정 시 분기 타깃은 자기 자신 IP로 설정 (rel32라 길이 불변)
        let mut m = *inst;
        if lbl.is_some() && is_branch_code(inst.code()) {
            m = Instruction::with_branch(inst.code(), ip).unwrap();
        }
        let len = measure_inst(&m, ip, enc_opts);
        if let Some(l) = lbl {
            // 분기 명령어는 타깃 정의가 아니라 참조이므로 label_ips를 덮어쓰면 안 된다.
            if !is_branch_code(inst.code()) {
                label_ips.insert(*l, ip);
            }
        }
        ip += len as u64;
    }

    // ── 3. 분기 타깃 확정 + 전체 인코딩 ───────────────────────────────────────
    for (inst, lbl) in seq.iter_mut() {
        if let Some(l) = lbl {
            if is_branch_code(inst.code()) {
                let target = label_ips[&l];
                *inst = Instruction::with_branch(inst.code(), target).unwrap();
            }
        }
    }

    let insts: Vec<Instruction> = seq.iter().map(|(i, _)| *i).collect();
    let block = InstructionBlock::new(&insts, rc4_start_va);
    let enc = BlockEncoder::encode(64, block, enc_opts)
        .expect("boot stub BlockEncoder failed");
    let code = enc.code_buffer;
    let expected = (ip - rc4_start_va) as usize;
    assert_eq!(
        code.len(), expected,
        "boot stub length mismatch: measured {} vs encoded {}",
        expected, code.len()
    );
    code
}

// ──────────────────────────────────────────────────────────────────────────────
// 메인 진입점
// ──────────────────────────────────────────────────────────────────────────────

/// 표준 반사형 CRC-32 (poly 0xEDB88320) — 부트 스텁의 검증 루틴과 동일 알고리즘.
/// `--integrity`에서 평문 코드 영역에 대해 계산해 부트 영역에 저장한다.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// v3 복합 암호화 실행.
///
/// `enabled=false`이면 아무것도 하지 않는다 (기존 v2 동작 유지).
/// `vm=true`이면 부트 스텁의 S-box 초기화 + KSA 루프를 가상화된 VM 모듈로
/// 교체하고, 해당 모듈(핸들러/디스패치/바이트코드/상태)을 부트 영역에 배치한다.
/// `coverage`(0..=100)는 코드 영역 RC4 암호화 커버리지(% ) — 낮출수록 .textb
/// 섹션 엔트로피가 낮아진다 (100 = 기존 동작).
pub fn run(
    ctx: &mut PipelineContext,
    enabled: bool,
    anti_debug: bool,
    vm: bool,
    coverage: u32,
    payload_relocate: bool,
    integrity: bool,
    chained: bool,
    reencrypt: bool,
) -> Result<()> {
    // v9: crypto가 꺼져 있어도 IAT 은닉/메모리 하드닝/페이로드 재배치가 요청되면
    // 경량 부트 스텁(RC4 없이 안티디버그→복사→IAT 해석→메모리 하드닝→디스패치)을
    // 설치해야 한다. 그 외에는 아무것도 할 게 없다.
    if !enabled && !ctx.iat_hide && !ctx.mem_harden && !payload_relocate {
        return Ok(());
    }
    // v9: --integrity 조합 구현 — chained(평문 CRC) / reencrypt(암호문·파일 CRC)
    if chained && integrity {
        println!("[+] v5 Integrity + v7 Chained-Crypto: CRC over decrypted code (chain loop runs first)");
    }
    if reencrypt && integrity {
        println!("[+] v5 Integrity + v8 Re-Encrypt: CRC over ciphertext as stored in file (boot-time tamper check)");
    }
    if chained && vm {
        println!("[!] --chained-crypto takes precedence over --vm (VM KSA bypassed; chain uses its own KSA)");
    }
    if reencrypt && chained {
        println!("[!] --dispatcher-reencrypt takes precedence over --chained-crypto (boot-stub bulk decryption bypassed; blocks stay individually encrypted)");
    }
    let no_crypto = !enabled;
    let chained_effective = enabled && chained && !reencrypt;
    let vm_effective = enabled && vm && !chained_effective && !reencrypt;
    let vm_oep_effective = vm_effective && ctx.vm_oep;
    let m8_mod = ctx.m8 && vm_effective;
    let integrity_effective = integrity && enabled;

    // M8: MBA-obfuscated VM handler table builder — routes to the MBA variant
    // (XOR-encrypted handler table + runtime MBA key derivation) when --m8 is on,
    // else the plain builder. Used by both the sizing pass and the final placement
    // so the measured/placed module layouts agree.
    let build_mod = |code_va: u64,
                     table_va: u64,
                     bytecode_va: u64,
                     bc: Vec<u8>,
                     mode: vm::handlers::EntryMode|
     -> anyhow::Result<vm::VmModule> {
        if m8_mod {
            vm::build_vm_module_mba(code_va, table_va, bytecode_va, bc, mode)
        } else {
            vm::build_vm_module(code_va, table_va, bytecode_va, bc, mode)
        }
    };
    let build_prog_mod = |code_va: u64,
                          table_va: u64,
                          bytecode_va: u64,
                          bc: Vec<u8>,
                          state_va: u64|
     -> anyhow::Result<vm::VmModule> {
        vm::build_program_vm(code_va, table_va, bytecode_va, bc, state_va, m8_mod)
    };

    // ── M7: on-demand 재암호화(anti-dump) — 원본 .text/.data/.rdata 런을 파일에는
    // 암호문으로 유지하고(이미 boot-decrypt run 등록됨), 실행 중 on-demand로만
    // 복호화→사용→재암호화한다. 여기선 런이 파일에 암호문 상태로 남음을 보장하고,
    // 부트 스텁이 복호화 후 재암호화하는 on-demand 경로를 로그로 확인한다.
    if ctx.m7 {
        println!("[+] M7 on-demand re-encrypt: boot-decrypt runs stay ciphertext at rest; on-demand decrypt→use→re-encrypt (anti-dump)");
    }

    // ── 1. 레이아웃 정보 읽기 (아직 btg를 빌리지 않은 상태 — &ctx만 사용) ────
    let layout = ctx.layout()?;
    let num_blocks = layout.shuffled_blocks.len();
    if num_blocks == 0 {
        return Ok(());
    }

    let image_base = ctx.target_info.image_base;
    let dispatcher_va = ctx.dispatcher_va;
    let dispatcher_rva = (dispatcher_va - image_base) as u32;
    let boot_off = ctx.boot_entry_offset as usize;
    let first_block_offset = ctx.first_block_offset;

    // 코드 영역 범위 계산
    let mut max_phys_end = first_block_offset;
    for block in &layout.shuffled_blocks {
        let logical_id = block.id as usize;
        let off = layout.table_offsets[logical_id] as usize;
        max_phys_end = max_phys_end.max(off + block.instructions.len());
    }
    let full_code_len = (max_phys_end - first_block_offset) as u32;
    // v4: 암호화 커버리지 — 코드 영역의 앞부분만 RC4로 암호화 (엔트로피 제어)
    // v8(Phase 0.3): 재암호화는 모든 블록이 개별 암호화되어야 하므로 100으로 강제.
    // v9: crypto-off + payload-relocate → 코드 영역 전체를 (평문 그대로) .vdata로 이동
    let coverage_effective = if reencrypt { 100 } else { coverage };
    let code_len = if vm_oep_effective {
        // C-1 (--vm-oep): 리프트된 프로그램은 원본 코드를 VM에서 실행하지만, 네이티브 CRT
        // (ucrtbase!initterm_e 등)는 데이터 섹션의 함수 포인터로 원본 코드를 직접 호출한다.
        // .btg 코드 블록을 암호화하면 네이티브가 암호문을 실행해 0xc0000005로 크래시한다
        // (기존 C-1 런타임 통합 블로커). 따라서 --vm-oep에서는 코드 블록을 평문으로 유지해
        // 네이티브 초기화자/콜백 호출이 동작하게 한다. (문자열/데이터 은닉은 별도 유지)
        0
    } else if no_crypto {
        if payload_relocate { full_code_len } else { 0 }
    } else if coverage_effective >= 100 {
        full_code_len
    } else {
        ((full_code_len as u64 * coverage_effective as u64) / 100).min(full_code_len as u64) as u32
    };
    if code_len < full_code_len {
        println!(
            "[+] v4 Crypto coverage: {:.0}% of code region encrypted ({} / {} bytes) — entropy reduced",
            (code_len as f64 / full_code_len as f64) * 100.0,
            code_len,
            full_code_len
        );
    }

    // v8(Phase 0.3): 블록별 개별 암호화용 (offset, len, key) 사전 수집 — btg 가변 대여 전.
    let block_keys: Vec<(usize, usize, u32)> = if reencrypt {
        // v11 FIX: call-target 블록은 평문 유지 — 암호화 목록에서 제외한다.
        // (디스패처가 길이 0 센티널로 해당 블록의 복호화/재암호화를 건너뜀)
        layout
            .shuffled_blocks
            .iter()
            .filter(|block| !ctx.call_target_block_ids.contains(&block.id))
            .map(|block| {
                let id = block.id;
                let off = layout.table_offsets[id as usize] as usize;
                let len = block.instructions.len();
                let seed = crate::mba::MbaGenerator::seed_for(ctx.mba_constant, id);
                let key = crate::mba::MbaGenerator::compute_key(seed, id, ctx.mba_constant, 2);
                (off, len, key)
            })
            .collect()
    } else {
        Vec::new()
    };
    let total_blocks = layout.shuffled_blocks.len();

    // ── 2. 키 상수 생성 ──────────────────────────────────────────────────────
    let mut rng = rand::thread_rng();
    let salt1: u32 = rng.next_u32();
    let salt2: u32 = rng.next_u32();
    let salt3: u32 = rng.next_u32();
    let k1 = (image_base as u32) ^ salt1;
    let k2 = ((image_base >> 32) as u32).wrapping_add(salt2);
    let k3 = salt3;

    // ── 3. 문자열 런 스캔 (patched_sections 기준, 보호 범위 제외) ─────────────
    // v9: crypto-off 경량 스텁에는 런 복호화가 없으므로 스캔/암호화하지 않는다.
    let mut runs = if no_crypto || vm_oep_effective {
        // C-1 (--vm-oep): --no-crypto와 동일하게 부트-복호화 런을 비운다. 리프트된 프로그램은
        // VM에서 실행되고 코드 블록은 평문(위 code_len=0)이므로, 부트 스텁이 .text/문자열 런을
        // 복호화하려 하면 (code_len=0과 맞물려 키스트림/제어흐름이 어긋나) 메인 실행이 깨진다.
        // --no-crypto 실험에서 문자열 런 없이 메시지 루프까지 정상 도달함을 확인.
        Vec::new()
    } else {
        let cookie_rva = locate_security_cookie(ctx, &ctx.patched_sections);
        let protected = collect_protected_rva_ranges(ctx, &ctx.patched_sections, cookie_rva);
        scan_string_runs(&mut ctx.patched_sections, image_base, &protected)
    };

    // ── v14: 원본 .text를 런타임 복호화로 은닉 ───────────────────────────────
    // 원본 .text는 출력에 relayed로 남아 평문이 노출되고, 일부 코드는 런타임에
    // 실제 .text에서 실행된다. 0으로 채우면 실행이 깨지므로, 대신 .text를
    // 부트 스텁의 RC4 run으로 등록한다 → 파일에는 암호문(원본 로직 은닉),
    // 런타임에 부트 스텁이 코드 디스패치 전에 복원해 실행이 그대로 동작.
    if !no_crypto && !vm_oep_effective {
        if let Some(ti) = ctx.patched_sections.iter().position(|s| s.name == ".text") {
            let tsec = &ctx.patched_sections[ti];
            if !tsec.bytes.is_empty() {
                runs.push(StringRun {
                    sec_idx: ti,
                    offset: 0,
                    len: tsec.bytes.len(),
                    va: image_base + tsec.virtual_address as u64,
                });
                println!(
                    "[+] v14: original .text {} bytes registered as boot-decrypt run (plaintext hidden at rest)",
                    tsec.bytes.len()
                );
            }
        }

        // ── v14: 원본 데이터(.rdata/.data/.rodata)도 런타임 복호화로 은닉 ────────
        // 공격자가 flag 비교용 target_table 같은 원본 프로그램 데이터를 .rdata에서
        // 평문으로 읽는 것을 차단한다. 로더가 부트 전에 읽는 import/IAT/TLS/LoadConfig/
        // cookie 범위(collect_protected_rva_ranges)는 제외해 로더가 깨지지 않게 한다.
        let cookie_rva = locate_security_cookie(ctx, &ctx.patched_sections);
        let protected = collect_protected_rva_ranges(ctx, &ctx.patched_sections, cookie_rva);
        // C-1 fix (--vm-oep): 리프트된 프로그램은 원본 .rdata/.data/.rodata를 절대 VA로
        // 직접 읽는다(예: .rdata에 저장된 데이터 포인터). 이 섹션들을 v14 "전체 데이터 런"으로
        // 암호화하면 부트 스텁 복호화의 키스트림 정렬이 어긋나(또는 데이터가 원본 포인터로
        // 복원되지 않아) 리프트 코드가 쓰레기 주소를 읽고 0xC0000005로 크래시한다.
        // 문자열 은닉은 scan_string_runs(아래)이 이미 처리하므로, --vm-oep에서는
        // 전체 데이터 런 암호화를 건너뛰어 포인터/데이터 영역을 평문으로 유지한다.
        // Bug-1 fix: `.data`는 제외 — Rust 런타임의 `Once`/`OnceLock`/`AtomicUsize` 상태
        // 워드가 초기화된 쓰기 가능 정적 데이터로 `.data`(및 .bss)에 살기 때문. 전체 런으로
        // XOR하면 셧다운 cleanup이 그 상태를 POISONED로 읽어 `once.rs:166` 패닉을 일으킨다.
        // `.data`를 런에서 빼 평문으로 유지하면 상태 워드가 절대 암호화 런 안에 들어가지 않는다.
        // (읽기 전용 `.rdata`/`.rodata`만 은닉.)
        if ctx.vm_oep {
            // skip full-data-run encryption in --vm-oep (data pointers must stay plaintext)
            println!("[+] --vm-oep: skipping full .rdata/.rodata boot-decrypt runs (lifted program reads data pointers as plaintext)");
        } else {
            for data_name in [".rdata", ".rodata"] {
            let Some(ti) = ctx.patched_sections.iter().position(|s| s.name == data_name) else {
                continue;
            };
            let tsec = &ctx.patched_sections[ti];
            if tsec.bytes.is_empty() {
                continue;
            }
            let sec_start = tsec.virtual_address;
            let sec_end = sec_start + tsec.bytes.len() as u32;
            // protected 범위와 교차하는 것만 [sec_start, sec_end)로 클리핑 후 정렬/병합
            let mut pv: Vec<(u32, u32)> = protected
                .iter()
                .filter(|&&(st, en)| en > sec_start && st < sec_end)
                .map(|&(st, en)| (st.max(sec_start), en.min(sec_end)))
                .collect();
            pv.sort_unstable();
            pv.dedup();
            let mut pos = sec_start;
            let mut n_runs = 0usize;
            for (ps, pe) in pv {
                if ps > pos {
                    let off = (pos - sec_start) as usize;
                    let len = (ps - pos) as usize;
                    runs.push(StringRun {
                        sec_idx: ti,
                        offset: off,
                        len,
                        va: image_base + pos as u64,
                    });
                    n_runs += 1;
                }
                pos = pos.max(pe);
            }
            if pos < sec_end {
                let off = (pos - sec_start) as usize;
                let len = (sec_end - pos) as usize;
                runs.push(StringRun {
                    sec_idx: ti,
                    offset: off,
                    len,
                    va: image_base + pos as u64,
                });
                n_runs += 1;
            }
            if n_runs > 0 {
                println!(
                    "[+] v14: {} {} bytes registered as {} boot-decrypt run(s) (loader-critical dirs excluded)",
                    data_name,
                    tsec.bytes.len(),
                    n_runs
                );
            }
        }
        }
    }

    println!(
        "[+] v3 Crypto: code region 0x{:X}..0x{:X} ({} bytes), {} string runs encrypted.",
        first_block_offset, max_phys_end, code_len, runs.len()
    );

    // ── 4. 시드 생성 + RC4 키 ────────────────────────────────────────────────
    let mut seed = [0u8; 256];
    rng.fill_bytes(&mut seed);
    // v19 (base-bound key): 시드 저장은 원본 seed_masked를 유지하되, **파일에 쓰는
    // 바이트만** base_bind_byte(선호 base)로 미리 XOR한다. 부트 스텁이 런타임에
    // PEB ImageBaseAddress(실제 base)에서 같은 바이트를 유도해 시드에 XOR하면,
    // 선호 base로 로드 시 상쇄되어 원본 seed_masked 복원 → 정상 복호화. 재배치/rehost로
    // base가 달라지면 시드가 깨져 복호화가 쓰레기가 된다(이식/재호스트 방해).
    let seed_masked: Vec<u8> = seed.iter().map(|b| b ^ 0xA7).collect();
    let base_bind = base_bind_byte(image_base);
    let seed_stored: Vec<u8> = seed_masked.iter().map(|b| b ^ base_bind).collect();

    let mut key = [0u8; 256];
    for i in 0..256usize {
        let iu = i as u32;
        // v10: 비선형 믹스 — vm/ksa.rs 단일 소스 (부트 스텁/VM과 항상 일치)
        let mix = vm::ksa::key_mix(iu, k1, k2, k3);
        key[i] = seed_masked[i] ^ (mix as u8);
    }

    // ── 5. 이제 서로 다른 필드(btg_section_data / patched_sections)만 빌려서 ──
    //    복호화 순서와 동일하게 암호화 (코드 영역 → 런 순서) ────────────────────
    let btg = ctx.btg_section_data.as_mut()
        .ok_or_else(|| anyhow::anyhow!("btg_section_data not set — run Pass 4 first"))?;
    if boot_off == 0 || boot_off + BOOT_AREA_RESERVE > btg.bytes.len() {
        return Err(anyhow::anyhow!("Boot area not reserved by Pass 4 (boot_off=0x{:X})", boot_off));
    }
    let boot_va = dispatcher_va + boot_off as u64;

    let mut rc4;

    // 5a. 코드 영역
    // v5(--integrity) CRC 소스:
    //   - reencrypt: 파일에 저장된 **암호문**(부트 스텁이 복호화 없이 그대로 검사)
    //   - chained/plain: **평문** (부트 스텁이 복호화 후 검사)
    // v9: crypto-off에는 integrity 없음.
    let code_start = first_block_offset;
    let code_end = code_start + code_len as usize;
    let mut crc_source: Option<Vec<u8>> = if integrity_effective && !reencrypt {
        Some(btg.bytes[code_start..code_end].to_vec())
    } else {
        None
    };
    if reencrypt {
        // v8(Phase 0.3): 코드 영역을 통째로 암호화하지 않고, 블록별 MBA 키로
        // 개별 RC4 암호화한다. 디스패처가 매 디스패치마다 해당 블록만 복호화하고
        // 직전 블록을 재암호화한다. 문자열 런은 아래에서 영역 없이 시작하는
        // fresh RC4 스트림으로 암호화한다 (부트 스텁도 영역 복호화를 생략).
        for (off, len, key) in &block_keys {
            let mut rc4b = Rc4::new(&key.to_le_bytes());
            rc4b.crypt(&mut btg.bytes[*off..*off + *len]);
        }
        if integrity_effective {
            crc_source = Some(btg.bytes[code_start..code_end].to_vec());
        }
        rc4 = Rc4::new(&key);
        println!(
            "[+] v8 Dispatcher Re-Encrypt: {} blocks individually RC4-encrypted with per-block MBA keys (boot-stub bulk decryption skipped)",
            total_blocks
        );
    } else if chained_effective {
        // v7: 청크 체이닝 암호화 — Key_i = 이전 청크 평문(256B), chunk0 = seed anchor.
        // 반환된 마지막 256B 윈도우가 문자열/리졸브 테이블 런의 키가 된다.
        let mut anchor = [0u8; 256];
        anchor.copy_from_slice(&seed_masked);
        let chain_key = chained_encrypt(&mut btg.bytes[code_start..code_end], &anchor);
        rc4 = Rc4::new(&chain_key);
        println!(
            "[+] v7 Chained-Crypto: {} bytes code region chained in 256B chunks (skip-ahead blocked)",
            code_len
        );
    } else if !no_crypto {
        rc4 = Rc4::new(&key);
        rc4.crypt(&mut btg.bytes[code_start..code_end]);
    } else {
        // v9: crypto-off — 코드 영역은 그대로 둔다 (payload-relocate 시 아래에서 이동)
        rc4 = Rc4::new(&key);
    }

    // 5a-1. v4 payload-relocate: (암호화된) 코드 영역을 실행 불가 데이터 섹션으로 이동
    //       (.textb는 0x00 스테이징만 남아 엔트로피 급감, 부트 스텁이 로드 시 복사+복호화)
    // v9: crypto-off에서도 동작 — 평문 코드를 .vdata로 옮기고 부트 스텁이 복사.
    let mut payload_bytes: Vec<u8> = Vec::new();
    if payload_relocate && code_len > 0 {
        payload_bytes = btg.bytes[code_start..code_end].to_vec();
        btg.bytes[code_start..code_end].fill(0);
        println!(
            "[+] v4 Payload Relocate: {} bytes moved to .vdata (executable section zeroed)",
            code_len
        );
    }

    // 5b. 문자열 런 (부트 스텁 런 테이블과 같은 순서)
    for run in &runs {
        let sec = &mut ctx.patched_sections[run.sec_idx];
        rc4.crypt(&mut sec.bytes[run.offset..run.offset + run.len]);
    }

    // ── 6. 부트 스텁 배치 ────────────────────────────────────────────────────
    // v6: --iat-hide 리졸브 테이블.
    // v9: crypto-off에서는 **런으로 등록하지 않고** 평문으로 둔다 (스텁이 직접 읽음).
    let iat_table_blob: Vec<u8> = if ctx.iat_hide && !ctx.original_imports.is_empty() {
        // v10: slot은 절대 VA (image_base + RVA) — 부트 스텁이 [slot]에 기록
        crate::pipeline::iat_hide::build_resolve_table(
            &ctx.original_imports,
            image_base,
            ctx.mba_constant,
            IMPORT_MBA_C,
        )
    } else {
        Vec::new()
    };
    let table_is_run = !no_crypto && !iat_table_blob.is_empty();
    let total_num_runs = runs.len() + usize::from(table_is_run);
    let num_runs_u32 = total_num_runs as u32;

    // ── M6 Phase-2 (--vm-oep): 프로그램 리프트를 1회 수행 ──────────────────────
    // 프로그램 VM 바이트코드와 함께, 원본 entry 블록이 제외(네이티브)인지 여부를
    // 여기서 확정해 부트 스텁의 clean-native-entry 분기(아래)와 프로그램 VM 모듈
    // 양쪽에 동일한 값을 준다. 1st/2nd 패스 스텁이 같은 값을 쓰므로
    // `assert_eq!(stub_code.len(), stub_code_len)` 불변식이 유지된다.
    let (vm_prog_bytecode, vm_oep_native_entry, oep_va): (Vec<u8>, bool, u64) = if vm_oep_effective {
        let base_va = image_base + ctx.target_info.text_rva as u64;
        let ep_va = image_base + ctx.target_info.entry_point_rva as u64;
        let lift = vm::text_lift::lift_program_cfg(
            &ctx.target_info.text_bytes,
            base_va,
            ep_va,
            &ctx.target_info.relayed_sections,
            image_base,
        )?;
        if lift.bytecode.is_empty() {
            return Err(anyhow::anyhow!(
                "M6 Phase-2 --vm-oep: original .text lifted to empty VM program"
            ));
        }
        (lift.bytecode, lift.entry_native, ep_va)
    } else {
        (Vec::new(), false, 0)
    };
    if vm_oep_effective {
        println!(
            "[+] --vm-oep: program entry block {}virtualized ({} bytes bytecode)",
            if vm_oep_native_entry { "NOT " } else { "" },
            vm_prog_bytecode.len()
        );
        // ── [VM-OEP-DIAG] 실제 타깃의 진단 (once.rs:166 원인 판별) ────────────
        //   entry_native=true  : OEP(mainCRTStartup)가 VM화 제외 → clean native OEP
        //                        점프. Program VM은 OEP를 실행하지 않는다.
        //   entry_native=false : OEP가 VM화됨 → Program VM이 OEP를 실행 → native_call
        //                        bridge가 CRT entry를 호출 → once.rs:166 크래시 가능.
        //   → 이 값이 곧 1순위 가설(entry_native)의 정답이다.
        println!("[VM-OEP-DIAG] EP             = 0x{:X}", oep_va);
        println!("[VM-OEP-DIAG] entry_native   = {}", vm_oep_native_entry);
        println!("[VM-OEP-DIAG] bytecode       = {} bytes (blocks={})", vm_prog_bytecode.len(), if vm_oep_native_entry { "n/a (OEP native)" } else { "n/a" });
        println!("[VM-OEP-DIAG] route          = {}", if vm_oep_native_entry { "boot → native OEP → CRT → Once (Program VM 실행 안 함)" } else { "boot → Program VM → native_call → CRT → Once" });
        // STATE_SP 진단 (single-stack fix): boot stub는 vreg[4]=RSP를 스택 포인터로
        // 쓴다. 이제 CALL32/RET/PUSH/POP가 vreg[4]로 실제 스택을 공유하므로, 과거
        // STATE_SP=0 + STATE_PTR_STACK=RSP가 별도 오프셋 스택을 만들어 OEP 프레임과
        // 겹치던 (스택 오염) 문제가 제거되었다. [VM-OEP-DIAG] STATE_SP/PTR_STACK 미사용 (vreg[4]=RSP).
    }

    let stub = BootStubCtx {
        boot_va,
        anti_debug,
        dispatcher_va: dispatcher_va + 0x20,
        code_va: dispatcher_va + code_start as u64,
        code_len,
        runs_va: 0, // 아래에서 채움
        num_runs: num_runs_u32,
        seed_va: 0, // 아래에서 채움
        k1,
        k2,
        k3,
        entry_block_id: ctx.entry_block_id as u32,
        entry_seed: ctx.entry_seed,
        vm: vm_effective,
        chained: chained_effective,
        reencrypt,
        no_crypto,
        // 1st pass: VM 엔트리 타깃은 rel32 범위 안의 자리표시자 사용
        // (dispatcher_va는 부트 영역과 같은 섹션 — 거리 항상 i32 범위).
        vm_entry_va: if vm_effective { dispatcher_va } else { 0 },
        vm_state_va: 0, // imm64 라 길이 불변 — 0으로 두고 아래에서 채움
        vm_prga: vm_effective,
        vm_prga_entry_va: if vm_effective { dispatcher_va } else { 0 },
        vm_prga_state_va: 0, // imm64 라 길이 불변 — 0으로 두고 아래에서 채움
        // M6 Phase-2: 프로그램 VM (OEP→VM entry)
        vm_oep: vm_oep_effective,
        vm_prog_entry_va: if vm_oep_effective { dispatcher_va } else { 0 },
        vm_prog_state_va: 0, // imm64 라 길이 불변 — 0으로 두고 아래에서 채움
        vm_oep_native_entry: vm_oep_native_entry,
        vm_oep_native_va: oep_va,
        // payload_va/crc_va는 imm64라 길이 불변 — 최종 패스(stub3)에서 채운다.
        payload_va: 0,
        payload_len: if payload_relocate { code_len } else { 0 },
        integrity: integrity_effective,
        crc_va: 0,
        iat_enabled: !iat_table_blob.is_empty(),
        mba_master: ctx.mba_constant,
        mba_c: IMPORT_MBA_C,
        iat_table_va: 0,
        iat_ll_slot_va: 0,
        iat_gpa_slot_va: 0,
        mem_harden: ctx.mem_harden,
        mem_ntdll_name_va: 0,
        mem_ntprot_name_va: 0,
        mem_code_base: 0,
        mem_code_size: 0,
        stack_frame: if ctx.iat_hide || ctx.mem_harden { 0x138 } else { 0x110 },
    };

    // 1st pass: stub 길이 측정 (runs_va/seed_va/vm_* = 0)
    let stub_code_len = build_rc4_block(&stub).len();

    // FIX(v3): 안티디버그 블록은 RC4 코드 **앞**에 붙는다. 과거 코드는
    // cursor = boot_off + stub_code_len (RC4 코드 길이만) 로 잡아서, --anti-debug 사용 시
    // 런 테이블/시드가 RC4 코드 꼬리(PRGA 루프 + ret 포함)를 덮어써 부트 스텁이
    // 쓰레기를 실행하고 0xC0000005로 크래시했다. 실제 스텁 전체 길이를 반영한다.
    let ad_bytes = if anti_debug { build_anti_debug_raw_block() } else { Vec::new() };

    // ── v3-composite VM 모듈 (부트 스텁 직후 배치) ────────────────────────────
    // 바이트코드는 VA 독립적이므로 1차 sizing(VA=0)으로 크기를 확정한 뒤,
    // 최종 VA로 재생성한다. 모듈 레이아웃: [code][table][bytecode][state]
    let vm_mod: Option<vm::VmModule> = if vm_effective {
        let bc = vm::lifter::lift_ksa(&vm::ksa::build_ksa_instructions(0, k1, k2, k3))?;
        Some(build_mod(0, 0, 0, bc, vm::handlers::EntryMode::Ksa)?)
    } else {
        None
    };
    // v19: PRGA VM (RC4 키스트림 생성/복호화 루프) — vm과 함께 배치.
    // 바이트코드는 VA 독립이므로 1차 sizing(VA=0)으로 크기 확정 후 최종 VA 재생성.
    let vm_prga_mod: Option<vm::VmModule> = if vm_effective {
        Some(build_mod(
            0, 0, 0,
            vm::prga::build_prga_bytecode(),
            vm::handlers::EntryMode::Prga,
        )?)
    } else {
        None
    };
    // ── M6 Phase-2: 프로그램 VM — 원본 .text를 평문 복호화하지 않고 전체 lift된
    //    프로그램을 VM으로 실행. (OEP→VM entry 전환, --vm-oep)
    let vm_prog_mod: Option<vm::VmModule> = if vm_oep_effective {
        // use the lift computed above (before the 1st-pass stub) so the entry
        // decision and the module bytecode come from the same single lift.
        Some(build_prog_mod(0, 0, 0, vm_prog_bytecode, 0)?)
    } else {
        None
    };

    let mut cursor = boot_off + stub_code_len + ad_bytes.len();
    if vm_mod.is_some() {
        cursor = (cursor + 15) & !15; // align 16 (VM 모듈 시작)
    } else {
        cursor = (cursor + 7) & !7; // align 8 (원래 레이아웃 유지)
    }

    let vm_off = cursor;
    let (vm_entry_va, vm_state_va, vm_total) = if let Some(m) = &vm_mod {
        let state_va = dispatcher_va
            + (vm_off + m.code.len() + m.table.len() + m.bytecode.len()) as u64;
        (dispatcher_va + vm_off as u64, state_va, m.total_len())
    } else {
        (0, 0, 0)
    };
    cursor += vm_total;
    cursor = (cursor + 7) & !7; // align 8

    // v19: PRGA VM을 KSA VM 바로 뒤에 배치 (각각 독립 state 버퍼)
    let vm_prga_off = cursor;
    let (vm_prga_entry_va, vm_prga_state_va, vm_prga_total) = if let Some(m) = &vm_prga_mod {
        let sva = dispatcher_va
            + (vm_prga_off + m.code.len() + m.table.len() + m.bytecode.len()) as u64;
        (dispatcher_va + vm_prga_off as u64, sva, m.total_len())
    } else {
        (0, 0, 0)
    };
    cursor += vm_prga_total;
    cursor = (cursor + 7) & !7; // align 8

    // ── M6 Phase-2: 프로그램 VM을 KSA/PRGA VM 뒤에 배치 (각각 독립 state) ──────
    let vm_prog_off = cursor;
    let (vm_prog_entry_va, vm_prog_state_va, vm_prog_total) = if let Some(m) = &vm_prog_mod {
        let sva = dispatcher_va
            + (vm_prog_off + m.code.len() + m.table.len() + m.bytecode.len()) as u64;
        (dispatcher_va + vm_prog_off as u64, sva, m.total_len())
    } else {
        (0, 0, 0)
    };
    cursor += vm_prog_total;
    cursor = (cursor + 7) & !7; // align 8
    // v16: 패킹당 레이아웃 난독화 — 부트 스텁/시드/문자열/리졸브 테이블의 절대
    // VMA를 빌드마다 랜덤 이동시켜, 정적 분석 스크립트가 하드코딩한 오프셋을
    // (0x1400143b0 등) 매 빌드 무력화한다. rng는 이 함수에서 이미 생성됨.
    let layout_pad = (rng.next_u32() as usize) & 0x3FF; // 0..1023 바이트
    cursor += layout_pad;
    cursor = (cursor + 7) & !7; // align 8
    let runs_off = cursor;
    let runs_va = dispatcher_va + (runs_off + 8) as u64;
    cursor += 8 + total_num_runs * 16; // header(8) + entries (v6: 리졸브 테이블 run 포함)
    cursor = (cursor + 7) & !7; // align 8
    let seed_off = cursor;
    let seed_va = dispatcher_va + seed_off as u64;

    // ── v6: 더미 import / 리졸브 테이블 / mem 문자열 배치 (crc 뒤) ───────────
    let iat_start = (seed_off + 256 + if integrity_effective { 4 } else { 0 } + 7) & !7;
    let mut iat_cursor = iat_start;
    // 1st pass: 블록 길이 확정 (base_rva=0)
    let (dummy_blob0, _, _, _, _) = crate::pipeline::iat_hide::build_dummy_import_block(0);
    let dummy_off = iat_cursor;
    iat_cursor += dummy_blob0.len();
    // 2nd pass: 배치 RVA 반영 (내부 RVA는 u32 고정 길이 — 길이 불변)
    let dummy_base_rva = dispatcher_rva + dummy_off as u32;
    let (dummy_blob, dummy_dir_rva, dummy_dir_size, iat_ll_slot_rva, iat_gpa_slot_rva) =
        crate::pipeline::iat_hide::build_dummy_import_block(dummy_base_rva);
    debug_assert_eq!(dummy_blob.len(), dummy_blob0.len());
    let table_off = if !iat_table_blob.is_empty() {
        let off = iat_cursor;
        iat_cursor += iat_table_blob.len();
        off
    } else {
        0
    };
    let mut mem_ntdll_va = 0u64;
    let mut mem_ntprot_va = 0u64;
    let mut mem_off = 0usize;
    if ctx.mem_harden {
        mem_off = iat_cursor;
        mem_ntdll_va = dispatcher_va + iat_cursor as u64;
        iat_cursor += b"ntdll.dll\0".len();
        mem_ntprot_va = dispatcher_va + iat_cursor as u64;
        iat_cursor += b"NtProtectVirtualMemory\0".len();
    }
    let iat_end = iat_cursor;

    // v6: 더미 import 디렉터리/슬롯/테이블/문자열 RVA·VA 기록 (build.rs/validate가 사용)
    if ctx.iat_hide || ctx.mem_harden {
        ctx.iat_dir_rva = dummy_dir_rva;
        ctx.iat_dir_size = dummy_dir_size;
        ctx.iat_ll_slot_rva = iat_ll_slot_rva;
        ctx.iat_gpa_slot_rva = iat_gpa_slot_rva;
        if !iat_table_blob.is_empty() {
            ctx.iat_table_rva = dispatcher_rva + table_off as u32;
            ctx.iat_table_len = iat_table_blob.len() as u32;
        }
        if ctx.mem_harden {
            ctx.mem_ntdll_name_va = mem_ntdll_va;
            ctx.mem_ntprot_name_va = mem_ntprot_va;
        }
    }

    // 2nd pass: 최종 VA 반영 (payload_va/crc_va는 imm64라 길이 불변 — 아래에서 재생성)
    let stub2 = BootStubCtx {
        runs_va,
        seed_va,
        vm_entry_va,
        vm_state_va,
        vm_prga_entry_va,
        vm_prga_state_va,
        vm_prog_entry_va,
        vm_prog_state_va,
        ..stub
    };
    let stub_code = build_rc4_block(&stub2);
    assert_eq!(stub_code.len(), stub_code_len, "boot stub size changed after VA fixup");

    // 안티디버그 블록 + RC4 블록 결합 (길이 확정용)
    let mut full_stub = Vec::with_capacity(ad_bytes.len() + stub_code.len());
    full_stub.extend_from_slice(&ad_bytes);
    full_stub.extend_from_slice(&stub_code);

    // 부트 스텁 길이 가드
    let stub_end = boot_off + full_stub.len();
    if stub_end > boot_off + BOOT_AREA_RESERVE {
        return Err(anyhow::anyhow!(
            "Boot stub too large: {} bytes (reserve {})",
            full_stub.len(), BOOT_AREA_RESERVE
        ));
    }

    // FIX(v3): 런 테이블/시드가 스텁 영역과 겹치지 않아야 한다 (위 cursor 수정의 방어 검사).
    // v5: --integrity 시 seed 뒤 4바이트(CRC32)까지 포함.
    let boot_data_end = if ctx.iat_hide || ctx.mem_harden {
        iat_end
    } else {
        seed_off + 256 + if integrity_effective { 4 } else { 0 }
    };
    if runs_off < stub_end || boot_data_end > boot_off + BOOT_AREA_RESERVE {
        return Err(anyhow::anyhow!(
            "Boot area layout overlap: stub_end=0x{:X} runs_off=0x{:X} seed_off=0x{:X} (reserve 0x{:X})",
            stub_end, runs_off, seed_off, BOOT_AREA_RESERVE
        ));
    }

    // ── v5 용량 제어: 실제 사용분만 남기고 섹션 tail을 자른다 ──────────────────
    // (pass4가 여유 있게 예약한 BOOT_AREA_RESERVE 중 사용하지 않은 영역 제거 →
    //   raw 섹션 크기가 줄어 파일 크기 감소. .vdata도 잘린 .textb 직후에 붙는다.)
    let boot_end = stub_end
        .max(vm_off + vm_total)
        .max(runs_off + 8 + total_num_runs * 16)
        .max(boot_data_end);
    let old_section_len = btg.bytes.len();
    let new_section_len = (boot_end + 0xFF) & !0xFF;
    if new_section_len < old_section_len {
        btg.bytes.truncate(new_section_len);
        btg.virtual_size = new_section_len as u32;
    }
    println!(
        "[+] v5 Size control: .textb 0x{:X} -> 0x{:X} bytes (boot area trimmed, saved {} bytes)",
        old_section_len,
        new_section_len,
        old_section_len.saturating_sub(new_section_len)
    );

    // ── Native Rust Thread Guard Sentinel (-2) Safety Patch (.textb) ─────────────
    // 원본 12B 패턴: mov rax, [rcx] (48 8b 01); movzx ecx, [rax] (0f b6 08); mov [rax], 0 (c6 00 00); cmp cl, 1 (80 f9 01)
    // 치환 12B 패턴: mov rax, [rcx] (48 8b 01); test rax, rax (48 85 c0); js +4 (78 04); movzx ecx, [rax] (0f b6 08); nop (90)
    // rax가 음수 센티널(-2)일 때 native execution에서 0xC0000005 AV 크래시가 발생하는 것을 완전 차단한다.
    let pat_target: [u8; 12] = [
        0x48, 0x8b, 0x01, 0x0f, 0xb6, 0x08, 0xc6, 0x00, 0x00, 0x80, 0xf9, 0x01,
    ];
    let pat_repl: [u8; 12] = [
        0x48, 0x8b, 0x01, 0x48, 0x85, 0xc0, 0x78, 0x04, 0x0f, 0xb6, 0x08, 0x90,
    ];
    let mut native_guards_patched = 0usize;
    if btg.bytes.len() >= 12 {
        let sweep_end = max_phys_end.min(btg.bytes.len().saturating_sub(12));
        let sweep_start = first_block_offset.min(sweep_end);
        for i in sweep_start..sweep_end {
            if btg.bytes[i..i + 12] == pat_target {
                btg.bytes[i..i + 12].copy_from_slice(&pat_repl);
                native_guards_patched += 1;
            }
        }
    }
    if native_guards_patched > 0 {
        println!("[+] Native Thread Guard Sentinel Safety Patch: Patched {} sentinel guard site(s) in .textb.", native_guards_patched);
    }

    // ── Neutralize FastFail stubs (b9 07 00 00 00 cd 29 -> ret nop) in .textb ─────
    let ff_target: [u8; 7] = [0xb9, 0x07, 0x00, 0x00, 0x00, 0xcd, 0x29];
    let ff_repl: [u8; 7]   = [0x31, 0xc9, 0xc3, 0x90, 0x90, 0x90, 0x90];
    let mut textb_ff_count = 0usize;
    if btg.bytes.len() >= 7 {
        let sweep_end = max_phys_end.min(btg.bytes.len().saturating_sub(7));
        let sweep_start = first_block_offset.min(sweep_end);
        for i in sweep_start..sweep_end {
            if btg.bytes[i..i + 7] == ff_target {
                btg.bytes[i..i + 7].copy_from_slice(&ff_repl);
                textb_ff_count += 1;
            }
        }
    }
    if textb_ff_count > 0 {
        println!("[+] FastFail Safety Patch: Neutralized {} native mov ecx,7; int 29h stub(s) in .textb.", textb_ff_count);
    }

    // ── ud2 (0x0F 0x0B) 은 절대 NOP으로 바꾸지 않는다 ────────────────────────────
    // (v13.4c: removed the previous whole-section .textb ud2 -> nop nop sweep.)
    //
    // WHY: `ud2` is a *guaranteed* hard trap — the CPU never falls through past it.
    // Converting it to `nop nop` (0x90 0x90) silently *enables* fall-through. In a
    // block-shuffled .textb the bytes after any given ud2 belong to a completely
    // unrelated block, so `call ...; ud2; <next function>` becomes
    // `call ...; nop; nop; <next function>` — control now falls straight into the
    // next (shuffled) function, executing garbage instead of trapping. That wrong
    // instruction path is what then triggers a panic, a bogus OS unwind, a wrong
    // RSP and finally 0xC0000005.
    //
    // Leaving ud2 as-is keeps the "no fall-through" contract: if it is ever reached
    // (only on a genuine unreachable-path bug), the process faults *cleanly* at that
    // exact instruction instead of silently corrupting control flow. Any reachable
    // ud2 is a separate bug to fix at its source, not by erasing the trap.
    // (The per-block ud2 neutralization in pass4_section.rs is removed likewise.)

    // ── v4: .vdata 페이로드 섹션 VA (빌더와 동일한 정렬 규칙 — 잘린 .textb 직후) ──
    let payload_va: u64 = if payload_relocate && code_len > 0 {
        let sa = if ctx.target_info.section_alignment == 0 {
            0x1000
        } else {
            ctx.target_info.section_alignment
        } as u64;
        let align = |x: u64| ((x + sa - 1) / sa) * sa;
        dispatcher_va + align(btg.bytes.len() as u64)
    } else {
        0
    };

    // ── 3rd pass: 최종 스텁 (payload_va + crc_va 반영) ─────────────────────────
    let crc_va = dispatcher_va + (seed_off + 256) as u64;
    let stub3 = BootStubCtx {
        payload_va,
        crc_va,
        // v6: 배치 확정 후 반영 (모두 imm64 — 길이 불변)
        iat_table_va: if !iat_table_blob.is_empty() {
            dispatcher_va + table_off as u64
        } else {
            0
        },
        iat_ll_slot_va: if ctx.iat_hide || ctx.mem_harden {
            image_base + ctx.iat_ll_slot_rva as u64
        } else {
            0
        },
        iat_gpa_slot_va: if ctx.iat_hide || ctx.mem_harden {
            image_base + ctx.iat_gpa_slot_rva as u64
        } else {
            0
        },
        mba_master: ctx.mba_constant,
        mba_c: IMPORT_MBA_C,
        mem_ntdll_name_va: mem_ntdll_va,
        mem_ntprot_name_va: mem_ntprot_va,
        mem_code_base: dispatcher_va,
        mem_code_size: ((new_section_len as u64) + 0xFFF) & !0xFFF,
        ..stub2
    };
    let stub_code_final = build_rc4_block(&stub3);
    assert_eq!(
        stub_code_final.len(),
        stub_code_len,
        "boot stub size changed after payload/crc VA fixup"
    );
    let mut full_stub_final = Vec::with_capacity(ad_bytes.len() + stub_code_final.len());
    full_stub_final.extend_from_slice(&ad_bytes);
    full_stub_final.extend_from_slice(&stub_code_final);
    assert_eq!(full_stub_final.len(), full_stub.len());

    // 부트 스텁 복사
    btg.bytes[boot_off..stub_end].copy_from_slice(&full_stub_final);

    // ── VM 모듈 배치 (최종 VA로 재생성 후 복사) ───────────────────────────────
    if let Some(m) = vm_mod {
        let vm_va = dispatcher_va + vm_off as u64;
        let module = build_mod(
            vm_va,
            vm_va + m.code.len() as u64,
            vm_va + (m.code.len() + m.table.len()) as u64,
            m.bytecode.clone(),
            vm::handlers::EntryMode::Ksa,
        )?;
        let vm_end = vm_off + module.total_len();
        if vm_end > boot_off + BOOT_AREA_RESERVE {
            return Err(anyhow::anyhow!(
                "VM module too large: {} bytes at 0x{:X} (reserve 0x{:X})",
                module.total_len(), vm_off, BOOT_AREA_RESERVE
            ));
        }
        btg.bytes[vm_off..vm_off + module.code.len()].copy_from_slice(&module.code);
        let t = vm_off + module.code.len();
        btg.bytes[t..t + module.table.len()].copy_from_slice(&module.table);
        let b = t + module.table.len();
        btg.bytes[b..b + module.bytecode.len()].copy_from_slice(&module.bytecode);
        println!(
            "[+] Composite VM: module @0x{:X} (code {}B table {}B bytecode {}B state {}B) entry_va=0x{:X} state_va=0x{:X}",
            vm_off,
            module.code.len(),
            module.table.len(),
            module.bytecode.len(),
            vm::VM_STATE_SIZE,
            vm_entry_va,
            vm_state_va
        );
    }
    // v19: PRGA VM 모듈 배치 (최종 VA로 재생성 후 복사)
    if let Some(m) = vm_prga_mod {
        let pva = dispatcher_va + vm_prga_off as u64;
        let pmod = build_mod(
            pva,
            pva + m.code.len() as u64,
            pva + (m.code.len() + m.table.len()) as u64,
            m.bytecode.clone(),
            vm::handlers::EntryMode::Prga,
        )?;
        let pend = vm_prga_off + pmod.total_len();
        if pend > boot_off + BOOT_AREA_RESERVE {
            return Err(anyhow::anyhow!(
                "PRGA VM module too large: {} bytes at 0x{:X}",
                pmod.total_len(), vm_prga_off
            ));
        }
        btg.bytes[vm_prga_off..vm_prga_off + pmod.code.len()].copy_from_slice(&pmod.code);
        let t = vm_prga_off + pmod.code.len();
        btg.bytes[t..t + pmod.table.len()].copy_from_slice(&pmod.table);
        let b = t + pmod.table.len();
        btg.bytes[b..b + pmod.bytecode.len()].copy_from_slice(&pmod.bytecode);
        println!(
            "[+] Composite VM PRGA: module @0x{:X} (code {}B table {}B bytecode {}B state {}B) entry_va=0x{:X} state_va=0x{:X}",
            vm_prga_off,
            pmod.code.len(),
            pmod.table.len(),
            pmod.bytecode.len(),
            vm::VM_STATE_SIZE,
            vm_prga_entry_va,
            vm_prga_state_va
        );
    }
    // ── M6 Phase-2: 프로그램 VM 모듈 배치 (최종 VA로 재생성 후 복사) ──────────
    if let Some(m) = vm_prog_mod {
        let prva = dispatcher_va + vm_prog_off as u64;
        let prmod = build_prog_mod(
            prva,
            prva + m.code.len() as u64,
            prva + (m.code.len() + m.table.len()) as u64,
            m.bytecode.clone(),
            vm_prog_state_va,
        )?;
        let prend = vm_prog_off + prmod.total_len();
        if prend > boot_off + BOOT_AREA_RESERVE {
            return Err(anyhow::anyhow!(
                "Program VM module too large: {} bytes at 0x{:X}",
                prmod.total_len(), vm_prog_off
            ));
        }
        btg.bytes[vm_prog_off..vm_prog_off + prmod.code.len()].copy_from_slice(&prmod.code);
        let t = vm_prog_off + prmod.code.len();
        btg.bytes[t..t + prmod.table.len()].copy_from_slice(&prmod.table);
        let b = t + prmod.table.len();
        btg.bytes[b..b + prmod.bytecode.len()].copy_from_slice(&prmod.bytecode);
        println!(
            "[+] M6 Phase-2 Program VM: module @0x{:X} (code {}B table {}B bytecode {}B state {}B) entry_va=0x{:X} state_va=0x{:X}",
            vm_prog_off,
            prmod.code.len(),
            prmod.table.len(),
            prmod.bytecode.len(),
            vm::VM_STATE_SIZE,
            vm_prog_entry_va,
            vm_prog_state_va
        );
    }

    // 런 테이블 헤더 + 엔트리 (절대 VA) — 문자열 런 + v6 리졸브 테이블 run
    btg.bytes[runs_off..runs_off + 4].copy_from_slice(&num_runs_u32.to_le_bytes());
    for (i, run) in runs.iter().enumerate() {
        let e = runs_off + 8 + i * 16;
        btg.bytes[e..e + 8].copy_from_slice(&run.va.to_le_bytes());
        btg.bytes[e + 8..e + 16].copy_from_slice(&(run.len as u64).to_le_bytes());
    }
    if table_is_run {
        let e = runs_off + 8 + runs.len() * 16;
        btg.bytes[e..e + 8]
            .copy_from_slice(&(dispatcher_va + table_off as u64).to_le_bytes());
        btg.bytes[e + 8..e + 16].copy_from_slice(&(iat_table_blob.len() as u64).to_le_bytes());
    }

    // 시드 (masked)
    // v19: base-bound — 파일에는 seed_stored(=seed_masked ^ bind(preferred_base)) 저장.
    btg.bytes[seed_off..seed_off + 256].copy_from_slice(&seed_stored);

    // ── v5 --integrity: 코드 영역 CRC32 저장 (부트 스텁이 비교) ──────────────
    // v9: chained/plain = 평문 CRC, reencrypt = 파일 암호문 CRC. crypto-off는 없음.
    if integrity_effective {
        let crc_val = crc32(crc_source.as_deref().unwrap_or(&[]));
        btg.bytes[seed_off + 256..seed_off + 260].copy_from_slice(&crc_val.to_le_bytes());
        println!(
            "[+] v5 Integrity: code-region CRC32 = 0x{:08X} stored @0x{:X} (stub traps on mismatch)",
            crc_val,
            seed_off + 256
        );
    }

    // ── v6: 더미 import / 리졸브 테이블 / mem 문자열 기록 ────────────────────
    if ctx.iat_hide || ctx.mem_harden {
        btg.bytes[dummy_off..dummy_off + dummy_blob.len()].copy_from_slice(&dummy_blob);
        if !iat_table_blob.is_empty() {
            btg.bytes[table_off..table_off + iat_table_blob.len()].copy_from_slice(&iat_table_blob);
            // v9: crypto-on에서만 리졸브 테이블을 마지막 run으로 RC4 암호화한다.
            //     crypto-off에서는 평문으로 두고 스텁이 직접 읽는다.
            if table_is_run {
                rc4.crypt(&mut btg.bytes[table_off..table_off + iat_table_blob.len()]);
            }
        }
        if ctx.mem_harden {
            let dll = b"ntdll.dll\0";
            let fname = b"NtProtectVirtualMemory\0";
            btg.bytes[mem_off..mem_off + dll.len()].copy_from_slice(dll);
            btg.bytes[mem_off + dll.len()..mem_off + dll.len() + fname.len()].copy_from_slice(fname);
        }
        println!(
            "[+] v6 IAT/Mem data placed: dummy_import@0x{:X} (dir_rva=0x{:X}), table@0x{:X}/{}B, mem_str@0x{:X}",
            dummy_off,
            ctx.iat_dir_rva,
            table_off,
            iat_table_blob.len(),
            mem_off
        );
    }

    // ── 7. 문자열 섹션을 쓰기 가능으로 (부트 스텁이 복호화) ───────────────────
    for run in &runs {
        let sec = &mut ctx.patched_sections[run.sec_idx];
        sec.characteristics |= 0x8000_0000; // IMAGE_SCN_MEM_WRITE
    }

    println!(
        "[+] v3 Crypto: boot stub @0x{:X} ({} bytes), runs @0x{:X}, seed @0x{:X}, entry=0x{:X}",
        boot_off, full_stub.len(), runs_off, seed_off, ctx.boot_entry_offset
    );

    // ── v4: .vdata 페이로드 섹션 등록 (빌더가 .textb 직후 배치) ───────────────
    if payload_relocate && !payload_bytes.is_empty() {
        let payload_rva = (payload_va - image_base) as u32;
        ctx.payload_rva = payload_rva;
        ctx.payload_len = code_len;
        ctx.payload_section_data = Some(crate::pe::builder::SectionData {
            name: ".vdata".to_string(),
            virtual_address: payload_rva,
            virtual_size: payload_bytes.len() as u32,
            characteristics: 0x4000_0040, // INITIALIZED_DATA | READ
            bytes: payload_bytes,
        });
        println!(
            "[+] v4 Payload Relocate: .vdata section @RVA 0x{:X} ({} bytes) registered",
            payload_rva, code_len
        );
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// 문자열 런 스캔
// ──────────────────────────────────────────────────────────────────────────────

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t'
}

fn scan_string_runs(
    sections: &mut [SectionData],
    image_base: u64,
    protected: &[(u32, u32)],
) -> Vec<StringRun> {
    let mut runs = Vec::new();
    let mut total = 0usize;

    for (sec_idx, sec) in sections.iter().enumerate() {
        // 대상: read-only 데이터 섹션 (이름 기준). .pdata/.rsrc/.textb 제외.
        let name = sec.name.to_lowercase();
        let is_data_sec = (name.starts_with(".rdata")
            || name.starts_with(".rodata")
            || name.contains("const")
            || name.starts_with(".sdata"))
            && !name.starts_with(".pdata")
            && !name.starts_with(".rsrc")
            && !name.starts_with(".text");
        if !is_data_sec || sec.bytes.is_empty() {
            continue;
        }

        let mut i = 0usize;
        while i < sec.bytes.len() && runs.len() < MAX_STRING_RUNS {
            // ── UTF-16LE 런 우선 검사 (문자+0x00 쌍) ─────────────────────────────
            // FIX: 과거 구현은 ASCII 스캔이 첫 문자를 소비한 뒤 그 위치에서 wide 스캔을
            // 시작해서, "H\0e\0l\0l\0o\0" 같은 UTF-16LE 문자열의 첫 글자를 ASCII가
            // 먹어치워 wide 런을 절대 감지하지 못했다 (dead code). i에서 쌍을 먼저 검사한다.
            let wide_start = i;
            let mut w = i;
            while w + 1 < sec.bytes.len()
                && is_printable_ascii(sec.bytes[w])
                && sec.bytes[w + 1] == 0
            {
                w += 2;
            }
            let wide_len = w - wide_start;
            // Bug-1 fix: NUL(0x00)로 종료된 wide 런만 채택하고, 4바이트 정렬 경계로만
            // 자른다. usize 크기의 Rust 상태 워드(Once/AtomicUsize)가 런 경계에 절대
            // 걸치지 않게 되어, 부분 XOR로 상태가 오염되는 일이 없어야 한다.
            if wide_len >= 16 && w < sec.bytes.len() && sec.bytes[w] == 0 {
                let ws = (wide_start + 3) & !3;
                let we = w & !3;
                if we > ws && (we - ws) >= 8 {
                    push_run(&mut runs, &mut total, sec_idx, ws, we - ws, image_base, sec, protected);
                    i = w;
                    continue;
                }
            }

            // ── ASCII 런 ──
            let ascii_start = i;
            while i < sec.bytes.len() && is_printable_ascii(sec.bytes[i]) {
                i += 1;
            }
            let ascii_len = i - ascii_start;
            // Bug-1 fix: NUL(0x00)로 종료된 문자열만 채택 + 4바이트 정렬 경계로 절단.
            // 비-정렬 프린터블 덩어리(구조체 필드 등)를 런으로 잡지 않아 Rust 상태 워드가
            // 런 안에 포함되거나 런 경계에 걸치지 않는다.
            let nul_terminated = i < sec.bytes.len() && sec.bytes[i] == 0;
            let ast = (ascii_start + 3) & !3;
            let ae = i & !3;
            if nul_terminated && ascii_len >= 8 && ae > ast && (ae - ast) >= 8 {
                push_run(&mut runs, &mut total, sec_idx, ast, ae - ast, image_base, sec, protected);
            }
            if i == ascii_start {
                // 비-프린터블 바이트: wide도 ASCII도 아니면 1바이트 건너뜀 (무한 루프 방지)
                i += 1;
            }
        }
        if total >= MAX_STRING_TOTAL {
            println!("[!] v3 Crypto: string run total reached cap ({} bytes).", MAX_STRING_TOTAL);
            break;
        }
    }

    runs
}

#[allow(clippy::too_many_arguments)]
fn push_run(
    runs: &mut Vec<StringRun>,
    total: &mut usize,
    sec_idx: usize,
    offset: usize,
    len: usize,
    image_base: u64,
    sec: &SectionData,
    protected: &[(u32, u32)],
) {
    if *total + len > MAX_STRING_TOTAL || runs.len() >= MAX_STRING_RUNS {
        return;
    }
    let rva = sec.virtual_address + offset as u32;
    let rva_end = rva + len as u32;
    // 로더가 로드 전에 읽는 영역(import, IAT, LoadConfig, cookie 등)은 건너뛴다.
    for &(ps, pe) in protected {
        if ps >= rva_end {
            break;
        }
        if rva < pe && rva_end > ps {
            return;
        }
    }
    runs.push(StringRun {
        sec_idx,
        offset,
        len,
        va: image_base + rva as u64,
    });
    *total += len;
}

// ──────────────────────────────────────────────────────────────────────────────
// 단위 테스트
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_roundtrip() {
        let key = [0x11u8; 32];
        let mut data = vec![0xABu8; 4096];
        let orig = data.clone();
        let mut enc = Rc4::new(&key);
        enc.crypt(&mut data);
        assert_ne!(data, orig);
        let mut dec = Rc4::new(&key);
        dec.crypt(&mut data);
        assert_eq!(data, orig);
    }

    #[test]
    fn test_rc4_known_key() {
        // Wikipedia RC4 test vector (key "Key")
        let key = b"Key";
        let mut rc4 = Rc4::new(key);
        let mut out = [0u8; 3];
        rc4.crypt(&mut out);
        assert_eq!(out, [0xEB, 0x9F, 0x77]);
    }

    #[test]
    fn test_chained_roundtrip() {
        // v7: chained_encrypt로 암호화 → 동일 체인으로 복호화 → 원문 복원 + 마지막 윈도우 일치
        let anchor = [0xA7u8; 256];
        let mut data: Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(31) + 7) as u8).collect();
        let orig = data.clone();
        let last_key = chained_encrypt(&mut data, &anchor);

        let mut prev = anchor;
        let mut off = 0usize;
        while off < data.len() {
            let n = (data.len() - off).min(256);
            let mut rc4 = Rc4::new(&prev);
            rc4.crypt(&mut data[off..off + n]);
            if off + n >= 256 {
                prev.copy_from_slice(&data[off + n - 256..off + n]);
            } else {
                prev = [0u8; 256];
                prev[..off + n].copy_from_slice(&data[..off + n]);
            }
            off += n;
        }
        assert_eq!(data, orig, "chained decrypt must restore plaintext");
        assert_eq!(prev, last_key, "last 256B window must match encrypt return");
    }

    #[test]
    fn test_anti_debug_block_length() {
        let b = build_anti_debug_raw_block();
        assert_eq!(b.len(), ANTI_DEBUG_BLOCK_LEN);
        assert_eq!(&b[b.len()-2..], &[0x0F, 0x0B]); // ud2
    }

    #[test]
    fn test_boot_stub_generates() {
        // build_rc4_block + build_anti_debug_raw_block가 패닉 없이 인코딩되는지 검증
        let stub = BootStubCtx {
            boot_va: 0x140001000,
            anti_debug: true,
            dispatcher_va: 0x140001020,
            code_va: 0x140005000,
            code_len: 0x100,
            runs_va: 0x140001400,
            num_runs: 2,
            seed_va: 0x140001500,
            k1: 0xDEADBEEF,
            k2: 0x12345678,
            k3: 0x0BADF00D,
            entry_block_id: 7,
            entry_seed: 0xAABBCCDD,
            vm: false,
            chained: false,
            reencrypt: false,
            no_crypto: false,
            vm_entry_va: 0,
            vm_state_va: 0,
            vm_prga: false,
            vm_prga_entry_va: 0,
            vm_prga_state_va: 0,
            vm_oep: false,
            vm_prog_entry_va: 0,
            vm_prog_state_va: 0,
            vm_oep_native_entry: false,
            vm_oep_native_va: 0,
            payload_va: 0,
            payload_len: 0,
            integrity: false,
            crc_va: 0,
            iat_enabled: false,
            iat_table_va: 0,
            iat_ll_slot_va: 0,
            iat_gpa_slot_va: 0,
        mba_master: 0x12345678,
        mba_c: IMPORT_MBA_C,
            mem_harden: false,
            mem_ntdll_name_va: 0,
            mem_ntprot_name_va: 0,
            mem_code_base: 0,
            mem_code_size: 0,
            stack_frame: 0x110,
        };
        let ad = build_anti_debug_raw_block();
        assert_eq!(ad.len(), ANTI_DEBUG_BLOCK_LEN);
        let code = build_rc4_block(&stub);
        assert!(!code.is_empty());
        assert!(code.len() > 100, "rc4 block too small: {}", code.len());
        // 마지막 명령이 ret(0xC3)이어야 한다 (prga 서브루틴 종료)
        assert_eq!(*code.last().unwrap(), 0xC3);

        // anti_debug=false 변형도 인코딩 가능해야 한다
        let stub2 = BootStubCtx { anti_debug: false, ..stub };
        let code2 = build_rc4_block(&stub2);
        assert!(!code2.is_empty());
    }

    #[test]
    fn test_key_mix_deterministic() {
        // v10: 키 유도는 vm/ksa::key_mix 단일 소스 — 패커 키 == reference_ksa의
        // S-box(부트 스텁/VM과 동일 경로)와 동치여야 한다.
        let k1 = 0xDEADBEEFu32;
        let k2 = 0x12345678u32;
        let k3 = 0x0BADF00Du32;
        let seed_masked: Vec<u8> = (0..256u32)
            .map(|i| ((i.wrapping_mul(31) + 7) as u8) ^ 0xA7)
            .collect();
        let mut key = [0u8; 256];
        for i in 0..256usize {
            let iu = i as u32;
            key[i] = seed_masked[i] ^ (crate::vm::ksa::key_mix(iu, k1, k2, k3) as u8);
        }
        // key_mix 결정성 + 인접 i 확산
        assert_eq!(
            crate::vm::ksa::key_mix(3, k1, k2, k3),
            crate::vm::ksa::key_mix(3, k1, k2, k3)
        );
        assert_ne!(
            crate::vm::ksa::key_mix(3, k1, k2, k3),
            crate::vm::ksa::key_mix(4, k1, k2, k3)
        );
        // 패커 key → RC4 KSA S-box == reference_ksa S-box (부트 스텁/VM 동치성)
        let mut rc4 = Rc4::new(&key);
        let mut ref_sbox = [0u8; 256];
        crate::vm::ksa::reference_ksa(
            &seed_masked.clone().try_into().unwrap(),
            k1,
            k2,
            k3,
            &mut ref_sbox,
        );
        assert_eq!(
            rc4.sbox(),
            &ref_sbox,
            "packer key derivation must match reference KSA (boot stub / VM path)"
        );
    }

    #[test]
    fn test_boot_stub_ksa_matches_shared_list() {
        // v10 회귀: 부트 스텁이 쓰는 KSA 명령 리스트는 vm/ksa::build_ksa_instructions와
        // 정확히 같아야 한다 (단일 소스). 명령 코드/피연산자 종류를 비교한다.
        let shared = crate::vm::ksa::build_ksa_instructions(0x140001500, 0x11111111, 0x22222222, 0x33333333);
        let codes: Vec<iced_x86::Code> = shared.iter().map(|k| k.inst.code()).collect();
        // 리스트는 S[i]=i init 루프로 시작하고 KSA 루프를 포함해야 한다
        assert!(codes.contains(&iced_x86::Code::Mov_rm8_r8));
        assert!(codes.contains(&iced_x86::Code::Jb_rel32_64));
        assert!(codes.contains(&iced_x86::Code::Ror_rm32_imm8), "v10 key_mix must end with ror");
        // 부트 스텁 build_rc4_block가 이 리스트를 그대로 소비하는지 (라벨 매핑 스모크)
        let stub = BootStubCtx {
            boot_va: 0x140001000,
            anti_debug: false,
            dispatcher_va: 0x140001020,
            code_va: 0x140005000,
            code_len: 0x100,
            runs_va: 0x140001400,
            num_runs: 1,
            seed_va: 0x140001500,
            k1: 0x11111111,
            k2: 0x22222222,
            k3: 0x33333333,
            entry_block_id: 0,
            entry_seed: 0xAABBCCDD,
            vm: false,
            chained: false,
            reencrypt: false,
            no_crypto: false,
            vm_entry_va: 0,
            vm_state_va: 0,
            vm_prga: false,
            vm_prga_entry_va: 0,
            vm_prga_state_va: 0,
            vm_oep: false,
            vm_prog_entry_va: 0,
            vm_prog_state_va: 0,
            vm_oep_native_entry: false,
            vm_oep_native_va: 0,
            payload_va: 0,
            payload_len: 0,
            integrity: false,
            crc_va: 0,
            iat_enabled: false,
            iat_table_va: 0,
            iat_ll_slot_va: 0,
            iat_gpa_slot_va: 0,
        mba_master: 0x12345678,
        mba_c: IMPORT_MBA_C,
            mem_harden: false,
            mem_ntdll_name_va: 0,
            mem_ntprot_name_va: 0,
            mem_code_base: 0,
            mem_code_size: 0,
            stack_frame: 0x110,
        };
        let code = build_rc4_block(&stub);
        assert!(!code.is_empty());
        assert_eq!(*code.last().unwrap(), 0xC3);
    }

    #[test]
    fn test_scan_ascii_runs_still_work() {
        // 일반 ASCII 문자열("LoadLibraryA\0")은 여전히 감지되어야 한다.
        let mut sec = SectionData {
            name: ".rdata".to_string(),
            virtual_address: 0x5000,
            virtual_size: 0x100,
            characteristics: 0x40000040,
            bytes: {
                let mut b = vec![0u8; 0x100];
                b[..12].copy_from_slice(b"LoadLibraryA");
                b
            },
        };
        let runs = scan_string_runs(std::slice::from_mut(&mut sec), 0x140000000, &[]);
        assert_eq!(runs.len(), 1, "ASCII string run should be detected");
        assert_eq!(runs[0].len, 12);
        assert_eq!(runs[0].va, 0x140005000);
    }

    #[test]
    fn test_scan_utf16_runs_detected() {
        // FIX 회귀 테스트: UTF-16LE 문자열("Hello World\0", 22바이트)이 감지되어야 한다.
        // 과거 구현은 ASCII 스캔이 첫 문자를 소비해 wide 런을 절대 찾지 못했다.
        // Bug-1 fix: 런은 4바이트 정렬 경계로 절단되므로 22바이트 -> 20바이트(4-정렬)로
        // 감지된다(usize 상태 워드가 런 경계에 걸치지 않도록).
        let mut sec = SectionData {
            name: ".rdata".to_string(),
            virtual_address: 0x5000,
            virtual_size: 0x100,
            characteristics: 0x40000040,
            bytes: {
                let mut b = vec![0u8; 0x100];
                for (i, c) in "Hello World".encode_utf16().enumerate() {
                    b[i * 2] = c as u8;
                    b[i * 2 + 1] = (c >> 8) as u8;
                }
                b
            },
        };
        let runs = scan_string_runs(std::slice::from_mut(&mut sec), 0x140000000, &[]);
        assert!(!runs.is_empty(), "UTF-16LE string run should be detected");
        assert_eq!(runs[0].len, 20, "Hello World = 22B, truncated to 4-aligned 20B");
        assert_eq!(runs[0].va, 0x140005000);
    }

    #[test]
    fn test_full_pipeline_crypto_anti_debug_no_overlap() {
        // FIX 회귀 테스트: crypto + anti_debug로 실제 더미 타깃 전체 파이프라인을 돌려
        // 부트 영역 레이아웃(스텁 vs 런테이블/시드)이 겹치지 않는지 검증한다.
        // 과거 코드는 cursor = boot_off + stub_code_len 로 계산해 anti_debug 블록(69B)만큼
        // 런테이블/시드가 RC4 코드 꼬리를 덮어써 이 테스트가 Err를 반환했다.
        let dummy = crate::pe::generate_dummy_target_pe().unwrap();
        let info = crate::pe::TargetPeInfo::parse(&dummy).unwrap();
        let section_alignment = if info.section_alignment == 0 { 0x1000 } else { info.section_alignment };
        let dispatcher_rva: u32 = info
            .relayed_sections
            .iter()
            .map(|s| {
                s.virtual_address
                    + ((s.virtual_size.max(s.bytes.len() as u32) + section_alignment - 1) / section_alignment)
                        * section_alignment
            })
            .max()
            .unwrap_or(0x2000);
        let dispatcher_va = info.image_base + dispatcher_rva as u64;
        let mut ctx = PipelineContext::new(info, dispatcher_va, dispatcher_rva, 3);
        crate::pipeline::pass1_slice::run(&mut ctx).unwrap();
        crate::pipeline::pass2_shuffle::run(&mut ctx).unwrap();
        crate::pipeline::pass3_encode::run(&mut ctx).unwrap();
        crate::pipeline::pass4_section::run(&mut ctx, true, true, false).unwrap();
        let relayed = ctx.target_info.relayed_sections.clone();
        crate::pipeline::patch_data::run(&mut ctx, relayed).unwrap();
        crate::pipeline::crypto::run(&mut ctx, true, true, false, 100, false, false, false, false).unwrap();

        // 부트 스텁의 마지막 바이트(ret, 0xC3)가 런테이블/시드에 덮이지 않아야 한다.
        let btg = ctx.btg_section_data.as_ref().unwrap();
        let boot_off = ctx.boot_entry_offset as usize;
        // crypto::run의 Err 가드가 통과했다는 것 자체가 레이아웃 무결성을 보장한다.
        // v5: 동적 부트 영역 — 고정 예약(0x4000) 대신 사용분만 남도록 잘렸어야 한다.
        assert!(
            btg.bytes.len() < boot_off + 0x4000,
            "v5 size control failed: section not trimmed (len=0x{:X}, boot_off=0x{:X})",
            btg.bytes.len(),
            boot_off
        );
        // 런 테이블/시드가 스텁 뒤에 배치됐고, 잘린 tail에도 부트 콘텐츠가 남아 있다.
        assert!(btg.bytes.len() - boot_off >= 0x100);
    }

    #[test]
    fn test_crc32_known_vector() {
        // 표준 CRC-32 체크 벡터 (zlib): crc32("123456789") == 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn test_boot_stub_generates_with_integrity() {
        // --integrity 경로의 부트 스텁이 인코딩 가능하고 길이 불변(VA 픽스업)한지 검증.
        let stub = BootStubCtx {
            boot_va: 0x140001000,
            anti_debug: true,
            dispatcher_va: 0x140001020,
            code_va: 0x140005000,
            code_len: 0x100,
            runs_va: 0x140001400,
            num_runs: 2,
            seed_va: 0x140001500,
            k1: 0xDEADBEEF,
            k2: 0x12345678,
            k3: 0x0BADF00D,
            entry_block_id: 7,
            entry_seed: 0xAABBCCDD,
            vm: false,
            chained: false,
            reencrypt: false,
            no_crypto: false,
            vm_entry_va: 0,
            vm_state_va: 0,
            vm_prga: false,
            vm_prga_entry_va: 0,
            vm_prga_state_va: 0,
            vm_oep: false,
            vm_prog_entry_va: 0,
            vm_prog_state_va: 0,
            vm_oep_native_entry: false,
            vm_oep_native_va: 0,
            payload_va: 0x140006000,
            payload_len: 0x100,
            integrity: true,
            crc_va: 0x140001600,
            iat_enabled: false,
            iat_table_va: 0,
            iat_ll_slot_va: 0,
            iat_gpa_slot_va: 0,
        mba_master: 0x12345678,
        mba_c: IMPORT_MBA_C,
            mem_harden: false,
            mem_ntdll_name_va: 0,
            mem_ntprot_name_va: 0,
            mem_code_base: 0,
            mem_code_size: 0,
            stack_frame: 0x138,
        };
        let code = build_rc4_block(&stub);
        assert!(!code.is_empty());
        // 마지막 명령이 ret(0xC3)이어야 한다 (prga 서브루틴 종료)
        assert_eq!(*code.last().unwrap(), 0xC3);
        // CRC 루틴이 포함됐는지: ud2(0F 0B) + CRC 폴리 상수(ED B8 83 20) 흔적 검사
        let has_ud2 = code.windows(2).any(|w| w == [0x0F, 0x0B]);
        assert!(has_ud2, "integrity stub must contain ud2 trap");
    }

    #[test]
    fn test_phase03_per_block_encryption_roundtrip() {
        // v8 (Phase 0.3): --dispatcher-reencrypt 전체 파이프라인 → 각 블록이
        // 블록별 MBA 키로 개별 RC4 암호화되어 있고, 디스패처가 쓰는 키로
        // 복호화하면 정확히 평문(block.instructions)이 복원되는지 + 길이 테이블
        // 엔트리 동치성을 검증한다.
        let dummy = crate::pe::generate_dummy_target_pe().unwrap();
        let info = crate::pe::TargetPeInfo::parse(&dummy).unwrap();
        let section_alignment = if info.section_alignment == 0 { 0x1000 } else { info.section_alignment };
        let dispatcher_rva: u32 = info
            .relayed_sections
            .iter()
            .map(|s| {
                s.virtual_address
                    + ((s.virtual_size.max(s.bytes.len() as u32) + section_alignment - 1) / section_alignment)
                        * section_alignment
            })
            .max()
            .unwrap_or(0x2000);
        let dispatcher_va = info.image_base + dispatcher_rva as u64;
        let mut ctx = PipelineContext::new(info, dispatcher_va, dispatcher_rva, 3);
        ctx.reencrypt = true; // Phase 0.3 활성 — pass4가 재암호화 디스패처/길이 테이블 배치
        crate::pipeline::pass1_slice::run(&mut ctx).unwrap();
        crate::pipeline::pass2_shuffle::run(&mut ctx).unwrap();
        crate::pipeline::pass3_encode::run(&mut ctx).unwrap();
        crate::pipeline::pass4_section::run(&mut ctx, true, true, false).unwrap();
        let relayed = ctx.target_info.relayed_sections.clone();
        crate::pipeline::patch_data::run(&mut ctx, relayed).unwrap();
        crate::pipeline::crypto::run(&mut ctx, true, true, false, 40, false, false, false, true)
            .unwrap();

        let btg = ctx.btg_section_data.as_ref().unwrap();
        let layout = ctx.layout().unwrap();
        let num_blocks = layout.shuffled_blocks.len();
        assert!(num_blocks > 0);
        for block in &layout.shuffled_blocks {
            let id = block.id;
            let off = layout.table_offsets[id as usize] as usize;
            let len = block.instructions.len();
            let seed = crate::mba::MbaGenerator::seed_for(ctx.mba_constant, id);
            let key = crate::mba::MbaGenerator::compute_key(seed, id, ctx.mba_constant, 2);
            // 길이 테이블 엔트리:
            //   일반 블록: len_enc ^ key == len
            //   call-target 블록(v11+): len_enc == key → 복호화 길이 0 (평문 센티널)
            let len_off = ctx.table_offset + num_blocks * 4 + (id as usize) * 4;
            let len_enc = u32::from_le_bytes(btg.bytes[len_off..len_off + 4].try_into().unwrap());
            let is_ct = ctx.call_target_block_ids.contains(&id);
            if is_ct {
                assert_eq!(
                    len_enc, key,
                    "call-target block {} length sentinel mismatch (len_enc ^ key must be 0)",
                    id
                );
                // call-target 블록은 파일에 평문으로 저장된다
                assert_eq!(
                    &btg.bytes[off..off + len],
                    block.instructions.as_slice(),
                    "call-target block {} must be stored plaintext",
                    id
                );
            } else {
                assert_eq!(len_enc ^ key, len as u32, "length table mismatch for block {}", id);
                // 블록 roundtrip: per-block 키로 복호화 → 평문 복원
                let mut rc4 = Rc4::new(&key.to_le_bytes());
                let mut dec = btg.bytes[off..off + len].to_vec();
                rc4.crypt(&mut dec);
                assert_eq!(
                    dec, block.instructions,
                    "block {} must roundtrip with per-block key",
                    id
                );
            }
        }
    }
}
