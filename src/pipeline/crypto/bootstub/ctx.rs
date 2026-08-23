// ==============================================================================
// BTG - boot-stub shared types/labels - split from bootstub.rs
// ==============================================================================

#[derive(Clone, Copy)]
pub(crate) struct BootStubCtx {
    pub(crate) boot_va: u64, // 부트 스텁 시작 VA
    pub(crate) anti_debug: bool,
    pub(crate) dispatcher_va: u64, // 디스패처 본체 (섹션 + 0x20)
    pub(crate) code_va: u64,
    pub(crate) code_len: u32,
    pub(crate) runs_va: u64,
    pub(crate) num_runs: u32,
    pub(crate) seed_va: u64,
    /// Decrypt-descriptor (M11): 정적 decrypt target/size/bytecode/table 주소를
    /// 부트 스텁 imm으로 박지 않고, 이 메타데이터를 부트 데이터 영역에 파생 키
    /// (RC4 keystream, 키 유도 계층)로 암호화해 저장하고 런타임에 복호화해 쓴다.
    /// desc_va = 암호화된 디스크립터 VA, desc_size = 복호화할 바이트 수.
    pub(crate) desc_va: u64,
    pub(crate) desc_size: u32,
    /// (M12) true = 순수 RC4 비-chained/비-reencrypt/비-vm 경로가 정적 imm 대신
    /// 암호화 디크립트 디스크립터(desc_va)를 런타임 복호화해 decrypt target/size를
    /// 얻는다. 그 외 모드(chained/C1/ChaCha/vm)는 기존 imm 경로를 유지(무회귀).
    pub(crate) desc_used: bool,
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
    /// Commercial program VM state ABI seed. `None` keeps the legacy fixed
    /// offsets used by the classic program VM.
    pub(crate) vm_prog_runtime_layout_seed: Option<u64>,
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
    /// P5: pointer to the .text at-rest decrypt run-table (array of {va:u64, len:u64} pairs),
    /// covering exactly the non-TLS `.text` regions encrypted at rest. The boot stub decrypts
    /// these runs (fresh RC4 seed keystream) in order, then the program-VM bytecode, so the
    /// TLS-callback functions the loader runs pre-boot stay plaintext. (0 / 0 = no-op.)
    pub(crate) vm_oep_text_runs_va: u64,
    pub(crate) vm_oep_text_runs_count: u32,

    // ── v7 chained-crypto ──────────────────────────────────────────────────
    /// true = C1을 256B 청크 단위로 재키잉해 순차 복호화
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
    pub(crate) mac_va: u64,
    /// S2(멀티사이트): 두 번째 저장 CRC2 값의 VA (4바이트, mac 뒤 — crc ^ W32).
    pub(crate) crc2_va: u64,
    /// S3/S4(멀티사이트 확장): crc2 뒤의 세 번째/네 번째 CRC 검증 사이트 저장 값 VA.
    /// 사이트 3는 IAT 리졸브 직후, 사이트 4는 디스패처 진입 직전에 실행 — 부트
    /// 스텁 전체에 걸쳐 검증 지점을 분산해 한 위치의 단일 바이트 패치로 무력화 불가.
    pub(crate) crc3_va: u64,
    pub(crate) crc4_va: u64,
    /// MAC 프리엠블에서 유도한 W32(runtime-derived whiten)를 저장하는 스크래치 슬롯 VA.
    /// 사이트 3/4가 R15가 클로버된 뒤에도 W32를 재사용하도록 보존한다 (4B).
    pub(crate) w32_slot_va: u64,
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
    /// Mutable tail (Program-VM state/call stack/bootstrap data), sealed RW so
    /// no page remains writable+executable after bootstrap.
    pub(crate) mem_state_base: u64,
    pub(crate) mem_state_size: u64,
    /// 스택 프레임 크기 — 외부 API 호출 시 16B 정렬 보장(0x138), 아니면 0x118
    pub(crate) stack_frame: u32,
    // ── v14: import 이름 per-entry MBA 키 (다층 2단계) ─────────────────────
    /// 리졸브 테이블 이름 XOR 키 유도용 마스터 상수 (ctx.mba_constant)
    pub(crate) mba_master: u32,
    /// 리졸브 테이블 이름 XOR 키 유도용 MBA 상수
    pub(crate) mba_c: u32,
    // ── v60/v63: --custom-cipher / --crypto-mode 부트 스텁 경로 ───────────────
    /// 선택된 crypto primitive (RC4 / BTG-C1 / ChaCha20). v63 (T3-1 Phase B):
    /// `c1_mode` 불리언을 `CryptoMode` variant로 승격 — 부트 스텁이 키스트림
    /// 서브루틴(Prga) 대신 상태형 blob(BTG-C1 / ChaCha20)을 선택한다.
    pub(crate) crypto_mode: crate::crypto::CryptoMode,
    /// BTG-C1 crypt blob 엔트리 VA (rcx=buf, rdx=len — 상태는 c1_state_va 유지).
    pub(crate) c1_blob_va: u64,
    /// BTG-C1 상태 버퍼 VA (0x80B: key[32]@+0x00, ctr[8]@+0x20, nonce[4]@+0x28,
    /// ks[64]@+0x30, ks_off[4]@+0x70). 부트 스텁 emit_c1_init이 런타임에 초기화.
    pub(crate) c1_state_va: u64,
    /// ChaCha20 crypt blob 엔트리 VA (rcx=buf, rdx=len — 상태는 chacha_state_va 유지).
    /// (--crypto-mode chacha20 + 평문 경로에서만 활성.)
    pub(crate) chacha_blob_va: u64,
    /// ChaCha20 상태 버퍼 VA (0x80B: key[32]@+0x00, ctr[8]@+0x20, nonce[12]@+0x28,
    /// ks[64]@+0x38, ks_off[4]@+0x78). 부트 스텁 emit_chacha_init이 런타임에 초기화.
    pub(crate) chacha_state_va: u64,
    // ── T3-1 Phase D (--crypto-mode chacha20 + AEAD): Poly1305 pre-decrypt 인증 ──
    /// true = chacha 경로가 at-rest 암호문을 복호화 **전에** Poly1305 AEAD 태그로
    /// 인증한다 (태그 불일치 시 ud2 — fail-safe, decrypt-and-run 금지).
    /// place.rs가 chacha_mode일 때만 켠다 (RC4/C1 경로 무영향).
    pub(crate) chacha_aead: bool,
    /// Poly1305 네이티브 verify blob 엔트리 VA (rel32 call 타깃).
    pub(crate) poly_blob_va: u64,
    /// 32B volatile scratch for the runtime-derived ChaCha20-Poly1305 one-time key.
    pub(crate) poly_key_va: u64,
    /// 16B Poly1305 AEAD 태그 VA (패커가 암호문+AAD로 계산해 기록).
    pub(crate) poly_tag_va: u64,
}

/// (M12) 부트 스텁 스택 프레임 내 디크립트 디스크립터 스테이지 레이아웃.
/// RBX(=RSP, S-box base) 기준:
///   [RBX+0x000..0x100] = 주 RC4 S-box (기존)
///   [RBX+DESC_SBOX_OFF..+0x100] = 디스크립터 전용 제2 RC4 S-box
///   [RBX+DESC_STG_OFF..+0x40]  = 복호화된 디스크립터 스태깅 (8 x u64 LE)
pub(crate) const DESC_SBOX_OFF: u32 = 0x100;
pub(crate) const DESC_STG_OFF: u32 = 0x200;
pub(crate) const DESC_STG_CODE_VA: u32 = 0x200;
pub(crate) const DESC_STG_CODE_LEN: u32 = 0x208;
pub(crate) const DESC_STG_RUNS_VA: u32 = 0x210;
pub(crate) const DESC_STG_NUM_RUNS: u32 = 0x218;
pub(crate) const DESC_STG_BC_VA: u32 = 0x220;
pub(crate) const DESC_STG_BC_LEN: u32 = 0x228;
pub(crate) const DESC_STG_TEXT_RUNS_VA: u32 = 0x230;
pub(crate) const DESC_STG_TEXT_RUNS_COUNT: u32 = 0x238;

impl BootStubCtx {
    /// true = BTG-C1 상태형 키스트림 blob 사용 (v60 --custom-cipher).
    pub(crate) fn c1_mode(&self) -> bool {
        self.crypto_mode == crate::crypto::CryptoMode::C1
    }
    /// true = ChaCha20 (RFC 8439) crypt blob 사용 (v63 --crypto-mode chacha20).
    pub(crate) fn chacha_mode(&self) -> bool {
        self.crypto_mode == crate::crypto::CryptoMode::ChaCha20
    }
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
    // S1 keyed-MAC runtime verification loop
    MacInitLoop,
    MacDataLoop,
    MacDone,
    MacOk,
    // S2 (--integrity multi-site hardening): whiten-key 유도 + 두 번째 CRC 사이트
    WhitenLoop,
    Crc2Loop,
    Crc2Bit,
    Crc2Skip,
    Crc2Done,
    Crc2Ok,
    // S3/S4 (멀티사이트 확장) — IAT 리졸브 직후 / 디스패처 진입 직전의 독립 CRC 검증
    Crc3Loop,
    Crc3Bit,
    Crc3Skip,
    Crc3Done,
    Crc3Ok,
    Crc4Loop,
    Crc4Bit,
    Crc4Skip,
    Crc4Done,
    Crc4Ok,
    DistDescLoop,
    DistMagicOk,
    DistCountOk,
    DistByteLoop,
    DistByteDone,
    DistDescOk,
    DistAllOk,
    // S1 runtime-derived poison interlock (emit_run_decrypt) — tamper 시 런/리졸브 손상
    PoisonLoop,
    PoisonDone,
    // TrashFormer 부트 정크의 real-looking mixing loop (길이=0 dead path 제거)
    JunkMixLoop,
    // ── v6 IAT resolve ──
    DllLoop,
    FuncLoop,
    FuncOrdinal,
    FuncCall,
    DllNext,
    ResolveDone,
    // ── v6 mem-harden ──
    MemDone,
    MemFail,
    MemOpenDone,
    MemOpenFail,
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
    // ── v60: BTG-C1 상태 초기화 (키/카운터/nonce/ks_off 기록) ──
    C1KeyLoop,
    // ── M12: 디크립트 디스크립터 스테이지 (제2 S-box KSA + PRGA) ──
    DescInit,
    DescKsa,
    DescPrga,
    DescDone,
    // ── v63: ChaCha20 상태 초기화 (키[32]/ctr/nonce[12]/ks_off 기록) ──
    ChaKeyLoop,
    // ── T3-1 Phase D: Poly1305 AEAD 인증 통과 (ud2 우회) ──
    PolyOk,
}

/// 단일 Instruction을 어셈블해 정확한 인코딩 길이를 측정한다.
/// 상대 분기는 rel32 형태이므로 타깃 값과 무관하게 길이가 고정된다.

pub(crate) fn base_bind_byte(base: u64) -> u8 {
    // Load addresses are intentionally excluded from cryptographic identity:
    // ASLR changes them before the boot stub runs. Region AAD/build identity
    // provides stable domain separation instead.
    let _ = base;
    0
}
