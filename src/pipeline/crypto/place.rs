// ==============================================================================
// Boot-stub placement: stub building (3 passes), VM module embed, boot-data writes
// ==============================================================================

use super::bootstub::{build_anti_debug_raw_block, build_rc4_block, BootStubCtx};
use super::cipher::Rc4;
use super::integrity::crc32;
use super::scan::StringRun;
use super::{BootStreamCipher, IMPORT_MBA_C};
use crate::pipeline::pass4_section::BOOT_AREA_RESERVE;
use crate::pipeline::PipelineContext;
use crate::vm;
use anyhow::Result;
use rand::RngCore;

mod lift;
mod vm_build;

use lift::lift_program;
use vm_build::{build_prog_vm_mod, build_vm_mod};

/// BTG-C1 상태 버퍼 크기 (key[32] + ctr[8] + nonce[4] + pad + ks[64] + ks_off[4] = 0x80).
const C1_STATE_SIZE: usize = 0x80;

pub(crate) fn place_boot_stub(
    ctx: &mut PipelineContext,
    stream: &mut BootStreamCipher,
    runs: &[StringRun],
    seed_masked: &[u8],
    seed_stored: &[u8],
    crc_source: Option<Vec<u8>>,
    payload_bytes: Vec<u8>,
    no_crypto: bool,
    anti_debug: bool,
    vm_effective: bool,
    vm_oep_effective: bool,
    vm_commercial: bool,
    chained_effective: bool,
    reencrypt: bool,
    integrity_effective: bool,
    payload_relocate: bool,
    image_base: u64,
    dispatcher_va: u64,
    dispatcher_rva: u32,
    boot_off: usize,
    code_start: usize,
    code_len: u32,
    k1: u32,
    k2: u32,
    k3: u32,
    m8_mod: bool,
    crypto_mode: crate::crypto::CryptoMode,
    rng: &mut impl RngCore,
) -> Result<()> {
    let boot_va = dispatcher_va + boot_off as u64;
    let c1_mode = crypto_mode == crate::crypto::CryptoMode::C1;
    let chacha_mode = crypto_mode == crate::crypto::CryptoMode::ChaCha20;

    // M8: VM module builders live in `vm_build` (MBA-variant vs plain routing).
    // P3 (G1): 상용 프로그램 리프트의 ip_map (source-IP -> micro-op index) — the
    // VirtualBranch native handler uses it to resolve branch targets to bytecode
    // byte offsets. Populated in the lift below and passed to build_prog_vm_mod.
    let (vm_prog_bytecode, vm_oep_native_entry, oep_va, vm_prog_ip_map) = lift_program(
        ctx,
        image_base,
        vm_oep_effective,
        vm_commercial,
    )?;

    let btg = ctx.btg_section_data.as_mut()
        .ok_or_else(|| anyhow::anyhow!("btg_section_data not set — run Pass 4 first"))?;

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
    // (리프트 본체는 `lift::lift_program` — 위에서 호출됨)
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
        // M6 Phase-2.3 at-rest: VM bytecode VA/길이 (imm — 최종 패스에서 채움)
        vm_oep_bc_va: 0,
        vm_oep_bc_len: 0,
        vm_oep_text_runs_va: 0,
        vm_oep_text_runs_count: 0,
        // payload_va/crc_va는 imm64라 길이 불변 — 최종 패스(stub3)에서 채운다.
        payload_va: 0,
        payload_len: if payload_relocate { code_len } else { 0 },
        integrity: integrity_effective,
        crc_va: 0,
        mac_va: 0,
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
        // Win64 entry에서 RSP는 16-byte 경계보다 8만큼 어긋나 있다. 8 mod 16인
        // 프레임을 빼야 VM/native helper CALL 직전 RSP가 16-byte 정렬된다.
        stack_frame: if ctx.iat_hide || ctx.mem_harden { 0x138 } else { 0x118 },
        // v60/v63 (--custom-cipher / --crypto-mode): 선택된 crypto primitive
        // (1st pass 자리표시자 — stub2/3에서 확정)
        crypto_mode,
        // c1_blob_va는 rel32 `call` 타깃이라 패스1에서 유효한 in-range 자리표시자
        // (dispatcher_va)를 써야 BlockEncoder가 측정/인코딩에 실패하지 않는다.
        // (0이면 diff가 i32를 벗어나 "Branch distance is too far away" — VM 엔트리와 동일 방침)
        c1_blob_va: if c1_mode { dispatcher_va } else { 0 },
        c1_state_va: 0,
        // v63: ChaCha20 blob도 rel32 call 타깃 — 동일한 자리표시자 방침.
        chacha_blob_va: if chacha_mode { dispatcher_va } else { 0 },
        chacha_state_va: 0,
    };

    // 1st pass: stub 길이 측정 (runs_va/seed_va/vm_* = 0)
    let stub_code_len = build_rc4_block(&stub)?.len();

    // FIX(v3): 안티디버그 블록은 RC4 코드 **앞**에 붙는다. 과거 코드는
    // cursor = boot_off + stub_code_len (RC4 코드 길이만) 로 잡아서, --anti-debug 사용 시
    // 런 테이블/시드가 RC4 코드 꼬리(PRGA 루프 + ret 포함)를 덮어써 부트 스텁이
    // 쓰레기를 실행하고 0xC0000005로 크래시했다. 실제 스텁 전체 길이를 반영한다.
    let ad_bytes = if anti_debug { build_anti_debug_raw_block() } else { Vec::new() };

    // ── v3-composite VM 모듈 (부트 스텁 직후 배치) ────────────────────────────
    // 바이트코드는 VA 독립적이므로 1차 sizing(VA=0)으로 크기를 확정한 뒤,
    // 최종 VA로 재생성한다. 모듈 레이아웃: [code][table][bytecode][state]
    // v61: --custom-cipher + --vm — RC4 KSA 대신 C1 상태 초기화 VM(C1Init 모드).
    let vm_mod: Option<vm::VmModule> = if vm_effective {
        if c1_mode {
            let bc = vm::c1::build_c1_init_bytecode();
            Some(build_vm_mod(m8_mod, 0, 0, 0, bc, vm::handlers::EntryMode::C1Init, rng)?)
        } else {
            let bc = vm::lifter::lift_ksa(&vm::ksa::build_ksa_instructions(0, k1, k2, k3))?;
            Some(build_vm_mod(m8_mod, 0, 0, 0, bc, vm::handlers::EntryMode::Ksa, rng)?)
        }
    } else {
        None
    };
    // v19: PRGA VM (RC4 키스트림 생성/복호화 루프) — vm과 함께 배치.
    // 바이트코드는 VA 독립이므로 1차 sizing(VA=0)으로 크기 확정 후 최종 VA 재생성.
    // v61: --custom-cipher + --vm — 키스트림은 C1 blob이 생성하므로 PRGA VM 생략.
    let vm_prga_mod: Option<vm::VmModule> = if vm_effective && !c1_mode {
        Some(build_vm_mod(m8_mod, 
            0, 0, 0,
            vm::prga::build_prga_bytecode(),
            vm::handlers::EntryMode::Prga,
            rng,
        )?)
    } else {
        None
    };
    // ── M6 Phase-2: 프로그램 VM — 원본 .text를 평문 복호화하지 않고 전체 lift된
    //    프로그램을 VM으로 실행. (OEP→VM entry 전환, --vm-oep)
    let vm_prog_mod: Option<vm::VmModule> = if vm_oep_effective {
        // use the lift computed above (before the 1st-pass stub) so the entry
        // decision and the module bytecode come from the same single lift.
        Some(build_prog_vm_mod(vm_commercial, ctx.poly_vm_seed, 0, 0, 0, vm_prog_bytecode, 0, vm_prog_ip_map.as_ref(), m8_mod, rng)?)
    } else {
        None
    };

    let mut cursor = boot_off + stub_code_len + ad_bytes.len();
    if vm_mod.is_some() {
        cursor = (cursor + 15) & !15; // align 16 (VM 모듈 시작)
    } else {
        cursor = (cursor + 7) & !7; // align 8 (원래 레이아웃 유지)
    }

    // ── v60 (--custom-cipher): BTG-C1 blob + S-box + 상태 영역 배치 ────────────
    // BTG-C1 crypt blob(완전 전개 네이티브 라운드)을 스텁 직후에 두고, 그 뒤에
    // 256B S-box 상수 테이블(패커가 기록)과 0x80B 상태 버퍼(스텁이 초기화)를 붙인다.
    // blob 길이는 imm64/rel32만 써서 VA와 무관(고정) — 1차 sizing에서 확정 가능.
    let mut c1_blob_off = 0usize;
    let mut c1_sbox_off = 0usize;
    let mut c1_state_off = 0usize;
    let c1_blob_len = if c1_mode {
        let len = crate::crypto::native::emit_btg_crypt_blob(0, 0).len();
        c1_blob_off = cursor;
        c1_sbox_off = c1_blob_off + len;
        c1_state_off = c1_sbox_off + 256;
        len
    } else {
        0
    };
    let c1_blob_va = if c1_mode { dispatcher_va + c1_blob_off as u64 } else { 0 };
    let c1_sbox_va = if c1_mode { dispatcher_va + c1_sbox_off as u64 } else { 0 };
    let c1_state_va = if c1_mode { dispatcher_va + c1_state_off as u64 } else { 0 };
    let c1_end = if c1_mode { c1_state_off + C1_STATE_SIZE } else { cursor };
    cursor = c1_end;

    // ── v63 (--crypto-mode chacha20): ChaCha20 crypt blob + 상태 영역 배치 ──────
    // RFC 8439 네이티브 blob(완전 전개 20 라운드)을 스텁 직후에 두고, 그 뒤에
    // 0x80B 상태 버퍼(key/ctr/nonce/ks/ks_off — 스텁 emit_chacha_init이 초기화)를
    // 붙인다. blob 길이는 imm64/rel32만 써서 VA와 무관(고정) — 1차 sizing 확정.
    let mut chacha_blob_off = 0usize;
    let mut chacha_state_off = 0usize;
    let chacha_blob_len = if chacha_mode {
        let len = crate::crypto::chacha20_native::emit_chacha20_blob(0).len();
        chacha_blob_off = cursor;
        chacha_state_off = chacha_blob_off + len;
        len
    } else {
        0
    };
    let chacha_blob_va = if chacha_mode {
        dispatcher_va + chacha_blob_off as u64
    } else {
        0
    };
    let chacha_state_va = if chacha_mode {
        dispatcher_va + chacha_state_off as u64
    } else {
        0
    };
    let chacha_end = if chacha_mode {
        chacha_state_off + crate::crypto::chacha20::CHA_STATE_SIZE
    } else {
        cursor
    };
    cursor = chacha_end;

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
    // reserve the dedicated bytecode return-IP stack (CALL_STACK_SIZE) for the program VM
    cursor += vm_prog_total
        + if vm_prog_mod.is_some() { crate::vm::interp::CALL_STACK_SIZE } else { 0 };
    cursor = (cursor + 7) & !7; // align 8

    // ── P4 (전체 SEH 가상화): Program VM 모듈 위치를 ctx에 기록 — build.rs가
    // .pdata 브리지 UNWIND_INFO로 이 영역을 커버해 OS unwinder가 VM 내부 프레임을
    // (더미 핸들러 대신) 결정적으로 걷게 한다. ---------------------------------
    ctx.vm_prog_rva = if vm_prog_mod.is_some() {
        dispatcher_rva.saturating_add(vm_prog_off as u32)
    } else {
        0
    };
    ctx.vm_prog_total = vm_prog_total as u32;

    // ── M6 Phase-2.3: at-rest 암호화 대상 확정 ──────────────────────────────
    // Program VM bytecode offset/len (boot area — .textb는 이미 RWX라 in-place 복호화 가능)
    let vm_prog_bc_len = if vm_oep_effective {
        vm_prog_mod.as_ref().map(|m| m.bytecode.len() as u32).unwrap_or(0)
    } else {
        0
    };
    let vm_prog_bc_off = if vm_prog_bc_len > 0 {
        let m = vm_prog_mod.as_ref()
            .expect("T3-3: vm_prog_bc_len > 0 implies vm_prog_mod is Some (checked above)");
        vm_prog_off + m.code.len() + m.table.len()
    } else {
        0
    };
    let vm_prog_bc_va = if vm_prog_bc_len > 0 {
        dispatcher_va + vm_prog_bc_off as u64
    } else {
        0
    };
    // 보존 원본 .text at-rest 암호화는 실제 실행되는 TLS 콜백이 없는 타깃에서 활성화.
    // TLS 디렉터리 내 AddressOfCallBacks가 가리키는 콜백 배열이 존재하지 않으면
    // 로더가 사전 실행하는 콜백이 없으므로 .text 전체를 안전하게 100% 암호화한다.
    let has_tls_cb = ctx.target_info.data_directories.get(9).map(|dir| {
        if dir.virtual_address == 0 || dir.size < 0x20 {
            return false;
        }
        ctx.patched_sections.iter().any(|sec| {
            if dir.virtual_address < sec.virtual_address {
                return false;
            }
            let off = (dir.virtual_address - sec.virtual_address) as usize;
            off + 0x20 <= sec.bytes.len()
                && sec.bytes[off + 0x18..off + 0x20].try_into().ok()
                    .map(|b: [u8; 8]| u64::from_le_bytes(b) != 0)
                    .unwrap_or(false)
        })
    }).unwrap_or(false);

    // P5: partial .text at-rest encryption — encrypt every `.text` region EXCEPT
    // the TLS-callback-reachable function ranges (the loader runs those before
    // the boot stub, so they must stay plaintext on disk). The complement of
    // `detect_tls_callback_ranges` within `.text` becomes the encryptable runs,
    // decrypted by the boot stub (fresh RC4(seed)) in the same order before the
    // program-VM bytecode. No TLS callbacks -> a single run over the whole
    // `.text` (identical to the previous whole-region behaviour).
    let mut text_enc_runs: Vec<(u64, u32)> = Vec::new(); // (VA, len)
    if vm_oep_effective {
        let base_va = image_base + ctx.target_info.text_rva as u64;
        let excl = crate::vm::text_lift::detect_tls_callback_ranges(
            &ctx.target_info.text_bytes,
            base_va,
            image_base,
            &ctx.patched_sections,
            &ctx.target_info.data_directories,
        );
        if let Some(sec) = ctx.patched_sections.iter().find(|s| s.name == ".text") {
            let sec_start = image_base + sec.virtual_address as u64;
            let sec_end = sec_start + sec.bytes.len() as u64;
            let mut ranges = excl.func_ranges.clone();
            ranges.sort_by_key(|r| r.0);
            let mut cursor = sec_start;
            for (s, e) in ranges {
                let s = s.max(sec_start);
                let e = e.min(sec_end);
                if s >= e {
                    continue;
                }
                if s > cursor {
                    text_enc_runs.push((cursor, (s - cursor) as u32));
                }
                cursor = cursor.max(e);
            }
            if cursor < sec_end {
                text_enc_runs.push((cursor, (sec_end - cursor) as u32));
            }
        }
    }
    let text_enc = vm_oep_effective && !text_enc_runs.is_empty();
    let text_enc_total: u64 = text_enc_runs.iter().map(|&(_, l)| l as u64).sum();
    if vm_oep_effective {
        println!(
            "[+] --vm-oep at-rest: Program VM bytecode {}",
            if vm_prog_bc_len > 0 {
                format!("encrypted ({}B)", vm_prog_bc_len)
            } else {
                "(no bytecode)".to_string()
            }
        );
        if text_enc && !text_enc_runs.is_empty() {
            println!(
                "[+] --vm-oep at-rest: preserved .text encrypted in {} run(s), {}B total (TLS-callback funcs kept plaintext)",
                text_enc_runs.len(), text_enc_total
            );
        } else if has_tls_cb {
            println!("[!] --vm-oep at-rest: preserved .text fully TLS-reachable; no .text runs encrypted");
        }
    }
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

    // ── P5: .text at-rest decrypt run-table (va,len u64 pairs) ────────────────
    // P5: .text at-rest decrypt run-table is only emitted when there is >=1 at-rest
    // run; otherwise the boot stub sees count==0 and no-ops (no file table written).
    let text_runs_block = if text_enc_runs.is_empty() {
        0
    } else {
        8 + text_enc_runs.len() * 16
    };
    let text_runs_off = (seed_off + 256 + if integrity_effective { 4 + 8 } else { 0 } + 7) & !7;
    let text_runs_va = if text_enc_runs.is_empty() {
        0
    } else {
        dispatcher_va + (text_runs_off + 8) as u64
    };
    let text_runs_count = text_enc_runs.len() as u32;

    // ── v6: 더미 import / 리졸브 테이블 / mem 문자열 배치 (crc 뒤) ───────────
    let iat_start = text_runs_off + text_runs_block;
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
        // v60: BTG-C1 blob/상태 VA (imm64/rel32 — 길이 불변)
        c1_blob_va,
        c1_state_va,
        // v63: ChaCha20 blob/상태 VA (rel32/imm64 — 길이 불변)
        chacha_blob_va,
        chacha_state_va,
        ..stub
    };
    let stub_code = build_rc4_block(&stub2)?;
    if stub_code.len() != stub_code_len {
        anyhow::bail!("boot stub size changed after VA fixup: {} vs {}", stub_code.len(), stub_code_len);
    }

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
        seed_off + 256 + if integrity_effective { 4 + 8 } else { 0 }
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
    //
    // T0-1 FIX ①: Program VM 모듈 전체(vm_prog_off + vm_prog_total + CALL_STACK_SIZE)를
    // boot_end에 포함. 기존 코드는 KSA/PRGA VM만 포함해 truncate()가 Program VM 영역을
    // 잘라버려 vm_prog_bc_off 이후가 모두 0x00이 되는 silent corruption이 발생했다.
    // CALL_STACK_SIZE(0x2000): 부트 스텁 vm_embed.rs가 Program VM state 직후에 예약하는
    // return-IP 스택 영역 — truncate가 이를 포함해야 한다.
    let vm_prog_call_stack = if vm_prog_mod.is_some() {
        crate::vm::interp::CALL_STACK_SIZE
    } else {
        0
    };
    let boot_end = stub_end
        .max(c1_end)
        .max(chacha_end)
        .max(vm_off + vm_total)
        .max(vm_prga_off + vm_prga_total)
        .max(vm_prog_off + vm_prog_total + vm_prog_call_stack)
        .max(runs_off + 8 + total_num_runs * 16)
        .max(text_runs_off + text_runs_block)
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

    // `.textb`의 Rust TLS guard와 fast-fail 바이트도 그대로 둔다. 조건 분기를
    // 삭제하거나 noreturn fast-fail을 `ret`으로 바꾸면 종료 상태가 손상된다.

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
    let mac_va = dispatcher_va + (seed_off + 260) as u64;
    let stub3 = BootStubCtx {
        payload_va,
        crc_va,
        mac_va,
        // M6 Phase-2.3: at-rest 암호화 대상 VA/길이 확정 (imm64/imm32 — 길이 불변)
        vm_oep_bc_va: vm_prog_bc_va,
        vm_oep_bc_len: vm_prog_bc_len,
        vm_oep_text_runs_va: text_runs_va,
        vm_oep_text_runs_count: text_runs_count,
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
    let stub_code_final = build_rc4_block(&stub3)?;
    if stub_code_final.len() != stub_code_len {
        anyhow::bail!(
            "boot stub size changed after payload/crc VA fixup: {} vs {}",
            stub_code_final.len(),
            stub_code_len
        );
    }
    let mut full_stub_final = Vec::with_capacity(ad_bytes.len() + stub_code_final.len());
    full_stub_final.extend_from_slice(&ad_bytes);
    full_stub_final.extend_from_slice(&stub_code_final);
    if full_stub_final.len() != full_stub.len() {
        anyhow::bail!("boot stub final length mismatch: {} vs {}", full_stub_final.len(), full_stub.len());
    }

    // 부트 스텁 복사
    btg.bytes[boot_off..stub_end].copy_from_slice(&full_stub_final);

    // ── v60 (--custom-cipher): BTG-C1 blob + S-box + 상태 영역 기록 ───────────
    if c1_mode {
        // blob은 최종 VA(c1_state_va/c1_sbox_va)로 재생성 — 길이는 1차와 동일.
        let blob = crate::crypto::native::emit_btg_crypt_blob(c1_state_va, c1_sbox_va);
        debug_assert_eq!(blob.len(), c1_blob_len, "BTG-C1 blob length must be VA-independent");
        btg.bytes[c1_blob_off..c1_blob_off + blob.len()].copy_from_slice(&blob);
        // S-box 상수 테이블 (패커가 기록 — 스텁 emit_c1_init은 상태만 초기화)
        let sbox = crate::crypto::nonlinear::sbox();
        btg.bytes[c1_sbox_off..c1_sbox_off + 256].copy_from_slice(&sbox);
        // 상태 버퍼는 0으로 초기화 (스텁이 런타임에 key/ctr/nonce/ks_off 기록)
        btg.bytes[c1_state_off..c1_state_off + C1_STATE_SIZE].fill(0);
        println!(
            "[+] v60 BTG-C1: crypt blob @0x{:X} ({}B), sbox @0x{:X}, state @0x{:X}",
            c1_blob_off, blob.len(), c1_sbox_off, c1_state_off
        );
    }

    // ── v63 (--crypto-mode chacha20): ChaCha20 blob + 상태 영역 기록 ──────────
    if chacha_mode {
        // blob은 최종 VA(chacha_state_va)로 재생성 — 길이는 1차와 동일.
        let blob = crate::crypto::chacha20_native::emit_chacha20_blob(chacha_state_va);
        debug_assert_eq!(blob.len(), chacha_blob_len, "ChaCha20 blob length must be VA-independent");
        btg.bytes[chacha_blob_off..chacha_blob_off + blob.len()].copy_from_slice(&blob);
        // 상태 버퍼는 0으로 초기화 (스텁 emit_chacha_init이 런타임에 key/ctr/nonce/ks_off 기록)
        let st_size = crate::crypto::chacha20::CHA_STATE_SIZE;
        btg.bytes[chacha_state_off..chacha_state_off + st_size].fill(0);
        println!(
            "[+] v63 ChaCha20: crypt blob @0x{:X} ({}B), state @0x{:X}",
            chacha_blob_off, blob.len(), chacha_state_off
        );
    }

    // ── VM 모듈 배치 (최종 VA로 재생성 후 복사) ───────────────────────────────
    if let Some(m) = vm_mod {
        let vm_va = dispatcher_va + vm_off as u64;
        let mode = if c1_mode { vm::handlers::EntryMode::C1Init } else { vm::handlers::EntryMode::Ksa };
        let module = build_vm_mod(m8_mod, 
            vm_va,
            vm_va + m.code.len() as u64,
            vm_va + (m.code.len() + m.table.len()) as u64,
            m.bytecode.clone(),
            mode,
            rng,
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
        let pmod = build_vm_mod(m8_mod, 
            pva,
            pva + m.code.len() as u64,
            pva + (m.code.len() + m.table.len()) as u64,
            m.bytecode.clone(),
            vm::handlers::EntryMode::Prga,
            rng,
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
let prmod = build_prog_vm_mod(vm_commercial, ctx.poly_vm_seed, 
              prva,
              prva + m.code.len() as u64,
              prva + (m.code.len() + m.table.len()) as u64,
              m.bytecode.clone(),
              vm_prog_state_va,
              vm_prog_ip_map.as_ref(),
              m8_mod,
              rng,
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

    // ── M6 Phase-2.3: at-rest 암호화 적용 ───────────────────────────────────
    // fresh RC4(seed_stored) 하나로 .text → bytecode 순 연속 암호화. 부트 스텁의
    // emit_rest_decrypt가 같은 순서로 복호화한다. (.textb는 RWX, .text는 WRITE
    // 비트 추가로 in-place 복호화를 허용한다.)
    if vm_oep_effective && (!text_enc_runs.is_empty() || vm_prog_bc_len > 0) {
        if !text_enc_runs.is_empty() {
            if let Some(sec) = ctx.patched_sections.iter_mut().find(|s| s.name == ".text") {
                sec.characteristics |= 0x8000_0000; // IMAGE_SCN_MEM_WRITE (boot in-place decrypt)
            }
        }
        let mut r = Rc4::new(seed_masked);
        if !text_enc_runs.is_empty() {
            if let Some(sec) = ctx.patched_sections.iter_mut().find(|s| s.name == ".text") {
                let sec_start = image_base + sec.virtual_address as u64;
                for &(va, len) in &text_enc_runs {
                    let off = (va - sec_start) as usize;
                    r.crypt(&mut sec.bytes[off..off + len as usize]);
                }
            }
        }
        if vm_prog_bc_len > 0 {
            // T0-1 FIX ②: at-rest 암호화 슬라이스 전 bound 검사.
            // boot_end FIX ① 이후에도 vm_prog_bc_off 계산 오류(code/table len 잘못
            // 참조)가 있으면 여기서 OOB panic이 발생할 수 있다. truncate 후 섹션
            // 경계를 초과하는 경우를 명시적 Err로 전환해 silent OOB를 방어한다.
            let bc_end = vm_prog_bc_off + vm_prog_bc_len as usize;
            if bc_end > btg.bytes.len() {
                return Err(anyhow::anyhow!(
                    "T0-1: Program VM bytecode at-rest encrypt OOB: \
                     vm_prog_bc_off=0x{:X} len=0x{:X} but section is only 0x{:X}B \
                     (boot_end=0x{:X} new_section_len=0x{:X}). \
                     Likely vm_prog_off/vm_prog_total mismatch.",
                    vm_prog_bc_off, vm_prog_bc_len, btg.bytes.len(),
                    boot_end, new_section_len
                ));
            }
            r.crypt(&mut btg.bytes[vm_prog_bc_off..bc_end]);
        }
        println!(
            "[+] --vm-oep at-rest: fresh-RC4(seed) encryption applied (preserved .text {} run(s)/{}B + Program VM bytecode {}B)",
            text_enc_runs.len(), text_enc_total, vm_prog_bc_len
        );
        // P0-⑦: .text 보존 런(원본 절대 VA 포함)이 at-rest 암호화됨 → 로더 .reloc
        // 적용 시 암호문 파괴 → relocation-aware(ASLR) 비활성화.
        ctx.at_rest_encrypted = true;
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

    // ── P5: .text at-rest decrypt run-table 기록 (부트 스텁 emit_rest_decrypt가 소비) ──
    if !text_enc_runs.is_empty() {
        btg.bytes[text_runs_off..text_runs_off + 4].copy_from_slice(&text_runs_count.to_le_bytes());
        for (i, &(va, len)) in text_enc_runs.iter().enumerate() {
            let e = text_runs_off + 8 + i * 16;
            btg.bytes[e..e + 8].copy_from_slice(&va.to_le_bytes());
            btg.bytes[e + 8..e + 16].copy_from_slice(&(len as u64).to_le_bytes());
        }
    }

    // ── v5 --integrity: 코드 영역 CRC32 저장 (부트 스텁이 비교) ──────────────
    // v9: chained/plain = 평문 CRC, reencrypt = 파일 암호문 CRC. crypto-off는 없음.
    if integrity_effective {
        let crc_val = crc32(crc_source.as_deref().unwrap_or(&[]));
        // T2-3: 키 결합 MAC — CRC32는 키 없는 손상검출용이라 변조 시 4바이트를 함께
        // 바꾸면 우회된다. seed_stored를 키로 코드 영역 keyed-MAC을 계산해 로그로
        // 남긴다 (변조 시 실행 거부용 — 부트 스텁 네이티브 검증은 별도 계층으로 확장).
        let mac_val = crate::crypto::BtgKeyedMac::mac(seed_stored, crc_source.as_deref().unwrap_or(&[]));
        println!("[+] T2-3 Integrity keyed-MAC over code region: {:016X} (keyed)", mac_val);
        btg.bytes[seed_off + 256..seed_off + 260].copy_from_slice(&crc_val.to_le_bytes());
        // S1: keyed-MAC(8B)를 crc 뒤 seed_off+260에 저장 — 부트 스텁이 런타임에
        // 재계산·비교 (불일치 시 ud2). 키 = seed_stored.
        btg.bytes[seed_off + 260..seed_off + 268].copy_from_slice(&mac_val.to_le_bytes());
        println!(
            "[+] S1 Integrity keyed-MAC stored @0x{:X} (8B, keyed=seed_stored; boot stub re-verifies -> ud2 on mismatch)",
            seed_off + 260
        );
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
            // v9: crypto-on에서만 리졸브 테이블을 마지막 run으로 암호화한다.
            //     crypto-off에서는 평문으로 두고 스텁이 직접 읽는다.
            // v60: BTG-C1 경로도 코드/런과 같은 연속 키스트림으로 이어 암호화.
            if table_is_run {
                stream.crypt(&mut btg.bytes[table_off..table_off + iat_table_blob.len()]);
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
    for run in runs {
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
