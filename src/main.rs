
// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Security Framework & QA Pipeline
// ==============================================================================

use btg_packer::cli::CliArgs;
use btg_packer::error;
use btg_packer::pe::{self, TargetPeInfo, generate_dummy_target_pe};
use btg_packer::pipeline::{self, PipelineContext};
use btg_packer::qa::{self, QaBenchmarkRunner};
use btg_packer::vm;
use btg_packer::debug;
use clap::Parser;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::env;
use std::fs;

/// Bug-7 fix: env_logger leaks its Pipe writer (log::set_boxed_logger does a
/// Box::leak), so the log file is never flushed/closed by Drop. Hold a cloned
/// handle and flush+sync it when `main` returns, covering every exit path.
struct LogFlushGuard(std::fs::File);
impl Drop for LogFlushGuard {
    fn drop(&mut self) {
        use std::io::Write;
        let _ = self.0.flush();
        let _ = self.0.sync_all();
    }
}

fn main() -> error::Result<()> {
    let args = CliArgs::parse();

    // ── v9: --full — 최대 보호 스택을 단일 플래그로 켠다 ─────────────────────────
    // 개별 플래그가 함께 주어지면 그 플래그가 우선(OR), --full은 부족한 나머지를
    // 채운다. 상충 조합은 기존 규칙(재암호화 우선, chained/vm 무효화)으로 해소.
    let full = args.full;
    // FIX(v14 --vm-oep + --full): --vm-oep(전체 프로그램 VM 가상화)와 --full이
    // 함의하는 --dispatcher-reencrypt(블록 단위 네이티브 디스패치 재암호화)는 서로
    // 배타적인 디스패치 모델이다. vm-oep는 부트 스텁 bulk-복호화 경로를 써서 원본
    // 프로그램을 프로그램 VM으로 lift하므로, 둘을 함께 주면(--full --vm-oep) vm-oep가
    // 우선해서 reencrypt는 끈다. 이로써 두 플래그가 동시에 동작한다.
    let vm_oep_requested = args.vm_oep;
    let anti_debug = args.anti_debug || full;
    let dispatcher_reencrypt = (args.dispatcher_reencrypt || full) && !vm_oep_requested;
    if (args.dispatcher_reencrypt || full) && vm_oep_requested {
        eprintln!("[!] --vm-oep takes precedence over --dispatcher-reencrypt (implied by --full): per-block re-encryption skipped so the whole program can be virtualized into the program VM");
    }
    let integrity = args.integrity || full;
    let payload_relocate = args.payload_relocate || full;
    let rsrc_register = args.rsrc_register || full;
    // FIX(v14 --vm-oep + --full): --iat-hide(--full이 켬)는 네이티브 디스패치용 IAT
    // 은닉/재구성이므로, 원본 프로그램 전체를 VM으로 lift해 데이터·import 포인터를
    // 평문으로 직접 읽는 --vm-oep와 양립하지 않는다. 게다가 TLS callback이 있는 PE
    // (Rust/CRT 대상)에선 iat-hide가 하드-에러로 실패한다. --vm-oep가 우선한다.
    let iat_hide = (args.iat_hide || full) && !vm_oep_requested;
    if (args.iat_hide || full) && vm_oep_requested {
        eprintln!("[!] --vm-oep takes precedence over --iat-hide (implied by --full): IAT hiding skipped (incompatible with full-program VM virtualization / TLS-callback targets)");
    }
    // FIX(v12.2): --dispatcher-reencrypt(런타임 블록 단위 복호화)는 .textb 블록
    // 영역에 대한 쓰기 권한이 계속 필요하다. --mem-harden(RX 전환)과 동시 적용하면
    // 디스패처의 첫 in-place 복호화가 RX 페이지에 쓰다 0xC0000005 크래시
    // (fault @ dispatcher block_crypt PRGA `xor [rcx],al`). 재암호화가 우선이며
    // mem-harden의 RX 전환은 생략한다.
    // FIX(v14 --vm-oep + --full): --mem-harden(.textb → RX 전환)은 프로그램 VM
    // 런타임과도 양립하지 않는다 (lift된 프로그램 실행 중 .textb 쓰기 → 0xC0000005).
    // --vm-oep가 우선해 mem-harden도 끈다.
    let mem_harden = (args.mem_harden || full) && !dispatcher_reencrypt && !vm_oep_requested;
    if (args.mem_harden || full) && dispatcher_reencrypt {
        eprintln!("[!] --dispatcher-reencrypt takes precedence over --mem-harden: runtime per-block decryption needs writable .textb (RX transition skipped)");
    } else if (args.mem_harden || full) && vm_oep_requested {
        eprintln!("[!] --vm-oep takes precedence over --mem-harden (implied by --full): .textb RX switch skipped (incompatible with the program VM's runtime)");
    }
    let obf_level = if full { 3u32 } else { args.obf_level };

    // ── 로그 초기화 ───────────────────────────────────────────────────────────────
    let log_level = if args.debug {
        log::LevelFilter::Trace
    } else {
        log::LevelFilter::Debug
    };
    let mut builder = env_logger::Builder::from_default_env();
    builder.filter_level(log_level);
    let mut _log_flush: Option<LogFlushGuard> = None;
    if let Some(ref log_path) = args.log_file {
        if let Ok(file) = std::fs::File::create(log_path) {
            // Bug-7 fix: keep a cloned handle in an RAII guard that flushes+syncs on
            // drop, so the log file's buffered tail survives every exit path even
            // though env_logger leaks the logger's own Pipe handle.
            _log_flush = file.try_clone().ok().map(LogFlushGuard);
            builder.target(env_logger::Target::Pipe(Box::new(file)));
        }
    }
    let _ = builder.try_init();

    // ── VM SELF-TEST 모드 ─────────────────────────────────────────────────────────
    if args.vm_test {
        // flush stdout so the buffered PASS/FAIL lines survive process exit, and
        // surface the outcome on stderr (unbuffered) for remote/non-tty runs.
        use std::io::Write;
        let r = vm::run_self_test();
        // Flush so all buffered PASS/FAIL lines are visible even when stdout is a
        // redirected file/pipe (Rust line-buffers stdout only on a TTY).
        let _ = std::io::stdout().flush();
        r?;
        return Ok(());
    }

    // ── M8: VM 성능 벤치마크 모드 (인터프리터 vs 네이티브 VM 처리량) ─────────────
    if args.vm_bench {
        vm::run_vm_bench()?;
        return Ok(());
    }

    // ── M6: 원본 .text → VM lift 커버리지 진단 모드 ──────────────────────────────
    if args.text_vm {
        let input_path = args.input;
        if !input_path.exists() {
            println!("[!] Input file not found. Generating default test payload: {}", input_path.display());
            let dummy_bytes = generate_dummy_target_pe()?;
            std::fs::write(&input_path, &dummy_bytes)?;
        }
        let input_pe_bytes = std::fs::read(&input_path)?;
        let info = pe::TargetPeInfo::parse(&input_pe_bytes)?;
        let base_va = info.image_base + info.text_rva as u64;
        let ep_va = info.image_base + info.entry_point_rva as u64;
        let report = vm::text_lift::analyze_text_lift(
            &info.text_bytes,
            base_va,
            ep_va,
            &info.relayed_sections,
            info.image_base,
        )?;
        println!("==================================================================");
        println!(" [M6] 원본 .text → VM lift 커버리지 리포트 ({} bytes .text)", info.text_bytes.len());
        println!("==================================================================");
        println!("  기본 블록:            {}", report.total_blocks);
        println!("  총 명령:              {}", report.total_instructions);
        println!("  lift 가능 명령:       {} ({:.2}%)", report.liftable_instructions, report.coverage() * 100.0);
        println!("  lift 불가 명령:       {}", report.unsupported_instructions);
        println!("  완전 lift 가능 블록:  {}", report.fully_liftable_blocks);
        println!("  lift 바이트코드 총량: {} bytes", report.bytecode_total);
        if !report.unsupported.is_empty() {
            println!("\n  [A-5] lift 불가 명령 목록 (패킹 실패 지점):");
            use std::collections::BTreeMap;
            let mut by_code: BTreeMap<String, usize> = BTreeMap::new();
            for (s, c) in &report.unsupported {
                *by_code.entry(format!("{:?} ({})", c, s)).or_insert(0) += 1;
            }
            for (k, v) in by_code {
                println!("    - {}  (x{})", k, v);
            }
        }
        println!("==================================================================");
        return Ok(());
    }

    // ── M6 Phase-2: OEP→VM entry 전환 데이터 경로 진단 (전체 도달 CFG → 단일 VM) ──
    if args.text_vm_oep {
        let input_path = args.input;
        if !input_path.exists() {
            println!("[!] Input file not found. Generating default test payload: {}", input_path.display());
            let dummy_bytes = generate_dummy_target_pe()?;
            std::fs::write(&input_path, &dummy_bytes)?;
        }
        let input_pe_bytes = std::fs::read(&input_path)?;
        let info = pe::TargetPeInfo::parse(&input_pe_bytes)?;
        let base_va = info.image_base + info.text_rva as u64;
        let ep_va = info.image_base + info.entry_point_rva as u64;
        let lift = vm::text_lift::lift_program_cfg(
            &info.text_bytes,
            base_va,
            ep_va,
            &info.relayed_sections,
            info.image_base,
            &input_pe_bytes,
        )?;
        println!("==================================================================");
        println!(" [M6 Phase-2] OEP→VM entry 전환 진단 (도달 CFG → 단일 VM 프로그램)");
        println!("  EP(원본 entry) VA:   0x{:X}", ep_va);
        println!("  entry block VA:      0x{:X}", lift.entry_va);
        println!("  CFG 블록 수:         {}", lift.blocks);
        println!("  총 명령:             {}", lift.total_instructions);
        println!("  lift 불가 명령:      {} ({:.2}%)", lift.unsupported.len(), lift.coverage() * 100.0);
        println!("  단일 VM 프로그램:    {} bytes bytecode", lift.bytecode.len());
        if !lift.bytecode.is_empty() {
            println!("\n  첫 32B bytecode:");
            let mut line = String::from("    ");
            for b in lift.bytecode.iter().take(32) {
                line += &format!("{:02X} ", b);
            }
            println!("{}", line.trim_end());
            let nops = lift.bytecode.iter().filter(|&&b| b == 0x50).count();
            println!("  (디스패처용 NOP opcode 0x50 카운트: {})", nops);
        }
        // ── C-1 (v36): VM 메모리 모델 리포트 ─────────────────────────────────
        {
            let sections: Vec<(String, u32, u32)> = info
                .relayed_sections
                .iter()
                .map(|s| (s.name.clone(), s.virtual_address, s.virtual_size.max(s.bytes.len() as u32)))
                .collect();
            let mem = vm::mem_model::model_from_pe(
                info.image_base,
                info.entry_point_rva,
                info.text_rva,
                info.text_bytes.len() as u32,
                &sections,
            );
            println!("  ── VM 메모리 모델 (C-1) ──");
            for r in &mem.regions {
                println!(
                    "    {:<12} base=0x{:X} size=0x{:X} rwx={:03b}",
                    r.kind.name(),
                    r.base_va,
                    r.size,
                    r.rwx
                );
            }
            let ep_mapped = mem.is_mapped(ep_va);
            println!("  EP(0x{:X}) mapped in model: {}", ep_va, ep_mapped);
        }
        // ── M6 Phase-2 (v38): 프로그램 VM 모듈 (원본 프로그램 → VM 실행 코어) ──
        if !lift.bytecode.is_empty() {
            let vm_size_est = 0x2000 + 0x2000 + lift.bytecode.len() + vm::interp::STATE_SIZE;
            println!("  ── 프로그램 VM 모듈 (M6 Phase-2) ──");
            println!("    bytecode: {} bytes", lift.bytecode.len());
            println!("    state:    {} bytes (STATE_SIZE)", vm::interp::STATE_SIZE);
            println!("    code+table estimate: ~0x4000 bytes");
            println!("    embedded module estimate: {} bytes", vm_size_est);
            println!("    (빌드 스텁이 이 VM 프로그램을 디스패치 — OEP→VM entry 실행 코어)");
        }
        println!("==================================================================");
        return Ok(());
    }

    // ── QA 벤치마크 모드 ──────────────────────────────────────────────────────────
    if args.test_qa {
        run_qa_suite()?;
        return Ok(());
    }

    // v3: 복합 VM 암호화 (기본 ON) — 먼저 정의 (아래 가드에서 사용)
    let crypto_enabled = !args.no_crypto;

    // ── 재점검 보고서 기반 가드 (H3/H4) ───────────────────────────────────────
    if rsrc_register && !payload_relocate {
        return Err(error::BtgError::Anyhow(anyhow::anyhow!(
            "--rsrc-register requires --payload-relocate (there is no relocated payload to register as RT_RCDATA)"
        )));
    }
    if args.chained_crypto && args.crypto_coverage < 100 {
        eprintln!(
            "[!] --chained-crypto + --crypto-coverage < 100 leaves plaintext code in the file (recommend 100)"
        );
    }
    if !crypto_enabled && args.chained_crypto {
        eprintln!("[!] --chained-crypto requires the crypto layer; ignoring (use without --no-crypto)");
    }
    if !crypto_enabled && integrity {
        eprintln!("[!] --integrity requires the crypto layer; ignoring (use without --no-crypto)");
    }

    println!("==================================================================");
    println!(" [BTG PACKER v1.0.0] Bidirectional Trigger Graph Security Framework ");
    println!("==================================================================");
    if full {
        println!("[+] FULL: obf_level=3, anti-debug, dispatcher-reencrypt, integrity, payload-relocate, rsrc-register, iat-hide, mem-harden");
    }

    if anti_debug {
        println!("[+] Anti-Debugging: ENABLED (PEB.BeingDebugged + NtGlobalFlag + Heap.Flags)");
    }

    if crypto_enabled {
        println!(
            "[+] Composite VM Crypto: ENABLED ({} keyed stream — code region + string literals)",
            if !args.rc4 { "BTG-C1" } else { "RC4" }
        );
    } else {
        println!("[!] Composite VM Crypto: DISABLED (--no-crypto)");
    }

    // v8: Phase 0.3 (디스패처 재암호화) 가드 — crypto 필수
    if dispatcher_reencrypt && !crypto_enabled {
        return Err(error::BtgError::Anyhow(anyhow::anyhow!(
            "--dispatcher-reencrypt requires the crypto layer (remove --no-crypto)"
        )));
    }
    if dispatcher_reencrypt && args.chained_crypto {
        eprintln!("[!] --dispatcher-reencrypt takes precedence over --chained-crypto (boot-stub bulk decryption is bypassed)");
    }
    if dispatcher_reencrypt && args.crypto_coverage < 100 {
        eprintln!("[!] --dispatcher-reencrypt overrides --crypto-coverage to 100 (all blocks must be individually encrypted)");
    }

    // v3-composite: VM 가상화 (KSA 키 스케줄 → 바이트코드 + 핸들러)
    let vm_enabled = (args.vm || args.vm_oep) && crypto_enabled;
    if (args.vm || args.vm_oep) && !crypto_enabled {
        println!("[!] --vm / --vm-oep requires the crypto layer; ignoring (use without --no-crypto)");
    }
    if vm_enabled {
        println!("[+] Composite VM: ENABLED (boot-stub RC4 KSA executed via generated VM handlers)");
    }

    // ── 입력 PE 로드 ──────────────────────────────────────────────────────────────
    let input_path = args.input;
    if !input_path.exists() {
        println!("[!] Input file not found. Generating default test payload: {}", input_path.display());
        let dummy_bytes = generate_dummy_target_pe()?;
        fs::write(&input_path, &dummy_bytes)?;
    }

    let input_pe_bytes = fs::read(&input_path)?;
    println!("[+] Target PE Loaded: {} ({} bytes)", input_path.display(), input_pe_bytes.len());

    // ── PE 파싱 ──────────────────────────────────────────────────────────────────
    let target_info = TargetPeInfo::parse(&input_pe_bytes)?;
    println!("[+] Target ImageBase:  0x{:X}", target_info.image_base);
    println!("[+] Target .text RVA:  0x{:X}", target_info.text_rva);
    println!("[+] Target Subsystem:  {}", target_info.subsystem);
    println!("[+] Relayed {} original PE sections.", target_info.relayed_sections.len());

    // ── Dispatcher RVA 동적 계산 (원본 섹션 끝 이후) ──────────────────────────────
    let section_alignment = if target_info.section_alignment == 0 { 0x1000 } else { target_info.section_alignment };
    let dispatcher_rva: u32 = target_info
        .relayed_sections
        .iter()
        .map(|s| {
            s.virtual_address
                + ((s.virtual_size.max(s.bytes.len() as u32) + section_alignment - 1) / section_alignment)
                    * section_alignment
        })
        .max()
        .unwrap_or(0x2000);
    let dispatcher_va = target_info.image_base + dispatcher_rva as u64;

    let obf_complexity = obf_level.clamp(1, 3) as usize;

    // ── PipelineContext 생성 ───────────────────────────────────────────────────────
    let mut ctx = PipelineContext::new(target_info, dispatcher_va, dispatcher_rva, obf_complexity);
    // ── P3-1: 결정적 빌드 (--seed) — 단일 시드 RNG 고정 ──────────────────────────
    // `--seed <u64>`가 주어지면 ctx.rng를 고정한다. 셔플/mba_constant/crypto 시드/
    // 폴리 시드/레이아웃 패드가 모두 이 RNG에서 파생되므로, 같은 input + seed +
    // config → 같은 output (재현·디버깅·상용 배포용).
    if let Some(seed) = args.seed {
        ctx.rng = StdRng::seed_from_u64(seed);
        println!("[+] P3-1 Deterministic build: RNG seeded 0x{:016X} (--seed)", seed);
    }
    // v5: 안티디버그 여부 기록 (validate의 부트 스텁 프롤로그 검사가 사용)
    ctx.anti_debug = anti_debug || args.trace_blocks;
    // v6: MBA 키 스케줄 상수 (패킹당 1회 — 슬라이서/패스3/패스4/디스패처 공유)
    // P3-1: --seed 시 단일 시드 RNG에서 파생 (thread_rng 대신 ctx.rng 배선)
    ctx.mba_constant = ctx.rng.next_u32();
    // ── v61: M7 (on-demand 재암호화) 판정 — per-block reencrypt 계열 디스패처를
    // 쓰므로 --dispatcher-reencrypt와 상호 배타, --vm/--vm-oep(일괄 복호화 부트
    // 흐름)와도 배타. crypto 필수. (ctx.reencrypt가 아래에서 이를 반영)
    let m7_effective = args.m7 && crypto_enabled && !vm_enabled && !dispatcher_reencrypt;
    // v8: Phase 0.3 디스패처 재암호화 (pass2 테이블 배치/디스패처/부트 스텁에 전달)
    // v61: --m7(on-demand 재암호화)도 per-block reencrypt 플러밍(블록별 암호화 +
    // 3-푸시 규약 + 부트 스텁 일괄 복호화 생략)을 재사용하므로 reencrypt로 묶는다.
    // 단, M7은 v14의 "평문 유지" 대신 refcount-safe "실행 후 재암호화" 디스패처를 쓴다.
    ctx.reencrypt = dispatcher_reencrypt || m7_effective;
    // v6: IAT 은닉/메모리 하드닝 — pass4가 부트 영역/특성을 결정하기 전에 설정
    // (crypto off여도 부트 스텁이 필요할 수 있으므로 pass4보다 먼저 알아야 한다)
    ctx.iat_hide = iat_hide;
    ctx.mem_harden = mem_harden;
    // v13.4d experiment (A/B): 원본 .pdata 유지 여부 — build.rs의 .pdata 재구성 gate
    ctx.keep_pdata = args.keep_pdata;
    // v13.4d diag: 디스패처 ring-buffer (마지막 32개 block id) 주입 여부
    ctx.block_ring = args.block_ring;
    // v62: BTG-C1을 기본 암호로 (--rc4로 RC4 복귀). --custom-cipher는 기본값이라
    // 명시적 동의에만 쓰이고, --rc4와 함께 주면 --rc4가 우선한다.
    if args.rc4 && args.custom_cipher {
        eprintln!("[!] --rc4 takes precedence over --custom-cipher (BTG-C1 is the default cipher; --rc4 forces RC4-256)");
    }
    ctx.custom_cipher = !args.rc4;
    // M6 Phase-2: OEP→VM entry 전환 — 부트 스텁이 원본 .text를 평문 복호화하지
    // 않고 lift된 프로그램 VM 모듈로 디스패치. (--vm 필요)
    // v59: patch_data가 .rdata/.data 포인터 재배치를 vm_oep 모드에서 원본 .text
    // 유지로 바꾸므로 **pass1 이전에** 설정해야 한다. (기존엔 crypto 직전 설정)
    ctx.vm_oep = args.vm_oep && vm_enabled;
    // P3 (G1): --vm-commercial — --vm-oep의 백엔드를 상용 엔진으로 전환 (회귀 안전).
    // `--vm --vm-oep --vm-commercial` 모두 켜야 상용 경로를 쓰고, 레거시 --vm-oep
    // 경로는 바이트 동일 유지한다.
    ctx.vm_commercial = args.vm_commercial && args.vm_oep && vm_enabled;
    // ── M7: on-demand 재암호화(anti-dump) — 실행 후 블록을 즉시 재암호화하는
    // refcount-safe 디스패처로, 어느 순간에도 "실행 중인 블록만 평문"이다.
    // (m7_effective는 위에서 crypto/vm/reencrypt 배타성과 함께 판정됨.
    //  ⚠ pass2가 상태 테이블을 예약하므로 **pass1 이전에** 설정해야 한다.)
    if args.m7 && !m7_effective {
        eprintln!(
            "[!] --m7 (on-demand re-encrypt) requires the crypto layer and conflicts with --dispatcher-reencrypt / --vm / --vm-oep (per-block dispatcher vs bulk-decrypt boot flow); ignored"
        );
    }
    ctx.m7 = m7_effective;

    // ── Phase 6: SDK Marker Selective VM Pass (if markers present) ───────────────
    if vm_enabled {
        // T1-1: 폴리모픽 VM 시드 — --seed 주어지면 단일 시드 RNG에서 파생(결정적),
        // 아니면 OsRng 엔트로피와 동등한 랜덤 값.
        let poly_seed: u64 = ctx.rng.next_u64();
        ctx.poly_vm_seed = poly_seed;
        ctx.poly_vm_seed_masked =
            poly_seed ^ 0xA7B3C5D1E9F20486u64.wrapping_mul(ctx.mba_constant as u64);
        let _ = pipeline::selective_vm::SelectiveVmPass::run(&mut ctx, poly_seed);
    }

    // ── Pass 1: CFG 추출 + MicroSlicer ────────────────────────────────────────────
    pipeline::pass1_slice::run(&mut ctx)?;

    // ── Pass 2: Layout Shuffling ──────────────────────────────────────────────────
    pipeline::pass2_shuffle::run(&mut ctx)?;

    // ── Pass 3: RIP Fixup + BlockEncoder ─────────────────────────────────────────
    pipeline::pass3_encode::run(&mut ctx)?;

    // ── Pass 4: .btg 섹션 조립 (anti_debug + crypto + iat/mem 플래그 전달) ────────
    let anti_debug_enabled = anti_debug || args.trace_blocks;
    // v9: crypto가 꺼져 있어도 IAT/메모리 하드닝/페이로드 재배치가 있으면
    // 부트 스텁 영역을 예약해야 한다.
    let needs_boot_stub = crypto_enabled || iat_hide || mem_harden || payload_relocate;
    pipeline::pass4_section::run(&mut ctx, anti_debug_enabled, needs_boot_stub, args.trace_blocks)?;

    // ── Patch: 섹션 재배치 + CFG 픽스업 ──────────────────────────────────────────
    let relayed_sections = ctx.target_info.relayed_sections.clone();
    pipeline::patch_data::run(&mut ctx, relayed_sections)?;

    // ── v6: IAT 은닉 + 메모리 하드닝 준비 (원본 import 추출/제거) — crypto 앞에서 실행 ──
    if iat_hide || mem_harden {
        ctx.original_imports = pipeline::iat_hide::collect_from_pe(&input_pe_bytes)?;
        pipeline::iat_hide::run(&mut ctx)?;
    }

    // ── M6 Phase-2: OEP→VM entry 전환 — 부트 스텁이 원본 .text를 평문 복호화하지
    // 않고 lift된 프로그램 VM 모듈로 디스패치. (--vm 필요, 기본 false → 기존 경로 유지)
    // (v59: vm_oep는 pass1 이전에 이미 설정됨 — 위의 초기화 참조)

    // ── M8: VM handler 테이블 MBA 난독화 (--vm 필요, 기본 false → 기존 경로 유지)
    ctx.m8 = args.m8 && vm_enabled;

    // ── v3 Crypto: 코드 영역 + 문자열 암호화, 부트 스텁 설치 (--vm 시 KSA 가상화) ──
    // v9: crypto가 꺼져 있어도 --iat-hide/--mem-harden/--payload-relocate가 있으면
    // 부트 스텁(RC4 없는 경량 버전)을 설치해야 한다.
    // ── v42 (M9): VM 바이트코드 매퍼 — 패킹 시 lift 되는 명령을 기록 ─────────
    // crypto::run 안에서 KSA/PRGA/프로그램 VM 바이트코드가 lift 되므로, 매퍼를
    // 그 앞에서 켠 뒤 빌드 후 <output>.map 으로 덤프한다.
    if args.map || args.sym_map {
        vm::mapper::begin("pack");
        println!("[+] M9 VM Bytecode Mapper: ENABLED (will write <output>.map{})",
            if args.sym_map { " + .sym" } else { "" });
    }

    // v61: --dispatcher-reencrypt OR --m7 (둘 다 per-block) — ctx.reencrypt를
    // 빌림으로 읽기 전에 값만 캡처한다 (crypto::run이 &mut ctx를 받으므로).
    let reencrypt_effective = ctx.reencrypt;
    pipeline::crypto::run(
        &mut ctx,
        crypto_enabled,
        anti_debug_enabled,
        vm_enabled,
        args.crypto_coverage,
        payload_relocate,
        integrity,
        args.chained_crypto,
        reencrypt_effective,
    )?;


    // ── v4: RT_RCDATA 정식 리소스 등록 (--payload-relocate 필요) ─────────────
    if rsrc_register {
        pipeline::rsrc_register::run(&mut ctx)?;
    }

    // ── T1-3: 폴리모픽 VM 스텁 임베드 + 마커 트램펄린 패치 ──────────────────
    // SelectiveVmPass가 ctx.poly_vm_regions에 보존한 바이트코드/시드는 여기서
    // 출력 PE의 .textb tail에 .btgvm 모듈로 실제로 심어지고, SDK 마커 리전
    // 시작을 VM 진입 스텁으로 redirect하는 트램펄린이 .text에 패치된다.
    // (마커가 없으면 no-op — 출력은 기존과 동일.)
    if vm_enabled {
        let _ = pipeline::poly_embed::embed_poly_vm_into_pipeline(&mut ctx)?;
    }

    // ── Build: PE 합성 + 파일 기록 ───────────────────────────────────────────────
    let output_path = args.output;
    let output_pe_bytes = pipeline::build::run(&ctx, Some(&output_path))?;

    // ── v4: 섹션별 엔트로피 리포트 (탐지 도구의 엔트로피 지표 확인용) ─────────────
    btg_packer::analysis::entropy::print_entropy_report(&output_pe_bytes);

    // ── v5: 자체검증 — 출력 PE를 다시 파싱해 구조적 불변식 검증 ──────────────────
    pipeline::validate::run(&ctx, &output_pe_bytes)?;

    // ── v42 (M9) / v50 (M10): VM 매퍼 덤프 ─────────────────────────────
    // `--map` 명령 단위(bytecode offset→원본 VA)를 <output>.map으로,
    // `--sym-map` 블록 단위 심볼릭 맵(+ .pdata 함수 귀속)을 <output>.sym으로 기록.
    // mapper는 1회만 take 한다 (두 파일 모두 같은 기록 사용).
    if args.map || args.sym_map {
        if let Some(m) = vm::mapper::take() {
            if args.map {
                let mut map_path = output_path.clone();
                map_path.set_extension(
                    format!("{}.map", output_path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_else(|| String::from("out"))),
                );
                let n = vm::mapper::write_map_to(&m, &map_path)
                    .map_err(|e| error::BtgError::Anyhow(anyhow::anyhow!(
                        "M9: failed to write VM map {}: {}", map_path.display(), e)))?;
                println!("[+] M9 VM map written: {} ({} entries)", map_path.display(), n);
            }
            if args.sym_map {
                let mut sym_path = output_path.clone();
                sym_path.set_extension(
                    format!("{}.sym", output_path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_else(|| String::from("out"))),
                );
                // .pdata 함수 테이블 (relayed_sections 에서)
                let mut funcs: Vec<(u64, u64)> = Vec::new();
                if let Some(pd) = ctx.target_info.relayed_sections.iter().find(|s| s.name == ".pdata") {
                    for chunk in pd.bytes.chunks_exact(12) {
                        if chunk.len() < 12 { break; }
                        let s0 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        let e0 = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                        if s0 > 0 && e0 > s0 {
                            funcs.push((ctx.target_info.image_base + s0 as u64,
                                        ctx.target_info.image_base + e0 as u64));
                        }
                    }
                    funcs.sort();
                }
                let n = vm::mapper::write_sym_to(&m, &sym_path, &funcs, ctx.target_info.image_base)
                    .map_err(|e| error::BtgError::Anyhow(anyhow::anyhow!(
                        "M10: failed to write VM symbol map {}: {}", sym_path.display(), e)))?;
                println!("[+] M10 VM symbol map written: {} ({} blocks)", sym_path.display(), n);
            }
            // P3 (G1): 상용 RISC lift의 micro-op 단위 매핑 CSV
            // (원본 VA → RISC micro-op 인덱스 → 폴리 바이트코드 오프셋).
            if !m.risc_entries.is_empty() {
                let mut csv_path = output_path.clone();
                csv_path.set_extension(
                    format!("{}.riscmap.csv", output_path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_else(|| String::from("out"))),
                );
                let n = vm::mapper::write_risc_csv_to(&m, &csv_path)
                    .map_err(|e| error::BtgError::Anyhow(anyhow::anyhow!(
                        "P3: failed to write commercial RISC map CSV {}: {}", csv_path.display(), e)))?;
                println!("[+] P3 commercial RISC map CSV written: {} ({} micro-ops)", csv_path.display(), n);
            }
        } else {
            println!("[!] M9/M10: mapper enabled but no bytecode was lifted (nothing to map)");
        }
    }

    // ── 디버그 출력 ───────────────────────────────────────────────────────────────
    debug::export_debug_layout_log(
        &output_path,
        ctx.target_info.image_base,
        dispatcher_rva,
        dispatcher_rva,
        ctx.layout()?,
    )?;

    debug::verify_overlapped_disassembly(
        &output_pe_bytes,
        dispatcher_rva as u64,
        ctx.target_info.image_base,
        ctx.layout()?,
    )?;

    Ok(())
}

fn run_qa_suite() -> error::Result<()> {
    println!("==================================================================");
    println!(" [QA BENCHMARK SUITE] Running Multi-Compiler PE Compatibility Suite ");
    println!("==================================================================");

    let current_exe = env::current_exe()?;
    let targets = QaBenchmarkRunner::discover_targets();
    println!("[+] Discovered {} PE benchmark targets.", targets.len());

    println!("\n---------------------------------------------------------------------------------------------");
    println!(" Target Name              | Compiler Environment | Orig Size | Packed Size | Sections | Exec ");
    println!("---------------------------------------------------------------------------------------------");

    for target in &targets {
        if let Ok(res) = QaBenchmarkRunner::run_benchmark_test(target, &current_exe) {
            // stdout 으로 출력 (env_logger 가 120자에서 로그를 잘라 PASS/FAIL 이
            // 사라지는 문제 방지).
            println!(
                " {:<24} | {:<20} | {:<9} | {:<11} | {:<8} | {}",
                res.target_name,
                res.compiler,
                res.original_size,
                res.packed_size,
                res.relayed_sections_count,
                if res.execution_success { "PASS [OK]" } else { "FAIL" }
            );
            if !res.execution_success {
                println!("      → {}", res.exec_detail);
            }
        }
    }
    println!("---------------------------------------------------------------------------------------------\n");
    println!("[SUCCESS] QA Benchmark Testing Suite Completed.");
    Ok(())
}
