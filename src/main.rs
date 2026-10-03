// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Security Framework & QA Pipeline
// ==============================================================================

mod qa_runner;

use btg_packer::cli::CliArgs;
use btg_packer::debug;
use btg_packer::error;
use btg_packer::pe::{self, generate_dummy_target_pe, TargetPeInfo};
use btg_packer::pipeline::{self, PipelineContext};
use btg_packer::qa::QaBenchmarkRunner;
use btg_packer::vm;
use clap::Parser;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::env;
use std::fs;
use std::io::Write;

/// Bug-7 fix: env_logger leaks its Pipe writer (log::set_boxed_logger does a
/// Box::leak), so the log file is never flushed/closed by Drop. Hold a cloned
/// handle and flush+sync it when `main` returns, covering every exit path.
struct LogFlushGuard(std::fs::File);
impl Drop for LogFlushGuard {
    fn drop(&mut self) {
        let _ = self.0.flush();
        let _ = self.0.sync_all();
    }
}

#[cfg(windows)]
struct StdoutSilencer {
    original: *mut std::ffi::c_void,
    nul: *mut std::ffi::c_void,
}

#[cfg(windows)]
impl StdoutSilencer {
    fn activate() -> Option<Self> {
        const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const OPEN_EXISTING: u32 = 3;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

        #[link(name = "Kernel32")]
        extern "system" {
            fn GetStdHandle(kind: u32) -> *mut std::ffi::c_void;
            fn SetStdHandle(kind: u32, handle: *mut std::ffi::c_void) -> i32;
            fn CreateFileW(
                name: *const u16,
                desired_access: u32,
                share_mode: u32,
                security_attributes: *mut std::ffi::c_void,
                creation_disposition: u32,
                flags_and_attributes: u32,
                template_file: *mut std::ffi::c_void,
            ) -> *mut std::ffi::c_void;
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }

        let nul_name: Vec<u16> = "NUL\0".encode_utf16().collect();
        let nul = unsafe {
            CreateFileW(
                nul_name.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        let invalid = (-1isize) as *mut std::ffi::c_void;
        if nul.is_null() || nul == invalid {
            return None;
        }

        let original = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        if unsafe { SetStdHandle(STD_OUTPUT_HANDLE, nul) } == 0 {
            unsafe {
                CloseHandle(nul);
            }
            return None;
        }
        Some(Self { original, nul })
    }
}

#[cfg(windows)]
impl Drop for StdoutSilencer {
    fn drop(&mut self) {
        const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
        #[link(name = "Kernel32")]
        extern "system" {
            fn SetStdHandle(kind: u32, handle: *mut std::ffi::c_void) -> i32;
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }
        unsafe {
            let _ = SetStdHandle(STD_OUTPUT_HANDLE, self.original);
            let _ = CloseHandle(self.nul);
        }
    }
}

#[cfg(not(windows))]
struct StdoutSilencer;

#[cfg(not(windows))]
impl StdoutSilencer {
    fn activate() -> Option<Self> {
        None
    }
}

struct PackProgress;

impl PackProgress {
    fn new(enabled: bool, refresh_ms: u64, progress_only: bool) -> Self {
        btg_packer::progress::configure(enabled, refresh_ms, progress_only);
        Self
    }

    fn report(&mut self, percent: u8, stage: &str) {
        btg_packer::progress::checkpoint(u32::from(percent) * 100, stage);
    }
}

impl Drop for PackProgress {
    fn drop(&mut self) {
        btg_packer::progress::finish_console_line();
    }
}
fn main() -> error::Result<()> {
    let args = CliArgs::parse();

    if args.literal_catalog_only {
        let input = fs::read(&args.input)?;
        let catalog = pipeline::literal_discovery::discover(&input)
            .map_err(error::BtgError::Anyhow)?;
        println!("{}", catalog.public_summary());
        return Ok(());
    }

    // Preflight release separation before logs, cache creation, or output writes.
    let release_plan = if let Some(destination) = args.release_dir.as_deref() {
        let mut roots = args.private_root.clone();
        roots.push(args.cache_dir.clone());
        let source = if args.release_export_only { &args.input } else { &args.output };
        let plan = btg_packer::release_export::ReleasePlan::prepare(source, destination, &roots)
            .map_err(error::BtgError::Anyhow)?;
        if let Some(log_path) = args.log_file.as_deref() {
            plan.check_diagnostic_path(log_path).map_err(error::BtgError::Anyhow)?;
        }
        for private_input in args.literal_map.iter().chain(args.private_build_key.iter()) {
            plan.check_diagnostic_path(private_input).map_err(error::BtgError::Anyhow)?;
        }
        Some(plan)
    } else {
        None
    };

    if args.release_export_only {
        release_plan.as_ref().expect("clap requires --release-dir")
            .finish().map_err(error::BtgError::Anyhow)?;
        println!("release export complete: program.exe + manifest.json only; execution not verified");
        return Ok(());
    }

    // Audit before logging/cache/packing: never creates an EXE or sidecar.
    if args.literal_audit_only {
        let result = btg_packer::pipeline::literal_audit::audit_files(
            &args.input,
            args.literal_map
                .as_deref()
                .expect("clap requires --literal-map"),
        )
        .map_err(error::BtgError::Anyhow)?;
        println!("{}", result.public_summary());
        return Ok(());
    }

    if args.verify_seeds > 0 {
        return btg_packer::multi_seed::run(&args).map_err(error::BtgError::Anyhow);
    }
    let mut literal_input = if let Some(path) = args.literal_map.as_deref() {
        let map_path = fs::canonicalize(path)?;
        for destination in std::iter::once(args.output.clone())
            .chain(std::iter::once(btg_packer::build_cache::manifest_path(&args.output)))
            .chain(args.log_file.iter().cloned()) {
            if let Ok(resolved) = fs::canonicalize(destination) {
                let same = if cfg!(windows) {
                    map_path.to_string_lossy().eq_ignore_ascii_case(&resolved.to_string_lossy())
                } else { map_path == resolved };
                if same { return Err(error::BtgError::Anyhow(anyhow::anyhow!(
                    "private literal map must not be used as an output or log destination"
                ))); }
            }
        }
        Some(pipeline::literal_audit::LiteralBuildInput::read(&args.input, path)
            .map_err(error::BtgError::Anyhow)?)
    } else { None };
    if args.section_name_mode == btg_packer::cli::SectionNameMode::Seeded && args.seed.is_none() {
        return Err(error::BtgError::Anyhow(anyhow::anyhow!(
            "--section-name-mode seeded requires an explicit --seed"
        )));
    }

    // ── P1: feature resolver 리팩터링 — RequestedConfig → ResolvedConfig ─────────
    // CLI 플래그의 정책 결정(--full 확장 · vm-oep/reencrypt/mem-harden 상충 해소 ·
    // crypto gate · m7/m8 파생)을 main.rs 인라인에서 `protection_profile::resolve`
    // 로 분리한다. 순수 함수라 단위 테스트로 정책 매트릭스를 검증할 수 있다.
    // 기존 main.rs 규칙을 의미 보존 — 이하 코드는 오직 해석된 값을 소비한다.
    let profile_req = btg_packer::protection_profile::RequestedConfig::from_cli(&args);
    let profile = btg_packer::protection_profile::resolve(&profile_req);
    if !args.progress_only {
        for w in &profile.warnings {
            eprintln!("[!] {w}");
        }
    }
    let cfg = &profile.config;
    if args.boot_vm_policy != btg_packer::cli::BootVmPolicy::Native
        && (!cfg.crypto_enabled || cfg.crypto_mode != btg_packer::crypto::CryptoMode::ChaCha20) {
        return Err(error::BtgError::Anyhow(anyhow::anyhow!(
            "--boot-vm-policy requires enabled ChaCha20 stage authentication"
        )));
    }
    if args.vm_variant_policy == btg_packer::cli::VmVariantPolicy::Seeded
        && (args.seed.is_none() || !cfg.vm_commercial || !cfg.vm_oep || !cfg.crypto_enabled) {
        return Err(error::BtgError::Anyhow(anyhow::anyhow!(
            "--vm-variant-policy seeded requires --seed and an enabled commercial whole-program VM"
        )));
    }
    if args.vm_family_policy == btg_packer::cli::VmFamilyPolicy::Single
        && (!cfg.vm_commercial || !cfg.vm_oep || !cfg.crypto_enabled) {
        return Err(error::BtgError::Anyhow(anyhow::anyhow!(
            "--vm-family-policy single requires an enabled commercial whole-program VM"
        )));
    }
    let _handler_codec_guard = if args.handler_prf {
        if !cfg.vm_commercial || !cfg.vm_oep || !cfg.crypto_enabled {
            return Err(error::BtgError::Anyhow(anyhow::anyhow!(
                "--handler-prf requires an enabled commercial whole-program VM"
            )));
        }
        let settings = match args.private_build_key.as_deref() {
            Some(path) => {
                let key_path = fs::canonicalize(path)?;
                for destination in std::iter::once(args.output.clone())
                    .chain(std::iter::once(btg_packer::build_cache::manifest_path(&args.output)))
                    .chain(args.log_file.iter().cloned()) {
                    if let Ok(resolved) = fs::canonicalize(&destination) {
                        let same = if cfg!(windows) {
                            key_path.as_os_str().to_string_lossy().eq_ignore_ascii_case(&resolved.as_os_str().to_string_lossy())
                        } else { key_path == resolved };
                        if same { return Err(error::BtgError::Anyhow(anyhow::anyhow!(
                            "private build key must not be used as an output or log destination"
                        ))); }
                    }
                }
                btg_packer::vm::handler_table_codec::BuildSettings::read_private_key(path)
                    .map_err(error::BtgError::Anyhow)?
            },
            None => Default::default(),
        };
        Some(btg_packer::vm::handler_table_codec::activate(settings))
    } else { None };
    if literal_input.is_some() && (cfg.reencrypt || args.chained_crypto || !cfg.crypto_enabled) {
        return Err(error::BtgError::Anyhow(anyhow::anyhow!(
            "literal map requires the bulk boot-decryption path"
        )));
    }

    if args.strict_profile && args.allow_partial_vm {
        return Err(error::BtgError::Anyhow(anyhow::anyhow!(
            "--allow-partial-vm cannot be combined with --strict-profile"
        )));
    }

    // 하드 에러 (정책 위반 → 조기 종료) — resolve 가 수집한 내용을 Err 로 승격.
    if let Some(e) = profile.errors.first() {
        return Err(error::BtgError::Anyhow(anyhow::anyhow!("{}", e.message())));
    }
    if args.strict_profile && !profile.warnings.is_empty() {
        return Err(error::BtgError::Anyhow(anyhow::anyhow!(
            "--strict-profile rejected {} protection downgrade(s): {}",
            profile.warnings.len(),
            profile.warnings.join("; ")
        )));
    }

    // ── v9: --full — 최대 보호 스택을 단일 플래그로 켠다 ─────────────────────────
    // (해석은 protection_profile::resolve 로 이동 — 아래는 값 소비만.)
    let full = cfg.full;
    // FIX(v14 --vm-oep + --full): --vm-oep(전체 프로그램 VM 가상화)와 --full이
    // 함의하는 --dispatcher-reencrypt(블록 단위 네이티브 디스패치 재암호화)는 서로
    // 배타적인 디스패치 모델이다. vm-oep는 부트 스텁 bulk-복호화 경로를 써서 원본
    // 프로그램을 프로그램 VM으로 lift하므로, 둘을 함께 주면(--full --vm-oep) vm-oep가
    // 우선해서 reencrypt는 끈다. 이로써 두 플래그가 동시에 동작한다.
    // (상충 해소 자체는 protection_profile::resolve 가 처리 — 아래는 값 소비.)
    let anti_debug = cfg.anti_debug;
    let anti_debug_policy = cfg.anti_debug_policy;
    let dispatcher_reencrypt = cfg.dispatcher_reencrypt;
    let integrity = cfg.integrity;
    let payload_relocate = cfg.payload_relocate;
    let rsrc_register = cfg.rsrc_register;
    // P1-6: VM-OEP native-call sites and native-owned startup thunks share the
    // resolver-populated slots, so IAT hiding remains effective with Program-VM.
    let iat_hide = cfg.iat_hide;
    // FIX(v12.2): --dispatcher-reencrypt(런타임 블록 단위 복호화)는 .textb 블록
    // 영역에 대한 쓰기 권한이 계속 필요하다. --mem-harden(RX 전환)과 동시 적용하면
    // 디스패처의 첫 in-place 복호화가 RX 페이지에 쓰다 0xC0000005 크래시
    // (fault @ dispatcher block_crypt PRGA `xor [rcx],al`). 재암호화가 우선이며
    // mem-harden의 RX 전환은 생략한다.
    // P1-5: Program-VM bytecode remains ciphertext and mutable state has its own
    // ownership; the generated code region can therefore be sealed RX.
    let mem_harden = cfg.mem_harden;
    let obf_level = cfg.obf_level;

    // ── 로그 초기화 ───────────────────────────────────────────────────────────────
    let log_level = if args.debug {
        log::LevelFilter::Trace
    } else {
        log::LevelFilter::Info
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
    } else if args.progress_only {
        // Keep log:: diagnostics from colliding with the single live gauge.
        builder.target(env_logger::Target::Pipe(Box::new(std::io::sink())));
    }
    let _ = builder.try_init();

    // ── VM SELF-TEST 모드 ─────────────────────────────────────────────────────────
    if args.vm_test {
        // flush stdout so the buffered PASS/FAIL lines survive process exit, and
        // surface the outcome on stderr (unbuffered) for remote/non-tty runs.
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
            println!(
                "[!] Input file not found. Generating default test payload: {}",
                input_path.display()
            );
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
        println!(
            " [M6] 원본 .text → VM lift 커버리지 리포트 ({} bytes .text)",
            info.text_bytes.len()
        );
        println!("==================================================================");
        println!("  기본 블록:            {}", report.total_blocks);
        println!("  총 명령:              {}", report.total_instructions);
        println!(
            "  lift 가능 명령:       {} ({:.2}%)",
            report.liftable_instructions,
            report.coverage() * 100.0
        );
        println!(
            "  lift 불가 명령:       {}",
            report.unsupported_instructions
        );
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
            println!(
                "[!] Input file not found. Generating default test payload: {}",
                input_path.display()
            );
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
        println!(
            "  lift 불가 명령:      {} ({:.2}%)",
            lift.unsupported.len(),
            lift.coverage() * 100.0
        );
        println!(
            "  단일 VM 프로그램:    {} bytes bytecode",
            lift.bytecode.len()
        );
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
                .map(|s| {
                    (
                        s.name.clone(),
                        s.virtual_address,
                        s.virtual_size.max(s.bytes.len() as u32),
                    )
                })
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
            println!(
                "    state:    {} bytes (STATE_SIZE)",
                vm::interp::STATE_SIZE
            );
            println!("    code+table estimate: ~0x4000 bytes");
            println!("    embedded module estimate: {} bytes", vm_size_est);
            println!("    (빌드 스텁이 이 VM 프로그램을 디스패치 — OEP→VM entry 실행 코어)");
        }
        println!("==================================================================");
        return Ok(());
    }

    // ── QA 벤치마크 모드 ──────────────────────────────────────────────────────────
    if args.test_qa {
        // P0-1: QA 실행 전 실전 코퍼스 자동 생성 (없는 프로파일만 빌드).
        let built = btg_packer::qa::QaBenchmarkRunner::build_corpus()?;
        if !built.is_empty() {
            println!(
                "[+] P0-1 QA corpus: generated {} variant(s): {}",
                built.len(),
                built.join(", ")
            );
        }
        qa_runner::run_qa_suite(args.qa_commercial)?;
        return Ok(());
    }

    // ── P0-1: 실전 컴파일러 코퍼스 생성 전용 모드 ──────────────────────────────────
    if args.qa_gen_corpus {
        let built = btg_packer::qa::QaBenchmarkRunner::build_corpus()?;
        let status = if built.is_empty() {
            "all up-to-date".to_string()
        } else {
            built.join(", ")
        };
        println!(
            "[+] P0-1 QA corpus: {} variant(s) under ./corpus ({})",
            btg_packer::qa::CORPUS_PROFILES.len(),
            status
        );
        return Ok(());
    }

    // v3: 복합 VM 암호화 (기본 ON) — 먼저 정의 (아래 가드에서 사용)
    let crypto_enabled = cfg.crypto_enabled;

    // --progress-only owns the console: ordinary println! diagnostics are sent
    // to NUL while the progress renderer keeps stderr as the single live line.
    let _stdout_silencer = if args.progress_only {
        StdoutSilencer::activate()
    } else {
        None
    };

    // ── 재점검 보고서 기반 가드 (H3/H4) ───────────────────────────────────────
    if rsrc_register && !payload_relocate {
        return Err(error::BtgError::Anyhow(anyhow::anyhow!(
            "--rsrc-register requires --payload-relocate (there is no relocated payload to register as RT_RCDATA)"
        )));
    }
    if !args.progress_only && args.chained_crypto && args.crypto_coverage < 100 {
        eprintln!(
            "[!] --chained-crypto + --crypto-coverage < 100 leaves plaintext code in the file (recommend 100)"
        );
    }
    if !args.progress_only && !crypto_enabled && args.chained_crypto {
        eprintln!(
            "[!] --chained-crypto requires the crypto layer; ignoring (use without --no-crypto)"
        );
    }
    if !args.progress_only && !crypto_enabled && integrity {
        eprintln!("[!] --integrity requires the crypto layer; ignoring (use without --no-crypto)");
    }

    println!("==================================================================");
    println!(
        " [BTG PACKER v{}] Bidirectional Trigger Graph Security Framework ",
        env!("CARGO_PKG_VERSION")
    );
    println!("==================================================================");
    if full {
        println!("[+] FULL: obf_level=3, anti-debug, dispatcher-reencrypt, integrity, payload-relocate, rsrc-register, iat-hide, mem-harden");
    }

    if anti_debug {
        println!("[+] Anti-Debugging: ENABLED (PEB.BeingDebugged + NtGlobalFlag + Heap.Flags, failure policy={})", anti_debug_policy.as_str());
    }

    if crypto_enabled {
        let mode_str = match cfg.crypto_mode {
            btg_packer::crypto::CryptoMode::Rc4 => "RC4 (RETIRED/INVALID)",
            btg_packer::crypto::CryptoMode::C1 => "BTG-C1",
            btg_packer::crypto::CryptoMode::ChaCha20 => "ChaCha20 (RFC 8439)",
        };
        println!(
            "[+] Composite VM Crypto: ENABLED ({} keyed stream — code region + string literals)",
            mode_str
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
    if !args.progress_only && dispatcher_reencrypt && args.chained_crypto {
        eprintln!("[!] --dispatcher-reencrypt takes precedence over --chained-crypto (boot-stub bulk decryption is bypassed)");
    }
    if !args.progress_only && dispatcher_reencrypt && args.crypto_coverage < 100 {
        eprintln!("[!] --dispatcher-reencrypt overrides --crypto-coverage to 100 (all blocks must be individually encrypted)");
    }

    // v3-composite: VM 가상화 (KSA 키 스케줄 → 바이트코드 + 핸들러)
    let vm_enabled = cfg.vm_enabled;
    if vm_enabled {
        println!(
            "[+] Composite VM: ENABLED ({})",
            if cfg.crypto_mode == btg_packer::crypto::CryptoMode::ChaCha20 {
                "ChaCha20-Poly1305 boot crypto; generated VM executes the protected program"
            } else {
                "experimental C1 initialization via generated VM handlers"
            }
        );
    }

    let mut progress = PackProgress::new(
        !args.no_progress,
        args.progress_refresh_ms,
        args.progress_only,
    );
    progress.report(1, "Starting pack pipeline");

    let cache_args = args.clone();
    let reuse_completed_package = !args.verify_output && !args.debug && !args.trace_blocks
        && !args.map && !args.sym_map && args.log_file.is_none()
        && !std::env::vars_os().any(|(key, _)| key.to_string_lossy().starts_with("BTG_"));

    // ── 입력 PE 로드 ──────────────────────────────────────────────────────────────
    let input_path = args.input;
    if !input_path.exists() && literal_input.is_none() {
        println!(
            "[!] Input file not found. Generating default test payload: {}",
            input_path.display()
        );
        let dummy_bytes = generate_dummy_target_pe()?;
        fs::write(&input_path, &dummy_bytes)?;
    }

    let input_pe_bytes = if let Some(snapshot) = literal_input.as_mut() {
        snapshot.take_input()
    } else { fs::read(&input_path)? };
    println!(
        "[+] Target PE Loaded: {} ({} bytes)",
        input_path.display(),
        input_pe_bytes.len()
    );
    progress.report(4, "Input PE loaded");

    let build_cache = btg_packer::build_cache::BuildCache::open_with_literal_identity(
        &cache_args, &input_pe_bytes, literal_input.as_ref().map(|snapshot| snapshot.map_identity()))?;
    let _cache_session = build_cache.as_ref().map(|cache| cache.activate());
    if reuse_completed_package {
        if let Some(cache) = &build_cache {
            if cache.restore(&args.output)? {
                if let Some(plan) = &release_plan {
                    plan.finish().map_err(error::BtgError::Anyhow)?;
                }
                btg_packer::progress::complete("Pack complete (cached package restored)");
                return Ok(());
            }
        }
    }

    // ── PE 파싱 ──────────────────────────────────────────────────────────────────
    let target_info = TargetPeInfo::parse(&input_pe_bytes)?;
    println!("[+] Target ImageBase:  0x{:X}", target_info.image_base);
    println!("[+] Target .text RVA:  0x{:X}", target_info.text_rva);
    println!("[+] Target Subsystem:  {}", target_info.subsystem);
    println!(
        "[+] Relayed {} original PE sections.",
        target_info.relayed_sections.len()
    );
    progress.report(7, "PE parsed and section map loaded");

    // ── Dispatcher RVA 동적 계산 (원본 섹션 끝 이후) ──────────────────────────────
    let section_alignment = if target_info.section_alignment == 0 {
        0x1000
    } else {
        target_info.section_alignment
    };
    let dispatcher_rva: u32 = target_info
        .relayed_sections
        .iter()
        .map(|s| {
            s.virtual_address
                + ((s.virtual_size.max(s.bytes.len() as u32) + section_alignment - 1)
                    / section_alignment)
                    * section_alignment
        })
        .max()
        .unwrap_or(0x2000);
    let dispatcher_va = target_info.image_base + dispatcher_rva as u64;

    let obf_complexity = obf_level.clamp(1, 3) as usize;

    // ── PipelineContext 생성 ───────────────────────────────────────────────────────
    let mut ctx = PipelineContext::new(target_info, dispatcher_va, dispatcher_rva, obf_complexity);
    if let Some(snapshot) = literal_input {
        ctx.literal_catalog = Some(snapshot.catalog().clone());
        ctx.literal_payload_hashes = snapshot.payload_hashes().clone();
    }
    // ── P3-1: 결정적 빌드 (--seed) — 단일 시드 RNG 고정 ──────────────────────────
    // `--seed <u64>`가 주어지면 ctx.rng를 고정한다. 셔플/mba_constant/crypto 시드/
    // 폴리 시드/레이아웃 패드가 모두 이 RNG에서 파생되므로, 같은 input + seed +
    // config → 같은 output (재현·디버깅·상용 배포용).
    if let Some(seed) = args.seed {
        ctx.rng = StdRng::seed_from_u64(seed);
        println!(
            "[+] P3-1 Deterministic build: RNG seeded 0x{:016X} (--seed)",
            seed
        );
    }
    // v5: 안티디버그 여부 기록 (validate의 부트 스텁 프롤로그 검사가 사용)
    ctx.anti_debug = anti_debug || args.trace_blocks;
    // v6: MBA 키 스케줄 상수 (패킹당 1회 — 슬라이서/패스3/패스4/디스패처 공유)
    // P3-1: --seed 시 단일 시드 RNG에서 파생 (thread_rng 대신 ctx.rng 배선)
    ctx.mba_constant = ctx.rng.next_u32();
    // ── v61: M7 (on-demand 재암호화) 판정 — per-block reencrypt 계열 디스패처를
    // 쓰므로 --dispatcher-reencrypt와 상호 배타, --vm/--vm-oep(일괄 복호화 부트
    // 흐름)와도 배타. crypto 필수. (ctx.reencrypt가 아래에서 이를 반영)
    let m7_effective = cfg.m7;
    // v8: Phase 0.3 디스패처 재암호화 (pass2 테이블 배치/디스패처/부트 스텁에 전달)
    // v61: --m7(on-demand 재암호화)도 per-block reencrypt 플러밍(블록별 암호화 +
    // 3-푸시 규약 + 부트 스텁 일괄 복호화 생략)을 재사용하므로 reencrypt로 묶는다.
    // 단, M7은 v14의 "평문 유지" 대신 refcount-safe "실행 후 재암호화" 디스패처를 쓴다.
    ctx.reencrypt = cfg.reencrypt;
    // v6: IAT 은닉/메모리 하드닝 — pass4가 부트 영역/특성을 결정하기 전에 설정
    // (crypto off여도 부트 스텁이 필요할 수 있으므로 pass4보다 먼저 알아야 한다)
    ctx.iat_hide = cfg.iat_hide;
    ctx.mem_harden = cfg.mem_harden;
    // v13.4d experiment (A/B): 원본 .pdata 유지 여부 — build.rs의 .pdata 재구성 gate
    ctx.keep_pdata = args.keep_pdata;
    // v13.4d diag: 디스패처 ring-buffer (마지막 32개 block id) 주입 여부
    ctx.block_ring = args.block_ring;
    // RC4 requests are rejected by protection_profile::resolve; no implicit fallback.
    ctx.custom_cipher = cfg.custom_cipher;
    // --crypto-mode 선택 (C1/ChaCha20) — 커스텀 암호 경로
    // (재암호화/VM)는 계속 custom_cipher를 쓰고, 평문 bulk at-rest 경로만 crypto_mode.
    ctx.crypto_mode = cfg.crypto_mode;
    // M6 Phase-2: OEP→VM entry 전환 — 부트 스텁이 원본 .text를 평문 복호화하지
    // 않고 lift된 프로그램 VM 모듈로 디스패치. (--vm 필요)
    // v59: patch_data가 .rdata/.data 포인터 재배치를 vm_oep 모드에서 원본 .text
    // 유지로 바꾸므로 **pass1 이전에** 설정해야 한다. (기존엔 crypto 직전 설정)
    ctx.vm_oep = cfg.vm_oep;
    // P3 (G1): --vm-commercial — --vm-oep의 백엔드를 상용 엔진으로 전환 (회귀 안전).
    // `--vm --vm-oep --vm-commercial` 모두 켜야 상용 경로를 쓰고, 레거시 --vm-oep
    // 경로는 바이트 동일 유지한다.
    ctx.vm_commercial = cfg.vm_commercial;
    ctx.vm_variant_policy = args.vm_variant_policy;
    ctx.boot_vm_policy = args.boot_vm_policy;
    ctx.vm_family_policy = args.vm_family_policy;
    // ── M7: on-demand 재암호화(anti-dump) — 실행 후 블록을 즉시 재암호화하는
    // refcount-safe 디스패처로, 어느 순간에도 "실행 중인 블록만 평문"이다.
    // (m7_effective는 위에서 crypto/vm/reencrypt 배타성과 함께 판정됨.
    //  ⚠ pass2가 상태 테이블을 예약하므로 **pass1 이전에** 설정해야 한다.)
    ctx.m7 = m7_effective;
    progress.report(10, "Pipeline context initialized");

    // ── Phase 6: SDK Marker Selective VM Pass (if markers present) ───────────────
    if vm_enabled {
        progress.report(11, "Preparing VM analysis / selective virtualization");
        // T1-1: 폴리모픽 VM 시드 — --seed 주어지면 단일 시드 RNG에서 파생(결정적),
        // 아니면 OsRng 엔트로피와 동등한 랜덤 값.
        let poly_seed: u64 = ctx.rng.next_u64();
        ctx.poly_vm_seed = poly_seed;
        ctx.poly_vm_seed_masked =
            poly_seed ^ 0xA7B3C5D1E9F20486u64.wrapping_mul(ctx.mba_constant as u64);
        if ctx.vm_oep && ctx.vm_commercial {
            let marked = btg_packer::sdk::MarkerScanner::scan_markers(&ctx.target_info.text_bytes);
            if !marked.is_empty() {
                println!(
                    "[+] SDK markers: {} region(s) delegated to commercial Program-VM 100% ownership gate",
                    marked.len()
                );
            }
        } else {
            let _ = pipeline::selective_vm::SelectiveVmPass::run(&mut ctx, poly_seed);
        }
    }
    progress.report(15, "Pre-pass preparation complete");

    // ── Pass 1: CFG 추출 + MicroSlicer ────────────────────────────────────────────
    progress.report(16, "Pass 1/4: CFG extraction + micro-slicing");
    btg_packer::progress::begin_phase(1600, 1400, "Pass 1/4: CFG extraction + micro-slicing");
    pipeline::pass1_slice::run(&mut ctx)?;
    progress.report(30, "Pass 1/4 complete");

    // ── Pass 2: Layout Shuffling ──────────────────────────────────────────────────
    progress.report(31, "Pass 2/4: layout shuffling");
    btg_packer::progress::begin_phase(3100, 900, "Pass 2/4: physical layout shuffling");
    pipeline::pass2_shuffle::run(&mut ctx)?;
    progress.report(40, "Pass 2/4 complete");

    // ── Pass 3: RIP Fixup + BlockEncoder ─────────────────────────────────────────
    progress.report(41, "Pass 3/4: RIP fixups + block encoding");
    btg_packer::progress::begin_phase(4100, 700, "Pass 3/4: RIP fixups + dense block encoding");
    pipeline::pass3_encode::run(&mut ctx)?;
    progress.report(48, "Pass 3/4 complete");

    // ── Pass 4: .btg 섹션 조립 (anti_debug + crypto + iat/mem 플래그 전달) ────────
    let anti_debug_enabled = anti_debug || args.trace_blocks;
    // v9: crypto가 꺼져 있어도 IAT/메모리 하드닝/페이로드 재배치가 있으면
    // 부트 스텁 영역을 예약해야 한다.
    let needs_boot_stub = cfg.needs_boot_stub;
    // readccc §4.5: graceful failure 정책을 부트 스텁/디스패처에 전달.
    progress.report(49, "Pass 4/4: assembling protected sections");
    btg_packer::progress::begin_phase(4900, 600, "Pass 4/4: protected section assembly");
    pipeline::pass4_section::run(
        &mut ctx,
        anti_debug_enabled,
        anti_debug_policy,
        needs_boot_stub,
        args.trace_blocks,
    )?;
    progress.report(55, "Pass 4/4 complete");

    // ── Patch: 섹션 재배치 + CFG 픽스업 ──────────────────────────────────────────
    progress.report(56, "Applying section relocation + CFG fixups");
    let relayed_sections = ctx.target_info.relayed_sections.clone();
    btg_packer::progress::begin_phase(5600, 500, "Relocation + CFG/data fixups");
    pipeline::patch_data::run(&mut ctx, relayed_sections)?;
    progress.report(61, "Relocation + fixups complete");

    // ── v6: IAT 은닉 + 메모리 하드닝 준비 (원본 import 추출/제거) — crypto 앞에서 실행 ──
    if iat_hide || mem_harden {
        progress.report(62, "Preparing IAT hiding / memory-hardening metadata");
        ctx.original_imports = pipeline::iat_hide::collect_from_pe(&input_pe_bytes)?;
        pipeline::iat_hide::run(&mut ctx)?;
    }
    progress.report(65, "Pre-crypto preparation complete");

    // ── M6 Phase-2: OEP→VM entry 전환 — 부트 스텁이 원본 .text를 평문 복호화하지
    // 않고 lift된 프로그램 VM 모듈로 디스패치. (--vm 필요, 기본 false → 기존 경로 유지)
    // (v59: vm_oep는 pass1 이전에 이미 설정됨 — 위의 초기화 참조)

    // ── M8: VM handler 테이블 MBA 난독화 (--vm 필요, 기본 false → 기존 경로 유지)
    ctx.m8 = cfg.m8;

    // ── v3 Crypto: 코드 영역 + 문자열 암호화, 부트 스텁 설치 (--vm 시 KSA 가상화) ──
    // v9: crypto가 꺼져 있어도 --iat-hide/--mem-harden/--payload-relocate가 있으면
    // 부트 스텁(RC4 없는 경량 버전)을 설치해야 한다.
    // ── v42 (M9): VM 바이트코드 매퍼 — 패킹 시 lift 되는 명령을 기록 ─────────
    // crypto::run 안에서 KSA/PRGA/프로그램 VM 바이트코드가 lift 되므로, 매퍼를
    // 그 앞에서 켠 뒤 빌드 후 <output>.map 으로 덤프한다.
    if args.map || args.sym_map {
        vm::mapper::begin("pack");
        println!(
            "[+] M9 VM Bytecode Mapper: ENABLED (will write <output>.map{})",
            if args.sym_map { " + .sym" } else { "" }
        );
    }

    // v61: --dispatcher-reencrypt OR --m7 (둘 다 per-block) — ctx.reencrypt를
    // 빌림으로 읽기 전에 값만 캡처한다 (crypto::run이 &mut ctx를 받으므로).
    let reencrypt_effective = ctx.reencrypt;
    progress.report(66, "Applying crypto / Program-VM protection");
    btg_packer::progress::begin_phase(6600, 1800, "Crypto + Program-VM protection");
    pipeline::crypto::run(
        &mut ctx,
        crypto_enabled,
        anti_debug_enabled,
        anti_debug_policy,
        vm_enabled,
        args.crypto_coverage,
        payload_relocate,
        integrity,
        args.chained_crypto,
        reencrypt_effective,
    )?;
    progress.report(84, "Crypto / Program-VM protection complete");

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
        progress.report(85, "Embedding polymorphic VM runtime");
        btg_packer::progress::begin_phase(8500, 200, "Embedding selective/polymorphic VM runtime");
        let _ = pipeline::poly_embed::embed_poly_vm_into_pipeline(&mut ctx)?;
    }
    progress.report(87, "Runtime/resource embedding complete");

    // ── Build: PE 합성 + 파일 기록 ───────────────────────────────────────────────
    let output_path = args.output;
    // Build in memory first. A strict-profile artifact is not committed to its
    // final path until both structural and effective-capability checks pass.
    progress.report(88, "Building final PE image");
    btg_packer::progress::begin_phase(8800, 300, "Building final PE image");
    let mut output_pe_bytes = pipeline::build::run(&ctx, None)?;
    progress.report(91, "Final PE image built");

    // ── v4: 섹션별 엔트로피 리포트 (탐지 도구의 엔트로피 지표 확인용) ─────────────
    btg_packer::analysis::entropy::print_entropy_report(&output_pe_bytes);

    // ── v5: 자체검증 — 출력 PE를 다시 파싱해 구조적 불변식 검증 ──────────────────
    progress.report(92, "Validating protected PE invariants");
    btg_packer::progress::begin_phase(9200, 300, "Validating protected PE invariants");
    pipeline::validate::run(&ctx, &output_pe_bytes)?;
    let effective_profile =
        pipeline::validate::validate_effective_profile(&ctx, cfg, &output_pe_bytes)?;
    if args.strict_profile {
        effective_profile.ensure_strict()?;
    } else if cfg.vm_commercial && !args.allow_partial_vm {
        effective_profile.ensure_vm_full_coverage()?;
    }
    let naming_pe = goblin::pe::PE::parse(&output_pe_bytes).map_err(anyhow::Error::from)?;
    let existing_section_names = naming_pe
        .sections
        .iter()
        .map(|section| {
            let end = section.name.iter().position(|&byte| byte == 0).unwrap_or(8);
            String::from_utf8_lossy(&section.name[..end]).into_owned()
        })
        .collect::<Vec<_>>();
    if let Some(plan) = pipeline::section_names::SectionNamePlan::create(
        args.section_name_mode,
        args.seed,
        existing_section_names,
    )? {
        let rewritten = plan.rewrite_pe_headers(&mut output_pe_bytes)?;
        println!(
            "[+] Section-name randomization: rewrote {} section header(s) ({:?})",
            rewritten, args.section_name_mode
        );
    }
    progress.report(95, "Validation complete");
    std::fs::write(&output_path, &output_pe_bytes)?;
    progress.report(96, "Protected output written");
    let verification_report = if args.verify_output {
        progress.report(97, "Running execution-equivalence verification");
        match btg_packer::differential::verify_equivalent(
            &input_path,
            &output_path,
            std::time::Duration::from_secs(args.verify_timeout_secs.max(1)),
        ) {
            Ok(report) => {
                println!(
                    "[VERIFY] OK original/protected execution equivalent: exit={}, stdout={}B, stderr={}B",
                    report.original.exit_code,
                    report.original.stdout.len(),
                    report.original.stderr.len()
                );
                Some(report)
            }
            Err(verify_error) => {
                let isolated = btg_packer::differential::isolate_failed_output(&output_path)
                    .map_err(error::BtgError::Anyhow)?;
                return Err(error::BtgError::Anyhow(anyhow::anyhow!(
                    "{}; failed output isolated as {}",
                    verify_error,
                    isolated.display()
                )));
            }
        }
    } else {
        None
    };
    progress.report(98, "Output verification stage complete");
    let emit_private_evidence = args.debug
        || args.map
        || args.sym_map
        || std::env::var_os("BTG_EMIT_PRIVATE_EVIDENCE").is_some();
    if emit_private_evidence {
        let evidence =
            pipeline::reports::EvidenceReportBundle::render(&ctx.unsupported_instructions);
        let evidence_artifacts = evidence.artifacts_for(&output_path);
        pipeline::reports::write_evidence_artifacts(&evidence_artifacts)?;
        println!(
            "[+] private unsupported-instruction evidence written: {}",
            evidence_artifacts[0].path.display()
        );
        // Ownership is an original-RVA mapping artifact and must never be
        // emitted beside a normal production binary by default.
        if let Some(own_csv) = pipeline::validate::ownership_csv(&ctx, &output_pe_bytes)? {
            let mut own_path = output_path.clone();
            own_path.set_extension(format!(
                "{}.ownership.csv",
                output_path
                    .extension()
                    .map(|e| e.to_string_lossy().to_string())
                    .unwrap_or_else(|| "out".into())
            ));
            std::fs::write(&own_path, own_csv)?;
            println!(
                "[+] private function-ownership map written: {}",
                own_path.display()
            );
        }
    } else {
        println!(
            "[+] Private mapping/evidence artifacts suppressed (use --debug, --map, --sym-map, or BTG_EMIT_PRIVATE_EVIDENCE=1 for an isolated analysis build)"
        );
    }

    // ── 상용 3-2: Build Manifest — 패킹 로그 + <output>.manifest ─────────────
    // input/output SHA-256 + 결정적 build_id + vm/crypto 버전 + 적용 feature
    // flags 를 기록한다. build_id 는 (seed, input_hash) 의 순수 함수라 같은
    // input+seed+config 는 같은 build_id 를 낸다 (크래시 재현/지원용).
    {
        let input_hash = btg_packer::manifest::sha256_hex(&input_pe_bytes);
        let output_hash = btg_packer::manifest::sha256_hex(&output_pe_bytes);
        let mut flags = btg_packer::manifest::feature_flags(
            anti_debug,
            vm_enabled,
            ctx.vm_oep,
            ctx.vm_commercial,
            ctx.m7,
            ctx.m8,
            integrity,
            dispatcher_reencrypt,
            payload_relocate,
            rsrc_register,
            iat_hide,
            mem_harden,
            ctx.custom_cipher,
            cfg.crypto_mode == btg_packer::crypto::CryptoMode::ChaCha20,
            args.map,
            args.sym_map,
            args.seed.is_some(),
        );
        if args.handler_prf {
            flags.push("handler-codec-v2-prf-init".into());
            if args.private_build_key.is_some() { flags.push("private-build-key".into()); }
        }
        if ctx.boot_vm_policy != btg_packer::cli::BootVmPolicy::Native {
            flags.push("boot-vm-v2-authenticated-stage-schedule".into());
            flags.push("boot-native-metadata-root-and-os-bridges".into());
            if ctx.boot_vm_policy == btg_packer::cli::BootVmPolicy::SelectedStages {
                flags.push("boot-crypto-vm-v1-chacha-rounds".into());
                flags.push("boot-native-poly1305-and-stream-bridges".into());
            }
            if ctx.boot_vm_policy == btg_packer::cli::BootVmPolicy::FullCrypto {
                flags.push("boot-crypto-vm-v2-chacha20-poly1305-all-instructions".into());
                flags.push("boot-native-crypto-authentication-root".into());
            }
        }
        if ctx.vm_variant_policy == btg_packer::cli::VmVariantPolicy::Seeded {
            flags.push(format!("vm-variant-schema-{}-seeded", btg_packer::vm::poly::variant_plan::VARIANT_SCHEMA_VERSION));
        }
        if ctx.vm_commercial && ctx.vm_oep {
            flags.push("vm-family-lowering-v2-stack-register-mixed-fused".into());
            flags.push("vm-shared-canonical-memory-and-host-bridge-abi".into());
        }
        if ctx.vm_family_policy == btg_packer::cli::VmFamilyPolicy::Single {
            flags.push("vm-family-single-independent-lowering".into());
        }
        if crypto_enabled && cfg.crypto_mode == btg_packer::crypto::CryptoMode::ChaCha20
            && !ctx.reencrypt && !args.chained_crypto {
            flags.push("boot-stage-aead-v64".into());
        }
        // readccc §4.4: W^X 메모리 계약 기술 — 실행 코드의 권한 라이프사이클을
        // capability manifest에 기록한다 (고객이 무엇을 보장하는지 알 수 있게).
        // resolve()가 mem_harden/reencrypt/vm-oep 상충을 이미 해소했으므로
        // cfg 값 그대로 사용한다. mem_harden이 유효하면 부트 스텁이 복호화+
        // 무결성 검증 후 .textb를 RX로 전환(rx-after-verify)한다.
        let mut wx_contract = if cfg.mem_harden {
            "transient-rw-to-rx,rx-after-verify,rw-state".to_string()
        } else {
            "rwx-at-rest".to_string()
        };
        if payload_relocate {
            wx_contract.push_str(",code-data-split");
        }
        if ctx.at_rest_encrypted {
            wx_contract.push_str(",at-rest-ciphertext");
        }
        let manifest =
            btg_packer::manifest::BuildManifest::new(args.seed, flags, input_hash, output_hash)
                // P3-2/readccc §6.1: capability manifest — effective crypto primitive,
                // at-rest encryption, ASLR trade-off, integrity, coverage, anti-debug
                // policy, W^X memory contract.
                .with_capabilities(
                    match cfg.crypto_mode {
                        btg_packer::crypto::CryptoMode::Rc4 => unreachable!(
                            "RC4 must be rejected by protection profile before manifest emission"
                        ),
                        btg_packer::crypto::CryptoMode::C1 => "c1",
                        btg_packer::crypto::CryptoMode::ChaCha20 => "chacha20",
                    },
                    ctx.at_rest_encrypted,
                    effective_profile.aslr_preserved,
                    integrity,
                    args.crypto_coverage,
                    anti_debug_policy.as_str(),
                    &wx_contract,
                )
                .with_execution_verification(args.verify_output, verification_report.as_ref())
                .with_effective_profile(&effective_profile)
                .with_vm_ownership(
                    ctx.vm_coverage.as_ref(),
                    ctx.vm_prog_rva,
                    ctx.vm_prog_native_bridge,
                    &ctx.vm_prog_chunks,
                    ctx.vm_prog_bytecode_rva,
                    ctx.vm_prog_bytecode_len,
                    ctx.vm_prog_runtime_cipher_hash.as_deref(),
                )
                .with_vm_original_metrics(if let Some(coverage) = ctx.vm_coverage.as_ref() {
                    btg_packer::manifest::VmOriginalMetrics {
                        vm_original_functions: Some(coverage.total_functions as u64),
                        vm_original_blocks: Some(coverage.total_blocks as u64),
                        vm_original_instructions: Some(coverage.total_instructions as u64),
                        native_original_functions: Some(
                            coverage
                                .total_functions
                                .saturating_sub(coverage.vm_functions)
                                as u64,
                        ),
                        original_text_exec_bytes: effective_profile.original_text_exec_bytes,
                        original_text_plain_bytes: effective_profile.original_text_plain_bytes,
                        native_island_functions: effective_profile.native_island_functions,
                        native_island_bytes: effective_profile.native_island_bytes,
                        native_island_blockers: effective_profile.native_island_blockers,
                        unresolved_edges: coverage.unresolved_internal_edges,
                    }
                } else {
                    btg_packer::manifest::VmOriginalMetrics::default()
                })
                .with_vm_exposure(
                    btg_packer::analysis::vm_exposure::measure_pe(&output_pe_bytes).ok(),
                );
        println!("[+] Build manifest (P3-2):");
        for line in manifest.render().lines() {
            println!("      {}", line);
        }
        // ⚠ P0-1: 확장자를 `<exe>.manifest`로 쓰면 Windows 로더가 이를 **외부 앱
        // 매니페스트(XML)**로 인식해 활성화에 실패하고 "side-by-side configuration
        // is incorrect" 로 모든 패킹 바이너리 실행이 차단된다 (실제 코퍼스 QA에서
        // 적발). 로더가 자동 활성화하는 `<exe>.manifest` 와 충돌하지 않는
        // `.btgmanifest` 확장자를 사용한다.
        let mut manifest_path = output_path.clone();
        manifest_path.set_extension(
            output_path
                .extension()
                .map(|e| format!("{}.btgmanifest", e.to_string_lossy()))
                .unwrap_or_else(|| "btgmanifest".to_string()),
        );
        manifest.write_manifest(&manifest_path).map_err(|e| {
            error::BtgError::Anyhow(anyhow::anyhow!(
                "P3-2: failed to write build manifest {}: {}",
                manifest_path.display(),
                e
            ))
        })?;
        println!(
            "[+] P3-2 Build manifest written: {}",
            manifest_path.display()
        );
    }

    // ── v42 (M9) / v50 (M10): VM 매퍼 덤프 ─────────────────────────────
    // `--map` 명령 단위(bytecode offset→원본 VA)를 <output>.map으로,
    // `--sym-map` 블록 단위 심볼릭 맵(+ .pdata 함수 귀속)을 <output>.sym으로 기록.
    // mapper는 1회만 take 한다 (두 파일 모두 같은 기록 사용).
    if args.map || args.sym_map {
        if let Some(m) = vm::mapper::take() {
            if args.map {
                let mut map_path = output_path.clone();
                map_path.set_extension(format!(
                    "{}.map",
                    output_path
                        .extension()
                        .map(|e| e.to_string_lossy().to_string())
                        .unwrap_or_else(|| String::from("out"))
                ));
                let n = vm::mapper::write_map_to(&m, &map_path).map_err(|e| {
                    error::BtgError::Anyhow(anyhow::anyhow!(
                        "M9: failed to write VM map {}: {}",
                        map_path.display(),
                        e
                    ))
                })?;
                println!(
                    "[+] M9 VM map written: {} ({} entries)",
                    map_path.display(),
                    n
                );
            }
            if args.sym_map {
                let mut sym_path = output_path.clone();
                sym_path.set_extension(format!(
                    "{}.sym",
                    output_path
                        .extension()
                        .map(|e| e.to_string_lossy().to_string())
                        .unwrap_or_else(|| String::from("out"))
                ));
                // .pdata 함수 테이블 (relayed_sections 에서)
                let mut funcs: Vec<(u64, u64)> = Vec::new();
                if let Some(pd) = ctx
                    .target_info
                    .relayed_sections
                    .iter()
                    .find(|s| s.name == ".pdata")
                {
                    for chunk in pd.bytes.chunks_exact(12) {
                        if chunk.len() < 12 {
                            break;
                        }
                        let s0 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        let e0 = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                        if s0 > 0 && e0 > s0 {
                            funcs.push((
                                ctx.target_info.image_base + s0 as u64,
                                ctx.target_info.image_base + e0 as u64,
                            ));
                        }
                    }
                    funcs.sort();
                }
                let n = vm::mapper::write_sym_to(&m, &sym_path, &funcs, ctx.target_info.image_base)
                    .map_err(|e| {
                        error::BtgError::Anyhow(anyhow::anyhow!(
                            "M10: failed to write VM symbol map {}: {}",
                            sym_path.display(),
                            e
                        ))
                    })?;
                println!(
                    "[+] M10 VM symbol map written: {} ({} blocks)",
                    sym_path.display(),
                    n
                );
            }
            // P3 (G1): 상용 RISC lift의 micro-op 단위 매핑 CSV
            // (원본 VA → RISC micro-op 인덱스 → 폴리 바이트코드 오프셋).
            if !m.risc_entries.is_empty() {
                let mut csv_path = output_path.clone();
                csv_path.set_extension(format!(
                    "{}.riscmap.csv",
                    output_path
                        .extension()
                        .map(|e| e.to_string_lossy().to_string())
                        .unwrap_or_else(|| String::from("out"))
                ));
                let n = vm::mapper::write_risc_csv_to(&m, &csv_path).map_err(|e| {
                    error::BtgError::Anyhow(anyhow::anyhow!(
                        "P3: failed to write commercial RISC map CSV {}: {}",
                        csv_path.display(),
                        e
                    ))
                })?;
                println!(
                    "[+] P3 commercial RISC map CSV written: {} ({} micro-ops)",
                    csv_path.display(),
                    n
                );
            }
        } else {
            println!("[!] M9/M10: mapper enabled but no bytecode was lifted (nothing to map)");
        }
    }

    progress.report(99, "Finalizing optional diagnostics");

    // ── 디버그 출력 ───────────────────────────────────────────────────────────────
    if args.debug || args.trace_blocks {
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
    }

    if reuse_completed_package {
        if let Some(cache) = &build_cache {
            if let Err(error) = cache.save(&output_path, &output_pe_bytes) {
                log::warn!("Could not save completed build package: {error}");
            }
        }
    }
    if let Some(plan) = &release_plan {
        plan.finish().map_err(error::BtgError::Anyhow)?;
    }
    btg_packer::progress::complete("Pack complete");
    Ok(())
}
