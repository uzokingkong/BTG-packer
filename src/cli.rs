// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Security Framework
// ==============================================================================

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "btg-packer",
    author = "BTG Security Research Team",
    version = "1.0.0",
    about = "Bidirectional Trigger Graph (BTG) Security Framework"
)]
pub struct CliArgs {
    /// Input PE target binary path
    #[arg(short, long, default_value = "dummy_target.exe")]
    pub input: PathBuf,

    /// Output protected PE binary path
    #[arg(short, long, default_value = "protected_btg.exe")]
    pub output: PathBuf,

    /// Fail instead of silently downgrading or disabling any requested
    /// protection feature because of an incompatible option combination.
    #[arg(long, default_value_t = false)]
    pub strict_profile: bool,

    /// Permit a commercial Program-VM build whose measured function, block, or
    /// instruction coverage is below 100%. This is a development-only escape
    /// hatch and cannot be combined with --strict-profile.
    #[arg(long, default_value_t = false, conflicts_with = "strict_profile")]
    pub allow_partial_vm: bool,

    /// Execute the original and protected binaries after packing and fail when
    /// exit code, stdout, or stderr differ byte-for-byte.
    #[arg(long, default_value_t = false)]
    pub verify_output: bool,

    /// Per-process timeout used by --verify-output in seconds.
    #[arg(long, default_value_t = 30)]
    pub verify_timeout_secs: u64,

    /// Run N independent seeded pack + execution-verification jobs. Each child
    /// receives --verify-output and writes a distinct seed-suffixed artifact.
    #[arg(long, default_value_t = 0)]
    pub verify_seeds: u32,

    /// Seed for deterministic builds. Sets RNG seeds for all randomization
    /// (block shuffling, MBA constants, crypto/poly seeds, layout padding).
    /// Same input + seed + config produces reproducible, identical output.
    #[arg(long)]
    pub seed: Option<u64>,

    /// Obfuscation intensity level (1: Basic, 2: MBA, 3: Overlapping + MBA)
    #[arg(short = 'l', long, default_value_t = 3)]
    pub obf_level: u32,

    /// Enable Anti-Debugging features
    #[arg(short = 'a', long, default_value_t = false)]
    pub anti_debug: bool,

    /// Anti-debug detection failure policy: `trap` (UD2/crash, default) |
    /// `hang` (infinite stall) | `warn` (fail-open, proceed normally).
    #[arg(long, value_enum, default_value_t = crate::dispatcher::antidebug::AntiDebugPolicy::Trap)]
    pub anti_debug_policy: crate::dispatcher::antidebug::AntiDebugPolicy,

    /// Run Automated Multi-Compiler QA Benchmark Suite
    #[arg(short = 't', long, default_value_t = false)]
    pub test_qa: bool,

    /// Run the QA suite through the commercial Program-VM backend and fail the
    /// command when packed output differs from the original program.
    #[arg(long, default_value_t = false)]
    pub qa_commercial: bool,

    /// Generate real-world compiler test corpus and exit (corpus/*.exe).
    /// Builds test crates across -O0/-O1/-O2/-O3/LTO/CGU16/panic-abort/overflow-checks.
    #[arg(long, default_value_t = false)]
    pub qa_gen_corpus: bool,

    /// Enable verbose Debug logging mode
    #[arg(short = 'd', long, default_value_t = false)]
    pub debug: bool,

    /// Output log file path (optional)
    #[arg(short = 'g', long)]
    pub log_file: Option<PathBuf>,

    /// Inject runtime block execution tracer into packed binary
    #[arg(long, default_value_t = false)]
    pub trace_blocks: bool,

    /// Disable composite VM encryption (boot-stub code/string encryption).
    /// By default (flag absent) the encryption layer is ON.
    #[arg(long, default_value_t = false)]
    pub no_crypto: bool,

    /// Virtualize boot-stub key schedule into generated VM (bytecode + handlers).
    /// Requires the crypto layer.
    #[arg(long, default_value_t = false)]
    pub vm: bool,

    /// Run the VM self-test (lifter / interpreter / native handlers) and exit.
    #[arg(long, default_value_t = false)]
    pub vm_test: bool,

    /// Diagnose original .text -> VM lift coverage without packing.
    /// Decodes basic blocks from input PE and reports unsupported instructions.
    #[arg(long, default_value_t = false)]
    pub text_vm: bool,

    /// Lift reachable CFG from EP into a single VM program and report coverage metrics without packing.
    #[arg(long, default_value_t = false)]
    pub text_vm_oep: bool,

    /// Relocate encrypted code region to a non-executable data section (.vdata).
    /// Lowers .textb entropy to near-zero; boot stub copies and decrypts at load time.
    #[arg(long, default_value_t = false)]
    pub payload_relocate: bool,

    /// Register relocated payload (.vdata) as a formal RT_RCDATA resource
    /// (reconstructs PE resource directory, requires --payload-relocate).
    #[arg(long, default_value_t = false)]
    pub rsrc_register: bool,

    /// Code region encryption coverage percentage (0-100, default 100).
    /// Lower values leave remaining code as CFG-flattened plaintext to lower entropy.
    #[arg(long, default_value_t = 100)]
    pub crypto_coverage: u32,

    /// 256-byte chunk chained encryption with key derivation from previous chunk plaintext
    /// and self-destruction (zeroing seed/S-box/payload after decryption).
    #[arg(long, default_value_t = false)]
    pub chained_crypto: bool,

    /// Enable boot-time and runtime integrity verification (CRC32 / keyed MAC).
    /// Corrupted ciphertext or tampering triggers fail-closed response.
    #[arg(long, default_value_t = false)]
    pub integrity: bool,

    /// Hide import table — strips original import directory and replaces with
    /// minimal resolver; boot stub dynamically reconstructs IAT slots at runtime.
    #[arg(long, default_value_t = false)]
    pub iat_hide: bool,

    /// Memory hardening — enforces W^X permissions: immutable code/tables -> RX,
    /// mutable VM state -> RW after bootstrap. Fails closed on protection failure.
    #[arg(long, default_value_t = false)]
    pub mem_harden: bool,

    /// Dispatcher-coupled runtime block re-encryption (anti-dump).
    /// Each basic block is encrypted with a per-block key; dispatcher decrypts target
    /// block and re-encrypts previous block on every dispatch.
    #[arg(long, default_value_t = false)]
    pub dispatcher_reencrypt: bool,

    /// FULL — Enables maximum protection stack:
    /// `-l 3 -a --dispatcher-reencrypt --integrity --payload-relocate
    ///  --rsrc-register --iat-hide --mem-harden`.
    #[arg(long, default_value_t = false)]
    pub full: bool,

    /// Redirect Original Entry Point (OEP) to the virtualized Program-VM module.
    /// Boot stub dispatches directly to VM entry instead of decrypting .text in place.
    #[arg(long, default_value_t = false)]
    pub vm_oep: bool,

    /// Enable commercial Program-VM backend (RISC lifting -> polymorphic ISA -> threaded native runtime).
    /// Must be combined with `--vm --vm-oep`.
    #[arg(long, default_value_t = false)]
    pub vm_commercial: bool,

    /// M7: On-demand data lifetime and object-granular re-encryption (anti-dump).
    /// Protects literal data objects with decrypt-use-reencrypt lifecycle.
    #[arg(long, default_value_t = false)]
    pub m7: bool,

    /// M8: Conceal VM handler table addresses via MBA polynomial encoding.
    /// Table pointers are obfuscated and resolved at runtime via algebraic identities.
    #[arg(long, default_value_t = false)]
    pub m8: bool,

    /// Run VM benchmark — measures and compares interpreter vs native VM throughput and exits.
    #[arg(long, default_value_t = false)]
    pub vm_bench: bool,

    /// Generate instruction-level VM bytecode mapping file (<output>.map).
    /// Maps bytecode offsets to original VAs and disassemblies for crash triage.
    #[arg(long, default_value_t = false)]
    pub map: bool,

    /// Generate block-level symbolic mapping file (<output>.sym).
    /// Records bytecode offset ranges, original block VAs, and function ownership.
    #[arg(long, default_value_t = false)]
    pub sym_map: bool,

    /// Preserve original .pdata SEH exception table without adding dispatcher leaf entries.
    #[arg(long, default_value_t = false)]
    pub keep_pdata: bool,

    /// Inject a 32-entry dispatched block ID ring-buffer for diagnostic crash dumps.
    #[arg(long, default_value_t = false)]
    pub block_ring: bool,

    /// Explicitly specify BTG-C1 stream cipher path.
    #[arg(long, default_value_t = false)]
    pub custom_cipher: bool,

    /// Retired RC4 compatibility flag. Explicitly rejected if specified.
    #[arg(long, default_value_t = false)]
    pub rc4: bool,

    /// Select crypto primitive — `c1` | `chacha20` (default: `chacha20`).
    /// `chacha20` = RFC 8439 ChaCha20 authenticated bulk encryption.
    /// `c1` = BTG-C1 custom 512-bit stream cipher.
    #[arg(long, value_enum)]
    pub crypto_mode: Option<CryptoModeCli>,
}

/// Crypto mode CLI selection.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoModeCli {
    /// BTG-C1 custom 512-bit stream cipher.
    #[value(name = "c1")]
    C1,
    /// ChaCha20 (RFC 8439) bulk stream cipher.
    #[value(name = "chacha20")]
    ChaCha20,
}

#[cfg(test)]
mod crypto_cli_tests {
    use super::*;

    #[test]
    fn crypto_mode_rc4_is_not_a_parseable_value() {
        let error = CliArgs::try_parse_from(["btg-packer", "--crypto-mode", "rc4"])
            .expect_err("retired RC4 must not remain a selectable crypto mode");
        let rendered = error.to_string();
        assert!(rendered.contains("invalid value 'rc4'"));
        assert!(rendered.contains("possible values: c1, chacha20"));
    }

    #[test]
    fn legacy_rc4_flag_is_preserved_for_explicit_policy_rejection() {
        let args = CliArgs::try_parse_from(["btg-packer", "--rc4"]).unwrap();
        assert!(args.rc4);
    }
}
