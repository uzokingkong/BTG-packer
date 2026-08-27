// ==============================================================================
// BTG - Protection Profile: RequestedConfig → ResolvedConfig policy resolution
// ==============================================================================
// 보고서 P1: "feature resolver 리팩터링" — CLI 플래그의 정책 결정 로직을
// main.rs 의 인라인 if/else 에서 분리한다.
//
//   RequestedConfig (원시 CLI 플래그 스냅샷)
//        ↓  `resolve()` (순수 함수 — 규칙 우선순위·--full 확장·상충 해소)
//   ResolvedConfig (파이프라인이 실제로 쓰는 최종 불리언/파생 값)
//        ↓
//   main.rs / PipelineContext
//
// 기존 main.rs 의 규칙을 **의미 보존**하며 옮겼다:
//  * `--full`은 부족한 플래그를 채운다 (개별 플래그 우선, OR).
//  * `--vm-oep`는 네이티브 block dispatcher re-encryption만 무력화한다.
//    IAT hiding과 post-bootstrap RX sealing은 Program-VM과 함께 적용된다.
//  * `--dispatcher-reencrypt`는 `--mem-harden`을 무력화 (재암호화는 .textb 쓰기 필요).
//  * `--m7`(on-demand 재암호화)는 crypto + 비-VM일 때만 유효.
//  * crypto off면 `--vm`/`--vm-oep`/`--m7`/`--chained-crypto`/`--integrity` 비활성.
//  * 제거된 `--rc4` 요청은 다른 암호로 폴백하지 않고 하드 에러.
//
// 모든 경고는 `Vec<String>`으로 모아 main.rs 가 출력한다 (stdout 순서 보존).
// 하드 에러(`--rsrc-register`→`--payload-relocate` 필요, `--dispatcher-reencrypt`
// →crypto 필요)는 `validate()` 로 분리해 호출부에서 Err 로 반환할 수 있다.
// ==============================================================================

use crate::cli::{CliArgs, CryptoModeCli};
use crate::crypto::CryptoMode;
use crate::dispatcher::antidebug::AntiDebugPolicy;

/// 패킹 정책에 영향을 주는 원시 CLI 플래그 스냅샷. `resolve()`의 입력.
#[derive(Debug, Clone)]
pub struct RequestedConfig {
    pub full: bool,
    pub obf_level: u32,
    pub anti_debug: bool,
    /// readccc §4.5: anti-debug 탐지 실패 정책 (Trap/Hang/Warn).
    pub anti_debug_policy: AntiDebugPolicy,
    pub no_crypto: bool,
    pub vm: bool,
    pub vm_oep: bool,
    pub vm_commercial: bool,
    pub m7: bool,
    pub m8: bool,
    pub payload_relocate: bool,
    pub rsrc_register: bool,
    pub crypto_coverage: u32,
    pub chained_crypto: bool,
    pub integrity: bool,
    pub iat_hide: bool,
    pub mem_harden: bool,
    pub dispatcher_reencrypt: bool,
    pub custom_cipher: bool,
    pub rc4: bool,
    /// v63 (T3-1 Phase B): --crypto-mode 명시 선택 (없으면 레거시 플래그로 파생).
    pub crypto_mode: Option<CryptoModeCli>,
}

impl RequestedConfig {
    pub fn from_cli(args: &CliArgs) -> Self {
        Self {
            full: args.full,
            obf_level: args.obf_level,
            anti_debug: args.anti_debug,
            anti_debug_policy: args.anti_debug_policy,
            no_crypto: args.no_crypto,
            vm: args.vm,
            vm_oep: args.vm_oep,
            vm_commercial: args.vm_commercial,
            m7: args.m7,
            m8: args.m8,
            payload_relocate: args.payload_relocate,
            rsrc_register: args.rsrc_register,
            crypto_coverage: args.crypto_coverage,
            chained_crypto: args.chained_crypto,
            integrity: args.integrity,
            iat_hide: args.iat_hide,
            mem_harden: args.mem_harden,
            dispatcher_reencrypt: args.dispatcher_reencrypt,
            custom_cipher: args.custom_cipher,
            rc4: args.rc4,
            crypto_mode: args.crypto_mode,
        }
    }
}

/// 파이프라인이 실제로 소비하는 해석된 정책 (모든 상충이 해소된 최종 값).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfig {
    pub full: bool,
    /// --full 이면 3, 아니면 요청 값 (clamp 는 호출부가 유지).
    pub obf_level: u32,
    pub anti_debug: bool,
    /// readccc §4.5: anti-debug 탐지 실패 정책 (Trap/Hang/Warn).
    pub anti_debug_policy: AntiDebugPolicy,
    pub dispatcher_reencrypt: bool,
    pub integrity: bool,
    pub payload_relocate: bool,
    pub rsrc_register: bool,
    pub iat_hide: bool,
    pub mem_harden: bool,
    /// `!--no-crypto` — 복합 VM 암호 레이어.
    pub crypto_enabled: bool,
    /// `(--vm || --vm-oep) && crypto` — 폴리모픽 VM 이 활성.
    pub vm_enabled: bool,
    /// `--m7 && crypto && !vm` — on-demand 재암호화 디스패처.
    pub m7: bool,
    /// `dispatcher_reencrypt || m7` — ctx.reencrypt (per-block 재암호화 계열).
    pub reencrypt: bool,
    /// `--vm-oep && vm_enabled` — ctx.vm_oep (OEP→프로그램 VM 진입).
    pub vm_oep: bool,
    /// `--vm-commercial && --vm-oep && vm_enabled` — 상용 RISC 엔진 백엔드.
    pub vm_commercial: bool,
    /// 현대 암호 경로 사용 여부. RC4 요청은 해석 전에 거부된다.
    pub custom_cipher: bool,
    /// 선택된 crypto primitive (C1/ChaCha20).
    pub crypto_mode: CryptoMode,
    /// `--m8 && vm_enabled` — VM 핸들러 테이블 MBA 난독화.
    pub m8: bool,
    /// 부트 스텁 영역이 필요한지 (crypto/iat/mem/payload 중 하나라도 켜짐).
    pub needs_boot_stub: bool,
}

/// 하드 에러 — `resolve()` 이후 호출부가 Err 로 승격해 반환한다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// `--rsrc-register` 는 `--payload-relocate` 를 요구한다.
    RsrcRegisterRequiresPayloadRelocate,
    /// `--dispatcher-reencrypt` 는 crypto 레이어를 요구한다.
    DispatcherReencryptRequiresCrypto,
    /// RC4는 제거됐으며 다른 primitive로 묵시 변환하지 않는다.
    Rc4Retired,
    /// C1 is compiled/selectable only in explicit research builds.
    ExperimentalC1Disabled,
}

impl ResolveError {
    pub fn message(&self) -> &'static str {
        match self {
            ResolveError::RsrcRegisterRequiresPayloadRelocate => {
                "--rsrc-register requires --payload-relocate (there is no relocated payload to register as RT_RCDATA)"
            }
            ResolveError::DispatcherReencryptRequiresCrypto => {
                "--dispatcher-reencrypt requires the crypto layer (remove --no-crypto)"
            }
            ResolveError::Rc4Retired => {
                "RC4 has been retired; remove --rc4 and select --crypto-mode chacha20"
            }
            ResolveError::ExperimentalC1Disabled => {
                "C1 is experimental; rebuild with --features experimental-custom-crypto to select it"
            }
        }
    }
}

/// `resolve()` 의 결과 — 최종 설정 + 수집된 경고.
#[derive(Debug)]
pub struct ResolveOutcome {
    pub config: ResolvedConfig,
    pub warnings: Vec<String>,
    /// 하드 에러. 비어 있으면 정상, 아니면 호출부가 Err 로 반환.
    pub errors: Vec<ResolveError>,
}

/// 정책 해석 (순수 함수 — 테스트 가능). 기존 main.rs 의 규칙을 의미 보존한다.
pub fn resolve(req: &RequestedConfig) -> ResolveOutcome {
    let mut warnings: Vec<String> = Vec::new();
    let mut errors: Vec<ResolveError> = Vec::new();

    let full = req.full;
    let vm_oep_requested = req.vm_oep;

    let anti_debug = req.anti_debug || full;

    let dispatcher_reencrypt = (req.dispatcher_reencrypt || full) && !vm_oep_requested;
    if (req.dispatcher_reencrypt || full) && vm_oep_requested {
        warnings.push(
            "--vm-oep takes precedence over --dispatcher-reencrypt (implied by --full): per-block re-encryption skipped so the whole program can be virtualized into the program VM".into(),
        );
    }

    let integrity = req.integrity || full;
    let payload_relocate = req.payload_relocate || full;
    let rsrc_register = req.rsrc_register || full;

    // P1-6: the Program-VM bridge and import resolver share the same original
    // IAT slots, so hiding is orthogonal to VM ownership.  Do not silently
    // downgrade this protection when --vm-oep is selected.
    let iat_hide = req.iat_hide || full;

    // --dispatcher-reencrypt 는 .textb 에 쓰기 권한이 계속 필요하므로 mem-harden 의
    // RX 전환과 배타적. Program-VM bytecode is ciphertext/read-only at runtime
    // and mutable VM state is separately owned, so vm-oep itself is not a
    // reason to suppress the post-bootstrap RX seal (P1-5).
    let mem_harden = (req.mem_harden || full) && !dispatcher_reencrypt;
    if (req.mem_harden || full) && dispatcher_reencrypt {
        warnings.push(
            "--dispatcher-reencrypt takes precedence over --mem-harden: runtime per-block decryption needs writable .textb (RX transition skipped)".into(),
        );
    }

    let obf_level = if full { 3u32 } else { req.obf_level };

    let crypto_enabled = !req.no_crypto;
    let vm_enabled = (req.vm || req.vm_oep) && crypto_enabled;
    let vm_oep_effective = req.vm_oep && vm_enabled;
    let vm_commercial = req.vm_commercial && req.vm_oep && vm_enabled;
    let native_m7 = req.m7 && crypto_enabled && !vm_enabled;
    let program_vm_m7 = req.m7 && crypto_enabled && vm_commercial;
    let m7_effective = native_m7 || program_vm_m7;
    // Native M7 reuses the shuffled-block dispatcher. Program-VM M7 has its
    // own bytecode chunk lifecycle and must not disable vm_effective below.
    let reencrypt = dispatcher_reencrypt || native_m7;
    // RC4는 안전한 기본값으로 조용히 바꾸지 않는다. 오래된 --rc4 플래그는
    // 파싱하되 하드 에러로 남겨 CI/배포 스크립트가 명시적으로 마이그레이션하게 한다.
    if req.rc4 {
        errors.push(ResolveError::Rc4Retired);
    }
    // Custom crypto is an explicit experimental selection. Production and all
    // implicit defaults use the standard ChaCha20-Poly1305 path.
    let c1_requested = req.custom_cipher || matches!(req.crypto_mode, Some(CryptoModeCli::C1));
    if c1_requested && !cfg!(feature = "experimental-custom-crypto") {
        errors.push(ResolveError::ExperimentalC1Disabled);
    }
    let custom_cipher = c1_requested && cfg!(feature = "experimental-custom-crypto");
    let crypto_mode = match req.crypto_mode {
        Some(CryptoModeCli::C1) if cfg!(feature = "experimental-custom-crypto") => CryptoMode::C1,
        Some(CryptoModeCli::C1) => CryptoMode::ChaCha20,
        Some(CryptoModeCli::ChaCha20) => CryptoMode::ChaCha20,
        None => CryptoMode::ChaCha20,
    };
    let m8 = req.m8 && vm_enabled;
    let needs_boot_stub = crypto_enabled || iat_hide || mem_harden || payload_relocate;

    // ── 경고/에러 (기존 main.rs 순서 보존) ───────────────────────────────────
    if rsrc_register && !payload_relocate {
        errors.push(ResolveError::RsrcRegisterRequiresPayloadRelocate);
    }
    if req.chained_crypto && req.crypto_coverage < 100 {
        warnings.push(
            "--chained-crypto + --crypto-coverage < 100 leaves plaintext code in the file (recommend 100)".into(),
        );
    }
    if !crypto_enabled && req.chained_crypto {
        warnings.push(
            "--chained-crypto requires the crypto layer; ignoring (use without --no-crypto)".into(),
        );
    }
    if !crypto_enabled && integrity {
        warnings.push(
            "--integrity requires the crypto layer; ignoring (use without --no-crypto)".into(),
        );
    }
    if dispatcher_reencrypt && !crypto_enabled {
        errors.push(ResolveError::DispatcherReencryptRequiresCrypto);
    }
    if dispatcher_reencrypt && req.chained_crypto {
        warnings.push(
            "--dispatcher-reencrypt takes precedence over --chained-crypto (boot-stub bulk decryption is bypassed)".into(),
        );
    }
    if dispatcher_reencrypt && req.crypto_coverage < 100 {
        warnings.push(
            "--dispatcher-reencrypt overrides --crypto-coverage to 100 (all blocks must be individually encrypted)".into(),
        );
    }
    if (req.vm || req.vm_oep) && !crypto_enabled {
        warnings.push(
            "--vm / --vm-oep requires the crypto layer; ignoring (use without --no-crypto)".into(),
        );
    }
    if req.m7 && !m7_effective {
        warnings.push(
            "--m7 requires crypto and either native mode or --vm --vm-oep --vm-commercial; ignored for this profile".into(),
        );
    }
    ResolveOutcome {
        config: ResolvedConfig {
            full,
            obf_level,
            anti_debug,
            anti_debug_policy: req.anti_debug_policy,
            dispatcher_reencrypt,
            integrity,
            payload_relocate,
            rsrc_register,
            iat_hide,
            mem_harden,
            crypto_enabled,
            vm_enabled,
            m7: m7_effective,
            reencrypt,
            vm_oep: vm_oep_effective,
            vm_commercial,
            custom_cipher,
            crypto_mode,
            m8,
            needs_boot_stub,
        },
        warnings,
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> RequestedConfig {
        RequestedConfig {
            full: false,
            obf_level: 2,
            anti_debug: false,
            anti_debug_policy: AntiDebugPolicy::Trap,
            no_crypto: false,
            vm: false,
            vm_oep: false,
            vm_commercial: false,
            m7: false,
            m8: false,
            payload_relocate: false,
            rsrc_register: false,
            crypto_coverage: 100,
            chained_crypto: false,
            integrity: false,
            iat_hide: false,
            mem_harden: false,
            dispatcher_reencrypt: false,
            custom_cipher: false,
            rc4: false,
            crypto_mode: None,
        }
    }

    /// 기본 요청 → crypto/vm off, 부트 스텁 불필요.
    #[test]
    fn resolve_default() {
        let o = resolve(&base());
        let c = o.config;
        assert!(o.errors.is_empty());
        assert!(c.crypto_enabled, "crypto on by default");
        assert!(!c.vm_enabled);
        assert!(!c.vm_oep);
        assert!(!c.reencrypt);
        assert!(
            c.needs_boot_stub,
            "crypto on by default -> boot stub needed"
        );
        assert_eq!(c.obf_level, 2);
        assert!(!c.custom_cipher, "default cipher must not enable experimental C1");
    }

    /// --full → 최대 보호 스택 (+ obf 3, boot stub 필요).
    #[test]
    fn resolve_full() {
        let mut r = base();
        r.full = true;
        let o = resolve(&r);
        let c = o.config;
        assert!(o.errors.is_empty());
        assert!(c.anti_debug);
        assert!(c.dispatcher_reencrypt);
        assert!(c.integrity);
        assert!(c.payload_relocate);
        assert!(c.rsrc_register);
        assert!(c.iat_hide);
        assert!(
            !c.mem_harden,
            "--full implies dispatcher-reencrypt which disables mem-harden"
        );
        assert_eq!(c.obf_level, 3);
        assert!(c.needs_boot_stub);
        assert!(
            o.warnings.iter().any(|w| w.contains("mem-harden")),
            "mem-harden suppressed warning"
        );
    }

    /// --full --vm-oep → native dispatcher만 제외하고 IAT/W^X 보호는 유지.
    #[test]
    fn resolve_full_vm_oep_precedence() {
        let mut r = base();
        r.full = true;
        r.vm_oep = true;
        r.vm = true;
        let o = resolve(&r);
        let c = o.config;
        assert!(o.errors.is_empty());
        assert!(
            !c.dispatcher_reencrypt,
            "vm-oep disables dispatcher-reencrypt"
        );
        assert!(c.iat_hide, "vm-oep composes with iat-hide");
        assert!(c.mem_harden, "vm-oep composes with mem-harden");
        assert!(c.vm_enabled);
        assert!(c.vm_oep);
        assert!(
            o.warnings
                .iter()
                .any(|w| w.contains("vm-oep takes precedence")),
            "dispatcher precedence warning emitted"
        );
    }

    #[test]
    fn resolve_vm_oep_composes_with_iat_and_mem_hardening() {
        let mut r = base();
        r.vm_oep = true;
        r.iat_hide = true;
        r.mem_harden = true;
        let o = resolve(&r);
        assert!(o.errors.is_empty());
        assert!(o.config.vm_oep);
        assert!(o.config.iat_hide);
        assert!(o.config.mem_harden);
        assert!(!o.warnings.iter().any(|w| w.contains("IAT hiding skipped")));
        assert!(!o.warnings.iter().any(|w| w.contains("RX switch skipped")));
    }

    /// --vm-oep 단독 (vm 미지정) → vm_enabled (vm_oep 가 vm 을 함의), vm_oep 유효.
    #[test]
    fn resolve_vm_oep_implies_vm() {
        let mut r = base();
        r.vm_oep = true;
        let o = resolve(&r);
        let c = o.config;
        assert!(o.errors.is_empty());
        assert!(c.vm_enabled, "--vm-oep implies VM");
        assert!(c.vm_oep);
    }

    /// --no-crypto → crypto/vm/m7 비활성 + 관련 경고.
    #[test]
    fn resolve_no_crypto_gates() {
        let mut r = base();
        r.no_crypto = true;
        r.vm = true;
        r.vm_oep = true;
        r.m7 = true;
        r.chained_crypto = true;
        r.integrity = true;
        let o = resolve(&r);
        let c = o.config;
        assert!(!c.crypto_enabled);
        assert!(!c.vm_enabled);
        assert!(!c.vm_oep);
        assert!(!c.m7);
        assert!(o
            .warnings
            .iter()
            .any(|w| w.contains("requires the crypto layer")));
    }

    /// --m7 (crypto, 비-VM) → m7/reencrypt 유효.
    #[test]
    fn resolve_m7() {
        let mut r = base();
        r.m7 = true;
        let o = resolve(&r);
        let c = o.config;
        assert!(o.errors.is_empty());
        assert!(c.m7);
        assert!(c.reencrypt, "m7 shares the per-block reencrypt path");
    }

    /// --m7 + selective --vm (no Program-VM) remains unsupported.
    #[test]
    fn resolve_m7_with_vm() {
        let mut r = base();
        r.m7 = true;
        r.vm = true;
        let o = resolve(&r);
        assert!(!o.config.m7);
        assert!(o
            .warnings
            .iter()
            .any(|w| w.contains("--vm --vm-oep --vm-commercial")));
    }

    #[test]
    fn resolve_m7_with_commercial_program_vm_keeps_vm_path() {
        let mut r = base();
        r.m7 = true;
        r.vm = true;
        r.vm_oep = true;
        r.vm_commercial = true;
        let o = resolve(&r);
        assert!(o.errors.is_empty());
        assert!(o.config.m7);
        assert!(o.config.vm_oep);
        assert!(o.config.vm_commercial);
        assert!(
            !o.config.reencrypt,
            "Program-VM M7 must not select native block reencrypt"
        );
    }

    /// --dispatcher-reencrypt + --mem-harden → mem-harden 무효.
    #[test]
    fn resolve_reencrypt_disables_mem_harden() {
        let mut r = base();
        r.dispatcher_reencrypt = true;
        r.mem_harden = true;
        let o = resolve(&r);
        let c = o.config;
        assert!(o.errors.is_empty());
        assert!(c.dispatcher_reencrypt);
        assert!(!c.mem_harden);
        assert!(o
            .warnings
            .iter()
            .any(|w| w.contains("dispatcher-reencrypt takes precedence over --mem-harden")));
    }

    /// --rsrc-register 단독 → 하드 에러.
    #[test]
    fn resolve_rsrc_register_requires_payload_relocate() {
        let mut r = base();
        r.rsrc_register = true;
        let o = resolve(&r);
        assert!(o
            .errors
            .contains(&ResolveError::RsrcRegisterRequiresPayloadRelocate));
    }

    /// --rsrc-register + --payload-relocate → 에러 없음.
    #[test]
    fn resolve_rsrc_register_ok_with_payload() {
        let mut r = base();
        r.rsrc_register = true;
        r.payload_relocate = true;
        let o = resolve(&r);
        assert!(o.errors.is_empty());
        assert!(o.config.rsrc_register);
        assert!(o.config.payload_relocate);
    }

    /// --dispatcher-reencrypt + --no-crypto → 하드 에러.
    #[test]
    fn resolve_reencrypt_requires_crypto() {
        let mut r = base();
        r.dispatcher_reencrypt = true;
        r.no_crypto = true;
        let o = resolve(&r);
        assert!(o
            .errors
            .contains(&ResolveError::DispatcherReencryptRequiresCrypto));
    }

    /// --rc4 is a hard error and never silently maps to C1.
    #[test]
    fn resolve_rc4() {
        let mut r = base();
        r.rc4 = true;
        let o = resolve(&r);
        assert!(o.errors.contains(&ResolveError::Rc4Retired));
        assert_eq!(o.config.crypto_mode, CryptoMode::ChaCha20);
    }

    /// --m8 는 vm_enabled 일 때만 유효.
    #[test]
    fn resolve_m8_requires_vm() {
        let mut r = base();
        r.m8 = true;
        let o = resolve(&r);
        assert!(!o.config.m8);
        let mut r2 = base();
        r2.vm = true;
        r2.m8 = true;
        let o2 = resolve(&r2);
        assert!(o2.config.m8);
    }

    /// --crypto-mode chacha20 selects ChaCha20.
    #[test]
    fn resolve_crypto_mode_chacha20() {
        let mut r = base();
        r.crypto_mode = Some(CryptoModeCli::ChaCha20);
        let o = resolve(&r);
        assert_eq!(o.config.crypto_mode, CryptoMode::ChaCha20);
        assert!(!o.config.custom_cipher, "ChaCha20 must not enable experimental C1");
    }

    /// 기본 (플래그 없음) → RFC 8439 ChaCha20-Poly1305 경로.
    #[test]
    fn resolve_crypto_mode_default_chacha20() {
        let o = resolve(&base());
        assert_eq!(o.config.crypto_mode, CryptoMode::ChaCha20);
    }

    /// Legacy --rc4 remains rejected even without --crypto-mode.
    #[test]
    fn resolve_crypto_mode_derived_from_rc4() {
        let mut r = base();
        r.rc4 = true;
        let o = resolve(&r);
        assert!(o.errors.contains(&ResolveError::Rc4Retired));
        assert_eq!(o.config.crypto_mode, CryptoMode::ChaCha20);
    }
}
