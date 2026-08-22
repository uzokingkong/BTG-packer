// ==============================================================================
// BTG - Normalized Pipeline Configuration (Domit §46, §76)
// ==============================================================================
// Separates raw CLI configuration requests from the validated, normalized
// build configuration (`ResolvedConfig`), preventing flag conflicts and
// unexpected feature interactions.
// ==============================================================================

use crate::crypto::CryptoMode;
use anyhow::{anyhow, Result};

/// Raw build configuration requested directly via CLI or API.
#[derive(Debug, Clone)]
pub struct RequestedConfig {
    pub seed: Option<u64>,
    pub obf_level: usize,
    pub crypto_mode: CryptoMode,
    pub custom_cipher: bool,
    pub anti_debug: bool,
    pub iat_hide: bool,
    pub mem_harden: bool,
    pub reencrypt: bool,
    pub vm: bool,
    pub vm_oep: bool,
    pub vm_commercial: bool,
    pub m7: bool,
    pub m8: bool,
    pub payload_relocate: bool,
    pub keep_pdata: bool,
}

/// Normalized, validated configuration with resolved feature conflicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfig {
    pub seed: u64,
    pub effective_obf_level: usize,
    pub crypto_mode: CryptoMode,
    pub anti_debug: bool,
    pub iat_hide: bool,
    pub mem_harden: bool,
    pub reencrypt: bool,
    pub vm_oep: bool,
    pub vm_commercial: bool,
    pub m7: bool,
    pub m8: bool,
    pub payload_relocate: bool,
    pub keep_pdata: bool,
}

impl Default for RequestedConfig {
    fn default() -> Self {
        Self {
            seed: None,
            obf_level: 2,
            crypto_mode: CryptoMode::Rc4,
            custom_cipher: false,
            anti_debug: false,
            iat_hide: false,
            mem_harden: false,
            reencrypt: false,
            vm: false,
            vm_oep: false,
            vm_commercial: false,
            m7: false,
            m8: false,
            payload_relocate: false,
            keep_pdata: false,
        }
    }
}

impl RequestedConfig {
    /// Resolve and validate requested configuration against pipeline invariants.
    pub fn resolve(&self) -> Result<ResolvedConfig> {
        let seed = self.seed.unwrap_or(0x1337_C0DE_CAFE_BABE);

        // Effective MBA obfuscation level resolution (O1)
        let effective_obf_level = if self.reencrypt || self.m7 {
            2 // reencrypt / m7 paths enforce level 2 key derivation
        } else {
            self.obf_level.clamp(1, 3)
        };

        // Crypto mode resolution: custom_cipher flag maps to C1
        let crypto_mode = if self.custom_cipher && self.crypto_mode == CryptoMode::Rc4 {
            CryptoMode::C1
        } else {
            self.crypto_mode
        };

        // Commercial VM requires basic VM flags enabled
        let vm_commercial = self.vm_commercial && (self.vm || self.vm_oep);

        Ok(ResolvedConfig {
            seed,
            effective_obf_level,
            crypto_mode,
            anti_debug: self.anti_debug,
            iat_hide: self.iat_hide,
            mem_harden: self.mem_harden,
            reencrypt: self.reencrypt,
            vm_oep: self.vm_oep,
            vm_commercial,
            m7: self.m7,
            m8: self.m8,
            payload_relocate: self.payload_relocate,
            keep_pdata: self.keep_pdata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_resolution_enforces_reencrypt_obf_level_2() {
        let req = RequestedConfig {
            obf_level: 3,
            reencrypt: true,
            ..Default::default()
        };
        let resolved = req.resolve().unwrap();
        assert_eq!(resolved.effective_obf_level, 2);
    }

    #[test]
    fn test_custom_cipher_promotes_rc4_to_c1() {
        let req = RequestedConfig {
            custom_cipher: true,
            crypto_mode: CryptoMode::Rc4,
            ..Default::default()
        };
        let resolved = req.resolve().unwrap();
        assert_eq!(resolved.crypto_mode, CryptoMode::C1);
    }
}
