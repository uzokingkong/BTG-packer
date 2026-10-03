//! Versioned opt-in handler codec. Masks are address hiding, not authentication.
use super::key_domains::hmac_sha256;
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, fs::File, io::Read, path::Path};

pub const CODEC_VERSION: u32 = 2;
pub const ENTRY_COUNT: usize = 256;
pub const MASKS_OFFSET: i64 = 0x5200;
pub const READY_OFFSET: i64 = MASKS_OFFSET + (ENTRY_COUNT * 8) as i64;
pub const SCRATCH_OFFSET: i64 = READY_OFFSET + 16;
pub const STATE_END: usize = SCRATCH_OFFSET as usize + 128;

#[derive(Clone, Default)]
pub struct BuildSettings {
    private_key: Option<[u8; 32]>,
}
impl std::fmt::Debug for BuildSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerCodecSettings")
            .field("private_key_present", &self.private_key.is_some())
            .finish()
    }
}
impl BuildSettings {
    pub fn with_private_key(key: [u8; 32]) -> Self {
        Self {
            private_key: Some(key),
        }
    }
    pub fn read_private_key(path: &Path) -> Result<Self> {
        let mut key = Vec::new();
        File::open(path)
            .context("cannot open private build key")?
            .take(33)
            .read_to_end(&mut key)
            .context("cannot read private build key")?;
        ensure!(
            key.len() == 32,
            "private build key must contain exactly 32 binary bytes"
        );
        Ok(Self::with_private_key(key.try_into().unwrap()))
    }
    // Only hashed identity enters private cache naming; never public manifests.
    pub(crate) fn cache_identity(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"BTG/handler-codec/v2/cache");
        hash.update([u8::from(self.private_key.is_some())]);
        if let Some(key) = self.private_key {
            hash.update(key);
        }
        hash.finalize().into()
    }
}
thread_local! { static ACTIVE: RefCell<Option<BuildSettings>> = const { RefCell::new(None) }; }
// This guard restores thread-local state and therefore cannot cross threads.
pub struct BuildGuard(
    Option<BuildSettings>,
    std::marker::PhantomData<std::rc::Rc<()>>,
);
impl Drop for BuildGuard {
    fn drop(&mut self) {
        ACTIVE.with(|a| *a.borrow_mut() = self.0.take());
    }
}
pub fn activate(settings: BuildSettings) -> BuildGuard {
    BuildGuard(
        ACTIVE.with(|a| a.borrow_mut().replace(settings)),
        std::marker::PhantomData,
    )
}
pub(crate) fn active() -> Option<BuildSettings> {
    ACTIVE.with(|a| a.borrow().clone())
}

#[derive(Clone, PartialEq, Eq)]
pub struct HandlerCodec {
    key: [u8; 32],
    nonce: [u8; 12],
    pub masks: [u64; ENTRY_COUNT],
}
impl std::fmt::Debug for HandlerCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerCodec")
            .field("version", &CODEC_VERSION)
            .finish_non_exhaustive()
    }
}
impl HandlerCodec {
    pub fn new(
        seed: u64,
        family: u8,
        module_id: [u8; 32],
        table_id: u32,
        lane_id: u32,
        settings: &BuildSettings,
    ) -> Self {
        // Fixed-width canonical context: ABI, module, family, table and logical lane.
        let mut context = b"BTG/handler-codec/v2/x86-64\0".to_vec();
        context.extend(CODEC_VERSION.to_le_bytes());
        context.extend(module_id);
        context.push(family);
        context.extend(table_id.to_le_bytes());
        context.extend(lane_id.to_le_bytes());
        let mut ikm = seed.to_le_bytes().to_vec();
        ikm.push(u8::from(settings.private_key.is_some()));
        if let Some(key) = settings.private_key {
            ikm.extend(key);
        }
        let prk = hmac_sha256(b"BTG/handler-codec/HKDF-SHA256/v2", &ikm);
        let mut key_info = context.clone();
        key_info.extend(b"/mask-key\x01");
        let key = hmac_sha256(&prk, &key_info);
        context.extend(b"/mask-nonce\x01");
        let nonce: [u8; 12] = hmac_sha256(&prk, &context)[..12].try_into().unwrap();
        let mut masks = [0u64; ENTRY_COUNT];
        for block in 0..32 {
            let bytes = crate::crypto::chacha20::chacha20_block(&key, block as u32 + 1, &nonce);
            for slot in 0..8 {
                masks[block * 8 + slot] =
                    u64::from_le_bytes(bytes[slot * 8..slot * 8 + 8].try_into().unwrap());
            }
        }
        Self { key, nonce, masks }
    }
    pub(crate) fn initial_words(&self) -> [u32; 16] {
        let mut words = [0u32; 16];
        words[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
        for i in 0..8 {
            words[i + 4] = u32::from_le_bytes(self.key[i * 4..i * 4 + 4].try_into().unwrap());
        }
        words[12] = 1;
        for i in 0..3 {
            words[i + 13] = u32::from_le_bytes(self.nonce[i * 4..i * 4 + 4].try_into().unwrap());
        }
        words
    }
    pub fn encode(&self, opcode: u8, offset: u64, code_len: usize) -> Result<u64> {
        ensure!(
            offset < code_len as u64,
            "handler offset is outside module code"
        );
        Ok(offset ^ self.masks[opcode as usize])
    }
    pub fn decode(&self, opcode: u8, encoded: u64, code_base: u64, code_len: usize) -> Result<u64> {
        let offset = encoded ^ self.masks[opcode as usize];
        ensure!(
            offset < code_len as u64,
            "handler offset is outside module code"
        );
        code_base
            .checked_add(offset)
            .context("handler address overflow")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_contexts_private_keys_and_bounds() {
        let settings = BuildSettings::default();
        let baseline = HandlerCodec::new(7, 1, [2; 32], 3, 4, &settings);
        for other in [
            HandlerCodec::new(8, 1, [2; 32], 3, 4, &settings),
            HandlerCodec::new(7, 2, [2; 32], 3, 4, &settings),
            HandlerCodec::new(7, 1, [3; 32], 3, 4, &settings),
            HandlerCodec::new(7, 1, [2; 32], 4, 4, &settings),
            HandlerCodec::new(7, 1, [2; 32], 3, 5, &settings),
            HandlerCodec::new(
                7,
                1,
                [2; 32],
                3,
                4,
                &BuildSettings::with_private_key([0; 32]),
            ),
        ] {
            assert_ne!(baseline.masks, other.masks);
        }
        for op in 0..=255 {
            let encoded = baseline.encode(op, 17, 32).unwrap();
            assert_eq!(baseline.decode(op, encoded, 1000, 32).unwrap(), 1017);
            assert!(baseline
                .decode(op, baseline.masks[op as usize] ^ 32, 1000, 32)
                .is_err());
            assert!(baseline.decode(op, encoded, u64::MAX, 32).is_err());
        }
        assert!(baseline.encode(0, 32, 32).is_err());
        assert_eq!(baseline, HandlerCodec::new(7, 1, [2; 32], 3, 4, &settings));
    }
    #[test]
    fn scoped_configuration_restores_on_drop_and_never_formats_secrets() {
        assert!(active().is_none());
        let outer = activate(BuildSettings::default());
        let identity = active().unwrap().cache_identity();
        {
            let _inner = activate(BuildSettings::with_private_key([0xA7; 32]));
            assert_ne!(active().unwrap().cache_identity(), identity);
            assert!(!format!("{:?}", active().unwrap()).contains("167"));
        }
        assert_eq!(active().unwrap().cache_identity(), identity);
        drop(outer);
        assert!(active().is_none());
    }
}
