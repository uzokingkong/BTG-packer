use crate::pipeline::crypto::stages::Stage;
use anyhow::{ensure, Result};
use std::ops::Range;

pub(crate) const BOOT_PROGRAM_ABI: u32 = 1;
pub(crate) const BOOT_STAGE_CRYPTO_ABI: u32 = 64;
pub(crate) const MAX_BOOT_RECORDS: usize = 4096;

/// Only this approved slice is accessible; no arbitrary guest host pointers.
#[derive(Clone, Debug)]
pub(crate) struct StageContract {
    pub stage: Stage,
    pub record: u64,
    pub offset: usize,
    pub len: usize,
    pub tag: [u8; 16],
}

impl StageContract {
    pub fn range(&self, buffer_len: usize) -> Result<Range<usize>> {
        let end = self
            .offset
            .checked_add(self.len)
            .ok_or_else(|| anyhow::anyhow!("boot span overflow"))?;
        ensure!(end <= buffer_len, "boot span outside approved buffer");
        // RFC 8439 counter starts at one. Do not allow counter exhaustion.
        ensure!(
            self.len as u128 <= u32::MAX as u128 * 64,
            "boot ChaCha counter exhaustion"
        );
        Ok(self.offset..end)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootState {
    Fresh,
    Running,
    Ready,
    Failed,
}
