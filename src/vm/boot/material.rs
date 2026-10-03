//! Fixed bounded bootstrap material IR v1. Metadata derivation and program
//! authentication form the native root; other material stages run in Boot VM.
use crate::pipeline::crypto::stages::{Stage, STAGES};
pub(crate) const MATERIAL_PROGRAM_RECORD: u64 = u64::MAX - 1;
pub(crate) const DERIVE: u8 = 1;
pub(crate) const HALT: u8 = 0;
pub(crate) fn bytecode() -> Vec<u8> {
    let mut bytes = Vec::new();
    for stage in STAGES {
        if stage == Stage::Metadata {
            continue;
        }
        bytes.push(DERIVE);
        bytes.extend(stage.domain().to_le_bytes());
        bytes.extend((stage.offset() as u32).to_le_bytes());
    }
    bytes.push(HALT);
    bytes
}
