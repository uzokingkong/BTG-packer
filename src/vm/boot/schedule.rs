//! Versioned stage-control program. Each token selects a fixed, approved
//! bootstrap bridge. It cannot encode pointers, arbitrary calls or back edges.
pub(crate) const PHASE_COUNT: usize = 12;
pub(crate) const STATE_SIZE: usize = 32;
pub(crate) const AUTH_RECORD: u64 = u64::MAX - 4;

pub(crate) fn bytecode() -> Vec<u8> {
    (1..=PHASE_COUNT as u8).chain(std::iter::once(0)).collect()
}
