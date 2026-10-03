use super::contract::{StageContract, BOOT_PROGRAM_ABI, BOOT_STAGE_CRYPTO_ABI, MAX_BOOT_RECORDS};
use anyhow::{ensure, Result};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootOp {
    Authenticate(usize),
    Decrypt(usize),
    AuthenticateCurrent,
    DecryptCurrent,
    NextRecord { loop_pc: usize },
    Fail,
    PublishReady,
}

/// Bounded record orchestration. The only back edge increments the record
/// cursor; no arbitrary pointers, unbounded jumps or external OS calls exist.
#[derive(Clone, Debug)]
pub(crate) struct BootProgram {
    records: Vec<StageContract>,
    ops: Vec<BootOp>,
    buffer_len: usize,
    scratch_limit: usize,
}

impl BootProgram {
    pub fn authenticated_records(
        records: Vec<StageContract>,
        buffer_len: usize,
        scratch_limit: usize,
    ) -> Result<Self> {
        ensure!(records.len() <= MAX_BOOT_RECORDS, "too many boot records");
        let ops = if records.is_empty() { vec![BootOp::PublishReady] } else {
            vec![BootOp::AuthenticateCurrent, BootOp::DecryptCurrent,
                BootOp::NextRecord { loop_pc: 0 }, BootOp::PublishReady]
        };
        let program = Self {
            records,
            ops,
            buffer_len,
            scratch_limit,
        };
        program.validate(BOOT_PROGRAM_ABI, BOOT_STAGE_CRYPTO_ABI)?;
        Ok(program)
    }

    pub fn validate(&self, program_abi: u32, crypto_abi: u32) -> Result<()> {
        ensure!(
            program_abi == BOOT_PROGRAM_ABI && crypto_abi == BOOT_STAGE_CRYPTO_ABI,
            "boot ABI mismatch"
        );
        ensure!(
            self.records.len() <= MAX_BOOT_RECORDS,
            "too many boot records"
        );
        let mut spans = Vec::new();
        let mut total = 0usize;
        let mut identities = HashSet::new();
        for record in &self.records {
            let range = record.range(self.buffer_len)?;
            ensure!(
                identities.insert((record.stage as u32, record.record)),
                "duplicate boot stage/record identity"
            );
            if !range.is_empty() {
                spans.push(range);
            }
            total = total
                .checked_add(record.len)
                .ok_or_else(|| anyhow::anyhow!("boot scratch overflow"))?;
        }
        ensure!(total <= self.scratch_limit, "boot scratch budget exceeded");
        spans.sort_unstable_by_key(|range| range.start);
        ensure!(
            spans.windows(2).all(|pair| pair[0].end <= pair[1].start),
            "boot writable spans overlap"
        );
        ensure!(self.ops.len() <= MAX_BOOT_RECORDS * 2 + 4, "boot instruction budget exceeded");
        let mut status = vec![0u8; self.records.len()];
        let (mut pc, mut cursor, mut steps) = (0usize, 0usize, 0usize);
        loop {
            steps += 1;
            ensure!(steps <= MAX_BOOT_RECORDS * 4 + 4, "boot execution budget exceeded");
            let op = *self.ops.get(pc).ok_or_else(|| anyhow::anyhow!("boot missing terminal instruction"))?;
            match op {
                BootOp::Authenticate(_) | BootOp::AuthenticateCurrent => {
                    let index = match op { BootOp::Authenticate(index) => index, _ => cursor };
                    let state = status.get_mut(index).ok_or_else(|| anyhow::anyhow!("boot record outside contract"))?;
                    ensure!(*state == 0, "boot repeated authentication");
                    *state = 1;
                }
                BootOp::Decrypt(_) | BootOp::DecryptCurrent => {
                    let index = match op { BootOp::Decrypt(index) => index, _ => cursor };
                    let state = status.get_mut(index).ok_or_else(|| anyhow::anyhow!("boot record outside contract"))?;
                    ensure!(*state == 1, "boot decryption before authentication or repeated decryption");
                    *state = 2;
                }
                BootOp::NextRecord { loop_pc } => {
                    ensure!(loop_pc <= pc, "boot record loop must be a backward edge");
                    ensure!(status.get(cursor) == Some(&2), "boot record advanced before completion");
                    cursor += 1;
                    if cursor < self.records.len() { pc = loop_pc; continue; }
                }
                BootOp::PublishReady => {
                    ensure!(status.iter().all(|&state| state == 2), "boot premature ready publication");
                    ensure!(pc + 1 == self.ops.len(), "boot instructions after ready publication");
                    break;
                }
                BootOp::Fail => break,
            }
            pc += 1;
        }
        Ok(())
    }

    pub fn records(&self) -> &[StageContract] {
        &self.records
    }
    pub fn ops(&self) -> &[BootOp] {
        &self.ops
    }
    pub fn buffer_len(&self) -> usize {
        self.buffer_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::crypto::stages::Stage;
    fn record(offset: usize, len: usize, id: u64) -> StageContract {
        StageContract {
            stage: Stage::Bytecode,
            record: id,
            offset,
            len,
            tag: [0; 16],
        }
    }
    #[test]
    fn rejects_invalid_spans_budgets_and_order() {
        assert!(BootProgram::authenticated_records(vec![record(usize::MAX, 2, 0)], 8, 8).is_err());
        assert!(BootProgram::authenticated_records(vec![record(7, 2, 0)], 8, 8).is_err());
        assert!(
            BootProgram::authenticated_records(vec![record(0, 4, 0), record(3, 4, 1)], 8, 8)
                .is_err()
        );
        assert!(
            BootProgram::authenticated_records(vec![record(0, 4, 0), record(4, 4, 0)], 8, 8)
                .is_err()
        );
        assert!(BootProgram::authenticated_records(vec![record(0, 8, 0)], 8, 7).is_err());
        let mut program = BootProgram::authenticated_records(vec![record(0, 8, 0)], 8, 8).unwrap();
        assert!(program.validate(0, BOOT_STAGE_CRYPTO_ABI).is_err());
        program.ops.swap(0, 1);
        assert!(program
            .validate(BOOT_PROGRAM_ABI, BOOT_STAGE_CRYPTO_ABI)
            .is_err());
    }

    #[test]
    fn rejects_resource_and_counter_exhaustion() {
        let records = vec![record(0, 0, 0); MAX_BOOT_RECORDS + 1];
        assert!(BootProgram::authenticated_records(records, 0, 0).is_err());
        if usize::BITS >= 64 {
            let len = (u32::MAX as u64 * 64 + 1) as usize;
            assert!(BootProgram::authenticated_records(vec![record(0, len, 0)], len, len).is_err());
        }
    }

    #[test]
    fn bounded_record_loop_rejects_invalid_back_edges_and_early_publication() {
        let mut program = BootProgram::authenticated_records(
            vec![record(0, 4, 0), record(4, 4, 1)], 8, 8).unwrap();
        assert_eq!(program.ops.len(), 4);
        program.ops[2] = BootOp::NextRecord { loop_pc: 3 };
        assert!(program.validate(BOOT_PROGRAM_ABI, BOOT_STAGE_CRYPTO_ABI).is_err());
        program.ops[2] = BootOp::NextRecord { loop_pc: 2 };
        assert!(program.validate(BOOT_PROGRAM_ABI, BOOT_STAGE_CRYPTO_ABI).is_err());
        program.ops[2] = BootOp::NextRecord { loop_pc: 0 };
        program.ops[1] = BootOp::PublishReady;
        assert!(program.validate(BOOT_PROGRAM_ABI, BOOT_STAGE_CRYPTO_ABI).is_err());
    }
}
