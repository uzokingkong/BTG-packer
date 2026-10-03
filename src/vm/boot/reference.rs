use super::{
    contract::{BootState, BOOT_PROGRAM_ABI, BOOT_STAGE_CRYPTO_ABI},
    program::{BootOp, BootProgram},
};
use crate::crypto::chacha20;
use crate::pipeline::crypto::stages;
use anyhow::{ensure, Result};

/// Native crypto reference adapter; no Program VM state/table dependencies.
/// One-shot state: failure/ready cannot reenter. Caller creates a fresh instance
/// and supplies original ciphertext for retries.
pub(crate) struct BootReference {
    state: BootState,
}

struct Scratch(Vec<Vec<u8>>);
impl Drop for Scratch {
    fn drop(&mut self) {
        for record in &mut self.0 {
            for byte in record {
                unsafe { std::ptr::write_volatile(byte, 0) };
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl BootReference {
    pub fn new() -> Self {
        Self {
            state: BootState::Fresh,
        }
    }
    pub fn state(&self) -> BootState {
        self.state
    }

    pub fn run(
        &mut self,
        program: &BootProgram,
        seed: &[u8; 256],
        buffer: &mut [u8],
    ) -> Result<()> {
        ensure!(
            self.state == BootState::Fresh,
            "boot reference cannot reenter or repeat"
        );
        self.state = BootState::Running;
        let result = Self::execute(program, seed, buffer);
        self.state = if result.is_ok() {
            BootState::Ready
        } else {
            BootState::Failed
        };
        result
    }

    fn execute(program: &BootProgram, seed: &[u8; 256], buffer: &mut [u8]) -> Result<()> {
        program.validate(BOOT_PROGRAM_ABI, BOOT_STAGE_CRYPTO_ABI)?;
        ensure!(
            buffer.len() == program.buffer_len(),
            "boot approved buffer length mismatch"
        );
        // Allocate all bounded scratch before authentication. Plaintext remains
        // private until every stage succeeds. Failure preserves ciphertext.
        let mut scratch = Scratch(Vec::new());
        scratch.0.try_reserve_exact(program.records().len())?;
        for record in program.records() {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(record.len)?;
            bytes.extend_from_slice(&buffer[record.range(buffer.len())?]);
            scratch.0.push(bytes);
        }
        let (mut pc, mut cursor) = (0usize, 0usize);
        while let Some(op) = program.ops().get(pc).copied() {
            match op {
                BootOp::Authenticate(_) | BootOp::AuthenticateCurrent => {
                    let index = match op { BootOp::Authenticate(index) => index, _ => cursor };
                    let record = &program.records()[index];
                    let actual =
                        stages::authenticate(seed, record.stage, record.record, &scratch.0[index]);
                    let mismatch = actual
                        .iter()
                        .zip(record.tag)
                        .fold(0u8, |diff, (a, b)| diff | (a ^ b));
                    ensure!(
                        mismatch == 0,
                        "boot stage authentication failed at record {index}"
                    );
                }
                BootOp::Decrypt(_) | BootOp::DecryptCurrent => {
                    let index = match op { BootOp::Decrypt(index) => index, _ => cursor };
                    let record = &program.records()[index];
                    let (key, nonce) = stages::key_nonce(seed, record.stage, record.record);
                    let mut state = [0; chacha20::CHA_STATE_SIZE];
                    chacha20::chacha_init_state(&mut state, &key, &nonce);
                    state[chacha20::CHA_OFF_CTR..chacha20::CHA_OFF_CTR + 8]
                        .copy_from_slice(&1u64.to_le_bytes());
                    chacha20::chacha_apply(&mut state, &mut scratch.0[index]);
                }
                BootOp::NextRecord { loop_pc } => {
                    cursor += 1;
                    if cursor < program.records().len() { pc = loop_pc; continue; }
                }
                BootOp::Fail => anyhow::bail!("boot program explicit failure"),
                BootOp::PublishReady => {
                    for (record, plain) in program.records().iter().zip(&scratch.0) {
                        let range = record.range(buffer.len())?;
                        buffer[range].copy_from_slice(plain);
                    }
                }
            }
            pc += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::boot::contract::StageContract;
    use chacha20poly1305::{
        aead::{Aead, Payload},
        ChaCha20Poly1305, KeyInit,
    };

    #[test]
    fn all_stages_match_standard_aead_and_preserve_guards() {
        let seed = [0x93; 256];
        for stage in stages::STAGES {
            for len in [0, 1, 15, 16, 17, 63, 64, 65, 257] {
                let plain = vec![0x53; len];
                let mut cipher = plain.clone();
                let tag = stages::seal(&seed, stage, 17, &mut cipher);
                let (key, nonce) = stages::key_nonce(&seed, stage, 17);
                let mut sealed = cipher.clone();
                sealed.extend(tag);
                let expected = ChaCha20Poly1305::new((&key).into())
                    .decrypt(
                        (&nonce).into(),
                        Payload {
                            msg: &sealed,
                            aad: &crate::crypto::poly1305::POLY1305_AEAD_AAD,
                        },
                    )
                    .unwrap();
                let mut buffer = vec![0xAA];
                buffer.extend(cipher);
                buffer.push(0xBB);
                let program = BootProgram::authenticated_records(
                    vec![StageContract {
                        stage,
                        record: 17,
                        offset: 1,
                        len,
                        tag,
                    }],
                    buffer.len(),
                    len,
                )
                .unwrap();
                let mut vm = BootReference::new();
                vm.run(&program, &seed, &mut buffer).unwrap();
                assert_eq!(vm.state(), BootState::Ready);
                assert_eq!(&buffer[1..1 + len], expected);
                assert_eq!(buffer[0], 0xAA);
                assert_eq!(buffer[len + 1], 0xBB);
                assert!(vm.run(&program, &seed, &mut buffer).is_err());
            }
        }
    }

    #[test]
    fn late_auth_failure_is_transactional_and_cannot_reenter() {
        let seed = [0x61; 256];
        let mut buffer = vec![0x42; 32];
        let mut records = Vec::new();
        for (index, stage) in [stages::Stage::Payload, stages::Stage::Bytecode]
            .into_iter()
            .enumerate()
        {
            let tag = stages::seal(
                &seed,
                stage,
                index as u64,
                &mut buffer[index * 16..(index + 1) * 16],
            );
            records.push(StageContract {
                stage,
                record: index as u64,
                offset: index * 16,
                len: 16,
                tag,
            });
        }
        for tamper in 0..4 {
            let mut bad_records = records.clone();
            let mut bad_buffer = buffer.clone();
            match tamper {
                0 => bad_records[1].tag[0] ^= 1,
                1 => bad_buffer[31] ^= 1,
                2 => bad_records[1].record += 1,
                _ => bad_records[1].stage = stages::Stage::Data,
            }
            let original = bad_buffer.clone();
            let program = BootProgram::authenticated_records(bad_records, 32, 32).unwrap();
            let mut vm = BootReference::new();
            assert!(vm.run(&program, &seed, &mut bad_buffer).is_err());
            assert_eq!(vm.state(), BootState::Failed);
            assert_eq!(bad_buffer, original);
            assert!(vm.run(&program, &seed, &mut bad_buffer).is_err());
        }
        let program = BootProgram::authenticated_records(records, 32, 32).unwrap();
        let mut vm = BootReference::new();
        assert!(vm.run(&program, &seed, &mut buffer[..31]).is_err());
        assert_eq!(vm.state(), BootState::Failed);
    }

    #[test]
    fn multi_stage_success_wrong_seed_and_empty_program() {
        let seed = [0x61; 256];
        let mut buffer = vec![0x42; 32];
        let mut records = Vec::new();
        for (index, stage) in [stages::Stage::Metadata, stages::Stage::Resolver]
            .into_iter()
            .enumerate()
        {
            let tag = stages::seal(
                &seed,
                stage,
                u64::MAX,
                &mut buffer[index * 16..(index + 1) * 16],
            );
            records.push(StageContract {
                stage,
                record: u64::MAX,
                offset: index * 16,
                len: 16,
                tag,
            });
        }
        let program = BootProgram::authenticated_records(records, 32, 32).unwrap();
        let ciphertext = buffer.clone();
        let mut vm = BootReference::new();
        assert!(vm.run(&program, &[0x62; 256], &mut buffer).is_err());
        assert_eq!(buffer, ciphertext);
        assert_eq!(vm.state(), BootState::Failed);
        let mut vm = BootReference::new();
        vm.run(&program, &seed, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x42; 32]);
        assert_eq!(vm.state(), BootState::Ready);
        let empty = BootProgram::authenticated_records(Vec::new(), 0, 0).unwrap();
        let mut vm = BootReference::new();
        vm.run(&empty, &seed, &mut []).unwrap();
        assert_eq!(vm.state(), BootState::Ready);
    }
}
