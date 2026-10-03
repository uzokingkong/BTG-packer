//! RFC 8439 ChaCha20 mask initialization; no host callbacks or stack workspace.
use super::codegen_util::{movi, CodeBuilder};
use crate::vm::handler_table_codec::{HandlerCodec, MASKS_OFFSET, READY_OFFSET, SCRATCH_OFFSET};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

fn mem(offset: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ_size(Register::RDX, offset, 8)
}
fn quarter(b: &mut CodeBuilder, slots: [usize; 4]) {
    let regs = [Register::EAX, Register::ECX, Register::R9D, Register::R10D];
    for (&reg, &slot) in regs.iter().zip(&slots) {
        b.push(
            Instruction::with2(
                Code::Mov_r32_rm32,
                reg,
                mem(SCRATCH_OFFSET + slot as i64 * 4),
            )
            .unwrap(),
        );
    }
    for (a, c, d, rotate) in [(0, 1, 3, 16), (2, 3, 1, 12), (0, 1, 3, 8), (2, 3, 1, 7)] {
        b.push(Instruction::with2(Code::Add_rm32_r32, regs[a], regs[c]).unwrap());
        b.push(Instruction::with2(Code::Xor_rm32_r32, regs[d], regs[a]).unwrap());
        b.push(Instruction::with2(Code::Rol_rm32_imm8, regs[d], rotate).unwrap());
    }
    for (&reg, &slot) in regs.iter().zip(&slots) {
        b.push(
            Instruction::with2(
                Code::Mov_rm32_r32,
                mem(SCRATCH_OFFSET + slot as i64 * 4),
                reg,
            )
            .unwrap(),
        );
    }
}

/// Clobbers RAX/RCX/R9/R10/R11/RSI, preserving the pinned bytecode/state roles.
/// Each VM invocation owns its state lane; READY stays zero until all masks
/// and every decoded offset have passed validation in the caller.
pub(super) fn emit_init(b: &mut CodeBuilder, codec: &HandlerCodec) {
    b.push(Instruction::with2(Code::Mov_rm64_imm32, mem(READY_OFFSET), 0).unwrap());
    for (i, word) in codec.initial_words().iter().enumerate() {
        b.push(
            Instruction::with2(
                Code::Mov_rm32_imm32,
                mem(SCRATCH_OFFSET + 64 + i as i64 * 4),
                *word,
            )
            .unwrap(),
        );
    }
    movi(b, Register::R11, 0);
    let blocks = b.len();
    for i in 0..16 {
        b.push(
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EAX,
                mem(SCRATCH_OFFSET + 64 + i * 4),
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Mov_rm32_r32,
                mem(SCRATCH_OFFSET + i * 4),
                Register::EAX,
            )
            .unwrap(),
        );
    }
    movi(b, Register::RSI, 10);
    let rounds = b.len();
    for slots in [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15],
        [0, 5, 10, 15],
        [1, 6, 11, 12],
        [2, 7, 8, 13],
        [3, 4, 9, 14],
    ] {
        quarter(b, slots);
    }
    b.push(Instruction::with1(Code::Dec_rm64, Register::RSI).unwrap());
    b.jne(rounds);
    for i in 0..16 {
        b.push(
            Instruction::with2(
                Code::Mov_r32_rm32,
                Register::EAX,
                mem(SCRATCH_OFFSET + i * 4),
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Add_r32_rm32,
                Register::EAX,
                mem(SCRATCH_OFFSET + 64 + i * 4),
            )
            .unwrap(),
        );
        b.push(
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::RDX,
                    Register::R11,
                    1,
                    MASKS_OFFSET + i * 4,
                    8,
                ),
                Register::EAX,
            )
            .unwrap(),
        );
    }
    b.push(Instruction::with1(Code::Inc_rm32, mem(SCRATCH_OFFSET + 64 + 48)).unwrap());
    b.push(Instruction::with2(Code::Add_rm64_imm32, Register::R11, 64).unwrap());
    b.push(Instruction::with2(Code::Cmp_rm64_imm32, Register::R11, 2048).unwrap());
    b.jne(blocks);
    // Do not retain the working key schedule in per-invocation scratch.
    for i in 0..16 {
        b.push(Instruction::with2(Code::Mov_rm64_imm32, mem(SCRATCH_OFFSET + i * 8), 0).unwrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{
        arena::Arena,
        handler_table_codec::{BuildSettings, STATE_END},
    };

    #[test]
    fn native_prf_initialization_matches_all_256_reference_masks() {
        for settings in [
            BuildSettings::default(),
            BuildSettings::with_private_key([0xD3; 32]),
        ] {
            let codec = HandlerCodec::new(0x123456789ABCDEF0, 2, [7; 32], 3, 4, &settings);
            let mut arena = Arena::new(0x10000).unwrap();
            let state = 0x4000;
            let mut b = CodeBuilder::new();
            b.push(Instruction::with1(Code::Push_r64, Register::RSI).unwrap());
            movi(&mut b, Register::RDX, (arena.base + state) as u64);
            emit_init(&mut b, &codec);
            b.push(Instruction::with1(Code::Pop_r64, Register::RSI).unwrap());
            b.push(Instruction::with(Code::Retnq));
            let (code, _) = b.assemble(arena.base as u64).unwrap();
            assert!(code.len() < state);
            arena.bytes()[..code.len()].copy_from_slice(&code);
            arena.bytes()[state..state + STATE_END].fill(0xAA);
            arena.call(0);
            let bytes = arena.bytes();
            for (op, expected) in codec.masks.iter().enumerate() {
                let offset = state + MASKS_OFFSET as usize + op * 8;
                assert_eq!(
                    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                    *expected,
                    "opcode {op}"
                );
            }
            assert_eq!(
                &bytes[state + READY_OFFSET as usize..state + READY_OFFSET as usize + 8],
                &[0; 8]
            );
            assert!(bytes[state + SCRATCH_OFFSET as usize..state + STATE_END]
                .iter()
                .all(|&b| b == 0));
        }
    }
}
