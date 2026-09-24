//! Native MSVC throw boundary. Runtime-initialized relative callbacks are not
//! visible to the PE's static pointer inventory. Only typed, writable metadata
//! reached from the actual imported throw routine is eligible for translation.
use super::codegen_util::{movi, CodeBuilder};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

#[derive(Clone, Debug, Default)]
pub struct NativeExceptionBridge {
    pub image_base: u64,
    pub throw_iat_slots: Vec<u64>,
    /// Original writable section intervals, exclusive end (preferred VAs).
    pub writable_ranges: Vec<(u64, u64)>,
}

fn resolve(b: &mut CodeBuilder, edges: &[usize], target: usize) {
    for (edge, destination) in &mut b.branches {
        if edges.contains(edge) {
            *destination = target;
        }
    }
}

// Check an entire fixed-sized typed record before reading or writing it.
// R8 is the record pointer; only RAX and flags are clobbered.
fn writable(
    b: &mut CodeBuilder,
    config: &NativeExceptionBridge,
    size: u64,
    exits: &mut Vec<usize>,
) {
    let mut accepted = Vec::new();
    for &(start, end) in &config.writable_ranges {
        if end.saturating_sub(start) < size {
            continue;
        }
        movi(b, Register::RAX, start);
        b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R8, Register::RAX).unwrap());
        let below = b.br(Code::Jb_rel32_64, usize::MAX);
        movi(b, Register::RAX, end - size);
        b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R8, Register::RAX).unwrap());
        accepted.push(b.br(Code::Jbe_rel32_64, usize::MAX));
        resolve(b, &[below], b.len());
    }
    exits.push(b.br(Code::Jmp_rel32_64, usize::MAX));
    resolve(b, &accepted, b.len());
}

// Translate a code RVA at R8. Preserve the traversal registers RCX/RDX/R11.
fn rewrite_slot(b: &mut CodeBuilder, config: &NativeExceptionBridge, rewrites: &[(u64, u64)]) {
    b.push(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::R9D,
            MemoryOperand::with_base(Register::R8),
        )
        .unwrap(),
    );
    movi(b, Register::R10, config.image_base);
    b.push(Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::R10).unwrap());
    let mut done = Vec::new();
    for &(original, gateway) in rewrites {
        movi(b, Register::RAX, original);
        b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R9, Register::RAX).unwrap());
        let next = b.br(Code::Jne_rel32_64, usize::MAX);
        movi(b, Register::RAX, gateway);
        b.push(Instruction::with2(Code::Sub_rm64_r64, Register::RAX, Register::R10).unwrap());
        b.push(
            Instruction::with2(
                Code::Mov_rm32_r32,
                MemoryOperand::with_base(Register::R8),
                Register::EAX,
            )
            .unwrap(),
        );
        done.push(b.br(Code::Jmp_rel32_64, usize::MAX));
        resolve(b, &[next], b.len());
    }
    resolve(b, &done, b.len());
}

/// Emit before guest GPR materialization, on the native-only path. RDI is the
/// native target; R12 is the (subsequently permuted) VM state carrier. All guest
/// registers are still authoritative in state. No physical stack is changed.
pub(super) fn emit(
    b: &mut CodeBuilder,
    config: &NativeExceptionBridge,
    rewrites: &[(u64, u64)],
    guest_rdx_offset: i64,
) {
    if config.throw_iat_slots.is_empty() || config.writable_ranges.is_empty() || rewrites.is_empty()
    {
        return;
    }
    let mut matches = Vec::new();
    for &slot in &config.throw_iat_slots {
        movi(b, Register::RAX, slot);
        b.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base(Register::RAX),
            )
            .unwrap(),
        );
        b.push(Instruction::with2(Code::Cmp_rm64_r64, Register::RDI, Register::RAX).unwrap());
        matches.push(b.br(Code::Je_rel32_64, usize::MAX));
    }
    let mut exits = vec![b.br(Code::Jmp_rel32_64, usize::MAX)];
    resolve(b, &matches, b.len());
    b.push(
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::R8,
            MemoryOperand::with_base_displ_size(Register::R12, guest_rdx_offset, 8),
        )
        .unwrap(),
    );
    writable(b, config, 16, &mut exits);
    // ThrowInfo: attributes, destructor RVA, forward compatibility RVA, CTA RVA.
    b.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R8).unwrap());
    b.push(Instruction::with2(Code::Add_rm64_imm8, Register::R8, 4).unwrap());
    rewrite_slot(b, config, rewrites);
    b.push(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::R8D,
            MemoryOperand::with_base_displ_size(Register::RDX, 12, 8),
        )
        .unwrap(),
    );
    b.push(Instruction::with2(Code::Test_rm32_r32, Register::R8D, Register::R8D).unwrap());
    exits.push(b.br(Code::Je_rel32_64, usize::MAX));
    b.push(Instruction::with2(Code::Add_rm64_r64, Register::R8, Register::R10).unwrap());
    writable(b, config, 4, &mut exits);
    b.push(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::ECX,
            MemoryOperand::with_base(Register::R8),
        )
        .unwrap(),
    );
    b.push(Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX).unwrap());
    exits.push(b.br(Code::Je_rel32_64, usize::MAX));
    b.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, 4096).unwrap());
    exits.push(b.br(Code::Ja_rel32_64, usize::MAX));
    b.push(
        Instruction::with2(
            Code::Lea_r64_m,
            Register::R11,
            MemoryOperand::with_base_displ_size(Register::R8, 4, 8),
        )
        .unwrap(),
    );
    let loop_start = b.len();
    b.push(Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::R11).unwrap());
    writable(b, config, 4, &mut exits);
    b.push(
        Instruction::with2(
            Code::Mov_r32_rm32,
            Register::R8D,
            MemoryOperand::with_base(Register::R11),
        )
        .unwrap(),
    );
    b.push(Instruction::with2(Code::Test_rm32_r32, Register::R8D, Register::R8D).unwrap());
    exits.push(b.br(Code::Je_rel32_64, usize::MAX));
    b.push(Instruction::with2(Code::Add_rm64_r64, Register::R8, Register::R10).unwrap());
    writable(b, config, 28, &mut exits);
    // CatchableType: only copyFunction is code; type/displacement fields stay intact.
    b.push(Instruction::with2(Code::Add_rm64_imm8, Register::R8, 24).unwrap());
    rewrite_slot(b, config, rewrites);
    b.push(Instruction::with2(Code::Add_rm64_imm8, Register::R11, 4).unwrap());
    b.push(Instruction::with1(Code::Dec_rm32, Register::ECX).unwrap());
    b.br(Code::Jne_rel32_64, loop_start);
    resolve(b, &exits, b.len());
}

#[cfg(all(test, target_arch = "x86_64", target_os = "windows"))]
mod tests {
    use super::*;
    use crate::vm::arena::Arena;

    #[test]
    fn runtime_throw_metadata_rewrites_only_typed_writable_callbacks() {
        for case in 0..6 {
            let mut data = vec![0u8; 0x1000];
            let base = data.as_ptr() as u64;
            let image_base = base - 0x1000;
            let mut put = |offset: usize, value: u32| {
                data[offset..offset + 4].copy_from_slice(&value.to_le_bytes())
            };
            put(0x100, 0x2000); // opaque attributes look exactly like a code RVA
            put(0x104, 0x2000); // destructor
            put(0x108, 0); // forward compatibility
            put(0x10c, 0x1200); // CTA
            put(0x200, if case == 4 { 4097 } else { 1 });
            put(0x204, if case == 5 { 0 } else { 0x1300 });
            put(0x304, 0x2000); // type descriptor, must NOT be rewritten
            put(0x318, 0x2100); // copy function
            data[0..8].copy_from_slice(&0x12345678u64.to_le_bytes());
            data[0x80..0x88]
                .copy_from_slice(&(if case == 3 { 0 } else { base + 0x100 }).to_le_bytes());
            let config = NativeExceptionBridge {
                image_base,
                throw_iat_slots: vec![base],
                writable_ranges: if case == 2 {
                    vec![(base, base + 0x100)]
                } else {
                    vec![(base, base + 0x1000)]
                },
            };
            let mut b = CodeBuilder::new();
            b.push(Instruction::with1(Code::Push_r64, Register::R12).unwrap());
            b.push(Instruction::with1(Code::Push_r64, Register::RDI).unwrap());
            movi(&mut b, Register::R12, base);
            movi(
                &mut b,
                Register::RDI,
                if case == 1 { 0x87654321 } else { 0x12345678 },
            );
            emit(
                &mut b,
                &config,
                &[
                    (image_base + 0x2000, image_base + 0x2800),
                    (image_base + 0x2100, image_base + 0x2900),
                ],
                0x80,
            );
            b.push(Instruction::with1(Code::Pop_r64, Register::RDI).unwrap());
            b.push(Instruction::with1(Code::Pop_r64, Register::R12).unwrap());
            b.push(Instruction::with(Code::Retnq));
            let mut arena = Arena::new(0x10000).unwrap();
            let (code, _) = b.assemble(arena.base as u64).unwrap();
            arena.bytes()[..code.len()].copy_from_slice(&code);
            arena.seal().unwrap();
            arena.call(0);
            // Repeating a throw must not add the gateway delta a second time.
            arena.call(0);
            let read = |offset| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            assert_eq!(read(0x100), 0x2000, "attributes, case {case}");
            assert_eq!(read(0x304), 0x2000, "type, case {case}");
            assert_eq!(
                read(0x104),
                if [0, 4, 5].contains(&case) {
                    0x2800
                } else {
                    0x2000
                },
                "destructor, case {case}"
            );
            assert_eq!(
                read(0x318),
                if case == 0 { 0x2900 } else { 0x2100 },
                "copy, case {case}"
            );
        }
    }
}
