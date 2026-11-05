use super::*;
use crate::vm::arena::Arena;

const RESULT: u64 = 0x1234_5678_9ABC_DEF0;
const SECOND_RESULT: u64 = 0xFEDC_BA98_7654_3210;
const VECTOR_RESULT: u64 = 0x405E_DD2F_1A9F_BE77;
const NONVOLATILE: u64 = 0x1122_3344_5566_7788;
const VECTOR_NONVOLATILE: u64 = 0x8877_6655_4433_2211;

fn put_code(arena: &mut Arena, offset: usize, instructions: &[Instruction]) -> usize {
    let bytes = BlockEncoder::encode(
        64,
        InstructionBlock::new(instructions, (arena.base + offset) as u64),
        BlockEncoderOptions::NONE,
    )
    .unwrap()
    .code_buffer;
    arena.bytes()[offset..offset + bytes.len()].copy_from_slice(&bytes);
    bytes.len()
}

fn run_with_windows_teb(arena: &Arena) {
    let teb = [0u64; 16];
    let mut previous_gs = 0u64;
    // Windows gateways read the thread ID from GS:0x48; Linux TLS stays in FS
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1004, &mut previous_gs) },
        0
    );
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001, teb.as_ptr()) },
        0
    );
    arena.call(0);
    let restored = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001, previous_gs) };
    assert_eq!(restored, 0);
}

fn check_gateway_return(canonical: bool, seed: u64, overwrite: bool) {
    let state_offset = 0x40000;
    let gateway_offset = 0x1000;
    let entry_offset = 0x400;
    let wrong_return_offset = 0x300;
    let results_offset = 0x800;
    let reserve = multi_family_invocation_layout(0, 1).unwrap().reserve_size;
    let mut arena = Arena::new(state_offset + reserve).unwrap();
    let state_va = (arena.base + state_offset) as u64;
    let gateway_va = (arena.base + gateway_offset) as u64;
    let entry_va = (arena.base + entry_offset) as u64;
    let wrong_return_va = (arena.base + wrong_return_offset) as u64;
    let results_va = (arena.base + results_offset) as u64;
    let invocation = multi_family_invocation_layout(state_va, 1).unwrap();
    let layout = vm::threaded::VmRuntimeLayout::from_seed(seed);
    let gateway = if canonical {
        build_canonical_oep_gateway(
            gateway_va,
            entry_va,
            state_va,
            &layout,
            1,
            &invocation,
            &crate::vm::data_lifetime::LifetimeSyncTable {
                base_va: invocation.lifetime_sync_va,
                entries: Vec::new(),
            },
            0,
            invocation.host_stack_pool_va,
        )
    } else {
        build_native_entry_gateway(
            gateway_va,
            entry_va,
            state_va,
            0,
            &layout,
            invocation.lane_control_va,
            invocation.lane_group_stride as u64,
            invocation.host_stack_pool_va,
        )
    }
    .unwrap();
    assert!(gateway_offset + gateway.len() <= state_offset);
    arena.bytes()[gateway_offset..gateway_offset + gateway.len()].copy_from_slice(&gateway);

    // SysV test caller supplies Win64 shadow space and known preserved registers
    let prefix = [
        Instruction::with1(Code::Push_r64, Register::RBX).unwrap(),
        Instruction::with2(Code::Sub_rm64_imm8, Register::RSP, 0x20).unwrap(),
        Instruction::with2(Code::Mov_r64_imm64, Register::RBX, NONVOLATILE).unwrap(),
        Instruction::with2(Code::Mov_r64_imm64, Register::RAX, VECTOR_NONVOLATILE).unwrap(),
        Instruction::with2(Code::Movq_xmm_rm64, Register::XMM6, Register::RAX).unwrap(),
        Instruction::with2(Code::Movq_xmm_rm64, Register::XMM15, Register::RAX).unwrap(),
        Instruction::with_branch(Code::Call_rel32_64, gateway_va).unwrap(),
    ];
    let return_offset = put_code(&mut arena, 0, &prefix);
    let return_va = (arena.base + return_offset) as u64;
    let mut continuation =
        vec![Instruction::with2(Code::Mov_r64_imm64, Register::R11, results_va).unwrap()];
    for (offset, register, code) in [
        (8, Register::RAX, Code::Mov_rm64_r64),
        (16, Register::RDX, Code::Mov_rm64_r64),
        (24, Register::XMM0, Code::Movq_rm64_xmm),
        (32, Register::RBX, Code::Mov_rm64_r64),
        (40, Register::XMM6, Code::Movq_rm64_xmm),
        (48, Register::XMM15, Code::Movq_rm64_xmm),
    ] {
        continuation.push(
            Instruction::with2(
                code,
                MemoryOperand::with_base_displ_size(Register::R11, offset, 8),
                register,
            )
            .unwrap(),
        );
    }
    continuation.extend([
        Instruction::with2(Code::Add_rm64_imm8, Register::RSP, 0x20).unwrap(),
        Instruction::with1(Code::Pop_r64, Register::RBX).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    assert!(
        return_offset + put_code(&mut arena, return_offset, &continuation) < wrong_return_offset
    );

    // A wrong RET remains observable without crashing the test process
    put_code(
        &mut arena,
        wrong_return_offset,
        &[
            Instruction::with2(Code::Mov_r64_imm64, Register::R11, results_va).unwrap(),
            Instruction::with2(
                Code::Mov_rm64_imm32,
                MemoryOperand::with_base(Register::R11),
                1,
            )
            .unwrap(),
            Instruction::with_branch(Code::Jmp_rel32_64, return_va).unwrap(),
        ],
    );
    let mut callee = vec![Instruction::with2(
        Code::Mov_r64_rm64,
        Register::R11,
        MemoryOperand::with_base_displ_size(Register::RDX, layout.vregs[4] as i64, 8),
    )
    .unwrap()];
    if overwrite {
        // A VM-to-native tail bridge leaves its CALL continuation in this slot
        callee.extend([
            Instruction::with2(Code::Mov_r64_imm64, Register::R10, wrong_return_va).unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base(Register::R11),
                Register::R10,
            )
            .unwrap(),
        ]);
    }
    for (offset, value) in [
        (layout.vregs[0], RESULT),
        (layout.vregs[2], SECOND_RESULT),
        (layout.xmm, VECTOR_RESULT),
    ] {
        callee.extend([
            Instruction::with2(Code::Mov_r64_imm64, Register::R10, value).unwrap(),
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ_size(Register::RDX, offset as i64, 8),
                Register::R10,
            )
            .unwrap(),
        ]);
    }
    callee.extend([
        Instruction::with2(Code::Mov_r64_imm64, Register::RAX, VECTOR_RESULT).unwrap(),
        Instruction::with2(Code::Movq_xmm_rm64, Register::XMM0, Register::RAX).unwrap(),
        Instruction::with2(Code::Mov_r64_imm64, Register::RAX, RESULT).unwrap(),
        Instruction::with2(Code::Mov_r64_imm64, Register::RDX, SECOND_RESULT).unwrap(),
    ]);
    if !canonical {
        callee.extend([
            Instruction::with2(Code::Xor_rm64_r64, Register::RBX, Register::RBX).unwrap(),
            Instruction::with2(Code::Pxor_xmm_xmmm128, Register::XMM6, Register::XMM6).unwrap(),
            Instruction::with2(Code::Pxor_xmm_xmmm128, Register::XMM15, Register::XMM15).unwrap(),
            Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RAX).unwrap(),
            Instruction::with2(Code::Xor_rm64_r64, Register::RDX, Register::RDX).unwrap(),
            Instruction::with2(Code::Pxor_xmm_xmmm128, Register::XMM0, Register::XMM0).unwrap(),
        ]);
    }
    callee.push(Instruction::with(Code::Retnq));
    assert!(entry_offset + put_code(&mut arena, entry_offset, &callee) < results_offset);
    run_with_windows_teb(&arena);
    let observed: Vec<u64> = arena.bytes()[results_offset..results_offset + 56]
        .chunks_exact(8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        .collect();
    assert_eq!(
        observed,
        [
            0,
            RESULT,
            SECOND_RESULT,
            VECTOR_RESULT,
            NONVOLATILE,
            VECTOR_NONVOLATILE,
            VECTOR_NONVOLATILE,
        ],
        "canonical={canonical}, seed={seed}, overwrite={overwrite}"
    );
    let bitmap_offset = (invocation.lane_control_va - arena.base as u64) as usize;
    assert!(
        arena.bytes()[bitmap_offset..bitmap_offset + VM_LANE_CONTROL_SIZE]
            .iter()
            .all(|byte| *byte == 0),
        "native root must be released"
    );
}

#[test]
fn native_gateway_preserves_return_identity_when_guest_slot_changes() {
    for seed in [7, 11] {
        for overwrite in [false, true] {
            check_gateway_return(false, seed, overwrite);
        }
    }
}

#[test]
fn canonical_gateway_preserves_return_identity_when_guest_slot_changes() {
    for seed in [7, 11] {
        for overwrite in [false, true] {
            check_gateway_return(true, seed, overwrite);
        }
    }
}
