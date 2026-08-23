use std::collections::HashMap;

use super::eval::{MemoryPolicy, MemoryRegion, VmFault, VmFaultKind};
use super::{MicroInstr, MicroOperand, RiscEvalState, RiscOp, RiscProgram};

/// Common assertion boundary for evaluator/poly/threaded fault parity tests.
/// Keeping category, guest location, and pre-commit state together prevents a
/// backend from treating the right fault at the wrong instruction as parity.
fn assert_fault(
    result: Result<RiscEvalState, VmFault>,
    expected_kind: VmFaultKind,
    expected_vip: usize,
    expected_rip: Option<u64>,
) -> RiscEvalState {
    let fault = result.expect_err("program must produce a guest-visible fault");
    assert_eq!(fault.kind, expected_kind, "fault category");
    assert_eq!(fault.vip, expected_vip, "faulting micro-instruction");
    assert_eq!(fault.guest_rip, expected_rip, "faulting guest RIP");
    fault.state
}

fn mapped_program(instrs: Vec<MicroInstr>, fault_vip: usize, rip: u64) -> RiscProgram {
    RiscProgram::with_ip_map(instrs, HashMap::from([(rip, fault_vip)]))
}

#[test]
fn trap_reports_location_and_preserves_pre_fault_state() {
    let rip = 0x1400_01000;
    let program = mapped_program(
        vec![
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::VReg(0))
                .with_src1(MicroOperand::Imm64(0x1234)),
            MicroInstr::new(RiscOp::Trap),
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::VReg(0))
                .with_src1(MicroOperand::Imm64(0xDEAD)),
        ],
        1,
        rip,
    );

    let state = assert_fault(
        program.try_eval_state(&[0; 16]),
        VmFaultKind::Trap,
        1,
        Some(rip),
    );
    assert_eq!(state.regs[0], 0x1234, "prior instruction remains committed");
}

#[test]
fn divide_faults_are_typed_and_fault_before_commit() {
    for (name, divisor, ax, expected) in [
        ("zero", 0, 0x55, VmFaultKind::DivideByZero),
        ("quotient overflow", 1, 0x100, VmFaultKind::QuotientOverflow),
    ] {
        let program = RiscProgram::new(vec![
            MicroInstr::new(RiscOp::Divide {
                signed: false,
                width: 1,
            })
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::Imm64(divisor)),
            MicroInstr::new(RiscOp::Halt),
        ]);
        let mut regs = [0u64; 16];
        regs[0] = ax;
        regs[2] = 0x2222;
        regs[3] = 0x3333;

        let state = assert_fault(program.try_eval_state(&regs), expected, 0, None);
        assert_eq!(state.regs, regs, "{name}: divide must not partially commit");
    }
}

#[test]
fn unknown_indirect_route_is_not_a_normal_halt() {
    let target = 0x1800_0BAD;
    let program = RiscProgram::with_ip_map(
        vec![MicroInstr::new(RiscOp::VirtualIndirectJump).with_src1(MicroOperand::Imm64(target))],
        HashMap::new(),
    );

    let state = assert_fault(
        program.try_eval_state(&[0; 16]),
        VmFaultKind::UnknownIndirectRoute { target },
        0,
        None,
    );
    assert_eq!(state, RiscEvalState::default());
}

fn region(start: u64, len: u64, readable: bool, writable: bool) -> MemoryPolicy {
    MemoryPolicy::new(vec![MemoryRegion {
        start,
        len,
        readable,
        writable,
    }])
}

fn memory_program(op: RiscOp, address: u64) -> RiscProgram {
    RiscProgram::new(vec![
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::Imm64(0xCAFE)),
        MicroInstr::new(op)
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::Imm64(address))
            .with_src2(MicroOperand::Imm64(0x8877_6655_4433_2211)),
        MicroInstr::new(RiscOp::Halt),
    ])
}

#[test]
fn checked_memory_read_out_of_range_faults_before_destination_commit() {
    let address = 0x200f;
    let program = memory_program(RiscOp::MemoryRead { width: 2 }, address);
    let policy = region(0x2000, 0x10, true, true);
    let seed = HashMap::from([(address, 0xAA)]);

    let state = assert_fault(
        program.try_eval_state_with_mem_policy(&[0; 16], seed.clone(), &policy),
        VmFaultKind::MemoryAccess {
            address,
            width: 2,
            write: false,
        },
        1,
        None,
    );
    assert_eq!(state.regs[3], 0xCAFE, "failed read must not commit dst");
    assert_eq!(state.mem, seed, "failed read must not mutate memory");
}

#[test]
fn checked_memory_write_out_of_range_and_readonly_share_typed_taxonomy() {
    for (name, address, policy) in [
        ("out of range", 0x300f, region(0x3000, 0x10, true, true)),
        ("read only", 0x3008, region(0x3000, 0x10, true, false)),
    ] {
        let program = memory_program(RiscOp::MemoryWrite { width: 2 }, address);
        let seed = HashMap::from([(address, 0x5A), (address + 1, 0xA5)]);
        let state = assert_fault(
            program.try_eval_state_with_mem_policy(&[0; 16], seed.clone(), &policy),
            VmFaultKind::MemoryAccess {
                address,
                width: 2,
                write: true,
            },
            1,
            None,
        );
        assert_eq!(
            state.mem, seed,
            "{name}: failed write must be all-or-nothing"
        );
        assert_eq!(
            state.regs[3], 0xCAFE,
            "{name}: prior state remains committed"
        );
    }
}

#[test]
fn checked_memory_address_overflow_is_a_memory_fault_not_a_wraparound() {
    let address = u64::MAX - 3;
    let program = memory_program(RiscOp::MemoryWrite { width: 8 }, address);
    let policy = region(u64::MAX - 15, 15, true, true);
    let seed = HashMap::from([(address, 0x5A)]);

    let state = assert_fault(
        program.try_eval_state_with_mem_policy(&[0; 16], seed.clone(), &policy),
        VmFaultKind::MemoryAccess {
            address,
            width: 8,
            write: true,
        },
        1,
        None,
    );
    assert_eq!(
        state.mem, seed,
        "overflowing access must not partially write"
    );
    assert!(
        !state.mem.contains_key(&0),
        "address arithmetic must not wrap"
    );
}

#[test]
fn checked_memory_exact_region_boundary_is_permitted() {
    let address = 0x4008;
    let program = memory_program(RiscOp::MemoryWrite { width: 8 }, address);
    let policy = region(0x4000, 0x10, true, true);
    let state = program
        .try_eval_state_with_mem_policy(&[0; 16], HashMap::new(), &policy)
        .expect("access ending exactly at the exclusive region boundary is valid");

    assert_eq!(state.mem.get(&0x4008), Some(&0x11));
    assert_eq!(state.mem.get(&0x400f), Some(&0x88));
}
