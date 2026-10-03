//! Architecture lowering happens before encoding, independently of opcode maps.
use super::VmArchitectureFamily;
use crate::vm::risc::{MicroInstr as I, MicroOperand as O, RiscOp, RiscProgram};
use anyhow::{ensure, Result};
use std::collections::HashMap;

// Independent of guest RSP, invocation routing, chunk keys and PRF mask state.
pub const STACK_DEPTH: i64 = 0x5B00;
pub const STACK_BASE: i64 = 0x5B10;
pub const STACK_CAPACITY: usize = 16;
pub const ACCUMULATORS: i64 = 0x5C00;
pub const SPLIT_STATUS: i64 = 0x5C10;
pub const SPLIT_CONTROL: i64 = 0x5C18;
pub const PRODUCER_TOKEN: i64 = 0x5C20;
pub const STATE_END: usize = 0x5C28;
pub const LOWERING_ABI: u32 = 2;

pub struct LoweredProgram {
    pub program: RiscProgram,
    /// Each canonical instruction maps to its first architecture instruction.
    pub canonical_entries: Vec<usize>,
}
fn mov(dst: Option<O>, source: O) -> I {
    I {
        op: RiscOp::Mov,
        dst,
        src1: Some(source),
        src2: None,
        imm: 0,
    }
}
fn scalar(op: RiscOp) -> bool {
    matches!(
        op,
        RiscOp::Nor
            | RiscOp::AddWithCarry
            | RiscOp::ShiftLeft
            | RiscOp::ShiftRight
            | RiscOp::ArithmeticShiftRight
            | RiscOp::RotateLeft { .. }
            | RiscOp::Add { .. }
            | RiscOp::SubWithBorrow { .. }
            | RiscOp::Adc { .. }
            | RiscOp::Sbb { .. }
            | RiscOp::Inc { .. }
            | RiscOp::Dec { .. }
            | RiscOp::Not { .. }
            | RiscOp::BSwap { .. }
            | RiscOp::CountTrailingZeros { .. }
            | RiscOp::CountLeadingZeros { .. }
            | RiscOp::PopCount
    )
}

pub fn lower(source: &RiscProgram, family: VmArchitectureFamily) -> Result<LoweredProgram> {
    let mut instrs = Vec::new();
    let mut entries = Vec::with_capacity(source.instrs.len());
    for instruction in &source.instrs {
        entries.push(instrs.len());
        for operand in [instruction.dst, instruction.src1, instruction.src2]
            .into_iter()
            .flatten()
        {
            ensure!(
                !matches!(
                    operand,
                    O::StackPush | O::StackPop | O::StackPeek(_) | O::Accumulator(_)
                ),
                "family lowering requires canonical source operands"
            );
        }
        if matches!(
            instruction.op,
            RiscOp::Mov | RiscOp::MemoryRead { .. } | RiscOp::MemoryWrite { .. }
        ) && instruction.src1.is_some()
        {
            let a = instruction.src1.unwrap();
            let b = instruction.src2.unwrap_or(O::Imm64(0));
            let write = matches!(instruction.op, RiscOp::MemoryWrite { .. });
            match family {
                VmArchitectureFamily::Stack => {
                    if write {
                        instrs.push(mov(Some(O::StackPush), b));
                    }
                    instrs.push(mov(Some(O::StackPush), a));
                    if instruction.op != RiscOp::Mov {
                        let mut op = instruction.clone();
                        op.dst = if write { None } else { Some(O::StackPeek(0)) };
                        op.src1 = Some(O::StackPeek(0));
                        op.src2 = if write { Some(O::StackPeek(1)) } else { None };
                        instrs.push(op);
                    }
                    instrs.push(mov(if write { None } else { instruction.dst }, O::StackPop));
                    if write {
                        instrs.push(mov(None, O::StackPop));
                    }
                }
                VmArchitectureFamily::MixedRisc => {
                    instrs.push(mov(Some(O::Accumulator(0)), a));
                    if write {
                        instrs.push(mov(Some(O::Accumulator(1)), b));
                    }
                    if instruction.op != RiscOp::Mov {
                        let mut op = instruction.clone();
                        op.dst = if write { None } else { Some(O::Accumulator(0)) };
                        op.src1 = Some(O::Accumulator(0));
                        op.src2 = if write { Some(O::Accumulator(1)) } else { None };
                        instrs.push(op);
                    }
                    if !write {
                        instrs.push(mov(instruction.dst, O::Accumulator(0)));
                    }
                }
                _ => instrs.push(instruction.clone()),
            }
            continue;
        }
        if !scalar(instruction.op) || instruction.src1.is_none() {
            // Memory, vector, host and control operations retain the canonical
            // guest ABI. Internal stack/accumulators are empty at these boundaries.
            instrs.push(instruction.clone());
            continue;
        }
        let a = instruction.src1.unwrap();
        let b = instruction.src2.unwrap_or(O::Imm64(0));
        match family {
            VmArchitectureFamily::Stack => {
                instrs.push(mov(Some(O::StackPush), b));
                instrs.push(mov(Some(O::StackPush), a));
                let mut op = instruction.clone();
                op.dst = Some(O::StackPeek(0));
                op.src1 = Some(O::StackPeek(0));
                op.src2 = instruction.src2.map(|_| O::StackPeek(1));
                instrs.push(op);
                instrs.push(mov(instruction.dst, O::StackPop));
                instrs.push(mov(None, O::StackPop));
            }
            VmArchitectureFamily::MixedRisc => {
                instrs.push(mov(Some(O::Accumulator(0)), a));
                if instruction.src2.is_some() {
                    instrs.push(mov(Some(O::Accumulator(1)), b));
                }
                let mut op = instruction.clone();
                op.dst = Some(O::Accumulator(0));
                op.src1 = Some(O::Accumulator(0));
                op.src2 = instruction.src2.map(|_| O::Accumulator(1));
                instrs.push(op);
                instrs.push(mov(instruction.dst, O::Accumulator(0)));
            }
            VmArchitectureFamily::Register | VmArchitectureFamily::FusedCisc => {
                instrs.push(instruction.clone())
            }
        }
    }
    // Index branches and source-IP routes must agree with expanded instruction
    // positions; branches carrying original VAs keep their typed source identity.
    for instruction in &mut instrs {
        if matches!(instruction.op, RiscOp::VirtualBranch { .. })
            && instruction.src1.is_none()
            && !source
                .ip_map()
                .map_or(false, |map| map.contains_key(&instruction.imm))
        {
            let target = instruction.imm as usize;
            if let Some(&entry) = entries.get(target) {
                instruction.imm = entry as u64;
            }
        }
    }
    let routes: HashMap<_, _> = source
        .ip_map()
        .into_iter()
        .flatten()
        .map(|(&ip, &index)| entries.get(index).copied().map(|entry| (ip, entry)))
        .collect::<Option<_>>()
        .ok_or_else(|| anyhow::anyhow!("family source route outside canonical program"))?;
    Ok(LoweredProgram {
        program: RiscProgram::with_ip_map(instrs, routes),
        canonical_entries: entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::poly::{PolymorphicEncoder, PolymorphicInterpreter};
    #[test]
    fn independent_scalar_lowerings_match_reference_and_native() {
        let source = RiscProgram::new(vec![
            I::new(RiscOp::Mov)
                .with_dst(O::VReg(0))
                .with_src1(O::Imm64(0xFFFF_FFFF_FFFF_FF00)),
            I::new(RiscOp::Mov)
                .with_dst(O::Temp(7))
                .with_src1(O::Imm64(0xA537)),
            I::new(RiscOp::Add { width: 8 })
                .with_dst(O::VReg(1))
                .with_src1(O::VReg(0))
                .with_src2(O::Temp(7)),
            I::new(RiscOp::SubWithBorrow { width: 4 })
                .with_dst(O::Temp(7))
                .with_src1(O::VReg(1))
                .with_src2(O::Imm64(0x9000)),
            I::new(RiscOp::Nor)
                .with_dst(O::VReg(2))
                .with_src1(O::Temp(7))
                .with_src2(O::VReg(0)),
            I::new(RiscOp::RotateLeft { width: 2 })
                .with_dst(O::VReg(3))
                .with_src1(O::VReg(2))
                .with_src2(O::Imm64(3)),
            I::new(RiscOp::Mov)
                .with_dst(O::VReg(0))
                .with_src1(O::VReg(3)),
            I::new(RiscOp::Halt),
        ]);
        let expected = source.eval_state(&[0; 16]);
        let mut lengths = Vec::new();
        for family in VmArchitectureFamily::ALL {
            let lowered = lower(&source, family).unwrap();
            lengths.push(lowered.program.instrs.len());
            let seed = 0xF412;
            let bytecode = PolymorphicEncoder::new_for_family(seed, family)
                .encode(&lowered.program)
                .unwrap();
            let mut interpreter = PolymorphicInterpreter::new_for_family(seed, family);
            interpreter.run(&bytecode).unwrap();
            assert_eq!(interpreter.regs, expected.regs, "{family:?}");
            assert_eq!(interpreter.temps, expected.temps, "{family:?}");
            assert_eq!(
                interpreter.flags.raw & 0x8D5,
                expected.flags & 0x8D5,
                "{family:?}"
            );
            assert!(interpreter.operand_stack.is_empty());
            let native = crate::vm::threaded::poly_direct::run_native_poly_direct_for_family(
                &bytecode, seed, family, &[0; 16], None,
            )
            .unwrap();
            assert_eq!(native.regs, expected.regs, "native {family:?}");
            assert_eq!(native.temps, expected.temps, "native {family:?}");
            assert_eq!(
                native.flags & 0x8D5,
                expected.flags & 0x8D5,
                "native {family:?}"
            );
        }
        assert!(lengths[0] > lengths[2] && lengths[2] > lengths[1]);
    }

    #[test]
    fn lowered_width_flags_and_backward_branches_match_native() {
        use crate::vm::risc::BranchCondition as C;
        let source = RiscProgram::new(vec![
            I::new(RiscOp::Mov)
                .with_dst(O::VReg(0))
                .with_src1(O::Imm64(0)),
            I::new(RiscOp::Mov)
                .with_dst(O::VReg(1))
                .with_src1(O::Imm64(13)),
            I::new(RiscOp::Add { width: 4 })
                .with_dst(O::VReg(0))
                .with_src1(O::VReg(0))
                .with_src2(O::VReg(1)),
            I::new(RiscOp::Dec { width: 4 })
                .with_dst(O::VReg(1))
                .with_src1(O::VReg(1)),
            I::new(RiscOp::VirtualBranch { cond: C::NotZero }).with_imm(2),
            I::new(RiscOp::Halt),
        ]);
        let expected = source.eval_state(&[0; 16]);
        for family in VmArchitectureFamily::ALL {
            let lowered = lower(&source, family).unwrap();
            let bytecode = PolymorphicEncoder::new_for_family(93, family)
                .encode(&lowered.program)
                .unwrap();
            let mut interpreter = PolymorphicInterpreter::new_for_family(93, family);
            interpreter.run(&bytecode).unwrap();
            assert_eq!(interpreter.regs, expected.regs);
            let native = crate::vm::threaded::poly_direct::run_native_poly_direct_for_family(
                &bytecode, 93, family, &[0; 16], None,
            )
            .unwrap();
            assert_eq!(native.regs, expected.regs, "{family:?}");
            assert_eq!(native.flags & 0x8D5, expected.flags & 0x8D5, "{family:?}");
        }
    }

    #[test]
    fn fused_continuation_executes_actual_compound_records() {
        let seed = (0..1000)
            .find(|&seed| VmArchitectureFamily::for_build(seed) == VmArchitectureFamily::FusedCisc)
            .unwrap();
        let mut instrs = vec![mov(Some(O::VReg(0)), O::Imm64(0x121))];
        for _ in 0..4 {
            instrs.push(
                I::new(RiscOp::Nor)
                    .with_dst(O::VReg(1))
                    .with_src1(O::VReg(0))
                    .with_src2(O::Imm64(0xAF)),
            );
            instrs.push(
                I::new(RiscOp::ShiftRight)
                    .with_dst(O::VReg(0))
                    .with_src1(O::VReg(1))
                    .with_src2(O::Imm64(3)),
            );
        }
        instrs.push(I::new(RiscOp::Halt));
        let source = RiscProgram::new(instrs);
        let plan = super::super::VariantPlan::generate(
            [9; 32],
            seed,
            VmArchitectureFamily::FusedCisc,
            super::super::VariantPolicy::Stable,
        )
        .unwrap();
        let prepared=crate::vm::threaded::SuperOperatorSynthesizer::prepare_commercial_program_with_variant_plan(&source,&plan)
            .unwrap().expect("repeated sequence must fuse");
        assert!(!prepared.assigned.is_empty());
        assert!(prepared.rewritten_offsets.len() < source.instrs.len());
        let native = crate::vm::threaded::poly_direct::run_native_poly_direct_superops(
            &prepared.bytecode,
            &prepared.metadata,
            seed,
            &[0; 16],
            plan.runtime_layout().clone(),
            &prepared.assigned,
        )
        .unwrap();
        assert_eq!(native.regs, source.eval_state(&[0; 16]).regs);
    }

    #[test]
    fn family_memory_width_and_carry_results_match_canonical() {
        let mut operations = Vec::new();
        for width in [1, 2, 4, 8] {
            operations.extend([
                RiscOp::Add { width },
                RiscOp::SubWithBorrow { width },
                RiscOp::Adc { width },
                RiscOp::Sbb { width },
                RiscOp::Inc { width },
                RiscOp::Dec { width },
                RiscOp::Not { width },
                RiscOp::RotateLeft { width },
            ]);
        }
        operations.extend([
            RiscOp::Nor,
            RiscOp::AddWithCarry,
            RiscOp::ShiftLeft,
            RiscOp::ShiftRight,
            RiscOp::ArithmeticShiftRight,
        ]);
        let mut output = vec![0u8; operations.len() * 16];
        let address = output.as_mut_ptr() as u64;
        let mut instructions = Vec::new();
        for (index, operation) in operations.into_iter().enumerate() {
            let a = 0xFFFE_FFFF_FFFF_FF81u64.wrapping_add(index as u64 * 131);
            instructions.push(mov(Some(O::VReg(0)), O::Imm64(a)));
            instructions.push(mov(Some(O::VReg(1)), O::Imm64(3)));
            instructions.push(I::new(RiscOp::SetFlag).with_src1(O::Imm64(0x8D5)));
            let mut op = I::new(operation).with_dst(O::VReg(0)).with_src1(O::VReg(0));
            if !matches!(
                operation,
                RiscOp::Inc { .. } | RiscOp::Dec { .. } | RiscOp::Not { .. }
            ) {
                op.src2 = Some(O::VReg(1));
            }
            op.imm = 1;
            instructions.push(op);
            instructions.push(mov(Some(O::VReg(5)), O::Vflags));
            for (offset, register) in [(0, 0), (8, 5)] {
                instructions.push(
                    I::new(RiscOp::MemoryWrite { width: 8 })
                        .with_src1(O::Imm64(address + (index * 16 + offset) as u64))
                        .with_src2(O::VReg(register)),
                );
            }
            // Re-read a narrow memory result through each family's address model.
            instructions.push(
                I::new(RiscOp::MemoryRead { width: 1 })
                    .with_dst(O::Temp(7))
                    .with_src1(O::Imm64(address + index as u64 * 16)),
            );
        }
        instructions.push(I::new(RiscOp::Halt));
        let source = RiscProgram::new(instructions);
        let expected = source.eval_state(&[0; 16]);
        let bytes: Vec<_> = (0..output.len())
            .map(|i| expected.mem[&(address + i as u64)])
            .collect();
        for family in VmArchitectureFamily::ALL {
            output.fill(0);
            let lowered = lower(&source, family).unwrap();
            let bytecode = PolymorphicEncoder::new_for_family(173, family)
                .encode(&lowered.program)
                .unwrap();
            let mut interpreter = PolymorphicInterpreter::new_for_family(173, family);
            interpreter.run(&bytecode).unwrap();
            let interpreted: Vec<_> = (0..output.len())
                .map(|i| interpreter.mem[&(address + i as u64)])
                .collect();
            assert_eq!(interpreted, bytes, "reference {family:?}");
            let native = crate::vm::threaded::poly_direct::run_native_poly_direct_for_family(
                &bytecode, 173, family, &[0; 16], None,
            )
            .unwrap();
            for (index, (actual, expected)) in output
                .chunks_exact(16)
                .zip(bytes.chunks_exact(16))
                .enumerate()
            {
                assert_eq!(actual, expected, "native memory {family:?} case {index}");
            }
            assert_eq!(native.regs, expected.regs, "native regs {family:?}");
            assert_eq!(native.temps, expected.temps, "native temps {family:?}");
        }
    }
}
