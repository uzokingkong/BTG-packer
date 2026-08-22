// ==============================================================================
// BTG - Native Self-Decoding Dispatcher: tests - split from poly_direct.rs
// ==============================================================================

use super::*;
use crate::vm::arena::Arena;
use crate::vm::poly::{
    PolymorphicDecoder, PolymorphicEncoder, PolymorphicInterpreter, VirtualIsaSpec,
};
use crate::vm::risc::{
    BranchCondition, MicroInstr, MicroOperand, RiscDesynthesizer, RiscEvalState, RiscOp,
    RiscProgram,
};
use crate::vm::threaded::VmRuntimeLayout;
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction,
    InstructionBlock, MemoryOperand, Register,
};
use std::collections::HashMap;

fn install_operand_offsets(buf: &mut [u8], base: usize, offsets: &[u16]) {
    for (index, value) in offsets.iter().copied().enumerate() {
        buf[base + index * 2..base + index * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
}

#[test]
fn test_p2_9_chunk_lookup_hides_plain_boundaries_and_key_list() {
    use crate::vm::chunk_crypto::{chunk_key_from_module, module_key, BytecodeChunk};
    use crate::vm::table_layout::TableLayout;

    let seed = 0xB29D_4553_CAFE_1001;
    let mut encoder = PolymorphicEncoder::new(seed);
    let bytecode = encoder
        .encode(&RiscProgram::new(vec![MicroInstr::new(RiscOp::Halt)]))
        .unwrap();
    let chunks = vec![
        BytecodeChunk {
            offset: 0,
            len: 1,
            key: chunk_key_from_module(module_key(seed), 0),
        },
        BytecodeChunk {
            offset: 1,
            len: 1,
            key: chunk_key_from_module(module_key(seed), 1),
        },
        BytecodeChunk {
            offset: 2,
            len: bytecode.len().saturating_sub(2) as u32,
            key: chunk_key_from_module(module_key(seed), 2),
        },
    ];
    let parts = build_self_decoding_parts_with_superops_and_chunks(
        &bytecode,
        seed,
        0x100000,
        0x200000,
        0x300000,
        0x400000,
        0x500000,
        None,
        TableLayout::legacy(),
        VmRuntimeLayout::legacy(),
        &[],
        None,
        &chunks,
    )
    .unwrap();

    let mut decoder = Decoder::with_ip(64, &parts.code, 0x100000, DecoderOptions::NONE);
    while decoder.can_decode() {
        let ins = decoder.decode();
        assert!(
            !(ins.code() == Code::Cmp_rm64_imm32 && ins.op0_register() == Register::R12),
            "plaintext cmp VIP, boundary survived at {:#x}",
            ins.ip()
        );
    }
    for chunk in &chunks {
        assert!(
            !parts
                .code
                .windows(8)
                .any(|window| window == chunk.key.to_le_bytes()),
            "raw per-chunk key was embedded"
        );
    }
}

#[test]
fn test_p2_9_all_lookup_topologies_execute_outer_chunks_like_reference() {
    use crate::vm::chunk_crypto::{plan_chunks, ChunkLookupTopology};
    use std::collections::BTreeMap;

    let prog = RiscProgram::new(vec![
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::Imm64(0x1234_5678_9ABC_DEF0)),
        MicroInstr::new(RiscOp::AddWithCarry)
            .with_dst(MicroOperand::VReg(1))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::Imm64(0x1020_3040))
            .with_imm(0),
        MicroInstr::new(RiscOp::Nor)
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::VReg(1))
            .with_src2(MicroOperand::Imm64(0x55AA_55AA_55AA_55AA)),
        MicroInstr::new(RiscOp::Halt),
    ]);
    let reference = prog.eval_state(&[0u64; 16]);
    let mut seeds = BTreeMap::new();
    for seed in 1..=100u64 {
        seeds
            .entry(ChunkLookupTopology::from_seed(seed))
            .or_insert(seed);
        if seeds.len() == 3 {
            break;
        }
    }
    assert_eq!(seeds.len(), 3);

    for (topology, seed) in seeds {
        let mut encoder = PolymorphicEncoder::new(seed);
        let (bytecode, offsets) = encoder.encode_with_offsets(&prog).unwrap();
        let max_chunk = (bytecode.len() / 3).max(1);
        let chunks = plan_chunks(bytecode.len(), &offsets, seed, max_chunk);
        assert!(chunks.len() >= 2, "fixture did not split for {topology:?}");
        let native = run_native_poly_direct_chunks(&bytecode, seed, &[0u64; 16], &chunks).unwrap();
        assert_eq!(native.regs, reference.regs, "topology {topology:?}");
        assert_eq!(native.temps, reference.temps, "topology {topology:?}");
        assert_eq!(native.flags, reference.flags, "topology {topology:?}");
    }
}

#[test]
fn test_superop_extension_handler_is_registered_in_production_table() {
    use crate::vm::table_layout::TableLayout;
    use crate::vm::threaded::{
        AssignedSuperOp, SuperOpCandidate, SuperOpOccurrence, SuperOpPlan, VmRuntimeLayout,
    };

    let seed = 0x5A17_0F00_D123_4567;
    let prog = RiscProgram::new(vec![MicroInstr::new(RiscOp::Halt)]);
    let mut encoder = PolymorphicEncoder::new(seed);
    let bytecode = encoder.encode(&prog).unwrap();
    let spec = VirtualIsaSpec::from_seed(seed);
    let opcode = (u8::MIN..=u8::MAX)
        .find(|byte| !spec.reverse_opcode_map.contains_key(byte))
        .unwrap();
    let assigned = AssignedSuperOp {
        opcode,
        plan: SuperOpPlan {
            candidate: SuperOpCandidate {
                ops: vec![RiscOp::Nor, RiscOp::ShiftRight],
                occurrences: 1,
                first_index: 0,
                estimated_dispatch_savings: 1,
            },
            occurrences: vec![SuperOpOccurrence { start: 0, len: 2 }],
        },
    };
    let code_base = 0x100000;
    let parts = build_self_decoding_parts_with_superops(
        &bytecode,
        seed,
        code_base,
        0x200000,
        0x300000,
        0x400000,
        0x500000,
        None,
        TableLayout::legacy(),
        VmRuntimeLayout::legacy(),
        &[assigned],
        None,
    )
    .unwrap();
    let target = parts.table[opcode as usize] ^ per_op_key(parts.table_key, opcode);
    assert!((code_base..code_base + parts.code.len() as u64).contains(&target));

    let other_unused = (u8::MIN..=u8::MAX)
        .find(|byte| *byte != opcode && !spec.reverse_opcode_map.contains_key(byte))
        .unwrap();
    let trap = parts.table[other_unused as usize] ^ per_op_key(parts.table_key, other_unused);
    assert_ne!(
        target, trap,
        "extension opcode must not retain the trap handler"
    );
}

#[test]
fn test_native_superop_chain_matches_reference_execution() {
    use crate::vm::threaded::{
        SuperOpCandidate, SuperOpOccurrence, SuperOpPlan, SuperOperatorSynthesizer, VmRuntimeLayout,
    };
    let seed = 0x7E57_5A17_CAFE_1001;
    let instrs = vec![
        MicroInstr::new(RiscOp::Nor)
            .with_dst(MicroOperand::Temp(0))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::VReg(1)),
        MicroInstr::new(RiscOp::ShiftRight)
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::Temp(0))
            .with_src2(MicroOperand::Imm64(9)),
        MicroInstr::new(RiscOp::Halt),
    ];
    let prog = RiscProgram::new(instrs.clone());
    let plan = SuperOpPlan {
        candidate: SuperOpCandidate {
            ops: vec![RiscOp::Nor, RiscOp::ShiftRight],
            occurrences: 1,
            first_index: 0,
            estimated_dispatch_savings: 1,
        },
        occurrences: vec![SuperOpOccurrence { start: 0, len: 2 }],
    };
    let spec = VirtualIsaSpec::from_seed(seed);
    let assigned =
        SuperOperatorSynthesizer::assign_extension_opcodes(&spec, &[plan], seed).unwrap();
    let rewrite = SuperOperatorSynthesizer::rewrite_stream(&instrs, &assigned).unwrap();
    let mut fused_encoder = PolymorphicEncoder::new(seed);
    let (fused_bytecode, rewritten_offsets) =
        fused_encoder.encode_superop_rewrite(&rewrite).unwrap();
    let metadata = crate::vm::threaded::SuperOpBuildMetadata::from_rewrite(
        prog.clone(),
        &rewrite,
        &rewritten_offsets,
        fused_bytecode.len(),
    )
    .unwrap();

    let mut init = [0u64; 16];
    init[0] = 0x0123_4567_89AB_CDEF;
    init[1] = 0x1111_0000_FFFF_AAAA;
    let native = run_native_poly_direct_superops(
        &fused_bytecode,
        &metadata,
        seed,
        &init,
        VmRuntimeLayout::legacy(),
        &assigned,
    )
    .unwrap();
    let reference = prog.eval_state(&init);
    assert_eq!(native.regs, reference.regs);
    assert_eq!(native.temps, reference.temps);
    assert_eq!(native.flags, reference.flags);
}

#[test]
fn test_native_superop_branch_uses_rewritten_byte_offsets() {
    use crate::vm::threaded::{
        SuperOpBuildMetadata, SuperOpCandidate, SuperOpOccurrence, SuperOpPlan,
        SuperOperatorSynthesizer, VmRuntimeLayout,
    };
    let seed = 0xB12A_0C4F_5EED_2002;
    let instrs = vec![
        MicroInstr::new(RiscOp::Nor)
            .with_dst(MicroOperand::Temp(0))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::VReg(1)),
        MicroInstr::new(RiscOp::ShiftRight)
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::Temp(0))
            .with_src2(MicroOperand::Imm64(3)),
        MicroInstr::new(RiscOp::VirtualBranch {
            cond: BranchCondition::Always,
        })
        .with_imm(4),
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::Imm64(0xBAD)),
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::Imm64(0x600D)),
        MicroInstr::new(RiscOp::Halt),
    ];
    let prog = RiscProgram::new(instrs.clone());
    let plan = SuperOpPlan {
        candidate: SuperOpCandidate {
            ops: vec![RiscOp::Nor, RiscOp::ShiftRight],
            occurrences: 1,
            first_index: 0,
            estimated_dispatch_savings: 1,
        },
        occurrences: vec![SuperOpOccurrence { start: 0, len: 2 }],
    };
    let spec = VirtualIsaSpec::from_seed(seed);
    let assigned =
        SuperOperatorSynthesizer::assign_extension_opcodes(&spec, &[plan], seed).unwrap();
    let rewrite = SuperOperatorSynthesizer::rewrite_stream(&instrs, &assigned).unwrap();
    let mut encoder = PolymorphicEncoder::new(seed);
    let (bytecode, offsets) = encoder.encode_superop_rewrite(&rewrite).unwrap();
    let metadata =
        SuperOpBuildMetadata::from_rewrite(prog.clone(), &rewrite, &offsets, bytecode.len())
            .unwrap();
    assert_eq!(
        metadata.original_byte_offsets[0],
        metadata.original_byte_offsets[1]
    );
    assert_eq!(metadata.original_byte_offsets[4], offsets[3]);

    let mut init = [0u64; 16];
    init[0] = 0x1234_5678;
    init[1] = 0x0101_0101;
    let native = run_native_poly_direct_superops(
        &bytecode,
        &metadata,
        seed,
        &init,
        VmRuntimeLayout::legacy(),
        &assigned,
    )
    .unwrap();
    let reference = prog.eval_state(&init);
    assert_eq!(native.regs, reference.regs);
    assert_eq!(native.temps, reference.temps);
    assert_eq!(native.flags, reference.flags);
    assert_eq!(native.regs[3], 0x600D);
}

/// P2 (G3): 양-즉시 `AddWithCarry(Imm64, Imm64, cin=0)` — RIP-relative 주소
/// 계산(`lower_effective_address`의 `emit_add(temp, Imm64(abs), Imm64(0))`)이
/// 만드는 정확한 인코딩 패턴. 네이티브 self-decoding 런타임이 이 op의 바이트를
/// 인코더와 동일하게 소비하는지 차등 검증한다. (인터프리터/참조와 동치여야 함.)
#[test]
fn test_native_poly_direct_both_imm_addwithcarry_matches_reference() {
    let mut d = RiscDesynthesizer::new();
    // RIP-relative 주소 계산: AddWithCarry(Temp(4), Imm64(abs), Imm64(0), cin=0).
    d.instrs.push(
        MicroInstr::new(RiscOp::AddWithCarry)
            .with_dst(MicroOperand::Temp(4))
            .with_src1(MicroOperand::Imm64(0x14003F140))
            .with_src2(MicroOperand::Imm64(0))
            .with_imm(0),
    );
    // 결과를 레지스터로 (계산된 절대 주소가 보존되는지).
    d.instrs.push(
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::Temp(4)),
    );
    d.instrs.push(
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::VReg(1))
            .with_src1(MicroOperand::Imm64(0x2B992DDFA232)),
    );
    d.instrs.push(MicroInstr::new(RiscOp::Halt));
    let prog = RiscProgram::new(d.instrs);
    let init = [0u64; 16];

    for seed in [
        0x1122334455667788u64,
        0xDEADBEEFCAFE0001,
        0x123456789,
        0xBADF00D,
    ] {
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();

        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.run(&bytecode).unwrap();
        let ref_st = prog.eval_state(&init);

        assert_eq!(
            native.regs[0], 0x14003F140,
            "seed {seed:#x}: AddWithCarry(imm,imm) address"
        );
        assert_eq!(
            native.regs[1], 0x2B992DDFA232,
            "seed {seed:#x}: Mov(imm64) after two-imm op"
        );
        assert_eq!(
            native.regs, ref_st.regs,
            "seed {seed:#x}: native vs reference regs"
        );
        assert_eq!(
            interp.regs, ref_st.regs,
            "seed {seed:#x}: interpreter vs reference regs"
        );
    }
}

#[test]
fn test_adc_sbb_native_poly_and_reference_are_identical() {
    use crate::vm::risc::flags::VFLAG_CF;
    let prog = RiscProgram::new(vec![
        MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(VFLAG_CF)),
        MicroInstr::new(RiscOp::Adc { width: 1 })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::Imm64(0)),
        MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(VFLAG_CF)),
        MicroInstr::new(RiscOp::Sbb { width: 4 })
            .with_dst(MicroOperand::VReg(1))
            .with_src1(MicroOperand::VReg(1))
            .with_src2(MicroOperand::Imm64(0)),
        MicroInstr::new(RiscOp::Halt),
    ]);
    let mut init = [0u64; 16];
    init[0] = 0xFF;
    init[1] = 0x8000_0000;
    let reference = prog.eval_state(&init);
    assert_eq!(reference.regs[0], 0);
    assert_eq!(reference.regs[1], 0x7FFF_FFFF);

    for seed in [0xADC5_BB01u64, 0xADC5_BB02] {
        let mut encoder = PolymorphicEncoder::new(seed);
        let bytecode = encoder.encode(&prog).unwrap();
        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.regs = init;
        interp.run(&bytecode).unwrap();
        assert_eq!(native.regs, reference.regs, "native regs seed={seed:#x}");
        assert_eq!(native.flags, reference.flags, "native flags seed={seed:#x}");
        assert_eq!(interp.regs, reference.regs, "poly regs seed={seed:#x}");
        assert_eq!(
            interp.flags.raw, reference.flags,
            "poly flags seed={seed:#x}"
        );
    }
}

#[test]
fn test_rotate_left_native_poly_and_reference_are_identical() {
    let prog = RiscProgram::new(vec![
        MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8D5)),
        MicroInstr::new(RiscOp::RotateLeft { width: 1 })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::Imm64(1)),
        MicroInstr::new(RiscOp::RotateLeft { width: 8 })
            .with_dst(MicroOperand::VReg(1))
            .with_src1(MicroOperand::VReg(1))
            .with_src2(MicroOperand::VReg(2)),
        MicroInstr::new(RiscOp::Halt),
    ]);
    let mut init = [0u64; 16];
    init[0] = 0x81;
    init[1] = 0x8000_0000_0000_0001;
    init[2] = 1;
    let reference = prog.eval_state(&init);
    for seed in [0x7010_0001u64, 0x7010_0002] {
        let mut encoder = PolymorphicEncoder::new(seed);
        let bytecode = encoder.encode(&prog).unwrap();
        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.regs = init;
        interp.run(&bytecode).unwrap();
        assert_eq!(native.regs, reference.regs, "native regs seed={seed:#x}");
        assert_eq!(native.flags, reference.flags, "native flags seed={seed:#x}");
        assert_eq!(interp.regs, reference.regs, "poly regs seed={seed:#x}");
        assert_eq!(
            interp.flags.raw, reference.flags,
            "poly flags seed={seed:#x}"
        );
    }
}

#[test]
fn test_synthetic_xmm_window_maps_to_native_state_storage() {
    const XMM3: u64 = 0xF000_0000_0000_0030;
    let prog = RiscProgram::new(vec![
        MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
            .with_src1(MicroOperand::Imm64(XMM3))
            .with_src2(MicroOperand::Imm64(0x1122_3344_5566_7788)),
        MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
            .with_src1(MicroOperand::Imm64(XMM3 + 8))
            .with_src2(MicroOperand::Imm64(0x99AA_BBCC_DDEE_FF00)),
        MicroInstr::new(RiscOp::MemoryRead { width: 8 })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::Imm64(XMM3)),
        MicroInstr::new(RiscOp::MemoryRead { width: 8 })
            .with_dst(MicroOperand::VReg(1))
            .with_src1(MicroOperand::Imm64(XMM3 + 8)),
        MicroInstr::new(RiscOp::Halt),
    ]);
    let init = [0u64; 16];
    let reference = prog.eval_state(&init);
    for seed in [0x5EE0_0001u64, 0x5EE0_0002] {
        let mut encoder = PolymorphicEncoder::new(seed);
        let bytecode = encoder.encode(&prog).unwrap();
        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
        assert_eq!(native.regs, reference.regs, "seed={seed:#x}");
    }
}

#[test]
fn test_packed_sse_native_poly_and_reference_are_identical() {
    const XMM0: u64 = 0xF000_0000_0000_0000;
    const XMM1: u64 = XMM0 + 16;
    let prog = RiscProgram::new(vec![
        MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8D5)),
        MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
            .with_src1(MicroOperand::Imm64(XMM0))
            .with_src2(MicroOperand::Imm64(0x0004_0003_0002_0001)),
        MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
            .with_src1(MicroOperand::Imm64(XMM0 + 8))
            .with_src2(MicroOperand::Imm64(0x0008_0007_0006_0005)),
        MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
            .with_src1(MicroOperand::Imm64(XMM1))
            .with_src2(MicroOperand::Imm64(0x0001_0001_0001_0001)),
        MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
            .with_src1(MicroOperand::Imm64(XMM1 + 8))
            .with_src2(MicroOperand::Imm64(0x0001_0001_0001_0001)),
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::Temp(4))
            .with_src1(MicroOperand::Imm64(XMM0)),
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::Temp(5))
            .with_src1(MicroOperand::Imm64(XMM1)),
        // Consecutive packed instructions are intentional: they catch any
        // handler that corrupts R8 (the encrypted bytecode base) before the
        // next dispatch.
        MicroInstr::new(RiscOp::PackedAdd {
            elem_width: 2,
            lanes: 8,
        })
        .with_dst(MicroOperand::Temp(4))
        .with_src1(MicroOperand::Temp(4))
        .with_src2(MicroOperand::Temp(5)),
        MicroInstr::new(RiscOp::PackedCmpEq {
            elem_width: 2,
            lanes: 8,
        })
        .with_dst(MicroOperand::Temp(5))
        .with_src1(MicroOperand::Temp(4))
        .with_src2(MicroOperand::Temp(5)),
        MicroInstr::new(RiscOp::PackedCmpGt {
            elem_width: 2,
            lanes: 8,
        })
        .with_dst(MicroOperand::Temp(5))
        .with_src1(MicroOperand::Temp(4))
        .with_src2(MicroOperand::Temp(5)),
        MicroInstr::new(RiscOp::PackedUnpack {
            elem_width: 1,
            high: false,
        })
        .with_dst(MicroOperand::Temp(4))
        .with_src1(MicroOperand::Temp(4))
        .with_src2(MicroOperand::Temp(5)),
        MicroInstr::new(RiscOp::PackedShuffle { low_words: false })
            .with_dst(MicroOperand::Temp(4))
            .with_src1(MicroOperand::Temp(4))
            .with_src2(MicroOperand::Imm64(0b00_01_10_11)),
        MicroInstr::new(RiscOp::PackedShuffle { low_words: true })
            .with_dst(MicroOperand::Temp(5))
            .with_src1(MicroOperand::Temp(4))
            .with_src2(MicroOperand::Imm64(0b11_10_01_00)),
        MicroInstr::new(RiscOp::PackedShiftRightQ)
            .with_dst(MicroOperand::Temp(4))
            .with_src1(MicroOperand::Temp(4))
            .with_src2(MicroOperand::Imm64(4)),
        MicroInstr::new(RiscOp::PackedXor)
            .with_dst(MicroOperand::Temp(4))
            .with_src1(MicroOperand::Temp(4))
            .with_src2(MicroOperand::Temp(5)),
        MicroInstr::new(RiscOp::MemoryRead { width: 8 })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::Imm64(XMM0)),
        MicroInstr::new(RiscOp::MemoryRead { width: 8 })
            .with_dst(MicroOperand::VReg(1))
            .with_src1(MicroOperand::Imm64(XMM0 + 8)),
        MicroInstr::new(RiscOp::MemoryRead { width: 8 })
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::Imm64(XMM1)),
        MicroInstr::new(RiscOp::MemoryRead { width: 8 })
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::Imm64(XMM1 + 8)),
        MicroInstr::new(RiscOp::Halt),
    ]);
    let init = [0u64; 16];
    let reference = prog.eval_state(&init);
    for seed in [0x5E00_1001u64, 0x5E00_1002] {
        let mut encoder = PolymorphicEncoder::new(seed);
        let bytecode = encoder.encode(&prog).unwrap();
        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.run(&bytecode).unwrap();
        assert_eq!(
            &native.regs[..4],
            &reference.regs[..4],
            "native seed={seed:#x}"
        );
        assert_eq!(
            &interp.regs[..4],
            &reference.regs[..4],
            "poly seed={seed:#x}"
        );
        assert_eq!(
            native.flags, 0x8D5,
            "packed ops preserve flags seed={seed:#x}"
        );
        assert_eq!(interp.flags.raw, 0x8D5, "poly flags seed={seed:#x}");
    }
}

#[test]
fn test_shld_native_poly_and_reference_are_identical() {
    let prog = RiscProgram::new(vec![
        MicroInstr::new(RiscOp::DoubleShiftLeft { width: 8 })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::VReg(1))
            .with_src2(MicroOperand::Imm64(32)),
        MicroInstr::new(RiscOp::Halt),
    ]);
    let mut init = [0u64; 16];
    init[0] = 0x0123_4567_89AB_CDEF;
    init[1] = 0xFEDC_BA98_7654_3210;
    let reference = prog.eval_state(&init);
    for seed in [0x5A1D_0001u64, 0x5A1D_0002] {
        let mut encoder = PolymorphicEncoder::new(seed);
        let bytecode = encoder.encode(&prog).unwrap();
        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.regs = init;
        interp.run(&bytecode).unwrap();
        assert_eq!(native.regs[0], reference.regs[0], "native seed={seed:#x}");
        assert_eq!(interp.regs[0], reference.regs[0], "poly seed={seed:#x}");
        assert_eq!(native.flags, reference.flags, "native flags seed={seed:#x}");
    }
}

#[test]
fn test_seeded_runtime_layout_executes_like_legacy() {
    let seed = 0xA17E_5EED_CAFE_BABEu64;
    let prog = RiscProgram::new(vec![
        MicroInstr::new(RiscOp::Add { width: 8 })
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(1))
            .with_src2(MicroOperand::Imm64(0x1234)),
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::Temp(2))
            .with_src1(MicroOperand::VReg(3)),
        MicroInstr::new(RiscOp::Mov)
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::Temp(2)),
        MicroInstr::new(RiscOp::Halt),
    ]);
    let mut init = [0u64; 16];
    init[1] = 0x5555_AAAA_0000_1111;
    let mut enc = PolymorphicEncoder::new(seed);
    let bytecode = enc.encode(&prog).unwrap();
    let legacy = run_native_poly_direct(&bytecode, seed, &init).unwrap();
    let seeded = run_native_poly_direct_with_layout(
        &bytecode,
        seed,
        &init,
        None,
        crate::vm::threaded::VmRuntimeLayout::from_seed(seed),
    )
    .unwrap();
    assert_eq!(seeded.regs, legacy.regs);
    assert_eq!(seeded.temps, legacy.temps);
    assert_eq!(seeded.flags, legacy.flags);
}

/// The stage-14 file checksum shape: byte load, XOR with the running hash,
/// 64-bit two-operand IMUL, then pointer increment.  This executes against
/// real host memory so it covers the native MemoryRead{1} and MultiplyLow
/// handlers together rather than only the symbolic evaluator.
#[test]
fn test_native_poly_direct_fnv_byte_walk_matches_host_arithmetic() {
    let bytes = Box::new([0x00u8, 0xA5, 0x7F, 0xFF, 0x42, 0x11, 0x80, 0x5C]);
    let mut init = [0u64; 16];
    init[0] = bytes.as_ptr() as u64; // RAX: current byte
    init[2] = 0x0000_0100_0000_01B3; // RDX: FNV prime
    init[6] = 0xCBF2_9CE4_8422_2325; // RSI: running hash

    let mut d = RiscDesynthesizer::new();
    for _ in 0..bytes.len() {
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width: 1 })
                .with_dst(MicroOperand::VReg(9))
                .with_src1(MicroOperand::VReg(0)),
        );
        d.emit_xor(
            MicroOperand::VReg(9),
            MicroOperand::VReg(9),
            MicroOperand::VReg(6),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MultiplyLow {
                signed: true,
                width: 8,
            })
            .with_dst(MicroOperand::VReg(6))
            .with_src1(MicroOperand::VReg(9))
            .with_src2(MicroOperand::VReg(2)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::Add { width: 8 })
                .with_dst(MicroOperand::VReg(0))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(1)),
        );
    }
    d.instrs.push(MicroInstr::new(RiscOp::Halt));
    let prog = RiscProgram::new(d.instrs);

    let mut expected = init[6];
    for byte in bytes.iter() {
        expected = (expected ^ (*byte as u64)).wrapping_mul(init[2]);
    }
    for seed in [0x1234_5678_9ABC_DEF0, 0xDEAD_BEEF_CAFE_0001] {
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
        assert_eq!(native.regs[6], expected, "seed {seed:#x}: FNV byte walk");
        assert_eq!(
            native.regs[0],
            init[0] + bytes.len() as u64,
            "seed {seed:#x}: pointer advance"
        );
    }
}

/// Differential guard for the exact eight-byte unrolled FNV kernel emitted
/// by Rust's slice hashing loop (`movzx`, `xor`, two-operand `imul`).
#[test]
fn test_lifted_unrolled_fnv_kernel_matches_host_arithmetic() {
    use crate::vm::risc::lifter::RiscLifter;
    let bytes = Box::new([0x00u8, 0xA5, 0x7F, 0xFF, 0x42, 0x11, 0x80, 0x5C]);
    let raw: [u8; 94] = [
        0x44, 0x0F, 0xB6, 0x08, 0x49, 0x31, 0xF1, 0x4C, 0x0F, 0xAF, 0xCA, 0x44, 0x0F, 0xB6, 0x50,
        0x01, 0x4D, 0x31, 0xCA, 0x4C, 0x0F, 0xAF, 0xD2, 0x44, 0x0F, 0xB6, 0x48, 0x02, 0x4D, 0x31,
        0xD1, 0x4C, 0x0F, 0xAF, 0xCA, 0x44, 0x0F, 0xB6, 0x50, 0x03, 0x4D, 0x31, 0xCA, 0x4C, 0x0F,
        0xAF, 0xD2, 0x44, 0x0F, 0xB6, 0x48, 0x04, 0x4D, 0x31, 0xD1, 0x4C, 0x0F, 0xAF, 0xCA, 0x44,
        0x0F, 0xB6, 0x50, 0x05, 0x4D, 0x31, 0xCA, 0x4C, 0x0F, 0xAF, 0xD2, 0x44, 0x0F, 0xB6, 0x48,
        0x06, 0x4D, 0x31, 0xD1, 0x4C, 0x0F, 0xAF, 0xCA, 0x0F, 0xB6, 0x70, 0x07, 0x4C, 0x31, 0xCE,
        0x48, 0x0F, 0xAF, 0xF2,
    ];
    let mut decoder = Decoder::with_ip(64, &raw, 0x140001000, DecoderOptions::NONE);
    let mut lifter = RiscLifter::new();
    while decoder.can_decode() {
        lifter.lift_instruction(&decoder.decode()).unwrap();
    }
    lifter.desynth.instrs.push(MicroInstr::new(RiscOp::Halt));
    let prog = RiscProgram::new(lifter.desynth.instrs);
    let mut init = [0u64; 16];
    init[0] = bytes.as_ptr() as u64;
    init[2] = 0x0000_0100_0000_01B3;
    init[6] = 0xCBF2_9CE4_8422_2325;
    let expected = bytes
        .iter()
        .fold(init[6], |h, b| (h ^ *b as u64).wrapping_mul(init[2]));
    let seed = 0xA5A5_5A5A_1122_3344;
    let bytecode = PolymorphicEncoder::new(seed).encode(&prog).unwrap();
    let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
    assert_eq!(native.regs[6], expected, "lifted unrolled FNV kernel");
}

/// Same FNV operation with a lifted backward JNE edge. This exercises the
/// program VM's IP map, rolling-key re-sync and cross-basic-block state.
#[test]
fn test_lifted_fnv_loop_backward_branch_matches_host_arithmetic() {
    use crate::vm::risc::lifter::RiscLifter;
    let bytes = Box::new([0x33u8, 0x90, 0xFE, 0x01, 0x77, 0xC0, 0x12, 0xAB]);
    // Exact shape of Rust's FNV tail loop: index in r8, accumulator hand-off
    // through r9, byte load into esi, and a backward JNE to the r9 copy.
    let raw = [
        0x45, 0x31, 0xC0, // xor r8d,r8d
        0x4C, 0x8B, 0xCE, // mov r9,rsi
        0x42, 0x0F, 0xB6, 0x34, 0x00, // movzx esi,byte ptr [rax+r8]
        0x4C, 0x31, 0xCE, // xor rsi,r9
        0x48, 0x0F, 0xAF, 0xF2, // imul rsi,rdx
        0x49, 0xFF, 0xC0, // inc r8
        0x4C, 0x8B, 0xCE, // mov r9,rsi
        0x4C, 0x39, 0xC1, // cmp rcx,r8
        0x75, 0xE6, 0xC3, // jne mov r9,rsi; ret
    ];
    let mut decoder = Decoder::with_ip(64, &raw, 0x140002000, DecoderOptions::NONE);
    let mut lifter = RiscLifter::new();
    let mut ip_map = HashMap::new();
    while decoder.can_decode() {
        let inst = decoder.decode();
        ip_map.insert(inst.ip(), lifter.desynth.instrs.len());
        lifter.lift_instruction(&inst).unwrap();
    }
    let prog = RiscProgram::with_ip_map(lifter.desynth.instrs, ip_map.clone());
    let mut init = [0u64; 16];
    init[0] = bytes.as_ptr() as u64;
    init[1] = bytes.len() as u64;
    init[2] = 0x0000_0100_0000_01B3;
    init[6] = 0xCBF2_9CE4_8422_2325;
    let expected = bytes
        .iter()
        .fold(init[6], |h, b| (h ^ *b as u64).wrapping_mul(init[2]));
    let seed = 0xBADC_0FFE_1234_5678;
    let bytecode = PolymorphicEncoder::new(seed).encode(&prog).unwrap();
    // First distinguish flag evaluation from the backward-resync path: with
    // RCX=1, JNE must be not-taken after exactly one body execution.
    let mut one = init;
    one[1] = 1;
    let one_no_map = run_native_poly_direct(&bytecode, seed, &one).unwrap();
    let one_expected = (one[6] ^ bytes[0] as u64).wrapping_mul(one[2]);
    assert_eq!(
        one_no_map.regs[6], one_expected,
        "JNE not-taken without IP map"
    );
    let one_native = run_native_poly_direct_with(&bytecode, seed, &one, Some(&ip_map)).unwrap();
    assert_eq!(
        one_native.regs[6], one_expected,
        "JNE not-taken FNV iteration"
    );
    let native = run_native_poly_direct_with(&bytecode, seed, &init, Some(&ip_map)).unwrap();
    assert_eq!(native.regs[6], expected, "lifted backward-loop FNV result");
    assert_eq!(native.regs[8], bytes.len() as u64, "all bytes consumed");
}

/// Differential: native self-decoding == interpreter == reference.

#[test]

fn test_native_poly_direct_matches_interpreter_and_reference() {
    let mut d = RiscDesynthesizer::new();

    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0x200),
        MicroOperand::Imm64(0),
    );

    d.emit_add(
        MicroOperand::VReg(1),
        MicroOperand::Imm64(5),
        MicroOperand::Imm64(0),
    );

    d.instrs.push(
        MicroInstr::new(RiscOp::ShiftRight)
            .with_dst(MicroOperand::VReg(2))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::VReg(1)),
    );

    d.instrs.push(
        MicroInstr::new(RiscOp::ShiftLeft)
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::Imm64(2)),
    );

    d.instrs.push(
        MicroInstr::new(RiscOp::AddWithCarry)
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::VReg(1))
            .with_imm(0),
    );

    d.emit_push(MicroOperand::VReg(3));

    d.emit_push(MicroOperand::VReg(0));

    d.emit_pop(MicroOperand::VReg(4));

    d.instrs.push(
        MicroInstr::new(RiscOp::Nor)
            .with_dst(MicroOperand::VReg(5))
            .with_src1(MicroOperand::VReg(2))
            .with_src2(MicroOperand::VReg(1)),
    );

    d.instrs
        .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)));

    d.instrs.push(MicroInstr::new(RiscOp::Halt));

    let prog = RiscProgram::new(d.instrs);

    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut enc = PolymorphicEncoder::new(seed);

        let bytecode = enc.encode(&prog).unwrap();

        let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16]).unwrap();

        let mut interp = PolymorphicInterpreter::new(seed);

        interp.run(&bytecode).unwrap();

        let ref_st = prog.eval_state(&[0u64; 16]);

        assert_eq!(
            native.regs, ref_st.regs,
            "seed {seed:#x}: native regs != ref"
        );

        assert_eq!(
            interp.regs, ref_st.regs,
            "seed {seed:#x}: interp regs != ref"
        );

        assert_eq!(
            native.temps, ref_st.temps,
            "seed {seed:#x}: native temps != ref"
        );

        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: native flags {:#x} != ref {:#x}",
            native.flags, ref_st.flags
        );

        assert_eq!(
            interp.flags.raw, ref_st.flags,
            "seed {seed:#x}: interp flags != ref"
        );

        assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: native vsp != ref");

        assert_eq!(
            native.stack, ref_st.stack,
            "seed {seed:#x}: native stack != ref"
        );

        assert_eq!(native.regs[2], 0x10);

        assert_eq!(native.regs[3], 0x800);

        assert_eq!(native.regs[5], !(0x10 | 5));
    }
}

/// Simple add/xor/sub path.

#[test]

fn test_native_poly_direct_matches_decoder_path() {
    let seed = 0x8899AABBCCDDEEFF;

    let mut d = RiscDesynthesizer::new();

    d.emit_add(
        MicroOperand::VReg(0),
        MicroOperand::Imm64(1200),
        MicroOperand::Imm64(0),
    );

    d.emit_add(
        MicroOperand::VReg(1),
        MicroOperand::Imm64(450),
        MicroOperand::Imm64(0),
    );

    d.emit_sub(
        MicroOperand::VReg(0),
        MicroOperand::VReg(0),
        MicroOperand::VReg(1),
    );

    d.emit_xor(
        MicroOperand::VReg(0),
        MicroOperand::VReg(0),
        MicroOperand::Imm64(0x55),
    );

    d.instrs.push(MicroInstr::new(RiscOp::Halt));

    let prog = RiscProgram::new(d.instrs);

    let mut enc = PolymorphicEncoder::new(seed);

    let bytecode = enc.encode(&prog).unwrap();

    let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16]).unwrap();

    let ref_st = prog.eval_state(&[0u64; 16]);

    assert_eq!(native.regs[0], ref_st.regs[0]);

    assert_eq!(native.regs[1], ref_st.regs[1]);

    assert_eq!(native.regs[0], (1200 - 450) ^ 0x55);
}

/// NativeCallBridge no-op: the self-decoding dispatcher must CONSUME the

/// stream (opcode + 3 operand bytes + immediates) without changing any VM

/// state, so a following op is still reached. Differential: native

/// self-decoding == interpreter == reference (which treat NativeCallBridge

/// as a no-op), across multiple seeds and with both imm & vreg operands.

#[test]

fn test_native_poly_direct_native_call_bridge_noop() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();

        // R0 = 0x200

        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x200),
            MicroOperand::Imm64(0),
        );

        // Bridge with imm src1 + dst: must consume stream, change nothing.

        d.instrs.push(
            MicroInstr::new(RiscOp::NativeCallBridge)
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::Imm64(0x9999)),
        );

        // Bridge with vreg src1/src2 + dst: must consume stream, change nothing.

        d.instrs.push(
            MicroInstr::new(RiscOp::NativeCallBridge)
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
        );

        // State-changing op AFTER the bridges: only reached if the stream was

        // consumed by the no-op handlers (no desync / no premature stop).

        d.emit_add(
            MicroOperand::VReg(6),
            MicroOperand::VReg(0),
            MicroOperand::Imm64(1),
        );

        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);

        let mut enc = PolymorphicEncoder::new(seed);

        let bytecode = enc.encode(&prog).unwrap();

        let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16]).unwrap();

        let mut interp = PolymorphicInterpreter::new(seed);

        interp.run(&bytecode).unwrap();

        let ref_st = prog.eval_state(&[0u64; 16]);

        // Bridge must not have written regs 1/2 (no-op), and the post-bridge

        // op must have run (stream consumed correctly).

        assert_eq!(
            ref_st.regs[1], 0,
            "seed {seed:#x}: bridge wrote dst VReg(1)"
        );

        assert_eq!(
            ref_st.regs[2], 0,
            "seed {seed:#x}: bridge wrote dst VReg(2)"
        );

        assert_eq!(
            ref_st.regs[6], 0x201,
            "seed {seed:#x}: post-bridge op not reached"
        );

        assert_eq!(
            native.regs, ref_st.regs,
            "seed {seed:#x}: native regs != ref"
        );

        assert_eq!(
            interp.regs, ref_st.regs,
            "seed {seed:#x}: interp regs != ref"
        );

        assert_eq!(
            native.temps, ref_st.temps,
            "seed {seed:#x}: native temps != ref"
        );

        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: native flags {:#x} != ref {:#x}",
            native.flags, ref_st.flags
        );

        assert_eq!(
            interp.flags.raw, ref_st.flags,
            "seed {seed:#x}: interp flags != ref"
        );

        assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: native vsp != ref");

        assert_eq!(
            native.stack, ref_st.stack,
            "seed {seed:#x}: native stack != ref"
        );
    }
}

/// P3: CompareExchange{1,2,4,8} — native self-decoding handler == eval_state

/// (linear-block unit equivalence; success and failure paths, all widths).

#[test]

fn test_poly_direct_compare_exchange_all_widths_matches_reference() {
    use std::collections::HashMap;

    let seed = 0x13579BDF2468ACE0u64;

    let mut arena = Arena::new(ARENA_SIZE).unwrap();

    let base = arena.base;

    let code_off = OFF_CODE;

    let table_off = OFF_TABLE;

    let bytecode_off = OFF_BYTECODE;

    let state_off = OFF_STATE;

    let window_off = 0x30000usize; // clear of code/table/bytecode/state/stack

    let addr = (base + window_off) as u64;

    let code_va = (base + code_off) as u64;

    let table_va = (base + table_off) as u64;

    let bytecode_va = (base + bytecode_off) as u64;

    let state_va = (base + state_off) as u64;

    let stack_base = (base + OFF_STACK_BASE) as u64;

    for width in [1u8, 2, 4, 8] {
        let newv: u64 = 0x0BAD_F00D_CAFE_1234;

        let mut d = RiscDesynthesizer::new();

        d.instrs.push(
            MicroInstr::new(RiscOp::CompareExchange { width })
                .with_src1(MicroOperand::VReg(1)) // addr (set in init_regs)
                .with_src2(MicroOperand::Imm64(newv)),
        );

        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);

        let mut enc = PolymorphicEncoder::new(seed);

        let bytecode = enc.encode(&prog).unwrap();

        let parts = build_self_decoding_parts(
            &bytecode,
            seed,
            code_va,
            table_va,
            bytecode_va,
            state_va,
            stack_base,
        )
        .expect("build self-decoding parts");

        assert!(
            parts.code.len() + OFF_CODE <= OFF_TABLE,
            "dispatcher code overflowed into table region: code_len={}",
            parts.code.len()
        );

        // Place parts into arena once per width; state/memory re-seeded per scenario.

        {
            let buf = arena.bytes();

            buf[code_off..code_off + parts.code.len()].copy_from_slice(&parts.code);

            for (i, v) in parts.table.iter().enumerate() {
                buf[table_off + i * 8..table_off + i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }

            install_operand_offsets(buf, OFF_OP_OFFS, &parts.offs_tab);

            buf[OFF_OP_FLAGS..OFF_OP_FLAGS + 256].copy_from_slice(&parts.flags_tab);

            buf[bytecode_off..bytecode_off + bytecode.len()].copy_from_slice(&bytecode);
        }

        let old: u64 = 0xFEDC_BA98_7654_3210;

        let scenarios: [(&str, u64, u64, bool); 3] = [
            ("success", old, old, true),
            ("failure", old ^ 0x1, old, false),
            // P1-6: acc(0) < old(0x10) → CMP borrow → CF=1 (비-ZF 플래그 검증).
            ("below", 0x0, old, false),
        ];

        for (label, acc, old, success) in scenarios {
            let mask = if width == 8 {
                u64::MAX
            } else {
                (1u64 << (width * 8)) - 1
            };

            // init regs: reg[0]=acc (expected), reg[1]=addr

            let mut init = [0u64; 16];

            init[0] = acc;

            init[1] = addr;

            // seed window + state identically in native arena and reference HashMap.

            {
                let buf = arena.bytes();

                buf[window_off..window_off + 8].copy_from_slice(&old.to_le_bytes());

                buf[state_off..state_off + STATE_END as usize].fill(0);

                for (i, v) in init.iter().enumerate() {
                    buf[state_off + REGS_OFF as usize + i * 8
                        ..state_off + REGS_OFF as usize + i * 8 + 8]
                        .copy_from_slice(&v.to_le_bytes());
                }
            }

            let mut seed_mem = HashMap::new();

            for (k, b) in old.to_le_bytes().iter().enumerate() {
                seed_mem.insert(addr.wrapping_add(k as u64), *b);
            }

            let ref_st = prog.eval_state_with_mem(&init, seed_mem);

            arena.call(code_off);

            let buf = arena.bytes();

            let s = state_off;

            let mut nat = RiscEvalState::default();

            for i in 0..16 {
                nat.regs[i] = u64::from_le_bytes(
                    buf[s + REGS_OFF as usize + i * 8..s + REGS_OFF as usize + i * 8 + 8]
                        .try_into()
                        .unwrap(),
                );
            }

            for i in 0..8 {
                nat.temps[i] = u64::from_le_bytes(
                    buf[s + TEMPS_OFF as usize + i * 8..s + TEMPS_OFF as usize + i * 8 + 8]
                        .try_into()
                        .unwrap(),
                );
            }

            nat.flags = u64::from_le_bytes(
                buf[s + FLAGS_OFF as usize..s + FLAGS_OFF as usize + 8]
                    .try_into()
                    .unwrap(),
            );

            nat.vsp = u64::from_le_bytes(
                buf[s + VSP_OFF as usize..s + VSP_OFF as usize + 8]
                    .try_into()
                    .unwrap(),
            );

            assert_eq!(
                nat.regs, ref_st.regs,
                "w{width} {label}: regs mismatch (nat={:?} ref={:?})",
                nat.regs, ref_st.regs
            );

            assert_eq!(
                nat.flags, ref_st.flags,
                "w{width} {label}: flags nat={:#x} ref={:#x}",
                nat.flags, ref_st.flags
            );

            assert_eq!(nat.temps, ref_st.temps, "w{width} {label}: temps mismatch");

            assert_eq!(nat.vsp, ref_st.vsp, "w{width} {label}: vsp mismatch");

            // memory side-effect: width low bytes written/unchanged == reference.

            let nat_mem = u64::from_le_bytes(buf[window_off..window_off + 8].try_into().unwrap());

            let mut ref_mem = 0u64;

            for k in 0..width as usize {
                ref_mem |=
                    (*ref_st.mem.get(&addr.wrapping_add(k as u64)).unwrap_or(&0) as u64) << (k * 8);
            }

            assert_eq!(
                nat_mem & mask,
                ref_mem,
                "w{width} {label}: mem mismatch nat={:#x} ref={:#x}",
                nat_mem & mask,
                ref_mem
            );

            assert_eq!(
                nat_mem & mask,
                if success { newv & mask } else { old & mask },
                "w{width} {label}: mem side-effect wrong (expect {:#x})",
                if success { newv & mask } else { old & mask }
            );

            assert_eq!(
                nat.flags & 0x40 != 0,
                success,
                "w{width} {label}: ZF wrong (nat.flags={:#x})",
                nat.flags
            );
            // P1-6: 비-ZF 상태 플래그도 CMP(acc-old) 기준으로 set 된다 — "below"는
            // acc(0) < old 이므로 borrow → CF=1 이어야 한다.
            if label == "below" {
                assert_ne!(
                    nat.flags & 0x1,
                    0,
                    "w{width} below: CF must be set (CMP borrow)"
                );
            }
        }
    }
}

/// P0-4: AtomicExchange / AtomicAdd — native self-decoding handler == eval_state
/// (모든 폭). 원자 RMW 의미론: XCHG 는 swap(플래그 불변), XADD 는 덧셈 플래그
/// 를 폭별로 set. arena window 를 메모리 주소로 사용하고 참조 HashMap 과 동일
/// 시드해 레지스터/플래그/메모리 부수효과를 비교한다.
#[test]
fn test_poly_direct_atomic_exchange_add_all_widths_matches_reference() {
    use std::collections::HashMap;

    let seed = 0x13579BDF2468ACE0u64;
    let mut arena = Arena::new(ARENA_SIZE).unwrap();
    let base = arena.base;
    let code_off = OFF_CODE;
    let table_off = OFF_TABLE;
    let bytecode_off = OFF_BYTECODE;
    let state_off = OFF_STATE;
    let window_off = 0x30000usize; // clear of code/table/bytecode/state/stack
    let addr = (base + window_off) as u64;
    let code_va = (base + code_off) as u64;
    let table_va = (base + table_off) as u64;
    let bytecode_va = (base + bytecode_off) as u64;
    let state_va = (base + state_off) as u64;
    let stack_base = (base + OFF_STACK_BASE) as u64;

    for width in [1u8, 2, 4, 8] {
        let mask = if width == 8 {
            u64::MAX
        } else {
            (1u64 << (width * 8)) - 1
        };
        let ex_val: u64 = 0x0BAD_F00D_CAFE_1234; // 레지스터에 들어갈 교환값 (폭 마스크)
        let addend: u64 = 0x05;
        let old: u64 = 0xFEDC_BA98_7654_3210;

        let mut d = RiscDesynthesizer::new();
        // AtomicExchange{width}: dst = VReg(0) (레지스터), src1 = VReg(1) (addr).
        d.instrs.push(
            MicroInstr::new(RiscOp::AtomicExchange { width })
                .with_dst(MicroOperand::VReg(0))
                .with_src1(MicroOperand::VReg(1)),
        );
        // AtomicAdd{width}: dst = VReg(0) (이전 [addr]), src1 = addr, src2 = addend.
        d.instrs.push(
            MicroInstr::new(RiscOp::AtomicAdd { width })
                .with_dst(MicroOperand::VReg(0))
                .with_src1(MicroOperand::VReg(1))
                .with_src2(MicroOperand::VReg(2)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);

        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();

        let parts = build_self_decoding_parts(
            &bytecode,
            seed,
            code_va,
            table_va,
            bytecode_va,
            state_va,
            stack_base,
        )
        .expect("build self-decoding parts");
        assert!(
            parts.code.len() + OFF_CODE <= OFF_TABLE,
            "dispatcher code overflowed into table region: code_len={}",
            parts.code.len()
        );

        {
            let buf = arena.bytes();
            buf[code_off..code_off + parts.code.len()].copy_from_slice(&parts.code);
            for (i, v) in parts.table.iter().enumerate() {
                buf[table_off + i * 8..table_off + i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }
            install_operand_offsets(buf, OFF_OP_OFFS, &parts.offs_tab);
            buf[OFF_OP_FLAGS..OFF_OP_FLAGS + 256].copy_from_slice(&parts.flags_tab);
            buf[bytecode_off..bytecode_off + bytecode.len()].copy_from_slice(&bytecode);
        }

        let mut init = [0u64; 16];
        init[0] = ex_val;
        init[1] = addr;
        init[2] = addend;

        {
            let buf = arena.bytes();
            buf[window_off..window_off + 8].copy_from_slice(&old.to_le_bytes());
            buf[state_off..state_off + STATE_END as usize].fill(0);
            for (i, v) in init.iter().enumerate() {
                buf[state_off + REGS_OFF as usize + i * 8
                    ..state_off + REGS_OFF as usize + i * 8 + 8]
                    .copy_from_slice(&v.to_le_bytes());
            }
        }
        let mut seed_mem = HashMap::new();
        for (k, b) in old.to_le_bytes().iter().enumerate() {
            seed_mem.insert(addr.wrapping_add(k as u64), *b);
        }

        let ref_st = prog.eval_state_with_mem(&init, seed_mem);

        arena.call(code_off);

        let buf = arena.bytes();
        let s = state_off;
        let mut nat = RiscEvalState::default();
        for i in 0..16 {
            nat.regs[i] = u64::from_le_bytes(
                buf[s + REGS_OFF as usize + i * 8..s + REGS_OFF as usize + i * 8 + 8]
                    .try_into()
                    .unwrap(),
            );
        }
        for i in 0..8 {
            nat.temps[i] = u64::from_le_bytes(
                buf[s + TEMPS_OFF as usize + i * 8..s + TEMPS_OFF as usize + i * 8 + 8]
                    .try_into()
                    .unwrap(),
            );
        }
        nat.flags = u64::from_le_bytes(
            buf[s + FLAGS_OFF as usize..s + FLAGS_OFF as usize + 8]
                .try_into()
                .unwrap(),
        );
        nat.vsp = u64::from_le_bytes(
            buf[s + VSP_OFF as usize..s + VSP_OFF as usize + 8]
                .try_into()
                .unwrap(),
        );

        assert_eq!(
            nat.regs, ref_st.regs,
            "w{width}: regs mismatch (nat={:?} ref={:?})",
            nat.regs, ref_st.regs
        );
        assert_eq!(
            nat.flags, ref_st.flags,
            "w{width}: flags nat={:#x} ref={:#x}",
            nat.flags, ref_st.flags
        );
        assert_eq!(nat.temps, ref_st.temps, "w{width}: temps mismatch");
        assert_eq!(nat.vsp, ref_st.vsp, "w{width}: vsp mismatch");

        // 메모리 부수효과: XCHG 후 [addr] = ex_val, XADD 후 [addr] = ex_val + addend.
        let nat_mem = u64::from_le_bytes(buf[window_off..window_off + 8].try_into().unwrap());
        let mut ref_mem = 0u64;
        for k in 0..width as usize {
            ref_mem |=
                (*ref_st.mem.get(&addr.wrapping_add(k as u64)).unwrap_or(&0) as u64) << (k * 8);
        }
        assert_eq!(
            nat_mem & mask,
            ref_mem,
            "w{width}: mem mismatch nat={:#x} ref={:#x}",
            nat_mem & mask,
            ref_mem
        );
        // XCHG: reg[0] = old [addr]; XADD: reg[0] = 이전 [addr] (= ex_val).
        assert_eq!(
            nat.regs[0] & mask,
            ex_val & mask,
            "w{width}: dst = old [addr] after exchange+add"
        );
        assert_eq!(
            nat_mem & mask,
            (ex_val.wrapping_add(addend)) & mask,
            "w{width}: [addr] = ex_val + addend"
        );
    }
}

/// Differential: native self-decoding Multiply/MultiplyLow == interpreter ==

/// reference (linear-block unit equivalence), signed/unsigned across widths —

/// including RDX(high)/regs[2] and the CF=OF overflow flags, and the width-1

/// AX packing ((high<<8)|low).

#[test]
fn test_poly_direct_multiply_matches_reference() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();
        // Load operands via adds (interpreter starts from zero regs).
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x1_0000_0001),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(3),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(3),
            MicroOperand::Imm64(0x7FFF_FFFF),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(4),
            MicroOperand::Imm64(0xFF),
            MicroOperand::Imm64(0),
        );
        // Clean flag base: isolates the multiply CF/OF handling from the
        // AddWithCarry setup (native h_add preserves PF/AF instead of recomputing).
        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0)));
        // unsigned MUL r64: R0=0x1_0000_0001, R1=3 -> RDX:RAX, low->R0, high->R2.
        d.instrs.push(
            MicroInstr::new(RiscOp::Multiply {
                signed: false,
                width: 8,
            })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::VReg(0))
            .with_src2(MicroOperand::VReg(1)),
        );
        // signed IMUL r32 (MultiplyLow): 0x7FFFFFFF * 2 = 0xFFFFFFFE, CF=OF=1.
        d.instrs.push(
            MicroInstr::new(RiscOp::MultiplyLow {
                signed: true,
                width: 4,
            })
            .with_dst(MicroOperand::VReg(6))
            .with_src1(MicroOperand::VReg(3))
            .with_src2(MicroOperand::Imm64(2)),
        );
        // P0-2 signed IMUL r8 — 부호 확장 고 half:
        //  (a) -1 * -1 = +1 -> AX=0x0001, CF=OF=0 (기존 버그: 0xFE01 + CF|OF).
        d.instrs.push(
            MicroInstr::new(RiscOp::Multiply {
                signed: true,
                width: 1,
            })
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::VReg(4))
            .with_src2(MicroOperand::VReg(4)),
        );
        //  (b) -1 * 2 = -2 -> AX=0xFFFE, CF=OF=0 (고 half 0xFF).
        d.instrs.push(
            MicroInstr::new(RiscOp::Multiply {
                signed: true,
                width: 1,
            })
            .with_dst(MicroOperand::VReg(8))
            .with_src1(MicroOperand::VReg(4))
            .with_src2(MicroOperand::Imm64(2)),
        );
        //  (c) 127 * 2 = 254 > signed-8-bit -> AX=0x00FE, CF=OF=1.
        d.instrs.push(
            MicroInstr::new(RiscOp::Multiply {
                signed: true,
                width: 1,
            })
            .with_dst(MicroOperand::VReg(9))
            .with_src1(MicroOperand::Imm64(0x7F))
            .with_src2(MicroOperand::Imm64(2)),
        );
        //  (d) signed IMUL r16 (Multiply, RDX high): -1 * -1 = 1 -> low=1, RDX=0.
        d.emit_add(
            MicroOperand::VReg(5),
            MicroOperand::Imm64(0xFFFF),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::Multiply {
                signed: true,
                width: 2,
            })
            .with_dst(MicroOperand::VReg(10))
            .with_src1(MicroOperand::VReg(5))
            .with_src2(MicroOperand::VReg(5)),
        );
        //  (e) signed IMUL r64 오버플로: 0x4000_0000_0000_0000 * 2 → low=0x8000_0000_0000_0000,
        //      CF=OF=1 (고 half(0) != low 부호 확장). 먼저 실행 — regs[2]/flags 는 (f)가 덮어쓴다.
        d.instrs.push(
            MicroInstr::new(RiscOp::Multiply {
                signed: true,
                width: 8,
            })
            .with_dst(MicroOperand::VReg(11))
            .with_src1(MicroOperand::Imm64(0x4000_0000_0000_0000))
            .with_src2(MicroOperand::Imm64(2)),
        );
        //  (f) signed IMUL r64 (Multiply, RDX high): -1 * 2 = -2 → low=0xFFFF_FFFF_FFFF_FFFE,
        //      high(RDX) = 0xFFFF_FFFF_FFFF_FFFF (-1, 부호 확장 — unsigned mul 의 1 이 아님).
        //      마지막 실행 → 최종 regs[2]/flags 가 (f) 결과를 반영한다.
        d.instrs.push(
            MicroInstr::new(RiscOp::Multiply {
                signed: true,
                width: 8,
            })
            .with_dst(MicroOperand::VReg(12))
            .with_src1(MicroOperand::Imm64(0xFFFF_FFFF_FFFF_FFFF))
            .with_src2(MicroOperand::Imm64(2)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);

        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16]).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.run(&bytecode).unwrap();
        let ref_st = prog.eval_state(&[0u64; 16]);

        assert_eq!(
            native.regs, ref_st.regs,
            "seed {seed:#x}: mul native regs != ref"
        );
        assert_eq!(
            interp.regs, ref_st.regs,
            "seed {seed:#x}: mul interp regs != ref"
        );
        assert_eq!(
            native.temps, ref_st.temps,
            "seed {seed:#x}: mul native temps != ref"
        );
        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: mul native flags {:#x} != ref {:#x}",
            native.flags, ref_st.flags
        );
        assert_eq!(
            interp.flags.raw, ref_st.flags,
            "seed {seed:#x}: mul interp flags != ref"
        );
        assert_eq!(
            native.regs[0], 0x3_0000_0003,
            "seed {seed:#x}: MUL low wrong"
        );
        assert_eq!(
            native.regs[2], 0xFFFF_FFFF_FFFF_FFFF,
            "seed {seed:#x}: final MUL high wrong (last Multiply overwrites RDX)"
        );
        assert_eq!(
            native.regs[6], 0xFFFF_FFFE,
            "seed {seed:#x}: IMUL low wrong"
        );
        // P0-2 부호 고 half 정합: -1*-1=+1, -1*2=-2, 127*2=overflow.
        assert_eq!(
            native.regs[7], 0x0001,
            "seed {seed:#x}: IMUL r8 -1*-1 wrong"
        );
        assert_eq!(native.regs[8], 0xFFFE, "seed {seed:#x}: IMUL r8 -1*2 wrong");
        assert_eq!(
            native.regs[9], 0x00FE,
            "seed {seed:#x}: IMUL r8 127*2 wrong"
        );
        assert_eq!(
            native.regs[10], 1,
            "seed {seed:#x}: IMUL r16 -1*-1 low wrong"
        );
        // P0-2 signed IMUL r64: 오버플로 low=0x8000_0000_0000_0000, 마지막 -1*2 는
        // low=0xFFFF_FFFF_FFFF_FFFE + high(RDX)=−1 (부호 확장 — unsigned mul 의 1 이 아님).
        assert_eq!(
            native.regs[11], 0x8000_0000_0000_0000,
            "seed {seed:#x}: IMUL r64 overflow low wrong"
        );
        assert_eq!(
            native.regs[12], 0xFFFF_FFFF_FFFF_FFFE,
            "seed {seed:#x}: IMUL r64 -1*2 low wrong"
        );
        assert_eq!(
            native.regs[2], 0xFFFF_FFFF_FFFF_FFFF,
            "seed {seed:#x}: IMUL r64 -1*2 high(RDX) wrong (unsigned mul bug)"
        );
        // 최종 CF|OF: 마지막 -1*2 는 오버플로 아님 → CF=OF=0.
        assert_eq!(
            native.flags & 0x801,
            0,
            "seed {seed:#x}: final IMUL CF|OF must be clear"
        );
    }
}

#[test]
fn test_narrow_shift_flags_preserved_matches_reference() {
    use crate::vm::risc::RiscLifter;
    use iced_x86::{Decoder, DecoderOptions};

    // P0-3: 8/16비트 시프트의 합성 mask/sign-extend/preserve op(Nor 시퀀스)가
    // 시프트 flags를 덮어쓰지 않아야 한다:
    //   mov rax, 0x1122334455667788 ; sub al, 1 → al=0x87 (SF=1, CF=0)
    //   shl al, 0  ; count==0 → x86 flags 보존 (SF=1 유지, AND/OR 로 소실 금지)
    //   shr al, 1  ; 0x87>>1 = 0x43, CF = shift-out bit0 = 1 (test 가 CF 를
    //               ; clear 하면 안 됨), 최종 rax = 0x1122334455667743
    let raw = [
        0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov rax, imm64
        0x2C, 0x01, // sub al, 1
        0xC0, 0xE0, 0x00, // shl al, 0
        0xC0, 0xE8, 0x01, // shr al, 1
        0xC3, // ret
    ];
    let base = 0x140001000u64;

    let mut decoder = Decoder::with_ip(64, &raw, base, DecoderOptions::NONE);
    let mut lifter = RiscLifter::new();
    while decoder.can_decode() {
        lifter
            .lift_instruction(&decoder.decode())
            .expect("all RISC-liftable");
    }
    let prog = RiscProgram::new(lifter.desynth.instrs);
    let init = [0u64; 16];
    let ref_st = prog.eval_state(&init);

    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.run(&bytecode).unwrap();

        assert_eq!(
            native.regs, ref_st.regs,
            "seed {seed:#x}: shift native regs != ref"
        );
        assert_eq!(
            interp.regs, ref_st.regs,
            "seed {seed:#x}: shift interp regs != ref"
        );
        assert_eq!(
            native.temps, ref_st.temps,
            "seed {seed:#x}: shift native temps != ref"
        );
        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: shift native flags {:#x} != ref {:#x}",
            native.flags, ref_st.flags
        );
        assert_eq!(
            interp.flags.raw, ref_st.flags,
            "seed {seed:#x}: shift interp flags != ref"
        );
        assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: vsp mismatch");
        assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: stack mismatch");

        // x86 실제 의미론 값 단언:
        //  * 최종 rax: 상위 보존 + low byte 0x43.
        assert_eq!(
            native.regs[0], 0x1122334455667743,
            "seed {seed:#x}: rax final"
        );
        //  * shr al,1 의 CF = shift-out bit0(=1) — 합성 AND 가 CF 를 소실하면 안 됨.
        assert_ne!(
            native.flags & crate::vm::risc::flags::VFLAG_CF,
            0,
            "seed {seed:#x}: shift CF lost by synthetic AND/OR"
        );
        //  * shl al,0 후에도 SF 는 sub al,1 이 set 한 값이 유지되어야 함 — 위 shr 의
        //    결과(0x43)는 bit63 미셋이라 최종 SF=0 (참조와 동일).
        assert_eq!(
            native.flags & crate::vm::risc::flags::VFLAG_SF,
            0,
            "seed {seed:#x}: SF after shr"
        );
    }
}

/// P0-1: 네이티브 self-decoding CALL/RET 라운드트립 — callee 의 `VirtualRet` 가
/// 가상 스택의 복귀 주소(source-IP, ip_map)를 branch-map 으로 해석해 호출자로
/// **복귀**하고, 호출자는 fallthrough 를 계속 실행해야 한다 (이전엔 RET→Halt 로
/// 복귀가 불가능했다). 최상위(빈 스택) ret 는 Halt 로 종료.
#[test]
fn test_poly_direct_call_ret_roundtrip_matches_reference() {
    use std::collections::HashMap;
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();
        // idx0: push 복귀 주소 0x140001004 (= idx4, 호출자 fallthrough).
        d.instrs
            .push(MicroInstr::new(RiscOp::VirtualPush).with_src1(MicroOperand::Imm64(0x140001004)));
        // idx1: call → callee (source-IP 0x140001005 = idx5).
        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            })
            .with_imm(0x140001005),
        );
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(99),
            MicroOperand::Imm64(0),
        ); // idx2: skipped
        d.emit_add(
            MicroOperand::VReg(3),
            MicroOperand::Imm64(55),
            MicroOperand::Imm64(0),
        ); // idx3: skipped
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x2A),
            MicroOperand::Imm64(0),
        ); // idx4: caller resumes
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(7),
            MicroOperand::Imm64(0),
        ); // idx5: callee
        d.instrs.push(MicroInstr::new(RiscOp::VirtualRet)); // idx6: ret → idx4
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // idx7

        let mut ip_map = HashMap::new();
        for i in 0..8u64 {
            ip_map.insert(0x140001000u64 + i, i as usize);
        }
        let prog = RiscProgram::with_ip_map(d.instrs, ip_map.clone());
        let init = [0u64; 16];
        let ref_st = prog.eval_state(&init);

        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let native = run_native_poly_direct_with(&bytecode, seed, &init, Some(&ip_map)).unwrap();

        assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: call/ret regs");
        assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: call/ret temps");
        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: flags (nat={:#x} ref={:#x})",
            native.flags, ref_st.flags
        );
        assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: vsp");
        assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: stack");
        // caller resumed at idx4 → R0=0x2A, callee ran → R1=7.
        assert_eq!(
            native.regs[0], 0x2A,
            "seed {seed:#x}: caller resumed after ret"
        );
        assert_eq!(native.regs[1], 7, "seed {seed:#x}: callee executed");
        // skipped idx2/idx3.
        assert_eq!(native.regs[2], 0, "seed {seed:#x}: idx2 skipped");
        assert_eq!(native.regs[3], 0, "seed {seed:#x}: idx3 skipped");
        // top-level ret (빈 스택) → halt → 복귀 주소는 pop 되어 스택 비어 있음.
        assert_eq!(
            native.stack.len(),
            0,
            "seed {seed:#x}: stack empty after roundtrip"
        );
        assert_eq!(native.vsp, 0, "seed {seed:#x}: vsp balanced");
    }
}

/// F1: 네이티브 브릿지(nf_real)가 Win64 FP ABI 를 실제로 구현하는지 검증한다.
///  - positional XMM0-3 미러링: FP 인자(regs[1]..=regs[4] = RCX/RDX/R8/R9)를
///    `movq xmmN, gpr` 로 전달한다 (Win64: i 번째 인자가 FP 이면 XMM[i-1]).
///  - FP 리턴: `SetNativeFpReturn{4/8}` 힌트가 FP_RET_OFF 슬롯에 기록되면,
///    브릿지가 반환값을 XMM0(FP)의 low 폭 바이트에서 regs[0] 으로 동기화한다.
///  네이티브 callee(arena 안)를 실제로 호출해 결과를 확인하는 실행 검증.
#[test]
fn test_native_bridge_fp_arg_and_return_matches_abi() {
    for (w, callee, val, expected) in [
        (
            8u8,
            Code::Mulsd_xmm_xmmm64,
            2.5f64.to_bits(),
            6.25f64.to_bits(),
        ), // 2.5*2.5
        (
            4u8,
            Code::Mulss_xmm_xmmm32,
            2.5f32.to_bits() as u64,
            6.25f32.to_bits() as u64,
        ), // f32
    ] {
        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut arena = Arena::new(ARENA_SIZE).unwrap();
            // native callee: op xmm0, xmm0 ; ret  (squares XMM0).
            let callee_off = 0x30000usize;
            {
                let buf = arena.bytes();
                let callee_instrs = vec![
                    Instruction::with2(callee, Register::XMM0, Register::XMM0).unwrap(),
                    Instruction::with(Code::Retnq),
                ];
                let blk = iced_x86::InstructionBlock::new(&callee_instrs, 0x140000000);
                let enc = iced_x86::BlockEncoder::encode(
                    64,
                    blk,
                    iced_x86::BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
                )
                .unwrap();
                buf[callee_off..callee_off + enc.code_buffer.len()]
                    .copy_from_slice(&enc.code_buffer);
            }
            let callee_va = (arena.base + callee_off) as u64;

            // RISC program: arg1(regs[1]=RCX→XMM0) = FP 값; FP-return 힌트;
            // push ret_ip; branch to native callee (not in ip_map → bridge); Halt.
            let build_prog = |ret_ip: u64| {
                let mut d = RiscDesynthesizer::new();
                d.instrs.push(
                    MicroInstr::new(RiscOp::Mov)
                        .with_dst(MicroOperand::VReg(1))
                        .with_src1(MicroOperand::Imm64(val)),
                );
                d.instrs
                    .push(MicroInstr::new(RiscOp::SetNativeFpReturn { width: w }));
                d.instrs.push(
                    MicroInstr::new(RiscOp::VirtualPush).with_src1(MicroOperand::Imm64(ret_ip)),
                );
                d.instrs.push(
                    MicroInstr::new(RiscOp::VirtualBranch {
                        cond: BranchCondition::Always,
                    })
                    .with_imm(callee_va),
                );
                d.instrs.push(MicroInstr::new(RiscOp::Halt));
                RiscProgram::new(d.instrs)
            };

            // 첫 인코딩으로 Halt 의 바이트 오프셋(=ret_ip) 확보 후 재인코딩.
            let probe = build_prog(0);
            let mut enc = PolymorphicEncoder::new(seed);
            let (_, offsets) = enc.encode_with_offsets(&probe).unwrap();
            let ret_ip = offsets[offsets.len() - 1] as u64; // Halt offset
            let prog = build_prog(ret_ip);
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();

            let code_off = OFF_CODE;
            let table_off = OFF_TABLE;
            let bytecode_off = OFF_BYTECODE;
            let state_off = OFF_STATE;
            let code_va = (arena.base + code_off) as u64;
            let table_va = (arena.base + table_off) as u64;
            let bytecode_va = (arena.base + bytecode_off) as u64;
            let state_va = (arena.base + state_off) as u64;
            let stack_base = (arena.base + OFF_STACK_BASE) as u64;

            let runtime_layout = VmRuntimeLayout::from_seed(seed);
            let parts = build_self_decoding_parts_with_layouts(
                &bytecode,
                seed,
                code_va,
                table_va,
                bytecode_va,
                state_va,
                stack_base,
                None,
                crate::vm::table_layout::TableLayout::legacy(),
                runtime_layout.clone(),
            )
            .expect("build parts");

            {
                let buf = arena.bytes();
                buf[code_off..code_off + parts.code.len()].copy_from_slice(&parts.code);
                for (i, v) in parts.table.iter().enumerate() {
                    buf[table_off + i * 8..table_off + i * 8 + 8].copy_from_slice(&v.to_le_bytes());
                }
                install_operand_offsets(buf, OFF_OP_OFFS, &parts.offs_tab);
                buf[OFF_OP_FLAGS..OFF_OP_FLAGS + 256].copy_from_slice(&parts.flags_tab);
                buf[OFF_COND_CODES..OFF_COND_CODES + 256].copy_from_slice(&parts.cond_codes);
                buf[OFF_BRANCH_MAP..OFF_BRANCH_MAP + parts.branch_map.len()]
                    .copy_from_slice(&parts.branch_map);
                buf[bytecode_off..bytecode_off + bytecode.len()].copy_from_slice(&bytecode);
                buf[state_off..state_off + runtime_layout.total_size].fill(0);
                buf[OFF_STACK_BASE - 0x2000..OFF_STACK_BASE].fill(0);
                let arg_off = state_off + runtime_layout.vregs[1] as usize;
                buf[arg_off..arg_off + 8].copy_from_slice(&val.to_le_bytes()); // regs[1] = FP arg
                                                                               // Native bridge calls execute on the guest stack.  This
                                                                               // direct-arena test bypasses the normal program-entry
                                                                               // capture, so seed its synthetic guest RSP explicitly.
                let guest_rsp = stack_base - 0x100;
                let rsp_off = state_off + runtime_layout.vregs[4] as usize;
                buf[rsp_off..rsp_off + 8].copy_from_slice(&guest_rsp.to_le_bytes());
            }

            arena.call(code_off);

            let buf = arena.bytes();
            let r0_off = state_off + runtime_layout.vregs[0] as usize;
            let r0 = u64::from_le_bytes(buf[r0_off..r0_off + 8].try_into().unwrap());
            // 브릿지가 FP 리턴을 XMM0 에서 가져와 regs[0] 로 썼어야 한다.
            assert_eq!(
                    r0, expected,
                    "w{w} seed {seed:#x}: bridge FP return regs[0] wrong (got {r0:#x}, want {expected:#x})"
                );
            // FP 인자가 XMM0 으로 전달됐는지 간접 증명: callee 는 xmm0*xmm0 를 했으므로
            // regs[0] = val*val 가 성립하면 positional mirror 가 정확히 동작한 것이다.
            assert_ne!(
                r0, val,
                "w{w} seed {seed:#x}: callee did not square XMM0 (arg not delivered?)"
            );
        }
    }
}

/// F1: 네이티브 브릿지의 positional XMM 미러(movq xmmN, rcx/rdx/r8/r9)와
/// FP 리턴 동기화(movq rax,xmm0 / movd eax,xmm0) 시퀀스가 코드에 존재하는지.
#[test]
fn test_bridge_emits_xmm_mirror_and_fp_return() {
    use crate::vm::poly::PolymorphicDecoder;
    let seed = 0x13579BDF2468ACE0u64;
    let mut d = RiscDesynthesizer::new();
    d.instrs
        .push(MicroInstr::new(RiscOp::VirtualPush).with_src1(MicroOperand::Imm64(0x140001002)));
    d.instrs.push(
        MicroInstr::new(RiscOp::VirtualBranch {
            cond: BranchCondition::Always,
        })
        .with_src1(MicroOperand::VReg(0)),
    );
    d.instrs.push(MicroInstr::new(RiscOp::Halt));
    let prog = RiscProgram::new(d.instrs);

    let mut enc = PolymorphicEncoder::new(seed);
    let bytecode = enc.encode(&prog).unwrap();

    let code_off = 0x1000usize;
    let table_off = 0x8000usize;
    let bytecode_off = 0x9000usize;
    let state_off = 0xA000usize;
    let mut arena = Arena::new(ARENA_SIZE).unwrap();
    let base = arena.base;
    let code_va = (base + code_off) as u64;
    let table_va = (base + table_off) as u64;
    let bytecode_va = (base + bytecode_off) as u64;
    let state_va = (base + state_off) as u64;
    let stack_base = (base + OFF_STACK_BASE) as u64;

    let parts = build_self_decoding_parts(
        &bytecode,
        seed,
        code_va,
        table_va,
        bytecode_va,
        state_va,
        stack_base,
    )
    .expect("build parts");

    let mut mir = [false; 4];
    let mut ret_movq = false;
    let mut ret_movd = false;
    let mut dec =
        iced_x86::Decoder::with_ip(64, &parts.code, code_va, iced_x86::DecoderOptions::NONE);
    while dec.can_decode() {
        let ins = dec.decode();
        match ins.code() {
            Code::Movq_xmm_rm64 => {
                for (i, gpr) in [Register::RCX, Register::RDX, Register::R8, Register::R9]
                    .iter()
                    .enumerate()
                {
                    if ins.op1_register() == *gpr {
                        mir[i] = true;
                    }
                }
            }
            Code::Movq_rm64_xmm => ret_movq = true, // f64 return sync
            Code::Movd_rm32_xmm => ret_movd = true, // f32 return sync
            _ => {}
        }
    }
    assert!(
        mir.iter().all(|&b| b),
        "bridge must mirror regs[1..4] -> XMM0-3 (mir={mir:?})"
    );
    assert!(
        ret_movq && ret_movd,
        "bridge must support FP return sync (movq rax,xmm0 + movd eax,xmm0)"
    );
}

/// Differential: native self-decoding Divide/IDivide == interpreter ==

/// reference, unsigned/signed across widths — quotient -> dst, remainder ->

/// RDX (regs[2], w>=2), width-1 AX packing, and div-by-zero -> 0.

#[test]

fn test_poly_direct_divide_matches_reference() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();

        // Load all operands first (interpreter starts from zero regs).

        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(1000),
            MicroOperand::Imm64(0),
        );

        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(0),
            MicroOperand::Imm64(0),
        );

        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(7),
            MicroOperand::Imm64(0),
        );

        d.emit_add(
            MicroOperand::VReg(5),
            MicroOperand::Imm64((-3i64) as u64),
            MicroOperand::Imm64(0),
        );

        d.emit_add(
            MicroOperand::VReg(6),
            MicroOperand::Imm64(0),
            MicroOperand::Imm64(0),
        );

        // Clean flag base (divide does not touch flags).

        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0)));

        // unsigned DIV r64: R0=1000, R2(RDX)=0, divisor R1=7 -> q=142, r=6.

        d.instrs.push(
            MicroInstr::new(RiscOp::Divide {
                signed: false,
                width: 8,
            })
            .with_dst(MicroOperand::VReg(0))
            .with_src1(MicroOperand::VReg(1)),
        );

        // Re-arm RAX/RDX for the IDIV (the DIV above overwrote R0=142, R2=6):

        // R0=1000 (low), R2=0 (high). Dst R3 holds the quotient.

        d.instrs.push(
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::VReg(0))
                .with_src1(MicroOperand::Imm64(1000)),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::Imm64(0)),
        );

        d.emit_add(
            MicroOperand::VReg(3),
            MicroOperand::Imm64(0),
            MicroOperand::Imm64(0),
        );

        // signed IDIV r32: R0=1000, R2(RDX)=0, divisor R5=-3 -> q=-333, r=1.

        d.instrs.push(
            MicroInstr::new(RiscOp::Divide {
                signed: true,
                width: 4,
            })
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::VReg(5)),
        );

        // div-by-zero: divisor 0 -> 0 (dst stays 0, regs[2]=0).

        d.instrs.push(
            MicroInstr::new(RiscOp::Divide {
                signed: false,
                width: 8,
            })
            .with_dst(MicroOperand::VReg(6))
            .with_src1(MicroOperand::VReg(6)),
        );

        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);

        let mut enc = PolymorphicEncoder::new(seed);

        let bytecode = enc.encode(&prog).unwrap();

        let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16]).unwrap();

        let mut interp = PolymorphicInterpreter::new(seed);

        interp.run(&bytecode).unwrap();

        let ref_st = prog.eval_state(&[0u64; 16]);

        assert_eq!(
            native.regs, ref_st.regs,
            "seed {seed:#x}: div native regs != ref"
        );

        assert_eq!(
            interp.regs, ref_st.regs,
            "seed {seed:#x}: div interp regs != ref"
        );

        assert_eq!(
            native.temps, ref_st.temps,
            "seed {seed:#x}: div native temps != ref"
        );

        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: div native flags {:#x} != ref {:#x}",
            native.flags, ref_st.flags
        );

        assert_eq!(
            interp.flags.raw, ref_st.flags,
            "seed {seed:#x}: div interp flags != ref"
        );

        assert_eq!(native.regs[0], 1000, "seed {seed:#x}: R0 re-armed for IDIV");

        assert_eq!(
            native.regs[3] as i32, -333,
            "seed {seed:#x}: IDIV w4 quotient wrong"
        );

        // div-by-zero runs last and clears regs[2] (RDX) to 0.

        assert_eq!(
            native.regs[2], 0,
            "seed {seed:#x}: IDIV w4 remainder lost / div-by-zero clears regs[2]"
        );

        assert_eq!(
            native.regs[6], 0,
            "seed {seed:#x}: div-by-zero must yield 0"
        );

        assert_eq!(
            native.regs[2], 0,
            "seed {seed:#x}: div-by-zero clears regs[2]"
        );
    }
}

/// P2 differential: BSwap / BitScanForward/Reverse / TZCNT / LZCNT / PopCount

/// native self-decoding handlers == eval_state (regs/temps/flags/vsp/stack).

#[test]

fn test_native_poly_direct_bitscan_count_popcnt_matches_reference() {
    let seeds = [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789];

    for seed in seeds {
        let mut d = RiscDesynthesizer::new();

        // BSWAP r64

        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x0102_0304_0506_0708),
            MicroOperand::Imm64(0),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::BSwap { width: 8 })
                .with_dst(MicroOperand::VReg(8))
                .with_src1(MicroOperand::VReg(0)),
        );

        // BSWAP r32 (low 32 bits swapped, high bits discarded)

        d.instrs.push(
            MicroInstr::new(RiscOp::BSwap { width: 4 })
                .with_dst(MicroOperand::VReg(9))
                .with_src1(MicroOperand::VReg(0)),
        );

        // BSF / BSR

        d.emit_add(
            MicroOperand::VReg(3),
            MicroOperand::Imm64(0x1000),
            MicroOperand::Imm64(0),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::BitScanForward)
                .with_dst(MicroOperand::VReg(4))
                .with_src1(MicroOperand::VReg(3)),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::BitScanReverse)
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(3)),
        );

        // BSF src==0 -> ZF=1, dst=0

        d.instrs.push(
            MicroInstr::new(RiscOp::BitScanForward)
                .with_dst(MicroOperand::VReg(6))
                .with_src1(MicroOperand::Imm64(0)),
        );

        // TZCNT / LZCNT across widths, incl. width-truncated-zero (bit above width)

        d.emit_add(
            MicroOperand::VReg(7),
            MicroOperand::Imm64(0x8000_0000_0000_1000),
            MicroOperand::Imm64(0),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::CountTrailingZeros { width: 8 })
                .with_dst(MicroOperand::Temp(0))
                .with_src1(MicroOperand::VReg(7)),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::CountLeadingZeros { width: 8 })
                .with_dst(MicroOperand::Temp(1))
                .with_src1(MicroOperand::VReg(7)),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::CountTrailingZeros { width: 4 })
                .with_dst(MicroOperand::Temp(2))
                .with_src1(MicroOperand::VReg(7)),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::CountLeadingZeros { width: 4 })
                .with_dst(MicroOperand::Temp(3))
                .with_src1(MicroOperand::VReg(7)),
        );

        // width 2 with low 16 bits == 0 -> dst=16, CF=1, ZF=1

        d.instrs.push(
            MicroInstr::new(RiscOp::CountTrailingZeros { width: 2 })
                .with_dst(MicroOperand::Temp(4))
                .with_src1(MicroOperand::VReg(7)),
        );

        // LZCNT w2 on odd low value

        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(1),
            MicroOperand::Imm64(0),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::CountLeadingZeros { width: 2 })
                .with_dst(MicroOperand::Temp(5))
                .with_src1(MicroOperand::VReg(0)),
        );

        // POPCNT (even popcount -> PF set) and POPCNT(0) -> ZF=1

        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(0xFF),
            MicroOperand::Imm64(0),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::PopCount)
                .with_dst(MicroOperand::Temp(6))
                .with_src1(MicroOperand::VReg(1)),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::PopCount)
                .with_dst(MicroOperand::Temp(7))
                .with_src1(MicroOperand::Imm64(0)),
        );

        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);

        let init = [0u64; 16];

        let mut enc = PolymorphicEncoder::new(seed);

        let bytecode = enc.encode(&prog).unwrap();

        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();

        let ref_st = prog.eval_state(&init);

        assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: regs");

        assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: temps");

        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: flags ref={:#x} native={:#x}",
            ref_st.flags, native.flags
        );

        assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: vsp");

        assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: stack");

        assert_eq!(
            native.regs[8], 0x0807_0605_0403_0201,
            "seed {seed:#x}: bswap64"
        );

        assert_eq!(native.regs[9], 0x0807_0605, "seed {seed:#x}: bswap32");

        assert_eq!(native.regs[4], 12, "seed {seed:#x}: bsf(0x1000)");

        assert_eq!(native.regs[5], 12, "seed {seed:#x}: bsr(0x1000)");

        assert_eq!(native.regs[6], 0, "seed {seed:#x}: bsf(0)");
    }
}

/// Differential: native self-decoding VirtualBranch (taken/not-taken, forward

/// and backward rolling-key re-sync) == eval_state. Absolute-index targets (no

/// ip_map): a forward Always branch skips an instruction, then a backward

/// NotZero loop runs until a counter reaches 3. This validates DEC_COND

/// taken/not-taken and the rolling-key re-sync against the reference simulator.

#[test]

fn test_poly_direct_virtual_branch_forward_reverse_matches_reference() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();

        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(10),
            MicroOperand::Imm64(0),
        ); // idx0: R0=10

        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(0),
            MicroOperand::Imm64(0),
        ); // idx1: R1=0

        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(0),
            MicroOperand::Imm64(0),
        ); // idx2: R2=0

        // idx3: forward Always branch -> idx5 (skips idx4)

        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            })
            .with_imm(5),
        );

        d.emit_add(
            MicroOperand::VReg(3),
            MicroOperand::Imm64(99),
            MicroOperand::Imm64(0),
        ); // idx4: skipped

        d.emit_add(
            MicroOperand::VReg(4),
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
        ); // idx5: R4 = R0+R1

        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::VReg(1),
            MicroOperand::Imm64(1),
        ); // idx6: R1 = R1+1

        d.emit_sub(
            MicroOperand::VReg(5),
            MicroOperand::VReg(1),
            MicroOperand::Imm64(3),
        ); // idx7: R5 = R1-3

        // idx8: backward NotZero branch -> idx6 (loop until R1==3)

        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::NotZero,
            })
            .with_imm(6),
        );

        d.emit_add(
            MicroOperand::VReg(6),
            MicroOperand::Imm64(777),
            MicroOperand::Imm64(0),
        ); // idx9: post-loop

        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);

        let init = [0u64; 16];

        let ref_st = prog.eval_state(&init);

        let mut enc = PolymorphicEncoder::new(seed);

        let bytecode = enc.encode(&prog).unwrap();

        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();

        assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: regs");

        assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: temps");

        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: flags (nat={:#x} ref={:#x})",
            native.flags, ref_st.flags
        );

        assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: vsp");

        assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: stack");

        assert_eq!(
            native.regs[3], 0,
            "seed {seed:#x}: forward branch must skip idx4"
        );

        assert_eq!(native.regs[1], 3, "seed {seed:#x}: loop counter reached 3");

        assert_eq!(native.regs[4], 10, "seed {seed:#x}: R4 = R0+R1");

        assert_eq!(native.regs[6], 777, "seed {seed:#x}: post-loop reached");
    }
}

/// Differential: native self-decoding VirtualBranch with ip_map (source-IP ->

/// program index) resolution == eval_state. The absolute-index target is a

/// source-IP that ip_map maps to a program index; the branch map resolves it to

/// a bytecode byte offset and re-syncs the key.

#[test]

fn test_poly_direct_virtual_branch_ipmap_resolution_matches_reference() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();

        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(5),
            MicroOperand::Imm64(0),
        ); // idx0: R0=5

        // idx1: absolute-index target = source-IP 0x140001000+4 (idx4, forward)

        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::NotZero,
            })
            .with_imm(0x140001000 + 4),
        );

        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(99),
            MicroOperand::Imm64(0),
        ); // idx2: skipped

        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(55),
            MicroOperand::Imm64(0),
        ); // idx3: skipped

        d.emit_add(
            MicroOperand::VReg(3),
            MicroOperand::VReg(0),
            MicroOperand::VReg(0),
        ); // idx4: R3 = R0+R0

        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let mut ip_map = HashMap::new();

        for i in 0..6 {
            ip_map.insert(0x140001000u64 + i as u64, i);
        }

        let prog = RiscProgram::with_ip_map(d.instrs, ip_map.clone());

        let init = [0u64; 16];

        let ref_st = prog.eval_state(&init);

        let mut enc = PolymorphicEncoder::new(seed);

        let bytecode = enc.encode(&prog).unwrap();

        let native = run_native_poly_direct_with(&bytecode, seed, &init, Some(&ip_map)).unwrap();

        assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: regs");

        assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: temps");

        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: flags (nat={:#x} ref={:#x})",
            native.flags, ref_st.flags
        );

        assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: vsp");

        assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: stack");

        assert_eq!(native.regs[3], 10, "seed {seed:#x}: ip_map target reached");

        assert_eq!(native.regs[1], 0, "seed {seed:#x}: idx2 skipped");

        assert_eq!(native.regs[2], 0, "seed {seed:#x}: idx3 skipped");
    }
}

/// Cond-byte decode foundation: the cond-codes table built from the spec's

/// branch_cond_map must map every BranchCondition's encoded byte to the

/// canonical COND_* code (and unknown bytes to COND_INVALID). This is the

/// table `sub_dec_ops_cond` reads to decode the cond byte of

/// VirtualBranch/Setcc/ConditionalMove into the DEC_COND state slot.

#[test]

fn test_cond_codes_table_matches_branch_cond_map() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let spec = VirtualIsaSpec::from_seed(seed);

        let parts =
            build_self_decoding_parts(&[], seed, 0x100000, 0x200000, 0x300000, 0x400000, 0x500000)
                .unwrap();

        // Every encoded cond byte -> its canonical code; everything else invalid.

        for (cond, &byte) in &spec.branch_cond_map {
            assert_eq!(
                parts.cond_codes[byte as usize],
                cond_code(*cond),
                "seed {seed:#x}: cond {cond:?} (byte {byte:#04x}) code mismatch"
            );
        }

        for raw in 0u16..256 {
            let raw = raw as u8;

            if !spec.branch_cond_map.values().any(|&b| b == raw) {
                assert_eq!(
                    parts.cond_codes[raw as usize], COND_INVALID,
                    "seed {seed:#x}: stray byte {raw:#04x} must be invalid"
                );
            }
        }

        // cond_code() is injective across the 22 supported conditions.

        let mut seen = std::collections::HashSet::new();

        for cond in spec.branch_cond_map.keys() {
            assert!(
                seen.insert(cond_code(*cond)),
                "seed {seed:#x}: dup code for {cond:?}"
            );
        }
    }
}

/// Differential: native self-decoding Setcc / ConditionalMove == interpreter ==

/// reference across every condition code and several flag patterns (CF/PF/ZF/

/// SF/OF combos) plus the CounterZero (regs[1]) conditions. Setcc writes a

/// full-width 0/1 with no flag change; ConditionalMove stores src1 only when

/// the condition holds. Each is exercised on the cond byte decoded via

/// sub_dec_ops_cond into the DEC_COND slot.

#[test]

fn test_native_poly_direct_setcc_cmov_diff() {
    // flag patterns covering CF(0x1)/PF(0x4)/ZF(0x40)/SF(0x80)/OF(0x800) combos.

    let flag_patterns: [u64; 12] = [
        0x0, 0x1, 0x4, 0x40, 0x80, 0x800, 0x41, 0xC0, 0x880, 0x8C1, 0x8C5, 0x8D5,
    ];

    let conds: [BranchCondition; 22] = [
        BranchCondition::Always,
        BranchCondition::Zero,
        BranchCondition::NotZero,
        BranchCondition::Carry,
        BranchCondition::NotCarry,
        BranchCondition::Sign,
        BranchCondition::NotSign,
        BranchCondition::Overflow,
        BranchCondition::NotOverflow,
        BranchCondition::Greater,
        BranchCondition::Less,
        BranchCondition::GreaterOrEqual,
        BranchCondition::LessOrEqual,
        BranchCondition::Above,
        BranchCondition::AboveOrEqual,
        BranchCondition::Below,
        BranchCondition::BelowOrEqual,
        BranchCondition::Parity,
        BranchCondition::NotParity,
        BranchCondition::CounterZero(2),
        BranchCondition::CounterZero(4),
        BranchCondition::CounterZero(8),
    ];

    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();

        // R1 = nonzero counter (CounterZero false), zeroed later for the true path.

        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(0x1234),
            MicroOperand::Imm64(0),
        );

        // Setcc: sweep every condition against every flag pattern into regs 4..6

        // (spread + reused so overwrites are exercised too).

        for (pi, &flags) in flag_patterns.iter().enumerate() {
            d.instrs
                .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(flags)));

            for (ci, &cond) in conds.iter().enumerate() {
                d.instrs.push(
                    MicroInstr::new(RiscOp::Setcc { cond })
                        .with_dst(MicroOperand::VReg((4 + ((pi * 22 + ci) % 3)) as u8)),
                );
            }
        }

        // ConditionalMove: taken / not-taken / always across several conds.

        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x40))); // ZF

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::Zero,
            })
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::VReg(1)),
        ); // taken

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::NotZero,
            })
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::VReg(1)),
        ); // not taken

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::Above,
            })
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::VReg(1)),
        ); // ZF -> not taken

        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x1))); // CF

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::Below,
            })
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::VReg(1)),
        ); // taken

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::NotCarry,
            })
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::VReg(1)),
        ); // not taken

        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x800))); // OF

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::Less,
            })
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::VReg(1)),
        ); // SF!=OF -> taken

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::GreaterOrEqual,
            })
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::VReg(1)),
        ); // not taken

        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x880))); // SF|OF

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::Greater,
            })
            .with_dst(MicroOperand::VReg(8))
            .with_src1(MicroOperand::VReg(1)),
        ); // SF==OF && !ZF -> taken

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::Less,
            })
            .with_dst(MicroOperand::VReg(8))
            .with_src1(MicroOperand::VReg(1)),
        ); // not taken

        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x4))); // PF

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::Parity,
            })
            .with_dst(MicroOperand::VReg(8))
            .with_src1(MicroOperand::VReg(1)),
        ); // taken

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::NotParity,
            })
            .with_dst(MicroOperand::VReg(8))
            .with_src1(MicroOperand::VReg(1)),
        ); // not taken

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::Always,
            })
            .with_dst(MicroOperand::VReg(8))
            .with_src1(MicroOperand::VReg(1)),
        ); // taken

        // CounterZero true path: zero R1 (Mov imm0) then test all widths.

        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0)));

        d.instrs.push(
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::Imm64(0)),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::Setcc {
                cond: BranchCondition::CounterZero(2),
            })
            .with_dst(MicroOperand::VReg(10)),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::Setcc {
                cond: BranchCondition::CounterZero(4),
            })
            .with_dst(MicroOperand::VReg(11)),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::Setcc {
                cond: BranchCondition::CounterZero(8),
            })
            .with_dst(MicroOperand::VReg(12)),
        );

        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove {
                cond: BranchCondition::CounterZero(8),
            })
            .with_dst(MicroOperand::VReg(13))
            .with_src1(MicroOperand::VReg(2)),
        );

        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);

        let mut enc = PolymorphicEncoder::new(seed);

        let bytecode = enc.encode(&prog).unwrap();

        let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16]).unwrap();

        let mut interp = PolymorphicInterpreter::new(seed);

        interp.run(&bytecode).unwrap();

        let ref_st = prog.eval_state(&[0u64; 16]);

        assert_eq!(
            native.regs, ref_st.regs,
            "seed {seed:#x}: native regs != ref"
        );

        assert_eq!(
            interp.regs, ref_st.regs,
            "seed {seed:#x}: interp regs != ref"
        );

        assert_eq!(
            native.temps, ref_st.temps,
            "seed {seed:#x}: native temps != ref"
        );

        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: native flags {:#x} != ref {:#x}",
            native.flags, ref_st.flags
        );

        assert_eq!(
            interp.flags.raw, ref_st.flags,
            "seed {seed:#x}: interp flags != ref"
        );

        assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: native vsp != ref");

        assert_eq!(
            native.stack, ref_st.stack,
            "seed {seed:#x}: native stack != ref"
        );

        // concrete sanity: after zeroing R1, CounterZero(8) setcc writes 1.

        assert_eq!(
            ref_st.regs[12], 1,
            "seed {seed:#x}: CounterZero(8) setcc should be 1"
        );
    }
}

/// R4: SSE/FPU 스칼라 — FloatAdd/Sub/Mul/Div{4,8} + IntToFloat/FloatToInt/
/// FloatToFloat 네이티브 self-decoding 핸들러 == 폴리 인터프리터 == eval_state
/// (참조). 모든 reachable src/dst_bits·truncate 조합을 3 seeds 로 차등 검증한다.
#[test]
fn test_poly_direct_float_matches_reference() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();
        let f32bits = |x: f32| (x.to_bits() as u64);
        let f64bits = |x: f64| x.to_bits();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(f32bits(2.5)),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(f32bits(1.5)),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(f64bits(3.0)),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(3),
            MicroOperand::Imm64(f64bits(1.25)),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(4),
            MicroOperand::Imm64((-7i64) as u64),
            MicroOperand::Imm64(0),
        );
        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x200)));
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatAdd { width: 4 })
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatMul { width: 8 })
                .with_dst(MicroOperand::VReg(6))
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::VReg(3)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatDiv { width: 8 })
                .with_dst(MicroOperand::VReg(7))
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::VReg(3)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatSub { width: 4 })
                .with_dst(MicroOperand::VReg(8))
                .with_src1(MicroOperand::VReg(1))
                .with_src2(MicroOperand::VReg(0)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::IntToFloat {
                src_bits: 8,
                dst_bits: 8,
            })
            .with_dst(MicroOperand::VReg(9))
            .with_src1(MicroOperand::VReg(4)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::IntToFloat {
                src_bits: 4,
                dst_bits: 4,
            })
            .with_dst(MicroOperand::VReg(10))
            .with_src1(MicroOperand::VReg(4)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatToFloat {
                src_bits: 4,
                dst_bits: 8,
            })
            .with_dst(MicroOperand::VReg(11))
            .with_src1(MicroOperand::VReg(0)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatToFloat {
                src_bits: 8,
                dst_bits: 4,
            })
            .with_dst(MicroOperand::VReg(12))
            .with_src1(MicroOperand::VReg(2)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatToInt {
                src_bits: 4,
                dst_bits: 4,
                truncate: false,
            })
            .with_dst(MicroOperand::VReg(13))
            .with_src1(MicroOperand::VReg(0)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatToInt {
                src_bits: 4,
                dst_bits: 4,
                truncate: true,
            })
            .with_dst(MicroOperand::VReg(14))
            .with_src1(MicroOperand::VReg(0)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatToInt {
                src_bits: 8,
                dst_bits: 4,
                truncate: true,
            })
            .with_dst(MicroOperand::VReg(15))
            .with_src1(MicroOperand::VReg(6)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        let init = [0u64; 16];

        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.run(&bytecode).unwrap();
        let ref_st = prog.eval_state(&init);

        assert_eq!(
            native.regs, ref_st.regs,
            "seed {seed:#x}: float native regs != ref"
        );
        assert_eq!(
            interp.regs, ref_st.regs,
            "seed {seed:#x}: float interp regs != ref"
        );
        assert_eq!(
            native.temps, ref_st.temps,
            "seed {seed:#x}: float native temps != ref"
        );
        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: float native flags != ref"
        );
        assert_eq!(
            interp.flags.raw, ref_st.flags,
            "seed {seed:#x}: float interp flags != ref"
        );

        assert_eq!(ref_st.regs[5], f32bits(4.0), "seed {seed:#x}: FloatAdd32");
        assert_eq!(ref_st.regs[6], f64bits(3.75), "seed {seed:#x}: FloatMul64");
        assert_eq!(ref_st.regs[7], f64bits(2.4), "seed {seed:#x}: FloatDiv64");
        assert_eq!(ref_st.regs[8], f32bits(-1.0), "seed {seed:#x}: FloatSub32");
        assert_eq!(
            ref_st.regs[9],
            f64bits(-7.0),
            "seed {seed:#x}: IntToFloat64"
        );
        assert_eq!(
            ref_st.regs[10],
            f32bits(-7.0),
            "seed {seed:#x}: IntToFloat32"
        );
        assert_eq!(
            ref_st.regs[11],
            f64bits(2.5),
            "seed {seed:#x}: FloatToFloat 4->8"
        );
        assert_eq!(
            ref_st.regs[12],
            f32bits(3.0),
            "seed {seed:#x}: FloatToFloat 8->4"
        );
        assert_eq!(
            ref_st.regs[13], 2,
            "seed {seed:#x}: FloatToInt32 round-half-even 2.5"
        );
        assert_eq!(ref_st.regs[14], 2, "seed {seed:#x}: FloatToInt32 trunc 2.5");
        assert_eq!(
            ref_st.regs[15], 3,
            "seed {seed:#x}: FloatToInt32 trunc 3.75"
        );
    }
}

/// R4: FloatToInt 부동-정수 변환의 특수값 — NaN / ±Inf / out-of-range 가
/// "integer indefinite" (0x8000_0000 / 0x8000_0000_0000_0000) 을 생성하는지
/// eval_state(참조)와 네이티브가 동치인지 차등 검증한다.
#[test]
fn test_poly_direct_float_to_int_special_values_matches_reference() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x7FC0_0000),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(0x7F80_0000),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(2),
            MicroOperand::Imm64(f64::INFINITY.to_bits()),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(3),
            MicroOperand::Imm64(f64::NAN.to_bits()),
            MicroOperand::Imm64(0),
        );
        d.instrs
            .push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0)));
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatToInt {
                src_bits: 4,
                dst_bits: 4,
                truncate: true,
            })
            .with_dst(MicroOperand::VReg(4))
            .with_src1(MicroOperand::VReg(0)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatToInt {
                src_bits: 4,
                dst_bits: 4,
                truncate: true,
            })
            .with_dst(MicroOperand::VReg(5))
            .with_src1(MicroOperand::VReg(1)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatToInt {
                src_bits: 8,
                dst_bits: 8,
                truncate: true,
            })
            .with_dst(MicroOperand::VReg(6))
            .with_src1(MicroOperand::VReg(2)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::FloatToInt {
                src_bits: 8,
                dst_bits: 8,
                truncate: true,
            })
            .with_dst(MicroOperand::VReg(7))
            .with_src1(MicroOperand::VReg(3)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        let init = [0u64; 16];

        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.run(&bytecode).unwrap();
        let ref_st = prog.eval_state(&init);

        assert_eq!(
            native.regs, ref_st.regs,
            "seed {seed:#x}: special native regs != ref"
        );
        assert_eq!(
            interp.regs, ref_st.regs,
            "seed {seed:#x}: special interp regs != ref"
        );
        assert_eq!(
            native.flags, ref_st.flags,
            "seed {seed:#x}: special native flags != ref"
        );
        assert_eq!(
            ref_st.regs[4], 0x8000_0000,
            "seed {seed:#x}: f32 NaN -> i32 indefinite"
        );
        assert_eq!(
            ref_st.regs[5], 0x8000_0000,
            "seed {seed:#x}: f32 +Inf -> i32 indefinite"
        );
        assert_eq!(
            ref_st.regs[6], 0x8000_0000_0000_0000,
            "seed {seed:#x}: f64 +Inf -> i64 indefinite"
        );
        assert_eq!(
            ref_st.regs[7], 0x8000_0000_0000_0000,
            "seed {seed:#x}: f64 NaN -> i64 indefinite"
        );
    }
}

/// P6-3: handler-restore prevention — the dispatch table must NOT be
/// decryptable with a single XOR constant. For every registered opcode byte,
/// `table[byte] ^ per_op_key(master, byte)` recovers the handler VA inside the
/// code region, while `table[byte] ^ master` (the old P6-1 single-key restore)
/// must NOT land inside the code region — each entry uses a distinct key derived
/// from the opcode byte itself, so a dumped/restored table cannot be un-XORed
/// wholesale.
#[test]
fn test_table_not_restorable_by_single_xor() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        // Build a small program so the table has real registered handlers.
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x200),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(5),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();

        let code_base = 0x100000u64;
        let parts = build_self_decoding_parts(
            &bytecode, seed, code_base, 0x200000, 0x300000, 0x400000, 0x500000,
        )
        .unwrap();
        let code_lo = code_base;
        let code_hi = code_base + parts.code.len() as u64;
        let master = parts.table_key;

        let spec = VirtualIsaSpec::from_seed(seed);
        let mut checked = 0usize;
        for (op, &byte) in &spec.opcode_map {
            let v = parts.table[byte as usize];
            // per-opcode key decrypts into the code region (real handler VA).
            let dec = v ^ per_op_key(master, byte);
            assert!(
                    (code_lo..code_hi).contains(&dec),
                    "seed {seed:#x}: op {op:?} per-opkey decode {dec:#x} outside [{code_lo:#x},{code_hi:#x})"
                );
            // single master XOR must NOT land in the code region (P6-1 restore fails).
            let naive = v ^ master;
            assert!(
                !(code_lo..code_hi).contains(&naive),
                "seed {seed:#x}: op {op:?} single-XOR restore leaked handler VA {naive:#x}"
            );
            checked += 1;
        }
        assert!(checked > 0, "seed {seed:#x}: no registered ops to check");
        // The master key itself never appears as a table value.
        for &v in parts.table.iter() {
            assert_ne!(v, master, "seed {seed:#x}: master key leaked in table");
        }
    }
}

/// P6-3: unused opcode bytes must decode to a shared trap handler (ud2) — not the
/// old h_nop no-op fallback — so probing an unmapped byte faults instead of
/// silently continuing. All unused slots decode to the same VA, and that VA is
/// inside the code region but distinct from every registered handler VA.
#[test]
fn test_unused_opcode_slots_decode_to_trap() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x200),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();

        let code_base = 0x100000u64;
        let parts = build_self_decoding_parts(
            &bytecode, seed, code_base, 0x200000, 0x300000, 0x400000, 0x500000,
        )
        .unwrap();
        let code_hi = code_base + parts.code.len() as u64;
        let master = parts.table_key;

        let spec = VirtualIsaSpec::from_seed(seed);
        let mut used: Vec<u8> = Vec::new();
        for &byte in spec.opcode_map.values() {
            used.push(byte);
        }
        let mut trap_va: Option<u64> = None;
        let mut count = 0usize;
        for byte in 0u16..256 {
            let byte = byte as u8;
            if used.contains(&byte) {
                continue;
            }
            let dec = parts.table[byte as usize] ^ per_op_key(master, byte);
            match trap_va {
                None => trap_va = Some(dec),
                Some(t) => assert_eq!(
                    t, dec,
                    "seed {seed:#x}: unused slot {byte:#04x} not the shared trap VA"
                ),
            }
            assert!(
                (code_base..code_hi).contains(&dec),
                "seed {seed:#x}: unused slot {byte:#04x} trap VA {dec:#x} outside code region"
            );
            count += 1;
        }
        // The canonical ISA grows as formerly native-only instructions become
        // virtualizable. Keep a meaningful trap reserve without freezing the
        // old opcode cardinality as a false invariant.
        assert!(
            count >= 64,
            "seed {seed:#x}: expected at least 64 unused trap slots, got {count}"
        );
        // The trap VA must differ from every registered handler VA.
        let trap = trap_va.unwrap();
        for (op, &byte) in &spec.opcode_map {
            let dec = parts.table[byte as usize] ^ per_op_key(master, byte);
            if *op == RiscOp::Trap {
                assert!((code_base..code_hi).contains(&dec));
                continue;
            }
            assert_ne!(
                trap, dec,
                "seed {seed:#x}: op {op:?} decodes to the trap VA"
            );
        }
    }
}

/// P6-3: the table integrity self-check embedded in the entry stub must be
/// patched with exactly `table_checksum(table)`. This is what lets the runtime
/// detect a patched/restored table (mismatch -> ud2 at VM entry).
#[test]
fn test_table_checksum_matches_builtin() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x200),
            MicroOperand::Imm64(0),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let parts = build_self_decoding_parts(
            &bytecode, seed, 0x100000, 0x200000, 0x300000, 0x400000, 0x500000,
        )
        .unwrap();
        let expect = table_checksum_with_topology(&parts.table, parts.table_integrity_topology);
        assert_eq!(
            parts.table_checksum, expect,
            "seed {seed:#x}: checksum mismatch"
        );
        assert_ne!(
            parts.table_checksum, 0x1234_5678,
            "seed {seed:#x}: placeholder not patched"
        );
    }
}

#[test]
fn table_integrity_topology_is_distinct_per_family() {
    use crate::vm::poly::VmArchitectureFamily;
    use std::collections::HashSet;

    let topologies: HashSet<_> = VmArchitectureFamily::ALL
        .into_iter()
        .map(TableIntegrityTopology::for_family)
        .collect();
    assert_eq!(topologies.len(), VmArchitectureFamily::ALL.len());
}

/// P6-3: per-opcode keys must be injective over the 256 possible opcode bytes so
/// no two entries share a key (a collision would let a single-XOR attack recover
/// that pair). The dispatch loop recomputes the same key from the opcode byte.
#[test]
fn test_per_opcode_keys_injective() {
    for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
        let mut d = RiscDesynthesizer::new();
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let parts = build_self_decoding_parts(
            &bytecode, seed, 0x100000, 0x200000, 0x300000, 0x400000, 0x500000,
        )
        .unwrap();
        let master = parts.table_key;
        let mut seen = std::collections::HashSet::new();
        for op in 0u16..256 {
            let k = per_op_key(master, op as u8);
            assert!(
                seen.insert(k),
                "seed {seed:#x}: key collision at opcode {op:#04x} ({k:#x})"
            );
        }
    }
}
