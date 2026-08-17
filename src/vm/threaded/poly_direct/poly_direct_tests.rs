// ==============================================================================
// BTG - Native Self-Decoding Dispatcher: tests - split from poly_direct.rs
// ==============================================================================

    use super::*;

    use crate::vm::poly::{PolymorphicEncoder, PolymorphicInterpreter};

    use crate::vm::risc::RiscDesynthesizer;

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
        d.instrs.push(MicroInstr::new(RiscOp::Mov).with_dst(MicroOperand::VReg(1)).with_src1(MicroOperand::Imm64(0x2B992DDFA232)));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        let init = [0u64; 16];

        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789, 0xBADF00D] {
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();

            let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();
            let mut interp = PolymorphicInterpreter::new(seed);
            interp.run(&bytecode).unwrap();
            let ref_st = prog.eval_state(&init);

            assert_eq!(native.regs[0], 0x14003F140, "seed {seed:#x}: AddWithCarry(imm,imm) address");
            assert_eq!(native.regs[1], 0x2B992DDFA232, "seed {seed:#x}: Mov(imm64) after two-imm op");
            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: native vs reference regs");
            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: interpreter vs reference regs");
        }
    }



    /// Differential: native self-decoding == interpreter == reference.

    #[test]

    fn test_native_poly_direct_matches_interpreter_and_reference() {

        let mut d = RiscDesynthesizer::new();

        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x200), MicroOperand::Imm64(0));

        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(5), MicroOperand::Imm64(0));

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

        d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)));

        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);



        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {

            let mut enc = PolymorphicEncoder::new(seed);

            let bytecode = enc.encode(&prog).unwrap();



            let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16]).unwrap();



            let mut interp = PolymorphicInterpreter::new(seed);

            interp.run(&bytecode).unwrap();



            let ref_st = prog.eval_state(&[0u64; 16]);



            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: native regs != ref");

            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: interp regs != ref");

            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: native temps != ref");

            assert_eq!(

                native.flags, ref_st.flags,

                "seed {seed:#x}: native flags {:#x} != ref {:#x}",

                native.flags, ref_st.flags

            );

            assert_eq!(interp.flags.raw, ref_st.flags, "seed {seed:#x}: interp flags != ref");

            assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: native vsp != ref");

            assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: native stack != ref");

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

        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(1200), MicroOperand::Imm64(0));

        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(450), MicroOperand::Imm64(0));

        d.emit_sub(MicroOperand::VReg(0), MicroOperand::VReg(0), MicroOperand::VReg(1));

        d.emit_xor(MicroOperand::VReg(0), MicroOperand::VReg(0), MicroOperand::Imm64(0x55));

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

            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x200), MicroOperand::Imm64(0));

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

            d.emit_add(MicroOperand::VReg(6), MicroOperand::VReg(0), MicroOperand::Imm64(1));

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

            assert_eq!(ref_st.regs[1], 0, "seed {seed:#x}: bridge wrote dst VReg(1)");

            assert_eq!(ref_st.regs[2], 0, "seed {seed:#x}: bridge wrote dst VReg(2)");

            assert_eq!(ref_st.regs[6], 0x201, "seed {seed:#x}: post-bridge op not reached");



            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: native regs != ref");

            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: interp regs != ref");

            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: native temps != ref");

            assert_eq!(

                native.flags, ref_st.flags,

                "seed {seed:#x}: native flags {:#x} != ref {:#x}",

                native.flags, ref_st.flags

            );

            assert_eq!(interp.flags.raw, ref_st.flags, "seed {seed:#x}: interp flags != ref");

            assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: native vsp != ref");

            assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: native stack != ref");

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

                &bytecode, seed, code_va, table_va, bytecode_va, state_va, stack_base,

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

                buf[OFF_OP_OFFS..OFF_OP_OFFS + 256].copy_from_slice(&parts.offs_tab);

                buf[OFF_OP_FLAGS..OFF_OP_FLAGS + 256].copy_from_slice(&parts.flags_tab);

                buf[bytecode_off..bytecode_off + bytecode.len()].copy_from_slice(&bytecode);

            }



            let old: u64 = 0xFEDC_BA98_7654_3210;

            let scenarios: [(&str, u64, u64, bool); 2] = [

                ("success", old, old, true),

                ("failure", old ^ 0x1, old, false),

            ];

            for (label, acc, old, success) in scenarios {

                let mask = if width == 8 { u64::MAX } else { (1u64 << (width * 8)) - 1 };



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

                        buf[state_off + REGS_OFF as usize + i * 8..state_off + REGS_OFF as usize + i * 8 + 8]

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

                nat.flags = u64::from_le_bytes(buf[s + FLAGS_OFF as usize..s + FLAGS_OFF as usize + 8].try_into().unwrap());

                nat.vsp = u64::from_le_bytes(buf[s + VSP_OFF as usize..s + VSP_OFF as usize + 8].try_into().unwrap());



                assert_eq!(nat.regs, ref_st.regs, "w{width} {label}: regs mismatch (nat={:?} ref={:?})", nat.regs, ref_st.regs);

                assert_eq!(nat.flags, ref_st.flags, "w{width} {label}: flags nat={:#x} ref={:#x}", nat.flags, ref_st.flags);

                assert_eq!(nat.temps, ref_st.temps, "w{width} {label}: temps mismatch");

                assert_eq!(nat.vsp, ref_st.vsp, "w{width} {label}: vsp mismatch");



                // memory side-effect: width low bytes written/unchanged == reference.

                let nat_mem = u64::from_le_bytes(buf[window_off..window_off + 8].try_into().unwrap());

                let mut ref_mem = 0u64;

                for k in 0..width as usize {

                    ref_mem |= (*ref_st.mem.get(&addr.wrapping_add(k as u64)).unwrap_or(&0) as u64) << (k * 8);

                }

                assert_eq!(nat_mem & mask, ref_mem, "w{width} {label}: mem mismatch nat={:#x} ref={:#x}", nat_mem & mask, ref_mem);

                assert_eq!(

                    nat_mem & mask,

                    if success { newv & mask } else { old & mask },

                    "w{width} {label}: mem side-effect wrong (expect {:#x})",

                    if success { newv & mask } else { old & mask }

                );

                assert_eq!(nat.flags & 0x40 != 0, success, "w{width} {label}: ZF wrong (nat.flags={:#x})", nat.flags);

            }

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

            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x1_0000_0001), MicroOperand::Imm64(0));

            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(3), MicroOperand::Imm64(0));

            d.emit_add(MicroOperand::VReg(3), MicroOperand::Imm64(0x7FFF_FFFF), MicroOperand::Imm64(0));

            d.emit_add(MicroOperand::VReg(4), MicroOperand::Imm64(0xFF), MicroOperand::Imm64(0));

            // Clean flag base: isolates the multiply CF/OF handling from the

            // AddWithCarry setup (native h_add preserves PF/AF instead of recomputing).

            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0)));

            // unsigned MUL r64: R0=0x1_0000_0001, R1=3 -> RDX:RAX, low->R0, high->R2.

            d.instrs.push(

                MicroInstr::new(RiscOp::Multiply { signed: false, width: 8 })

                    .with_dst(MicroOperand::VReg(0))

                    .with_src1(MicroOperand::VReg(0))

                    .with_src2(MicroOperand::VReg(1)),

            );

            // signed IMUL r32 (MultiplyLow): 0x7FFFFFFF * 2 = 0xFFFFFFFE, CF=OF=1.

            d.instrs.push(

                MicroInstr::new(RiscOp::MultiplyLow { signed: true, width: 4 })

                    .with_dst(MicroOperand::VReg(6))

                    .with_src1(MicroOperand::VReg(3))

                    .with_src2(MicroOperand::Imm64(2)),

            );

            // signed IMUL r8 (Multiply width 1): 0xFF * 0xFF -> AX = 0xFE01, CF=OF=1.

            d.instrs.push(

                MicroInstr::new(RiscOp::Multiply { signed: true, width: 1 })

                    .with_dst(MicroOperand::VReg(7))

                    .with_src1(MicroOperand::VReg(4))

                    .with_src2(MicroOperand::VReg(4)),

            );

            d.instrs.push(MicroInstr::new(RiscOp::Halt));

            let prog = RiscProgram::new(d.instrs);



            let mut enc = PolymorphicEncoder::new(seed);

            let bytecode = enc.encode(&prog).unwrap();

            let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16]).unwrap();

            let mut interp = PolymorphicInterpreter::new(seed);

            interp.run(&bytecode).unwrap();

            let ref_st = prog.eval_state(&[0u64; 16]);



            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: mul native regs != ref");

            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: mul interp regs != ref");

            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: mul native temps != ref");

            assert_eq!(

                native.flags, ref_st.flags,

                "seed {seed:#x}: mul native flags {:#x} != ref {:#x}",

                native.flags, ref_st.flags

            );

            assert_eq!(interp.flags.raw, ref_st.flags, "seed {seed:#x}: mul interp flags != ref");

            assert_eq!(native.regs[0], 0x3_0000_0003, "seed {seed:#x}: MUL low wrong");

            assert_eq!(native.regs[2], 0, "seed {seed:#x}: MUL high wrong");

            assert_eq!(native.regs[6], 0xFFFF_FFFE, "seed {seed:#x}: IMUL low wrong");

            assert_eq!(native.regs[7], 0xFE01, "seed {seed:#x}: IMUL r8 AX pack wrong");

            assert_eq!(native.flags & 0x801, 0x801, "seed {seed:#x}: CF|OF not set");

        }

    }



    /// Differential: native self-decoding Divide/IDivide == interpreter ==

    /// reference, unsigned/signed across widths — quotient -> dst, remainder ->

    /// RDX (regs[2], w>=2), width-1 AX packing, and div-by-zero -> 0.

    #[test]

    fn test_poly_direct_divide_matches_reference() {

        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {

            let mut d = RiscDesynthesizer::new();

            // Load all operands first (interpreter starts from zero regs).

            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(1000), MicroOperand::Imm64(0));

            d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64(0), MicroOperand::Imm64(0));

            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(7), MicroOperand::Imm64(0));

            d.emit_add(MicroOperand::VReg(5), MicroOperand::Imm64((-3i64) as u64), MicroOperand::Imm64(0));

            d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(0), MicroOperand::Imm64(0));

            // Clean flag base (divide does not touch flags).

            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0)));

            // unsigned DIV r64: R0=1000, R2(RDX)=0, divisor R1=7 -> q=142, r=6.

            d.instrs.push(

                MicroInstr::new(RiscOp::Divide { signed: false, width: 8 })

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

            d.emit_add(MicroOperand::VReg(3), MicroOperand::Imm64(0), MicroOperand::Imm64(0));

            // signed IDIV r32: R0=1000, R2(RDX)=0, divisor R5=-3 -> q=-333, r=1.

            d.instrs.push(

                MicroInstr::new(RiscOp::Divide { signed: true, width: 4 })

                    .with_dst(MicroOperand::VReg(3))

                    .with_src1(MicroOperand::VReg(5)),

            );

            // div-by-zero: divisor 0 -> 0 (dst stays 0, regs[2]=0).

            d.instrs.push(

                MicroInstr::new(RiscOp::Divide { signed: false, width: 8 })

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



            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: div native regs != ref");

            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: div interp regs != ref");

            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: div native temps != ref");

            assert_eq!(

                native.flags, ref_st.flags,

                "seed {seed:#x}: div native flags {:#x} != ref {:#x}",

                native.flags, ref_st.flags

            );

            assert_eq!(interp.flags.raw, ref_st.flags, "seed {seed:#x}: div interp flags != ref");

            assert_eq!(native.regs[0], 1000, "seed {seed:#x}: R0 re-armed for IDIV");

            assert_eq!(native.regs[3] as i32, -333, "seed {seed:#x}: IDIV w4 quotient wrong");

            // div-by-zero runs last and clears regs[2] (RDX) to 0.

            assert_eq!(native.regs[2], 0, "seed {seed:#x}: IDIV w4 remainder lost / div-by-zero clears regs[2]");

            assert_eq!(native.regs[6], 0, "seed {seed:#x}: div-by-zero must yield 0");

            assert_eq!(native.regs[2], 0, "seed {seed:#x}: div-by-zero clears regs[2]");

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

            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x0102_0304_0506_0708), MicroOperand::Imm64(0));

            d.instrs.push(MicroInstr::new(RiscOp::BSwap { width: 8 }).with_dst(MicroOperand::VReg(8)).with_src1(MicroOperand::VReg(0)));

            // BSWAP r32 (low 32 bits swapped, high bits discarded)

            d.instrs.push(MicroInstr::new(RiscOp::BSwap { width: 4 }).with_dst(MicroOperand::VReg(9)).with_src1(MicroOperand::VReg(0)));

            // BSF / BSR

            d.emit_add(MicroOperand::VReg(3), MicroOperand::Imm64(0x1000), MicroOperand::Imm64(0));

            d.instrs.push(MicroInstr::new(RiscOp::BitScanForward).with_dst(MicroOperand::VReg(4)).with_src1(MicroOperand::VReg(3)));

            d.instrs.push(MicroInstr::new(RiscOp::BitScanReverse).with_dst(MicroOperand::VReg(5)).with_src1(MicroOperand::VReg(3)));

            // BSF src==0 -> ZF=1, dst=0

            d.instrs.push(MicroInstr::new(RiscOp::BitScanForward).with_dst(MicroOperand::VReg(6)).with_src1(MicroOperand::Imm64(0)));

            // TZCNT / LZCNT across widths, incl. width-truncated-zero (bit above width)

            d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(0x8000_0000_0000_1000), MicroOperand::Imm64(0));

            d.instrs.push(MicroInstr::new(RiscOp::CountTrailingZeros { width: 8 }).with_dst(MicroOperand::Temp(0)).with_src1(MicroOperand::VReg(7)));

            d.instrs.push(MicroInstr::new(RiscOp::CountLeadingZeros { width: 8 }).with_dst(MicroOperand::Temp(1)).with_src1(MicroOperand::VReg(7)));

            d.instrs.push(MicroInstr::new(RiscOp::CountTrailingZeros { width: 4 }).with_dst(MicroOperand::Temp(2)).with_src1(MicroOperand::VReg(7)));

            d.instrs.push(MicroInstr::new(RiscOp::CountLeadingZeros { width: 4 }).with_dst(MicroOperand::Temp(3)).with_src1(MicroOperand::VReg(7)));

            // width 2 with low 16 bits == 0 -> dst=16, CF=1, ZF=1

            d.instrs.push(MicroInstr::new(RiscOp::CountTrailingZeros { width: 2 }).with_dst(MicroOperand::Temp(4)).with_src1(MicroOperand::VReg(7)));

            // LZCNT w2 on odd low value

            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(1), MicroOperand::Imm64(0));

            d.instrs.push(MicroInstr::new(RiscOp::CountLeadingZeros { width: 2 }).with_dst(MicroOperand::Temp(5)).with_src1(MicroOperand::VReg(0)));

            // POPCNT (even popcount -> PF set) and POPCNT(0) -> ZF=1

            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(0xFF), MicroOperand::Imm64(0));

            d.instrs.push(MicroInstr::new(RiscOp::PopCount).with_dst(MicroOperand::Temp(6)).with_src1(MicroOperand::VReg(1)));

            d.instrs.push(MicroInstr::new(RiscOp::PopCount).with_dst(MicroOperand::Temp(7)).with_src1(MicroOperand::Imm64(0)));

            d.instrs.push(MicroInstr::new(RiscOp::Halt));



            let prog = RiscProgram::new(d.instrs);

            let init = [0u64; 16];

            let mut enc = PolymorphicEncoder::new(seed);

            let bytecode = enc.encode(&prog).unwrap();

            let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();

            let ref_st = prog.eval_state(&init);



            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: regs");

            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: temps");

            assert_eq!(native.flags, ref_st.flags, "seed {seed:#x}: flags ref={:#x} native={:#x}", ref_st.flags, native.flags);

            assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: vsp");

            assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: stack");

            assert_eq!(native.regs[8], 0x0807_0605_0403_0201, "seed {seed:#x}: bswap64");

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

            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(10), MicroOperand::Imm64(0)); // idx0: R0=10

            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(0), MicroOperand::Imm64(0));  // idx1: R1=0

            d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64(0), MicroOperand::Imm64(0));  // idx2: R2=0

            // idx3: forward Always branch -> idx5 (skips idx4)

            d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::Always }).with_imm(5));

            d.emit_add(MicroOperand::VReg(3), MicroOperand::Imm64(99), MicroOperand::Imm64(0)); // idx4: skipped

            d.emit_add(MicroOperand::VReg(4), MicroOperand::VReg(0), MicroOperand::VReg(1));     // idx5: R4 = R0+R1

            d.emit_add(MicroOperand::VReg(1), MicroOperand::VReg(1), MicroOperand::Imm64(1));    // idx6: R1 = R1+1

            d.emit_sub(MicroOperand::VReg(5), MicroOperand::VReg(1), MicroOperand::Imm64(3));    // idx7: R5 = R1-3

            // idx8: backward NotZero branch -> idx6 (loop until R1==3)

            d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::NotZero }).with_imm(6));

            d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(777), MicroOperand::Imm64(0)); // idx9: post-loop

            d.instrs.push(MicroInstr::new(RiscOp::Halt));

            let prog = RiscProgram::new(d.instrs);

            let init = [0u64; 16];

            let ref_st = prog.eval_state(&init);



            let mut enc = PolymorphicEncoder::new(seed);

            let bytecode = enc.encode(&prog).unwrap();

            let native = run_native_poly_direct(&bytecode, seed, &init).unwrap();



            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: regs");

            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: temps");

            assert_eq!(native.flags, ref_st.flags, "seed {seed:#x}: flags (nat={:#x} ref={:#x})", native.flags, ref_st.flags);

            assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: vsp");

            assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: stack");

            assert_eq!(native.regs[3], 0, "seed {seed:#x}: forward branch must skip idx4");

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

            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(5), MicroOperand::Imm64(0));   // idx0: R0=5

            // idx1: absolute-index target = source-IP 0x140001000+4 (idx4, forward)

            d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::NotZero }).with_imm(0x140001000 + 4));

            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(99), MicroOperand::Imm64(0));  // idx2: skipped

            d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64(55), MicroOperand::Imm64(0));  // idx3: skipped

            d.emit_add(MicroOperand::VReg(3), MicroOperand::VReg(0), MicroOperand::VReg(0));     // idx4: R3 = R0+R0

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

            assert_eq!(native.flags, ref_st.flags, "seed {seed:#x}: flags (nat={:#x} ref={:#x})", native.flags, ref_st.flags);

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

            let parts = build_self_decoding_parts(

                &[],

                seed,

                0x100000,

                0x200000,

                0x300000,

                0x400000,

                0x500000,

            )

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

                        parts.cond_codes[raw as usize],

                        COND_INVALID,

                        "seed {seed:#x}: stray byte {raw:#04x} must be invalid"

                    );

                }

            }

            // cond_code() is injective across the 22 supported conditions.

            let mut seen = std::collections::HashSet::new();

            for cond in spec.branch_cond_map.keys() {

                assert!(seen.insert(cond_code(*cond)), "seed {seed:#x}: dup code for {cond:?}");

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

            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(0x1234), MicroOperand::Imm64(0));

            // Setcc: sweep every condition against every flag pattern into regs 4..6

            // (spread + reused so overwrites are exercised too).

            for (pi, &flags) in flag_patterns.iter().enumerate() {

                d.instrs.push(

                    MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(flags)),

                );

                for (ci, &cond) in conds.iter().enumerate() {

                    d.instrs.push(

                        MicroInstr::new(RiscOp::Setcc { cond })

                            .with_dst(MicroOperand::VReg((4 + ((pi * 22 + ci) % 3)) as u8)),

                    );

                }

            }

            // ConditionalMove: taken / not-taken / always across several conds.

            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x40))); // ZF

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::Zero })

                .with_dst(MicroOperand::VReg(7)).with_src1(MicroOperand::VReg(1))); // taken

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::NotZero })

                .with_dst(MicroOperand::VReg(7)).with_src1(MicroOperand::VReg(1))); // not taken

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::Above })

                .with_dst(MicroOperand::VReg(7)).with_src1(MicroOperand::VReg(1))); // ZF -> not taken

            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x1))); // CF

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::Below })

                .with_dst(MicroOperand::VReg(7)).with_src1(MicroOperand::VReg(1))); // taken

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::NotCarry })

                .with_dst(MicroOperand::VReg(7)).with_src1(MicroOperand::VReg(1))); // not taken

            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x800))); // OF

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::Less })

                .with_dst(MicroOperand::VReg(7)).with_src1(MicroOperand::VReg(1))); // SF!=OF -> taken

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::GreaterOrEqual })

                .with_dst(MicroOperand::VReg(7)).with_src1(MicroOperand::VReg(1))); // not taken

            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x880))); // SF|OF

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::Greater })

                .with_dst(MicroOperand::VReg(8)).with_src1(MicroOperand::VReg(1))); // SF==OF && !ZF -> taken

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::Less })

                .with_dst(MicroOperand::VReg(8)).with_src1(MicroOperand::VReg(1))); // not taken

            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x4))); // PF

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::Parity })

                .with_dst(MicroOperand::VReg(8)).with_src1(MicroOperand::VReg(1))); // taken

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::NotParity })

                .with_dst(MicroOperand::VReg(8)).with_src1(MicroOperand::VReg(1))); // not taken

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::Always })

                .with_dst(MicroOperand::VReg(8)).with_src1(MicroOperand::VReg(1))); // taken

            // CounterZero true path: zero R1 (Mov imm0) then test all widths.

            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0)));

            d.instrs.push(MicroInstr::new(RiscOp::Mov)

                .with_dst(MicroOperand::VReg(1)).with_src1(MicroOperand::Imm64(0)));

            d.instrs.push(MicroInstr::new(RiscOp::Setcc { cond: BranchCondition::CounterZero(2) })

                .with_dst(MicroOperand::VReg(10)));

            d.instrs.push(MicroInstr::new(RiscOp::Setcc { cond: BranchCondition::CounterZero(4) })

                .with_dst(MicroOperand::VReg(11)));

            d.instrs.push(MicroInstr::new(RiscOp::Setcc { cond: BranchCondition::CounterZero(8) })

                .with_dst(MicroOperand::VReg(12)));

            d.instrs.push(MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::CounterZero(8) })

                .with_dst(MicroOperand::VReg(13)).with_src1(MicroOperand::VReg(2)));

            d.instrs.push(MicroInstr::new(RiscOp::Halt));

            let prog = RiscProgram::new(d.instrs);



            let mut enc = PolymorphicEncoder::new(seed);

            let bytecode = enc.encode(&prog).unwrap();



            let native = run_native_poly_direct(&bytecode, seed, &[0u64; 16]).unwrap();

            let mut interp = PolymorphicInterpreter::new(seed);

            interp.run(&bytecode).unwrap();

            let ref_st = prog.eval_state(&[0u64; 16]);



            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: native regs != ref");

            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: interp regs != ref");

            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: native temps != ref");

            assert_eq!(

                native.flags, ref_st.flags,

                "seed {seed:#x}: native flags {:#x} != ref {:#x}",

                native.flags, ref_st.flags

            );

            assert_eq!(interp.flags.raw, ref_st.flags, "seed {seed:#x}: interp flags != ref");

            assert_eq!(native.vsp, ref_st.vsp, "seed {seed:#x}: native vsp != ref");

            assert_eq!(native.stack, ref_st.stack, "seed {seed:#x}: native stack != ref");

            // concrete sanity: after zeroing R1, CounterZero(8) setcc writes 1.

            assert_eq!(ref_st.regs[12], 1, "seed {seed:#x}: CounterZero(8) setcc should be 1");

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
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(f32bits(2.5)), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(f32bits(1.5)), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64(f64bits(3.0)), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(3), MicroOperand::Imm64(f64bits(1.25)), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(4), MicroOperand::Imm64((-7i64) as u64), MicroOperand::Imm64(0));
            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x200)));
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
                MicroInstr::new(RiscOp::IntToFloat { src_bits: 8, dst_bits: 8 })
                    .with_dst(MicroOperand::VReg(9))
                    .with_src1(MicroOperand::VReg(4)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::IntToFloat { src_bits: 4, dst_bits: 4 })
                    .with_dst(MicroOperand::VReg(10))
                    .with_src1(MicroOperand::VReg(4)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::FloatToFloat { src_bits: 4, dst_bits: 8 })
                    .with_dst(MicroOperand::VReg(11))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::FloatToFloat { src_bits: 8, dst_bits: 4 })
                    .with_dst(MicroOperand::VReg(12))
                    .with_src1(MicroOperand::VReg(2)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::FloatToInt { src_bits: 4, dst_bits: 4, truncate: false })
                    .with_dst(MicroOperand::VReg(13))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::FloatToInt { src_bits: 4, dst_bits: 4, truncate: true })
                    .with_dst(MicroOperand::VReg(14))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::FloatToInt { src_bits: 8, dst_bits: 4, truncate: true })
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

            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: float native regs != ref");
            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: float interp regs != ref");
            assert_eq!(native.temps, ref_st.temps, "seed {seed:#x}: float native temps != ref");
            assert_eq!(native.flags, ref_st.flags, "seed {seed:#x}: float native flags != ref");
            assert_eq!(interp.flags.raw, ref_st.flags, "seed {seed:#x}: float interp flags != ref");

            assert_eq!(ref_st.regs[5], f32bits(4.0), "seed {seed:#x}: FloatAdd32");
            assert_eq!(ref_st.regs[6], f64bits(3.75), "seed {seed:#x}: FloatMul64");
            assert_eq!(ref_st.regs[7], f64bits(2.4), "seed {seed:#x}: FloatDiv64");
            assert_eq!(ref_st.regs[8], f32bits(-1.0), "seed {seed:#x}: FloatSub32");
            assert_eq!(ref_st.regs[9], f64bits(-7.0), "seed {seed:#x}: IntToFloat64");
            assert_eq!(ref_st.regs[10], f32bits(-7.0), "seed {seed:#x}: IntToFloat32");
            assert_eq!(ref_st.regs[11], f64bits(2.5), "seed {seed:#x}: FloatToFloat 4->8");
            assert_eq!(ref_st.regs[12], f32bits(3.0), "seed {seed:#x}: FloatToFloat 8->4");
            assert_eq!(ref_st.regs[13], 2, "seed {seed:#x}: FloatToInt32 round-half-even 2.5");
            assert_eq!(ref_st.regs[14], 2, "seed {seed:#x}: FloatToInt32 trunc 2.5");
            assert_eq!(ref_st.regs[15], 3, "seed {seed:#x}: FloatToInt32 trunc 3.75");
        }
    }

    /// R4: FloatToInt 부동-정수 변환의 특수값 — NaN / ±Inf / out-of-range 가
    /// "integer indefinite" (0x8000_0000 / 0x8000_0000_0000_0000) 을 생성하는지
    /// eval_state(참조)와 네이티브가 동치인지 차등 검증한다.
    #[test]
    fn test_poly_direct_float_to_int_special_values_matches_reference() {
        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut d = RiscDesynthesizer::new();
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x7FC0_0000), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(0x7F80_0000), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64(f64::INFINITY.to_bits()), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(3), MicroOperand::Imm64(f64::NAN.to_bits()), MicroOperand::Imm64(0));
            d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0)));
            d.instrs.push(
                MicroInstr::new(RiscOp::FloatToInt { src_bits: 4, dst_bits: 4, truncate: true })
                    .with_dst(MicroOperand::VReg(4))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::FloatToInt { src_bits: 4, dst_bits: 4, truncate: true })
                    .with_dst(MicroOperand::VReg(5))
                    .with_src1(MicroOperand::VReg(1)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::FloatToInt { src_bits: 8, dst_bits: 8, truncate: true })
                    .with_dst(MicroOperand::VReg(6))
                    .with_src1(MicroOperand::VReg(2)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::FloatToInt { src_bits: 8, dst_bits: 8, truncate: true })
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

            assert_eq!(native.regs, ref_st.regs, "seed {seed:#x}: special native regs != ref");
            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: special interp regs != ref");
            assert_eq!(native.flags, ref_st.flags, "seed {seed:#x}: special native flags != ref");
            assert_eq!(ref_st.regs[4], 0x8000_0000, "seed {seed:#x}: f32 NaN -> i32 indefinite");
            assert_eq!(ref_st.regs[5], 0x8000_0000, "seed {seed:#x}: f32 +Inf -> i32 indefinite");
            assert_eq!(ref_st.regs[6], 0x8000_0000_0000_0000, "seed {seed:#x}: f64 +Inf -> i64 indefinite");
            assert_eq!(ref_st.regs[7], 0x8000_0000_0000_0000, "seed {seed:#x}: f64 NaN -> i64 indefinite");
        }
    }
