// ==============================================================================
// VM self-test submodule: flags.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use rand::RngCore;
use anyhow::{Result, anyhow};
use crate::vm::{bytecode, handlers, interp};
use iced_x86::{Code, Instruction, Register};
use crate::vm::{build_vm_module};
use crate::vm::arena::{Arena};
use crate::vm::encode::{encode_trampoline};


pub(crate) fn run_flags_jcc_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::flags;

    let mut rng = rand::thread_rng();
    let pairs: Vec<(u32, u32)> = (0..24).map(|_| (rng.next_u32(), rng.next_u32())).collect();

    // Reusable native VM module + trampoline in one RWX arena.
    let mut arena = Arena::new(0x30000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x5800;
    let bc_va = arena.base + 0x5000;
    let state_va = arena.base + 0x6000;
    let tramp_va = arena.base + 0x7000;
    let module = build_vm_module(
        code_va as u64,
        table_va as u64,
        bc_va as u64,
        vec![0u8; 64],
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(
        state_va as u64,
        code_va as u64,
        code_va as u64,
        code_va as u64,
        tramp_va as u64,
    )?;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x5800..0x5800 + module.table.len()].copy_from_slice(&module.table);
        b[0x7000..0x7000 + tramp.len()].copy_from_slice(&tramp);
    }

    // Run `prog` through the interpreter and the native VM; both must agree on
    // the flag slot and all vregs. Returns (flags, vregs).
    let mut run_prog = |prog: &[u8]| -> (u64, [u64; 16]) {
        // interpreter
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 16];
        interp::interpret(&mut st, &mut mem, prog).unwrap();
        let flags_i = u64::from_le_bytes(st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8].try_into().unwrap());
        let mut vregs_i = [0u64; 16];
        for i in 0..16 {
            vregs_i[i] = u64::from_le_bytes(st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
        }
        // native
        {
            let b = arena.bytes();
            b[0x5000..0x5000 + prog.len()].copy_from_slice(prog);
            b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
        }
        arena.call(0x7000);
        let b = arena.bytes();
        let sf = 0x6000usize; // state buffer base within the arena
        let flags_n = u64::from_le_bytes(b[sf + interp::STATE_FLAGS..sf + interp::STATE_FLAGS + 8].try_into().unwrap());
        let mut vregs_n = [0u64; 16];
        for i in 0..16 {
            vregs_n[i] = u64::from_le_bytes(b[sf + interp::STATE_VREGS + i * 8..sf + interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
        }
        assert_eq!(flags_i, flags_n, "interp vs native flags mismatch (interp=0x{:X} native=0x{:X}) prog:\n{}", flags_i, flags_n, crate::vm::bytecode::disassemble(prog));
        assert_eq!(vregs_i, vregs_n, "interp vs native vregs mismatch");
        (flags_i, vregs_i)
    };

    // 1) flag-setting ops (interp == native == flags.rs reference)
    for &(a, b) in &pairs {
        for (op, expect) in [
            (OP_ADD_R_R, flags::add_flags(a, b)),
            (OP_SUB_R_R, flags::sub_flags(a, b)),
            (OP_XOR_R_R, flags::logical_flags(a ^ b)),
            (OP_AND_R_R, flags::logical_flags(a & b)),
        ] {
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.mov_r_imm32(1, b);
            bc.binop_r_r(op, 0, 1);
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, expect & FLAG_MASK, "binop 0x{:02X} a=0x{:X} b=0x{:X}", op, a, b);
        }
        for (op, expect) in [
            (OP_ADD_R_IMM32, flags::add_flags(a, b)),
            (OP_XOR_R_IMM32, flags::logical_flags(a ^ b)),
            (OP_AND_R_IMM32, flags::logical_flags(a & b)),
        ] {
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.binop_r_imm32(op, 0, b);
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, expect & FLAG_MASK, "immop 0x{:02X} a=0x{:X} b=0x{:X}", op, a, b);
        }
        {
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.cmp_r_imm32(0, b);
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, flags::sub_flags(a, b) & FLAG_MASK, "cmp a=0x{:X} b=0x{:X}", a, b);
        }
        {
            let mut bci = BytecodeBuilder::new();
            bci.mov_r_imm32(0, a);
            bci.inc_r(0);
            bci.halt();
            let (got, _) = run_prog(&bci.finish());
            assert_eq!(got & FLAG_MASK, flags::inc_flags(a, 0) & FLAG_MASK, "inc a=0x{:X}", a);

            let mut bcd = BytecodeBuilder::new();
            bcd.mov_r_imm32(0, a);
            bcd.dec_r(0);
            bcd.halt();
            let (got, _) = run_prog(&bcd.finish());
            assert_eq!(got & FLAG_MASK, flags::dec_flags(a, 0) & FLAG_MASK, "dec a=0x{:X}", a);
        }
    }

    // 2) All 16 Jcc conditions (incl. unsigned JA/JBE), with flags baseline = sub(a, b).
    let conds: [u8; 16] = [
        COND_JE, COND_JNE, COND_JB, COND_JAE, COND_JG, COND_JGE, COND_JL, COND_JLE,
        COND_JS, COND_JNS, COND_JO, COND_JNO, COND_JP, COND_JNP, COND_JA, COND_JBE,
    ];
    for &(a, b) in &pairs {
        let base_flags = flags::sub_flags(a, b);
        for (i, c) in conds.iter().enumerate() {
            // One vreg per condition would overflow the 16-vreg file with 16
            // conditions, so build a fresh tiny program per condition: reuse
            // v2 as the output scratch and read it immediately.
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.mov_r_imm32(1, b);
            bc.binop_r_r(OP_SUB_R_R, 0, 1);
            let skip = bc.new_label();
            // v2 = 1 if the condition is taken, else 0:
            //   mov v2, 1 ; jcc8 c, SKIP ; mov v2, 0 ; SKIP:
            bc.mov_r_imm32(2, 1);
            bc.jcc8(*c, skip);
            bc.mov_r_imm32(2, 0);
            bc.mark_label(skip);
            bc.halt();
            let (_, vregs) = run_prog(&bc.finish());
            let expected = if flags::cond_taken(*c, base_flags) { 1u64 } else { 0u64 };
            assert_eq!(vregs[2], expected, "cond {} a=0x{:X} b=0x{:X}", c, a, b);
        }
    }

    // 3) M2: 64-bit arithmetic + shifts + TEST (interp == native == flags::ref)
    {
        let mut rng2 = rand::thread_rng();
        let pairs64: Vec<(u64, u64)> = (0..12).map(|_| (rng2.next_u64(), rng2.next_u64())).collect();
        for &(a, b) in &pairs64 {
            for (op, expect) in [
                (OP_ADD_R_R64, flags::add_flags64(a, b)),
                (OP_SUB_R_R64, flags::sub_flags64(a, b)),
                (OP_XOR_R_R64, flags::logical_flags64(a ^ b)),
                (OP_AND_R_R64, flags::logical_flags64(a & b)),
            ] {
                let mut bc = BytecodeBuilder::new();
                bc.mov_r_imm64(0, a);
                bc.mov_r_imm64(1, b);
                bc.binop_r_r64(op, 0, 1);
                bc.halt();
                let (got, _) = run_prog(&bc.finish());
                assert_eq!(got & FLAG_MASK, expect & FLAG_MASK, "op64 0x{:02X} a=0x{:X} b=0x{:X}", op, a, b);
            }
            let imm32 = (b as u32).wrapping_add(0x1234_5AA5);
            let imm64 = (imm32 as i32) as i64 as u64;
            for (op, expect) in [
                (OP_ADD_R_IMM64, flags::add_flags64(a, imm64)),
                (OP_XOR_R_IMM64, flags::logical_flags64(a ^ imm64)),
                (OP_AND_R_IMM64, flags::logical_flags64(a & imm64)),
            ] {
                let mut bc = BytecodeBuilder::new();
                bc.mov_r_imm64(0, a);
                bc.binop_r_imm64(op, 0, imm32);
                bc.halt();
                let (got, _) = run_prog(&bc.finish());
                assert_eq!(got & FLAG_MASK, expect & FLAG_MASK, "imm64 0x{:02X} a=0x{:X} i=0x{:X}", op, a, imm32);
            }
        }
        // shifts (imm8 and CL); count in 1..=31 (count 0 leaves flags unchanged)
        for _ in 0..40 {
            let x = rng2.next_u32();
            let n = 1 + (rng2.next_u32() & 30);
            let cases: [(u8, u32, u64, u64, u64); 3] = [
                (OP_SHL_R_IMM8, n, x.wrapping_shl(n) as u64, flags::shift_flags(flags::ShiftKind::Shl, x, n, x.wrapping_shl(n)), flags::shift_flags(flags::ShiftKind::Shl, x, n, x.wrapping_shl(n))),
                (OP_SHR_R_IMM8, n, x.wrapping_shr(n) as u64, flags::shift_flags(flags::ShiftKind::Shr, x, n, x.wrapping_shr(n)), 0),
                (OP_SAR_R_IMM8, n, ((x as i32) >> n) as u32 as u64, flags::shift_flags(flags::ShiftKind::Sar, x, n, ((x as i32) >> n) as u32), 0),
            ];
            for (op, cnt, ev, ef, _) in cases {
                let mut bc = BytecodeBuilder::new();
                bc.mov_r_imm32(0, x);
                bc.shift_r_imm8(op, 0, cnt as u8);
                bc.halt();
                let (got, vregs) = run_prog(&bc.finish());
                assert_eq!(vregs[0], ev, "shift imm8 op=0x{:02X} x=0x{:X} n={}", op, x, n);
                assert_eq!(got & FLAG_MASK, ef & FLAG_MASK, "shift imm8 fl op=0x{:02X} x=0x{:X} n={}", op, x, n);
            }
            // CL shifts (count in vreg[1])
            for (op, ev, ef) in [
                (OP_SHL_R_CL, x.wrapping_shl(n) as u64, flags::shift_flags(flags::ShiftKind::Shl, x, n, x.wrapping_shl(n))),
                (OP_SHR_R_CL, x.wrapping_shr(n) as u64, flags::shift_flags(flags::ShiftKind::Shr, x, n, x.wrapping_shr(n))),
                (OP_SAR_R_CL, ((x as i32) >> n) as u32 as u64, flags::shift_flags(flags::ShiftKind::Sar, x, n, ((x as i32) >> n) as u32)),
            ] {
                let mut bc = BytecodeBuilder::new();
                bc.mov_r_imm32(0, x);
                bc.mov_r_imm32(1, n);
                bc.shift_r_cl(op, 0);
                bc.halt();
                let (got, vregs) = run_prog(&bc.finish());
                assert_eq!(vregs[0], ev, "shift cl op=0x{:02X} x=0x{:X} n={}", op, x, n);
                assert_eq!(got & FLAG_MASK, ef & FLAG_MASK, "shift cl fl op=0x{:02X} x=0x{:X} n={}", op, x, n);
            }
        }
        // count == 0 → RFLAGS 불변 (x86: shl/shr/sar count 0 은 flags 유지).
        // 이전 버그: native handler 가 count==0 에도 `and ecx, mask`/디스패처가
        // 세운 플래그를 capture 해 STATE_FLAGS 를 덮어썼다 (interp 와 차등 불일치).
        for (op, kind) in [
            (OP_SHL_R_IMM8, flags::ShiftKind::Shl),
            (OP_SHR_R_IMM8, flags::ShiftKind::Shr),
            (OP_SAR_R_IMM8, flags::ShiftKind::Sar),
        ] {
            let x = 0x9ABC_DE01u32;
            let expect = flags::shift_flags(
                kind,
                x,
                1,
                match kind {
                    flags::ShiftKind::Shl => x.wrapping_shl(1),
                    flags::ShiftKind::Shr => x.wrapping_shr(1),
                    flags::ShiftKind::Sar => ((x as i32) >> 1) as u32,
                },
            );
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, x);
            bc.shift_r_imm8(op, 0, 1); // flags 세팅 (count 1)
            bc.shift_r_imm8(op, 0, 0); // count==0 → flags 불변
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, expect & FLAG_MASK, "count==0 shift must preserve flags (imm8 0x{:02X})", op);
        }
        for (op, kind) in [
            (OP_SHL_R_CL, flags::ShiftKind::Shl),
            (OP_SHR_R_CL, flags::ShiftKind::Shr),
            (OP_SAR_R_CL, flags::ShiftKind::Sar),
        ] {
            let x = 0x9ABC_DE01u32;
            let expect = flags::shift_flags(
                kind,
                x,
                1,
                match kind {
                    flags::ShiftKind::Shl => x.wrapping_shl(1),
                    flags::ShiftKind::Shr => x.wrapping_shr(1),
                    flags::ShiftKind::Sar => ((x as i32) >> 1) as u32,
                },
            );
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, x);
            bc.mov_r_imm32(1, 1);
            bc.shift_r_cl(op, 0); // flags 세팅 (count 1)
            bc.mov_r_imm32(1, 0);
            bc.shift_r_cl(op, 0); // count==0 → flags 불변
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, expect & FLAG_MASK, "count==0 shift must preserve flags (cl 0x{:02X})", op);
        }
        // TEST (rr and imm)
        for _ in 0..16 {
            let (a, b) = (rng2.next_u32(), rng2.next_u32());
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.mov_r_imm32(1, b);
            bc.test_r_r32(0, 1);
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, flags::logical_flags(a & b) & FLAG_MASK, "test rr a=0x{:X} b=0x{:X}", a, b);

            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm32(0, a);
            bc.test_r_imm32(0, b);
            bc.halt();
            let (got, _) = run_prog(&bc.finish());
            assert_eq!(got & FLAG_MASK, flags::logical_flags(a & b) & FLAG_MASK, "test imm a=0x{:X} b=0x{:X}", a, b);
        }
    }

    Ok(())
}


/// [34] carry/width-flag regression — locks in the P0/P1 fixes:
///   1. `lift_sbb` must read the INCOMING CF (not the current SUB's borrow),
///      so `sbb dst,src` = dst - src - CF_in for every CF_in/dst/src combo.
///   2. XADD 8/16-bit flags must be width-correct (native `lock xadd [addr],al/ax`
///      sets CF/SF/OF/AF from the 8/16-bit boundary, not bit 31).
///   3. CMPXCHG must preserve the non-ZF flags (native handler captures only ZF).
pub(crate) fn run_carry_flag_fix_test() -> anyhow::Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::interp::{STATE_FLAGS, STATE_VREGS};
    use crate::vm::lifter::lift_one;
    use iced_x86::{Code, Instruction, Register};

    let mut st = vec![0u8; interp::STATE_SIZE];
    let vreg = |idx: usize| STATE_VREGS + idx * 8;
    let set_v = |s: &mut [u8], i: usize, v: u64| s[vreg(i)..vreg(i) + 8].copy_from_slice(&v.to_le_bytes());
    let get_v = |s: &[u8], i: usize| u64::from_le_bytes(s[vreg(i)..vreg(i) + 8].try_into().unwrap());
    let set_cf = |s: &mut [u8], on: bool| {
        let f = u64::from_le_bytes(s[STATE_FLAGS..STATE_FLAGS + 8].try_into().unwrap());
        let nf = if on { f | F_CF } else { f & !F_CF };
        s[STATE_FLAGS..STATE_FLAGS + 8].copy_from_slice(&nf.to_le_bytes());
    };
    let flags = |s: &[u8]| u64::from_le_bytes(s[STATE_FLAGS..STATE_FLAGS + 8].try_into().unwrap());

    // 1) SBB incoming-CF
    for (cf_in, rax, rbx) in [
        (1u64, 0u64, 0u64),      // 0-0-1 = -1
        (0u64, 5u64, 8u64),      // 5-8-0 = -3  (current sub borrows, but CF_in=0)
        (1u64, 5u64, 3u64),      // 5-3-1 = 1
        (1u64, 0x100u64, 0u64),  // 0x100-0-1 = 0xFF
        (0u64, 0xFFu64, 0xFFu64),// 0xFF-0xFF-0 = 0
    ] {
        let inst = Instruction::with2(Code::Sbb_r64_rm64, Register::RAX, Register::RBX).unwrap();
        let mut b = BytecodeBuilder::new();
        lift_one(&mut b, &inst)?;
        b.halt();
        let code = b.finish();
        st.fill(0);
        set_v(&mut st, 0, rax);
        set_v(&mut st, 3, rbx);
        set_cf(&mut st, cf_in != 0);
        let mut mem = vec![0u8; 0x1000];
        interp::interpret(&mut st, &mut mem, &code)?;
        let got = get_v(&st, 0);
        let real = rax.wrapping_sub(rbx).wrapping_sub(cf_in);
        if got != real {
            return Err(anyhow!("[34] SBB: cf_in={} rax=0x{:X} rbx=0x{:X} got 0x{:X} want 0x{:X}", cf_in, rax, rbx, got, real));
        }
    }

    // 2) XADD 8/16 width flags
    for (w, op, a_lo, addend) in [(8u64, OP_XADD_MEM8_A, 0xFFu64, 1u64), (16u64, OP_XADD_MEM16_A, 0xFFFFu64, 1u64)] {
        let mut bc = BytecodeBuilder::new();
        bc.mem_xadd_a(op, 15, 14);
        bc.halt();
        let code = bc.finish();
        st.fill(0);
        let addr = 0x8000usize;
        set_v(&mut st, 15, addr as u64);
        set_v(&mut st, 14, addend as u64);
        let mut mem = vec![0u8; 0x10000];
        if w == 8 { mem[addr] = a_lo as u8; } else { mem[addr..addr + 2].copy_from_slice(&(a_lo as u16).to_le_bytes()); }
        interp::interpret(&mut st, &mut mem, &code)?;
        let (z, c) = if w == 8 {
            let a = a_lo as u8; let s = addend as u8; let r = a.wrapping_add(s);
            (r == 0, ((a as u32) + (s as u32)) > 0xFF)
        } else {
            let a = a_lo as u16; let s = addend as u16; let r = a.wrapping_add(s);
            (r == 0, ((a as u32) + (s as u32)) > 0xFFFF)
        };
        let fl = flags(&st);
        if (fl & F_ZF != 0) != z || (fl & F_CF != 0) != c {
            return Err(anyhow!("[34] XADD{} flags wrong: got ZF={} CF={} want ZF={} CF={}", w, fl & F_ZF != 0, fl & F_CF != 0, z, c));
        }
    }

    // 3) CMPXCHG flag preservation (CF must survive a successful 8-bit CAS)
    {
        let mut b = BytecodeBuilder::new();
        b.mem_cmpxchg_a(OP_CMPXCHG_MEM8_A, 15, 14);
        b.halt();
        let code = b.finish();
        st.fill(0);
        let addr = 0x8000usize;
        set_v(&mut st, 15, addr as u64);
        set_v(&mut st, 14, 0x22);
        set_v(&mut st, 0, 0xDEAD_0000_0000_0011); // RAX low byte = expected 0x11
        let mut mem = vec![0u8; 0x10000];
        mem[addr] = 0x11;
        set_cf(&mut st, true);
        interp::interpret(&mut st, &mut mem, &code)?;
        if flags(&st) & F_CF == 0 {
            return Err(anyhow!("[34] CMPXCHG must preserve CF across a successful CAS"));
        }
    }

    Ok(())
}
