// ==============================================================================
// VM self-test submodule: muldiv.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use crate::vm::arena::Arena;
use crate::vm::build_vm_module;
use crate::vm::encode::encode_trampoline;
use crate::vm::{bytecode, handlers, interp};
use anyhow::{anyhow, Result};
use rand::RngCore;

/// [20] A-2 (v31): 1-operand signed/unsigned multiply-divide + BSWAP.
/// Cross-checks the Rust interpreter against the native x86-64 handlers for the
/// new accumulator-pair opcodes (MUL/IMUL/DIV/IDIV 32/64) and BSWAP (32/64),
/// over random inputs. (div-by-zero is deliberately avoided.)
pub(crate) fn run_a2_muldiv_bswap_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut rng = rand::thread_rng();
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
        vec![0u8; 128],
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

    // run prog: set v0=rax(low), v2=rdx(high) and src vreg, run, compare interp vs native.
    let mut run_prog = |prog: &[u8], rax: u64, rdx: u64, src: u8, sval: u64| -> (u64, u64, u64) {
        // interpreter
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 64];
        st[interp::STATE_VREGS + 0 * 8..][..8].copy_from_slice(&rax.to_le_bytes());
        st[interp::STATE_VREGS + 2 * 8..][..8].copy_from_slice(&rdx.to_le_bytes());
        st[interp::STATE_VREGS + (src as usize) * 8..][..8].copy_from_slice(&sval.to_le_bytes());
        interp::interpret(&mut st, &mut mem, prog).unwrap();
        let i = (
            u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..][..8].try_into().unwrap()),
            u64::from_le_bytes(st[interp::STATE_VREGS + 2 * 8..][..8].try_into().unwrap()),
            u64::from_le_bytes(
                st[interp::STATE_VREGS + (src as usize) * 8..][..8]
                    .try_into()
                    .unwrap(),
            ),
        );
        // native
        {
            let b = arena.bytes();
            b[0x5000..0x5000 + prog.len()].copy_from_slice(prog);
            b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
            b[0x6000 + interp::STATE_VREGS + 0 * 8..][..8].copy_from_slice(&rax.to_le_bytes());
            b[0x6000 + interp::STATE_VREGS + 2 * 8..][..8].copy_from_slice(&rdx.to_le_bytes());
            b[0x6000 + interp::STATE_VREGS + (src as usize) * 8..][..8]
                .copy_from_slice(&sval.to_le_bytes());
        }
        arena.call(0x7000);
        let b = arena.bytes();
        let sf = 0x6000usize;
        let n = (
            u64::from_le_bytes(
                b[sf + interp::STATE_VREGS + 0 * 8..][..8]
                    .try_into()
                    .unwrap(),
            ),
            u64::from_le_bytes(
                b[sf + interp::STATE_VREGS + 2 * 8..][..8]
                    .try_into()
                    .unwrap(),
            ),
            u64::from_le_bytes(
                b[sf + interp::STATE_VREGS + (src as usize) * 8..][..8]
                    .try_into()
                    .unwrap(),
            ),
        );
        assert_eq!(
            i,
            n,
            "[20] interp vs native mismatch\n{}",
            crate::vm::bytecode::disassemble(prog)
        );
        i
    };

    // MUL32: EDX:EAX = EAX * src32. src = v1.
    for _ in 0..20 {
        let (a, b) = (rng.next_u32(), rng.next_u32());
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, b);
        bc.mul_r(OP_MUL_R_R32, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a as u64, 0, 1, b as u64);
        let p = (a as u64) * (b as u64);
        assert_eq!(
            (lo, hi),
            (p as u32 as u64, (p >> 32) as u64),
            "[20] MUL32 a={:X} b={:X}",
            a,
            b
        );
    }
    // MUL64
    for _ in 0..20 {
        let (a, b) = (rng.next_u64(), rng.next_u64());
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(1, b);
        bc.mul_r(OP_MUL_R_R64, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a, 0, 1, b);
        let p = (a as u128) * (b as u128);
        assert_eq!(
            (lo, hi),
            (p as u64, (p >> 64) as u64),
            "[20] MUL64 a={:X} b={:X}",
            a,
            b
        );
    }
    // IMUL32 (signed): product = (i32)a * (i32)b, low32 in EAX, high32 in EDX
    for _ in 0..20 {
        let (a, b) = (rng.next_u32(), rng.next_u32());
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, b);
        bc.mul_r(OP_IMUL1_R_R32, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a as u64, 0, 1, b as u64);
        let p = (a as i32 as i64) * (b as i32 as i64);
        assert_eq!(
            (lo, hi),
            (p as u32 as u64, (p >> 32) as u32 as u64),
            "[20] IMUL32 a={:X} b={:X}",
            a,
            b
        );
    }
    // IMUL64 (signed)
    for _ in 0..20 {
        let (a, b) = (rng.next_u64(), rng.next_u64());
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(1, b);
        bc.mul_r(OP_IMUL1_R_R64, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a, 0, 1, b);
        let p = (a as i64 as i128) * (b as i64 as i128);
        assert_eq!(
            (lo, hi),
            (p as u64, (p >> 64) as u64),
            "[20] IMUL64 a={:X} b={:X}",
            a,
            b
        );
    }
    // DIV32: EAX = EDX:EAX / src32, EDX = remainder. Constrain hi (EDX) small and
    // divisor top-bit-set so the quotient always fits 32 bits (no x86 #DE trap).
    for _ in 0..20 {
        let lo = rng.next_u32();
        let hi = rng.next_u32() & 0xFFFF; // small high half
        let d = rng.next_u32() | 0x8000_0000; // d >= 2^31 > hi
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, d);
        bc.mul_r(OP_DIV_R_R32, 1);
        bc.halt();
        let dividend = ((hi as u64) << 32) | (lo as u64);
        let (q, r, _) = run_prog(&bc.finish(), lo as u64, hi as u64, 1, d as u64);
        assert_eq!(
            (q, r),
            (
                (dividend / d as u64) as u32 as u64,
                (dividend % d as u64) as u32 as u64
            ),
            "[20] DIV32 hi={:X} d={:X}",
            hi,
            d
        );
    }
    // DIV64: same constraint — hi small, divisor top-bit-set -> quotient fits 64 bits.
    for _ in 0..20 {
        let lo = rng.next_u64();
        let hi = rng.next_u64() & 0xFFFF; // small high half
        let d = rng.next_u64() | (1u64 << 63); // d >= 2^63 > hi
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(1, d);
        bc.mul_r(OP_DIV_R_R64, 1);
        bc.halt();
        let dividend = ((hi as u128) << 64) | (lo as u128);
        let (q, r, _) = run_prog(&bc.finish(), lo, hi, 1, d);
        assert_eq!(
            (q, r),
            ((dividend / d as u128) as u64, (dividend % d as u128) as u64),
            "[20] DIV64 hi={:X} d={:X}",
            hi,
            d
        );
    }
    // IDIV32 (signed): keep the dividend a small sign-extended value so the
    // quotient always fits i32 (no #DE). dv = small signed; hi:lo = sign-extend.
    for _ in 0..20 {
        let dv = (rng.next_u32() & 0xFFFF) as i16 as i32; // small signed
        let lo = dv as u32;
        let hi = ((dv as i64) >> 32) as u32; // sign extension into high half
        let d = (rng.next_u32() as i32) | 1; // nonzero, any sign
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, d as u32);
        bc.mul_r(OP_IDIV_R_R32, 1);
        bc.halt();
        let dividend = (((hi as u64) << 32) | (lo as u64)) as i64;
        let (q, r, _) = run_prog(&bc.finish(), lo as u64, hi as u64, 1, d as u32 as u64);
        let qe = (dividend / d as i64) as u32 as u64;
        let re = (dividend % d as i64) as u32 as u64;
        assert_eq!(
            (q, r),
            (qe, re),
            "[20] IDIV32 dividend={:X} d={:X}",
            dividend as u64,
            d
        );
    }
    // IDIV64 (signed): small sign-extended dividend -> quotient fits i64.
    for _ in 0..20 {
        let dv = (rng.next_u64() & 0xFFFF) as i16 as i64; // small signed
        let lo = dv as u64;
        let hi = ((dv as i128) >> 64) as u64; // sign extension into high half
        let d = (rng.next_u64() as i64) | 1; // nonzero, any sign
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(1, d as u64);
        bc.mul_r(OP_IDIV_R_R64, 1);
        bc.halt();
        let dividend = (((hi as u128) << 64) | (lo as u128)) as i128;
        let (q, r, _) = run_prog(&bc.finish(), lo, hi, 1, d as u64);
        let qe = (dividend / d as i128) as u64;
        let re = (dividend % d as i128) as u64;
        assert_eq!(
            (q, r),
            (qe, re),
            "[20] IDIV64 dividend={:X} d={:X}",
            dividend as u64,
            d
        );
    }
    // BSWAP32 / BSWAP64 (src = the register itself)
    for _ in 0..20 {
        let v = rng.next_u32();
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, v);
        bc.bswap_r(OP_BSWAP_R32, 1);
        bc.halt();
        let (_, _, s) = run_prog(&bc.finish(), 0, 0, 1, v as u64);
        assert_eq!(s, v.swap_bytes() as u64, "[20] BSWAP32 v={:X}", v);
    }
    for _ in 0..20 {
        let v = rng.next_u64();
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(1, v);
        bc.bswap_r(OP_BSWAP_R64, 1);
        bc.halt();
        let (_, _, s) = run_prog(&bc.finish(), 0, 0, 1, v);
        assert_eq!(s, v.swap_bytes(), "[20] BSWAP64 v={:X}", v);
    }
    Ok(())
}

/// [22] A-2 (v33): 1-op MUL/IMUL/DIV/IDIV 8/16-bit width.
/// Cross-checks the Rust interpreter against the native x86-64 handlers for the new
/// byte/word accumulator-pair opcodes (MUL8/16, IMUL8/16, DIV8/16, IDIV8/16) over
/// random inputs. The harness builds the VM module once and runs each tiny program
/// through both the interpreter and the native handler loop, asserting identical
/// (rax, rdx, src) state. Division inputs are constrained so the quotient fits the
/// destination width (no x86 #DE trap).
pub(crate) fn run_a2_muldiv_8_16_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut rng = rand::thread_rng();
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
        vec![0u8; 128],
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

    let mut run_prog = |prog: &[u8], rax: u64, rdx: u64, src: u8, sval: u64| -> (u64, u64, u64) {
        // interpreter
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 64];
        st[interp::STATE_VREGS + 0 * 8..][..8].copy_from_slice(&rax.to_le_bytes());
        st[interp::STATE_VREGS + 2 * 8..][..8].copy_from_slice(&rdx.to_le_bytes());
        st[interp::STATE_VREGS + (src as usize) * 8..][..8].copy_from_slice(&sval.to_le_bytes());
        interp::interpret(&mut st, &mut mem, prog).unwrap();
        let i = (
            u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..][..8].try_into().unwrap()),
            u64::from_le_bytes(st[interp::STATE_VREGS + 2 * 8..][..8].try_into().unwrap()),
            u64::from_le_bytes(
                st[interp::STATE_VREGS + (src as usize) * 8..][..8]
                    .try_into()
                    .unwrap(),
            ),
        );
        // native
        {
            let b = arena.bytes();
            b[0x5000..0x5000 + prog.len()].copy_from_slice(prog);
            b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
            b[0x6000 + interp::STATE_VREGS + 0 * 8..][..8].copy_from_slice(&rax.to_le_bytes());
            b[0x6000 + interp::STATE_VREGS + 2 * 8..][..8].copy_from_slice(&rdx.to_le_bytes());
            b[0x6000 + interp::STATE_VREGS + (src as usize) * 8..][..8]
                .copy_from_slice(&sval.to_le_bytes());
        }
        arena.call(0x7000);
        let b = arena.bytes();
        let sf = 0x6000usize;
        let n = (
            u64::from_le_bytes(
                b[sf + interp::STATE_VREGS + 0 * 8..][..8]
                    .try_into()
                    .unwrap(),
            ),
            u64::from_le_bytes(
                b[sf + interp::STATE_VREGS + 2 * 8..][..8]
                    .try_into()
                    .unwrap(),
            ),
            u64::from_le_bytes(
                b[sf + interp::STATE_VREGS + (src as usize) * 8..][..8]
                    .try_into()
                    .unwrap(),
            ),
        );
        assert_eq!(
            i,
            n,
            "[22] interp vs native mismatch\n{}",
            crate::vm::bytecode::disassemble(prog)
        );
        i
    };

    // MUL8: AX = AL * src8 (unsigned), zero-extended into v0; v2 unchanged.
    for _ in 0..25 {
        let (a, s) = (rng.next_u64() & 0xFF, rng.next_u64() & 0xFF);
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, s as u32);
        bc.mul_r(OP_MUL_R_R8, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a, 0xAAAA_AAAA_AAAA_AAAA, 1, s);
        let expect = ((a as u16) * (s as u16)) as u64;
        assert_eq!(lo, expect, "[22] MUL8 a={:X} s={:X}", a, s);
        assert_eq!(hi, 0xAAAA_AAAA_AAAA_AAAA, "[22] MUL8 must not touch RDX");
    }
    // IMUL8 (signed)
    for _ in 0..25 {
        let (a, s) = (rng.next_u64() & 0xFF, rng.next_u64() & 0xFF);
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, s as u32);
        bc.mul_r(OP_IMUL1_R_R8, 1);
        bc.halt();
        let (lo, _, _) = run_prog(&bc.finish(), a, 0, 1, s);
        let expect = ((a as u8 as i8 as i16) * (s as u8 as i8 as i16)) as u16 as u64;
        assert_eq!(lo, expect, "[22] IMUL8 a={:X} s={:X}", a, s);
    }
    // MUL16: DX:AX = AX * src16; v0=low16, v2=high16 (zero-extended).
    for _ in 0..25 {
        let (a, s) = (rng.next_u64() & 0xFFFF, rng.next_u64() & 0xFFFF);
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, s as u32);
        bc.mul_r(OP_MUL_R_R16, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a, 0, 1, s);
        let p = ((a as u32) * (s as u32)) as u64;
        assert_eq!(
            (lo, hi),
            (p & 0xFFFF, (p >> 16) & 0xFFFF),
            "[22] MUL16 a={:X} s={:X}",
            a,
            s
        );
    }
    // IMUL16 (signed)
    for _ in 0..25 {
        let (a, s) = (rng.next_u64() & 0xFFFF, rng.next_u64() & 0xFFFF);
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, s as u32);
        bc.mul_r(OP_IMUL1_R_R16, 1);
        bc.halt();
        let (lo, hi, _) = run_prog(&bc.finish(), a, 0, 1, s);
        let p = (a as u16 as i16 as i32) * (s as u16 as i16 as i32);
        let pu = p as u32 as u64;
        assert_eq!(
            (lo, hi),
            (pu & 0xFFFF, (pu >> 16) & 0xFFFF),
            "[22] IMUL16 a={:X} s={:X}",
            a,
            s
        );
    }
    // DIV8: AL = AX / src8; AH = rem. Constrain divisor high so quotient fits 8 bits.
    for _ in 0..25 {
        let ax = rng.next_u64() & 0xFFFF; // AX dividend
        let d = rng.next_u64() & 0xFF; // src8
        if d == 0 {
            continue;
        }
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, d as u32);
        bc.mul_r(OP_DIV_R_R8, 1);
        bc.halt();
        let q = (ax as u16) / (d as u8 as u16);
        if q > 0xFF {
            continue;
        } // would #DE; skip
        let r = (ax as u16) % (d as u8 as u16);
        let expect = ((q & 0xFF) as u64) | (((r & 0xFF) as u64) << 8);
        let (lo, _, _) = run_prog(&bc.finish(), ax, 0, 1, d);
        assert_eq!(lo, expect, "[22] DIV8 ax={:X} d={:X}", ax, d);
    }
    // DIV16: AX = DX:AX / src16; DX = rem. Constrain dividend high so quotient fits 16.
    for _ in 0..25 {
        let lo = rng.next_u64() & 0xFFFF;
        let hi = rng.next_u64() & 0xFF; // small high half
        let d = rng.next_u64() & 0xFFFF;
        if d == 0 {
            continue;
        }
        let dividend = (hi << 16) | lo;
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, d as u32);
        bc.mul_r(OP_DIV_R_R16, 1);
        bc.halt();
        let q = dividend / d;
        if q > 0xFFFF {
            continue;
        }
        let r = dividend % d;
        let (got_lo, got_hi, _) = run_prog(&bc.finish(), lo, hi, 1, d);
        assert_eq!(
            (got_lo, got_hi),
            (q, r),
            "[22] DIV16 lo={:X} hi={:X} d={:X}",
            lo,
            hi,
            d
        );
    }
    // IDIV8 (signed): AL = AX / src8; AH = rem, where AX is a signed i16.
    for _ in 0..25 {
        let a = rng.next_u64() & 0xFFFF;
        let d = rng.next_u64() & 0xFF;
        if d == 0 {
            continue;
        }
        let a16 = a as u16 as i16;
        let d8 = d as u8 as i8 as i16;
        let q = a16 / d8;
        if q < -128 || q > 127 {
            continue;
        }
        let r = a16 % d8;
        let expect = ((q as i8 as u8) as u64) | (((r as i8 as u8) as u64) << 8);
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm32(1, d as u32);
        bc.mul_r(OP_IDIV_R_R8, 1);
        bc.halt();
        let (lo, _, _) = run_prog(&bc.finish(), a, 0, 1, d);
        assert_eq!(lo, expect, "[22] IDIV8 a={:X} d={:X}", a, d);
    }
    // IDIV16 (signed): AX = DX:AX / src16; DX = rem (32-bit signed dividend).
    for _ in 0..25 {
        let lo = rng.next_u64() & 0xFFFF;
        let hi = rng.next_u64() & 0xFFFF;
        let d = rng.next_u64() & 0xFFFF;
        if d == 0 {
            continue;
        }
        let dividend = (hi << 16 | lo) as u32 as i32;
        let ds = d as u16 as i16 as i32;
        if dividend == i32::MIN && ds == -1 {
            continue;
        }
        let q = dividend / ds;
        if q < -32768 || q > 32767 {
            continue;
        }
        let r = dividend % ds;
        let (got_lo, got_hi, _) = run_prog(&bc_mk(d as u32), lo, hi, 1, d);
        assert_eq!(
            (got_lo, got_hi),
            ((q as i16 as u16) as u64, (r as i16 as u16) as u64),
            "[22] IDIV16 lo={:X} hi={:X} d={:X}",
            lo,
            hi,
            d
        );
    }

    Ok(())
}

pub(crate) fn bc_mk(d: u32) -> Vec<u8> {
    use crate::vm::bytecode::*;
    let mut b = BytecodeBuilder::new();
    b.mov_r_imm32(1, d);
    b.mul_r(OP_IDIV_R_R16, 1);
    b.halt();
    b.finish()
}
