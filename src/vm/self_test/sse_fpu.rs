// ==============================================================================
// VM self-test submodule: sse_fpu.rs
// ==============================================================================
//
// Group A (Phase 2.1): SSE/FPU. Scalar FP arithmetic (ADD/Sub/Mul/Div SS+SD),
// 128-bit logic (PAND/POR/PANDN), conversions (CVTSI2SD/SS, CVTSS2SD/CVTSD2SS,
// CVTTSS2SI/CVTTSD2SI trunc + CVTSS2SI/CVTSD2SI round-nearest-even) and
// PEXTRD/PINSRD. Bytecode is built directly from the registry opcodes and run
// through BOTH the reference interpreter and the native VM, comparing the XMM
// file / vregs / flags (interp == native == expected). A lift smoke test also
// decodes real x86 SSE bytes and lifts them end-to-end.

use crate::vm::bytecode::{self, BytecodeBuilder};
use crate::vm::interp;
use anyhow::{anyhow, Result};

use super::util::{interp_state, run_native, set_vreg, set_xmm, vreg, xmm};

/// Build a program, seed the state, run interp + native, return both states.
fn run_case(
    build: impl Fn(&mut BytecodeBuilder),
    seed: impl Fn(&mut [u8]),
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut b = BytecodeBuilder::new();
    build(&mut b);
    b.halt();
    let bc = b.finish();
    let (mut st, mut mem) = interp_state();
    seed(&mut st);
    interp::interpret(&mut st, &mut mem, &bc)
        .map_err(|e| anyhow!("sse_fpu interp failed: {:?}", e))?;
    let (st_n, _base) = run_native(&bc, &[], 0, |s, _| seed(s))?;
    Ok((st, st_n))
}

fn xmm_f32(st: &[u8], x: usize) -> f32 {
    f32::from_le_bytes(xmm(st, x)[0..4].try_into().unwrap())
}

fn xmm_f64(st: &[u8], x: usize) -> f64 {
    f64::from_le_bytes(xmm(st, x)[0..8].try_into().unwrap())
}

fn flags(st: &[u8]) -> u64 {
    u64::from_le_bytes(
        st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8]
            .try_into()
            .unwrap(),
    )
}

/// Run the Group A (SSE/FPU) check.
pub(crate) fn run_sse_fpu_test() -> Result<()> {
    use crate::vm::bytecode::*;

    // ?? scalar FP arithmetic (low element op, upper bytes preserved) ????????
    {
        // addss xmm0, xmm1: 1.5 + 2.25 = 3.75; upper 12 bytes of xmm0 preserved.
        let build = |b: &mut BytecodeBuilder| b.sse_fp_xmm(OP_ADDSS_XMM, 0, 1);
        let seed = |s: &mut [u8]| {
            let mut x0 = [0u8; 16];
            x0[0..4].copy_from_slice(&1.5f32.to_le_bytes());
            for (i, v) in x0.iter_mut().enumerate().skip(4) {
                *v = 0x80 + i as u8;
            } // sentinel upper bytes
            set_xmm(s, 0, &x0);
            set_xmm(s, 1, &2.25f32.to_le_bytes().repeat(4).try_into().unwrap());
        };
        let (si, sn) = run_case(build, seed)?;
        for (tag, st) in [("interp", &si), ("native", &sn)] {
            assert!(
                (xmm_f32(st, 0) - 3.75).abs() < 1e-6,
                "addss {tag}: {}",
                xmm_f32(st, 0)
            );
            for (i, v) in xmm(st, 0).iter().enumerate().skip(4) {
                assert_eq!(*v, 0x80 + i as u8, "addss {tag}: upper byte {i} clobbered");
            }
        }
    }
    {
        // divsd xmm2, xmm3: 10.0 / 4.0 = 2.5
        let build = |b: &mut BytecodeBuilder| b.sse_fp_xmm(OP_DIVSD_XMM, 2, 3);
        let seed = |s: &mut [u8]| {
            set_xmm(s, 2, &10.0f64.to_le_bytes().repeat(2).try_into().unwrap());
            set_xmm(s, 3, &4.0f64.to_le_bytes().repeat(2).try_into().unwrap());
        };
        let (si, sn) = run_case(build, seed)?;
        for (tag, st) in [("interp", &si), ("native", &sn)] {
            assert!(
                (xmm_f64(st, 2) - 2.5).abs() < 1e-12,
                "divsd {tag}: {}",
                xmm_f64(st, 2)
            );
        }
    }
    {
        // subss / mulsd: 5.0f32 - 5.5f32 = -0.5 ; 1.5f64 * -2.0 = -3.0
        let build = |b: &mut BytecodeBuilder| {
            b.sse_fp_xmm(OP_SUBSS_XMM, 0, 1);
            b.sse_fp_xmm(OP_MULSD_XMM, 2, 3);
        };
        let seed = |s: &mut [u8]| {
            set_xmm(s, 0, &5.0f32.to_le_bytes().repeat(4).try_into().unwrap());
            set_xmm(s, 1, &5.5f32.to_le_bytes().repeat(4).try_into().unwrap());
            set_xmm(s, 2, &1.5f64.to_le_bytes().repeat(2).try_into().unwrap());
            set_xmm(s, 3, &(-2.0f64).to_le_bytes().repeat(2).try_into().unwrap());
        };
        let (si, sn) = run_case(build, seed)?;
        for (tag, st) in [("interp", &si), ("native", &sn)] {
            assert!(
                (xmm_f32(st, 0) - (-0.5)).abs() < 1e-6,
                "subss {tag}: {}",
                xmm_f32(st, 0)
            );
            assert!((xmm_f64(st, 2) - (-3.0)).abs() < 1e-12, "mulsd {tag}");
        }
    }

    // ?? SSE/FPU ops leave the status flags untouched ????????????????????????
    {
        let build = |b: &mut BytecodeBuilder| {
            b.sse_fp_xmm(OP_ADDSD_XMM, 0, 1);
            b.sse_logic_xmm(OP_PAND_XMM, 2, 3);
            b.cvt_fp_int(OP_CVTTSD2SI, 5, 0);
        };
        let seed = |s: &mut [u8]| {
            set_xmm(s, 0, &1.0f64.to_le_bytes().repeat(2).try_into().unwrap());
            set_xmm(s, 1, &2.0f64.to_le_bytes().repeat(2).try_into().unwrap());
            // arbitrary modelled flag word
            s[interp::STATE_FLAGS..interp::STATE_FLAGS + 8]
                .copy_from_slice(&(F_CF | F_ZF | F_SF).to_le_bytes());
        };
        let (si, sn) = run_case(build, seed)?;
        for (tag, st) in [("interp", &si), ("native", &sn)] {
            assert_eq!(
                flags(st),
                F_CF | F_ZF | F_SF,
                "SSE/FPU must preserve STATE_FLAGS ({tag})"
            );
            assert_eq!(vreg(st, 5), 3, "cvttsd2si 3.0 ({tag})");
        }
    }

    // ?? 128-bit logic: PAND / POR / PANDN ????????????????????????????????????
    {
        let build = |b: &mut BytecodeBuilder| {
            b.sse_logic_xmm(OP_PAND_XMM, 0, 1);
            b.sse_logic_xmm(OP_POR_XMM, 2, 3);
            b.sse_logic_xmm(OP_PANDN_XMM, 4, 5);
        };
        let seed = |s: &mut [u8]| {
            set_xmm(s, 0, &[0xF0u8; 16]);
            set_xmm(s, 1, &[0x3Cu8; 16]);
            set_xmm(s, 2, &[0x0Fu8; 16]);
            set_xmm(s, 3, &[0x30u8; 16]);
            set_xmm(s, 4, &[0xAAu8; 16]);
            set_xmm(s, 5, &[0xFFu8; 16]);
        };
        let (si, sn) = run_case(build, seed)?;
        for (tag, st) in [("interp", &si), ("native", &sn)] {
            assert!(xmm(st, 0).iter().all(|&b| b == 0x30), "pand {tag}");
            assert!(xmm(st, 2).iter().all(|&b| b == 0x3F), "por {tag}");
            assert!(xmm(st, 4).iter().all(|&b| b == 0x55), "pandn {tag}");
        }
    }

    // ?? int -> float: cvtsi2ss (i32) / cvtsi2sd (i64); upper bits zeroed ?????
    {
        let build = |b: &mut BytecodeBuilder| {
            b.cvt_int_fp(OP_CVTSI2SS_XMM, 0, 1); // xmm0 = (f32)(i32)v1
            b.cvt_int_fp(OP_CVTSI2SD_XMM, 2, 3); // xmm2 = (f64)(i64)v3
            b.cvt_fp_int(OP_CVTTSS2SI, 4, 0); // v4 = trunc(xmm0.low)
        };
        let seed = |s: &mut [u8]| {
            set_vreg(s, 1, 42);
            set_vreg(s, 3, (-3i64) as u64);
            // dirty dst upper bytes must be zeroed by the convert
            set_xmm(s, 0, &[0xEEu8; 16]);
            set_xmm(s, 2, &[0xEEu8; 16]);
        };
        let (si, sn) = run_case(build, seed)?;
        for (tag, st) in [("interp", &si), ("native", &sn)] {
            assert!((xmm_f32(st, 0) - 42.0).abs() < 1e-6, "cvtsi2ss {tag}");
            assert!((xmm_f64(st, 2) - (-3.0)).abs() < 1e-12, "cvtsi2sd {tag}");
            assert!(
                xmm(st, 0)[4..16].iter().all(|&b| b == 0),
                "cvtsi2ss upper not zeroed {tag}"
            );
            assert!(
                xmm(st, 2)[8..16].iter().all(|&b| b == 0),
                "cvtsi2sd upper not zeroed {tag}"
            );
            assert_eq!(vreg(st, 4), 42, "cvttss2si 42.0 ({tag})");
        }
    }

    // ?? float <-> float: cvtss2sd / cvtsd2ss ?????????????????????????????????
    {
        let build = |b: &mut BytecodeBuilder| {
            b.cvt_fp_fp(OP_CVTSS2SD_XMM, 0, 1); // xmm0.low = (f64)(f32)xmm1.low
            b.cvt_fp_fp(OP_CVTSD2SS_XMM, 2, 3); // xmm2.low = (f32)(f64)xmm3.low
        };
        let seed = |s: &mut [u8]| {
            set_xmm(s, 1, &2.5f32.to_le_bytes().repeat(4).try_into().unwrap());
            set_xmm(
                s,
                3,
                &(-6.25f64).to_le_bytes().repeat(2).try_into().unwrap(),
            );
            set_xmm(s, 0, &[0xEEu8; 16]);
            set_xmm(s, 2, &[0xEEu8; 16]);
        };
        let (si, sn) = run_case(build, seed)?;
        for (tag, st) in [("interp", &si), ("native", &sn)] {
            assert!((xmm_f64(st, 0) - 2.5).abs() < 1e-12, "cvtss2sd {tag}");
            assert!((xmm_f32(st, 2) - (-6.25)).abs() < 1e-6, "cvtsd2ss {tag}");
            assert!(
                xmm(st, 0)[8..16].iter().all(|&b| b == 0),
                "cvtss2sd upper64 {tag}"
            );
            assert!(
                xmm(st, 2)[4..16].iter().all(|&b| b == 0),
                "cvtsd2ss upper96 {tag}"
            );
        }
    }

    // ?? float -> int: trunc vs round-to-nearest-even (+ sign/edge cases) ?????
    {
        let build = |b: &mut BytecodeBuilder| {
            b.cvt_fp_int(OP_CVTTSS2SI, 0, 4); // v0 = trunc(3.9) = 3
            b.cvt_fp_int(OP_CVTTSD2SI, 1, 5); // v1 = trunc(-7.9) = -7
            b.cvt_fp_int(OP_CVTSS2SI, 2, 6); // v2 = rne(2.5) = 2 (ties even)
            b.cvt_fp_int(OP_CVTSD2SI, 3, 7); // v3 = rne(3.5) = 4 (ties even)
            b.cvt_fp_int(OP_CVTSS2SI, 8, 9); // v8 = rne(4.5) = 4 (ties even)
            b.cvt_fp_int(OP_CVTTSD2SI, 10, 11); // v10 = trunc(1e30) -> 0x8000_0000
        };
        let seed = |s: &mut [u8]| {
            set_xmm(s, 4, &3.9f32.to_le_bytes().repeat(4).try_into().unwrap());
            set_xmm(s, 5, &(-7.9f64).to_le_bytes().repeat(2).try_into().unwrap());
            set_xmm(s, 6, &2.5f32.to_le_bytes().repeat(4).try_into().unwrap());
            set_xmm(s, 7, &3.5f64.to_le_bytes().repeat(2).try_into().unwrap());
            set_xmm(s, 9, &4.5f32.to_le_bytes().repeat(4).try_into().unwrap());
            set_xmm(s, 11, &1e30f64.to_le_bytes().repeat(2).try_into().unwrap());
        };
        let (si, sn) = run_case(build, seed)?;
        for (tag, st) in [("interp", &si), ("native", &sn)] {
            assert_eq!(vreg(st, 0), 3, "cvttss2si 3.9 ({tag})");
            assert_eq!(vreg(st, 1), 0xFFFF_FFF9, "cvttsd2si -7.9 ({tag})");
            assert_eq!(vreg(st, 2), 2, "cvtss2si 2.5 ties-even ({tag})");
            assert_eq!(vreg(st, 3), 4, "cvtsd2si 3.5 ties-even ({tag})");
            assert_eq!(vreg(st, 8), 4, "cvtss2si 4.5 ties-even ({tag})");
            assert_eq!(vreg(st, 10), 0x8000_0000, "cvttsd2si overflow ({tag})");
        }
    }

    // ?? pextrd / pinsrd dword lanes ??????????????????????????????????????????
    {
        let build = |b: &mut BytecodeBuilder| {
            b.pextrd_xmm(0, 1, 0); // v0 = xmm1.dword[0]
            b.pextrd_xmm(2, 1, 3); // v2 = xmm1.dword[3]
            b.pinsrd_xmm(2, 3, 2); // xmm2.dword[2] = v3.low32
            b.pextrd_xmm(4, 2, 2); // v4 = xmm2.dword[2] (roundtrip)
        };
        let seed = |s: &mut [u8]| {
            let mut x1 = [0u8; 16];
            for i in 0..4 {
                x1[i * 4..i * 4 + 4].copy_from_slice(&(0x1111_0000u32 + i as u32).to_le_bytes());
            }
            set_xmm(s, 1, &x1);
            set_xmm(s, 2, &[0u8; 16]);
            set_vreg(s, 3, 0xDEAD_BEEF);
        };
        let (si, sn) = run_case(build, seed)?;
        for (tag, st) in [("interp", &si), ("native", &sn)] {
            assert_eq!(vreg(st, 0), 0x1111_0000, "pextrd lane0 ({tag})");
            assert_eq!(vreg(st, 2), 0x1111_0003, "pextrd lane3 ({tag})");
            assert_eq!(vreg(st, 4), 0xDEAD_BEEF, "pinsrd roundtrip ({tag})");
        }
    }

    // ?? lift smoke test: real x86 SSE bytes lift + execute end-to-end ????????
    {
        use crate::vm::lifter::{diagnose_unsupported, lift_block, LiftedInstr};
        use iced_x86::{Decoder, DecoderOptions};
        // addss xmm1, xmm0 ; pinsrd xmm2, eax, 1 ; pextrd edx, xmm2, 0
        let raw: [u8; 16] = [
            0xF3, 0x0F, 0x58, 0xC8, // addss xmm1, xmm0
            0x66, 0x0F, 0x3A, 0x22, 0xD0, 0x01, // pinsrd xmm2, eax, 1
            0x66, 0x0F, 0x3A, 0x16, 0xD2, 0x00, // pextrd edx, xmm2, 0
        ];
        let mut dec = Decoder::with_ip(64, &raw, 0, DecoderOptions::NONE);
        let seq: Vec<LiftedInstr> = (0..3).map(|_| LiftedInstr::plain(dec.decode())).collect();
        let bad = diagnose_unsupported(&seq);
        assert!(bad.is_empty(), "sse_fpu lift: unsupported {:?}", bad);
        let bc = lift_block(&seq, 0)?;
        let seed = |s: &mut [u8]| {
            set_xmm(s, 0, &1.0f32.to_le_bytes().repeat(4).try_into().unwrap());
            set_xmm(s, 1, &2.5f32.to_le_bytes().repeat(4).try_into().unwrap());
            set_xmm(s, 2, &[0u8; 16]);
            set_vreg(s, 0, 0xAABB_CC00); // rax (pinsrd source)
        };
        let (mut st, mut mem) = interp_state();
        seed(&mut st);
        interp::interpret(&mut st, &mut mem, &bc)
            .map_err(|e| anyhow!("sse_fpu lift interp failed: {:?}", e))?;
        let (sn, _base) = run_native(&bc, &[], 0, |s, _| seed(s))?;
        for (tag, st) in [("interp", &st), ("native", &sn)] {
            assert!(
                (xmm_f32(st, 1) - 3.5).abs() < 1e-6,
                "lift addss ({tag}): {}",
                xmm_f32(st, 1)
            );
            assert_eq!(vreg(st, 2), 0, "lift pextrd lane0 ({tag})");
            let x2 = xmm(st, 2);
            assert_eq!(
                u32::from_le_bytes(x2[4..8].try_into().unwrap()),
                0xAABB_CC00,
                "lift pinsrd lane1 ({tag})"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_fpu_runs_under_cargo() {
        run_sse_fpu_test().expect("SSE/FPU group check failed");
    }
}
