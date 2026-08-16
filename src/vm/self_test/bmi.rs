// ==============================================================================
// VM self-test submodule: bmi.rs
// ==============================================================================
//
// Group B (Phase 2.1): BMI1/2 register-register ops. LZCNT / POPCNT / BLSR /
// BLSMSK / BLSI / ANDN are built directly as bytecode (registry opcodes), then
// executed through BOTH the reference interpreter and the native VM, and the
// resulting vregs are compared (interp == native == expected).

use anyhow::{Result, anyhow};
use crate::vm::bytecode::{self, BytecodeBuilder};
use crate::vm::{handlers, interp};

use super::util::{run_native, set_vreg, vreg};

/// Build a program that exercises one Group B opcode: dst_vreg=3, src=4
/// (ANDN: src1=4, src2=5). `seed` pre-loads the input vregs.
fn run_case(
    build: impl Fn(&mut BytecodeBuilder),
    seed: impl Fn(&mut [u8]),
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut b = BytecodeBuilder::new();
    build(&mut b);
    b.halt();
    let bc = b.finish();

    // interp
    let (mut st, mut mem) = super::util::interp_state();
    seed(&mut st);
    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("bmi interp failed: {:?}", e))?;

    // native
    let (st_n, _base) = run_native(&bc, &[], 0, |s, _| seed(s))?;
    Ok((st, st_n))
}

/// Run the Group B check. Returns Ok(()) iff interp and native match.
pub(crate) fn run_bmi_test() -> Result<()> {
    use crate::vm::bytecode::*;

    // (name, build_fn, seed_fn, expected_dst)
    let cases: Vec<(&str, Box<dyn Fn(&mut BytecodeBuilder)>, Box<dyn Fn(&mut [u8])>, u64)> = vec![
        // lzcnt32(0x0F00) = 20
        (
            "lzcnt32",
            Box::new(|b| b.lzcnt_r(OP_LZCNT_R32, 3, 4)),
            Box::new(|s| set_vreg(s, 4, 0x0F00)),
            20,
        ),
        // lzcnt32(0) = 32
        (
            "lzcnt32_zero",
            Box::new(|b| b.lzcnt_r(OP_LZCNT_R32, 3, 4)),
            Box::new(|s| set_vreg(s, 4, 0)),
            32,
        ),
        // lzcnt64(1<<40) = 23
        (
            "lzcnt64",
            Box::new(|b| b.lzcnt_r(OP_LZCNT_R64, 3, 4)),
            Box::new(|s| set_vreg(s, 4, 1u64 << 40)),
            23,
        ),
        // popcnt32(0xF0F0F0F0) = 16
        (
            "popcnt32",
            Box::new(|b| b.popcnt_r(OP_POPCNT_R32, 3, 4)),
            Box::new(|s| set_vreg(s, 4, 0xF0F0_F0F0)),
            16,
        ),
        // popcnt64(0xFFFFFFFF_FFFFFFFF) = 64
        (
            "popcnt64",
            Box::new(|b| b.popcnt_r(OP_POPCNT_R64, 3, 4)),
            Box::new(|s| set_vreg(s, 4, 0xFFFF_FFFF_FFFF_FFFF)),
            64,
        ),
        // blsr32(0x1100) = 0x1000
        (
            "blsr32",
            Box::new(|b| b.blsr_r(OP_BLSR_R32, 3, 4)),
            Box::new(|s| set_vreg(s, 4, 0x1100)),
            0x1000,
        ),
        // blsr64(0x8000000000000000 | 1) = 0x8000000000000000
        (
            "blsr64",
            Box::new(|b| b.blsr_r(OP_BLSR_R64, 3, 4)),
            Box::new(|s| set_vreg(s, 4, 0x8000_0000_0000_0001)),
            0x8000_0000_0000_0000,
        ),
        // blsmsk32(0x1000) = 0x1FFF
        (
            "blsmsk32",
            Box::new(|b| b.blsmsk_r(OP_BLSMSK_R32, 3, 4)),
            Box::new(|s| set_vreg(s, 4, 0x1000)),
            0x1FFF,
        ),
        // blsmsk64(0x8000000000000000) = 0xFFFFFFFFFFFFFFFF
        (
            "blsmsk64",
            Box::new(|b| b.blsmsk_r(OP_BLSMSK_R64, 3, 4)),
            Box::new(|s| set_vreg(s, 4, 0x8000_0000_0000_0000)),
            0xFFFF_FFFF_FFFF_FFFF,
        ),
        // blsi32(0x1100) = 0x100
        (
            "blsi32",
            Box::new(|b| b.blsi_r(OP_BLSI_R32, 3, 4)),
            Box::new(|s| set_vreg(s, 4, 0x1100)),
            0x100,
        ),
        // blsi64(0xF0) = 0x10
        (
            "blsi64",
            Box::new(|b| b.blsi_r(OP_BLSI_R64, 3, 4)),
            Box::new(|s| set_vreg(s, 4, 0xF0)),
            0x10,
        ),
        // andn32(0xFF00FF00, 0x0FF0_0000) = ~0xFF00FF00 & 0x0FF00000
        (
            "andn32",
            Box::new(|b| b.andn_r(OP_ANDN_R_R32, 3, 4, 5)),
            Box::new(|s| {
                set_vreg(s, 4, 0xFF00_FF00u64); // src1
                set_vreg(s, 5, 0x0FF0_0000u64); // src2
            }),
            !0xFF00_FF00u64 & 0x0FF0_0000u64,
        ),
        // andn64(0xFFFF_FFFF_0000_0000, 0xFFFF_0000_FFFF_0000)
        (
            "andn64",
            Box::new(|b| b.andn_r(OP_ANDN_R_R64, 3, 4, 5)),
            Box::new(|s| {
                set_vreg(s, 4, 0xFFFF_FFFF_0000_0000u64);
                set_vreg(s, 5, 0xFFFF_0000_FFFF_0000u64);
            }),
            !0xFFFF_FFFF_0000_0000u64 & 0xFFFF_0000_FFFF_0000u64,
        ),
    ];

    for (name, build, seed, expected) in cases {
        let (st_i, st_n) = run_case(build, seed)?;
        let got_i = vreg(&st_i, 3);
        let got_n = vreg(&st_n, 3);
        assert_eq!(got_i, expected, "{name}: interp mismatch: expected 0x{:X} got 0x{:X}", expected, got_i);
        assert_eq!(got_n, expected, "{name}: native mismatch: expected 0x{:X} got 0x{:X}", expected, got_n);
        assert_eq!(got_i, got_n, "{name}: interp != native (0x{:X} vs 0x{:X})", got_i, got_n);
    }

    // Regression: BLSR/BLSMSK/BLSI/ANDN are NOT flagless. Intel SDM gives them
    // flag semantics (BLS*: ZF from the result, SF/OF/CF cleared; ANDN: SF/ZF
    // from the result, CF/OF cleared), so a following `jz` reads real flags.
    // Both the reference interpreter and the native handlers must update
    // STATE_FLAGS identically.
    run_bmi_flags_test()?;

    Ok(())
}

/// Read the modelled flags word from a state buffer (STATE_FLAGS slot).
fn flags_of(st: &[u8]) -> u64 {
    u64::from_le_bytes(st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8].try_into().unwrap())
}

/// Differential flags check for the BMI group: run each op over several inputs
/// (incl. zero / power-of-two / full-width) through interp AND native with a
/// dirty pre-set flag word, and require the resulting STATE_FLAGS to match.
pub(crate) fn run_bmi_flags_test() -> Result<()> {
    use crate::vm::bytecode::*;

    // DF=0 (matches the entry stub's `cld`); every other modelled bit dirty so
    // the "SF/OF/CF cleared" behavior is actually observable.
    let seed_flags = FLAG_MASK & !F_DF;
    let inputs: [u64; 5] = [0, 1, 0x1000, 0x8000_0000_0000_0001, 0xFFFF_FFFF_FFFF_FFFF];

    let cases: Vec<(&str, Box<dyn Fn(&mut BytecodeBuilder)>)> = vec![
        ("blsr32", Box::new(|b| b.blsr_r(OP_BLSR_R32, 3, 4))),
        ("blsr64", Box::new(|b| b.blsr_r(OP_BLSR_R64, 3, 4))),
        ("blsmsk32", Box::new(|b| b.blsmsk_r(OP_BLSMSK_R32, 3, 4))),
        ("blsmsk64", Box::new(|b| b.blsmsk_r(OP_BLSMSK_R64, 3, 4))),
        ("blsi32", Box::new(|b| b.blsi_r(OP_BLSI_R32, 3, 4))),
        ("blsi64", Box::new(|b| b.blsi_r(OP_BLSI_R64, 3, 4))),
        ("andn32", Box::new(|b| b.andn_r(OP_ANDN_R_R32, 3, 4, 5))),
        ("andn64", Box::new(|b| b.andn_r(OP_ANDN_R_R64, 3, 4, 5))),
    ];

    for (name, build) in &cases {
        let mut b = BytecodeBuilder::new();
        build(&mut b);
        b.halt();
        let prog = b.finish();

        for (i, src) in inputs.iter().enumerate() {
            let (mut st_i, mut mem_i) = super::util::interp_state();
            st_i[interp::STATE_FLAGS..interp::STATE_FLAGS + 8]
                .copy_from_slice(&seed_flags.to_le_bytes());
            set_vreg(&mut st_i, 4, *src);
            set_vreg(&mut st_i, 5, *src ^ 0x0F0F);
            interp::interpret(&mut st_i, &mut mem_i, &prog)
                .map_err(|e| anyhow!("{name} interp failed: {:?}", e))?;

            let (st_n, _base) = run_native(&prog, &[], 0, |s, _| {
                s[interp::STATE_FLAGS..interp::STATE_FLAGS + 8]
                    .copy_from_slice(&seed_flags.to_le_bytes());
                set_vreg(s, 4, *src);
                set_vreg(s, 5, *src ^ 0x0F0F);
            })?;

            let fi = flags_of(&st_i) & FLAG_MASK;
            let fnat = flags_of(&st_n) & FLAG_MASK;
            assert_eq!(
                fnat, fi,
                "{name}(0x{src:X})#{i}: native flags 0x{fnat:X} != interp flags 0x{fi:X}"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bmi_runs_under_cargo() {
        run_bmi_test().expect("BMI1/2 group check failed");
    }
}
