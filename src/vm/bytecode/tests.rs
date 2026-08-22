use super::*;

/// A backward jmp8 whose offset falls outside [-128, 127] must be auto-widened
/// to jmp32 (Bug-3 fix) instead of truncating to a wrong i8 target.
#[test]
fn rel8_jmp_widens_to_rel32_when_out_of_range() {
    let mut b = BytecodeBuilder::new();
    let target = b.new_label();
    b.mark_label(target); // target at byte 0
    for _ in 0..200 {
        b.nop(); // bytes 0..=199
    }
    b.jmp8(target); // jmp8 at byte 200, rel field at 201 -> rel = 0-(201+1) = -202 (out of range)
    let code = b.finish();
    assert_eq!(
        code[200], OP_JMP32,
        "jmp8 should have been widened to jmp32"
    );
    let rel = i32::from_le_bytes(code[201..205].try_into().unwrap());
    assert_eq!(rel, 0 - 205, "widened jmp32 target must still be byte 0");
    // The interpreter must land on byte 0: ip = 205 + rel = 205 - 205 = 0.
}

/// jb8 has no rel32 sibling; it must widen to jcc32 with COND_JB (Bug-3 fix).
#[test]
fn rel8_jb_widens_to_jcc32() {
    let mut b = BytecodeBuilder::new();
    let target = b.new_label();
    b.mark_label(target);
    for _ in 0..200 {
        b.nop();
    }
    b.jb8(target);
    let code = b.finish();
    assert_eq!(code[200], OP_JCC32, "jb8 should have been widened to jcc32");
    assert_eq!(code[201], COND_JB, "jcc32 cond byte must be COND_JB");
    let rel = i32::from_le_bytes(code[202..206].try_into().unwrap());
    assert_eq!(rel, 0 - 206);
}

/// Branches that stay within rel8 range are left untouched.
#[test]
fn rel8_in_range_unchanged() {
    let mut b = BytecodeBuilder::new();
    let target = b.new_label();
    b.mark_label(target);
    for _ in 0..40 {
        b.nop();
    }
    b.jmp8(target);
    let code = b.finish();
    assert_eq!(code[40], OP_JMP8, "in-range jmp8 must stay jmp8");
    let rel = code[41] as i8 as i32;
    assert_eq!(rel, 0 - 42);
}
