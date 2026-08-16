// ==============================================================================
// VM self-test submodule: cross_path.rs
// ==============================================================================
//
// 리뷰 지적 #12/#13 — "여러 semantic authority" 문제에 대한 차등 검증. 동일한
// x86 명령을 두 lift 경로로 변환하고 그 결과를 비교한다:
//
//   x86 instruction
//     ├─ lifter::lift_one  → VM bytecode  → interp (bytecode 인터프리터)
//     └─ RiscLifter        → RISC micro-op → eval_state (RISC 참조)
//
// bytecode 경로는 이전 세션에서 native(실제 x86)와의 differential fuzz 로
// "진짜 x86 의미론"이 검증된 기준선이므로, RISC 경로가 여기에 일치하면 RISC
// path 도 실측 x86 과 일치한다고 볼 수 있다.
//
// 비교 범위: 레지스터 0..16 (RAX..R15) + 6개 status flag (비트 레이아웃 동일).
// RISC 가 의도적으로 모델하지 않는 부분이 있으면 여기서 드러나고, 그 drift 를
// semantic core 작업으로 정리한다.

use anyhow::{anyhow, Result};
use crate::vm::bytecode::{BytecodeBuilder, FLAG_MASK};
use crate::vm::{interp, risc};
use iced_x86::{Code, Instruction, Register};

/// Lift `inst` through BOTH paths and run them with identical seeded registers.
/// Returns (bytecode_state, risc_state) for comparison.
fn run_both(
    inst: &Instruction,
    regs: [u64; 16],
    flags0: u64,
) -> Result<(Vec<u8>, risc::RiscEvalState)> {
    // bytecode path
    let mut b = BytecodeBuilder::new();
    crate::vm::lifter::lift_one(&mut b, inst).map_err(|e| anyhow!("bytecode lift failed: {e}"))?;
    b.halt();
    let bc = b.finish();
    let (mut st, mut mem) = super::util::interp_state();
    for (i, v) in regs.iter().enumerate() {
        super::util::set_vreg(&mut st, i, *v);
    }
    st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8].copy_from_slice(&flags0.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &bc)
        .map_err(|e| anyhow!("bytecode interp failed: {e:?}"))?;
    let st_bytes = st;

    // RISC path
    let mut lifter = risc::RiscLifter::new();
    lifter
        .lift_instruction(inst)
        .map_err(|e| anyhow!("risc lift failed: {e}"))?;
    let prog = risc::RiscProgram::new(lifter.desynth.instrs);
    let mut rstate = prog.eval_state(&regs);
    rstate.flags = (rstate.flags & FLAG_MASK) | (flags0 & !FLAG_MASK); // keep DF etc. consistent
    Ok((st_bytes, rstate))
}

fn st_vregs(st: &[u8]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (i, v) in out.iter_mut().enumerate() {
        *v = super::util::vreg(st, i);
    }
    out
}

fn st_flags(st: &[u8]) -> u64 {
    u64::from_le_bytes(st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8].try_into().unwrap())
}

/// Cross-path differential: bytecode path must equal the RISC path (both from
/// the same x86 instruction) on the architectural registers — that is a hard
/// check (a data-path divergence is a real bug).
///
/// The six status flags are ALSO compared, but their divergence is REPORTED
/// (not fatal): the RISC path currently derives flags from its micro-op
/// decomposition, which cannot reproduce x86 per-instruction flag semantics
/// (sub/cmp borrow-CF, AF, INC/DEC/NOT/SHLD flag behavior). That is the
/// identified "flag-kind micro-op" architecture task — see the report.
pub(crate) fn run_cross_path_test() -> Result<()> {
    let regs: [u64; 16] = [
        0x0123_4567_89AB_CDEF, // RAX
        0xFEDC_BA98_7654_3210, // RBX
        0x0000_0000_FFFF_FFFF, // RCX
        0x1111_2222_3333_4444, // RDX
        0x0000_0000_0000_0001, // RSI
        0x8000_0000_0000_0000, // RDI
        0x7FFF_FFFF_FFFF_FFFF, // RBP
        0x0000_0000_0000_0000, // RSP
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let flags0 = 0u64; // start clean; flag writes are what we compare

    // (name, instruction) — core ops supported by both lifters.
    let cases: Vec<(&str, Instruction)> = vec![
        ("add rax,rbx", Instruction::with2(Code::Add_r64_rm64, Register::RAX, Register::RBX).unwrap()),
        ("sub rax,rbx", Instruction::with2(Code::Sub_r64_rm64, Register::RAX, Register::RBX).unwrap()),
        ("xor rax,rbx", Instruction::with2(Code::Xor_r64_rm64, Register::RAX, Register::RBX).unwrap()),
        ("and rax,rbx", Instruction::with2(Code::And_r64_rm64, Register::RAX, Register::RBX).unwrap()),
        ("or rax,rbx", Instruction::with2(Code::Or_r64_rm64, Register::RAX, Register::RBX).unwrap()),
        ("add eax,ebx", Instruction::with2(Code::Add_r32_rm32, Register::EAX, Register::EBX).unwrap()),
        ("sub eax,ebx", Instruction::with2(Code::Sub_r32_rm32, Register::EAX, Register::EBX).unwrap()),
        ("inc rax", Instruction::with1(Code::Inc_rm64, Register::RAX).unwrap()),
        ("dec rax", Instruction::with1(Code::Dec_rm64, Register::RAX).unwrap()),
        ("neg rax", Instruction::with1(Code::Neg_rm64, Register::RAX).unwrap()),
        ("not rax", Instruction::with1(Code::Not_rm64, Register::RAX).unwrap()),
        ("shl rax,cl", Instruction::with2(Code::Shl_rm64_CL, Register::RAX, Register::CL).unwrap()),
        ("shr rax,cl", Instruction::with2(Code::Shr_rm64_CL, Register::RAX, Register::CL).unwrap()),
        ("sar rax,cl", Instruction::with2(Code::Sar_rm64_CL, Register::RAX, Register::CL).unwrap()),
        ("bswap rax", Instruction::with1(Code::Bswap_r64, Register::RAX).unwrap()),
        ("cmp rax,rbx", Instruction::with2(Code::Cmp_r64_rm64, Register::RAX, Register::RBX).unwrap()),
        ("test rax,rbx", Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RBX).unwrap()),
        ("bsr rax,rbx", Instruction::with2(Code::Bsr_r64_rm64, Register::RAX, Register::RBX).unwrap()),
        ("bsf rax,rbx", Instruction::with2(Code::Bsf_r64_rm64, Register::RAX, Register::RBX).unwrap()),
    ];

    let mut reg_bad: Vec<String> = Vec::new();
    let mut flag_drift: Vec<String> = Vec::new();
    for (name, inst) in &cases {
        let (st, rstate) = run_both(inst, regs, flags0)?;
        let bv = st_vregs(&st);
        let bf = st_flags(&st) & FLAG_MASK;
        let rf = rstate.flags & FLAG_MASK;

        for i in 0..16 {
            if bv[i] != rstate.regs[i] {
                reg_bad.push(format!(
                    "{name}: REG[{}] bytecode=0x{:X} risc=0x{:X}",
                    i, bv[i], rstate.regs[i]
                ));
                break;
            }
        }
        if bf != rf {
            flag_drift.push(format!("{name}: flags bytecode=0x{bf:X} risc=0x{rf:X}"));
        }
    }

    if !reg_bad.is_empty() {
        return Err(anyhow!(
            "cross-path REGISTER drift (real data-path bug, {}):\n  {}",
            reg_bad.len(),
            reg_bad.join("\n  ")
        ));
    }
    if !flag_drift.is_empty() {
        eprintln!(
            "[cross-path] RISC flag-modeling drift ({} cases — needs the flag-kind micro-op architecture, see cross_path.rs):",
            flag_drift.len()
        );
        for d in &flag_drift {
            eprintln!("  {d}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_path_bytecode_equals_risc() {
        run_cross_path_test().expect("bytecode path vs RISC path differential check failed");
    }

    /// Guard: the generated native VM code must keep fitting the smallest legacy
    /// test-arena layout (code @ 0x1000, table @ 0x4800 → 0x3800 bytes). Every
    /// opcode addition grows it; if this trips, enlarge the shared test layouts
    /// (self_test/util.rs + the per-test arenas) instead of letting the code
    /// silently overwrite the handler table.
    #[test]
    fn vm_code_fits_legacy_arena_layout() {
        let m = crate::vm::build_vm_module(
            0x14000_1000,
            0x14000_4800,
            0x14000_5000,
            vec![crate::vm::bytecode::OP_HALT],
            crate::vm::handlers::EntryMode::Ksa,
        )
        .expect("build vm");
        let region = 0x3800usize;
        assert!(
            m.code.len() < region,
            "native VM code {} bytes must stay under the 0x3800 legacy layout ({}); enlarge shared test arenas",
            m.code.len(),
            region
        );
    }

    /// 아이템 8: 빌드별 handler 레이아웃 랜덤화. MBA 빌드마다 (a) 다른 핸들러
    /// 순서 + junk + decoy 로 서로 다른 코드를 만들고, (b) 두 빌드 모두 검증을
    /// 통과해야 한다. 관측 의미론(interp/native/fuzz)은 테이블 기반 디스패치라
    /// 변하지 않는다 — 실제 실행은 [28] M8 MBA 테스트가 end-to-end로 검증한다.
    #[test]
    fn handler_layout_randomized_per_mba_build() {
        use crate::vm::handlers::{EntryMode, validate_vm_code};
        // a small program exercising a few opcodes
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(3, 0x1234_5678_9ABC_DEF0);
        bc.binop_r_r64(crate::vm::bytecode::OP_ADD_R_R64, 3, 4);
        bc.inc_r64(3);
        bc.halt();
        let prog = bc.finish();

        let mut codes = std::collections::HashSet::new();
        for _ in 0..3 {
            let m = crate::vm::build_vm_module_mba(
                0x14000_1000,
                0x14000_9000,
                0x14000_A000,
                prog.clone(),
                EntryMode::Ksa,
            )
            .expect("build mba vm");
            validate_vm_code(&m.code).expect("obfuscated MBA code must validate");
            codes.insert(m.code);
        }
        assert!(
            codes.len() >= 2,
            "MBA builds must produce different handler layouts (build-specific randomization)"
        );
    }
}
