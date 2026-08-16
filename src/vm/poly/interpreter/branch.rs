// ==============================================================================
// BTG - Polymorphic Interpreter: branch predicates - split from interpreter.rs
// ==============================================================================

use crate::vm::poly::isa_spec::VirtualIsaSpec;
use crate::vm::risc::{BranchCondition, VirtualFlags};

/// 조건 분기가 걸리는지 평가 (x86 조건 코드 의미론). `src/vm/risc/mod.rs::branch_taken`과 동일.
pub(crate) fn branch_taken(cond: BranchCondition, flags: &VirtualFlags) -> bool {
    match cond {
        BranchCondition::Always => true,
        BranchCondition::Zero => flags.zf(),
        BranchCondition::NotZero => !flags.zf(),
        BranchCondition::Carry => flags.cf(),
        BranchCondition::NotCarry => !flags.cf(),
        BranchCondition::Sign => flags.sf(),
        BranchCondition::NotSign => !flags.sf(),
        BranchCondition::Overflow => flags.of(),
        BranchCondition::NotOverflow => !flags.of(),
        // signed comparisons
        BranchCondition::Greater => !flags.zf() && (flags.sf() == flags.of()), // JG
        BranchCondition::Less => flags.sf() != flags.of(),                      // JL
        BranchCondition::GreaterOrEqual => flags.sf() == flags.of(),            // JGE
        BranchCondition::LessOrEqual => flags.zf() || (flags.sf() != flags.of()), // JLE
        // unsigned comparisons (precise)
        BranchCondition::Above => !flags.cf() && !flags.zf(),           // JA: CF=0 && ZF=0
        BranchCondition::AboveOrEqual => !flags.cf(),                    // JAE: CF=0
        BranchCondition::Below => flags.cf(),                            // JB: CF=1
        BranchCondition::BelowOrEqual => flags.cf() || flags.zf(),       // JBE: CF=1 || ZF=1
        // parity
        BranchCondition::Parity => flags.pf(),      // JP
        BranchCondition::NotParity => !flags.pf(),  // JNP
        // counter-based (Jcxz/Jecxz/Jrcxz): handled by branch_taken_with_state
        BranchCondition::CounterZero(_) => false,
    }
}

/// 분기 평가 — `CounterZero`(카운터 기반)는 레지스터 상태가 필요하므로 상태까지 전달.
/// `src/vm/risc/mod.rs::branch_taken_with_state`과 동일: RCX(reg[1])의 하위 width 바이트가 0인지.
pub(crate) fn branch_taken_with_state(cond: BranchCondition, flags: &VirtualFlags, regs: &[u64; 16]) -> bool {
    if let BranchCondition::CounterZero(width) = cond {
        let mask = match width {
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            _ => u64::MAX,
        };
        return (regs[1] & mask) == 0;
    }
    branch_taken(cond, flags)
}
