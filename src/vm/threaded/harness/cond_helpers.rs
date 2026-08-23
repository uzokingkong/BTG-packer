use crate::vm::risc::BranchCondition;
use iced_x86::Code;

/// BranchCondition -> SETcc rm8 코드 (CounterZero 제외).
pub(crate) fn cond_to_setcc_code(cond: BranchCondition) -> Option<Code> {
    match cond {
        BranchCondition::Zero => Some(Code::Sete_rm8),
        BranchCondition::NotZero => Some(Code::Setne_rm8),
        BranchCondition::Carry | BranchCondition::Below => Some(Code::Setb_rm8),
        BranchCondition::NotCarry | BranchCondition::AboveOrEqual => Some(Code::Setae_rm8),
        BranchCondition::Sign => Some(Code::Sets_rm8),
        BranchCondition::NotSign => Some(Code::Setns_rm8),
        BranchCondition::Overflow => Some(Code::Seto_rm8),
        BranchCondition::NotOverflow => Some(Code::Setno_rm8),
        BranchCondition::Greater => Some(Code::Setg_rm8),
        BranchCondition::Less => Some(Code::Setl_rm8),
        BranchCondition::GreaterOrEqual => Some(Code::Setge_rm8),
        BranchCondition::LessOrEqual => Some(Code::Setle_rm8),
        BranchCondition::Above => Some(Code::Seta_rm8),
        BranchCondition::BelowOrEqual => Some(Code::Setbe_rm8),
        BranchCondition::Parity => Some(Code::Setp_rm8),
        BranchCondition::NotParity => Some(Code::Setnp_rm8),
        BranchCondition::CounterZero(_) => None,
        BranchCondition::Always => Some(Code::Sete_rm8),
    }
}

/// BranchCondition -> CMOVcc r64, r/m64 코드 (CounterZero 제외).
pub(crate) fn cond_to_cmov_code(cond: BranchCondition) -> Option<Code> {
    match cond {
        BranchCondition::Zero => Some(Code::Cmove_r64_rm64),
        BranchCondition::NotZero => Some(Code::Cmovne_r64_rm64),
        BranchCondition::Carry | BranchCondition::Below => Some(Code::Cmovb_r64_rm64),
        BranchCondition::NotCarry | BranchCondition::AboveOrEqual => Some(Code::Cmovae_r64_rm64),
        BranchCondition::Sign => Some(Code::Cmovs_r64_rm64),
        BranchCondition::NotSign => Some(Code::Cmovns_r64_rm64),
        BranchCondition::Overflow => Some(Code::Cmovo_r64_rm64),
        BranchCondition::NotOverflow => Some(Code::Cmovno_r64_rm64),
        BranchCondition::Greater => Some(Code::Cmovg_r64_rm64),
        BranchCondition::Less => Some(Code::Cmovl_r64_rm64),
        BranchCondition::GreaterOrEqual => Some(Code::Cmovge_r64_rm64),
        BranchCondition::LessOrEqual => Some(Code::Cmovle_r64_rm64),
        BranchCondition::Above => Some(Code::Cmova_r64_rm64),
        BranchCondition::BelowOrEqual => Some(Code::Cmovbe_r64_rm64),
        BranchCondition::Parity => Some(Code::Cmovp_r64_rm64),
        BranchCondition::NotParity => Some(Code::Cmovnp_r64_rm64),
        BranchCondition::CounterZero(_) => None,
        BranchCondition::Always => Some(Code::Cmovne_r64_rm64),
    }
}
