//! Bounded, conservative value flow for resolving indirect transfers.
//!
//! This is intentionally not a general symbolic executor.  Unsupported writes,
//! excessive state, or arithmetic that cannot be represented by the small affine
//! domain become `Unknown` instead of guessing a target.

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueBase {
    Absolute,
    ImageBase,
    Rip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbstractValue {
    Unknown,
    Constant(u64),
    ImageBase {
        addend: i64,
    },
    RipRelative {
        target: u64,
    },
    Affine {
        base: ValueBase,
        index: Register,
        scale: u8,
        addend: i64,
        signed: bool,
    },
}

impl Default for AbstractValue {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareKind {
    Equal,
    NotEqual,
    Below,
    BelowOrEqual,
    Above,
    AboveOrEqual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bound {
    pub compare: CompareKind,
    pub upper: u64,
    pub inclusive: bool,
    pub compare_ip: u64,
    pub branch_ip: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct ValueFlowConfig {
    pub image_base: u64,
    pub max_instructions: usize,
    pub max_states: usize,
}

impl Default for ValueFlowConfig {
    fn default() -> Self {
        Self {
            image_base: 0,
            max_instructions: 4096,
            max_states: 128,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct State {
    values: BTreeMap<Register, AbstractValue>,
    bounds: BTreeMap<Register, Bound>,
    pending_cmp: Option<(Register, u64, u64)>,
}

#[derive(Debug, Clone)]
pub struct ValueFlowResult {
    before: Vec<State>,
    pub truncated: bool,
}

impl ValueFlowResult {
    pub fn value_before(&self, instruction_index: usize, register: Register) -> AbstractValue {
        self.before
            .get(instruction_index)
            .and_then(|s| s.values.get(&full_register(register)).copied())
            .unwrap_or(AbstractValue::Unknown)
    }
    pub fn bound_before(&self, instruction_index: usize, register: Register) -> Option<Bound> {
        self.before
            .get(instruction_index)
            .and_then(|s| s.bounds.get(&full_register(register)).copied())
    }

    /// Computes the effective address of a memory operand from the bounded
    /// state immediately before that instruction. This does not dereference
    /// memory; consumers must validate the resulting slot against typed data.
    pub fn memory_address_before(
        &self,
        instruction_index: usize,
        instruction: &Instruction,
        image_base: u64,
    ) -> AbstractValue {
        self.before
            .get(instruction_index)
            .map(|state| memory_value(instruction, state, image_base))
            .unwrap_or(AbstractValue::Unknown)
    }
}

pub fn analyze(instructions: &[Instruction], config: ValueFlowConfig) -> ValueFlowResult {
    let limit = instructions.len().min(config.max_instructions);
    let mut state = State::default();
    let mut before = Vec::with_capacity(limit);
    let mut truncated = instructions.len() > limit;
    for ins in &instructions[..limit] {
        before.push(state.clone());
        transfer(ins, &mut state, config.image_base);
        if state.values.len() + state.bounds.len() > config.max_states {
            state = State::default();
            truncated = true;
        }
    }
    ValueFlowResult { before, truncated }
}

fn transfer(ins: &Instruction, state: &mut State, image_base: u64) {
    if let Some((reg, imm, cmp_ip)) = state.pending_cmp.take() {
        let (kind, inclusive) = match ins.mnemonic() {
            Mnemonic::Ja => (Some(CompareKind::BelowOrEqual), true),
            Mnemonic::Jae => (Some(CompareKind::Below), false),
            Mnemonic::Jb => (Some(CompareKind::AboveOrEqual), true),
            Mnemonic::Jbe => (Some(CompareKind::Above), false),
            Mnemonic::Je => (Some(CompareKind::NotEqual), true),
            Mnemonic::Jne => (Some(CompareKind::Equal), true),
            _ => (None, false),
        };
        if let Some(compare) = kind {
            state.bounds.insert(
                reg,
                Bound {
                    compare,
                    upper: imm,
                    inclusive,
                    compare_ip: cmp_ip,
                    branch_ip: Some(ins.ip()),
                },
            );
        }
    }

    if ins.mnemonic() == Mnemonic::Cmp && ins.op_count() >= 2 {
        if let (Some(reg), Some(imm)) = (register_operand(ins, 0), immediate(ins, 1)) {
            state.pending_cmp = Some((full_register(reg), imm, ins.ip()));
        }
        return;
    }

    let Some(dst) = register_operand(ins, 0).map(full_register) else {
        return;
    };
    // Operand zero is not necessarily a destination (`push rax`, `test rax`,
    // `call rax`). Preserve reaching definitions across pure register uses.
    let mut info_factory = InstructionInfoFactory::new();
    if !matches!(
        info_factory.info(ins).op0_access(),
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    ) {
        return;
    }
    // A selector is commonly range-checked in one register and copied to a
    // different register for addressing the jump table. Preserve that proof
    // only for an exact register copy; every other write invalidates it.
    let copied_bound = (ins.mnemonic() == Mnemonic::Mov)
        .then(|| register_operand(ins, 1).map(full_register))
        .flatten()
        .and_then(|src| state.bounds.get(&src).copied());
    let value = match ins.mnemonic() {
        Mnemonic::Mov => operand_value(ins, 1, state, image_base),
        Mnemonic::Lea if ins.op1_kind() == OpKind::Memory => memory_value(ins, state, image_base),
        Mnemonic::Movzx => extend_value(operand_value(ins, 1, state, image_base), false),
        Mnemonic::Movsx | Mnemonic::Movsxd => {
            extend_value(operand_value(ins, 1, state, image_base), true)
        }
        Mnemonic::Add | Mnemonic::Sub => {
            let lhs = state
                .values
                .get(&dst)
                .copied()
                .unwrap_or(AbstractValue::Unknown);
            let rhs = immediate(ins, 1);
            rhs.map(|n| {
                add_constant(
                    lhs,
                    if ins.mnemonic() == Mnemonic::Sub {
                        -(n as i64)
                    } else {
                        n as i64
                    },
                )
            })
            .unwrap_or(AbstractValue::Unknown)
        }
        Mnemonic::Xor if register_operand(ins, 1).map(full_register) == Some(dst) => {
            AbstractValue::Constant(0)
        }
        _ => {
            // Fail closed for any instruction that writes operand zero.
            if ins.op0_kind() == OpKind::Register {
                AbstractValue::Unknown
            } else {
                return;
            }
        }
    };
    state.values.insert(dst, value);
    state.bounds.remove(&dst);
    if let Some(bound) = copied_bound {
        state.bounds.insert(dst, bound);
    } else if ins.mnemonic() == Mnemonic::Movzx {
        let source_bytes = match ins.op1_kind() {
            OpKind::Register => ins.op1_register().size(),
            OpKind::Memory => ins.memory_size().size(),
            _ => 0,
        };
        if matches!(source_bytes, 1 | 2) {
            state.bounds.insert(
                dst,
                Bound {
                    compare: CompareKind::BelowOrEqual,
                    upper: (1_u64 << (source_bytes * 8)) - 1,
                    inclusive: true,
                    compare_ip: ins.ip(),
                    branch_ip: None,
                },
            );
        }
    }
}

fn operand_value(ins: &Instruction, operand: u32, state: &State, image_base: u64) -> AbstractValue {
    if let Some(r) = register_operand(ins, operand) {
        return state
            .values
            .get(&full_register(r))
            .copied()
            .unwrap_or(AbstractValue::Unknown);
    }
    if let Some(n) = immediate(ins, operand) {
        return if n == image_base {
            AbstractValue::ImageBase { addend: 0 }
        } else {
            AbstractValue::Constant(n)
        };
    }
    AbstractValue::Unknown
}

fn memory_value(ins: &Instruction, state: &State, image_base: u64) -> AbstractValue {
    if ins.is_ip_rel_memory_operand() {
        return AbstractValue::RipRelative {
            target: ins.ip_rel_memory_address(),
        };
    }
    let index = full_register(ins.memory_index());
    let scale = ins.memory_index_scale() as u8;
    let disp = ins.memory_displacement64() as i64;
    let base_reg = full_register(ins.memory_base());
    let (base, base_addend) = if base_reg == Register::None {
        (ValueBase::Absolute, 0)
    } else {
        match state
            .values
            .get(&base_reg)
            .copied()
            .unwrap_or(AbstractValue::Unknown)
        {
            AbstractValue::ImageBase { addend } => (ValueBase::ImageBase, addend),
            AbstractValue::RipRelative { target } => (ValueBase::Rip, target as i64),
            AbstractValue::Constant(n) if n == image_base => (ValueBase::ImageBase, 0),
            AbstractValue::Constant(n) => (ValueBase::Absolute, n as i64),
            _ => return AbstractValue::Unknown,
        }
    };
    let Some(addend) = base_addend.checked_add(disp) else {
        return AbstractValue::Unknown;
    };
    if index == Register::None {
        return match base {
            ValueBase::ImageBase => AbstractValue::ImageBase { addend },
            ValueBase::Rip => AbstractValue::RipRelative {
                target: addend as u64,
            },
            ValueBase::Absolute => AbstractValue::Constant(addend as u64),
        };
    }
    AbstractValue::Affine {
        base,
        index,
        scale,
        addend,
        signed: false,
    }
}

fn extend_value(value: AbstractValue, signed: bool) -> AbstractValue {
    match value {
        AbstractValue::Affine {
            base,
            index,
            scale,
            addend,
            ..
        } => AbstractValue::Affine {
            base,
            index,
            scale,
            addend,
            signed,
        },
        AbstractValue::Constant(n) => AbstractValue::Constant(n),
        _ => AbstractValue::Unknown,
    }
}

fn add_constant(value: AbstractValue, delta: i64) -> AbstractValue {
    match value {
        AbstractValue::Constant(n) => n
            .checked_add_signed(delta)
            .map(AbstractValue::Constant)
            .unwrap_or(AbstractValue::Unknown),
        AbstractValue::ImageBase { addend } => addend
            .checked_add(delta)
            .map(|addend| AbstractValue::ImageBase { addend })
            .unwrap_or(AbstractValue::Unknown),
        AbstractValue::RipRelative { target } => target
            .checked_add_signed(delta)
            .map(|target| AbstractValue::RipRelative { target })
            .unwrap_or(AbstractValue::Unknown),
        AbstractValue::Affine {
            base,
            index,
            scale,
            addend,
            signed,
        } => addend
            .checked_add(delta)
            .map(|addend| AbstractValue::Affine {
                base,
                index,
                scale,
                addend,
                signed,
            })
            .unwrap_or(AbstractValue::Unknown),
        AbstractValue::Unknown => AbstractValue::Unknown,
    }
}

fn register_operand(ins: &Instruction, operand: u32) -> Option<Register> {
    if operand >= ins.op_count() || ins.op_kind(operand) != OpKind::Register {
        None
    } else {
        Some(ins.op_register(operand))
    }
}

fn immediate(ins: &Instruction, operand: u32) -> Option<u64> {
    if operand >= ins.op_count() {
        return None;
    }
    match ins.op_kind(operand) {
        OpKind::Immediate8 => Some(ins.immediate8() as u64),
        OpKind::Immediate16 => Some(ins.immediate16() as u64),
        OpKind::Immediate32 => Some(ins.immediate32() as u64),
        OpKind::Immediate64 => Some(ins.immediate64()),
        OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
            Some(ins.immediate8to64() as u64)
        }
        OpKind::Immediate32to64 => Some(ins.immediate32to64() as u64),
        _ => None,
    }
}

fn full_register(register: Register) -> Register {
    register.full_register()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bytes: &[u8]) -> Vec<Instruction> {
        let mut d = Decoder::with_ip(64, bytes, 0x140001000, DecoderOptions::NONE);
        let mut out = Vec::new();
        while d.can_decode() {
            out.push(d.decode());
        }
        out
    }

    #[test]
    fn tracks_rip_affine_and_bounds() {
        // lea rax,[rip+0x20]; lea rdx,[rax+rcx*4+8]; cmp ecx,7; ja +0; jmp rdx
        let ins = decode(&[
            0x48, 0x8d, 0x05, 0x20, 0, 0, 0, 0x48, 0x8d, 0x54, 0x88, 0x08, 0x83, 0xf9, 0x07, 0x77,
            0, 0xff, 0xe2,
        ]);
        let result = analyze(
            &ins,
            ValueFlowConfig {
                image_base: 0x140000000,
                ..Default::default()
            },
        );
        assert!(matches!(
            result.value_before(1, Register::RAX),
            AbstractValue::RipRelative { .. }
        ));
        assert!(matches!(
            result.value_before(2, Register::RDX),
            AbstractValue::Affine {
                base: ValueBase::Rip,
                scale: 4,
                ..
            }
        ));
        let b = result.bound_before(4, Register::RCX).unwrap();
        assert_eq!((b.upper, b.inclusive), (7, true));
    }

    #[test]
    fn zero_extension_proves_finite_selector_domain() {
        let instructions = decode(&[0x44, 0x0f, 0xb6, 0x41, 0x08]); // movzx r8d,byte ptr [rcx+8]
        let result = analyze(&instructions, ValueFlowConfig::default());
        let state_after = analyze(
            &decode(&[0x44, 0x0f, 0xb6, 0x41, 0x08, 0x90]),
            ValueFlowConfig::default(),
        );
        assert!(result.bound_before(0, Register::R8).is_none());
        let bound = state_after.bound_before(1, Register::R8).unwrap();
        assert_eq!(bound.compare, CompareKind::BelowOrEqual);
        assert_eq!(bound.upper, 0xff);
        assert!(bound.branch_ip.is_none());
    }

    #[test]
    fn register_uses_preserve_reaching_values_and_bounds() {
        // mov r14,imagebase; movzx r8d,byte ptr [rcx]; push r14; test r8d,r8d; nop
        let instructions = decode(&[
            0x49, 0xbe, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x44, 0x0f, 0xb6, 0x01,
            0x41, 0x56, 0x45, 0x85, 0xc0, 0x90,
        ]);
        let result = analyze(
            &instructions,
            ValueFlowConfig {
                image_base: 0x140000000,
                ..Default::default()
            },
        );
        assert_eq!(
            result.value_before(4, Register::R14),
            AbstractValue::ImageBase { addend: 0 }
        );
        assert_eq!(result.bound_before(4, Register::R8).unwrap().upper, 0xff);
    }

    #[test]
    fn tracks_image_base_scaled_index_and_extensions() {
        // mov rax,imagebase; lea rdx,[rax+rcx*8+0x30]; movsxd rdx,edx
        let mut bytes = vec![0x48, 0xb8];
        bytes.extend_from_slice(&0x140000000u64.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0x8d, 0x54, 0xc8, 0x30, 0x48, 0x63, 0xd2]);
        let ins = decode(&bytes);
        let r = analyze(
            &ins,
            ValueFlowConfig {
                image_base: 0x140000000,
                ..Default::default()
            },
        );
        assert!(matches!(
            r.value_before(2, Register::RDX),
            AbstractValue::Affine {
                base: ValueBase::ImageBase,
                scale: 8,
                ..
            }
        ));
    }

    #[test]
    fn caps_and_unknown_fail_closed() {
        let ins = decode(&[0x48, 0x89, 0xd8, 0x48, 0x0f, 0xaf, 0xc1]);
        let r = analyze(
            &ins,
            ValueFlowConfig {
                max_instructions: 1,
                ..Default::default()
            },
        );
        assert!(r.truncated);
        assert_eq!(r.value_before(0, Register::RAX), AbstractValue::Unknown);
        assert_eq!(r.value_before(9, Register::RAX), AbstractValue::Unknown);
    }
}
