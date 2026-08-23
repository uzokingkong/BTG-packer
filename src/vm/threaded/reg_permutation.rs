// ==============================================================================
// BTG VM - Dynamic Register Permutation & Context Offset Scrambler
// ==============================================================================
// Destroys static register bindings (R8=bytecode, R12=VIP, R14=Key, R15=Table, RDX=State).
// Each basic block / handler cluster derives a unique GPR allocation from the build seed,
// and transition trampolines cycle registers dynamically at runtime.
// ==============================================================================

use iced_x86::{Code, Instruction, Register};
use std::collections::HashMap;

/// Core VM operational roles mapped to hardware general-purpose registers (GPRs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VmRole {
    /// Virtual Program Counter (byte offset into encrypted stream).
    Vpc,
    /// Virtual Context / State Base Pointer (points to VmExecutionContext buffer).
    VContext,
    /// 64-bit Rolling Decryption Key.
    RollingKey,
    /// Encrypted bytecode buffer base pointer.
    BytecodeBase,
    /// Handler jump table / metadata base pointer.
    TableBase,
    /// Virtual data-stack top used by VM push/pop handlers.
    StackBase,
    /// Primary arithmetic / fetch scratch register.
    Temp0,
    /// Secondary scratch register.
    Temp1,
    /// Tertiary scratch register.
    Temp2,
}

/// Available x86-64 GPRs for dynamic VM role allocation (excluding RSP).
pub const USABLE_GPRS: [Register; 14] = [
    Register::RAX,
    Register::RBX,
    Register::RCX,
    Register::RDX,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

/// Dynamic GPR assignment configuration for a specific VM basic block or handler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterAssignment {
    pub(crate) role_to_gpr: HashMap<VmRole, Register>,
    pub(crate) gpr_to_role: HashMap<Register, VmRole>,
}

impl RegisterAssignment {
    /// Creates the standard/legacy register assignment (used for fallback or base reference).
    pub fn legacy() -> Self {
        let mut role_to_gpr = HashMap::new();
        let mut gpr_to_role = HashMap::new();

        let pairs = [
            (VmRole::BytecodeBase, Register::R8),
            (VmRole::Vpc, Register::R12),
            (VmRole::RollingKey, Register::R14),
            (VmRole::TableBase, Register::R15),
            (VmRole::VContext, Register::RDX),
            (VmRole::StackBase, Register::R13),
            (VmRole::Temp0, Register::RAX),
            (VmRole::Temp1, Register::RCX),
            (VmRole::Temp2, Register::R9),
        ];

        for (role, gpr) in pairs {
            role_to_gpr.insert(role, gpr);
            gpr_to_role.insert(gpr, role);
        }

        Self {
            role_to_gpr,
            gpr_to_role,
        }
    }

    /// Production-safe assignment for the long-lived dispatcher roles.
    ///
    /// The four nonvolatile legacy carriers are permuted among VIP, virtual
    /// stack, rolling key and table roles. BytecodeBase(R8) and VContext(RDX)
    /// remain pinned because those registers also have architectural Win64/IDIV
    /// meanings in bridge/handler code. Keeping the carrier set unchanged means
    /// the existing Win64 prologue preserves every selected permutation.
    pub fn production_from_seed(seed: u64) -> Self {
        let roles = [
            VmRole::Vpc,
            VmRole::StackBase,
            VmRole::RollingKey,
            VmRole::TableBase,
        ];
        let mut carriers = [Register::R12, Register::R13, Register::R14, Register::R15];
        let mut mixed = seed ^ 0xA076_1D64_78BD_642F;
        for i in (1..carriers.len()).rev() {
            mixed ^= mixed >> 12;
            mixed ^= mixed << 25;
            mixed ^= mixed >> 27;
            mixed = mixed.wrapping_mul(0x2545_F491_4F6C_DD1D);
            carriers.swap(i, (mixed as usize) % (i + 1));
        }

        let mut assignment = Self::legacy();
        for role in roles {
            if let Some(old) = assignment.role_to_gpr.remove(&role) {
                assignment.gpr_to_role.remove(&old);
            }
        }
        for (role, gpr) in roles.into_iter().zip(carriers) {
            assignment.role_to_gpr.insert(role, gpr);
            assignment.gpr_to_role.insert(gpr, role);
        }
        assignment
    }

    /// Maps an occurrence of a legacy long-lived carrier (including its
    /// 32/16/8-bit view) to this assignment. Other registers are unchanged.
    pub fn map_legacy_carrier(&self, reg: Register) -> Register {
        let (role, width) = match reg {
            Register::R12 => (VmRole::Vpc, 64),
            Register::R12D => (VmRole::Vpc, 32),
            Register::R12W => (VmRole::Vpc, 16),
            Register::R12L => (VmRole::Vpc, 8),
            Register::R13 => (VmRole::StackBase, 64),
            Register::R13D => (VmRole::StackBase, 32),
            Register::R13W => (VmRole::StackBase, 16),
            Register::R13L => (VmRole::StackBase, 8),
            Register::R14 => (VmRole::RollingKey, 64),
            Register::R14D => (VmRole::RollingKey, 32),
            Register::R14W => (VmRole::RollingKey, 16),
            Register::R14L => (VmRole::RollingKey, 8),
            Register::R15 => (VmRole::TableBase, 64),
            Register::R15D => (VmRole::TableBase, 32),
            Register::R15W => (VmRole::TableBase, 16),
            Register::R15L => (VmRole::TableBase, 8),
            _ => return reg,
        };
        match (self.get(role), width) {
            (Register::R12, 64) => Register::R12,
            (Register::R12, 32) => Register::R12D,
            (Register::R12, 16) => Register::R12W,
            (Register::R12, 8) => Register::R12L,
            (Register::R13, 64) => Register::R13,
            (Register::R13, 32) => Register::R13D,
            (Register::R13, 16) => Register::R13W,
            (Register::R13, 8) => Register::R13L,
            (Register::R14, 64) => Register::R14,
            (Register::R14, 32) => Register::R14D,
            (Register::R14, 16) => Register::R14W,
            (Register::R14, 8) => Register::R14L,
            (Register::R15, 64) => Register::R15,
            (Register::R15, 32) => Register::R15D,
            (Register::R15, 16) => Register::R15W,
            (Register::R15, 8) => Register::R15L,
            _ => reg,
        }
    }

    /// Reject incomplete or colliding role maps before they reach codegen.
    pub fn validate(&self) -> Result<(), String> {
        let roles = [
            VmRole::BytecodeBase,
            VmRole::Vpc,
            VmRole::StackBase,
            VmRole::RollingKey,
            VmRole::TableBase,
            VmRole::VContext,
            VmRole::Temp0,
            VmRole::Temp1,
            VmRole::Temp2,
        ];
        let mut seen = std::collections::HashSet::new();
        for role in roles {
            let gpr = self.get(role);
            if gpr == Register::None || gpr == Register::RSP {
                return Err(format!("invalid register {gpr:?} for {role:?}"));
            }
            if !seen.insert(gpr) {
                return Err(format!("register {gpr:?} assigned more than once"));
            }
            if self.role_of(gpr) != Some(role) {
                return Err(format!("forward/reverse map mismatch for {role:?}"));
            }
        }
        Ok(())
    }

    /// Deterministically derives a unique, collision-free GPR assignment from a seed and block ID.
    pub fn from_seed_and_block(seed: u64, block_id: u32) -> Self {
        let mut mixed = seed
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add((block_id as u64).rotate_left(19))
            ^ 0x517C_C1B7_2722_0A95;

        // Fisher-Yates shuffle of USABLE_GPRS
        let mut pool = USABLE_GPRS;
        for i in (1..pool.len()).rev() {
            mixed = mixed
                .wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0x1405_7B7E_F767_814F);
            let j = ((mixed >> 32) as usize) % (i + 1);
            pool.swap(i, j);
        }

        let roles = [
            VmRole::BytecodeBase,
            VmRole::Vpc,
            VmRole::RollingKey,
            VmRole::TableBase,
            VmRole::VContext,
            VmRole::StackBase,
            VmRole::Temp0,
            VmRole::Temp1,
            VmRole::Temp2,
        ];

        let mut role_to_gpr = HashMap::new();
        let mut gpr_to_role = HashMap::new();

        for (idx, &role) in roles.iter().enumerate() {
            let gpr = pool[idx];
            role_to_gpr.insert(role, gpr);
            gpr_to_role.insert(gpr, role);
        }

        Self {
            role_to_gpr,
            gpr_to_role,
        }
    }

    /// Returns the assigned GPR for a given role.
    pub fn get(&self, role: VmRole) -> Register {
        *self.role_to_gpr.get(&role).unwrap_or(&Register::None)
    }

    /// Returns the role mapped to a given GPR, if any.
    pub fn role_of(&self, gpr: Register) -> Option<VmRole> {
        self.gpr_to_role.get(&gpr).copied()
    }

    /// Emits optimal register transition machine instructions from `self` to `target`.
    /// Handles permutation cycles safely using temporary registers or `xchg`.
    pub fn emit_transition(&self, target: &RegisterAssignment) -> Vec<Instruction> {
        let mut instrs = Vec::new();
        if self == target {
            return instrs;
        }

        let roles = [
            VmRole::BytecodeBase,
            VmRole::Vpc,
            VmRole::RollingKey,
            VmRole::TableBase,
            VmRole::VContext,
            VmRole::StackBase,
        ];

        let mut current_map: HashMap<VmRole, Register> = self.role_to_gpr.clone();
        let target_map: HashMap<VmRole, Register> = target.role_to_gpr.clone();

        for &role in &roles {
            let cur_reg = current_map[&role];
            let tgt_reg = target_map[&role];

            if cur_reg == tgt_reg {
                continue;
            }

            // If another role currently occupies tgt_reg, we swap them via xchg
            if let Some(&other_role) = current_map
                .iter()
                .find(|(_, &r)| r == tgt_reg)
                .map(|(k, _)| k)
            {
                if let Ok(ins) = Instruction::with2(Code::Xchg_rm64_r64, cur_reg, tgt_reg) {
                    instrs.push(ins);
                }
                current_map.insert(role, tgt_reg);
                current_map.insert(other_role, cur_reg);
            } else {
                if let Ok(ins) = Instruction::with2(Code::Mov_r64_rm64, tgt_reg, cur_reg) {
                    instrs.push(ins);
                }
                current_map.insert(role, tgt_reg);
            }
        }

        instrs
    }
}

/// Scrambles internal memory slot offsets of the VM Execution Context (VRegs, Temps, Flags).
/// Prevents static reverse engineering of linear struct offsets.
#[derive(Clone, Debug)]
pub struct ContextOffsetScrambler {
    /// Shuffled slot offsets for 16 Virtual Registers (V0..V15).
    vreg_offsets: [i32; 16],
    /// Shuffled slot offsets for 8 Virtual Temps (T0..T7).
    temp_offsets: [i32; 8],
    /// Scrambled offset for the virtual flags register.
    flags_offset: i32,
    /// Total scrambled size in bytes (aligned to 16).
    total_size: usize,
}

impl ContextOffsetScrambler {
    /// Derives a deterministic, collision-free slot layout from a seed.
    pub fn from_seed(seed: u64) -> Self {
        let mut mixed = seed.wrapping_mul(0x517C_C1B7_2722_0A95) ^ 0x9E37_79B9_7F4A_7C15;

        // Total slots: 16 vregs + 8 temps + 1 flags + 7 padding slots = 32 slots (256 bytes)
        let mut slot_indices: [usize; 32] = [0; 32];
        for i in 0..32 {
            slot_indices[i] = i;
        }

        // Shuffle slots
        for i in (1..32).rev() {
            mixed = mixed
                .wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0x1405_7B7E_F767_814F);
            let j = ((mixed >> 32) as usize) % (i + 1);
            slot_indices.swap(i, j);
        }

        let mut vreg_offsets = [0i32; 16];
        for i in 0..16 {
            vreg_offsets[i] = (slot_indices[i] * 8) as i32;
        }

        let mut temp_offsets = [0i32; 8];
        for i in 0..8 {
            temp_offsets[i] = (slot_indices[16 + i] * 8) as i32;
        }

        let flags_offset = (slot_indices[24] * 8) as i32;

        Self {
            vreg_offsets,
            temp_offsets,
            flags_offset,
            total_size: 256,
        }
    }

    /// Returns the scrambled byte offset for Virtual Register `vreg_idx` (0..15).
    pub fn vreg_offset(&self, vreg_idx: u8) -> i32 {
        self.vreg_offsets[(vreg_idx & 0x0F) as usize]
    }

    /// Returns the scrambled byte offset for Virtual Temp `temp_idx` (0..7).
    pub fn temp_offset(&self, temp_idx: u8) -> i32 {
        self.temp_offsets[(temp_idx & 0x07) as usize]
    }

    /// Returns the scrambled byte offset for the Flags register.
    pub fn flags_offset(&self) -> i32 {
        self.flags_offset
    }

    /// Returns the total size of the scrambled context.
    pub fn total_size(&self) -> usize {
        self.total_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_assignment_uniqueness() {
        let assign = RegisterAssignment::from_seed_and_block(0x1234_5678_9ABC_DEF0, 42);
        let roles = [
            VmRole::BytecodeBase,
            VmRole::Vpc,
            VmRole::RollingKey,
            VmRole::TableBase,
            VmRole::VContext,
            VmRole::Temp0,
            VmRole::Temp1,
            VmRole::Temp2,
        ];

        let mut seen = std::collections::HashSet::new();
        for &role in &roles {
            let gpr = assign.get(role);
            assert_ne!(gpr, Register::None);
            assert_ne!(gpr, Register::RSP, "RSP must never be assigned as VM role");
            assert!(
                seen.insert(gpr),
                "Duplicate GPR assigned for role {:?}",
                role
            );
        }
        assign
            .validate()
            .expect("complete assignment must validate");
    }

    #[test]
    fn production_assignment_only_permutes_persistent_carriers() {
        let allowed: std::collections::HashSet<_> =
            [Register::R12, Register::R13, Register::R14, Register::R15]
                .into_iter()
                .collect();
        let roles = [
            VmRole::Vpc,
            VmRole::StackBase,
            VmRole::RollingKey,
            VmRole::TableBase,
        ];
        for seed in 0..128u64 {
            let a = RegisterAssignment::production_from_seed(seed);
            a.validate().unwrap();
            let got: std::collections::HashSet<_> = roles.into_iter().map(|r| a.get(r)).collect();
            assert_eq!(got, allowed);
            assert_eq!(a.get(VmRole::BytecodeBase), Register::R8);
            assert_eq!(a.get(VmRole::VContext), Register::RDX);
            assert_eq!(a.get(VmRole::Temp0), Register::RAX);
            assert_eq!(a.get(VmRole::Temp1), Register::RCX);
            assert_eq!(a.get(VmRole::Temp2), Register::R9);
        }
    }

    #[test]
    fn production_assignment_is_deterministic_and_diverse() {
        let a = RegisterAssignment::production_from_seed(0x1234_5678);
        assert_eq!(a, RegisterAssignment::production_from_seed(0x1234_5678));
        let mut signatures = std::collections::HashSet::new();
        for seed in 0..32u64 {
            let p = RegisterAssignment::production_from_seed(seed);
            signatures.insert((
                p.get(VmRole::BytecodeBase),
                p.get(VmRole::Vpc),
                p.get(VmRole::StackBase),
                p.get(VmRole::RollingKey),
                p.get(VmRole::TableBase),
                p.get(VmRole::VContext),
            ));
        }
        assert!(signatures.len() >= 16, "insufficient role-layout diversity");
    }

    #[test]
    fn test_register_assignment_diversity() {
        let a1 = RegisterAssignment::from_seed_and_block(0x1111_2222_3333_4444, 1);
        let a2 = RegisterAssignment::from_seed_and_block(0x5555_6666_7777_8888, 2);

        // Different seeds/blocks must yield different assignments
        assert_ne!(a1.role_to_gpr, a2.role_to_gpr);
    }

    #[test]
    fn test_register_transition_emission() {
        let a1 = RegisterAssignment::from_seed_and_block(0xAAAABBBBCCCCDDDD, 10);
        let a2 = RegisterAssignment::from_seed_and_block(0x1234567812345678, 20);

        let transitions = a1.emit_transition(&a2);
        // Ensure instructions were generated for differing layouts
        assert!(!transitions.is_empty());
    }

    #[test]
    fn test_context_offset_scrambler_bijective() {
        let scrambler = ContextOffsetScrambler::from_seed(0xCAFE_BABE_DEAD_BEEF);
        let mut seen_offsets = std::collections::HashSet::new();

        for i in 0..16 {
            let off = scrambler.vreg_offset(i);
            assert!(seen_offsets.insert(off), "Duplicate offset for vreg {}", i);
        }
        for i in 0..8 {
            let off = scrambler.temp_offset(i);
            assert!(seen_offsets.insert(off), "Duplicate offset for temp {}", i);
        }
        assert!(
            seen_offsets.insert(scrambler.flags_offset()),
            "Duplicate offset for flags"
        );
    }
}
