//! Architecture-level polymorphism for the commercial program VM.
//!
//! This is deliberately separate from opcode permutation.  A family describes
//! the parts of the virtual machine ABI which an emitter/dispatcher must agree
//! on and provides deterministic, function-local selection.  Keeping this in a
//! value object also prevents code generators from silently mixing two family
//! ABIs without going through [`CrossVmBridge`].

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum VmArchitectureFamily {
    Stack = 0,
    Register = 1,
    MixedRisc = 2,
    FusedCisc = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DispatchTopology {
    CallRet,
    DirectThreaded,
    IndirectThreaded,
    Distributed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlagModel {
    LazyStack,
    Packed,
    Split,
    ProducerToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VmCallConvention {
    StackFrame,
    RegisterWindow,
    Descriptor,
    Continuation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VmFamilyProfile {
    pub family: VmArchitectureFamily,
    pub register_count: u8,
    pub native_width: u8,
    pub variable_width_operands: bool,
    pub flag_model: FlagModel,
    pub dispatch: DispatchTopology,
    pub call_convention: VmCallConvention,
    /// Domain separator used before opcode/register/condition generation.
    pub isa_domain: u64,
}

impl VmArchitectureFamily {
    pub const ALL: [Self; 4] = [
        Self::Stack,
        Self::Register,
        Self::MixedRisc,
        Self::FusedCisc,
    ];

    pub fn profile(self) -> VmFamilyProfile {
        match self {
            Self::Stack => VmFamilyProfile {
                family: self,
                register_count: 8,
                native_width: 8,
                variable_width_operands: false,
                flag_model: FlagModel::LazyStack,
                dispatch: DispatchTopology::CallRet,
                call_convention: VmCallConvention::StackFrame,
                isa_domain: 0x5354_4143_4B56_4D01,
            },
            Self::Register => VmFamilyProfile {
                family: self,
                register_count: 16,
                native_width: 8,
                variable_width_operands: false,
                flag_model: FlagModel::Packed,
                dispatch: DispatchTopology::DirectThreaded,
                call_convention: VmCallConvention::RegisterWindow,
                isa_domain: 0x5245_4749_5354_4552,
            },
            Self::MixedRisc => VmFamilyProfile {
                family: self,
                register_count: 24,
                native_width: 4,
                variable_width_operands: true,
                flag_model: FlagModel::Split,
                dispatch: DispatchTopology::IndirectThreaded,
                call_convention: VmCallConvention::Descriptor,
                isa_domain: 0x4D49_5845_4452_4953,
            },
            Self::FusedCisc => VmFamilyProfile {
                family: self,
                register_count: 12,
                native_width: 8,
                variable_width_operands: true,
                flag_model: FlagModel::ProducerToken,
                dispatch: DispatchTopology::Distributed,
                call_convention: VmCallConvention::Continuation,
                isa_domain: 0x4655_5345_4443_4953,
            },
        }
    }

    /// Build-level default. SplitMix finalization avoids correlations between
    /// adjacent CLI seeds while keeping reproducible builds reproducible.
    pub fn for_build(seed: u64) -> Self {
        Self::ALL[(mix64(seed) as usize) % Self::ALL.len()]
    }

    /// Select independently per function. `function_id` must be a stable RVA or
    /// lift-time function id, not traversal order.
    pub fn for_function(seed: u64, function_id: u64) -> Self {
        Self::ALL[(mix64(seed ^ function_id.rotate_left(23)) as usize) % Self::ALL.len()]
    }
}

/// Serializable description of a required cross-family transition. The bridge
/// always uses the canonical 16 x u64 register image and packed RFLAGS as its
/// interchange ABI; family-specific state remains private on either side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossVmBridge {
    pub caller: VmArchitectureFamily,
    pub callee: VmArchitectureFamily,
    pub function_id: u64,
    pub preserve_register_mask: u16,
    pub preserve_flags: bool,
}

impl CrossVmBridge {
    pub fn between(
        caller: VmArchitectureFamily,
        callee: VmArchitectureFamily,
        function_id: u64,
    ) -> Option<Self> {
        (caller != callee).then_some(Self {
            caller,
            callee,
            function_id,
            preserve_register_mask: u16::MAX,
            preserve_flags: true,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionFamilyAssignment {
    pub function_id: u64,
    pub family: VmArchitectureFamily,
    pub incoming_bridge: Option<CrossVmBridge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionFamilyPlan {
    pub entry_function: u64,
    pub entry_family: VmArchitectureFamily,
    pub assignments: Vec<FunctionFamilyAssignment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionOpRange {
    pub function_id: u64,
    pub start_op: usize,
    pub end_op: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyOpPartition {
    pub family: VmArchitectureFamily,
    pub regions: Vec<FunctionOpRange>,
}

impl ProductionFamilyPlan {
    pub fn new(seed: u64, entry_function: u64, function_ids: &[u64]) -> Self {
        let mut ids = function_ids.to_vec();
        if entry_function != 0 && !ids.contains(&entry_function) {
            ids.push(entry_function);
        }
        ids.sort_unstable();
        ids.dedup();
        Self {
            entry_function,
            entry_family: VmArchitectureFamily::for_function(seed, entry_function),
            assignments: assign_function_families(seed, entry_function, &ids),
        }
    }

    pub fn represented_families(&self) -> BTreeSet<VmArchitectureFamily> {
        represented_families(&self.assignments)
    }

    pub fn cross_family_bridge_count(&self) -> usize {
        self.assignments
            .iter()
            .filter(|assignment| assignment.incoming_bridge.is_some())
            .count()
    }

    pub fn assignment_for(&self, function_id: u64) -> Option<&FunctionFamilyAssignment> {
        self.assignments
            .iter()
            .find(|assignment| assignment.function_id == function_id)
    }

    pub fn partition_regions(
        &self,
        ranges: &[FunctionOpRange],
        program_len: usize,
    ) -> Result<Vec<FamilyOpPartition>, String> {
        let mut sorted = ranges.to_vec();
        sorted.sort_by_key(|range| (range.start_op, range.end_op));
        let mut previous_end = 0usize;
        for range in &sorted {
            if range.start_op >= range.end_op || range.end_op > program_len {
                return Err(format!(
                    "invalid function op range {:#x}: {}..{} / {}",
                    range.function_id, range.start_op, range.end_op, program_len
                ));
            }
            if range.start_op < previous_end {
                return Err(format!(
                    "overlapping function op range at {:#x}: {} < {}",
                    range.function_id, range.start_op, previous_end
                ));
            }
            if self.assignment_for(range.function_id).is_none() {
                return Err(format!(
                    "function op range has no family assignment: {:#x}",
                    range.function_id
                ));
            }
            previous_end = range.end_op;
        }

        let mut partitions = Vec::new();
        for family in VmArchitectureFamily::ALL {
            let regions: Vec<_> = sorted
                .iter()
                .copied()
                .filter(|range| {
                    self.assignment_for(range.function_id)
                        .map(|assignment| assignment.family == family)
                        .unwrap_or(false)
                })
                .collect();
            if !regions.is_empty() {
                partitions.push(FamilyOpPartition { family, regions });
            }
        }
        Ok(partitions)
    }
}

/// Deterministically assigns functions and materializes bridge requirements.
pub fn assign_function_families(
    seed: u64,
    entry_function: u64,
    function_ids: &[u64],
) -> Vec<FunctionFamilyAssignment> {
    let entry_family = VmArchitectureFamily::for_function(seed, entry_function);
    function_ids
        .iter()
        .copied()
        .map(|id| {
            let family = VmArchitectureFamily::for_function(seed, id);
            FunctionFamilyAssignment {
                function_id: id,
                family,
                incoming_bridge: CrossVmBridge::between(entry_family, family, id),
            }
        })
        .collect()
}

/// Compact architecture signature used by the N-build diversity gate.
pub fn architecture_signature(seed: u64, functions: &[u64]) -> String {
    let assignments =
        assign_function_families(seed, functions.first().copied().unwrap_or(0), functions);
    assignments
        .iter()
        .map(|a| char::from(b'0' + a.family as u8))
        .collect()
}

pub fn represented_families(
    assignments: &[FunctionFamilyAssignment],
) -> BTreeSet<VmArchitectureFamily> {
    assignments.iter().map(|a| a.family).collect()
}

pub(crate) fn family_isa_seed(seed: u64, family: VmArchitectureFamily) -> u64 {
    mix64(seed ^ family.profile().isa_domain)
}

fn mix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::poly::{PolymorphicDecoder, PolymorphicEncoder};
    use crate::vm::risc::{MicroInstr, RiscOp, RiscProgram};

    #[test]
    fn profiles_are_architecturally_distinct() {
        let profiles: Vec<_> = VmArchitectureFamily::ALL
            .iter()
            .map(|f| f.profile())
            .collect();
        assert!(
            profiles
                .iter()
                .map(|p| p.dispatch)
                .collect::<BTreeSet<_>>()
                .len()
                >= 3
        );
        assert!(
            profiles
                .iter()
                .map(|p| p.call_convention)
                .collect::<BTreeSet<_>>()
                .len()
                >= 3
        );
        assert!(
            profiles
                .iter()
                .map(|p| (p.register_count, p.native_width))
                .collect::<BTreeSet<_>>()
                .len()
                >= 3
        );
    }

    #[test]
    fn twenty_seed_gate_does_not_collapse_to_one_family_signature() {
        let functions: Vec<u64> = (0..32).map(|n| 0x1000 + n * 0x40).collect();
        let signatures: BTreeSet<_> = (0..20)
            .map(|seed| architecture_signature(seed, &functions))
            .collect();
        assert!(
            signatures.len() >= 10,
            "N=20 architecture signatures collapsed: {signatures:?}"
        );
        let all: BTreeSet<_> = (0..20)
            .flat_map(|seed| assign_function_families(seed, functions[0], &functions))
            .map(|assignment| assignment.family)
            .collect();
        assert!(all.len() >= 3, "fewer than three VM families represented");
    }

    #[test]
    fn cross_family_bridge_is_full_state_preserving() {
        let bridge = CrossVmBridge::between(
            VmArchitectureFamily::Stack,
            VmArchitectureFamily::MixedRisc,
            7,
        )
        .unwrap();
        assert_eq!(bridge.preserve_register_mask, u16::MAX);
        assert!(bridge.preserve_flags);
        assert!(CrossVmBridge::between(bridge.caller, bridge.caller, 7).is_none());
    }

    #[test]
    fn every_family_has_a_distinct_executable_isa_codec() {
        let seed = 0xA11C_EF00_5512_9917;
        let program = RiscProgram::new(vec![MicroInstr::new(RiscOp::Halt)]);
        let mut streams = BTreeSet::new();
        for family in VmArchitectureFamily::ALL {
            let mut encoder = PolymorphicEncoder::new_for_family(seed, family);
            let stream = encoder.encode(&program).unwrap();
            let mut decoder = PolymorphicDecoder::new_for_family(seed, family);
            assert_eq!(decoder.decode(&stream).unwrap().instrs[0].op, RiscOp::Halt);
            streams.insert(stream);
        }
        assert_eq!(streams.len(), VmArchitectureFamily::ALL.len());
    }

    #[test]
    fn production_plan_is_function_stable_and_bridges_only_cross_family() {
        let functions: Vec<u64> = (0..64).map(|n| 0x1400_001000 + n * 0x80).collect();
        let plan = ProductionFamilyPlan::new(0xA11C_E551, functions[0], &functions);
        assert_eq!(plan.assignments.len(), functions.len());
        assert!(plan.represented_families().len() >= 3);
        assert_eq!(
            plan.assignment_for(plan.entry_function).unwrap().family,
            plan.entry_family
        );
        for assignment in &plan.assignments {
            assert_eq!(
                assignment.incoming_bridge.is_some(),
                assignment.family != plan.entry_family,
                "same-family edge emitted a bridge for {:#x}",
                assignment.function_id
            );
        }
    }

    #[test]
    fn production_partition_groups_ranges_without_overlap() {
        let functions = [0x1000, 0x1100, 0x1200, 0x1300];
        let plan = ProductionFamilyPlan::new(0x5151_AAAA, functions[0], &functions);
        let ranges: Vec<_> = functions
            .iter()
            .enumerate()
            .map(|(index, function_id)| FunctionOpRange {
                function_id: *function_id,
                start_op: 1 + index * 10,
                end_op: 1 + (index + 1) * 10,
            })
            .collect();
        let partitions = plan.partition_regions(&ranges, 41).unwrap();
        assert_eq!(
            partitions
                .iter()
                .map(|part| part.regions.len())
                .sum::<usize>(),
            ranges.len()
        );
        let mut overlap = ranges.clone();
        overlap[1].start_op = overlap[0].end_op - 1;
        assert!(plan.partition_regions(&overlap, 41).is_err());
    }
}
