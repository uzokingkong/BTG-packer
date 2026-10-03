//! Immutable, private build-time contract. This first schema snapshots the
//! existing ISA and state layout; it does not claim independent family runtimes
//! or additional handler recipes. Never include these bytes in public manifests.
use super::{variant_validate, VirtualIsaSpec, VmArchitectureFamily};
use crate::vm::table_layout::TableLayout;
use crate::vm::threaded::reg_permutation::RegisterAssignment;
use crate::vm::threaded::VmRuntimeLayout;
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};

pub const VARIANT_SCHEMA_VERSION: u32 = 3;
pub const VARIANT_FAMILY_ABI_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VariantPolicy {
    /// Preserve the existing seed/family ISA generation contract.
    Stable,
    /// Domain-separate the ISA and state layout by canonical module identity.
    Seeded,
}

#[derive(Clone, Debug)]
pub struct VariantPlan {
    module_identity: [u8; 32],
    policy: VariantPolicy,
    spec: VirtualIsaSpec,
    layout: VmRuntimeLayout,
    table: TableLayout,
    carriers: RegisterAssignment,
    wrapper_padding: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanSnapshot {
    schema: u32,
    family_abi: u32,
    module: [u8; 32],
    policy: VariantPolicy,
    family: VmArchitectureFamily,
    seed: u64,
    operand_mask: u64,
    registers: [u8; 16],
    inverse_registers: [u8; 16],
    opcodes: Vec<(u8, crate::vm::risc::RiscOp)>,
    conditions: Vec<(u8, crate::vm::risc::BranchCondition)>,
    layout: VmRuntimeLayout,
    table: TableLayout,
    carriers: [u8; 4],
    wrapper_padding: Vec<u8>,
}

impl VariantPlan {
    /// Migration adapter for callers with an already selected runtime layout.
    /// Takes ownership so subsequent placement passes can share this snapshot.
    pub(crate) fn from_contract(
        module_identity: [u8; 32],
        spec: VirtualIsaSpec,
        layout: VmRuntimeLayout,
        table: TableLayout,
    ) -> Result<Self> {
        variant_validate::validate_contract(&spec, &layout)?;
        table.validate()?;
        let carriers = RegisterAssignment::production_from_seed(spec.seed);
        carriers.validate().map_err(anyhow::Error::msg)?;
        let wrapper_padding = (0..=255)
            .map(|byte| {
                let plan =
                    crate::vm::handler_poly::HandlerSynthesisPlan::synthesize(spec.seed, byte);
                1 + ((plan.context_key ^ plan.dead_state_slots as u64 ^ plan.control_splits as u64)
                    & 3) as u8
            })
            .collect();
        Ok(Self {
            module_identity,
            policy: VariantPolicy::Stable,
            spec,
            layout,
            table,
            carriers,
            wrapper_padding,
        })
    }

    /// `module_identity` is a content digest or other canonical identity, never
    /// a path, traversal index, timestamp, or provisional placement address.
    pub fn generate(
        module_identity: [u8; 32],
        seed: u64,
        family: VmArchitectureFamily,
        policy: VariantPolicy,
    ) -> Result<Self> {
        let effective_seed = match policy {
            VariantPolicy::Stable => seed,
            VariantPolicy::Seeded => {
                let mut hash = Sha256::new();
                hash.update(b"BTG/variant-plan/seed\0");
                hash.update(VARIANT_SCHEMA_VERSION.to_le_bytes());
                hash.update(VARIANT_FAMILY_ABI_VERSION.to_le_bytes());
                hash.update(module_identity);
                hash.update(seed.to_le_bytes());
                hash.update([family as u8]);
                let digest = hash.finalize();
                u64::from_le_bytes(digest[..8].try_into().unwrap())
            }
        };
        let mut plan = Self::from_contract(
            module_identity,
            VirtualIsaSpec::from_seed_and_family(effective_seed, family),
            VmRuntimeLayout::from_seed(effective_seed),
            TableLayout::from_seed(effective_seed),
        )?;
        plan.policy = policy;
        Ok(plan)
    }

    pub fn isa(&self) -> &VirtualIsaSpec {
        &self.spec
    }
    pub fn runtime_layout(&self) -> &VmRuntimeLayout {
        &self.layout
    }
    pub fn module_identity(&self) -> [u8; 32] {
        self.module_identity
    }
    pub fn policy(&self) -> VariantPolicy {
        self.policy
    }

    pub fn table_layout(&self) -> TableLayout {
        self.table
    }
    pub fn native_role_assignment(&self) -> &RegisterAssignment {
        &self.carriers
    }
    /// Padding variation is not counted as semantic handler diversity.
    pub fn handler_wrapper_padding(&self, opcode: u8) -> usize {
        self.wrapper_padding[opcode as usize] as usize
    }

    /// Canonical private checkpoint. Map entries are ordered by wire token and
    /// all semantics are typed, versioned serde records rather than Debug text.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut opcodes: Vec<_> = self
            .spec
            .reverse_opcode_map
            .iter()
            .map(|(&token, &op)| (token, op))
            .collect();
        opcodes.sort_unstable_by_key(|(token, _)| *token);
        let mut conditions: Vec<_> = self
            .spec
            .reverse_branch_cond_map
            .iter()
            .map(|(&token, &cond)| (token, cond))
            .collect();
        conditions.sort_unstable_by_key(|(token, _)| *token);
        serde_json::to_vec(&PlanSnapshot {
            schema: VARIANT_SCHEMA_VERSION,
            family_abi: VARIANT_FAMILY_ABI_VERSION,
            module: self.module_identity,
            policy: self.policy,
            family: self.spec.family,
            seed: self.spec.seed,
            operand_mask: self.spec.operand_mask,
            registers: self.spec.register_permutation,
            inverse_registers: self.spec.reverse_reg_permutation,
            opcodes,
            conditions,
            layout: self.layout.clone(),
            table: self.table,
            carriers: self.carriers.carrier_order(),
            wrapper_padding: self.wrapper_padding.clone(),
        })
        .expect("typed variant snapshot contains only JSON-compatible values")
    }

    /// Restore the actual selected maps and layout, without rerolling any plan
    /// fields. `expected_identity` must come from the containing checkpoint.
    /// These checks detect corruption; local build caches are not trust roots.
    pub fn restore(bytes: &[u8], expected_identity: &[u8; 32]) -> Result<Self> {
        ensure!(bytes.len() <= 128 * 1024, "variant checkpoint too large");
        ensure!(
            <[u8; 32]>::from(Sha256::digest(bytes)) == *expected_identity,
            "variant checkpoint digest mismatch"
        );
        let snapshot: PlanSnapshot = serde_json::from_slice(bytes)?;
        ensure!(
            snapshot.schema == VARIANT_SCHEMA_VERSION
                && snapshot.family_abi == VARIANT_FAMILY_ABI_VERSION,
            "unsupported variant schema/family ABI"
        );
        ensure!(
            snapshot.opcodes.len() <= 256 && snapshot.conditions.len() <= 256,
            "variant map too large"
        );
        let opcode_count = snapshot.opcodes.len();
        let condition_count = snapshot.conditions.len();
        let spec = VirtualIsaSpec {
            seed: snapshot.seed,
            family: snapshot.family,
            family_profile: snapshot.family.profile(),
            opcode_map: snapshot
                .opcodes
                .iter()
                .map(|&(token, op)| (op, token))
                .collect(),
            reverse_opcode_map: snapshot.opcodes.into_iter().collect(),
            branch_cond_map: snapshot
                .conditions
                .iter()
                .map(|&(token, cond)| (cond, token))
                .collect(),
            reverse_branch_cond_map: snapshot.conditions.into_iter().collect(),
            operand_mask: snapshot.operand_mask,
            register_permutation: snapshot.registers,
            reverse_reg_permutation: snapshot.inverse_registers,
        };
        ensure!(
            spec.opcode_map.len() == opcode_count
                && spec.reverse_opcode_map.len() == opcode_count
                && spec.branch_cond_map.len() == condition_count
                && spec.reverse_branch_cond_map.len() == condition_count,
            "duplicate variant checkpoint map entry"
        );
        variant_validate::validate_contract(&spec, &snapshot.layout)?;
        snapshot.table.validate()?;
        ensure!(
            snapshot.wrapper_padding.len() == 256
                && snapshot.wrapper_padding.iter().all(|n| (1..=4).contains(n)),
            "unsupported handler wrapper padding"
        );
        let carriers = RegisterAssignment::from_carrier_order(snapshot.carriers)
            .map_err(anyhow::Error::msg)?;
        let plan = Self {
            module_identity: snapshot.module,
            policy: snapshot.policy,
            spec,
            layout: snapshot.layout,
            table: snapshot.table,
            carriers,
            wrapper_padding: snapshot.wrapper_padding,
        };
        ensure!(
            plan.canonical_bytes() == bytes,
            "variant checkpoint is not canonical"
        );
        Ok(plan)
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// Bind a module checkpoint to the full plan, including module and ABI.
    pub fn validate_checkpoint_identity(&self, identity: &[u8; 32]) -> Result<()> {
        anyhow::ensure!(
            *identity == self.digest(),
            "variant checkpoint identity mismatch"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::poly::{PolymorphicDecoder, PolymorphicEncoder};
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscOp, RiscProgram};

    #[test]
    fn restores_actual_plan_and_rejects_bad_checkpoints() {
        for family in VmArchitectureFamily::ALL {
            let plan = VariantPlan::generate([9; 32], 31, family, VariantPolicy::Seeded).unwrap();
            let bytes = plan.canonical_bytes();
            let restored = VariantPlan::restore(&bytes, &plan.digest()).unwrap();
            assert_eq!(restored.canonical_bytes(), bytes);
            assert_eq!(restored.runtime_layout(), plan.runtime_layout());
            assert_eq!(restored.isa().opcode_map, plan.isa().opcode_map);
            assert_eq!(restored.table_layout(), plan.table_layout());
            assert_eq!(
                restored.native_role_assignment(),
                plan.native_role_assignment()
            );
            for opcode in 0..=255 {
                assert_eq!(
                    restored.handler_wrapper_padding(opcode),
                    plan.handler_wrapper_padding(opcode)
                );
            }
            assert!(VariantPlan::restore(&bytes, &[0; 32]).is_err());
            for mutation in 0..8 {
                let mut snapshot: PlanSnapshot = serde_json::from_slice(&bytes).unwrap();
                match mutation {
                    0 => snapshot.schema += 1,
                    1 => snapshot.family_abi += 1,
                    2 => snapshot.opcodes.push(snapshot.opcodes[0]),
                    3 => snapshot.layout.xmm_slots = usize::MAX,
                    4 => snapshot.registers[0] = 16,
                    5 => snapshot.carriers[0] = 4,
                    6 => snapshot.table.operand_offs_off = 0,
                    _ => snapshot.wrapper_padding[0] = 0,
                }
                let bad = serde_json::to_vec(&snapshot).unwrap();
                assert!(VariantPlan::restore(&bad, &Sha256::digest(&bad).into()).is_err());
            }
        }
    }

    #[test]
    fn reproducible_and_module_scoped() {
        for family in VmArchitectureFamily::ALL {
            let make =
                |id, seed| VariantPlan::generate(id, seed, family, VariantPolicy::Seeded).unwrap();
            let a = make([1; 32], 42);
            let b = make([1; 32], 42);
            assert_eq!(a.canonical_bytes(), b.canonical_bytes());
            assert_eq!(a.digest(), b.digest());
            let c = make([2; 32], 42);
            let d = make([1; 32], 43);
            assert_ne!(a.isa().opcode_map, c.isa().opcode_map);
            assert_ne!(a.isa().register_permutation, d.isa().register_permutation);
            assert_ne!(a.runtime_layout(), d.runtime_layout());
            assert!(a.validate_checkpoint_identity(&b.digest()).is_ok());
            assert!(a.validate_checkpoint_identity(&c.digest()).is_err());
            assert!(a.validate_checkpoint_identity(&d.digest()).is_err());
        }
    }

    #[test]
    fn shared_plan_codec_round_trip_and_legacy_compatibility() {
        let program = RiscProgram::new(vec![
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::Imm64(0x123456789ABCDEF0)),
            MicroInstr::new(RiscOp::Halt),
        ]);
        for family in VmArchitectureFamily::ALL {
            for policy in [VariantPolicy::Stable, VariantPolicy::Seeded] {
                let plan = VariantPlan::generate([7; 32], 99, family, policy).unwrap();
                let bytes = PolymorphicEncoder::from_variant_plan(&plan)
                    .encode(&program)
                    .unwrap();
                let decoded = PolymorphicDecoder::from_variant_plan(&plan)
                    .decode(&bytes)
                    .unwrap();
                assert_eq!(
                    format!("{:?}", decoded.instrs),
                    format!("{:?}", program.instrs)
                );
                if policy == VariantPolicy::Stable {
                    assert_eq!(
                        bytes,
                        PolymorphicEncoder::new_for_family(99, family)
                            .encode(&program)
                            .unwrap()
                    );
                }
            }
        }
    }
}
