use crate::vm::poly::{FamilyOpPartition, ProductionFamilyPlan, VmArchitectureFamily};
use crate::vm::risc::{BranchCondition, MicroOperand, RiscOp, RiscProgram};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct EncodedFamilyPartition {
    pub family: VmArchitectureFamily,
    pub bytecode: Vec<u8>,
    pub instruction_offsets: Vec<usize>,
    pub ip_map: HashMap<u64, usize>,
    /// Family-separated domains used by the module builder for state layout,
    /// handler table, fetch topology, and runtime key derivation.
    pub module_domain: u64,
    /// Dedicated local continuation used when a cross-family tail jump returns
    /// from its target module.
    pub exit_byte_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossFamilyRouteRecord {
    pub route_id: u32,
    pub source_family: VmArchitectureFamily,
    pub source_local_op: usize,
    pub resume_local_op: Option<usize>,
    pub target_family: VmArchitectureFamily,
    pub target_va: u64,
    pub target_local_op: usize,
    pub kind: CrossFamilyRouteKind,
}

#[derive(Debug, Clone)]
pub struct MaterializedMultiFamilyProgram {
    pub modules: Vec<EncodedFamilyPartition>,
    pub route_table: Vec<CrossFamilyRouteRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossFamilyRouteKind {
    Call,
    Jump,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossFamilyRoute {
    pub source_function: u64,
    pub source_family: VmArchitectureFamily,
    pub source_op: usize,
    pub target_function: u64,
    pub target_family: VmArchitectureFamily,
    pub target_va: u64,
    pub kind: CrossFamilyRouteKind,
}

#[derive(Debug, Clone)]
pub struct FamilyProgramPartition {
    pub family: VmArchitectureFamily,
    pub program: RiscProgram,
    pub original_to_local: HashMap<usize, usize>,
    pub function_ids: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct MultiFamilyProgramPlan {
    pub partitions: Vec<FamilyProgramPartition>,
    pub routes: Vec<CrossFamilyRoute>,
}

impl MultiFamilyProgramPlan {
    pub fn build(
        program: &RiscProgram,
        family_plan: &ProductionFamilyPlan,
        partitions: &[FamilyOpPartition],
    ) -> Result<Self, String> {
        let global_ip_map = program
            .ip_map()
            .ok_or_else(|| "multi-family program requires a source IP map".to_string())?;
        let mut op_owner = HashMap::new();
        for partition in partitions {
            for range in &partition.regions {
                for op in range.start_op..range.end_op {
                    if op_owner.insert(op, range.function_id).is_some() {
                        return Err(format!("RISC op {op} has multiple function owners"));
                    }
                }
            }
        }

        let mut output = Vec::new();
        for partition in partitions {
            let mut instrs = Vec::new();
            let mut original_to_local = HashMap::new();
            let mut function_ids = Vec::new();
            for range in &partition.regions {
                function_ids.push(range.function_id);
                for original in range.start_op..range.end_op {
                    original_to_local.insert(original, instrs.len());
                    instrs.push(program.instrs[original].clone());
                }
            }
            let local_ip_map: HashMap<u64, usize> = global_ip_map
                .iter()
                .filter_map(|(ip, original)| {
                    original_to_local
                        .get(original)
                        .copied()
                        .map(|local| (*ip, local))
                })
                .collect();
            output.push(FamilyProgramPartition {
                family: partition.family,
                program: RiscProgram::with_ip_map(instrs, local_ip_map),
                original_to_local,
                function_ids,
            });
        }

        let mut routes = Vec::new();
        for (source_op, ins) in program.instrs.iter().enumerate() {
            let RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            } = ins.op
            else {
                continue;
            };
            if ins.src1.is_some() {
                continue;
            }
            let Some(&target_op) = global_ip_map.get(&ins.imm) else {
                continue;
            };
            let (Some(&source_function), Some(&target_function)) =
                (op_owner.get(&source_op), op_owner.get(&target_op))
            else {
                continue;
            };
            let source = family_plan
                .assignment_for(source_function)
                .ok_or_else(|| format!("missing source family for {source_function:#x}"))?;
            let target = family_plan
                .assignment_for(target_function)
                .ok_or_else(|| format!("missing target family for {target_function:#x}"))?;
            if source.family == target.family {
                continue;
            }
            let is_call = source_op > 0
                && matches!(program.instrs[source_op - 1].op, RiscOp::VirtualPush)
                && matches!(
                    program.instrs[source_op - 1].src1,
                    Some(MicroOperand::Imm64(_))
                );
            routes.push(CrossFamilyRoute {
                source_function,
                source_family: source.family,
                source_op,
                target_function,
                target_family: target.family,
                target_va: ins.imm,
                kind: if is_call {
                    CrossFamilyRouteKind::Call
                } else {
                    CrossFamilyRouteKind::Jump
                },
            });
        }
        Ok(Self {
            partitions: output,
            routes,
        })
    }

    pub fn materialize(&self, seed: u64) -> Result<MaterializedMultiFamilyProgram, String> {
        let mut modules = Vec::with_capacity(self.partitions.len());
        for partition in &self.partitions {
            let mut routed_program = partition.program.clone();
            routed_program
                .instrs
                .push(crate::vm::risc::MicroInstr::new(RiscOp::Halt));
            let mut encoder = crate::vm::poly::PolymorphicEncoder::new_for_family(
                seed ^ family_domain(partition.family),
                partition.family,
            );
            let (bytecode, instruction_offsets) = encoder
                .encode_with_offsets(&routed_program)
                .map_err(|error| error.to_string())?;
            let exit_byte_offset = *instruction_offsets
                .last()
                .ok_or_else(|| "family partition emitted no exit offset".to_string())?;
            modules.push(EncodedFamilyPartition {
                family: partition.family,
                bytecode,
                instruction_offsets,
                ip_map: partition.program.ip_map().cloned().unwrap_or_default(),
                module_domain: seed ^ family_domain(partition.family),
                exit_byte_offset,
            });
        }

        let mut route_table = Vec::with_capacity(self.routes.len());
        for (route_id, route) in self.routes.iter().enumerate() {
            let source = self
                .partitions
                .iter()
                .find(|partition| partition.family == route.source_family)
                .ok_or_else(|| format!("missing source partition {:?}", route.source_family))?;
            let target = self
                .partitions
                .iter()
                .find(|partition| partition.family == route.target_family)
                .ok_or_else(|| format!("missing target partition {:?}", route.target_family))?;
            let source_local_op = source
                .original_to_local
                .get(&route.source_op)
                .copied()
                .ok_or_else(|| format!("missing local source op {}", route.source_op))?;
            let target_local_op = target
                .program
                .ip_map()
                .and_then(|map| map.get(&route.target_va))
                .copied()
                .ok_or_else(|| format!("missing local target VA {:#x}", route.target_va))?;
            route_table.push(CrossFamilyRouteRecord {
                route_id: u32::try_from(route_id)
                    .map_err(|_| "cross-family route table exceeds u32".to_string())?,
                source_family: route.source_family,
                source_local_op,
                resume_local_op: (route.kind == CrossFamilyRouteKind::Call)
                    .then_some(source_local_op + 1),
                target_family: route.target_family,
                target_va: route.target_va,
                target_local_op,
                kind: route.kind,
            });
        }
        Ok(MaterializedMultiFamilyProgram {
            modules,
            route_table,
        })
    }
}

fn family_domain(family: VmArchitectureFamily) -> u64 {
    match family {
        VmArchitectureFamily::Stack => 0x5354_4143_4B00_0001,
        VmArchitectureFamily::Register => 0x5245_4749_5354_0002,
        VmArchitectureFamily::MixedRisc => 0x4D49_5845_4452_0003,
        VmArchitectureFamily::FusedCisc => 0x4655_5345_4443_0004,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::poly::FunctionOpRange;
    use crate::vm::risc::{MicroInstr, MicroOperand};

    #[test]
    fn splits_program_and_classifies_cross_family_call() {
        let seed = 7;
        let functions = [0x1000, 0x2000];
        let mut family_plan = ProductionFamilyPlan::new(seed, functions[0], &functions);
        family_plan.assignments[0].family = VmArchitectureFamily::Stack;
        family_plan.assignments[1].family = VmArchitectureFamily::Register;
        let ranges = [
            FunctionOpRange {
                function_id: 0x1000,
                start_op: 0,
                end_op: 3,
            },
            FunctionOpRange {
                function_id: 0x2000,
                start_op: 3,
                end_op: 5,
            },
        ];
        let partitions = family_plan.partition_regions(&ranges, 5).unwrap();
        let program = RiscProgram::with_ip_map(
            vec![
                MicroInstr::new(RiscOp::VirtualPush).with_src1(MicroOperand::Imm64(0x1005)),
                MicroInstr::new(RiscOp::VirtualBranch {
                    cond: BranchCondition::Always,
                })
                .with_imm(0x2000),
                MicroInstr::new(RiscOp::VirtualRet),
                MicroInstr::new(RiscOp::Mov),
                MicroInstr::new(RiscOp::VirtualRet),
            ],
            HashMap::from([(0x1000, 0), (0x2000, 3)]),
        );
        let split = MultiFamilyProgramPlan::build(&program, &family_plan, &partitions).unwrap();
        assert_eq!(split.partitions.len(), 2);
        assert_eq!(split.routes.len(), 1);
        assert_eq!(split.routes[0].kind, CrossFamilyRouteKind::Call);
        let materialized = split.materialize(seed).unwrap();
        assert_eq!(materialized.modules.len(), 2);
        assert_eq!(materialized.route_table.len(), 1);
        let route = materialized.route_table[0];
        assert_eq!(route.source_local_op, 1);
        assert_eq!(route.resume_local_op, Some(2));
        assert_eq!(route.target_local_op, 0);
        assert_ne!(
            materialized.modules[0].module_domain,
            materialized.modules[1].module_domain
        );
    }
}
