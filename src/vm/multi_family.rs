use crate::vm::poly::{FamilyOpPartition, ProductionFamilyPlan, VmArchitectureFamily};
use crate::vm::risc::{BranchCondition, MicroOperand, RiscOp, RiscProgram};
use crate::vm::route_table::{GatewayKind, MaterializedRouteTable, OriginalTargetRva};
use crate::vm::threaded::{poly_direct::NativeCrossFamilyRoute, VmRuntimeLayout};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct EncodedFamilyPartition {
    pub family: VmArchitectureFamily,
    /// Canonical original function-entry VAs owned by this family. Runtime
    /// indirect calls use these entries to route away from non-executable
    /// original `.text` even when no static VirtualBranch names the target.
    pub function_ids: Vec<u64>,
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

/// Final generated addresses for one independently emitted family module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratedFamilyGateway {
    pub family: VmArchitectureFamily,
    pub entry_va: u64,
    pub state_va: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalRouteMaterializationError {
    DuplicateModuleFamily(VmArchitectureFamily),
    DuplicateGatewayFamily(VmArchitectureFamily),
    DuplicateOriginalTarget(OriginalTargetRva),
    MissingModule(VmArchitectureFamily),
    MissingGateway(VmArchitectureFamily),
    NullGateway(VmArchitectureFamily),
    InvalidGatewayKind {
        rva: OriginalTargetRva,
        kind: GatewayKind,
    },
    SameFamilyRoute {
        rva: OriginalTargetRva,
        family: VmArchitectureFamily,
    },
    EntryVipOutOfRange {
        rva: OriginalTargetRva,
        family: VmArchitectureFamily,
        entry_vip: u64,
    },
}

impl std::fmt::Display for CanonicalRouteMaterializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "canonical cross-family route rejected: {self:?}")
    }
}

impl std::error::Error for CanonicalRouteMaterializationError {}

impl MaterializedMultiFamilyProgram {
    /// Converts the authoritative RVA routes into native generated-code
    /// descriptors. No address or family is inferred when its generated
    /// destination is absent.
    pub fn materialize_canonical_native_routes(
        &self,
        source_family: VmArchitectureFamily,
        routes: &MaterializedRouteTable,
        gateways: &[GeneratedFamilyGateway],
        tail_jump_resume_offset: Option<u64>,
    ) -> Result<Vec<NativeCrossFamilyRoute>, CanonicalRouteMaterializationError> {
        let mut modules = HashMap::new();
        for module in &self.modules {
            if modules.insert(module.family, module).is_some() {
                return Err(CanonicalRouteMaterializationError::DuplicateModuleFamily(
                    module.family,
                ));
            }
        }
        if !modules.contains_key(&source_family) {
            return Err(CanonicalRouteMaterializationError::MissingModule(
                source_family,
            ));
        }
        let mut destinations = HashMap::new();
        for gateway in gateways {
            if destinations.insert(gateway.family, *gateway).is_some() {
                return Err(CanonicalRouteMaterializationError::DuplicateGatewayFamily(
                    gateway.family,
                ));
            }
            if gateway.entry_va == 0 || gateway.state_va == 0 {
                return Err(CanonicalRouteMaterializationError::NullGateway(
                    gateway.family,
                ));
            }
        }

        let mut seen_targets = HashSet::new();
        let mut native = Vec::new();
        for &(rva, route) in routes.entries() {
            if !seen_targets.insert(rva) {
                // MaterializedRouteTable normally guarantees this; retain the
                // check at the generated-code trust boundary.
                return Err(CanonicalRouteMaterializationError::DuplicateOriginalTarget(
                    rva,
                ));
            }
            if route.gateway != GatewayKind::CrossFamily {
                return Err(CanonicalRouteMaterializationError::InvalidGatewayKind {
                    rva,
                    kind: route.gateway,
                });
            }
            if route.family == source_family {
                return Err(CanonicalRouteMaterializationError::SameFamilyRoute {
                    rva,
                    family: route.family,
                });
            }
            let module = modules.get(&route.family).copied().ok_or(
                CanonicalRouteMaterializationError::MissingModule(route.family),
            )?;
            let destination = destinations.get(&route.family).copied().ok_or(
                CanonicalRouteMaterializationError::MissingGateway(route.family),
            )?;
            let local_op = usize::try_from(route.entry_vip.0).ok();
            let byte_offset = local_op
                .and_then(|index| module.instruction_offsets.get(index))
                .copied()
                .ok_or(CanonicalRouteMaterializationError::EntryVipOutOfRange {
                    rva,
                    family: route.family,
                    entry_vip: route.entry_vip.0,
                })?;
            native.push(NativeCrossFamilyRoute {
                target_va: u64::from(rva.0),
                source_next_byte_offset: None,
                target_entry_va: destination.entry_va,
                target_state_va: destination.state_va,
                target_byte_offset: byte_offset as u64,
                target_layout: VmRuntimeLayout::from_seed(module.module_domain),
                tail_jump_resume_offset,
            });
        }
        Ok(native)
    }
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
            if std::env::var_os("BTG_TRACE_OP_MAP").is_some() {
                let local_to_ip: HashMap<usize, u64> = partition
                    .program
                    .ip_map()
                    .into_iter()
                    .flatten()
                    .map(|(&ip, &local)| (local, ip))
                    .collect();
                for (local, instruction) in partition.program.instrs.iter().enumerate() {
                    eprintln!(
                        "BTG_OP_MAP family={:?} local={} offset={:#x} ip={} op={:?}",
                        partition.family,
                        local,
                        instruction_offsets[local],
                        local_to_ip
                            .get(&local)
                            .map(|ip| format!("{ip:#x}"))
                            .unwrap_or_else(|| "-".to_string()),
                        instruction.op
                    );
                }
            }
            let exit_byte_offset = *instruction_offsets
                .last()
                .ok_or_else(|| "family partition emitted no exit offset".to_string())?;
            modules.push(EncodedFamilyPartition {
                family: partition.family,
                function_ids: partition.function_ids.clone(),
                bytecode,
                instruction_offsets,
                ip_map: partition.program.ip_map().cloned().unwrap_or_default(),
                module_domain: seed ^ family_domain(partition.family),
                exit_byte_offset,
            });
        }

        let mut route_table = Vec::with_capacity(self.routes.len());

        // Runtime routing must retain source-callsite identity.  A single source
        // family can legitimately CALL and tail-JUMP to the same target function;
        // target VA alone is therefore not a unique route key.  Keep one record
        // per source branch and only reject an actual duplicate source-site key.
        let mut runtime_sites: HashMap<
            (VmArchitectureFamily, usize, u64),
            (VmArchitectureFamily, usize, CrossFamilyRouteKind),
        > = HashMap::new();

        for route in &self.routes {
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

            let runtime_key = (route.source_family, source_local_op, route.target_va);
            let runtime_destination = (route.target_family, target_local_op, route.kind);
            if let Some(existing) = runtime_sites.insert(runtime_key, runtime_destination) {
                if existing != runtime_destination {
                    return Err(format!(
                        "ambiguous cross-family source site op {} target {:#x} from {:?}: existing {:?}, new {:?}",
                        source_local_op, route.target_va, route.source_family, existing, runtime_destination
                    ));
                }
                // Identical duplicate evidence for the exact same source branch.
                continue;
            }

            let route_id = u32::try_from(route_table.len())
                .map_err(|_| "cross-family route table exceeds u32".to_string())?;
            route_table.push(CrossFamilyRouteRecord {
                route_id,
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
    use crate::analysis::program_model::FunctionId;
    use crate::vm::poly::FunctionOpRange;
    use crate::vm::risc::{MicroInstr, MicroOperand};
    use crate::vm::route_table::{EntryVip, FunctionRoute};

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

    fn encoded_module(family: VmArchitectureFamily, domain: u64) -> EncodedFamilyPartition {
        EncodedFamilyPartition {
            family,
            function_ids: Vec::new(),
            bytecode: vec![0; 16],
            instruction_offsets: vec![0, 7, 12],
            ip_map: HashMap::new(),
            module_domain: domain,
            exit_byte_offset: 12,
        }
    }

    fn canonical_routes(entries: Vec<(u32, VmArchitectureFamily, u64)>) -> MaterializedRouteTable {
        MaterializedRouteTable::from_sorted_entries(
            entries
                .into_iter()
                .enumerate()
                .map(|(index, (rva, family, vip))| {
                    (
                        OriginalTargetRva(rva),
                        FunctionRoute {
                            function_id: FunctionId(index as u32 + 1),
                            family,
                            entry_vip: EntryVip(vip),
                            gateway: GatewayKind::CrossFamily,
                        },
                    )
                })
                .collect(),
        )
    }

    #[test]
    fn canonical_routes_resolve_to_generated_family_gateway_and_local_offset() {
        let program = MaterializedMultiFamilyProgram {
            modules: vec![
                encoded_module(VmArchitectureFamily::Stack, 11),
                encoded_module(VmArchitectureFamily::Register, 22),
            ],
            route_table: Vec::new(),
        };
        let routes = canonical_routes(vec![(0x2000, VmArchitectureFamily::Register, 1)]);
        let native = program
            .materialize_canonical_native_routes(
                VmArchitectureFamily::Stack,
                &routes,
                &[GeneratedFamilyGateway {
                    family: VmArchitectureFamily::Register,
                    entry_va: 0x5000,
                    state_va: 0x9000,
                }],
                Some(12),
            )
            .unwrap();
        assert_eq!(native.len(), 1);
        assert_eq!(native[0].target_va, 0x2000);
        assert_eq!(native[0].target_entry_va, 0x5000);
        assert_eq!(native[0].target_state_va, 0x9000);
        assert_eq!(native[0].target_byte_offset, 7);
        assert_eq!(native[0].tail_jump_resume_offset, Some(12));
        assert_eq!(native[0].target_layout, VmRuntimeLayout::from_seed(22));
    }

    #[test]
    fn canonical_route_materialization_fails_closed_on_missing_or_duplicate_data() {
        let program = MaterializedMultiFamilyProgram {
            modules: vec![
                encoded_module(VmArchitectureFamily::Stack, 11),
                encoded_module(VmArchitectureFamily::Register, 22),
            ],
            route_table: Vec::new(),
        };
        let routes = canonical_routes(vec![(0x2000, VmArchitectureFamily::Register, 3)]);
        assert!(matches!(
            program.materialize_canonical_native_routes(
                VmArchitectureFamily::Stack,
                &routes,
                &[],
                None,
            ),
            Err(CanonicalRouteMaterializationError::MissingGateway(
                VmArchitectureFamily::Register
            ))
        ));
        let gateways = [
            GeneratedFamilyGateway {
                family: VmArchitectureFamily::Register,
                entry_va: 1,
                state_va: 2,
            },
            GeneratedFamilyGateway {
                family: VmArchitectureFamily::Register,
                entry_va: 3,
                state_va: 4,
            },
        ];
        assert!(matches!(
            program.materialize_canonical_native_routes(
                VmArchitectureFamily::Stack,
                &routes,
                &gateways,
                None,
            ),
            Err(CanonicalRouteMaterializationError::DuplicateGatewayFamily(
                VmArchitectureFamily::Register
            ))
        ));

        let valid_gateway = [gateways[0]];
        assert!(matches!(
            program.materialize_canonical_native_routes(
                VmArchitectureFamily::Stack,
                &routes,
                &valid_gateway,
                None,
            ),
            Err(CanonicalRouteMaterializationError::EntryVipOutOfRange { .. })
        ));
    }
}
