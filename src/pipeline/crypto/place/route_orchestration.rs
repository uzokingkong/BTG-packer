use crate::analysis::indirect_targets::{IndirectTarget, ResolutionStatus};
use crate::analysis::program_model::{FunctionId, ProgramModel};
use crate::vm::multi_family::MaterializedMultiFamilyProgram;
use crate::vm::poly::ProductionFamilyPlan;
use crate::vm::route_table::{
    EntryVip, FunctionRoute, GatewayKind, MaterializedRouteTable, OriginalTargetRva, RouteTable,
};
use anyhow::{anyhow, bail, Result};
use std::collections::BTreeMap;

const MAX_COMMERCIAL_ROUTES: usize = 65_536;

/// Builds the immutable runtime route image from canonical indirect-target
/// proof. Incomplete sites do not assert routes; every internal target of a
/// complete site must have an exact canonical function entry and a materialized
/// family-local instruction offset.
pub(super) fn build_commercial_routes(
    program: &ProgramModel,
    plan: &ProductionFamilyPlan,
    materialized: &MaterializedMultiFamilyProgram,
    image_base: u64,
) -> Result<Option<MaterializedRouteTable>> {
    let mut required = BTreeMap::<OriginalTargetRva, (FunctionId, u64, GatewayKind)>::new();

    for site in program.indirect_targets.sites.values() {
        if site.status != ResolutionStatus::Complete {
            continue;
        }
        let source = program
            .functions
            .get(&site.source_function)
            .ok_or_else(|| {
                anyhow!(
                    "canonical indirect site {:?} has no source function",
                    site.id
                )
            })?;
        let source_rva = *source
            .entries
            .iter()
            .next()
            .ok_or_else(|| anyhow!("canonical source function {:?} has no entry", source.id))?;
        let source_va = image_base
            .checked_add(u64::from(source_rva))
            .ok_or_else(|| anyhow!("source function VA overflow at RVA {source_rva:#x}"))?;
        let source_family = plan.assignment_for(source_va).ok_or_else(|| {
            anyhow!("complete indirect site {:?} source RVA {source_rva:#x} has no family assignment", site.id)
        })?.family;

        for target in site.targets.targets.keys() {
            let (function_id, target_rva) = match *target {
                IndirectTarget::External(_) => continue,
                IndirectTarget::Function(id) => {
                    let function = program.functions.get(&id).ok_or_else(|| {
                        anyhow!(
                            "complete indirect site {:?} targets missing function {id:?}",
                            site.id
                        )
                    })?;
                    let rva = *function.entries.iter().next().ok_or_else(|| {
                        anyhow!("complete indirect target function {id:?} has no entry")
                    })?;
                    (id, rva)
                }
                IndirectTarget::Block(id) => {
                    let block = program.blocks.get(&id).ok_or_else(|| {
                        anyhow!(
                            "complete indirect site {:?} targets missing block {id:?}",
                            site.id
                        )
                    })?;
                    let function = program.functions.get(&block.function_id).ok_or_else(|| {
                        anyhow!("complete indirect target block {id:?} has no function")
                    })?;
                    if !function.entries.contains(&block.range.start) {
                        bail!("complete indirect target block {id:?} at RVA {:#x} is not a canonical function entry", block.range.start);
                    }
                    (block.function_id, block.range.start)
                }
            };
            let target_va = image_base
                .checked_add(u64::from(target_rva))
                .ok_or_else(|| anyhow!("target function VA overflow at RVA {target_rva:#x}"))?;
            let target_family = plan
                .assignment_for(target_va)
                .ok_or_else(|| {
                    anyhow!("complete indirect target RVA {target_rva:#x} has no family assignment")
                })?
                .family;
            let module = materialized.modules.iter().find(|module| module.family == target_family)
                .ok_or_else(|| anyhow!("complete indirect target RVA {target_rva:#x} has no materialized {:?} module", target_family))?;
            let entry_vip = *module.ip_map.get(&target_va).ok_or_else(|| {
                anyhow!(
                    "complete indirect target RVA {target_rva:#x} has no family-local entry VIP"
                )
            })?;
            let gateway = if source_family == target_family {
                GatewayKind::VmEntry
            } else {
                GatewayKind::CrossFamily
            };
            let candidate = (function_id, entry_vip as u64, gateway);
            if let Some(existing) = required.insert(OriginalTargetRva(target_rva), candidate) {
                if existing != candidate {
                    bail!("complete indirect target RVA {target_rva:#x} requires conflicting family gateways");
                }
            }
        }
    }

    if required.is_empty() {
        return Ok(None);
    }
    let mut table = RouteTable::default();
    for (rva, (function_id, entry_vip, gateway)) in required {
        let target_va = image_base + u64::from(rva.0);
        let family = plan
            .assignment_for(target_va)
            .ok_or_else(|| anyhow!("route target RVA {:#x} lost its family assignment", rva.0))?
            .family;
        table.register(
            program,
            rva,
            FunctionRoute {
                function_id,
                family,
                entry_vip: EntryVip(entry_vip),
                gateway,
            },
        )?;
    }
    Ok(Some(table.materialize(MAX_COMMERCIAL_ROUTES)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::indirect_targets::{
        IndirectKind, IndirectSite, IndirectSiteId, TargetProvenance, TargetSet,
    };
    use crate::analysis::program_model::{
        BlockId, BlockModel, ByteClass, FunctionModel, FunctionProvenance, RvaRange,
    };
    use crate::vm::multi_family::EncodedFamilyPartition;
    use crate::vm::poly::{FunctionFamilyAssignment, VmArchitectureFamily};
    use std::collections::{BTreeSet, HashMap};

    const BASE: u64 = 0x1_4000_0000;

    fn fixture() -> (
        ProgramModel,
        ProductionFamilyPlan,
        MaterializedMultiFamilyProgram,
    ) {
        let mut program = ProgramModel::default();
        for (fid, bid, start) in [
            (FunctionId(1), BlockId(1), 0x1000),
            (FunctionId(2), BlockId(2), 0x2000),
        ] {
            let range = RvaRange::new(start, start + 0x10).unwrap();
            program.functions.insert(
                fid,
                FunctionModel {
                    id: fid,
                    ranges: vec![range],
                    entries: BTreeSet::from([start]),
                    blocks: BTreeSet::from([bid]),
                    provenance: BTreeSet::from([FunctionProvenance::Pdata]),
                    unwind: None,
                },
            );
            program.blocks.insert(
                bid,
                BlockModel {
                    id: bid,
                    function_id: fid,
                    range,
                    instructions: Vec::new(),
                    byte_class: ByteClass::Instruction,
                },
            );
        }
        let mut targets = TargetSet::default();
        targets.insert(
            IndirectTarget::Function(FunctionId(2)),
            TargetProvenance::PointerTable,
        );
        program.indirect_targets.sites.insert(
            IndirectSiteId(7),
            IndirectSite {
                id: IndirectSiteId(7),
                instruction_rva: 0x1000,
                source_block: BlockId(1),
                source_function: FunctionId(1),
                kind: IndirectKind::Call,
                status: ResolutionStatus::Complete,
                targets,
                table: None,
            },
        );
        let plan = ProductionFamilyPlan {
            entry_function: BASE + 0x1000,
            entry_family: VmArchitectureFamily::Stack,
            assignments: vec![
                FunctionFamilyAssignment {
                    function_id: BASE + 0x1000,
                    family: VmArchitectureFamily::Stack,
                    incoming_bridge: None,
                },
                FunctionFamilyAssignment {
                    function_id: BASE + 0x2000,
                    family: VmArchitectureFamily::Register,
                    incoming_bridge: None,
                },
            ],
        };
        let modules = vec![EncodedFamilyPartition {
            family: VmArchitectureFamily::Register,
            bytecode: vec![0],
            instruction_offsets: vec![0],
            ip_map: HashMap::from([(BASE + 0x2000, 0)]),
            module_domain: 1,
            exit_byte_offset: 0,
        }];
        (
            program,
            plan,
            MaterializedMultiFamilyProgram {
                modules,
                route_table: Vec::new(),
            },
        )
    }

    #[test]
    fn stages_complete_internal_target_with_family_local_vip() {
        let (program, plan, multi) = fixture();
        let routes = build_commercial_routes(&program, &plan, &multi, BASE)
            .unwrap()
            .unwrap();
        let route = routes.lookup(OriginalTargetRva(0x2000)).unwrap();
        assert_eq!(route.function_id, FunctionId(2));
        assert_eq!(route.family, VmArchitectureFamily::Register);
        assert_eq!(route.entry_vip, EntryVip(0));
        assert_eq!(route.gateway, GatewayKind::CrossFamily);
    }

    #[test]
    fn no_indirect_proof_emits_no_route_section_and_missing_vip_fails_closed() {
        let (mut program, plan, mut multi) = fixture();
        program.indirect_targets.sites.clear();
        assert!(build_commercial_routes(&program, &plan, &multi, BASE)
            .unwrap()
            .is_none());
        let (program, plan, _) = fixture();
        multi.modules[0].ip_map.clear();
        assert!(build_commercial_routes(&program, &plan, &multi, BASE)
            .unwrap_err()
            .to_string()
            .contains("entry VIP"));
    }
}
