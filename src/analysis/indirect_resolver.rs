//! Fail-closed application of indirect-target analysis to the canonical model.

use std::collections::{BTreeMap, BTreeSet};

use super::indirect_targets::{
    IndirectKind, IndirectSiteId, IndirectTarget, ResolutionStatus, TargetProvenance,
};
use super::program_model::{BlockId, EdgeKind, EdgeModel, EdgeTarget, FunctionId, ProgramModel};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndirectResolution {
    pub site: IndirectSiteId,
    pub target_rvas: BTreeSet<u32>,
    pub provenance: TargetProvenance,
    /// True only when the producer proved that the target inventory is exhaustive.
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndirectResolveError {
    MissingSite(IndirectSiteId),
    EmptyCompleteSet(IndirectSiteId),
    UnmappedTarget(IndirectSiteId, u32),
    AmbiguousTarget(IndirectSiteId, u32),
    MissingUnresolvedEdge(IndirectSiteId),
    MultipleUnresolvedEdges(IndirectSiteId),
}

impl std::fmt::Display for IndirectResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot apply indirect resolution: {self:?}")
    }
}

impl std::error::Error for IndirectResolveError {}

/// Atomically maps analyzed RVAs and updates both the site inventory and its CFG edge.
///
/// Calls may target only declared function entries; jumps may target only block starts.
/// This deliberately refuses to guess when the canonical model has an ambiguous address.
pub fn apply_indirect_resolution(
    program: &mut ProgramModel,
    resolution: &IndirectResolution,
) -> Result<(), IndirectResolveError> {
    let mut next = program.clone();
    apply(&mut next, resolution)?;
    *program = next;
    Ok(())
}

/// Marks a canonical indirect call as an exhaustive external slot dispatch
/// (for example, a PE IAT entry). The slot VA is used as the stable external
/// identity; the loader-populated function VA is intentionally not guessed.
pub fn apply_external_indirect_resolution(
    program: &mut ProgramModel,
    site_id: IndirectSiteId,
    slot_va: u64,
    provenance: TargetProvenance,
) -> Result<(), IndirectResolveError> {
    let mut next = program.clone();
    let site = next
        .indirect_targets
        .sites
        .get(&site_id)
        .ok_or(IndirectResolveError::MissingSite(site_id))?
        .clone();
    let edge_kind = match site.kind {
        IndirectKind::Call => EdgeKind::IndirectCall,
        IndirectKind::Jump => EdgeKind::IndirectJump,
    };
    let matching = next
        .edges
        .iter()
        .enumerate()
        .filter(|(_, edge)| {
            edge.source == site.source_block
                && edge.kind == edge_kind
                && edge.target == EdgeTarget::Unresolved
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [index] => {
            next.edges.remove(*index);
        }
        [] => return Err(IndirectResolveError::MissingUnresolvedEdge(site_id)),
        _ => return Err(IndirectResolveError::MultipleUnresolvedEdges(site_id)),
    }
    let target = IndirectTarget::External(slot_va);
    let target_site = next.indirect_targets.sites.get_mut(&site_id).unwrap();
    target_site.targets.insert(target, provenance);
    target_site.status = ResolutionStatus::Complete;
    next.edges.push(EdgeModel {
        source: site.source_block,
        kind: edge_kind,
        target: EdgeTarget::External(slot_va),
    });
    next.edges.sort_by_key(edge_key);
    *program = next;
    Ok(())
}

/// Closes an indirect site with the canonical runtime-route partition. At
/// execution time the computed address is first looked up in the complete
/// ProgramModel route; addresses outside the image use the native bridge.
/// This represents the dispatch algorithm itself, not a guessed target.
pub fn apply_runtime_route_resolution(
    program: &mut ProgramModel,
    site_id: IndirectSiteId,
) -> Result<(), IndirectResolveError> {
    let mut next = program.clone();
    let site = next
        .indirect_targets
        .sites
        .get(&site_id)
        .ok_or(IndirectResolveError::MissingSite(site_id))?
        .clone();
    let edge_kind = match site.kind {
        IndirectKind::Call => EdgeKind::IndirectCall,
        IndirectKind::Jump => EdgeKind::IndirectJump,
    };
    let matching = next
        .edges
        .iter()
        .enumerate()
        .filter(|(_, edge)| {
            edge.source == site.source_block
                && edge.kind == edge_kind
                && edge.target == EdgeTarget::Unresolved
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let [index] = matching.as_slice() else {
        return Err(if matching.is_empty() {
            IndirectResolveError::MissingUnresolvedEdge(site_id)
        } else {
            IndirectResolveError::MultipleUnresolvedEdges(site_id)
        });
    };
    next.edges.remove(*index);
    let target_site = next.indirect_targets.sites.get_mut(&site_id).unwrap();
    target_site.targets.insert(
        IndirectTarget::RuntimeRoute,
        TargetProvenance::RuntimeRoute,
    );
    target_site.status = ResolutionStatus::Complete;
    next.edges.push(EdgeModel {
        source: site.source_block,
        kind: edge_kind,
        target: EdgeTarget::RuntimeRoute,
    });
    next.edges.sort_by_key(edge_key);
    *program = next;
    Ok(())
}

/// Atomically applies a producer's complete batch of indirect-target evidence.
///
/// A later request may depend on an earlier request in the same batch (for
/// example, partial evidence followed by a complete inventory).  Validation is
/// therefore performed in order on a clone, while publication remains all or
/// nothing.
pub fn apply_indirect_resolutions(
    program: &mut ProgramModel,
    resolutions: &[IndirectResolution],
) -> Result<(), IndirectResolveError> {
    let mut next = program.clone();
    for resolution in resolutions {
        apply(&mut next, resolution)?;
    }
    *program = next;
    Ok(())
}

fn apply(
    program: &mut ProgramModel,
    resolution: &IndirectResolution,
) -> Result<(), IndirectResolveError> {
    let site = program
        .indirect_targets
        .sites
        .get(&resolution.site)
        .ok_or(IndirectResolveError::MissingSite(resolution.site))?
        .clone();
    if resolution.complete && resolution.target_rvas.is_empty() {
        return Err(IndirectResolveError::EmptyCompleteSet(resolution.site));
    }

    let block_starts = block_start_index(program);
    let function_entries = function_entry_index(program);
    let mut mapped = BTreeSet::new();
    for &rva in &resolution.target_rvas {
        let target = match site.kind {
            IndirectKind::Jump => {
                unique(&block_starts, resolution.site, rva).map(IndirectTarget::Block)?
            }
            IndirectKind::Call => {
                unique(&function_entries, resolution.site, rva).map(IndirectTarget::Function)?
            }
        };
        mapped.insert(target);
    }

    let edge_kind = match site.kind {
        IndirectKind::Call => EdgeKind::IndirectCall,
        IndirectKind::Jump => EdgeKind::IndirectJump,
    };
    let matching = program
        .edges
        .iter()
        .enumerate()
        .filter(|(_, edge)| {
            edge.source == site.source_block
                && edge.kind == edge_kind
                && edge.target == EdgeTarget::Unresolved
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matching.len() {
        0 => return Err(IndirectResolveError::MissingUnresolvedEdge(resolution.site)),
        1 => {}
        _ => {
            return Err(IndirectResolveError::MultipleUnresolvedEdges(
                resolution.site,
            ))
        }
    }

    let target_site = program
        .indirect_targets
        .sites
        .get_mut(&resolution.site)
        .unwrap();
    for &target in &mapped {
        target_site.targets.insert(target, resolution.provenance);
    }
    target_site.status = if resolution.complete {
        ResolutionStatus::Complete
    } else if target_site.targets.is_empty() {
        ResolutionStatus::Unresolved
    } else {
        ResolutionStatus::Partial
    };

    let unresolved_index = matching[0];
    program.edges.remove(unresolved_index);
    for target in mapped {
        program.edges.push(EdgeModel {
            source: site.source_block,
            kind: edge_kind,
            target: match target {
                IndirectTarget::Block(id) => EdgeTarget::Block(id),
                IndirectTarget::Function(id) => EdgeTarget::Function(id),
                IndirectTarget::External(va) => EdgeTarget::External(va),
                IndirectTarget::RuntimeRoute => EdgeTarget::RuntimeRoute,
            },
        });
    }
    if !resolution.complete {
        program.edges.push(EdgeModel {
            source: site.source_block,
            kind: edge_kind,
            target: EdgeTarget::Unresolved,
        });
    }
    program.edges.sort_by_key(edge_key);
    Ok(())
}

fn unique<T: Copy>(
    index: &BTreeMap<u32, Vec<T>>,
    site: IndirectSiteId,
    rva: u32,
) -> Result<T, IndirectResolveError> {
    match index.get(&rva).map(Vec::as_slice) {
        None | Some([]) => Err(IndirectResolveError::UnmappedTarget(site, rva)),
        Some([id]) => Ok(*id),
        Some(_) => Err(IndirectResolveError::AmbiguousTarget(site, rva)),
    }
}

fn block_start_index(program: &ProgramModel) -> BTreeMap<u32, Vec<BlockId>> {
    let mut out: BTreeMap<u32, Vec<BlockId>> = BTreeMap::new();
    for block in program.blocks.values() {
        out.entry(block.range.start).or_default().push(block.id);
    }
    out
}

fn function_entry_index(program: &ProgramModel) -> BTreeMap<u32, Vec<FunctionId>> {
    let mut out: BTreeMap<u32, Vec<FunctionId>> = BTreeMap::new();
    for function in program.functions.values() {
        for &entry in &function.entries {
            out.entry(entry).or_default().push(function.id);
        }
    }
    out
}

fn edge_key(edge: &EdgeModel) -> (BlockId, u8, u8, u64) {
    let kind = match edge.kind {
        EdgeKind::DirectBranch => 0,
        EdgeKind::DirectCall => 1,
        EdgeKind::TailCall => 2,
        EdgeKind::Fallthrough => 3,
        EdgeKind::IndirectCall => 4,
        EdgeKind::IndirectJump => 5,
        EdgeKind::Return => 6,
    };
    let (target_kind, target) = match edge.target {
        EdgeTarget::Block(id) => (0, u64::from(id.0)),
        EdgeTarget::Function(id) => (1, u64::from(id.0)),
        EdgeTarget::External(va) => (2, va),
        EdgeTarget::RuntimeRoute => (3, 0),
        EdgeTarget::Unresolved => (4, 0),
    };
    (edge.source, kind, target_kind, target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::indirect_targets::{IndirectSite, TargetSet};
    use crate::analysis::program_model::{
        BlockModel, ByteClass, FunctionModel, FunctionProvenance, RvaRange,
    };

    fn model(kind: IndirectKind) -> ProgramModel {
        let mut p = ProgramModel::default();
        for (fid, bid, start) in [(1, 11, 0x1000), (2, 22, 0x2000)] {
            let range = RvaRange::new(start, start + 0x10).unwrap();
            p.functions.insert(
                FunctionId(fid),
                FunctionModel {
                    id: FunctionId(fid),
                    ranges: vec![range],
                    entries: BTreeSet::from([start]),
                    blocks: BTreeSet::from([BlockId(bid)]),
                    provenance: BTreeSet::from([FunctionProvenance::EntryPoint]),
                    unwind: None,
                },
            );
            p.blocks.insert(
                BlockId(bid),
                BlockModel {
                    id: BlockId(bid),
                    function_id: FunctionId(fid),
                    range,
                    instructions: vec![],
                    byte_class: ByteClass::Instruction,
                },
            );
        }
        p.indirect_targets.sites.insert(
            IndirectSiteId(7),
            IndirectSite {
                id: IndirectSiteId(7),
                instruction_rva: 0x1008,
                source_block: BlockId(11),
                source_function: FunctionId(1),
                kind,
                status: ResolutionStatus::Unresolved,
                targets: TargetSet::default(),
                table: None,
            },
        );
        p.edges.push(EdgeModel {
            source: BlockId(11),
            kind: match kind {
                IndirectKind::Call => EdgeKind::IndirectCall,
                IndirectKind::Jump => EdgeKind::IndirectJump,
            },
            target: EdgeTarget::Unresolved,
        });
        p
    }

    #[test]
    fn resolves_call_and_replaces_unresolved_edge() {
        let mut p = model(IndirectKind::Call);
        apply_indirect_resolution(
            &mut p,
            &IndirectResolution {
                site: IndirectSiteId(7),
                target_rvas: BTreeSet::from([0x2000]),
                provenance: TargetProvenance::PointerTable,
                complete: true,
            },
        )
        .unwrap();
        assert_eq!(
            p.indirect_targets.sites[&IndirectSiteId(7)].status,
            ResolutionStatus::Complete
        );
        assert_eq!(p.edges[0].target, EdgeTarget::Function(FunctionId(2)));
    }

    #[test]
    fn resolves_loader_slot_as_complete_external_edge() {
        let mut p = model(IndirectKind::Call);
        apply_external_indirect_resolution(
            &mut p,
            IndirectSiteId(7),
            0x140003000,
            TargetProvenance::ImportAddressTable,
        )
        .unwrap();
        let site = &p.indirect_targets.sites[&IndirectSiteId(7)];
        assert_eq!(site.status, ResolutionStatus::Complete);
        assert!(site
            .targets
            .targets
            .contains_key(&IndirectTarget::External(0x140003000)));
        assert!(p.edges.iter().any(|edge| {
            edge.kind == EdgeKind::IndirectCall && edge.target == EdgeTarget::External(0x140003000)
        }));
        assert!(!p
            .edges
            .iter()
            .any(|edge| edge.target == EdgeTarget::Unresolved));
    }

    #[test]
    fn partial_jump_keeps_one_unresolved_edge_and_is_deterministic() {
        let request = IndirectResolution {
            site: IndirectSiteId(7),
            target_rvas: BTreeSet::from([0x2000]),
            provenance: TargetProvenance::JumpTable,
            complete: false,
        };
        let mut a = model(IndirectKind::Jump);
        let mut b = a.clone();
        apply_indirect_resolution(&mut a, &request).unwrap();
        apply_indirect_resolution(&mut b, &request).unwrap();
        assert_eq!(
            a.edges.iter().map(|e| &e.target).collect::<Vec<_>>(),
            b.edges.iter().map(|e| &e.target).collect::<Vec<_>>()
        );
        assert!(a
            .edges
            .iter()
            .any(|e| e.target == EdgeTarget::Block(BlockId(22))));
        assert!(a.edges.iter().any(|e| e.target == EdgeTarget::Unresolved));
    }

    #[test]
    fn unmapped_target_is_atomic_and_fail_closed() {
        let mut p = model(IndirectKind::Call);
        let before = p.clone();
        let error = apply_indirect_resolution(
            &mut p,
            &IndirectResolution {
                site: IndirectSiteId(7),
                target_rvas: BTreeSet::from([0x2004]),
                provenance: TargetProvenance::ConstantPropagation,
                complete: true,
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            IndirectResolveError::UnmappedTarget(IndirectSiteId(7), 0x2004)
        );
        assert_eq!(p.edges.len(), before.edges.len());
        assert_eq!(p.indirect_targets, before.indirect_targets);
    }

    #[test]
    fn batch_is_atomic_when_a_later_resolution_fails() {
        let mut p = model(IndirectKind::Jump);
        let before = p.clone();
        let requests = [
            IndirectResolution {
                site: IndirectSiteId(7),
                target_rvas: BTreeSet::from([0x2000]),
                provenance: TargetProvenance::JumpTable,
                complete: false,
            },
            IndirectResolution {
                site: IndirectSiteId(99),
                target_rvas: BTreeSet::from([0x2000]),
                provenance: TargetProvenance::JumpTable,
                complete: true,
            },
        ];
        assert_eq!(
            apply_indirect_resolutions(&mut p, &requests),
            Err(IndirectResolveError::MissingSite(IndirectSiteId(99)))
        );
        let edge_shape = |model: &ProgramModel| {
            model
                .edges
                .iter()
                .map(|edge| (edge.source, edge.kind, edge.target.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(edge_shape(&p), edge_shape(&before));
        assert_eq!(p.indirect_targets, before.indirect_targets);
    }
}
