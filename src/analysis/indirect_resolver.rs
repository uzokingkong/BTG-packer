//! Fail-closed application of indirect-target analysis to the canonical model.

use std::collections::{BTreeMap, BTreeSet, HashSet};

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
    InvalidProducerTarget {
        producer: String,
        site: IndirectSiteId,
        instruction_rva: u32,
        kind: IndirectKind,
        target_rva: u32,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProducerApplyReport {
    pub resolutions_seen: usize,
    pub resolutions_applied: usize,
    pub targets_discarded: usize,
}

/// Immutable lookup tables shared by every producer in one canonical-model
/// pass. Rebuild only after a transformation changes block/function entries.
pub struct ProducerValidationIndexes {
    decoded_rvas: HashSet<u32>,
    block_starts: BTreeMap<u32, Vec<BlockId>>,
    function_entries: BTreeMap<u32, Vec<FunctionId>>,
}

impl ProducerValidationIndexes {
    pub fn build(program: &ProgramModel) -> Self {
        let image_delta = program.blocks.values().find_map(|block| {
            block.instructions.first().and_then(|instruction| {
                instruction.ip().checked_sub(block.range.start as u64)
            })
        });
        let decoded_rvas = image_delta
            .map(|delta| parallel_decoded_rvas(program, delta))
            .unwrap_or_default();
        Self {
            decoded_rvas,
            block_starts: block_start_index(program),
            function_entries: function_entry_index(program),
        }
    }
}

fn parallel_decoded_rvas(program: &ProgramModel, image_delta: u64) -> HashSet<u32> {
    let blocks = program.blocks.values().collect::<Vec<_>>();
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(blocks.len().max(1));
    if workers == 1 || blocks.len() < 4096 {
        return blocks
            .into_iter()
            .flat_map(|block| &block.instructions)
            .filter_map(|instruction| instruction.ip().checked_sub(image_delta))
            .filter_map(|rva| u32::try_from(rva).ok())
            .collect();
    }
    let chunk_len = blocks.len().div_ceil(workers);
    let instruction_count = blocks.iter().map(|block| block.instructions.len()).sum();
    std::thread::scope(|scope| {
        let handles = blocks
            .chunks(chunk_len)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .flat_map(|block| &block.instructions)
                        .filter_map(|instruction| instruction.ip().checked_sub(image_delta))
                        .filter_map(|rva| u32::try_from(rva).ok())
                        .collect::<HashSet<_>>()
                })
            })
            .collect::<Vec<_>>();
        let mut merged = HashSet::with_capacity(instruction_count);
        for handle in handles {
            merged.extend(handle.join().expect("decoded-index worker panicked"));
        }
        merged
    })
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

/// Applies external producer evidence in one transaction. The unresolved-edge
/// index is built once, each edge is replaced in place, and ordering is
/// restored once after the whole batch.
pub fn apply_external_indirect_resolutions(
    program: &mut ProgramModel,
    producer: &str,
    resolutions: &[(IndirectSiteId, u64, TargetProvenance)],
) -> Result<(), IndirectResolveError> {
    let mut next = program.clone();
    let mut unresolved = BTreeMap::<(BlockId, u8), Vec<usize>>::new();
    for (index, edge) in next.edges.iter().enumerate() {
        if edge.target == EdgeTarget::Unresolved {
            unresolved.entry((edge.source, edge_kind_id(edge.kind))).or_default().push(index);
        }
    }
    crate::progress::begin_detail_task(
        format!("ProgramModel: applying {} producer results", producer),
        resolutions.len() as u64,
        "resolutions",
    );
    for (ordinal, &(site_id, slot_va, provenance)) in resolutions.iter().enumerate() {
        if ordinal & 0x3f == 0 { crate::progress::set_position(ordinal as u64); }
        let site = next.indirect_targets.sites.get(&site_id)
            .ok_or(IndirectResolveError::MissingSite(site_id))?.clone();
        let edge_kind = match site.kind {
            IndirectKind::Call => EdgeKind::IndirectCall,
            IndirectKind::Jump => EdgeKind::IndirectJump,
        };
        let indexes = unresolved.get_mut(&(site.source_block, edge_kind_id(edge_kind)))
            .ok_or(IndirectResolveError::MissingUnresolvedEdge(site_id))?;
        let index = indexes.pop().ok_or(IndirectResolveError::MissingUnresolvedEdge(site_id))?;
        next.edges[index] = EdgeModel {
            source: site.source_block,
            kind: edge_kind,
            target: EdgeTarget::External(slot_va),
        };
        let target_site = next.indirect_targets.sites.get_mut(&site_id).unwrap();
        target_site.targets.insert(IndirectTarget::External(slot_va), provenance);
        target_site.status = ResolutionStatus::Complete;
    }
    next.edges.sort_by_key(edge_key);
    crate::progress::set_position(resolutions.len() as u64);
    crate::progress::finish_task(format!(
        "ProgramModel {} producer complete: {} resolution(s)", producer, resolutions.len()
    ));
    *program = next;
    Ok(())
}

pub fn apply_runtime_route_resolutions(
    program: &mut ProgramModel,
    site_ids: &[IndirectSiteId],
) -> Result<(), IndirectResolveError> {
    let batch = site_ids.iter().map(|&site| {
        (site, 0, TargetProvenance::RuntimeRoute)
    }).collect::<Vec<_>>();
    let mut next = program.clone();
    let mut unresolved = BTreeMap::<(BlockId, u8), Vec<usize>>::new();
    for (index, edge) in next.edges.iter().enumerate() {
        if edge.target == EdgeTarget::Unresolved {
            unresolved.entry((edge.source, edge_kind_id(edge.kind))).or_default().push(index);
        }
    }
    crate::progress::begin_detail_task("ProgramModel: closing runtime-route sites", batch.len() as u64, "sites");
    for (ordinal, &(site_id, _, _)) in batch.iter().enumerate() {
        if ordinal & 0x3f == 0 { crate::progress::set_position(ordinal as u64); }
        let site = next.indirect_targets.sites.get(&site_id)
            .ok_or(IndirectResolveError::MissingSite(site_id))?.clone();
        let edge_kind = match site.kind { IndirectKind::Call => EdgeKind::IndirectCall, IndirectKind::Jump => EdgeKind::IndirectJump };
        let indexes = unresolved.get_mut(&(site.source_block, edge_kind_id(edge_kind)))
            .ok_or(IndirectResolveError::MissingUnresolvedEdge(site_id))?;
        let index = indexes.pop().ok_or(IndirectResolveError::MissingUnresolvedEdge(site_id))?;
        next.edges[index] = EdgeModel { source: site.source_block, kind: edge_kind, target: EdgeTarget::RuntimeRoute };
        let target_site = next.indirect_targets.sites.get_mut(&site_id).unwrap();
        target_site.targets.insert(IndirectTarget::RuntimeRoute, TargetProvenance::RuntimeRoute);
        target_site.status = ResolutionStatus::Complete;
    }
    next.edges.sort_by_key(edge_key);
    crate::progress::set_position(site_ids.len() as u64);
    crate::progress::finish_task(format!("ProgramModel runtime-route closure complete: {} site(s)", site_ids.len()));
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
    target_site
        .targets
        .insert(IndirectTarget::RuntimeRoute, TargetProvenance::RuntimeRoute);
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

/// Validate producer output against the decoded canonical instruction domain
/// before publishing it. Invalid automatic evidence is discarded and leaves
/// the site unresolved so the final runtime-route partition can handle it.
/// Caller-supplied evidence can opt into strict diagnostics instead.
pub fn apply_producer_resolutions(
    program: &mut ProgramModel,
    producer: &str,
    resolutions: &[IndirectResolution],
    strict: bool,
) -> Result<ProducerApplyReport, IndirectResolveError> {
    let indexes = ProducerValidationIndexes::build(program);
    apply_producer_resolutions_with_indexes(program, producer, resolutions, strict, &indexes)
}

pub fn apply_producer_resolutions_with_indexes(
    program: &mut ProgramModel,
    producer: &str,
    resolutions: &[IndirectResolution],
    strict: bool,
    indexes: &ProducerValidationIndexes,
) -> Result<ProducerApplyReport, IndirectResolveError> {
    let mut unresolved_edges = BTreeMap::<(BlockId, u8), Vec<usize>>::new();
    for (index, edge) in program.edges.iter().enumerate() {
        if edge.target == EdgeTarget::Unresolved {
            unresolved_edges
                .entry((edge.source, edge_kind_id(edge.kind)))
                .or_default()
                .push(index);
        }
    }
    let mut report = ProducerApplyReport {
        resolutions_seen: resolutions.len(),
        ..Default::default()
    };
    crate::progress::begin_detail_task(
        format!("ProgramModel: validating {} producer results", producer),
        resolutions.len() as u64,
        "resolutions",
    );

    for (resolution_index, resolution) in resolutions.iter().enumerate() {
        if resolution_index & 0x3f == 0 {
            crate::progress::set_position(resolution_index as u64);
        }
        let site = program
            .indirect_targets
            .sites
            .get(&resolution.site)
            .ok_or(IndirectResolveError::MissingSite(resolution.site))?
            .clone();
        if !indexes.decoded_rvas.contains(&site.instruction_rva) {
            let error = IndirectResolveError::InvalidProducerTarget {
                producer: producer.to_string(),
                site: site.id,
                instruction_rva: site.instruction_rva,
                kind: site.kind,
                target_rva: site.instruction_rva,
                reason: "indirect site is not a decoded instruction boundary",
            };
            if strict {
                return Err(error);
            }
            report.targets_discarded += resolution.target_rvas.len();
            crate::progress_safe_eprintln!(
                "[INDIRECT] discarded producer={} site={} instruction_rva=0x{:X} kind={:?}: site is not a decoded instruction boundary",
                producer,
                site.id.0,
                site.instruction_rva,
                site.kind
            );
            continue;
        }
        let mut filtered = resolution.clone();
        let mut first_invalid = None;
        filtered.target_rvas.retain(|target_rva| {
            let reason = if !indexes.decoded_rvas.contains(target_rva) {
                Some("not a decoded instruction boundary")
            } else {
                match site.kind {
                    IndirectKind::Call if !indexes.function_entries.contains_key(target_rva) => {
                        Some("indirect call target is not a function entry")
                    }
                    IndirectKind::Jump if !indexes.block_starts.contains_key(target_rva) => {
                        Some("indirect jump target is not a basic-block start")
                    }
                    _ => None,
                }
            };
            let Some(reason) = reason else { return true };
            first_invalid.get_or_insert((*target_rva, reason));
            report.targets_discarded += 1;
            crate::progress_safe_eprintln!(
                "[INDIRECT] discarded producer={} site={} instruction_rva=0x{:X} kind={:?} target_rva=0x{:X}: {}",
                producer,
                site.id.0,
                site.instruction_rva,
                site.kind,
                target_rva,
                reason
            );
            false
        });
        if strict && first_invalid.is_some() {
            let (target_rva, reason) = first_invalid.unwrap();
            return Err(IndirectResolveError::InvalidProducerTarget {
                producer: producer.to_string(),
                site: site.id,
                instruction_rva: site.instruction_rva,
                kind: site.kind,
                target_rva,
                reason,
            });
        }
        if filtered.target_rvas.len() != resolution.target_rvas.len() {
            filtered.complete = false;
        }
        if filtered.target_rvas.is_empty() {
            continue;
        }
        let expected_kind = match site.kind {
            IndirectKind::Call => EdgeKind::IndirectCall,
            IndirectKind::Jump => EdgeKind::IndirectJump,
        };
        let edge_hint = unresolved_edges
            .get(&(site.source_block, edge_kind_id(expected_kind)))
            .and_then(|indexes| match indexes.as_slice() {
                [index] => Some(*index),
                _ => None,
            });
        apply_with_indexes(
            program,
            &filtered,
            &indexes.block_starts,
            &indexes.function_entries,
            edge_hint,
        )?;
        report.resolutions_applied += 1;
    }
    program.edges.sort_by_key(edge_key);
    crate::progress::set_position(resolutions.len() as u64);
    crate::progress::finish_task(format!(
        "ProgramModel {} producer applied: {} resolution(s), {} target(s) discarded",
        producer, report.resolutions_applied, report.targets_discarded
    ));
    Ok(report)
}

fn apply(
    program: &mut ProgramModel,
    resolution: &IndirectResolution,
) -> Result<(), IndirectResolveError> {
    let block_starts = block_start_index(program);
    let function_entries = function_entry_index(program);
    apply_with_indexes(program, resolution, &block_starts, &function_entries, None)
}

fn apply_with_indexes(
    program: &mut ProgramModel,
    resolution: &IndirectResolution,
    block_starts: &BTreeMap<u32, Vec<BlockId>>,
    function_entries: &BTreeMap<u32, Vec<FunctionId>>,
    unresolved_edge_hint: Option<usize>,
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

    let mut mapped = BTreeSet::new();
    for &rva in &resolution.target_rvas {
        let target = match site.kind {
            IndirectKind::Jump => {
                unique(block_starts, resolution.site, rva).map(IndirectTarget::Block)?
            }
            IndirectKind::Call => {
                unique(function_entries, resolution.site, rva).map(IndirectTarget::Function)?
            }
        };
        mapped.insert(target);
    }

    let edge_kind = match site.kind {
        IndirectKind::Call => EdgeKind::IndirectCall,
        IndirectKind::Jump => EdgeKind::IndirectJump,
    };
    let matching = unresolved_edge_hint
        .filter(|index| {
            program.edges.get(*index).is_some_and(|edge| {
                edge.source == site.source_block
                    && edge.kind == edge_kind
                    && edge.target == EdgeTarget::Unresolved
            })
        })
        .map(|index| vec![index])
        .unwrap_or_else(|| {
            program
                .edges
                .iter()
                .enumerate()
                .filter(|(_, edge)| {
                    edge.source == site.source_block
                        && edge.kind == edge_kind
                        && edge.target == EdgeTarget::Unresolved
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>()
        });
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
    let mut generated = mapped
        .into_iter()
        .map(|target| EdgeModel {
            source: site.source_block,
            kind: edge_kind,
            target: match target {
                IndirectTarget::Block(id) => EdgeTarget::Block(id),
                IndirectTarget::Function(id) => EdgeTarget::Function(id),
                IndirectTarget::External(va) => EdgeTarget::External(va),
                IndirectTarget::RuntimeRoute => EdgeTarget::RuntimeRoute,
            },
        })
        .collect::<Vec<_>>();
    if resolution.complete {
        // Preserve vector indexes during batch application: replace the one
        // unresolved edge in place and append only additional destinations.
        let first = generated.remove(0);
        program.edges[unresolved_index] = first;
        program.edges.extend(generated);
    } else {
        program.edges.extend(generated);
    }
    if unresolved_edge_hint.is_none() {
        program.edges.sort_by_key(edge_key);
    }
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
    let kind = edge_kind_id(edge.kind);
    let (target_kind, target) = match edge.target {
        EdgeTarget::Block(id) => (0, u64::from(id.0)),
        EdgeTarget::Function(id) => (1, u64::from(id.0)),
        EdgeTarget::External(va) => (2, va),
        EdgeTarget::RuntimeRoute => (3, 0),
        EdgeTarget::Unresolved => (4, 0),
    };
    (edge.source, kind, target_kind, target)
}

fn edge_kind_id(kind: EdgeKind) -> u8 {
    match kind {
        EdgeKind::DirectBranch => 0,
        EdgeKind::DirectCall => 1,
        EdgeKind::TailCall => 2,
        EdgeKind::Fallthrough => 3,
        EdgeKind::IndirectCall => 4,
        EdgeKind::IndirectJump => 5,
        EdgeKind::Return => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::indirect_targets::{IndirectSite, TargetSet};
    use crate::analysis::program_model::{
        BlockModel, ByteClass, FunctionModel, FunctionProvenance, RvaRange,
    };
    use iced_x86::{Code, Instruction};

    fn instruction(ip: u64) -> Instruction {
        let mut instruction = Instruction::with(Code::Nopd);
        instruction.set_ip(ip);
        instruction
    }

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
                    instructions: vec![
                        instruction(0x1400_0000 + start as u64),
                        instruction(0x1400_0000 + start as u64 + 8),
                    ],
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
    fn automatic_producer_discards_mid_instruction_target_and_keeps_runtime_fallback() {
        let mut p = model(IndirectKind::Call);
        let report = apply_producer_resolutions(
            &mut p,
            "test-producer",
            &[IndirectResolution {
                site: IndirectSiteId(7),
                target_rvas: BTreeSet::from([0x2004]),
                provenance: TargetProvenance::ConstantPropagation,
                complete: true,
            }],
            false,
        )
        .unwrap();
        assert_eq!(report.targets_discarded, 1);
        assert_eq!(report.resolutions_applied, 0);
        assert_eq!(
            p.indirect_targets.sites[&IndirectSiteId(7)].status,
            ResolutionStatus::Unresolved
        );
        apply_runtime_route_resolution(&mut p, IndirectSiteId(7)).unwrap();
        assert_eq!(
            p.indirect_targets.sites[&IndirectSiteId(7)].status,
            ResolutionStatus::Complete
        );
    }

    #[test]
    fn strict_producer_error_names_producer_site_kind_and_rvas() {
        let mut p = model(IndirectKind::Call);
        let error = apply_producer_resolutions(
            &mut p,
            "user-supplied",
            &[IndirectResolution {
                site: IndirectSiteId(7),
                target_rvas: BTreeSet::from([0x2008]),
                provenance: TargetProvenance::UserSupplied,
                complete: true,
            }],
            true,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            IndirectResolveError::InvalidProducerTarget {
                ref producer,
                site: IndirectSiteId(7),
                instruction_rva: 0x1008,
                kind: IndirectKind::Call,
                target_rva: 0x2008,
                ..
            } if producer == "user-supplied"
        ));
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
