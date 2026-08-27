//! Typed evidence and target sets for indirect control transfers.
//!
//! This module deliberately contains no decoder policy.  Producers (bounded
//! value flow, relocation scanning, jump-table recovery, etc.) contribute
//! evidence here and receive one deterministic, canonical target inventory.

use std::collections::{BTreeMap, BTreeSet};

use super::program_model::{BlockId, FunctionId, ProgramModel, RvaRange};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IndirectSiteId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndirectKind {
    Call,
    Jump,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TargetProvenance {
    ConstantPropagation,
    Relocation,
    JumpTable,
    PointerTable,
    Vtable,
    ImportAddressTable,
    LoadConfig,
    DynamicImport,
    AbiArgument,
    RuntimeCallback,
    /// Exhaustive runtime partition: canonical internal block/function lookup,
    /// with the non-image remainder delegated to the native transfer bridge.
    RuntimeRoute,
    UserSupplied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndirectTarget {
    Block(BlockId),
    Function(FunctionId),
    External(u64),
    RuntimeRoute,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TargetSet {
    /// A map (instead of a vector) makes evidence union independent of pass order.
    pub targets: BTreeMap<IndirectTarget, BTreeSet<TargetProvenance>>,
}

impl TargetSet {
    pub fn insert(&mut self, target: IndirectTarget, provenance: TargetProvenance) {
        self.targets.entry(target).or_default().insert(provenance);
    }

    pub fn merge(&mut self, other: &Self) {
        for (&target, evidence) in &other.targets {
            self.targets.entry(target).or_default().extend(evidence);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResolutionStatus {
    Unresolved,
    Partial,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTableDescriptor {
    pub table: RvaRange,
    pub entry_width: u8,
    pub entry_count: u32,
    pub base_rva: u32,
    pub entries_are_relative: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerTableDescriptor {
    pub table: RvaRange,
    pub entry_width: u8,
    pub entry_count: u32,
    pub relocation_backed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableDescriptor {
    Jump(JumpTableDescriptor),
    Pointer(PointerTableDescriptor),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndirectSite {
    pub id: IndirectSiteId,
    pub instruction_rva: u32,
    pub source_block: BlockId,
    pub source_function: FunctionId,
    pub kind: IndirectKind,
    pub status: ResolutionStatus,
    pub targets: TargetSet,
    pub table: Option<TableDescriptor>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndirectTargetModel {
    pub sites: BTreeMap<IndirectSiteId, IndirectSite>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndirectEdgeMetrics {
    pub sites: u64,
    pub resolved_internal_edges: u64,
    pub unresolved_internal_edges: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndirectTargetError {
    ConflictingSite(IndirectSiteId),
    MissingSourceBlock(IndirectSiteId, BlockId),
    SourceFunctionMismatch(IndirectSiteId),
    InstructionOutsideBlock(IndirectSiteId),
    MissingTargetBlock(IndirectSiteId, BlockId),
    MissingTargetFunction(IndirectSiteId, FunctionId),
    InvalidStatus(IndirectSiteId),
    InvalidTable(IndirectSiteId),
}

impl IndirectTargetModel {
    /// Merge observations without depending on analysis-pass order. Structural
    /// disagreement is rejected; target evidence and the strongest status win.
    pub fn merge_site(&mut self, site: IndirectSite) -> Result<(), IndirectTargetError> {
        let Some(current) = self.sites.get_mut(&site.id) else {
            self.sites.insert(site.id, site);
            return Ok(());
        };
        if current.instruction_rva != site.instruction_rva
            || current.source_block != site.source_block
            || current.source_function != site.source_function
            || current.kind != site.kind
            || (current.table.is_some() && site.table.is_some() && current.table != site.table)
        {
            return Err(IndirectTargetError::ConflictingSite(site.id));
        }
        current.targets.merge(&site.targets);
        current.status = current.status.max(site.status);
        if current.table.is_none() {
            current.table = site.table;
        }
        Ok(())
    }

    pub fn validate(&self, program: &ProgramModel) -> Result<(), IndirectTargetError> {
        for site in self.sites.values() {
            let block = program.blocks.get(&site.source_block).ok_or(
                IndirectTargetError::MissingSourceBlock(site.id, site.source_block),
            )?;
            if block.function_id != site.source_function {
                return Err(IndirectTargetError::SourceFunctionMismatch(site.id));
            }
            if !(block.range.start <= site.instruction_rva
                && site.instruction_rva < block.range.end)
            {
                return Err(IndirectTargetError::InstructionOutsideBlock(site.id));
            }
            for target in site.targets.targets.keys() {
                match *target {
                    IndirectTarget::Block(id) if !program.blocks.contains_key(&id) => {
                        return Err(IndirectTargetError::MissingTargetBlock(site.id, id));
                    }
                    IndirectTarget::Function(id) if !program.functions.contains_key(&id) => {
                        return Err(IndirectTargetError::MissingTargetFunction(site.id, id));
                    }
                    _ => {}
                }
            }
            if site.status == ResolutionStatus::Unresolved && !site.targets.is_empty()
                || site.status == ResolutionStatus::Complete && site.targets.is_empty()
            {
                return Err(IndirectTargetError::InvalidStatus(site.id));
            }
            if let Some(table) = &site.table {
                let (range, width, count) = match table {
                    TableDescriptor::Jump(t) => (t.table, t.entry_width, t.entry_count),
                    TableDescriptor::Pointer(t) => (t.table, t.entry_width, t.entry_count),
                };
                let extent = range.end.checked_sub(range.start).map(u64::from);
                if !matches!(width, 1 | 2 | 4 | 8)
                    || count == 0
                    || extent != Some(u64::from(width) * u64::from(count))
                {
                    return Err(IndirectTargetError::InvalidTable(site.id));
                }
            }
        }
        Ok(())
    }

    pub fn edge_metrics(&self) -> IndirectEdgeMetrics {
        let mut result = IndirectEdgeMetrics {
            sites: self.sites.len() as u64,
            ..Default::default()
        };
        for site in self.sites.values() {
            result.resolved_internal_edges += site
                .targets
                .targets
                .keys()
                .filter(|target| {
                    matches!(
                        target,
                        IndirectTarget::Block(_) | IndirectTarget::Function(_)
                    )
                })
                .count() as u64;
            if site.status != ResolutionStatus::Complete {
                // One conservative unknown continuation per incomplete transfer site.
                result.unresolved_internal_edges += 1;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::super::program_model::{BlockModel, ByteClass, FunctionModel, FunctionProvenance};
    use super::*;

    fn program() -> ProgramModel {
        let range = RvaRange::new(0x1000, 0x1010).unwrap();
        let mut p = ProgramModel::default();
        p.functions.insert(
            FunctionId(1),
            FunctionModel {
                id: FunctionId(1),
                ranges: vec![range],
                entries: BTreeSet::from([0x1000]),
                blocks: BTreeSet::from([BlockId(2)]),
                provenance: BTreeSet::from([FunctionProvenance::EntryPoint]),
                unwind: None,
            },
        );
        p.blocks.insert(
            BlockId(2),
            BlockModel {
                id: BlockId(2),
                function_id: FunctionId(1),
                range,
                instructions: vec![],
                byte_class: ByteClass::Instruction,
            },
        );
        p
    }

    fn site(status: ResolutionStatus, provenance: TargetProvenance) -> IndirectSite {
        let mut targets = TargetSet::default();
        targets.insert(IndirectTarget::Function(FunctionId(1)), provenance);
        IndirectSite {
            id: IndirectSiteId(9),
            instruction_rva: 0x1008,
            source_block: BlockId(2),
            source_function: FunctionId(1),
            kind: IndirectKind::Call,
            status,
            targets,
            table: None,
        }
    }

    #[test]
    fn merge_is_deterministic_and_unions_evidence() {
        let a = site(ResolutionStatus::Partial, TargetProvenance::Relocation);
        let b = site(
            ResolutionStatus::Complete,
            TargetProvenance::ConstantPropagation,
        );
        let mut left = IndirectTargetModel::default();
        left.merge_site(a.clone()).unwrap();
        left.merge_site(b.clone()).unwrap();
        let mut right = IndirectTargetModel::default();
        right.merge_site(b).unwrap();
        right.merge_site(a).unwrap();
        assert_eq!(left, right);
        assert_eq!(
            left.sites[&IndirectSiteId(9)].status,
            ResolutionStatus::Complete
        );
        assert_eq!(
            left.sites[&IndirectSiteId(9)]
                .targets
                .targets
                .values()
                .next()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn validates_canonical_ownership_and_reports_metrics() {
        let mut model = IndirectTargetModel::default();
        model
            .merge_site(site(ResolutionStatus::Partial, TargetProvenance::Vtable))
            .unwrap();
        model.validate(&program()).unwrap();
        assert_eq!(
            model.edge_metrics(),
            IndirectEdgeMetrics {
                sites: 1,
                resolved_internal_edges: 1,
                unresolved_internal_edges: 1
            }
        );
    }

    #[test]
    fn rejects_malformed_table_extent() {
        let mut s = site(ResolutionStatus::Complete, TargetProvenance::JumpTable);
        s.table = Some(TableDescriptor::Jump(JumpTableDescriptor {
            table: RvaRange::new(0x2000, 0x2009).unwrap(),
            entry_width: 4,
            entry_count: 2,
            base_rva: 0x2000,
            entries_are_relative: true,
        }));
        let mut model = IndirectTargetModel::default();
        model.merge_site(s).unwrap();
        assert!(matches!(
            model.validate(&program()),
            Err(IndirectTargetError::InvalidTable(_))
        ));
    }
}
