//! Canonical, address-independent model of the original executable program.

use iced_x86::Instruction;
use std::collections::{BTreeMap, BTreeSet};

macro_rules! stable_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u32);
    };
}

stable_id!(FunctionId);
stable_id!(BlockId);
stable_id!(CodePointerId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RvaRange {
    pub start: u32,
    pub end: u32,
}

impl RvaRange {
    pub fn new(start: u32, end: u32) -> Result<Self, ProgramModelError> {
        (start < end)
            .then_some(Self { start, end })
            .ok_or(ProgramModelError::InvalidRange { start, end })
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FunctionProvenance {
    Pdata,
    Export,
    Tls,
    Crt,
    LoadConfig,
    DirectCall,
    Relocation,
    DataCodePointer,
    CallbackTable,
    TailCall,
    EntryPoint,
    AmbiguousBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteClass {
    Instruction,
    ReachableTrap,
    Padding,
    EmbeddedData,
    Generated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    DirectBranch,
    DirectCall,
    TailCall,
    Fallthrough,
    IndirectCall,
    IndirectJump,
    Return,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeTarget {
    Block(BlockId),
    Function(FunctionId),
    External(u64),
    RuntimeRoute,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeModel {
    pub source: BlockId,
    pub kind: EdgeKind,
    pub target: EdgeTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindRef {
    pub runtime_function: RvaRange,
    pub unwind_info_rva: u32,
}

#[derive(Debug, Clone)]
pub struct FunctionModel {
    pub id: FunctionId,
    pub ranges: Vec<RvaRange>,
    pub entries: BTreeSet<u32>,
    pub blocks: BTreeSet<BlockId>,
    pub provenance: BTreeSet<FunctionProvenance>,
    pub unwind: Option<UnwindRef>,
}

#[derive(Debug, Clone)]
pub struct BlockModel {
    pub id: BlockId,
    pub function_id: FunctionId,
    pub range: RvaRange,
    pub instructions: Vec<Instruction>,
    pub byte_class: ByteClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CodePointerEncoding {
    Va64,
    Rva32,
    Rel32,
    TableRelative,
    DirectoryField,
}

#[derive(Debug, Clone)]
pub struct CodePointerModel {
    pub id: CodePointerId,
    pub location: RvaRange,
    pub encoding: CodePointerEncoding,
    pub target: FunctionId,
    pub provenance: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct ProgramModel {
    pub executable_ranges: Vec<RvaRange>,
    pub functions: BTreeMap<FunctionId, FunctionModel>,
    pub blocks: BTreeMap<BlockId, BlockModel>,
    pub edges: Vec<EdgeModel>,
    pub indirect_targets: crate::analysis::indirect_targets::IndirectTargetModel,
    /// Typed switch/callback destinations discovered before the decoded block
    /// partition was refined. Pass-1 feeds these RVAs back into CFG extraction.
    pub discovered_indirect_code_targets: BTreeSet<u32>,
    pub code_pointers: BTreeMap<CodePointerId, CodePointerModel>,
    pub tls_callbacks: BTreeSet<FunctionId>,
    pub crt_entries: BTreeSet<FunctionId>,
    pub exports: BTreeSet<FunctionId>,
    pub unknown_ranges: Vec<RvaRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramModelError {
    InvalidRange { start: u32, end: u32 },
    OverlappingExecutableRanges { left: RvaRange, right: RvaRange },
    MissingFunction(FunctionId),
    BlockOutsideFunction(BlockId),
}

impl std::fmt::Display for ProgramModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid canonical program model: {self:?}")
    }
}

impl std::error::Error for ProgramModelError {}

impl ProgramModel {
    /// Canonical fail-closed inventory used by ownership and dependency policy.
    /// Consumers must not rediscover indirect instructions or infer resolution
    /// from the derived `edges` vector.
    pub fn incomplete_indirect_functions(&self) -> BTreeMap<FunctionId, u32> {
        use crate::analysis::indirect_targets::ResolutionStatus;
        let mut result: BTreeMap<FunctionId, u32> = BTreeMap::new();
        for site in self.indirect_targets.sites.values() {
            if site.status != ResolutionStatus::Complete {
                result
                    .entry(site.source_function)
                    .and_modify(|rva| *rva = (*rva).min(site.instruction_rva))
                    .or_insert(site.instruction_rva);
            }
        }
        result
    }

    pub fn unresolved_internal_edge_count(&self) -> u64 {
        self.indirect_targets
            .edge_metrics()
            .unresolved_internal_edges
    }

    /// Canonical entry RVAs that may be entered without the shuffled
    /// dispatcher. Re-encryption policy consumes this inventory instead of
    /// linearly decoding `.text` a second time with local heuristics.
    pub fn direct_entry_rvas(&self) -> BTreeSet<u32> {
        let mut entries = BTreeSet::new();
        for edge in &self.edges {
            if !matches!(edge.kind, EdgeKind::DirectCall | EdgeKind::TailCall) {
                continue;
            }
            match edge.target {
                EdgeTarget::Block(id) => {
                    if let Some(block) = self.blocks.get(&id) {
                        entries.insert(block.range.start);
                    }
                }
                EdgeTarget::Function(id) => {
                    if let Some(function) = self.functions.get(&id) {
                        entries.extend(function.entries.iter().copied());
                    }
                }
                EdgeTarget::External(_) | EdgeTarget::RuntimeRoute | EdgeTarget::Unresolved => {}
            }
        }
        for pointer in self.code_pointers.values() {
            if let Some(function) = self.functions.get(&pointer.target) {
                entries.extend(function.entries.iter().copied());
            }
        }
        entries
    }

    pub fn validate(&self) -> Result<(), ProgramModelError> {
        let mut ranges = self.executable_ranges.clone();
        ranges.sort();
        for pair in ranges.windows(2) {
            if pair[0].overlaps(pair[1]) {
                return Err(ProgramModelError::OverlappingExecutableRanges {
                    left: pair[0],
                    right: pair[1],
                });
            }
        }
        for block in self.blocks.values() {
            let function = self
                .functions
                .get(&block.function_id)
                .ok_or(ProgramModelError::MissingFunction(block.function_id))?;
            if !function.blocks.contains(&block.id)
                || !function
                    .ranges
                    .iter()
                    .any(|range| range.start <= block.range.start && block.range.end <= range.end)
            {
                return Err(ProgramModelError::BlockOutsideFunction(block.id));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_ids_are_not_rvas_and_validate_membership() {
        let fid = FunctionId(7);
        let bid = BlockId(11);
        let range = RvaRange::new(0x1000, 0x1010).unwrap();
        let mut model = ProgramModel {
            executable_ranges: vec![range],
            ..Default::default()
        };
        model.functions.insert(
            fid,
            FunctionModel {
                id: fid,
                ranges: vec![range],
                entries: BTreeSet::from([0x1000]),
                blocks: BTreeSet::from([bid]),
                provenance: BTreeSet::from([FunctionProvenance::EntryPoint]),
                unwind: None,
            },
        );
        model.blocks.insert(
            bid,
            BlockModel {
                id: bid,
                function_id: fid,
                range,
                instructions: Vec::new(),
                byte_class: ByteClass::Instruction,
            },
        );
        model.validate().unwrap();
    }

    #[test]
    fn overlapping_executable_ranges_are_rejected() {
        let model = ProgramModel {
            executable_ranges: vec![
                RvaRange::new(0x1000, 0x1100).unwrap(),
                RvaRange::new(0x1080, 0x1200).unwrap(),
            ],
            ..Default::default()
        };
        assert!(matches!(
            model.validate(),
            Err(ProgramModelError::OverlappingExecutableRanges { .. })
        ));
    }
}
