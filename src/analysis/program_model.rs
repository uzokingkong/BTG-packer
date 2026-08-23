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
