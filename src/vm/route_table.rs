//! Authoritative routing from original executable addresses into the VM.
//!
//! Original RVAs are rewriteable lookup keys, never function identities.  A
//! route is accepted only when the canonical [`ProgramModel`] proves that the
//! RVA is an entry of the supplied [`FunctionId`].  Lookup failures are errors
//! so callers cannot accidentally fall back to original native code.

use crate::analysis::program_model::{FunctionId, ProgramModel};
use crate::vm::poly::VmArchitectureFamily;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OriginalTargetRva(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryVip(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GatewayKind {
    /// The target can enter its owning family directly.
    VmEntry,
    /// Entry requires the canonical cross-family state bridge.
    CrossFamily,
    /// Entry is exposed to native/external callers through generated code.
    NativeEntry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionRoute {
    pub function_id: FunctionId,
    pub family: VmArchitectureFamily,
    pub entry_vip: EntryVip,
    pub gateway: GatewayKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTableError {
    MissingFunction(FunctionId),
    RvaIsNotFunctionEntry {
        rva: OriginalTargetRva,
        function_id: FunctionId,
    },
    DuplicateOriginalTarget(OriginalTargetRva),
    ConflictingFunctionRoute(FunctionId),
    UnknownOriginalTarget(OriginalTargetRva),
    UnknownFunction(FunctionId),
    RouteLimitExceeded {
        count: usize,
        limit: usize,
    },
}

impl std::fmt::Display for RouteTableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VM route table rejected target: {self:?}")
    }
}

impl std::error::Error for RouteTableError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteTable {
    by_original_rva: BTreeMap<OriginalTargetRva, FunctionId>,
    by_function: BTreeMap<FunctionId, FunctionRoute>,
}

/// Immutable, size-bounded form intended for generated/runtime consumers.
///
/// Materialization is the boundary at which an unbounded analysis map becomes
/// a deterministic lookup table.  Consumers must handle a typed miss; there is
/// deliberately no native-address fallback here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedRouteTable {
    entries: Vec<(OriginalTargetRva, FunctionRoute)>,
}

impl RouteTable {
    pub fn register(
        &mut self,
        program: &ProgramModel,
        original_rva: OriginalTargetRva,
        route: FunctionRoute,
    ) -> Result<(), RouteTableError> {
        let function = program
            .functions
            .get(&route.function_id)
            .ok_or(RouteTableError::MissingFunction(route.function_id))?;
        if !function.entries.contains(&original_rva.0) {
            return Err(RouteTableError::RvaIsNotFunctionEntry {
                rva: original_rva,
                function_id: route.function_id,
            });
        }
        if self.by_original_rva.contains_key(&original_rva) {
            return Err(RouteTableError::DuplicateOriginalTarget(original_rva));
        }
        if let Some(existing) = self.by_function.get(&route.function_id) {
            if existing != &route {
                return Err(RouteTableError::ConflictingFunctionRoute(route.function_id));
            }
        }
        self.by_original_rva.insert(original_rva, route.function_id);
        self.by_function.entry(route.function_id).or_insert(route);
        Ok(())
    }

    /// Resolve the complete typed chain RVA -> FunctionId -> VM destination.
    pub fn resolve(&self, rva: OriginalTargetRva) -> Result<FunctionRoute, RouteTableError> {
        let function_id = *self
            .by_original_rva
            .get(&rva)
            .ok_or(RouteTableError::UnknownOriginalTarget(rva))?;
        self.route_for_function(function_id)
    }

    pub fn route_for_function(
        &self,
        function_id: FunctionId,
    ) -> Result<FunctionRoute, RouteTableError> {
        self.by_function
            .get(&function_id)
            .copied()
            .ok_or(RouteTableError::UnknownFunction(function_id))
    }

    pub fn len(&self) -> usize {
        self.by_original_rva.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_original_rva.is_empty()
    }

    pub fn materialize(
        &self,
        max_routes: usize,
    ) -> Result<MaterializedRouteTable, RouteTableError> {
        if self.by_original_rva.len() > max_routes {
            return Err(RouteTableError::RouteLimitExceeded {
                count: self.by_original_rva.len(),
                limit: max_routes,
            });
        }
        let mut entries = Vec::with_capacity(self.by_original_rva.len());
        for (&rva, &function_id) in &self.by_original_rva {
            entries.push((rva, self.route_for_function(function_id)?));
        }
        Ok(MaterializedRouteTable { entries })
    }
}

impl MaterializedRouteTable {
    pub(crate) fn entries(&self) -> &[(OriginalTargetRva, FunctionRoute)] {
        &self.entries
    }

    pub(crate) fn from_sorted_entries(entries: Vec<(OriginalTargetRva, FunctionRoute)>) -> Self {
        Self { entries }
    }

    /// Bounded binary lookup over the immutable, RVA-sorted route image.
    pub fn lookup(&self, rva: OriginalTargetRva) -> Result<FunctionRoute, RouteTableError> {
        self.entries
            .binary_search_by_key(&rva, |(key, _)| *key)
            .map(|index| self.entries[index].1)
            .map_err(|_| RouteTableError::UnknownOriginalTarget(rva))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::program_model::{FunctionModel, FunctionProvenance, RvaRange};
    use std::collections::BTreeSet;

    fn program() -> ProgramModel {
        let mut program = ProgramModel::default();
        program.functions.insert(
            FunctionId(7),
            FunctionModel {
                id: FunctionId(7),
                ranges: vec![RvaRange::new(0x1000, 0x1100).unwrap()],
                entries: BTreeSet::from([0x1000, 0x1080]),
                blocks: BTreeSet::new(),
                provenance: BTreeSet::from([FunctionProvenance::Pdata]),
                unwind: None,
            },
        );
        program
    }

    fn route() -> FunctionRoute {
        FunctionRoute {
            function_id: FunctionId(7),
            family: VmArchitectureFamily::MixedRisc,
            entry_vip: EntryVip(23),
            gateway: GatewayKind::CrossFamily,
        }
    }

    #[test]
    fn resolves_alias_entries_through_stable_function_identity() {
        let mut table = RouteTable::default();
        table
            .register(&program(), OriginalTargetRva(0x1000), route())
            .unwrap();
        table
            .register(&program(), OriginalTargetRva(0x1080), route())
            .unwrap();
        assert_eq!(table.resolve(OriginalTargetRva(0x1080)).unwrap(), route());
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn lookup_miss_is_a_typed_failure() {
        let error = RouteTable::default()
            .resolve(OriginalTargetRva(0xDEAD))
            .unwrap_err();
        assert_eq!(
            error,
            RouteTableError::UnknownOriginalTarget(OriginalTargetRva(0xDEAD))
        );
    }

    #[test]
    fn rejects_unproven_and_duplicate_original_targets() {
        let mut table = RouteTable::default();
        assert!(matches!(
            table.register(&program(), OriginalTargetRva(0x1004), route()),
            Err(RouteTableError::RvaIsNotFunctionEntry { .. })
        ));
        table
            .register(&program(), OriginalTargetRva(0x1000), route())
            .unwrap();
        assert_eq!(
            table
                .register(&program(), OriginalTargetRva(0x1000), route())
                .unwrap_err(),
            RouteTableError::DuplicateOriginalTarget(OriginalTargetRva(0x1000))
        );
    }

    #[test]
    fn rejects_conflicting_metadata_for_one_function() {
        let mut table = RouteTable::default();
        table
            .register(&program(), OriginalTargetRva(0x1000), route())
            .unwrap();
        let mut conflict = route();
        conflict.entry_vip = EntryVip(99);
        assert_eq!(
            table
                .register(&program(), OriginalTargetRva(0x1080), conflict)
                .unwrap_err(),
            RouteTableError::ConflictingFunctionRoute(FunctionId(7))
        );
    }

    #[test]
    fn materialized_lookup_is_bounded_and_fail_closed() {
        let mut table = RouteTable::default();
        table
            .register(&program(), OriginalTargetRva(0x1080), route())
            .unwrap();
        table
            .register(&program(), OriginalTargetRva(0x1000), route())
            .unwrap();

        assert_eq!(
            table.materialize(1).unwrap_err(),
            RouteTableError::RouteLimitExceeded { count: 2, limit: 1 }
        );
        let runtime = table.materialize(2).unwrap();
        assert_eq!(runtime.lookup(OriginalTargetRva(0x1000)).unwrap(), route());
        assert_eq!(
            runtime.lookup(OriginalTargetRva(0x1004)).unwrap_err(),
            RouteTableError::UnknownOriginalTarget(OriginalTargetRva(0x1004))
        );
    }
}
