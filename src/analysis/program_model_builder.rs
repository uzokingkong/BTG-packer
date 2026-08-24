//! Deterministic construction of the canonical program model from PE metadata.

use super::program_model::{
    BlockId, BlockModel, ByteClass, CodePointerEncoding, CodePointerId, CodePointerModel, EdgeKind,
    EdgeModel, EdgeTarget, FunctionId, FunctionModel, FunctionProvenance, ProgramModel,
    ProgramModelError, RvaRange, UnwindRef,
};
use crate::graph::cfg::BasicBlock;
use crate::pe::{load_config::LoadConfig64, parser::TargetPeInfo, tls::TlsDirectory64};
use iced_x86::FlowControl;
use std::collections::{BTreeMap, BTreeSet};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

#[derive(Debug)]
pub enum ProgramModelBuildError {
    Model(ProgramModelError),
    Indirect(crate::analysis::indirect_targets::IndirectTargetError),
    IndirectResolution(crate::analysis::indirect_resolver::IndirectResolveError),
    RangeOverflow { start: u32, size: u32 },
}

impl From<ProgramModelError> for ProgramModelBuildError {
    fn from(value: ProgramModelError) -> Self {
        Self::Model(value)
    }
}

impl From<crate::analysis::indirect_targets::IndirectTargetError> for ProgramModelBuildError {
    fn from(value: crate::analysis::indirect_targets::IndirectTargetError) -> Self {
        Self::Indirect(value)
    }
}

impl From<crate::analysis::indirect_resolver::IndirectResolveError> for ProgramModelBuildError {
    fn from(value: crate::analysis::indirect_resolver::IndirectResolveError) -> Self {
        Self::IndirectResolution(value)
    }
}

impl std::fmt::Display for ProgramModelBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to build canonical program model: {self:?}")
    }
}
impl std::error::Error for ProgramModelBuildError {}

#[derive(Debug, Clone)]
struct PointSeed {
    rva: u32,
    provenance: FunctionProvenance,
    pointer: Option<(RvaRange, CodePointerEncoding, &'static str)>,
}

/// Builds stable IDs by sorted RVA order, independent of discovery order.
pub struct ProgramModelBuilder<'a> {
    target: &'a TargetPeInfo,
    points: Vec<PointSeed>,
}

impl<'a> ProgramModelBuilder<'a> {
    pub fn new(target: &'a TargetPeInfo) -> Self {
        let mut builder = Self {
            target,
            points: vec![PointSeed {
                rva: target.entry_point_rva,
                provenance: FunctionProvenance::EntryPoint,
                pointer: None,
            }],
        };
        if let Some(tls) = target.tls() {
            builder = builder.seed_tls(tls);
        }
        if let Some(config) = target.load_config() {
            builder = builder.seed_load_config(config);
        }
        if let Some(exports) = target.exports() {
            for entry in exports.executable_entries() {
                builder.points.push(PointSeed {
                    rva: entry.address_rva,
                    provenance: FunctionProvenance::Export,
                    pointer: None,
                });
            }
        }

        let executable_ranges: Vec<RvaRange> = target
            .executable_sections()
            .iter()
            .filter_map(|section| {
                let end = section.virtual_address.checked_add(section.virtual_size)?;
                RvaRange::new(section.virtual_address, end).ok()
            })
            .collect();
        let protected_metadata: Vec<RvaRange> = target
            .data_directories
            .iter()
            .filter_map(|directory| {
                let end = directory.virtual_address.checked_add(directory.size)?;
                RvaRange::new(directory.virtual_address, end).ok()
            })
            .collect();
        let pointer_scan = crate::analysis::code_pointers::CodePointerScan {
            image_base: target.image_base,
            sections: &target.relayed_sections,
            executable_ranges: &executable_ranges,
            dir64_slots: target.dir64_relocations(),
            protected_metadata: &protected_metadata,
        };
        for pointer in pointer_scan.inventory() {
            let provenance = match pointer.provenance {
                crate::analysis::code_pointers::CodePointerProvenance::Dir64Relocation => {
                    "dir64-relocation"
                }
                crate::analysis::code_pointers::CodePointerProvenance::DataRva32 => "data-rva32",
            };
            builder.points.push(PointSeed {
                rva: pointer.target_rva,
                provenance: FunctionProvenance::DataCodePointer,
                pointer: Some((pointer.location, pointer.encoding, provenance)),
            });
        }
        for table in crate::analysis::crt::discover_callback_tables(
            target.image_base,
            &target.relayed_sections,
            target.executable_sections(),
            target.dir64_relocations(),
        ) {
            let function_provenance = match table.kind {
                crate::analysis::crt::CrtTableKind::CInitializer
                | crate::analysis::crt::CrtTableKind::CxxInitializer
                | crate::analysis::crt::CrtTableKind::PreTerminator
                | crate::analysis::crt::CrtTableKind::Terminator => FunctionProvenance::Crt,
                crate::analysis::crt::CrtTableKind::RelocationBacked => {
                    FunctionProvenance::CallbackTable
                }
            };
            for slot in table.slots {
                let Some(end) = slot.slot_rva.checked_add(8) else {
                    continue;
                };
                builder.points.push(PointSeed {
                    rva: slot.target_rva,
                    provenance: function_provenance,
                    pointer: RvaRange::new(slot.slot_rva, end)
                        .ok()
                        .map(|range| (range, CodePointerEncoding::Va64, "crt-callback-table")),
                });
            }
        }
        builder
    }

    pub fn seed_tls(mut self, tls: &TlsDirectory64) -> Self {
        for callback in &tls.callbacks {
            if let Some(rva) = callback.address.rva {
                self.points.push(PointSeed {
                    rva,
                    provenance: FunctionProvenance::Tls,
                    pointer: RvaRange::new(callback.slot_rva, callback.slot_rva.saturating_add(8))
                        .ok()
                        .map(|range| (range, CodePointerEncoding::Va64, "tls-callback")),
                });
            }
        }
        self
    }

    /// Seeds mitigation entry points and the RVA entries contained in CFG/EH tables.
    pub fn seed_load_config(mut self, config: &LoadConfig64) -> Self {
        let code = config.code;
        for rva in [
            code.guard_cf_check,
            code.guard_cf_dispatch,
            code.guard_rf_failure_routine,
            code.guard_rf_failure_routine_function,
            code.guard_rf_verify_stack_pointer,
            code.guard_xfg_check,
            code.guard_xfg_dispatch,
            code.guard_xfg_table_dispatch,
            code.cast_guard_failure_mode,
            code.guard_memcpy,
        ]
        .into_iter()
        .flatten()
        {
            self.points.push(PointSeed {
                rva,
                provenance: FunctionProvenance::LoadConfig,
                pointer: None,
            });
        }
        if let Some(table) = config.guard_cf_function_table {
            let stride = config.guard_cf_entry_size as usize;
            for index in 0..config.guard_cf_function_count as usize {
                let location = table.rva.saturating_add((index * stride) as u32);
                if let Some(rva) = read_u32_at(self.target, location) {
                    self.points.push(PointSeed {
                        rva,
                        provenance: FunctionProvenance::LoadConfig,
                        pointer: RvaRange::new(location, location.saturating_add(4))
                            .ok()
                            .map(|range| (range, CodePointerEncoding::Rva32, "guard-cf-table")),
                    });
                }
            }
        }
        if let Some(table) = config.guard_eh_continuation_table {
            for index in 0..config.guard_eh_continuation_count as u32 {
                let location = table.rva.saturating_add(index.saturating_mul(4));
                if let Some(rva) = read_u32_at(self.target, location) {
                    self.points.push(PointSeed {
                        rva,
                        provenance: FunctionProvenance::LoadConfig,
                        pointer: RvaRange::new(location, location.saturating_add(4))
                            .ok()
                            .map(|range| {
                                (range, CodePointerEncoding::Rva32, "guard-eh-continuation")
                            }),
                    });
                }
            }
        }
        self
    }

    pub fn build(mut self) -> Result<ProgramModel, ProgramModelBuildError> {
        let executable_ranges = executable_ranges(self.target)?;
        let in_exec = |rva| {
            executable_ranges
                .iter()
                .any(|r| r.start <= rva && rva < r.end)
        };
        self.points.retain(|seed| in_exec(seed.rva));
        self.points.sort_by_key(|seed| (seed.rva, seed.provenance));

        let mut groups: Vec<(RvaRange, Vec<&crate::pe::parser::RuntimeFunction>)> = Vec::new();
        let mut pdata: Vec<_> = self
            .target
            .original_pdata_entries
            .iter()
            .filter_map(|rf| {
                RvaRange::new(rf.begin_address, rf.end_address)
                    .ok()
                    .map(|r| (r, rf))
            })
            .filter(|(r, _)| {
                executable_ranges
                    .iter()
                    .any(|x| x.start <= r.start && r.end <= x.end)
            })
            .collect();
        pdata.sort_by_key(|(r, _)| *r);
        for (range, rf) in pdata {
            if let Some((last, records)) =
                groups.last_mut().filter(|(last, _)| last.overlaps(range))
            {
                last.end = last.end.max(range.end);
                records.push(rf);
            } else {
                groups.push((range, vec![rf]));
            }
        }

        // Point-only functions occupy one byte. They intentionally do not claim an
        // inferred body; later disassembly may expand them and shrink unknown_ranges.
        for seed in &self.points {
            if !groups
                .iter()
                .any(|(r, _)| r.start <= seed.rva && seed.rva < r.end)
            {
                groups.push((
                    RvaRange {
                        start: seed.rva,
                        end: seed.rva + 1,
                    },
                    Vec::new(),
                ));
            }
        }
        groups.sort_by_key(|(r, _)| *r);

        let mut model = ProgramModel {
            executable_ranges,
            ..Default::default()
        };
        let mut rva_to_function = BTreeMap::new();
        for (index, (range, records)) in groups.iter().enumerate() {
            let id = FunctionId(index as u32);
            let matching: Vec<_> = self
                .points
                .iter()
                .filter(|p| range.start <= p.rva && p.rva < range.end)
                .collect();
            let mut provenance: BTreeSet<_> = matching.iter().map(|p| p.provenance).collect();
            if !records.is_empty() {
                provenance.insert(FunctionProvenance::Pdata);
            }
            if records.len() > 1 || records.is_empty() {
                provenance.insert(FunctionProvenance::AmbiguousBoundary);
            }
            let entries = matching
                .iter()
                .map(|p| p.rva)
                .chain(records.iter().map(|r| r.begin_address))
                .collect();
            let unwind = (records.len() == 1).then(|| UnwindRef {
                runtime_function: *range,
                unwind_info_rva: records[0].unwind_info_address,
            });
            model.functions.insert(
                id,
                FunctionModel {
                    id,
                    ranges: vec![*range],
                    entries,
                    blocks: BTreeSet::new(),
                    provenance,
                    unwind,
                },
            );
            for rva in range.start..range.end {
                rva_to_function.insert(rva, id);
            }
        }
        let mut pointer_id = 0;
        let mut seen_pointers = BTreeSet::new();
        for seed in &self.points {
            if let (Some(target), Some((location, encoding, provenance))) =
                (rva_to_function.get(&seed.rva).copied(), seed.pointer)
            {
                if !seen_pointers.insert((location, encoding, target)) {
                    continue;
                }
                let id = CodePointerId(pointer_id);
                pointer_id += 1;
                model.code_pointers.insert(
                    id,
                    CodePointerModel {
                        id,
                        location,
                        encoding,
                        target,
                        provenance,
                    },
                );
                if seed.provenance == FunctionProvenance::Tls {
                    model.tls_callbacks.insert(target);
                }
            }
        }
        for (id, function) in &model.functions {
            if function.provenance.contains(&FunctionProvenance::Tls) {
                model.tls_callbacks.insert(*id);
            }
            if function.provenance.contains(&FunctionProvenance::Crt) {
                model.crt_entries.insert(*id);
            }
            if function.provenance.contains(&FunctionProvenance::Export) {
                model.exports.insert(*id);
            }
        }
        model.unknown_ranges = complement(
            &model.executable_ranges,
            &model
                .functions
                .values()
                .flat_map(|f| f.ranges.iter().copied())
                .collect::<Vec<_>>(),
        );
        model.validate()?;
        Ok(model)
    }

    /// Builds the metadata model and merges a decoded CFG into its canonical block partition.
    /// CFG addresses are VAs; the canonical model deliberately stores only RVAs.
    pub fn build_with_basic_blocks(
        self,
        blocks: &[BasicBlock],
    ) -> Result<ProgramModel, ProgramModelBuildError> {
        let image_base = self.target.image_base;
        let mut model = self.build()?;
        merge_basic_blocks(&mut model, blocks, image_base)?;
        Ok(model)
    }

    /// Builds the decoded canonical model and applies already-proven indirect
    /// targets before publishing it to a pipeline context.
    ///
    /// Producers must supply canonical site IDs and explicitly state whether
    /// their inventory is exhaustive; this boundary intentionally performs no
    /// instruction-shape guessing.
    pub fn build_with_basic_blocks_and_indirect_resolutions(
        self,
        blocks: &[BasicBlock],
        resolutions: &[crate::analysis::indirect_resolver::IndirectResolution],
    ) -> Result<ProgramModel, ProgramModelBuildError> {
        let image_base = self.target.image_base;
        let mut model = self.build_with_basic_blocks(blocks)?;
        // Direct memory-call slots can be linked automatically and safely.
        // Explicit producer results take precedence per site; this prevents
        // two passes from competing for the same unresolved CFG edge.
        let explicit_sites: BTreeSet<_> = resolutions.iter().map(|r| r.site).collect();
        let mut combined = resolutions.to_vec();
        combined.extend(
            crate::analysis::pointer_tables::produce(&model, image_base, &[])
                .into_iter()
                .filter(|r| !explicit_sites.contains(&r.site)),
        );
        crate::analysis::indirect_resolver::apply_indirect_resolutions(&mut model, &combined)?;
        model.indirect_targets.validate(&model)?;
        model.validate()?;
        Ok(model)
    }

    /// Builds a decoded model and runs the built-in fail-closed dense-switch
    /// producer before applying any caller-provided evidence.
    pub fn build_with_basic_blocks_and_auto_indirect_resolutions(
        self,
        blocks: &[BasicBlock],
        resolutions: &[crate::analysis::indirect_resolver::IndirectResolution],
    ) -> Result<ProgramModel, ProgramModelBuildError> {
        let image_base = self.target.image_base;
        let sections = self
            .target
            .relayed_sections
            .iter()
            .map(|s| crate::analysis::switch_targets::SwitchSection {
                name: &s.name,
                rva: s.virtual_address,
                bytes: &s.bytes,
            })
            .collect::<Vec<_>>();
        let relayed_sections = self.target.relayed_sections.clone();
        let iat = self.target.data_directories.get(12).and_then(|directory| {
            (directory.virtual_address != 0 && directory.size != 0).then_some(
                crate::analysis::program_model::RvaRange {
                    start: directory.virtual_address,
                    end: directory.virtual_address.saturating_add(directory.size),
                },
            )
        });
        let get_proc_address_slots = crate::pipeline::iat_hide::collect_from_pe(
            &self.target.original_pe_bytes,
        )
        .unwrap_or_default()
        .into_iter()
        .filter_map(|import| match import.func {
            crate::pipeline::iat_hide::FuncRef::Name(name)
                if name.eq_ignore_ascii_case("GetProcAddress") => Some(import.slot_rva),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
        let load_config_slots = self
            .target
            .load_config
            .as_ref()
            .map(|load| {
                let code = &load.code;
                [
                    code.guard_cf_check,
                    code.guard_cf_dispatch,
                    code.guard_rf_failure_routine,
                    code.guard_rf_failure_routine_function,
                    code.guard_rf_verify_stack_pointer,
                    code.guard_xfg_check,
                    code.guard_xfg_dispatch,
                    code.guard_xfg_table_dispatch,
                    code.cast_guard_failure_mode,
                    code.guard_memcpy,
                ]
                .into_iter()
                .flatten()
                .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let mut model = self.build_with_basic_blocks(blocks)?;
        let mut produced = crate::analysis::switch_producer::produce_switch_resolutions(
            &model, image_base, &sections,
        );
        let switch_targets = produced
            .iter()
            .flat_map(|item| item.resolution.target_rvas.iter().copied())
            .collect::<BTreeSet<_>>();
        model
            .discovered_indirect_code_targets
            .extend(switch_targets.iter().copied());
        split_blocks_at_targets(&mut model, image_base, &switch_targets);
        let mapped_starts = model
            .blocks
            .values()
            .map(|block| block.range.start)
            .collect::<BTreeSet<_>>();
        for item in &mut produced {
            let before = item.resolution.target_rvas.len();
            item.resolution
                .target_rvas
                .retain(|target| mapped_starts.contains(target));
            if item.resolution.target_rvas.len() != before {
                item.resolution.complete = false;
            }
        }
        produced.retain(|item| !item.resolution.target_rvas.is_empty());
        let explicit_sites = resolutions.iter().map(|r| r.site).collect::<BTreeSet<_>>();
        let automatic = produced
            .iter()
            .filter(|p| !explicit_sites.contains(&p.resolution.site))
            .map(|p| p.resolution.clone())
            .collect::<Vec<_>>();
        crate::analysis::indirect_resolver::apply_indirect_resolutions(&mut model, &automatic)?;
        for p in produced
            .into_iter()
            .filter(|p| !explicit_sites.contains(&p.resolution.site))
        {
            if let Some(table) = p.table {
                if let Some(site) = model.indirect_targets.sites.get_mut(&p.resolution.site) {
                    site.table = Some(table);
                }
            }
        }
        // Resolve direct memory function-pointer slots after switch sites have
        // been applied. This producer is site-scoped and only consumes
        // canonical code-pointer inventory; unrelated global candidates are
        // never assigned to an indirect call.
        let pointer_resolutions = crate::analysis::pointer_tables::produce(&model, image_base, &[])
            .into_iter()
            .filter(|p| !explicit_sites.contains(&p.site))
            .collect::<Vec<_>>();
        crate::analysis::indirect_resolver::apply_indirect_resolutions(
            &mut model,
            &pointer_resolutions,
        )?;
        let local_resolutions =
            crate::analysis::pointer_tables::produce_local_value_flow(&model, image_base)
                .into_iter()
                .filter(|p| !explicit_sites.contains(&p.site))
                .collect::<Vec<_>>();
        crate::analysis::indirect_resolver::apply_indirect_resolutions(
            &mut model,
            &local_resolutions,
        )?;
        let stack_resolutions =
            crate::analysis::pointer_tables::produce_stack_spill_resolutions(&model, image_base)
                .into_iter()
                .filter(|p| !explicit_sites.contains(&p.site))
                .collect::<Vec<_>>();
        let stack_callback_entries = stack_resolutions
            .iter()
            .flat_map(|resolution| resolution.target_rvas.iter().copied())
            .collect::<BTreeSet<_>>();
        if !stack_callback_entries.is_empty() {
            model
                .discovered_indirect_code_targets
                .extend(stack_callback_entries.iter().copied());
            split_blocks_at_targets(&mut model, image_base, &stack_callback_entries);
            for entry in &stack_callback_entries {
                if let Some(function) = model
                    .functions
                    .values_mut()
                    .find(|function| {
                        function
                            .ranges
                            .iter()
                            .any(|range| range.start <= *entry && *entry < range.end)
                    })
                {
                    function.entries.insert(*entry);
                }
            }
        }
        crate::analysis::indirect_resolver::apply_indirect_resolutions(
            &mut model,
            &stack_resolutions,
        )?;
        let abi_resolutions =
            crate::analysis::pointer_tables::produce_abi_argument_resolutions(&model, image_base)
                .into_iter()
                .filter(|p| !explicit_sites.contains(&p.site))
                .collect::<Vec<_>>();
        crate::analysis::indirect_resolver::apply_indirect_resolutions(
            &mut model,
            &abi_resolutions,
        )?;
        let vtable_bases =
            crate::analysis::pointer_tables::discover_rust_vtable_bases(&model, &relayed_sections);
        let vtable_resolutions = crate::analysis::pointer_tables::produce_rust_vtable_resolutions(
            &model,
            image_base,
            &vtable_bases,
        )
        .into_iter()
        .filter(|p| !explicit_sites.contains(&p.site))
        .collect::<Vec<_>>();
        crate::analysis::indirect_resolver::apply_indirect_resolutions(
            &mut model,
            &vtable_resolutions,
        )?;
        if let Some(iat) = iat {
            for (site, slot_va) in
                crate::analysis::pointer_tables::produce_iat_slots(&model, image_base, iat)
            {
                if !explicit_sites.contains(&site) {
                    crate::analysis::indirect_resolver::apply_external_indirect_resolution(
                        &mut model,
                        site,
                        slot_va,
                        crate::analysis::indirect_targets::TargetProvenance::ImportAddressTable,
                    )?;
                }
            }
        }
        for (site, resolver_slot_va) in
            crate::analysis::pointer_tables::produce_dynamic_import_resolutions(
                &model,
                image_base,
                &get_proc_address_slots,
                &relayed_sections,
            )
        {
            if !explicit_sites.contains(&site) {
                crate::analysis::indirect_resolver::apply_external_indirect_resolution(
                    &mut model,
                    site,
                    resolver_slot_va,
                    crate::analysis::indirect_targets::TargetProvenance::DynamicImport,
                )?;
            }
        }
        for slot_rva in load_config_slots {
            let range = crate::analysis::program_model::RvaRange {
                start: slot_rva,
                end: slot_rva.saturating_add(8),
            };
            for (site, slot_va) in
                crate::analysis::pointer_tables::produce_iat_slots(&model, image_base, range)
            {
                if !explicit_sites.contains(&site) {
                    crate::analysis::indirect_resolver::apply_external_indirect_resolution(
                        &mut model,
                        site,
                        slot_va,
                        crate::analysis::indirect_targets::TargetProvenance::LoadConfig,
                    )?;
                }
            }
        }
        crate::analysis::indirect_resolver::apply_indirect_resolutions(&mut model, resolutions)?;
        model.indirect_targets.validate(&model)?;
        model.validate()?;
        Ok(model)
    }
}

/// Refines the canonical partition at proven indirect-jump destinations that
/// already correspond to decoded instructions. Incoming edges continue to
/// enter the old prefix; terminal outgoing edges move to the new suffix.
fn split_blocks_at_targets(model: &mut ProgramModel, image_base: u64, targets: &BTreeSet<u32>) {
    for &target in targets {
        if model
            .blocks
            .values()
            .any(|block| block.range.start == target)
        {
            continue;
        }
        let Some((block_id, split_index)) = model.blocks.iter().find_map(|(&id, block)| {
            block
                .instructions
                .iter()
                .position(|instruction| {
                    instruction
                        .ip()
                        .checked_sub(image_base)
                        .and_then(|rva| u32::try_from(rva).ok())
                        == Some(target)
                })
                .filter(|&index| index > 0)
                .map(|index| (id, index))
        }) else {
            continue;
        };
        let Some(mut prefix) = model.blocks.remove(&block_id) else {
            continue;
        };
        let suffix_instructions = prefix.instructions.split_off(split_index);
        let old_end = prefix.range.end;
        prefix.range.end = target;
        let function_id = prefix.function_id;
        let new_id = crate::analysis::program_model::BlockId(
            model.blocks.keys().next_back().map_or(0, |id| id.0 + 1),
        );
        let suffix = crate::analysis::program_model::BlockModel {
            id: new_id,
            function_id,
            range: crate::analysis::program_model::RvaRange {
                start: target,
                end: old_end,
            },
            instructions: suffix_instructions,
            byte_class: prefix.byte_class,
        };
        model.blocks.insert(block_id, prefix);
        model.blocks.insert(new_id, suffix);
        if let Some(function) = model.functions.get_mut(&function_id) {
            function.blocks.insert(new_id);
        }
        for edge in &mut model.edges {
            if edge.source == block_id {
                edge.source = new_id;
            }
        }
        for site in model.indirect_targets.sites.values_mut() {
            if site.source_block == block_id && site.instruction_rva >= target {
                site.source_block = new_id;
            }
        }
        model.edges.push(crate::analysis::program_model::EdgeModel {
            source: block_id,
            kind: crate::analysis::program_model::EdgeKind::Fallthrough,
            target: crate::analysis::program_model::EdgeTarget::Block(new_id),
        });
    }
}

fn merge_basic_blocks(
    model: &mut ProgramModel,
    blocks: &[BasicBlock],
    image_base: u64,
) -> Result<(), ProgramModelBuildError> {
    let va_to_rva = |va: u64| u32::try_from(va.checked_sub(image_base)?).ok();
    let mut decoded = Vec::new();
    for block in blocks {
        let Some(start) = va_to_rva(block.start_va) else {
            continue;
        };
        let Some(last) = block.instructions.last() else {
            continue;
        };
        let Some(end) = va_to_rva(last.ip().saturating_add(last.len() as u64)) else {
            continue;
        };
        let Ok(range) = RvaRange::new(start, end) else {
            continue;
        };
        if model
            .executable_ranges
            .iter()
            .any(|x| x.start <= start && end <= x.end)
        {
            decoded.push((start, range, block));
        }
    }
    decoded.sort_by_key(|(start, _, _)| *start);

    // Direct calls and cross-function unconditional branches are function-entry evidence.
    let mut seeds = BTreeMap::<u32, FunctionProvenance>::new();
    for (_, _, block) in &decoded {
        let Some(last) = block.instructions.last() else {
            continue;
        };
        if matches!(
            last.flow_control(),
            FlowControl::Call | FlowControl::UnconditionalBranch
        ) {
            if let Some(target) = va_to_rva(last.near_branch_target()) {
                if model
                    .executable_ranges
                    .iter()
                    .any(|x| x.start <= target && target < x.end)
                {
                    let source_owner = model
                        .functions
                        .iter()
                        .find(|(_, f)| {
                            f.ranges.iter().any(|r| {
                                r.start <= va_to_rva(block.start_va).unwrap_or(u32::MAX)
                                    && va_to_rva(block.start_va).unwrap_or(u32::MAX) < r.end
                            })
                        })
                        .map(|(id, _)| *id);
                    let target_owner = model
                        .functions
                        .iter()
                        .find(|(_, f)| f.ranges.iter().any(|r| r.start <= target && target < r.end))
                        .map(|(id, _)| *id);
                    if last.flow_control() == FlowControl::Call
                        || (source_owner.is_some() && source_owner != target_owner)
                    {
                        seeds.insert(
                            target,
                            if last.flow_control() == FlowControl::Call {
                                FunctionProvenance::DirectCall
                            } else {
                                FunctionProvenance::TailCall
                            },
                        );
                    }
                }
            }
        }
    }
    for (rva, provenance) in seeds {
        if let Some(function) = model
            .functions
            .values_mut()
            .find(|f| f.ranges.iter().any(|r| r.start <= rva && rva < r.end))
        {
            function.entries.insert(rva);
            function.provenance.insert(provenance);
        } else {
            let id = FunctionId(model.functions.keys().next_back().map_or(0, |id| id.0 + 1));
            model.functions.insert(
                id,
                FunctionModel {
                    id,
                    ranges: vec![RvaRange {
                        start: rva,
                        end: rva + 1,
                    }],
                    entries: [rva].into_iter().collect(),
                    blocks: BTreeSet::new(),
                    provenance: [provenance, FunctionProvenance::AmbiguousBoundary]
                        .into_iter()
                        .collect(),
                    unwind: None,
                },
            );
        }
    }

    let entries: Vec<(u32, FunctionId)> = model
        .functions
        .iter()
        .flat_map(|(id, f)| f.entries.iter().map(move |rva| (*rva, *id)))
        .collect();
    let mut starts = BTreeMap::new();
    for (ordinal, (start, range, block)) in decoded.iter().enumerate() {
        let owner = model
            .functions
            .iter()
            .find(|(_, f)| f.ranges.iter().any(|r| r.start <= *start && *start < r.end))
            .map(|(id, _)| *id)
            .or_else(|| {
                entries
                    .iter()
                    .filter(|(entry, _)| entry <= start)
                    .max_by_key(|(entry, _)| *entry)
                    .map(|(_, id)| *id)
            });
        let Some(owner) = owner else { continue };
        let id = BlockId(ordinal as u32);
        let function = model.functions.get_mut(&owner).unwrap();
        if !function
            .ranges
            .iter()
            .any(|r| r.start <= range.start && range.end <= r.end)
        {
            function.ranges.push(*range);
            function.ranges.sort();
            function
                .provenance
                .insert(FunctionProvenance::AmbiguousBoundary);
        }
        function.blocks.insert(id);
        model.blocks.insert(
            id,
            BlockModel {
                id,
                function_id: owner,
                range: *range,
                instructions: block.instructions.clone(),
                byte_class: ByteClass::Instruction,
            },
        );
        starts.insert(*start, id);
    }
    for (start, _, block) in &decoded {
        let Some(&source) = starts.get(start) else {
            continue;
        };
        let Some(last) = block.instructions.last() else {
            continue;
        };
        let next = va_to_rva(last.ip().saturating_add(last.len() as u64));
        let direct = va_to_rva(last.near_branch_target());
        let mut push = |kind, target: Option<u32>| {
            model.edges.push(EdgeModel {
                source,
                kind,
                target: target
                    .and_then(|r| starts.get(&r).copied())
                    .map(EdgeTarget::Block)
                    .unwrap_or_else(|| {
                        target
                            .and_then(|r| {
                                model
                                    .functions
                                    .iter()
                                    .find(|(_, f)| f.entries.contains(&r))
                                    .map(|(id, _)| EdgeTarget::Function(*id))
                            })
                            .unwrap_or(EdgeTarget::Unresolved)
                    }),
            })
        };
        match last.flow_control() {
            FlowControl::ConditionalBranch => {
                push(EdgeKind::DirectBranch, direct);
                push(EdgeKind::Fallthrough, next);
            }
            FlowControl::UnconditionalBranch => {
                let tail = direct.and_then(|r| {
                    model
                        .functions
                        .iter()
                        .find(|(_, f)| f.entries.contains(&r))
                        .map(|(id, _)| *id)
                }) != Some(model.blocks[&source].function_id);
                push(
                    if tail {
                        EdgeKind::TailCall
                    } else {
                        EdgeKind::DirectBranch
                    },
                    direct,
                );
            }
            FlowControl::Call => {
                push(EdgeKind::DirectCall, direct);
                push(EdgeKind::Fallthrough, next);
            }
            FlowControl::IndirectCall | FlowControl::IndirectBranch => {
                let site_id = crate::analysis::indirect_targets::IndirectSiteId(
                    model.indirect_targets.sites.len() as u32,
                );
                let instruction_rva = va_to_rva(last.ip()).unwrap_or(*start);
                let source_function = model.blocks[&source].function_id;
                model
                    .indirect_targets
                    .merge_site(crate::analysis::indirect_targets::IndirectSite {
                        id: site_id,
                        instruction_rva,
                        source_block: source,
                        source_function,
                        kind: if last.flow_control() == FlowControl::IndirectCall {
                            crate::analysis::indirect_targets::IndirectKind::Call
                        } else {
                            crate::analysis::indirect_targets::IndirectKind::Jump
                        },
                        status: crate::analysis::indirect_targets::ResolutionStatus::Unresolved,
                        targets: Default::default(),
                        table: None,
                    })
                    .expect("new canonical indirect-site id must be unique");
                push(
                    if last.flow_control() == FlowControl::IndirectCall {
                        EdgeKind::IndirectCall
                    } else {
                        EdgeKind::IndirectJump
                    },
                    None,
                );
                if last.flow_control() == FlowControl::IndirectCall {
                    push(EdgeKind::Fallthrough, next);
                }
            }
            _ => {
                if block
                    .successor_vas
                    .iter()
                    .any(|&va| Some(va) == next.map(|r| image_base + r as u64))
                {
                    push(EdgeKind::Fallthrough, next);
                }
            }
        }
    }
    model.unknown_ranges = complement(
        &model.executable_ranges,
        &model.blocks.values().map(|b| b.range).collect::<Vec<_>>(),
    );
    model.indirect_targets.validate(model)?;
    model.validate()?;
    Ok(())
}

fn executable_ranges(target: &TargetPeInfo) -> Result<Vec<RvaRange>, ProgramModelBuildError> {
    let mut ranges = Vec::new();
    for section in target
        .relayed_sections
        .iter()
        .filter(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
    {
        let size = section
            .virtual_size
            .max(section.bytes.len().min(u32::MAX as usize) as u32);
        let end = section.virtual_address.checked_add(size).ok_or(
            ProgramModelBuildError::RangeOverflow {
                start: section.virtual_address,
                size,
            },
        )?;
        if section.virtual_address < end {
            ranges.push(RvaRange::new(section.virtual_address, end)?);
        }
    }
    ranges.sort();
    // PE sections may be malformed/overlapping. Keep that explicit and reject it.
    for pair in ranges.windows(2) {
        if pair[0].overlaps(pair[1]) {
            return Err(ProgramModelError::OverlappingExecutableRanges {
                left: pair[0],
                right: pair[1],
            }
            .into());
        }
    }
    Ok(ranges)
}

fn read_u32_at(target: &TargetPeInfo, rva: u32) -> Option<u32> {
    target.relayed_sections.iter().find_map(|section| {
        let offset = rva.checked_sub(section.virtual_address)? as usize;
        let bytes = section.bytes.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    })
}

fn complement(executable: &[RvaRange], claimed: &[RvaRange]) -> Vec<RvaRange> {
    let mut out = Vec::new();
    for exec in executable {
        let mut cursor = exec.start;
        for range in claimed.iter().filter(|r| r.overlaps(*exec)) {
            let start = range.start.max(exec.start);
            let end = range.end.min(exec.end);
            if cursor < start {
                out.push(RvaRange {
                    start: cursor,
                    end: start,
                });
            }
            cursor = cursor.max(end);
        }
        if cursor < exec.end {
            out.push(RvaRange {
                start: cursor,
                end: exec.end,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{
        builder::{DataDirectory, SectionData},
        parser::{ExecutableSection, RuntimeFunction},
    };
    use iced_x86::{Decoder, DecoderOptions};

    fn target(pdata: Vec<RuntimeFunction>) -> TargetPeInfo {
        TargetPeInfo {
            image_base: 0x140000000,
            text_rva: 0x1000,
            text_raw_ptr: 0,
            text_size: 0x100,
            text_vsize: 0x100,
            text_bytes: vec![0x90; 0x100],
            entry_point_rva: 0x1010,
            subsystem: 3,
            original_dll_characteristics: 0,
            dll_characteristics: 0,
            stack_reserve: 0,
            stack_commit: 0,
            heap_reserve: 0,
            heap_commit: 0,
            file_alignment: 0x200,
            section_alignment: 0x1000,
            data_directories: vec![
                DataDirectory {
                    virtual_address: 0,
                    size: 0
                };
                16
            ],
            relayed_sections: vec![SectionData {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: 0x100,
                characteristics: IMAGE_SCN_MEM_EXECUTE,
                bytes: vec![0x90; 0x100],
            }],
            executable_sections: vec![ExecutableSection {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: 0x100,
                characteristics: IMAGE_SCN_MEM_EXECUTE,
                bytes: vec![0x90; 0x100],
            }],
            unwind_functions: Vec::new(),
            tls: None,
            load_config: None,
            exports: None,
            dir64_relocations: Vec::new(),
            original_headers_bytes: Vec::new(),
            original_pdata_entries: pdata,
            original_pe_bytes: Vec::new(),
        }
    }

    #[test]
    fn pdata_oep_and_unknown_form_exact_partition() {
        let model = ProgramModelBuilder::new(&target(vec![RuntimeFunction {
            begin_address: 0x1020,
            end_address: 0x1040,
            unwind_info_address: 0x2000,
        }]))
        .build()
        .unwrap();
        assert_eq!(model.functions.len(), 2);
        assert_eq!(
            model.functions[&FunctionId(0)].ranges[0],
            RvaRange {
                start: 0x1010,
                end: 0x1011
            }
        );
        assert_eq!(
            model.functions[&FunctionId(1)].ranges[0],
            RvaRange {
                start: 0x1020,
                end: 0x1040
            }
        );
        assert_eq!(
            model.unknown_ranges,
            vec![
                RvaRange {
                    start: 0x1000,
                    end: 0x1010
                },
                RvaRange {
                    start: 0x1011,
                    end: 0x1020
                },
                RvaRange {
                    start: 0x1040,
                    end: 0x1100
                },
            ]
        );
    }

    #[test]
    fn overlapping_pdata_is_one_ambiguous_stable_function() {
        let model = ProgramModelBuilder::new(&target(vec![
            RuntimeFunction {
                begin_address: 0x1040,
                end_address: 0x1080,
                unwind_info_address: 1,
            },
            RuntimeFunction {
                begin_address: 0x1020,
                end_address: 0x1060,
                unwind_info_address: 2,
            },
        ]))
        .build()
        .unwrap();
        let merged = &model.functions[&FunctionId(1)];
        assert_eq!(
            merged.ranges,
            vec![RvaRange {
                start: 0x1020,
                end: 0x1080
            }]
        );
        assert!(merged
            .provenance
            .contains(&FunctionProvenance::AmbiguousBoundary));
        assert_eq!(merged.unwind, None);
    }

    fn block(image_base: u64, rva: u32, bytes: &[u8], successors: &[u32]) -> BasicBlock {
        let va = image_base + rva as u64;
        let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            instructions.push(decoder.decode());
        }
        BasicBlock {
            id: rva,
            start_va: va,
            instructions,
            successor_vas: successors
                .iter()
                .map(|rva| image_base + *rva as u64)
                .collect(),
        }
    }

    #[test]
    fn cfg_blocks_seed_functions_edges_and_recompute_unknown_bytes() {
        let target = target(Vec::new());
        let base = target.image_base;
        let blocks = vec![
            // call 0x1020
            block(base, 0x1010, &[0xe8, 0x0b, 0, 0, 0], &[0x1015]),
            block(base, 0x1015, &[0xc3], &[]),
            block(base, 0x1020, &[0x75, 0x02], &[0x1022, 0x1024]),
            block(base, 0x1022, &[0xeb, 0x00], &[0x1024]),
            block(base, 0x1024, &[0xc3], &[]),
        ];
        let model = ProgramModelBuilder::new(&target)
            .build_with_basic_blocks(&blocks)
            .unwrap();

        let callee = model
            .functions
            .values()
            .find(|f| f.entries.contains(&0x1020))
            .unwrap();
        assert!(callee.provenance.contains(&FunctionProvenance::DirectCall));
        assert_eq!(model.blocks.len(), 5);
        assert!(model.edges.iter().any(|e| e.kind == EdgeKind::DirectCall
            && e.target
                == EdgeTarget::Block(
                    *model.functions[&FunctionId(1)]
                        .blocks
                        .iter()
                        .next()
                        .unwrap()
                )));
        assert!(model.edges.iter().any(|e| e.kind == EdgeKind::Fallthrough));
        assert!(model.edges.iter().any(|e| e.kind == EdgeKind::DirectBranch));
        assert!(!model
            .unknown_ranges
            .iter()
            .any(|r| r.start <= 0x1020 && 0x1025 <= r.end));
    }

    #[test]
    fn cfg_va_below_image_base_is_ignored() {
        let target = target(Vec::new());
        let foreign = BasicBlock {
            id: 7,
            start_va: target.image_base - 1,
            instructions: vec![],
            successor_vas: vec![],
        };
        let model = ProgramModelBuilder::new(&target)
            .build_with_basic_blocks(&[foreign])
            .unwrap();
        assert!(model.blocks.is_empty());
    }
}
