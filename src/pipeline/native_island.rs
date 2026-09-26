//! Canonical relocation inventory for native code retained by a partial
//! commercial VM build.
//!
//! It converts the canonical ProgramModel and ownership decision into one
//! fail-closed plan, then materializes native code in a seed-dependent layout
//! while repairing in-place PC-relative encodings. External pointer and unwind
//! publication remains a separate commit step so original `.text` cannot be
//! discarded before every consumer has switched to the generated island.

use crate::analysis::indirect_targets::{
    IndirectTarget, ResolutionStatus, TableDescriptor, TargetProvenance,
};
use crate::analysis::program_model::{
    CodePointerEncoding, EdgeKind, EdgeTarget, FunctionId, ProgramModel,
};
use crate::pe::builder::SectionData;
use crate::pe::parser::TargetPeInfo;
use crate::pipeline::ownership::{FunctionOwnershipDiagnostic, OwnershipOrigin};
use anyhow::{anyhow, bail, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Register};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NativeEntryKind {
    TlsCallback,
    CrtInitializer,
    Export,
    AddressTaken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RipRelativeReference {
    pub instruction_rva: u32,
    pub target_va: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeInstruction {
    pub rva: u32,
    pub len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectEdgeReference {
    pub source_rva: u32,
    pub target_rva: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindReference {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_info_rva: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeIslandFunction {
    pub function_id: FunctionId,
    pub start_rva: u32,
    pub end_rva: u32,
    pub entries: Vec<u32>,
    pub instructions: Vec<NativeInstruction>,
    pub rip_relative_references: Vec<RipRelativeReference>,
    pub direct_edges: Vec<DirectEdgeReference>,
    pub fallthrough_target_rva: Option<u32>,
    pub unwind: Option<UnwindReference>,
    pub dir64_slots: Vec<u32>,
    pub entry_kinds: BTreeSet<NativeEntryKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeIslandBlocker {
    MissingProgramFunction { start_rva: u32 },
    MissingBlock { function_id: FunctionId },
    UnknownExecutableRange { start_rva: u32, end_rva: u32 },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NativeIslandPlan {
    pub functions: Vec<NativeIslandFunction>,
    pub blockers: Vec<NativeIslandBlocker>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeIslandPlacement {
    pub original_start_rva: u32,
    pub original_end_rva: u32,
    pub island_start_rva: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeIslandImage {
    pub base_rva: u32,
    pub bytes: Vec<u8>,
    pub placements: Vec<NativeIslandPlacement>,
    pub patched_rip_references: u64,
    pub patched_direct_edges: u64,
    pub patched_dir64_slots: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NativeReferenceAudit {
    pub inventoried_slots: u64,
    pub relocated_slots: u64,
    pub original_slots: u64,
    pub other_slots: u64,
    pub unsupported_slots: u64,
    pub original_unwind_metadata_slots: u64,
    pub original_cxx_eh_slots: u64,
    pub original_by_provenance: BTreeMap<&'static str, u64>,
    pub original_locations: Vec<(u32, &'static str, CodePointerEncoding)>,
}

impl NativeIslandPlan {
    pub fn is_ready_for_emission(&self) -> bool {
        !self.functions.is_empty() && self.blockers.is_empty()
    }

    pub fn native_bytes(&self) -> u64 {
        self.functions
            .iter()
            .map(|function| u64::from(function.end_rva.saturating_sub(function.start_rva)))
            .sum()
    }

    pub fn entry_count(&self) -> usize {
        self.callable_rvas().len()
    }

    fn callable_rvas(&self) -> BTreeSet<u32> {
        let is_relocated = |rva: u32| {
            self.functions
                .iter()
                .any(|function| function.start_rva <= rva && rva < function.end_rva)
        };
        let mut result = BTreeSet::new();
        for function in &self.functions {
            result.insert(function.start_rva);
            result.extend(
                function
                    .entries
                    .iter()
                    .copied()
                    .filter(|rva| is_relocated(*rva)),
            );
            result.extend(
                function
                    .direct_edges
                    .iter()
                    .map(|edge| edge.target_rva)
                    .filter(|rva| is_relocated(*rva)),
            );
            result.extend(
                function
                    .fallthrough_target_rva
                    .filter(|rva| is_relocated(*rva)),
            );
        }
        result
    }

    /// Exact original-VA -> island-VA pairs consumed by the VM native-call
    /// bridge. Alternate/cold entries are preserved instead of collapsing to
    /// the canonical function start.
    pub fn native_call_rewrites(
        &self,
        image_base: u64,
        image: &NativeIslandImage,
    ) -> Result<Vec<(u64, u64)>> {
        let mut rewrites = Vec::new();
        for entry_rva in self.callable_rvas() {
            let relocated = Self::translate_rva(&image.placements, entry_rva).ok_or_else(|| {
                anyhow!("native callable RVA {entry_rva:#x} is outside every emitted placement")
            })?;
            rewrites.push((
                image_base + u64::from(entry_rva),
                image_base + u64::from(relocated),
            ));
        }
        rewrites.sort_unstable();
        rewrites.dedup_by_key(|rewrite| rewrite.0);
        Ok(rewrites)
    }

    fn translate_rva(placements: &[NativeIslandPlacement], rva: u32) -> Option<u32> {
        placements
            .iter()
            .filter(|placement| {
                placement.original_start_rva <= rva && rva < placement.original_end_rva
            })
            .max_by_key(|placement| placement.original_start_rva)
            .map(|placement| {
                placement
                    .island_start_rva
                    .saturating_add(rva - placement.original_start_rva)
            })
    }

    fn placement_for_function<'a>(
        placements: &'a [NativeIslandPlacement],
        function: &NativeIslandFunction,
    ) -> Option<&'a NativeIslandPlacement> {
        placements
            .iter()
            .filter(|placement| {
                placement.original_start_rva == function.start_rva
                    && function.end_rva <= placement.original_end_rva
            })
            .min_by_key(|placement| placement.original_end_rva)
    }

    /// Materialize the native functions into a build-seed-dependent layout and
    /// repair every PC-relative reference whose source moved. This deliberately
    /// returns an error for encodings that cannot be rewritten in place; the
    /// caller must never fall back to the original `.text` address.
    pub fn emit(
        &self,
        target: &TargetPeInfo,
        base_rva: u32,
        seed: u64,
    ) -> Result<NativeIslandImage> {
        self.emit_with_external_redirects(target, base_rva, seed, &BTreeMap::new())
    }

    pub fn emit_with_external_redirects(
        &self,
        target: &TargetPeInfo,
        base_rva: u32,
        seed: u64,
        external_redirects: &BTreeMap<u64, u64>,
    ) -> Result<NativeIslandImage> {
        if !self.is_ready_for_emission() {
            bail!(
                "native-island plan is incomplete ({} blocker(s))",
                self.blockers.len()
            );
        }
        // Short inter-function branches cannot be expanded in-place without
        // shifting every following instruction and rebuilding unwind ranges.
        // Build relocation clusters for rel8/fallthrough-connected functions,
        // preserve original deltas inside each cluster, and randomize only the
        // cluster order and inter-cluster padding.
        let function_count = self.functions.len();
        let mut effective_ends = self
            .functions
            .iter()
            .map(|function| function.end_rva)
            .collect::<Vec<_>>();
        // PE unwind ranges occasionally stop immediately before a shared RET
        // leaf reached by a rel8 conditional branch (for example 0x2835 ->
        // 0x2840). Include that one decoded instruction in the source
        // placement so the short edge remains local instead of targeting the
        // retired original .text byte.
        for (index, function) in self.functions.iter().enumerate() {
            for site in &function.instructions {
                let source_offset = site.rva.saturating_sub(target.text_rva) as usize;
                let source_end = source_offset.saturating_add(site.len as usize);
                let Some(encoded) = target.text_bytes.get(source_offset..source_end) else {
                    continue;
                };
                let old_ip = target.image_base + u64::from(site.rva);
                let mut decoder = Decoder::with_ip(64, encoded, old_ip, DecoderOptions::NONE);
                let instruction = decoder.decode();
                let offsets = decoder.get_constant_offsets(&instruction);
                if offsets.immediate_size() != 1
                    || !matches!(
                        instruction.flow_control(),
                        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
                    )
                {
                    continue;
                }
                let branch_rva = instruction
                    .near_branch_target()
                    .saturating_sub(target.image_base) as u32;
                let has_canonical_owner = self.functions.iter().any(|candidate| {
                    candidate.start_rva <= branch_rva && branch_rva < candidate.end_rva
                });
                if !has_canonical_owner
                    && branch_rva >= function.end_rva
                    && branch_rva.saturating_sub(function.end_rva) <= i8::MAX as u32
                {
                    let tail_offset = function.end_rva.saturating_sub(target.text_rva) as usize;
                    if let Some(tail) = target.text_bytes.get(tail_offset..) {
                        let scan_len = tail.len().min(128);
                        let mut tail_decoder = Decoder::with_ip(
                            64,
                            &tail[..scan_len],
                            target.image_base + u64::from(function.end_rva),
                            DecoderOptions::NONE,
                        );
                        let mut extended_end = function.end_rva;
                        while tail_decoder.can_decode() {
                            let tail_instruction = tail_decoder.decode();
                            if tail_instruction.is_invalid()
                                || tail_instruction.code() == iced_x86::Code::Int3
                            {
                                break;
                            }
                            extended_end = tail_instruction.ip().saturating_sub(target.image_base)
                                as u32
                                + tail_instruction.len() as u32;
                        }
                        if branch_rva < extended_end {
                            effective_ends[index] = effective_ends[index].max(extended_end);
                        }
                    }
                }
            }

            if let Some(target_rva) = function.fallthrough_target_rva {
                let has_canonical_owner = self.functions.iter().any(|candidate| {
                    candidate.start_rva <= target_rva && target_rva < candidate.end_rva
                });
                if !has_canonical_owner && target_rva == function.end_rva {
                    let tail_offset = target_rva.saturating_sub(target.text_rva) as usize;
                    if let Some(tail) = target.text_bytes.get(tail_offset..) {
                        let scan_len = tail.len().min(4096);
                        let mut decoder = Decoder::with_ip(
                            64,
                            &tail[..scan_len],
                            target.image_base + u64::from(target_rva),
                            DecoderOptions::NONE,
                        );
                        let mut extended_end = target_rva;
                        while decoder.can_decode() {
                            let instruction = decoder.decode();
                            if instruction.is_invalid()
                                || instruction.code() == iced_x86::Code::Int3
                            {
                                break;
                            }
                            extended_end = instruction.ip().saturating_sub(target.image_base)
                                as u32
                                + instruction.len() as u32;
                        }
                        effective_ends[index] = effective_ends[index].max(extended_end);
                    }
                }
            }
        }
        let mut parent = (0..function_count).collect::<Vec<_>>();
        fn root(parent: &mut [usize], mut index: usize) -> usize {
            while parent[index] != index {
                let next = parent[index];
                parent[index] = parent[next];
                index = next;
            }
            index
        }
        fn join(parent: &mut [usize], left: usize, right: usize) {
            let left = root(parent, left);
            let right = root(parent, right);
            if left != right {
                parent[right] = left;
            }
        }
        let owner_index = |rva: u32| {
            self.functions
                .iter()
                .enumerate()
                .filter(|(_, function)| function.start_rva <= rva && rva < function.end_rva)
                .max_by_key(|(_, function)| function.start_rva)
                .map(|(index, _)| index)
                .or_else(|| {
                    self.functions
                        .iter()
                        .enumerate()
                        .filter(|(index, function)| {
                            function.start_rva <= rva && rva < effective_ends[*index]
                        })
                        .max_by_key(|(_, function)| function.start_rva)
                        .map(|(index, _)| index)
                })
        };
        for (source_index, function) in self.functions.iter().enumerate() {
            if let Some(target_index) = function.fallthrough_target_rva.and_then(owner_index) {
                join(&mut parent, source_index, target_index);
            }
            for site in &function.instructions {
                let source_offset = site.rva.saturating_sub(target.text_rva) as usize;
                let source_end = source_offset.saturating_add(site.len as usize);
                let Some(encoded) = target.text_bytes.get(source_offset..source_end) else {
                    continue;
                };
                let old_ip = target.image_base + u64::from(site.rva);
                let mut decoder = Decoder::with_ip(64, encoded, old_ip, DecoderOptions::NONE);
                let instruction = decoder.decode();
                let offsets = decoder.get_constant_offsets(&instruction);
                if offsets.immediate_size() != 1
                    || !matches!(
                        instruction.flow_control(),
                        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
                    )
                {
                    continue;
                }
                let target_rva = instruction
                    .near_branch_target()
                    .saturating_sub(target.image_base) as u32;
                if let Some(target_index) = owner_index(target_rva) {
                    join(&mut parent, source_index, target_index);
                }
            }
        }

        let mut grouped = BTreeMap::<usize, Vec<&NativeIslandFunction>>::new();
        for (index, function) in self.functions.iter().enumerate() {
            let group = root(&mut parent, index);
            grouped.entry(group).or_default().push(function);
        }
        let mut order = grouped.into_values().collect::<Vec<_>>();
        for cluster in &mut order {
            cluster.sort_unstable_by_key(|function| function.start_rva);
        }
        order.sort_unstable_by_key(|cluster| {
            let cluster_rva = cluster[0].start_rva;
            let mut value = seed ^ u64::from(cluster_rva) ^ 0x4E49_534C_414E_4421;
            value ^= value >> 30;
            value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
            value ^= value >> 27;
            value.wrapping_mul(0x94D0_49BB_1331_11EB) ^ (value >> 31)
        });

        let mut bytes = Vec::new();
        let mut placements = Vec::with_capacity(self.functions.len());
        for cluster in &order {
            let cluster_origin = cluster[0].start_rva;
            let cluster_end = cluster
                .iter()
                .map(|function| {
                    let index = self
                        .functions
                        .iter()
                        .position(|candidate| candidate.function_id == function.function_id)
                        .unwrap();
                    effective_ends[index]
                        .saturating_add(u32::from(function.fallthrough_target_rva.is_some()) * 5)
                })
                .max()
                .unwrap_or(cluster_origin);
            let pad = (((seed.rotate_left(cluster_origin & 63) ^ u64::from(cluster_origin)) & 0x3F)
                as usize
                + 15)
                & !15;
            bytes.resize(bytes.len().saturating_add(pad), 0xCC);
            let aligned = (bytes.len() + 15) & !15;
            bytes.resize(aligned, 0xCC);
            let cluster_start_rva = base_rva
                .checked_add(bytes.len() as u32)
                .ok_or_else(|| anyhow!("native-island cluster RVA overflow"))?;
            let cluster_len = cluster_end.saturating_sub(cluster_origin) as usize;
            let cluster_offset = bytes.len();
            bytes.resize(cluster_offset.saturating_add(cluster_len), 0xCC);
            for function in cluster {
                let source_offset = function
                    .start_rva
                    .checked_sub(target.text_rva)
                    .ok_or_else(|| anyhow!("native function begins before input .text"))?
                    as usize;
                let index = self
                    .functions
                    .iter()
                    .position(|candidate| candidate.function_id == function.function_id)
                    .unwrap();
                let effective_end = effective_ends[index];
                let function_len = effective_end.saturating_sub(function.start_rva) as usize;
                let source_end = source_offset
                    .checked_add(function_len)
                    .ok_or_else(|| anyhow!("native function source range overflow"))?;
                let source = target
                    .text_bytes
                    .get(source_offset..source_end)
                    .ok_or_else(|| {
                        anyhow!(
                            "native function {:#x} is outside input .text",
                            function.start_rva
                        )
                    })?;
                let relative = function.start_rva.saturating_sub(cluster_origin) as usize;
                bytes[cluster_offset + relative..cluster_offset + relative + function_len]
                    .copy_from_slice(source);
                placements.push(NativeIslandPlacement {
                    original_start_rva: function.start_rva,
                    original_end_rva: effective_end,
                    island_start_rva: cluster_start_rva.saturating_add(relative as u32),
                });
            }
        }

        let mut patched_rip_references = 0u64;
        let mut patched_direct_edges = 0u64;
        let mut patched_dir64_slots = 0u64;
        let mut rel8_thunk_offsets = BTreeSet::new();
        for function in &self.functions {
            let function_placement = Self::placement_for_function(&placements, function)
                .ok_or_else(|| anyhow!("native function placement disappeared"))?;
            for &slot_rva in &function.dir64_slots {
                let source_offset = slot_rva
                    .checked_sub(target.text_rva)
                    .ok_or_else(|| anyhow!("DIR64 slot precedes input .text"))?
                    as usize;
                let original_va = u64::from_le_bytes(
                    target
                        .text_bytes
                        .get(source_offset..source_offset + 8)
                        .ok_or_else(|| anyhow!("DIR64 slot exceeds input .text"))?
                        .try_into()
                        .map_err(|_| anyhow!("DIR64 slot slice drift"))?,
                );
                let original_rva = original_va.saturating_sub(target.image_base) as u32;
                let Some(relocated_rva) = Self::translate_rva(&placements, original_rva) else {
                    continue;
                };
                let relocated_slot_rva = function_placement
                    .island_start_rva
                    .saturating_add(slot_rva.saturating_sub(function.start_rva));
                let offset = relocated_slot_rva.saturating_sub(base_rva) as usize;
                let relocated_va = target.image_base + u64::from(relocated_rva);
                bytes[offset..offset + 8].copy_from_slice(&relocated_va.to_le_bytes());
                patched_dir64_slots += 1;
            }
        }
        for function in &self.functions {
            let Some(target_rva) = function.fallthrough_target_rva else {
                continue;
            };
            let source_rva = Self::placement_for_function(&placements, function)
                .ok_or_else(|| anyhow!("fallthrough source placement disappeared"))?
                .island_start_rva
                .saturating_add(function.end_rva.saturating_sub(function.start_rva));
            let destination_rva = Self::translate_rva(&placements, target_rva)
                .or_else(|| {
                    external_redirects
                        .get(&(target.image_base + u64::from(target_rva)))
                        .and_then(|va| va.checked_sub(target.image_base))
                        .and_then(|rva| u32::try_from(rva).ok())
                })
                .unwrap_or(target_rva);
            if destination_rva == source_rva {
                continue;
            }
            let displacement =
                i32::try_from(i64::from(destination_rva) - i64::from(source_rva.saturating_add(5)))
                    .map_err(|_| anyhow!("native fallthrough target exceeds rel32"))?;
            let offset = source_rva.saturating_sub(base_rva) as usize;
            bytes[offset] = 0xE9;
            bytes[offset + 1..offset + 5].copy_from_slice(&displacement.to_le_bytes());
            patched_direct_edges += 1;
        }
        for function in &self.functions {
            let function_placement = Self::placement_for_function(&placements, function)
                .ok_or_else(|| anyhow!("native function placement disappeared"))?;
            let new_function_rva = function_placement.island_start_rva;
            let mut relocation_sites = function.instructions.clone();
            let source_start = function.start_rva.saturating_sub(target.text_rva) as usize;
            let source_len = function_placement
                .original_end_rva
                .saturating_sub(function.start_rva) as usize;
            if let Some(source) = target
                .text_bytes
                .get(source_start..source_start.saturating_add(source_len))
            {
                let mut decoder = Decoder::with_ip(
                    64,
                    source,
                    target.image_base + u64::from(function.start_rva),
                    DecoderOptions::NONE,
                );
                while decoder.can_decode() {
                    let instruction = decoder.decode();
                    if instruction.is_invalid() {
                        break;
                    }
                    relocation_sites.push(NativeInstruction {
                        rva: instruction.ip().saturating_sub(target.image_base) as u32,
                        len: instruction.len() as u8,
                    });
                }
            }
            relocation_sites.sort_unstable_by_key(|site| site.rva);
            relocation_sites.dedup_by_key(|site| site.rva);
            for site in &relocation_sites {
                let source_offset = site
                    .rva
                    .checked_sub(target.text_rva)
                    .ok_or_else(|| anyhow!("native instruction before input .text"))?
                    as usize;
                let source_end = source_offset.saturating_add(site.len as usize);
                let encoded = target
                    .text_bytes
                    .get(source_offset..source_end)
                    .ok_or_else(|| {
                        anyhow!("native instruction {:#x} exceeds input .text", site.rva)
                    })?;
                let old_ip = target.image_base + u64::from(site.rva);
                let mut decoder = Decoder::with_ip(64, encoded, old_ip, DecoderOptions::NONE);
                let instruction = decoder.decode();
                if instruction.is_invalid() || instruction.len() != site.len as usize {
                    bail!("native instruction decode drift at RVA {:#x}", site.rva);
                }
                let offsets = decoder.get_constant_offsets(&instruction);
                let new_site_rva = new_function_rva
                    .checked_add(site.rva - function.start_rva)
                    .ok_or_else(|| anyhow!("native instruction destination overflow"))?;
                let island_offset = new_site_rva
                    .checked_sub(base_rva)
                    .ok_or_else(|| anyhow!("native instruction precedes island"))?
                    as usize;
                let new_next_va =
                    target.image_base + u64::from(new_site_rva) + instruction.len() as u64;

                if instruction.is_ip_rel_memory_operand()
                    || matches!(instruction.memory_base(), Register::RIP | Register::EIP)
                {
                    if offsets.displacement_size() != 4 {
                        bail!("unsupported RIP displacement width at RVA {:#x}", site.rva);
                    }
                    let old_target_va = instruction.ip_rel_memory_address();
                    let old_target_rva = old_target_va.saturating_sub(target.image_base) as u32;
                    let local_target = (function.start_rva <= old_target_rva
                        && old_target_rva < function_placement.original_end_rva)
                        .then(|| {
                            target.image_base
                                + u64::from(function_placement.island_start_rva.saturating_add(
                                    old_target_rva.saturating_sub(function.start_rva),
                                ))
                        });
                    let new_target_va = local_target
                        .or_else(|| {
                            Self::translate_rva(&placements, old_target_rva)
                                .map(|rva| target.image_base + u64::from(rva))
                        })
                        .or_else(|| external_redirects.get(&old_target_va).copied())
                        .unwrap_or(old_target_va);
                    let displacement = i64::try_from(new_target_va as i128 - new_next_va as i128)
                        .map_err(|_| {
                        anyhow!("RIP displacement overflow at RVA {:#x}", site.rva)
                    })?;
                    let displacement = i32::try_from(displacement).map_err(|_| {
                        anyhow!("RIP target out of rel32 range at RVA {:#x}", site.rva)
                    })?;
                    let patch = island_offset + offsets.displacement_offset();
                    bytes[patch..patch + 4].copy_from_slice(&displacement.to_le_bytes());
                    patched_rip_references += 1;
                }

                if matches!(
                    instruction.flow_control(),
                    FlowControl::Call
                        | FlowControl::UnconditionalBranch
                        | FlowControl::ConditionalBranch
                ) {
                    let old_target_va = instruction.near_branch_target();
                    let old_target_rva = old_target_va.saturating_sub(target.image_base) as u32;
                    // Every relative branch must be re-encoded after its
                    // source moves.  Targets owned by the island move with
                    // it; all other targets remain at their original RVA.
                    // Keeping the old displacement for an external CALL/JMP
                    // would instead preserve only the old *distance* and send
                    // execution to an unrelated address near the island.
                    let local_target = (function.start_rva <= old_target_rva
                        && old_target_rva < function_placement.original_end_rva)
                        .then(|| {
                            target.image_base
                                + u64::from(function_placement.island_start_rva.saturating_add(
                                    old_target_rva.saturating_sub(function.start_rva),
                                ))
                        });
                    let new_target_va = local_target
                        .or_else(|| {
                            Self::translate_rva(&placements, old_target_rva)
                                .map(|rva| target.image_base + u64::from(rva))
                        })
                        .or_else(|| external_redirects.get(&old_target_va).copied())
                        .unwrap_or(old_target_va);
                    let displacement = i64::try_from(new_target_va as i128 - new_next_va as i128)
                        .map_err(|_| {
                        anyhow!("branch displacement overflow at RVA {:#x}", site.rva)
                    })?;
                    let immediate_size = offsets.immediate_size();
                    let patch = island_offset + offsets.immediate_offset();
                    match immediate_size {
                        1 => {
                            let value = if let Ok(value) = i8::try_from(displacement) {
                                value
                            } else {
                                let next_offset = island_offset + instruction.len();
                                let lo = next_offset.saturating_sub(128);
                                let hi = bytes.len().min(next_offset.saturating_add(128));
                                let thunk_offset = (lo..hi.saturating_sub(4))
                                    .find(|&candidate| {
                                        !rel8_thunk_offsets
                                            .iter()
                                            .any(|used| candidate < *used + 5 && *used < candidate + 5)
                                            && bytes[candidate..candidate + 5]
                                                .iter()
                                                .all(|byte| *byte == 0xCC)
                                            && !(0..5).any(|delta| {
                                                let rva = base_rva
                                                    .saturating_add((candidate + delta) as u32);
                                                placements.iter().any(|placement| {
                                                    placement.original_start_rva
                                                        < placement.original_end_rva
                                                        && placement.island_start_rva <= rva
                                                        && rva
                                                            < placement.island_start_rva.saturating_add(
                                                                placement.original_end_rva
                                                                    - placement.original_start_rva,
                                                            )
                                                })
                                            })
                                    })
                                    .ok_or_else(|| {
                                        anyhow!(
                                            "no nearby rel8 thunk space at RVA {:#x} for target {:#x}",
                                            site.rva,
                                            old_target_rva,
                                        )
                                    })?;
                                let thunk_rva = base_rva.saturating_add(thunk_offset as u32);
                                let thunk_next_va = target.image_base + u64::from(thunk_rva) + 5;
                                let thunk_displacement =
                                    i32::try_from(new_target_va as i128 - thunk_next_va as i128)
                                        .map_err(|_| {
                                            anyhow!(
                                                "rel8 thunk target out of rel32 range at RVA {:#x}",
                                                site.rva
                                            )
                                        })?;
                                bytes[thunk_offset] = 0xE9;
                                bytes[thunk_offset + 1..thunk_offset + 5]
                                    .copy_from_slice(&thunk_displacement.to_le_bytes());
                                rel8_thunk_offsets.insert(thunk_offset);
                                i8::try_from(
                                    i64::from(thunk_rva)
                                        - i64::from(new_site_rva + instruction.len() as u32),
                                )
                                .map_err(|_| anyhow!("allocated rel8 thunk is not reachable"))?
                            };
                            bytes[patch] = value as u8;
                        }
                        4 => {
                            let value = i32::try_from(displacement).map_err(|_| {
                                anyhow!("rel32 branch out of range at RVA {:#x}", site.rva)
                            })?;
                            bytes[patch..patch + 4].copy_from_slice(&value.to_le_bytes());
                        }
                        _ => bail!("unsupported relative branch width at RVA {:#x}", site.rva),
                    }
                    patched_direct_edges += 1;
                }
            }
        }

        Ok(NativeIslandImage {
            base_rva,
            bytes,
            placements,
            patched_rip_references,
            patched_direct_edges,
            patched_dir64_slots,
        })
    }

    /// Redirect exception/unwind handler RVAs embedded in typed UNWIND_INFO.
    /// Relocated RUNTIME_FUNCTION rows may continue sharing the original
    /// unwind record, but its handler cannot remain an original `.text` thunk
    /// once that section is NX.
    pub fn redirect_unwind_handlers(
        &self,
        target: &TargetPeInfo,
        image: &NativeIslandImage,
        sections: &mut [SectionData],
    ) -> Result<u64> {
        let mut patched = 0u64;
        let mut seen = BTreeSet::new();
        for (_, info) in target
            .unwind_functions
            .iter()
            .flat_map(|function| function.chain.iter())
        {
            let crate::pe::unwind::UnwindTrailer::Handler {
                handler_rva,
                language_data_rva,
            } = info.trailer
            else {
                continue;
            };
            let Some(relocated_handler) = Self::translate_rva(&image.placements, handler_rva)
            else {
                continue;
            };
            let slot_rva = language_data_rva
                .checked_sub(4)
                .ok_or_else(|| anyhow!("UNWIND_INFO handler slot underflow"))?;
            if !seen.insert(slot_rva) {
                continue;
            }
            let section = sections
                .iter_mut()
                .find(|section| {
                    let end = section
                        .virtual_address
                        .checked_add(section.bytes.len() as u32);
                    section.virtual_address <= slot_rva
                        && end.is_some_and(|end| slot_rva.saturating_add(4) <= end)
                })
                .ok_or_else(|| anyhow!("UNWIND_INFO handler slot RVA {slot_rva:#x} is not file-backed"))?;
            let offset = (slot_rva - section.virtual_address) as usize;
            section.bytes[offset..offset + 4]
                .copy_from_slice(&relocated_handler.to_le_bytes());
            patched += 1;
        }
        Ok(patched)
    }

    /// Redirect canonical external code-pointer slots to their emitted native
    /// entry. Only encodings whose base is explicit in ProgramModel are
    /// accepted; table-relative encodings require their table descriptor and
    /// therefore remain fail-closed for the later typed-directory pass.
    pub fn redirect_code_pointers(
        &self,
        target: &TargetPeInfo,
        program: &ProgramModel,
        image: &NativeIslandImage,
        sections: &mut [SectionData],
    ) -> Result<u64> {
        let mut patched = 0u64;
        let cxx_eh_slots = crate::pe::cxx_eh::collect_code_rva_slots(
            target.unwind_functions.iter().flat_map(|function| {
                function
                    .chain
                    .iter()
                    .filter_map(|(_, info)| match info.trailer {
                        crate::pe::unwind::UnwindTrailer::Handler {
                            language_data_rva, ..
                        } => Some(language_data_rva),
                        _ => None,
                    })
            }),
            &target.relayed_sections,
        );
        let mut consumed_slots = BTreeSet::new();
        for site in program.indirect_targets.sites.values() {
            if site.status != ResolutionStatus::Complete
                || !site.targets.targets.values().any(|evidence| {
                    evidence.contains(&TargetProvenance::PointerTable)
                        || evidence.contains(&TargetProvenance::Vtable)
                })
            {
                continue;
            }
            let Some(block) = program.blocks.get(&site.source_block) else {
                continue;
            };
            let Some(instruction) = block.instructions.iter().find(|instruction| {
                instruction.ip().saturating_sub(target.image_base) as u32 == site.instruction_rva
            }) else {
                continue;
            };
            if instruction.op0_kind() != iced_x86::OpKind::Memory
                || instruction.memory_index() != Register::None
            {
                continue;
            }
            let slot_rva = if matches!(instruction.memory_base(), Register::RIP | Register::EIP) {
                instruction
                    .ip_rel_memory_address()
                    .checked_sub(target.image_base)
                    .and_then(|value| u32::try_from(value).ok())
            } else if instruction.memory_base() == Register::None {
                instruction
                    .memory_displacement64()
                    .checked_sub(target.image_base)
                    .and_then(|value| u32::try_from(value).ok())
            } else {
                None
            };
            if let Some(slot_rva) = slot_rva {
                consumed_slots.insert(slot_rva);
            }
        }
        for pointer in program.code_pointers.values() {
            let typed_directory_pointer = matches!(
                pointer.provenance,
                "tls-callback" | "crt-callback-table" | "guard-cf-table" | "guard-eh-continuation"
            );
            let relocation_backed_pointer = pointer.provenance == "dir64-relocation"
                && std::env::var_os("BTG_REDIRECT_NATIVE_ISLAND_DIR64_POINTERS").is_some();
            let cxx_eh_pointer = cxx_eh_slots.contains(&pointer.location.start)
                && std::env::var_os("BTG_REDIRECT_NATIVE_ISLAND_CXX_EH").is_some();
            if !typed_directory_pointer
                && !relocation_backed_pointer
                && !cxx_eh_pointer
                && !consumed_slots.contains(&pointer.location.start)
                && !program
                    .typed_pointer_slots
                    .contains_key(&pointer.location.start)
            {
                // Heuristic data-va/rva scans establish analysis seeds, not a
                // sufficiently strong rewrite proof. A slot becomes writable
                // only when a complete canonical indirect site directly names
                // it, or a typed PE directory owns it.
                continue;
            }
            let Some(_function) = program.functions.get(&pointer.target) else {
                bail!("code pointer {:?} targets a missing function", pointer.id);
            };
            let width = pointer.location.end.saturating_sub(pointer.location.start) as usize;
            let section = sections
                .iter_mut()
                .find(|section| {
                    pointer.location.start >= section.virtual_address
                        && u64::from(pointer.location.end)
                            <= u64::from(section.virtual_address) + section.bytes.len() as u64
                })
                .ok_or_else(|| {
                    anyhow!(
                        "code pointer {:?} location {:#x} is not file-backed",
                        pointer.id,
                        pointer.location.start
                    )
                })?;
            let offset = (pointer.location.start - section.virtual_address) as usize;
            let original_target_rva = match pointer.encoding {
                CodePointerEncoding::Va64 => {
                    if width != 8 {
                        bail!("VA64 code pointer {:?} has width {}", pointer.id, width);
                    }
                    let value = u64::from_le_bytes(
                        section.bytes[offset..offset + 8]
                            .try_into()
                            .map_err(|_| anyhow!("VA64 pointer slice drift"))?,
                    );
                    u32::try_from(value.saturating_sub(target.image_base)).map_err(|_| {
                        anyhow!("VA64 code pointer {:?} target is outside image", pointer.id)
                    })?
                }
                CodePointerEncoding::Rva32 | CodePointerEncoding::DirectoryField => {
                    if width != 4 {
                        bail!("RVA code pointer {:?} has width {}", pointer.id, width);
                    }
                    u32::from_le_bytes(
                        section.bytes[offset..offset + 4]
                            .try_into()
                            .map_err(|_| anyhow!("RVA32 pointer slice drift"))?,
                    )
                }
                CodePointerEncoding::Rel32 => {
                    if width != 4 {
                        bail!("rel32 code pointer {:?} has width {}", pointer.id, width);
                    }
                    let displacement = i32::from_le_bytes(
                        section.bytes[offset..offset + 4]
                            .try_into()
                            .map_err(|_| anyhow!("rel32 pointer slice drift"))?,
                    );
                    let target_va = (target.image_base + u64::from(pointer.location.end))
                        .wrapping_add_signed(i64::from(displacement));
                    u32::try_from(target_va.saturating_sub(target.image_base)).map_err(|_| {
                        anyhow!(
                            "rel32 code pointer {:?} target is outside image",
                            pointer.id
                        )
                    })?
                }
                CodePointerEncoding::TableRelative => {
                    bail!(
                        "table-relative code pointer {:?} requires typed table base",
                        pointer.id
                    );
                }
            };
            let Some(new_entry) = Self::translate_rva(&image.placements, original_target_rva)
            else {
                continue;
            };
            match pointer.encoding {
                CodePointerEncoding::Va64 => {
                    let value = target.image_base + u64::from(new_entry);
                    section.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                }
                CodePointerEncoding::Rva32 | CodePointerEncoding::DirectoryField => {
                    section.bytes[offset..offset + 4].copy_from_slice(&new_entry.to_le_bytes());
                }
                CodePointerEncoding::Rel32 => {
                    let origin = target.image_base + u64::from(pointer.location.end);
                    let destination = target.image_base + u64::from(new_entry);
                    let displacement = i32::try_from(destination as i128 - origin as i128)
                        .map_err(|_| anyhow!("code pointer {:?} exceeds rel32", pointer.id))?;
                    section.bytes[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
                }
                CodePointerEncoding::TableRelative => unreachable!(),
            }
            patched += 1;
        }
        Ok(patched)
    }

    /// Rewrite complete, typed jump tables whose entries target relocated
    /// native code. The descriptor is the authority for both table extent and
    /// scalar encoding; heuristic code-pointer scans are deliberately not
    /// consumed here.
    pub fn redirect_indirect_tables(
        &self,
        target: &TargetPeInfo,
        program: &ProgramModel,
        image: &NativeIslandImage,
        sections: &mut [SectionData],
    ) -> Result<u64> {
        let mut patched = 0u64;
        let mut seen = BTreeSet::new();
        'sites: for site in program.indirect_targets.sites.values() {
            if site.status != ResolutionStatus::Complete {
                continue;
            }
            let Some(TableDescriptor::Jump(table)) = &site.table else {
                continue;
            };
            if !site.targets.targets.values().any(|evidence| {
                evidence.contains(&TargetProvenance::JumpTable)
                    || evidence.contains(&TargetProvenance::PointerTable)
            }) {
                continue;
            }
            let key = (
                table.table.start,
                table.table.end,
                table.entry_width,
                table.entry_count,
                table.base_rva,
                table.entries_are_relative,
            );
            if !seen.insert(key) {
                continue;
            }
            if !matches!(table.entry_width, 4 | 8) {
                bail!(
                    "unsupported native-island jump-table width {} at RVA {:#x}",
                    table.entry_width,
                    table.table.start
                );
            }
            let mut proven_targets = BTreeSet::new();
            for (indirect_target, evidence) in &site.targets.targets {
                if !evidence.contains(&TargetProvenance::JumpTable) {
                    continue;
                }
                match *indirect_target {
                    IndirectTarget::Block(id) => {
                        if let Some(block) = program.blocks.get(&id) {
                            proven_targets.insert(block.range.start);
                        }
                    }
                    IndirectTarget::Function(id) => {
                        if let Some(function) = program.functions.get(&id) {
                            proven_targets.extend(function.entries.iter().copied());
                        }
                    }
                    IndirectTarget::External(_) | IndirectTarget::RuntimeRoute => {}
                }
            }
            // Status may have been promoted to Complete by the runtime-route
            // fallback after a partial table recovery. Preflight the complete
            // descriptor against only JumpTable-proven targets before writing
            // a single byte.
            for index in 0..table.entry_count {
                let Some(entry_rva) = table
                    .table
                    .start
                    .checked_add(index.saturating_mul(u32::from(table.entry_width)))
                else {
                    continue 'sites;
                };
                let Some(original_section) = target.relayed_sections.iter().find(|section| {
                    let end = section
                        .virtual_address
                        .checked_add(section.bytes.len() as u32);
                    section.virtual_address <= entry_rva
                        && end.is_some_and(|end| entry_rva + u32::from(table.entry_width) <= end)
                }) else {
                    continue 'sites;
                };
                let offset = (entry_rva - original_section.virtual_address) as usize;
                let raw = &original_section.bytes[offset..offset + usize::from(table.entry_width)];
                let original_rva = if table.entries_are_relative {
                    if table.entry_width != 4 {
                        continue 'sites;
                    }
                    let Ok(bytes) = <[u8; 4]>::try_from(raw) else {
                        continue 'sites;
                    };
                    let value = i64::from(table.base_rva) + i64::from(i32::from_le_bytes(bytes));
                    let Ok(value) = u32::try_from(value) else {
                        continue 'sites;
                    };
                    value
                } else if table.entry_width == 8 {
                    let Ok(bytes) = <[u8; 8]>::try_from(raw) else {
                        continue 'sites;
                    };
                    let Some(value) = u64::from_le_bytes(bytes).checked_sub(target.image_base)
                    else {
                        continue 'sites;
                    };
                    let Ok(value) = u32::try_from(value) else {
                        continue 'sites;
                    };
                    value
                } else {
                    let Ok(bytes) = <[u8; 4]>::try_from(raw) else {
                        continue 'sites;
                    };
                    u32::from_le_bytes(bytes)
                };
                if !proven_targets.contains(&original_rva) {
                    continue 'sites;
                }
            }
            for index in 0..table.entry_count {
                let entry_rva = table
                    .table
                    .start
                    .checked_add(index.saturating_mul(u32::from(table.entry_width)))
                    .ok_or_else(|| anyhow!("jump-table entry RVA overflow"))?;
                let original_section = target
                    .relayed_sections
                    .iter()
                    .find(|section| {
                        let end = section
                            .virtual_address
                            .checked_add(section.bytes.len() as u32);
                        section.virtual_address <= entry_rva
                            && end
                                .is_some_and(|end| entry_rva + u32::from(table.entry_width) <= end)
                    })
                    .ok_or_else(|| {
                        anyhow!("original jump table RVA {entry_rva:#x} is not file-backed")
                    })?;
                let original_offset = (entry_rva - original_section.virtual_address) as usize;
                let width = table.entry_width as usize;
                let raw = &original_section.bytes[original_offset..original_offset + width];

                let section = sections
                    .iter_mut()
                    .find(|section| {
                        let end = section
                            .virtual_address
                            .checked_add(section.bytes.len() as u32);
                        section.virtual_address <= entry_rva
                            && end
                                .is_some_and(|end| entry_rva + u32::from(table.entry_width) <= end)
                    })
                    .ok_or_else(|| anyhow!("jump table RVA {entry_rva:#x} is not file-backed"))?;
                let offset = (entry_rva - section.virtual_address) as usize;
                let original_rva = if table.entries_are_relative {
                    if width != 4 {
                        bail!("relative jump table at {entry_rva:#x} is not rel32");
                    }
                    let displacement = i32::from_le_bytes(
                        raw.try_into()
                            .map_err(|_| anyhow!("rel32 jump-table slice drift"))?,
                    );
                    u32::try_from(i64::from(table.base_rva) + i64::from(displacement)).map_err(
                        |_| {
                            anyhow!(
                                "relative jump-table target outside image: table={:#x} entry={} base={:#x} displacement={:#x}",
                                table.table.start,
                                index,
                                table.base_rva,
                                displacement
                            )
                        },
                    )?
                } else if width == 8 {
                    let va = u64::from_le_bytes(
                        raw.try_into()
                            .map_err(|_| anyhow!("VA64 jump-table slice drift"))?,
                    );
                    u32::try_from(va.saturating_sub(target.image_base))
                        .map_err(|_| anyhow!("VA64 jump-table target outside image"))?
                } else {
                    u32::from_le_bytes(
                        raw.try_into()
                            .map_err(|_| anyhow!("RVA32 jump-table slice drift"))?,
                    )
                };
                let Some(relocated_rva) = Self::translate_rva(&image.placements, original_rva)
                else {
                    continue;
                };
                if table.entries_are_relative {
                    let value = i32::try_from(i64::from(relocated_rva) - i64::from(table.base_rva))
                        .map_err(|_| anyhow!("relocated jump-table target exceeds rel32"))?;
                    section.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                } else if width == 8 {
                    let value = target.image_base + u64::from(relocated_rva);
                    section.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                } else {
                    section.bytes[offset..offset + 4].copy_from_slice(&relocated_rva.to_le_bytes());
                }
                patched += 1;
            }
        }
        Ok(patched)
    }

    /// Re-read canonical code-pointer slots from the prospective output and
    /// classify references to native functions. This is typed evidence for the
    /// original-.text retirement gate, not a raw byte-pattern scan.
    pub fn audit_native_code_pointers(
        &self,
        target: &TargetPeInfo,
        program: &ProgramModel,
        image: &NativeIslandImage,
        sections: &[SectionData],
    ) -> NativeReferenceAudit {
        let mut audit = NativeReferenceAudit::default();
        let cxx_eh_slots = crate::pe::cxx_eh::collect_code_rva_slots(
            target.unwind_functions.iter().flat_map(|function| {
                function
                    .chain
                    .iter()
                    .filter_map(|(_, info)| match info.trailer {
                        crate::pe::unwind::UnwindTrailer::Handler {
                            language_data_rva, ..
                        } => Some(language_data_rva),
                        _ => None,
                    })
            }),
            &target.relayed_sections,
        );
        // Keep the retirement audit's trust boundary identical to the
        // rewrite pass above.  In particular, raw data-rva32/data-va64 scans
        // are discovery hints and can alias ordinary constants; treating
        // those hints as authoritative pointers makes the fail-closed gate
        // report references that the typed rewriter intentionally cannot
        // prove or mutate.
        let mut consumed_slots = BTreeSet::new();
        for site in program.indirect_targets.sites.values() {
            if site.status != ResolutionStatus::Complete
                || !site.targets.targets.values().any(|evidence| {
                    evidence.contains(&TargetProvenance::PointerTable)
                        || evidence.contains(&TargetProvenance::Vtable)
                })
            {
                continue;
            }
            let Some(block) = program.blocks.get(&site.source_block) else {
                continue;
            };
            let Some(instruction) = block.instructions.iter().find(|instruction| {
                instruction.ip().saturating_sub(target.image_base) as u32 == site.instruction_rva
            }) else {
                continue;
            };
            if instruction.op0_kind() != iced_x86::OpKind::Memory
                || instruction.memory_index() != Register::None
            {
                continue;
            }
            let slot_rva = if matches!(instruction.memory_base(), Register::RIP | Register::EIP) {
                instruction
                    .ip_rel_memory_address()
                    .checked_sub(target.image_base)
                    .and_then(|value| u32::try_from(value).ok())
            } else if instruction.memory_base() == Register::None {
                instruction
                    .memory_displacement64()
                    .checked_sub(target.image_base)
                    .and_then(|value| u32::try_from(value).ok())
            } else {
                None
            };
            if let Some(slot_rva) = slot_rva {
                consumed_slots.insert(slot_rva);
            }
        }
        for pointer in program.code_pointers.values() {
            let typed_directory_pointer = matches!(
                pointer.provenance,
                "tls-callback" | "crt-callback-table" | "guard-cf-table" | "guard-eh-continuation"
            );
            let relocation_backed_pointer = pointer.provenance == "dir64-relocation"
                && std::env::var_os("BTG_REDIRECT_NATIVE_ISLAND_DIR64_POINTERS").is_some();
            let cxx_eh_pointer = cxx_eh_slots.contains(&pointer.location.start)
                && std::env::var_os("BTG_REDIRECT_NATIVE_ISLAND_CXX_EH").is_some();
            if !typed_directory_pointer
                && !relocation_backed_pointer
                && !cxx_eh_pointer
                && !consumed_slots.contains(&pointer.location.start)
                && !program
                    .typed_pointer_slots
                    .contains_key(&pointer.location.start)
            {
                continue;
            }
            let Some(function) = program.functions.get(&pointer.target) else {
                continue;
            };
            let Some(&original_rva) = function.entries.iter().next() else {
                continue;
            };
            let Some(relocated_rva) = Self::translate_rva(&image.placements, original_rva) else {
                continue;
            };
            audit.inventoried_slots += 1;
            let width = pointer.location.end.saturating_sub(pointer.location.start) as usize;
            let Some(section) = sections.iter().find(|section| {
                let end = section
                    .virtual_address
                    .checked_add(section.bytes.len() as u32);
                section.virtual_address <= pointer.location.start
                    && end.is_some_and(|end| pointer.location.end <= end)
            }) else {
                audit.other_slots += 1;
                continue;
            };
            let offset = (pointer.location.start - section.virtual_address) as usize;
            let raw = &section.bytes[offset..offset + width];
            let stored_target_rva = match pointer.encoding {
                CodePointerEncoding::Va64 if width == 8 => <[u8; 8]>::try_from(raw)
                    .ok()
                    .map(u64::from_le_bytes)
                    .and_then(|value| value.checked_sub(target.image_base))
                    .and_then(|value| u32::try_from(value).ok()),
                CodePointerEncoding::Rva32 | CodePointerEncoding::DirectoryField if width == 4 => {
                    <[u8; 4]>::try_from(raw).ok().map(u32::from_le_bytes)
                }
                CodePointerEncoding::Rel32 if width == 4 => {
                    <[u8; 4]>::try_from(raw).ok().and_then(|bytes| {
                        let displacement = i32::from_le_bytes(bytes);
                        let origin = target.image_base + u64::from(pointer.location.end);
                        origin
                            .checked_add_signed(i64::from(displacement))
                            .and_then(|value| value.checked_sub(target.image_base))
                            .and_then(|value| u32::try_from(value).ok())
                    })
                }
                CodePointerEncoding::TableRelative
                | CodePointerEncoding::Va64
                | CodePointerEncoding::Rva32
                | CodePointerEncoding::DirectoryField
                | CodePointerEncoding::Rel32 => {
                    audit.unsupported_slots += 1;
                    continue;
                }
            };
            match stored_target_rva {
                Some(value) if value == relocated_rva => audit.relocated_slots += 1,
                Some(value) if value == original_rva => {
                    audit.original_slots += 1;
                    *audit
                        .original_by_provenance
                        .entry(pointer.provenance)
                        .or_default() += 1;
                    audit.original_locations.push((
                        pointer.location.start,
                        pointer.provenance,
                        pointer.encoding,
                    ));
                    if target.unwind_functions.iter().any(|function| {
                        function.chain.iter().any(|(unwind_rva, _)| {
                            *unwind_rva <= pointer.location.start
                                && pointer.location.start < unwind_rva.saturating_add(0x40)
                        })
                    }) {
                        audit.original_unwind_metadata_slots += 1;
                    }
                    if cxx_eh_slots.contains(&pointer.location.start) {
                        audit.original_cxx_eh_slots += 1;
                    }
                }
                _ => audit.other_slots += 1,
            }
        }
        audit
    }

    pub fn build(
        target: &TargetPeInfo,
        program: &ProgramModel,
        ownership: &[FunctionOwnershipDiagnostic],
    ) -> Self {
        let native = ownership
            .iter()
            .filter(|record| {
                record.origin == OwnershipOrigin::Original && !record.function.owned_by_vm
            })
            .collect::<Vec<_>>();
        let native_ids = native
            .iter()
            .filter_map(|record| {
                program
                    .functions
                    .values()
                    .find(|function| function.entries.contains(&record.function.start_rva))
                    .map(|function| function.id)
            })
            .collect::<BTreeSet<_>>();
        let block_starts = program
            .blocks
            .iter()
            .map(|(id, block)| (*id, block.range.start))
            .collect::<BTreeMap<_, _>>();

        let mut plan = Self::default();
        for record in native {
            let start_rva = record.function.start_rva;
            let end_rva = record.function.end_rva;
            let Some(function) = program
                .functions
                .values()
                .find(|function| function.entries.contains(&start_rva))
            else {
                plan.blockers
                    .push(NativeIslandBlocker::MissingProgramFunction { start_rva });
                continue;
            };
            // The ownership range is the relocation unit. ProgramModel may
            // retain several disjoint provenance ranges for the same canonical
            // function (landing pads and cold fragments in particular); that
            // is dependency information, not a reason to drop the native
            // function from the plan.
            if function
                .blocks
                .iter()
                .any(|block_id| !program.blocks.contains_key(block_id))
            {
                plan.blockers.push(NativeIslandBlocker::MissingBlock {
                    function_id: function.id,
                });
                continue;
            }

            let mut instructions = Vec::new();
            let mut rip_relative_references = Vec::new();
            for block_id in &function.blocks {
                let block = &program.blocks[block_id];
                for instruction in &block.instructions {
                    let instruction_rva = instruction.ip().saturating_sub(target.image_base) as u32;
                    let instruction_end = instruction_rva.saturating_add(instruction.len() as u32);
                    if instruction_rva < start_rva || instruction_end > end_rva {
                        continue;
                    }
                    instructions.push(NativeInstruction {
                        rva: instruction_rva,
                        len: instruction.len() as u8,
                    });
                    if matches!(instruction.memory_base(), Register::RIP | Register::EIP) {
                        rip_relative_references.push(RipRelativeReference {
                            instruction_rva,
                            target_va: instruction.ip_rel_memory_address(),
                        });
                    }
                }
            }
            // Canonical provenance can omit an overlapping/cold block even
            // though the enclosing ownership range is valid executable code.
            // Decode the relocation unit itself so RIP-relative references in
            // those bytes are never copied with their old displacement.
            let range_offset = start_rva.saturating_sub(target.text_rva) as usize;
            let range_len = end_rva.saturating_sub(start_rva) as usize;
            if let Some(range_bytes) = target
                .text_bytes
                .get(range_offset..range_offset.saturating_add(range_len))
            {
                let mut decoder = Decoder::with_ip(
                    64,
                    range_bytes,
                    target.image_base + u64::from(start_rva),
                    DecoderOptions::NONE,
                );
                while decoder.can_decode() {
                    let instruction = decoder.decode();
                    if instruction.is_invalid() {
                        break;
                    }
                    let instruction_rva = instruction.ip().saturating_sub(target.image_base) as u32;
                    instructions.push(NativeInstruction {
                        rva: instruction_rva,
                        len: instruction.len() as u8,
                    });
                    if matches!(instruction.memory_base(), Register::RIP | Register::EIP) {
                        rip_relative_references.push(RipRelativeReference {
                            instruction_rva,
                            target_va: instruction.ip_rel_memory_address(),
                        });
                    }
                }
            }
            rip_relative_references.sort_unstable_by_key(|reference| reference.instruction_rva);
            rip_relative_references.dedup_by_key(|reference| reference.instruction_rva);
            instructions.sort_unstable_by_key(|instruction| instruction.rva);
            instructions.dedup_by_key(|instruction| instruction.rva);

            let mut direct_edges = Vec::new();
            let mut fallthrough_target_rva = None;
            for edge in &program.edges {
                if !function.blocks.contains(&edge.source) {
                    continue;
                }
                if program.blocks.get(&edge.source).is_none_or(|source| {
                    source.range.start < start_rva || source.range.end > end_rva
                }) {
                    continue;
                }
                let Some(&source_rva) = block_starts.get(&edge.source) else {
                    continue;
                };
                let target_rva = match edge.target {
                    EdgeTarget::Block(id) => block_starts.get(&id).copied(),
                    EdgeTarget::Function(id) => program
                        .functions
                        .get(&id)
                        .and_then(|target| target.entries.iter().next().copied()),
                    EdgeTarget::External(_) | EdgeTarget::RuntimeRoute | EdgeTarget::Unresolved => {
                        None
                    }
                };
                if let Some(target_rva) = target_rva {
                    if edge.kind == EdgeKind::Fallthrough
                        && program
                            .blocks
                            .get(&edge.source)
                            .is_some_and(|source| source.range.end == end_rva)
                        && !(start_rva <= target_rva && target_rva < end_rva)
                    {
                        fallthrough_target_rva = Some(target_rva);
                    }
                    direct_edges.push(DirectEdgeReference {
                        source_rva,
                        target_rva,
                    });
                }
            }
            direct_edges.sort_unstable_by_key(|edge| (edge.source_rva, edge.target_rva));
            direct_edges.dedup();

            let unwind = target
                .original_pdata_entries
                .iter()
                .find(|entry| entry.begin_address == start_rva && entry.end_address == end_rva)
                .map(|entry| UnwindReference {
                    begin_rva: entry.begin_address,
                    end_rva: entry.end_address,
                    unwind_info_rva: entry.unwind_info_address,
                });
            let dir64_slots = target
                .dir64_relocations
                .iter()
                .copied()
                .filter(|slot| start_rva <= *slot && *slot < end_rva)
                .collect();
            let mut entry_kinds = BTreeSet::new();
            if program.tls_callbacks.contains(&function.id) {
                entry_kinds.insert(NativeEntryKind::TlsCallback);
            }
            if program.crt_entries.contains(&function.id) {
                entry_kinds.insert(NativeEntryKind::CrtInitializer);
            }
            if program.exports.contains(&function.id) {
                entry_kinds.insert(NativeEntryKind::Export);
            }
            if program
                .code_pointers
                .values()
                .any(|pointer| pointer.target == function.id)
            {
                entry_kinds.insert(NativeEntryKind::AddressTaken);
            }

            plan.functions.push(NativeIslandFunction {
                function_id: function.id,
                start_rva,
                end_rva,
                entries: function
                    .entries
                    .iter()
                    .copied()
                    .filter(|entry| start_rva <= *entry && *entry < end_rva)
                    .collect(),
                instructions,
                rip_relative_references,
                direct_edges,
                fallthrough_target_rva,
                unwind,
                dir64_slots,
                entry_kinds,
            });
        }

        // Unknown executable bytes cannot be discarded merely because all
        // named native functions were inventoried.
        for range in &program.unknown_ranges {
            if native_ids.iter().any(|id| {
                program.functions.get(id).is_some_and(|function| {
                    function.ranges.iter().any(|owned| owned.overlaps(*range))
                })
            }) {
                plan.blockers
                    .push(NativeIslandBlocker::UnknownExecutableRange {
                        start_rva: range.start,
                        end_rva: range.end,
                    });
            }
        }
        plan.functions
            .sort_unstable_by_key(|function| function.start_rva);
        plan
    }
}
