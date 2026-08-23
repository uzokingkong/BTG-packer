//! Conservative control-flow seeds recovered by linear decoding of executable sections.
//!
//! This is deliberately only a seed collector.  It does not claim reachability and it
//! does not create functions or basic blocks; `ProgramModelBuilder` can decide how to
//! merge these typed observations with stronger metadata such as `.pdata`.

use crate::pe::parser::{ExecutableSection, TargetPeInfo};
use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CfgSeedProvenance {
    DirectCall,
    TailCall,
    DirectBranch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectTarget {
    /// The target is inside one of the image's executable sections.
    ExecutableRva(u32),
    /// A valid direct target that is not executable code in this image.
    ExternalVa(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectTransfer {
    pub source_rva: u32,
    pub instruction_len: u8,
    pub provenance: CfgSeedProvenance,
    pub target: DirectTarget,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CfgSeedScan {
    pub transfers: Vec<DirectTransfer>,
    /// Candidate function entries. Direct calls and direct tail jumps contribute here.
    pub function_entries: BTreeMap<u32, BTreeSet<CfgSeedProvenance>>,
    /// Candidate block entries. All internal direct control transfers contribute here.
    pub block_entries: BTreeMap<u32, BTreeSet<CfgSeedProvenance>>,
    /// RVAs at which iced-x86 could not decode a valid instruction.
    pub invalid_instruction_rvas: BTreeSet<u32>,
}

impl CfgSeedScan {
    pub fn scan(target: &TargetPeInfo) -> Self {
        scan_executable_sections(target.image_base, target.executable_sections())
    }

    pub fn function_entry_rvas(&self) -> impl Iterator<Item = u32> + '_ {
        self.function_entries.keys().copied()
    }

    pub fn block_entry_rvas(&self) -> impl Iterator<Item = u32> + '_ {
        self.block_entries.keys().copied()
    }
}

pub fn scan_executable_sections(image_base: u64, sections: &[ExecutableSection]) -> CfgSeedScan {
    let executable = executable_spans(sections);
    let mut result = CfgSeedScan::default();

    for section in sections {
        // Bytes beyond VirtualSize are file-alignment padding, not mapped code.
        let logical_len = (section.virtual_size as usize).min(section.bytes.len());
        let Some(section_va) = image_base.checked_add(section.virtual_address as u64) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(
            64,
            &section.bytes[..logical_len],
            section_va,
            DecoderOptions::NONE,
        );

        while decoder.can_decode() {
            let instruction = decoder.decode();
            let Some(source_rva) = instruction
                .ip()
                .checked_sub(image_base)
                .and_then(|rva| u32::try_from(rva).ok())
            else {
                continue;
            };
            if instruction.is_invalid() {
                result.invalid_instruction_rvas.insert(source_rva);
                continue;
            }

            let provenance = match instruction.flow_control() {
                FlowControl::Call if is_direct_near_branch(&instruction) => {
                    Some(CfgSeedProvenance::DirectCall)
                }
                FlowControl::UnconditionalBranch if is_direct_near_branch(&instruction) => {
                    // A linear scan cannot prove function ownership. Treat direct JMPs as
                    // conservative tail-call candidates; the builder can demote intra-function
                    // jumps after boundaries are known.
                    Some(CfgSeedProvenance::TailCall)
                }
                FlowControl::ConditionalBranch if is_direct_near_branch(&instruction) => {
                    Some(CfgSeedProvenance::DirectBranch)
                }
                _ => None,
            };
            let Some(provenance) = provenance else {
                continue;
            };
            let target_va = instruction.near_branch_target();
            let target = target_va
                .checked_sub(image_base)
                .and_then(|rva| u32::try_from(rva).ok())
                .filter(|rva| contains_rva(&executable, *rva))
                .map(DirectTarget::ExecutableRva)
                .unwrap_or(DirectTarget::ExternalVa(target_va));

            result.transfers.push(DirectTransfer {
                source_rva,
                instruction_len: instruction.len() as u8,
                provenance,
                target,
            });
            if let DirectTarget::ExecutableRva(target_rva) = target {
                result
                    .block_entries
                    .entry(target_rva)
                    .or_default()
                    .insert(provenance);
                if matches!(
                    provenance,
                    CfgSeedProvenance::DirectCall | CfgSeedProvenance::TailCall
                ) {
                    result
                        .function_entries
                        .entry(target_rva)
                        .or_default()
                        .insert(provenance);
                }
            }
        }
    }
    result
}

fn is_direct_near_branch(instruction: &iced_x86::Instruction) -> bool {
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

fn executable_spans(sections: &[ExecutableSection]) -> Vec<(u32, u32)> {
    sections
        .iter()
        .filter_map(|section| {
            let file_len = u32::try_from(section.bytes.len()).unwrap_or(u32::MAX);
            let len = section.virtual_size.min(file_len);
            section
                .virtual_address
                .checked_add(len)
                .map(|end| (section.virtual_address, end))
        })
        .collect()
}

fn contains_rva(spans: &[(u32, u32)], rva: u32) -> bool {
    spans.iter().any(|&(start, end)| start <= rva && rva < end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(rva: u32, virtual_size: u32, bytes: &[u8]) -> ExecutableSection {
        ExecutableSection {
            name: ".text".into(),
            virtual_address: rva,
            virtual_size,
            characteristics: 0x6000_0020,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn collects_typed_internal_call_branch_and_tail_seeds() {
        // 1000: call 1010; 1005: je 1012; 100b: jmp 1014
        let mut bytes = vec![
            0xE8, 0x0B, 0, 0, 0, 0x0F, 0x84, 7, 0, 0, 0, 0xE9, 4, 0, 0, 0,
        ];
        bytes.resize(0x20, 0xC3);
        let scan = scan_executable_sections(0x1400_0000_0, &[section(0x1000, 0x20, &bytes)]);

        assert_eq!(scan.transfers.len(), 3);
        assert_eq!(
            scan.function_entry_rvas().collect::<Vec<_>>(),
            vec![0x1010, 0x1014]
        );
        assert_eq!(
            scan.block_entry_rvas().collect::<Vec<_>>(),
            vec![0x1010, 0x1012, 0x1014]
        );
        assert!(scan.function_entries[&0x1010].contains(&CfgSeedProvenance::DirectCall));
        assert!(scan.function_entries[&0x1014].contains(&CfgSeedProvenance::TailCall));
    }

    #[test]
    fn excludes_indirect_transfers_external_targets_and_raw_padding_from_seeds() {
        // call rax; call to VA immediately beyond mapped VirtualSize; raw-padding self-call
        let bytes = [
            0xFF, 0xD0, 0xE8, 9, 0, 0, 0, 0xC3, 0xE8, 0xF3, 0xFF, 0xFF, 0xFF,
        ];
        let scan = scan_executable_sections(0x1400_0000_0, &[section(0x2000, 8, &bytes)]);
        assert_eq!(scan.transfers.len(), 1);
        assert_eq!(
            scan.transfers[0].target,
            DirectTarget::ExternalVa(0x1_4000_2010)
        );
        assert!(scan.function_entries.is_empty());
        assert!(scan.block_entries.is_empty());
    }

    #[test]
    fn reports_invalid_decode_without_panicking() {
        let scan = scan_executable_sections(0x1400_0000_0, &[section(0x3000, 1, &[0x0F])]);
        assert_eq!(scan.invalid_instruction_rvas, BTreeSet::from([0x3000]));
    }
}
