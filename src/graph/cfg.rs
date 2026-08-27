// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Multi-Edge CFG Extractor Engine
// ==============================================================================

use crate::core::graph::{BidirectionalGraph, EdgeType};
use anyhow::Result;
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction};

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: u32,
    pub start_va: u64,
    pub instructions: Vec<Instruction>,
    pub successor_vas: Vec<u64>,
}

pub struct CfgExtractor;

impl CfgExtractor {
    pub fn extract(
        text_bytes: &[u8],
        base_va: u64,
        entry_point_va: u64,
        relayed_sections: &[crate::pe::builder::SectionData],
        image_base: u64,
    ) -> Result<(Vec<BasicBlock>, BidirectionalGraph)> {
        Self::extract_with_additional_starts(
            text_bytes,
            base_va,
            entry_point_va,
            relayed_sections,
            image_base,
            &[],
        )
    }

    pub fn extract_with_additional_starts(
        text_bytes: &[u8],
        base_va: u64,
        entry_point_va: u64,
        relayed_sections: &[crate::pe::builder::SectionData],
        image_base: u64,
        additional_starts: &[u64],
    ) -> Result<(Vec<BasicBlock>, BidirectionalGraph)> {
        // RawSize commonly includes file-alignment zero padding after .text's
        // VirtualSize. Decoding that padding creates fake `add [rax],al` blocks
        // and used to be masked later by a synthetic RET. Restrict CFG input to
        // the executable virtual span when section metadata is available.
        let logical_len = relayed_sections
            .iter()
            .find(|sec| sec.name == ".text" && image_base + sec.virtual_address as u64 == base_va)
            .map(|sec| sec.virtual_size as usize)
            .unwrap_or(text_bytes.len())
            .min(text_bytes.len());
        let text_bytes = &text_bytes[..logical_len];
        // Collect explicit control-flow targets before classifying 0xCC runs. A
        // branch-targeted INT3 is executable program semantics, never padding.
        let mut explicit_code_targets = std::collections::BTreeSet::new();
        explicit_code_targets.insert(entry_point_va);
        explicit_code_targets.extend(additional_starts.iter().copied());
        let mut target_decoder = Decoder::with_ip(64, text_bytes, base_va, DecoderOptions::NONE);
        while target_decoder.can_decode() {
            let inst = target_decoder.decode();
            if !inst.is_invalid()
                && matches!(
                    inst.flow_control(),
                    FlowControl::UnconditionalBranch
                        | FlowControl::ConditionalBranch
                        | FlowControl::Call
                )
            {
                let target = inst.near_branch_target();
                if target >= base_va && target < base_va + text_bytes.len() as u64 {
                    explicit_code_targets.insert(target);
                }
            }
        }

        let mut decoder = Decoder::with_ip(64, text_bytes, base_va, DecoderOptions::NONE);

        let mut instructions = Vec::new();
        // (pad_start_ip, first_real_ip): 0xCC padding runs and the first real
        // instruction after each run. Used to re-materialize block boundaries
        // that fall inside padding (e.g. the byte right after a `ret`).
        let mut pad_runs: Vec<(u64, u64)> = Vec::new();
        let mut pad_start: Option<u64> = None;

        while decoder.can_decode() {
            let inst = decoder.decode();

            if inst.is_invalid() {
                // Invalid decode gaps are not valid instructions. Keep their
                // boundary bookkeeping separate from intentional INT3 traps.
                if pad_start.is_none() {
                    pad_start = Some(inst.ip());
                }
                let current_ip = decoder.ip();
                if ((current_ip - base_va) as usize) < text_bytes.len() {
                    decoder = Decoder::with_ip(
                        64,
                        &text_bytes[(current_ip - base_va) as usize..],
                        current_ip,
                        DecoderOptions::NONE,
                    );
                }
                continue;
            }

            if inst.code() == Code::Int3 {
                let after_terminal = pad_start.is_some()
                    || instructions.last().is_some_and(|prev: &Instruction| {
                        matches!(
                            prev.flow_control(),
                            FlowControl::Return | FlowControl::UnconditionalBranch
                        )
                    });
                if after_terminal && !explicit_code_targets.contains(&inst.ip()) {
                    if pad_start.is_none() {
                        pad_start = Some(inst.ip());
                    }
                    continue;
                }
                // Reachable/targeted INT3 is a real trap instruction.
            }

            if let Some(ps) = pad_start.take() {
                pad_runs.push((ps, inst.ip()));
            }
            instructions.push(inst);
        }
        if let Some(ps) = pad_start.take() {
            pad_runs.push((ps, base_va + text_bytes.len() as u64));
        }

        if instructions.is_empty() {
            return Ok((Vec::new(), BidirectionalGraph::new()));
        }

        let text_end_va = base_va + text_bytes.len() as u64;

        // Identify all basic block boundary target IPs
        let mut block_starts = std::collections::BTreeSet::new();
        block_starts.insert(base_va);
        if entry_point_va >= base_va && entry_point_va < text_end_va {
            block_starts.insert(entry_point_va);
        }
        block_starts.extend(
            additional_starts
                .iter()
                .copied()
                .filter(|target| *target >= base_va && *target < text_end_va),
        );

        // CRITICAL FIX: Scan .rdata, .data, .pdata for function pointers and RVA/VA table targets
        // that are referenced only from data sections (e.g. CRT init tables, vtables, SEH scope tables).
        // Adding them to block_starts ensures every indirect function entry becomes a discrete TriggerBlock
        // with an exact match in va_to_trigger_id!
        for sec in relayed_sections {
            if sec.name == ".rdata" || sec.name == ".data" || sec.name == ".pdata" {
                if sec.bytes.len() >= 4 {
                    for off in (0..sec.bytes.len().saturating_sub(3)).step_by(4) {
                        // Check 32-bit RVA
                        let val32 = u32::from_le_bytes(
                            sec.bytes[off..off + 4].try_into().unwrap_or([0; 4]),
                        );
                        let va32 = image_base + val32 as u64;
                        if va32 >= base_va && va32 < text_end_va {
                            block_starts.insert(va32);
                        }

                        // Check 64-bit VA (at 8-byte aligned offsets)
                        if off % 8 == 0 && off + 8 <= sec.bytes.len() {
                            let val64 = u64::from_le_bytes(
                                sec.bytes[off..off + 8].try_into().unwrap_or([0; 8]),
                            );
                            if val64 >= base_va && val64 < text_end_va {
                                block_starts.insert(val64);
                            }
                        }
                    }
                }
            }
        }

        for inst in &instructions {
            match inst.flow_control() {
                FlowControl::UnconditionalBranch
                | FlowControl::ConditionalBranch
                | FlowControl::Call => {
                    let target_ip = inst.near_branch_target();
                    if target_ip >= base_va && target_ip < base_va + text_bytes.len() as u64 {
                        block_starts.insert(target_ip);
                    }
                    let next_ip = inst.ip() + inst.len() as u64;
                    if next_ip < base_va + text_bytes.len() as u64 {
                        block_starts.insert(next_ip);
                    }
                }
                FlowControl::IndirectBranch | FlowControl::IndirectCall => {
                    // CRITICAL: guard-dispatch/check thunks (`jmp qword ptr [rip+__guard_*_fptr]`,
                    // and `jmp rax` tails) are indirect branches. Without a block boundary here
                    // the thunk address is not a block start, so it never lands in
                    // va_to_trigger_id, and resolve_va_to_real_va() falls back to the WRONG
                    // relocated block. In real_win_calc.exe the CRT init loop calls each
                    // initializer through the guard-dispatch thunk chain (fothk 0x2010 ->
                    // jmp 0x1BF0 -> jmp [0x32A8]); with the thunk mis-mapped the call landed on
                    // the relocated __report_gsfailure, which raised STATUS_STACK_BUFFER_OVERRUN
                    // (0xC0000409 / FAST_FAIL_STACK_COOKIE_CHECK_FAILURE) at startup.
                    block_starts.insert(inst.ip());
                    let next_ip = inst.ip() + inst.len() as u64;
                    if next_ip < base_va + text_bytes.len() as u64 {
                        block_starts.insert(next_ip);
                    }
                }
                FlowControl::Return => {
                    let next_ip = inst.ip() + inst.len() as u64;
                    if next_ip < base_va + text_bytes.len() as u64 {
                        block_starts.insert(next_ip);
                    }
                }
                _ => {}
            }
        }

        // Re-materialize block boundaries that fell inside 0xCC padding: when a
        // terminator's fall-through IP (e.g. the byte right after `ret`) is 0xCC
        // padding, the padding is skipped and the next real function (e.g. a CRT
        // initializer at 0x1390 that is only referenced from the .rdata init
        // table, never branched to) gets appended to the PREVIOUS block. Its
        // relocated entry then points at the previous function's epilogue
        // (`add rsp,88h; ret`) instead of the function body -> the init loop
        // pops 0x88 bytes and runs garbage -> call 0x0 -> 0xC0000005.
        for (pad_start, first_real) in &pad_runs {
            if *first_real < base_va + text_bytes.len() as u64 && block_starts.contains(pad_start) {
                block_starts.insert(*first_real);
            }
        }

        // Construct Basic Blocks & Successor Edges
        let mut basic_blocks = Vec::new();
        let mut current_block_id = 0u32;
        let mut current_insts = Vec::new();
        let mut current_start_va = base_va;

        for inst in instructions {
            let inst_va = inst.ip();

            if block_starts.contains(&inst_va) && !current_insts.is_empty() {
                let successors = Self::compute_successors(&current_insts);
                basic_blocks.push(BasicBlock {
                    id: current_block_id,
                    start_va: current_start_va,
                    instructions: std::mem::take(&mut current_insts),
                    successor_vas: successors,
                });
                current_block_id += 1;
                current_start_va = inst_va;
            }

            current_insts.push(inst);
        }

        if !current_insts.is_empty() {
            let successors = Self::compute_successors(&current_insts);
            basic_blocks.push(BasicBlock {
                id: current_block_id,
                start_va: current_start_va,
                instructions: current_insts,
                successor_vas: successors,
            });
        }

        let mut graph = BidirectionalGraph::new();
        for bb in &basic_blocks {
            if let Some(last) = bb.instructions.last() {
                match last.flow_control() {
                    FlowControl::UnconditionalBranch => {
                        let target = last.near_branch_target();
                        let target_id = basic_blocks
                            .iter()
                            .find(|b| b.start_va == target)
                            .map(|b| b.id)
                            .unwrap_or(u32::MAX);
                        if target_id != u32::MAX {
                            graph.add_edge(bb.id, target_id, EdgeType::Unconditional, 1);
                        }
                    }
                    FlowControl::ConditionalBranch => {
                        let taken = last.near_branch_target();
                        let fallthrough = last.ip() + last.len() as u64;
                        let taken_id = basic_blocks
                            .iter()
                            .find(|b| b.start_va == taken)
                            .map(|b| b.id)
                            .unwrap_or(u32::MAX);
                        let fallthrough_id = basic_blocks
                            .iter()
                            .find(|b| b.start_va == fallthrough)
                            .map(|b| b.id)
                            .unwrap_or(u32::MAX);

                        if taken_id != u32::MAX {
                            graph.add_edge(bb.id, taken_id, EdgeType::ConditionalTrue, 1);
                        }
                        if fallthrough_id != u32::MAX {
                            graph.add_edge(bb.id, fallthrough_id, EdgeType::ConditionalFalse, 1);
                        }
                    }
                    FlowControl::Call => {
                        let return_site = last.ip() + last.len() as u64;
                        let return_id = basic_blocks
                            .iter()
                            .find(|b| b.start_va == return_site)
                            .map(|b| b.id)
                            .unwrap_or(u32::MAX);
                        if return_id != u32::MAX {
                            graph.add_edge(bb.id, return_id, EdgeType::Call, 1);
                        }
                    }
                    FlowControl::Return => {
                        // Return targets are not easily resolvable statically in a single pass without symbolic exec
                    }
                    _ => {}
                }
            } else if bb.id + 1 < basic_blocks.len() as u32 {
                graph.add_edge(bb.id, bb.id + 1, EdgeType::Unconditional, 1);
            }
        }

        Ok((basic_blocks, graph))
    }

    fn compute_successors(insts: &[Instruction]) -> Vec<u64> {
        let mut successors = Vec::new();
        if let Some(last) = insts.last() {
            match last.flow_control() {
                FlowControl::UnconditionalBranch => {
                    successors.push(last.near_branch_target());
                }
                FlowControl::ConditionalBranch => {
                    successors.push(last.near_branch_target()); // Taken path target
                    successors.push(last.ip() + last.len() as u64); // Fallthrough path target
                }
                FlowControl::Call => {
                    successors.push(last.ip() + last.len() as u64); // Return site
                }
                _ => {}
            }
        }
        successors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reachable_int3_is_preserved() {
        let bytes = [0xCC, 0xC3]; // int3; ret
        let (blocks, _) = CfgExtractor::extract(&bytes, 0x1000, 0x1000, &[], 0).unwrap();
        assert_eq!(blocks[0].instructions[0].code(), Code::Int3);
    }

    #[test]
    fn branch_targeted_int3_is_preserved() {
        let bytes = [0xEB, 0x01, 0xC3, 0xCC, 0xC3]; // jmp +1 -> int3
        let (blocks, _) = CfgExtractor::extract(&bytes, 0x1000, 0x1000, &[], 0).unwrap();
        assert!(blocks
            .iter()
            .flat_map(|b| &b.instructions)
            .any(|inst| inst.ip() == 0x1003 && inst.code() == Code::Int3));
    }

    #[test]
    fn terminal_alignment_int3_run_is_padding() {
        let bytes = [0xC3, 0xCC, 0xCC, 0x90, 0xC3];
        let (blocks, _) = CfgExtractor::extract(&bytes, 0x1000, 0x1000, &[], 0).unwrap();
        assert!(!blocks
            .iter()
            .flat_map(|b| &b.instructions)
            .any(|inst| inst.code() == Code::Int3));
    }
}
