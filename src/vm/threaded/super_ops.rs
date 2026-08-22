// ==============================================================================
// BTG - Commercial-Grade VM: Super-Operator Fusion Synthesizer
// ==============================================================================
// 빈번하게 연속 실행되는 마이크로 연산 패턴(예: POP + ADD + PUSH, READ + XOR + WRITE)을
// 감지하여 단 하나의 거대한 네이티브 복합 핸들러(Super-Operator)로 융합한다.
// 디스패치 경계를 완전히 지워 분석 도구의 슬라이싱을 무력화한다.
// ==============================================================================

use crate::vm::poly::{PolymorphicEncoder, VirtualIsaSpec};
use crate::vm::risc::{MicroInstr, MicroOperand, RiscOp};
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FusedPattern {
    /// Pop -> AddWithCarry -> Push
    PopAddPush,
    /// MemoryRead -> Nor -> MemoryWrite
    ReadNorWrite,
    /// Pop -> Nor -> Push
    PopNorPush,
}

pub struct SuperOperatorSynthesizer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperOpCandidate {
    pub ops: Vec<RiscOp>,
    pub occurrences: usize,
    pub first_index: usize,
    /// Dispatches removed if every non-overlapping occurrence is fused.
    pub estimated_dispatch_savings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperOpOccurrence {
    pub start: usize,
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperOpPlan {
    pub candidate: SuperOpCandidate,
    pub occurrences: Vec<SuperOpOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperOpIndexMap {
    /// Original instruction index to rewritten instruction index. Instructions
    /// consumed by one super-op all map to its single replacement index.
    pub old_to_new: Vec<usize>,
    pub rewritten_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedSuperOp {
    /// Build-local opcode byte. It is deliberately absent from the canonical
    /// RiscOp map and is meaningful only with this build's extension table.
    pub opcode: u8,
    pub plan: SuperOpPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuperOpStreamInstr {
    Primitive(MicroInstr),
    Fused { opcode: u8, body: Vec<MicroInstr> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperOpRewrite {
    pub instrs: Vec<SuperOpStreamInstr>,
    pub index_map: SuperOpIndexMap,
}

#[derive(Debug, Clone)]
pub struct SuperOpBuildMetadata {
    pub source_program: crate::vm::risc::RiscProgram,
    /// One entry per original instruction. Fused body members intentionally
    /// share their replacement instruction's byte offset.
    pub original_byte_offsets: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct PreparedSuperOpProgram {
    pub bytecode: Vec<u8>,
    pub rewritten_offsets: Vec<usize>,
    pub assigned: Vec<AssignedSuperOp>,
    pub metadata: SuperOpBuildMetadata,
}

impl SuperOpBuildMetadata {
    pub fn from_rewrite(
        source_program: crate::vm::risc::RiscProgram,
        rewrite: &SuperOpRewrite,
        rewritten_offsets: &[usize],
        bytecode_len: usize,
    ) -> anyhow::Result<Self> {
        if source_program.instrs.len() != rewrite.index_map.old_to_new.len()
            || rewritten_offsets.len() != rewrite.index_map.rewritten_len
        {
            return Err(anyhow::anyhow!(
                "super-op metadata cardinality mismatch: source={} old-map={} offsets={} rewritten={}",
                source_program.instrs.len(),
                rewrite.index_map.old_to_new.len(),
                rewritten_offsets.len(),
                rewrite.index_map.rewritten_len
            ));
        }
        let mut original_byte_offsets = Vec::with_capacity(source_program.instrs.len());
        for &rewritten_index in &rewrite.index_map.old_to_new {
            let offset = *rewritten_offsets.get(rewritten_index).ok_or_else(|| {
                anyhow::anyhow!("super-op rewritten index {rewritten_index} is out of range")
            })?;
            if offset >= bytecode_len {
                return Err(anyhow::anyhow!(
                    "super-op byte offset {offset:#x} exceeds stream length {bytecode_len:#x}"
                ));
            }
            original_byte_offsets.push(offset);
        }
        Ok(Self {
            source_program,
            original_byte_offsets,
        })
    }
}

impl SuperOperatorSynthesizer {
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn is_fusion_barrier(op: RiscOp) -> bool {
        matches!(
            op,
            RiscOp::VirtualBranch { .. }
                | RiscOp::VirtualRet
                | RiscOp::NativeCallBridge
                | RiscOp::VmCallBridge
                | RiscOp::Halt
        )
    }

    /// Initial production allow-list. These handlers have ordinary operand
    /// records and dispatch-only exits, making body chaining auditable. Wider
    /// and memory/atomic/bridge operations remain canonical until dedicated
    /// differential coverage promotes them.
    fn is_production_fusable(op: RiscOp) -> bool {
        matches!(
            op,
            RiscOp::Nor
                | RiscOp::AddWithCarry
                | RiscOp::ShiftRight
                | RiscOp::ArithmeticShiftRight
                | RiscOp::ShiftLeft
                | RiscOp::Mov
        )
    }

    /// Analyze build-local hot sequences without crossing control-flow or call
    /// boundaries. Results are deterministic: savings, frequency, sequence
    /// length and first occurrence form the stable ranking key.
    pub fn hot_sequences(
        instrs: &[MicroInstr],
        min_len: usize,
        max_len: usize,
        min_occurrences: usize,
    ) -> Vec<SuperOpCandidate> {
        if min_len < 2 || min_len > max_len || instrs.len() < min_len {
            return Vec::new();
        }
        let mut counts: HashMap<Vec<RiscOp>, (usize, usize)> = HashMap::new();
        for len in min_len..=max_len.min(instrs.len()) {
            for start in 0..=instrs.len() - len {
                let slice = &instrs[start..start + len];
                if slice.iter().any(|ins| {
                    Self::is_fusion_barrier(ins.op) || !Self::is_production_fusable(ins.op)
                }) {
                    continue;
                }
                let ops: Vec<RiscOp> = slice.iter().map(|ins| ins.op).collect();
                let entry = counts.entry(ops).or_insert((0, start));
                entry.0 += 1;
            }
        }
        let mut out: Vec<_> = counts
            .into_iter()
            .filter(|(_, (count, _))| *count >= min_occurrences)
            .map(|(ops, (occurrences, first_index))| {
                let estimated_dispatch_savings = occurrences * (ops.len() - 1);
                SuperOpCandidate {
                    ops,
                    occurrences,
                    first_index,
                    estimated_dispatch_savings,
                }
            })
            .collect();
        out.sort_by(|a, b| {
            b.estimated_dispatch_savings
                .cmp(&a.estimated_dispatch_savings)
                .then_with(|| b.occurrences.cmp(&a.occurrences))
                .then_with(|| b.ops.len().cmp(&a.ops.len()))
                .then_with(|| a.first_index.cmp(&b.first_index))
        });
        out
    }

    /// Select concrete, non-overlapping occurrences for build-local super-ops.
    /// A protected instruction may begin a fused window, but may never occur in
    /// its interior: branch destinations must remain independently addressable.
    pub fn plan_hot_sequences(
        instrs: &[MicroInstr],
        protected_indices: &HashSet<usize>,
        min_len: usize,
        max_len: usize,
        min_occurrences: usize,
        max_superops: usize,
        seed: u64,
    ) -> Vec<SuperOpPlan> {
        let mut candidates = Self::hot_sequences(instrs, min_len, max_len, min_occurrences);
        candidates.sort_by(|a, b| {
            b.estimated_dispatch_savings
                .cmp(&a.estimated_dispatch_savings)
                .then_with(|| b.occurrences.cmp(&a.occurrences))
                .then_with(|| {
                    let rank = |candidate: &SuperOpCandidate| {
                        let mut hasher = DefaultHasher::new();
                        candidate.ops.hash(&mut hasher);
                        hasher.finish() ^ seed
                    };
                    rank(a).cmp(&rank(b))
                })
                .then_with(|| a.first_index.cmp(&b.first_index))
        });

        let mut occupied = vec![false; instrs.len()];
        let mut plans = Vec::new();
        for mut candidate in candidates {
            if plans.len() == max_superops {
                break;
            }
            let len = candidate.ops.len();
            let mut occurrences = Vec::new();
            for start in 0..=instrs.len().saturating_sub(len) {
                if instrs[start..start + len]
                    .iter()
                    .map(|ins| ins.op)
                    .ne(candidate.ops.iter().copied())
                    || (start + 1..start + len).any(|index| protected_indices.contains(&index))
                    || occupied[start..start + len].iter().any(|used| *used)
                {
                    continue;
                }
                occupied[start..start + len].fill(true);
                occurrences.push(SuperOpOccurrence { start, len });
            }
            if occurrences.len() < min_occurrences {
                for occurrence in &occurrences {
                    occupied[occurrence.start..occurrence.start + occurrence.len].fill(false);
                }
                continue;
            }
            candidate.occurrences = occurrences.len();
            candidate.first_index = occurrences[0].start;
            candidate.estimated_dispatch_savings = occurrences.len() * (len - 1);
            plans.push(SuperOpPlan {
                candidate,
                occurrences,
            });
        }
        plans
    }

    /// Build the address-translation contract used when bytecode is compacted.
    /// Plans must be disjoint and in bounds; accepting malformed plans here
    /// would silently corrupt branch-map offsets later in the native builder.
    pub fn build_index_map(
        instr_count: usize,
        plans: &[SuperOpPlan],
    ) -> anyhow::Result<SuperOpIndexMap> {
        let mut fused_len_at = vec![0usize; instr_count];
        let mut consumed = vec![false; instr_count];
        for occurrence in plans.iter().flat_map(|plan| &plan.occurrences) {
            let end = occurrence
                .start
                .checked_add(occurrence.len)
                .ok_or_else(|| anyhow::anyhow!("super-op occurrence range overflow"))?;
            if occurrence.len < 2 || end > instr_count {
                return Err(anyhow::anyhow!(
                    "invalid super-op occurrence [{}..{}) for {instr_count} instructions",
                    occurrence.start,
                    end
                ));
            }
            if consumed[occurrence.start..end].iter().any(|used| *used) {
                return Err(anyhow::anyhow!(
                    "overlapping super-op occurrence [{}..{})",
                    occurrence.start,
                    end
                ));
            }
            consumed[occurrence.start..end].fill(true);
            fused_len_at[occurrence.start] = occurrence.len;
        }

        let mut old_to_new = vec![0usize; instr_count];
        let mut old = 0usize;
        let mut new = 0usize;
        while old < instr_count {
            let len = fused_len_at[old];
            if len == 0 {
                old_to_new[old] = new;
                old += 1;
            } else {
                old_to_new[old..old + len].fill(new);
                old += len;
            }
            new += 1;
        }
        Ok(SuperOpIndexMap {
            old_to_new,
            rewritten_len: new,
        })
    }

    /// Allocate collision-free, seed-diversified extension opcodes without
    /// changing the canonical ISA. The returned opcode order corresponds to
    /// the supplied plan order and therefore forms a compact build-local ABI.
    pub fn assign_extension_opcodes(
        spec: &VirtualIsaSpec,
        plans: &[SuperOpPlan],
        seed: u64,
    ) -> anyhow::Result<Vec<AssignedSuperOp>> {
        let mut free: Vec<u8> = (u8::MIN..=u8::MAX)
            .filter(|byte| !spec.reverse_opcode_map.contains_key(byte))
            .collect();
        if plans.len() > free.len() {
            return Err(anyhow::anyhow!(
                "super-op extension needs {} opcodes but only {} ISA slots are free",
                plans.len(),
                free.len()
            ));
        }

        let mut rng_state = seed ^ 0x5355_5045_524F_5053;
        for i in (1..free.len()).rev() {
            let j = (Self::splitmix64(&mut rng_state) as usize) % (i + 1);
            free.swap(i, j);
        }
        Ok(plans
            .iter()
            .cloned()
            .zip(free)
            .map(|(plan, opcode)| AssignedSuperOp { opcode, plan })
            .collect())
    }

    /// Rewrite selected occurrences into an explicit extension stream. Fused
    /// bodies retain complete MicroInstr operands so a native handler generator
    /// can consume the same semantic input as the primitive handlers.
    pub fn rewrite_stream(
        instrs: &[MicroInstr],
        assigned: &[AssignedSuperOp],
    ) -> anyhow::Result<SuperOpRewrite> {
        let plans: Vec<_> = assigned.iter().map(|item| item.plan.clone()).collect();
        let index_map = Self::build_index_map(instrs.len(), &plans)?;
        let mut starts: HashMap<usize, (&AssignedSuperOp, usize)> = HashMap::new();
        for item in assigned {
            for occurrence in &item.plan.occurrences {
                if occurrence.len != item.plan.candidate.ops.len() {
                    return Err(anyhow::anyhow!(
                        "super-op at {} has length {}, candidate requires {}",
                        occurrence.start,
                        occurrence.len,
                        item.plan.candidate.ops.len()
                    ));
                }
                let actual = &instrs[occurrence.start..occurrence.start + occurrence.len];
                if actual
                    .iter()
                    .map(|ins| ins.op)
                    .ne(item.plan.candidate.ops.iter().copied())
                {
                    return Err(anyhow::anyhow!(
                        "super-op candidate does not match instructions at {}",
                        occurrence.start
                    ));
                }
                starts.insert(occurrence.start, (item, occurrence.len));
            }
        }

        let mut rewritten = Vec::with_capacity(index_map.rewritten_len);
        let mut index = 0usize;
        while index < instrs.len() {
            if let Some((item, len)) = starts.get(&index) {
                rewritten.push(SuperOpStreamInstr::Fused {
                    opcode: item.opcode,
                    body: instrs[index..index + *len].to_vec(),
                });
                index += *len;
            } else {
                rewritten.push(SuperOpStreamInstr::Primitive(instrs[index].clone()));
                index += 1;
            }
        }
        if rewritten.len() != index_map.rewritten_len {
            return Err(anyhow::anyhow!(
                "super-op rewrite length {} disagrees with index map {}",
                rewritten.len(),
                index_map.rewritten_len
            ));
        }
        Ok(SuperOpRewrite {
            instrs: rewritten,
            index_map,
        })
    }

    /// End-to-end commercial preparation policy. Returns `None` when no pattern
    /// removes at least two dispatches, keeping small/cold programs byte-exact.
    pub fn prepare_commercial_program(
        program: &crate::vm::risc::RiscProgram,
        seed: u64,
    ) -> anyhow::Result<Option<PreparedSuperOpProgram>> {
        let mut protected = HashSet::new();
        if let Some(ip_map) = program.ip_map() {
            protected.extend(ip_map.values().copied());
        }
        for ins in &program.instrs {
            if matches!(ins.op, RiscOp::VirtualBranch { .. }) && ins.src1.is_none() {
                let target = program
                    .ip_map()
                    .and_then(|map| map.get(&ins.imm).copied())
                    .unwrap_or(ins.imm as usize);
                if target < program.instrs.len() {
                    protected.insert(target);
                }
            }
        }
        let plans = Self::plan_hot_sequences(
            &program.instrs,
            &protected,
            2,
            4,
            2,
            4,
            seed ^ 0x5035_434F_4D4D_4552,
        );
        let plans: Vec<_> = plans
            .into_iter()
            .filter(|plan| plan.candidate.estimated_dispatch_savings >= 2)
            .collect();
        if plans.is_empty() {
            return Ok(None);
        }
        let spec = VirtualIsaSpec::from_seed(seed);
        let assigned = Self::assign_extension_opcodes(&spec, &plans, seed)?;
        let rewrite = Self::rewrite_stream(&program.instrs, &assigned)?;
        let mut encoder = PolymorphicEncoder::new(seed);
        let (bytecode, rewritten_offsets) = encoder.encode_superop_rewrite(&rewrite)?;
        let metadata = SuperOpBuildMetadata::from_rewrite(
            program.clone(),
            &rewrite,
            &rewritten_offsets,
            bytecode.len(),
        )?;
        Ok(Some(PreparedSuperOpProgram {
            bytecode,
            rewritten_offsets,
            assigned,
            metadata,
        }))
    }

    fn binary_consumes(op: &MicroInstr, value: &Option<MicroOperand>) -> bool {
        value.is_some() && (op.src1 == *value || op.src2 == *value)
    }

    fn stack_flow_is_valid(pop: &MicroInstr, binary: &MicroInstr, push: &MicroInstr) -> bool {
        Self::binary_consumes(binary, &pop.dst) && binary.dst.is_some() && push.src1 == binary.dst
    }

    /// 마이크로 연산 시퀀스에서 슈퍼 오퍼레이터 패턴 매칭 및 융합
    pub fn find_patterns(instrs: &[MicroInstr]) -> Vec<(usize, FusedPattern)> {
        let mut matches = Vec::new();
        let mut i = 0;
        while i + 2 < instrs.len() {
            let i1 = &instrs[i];
            let i2 = &instrs[i + 1];
            let i3 = &instrs[i + 2];

            // Match Pop -> AddWithCarry -> Push
            if i1.op == RiscOp::VirtualPop
                && i2.op == RiscOp::AddWithCarry
                && i3.op == RiscOp::VirtualPush
                && Self::stack_flow_is_valid(i1, i2, i3)
            {
                matches.push((i, FusedPattern::PopAddPush));
                i += 3;
                continue;
            }

            // Match Pop -> Nor -> Push
            if i1.op == RiscOp::VirtualPop
                && i2.op == RiscOp::Nor
                && i3.op == RiscOp::VirtualPush
                && Self::stack_flow_is_valid(i1, i2, i3)
            {
                matches.push((i, FusedPattern::PopNorPush));
                i += 3;
                continue;
            }

            // MemoryRead -> Nor -> MemoryWrite is safe only when widths and
            // address/value dataflow agree exactly. Merely matching op names can
            // otherwise fuse unrelated loads and stores across different addresses.
            if let (
                RiscOp::MemoryRead { width: read_w },
                RiscOp::Nor,
                RiscOp::MemoryWrite { width: write_w },
            ) = (&i1.op, &i2.op, &i3.op)
            {
                if read_w == write_w
                    && Self::binary_consumes(i2, &i1.dst)
                    && i2.dst.is_some()
                    && i3.src1 == i1.src1
                    && i3.src2 == i2.dst
                {
                    matches.push((i, FusedPattern::ReadNorWrite));
                    i += 3;
                    continue;
                }
            }

            i += 1;
        }

        matches
    }

    /// 융합된 Super-Operator 네이티브 x86-64 핸들러 생성
    pub fn emit_fused_handler(pattern: &FusedPattern, target_va: u64) -> anyhow::Result<Vec<u8>> {
        use super::direct_tail::DirectTailEmitter;
        use iced_x86::{Code, Instruction, MemoryOperand, Register};

        let mut instrs = Vec::new();

        match pattern {
            FusedPattern::PopAddPush => {
                // Pop R10 from virtual stack (RSP), Pop R11, Add R10, R11, Push R10
                // pop r10
                instrs.push(
                    Instruction::with1(Code::Pop_r64, Register::R10)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                // pop r11
                instrs.push(
                    Instruction::with1(Code::Pop_r64, Register::R11)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                // add r10, r11
                instrs.push(
                    Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                // push r10
                instrs.push(
                    Instruction::with1(Code::Push_r64, Register::R10)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
            }
            FusedPattern::PopNorPush => {
                // pop r10
                instrs.push(
                    Instruction::with1(Code::Pop_r64, Register::R10)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                // pop r11
                instrs.push(
                    Instruction::with1(Code::Pop_r64, Register::R11)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                // or r10, r11
                instrs.push(
                    Instruction::with2(Code::Or_rm64_r64, Register::R10, Register::R11)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                // not r10
                instrs.push(
                    Instruction::with1(Code::Not_rm64, Register::R10)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                // push r10
                instrs.push(
                    Instruction::with1(Code::Push_r64, Register::R10)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
            }
            FusedPattern::ReadNorWrite => {
                // Read from [R10], NOR with R11, Write to [R10]
                let mem_op = MemoryOperand::with_base(Register::R10);
                // mov rax, [r10]
                instrs.push(
                    Instruction::with2(Code::Mov_r64_rm64, Register::RAX, mem_op)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                // or rax, r11
                instrs.push(
                    Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::R11)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                // not rax
                instrs.push(
                    Instruction::with1(Code::Not_rm64, Register::RAX)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                // mov [r10], rax
                instrs.push(
                    Instruction::with2(Code::Mov_rm64_r64, mem_op, Register::RAX)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
            }
        }

        // Direct tail-call epilogue
        DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
        DirectTailEmitter::assemble(instrs, target_va)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fused_handler_emission() {
        let pop_add_push =
            SuperOperatorSynthesizer::emit_fused_handler(&FusedPattern::PopAddPush, 0x140001000)
                .unwrap();
        let pop_nor_push =
            SuperOperatorSynthesizer::emit_fused_handler(&FusedPattern::PopNorPush, 0x140001050)
                .unwrap();
        let read_nor_write =
            SuperOperatorSynthesizer::emit_fused_handler(&FusedPattern::ReadNorWrite, 0x1400010A0)
                .unwrap();

        assert!(!pop_add_push.is_empty());
        assert!(!pop_nor_push.is_empty());
        assert!(!read_nor_write.is_empty());
    }

    #[test]
    fn matcher_rejects_broken_stack_dataflow() {
        let instrs = vec![
            MicroInstr::new(RiscOp::VirtualPop).with_dst(MicroOperand::Temp(0)),
            MicroInstr::new(RiscOp::Nor)
                .with_dst(MicroOperand::Temp(1))
                .with_src1(MicroOperand::Temp(2))
                .with_src2(MicroOperand::Temp(3)),
            MicroInstr::new(RiscOp::VirtualPush).with_src1(MicroOperand::Temp(1)),
        ];
        assert!(SuperOperatorSynthesizer::find_patterns(&instrs).is_empty());
    }

    #[test]
    fn matcher_validates_read_nor_write_flow_and_width() {
        let addr = MicroOperand::VReg(4);
        let loaded = MicroOperand::Temp(0);
        let result = MicroOperand::Temp(1);
        let good = vec![
            MicroInstr::new(RiscOp::MemoryRead { width: 8 })
                .with_dst(loaded)
                .with_src1(addr),
            MicroInstr::new(RiscOp::Nor)
                .with_dst(result)
                .with_src1(loaded)
                .with_src2(MicroOperand::VReg(2)),
            MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
                .with_src1(addr)
                .with_src2(result),
        ];
        assert_eq!(
            SuperOperatorSynthesizer::find_patterns(&good),
            vec![(0, FusedPattern::ReadNorWrite)]
        );

        let mut wrong_width = good.clone();
        wrong_width[2].op = RiscOp::MemoryWrite { width: 4 };
        assert!(SuperOperatorSynthesizer::find_patterns(&wrong_width).is_empty());

        let mut wrong_address = good;
        wrong_address[2].src1 = Some(MicroOperand::VReg(5));
        assert!(SuperOperatorSynthesizer::find_patterns(&wrong_address).is_empty());
    }

    #[test]
    fn hot_sequence_analysis_ranks_program_local_patterns() {
        let op = |op| MicroInstr::new(op);
        let instrs = vec![
            op(RiscOp::Nor),
            op(RiscOp::AddWithCarry),
            op(RiscOp::ShiftRight),
            op(RiscOp::Nor),
            op(RiscOp::AddWithCarry),
            op(RiscOp::ShiftRight),
            op(RiscOp::Nor),
            op(RiscOp::AddWithCarry),
            op(RiscOp::ShiftRight),
            op(RiscOp::Halt),
        ];
        let candidates = SuperOperatorSynthesizer::hot_sequences(&instrs, 2, 4, 2);
        assert!(!candidates.is_empty());
        assert_eq!(
            candidates[0].ops,
            vec![RiscOp::Nor, RiscOp::AddWithCarry, RiscOp::ShiftRight]
        );
        assert_eq!(candidates[0].occurrences, 3);
        assert_eq!(candidates[0].estimated_dispatch_savings, 6);
    }

    #[test]
    fn hot_sequence_analysis_never_crosses_control_flow() {
        let op = |op| MicroInstr::new(op);
        let instrs = vec![
            op(RiscOp::Nor),
            op(RiscOp::VirtualBranch {
                cond: crate::vm::risc::BranchCondition::Always,
            }),
            op(RiscOp::Nor),
            op(RiscOp::VirtualBranch {
                cond: crate::vm::risc::BranchCondition::Always,
            }),
        ];
        let candidates = SuperOperatorSynthesizer::hot_sequences(&instrs, 2, 3, 2);
        assert!(candidates.is_empty());
    }

    #[test]
    fn planner_uses_only_non_overlapping_occurrences() {
        let instrs = vec![MicroInstr::new(RiscOp::Nor); 6];
        let plans =
            SuperOperatorSynthesizer::plan_hot_sequences(&instrs, &HashSet::new(), 3, 3, 2, 1, 7);
        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[0].occurrences,
            vec![
                SuperOpOccurrence { start: 0, len: 3 },
                SuperOpOccurrence { start: 3, len: 3 },
            ]
        );
        assert_eq!(plans[0].candidate.occurrences, 2);
        assert_eq!(plans[0].candidate.estimated_dispatch_savings, 4);
    }

    #[test]
    fn planner_preserves_branch_entry_points() {
        let op = |op| MicroInstr::new(op);
        let instrs = vec![
            op(RiscOp::Nor),
            op(RiscOp::AddWithCarry),
            op(RiscOp::ShiftRight),
            op(RiscOp::Nor),
            op(RiscOp::AddWithCarry),
            op(RiscOp::ShiftRight),
            op(RiscOp::Nor),
            op(RiscOp::AddWithCarry),
            op(RiscOp::ShiftRight),
        ];
        let protected = HashSet::from([1usize, 6usize]);
        let plans =
            SuperOperatorSynthesizer::plan_hot_sequences(&instrs, &protected, 3, 3, 2, 1, 11);
        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[0].occurrences,
            vec![
                SuperOpOccurrence { start: 3, len: 3 },
                SuperOpOccurrence { start: 6, len: 3 },
            ]
        );
    }

    #[test]
    fn index_map_tracks_compacted_super_ops() {
        let candidate = SuperOpCandidate {
            ops: vec![RiscOp::Nor, RiscOp::AddWithCarry, RiscOp::ShiftRight],
            occurrences: 2,
            first_index: 1,
            estimated_dispatch_savings: 4,
        };
        let plans = vec![SuperOpPlan {
            candidate,
            occurrences: vec![
                SuperOpOccurrence { start: 1, len: 3 },
                SuperOpOccurrence { start: 5, len: 3 },
            ],
        }];
        let map = SuperOperatorSynthesizer::build_index_map(9, &plans).unwrap();
        assert_eq!(map.old_to_new, vec![0, 1, 1, 1, 2, 3, 3, 3, 4]);
        assert_eq!(map.rewritten_len, 5);
    }

    #[test]
    fn index_map_rejects_overlapping_plans() {
        let candidate = SuperOpCandidate {
            ops: vec![RiscOp::Nor, RiscOp::Nor],
            occurrences: 2,
            first_index: 0,
            estimated_dispatch_savings: 2,
        };
        let plans = vec![SuperOpPlan {
            candidate,
            occurrences: vec![
                SuperOpOccurrence { start: 0, len: 2 },
                SuperOpOccurrence { start: 1, len: 2 },
            ],
        }];
        assert!(SuperOperatorSynthesizer::build_index_map(4, &plans).is_err());
    }

    #[test]
    fn extension_opcodes_are_deterministic_and_collision_free() {
        let instrs = vec![
            MicroInstr::new(RiscOp::Nor),
            MicroInstr::new(RiscOp::AddWithCarry),
            MicroInstr::new(RiscOp::Nor),
            MicroInstr::new(RiscOp::AddWithCarry),
        ];
        let plans = SuperOperatorSynthesizer::plan_hot_sequences(
            &instrs,
            &HashSet::new(),
            2,
            2,
            2,
            1,
            0x1234,
        );
        let spec = VirtualIsaSpec::from_seed(0x1234);
        let a = SuperOperatorSynthesizer::assign_extension_opcodes(&spec, &plans, 0x5678).unwrap();
        let b = SuperOperatorSynthesizer::assign_extension_opcodes(&spec, &plans, 0x5678).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 1);
        assert!(!spec.reverse_opcode_map.contains_key(&a[0].opcode));
    }

    #[test]
    fn extension_opcode_assignment_changes_with_seed() {
        let candidate = SuperOpCandidate {
            ops: vec![RiscOp::Nor, RiscOp::Nor],
            occurrences: 1,
            first_index: 0,
            estimated_dispatch_savings: 1,
        };
        let plans = vec![SuperOpPlan {
            candidate,
            occurrences: vec![SuperOpOccurrence { start: 0, len: 2 }],
        }];
        let spec = VirtualIsaSpec::from_seed(99);
        let a = SuperOperatorSynthesizer::assign_extension_opcodes(&spec, &plans, 1).unwrap();
        let b = SuperOperatorSynthesizer::assign_extension_opcodes(&spec, &plans, 2).unwrap();
        assert_ne!(a[0].opcode, b[0].opcode);
    }

    #[test]
    fn rewrite_stream_preserves_full_instruction_bodies() {
        let instrs = vec![
            MicroInstr::new(RiscOp::Nor)
                .with_dst(MicroOperand::Temp(0))
                .with_src1(MicroOperand::VReg(1))
                .with_src2(MicroOperand::VReg(2)),
            MicroInstr::new(RiscOp::AddWithCarry)
                .with_dst(MicroOperand::Temp(1))
                .with_src1(MicroOperand::Temp(0))
                .with_src2(MicroOperand::Imm64(9)),
            MicroInstr::new(RiscOp::Halt),
        ];
        let plan = SuperOpPlan {
            candidate: SuperOpCandidate {
                ops: vec![RiscOp::Nor, RiscOp::AddWithCarry],
                occurrences: 1,
                first_index: 0,
                estimated_dispatch_savings: 1,
            },
            occurrences: vec![SuperOpOccurrence { start: 0, len: 2 }],
        };
        let assigned = vec![AssignedSuperOp { opcode: 0xA5, plan }];
        let rewrite = SuperOperatorSynthesizer::rewrite_stream(&instrs, &assigned).unwrap();
        assert_eq!(rewrite.index_map.old_to_new, vec![0, 0, 1]);
        assert_eq!(rewrite.instrs.len(), 2);

        let flattened: Vec<MicroInstr> = rewrite
            .instrs
            .into_iter()
            .flat_map(|item| match item {
                SuperOpStreamInstr::Primitive(ins) => vec![ins],
                SuperOpStreamInstr::Fused { body, .. } => body,
            })
            .collect();
        assert_eq!(flattened, instrs);
    }

    #[test]
    fn rewrite_stream_rejects_stale_candidate() {
        let instrs = vec![
            MicroInstr::new(RiscOp::Nor),
            MicroInstr::new(RiscOp::ShiftLeft),
        ];
        let assigned = vec![AssignedSuperOp {
            opcode: 7,
            plan: SuperOpPlan {
                candidate: SuperOpCandidate {
                    ops: vec![RiscOp::Nor, RiscOp::ShiftRight],
                    occurrences: 1,
                    first_index: 0,
                    estimated_dispatch_savings: 1,
                },
                occurrences: vec![SuperOpOccurrence { start: 0, len: 2 }],
            },
        }];
        assert!(SuperOperatorSynthesizer::rewrite_stream(&instrs, &assigned).is_err());
    }

    #[test]
    fn commercial_preparation_skips_cold_programs() {
        let program = crate::vm::risc::RiscProgram::new(vec![
            MicroInstr::new(RiscOp::Nor),
            MicroInstr::new(RiscOp::ShiftRight),
            MicroInstr::new(RiscOp::Halt),
        ]);
        assert!(
            SuperOperatorSynthesizer::prepare_commercial_program(&program, 7)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn commercial_preparation_builds_profitable_extension() {
        let program = crate::vm::risc::RiscProgram::new(vec![
            MicroInstr::new(RiscOp::Nor),
            MicroInstr::new(RiscOp::ShiftRight),
            MicroInstr::new(RiscOp::Nor),
            MicroInstr::new(RiscOp::ShiftRight),
            MicroInstr::new(RiscOp::Halt),
        ]);
        let prepared = SuperOperatorSynthesizer::prepare_commercial_program(&program, 9)
            .unwrap()
            .unwrap();
        assert!(!prepared.assigned.is_empty());
        assert_eq!(prepared.metadata.original_byte_offsets.len(), 5);
        assert!(prepared.bytecode.len() > 1);
    }
}
