// ==============================================================================
// BTG (Bidirectional Trigger Graph) - 2-Pass Micro-Slicing Engine (Pass 1)
// ==============================================================================

use crate::core::trigger_block::{TriggerBlock, EntryPointInfo, EntryPointType, CpuState};
use crate::graph::cfg::BasicBlock;
use crate::mba::MbaGenerator;
use anyhow::Result;
use iced_x86::{Code, FlowControl, Instruction, Register};
use std::collections::{HashMap, BTreeMap, HashSet};

pub struct MicroSlicer {
    max_chunk_size: usize,
    obf_level: usize,
    mba_constant: u32,
    /// v10: 디스패처 스택 규약 선택.
    ///   true  = 재암호화 디스패처 3-푸시 규약 [seed][target_id][current_id]
    ///   false = 일반 디스패처 2-푸시 규약   [seed][target_id]
    /// FIX(v10): v8에서 모든 스텁을 3-푸시로 바꿨지만 일반 디스패처는 2슬롯만
    /// 소비(lea rsp,[rsp+8] + ret)해서, 일반 모드에서 디스패치마다 8바이트가
    /// 스택에 남아 타깃 블록의 RSP가 원본보다 8 낮아졌다. (ret 종단 블록이
    /// 가비지를 pop → 크래시, SSE 16B 정렬 붕괴)
    reencrypt: bool,
}

impl MicroSlicer {
    pub fn new(max_chunk_size: usize, obf_level: usize, mba_constant: u32, reencrypt: bool) -> Self {
        Self {
            max_chunk_size,
            obf_level,
            mba_constant,
            reencrypt,
        }
    }

    /// Pass 1: Slices basic blocks into Trigger Blocks containing raw Instruction lists (2-Pass Engine)
    pub fn slice_blocks(
        &self,
        basic_blocks: &[BasicBlock],
        dispatcher_va: u64,
        text_start_va: u64,
        text_end_va: u64,
    ) -> Result<(Vec<TriggerBlock>, BTreeMap<u64, u32>, HashSet<u32>)> {

        let mut draft_blocks = Vec::new();
        let mut va_to_trigger_id = BTreeMap::new();
        let mut next_trigger_id = 0u32;

        // --------------------------------------------------------------------------
        // PASS A: Actual Chunking & Exact VA -> Trigger ID Mapping Construction
        // -------------------------------------------------------------------------
        for bb in basic_blocks {
            let mut chunk = Vec::new();
            let mut first_block_for_bb = true;

            for (idx, inst) in bb.instructions.iter().enumerate() {
                let current_inst = *inst;
                let is_last_inst = idx == bb.instructions.len() - 1;
                let flow = current_inst.flow_control();

                // Map every instruction's original IP to the current trigger_id
                // This ensures branch targets pointing anywhere inside a sliced block resolve correctly!
                va_to_trigger_id.entry(current_inst.ip()).or_insert(next_trigger_id);
                if first_block_for_bb {
                    va_to_trigger_id.entry(bb.start_va).or_insert(next_trigger_id);
                    first_block_for_bb = false;
                }


                chunk.push(current_inst);

                if is_last_inst {
                    let tb = TriggerBlock::new(next_trigger_id);

                    draft_blocks.push((
                        tb,
                        std::mem::take(&mut chunk),
                        is_last_inst,
                        flow,
                        current_inst,
                        next_trigger_id,
                    ));

                    next_trigger_id += 1;
                }
            }
        }


        // ---------------------------------------------------------------------------
        // v11: 직접 call 타깃 블록 수집 (재암호화 모드 평문 유지 대상)
        // ---------------------------------------------------------------------------
        // 기본 블록의 call 명령 중 .text 내부 블록 진입점을 가리키는 것을 수집한다.
        // 재암호화 디스패처는 디스패치된 블록만 복호화하므로, call로 직접 실행되는
        // 블록이 암호문 상태로 남으면 0xC0000096 (privileged instruction) 크래시가
        // 발생한다 (full.exe Block 3920 재현). 이 집합의 블록은 암호화되지 않고
        // 디스패처가 길이 0 센티널로 암호화/복호화를 건너뛴다.
        let mut call_target_block_ids: HashSet<u32> = HashSet::new();
        for bb in basic_blocks {
            for inst in &bb.instructions {
                if inst.flow_control() == FlowControl::Call {
                    let tgt = inst.near_branch_target();
                    // FIX(v12.3): exact match 실패 시 포함 관계로 해석 — 선형
                    // 디스어셈블 정렬 문제 등으로 call 타깃이 블록 내부 명령을
                    // 가리키면 그 블록도 call-target(평문)으로 유지한다.
                    // (0xC000001D call-into-ciphertext 크래시 — 실측: 직접 call
                    //  타깃 1건 누락 → 해당 블록이 암호문인 채 실행됨)
                    let id = Self::resolve_target_id(
                        &va_to_trigger_id,
                        tgt,
                        0,
                        text_start_va,
                        text_end_va,
                    )
                    .or_else(|| {
                        Self::resolve_target_id_contained(
                            &va_to_trigger_id,
                            tgt,
                            text_start_va,
                            text_end_va,
                        )
                    });
                    if let Some(id) = id {
                        call_target_block_ids.insert(id);
                    }
                }
            }
        }

        // ---------------------------------------------------------------------------
        // PASS B: Branch Target Resolution & Dispatcher Stub Generation
        // --------------------------------------------------------------------------
        let mut trigger_blocks = Vec::with_capacity(draft_blocks.len());

        for (mut tb, mut chunk, is_last_inst, flow, current_inst, block_id) in draft_blocks {
            let cpu_state = CpuState {
                registers: HashMap::new(),
                flags: 0,
                stack_delta: 0,
            };

            tb.add_entry_point(EntryPointInfo {
                offset: 0,
                entry_type: EntryPointType::Normal,
                cpu_state: cpu_state.clone(),
                execution_path: vec![block_id],
            }).unwrap_or_default();

            // Overlapping entry points (+1 offset) are disabled to guarantee 100% EFLAGS preservation.
            // Opcode 0x02 (ADD) at +1 offset mutated CPU flags (ZF/SF/CF), corrupting conditional branches.
            let enable_overlap = false;
            if enable_overlap {
                tb.add_entry_point(EntryPointInfo {
                    offset: 1,
                    entry_type: EntryPointType::Misaligned(1),
                    cpu_state,
                    execution_path: vec![block_id, block_id + 1],
                }).unwrap_or_default();
            }

            let is_terminal = is_last_inst && matches!(flow, FlowControl::Return | FlowControl::IndirectBranch);

            // v14 FIX: 터미널 블록(ret/간접분기 종단)도 평문 유지 대상에 추가한다.
            // 재암호화 디스패처는 디스패치할 때마다 타깃 블록을 복호화하지만, 터미널
            // 블록은 실행 후 디스패처로 돌아가지 않고 `ret`/간접점프로 복귀하므로
            // 다시 암호화되지 않는다. 따라서 같은 터미널 블록이 두 번째 디스패치되면
            // 이미 평문인 블록을 한 번 더 XOR → 암호문으로 되돌아가 실행 → 크래시.
            // (rbt_full.exe 0xC0000005 @ 0x56769 — Block 4284 `mov rax,[rsp+38h]...ret`
            //  함수 에필로그가 2회 이상 디스패치되며 재현)
            if is_terminal {
                call_target_block_ids.insert(block_id as u32);
            }

            // GS 루틴 판정:
            // - `mov [..], 0xC0000409`(GS failure 킋업) 는 `cmp rcx, r/m64`(쿠키 검삩) 블라'd GS 루틴으로 간주.
            // - 단, 조건 분기(jcc)로 끝나닔 블라'` 제외한다. jcc는 아래 분기 스텁 생성 단계에서
            //   `chunk.pop()`으로 제거되는데, 여기서 `ret`을 먼저 추가하면 pop이 추가된 `ret`을
            //   지워 원본 jcc가 그대로 남는 double-jcc 구조가 되어, 두 분기 타깃이 우연히 같은
            //   목적지로 재배치될 때만 동작하는 비결정적 코드가 만들어진다.
            let is_gs_routine = !(is_last_inst && matches!(flow, FlowControl::ConditionalBranch))
                && chunk.iter().any(|inst| {
                    (inst.code() == Code::Mov_rm32_imm32 && inst.immediate32() == 0xC0000409)
                        || (inst.code() == Code::Cmp_r64_rm64
                            && inst.op0_register() == iced_x86::Register::RCX
                            // MSVC GS 쿠키 비교는 항상 [rsp+imm]/[rbp+imm] 스택 슬롯을 대상으로 한다.
                            // 레지스터-인덱스 메모리 비교(예: `cmp rcx,[rbx+10h]`)는 일반 벡터/컨테이너
                            // 코드이므로 GS 루틴으로 오판하면 안 된다 -> 가짜 `ret` 삽입 금지.
                            // (charmap 0xC0000005 @ .data+0xF8 근본 원인: 블록 2696이 이 오판으로 가짜
                            //  ret를 얻어 해제되지 않은 wrapper 프레임을 pop한 뒤 .data로 점프)
                            && inst.op1_kind() == iced_x86::OpKind::Memory
                            && matches!(inst.memory_base(),
                                iced_x86::Register::RSP | iced_x86::Register::RBP))
                });

            if is_gs_routine {
                let last_code = chunk.last().map(|inst| inst.code());
                if last_code != Some(Code::Retnq) && last_code != Some(Code::Jmp_rel32_64) && last_code != Some(Code::Jmp_rm64) {
                    chunk.push(Instruction::with(Code::Retnq));
                    // v14: 가짜 ret를 삽입한 GS 블록도 디스패처 스텁 없이 종단된다 —
                    // 재암호화 디스패처의 이중 복호화 방지를 위해 평문 유지 대상에 추가.
                    call_target_block_ids.insert(block_id as u32);
                }
            }

            if is_last_inst && matches!(flow, FlowControl::ConditionalBranch) {
                // Remove the raw conditional branch instruction pushed in PASS A (since we replace it with jcc_inst + stubs)
                chunk.pop();

                let taken_target_va = current_inst.near_branch_target();
                let fallthrough_va = current_inst.ip() + current_inst.len() as u64;

                let taken_id = Self::resolve_target_id(&va_to_trigger_id, taken_target_va, block_id, text_start_va, text_end_va);
                let fall_id = Self::resolve_target_id(&va_to_trigger_id, fallthrough_va, block_id, text_start_va, text_end_va);
                let taken_is_trigger = taken_id.is_some();
                let fall_is_trigger = fall_id.is_some();

                // Dispatcher stub: push [current_id?][target_id][seed] + jmp dispatcher.
                // v8(Phase 0.3): 재암호화 디스패처 3-푸시 규약 — [seed][target_id][current_id].
                // current_id(자기 자신)는 디스패처가 '직전 블록'을 재암호화하는 데 쓰인다.
                // v10 FIX: 일반 디스패처는 2-푸시 규약이므로 current_id push를 생략한다
                // (남으면 디스패치마다 8B 스택 누수 → RSP 8바이트 어긋남).
                let push_dispatch_stub = |chunk: &mut Vec<Instruction>, target: u32| -> anyhow::Result<usize> {
                    let stub_idx = chunk.len();
                    if self.reencrypt {
                        chunk.push(Instruction::with1(Code::Pushq_imm32, block_id as i32)?);
                    }
                    chunk.push(Instruction::with1(Code::Pushq_imm32, target as i32)?);
                    let seed = MbaGenerator::seed_for(self.mba_constant, target);
                    chunk.push(Instruction::with1(Code::Pushq_imm32, seed as i32)?);
                    chunk.push(Instruction::with_branch(Code::Jmp_rel32_64, dispatcher_va)?);
                    Ok(stub_idx)
                };

                let jcc_inst_idx = chunk.len();
                // as_near_branch() mutates in-place (&mut self -> ()) in iced-x86 v1.21.
                // Clone current_inst, then mutate the clone to near-branch form.
                let mut jcc_inst = current_inst;
                jcc_inst.as_near_branch();
                // Placeholder target for size measurement in prep-loop:
                // Jcc near (rel32) = 6 bytes
                // Fallthrough stub = 2~3×push(10~15) + jmp(5) = 15~20 bytes
                // (rel32 jcc는 타깃과 무관하게 항상 6바이트 — pass3가 실제 IP로 재설정)
                if taken_is_trigger && fall_is_trigger {
                    // Both targets dispatch (original behavior).
                    let target_taken_id = taken_id.unwrap();
                    let target_fallthrough_id = fall_id.unwrap();
                    jcc_inst.set_near_branch64(current_inst.ip() + 26);
                    chunk.push(jcc_inst);
                    push_dispatch_stub(&mut chunk, target_fallthrough_id)?;
                    let taken_stub_idx = push_dispatch_stub(&mut chunk, target_taken_id)?;
                    tb.jcc_info = Some((jcc_inst_idx, taken_stub_idx));
                } else if taken_is_trigger {
                    // Fall target is NATIVE (SEH-excluded function): jcc taken →
                    // dispatcher stub; not-taken falls to the original .text address.
                    let target_taken_id = taken_id.unwrap();
                    jcc_inst.set_near_branch64(current_inst.ip() + 26);
                    chunk.push(jcc_inst);
                    chunk.push(Instruction::with_branch(Code::Jmp_rel32_64, fallthrough_va)?);
                    let taken_stub_idx = push_dispatch_stub(&mut chunk, target_taken_id)?;
                    tb.jcc_info = Some((jcc_inst_idx, taken_stub_idx));
                } else if fall_is_trigger {
                    // Taken target is NATIVE: jcc keeps its original taken target
                    // (pass3 resolves it to .text); not-taken dispatches to fall.
                    let target_fallthrough_id = fall_id.unwrap();
                    jcc_inst.set_near_branch64(taken_target_va);
                    chunk.push(jcc_inst);
                    push_dispatch_stub(&mut chunk, target_fallthrough_id)?;
                    tb.jcc_info = None;
                } else {
                    // Both targets NATIVE: keep the original jcc + jmp (pass3
                    // resolves both displacements to original .text addresses).
                    jcc_inst.set_near_branch64(taken_target_va);
                    chunk.push(jcc_inst);
                    chunk.push(Instruction::with_branch(Code::Jmp_rel32_64, fallthrough_va)?);
                    tb.jcc_info = None;
                }
            } else if !is_terminal {
                let is_uncond_jmp = is_last_inst && matches!(flow, FlowControl::UnconditionalBranch);
                let target_block_id_opt = if is_last_inst {
                    if is_uncond_jmp {
                        let target_va = current_inst.near_branch_target();
                        let target_id = Self::resolve_target_id(&va_to_trigger_id, target_va, block_id, text_start_va, text_end_va);
                        if target_id.is_some() {
                            chunk.pop(); // Remove raw JMP instruction ONLY if successfully replaced with Dispatcher stub
                        }
                        target_id
                    } else {
                        let fallthrough_va = current_inst.ip() + current_inst.len() as u64;
                        Self::resolve_target_id(&va_to_trigger_id, fallthrough_va, block_id, text_start_va, text_end_va)
                    }
                } else {
                    Self::resolve_target_id(&va_to_trigger_id, current_inst.ip() + current_inst.len() as u64, block_id, text_start_va, text_end_va)
                };

                if let Some(target_block_id) = target_block_id_opt {
                    let seed = MbaGenerator::seed_for(self.mba_constant, target_block_id);
                    // O1: --obf-level 에 따른 키 스케줄 (reencrypt/M7 디스패처는 레벨 2 고정).
                    let level = if self.reencrypt {
                        2
                    } else {
                        self.obf_level.clamp(1, 3)
                    };
                    let key =
                        MbaGenerator::compute_key(seed, target_block_id, self.mba_constant, level);

                    // v10 FIX: current_id push는 재암호화(3-푸시) 모드에서만.
                    if self.reencrypt {
                        chunk.push(Instruction::with1(Code::Pushq_imm32, block_id as i32)?); // current
                    }
                    chunk.push(Instruction::with1(Code::Pushq_imm32, target_block_id as i32)?);
                    chunk.push(Instruction::with1(Code::Pushq_imm32, seed as i32)?);
                    chunk.push(Instruction::with_branch(Code::Jmp_rel32_64, dispatcher_va)?);
                } else if !is_uncond_jmp {
                    // Out-of-bounds fallthrough target for non-JMP block -> emit safe return to caller
                    chunk.push(Instruction::with(Code::Retnq));
                }
            }

            tb.raw_instructions = chunk;
            trigger_blocks.push(tb);
        }

        Ok((trigger_blocks, va_to_trigger_id, call_target_block_ids))
    }

    /// Resolves a target VA a lightweight Trigger Block ID using BTreeMap range search.
    /// Strictly verifies that target_va lies inside original .text section bounds [text_start_va, text_end_va).
    fn resolve_target_id(
        map: &BTreeMap<u64, u32>,
        target_va: u64,
        _current_block_id: u32,
        text_start_va: u64,
        text_end_va: u64,
    ) -> Option<u32> {
        // Target VA must be strictly inside original .text section bounds
        if target_va < text_start_va || target_va >= text_end_va {
            return None;
        }

        if let Some((&_exact_va, &id)) = map.get_key_value(&target_va) {
            return Some(id);
        }

        // Exact match required; do not guess random block IDs from unrelated functions
        None
    }

    /// FIX(v12.3): call 타깃이 블록 내부 명령을 가리킬 때(exact match 실패) 포함
    /// 관계로 해석 — 직전 명령 IP의 트리거 블록이 그 블록이다. (0xC000001D 수정)
    fn resolve_target_id_contained(
        map: &BTreeMap<u64, u32>,
        target_va: u64,
        text_start_va: u64,
        text_end_va: u64,
    ) -> Option<u32> {
        if target_va < text_start_va || target_va >= text_end_va {
            return None;
        }
        map.range(..=target_va).next_back().map(|(_, &id)| id)
    }

}
