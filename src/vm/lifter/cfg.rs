// ==============================================================================
// BTG v24 - x86-64 ??VM Bytecode Lifter: multi-block CFG orchestration
// ==============================================================================
// `lift_block` (single straight-line basic block), `lift_cfg` / `lift_cfg_switch`
// (multi-block control-flow lift with switch jump-table dispatch and panic/
// unwind exclusions), and `diagnose_unsupported` (report which instructions a
// block cannot lift). The single-instruction `lift_one` and the shared infra
// (`vreg`, `SCRATCH`, `SCRATCH2`, `check_scratch_collision`, `is_jcc`, `jcc_cond`,
// `mem_emit`, `has_rip_operand`) live in `super` (mod.rs / mem.rs). These four
// functions are re-exported from mod.rs so `lifter::lift_block` etc. remain the
// public API.
// ==============================================================================

use super::mem::{has_rip_operand, mem_emit};
use super::{
    check_scratch_collision, is_jcc, jcc_cond, lift_one, vreg, LiftedInstr, SCRATCH, SCRATCH2,
};
use crate::vm::bytecode::*;
use anyhow::{Result, anyhow};
use iced_x86::{Code, OpKind, Register};

/// A-5: diagnose which instructions in a block cannot be lifted.
pub fn diagnose_unsupported(seq: &[LiftedInstr]) -> Vec<(String, Code)> {
    let mut bad = Vec::new();
    for it in seq {
        let inst = it.inst;
        let code = inst.code();
        if it.target.is_some() {
            continue;
        }
        if code == Code::Call_rel32_64 || code == Code::Retnq {
            continue;
        }
        if matches!(
            code,
            Code::Jmp_rel32_64 | Code::Jmp_rel8_64
                | Code::Je_rel32_64 | Code::Jne_rel32_64 | Code::Jb_rel32_64
                | Code::Jae_rel32_64 | Code::Jg_rel32_64 | Code::Jge_rel32_64 | Code::Jl_rel32_64
                | Code::Jle_rel32_64 | Code::Js_rel32_64 | Code::Jns_rel32_64 | Code::Jo_rel32_64
                | Code::Jno_rel32_64 | Code::Jp_rel32_64 | Code::Jnp_rel32_64
                | Code::Ja_rel32_64 | Code::Jbe_rel32_64
                | Code::Je_rel8_64 | Code::Jne_rel8_64 | Code::Jb_rel8_64
                | Code::Jae_rel8_64 | Code::Jg_rel8_64 | Code::Jge_rel8_64 | Code::Jl_rel8_64
                | Code::Jle_rel8_64 | Code::Js_rel8_64 | Code::Jns_rel8_64 | Code::Jo_rel8_64
                | Code::Jno_rel8_64 | Code::Jp_rel8_64 | Code::Jnp_rel8_64
                | Code::Ja_rel8_64 | Code::Jbe_rel8_64
                | Code::Jecxz_rel8_64 | Code::Jrcxz_rel8_64
                | Code::Loopne_rel8_64_RCX
        ) {
            continue;
        }
        let mut b = BytecodeBuilder::new();
        if lift_one(&mut b, &inst).is_err() {
            bad.push((inst.to_string(), code));
        }
    }
    bad
}

/// Lift a complete block.
pub fn lift_block(seq: &[LiftedInstr], seq_base_va: u64) -> Result<Vec<u8>> {
    let mut b = BytecodeBuilder::new();
    let mut labels = std::collections::HashMap::new();
    let mut va = seq_base_va;

    for item in seq {
        if let Some(l) = item.label {
            let id = *labels.entry(l).or_insert_with(|| b.new_label());
            b.mark_label(id);
        }

        let inst = item.inst;
        let code = inst.code();

        if crate::vm::mapper::active() {
            crate::vm::mapper::record(b.bytes.len(), &inst, va, "Block");
        }

        if let Some(t) = item.target {
            let id = *labels.entry(t).or_insert_with(|| b.new_label());
            match code {
                Code::Jmp_rel32_64 | Code::Jmp_rel8_64 => b.jmp8(id),
                c if is_jcc(c) => {
                    if c == Code::Loopne_rel8_64_RCX {
                        b.dec_r(1);
                    } else if matches!(c, Code::Jecxz_rel8_64 | Code::Jrcxz_rel8_64) {
                        b.test_r_r32(1, 1);
                    }
                    b.jcc8(jcc_cond(c), id);
                }
                Code::Call_rel32_64 => {
                    b.mov_r_imm64(SCRATCH, va.wrapping_add(inst.len() as u64));
                    b.push_r(SCRATCH);
                    b.call8(id);
                }
                _ => return Err(anyhow!("lifter: unsupported branch {:?}", code)),
            }
            va = va.wrapping_add(inst.len() as u64);
            continue;
        }

        if code == Code::Call_rel32_64 {
            let id = match item.target {
                Some(t) => *labels.entry(t).or_insert_with(|| b.new_label()),
                None => return Err(anyhow!("lifter: CALL requires a target label")),
            };
            b.mov_r_imm64(SCRATCH, va.wrapping_add(inst.len() as u64));
            b.push_r(SCRATCH);
            b.call8(id);
            va = va.wrapping_add(inst.len() as u64);
            continue;
        }

        let inst_va = va;
        let n = inst.len() as u64;
        let had_rip = has_rip_operand(&inst);
        if had_rip {
            b.set_rip(inst_va);
        }
        lift_one(&mut b, &inst)?;
        va = inst_va.wrapping_add(n);
    }

    b.halt();
    // Phase 2.3 (v56): run the assembled stream through the IR pipeline
    // (VInstr + const copy-prop / dead-mov elim / peephole, then re-encode).
    // --map/--sym-map diagnostics (mapper active) keep the legacy byte-exact
    // path so recorded offsets stay valid.
    if crate::vm::mapper::active() {
        Ok(b.try_finish()?)
    } else {
        let (bytes, branches, labels) = b.into_parts();
        super::ir::run_ir_pipeline(&bytes, &branches, &labels)
    }
}

/// M5 (v30) ??multi-block control-flow lift driver.
pub fn lift_cfg(blocks: &[crate::graph::BasicBlock]) -> Result<Vec<u8>> {
    lift_cfg_switch(blocks, &[], &std::collections::HashMap::new(), None, &Default::default(), &[])
}

/// Lift a whole CFG to a single VM program.
///
/// `excluded` = block start VAs kept native (bridged via native_call).
/// `excluded_func_ranges` = the whole `.pdata` function ranges those blocks
/// belong to. When bridging to an excluded block, we must jump to the
/// **function entry** (its prologue), NOT the mid-function block start:
/// calling a mid-function block skips the prologue, so the callee's RSP/frame
/// is wrong and any internal `call` is 8-byte misaligned ??0xC0000005 inside
/// e.g. GetModuleHandleA (--vm-oep boot crash, problem.txt).
pub fn lift_cfg_switch(
    blocks: &[crate::graph::BasicBlock],
    switch_cases: &[(u64, Vec<(i64, u64)>)],
    switch_idx: &std::collections::HashMap<u64, u8>,
    entry_va: Option<u64>,
    excluded: &std::collections::HashSet<u64>,
    excluded_func_ranges: &[(u64, u64)],
) -> Result<Vec<u8>> {
    use iced_x86::FlowControl;
    let mut b = BytecodeBuilder::new();
    let mut block_label: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
    for bb in blocks {
        block_label.insert(bb.start_va, b.new_label());
    }
    let mut sym_blocks: Vec<(usize, u64, bool, u64)> = Vec::new();
    let switch_lookup: std::collections::HashMap<u64, &Vec<(i64, u64)>> =
        switch_cases.iter().map(|(va, cases)| (*va, cases)).collect();

    if let Some(entry) = entry_va {
        let target_lbl = block_label.get(&entry).copied().or_else(|| {
            blocks
                .iter()
                .filter(|b| b.start_va >= entry)
                .min_by_key(|b| b.start_va)
                .map(|b| block_label[&b.start_va])
                .or_else(|| blocks.first().map(|b| block_label[&b.start_va]))
        });
        if let Some(lbl) = target_lbl {
            b.jmp32(lbl);
        } else {
            return Err(anyhow!(
                "lift_cfg_switch: no valid block start found for entry_va 0x{:X}", entry
            ));
        }
    }

    for bb in blocks {
        b.mark_label(block_label[&bb.start_va]);
        let src_len: u64 = bb.instructions.iter().map(|i| i.len() as u64).sum();
        if crate::vm::mapper::active() {
            sym_blocks.push((b.bytes.len(), bb.start_va, excluded.contains(&bb.start_va), src_len));
        }
        if excluded.contains(&bb.start_va) {
            // v59: bridge to the enclosing FUNCTION entry so the prologue runs.
            let target = func_entry_for(bb.start_va, excluded_func_ranges);
            b.mov_r_imm64(SCRATCH, target);
            b.native_call(SCRATCH);
            b.ret();
            continue;
        }
        let n = bb.instructions.len();        let mut va = bb.start_va;
        for (i, inst) in bb.instructions.iter().enumerate() {
            let is_last = i + 1 == n;
            let inst_va = va;
            let len = inst.len() as u64;
            if has_rip_operand(inst) {
                b.set_rip(inst_va);
            }
            let code = inst.code();
            if crate::vm::mapper::active() {
                crate::vm::mapper::record(b.bytes.len(), inst, inst_va, "Program");
            }
            check_scratch_collision(inst)?;
            if switch_lookup.contains_key(&inst_va) {
                let cases = switch_lookup[&inst_va];
                let idx = if let Some(iv) = switch_idx.get(&inst_va) {
                    *iv
                } else if inst.op0_kind() == OpKind::Memory {
                    let idx_reg = if inst.memory_base() != Register::None {
                        inst.memory_base()
                    } else if inst.memory_index() != Register::None {
                        inst.memory_index()
                    } else {
                        return Err(anyhow!(
                            "lift_cfg: switch jump-table operand has no index register @0x{:X}",
                            inst_va
                        ));
                    };
                    vreg(idx_reg)?
                } else {
                    return Err(anyhow!(
                        "lift_cfg: register-form switch @0x{:X} has no resolved index register",
                        inst_va
                    ));
                };
                let mut emitted = false;
                for (case_val, target_va) in cases {
                    let lbl = match block_label.get(target_va) {
                        Some(&l) => l,
                        None => {
                            continue;
                        }
                    };
                    b.mov_r_r(SCRATCH, idx);
                    b.mov_r_imm32(SCRATCH2, *case_val as u32);
                    b.binop_r_r(OP_SUB_R_R, SCRATCH, SCRATCH2);
                    b.jcc32(COND_JE, lbl);
                    emitted = true;
                }
                if emitted {
                    if is_last && inst.op0_kind() == OpKind::Memory {
                        let addr = mem_emit(&mut b, inst, 0)?;
                        b.mem_load_a(OP_MOV_R_MEM64_A, SCRATCH, addr);
                        b.native_call(SCRATCH);
                        b.halt();
                        va += len;
                        continue;
                    }
                }
            }
            if is_last {
                let fc = inst.flow_control();
                match fc {
                    FlowControl::UnconditionalBranch => {
                        let t = inst.near_branch_target();
                        if let Some(&lbl) = block_label.get(&t) {
                            b.jmp32(lbl);
                        } else {
                            b.mov_r_imm64(SCRATCH, func_entry_for(t, excluded_func_ranges));
                            b.native_call(SCRATCH);
                            b.halt();
                        }
                        va += len;
                        continue;
                    }
                    FlowControl::ConditionalBranch => {
                        if code == Code::Loopne_rel8_64_RCX {
                            b.dec_r(1);
                            b.jcc32(COND_JNE, *block_label.get(&inst.near_branch_target()).ok_or_else(|| anyhow!("loopne target"))?);
                        } else if matches!(code,
                            Code::Jecxz_rel8_64 | Code::Jrcxz_rel8_64)
                        {
                            let t = inst.near_branch_target();
                            b.test_r_r32(1, 1);
                            if let Some(&lbl) = block_label.get(&t) {
                                b.jcc32(COND_JE, lbl);
                            } else {
                                b.mov_r_imm64(SCRATCH, func_entry_for(t, excluded_func_ranges));
                                b.native_call(SCRATCH);
                                b.halt();
                            }
                        } else {
                            let t = inst.near_branch_target();
                            if let Some(&lbl) = block_label.get(&t) {
                                b.jcc32(jcc_cond(code), lbl);
                            } else {
                                b.mov_r_imm64(SCRATCH, func_entry_for(t, excluded_func_ranges));
                                b.native_call(SCRATCH);
                                b.halt();
                            }
                        }
                        va += len;
                        continue;
                    }
                    FlowControl::Call => {
                        let t = inst.near_branch_target();
                        if let Some(&lbl) = block_label.get(&t) {
                            b.mov_r_imm64(SCRATCH, va.wrapping_add(len as u64));
                            b.push_r(SCRATCH);
                            b.call32(lbl);
                        } else {
                            b.mov_r_imm64(SCRATCH, func_entry_for(t, excluded_func_ranges));
                            b.native_call(SCRATCH);
                            b.halt();
                        }
                        va += len;
                        continue;
                    }
                    FlowControl::Return => {
                        // P0-0 (vm-oep): 엔트리 블록의 종료 `ret` 는 프로그램 VM 의
                        // 최상위 복귀다. 부트 스텁이 콜 프레임 없이 직접 JMP 로 진입하므로
                        // (KSA/PRGA VM 과 달리 return-IP 가 VM 콜 스택에 없다) OP_RET 로
                        // lift 하면 빈 콜 스택을 pop 해 r9=0 → 디스패처 0xC0000005 크래시
                        // (실제 dummy 1.5KB에서 재현). HALT 로 대체해 프로그램 VM 을 종료한다.
                        // (중첩 함수의 ret 는 in-VM CALL32 가 콜 스택을 push 하므로 그대로
                        //  OP_RET — 여기선 엔트리 블록만 취급.)
                        if Some(bb.start_va) == entry_va {
                            b.halt();
                        } else {
                            b.ret();
                        }
                        va += len;
                        continue;
                    }
                    _ => { /* not a terminator: fall through to next block */ }
                }
            }
            lift_one(&mut b, inst).map_err(|e| anyhow!("{} (at VA 0x{:X}, inst={})", e, inst_va, inst))?;
            va += len;
        }
    }

    b.halt();
    if crate::vm::mapper::active() && !sym_blocks.is_empty() {
        let total = b.bytes.len();
        for (i, &(bc_start, src_va, native, src_len)) in sym_blocks.iter().enumerate() {
            let bc_end = sym_blocks.get(i + 1).map(|&(s, _, _, _)| s).unwrap_or(total);
            crate::vm::mapper::record_block_start(
                bc_start,
                src_va,
                native,
                if native { "native" } else { "program" },
                0,
                if native { "plain" } else { "program-vm" },
            );
            crate::vm::mapper::end_block(bc_end, src_va + src_len);
        }
    }
    // Phase 2.3 (v56): IR pipeline (see lift_block); --map/--sym-map keeps the
    // legacy byte-exact path for offset validity.
    if crate::vm::mapper::active() {
        Ok(b.try_finish()?)
    } else {
        let (bytes, branches, labels) = b.into_parts();
        super::ir::run_ir_pipeline(&bytes, &branches, &labels)
    }
}

/// v59: if `va` lies inside one of the excluded `.pdata` function ranges,
/// return that function's ENTRY address so a native bridge runs the full
/// function (prologue included). Otherwise return `va` unchanged.
fn func_entry_for(va: u64, excluded_func_ranges: &[(u64, u64)]) -> u64 {
    excluded_func_ranges
        .iter()
        .find(|&&(s, e)| s <= va && va < e)
        .map(|&(s, _)| s)
        .unwrap_or(va)
}
