// ==============================================================================
// BTG v26 - M6 Phase 1: 원본 .text → VM bytecode lift (coverage + lift path)
// ==============================================================================
//
// M6 목표: 원본 `.text` 를 VM 바이트코드로 lift 하여 "복호화된 원본" 자체를
// 제거한다. 이 파일은 그 첫 단계를 구현한다:
//
//   1. `analyze_text_lift` — 원본 `.text` 섹션을 디코드해 기본 블록으로 나누고,
//      각 블록의 모든 명령이 현재 1:1 리프터(lift_one/lift_block)로 lift 가능한지
//      **커버리지 리포트**를 만든다. lift 불가 명령은 (문자열, Code)로 나열해
//      A-5 진단과 패킹 시 실패 지점을 노출한다.
//   2. `lift_text_block` — 실제 기본 블록 하나를 VM 바이트코드로 lift 하는 경로.
//      (리프터/인터프리터/네이티브 VM 동치 검증은 vm/mod.rs 의 [16] 셀프테스트)
//
// 이 단계는 "원본 .text lift" 의 진단·변환 코어이다. 부트 통합(OEP → VM entry
// 교체, 다중 블록 제어흐름 연결)은 M5(제어흐름)와 C-2(OEP 전환) 이후 단계이며
// 이 모듈의 출력(블록별 바이트코드 + 커버리지)을 소비한다.
// ==============================================================================

use crate::graph::{BasicBlock, CfgExtractor};
use crate::vm::lifter::{diagnose_unsupported, lift_block, lift_cfg, lift_cfg_switch, LiftedInstr};
use crate::vm::risc::{RiscLifter, RiscProgram};
use anyhow::{anyhow, Result};
use iced_x86::Code;
use iced_x86::Instruction;
use std::collections::{HashMap, HashSet};

pub mod commercial;
pub mod exclusions;
pub mod switch;
#[cfg(test)]
mod tests;
pub mod tls_guard;

pub use commercial::{
    lift_program_cfg_commercial, lift_program_cfg_commercial_with_model, ProgramLiftCommercial,
};
pub use exclusions::{
    detect_panic_unwind_ranges, detect_seh_native_functions, detect_setjmp_longjmp_functions,
};
pub use switch::resolve_switch_cases;
pub use tls_guard::{detect_tls_callback_ranges, TlsCallbackExclusion};

/// 기본 블록 하나의 lift 결과.
#[derive(Debug, Clone)]
pub struct BlockLift {
    /// 블록 시작 VA (원본 이미지 기준)
    pub start_va: u64,
    /// 블록 내 명령 수
    pub instructions: usize,
    /// 블록 내 lift 가능 명령 수
    pub liftable: usize,
    /// lift 불가 명령 (문자열, iced Code)
    pub unsupported: Vec<(String, Code)>,
    /// true = 이 블록이 (단일 블록 리프터로) 온전히 lift 가능
    pub liftable_block: bool,
    /// lift 성공 시 VM 바이트코드 길이 (바이트), 실패 시 0
    pub bytecode_len: usize,
}

/// 원본 `.text` 전체의 lift 커버리지 리포트.
#[derive(Debug, Clone)]
pub struct TextLiftReport {
    /// CFG가 추출한 기본 블록 수
    pub total_blocks: usize,
    /// 블록 내 총 명령 수
    pub total_instructions: usize,
    /// lift 가능 명령 수 (1:1 테이블 커버)
    pub liftable_instructions: usize,
    /// lift 불가 명령 수
    pub unsupported_instructions: usize,
    /// lift 불가 명령 전체 목록 (중복 포함, 진단용)
    pub unsupported: Vec<(String, Code)>,
    /// 완전 lift 가능 블록 수
    pub fully_liftable_blocks: usize,
    /// 블록별 결과
    pub blocks: Vec<BlockLift>,
    /// 전체 lift 성공 블록의 VM 바이트코드 총 길이
    pub bytecode_total: usize,
}

impl TextLiftReport {
    /// lift 가능한 명령 비율 (0.0 ..= 1.0). 빈 블록이면 1.0.
    pub fn coverage(&self) -> f64 {
        if self.total_instructions == 0 {
            1.0
        } else {
            self.liftable_instructions as f64 / self.total_instructions as f64
        }
    }
}

/// 원본 `.text` 섹션 바이트를 디코드해 기본 블록으로 나누고, 각 블록의
/// lift 커버리지와 (lift 가능하면) 실제 VM 바이트코드를 계산한다.
///
/// `text_bytes` = 원본 .text raw 바이트, `base_va` = .text 섹션 시작 VA,
/// `entry_point_va` = 원본 entry VA. `relayed_sections`/`image_base`는
/// CFG 추출이 함수 포인터/테이블 타깃을 블록 경계로 추가하는 데 쓰인다.
pub fn analyze_text_lift(
    text_bytes: &[u8],
    base_va: u64,
    entry_point_va: u64,
    relayed_sections: &[crate::pe::builder::SectionData],
    image_base: u64,
) -> Result<TextLiftReport> {
    let (blocks, _graph) = CfgExtractor::extract(
        text_bytes,
        base_va,
        entry_point_va,
        relayed_sections,
        image_base,
    )?;
    if blocks.is_empty() {
        return Ok(TextLiftReport {
            total_blocks: 0,
            total_instructions: 0,
            liftable_instructions: 0,
            unsupported_instructions: 0,
            unsupported: Vec::new(),
            fully_liftable_blocks: 0,
            blocks: Vec::new(),
            bytecode_total: 0,
        });
    }

    let mut total_inst = 0usize;
    let mut total_liftable = 0usize;
    let mut all_unsupported: Vec<(String, Code)> = Vec::new();
    let mut fully = 0usize;
    let mut bytecode_total = 0usize;
    let mut per_block: Vec<BlockLift> = Vec::with_capacity(blocks.len());

    for bb in &blocks {
        // Diagnostic-only zero-padding filter (M6 Phase-2). Compiler alignment
        // padding `add [rax],al` (opcode 00 00) is not real code — it is the
        // single biggest false "unsupported" in the coverage report. We filter
        // it *here* in the diagnostic path so it never counts against coverage,
        // WITHOUT touching CfgExtractor (which the packer's pass1_slice shares,
        // and where changing block layout regresses the boot-area layout).
        let real: Vec<iced_x86::Instruction> = bb
            .instructions
            .iter()
            .copied()
            .filter(|i| !is_zero_padding(i))
            .collect();
        if real.is_empty() {
            continue; // block is pure padding — not real code
        }
        total_inst += real.len();

        // 블록을 LiftedInstr 시퀀스로 (분기 타깃은 블록 외부 — 리프터가 처리하는
        // 종단 분기는 target 없이 plain으로 두고, 커버리지는 diagnose_unsupported
        // 가 분기 명령을 건너뛰므로 내부 명령 lift 가능성만 본다).
        let seq: Vec<LiftedInstr> = real.iter().map(|i| LiftedInstr::plain(*i)).collect();

        let bad = diagnose_unsupported(&seq);
        let liftable = real.len().saturating_sub(bad.len());

        let block_liftable = bad.is_empty();
        if block_liftable {
            // 종단 분기가 없거나 ret 로 끝나는 단일 블록은 실제로 lift 가능.
            // (jcc/jmp/call 종단은 타깃 블록과의 연결이 필요 → M5 영역)
            let bc = lift_block(&seq, bb.start_va);
            match bc {
                Ok(code) => {
                    fully += 1;
                    bytecode_total += code.len();
                    per_block.push(BlockLift {
                        start_va: bb.start_va,
                        instructions: real.len(),
                        liftable,
                        unsupported: Vec::new(),
                        liftable_block: true,
                        bytecode_len: code.len(),
                    });
                }
                Err(_) => {
                    // ret 외 제어흐름 종단(외부 분기)은 단일 블록 리프터로 연결 불가 —
                    // 명령 자체는 lift 가능하나 블록 단위 lift는 M5 필요.
                    per_block.push(BlockLift {
                        start_va: bb.start_va,
                        instructions: real.len(),
                        liftable,
                        unsupported: Vec::new(),
                        liftable_block: false,
                        bytecode_len: 0,
                    });
                }
            }
        } else {
            all_unsupported.extend(bad.iter().cloned());
            per_block.push(BlockLift {
                start_va: bb.start_va,
                instructions: real.len(),
                liftable,
                unsupported: bad,
                liftable_block: false,
                bytecode_len: 0,
            });
        }

        total_liftable += liftable;
    }

    Ok(TextLiftReport {
        total_blocks: blocks.len(),
        total_instructions: total_inst,
        liftable_instructions: total_liftable,
        unsupported_instructions: all_unsupported.len(),
        unsupported: all_unsupported,
        fully_liftable_blocks: fully,
        blocks: per_block,
        bytecode_total,
    })
}

/// M6 Phase-2 데이터 경로: 원본 `.text`의 **entry(EP)로부터 도달 가능한 CFG 전체**를
/// 하나의 VM 프로그램(단일 bytecode blob)으로 lift한다. `lift_cfg`가 다중블록
/// rel32 분기(JMP32/JCC32/CALL32) + 블록 연결을 emit하므로, 이 결과를 VM 엔트리에
/// 배치하면 "OEP→VM entry 블록 전환"의 실행 코어가 된다 (부트 스텁 배선은 별도 단계).
///
/// Returns:
/// - `bytecode`: 단일 VM 프로그램 (전체 도달 CFG)
/// - `entry_va`: 원본 entry block의 start_va (VM 프로그램의 논리적 시작)
/// - `blocks`/`total_instructions`: CFG 규모
/// - `coverage()`: lift 가능 명령 비율
#[derive(Debug, Clone)]
pub struct ProgramLift {
    pub bytecode: Vec<u8>,
    pub entry_va: u64,
    /// true when the program entry block was excluded (kept native) and the VM
    /// program therefore bridges straight to the native OEP on its first dispatch.
    /// The boot stub uses this to take a clean native entry instead of the
    /// OP_NATIVE_CALL bridge (which leaves VM infra in r12-r15 and corrupts the
    /// Rust runtime's Once teardown -> once.rs:166 `f.take().unwrap()` on None).
    pub entry_native: bool,
    pub blocks: usize,
    pub total_instructions: usize,
    pub unsupported: Vec<(String, Code)>,
}

impl ProgramLift {
    pub fn coverage(&self) -> f64 {
        if self.total_instructions == 0 {
            1.0
        } else {
            self.total_instructions
                .saturating_sub(self.unsupported.len()) as f64
                / self.total_instructions as f64
        }
    }
}

pub fn lift_program_cfg(
    text_bytes: &[u8],
    base_va: u64,
    entry_point_va: u64,
    relayed_sections: &[crate::pe::builder::SectionData],
    image_base: u64,
    pe_bytes: &[u8],
) -> Result<ProgramLift> {
    let (blocks, _g) = CfgExtractor::extract(
        text_bytes,
        base_va,
        entry_point_va,
        relayed_sections,
        image_base,
    )?;
    if blocks.is_empty() {
        return Ok(ProgramLift {
            bytecode: Vec::new(),
            entry_va: entry_point_va,
            entry_native: false,
            blocks: 0,
            total_instructions: 0,
            unsupported: Vec::new(),
        });
    }

    // 전체 블록을 하나의 CFG로 lift (JMP/JCC/CALL/indirect/RET 모두 블록 연결).
    // C-1 import bridge fix: CfgExtractor lays blocks out in address order, so the
    // *program* entry block (EP) is not necessarily bytecode[0]. Pass `Some(entry_va)`
    // so the VM program begins with a jump to the EP block; otherwise the first
    // instruction is whatever lives at the lowest .text address (often a trailing
    // `ret`), and dispatching the program pops a garbage return address (r9 -> DLL VA).
    // C-1 fix (switch jump-tables): resolve `Jmp_rm64` jump-table terminators so
    // they dispatch *inside the VM* (compare-and-jump chain) instead of falling
    // back to the native bridge into a mid-function case label (where the
    // enclosing function prologue never ran -> 0xC0000005 on the exit path).
    let switch_cases = resolve_switch_cases(text_bytes, base_va, relayed_sections, image_base);
    if !switch_cases.is_empty() {
        println!(
            "[+] --vm-oep: resolved {} jump-table switch(es) for in-VM dispatch",
            switch_cases.len()
        );
    }
    let sc: Vec<(u64, Vec<(i64, u64)>)> = switch_cases
        .iter()
        .map(|(va, _, c)| (*va, c.clone()))
        .collect();
    let sc_idx: std::collections::HashMap<u64, u8> =
        switch_cases.iter().map(|(va, iv, _)| (*va, *iv)).collect();
    // Panic/unwind runtime exclusion: detect the Rust std/CRT panic & unwind
    // functions (std::panicking, core::panicking, rust_begin_unwind, the CRT
    // _CxxThrowException / __CxxFrameHandler paths, Once teardown, …) and keep
    // them NATIVE instead of virtualizing them. Their SEH/unwind metadata must
    // match the real native frame layout; block-shuffling them into the VM is
    // what corrupts the unwind chain on panic (the once.rs:166 teardown crash).
    //
    // v56 (Phase 2.2): the two purely-atomicity-driven lock nets
    // (`block_has_lock_atomic_on_global` / `block_has_lock_memory_rmw` and the
    // LOCK-RMW function quarantine inside `detect_panic_unwind_ranges`) were
    // REMOVED: every lock-prefixed memory RMW that occurs is now a real
    // `lock`-prefixed VM opcode (CMPXCHG/XCHG/XADD v46-v49, LOCK INC/DEC v55),
    // so virtualizing those blocks no longer lowers an atomic update to a
    // non-atomic load->modify->store. What remains excluded is the structural
    // SEH set only: the panic/unwind runtime functions and every block touching
    // their shared-state globals.
    //
    // v59 (VM coverage): switch from `detect_panic_unwind_ranges` (bidirectional
    // call + shared-global closure, ~11,016 blocks = most of the program kept
    // native) to `detect_seh_native_functions` (the same minimal rule the block-
    // shuffle path uses): panic-string referencing fns U EHANDLER fns U the
    // raise..catch frames, minus the entry fn. This keeps exactly the frames the
    // OS unwinder walks native, so the Program VM actually virtualizes the rest
    // of the program (previously ~1.1K of 12K blocks). The Once/atomicity
    // concern is handled by the real lock VM opcodes (v46-v49/v55), so the old
    // shared-global block net is dropped here too.
    let excl = detect_seh_native_functions(
        text_bytes,
        base_va,
        image_base,
        relayed_sections,
        entry_point_va,
        true,
    );
    let mut excl = excl;
    // setjmp/longjmp boundary: keep every non-local-jump user (and its call
    // closure) native — a longjmp through virtualized code restores the host
    // register file and diverges from the VM's virtual registers.
    let sjlj = detect_setjmp_longjmp_functions(
        pe_bytes,
        text_bytes,
        base_va,
        image_base,
        relayed_sections,
    );
    excl.func_ranges.extend(sjlj);
    excl.func_ranges.sort_by_key(|r| r.0);
    excl.func_ranges.dedup();
    let mut excluded_blocks: std::collections::HashSet<u64> = blocks
        .iter()
        .filter(|bb| {
            excl.func_ranges
                .iter()
                .any(|(s, e)| *s <= bb.start_va && bb.start_va < *e)
        })
        .map(|bb| bb.start_va)
        .collect();

    // v59: 리프터가 처리 못 하는 명령을 포함한 블록을 네이티브로 유지 (전체
    // 프로그램을 VM화할 때 SHLD/SHRD 같은 비커버 명령이 lift_cfg를 실패시킨다).
    // 커버리지 확대로 새로 VM에 들어온 코드에서 미지원 명령이 나오면 그 함수를
    // 제외해 패킹 실패를 막는다. (SHLD/SHRD 등은 향후 VM opcode 추가로 lift.)
    loop {
        let mut added = 0;
        for bb in blocks.iter() {
            if excluded_blocks.contains(&bb.start_va) {
                continue;
            }
            let real: Vec<iced_x86::Instruction> = bb
                .instructions
                .iter()
                .copied()
                .filter(|i| !is_zero_padding(i))
                .collect();
            let seq: Vec<LiftedInstr> = real.iter().map(|i| LiftedInstr::plain(*i)).collect();
            let bad = diagnose_unsupported(&seq);
            if !bad.is_empty() {
                // 블록 전체 대신 포함 함수 전체를 제외 (프롤로그/에필로그 일관성)
                if let Some((s, e)) = excl
                    .func_ranges
                    .iter()
                    .find(|(s, e)| *s <= bb.start_va && bb.start_va < *e)
                {
                    for other in blocks.iter() {
                        if *s <= other.start_va && other.start_va < *e {
                            if excluded_blocks.insert(other.start_va) {
                                added += 1;
                            }
                        }
                    }
                } else if excluded_blocks.insert(bb.start_va) {
                    added += 1;
                }
            }
        }
        if added == 0 {
            break;
        }
    }
    println!(
        "[+] --vm-oep: excluded {} block(s) (SEH minimal + un-liftable-instruction functions)",
        excluded_blocks.len()
    );

    // FIX(v14 redesign -- whole-program VM must actually execute): the OEP was
    // landing in the panic/unwind/Once/lock exclusion net, which forced
    // entry_native=true and made the boot stub jump straight to the native OEP
    // (the Program VM was built but never dispatched). Force the OEP into the
    // VM so the boot stub enters the Program VM, which runs the lifted OEP and
    // enters every excluded runtime callee through the native-call bridge.
    // Only do this if the entry block itself lifts cleanly (no unsupported
    // instructions); otherwise fall back to the native-OEP route.
    if entry_point_va != 0 {
        let entry_liftable = blocks
            .iter()
            .find(|bb| bb.start_va == entry_point_va)
            .map(|bb| {
                let real: Vec<iced_x86::Instruction> = bb
                    .instructions
                    .iter()
                    .copied()
                    .filter(|i| !is_zero_padding(i))
                    .collect();
                let seq: Vec<LiftedInstr> = real.iter().map(|i| LiftedInstr::plain(*i)).collect();
                diagnose_unsupported(&seq).is_empty()
            })
            .unwrap_or(false);
        if entry_liftable {
            excluded_blocks.remove(&entry_point_va);
            println!(
                "[+] --vm-oep: OEP virtualized (entry_native=false) -- Program VM now dispatches the program; excluded runtime callees run via the native-call bridge"
            );
        } else {
            println!(
                "[!] --vm-oep: OEP not liftable -- keeping entry_native=true (fall back to native OEP)"
            );
        }
    }
    if !excluded_blocks.is_empty() {
        println!(
            "[+] --vm-oep: excluding {} Rust panic/unwind/Once runtime block(s) from VMization (native SEH preserved)",
            excluded_blocks.len()
        );
    }
    let bytecode = lift_cfg_switch(
        &blocks,
        &sc,
        &sc_idx,
        Some(entry_point_va),
        &excluded_blocks,
        &excl.func_ranges,
    )
    .map_err(|e| anyhow!("lift_program_cfg: lift_cfg failed: {}", e))?;

    // lift 불가 명령 진단 (실패 지점 노출 — 전체 프로그램 lift의 정확도).
    let mut unsupported = Vec::new();
    let mut total_inst = 0usize;
    for bb in &blocks {
        let real: Vec<iced_x86::Instruction> = bb
            .instructions
            .iter()
            .copied()
            .filter(|i| !is_zero_padding(i))
            .collect();
        total_inst += real.len();
        let seq: Vec<LiftedInstr> = real.iter().map(|i| LiftedInstr::plain(*i)).collect();
        unsupported.extend(diagnose_unsupported(&seq));
    }

    let entry_block = blocks
        .iter()
        .find(|b| b.start_va == entry_point_va)
        .map(|b| b.start_va)
        .unwrap_or(entry_point_va);

    Ok(ProgramLift {
        bytecode,
        entry_va: entry_block,
        entry_native: excluded_blocks.contains(&entry_block),
        blocks: blocks.len(),
        total_instructions: total_inst,
        unsupported,
    })
}

/// lift 가능한 기본 블록 하나를 실제 VM 바이트코드로 변환한다.
/// (analyze_text_lift에서 `liftable_block==true` 인 블록과 동일 경로)
pub fn lift_text_block(bb: &BasicBlock) -> Result<Vec<u8>> {
    let seq: Vec<LiftedInstr> = bb
        .instructions
        .iter()
        .map(|i| LiftedInstr::plain(*i))
        .collect();
    lift_block(&seq, bb.start_va)
        .map_err(|e| anyhow!("lift_text_block failed @0x{:X}: {}", bb.start_va, e))
}

/// Is this instruction compiler zero-fill padding (`add [rax],al`, opcode 00 00)?
pub(crate) fn is_zero_padding(inst: &iced_x86::Instruction) -> bool {
    use iced_x86::{Code, OpKind, Register};
    inst.code() == Code::Add_rm8_r8
        && inst.op0_kind() == OpKind::Memory
        && inst.memory_base() == Register::RAX
        && inst.memory_index() == Register::None
        && inst.memory_displacement64() == 0
        && inst.op1_register() == Register::AL
}
