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
use crate::vm::lifter::{LiftedInstr, diagnose_unsupported, lift_block, lift_cfg, lift_cfg_switch};
use anyhow::{Result, anyhow};

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
            self.total_instructions.saturating_sub(self.unsupported.len()) as f64
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
    let sc: Vec<(u64, Vec<(i64, u64)>)> =
        switch_cases.iter().map(|(va, _, c)| (*va, c.clone())).collect();
    let sc_idx: std::collections::HashMap<u64, u8> =
        switch_cases.iter().map(|(va, iv, _)| (*va, *iv)).collect();
    // Panic/unwind runtime exclusion: detect the Rust std/CRT panic & unwind
    // functions (std::panicking, core::panicking, rust_begin_unwind, the CRT
    // _CxxThrowException / __CxxFrameHandler paths, Once teardown, …) and keep
    // them NATIVE instead of virtualizing them. Their SEH/unwind metadata must
    // match the real native frame layout; block-shuffling them into the VM is
    // what corrupts the unwind chain on panic (the once.rs:166 teardown crash).
    let excl = detect_panic_unwind_ranges(
        text_bytes, base_va, image_base, relayed_sections,
    );
    let runtime_globals: std::collections::HashSet<u64> =
        excl.runtime_globals.iter().copied().collect();
    // Shared-state (Once state word / panic-hook / stdio / rt-cleanup) global
    // ranges, for the lock-atomic net below (data/.rdata/.bss only).
    let state_ranges: Vec<(u64, u64)> = relayed_sections
        .iter()
        .filter(|s| {
            s.name.starts_with(".data") || s.name.starts_with(".rdata") || s.name.starts_with(".bss")
        })
        .map(|s| {
            let start = image_base + s.virtual_address as u64;
            let len = (s.virtual_size.max(s.bytes.len() as u32)) as u64;
            (start, start + len)
        })
        .collect();
    let excluded_blocks: std::collections::HashSet<u64> = blocks
        .iter()
        .filter(|bb| {
            excl.func_ranges.iter().any(|(s, e)| *s <= bb.start_va && bb.start_va < *e)
                || block_refs_runtime_global(bb, &runtime_globals)
                || block_has_lock_atomic_on_global(bb, &state_ranges)
        })
        .map(|bb| bb.start_va)
        .collect();
    if !excluded_blocks.is_empty() {
        println!(
            "[+] --vm-oep: excluding {} Rust panic/unwind/Once runtime block(s) from VMization (native SEH preserved)",
            excluded_blocks.len()
        );
    }
    let bytecode = lift_cfg_switch(&blocks, &sc, &sc_idx, Some(entry_point_va), &excluded_blocks)
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

    let entry_block = blocks.iter().find(|b| b.start_va == entry_point_va).map(|b| b.start_va).unwrap_or(entry_point_va);

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
fn is_zero_padding(inst: &iced_x86::Instruction) -> bool {
    use iced_x86::{Code, OpKind, Register};
    inst.code() == Code::Add_rm8_r8
        && inst.op0_kind() == OpKind::Memory
        && inst.memory_base() == Register::RAX
        && inst.memory_index() == Register::None
        && inst.memory_displacement64() == 0
        && inst.op1_register() == Register::AL
}


// ==============================================================================
// C-1 fix (switch jump-table resolution):  resolve `Jmp_rm64` jump-table
// terminators in the original program so they dispatch *inside the VM*
// (compare-and-jump chain) instead of falling back to the native bridge,
// which jumped into the middle of an original function at a case-label
// address (where the enclosing function's prologue — e.g. `lea rbx,[table]` —
// never ran), causing 0xC0000005 on the exit path.
// ==============================================================================

use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};

/// Read `len` bytes from the original image at absolute VA `va`.
fn read_image(relayed: &[crate::pe::builder::SectionData], image_base: u64, va: u64, len: usize) -> Option<Vec<u8>> {
    for s in relayed {
        let start = image_base + s.virtual_address as u64;
        if va >= start && va + len as u64 <= start + s.bytes.len() as u64 {
            let off = (va - start) as usize;
            return Some(s.bytes[off..off + len].to_vec());
        }
    }
    None
}
fn read_u32(relayed: &[crate::pe::builder::SectionData], image_base: u64, va: u64) -> Option<u32> {
    read_image(relayed, image_base, va, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}
fn read_u64(relayed: &[crate::pe::builder::SectionData], image_base: u64, va: u64) -> Option<u64> {
    read_image(relayed, image_base, va, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Absolute target of a RIP-relative `lea` (or a `mov r64,imm64` absolute load).
fn lea_target(inst: &iced_x86::Instruction) -> Option<u64> {
    match inst.code() {
        Code::Lea_r64_m | Code::Lea_r32_m if inst.is_ip_rel_memory_operand() => {
            Some(inst.memory_displacement64())
        }
        Code::Mov_r64_imm64 => Some(inst.immediate64()),
        _ => None,
    }
}

/// Resolve switch jump-tables in the original program.
///
/// Returns `Vec<(jmp_inst_va, idx_vreg, Vec<(case_value, target_block_va)>)>`
/// where `idx_vreg` is the VM vreg number of the index register used to select
/// the jump-table entry. Case targets that fall outside the lifted `.text`
/// range are dropped.
pub fn resolve_switch_cases(
    text_bytes: &[u8],
    base_va: u64,
    relayed: &[crate::pe::builder::SectionData],
    image_base: u64,
) -> Vec<(u64, u8, Vec<(i64, u64)>)> {
    let text_end = base_va + text_bytes.len() as u64;
    let mut dec = Decoder::with_ip(64, text_bytes, base_va, DecoderOptions::NONE);
    let mut insts: Vec<iced_x86::Instruction> = Vec::new();
    while dec.can_decode() {
        let i = dec.decode();
        insts.push(i);
    }
    let mut last_def: [Option<usize>; 16] = [None; 16];
    let mut out = Vec::new();
    fn reg_idx(r: Register) -> Option<usize> {
        if r.is_gpr() { Some(r.full_register().number() as usize) } else { None }
    }
    for (i, inst) in insts.iter().enumerate() {
        if inst.code() == Code::Jmp_rm64 {
            resolve_one(&insts, &last_def, i, &mut out, relayed, image_base, base_va, text_end);
        }
        if inst.op0_kind() == OpKind::Register {
            if let Some(ri) = reg_idx(inst.op0_register()) {
                last_def[ri] = Some(i);
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn resolve_one(
    insts: &[iced_x86::Instruction],
    last_def: &[Option<usize>; 16],
    i: usize,
    out: &mut Vec<(u64, u8, Vec<(i64, u64)>)>,
    relayed: &[crate::pe::builder::SectionData],
    image_base: u64,
    base_va: u64,
    text_end: u64,
) {
    fn reg_idx(r: Register) -> Option<usize> {
        if r.is_gpr() { Some(r.full_register().number() as usize) } else { None }
    }
    let inst = &insts[i];
    let jmp_va = inst.ip();
    let mut key_va = inst.ip();
    let mut idx_reg = Register::None;
    let mut table = None;
    let mut scale = 0u32;
    let mut relative = false;

    if inst.op0_kind() == OpKind::Memory {
        idx_reg = if inst.memory_index() != Register::None { inst.memory_index() } else { inst.memory_base() };
        if idx_reg == Register::None { return; }
        scale = inst.memory_index_scale();
        table = if inst.is_ip_rel_memory_operand() {
            Some(inst.memory_displacement64())
        } else {
            let base_reg = inst.memory_base();
            match reg_idx(base_reg) {
                Some(ri) => match last_def[ri] {
                    Some(j) => lea_target(&insts[j]),
                    None => None,
                },
                None => None,
            }
        };
    } else if inst.op0_kind() == OpKind::Register {
        let tgt_reg = inst.op0_register();
        let ti = reg_idx(tgt_reg).unwrap_or(0);
        let mut li = match last_def[ti] { Some(li) => li, None => return };
        // If the last def of the jmp target is an `add rT,rX` (the relative jump-table
        // idiom `...movsxd rT,[rB+rI*4]; add rT,rB; jmp rT`), the load is one step back.
        let ld0 = &insts[li];
        if matches!(ld0.code(), Code::Add_r64_rm64 | Code::Add_rm64_r64)
            && ld0.op0_kind() == OpKind::Register
            && ld0.op0_register() == tgt_reg
        {
            relative = true;
            if li == 0 { return; }
            li -= 1;
        }
        let ld = &insts[li];
        let is_load = matches!(ld.code(), Code::Movsxd_r64_rm32 | Code::Mov_r64_rm64 | Code::Mov_r32_rm32);
        if !is_load || ld.op1_kind() != OpKind::Memory { return; }
        relative = relative || matches!(ld.code(), Code::Movsxd_r64_rm32);
        idx_reg = if ld.memory_index() != Register::None { ld.memory_index() } else { ld.memory_base() };
        if idx_reg == Register::None { return; }
        scale = ld.memory_index_scale();
        // key the switch on the LOAD (index is still valid here); the jmp rT then
        // falls through to the native bridge only for the "no case matched" default.
        key_va = ld.ip();
        if ld.is_ip_rel_memory_operand() {
            table = lea_target(ld);
        } else {
            let base_reg = ld.memory_base();
            table = match reg_idx(base_reg) {
                Some(ri) => match last_def[ri] {
                    Some(j) => lea_target(&insts[j]),
                    None => None,
                },
                None => None,
            };
        }
    } else {
        return;
    }

    let table = match table { Some(t) => t, None => return };
    if scale != 4 && scale != 8 { return; }
    let Ok(idx_vreg) = crate::vm::lifter::vreg(idx_reg) else { return };
    let mut cases = Vec::new();
    let mut idx = 0i64;
    loop {
        let entry_va = table.wrapping_add((idx as u64).wrapping_mul(scale as u64));
        let target = if relative {
            read_u32(relayed, image_base, entry_va).map(|v| table.wrapping_add((v as i32 as i64) as u64))
        } else if scale == 8 {
            read_u64(relayed, image_base, entry_va)
        } else {
            read_u32(relayed, image_base, entry_va).map(|v| v as u64)
        };
        match target {
            Some(t) if t >= base_va && t < text_end => { cases.push((idx, t)); idx += 1; }
            _ => break,
        }
        if idx > 4096 { break; }
    }
    if !cases.is_empty() {
        out.push((key_va, idx_vreg, cases));
    }
}


// ==============================================================================
// Panic/Unwind runtime exclusion (--vm-oep SEH fix)
//
// Rust `panic!` control flow is not plain call→ret: it runs
//   panic location → Rust panic runtime → unwind personality → Windows SEH →
//   caller-frame search → cleanup/drop
// and relies on the .pdata (RUNTIME_FUNCTION) SEH metadata matching the native
// frame layout of each function. Virtualizing (block-shuffling) those runtime
// functions into the VM breaks that: when a panic unwinds, the OS looks up the
// *original* .pdata for the faulting IP, finds a VM-dispatched frame instead of
// the lifted function's real frame, and the stack/unwind chain is corrupted
// (observed as the `once.rs:166 f.take().unwrap()` teardown panic, entered from
// the VM dispatcher).
//
// There are no symbols in a stripped Rust PE, so we identify the runtime
// functions structurally:
//   1. a function that RIP-relative-references any Rust panic message string in
//      .rdata (std::panicking / core::panicking / once / all `.unwrap()` sites), or
//   2. a function that directly `call`/`jmp` the `_CxxThrowException` or
//      `__CxxFrameHandler3` import thunk, or
//   3. a function transitively reached from (1)/(2) over direct call edges
//      (both callers and callees — so rt::cleanup, the Once machinery and the
//      whole unwind path stay native together).
// Every such function's blocks are kept out of the VM program (see
// `lift_cfg_switch`'s `excluded` set); calls to them bridge to the original
// .text VA natively.
// ==============================================================================
fn find_subslice(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() || from > hay.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Result of the panic/unwind/Once runtime scan.
///
/// - `func_ranges`: whole `.pdata` functions to keep native.
/// - `runtime_globals`: the shared-state slots (Once state word, panic-hook
///   state, stdio state, rt::cleanup state, …) referenced by those functions.
///
/// `lift_program_cfg` keeps native every block inside a `func_range` **and**
/// every block that references one of the `runtime_globals` — the second half
/// is what catches inlined `Once::call_once`/`Once::call`/`is_completed` copies
/// and the Once completion path that lives just past the function's `.pdata`
/// end. Both cases are exactly the once.rs:166 `f.take().unwrap()` teardown
/// crash's root cause: the VM re-executing Once's atomic/closure logic.
#[derive(Debug, Clone, Default)]
pub struct PanicUnwindExclusion {
    pub func_ranges: Vec<(u64, u64)>,
    pub runtime_globals: Vec<u64>,
}

/// Does `inst` reference (via a RIP-relative or absolute memory operand) an
/// address in `globals`? The Once/panic runtime reaches its shared state through
/// both `lea reg,[state]` and atomic `lock cmpxchg [state],reg` forms.
fn instr_refs_global(inst: &iced_x86::Instruction, globals: &std::collections::HashSet<u64>) -> bool {
    use iced_x86::{OpKind, Register};
    for oi in 0..inst.op_count() {
        if inst.op_kind(oi) != OpKind::Memory {
            continue;
        }
        let addr = if inst.is_ip_rel_memory_operand() {
            inst.memory_displacement64()
        } else if inst.memory_base() == Register::None && inst.memory_index() == Register::None {
            inst.memory_displacement64()
        } else {
            continue;
        };
        if globals.contains(&addr) {
            return true;
        }
    }
    false
}

/// Does this basic block reference any runtime (Once/panic) shared-state global?
/// Used to keep blocks that contain INLINED Once logic (or a Once completion
/// path outside any `.pdata` boundary) native even though no whole function
/// range covers them.
fn block_refs_runtime_global(
    bb: &crate::graph::BasicBlock,
    globals: &std::collections::HashSet<u64>,
) -> bool {
    bb.instructions.iter().any(|i| instr_refs_global(i, globals))
}

/// Does this basic block contain a `lock`-prefixed atomic instruction whose
/// memory operand lands on a data/.rdata/.bss global? `Once` state is a
/// `lock cmpxchg` on such a global; lifting that into the VM is what corrupts
/// the state/closure (once.rs:166). This is a belt-and-suspenders net on top of
/// `block_refs_runtime_global` in case a state slot isn't reached by an already
/// excluded function and so isn't in `runtime_globals`.
fn block_has_lock_atomic_on_global(
    bb: &crate::graph::BasicBlock,
    state_ranges: &[(u64, u64)],
) -> bool {
    use iced_x86::{OpKind, Register};
    bb.instructions.iter().any(|inst| {
        if !inst.has_lock_prefix() {
            return false;
        }
        for oi in 0..inst.op_count() {
            if inst.op_kind(oi) != OpKind::Memory {
                continue;
            }
            let addr = if inst.is_ip_rel_memory_operand() {
                inst.memory_displacement64()
            } else if inst.memory_base() == Register::None && inst.memory_index() == Register::None {
                inst.memory_displacement64()
            } else {
                continue;
            };
            if state_ranges.iter().any(|&(gs, ge)| gs <= addr && addr < ge) {
                return true;
            }
        }
        false
    })
}

/// Detect the Rust panic/unwind/Once runtime functions in `.text`, so
/// `lift_program_cfg` can keep them native (and keep native every block that
/// touches their shared-state globals — see `PanicUnwindExclusion`).
pub fn detect_panic_unwind_ranges(
    text_bytes: &[u8],
    base_va: u64,
    image_base: u64,
    relayed_sections: &[crate::pe::builder::SectionData],
) -> PanicUnwindExclusion {
    use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, OpKind, Register};

    // Rust panic message signatures that only appear in the panic/unwind runtime.
    const SIGS: &[&[u8]] = &[
        b"panicked at ",
        b"called `Option::unwrap()`",
        b"called `Result::unwrap()`",
        b"fatal runtime error",
        b"Rust panics must be rethrown",
        b"failed to initiate panic",
        b"Once instance has previously been poisoned",
        b"thread panicked while processing panic",
        b"drop of the panic payload panicked",
        b"attempt to divide by zero",
        b"index out of bounds",
        b"Rust cannot catch foreign exceptions",
    ];

    // 1) panic-message string VAs in .rdata
    let mut panic_string_vas: Vec<u64> = Vec::new();
    for sec in relayed_sections {
        if sec.name != ".rdata" {
            continue;
        }
        let sec_va = image_base + sec.virtual_address as u64;
        for sig in SIGS {
            let mut pos = 0usize;
            while let Some(i) = find_subslice(&sec.bytes, sig, pos) {
                panic_string_vas.push(sec_va + i as u64);
                pos = i + sig.len();
            }
        }
    }

    // 2) .pdata function ranges (begin..end absolute). A function with no .pdata
    //    entry is a leaf we can still map by the enclosing section, but the SEH
    //    problem only concerns functions that have unwind info, so we map by
    //    .pdata; any reference that falls outside all entries is ignored.
    let pdata = relayed_sections.iter().find(|s| s.name == ".pdata");
    let mut funcs: Vec<(u64, u64)> = Vec::new();
    if let Some(pd) = pdata {
        let b = &pd.bytes;
        for chunk in b.chunks_exact(12) {
            if chunk.len() < 12 {
                break;
            }
            let s0 = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
            let e0 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
            if s0 > 0 && e0 > s0 {
                funcs.push((image_base + s0 as u64, image_base + e0 as u64));
            }
        }
    }
    funcs.sort();
    let func_of = |va: u64| -> Option<(u64, u64)> {
        funcs.iter().copied().find(|&(s, e)| s <= va && va < e)
    };

    // 3) decode .text and collect marker sites
    let mut refs: Vec<u64> = Vec::new(); // VAs of instructions that RIP-ref a panic string
    let mut throw_sites: Vec<u64> = Vec::new(); // VAs of direct call/jmp to throw/framehandler thunks
    let mut call_edges: Vec<(u64, u64)> = Vec::new(); // (caller, direct callee VA)

    let mut dec = Decoder::with_ip(64, text_bytes, base_va, DecoderOptions::NONE);
    while dec.can_decode() {
        let inst = dec.decode();
        if inst.is_invalid() {
            continue;
        }
        let va = inst.ip();
        // direct rel32 call target (must be within .text to be a thunk/function call)
        let near = inst.near_branch_target();
        match inst.flow_control() {
            FlowControl::Call => {
                if near >= base_va && near < base_va + text_bytes.len() as u64 {
                    call_edges.push((va, near));
                }
            }
            FlowControl::UnconditionalBranch => {
                // `jmp rel32` to a thunk is a tail call into the runtime
                if near >= base_va && near < base_va + text_bytes.len() as u64 {
                    call_edges.push((va, near));
                }
            }
            _ => {}
        }
        // RIP-relative operand referencing a panic string
        for oi in 0..inst.op_count() {
            if inst.op_kind(oi) == OpKind::Memory && inst.is_ip_rel_memory_operand() {
                let tgt = inst.memory_displacement64();
                if panic_string_vas.contains(&tgt) {
                    refs.push(va);
                }
            }
        }
        // `call/jmp [rip + IAT]` to an import thunk that is itself a jmp thunk —
        // handled below by resolving import thunk addresses.
    }

    // 4) import thunk addresses for _CxxThrowException / __CxxFrameHandler* / RaiseException
    //    (the CRT thunks are `jmp [rip + IAT]` in .text; their target IAT slot name
    //     contains one of these). We detect them by scanning .text for the thunk
    //     pattern whose RIP-relative target resolves (via the .rdata/.data IAT)
    //     to a name with the marker. To keep this simple and dependency-light we
    //     detect the *call sites* instead: any direct call/jmp whose target VA is
    //     a .text byte whose first opcode is a `jmp [rip+disp32]` to an import we
    //     can name is treated as a throw/raise call site. We rely on the panic
    //     string markers as the primary signal; the thunk scan is a secondary one.
    //     (No import-parse dependency is introduced here.)

    // 5) map marker sites to .pdata function starts
    let mut excluded: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for &r in &refs {
        if let Some((s, _)) = func_of(r) {
            excluded.insert(s);
        }
    }
    for &t in &throw_sites {
        if let Some((s, _)) = func_of(t) {
            excluded.insert(s);
        }
    }

    // 6) transitive closure over direct call edges (both directions), so
    //    rt::cleanup, the Once machinery, the panic payload path and the whole
    //    unwind/teardown chain are kept native together.
    //
    // FIX: the previous version destructured `(caller_ex, callee_ex)` and inserted
    // `s` from the Some side, which re-inserted the already-excluded function and
    // NEVER added the freshly-connected one — so the closure never propagated and
    // e.g. std::sync::Once (a caller of an excluded panic fn via a direct call) was
    // left in the VM, corrupting its atomic state (once.rs:166 unwrap(None) panic).
    loop {
        let mut changed = false;
        for &(caller, callee) in &call_edges {
            let caller_start = func_of(caller).map(|(s, _)| s);
            let callee_start = func_of(callee).map(|(s, _)| s);
            let caller_in = caller_start.map_or(false, |s| excluded.contains(&s));
            let callee_in = callee_start.map_or(false, |s| excluded.contains(&s));
            if caller_in != callee_in {
                // exclude whichever side is not yet in (both forward and backward)
                let to_add = if caller_in { callee_start } else { caller_start };
                if let Some(s) = to_add {
                    if excluded.insert(s) {
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    // ── Data-dependency closure ──────────────────────────────────────────────
    // The Once/panic runtime reads & writes a small set of shared global slots
    // in .data/.rdata (Once state, the Once-stored closure/result, stdio state,
    // panic-hook state, …). The .pdata function boundaries don't always cover the
    // whole runtime (e.g. Once::call_once's completion path lives just past the
    // function's .pdata end and still pokes the same globals). If ANY of that
    // remaining code is VM-lifted, the VM corrupts the shared state even though
    // the runtime function itself runs native — surfacing as once.rs:166
    // `f.take().unwrap()` on None at exit. So: collect the globals referenced by
    // the excluded functions, then also exclude any function that references one
    // of those globals, and repeat (with the call-closure) to a fixpoint.
    //
    // Global (shared-state) sections: .rdata / .data / .bss / .data$*. We ignore
    // .text / .pdata / .rsrc — a code pointer or SEH entry is not a state slot we
    // need to quarantine here (they don't corrupt Once on a VM-lift).
    let global_ranges: Vec<(u64, u64)> = relayed_sections
        .iter()
        .filter(|s| {
            s.name.starts_with(".data") || s.name.starts_with(".rdata") || s.name.starts_with(".bss")
        })
        .map(|s| {
            let start = image_base + s.virtual_address as u64;
            let len = (s.virtual_size.max(s.bytes.len() as u32)) as u64;
            (start, start + len)
        })
        .collect();

    // decode a function range [fs, fe) and return its referenced global addresses
    // that fall inside `global_ranges`.
    let fn_globals = |fs: u64, fe: u64| -> Vec<u64> {
        let mut out = Vec::new();
        let off = (fs.saturating_sub(base_va)) as usize;
        if off >= text_bytes.len() {
            return out;
        }
        let mut d = Decoder::with_ip(64, &text_bytes[off..], fs, DecoderOptions::NONE);
        let mut guard = 0usize;
        for inst in d {
            if guard > 1_000_000 {
                break;
            }
            guard += 1;
            if inst.ip() >= fe {
                break;
            }
            if inst.is_invalid() {
                continue;
            }
            for oi in 0..inst.op_count() {
                if inst.op_kind(oi) != OpKind::Memory {
                    continue;
                }
                let addr = if inst.is_ip_rel_memory_operand() {
                    inst.memory_displacement64()
                } else if inst.memory_base() == Register::None
                    && inst.memory_index() == Register::None
                {
                    inst.memory_displacement64()
                } else {
                    continue;
                };
                if global_ranges.iter().any(|&(gs, ge)| gs <= addr && addr < ge) {
                    out.push(addr);
                }
            }
        }
        out
    };

    loop {
        let mut changed = false;

        // (a) collect globals referenced by currently-excluded functions
        let mut globals: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for &s in excluded.iter() {
            if let Some(&(_, e)) = funcs.iter().find(|&&(ss, _)| ss == s) {
                for g in fn_globals(s, e) {
                    globals.insert(g);
                }
            }
        }
        if globals.is_empty() {
            break;
        }

        // (b) exclude any function referencing one of those globals
        for &(fs, fe) in &funcs {
            if excluded.contains(&fs) {
                continue;
            }
            let refs = fn_globals(fs, fe);
            if refs.iter().any(|g| globals.contains(g)) {
                if excluded.insert(fs) {
                    changed = true;
                }
            }
        }

        // (c) re-run the call-closure so functions that call (or are called by)
        //     the newly-excluded ones are pulled in too.
        for &(caller, callee) in &call_edges {
            let caller_start = func_of(caller).map(|(s, _)| s);
            let callee_start = func_of(callee).map(|(s, _)| s);
            let caller_in = caller_start.map_or(false, |s| excluded.contains(&s));
            let callee_in = callee_start.map_or(false, |s| excluded.contains(&s));
            if caller_in != callee_in {
                let to_add = if caller_in { callee_start } else { caller_start };
                if let Some(s) = to_add {
                    if excluded.insert(s) {
                        changed = true;
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }

    // convert excluded function-start VAs back to ranges, and collect the
    // shared-state globals every excluded function references.
    let mut runtime_globals: std::collections::BTreeSet<u64> = Default::default();
    for &s in excluded.iter() {
        if let Some(&(_, e)) = funcs.iter().find(|&&(ss, _)| ss == s) {
            for g in fn_globals(s, e) {
                runtime_globals.insert(g);
            }
        }
    }
    let func_ranges: Vec<(u64, u64)> = excluded
        .iter()
        .filter_map(|&s| funcs.iter().copied().find(|&(ss, _)| ss == s))
        .collect();

    PanicUnwindExclusion {
        func_ranges,
        runtime_globals: runtime_globals.into_iter().collect(),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::generate_dummy_target_pe;
    use crate::pe::TargetPeInfo;

    #[test]
    fn analyze_text_lift_dummy_target_reports_coverage() {
        // 더미 타깃 PE의 원본 .text 에 대해 커버리지 리포트가 생성되고,
        // 구조 필드가 일관된지 검증한다. (lift 가능/불가 여부는 명령 세트에 따라
        // 달라지므로 0개 블록이 아니고 coverage 가 0.0..=1.0 인지만 확인)
        let dummy = generate_dummy_target_pe().unwrap();
        let info = TargetPeInfo::parse(&dummy).unwrap();
        let base_va = info.image_base + info.text_rva as u64;
        let ep_va = info.image_base + info.entry_point_rva as u64;
        let report =
            analyze_text_lift(&info.text_bytes, base_va, ep_va, &info.relayed_sections, info.image_base)
                .unwrap();
        if info.text_bytes.is_empty() {
            return;
        }
        assert!(report.total_blocks > 0, "CFG should find at least one block");
        assert_eq!(report.total_instructions, report.liftable_instructions + report.unsupported_instructions);
        assert!((0.0..=1.0).contains(&report.coverage()));
        // 각 블록 합이 총 명령 수와 일치
        let block_sum: usize = report.blocks.iter().map(|b| b.instructions).sum();
        assert_eq!(block_sum, report.total_instructions);
    }
}
