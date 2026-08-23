// ==============================================================================
// BTG v26+ - P3 (G1): Whole-program RISC lift for the commercial engine backend
// ==============================================================================
//
// `lift_program_cfg_commercial` reuses `lift_program_cfg`'s CFG/block/exclusion/
// OEP-force/switch-jump-table decisions, but lifts each *included* block's
// instructions with the commercial `RiscLifter` instead of the legacy 1:1
// bytecode lifter, producing a `RiscProgram` (with an ip_map linking source-IP →
// program index so `VirtualBranch` targets resolve). Blocks whose instructions
// the RISC lifter cannot lift are kept NATIVE (전량-거부, same rule as
// selective_vm T1-2) so no wrong / half-lifted code is ever generated.
// ==============================================================================

use super::exclusions::seh::parse_pdata_functions;
use super::{
    detect_seh_native_functions, detect_setjmp_longjmp_functions, is_zero_padding,
    resolve_switch_cases,
};
use crate::graph::CfgExtractor;
use crate::vm::poly::isa_spec::VirtualIsaSpec;
use crate::vm::risc::{BranchCondition, MicroInstr, MicroOperand, RiscLifter, RiscOp, RiscProgram};
use anyhow::Result;
use iced_x86::{Code, FlowControl, Instruction, Register};
use std::collections::{HashMap, HashSet};

fn emit_lifetime_toggle(
    lifter: &mut RiscLifter,
    object: &crate::vm::data_lifetime::LiteralObject,
    image_base: u64,
    build_key: u64,
) {
    let flags = MicroOperand::Temp(7);
    let address = MicroOperand::Temp(6);
    let value = MicroOperand::Temp(5);
    lifter.desynth.instrs.push(
        MicroInstr::new(RiscOp::Mov)
            .with_dst(flags)
            .with_src1(MicroOperand::Vflags),
    );
    for index in 0..object.len {
        lifter
            .desynth
            .instrs
            .push(
                MicroInstr::new(RiscOp::Mov)
                    .with_dst(address)
                    .with_src1(MicroOperand::Imm64(
                        image_base + object.rva as u64 + index as u64,
                    )),
            );
        lifter.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width: 1 })
                .with_dst(value)
                .with_src1(address),
        );
        lifter.desynth.emit_xor(
            value,
            value,
            MicroOperand::Imm64(crate::vm::data_lifetime::scoped_mask_byte(
                build_key, object.rva, index,
            ) as u64),
        );
        lifter.desynth.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 1 })
                .with_src1(address)
                .with_src2(value),
        );
    }
    lifter
        .desynth
        .instrs
        .push(MicroInstr::new(RiscOp::SetFlag).with_src1(flags));
}

fn emit_lifetime_sync(lifter: &mut RiscLifter, index: usize, acquire: bool) {
    lifter.desynth.instrs.push(
        MicroInstr::new(if acquire {
            RiscOp::LifetimeAcquire
        } else {
            RiscOp::LifetimeRelease
        })
        .with_src1(MicroOperand::Imm64(index as u64)),
    );
}

/// 블록의 모든 명령이 RISC lift 되고, 생성된 RISC op 가 전부 **폴리 인코딩 가능**한지.
///
/// RISC 리프터는 Float 스칼라(FloatAdd/FloatToFloat/...)를 lift 할 수 있지만, 폴리
/// ISA(opcode 집합)에는 그런 op 가 없다. 그대로 두면 `PolymorphicEncoder::encode`가
/// `opcode mapping missing` 오류를 내므로, 인코딩 불가 op 를 포함한 함수는 네이티브로
/// 유지한다 (절반 lift 금지 — RISC-unliftable 과 동일한 전량-거부 규칙).
fn block_poly_liftable(real: &[Instruction]) -> bool {
    let mut lifter = RiscLifter::new();
    for i in real {
        // Legacy high-byte registers alias bits 8..15 of RAX..RBX.  The RISC
        // reference lifter preserves their value and flags, but that aliasing
        // contract is not yet certified across every commercial native handler
        // family.  Keep the containing function native instead of silently
        // changing crypto/checksum results (notably `mov [mem], bh`).
        if (0..i.op_count()).any(|op| {
            matches!(
                i.op_register(op),
                Register::AH | Register::BH | Register::CH | Register::DH
            )
        }) {
            return false;
        }
        let before = lifter.desynth.instrs.len();
        if lifter.lift_instruction(i).is_err() {
            return false;
        }
        if lifter.desynth.instrs[before..]
            .iter()
            .any(|op| !VirtualIsaSpec::is_encodable(op.op))
        {
            return false;
        }
    }
    true
}

/// F1: 네이티브 유지(제외) 함수 중 **FP 리턴** 함수를 감지 — VA → (4=f32, 8=f64).
///
/// 보수적 휴리스틱: 함수를 디코드해 (a) FP-클래스 연산이 XMM0 를 마지막으로 쓰는
/// (예: `movsd xmm0,[x]; ret`, `addsd xmm0,xmm1; ...; ret`) 반면 (b) 그 뒤에
/// RAX/EAX/AX/AL 를 다시 쓰는 (=정수 리턴) 쓰기가 없으면 FP 리턴으로 분류한다.
/// 순수 스칼라 FP 산술/cvtsi2*/movsd/movss 만 세고, 모호한 movaps/movups/movq
/// (벡터/정수 이동일 수 있음) 는 세지 않는다 — false positive 는 브릿지가 정수
/// 리턴을 XMM0(가비지)에서 읽는 조용한 오답으로 이어지므로 보수적으로.
/// 이 분류 결과는 `RiscProgram::annotate_native_fp_returns` 로 직접 콜 사이트에
/// `SetNativeFpReturn{width}` 힌트를 주입하는 데 쓰인다.
fn detect_fp_return_functions(
    text_bytes: &[u8],
    base_va: u64,
    func_ranges: &[(u64, u64)],
) -> HashMap<u64, u8> {
    use iced_x86::{Decoder, DecoderOptions, OpKind, Register};
    let mut out = HashMap::new();
    for &(s, e) in func_ranges {
        if e <= s {
            continue;
        }
        let off = s.wrapping_sub(base_va) as usize;
        if off + 1 > text_bytes.len() {
            continue;
        }
        let len = (e - s) as usize;
        let end = len.min(text_bytes.len().saturating_sub(off));
        let mut dec = Decoder::with_ip(64, &text_bytes[off..off + end], s, DecoderOptions::NONE);
        let mut width: u8 = 0;
        let mut last_xmm0_fp: Option<u64> = None;
        let mut last_rax_write: Option<u64> = None;
        while dec.can_decode() {
            let inst = dec.decode();
            let m = format!("{:?}", inst.mnemonic()).to_ascii_lowercase();
            let writes_xmm0 = inst.op_count() > 0
                && inst.op0_kind() == OpKind::Register
                && inst.op0_register() == Register::XMM0;
            if writes_xmm0 {
                // FP-클래스 스칼라: sd/ss 접미 산술 + 변환 + FP 로드.
                let fp_class = m.ends_with("sd") || m.ends_with("ss") || m.starts_with("cvtsi2");
                if fp_class {
                    let w = if m.ends_with("sd") || m.starts_with("cvtsi2") && m.ends_with("sd") {
                        8u8
                    } else {
                        4u8
                    };
                    width = width.max(w);
                    last_xmm0_fp = Some(inst.ip());
                }
            }
            let writes_rax = inst.op_count() > 0
                && inst.op0_kind() == OpKind::Register
                && matches!(
                    inst.op0_register(),
                    Register::RAX | Register::EAX | Register::AX | Register::AL
                );
            if writes_rax {
                last_rax_write = Some(inst.ip());
            }
        }
        // XMM0 FP 쓰기가 RAX 마지막 쓰기 **이후**이면 FP 리턴 (RAX 재쓰기가 없으면 FP).
        if let Some(xmm) = last_xmm0_fp {
            match last_rax_write {
                None => {
                    out.insert(s, width);
                }
                Some(rax) if rax < xmm => {
                    out.insert(s, width);
                }
                _ => {}
            }
        }
    }
    out
}

/// P3 (G1): --vm-oep 상용 엔진 백엔드용 프로그램 리프트 결과.
#[derive(Debug, Clone)]
pub struct ProgramLiftCommercial {
    /// 포함 블록 전체를 연결한 RISC 프로그램 (분기 타깃은 ip_map으로 해석).
    pub program: RiscProgram,
    /// 원본 entry 블록 start_va (VM 프로그램의 논리적 시작).
    pub entry_va: u64,
    /// Stable .pdata function start containing the entry block (or entry VA
    /// when no unwind function describes it).
    pub entry_function_id: u64,
    /// true = 프로그램 entry 블록이 제외(네이티브 유지)되어 부트 스텁이
    /// clean native entry를 쓴다.
    pub entry_native: bool,
    /// CFG 추출 기본 블록 수.
    pub blocks: usize,
    /// 실제로 VM에 포함(lift)된 블록 수.
    pub virtualized_blocks: usize,
    /// 네이티브로 유지된 블록 수 (SEH 제외 + RISC-unliftable 제외).
    pub native_blocks: usize,
    /// 전체(제외 포함) 원본 명령 수.
    pub total_instructions: usize,
    /// VM 소유 블록에 포함된 원본 x64 명령 수.
    pub virtualized_instructions: usize,
    /// CFG에 관측된 .pdata 함수 수 / 그중 완전 VM 소유 함수 수.
    pub total_functions: usize,
    pub virtualized_functions: usize,
    /// Stable source VAs of fully VM-owned functions. Production family
    /// assignment consumes these IDs; traversal order is never used.
    pub virtualized_function_ids: Vec<u64>,
    /// Contiguous RISC micro-op ownership ranges for VM-owned functions.
    pub function_op_ranges: Vec<crate::vm::poly::FunctionOpRange>,
    pub data_lifetime_objects: Vec<crate::vm::data_lifetime::LiteralObject>,
    pub hot_path_profiled: bool,
    pub hot_vm_weight: u64,
    pub hot_total_weight: u64,
    pub sensitive_regions: usize,
    /// lift된 RISC 마이크로-op 수.
    pub lifted_ops: usize,
    /// RISC 리프터가 처리 못 하는 명령 진단 (실패 지점 노출).
    pub unsupported: Vec<(String, Code)>,
}

impl ProgramLiftCommercial {
    /// VM화된 비율 (포함 블록 / 전체 블록).
    pub fn virtualized_ratio(&self) -> f64 {
        if self.blocks == 0 {
            0.0
        } else {
            self.virtualized_blocks as f64 / self.blocks as f64
        }
    }
}

/// P0-①: VM ↔ native 경계의 함수 원자성.
///
/// 포함 블록에서 제외(네이티브 유지) 블록으로 나가는 직접 분기(`VirtualBranch
/// { cond }`의 `imm` = 원본 source-IP)는, 그 타깃이 제외 **함수 범위** 안에
/// 있으면 **함수 진입(프롤로그) 주소**로 리다이렉트한다. 네이티브 브리지가
/// 함수 중간(예: 에필로그 `add rsp,..; pop; ret`)이 아니라 함수 처음부터
/// 실행되게 하여, 프롤로그 없는 프레임 실행·스택 파괴를 막는다.
///
/// `ip_map`에 있는 타깃(= 가상화된 블록)은 VM 내부 분기이므로 건드리지 않는다.
/// `excluded_func_ranges`는 제외 함수의 `(start, end)` 범위 목록.
fn bridge_to_function_entries(
    program: &mut RiscProgram,
    ip_map: &HashMap<u64, usize>,
    excluded_func_ranges: &[(u64, u64)],
) -> usize {
    if excluded_func_ranges.is_empty() {
        return 0;
    }
    let entry_for = |va: u64| -> u64 {
        excluded_func_ranges
            .iter()
            .find(|&&(s, e)| s <= va && va < e)
            .map(|&(s, _)| s)
            .unwrap_or(va)
    };
    let mut redirected = 0;
    for ins in program.instrs.iter_mut() {
        // 직접 타깃(imm)만 — src1(런타임 값/간접)은 정적 리다이렉트 불가.
        if matches!(ins.op, RiscOp::VirtualBranch { .. }) && ins.src1.is_none() {
            let target = ins.imm;
            // 가상화된 블록이면 VM 내부 분기 (ip_map 존재) → 유지.
            if ip_map.contains_key(&target) {
                continue;
            }
            let entry = entry_for(target);
            if entry != target {
                ins.imm = entry;
                redirected += 1;
            }
        }
    }
    redirected
}

/// P3 (G1): 원본 `.text`의 entry로부터 도달 가능한 CFG를 **RISC lift**해
/// 상용 엔진(risc→poly→threaded) 프로그램으로 만든다.
///
/// `lift_program_cfg`와 **동일한** CfgExtractor 블록 분할, `detect_seh_native_functions`
/// 제외 넷, OEP-force, switch jump-table 해석을 그대로 재사용한다. 차이는:
/// 각 포함 블록의 명령을 1:1 레거시 바이트코드 대신 `RiscLifter`로 lift하고,
/// 블록/분기 타깃을 연결하는 ip_map을 가진 `RiscProgram`을 만든다.
/// RISC 리프터가 처리 못 하는 명령이 있는 블록은 (그 함수 전체를) 네이티브로
/// 유지한다 — 절대 절반 lift/잘못된 코드를 만들지 않는다.
pub fn lift_program_cfg_commercial(
    text_bytes: &[u8],
    base_va: u64,
    entry_point_va: u64,
    relayed_sections: &[crate::pe::builder::SectionData],
    image_base: u64,
    lifetime_objects: &[crate::vm::data_lifetime::LiteralObject],
    lifetime_key: u64,
) -> Result<ProgramLiftCommercial> {
    let marker_regions = crate::sdk::MarkerScanner::scan_markers(text_bytes);
    let mut marker_normalized;
    let cfg_text = if marker_regions.is_empty() {
        text_bytes
    } else {
        marker_normalized = text_bytes.to_vec();
        for region in &marker_regions {
            marker_normalized[region.start_offset - 8..region.start_offset].fill(0x90);
            marker_normalized[region.end_offset + 2..region.end_offset + 10].fill(0x90);
        }
        marker_normalized.as_slice()
    };
    let (mut blocks, _g) = CfgExtractor::extract(
        cfg_text,
        base_va,
        entry_point_va,
        relayed_sections,
        image_base,
    )?;
    // Marker signatures are inline data skipped by their leading `jmp +8`.
    // A whole-text CFG sweep can still seed blocks inside those eight bytes;
    // discard only such impossible entries before liftability/atomicity logic.
    blocks.retain(|bb| {
        let off = bb.start_va.saturating_sub(base_va) as usize;
        !marker_regions.iter().any(|region| {
            (region.start_offset.saturating_sub(8)..region.start_offset).contains(&off)
                || (region.end_offset + 2..region.end_offset + 10).contains(&off)
        })
    });
    if blocks.is_empty() {
        return Ok(ProgramLiftCommercial {
            program: RiscProgram::new(Vec::new()),
            entry_va: entry_point_va,
            entry_function_id: entry_point_va,
            entry_native: false,
            blocks: 0,
            virtualized_blocks: 0,
            native_blocks: 0,
            total_instructions: 0,
            virtualized_instructions: 0,
            total_functions: 0,
            virtualized_functions: 0,
            virtualized_function_ids: Vec::new(),
            function_op_ranges: Vec::new(),
            data_lifetime_objects: Vec::new(),
            hot_path_profiled: false,
            hot_vm_weight: 0,
            hot_total_weight: 0,
            sensitive_regions: 0,
            lifted_ops: 0,
            unsupported: Vec::new(),
        });
    }

    // switch jump-table 해석 (lift_program_cfg와 동일 — 정보 제공. 간접 분기
    // 타깃은 ip_map으로 해석되고, lift 불가 시 네이티브 유지).
    let switch_cases = resolve_switch_cases(text_bytes, base_va, relayed_sections, image_base);
    if !switch_cases.is_empty() {
        println!(
            "[+] --vm-commercial: resolved {} jump-table switch(es) for in-VM dispatch",
            switch_cases.len()
        );
    }

    // F2: SEH/panic-unwind 제외 넷 — BTG_SEH_NONE=1 설정 시 full-SEH 가상화 적용
    let full_seh = std::env::var("BTG_SEH_OWNERSHIP").map_or(false, |v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "full" | "strict" | "guarded"
        )
    }) || std::env::var("BTG_SEH_NONE").map_or(false, |v| v != "0");
    let mut excl = detect_seh_native_functions(
        text_bytes,
        base_va,
        image_base,
        relayed_sections,
        entry_point_va,
        full_seh,
    );
    let seh_func_ranges = excl.func_ranges.clone();
    // Commercial whole-program lifting bypasses the legacy wrapper where the
    // non-local-jump boundary was historically applied.  Static MSVC
    // setjmp/longjmp signatures do not need PE imports, so enforce that policy
    // here as well.
    excl.func_ranges.extend(detect_setjmp_longjmp_functions(
        &[],
        text_bytes,
        base_va,
        image_base,
        relayed_sections,
    ));
    excl.func_ranges.sort_by_key(|range| range.0);
    excl.func_ranges.dedup();
    let mut excluded_blocks: HashSet<u64> = blocks
        .iter()
        .filter(|bb| {
            excl.func_ranges
                .iter()
                .any(|(s, e)| *s <= bb.start_va && bb.start_va < *e)
        })
        .map(|bb| bb.start_va)
        .collect();
    let seh_policy_blocks: HashSet<u64> = blocks
        .iter()
        .filter(|bb| {
            seh_func_ranges
                .iter()
                .any(|(s, e)| *s <= bb.start_va && bb.start_va < *e)
        })
        .map(|bb| bb.start_va)
        .collect();
    // Function ownership must be atomic for *all* functions, not only the
    // SEH subset.  A RISC-unliftable block in an ordinary .pdata function used
    // to leave its siblings virtualized, allowing a VM branch to land in the
    // native function body without its prologue/ABI state.  Track the complete
    // native-function set independently from the SEH policy so every later
    // bridge and return-value decision sees the same ownership boundary.
    let all_function_ranges: Vec<(u64, u64)> = parse_pdata_functions(relayed_sections, image_base)
        .into_iter()
        .map(|(start, end, _)| (start, end))
        .collect();
    let mut native_function_ranges = excl.func_ranges.clone();

    // A function that uses a legacy high-byte register is kept native together
    // with its direct-call dependency closure.  Mixing its native frame with
    // commercial-VM crypto callees was observed to preserve process control
    // flow while silently changing the computed digest.  Treat that connected
    // calculation as one semantic ownership unit until every aliasing/call
    // combination has a native-handler differential proof.
    let has_high_byte = |i: &Instruction| {
        (0..i.op_count()).any(|op| {
            matches!(
                i.op_register(op),
                Register::AH | Register::BH | Register::CH | Register::DH
            )
        })
    };
    let mut semantic_quarantine: HashSet<(u64, u64)> = all_function_ranges
        .iter()
        .copied()
        .filter(|(s, e)| {
            blocks.iter().any(|bb| {
                *s <= bb.start_va
                    && bb.start_va < *e
                    && bb.instructions.iter().any(has_high_byte)
            })
        })
        .collect();
    loop {
        let mut discovered = Vec::new();
        for &(s, e) in &semantic_quarantine {
            for inst in blocks
                .iter()
                .filter(|bb| s <= bb.start_va && bb.start_va < e)
                .flat_map(|bb| bb.instructions.iter())
                .filter(|inst| inst.flow_control() == FlowControl::Call)
            {
                let target = inst.near_branch_target();
                if let Some(range) = all_function_ranges
                    .iter()
                    .copied()
                    .find(|(cs, ce)| *cs <= target && target < *ce)
                {
                    if !semantic_quarantine.contains(&range) {
                        discovered.push(range);
                    }
                }
            }
        }
        if discovered.is_empty() {
            break;
        }
        semantic_quarantine.extend(discovered);
    }
    for range in &semantic_quarantine {
        if !native_function_ranges.contains(range) {
            native_function_ranges.push(*range);
        }
        for bb in &blocks {
            if range.0 <= bb.start_va && bb.start_va < range.1 {
                excluded_blocks.insert(bb.start_va);
            }
        }
    }

    // SHLD and BT/BTR/BTS have passed family-isolated and combined whole-program
    // differential execution, so they are VM-owned by default.  Keep an opt-in
    // diagnostic quarantine for reproducing old ownership boundaries.
    let quarantined_families = std::env::var("BTG_VM_INTEGRATION_QUARANTINE")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let quarantine_shld = quarantined_families.split(',').any(|v| v.trim() == "shld");
    let quarantine_bt = quarantined_families
        .split(',')
        .any(|v| matches!(v.trim(), "bt" | "bit-test"));
    let integration_sensitive = |i: &Instruction| {
        (quarantine_shld && matches!(i.code(), iced_x86::Code::Shld_rm64_r64_imm8))
            || (quarantine_bt
                && matches!(
                    i.code(),
                    iced_x86::Code::Bt_rm32_imm8
                        | iced_x86::Code::Bt_rm32_r32
                        | iced_x86::Code::Bt_rm64_imm8
                        | iced_x86::Code::Bt_rm64_r64
                        | iced_x86::Code::Btr_rm64_imm8
                        | iced_x86::Code::Btr_rm64_r64
                        | iced_x86::Code::Bts_rm64_imm8
                        | iced_x86::Code::Bts_rm64_r64
                ))
    };
    let quarantine_ranges: Vec<(u64, u64)> = all_function_ranges
        .iter()
        .copied()
        .filter(|(s, e)| {
            blocks.iter().any(|bb| {
                *s <= bb.start_va
                    && bb.start_va < *e
                    && bb.instructions.iter().any(integration_sensitive)
            })
        })
        .collect();
    let mut integration_quarantine_blocks = HashSet::new();
    for range in quarantine_ranges {
        if !native_function_ranges.contains(&range) {
            native_function_ranges.push(range);
        }
        for bb in &blocks {
            if range.0 <= bb.start_va && bb.start_va < range.1 {
                integration_quarantine_blocks.insert(bb.start_va);
                excluded_blocks.insert(bb.start_va);
            }
        }
    }

    // RISC-unliftable 제외 넷 (전량-거부): RISC 리프터가 못 다루는 명령이 있는
    // 블록은 (그 함수 전체를) 네이티브로 유지 — 절대 절반 lift 금지.
    //
    // ⚠ 알려진 잠재 리스크 (P2 후속): SEH func_ranges 밖의 함수는 unliftable 블록
    // 하나만 제외되어 가상화↔네이티브 경계가 함수 중간에 생길 수 있다. 그 경계를
    // 건너는 가상화된 `jmp/call`이 네이티브 브리지로 함수 **꼬리**(add rsp; pop; ret)
    // 를 호출하면 스택 프레임이 파괴된다(이번 타깃에선 RIP-relative 크래시로 발현).
    // `.pdata` 함수 원자성으로 막을 수 있지만 커버리지가 절반으로 하락해(4513→2317)
    // 채택하지 않음. 함수 원자성 + 경계-브리지 재설계는 후속 P2 항목.
    loop {
        let mut added = 0;
        for bb in blocks.iter() {
            if excluded_blocks.contains(&bb.start_va) {
                continue;
            }
            let real: Vec<Instruction> = bb
                .instructions
                .iter()
                .copied()
                .filter(|i| !is_zero_padding(i))
                .collect();
            if real.is_empty() {
                continue;
            }
            if !block_poly_liftable(&real) {
                if let Some((s, e)) = all_function_ranges
                    .iter()
                    .find(|(s, e)| *s <= bb.start_va && bb.start_va < *e)
                {
                    if !native_function_ranges.iter().any(|r| r == &(*s, *e)) {
                        native_function_ranges.push((*s, *e));
                    }
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
        "[+] --vm-commercial ownership exclusions: total={} SEH/panic={} integration-quarantine={} other/function-atomic={}",
        excluded_blocks.len(),
        seh_policy_blocks.len(),
        integration_quarantine_blocks.len(),
        excluded_blocks
            .len()
            .saturating_sub(seh_policy_blocks.union(&integration_quarantine_blocks).count())
    );

    // OEP-force (lift_program_cfg와 동일): entry 블록이 RISC로 온전히 lift되고
    // 폴리 인코딩 가능하면 OEP를 VM에 포함해 entry_native=false를 만든다.
    // 아니면 네이티브 OEP 유지.
    if entry_point_va != 0 {
        let entry_liftable = blocks
            .iter()
            .find(|bb| bb.start_va == entry_point_va)
            .map(|bb| {
                let real: Vec<Instruction> = bb
                    .instructions
                    .iter()
                    .copied()
                    .filter(|i| !is_zero_padding(i))
                    .collect();
                block_poly_liftable(&real)
            })
            .unwrap_or(false);
        let entry_function_native = native_function_ranges
            .iter()
            .any(|(s, e)| *s <= entry_point_va && entry_point_va < *e);
        if entry_liftable && !entry_function_native {
            excluded_blocks.remove(&entry_point_va);
            println!(
                "[+] --vm-commercial: OEP virtualized (entry_native=false) -- Program VM dispatches the program"
            );
        } else {
            println!(
                "[!] --vm-commercial: OEP function is not fully RISC-liftable -- keeping entry_native=true (native OEP)"
            );
        }
    }

    // 2nd pass: 포함(비제외) 블록을 실제로 RISC lift해 프로그램 + ip_map 구성.
    let mut instrs: Vec<MicroInstr> = Vec::new();
    let mut ip_map: HashMap<u64, usize> = HashMap::new();
    // Exception/unwind safety: exact-width reads finish inside one VM
    // instruction. LEA->call scopes are also eligible because every native-call
    // RUNTIME_FUNCTION now carries a language-specific UHANDLER which restores
    // ciphertext and releases every lifetime entry owned by the unwinding TEB.
    let eligible_lifetime_objects: Vec<_> = lifetime_objects
        .iter()
        .filter(|object| {
            object.references.iter().all(|reference| {
                let va = image_base + *reference as u64;
                blocks.iter().any(|block| {
                    !excluded_blocks.contains(&block.start_va)
                        && block.instructions.iter().any(|instruction| {
                            if instruction.ip() != va {
                                return false;
                            }
                            if crate::vm::data_lifetime::is_unwind_safe_direct_reference(
                                instruction,
                                object,
                                image_base,
                            ) {
                                return true;
                            }
                            let destination = instruction.op0_register().full_register();
                            instruction.code() == Code::Lea_r64_m
                                && instruction.is_ip_rel_memory_operand()
                                && matches!(
                                    destination,
                                    Register::RCX | Register::RDX | Register::R8 | Register::R9
                                )
                                && {
                                    let target = instruction.ip_rel_memory_address();
                                    target >= image_base + object.rva as u64
                                        && target
                                            < image_base
                                                + object.rva.saturating_add(object.len) as u64
                                }
                        })
                })
            })
        })
        .cloned()
        .collect();
    let unwind_unsafe_lifetime_objects = lifetime_objects
        .len()
        .saturating_sub(eligible_lifetime_objects.len());
    if unwind_unsafe_lifetime_objects != 0 {
        println!(
            "[+] P2-14 lifetime unwind gate: excluded {} unproven cross-boundary object(s); exact-width and cleanup-backed call scopes may be sealed",
            unwind_unsafe_lifetime_objects
        );
    }
    let lifetime_sync_indices: HashMap<u32, usize> = {
        let mut rvas: Vec<_> = eligible_lifetime_objects
            .iter()
            .map(|object| object.rva)
            .collect();
        rvas.sort_unstable();
        rvas.dedup();
        rvas.into_iter()
            .enumerate()
            .map(|(index, rva)| (rva, index))
            .collect()
    };
    let mut applied_lifetime_references: HashMap<u32, HashSet<u32>> = HashMap::new();
    // P3 (G1): CfgExtractor는 블록을 주소 순으로 나열하므로 OEP가 바이트코드[0]이
    // 아니다. 레거시 `lift_cfg_switch(.., Some(entry_va))`의 entry-jump와 동일하게,
    // OEP가 VM화(비제외)되면 프로그램 맨 앞에 `VirtualBranch(Always) → OEP`를
    // prepend해 디스패처가 OEP에서 실행을 시작하게 한다. (타깃은 절대 source-IP —
    // branch-map이 ip_map으로 바이트 오프셋 해석.) OEP가 제외(네이티브)면 부트
    // 스텁이 VM을 디스패치하지 않으므로 prepend하지 않는다.
    if entry_point_va != 0 && !excluded_blocks.contains(&entry_point_va) {
        instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            })
            .with_imm(entry_point_va),
        );
    }
    let mut virtualized = 0usize;
    let mut native_blocks = 0usize;
    let mut total_inst = 0usize;
    let mut virtualized_inst = 0usize;
    let mut raw_function_op_ranges: Vec<crate::vm::poly::FunctionOpRange> = Vec::new();
    for bb in &blocks {
        let real: Vec<Instruction> = bb
            .instructions
            .iter()
            .copied()
            .filter(|i| !is_zero_padding(i))
            .collect();
        if real.is_empty() {
            continue;
        }
        total_inst += real.len();
        if excluded_blocks.contains(&bb.start_va) {
            native_blocks += 1;
            continue;
        }
        // 전량-리프트: 블록 전체가 성공해야만 포함. 실패하면 해당 블록을 네이티브로.
        let mut lifter = RiscLifter::new();
        let mut local_ip: Vec<(u64, usize)> = Vec::new();
        let mut pending_lifetime: HashMap<
            Register,
            (crate::vm::data_lifetime::LiteralObject, u32),
        > = HashMap::new();
        let mut ok = true;
        for i in &real {
            local_ip.push((i.ip(), lifter.desynth.instrs.len()));
            let is_call = matches!(
                i.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            );
            let direct_scope =
                if !is_call && i.is_ip_rel_memory_operand() && i.code() != Code::Lea_r64_m {
                    let target = i.ip_rel_memory_address();
                    eligible_lifetime_objects
                        .iter()
                        .find(|object| {
                            target >= image_base + object.rva as u64
                                && target
                                    < image_base + object.rva.saturating_add(object.len) as u64
                        })
                        .cloned()
                } else {
                    None
                };
            if let Some(object) = direct_scope {
                emit_lifetime_sync(&mut lifter, lifetime_sync_indices[&object.rva], true);
                emit_lifetime_toggle(&mut lifter, &object, image_base, lifetime_key);
                if lifter.lift_instruction(i).is_err() {
                    ok = false;
                    break;
                }
                emit_lifetime_toggle(&mut lifter, &object, image_base, lifetime_key);
                emit_lifetime_sync(&mut lifter, lifetime_sync_indices[&object.rva], false);
                applied_lifetime_references
                    .entry(object.rva)
                    .or_default()
                    .insert((i.ip() - image_base) as u32);
                let destination = i.op0_register().full_register();
                if destination != Register::None {
                    pending_lifetime.remove(&destination);
                }
                continue;
            }
            if is_call {
                let mut scoped: Vec<_> = pending_lifetime.values().cloned().collect();
                scoped.sort_by_key(|(object, _)| object.rva);
                scoped.dedup_by_key(|(object, _)| object.rva);
                for (object, _) in &scoped {
                    emit_lifetime_sync(&mut lifter, lifetime_sync_indices[&object.rva], true);
                    emit_lifetime_toggle(&mut lifter, object, image_base, lifetime_key);
                }
                if lifter.lift_instruction(i).is_err() {
                    ok = false;
                    break;
                }
                for (object, reference) in &scoped {
                    emit_lifetime_toggle(&mut lifter, object, image_base, lifetime_key);
                    emit_lifetime_sync(&mut lifter, lifetime_sync_indices[&object.rva], false);
                    applied_lifetime_references
                        .entry(object.rva)
                        .or_default()
                        .insert(*reference);
                }
                pending_lifetime.clear();
                continue;
            }
            if lifter.lift_instruction(i).is_err() {
                ok = false;
                break;
            }
            let destination = i.op0_register().full_register();
            if destination != Register::None {
                pending_lifetime.remove(&destination);
            }
            if i.code() == Code::Lea_r64_m && i.is_ip_rel_memory_operand() {
                if matches!(
                    destination,
                    Register::RCX | Register::RDX | Register::R8 | Register::R9
                ) {
                    let target = i.ip_rel_memory_address();
                    if let Some(object) = eligible_lifetime_objects.iter().find(|object| {
                        target >= image_base + object.rva as u64
                            && target < image_base + object.rva.saturating_add(object.len) as u64
                    }) {
                        pending_lifetime
                            .insert(destination, (object.clone(), (i.ip() - image_base) as u32));
                    }
                }
            }
        }
        if ok {
            let base = instrs.len();
            for &(ip, idx) in &local_ip {
                ip_map.insert(ip, base + idx);
            }
            let block_ops = lifter.desynth.instrs.len();
            instrs.extend(lifter.desynth.instrs);
            if let Some((function_id, _)) = all_function_ranges
                .iter()
                .find(|(start, end)| *start <= bb.start_va && bb.start_va < *end)
            {
                raw_function_op_ranges.push(crate::vm::poly::FunctionOpRange {
                    function_id: *function_id,
                    start_op: base,
                    end_op: base + block_ops,
                });
            }
            virtualized += 1;
            virtualized_inst += real.len();
            // P3 (G1): 상용 엔진 리프트 매핑 기록 — 원본 VA → RISC micro-op 인덱스
            // 범위. 폴리 바이트코드 오프셋은 인코딩 후 fill_risc_poly_offsets가 채운다.
            if crate::vm::mapper::active() {
                for (k, &(ip, idx)) in local_ip.iter().enumerate() {
                    let end = local_ip.get(k + 1).map(|&(_, n)| n).unwrap_or(block_ops);
                    let count = end.saturating_sub(idx);
                    if count == 0 {
                        continue;
                    }
                    crate::vm::mapper::record_risc_entry(
                        ip,
                        real[k].len(),
                        format!("{:X} {}", ip, real[k]),
                        base + idx,
                        count,
                    );
                }
            }
        } else {
            native_blocks += 1;
        }
    }

    // P0-①: VM↔native 경계 함수 원자성 — 제외 함수 범위로 나가는 직접 분기 타깃을
    // 함수 진입(프롤로그)으로 리다이렉트해, 네이티브 브리지가 함수 중간(에필로그)
    // 이 아니라 처음부터 실행하게 한다 (프롤로그 없는 프레임 실행 방지).
    // (ip_map은 with_ip_map이 소비하므로 판정용 사본을 유지 — pack-time 1회 패스.)
    let ip_map_snapshot = ip_map.clone();
    let mut program = RiscProgram::with_ip_map(instrs, ip_map);
    let lifted_ops = program.instrs.len();
    let redirected =
        bridge_to_function_entries(&mut program, &ip_map_snapshot, &native_function_ranges);
    if redirected > 0 {
        println!(
            "[+] P0-① boundary atomicity: redirected {} direct branch(es) to excluded function entry (prologue-preserving native bridge)",
            redirected
        );
    }

    // F1: 네이티브 유지 함수의 FP 리턴 감지 → 직접 콜 사이트에 SetNativeFpReturn
    // 힌트 주입. 네이티브 브릿지가 double/float 리턴 함수를 XMM0(FP)가 아니라
    // RAX(정수)에서 읽는 조용한 오답을 막는다. (보수적 — false positive 는 정수
    // 함수를 XMM0 가비지로 잘못 읽으므로 위험.)
    let fp_returns = detect_fp_return_functions(text_bytes, base_va, &native_function_ranges);
    if !fp_returns.is_empty() {
        program.annotate_native_fp_returns(&fp_returns);
        println!(
            "[+] F1 bridge FP-return: {} native function(s) detected as FP-returning (f32/f64) — SetNativeFpReturn hints injected",
            fp_returns.len()
        );
    }

    // 진단: env BTG_DUMP_RISC_OPS 가 설정되면 lift된 RISC op 히스토그램을 출력한다.
    // (실제 샘플이 어떤 핸들러 셋을 필요로 하는지 파악 — 상용 임베드 핸들러 커버리지 결정)
    if std::env::var("BTG_DUMP_RISC_OPS").is_ok() {
        use std::collections::BTreeMap;
        let mut hist: BTreeMap<String, usize> = BTreeMap::new();
        for ins in &program.instrs {
            let key = match ins.op {
                RiscOp::MemoryRead { width } => format!("MemoryRead[{width}]"),
                RiscOp::MemoryWrite { width } => format!("MemoryWrite[{width}]"),
                RiscOp::VirtualBranch { cond } => format!("VirtualBranch({cond:?})"),
                other => format!("{other:?}"),
            };
            *hist.entry(key).or_insert(0) += 1;
        }
        println!(
            "[BTG_DUMP_RISC_OPS] lifted_ops={} total_instrs={}",
            lifted_ops,
            program.instrs.len()
        );
        for (k, v) in &hist {
            println!("  {k}: {v}");
        }
    }

    let entry_block = blocks
        .iter()
        .find(|b| b.start_va == entry_point_va)
        .map(|b| b.start_va)
        .unwrap_or(entry_point_va);

    // RISC-lift 불가 명령 진단 (실패 지점 노출 — 전체 프로그램 lift 정확도).
    //
    // P2 (G3) 정제: SEH/panic-unwind 로 네이티브 유지되는 블록(구조적으로 VM 대상이
    // 아님)은 제외하고, **RISC-unliftable 만으로** 네이티브로 밀려난 블록의 실패
    // 명령만 집계한다. 그래야 남은 RISC 리프터 확장 항목(= P2 게이트)이 정확히 보인다.
    let seh_block = seh_policy_blocks;
    let mut risc_unliftable_blocks = 0usize;
    let mut unsupported = Vec::new();
    let mut unsupported_reasons: Vec<(u64, String)> = Vec::new();
    for bb in &blocks {
        if seh_block.contains(&bb.start_va) {
            continue;
        }
        let real: Vec<Instruction> = bb
            .instructions
            .iter()
            .copied()
            .filter(|i| !is_zero_padding(i))
            .collect();
        let mut lifter = RiscLifter::new();
        let mut failed = false;
        for i in &real {
            if let Err(err) = lifter.lift_instruction(i) {
                failed = true;
                unsupported.push((format!("0x{:X}", i.ip()), i.code()));
                unsupported_reasons.push((i.ip(), err.to_string()));
            }
        }
        if failed {
            risc_unliftable_blocks += 1;
        }
    }
    println!(
        "[P2-RISC-GAP] blocks: {} virtualized, {} native (SEH/panic-policy {} + integration-quarantine {} + RISC-unliftable {}), {} RISC-lift unsupported instruction(s) in RISC-unliftable blocks:",
        virtualized,
        native_blocks,
        seh_block.len(),
        integration_quarantine_blocks.len(),
        risc_unliftable_blocks,
        unsupported.len()
    );
    if !unsupported.is_empty() {
        use std::collections::BTreeMap;
        let mut by_code: BTreeMap<String, usize> = BTreeMap::new();
        for (s, c) in &unsupported {
            *by_code.entry(format!("{:?}", c)).or_insert(0) += 1;
        }
        for (k, v) in &by_code {
            println!("    - {}  (x{})", k, v);
        }

        // Reason-level diagnostics distinguish a missing opcode from a supported
        // opcode rejected by an addressing/operand constraint. Also report the
        // number of distinct .pdata functions affected so work can be prioritized
        // by recovered VM coverage instead of raw instruction frequency alone.
        let mut by_reason: BTreeMap<String, (usize, HashSet<u64>)> = BTreeMap::new();
        for (ip, reason) in &unsupported_reasons {
            let function_start = all_function_ranges
                .iter()
                .find(|(s, e)| *s <= *ip && *ip < *e)
                .map(|(s, _)| *s)
                .unwrap_or(*ip);
            let entry = by_reason
                .entry(reason.clone())
                .or_insert_with(|| (0, HashSet::new()));
            entry.0 += 1;
            entry.1.insert(function_start);
        }
        println!("[P2-RISC-REASON] failure reasons (occurrences / affected functions):");
        for (reason, (count, functions)) in &by_reason {
            println!(
                "    - {}  (x{} / {} function(s))",
                reason,
                count,
                functions.len()
            );
        }
    } else {
        println!("[P2-RISC-GAP] all non-SEH blocks RISC-liftable (no unsupported)");
    }

    let observed_functions: Vec<(u64, u64)> = all_function_ranges
        .iter()
        .copied()
        .filter(|(s, e)| {
            blocks
                .iter()
                .any(|bb| *s <= bb.start_va && bb.start_va < *e)
        })
        .collect();
    let virtualized_function_ids: Vec<u64> = observed_functions
        .iter()
        .filter(|(s, e)| {
            blocks.iter().any(|bb| {
                *s <= bb.start_va && bb.start_va < *e && !excluded_blocks.contains(&bb.start_va)
            }) && !blocks.iter().any(|bb| {
                *s <= bb.start_va && bb.start_va < *e && excluded_blocks.contains(&bb.start_va)
            })
        })
        .map(|(start, _)| *start)
        .collect();
    let virtualized_functions = virtualized_function_ids.len();
    raw_function_op_ranges.sort_by_key(|range| (range.function_id, range.start_op));
    let mut function_op_ranges: Vec<crate::vm::poly::FunctionOpRange> = Vec::new();
    for range in raw_function_op_ranges {
        if !virtualized_function_ids.contains(&range.function_id) {
            continue;
        }
        if let Some(last) = function_op_ranges.last_mut() {
            if last.function_id == range.function_id && last.end_op == range.start_op {
                last.end_op = range.end_op;
                continue;
            }
        }
        function_op_ranges.push(range);
    }
    function_op_ranges.sort_by_key(|range| range.start_op);
    let entry_function_id = observed_functions
        .iter()
        .find(|(start, end)| *start <= entry_point_va && entry_point_va < *end)
        .map(|(start, _)| *start)
        .unwrap_or(entry_point_va);
    let instruction_ratio = if total_inst == 0 {
        0.0
    } else {
        virtualized_inst as f64 / total_inst as f64
    };

    // SDK marker regions are an explicit 100%-ownership contract. A marked
    // range that is unreachable from the recovered CFG, or contains any native
    // block, is a hard pack failure rather than a best-effort hint.
    for (index, region) in marker_regions.iter().enumerate() {
        let start = base_va + region.start_offset as u64;
        let end = base_va + region.end_offset as u64;
        let covered: Vec<_> = blocks
            .iter()
            .filter(|bb| {
                bb.instructions
                    .iter()
                    .any(|ins| start <= ins.ip() && ins.ip() < end)
            })
            .collect();
        if covered.is_empty()
            || covered
                .iter()
                .any(|bb| excluded_blocks.contains(&bb.start_va))
        {
            let native: Vec<String> = covered
                .iter()
                .filter(|bb| excluded_blocks.contains(&bb.start_va))
                .map(|bb| format!("0x{:X}", bb.start_va))
                .collect();
            return Err(anyhow::anyhow!(
                "sensitive marker ownership gate failed for region {} (0x{:X}..0x{:X}): every covered block must be VM-owned (covered={}, native={:?})",
                index + 1,
                start,
                end,
                covered.len(),
                native,
            ));
        }
    }
    if !marker_regions.is_empty() {
        println!(
            "[VM-SENSITIVE-GATE] {} marked region(s), 100% VM ownership -- PASS",
            marker_regions.len()
        );
    }

    // Optional weighted hot-path profile: comma-separated `RVA[:hits]` or
    // absolute `VA[:hits]`. Supplying a profile makes 100% hot ownership a
    // release gate; absent profile data is reported explicitly as unprofiled.
    let hot_profile = std::env::var("BTG_VM_HOT_PATH").ok();
    let mut hot_vm = 0u64;
    let mut hot_total = 0u64;
    if let Some(raw) = hot_profile.as_deref() {
        for item in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            let (address, hits) = item.split_once(':').unwrap_or((item, "1"));
            let parsed = address
                .strip_prefix("0x")
                .or_else(|| address.strip_prefix("0X"))
                .map(|v| u64::from_str_radix(v, 16))
                .unwrap_or_else(|| address.parse::<u64>())
                .map_err(|_| anyhow::anyhow!("invalid BTG_VM_HOT_PATH address: {address}"))?;
            let va = if parsed < image_base {
                image_base + parsed
            } else {
                parsed
            };
            let weight: u64 = hits
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid BTG_VM_HOT_PATH hit count: {hits}"))?;
            hot_total = hot_total.saturating_add(weight);
            if ip_map_snapshot.contains_key(&va) {
                hot_vm = hot_vm.saturating_add(weight);
            }
        }
        if hot_total == 0 || hot_vm != hot_total {
            return Err(anyhow::anyhow!(
                "VM hot-path ownership gate failed: VM-owned weight {}/{} ({:.3}%)",
                hot_vm,
                hot_total,
                if hot_total == 0 {
                    0.0
                } else {
                    hot_vm as f64 * 100.0 / hot_total as f64
                }
            ));
        }
    }
    let hot_json = if hot_profile.is_some() {
        format!(
            "{{\"status\":\"profiled\",\"vm_weight\":{},\"total_weight\":{},\"ratio\":{:.6}}}",
            hot_vm,
            hot_total,
            hot_vm as f64 / hot_total as f64
        )
    } else {
        "{\"status\":\"unprofiled\"}".to_string()
    };
    println!(
        "[VM-COVERAGE] {{\"blocks\":{{\"vm\":{},\"total\":{},\"ratio\":{:.6}}},\"instructions\":{{\"vm\":{},\"total\":{},\"ratio\":{:.6}}},\"functions\":{{\"vm\":{},\"total\":{},\"ratio\":{:.6}}},\"hot_path\":{}}}",
        virtualized,
        blocks.len(),
        if blocks.is_empty() { 0.0 } else { virtualized as f64 / blocks.len() as f64 },
        virtualized_inst,
        total_inst,
        instruction_ratio,
        virtualized_functions,
        observed_functions.len(),
        if observed_functions.is_empty() { 0.0 } else { virtualized_functions as f64 / observed_functions.len() as f64 },
        hot_json,
    );
    if let Ok(raw) = std::env::var("BTG_MIN_VM_INSTRUCTION_COVERAGE") {
        let minimum: f64 = raw.parse().map_err(|_| {
            anyhow::anyhow!("BTG_MIN_VM_INSTRUCTION_COVERAGE must be a percentage in 0..=100")
        })?;
        if !(0.0..=100.0).contains(&minimum) {
            return Err(anyhow::anyhow!(
                "BTG_MIN_VM_INSTRUCTION_COVERAGE must be a percentage in 0..=100"
            ));
        }
        let actual = instruction_ratio * 100.0;
        if actual + f64::EPSILON < minimum {
            return Err(anyhow::anyhow!(
                "VM instruction coverage gate failed: actual {:.3}% < required {:.3}%",
                actual,
                minimum
            ));
        }
    }

    let data_lifetime_objects: Vec<_> = eligible_lifetime_objects
        .into_iter()
        .filter(|object| {
            applied_lifetime_references
                .get(&object.rva)
                .is_some_and(|references| {
                    object
                        .references
                        .iter()
                        .all(|reference| references.contains(reference))
                })
        })
        .collect();

    Ok(ProgramLiftCommercial {
        program,
        entry_va: entry_block,
        entry_function_id,
        entry_native: excluded_blocks.contains(&entry_block),
        blocks: blocks.len(),
        virtualized_blocks: virtualized,
        native_blocks,
        total_instructions: total_inst,
        virtualized_instructions: virtualized_inst,
        total_functions: observed_functions.len(),
        virtualized_functions,
        virtualized_function_ids,
        function_op_ranges,
        data_lifetime_objects,
        hot_path_profiled: hot_profile.is_some(),
        hot_vm_weight: hot_vm,
        hot_total_weight: hot_total,
        sensitive_regions: marker_regions.len(),
        lifted_ops,
        unsupported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_scope_emits_balanced_global_sync_ops() {
        let mut lifter = RiscLifter::new();
        emit_lifetime_sync(&mut lifter, 9, true);
        emit_lifetime_sync(&mut lifter, 9, false);
        assert_eq!(lifter.desynth.instrs.len(), 2);
        assert_eq!(lifter.desynth.instrs[0].op, RiscOp::LifetimeAcquire);
        assert_eq!(lifter.desynth.instrs[1].op, RiscOp::LifetimeRelease);
        assert_eq!(lifter.desynth.instrs[0].src1, Some(MicroOperand::Imm64(9)));
        assert_eq!(lifter.desynth.instrs[1].src1, Some(MicroOperand::Imm64(9)));
    }

    /// lift_program_cfg_commercial과 lift_program_cfg가 같은 블록 셋을 커버하는지
    /// (RISC lift 가능한 소형 합성 프로그램) 검증. 또한 RISC-unliftable 블록이
    /// 잘못된 바이트코드를 만들지 않고 네이티브로 유지되는지 검증한다.
    #[test]
    fn test_lift_commercial_covers_same_blocks_and_keeps_unliftable_native() {
        // 세 개의 리프 가능/불가 함수를 가진 소형 합성 .text:
        //   0x1000: mov rax, 1 ; mov [rbx], rax ; ret      (전부 RISC lift 가능)
        //   0x100D: mov rcx, 2 ; ret                        (RISC lift 가능)
        //   0x1016: syscall ; ret                           (RISC lift 불가 → 네이티브)
        // 세 함수 모두 .pdata에 없는 leaf — SEH 제외 넷에 안 걸림 (구조적 제외 없음).
        let mut text = Vec::new();
        let f0 = [
            0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
            0x48, 0x89, 0x03, // mov [rbx], rax
            0xC3, // ret
        ];
        let f1 = [
            0x48, 0xC7, 0xC1, 0x02, 0x00, 0x00, 0x00, // mov rcx, 2
            0xC3, // ret
        ];
        let f2 = [
            0x0F, 0x05, // syscall (RISC lifter intentionally unsupported)
            0xC3, // ret
        ];
        text.extend_from_slice(&f0);
        text.extend_from_slice(&f1);
        text.extend_from_slice(&f2);
        let base_va = 0x140001000u64;
        let entry = base_va;

        let lift_legacy =
            crate::vm::text_lift::lift_program_cfg(&text, base_va, entry, &[], 0x140000000, &[])
                .expect("legacy lift");
        let lift_com = lift_program_cfg_commercial(&text, base_va, entry, &[], 0x140000000, &[], 0)
            .expect("commercial lift");

        // 레거시 리프터는 세 함수 모두 lift 가능 → 모두 포함 (블록 수 동일).
        assert_eq!(
            lift_legacy.blocks, lift_com.blocks,
            "CFG block set identical"
        );
        // 상용 경로는 f0/f1을 VM화하고 f2(syscall)는 네이티브로 유지해야 한다.
        assert_eq!(
            lift_com.virtualized_blocks,
            lift_com.blocks - 1,
            "all blocks except syscall virtualized"
        );
        assert_eq!(lift_com.native_blocks, 1, "f2 (syscall) kept native");
        // ip_map이 포함 블록의 명령 IP를 해석해야 한다 (f0 첫 명령).
        assert!(
            lift_com.program.instrs.len() > 0,
            "commercial lift produced RISC micro-ops"
        );
        // syscall이 unsupported 진단에 기록되어야 한다.
        assert!(
            !lift_com.unsupported.is_empty(),
            "unsupported diagnostics should list syscall"
        );
    }

    /// P3 (G1) 핵심 경로 차등 검증 (선형 블록 단위 동치 — 분기/제어흐름 제외,
    /// 사용자 규칙 "차등 테스트는 선형 블록 단위 동치로 한정"):
    /// x86 바이트 → `RiscLifter` → `RiscProgram` → `PolymorphicEncoder`(롤링키
    /// 바이트코드) → `run_native_poly`(DirectThreadedNativeRunner 네이티브 하네스)
    /// 실행 결과 == `RiscProgram::eval_state` 참조 상태.
    ///
    /// 대표 다중명령 선형 블록 (mov/add/shl/shr/xor/push/pop/mov/ret — 전부
    /// 네이티브 하네스 지원 op NOR/ADD/SHR/SHL/PUSH/POP/HALT로만 분해)을 lift해
    /// 폴리모픽 인코딩한 뒤 네이티브/참조 양쪽에 실행해 레지스터·임시·플래그·
    /// VSP·스택이 완전히 일치하는지 여러 시드에서 검증한다.
    #[test]
    fn test_commercial_lift_encode_native_matches_reference_linear_block() {
        use crate::vm::poly::PolymorphicEncoder;
        use crate::vm::risc::RiscProgram;
        use crate::vm::threaded::harness::run_native_poly;
        use iced_x86::{Decoder, DecoderOptions};

        // 대표 선형 블록:
        //   mov rax, 100      ; mov rbx, 50      ; add rax, rbx
        //   shl rax, 2        ; shr rax, 1       ; xor rax, 0x1234
        //   push rbx          ; pop rcx          ; mov rdx, rax      ; ret
        let raw = [
            0x48, 0xC7, 0xC0, 0x64, 0x00, 0x00, 0x00, // mov rax, 100
            0x48, 0xC7, 0xC3, 0x32, 0x00, 0x00, 0x00, // mov rbx, 50
            0x48, 0x01, 0xD8, // add rax, rbx
            0x48, 0xC1, 0xE0, 0x02, // shl rax, 2
            0x48, 0xC1, 0xE8, 0x01, // shr rax, 1
            0x48, 0x35, 0x34, 0x12, 0x00, 0x00, // xor rax, 0x1234
            0x53, // push rbx
            0x59, // pop rcx
            0x48, 0x89, 0xC2, // mov rdx, rax
            0xC3, // ret
        ];
        let base = 0x140001000u64;

        // RISC lift — 전 명령이 리프터에 받아들여져야 한다 (전량-거부 없음).
        let mut decoder = Decoder::with_ip(64, &raw, base, DecoderOptions::NONE);
        let mut lifter = RiscLifter::new();
        while decoder.can_decode() {
            let inst = decoder.decode();
            lifter
                .lift_instruction(&inst)
                .expect("all instructions RISC-liftable");
        }
        let prog = RiscProgram::new(lifter.desynth.instrs);
        assert!(!prog.instrs.is_empty(), "lifted program must be non-empty");

        let init = [0u64; 16];
        let ref_st = prog.eval_state(&init);

        // 폴리모픽 인코딩 → 네이티브 실행 — 여러 시드에서 참조와 일치해야 한다.
        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();
            let nat = run_native_poly(&bytecode, seed, &init).unwrap();

            assert_eq!(nat.regs, ref_st.regs, "seed {seed:#x}: regs mismatch");
            assert_eq!(nat.temps, ref_st.temps, "seed {seed:#x}: temps mismatch");
            assert_eq!(
                nat.flags, ref_st.flags,
                "seed {seed:#x}: flags mismatch (ref={:#x} nat={:#x})",
                ref_st.flags, nat.flags
            );
            assert_eq!(nat.vsp, ref_st.vsp, "seed {seed:#x}: vsp mismatch");
            assert_eq!(nat.stack, ref_st.stack, "seed {seed:#x}: stack mismatch");
        }

        // 최종 레지스터/스택 값 직접 확인 (결과 무결성).
        assert_eq!(ref_st.regs[0], ((100 + 50) << 2 >> 1) ^ 0x1234, "rax final");
        assert_eq!(ref_st.regs[3], 50, "rbx = 50");
        assert_eq!(ref_st.regs[1], 50, "pop rcx returns pushed rbx");
        assert_eq!(ref_st.regs[2], ref_st.regs[0], "mov rdx, rax");
        assert_eq!(ref_st.stack.len(), 0, "push+pop balanced");
        assert_eq!(ref_st.vsp, 0, "vsp balanced");
    }

    /// P3 (G1) 통합 차등 검증 — **프로그램(OEP) 경로** 실행 동치.
    ///
    /// `lift_program_cfg_commercial`(실제 `--vm-commercial` 프로그램 lift 경로)가
    /// 만든 `RiscProgram`(ip_map 포함)을 `PolymorphicEncoder`로 롤링키 바이트코드로
    /// 인코딩해 `run_native_poly`(DirectThreadedNativeRunner 네이티브 하네스)로 실행한
    /// 결과 상태가 `RiscProgram::eval_state` 참조 상태와 동치인지 검증한다.
    ///
    /// 전량-리프트 가능한 단일 선형 함수(분기 없음, 종단 ret)를 .text로 구성해
    /// `lift_program_cfg_commercial`을 통과시키므로, OEP가 VM화(entry_native=false)되고
    /// 만들어진 프로그램은 오직 네이티브 하네스 지원 op(NOR/ADD/SHR/SHL/PUSH/POP/HALT)만
    /// 포함한다. 분기(taken)의 실제 제어흐름은 네이티브 디스패처가 담당하므로, 이 통합
    /// 테스트는 **선형 블록 단위 동치**(regs/temps/flags/vsp/stack)만 계약으로 검증한다
    /// (계약 문서 `docs/commercial-vm-engine.md` §3 참조).
    #[test]
    fn test_commercial_program_lift_integration_execution_equivalence() {
        use crate::vm::threaded::harness::run_native_risc;

        // 전량-RISC-lift 가능한 단일 함수 (분기 없음, ret 종단):
        //   mov rax, 100 ; mov rbx, 50 ; add rax, rbx ; shl rax, 2 ; shr rax, 1
        //   xor rax, 0x1234 ; push rbx ; pop rcx ; mov rdx, rax ; ret
        let f0 = [
            0x48, 0xC7, 0xC0, 0x64, 0x00, 0x00, 0x00, // mov rax, 100
            0x48, 0xC7, 0xC3, 0x32, 0x00, 0x00, 0x00, // mov rbx, 50
            0x48, 0x01, 0xD8, // add rax, rbx
            0x48, 0xC1, 0xE0, 0x02, // shl rax, 2
            0x48, 0xC1, 0xE8, 0x01, // shr rax, 1
            0x48, 0x35, 0x34, 0x12, 0x00, 0x00, // xor rax, 0x1234
            0x53, // push rbx
            0x59, // pop rcx
            0x48, 0x89, 0xC2, // mov rdx, rax
            0xC3, // ret
        ];
        let base_va = 0x140001000u64;
        let entry = base_va;

        let lift = lift_program_cfg_commercial(&f0, base_va, entry, &[], 0x140000000, &[], 0)
            .expect("commercial program lift");
        // OEP가 RISC로 온전히 lift되므로 VM화(entry_native=false)되어야 한다.
        assert!(!lift.entry_native, "OEP virtualized (entry_native=false)");
        assert!(
            lift.virtualized_blocks >= 1,
            "at least one block virtualized"
        );
        assert!(!lift.program.instrs.is_empty(), "lifted program non-empty");
        // OEP가 VM화되면 lift된 프로그램은 `VirtualBranch(Always) → OEP` entry-jump로
        // 시작한다 (CfgExtractor 주소순 블록 나열에서 OEP가 바이트코드[0]이 아니므로).
        assert!(
            matches!(lift.program.instrs[0].op, RiscOp::VirtualBranch { .. }),
            "lifted program must begin with the OEP entry-jump"
        );

        let init = [0u64; 16];
        let ref_st = lift.program.eval_state(&init);

        // 리프트된 RiscProgram (ip_map 보존)을 네이티브 하네스로 실행 == 참조.
        // (entry-jump는 ip_map으로 타깃을 해석하므로 `run_native_risc`를 사용한다 —
        //  바이트코드 복호화 경로는 ip_map을 수반하지 않아 절대-IP 분기를 해석할 수 없다.)
        let nat = run_native_risc(&lift.program, &init).unwrap();
        assert_eq!(nat.regs, ref_st.regs, "regs mismatch");
        assert_eq!(nat.temps, ref_st.temps, "temps mismatch");
        assert_eq!(
            nat.flags, ref_st.flags,
            "flags mismatch (ref={:#x} nat={:#x})",
            ref_st.flags, nat.flags
        );
        assert_eq!(nat.vsp, ref_st.vsp, "vsp mismatch");
        assert_eq!(nat.stack, ref_st.stack, "stack mismatch");

        // 결과 무결성 (프로그램 경로에서도 최종 값이 기대와 일치).
        assert_eq!(ref_st.regs[0], ((100 + 50) << 2 >> 1) ^ 0x1234, "rax final");
        assert_eq!(ref_st.regs[3], 50, "rbx = 50");
        assert_eq!(ref_st.regs[1], 50, "pop rcx returns pushed rbx");
        assert_eq!(ref_st.regs[2], ref_st.regs[0], "mov rdx, rax");
        assert_eq!(ref_st.stack.len(), 0, "push+pop balanced");
        assert_eq!(ref_st.vsp, 0, "vsp balanced");
    }

    /// P3 (G1) 확장 선형 블록 차등 검증 — 플래그 갱신(ADD/NOR/SHR/SHL)을 포함한
    /// 더 긴 선형 블록을 RISC 리프트 → 폴리 인코딩 → 네이티브 하네스로 실행해
    /// `eval_state` 참조와 regs/temps/flags/vsp/stack 전부 동치인지 여러 시드에서 검증.
    ///
    /// (선형 블록 단위 동치로 한정 — taken-분기 제어흐름은 네이티브 디스패처 담당.)
    #[test]
    fn test_commercial_extended_linear_block_matches_reference() {
        use crate::vm::poly::PolymorphicEncoder;
        use crate::vm::risc::RiscProgram;
        use crate::vm::threaded::harness::run_native_poly;
        use iced_x86::{Decoder, DecoderOptions};

        // mov rax, 0x200 ; mov rbx, 5 ; add rax, rbx ; shl rax, 3 ; shr rax, 1
        // sub rax, 0x10 ; and rax, 0xFFFF ; xor rcx, rcx ; push rax ; push rbx
        // pop rdx ; pop rcx ; mov rsi, rax ; ret
        let raw = [
            0x48, 0xC7, 0xC0, 0x00, 0x02, 0x00, 0x00, // mov rax, 0x200
            0x48, 0xC7, 0xC3, 0x05, 0x00, 0x00, 0x00, // mov rbx, 5
            0x48, 0x01, 0xD8, // add rax, rbx
            0x48, 0xC1, 0xE0, 0x03, // shl rax, 3
            0x48, 0xC1, 0xE8, 0x01, // shr rax, 1
            0x48, 0x83, 0xE8, 0x10, // sub rax, 0x10
            0x48, 0x25, 0xFF, 0xFF, 0x00, 0x00, // and rax, 0xFFFF
            0x48, 0x31, 0xC9, // xor rcx, rcx
            0x50, // push rax
            0x53, // push rbx
            0x5A, // pop rdx
            0x59, // pop rcx
            0x48, 0x89, 0xC6, // mov rsi, rax
            0xC3, // ret
        ];
        let base = 0x140001000u64;
        let mut decoder = Decoder::with_ip(64, &raw, base, DecoderOptions::NONE);
        let mut lifter = RiscLifter::new();
        while decoder.can_decode() {
            let inst = decoder.decode();
            lifter
                .lift_instruction(&inst)
                .expect("all instructions RISC-liftable");
        }
        let prog = RiscProgram::new(lifter.desynth.instrs);
        assert!(!prog.instrs.is_empty(), "lifted program must be non-empty");

        let init = [0u64; 16];
        let ref_st = prog.eval_state(&init);

        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();
            let nat = run_native_poly(&bytecode, seed, &init).unwrap();

            assert_eq!(nat.regs, ref_st.regs, "seed {seed:#x}: regs mismatch");
            assert_eq!(nat.temps, ref_st.temps, "seed {seed:#x}: temps mismatch");
            assert_eq!(
                nat.flags, ref_st.flags,
                "seed {seed:#x}: flags mismatch (ref={:#x} nat={:#x})",
                ref_st.flags, nat.flags
            );
            assert_eq!(nat.vsp, ref_st.vsp, "seed {seed:#x}: vsp mismatch");
            assert_eq!(nat.stack, ref_st.stack, "seed {seed:#x}: stack mismatch");
        }

        // 기대 값 직접 확인.
        let exp_rax = ((((0x200u64 + 5) << 3) >> 1).wrapping_sub(0x10)) & 0xFFFF;
        assert_eq!(ref_st.regs[0], exp_rax, "rax final"); // reg[0] = rax
                                                          // push rax; push rbx; pop rdx; pop rcx → rdx=rbx(5), rcx=rax(exp_rax)
        assert_eq!(ref_st.regs[1], exp_rax, "rcx = popped rax"); // reg[1] = rcx
        assert_eq!(ref_st.regs[2], 5, "rdx = pushed rbx"); // reg[2] = rdx
        assert_eq!(ref_st.regs[3], 5, "rbx still 5"); // reg[3] = rbx
        assert_eq!(ref_st.regs[6], exp_rax, "rsi = rax"); // reg[6] = rsi
        assert_eq!(ref_st.stack.len(), 0, "push+pop balanced");
        assert_eq!(ref_st.vsp, 0, "vsp balanced");
    }

    /// P2 (G3): 8-bit ALU/CMP/TEST/NOP lift 정확성 — **값 단언**(x86 실제 의미론).
    ///
    /// 선형 블록 단위 동치(레퍼런스==네이티브)는 lift 자체의 버그(예: 8/16비트 상위
    /// 비트 미보존, 8비트 CMP가 전체 64비트 레지스터를 비교)를 잡지 못한다 — 양쪽이
    /// 같은 (잘못된) lift를 쓰기 때문. 그래서 여기서는 **x86 기대 값**을 직접 단언해
    /// 8비트 부분-쓰기 상위 비트 보존과 8비트 CMP/TEST의 low-byte 비교를 고정한다.
    ///
    ///   mov rax, 0x1122334455667788 ; add al, 1 ; add al, 0x7F ; sub al, 2
    ///   cmp al, 6 ; test al, 1 ; nop ; xor ecx, ecx ; mov cl, 0x80 ; test al, cl ; ret
    ///
    /// 최종 rax = 0x1122334455667706 (상위 비트 보존 + low-byte 0x06),
    /// rcx = 0x80. CF는 add 0x7F에서 세트(0x89+0x7F=0x108), 최종 test al,cl → ZF=1.
    #[test]
    fn test_commercial_8bit_partial_write_and_cmp_test_matches_reference() {
        use crate::vm::poly::PolymorphicEncoder;
        use crate::vm::risc::RiscProgram;
        use crate::vm::threaded::harness::run_native_poly;
        use iced_x86::{Decoder, DecoderOptions};

        let raw = [
            0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, // mov rax, 0x1122334455667788
            0x04, 0x01, // add al, 1
            0x04, 0x7F, // add al, 0x7F  (low 0x89+0x7F=0x108 → 0x08, CF=1)
            0x2C, 0x02, // sub al, 2    (0x08-2 = 0x06)
            0x3C, 0x06, // cmp al, 6    (ZF=1)
            0xA8, 0x01, // test al, 1   (0x06&1=0 → ZF=0)
            0x90, // nop
            0x31, 0xC9, // xor ecx, ecx
            0xB1, 0x80, // mov cl, 0x80
            0x84, 0xC8, // test al, cl  (0x06&0x80=0 → ZF=1)
            0xC3, // ret
        ];
        let base = 0x140001000u64;

        let mut decoder = Decoder::with_ip(64, &raw, base, DecoderOptions::NONE);
        let mut lifter = RiscLifter::new();
        while decoder.can_decode() {
            let inst = decoder.decode();
            lifter
                .lift_instruction(&inst)
                .expect("all instructions RISC-liftable");
        }
        let prog = RiscProgram::new(lifter.desynth.instrs);
        assert!(!prog.instrs.is_empty(), "lifted program must be non-empty");

        let init = [0u64; 16];
        let ref_st = prog.eval_state(&init);

        // P2 (G3): 하네스 8/16비트 Add/Sub 어셈블 버그(Register 63 + 상위 비트 0-확장)
        // 를 고친 뒤 `run_native_poly` 차등 실행 == `eval_state` 참조 (regs/temps/vsp).
        // flags는 store_flags의 FLAG_MASK가 PF/AF를 제외하므로 전부 동치를 단언하지
        // 않고, 아래에서 ZF 값 단언으로 8비트 CMP/TEST 플래그를 고정한다.
        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();
            let nat = run_native_poly(&bytecode, seed, &init)
                .map_err(|e| format!("seed {seed:#x}: native run failed: {e}"))
                .unwrap();
            assert_eq!(nat.regs, ref_st.regs, "seed {seed:#x}: regs mismatch");
            assert_eq!(nat.temps, ref_st.temps, "seed {seed:#x}: temps mismatch");
            assert_eq!(nat.vsp, ref_st.vsp, "seed {seed:#x}: vsp mismatch");
        }

        // x86 실제 의미론 값 단언 (lift 버그 회귀 고정):
        assert_eq!(
            ref_st.regs[0], 0x1122334455667706,
            "rax: upper preserved + low byte 0x06"
        );
        // mov cl, 0x80 → rcx low byte 0x80 (rcx는 xor로 0 확장됨)
        assert_eq!(ref_st.regs[1], 0x80, "rcx low byte 0x80");
        // 최종 test al, cl: 0x06 & 0x80 == 0 → ZF=1
        assert_ne!(
            ref_st.flags & crate::vm::risc::flags::VFLAG_ZF,
            0,
            "ZF set by final test"
        );
        assert_eq!(ref_st.vsp, 0, "vsp balanced");
    }

    /// P0-①: VM↔native 경계 함수 원자성 — 제외 함수 범위로 나가는 직접 `VirtualBranch`
    /// 타깃이 함수 진입(프롤로그) 주소로 리다이렉트되는지, 가상화된 블록(ip_map 존재)
    /// 분기는 유지되는지, 범위 밖 타깃은 그대로인지 검증한다.
    #[test]
    fn test_bridge_to_function_entries_redirects_excluded_mid_function() {
        use crate::vm::risc::{BranchCondition, MicroOperand, RiscOp};

        // 제외 함수: [0x140002000 .. 0x140002040). 그 안의 중간 블록 0x140002028로
        // 가는 직접 분기는 함수 진입 0x140002000으로 리다이렉트돼야 한다.
        let func_ranges = vec![(0x140002000u64, 0x140002040u64)];
        let mut ip_map = HashMap::new();
        ip_map.insert(0x140001000u64, 0usize); // 가상화된 블록

        let mut prog = RiscProgram::new(vec![
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            })
            .with_imm(0x140002028), // → 함수 중간 (리다이렉트)
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Zero,
            })
            .with_imm(0x140001000), // → 가상화 블록 (유지)
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            })
            .with_imm(0x140003000), // → 범위 밖 (유지)
            MicroInstr::new(RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            })
            .with_src1(MicroOperand::VReg(1)), // 간접 (유지)
        ]);

        let n = bridge_to_function_entries(&mut prog, &ip_map, &func_ranges);
        assert_eq!(n, 1, "exactly the mid-function branch is redirected");
        assert_eq!(
            prog.instrs[0].imm, 0x140002000,
            "redirected to function entry (prologue)"
        );
        assert_eq!(
            prog.instrs[1].imm, 0x140001000,
            "virtualized-block branch untouched"
        );
        assert_eq!(
            prog.instrs[2].imm, 0x140003000,
            "out-of-range branch untouched"
        );
        assert!(prog.instrs[3].src1.is_some(), "indirect branch untouched");
    }
}
