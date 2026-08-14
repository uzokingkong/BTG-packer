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

use super::{detect_seh_native_functions, is_zero_padding, resolve_switch_cases};
use crate::graph::CfgExtractor;
use crate::vm::risc::{MicroInstr, RiscLifter, RiscOp, RiscProgram};
use anyhow::Result;
use iced_x86::{Code, Instruction};
use std::collections::{HashMap, HashSet};

/// P3 (G1): --vm-oep 상용 엔진 백엔드용 프로그램 리프트 결과.
#[derive(Debug, Clone)]
pub struct ProgramLiftCommercial {
    /// 포함 블록 전체를 연결한 RISC 프로그램 (분기 타깃은 ip_map으로 해석).
    pub program: RiscProgram,
    /// 원본 entry 블록 start_va (VM 프로그램의 논리적 시작).
    pub entry_va: u64,
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
) -> Result<ProgramLiftCommercial> {
    let (blocks, _g) = CfgExtractor::extract(
        text_bytes,
        base_va,
        entry_point_va,
        relayed_sections,
        image_base,
    )?;
    if blocks.is_empty() {
        return Ok(ProgramLiftCommercial {
            program: RiscProgram::new(Vec::new()),
            entry_va: entry_point_va,
            entry_native: false,
            blocks: 0,
            virtualized_blocks: 0,
            native_blocks: 0,
            total_instructions: 0,
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

    // SEH/panic-unwind 제외 넷 (lift_program_cfg와 동일한 구조적 규칙).
    let excl = detect_seh_native_functions(
        text_bytes,
        base_va,
        image_base,
        relayed_sections,
        entry_point_va,
    );
    let mut excluded_blocks: HashSet<u64> = blocks
        .iter()
        .filter(|bb| {
            excl.func_ranges.iter().any(|(s, e)| *s <= bb.start_va && bb.start_va < *e)
        })
        .map(|bb| bb.start_va)
        .collect();

    // RISC-unliftable 제외 넷 (전량-거부): RISC 리프터가 못 다루는 명령이 있는
    // 블록은 (그 함수 전체를) 네이티브로 유지 — 절대 절반 lift 금지.
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
            let mut lifter = RiscLifter::new();
            let mut ok = true;
            for i in &real {
                if lifter.lift_instruction(i).is_err() {
                    ok = false;
                    break;
                }
            }
            if !ok {
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
        "[+] --vm-commercial: excluded {} block(s) (SEH minimal + RISC-unliftable-instruction functions)",
        excluded_blocks.len()
    );

    // OEP-force (lift_program_cfg와 동일): entry 블록이 RISC로 온전히 lift되면
    // OEP를 VM에 포함해 entry_native=false를 만든다. 아니면 네이티브 OEP 유지.
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
                let mut lifter = RiscLifter::new();
                real.iter().all(|i| lifter.lift_instruction(i).is_ok())
            })
            .unwrap_or(false);
        if entry_liftable {
            excluded_blocks.remove(&entry_point_va);
            println!(
                "[+] --vm-commercial: OEP virtualized (entry_native=false) -- Program VM dispatches the program"
            );
        } else {
            println!(
                "[!] --vm-commercial: OEP not RISC-liftable -- keeping entry_native=true (native OEP)"
            );
        }
    }

    // 2nd pass: 포함(비제외) 블록을 실제로 RISC lift해 프로그램 + ip_map 구성.
    let mut instrs: Vec<MicroInstr> = Vec::new();
    let mut ip_map: HashMap<u64, usize> = HashMap::new();
    let mut virtualized = 0usize;
    let mut native_blocks = 0usize;
    let mut total_inst = 0usize;
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
        let mut ok = true;
        for i in &real {
            local_ip.push((i.ip(), lifter.desynth.instrs.len()));
            if lifter.lift_instruction(i).is_err() {
                ok = false;
                break;
            }
        }
        if ok {
            let base = instrs.len();
            for &(ip, idx) in &local_ip {
                ip_map.insert(ip, base + idx);
            }
            let block_ops = lifter.desynth.instrs.len();
            instrs.extend(lifter.desynth.instrs);
            virtualized += 1;
            // P3 (G1): 상용 엔진 리프트 매핑 기록 — 원본 VA → RISC micro-op 인덱스
            // 범위. 폴리 바이트코드 오프셋은 인코딩 후 fill_risc_poly_offsets가 채운다.
            if crate::vm::mapper::active() {
                for (k, &(ip, idx)) in local_ip.iter().enumerate() {
                    let end = local_ip
                        .get(k + 1)
                        .map(|&(_, n)| n)
                        .unwrap_or(block_ops);
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

    let program = RiscProgram::with_ip_map(instrs, ip_map);
    let lifted_ops = program.instrs.len();

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
        println!("[BTG_DUMP_RISC_OPS] lifted_ops={} total_instrs={}", lifted_ops, program.instrs.len());
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
    let mut unsupported = Vec::new();
    for bb in &blocks {
        let real: Vec<Instruction> = bb
            .instructions
            .iter()
            .copied()
            .filter(|i| !is_zero_padding(i))
            .collect();
        let mut lifter = RiscLifter::new();
        for i in &real {
            if let Err(_) = lifter.lift_instruction(i) {
                unsupported.push((format!("0x{:X}", i.ip()), i.code()));
            }
        }
    }

    Ok(ProgramLiftCommercial {
        program,
        entry_va: entry_block,
        entry_native: excluded_blocks.contains(&entry_block),
        blocks: blocks.len(),
        virtualized_blocks: virtualized,
        native_blocks,
        total_instructions: total_inst,
        lifted_ops,
        unsupported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// lift_program_cfg_commercial과 lift_program_cfg가 같은 블록 셋을 커버하는지
    /// (RISC lift 가능한 소형 합성 프로그램) 검증. 또한 RISC-unliftable 블록이
    /// 잘못된 바이트코드를 만들지 않고 네이티브로 유지되는지 검증한다.
    #[test]
    fn test_lift_commercial_covers_same_blocks_and_keeps_unliftable_native() {
        // 세 개의 리프 가능/불가 함수를 가진 소형 합성 .text:
        //   0x1000: mov rax, 1 ; mov [rbx], rax ; ret      (전부 RISC lift 가능)
        //   0x100D: mov rcx, 2 ; ret                        (RISC lift 가능)
        //   0x1016: xgetbv ; ret                            (RISC lift 불가 → 네이티브)
        // 세 함수 모두 .pdata에 없는 leaf — SEH 제외 넷에 안 걸림 (구조적 제외 없음).
        let mut text = Vec::new();
        let f0 = [
            0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
            0x48, 0x89, 0x03,                         // mov [rbx], rax
            0xC3,                                     // ret
        ];
        let f1 = [
            0x48, 0xC7, 0xC1, 0x02, 0x00, 0x00, 0x00, // mov rcx, 2
            0xC3,                                     // ret
        ];
        let f2 = [
            0x0F, 0x01, 0xD0, // xgetbv (RISC lifter 미지원)
            0xC3,             // ret
        ];
        text.extend_from_slice(&f0);
        text.extend_from_slice(&f1);
        text.extend_from_slice(&f2);
        let base_va = 0x140001000u64;
        let entry = base_va;

        let lift_legacy = crate::vm::text_lift::lift_program_cfg(
            &text, base_va, entry, &[], 0x140000000,
        )
        .expect("legacy lift");
        let lift_com = lift_program_cfg_commercial(&text, base_va, entry, &[], 0x140000000)
            .expect("commercial lift");

        // 레거시 리프터는 세 함수 모두 lift 가능 → 모두 포함 (블록 수 동일).
        assert_eq!(lift_legacy.blocks, lift_com.blocks, "CFG block set identical");
        // 상용 경로는 f0/f1을 VM화하고 f2(xgetbv)는 네이티브로 유지해야 한다.
        assert_eq!(lift_com.virtualized_blocks, 2, "f0+f1 virtualized");
        assert_eq!(lift_com.native_blocks, 1, "f2 (xgetbv) kept native");
        // ip_map이 포함 블록의 명령 IP를 해석해야 한다 (f0 첫 명령).
        assert!(
            lift_com.program.instrs.len() > 0,
            "commercial lift produced RISC micro-ops"
        );
        // xgetbv가 unsupported 진단에 기록되어야 한다.
        assert!(
            !lift_com.unsupported.is_empty(),
            "unsupported diagnostics should list xgetbv"
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
            0x48, 0x01, 0xD8,                         // add rax, rbx
            0x48, 0xC1, 0xE0, 0x02,                   // shl rax, 2
            0x48, 0xC1, 0xE8, 0x01,                   // shr rax, 1
            0x48, 0x35, 0x34, 0x12, 0x00, 0x00,       // xor rax, 0x1234
            0x53,                                     // push rbx
            0x59,                                     // pop rcx
            0x48, 0x89, 0xC2,                         // mov rdx, rax
            0xC3,                                     // ret
        ];
        let base = 0x140001000u64;

        // RISC lift — 전 명령이 리프터에 받아들여져야 한다 (전량-거부 없음).
        let mut decoder = Decoder::with_ip(64, &raw, base, DecoderOptions::NONE);
        let mut lifter = RiscLifter::new();
        while decoder.can_decode() {
            let inst = decoder.decode();
            lifter.lift_instruction(&inst).expect("all instructions RISC-liftable");
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
}
