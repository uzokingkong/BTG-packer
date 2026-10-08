//! BTG VM coverage auditor.
//!
//! Enumerates every iced-x86 `Code` variant, builds a representative 64-bit
//! `Instruction`, runs the real BTG RISC lifter, inspects the emitted RISC ops,
//! and then checks the canonical commercial capability registry.  The result is
//! emitted as TXT/CSV/JSON so coverage can be tracked in CI.

use btg_packer::vm::risc::{capabilities, RiscLifter, RiscOp};
use clap::Parser;
use iced_x86::{Code, Instruction, OpCodeOperandKind, OpKind, Register};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(name = "vm-coverage")]
#[command(about = "Audit iced-x86 Code -> BTG lifter -> RiscOp -> commercial VM coverage")]
struct Args {
    /// Output directory. Defaults to ./coverage.
    #[arg(long, default_value = "coverage")]
    out_dir: PathBuf,

    /// Do not include iced-x86 pseudo/directive Code variants in the report.
    #[arg(long)]
    instructions_only: bool,
}

#[derive(Debug, Clone, Serialize)]
struct OpCapability {
    op: String,
    kind: String,
    evaluator: bool,
    poly_codec: bool,
    poly_interpreter: bool,
    production_threaded: bool,
    reads_flags: bool,
    writes_flags: bool,
    may_fault: bool,
}

#[derive(Debug, Clone, Serialize)]
struct CodeRecord {
    code_id: usize,
    code: String,
    mnemonic: String,
    encoding: String,
    is_instruction: bool,
    mode64: bool,
    privileged: bool,
    cpl0: bool,
    cpl3: bool,
    input_output: bool,
    cpuid_features: Vec<String>,
    op_kinds: Vec<String>,
    lock_allowed: bool,
    rep_allowed: bool,
    repne_allowed: bool,
    flow_control: String,
    lifter: String,
    lift_error: Option<String>,
    risc_ops: Vec<String>,
    capabilities: Vec<OpCapability>,
    isa: String,
    interpreter: String,
    threaded: String,
    status: String,
}

#[derive(Debug, Clone, Serialize, Default)]
struct Summary {
    total_code_values: usize,
    instruction_code_values: usize,
    non_instruction_code_values: usize,
    full_pipeline: usize,
    lifted_no_micro_op: usize,
    unsupported: usize,
    lift_error: usize,
    evaluator_gap: usize,
    isa_gap: usize,
    interpreter_gap: usize,
    threaded_gap: usize,
    other: usize,
}

#[derive(Debug, Serialize)]
struct Report {
    generated_unix_seconds: u64,
    iced_x86_version: &'static str,
    total_expected_code_values: usize,
    summary: Summary,
    by_mnemonic: BTreeMap<String, usize>,
    by_encoding: BTreeMap<String, usize>,
    records: Vec<CodeRecord>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out_dir)?;

    // Audit every Code variant resiliently: a probe/lift that panics on one
    // exotic instruction must not abort the whole enumeration. Each panic is
    // caught and recorded as PROBE_PANIC so the DB still completes and the
    // offending Code is observable.
    let mut records = Vec::new();
    for code in Code::values() {
        let info = code.op_code();
        if args.instructions_only && !info.is_instruction() {
            continue;
        }
        let rec = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| audit_code(code)))
            .unwrap_or_else(|_| panic_record(code));
        records.push(rec);
    }

    let summary = summarize(&records);
    let mut by_mnemonic = BTreeMap::new();
    let mut by_encoding = BTreeMap::new();
    for r in &records {
        *by_mnemonic.entry(r.mnemonic.clone()).or_insert(0) += 1;
        *by_encoding.entry(r.encoding.clone()).or_insert(0) += 1;
    }

    let report = Report {
        generated_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        iced_x86_version: "1.21",
        total_expected_code_values: 4936,
        summary,
        by_mnemonic,
        by_encoding,
        records,
    };

    let json = serde_json::to_string_pretty(&report)?;
    fs::write(args.out_dir.join("vm_coverage.json"), json)?;
    fs::write(args.out_dir.join("vm_coverage.csv"), render_csv(&report.records))?;
    fs::write(args.out_dir.join("vm_coverage.txt"), render_txt(&report))?;

    println!("BTG VM coverage audit complete");
    println!("  Code values scanned : {}", report.records.len());
    println!("  instructions        : {}", report.summary.instruction_code_values);
    println!("  full pipeline       : {}", report.summary.full_pipeline);
    println!("  unsupported        : {}", report.summary.unsupported);
    println!("  lift errors        : {}", report.summary.lift_error);
    println!("  ISA gaps           : {}", report.summary.isa_gap);
    println!("  interpreter gaps   : {}", report.summary.interpreter_gap);
    println!("  threaded gaps      : {}", report.summary.threaded_gap);
    println!("  output             : {}", args.out_dir.display());
    Ok(())
}

/// Minimal record for a Code whose probe/lift panicked (caught). Reads only the
/// op-code metadata, which is the same safe call `audit_code` makes first, so it
/// cannot itself trip the panicking path (probe build / lift).
fn panic_record(code: Code) -> CodeRecord {
    let info = code.op_code();
    CodeRecord {
        code_id: code as usize,
        code: format!("{:?}", code),
        mnemonic: format!("{:?}", info.mnemonic()),
        encoding: format!("{:?}", info.encoding()),
        is_instruction: info.is_instruction(),
        mode64: info.mode64(),
        privileged: info.is_privileged(),
        cpl0: info.cpl0(),
        cpl3: info.cpl3(),
        input_output: info.is_input_output(),
        cpuid_features: Vec::new(),
        op_kinds: info.op_kinds().iter().map(|k| format!("{:?}", k)).collect(),
        lock_allowed: info.can_use_lock_prefix(),
        rep_allowed: info.can_use_rep_prefix(),
        repne_allowed: info.can_use_repne_prefix(),
        flow_control: "<probe-panic>".to_string(),
        lifter: "PROBE_PANIC".to_string(),
        lift_error: Some("probe/lift panicked (caught)".to_string()),
        risc_ops: Vec::new(),
        capabilities: Vec::new(),
        isa: "N/A".to_string(),
        interpreter: "N/A".to_string(),
        threaded: "N/A".to_string(),
        status: "PROBE_PANIC".to_string(),
    }
}

fn audit_code(code: Code) -> CodeRecord {
    let info = code.op_code();
    let instruction = build_probe_instruction(code);
    let op_kinds = info
        .op_kinds()
        .iter()
        .map(|k| format!("{:?}", k))
        .collect::<Vec<_>>();

    let cpuid_features = instruction
        .as_ref()
        .map(|i| {
            i.cpuid_features()
                .iter()
                .map(|f| format!("{:?}", f))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut record = CodeRecord {
        code_id: code as usize,
        code: format!("{:?}", code),
        mnemonic: format!("{:?}", info.mnemonic()),
        encoding: format!("{:?}", info.encoding()),
        is_instruction: info.is_instruction(),
        mode64: info.mode64(),
        privileged: info.is_privileged(),
        cpl0: info.cpl0(),
        cpl3: info.cpl3(),
        input_output: info.is_input_output(),
        cpuid_features,
        op_kinds,
        lock_allowed: info.can_use_lock_prefix(),
        rep_allowed: info.can_use_rep_prefix(),
        repne_allowed: info.can_use_repne_prefix(),
        flow_control: instruction
            .as_ref()
            .map(|i| format!("{:?}", i.flow_control()))
            .unwrap_or_else(|| "<probe-build-failed>".to_string()),
        lifter: "NOT_RUN".to_string(),
        lift_error: None,
        risc_ops: Vec::new(),
        capabilities: Vec::new(),
        isa: "N/A".to_string(),
        interpreter: "N/A".to_string(),
        threaded: "N/A".to_string(),
        status: "UNKNOWN".to_string(),
    };

    if !info.is_instruction() {
        record.status = "NON_INSTRUCTION".to_string();
        record.lifter = "NOT_APPLICABLE".to_string();
        return record;
    }

    let Some(instruction) = instruction else {
        record.lifter = "PROBE_BUILD_ERROR".to_string();
        record.status = "LIFT_ERROR".to_string();
        record.lift_error = Some("could not construct representative Instruction".to_string());
        return record;
    };

    let mut lifter = RiscLifter::new();
    match lifter.lift_instruction(&instruction) {
        Ok(()) => {
            record.lifter = "SUPPORTED".to_string();
            let ops = lifter.desynth.instrs.iter().map(|m| m.op).collect::<Vec<_>>();
            let unique = ops
                .iter()
                .map(|op| format!("{} ({op:?})", op.kind().stable_name()))
                .collect::<BTreeSet<_>>();
            record.risc_ops = unique.into_iter().collect();

            let mut caps = Vec::new();
            for op in ops {
                let c = capabilities(op);
                caps.push(OpCapability {
                    op: format!("{op:?}"),
                    kind: op.kind().stable_name().to_string(),
                    evaluator: c.evaluator,
                    poly_codec: c.poly_codec,
                    poly_interpreter: c.poly_interpreter,
                    production_threaded: c.production_threaded,
                    reads_flags: c.reads_flags,
                    writes_flags: c.writes_flags,
                    may_fault: c.may_fault,
                });
            }
            caps.sort_by(|a, b| a.op.cmp(&b.op));
            caps.dedup_by(|a, b| a.op == b.op);
            record.capabilities = caps;

            if record.risc_ops.is_empty() {
                record.isa = "N/A".to_string();
                record.interpreter = "N/A".to_string();
                record.threaded = "N/A".to_string();
                record.status = "LIFTED_NO_MICRO_OP".to_string();
                return record;
            }

            record.isa = if record.capabilities.iter().all(|c| c.poly_codec) {
                "SUPPORTED"
            } else {
                "GAP"
            }
            .to_string();
            record.interpreter = if record.capabilities.iter().all(|c| c.poly_interpreter) {
                "SUPPORTED"
            } else {
                "GAP"
            }
            .to_string();
            record.threaded = if record.capabilities.iter().all(|c| c.production_threaded) {
                "SUPPORTED"
            } else {
                "GAP"
            }
            .to_string();

            record.status = if !record.capabilities.iter().all(|c| c.evaluator) {
                "EVALUATOR_GAP"
            } else if record.capabilities.iter().any(|c| !c.poly_codec) {
                "ISA_GAP"
            } else if record.capabilities.iter().any(|c| !c.poly_interpreter) {
                "INTERPRETER_GAP"
            } else if record.capabilities.iter().any(|c| !c.production_threaded) {
                "THREADED_GAP"
            } else {
                "FULL_PIPELINE"
            }
            .to_string();
        }
        Err(err) => {
            let msg = format!("{err:#}");
            let unsupported = msg.contains("unsupported opcode")
                || msg.contains("unsupported")
                || msg.contains("not supported");
            record.lifter = if unsupported { "UNSUPPORTED" } else { "ERROR" }.to_string();
            record.lift_error = Some(msg);
            record.status = if unsupported {
                "UNSUPPORTED".to_string()
            } else {
                "LIFT_ERROR".to_string()
            };
        }
    }

    record
}

fn build_probe_instruction(code: Code) -> Option<Instruction> {
    if !code.op_code().is_instruction() {
        return None;
    }

    let mut inst = Instruction::with(code);
    inst.set_ip(0x0000_0000_0040_1000);

    for (idx, kind) in code.op_code().op_kinds().iter().copied().enumerate() {
        let actual = actual_op_kind(kind);
        inst.set_op_kind(idx as u32, actual);
        populate_operand(&mut inst, idx as u32, kind, actual);
    }

    Some(inst)
}

fn actual_op_kind(kind: OpCodeOperandKind) -> OpKind {
    use OpCodeOperandKind::*;
    match kind {
        None => OpKind::Register, // never used when op_count excludes the slot
        farbr2_2 => OpKind::FarBranch16,
        farbr4_2 => OpKind::FarBranch32,
        mem_offs | mem | mem_mpx | mem_mib | mem_vsib32x | mem_vsib64x | mem_vsib32y
        | mem_vsib64y | mem_vsib32z | mem_vsib64z | r8_or_mem | r16_or_mem | r32_or_mem
        | r32_or_mem_mpx | r64_or_mem | r64_or_mem_mpx | mm_or_mem | xmm_or_mem | ymm_or_mem
        | zmm_or_mem | bnd_or_mem_mpx | k_or_mem | r16_reg_mem | r32_reg_mem => OpKind::Memory,
        r8_reg | r8_opcode | r16_reg | r16_rm | r16_opcode | r32_reg | r32_vvvv | r32_rm
        | r32_opcode | r64_reg | r64_rm | r64_opcode | r64_vvvv | seg_reg | k_reg | kp1_reg
        | k_rm | k_vvvv | mm_reg | mm_rm | xmm_reg | xmm_rm | xmm_vvvv | xmmp3_vvvv
        | xmm_is4 | xmm_is5 | ymm_reg | ymm_rm | ymm_vvvv | ymm_is4 | ymm_is5 | zmm_reg
        | zmm_rm | zmm_vvvv | zmmp3_vvvv | cr_reg | dr_reg | tr_reg | bnd_reg | es | cs | ss
        | ds | fs | gs | al | cl | ax | dx | eax | rax | st0 | sti_opcode | tmm_reg | tmm_rm
        | tmm_vvvv => OpKind::Register,
        imm4_m2z | imm8 | imm8_const_1 => OpKind::Immediate8,
        imm8sex16 => OpKind::Immediate8to16,
        imm8sex32 => OpKind::Immediate8to32,
        imm8sex64 => OpKind::Immediate8to64,
        imm16 => OpKind::Immediate16,
        imm32 => OpKind::Immediate32,
        imm32sex64 => OpKind::Immediate32to64,
        imm64 => OpKind::Immediate64,
        seg_rSI => OpKind::MemorySegRSI,
        es_rDI => OpKind::MemoryESRDI,
        seg_rDI => OpKind::MemorySegRDI,
        seg_rBX_al => OpKind::MemorySegRSI,
        br16_1 | brdisp_2 => OpKind::NearBranch16,
        br32_1 | brdisp_4 => OpKind::NearBranch32,
        br64_1 => OpKind::NearBranch64,
        br16_2 => OpKind::NearBranch16,
        br32_4 => OpKind::NearBranch32,
        br64_4 => OpKind::NearBranch64,
        xbegin_2 => OpKind::NearBranch16,
        xbegin_4 => OpKind::NearBranch32,
        sibmem => OpKind::Memory,
        _ => OpKind::Register,
    }
}

fn populate_operand(inst: &mut Instruction, index: u32, kind: OpCodeOperandKind, actual: OpKind) {
    use OpCodeOperandKind::*;
    if matches!(actual, OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
        match actual {
            OpKind::NearBranch16 => inst.set_near_branch16(0x1100),
            OpKind::NearBranch32 => inst.set_near_branch32(0x1100),
            OpKind::NearBranch64 => inst.set_near_branch64(0x1100),
            _ => unreachable!(),
        }
        return;
    }
    if matches!(actual, OpKind::FarBranch16 | OpKind::FarBranch32) {
        match actual {
            OpKind::FarBranch16 => inst.set_far_branch16(0x1100),
            OpKind::FarBranch32 => inst.set_far_branch32(0x1100),
            _ => unreachable!(),
        }
        inst.set_far_branch_selector(0x33);
        return;
    }
    if matches!(
        actual,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    ) {
        match actual {
            OpKind::Immediate8 => inst.set_immediate8(1),
            OpKind::Immediate8_2nd => inst.set_immediate8_2nd(1),
            OpKind::Immediate16 => inst.set_immediate16(1),
            OpKind::Immediate32 => inst.set_immediate32(1),
            OpKind::Immediate64 => inst.set_immediate64(1),
            OpKind::Immediate8to16 => inst.set_immediate8to16(1),
            OpKind::Immediate8to32 => inst.set_immediate8to32(1),
            OpKind::Immediate8to64 => inst.set_immediate8to64(1),
            OpKind::Immediate32to64 => inst.set_immediate32to64(1),
            _ => unreachable!(),
        }
        return;
    }
    if matches!(
        actual,
        OpKind::Memory
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI
    ) {
        let (base, index_reg) = match kind {
            seg_rSI | seg_rBX_al => (Register::RBX, Register::RAX),
            es_rDI => (Register::RDI, Register::None),
            seg_rDI => (Register::RDI, Register::None),
            mem_vsib32x | mem_vsib64x => (Register::RAX, Register::XMM1),
            mem_vsib32y | mem_vsib64y => (Register::RAX, Register::YMM1),
            mem_vsib32z | mem_vsib64z => (Register::RAX, Register::ZMM1),
            _ => (Register::RAX, Register::None),
        };
        inst.set_memory_base(base);
        inst.set_memory_index(index_reg);
        inst.set_memory_index_scale(1);
        inst.set_memory_displacement64(0x2000);
        if matches!(kind, seg_rDI) {
            inst.set_segment_prefix(Register::DS);
        }
        return;
    }

    if actual == OpKind::Register {
        inst.set_op_register(index, register_for_kind(kind));
    }
}

fn register_for_kind(kind: OpCodeOperandKind) -> Register {
    use OpCodeOperandKind::*;
    match kind {
        al => Register::AL,
        cl => Register::CL,
        ax => Register::AX,
        dx => Register::DX,
        eax => Register::EAX,
        rax => Register::RAX,
        es => Register::ES,
        cs => Register::CS,
        ss => Register::SS,
        ds => Register::DS,
        fs => Register::FS,
        gs => Register::GS,
        cr_reg => Register::CR0,
        dr_reg => Register::DR0,
        tr_reg => Register::TR3,
        bnd_reg => Register::BND0,
        mm_reg | mm_rm | mm_or_mem => Register::MM0,
        xmm_reg | xmm_rm | xmm_vvvv | xmmp3_vvvv | xmm_is4 | xmm_is5 | xmm_or_mem => Register::XMM0,
        ymm_reg | ymm_rm | ymm_vvvv | ymm_is4 | ymm_is5 | ymm_or_mem => Register::YMM0,
        zmm_reg | zmm_rm | zmm_vvvv | zmmp3_vvvv | zmm_or_mem => Register::ZMM0,
        k_reg | kp1_reg | k_rm | k_vvvv | k_or_mem => Register::K1,
        tmm_reg | tmm_rm | tmm_vvvv => Register::TMM0,
        r8_opcode | r8_reg | r8_or_mem => Register::AL,
        r16_opcode | r16_reg | r16_rm | r16_or_mem => Register::AX,
        r32_opcode | r32_reg | r32_vvvv | r32_rm | r32_or_mem | r32_or_mem_mpx => Register::EAX,
        r64_opcode | r64_reg | r64_vvvv | r64_rm | r64_or_mem | r64_or_mem_mpx => Register::RAX,
        seg_reg => Register::DS,
        st0 | sti_opcode => Register::ST0,
        _ => Register::RAX,
    }
}

fn summarize(records: &[CodeRecord]) -> Summary {
    let mut s = Summary {
        total_code_values: records.len(),
        ..Summary::default()
    };
    for r in records {
        if r.is_instruction {
            s.instruction_code_values += 1;
        } else {
            s.non_instruction_code_values += 1;
        }
        match r.status.as_str() {
            "FULL_PIPELINE" => s.full_pipeline += 1,
            "LIFTED_NO_MICRO_OP" => s.lifted_no_micro_op += 1,
            "UNSUPPORTED" => s.unsupported += 1,
            "LIFT_ERROR" => s.lift_error += 1,
            "EVALUATOR_GAP" => s.evaluator_gap += 1,
            "ISA_GAP" => s.isa_gap += 1,
            "INTERPRETER_GAP" => s.interpreter_gap += 1,
            "THREADED_GAP" => s.threaded_gap += 1,
            _ => s.other += 1,
        }
    }
    s
}

fn render_csv(records: &[CodeRecord]) -> String {
    let mut out = String::new();
    out.push_str("code_id,code,mnemonic,encoding,is_instruction,mode64,privileged,cpl0,cpl3,input_output,op_kinds,lifter,lift_error,risc_ops,isa,interpreter,threaded,status\n");
    for r in records {
        let row = [
            r.code_id.to_string(),
            r.code.clone(),
            r.mnemonic.clone(),
            r.encoding.clone(),
            r.is_instruction.to_string(),
            r.mode64.to_string(),
            r.privileged.to_string(),
            r.cpl0.to_string(),
            r.cpl3.to_string(),
            r.input_output.to_string(),
            r.op_kinds.join("|"),
            r.lifter.clone(),
            r.lift_error.clone().unwrap_or_default(),
            r.risc_ops.join("|"),
            r.isa.clone(),
            r.interpreter.clone(),
            r.threaded.clone(),
            r.status.clone(),
        ];
        let escaped = row.iter().map(|s| csv_escape(s)).collect::<Vec<_>>();
        out.push_str(&escaped.join(","));
        out.push('\n');
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn render_txt(report: &Report) -> String {
    let s = &report.summary;
    let mut out = String::new();
    writeln!(out, "BTG VM AUTOMATED CPU COVERAGE REPORT").unwrap();
    writeln!(out, "=================================").unwrap();
    writeln!(out, "iced-x86: {}", report.iced_x86_version).unwrap();
    writeln!(out, "Code values scanned: {}", s.total_code_values).unwrap();
    writeln!(out, "Expected Code enum count: {}", report.total_expected_code_values).unwrap();
    writeln!(out).unwrap();

    writeln!(out, "SUMMARY").unwrap();
    writeln!(out, "-------").unwrap();
    writeln!(out, "instructions       : {}", s.instruction_code_values).unwrap();
    writeln!(out, "non-instructions   : {}", s.non_instruction_code_values).unwrap();
    writeln!(out, "FULL_PIPELINE      : {}", s.full_pipeline).unwrap();
    writeln!(out, "LIFTED_NO_MICRO_OP : {}", s.lifted_no_micro_op).unwrap();
    writeln!(out, "UNSUPPORTED        : {}", s.unsupported).unwrap();
    writeln!(out, "LIFT_ERROR         : {}", s.lift_error).unwrap();
    writeln!(out, "EVALUATOR_GAP      : {}", s.evaluator_gap).unwrap();
    writeln!(out, "ISA_GAP            : {}", s.isa_gap).unwrap();
    writeln!(out, "INTERPRETER_GAP    : {}", s.interpreter_gap).unwrap();
    writeln!(out, "THREADED_GAP       : {}", s.threaded_gap).unwrap();
    writeln!(out, "OTHER              : {}", s.other).unwrap();
    writeln!(out).unwrap();

    writeln!(out, "BY ENCODING").unwrap();
    writeln!(out, "-----------").unwrap();
    for (encoding, count) in &report.by_encoding {
        writeln!(out, "{encoding:12} {count}").unwrap();
    }
    writeln!(out).unwrap();

    writeln!(out, "UNSUPPORTED / GAP CODE VARIANTS").unwrap();
    writeln!(out, "-------------------------------").unwrap();
    for r in &report.records {
        if matches!(
            r.status.as_str(),
            "UNSUPPORTED" | "LIFT_ERROR" | "EVALUATOR_GAP" | "ISA_GAP" | "INTERPRETER_GAP" | "THREADED_GAP"
        ) {
            writeln!(
                out,
                "{:04} {:32} {:16} {:12} {:18} lifter={} risc=[{}] isa={} interp={} threaded={}",
                r.code_id,
                r.code,
                r.mnemonic,
                r.encoding,
                r.status,
                r.lifter,
                r.risc_ops.join(";"),
                r.isa,
                r.interpreter,
                r.threaded
            )
            .unwrap();
            if let Some(err) = &r.lift_error {
                writeln!(out, "      reason: {err}").unwrap();
            }
        }
    }
    writeln!(out).unwrap();

    writeln!(out, "FULL PIPELINE CODE VARIANTS").unwrap();
    writeln!(out, "---------------------------").unwrap();
    for r in &report.records {
        if r.status == "FULL_PIPELINE" || r.status == "LIFTED_NO_MICRO_OP" {
            writeln!(out, "{:04} {:32} {:16} {}", r.code_id, r.code, r.mnemonic, r.status).unwrap();
        }
    }
    writeln!(out).unwrap();
    writeln!(out, "NOTES").unwrap();
    writeln!(out, "-----").unwrap();
    writeln!(out, "1. FULL_PIPELINE means the real BTG RiscLifter succeeded and every emitted RiscOp passed the canonical capability registry.").unwrap();
    writeln!(out, "2. ISA/Interpreter/Threaded are reported from RiscOpCapabilities, whose commercial contract is backed by VirtualIsaSpec::is_encodable().").unwrap();
    writeln!(out, "3. This is a representative operand probe. It tests each iced-x86 Code variant, not every legal operand permutation or every prefix combination.").unwrap();
    writeln!(out, "4. A LIFT_ERROR means the opcode reached the lifter but the generic probe could not form a valid/processable semantic instance; it is not automatically equivalent to UNSUPPORTED.").unwrap();
    writeln!(out, "5. For production compatibility, pair this report with real binary corpus tests and semantic differential tests.").unwrap();
    out
}
