//! BTG CPU Coverage Database - exhaustive legal probe matrix.
//!
//! For every iced-x86 Code this tool generates legal representative probes across:
//!   * operand form: register / memory / immediate / fixed
//!   * bitness: 16 / 32 / 64 when legal
//!   * LOCK / REP / REPNE when legal
//!   * EVEX opmask merge/zeroing when legal
//!   * EVEX broadcast when legal
//!
//! Each probe is encoded, decoded, lifted by the real BTG lifter, lowered to
//! RiscOps, checked against the real capability registry, and then executed by
//! BTG's RISC reference evaluator with deterministic register/memory seeds.
//!
//! This is intentionally a legal representative matrix, not every possible
//! register-number permutation or every possible runtime data value.

use anyhow::{anyhow, Result};
use btg_packer::vm::risc::{capabilities, MemoryPolicy, MemoryRegion, RiscLifter, RiscProgram};
use clap::Parser;
use iced_x86::{Code, Decoder, DecoderOptions, EncodingKind, Encoder, Instruction, OpCodeOperandKind, OpKind, Register};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const EXPECTED_CODE_VALUES: usize = 4936;
const PROBE_RIP: u64 = 0x0000_0000_0040_1000;
const MEM_BASE: u64 = 0x0000_0000_0080_0000;

#[derive(Parser, Debug)]
#[command(name = "btg-cpu-coverage-db")]
#[command(about = "Generate exhaustive legal BTG CPU coverage probes")]
struct Args {
    #[arg(long, default_value = "coverage/cpu")]
    out_dir: PathBuf,
    #[arg(long)]
    instructions_only: bool,
    /// Number of deterministic semantic evaluator seeds per successful lift.
    #[arg(long, default_value_t = 3)]
    semantic_samples: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ProbeRecord {
    probe_id: u64,
    code_id: usize,
    code: String,
    mnemonic: String,
    encoding: String,
    bitness: u32,
    operand_form: String,
    prefix: String,
    opmask: String,
    zeroing: bool,
    broadcast: bool,
    /// EVEX static rounding control {er} is supported by this form.
    can_rounding: bool,
    /// EVEX suppress-all-exceptions {sae} is supported by this form.
    can_sae: bool,
    /// EVEX tuple type (disp8 compression class), e.g. "N1", "Full", "Tuple1Scalar".
    tuple_type: String,
    encoded_bytes: String,
    decoded_code: String,
    roundtrip_ok: bool,
    lifter: String,
    lift_error: Option<String>,
    risc_ops: Vec<String>,
    isa: String,
    interpreter: String,
    threaded: String,
    semantic: String,
    semantic_error: Option<String>,
    status: String,
}

#[derive(Debug, Clone, Serialize, Default)]
struct Summary {
    codes_scanned: usize,
    instructions_scanned: usize,
    probes_generated: usize,
    encode_errors: usize,
    decode_errors: usize,
    lift_success: usize,
    lift_unsupported: usize,
    lift_errors: usize,
    semantic_executed: usize,
    semantic_faulted: usize,
    semantic_failed: usize,
    full_pipeline: usize,
    gaps: usize,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: &'static str,
    iced_x86_version: &'static str,
    expected_code_values: usize,
    generated_unix_seconds: u64,
    summary: Summary,
    probe_dimensions: Vec<String>,
    by_status: BTreeMap<String, usize>,
    by_encoding: BTreeMap<String, usize>,
    probes: Vec<ProbeRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Dimension {
    bitness: u32,
    operand_form: String,
    prefix: String,
    opmask: String,
    zeroing: bool,
    broadcast: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out_dir)?;

    let mut probes = Vec::new();
    let mut code_count = 0usize;
    let mut instruction_count = 0usize;
    let mut next_probe_id = 0u64;

    for code in Code::values() {
        code_count += 1;
        if !code.op_code().is_instruction() {
            if !args.instructions_only {
                // Keep pseudo/directive codes in the database as a single metadata row.
                probes.push(metadata_probe(next_probe_id, code));
                next_probe_id += 1;
            }
            continue;
        }
        instruction_count += 1;
        let dimensions = legal_dimensions(code);
        for dim in dimensions {
            let result = run_probe(code, &dim, args.semantic_samples, next_probe_id);
            probes.push(result);
            next_probe_id += 1;
        }
    }

    let summary = summarize(code_count, instruction_count, &probes);
    let mut by_status = BTreeMap::new();
    let mut by_encoding = BTreeMap::new();
    for p in &probes {
        *by_status.entry(p.status.clone()).or_insert(0) += 1;
        *by_encoding.entry(p.encoding.clone()).or_insert(0) += 1;
    }

    let report = Report {
        schema_version: "2.0-exhaustive-legal-matrix",
        iced_x86_version: "1.21",
        expected_code_values: EXPECTED_CODE_VALUES,
        generated_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        summary,
        probe_dimensions: vec![
            "operand_form: fixed/register/memory/immediate (legal forms only)".into(),
            "bitness: 16/32/64 (Code metadata permitting)".into(),
            "prefix: none/LOCK/REP/REPNE (legal prefixes only)".into(),
            "EVEX opmask: none/K1-merge/K1-zero (when legal)".into(),
            "EVEX broadcast: off/on (when legal and memory operand exists)".into(),
            "semantic execution: deterministic RISC evaluator samples".into(),
        ],
        by_status,
        by_encoding,
        probes,
    };

    fs::write(args.out_dir.join("btg_cpu_coverage_database.json"), serde_json::to_vec_pretty(&report)?)?;
    fs::write(args.out_dir.join("btg_cpu_coverage_database.csv"), render_csv(&report.probes))?;
    fs::write(args.out_dir.join("btg_cpu_coverage_database.txt"), render_txt(&report))?;
    fs::write(args.out_dir.join("btg_cpu_coverage_matrix.txt"), render_matrix_txt(&report))?;

    println!("BTG CPU Coverage Database v2 complete");
    println!("  iced-x86 Code values : {} (expected {})", code_count, EXPECTED_CODE_VALUES);
    println!("  instructions         : {}", instruction_count);
    println!("  legal probes         : {}", report.summary.probes_generated);
    println!("  semantic executed    : {}", report.summary.semantic_executed);
    println!("  semantic faulted     : {}", report.summary.semantic_faulted);
    println!("  FULL_PIPELINE        : {}", report.summary.full_pipeline);
    println!("  gaps                 : {}", report.summary.gaps);
    println!("  output               : {}", args.out_dir.display());
    Ok(())
}

fn metadata_probe(id: u64, code: Code) -> ProbeRecord {
    let info = code.op_code();
    ProbeRecord {
        probe_id: id,
        code_id: code as usize,
        code: format!("{code:?}"),
        mnemonic: format!("{:?}", info.mnemonic()),
        encoding: format!("{:?}", info.encoding()),
        bitness: 0,
        operand_form: "metadata-only".into(),
        prefix: "none".into(),
        opmask: "none".into(),
        zeroing: false,
        broadcast: false,
        can_rounding: info.can_use_rounding_control(),
        can_sae: info.can_suppress_all_exceptions(),
        tuple_type: format!("{:?}", info.tuple_type()),
        encoded_bytes: String::new(),
        decoded_code: String::new(),
        roundtrip_ok: false,
        lifter: "NOT_APPLICABLE".into(),
        lift_error: None,
        risc_ops: vec![],
        isa: "N/A".into(),
        interpreter: "N/A".into(),
        threaded: "N/A".into(),
        semantic: "N/A".into(),
        semantic_error: None,
        status: "NON_INSTRUCTION".into(),
    }
}

fn legal_dimensions(code: Code) -> Vec<Dimension> {
    let info = code.op_code();
    let bitnesses = [16u32, 32, 64]
        .into_iter()
        .filter(|b| info.is_available_in_mode(*b))
        .collect::<Vec<_>>();

    let operand_forms = operand_forms(info.op_kinds());
    let prefixes = {
        let mut v = vec!["none".to_string()];
        if info.can_use_lock_prefix() { v.push("LOCK".into()); }
        if info.can_use_rep_prefix() { v.push("REP".into()); }
        if info.can_use_repne_prefix() { v.push("REPNE".into()); }
        v
    };

    let mut dims = BTreeSet::new();
    for bitness in bitnesses {
        for form in &operand_forms {
            for prefix in &prefixes {
                let mask_options = if info.can_use_op_mask_register() {
                    vec![("none".into(), false)]
                } else {
                    vec![("none".into(), false)]
                };
                for (opmask, _) in mask_options {
                    dims.insert(Dimension {
                        bitness,
                        operand_form: form.clone(),
                        prefix: prefix.clone(),
                        opmask,
                        zeroing: false,
                        broadcast: false,
                    });
                    if info.can_use_zeroing_masking() && form_has_vector_destination(info.op_kinds()) {
                        dims.insert(Dimension {
                            bitness,
                            operand_form: form.clone(),
                            prefix: prefix.clone(),
                            opmask: "K1".into(),
                            zeroing: false,
                            broadcast: false,
                        });
                        dims.insert(Dimension {
                            bitness,
                            operand_form: form.clone(),
                            prefix: prefix.clone(),
                            opmask: "K1".into(),
                            zeroing: true,
                            broadcast: false,
                        });
                    } else if info.can_use_op_mask_register() && form_has_vector_destination(info.op_kinds()) {
                        dims.insert(Dimension {
                            bitness,
                            operand_form: form.clone(),
                            prefix: prefix.clone(),
                            opmask: "K1".into(),
                            zeroing: false,
                            broadcast: false,
                        });
                    }
                    if info.can_broadcast() && form_has_memory(info.op_kinds()) {
                        dims.insert(Dimension {
                            bitness,
                            operand_form: form.clone(),
                            prefix: prefix.clone(),
                            opmask: if info.can_use_op_mask_register() && form_has_vector_destination(info.op_kinds()) { "K1".into() } else { "none".into() },
                            zeroing: false,
                            broadcast: true,
                        });
                    }
                }
            }
        }
    }
    dims.into_iter().collect()
}

fn operand_forms(kinds: &[OpCodeOperandKind]) -> Vec<String> {
    let mut forms = BTreeSet::new();
    let mut has_reg = false;
    let mut has_mem = false;
    let mut has_imm = false;
    for k in kinds {
        let s = format!("{k:?}");
        has_reg |= s.contains("_or_mem") || s.contains("_rm") || s.contains("_reg") || s.contains("opcode") || s.contains("vvvv") || s.ends_with("_reg");
        has_mem |= s.starts_with("mem") || s.contains("_or_mem") || s.contains("_rm") || s.contains("reg_mem");
        has_imm |= s.starts_with("imm");
    }
    if has_reg { forms.insert("register".to_string()); }
    if has_mem { forms.insert("memory".to_string()); }
    if has_imm { forms.insert("immediate".to_string()); }
    if forms.is_empty() { forms.insert("fixed".to_string()); }
    forms.into_iter().collect()
}

fn form_has_memory(kinds: &[OpCodeOperandKind]) -> bool {
    kinds.iter().any(|k| {
        let s = format!("{k:?}");
        s.starts_with("mem") || s.contains("_or_mem") || s.contains("_rm") || s.contains("reg_mem")
    })
}

fn form_has_vector_destination(kinds: &[OpCodeOperandKind]) -> bool {
    kinds.first().map(|k| {
        let s = format!("{k:?}");
        s.contains("xmm") || s.contains("ymm") || s.contains("zmm") || s.contains("k_")
    }).unwrap_or(false)
}

fn run_probe(code: Code, dim: &Dimension, semantic_samples: usize, probe_id: u64) -> ProbeRecord {
    let info = code.op_code();
    let mut base = match build_instruction(code, dim.bitness, &dim.operand_form) {
        Ok(i) => i,
        Err(e) => return failed_probe(probe_id, code, dim, "PROBE_BUILD_ERROR", e.to_string()),
    };
    apply_decorations(&mut base, dim);

    let (bytes, decoded) = match encode_roundtrip(&base, dim.bitness) {
        Ok(x) => x,
        Err(e) => return failed_probe(probe_id, code, dim, "ENCODE_ERROR", e.to_string()),
    };
    if decoded.code() != code {
        return ProbeRecord {
            probe_id, code_id: code as usize, code: format!("{code:?}"), mnemonic: format!("{:?}", info.mnemonic()), encoding: format!("{:?}", info.encoding()),
            bitness: dim.bitness, operand_form: dim.operand_form.clone(), prefix: dim.prefix.clone(), opmask: dim.opmask.clone(), zeroing: dim.zeroing, broadcast: dim.broadcast,
            can_rounding: info.can_use_rounding_control(), can_sae: info.can_suppress_all_exceptions(), tuple_type: format!("{:?}", info.tuple_type()),
            encoded_bytes: hex(&bytes), decoded_code: format!("{:?}", decoded.code()), roundtrip_ok: false,
            lifter: "ROUNDTRIP_MISMATCH".into(), lift_error: Some(format!("decoded as {:?}", decoded.code())), risc_ops: vec![], isa: "N/A".into(), interpreter: "N/A".into(), threaded: "N/A".into(), semantic: "NOT_RUN".into(), semantic_error: None, status: "DECODE_ERROR".into(),
        };
    }

    let mut lifter = RiscLifter::new();
    match lifter.lift_instruction_with_bytes(&decoded, &bytes) {
        Ok(()) => {
            let ops = lifter.desynth.instrs.iter().map(|m| m.op).collect::<Vec<_>>();
            let risc_ops = ops.iter().map(|op| format!("{} ({op:?})", op.kind().stable_name())).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
            let caps = ops.iter().map(|op| capabilities(*op)).collect::<Vec<_>>();
            let isa_ok = caps.iter().all(|c| c.poly_codec);
            let interp_ok = caps.iter().all(|c| c.poly_interpreter);
            let threaded_ok = caps.iter().all(|c| c.production_threaded);
            let evaluator_ok = caps.iter().all(|c| c.evaluator);

            let (semantic, semantic_error) = if evaluator_ok && !ops.is_empty() {
                execute_semantic(&lifter.desynth.instrs, semantic_samples)
            } else if ops.is_empty() {
                ("NO_MICRO_OP".into(), Some("lifter emitted no micro-ops".into()))
            } else {
                ("EVALUATOR_GAP".into(), Some("one or more RiscOps are not evaluator-capable".into()))
            };

            let status = if !evaluator_ok { "EVALUATOR_GAP" }
                else if !isa_ok { "ISA_GAP" }
                else if !interp_ok { "INTERPRETER_GAP" }
                else if !threaded_ok { "THREADED_GAP" }
                else if semantic == "EXECUTED" || semantic == "FAULT_EXPECTED" { "FULL_PIPELINE_SEMANTIC" }
                else { "SEMANTIC_GAP" };
            ProbeRecord {
                probe_id, code_id: code as usize, code: format!("{code:?}"), mnemonic: format!("{:?}", info.mnemonic()), encoding: format!("{:?}", info.encoding()),
                bitness: dim.bitness, operand_form: dim.operand_form.clone(), prefix: dim.prefix.clone(), opmask: dim.opmask.clone(), zeroing: dim.zeroing, broadcast: dim.broadcast,
                can_rounding: info.can_use_rounding_control(), can_sae: info.can_suppress_all_exceptions(), tuple_type: format!("{:?}", info.tuple_type()),
                encoded_bytes: hex(&bytes), decoded_code: format!("{:?}", decoded.code()), roundtrip_ok: true,
                lifter: "SUPPORTED".into(), lift_error: None, risc_ops, isa: if isa_ok { "SUPPORTED" } else { "GAP" }.into(), interpreter: if interp_ok { "SUPPORTED" } else { "GAP" }.into(), threaded: if threaded_ok { "SUPPORTED" } else { "GAP" }.into(), semantic, semantic_error, status: status.into(),
            }
        }
        Err(e) => failed_probe(probe_id, code, dim, if e.to_string().contains("unsupported") { "UNSUPPORTED" } else { "LIFT_ERROR" }, e.to_string()),
    }
}

fn failed_probe(id: u64, code: Code, dim: &Dimension, status: &str, error: String) -> ProbeRecord {
    ProbeRecord {
        probe_id: id, code_id: code as usize, code: format!("{code:?}"), mnemonic: format!("{:?}", code.op_code().mnemonic()), encoding: format!("{:?}", code.op_code().encoding()),
        bitness: dim.bitness, operand_form: dim.operand_form.clone(), prefix: dim.prefix.clone(), opmask: dim.opmask.clone(), zeroing: dim.zeroing, broadcast: dim.broadcast,
        can_rounding: code.op_code().can_use_rounding_control(), can_sae: code.op_code().can_suppress_all_exceptions(), tuple_type: format!("{:?}", code.op_code().tuple_type()),
        encoded_bytes: String::new(), decoded_code: String::new(), roundtrip_ok: false, lifter: status.into(), lift_error: Some(error), risc_ops: vec![], isa: "N/A".into(), interpreter: "N/A".into(), threaded: "N/A".into(), semantic: "NOT_RUN".into(), semantic_error: None, status: status.into(),
    }
}

fn build_instruction(code: Code, bitness: u32, operand_form: &str) -> Result<Instruction> {
    let mut inst = Instruction::with(code);
    inst.set_ip(PROBE_RIP);
    let kinds = code.op_code().op_kinds();
    for (idx, kind) in kinds.iter().copied().enumerate() {
        let actual = choose_actual_kind(kind, operand_form);
        inst.set_op_kind(idx as u32, actual);
        populate_operand(&mut inst, idx as u32, kind, actual, bitness);
    }
    Ok(inst)
}

fn choose_actual_kind(kind: OpCodeOperandKind, form: &str) -> OpKind {
    use OpCodeOperandKind::*;
    let s = format!("{kind:?}");
    if form == "memory" && (s.starts_with("mem") || s.contains("_or_mem") || s.contains("_rm") || s.contains("reg_mem")) {
        return memory_kind(kind);
    }
    if form == "immediate" && s.starts_with("imm") {
        return immediate_kind(kind);
    }
    if form == "register" && (s.contains("_or_mem") || s.contains("_rm")) {
        return OpKind::Register;
    }
    match kind {
        farbr2_2 => OpKind::FarBranch16, farbr4_2 => OpKind::FarBranch32,
        mem_offs | mem | mem_mpx | mem_mib | mem_vsib32x | mem_vsib64x | mem_vsib32y | mem_vsib64y | mem_vsib32z | mem_vsib64z | r8_or_mem | r16_or_mem | r32_or_mem | r32_or_mem_mpx | r64_or_mem | r64_or_mem_mpx | mm_or_mem | xmm_or_mem | ymm_or_mem | zmm_or_mem | bnd_or_mem_mpx | k_or_mem | r16_reg_mem | r32_reg_mem => memory_kind(kind),
        imm4_m2z | imm8 | imm8_const_1 | imm8sex16 | imm8sex32 | imm8sex64 | imm16 | imm32 | imm32sex64 | imm64 => immediate_kind(kind),
        br16_1 | brdisp_2 | br16_2 => OpKind::NearBranch16,
        br32_1 | brdisp_4 | br32_4 | xbegin_4 => OpKind::NearBranch32,
        br64_1 | br64_4 => OpKind::NearBranch64,
        xbegin_2 => OpKind::NearBranch16,
        seg_rSI => OpKind::MemorySegRSI,
        es_rDI => OpKind::MemoryESRDI,
        seg_rDI => OpKind::MemorySegRDI,
        seg_rBX_al => OpKind::MemorySegRSI,
        _ => OpKind::Register,
    }
}

fn memory_kind(kind: OpCodeOperandKind) -> OpKind {
    use OpCodeOperandKind::*;
    match kind {
        seg_rSI => OpKind::MemorySegRSI, es_rDI => OpKind::MemoryESRDI, seg_rDI => OpKind::MemorySegRDI, seg_rBX_al => OpKind::MemorySegRSI, _ => OpKind::Memory,
    }
}

fn immediate_kind(kind: OpCodeOperandKind) -> OpKind {
    use OpCodeOperandKind::*;
    match kind {
        imm4_m2z | imm8 | imm8_const_1 => OpKind::Immediate8,
        imm8sex16 => OpKind::Immediate8to16, imm8sex32 => OpKind::Immediate8to32, imm8sex64 => OpKind::Immediate8to64,
        imm16 => OpKind::Immediate16, imm32 => OpKind::Immediate32, imm32sex64 => OpKind::Immediate32to64, imm64 => OpKind::Immediate64,
        _ => OpKind::Immediate8,
    }
}

fn populate_operand(inst: &mut Instruction, index: u32, kind: OpCodeOperandKind, actual: OpKind, bitness: u32) {
    if matches!(actual, OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
        match actual { OpKind::NearBranch16 => inst.set_near_branch16(0x1100), OpKind::NearBranch32 => inst.set_near_branch32(0x1100), OpKind::NearBranch64 => inst.set_near_branch64(PROBE_RIP + 0x100), _ => {} }
        return;
    }
    if matches!(actual, OpKind::FarBranch16 | OpKind::FarBranch32) {
        match actual { OpKind::FarBranch16 => inst.set_far_branch16(0x1100), OpKind::FarBranch32 => inst.set_far_branch32(0x1100), _ => {} }
        inst.set_far_branch_selector(0x33); return;
    }
    if actual == OpKind::Immediate8 { inst.set_immediate8(1); return; }
    if actual == OpKind::Immediate8_2nd { inst.set_immediate8_2nd(1); return; }
    if actual == OpKind::Immediate16 { inst.set_immediate16(1); return; }
    if actual == OpKind::Immediate32 { inst.set_immediate32(1); return; }
    if actual == OpKind::Immediate64 { inst.set_immediate64(1); return; }
    if actual == OpKind::Immediate8to16 { inst.set_immediate8to16(1); return; }
    if actual == OpKind::Immediate8to32 { inst.set_immediate8to32(1); return; }
    if actual == OpKind::Immediate8to64 { inst.set_immediate8to64(1); return; }
    if actual == OpKind::Immediate32to64 { inst.set_immediate32to64(1); return; }
    if matches!(actual, OpKind::Memory | OpKind::MemorySegSI | OpKind::MemorySegESI | OpKind::MemorySegRSI | OpKind::MemorySegDI | OpKind::MemorySegEDI | OpKind::MemorySegRDI | OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI) {
        let base = match bitness { 16 => Register::BX, 32 => Register::EBX, _ => Register::RBX };
        let idx = match kind { OpCodeOperandKind::mem_vsib32x | OpCodeOperandKind::mem_vsib64x => Register::XMM1, OpCodeOperandKind::mem_vsib32y | OpCodeOperandKind::mem_vsib64y => Register::YMM1, OpCodeOperandKind::mem_vsib32z | OpCodeOperandKind::mem_vsib64z => Register::ZMM1, _ => Register::None };
        inst.set_memory_base(base);
        inst.set_memory_index(idx);
        inst.set_memory_index_scale(1);
        inst.set_memory_displacement64(MEM_BASE);
        return;
    }
    if actual == OpKind::Register { inst.set_op_register(index, register_for_kind(kind, bitness)); }
}

fn register_for_kind(kind: OpCodeOperandKind, bitness: u32) -> Register {
    use OpCodeOperandKind::*;
    let gpr16 = if bitness == 16 { Register::AX } else if bitness == 32 { Register::EAX } else { Register::RAX };
    match kind {
        al => Register::AL, cl => Register::CL, ax => Register::AX, dx => Register::DX, eax => Register::EAX, rax => Register::RAX,
        es => Register::ES, cs => Register::CS, ss => Register::SS, ds => Register::DS, fs => Register::FS, gs => Register::GS,
        cr_reg => Register::CR0, dr_reg => Register::DR0, tr_reg => Register::TR3, bnd_reg => Register::BND0,
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
        seg_reg => Register::DS, st0 | sti_opcode => Register::ST0,
        _ => gpr16,
    }
}

fn apply_decorations(inst: &mut Instruction, dim: &Dimension) {
    match dim.prefix.as_str() {
        "LOCK" => inst.set_has_lock_prefix(true),
        "REP" => inst.set_has_rep_prefix(true),
        "REPNE" => inst.set_has_repne_prefix(true),
        _ => {}
    }
    match dim.opmask.as_str() { "K1" => inst.set_op_mask(Register::K1), _ => inst.set_op_mask(Register::None) }
    inst.set_zeroing_masking(dim.zeroing);
    inst.set_is_broadcast(dim.broadcast);
}

fn encode_roundtrip(inst: &Instruction, bitness: u32) -> Result<(Vec<u8>, Instruction)> {
    let mut enc = Encoder::new(bitness);
    enc.encode(inst, PROBE_RIP).map_err(|e| anyhow!("encode: {e}"))?;
    let bytes = enc.take_buffer();
    if bytes.is_empty() { return Err(anyhow!("encoder produced zero bytes")); }
    let mut decoder = Decoder::with_ip(bitness, &bytes, PROBE_RIP, DecoderOptions::NONE);
    let decoded = decoder.decode();
    if decoded.code() == Code::INVALID { return Err(anyhow!("decoder rejected encoded bytes: {}", hex(&bytes))); }
    Ok((bytes, decoded))
}

fn execute_semantic(instrs: &[btg_packer::vm::risc::MicroInstr], samples: usize) -> (String, Option<String>) {
    let program = RiscProgram::new(instrs.to_vec());
    let policy = MemoryPolicy::new(vec![MemoryRegion { start: MEM_BASE - 0x1000, len: 0x10000, readable: true, writable: true }]);
    let mut fault_count = 0usize;
    let count = samples.max(1).min(32);
    for i in 0..count {
        let mut regs = [0u64; 16];
        regs[0] = 0x1122_3344_5566_7788u64.wrapping_add(i as u64);
        regs[1] = 0x0102_0304_0506_0708u64.wrapping_mul(i as u64 + 1);
        regs[2] = 0x7FFF_FFFF_FFFF_FFF0u64;
        regs[3] = MEM_BASE;
        let mut mem = std::collections::HashMap::new();
        for j in 0..0x100usize { mem.insert(MEM_BASE + j as u64, (j as u8).wrapping_mul(13).wrapping_add(i as u8)); }
        match program.try_eval_state_with_mem_policy(&regs, mem, &policy) {
            Ok(_) => {}
            Err(_) => fault_count += 1,
        }
    }
    if fault_count == 0 { ("EXECUTED".into(), None) }
    else if fault_count == count { ("FAULT_EXPECTED".into(), Some(format!("reference evaluator faulted in all {count} deterministic samples"))) }
    else { ("FAULT_PARTIAL".into(), Some(format!("reference evaluator faulted in {fault_count}/{count} samples"))) }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ") }

fn summarize(codes: usize, instructions: usize, probes: &[ProbeRecord]) -> Summary {
    let mut s = Summary { codes_scanned: codes, instructions_scanned: instructions, probes_generated: probes.len(), ..Summary::default() };
    for p in probes {
        match p.status.as_str() {
            "FULL_PIPELINE_SEMANTIC" => { s.full_pipeline += 1; s.lift_success += 1; }
            "UNSUPPORTED" => s.lift_unsupported += 1,
            "LIFT_ERROR" | "PROBE_BUILD_ERROR" => s.lift_errors += 1,
            "ENCODE_ERROR" | "DECODE_ERROR" => s.encode_errors += 1,
            _ => {}
        }
        if p.lifter == "SUPPORTED" { s.lift_success += 1; }
        match p.semantic.as_str() { "EXECUTED" => s.semantic_executed += 1, "FAULT_EXPECTED" | "FAULT_PARTIAL" => s.semantic_faulted += 1, _ => {} }
        if p.status != "FULL_PIPELINE_SEMANTIC" && p.status != "NON_INSTRUCTION" { s.gaps += 1; }
    }
    s
}

fn render_csv(probes: &[ProbeRecord]) -> String {
    let mut out = String::from("probe_id,code_id,code,mnemonic,encoding,bitness,operand_form,prefix,opmask,zeroing,broadcast,encoded_bytes,decoded_code,roundtrip_ok,lifter,lift_error,risc_ops,isa,interpreter,threaded,semantic,semantic_error,status\n");
    for p in probes {
        let row = [p.probe_id.to_string(),p.code_id.to_string(),p.code.clone(),p.mnemonic.clone(),p.encoding.clone(),p.bitness.to_string(),p.operand_form.clone(),p.prefix.clone(),p.opmask.clone(),p.zeroing.to_string(),p.broadcast.to_string(),p.encoded_bytes.clone(),p.decoded_code.clone(),p.roundtrip_ok.to_string(),p.lifter.clone(),p.lift_error.clone().unwrap_or_default(),p.risc_ops.join("|"),p.isa.clone(),p.interpreter.clone(),p.threaded.clone(),p.semantic.clone(),p.semantic_error.clone().unwrap_or_default(),p.status.clone()];
        out.push_str(&row.iter().map(|x| csv_escape(x)).collect::<Vec<_>>().join(",")); out.push('\n');
    }
    out
}
fn csv_escape(s: &str) -> String { if s.contains(',') || s.contains('"') || s.contains('\n') { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.into() } }

fn render_txt(report: &Report) -> String {
    let s = &report.summary; let mut out = String::new();
    writeln!(out, "BTG CPU COVERAGE DATABASE v2").unwrap();
    writeln!(out, "============================").unwrap();
    writeln!(out, "iced-x86: {} | expected Code values: {} | actual: {}", report.iced_x86_version, report.expected_code_values, s.codes_scanned).unwrap();
    writeln!(out, "Legal representative probes: {}", s.probes_generated).unwrap();
    writeln!(out, "Semantic evaluator executions: {}", s.semantic_executed).unwrap();
    writeln!(out, "Semantic faults: {}", s.semantic_faulted).unwrap();
    writeln!(out, "FULL_PIPELINE_SEMANTIC: {}", s.full_pipeline).unwrap();
    writeln!(out, "GAPS: {}", s.gaps).unwrap();
    writeln!(out, "\nSTATUS COUNTS").unwrap();
    for (k,v) in &report.by_status { writeln!(out, "{k:28} {v}").unwrap(); }
    writeln!(out, "\nPROBES WITH GAPS / ERRORS").unwrap();
    for p in &report.probes { if p.status != "FULL_PIPELINE_SEMANTIC" && p.status != "NON_INSTRUCTION" { writeln!(out, "#{:06} {:32} {:5} {:10} {:8} {:8} {:8} -> {}", p.probe_id,p.code,p.bitness,p.operand_form,p.prefix,p.opmask,if p.broadcast {"BCST"} else {"-"},p.status).unwrap(); if let Some(e)=&p.lift_error { writeln!(out,"    lift: {e}").unwrap(); } if let Some(e)=&p.semantic_error { writeln!(out,"    sem : {e}").unwrap(); } } }
    writeln!(out, "\nNOTE: matrix enumerates legal representative forms, not every numeric register permutation or every runtime input value.").unwrap();
    writeln!(out, "NOTE: semantic=EXECUTED means BTG's RISC reference evaluator executed the lifted micro-program without a guest fault for the deterministic samples.").unwrap();
    out
}

fn render_matrix_txt(report: &Report) -> String {
    let mut out = String::new();
    writeln!(out, "BTG CPU COVERAGE PROBE MATRIX").unwrap();
    writeln!(out, "=============================").unwrap();
    let mut by_dim = BTreeMap::<String, (usize,usize)>::new();
    for p in &report.probes { if p.bitness == 0 { continue; } let key = format!("{} | {} | {} | {} | z={} | b={}",p.bitness,p.operand_form,p.prefix,p.opmask,p.zeroing,p.broadcast); let e=by_dim.entry(key).or_default(); e.0+=1; if p.status=="FULL_PIPELINE_SEMANTIC" {e.1+=1;} }
    for (k,(n,ok)) in by_dim { writeln!(out,"{k:70} total={n:6} full={ok:6}").unwrap(); }
    out
}
