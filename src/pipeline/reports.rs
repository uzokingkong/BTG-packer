//! Deterministic, side-effect-free evidence reports for the canonical program model.
//!
//! Keeping rendering separate from artifact I/O makes the exact evidence bytes
//! testable and lets callers commit all build artifacts atomically.

use crate::analysis::program_model::{
    BlockModel, ByteClass, CodePointerEncoding, CodePointerModel, EdgeKind, EdgeModel, EdgeTarget,
    ProgramModel, RvaRange,
};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::vm::risc::CommercialCapabilityError;

pub use crate::vm::risc::unsupported_report::{
    UnsupportedInstruction, UnsupportedInstructionReport, UnsupportedReportError, UnsupportedStage,
};

/// The four canonical model reports consumed by build evidence tooling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramModelCsvReports {
    pub executable_byte_partition: String,
    pub unknown_ranges: String,
    pub edges: String,
    pub code_pointers: String,
}

/// Side-effect-free bytes for evidence artifacts emitted beside the protected PE.
/// Keeping this bundle independent of filesystem I/O lets the pipeline validate
/// the final image before any evidence file is staged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceReportBundle {
    pub unsupported_instructions: String,
    pub capability_mismatches: String,
}

impl EvidenceReportBundle {
    pub fn render(unsupported: &UnsupportedInstructionReport) -> Self {
        Self::render_with_capability_mismatches(unsupported, &CapabilityMismatchReport::new())
    }

    pub fn render_with_capability_mismatches(
        unsupported: &UnsupportedInstructionReport,
        capability_mismatches: &CapabilityMismatchReport,
    ) -> Self {
        Self {
            unsupported_instructions: unsupported.render_csv(),
            capability_mismatches: capability_mismatches.render_csv(),
        }
    }

    pub fn artifacts_for(&self, output: &Path) -> Vec<EvidenceArtifact> {
        vec![
            EvidenceArtifact {
                path: appended_extension(output, "unsupported.csv"),
                bytes: self.unsupported_instructions.as_bytes().to_vec(),
            },
            EvidenceArtifact {
                path: appended_extension(output, "capability-mismatches.csv"),
                bytes: self.capability_mismatches.as_bytes().to_vec(),
            },
        ]
    }
}

/// Micro-op capability evidence. This is deliberately separate from x86
/// unsupported-instruction evidence: a capability assertion has no truthful
/// instruction address, byte sequence, or iced-x86 opcode to report.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CapabilityMismatchRecord {
    pub instruction_index: usize,
    pub op_name: String,
    pub missing_capabilities: Vec<String>,
}

impl From<&CommercialCapabilityError> for CapabilityMismatchRecord {
    fn from(error: &CommercialCapabilityError) -> Self {
        let mut missing_capabilities: Vec<_> = error
            .missing
            .iter()
            .map(|capability| capability.stable_name().to_owned())
            .collect();
        missing_capabilities.sort();
        missing_capabilities.dedup();
        Self {
            instruction_index: error.instruction_index,
            op_name: error.op_name.to_owned(),
            missing_capabilities,
        }
    }
}

/// Deterministic aggregate of commercial micro-op capability failures.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityMismatchReport {
    rows: std::collections::BTreeMap<CapabilityMismatchRecord, u64>,
}

impl CapabilityMismatchReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(
        &mut self,
        error: &CommercialCapabilityError,
    ) -> Result<(), CapabilityMismatchReportError> {
        let count = self.rows.entry(error.into()).or_insert(0);
        *count = count
            .checked_add(1)
            .ok_or(CapabilityMismatchReportError::FrequencyOverflow)?;
        Ok(())
    }

    pub fn from_error(error: &CommercialCapabilityError) -> Self {
        let mut report = Self::new();
        // A fresh report cannot overflow on its first record.
        report.record(error).expect("fresh capability report");
        report
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn render_csv(&self) -> String {
        let mut out = String::from("micro_op_index,op_name,missing_capabilities,frequency\n");
        for (row, frequency) in &self.rows {
            push_report_csv_row(
                &mut out,
                &[
                    row.instruction_index.to_string(),
                    row.op_name.clone(),
                    row.missing_capabilities.join(";"),
                    frequency.to_string(),
                ],
            );
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityMismatchReportError {
    #[error("capability mismatch frequency overflow")]
    FrequencyOverflow,
}

fn push_report_csv_row(out: &mut String, fields: &[String]) {
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        if field
            .bytes()
            .any(|byte| matches!(byte, b',' | b'"' | b'\r' | b'\n'))
        {
            out.push('"');
            out.push_str(&field.replace('"', "\"\""));
            out.push('"');
        } else {
            out.push_str(field);
        }
    }
    out.push('\n');
}

/// A fully rendered artifact awaiting commit. No writer needs access to mutable
/// pipeline state, which prevents reporting from changing build decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceArtifact {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

/// Commit each rendered artifact through a sibling temporary file. The final
/// name never observes a partial CSV, including the header-only empty report.
pub fn write_evidence_artifacts(artifacts: &[EvidenceArtifact]) -> io::Result<()> {
    for artifact in artifacts {
        atomic_write(&artifact.path, &artifact.bytes)?;
    }
    Ok(())
}

fn appended_extension(output: &Path, suffix: &str) -> PathBuf {
    let mut path = output.to_path_buf();
    let extension = output
        .extension()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".to_owned());
    path.set_extension(format!("{extension}.{suffix}"));
    path
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "artifact has no file name"))?;
    let mut temp_name = file_name.to_os_string();
    temp_name.push(format!(".tmp.{}", std::process::id()));
    let temp_path = path.with_file_name(temp_name);

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        replace_file(&temp_path, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both pointers reference NUL-terminated buffers which remain alive
    // for the duration of the synchronous Win32 call.
    let ok = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn render_program_model_csv_reports(model: &ProgramModel) -> ProgramModelCsvReports {
    ProgramModelCsvReports {
        executable_byte_partition: render_executable_byte_partition_csv(model),
        unknown_ranges: render_unknown_ranges_csv(model),
        edges: render_edges_csv(model),
        code_pointers: render_code_pointers_csv(model),
    }
}

/// Render every classified block and every explicitly unknown executable range.
/// Rows are address ordered; `record_kind` keeps unknown bytes distinct from a
/// block whose `byte_class` is itself `unknown`.
pub fn render_executable_byte_partition_csv(model: &ProgramModel) -> String {
    enum Row<'a> {
        Block(&'a BlockModel),
        Unknown(RvaRange),
    }
    let mut rows: Vec<(u32, u32, u8, u32, Row<'_>)> = model
        .blocks
        .values()
        .map(|block| {
            (
                block.range.start,
                block.range.end,
                0,
                block.id.0,
                Row::Block(block),
            )
        })
        .chain(
            model
                .unknown_ranges
                .iter()
                .copied()
                .map(|range| (range.start, range.end, 1, 0, Row::Unknown(range))),
        )
        .collect();
    rows.sort_by_key(|row| (row.0, row.1, row.2, row.3));

    let mut out =
        String::from("record_kind,start_rva,end_rva,byte_count,byte_class,function_id,block_id\n");
    for (_, _, _, _, row) in rows {
        match row {
            Row::Block(block) => push_row(
                &mut out,
                &[
                    "block".into(),
                    rva(block.range.start),
                    rva(block.range.end),
                    (block.range.end - block.range.start).to_string(),
                    byte_class(block.byte_class).into(),
                    block.function_id.0.to_string(),
                    block.id.0.to_string(),
                ],
            ),
            Row::Unknown(range) => push_row(
                &mut out,
                &[
                    "unknown_range".into(),
                    rva(range.start),
                    rva(range.end),
                    (range.end - range.start).to_string(),
                    "unknown".into(),
                    String::new(),
                    String::new(),
                ],
            ),
        }
    }
    out
}

pub fn render_unknown_ranges_csv(model: &ProgramModel) -> String {
    let mut ranges = model.unknown_ranges.clone();
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut out = String::from("start_rva,end_rva,byte_count\n");
    for range in ranges {
        push_row(
            &mut out,
            &[
                rva(range.start),
                rva(range.end),
                (range.end - range.start).to_string(),
            ],
        );
    }
    out
}

pub fn render_edges_csv(model: &ProgramModel) -> String {
    let mut edges: Vec<&EdgeModel> = model.edges.iter().collect();
    edges.sort_by_key(|edge| {
        let (target_kind, target_value) = edge_target_sort_key(&edge.target);
        (
            edge.source.0,
            edge_kind(edge.kind),
            target_kind,
            target_value,
        )
    });
    let mut out = String::from("source_block_id,edge_kind,target_kind,target_id,target_address\n");
    for edge in edges {
        let (target_kind, target_id, target_address) = match &edge.target {
            EdgeTarget::Block(id) => ("block", id.0.to_string(), String::new()),
            EdgeTarget::Function(id) => ("function", id.0.to_string(), String::new()),
            EdgeTarget::External(address) => {
                ("external", String::new(), format!("0x{address:016X}"))
            }
            EdgeTarget::RuntimeRoute => ("runtime_route", String::new(), String::new()),
            EdgeTarget::Unresolved => ("unresolved", String::new(), String::new()),
        };
        push_row(
            &mut out,
            &[
                edge.source.0.to_string(),
                edge_kind(edge.kind).into(),
                target_kind.into(),
                target_id,
                target_address,
            ],
        );
    }
    out
}

pub fn render_code_pointers_csv(model: &ProgramModel) -> String {
    let mut pointers: Vec<&CodePointerModel> = model.code_pointers.values().collect();
    pointers.sort_by_key(|pointer| (pointer.location.start, pointer.location.end, pointer.id.0));
    let mut out = String::from(
        "code_pointer_id,location_start_rva,location_end_rva,byte_count,encoding,target_function_id,provenance\n",
    );
    for pointer in pointers {
        push_row(
            &mut out,
            &[
                pointer.id.0.to_string(),
                rva(pointer.location.start),
                rva(pointer.location.end),
                (pointer.location.end - pointer.location.start).to_string(),
                pointer_encoding(pointer.encoding).into(),
                pointer.target.0.to_string(),
                pointer.provenance.into(),
            ],
        );
    }
    out
}

fn rva(value: u32) -> String {
    format!("0x{value:08X}")
}

fn byte_class(value: ByteClass) -> &'static str {
    match value {
        ByteClass::Instruction => "instruction",
        ByteClass::ReachableTrap => "reachable_trap",
        ByteClass::Padding => "padding",
        ByteClass::EmbeddedData => "embedded_data",
        ByteClass::Generated => "generated",
        ByteClass::Unknown => "unknown",
    }
}

fn edge_kind(value: EdgeKind) -> &'static str {
    match value {
        EdgeKind::DirectBranch => "direct_branch",
        EdgeKind::DirectCall => "direct_call",
        EdgeKind::TailCall => "tail_call",
        EdgeKind::Fallthrough => "fallthrough",
        EdgeKind::IndirectCall => "indirect_call",
        EdgeKind::IndirectJump => "indirect_jump",
        EdgeKind::Return => "return",
    }
}

fn edge_target_sort_key(target: &EdgeTarget) -> (u8, u64) {
    match target {
        EdgeTarget::Block(id) => (0, id.0 as u64),
        EdgeTarget::Function(id) => (1, id.0 as u64),
        EdgeTarget::External(address) => (2, *address),
        EdgeTarget::RuntimeRoute => (3, 0),
        EdgeTarget::Unresolved => (4, 0),
    }
}

fn pointer_encoding(value: CodePointerEncoding) -> &'static str {
    match value {
        CodePointerEncoding::Va64 => "va64",
        CodePointerEncoding::Rva32 => "rva32",
        CodePointerEncoding::Rel32 => "rel32",
        CodePointerEncoding::TableRelative => "table_relative",
        CodePointerEncoding::DirectoryField => "directory_field",
    }
}

fn push_row(out: &mut String, fields: &[String]) {
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        push_csv_field(out, field);
    }
    out.push('\n');
}

fn push_csv_field(out: &mut String, field: &str) {
    if field
        .bytes()
        .any(|byte| matches!(byte, b',' | b'"' | b'\n' | b'\r'))
    {
        out.push('"');
        for ch in field.chars() {
            if ch == '"' {
                out.push('"');
            }
            out.push(ch);
        }
        out.push('"');
    } else {
        out.push_str(field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::program_model::{BlockId, CodePointerId, FunctionId};

    #[test]
    fn reports_are_address_ordered_and_csv_safe() {
        let mut model = ProgramModel::default();
        model.blocks.insert(
            BlockId(9),
            BlockModel {
                id: BlockId(9),
                function_id: FunctionId(3),
                range: RvaRange::new(0x1020, 0x1030).unwrap(),
                instructions: Vec::new(),
                byte_class: ByteClass::Padding,
            },
        );
        model.unknown_ranges = vec![
            RvaRange::new(0x1030, 0x1040).unwrap(),
            RvaRange::new(0x1000, 0x1020).unwrap(),
        ];
        model.code_pointers.insert(
            CodePointerId(7),
            CodePointerModel {
                id: CodePointerId(7),
                location: RvaRange::new(0x3010, 0x3018).unwrap(),
                encoding: CodePointerEncoding::Va64,
                target: FunctionId(3),
                provenance: "reloc,\"tls\"",
            },
        );

        assert_eq!(
            render_executable_byte_partition_csv(&model),
            "record_kind,start_rva,end_rva,byte_count,byte_class,function_id,block_id\n\
unknown_range,0x00001000,0x00001020,32,unknown,,\n\
block,0x00001020,0x00001030,16,padding,3,9\n\
unknown_range,0x00001030,0x00001040,16,unknown,,\n"
        );
        assert!(render_code_pointers_csv(&model)
            .ends_with("7,0x00003010,0x00003018,8,va64,3,\"reloc,\"\"tls\"\"\"\n"));
    }

    #[test]
    fn edges_have_a_stable_semantic_order() {
        let mut model = ProgramModel::default();
        model.edges = vec![
            EdgeModel {
                source: BlockId(2),
                kind: EdgeKind::Return,
                target: EdgeTarget::Unresolved,
            },
            EdgeModel {
                source: BlockId(1),
                kind: EdgeKind::DirectCall,
                target: EdgeTarget::External(0x140001000),
            },
            EdgeModel {
                source: BlockId(1),
                kind: EdgeKind::DirectBranch,
                target: EdgeTarget::Block(BlockId(8)),
            },
        ];
        assert_eq!(
            render_edges_csv(&model),
            "source_block_id,edge_kind,target_kind,target_id,target_address\n\
1,direct_branch,block,8,\n\
1,direct_call,external,,0x0000000140001000\n\
2,return,unresolved,,\n"
        );
    }

    #[test]
    fn empty_reports_still_publish_their_schemas() {
        let reports = render_program_model_csv_reports(&ProgramModel::default());
        assert_eq!(reports.unknown_ranges, "start_rva,end_rva,byte_count\n");
        assert_eq!(
            reports.edges,
            "source_block_id,edge_kind,target_kind,target_id,target_address\n"
        );
    }

    #[test]
    fn empty_unsupported_report_stages_a_header_only_sibling_artifact() {
        let bundle = EvidenceReportBundle::render(&UnsupportedInstructionReport::new());
        let artifacts = bundle.artifacts_for(Path::new("protected.exe"));
        assert_eq!(artifacts.len(), 2);
        assert_eq!(
            artifacts[0].path,
            PathBuf::from("protected.exe.unsupported.csv")
        );
        assert_eq!(
            String::from_utf8(artifacts[0].bytes.clone()).unwrap(),
            "function_rva,instruction_rva,ip,iced_code,operand_summary,raw_bytes,frequency,failure_stage,failure_detail\n"
        );
        assert_eq!(
            artifacts[1].path,
            PathBuf::from("protected.exe.capability-mismatches.csv")
        );
        assert_eq!(
            String::from_utf8(artifacts[1].bytes.clone()).unwrap(),
            "micro_op_index,op_name,missing_capabilities,frequency\n"
        );
    }

    #[test]
    fn capability_errors_render_without_fabricating_x86_evidence() {
        use crate::vm::risc::{CommercialCapability, CommercialCapabilityError};

        let error = CommercialCapabilityError {
            instruction_index: 17,
            op_name: "vm_call_bridge",
            missing: vec![
                CommercialCapability::ProductionThreaded,
                CommercialCapability::PolyCodec,
                CommercialCapability::PolyInterpreter,
            ],
        };
        let report = CapabilityMismatchReport::from_error(&error);
        let bundle = EvidenceReportBundle::render_with_capability_mismatches(
            &UnsupportedInstructionReport::new(),
            &report,
        );

        assert_eq!(
            bundle.capability_mismatches,
            "micro_op_index,op_name,missing_capabilities,frequency\n\
17,vm_call_bridge,poly_codec;poly_interpreter;production_threaded,1\n"
        );
        assert!(!bundle.capability_mismatches.contains("iced_code"));
        assert!(!bundle.capability_mismatches.contains("raw_bytes"));
    }

    #[test]
    fn capability_report_aggregates_and_sorts_deterministically() {
        use crate::vm::risc::{CommercialCapability, CommercialCapabilityError};

        let later = CommercialCapabilityError {
            instruction_index: 9,
            op_name: "vm_call_bridge",
            missing: vec![CommercialCapability::PolyCodec],
        };
        let earlier = CommercialCapabilityError {
            instruction_index: 2,
            op_name: "native_call_bridge",
            missing: vec![CommercialCapability::ProductionThreaded],
        };
        let mut report = CapabilityMismatchReport::new();
        report.record(&later).unwrap();
        report.record(&earlier).unwrap();
        report.record(&later).unwrap();

        assert_eq!(report.len(), 2);
        assert_eq!(
            report.render_csv(),
            "micro_op_index,op_name,missing_capabilities,frequency\n\
2,native_call_bridge,production_threaded,1\n\
9,vm_call_bridge,poly_codec,2\n"
        );
    }

    #[test]
    fn evidence_writer_commits_the_exact_rendered_bytes() {
        let unique = format!(
            "btg-evidence-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        fs::create_dir_all(&directory).unwrap();
        let output = directory.join("sample.bin");
        let bundle = EvidenceReportBundle::render(&UnsupportedInstructionReport::new());
        let artifacts = bundle.artifacts_for(&output);

        write_evidence_artifacts(&artifacts).unwrap();
        assert_eq!(fs::read(&artifacts[0].path).unwrap(), artifacts[0].bytes);
        let replacement = EvidenceArtifact {
            path: artifacts[0].path.clone(),
            bytes: b"replacement\n".to_vec(),
        };
        write_evidence_artifacts(&[replacement.clone()]).unwrap();
        assert_eq!(fs::read(&replacement.path).unwrap(), replacement.bytes);
        assert!(!directory
            .join(format!(
                "sample.bin.unsupported.csv.tmp.{}",
                std::process::id()
            ))
            .exists());

        fs::remove_dir_all(directory).unwrap();
    }
}
