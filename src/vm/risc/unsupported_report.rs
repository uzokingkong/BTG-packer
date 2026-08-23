//! Deterministic evidence for x86 instructions that could not be virtualized.

use iced_x86::{Code, Formatter, Instruction, NasmFormatter};
use std::collections::BTreeMap;
use std::fmt;

/// Architectural x86 instructions cannot exceed 15 bytes.
pub const MAX_X86_INSTRUCTION_BYTES: usize = 15;
/// Prevent diagnostics supplied by a failed stage from growing reports without bound.
pub const MAX_FAILURE_DETAIL_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnsupportedStage {
    Decode,
    Registry,
    Lift,
    Validate,
    Encode,
}

impl UnsupportedStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Decode => "decode",
            Self::Registry => "registry",
            Self::Lift => "lift",
            Self::Validate => "validate",
            Self::Encode => "encode",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedReportError {
    RawBytesTooLong(usize),
    FailureDetailTooLong(usize),
    FrequencyOverflow,
}

impl fmt::Display for UnsupportedReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RawBytesTooLong(n) => write!(f, "x86 instruction has {n} bytes (maximum is 15)"),
            Self::FailureDetailTooLong(n) => {
                write!(f, "failure detail has {n} bytes (maximum is 1024)")
            }
            Self::FrequencyOverflow => f.write_str("unsupported instruction frequency overflow"),
        }
    }
}

impl std::error::Error for UnsupportedReportError {}

/// One unsupported occurrence. `rva` and `ip` are kept separately so rebasing is auditable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedInstruction {
    pub function_rva: u32,
    pub instruction_rva: u32,
    pub ip: u64,
    pub code: Code,
    pub operand_summary: String,
    pub raw_bytes: Vec<u8>,
    pub stage: UnsupportedStage,
    pub failure_detail: String,
}

impl UnsupportedInstruction {
    pub fn new(
        function_rva: u32,
        instruction_rva: u32,
        instruction: &Instruction,
        raw_bytes: &[u8],
        stage: UnsupportedStage,
        failure_detail: impl Into<String>,
    ) -> Result<Self, UnsupportedReportError> {
        if raw_bytes.len() > MAX_X86_INSTRUCTION_BYTES {
            return Err(UnsupportedReportError::RawBytesTooLong(raw_bytes.len()));
        }
        let failure_detail = failure_detail.into();
        if failure_detail.len() > MAX_FAILURE_DETAIL_BYTES {
            return Err(UnsupportedReportError::FailureDetailTooLong(
                failure_detail.len(),
            ));
        }
        Ok(Self {
            function_rva,
            instruction_rva,
            ip: instruction.ip(),
            code: instruction.code(),
            operand_summary: operand_summary(instruction),
            raw_bytes: raw_bytes.to_vec(),
            stage,
            failure_detail,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AggregateKey {
    function_rva: u32,
    instruction_rva: u32,
    ip: u64,
    code: u32,
    operand_summary: String,
    raw_bytes: Vec<u8>,
    stage: UnsupportedStage,
    failure_detail: String,
}

/// Aggregates identical evidence and renders rows in semantic/address order.
#[derive(Debug, Clone, Default)]
pub struct UnsupportedInstructionReport {
    rows: BTreeMap<AggregateKey, u64>,
    occurrences: u64,
}

impl UnsupportedInstructionReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, item: UnsupportedInstruction) -> Result<(), UnsupportedReportError> {
        let key = AggregateKey {
            function_rva: item.function_rva,
            instruction_rva: item.instruction_rva,
            ip: item.ip,
            code: item.code as u32,
            operand_summary: item.operand_summary,
            raw_bytes: item.raw_bytes,
            stage: item.stage,
            failure_detail: item.failure_detail,
        };
        let next_occurrences = self
            .occurrences
            .checked_add(1)
            .ok_or(UnsupportedReportError::FrequencyOverflow)?;
        let count = self.rows.entry(key).or_insert(0);
        *count = count
            .checked_add(1)
            .ok_or(UnsupportedReportError::FrequencyOverflow)?;
        self.occurrences = next_occurrences;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Total unsupported instruction occurrences represented by the CSV.
    ///
    /// Unlike [`Self::len`], this includes duplicates folded into a row's
    /// `frequency` column and is therefore the value coverage metrics must use.
    pub fn occurrence_count(&self) -> u64 {
        self.occurrences
    }

    pub fn render_csv(&self) -> String {
        let mut out = String::from(
            "function_rva,instruction_rva,ip,iced_code,operand_summary,raw_bytes,frequency,failure_stage,failure_detail\n",
        );
        for (row, frequency) in &self.rows {
            let fields = [
                format!("0x{:08X}", row.function_rva),
                format!("0x{:08X}", row.instruction_rva),
                format!("0x{:016X}", row.ip),
                format!(
                    "{:?}",
                    Code::try_from(row.code as usize).unwrap_or(Code::INVALID)
                ),
                row.operand_summary.clone(),
                row.raw_bytes.iter().map(|b| format!("{b:02X}")).collect(),
                frequency.to_string(),
                row.stage.as_str().into(),
                row.failure_detail.clone(),
            ];
            push_csv_row(&mut out, &fields);
        }
        out
    }
}

fn operand_summary(instruction: &Instruction) -> String {
    let mut formatter = NasmFormatter::new();
    let mut text = String::new();
    formatter.format(instruction, &mut text);
    text.split_once(char::is_whitespace)
        .map_or_else(String::new, |(_, operands)| operands.trim().to_owned())
}

fn push_csv_row(out: &mut String, fields: &[String]) {
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        if field
            .bytes()
            .any(|b| matches!(b, b',' | b'"' | b'\r' | b'\n'))
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
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(ip: u64, bytes: &[u8]) -> Instruction {
        let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        decoder.decode()
    }

    #[test]
    fn aggregates_and_sorts_deterministically() {
        let mov = decode(0x140001020, &[0x48, 0x89, 0xD8]);
        let add = decode(0x140001010, &[0x48, 0x01, 0xD8]);
        let mut report = UnsupportedInstructionReport::new();
        for inst in [&mov, &add, &add] {
            let rva = (inst.ip() - 0x140000000) as u32;
            report
                .record(
                    UnsupportedInstruction::new(
                        0x1000,
                        rva,
                        inst,
                        if inst.ip() == add.ip() {
                            &[0x48, 0x01, 0xD8]
                        } else {
                            &[0x48, 0x89, 0xD8]
                        },
                        UnsupportedStage::Lift,
                        "unsupported",
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let csv = report.render_csv();
        assert_eq!(report.len(), 2);
        assert_eq!(report.occurrence_count(), 3);
        let lines: Vec<_> = csv.lines().collect();
        assert!(lines[1].starts_with("0x00001000,0x00001010"));
        assert!(lines[1].contains(",2,lift,"));
        assert!(lines[2].starts_with("0x00001000,0x00001020"));
        assert_eq!(csv, report.render_csv());
    }

    #[test]
    fn empty_report_has_zero_occurrences() {
        let report = UnsupportedInstructionReport::new();
        assert_eq!(report.occurrence_count(), 0);
        assert!(report.is_empty());
        assert_eq!(report.render_csv().lines().count(), 1);
    }

    #[test]
    fn csv_escapes_stage_detail() {
        let inst = decode(0x1000, &[0x90]);
        let mut report = UnsupportedInstructionReport::new();
        report
            .record(
                UnsupportedInstruction::new(
                    1,
                    2,
                    &inst,
                    &[0x90],
                    UnsupportedStage::Validate,
                    "bad, \"shape\"\nnext",
                )
                .unwrap(),
            )
            .unwrap();
        assert!(report.render_csv().contains("\"bad, \"\"shape\"\"\nnext\""));
    }

    #[test]
    fn rejects_out_of_bounds_fields() {
        let inst = decode(0x1000, &[0x90]);
        assert!(matches!(
            UnsupportedInstruction::new(0, 0, &inst, &[0; 16], UnsupportedStage::Decode, "x"),
            Err(UnsupportedReportError::RawBytesTooLong(16))
        ));
        assert!(matches!(
            UnsupportedInstruction::new(
                0,
                0,
                &inst,
                &[],
                UnsupportedStage::Decode,
                "x".repeat(1025)
            ),
            Err(UnsupportedReportError::FailureDetailTooLong(1025))
        ));
    }
}
