// ==============================================================================
// BTG - Experimental textual IR ingestion
// ==============================================================================
// A deliberately small LLVM-like textual grammar parsed into RiscProgram.
// This is not an LLVM pass, bitcode reader, or LLVM SDK.
//
// S5 (implementation-gap-plan 축4): 이전엔 24줄 스텁(`build_risc_program`이
// `vf.body.clone()`만 수행) + SDK 마커가 "데이터 임베드만" 되어 소비 런타임이
// 검증되지 않았다. 이 파일은
//   1) 제한된 텍스트 IR을 RISC micro-op으로 합성하는 `ExperimentalIrParser`,
//   2) 폴리모픽(rolling-key) 바이트코드를 **소비**(복호화)해 원래 `RiscProgram` 을
//      복원하고 원본과 실행 정합(regs/flags/stack)을 검증하는 `PolyConsumptionRuntime`
// 을 제공한다. `selective_vm.rs` 가 마커 리전을 encode 한 뒤 이 소비 런타임으로
// 검증을 통과한 리전만 임베드한다 (데이터 임베드에 그치지 않고 실행 정합 검증).
// ==============================================================================

use crate::vm::poly::{PolymorphicDecoder, PolymorphicEncoder};
use crate::vm::risc::{
    MicroInstr, MicroOperand, RiscDesynthesizer, RiscEvalState, RiscOp, RiscProgram,
};
use anyhow::{anyhow, Context, Result};

/// Function produced by the experimental textual parser.
#[derive(Debug, Clone)]
pub struct ExperimentalIrFunction {
    pub name: String,
    pub body: Vec<MicroInstr>,
}

/// RISC 마이크로-op 를 생성하는 데 필요한 합성기의 가변 파생 타입.
/// (`RiscDesynthesizer` 를 직접 노출하지 않고, 파서가 사용할 수 있는 얇은 래퍼.)
pub struct ExperimentalIrSynthesizer {
    pub d: RiscDesynthesizer,
}

impl ExperimentalIrSynthesizer {
    pub fn new() -> Self {
        Self {
            d: RiscDesynthesizer::new(),
        }
    }

    /// IR 피연산자(예: `%r0`, `42`)를 `MicroOperand` 로 해석한다.
    fn parse_operand(s: &str) -> Result<MicroOperand> {
        let s = s.trim();
        if s.is_empty() {
            return Err(anyhow!("empty operand"));
        }
        if let Some(rest) = s.strip_prefix('%') {
            let idx: u8 = rest.parse().map_err(|_| anyhow!("invalid SSA reg `{s}`"))?;
            Ok(MicroOperand::VReg(idx))
        } else {
            let v: u64 = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).map_err(|_| anyhow!("invalid hex imm `{s}`"))?
            } else {
                s.parse().map_err(|_| anyhow!("invalid imm `{s}`"))?
            };
            Ok(MicroOperand::Imm64(v))
        }
    }

    /// 단일 LLVM-IR 스타일 연산 한 줄을 RISC 마이크로-op 로 합성한다.
    /// 지원 연산: add/sub/xor/and/or/not/neg/shl/lshr/ashr (i64), ret.
    ///
    /// 라인 형식 (공백/`,` 로 토큰 분리):
    ///   `%dst = add i64 %a, %b`
    ///   `%dst = mul i64 %a, %b`
    ///   `ret i64 %v`
    ///   `%dst = xor i64 %a, %b`
    pub fn emit_line(&mut self, line: &str) -> Result<()> {
        // 주석/빈 줄 제거
        let line = line.split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            return Ok(());
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.is_empty() {
            return Ok(());
        }

        // `ret [i64] %v`
        if toks[0] == "ret" {
            if let Some(v) = toks.last() {
                let v = v.trim_matches(',');
                if !v.is_empty() && v != "void" {
                    let op = Self::parse_operand(v)?;
                    self.d.instrs.push(
                        MicroInstr::new(RiscOp::Mov)
                            .with_dst(MicroOperand::VReg(0))
                            .with_src1(op),
                    );
                }
            }
            self.d.instrs.push(MicroInstr::new(RiscOp::Halt));
            return Ok(());
        }

        // `%dst = OP i64 a, b`  (toks: [%dst, =, OP, i64, a, b])
        if toks.len() < 5 || toks[1] != "=" {
            return Err(anyhow!("unsupported IR line: `{line}`"));
        }
        let dst = Self::parse_operand(toks[0])?;
        let op = toks[2];
        // toks[3] = 타입 (i64), toks[4] = a, toks[5] = b (쉼표 제거). 단항(not/neg)은 b 없음.
        let a = Self::parse_operand(toks[4].trim_matches(','))?;
        let is_unary = matches!(op, "not" | "neg");
        let b = if is_unary {
            MicroOperand::Imm64(0)
        } else {
            if toks.len() < 6 {
                return Err(anyhow!("binary op `{op}` needs two operands: `{line}`"));
            }
            Self::parse_operand(toks[5].trim_matches(','))?
        };

        match op {
            "add" => self.d.emit_add(dst, a, b),
            "sub" => self.d.emit_sub(dst, a, b),
            "xor" => self.d.emit_xor(dst, a, b),
            "and" => self.d.emit_and(dst, a, b),
            "or" => self.d.emit_or(dst, a, b),
            "not" => self.d.emit_not(dst, a),
            "neg" => self.d.emit_neg(dst, a),
            "shl" => self.d.instrs.push(
                MicroInstr::new(RiscOp::ShiftLeft)
                    .with_dst(dst)
                    .with_src1(a)
                    .with_src2(b),
            ),
            "lshr" => self.d.instrs.push(
                MicroInstr::new(RiscOp::ShiftRight)
                    .with_dst(dst)
                    .with_src1(a)
                    .with_src2(b),
            ),
            "ashr" => self.d.instrs.push(
                MicroInstr::new(RiscOp::ArithmeticShiftRight)
                    .with_dst(dst)
                    .with_src1(a)
                    .with_src2(b),
            ),
            "mul" => self.d.instrs.push(
                MicroInstr::new(RiscOp::MultiplyLow {
                    signed: false,
                    width: 8,
                })
                .with_dst(dst)
                .with_src1(a)
                .with_src2(b),
            ),
            other => return Err(anyhow!("unsupported IR op `{other}` in `{line}`")),
        }
        Ok(())
    }
}

impl Default for ExperimentalIrSynthesizer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ExperimentalIrParser;

impl ExperimentalIrParser {
    /// LLVM-IR 텍스트 한 함수 본문을 `RiscProgram` 으로 직접 합성한다.
    /// `fn_name` 은 진단용. 파싱에 실패하면 `Err` 를 반환한다 (조용한 스킵 금지).
    pub fn synthesize_ir(fn_name: &str, ir: &str) -> Result<RiscProgram> {
        let mut synth = ExperimentalIrSynthesizer::new();
        for (i, line) in ir.lines().enumerate() {
            synth
                .emit_line(line)
                .with_context(|| format!("{fn_name}: IR line {}: `{line}`", i + 1))?;
        }
        if !synth.d.instrs.iter().any(|ins| ins.op == RiscOp::Halt) {
            synth.d.instrs.push(MicroInstr::new(RiscOp::Halt));
        }
        Ok(RiscProgram::new(synth.d.instrs))
    }

    /// 합성된 가상 함수의 RISC 본문을 `RiscProgram` 으로 검증·빌드한다.
    pub fn build_risc_program(vf: &ExperimentalIrFunction) -> RiscProgram {
        RiscProgram::new(vf.body.clone())
    }

    /// Parse the restricted textual grammar into an experimental IR function.
    pub fn parse_ir(fn_name: &str, ir: &str) -> Result<ExperimentalIrFunction> {
        let prog = Self::synthesize_ir(fn_name, ir)?;
        Ok(ExperimentalIrFunction {
            name: fn_name.to_string(),
            body: prog.instrs,
        })
    }
}

#[deprecated(note = "this is an experimental textual IR parser, not an LLVM pass/SDK")]
pub type LlvmSynthesizer = ExperimentalIrSynthesizer;
#[deprecated(note = "use ExperimentalIrParser; no LLVM pass or bitcode ingestion is provided")]
pub type LlvmIngestionInterface = ExperimentalIrParser;

/// S5: 폴리모픽(rolling-key) 바이트코드 **소비 런타임**.
///
/// `PolymorphicEncoder` 로 암호화한 바이트코드를 `PolymorphicDecoder`(같은 시드의
/// rolling-key)로 복호화해 원래 `RiscProgram` 을 복원하고, 원본과 **실행 정합**
/// (여러 입력 레지스터 벡터에 대한 `eval_state` 의 regs/flags/vsp/stack/temps 동치)을
/// 검증한다. `selective_vm.rs` 가 SDK 마커 리전을 encode 한 뒤 이 런타임으로
/// 소비·검증을 통과한 리전만 `.btgvm` 섹션에 임베드한다.
pub struct PolyConsumptionRuntime;

impl PolyConsumptionRuntime {
    /// 롤링키로 바이트코드를 복호화해 원래 `RiscProgram` 을 복원한다.
    pub fn decode(bytecode: &[u8], seed: u64) -> Result<RiscProgram> {
        let mut dec = PolymorphicDecoder::new(seed);
        dec.decode_full(bytecode, false)
    }

    /// 복호화된 프로그램과 원본 프로그램의 마이크로-op 목록이 동일한지 확인한다.
    pub fn assert_op_list_eq(decoded: &RiscProgram, expected: &RiscProgram) -> Result<()> {
        if decoded.instrs.len() != expected.instrs.len() {
            return Err(anyhow!(
                "consumption op-list mismatch: decoded {} vs expected {}",
                decoded.instrs.len(),
                expected.instrs.len()
            ));
        }
        for (i, (d, e)) in decoded
            .instrs
            .iter()
            .zip(expected.instrs.iter())
            .enumerate()
        {
            if d != e {
                return Err(anyhow!(
                    "consumption op-list mismatch at #{i}: decoded {d:?} vs expected {e:?}"
                ));
            }
        }
        Ok(())
    }

    /// 두 상태가 실행 정합(regs/flags/vsp/stack/temps)인지 비교한다.
    pub fn assert_state_eq(decoded: &RiscEvalState, expected: &RiscEvalState) -> Result<()> {
        if decoded.regs != expected.regs {
            return Err(anyhow!(
                "consumption exec mismatch: regs {:#x?} vs {:#x?}",
                decoded.regs,
                expected.regs
            ));
        }
        if decoded.flags != expected.flags {
            return Err(anyhow!(
                "consumption exec mismatch: flags {:#x} vs {:#x}",
                decoded.flags,
                expected.flags
            ));
        }
        if decoded.vsp != expected.vsp {
            return Err(anyhow!(
                "consumption exec mismatch: vsp {:#x} vs {:#x}",
                decoded.vsp,
                expected.vsp
            ));
        }
        if decoded.stack != expected.stack {
            return Err(anyhow!("consumption exec mismatch: stack depth"));
        }
        if decoded.temps != expected.temps {
            return Err(anyhow!("consumption exec mismatch: temps"));
        }
        Ok(())
    }

    /// 바이트코드를 소비(복호화)하고, 여러 입력 벡터에 대해 원본 프로그램과
    /// 실행 결과가 일치하는지 검증한다.
    pub fn verify_execution(bytecode: &[u8], seed: u64, expected: &RiscProgram) -> Result<()> {
        let decoded = Self::decode(bytecode, seed)?;
        Self::assert_op_list_eq(&decoded, expected)?;

        let input_vectors: [[u64; 16]; 4] = [
            [0u64; 16],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            [0x1122_3344_5566_7788u64; 16],
            [
                0xDEAD_BEEF_CAFE_F00Du64,
                0x0123_4567_89AB_CDEF,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
            ],
        ];
        for (i, init) in input_vectors.iter().enumerate() {
            let d = decoded.eval_state(init);
            let e = expected.eval_state(init);
            Self::assert_state_eq(&d, &e).with_context(|| format!("input vector #{i}"))?;
        }
        Ok(())
    }

    /// SDK 마커 리전의 (bytecode, seed) 를 소비·검증한다.
    pub fn verify_region(bytecode: &[u8], seed: u64, expected_prog: &RiscProgram) -> Result<()> {
        Self::verify_execution(bytecode, seed, expected_prog)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_prog() -> RiscProgram {
        ExperimentalIrParser::synthesize_ir(
            "sample",
            "%0 = add i64 %0, 0x1337
             %1 = mul i64 %0, 5
             ret i64 %1",
        )
        .unwrap()
    }

    /// rolling-key 소비 라운드트립: encode → decode → 원본 op 목록 복원.
    #[test]
    fn test_consumption_decode_roundtrip_op_list() {
        let prog = sample_prog();
        let seed = 0x8899AABBCCDDEEFFu64;
        let mut enc = PolymorphicEncoder::new(seed);
        let bc = enc.encode(&prog).unwrap();
        let decoded = PolyConsumptionRuntime::decode(&bc, seed).unwrap();
        assert!(decoded.instrs.len() >= prog.instrs.len());
        PolyConsumptionRuntime::assert_op_list_eq(&decoded, &prog).unwrap();
    }

    /// SDK 마커 리전 소비 런타임 실검증: 여러 입력 벡터에서 실행 정합.
    #[test]
    fn test_consumption_verify_execution_matches_reference() {
        let prog = sample_prog();
        let seed = 0xDEADBEEFCAFEF00Du64;
        let mut enc = PolymorphicEncoder::new(seed);
        let bc = enc.encode(&prog).unwrap();
        PolyConsumptionRuntime::verify_region(&bc, seed, &prog).unwrap();
    }

    /// 잘못된 시드로 소비하면 실패해야 한다 (롤링키 desync).
    #[test]
    fn test_consumption_wrong_seed_fails() {
        let prog = sample_prog();
        let seed = 0x123456789ABCDEF0u64;
        let wrong_seed = seed.wrapping_add(1);
        let mut enc = PolymorphicEncoder::new(seed);
        let bc = enc.encode(&prog).unwrap();
        assert!(PolyConsumptionRuntime::verify_region(&bc, wrong_seed, &prog).is_err());
    }

    /// IR 파서가 단항 연산(not/neg)을 처리한다.
    #[test]
    fn test_ir_parser_unary_ops() {
        let prog = ExperimentalIrParser::synthesize_ir(
            "u",
            "%0 = not i64 %1\n%2 = neg i64 %3\nret i64 %0",
        )
        .unwrap();
        assert!(prog.instrs.iter().any(|i| i.op == RiscOp::Nor));
        assert!(prog.instrs.iter().any(|i| i.op == RiscOp::AddWithCarry));
    }

    /// IR 파서가 지원하지 않는 연산을 조용히 넘기지 않고 Err 를 낸다.
    #[test]
    fn test_ir_parser_rejects_unknown_op() {
        let r = ExperimentalIrParser::synthesize_ir("bad", "%0 = frobnicate i64 %1, %2");
        assert!(r.is_err());
    }

    /// `LlvmIngestionInterface::parse_ir` → `build_risc_program` 파이프라인.
    #[test]
    fn test_ingest_parse_then_build() {
        let vf = ExperimentalIrParser::parse_ir("f", "%0 = add i64 %0, 2\nret i64 %0").unwrap();
        let prog = ExperimentalIrParser::build_risc_program(&vf);
        assert_eq!(prog.instrs.len(), vf.body.len());
    }
}
