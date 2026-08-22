// ==============================================================================
// BTG - Commercial-Grade VM: Polymorphic Bytecode Stream Encoder
// ==============================================================================

use super::architecture_family::VmArchitectureFamily;
use super::isa_spec::VirtualIsaSpec;
use super::rolling_key::RollingKeyEngine;
use crate::vm::risc::{MicroInstr, MicroOperand, RiscOp, RiscProgram};
use crate::vm::threaded::{SuperOpRewrite, SuperOpStreamInstr};
use anyhow::{anyhow, Result};

pub struct PolymorphicEncoder {
    pub spec: VirtualIsaSpec,
    pub rolling: RollingKeyEngine,
}

impl PolymorphicEncoder {
    pub fn new(seed: u64) -> Self {
        Self::new_for_family(seed, VmArchitectureFamily::for_build(seed))
    }

    /// Construct an encoder for a function-assigned architecture family.
    pub fn new_for_family(seed: u64, family: VmArchitectureFamily) -> Self {
        Self {
            spec: VirtualIsaSpec::from_seed_and_family(seed, family),
            rolling: RollingKeyEngine::new(seed),
        }
    }

    /// RiscProgram을 무작위 암호화된 폴리모픽 바이트코드로 인코딩
    ///
    /// 인스트럭션 스트림 형식 (`PolymorphicDecoder`/`PolymorphicInterpreter`와 공유):
    /// ```text
    /// opcode(1B) [branch_cond(1B)]* dst(1B) src1(1B) src2(1B) [imm 8B]...
    /// ```
    /// * `opcode` — `VirtualIsaSpec::opcode_for` 로 조회. `VirtualBranch` 는 조건과
    ///   무관한 단일 opcode 를 공유하고, `MemoryRead`/`MemoryWrite` 는 **폭을 보존**해
    ///   폭(1/2/4/8)마다 서로 다른 opcode 를 사용한다.
    /// * `*` — `VirtualBranch` 일 때만 opcode 직후에 조건 바이트를 붙인다
    ///   (`branch_cond_map` 로 부호화).
    /// * 피연산자 — dst/src1/src2 각 1B.
    /// * 즉시값 — `src == Imm64` 인 피연산자마다 8B. `AddWithCarry` 에서 즉시 피연산자가
    ///   없으면 `cin(imm)` 을 8B로 붙인다. `VirtualBranch` 의 절대-인덱스 타깃(src1 없음,
    ///   `imm` 을 타깃 인덱스로 사용)은 항상 8B로 붙인다. (간접 타깃은 `src1` 에 실린다.)
    pub fn encode(&mut self, prog: &RiscProgram) -> Result<Vec<u8>> {
        Ok(self.encode_with_offsets(prog)?.0)
    }

    fn push_encrypted(&mut self, out: &mut Vec<u8>, vip: &mut u64, byte: u8) {
        out.push(self.rolling.encrypt_byte(byte, *vip));
        *vip += 1;
    }

    /// Encode the part of an instruction following its opcode. Super-op bodies
    /// use exactly this canonical record, allowing their native handlers to
    /// reuse the normal operand decoder without embedding nested opcodes.
    fn encode_operand_record(&mut self, ins: &MicroInstr, out: &mut Vec<u8>, vip: &mut u64) {
        match ins.op {
            RiscOp::VirtualBranch { cond }
            | RiscOp::Setcc { cond }
            | RiscOp::ConditionalMove { cond } => {
                self.push_encrypted(out, vip, self.spec.encode_cond(cond));
            }
            _ => {}
        }
        let encode_operand = |op: Option<MicroOperand>, spec: &VirtualIsaSpec| match op {
            Some(MicroOperand::VReg(r)) => (0x80 | spec.encode_reg(r), None),
            Some(MicroOperand::Temp(t)) => (0xC0 | (t & 0x07), None),
            Some(MicroOperand::Imm64(v)) => (0x01, Some(v)),
            Some(MicroOperand::Vsp) => (0x40, None),
            Some(MicroOperand::Vflags) => (0x41, None),
            _ => (0x00, None),
        };
        let (dst, _) = encode_operand(ins.dst, &self.spec);
        let (src1, imm1) = encode_operand(ins.src1, &self.spec);
        let (src2, imm2) = encode_operand(ins.src2, &self.spec);
        self.push_encrypted(out, vip, dst);
        self.push_encrypted(out, vip, src1);
        self.push_encrypted(out, vip, src2);
        for value in [imm1, imm2].into_iter().flatten() {
            for byte in (value ^ self.spec.operand_mask).to_le_bytes() {
                self.push_encrypted(out, vip, byte);
            }
        }
        let trailing = if matches!(ins.op, RiscOp::VirtualBranch { .. }) && ins.src1.is_none() {
            Some(ins.imm)
        } else if ins.op == RiscOp::AddWithCarry && imm1.is_none() && imm2.is_none() {
            Some(ins.imm)
        } else {
            None
        };
        if let Some(value) = trailing {
            for byte in (value ^ self.spec.operand_mask).to_le_bytes() {
                self.push_encrypted(out, vip, byte);
            }
        }
    }

    /// Encode a build-local super-op stream. A fused item emits one extension
    /// opcode followed by each body's canonical operand record; primitive items
    /// retain the ordinary opcode+record format.
    pub fn encode_superop_rewrite(
        &mut self,
        rewrite: &SuperOpRewrite,
    ) -> Result<(Vec<u8>, Vec<usize>)> {
        let mut out = Vec::new();
        let mut offsets = Vec::with_capacity(rewrite.instrs.len());
        let mut vip = 0u64;
        for item in &rewrite.instrs {
            offsets.push(out.len());
            match item {
                SuperOpStreamInstr::Primitive(ins) => {
                    let opcode = self.spec.opcode_for(ins.op).ok_or_else(|| {
                        anyhow!(
                            "polymorphic encoder: opcode mapping missing for {:?}",
                            ins.op
                        )
                    })?;
                    self.push_encrypted(&mut out, &mut vip, opcode);
                    self.encode_operand_record(ins, &mut out, &mut vip);
                }
                SuperOpStreamInstr::Fused { opcode, body } => {
                    if self.spec.reverse_opcode_map.contains_key(opcode) {
                        return Err(anyhow!(
                            "super-op opcode {opcode:#04x} collides with canonical ISA"
                        ));
                    }
                    self.push_encrypted(&mut out, &mut vip, *opcode);
                    for ins in body {
                        self.encode_operand_record(ins, &mut out, &mut vip);
                    }
                }
            }
        }
        Ok((out, offsets))
    }

    /// RiscProgram을 인코딩하면서 각 micro-op이 시작하는 폴리 바이트코드 오프셋도
    /// 함께 돌려준다. `offsets[i]` = `prog.instrs[i]`(i번째 RISC micro-op)의
    /// 인코딩 시작 오프셋. `offsets.len() == prog.instrs.len()`이며 오프셋은 단조
    /// 증가한다. P3 상용 경로의 매퍼(M9)가 "원본 VA → RISC micro-op 인덱스 →
    /// 폴리 바이트코드 오프셋" 매핑을 기록하는 데 쓴다. [`encode`]는 오프셋을
    /// 버리고 동일한 바이트코드만 반환한다.
    pub fn encode_with_offsets(&mut self, prog: &RiscProgram) -> Result<(Vec<u8>, Vec<usize>)> {
        let mut out = Vec::new();
        let mut offsets = Vec::with_capacity(prog.instrs.len());
        let mut vip = 0u64;

        for ins in &prog.instrs {
            offsets.push(out.len());
            // opcode — VirtualBranch 는 조건과 무관한 단일 canonical opcode.
            let opcode_byte = self.spec.opcode_for(ins.op).ok_or_else(|| {
                anyhow!(
                    "polymorphic encoder: opcode mapping missing for {:?}",
                    ins.op
                )
            })?;

            // 1. Encode Opcode with rolling key
            let enc_op = self.rolling.encrypt_byte(opcode_byte, vip);
            out.push(enc_op);
            vip += 1;

            // 1b. 조건 바이트 — VirtualBranch·Setcc·ConditionalMove 는 조건과 무관한
            //     단일 Opcode 를 공유하고 조건은 `branch_cond_map` 으로 부호화한다.
            match ins.op {
                RiscOp::VirtualBranch { cond }
                | RiscOp::Setcc { cond }
                | RiscOp::ConditionalMove { cond } => {
                    let cond_byte = self.spec.encode_cond(cond);
                    out.push(self.rolling.encrypt_byte(cond_byte, vip));
                    vip += 1;
                }
                _ => {}
            }

            // 2. Encode operands if present
            let encode_operand =
                |op: Option<MicroOperand>, spec: &VirtualIsaSpec| -> (u8, Option<u64>) {
                    match op {
                        Some(MicroOperand::VReg(r)) => (0x80 | spec.encode_reg(r), None),
                        Some(MicroOperand::Temp(t)) => (0xC0 | (t & 0x07), None),
                        Some(MicroOperand::Imm64(v)) => (0x01, Some(v)),
                        Some(MicroOperand::Vsp) => (0x40, None),
                        Some(MicroOperand::Vflags) => (0x41, None),
                        _ => (0x00, None),
                    }
                };

            let (op_dst, _) = encode_operand(ins.dst, &self.spec);
            let (op_src1, imm1) = encode_operand(ins.src1, &self.spec);
            let (op_src2, imm2) = encode_operand(ins.src2, &self.spec);

            out.push(self.rolling.encrypt_byte(op_dst, vip));
            vip += 1;
            out.push(self.rolling.encrypt_byte(op_src1, vip));
            vip += 1;
            out.push(self.rolling.encrypt_byte(op_src2, vip));
            vip += 1;

            // 3. Emit immediates
            if let Some(v1) = imm1 {
                let enc = v1 ^ self.spec.operand_mask;
                for b in enc.to_le_bytes() {
                    out.push(self.rolling.encrypt_byte(b, vip));
                    vip += 1;
                }
            }
            if let Some(v2) = imm2 {
                let enc = v2 ^ self.spec.operand_mask;
                for b in enc.to_le_bytes() {
                    out.push(self.rolling.encrypt_byte(b, vip));
                    vip += 1;
                }
            }

            // VirtualBranch 절대-인덱스 타깃: src1 이 없으면 `imm` 을 타깃 인덱스로 사용.
            let is_abs_branch =
                matches!(ins.op, RiscOp::VirtualBranch { .. }) && ins.src1.is_none();
            if is_abs_branch {
                let enc = ins.imm ^ self.spec.operand_mask;
                for b in enc.to_le_bytes() {
                    out.push(self.rolling.encrypt_byte(b, vip));
                    vip += 1;
                }
            } else if ins.op == RiscOp::AddWithCarry && imm1.is_none() && imm2.is_none() {
                // AddWithCarry 의 cin 8B (등록 피연산자만). 다른 op 의 `imm` 필드
                // (예: 스케일 쉬프트 ShiftLeft with_imm(1/2/3)) 는 참조 eval_state 가
                // src2 로 시프트 횟수를 읽어 의미가 없고, decoder/interpreter/native
                // 어디에도 소비되지 않으므로 스트림에 쓰지 않는다. 이전 코드가
                // `|| ins.imm != 0` 으로 스케일 쉬프트에 8B 를 써서 디코더와
                // desync(전체 프로그램 상용 경로 첫 스케일 쉬프트에서 바이트 오프셋
                // 불일치 → 브랜치 맵/롤링키 재동기화 오류)를 일으켰다.
                let enc = ins.imm ^ self.spec.operand_mask;
                for b in enc.to_le_bytes() {
                    out.push(self.rolling.encrypt_byte(b, vip));
                    vip += 1;
                }
            }
        }

        Ok((out, offsets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::poly::PolymorphicDecoder;
    use crate::vm::risc::{BranchCondition, MicroOperand, RiscOp, RiscProgram};

    /// 전체 신규 op (메모리 폭별 · 산술시프트 · 브랜치(모든 조건/CounterZero 폭 포함,
    /// 절대/간접 타깃) · 네이티브 콜 브리지)를 인코딩하고 디코더로 라운드트립해
    /// opcode 매핑 누락 없음 + 피연산자/폭/조건/타깃 보존을 검증한다.
    #[test]
    fn test_encode_all_new_ops_roundtrip() {
        let seed = 0xCAFE_F00D_1234_5678;
        let mut instrs = Vec::new();

        // 메모리 폭별로 서로 다른 opcode 사용 (폭 보존)
        for w in [1u8, 2, 4, 8] {
            instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width: w })
                    .with_dst(MicroOperand::VReg(0))
                    .with_src1(MicroOperand::VReg(1)),
            );
            instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width: w })
                    .with_src1(MicroOperand::VReg(1))
                    .with_src2(MicroOperand::VReg(2)),
            );
        }

        // 산술 시프트
        instrs.push(
            MicroInstr::new(RiscOp::ArithmeticShiftRight)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
        );
        // 산술 시프트 + 즉시 카운트
        instrs.push(
            MicroInstr::new(RiscOp::ArithmeticShiftRight)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(3)),
        );

        // VirtualBranch: 모든 조건 + 절대-인덱스 타깃 & 간접(src1) 타깃
        for cond in [
            BranchCondition::Always,
            BranchCondition::Zero,
            BranchCondition::NotZero,
            BranchCondition::Carry,
            BranchCondition::NotCarry,
            BranchCondition::Sign,
            BranchCondition::NotSign,
            BranchCondition::Overflow,
            BranchCondition::NotOverflow,
            BranchCondition::Greater,
            BranchCondition::Less,
            BranchCondition::GreaterOrEqual,
            BranchCondition::LessOrEqual,
            BranchCondition::Above,
            BranchCondition::AboveOrEqual,
            BranchCondition::Below,
            BranchCondition::BelowOrEqual,
            BranchCondition::Parity,
            BranchCondition::NotParity,
            BranchCondition::CounterZero(2),
            BranchCondition::CounterZero(4),
            BranchCondition::CounterZero(8),
        ] {
            // 절대-인덱스 타깃 (src1 없음, imm=타깃)
            instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond }).with_imm(7));
            // 간접 타깃 (src1 동적 값) — 타깃은 src1에 실리고 imm 은 사용되지 않음(평가 시 무시).
            instrs.push(
                MicroInstr::new(RiscOp::VirtualBranch { cond }).with_src1(MicroOperand::VReg(4)),
            );
            // Imm64 src1 타깃
            instrs.push(
                MicroInstr::new(RiscOp::VirtualBranch { cond }).with_src1(MicroOperand::Imm64(9)),
            );
        }

        // NativeCallBridge (즉시 인자 포함)
        instrs.push(
            MicroInstr::new(RiscOp::NativeCallBridge)
                .with_dst(MicroOperand::VReg(0))
                .with_src1(MicroOperand::Imm64(0x1234)),
        );
        instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(instrs);

        // 1. 모든 op 에 대해 opcode 매핑이 존재해야 한다 (에러 없이 인코딩).
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc
            .encode(&prog)
            .expect("polymorphic encoder: no opcode mapping missing for any RiscOp");

        // 2. 디코더로 라운드트립 → op/피연산자/폭/조건/타깃 모두 보존.
        let mut dec = PolymorphicDecoder::new(seed);
        let recovered = dec
            .decode(&bytecode)
            .expect("decoder must roundtrip encoder output");
        assert_eq!(recovered.instrs.len(), prog.instrs.len());
        for (a, b) in recovered.instrs.iter().zip(prog.instrs.iter()) {
            assert_eq!(a.op, b.op, "op mismatch: {a:?} vs {b:?}");
            assert_eq!(a.dst, b.dst);
            assert_eq!(a.src1, b.src1);
            assert_eq!(a.src2, b.src2);
            assert_eq!(a.imm, b.imm);
        }
    }

    /// 메모리 폭을 8로 통합(collapse)하지 않고 폭별 opcode 를 사용하는지 직접 검증.
    #[test]
    fn test_encode_preserves_memory_width_opcodes() {
        let seed = 0xDEADBEEF_1234_5678;
        let spec = VirtualIsaSpec::from_seed(seed);

        // 폭별로 다른 인코딩 스트림이 나와야 한다 (폭 통합 금지).
        let mk = |w: u8| {
            let mut d = RiscDesynthesizer2::default();
            d.push(
                MicroInstr::new(RiscOp::MemoryRead { width: w })
                    .with_dst(MicroOperand::VReg(0))
                    .with_src1(MicroOperand::VReg(1)),
            );
            d.push(MicroInstr::new(RiscOp::Halt));
            let mut enc = PolymorphicEncoder::new(seed);
            enc.encode(&d.prog()).unwrap()
        };

        let b1 = mk(1);
        let b2 = mk(2);
        let b4 = mk(4);
        let b8 = mk(8);
        assert_ne!(b1, b2, "width 1 vs 2 must differ");
        assert_ne!(b2, b4, "width 2 vs 4 must differ");
        assert_ne!(b4, b8, "width 4 vs 8 must differ");

        // 라운드트립으로 폭이 실제로 보존되는지 확인.
        let mut dec = PolymorphicDecoder::new(seed);
        let rec1 = dec.decode(&b1).unwrap();
        assert_eq!(rec1.instrs[0].op, RiscOp::MemoryRead { width: 1 });
        let mut dec = PolymorphicDecoder::new(seed);
        let rec8 = dec.decode(&b8).unwrap();
        assert_eq!(rec8.instrs[0].op, RiscOp::MemoryRead { width: 8 });
    }

    /// 인코더/디코더가 같은 시드로 동기화되어야 하는 기존 계약 재확인
    /// (이전 부호화 방식과 하위 호환: 기존 op 들의 라운드트립).
    #[test]
    fn test_encode_existing_ops_roundtrip() {
        use crate::vm::risc::RiscDesynthesizer;
        let seed = 0x8899AABBCCDDEEFF;
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(1200),
            MicroOperand::Imm64(0),
        );
        d.emit_sub(
            MicroOperand::VReg(0),
            MicroOperand::VReg(0),
            MicroOperand::Imm64(0x55),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);

        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let mut dec = PolymorphicDecoder::new(seed);
        let recovered = dec.decode(&bytecode).unwrap();
        assert_eq!(recovered.instrs.len(), prog.instrs.len());
        for (a, b) in recovered.instrs.iter().zip(prog.instrs.iter()) {
            assert_eq!(a.op, b.op);
            assert_eq!(a.dst, b.dst);
            assert_eq!(a.src1, b.src1);
            assert_eq!(a.src2, b.src2);
            assert_eq!(a.imm, b.imm);
        }
    }

    #[test]
    fn superop_encoder_matches_canonical_stream_without_fusion() {
        use crate::vm::threaded::{SuperOpIndexMap, SuperOpRewrite, SuperOpStreamInstr};
        let seed = 0xA11C_E55A_9912_4401;
        let instrs = vec![
            MicroInstr::new(RiscOp::Mov)
                .with_dst(MicroOperand::VReg(0))
                .with_src1(MicroOperand::Imm64(0x1234)),
            MicroInstr::new(RiscOp::Halt),
        ];
        let rewrite = SuperOpRewrite {
            instrs: instrs
                .iter()
                .cloned()
                .map(SuperOpStreamInstr::Primitive)
                .collect(),
            index_map: SuperOpIndexMap {
                old_to_new: vec![0, 1],
                rewritten_len: 2,
            },
        };
        let mut canonical = PolymorphicEncoder::new(seed);
        let expected = canonical.encode(&RiscProgram::new(instrs)).unwrap();
        let mut extension = PolymorphicEncoder::new(seed);
        let (actual, offsets) = extension.encode_superop_rewrite(&rewrite).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(offsets.len(), 2);
    }

    #[test]
    fn superop_encoder_emits_one_opcode_for_fused_body() {
        use crate::vm::poly::RollingKeyEngine;
        use crate::vm::threaded::{SuperOpIndexMap, SuperOpRewrite, SuperOpStreamInstr};
        let seed = 0x5155_5045_524F_5001;
        let spec = VirtualIsaSpec::from_seed(seed);
        let extension_opcode = (u8::MIN..=u8::MAX)
            .find(|byte| !spec.reverse_opcode_map.contains_key(byte))
            .unwrap();
        let first = MicroInstr::new(RiscOp::Nor)
            .with_dst(MicroOperand::Temp(0))
            .with_src1(MicroOperand::VReg(1))
            .with_src2(MicroOperand::VReg(2));
        let second = MicroInstr::new(RiscOp::ShiftRight)
            .with_dst(MicroOperand::VReg(3))
            .with_src1(MicroOperand::Temp(0))
            .with_src2(MicroOperand::Imm64(7));
        let halt = MicroInstr::new(RiscOp::Halt);
        let rewrite = SuperOpRewrite {
            instrs: vec![
                SuperOpStreamInstr::Fused {
                    opcode: extension_opcode,
                    body: vec![first.clone(), second.clone()],
                },
                SuperOpStreamInstr::Primitive(halt.clone()),
            ],
            index_map: SuperOpIndexMap {
                old_to_new: vec![0, 0, 1],
                rewritten_len: 2,
            },
        };
        let mut normal = PolymorphicEncoder::new(seed);
        let normal_bytes = normal
            .encode(&RiscProgram::new(vec![first, second, halt]))
            .unwrap();
        let mut fused = PolymorphicEncoder::new(seed);
        let (fused_bytes, offsets) = fused.encode_superop_rewrite(&rewrite).unwrap();
        assert_eq!(fused_bytes.len() + 1, normal_bytes.len());
        assert_eq!(offsets.len(), 2);
        let mut rolling = RollingKeyEngine::new(seed);
        assert_eq!(rolling.decrypt_byte(fused_bytes[0], 0), extension_opcode);
    }
}

// 작은 헬퍼: 특정 폭 인스트럭션만 담는 프로그램을 조립한다.
#[cfg(test)]
struct RiscDesynthesizer2 {
    instrs: Vec<MicroInstr>,
}
#[cfg(test)]
impl RiscDesynthesizer2 {
    fn default() -> Self {
        Self { instrs: Vec::new() }
    }
    fn push(&mut self, i: MicroInstr) {
        self.instrs.push(i);
    }
    fn prog(&self) -> RiscProgram {
        RiscProgram::new(self.instrs.clone())
    }
}
