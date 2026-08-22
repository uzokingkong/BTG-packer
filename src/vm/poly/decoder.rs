// ==============================================================================
// BTG - Commercial-Grade VM: Polymorphic Bytecode Stream Decoder (T1-4)
// ==============================================================================
// `PolymorphicEncoder`가 롤링 키로 암호화한 폴리모픽 바이트코드 스트림을 다시
// 원래의 `RiscProgram`(마이크로-op 시퀀스)으로 복호화한다. `PolymorphicInterpreter`
// 가 스트림을 해석할 때와 **동일한 복호화/피연산자 디코딩 계약**을 따르므로,
// 디코더로 복원한 프로그램을 네이티브 하네스(`NativeVmHarness`)에 넣어 실행하면
// 인터프리터 실행 결과와 완전히 일치한다 (T1-4 "네이티브↔폴리모픽 동치").
// ==============================================================================

use super::architecture_family::VmArchitectureFamily;
use super::isa_spec::VirtualIsaSpec;
use super::rolling_key::RollingKeyEngine;
use crate::vm::risc::{BranchCondition, MicroInstr, MicroOperand, RiscOp, RiscProgram};
use anyhow::{anyhow, Result};

/// 디코드 시 최대 마이크로-op 수 (리소스 가드). 루프는 어차피 스트림 끝에서
/// 종료되므로 이 캡은 병리적 입력 방어용이다. 상용(`--vm-commercial`) 전체
/// 프로그램은 수백만 op 로 커질 수 있어 기존 200k 캡은 너무 낮았다
/// (self-decoding branch-map 검증 실패). 4M op ≈ 소스 20MB 이상을 커버.
pub const MAX_DECODE_INSTRS: usize = 4_000_000;

/// 폴리모픽 바이트코드 → `RiscProgram` 복호화기.
pub struct PolymorphicDecoder {
    pub spec: VirtualIsaSpec,
    pub rolling: RollingKeyEngine,
}

impl PolymorphicDecoder {
    pub fn new(seed: u64) -> Self {
        Self::new_for_family(seed, VmArchitectureFamily::for_build(seed))
    }

    pub fn new_for_family(seed: u64, family: VmArchitectureFamily) -> Self {
        Self {
            spec: VirtualIsaSpec::from_seed_and_family(seed, family),
            rolling: RollingKeyEngine::new(seed),
        }
    }

    /// 암호화된 스트림을 한 인스트럭션씩 복호화해 `RiscProgram`으로 되돌린다.
    ///
    /// 복호화 순서·피연산자 디코딩은 `PolymorphicInterpreter::run`과 동일:
    ///   opcode 1B → (VirtualBranch 면 조건 1B) → dst/src1/src2 3B → (src==Imm64 이면) 8B
    ///   즉시값 → (AddWithCarry 이고 즉시 피연산자가 없으면) cin 8B → (VirtualBranch 의
    ///   절대-인덱스 타깃(src1 없음)이면) 타깃 8B. 즉시값은 `operand_mask`로 XOR 복원.
    pub fn decode(&mut self, bytecode: &[u8]) -> Result<RiscProgram> {
        self.decode_full(bytecode, true)
    }

    /// `decode` + `decode_full(.., stop_at_halt=false)`: decode the ENTIRE stream
    /// without stopping at Halt. The whole-program commercial lift contains many
    /// Halt ops (one per `ret`), and the branch-map builder needs byte offsets for
    /// every micro-op, so it must not truncate at the first Halt.
    pub fn decode_full(&mut self, bytecode: &[u8], stop_at_halt: bool) -> Result<RiscProgram> {
        let mut instrs = Vec::new();
        let mut vip = 0usize;

        while vip < bytecode.len() {
            // 1. Opcode
            let raw_op = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;
            let risc_op = self
                .spec
                .reverse_opcode_map
                .get(&raw_op)
                .cloned()
                .ok_or_else(|| {
                    anyhow!(super::DecodeError::InvalidOpcode {
                        byte: raw_op,
                        at: vip
                    })
                })?;

            // 1b. 조건 바이트 — VirtualBranch·Setcc·ConditionalMove (opcode 직후)
            let cond = if let RiscOp::VirtualBranch { .. }
            | RiscOp::Setcc { .. }
            | RiscOp::ConditionalMove { .. } = risc_op
            {
                if vip >= bytecode.len() {
                    return Err(anyhow!(super::DecodeError::TruncatedOpcode { at: vip }));
                }
                let raw_cond = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                vip += 1;
                self.spec.decode_cond(raw_cond).ok_or_else(|| {
                    anyhow!(super::DecodeError::InvalidCondition {
                        byte: raw_cond,
                        at: vip
                    })
                })?
            } else {
                BranchCondition::Always
            };
            let risc_op = match risc_op {
                RiscOp::VirtualBranch { .. } => RiscOp::VirtualBranch { cond },
                RiscOp::Setcc { .. } => RiscOp::Setcc { cond },
                RiscOp::ConditionalMove { .. } => RiscOp::ConditionalMove { cond },
                other => other,
            };

            if vip + 3 > bytecode.len() {
                return Err(anyhow!(super::DecodeError::TruncatedOperand { at: vip }));
            }
            let op_dst = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;
            let op_src1 = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;
            let op_src2 = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;

            // 2. Immediates (src == Imm64 일 때 8B)
            let imm1 = if op_src1 == 0x01 {
                if vip + 8 > bytecode.len() {
                    return Err(anyhow!(super::DecodeError::TruncatedImmediate { at: vip }));
                }
                let mut b = [0u8; 8];
                for i in 0..8 {
                    b[i] = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                    vip += 1;
                }
                u64::from_le_bytes(b) ^ self.spec.operand_mask
            } else {
                0
            };
            let imm2 = if op_src2 == 0x01 {
                if vip + 8 > bytecode.len() {
                    return Err(anyhow!(super::DecodeError::TruncatedImmediate { at: vip }));
                }
                let mut b = [0u8; 8];
                for i in 0..8 {
                    b[i] = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                    vip += 1;
                }
                u64::from_le_bytes(b) ^ self.spec.operand_mask
            } else {
                0
            };
            // cin (AddWithCarry 이고 즉시 피연산자 없을 때 8B) — 인터프리터와 동일 규칙.
            let cin = if op_src1 != 0x01 && op_src2 != 0x01 && risc_op == RiscOp::AddWithCarry {
                if vip + 8 > bytecode.len() {
                    return Err(anyhow!(super::DecodeError::TruncatedImmediate { at: vip }));
                }
                let mut b = [0u8; 8];
                for i in 0..8 {
                    b[i] = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                    vip += 1;
                }
                u64::from_le_bytes(b) ^ self.spec.operand_mask
            } else {
                0
            };

            // VirtualBranch 절대-인덱스 타깃 (src1 이 없으면 8B 즉시값). src1 은 0x00 으로
            // 부호화되므로 `op_src1 == 0x00` 이 곧 "src1 없음" 과 동치다.
            let branch_target =
                if matches!(risc_op, RiscOp::VirtualBranch { .. }) && op_src1 == 0x00 {
                    if vip + 8 > bytecode.len() {
                        return Err(anyhow!(super::DecodeError::TruncatedBranchTarget {
                            at: vip
                        }));
                    }
                    let mut b = [0u8; 8];
                    for i in 0..8 {
                        b[i] = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                        vip += 1;
                    }
                    u64::from_le_bytes(b) ^ self.spec.operand_mask
                } else {
                    0
                };

            let decode_op = |raw: u8| -> Option<MicroOperand> {
                let kind = raw & 0xC0;
                let payload = raw & 0x3F;
                match kind {
                    0x80 => Some(MicroOperand::VReg(self.spec.decode_reg(payload))),
                    0xC0 => Some(MicroOperand::Temp(payload & 0x07)),
                    0x40 => {
                        if payload == 0x01 {
                            Some(MicroOperand::Vflags)
                        } else {
                            Some(MicroOperand::Vsp)
                        }
                    }
                    _ => {
                        if raw == 0x01 {
                            None // Imm64 은 decode_op 호출부에서 즉시값으로 대체
                        } else {
                            None
                        }
                    }
                }
            };

            let mut ins = MicroInstr::new(risc_op);
            ins.dst = decode_op(op_dst);
            ins.src1 = match op_src1 {
                0x01 => Some(MicroOperand::Imm64(imm1)),
                _ => decode_op(op_src1),
            };
            ins.src2 = match op_src2 {
                0x01 => Some(MicroOperand::Imm64(imm2)),
                _ => decode_op(op_src2),
            };
            // VirtualBranch 절대-인덱스 타깃이면 imm 을 타깃으로, 아니면 cin.
            ins.imm = if matches!(risc_op, RiscOp::VirtualBranch { .. }) && op_src1 == 0x00 {
                branch_target
            } else {
                cin
            };

            instrs.push(ins);
            if stop_at_halt && risc_op == RiscOp::Halt {
                break;
            }
            if instrs.len() > MAX_DECODE_INSTRS {
                return Err(anyhow!(super::DecodeError::InstructionLimitExceeded {
                    limit: MAX_DECODE_INSTRS,
                    at: vip,
                }));
            }
        }

        Ok(RiscProgram::new(instrs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::poly::PolymorphicEncoder;
    use crate::vm::risc::RiscDesynthesizer;

    /// 디코더 ↔ 인코더 라운드트립: encode(prog) → decode() → 원래 프로그램과 op 목록 동일.
    #[test]
    fn test_poly_decode_roundtrip_op_list() {
        let seed = 0x8899AABBCCDDEEFF;
        let mut d = RiscDesynthesizer::new();
        d.emit_add(
            MicroOperand::VReg(0),
            MicroOperand::Imm64(1200),
            MicroOperand::Imm64(0),
        );
        d.emit_add(
            MicroOperand::VReg(1),
            MicroOperand::Imm64(450),
            MicroOperand::Imm64(0),
        );
        d.emit_sub(
            MicroOperand::VReg(0),
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
        );
        d.emit_xor(
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

        // 원래 프로그램과 디코드된 프로그램의 op 시퀀스가 동일해야 한다.
        assert_eq!(recovered.instrs.len(), prog.instrs.len());
        for (a, b) in recovered.instrs.iter().zip(prog.instrs.iter()) {
            assert_eq!(a.op, b.op);
            assert_eq!(a.dst, b.dst);
            assert_eq!(a.src1, b.src1);
            assert_eq!(a.src2, b.src2);
            assert_eq!(a.imm, b.imm);
        }

        // 그리고 참조 시뮬레이터 실행 결과도 같아야 한다.
        let ref_st = prog.eval_state(&[0u64; 16]);
        let dec_st = recovered.eval_state(&[0u64; 16]);
        assert_eq!(dec_st.regs[0], ref_st.regs[0]);
        assert_eq!(dec_st.regs[1], ref_st.regs[1]);
        assert_eq!(dec_st.flags, ref_st.flags);
    }

    /// decode_full must recover EVERY instruction (including those after a Halt —
    /// the whole-program commercial lift emits one Halt per `ret`, so the stream
    /// has many Halts and decoding must not truncate at the first one).
    #[test]
    fn test_decode_full_keeps_instructions_after_halt() {
        use crate::vm::risc::{MicroInstr, MicroOperand, RiscOp};
        let seed = 0x1122334455667788u64;
        let mut instrs = Vec::new();
        for i in 0..5u64 {
            instrs.push(
                MicroInstr::new(RiscOp::Mov)
                    .with_dst(MicroOperand::VReg(0))
                    .with_src1(MicroOperand::Imm64(i)),
            );
            instrs.push(MicroInstr::new(RiscOp::Halt));
        }
        let prog = RiscProgram::new(instrs);
        let mut enc = PolymorphicEncoder::new(seed);
        let bc = enc.encode(&prog).unwrap();

        let mut dec = PolymorphicDecoder::new(seed);
        let full = dec.decode_full(&bc, false).unwrap();
        assert_eq!(
            full.instrs.len(),
            prog.instrs.len(),
            "decode_full must keep every instruction (incl. after Halt)"
        );
        for (a, b) in full.instrs.iter().zip(prog.instrs.iter()) {
            assert_eq!(a.op, b.op);
            assert_eq!(a.dst, b.dst);
            assert_eq!(a.src1, b.src1);
            assert_eq!(a.src2, b.src2);
            assert_eq!(a.imm, b.imm);
        }
    }
}
