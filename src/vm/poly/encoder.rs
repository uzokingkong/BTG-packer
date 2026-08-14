// ==============================================================================
// BTG - Commercial-Grade VM: Polymorphic Bytecode Stream Encoder
// ==============================================================================

use super::isa_spec::VirtualIsaSpec;
use super::rolling_key::RollingKeyEngine;
use crate::vm::risc::{MicroInstr, MicroOperand, RiscOp, RiscProgram};
use anyhow::{anyhow, Result};

pub struct PolymorphicEncoder {
    pub spec: VirtualIsaSpec,
    pub rolling: RollingKeyEngine,
}

impl PolymorphicEncoder {
    pub fn new(seed: u64) -> Self {
        Self {
            spec: VirtualIsaSpec::from_seed(seed),
            rolling: RollingKeyEngine::new(seed),
        }
    }

    /// RiscProgram을 무작위 암호화된 폴리모픽 바이트코드로 인코딩
    pub fn encode(&mut self, prog: &RiscProgram) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut vip = 0u64;

        for ins in &prog.instrs {
            let base_op = match ins.op {
                RiscOp::MemoryRead { .. } => RiscOp::MemoryRead { width: 8 },
                RiscOp::MemoryWrite { .. } => RiscOp::MemoryWrite { width: 8 },
                op => op,
            };

            let opcode_byte = *self
                .spec
                .opcode_map
                .get(&base_op)
                .ok_or_else(|| anyhow!("polymorphic encoder: opcode mapping missing for {:?}", ins.op))?;

            // 1. Encode Opcode with rolling key
            let enc_op = self.rolling.encrypt_byte(opcode_byte, vip);
            out.push(enc_op);
            vip += 1;

            // 2. Encode operands if present
            let encode_operand = |op: Option<MicroOperand>, spec: &VirtualIsaSpec| -> (u8, Option<u64>) {
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
            if imm1.is_none() && imm2.is_none() && (ins.op == RiscOp::AddWithCarry || ins.imm != 0) {
                let enc = ins.imm ^ self.spec.operand_mask;
                for b in enc.to_le_bytes() {
                    out.push(self.rolling.encrypt_byte(b, vip));
                    vip += 1;
                }
            }
        }

        Ok(out)
    }
}
