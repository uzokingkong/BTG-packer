// ==============================================================================
// BTG - Commercial-Grade VM: Polymorphic Bytecode Stream Interpreter
// ==============================================================================
// 가변 암호화된 폴리모픽 바이트코드를 런타임에 롤링 키로 스트림 복호화하면서
// 가상 CPU 상태(레지스터, 플래그, 가상 스택)를 직접 시뮬레이션 및 실행한다.
// ==============================================================================

use super::isa_spec::VirtualIsaSpec;
use super::rolling_key::RollingKeyEngine;
use crate::vm::risc::{RiscOp, VirtualFlags};
use anyhow::{anyhow, Result};

pub struct PolymorphicInterpreter {
    pub spec: VirtualIsaSpec,
    pub rolling: RollingKeyEngine,
    pub regs: [u64; 16],
    pub temps: [u64; 8],
    pub flags: VirtualFlags,
    pub stack: Vec<u64>,
}

impl PolymorphicInterpreter {
    pub fn new(seed: u64) -> Self {
        Self {
            spec: VirtualIsaSpec::from_seed(seed),
            rolling: RollingKeyEngine::new(seed),
            regs: [0u64; 16],
            temps: [0u64; 8],
            flags: VirtualFlags::default(),
            stack: Vec::with_capacity(1024),
        }
    }

    /// 암호화된 바이트코드 스트림 실행
    pub fn run(&mut self, bytecode: &[u8]) -> Result<()> {
        let mut vip = 0usize;

        while vip < bytecode.len() {
            // 1. Decrypt Opcode
            let enc_op = bytecode[vip];
            let raw_op = self.rolling.decrypt_byte(enc_op, vip as u64);
            vip += 1;

            let risc_op = self
                .spec
                .reverse_opcode_map
                .get(&raw_op)
                .cloned()
                .ok_or_else(|| anyhow!("poly interp: unknown decrypted opcode 0x{raw_op:02X} at offset 0x{vip:X}"))?;

            // 2. Decrypt 3 operand bytes
            if vip + 3 > bytecode.len() {
                break;
            }
            let op_dst_raw = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;
            let op_src1_raw = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;
            let op_src2_raw = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;

            // 3. Decrypt 8-byte immediates if present
            let imm1 = if op_src1_raw == 0x01 {
                let mut b = [0u8; 8];
                for i in 0..8 {
                    if vip < bytecode.len() {
                        b[i] = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                        vip += 1;
                    }
                }
                u64::from_le_bytes(b) ^ self.spec.operand_mask
            } else {
                0
            };

            let imm2 = if op_src2_raw == 0x01 {
                let mut b = [0u8; 8];
                for i in 0..8 {
                    if vip < bytecode.len() {
                        b[i] = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                        vip += 1;
                    }
                }
                u64::from_le_bytes(b) ^ self.spec.operand_mask
            } else {
                0
            };

            let cin = if op_src1_raw != 0x01 && op_src2_raw != 0x01 && (risc_op == RiscOp::AddWithCarry) {
                let mut b = [0u8; 8];
                for i in 0..8 {
                    if vip < bytecode.len() {
                        b[i] = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                        vip += 1;
                    }
                }
                u64::from_le_bytes(b) ^ self.spec.operand_mask
            } else {
                0
            };

            // Helper to resolve decoded operand value
            let get_operand_val = |raw: u8,
                                   spec: &VirtualIsaSpec,
                                   regs: &[u64; 16],
                                   temps: &[u64; 8],
                                   flags: u64,
                                   imm: u64|
             -> u64 {
                let kind = raw & 0xC0;
                let payload = raw & 0x3F;
                match kind {
                    0x80 => {
                        let reg_idx = spec.decode_reg(payload);
                        regs[reg_idx as usize]
                    }
                    0xC0 => temps[(payload & 0x07) as usize],
                    0x40 => {
                        if payload == 0x01 {
                            flags
                        } else {
                            0
                        }
                    }
                    _ => {
                        if raw == 0x01 {
                            imm
                        } else {
                            0
                        }
                    }
                }
            };

            // 4. Execute RiscOp
            match risc_op {
                RiscOp::Nor => {
                    let a = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, imm1);
                    let b = get_operand_val(op_src2_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, imm2);
                    let res = !(a | b);
                    self.flags.update_logic64(res);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::AddWithCarry => {
                    let a = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, imm1);
                    let b = get_operand_val(op_src2_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, imm2);

                    let (res, _cout) = self.flags.update_add64(a, b, cin);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::VirtualPush => {
                    let v = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, imm1);
                    self.stack.push(v);
                }
                RiscOp::VirtualPop => {
                    let v = self.stack.pop().unwrap_or(0);
                    self.store_operand(op_dst_raw, v);
                }
                RiscOp::Halt => {
                    break;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn store_operand(&mut self, raw: u8, val: u64) {
        let kind = raw & 0xC0;
        let payload = raw & 0x3F;
        match kind {
            0x80 => {
                let reg_idx = self.spec.decode_reg(payload);
                self.regs[reg_idx as usize] = val;
            }
            0xC0 => {
                self.temps[(payload & 0x07) as usize] = val;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::poly::PolymorphicEncoder;
    use crate::vm::risc::{MicroOperand, RiscDesynthesizer, RiscProgram};

    #[test]
    fn test_polymorphic_encoder_and_interpreter_roundtrip() {
        let seed = 0x8899AABBCCDDEEFF;
        let mut d = RiscDesynthesizer::new();

        // R0 = 1200
        // R1 = 450
        // R0 = R0 - R1  (750)
        // R0 = R0 ^ 0x55 (750 ^ 85 = 795)
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(1200), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(450), MicroOperand::Imm64(0));
        d.emit_sub(MicroOperand::VReg(0), MicroOperand::VReg(0), MicroOperand::VReg(1));
        d.emit_xor(MicroOperand::VReg(0), MicroOperand::VReg(0), MicroOperand::Imm64(0x55));

        let prog = RiscProgram::new(d.instrs);

        // 1. Encode with polymorphic randomized ISA & rolling key
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();

        // 2. Execute on polymorphic interpreter
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.run(&bytecode).unwrap();

        assert_eq!(interp.regs[0], (1200 - 450) ^ 0x55);
        assert_eq!(interp.regs[1], 450);
    }
}
