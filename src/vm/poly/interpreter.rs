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
    /// 가상 스택 포인터 (바이트 오프셋, 아래로 성장). `RiscProgram::eval_state`와 동일 계약.
    pub vsp: u64,
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
            vsp: 0,
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
                                   vsp: u64,
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
                            vsp
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
                    let a = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm1);
                    let b = get_operand_val(op_src2_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm2);
                    let res = !(a | b);
                    self.flags.update_logic64(res);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::AddWithCarry => {
                    let a = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm1);
                    let b = get_operand_val(op_src2_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm2);

                    let (res, _cout) = self.flags.update_add64(a, b, cin);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::ShiftRight => {
                    let a = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm1);
                    let cnt = get_operand_val(op_src2_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm2) & 63;
                    let res = if cnt == 0 { a } else { a >> cnt };
                    self.flags.update_logic64(res);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::ShiftLeft => {
                    let a = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm1);
                    let cnt = get_operand_val(op_src2_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm2) & 63;
                    let res = if cnt == 0 { a } else { a << cnt };
                    self.flags.update_logic64(res);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::VirtualPush => {
                    let v = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm1);
                    self.vsp = self.vsp.wrapping_sub(8);
                    self.stack.push(v);
                }
                RiscOp::VirtualPop => {
                    if let Some(v) = self.stack.pop() {
                        self.vsp = self.vsp.wrapping_add(8);
                        self.store_operand(op_dst_raw, v);
                    }
                }
                RiscOp::SetFlag => {
                    let v = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm1);
                    self.flags.raw = v & 0x8D5; // CF|PF|AF|ZF|SF|OF 마스크
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
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscDesynthesizer, RiscProgram, RiscOp};

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

    /// T1-4 차등 검증: 인터프리터(폴리모픽) == 참조 시뮬레이터(eval_state).
    /// 두 구현이 같은 프로그램에 대해 동일한 레지스터/스택/플래그 상태를 내야 한다.
    #[test]
    fn test_poly_interp_matches_reference_state() {
        let seed = 0x1122334455667788;
        let mut d = RiscDesynthesizer::new();

        // R0 = 0x200, R1 = 5
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x200), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(5), MicroOperand::Imm64(0));
        // R2 = R0 >> R1  (0x10)
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftRight)
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
        );
        // R3 = R0 << 2 (0x800)
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftLeft)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(2)),
        );
        // push R3, pop R4
        d.emit_push(MicroOperand::VReg(3));
        d.emit_pop(MicroOperand::VReg(4));
        // NOR: R5 = ~(R2 | R1)
        d.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::VReg(1)),
        );
        // Halt
        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);

        // 참조 시뮬레이터
        let ref_st = prog.eval_state(&[0u64; 16]);

        // 폴리모픽 인코딩 + 인터프리터
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.run(&bytecode).unwrap();

        assert_eq!(interp.regs[0], ref_st.regs[0]);
        assert_eq!(interp.regs[1], ref_st.regs[1]);
        assert_eq!(interp.regs[2], ref_st.regs[2], "shift right");
        assert_eq!(interp.regs[3], ref_st.regs[3], "shift left");
        assert_eq!(interp.regs[4], ref_st.regs[4], "pop");
        assert_eq!(interp.regs[5], ref_st.regs[5], "nor");
        assert_eq!(interp.flags.raw, ref_st.flags, "flags");
        assert_eq!(interp.vsp, ref_st.vsp, "vsp");
        assert_eq!(interp.stack.len(), ref_st.stack.len(), "stack depth");
        assert_eq!(interp.regs[2], 0x10);
        assert_eq!(interp.regs[3], 0x800);
        assert_eq!(interp.regs[5], !(0x10 | 5));
    }
}
