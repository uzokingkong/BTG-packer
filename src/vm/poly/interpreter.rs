// ==============================================================================
// BTG - Commercial-Grade VM: Polymorphic Bytecode Stream Interpreter
// ==============================================================================
// 가변 암호화된 폴리모픽 바이트코드를 런타임에 롤링 키로 스트림 복호화하면서
// 가상 CPU 상태(레지스터, 플래그, 가상 스택, 가상 메모리)를 직접 시뮬레이션 및 실행한다.
//
// `RiscProgram::eval_state`(src/vm/risc/mod.rs)와 동일한 의미론을 유지하며,
// T1-4 차등(differential) 검증 기준이 된다. 추가된 5개 연산:
//   * ArithmeticShiftRight — 부호 있는 산술 우측 시프트 (SAR)
//   * MemoryRead / MemoryWrite — 바이트 세분 리틀엔디언 가상 메모리 (폭 1/2/4/8)
//   * VirtualBranch — 조건 분기 (모든 BranchCondition, CounterZero 포함)
//   * NativeCallBridge — 인지된 no-op 스텁 (실제 호스트 콜은 런타임 계층, Phase P3)
// ==============================================================================

use super::isa_spec::VirtualIsaSpec;
use super::rolling_key::RollingKeyEngine;
use crate::vm::risc::{BranchCondition, RiscOp, VirtualFlags};
use anyhow::{anyhow, Result};
use std::collections::HashMap;

pub struct PolymorphicInterpreter {
    pub spec: VirtualIsaSpec,
    pub rolling: RollingKeyEngine,
    pub regs: [u64; 16],
    pub temps: [u64; 8],
    pub flags: VirtualFlags,
    pub stack: Vec<u64>,
    /// 가상 스택 포인터 (바이트 오프셋, 아래로 성장). `RiscProgram::eval_state`와 동일 계약.
    pub vsp: u64,
    /// 가상 메모리 (주소 → 바이트, `MemoryRead`/`MemoryWrite` 대상).
    /// `RiscEvalState.mem`과 동일 계약: 미기입 주소는 0으로 취급.
    pub mem: HashMap<u64, u8>,
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
            mem: HashMap::new(),
        }
    }

    /// 사전 초기화된 가상 메모리로 인터프리터를 만든다.
    /// (메모리 피연산자 차등 테스트에서 초기 `.data`/`.bss`를 주입하기 위함 —
    /// `RiscProgram::eval_state_with_mem`과 동일 계약.)
    pub fn with_mem(mut self, mem: HashMap<u64, u8>) -> Self {
        self.mem = mem;
        self
    }

    /// 암호화된 바이트코드 스트림 실행
    pub fn run(&mut self, bytecode: &[u8]) -> Result<()> {
        let mut vip = 0usize;
        // 각 인스트럭션 **opcode 의 시작 바이트 오프셋** (인덱스 순). taken 분기의
        // 인스트럭션-인덱스 타깃을 바이트 오프셋으로 변환해 `eval_state`와 일치시킨다.
        let instr_starts = self.instr_starts(bytecode);

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

            // 1b. VirtualBranch: 조건 바이트 (opcode 직후, decoder와 동일 계약)
            let risc_op = match risc_op {
                RiscOp::VirtualBranch { .. } => {
                    if vip >= bytecode.len() {
                        break;
                    }
                    let raw_cond = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                    vip += 1;
                    let cond = self
                        .spec
                        .decode_cond(raw_cond)
                        .ok_or_else(|| anyhow!("poly interp: unknown branch cond 0x{raw_cond:02X} at offset 0x{vip:X}"))?;
                    RiscOp::VirtualBranch { cond }
                }
                other => other,
            };

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

            // cin (AddWithCarry 이고 즉시 피연산자 없을 때 8B) — decoder와 동일 규칙.
            let cin = if op_src1_raw != 0x01 && op_src2_raw != 0x01 && risc_op == RiscOp::AddWithCarry {
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

            // VirtualBranch 절대-인덱스 타깃 (src1 없음 → 8B 즉시값) — decoder와 동일 계약.
            // src1 은 `None`이면 0x00 으로 부호화되므로 `op_src1_raw == 0x00` 이 곧 "src1 없음".
            let branch_target =
                if matches!(risc_op, RiscOp::VirtualBranch { .. }) && op_src1_raw == 0x00 {
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
                RiscOp::ArithmeticShiftRight => {
                    let a = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm1);
                    let cnt = get_operand_val(op_src2_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm2) & 63;
                    let res = if cnt == 0 { a } else { ((a as i64) >> cnt) as u64 };
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
                RiscOp::MemoryRead { width } => {
                    let addr = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm1);
                    let val = mem_read(&self.mem, addr, width);
                    self.store_operand(op_dst_raw, val);
                }
                RiscOp::MemoryWrite { width } => {
                    let addr = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm1);
                    let val = get_operand_val(op_src2_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm2);
                    mem_write(&mut self.mem, addr, width, val);
                }
                RiscOp::VirtualBranch { cond } => {
                    if branch_taken_with_state(cond, &self.flags, &self.regs) {
                        // 타깃: src1(동적/즉시 값) 또는 절대-인덱스(imm) — eval_state 와 동일 의미론:
                        // 둘 다 **인스트럭션 인덱스**다. 폴리 스트림의 vip 는 바이트 오프셋이므로
                        // `instr_starts` 테이블로 인덱스 → 시작 바이트 오프셋으로 변환한다.
                        let target = if op_src1_raw != 0x00 {
                            get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm1)
                        } else {
                            branch_target
                        };
                        // 범위 밖 타깃 → eval_state 와 동일하게 실행 종료 (vip 를 스트림 끝으로).
                        let Some(&target_off) = instr_starts.get(target as usize) else {
                            vip = bytecode.len();
                            continue;
                        };
                        // 건너뛴 [vip, target_off) 구간의 롤링 키스트림을 전진시켜 동기화한 뒤 점프.
                        if target_off > vip {
                            fast_forward_roll(&mut self.rolling, bytecode, vip, target_off);
                        }
                        vip = target_off;
                        continue;
                    }
                }
                RiscOp::SetFlag => {
                    let v = get_operand_val(op_src1_raw, &self.spec, &self.regs, &self.temps, self.flags.raw, self.vsp, imm1);
                    self.flags.raw = v & 0x8D5; // CF|PF|AF|ZF|SF|OF 마스크
                }
                RiscOp::NativeCallBridge => {
                    // 인지된 no-op 스텁. 실제 네이티브/호스트 콜은 런타임 계층(Phase P3) 책임.
                    // 평가된 피연산자 바이트는 스트림에서 소비됐지만 VM 상태에는 영향을 주지 않는다.
                }
                RiscOp::Halt => {
                    break;
                }
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

    /// 바이트코드를 선형 디코드해 각 인스트럭션 **opcode 의 시작 바이트 오프셋** 을
    /// 인덱스 순으로 모은 테이블을 만든다. `eval_state` 는 `vip` 를 인스트럭션 인덱스로
    /// 쓰지만 폴리 스트림의 `vip` 는 바이트 오프셋이므로, taken 분기의 인덱스 타깃을
    /// 이 테이블로 바이트 오프셋으로 변환해 일치시킨다. 디코드 스텝핑은 decoder/run 과
    /// 정확히 동일하며, 롤링 키는 `Copy` 복제본으로 전진시켜 원본 상태를 건드리지 않는다.
    fn instr_starts(&self, bytecode: &[u8]) -> Vec<usize> {
        let mut starts = Vec::new();
        let mut vip = 0usize;
        let mut rolling = self.rolling; // Copy — 선형 스캔 전용 복제본
        while vip < bytecode.len() {
            starts.push(vip);
            let raw_op = rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;
            let Some(risc_op) = self.spec.reverse_opcode_map.get(&raw_op).copied() else {
                break;
            };
            let risc_op = match risc_op {
                RiscOp::VirtualBranch { .. } => {
                    if vip >= bytecode.len() {
                        break;
                    }
                    let _ = rolling.decrypt_byte(bytecode[vip], vip as u64);
                    vip += 1;
                    RiscOp::VirtualBranch { cond: BranchCondition::Always }
                }
                other => other,
            };
            if vip + 3 > bytecode.len() {
                break;
            }
            let op_dst = rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;
            let op_src1 = rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;
            let op_src2 = rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;

            let has_imm1 = op_src1 == 0x01;
            let has_imm2 = op_src2 == 0x01;
            let take8 = |vip: &mut usize, rolling: &mut RollingKeyEngine, bytecode: &[u8]| {
                for _ in 0..8 {
                    if *vip < bytecode.len() {
                        let _ = rolling.decrypt_byte(bytecode[*vip], *vip as u64);
                        *vip += 1;
                    }
                }
            };
            if has_imm1 {
                take8(&mut vip, &mut rolling, bytecode);
            }
            if has_imm2 {
                take8(&mut vip, &mut rolling, bytecode);
            }
            if risc_op == RiscOp::AddWithCarry && !has_imm1 && !has_imm2 {
                take8(&mut vip, &mut rolling, bytecode);
            }
            if matches!(risc_op, RiscOp::VirtualBranch { .. }) && op_src1 == 0x00 {
                take8(&mut vip, &mut rolling, bytecode);
            }
            if risc_op == RiscOp::Halt {
                break;
            }
        }
        starts
    }
}

/// 조건 분기가 걸리는지 평가 (x86 조건 코드 의미론). `src/vm/risc/mod.rs::branch_taken`과 동일.
fn branch_taken(cond: BranchCondition, flags: &VirtualFlags) -> bool {
    match cond {
        BranchCondition::Always => true,
        BranchCondition::Zero => flags.zf(),
        BranchCondition::NotZero => !flags.zf(),
        BranchCondition::Carry => flags.cf(),
        BranchCondition::NotCarry => !flags.cf(),
        BranchCondition::Sign => flags.sf(),
        BranchCondition::NotSign => !flags.sf(),
        BranchCondition::Overflow => flags.of(),
        BranchCondition::NotOverflow => !flags.of(),
        // signed comparisons
        BranchCondition::Greater => !flags.zf() && (flags.sf() == flags.of()), // JG
        BranchCondition::Less => flags.sf() != flags.of(),                      // JL
        BranchCondition::GreaterOrEqual => flags.sf() == flags.of(),            // JGE
        BranchCondition::LessOrEqual => flags.zf() || (flags.sf() != flags.of()), // JLE
        // unsigned comparisons (precise)
        BranchCondition::Above => !flags.cf() && !flags.zf(),           // JA: CF=0 && ZF=0
        BranchCondition::AboveOrEqual => !flags.cf(),                    // JAE: CF=0
        BranchCondition::Below => flags.cf(),                            // JB: CF=1
        BranchCondition::BelowOrEqual => flags.cf() || flags.zf(),       // JBE: CF=1 || ZF=1
        // parity
        BranchCondition::Parity => flags.pf(),      // JP
        BranchCondition::NotParity => !flags.pf(),  // JNP
        // counter-based (Jcxz/Jecxz/Jrcxz): handled by branch_taken_with_state
        BranchCondition::CounterZero(_) => false,
    }
}

/// 분기 평가 — `CounterZero`(카운터 기반)는 레지스터 상태가 필요하므로 상태까지 전달.
/// `src/vm/risc/mod.rs::branch_taken_with_state`과 동일: RCX(reg[1])의 하위 width 바이트가 0인지.
fn branch_taken_with_state(cond: BranchCondition, flags: &VirtualFlags, regs: &[u64; 16]) -> bool {
    if let BranchCondition::CounterZero(width) = cond {
        let mask = match width {
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            _ => u64::MAX,
        };
        return (regs[1] & mask) == 0;
    }
    branch_taken(cond, flags)
}

/// 리틀엔디언 `width`바이트 메모리 읽기. 미기입 주소는 0으로 취급.
/// `src/vm/risc/mod.rs::mem_read`과 동일.
fn mem_read(mem: &HashMap<u64, u8>, addr: u64, width: u8) -> u64 {
    let mut v = 0u64;
    for i in 0..width {
        if let Some(&b) = mem.get(&addr.wrapping_add(i as u64)) {
            v |= (b as u64) << (i as u64 * 8);
        }
    }
    v
}

/// 리틀엔디언 `width`바이트 메모리 쓰기. `src/vm/risc/mod.rs::mem_write`과 동일.
fn mem_write(mem: &mut HashMap<u64, u8>, addr: u64, width: u8, val: u64) {
    for i in 0..width {
        mem.insert(addr.wrapping_add(i as u64), (val >> (i as u64 * 8)) as u8);
    }
}

/// taken 분기로 건너뛴 `[from, to)` 구간의 바이트를 복호화·폐기하며 롤링 키를 전진시켜,
/// 선형 인코딩과 동일한 키 상태에 도달하게 한다 (키스트림 동기화).
fn fast_forward_roll(rolling: &mut RollingKeyEngine, bytecode: &[u8], from: usize, to: usize) {
    let mut p = from;
    while p < to {
        let _ = rolling.decrypt_byte(bytecode[p], p as u64);
        p += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::poly::PolymorphicEncoder;
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscDesynthesizer, RiscEvalState, RiscProgram, RiscOp};

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

    // ---- 신규 연산 (P1) 차등 검증 -------------------------------------------------

    const DIFF_SEEDS: [u64; 3] = [0x1111_2222_3333_4444, 0xCAFE_F00D_DEAD_BEEF, 0x8899_AABB_CCDD_EEFF];

    /// 인터프리터 전체 상태 == eval_state 전체 상태 (regs/temps/flags/vsp/stack/mem).
    fn assert_full_state_eq(interp: &PolymorphicInterpreter, ref_st: &RiscEvalState) {
        assert_eq!(interp.regs, ref_st.regs, "regs");
        assert_eq!(interp.temps, ref_st.temps, "temps");
        assert_eq!(interp.flags.raw, ref_st.flags, "flags");
        assert_eq!(interp.vsp, ref_st.vsp, "vsp");
        assert_eq!(interp.stack, ref_st.stack, "stack");
        assert_eq!(interp.mem, ref_st.mem, "mem");
    }

    fn run_diff(seed: u64, prog: &RiscProgram, init_regs: &[u64; 16]) {
        let ref_st = prog.eval_state(init_regs);

        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(prog).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.regs = *init_regs;
        interp.run(&bytecode).unwrap();

        assert_full_state_eq(&interp, &ref_st);
    }

    /// ArithmeticShiftRight 차등 (SAR, 논리 플래그 갱신 포함).
    #[test]
    fn test_poly_diff_arithmetic_shift_right() {
        for seed in DIFF_SEEDS {
            let mut d = RiscDesynthesizer::new();
            // R1 = 음수 값 (SF=1 확인용)
            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(0x8000_0000_0000_000F), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64(4), MicroOperand::Imm64(0));
            // R3 = R1 >> R2 (산술) → 부호 비트 유지
            d.instrs.push(
                MicroInstr::new(RiscOp::ArithmeticShiftRight)
                    .with_dst(MicroOperand::VReg(3))
                    .with_src1(MicroOperand::VReg(1))
                    .with_src2(MicroOperand::VReg(2)),
            );
            // R4 = R1 >> 63 (전부 부호 비트)
            d.instrs.push(
                MicroInstr::new(RiscOp::ArithmeticShiftRight)
                    .with_dst(MicroOperand::VReg(4))
                    .with_src1(MicroOperand::VReg(1))
                    .with_src2(MicroOperand::Imm64(63)),
            );
            // R5 = R1 >> 0 (cnt==0 → 그대로)
            d.instrs.push(
                MicroInstr::new(RiscOp::ArithmeticShiftRight)
                    .with_dst(MicroOperand::VReg(5))
                    .with_src1(MicroOperand::VReg(1))
                    .with_src2(MicroOperand::Imm64(0)),
            );
            d.instrs.push(MicroInstr::new(RiscOp::Halt));
            let prog = RiscProgram::new(d.instrs);
            run_diff(seed, &prog, &[0u64; 16]);
        }
    }

    /// MemoryRead/MemoryWrite (폭 1/2/4/8) 차등 — 메모리 상태 전체 비교.
    #[test]
    fn test_poly_diff_memory_read_write_all_widths() {
        for seed in DIFF_SEEDS {
            let mut d = RiscDesynthesizer::new();
            // R0 = 기준 주소
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x1000), MicroOperand::Imm64(0));
            // T0 = 기준 주소 + 8
            d.emit_add(MicroOperand::Temp(0), MicroOperand::Imm64(0x1008), MicroOperand::Imm64(0));
            // 각 폭으로 Write (중첩/비중첩)
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width: 1 })
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::Imm64(0xAB)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width: 2 })
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::Imm64(0xCDEF)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width: 4 })
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::Imm64(0x11223344)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
                    .with_src1(MicroOperand::Temp(0))
                    .with_src2(MicroOperand::Imm64(0xDEADBEEFCAFEF00D)),
            );
            // 각 폭으로 Read back
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width: 1 })
                    .with_dst(MicroOperand::VReg(1))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width: 2 })
                    .with_dst(MicroOperand::VReg(2))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width: 4 })
                    .with_dst(MicroOperand::VReg(3))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width: 8 })
                    .with_dst(MicroOperand::VReg(4))
                    .with_src1(MicroOperand::Temp(0)),
            );
            // 폭 초과 읽기 (8바이트 폭, 4바이트만 기입된 영역 → 상위 0)
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width: 8 })
                    .with_dst(MicroOperand::VReg(5))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(MicroInstr::new(RiscOp::Halt));
            let prog = RiscProgram::new(d.instrs);
            run_diff(seed, &prog, &[0u64; 16]);
        }
    }

    /// NativeCallBridge — 인지된 no-op 스텁 차등 (상태 불변).
    #[test]
    fn test_poly_diff_native_call_bridge() {
        for seed in DIFF_SEEDS {
            let mut d = RiscDesynthesizer::new();
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x1234), MicroOperand::Imm64(0));
            // 즉시 인자와 dst 를 가진 브리지 — VM 상태 변화 없이 스트림만 소비.
            d.instrs.push(
                MicroInstr::new(RiscOp::NativeCallBridge)
                    .with_dst(MicroOperand::VReg(1))
                    .with_src1(MicroOperand::Imm64(0x9999)),
            );
            // 뒤따르는 연산이 정상 실행되어야 한다 (스트림 sync 유지).
            d.emit_add(MicroOperand::VReg(6), MicroOperand::VReg(0), MicroOperand::Imm64(1));
            d.instrs.push(MicroInstr::new(RiscOp::Halt));
            let prog = RiscProgram::new(d.instrs);
            run_diff(seed, &prog, &[0u64; 16]);
        }
    }

    /// VirtualBranch 차등 — 모든 조건(포함 CounterZero 폭)을 **미충족(not-taken)** 상태로
    /// 배치해 롤링 키 스트림을 선형으로 유지하면서 분기 판정이 eval_state 와 일치하는지 검증.
    /// (taken 분기의 VIP 점프 자체는 아래 `branch_taken_with_state` 단위 테스트가 담당.)
    #[test]
    fn test_poly_diff_virtual_branch_not_taken_all_conditions() {
        // 롤링 키 스트림은 선형 실행만 동기를 유지하므로, 분기 **미충족(not-taken)** 조건들을
        // 배치해 분기 판정이 eval_state 와 일치하는지 차등 검증한다 (잘못 taken 되면 키가
        // desync 되어 실패). taken 판정 자체는 아래 `test_branch_taken_with_state_all_conditions`
        // 가 모든 조건(포함 CounterZero 폭)을 단위 검증한다.
        for seed in DIFF_SEEDS {
            let mut d = RiscDesynthesizer::new();
            // R0=10, R1=5 (CounterZero 검증: RCX=reg1=5 != 0 → not taken)
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(10), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(5), MicroOperand::Imm64(0));
            // 플래그를 ZF=1|PF=1 (0x44) 로 명시 설정
            d.instrs.push(
                MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x44)),
            );

            // ZF=1, PF=1, CF=0, SF=0, OF=0, reg1=5 에서 반드시 **not-taken** 인 조건들
            let not_taken: &[BranchCondition] = &[
                BranchCondition::NotZero,       // !ZF → false
                BranchCondition::Carry,         // CF=0 → false
                BranchCondition::Sign,          // SF=0 → false
                BranchCondition::Overflow,      // OF=0 → false
                BranchCondition::Greater,       // ZF=1 → false
                BranchCondition::Less,          // SF==OF → false
                BranchCondition::Above,         // ZF=1 → false
                BranchCondition::Below,         // CF=0 → false
                BranchCondition::NotParity,     // PF=1 → false
                BranchCondition::CounterZero(2),// reg1=5 != 0 → false
                BranchCondition::CounterZero(4),
                BranchCondition::CounterZero(8),
            ];

            for cond in not_taken {
                // 절대-인덱스 타깃 (src1 없음, imm=타깃) — not-taken 이므로 무시됨
                d.instrs.push(
                    MicroInstr::new(RiscOp::VirtualBranch { cond: *cond }).with_imm(99),
                );
                // 간접(src1 동적) 타깃 — 역시 not-taken
                d.instrs.push(
                    MicroInstr::new(RiscOp::VirtualBranch { cond: *cond })
                        .with_src1(MicroOperand::VReg(0))
                        .with_imm(99),
                );
            }

            // 이후 연산이 정상 실행되어야 한다 (분기 미충족 → 선형 진행).
            d.emit_add(MicroOperand::VReg(6), MicroOperand::VReg(0), MicroOperand::Imm64(1));
            d.instrs.push(MicroInstr::new(RiscOp::Halt));
            let prog = RiscProgram::new(d.instrs);
            run_diff(seed, &prog, &[0u64; 16]);
        }
    }

    /// branch_taken_with_state — 모든 조건의 taken/not-taken 판정을 단위 검증
    /// (CounterZero 폭별 RCX 하위 바이트 검사 포함).
    #[test]
    fn test_branch_taken_with_state_all_conditions() {
        let mut flags = VirtualFlags::default();
        // ZF=1, SF=0, OF=0, CF=0, PF=1
        flags.raw = crate::vm::risc::flags::VFLAG_ZF | crate::vm::risc::flags::VFLAG_PF;
        let mut regs = [0u64; 16];
        regs[1] = 0x1234_5678_9ABC_0000; // low16 == 0, low32 != 0, full != 0

        let check = |cond: BranchCondition, flags: &VirtualFlags, regs: &[u64; 16], expect: bool| {
            assert_eq!(
                branch_taken_with_state(cond, flags, regs),
                expect,
                "cond {cond:?}",
            );
        };

        check(BranchCondition::Always, &flags, &regs, true);
        check(BranchCondition::Zero, &flags, &regs, true);
        check(BranchCondition::NotZero, &flags, &regs, false);
        check(BranchCondition::Carry, &flags, &regs, false);
        check(BranchCondition::NotCarry, &flags, &regs, true);
        check(BranchCondition::Sign, &flags, &regs, false);
        check(BranchCondition::NotSign, &flags, &regs, true);
        check(BranchCondition::Overflow, &flags, &regs, false);
        check(BranchCondition::NotOverflow, &flags, &regs, true);
        check(BranchCondition::Greater, &flags, &regs, false); // ZF=1
        check(BranchCondition::Less, &flags, &regs, false);    // SF==OF
        check(BranchCondition::GreaterOrEqual, &flags, &regs, true); // SF==OF
        check(BranchCondition::LessOrEqual, &flags, &regs, true);    // ZF=1
        check(BranchCondition::Above, &flags, &regs, false);   // ZF=1
        check(BranchCondition::AboveOrEqual, &flags, &regs, true);   // CF=0
        check(BranchCondition::Below, &flags, &regs, false);   // CF=0
        check(BranchCondition::BelowOrEqual, &flags, &regs, true);   // ZF=1
        check(BranchCondition::Parity, &flags, &regs, true);   // PF=1
        check(BranchCondition::NotParity, &flags, &regs, false);

        // CounterZero: RCX(reg1) low bytes
        check(BranchCondition::CounterZero(2), &flags, &regs, true);  // low16 = 0x0000 == 0
        check(BranchCondition::CounterZero(4), &flags, &regs, false); // low32 = 0x9ABC0000 != 0
        check(BranchCondition::CounterZero(8), &flags, &regs, false); // full != 0
        regs[1] = 0;
        check(BranchCondition::CounterZero(2), &flags, &regs, true);
        check(BranchCondition::CounterZero(4), &flags, &regs, true);
        check(BranchCondition::CounterZero(8), &flags, &regs, true);
    }
    // ---- 요구되는 명명 차등 테스트 (PolymorphicInterpreter == eval_state, >=3 seeds) ----

    /// `run_diff` 의 시드된 메모리 버전 — 인터프리터 `with_mem` 과 참조 `eval_state_with_mem`
    /// 에 동일한 초기 메모리를 주입하고 전체 상태(regs/temps/flags/vsp/stack/mem)를 비교한다.
    fn run_diff_mem(seed: u64, prog: &RiscProgram, init_regs: &[u64; 16], mem: HashMap<u64, u8>) {
        let ref_st = prog.eval_state_with_mem(init_regs, mem.clone());

        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(prog).unwrap();
        let mut interp = PolymorphicInterpreter::new(seed);
        interp.regs = *init_regs;
        let mut interp = interp.with_mem(mem);
        interp.run(&bytecode).unwrap();

        assert_full_state_eq(&interp, &ref_st);
    }

    /// ArithmeticShiftRight 차등 — 음수/양수 소스, 즉시+레지스터 카운트, 시프트 수 0..63 전부.
    #[test]
    fn test_poly_arith_shift_matches_reference() {
        for seed in DIFF_SEEDS {
            let mut d = RiscDesynthesizer::new();
            // R0 = 음수 소스 (부호 비트 유지 확인), R1 = 양수 소스
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0xFFFF_FFFF_FFFF_FFF0), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(0x1234_5678_9ABC_DEF0), MicroOperand::Imm64(0));
            // R2 = 레지스터 카운트 (register-count SAR)
            d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64(7), MicroOperand::Imm64(0));
            // 즉시 카운트 0..63 전부
            for cnt in 0u64..64 {
                d.instrs.push(
                    MicroInstr::new(RiscOp::ArithmeticShiftRight)
                        .with_dst(MicroOperand::VReg(3))
                        .with_src1(MicroOperand::VReg(0))
                        .with_src2(MicroOperand::Imm64(cnt)),
                );
            }
            // 레지스터 카운트 SAR (R1 >> R2)
            d.instrs.push(
                MicroInstr::new(RiscOp::ArithmeticShiftRight)
                    .with_dst(MicroOperand::VReg(4))
                    .with_src1(MicroOperand::VReg(1))
                    .with_src2(MicroOperand::VReg(2)),
            );
            d.instrs.push(MicroInstr::new(RiscOp::Halt));
            let prog = RiscProgram::new(d.instrs);
            run_diff(seed, &prog, &[0u64; 16]);
        }
    }

    /// MemoryRead/MemoryWrite (폭 1/2/4/8) 차등 — **시드된 초기 메모리**를 인터프리터
    /// (`with_mem`)와 참조 (`eval_state_with_mem`) 양쪽에 주입하고, 특히 mem 전체 상태를 비교.
    #[test]
    fn test_poly_mem_rw_matches_reference() {
        for seed in DIFF_SEEDS {
            // 초기 메모리 시드: 0x2000 영역 16바이트 패턴
            let mut seed_mem = HashMap::new();
            for i in 0u64..16 {
                seed_mem.insert(0x2000 + i, ((i * 7 + 3) & 0xFF) as u8);
            }
            let mut d = RiscDesynthesizer::new();
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x2000), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::Temp(0), MicroOperand::Imm64(0x3000), MicroOperand::Imm64(0));
            // 시드 메모리에서 폭별 읽기 (R1/R2/R4/R8)
            for w in [1u8, 2, 4, 8] {
                d.instrs.push(
                    MicroInstr::new(RiscOp::MemoryRead { width: w })
                        .with_dst(MicroOperand::VReg(w))
                        .with_src1(MicroOperand::VReg(0)),
                );
            }
            // 폭별 쓰기 (0x3000 에 8/2, 0x2000 에 4/1 — 일부 중첩)
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
                    .with_src1(MicroOperand::Temp(0))
                    .with_src2(MicroOperand::Imm64(0xDEAD_BEEF_CAFE_F00D)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width: 4 })
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::Imm64(0x1122_3344)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width: 2 })
                    .with_src1(MicroOperand::Temp(0))
                    .with_src2(MicroOperand::Imm64(0xABCD)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryWrite { width: 1 })
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::Imm64(0x5A)),
            );
            // 쓴 영역을 다시 읽어 확인
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width: 8 })
                    .with_dst(MicroOperand::VReg(5))
                    .with_src1(MicroOperand::Temp(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MemoryRead { width: 4 })
                    .with_dst(MicroOperand::VReg(6))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(MicroInstr::new(RiscOp::Halt));
            let prog = RiscProgram::new(d.instrs);
            run_diff_mem(seed, &prog, &[0u64; 16], seed_mem);
        }
    }

    /// VirtualBranch 차등 — **taken AND not-taken**, CounterZero(2/4/8) 포함.
    /// taken 분기는 인스트럭션-인덱스 타깃을 `instr_starts`로 바이트 오프셋으로 변환해
    /// 점프하며, 건너뛴 영역의 롤링 키스트림을 `fast_forward_roll`로 동기화한다.
    #[test]
    fn test_poly_branch_matches_reference() {
        for seed in DIFF_SEEDS {
            // (1) taken(forward) — ZF=1 이면 index1 의 분기가 index3 으로 점프, index2 는 건너뜀
            let mut d = RiscDesynthesizer::new();
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0), MicroOperand::Imm64(0)); // index0: ZF=1
            d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::Zero }).with_imm(3)); // index1
            d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(111), MicroOperand::Imm64(0)); // index2: 건너뜀
            d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(222), MicroOperand::Imm64(0)); // index3: 실작업
            d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
            run_diff(seed, &RiscProgram::new(d.instrs), &[0u64; 16]);

            // (2) not-taken — ZF=0 이면 fall-through
            let mut d = RiscDesynthesizer::new();
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(5), MicroOperand::Imm64(0)); // index0: ZF=0
            d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::Zero }).with_imm(4)); // index1
            d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(222), MicroOperand::Imm64(0)); // index2
            d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index3
            d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(999), MicroOperand::Imm64(0)); // index4: 미도달
            run_diff(seed, &RiscProgram::new(d.instrs), &[0u64; 16]);

            // (3) taken(간접, src1 동적 타깃) — R5=4 가 타깃 인덱스, index3 으로 점프해 index2 건너뜀
            let mut d = RiscDesynthesizer::new();
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0), MicroOperand::Imm64(0)); // index0: ZF=1
            d.emit_add(MicroOperand::VReg(5), MicroOperand::Imm64(4), MicroOperand::Imm64(0)); // index1: R5=4 (동적 타깃)
            d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::Zero }).with_src1(MicroOperand::VReg(5))); // index2
            d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(111), MicroOperand::Imm64(0)); // index3: 건너뜀
            d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(222), MicroOperand::Imm64(0)); // index4: 실작업(타깃)
            d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index5
            run_diff(seed, &RiscProgram::new(d.instrs), &[0u64; 16]);

            // (4) CounterZero 폭별 taken(reg[1]=0) & not-taken(reg[1] 전 폭 nonzero)
            for w in [2u8, 4, 8] {
                // taken
                let mut d = RiscDesynthesizer::new();
                d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::CounterZero(w) }).with_imm(3)); // index0
                d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(111), MicroOperand::Imm64(0)); // index1: 건너뜀
                d.emit_add(MicroOperand::VReg(8), MicroOperand::Imm64(55), MicroOperand::Imm64(0));  // index2: 건너뜀
                d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(222), MicroOperand::Imm64(0)); // index3: 실작업
                d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
                run_diff(seed, &RiscProgram::new(d.instrs), &[0u64; 16]);

                // not-taken
                let mut d = RiscDesynthesizer::new();
                d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::CounterZero(w) }).with_imm(3)); // index0
                d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(111), MicroOperand::Imm64(0)); // index1
                d.emit_add(MicroOperand::VReg(8), MicroOperand::Imm64(55), MicroOperand::Imm64(0));  // index2
                d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(222), MicroOperand::Imm64(0)); // index3
                d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
                let mut regs = [0u64; 16];
                regs[1] = 0x1234_5678_9ABC_DEF0; // 모든 폭에서 0 이 아님
                run_diff(seed, &RiscProgram::new(d.instrs), &regs);
            }
        }
    }

    /// NativeCallBridge no-op 스텁 차등 — 브리지 양쪽(즉시/레지스터 인자 포함)에서 상태 불변,
    /// 이후 연산이 스트림 동기를 유지하며 정상 실행됨을 전체 상태로 확인.
    #[test]
    fn test_poly_native_call_bridge_stub() {
        for seed in DIFF_SEEDS {
            let mut d = RiscDesynthesizer::new();
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x1234), MicroOperand::Imm64(0));
            d.instrs.push(
                MicroInstr::new(RiscOp::NativeCallBridge)
                    .with_dst(MicroOperand::VReg(1))
                    .with_src1(MicroOperand::Imm64(0x9999)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::NativeCallBridge)
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::VReg(1)),
            );
            d.emit_add(MicroOperand::VReg(6), MicroOperand::VReg(0), MicroOperand::Imm64(1));
            d.instrs.push(MicroInstr::new(RiscOp::Halt));
            let prog = RiscProgram::new(d.instrs);
            run_diff(seed, &prog, &[0u64; 16]);
        }
    }

    /// 전체 도달 가능한 RiscOp 집합(메모리 폭별 + VirtualBranch 포함)의 opcode 맵
    /// 유일성/일관성 검증 — 전 opcode 바이트 유일, forward/reverse 맵 일치, 충돌 없음,
    /// VirtualBranch 조건 부호화도 전 조건 유일 라운드트립.
    #[test]
    fn test_poly_opcode_map_uniqueness_complete_isa() {
        use crate::vm::poly::VirtualIsaSpec;
        for seed in DIFF_SEEDS {
            let spec = VirtualIsaSpec::from_seed(seed);

            let full: Vec<RiscOp> = vec![
                RiscOp::Nor,
                RiscOp::AddWithCarry,
                RiscOp::ShiftRight,
                RiscOp::ArithmeticShiftRight,
                RiscOp::ShiftLeft,
                RiscOp::VirtualPush,
                RiscOp::VirtualPop,
                RiscOp::MemoryRead { width: 1 },
                RiscOp::MemoryRead { width: 2 },
                RiscOp::MemoryRead { width: 4 },
                RiscOp::MemoryRead { width: 8 },
                RiscOp::MemoryWrite { width: 1 },
                RiscOp::MemoryWrite { width: 2 },
                RiscOp::MemoryWrite { width: 4 },
                RiscOp::MemoryWrite { width: 8 },
                RiscOp::VirtualBranch { cond: BranchCondition::Always },
                RiscOp::NativeCallBridge,
                RiscOp::SetFlag,
                RiscOp::Halt,
            ];

            // 전 opcode 존재
            for op in &full {
                assert!(spec.opcode_for(*op).is_some(), "missing opcode for {op:?}");
            }
            // 유일성
            let mut bytes: Vec<u8> = full.iter().map(|op| spec.opcode_for(*op).unwrap()).collect();
            bytes.sort_unstable();
            bytes.dedup();
            assert_eq!(bytes.len(), full.len(), "opcode collision in complete ISA");
            // forward/reverse 일치
            for op in &full {
                let b = spec.opcode_for(*op).unwrap();
                assert_eq!(spec.reverse_opcode_map.get(&b), Some(op), "reverse map inconsistent for {op:?}");
            }
            assert_eq!(spec.opcode_map.len(), spec.reverse_opcode_map.len());

            // 모든 VirtualBranch 조건 유일 부호화 라운드트립
            let conds = [
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
            ];
            let mut cond_bytes: Vec<u8> = Vec::new();
            for cond in conds {
                let b = spec.encode_cond(cond);
                cond_bytes.push(b);
                assert_eq!(spec.decode_cond(b), Some(cond), "cond roundtrip {cond:?}");
            }
            cond_bytes.sort_unstable();
            cond_bytes.dedup();
            assert_eq!(cond_bytes.len(), 22, "branch cond byte collision");
        }
    }
}
