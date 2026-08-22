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
use crate::vm::risc::flags::VFLAG_DF;
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
        // 각 시작점의 롤링 키 스냅샷도 함께 캡처 — backward 분기(loop)에서 타깃
        // 위치의 키 상태를 복원하기 위함 (항상 선형 실행과 동일한 키 스트림 유지).
        let (instr_starts, key_snapshots) = self.instr_starts(bytecode);

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
                .ok_or_else(|| {
                    anyhow!(
                        "poly interp: unknown decrypted opcode 0x{raw_op:02X} at offset 0x{vip:X}"
                    )
                })?;

            // 1b. 조건 바이트 — VirtualBranch·Setcc·ConditionalMove (decoder 와 동일 계약)
            let risc_op = match risc_op {
                RiscOp::VirtualBranch { .. }
                | RiscOp::Setcc { .. }
                | RiscOp::ConditionalMove { .. } => {
                    if vip >= bytecode.len() {
                        break;
                    }
                    let raw_cond = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                    vip += 1;
                    let cond = self.spec.decode_cond(raw_cond).ok_or_else(|| {
                        anyhow!(
                            "poly interp: unknown branch cond 0x{raw_cond:02X} at offset 0x{vip:X}"
                        )
                    })?;
                    match risc_op {
                        RiscOp::VirtualBranch { .. } => RiscOp::VirtualBranch { cond },
                        RiscOp::Setcc { .. } => RiscOp::Setcc { cond },
                        _ => RiscOp::ConditionalMove { cond },
                    }
                }
                other => other,
            };

            // 2. Decrypt 3 operand bytes
            if vip + 3 > bytecode.len() {
                break;
            }
            let mut operands = [0u8; 3];
            for logical_slot in self.spec.operand_order() {
                operands[logical_slot] = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                vip += 1;
            }
            let [op_dst_raw, op_src1_raw, op_src2_raw] = operands;

            // 3. Decrypt family-local compact immediates (1/2/4/8 bytes).
            let read_immediate = |marker: u8, vip: &mut usize, rolling: &mut RollingKeyEngine| {
                let width = self.spec.immediate_width(marker).unwrap_or(0);
                let mut b = [0u8; 8];
                for byte in b.iter_mut().take(width) {
                    if *vip < bytecode.len() {
                        *byte = rolling.decrypt_byte(bytecode[*vip], *vip as u64);
                        *vip += 1;
                    }
                }
                self.spec
                    .decode_immediate_payload(marker, u64::from_le_bytes(b))
            };
            let imm1 = if self.spec.is_immediate_marker(op_src1_raw) {
                read_immediate(op_src1_raw, &mut vip, &mut self.rolling)
            } else {
                0
            };

            let imm2 = if self.spec.is_immediate_marker(op_src2_raw) {
                read_immediate(op_src2_raw, &mut vip, &mut self.rolling)
            } else {
                0
            };

            // cin (AddWithCarry 이고 즉시 피연산자 없을 때 8B) — decoder와 동일 규칙.
            let cin = if !self.spec.is_immediate_marker(op_src1_raw)
                && !self.spec.is_immediate_marker(op_src2_raw)
                && risc_op == RiscOp::AddWithCarry
            {
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
                    if vip >= bytecode.len() {
                        break;
                    }
                    let marker = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                    vip += 1;
                    let width = self.spec.branch_target_width(marker).ok_or_else(|| {
                        anyhow!("poly interp: invalid branch marker 0x{marker:02X}")
                    })?;
                    let mut b = [0u8; 8];
                    for byte in b.iter_mut().take(width) {
                        if vip < bytecode.len() {
                            *byte = self.rolling.decrypt_byte(bytecode[vip], vip as u64);
                            vip += 1;
                        }
                    }
                    self.spec
                        .decode_compact_branch_target(
                            marker,
                            u64::from_le_bytes(b)
                                ^ (self.spec.operand_mask
                                    & if width == 8 {
                                        u64::MAX
                                    } else {
                                        (1u64 << (width * 8)) - 1
                                    }),
                        )
                        .unwrap()
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
                        if spec.is_immediate_marker(raw) {
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
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let res = !(a | b);
                    self.flags.update_logic64(res);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::Mov => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    // 플래그를 변경하지 않는 순수 복사.
                    self.store_operand(op_dst_raw, a);
                }
                RiscOp::AddWithCarry => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );

                    let (res, _cout) = self.flags.update_add64(a, b, cin);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::ShiftRight => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let cnt = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    ) & 63;
                    let res = if cnt == 0 { a } else { a >> cnt };
                    // x86: count==0 이면 RFLAGS 불변.
                    if cnt != 0 {
                        self.flags.update_logic64(res);
                        if (a >> (cnt - 1)) & 1 != 0 {
                            self.flags.raw |= crate::vm::risc::flags::VFLAG_CF;
                        }
                    }
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::ArithmeticShiftRight => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let cnt = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    ) & 63;
                    let res = if cnt == 0 {
                        a
                    } else {
                        ((a as i64) >> cnt) as u64
                    };
                    // x86: count==0 이면 RFLAGS 불변.
                    if cnt != 0 {
                        self.flags.update_logic64(res);
                        if (a >> (cnt - 1)) & 1 != 0 {
                            self.flags.raw |= crate::vm::risc::flags::VFLAG_CF;
                        }
                    }
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::ShiftLeft => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let cnt = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    ) & 63;
                    let res = if cnt == 0 { a } else { a << cnt };
                    // x86: count==0 이면 RFLAGS 불변.
                    if cnt != 0 {
                        self.flags.update_logic64(res);
                        if (a >> (64 - cnt)) & 1 != 0 {
                            self.flags.raw |= crate::vm::risc::flags::VFLAG_CF;
                        }
                    }
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::RotateLeft { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let c = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let res = self.flags.update_rol(a, c, width);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::Add { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let res = self.flags.update_add(a, b, width);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::SubWithBorrow { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let res = self.flags.update_sub(a, b, width);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::Adc { width } | RiscOp::Sbb { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let res = if matches!(risc_op, RiscOp::Adc { .. }) {
                        self.flags.update_adc(a, b, width)
                    } else {
                        self.flags.update_sbb(a, b, width)
                    };
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::Inc { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let res = self.flags.update_inc(a, width);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::Dec { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let res = self.flags.update_dec(a, width);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::Not { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let res = !a & crate::vm::risc::flags::mask_for_width(width);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::VirtualPush => {
                    let v = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
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
                    let addr = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let val = mem_read(&self.mem, addr, width);
                    self.store_operand(op_dst_raw, val);
                }
                RiscOp::MemoryWrite { width } => {
                    let addr = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let val = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    mem_write(&mut self.mem, addr, width, val);
                }
                RiscOp::VirtualBranch { cond } => {
                    if branch_taken_with_state(cond, &self.flags, &self.regs) {
                        // 타깃: src1(동적/즉시 값) 또는 절대-인덱스(imm) — eval_state 와 동일 의미론:
                        // 둘 다 **인스트럭션 인덱스**다. 폴리 스트림의 vip 는 바이트 오프셋이므로
                        // `instr_starts` 테이블로 인덱스 → 시작 바이트 오프셋으로 변환한다.
                        let target = if op_src1_raw != 0x00 {
                            get_operand_val(
                                op_src1_raw,
                                &self.spec,
                                &self.regs,
                                &self.temps,
                                self.flags.raw,
                                self.vsp,
                                imm1,
                            )
                        } else {
                            branch_target
                        };
                        // 범위 밖 타깃 → eval_state 와 동일하게 실행 종료 (vip 를 스트림 끝으로).
                        let Some((&target_off, &target_key)) = instr_starts
                            .get(target as usize)
                            .zip(key_snapshots.get(target as usize))
                        else {
                            vip = bytecode.len();
                            continue;
                        };
                        // 롤링 키를 타깃 인스트럭션 시작 시점의 **선형 실행 키 상태**로 복원.
                        // forward 점프뿐 아니라 backward 점프(loop)에서도 정확하다.
                        // (기존 `fast_forward_roll`은 forward만 동기화해 backward에서
                        //  키가 desync 되어 두 번째 loop부터 스트림을 잘못 복호화했다.)
                        self.rolling.current_key = target_key;
                        vip = target_off;
                        continue;
                    }
                }
                RiscOp::SetFlag => {
                    let v = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    self.flags.raw = v & (0x8D5 | VFLAG_DF); // status bits + DF
                }
                RiscOp::NativeCallBridge => {
                    // 인지된 no-op 스텁. 실제 네이티브/호스트 콜은 런타임 계층(Phase P3) 책임.
                    // 평가된 피연산자 바이트는 스트림에서 소비됐지만 VM 상태에는 영향을 주지 않는다.
                }
                RiscOp::SetNativeFpReturn { .. } => {
                    // F1: 네이티브 브릿지 FP 리턴 힌트 — 폴리 경로엔 브릿지가 없으므로 no-op.
                }
                RiscOp::VmCallBridge => {
                    // P1 (③): 인지된 no-op 스텁 — 서브 VM 레지스트리 기반 실제
                    // nested-VM 실행은 런타임 계층(P3 상용 통합) 책임. `is_encodable`
                    // 에 등록하지 않으므로 폴리 경로가 이 op 를 만나지 않는다.
                    // (참조 eval_state 가 서브 VM 실행으로 VM→VM 콜 의미론을 검증.)
                }
                // ── P2: 정수/비트/제어 복합 연산 (eval_state 와 동일 의미론) ────────
                RiscOp::Multiply { signed, width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    mul_wide_interp(
                        &mut self.regs,
                        &mut self.temps,
                        &self.spec,
                        &mut self.flags,
                        a,
                        b,
                        signed,
                        width,
                        op_dst_raw,
                    );
                }
                RiscOp::MultiplyLow { signed, width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    mul_low_interp(
                        &mut self.regs,
                        &mut self.temps,
                        &self.spec,
                        &mut self.flags,
                        a,
                        b,
                        signed,
                        width,
                        op_dst_raw,
                    );
                }
                RiscOp::Divide { signed, width } => {
                    let divisor = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    div_wide_interp(
                        &mut self.regs,
                        &mut self.temps,
                        &self.spec,
                        divisor,
                        signed,
                        width,
                        op_dst_raw,
                    );
                }
                RiscOp::BSwap { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let res = if width == 4 {
                        ((a as u32).swap_bytes()) as u64
                    } else {
                        a.swap_bytes()
                    };
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::BitScanForward => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    if a == 0 {
                        self.flags.set_zf(true);
                        self.store_operand(op_dst_raw, 0);
                    } else {
                        self.flags.set_zf(false);
                        self.store_operand(op_dst_raw, a.trailing_zeros() as u64);
                    }
                }
                RiscOp::BitScanReverse => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    if a == 0 {
                        self.flags.set_zf(true);
                        self.store_operand(op_dst_raw, 0);
                    } else {
                        self.flags.set_zf(false);
                        self.store_operand(op_dst_raw, 63 - a.leading_zeros() as u64);
                    }
                }
                RiscOp::CountTrailingZeros { width } => {
                    let bits = width as u32 * 8;
                    let mask = width_mask_interp(bits);
                    let s = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    ) & mask;
                    if s == 0 {
                        self.flags.set_cf(true);
                        self.flags.set_zf(true);
                        self.store_operand(op_dst_raw, bits as u64);
                    } else {
                        self.flags.set_cf(false);
                        let c = s.trailing_zeros() as u64;
                        self.flags.set_zf(c == 0);
                        self.store_operand(op_dst_raw, c);
                    }
                }
                RiscOp::CountLeadingZeros { width } => {
                    let bits = width as u32 * 8;
                    let mask = width_mask_interp(bits);
                    let s = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    ) & mask;
                    if s == 0 {
                        self.flags.set_cf(true);
                        self.flags.set_zf(true);
                        self.store_operand(op_dst_raw, bits as u64);
                    } else {
                        self.flags.set_cf(false);
                        let msb = 63 - s.leading_zeros() as u64;
                        let c = (bits as u64 - 1) - msb;
                        self.flags.set_zf(c == 0);
                        self.store_operand(op_dst_raw, c);
                    }
                }
                RiscOp::PopCount => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let res = a.count_ones() as u64;
                    self.flags.update_logic64(res);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::Setcc { cond } => {
                    let v = branch_taken_with_state(cond, &self.flags, &self.regs);
                    self.store_operand(op_dst_raw, v as u64);
                }
                RiscOp::ConditionalMove { cond } => {
                    if branch_taken_with_state(cond, &self.flags, &self.regs) {
                        let v = get_operand_val(
                            op_src1_raw,
                            &self.spec,
                            &self.regs,
                            &self.temps,
                            self.flags.raw,
                            self.vsp,
                            imm1,
                        );
                        self.store_operand(op_dst_raw, v);
                    }
                }
                RiscOp::CompareExchange { width } => {
                    let addr = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let newv = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let bits = width as u32 * 8;
                    let mask = width_mask_interp(bits);
                    let acc = self.regs[0] & mask;
                    let old = mem_read(&self.mem, addr, width) & mask;
                    // P1-6: CMP(acc - old) 전체 상태 플래그 (ZF 포함).
                    let _ = self.flags.update_sub(acc, old, width);
                    if old == acc {
                        mem_write(&mut self.mem, addr, width, newv & mask);
                    } else {
                        self.regs[0] = old;
                    }
                }
                // The single-threaded semantic interpreter has no competing
                // lifetime scopes; production atomicity lives in native handlers.
                RiscOp::LifetimeAcquire | RiscOp::LifetimeRelease => {}
                RiscOp::AtomicExchange { width } => {
                    // P0-4: old = [addr]; [addr] = dst; dst = old. 플래그 불변.
                    let addr = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let old = mem_read(&self.mem, addr, width);
                    let reg_v = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    mem_write(&mut self.mem, addr, width, reg_v);
                    self.store_operand(op_dst_raw, old);
                }
                RiscOp::AtomicAdd { width } => {
                    // P0-4: old = [addr]; new = old + src2 (폭별 플래그); [addr] = new; dst = old.
                    let addr = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let addend = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let old = mem_read(&self.mem, addr, width);
                    let mask = width_mask_interp(width as u32 * 8);
                    let newv = self.flags.update_add(old, addend, width) & mask;
                    mem_write(&mut self.mem, addr, width, newv);
                    self.store_operand(op_dst_raw, old & mask);
                }
                RiscOp::Halt | RiscOp::Trap => {
                    break;
                }
                RiscOp::VirtualRet => {
                    // P0-1: eval_state `VirtualRet` 와 동일 — 가상 스택 pop 후,
                    // 인스트럭션 인덱스(ip_map 없는 폴리 경로)로 해석. 범위 밖/
                    // 빈 스택 → 실행 종료(네이티브/최상위 복귀).
                    let ret_ip = match self.stack.pop() {
                        Some(v) => {
                            self.vsp = self.vsp.wrapping_add(8);
                            v
                        }
                        None => {
                            vip = bytecode.len();
                            continue;
                        }
                    };
                    let Some((&target_off, &target_key)) = instr_starts
                        .get(ret_ip as usize)
                        .zip(key_snapshots.get(ret_ip as usize))
                    else {
                        vip = bytecode.len();
                        continue;
                    };
                    self.rolling.current_key = target_key;
                    vip = target_off;
                    continue;
                }
                // R4: SSE/FPU 스칼라 — eval_state(참조)와 동치. FloatAdd/Sub/Mul/Div
                // 는 폭별(4/8) f32/f64 비트 해석 후 산술, 결과는 다시 비트로 저장.
                // IntToFloat/FloatToInt/FloatToFloat 는 변환. 플래그 변경 없음.
                RiscOp::FloatAdd { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let res = if width == 4 {
                        (f32::from_bits(a as u32) + f32::from_bits(b as u32)).to_bits() as u64
                    } else {
                        (f64::from_bits(a) + f64::from_bits(b)).to_bits()
                    };
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::FloatSub { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let res = if width == 4 {
                        (f32::from_bits(a as u32) - f32::from_bits(b as u32)).to_bits() as u64
                    } else {
                        (f64::from_bits(a) - f64::from_bits(b)).to_bits()
                    };
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::FloatMul { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let res = if width == 4 {
                        (f32::from_bits(a as u32) * f32::from_bits(b as u32)).to_bits() as u64
                    } else {
                        (f64::from_bits(a) * f64::from_bits(b)).to_bits()
                    };
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::FloatDiv { width } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let res = if width == 4 {
                        (f32::from_bits(a as u32) / f32::from_bits(b as u32)).to_bits() as u64
                    } else {
                        (f64::from_bits(a) / f64::from_bits(b)).to_bits()
                    };
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::IntToFloat { src_bits, dst_bits } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let iv = if src_bits == 4 {
                        (a as i32) as i64
                    } else {
                        a as i64
                    };
                    let res = if dst_bits == 4 {
                        (iv as f32).to_bits() as u64
                    } else {
                        (iv as f64).to_bits()
                    };
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::FloatToInt {
                    src_bits,
                    dst_bits,
                    truncate,
                } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let f = if src_bits == 4 {
                        f32::from_bits(a as u32) as f64
                    } else {
                        f64::from_bits(a)
                    };
                    let res = cvt_f64_int_interp(f, dst_bits, truncate);
                    self.store_operand(op_dst_raw, res);
                }
                RiscOp::FloatToFloat { src_bits, dst_bits } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let res = if src_bits == 4 {
                        (f32::from_bits(a as u32) as f64).to_bits()
                    } else {
                        (f64::from_bits(a) as f32).to_bits() as u64
                    };
                    self.store_operand(op_dst_raw, res);
                }
                // ── P1 (②): packed SSE — 슬롯 주소 피연산자, 16바이트 메모리 I/O, 플래그 불변 ──
                // eval_state(참조)와 동치. packed 정수 연산은 RFLAGS 를 바꾸지 않는다.
                // (참조: XMM 슬롯은 XMM_SLOT_BASE + idx*16 가상 메모리 — self.mem 에
                //  놓이며, lifter 가 슬롯 주소를 피연산자로 만들어 준다.)
                RiscOp::PackedMove => {
                    let src = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let dst = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    let mut bytes = [0u8; 16];
                    for i in 0..16u64 {
                        bytes[i as usize] =
                            self.mem.get(&src.wrapping_add(i)).copied().unwrap_or(0);
                    }
                    for i in 0..16u64 {
                        self.mem.insert(dst.wrapping_add(i), bytes[i as usize]);
                    }
                }
                RiscOp::PackedAdd { elem_width, lanes } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    let mask = crate::vm::risc::flags::mask_for_width(elem_width);
                    for lane in 0..lanes as u64 {
                        let off = lane * elem_width as u64;
                        let ea = mem_read(&self.mem, a.wrapping_add(off), elem_width);
                        let eb = mem_read(&self.mem, b.wrapping_add(off), elem_width);
                        mem_write(
                            &mut self.mem,
                            d.wrapping_add(off),
                            elem_width,
                            ea.wrapping_add(eb) & mask,
                        );
                    }
                }
                RiscOp::PackedSub { elem_width, lanes } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    let mask = crate::vm::risc::flags::mask_for_width(elem_width);
                    for lane in 0..lanes as u64 {
                        let off = lane * elem_width as u64;
                        let ea = mem_read(&self.mem, a.wrapping_add(off), elem_width);
                        let eb = mem_read(&self.mem, b.wrapping_add(off), elem_width);
                        mem_write(
                            &mut self.mem,
                            d.wrapping_add(off),
                            elem_width,
                            ea.wrapping_sub(eb) & mask,
                        );
                    }
                }
                RiscOp::PackedXor => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    for i in 0..16u64 {
                        let ba = self.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                        let bb = self.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                        self.mem.insert(d.wrapping_add(i), ba ^ bb);
                    }
                }
                RiscOp::PackedAnd => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    for i in 0..16u64 {
                        let ba = self.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                        let bb = self.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                        self.mem.insert(d.wrapping_add(i), ba & bb);
                    }
                }
                RiscOp::PackedOr => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    for i in 0..16u64 {
                        let ba = self.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                        let bb = self.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                        self.mem.insert(d.wrapping_add(i), ba | bb);
                    }
                }
                RiscOp::PackedAndNot => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    for i in 0..16u64 {
                        let ba = self.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                        let bb = self.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                        self.mem.insert(d.wrapping_add(i), ba & !bb);
                    }
                }
                RiscOp::PackedCmpEq { elem_width, lanes } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    let all_ones = (0..elem_width).fold(0u64, |acc, _| (acc << 8) | 0xFF);
                    for lane in 0..lanes as u64 {
                        let off = lane * elem_width as u64;
                        let ea = mem_read(&self.mem, a.wrapping_add(off), elem_width);
                        let eb = mem_read(&self.mem, b.wrapping_add(off), elem_width);
                        let er = if ea == eb { all_ones } else { 0 };
                        mem_write(&mut self.mem, d.wrapping_add(off), elem_width, er);
                    }
                }
                RiscOp::PackedCmpGt { elem_width, lanes } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    let all_ones = (0..elem_width).fold(0u64, |acc, _| (acc << 8) | 0xFF);
                    let shift = 64 - elem_width as u32 * 8;
                    for lane in 0..lanes as u64 {
                        let off = lane * elem_width as u64;
                        let ea = mem_read(&self.mem, a.wrapping_add(off), elem_width);
                        let eb = mem_read(&self.mem, b.wrapping_add(off), elem_width);
                        let er = if ((ea << shift) as i64) > ((eb << shift) as i64) {
                            all_ones
                        } else {
                            0
                        };
                        mem_write(&mut self.mem, d.wrapping_add(off), elem_width, er);
                    }
                }
                RiscOp::PackedUnpack { elem_width, high } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let b = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    let mut av = [0u8; 16];
                    let mut bv = [0u8; 16];
                    for i in 0..16u64 {
                        av[i as usize] = self.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                        bv[i as usize] = self.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                    }
                    let half = 8usize / elem_width as usize;
                    let base = if high { 8 } else { 0 };
                    for lane in 0..half {
                        for j in 0..elem_width as usize {
                            self.mem.insert(
                                d + (2 * lane * elem_width as usize + j) as u64,
                                av[base + lane * elem_width as usize + j],
                            );
                            self.mem.insert(
                                d + ((2 * lane + 1) * elem_width as usize + j) as u64,
                                bv[base + lane * elem_width as usize + j],
                            );
                        }
                    }
                }
                RiscOp::PackedShiftRightQ => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    let count = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let lo = mem_read(&self.mem, a, 8);
                    let hi = mem_read(&self.mem, a.wrapping_add(8), 8);
                    mem_write(
                        &mut self.mem,
                        d,
                        8,
                        if count >= 64 { 0 } else { lo >> count },
                    );
                    mem_write(
                        &mut self.mem,
                        d.wrapping_add(8),
                        8,
                        if count >= 64 { 0 } else { hi >> count },
                    );
                }
                RiscOp::PackedShuffle { low_words } => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    let control = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    ) as u8;
                    let mut src = [0u8; 16];
                    for i in 0..16u64 {
                        src[i as usize] = self.mem.get(&(a + i)).copied().unwrap_or(0);
                    }
                    if low_words {
                        for i in 0..16u64 {
                            self.mem.insert(d + i, src[i as usize]);
                        }
                        for lane in 0..4usize {
                            let sel = ((control >> (lane * 2)) & 3) as usize;
                            for j in 0..2usize {
                                self.mem.insert(d + (lane * 2 + j) as u64, src[sel * 2 + j]);
                            }
                        }
                    } else {
                        for lane in 0..4usize {
                            let sel = ((control >> (lane * 2)) & 3) as usize;
                            for j in 0..4usize {
                                self.mem.insert(d + (lane * 4 + j) as u64, src[sel * 4 + j]);
                            }
                        }
                    }
                }
                RiscOp::DoubleShiftLeft { width } => {
                    let bits = width as u32 * 8;
                    let count = (get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    ) & 0x3F) as u32;
                    if count != 0 {
                        let mask = width_mask_interp(bits);
                        let old = get_operand_val(
                            op_dst_raw,
                            &self.spec,
                            &self.regs,
                            &self.temps,
                            self.flags.raw,
                            self.vsp,
                            0,
                        ) & mask;
                        let src = get_operand_val(
                            op_src1_raw,
                            &self.spec,
                            &self.regs,
                            &self.temps,
                            self.flags.raw,
                            self.vsp,
                            imm1,
                        ) & mask;
                        let res = ((old << count) | (src >> (bits - count))) & mask;
                        let cf = (old >> (bits - count)) & 1;
                        self.flags.raw &= !(1 | 4 | 0x40 | 0x80 | 0x800);
                        self.flags.raw |= cf;
                        if res == 0 {
                            self.flags.raw |= 0x40;
                        }
                        if res & (1u64 << (bits - 1)) != 0 {
                            self.flags.raw |= 0x80;
                        }
                        self.flags.set_parity(res);
                        if count == 1 && (((res >> (bits - 1)) ^ cf) & 1) != 0 {
                            self.flags.raw |= 0x800;
                        }
                        self.store_operand(op_dst_raw, res);
                    }
                }
                RiscOp::BitTest {
                    width,
                    modify,
                    memory,
                } => {
                    let index = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    );
                    let bits = width as u64 * 8;
                    let bit = index % bits;
                    let src = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let old = if memory {
                        mem_read(
                            &self.mem,
                            src.wrapping_add((index / bits) * width as u64),
                            width,
                        )
                    } else {
                        src & width_mask_interp(width as u32 * 8)
                    };
                    self.flags.raw = (self.flags.raw & !1) | ((old >> bit) & 1);
                    if modify != 0 {
                        let newv = if modify == 1 {
                            old & !(1u64 << bit)
                        } else {
                            old | (1u64 << bit)
                        };
                        if memory {
                            mem_write(
                                &mut self.mem,
                                src.wrapping_add((index / bits) * width as u64),
                                width,
                                newv,
                            );
                        } else {
                            self.store_operand(op_dst_raw, newv);
                        }
                    }
                }
                RiscOp::PackedMovMaskBytes | RiscOp::PackedMovMaskPs => {
                    let a = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let mut mask = 0u64;
                    if risc_op == RiscOp::PackedMovMaskBytes {
                        for i in 0..16u64 {
                            mask |= ((mem_read(&self.mem, a + i, 1) >> 7) & 1) << i;
                        }
                    } else {
                        for i in 0..4u64 {
                            mask |= ((mem_read(&self.mem, a + i * 4, 4) >> 31) & 1) << i;
                        }
                    }
                    self.store_operand(op_dst_raw, mask);
                }
                RiscOp::PackedInsertWord => {
                    let d = get_operand_val(
                        op_dst_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        0,
                    );
                    let value = get_operand_val(
                        op_src1_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm1,
                    );
                    let lane = get_operand_val(
                        op_src2_raw,
                        &self.spec,
                        &self.regs,
                        &self.temps,
                        self.flags.raw,
                        self.vsp,
                        imm2,
                    ) & 7;
                    mem_write(&mut self.mem, d + lane * 2, 2, value);
                }
                RiscOp::CpuId => {
                    self.regs[0] = 0;
                    self.regs[3] = 0;
                    self.regs[1] = 0;
                    self.regs[2] = 0;
                }
                RiscOp::XGetBv => {
                    self.regs[0] = 0;
                    self.regs[2] = 0;
                }
                RiscOp::ReadSegmentBase { .. } => self.store_operand(op_dst_raw, 0),
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
    /// 인덱스 순으로 모은 테이블과, 각 시작점에서의 **롤링 키 상태**(`current_key`)
    /// 스냅샷을 함께 만든다. `eval_state` 는 `vip` 를 인스트럭션 인덱스로 쓰지만
    /// 폴리 스트림의 `vip` 는 바이트 오프셋이므로, taken 분기의 인덱스 타깃을
    /// 이 테이블로 바이트 오프셋으로 변환해 일치시킨다. 키 스냅샷은 분기(특히
    /// backward) 시 타깃 위치의 키 상태를 복원해 선형 실행과 동일한 키 스트림을
    /// 유지하는 데 쓴다. 디코드 스텝핑은 decoder/run 과 정확히 동일하며, 롤링
    /// 키는 `Copy` 복제본으로 전진시켜 원본 상태를 건드리지 않는다.
    fn instr_starts(&self, bytecode: &[u8]) -> (Vec<usize>, Vec<u64>) {
        let mut starts = Vec::new();
        let mut keys = Vec::new();
        let mut vip = 0usize;
        let mut rolling = self.rolling; // Copy — 선형 스캔 전용 복제본
        while vip < bytecode.len() {
            starts.push(vip);
            keys.push(rolling.current_key);
            let raw_op = rolling.decrypt_byte(bytecode[vip], vip as u64);
            vip += 1;
            let Some(risc_op) = self.spec.reverse_opcode_map.get(&raw_op).copied() else {
                break;
            };
            let risc_op = match risc_op {
                RiscOp::VirtualBranch { .. }
                | RiscOp::Setcc { .. }
                | RiscOp::ConditionalMove { .. } => {
                    if vip >= bytecode.len() {
                        break;
                    }
                    let _ = rolling.decrypt_byte(bytecode[vip], vip as u64);
                    vip += 1;
                    RiscOp::VirtualBranch {
                        cond: BranchCondition::Always,
                    }
                }
                other => other,
            };
            if vip + 3 > bytecode.len() {
                break;
            }
            let mut operands = [0u8; 3];
            for logical_slot in self.spec.operand_order() {
                operands[logical_slot] = rolling.decrypt_byte(bytecode[vip], vip as u64);
                vip += 1;
            }
            let [_op_dst, op_src1, op_src2] = operands;

            let imm1_width = self.spec.immediate_width(op_src1);
            let imm2_width = self.spec.immediate_width(op_src2);
            let take8 = |vip: &mut usize, rolling: &mut RollingKeyEngine, bytecode: &[u8]| {
                for _ in 0..8 {
                    if *vip < bytecode.len() {
                        let _ = rolling.decrypt_byte(bytecode[*vip], *vip as u64);
                        *vip += 1;
                    }
                }
            };
            if let Some(width) = imm1_width {
                for _ in 0..width {
                    if vip < bytecode.len() {
                        let _ = rolling.decrypt_byte(bytecode[vip], vip as u64);
                        vip += 1;
                    }
                }
            }
            if let Some(width) = imm2_width {
                for _ in 0..width {
                    if vip < bytecode.len() {
                        let _ = rolling.decrypt_byte(bytecode[vip], vip as u64);
                        vip += 1;
                    }
                }
            }
            if risc_op == RiscOp::AddWithCarry && imm1_width.is_none() && imm2_width.is_none() {
                take8(&mut vip, &mut rolling, bytecode);
            }
            if matches!(risc_op, RiscOp::VirtualBranch { .. }) && op_src1 == 0x00 {
                if vip < bytecode.len() {
                    let marker = rolling.decrypt_byte(bytecode[vip], vip as u64);
                    vip += 1;
                    if let Some(width) = self.spec.branch_target_width(marker) {
                        for _ in 0..width {
                            if vip < bytecode.len() {
                                let _ = rolling.decrypt_byte(bytecode[vip], vip as u64);
                                vip += 1;
                            }
                        }
                    }
                }
            }
            if risc_op == RiscOp::Halt {
                break;
            }
        }
        (starts, keys)
    }
}

mod arith;
mod branch;
mod mem;

pub(crate) use arith::{
    cvt_f64_int_interp, div_wide_interp, interp_store, mul_low_interp, mul_wide_interp,
    sign_extend_i128_interp, width_mask_interp,
};
pub(crate) use branch::{branch_taken, branch_taken_with_state};
pub(crate) use mem::{mem_read, mem_write};

#[cfg(test)]
mod tests;
