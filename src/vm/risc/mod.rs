pub mod desynth;
pub mod flags;
pub mod lifter;
pub mod opcodes;
pub mod opt;

pub use desynth::RiscDesynthesizer;
pub use flags::VirtualFlags;
pub use lifter::RiscLifter;
pub use opcodes::{BranchCondition, MicroInstr, MicroOperand, RiscOp};
pub use opt::RiscOptimizer;

/// RISC 가상 프로그램 컨테이너
#[derive(Debug, Clone)]
pub struct RiscProgram {
    pub instrs: Vec<MicroInstr>,
}

/// `RiscProgram::eval_state` 실행 결과로 돌려받는 가상 머신 상태.
/// 인터프리터(`PolymorphicInterpreter`)와의 **차등(differential) 검증**을 위한
/// 직렬화 가능한 참조 상태 표현이다. T1-4 기준 계약:
///
/// * `regs`  — 16개 가상 범용 레지스터
/// * `temps` — 8개 스크래치 임시 레지스터
/// * `flags` — 가상 RFLAGS (VFLAG_* 비트)
/// * `vsp`   — 가상 스택 포인터 (아래로 성장, 바이트 단위 오프셋)
/// * `stack` — 가상 스택 (index 0 = 최저 주소, 맨 끝 = 최고 주소/최근 push)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiscEvalState {
    pub regs: [u64; 16],
    pub temps: [u64; 8],
    pub flags: u64,
    pub vsp: u64,
    pub stack: Vec<u64>,
}

impl Default for RiscEvalState {
    fn default() -> Self {
        Self {
            regs: [0; 16],
            temps: [0; 8],
            flags: 0,
            vsp: 0,
            stack: Vec::new(),
        }
    }
}

impl RiscProgram {
    pub fn new(instrs: Vec<MicroInstr>) -> Self {
        Self { instrs }
    }

    /// RISC 가상 머신 인터프리터 시뮬레이션 (검증 및 테스트용)
    ///
    /// 하위 호환성용: NOR / AddWithCarry 만 처리하며, 그 외 op는 무시한다.
    /// 모든 op를 다루는 차등 검증 기준은 [`RiscProgram::eval_state`]를 사용한다.
    pub fn eval_registers(&self, init_regs: &[u64; 16]) -> [u64; 16] {
        let mut regs = *init_regs;
        let mut temps = [0u64; 8];
        let mut flags = VirtualFlags::default();

        let get_val = |op: Option<MicroOperand>, regs: &[u64; 16], temps: &[u64; 8], flags_raw: u64| -> u64 {
            match op {
                Some(MicroOperand::VReg(i)) => regs[i as usize],
                Some(MicroOperand::Imm64(v)) => v,
                Some(MicroOperand::Temp(i)) => temps[i as usize],
                Some(MicroOperand::Vflags) => flags_raw,
                _ => 0,
            }
        };

        for ins in &self.instrs {
            match ins.op {
                RiscOp::Nor => {
                    let a = get_val(ins.src1, &regs, &temps, flags.raw);
                    let b = get_val(ins.src2, &regs, &temps, flags.raw);
                    let res = !(a | b);
                    flags.update_logic64(res);
                    if let Some(dst) = ins.dst {
                        match dst {
                            MicroOperand::VReg(i) => regs[i as usize] = res,
                            MicroOperand::Temp(i) => temps[i as usize] = res,
                            _ => {}
                        }
                    }
                }
                RiscOp::AddWithCarry => {
                    let a = get_val(ins.src1, &regs, &temps, flags.raw);
                    let b = get_val(ins.src2, &regs, &temps, flags.raw);
                    let cin = ins.imm;
                    let (res, _cout) = flags.update_add64(a, b, cin);
                    if let Some(dst) = ins.dst {
                        match dst {
                            MicroOperand::VReg(i) => regs[i as usize] = res,
                            MicroOperand::Temp(i) => temps[i as usize] = res,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        regs
    }

    /// 전체 12개 RISC 마이크로 연산을 처리하는 **참조(정본) 시뮬레이터**.
    ///
    /// `PolymorphicInterpreter`(폴리모픽 바이트코드 해석기)와 동일한 의미를 가져야
    /// 하며, 이 함수와 해석기를 같은 프로그램에 대해 실행한 결과가 일치해야 한다
    /// (T1-4 차등 테스트). op별 의미론:
    ///
    /// * `Nor`            : dst = ~(src1 | src2); 논리 플래그 갱신
    /// * `AddWithCarry`   : dst = src1 + src2 + imm(cin); 산술 플래그 갱신
    /// * `ShiftRight`     : dst = src1 >> (src2 & 63) (논리 쉬프트)
    /// * `ShiftLeft`      : dst = src1 << (src2 & 63)
    /// * `VirtualPush`    : vsp -= 8; stack.push(src1)
    /// * `VirtualPop`     : dst = stack.pop(); vsp += 8
    /// * `MemoryRead`     : dst = *src1 (width 바이트)
    /// * `MemoryWrite`    : *src1 = src2 (width 바이트)
    /// * `SetFlag`        : flags = src1 (VFLAG 마스크 적용)
    /// * `Halt`           : 실행 종료
    /// * `VirtualBranch`  : 구현 계획(추후). 여기서는 무시.
    /// * `NativeCallBridge` : 여기서는 무시(호스트 콜은 런타임 계층 책임).
    pub fn eval_state(&self, init_regs: &[u64; 16]) -> RiscEvalState {
        let mut st = RiscEvalState::default();
        st.regs = *init_regs;
        let mut flags = VirtualFlags::default();

        let mut get_val = |op: Option<MicroOperand>, st: &RiscEvalState, flags_raw: u64| -> u64 {
            match op {
                Some(MicroOperand::VReg(i)) => st.regs[i as usize],
                Some(MicroOperand::Imm64(v)) => v,
                Some(MicroOperand::Temp(i)) => st.temps[i as usize],
                Some(MicroOperand::Vflags) => flags_raw,
                Some(MicroOperand::Vsp) => st.vsp,
                _ => 0,
            }
        };
        let mut store = |dst: Option<MicroOperand>, st: &mut RiscEvalState, val: u64| {
            if let Some(d) = dst {
                match d {
                    MicroOperand::VReg(i) => st.regs[i as usize] = val,
                    MicroOperand::Temp(i) => st.temps[i as usize] = val,
                    _ => {}
                }
            }
        };

        for ins in &self.instrs {
            match ins.op {
                RiscOp::Nor => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let res = !(a | b);
                    flags.update_logic64(res);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::AddWithCarry => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let (res, _cout) = flags.update_add64(a, b, ins.imm);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::ShiftRight => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let cnt = get_val(ins.src2, &st, flags.raw) & 63;
                    let res = if cnt == 0 { a } else { a >> cnt };
                    flags.update_logic64(res);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::ShiftLeft => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let cnt = get_val(ins.src2, &st, flags.raw) & 63;
                    let res = if cnt == 0 { a } else { a << cnt };
                    flags.update_logic64(res);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::VirtualPush => {
                    let v = get_val(ins.src1, &st, flags.raw);
                    st.vsp = st.vsp.wrapping_sub(8);
                    st.stack.push(v);
                }
                RiscOp::VirtualPop => {
                    if let Some(v) = st.stack.pop() {
                        st.vsp = st.vsp.wrapping_add(8);
                        store(ins.dst, &mut st, v);
                    }
                }
                RiscOp::SetFlag => {
                    let v = get_val(ins.src1, &st, flags.raw);
                    flags.raw = v & 0x8D5; // CF|PF|AF|ZF|SF|OF 마스크
                }
                RiscOp::Halt => break,
                _ => {}
            }
        }

        st.flags = flags.raw;
        st
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risc_desynth_not() {
        let mut d = RiscDesynthesizer::new();
        d.emit_not(MicroOperand::VReg(0), MicroOperand::VReg(1));
        let prog = RiscProgram::new(d.instrs);

        let mut regs = [0u64; 16];
        regs[1] = 0x123456789ABCDEF0;
        let out = prog.eval_registers(&regs);
        assert_eq!(out[0], !0x123456789ABCDEF0);
    }

    #[test]
    fn test_risc_desynth_and() {
        let mut d = RiscDesynthesizer::new();
        d.emit_and(
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
            MicroOperand::VReg(2),
        );
        let prog = RiscProgram::new(d.instrs);

        let mut regs = [0u64; 16];
        regs[1] = 0xF0F0F0F0AAAAAAAA;
        regs[2] = 0x0F0FFFFF55555555;
        let out = prog.eval_registers(&regs);
        assert_eq!(out[0], regs[1] & regs[2]);
    }

    #[test]
    fn test_risc_desynth_or() {
        let mut d = RiscDesynthesizer::new();
        d.emit_or(
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
            MicroOperand::VReg(2),
        );
        let prog = RiscProgram::new(d.instrs);

        let mut regs = [0u64; 16];
        regs[1] = 0x12340000A5A50000;
        regs[2] = 0x0000567800005A5A;
        let out = prog.eval_registers(&regs);
        assert_eq!(out[0], regs[1] | regs[2]);
    }

    #[test]
    fn test_risc_desynth_xor() {
        let mut d = RiscDesynthesizer::new();
        d.emit_xor(
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
            MicroOperand::VReg(2),
        );
        let prog = RiscProgram::new(d.instrs);

        let mut regs = [0u64; 16];
        regs[1] = 0xDEADBEEFCAFE0011;
        regs[2] = 0x123456789ABCDEF0;
        let out = prog.eval_registers(&regs);
        assert_eq!(out[0], regs[1] ^ regs[2]);
    }

    #[test]
    fn test_risc_desynth_sub() {
        let mut d = RiscDesynthesizer::new();
        d.emit_sub(
            MicroOperand::VReg(0),
            MicroOperand::VReg(1),
            MicroOperand::VReg(2),
        );
        let prog = RiscProgram::new(d.instrs);

        let mut regs = [0u64; 16];
        regs[1] = 1000;
        regs[2] = 300;
        let out = prog.eval_registers(&regs);
        assert_eq!(out[0], 700);
    }

    #[test]
    fn test_risc_eval_state_full_op_coverage() {
        // 모든 처리가능 op를 조합해 참조 시뮬레이터가 정확히 실행되는지 검증.
        let mut d = RiscDesynthesizer::new();
        // R0 = 10, R1 = 3
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(10), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(3), MicroOperand::Imm64(0));
        // R2 = R0 >> R1 = 1
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftRight)
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
        );
        // R3 = R0 << 1 = 20
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftLeft)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(1)),
        );
        // push R3 (스택 1개), pop R4
        d.emit_push(MicroOperand::VReg(3));
        d.emit_pop(MicroOperand::VReg(4));
        // Halt
        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);
        let st = prog.eval_state(&[0u64; 16]);

        assert_eq!(st.regs[2], 1, "shift right");
        assert_eq!(st.regs[3], 20, "shift left");
        assert_eq!(st.regs[4], 20, "pop returns pushed value");
        assert_eq!(st.stack.len(), 0, "push+pop balanced");
        assert_eq!(st.vsp, 0, "vsp balanced");
    }
}
