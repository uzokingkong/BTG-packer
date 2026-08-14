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

impl RiscProgram {
    pub fn new(instrs: Vec<MicroInstr>) -> Self {
        Self { instrs }
    }

    /// RISC 가상 머신 인터프리터 시뮬레이션 (검증 및 테스트용)
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
}
