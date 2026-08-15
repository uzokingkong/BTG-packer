pub mod desynth;
pub mod flags;
pub mod lifter;
pub mod opcodes;
pub mod opt;

use std::collections::HashMap;

pub use desynth::RiscDesynthesizer;
pub use flags::VirtualFlags;
pub use lifter::RiscLifter;
pub use opcodes::{BranchCondition, MicroInstr, MicroOperand, RiscOp};
pub use opt::RiscOptimizer;

/// RISC 가상 프로그램 컨테이너
#[derive(Debug, Clone)]
pub struct RiscProgram {
    pub instrs: Vec<MicroInstr>,
    /// 선택적 소스-IP → 인덱스 맵. `VirtualBranch`의 타깃(절대 x86 IP)을
    /// `instrs` 벡터 내 시작 인덱스로 변환해 `eval_state`가 분기를 실행하게 한다.
    /// `None`이면 `VirtualBranch.imm`을 직접 인덱스로 해석한다(선형 실행 보조).
    ip_map: Option<HashMap<u64, usize>>,
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
/// * `mem`   — 가상 메모리 (주소 → 바이트, `MemoryRead`/`MemoryWrite` 대상)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiscEvalState {
    pub regs: [u64; 16],
    pub temps: [u64; 8],
    pub flags: u64,
    pub vsp: u64,
    pub stack: Vec<u64>,
    pub mem: HashMap<u64, u8>,
}

impl Default for RiscEvalState {
    fn default() -> Self {
        Self {
            regs: [0; 16],
            temps: [0; 8],
            flags: 0,
            vsp: 0,
            stack: Vec::new(),
            mem: HashMap::new(),
        }
    }
}

impl RiscProgram {
    pub fn new(instrs: Vec<MicroInstr>) -> Self {
        Self {
            instrs,
            ip_map: None,
        }
    }

    /// 리프터가 기록한 소스-IP → 인덱스 맵을 가진 프로그램을 만든다.
    /// (분기 타깃을 실행 가능한 VIP 인덱스로 해석하기 위함.)
    pub fn with_ip_map(instrs: Vec<MicroInstr>, ip_map: HashMap<u64, usize>) -> Self {
        Self {
            instrs,
            ip_map: Some(ip_map),
        }
    }

/// ip_map(소스-IP → 프로그램 인덱스)을 통해 분기 타깃 절대 x86 IP를
    /// 프로그램 인덱스로 해석한다. (ip_map이 없으면 imm을 그대로 인덱스로 사용 —
    /// eval_state의 VirtualBranch와 동일한 해석)
    pub fn resolve_target(&self, imm: u64) -> usize {
        self.ip_map
            .as_ref()
            .and_then(|m| m.get(&imm))
            .copied()
            .unwrap_or(imm as usize)
    }

    /// 분기 타깃 해석용 ip_map 접근자 (네이티브 하네스가 정적 분기 타깃을
    /// 블록 인덱스로 베이크할 때 사용).
    pub fn ip_map(&self) -> Option<&HashMap<u64, usize>> {
        self.ip_map.as_ref()
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
                RiscOp::Mov => {
                    let a = get_val(ins.src1, &regs, &temps, flags.raw);
                    if let Some(dst) = ins.dst {
                        match dst {
                            MicroOperand::VReg(i) => regs[i as usize] = a,
                            MicroOperand::Temp(i) => temps[i as usize] = a,
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
    /// * `MemoryRead`     : dst = *src1 (width 바이트, 리틀엔디언)
    /// * `MemoryWrite`    : *src1 = src2 (width 바이트, 리틀엔디언)
    /// * `SetFlag`        : flags = src1 (VFLAG 마스크 적용)
    /// * `Halt`           : 실행 종료
    /// * `VirtualBranch`  : 조건이 참이면 VIP = 타깃(src1이 있으면 그 값, 없으면 imm).
    ///                      ip_map이 있으면 타깃 절대 IP → 인덱스로 변환.
    /// * `NativeCallBridge` : 여기서는 무시(호스트 콜은 런타임 계층 책임).
    pub fn eval_state(&self, init_regs: &[u64; 16]) -> RiscEvalState {
        self.eval_state_impl(init_regs, &HashMap::new())
    }

    /// 메모리를 사전 초기화한 상태에서 참조 시뮬레이터 실행.
    /// (메모리 피연산자 차등 테스트에서 초기 `.data`/`.bss`를 주입하기 위함.)
    pub fn eval_state_with_mem(
        &self,
        init_regs: &[u64; 16],
        mem: HashMap<u64, u8>,
    ) -> RiscEvalState {
        self.eval_state_impl(init_regs, &mem)
    }

    fn eval_state_impl(&self, init_regs: &[u64; 16], mem_seed: &HashMap<u64, u8>) -> RiscEvalState {
        let mut st = RiscEvalState::default();
        st.regs = *init_regs;
        st.mem = mem_seed.clone();
        let mut flags = VirtualFlags::default();

        let get_val = |op: Option<MicroOperand>, st: &RiscEvalState, flags_raw: u64| -> u64 {
            match op {
                Some(MicroOperand::VReg(i)) => st.regs[i as usize],
                Some(MicroOperand::Imm64(v)) => v,
                Some(MicroOperand::Temp(i)) => st.temps[i as usize],
                Some(MicroOperand::Vflags) => flags_raw,
                Some(MicroOperand::Vsp) => st.vsp,
                _ => 0,
            }
        };
        let store = |dst: Option<MicroOperand>, st: &mut RiscEvalState, val: u64| {
            if let Some(d) = dst {
                match d {
                    MicroOperand::VReg(i) => st.regs[i as usize] = val,
                    MicroOperand::Temp(i) => st.temps[i as usize] = val,
                    _ => {}
                }
            }
        };

        let mut vip = 0usize;
        while vip < self.instrs.len() {
            let ins = &self.instrs[vip];
            match ins.op {
                RiscOp::Nor => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let res = !(a | b);
                    flags.update_logic64(res);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::Mov => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    // 플래그를 변경하지 않는 순수 복사.
                    store(ins.dst, &mut st, a);
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
                RiscOp::ArithmeticShiftRight => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let cnt = get_val(ins.src2, &st, flags.raw) & 63;
                    let res = if cnt == 0 { a } else { ((a as i64) >> cnt) as u64 };
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
                RiscOp::MemoryRead { width } => {
                    let addr = get_val(ins.src1, &st, flags.raw);
                    let val = mem_read(&st.mem, addr, width);
                    store(ins.dst, &mut st, val);
                }
                RiscOp::MemoryWrite { width } => {
                    let addr = get_val(ins.src1, &st, flags.raw);
                    let val = get_val(ins.src2, &st, flags.raw);
                    mem_write(&mut st.mem, addr, width, val);
                }
                RiscOp::SetFlag => {
                    let v = get_val(ins.src1, &st, flags.raw);
                    flags.raw = v & 0x8D5; // CF|PF|AF|ZF|SF|OF 마스크
                }
                RiscOp::VirtualBranch { cond } => {
                    if branch_taken_with_state(cond, &flags, &st.regs) {
                        // 타깃: src1(동적 값, 간접 call) 또는 imm(절대 x86 IP)
                        let target = match ins.src1 {
                            Some(op) => get_val(Some(op), &st, flags.raw),
                            None => ins.imm,
                        };
                        let idx = self
                            .ip_map
                            .as_ref()
                            .and_then(|m| m.get(&target))
                            .copied()
                            .unwrap_or(target as usize);
                        vip = idx;
                        continue;
                    }
                }
                RiscOp::Halt => break,
                RiscOp::NativeCallBridge => {}
                // ── P2: 정수/비트/제어 복합 연산 ─────────────────────────────────
                RiscOp::Multiply { signed, width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    mul_wide(&mut st, &mut flags, a, b, signed, width, ins.dst);
                }
                RiscOp::MultiplyLow { signed, width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    mul_low(&mut st, &mut flags, a, b, signed, width, ins.dst);
                }
                RiscOp::Divide { signed, width } => {
                    let divisor = get_val(ins.src1, &st, flags.raw);
                    div_wide(&mut st, divisor, signed, width, ins.dst);
                }
                RiscOp::BSwap { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let res = if width == 4 {
                        (a.swap_bytes() as u32) as u64
                    } else {
                        a.swap_bytes()
                    };
                    store(ins.dst, &mut st, res);
                }
                RiscOp::BitScanForward => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    if a == 0 {
                        flags.set_zf(true);
                        store(ins.dst, &mut st, 0);
                    } else {
                        flags.set_zf(false);
                        store(ins.dst, &mut st, a.trailing_zeros() as u64);
                    }
                }
                RiscOp::BitScanReverse => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    if a == 0 {
                        flags.set_zf(true);
                        store(ins.dst, &mut st, 0);
                    } else {
                        flags.set_zf(false);
                        store(ins.dst, &mut st, 63 - a.leading_zeros() as u64);
                    }
                }
                RiscOp::CountTrailingZeros { width } => {
                    let bits = width as u32 * 8;
                    let mask = width_mask(bits);
                    let s = get_val(ins.src1, &st, flags.raw) & mask;
                    if s == 0 {
                        flags.set_cf(true);
                        flags.set_zf(true);
                        store(ins.dst, &mut st, bits as u64);
                    } else {
                        flags.set_cf(false);
                        let c = s.trailing_zeros() as u64;
                        flags.set_zf(c == 0);
                        store(ins.dst, &mut st, c);
                    }
                }
                RiscOp::CountLeadingZeros { width } => {
                    let bits = width as u32 * 8;
                    let mask = width_mask(bits);
                    let s = get_val(ins.src1, &st, flags.raw) & mask;
                    if s == 0 {
                        flags.set_cf(true);
                        flags.set_zf(true);
                        store(ins.dst, &mut st, bits as u64);
                    } else {
                        flags.set_cf(false);
                        // 폭 한정 clz: (bits-1) - msb_index
                        let msb = 63 - s.leading_zeros() as u64;
                        let c = (bits as u64 - 1) - msb;
                        flags.set_zf(c == 0);
                        store(ins.dst, &mut st, c);
                    }
                }
                RiscOp::PopCount => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let res = a.count_ones() as u64;
                    flags.update_logic64(res);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::Setcc { cond } => {
                    let v = branch_taken_with_state(cond, &flags, &st.regs);
                    store(ins.dst, &mut st, v as u64);
                }
                RiscOp::ConditionalMove { cond } => {
                    if branch_taken_with_state(cond, &flags, &st.regs) {
                        let v = get_val(ins.src1, &st, flags.raw);
                        store(ins.dst, &mut st, v);
                    }
                }
                RiscOp::CompareExchange { width } => {
                    let addr = get_val(ins.src1, &st, flags.raw);
                    let newv = get_val(ins.src2, &st, flags.raw);
                    let bits = width as u32 * 8;
                    let mask = width_mask(bits);
                    let acc = st.regs[0] & mask;
                    let old = mem_read(&st.mem, addr, width) & mask;
                    if old == acc {
                        mem_write(&mut st.mem, addr, width, newv & mask);
                        flags.set_zf(true);
                    } else {
                        st.regs[0] = old;
                        flags.set_zf(false);
                    }
                }
                RiscOp::FloatAdd { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let res = if width == 4 {
                        (f32::from_bits(a as u32) + f32::from_bits(b as u32)).to_bits() as u64
                    } else {
                        (f64::from_bits(a) + f64::from_bits(b)).to_bits()
                    };
                    store(ins.dst, &mut st, res);
                }
                RiscOp::FloatSub { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let res = if width == 4 {
                        (f32::from_bits(a as u32) - f32::from_bits(b as u32)).to_bits() as u64
                    } else {
                        (f64::from_bits(a) - f64::from_bits(b)).to_bits()
                    };
                    store(ins.dst, &mut st, res);
                }
                RiscOp::FloatMul { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let res = if width == 4 {
                        (f32::from_bits(a as u32) * f32::from_bits(b as u32)).to_bits() as u64
                    } else {
                        (f64::from_bits(a) * f64::from_bits(b)).to_bits()
                    };
                    store(ins.dst, &mut st, res);
                }
                RiscOp::FloatDiv { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let res = if width == 4 {
                        (f32::from_bits(a as u32) / f32::from_bits(b as u32)).to_bits() as u64
                    } else {
                        (f64::from_bits(a) / f64::from_bits(b)).to_bits()
                    };
                    store(ins.dst, &mut st, res);
                }
                RiscOp::IntToFloat { src_bits, dst_bits } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let iv = if src_bits == 4 { (a as i32) as i64 } else { a as i64 };
                    let res = if dst_bits == 4 {
                        (iv as f32).to_bits() as u64
                    } else {
                        (iv as f64).to_bits()
                    };
                    store(ins.dst, &mut st, res);
                }
                RiscOp::FloatToInt { src_bits, dst_bits, truncate } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let f = if src_bits == 4 { f32::from_bits(a as u32) as f64 } else { f64::from_bits(a) };
                    let iv = if truncate {
                        (f.trunc() as i64) as u64
                    } else {
                        round_ties_even(f) as u64
                    };
                    let res = if dst_bits == 8 { iv } else { iv & 0xFFFF_FFFF };
                    store(ins.dst, &mut st, res);
                }
                RiscOp::FloatToFloat { src_bits, dst_bits } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let res = if src_bits == 4 {
                        (f32::from_bits(a as u32) as f64).to_bits()
                    } else {
                        (f64::from_bits(a) as f32).to_bits() as u64
                    };
                    store(ins.dst, &mut st, res);
                }
            }
            vip += 1;
        }

        st.flags = flags.raw;
        st
    }
}

/// 조건 분기가 걸리는지 평가 (x86 조건 코드 의미론).
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
fn branch_taken_with_state(cond: BranchCondition, flags: &VirtualFlags, regs: &[u64; 16]) -> bool {
    if let BranchCondition::CounterZero(width) = cond {
        // Jcxz(2)/Jecxz(4)/Jrcxz(8): RCX(reg[1])의 하위 width 바이트가 0인지
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
fn mem_read(mem: &HashMap<u64, u8>, addr: u64, width: u8) -> u64 {
    let mut v = 0u64;
    for i in 0..width {
        if let Some(&b) = mem.get(&addr.wrapping_add(i as u64)) {
            v |= (b as u64) << (i as u64 * 8);
        }
    }
    v
}

/// 리틀엔디언 `width`바이트 메모리 쓰기.
fn mem_write(mem: &mut HashMap<u64, u8>, addr: u64, width: u8, val: u64) {
    for i in 0..width {
        mem.insert(addr.wrapping_add(i as u64), (val >> (i as u64 * 8)) as u8);
    }
}

// ── P2: 정수/비트 복합 연산 참조 헬퍼 ─────────────────────────────────────────

/// `width`바이트 폭의 비트 마스크.
fn width_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// round-to-nearest-even (x86 MXCSR 기본 RC) — 정확히 half-way 인 경우 짝수 쪽으로 반올림.
fn round_ties_even(x: f64) -> i64 {
    let fl = x.floor();
    let diff = x - fl;
    if diff == 0.5 {
        let f = fl as i64;
        if f % 2 == 0 { f } else { f + 1 }
    } else {
        x.round() as i64
    }
}

/// `bits` 비트 값 `v`를 i128 로 부호 확장 (bits < 128).
fn sign_extend_i128(v: u128, bits: u32) -> i128 {
    let shift = 128 - bits;
    ((v << shift) as i128) >> shift
}

/// 1-피연산자 MUL/IMUL 참조: low → dst, high → RDX(폭 ≥ 2) 또는 AX(폭 1).
fn mul_wide(
    st: &mut RiscEvalState,
    flags: &mut VirtualFlags,
    a: u64,
    b: u64,
    signed: bool,
    width: u8,
    dst: Option<MicroOperand>,
) {
    let bits = width as u32 * 8;
    let mask = width_mask(bits);
    let am = a & mask;
    let bm = b & mask;
    let full = (am as u128) * (bm as u128);
    let low = full as u64;
    let high = ((full >> bits) as u64) & mask;
    let ovf = if signed {
        let sign_ext = if low & (1u64 << (bits - 1)) != 0 { mask } else { 0 };
        high != sign_ext
    } else {
        high != 0
    };
    flags.set_cf_of(ovf);
    if width == 1 {
        // AX = AL·r/m8 — AH(high 8비트)를 RAX 비트 8..15 로.
        store_dst(st, dst, (low & 0xFF) | ((high & 0xFF) << 8));
    } else {
        store_dst(st, dst, low);
        st.regs[2] = high; // RDX
    }
}

/// 2/3-피연산자 IMUL 참조: dst = low(src1·src2), RDX 미기록.
fn mul_low(
    st: &mut RiscEvalState,
    flags: &mut VirtualFlags,
    a: u64,
    b: u64,
    signed: bool,
    width: u8,
    dst: Option<MicroOperand>,
) {
    let bits = width as u32 * 8;
    let mask = width_mask(bits);
    let am = a & mask;
    let bm = b & mask;
    let full = (am as u128) * (bm as u128);
    let low = full as u64;
    let high = ((full >> bits) as u64) & mask;
    let ovf = if signed {
        let sign_ext = if low & (1u64 << (bits - 1)) != 0 { mask } else { 0 };
        high != sign_ext
    } else {
        high != 0
    };
    flags.set_cf_of(ovf);
    store_dst(st, dst, low);
}

/// DIV/IDIV 참조: 피제수 = RDX:RAX(폭별, 폭 1 은 AX), 제수 = divisor,
/// 몫 → dst(RAX), 나머지 → RDX. (제수 0 또는 몫 오버플로는 x86 #DE — 참조에서는
/// 결과 0 으로 취급해 크래시 회피.)
fn div_wide(st: &mut RiscEvalState, divisor: u64, signed: bool, width: u8, dst: Option<MicroOperand>) {
    let bits = width as u32 * 8;
    let mask = width_mask(bits);
    // 폭 1(8비트 DIV/IDIV)은 AX(reg0 low16)가 피제수 — RDX 미사용.
    let (dividend, dvbits) = if width == 1 {
        ((st.regs[0] & 0xFFFF) as u128, 16u32)
    } else {
        (
            ((st.regs[2] & mask) as u128) << bits | (st.regs[0] & mask) as u128,
            bits * 2,
        )
    };
    let dv = (divisor & mask) as u128;
    if dv == 0 {
        // #DE → 참조 기본값 (0). 폭 1 은 AX(dst) 형태.
        if width == 1 {
            store_dst(st, dst, 0);
        } else {
            store_dst(st, dst, 0);
            st.regs[2] = 0;
        }
        return;
    }
    let (q, r) = if signed {
        let d = sign_extend_i128(dividend, dvbits);
        let s = sign_extend_i128(dv as u64 as u128, bits);
        // Rust 정수 나눗셈은 0 쪽으로 절단 — IDIV 와 동일.
        let (q, r) = (d / s, d % s);
        (q as u128, r as u128)
    } else {
        (dividend / dv, dividend % dv)
    };
    if width == 1 {
        // AL = 몫, AH = 나머지 → AX(dst).
        let ax = ((r as u64) & 0xFF) << 8 | ((q as u64) & 0xFF);
        store_dst(st, dst, ax);
    } else {
        store_dst(st, dst, (q as u64) & mask);
        st.regs[2] = (r as u64) & mask;
    }
}

/// dst(Some VReg/Temp) 저장 — eval_state 의 `store` 클로저와 동일.
fn store_dst(st: &mut RiscEvalState, dst: Option<MicroOperand>, val: u64) {
    if let Some(d) = dst {
        match d {
            MicroOperand::VReg(i) => st.regs[i as usize] = val,
            MicroOperand::Temp(i) => st.temps[i as usize] = val,
            _ => {}
        }
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

    #[test]
    fn test_eval_state_memory_read_write() {
        let mut d = RiscDesynthesizer::new();
        // T0 = 0x1000 (addr), R0 = 0x1234 (val), write 8 bytes, read back to R1
        d.emit_add(MicroOperand::Temp(0), MicroOperand::Imm64(0x1000), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x12345678), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryWrite { width: 8 })
                .with_src1(MicroOperand::Temp(0))
                .with_src2(MicroOperand::VReg(0)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MemoryRead { width: 4 })
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::Temp(0)),
        );
        let prog = RiscProgram::new(d.instrs);
        let st = prog.eval_state(&[0u64; 16]);
        assert_eq!(st.regs[1], 0x12345678, "read back low 4 bytes");
        assert_eq!(st.mem.get(&0x1000), Some(&0x78));
        assert_eq!(st.mem.get(&0x1007), Some(&0x00));
    }

    #[test]
    fn test_eval_state_virtual_branch_taken_and_not() {
        // R0=10, R1=10 -> sub sets ZF. branch{Zero} target 1 (direct index).
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(10), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(10), MicroOperand::Imm64(0));
        d.emit_sub(MicroOperand::Temp(0), MicroOperand::VReg(0), MicroOperand::VReg(1));
        // index 4 = VirtualBranch{Zero -> 7} ; then Halt at 5 (not reached), Halt at 6
        // Use direct index target 7.
        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::Zero }).with_imm(7),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // 5
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // 6
        d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(99), MicroOperand::Imm64(0)); // 7
        let prog = RiscProgram::new(d.instrs);
        let st = prog.eval_state(&[0u64; 16]);
        assert_eq!(st.regs[7], 99, "branch taken (ZF set)");
    }
}
