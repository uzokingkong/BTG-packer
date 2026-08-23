use std::collections::HashMap;

use super::flags::{
    mask_for_width, VirtualFlags, VFLAG_CF, VFLAG_DF, VFLAG_OF, VFLAG_PF, VFLAG_SF, VFLAG_ZF,
};
use super::math_util::*;
use super::opcodes::{BranchCondition, MicroInstr, MicroOperand, RiscOp};
use super::{RiscEvalState, RiscProgram};

/// A guest-visible evaluator failure. `state` is the precise state before the
/// faulting instruction commits any result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmFault {
    pub kind: VmFaultKind,
    /// Micro-instruction index in the RISC program.
    pub vip: usize,
    /// Original guest instruction address when an `ip_map` is available.
    pub guest_rip: Option<u64>,
    pub state: RiscEvalState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmFaultKind {
    DivideByZero,
    QuotientOverflow,
    Trap,
    UnknownIndirectRoute {
        target: u64,
    },
    UnknownReturnRoute {
        target: u64,
    },
    MemoryAccess {
        address: u64,
        width: u8,
        write: bool,
    },
}

/// Optional address-space policy for checked evaluator memory accesses.
///
/// The legacy evaluator APIs do not install a policy and therefore retain the
/// sparse, zero-filled `HashMap` behavior. When a policy is supplied, every
/// byte of a `MemoryRead`/`MemoryWrite` must fit in one region with the
/// requested permission.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryPolicy {
    regions: Vec<MemoryRegion>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub len: u64,
    pub readable: bool,
    pub writable: bool,
}

impl MemoryPolicy {
    pub fn new(regions: Vec<MemoryRegion>) -> Self {
        Self { regions }
    }

    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    fn permits(&self, address: u64, width: u8, write: bool) -> bool {
        let Some(end) = address.checked_add(width as u64) else {
            return false;
        };
        width != 0
            && self.regions.iter().any(|region| {
                let Some(region_end) = region.start.checked_add(region.len) else {
                    return false;
                };
                address >= region.start
                    && end <= region_end
                    && if write {
                        region.writable
                    } else {
                        region.readable
                    }
            })
    }
}

enum ExecResult {
    /// ???깅쾳 嶺뚮ㅏ援앲???怨쀬Ŧ 嶺뚯쉳?듸쭛?
    Next,
    /// ?釉뚯뫅????vip ????濚??筌뤾퍓????댁Ŧ ???깆젧.
    Jump(usize),
    /// Halt ???熬곣뫁夷?윜諛몄굡????リ턁筌?
    Halt,
}

fn div_wide_fallible(
    st: &mut RiscEvalState,
    divisor: u64,
    signed: bool,
    width: u8,
    dst: Option<MicroOperand>,
) -> Result<(), VmFaultKind> {
    let bits = width as u32 * 8;
    let mask = width_mask(bits);
    let (dividend, dividend_bits) = if width == 1 {
        ((st.regs[0] & 0xffff) as u128, 16)
    } else {
        (
            ((st.regs[2] & mask) as u128) << bits | (st.regs[0] & mask) as u128,
            bits * 2,
        )
    };
    let raw_divisor = (divisor & mask) as u128;
    if raw_divisor == 0 {
        return Err(VmFaultKind::DivideByZero);
    }

    let (quotient, remainder) = if signed {
        let dividend = sign_extend_i128(dividend, dividend_bits);
        let divisor = sign_extend_i128(raw_divisor, bits);
        let Some(quotient) = dividend.checked_div(divisor) else {
            return Err(VmFaultKind::QuotientOverflow);
        };
        let remainder = dividend % divisor;
        let min = -(1i128 << (bits - 1));
        let max = (1i128 << (bits - 1)) - 1;
        if quotient < min || quotient > max {
            return Err(VmFaultKind::QuotientOverflow);
        }
        (quotient as u128, remainder as u128)
    } else {
        let quotient = dividend / raw_divisor;
        let max = mask as u128;
        if quotient > max {
            return Err(VmFaultKind::QuotientOverflow);
        }
        (quotient, dividend % raw_divisor)
    };

    if width == 1 {
        store_dst(
            st,
            dst,
            ((remainder as u64) & 0xff) << 8 | ((quotient as u64) & 0xff),
        );
    } else {
        store_dst(st, dst, (quotient as u64) & mask);
        st.regs[2] = (remainder as u64) & mask;
    }
    Ok(())
}

impl RiscProgram {
    pub fn new(instrs: Vec<MicroInstr>) -> Self {
        Self {
            instrs,
            ip_map: None,
            sub_vms: HashMap::new(),
        }
    }

    /// ?洹먮뿫???? ?リ옇?▽빳?????裕?IP ???筌뤾퍓???嶺뚮씭踰???띠럾?嶺??熬곣뫁夷?윜諛몄굡???嶺뚮씭??キ??
    /// (?釉뚯뫅????濚밸Þ??????덈뺄 ?띠럾??繞③뇡?VIP ?筌뤾퍓????댁Ŧ ??怨댄맍???얄뵛 ?熬곥굥留?)
    pub fn with_ip_map(instrs: Vec<MicroInstr>, ip_map: HashMap<u64, usize>) -> Self {
        Self {
            instrs,
            ip_map: Some(ip_map),
            sub_vms: HashMap::new(),
        }
    }

    /// P1 (③): VmCallBridge 서브 VM 레지스트리를 함께 설정한 RiscProgram.
    pub fn with_sub_vms(instrs: Vec<MicroInstr>, sub_vms: HashMap<u64, RiscProgram>) -> Self {
        Self {
            instrs,
            ip_map: None,
            sub_vms,
        }
    }

    /// VmCallBridge 서브 VM 조회 (프로그램 id → 서브 RiscProgram).
    pub fn sub_vm(&self, id: u64) -> Option<&RiscProgram> {
        self.sub_vms.get(&id)
    }

    /// F1: 네이티브 콜 사이트의 FP 리턴 힌트 주입.
    ///
    /// 직접 콜은 `VirtualPush(ret_ip); VirtualBranch{Always}.with_imm(target)` 로
    /// lift 된다. `fp_returns`(타깃 VA → 4=f32 / 8=f64)에 해당 타깃이 있으면 그
    /// VirtualBranch **직전**에 `SetNativeFpReturn{width}` 를 삽입해, 타깃이
    /// branch-map 에 없어 네이티브 브릿지로 나갈 때 반환값을 XMM0(FP)에서
    /// regs[0] 으로 동기화하도록 한다. (VM 내부 타깃이면 브릿지가 안 쓰이므로
    /// 무해한 스테일 슬롯 기록일 뿐.)
    pub fn annotate_native_fp_returns(&mut self, fp_returns: &std::collections::HashMap<u64, u8>) {
        if fp_returns.is_empty() {
            return;
        }
        let mut out = Vec::with_capacity(self.instrs.len() + fp_returns.len());
        for ins in &self.instrs {
            if let RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            } = ins.op
            {
                if ins.src1.is_none() {
                    if let Some(&w) = fp_returns.get(&ins.imm) {
                        if w == 4 || w == 8 {
                            out.push(MicroInstr::new(RiscOp::SetNativeFpReturn { width: w }));
                        }
                    }
                }
            }
            out.push(ins.clone());
        }
        self.instrs = out;
    }

    /// ip_map(???裕?IP ???熬곣뫁夷?윜諛몄굡???筌뤾퍓???????????釉뚯뫅????濚???? x86 IP??
    /// ?熬곣뫁夷?윜諛몄굡???筌뤾퍓????댁Ŧ ??怨댄맍??類ｋ펲. (ip_map????怨몃さ嶺?imm???잙갭梨????筌뤾퍓????댁Ŧ ??????
    /// eval_state??VirtualBranch?? ???됰뎄????怨댄맍)
    pub fn resolve_target(&self, imm: u64) -> usize {
        self.ip_map
            .as_ref()
            .and_then(|m| m.get(&imm))
            .copied()
            .unwrap_or(imm as usize)
    }

    /// ?釉뚯뫅????濚???怨댄맍??ip_map ??얜∥???(???깅턄??⑤벤????濡ろ맟??? ?筌먦끉???釉뚯뫅????濚밸Þ???
    /// ??곕?餓??筌뤾퍓????댁Ŧ ?뺢퀣伊???????????.
    pub fn ip_map(&self) -> Option<&HashMap<u64, usize>> {
        self.ip_map.as_ref()
    }

    /// RISC ?띠럾????誘⑹굣???筌뤿굛??熬곣뱿遊????????깅턄??(?롪틵?嶺??????裕?筌뤾쑴??
    ///
    /// ??瑜곷쭊 ?筌뤿굞??繹먮냱?? NOR / AddWithCarry 嶺?嶺뚳퐣瑗????? ????op????쒕샍???類ｋ펲.
    /// 嶺뚮ㅄ維獄?op?????쇳렩??嶺뚢뼰維甕??롪틵?嶺??リ옇???? [`RiscProgram::eval_state`]???????類ｋ펲.
    pub fn eval_registers(&self, init_regs: &[u64; 16]) -> [u64; 16] {
        let mut regs = *init_regs;
        let mut temps = [0u64; 8];
        let mut flags = VirtualFlags::default();

        let get_val =
            |op: Option<MicroOperand>, regs: &[u64; 16], temps: &[u64; 8], flags_raw: u64| -> u64 {
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
                RiscOp::Add { width } => {
                    let a = get_val(ins.src1, &regs, &temps, flags.raw);
                    let b = get_val(ins.src2, &regs, &temps, flags.raw);
                    let m = crate::vm::risc::flags::mask_for_width(width);
                    let r = a.wrapping_add(b) & m;
                    if let Some(dst) = ins.dst {
                        match dst {
                            MicroOperand::VReg(i) => regs[i as usize] = r,
                            MicroOperand::Temp(i) => temps[i as usize] = r,
                            _ => {}
                        }
                    }
                }
                RiscOp::SubWithBorrow { width } => {
                    let a = get_val(ins.src1, &regs, &temps, flags.raw);
                    let b = get_val(ins.src2, &regs, &temps, flags.raw);
                    let m = crate::vm::risc::flags::mask_for_width(width);
                    let r = a.wrapping_sub(b) & m;
                    if let Some(dst) = ins.dst {
                        match dst {
                            MicroOperand::VReg(i) => regs[i as usize] = r,
                            MicroOperand::Temp(i) => temps[i as usize] = r,
                            _ => {}
                        }
                    }
                }
                RiscOp::Adc { width } | RiscOp::Sbb { width } => {
                    let a = get_val(ins.src1, &regs, &temps, flags.raw);
                    let b = get_val(ins.src2, &regs, &temps, flags.raw);
                    let r = if matches!(ins.op, RiscOp::Adc { .. }) {
                        flags.update_adc(a, b, width)
                    } else {
                        flags.update_sbb(a, b, width)
                    };
                    if let Some(dst) = ins.dst {
                        match dst {
                            MicroOperand::VReg(i) => regs[i as usize] = r,
                            MicroOperand::Temp(i) => temps[i as usize] = r,
                            _ => {}
                        }
                    }
                }
                RiscOp::Inc { width } => {
                    let a = get_val(ins.src1, &regs, &temps, flags.raw);
                    let m = crate::vm::risc::flags::mask_for_width(width);
                    let r = a.wrapping_add(1) & m;
                    if let Some(dst) = ins.dst {
                        match dst {
                            MicroOperand::VReg(i) => regs[i as usize] = r,
                            MicroOperand::Temp(i) => temps[i as usize] = r,
                            _ => {}
                        }
                    }
                }
                RiscOp::Dec { width } => {
                    let a = get_val(ins.src1, &regs, &temps, flags.raw);
                    let m = crate::vm::risc::flags::mask_for_width(width);
                    let r = a.wrapping_sub(1) & m;
                    if let Some(dst) = ins.dst {
                        match dst {
                            MicroOperand::VReg(i) => regs[i as usize] = r,
                            MicroOperand::Temp(i) => temps[i as usize] = r,
                            _ => {}
                        }
                    }
                }
                RiscOp::Not { width } => {
                    let a = get_val(ins.src1, &regs, &temps, flags.raw);
                    let m = crate::vm::risc::flags::mask_for_width(width);
                    let r = !a & m;
                    if let Some(dst) = ins.dst {
                        match dst {
                            MicroOperand::VReg(i) => regs[i as usize] = r,
                            MicroOperand::Temp(i) => temps[i as usize] = r,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        regs
    }

    /// ?熬곣뫕??12??RISC 嶺뚮씭????餓???⑥ろ뀰??嶺뚳퐣瑗???濡ル츎 **嶺뚣볦굣???筌먲퐢沅? ??????깅턄??*.
    ///
    /// `PolymorphicInterpreter`(????怨살춻?????꾩룆???筌뤾쑵留????怨댄맍???? ???됰뎄????????띠럾??筌뤾쑬??
    /// ???? ????貫??? ??怨댄맍?リ옇?? ?띠룇?? ?熬곣뫁夷?윜諛몄굡??????????덈뺄???롪퍒???쒖쾸? ??源딅뭵??怨룻뒍 ??類ｋ펲
    /// (T1-4 嶺뚢뼰維甕????裕??. op???????
    ///
    /// * `Nor`            : dst = ~(src1 | src2); ??寃몃뉴 ????뗥윜??띠룄???
    /// * `AddWithCarry`   : dst = src1 + src2 + imm(cin); ??⑥ル뻿 ????뗥윜??띠룄???
    /// * `ShiftRight`     : dst = src1 >> (src2 & 63) (??寃몃뉴 ?????
    /// * `ShiftLeft`      : dst = src1 << (src2 & 63)
    /// * `VirtualPush`    : vsp -= 8; stack.push(src1)
    /// * `VirtualPop`     : dst = stack.pop(); vsp += 8
    /// * `MemoryRead`     : dst = *src1 (width ?꾩룆???? ?洹???븐뼔???
    /// * `MemoryWrite`    : *src1 = src2 (width ?꾩룆???? ?洹???븐뼔???
    /// * `SetFlag`        : flags = src1 (VFLAG 嶺뚮씭??????⑤챷??
    /// * `Halt`           : ???덈뺄 ??リ턁筌?
    /// * `VirtualBranch`  : ?브퀗?쀦뤃??嶺뚣볦굣?醫묒춺?VIP = ??濚?src1?????깅さ嶺????? ??怨몃さ嶺?imm).
    ///                      ip_map?????깅さ嶺???濚???? IP ???筌뤾퍓????댁Ŧ ?곌떠???
    /// * `NativeCallBridge` : ?????類ｋ츎 ??쒕샍???筌뤾쑬裕???袁⑸츋? ???????ｌ뫒筌?嶺?援??.
    pub fn eval_state(&self, init_regs: &[u64; 16]) -> RiscEvalState {
        self.try_eval_state(init_regs)
            .unwrap_or_else(|fault| fault.state)
    }

    pub fn try_eval_state(&self, init_regs: &[u64; 16]) -> Result<RiscEvalState, VmFault> {
        self.eval_state_impl(init_regs, &HashMap::new(), None)
    }

    /// 嶺뚮∥???꾨뎨?? ?????貫?껆뵳??됀????⑤객臾?????嶺뚣볦굣????????깅턄?????덈뺄.
    /// (嶺뚮∥???꾨뎨???源낆뿼??⑥ъ겱 嶺뚢뼰維甕????裕?筌뤾쑬????貫?껆뵳?`.data`/`.bss`???낅슣?????얄뵛 ?熬곥굥留?)
    pub fn eval_state_with_mem(
        &self,
        init_regs: &[u64; 16],
        mem: HashMap<u64, u8>,
    ) -> RiscEvalState {
        self.try_eval_state_with_mem(init_regs, mem)
            .unwrap_or_else(|fault| fault.state)
    }

    pub fn try_eval_state_with_mem(
        &self,
        init_regs: &[u64; 16],
        mem: HashMap<u64, u8>,
    ) -> Result<RiscEvalState, VmFault> {
        self.eval_state_impl(init_regs, &mem, None)
    }

    pub fn eval_state_with_mem_policy(
        &self,
        init_regs: &[u64; 16],
        mem: HashMap<u64, u8>,
        policy: &MemoryPolicy,
    ) -> RiscEvalState {
        self.try_eval_state_with_mem_policy(init_regs, mem, policy)
            .unwrap_or_else(|fault| fault.state)
    }

    pub fn try_eval_state_with_mem_policy(
        &self,
        init_regs: &[u64; 16],
        mem: HashMap<u64, u8>,
        policy: &MemoryPolicy,
    ) -> Result<RiscEvalState, VmFault> {
        self.eval_state_impl(init_regs, &mem, Some(policy))
    }

    fn eval_state_impl(
        &self,
        init_regs: &[u64; 16],
        mem_seed: &HashMap<u64, u8>,
        memory_policy: Option<&MemoryPolicy>,
    ) -> Result<RiscEvalState, VmFault> {
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
            let fault = |kind: VmFaultKind, st: &RiscEvalState, flags_raw: u64| {
                let mut state = st.clone();
                state.flags = flags_raw;
                VmFault {
                    kind,
                    vip,
                    guest_rip: self.ip_map.as_ref().and_then(|map| {
                        map.iter()
                            .filter(|(_, mapped_vip)| **mapped_vip == vip)
                            .map(|(rip, _)| *rip)
                            .min()
                    }),
                    state,
                }
            };
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
                    // ????뗥윜諛몄굡? ?곌떠??롪퍔???彛? ???낅츎 ??戮?빢 ?곌랜踰딀쾮?
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
                    // x86: count==0 ?????RFLAGS ?釉띾쐞?
                    if cnt != 0 {
                        flags.update_logic64(res);
                        if (a >> (cnt - 1)) & 1 != 0 {
                            flags.raw |= VFLAG_CF;
                        }
                    }
                    store(ins.dst, &mut st, res);
                }
                RiscOp::ArithmeticShiftRight => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let cnt = get_val(ins.src2, &st, flags.raw) & 63;
                    let res = if cnt == 0 {
                        a
                    } else {
                        ((a as i64) >> cnt) as u64
                    };
                    if cnt != 0 {
                        flags.update_logic64(res);
                        if (a >> (cnt - 1)) & 1 != 0 {
                            flags.raw |= VFLAG_CF;
                        }
                    }
                    store(ins.dst, &mut st, res);
                }
                RiscOp::ShiftLeft => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let cnt = get_val(ins.src2, &st, flags.raw) & 63;
                    let res = if cnt == 0 { a } else { a << cnt };
                    if cnt != 0 {
                        flags.update_logic64(res);
                        if (a >> (64 - cnt)) & 1 != 0 {
                            flags.raw |= VFLAG_CF;
                        }
                    }
                    store(ins.dst, &mut st, res);
                }
                RiscOp::RotateLeft { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let c = get_val(ins.src2, &st, flags.raw);
                    let res = flags.update_rol(a, c, width);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::Add { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let res = flags.update_add(a, b, width);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::SubWithBorrow { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let res = flags.update_sub(a, b, width);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::Adc { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let res = flags.update_adc(a, b, width);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::Sbb { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let res = flags.update_sbb(a, b, width);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::Inc { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let res = flags.update_inc(a, width);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::Dec { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let res = flags.update_dec(a, width);
                    store(ins.dst, &mut st, res);
                }
                RiscOp::Not { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let res = !a & crate::vm::risc::flags::mask_for_width(width);
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
                    if memory_policy.is_some_and(|policy| !policy.permits(addr, width, false)) {
                        return Err(fault(
                            VmFaultKind::MemoryAccess {
                                address: addr,
                                width,
                                write: false,
                            },
                            &st,
                            flags.raw,
                        ));
                    }
                    let val = mem_read(&st.mem, addr, width);
                    store(ins.dst, &mut st, val);
                }
                RiscOp::MemoryWrite { width } => {
                    let addr = get_val(ins.src1, &st, flags.raw);
                    let val = get_val(ins.src2, &st, flags.raw);
                    if memory_policy.is_some_and(|policy| !policy.permits(addr, width, true)) {
                        return Err(fault(
                            VmFaultKind::MemoryAccess {
                                address: addr,
                                width,
                                write: true,
                            },
                            &st,
                            flags.raw,
                        ));
                    }
                    mem_write(&mut st.mem, addr, width, val);
                }
                RiscOp::SetFlag => {
                    let v = get_val(ins.src1, &st, flags.raw);
                    // CF|PF|AF|ZF|SF|OF status bits, plus DF (bit 10) ??CLD/STD
                    // lower to `SetFlag(flags & ~DF)` / `SetFlag(flags | DF)`.
                    flags.raw = v & (0x8D5 | VFLAG_DF);
                }
                RiscOp::VirtualBranch { cond } => {
                    if branch_taken_with_state(cond, &flags, &st.regs) {
                        // ??濚? src1(???됱쓤 ?? ?띠룄???call) ???裕?imm(??? x86 IP)
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
                RiscOp::VirtualIndirectCall | RiscOp::VirtualIndirectJump => {
                    let target = get_val(ins.src1, &st, flags.raw);
                    let Some(idx) = self.ip_map.as_ref().and_then(|m| m.get(&target)).copied()
                    else {
                        return Err(fault(
                            VmFaultKind::UnknownIndirectRoute { target },
                            &st,
                            flags.raw,
                        ));
                    };
                    vip = idx;
                    continue;
                }
                RiscOp::Halt => break,
                RiscOp::Trap => return Err(fault(VmFaultKind::Trap, &st, flags.raw)),
                RiscOp::VirtualRet => {
                    // P0-1: 가상 스택에서 복귀 주소를 pop. ip_map(가상화 블록)에 있으면
                    // VM 내부 복귀 분기, 없으면(빈 스택/네이티브 복귀) Halt 로 종료.
                    let ret_ip = match st.stack.pop() {
                        Some(v) => {
                            st.vsp = st.vsp.wrapping_add(8);
                            v
                        }
                        None => break, // 빈 스택 → VM 프로그램 종료
                    };
                    let idx = self.ip_map.as_ref().and_then(|m| m.get(&ret_ip)).copied();
                    match idx {
                        Some(i) => {
                            vip = i;
                            continue;
                        }
                        None => break, // 네이티브/미가상화 복귀 주소 → 종료
                    }
                }
                RiscOp::NativeCallBridge => {}
                RiscOp::SetNativeFpReturn { .. } => {}
                // ── P1 (③): VM→VM 콜 브릿지 — 서브 VM 실행 후 복귀 ──────────────
                // 호출자 상태(regs/temps/flags/vsp/stack)를 스냅샷하고, `imm`의
                // 프로그램 id 로 서브 VM을 **현재 regs/mem** 위에서 실행한다 (인자는
                // 레지스터로 전달 — x64 유사 컨벤션). 복귀 시 호출자 상태를 복원하되
                // RAX(vreg 0)만 서브 VM 반환값으로 대체하고, 서브 VM이 쓴 mem 을
                // 보존한다 (아웃-파라미터/스택/힙 반영). 서브 VM은 Halt 까지 실행.
                RiscOp::VmCallBridge => {
                    if let Some(sub) = self.sub_vm(ins.imm) {
                        let saved_regs = st.regs;
                        let saved_temps = st.temps;
                        let saved_flags = flags.raw;
                        let saved_vsp = st.vsp;
                        let saved_stack = std::mem::take(&mut st.stack);
                        let sub_state =
                            match sub.eval_state_impl(&saved_regs, &st.mem, memory_policy) {
                                Ok(state) => state,
                                Err(fault) => return Err(fault),
                            };
                        // 호출자 상태 복원 (스택 포인터·플래그·temps 유지).
                        st.regs = saved_regs;
                        st.temps = saved_temps;
                        flags.raw = saved_flags;
                        st.vsp = saved_vsp;
                        st.stack = saved_stack;
                        // 반환값 RAX + 서브 VM이 기록한 메모리 반영.
                        st.regs[0] = sub_state.regs[0];
                        st.mem = sub_state.mem;
                    }
                    // 등록되지 않은 id → 참조도 no-op (NativeCallBridge와 동일 계약).
                }
                // ???? P2: ?筌먦끇?????????戮?꽑 ?곌랜踰뤻뜮? ??⑥ろ뀰 ??????????????????????????????????????????????????????????????????
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
                    if let Err(kind) = div_wide_fallible(&mut st, divisor, signed, width, ins.dst) {
                        return Err(fault(kind, &st, flags.raw));
                    }
                }
                RiscOp::BSwap { width } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let res = if width == 4 {
                        ((a as u32).swap_bytes()) as u64
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
                        // ????戮곗젧 clz: (bits-1) - msb_index
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
                    // P1-6: CMPXCHG 는 ZF 뿐 아니라 CMP(acc - old) 의 모든 상태 플래그
                    // (CF/SF/OF/PF/AF) 를 set 한다 — `update_sub` 가 폭별 SUB 플래그를
                    // 계산하며 ZF 는 acc == old 일 때 1 (성공) 과 정확히 일치한다.
                    let _ = flags.update_sub(acc, old, width);
                    if old == acc {
                        mem_write(&mut st.mem, addr, width, newv & mask);
                    } else {
                        st.regs[0] = old;
                    }
                }
                RiscOp::LifetimeAcquire | RiscOp::LifetimeRelease => {}
                RiscOp::AtomicExchange { width } => {
                    // P0-4: 원자적 XCHG — old = [src1]; [src1] = dst; dst = old.
                    // 플래그 불변 (x86 XCHG 는 RFLAGS 무변경).
                    let addr = get_val(ins.src1, &st, flags.raw);
                    let old = mem_read(&st.mem, addr, width);
                    let reg_v = get_val(ins.dst, &st, flags.raw);
                    mem_write(&mut st.mem, addr, width, reg_v);
                    store(ins.dst, &mut st, old);
                }
                RiscOp::AtomicAdd { width } => {
                    // P0-4: 원자적 XADD — old = [src1]; new = old + src2 (폭별 플래그);
                    // [src1] = new; dst = old.
                    let addr = get_val(ins.src1, &st, flags.raw);
                    let addend = get_val(ins.src2, &st, flags.raw);
                    let old = mem_read(&st.mem, addr, width);
                    let mask = width_mask(width as u32 * 8);
                    let newv = flags.update_add(old, addend, width) & mask;
                    mem_write(&mut st.mem, addr, width, newv);
                    store(ins.dst, &mut st, old & mask);
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
                    store(ins.dst, &mut st, res);
                }
                RiscOp::FloatToInt {
                    src_bits,
                    dst_bits,
                    truncate,
                } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let f = if src_bits == 4 {
                        f32::from_bits(a as u32) as f64
                    } else {
                        f64::from_bits(a)
                    };
                    let res = cvt_f64_int(f, dst_bits, truncate);
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
                // ── P1 (②): packed SSE — XMM 슬롯 주소 피연산자, 16바이트 메모리 I/O ──
                // x86 packed 정수 연산은 RFLAGS 를 바꾸지 않으므로 flags 무변경.
                // (참조: `PADDQ` = 2× 64-bit add → 64-bit add 로 분해하면 lane 간
                //  캐리 전파가 생겨 틀리므로 전용 op 로 요소 경계를 지킨다.)
                RiscOp::PackedMove => {
                    let src = get_val(ins.src1, &st, flags.raw);
                    let dst = get_val(ins.dst, &st, flags.raw);
                    let mut bytes = [0u8; 16];
                    for i in 0..16 {
                        bytes[i] = st
                            .mem
                            .get(&src.wrapping_add(i as u64))
                            .copied()
                            .unwrap_or(0);
                    }
                    for i in 0..16 {
                        st.mem.insert(dst.wrapping_add(i as u64), bytes[i]);
                    }
                }
                RiscOp::PackedAdd { elem_width, lanes } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let d = get_val(ins.dst, &st, flags.raw);
                    let mask = mask_for_width(elem_width);
                    for lane in 0..lanes as u64 {
                        let off = lane * elem_width as u64;
                        let ea = mem_read(&st.mem, a.wrapping_add(off), elem_width);
                        let eb = mem_read(&st.mem, b.wrapping_add(off), elem_width);
                        let er = ea.wrapping_add(eb) & mask;
                        mem_write(&mut st.mem, d.wrapping_add(off), elem_width, er);
                    }
                }
                RiscOp::PackedSub { elem_width, lanes } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let d = get_val(ins.dst, &st, flags.raw);
                    let mask = mask_for_width(elem_width);
                    for lane in 0..lanes as u64 {
                        let off = lane * elem_width as u64;
                        let ea = mem_read(&st.mem, a.wrapping_add(off), elem_width);
                        let eb = mem_read(&st.mem, b.wrapping_add(off), elem_width);
                        let er = ea.wrapping_sub(eb) & mask;
                        mem_write(&mut st.mem, d.wrapping_add(off), elem_width, er);
                    }
                }
                RiscOp::PackedXor => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let d = get_val(ins.dst, &st, flags.raw);
                    for i in 0..16u64 {
                        let ba = st.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                        let bb = st.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                        st.mem.insert(d.wrapping_add(i), ba ^ bb);
                    }
                }
                RiscOp::PackedAnd => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let d = get_val(ins.dst, &st, flags.raw);
                    for i in 0..16u64 {
                        let ba = st.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                        let bb = st.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                        st.mem.insert(d.wrapping_add(i), ba & bb);
                    }
                }
                RiscOp::PackedOr => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let d = get_val(ins.dst, &st, flags.raw);
                    for i in 0..16u64 {
                        let ba = st.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                        let bb = st.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                        st.mem.insert(d.wrapping_add(i), ba | bb);
                    }
                }
                RiscOp::PackedAndNot => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let d = get_val(ins.dst, &st, flags.raw);
                    for i in 0..16u64 {
                        let ba = st.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                        let bb = st.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                        st.mem.insert(d.wrapping_add(i), ba & !bb);
                    }
                }
                RiscOp::PackedCmpEq { elem_width, lanes } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let d = get_val(ins.dst, &st, flags.raw);
                    let all_ones = (0..elem_width).fold(0u64, |acc, _| (acc << 8) | 0xFF);
                    for lane in 0..lanes as u64 {
                        let off = lane * elem_width as u64;
                        let ea = mem_read(&st.mem, a.wrapping_add(off), elem_width);
                        let eb = mem_read(&st.mem, b.wrapping_add(off), elem_width);
                        let er = if ea == eb { all_ones } else { 0 };
                        mem_write(&mut st.mem, d.wrapping_add(off), elem_width, er);
                    }
                }
                RiscOp::PackedCmpGt { elem_width, lanes } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let d = get_val(ins.dst, &st, flags.raw);
                    let all_ones = mask_for_width(elem_width);
                    let shift = 64 - elem_width as u32 * 8;
                    for lane in 0..lanes as u64 {
                        let off = lane * elem_width as u64;
                        let ea = mem_read(&st.mem, a.wrapping_add(off), elem_width);
                        let eb = mem_read(&st.mem, b.wrapping_add(off), elem_width);
                        let er = if ((ea << shift) as i64) > ((eb << shift) as i64) {
                            all_ones
                        } else {
                            0
                        };
                        mem_write(&mut st.mem, d.wrapping_add(off), elem_width, er);
                    }
                }
                RiscOp::PackedUnpack { elem_width, high } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let b = get_val(ins.src2, &st, flags.raw);
                    let d = get_val(ins.dst, &st, flags.raw);
                    let mut av = [0u8; 16];
                    let mut bv = [0u8; 16];
                    for i in 0..16u64 {
                        av[i as usize] = st.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                        bv[i as usize] = st.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                    }
                    let half = 8usize / elem_width as usize;
                    let base = if high { 8 } else { 0 };
                    for lane in 0..half {
                        for j in 0..elem_width as usize {
                            st.mem.insert(
                                d + (2 * lane * elem_width as usize + j) as u64,
                                av[base + lane * elem_width as usize + j],
                            );
                            st.mem.insert(
                                d + ((2 * lane + 1) * elem_width as usize + j) as u64,
                                bv[base + lane * elem_width as usize + j],
                            );
                        }
                    }
                }
                RiscOp::PackedShiftRightQ => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let d = get_val(ins.dst, &st, flags.raw);
                    let count = get_val(ins.src2, &st, flags.raw);
                    let lo = mem_read(&st.mem, a, 8);
                    let hi = mem_read(&st.mem, a.wrapping_add(8), 8);
                    mem_write(&mut st.mem, d, 8, if count >= 64 { 0 } else { lo >> count });
                    mem_write(
                        &mut st.mem,
                        d.wrapping_add(8),
                        8,
                        if count >= 64 { 0 } else { hi >> count },
                    );
                }
                RiscOp::PackedShuffle { low_words } => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let d = get_val(ins.dst, &st, flags.raw);
                    let control = get_val(ins.src2, &st, flags.raw) as u8;
                    let mut src = [0u8; 16];
                    for i in 0..16u64 {
                        src[i as usize] = st.mem.get(&(a + i)).copied().unwrap_or(0);
                    }
                    if low_words {
                        for i in 0..16u64 {
                            st.mem.insert(d + i, src[i as usize]);
                        }
                        for lane in 0..4usize {
                            let sel = ((control >> (lane * 2)) & 3) as usize;
                            for j in 0..2usize {
                                st.mem.insert(d + (lane * 2 + j) as u64, src[sel * 2 + j]);
                            }
                        }
                    } else {
                        for lane in 0..4usize {
                            let sel = ((control >> (lane * 2)) & 3) as usize;
                            for j in 0..4usize {
                                st.mem.insert(d + (lane * 4 + j) as u64, src[sel * 4 + j]);
                            }
                        }
                    }
                }
                RiscOp::DoubleShiftLeft { width } => {
                    let bits = width as u32 * 8;
                    let count = (get_val(ins.src2, &st, flags.raw) & 0x3F) as u32;
                    if count != 0 {
                        let mask = mask_for_width(width);
                        let old = get_val(ins.dst, &st, flags.raw) & mask;
                        let src = get_val(ins.src1, &st, flags.raw) & mask;
                        let res = ((old << count) | (src >> (bits - count))) & mask;
                        let cf = (old >> (bits - count)) & 1;
                        flags.raw &= !(VFLAG_CF | VFLAG_OF | VFLAG_SF | VFLAG_ZF | VFLAG_PF);
                        flags.raw |= cf;
                        if res == 0 {
                            flags.raw |= VFLAG_ZF;
                        }
                        if res & (1u64 << (bits - 1)) != 0 {
                            flags.raw |= VFLAG_SF;
                        }
                        flags.set_parity(res);
                        if count == 1 && (((res >> (bits - 1)) ^ cf) & 1) != 0 {
                            flags.raw |= VFLAG_OF;
                        }
                        store(ins.dst, &mut st, res);
                    }
                }
                RiscOp::BitTest {
                    width,
                    modify,
                    memory,
                } => {
                    let index = get_val(ins.src2, &st, flags.raw);
                    let bits = width as u64 * 8;
                    let bit = index % bits;
                    let old = if memory {
                        let base = get_val(ins.src1, &st, flags.raw);
                        mem_read(
                            &st.mem,
                            base.wrapping_add((index / bits) * width as u64),
                            width,
                        )
                    } else {
                        get_val(ins.src1, &st, flags.raw) & mask_for_width(width)
                    };
                    flags.raw = (flags.raw & !VFLAG_CF) | ((old >> bit) & 1);
                    if modify != 0 {
                        let newv = if modify == 1 {
                            old & !(1u64 << bit)
                        } else {
                            old | (1u64 << bit)
                        };
                        if memory {
                            let base = get_val(ins.src1, &st, flags.raw);
                            mem_write(
                                &mut st.mem,
                                base.wrapping_add((index / bits) * width as u64),
                                width,
                                newv,
                            );
                        } else {
                            store(ins.dst, &mut st, newv);
                        }
                    }
                }
                RiscOp::PackedMovMaskBytes | RiscOp::PackedMovMaskPs => {
                    let a = get_val(ins.src1, &st, flags.raw);
                    let mut mask = 0u64;
                    if ins.op == RiscOp::PackedMovMaskBytes {
                        for i in 0..16u64 {
                            mask |= ((mem_read(&st.mem, a + i, 1) >> 7) & 1) << i;
                        }
                    } else {
                        for i in 0..4u64 {
                            mask |= ((mem_read(&st.mem, a + i * 4, 4) >> 31) & 1) << i;
                        }
                    }
                    store(ins.dst, &mut st, mask);
                }
                RiscOp::PackedInsertWord => {
                    let d = get_val(ins.dst, &st, flags.raw);
                    let value = get_val(ins.src1, &st, flags.raw);
                    let lane = get_val(ins.src2, &st, flags.raw) & 7;
                    mem_write(&mut st.mem, d + lane * 2, 2, value);
                }
                RiscOp::CpuId => {
                    st.regs[0] = 0;
                    st.regs[3] = 0;
                    st.regs[1] = 0;
                    st.regs[2] = 0;
                }
                RiscOp::XGetBv => {
                    st.regs[0] = 0;
                    st.regs[2] = 0;
                }
                RiscOp::ReadSegmentBase { .. } => store(ins.dst, &mut st, 0),
            }
            vip += 1;
        }

        st.flags = flags.raw;
        Ok(st)
    }

    /// ??濡る룎??micro-instruction??(??寃? ??⑤객臾?????????덈뺄??類ｋ펲. `eval_state_impl`
    /// ????op ?곌랜梨뜻룇??**???됰뎄???????*???띠럾??筌뤾쑬?????? ??⑤객臾???됀???嶺뚣볦굣???????
    /// (`eval_state_encrypted`)?띠럾? ????貫???"handler"???????類ｋ펲. 嶺뚢뼰維甕????裕?筌?
    /// ???롪퍔?δ빳????源딅뭵???띠룆踰???類ｋ펲.
    fn exec_one(
        &self,
        ins: &MicroInstr,
        st: &mut RiscEvalState,
        flags: &mut VirtualFlags,
    ) -> ExecResult {
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

        match ins.op {
            RiscOp::Nor => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let res = !(a | b);
                flags.update_logic64(res);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::Mov => {
                let a = get_val(ins.src1, st, flags.raw);
                store(ins.dst, st, a);
                ExecResult::Next
            }
            RiscOp::AddWithCarry => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let (res, _cout) = flags.update_add64(a, b, ins.imm);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::ShiftRight => {
                let a = get_val(ins.src1, st, flags.raw);
                let cnt = get_val(ins.src2, st, flags.raw) & 63;
                let res = if cnt == 0 { a } else { a >> cnt };
                if cnt != 0 {
                    flags.update_logic64(res);
                    if (a >> (cnt - 1)) & 1 != 0 {
                        flags.raw |= VFLAG_CF;
                    }
                }
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::ArithmeticShiftRight => {
                let a = get_val(ins.src1, st, flags.raw);
                let cnt = get_val(ins.src2, st, flags.raw) & 63;
                let res = if cnt == 0 {
                    a
                } else {
                    ((a as i64) >> cnt) as u64
                };
                if cnt != 0 {
                    flags.update_logic64(res);
                    if (a >> (cnt - 1)) & 1 != 0 {
                        flags.raw |= VFLAG_CF;
                    }
                }
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::ShiftLeft => {
                let a = get_val(ins.src1, st, flags.raw);
                let cnt = get_val(ins.src2, st, flags.raw) & 63;
                let res = if cnt == 0 { a } else { a << cnt };
                if cnt != 0 {
                    flags.update_logic64(res);
                    if (a >> (64 - cnt)) & 1 != 0 {
                        flags.raw |= VFLAG_CF;
                    }
                }
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::RotateLeft { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let c = get_val(ins.src2, st, flags.raw);
                let res = flags.update_rol(a, c, width);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::Add { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let res = flags.update_add(a, b, width);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::SubWithBorrow { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let res = flags.update_sub(a, b, width);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::Adc { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let res = flags.update_adc(a, b, width);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::Sbb { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let res = flags.update_sbb(a, b, width);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::Inc { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let res = flags.update_inc(a, width);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::Dec { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let res = flags.update_dec(a, width);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::Not { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let res = !a & crate::vm::risc::flags::mask_for_width(width);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::VirtualPush => {
                let v = get_val(ins.src1, st, flags.raw);
                st.vsp = st.vsp.wrapping_sub(8);
                st.stack.push(v);
                ExecResult::Next
            }
            RiscOp::VirtualPop => {
                if let Some(v) = st.stack.pop() {
                    st.vsp = st.vsp.wrapping_add(8);
                    store(ins.dst, st, v);
                }
                ExecResult::Next
            }
            RiscOp::MemoryRead { width } => {
                let addr = get_val(ins.src1, st, flags.raw);
                let val = mem_read(&st.mem, addr, width);
                store(ins.dst, st, val);
                ExecResult::Next
            }
            RiscOp::MemoryWrite { width } => {
                let addr = get_val(ins.src1, st, flags.raw);
                let val = get_val(ins.src2, st, flags.raw);
                mem_write(&mut st.mem, addr, width, val);
                ExecResult::Next
            }
            RiscOp::SetFlag => {
                let v = get_val(ins.src1, st, flags.raw);
                flags.raw = v & (0x8D5 | VFLAG_DF);
                ExecResult::Next
            }
            RiscOp::VirtualBranch { cond } => {
                if branch_taken_with_state(cond, flags, &st.regs) {
                    let target = match ins.src1 {
                        Some(op) => get_val(Some(op), st, flags.raw),
                        None => ins.imm,
                    };
                    let idx = self
                        .ip_map
                        .as_ref()
                        .and_then(|m| m.get(&target))
                        .copied()
                        .unwrap_or(target as usize);
                    return ExecResult::Jump(idx);
                }
                ExecResult::Next
            }
            RiscOp::VirtualIndirectCall | RiscOp::VirtualIndirectJump => {
                let target = get_val(ins.src1, st, flags.raw);
                match self.ip_map.as_ref().and_then(|m| m.get(&target)).copied() {
                    Some(idx) => ExecResult::Jump(idx),
                    None => ExecResult::Halt,
                }
            }
            RiscOp::Halt | RiscOp::Trap => ExecResult::Halt,
            RiscOp::VirtualRet => {
                // P0-1: pop → ip_map(가상화) 복귀 분기, 없으면(빈 스택/네이티브) 종료.
                let ret_ip = match st.stack.pop() {
                    Some(v) => {
                        st.vsp = st.vsp.wrapping_add(8);
                        v
                    }
                    None => return ExecResult::Halt,
                };
                let idx = self.ip_map.as_ref().and_then(|m| m.get(&ret_ip)).copied();
                match idx {
                    Some(i) => ExecResult::Jump(i),
                    None => ExecResult::Halt,
                }
            }
            RiscOp::NativeCallBridge => ExecResult::Next,
            RiscOp::SetNativeFpReturn { .. } => ExecResult::Next,
            RiscOp::VmCallBridge => ExecResult::Next,
            RiscOp::Multiply { signed, width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                mul_wide(st, flags, a, b, signed, width, ins.dst);
                ExecResult::Next
            }
            RiscOp::MultiplyLow { signed, width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                mul_low(st, flags, a, b, signed, width, ins.dst);
                ExecResult::Next
            }
            RiscOp::Divide { signed, width } => {
                let divisor = get_val(ins.src1, st, flags.raw);
                div_wide(st, divisor, signed, width, ins.dst);
                ExecResult::Next
            }
            RiscOp::BSwap { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let res = if width == 4 {
                    ((a as u32).swap_bytes()) as u64
                } else {
                    a.swap_bytes()
                };
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::BitScanForward => {
                let a = get_val(ins.src1, st, flags.raw);
                if a == 0 {
                    flags.set_zf(true);
                    store(ins.dst, st, 0);
                } else {
                    flags.set_zf(false);
                    store(ins.dst, st, a.trailing_zeros() as u64);
                }
                ExecResult::Next
            }
            RiscOp::BitScanReverse => {
                let a = get_val(ins.src1, st, flags.raw);
                if a == 0 {
                    flags.set_zf(true);
                    store(ins.dst, st, 0);
                } else {
                    flags.set_zf(false);
                    store(ins.dst, st, 63 - a.leading_zeros() as u64);
                }
                ExecResult::Next
            }
            RiscOp::CountTrailingZeros { width } => {
                let bits = width as u32 * 8;
                let mask = width_mask(bits);
                let s = get_val(ins.src1, st, flags.raw) & mask;
                if s == 0 {
                    flags.set_cf(true);
                    flags.set_zf(true);
                    store(ins.dst, st, bits as u64);
                } else {
                    flags.set_cf(false);
                    let c = s.trailing_zeros() as u64;
                    flags.set_zf(c == 0);
                    store(ins.dst, st, c);
                }
                ExecResult::Next
            }
            RiscOp::CountLeadingZeros { width } => {
                let bits = width as u32 * 8;
                let mask = width_mask(bits);
                let s = get_val(ins.src1, st, flags.raw) & mask;
                if s == 0 {
                    flags.set_cf(true);
                    flags.set_zf(true);
                    store(ins.dst, st, bits as u64);
                } else {
                    flags.set_cf(false);
                    let msb = 63 - s.leading_zeros() as u64;
                    let c = (bits as u64 - 1) - msb;
                    flags.set_zf(c == 0);
                    store(ins.dst, st, c);
                }
                ExecResult::Next
            }
            RiscOp::PopCount => {
                let a = get_val(ins.src1, st, flags.raw);
                let res = a.count_ones() as u64;
                flags.update_logic64(res);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::Setcc { cond } => {
                let v = branch_taken_with_state(cond, flags, &st.regs);
                store(ins.dst, st, v as u64);
                ExecResult::Next
            }
            RiscOp::ConditionalMove { cond } => {
                if branch_taken_with_state(cond, flags, &st.regs) {
                    let v = get_val(ins.src1, st, flags.raw);
                    store(ins.dst, st, v);
                }
                ExecResult::Next
            }
            RiscOp::CompareExchange { width } => {
                let addr = get_val(ins.src1, st, flags.raw);
                let newv = get_val(ins.src2, st, flags.raw);
                let bits = width as u32 * 8;
                let mask = width_mask(bits);
                let acc = st.regs[0] & mask;
                let old = mem_read(&st.mem, addr, width) & mask;
                // P1-6: CMP(acc - old) 의 전체 상태 플래그 (ZF 포함) — update_sub.
                let _ = flags.update_sub(acc, old, width);
                if old == acc {
                    mem_write(&mut st.mem, addr, width, newv & mask);
                } else {
                    st.regs[0] = old;
                }
                ExecResult::Next
            }
            RiscOp::LifetimeAcquire | RiscOp::LifetimeRelease => ExecResult::Next,
            RiscOp::AtomicExchange { width } => {
                // P0-4: 원자적 XCHG — old = [src1]; [src1] = dst; dst = old. 플래그 불변.
                let addr = get_val(ins.src1, st, flags.raw);
                let old = mem_read(&st.mem, addr, width);
                let reg_v = get_val(ins.dst, st, flags.raw);
                mem_write(&mut st.mem, addr, width, reg_v);
                store(ins.dst, st, old);
                ExecResult::Next
            }
            RiscOp::AtomicAdd { width } => {
                // P0-4: 원자적 XADD — old = [src1]; new = old + src2 (폭별 플래그);
                // [src1] = new; dst = old.
                let addr = get_val(ins.src1, st, flags.raw);
                let addend = get_val(ins.src2, st, flags.raw);
                let old = mem_read(&st.mem, addr, width);
                let mask = width_mask(width as u32 * 8);
                let newv = flags.update_add(old, addend, width) & mask;
                mem_write(&mut st.mem, addr, width, newv);
                store(ins.dst, st, old & mask);
                ExecResult::Next
            }
            RiscOp::FloatAdd { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let res = if width == 4 {
                    (f32::from_bits(a as u32) + f32::from_bits(b as u32)).to_bits() as u64
                } else {
                    (f64::from_bits(a) + f64::from_bits(b)).to_bits()
                };
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::FloatSub { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let res = if width == 4 {
                    (f32::from_bits(a as u32) - f32::from_bits(b as u32)).to_bits() as u64
                } else {
                    (f64::from_bits(a) - f64::from_bits(b)).to_bits()
                };
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::FloatMul { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let res = if width == 4 {
                    (f32::from_bits(a as u32) * f32::from_bits(b as u32)).to_bits() as u64
                } else {
                    (f64::from_bits(a) * f64::from_bits(b)).to_bits()
                };
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::FloatDiv { width } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let res = if width == 4 {
                    (f32::from_bits(a as u32) / f32::from_bits(b as u32)).to_bits() as u64
                } else {
                    (f64::from_bits(a) / f64::from_bits(b)).to_bits()
                };
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::IntToFloat { src_bits, dst_bits } => {
                let a = get_val(ins.src1, st, flags.raw);
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
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::FloatToInt {
                src_bits,
                dst_bits,
                truncate,
            } => {
                let a = get_val(ins.src1, st, flags.raw);
                let f = if src_bits == 4 {
                    f32::from_bits(a as u32) as f64
                } else {
                    f64::from_bits(a)
                };
                let res = cvt_f64_int(f, dst_bits, truncate);
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::FloatToFloat { src_bits, dst_bits } => {
                let a = get_val(ins.src1, st, flags.raw);
                let res = if src_bits == 4 {
                    (f32::from_bits(a as u32) as f64).to_bits()
                } else {
                    (f64::from_bits(a) as f32).to_bits() as u64
                };
                store(ins.dst, st, res);
                ExecResult::Next
            }
            // ── P1 (②): packed SSE — 슬롯 주소 피연산자, 16바이트 메모리 I/O, 플래그 불변 ──
            RiscOp::PackedMove => {
                let src = get_val(ins.src1, st, flags.raw);
                let dst = get_val(ins.dst, st, flags.raw);
                let mut bytes = [0u8; 16];
                for i in 0..16u64 {
                    bytes[i as usize] = st.mem.get(&src.wrapping_add(i)).copied().unwrap_or(0);
                }
                for i in 0..16u64 {
                    st.mem.insert(dst.wrapping_add(i), bytes[i as usize]);
                }
                ExecResult::Next
            }
            RiscOp::PackedAdd { elem_width, lanes } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let d = get_val(ins.dst, st, flags.raw);
                let mask = mask_for_width(elem_width);
                for lane in 0..lanes as u64 {
                    let off = lane * elem_width as u64;
                    let ea = mem_read(&st.mem, a.wrapping_add(off), elem_width);
                    let eb = mem_read(&st.mem, b.wrapping_add(off), elem_width);
                    mem_write(
                        &mut st.mem,
                        d.wrapping_add(off),
                        elem_width,
                        ea.wrapping_add(eb) & mask,
                    );
                }
                ExecResult::Next
            }
            RiscOp::PackedSub { elem_width, lanes } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let d = get_val(ins.dst, st, flags.raw);
                let mask = mask_for_width(elem_width);
                for lane in 0..lanes as u64 {
                    let off = lane * elem_width as u64;
                    let ea = mem_read(&st.mem, a.wrapping_add(off), elem_width);
                    let eb = mem_read(&st.mem, b.wrapping_add(off), elem_width);
                    mem_write(
                        &mut st.mem,
                        d.wrapping_add(off),
                        elem_width,
                        ea.wrapping_sub(eb) & mask,
                    );
                }
                ExecResult::Next
            }
            RiscOp::PackedXor => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let d = get_val(ins.dst, st, flags.raw);
                for i in 0..16u64 {
                    let ba = st.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                    let bb = st.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                    st.mem.insert(d.wrapping_add(i), ba ^ bb);
                }
                ExecResult::Next
            }
            RiscOp::PackedAnd => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let d = get_val(ins.dst, st, flags.raw);
                for i in 0..16u64 {
                    let ba = st.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                    let bb = st.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                    st.mem.insert(d.wrapping_add(i), ba & bb);
                }
                ExecResult::Next
            }
            RiscOp::PackedOr => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let d = get_val(ins.dst, st, flags.raw);
                for i in 0..16u64 {
                    let ba = st.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                    let bb = st.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                    st.mem.insert(d.wrapping_add(i), ba | bb);
                }
                ExecResult::Next
            }
            RiscOp::PackedAndNot => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let d = get_val(ins.dst, st, flags.raw);
                for i in 0..16u64 {
                    let ba = st.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                    let bb = st.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                    st.mem.insert(d.wrapping_add(i), ba & !bb);
                }
                ExecResult::Next
            }
            RiscOp::PackedCmpEq { elem_width, lanes } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let d = get_val(ins.dst, st, flags.raw);
                let all_ones = (0..elem_width).fold(0u64, |acc, _| (acc << 8) | 0xFF);
                for lane in 0..lanes as u64 {
                    let off = lane * elem_width as u64;
                    let ea = mem_read(&st.mem, a.wrapping_add(off), elem_width);
                    let eb = mem_read(&st.mem, b.wrapping_add(off), elem_width);
                    let er = if ea == eb { all_ones } else { 0 };
                    mem_write(&mut st.mem, d.wrapping_add(off), elem_width, er);
                }
                ExecResult::Next
            }
            RiscOp::PackedCmpGt { elem_width, lanes } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let d = get_val(ins.dst, st, flags.raw);
                let all_ones = mask_for_width(elem_width);
                let shift = 64 - elem_width as u32 * 8;
                for lane in 0..lanes as u64 {
                    let off = lane * elem_width as u64;
                    let ea = mem_read(&st.mem, a.wrapping_add(off), elem_width);
                    let eb = mem_read(&st.mem, b.wrapping_add(off), elem_width);
                    let er = if ((ea << shift) as i64) > ((eb << shift) as i64) {
                        all_ones
                    } else {
                        0
                    };
                    mem_write(&mut st.mem, d.wrapping_add(off), elem_width, er);
                }
                ExecResult::Next
            }
            RiscOp::PackedUnpack { elem_width, high } => {
                let a = get_val(ins.src1, st, flags.raw);
                let b = get_val(ins.src2, st, flags.raw);
                let d = get_val(ins.dst, st, flags.raw);
                let mut av = [0u8; 16];
                let mut bv = [0u8; 16];
                for i in 0..16u64 {
                    av[i as usize] = st.mem.get(&a.wrapping_add(i)).copied().unwrap_or(0);
                    bv[i as usize] = st.mem.get(&b.wrapping_add(i)).copied().unwrap_or(0);
                }
                let half = 8usize / elem_width as usize;
                let base = if high { 8 } else { 0 };
                for lane in 0..half {
                    for j in 0..elem_width as usize {
                        st.mem.insert(
                            d + (2 * lane * elem_width as usize + j) as u64,
                            av[base + lane * elem_width as usize + j],
                        );
                        st.mem.insert(
                            d + ((2 * lane + 1) * elem_width as usize + j) as u64,
                            bv[base + lane * elem_width as usize + j],
                        );
                    }
                }
                ExecResult::Next
            }
            RiscOp::PackedShiftRightQ => {
                let a = get_val(ins.src1, st, flags.raw);
                let d = get_val(ins.dst, st, flags.raw);
                let count = get_val(ins.src2, st, flags.raw);
                let lo = mem_read(&st.mem, a, 8);
                let hi = mem_read(&st.mem, a.wrapping_add(8), 8);
                mem_write(&mut st.mem, d, 8, if count >= 64 { 0 } else { lo >> count });
                mem_write(
                    &mut st.mem,
                    d.wrapping_add(8),
                    8,
                    if count >= 64 { 0 } else { hi >> count },
                );
                ExecResult::Next
            }
            RiscOp::PackedShuffle { low_words } => {
                let a = get_val(ins.src1, st, flags.raw);
                let d = get_val(ins.dst, st, flags.raw);
                let control = get_val(ins.src2, st, flags.raw) as u8;
                let mut src = [0u8; 16];
                for i in 0..16u64 {
                    src[i as usize] = st.mem.get(&(a + i)).copied().unwrap_or(0);
                }
                if low_words {
                    for i in 0..16u64 {
                        st.mem.insert(d + i, src[i as usize]);
                    }
                    for lane in 0..4usize {
                        let sel = ((control >> (lane * 2)) & 3) as usize;
                        for j in 0..2usize {
                            st.mem.insert(d + (lane * 2 + j) as u64, src[sel * 2 + j]);
                        }
                    }
                } else {
                    for lane in 0..4usize {
                        let sel = ((control >> (lane * 2)) & 3) as usize;
                        for j in 0..4usize {
                            st.mem.insert(d + (lane * 4 + j) as u64, src[sel * 4 + j]);
                        }
                    }
                }
                ExecResult::Next
            }
            RiscOp::DoubleShiftLeft { width } => {
                let bits = width as u32 * 8;
                let count = (get_val(ins.src2, st, flags.raw) & 0x3F) as u32;
                if count != 0 {
                    let mask = mask_for_width(width);
                    let old = get_val(ins.dst, st, flags.raw) & mask;
                    let src = get_val(ins.src1, st, flags.raw) & mask;
                    let res = ((old << count) | (src >> (bits - count))) & mask;
                    let cf = (old >> (bits - count)) & 1;
                    flags.raw &= !(VFLAG_CF | VFLAG_OF | VFLAG_SF | VFLAG_ZF | VFLAG_PF);
                    flags.raw |= cf;
                    if res == 0 {
                        flags.raw |= VFLAG_ZF;
                    }
                    if res & (1u64 << (bits - 1)) != 0 {
                        flags.raw |= VFLAG_SF;
                    }
                    flags.set_parity(res);
                    if count == 1 && (((res >> (bits - 1)) ^ cf) & 1) != 0 {
                        flags.raw |= VFLAG_OF;
                    }
                    store(ins.dst, st, res);
                }
                ExecResult::Next
            }
            RiscOp::BitTest {
                width,
                modify,
                memory,
            } => {
                let index = get_val(ins.src2, st, flags.raw);
                let bits = width as u64 * 8;
                let bit = index % bits;
                let old = if memory {
                    let base = get_val(ins.src1, st, flags.raw);
                    mem_read(
                        &st.mem,
                        base.wrapping_add((index / bits) * width as u64),
                        width,
                    )
                } else {
                    get_val(ins.src1, st, flags.raw) & mask_for_width(width)
                };
                flags.raw = (flags.raw & !VFLAG_CF) | ((old >> bit) & 1);
                if modify != 0 {
                    let newv = if modify == 1 {
                        old & !(1u64 << bit)
                    } else {
                        old | (1u64 << bit)
                    };
                    if memory {
                        let base = get_val(ins.src1, st, flags.raw);
                        mem_write(
                            &mut st.mem,
                            base.wrapping_add((index / bits) * width as u64),
                            width,
                            newv,
                        );
                    } else {
                        store(ins.dst, st, newv);
                    }
                }
                ExecResult::Next
            }
            RiscOp::PackedMovMaskBytes | RiscOp::PackedMovMaskPs => {
                let a = get_val(ins.src1, st, flags.raw);
                let mut mask = 0u64;
                if ins.op == RiscOp::PackedMovMaskBytes {
                    for i in 0..16u64 {
                        mask |= ((mem_read(&st.mem, a + i, 1) >> 7) & 1) << i;
                    }
                } else {
                    for i in 0..4u64 {
                        mask |= ((mem_read(&st.mem, a + i * 4, 4) >> 31) & 1) << i;
                    }
                }
                store(ins.dst, st, mask);
                ExecResult::Next
            }
            RiscOp::PackedInsertWord => {
                let d = get_val(ins.dst, st, flags.raw);
                let value = get_val(ins.src1, st, flags.raw);
                let lane = get_val(ins.src2, st, flags.raw) & 7;
                mem_write(&mut st.mem, d + lane * 2, 2, value);
                ExecResult::Next
            }
            RiscOp::CpuId => {
                st.regs[0] = 0;
                st.regs[3] = 0;
                st.regs[1] = 0;
                st.regs[2] = 0;
                ExecResult::Next
            }
            RiscOp::XGetBv => {
                st.regs[0] = 0;
                st.regs[2] = 0;
                ExecResult::Next
            }
            RiscOp::ReadSegmentBase { .. } => {
                store(ins.dst, st, 0);
                ExecResult::Next
            }
        }
    }

    /// ??⑤객臾???됀???嶺뚣볦굣???????(?熬곣뫗逾??7 ??Themida-class ??⑤객臾???됀???.
    ///
    /// ?띠럾?????????꾩댉 ???逾??flags ??**?β뼯?뉐퐲????댁Ŧ XOR ??됀???븐뼔彛?嶺??т빳?* ??????겶?
    /// ??micro-instruction("handler")????얜∥?????곌랜踰???????ｌ뫒亦???**???깅쾳 ??*??
    /// ????筌뤿굞???類ｋ펲. ???노츎 ???덈뺄??嶺뚮ㅏ援앲??됱춹??덈펲 ???뺢퀡?녽??熬곣뫗異???????⑤객臾??嶺뚮ㅏ援앲??????
    /// ??疫???됀???븐뼔??????덈펲. ?롪퍒??????筌??濡ル펲 ??`eval_state_encrypted` ??嶺뚣끉裕뉏펺?
    /// ??⑤객臾????寃?`eval_state` ?? ?꾩룇瑗띈キ????源딅뭵??怨룻뒍 ???? 嶺뚢뼰維甕????裕?筌? ?띠룆踰???類ｋ펲.
    /// (嶺뚮∥???꾨뎨??熬곣뫁???濡ル츎 ?롪퍓????嶺뚮∥???꾨뎨??醫꾩쾵?????됀????뺢퀡?????????戮곕뇶.)
    pub fn eval_state_encrypted(&self, init_regs: &[u64; 16], seed_key: u64) -> RiscEvalState {
        let mut st = RiscEvalState::default();
        st.regs = *init_regs;
        st.mem = HashMap::new();
        let mut flags = VirtualFlags::default();

        // ?β뼯?뉐퐲??????댟?(LCG ????????꾩룆???筌뤾쑵留???????繞벿븐뫅?????됰뎄???繹먭퍒遊?.
        let step = |k: u64| {
            k.wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0x1405_7B7E_F767_814F)
        };
        let xors = |st: &mut RiscEvalState, flags: &mut VirtualFlags, k: u64| {
            for r in st.regs.iter_mut() {
                *r ^= k;
            }
            for t in st.temps.iter_mut() {
                *t ^= k;
            }
            flags.raw ^= k;
        };

        let mut key = seed_key;
        xors(&mut st, &mut flags, key); // ?貫?껆뵳???⑤객臾????됀?????⑤객臾뜹슖???戮곗굚

        let mut vip = 0usize;
        loop {
            if vip >= self.instrs.len() {
                break;
            }
            // handler: ?熬곣뫗?????댁Ŧ ?곌랜踰???????ｌ뫒亦?
            xors(&mut st, &mut flags, key);
            let res = self.exec_one(&self.instrs[vip], &mut st, &mut flags);
            // 嶺뚮ㅏ援앲????????⑤객臾????疫???됀??? ???깅쾳 ???댁Ŧ ????筌뤿굞??
            let nk = step(key);
            xors(&mut st, &mut flags, nk);
            key = nk;
            match res {
                ExecResult::Next => vip += 1,
                ExecResult::Jump(idx) => vip = idx,
                ExecResult::Halt => break,
            }
        }
        // 嶺뚮씭??嶺뚮씭留???뿉???됀???됀?????댁Ŧ ?곌랜踰???됀????寃???⑤객臾???꾩룇瑗??
        xors(&mut st, &mut flags, key);
        st.flags = flags.raw;
        st
    }
}

#[cfg(test)]
mod checked_memory_tests {
    use super::*;

    fn region(start: u64, len: u64, readable: bool, writable: bool) -> MemoryRegion {
        MemoryRegion {
            start,
            len,
            readable,
            writable,
        }
    }

    #[test]
    fn checked_read_preserves_fault_context_and_does_not_commit_destination() {
        let instrs = vec![
            MicroInstr::new(RiscOp::MemoryRead { width: 8 })
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::VReg(0)),
            MicroInstr::new(RiscOp::Halt),
        ];
        let program = RiscProgram::with_ip_map(instrs, HashMap::from([(0x401000, 0)]));
        let policy = MemoryPolicy::new(vec![region(0x2000, 8, true, false)]);
        let mut regs = [0u64; 16];
        regs[0] = 0x2004; // the full eight-byte read crosses the region end
        regs[1] = 0xfeed_face;

        let fault = program
            .try_eval_state_with_mem_policy(&regs, HashMap::new(), &policy)
            .unwrap_err();

        assert_eq!(
            fault.kind,
            VmFaultKind::MemoryAccess {
                address: 0x2004,
                width: 8,
                write: false,
            }
        );
        assert_eq!(fault.vip, 0);
        assert_eq!(fault.guest_rip, Some(0x401000));
        assert_eq!(fault.state.regs[1], 0xfeed_face);
    }

    #[test]
    fn checked_write_requires_permission_and_does_not_mutate_memory() {
        let program = RiscProgram::new(vec![
            MicroInstr::new(RiscOp::MemoryWrite { width: 4 })
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
            MicroInstr::new(RiscOp::Halt),
        ]);
        let policy = MemoryPolicy::new(vec![region(0x3000, 4, true, false)]);
        let mut regs = [0u64; 16];
        regs[0] = 0x3000;
        regs[1] = 0x1122_3344;
        let seed = HashMap::from([(0x3000, 0xaa)]);

        let fault = program
            .try_eval_state_with_mem_policy(&regs, seed.clone(), &policy)
            .unwrap_err();

        assert_eq!(
            fault.kind,
            VmFaultKind::MemoryAccess {
                address: 0x3000,
                width: 4,
                write: true,
            }
        );
        assert_eq!(fault.state.mem, seed);
    }

    #[test]
    fn checked_access_keeps_sparse_zero_fill_inside_permitted_region() {
        let program = RiscProgram::new(vec![
            MicroInstr::new(RiscOp::MemoryRead { width: 4 })
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::VReg(0)),
            MicroInstr::new(RiscOp::Halt),
        ]);
        let policy = MemoryPolicy::new(vec![region(0x5000, 0x10, true, true)]);
        let mut regs = [0u64; 16];
        regs[0] = 0x5004;

        let state = program
            .try_eval_state_with_mem_policy(&regs, HashMap::new(), &policy)
            .unwrap();
        assert_eq!(state.regs[1], 0);
    }

    #[test]
    fn legacy_memory_api_remains_unrestricted() {
        let program = RiscProgram::new(vec![
            MicroInstr::new(RiscOp::MemoryWrite { width: 1 })
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
            MicroInstr::new(RiscOp::Halt),
        ]);
        let mut regs = [0u64; 16];
        regs[0] = u64::MAX;
        regs[1] = 0x5a;
        let state = program
            .try_eval_state_with_mem(&regs, HashMap::new())
            .unwrap();
        assert_eq!(state.mem.get(&u64::MAX), Some(&0x5a));
    }
}
