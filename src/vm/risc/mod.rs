pub mod desynth;
pub mod flags;
pub mod lifter;
pub mod opcodes;
pub mod opt;

use std::collections::HashMap;

pub use desynth::RiscDesynthesizer;
pub use flags::{VFLAG_CF, VFLAG_DF};
pub use flags::VirtualFlags;
pub use lifter::RiscLifter;
pub use opcodes::{BranchCondition, MicroInstr, MicroOperand, RiscOp};
pub use opt::RiscOptimizer;

/// RISC ?띠럾????熬곣뫁夷?윜諛몄굡?????쳜??????
#[derive(Debug, Clone)]
pub struct RiscProgram {
    pub instrs: Vec<MicroInstr>,
    /// ??ルㅎ臾?????裕?IP ???筌뤾퍓???嶺? `VirtualBranch`????濚???? x86 IP)??
    /// `instrs` ?뺢껴?㎬땻?????戮곗굚 ?筌뤾퍓????댁Ŧ ?곌떠???臾먰돵 `eval_state`?띠럾? ?釉뚯뫅?깃퀋紐????덈뺄???우벟 ??類ｋ펲.
    /// `None`?????`VirtualBranch.imm`??嶺뚯쉳????筌뤾퍓????댁Ŧ ??怨댄맍??類ｋ펲(??ル쪇援????덈뺄 ?곌랜???.
    ip_map: Option<HashMap<u64, usize>>,
}

/// `RiscProgram::eval_state` ???덈뺄 ?롪퍒???앹뿉?????사뛾?녿즴???띠럾????誘⑹굣????⑤객臾?
/// ?筌뤿굛??熬곣뱿遊??`PolymorphicInterpreter`)????**嶺뚢뼰維甕?differential) ?롪틵?嶺?*???熬곥굥由?
/// 嶺뚯쉳?????띠럾??繞③뇡?嶺뚣볦굣????⑤객臾????ш껑????? T1-4 ?リ옇?? ??ｌ뫒??
///
/// * `regs`  ??16???띠럾????뺢퀡?????????꾩댉
/// * `temps` ??8?????꾩씩??瑜귣뭵 ?熬곣뫖六???????꾩댉
/// * `flags` ???띠럾???RFLAGS (VFLAG_* ?????
/// * `vsp`   ???띠럾??????꾨Ц ?????(?熬곣뫁?뗥슖??繹먮냱?? ?꾩룆??????關留????덈뒆??
/// * `stack` ???띠럾??????꾨Ц (index 0 = 嶺뚣끉裕? ?낅슣??? 嶺???= 嶺뚣끉裕???낅슣???嶺뚣끉裕??push)
/// * `mem`   ???띠럾???嶺뚮∥???꾨뎨?(?낅슣??????꾩룆???? `MemoryRead`/`MemoryWrite` ????
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

/// ??micro-instruction ???덈뺄????戮?꽑 ??????롪퍒???
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExecResult {
    /// ???깅쾳 嶺뚮ㅏ援앲???怨쀬Ŧ 嶺뚯쉳?듸쭛?
    Next,
    /// ?釉뚯뫅????vip ????濚??筌뤾퍓????댁Ŧ ???깆젧.
    Jump(usize),
    /// Halt ???熬곣뫁夷?윜諛몄굡????リ턁筌?
    Halt,
}

impl RiscProgram {
    pub fn new(instrs: Vec<MicroInstr>) -> Self {
        Self {
            instrs,
            ip_map: None,
        }
    }

    /// ?洹먮뿫???? ?リ옇?▽빳?????裕?IP ???筌뤾퍓???嶺뚮씭踰???띠럾?嶺??熬곣뫁夷?윜諛몄굡???嶺뚮씭??キ??
    /// (?釉뚯뫅????濚밸Þ??????덈뺄 ?띠럾??繞③뇡?VIP ?筌뤾퍓????댁Ŧ ??怨댄맍???얄뵛 ?熬곥굥留?)
    pub fn with_ip_map(instrs: Vec<MicroInstr>, ip_map: HashMap<u64, usize>) -> Self {
        Self {
            instrs,
            ip_map: Some(ip_map),
        }
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
        self.eval_state_impl(init_regs, &HashMap::new())
    }

    /// 嶺뚮∥???꾨뎨?? ?????貫?껆뵳??됀????⑤객臾?????嶺뚣볦굣????????깅턄?????덈뺄.
    /// (嶺뚮∥???꾨뎨???源낆뿼??⑥ъ겱 嶺뚢뼰維甕????裕?筌뤾쑬????貫?껆뵳?`.data`/`.bss`???낅슣?????얄뵛 ?熬곥굥留?)
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
                    let res = if cnt == 0 { a } else { ((a as i64) >> cnt) as u64 };
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
                RiscOp::Halt => break,
                RiscOp::NativeCallBridge => {}
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
                    div_wide(&mut st, divisor, signed, width, ins.dst);
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
            }
            vip += 1;
        }

        st.flags = flags.raw;
        st
    }

    /// ??濡る룎??micro-instruction??(??寃? ??⑤객臾?????????덈뺄??類ｋ펲. `eval_state_impl`
    /// ????op ?곌랜梨뜻룇??**???됰뎄???????*???띠럾??筌뤾쑬?????? ??⑤객臾???됀???嶺뚣볦굣???????
    /// (`eval_state_encrypted`)?띠럾? ????貫???"handler"???????類ｋ펲. 嶺뚢뼰維甕????裕?筌?
    /// ???롪퍔?δ빳????源딅뭵???띠룆踰???類ｋ펲.
    fn exec_one(&self, ins: &MicroInstr, st: &mut RiscEvalState, flags: &mut VirtualFlags) -> ExecResult {
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
                let res = if cnt == 0 { a } else { ((a as i64) >> cnt) as u64 };
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
            RiscOp::Halt => ExecResult::Halt,
            RiscOp::NativeCallBridge => ExecResult::Next,
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
                if old == acc {
                    mem_write(&mut st.mem, addr, width, newv & mask);
                    flags.set_zf(true);
                } else {
                    st.regs[0] = old;
                    flags.set_zf(false);
                }
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
                let iv = if src_bits == 4 { (a as i32) as i64 } else { a as i64 };
                let res = if dst_bits == 4 {
                    (iv as f32).to_bits() as u64
                } else {
                    (iv as f64).to_bits()
                };
                store(ins.dst, st, res);
                ExecResult::Next
            }
            RiscOp::FloatToInt { src_bits, dst_bits, truncate } => {
                let a = get_val(ins.src1, st, flags.raw);
                let f = if src_bits == 4 { f32::from_bits(a as u32) as f64 } else { f64::from_bits(a) };
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
        let step = |k: u64| k.wrapping_mul(0x5851_F42D_4C95_7F2D).wrapping_add(0x1405_7B7E_F767_814F);
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

/// ?브퀗?쀦뤃??釉뚯뫅?깃꼈泥? 濾곌쑬梨???? ??? (x86 ?브퀗?쀦뤃??袁⑤?獄??????.
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

/// ?釉뚯뫅????? ??`CounterZero`(?곸궠?????リ옇?↑?????????꾩댉 ??⑤객臾뜻뤆?쎛 ?熬곣뫗????????⑤객臾띄뭐癒?뒩? ?熬곣뫀堉?
fn branch_taken_with_state(cond: BranchCondition, flags: &VirtualFlags, regs: &[u64; 16]) -> bool {
    if let BranchCondition::CounterZero(width) = cond {
        // Jcxz(2)/Jecxz(4)/Jrcxz(8): RCX(reg[1])????瑜곷쭊 width ?꾩룆???筌? 0?筌?
        let mask = match width {
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            _ => u64::MAX,
        };
        return (regs[1] & mask) == 0;
    }
    branch_taken(cond, flags)
}

/// ?洹???븐뼔???`width`?꾩룆????嶺뚮∥???꾨뎨???袁ⓥ뵛. 亦껋꼶?뉒뵳???낅슣????0??怨쀬Ŧ ???た??
fn mem_read(mem: &HashMap<u64, u8>, addr: u64, width: u8) -> u64 {
    let mut v = 0u64;
    for i in 0..width {
        if let Some(&b) = mem.get(&addr.wrapping_add(i as u64)) {
            v |= (b as u64) << (i as u64 * 8);
        }
    }
    v
}

/// ?洹???븐뼔???`width`?꾩룆????嶺뚮∥???꾨뎨???⑤슢??
fn mem_write(mem: &mut HashMap<u64, u8>, addr: u64, width: u8, val: u64) {
    for i in 0..width {
        mem.insert(addr.wrapping_add(i as u64), (val >> (i as u64 * 8)) as u8);
    }
}

// ???? P2: ?筌먦끇????????곌랜踰뤻뜮? ??⑥ろ뀰 嶺뚣볦굣????????????????????????????????????????????????????????????????????????????????????????

/// `width`?꾩룆?????????????嶺뚮씭????
fn width_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// round-to-nearest-even (x86 MXCSR ?リ옇???RC) ???筌먐쇰꼪??half-way ???롪퍔???嶺뚯쉸鍮??嶺뚯옕????뿉??꾩룇瑗?湲븍뎨?
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

/// x86 CVT(T)Sx2SI reference semantics (must match the bytecode interpreter's
/// `cvt_f64_i32` in interp/xmm.rs). NaN / 筌??/ out-of-range produce the
/// "integer indefinite": 0x8000_0000 for a 32-bit destination, and
/// 0x8000_0000_0000_0000 for a 64-bit destination. Rust's `as i64` saturates
/// instead (NaN??, +???⑷샵i64::MAX), so it CANNOT be used directly.
fn cvt_f64_int(f: f64, dst_bits: u8, truncate: bool) -> u64 {
    let r = if truncate {
        f.trunc()
    } else {
        round_ties_even(f) as f64
    };
    match dst_bits {
        4 => {
            if !r.is_finite() || r < -2147483648.0 || r >= 2147483648.0 {
                0x8000_0000
            } else {
                r as i32 as u32 as u64
            }
        }
        _ => {
            if !r.is_finite() || r < -9_223_372_036_854_775_808.0 || r >= 9_223_372_036_854_775_808.0 {
                0x8000_0000_0000_0000
            } else {
                r as i64 as u64
            }
        }
    }
}

/// `bits` ???????`v`??i128 ???遊붋???筌먦끉??(bits < 128).
fn sign_extend_i128(v: u128, bits: u32) -> i128 {
    let shift = 128 - bits;
    ((v << shift) as i128) >> shift
}

/// 1-??源낆뿼??⑥ъ겱 MUL/IMUL 嶺뚣볦굣?? low ??dst, high ??RDX(????2) ???裕?AX(??1).
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
        // AX = AL鸚룸삺/m8 ??AH(high 8???????RAX ?????8..15 ??
        store_dst(st, dst, (low & 0xFF) | ((high & 0xFF) << 8));
    } else {
        store_dst(st, dst, low);
        st.regs[2] = high; // RDX
    }
}

/// 2/3-??源낆뿼??⑥ъ겱 IMUL 嶺뚣볦굣?? dst = low(src1鸚룸삻rc2), RDX 亦껋꼶?뉒뵳寃쎌뿉?
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

/// DIV/IDIV 嶺뚣볦굣?? ??源놁젷??= RDX:RAX(???? ??1 ?? AX), ??戮?빢 = divisor,
/// 嶺???dst(RAX), ??濡?룫嶺뚯솘? ??RDX. (??戮?빢 0 ???裕?嶺????댁뮅???夷??x86 #DE ??嶺뚣볦굣???????
/// ?롪퍒???0 ??怨쀬Ŧ ???た??????????怨뺣룛.)
fn div_wide(st: &mut RiscEvalState, divisor: u64, signed: bool, width: u8, dst: Option<MicroOperand>) {
    let bits = width as u32 * 8;
    let mask = width_mask(bits);
    // ??1(8?????DIV/IDIV)?? AX(reg0 low16)?띠럾? ??源놁젷????RDX 亦껋꼶梨룡쾮??
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
        // #DE ??嶺뚣볦굣???リ옇???泥?(0). ??1 ?? AX(dst) ?筌먐븍Ф.
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
        // Rust ?筌먦끇????濡ル빟??? 0 嶺뚯옕????뿉????덈펺 ??IDIV ?? ???됰뎄.
        let (q, r) = (d / s, d % s);
        (q as u128, r as u128)
    } else {
        (dividend / dv, dividend % dv)
    };
    if width == 1 {
        // AL = 嶺? AH = ??濡?룫嶺뚯솘? ??AX(dst).
        let ax = ((r as u64) & 0xFF) << 8 | ((q as u64) & 0xFF);
        store_dst(st, dst, ax);
    } else {
        store_dst(st, dst, (q as u64) & mask);
        st.regs[2] = (r as u64) & mask;
    }
}

/// dst(Some VReg/Temp) ??????eval_state ??`store` ???餓???? ???됰뎄.
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

    /// ?熬곣뫗逾??7: ??⑤객臾???됀???嶺뚣볦굣??????リ옇?? ??寃?eval_state ?? ???됰뎄??嶺뚣끉裕뉏펺???⑤객臾??
    /// ???????? ?롪틵?嶺뚯빘鍮쒒뇡??(?β뼯?뉐퐲????댁Ŧ ??됀???븐뼔彛?vreg/flags ??handler(exec_one) ???고뱺??類ㅼ떳
    /// ?곌랜踰???됀???嶺뚮ㅄ維??. ??類ｌ몓 ??類ｊ덧 ??????類ｌ몓 ?熬곣뫁夷?윜諛몄굡?????놁졑??怨쀬Ŧ 嶺뚢뼰維甕??筌먦끉逾?
    #[test]
    fn eval_state_encrypted_matches_plaintext() {
        use rand::rngs::StdRng;
        use rand::{Rng, RngCore, SeedableRng};
        let mut rng = StdRng::seed_from_u64(0x51A7E_5EED);

        for trial in 0..10 {
            let a = rng.next_u64();
            let b = rng.next_u64();
            let mut d = RiscDesynthesizer::new();
            d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(a), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(b), MicroOperand::Imm64(0));
            d.emit_add(MicroOperand::VReg(2), MicroOperand::VReg(0), MicroOperand::VReg(1));
            d.emit_xor(MicroOperand::VReg(3), MicroOperand::VReg(0), MicroOperand::VReg(1));
            d.instrs.push(
                MicroInstr::new(RiscOp::ShiftLeft)
                    .with_dst(MicroOperand::VReg(4))
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::VReg(1)),
            );
            d.emit_neg(MicroOperand::VReg(5), MicroOperand::VReg(0));
            d.emit_sub(MicroOperand::VReg(6), MicroOperand::VReg(0), MicroOperand::VReg(1));
            d.instrs.push(
                MicroInstr::new(RiscOp::BSwap { width: 8 })
                    .with_dst(MicroOperand::VReg(7))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::PopCount)
                    .with_dst(MicroOperand::VReg(8))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::CountTrailingZeros { width: 8 })
                    .with_dst(MicroOperand::VReg(9))
                    .with_src1(MicroOperand::VReg(0)),
            );
            d.emit_sub(MicroOperand::Temp(0), MicroOperand::VReg(0), MicroOperand::VReg(0));
            d.instrs.push(
                MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::Zero })
                    .with_dst(MicroOperand::VReg(10))
                    .with_src1(MicroOperand::VReg(1)),
            );
            d.instrs.push(
                MicroInstr::new(RiscOp::MultiplyLow { signed: false, width: 8 })
                    .with_dst(MicroOperand::VReg(11))
                    .with_src1(MicroOperand::VReg(0))
                    .with_src2(MicroOperand::VReg(1)),
            );
            // push/pop (stack) ??branch paths are covered by the existing tests
            d.emit_push(MicroOperand::VReg(2));
            d.emit_pop(MicroOperand::VReg(12));
            d.instrs.push(MicroInstr::new(RiscOp::Halt));

            let prog = RiscProgram::new(d.instrs);
            let regs = [0u64; 16];
            let plain = prog.eval_state(&regs);
            for _ in 0..4 {
                let key = rng.next_u64();
                let enc = prog.eval_state_encrypted(&regs, key);
                assert_eq!(enc.regs, plain.regs, "trial {trial} key 0x{key:X}: regs mismatch");
                assert_eq!(enc.flags, plain.flags, "trial {trial} key 0x{key:X}: flags 0x{:X} != 0x{:X}", enc.flags, plain.flags);
                assert_eq!(enc.vsp, plain.vsp, "trial {trial}: vsp mismatch");
                assert_eq!(enc.stack, plain.stack, "trial {trial}: stack mismatch");
            }
        }
    }

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
        // 嶺뚮ㅄ維獄?嶺뚳퐣瑗?怨⑹쾸???op???브퀗?ч뜮???嶺뚣볦굣????????깅턄??? ?筌먐쇰꼪?????덈뺄??濡ル츎嶺뚯솘? ?롪틵?嶺?
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
        // push R3 (???꾨Ц 1??, pop R4
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

    #[test]
    fn test_cvt_f64_int_x86_indefinite() {
        // 32-bit dst: NaN / 筌??/ out-of-range -> 0x8000_0000 (x86 indefinite),
        // NOT Rust's saturating cast (NaN->0, +??>i64::MAX).
        assert_eq!(cvt_f64_int(f64::NAN, 4, true), 0x8000_0000);
        assert_eq!(cvt_f64_int(f64::INFINITY, 4, true), 0x8000_0000);
        assert_eq!(cvt_f64_int(f64::NEG_INFINITY, 4, true), 0x8000_0000);
        assert_eq!(cvt_f64_int(2147483648.0, 4, true), 0x8000_0000); // 2^31
        assert_eq!(cvt_f64_int(-2147483649.0, 4, true), 0x8000_0000);
        assert_eq!(cvt_f64_int(-1.9, 4, true), (-1i32 as u32) as u64); // trunc toward 0
        assert_eq!(cvt_f64_int(1.9, 4, true), 1);
        assert_eq!(cvt_f64_int(2.5, 4, false), 2); // ties-to-even
        assert_eq!(cvt_f64_int(3.5, 4, false), 4); // ties-to-even
        // 64-bit dst: indefinite is 0x8000_0000_0000_0000.
        assert_eq!(cvt_f64_int(f64::NAN, 8, true), 0x8000_0000_0000_0000);
        assert_eq!(cvt_f64_int(9_223_372_036_854_775_808.0, 8, true), 0x8000_0000_0000_0000);
        assert_eq!(cvt_f64_int(-9_223_372_036_854_775_809.0, 8, true), 0x8000_0000_0000_0000);
        assert_eq!(cvt_f64_int(-1.9, 8, true), (-1i64) as u64);
    }
}
