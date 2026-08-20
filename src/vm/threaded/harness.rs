// ==============================================================================
// BTG - Commercial-Grade VM: Direct-Threaded Native Execution Harness (T1-4)
// ==============================================================================
// ??모듈?�?`DirectThreadedNativeRunner`가 ?�성???�들??머신코드�??�제 RWX
// arena??배치?�고, VM ?�태 버퍼(?��??�터/?�시/?�래�?VSP/?�택)�??�결????
// ?�리모픽 RISC ?�로그램??**?�이?�브�??�행**?�는 ?�네?�다.
//
// 검�?목표 (T1-4 "?�이?�브?�VM ?�태 ?�이 ?�행 검�?):
//   ?�이?�브 ?�행 결과 ?�태 == `RiscProgram::eval_state` 참조 ?�태
//   (?��??�터/?�시/?�래�?VSP/?�택 깊이 ?��? ?�치).
//
// ?�계:
//   * �?RISC 마이?�로 ?�산?�?"?�문??specialized) 블록"?�로 컴파?�된??
//     ?�연?�자 종류/?��??�터 ?�덱??즉시값이 코드???�점??베이?�되므�?
//     ?��??�에 바이?�코?��? ?�코?�하지 ?�고 ?�태 버퍼?�서 값을 직접 ?�어?�다.
//     (VReg/Temp/Imm64/Vsp/Vflags ??R10/R11, 결과??dst ?�롯???�??
//   * 블록 ?�이?�는 기존 `DirectTailEmitter`??직접 ?�레?�드 tail-dispatch
//     (opcode fetch ??key XOR ??[R15+rax*8] ?�이�??�덱????jmp)�?그�?�?
//     ?�결?�다. 명령마다 고유 opcode(?�번)�?부?�하�??�이블이 �?주소�?가리킨??
//   * ?�세 ABI: R10=src1/결과, R11=src2, R12=VIP, R13=?�택 ?�인??
//     R14=?? R15=?�들???�이�?베이?? RDX=?�태 버퍼 베이???�역 ?��?).
//
// ?�래�?처리: NOR/?�프?�는 `test`�?CF/OF=0·ZF/SF 갱신(update_logic64 ?�일),
// ADD??`add`+`adc`???�드?�어 CF/ZF/SF/OF ?�용(update_add64 ?�일).
// PF/AF??참조가 갱신?��? ?�으므�?보존?�다(CF|ZF|SF|OF = 0x8C1 마스??.
// ==============================================================================

use super::direct_tail::DirectTailEmitter;
use crate::vm::arena::Arena;
use crate::vm::poly::PolymorphicDecoder;
use crate::vm::risc::{BranchCondition, MicroInstr, MicroOperand, RiscEvalState, RiscOp, RiscProgram};
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, InstructionBlock, Register};

pub(crate) use layout::{OFF_BRANCH_MAP, OFF_BYTECODE, OFF_CODE, OFF_STACK_BASE, OFF_STATE, OFF_TABLE, ARENA_SIZE, REGS_OFF, TEMPS_OFF, FLAGS_OFF, VSP_OFF, STATE_END, FLAG_MASK};

mod branch_helper;
mod emit_block;
mod layout;
#[cfg(test)]
mod harness_tests;

/// 직접 ?�레?�드 ?�이?�브 VM ?�네??
pub struct NativeVmHarness {
    pub arena: Arena,
    pub code_off: usize,
    pub state_off: usize,
    pub bytecode_off: usize,
    pub stack_off: usize,
    pub state_base: u64,
    pub stack_base: u64,
}

impl NativeVmHarness {

    /// RISC ?�로그램???�문???�이?�브 블록?�로 컴파?�해 arena??배치?�다.
    pub fn compile(prog: &RiscProgram, key: u8) -> Result<Self> {
        Self::compile_with_mba(prog, key, 0)
    }

    /// P1 (④+다양화): `mba_prob`(0..=100) 확률로 `Add{width:8}` 핸들러를 MBA 시퀀스로
    /// emit 한다. 기본값 0 = 기존 `add r10, r11` 직렬 emit (회귀 무변경).
    ///
    /// `key`(빌드 키)는 `diversity_seed`로 전달되어, 같은 프로그램도 빌드마다
    /// 다른 블록 집합이 MBA(variant 0/1)로 emit 된다 (handler 코드 다형화).
    pub fn compile_with_mba(prog: &RiscProgram, key: u8, mba_prob: u32) -> Result<Self> {
        let mut arena = Arena::new(ARENA_SIZE)?;
        let state_base = (arena.base + OFF_STATE) as u64;
        let stack_base = (arena.base + OFF_STACK_BASE) as u64;
        let table_base = (arena.base + OFF_TABLE) as u64;
        let bytecode_base = (arena.base + OFF_BYTECODE) as u64;
        let code_base = (arena.base + OFF_CODE) as u64;
        let branch_map_va = (arena.base + OFF_BRANCH_MAP) as u64;

        // 1) 분기 �? (?�스-IP ???�덱?? ?�렬??(ip, index) u64 ??배열 (?�적 분기??.
        let branch_pairs: Vec<(u64, u64)> = {
            let mut v: Vec<(u64, u64)> = prog
                .ip_map()
                .map(|m| m.iter().map(|(&ip, &idx)| (ip, idx as u64)).collect())
                .unwrap_or_default();
            v.sort_unstable_by_key(|&(ip, _)| ip);
            v
        };

        // 2) ?�적 분기 ?��??�전 ?�석: VirtualBranch �?src1 ???�거??Imm64 ??�?
        //    Some(idx) = 목표 블록 ?�덱?? None = ?�적(?��????�석 ?�요).
        let mut static_targets: Vec<Option<u64>> = Vec::with_capacity(prog.instrs.len());
        for ins in &prog.instrs {
            let t = match ins.op {
                RiscOp::VirtualBranch { .. } => match ins.src1 {
                    None => Some(prog.resolve_target(ins.imm) as u64),
                    Some(MicroOperand::Imm64(v)) => Some(prog.resolve_target(v) as u64),
                    _ => None, // VReg/Temp/Vsp/Vflags ???�적
                },
                _ => Some(0), // 비분�???미사??
            };
            static_targets.push(t);
        }
        let needs_helper = static_targets.iter().any(|t| t.is_none());

        // 3) 코드�?블록 ?�위�??�성.
        //    �?블록?�?op ?�연?�자가 코드???�점??베이?�된?? VirtualBranch ??
        //    branch-free 방식(?�래�???setcc ???�덱???��? 계산 ???�이�??�프)?�로
        //    분기?�고, ?�적 ?�깃�? ?�캔 ?�퍼�??�출?�다.
        let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(prog.instrs.len());
        let mut helper_code: Option<Vec<u8>> = None;

        if needs_helper {
            helper_code = Some(Self::emit_branch_lookup_helper(branch_map_va, table_base)?);
        }

        // ?�트�?(helper ?�음 배치 ??call ?��? 주소�??�기 ?�해 helper 먼�? 배치).
        let entry_start = OFF_CODE + helper_code.as_ref().map_or(0, |h| h.len());
        let entry_va = (arena.base + entry_start) as u64;
        let mut entry_instrs = Vec::new();
        entry_instrs.push(Instruction::with1(Code::Push_r64, Register::R12).map_err(|e| anyhow!("{e}"))?);
        entry_instrs.push(Instruction::with1(Code::Push_r64, Register::R13).map_err(|e| anyhow!("{e}"))?);
        entry_instrs.push(Instruction::with1(Code::Push_r64, Register::R14).map_err(|e| anyhow!("{e}"))?);
        entry_instrs.push(Instruction::with1(Code::Push_r64, Register::R15).map_err(|e| anyhow!("{e}"))?);
        entry_instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::R12, bytecode_base).map_err(|e| anyhow!("{e}"))?);
        entry_instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::R13, stack_base).map_err(|e| anyhow!("{e}"))?);
        entry_instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::R14, key as u64).map_err(|e| anyhow!("{e}"))?);
        entry_instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::R15, table_base).map_err(|e| anyhow!("{e}"))?);
        entry_instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::RDX, state_base).map_err(|e| anyhow!("{e}"))?);
        DirectTailEmitter::emit_tail_dispatch(&mut entry_instrs)?;
        let entry = DirectTailEmitter::assemble(entry_instrs, entry_va)?;

        let helper_va = helper_code.as_ref().map(|_| (arena.base + OFF_CODE) as u64);
        // 1�? ?�스?�럭??리스???�성 (?�셈�??�님 ???�이?�웃 ??.
        let mut block_lists: Vec<Vec<Instruction>> = Vec::with_capacity(prog.instrs.len());
        for (i, ins) in prog.instrs.iter().enumerate() {
            let mut instrs = Vec::new();
            Self::emit_block(
                ins,
                &mut instrs,
                state_base,
                bytecode_base,
                i as u64,
                static_targets[i],
                helper_va,
                mba_prob,
                key as u64,
            )?;
            if !matches!(ins.op, RiscOp::Halt | RiscOp::VirtualRet) {
                DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
            } else {
                // HALT / VIRTUAL_RET(최상위): Win64 callee-saved ?��??�터(R12~R15) 복원 ??ret.
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R15).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R14).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R13).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R12).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with(Code::Retnq));
            }
            block_lists.push(instrs);
        }

        // 2�? 길이 측정 (base 0) ???�이?�웃 계산 (?�출 ?��? 주소�??�한 ?�제 base VA).
        let mut block_lengths = Vec::with_capacity(block_lists.len());
        for lst in &block_lists {
            block_lengths.push(DirectTailEmitter::assemble(lst.clone(), arena.base as u64)?.len());
        }
        let helper_len = helper_code.as_ref().map_or(0, |h| h.len());
        let mut seg_off = OFF_CODE + helper_len + entry.len();
        let mut block_vas: Vec<u64> = Vec::with_capacity(block_lists.len());
        for len in &block_lengths {
            block_vas.push((arena.base + seg_off) as u64);
            seg_off += len;
        }
        let fallback_va = (arena.base + seg_off) as u64;

        // 3�? ?�제 base VA �??�어?�블.
        let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(block_lists.len());
        for (lst, &va) in block_lists.iter().zip(block_vas.iter()) {
            blocks.push(DirectTailEmitter::assemble(lst.clone(), va)?);
        }

        // fallback 블록 (?�이블에???�용?��? ?��? opcode ???�순 ret)
        let fallback = DirectTailEmitter::assemble(vec![Instruction::with(Code::Retnq)], code_base)?;

        // 4) 배치: [helper][entry][block0..blockN][fallback]
        let mut layout = Vec::new();
        if let Some(h) = &helper_code {
            layout.push(h.clone());
        }
        layout.push(entry);
        for b in &blocks {
            layout.push(b.clone());
        }
        layout.push(fallback);

        // 5) ?�스?�치 ?�이�? table[명령?�번(?�크립트 opcode)] = 블록 VA.
        let mut table = vec![fallback_va as u64; 256];
        for (i, va) in block_vas.iter().enumerate() {
            table[i] = *va;
        }

        // 6) 바이?�코?? bytecode[i] = (i as u8) ^ key  ?? tail-dispatch가 key XOR�?복원.
        let mut bytecode = vec![0u8; blocks.len()];
        for (i, b) in bytecode.iter_mut().enumerate() {
            *b = (i as u8) ^ key;
        }

        // TEMP DEBUG DUMP
        if std::env::var("BTG_DUMP_HARNESS").is_ok() {
            let mut s = String::new();
            let mut off = OFF_CODE;
            for seg in &layout {
                s.push_str(&format!("-- seg @ 0x{:x} ({} bytes) --\n", off, seg.len()));
                let mut dec = iced_x86::Decoder::with_ip(64, seg, (arena.base + off) as u64, iced_x86::DecoderOptions::NONE);
                while dec.can_decode() {
                    let ins = dec.decode();
                    s.push_str(&format!("0x{:08x}  {:?}\n", ins.ip(), ins));
                }
                off += seg.len();
            }
            let _ = std::fs::write("C:\\Users\\uzoki\\Desktop\\asdfsadfecwecc\\_harness_dump.txt", s);
        }
        // 7) arena??복사.
        {
            let buf = arena.bytes();
            let mut off = OFF_CODE;
            for seg in &layout {
                buf[off..off + seg.len()].copy_from_slice(seg);
                off += seg.len();
            }
            buf[OFF_TABLE..OFF_TABLE + 256 * 8]
                .copy_from_slice(&bytemuck_le(&table));
            buf[OFF_BYTECODE..OFF_BYTECODE + bytecode.len()].copy_from_slice(&bytecode);
            buf[OFF_STATE..OFF_STATE + STATE_END].fill(0);
            // 분기 �? (ip, index) u64 ??배열.
            for (k, &(ip, idx)) in branch_pairs.iter().enumerate() {
                let o = OFF_BRANCH_MAP + k * 16;
                buf[o..o + 8].copy_from_slice(&ip.to_le_bytes());
                buf[o + 8..o + 16].copy_from_slice(&idx.to_le_bytes());
            }
            // ?�택 ?�역 ?�리??(OFF_STACK_BASE부??8KiB ?�래�?
            buf[OFF_STACK_BASE - 0x2000..OFF_STACK_BASE].fill(0);
        }

        let code_off = entry_va as usize - arena.base;
        Ok(Self {
            arena,
            code_off,
            state_off: OFF_STATE,
            bytecode_off: OFF_BYTECODE,
            stack_off: OFF_STACK_BASE,
            state_base,
            stack_base,
        })
    }

    /// `init_regs`�??�태 버퍼???�고 ?�이?�브 ?�행 ??최종 ?�태�??�려준??
    pub fn run(&mut self, init_regs: &[u64; 16]) -> Result<RiscEvalState> {
        // 초기 ?��??�터 ?�팅 + ?�태 버퍼 ?�초기화.
        {
            let buf = self.arena.bytes();
            buf[self.state_off..self.state_off + STATE_END].fill(0);
            for (i, v) in init_regs.iter().enumerate() {
                buf[self.state_off + REGS_OFF + i * 8..self.state_off + REGS_OFF + i * 8 + 8]
                    .copy_from_slice(&v.to_le_bytes());
            }
        }
        self.arena.call(self.code_off);

        // 최종 ?�태 ?�기.
        let buf = self.arena.bytes();
        let s = self.state_off;
        let mut st = RiscEvalState::default();
        for i in 0..16 {
            st.regs[i] = u64::from_le_bytes(buf[s + REGS_OFF + i * 8..s + REGS_OFF + i * 8 + 8].try_into().unwrap());
        }
        for i in 0..8 {
            st.temps[i] = u64::from_le_bytes(buf[s + TEMPS_OFF + i * 8..s + TEMPS_OFF + i * 8 + 8].try_into().unwrap());
        }
        st.flags = u64::from_le_bytes(buf[s + FLAGS_OFF..s + FLAGS_OFF + 8].try_into().unwrap());
        st.vsp = u64::from_le_bytes(buf[s + VSP_OFF..s + VSP_OFF + 8].try_into().unwrap());

        // ?�택 ?�구?? 참조 stack vec??push ?�서 그�?�? �?push??[stack_base-8].
        // ?��? push 개수 = (0 - vsp) / 8 (vsp < 0 ????.
        let pending = if (st.vsp as i64) < 0 {
            (-(st.vsp as i64) as u64) / 8
        } else {
            0
        };
        let mut stack = Vec::new();
        for k in 0..pending as usize {
            let off = self.stack_off as usize - (k + 1) * 8;
            let v = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            stack.push(v);
        }
        st.stack = stack;
        Ok(st)
    }
}

/// u64 벡터�?little-endian 바이?�로.
fn bytemuck_le(v: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 8);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

/// RISC ?�로그램???�이?�브�??�행?�고 참조 ?�태(`eval_state`)�??�려받는 ?�의 ?�수.
pub fn run_native_risc(prog: &RiscProgram, init_regs: &[u64; 16]) -> Result<RiscEvalState> {
    let mut vm = NativeVmHarness::compile(prog, 0x5A)?;
    vm.run(init_regs)
}

/// ?�전???�치?�야 ?�다.
pub fn run_native_poly(bytecode: &[u8], seed: u64, init_regs: &[u64; 16]) -> Result<RiscEvalState> {
    let mut dec = PolymorphicDecoder::new(seed);
    let prog = dec.decode(bytecode)?;
    // ?�이?�브 블록?�??�연?�자가 코드???�점??베이?�되므�? ?�스?�치 ?�는 ?�의 �?
    let mut vm = NativeVmHarness::compile(&prog, 0x5A)?;
    vm.run(init_regs)
}