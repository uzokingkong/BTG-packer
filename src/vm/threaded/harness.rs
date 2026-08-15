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

// ?�?�?arena ?�이?�웃 ?�프???�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?
const OFF_CODE: usize = 0x1000;    // ?�행 코드 (?�트�?+ 블록??
const OFF_TABLE: usize = 0x8000;   // ?�스?�치 ?�이�?(256 x u64)
const OFF_BYTECODE: usize = 0x9000;// opcode ?�트�?(고정??XOR)
const OFF_STATE: usize = 0xA000;   // VM ?�태 버퍼
const OFF_STACK_BASE: usize = 0xE000; // 가???�택 최상??(?�래�??�장, 8KiB)
const OFF_BRANCH_MAP: usize = 0xB000; // 분기 ?�석 �?((ip, index) u64 ?? ???�적 분기??
const ARENA_SIZE: usize = 0x40000;

// ?�?�??�태 버퍼 ?�이?�웃 (OFF_STATE 기�?) ?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?�?
const REGS_OFF: usize = 0x000;   // [u64;16]
const TEMPS_OFF: usize = 0x080;  // [u64;8]
const FLAGS_OFF: usize = 0x0C0;  // u64
const VSP_OFF: usize = 0x0C8;    // u64
const STATE_END: usize = 0x100;

// 참조가 갱신?�는 ?�래�?비트 (CF|ZF|SF|OF) ??PF/AF??보존.
const FLAG_MASK: u64 = 0x8C5; // CF|PF|ZF|SF|OF  (PF bit 2 added)

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
            )?;
            if ins.op != RiscOp::Halt {
                DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
            } else {
                // HALT: Win64 callee-saved ?��??�터(R12~R15) 복원 ??ret.
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

    /// ?�적 분기 ?��??�스-IP)??블록 ?�덱?�로 ?�석?�는 ?�캔 ?�퍼.
    /// ?�력: R10 = ?��?x86 IP. 출력: RAX = 블록 ?�덱??(찾으�?, �?찾으�?
    /// ?�스?�치 ?�이�?255] (=fallback, ret) �??�프.
    /// ?��? 브랜�?루프)가 ?�으므�????�스 브랜�??�치�?별도 ?�셈블된??
    fn emit_branch_lookup_helper(branch_map_va: u64, table_base: u64) -> Result<Vec<u8>> {
        // 맵�? (ip, index) u64 ??배열, ip == 0 종결??
        //   r11 = �??�작
        //   loop:
        //     mov rax, [r11]        ; ip
        //     test rax, rax
        //     jz  not_found         ; 종결??
        //     cmp r10, rax
        //     je  found
        //     add r11, 16
        //     jmp loop
        //   found:
        //     mov rax, [r11 + 8]    ; index
        //     ret
        //   not_found:
        //     mov rax, 255
        //     mov rax, [r15 + rax*8]; fallback (ret)
        //     jmp rax
        let mut instrs: Vec<Instruction> = Vec::new();
        instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::R11, branch_map_va).map_err(|e| anyhow!("{e}"))?);
        let label_loop = instrs.len();
        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, iced_x86::MemoryOperand::with_base(Register::R11)).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).map_err(|e| anyhow!("{e}"))?);
        let i_jz = instrs.len();
        instrs.push(Instruction::with_branch(Code::Je_rel32_64, 0).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with2(Code::Cmp_rm64_r64, Register::R10, Register::RAX).map_err(|e| anyhow!("{e}"))?);
        let i_je = instrs.len();
        instrs.push(Instruction::with_branch(Code::Je_rel32_64, 0).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::R11, 16).map_err(|e| anyhow!("{e}"))?);
        let i_jmp = instrs.len();
        instrs.push(Instruction::with_branch(Code::Jmp_rel32_64, 0).map_err(|e| anyhow!("{e}"))?);
        let label_found = instrs.len();
        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, iced_x86::MemoryOperand::with_base_displ_size(Register::R11, 8, 8)).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with(Code::Retnq));
        let label_not_found = instrs.len();
        instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 255).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, iced_x86::MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::RAX, 8, 0, 8)).map_err(|e| anyhow!("{e}"))?);
        instrs.push(Instruction::with1(Code::Jmp_rm64, Register::RAX).map_err(|e| anyhow!("{e}"))?);

        // ???�스 브랜�??�치 (BlockEncoder ??rel8/rel32 �??�동 축소 ???��?IP �?
        // 추정 ?�프?�으�?반복 ?�정???�렴?�킨??.
        let base = 0x140000000u64;
        let mut ips: Vec<u64> = (0..instrs.len()).map(|_| base).collect();
        let mut code = Vec::new();
        for _ in 0..16 {
            instrs[i_jz].set_near_branch64(ips[label_not_found]);
            instrs[i_je].set_near_branch64(ips[label_found]);
            instrs[i_jmp].set_near_branch64(ips[label_loop]);
            let blk = InstructionBlock::new(&instrs, base);
            let enc = iced_x86::BlockEncoder::encode(64, blk, iced_x86::BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
                .map_err(|e| anyhow!("branch helper encode: {e:?}"))?;
            let new_ips: Vec<u64> = enc.new_instruction_offsets.iter().map(|o| base + *o as u64).collect();
            code = enc.code_buffer;
            if new_ips == ips {
                ips = new_ips;
                break;
            }
            ips = new_ips;
        }
        let _ = table_base;
        Ok(code)
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

    /// ?�일 마이?�로 ?�산???�문???�이?�브 블록???�성?�다.
    /// `block_index` = ??블록??명령 ?�덱??(분기 fallthrough ?��?= index+1).
    /// `static_target` = ?�적 VirtualBranch ??목표 블록 ?�덱??(?�적?�면 None).
    /// `helper_va` = ?�적 분기 ?�캔 ?�퍼 주소 (?�적 분기가 ?�으�?None).
    fn emit_block(
        ins: &MicroInstr,
        instrs: &mut Vec<Instruction>,
        state_base: u64,
        bytecode_base: u64,
        block_index: u64,
        static_target: Option<u64>,
        helper_va: Option<u64>,
    ) -> Result<()> {
        // ?�태 버퍼 ?�근??메모�??�퍼?�드 ?�퍼.
        let mem = |disp: i64| -> iced_x86::MemoryOperand {
            iced_x86::MemoryOperand::with_base_index_scale_displ_size(
                Register::RDX,
                Register::None,
                1,
                disp,
                8,
            )
        };

        let load = |instrs: &mut Vec<Instruction>, op: Option<MicroOperand>, reg: Register| -> Result<()> {
            match op {
                Some(MicroOperand::VReg(i)) => {
                    instrs.push(Instruction::with2(Code::Mov_r64_rm64, reg, mem((REGS_OFF + i as usize * 8) as i64)).map_err(|e| anyhow!("{e}"))?);
                }
                Some(MicroOperand::Temp(t)) => {
                    instrs.push(Instruction::with2(Code::Mov_r64_rm64, reg, mem((TEMPS_OFF + t as usize * 8) as i64)).map_err(|e| anyhow!("{e}"))?);
                }
                Some(MicroOperand::Imm64(v)) => {
                    instrs.push(Instruction::with2(Code::Mov_r64_imm64, reg, v).map_err(|e| anyhow!("{e}"))?);
                }
                Some(MicroOperand::Vsp) => {
                    instrs.push(Instruction::with2(Code::Mov_r64_rm64, reg, mem(VSP_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                }
                Some(MicroOperand::Vflags) => {
                    instrs.push(Instruction::with2(Code::Mov_r64_rm64, reg, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                }
                _ => {
                    instrs.push(Instruction::with2(Code::Xor_r64_rm64, reg, reg).map_err(|e| anyhow!("{e}"))?);
                }
            }
            Ok(())
        };

        let store = |instrs: &mut Vec<Instruction>, dst: Option<MicroOperand>| -> Result<()> {
            match dst {
                Some(MicroOperand::VReg(i)) => {
                    instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem((REGS_OFF + i as usize * 8) as i64), Register::R10).map_err(|e| anyhow!("{e}"))?);
                }
                Some(MicroOperand::Temp(t)) => {
                    instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem((TEMPS_OFF + t as usize * 8) as i64), Register::R10).map_err(|e| anyhow!("{e}"))?);
                }
                _ => {}
            }
            Ok(())
        };

        // ?�래�??�롯???�재 x86 ?�래그의 CF|ZF|SF|OF �?병합 (PF/AF??보존).
        let store_flags = |instrs: &mut Vec<Instruction>| -> Result<()> {
            instrs.push(Instruction::with(Code::Pushfq));
            instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, FLAG_MASK as u32).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!FLAG_MASK) as i32).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
            Ok(())
        };

        // CF|OF �??�롯??병합 (MUL/IMUL ??ZF/SF/PF 보존).
        let store_cf_of = |instrs: &mut Vec<Instruction>| -> Result<()> {
            instrs.push(Instruction::with(Code::Pushfq));
            instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x801).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x801i32)).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
            Ok(())
        };

        // ZF �??�롯??병합 (BSF/BSR).
        let store_zf = |instrs: &mut Vec<Instruction>| -> Result<()> {
            instrs.push(Instruction::with(Code::Pushfq));
            instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x40).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x40i32)).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
            Ok(())
        };

        // CF|ZF 병합 (TZCNT/LZCNT).
        let store_cf_zf = |instrs: &mut Vec<Instruction>| -> Result<()> {
            instrs.push(Instruction::with(Code::Pushfq));
            instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0x41).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!0x41i32)).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
            Ok(())
        };

        // ?�태 ?�롯???�래그�? ?�제 x86 ?�래그로 복원 (setcc/cmovcc/분기 ?�용).
        let load_flags_to_hw = |instrs: &mut Vec<Instruction>| -> Result<()> {
            instrs.push(Instruction::with1(Code::Push_rm64, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with(Code::Popfq));
            Ok(())
        };

        // 조건 ?��? ??R8L = 0/1. (CounterZero ??regs[1] 검?? �????�드?�어 setcc.)
        let eval_cond = |instrs: &mut Vec<Instruction>, cond: BranchCondition| -> Result<()> {
            if cond == BranchCondition::Always {
                instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::R8, 1).map_err(|e| anyhow!("{e}"))?);
                return Ok(());
            }
            load_flags_to_hw(instrs)?;
            if let BranchCondition::CounterZero(width) = cond {
                let mask: u64 = match width {
                    2 => 0xFFFF,
                    4 => 0xFFFF_FFFF,
                    _ => u64::MAX,
                };
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, mem((REGS_OFF + 8) as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::R9, mask as i32).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R9, Register::R9).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Sete_rm8, Register::R8L).map_err(|e| anyhow!("{e}"))?);
            } else {
                let cc = cond_to_setcc_code(cond).ok_or_else(|| anyhow!("no setcc code for {cond:?}"))?;
                instrs.push(Instruction::with1(cc, Register::R8L).map_err(|e| anyhow!("{e}"))?);
            }
            Ok(())
        };

        match ins.op {
            RiscOp::Nor => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Not_rm64, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::Mov => {
                load(instrs, ins.src1, Register::R10)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::AddWithCarry => {
                load(instrs, ins.src1, Register::R10)?; // a
                load(instrs, ins.src2, Register::R11)?; // b
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::R11).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with(Code::Pushfq));
                instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                let cin = ins.imm;
                if cin != 0 {
                    if (cin as i8 as u64) == cin {
                        instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::R10, cin as i32).map_err(|e| anyhow!("{e}"))?);
                    } else if (cin as i32 as u64) == cin {
                        instrs.push(Instruction::with2(Code::Add_rm64_imm32, Register::R10, cin as i32).map_err(|e| anyhow!("{e}"))?);
                    } else {
                        instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::R11, cin).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                    }
                    instrs.push(Instruction::with(Code::Pushfq));
                    instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RCX, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                }
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with(Code::Pushfq));
                instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xC4).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Xor_rm64_r64, Register::R8, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_r64, Register::R8, Register::R9).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R8, 63).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Shl_rm64_imm8, Register::R8, 11).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::R8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!FLAG_MASK) as i32).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::ShiftRight => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Shr_rm64_CL, Register::R10, Register::CL).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::ArithmeticShiftRight => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Sar_rm64_CL, Register::R10, Register::CL).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::ShiftLeft => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Shl_rm64_CL, Register::R10, Register::CL).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::VirtualPush => {
                load(instrs, ins.src1, Register::R10)?;
                instrs.push(Instruction::with2(Code::Sub_rm64_imm8, Register::R13, 8).map_err(|e| anyhow!("{e}"))?);
                let sp = iced_x86::MemoryOperand::with_base(Register::R13);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, sp, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, mem(VSP_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Sub_rm64_imm8, Register::R10, 8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(VSP_OFF as i64), Register::R10).map_err(|e| anyhow!("{e}"))?);
            }
            RiscOp::VirtualPop => {
                let sp = iced_x86::MemoryOperand::with_base(Register::R13);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, sp).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::R13, 8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, mem(VSP_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::R11, 8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(VSP_OFF as i64), Register::R11).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::SetFlag => {
                load(instrs, ins.src1, Register::R10)?;
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::R10, 0x8D5).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::R10).map_err(|e| anyhow!("{e}"))?);
            }
            RiscOp::MemoryRead { width } => {
                load(instrs, ins.src1, Register::R10)?;
                let addr = iced_x86::MemoryOperand::with_base(Register::R10);
                let (code, vreg) = match width {
                    1 => (Code::Movzx_r32_rm8, Register::R10),
                    2 => (Code::Movzx_r32_rm16, Register::R10),
                    4 => (Code::Mov_r32_rm32, Register::R10D),
                    _ => (Code::Mov_r64_rm64, Register::R10),
                };
                instrs.push(Instruction::with2(code, vreg, addr).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::MemoryWrite { width } => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                let addr = iced_x86::MemoryOperand::with_base(Register::R10);
                let (code, vreg) = match width {
                    1 => (Code::Mov_rm8_r8, Register::R11L),
                    2 => (Code::Mov_rm16_r16, Register::R11W),
                    4 => (Code::Mov_rm32_r32, Register::R11D),
                    _ => (Code::Mov_rm64_r64, Register::R11),
                };
                instrs.push(Instruction::with2(code, addr, vreg).map_err(|e| anyhow!("{e}"))?);
            }
            RiscOp::CompareExchange { width } => {
                load(instrs, ins.src1, Register::R10)?; // addr
                load(instrs, ins.src2, Register::R11)?; // new
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, mem(REGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?); // acc
                if width < 8 {
                    let mask: u64 = match width {
                        1 => 0xFF,
                        2 => 0xFFFF,
                        _ => 0xFFFF_FFFF,
                    };
                    instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, mask as i32).map_err(|e| anyhow!("{e}"))?);
                }
                let addr = iced_x86::MemoryOperand::with_base(Register::R10);
                let (code, vreg) = match width {
                    1 => (Code::Cmpxchg_rm8_r8, Register::R11L),
                    2 => (Code::Cmpxchg_rm16_r16, Register::R11W),
                    4 => (Code::Cmpxchg_rm32_r32, Register::R11D),
                    _ => (Code::Cmpxchg_rm64_r64, Register::R11),
                };
                instrs.push(Instruction::with2(code, addr, vreg).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(REGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
                store_zf(instrs)?;
            }
            RiscOp::Multiply { signed, width } => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R10).map_err(|e| anyhow!("{e}"))?);
                let (code, vreg) = match (signed, width) {
                    (false, 1) => (Code::Mul_rm8, Register::R11L),
                    (false, 2) => (Code::Mul_rm16, Register::R11W),
                    (false, 4) => (Code::Mul_rm32, Register::R11D),
                    (false, _) => (Code::Mul_rm64, Register::R11),
                    (true, 1) => (Code::Imul_rm8, Register::R11L),
                    (true, 2) => (Code::Imul_rm16, Register::R11W),
                    (true, 4) => (Code::Imul_rm32, Register::R11D),
                    (true, _) => (Code::Imul_rm64, Register::R11),
                };
                instrs.push(Instruction::with1(code, vreg).map_err(|e| anyhow!("{e}"))?);
                if width == 1 {
                    instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10, Register::AX).map_err(|e| anyhow!("{e}"))?);
                } else {
                    // high ??R9 (??�� 마스??, low ??R10, RDX(state base) 복원.
                    match width {
                        2 => instrs.push(Instruction::with2(Code::Movzx_r64_rm16, Register::R9, Register::DX).map_err(|e| anyhow!("{e}"))?),
                        4 => instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::R9D, Register::EDX).map_err(|e| anyhow!("{e}"))?),
                        _ => instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RDX).map_err(|e| anyhow!("{e}"))?),
                    }
                    instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::RDX, state_base).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem((REGS_OFF + 16) as i64), Register::R9).map_err(|e| anyhow!("{e}"))?);
                }
                store_cf_of(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::MultiplyLow { signed, width } => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                let (code, r, v) = match (signed, width) {
                    (false, 2) => (Code::Imul_r16_rm16, Register::R10W, Register::R11W),
                    (false, 4) => (Code::Imul_r32_rm32, Register::R10D, Register::R11D),
                    (false, _) => (Code::Imul_r64_rm64, Register::R10, Register::R11),
                    (true, 2) => (Code::Imul_r16_rm16, Register::R10W, Register::R11W),
                    (true, 4) => (Code::Imul_r32_rm32, Register::R10D, Register::R11D),
                    (true, _) => (Code::Imul_r64_rm64, Register::R10, Register::R11),
                };
                instrs.push(Instruction::with2(code, r, v).map_err(|e| anyhow!("{e}"))?);
                store_cf_of(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::Divide { signed, width } => {
                load(instrs, ins.src1, Register::R11)?; // divisor
                // RDX(state base) �??�눗?�용?�로 ?��?�?R8 ??보존.
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::RDX).map_err(|e| anyhow!("{e}"))?);
                let r8mem = |disp: i64, sz: u32| -> iced_x86::MemoryOperand {
                    iced_x86::MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::None, 1, disp, sz)
                };
                match width {
                    1 => {
                        instrs.push(Instruction::with2(Code::Mov_r16_rm16, Register::AX, r8mem(REGS_OFF as i64, 2)).map_err(|e| anyhow!("{e}"))?);
                        let c = if signed { Code::Idiv_rm8 } else { Code::Div_rm8 };
                        instrs.push(Instruction::with1(c, Register::R11L).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10, Register::AX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R8).map_err(|e| anyhow!("{e}"))?);
                    }
                    2 => {
                        instrs.push(Instruction::with2(Code::Mov_r16_rm16, Register::DX, r8mem((REGS_OFF + 16) as i64, 2)).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r16_rm16, Register::AX, r8mem(REGS_OFF as i64, 2)).map_err(|e| anyhow!("{e}"))?);
                        let c = if signed { Code::Idiv_rm16 } else { Code::Div_rm16 };
                        instrs.push(Instruction::with1(c, Register::R11W).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R10, Register::AX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r32_rm16, Register::R9, Register::DX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R8).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem((REGS_OFF + 16) as i64), Register::R9).map_err(|e| anyhow!("{e}"))?);
                    }
                    4 => {
                        instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::EDX, r8mem((REGS_OFF + 16) as i64, 4)).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, r8mem(REGS_OFF as i64, 4)).map_err(|e| anyhow!("{e}"))?);
                        let c = if signed { Code::Idiv_rm32 } else { Code::Div_rm32 };
                        instrs.push(Instruction::with1(c, Register::R11D).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::R10D, Register::EAX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::R9D, Register::EDX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R8).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem((REGS_OFF + 16) as i64), Register::R9).map_err(|e| anyhow!("{e}"))?);
                    }
                    _ => {
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, r8mem((REGS_OFF + 16) as i64, 8)).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, r8mem(REGS_OFF as i64, 8)).map_err(|e| anyhow!("{e}"))?);
                        let c = if signed { Code::Idiv_rm64 } else { Code::Div_rm64 };
                        instrs.push(Instruction::with1(c, Register::R11).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RDX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::RDX, state_base).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem((REGS_OFF + 16) as i64), Register::R9).map_err(|e| anyhow!("{e}"))?);
                    }
                }
                store(instrs, ins.dst)?;
            }
            RiscOp::BSwap { width } => {
                load(instrs, ins.src1, Register::R10)?;
                let code = if width == 4 { Code::Bswap_r32 } else { Code::Bswap_r64 };
                instrs.push(Instruction::with1(code, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::BitScanForward => {
                load(instrs, ins.src1, Register::R10)?;
                instrs.push(Instruction::with2(Code::Bsf_r64_rm64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                // src==0 ??ZF=1, dst=0 (branch-free).
                instrs.push(Instruction::with1(Code::Setne_rm8, Register::R9L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::R9L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Neg_rm64, Register::R9).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_r64, Register::R10, Register::R9).map_err(|e| anyhow!("{e}"))?);
                store_zf(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::BitScanReverse => {
                load(instrs, ins.src1, Register::R10)?;
                instrs.push(Instruction::with2(Code::Bsr_r64_rm64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Setne_rm8, Register::R9L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R9D, Register::R9L).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Neg_rm64, Register::R9).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_r64, Register::R10, Register::R9).map_err(|e| anyhow!("{e}"))?);
                store_zf(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::CountTrailingZeros { width } => {
                load(instrs, ins.src1, Register::R10)?;
                let (code, r, v) = match width {
                    2 => (Code::Tzcnt_r16_rm16, Register::R10W, Register::R10W),
                    4 => (Code::Tzcnt_r32_rm32, Register::R10D, Register::R10D),
                    _ => (Code::Tzcnt_r64_rm64, Register::R10, Register::R10),
                };
                instrs.push(Instruction::with2(code, r, v).map_err(|e| anyhow!("{e}"))?);
                store_cf_zf(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::CountLeadingZeros { width } => {
                load(instrs, ins.src1, Register::R10)?;
                let (code, r, v) = match width {
                    2 => (Code::Lzcnt_r16_rm16, Register::R10W, Register::R10W),
                    4 => (Code::Lzcnt_r32_rm32, Register::R10D, Register::R10D),
                    _ => (Code::Lzcnt_r64_rm64, Register::R10, Register::R10),
                };
                instrs.push(Instruction::with2(code, r, v).map_err(|e| anyhow!("{e}"))?);
                store_cf_zf(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::PopCount => {
                load(instrs, ins.src1, Register::R10)?;
                instrs.push(Instruction::with2(Code::Popcnt_r64_rm64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::Setcc { cond } => {
                eval_cond(instrs, cond)?;
                instrs.push(Instruction::with2(Code::Movzx_r32_rm8, Register::R10D, Register::R8L).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::ConditionalMove { cond } => {
                eval_cond(instrs, cond)?;
                load(instrs, ins.dst, Register::R10)?;
                load(instrs, ins.src1, Register::R11)?;
                let cc = cond_to_cmov_code(cond).ok_or_else(|| anyhow!("no cmov code for {cond:?}"))?;
                instrs.push(Instruction::with2(cc, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::VirtualBranch { cond } => {
                let next_idx = block_index.wrapping_add(1);
                // 분기 후 타깃 블록이 실행되는 동안 r12(VIP) = 타깃 인덱스 + 1 이어야
                // 그 블록의 tail dispatch 가 다음 인덱스를 정확히 읽는다 (순차와 동일 불변식).
                // index 계산: rcx = 최종 인덱스; rax = rcx + 1 → r12; 점프 table[rcx].
                let emit_branch_jump = |instrs: &mut Vec<Instruction>| -> Result<()> {
                    instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 1).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::R12, bytecode_base).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Add_rm64_r64, Register::R12, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, iced_x86::MemoryOperand::with_base_index_scale_displ_size(Register::R15, Register::RCX, 8, 0, 8)).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with1(Code::Jmp_rm64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                    Ok(())
                };
                match static_target {
                    Some(target_idx) => {
                        eval_cond(instrs, cond)?;
                        instrs.push(Instruction::with2(Code::Movzx_r64_rm8, Register::RAX, Register::R8L).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Mov_r64_imm64, Register::RCX, target_idx).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Sub_rm64_imm32, Register::RCX, next_idx as i32).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Add_rm64_imm32, Register::RAX, next_idx as i32).map_err(|e| anyhow!("{e}"))?);
                        emit_branch_jump(instrs)?;
                    }
                    None => {
                        let helper = helper_va.ok_or_else(|| anyhow!("dynamic branch without helper"))?;
                        eval_cond(instrs, cond)?;
                        load(instrs, ins.src1, Register::R10)?;
                        instrs.push(Instruction::with_branch(Code::Call_rel32_64, helper).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Sub_rm64_imm32, Register::RAX, next_idx as i32).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Movzx_r64_rm8, Register::RCX, Register::R8L).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Imul_r64_rm64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                        instrs.push(Instruction::with2(Code::Add_rm64_imm32, Register::RAX, next_idx as i32).map_err(|e| anyhow!("{e}"))?);
                        emit_branch_jump(instrs)?;
                    }
                }
            }
            RiscOp::NativeCallBridge => {
                // ?��???no-op ???�태 불�?, tail dispatch �??�음 명령 진행.
            }
            RiscOp::Halt => {
                // ret (caller?�서 처리)
            }
            // P2 SSE/FPU scalar - not yet native-compilable (not poly-encodable).
            // Lifter-level diff tests use eval_state (reference); no-op here.
            RiscOp::FloatAdd { .. }
            | RiscOp::FloatSub { .. }
            | RiscOp::FloatMul { .. }
            | RiscOp::FloatDiv { .. }
            | RiscOp::IntToFloat { .. }
            | RiscOp::FloatToInt { .. }
            | RiscOp::FloatToFloat { .. } => {}
        }
        Ok(())
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

/// BranchCondition ??SETcc rm8 코드 (CounterZero ?�외 ??별도 처리).
fn cond_to_setcc_code(cond: BranchCondition) -> Option<Code> {
    match cond {
        BranchCondition::Zero => Some(Code::Sete_rm8),
        BranchCondition::NotZero => Some(Code::Setne_rm8),
        BranchCondition::Carry | BranchCondition::Below => Some(Code::Setb_rm8),
        BranchCondition::NotCarry | BranchCondition::AboveOrEqual => Some(Code::Setae_rm8),
        BranchCondition::Sign => Some(Code::Sets_rm8),
        BranchCondition::NotSign => Some(Code::Setns_rm8),
        BranchCondition::Overflow => Some(Code::Seto_rm8),
        BranchCondition::NotOverflow => Some(Code::Setno_rm8),
        BranchCondition::Greater => Some(Code::Setg_rm8),
        BranchCondition::Less => Some(Code::Setl_rm8),
        BranchCondition::GreaterOrEqual => Some(Code::Setge_rm8),
        BranchCondition::LessOrEqual => Some(Code::Setle_rm8),
        BranchCondition::Above => Some(Code::Seta_rm8),
        BranchCondition::BelowOrEqual => Some(Code::Setbe_rm8),
        BranchCondition::Parity => Some(Code::Setp_rm8),
        BranchCondition::NotParity => Some(Code::Setnp_rm8),
        BranchCondition::CounterZero(_) => None,
        BranchCondition::Always => Some(Code::Sete_rm8),
    }
}

/// BranchCondition ??CMOVcc r64, r/m64 코드 (CounterZero ?�외).
fn cond_to_cmov_code(cond: BranchCondition) -> Option<Code> {
    match cond {
        BranchCondition::Zero => Some(Code::Cmove_r64_rm64),
        BranchCondition::NotZero => Some(Code::Cmovne_r64_rm64),
        BranchCondition::Carry | BranchCondition::Below => Some(Code::Cmovb_r64_rm64),
        BranchCondition::NotCarry | BranchCondition::AboveOrEqual => Some(Code::Cmovae_r64_rm64),
        BranchCondition::Sign => Some(Code::Cmovs_r64_rm64),
        BranchCondition::NotSign => Some(Code::Cmovns_r64_rm64),
        BranchCondition::Overflow => Some(Code::Cmovo_r64_rm64),
        BranchCondition::NotOverflow => Some(Code::Cmovno_r64_rm64),
        BranchCondition::Greater => Some(Code::Cmovg_r64_rm64),
        BranchCondition::Less => Some(Code::Cmovl_r64_rm64),
        BranchCondition::GreaterOrEqual => Some(Code::Cmovge_r64_rm64),
        BranchCondition::LessOrEqual => Some(Code::Cmovle_r64_rm64),
        BranchCondition::Above => Some(Code::Cmova_r64_rm64),
        BranchCondition::BelowOrEqual => Some(Code::Cmovbe_r64_rm64),
        BranchCondition::Parity => Some(Code::Cmovp_r64_rm64),
        BranchCondition::NotParity => Some(Code::Cmovnp_r64_rm64),
        BranchCondition::CounterZero(_) => None,
        BranchCondition::Always => Some(Code::Cmovne_r64_rm64),
    }
}

/// RISC ?�로그램???�이?�브�??�행?�고 참조 ?�태(`eval_state`)�??�려받는 ?�의 ?�수.
pub fn run_native_risc(prog: &RiscProgram, init_regs: &[u64; 16]) -> Result<RiscEvalState> {
    let mut vm = NativeVmHarness::compile(prog, 0x5A)?;
    vm.run(init_regs)
}

/// ?�리모픽 롤링??바이?�코???�트림을 ?�이?�브�??�행?�는 ?�네??
///
/// T1-4 "?�이?�브?�폴리모???�터?�리???�치"???�심 경로: 출력 PE???�긴(?�는
/// ?�코?��? 만든) **?�호?�된** ?�리모픽 바이?�코?��? `PolymorphicDecoder`�?
/// 복호?�해(?�터?�리?��? ?�일 계약) ?�래 RISC ?�로그램??복원???? �??�로그램??
/// ?�문???�이?�브 블록?�로 컴파?�해 ?�행?�다. 결과 ?�태??
/// `PolymorphicInterpreter`(?�터?�리?? �?`RiscProgram::eval_state`(참조)?�?
/// ?�전???�치?�야 ?�다.
pub fn run_native_poly(bytecode: &[u8], seed: u64, init_regs: &[u64; 16]) -> Result<RiscEvalState> {
    let mut dec = PolymorphicDecoder::new(seed);
    let prog = dec.decode(bytecode)?;
    // ?�이?�브 블록?�??�연?�자가 코드???�점??베이?�되므�? ?�스?�치 ?�는 ?�의 �?
    let mut vm = NativeVmHarness::compile(&prog, 0x5A)?;
    vm.run(init_regs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscDesynthesizer, RiscOp};

    /// ?�양??op(NOR/ADD/SHR/SHL/PUSH/POP/SET_FLAG)�??��? ?�로그램??
    /// ?�이?�브 ?�행�?참조 ?��??�이?�에 각각 ?�려 결과 ?�태가 ?�치?�는지 검�?
    #[test]
    fn test_native_harness_matches_reference_state() {
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
        // R3 = R0 << 2  (0x800)
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftLeft)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(2)),
        );
        // R7 = R0 - R1  (0x1FB)  via AddWithCarry cin=1 (SUB de-synthesis)
        d.emit_sub(MicroOperand::VReg(7), MicroOperand::VReg(0), MicroOperand::VReg(1));
        // push R3, push R0, pop R4  ???��? push 1�?(R3)
        d.emit_push(MicroOperand::VReg(3));
        d.emit_push(MicroOperand::VReg(0));
        d.emit_pop(MicroOperand::VReg(4));
        // NOR: R5 = ~(R2 | R1)
        d.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::VReg(1)),
        );
        // SET_FLAG: ?�래�?= 0x8C1
        d.instrs.push(
            MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)),
        );
        // Halt
        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);
        let init = [0u64; 16];

        // 참조
        let ref_st = prog.eval_state(&init);
        // ?�이?�브
        let nat = run_native_risc(&prog, &init).unwrap();

        assert_eq!(nat.regs, ref_st.regs, "regs mismatch");
        assert_eq!(nat.temps, ref_st.temps, "temps mismatch");
        assert_eq!(nat.flags, ref_st.flags, "flags mismatch (ref={:#x} native={:#x})", ref_st.flags, nat.flags);
        assert_eq!(nat.vsp, ref_st.vsp, "vsp mismatch");
        assert_eq!(nat.stack, ref_st.stack, "stack mismatch");
    }

    /// ?�순 ADD ?�로그램??최종 ?��??�터 �?직접 ?�인.
    #[test]
    fn test_native_harness_add_value() {
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(1200), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(450), MicroOperand::Imm64(0));
        d.emit_sub(MicroOperand::VReg(0), MicroOperand::VReg(0), MicroOperand::VReg(1));
        d.emit_xor(MicroOperand::VReg(0), MicroOperand::VReg(0), MicroOperand::Imm64(0x55));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);

        let nat = run_native_risc(&prog, &[0u64; 16]).unwrap();
        assert_eq!(nat.regs[0], (1200 - 450) ^ 0x55);
        assert_eq!(nat.regs[1], 450);
    }

    /// T1-4 차등 검�? **?�호?�된** ?�리모픽 바이?�코???�트림을
    /// (1) ?�이?�브 ?�네??`run_native_poly`), (2) ?�리모픽 ?�터?�리??
    /// (3) 참조 ?��??�이??`eval_state`)??각각 ?�행?????�태가 ?�전???�치?�는지 검�?
    ///
    /// ?�는 "?�베?�된 .btgvm ?�텁??rolling-key ?�트림을 ?�이?�브�??�석·?�행?�는
    /// ?�계"??검�?기�??�다 ???�이?�브 ?�행???�터?�리?�·참조�? ?�치?�야 ?�다.
    #[test]
    fn test_native_poly_matches_interpreter_and_reference() {
        use crate::vm::poly::{PolymorphicEncoder, PolymorphicInterpreter};

        // ?�터?�리???�스?��? 같�? ?�로그램 (shift/push/pop/nor/flags ?�합).
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x200), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(5), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftRight)
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::ShiftLeft)
                .with_dst(MicroOperand::VReg(3))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::Imm64(2)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::AddWithCarry)
                .with_dst(MicroOperand::VReg(7))
                .with_src1(MicroOperand::VReg(0))
                .with_src2(MicroOperand::VReg(1))
                .with_imm(0),
        );
        d.emit_push(MicroOperand::VReg(3));
        d.emit_push(MicroOperand::VReg(0));
        d.emit_pop(MicroOperand::VReg(4));
        d.instrs.push(
            MicroInstr::new(RiscOp::Nor)
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::VReg(1)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);

        // ?�러 ?�드???�??각각 ?�리모픽 ?�코??????경로 비교.
        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();

            // (1) ?�이?�브
            let nat = run_native_poly(&bytecode, seed, &[0u64; 16]).unwrap();
            // (2) ?�터?�리??
            let mut interp = PolymorphicInterpreter::new(seed);
            interp.run(&bytecode).unwrap();
            // (3) 참조
            let ref_st = prog.eval_state(&[0u64; 16]);

            assert_eq!(nat.regs, ref_st.regs, "seed {seed:#x}: native regs != reference");
            assert_eq!(interp.regs, ref_st.regs, "seed {seed:#x}: interp regs != reference");
            assert_eq!(nat.temps, ref_st.temps, "seed {seed:#x}: native temps != reference");
            assert_eq!(nat.flags, ref_st.flags, "seed {seed:#x}: native flags != reference");
            assert_eq!(interp.flags.raw, ref_st.flags, "seed {seed:#x}: interp flags != reference");
            assert_eq!(nat.vsp, ref_st.vsp, "seed {seed:#x}: native vsp != reference");
            assert_eq!(nat.stack, ref_st.stack, "seed {seed:#x}: native stack != reference");
            assert_eq!(nat.regs[2], 0x10);
            assert_eq!(nat.regs[3], 0x800);
            assert_eq!(nat.regs[5], !(0x10 | 5));
        }
    }

    // ?�?� P2: ?�규 ?�수/비트/?�어 op ?�이?�브 차등 (native == eval_state) ?�?�?�?�?�?�?�?�?�?�

    /// ?�규 ?�산 ??계열 (Mov/ArithmeticShiftRight/Multiply/Divide/BSwap/BitScan/
    /// Count/PopCount/Setcc/ConditionalMove) ???�이?�브 ?�행??참조?� ?�전 ?�치 검�?
    /// TEMP isolated static branch.
    #[test]
    fn temp_static_branch_only() {
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0), MicroOperand::Imm64(0));
        d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::Zero }).with_imm(3));
        d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(111), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(222), MicroOperand::Imm64(0));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        let ref_st = prog.eval_state(&[0u64; 16]);
        let nat = run_native_risc(&prog, &[0u64; 16]).unwrap();
        assert_eq!(nat.regs, ref_st.regs);
        assert_eq!(nat.regs[6], 222);
        assert_eq!(nat.regs[7], 0);
    }

    #[test]
    fn test_native_new_ops_matches_reference() {
        use crate::vm::risc::BranchCondition;

        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x0102_0304_0506_0708), MicroOperand::Imm64(0));
        d.instrs.push(MicroInstr::new(RiscOp::Mov).with_dst(MicroOperand::VReg(1)).with_src1(MicroOperand::VReg(0)));
        d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64((-16i64) as u64), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::ArithmeticShiftRight)
                .with_dst(MicroOperand::VReg(2))
                .with_src1(MicroOperand::VReg(2))
                .with_src2(MicroOperand::Imm64(2)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::BSwap { width: 8 }).with_dst(MicroOperand::VReg(3)).with_src1(MicroOperand::VReg(0)));
        d.emit_add(MicroOperand::VReg(4), MicroOperand::Imm64(0x1000), MicroOperand::Imm64(0));
        d.instrs.push(MicroInstr::new(RiscOp::BitScanForward).with_dst(MicroOperand::VReg(5)).with_src1(MicroOperand::VReg(4)));
        d.instrs.push(MicroInstr::new(RiscOp::BitScanReverse).with_dst(MicroOperand::VReg(6)).with_src1(MicroOperand::VReg(4)));
        d.instrs.push(MicroInstr::new(RiscOp::BitScanForward).with_dst(MicroOperand::VReg(7)).with_src1(MicroOperand::Imm64(0)));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(0x8000_0000_0000_1000), MicroOperand::Imm64(0));
        d.instrs.push(MicroInstr::new(RiscOp::CountTrailingZeros { width: 8 }).with_dst(MicroOperand::VReg(2)).with_src1(MicroOperand::VReg(1)));
        d.instrs.push(MicroInstr::new(RiscOp::CountLeadingZeros { width: 8 }).with_dst(MicroOperand::VReg(3)).with_src1(MicroOperand::VReg(1)));
        d.instrs.push(MicroInstr::new(RiscOp::PopCount).with_dst(MicroOperand::VReg(4)).with_src1(MicroOperand::Imm64(0xFF)));
        d.emit_add(MicroOperand::VReg(5), MicroOperand::Imm64(0x1_0000_0001), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(3), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::Multiply { signed: false, width: 8 })
                .with_dst(MicroOperand::VReg(5))
                .with_src1(MicroOperand::VReg(5))
                .with_src2(MicroOperand::VReg(6)),
        );
        d.instrs.push(
            MicroInstr::new(RiscOp::MultiplyLow { signed: true, width: 4 })
                .with_dst(MicroOperand::VReg(6))
                .with_src1(MicroOperand::VReg(6))
                .with_src2(MicroOperand::Imm64(2)),
        );
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(1000), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(2), MicroOperand::Imm64(0), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(3), MicroOperand::Imm64(7), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::Divide { signed: false, width: 8 })
                .with_dst(MicroOperand::VReg(1))
                .with_src1(MicroOperand::VReg(3)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x44)));
        d.instrs.push(MicroInstr::new(RiscOp::Setcc { cond: BranchCondition::Zero }).with_dst(MicroOperand::VReg(4)));
        d.instrs.push(MicroInstr::new(RiscOp::Setcc { cond: BranchCondition::NotZero }).with_dst(MicroOperand::VReg(5)));
        d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(7), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::ConditionalMove { cond: BranchCondition::Zero })
                .with_dst(MicroOperand::VReg(7))
                .with_src1(MicroOperand::VReg(6)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);
        let init = [0u64; 16];
        let ref_st = prog.eval_state(&init);
        let nat = run_native_risc(&prog, &init).unwrap();
        assert_eq!(nat.regs, ref_st.regs, "regs mismatch");
        assert_eq!(nat.temps, ref_st.temps, "temps mismatch");
        assert_eq!(nat.flags, ref_st.flags, "flags mismatch (ref={:#x} nat={:#x})", ref_st.flags, nat.flags);
        assert_eq!(nat.vsp, ref_st.vsp, "vsp mismatch");
        assert_eq!(nat.stack, ref_st.stack, "stack mismatch");
    }

    /// ?�적/?�적 VirtualBranch ?�이?�브 ??branch-free ?�이�??�프 + ip_map ?�캔 ?�퍼.
    #[test]
    fn test_native_branch_static_and_dynamic_matches_reference() {
        use std::collections::HashMap;

        // ?�적 분기: imm=?��??�덱??(ip_map ?�음 ??resolve_target ??imm ???�덱?�로).
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0), MicroOperand::Imm64(0)); // ZF=1
        d.instrs.push(MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::Zero }).with_imm(3)); // index1
        d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(111), MicroOperand::Imm64(0)); // index2: 건너?�
        d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(222), MicroOperand::Imm64(0)); // index3
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
        let prog = RiscProgram::new(d.instrs);
        let ref_st = prog.eval_state(&[0u64; 16]);
        let nat = run_native_risc(&prog, &[0u64; 16]).unwrap();
        assert_eq!(nat.regs, ref_st.regs, "static branch regs");
        assert_eq!(nat.regs[6], 222, "static branch taken target");
        assert_eq!(nat.regs[7], 0, "static branch skipped block");

        // ?�적 분기: src1=VReg(?��?IP) ??ip_map ?�캔 ?�퍼�??�덱???�석.
        let mut ip_map = HashMap::new();
        for i in 0..5u64 {
            ip_map.insert(0x1000 + i, i as usize);
        }
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(5), MicroOperand::Imm64(0x1003), MicroOperand::Imm64(0)); // index0
        d.instrs.push(
            MicroInstr::new(RiscOp::VirtualBranch { cond: BranchCondition::Always })
                .with_src1(MicroOperand::VReg(5)),
        ); // index1: ?�적 분기 ??0x1003 ??index3
        d.emit_add(MicroOperand::VReg(7), MicroOperand::Imm64(111), MicroOperand::Imm64(0)); // index2
        d.emit_add(MicroOperand::VReg(6), MicroOperand::Imm64(222), MicroOperand::Imm64(0)); // index3
        d.instrs.push(MicroInstr::new(RiscOp::Halt)); // index4
        let prog = RiscProgram::with_ip_map(d.instrs, ip_map);
        let ref_st = prog.eval_state(&[0u64; 16]);
        let nat = run_native_risc(&prog, &[0u64; 16]).unwrap();
        assert_eq!(nat.regs, ref_st.regs, "dynamic branch regs");
        assert_eq!(nat.regs[6], 222, "dynamic branch target resolved via helper");
    }

    /// MemoryRead/Write + CompareExchange ?�이?�브 ??arena 창을 게스??메모리로 ?�용.
    #[test]
    fn test_native_memory_and_cmpxchg_matches_reference() {
        use std::collections::HashMap;

        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0xCAFE_F00D), MicroOperand::Imm64(0));
        d.instrs.push(MicroInstr::new(RiscOp::MemoryWrite { width: 8 }).with_src1(MicroOperand::VReg(1)).with_src2(MicroOperand::VReg(0)));
        d.instrs.push(MicroInstr::new(RiscOp::MemoryRead { width: 8 }).with_dst(MicroOperand::VReg(2)).with_src1(MicroOperand::VReg(1)));
        d.instrs.push(MicroInstr::new(RiscOp::MemoryRead { width: 4 }).with_dst(MicroOperand::VReg(3)).with_src1(MicroOperand::VReg(1)));
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0xCAFE_F00D), MicroOperand::Imm64(0));
        d.instrs.push(
            MicroInstr::new(RiscOp::CompareExchange { width: 8 })
                .with_src1(MicroOperand::VReg(1))
                .with_src2(MicroOperand::Imm64(0x1234)),
        );
        d.instrs.push(MicroInstr::new(RiscOp::MemoryRead { width: 8 }).with_dst(MicroOperand::VReg(4)).with_src1(MicroOperand::VReg(1)));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);
        let mut vm = NativeVmHarness::compile(&prog, 0x5A).unwrap();
        let addr = (vm.arena.base + 0x18000) as u64;

        let mut init = [0u64; 16];
        init[1] = addr;
        // 참조??arena 창이 0 ?�로 ?�작?�다�?가????0xCAFE_F00D 기록 경로�?검�?
        let seed_mem: HashMap<u64, u8> = HashMap::new();
        let ref_st = prog.eval_state_with_mem(&init, seed_mem);

        {
            let buf = vm.arena.bytes();
            for i in 0..16u64 {
                assert_eq!(buf[0x18000 + i as usize], 0, "arena window must start zeroed");
            }
        }
        let nat = vm.run(&init).unwrap();

        assert_eq!(nat.regs, ref_st.regs, "regs mismatch (mem/cmpxchg)");
        assert_eq!(nat.flags, ref_st.flags, "flags mismatch (ref={:#x} nat={:#x})", ref_st.flags, nat.flags);
        let buf = vm.arena.bytes();
        let mut stored = 0u64;
        for i in 0..8u64 {
            stored |= (buf[0x18000 + i as usize] as u64) << (i * 8);
        }
        assert_eq!(stored, 0x1234, "cmpxchg wrote new value");
    }
}
