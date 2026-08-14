// ==============================================================================
// BTG - Commercial-Grade VM: Direct-Threaded Native Execution Harness (T1-4)
// ==============================================================================
// 이 모듈은 `DirectThreadedNativeRunner`가 생성한 핸들러 머신코드를 실제 RWX
// arena에 배치하고, VM 상태 버퍼(레지스터/임시/플래그/VSP/스택)를 연결한 뒤
// 폴리모픽 RISC 프로그램을 **네이티브로 실행**하는 하네스다.
//
// 검증 목표 (T1-4 "네이티브↔VM 상태 전이 실행 검증"):
//   네이티브 실행 결과 상태 == `RiscProgram::eval_state` 참조 상태
//   (레지스터/임시/플래그/VSP/스택 깊이 전부 일치).
//
// 설계:
//   * 각 RISC 마이크로 연산은 "전문화(specialized) 블록"으로 컴파일된다.
//     피연산자 종류/레지스터 인덱스/즉시값이 코드젠 시점에 베이크되므로
//     런타임에 바이트코드를 디코드하지 않고 상태 버퍼에서 값을 직접 읽어온다.
//     (VReg/Temp/Imm64/Vsp/Vflags → R10/R11, 결과는 dst 슬롯에 저장)
//   * 블록 사이에는 기존 `DirectTailEmitter`의 직접 스레디드 tail-dispatch
//     (opcode fetch → key XOR → [R15+rax*8] 테이블 인덱스 → jmp)를 그대로
//     연결한다. 명령마다 고유 opcode(순번)를 부여하고 테이블이 그 주소를 가리킨다.
//   * 상세 ABI: R10=src1/결과, R11=src2, R12=VIP, R13=스택 포인터,
//     R14=키, R15=핸들러 테이블 베이스, RDX=상태 버퍼 베이스(전역 유지).
//
// 플래그 처리: NOR/시프트는 `test`로 CF/OF=0·ZF/SF 갱신(update_logic64 동일),
// ADD는 `add`+`adc`의 하드웨어 CF/ZF/SF/OF 사용(update_add64 동일).
// PF/AF는 참조가 갱신하지 않으므로 보존한다(CF|ZF|SF|OF = 0x8C1 마스크).
// ==============================================================================

use super::direct_tail::DirectTailEmitter;
use crate::vm::arena::Arena;
use crate::vm::poly::PolymorphicDecoder;
use crate::vm::risc::{MicroInstr, MicroOperand, RiscEvalState, RiscOp, RiscProgram};
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, Register};

// ── arena 레이아웃 오프셋 ─────────────────────────────────────────────────────
const OFF_CODE: usize = 0x1000;    // 실행 코드 (엔트리 + 블록들)
const OFF_TABLE: usize = 0x8000;   // 디스패치 테이블 (256 x u64)
const OFF_BYTECODE: usize = 0x9000;// opcode 스트림 (고정키 XOR)
const OFF_STATE: usize = 0xA000;   // VM 상태 버퍼
const OFF_STACK_BASE: usize = 0xE000; // 가상 스택 최상단 (아래로 성장, 8KiB)
const ARENA_SIZE: usize = 0x40000;

// ── 상태 버퍼 레이아웃 (OFF_STATE 기준) ──────────────────────────────────────
const REGS_OFF: usize = 0x000;   // [u64;16]
const TEMPS_OFF: usize = 0x080;  // [u64;8]
const FLAGS_OFF: usize = 0x0C0;  // u64
const VSP_OFF: usize = 0x0C8;    // u64
const STATE_END: usize = 0x100;

// 참조가 갱신하는 플래그 비트 (CF|ZF|SF|OF) — PF/AF는 보존.
const FLAG_MASK: u64 = 0x8C1;

/// 직접 스레디드 네이티브 VM 하네스.
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
    /// RISC 프로그램을 전문화 네이티브 블록들로 컴파일해 arena에 배치한다.
    pub fn compile(prog: &RiscProgram, key: u8) -> Result<Self> {
        let mut arena = Arena::new(ARENA_SIZE)?;
        let state_base = (arena.base + OFF_STATE) as u64;
        let stack_base = (arena.base + OFF_STACK_BASE) as u64;
        let table_base = (arena.base + OFF_TABLE) as u64;
        let bytecode_base = (arena.base + OFF_BYTECODE) as u64;
        let code_base = (arena.base + OFF_CODE) as u64;

        // 1) 각 명령을 전문화 블록으로 컴파일 (VA-독립 길이 — 재배치/전역 ref 없음).
        let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(prog.instrs.len());
        for ins in &prog.instrs {
            let mut instrs = Vec::new();
            Self::emit_block(ins, &mut instrs, state_base)?;
            // HALT 외 블록은 tail-dispatch로 다음 명령 연결.
            if ins.op != RiscOp::Halt {
                DirectTailEmitter::emit_tail_dispatch(&mut instrs)?;
            } else {
                // HALT: Win64 callee-saved 레지스터(R12~R15) 복원 후 ret.
                // 엔트리에서 push r12;push r13;push r14;push r15 순서로 저장했으므로 역순 pop.
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R15).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R14).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R13).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Pop_r64, Register::R12).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with(Code::Retnq));
            }
            let bytes = DirectTailEmitter::assemble(instrs, code_base)?;
            blocks.push(bytes);
        }

        // 2) 엔트리 스텁: Win64 callee-saved(R12~R15) 저장 후 ABI 레지스터 초기화.
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
        let entry = DirectTailEmitter::assemble(entry_instrs, code_base)?;

        // fallback 블록 (테이블에서 사용되지 않은 opcode → 단순 ret)
        let fallback = DirectTailEmitter::assemble(vec![Instruction::with(Code::Retnq)], code_base)?;

        // 3) 배치: [entry][block0..blockN][fallback]
        let mut layout = Vec::new();
        layout.push(entry);
        for b in &blocks {
            layout.push(b.clone());
        }
        layout.push(fallback);

        let mut cursor = OFF_CODE;
        let mut block_vas: Vec<u64> = Vec::new();
        let mut entry_va = code_base;
        let mut segment_starts = Vec::new();
        for seg in &layout {
            segment_starts.push(cursor);
            cursor += seg.len();
        }
        entry_va = arena.base as u64 + segment_starts[0] as u64;
        // 블록 VA들 (엔트리 다음부터)
        for i in 0..blocks.len() {
            block_vas.push(arena.base as u64 + segment_starts[1 + i] as u64);
        }
        let fallback_va = arena.base as u64 + segment_starts[1 + blocks.len()] as u64;

        // 4) 디스패치 테이블: table[명령순번(디크립트 opcode)] = 블록 VA.
        let mut table = vec![fallback_va as u64; 256];
        for (i, va) in block_vas.iter().enumerate() {
            table[i] = *va;
        }

        // 5) 바이트코드: bytecode[i] = (i as u8) ^ key  →  tail-dispatch가 key XOR로 복원.
        let mut bytecode = vec![0u8; blocks.len()];
        for (i, b) in bytecode.iter_mut().enumerate() {
            *b = (i as u8) ^ key;
        }

        // 6) arena에 복사.
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
            // 스택 영역 클리어 (OFF_STACK_BASE부터 8KiB 아래로)
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

    /// `init_regs`를 상태 버퍼에 심고 네이티브 실행 후 최종 상태를 돌려준다.
    pub fn run(&mut self, init_regs: &[u64; 16]) -> Result<RiscEvalState> {
        // 초기 레지스터 세팅 + 상태 버퍼 재초기화.
        {
            let buf = self.arena.bytes();
            buf[self.state_off..self.state_off + STATE_END].fill(0);
            for (i, v) in init_regs.iter().enumerate() {
                buf[self.state_off + REGS_OFF + i * 8..self.state_off + REGS_OFF + i * 8 + 8]
                    .copy_from_slice(&v.to_le_bytes());
            }
        }
        self.arena.call(self.code_off);

        // 최종 상태 읽기.
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

        // 스택 재구성: 참조 stack vec는 push 순서 그대로. 첫 push는 [stack_base-8].
        // 남은 push 개수 = (0 - vsp) / 8 (vsp < 0 일 때).
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

    /// 단일 마이크로 연산의 전문화 네이티브 블록을 생성한다.
    fn emit_block(ins: &MicroInstr, instrs: &mut Vec<Instruction>, state_base: u64) -> Result<()> {
        // 상태 버퍼 접근용 메모리 오퍼랜드 헬퍼.
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
                    // 없음/미지원 → 0
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

        // 플래그 슬롯에 현재 x86 플래그의 CF|ZF|SF|OF 를 병합 (PF/AF는 보존).
        let store_flags = |instrs: &mut Vec<Instruction>| -> Result<()> {
            // pushfq; pop rax ; and rax, FLAG_MASK
            instrs.push(Instruction::with(Code::Pushfq));
            instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, FLAG_MASK as u32).map_err(|e| anyhow!("{e}"))?);
            // rcx = 기존 슬롯 & ~FLAG_MASK  (PF/AF 보존)
            instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!FLAG_MASK) as i32).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
            instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
            Ok(())
        };

        match ins.op {
            RiscOp::Nor => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with1(Code::Not_rm64, Register::R10).map_err(|e| anyhow!("{e}"))?);
                // update_logic64: CF/OF=0, ZF/SF 갱신
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                store_flags(instrs)?;
                store(instrs, ins.dst)?;
            }
            RiscOp::AddWithCarry => {
                load(instrs, ins.src1, Register::R10)?; // a
                load(instrs, ins.src2, Register::R11)?; // b
                // 참조 update_add64(a,b,cin): res=(a+b+cin) mod 2^64,
                //   CF = c1|c2 (c1 = carry(a+b), c2 = carry((a+b mod)+cin)),
                //   ZF = res==0, SF = res<0, OF = ((a^res)&(b^res))>>63.
                // 네이티브: r8=a, r9=b 보존.
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::R11).map_err(|e| anyhow!("{e}"))?);
                // r10 = a+b (mod), CF = c1
                instrs.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11).map_err(|e| anyhow!("{e}"))?);
                // rcx = c1
                instrs.push(Instruction::with(Code::Pushfq));
                instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                // r10 = res = (a+b mod) + cin   (plain add — adc는 CF를 두 번 더하므로 부적합)
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
                    // rcx |= c2
                    instrs.push(Instruction::with(Code::Pushfq));
                    instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).map_err(|e| anyhow!("{e}"))?);
                    instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RCX, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                }
                // rax = ZF|SF (test가 CF/OF를 0으로)
                instrs.push(Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with(Code::Pushfq));
                instrs.push(Instruction::with1(Code::Pop_r64, Register::RAX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xC0).map_err(|e| anyhow!("{e}"))?); // ZF|SF
                // CF 비트 설정
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                // OF = ((a^res)&(b^res))>>63
                instrs.push(Instruction::with2(Code::Xor_rm64_r64, Register::R8, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Xor_rm64_r64, Register::R9, Register::R10).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_r64, Register::R8, Register::R9).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Shr_rm64_imm8, Register::R8, 63).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Shl_rm64_imm8, Register::R8, 11).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::R8).map_err(|e| anyhow!("{e}"))?);
                // slot 병합 (PF/AF 보존)
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::RCX, mem(FLAGS_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::RCX, (!FLAG_MASK) as i32).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RCX).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::RAX).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::ShiftRight => {
                load(instrs, ins.src1, Register::R10)?;
                load(instrs, ins.src2, Register::R11)?;
                // mov ecx, r11d ; shr r10, cl
                instrs.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::R11D).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Shr_rm64_CL, Register::R10, Register::CL).map_err(|e| anyhow!("{e}"))?);
                // update_logic64
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
                // sub r13, 8 ; mov [r13], r10
                instrs.push(Instruction::with2(Code::Sub_rm64_imm8, Register::R13, 8).map_err(|e| anyhow!("{e}"))?);
                let sp = iced_x86::MemoryOperand::with_base(Register::R13);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, sp, Register::R10).map_err(|e| anyhow!("{e}"))?);
                // vsp -= 8 (wrapping)
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, mem(VSP_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Sub_rm64_imm8, Register::R10, 8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(VSP_OFF as i64), Register::R10).map_err(|e| anyhow!("{e}"))?);
            }
            RiscOp::VirtualPop => {
                let sp = iced_x86::MemoryOperand::with_base(Register::R13);
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, sp).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::R13, 8).map_err(|e| anyhow!("{e}"))?);
                // vsp += 8 (wrapping)
                instrs.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, mem(VSP_OFF as i64)).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Add_rm64_imm8, Register::R11, 8).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(VSP_OFF as i64), Register::R11).map_err(|e| anyhow!("{e}"))?);
                store(instrs, ins.dst)?;
            }
            RiscOp::SetFlag => {
                load(instrs, ins.src1, Register::R10)?;
                // flags = src1 & 0x8D5
                instrs.push(Instruction::with2(Code::And_rm64_imm32, Register::R10, 0x8D5).map_err(|e| anyhow!("{e}"))?);
                instrs.push(Instruction::with2(Code::Mov_rm64_r64, mem(FLAGS_OFF as i64), Register::R10).map_err(|e| anyhow!("{e}"))?);
            }
            RiscOp::Halt => {
                // ret (caller에서 처리)
            }
            _ => {
                // MemoryRead/MemoryWrite/VirtualBranch/NativeCallBridge — 참조도 무시하므로 no-op.
                // (메모리 연산은 런타임 계층 책임 — 여기선 skip)
            }
        }
        Ok(())
    }
}

/// u64 벡터를 little-endian 바이트로.
fn bytemuck_le(v: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 8);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

/// RISC 프로그램을 네이티브로 실행하고 참조 상태(`eval_state`)를 돌려받는 편의 함수.
pub fn run_native_risc(prog: &RiscProgram, init_regs: &[u64; 16]) -> Result<RiscEvalState> {
    let mut vm = NativeVmHarness::compile(prog, 0x5A)?;
    vm.run(init_regs)
}

/// 폴리모픽 롤링키 바이트코드 스트림을 네이티브로 실행하는 하네스.
///
/// T1-4 "네이티브↔폴리모픽 인터프리터 동치"의 핵심 경로: 출력 PE에 심긴(또는
/// 인코더가 만든) **암호화된** 폴리모픽 바이트코드를 `PolymorphicDecoder`로
/// 복호화해(인터프리터와 동일 계약) 원래 RISC 프로그램을 복원한 뒤, 그 프로그램을
/// 전문화 네이티브 블록으로 컴파일해 실행한다. 결과 상태는
/// `PolymorphicInterpreter`(인터프리터) 및 `RiscProgram::eval_state`(참조)와
/// 완전히 일치해야 한다.
pub fn run_native_poly(bytecode: &[u8], seed: u64, init_regs: &[u64; 16]) -> Result<RiscEvalState> {
    let mut dec = PolymorphicDecoder::new(seed);
    let prog = dec.decode(bytecode)?;
    // 네이티브 블록은 피연산자가 코드젠 시점에 베이크되므로, 디스패치 키는 임의 값.
    let mut vm = NativeVmHarness::compile(&prog, 0x5A)?;
    vm.run(init_regs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscDesynthesizer, RiscOp};

    /// 다양한 op(NOR/ADD/SHR/SHL/PUSH/POP/SET_FLAG)를 섞은 프로그램을
    /// 네이티브 실행과 참조 시뮬레이터에 각각 돌려 결과 상태가 일치하는지 검증.
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
        // push R3, push R0, pop R4  → 남은 push 1개 (R3)
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
        // SET_FLAG: 플래그 = 0x8C1
        d.instrs.push(
            MicroInstr::new(RiscOp::SetFlag).with_src1(MicroOperand::Imm64(0x8C1)),
        );
        // Halt
        d.instrs.push(MicroInstr::new(RiscOp::Halt));

        let prog = RiscProgram::new(d.instrs);
        let init = [0u64; 16];

        // 참조
        let ref_st = prog.eval_state(&init);
        // 네이티브
        let nat = run_native_risc(&prog, &init).unwrap();

        assert_eq!(nat.regs, ref_st.regs, "regs mismatch");
        assert_eq!(nat.temps, ref_st.temps, "temps mismatch");
        assert_eq!(nat.flags, ref_st.flags, "flags mismatch (ref={:#x} native={:#x})", ref_st.flags, nat.flags);
        assert_eq!(nat.vsp, ref_st.vsp, "vsp mismatch");
        assert_eq!(nat.stack, ref_st.stack, "stack mismatch");
    }

    /// 단순 ADD 프로그램의 최종 레지스터 값 직접 확인.
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

    /// T1-4 차등 검증: **암호화된** 폴리모픽 바이트코드 스트림을
    /// (1) 네이티브 하네스(`run_native_poly`), (2) 폴리모픽 인터프리터,
    /// (3) 참조 시뮬레이터(`eval_state`)에 각각 실행해 세 상태가 완전히 일치하는지 검증.
    ///
    /// 이는 "임베드된 .btgvm 스텁이 rolling-key 스트림을 네이티브로 해석·실행하는
    /// 단계"의 검증 기준이다 — 네이티브 실행이 인터프리터·참조와 동치여야 한다.
    #[test]
    fn test_native_poly_matches_interpreter_and_reference() {
        use crate::vm::poly::{PolymorphicEncoder, PolymorphicInterpreter};

        // 인터프리터 테스트와 같은 프로그램 (shift/push/pop/nor/flags 혼합).
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

        // 여러 시드에 대해 각각 폴리모픽 인코딩 후 세 경로 비교.
        for seed in [0x1122334455667788u64, 0xDEADBEEFCAFE0001, 0x123456789] {
            let mut enc = PolymorphicEncoder::new(seed);
            let bytecode = enc.encode(&prog).unwrap();

            // (1) 네이티브
            let nat = run_native_poly(&bytecode, seed, &[0u64; 16]).unwrap();
            // (2) 인터프리터
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
}
