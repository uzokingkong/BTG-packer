// ============================================================
// BTG - Anti-Debugging Runtime Check Module
// ============================================================
// Generates a Position-Independent-Code (PIC) anti-debugging routine
// injected into the protected binary .btg section and executed once at
// the OEP before the dispatcher takes over. All checks are import-free:
// 1. PEB.BeingDebugged (PEB + 0x02)
// 2. PEB.NtGlobalFlag (PEB + 0xBC, mask 0x70)
// 3. RDTSC timing skew (debugger stepping inflates the TSC delta)
// If a debugger is detected, control enters an infinite loop so the
// debugger cannot pass the check. Registers and flags are restored
// before jumping into the dispatcher.

use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register};

pub const MAX_SIZE: usize = 128;

pub fn build(dispatcher_va: u64) -> Vec<u8> {
				// Synthetic PIC base; only relative branch deltas matter.
				let base_va = dispatcher_va + 0x200;
				let probe = make_instructions(dispatcher_va, base_va);
				let block = InstructionBlock::new(&probe, base_va);
				let first = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE).unwrap();
				let hang_va = base_va + (first.code_buffer.len() - 2) as u64;
				let ins = make_instructions(dispatcher_va, hang_va);
				let block2 = InstructionBlock::new(&ins, base_va);
				let enc = BlockEncoder::encode(64, block2, BlockEncoderOptions::NONE).unwrap();
				enc.code_buffer
}

fn make_instructions(dispatcher_va: u64, hang_va: u64) -> Vec<Instruction> {
				let mut ins: Vec<Instruction> = Vec::new();
				ins.push(Instruction::with(Code::Pushfq));
				ins.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
				ins.push(Instruction::with1(Code::Push_r64, Register::RCX).unwrap());
				ins.push(Instruction::with1(Code::Push_r64, Register::RDX).unwrap());
				let peb = MemoryOperand::new(Register::None, Register::None, 1, 0x60, 8, false, Register::GS);
				ins.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, peb).unwrap());
				let bd = MemoryOperand::with_base_displ(Register::RAX, 0x02);
				ins.push(Instruction::with2(Code::Cmp_rm8_imm8, bd, 0).unwrap());
				ins.push(Instruction::with_branch(Code::Jne_rel8_64, hang_va).unwrap());
				let ngf = MemoryOperand::with_base_displ(Register::RAX, 0xBC);
				ins.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, ngf).unwrap());
				ins.push(Instruction::with2(Code::And_rm32_imm32, Register::ECX, 0x70).unwrap());
				ins.push(Instruction::with_branch(Code::Jne_rel8_64, hang_va).unwrap());
				ins.push(Instruction::with(Code::Rdtsc));
				ins.push(Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap());
				ins.push(Instruction::with(Code::Rdtsc));
				ins.push(Instruction::with2(Code::Sub_rm32_r32, Register::EAX, Register::ECX).unwrap());
				ins.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::EAX, 0x100000).unwrap());
				ins.push(Instruction::with_branch(Code::Ja_rel8_64, hang_va).unwrap());
				ins.push(Instruction::with1(Code::Pop_r64, Register::RDX).unwrap());
				ins.push(Instruction::with1(Code::Pop_r64, Register::RCX).unwrap());
				ins.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
				ins.push(Instruction::with(Code::Popfq));
				ins.push(Instruction::with_branch(Code::Jmp_rel32_64, dispatcher_va + 0x20).unwrap());
				ins.push(Instruction::with_branch(Code::Jmp_rel8_64, hang_va).unwrap());
				ins
}
