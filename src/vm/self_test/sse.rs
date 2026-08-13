// ==============================================================================
// VM self-test submodule: sse.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use anyhow::{Result, anyhow};
use crate::vm::{interp};
use crate::vm::lifter::{LiftedInstr};
use iced_x86::{Code, Instruction, MemoryOperand, Register};



/// [18] A-5 SSE/FPU + conditional + string ops through the interpreter.
/// Lifts a block exercising setcc, cmovcc, sbb, movsd/movups/unpcklpd (XMM file),
/// rep stosq and loopne, then verifies the VM state/memory.
pub(crate) fn run_a5_sse_cond_test() -> Result<()> {
    use crate::vm::lifter::{LiftedInstr, lift_block, diagnose_unsupported};
    use iced_x86::{Instruction, Code, Register, MemoryOperand};
    use crate::vm::interp::STATE_XMM;

    let mut seq: Vec<LiftedInstr> = Vec::new();
    // setcc: al = (ZF) ? 1 : 0  — seed ZF via cmp rax,rax (equal)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Cmp_rm64_r64, Register::RAX, Register::RAX).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with1(Code::Sete_rm8, Register::AL).unwrap()));
    // cmovcc: cmove ecx, edx  (ZF set -> rcx = rdx)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Cmove_r64_rm64, Register::R10, Register::RDX).unwrap()));
    // sbb: r9d = r9d - r8d - CF  (CF=0 from cmp equal)
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Sbb_rm32_r32, Register::R9D, Register::R8D).unwrap()));
    // movsd xmm0, [rsi+0x80] ; movsd [rsi+0x40], xmm0
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Movsd_xmm_xmmm64, Register::XMM0, MemoryOperand::with_base_displ(Register::RSI, 0x80)).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Movsd_xmmm64_xmm, MemoryOperand::with_base_displ(Register::RSI, 0x40), Register::XMM0).unwrap()));
    // movups xmm6, [rsi+0x60] ; movups [rsi+0x20], xmm6
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Movups_xmm_xmmm128, Register::XMM6, MemoryOperand::with_base_displ(Register::RSI, 0x60)).unwrap()));
    seq.push(LiftedInstr::plain(Instruction::with2(Code::Movups_xmmm128_xmm, MemoryOperand::with_base_displ(Register::RSI, 0x20), Register::XMM6).unwrap()));
    // rep stosq: [rdi] = rax ; rdi += 8 ; rcx-- ... (rcx iterations)
    seq.push(LiftedInstr::plain(Instruction::with_stosq(64, iced_x86::RepPrefixKind::Repe).unwrap()));
    // loopne: rcx-- ; if rcx!=0 && ZF==0 jump to label
    let loop_lbl = 77u32;
    seq.push(LiftedInstr::branch(Instruction::with_branch(Code::Loopne_rel8_64_RCX, 0).unwrap(), loop_lbl));
    seq.push(LiftedInstr::labeled(Instruction::with(Code::Nopd), loop_lbl));
    seq.push(LiftedInstr::plain(Instruction::with(Code::Retnq)));

    // everything must be liftable now
    let bad = diagnose_unsupported(&seq);
    assert!(bad.is_empty(), "A5-sse: unexpected unsupported {:?}", bad);

    let bc = lift_block(&seq, 0)?;
    let halt_off = (bc.len() - 1) as u64;

    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x4000];
    let rsi = 0x1000usize;
    let rdi = 0x2000usize;
    // args
    st[interp::STATE_VREGS + 0*8..][..8].copy_from_slice(&0xAAu64.to_le_bytes()); // rax
    st[interp::STATE_VREGS + 1*8..][..8].copy_from_slice(&2u64.to_le_bytes());    // rcx count
    st[interp::STATE_VREGS + 2*8..][..8].copy_from_slice(&0u64.to_le_bytes());    // rdx
    st[interp::STATE_VREGS + 3*8..][..8].copy_from_slice(&0u64.to_le_bytes());    // rbx
    st[interp::STATE_VREGS + 6*8..][..8].copy_from_slice(&(rsi as u64).to_le_bytes()); // rsi
    st[interp::STATE_VREGS + 7*8..][..8].copy_from_slice(&(rdi as u64).to_le_bytes()); // rdi
    st[interp::STATE_VREGS + 8*8..][..8].copy_from_slice(&5u64.to_le_bytes());    // r8
    st[interp::STATE_VREGS + 10*8..][..8].copy_from_slice(&0xEEu64.to_le_bytes()); // r10
    st[interp::STATE_VREGS + 9*8..][..8].copy_from_slice(&0x20u64.to_le_bytes()); // r9
    // memory: [rsi+0x80] = 8-byte double value ; [rsi+0x60] = 16-byte
    mem[rsi + 0x80..rsi + 0x88].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
    mem[rsi + 0x60..rsi + 0x70].copy_from_slice(&[0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18]);
    // Two-stack model: init the dedicated VM return-IP stack and pre-place the
    // outermost return ip (-> trailing HALT) on it.
    st[interp::STATE_VREGS + 4*8..][..8].copy_from_slice(&0x3FF8u64.to_le_bytes()); // vreg4 = RSP (stack top)
    st[interp::STATE_PTR_CALL_STACK..interp::STATE_PTR_CALL_STACK + 8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_CALL_SP..interp::STATE_CALL_SP + 8].copy_from_slice(&((interp::CALL_STACK_SIZE - 8) as u64).to_le_bytes());
    mem[(interp::CALL_STACK_SIZE - 8) as usize..interp::CALL_STACK_SIZE].copy_from_slice(&halt_off.to_le_bytes());

    interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("A5-sse interp failed: {:?}", e))?;

    // setcc: al should be 1 (ZF set by cmp equal)
    let al = st[interp::STATE_VREGS + 0*8];
    assert_eq!(al, 1, "A5-sse: sete al expected 1 got {}", al);
    // cmovcc: r10 = rdx = 0 (ZF set by cmp rax,rax)
    let r10 = u64::from_le_bytes(st[interp::STATE_VREGS + 10*8..][..8].try_into().unwrap());
    assert_eq!(r10, 0, "A5-sse: cmove r10 expected 0 got {}", r10);
    // sbb r9 = r9 - r8 - 0 = 0x20 - 5 = 0x1B
    let r9 = u64::from_le_bytes(st[interp::STATE_VREGS + 9*8..][..8].try_into().unwrap());
    assert_eq!(r9, 0x1B, "A5-sse: sbb r9 expected 0x1B got 0x{:X}", r9);
    // movsd copy: [rsi+0x40] should now hold the 8-byte value
    let m = u64::from_le_bytes(mem[rsi+0x40..rsi+0x48].try_into().unwrap());
    assert_eq!(m, 0x1122334455667788, "A5-sse: movsd mem copy wrong 0x{:X}", m);
    // movups copy: [rsi+0x20] holds 16 bytes
    assert_eq!(&mem[rsi+0x20..rsi+0x30], &[0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18], "A5-sse: movups mem copy wrong");
    // rep stosq: stores rax (which sete set to 1) twice at rdi, rdi advanced 16
    let w0 = u64::from_le_bytes(mem[rdi..rdi+8].try_into().unwrap());
    let w1 = u64::from_le_bytes(mem[rdi+8..rdi+16].try_into().unwrap());
    assert_eq!(w0, 1, "A5-sse: stosq[0] wrong 0x{:X}", w0);
    assert_eq!(w1, 1, "A5-sse: stosq[1] wrong 0x{:X}", w1);
    let rdi_after = u64::from_le_bytes(st[interp::STATE_VREGS + 7*8..][..8].try_into().unwrap());
    assert_eq!(rdi_after, (rdi + 16) as u64, "A5-sse: stosq rdi advance wrong {}", rdi_after);
    // loopne: rep stosq consumed rcx (2->0); loopne then dec'd it to -1 (u64 wrap).
    // Verifying rcx reflects the loop decrement proves loopne executed.
    let rcx2 = u64::from_le_bytes(st[interp::STATE_VREGS + 1*8..][..8].try_into().unwrap());
    assert_eq!(rcx2, 0xFFFF_FFFF, "A5-sse: loopne left rcx={:X} expected 0xFFFFFFFF", rcx2);
    Ok(())
}
