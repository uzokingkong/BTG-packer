// ==============================================================================
// BTG v3 - VM Handler / Dispatch Codegen (x86-64, PIC)
// ==============================================================================
//
// Generates the native x86-64 machine code that executes the VM bytecode:
//
//   [entry stub]  saves caller regs, snapshots the S-box/seed pointers into
//                 the state buffer, sets up VM registers, jumps to dispatch
//   [dispatch]    fetch opcode byte at ip -> handler table -> jmp handler
//   [handlers]    one handler per opcode; each reads its operands from the
//                 bytecode stream at ip (r9), advances ip, jumps back
//
// Register contract inside the VM:
//   r8  = state buffer base      r9  = bytecode ip      r10 = handler table base
//   rax/rcx/rdx/r11 = scratch (clobbered freely)
//
// The generated code is position-independent except for two absolute imm64s in
// the entry stub (bytecode_va, table_va) — the caller supplies real VAs at
// pack time (or test-buffer addresses in the self-test).
//
// ── Module layout (v13.5 refactor) ─────────────────────────────────────────
// This module was split from a single ~2400-line monolith (`generate_vm_code`)
// into submodules, one per instruction family. `mod.rs` keeps the shared
// scaffolding — the `Cl` label enum, shared helpers (hdr, jmp_disp, cap_flags,
// m/vreg/ptrslot, ...), the entry stub + dispatch loop, and the two-pass
// layout/encode — and `generate_vm_code` delegates each `// ── ... ──` section
// to an `emit_*` helper in the family submodule, called in exactly the original
// order so the emitted instruction sequence is byte-identical. The public API
// (`handlers::generate_vm_code`, `validate_vm_code`, `EntryMode`, `VmCode`)
// is unchanged.
// ==============================================================================


use crate::vm::bytecode::*;
use crate::vm::interp::{STATE_CALL_SP, STATE_FLAGS, STATE_PTR_CALL_STACK, STATE_PTR_STACK, STATE_RIP, STATE_SEG_GS, STATE_SP, STATE_XMM};

use anyhow::{Result, anyhow};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};

/// Win64 callee-saved XMM registers that the VM must preserve across a native
/// bridge call (Bug-6 fix). Saved at VM entry and restored at HALT.
const XMM_SAVE: [Register; 10] = [
    Register::XMM6,
    Register::XMM7,
    Register::XMM8,
    Register::XMM9,
    Register::XMM10,
    Register::XMM11,
    Register::XMM12,
    Register::XMM13,
    Register::XMM14,
    Register::XMM15,
];

/// First pointer-slot offset; slots are 8-byte contiguous: SBOX=0x110, SEED=0x118, ...
const PTR_SLOTS_BASE: i64 = 0x110;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Cl {
    Entry,
    Dispatch,
    Invalid,
    Handler(u8),
    JbTaken,
    JccTaken,
    JccNotTaken,
    JccBlk(u8),
    JccDispatch,
    // v50: SETcc condition-evaluation labels (mirror JCC but produce a 0/1 byte)
    SetccDispatch,
    SetccBlk(u8),
    SetccMerge,
    // v24: addressing-mode branch continuations
    LeaNoIndex,
    LeaDone,
    HaltSearchLoop,
    HaltSearchFound,
    // v24: native API bridge
    Bridge,
}

/// Which routine the VM entry stub is wired to execute. The entry stub snapshots
/// different caller registers into the state pointer slots depending on mode:
///   * Ksa     — RCX=state, RBX=sbox base, RDX=seed VA   (snapshot SBOX+SEED slots)
///   * Prga    — RCX=state, RBX=sbox base, RDX=buf, R8=len (snapshot SBOX+BUF, v3=len)
///   * Program — RCX=state (pre-populated by boot stub; no pointer slot clobber)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryMode {
    Ksa,
    Prga,
    Program,
}

/// Result of VM code generation.
#[derive(Debug, Clone)]
pub struct VmCode {
    /// entry + dispatch + handlers machine code
    pub code: Vec<u8>,
    /// offset of the entry stub (== 0)
    pub entry_offset: usize,
    /// offset of the dispatch loop
    pub dispatch_offset: usize,
    /// handler offset per opcode (index 0 = invalid-opcode handler)
    pub handler_offsets: Vec<usize>,
}

/// `[base + disp]` memory operand with an explicitly chosen displacement size
/// (disp8 vs disp32) so measurement matches block encoding.
fn m(base: Register, disp: i32) -> MemoryOperand {
    if (-128..=127).contains(&disp) {
        MemoryOperand::with_base_displ_size(base, disp as i64, 1)
    } else {
        MemoryOperand::with_base_displ_size(base, disp as i64, 8)
    }
}

/// vreg slot: [r8 + idx*8 + STATE_VREGS(0)]
fn vreg(idx: Register) -> MemoryOperand {
    MemoryOperand::with_base_index_scale(Register::R8, idx, 8)
}

/// pointer slot: [r8 + slot*8 + PTR_SLOTS_BASE]
/// NOTE: iced encoder accepts displ_size 0/1/(addr_size/8); in 64-bit mode
/// the full-size displacement is 8 (encodes as disp32).
fn ptrslot(slot: Register) -> MemoryOperand {
    MemoryOperand::with_base_index_scale_displ_size(Register::R8, slot, 8, PTR_SLOTS_BASE, 8)
}

fn jmp_disp() -> Instruction {
    Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap()
}

/// Append a handler: first instruction gets the Handler(op) label.
fn hdr(seq: &mut Vec<(Instruction, Option<Cl>)>, op: u8, body: Vec<Instruction>) {
    let mut it = body.into_iter();
    seq.push((it.next().unwrap(), Some(Cl::Handler(op))));
    for i in it {
        seq.push((i, None));
    }
    seq.push((jmp_disp(), Some(Cl::Dispatch)));
}

/// The VM STATE_FLAGS slot as a memory operand `[r8 + STATE_FLAGS]`, with the
/// displacement size chosen so measurement matches block encoding.
fn state_flags_mem() -> MemoryOperand {
    if (-128..=127).contains(&(STATE_FLAGS as i32)) {
        MemoryOperand::with_base_displ_size(Register::R8, STATE_FLAGS as i64, 1)
    } else {
        MemoryOperand::with_base_displ_size(Register::R8, STATE_FLAGS as i64, 8)
    }
}

/// Capture the CPU status flags just set by an arithmetic op into the VM
/// STATE_FLAGS slot, masked to the modelled flag bits. `full=true` keeps all six
/// bits (ADD/SUB/CMP); `full=false` keeps only ZF/SF/PF (logical AND/XOR —
/// matching flags::logical_flags). Masking to FLAG_MASK keeps the stored word
/// identical to what the interpreter writes.
/// Must be emitted immediately after the result store (mov), before any
/// instruction that changes flags (e.g. `add r9, N`).
fn cap_flags(full: bool) -> Vec<Instruction> {
    let keep = if full { FLAG_MASK } else { F_ZF | F_SF | F_PF };
    vec![
        Instruction::with(Code::Pushfq),
        Instruction::with1(Code::Pop_r64, Register::R11).unwrap(),
        Instruction::with2(Code::And_rm64_imm32, Register::R11, (keep as u32) as i32).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, state_flags_mem(), Register::R11).unwrap(),
    ]
}

/// Capture INC/DEC flags: like cap_flags(true) but CF is *preserved* (x86 INC/DEC
/// do not modify CF). Old CF is read from the VM slot, merged into the new flags,
/// then masked to FLAG_MASK.
fn cap_flags_incdec() -> Vec<Instruction> {
    vec![
        Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(),
        Instruction::with(Code::Pushfq),
        Instruction::with1(Code::Pop_r64, Register::RCX).unwrap(),
        Instruction::with2(Code::And_rm64_imm32, Register::R11, 1).unwrap(),
        // clear CF (bit0) in the new flags: and rcx, -2
        Instruction::with2(Code::And_rm64_imm32, Register::RCX, -2).unwrap(),
        Instruction::with2(Code::Or_rm64_r64, Register::RCX, Register::R11).unwrap(),
        Instruction::with2(Code::And_rm64_imm32, Register::RCX, (FLAG_MASK as u32) as i32).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, state_flags_mem(), Register::RCX).unwrap(),
    ]
}

/// Capture shift flags: like cap_flags(true) but OF and AF are *defined as 0*
/// (x86 leaves OF/AF undefined for shifts; we define them 0 and the interpreter
/// agrees via flags::shift_flags).
fn cap_flags_shift() -> Vec<Instruction> {
    vec![
        Instruction::with(Code::Pushfq),
        Instruction::with1(Code::Pop_r64, Register::R11).unwrap(),
        Instruction::with2(Code::And_rm64_imm32, Register::R11, ((FLAG_MASK & !(F_OF | F_AF)) as u32) as i32).unwrap(),
        Instruction::with2(Code::Mov_rm64_r64, state_flags_mem(), Register::R11).unwrap(),
    ]
}

/// Generate the VM machine code.
/// - `code_va`: VA where `code` will be loaded
/// - `bytecode_va`: VA of the bytecode array (embedded in the entry stub)
/// - `table_va`: VA of the 8-byte handler table (embedded in the entry stub)
/// M8: MBA-obfuscated VM handler table.
///
/// When `mba_key` is `Some((a, b))`, the handler table stores each handler's
/// absolute address XOR-encrypted with `K = a + b (mod 2^64)`. The dispatch loop
/// derives `K` at runtime from the two embedded immediates via the MBA identity
/// `a + b == (a ^ b) + 2 * (a & b)`, then XORs the loaded entry before `jmp` — so
/// `K` never appears as a single plaintext constant, and the handler addresses in
/// the dumped table are not directly readable. `None` keeps the original (plain)
/// dispatch, byte-identical to pre-M8 output.
pub fn generate_vm_code(
    code_va: u64,
    bytecode_va: u64,
    table_va: u64,
    mode: EntryMode,
    mba_key: Option<(u64, u64)>,
) -> Result<VmCode> {
    let mut seq: Vec<(Instruction, Option<Cl>)> = Vec::new();

    // ── Entry stub ─────────────────────────────────────────────────────────────
    // Preserve ALL callee-saved GPRs (rbx, rbp, rsi, rdi, r12-r15) for the native
    // caller across the whole VM invocation. The bridge (OP_NATIVE_CALL) clobbers
    // rbp/r12-r15 (loading the lifted RBP/RSP vregs into the physical registers
    // and saving the VM infra there), so without this save/restore the caller's
    // rbp is left as the (possibly zeroed) RBP vreg — a null-frame write fault on
    // return (seen as run_self_test [13] "stack overflow" on Windows).
    // Push order (bottom->top): RAX,RCX,RDX,RBX,RBP,RSI,RDI,R8,R9,R10,R11,R15,R14,R13,R12.
    // Bug-6 fix: also save the Win64 callee-saved XMM6..XMM15 (160 bytes) first.
    // 160 is a multiple of 16, so RSP%16 is unchanged before the GPR pushes below.
    seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, 0xA0).unwrap(), Some(Cl::Entry)));
    for (i, xr) in XMM_SAVE.iter().enumerate() {
        seq.push((
            Instruction::with2(
                Code::Movdqu_xmmm128_xmm,
                MemoryOperand::with_base_displ(Register::RSP, (i * 16) as i64),
                *xr,
            )
            .unwrap(),
            None,
        ));
    }
    seq.push((Instruction::with1(Code::Push_r64, Register::RAX).unwrap(), None));
    for r in [
        Register::RCX,
        Register::RDX,
        Register::RBX,
        Register::RBP,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
    ] {
        seq.push((Instruction::with1(Code::Push_r64, r).unwrap(), None));
    }
    for r in [Register::R15, Register::R14, Register::R13, Register::R12] {
        seq.push((Instruction::with1(Code::Push_r64, r).unwrap(), None));
    }
    // rcx = state buffer (caller convention); snapshot native pointers if Ksa/Prga
    match mode {
        EntryMode::Ksa => {
            seq.push((
                Instruction::with2(Code::Mov_rm64_r64, m(Register::RCX, 0x110), Register::RBX).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Mov_rm64_r64, m(Register::RCX, 0x118), Register::RDX).unwrap(),
                None,
            ));
        }
        EntryMode::Prga => {
            seq.push((
                Instruction::with2(Code::Mov_rm64_r64, m(Register::RCX, 0x110), Register::RBX).unwrap(),
                None,
            ));
            seq.push((
                Instruction::with2(Code::Mov_rm64_r64, m(Register::RCX, 0x120), Register::RDX).unwrap(),
                None,
            ));
            // v3 = R8 (buffer length); VREGS+3*8 = 0 + 24 = 24
            seq.push((
                Instruction::with2(Code::Mov_rm64_r64, m(Register::RCX, 24), Register::R8).unwrap(),
                None,
            ));
        }
        EntryMode::Program => {
            // Program VM: pointer slots and vregs are pre-loaded by boot stub into state buffer.
            // Do NOT clobber state slots with caller RBX/RDX.
        }
    }
    seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::RCX).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R9, bytecode_va).unwrap(), None));
    seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R10, table_va).unwrap(), None));
    seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Cl::Dispatch)));

    // ── Dispatch loop ───────────────────────────────────────────────────────────
    seq.push((
        Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, MemoryOperand::with_base(Register::R9)).unwrap(),
        Some(Cl::Dispatch),
    ));
    seq.push((Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(), None));
    seq.push((
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base_index_scale(Register::R10, Register::RAX, 8),
        )
        .unwrap(),
        None,
    ));
    // M8: MBA handler-table decryption. K = a + b (mod 2^64); derive via the MBA
    // identity  a + b == (a ^ b) + 2 * (a & b)  so K is not a plaintext constant.
    // Preserve RCX and RDX across MBA computation to avoid clobbering caller/VM registers.
    if let Some((a, b)) = mba_key {
        seq.push((Instruction::with1(Code::Push_r64, Register::RCX).unwrap(), None));
        seq.push((Instruction::with1(Code::Push_r64, Register::RDX).unwrap(), None));
        // r11 = a (scratch); rcx = b
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::R11, a).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_imm64, Register::RCX, b).unwrap(), None));
        // rdx = a & b
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::And_rm64_r64, Register::RDX, Register::RCX).unwrap(), None));
        // rdx = 2 * (a & b)
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RDX, Register::RDX).unwrap(), None));
        // r11 = a ^ b
        seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::R11, Register::RCX).unwrap(), None));
        // r11 = (a ^ b) + 2*(a & b) == a + b == K
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::R11, Register::RDX).unwrap(), None));
        // rax ^= K  (decrypt handler entry)
        seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R11).unwrap(), None));
        seq.push((Instruction::with1(Code::Pop_r64, Register::RDX).unwrap(), None));
        seq.push((Instruction::with1(Code::Pop_r64, Register::RCX).unwrap(), None));
    }
    seq.push((Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap(), None));

    // ── Invalid opcode handler (table[0]) ───────────────────────────────────────
    seq.push((Instruction::with(Code::Ud2), Some(Cl::Invalid)));

    // ── Handlers ────────────────────────────────────────────────────────────────
    // Each `// ── ... ──` section of the original monolith became an `emit_*`
    // helper in one of the family submodules, invoked here in the EXACT original
    // order so the emitted instruction sequence (and every Cl label) is preserved.
    mov::emit_mov_r_imm32(&mut seq);
    mov::emit_mov_r_imm64(&mut seq);
    mov::emit_mov_r_r(&mut seq);
    alu::emit_alu_rr(&mut seq);
    alu::emit_alu_imm32(&mut seq);
    alu::emit_rol_r_imm8(&mut seq);
    alu::emit_ror_r_imm8(&mut seq);
    alu::emit_inc_dec(&mut seq);
    alu::emit_cmp_r_imm32(&mut seq);
    mem::emit_movzx_r_mem8(&mut seq);
    mem::emit_mov_mem8_r(&mut seq);
    branch::emit_jmp8(&mut seq);
    branch::emit_jb8(&mut seq);
    branch::emit_jcc(&mut seq);
    branch::emit_setcc(&mut seq);
    mov::emit_mov_r_r64(&mut seq);
    alu::emit_alu_rr64(&mut seq);
    alu::emit_alu_imm64(&mut seq);
    alu::emit_shift_imm8_32(&mut seq);
    alu::emit_shift_cl_32(&mut seq);
    alu::emit_test(&mut seq);
    mov::emit_mem_loads_wider(&mut seq);
    mov::emit_mem_stores_wider(&mut seq);
    stack::emit_push_r(&mut seq);
    stack::emit_pop_r(&mut seq);
    stack::emit_call8(&mut seq);
    stack::emit_ret(&mut seq);
    mem::emit_lea(&mut seq);
    mem::emit_set_rip(&mut seq);
    mem::emit_lea_rip(&mut seq);
    mem::emit_lea_gs(&mut seq);
    mem::emit_mem_loads_abs(&mut seq);
    mem::emit_mem_stores_abs(&mut seq);
    atomic::emit_cmpxchg(&mut seq);
    atomic::emit_xchg(&mut seq);
    atomic::emit_xadd(&mut seq);
    stack::emit_native_call(&mut seq);
    alu::emit_or_rr(&mut seq);
    alu::emit_or_imm(&mut seq);
    alu::emit_neg(&mut seq);
    alu::emit_not(&mut seq);
    alu::emit_shift_imm8_64(&mut seq);
    alu::emit_shift_cl_64(&mut seq);
    alu::emit_nop(&mut seq);
    xmm::emit_movsd_xmm_mem(&mut seq);
    xmm::emit_movsd_mem_xmm(&mut seq);
    xmm::emit_movq_xmm_gpr(&mut seq);
    xmm::emit_movq_gpr_xmm(&mut seq);
    xmm::emit_movups_xmm_mem(&mut seq);
    xmm::emit_movups_mem_xmm(&mut seq);
    xmm::emit_unpcklpd(&mut seq);
    xmm::emit_unpcklps(&mut seq);
    xmm::emit_xorps(&mut seq);
    xmm::emit_pshuflw(&mut seq);
    xmm::emit_pshufhw(&mut seq);
    xmm::emit_pshufd(&mut seq);
    xmm::emit_psrlq(&mut seq);
    xmm::emit_psllq(&mut seq);
    xmm::emit_pinsrw(&mut seq);
    alu::emit_cpuid(&mut seq);
    alu::emit_xgetbv(&mut seq);
    alu::emit_tzcnt(&mut seq);
    alu::emit_lzcnt(&mut seq);
    alu::emit_popcnt(&mut seq);
    alu::emit_blsr(&mut seq);
    alu::emit_blsmsk(&mut seq);
    alu::emit_blsi(&mut seq);
    alu::emit_andn(&mut seq);
    stack::emit_ret_imm16(&mut seq);
    muldiv::emit_mul_rr64(&mut seq);
    muldiv::emit_mul_rr32(&mut seq);
    muldiv::emit_imul1_rr64(&mut seq);
    muldiv::emit_imul1_rr32(&mut seq);
    muldiv::emit_div_rr64(&mut seq);
    muldiv::emit_div_rr32(&mut seq);
    muldiv::emit_idiv_rr64(&mut seq);
    muldiv::emit_idiv_rr32(&mut seq);
    muldiv::emit_bswap32(&mut seq);
    muldiv::emit_bswap64(&mut seq);
    muldiv::emit_bsr_bsf(&mut seq);
    muldiv::emit_mul_rr8(&mut seq);
    muldiv::emit_mul_rr16(&mut seq);
    muldiv::emit_imul1_rr8(&mut seq);
    muldiv::emit_imul1_rr16(&mut seq);
    muldiv::emit_div_rr8(&mut seq);
    muldiv::emit_div_rr16(&mut seq);
    muldiv::emit_idiv_rr8(&mut seq);
    muldiv::emit_idiv_rr16(&mut seq);
    branch::emit_halt(&mut seq);

    // ── Two-pass layout: measure each instruction, assign IPs / labels ─────────
    let mut ip = code_va;
    let mut label_ips: std::collections::HashMap<Cl, u64> = std::collections::HashMap::new();
    for (inst, lbl) in &seq {
        let mut m2 = *inst;
        if lbl.is_some() && is_branch_code(inst.code()) {
            m2 = Instruction::with_branch(inst.code(), ip).unwrap();
        }
        let len = measure(&m2, ip);
        if let Some(l) = lbl {
            if !is_branch_code(inst.code()) {
                label_ips.insert(*l, ip);
            }
        }
        ip += len as u64;
    }

    // ── Resolve branches and encode the whole block ─────────────────────────────
    let mut insts: Vec<Instruction> = Vec::with_capacity(seq.len());
    for (inst, lbl) in &seq {
        let mut m2 = *inst;
        if let Some(l) = lbl {
            if is_branch_code(inst.code()) {
                let target = label_ips[l];
                m2 = Instruction::with_branch(inst.code(), target).unwrap();
            }
        }
        insts.push(m2);
    }

    let block = InstructionBlock::new(&insts, code_va);
    let enc = BlockEncoder::encode(64, block, BlockEncoderOptions::DONT_FIX_BRANCHES)
        .map_err(|e| anyhow!("VM code BlockEncoder failed: {}", e))?;
    let code = enc.code_buffer;
    let expected = (ip - code_va) as usize;
    if code.len() != expected {
        return Err(anyhow!(
            "VM code length mismatch: measured {} vs encoded {}",
            expected,
            code.len()
        ));
    }

    let offsets: std::collections::HashMap<Cl, usize> = label_ips
        .into_iter()
        .map(|(l, va)| (l, (va - code_va) as usize))
        .collect();

    Ok(VmCode {
        entry_offset: offsets[&Cl::Entry],
        dispatch_offset: offsets[&Cl::Dispatch],
        handler_offsets: (0..NUM_OPS)
            .map(|op| {
                if op == 0 {
                    offsets[&Cl::Invalid]
                } else {
                    offsets[&Cl::Handler(op as u8)]
                }
            })
            .collect(),
        code,
    })
}

fn measure(inst: &Instruction, ip: u64) -> usize {
    let arr = [*inst];
    let block = InstructionBlock::new(&arr, ip);
    match BlockEncoder::encode(64, block, BlockEncoderOptions::DONT_FIX_BRANCHES) {
        Ok(res) => res.code_buffer.len(),
        Err(_) => {
            if inst.len() > 0 {
                inst.len()
            } else {
                5
            }
        }
    }
}

fn is_branch_code(code: Code) -> bool {
    matches!(
        code,
        Code::Jmp_rel32_64 | Code::Jne_rel32_64 | Code::Jb_rel32_64 | Code::Je_rel32_64
    )
}

/// Decode-validate the generated code (used by the self-test): every byte
/// must decode to valid instructions, and the code must contain a ret.
pub fn validate_vm_code(code: &[u8]) -> Result<()> {
    use iced_x86::{Decoder, DecoderOptions};
    let mut dec = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
    let mut found_ret = false;
    while dec.can_decode() {
        let inst = dec.decode();
        if inst.is_invalid() {
            return Err(anyhow!("VM code: invalid instruction at offset 0x{:X}", dec.ip()));
        }
        if inst.code() == Code::Retnq {
            found_ret = true;
        }
    }
    if !found_ret {
        return Err(anyhow!("VM code: no ret found"));
    }
    Ok(())
}

mod alu;
mod atomic;
mod branch;
mod mem;
mod mov;
mod muldiv;
mod stack;
mod xmm;
