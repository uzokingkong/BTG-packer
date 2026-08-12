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
enum Cl {
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

    // `with_base_displ` forces displ_size=1 (disp8) even for values that don't
    // fit an i8, which makes standalone measurement diverge from block encoding.
    // Pick the displacement size explicitly so measure() == block layout.
    let m = |base: Register, disp: i32| {
        if (-128..=127).contains(&disp) {
            MemoryOperand::with_base_displ_size(base, disp as i64, 1)
        } else {
            MemoryOperand::with_base_displ_size(base, disp as i64, 8)
        }
    };
    // vreg slot: [r8 + idx*8 + STATE_VREGS(0)]
    let vreg = |idx: Register| MemoryOperand::with_base_index_scale(Register::R8, idx, 8);
    // pointer slot: [r8 + slot*8 + PTR_SLOTS_BASE]
    // NOTE: iced encoder accepts displ_size 0/1/(addr_size/8); in 64-bit mode
    // the full-size displacement is 8 (encodes as disp32).
    let ptrslot = |slot: Register| {
        MemoryOperand::with_base_index_scale_displ_size(Register::R8, slot, 8, PTR_SLOTS_BASE, 8)
    };

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

    // ── 0x01 MOV_R_IMM32  (op, r, imm32) ────────────────────────────────────────
    hdr(
        &mut seq,
        OP_MOV_R_IMM32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap(),
        ],
    );
    // ── 0x02 MOV_R_IMM64  (op, r, imm64) ────────────────────────────────────────
    hdr(
        &mut seq,
        OP_MOV_R_IMM64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 9).unwrap(),
        ],
    );
    // ── 0x03 MOV_R_R  (op, dst, src) ────────────────────────────────────────────
    hdr(
        &mut seq,
        OP_MOV_R_R,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // ── 0x04-0x07 + 0x15 XOR/ADD/IMUL/SUB/AND r,r  (op, dst, src) ─────────────
    // fmod: 0 = no flags (IMUL), 1 = full flags (ADD/SUB), 2 = logical (XOR/AND)
    for (op, code, fmod) in [
        (OP_XOR_R_R, Code::Xor_rm32_r32, 2),
        (OP_ADD_R_R, Code::Add_rm32_r32, 1),
        (OP_IMUL_R_R, Code::Imul_r32_rm32, 0),
        (OP_SUB_R_R, Code::Sub_rm32_r32, 1),
        (OP_AND_R_R, Code::And_rm32_r32, 2),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(code, Register::EAX, Register::EDX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        ];
        match fmod {
            1 => body.extend(cap_flags(true)),
            2 => body.extend(cap_flags(false)),
            _ => {}
        }
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(&mut seq, op, body);
    }
    // ── 0x08-0x0A AND/XOR/ADD r,imm32  (op, r, imm32) — fmod 1=full 2=logical ──
    for (op, code, fmod) in [
        (OP_AND_R_IMM32, Code::And_rm32_r32, 2),
        (OP_XOR_R_IMM32, Code::Xor_rm32_r32, 2),
        (OP_ADD_R_IMM32, Code::Add_rm32_r32, 1),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(code, Register::EAX, Register::EDX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        ];
        if fmod == 1 {
            body.extend(cap_flags(true));
        } else {
            body.extend(cap_flags(false));
        }
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap());
        hdr(&mut seq, op, body);
    }
    // ── 0x0B ROL r,imm8  (op, r, imm8) ──────────────────────────────────────────
    hdr(
        &mut seq,
        OP_ROL_R_IMM8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::ECX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
            Instruction::with2(Code::Rol_rm32_CL, Register::EAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // ── 0x14 ROR r,imm8  (op, r, imm8) — v10 (강화된 key_mix의 ror) ────────────
    hdr(
        &mut seq,
        OP_ROR_R_IMM8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::ECX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
            Instruction::with2(Code::Ror_rm32_CL, Register::EAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // ── 0x0C / 0x0D INC/DEC r  (op, r) — sets flags, CF preserved ─────────────
    for (op, code) in [(OP_INC_R, Code::Inc_rm32), (OP_DEC_R, Code::Dec_rm32)] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with1(code, vreg(Register::RCX)).unwrap(),
        ];
        body.extend(cap_flags_incdec());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap());
        hdr(&mut seq, op, body);
    }
    // ── 0x0E CMP r,imm32  (op, r, imm32) — sets full flags ────────────────────
    {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Cmp_rm32_r32, Register::EAX, Register::EDX).unwrap(),
        ];
        body.extend(cap_flags(true));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap());
        hdr(&mut seq, OP_CMP_R_IMM32, body);
    }
    // ── 0x0F MOVZX r, byte [ptr[slot] + vreg[idx]] (op, dst, slot, idx) ────────
    hdr(
        &mut seq,
        OP_MOVZX_R_MEM8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RAX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, ptrslot(Register::RDX)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, MemoryOperand::with_base_index_scale(Register::R11, Register::RAX, 1)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
        ],
    );
    // ── 0x10 MOV byte [ptr[slot] + vreg[idx]], r8 (op, slot, idx, src) ─────────
    hdr(
        &mut seq,
        OP_MOV_MEM8_R,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, ptrslot(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RAX)).unwrap(),
            Instruction::with2(Code::Mov_rm8_r8, MemoryOperand::with_base_index_scale(Register::R11, Register::RCX, 1), Register::AL).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
        ],
    );
    // ── 0x11 JMP8 rel ───────────────────────────────────────────────────────────
    hdr(
        &mut seq,
        OP_JMP8,
        vec![
            Instruction::with2(Code::Movsx_r64_rm8, Register::RAX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::RAX).unwrap(),
        ],
    );
    // ── 0x12 JB8 rel (uses CF flag slot) ────────────────────────────────────────
    {
        seq.push((
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R8, STATE_FLAGS as i32)).unwrap(),
            Some(Cl::Handler(OP_JB8)),
        ));
        seq.push((Instruction::with2(Code::Test_rm8_imm8, Register::AL, 1).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jne_rel32_64, 0).unwrap(), Some(Cl::JbTaken)));
        seq.push((Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
        seq.push((
            Instruction::with2(Code::Movsx_r64_rm8, Register::RAX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Some(Cl::JbTaken),
        ));
        seq.push((Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::RAX).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }
    // ── 0x16 JCC8 cond, rel8 (M1: full x86 conditional-branch model) ──────────
    // Evaluates the condition against the VM STATE_FLAGS slot and branches.
    // The cond byte selects one of 14 sub-blocks; each builds the boolean in
    // registers (no popfq/pushfq), then jumps to the shared taken/not epilogues.
    {
        // (cond_id, native Jcc to emit for "taken" when the flag bit is set)
        // Each simple condition = test a single flag bit.
        let simple: [(u8, Code, u64, bool); 10] = [
            // cond, branch-taken jcc, flag bit, bit-set-means-taken
            (COND_JE, Code::Jne_rel32_64, F_ZF, true),
            (COND_JNE, Code::Je_rel32_64, F_ZF, false),
            (COND_JB, Code::Jne_rel32_64, F_CF, true),
            (COND_JAE, Code::Je_rel32_64, F_CF, false),
            (COND_JS, Code::Jne_rel32_64, F_SF, true),
            (COND_JNS, Code::Je_rel32_64, F_SF, false),
            (COND_JO, Code::Jne_rel32_64, F_OF, true),
            (COND_JNO, Code::Je_rel32_64, F_OF, false),
            (COND_JP, Code::Jne_rel32_64, F_PF, true),
            (COND_JNP, Code::Je_rel32_64, F_PF, false),
        ];
        let signed: [(u8, bool, bool); 4] = [
            // (cond, test_zf_or_delta, taken_when_zero)
            (COND_JG, true, true),   // JG:  test (ZF||delta), taken when ==0
            (COND_JGE, false, true), // JGE: test delta,        taken when ==0
            (COND_JL, false, false), // JL:  test delta,        taken when !=0
            (COND_JLE, true, false), // JLE: test (ZF||delta),  taken when !=0
        ];
        // delta = SF ^ OF ; zf = ZF flag.
        // We build r11 = (ZF || delta) as a 0/1-style non-zero value, and
        // rdx = delta as non-zero/zero. Then branch accordingly.

        // ── M5 (v30): rel32 branch handlers ────────────────────────────────
        // JCC32 shares the JCC8 cond-dispatch: set up rdx=taken-ip/r9=fallthrough
        // with a 4-byte rel, then jump into the shared dispatch chain.
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(), Some(Cl::Handler(OP_JCC32))));
        seq.push((Instruction::with2(Code::Movsxd_r64_rm32, Register::RDX, m(Register::R9, 1)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RDX, Register::R9).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::JccDispatch)));
        // JMP32 rel32: r9 += 4 + rel
        hdr(
            &mut seq,
            OP_JMP32,
            vec![
                Instruction::with2(Code::Movsxd_r64_rm32, Register::RAX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 4).unwrap(),
                Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::RAX).unwrap(),
            ],
        );
        // CALL32 rel32: push r9+4 (bytecode return IP) onto the VM return-IP stack
        // (STATE_CALL_SP); r9 += 4 + rel. (Two-stack model — see CALL8.)
        {
            seq.push((
                Instruction::with2(Code::Movsxd_r64_rm32, Register::RAX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Some(Cl::Handler(OP_CALL32)),
            ));
            seq.push((Instruction::with2(Code::Lea_r64_m, Register::RDX, MemoryOperand::with_base_displ(Register::R9, 4)).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, STATE_CALL_SP as i32)).unwrap(), None));
            seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::R11, 8).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, STATE_CALL_SP as i32), Register::R11).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::R8, STATE_PTR_CALL_STACK as i32)).unwrap(), None));
            seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::R11).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base(Register::RCX), Register::RDX).unwrap(), None));
            seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 4).unwrap(), None));
            seq.push((Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::RAX).unwrap(), None));
            seq.push((jmp_disp(), Some(Cl::Dispatch)));
        }

        // Handler entry: r9 -> (cond, rel)
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(), Some(Cl::Handler(OP_JCC8))));
        // rdx = sign-extended rel; r9 += 2 -> fallthrough ip
        seq.push((Instruction::with2(Code::Movsx_r64_rm8, Register::RDX, m(Register::R9, 1)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(), None));
        // taken ip = fallthrough + rel  (rdx = rel now, add fallthrough)
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RDX, Register::R9).unwrap(), None));

        // cond dispatch chain: cmp ecx,cond ; je block
        let unsigned: [(u8, Code, bool); 2] = [
            (COND_JA, Code::Je_rel32_64, false),   // taken when (CF|ZF)==0
            (COND_JBE, Code::Jne_rel32_64, true),  // taken when (CF|ZF)!=0
        ];
        let dispatch_conds = simple.iter().map(|(c, ..)| *c)
            .chain(signed.iter().map(|(c, ..)| *c))
            .chain(unsigned.iter().map(|(c, ..)| *c));
        let conds: Vec<u8> = dispatch_conds.collect();
        for (i, c) in conds.iter().enumerate() {
            let lbl = if i == 0 { Some(Cl::JccDispatch) } else { None };
            seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::ECX, *c as i32).unwrap(), lbl));
            seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Cl::JccBlk(*c))));
        }
        // unknown cond: treat as not taken (jump to not-taken epilogue)
        seq.push((jmp_disp(), Some(Cl::JccNotTaken)));

        // simple single-bit blocks
        for (cond, cc, bit, _) in &simple {
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(), Some(Cl::JccBlk(*cond))));
            seq.push((Instruction::with2(Code::Test_rm64_imm32, Register::R11, *bit as i32).unwrap(), None));
            seq.push((Instruction::with_branch(*cc, 0).unwrap(), Some(Cl::JccTaken)));
            seq.push((jmp_disp(), Some(Cl::JccNotTaken)));
        }

        // signed blocks (JG/JGE/JL/JLE). delta = SF^OF ; zf = ZF flag.
        // RAX ends with the tested boolean; branch per config.
        for (cond, test_zf_or_delta, taken_when_zero) in &signed {
            // r11 = flags ; rax = SF
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(), Some(Cl::JccBlk(*cond))));
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 7).unwrap(), None));
            seq.push((Instruction::with2(Code::Shr_rm64_CL, Register::RAX, Register::CL).unwrap(), None));
            seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).unwrap(), None));
            // rsi = OF
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 11).unwrap(), None));
            seq.push((Instruction::with2(Code::Shr_rm64_CL, Register::RSI, Register::CL).unwrap(), None));
            seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RSI, 1).unwrap(), None));
            // rax = delta = SF^OF
            seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RSI).unwrap(), None));
            // rsi = ZF (nonzero iff ZF set)
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(), None));
            seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RSI, F_ZF as i32).unwrap(), None));
            if *test_zf_or_delta {
                // test (ZF||delta): OR ZF into rax(delta)
                seq.push((Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RSI).unwrap(), None));
            }
            seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
            let cc = if *taken_when_zero { Code::Je_rel32_64 } else { Code::Jne_rel32_64 };
            seq.push((Instruction::with_branch(cc, 0).unwrap(), Some(Cl::JccTaken)));
            seq.push((jmp_disp(), Some(Cl::JccNotTaken)));
        }

        // unsigned combined conditions: JA (cond 14) and JBE (cond 15).
        // JA = !CF && !ZF  (above); JBE = CF || ZF (below/equal).
        // Build RAX = CF|ZF as 0/1, then branch taken iff (CF|ZF) is zero (JA)
        // or nonzero (JBE).
        for (cond, cc, _nonzero) in &unsigned {
            // r11 = flags ; rax = CF (bit 0)
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(), Some(Cl::JccBlk(*cond))));
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap(), None));
            seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RAX, F_CF as i32).unwrap(), None));
            // rsi = ZF (bit 6), OR into rax -> rax = CF|ZF
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(), None));
            seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RSI, F_ZF as i32).unwrap(), None));
            seq.push((Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RSI).unwrap(), None));
            seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
            seq.push((Instruction::with_branch(*cc, 0).unwrap(), Some(Cl::JccTaken)));
            seq.push((jmp_disp(), Some(Cl::JccNotTaken)));
        }

        // taken epilogue: r9 = taken ip (rdx holds it)
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::RDX).unwrap(), Some(Cl::JccTaken)));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
        // not-taken epilogue: r9 already = fallthrough (label on a non-branch)
        seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::R11, Register::R11).unwrap(), Some(Cl::JccNotTaken)));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }

    // ── v50: 0x89 SETCC (dst_vreg, cond) — writes ONLY the low byte, preserves
    // STATE_FLAGS (x86 setcc is a partial-register write that does not modify
    // flags). Evaluates cond against STATE_FLAGS, producing a 0/1, then merges
    // it into the low byte of the destination vreg. Never writes STATE_FLAGS,
    // so a following cmovcc/sbb reads the flags the setcc's source cmp set.
    {
        // entry: edi = dst vreg (preserved across cond blocks), edx = cond; r9 += 2
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EDI, MemoryOperand::with_base(Register::R9)).unwrap(), Some(Cl::Handler(OP_SETCC))));
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(), None));

        // cond dispatch chain: cmp edx,cond ; je SetccBlk(cond)
        let simple: [(u8, Code, u64, bool); 10] = [
            (COND_JE, Code::Setne_rm8, F_ZF, true),
            (COND_JNE, Code::Sete_rm8, F_ZF, false),
            (COND_JB, Code::Setne_rm8, F_CF, true),
            (COND_JAE, Code::Sete_rm8, F_CF, false),
            (COND_JS, Code::Setne_rm8, F_SF, true),
            (COND_JNS, Code::Sete_rm8, F_SF, false),
            (COND_JO, Code::Setne_rm8, F_OF, true),
            (COND_JNO, Code::Sete_rm8, F_OF, false),
            (COND_JP, Code::Setne_rm8, F_PF, true),
            (COND_JNP, Code::Sete_rm8, F_PF, false),
        ];
        let signed: [(u8, bool, bool); 4] = [
            (COND_JG, true, true),   // test (ZF||delta), taken when ==0
            (COND_JGE, false, true), // test delta,        taken when ==0
            (COND_JL, false, false), // test delta,        taken when !=0
            (COND_JLE, true, false), // test (ZF||delta),  taken when !=0
        ];
        let unsigned: [(u8, Code); 2] = [
            (COND_JA, Code::Sete_rm8),   // taken when (CF|ZF)==0
            (COND_JBE, Code::Setne_rm8), // taken when (CF|ZF)!=0
        ];
        let dispatch_conds: Vec<u8> = simple.iter().map(|(c, ..)| *c)
            .chain(signed.iter().map(|(c, ..)| *c))
            .chain(unsigned.iter().map(|(c, ..)| *c))
            .collect();
        for (i, c) in dispatch_conds.iter().enumerate() {
            let lbl = if i == 0 { Some(Cl::SetccDispatch) } else { None };
            seq.push((Instruction::with2(Code::Cmp_rm32_imm32, Register::EDX, *c as i32).unwrap(), lbl));
            seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Cl::SetccBlk(*c))));
        }
        // unknown cond -> treat as set to 0, merge
        seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RAX).unwrap(), Some(Cl::SetccBlk(0xFF))));
        seq.push((jmp_disp(), Some(Cl::SetccMerge)));

        // simple single-bit blocks: load flags, test bit, set AL via setcc
        for (cond, cc, bit, _set) in &simple {
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(), Some(Cl::SetccBlk(*cond))));
            seq.push((Instruction::with2(Code::Test_rm64_imm32, Register::R11, *bit as i32).unwrap(), None));
            seq.push((Instruction::with1(*cc, Register::AL).unwrap(), None));
            seq.push((jmp_disp(), Some(Cl::SetccMerge)));
        }

        // signed blocks: delta = SF^OF ; optionally OR ZF ; test -> set AL
        for (cond, test_zf_or_delta, taken_when_zero) in &signed {
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(), Some(Cl::SetccBlk(*cond))));
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 7).unwrap(), None));
            seq.push((Instruction::with2(Code::Shr_rm64_CL, Register::RAX, Register::CL).unwrap(), None));
            seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RAX, 1).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 11).unwrap(), None));
            seq.push((Instruction::with2(Code::Shr_rm64_CL, Register::RSI, Register::CL).unwrap(), None));
            seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RSI, 1).unwrap(), None));
            seq.push((Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RSI).unwrap(), None)); // rax = delta
            if *test_zf_or_delta {
                seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(), None));
                seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RSI, F_ZF as i32).unwrap(), None));
                seq.push((Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RSI).unwrap(), None));
            }
            let cc = if *taken_when_zero { Code::Sete_rm8 } else { Code::Setne_rm8 };
            seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
            seq.push((Instruction::with1(cc, Register::AL).unwrap(), None));
            seq.push((jmp_disp(), Some(Cl::SetccMerge)));
        }

        // unsigned combined: rax = CF|ZF (0/1), then set AL per JA/JBE
        for (cond, cc) in &unsigned {
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, state_flags_mem()).unwrap(), Some(Cl::SetccBlk(*cond))));
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::R11).unwrap(), None));
            seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RAX, F_CF as i32).unwrap(), None));
            seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R11).unwrap(), None));
            seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RSI, F_ZF as i32).unwrap(), None));
            seq.push((Instruction::with2(Code::Or_rm64_r64, Register::RAX, Register::RSI).unwrap(), None));
            seq.push((Instruction::with2(Code::Test_rm64_r64, Register::RAX, Register::RAX).unwrap(), None));
            seq.push((Instruction::with1(*cc, Register::AL).unwrap(), None));
            seq.push((jmp_disp(), Some(Cl::SetccMerge)));
        }

        // merge: dst = (dst & ~0xFF) | (AL & 1). STATE_FLAGS untouched (setcc must
        // not modify flags). rdi (value) still holds the dst vreg index.
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, Register::AL).unwrap(), Some(Cl::SetccMerge)));
        // [r8 + rdi*8] = dst vreg (rdi holds the *vreg index value*, not the reg)
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, MemoryOperand::with_base_index_scale(Register::R8, Register::RDI, 8)).unwrap(), None));
        seq.push((Instruction::with2(Code::And_rm64_imm32, Register::R11, !0xFFu32 as i32).unwrap(), None)); // clear low byte
        seq.push((Instruction::with2(Code::Or_rm64_r64, Register::R11, Register::RAX).unwrap(), None));       // OR in boolean
        seq.push((Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale(Register::R8, Register::RDI, 8), Register::R11).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }

    // ── M2 (v22) opcodes ─────────────────────────────────────────────────────
    // 0x17 MOV_R_R64 (dst, src) — full 64-bit copy
    hdr(        &mut seq,
        OP_MOV_R_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // 0x18-0x1C 64-bit reg-reg ops (fmod: 1=full, 2=logical, 0=none)
    for (op, code, fmod) in [
        (OP_ADD_R_R64, Code::Add_rm64_r64, 1),
        (OP_SUB_R_R64, Code::Sub_rm64_r64, 1),
        (OP_XOR_R_R64, Code::Xor_rm64_r64, 2),
        (OP_AND_R_R64, Code::And_rm64_r64, 2),
        (OP_IMUL_R_R64, Code::Imul_r64_rm64, 0),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(code, Register::RAX, Register::RDX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        ];
        match fmod {
            1 => body.extend(cap_flags(true)),
            2 => body.extend(cap_flags(false)),
            _ => {}
        }
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(&mut seq, op, body);
    }
    // 0x1D-0x1F 64-bit imm32 (sign-extended)
    for (op, code, fmod) in [
        (OP_ADD_R_IMM64, Code::Add_rm64_r64, 1),
        (OP_XOR_R_IMM64, Code::Xor_rm64_r64, 2),
        (OP_AND_R_IMM64, Code::And_rm64_r64, 2),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movsxd_r64_rm32, Register::RDX, Register::EDX).unwrap(),
            Instruction::with2(code, Register::RAX, Register::RDX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
        ];
        if fmod == 1 {
            body.extend(cap_flags(true));
        } else {
            body.extend(cap_flags(false));
        }
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap());
        hdr(&mut seq, op, body);
    }
    // 0x20-0x22 shifts by imm8 (32-bit)
    for (op, code) in [
        (OP_SHL_R_IMM8, Code::Shl_rm32_CL),
        (OP_SHR_R_IMM8, Code::Shr_rm32_CL),
        (OP_SAR_R_IMM8, Code::Sar_rm32_CL),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::ECX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::R11)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
            Instruction::with2(code, Register::EAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
        ];
        body.extend(cap_flags_shift());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(&mut seq, op, body);
    }
    // 0x23-0x25 shifts by CL (count = vreg[1] & 31, 32-bit)
    for (op, code) in [
        (OP_SHL_R_CL, Code::Shl_rm32_CL),
        (OP_SHR_R_CL, Code::Shr_rm32_CL),
        (OP_SAR_R_CL, Code::Sar_rm32_CL),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::ECX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::R11)).unwrap(),
            // count = vreg[1]
            Instruction::with2(Code::Mov_r32_imm32, Register::EDX, 1).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 31).unwrap(),
            Instruction::with2(code, Register::EAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
        ];
        body.extend(cap_flags_shift());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap());
        hdr(&mut seq, op, body);
    }
    // 0x26 TEST_R_R32 / 0x27 TEST_R_IMM32 (flags from AND, no write)
    {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RAX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EDX).unwrap(),
        ];
        body.extend(cap_flags(false));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(&mut seq, OP_TEST_R_R32, body);
    }
    {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RAX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Test_rm32_r32, Register::EAX, Register::EDX).unwrap(),
        ];
        body.extend(cap_flags(false));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap());
        hdr(&mut seq, OP_TEST_R_IMM32, body);
    }
    // 0x28-0x2C wider / sign-extending memory loads (dst, slot, idx)
    // MOVSX sign-extends to the full 64-bit vreg (matches flags/interp).
    for (op, code, dst) in [
        (OP_MOVZX_R_MEM16, Code::Movzx_r32_rm16, Register::EAX),
        (OP_MOVZX_R_MEM32, Code::Mov_r32_rm32, Register::EAX),
        (OP_MOVSX_R_MEM8, Code::Movsx_r64_rm8, Register::RAX),
        (OP_MOVSX_R_MEM16, Code::Movsx_r64_rm16, Register::RAX),
        (OP_MOV_R_MEM64, Code::Mov_r64_rm64, Register::RAX),
    ] {
        hdr(
            &mut seq,
            op,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RAX)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, ptrslot(Register::RDX)).unwrap(),
                Instruction::with2(code, dst, MemoryOperand::with_base_index_scale(Register::R11, Register::RAX, 1)).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
            ],
        );
    }
    // 0x2D-0x2F wider memory stores (slot, idx, src)
    for (op, store_code, src, load_code) in [
        (OP_MOV_MEM16_R, Code::Mov_rm16_r16, Register::AX, Code::Mov_r16_rm16),
        (OP_MOV_MEM32_R, Code::Mov_rm32_r32, Register::EAX, Code::Mov_r32_rm32),
        (OP_MOV_MEM64_R, Code::Mov_rm64_r64, Register::RAX, Code::Mov_r64_rm64),
    ] {
        hdr(
            &mut seq,
            op,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, ptrslot(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RCX, vreg(Register::RDX)).unwrap(),
                Instruction::with2(load_code, src, vreg(Register::RAX)).unwrap(),
                Instruction::with2(store_code, MemoryOperand::with_base_index_scale(Register::R11, Register::RCX, 1), src).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
            ],
        );
    }

    // ── M3 (v23): stack + call/ret ───────────────────────────────────────────
    // 0x30 PUSH_R (r): sp -= 8; *(stackbase+sp) = vreg[r]
    hdr(
        &mut seq,
        OP_PUSH_R,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, 0x20)).unwrap(),
            Instruction::with2(Code::Sub_rm64_imm32, Register::R11, 8).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x20), Register::R11).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base(Register::R11), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // 0x31 POP_R (r): vreg[r] = *(stackbase+sp); sp += 8
    hdr(
        &mut seq,
        OP_POP_R,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, 0x20)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base(Register::R11)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R11, 8).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x20), Register::R11).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // 0x32 CALL8 (rel8): push r9+1 (bytecode return IP) onto the VM return-IP
    // stack (STATE_CALL_SP); r9 += 1 + rel. The program's observed return VA is
    // pushed to [v4] separately by the lifter before the call (two-stack model).
    {
        seq.push((
            Instruction::with2(Code::Movsx_r64_rm8, Register::RAX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Some(Cl::Handler(OP_CALL8)),
        ));
        seq.push((Instruction::with2(Code::Lea_r64_m, Register::RDX, MemoryOperand::with_base_displ(Register::R9, 1)).unwrap(), None));
        // VM return-IP stack: csp -= 8; addr = base + csp; [addr] = bytecode return ip
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, STATE_CALL_SP as i32)).unwrap(), None));
        seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::R11, 8).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, STATE_CALL_SP as i32), Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::R8, STATE_PTR_CALL_STACK as i32)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RCX, Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base(Register::RCX), Register::RDX).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::R9, Register::RAX).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }
    // 0x33 RET: pop bytecode return IP from the VM return-IP stack (STATE_CALL_SP)
    // into r9; advance the architectural RSP (v4) past the caller's return VA.
    {
        seq.push((
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, STATE_CALL_SP as i32)).unwrap(),
            Some(Cl::Handler(OP_RET)),
        ));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, STATE_PTR_CALL_STACK as i32)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, MemoryOperand::with_base(Register::RAX)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R11, 8).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, STATE_CALL_SP as i32), Register::R11).unwrap(), None));
        // architectural RSP (v4) += 8
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, 0x20)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R11, 8).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x20), Register::R11).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }

    // ── M2 follow-up (v24): addressing modes ─────────────────────────────────
    // 0x34 OP_LEA (dst, base, idx, scale_enc, disp32)
    //   vreg[dst] = vreg[base] + (idx==ADDR_NO_INDEX?0 : vreg[idx]<<scale) + sext(disp32)
    {
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::ESI, MemoryOperand::with_base(Register::R9)).unwrap(), Some(Cl::Handler(OP_LEA))));
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, m(Register::R9, 1)).unwrap(), None));
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 2)).unwrap(), None));
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 3)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(), None));
        seq.push((Instruction::with2(Code::Cmp_rm8_imm8, Register::DL, ADDR_NO_INDEX as i32).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Je_rel32_64, 0).unwrap(), Some(Cl::LeaNoIndex)));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RBX, vreg(Register::RDX)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Shl_rm64_CL, Register::RBX, Register::CL).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::R11, Register::RBX).unwrap(), None));
        seq.push((Instruction::with2(Code::Movsxd_r64_rm32, Register::RAX, m(Register::R9, 4)).unwrap(), Some(Cl::LeaNoIndex)));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::R11, Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RSI), Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 8).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }
    // 0x35 OP_SET_RIP (imm64) — STATE_RIP = imm64
    {
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base(Register::R9)).unwrap(), Some(Cl::Handler(OP_SET_RIP))));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, STATE_RIP as i32), Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 8).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }
    // 0x36 OP_LEA_RIP (dst, rel32) — vreg[dst] = STATE_RIP + sext(rel32)
    {
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(), Some(Cl::Handler(OP_LEA_RIP))));
        seq.push((Instruction::with2(Code::Movsxd_r64_rm32, Register::RAX, m(Register::R9, 1)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, STATE_RIP as i32)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }
    // 0x6B OP_LEA_GS (dst, disp32) — vreg[dst] = STATE_SEG_GS + sext(disp32)
    // (gs:/fs: PEB/TEB 세그먼트 접근 — M6 Phase-2)
    {
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(), Some(Cl::Handler(OP_LEA_GS))));
        seq.push((Instruction::with2(Code::Movsxd_r64_rm32, Register::RAX, m(Register::R9, 1)).unwrap(), None));
        // v43/fix: dynamically read live GS:[0x30] (TEB.Self) so both main and worker threads
        // access their active thread's true TEB/TLS structures.
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11,
            MemoryOperand::with_base_displ_bcst_seg(Register::None, 0x30, false, Register::GS)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }
    // 0x37-0x3C absolute-address memory loads (dst, addr): addr = vreg[addr]
    for (op, code, dst_reg) in [
        (OP_MOVZX_R_MEM8_A, Code::Movzx_r32_rm8, Register::EAX),
        (OP_MOVZX_R_MEM16_A, Code::Movzx_r32_rm16, Register::EAX),
        (OP_MOVZX_R_MEM32_A, Code::Mov_r32_rm32, Register::EAX),
        (OP_MOVSX_R_MEM8_A, Code::Movsx_r64_rm8, Register::RAX),
        (OP_MOVSX_R_MEM16_A, Code::Movsx_r64_rm16, Register::RAX),
        (OP_MOV_R_MEM64_A, Code::Mov_r64_rm64, Register::RAX),
    ] {
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(), Some(Cl::Handler(op))));
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RDX)).unwrap(), None));
        seq.push((Instruction::with2(code, dst_reg, MemoryOperand::with_base(Register::R11)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }
    // 0x3D-0x40 absolute-address memory stores (addr, src)
    for (op, store_code, src_reg, load_code) in [
        (OP_MOV_MEM8_A, Code::Mov_rm8_r8, Register::AL, Code::Mov_r8_rm8),
        (OP_MOV_MEM16_A, Code::Mov_rm16_r16, Register::AX, Code::Mov_r16_rm16),
        (OP_MOV_MEM32_A, Code::Mov_rm32_r32, Register::EAX, Code::Mov_r32_rm32),
        (OP_MOV_MEM64_A, Code::Mov_rm64_r64, Register::RAX, Code::Mov_r64_rm64),
    ] {
        hdr(
            &mut seq,
            op,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
                Instruction::with2(load_code, src_reg, vreg(Register::RDX)).unwrap(),
                Instruction::with2(store_code, MemoryOperand::with_base(Register::R11), src_reg).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
            ],
        );
    }


    // ── v46: atomic memory compare-exchange (Once/futex CAS) ────────────────
    // OP_CMPXCHG_MEM32_A / OP_CMPXCHG_MEM64_A: [addr_vreg, src_vreg].
    //   RAX(v0)=expected; does a real `lock cmpxchg [addr], src` at the absolute
    //   address. On success [addr]=src and ZF=1; on failure RAX=[addr] and ZF=0.
    //   Preserves the atomicity/ordering the lifted Rust `Once` (futex CAS)
    //   requires; previously emulated non-atomically so COMPLETE was not durable
    //   and a 2nd call_once re-ran the closure -> panic.
    for (op, cmp_code, src_r, acc_r, load_code, store_code) in [
        // FIX(v47): 32-bit variant must commit the result to the 64-bit v0 slot
        // with a 64-bit store (`Mov_rm64_r64 [R8], RAX`) so that on a FAILED cmpxchg
        // the upper 32 bits of v0 are zero (hardware zero-extends EAX on the rm32
        // write) instead of leaving stale high bits from the previous expected value.
        // A 32-bit store (`Mov_rm32_r32 [R8], EAX`) does NOT clear the slot's upper
        // 32 bits because the destination is memory, not a register, so x64's
        // implicit upper-half zeroing does not apply. This violated the codebase
        // convention that 32-bit results are zero-extended when committed (cf. every
        // OP_*_R_R / OP_MUL_R_R32 handler, which store RAX into the 64-bit vreg).
        (OP_CMPXCHG_MEM32_A, Code::Cmpxchg_rm32_r32, Register::ECX, Register::RAX, Code::Mov_r32_rm32, Code::Mov_rm64_r64),
        (OP_CMPXCHG_MEM64_A, Code::Cmpxchg_rm64_r64, Register::RCX, Register::RAX, Code::Mov_r64_rm64, Code::Mov_rm64_r64),
        // v49: 8/16-bit variants. Hardware compares only AL/AX; on a failed cmpxchg
        // the CPU writes the byte/word into AL/AX and leaves the rest of RAX
        // untouched, so committing the full RAX to the v0 slot matches x86 exactly.
        // src is loaded as the low byte/word of the src vreg (CL/CX).
        (OP_CMPXCHG_MEM8_A, Code::Cmpxchg_rm8_r8, Register::CL, Register::RAX, Code::Mov_r8_rm8, Code::Mov_rm64_r64),
        (OP_CMPXCHG_MEM16_A, Code::Cmpxchg_rm16_r16, Register::CX, Register::RAX, Code::Mov_r16_rm16, Code::Mov_rm64_r64),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base(Register::R8)).unwrap(),
            Instruction::with2(load_code, src_r, vreg(Register::RDX)).unwrap(),
        ];
        let mut ci = Instruction::with2(cmp_code, MemoryOperand::with_base(Register::R11), src_r).unwrap();
        ci.set_has_lock_prefix(true);
        body.push(ci);
        body.push(Instruction::with2(store_code, MemoryOperand::with_base(Register::R8), acc_r).unwrap());
        // Deterministic ZF-only capture (cmpxchg defines ZF; other flags are
        // undefined). IMPORTANT: capture the flags with pushfq IMMEDIATELY after
        // the cmpxchg -- the `and rdx,~F_ZF` below would otherwise clobber ZF and
        // the captured "ZF" would be garbage, so the lifted `jne`/`setne` after
        // the Once CAS would misread success/failure and the Rust `Once` state
        // machine would break (closure runs twice -> panic at once.rs:166).
        body.push(Instruction::with(Code::Pushfq));
        body.push(Instruction::with1(Code::Pop_r64, Register::R11).unwrap());
        body.push(Instruction::with2(Code::And_rm64_imm32, Register::R11, F_ZF as i32).unwrap());
        body.push(Instruction::with2(Code::Mov_r64_rm64, Register::RDX, state_flags_mem()).unwrap());
        body.push(Instruction::with2(Code::And_rm64_imm32, Register::RDX, (F_ZF as u32).wrapping_neg() as i32).unwrap());
        body.push(Instruction::with2(Code::Or_rm64_r64, Register::RDX, Register::R11).unwrap());
        body.push(Instruction::with2(Code::Mov_rm64_r64, state_flags_mem(), Register::RDX).unwrap());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(&mut seq, op, body);
    }

    // ── v48: atomic memory XCHG / XADD (Once CompletionGuard swap / fetch-add) ─
    // OP_XCHG_MEM*_A / OP_XADD_MEM*_A: [addr_vreg, src_vreg].
    //   XCHG: real `xchg [addr], reg` — x86 memory XCHG is IMPLICITLY atomic (no
    //   LOCK prefix needed). This fixes the Rust `Once` CompletionGuard::drop()
    //   `xchg [state], COMPLETE`: the previous non-atomic load+store lift let a
    //   2nd call_once read the still-RUNNING state and re-run the closure, ending
    //   in `f.take().unwrap()` -> panic at once.rs:166. Register upper bits are
    //   preserved for 8/16-bit and zero-extended for 32-bit, exactly like x86.
    //   XADD: real `lock xadd [addr], reg` — atomic fetch-add (the Rust
    //   `AtomicUsize::fetch_add` refcount path). XADD needs LOCK for atomicity.
    //   [addr] becomes old+src, src becomes old [addr]; ADD flags are captured.
    for (op, xchg_code, xreg) in [
        (OP_XCHG_MEM8_A, Code::Xchg_rm8_r8, Register::AL),
        (OP_XCHG_MEM16_A, Code::Xchg_rm16_r16, Register::AX),
        (OP_XCHG_MEM32_A, Code::Xchg_rm32_r32, Register::EAX),
        (OP_XCHG_MEM64_A, Code::Xchg_rm64_r64, Register::RAX),
    ] {
        hdr(
            &mut seq,
            op,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
                // atomic swap: [addr] <-> reg  (implicitly atomic for memory xchg)
                Instruction::with2(xchg_code, MemoryOperand::with_base(Register::R11), xreg).unwrap(),
                // reg = old [addr]; upper bits already correct (see lift_xchg)
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RDX), Register::RAX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
            ],
        );
    }
    for (op, xadd_code, xreg) in [
        (OP_XADD_MEM8_A, Code::Xadd_rm8_r8, Register::AL),
        (OP_XADD_MEM16_A, Code::Xadd_rm16_r16, Register::AX),
        (OP_XADD_MEM32_A, Code::Xadd_rm32_r32, Register::EAX),
        (OP_XADD_MEM64_A, Code::Xadd_rm64_r64, Register::RAX),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
        ];
        // LOCK is mandatory for XADD atomicity (unlike XCHG).
        let mut ci = Instruction::with2(xadd_code, MemoryOperand::with_base(Register::R11), xreg).unwrap();
        ci.set_has_lock_prefix(true);
        body.push(ci);
        // src = old [addr] (upper bits per x86: preserved for 8/16, zeroed for 32)
        body.push(Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RDX), Register::RAX).unwrap());
        // xadd sets ADD flags (OF/SF/ZF/AF/PF/CF)
        body.extend(cap_flags(true));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(&mut seq, op, body);
    }

    // ── M3 follow-up (v24): native API bridge ─────────────────────────────────
    // 0x41 OP_NATIVE_CALL (target_vreg)
    //   Win64 call to vreg[target]; args v1->rcx, v2->rdx, v3->r8, v4->r9; ret->v0.
    //   The bridge saves the VM infra (state/ip/table) into callee-saved regs,
    //   loads args, calls, stores the return, then restores infra and dispatches.
    {
        seq.push((Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, MemoryOperand::with_base(Register::R9)).unwrap(), Some(Cl::Handler(OP_NATIVE_CALL))));
        seq.push((Instruction::with1(Code::Inc_rm64, Register::R9).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RAX)).unwrap(), None));
        seq.push((Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap(), Some(Cl::Bridge)));
    }
    // Bridge entry: r8=state, r9=ip, r10=table, r11=target.
    {
        seq.push((Instruction::with1(Code::Push_r64, Register::R12).unwrap(), Some(Cl::Bridge)));
        seq.push((Instruction::with1(Code::Push_r64, Register::R13).unwrap(), None));
        seq.push((Instruction::with1(Code::Push_r64, Register::R14).unwrap(), None));
        seq.push((Instruction::with1(Code::Push_r64, Register::R15).unwrap(), None));
        // keep state/ip/table in callee-saved regs across the native call
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R12, Register::R8).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R13, Register::R9).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::R10).unwrap(), None));
        // args (Win64 ABI): v1->rcx, v2->rdx, v8->r8, v9->r9.
        // FIX(C-1 runtime integration, --vm-oep): the bridge previously read the
        // 3rd/4th call args from v3/v4 (= RBX/RSP), but the LIFTED program places
        // call arguments in the real x64 argument registers rcx(v1)/rdx(v2)/
        // r8(v8)/r9(v9). So every native call with >=3 args (e.g. CRT __getmainargs,
        // __set_app_type, _initterm_e) received garbage in arg3/arg4, corrupting
        // CRT env/argv/static-init setup and leaving global/thread function pointers
        // at 0 -> later `call 0` / INVALID_POINTER_EXECUTE. Read v8/v9 for r8/r9.
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::R12, 8)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R12, 16)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R8, m(Register::R12, 64)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, m(Register::R12, 72)).unwrap(), None));
        // FIX(C-1 stack alignment): Win64 ABI requires RSP ≡ 0 (mod 16) at the
        // point of the `call` instruction (before the hardware push of ret addr).
        //
        // The required alignment offset at the bridge depends on the VM entry path:
        //   • Self-test  (call→trampoline→call→entry): entry stub sees RSP%16=8
        //   • vm_oep mode (boot stub jmp→entry):       entry stub sees RSP%16=0
        // In both cases, the bridge cannot know which alignment state it received.
        //
        // Solution: save the current RSP in R15 (already callee-saved; we restore
        // it before returning), explicitly align to 16 bytes, allocate shadow space,
        // call, then restore RSP from R15. This is safe because:
        //   • R12–R15 are callee-saved across the native call.
        //   • The 0x20 shadow space sits below the aligned RSP, satisfying Win64.
        //   • After the call, we restore RSP to exactly where we left it (from R15).
        //
        // This replaces the previous sub 0x28 heuristic which only worked correctly
        // for one entry path and crashed (GetStartupInfoA→RtlUnicodeStringToAnsiString
        // XMM misalignment → heap struct corruption) on the other.
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R15, Register::RSP).unwrap(), None));
        seq.push((Instruction::with2(Code::And_rm64_imm32, Register::RSP, -16i32).unwrap(), None));
        // FIX(C-1): reserve 0x20 shadow + 4*8 = 0x40 for the forwarded 5th+ stack args.
        // sub 0x20 alone would place them at [rsp+0x20..0x38] = the slots where r12-r15
        // were pushed (when entry RSP is 16-aligned), clobbering the saved state/ip/table
        // and corrupting r10 (handler table) on the restore -> dispatcher `jmp 0`. Use 0x60.
        seq.push((Instruction::with2(Code::Sub_rm64_imm32, Register::RSP, 0x60).unwrap(), None));
        // FIX(C-1 runtime integration, --vm-oep): forward the 5th+ stack arguments
        // from the VM's logical stack onto the native stack so native callees with
        // >4 args (e.g. CRT __getmainargs, CreateWindowExA) see them. The lifted
        // program stored them at [v4 + 0x20 ..] (v4 = the RSP vreg at STATE_VREGS+32);
        // the native callee reads the 5th arg at [rsp + 0x20]. Copy a 4-qword window.
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R12, 0x20)).unwrap(), None));
        // FIX(C-1): forward up to 8 stack args (args 5..12) so >8-arg native calls
        // (e.g. CreateWindowExA has 12) see all their arguments; the 0x60 frame below
        // already reserves 0x20 shadow + 8*8=0x40 for them.
        for i in 0..8 {
            seq.push((Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                MemoryOperand::with_base_displ(Register::RAX, 0x20 + i * 8),
            ).unwrap(), None));
            seq.push((Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ(Register::RSP, 0x20 + i * 8),
                Register::RCX,
            ).unwrap(), None));
        }
        // re-load register args (rcx/rdx/r8/r9) AND non-volatile/general registers (rbx/rbp/rsi/rdi)
        // so internal closures (e.g. 0x3790) see valid state pointers and sync updates back.
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::R12, 8)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R12, 16)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RBX, m(Register::R12, 24)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RBP, m(Register::R12, 40)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RSI, m(Register::R12, 48)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RDI, m(Register::R12, 56)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R8, m(Register::R12, 64)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, m(Register::R12, 72)).unwrap(), None));
        seq.push((Instruction::with1(Code::Call_rm64, Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::R15).unwrap(), None));
        // Bug-4 fix: sync the VM logical flags (state[STATE_FLAGS]) from the native
        // callee's physical RFLAGS, so a Jcc emitted right after a native call
        // (without an intervening test/cmp) reads the callee's actual flags — matching
        // native x86 semantics where flags after a `call` are whatever the callee left.
        // Must capture before the infra-restore `mov`/`pop` sequence that follows.
        seq.push((Instruction::with(Code::Pushfq), None));
        seq.push((Instruction::with1(Code::Pop_r64, Register::R11).unwrap(), None));
        seq.push((
            Instruction::with2(Code::And_rm64_imm32, Register::R11, (FLAG_MASK as u32) as i32).unwrap(),
            None,
        ));
        seq.push((
            Instruction::with2(
                Code::Mov_rm64_r64,
                m(Register::R12, STATE_FLAGS as i32),
                Register::R11,
            )
            .unwrap(),
            None,
        ));
        // store return -> vreg[0] and sync back updated rbx/rbp/rsi/rdi
        seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R12, 0), Register::RAX).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R12, 24), Register::RBX).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R12, 40), Register::RBP).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R12, 48), Register::RSI).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R12, 56), Register::RDI).unwrap(), None));
        // restore VM infra
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::R12).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, Register::R13).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::R14).unwrap(), None));
        seq.push((Instruction::with1(Code::Pop_r64, Register::R15).unwrap(), None));
        seq.push((Instruction::with1(Code::Pop_r64, Register::R14).unwrap(), None));
        seq.push((Instruction::with1(Code::Pop_r64, Register::R13).unwrap(), None));
        seq.push((Instruction::with1(Code::Pop_r64, Register::R12).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }

    // ── A-2 보강 (v25) — OR / NEG / NOT / 64-bit shift ────────────────────────
    // 0x42-0x45 OR r,r / r,r64 / r,imm32 / r,imm64 (logical flags)
    for (op, code, is64) in [
        (OP_OR_R_R, Code::Or_rm32_r32, false),
        (OP_OR_R_R64, Code::Or_rm64_r64, true),
    ] {
        let mut body = if !is64 {
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, vreg(Register::RDX)).unwrap(),
                Instruction::with2(code, Register::EAX, Register::EDX).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            ]
        } else {
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RDX, vreg(Register::RDX)).unwrap(),
                Instruction::with2(code, Register::RAX, Register::RDX).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            ]
        };
        body.extend(cap_flags(false));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(&mut seq, op, body);
    }
    for (op, code, is64) in [
        (OP_OR_R_IMM32, Code::Or_rm32_r32, false),
        (OP_OR_R_IMM64, Code::Or_rm64_r64, true),
    ] {
        let mut body = if !is64 {
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(code, Register::EAX, Register::EDX).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            ]
        } else {
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Movsxd_r64_rm32, Register::RDX, Register::EDX).unwrap(),
                Instruction::with2(code, Register::RAX, Register::RDX).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            ]
        };
        body.extend(cap_flags(false));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 5).unwrap());
        hdr(&mut seq, op, body);
    }

    // 0x46-0x47 NEG r (full flags), 0x48-0x49 NOT r (no flags)
    for (op, code, is64) in [
        (OP_NEG_R, Code::Neg_rm32, false),
        (OP_NEG_R64, Code::Neg_rm64, true),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
        ];
        if !is64 {
            body.push(Instruction::with1(code, vreg(Register::RCX)).unwrap());
        } else {
            body.push(Instruction::with1(code, vreg(Register::RCX)).unwrap());
        }
        body.extend(cap_flags(true));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap());
        hdr(&mut seq, op, body);
    }
    for (op, code, is64) in [
        (OP_NOT_R, Code::Not_rm32, false),
        (OP_NOT_R64, Code::Not_rm64, true),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with1(code, vreg(Register::RCX)).unwrap(),
        ];
        // NOT does not modify flags: no cap_flags.
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap());
        hdr(&mut seq, op, body);
    }

    // 0x4A-0x4C 64-bit shifts by imm8 (count masked to 63)
    for (op, code) in [
        (OP_SHL64_R_IMM8, Code::Shl_rm64_CL),
        (OP_SHR64_R_IMM8, Code::Shr_rm64_CL),
        (OP_SAR64_R_IMM8, Code::Sar_rm64_CL),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            // FIX(v26): R11에 vreg 인덱스(레지스터 번호)를 복사해야 한다. 과거 코드는
            // `mov r11, vreg[rcx]`(값)로 넣은 뒤 vreg[R11]을 인덱싱해 OOB 읽기
            // → 네이티브 크래시. 32-bit imm8 버전과 동일하게 인덱스를 복사한다.
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RCX).unwrap(), // R11 = reg index
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::R11)).unwrap(),
            Instruction::with2(code, Register::RAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
        ];
        body.extend(cap_flags_shift());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(&mut seq, op, body);
    }
    // 0x4D-0x4F 64-bit shifts by CL (count = vreg[1] & 63)
    for (op, code) in [
        (OP_SHL64_R_CL, Code::Shl_rm64_CL),
        (OP_SHR64_R_CL, Code::Shr_rm64_CL),
        (OP_SAR64_R_CL, Code::Sar_rm64_CL),
    ] {
        // FIX(v26): 이 핸들러는 vreg index 바이트(ECX)를 R11로 **복사**한 뒤
        // vreg[R11]로 읽어야 한다. 과거 코드는 `mov r11, vreg[rcx]`로 **값**을
        // R11에 넣은 채 vreg[R11]을 인덱싱해 out-of-bounds 읽기 → 네이티브
        // 크래시(0xC0000005)를 일으켰다. 32-bit CL 버전(0x23-0x25)과 동일하게
        // 카운트도 vreg[1]에서 읽는다.
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::RCX).unwrap(), // R11 = reg index (copy)
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::R11)).unwrap(), // RAX = vreg[reg]
            // count index = 1 (CL)
            Instruction::with2(Code::Mov_r32_imm32, Register::EDX, 1).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::ECX, vreg(Register::RDX)).unwrap(), // ECX = vreg[1]
            Instruction::with2(Code::And_rm32_imm32, Register::ECX, 63).unwrap(),
            Instruction::with2(code, Register::RAX, Register::CL).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::R11), Register::RAX).unwrap(),
        ];
        body.extend(cap_flags_shift());
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap());
        hdr(&mut seq, op, body);
    }

    // ── A-5 (v25): 0x50 NOP (no operands, no flags) ────────────────────────────
    hdr(&mut seq, OP_NOP, vec![Instruction::with(Code::Nopw)]);

    // ── A-5 (v29): XMM moves (operate on the state XMM file as memory) ─────────
    // Bytecode operand order: *_XMM_MEM=[xmm,addr] ; *_MEM_XMM=[addr,xmm].
    // r9->bytecode. XMM slot address = r8 + STATE_XMM + xmm*16 (computed in RDX).
    // 0x51 movsd xmm, [addr]  (8 bytes, zero high)
    hdr(
        &mut seq,
        OP_MOVSD_XMM_MEM,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RCX).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, MemoryOperand::with_base(Register::RAX)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64, 1), Register::RCX).unwrap(),
            Instruction::with2(Code::Mov_rm32_imm32, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64 + 8, 1), 0).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // 0x52 movsd [addr], xmm  (8 bytes)
    hdr(
        &mut seq,
        OP_MOVSD_MEM_XMM,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64, 1)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base(Register::RAX), Register::RCX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // 0x74 movq xmm[src] -> vreg[dst] (low 64 bits)
    hdr(
        &mut seq,
        OP_MOVQ_XMM_GPR,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64, 1)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // 0x75 movq vreg[src] -> xmm[dst] (low 64 bits, high zeroed)
    hdr(
        &mut seq,
        OP_MOVQ_GPR_XMM,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, STATE_XMM as i64, 1), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm32_imm32, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, STATE_XMM as i64 + 8, 1), 0).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // 0x53 movups xmm, [addr]  (16 bytes)
    hdr(
        &mut seq,
        OP_MOVUPS_XMM_MEM,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RCX).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, MemoryOperand::with_base(Register::RAX)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64, 1), Register::RCX).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::RAX, 8)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64 + 8, 1), Register::RCX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // 0x54 movups [addr], xmm  (16 bytes)
    hdr(
        &mut seq,
        OP_MOVUPS_MEM_XMM,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64, 1)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base(Register::RAX), Register::RCX).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64 + 8, 1)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::RAX, 8), Register::RCX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // 0x55 unpcklpd xmm[dst], xmm[src] -> {dst.lo, src.lo}
    hdr(
        &mut seq,
        OP_UNPCKLPD_XMM,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R10, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, STATE_XMM as i64, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64, 1)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, STATE_XMM as i64, 1), Register::R10).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, STATE_XMM as i64 + 8, 1), Register::R11).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // 0x8A unpcklps xmm[dst], xmm[src] -> { src.d1, dst.d1, src.d0, dst.d0 }.
    // SSE single-precision unpack: interleave the low 2 dwords of dst with the
    // low 2 dwords of src. All four dwords are read BEFORE any write so the
    // dst==src case is correct. Scratch: rax/rcx/rdx/rsi/rbx/r10/r11 (rsi/rbx
    // hold the src/dst slot base pointers; reloaded each dispatch like pshufd).
    {
        hdr(
            &mut seq,
            OP_UNPCKLPS_XMM,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
                // src slot base in RSI = r8 + src*16 + STATE_XMM
                Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R8).unwrap(),
                Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RDX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::RSI, STATE_XMM as i32).unwrap(),
                // dst slot base in RBX = r8 + dst*16 + STATE_XMM
                Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R8).unwrap(),
                Instruction::with2(Code::Add_rm64_r64, Register::RBX, Register::RCX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::RBX, STATE_XMM as i32).unwrap(),
                // read all four dwords before writing
                Instruction::with2(Code::Mov_r32_rm32, Register::EAX, MemoryOperand::with_base(Register::RSI)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::R10D, MemoryOperand::with_base_displ(Register::RSI, 4)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, MemoryOperand::with_base(Register::RBX)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::R11D, MemoryOperand::with_base_displ(Register::RBX, 4)).unwrap(),
                // write { src.d1, dst.d1, src.d0, dst.d0 } to dst slot
                Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base(Register::RBX), Register::EDX).unwrap(),
                Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base_displ(Register::RBX, 4), Register::EAX).unwrap(),
                Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base_displ(Register::RBX, 8), Register::R11D).unwrap(),
                Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base_displ(Register::RBX, 12), Register::R10D).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
            ],
        );
    }
    // 0x6C xorps xmm[dst] ^= xmm[src] (128-bit bitwise XOR). Uses r11/rax scratch
    // (preserves r10 = handler-table base). Mirrors the movsd/unpcklpd slot addressing.
    hdr(
        &mut seq,
        OP_XORPS_XMM,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
            // lo 64 bits: dst.lo ^= src.lo
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, STATE_XMM as i64, 1)).unwrap(),
            Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, STATE_XMM as i64, 1), Register::RAX).unwrap(),
            // hi 64 bits: dst.hi ^= src.hi
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64 + 8, 1)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, STATE_XMM as i64 + 8, 1)).unwrap(),
            Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, STATE_XMM as i64 + 8, 1), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // 0x6D-0x6F SSE shuffles: pshuflw/pshufhw/pshufd xmm[dst], xmm[src], imm8.
    // The imm is a runtime bytecode operand (r9+2), so it cannot be baked into
    // a native x86 shuffle immediate. We implement the shuffle with GPR word
    // extraction from the state XMM memory. Scratch: rax/rcx/rdx/r11/rbx/rsi
    // (all preserved around the VM call / dispatch reloads r10).
    // pshuflw: shuffle low 4 words; high 64 bits of dst unchanged.
    {
        hdr(
            &mut seq,
            OP_PSHUFLW_XMM,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
                // rsi = src slot base
                Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R8).unwrap(),
                Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RDX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::RSI, STATE_XMM as i32).unwrap(),
                // rbx = dst slot base
                Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R8).unwrap(),
                Instruction::with2(Code::Add_rm64_r64, Register::RBX, Register::RCX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::RBX, STATE_XMM as i32).unwrap(),
                // r11 = src.low (8 bytes)
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, MemoryOperand::with_base(Register::RSI)).unwrap(),
                // word0: sel=(imm&3); src=(r11>>(sel*16))&0xFFFF -> [rbx]
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
                Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
                Instruction::with2(Code::Mov_rm16_r16, MemoryOperand::with_base(Register::RBX), Register::DX).unwrap(),
                // word1: sel=((imm>>2)&3)
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 2).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
                Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
                Instruction::with2(Code::Mov_rm16_r16, MemoryOperand::with_base_displ(Register::RBX, 2), Register::DX).unwrap(),
                // word2: sel=((imm>>4)&3)
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 4).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
                Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
                Instruction::with2(Code::Mov_rm16_r16, MemoryOperand::with_base_displ(Register::RBX, 4), Register::DX).unwrap(),
                // word3: sel=((imm>>6)&3)
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 6).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
                Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
                Instruction::with2(Code::Mov_rm16_r16, MemoryOperand::with_base_displ(Register::RBX, 6), Register::DX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
            ],
        );
    }
    // pshufhw: shuffle high 4 words; low 64 bits of dst unchanged.
    {
        hdr(
            &mut seq,
            OP_PSHUFHW_XMM,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R8).unwrap(),
                Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RDX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::RSI, STATE_XMM as i32).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R8).unwrap(),
                Instruction::with2(Code::Add_rm64_r64, Register::RBX, Register::RCX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::RBX, STATE_XMM as i32).unwrap(),
                // r11 = src.high (bytes 8..15)
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, MemoryOperand::with_base_displ(Register::RSI, 8)).unwrap(),
                // word0 (dst offset 8): sel=(imm&3)
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
                Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
                Instruction::with2(Code::Mov_rm16_r16, MemoryOperand::with_base_displ(Register::RBX, 8), Register::DX).unwrap(),
                // word1 (dst offset 10): sel=((imm>>2)&3)
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 2).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
                Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
                Instruction::with2(Code::Mov_rm16_r16, MemoryOperand::with_base_displ(Register::RBX, 10), Register::DX).unwrap(),
                // word2 (dst offset 12): sel=((imm>>4)&3)
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 4).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
                Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
                Instruction::with2(Code::Mov_rm16_r16, MemoryOperand::with_base_displ(Register::RBX, 12), Register::DX).unwrap(),
                // word3 (dst offset 14): sel=((imm>>6)&3)
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 6).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Shl_rm32_imm8, Register::ECX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R11).unwrap(),
                Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
                Instruction::with2(Code::Mov_rm16_r16, MemoryOperand::with_base_displ(Register::RBX, 14), Register::DX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
            ],
        );
    }
    // pshufd: shuffle all 4 dwords; source dword offset = sel*4 bytes.
    {
        hdr(
            &mut seq,
            OP_PSHUFD_XMM,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::R8).unwrap(),
                Instruction::with2(Code::Add_rm64_r64, Register::RSI, Register::RDX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::RSI, STATE_XMM as i32).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R8).unwrap(),
                Instruction::with2(Code::Add_rm64_r64, Register::RBX, Register::RCX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::RBX, STATE_XMM as i32).unwrap(),
                // dword0 (dst offset 0): sel=(imm&3); src=[rsi+sel*4]
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, MemoryOperand::with_base_index_scale(Register::RSI, Register::RCX, 4)).unwrap(),
                Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base(Register::RBX), Register::EDX).unwrap(),
                // dword1 (dst offset 4): sel=((imm>>2)&3)
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 2).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, MemoryOperand::with_base_index_scale(Register::RSI, Register::RCX, 4)).unwrap(),
                Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base_displ(Register::RBX, 4), Register::EDX).unwrap(),
                // dword2 (dst offset 8): sel=((imm>>4)&3)
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 4).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, MemoryOperand::with_base_index_scale(Register::RSI, Register::RCX, 4)).unwrap(),
                Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base_displ(Register::RBX, 8), Register::EDX).unwrap(),
                // dword3 (dst offset 12): sel=((imm>>6)&3)
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EAX).unwrap(),
                Instruction::with2(Code::Shr_rm32_imm8, Register::ECX, 6).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 3).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::EDX, MemoryOperand::with_base_index_scale(Register::RSI, Register::RCX, 4)).unwrap(),
                Instruction::with2(Code::Mov_rm32_r32, MemoryOperand::with_base_displ(Register::RBX, 12), Register::EDX).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
            ],
        );
    }
    // ── A-6 (v50): packed 64-bit shifts by immediate ───────────────────────────
    // psrlq/psllq xmm[dst], imm8: shift each of the two 64-bit lanes right/left
    // by the bytecode imm count (masked to 6 bits, matching x86 shift-count masking).
    // Bytecode: [dst_xmm, imm8]. Slot base = r8 + STATE_XMM + dst*16.
    {
        let shl = false; // psrlq
        hdr(
            &mut seq,
            OP_PSRLQ_XMM_IMM8,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, STATE_XMM as i64, 1)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, (STATE_XMM + 8) as i64, 1)).unwrap(),
                // count into CL (masked to 6 bits by x86 for 64-bit shifts)
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 0x3F).unwrap(),
                Instruction::with2(Code::Shr_rm64_CL, Register::RAX, Register::CL).unwrap(),
                Instruction::with2(Code::Shr_rm64_CL, Register::R11, Register::CL).unwrap(),
                // store back (rcx is now count; recompute slot addr into rdx)
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64, 1), Register::RAX).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, (STATE_XMM + 8) as i64, 1), Register::R11).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
            ],
        );
    }
    {
        hdr(
            &mut seq,
            OP_PSLLQ_XMM_IMM8,
            vec![
                Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::RAX, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, STATE_XMM as i64, 1)).unwrap(),
                Instruction::with2(Code::Mov_r64_rm64, Register::R11, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RCX, 1, (STATE_XMM + 8) as i64, 1)).unwrap(),
                Instruction::with2(Code::Mov_r32_rm32, Register::ECX, Register::EDX).unwrap(),
                Instruction::with2(Code::And_rm32_imm32, Register::ECX, 0x3F).unwrap(),
                Instruction::with2(Code::Shl_rm64_CL, Register::RAX, Register::CL).unwrap(),
                Instruction::with2(Code::Shl_rm64_CL, Register::R11, Register::CL).unwrap(),
                Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, MemoryOperand::with_base(Register::R9)).unwrap(),
                Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 4).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, STATE_XMM as i64, 1), Register::RAX).unwrap(),
                Instruction::with2(Code::Mov_rm64_r64, MemoryOperand::with_base_index_scale_displ_size(Register::R8, Register::RDX, 1, (STATE_XMM + 8) as i64, 1), Register::R11).unwrap(),
                Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
            ],
        );
    }

    // ── v45: --vm-oep Rust-runtime additions ──────────────────────────────────
    // 0x78 pinsrw xmm[dst], vreg[src], lane_imm8: insert low 16 bits of vreg[src]
    //     into word lane (imm & 7) of XMM[dst]. Lane byte offset = (imm&7)*2.
    hdr(
        &mut seq,
        OP_PINSRW_XMM,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EAX, m(Register::R9, 2)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Shl_rm64_imm8, Register::RCX, 4).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::R8).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::RDX, STATE_XMM as i32).unwrap(),
            Instruction::with2(Code::Add_rm64_r64, Register::RDX, Register::RCX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EAX, 7).unwrap(),
            Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 1).unwrap(),
            Instruction::with2(Code::Mov_rm16_r16, MemoryOperand::with_base_index_scale(Register::RDX, Register::RAX, 1), Register::R11W).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 3).unwrap(),
        ],
    );
    // 0x79 cpuid (0 operands): run native CPUID. vreg0=leaf, vreg2=subleaf;
    // results EAX/EBX/ECX/EDX stored back to vreg0..3 (32-bit, zero-extended).
    hdr(
        &mut seq,
        OP_CPUID,
        vec![
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0x00)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::R8, 0x10)).unwrap(),
            Instruction::with(Code::Cpuid),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x00), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x08), Register::RBX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x10), Register::RCX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x18), Register::RDX).unwrap(),
        ],
    );
    // 0x7A xgetbv (0 operands): run native XGETBV. vreg2=RCX (subleaf), result
    // EDX:EAX stored to vreg3:vreg0 (32-bit each, zero-extended).
    hdr(
        &mut seq,
        OP_XGETBV,
        vec![
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, m(Register::R8, 0x10)).unwrap(),
            Instruction::with(Code::Xgetbv),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x00), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x18), Register::RDX).unwrap(),
        ],
    );
    // 0x7B tzcnt32 vreg[dst], vreg[src] (2 operands).
    // cnt = popcount((src & -src) - 1)  (== trailing zeros; == 32 when src==0).
    // flags: CF=ZF=1 if src==0 else 0. Branch-free, portable (no POPCNT/BSF dep).
    hdr(
        &mut seq,
        OP_TZCNT_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ESI, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RDX)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, Register::EAX).unwrap(),
            // cnt: EBX = popcount((src & -src) - 1)
            Instruction::with2(Code::Mov_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with1(Code::Neg_rm32, Register::EBX).unwrap(),
            Instruction::with2(Code::And_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with1(Code::Dec_rm32, Register::EBX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 1).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x55555555).unwrap(),
            Instruction::with2(Code::Sub_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EAX, 0x33333333).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EBX, 2).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EBX, 0x33333333).unwrap(),
            Instruction::with2(Code::Add_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 4).unwrap(),
            Instruction::with2(Code::Add_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EBX, 0x0F0F0F0F).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 8).unwrap(),
            Instruction::with2(Code::Add_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EAX, 16).unwrap(),
            Instruction::with2(Code::Add_r32_rm32, Register::EBX, Register::EAX).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EBX, 0xFF).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RSI), Register::RAX).unwrap(),
            // flags: CF=ZF=1 iff src==0
            Instruction::with2(Code::Mov_r32_rm32, Register::EDI, Register::R11D).unwrap(),
            Instruction::with1(Code::Neg_rm32, Register::EDI).unwrap(),
            Instruction::with2(Code::Or_r32_rm32, Register::EDI, Register::R11D).unwrap(),
            Instruction::with2(Code::Shr_rm32_imm8, Register::EDI, 31).unwrap(),
            Instruction::with1(Code::Neg_rm32, Register::EDI).unwrap(),
            Instruction::with1(Code::Not_rm32, Register::EDI).unwrap(),
            Instruction::with2(Code::And_rm32_imm32, Register::EDI, (F_CF | F_ZF) as u32).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, STATE_FLAGS as i32), Register::RDI).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap(),
        ],
    );
    // 0x7C ret imm16 (operands: imm16): pop bytecode return IP from the VM
    // return-IP stack into r9, then v4(RSP) += 8 + imm16 (cdecl arg cleanup).
    {
        seq.push((
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDI, MemoryOperand::with_base(Register::R9)).unwrap(),
            Some(Cl::Handler(OP_RET_IMM16)),
        ));
        // bytecode return IP = [base + csp]; csp += 8
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, STATE_CALL_SP as i32)).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, STATE_PTR_CALL_STACK as i32)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R11).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R9, MemoryOperand::with_base(Register::RAX)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R11, 8).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, STATE_CALL_SP as i32), Register::R11).unwrap(), None));
        // architectural RSP (v4) += 8 + imm16
        seq.push((Instruction::with2(Code::Mov_r64_rm64, Register::R11, m(Register::R8, 0x20)).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::R11, 8).unwrap(), None));
        seq.push((Instruction::with2(Code::Add_rm64_r64, Register::R11, Register::RDI).unwrap(), None));
        seq.push((Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0x20), Register::R11).unwrap(), None));
        seq.push((jmp_disp(), Some(Cl::Dispatch)));
    }
    // ── v31: 1-op multiply/divide + BSWAP ─────────────────────────────────────
    // The accumulator pair RAX(v0)/RDX(v2) maps directly to GPRs, so the native
    // handler uses the real x86 mul/div/imul/idiv instructions. src is a vreg.
    // MUL64: rdx:rax = rax * r11
    hdr(
        &mut seq,
        OP_MUL_R_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Mul_rm64, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // MUL32: edx:eax = eax * r11d (zero-extended into vregs)
    hdr(
        &mut seq,
        OP_MUL_R_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Mul_rm32, Register::R11D).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // IMUL64 (1-op): rdx:rax = rax * r11 (signed)
    hdr(
        &mut seq,
        OP_IMUL1_R_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Imul_rm64, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // IMUL32 (1-op, signed)
    hdr(
        &mut seq,
        OP_IMUL1_R_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Imul_rm32, Register::R11D).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // DIV64: rax = rdx:rax / r11; rdx = remainder (unsigned)
    hdr(
        &mut seq,
        OP_DIV_R_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Div_rm64, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // DIV32 (unsigned)
    hdr(
        &mut seq,
        OP_DIV_R_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Div_rm32, Register::R11D).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // IDIV64 (signed)
    hdr(
        &mut seq,
        OP_IDIV_R_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Idiv_rm64, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // IDIV32 (signed)
    hdr(
        &mut seq,
        OP_IDIV_R_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::EDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Idiv_rm32, Register::R11D).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // BSWAP32: r11d = bswap(vreg[r]); store zero-extended (upper 32 cleared)
    hdr(
        &mut seq,
        OP_BSWAP_R32,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r32_rm32, Register::R11D, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Bswap_r32, Register::R11D).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // BSWAP64
    hdr(
        &mut seq,
        OP_BSWAP_R64,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with1(Code::Bswap_r64, Register::R11).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::R11).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // BSR/BSF: dst = bit index (most/least significant set bit of src); ZF set if src==0.
    // Uses real x86 bsr/bsf; captures flags (cap_flags(false) keeps ZF/SF/PF).
    for (op, code32, code64, is64) in [
        (OP_BSR_R32, Code::Bsr_r32_rm32, Code::Bsr_r64_rm64, false),
        (OP_BSR_R64, Code::Bsr_r32_rm32, Code::Bsr_r64_rm64, true),
        (OP_BSF_R32, Code::Bsf_r32_rm32, Code::Bsf_r64_rm64, false),
        (OP_BSF_R64, Code::Bsf_r32_rm32, Code::Bsf_r64_rm64, true),
    ] {
        let mut body = vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, m(Register::R9, 1)).unwrap(),
        ];
        if is64 {
            body.push(Instruction::with2(Code::Mov_r64_rm64, Register::RAX, vreg(Register::RDX)).unwrap());
            body.push(Instruction::with2(code64, Register::RAX, Register::RAX).unwrap());
            body.push(Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap());
        } else {
            body.push(Instruction::with2(Code::Mov_r32_rm32, Register::EAX, vreg(Register::RDX)).unwrap());
            body.push(Instruction::with2(code32, Register::EAX, Register::EAX).unwrap());
            body.push(Instruction::with2(Code::Mov_rm64_r64, vreg(Register::RCX), Register::RAX).unwrap());
        }
        body.extend(cap_flags(false));
        body.push(Instruction::with2(Code::Add_rm64_imm32, Register::R9, 2).unwrap());
        hdr(&mut seq, op, body);
    }

    // ── v33: 1-op multiply/divide 8/16-bit width ────────────────────────────
    // Uses the real x86 8/16-bit mul/imul/div/idiv on the accumulator AX/DX.
    // MUL8: AX = AL * r11b (unsigned); result zero-extended into v0.
    hdr(
        &mut seq,
        OP_MUL_R_R8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFF).unwrap(),
            Instruction::with1(Code::Mul_rm8, Register::R11L).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // MUL16: DX:AX = AX * r11w (unsigned); v0=low16, v2=high16.
    hdr(
        &mut seq,
        OP_MUL_R_R16,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFFFF).unwrap(),
            Instruction::with1(Code::Mul_rm16, Register::R11W).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // IMUL8 (signed): AX = AL * r11b, treated as signed bytes.
    hdr(
        &mut seq,
        OP_IMUL1_R_R8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFF).unwrap(),
            Instruction::with1(Code::Imul_rm8, Register::R11L).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // IMUL16 (signed): DX:AX = AX * r11w, treated as signed words.
    hdr(
        &mut seq,
        OP_IMUL1_R_R16,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFFFF).unwrap(),
            Instruction::with1(Code::Imul_rm16, Register::R11W).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // DIV8: AL = AX / r11b; AH = remainder (unsigned). Quotient must fit 8 bits.
    hdr(
        &mut seq,
        OP_DIV_R_R8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFF).unwrap(),
            Instruction::with1(Code::Div_rm8, Register::R11L).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // DIV16: AX = DX:AX / r11w; DX = remainder (unsigned).
    hdr(
        &mut seq,
        OP_DIV_R_R16,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RDX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFFFF).unwrap(),
            Instruction::with1(Code::Div_rm16, Register::R11W).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // IDIV8 (signed): AL = AX / r11b; AH = remainder.
    hdr(
        &mut seq,
        OP_IDIV_R_R8,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFF).unwrap(),
            Instruction::with1(Code::Idiv_rm8, Register::R11L).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );
    // IDIV16 (signed): AX = DX:AX / r11w; DX = remainder.
    hdr(
        &mut seq,
        OP_IDIV_R_R16,
        vec![
            Instruction::with2(Code::Movzx_r32_rm8, Register::ECX, MemoryOperand::with_base(Register::R9)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RAX, m(Register::R8, 0)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RAX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, m(Register::R8, 16)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::RDX, 0xFFFF).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R11, vreg(Register::RCX)).unwrap(),
            Instruction::with2(Code::And_rm64_imm32, Register::R11, 0xFFFF).unwrap(),
            Instruction::with1(Code::Idiv_rm16, Register::R11W).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EAX, Register::AX).unwrap(),
            Instruction::with2(Code::Movzx_r32_rm16, Register::EDX, Register::DX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 0), Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, m(Register::R8, 16), Register::RDX).unwrap(),
            Instruction::with2(Code::Add_rm64_imm32, Register::R9, 1).unwrap(),
        ],
    );

    // ── 0x13 HALT: restore + ret ───────────────────────────────────────────────
    // Pop in the exact reverse of the entry pushes (see entry stub). This restores
    // the caller's callee-saved GPRs (incl. RBP) before retnq.
    {
        seq.push((Instruction::with1(Code::Pop_r64, Register::R12).unwrap(), Some(Cl::Handler(OP_HALT))));
        for r in [Register::R13, Register::R14, Register::R15] {
            seq.push((Instruction::with1(Code::Pop_r64, r).unwrap(), None));
        }
        seq.push((Instruction::with1(Code::Pop_r64, Register::R11).unwrap(), None));
        for r in [
            Register::R10,
            Register::R9,
            Register::R8,
            Register::RDI,
            Register::RSI,
            Register::RBP,
            Register::RBX,
            Register::RDX,
            Register::RCX,
            Register::RAX,
        ] {
            seq.push((Instruction::with1(Code::Pop_r64, r).unwrap(), None));
        }
        // Bug-6 fix: restore the Win64 callee-saved XMM6..XMM15 saved at entry
        // (160-byte block below the GPR saves), then retract the frame.
        for (i, xr) in XMM_SAVE.iter().enumerate() {
            seq.push((
                Instruction::with2(
                    Code::Movdqu_xmm_xmmm128,
                    *xr,
                    MemoryOperand::with_base_displ(Register::RSP, (i * 16) as i64),
                )
                .unwrap(),
                None,
            ));
        }
        seq.push((Instruction::with2(Code::Add_rm64_imm32, Register::RSP, 0xA0).unwrap(), None));
        seq.push((Instruction::with(Code::Retnq), None));
    }

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
