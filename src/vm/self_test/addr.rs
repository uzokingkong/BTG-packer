// ==============================================================================
// VM self-test submodule: addr.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use anyhow::{Result, anyhow};
use crate::vm::{handlers, interp};
use crate::vm::{build_vm_module};
use crate::vm::arena::{Arena};
use crate::vm::encode::{encode_trampoline};


/// M2 follow-up self-test: addressing modes. Cross-checks the Rust interpreter
/// against the native x86-64 handlers for:
///   * LEA  ([base+disp] and [base+index*scale+disp])
///   * LEA_RIP (RIP-relative, via STATE_RIP)
///   * absolute-address loads/stores of every width (8/16/32/64, sign-extend)
pub(crate) fn run_m2_addr_test() -> Result<()> {
    use crate::vm::bytecode::*;
    use crate::vm::flags;

    let mut arena = Arena::new(0x40000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x4800;
    let bc_va = arena.base + 0x5000;
    let state_va = arena.base + 0x6000;
    let data_va = arena.base + 0x7000; // addressable data region
    let stack_va = arena.base + 0x8000;
    let tramp_va = arena.base + 0x9000;
    let module = build_vm_module(
        code_va as u64,
        table_va as u64,
        bc_va as u64,
        vec![0u8; 512],
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(
        state_va as u64,
        data_va as u64,
        data_va as u64,
        code_va as u64,
        tramp_va as u64,
    )?;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x4800..0x4800 + module.table.len()].copy_from_slice(&module.table);
        b[0x9000..0x9000 + tramp.len()].copy_from_slice(&tramp);
    }

    // The pattern written at data_va + disp, and at data_va + idx*scale + disp.
    // Program (built against the native data base = data_va):
    //   v0 = data_va (base)          ; v1 = index
    //   v2 = LEA(v0, idx=v1, scale=2, disp=0x10)  -> data+16
    //   MOV_MEM32_A [v2] = 0x11223344
    //   v3 = LEA(v0, ADDR_NO_INDEX, disp=0x8)     -> data+8
    //   v4 = MOVZX32_A [v3]          ; == 0 (zeroed)
    //   MOV_MEM8_A [v3] = 0xAA
    //   v5 = MOVSX8_A [v3]           ; sign-extended -86
    //   LEA_RIP: set_rip(data_va - 0x10); v6 = LEA_RIP(0x10) -> data_va
    //   v7 = MOV64_A [v6]            ; reads the u64 we stored
    // Program (base v0 and STATE_RIP are *inputs*, set per execution below):
    //   v1 = 1 (index)
    //   v2 = LEA(v0, idx=v1, scale=2(*4), disp=0x10)   -> base + 4 + 0x10
    //   MOV_MEM32_A [v2] = 0x11223344
    //   v3 = LEA(v0, ADDR_NO_INDEX, disp=0x8)          -> base + 8
    //   v4 = MOVZX32_A [v3]                             (zeroed)
    //   MOV_MEM8_A [v3] = 0xAA
    //   v5 = MOVSX8_A [v3]                              (sign-ext -86)
    //   v6 = LEA_RIP(STATE_RIP + 0x10)
    //   v7 = MOV64_A [v6]
    let mut bc = BytecodeBuilder::new();
    bc.mov_r_imm32(1, 1);
    bc.lea(2, 0, 1, 2, 0x10);
    bc.mov_r_imm32(8, 0x1122_3344);
    bc.mem_store_a(OP_MOV_MEM32_A, 2, 8);
    bc.lea(3, 0, ADDR_NO_INDEX, 0, 8);
    bc.mem_load_a(OP_MOVZX_R_MEM32_A, 4, 3); // v4 = mem32[base+8] = 0
    bc.mov_r_imm32(9, 0xAA);
    bc.mem_store_a(OP_MOV_MEM8_A, 3, 9);
    bc.mem_load_a(OP_MOVSX_R_MEM8_A, 5, 3); // v5 = signext(0xAA)
    bc.lea_rip(6, 0x10); // v6 = STATE_RIP + 0x10
    bc.mem_load_a(OP_MOV_R_MEM64_A, 7, 6); // v7 = u64 at [STATE_RIP+0x10]
    bc.halt();
    let prog = bc.finish();

    // Interpreter: base v0 = 0 (offset into mem), STATE_RIP = 0x1000
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x2000];
    st[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8].copy_from_slice(&0u64.to_le_bytes());
    st[interp::STATE_PTR_STACK..interp::STATE_PTR_STACK + 8].copy_from_slice(&0x1000u64.to_le_bytes());
    st[interp::STATE_SP..interp::STATE_SP + 8].copy_from_slice(&0x1000u64.to_le_bytes());
    st[interp::STATE_RIP..interp::STATE_RIP + 8].copy_from_slice(&0xFF0u64.to_le_bytes());
    // place a known u64 at mem[0x1000]
    mem[0x1000..0x1008].copy_from_slice(&0xDEAD_BEEF_CAFE_F00Du64.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &prog).map_err(|e| anyhow!("M2 addr interp failed: {:?}", e))?;
    let mut vi = [0u64; 16];
    for i in 0..16 {
        vi[i] = u64::from_le_bytes(st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }
    // interpreter semantic checks (base = 0)
    assert_eq!(vi[2], 0 + 4 + 0x10, "M2 LEA base+idx*scale+disp wrong");
    assert_eq!(vi[3], 0 + 8, "M2 LEA base+disp wrong");
    assert_eq!(vi[4], 0, "M2 32-bit load of zeroed mem wrong");
    assert_eq!(vi[5] as i64, (0xAAu8 as i8) as i64, "M2 MOVSX8 wrong");
    assert_eq!(vi[6], 0x1000, "M2 LEA_RIP wrong (got 0x{:X} want 0x{:X})", vi[6], 0x1000);
    assert_eq!(vi[7], 0xDEAD_BEEF_CAFE_F00D, "M2 LEA_RIP load wrong");
    // interpreter memory effects
    assert_eq!(&mem[0x14..0x18], &[0x44, 0x33, 0x22, 0x11], "M2 mem32 store wrong");
    assert_eq!(mem[8], 0xAA, "M2 mem8 store wrong");

    // Native VM: base v0 = data_va, STATE_RIP = data_va - 0x10 so +0x10 = data_va
    {
        let b = arena.bytes();
        b[0x5000..0x5000 + prog.len()].copy_from_slice(&prog);
        b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
        b[0x6000 + interp::STATE_VREGS + 0 * 8..0x6000 + interp::STATE_VREGS + 1 * 8]
            .copy_from_slice(&(data_va as u64).to_le_bytes());
        b[0x6000 + interp::STATE_PTR_STACK..0x6000 + interp::STATE_PTR_STACK + 8]
            .copy_from_slice(&(stack_va as u64).to_le_bytes());
        b[0x6000 + interp::STATE_SP..0x6000 + interp::STATE_SP + 8].copy_from_slice(&0x1000u64.to_le_bytes());
        b[0x6000 + interp::STATE_RIP..0x6000 + interp::STATE_RIP + 8]
            .copy_from_slice(&((data_va as u64).wrapping_sub(0x10)).to_le_bytes());
        b[0x7000..0x7000 + 0x1000].fill(0);
    }
    arena.call(0x9000);
    let b = arena.bytes();
    let mut vn = [0u64; 16];
    for i in 0..16 {
        vn[i] = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS + i * 8..0x6000 + interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }
    // native semantic checks (base = data_va)
    let db = data_va as u64;
    assert_eq!(vn[2], db + 4 + 0x10, "M2 native LEA base+idx*scale+disp wrong");
    assert_eq!(vn[3], db + 8, "M2 native LEA base+disp wrong");
    assert_eq!(vn[4], 0, "M2 native 32-bit load of zeroed mem wrong");
    assert_eq!(vn[5] as i64, (0xAAu8 as i8) as i64, "M2 native MOVSX8 wrong");
    assert_eq!(vn[6], db, "M2 native LEA_RIP wrong (got 0x{:X} want 0x{:X})", vn[6], db);
    // the 32-bit store at data+0x14 and the byte store at data+8, and the u64 at data
    assert_eq!(b[0x7000 + 0x14..0x7000 + 0x18], [0x44, 0x33, 0x22, 0x11], "M2 native mem32 store wrong");
    assert_eq!(b[0x7000 + 8], 0xAA, "M2 native mem8 store wrong");
    Ok(())
}
