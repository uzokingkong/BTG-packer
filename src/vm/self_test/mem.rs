// ==============================================================================
// VM self-test submodule: mem.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use anyhow::{Result, anyhow};
use crate::vm::{handlers, interp};
use iced_x86::{Code};
use crate::vm::{build_vm_module};
use crate::vm::arena::{Arena};
use crate::vm::encode::{encode_trampoline};


/// M2 self-test: memory width (16/32/64-bit loads incl. sign-extend + stores).
/// Cross-checks the Rust interpreter against the native x86-64 handlers by
/// running the same bytecode in both memory models and comparing every vreg
/// and the mutated memory buffer.
pub(crate) fn run_m2_mem_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut arena = Arena::new(0x20000)?;
    let code_va = arena.base + 0x1000;
    let table_va = arena.base + 0x4800;
    let bc_va = arena.base + 0x5000;
    let state_va = arena.base + 0x6000;
    let data_va = arena.base + 0x7000; // S-box memory buffer
    let tramp_va = arena.base + 0x8000;
    let module = build_vm_module(
        code_va as u64,
        table_va as u64,
        bc_va as u64,
        vec![0u8; 128],
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
    let pat: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x4800..0x4800 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
        b[0x7000..0x7008].copy_from_slice(&pat);
    }

    // Bytecode: load widths from offset 0, sign-extend from offset 7/6, then
    // store 16/32/64-bit at offset 0 and reload.
    let mut bc = BytecodeBuilder::new();
    bc.mov_r_imm32(0, 0); // idx0 = 0
    bc.mov_r_imm32(1, 7); // idx1 = 7
    bc.mem_load(OP_MOVZX_R_MEM16, 2, MEM_SBOX, 0); // 0x2211
    bc.mem_load(OP_MOVZX_R_MEM32, 3, MEM_SBOX, 0); // 0x44332211
    bc.mem_load(OP_MOVSX_R_MEM8, 4, MEM_SBOX, 0);  // 0x11
    bc.mem_load(OP_MOVSX_R_MEM16, 5, MEM_SBOX, 0); // 0x2211
    bc.mem_load(OP_MOV_R_MEM64, 6, MEM_SBOX, 0);   // 0x8877665544332211
    bc.mem_load(OP_MOVSX_R_MEM8, 7, MEM_SBOX, 1);  // 0x88 -> sign-extend
    bc.mem_load(OP_MOVSX_R_MEM16, 8, MEM_SBOX, 1); // word @7 = 0x0088 -> 0x88 (pos)
    bc.mem_load(OP_MOVSX_R_MEM16, 9, MEM_SBOX, 0); // word @0 = 0x2211 (pos)
    bc.mov_r_imm32(10, 0xAAAA_BBBB);
    bc.mov_r_imm64(11, 0x0102_0304_0506_0708);
    bc.mem_store(OP_MOV_MEM16_R, MEM_SBOX, 0, 10); // mem[0..2]=0xBBBB
    bc.mem_load(OP_MOVZX_R_MEM16, 12, MEM_SBOX, 0); // 0xBBBB
    bc.mem_store(OP_MOV_MEM32_R, MEM_SBOX, 0, 10);  // mem[0..4]=0xAABBBBBB
    bc.mem_load(OP_MOVZX_R_MEM32, 13, MEM_SBOX, 0); // 0xAABBBBBB
    bc.mem_store(OP_MOV_MEM64_R, MEM_SBOX, 0, 11);  // mem[0..8]=0x0102030405060708
    bc.mem_load(OP_MOV_R_MEM64, 14, MEM_SBOX, 0);   // 0x0102030405060708
    bc.halt();
    let prog = bc.finish();

    // Interpreter
    let mut st = vec![0u8; interp::STATE_SIZE];
    let mut mem = vec![0u8; 0x100];
    mem[0..8].copy_from_slice(&pat);
    st[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8].copy_from_slice(&0u64.to_le_bytes());
    interp::interpret(&mut st, &mut mem, &prog).map_err(|e| anyhow!("M2 mem interp failed: {:?}", e))?;
    let mut vi = [0u64; 16];
    for i in 0..16 {
        vi[i] = u64::from_le_bytes(st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }
    let mem_i = mem[0..8].to_vec();

    // Native
    {
        let b = arena.bytes();
        b[0x5000..0x5000 + prog.len()].copy_from_slice(&prog);
        b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
        b[0x7000..0x7008].copy_from_slice(&pat);
    }
    arena.call(0x8000);
    let b = arena.bytes();
    let mut vn = [0u64; 16];
    for i in 0..16 {
        vn[i] = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS + i * 8..0x6000 + interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
    }
    let mem_n = b[0x7000..0x7008].to_vec();
    assert_eq!(vi, vn, "M2 memory loads/stores: interp vs native vreg mismatch\ninterp={:?}\nnative ={:?}", vi, vn);
    assert_eq!(mem_i, mem_n, "M2 memory buffer mismatch after stores");
    // sanity: v14 (full 64-bit reload) must be the stored value
    assert_eq!(vi[14], 0x0102_0304_0506_0708, "M2 64-bit store/reload wrong");
    Ok(())
}


/// [25] C-1 (v36): VM 메모리 모델 — region 스키마, address→region 해석, bounds 검증.
pub(crate) fn run_mem_model_test() -> Result<()> {
    use crate::vm::mem_model::{MemKind, MemRegion, VmMemoryModel};

    let mut m = VmMemoryModel::new();
    m.add(MemRegion::new(0x140001000, 0x2000, MemKind::Code, 0b111));
    m.add(MemRegion::new(0x140003000, 0x1000, MemKind::ReadOnly, 0b101));
    m.add(MemRegion::new(0x140004000, 0x1000, MemKind::Data, 0b011));
    m.add(MemRegion::new(0x70000000, 0x10000, MemKind::Stack, 0b011));
    m.add(MemRegion::new(0x80000000, 0x100000, MemKind::Heap, 0b011));
    m.add(MemRegion::new(0x7FFE0000, 0x1000, MemKind::System, 0b101)); // PEB/TEB area

    // resolve in/out
    assert_eq!(m.resolve(0x140001000).map(|r| r.kind), Some(MemKind::Code));
    assert_eq!(m.resolve(0x140002FFF).map(|r| r.kind), Some(MemKind::Code));
    assert_eq!(m.resolve(0x140003000).map(|r| r.kind), Some(MemKind::ReadOnly));
    assert!(m.resolve(0x140005000).is_none()); // gap after .data
    assert_eq!(m.resolve(0x7FFE0100).map(|r| r.kind), Some(MemKind::System));
    assert!(!m.is_mapped(0x1_0000_0000));

    // region-relative -> absolute
    assert_eq!(m.abs(0x140001000, 0x20), Some(0x140001020));
    assert_eq!(m.abs(0x140001000, 0x2000), None); // OOB

    // access bounds
    assert!(m.access_ok(0x140001000, 0x100));
    assert!(!m.access_ok(0x140002FF0, 0x20));

    // kind_at
    assert_eq!(m.kind_at(0x140004000), Some(MemKind::Data));
    Ok(())
}


/// [27] M7 (v41): on-demand 재암호화(anti-dump) — RC4 청크를 복호화→사용→재암호화하여
/// 반환 시점에 다시 암호문이 되고, "사용 직후 덤프"가 평문을 노출하지 않는지 검증한다.
pub(crate) fn run_m7_ondemand_reencrypt_test() -> Result<()> {
    use crate::pipeline::ondemand::{Rc4, process_on_demand, simulate_dump};

    let key = b"m7-ondemand-key-0x9E3779B9";
    let plain: &[u8] = b"The original .text must not be plaintext at dump time. 0123456789abcdef";
    // file-state ciphertext
    let mut cipher = plain.to_vec();
    let mut rc4 = Rc4::new(key);
    rc4.crypt(&mut cipher);
    assert_ne!(cipher, plain, "[27] cipher should differ from plain");

    // on-demand: decrypt→use→re-encrypt leaves it encrypted (anti-dump)
    assert!(simulate_dump(plain, &cipher, key), "[27] after use, dump must be encrypted");

    // use callback sees plaintext; after on-demand the buffer is ciphertext again
    let mut buf = cipher.clone();
    let mut seen = Vec::new();
    let blen = buf.len();
    process_on_demand(&mut buf, blen, key, |p| seen.extend_from_slice(p));
    assert_eq!(seen, plain, "[27] use callback must observe plaintext");
    assert_ne!(buf, plain, "[27] buffer must be re-encrypted after on-demand");

    // round-trip: decrypt again recovers plaintext (functional correctness kept)
    let mut rc4b = Rc4::new(key);
    rc4b.crypt(&mut buf);
    assert_eq!(buf, plain, "[27] re-decrypt must recover plaintext");

    Ok(())
}



/// v49: 8/16/32/64-bit atomic memory cmpxchg round-trip (interp == native).
/// Exercises OP_CMPXCHG_MEM8/16/32/64_A. For each width: init [addr], expected in
/// RAX (v0), new value in a src vreg. Verifies the success case writes mem + sets
/// ZF, and the stale-expected case leaves mem unchanged and loads [addr] into the
/// operand-width bytes of v0. Includes a byte-width case where RAX has dirty upper
/// bits and the low byte matches — under the old emulation that always took the
/// "not equal" branch; the fixed handler compares only AL.

/// v49: 8/16/32/64-bit atomic memory cmpxchg — interpreter round-trip.
/// Exercises OP_CMPXCHG_MEM8/16/32/64_A in the reference interpreter (pure Rust,
/// no native harness): for each width init [addr], expected in RAX (v0), new value
/// in a src vreg; verifies the success case writes mem + sets ZF, the stale-
/// expected case leaves mem unchanged and loads [addr] into the operand-width
/// bytes of v0, and a byte CAS with dirty upper RAX bits still succeeds (the old
/// 8/16 emulation compared the full 32-bit register and always failed). Also
/// guards the 64-bit path (previously truncated expected/cur to u32).
///
/// NOTE: the native handler path is not exercised here — the project's self-test
/// native VM harness cannot run cmpxchg handlers at all (the pre-existing 32-bit
/// cmpxchg also faults there), so this validates the interpreter semantics and
/// the fix's logic; the native 8/16 handlers mirror the working 32/64 handlers.

/// v49: 8/16/32/64-bit atomic memory cmpxchg — interp == native round-trip.
/// Exercises OP_CMPXCHG_MEM8/16/32/64_A through BOTH the reference interpreter and
/// the native VM (handler table placed in the arena, state vregs seeded), mirroring
/// the v48 XCHG/XADD self-test. Verifies the success case writes mem + sets ZF, the
/// stale-expected case leaves mem unchanged and loads [addr] into the operand-width
/// bytes of v0, and a byte CAS with dirty upper RAX bits still succeeds (the old
/// 8/16 emulation compared the full 32-bit register and always failed -> the Rust
/// Once byte flag never reached COMPLETE -> `f.take().unwrap()` panic). Also guards
/// the 64-bit path (previously truncated expected/cur to u32).
pub(crate) fn run_m4_cmpxchg_test() -> Result<()> {
    use crate::vm::bytecode::*;

    let mut varena = Arena::new(0x40000)?;
    let (vc, vt, vb, vs, vtr, vdata) = (
        varena.base + 0x1000,
        varena.base + 0x4800,
        varena.base + 0x5000,
        varena.base + 0x6000,
        varena.base + 0x8000,
        varena.base + 0x9000,
    );
    let module = build_vm_module(
        vc as u64,
        vt as u64,
        vb as u64,
        vec![0u8; 128],
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vs as u64, vdata as u64, vdata as u64, vc as u64, vtr as u64)?;
    {
        let b = varena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x4800..0x4800 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
    }
    let vbase = varena.base as u64;

    // (op, width, mem_init, expected(RAX), new(src), mem_after)
    let cases: &[(u8, usize, u64, u64, u64, u64)] = &[
        (OP_CMPXCHG_MEM8_A, 1, 0x11, 0x11, 0x22, 0x22), // clean success
        // byte CAS with DIRTY upper RAX bits, low byte matches -> must still succeed
        (OP_CMPXCHG_MEM8_A, 1, 0x11, 0x1122_3311, 0x22, 0x22),
        (OP_CMPXCHG_MEM8_A, 1, 0x11, 0x99, 0x22, 0x11), // stale expected -> no write
        (OP_CMPXCHG_MEM16_A, 2, 0x1122, 0x1122, 0x3344, 0x3344),
        (OP_CMPXCHG_MEM32_A, 4, 0x1122_3344, 0x1122_3344, 0x5566_7788, 0x5566_7788),
        (OP_CMPXCHG_MEM64_A, 8, 0x0102_0304_0506_0708, 0x0102_0304_0506_0708, 0x0a0b_0c0d_0e0f_1011, 0x0a0b_0c0d_0e0f_1011),
        (OP_CMPXCHG_MEM64_A, 8, 0x0102_0304_0506_0708, 0x0102_0304_0506_0709, 0x0a0b_0c0d_0e0f_1011, 0x0102_0304_0506_0708),
    ];

    for (op, width, mem_init, expected, new, mem_after) in cases {
        let mask: u64 = if *width == 8 { u64::MAX } else { (1u64 << (*width * 8)) - 1 };
        // bytecode: cmpxchg [v15], v14; halt  (addr/expected/new seeded in the state).
        let mut b = BytecodeBuilder::new();
        b.mem_cmpxchg_a(*op, 15, 14);
        b.halt();
        let prog = b.finish();
        let init_bytes: [u8; 8] = mem_init.to_le_bytes();

        // ---- interpreter (addr v15 = 0x8000 in the flat mem buffer) ----
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x10000];
        mem[0x8000..0x8000 + *width].copy_from_slice(&init_bytes[..*width]);
        for (v, x) in [(15usize, 0x8000u64), (0usize, *expected), (14usize, *new)] {
            let off = interp::STATE_VREGS + v * 8;
            st[off..off + 8].copy_from_slice(&x.to_le_bytes());
        }
        interp::interpret(&mut st, &mut mem, &prog)
            .map_err(|e| anyhow!("cmpxchg interp failed (op={}): {:?}", op, e))?;
        let v0_i = u64::from_le_bytes(st[interp::STATE_VREGS..interp::STATE_VREGS + 8].try_into().unwrap());
        let zf_i = u64::from_le_bytes(st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8].try_into().unwrap()) & F_ZF;

        // ---- native VM (addr v15 = vbase+0x8000 = arena offset 0x8000) ----
        {
            let b = varena.bytes();
            b[0x5000..0x5000 + prog.len()].copy_from_slice(&prog);
            b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
            b[0x9000..0x9008].copy_from_slice(&init_bytes);
            for (v, x) in [(15usize, vbase + 0x9000), (0usize, *expected), (14usize, *new)] {
                let off = interp::STATE_VREGS + v * 8;
                b[0x6000 + off..0x6000 + off + 8].copy_from_slice(&x.to_le_bytes());
            }
        }
        varena.call(0x8000);
        let b = varena.bytes();
        let v0_n = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS..0x6000 + interp::STATE_VREGS + 8].try_into().unwrap());
        let zf_n = u64::from_le_bytes(b[0x6000 + interp::STATE_FLAGS..0x6000 + interp::STATE_FLAGS + 8].try_into().unwrap()) & F_ZF;
        let mem_n: Vec<u8> = b[0x9000..0x9000 + *width].to_vec();

        // interp and native must agree
        assert_eq!(v0_i, v0_n, "cmpxchg op={} v0 interp/native mismatch", op);
        assert_eq!(zf_i, zf_n, "cmpxchg op={} ZF interp/native mismatch", op);
        assert_eq!(&mem[0x8000..0x8000 + *width], &mem_n[..], "cmpxchg op={} memory interp/native mismatch", op);

        // memory must equal mem_after
        let after: Vec<u8> = mem_after.to_le_bytes()[..*width].to_vec();
        assert_eq!(&mem[0x8000..0x8000 + *width], &after[..], "cmpxchg op={} memory != expected-after", op);

        // success iff operand-width low bytes of RAX match [addr]
        let expect_success = (expected & mask) == (mem_init & mask);
        assert_eq!(zf_i != 0, expect_success, "cmpxchg op={} ZF semantics wrong", op);
        if !expect_success {
            let v0_low = v0_i & mask;
            assert_eq!(v0_low, mem_init & mask, "cmpxchg op={} failed CAS must load [addr] into AL/AX/EAX/RAX", op);
        } else {
            assert_eq!(v0_i, *expected, "cmpxchg op={} success must leave RAX unchanged", op);
        }
    }
    Ok(())
}
