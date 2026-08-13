// ==============================================================================
// VM self-test submodule: mod.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use rand::RngCore;
use anyhow::{Result, anyhow};
use crate::vm::{bytecode, handlers, import_key, interp, ksa, lifter, prga};
use iced_x86::{Code, Instruction, Register};
use crate::vm::{VM_STATE_SIZE, build_vm_module};
use crate::vm::arena::{Arena};
use crate::vm::encode::{encode_ksa_native, encode_trampoline};

// ── submodule declarations (decomposed self_test) ───────────────
mod flags;
mod mem;
mod stack;
mod addr;
mod bridge;
mod lift;
mod a2_a5;
mod abi;
mod text;
mod multiblock;
mod muldiv;
mod sse;
mod exit;
mod cmov;
mod util;
mod string_ops;
mod bmi;
mod sse_fpu;
mod lock_incdec;

// ── test functions the orchestrator dispatches (from submodules) ──
use self::a2_a5::run_a2_a5_test;
use self::a2_a5::run_a2_lift_completion_test;
use self::muldiv::run_a2_muldiv_8_16_test;
use self::muldiv::run_a2_muldiv_bswap_test;
use self::a2_a5::run_a2a5_lift_residual_test;
use self::sse::run_a5_sse_cond_test;
use self::flags::run_carry_flag_fix_test;
use self::exit::run_exit_teardown_test;
use self::cmov::run_cmovcc_test;
use self::string_ops::run_string_ops_test;
use self::bmi::run_bmi_test;
use self::sse_fpu::run_sse_fpu_test;
use self::lock_incdec::run_lock_incdec_test;
use self::flags::run_flags_jcc_test;
use self::abi::run_handler_abi_test;
use self::addr::run_m2_addr_test;
use self::mem::run_m2_mem_test;
use self::bridge::run_m3_bridge_test;
use self::stack::run_m3_stack_test;
use self::mem::run_m4_cmpxchg_test;
use self::lift::run_m4_lift_test;
use self::multiblock::run_m5_multiblock_test;
use self::text::run_m6_phase2_lift_test;
use self::text::run_m6_phase2_native_program_test;
use self::mem::run_m7_ondemand_reencrypt_test;
use self::abi::run_m8_handler_mba_test;
use self::mem::run_mem_model_test;
use self::multiblock::run_switch_lift_test;
use self::text::run_text_lift_test;

// ── orchestrator + shared helper ──────────────────────────────────

/// Run the full VM self-test. Returns Ok(()) iff every stage matches.
pub fn run_self_test() -> Result<()> {
    use std::io::Write;
    println!("==================================================================");
    println!(" [VM SELF-TEST] Composite VM MVP — lifter / interpreter / handlers ");
    println!("==================================================================");
    let _ = std::io::stdout().flush();

    // ── Random inputs ──────────────────────────────────────────────────────────
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 256];
    rng.fill_bytes(&mut seed);
    let mut seed_masked = [0u8; 256];
    for (i, b) in seed.iter().enumerate() {
        seed_masked[i] = b ^ 0xA7;
    }
    let k1 = rng.next_u32();
    let k2 = rng.next_u32();
    let k3 = rng.next_u32();

    // ── Reference (pure Rust) ──────────────────────────────────────────────────
    let mut expected = [0u8; 256];
    ksa::reference_ksa(&seed_masked, k1, k2, k3, &mut expected);
    println!("[1] reference KSA computed (k1=0x{:08X} k2=0x{:08X} k3=0x{:08X})", k1, k2, k3);

    // ── Lift to bytecode ───────────────────────────────────────────────────────
    let seq = ksa::build_ksa_instructions(0, k1, k2, k3);
    let bc = lifter::lift_ksa(&seq)?;
    println!("[2] lifted {} KSA instructions -> {} bytes of bytecode", seq.len(), bc.len());
    log::debug!("VM bytecode:\n{}", bytecode::disassemble(&bc));

    // ── Interpreter ────────────────────────────────────────────────────────────
    {
        let mut state = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x2000];
        let sbox_off = 0x100usize;
        let seed_off = 0x1000usize;
        mem[seed_off..seed_off + 256].copy_from_slice(&seed_masked);
        state[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
            .copy_from_slice(&(sbox_off as u64).to_le_bytes());
        state[interp::STATE_PTR_SEED..interp::STATE_PTR_SEED + 8]
            .copy_from_slice(&(seed_off as u64).to_le_bytes());
        interp::interpret(&mut state, &mut mem, &bc)
            .map_err(|e| anyhow!("interpreter failed: {:?}", e))?;
        let ok = mem[sbox_off..sbox_off + 256] == expected[..];
        println!("[3] bytecode interpreter: {}", pass_fail(ok));
        if !ok {
            return Err(anyhow!("interpreter mismatch"));
        }
    }

    // ── Native execution arena ─────────────────────────────────────────────────
    let mut arena = Arena::new(0x20000)?;
    let sbox_va = arena.base + 0x2000;
    let seed_va = arena.base + 0x3000;
    let code_va = arena.base + 0x5000;
    let table_va = arena.base + 0x8000;
    let bc_va = arena.base + 0x9000;
    let state_va = arena.base + 0xA000;
    let vsbox_va = arena.base + 0xB000;
    let tramp_va = arena.base + 0xC000;

    // ── Native x86 KSA (the baseline the VM must match) ────────────────────────
    {
        let native = encode_ksa_native(seed_va as u64, k1, k2, k3, sbox_va as u64, code_va as u64)?;
        std::fs::write("native_ksa.bin", &native).ok();
        let b = arena.bytes();
        b[0x2000..0x2000 + 256].fill(0);
        b[0x3000..0x3000 + 256].copy_from_slice(&seed_masked);
        b[0x5000..0x5000 + native.len()].copy_from_slice(&native);
        arena.call(0x5000);
        let ok = arena.bytes()[0x2000..0x2000 + 256] == expected[..];
        println!("[4] native x86 KSA:              {}", pass_fail(ok));
        if !ok {
            return Err(anyhow!("native KSA mismatch"));
        }
    }

    // ── VM module: build, place, execute natively ──────────────────────────────
    {
        let module = build_vm_module(
            code_va as u64,
            table_va as u64,
            bc_va as u64,
            bc.clone(),
            handlers::EntryMode::Ksa,
        )?;
        handlers::validate_vm_code(&module.code)?;
        println!(
            "[5] VM module: code={}B table={}B bytecode={}B state={}B",
            module.code.len(),
            module.table.len(),
            module.bytecode.len(),
            VM_STATE_SIZE
        );
        let tramp = encode_trampoline(state_va as u64, vsbox_va as u64, seed_va as u64, code_va as u64, tramp_va as u64)?;
        let b = arena.bytes();
        b[0x5000..0x5000 + module.code.len()].copy_from_slice(&module.code);
        b[0x8000..0x8000 + module.table.len()].copy_from_slice(&module.table);
        b[0x9000..0x9000 + module.bytecode.len()].copy_from_slice(&module.bytecode);
        b[0xA000..0xA000 + VM_STATE_SIZE].fill(0);
        b[0xB000..0xB000 + 256].fill(0);
        b[0xC000..0xC000 + tramp.len()].copy_from_slice(&tramp);
        arena.call(0xC000);
        let ok = arena.bytes()[0xB000..0xB000 + 256] == expected[..];
        println!("[6] VM module native execution:   {}", pass_fail(ok));
        if !ok {
            return Err(anyhow!("VM module native execution mismatch"));
        }
    }

    // ── 2nd virtualized routine: import-name MBA key derivation ──────────────
    // (v14) Beyond RC4 KSA, the VM now also virtualizes the per-entry import XOR
    // key derivation. This proves the composite VM executes a real second
    // security routine (not just KSA) through its handlers.
    {
        let master = rng.next_u32();
        let c: u32 = 0x9E37_79B9;
        let bc_ik = import_key::build_import_key_bytecode(master, c);
        let mut state = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x100];
        let mut ok = true;
        for idx in [0u32, 1, 3, 7, 0x1234_5678, 0xDEAD_BEEF, 0xFFFF_FFFF] {
            state[interp::STATE_VREGS + 0 * 8..interp::STATE_VREGS + 1 * 8]
                .copy_from_slice(&(idx as u64).to_le_bytes());
            state[interp::STATE_VREGS + 1 * 8..interp::STATE_VREGS + 2 * 8].fill(0);
            interp::interpret(&mut state, &mut mem, &bc_ik)
                .map_err(|e| anyhow!("VM import-key interpreter failed: {:?}", e))?;
            let got = u64::from_le_bytes(
                state[interp::STATE_VREGS + 1 * 8..interp::STATE_VREGS + 2 * 8]
                    .try_into()
                    .unwrap(),
            ) as u32;
            let exp = import_key::reference_import_key(master, idx, c);
            if got != exp {
                ok = false;
            }
        }
        println!(
            "[7] VM import-name MBA key derivation (2nd virtualized routine): {}",
            pass_fail(ok)
        );
        if !ok {
            return Err(anyhow!("VM import-key bytecode mismatch"));
        }
    }

    // ── v19: PRGA (RC4 keystream generation) virtualized routine ────────────
    // (Target #3 — the string-run/code-region decrypt loop is lifted into the VM)
    {
        let mut rng2 = rand::thread_rng();
        let bc_prga = prga::build_prga_bytecode();
        let mut sbox = [0u8; 256];
        rng2.fill_bytes(&mut sbox);
        let mut buf = vec![0u8; 64];
        rng2.fill_bytes(&mut buf);
        let mut sbox_ref = sbox;
        let mut buf_ref = buf.clone();
        prga::reference_prga(&mut sbox_ref, &mut buf_ref);

        let mut state = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x400];
        let (sbox_off, buf_off) = (0usize, 0x100usize);
        mem[sbox_off..sbox_off + 256].copy_from_slice(&sbox);
        mem[buf_off..buf_off + buf.len()].copy_from_slice(&buf);
        state[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
            .copy_from_slice(&(sbox_off as u64).to_le_bytes());
        state[interp::STATE_PTR_BUF..interp::STATE_PTR_BUF + 8]
            .copy_from_slice(&(buf_off as u64).to_le_bytes());
        state[interp::STATE_VREGS + 3 * 8..interp::STATE_VREGS + 4 * 8]
            .copy_from_slice(&(buf.len() as u64).to_le_bytes());
        interp::interpret(&mut state, &mut mem, &bc_prga)
            .map_err(|e| anyhow!("VM PRGA interpreter failed: {:?}", e))?;
        let out = &mem[buf_off..buf_off + buf.len()];
        let ok = out == buf_ref.as_slice();
        println!(
            "[8] VM PRGA keystream generation (3rd virtualized routine): {} ({}B)",
            pass_fail(ok),
            buf.len()
        );
        if !ok {
            return Err(anyhow!("VM PRGA mismatch"));
        }
    }

    // ── M1: full flag model + Jcc conditions (interp == native == flags.rs) ──
    match run_flags_jcc_test() {
        Ok(_) => println!("[9] VM flag model + full Jcc (16 conds incl. JA/JBE): PASS"),
        Err(e) => {
            println!("[9] VM flag model + full Jcc:                   FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M2: 64-bit arithmetic / shifts / TEST / memory width ────────────────
    match run_m2_mem_test() {
        Ok(_) => println!("[10] M2 mem width (16/32/64-bit, sign-ext):   PASS"),
        Err(e) => {
            println!("[10] M2 mem width:                              FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M3: stack + call/ret (subroutine support) ───────────────────────────
    match run_m3_stack_test() {
        Ok(_) => println!("[11] M3 stack push/pop + call/ret:          PASS"),
        Err(e) => {
            println!("[11] M3 stack push/pop + call/ret:            FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M2 follow-up: addressing modes (LEA, LEA_RIP, absolute-addr mem) ────
    match run_m2_addr_test() {
        Ok(_) => println!("[12] M2 addressing modes (disp/idx*scale/RIP-rel): PASS"),
        Err(e) => {
            println!("[12] M2 addressing modes:                      FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M3 follow-up: native API bridge ─────────────────────────────────────
    match run_m3_bridge_test() {
        Ok(_) => println!("[13] M3 native API bridge (VM→GPR→call→restore): PASS"),
        Err(e) => {
            println!("[13] M3 native API bridge:                     FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M4: block lift (1:1 table + dummy_fn equivalence) ──────────────────
    match run_m4_lift_test() {
        Ok(_) => println!("[14] M4 block lift (dummy_fn == native):      PASS"),
        Err(e) => {
            println!("[14] M4 block lift:                              FAIL ({})", e);
            return Err(e);
        }
    }

    // ── M6 (v26): 원본 .text → VM lift (커버리지 + 실제 lift 동치) ──────────
    match run_text_lift_test() {
        Ok(_) => println!("[16] M6 text->VM lift (real .text block == native): PASS"),
        Err(e) => {
            println!("[16] M6 text->VM lift:                            FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-2/A-5: OR/NEG/NOT + 64-bit shifts + NOP + unsupported diagnostics ──
    match run_a2_a5_test() {
        Ok(_) => println!("[15] A-2/A-5 OR/NEG/NOT, 64-shift, NOP, diag:  PASS"),
        Err(e) => {
            println!("[15] A-2/A-5 opcodes/diagnostics:               FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-2/A-5 (v26): completed 1:1 lift table (reg/imm/cmp/test/push) ────
    match run_a2_lift_completion_test() {
        Ok(_) => println!("[17] A-2/A-5 lift-table completion (reg/imm/cmp/test/push): PASS"),
        Err(e) => {
            println!("[17] A-2/A-5 lift-table completion:               FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-5 (v29): SSE/FPU + conditional + string ops (setcc/cmovcc/sbb/XMM/stosq/loopne) ──
    match run_a5_sse_cond_test() {
        Ok(_) => println!("[18] A-5 SSE/FPU + setcc/cmovcc/sbb + rep stosq/loopne: PASS"),
        Err(e) => {
            println!("[18] A-5 SSE/FPU + setcc/cmovcc/sbb:              FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── M5 (v30): multi-block control-flow lift (rel32 branches + block connection) ──
    match run_m5_multiblock_test() {
        Ok(_) => println!("[19] M5 multi-block lift (loop, rel32 cross-block, block connect): PASS"),
        Err(e) => {
            println!("[19] M5 multi-block lift:                             FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-2 (v31): 1-op signed/unsigned multiply-divide + BSWAP ──────────────
    match run_a2_muldiv_bswap_test() {
        Ok(_) => println!("[20] A-2 mul/div (1-op MUL/IMUL/DIV/IDIV 32/64) + BSWAP: PASS"),
        Err(e) => {
            println!("[20] A-2 mul/div + BSWAP:                              FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-2/A-5 (v32): 8/16-bit arithmetic + JCXZ/JECXZ + rep movs/cmps ────
    match run_a2a5_lift_residual_test() {
        Ok(_) => println!("[21] A-2/A-5 8/16-bit arith + JCXZ/JECXZ + rep movs/cmps: PASS"),
        Err(e) => {
            println!("[21] A-2/A-5 8/16-bit arith + JCXZ/JECXZ + rep movs/cmps: FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── A-2 (v33): 1-op MUL/IMUL/DIV/IDIV 8/16-bit width ───────────────────
    match run_a2_muldiv_8_16_test() {
        Ok(_) => println!("[22] A-2 mul/div (1-op MUL/IMUL/DIV/IDIV 8/16-bit width): PASS"),
        Err(e) => {
            println!("[22] A-2 mul/div 8/16-bit:                                  FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── M6 Phase-2 (v34): OEP→VM entry 전환 데이터 경로 (전체 도달 CFG → 단일 VM) ──
    match run_m6_phase2_lift_test() {
        Ok(_) => println!("[23] M6 Phase-2 whole-CFG OEP lift (reachable CFG -> single VM): PASS"),
        Err(e) => {
            println!("[23] M6 Phase-2 whole-CFG OEP lift:                        FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── B-3 (v35): switch/테이블 점프 → VM 내부 디스패치 ─────────────────────────
    match run_switch_lift_test() {
        Ok(_) => println!("[24] B-3 switch jump table -> VM dispatch (compare-and-jump chain): PASS"),
        Err(e) => {
            println!("[24] B-3 switch jump table:                                FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── C-1 (v36): VM 메모리 모델 ──────────────────────────────────────────────
    match run_mem_model_test() {
        Ok(_) => println!("[25] C-1 VM memory model (region schema + resolve + bounds): PASS"),
        Err(e) => {
            println!("[25] C-1 VM memory model:                                  FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── M6 Phase-2 (v38): 원본 프로그램을 lift 한 VM 프로그램의 네이티브 VM 실행 ──
    match run_m6_phase2_native_program_test() {
        Ok(_) => println!("[26] M6 Phase-2 native-VM program execution (lifted CFG == native VM == x86): PASS"),
        Err(e) => {
            println!("[26] M6 Phase-2 native-VM program execution:              FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── M7 (v41): on-demand 재암호화(anti-dump) ────────────────────────────────
    match run_m7_ondemand_reencrypt_test() {
        Ok(_) => println!("[27] M7 on-demand re-encrypt (decrypt→use→re-encrypt; dump stays ciphertext): PASS"),
        Err(e) => {
            println!("[27] M7 on-demand re-encrypt:                              FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── M8 (v45): VM handler 테이블 MBA 난독화 (handler 주소 비평문) ────────────
    match run_m8_handler_mba_test() {
        Ok(_) => println!("[28] M8 VM handler-table MBA (dispatch derives K via a+b==(a^b)+2(a&b); table XOR-encrypted): PASS"),
        Err(e) => {
            println!("[28] M8 VM handler-table MBA:                              FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── v49: atomic memory compare-exchange (8/16/32/64) ─────────────────────────
    match run_m4_cmpxchg_test() {
        Ok(_) => println!("[29] v49 atomic mem cmpxchg (8/16/32/64; interp==native): PASS"),
        Err(e) => {
            println!("[29] v49 atomic mem cmpxchg:                            FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── P0-3 (v53 rework): R15/R14 are ordinary program vregs (14/15) ───────────
    // R14/R15 must LIFT (not be rejected) — the native VM virtualizes them into
    // state slots 14/15, distinct from the lifter's internal scratch vregs 16/17.
    // Rejecting them previously broke real --vm-oep packing (chve2_unpacked lifts
    // instructions using R15). Verify they lift AND execute correctly through the
    // interpreter (end-to-end: mov r15,imm64; mov rax,r15; halt -> rax==imm64).
    {
        use crate::vm::bytecode::BytecodeBuilder;
        use crate::vm::lifter::lift_one;
        let mut b = BytecodeBuilder::new();
        let r15_ok = lift_one(&mut b, &Instruction::with2(Code::Mov_r64_rm64, Register::R15, Register::RAX).unwrap()).is_ok();
        let r14_ok = lift_one(&mut b, &Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap()).is_ok();
        let normal_ok = lift_one(&mut b, &Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RBX).unwrap()).is_ok();
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(15, 0x1122_3344_5566_7788u64);
        bc.mov_r_r64(0, 15);
        bc.halt();
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 64];
        let exec_ok = interp::interpret(&mut st, &mut mem, &bc.finish()).is_ok();
        let rax = if exec_ok { u64::from_le_bytes(st[interp::STATE_VREGS + 0 * 8..][..8].try_into().unwrap()) } else { 0 };
        if r15_ok && r14_ok && normal_ok && exec_ok && rax == 0x1122_3344_5566_7788u64 {
            println!("[29] P0-3 R15/R14 usable as program vregs (lift + interp execution): PASS");
        } else {
            println!("[29] P0-3 R15/R14 register handling: FAIL (r15={} r14={} normal={} exec={} rax=0x{:X})", r15_ok, r14_ok, normal_ok, exec_ok, rax);
            return Err(anyhow!("[29] R15/R14 register handling failed"));
        }
    }
    // ── P2-10: opcode registry sync check ─────────────────────────────────────
    // The opcode set is declared once in the `opcodes!` macro (bytecode.rs).
    // Verify (a) every declared opcode resolves to a non-"??" mnemonic and an
    // operand length, (b) no duplicate values, and (c) the native handler table
    // (built over 0..NUM_OPS) has a distinct handler for every non-zero opcode
    // slot — so bytecode/handlers/interp/lifter cannot silently drift apart.
    {
        use crate::vm::bytecode::{NUM_OPS, OPCODE_INFO, opcode_name, opcode_operand_len};
        let mut ok = true;
        let mut seen = std::collections::HashSet::new();
        for (val, mnem, olen) in OPCODE_INFO {
            if opcode_name(*val) == "??" || opcode_name(*val) != *mnem {
                ok = false;
                eprintln!("[30] opcode {}: mnemonic mismatch (name='{}' table='{}')", val, opcode_name(*val), mnem);
            }
            if opcode_operand_len(*val) != Some(*olen) {
                ok = false;
                eprintln!("[30] opcode {}: operand-len mismatch", val);
            }
            if *val as usize >= NUM_OPS {
                ok = false;
                eprintln!("[30] opcode {}: value >= NUM_OPS", val);
            }
            if !seen.insert(*val) {
                ok = false;
                eprintln!("[30] duplicate opcode value 0x{:02X}", val);
            }
        }
        // handler-table coverage: every non-zero slot must have a real handler
        // (distinct from the invalid-opcode handler at slot 0).
        let vmc = handlers::generate_vm_code(0x1000, 0x3000, 0x2000, handlers::EntryMode::Ksa, None)?;
        let invalid_off = vmc.handler_offsets[0];
        for op in 1..NUM_OPS {
            if vmc.handler_offsets[op] == invalid_off {
                ok = false;
                eprintln!("[30] opcode slot 0x{:02X}: no distinct handler", op);
            }
        }
        if ok {
            println!("[30] P2-10 opcode registry sync ({} opcodes, mnemonic+olen+handler-table coverage): PASS", OPCODE_INFO.len());
        } else {
            return Err(anyhow!("[30] opcode registry sync failed"));
        }
    }
    // ── v48: atomic memory XCHG / XADD semantics (Once swap / fetch-add) ─────
    // Check [31] proves OP_XCHG_MEM*_A / OP_XADD_MEM*_A are a single atomic RMW
    // with x86-exact semantics: interpreter and native VM must both produce the
    // reference x86 result (8/16/32/64-bit). This is the fix for the Rust `Once`
    // CompletionGuard `xchg [state], COMPLETE` that was previously lifted as a
    // non-atomic load+store, letting a 2nd call_once re-run the closure and panic
    // at once.rs:166 (`f.take().unwrap()` on None).
    {
        use crate::vm::bytecode::*;
        let mut bc = BytecodeBuilder::new();
        bc.mem_xchg_a(OP_XCHG_MEM32_A, 9, 1);   // [8000h] <-> v1 (32-bit)
        bc.mem_xchg_a(OP_XCHG_MEM64_A, 10, 2);  // [8008h] <-> v2 (64-bit)
        bc.mem_xchg_a(OP_XCHG_MEM8_A, 11, 3);   // [8010h] <-> v3 (8-bit)
        bc.mem_xchg_a(OP_XCHG_MEM16_A, 12, 4);  // [8018h] <-> v4 (16-bit)
        bc.mem_xadd_a(OP_XADD_MEM32_A, 13, 5);  // [8020h] += v5 ; v5 = old
        bc.mem_xadd_a(OP_XADD_MEM64_A, 14, 6);  // [8028h] += v6 ; v6 = old
        bc.mem_xadd_a(OP_XADD_MEM8_A, 15, 7);   // [8030h] += v7 ; v7 = old
        bc.mem_xadd_a(OP_XADD_MEM16_A, 0, 8);   // [8038h] += v8 ; v8 = old (addr in v0)
        bc.halt();
        let prog = bc.finish();

        // Initial 64-byte data region (little-endian).
        let mut data_init = vec![0u8; 0x40];
        data_init[0x00..0x04].copy_from_slice(&0xAABB_CCDDu32.to_le_bytes());
        data_init[0x08..0x10].copy_from_slice(&0x8899_AABB_CCDD_EEFFu64.to_le_bytes());
        data_init[0x10] = 0x77;
        data_init[0x18..0x1A].copy_from_slice(&0x5566u16.to_le_bytes());
        data_init[0x20..0x24].copy_from_slice(&0x20u32.to_le_bytes());
        data_init[0x28..0x30].copy_from_slice(&0x300u64.to_le_bytes());
        data_init[0x30] = 0xFA;
        data_init[0x38..0x3A].copy_from_slice(&0xFFFFu16.to_le_bytes());

        // Expected final vregs v1..v8 (index 0 left zero).
        let want_v: [u64; 9] = [
            0, 0xAABB_CCDD, 0x8899_AABB_CCDD_EEFF, 0x77, 0x5566,
            0x20, 0x300, 0xFA, 0xFFFF,
        ];
        // Expected final data bytes.
        let mut want_d = vec![0u8; 0x40];
        want_d[0x00..0x04].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        want_d[0x08..0x10].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        want_d[0x10] = 0xAA;
        want_d[0x18..0x1A].copy_from_slice(&0xBBBBu16.to_le_bytes());
        want_d[0x20..0x24].copy_from_slice(&0x30u32.to_le_bytes());
        want_d[0x28..0x30].copy_from_slice(&0x400u64.to_le_bytes());
        want_d[0x30] = 0xFF;
        want_d[0x38..0x3A].copy_from_slice(&0x00FFu16.to_le_bytes());

        // Seed the vregs in a state buffer: data vregs 1..8 and address vregs
        // 9..15 + v0. `base` is the address base (0 for interp offset-space,
        // arena.base for native absolute space).
        macro_rules! seed_state {
            ($st:expr, $base:expr) => {{
                let s: &mut [u8] = $st;
                let base: u64 = $base;
                let mut put = |v: usize, x: u64| {
                    s[interp::STATE_VREGS + v * 8..interp::STATE_VREGS + v * 8 + 8]
                        .copy_from_slice(&x.to_le_bytes())
                };
                put(1, 0x1122_3344); put(2, 0x0102_0304_0506_0708);
                put(3, 0xAA); put(4, 0xBBBB); put(5, 0x10);
                put(6, 0x100); put(7, 0x05); put(8, 0x0100);
                put(9, base + 0x8000); put(10, base + 0x8008); put(11, base + 0x8010);
                put(12, base + 0x8018); put(13, base + 0x8020); put(14, base + 0x8028);
                put(15, base + 0x8030); put(0, base + 0x8038);
            }};
        }

        // Interpreter run.
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x10000];
        mem[0x8000..0x8000 + 0x40].copy_from_slice(&data_init);
        seed_state!(&mut st, 0u64);
        interp::interpret(&mut st, &mut mem, &prog)
            .map_err(|e| anyhow!("[31] atomic XCHG/XADD interp failed: {:?}", e))?;
        let mut vi = [0u64; 9];
        for i in 0..9 {
            vi[i] = u64::from_le_bytes(st[interp::STATE_VREGS + i * 8..interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
        }
        let mem_i = mem[0x8000..0x8000 + 0x40].to_vec();

        // Native VM run.
        let mut varena = Arena::new(0x40000)?;
        let (vc, vt, vb, vs, vtr, vdata) = (
            varena.base + 0x1000, varena.base + 0x4000, varena.base + 0x5000,
            varena.base + 0x6000, varena.base + 0x8000, varena.base + 0x9000,
        );
        let module = build_vm_module(vc as u64, vt as u64, vb as u64, prog.clone(), handlers::EntryMode::Ksa)?;
        handlers::validate_vm_code(&module.code)?;
        let tramp = encode_trampoline(vs as u64, vdata as u64, vdata as u64, vc as u64, vtr as u64)?;
        let vbase = varena.base as u64;
        {
            let b = varena.bytes();
            b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
            b[0x4000..0x4000 + module.table.len()].copy_from_slice(&module.table);
            b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
            b[0x5000..0x5000 + prog.len()].copy_from_slice(&prog);
            b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
            b[0x9000..0x9000 + 0x40].copy_from_slice(&data_init);
            seed_state!(&mut b[0x6000..0x6000 + interp::STATE_SIZE], vbase + 0x1000);
        }
        varena.call(0x8000);
        let b = varena.bytes();
        let mut vn = [0u64; 9];
        for i in 0..9 {
            vn[i] = u64::from_le_bytes(b[0x6000 + interp::STATE_VREGS + i * 8..0x6000 + interp::STATE_VREGS + i * 8 + 8].try_into().unwrap());
        }
        let mem_n = b[0x9000..0x9000 + 0x40].to_vec();

        assert_eq!(vi[1..], want_v[1..], "[31] atomic XCHG/XADD interpreter vregs mismatch\ninterp={:?}\nwant  ={:?}", &vi[1..], &want_v[1..]);
        assert_eq!(vn[1..], want_v[1..], "[31] atomic XCHG/XADD native vregs mismatch\nnative={:?}\nwant  ={:?}", &vn[1..], &want_v[1..]);
        // v0 was used only as the XADD16 address; it must be unchanged.
        assert_eq!(vi[0], 0x8038, "[31] interp address vreg clobbered");
        assert_eq!(vn[0], vbase + 0x9038, "[31] native address vreg clobbered");
        assert_eq!(mem_i, want_d, "[31] atomic XCHG/XADD interpreter mem mismatch");
        assert_eq!(mem_n, want_d, "[31] atomic XCHG/XADD native mem mismatch");
        println!("[31] v48 atomic memory XCHG/XADD (interp == native == x86, 8/16/32/64-bit): PASS");
    }
    let _ = std::io::stdout().flush();

    // ── [32] 종료 시 Once teardown 패닉 / VA 크래시 재현 테스트 ─────────
    match run_exit_teardown_test() {
        Ok(_) => println!("[32] exit teardown (Once CAS+XCHG+XADD width matrix + call_once x2 + R14/R15 isolation): PASS"),
        Err(e) => {
            println!("[32] exit teardown:                                        FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── [33] handler 생성 x64 코드의 ABI/스택/복귀 규약 검증 ─────────────
    match run_handler_abi_test() {
        Ok(_) => println!("[33] handler ABI/stack/return conventions (static decode + runtime callee-saved/RSP/XMM preservation incl. native bridge): PASS"),
        Err(e) => {
            println!("[33] handler ABI/stack/return:                            FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    // ── [34] carry-flag / width-flag regression (SBB incoming-CF, XADD 8/16
    // flags, CMPXCHG flag preservation). Locks in the P0/P1 fixes. ──────────
    match run_carry_flag_fix_test() {
        Ok(_) => println!("[34] carry/width-flag regression (SBB incoming-CF, XADD 8/16 flags, CMPXCHG flag preserve): PASS"),
        Err(e) => {
            println!("[34] carry/width-flag regression:                       FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    match run_cmovcc_test() {
        Ok(_) => println!("[35] D-1 CMOVcc (all cond families; lift==interp==native): PASS"),
        Err(e) => {
            println!("[35] D-1 CMOVcc:                                                FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    match run_string_ops_test() {
        Ok(_) => println!("[36] C-1 string ops (rep stos/movs/lods/scas/cmps + non-REP; interp==native): PASS"),
        Err(e) => {
            println!("[36] C-1 string ops:                                                                   FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    match run_bmi_test() {
        Ok(_) => println!("[37] B-1 BMI1/2 (lzcnt/popcnt/blsr/blsmsk/blsi/andn; interp==native): PASS"),
        Err(e) => {
            println!("[37] B-1 BMI1/2:                                                                     FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    match run_sse_fpu_test() {
        Ok(_) => println!("[38] A-1 SSE/FPU (scalar FP, 128-bit logic, cvt family, pextrd/pinsrd + lift; interp==native): PASS"),
        Err(e) => {
            println!("[38] A-1 SSE/FPU:                                                                    FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    match run_lock_incdec_test() {
        Ok(_) => println!("[39] v55 LOCK atomic inc/dec (8/16/32/64 + CF-preserve + lift; interp==native==x86): PASS"),
        Err(e) => {
            println!("[39] v55 LOCK atomic inc/dec:                                                    FAIL ({})", e);
            return Err(e);
        }
    }
    let _ = std::io::stdout().flush();

    println!("==================================================================");
    println!(" [VM SELF-TEST] ALL CHECKS PASSED");
    println!("==================================================================");
    Ok(())
}


fn pass_fail(ok: bool) -> String {
    if ok {
        "PASS".to_string()
    } else {
        "FAIL".to_string()
    }
}
