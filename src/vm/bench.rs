// ==============================================================================
// VM benchmark (--vm-bench): interpreter vs native VM throughput.
// ==============================================================================

use super::arena::Arena;
use super::encode::encode_trampoline;
use super::{build_vm_module_mba, VM_STATE_SIZE};
use crate::vm::{handlers, interp, ksa, lifter};
use anyhow::{Result, anyhow};
use rand::RngCore;

/// M8 (v45): VM 성능 벤치마크 — `--vm-bench`.
///
/// 동일한 KSA 바이트코드를 인터프리터와 네이티브 VM으로 여러 번 실행해 초당 처리량과
/// 평균 지연을 측정, VM이 네이티브에 비해 얼마나 느린지(또는 빠른지)를 보고한다.
/// 패킹 없이 `--vm-bench` 단독 실행으로 동작한다.
pub fn run_vm_bench() -> Result<()> {
    use std::time::Instant;

    let mut rng = rand::thread_rng();
    let mut seed_masked = [0u8; 256];
    rng.fill_bytes(&mut seed_masked);
    let (k1, k2, k3) = (rng.next_u32(), rng.next_u32(), rng.next_u32());

    let seq = ksa::build_ksa_instructions(0, k1, k2, k3);
    let bc = lifter::lift_ksa(&seq)?;

    // Build native VM once, reuse across iterations — with real arena VAs so the
    // entry stub's r9/r10 (bytecode/table) point at the actual placed memory.
    let mut arena = Arena::new(0x20000)?;
    let sbox_va = arena.base + 0x2000;
    let seed_va = arena.base + 0x3000;
    let code_va = arena.base + 0x5000;
    let table_va = arena.base + 0x7000;
    let bc_va = arena.base + 0x8000;
    let state_va = arena.base + 0x9000;
    let vsbox_va = arena.base + 0xA000;
    let tramp_va = arena.base + 0xB000;
    let module = build_vm_module_mba(code_va as u64, table_va as u64, bc_va as u64, bc.clone(), handlers::EntryMode::Ksa)?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(state_va as u64, vsbox_va as u64, seed_va as u64, code_va as u64, tramp_va as u64)?;
    {
        let b = arena.bytes();
        b[0x3000..0x3000 + 256].copy_from_slice(&seed_masked);
        b[0x5000..0x5000 + module.code.len()].copy_from_slice(&module.code);
        b[0x7000..0x7000 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + module.bytecode.len()].copy_from_slice(&module.bytecode);
        b[0xB000..0xB000 + tramp.len()].copy_from_slice(&tramp);
    }

    let iters = 2000usize;

    // Interpreter benchmark.
    let t0 = Instant::now();
    for _ in 0..iters {
        let mut st = vec![0u8; interp::STATE_SIZE];
        let mut mem = vec![0u8; 0x2000];
        mem[0x1000..0x1000 + 256].copy_from_slice(&seed_masked);
        st[interp::STATE_PTR_SBOX..interp::STATE_PTR_SBOX + 8]
            .copy_from_slice(&(0x100usize as u64).to_le_bytes());
        st[interp::STATE_PTR_SEED..interp::STATE_PTR_SEED + 8]
            .copy_from_slice(&(0x1000usize as u64).to_le_bytes());
        interp::interpret(&mut st, &mut mem, &bc).map_err(|e| anyhow!("bench interp failed: {:?}", e))?;
    }
    let interp_dur = t0.elapsed();

    // Native VM benchmark (MBA-obfuscated module).
    let t1 = Instant::now();
    for _ in 0..iters {
        let b = arena.bytes();
        b[0x9000..0x9000 + VM_STATE_SIZE].fill(0);
        b[0xA000..0xA000 + 256].fill(0);
        arena.call(0xB000);
    }
    let native_dur = t1.elapsed();

    let interp_per = interp_dur.as_secs_f64() / iters as f64;
    let native_per = native_dur.as_secs_f64() / iters as f64;
    let speedup = interp_per / native_per.max(1e-12);

    println!("==================================================================");
    println!(" [VM BENCH] M8 — 인터프리터 vs 네이티브 VM (KSA, {}회)", iters);
    println!("==================================================================");
    println!("  bytecode: {} B", bc.len());
    println!("  handler table: MBA-obfuscated (--m8 경로)");
    println!("  interpreter: {:.3} µs/iter", interp_per * 1e6);
    println!("  native VM:   {:.3} µs/iter", native_per * 1e6);
    println!("  native는 인터프리터 대비 {:.1}x", speedup);
    println!("==================================================================");
    Ok(())
}




