use std::hint::black_box;

mod arithmetic;
mod state_machine;
mod algorithms;
mod dispatch;
mod data;
mod crypto;
mod threads;
mod exceptions;
mod floating_point;
mod polymorphism;
mod mini_vm;
mod sys_interop;
mod tls_and_statics;
mod win32_ffi;
mod game_engine;
mod gui_overlay;
mod gui_window;

use arithmetic::*;
use state_machine::*;
use algorithms::*;
use dispatch::*;
use data::*;
use crypto::*;
use threads::*;
use exceptions::*;
use floating_point::*;
use polymorphism::*;
use mini_vm::*;
use sys_interop::*;
use tls_and_statics::*;
use game_engine::*;
use gui_window::*;

#[inline(never)]
fn banner() {
    println!("=========================================================================");
    println!("   Rust Advanced Protection Test & Win32 Cyber Defender Game v3.0");
    println!("=========================================================================");
}

#[inline(never)]
fn stage_one(input: u64) -> u64 {
    let a = complex_add(input, 0x1337);
    let b = complex_mul(a, 0x41);
    let c = rotate_mix(b);
    let d = conditional_transform(c);

    black_box(d)
}

#[inline(never)]
fn stage_two(input: u64) -> u64 {
    let mut state = MachineState::new(input);

    for i in 0..17 {
        state.step(i);
    }

    black_box(state.finish())
}

#[inline(never)]
fn stage_three(input: u64) -> u64 {
    let mut values = Vec::new();

    for i in 0..32u64 {
        let x = pseudo_random(input ^ i);
        values.push(x);
    }

    values.sort_unstable();

    let mut result = 0u64;

    for (i, value) in values.iter().enumerate() {
        result ^= value.rotate_left((i % 63) as u32);
        result = result.wrapping_mul(0x9E3779B185EBCA87);
    }

    black_box(result)
}

#[inline(never)]
fn stage_four(input: u64) -> u64 {
    let mut result = input;

    for i in 0..8 {
        result = dispatcher(
            match i {
                0 => Operation::Add,
                1 => Operation::Xor,
                2 => Operation::Rotate,
                3 => Operation::Multiply,
                4 => Operation::Subtract,
                5 => Operation::Mix,
                6 => Operation::Fold,
                _ => Operation::Final,
            },
            result,
            i as u64 + 1,
        );
    }

    black_box(result)
}

#[inline(never)]
fn recursive_test(value: u64, depth: u32) -> u64 {
    if depth == 0 {
        return value ^ 0xDEADBEEF;
    }

    let next = if value & 1 == 0 {
        value.rotate_left(7)
    } else {
        value.rotate_right(11)
    };

    recursive_test(
        next.wrapping_mul(0x100000001B3),
        depth - 1,
    )
}

#[inline(never)]
fn branch_forest(x: u64) -> u64 {
    let mut result = x;

    for i in 0..24 {
        result = match (result ^ i) & 7 {
            0 => result.wrapping_add(0x1111),
            1 => result.wrapping_mul(3),
            2 => result.rotate_left(5),
            3 => result ^ 0xAAAAAAAAAAAAAAAA,
            4 => result.wrapping_sub(0x2222),
            5 => result.rotate_right(9),
            6 => result.wrapping_mul(7),
            _ => !result,
        };
    }

    black_box(result)
}

#[inline(never)]
fn byte_processing(seed: u64) -> u64 {
    let mut buffer = test_buffer(seed);

    for i in 0..buffer.len() {
        let previous = if i == 0 {
            0x5Au8
        } else {
            buffer[i - 1]
        };

        buffer[i] = buffer[i]
            .wrapping_add(previous)
            .rotate_left((i % 7) as u32);
    }

    let mut hash = 0xCBF29CE484222325u64;

    for byte in buffer {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001B3);
    }

    black_box(hash)
}

fn main() {
    banner();

    let args: Vec<String> = std::env::args().collect();
    let is_headless = args.iter().any(|arg| arg == "--headless");
    let is_gui_only = args.iter().any(|arg| arg == "--gui");

    let seed = 0x1234_5678_9ABC_DEF0u64;

    println!("[1] arithmetic");
    let a = stage_one(seed);
    println!("    result = {:#016x}", a);

    println!("[2] state machine");
    let b = stage_two(a);
    println!("    result = {:#016x}", b);

    println!("[3] algorithm");
    let c = stage_three(b);
    println!("    result = {:#016x}", c);

    println!("[4] dispatcher");
    let d = stage_four(c);
    println!("    result = {:#016x}", d);

    println!("[5] recursion");
    let e = recursive_test(d, 8);
    println!("    result = {:#016x}", e);

    println!("[6] branch forest");
    let f = branch_forest(e);
    println!("    result = {:#016x}", f);

    println!("[7] byte processing");
    let g = byte_processing(f);
    println!("    result = {:#016x}", g);

    println!("[8] pure rust crypto (AES, ChaCha20, SHA256)");
    let h = stage_crypto(g);
    println!("    result = {:#016x}", h);

    println!("[9] multithreading & atomics");
    let i = stage_threads(h);
    println!("    result = {:#016x}", i);

    println!("[10] SEH unwinding & catch_unwind");
    let j = stage_exceptions(i);
    println!("    result = {:#016x}", j);

    println!("[11] floating point & Taylor series");
    let k = stage_floating_point(j);
    println!("    result = {:#016x}", k);

    println!("[12] dynamic vtables & closures");
    let l = stage_polymorphism(k);
    println!("    result = {:#016x}", l);

    println!("[13] internal bytecode VM interpreter");
    let m = stage_mini_vm(l);
    println!("    result = {:#016x}", m);

    println!("[14] system interop & file I/O");
    let n = stage_sys_interop(m);
    println!("    result = {:#016x}", n);

    println!("[15] TLS & static initialization");
    let o = stage_tls_and_statics(n);
    println!("    result = {:#016x}", o);

    println!("[16] CyberDefender game engine simulation");
    let game_sim_hash = run_game_simulation_benchmark(o, 100);
    println!("    result = {:#016x}", game_sim_hash);

    let stage_results: [(&'static str, u64); 15] = [
        ("1. Arithmetic", a),
        ("2. StateMachine", b),
        ("3. Algorithms", c),
        ("4. Dispatcher", d),
        ("5. Recursion", e),
        ("6. BranchForest", f),
        ("7. ByteProcess", g),
        ("8. Crypto(AES)", h),
        ("9. Multithread", i),
        ("10. SEH Unwind", j),
        ("11. FloatMath", k),
        ("12. DynamicVtable", l),
        ("13. MiniBytecodeVM", m),
        ("14. SysInteropIO", n),
        ("15. TLS & Statics", o),
    ];

    let final_value = final_mix(game_sim_hash, seed);

    println!();
    println!("-------------------------------------------------------------------------");
    println!("FINAL CHECKSUM = {:#016x}", final_value);
    println!("-------------------------------------------------------------------------");

    if !is_headless {
        println!("[+] Launching Win32 GUI Window & Cyber Defender Engine...");
        let auto_close = if is_gui_only { None } else { Some(120) };
        launch_gui_window(&stage_results, final_value, auto_close);
    }
}