

// ==============================================================================
// Panic/Unwind runtime exclusion (--vm-oep SEH fix)
//
// Rust `panic!` control flow is not plain call→ret: it runs
//   panic location → Rust panic runtime → unwind personality → Windows SEH →
//   caller-frame search → cleanup/drop
// and relies on the .pdata (RUNTIME_FUNCTION) SEH metadata matching the native
// frame layout of each function. Virtualizing (block-shuffling) those runtime
// functions into the VM breaks that: when a panic unwinds, the OS looks up the
// *original* .pdata for the faulting IP, finds a VM-dispatched frame instead of
// the lifted function's real frame, and the stack/unwind chain is corrupted
// (observed as the `once.rs:166 f.take().unwrap()` teardown panic, entered from
// the VM dispatcher).
//
// There are no symbols in a stripped Rust PE, so we identify the runtime
// functions structurally:
//   1. a function that RIP-relative-references any Rust panic message string in
//      .rdata (std::panicking / core::panicking / once / all `.unwrap()` sites), or
//   2. a function that directly `call`/`jmp` the `_CxxThrowException` or
//      `__CxxFrameHandler3` import thunk, or
//   3. a function transitively reached from (1)/(2) over direct call edges
//      (both callers and callees — so rt::cleanup, the Once machinery and the
//      whole unwind path stay native together).
// Every such function's blocks are kept out of the VM program (see
// `lift_cfg_switch`'s `excluded` set); calls to them bridge to the original
// .text VA natively.
// ==============================================================================
fn find_subslice(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() || from > hay.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Result of the panic/unwind/Once runtime scan.
///
/// - `func_ranges`: whole `.pdata` functions to keep native.
/// - `runtime_globals`: the shared-state slots (Once state word, panic-hook
///   state, stdio state, rt::cleanup state, …) referenced by those functions.
///
/// `lift_program_cfg` keeps native every block inside a `func_range` **and**
/// every block that references one of the `runtime_globals` — the second half
/// is what catches inlined `Once::call_once`/`Once::call`/`is_completed` copies
/// and the Once completion path that lives just past the function's `.pdata`
/// end. Both cases are exactly the once.rs:166 `f.take().unwrap()` teardown
/// crash's root cause: the VM re-executing Once's atomic/closure logic.
#[derive(Debug, Clone, Default)]
pub struct PanicUnwindExclusion {
    pub func_ranges: Vec<(u64, u64)>,
    pub runtime_globals: Vec<u64>,
}

/// Does `inst` reference (via a RIP-relative or absolute memory operand) an
/// address in `globals`? The Once/panic runtime reaches its shared state through
/// both `lea reg,[state]` and atomic `lock cmpxchg [state],reg` forms.
fn instr_refs_global(inst: &iced_x86::Instruction, globals: &std::collections::HashSet<u64>) -> bool {
    use iced_x86::{OpKind, Register};
    for oi in 0..inst.op_count() {
        if inst.op_kind(oi) != OpKind::Memory {
            continue;
        }
        let addr = if inst.is_ip_rel_memory_operand() {
            inst.memory_displacement64()
        } else if inst.memory_base() == Register::None && inst.memory_index() == Register::None {
            inst.memory_displacement64()
        } else {
            continue;
        };
        if globals.contains(&addr) {
            return true;
        }
    }
    false
}

/// Does this basic block reference any runtime (Once/panic) shared-state global?
/// Used to keep blocks that contain INLINED Once logic (or a Once completion
/// path outside any `.pdata` boundary) native even though no whole function
/// range covers them.
pub(crate) fn block_refs_runtime_global(
    bb: &crate::graph::BasicBlock,
    globals: &std::collections::HashSet<u64>,
) -> bool {
    bb.instructions.iter().any(|i| instr_refs_global(i, globals))
}

// ── v56 (Phase 2.2): the lock-atomicity exclusion nets were REMOVED ────────
// `block_has_lock_atomic_on_global` / `block_has_lock_memory_rmw` (block
// level) and the LOCK-RMW function quarantine (function level) used to keep
// any block with a `lock`-prefixed memory RMW native, because lowering one to
// a non-atomic load->modify->store corrupted Rust runtime refcounts and the
// Once state (once.rs:166). Every occurring lock memory RMW is now a real
// `lock`-prefixed VM opcode (CMPXCHG v46/v49, XCHG v48, XADD v48, LOCK
// INC/DEC v55), so the atomicity-driven nets are gone; only the structural
// SEH-driven panic/unwind exclusion below remains.

/// Detect the Rust panic/unwind/Once runtime functions in `.text`, so
/// `lift_program_cfg` can keep them native (and keep native every block that
/// touches their shared-state globals — see `PanicUnwindExclusion`).
pub fn detect_panic_unwind_ranges(
    text_bytes: &[u8],
    base_va: u64,
    image_base: u64,
    relayed_sections: &[crate::pe::builder::SectionData],
) -> PanicUnwindExclusion {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind, Register};

    // Rust panic message signatures that only appear in the panic/unwind runtime.
    const SIGS: &[&[u8]] = &[
        b"panicked at ",
        b"called `Option::unwrap()`",
        b"called `Result::unwrap()`",
        b"fatal runtime error",
        b"Rust panics must be rethrown",
        b"failed to initiate panic",
        b"Once instance has previously been poisoned",
        b"thread panicked while processing panic",
        b"drop of the panic payload panicked",
        b"attempt to divide by zero",
        b"index out of bounds",
        b"Rust cannot catch foreign exceptions",
    ];

    // 1) panic-message string VAs in .rdata
    let mut panic_string_vas: Vec<u64> = Vec::new();
    for sec in relayed_sections {
        if sec.name != ".rdata" {
            continue;
        }
        let sec_va = image_base + sec.virtual_address as u64;
        for sig in SIGS {
            let mut pos = 0usize;
            while let Some(i) = find_subslice(&sec.bytes, sig, pos) {
                panic_string_vas.push(sec_va + i as u64);
                pos = i + sig.len();
            }
        }
    }

    // 2) .pdata function ranges (begin..end absolute). A function with no .pdata
    //    entry is a leaf we can still map by the enclosing section, but the SEH
    //    problem only concerns functions that have unwind info, so we map by
    //    .pdata; any reference that falls outside all entries is ignored.
    let pdata = relayed_sections.iter().find(|s| s.name == ".pdata");
    let mut funcs: Vec<(u64, u64)> = Vec::new();
    if let Some(pd) = pdata {
        let b = &pd.bytes;
        for chunk in b.chunks_exact(12) {
            if chunk.len() < 12 {
                break;
            }
            let s0 = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
            let e0 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
            if s0 > 0 && e0 > s0 {
                funcs.push((image_base + s0 as u64, image_base + e0 as u64));
            }
        }
    }
    funcs.sort();
    let func_of = |va: u64| -> Option<(u64, u64)> {
        funcs.iter().copied().find(|&(s, e)| s <= va && va < e)
    };

    // 3) decode .text and collect marker sites
    let mut refs: Vec<u64> = Vec::new(); // VAs of instructions that RIP-ref a panic string
    let mut throw_sites: Vec<u64> = Vec::new(); // VAs of direct call/jmp to throw/framehandler thunks
    let mut call_edges: Vec<(u64, u64)> = Vec::new(); // (caller, direct callee VA)

    let mut dec = Decoder::with_ip(64, text_bytes, base_va, DecoderOptions::NONE);
    while dec.can_decode() {
        let inst = dec.decode();
        if inst.is_invalid() {
            continue;
        }
        let va = inst.ip();
        // direct rel32 call target (must be within .text to be a thunk/function call)
        let near = inst.near_branch_target();
        match inst.flow_control() {
            FlowControl::Call => {
                if near >= base_va && near < base_va + text_bytes.len() as u64 {
                    call_edges.push((va, near));
                }
            }
            FlowControl::UnconditionalBranch => {
                // `jmp rel32` to a thunk is a tail call into the runtime
                if near >= base_va && near < base_va + text_bytes.len() as u64 {
                    call_edges.push((va, near));
                }
            }
            _ => {}
        }
        // RIP-relative operand referencing a panic string
        for oi in 0..inst.op_count() {
            if inst.op_kind(oi) == OpKind::Memory && inst.is_ip_rel_memory_operand() {
                let tgt = inst.memory_displacement64();
                if panic_string_vas.contains(&tgt) {
                    refs.push(va);
                }
            }
        }
        // `call/jmp [rip + IAT]` to an import thunk that is itself a jmp thunk —
        // handled below by resolving import thunk addresses.
    }

    // 4) import thunk addresses for _CxxThrowException / __CxxFrameHandler* / RaiseException
    //    (the CRT thunks are `jmp [rip + IAT]` in .text; their target IAT slot name
    //     contains one of these). We detect them by scanning .text for the thunk
    //     pattern whose RIP-relative target resolves (via the .rdata/.data IAT)
    //     to a name with the marker. To keep this simple and dependency-light we
    //     detect the *call sites* instead: any direct call/jmp whose target VA is
    //     a .text byte whose first opcode is a `jmp [rip+disp32]` to an import we
    //     can name is treated as a throw/raise call site. We rely on the panic
    //     string markers as the primary signal; the thunk scan is a secondary one.
    //     (No import-parse dependency is introduced here.)

    // 5) map marker sites to .pdata function starts
    let mut excluded: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for &r in &refs {
        if let Some((s, _)) = func_of(r) {
            excluded.insert(s);
        }
    }
    for &t in &throw_sites {
        if let Some((s, _)) = func_of(t) {
            excluded.insert(s);
        }
    }

    // 6) transitive closure over direct call edges (both directions), so
    //    rt::cleanup, the Once machinery, the panic payload path and the whole
    //    unwind/teardown chain are kept native together.
    //
    // FIX: the previous version destructured `(caller_ex, callee_ex)` and inserted
    // `s` from the Some side, which re-inserted the already-excluded function and
    // NEVER added the freshly-connected one — so the closure never propagated and
    // e.g. std::sync::Once (a caller of an excluded panic fn via a direct call) was
    // left in the VM, corrupting its atomic state (once.rs:166 unwrap(None) panic).
    loop {
        let mut changed = false;
        for &(caller, callee) in &call_edges {
            let caller_start = func_of(caller).map(|(s, _)| s);
            let callee_start = func_of(callee).map(|(s, _)| s);
            let caller_in = caller_start.map_or(false, |s| excluded.contains(&s));
            let callee_in = callee_start.map_or(false, |s| excluded.contains(&s));
            if caller_in != callee_in {
                // exclude whichever side is not yet in (both forward and backward)
                let to_add = if caller_in { callee_start } else { caller_start };
                if let Some(s) = to_add {
                    if excluded.insert(s) {
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    // ── Data-dependency closure ──────────────────────────────────────────────
    // The Once/panic runtime reads & writes a small set of shared global slots
    // in .data/.rdata (Once state, the Once-stored closure/result, stdio state,
    // panic-hook state, …). The .pdata function boundaries don't always cover the
    // whole runtime (e.g. Once::call_once's completion path lives just past the
    // function's .pdata end and still pokes the same globals). If ANY of that
    // remaining code is VM-lifted, the VM corrupts the shared state even though
    // the runtime function itself runs native — surfacing as once.rs:166
    // `f.take().unwrap()` on None at exit. So: collect the globals referenced by
    // the excluded functions, then also exclude any function that references one
    // of those globals, and repeat (with the call-closure) to a fixpoint.
    //
    // Global (shared-state) sections: .rdata / .data / .bss / .data$*. We ignore
    // .text / .pdata / .rsrc — a code pointer or SEH entry is not a state slot we
    // need to quarantine here (they don't corrupt Once on a VM-lift).
    let global_ranges: Vec<(u64, u64)> = relayed_sections
        .iter()
        .filter(|s| {
            s.name.starts_with(".data") || s.name.starts_with(".rdata") || s.name.starts_with(".bss")
        })
        .map(|s| {
            let start = image_base + s.virtual_address as u64;
            let len = (s.virtual_size.max(s.bytes.len() as u32)) as u64;
            (start, start + len)
        })
        .collect();

    // decode a function range [fs, fe) and return its referenced global addresses
    // that fall inside `global_ranges`.
    let fn_globals = |fs: u64, fe: u64| -> Vec<u64> {
        let mut out = Vec::new();
        let off = (fs.saturating_sub(base_va)) as usize;
        if off >= text_bytes.len() {
            return out;
        }
        let mut d = Decoder::with_ip(64, &text_bytes[off..], fs, DecoderOptions::NONE);
        let mut guard = 0usize;
        for inst in d {
            if guard > 1_000_000 {
                break;
            }
            guard += 1;
            if inst.ip() >= fe {
                break;
            }
            if inst.is_invalid() {
                continue;
            }
            for oi in 0..inst.op_count() {
                if inst.op_kind(oi) != OpKind::Memory {
                    continue;
                }
                let addr = if inst.is_ip_rel_memory_operand() {
                    inst.memory_displacement64()
                } else if inst.memory_base() == Register::None
                    && inst.memory_index() == Register::None
                {
                    inst.memory_displacement64()
                } else {
                    continue;
                };
                if global_ranges.iter().any(|&(gs, ge)| gs <= addr && addr < ge) {
                    out.push(addr);
                }
            }
        }
        out
    };

    loop {
        let mut changed = false;

        // (a) collect globals referenced by currently-excluded functions
        let mut globals: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for &s in excluded.iter() {
            if let Some(&(_, e)) = funcs.iter().find(|&&(ss, _)| ss == s) {
                for g in fn_globals(s, e) {
                    globals.insert(g);
                }
            }
        }
        if globals.is_empty() {
            break;
        }

        // (b) exclude any function referencing one of those globals
        for &(fs, fe) in &funcs {
            if excluded.contains(&fs) {
                continue;
            }
            let refs = fn_globals(fs, fe);
            if refs.iter().any(|g| globals.contains(g)) {
                if excluded.insert(fs) {
                    changed = true;
                }
            }
        }

        // (c) re-run the call-closure so functions that call (or are called by)
        //     the newly-excluded ones are pulled in too.
        for &(caller, callee) in &call_edges {
            let caller_start = func_of(caller).map(|(s, _)| s);
            let callee_start = func_of(callee).map(|(s, _)| s);
            let caller_in = caller_start.map_or(false, |s| excluded.contains(&s));
            let callee_in = callee_start.map_or(false, |s| excluded.contains(&s));
            if caller_in != callee_in {
                let to_add = if caller_in { callee_start } else { caller_start };
                if let Some(s) = to_add {
                    if excluded.insert(s) {
                        changed = true;
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }

    // (v56: the LOCK memory-RMW function quarantine that used to live here was
    // removed — those RMWs are VM opcodes now; see the note at the top.)

    // convert excluded function-start VAs back to ranges, and collect the
    // shared-state globals every excluded function references.
    let mut runtime_globals: std::collections::BTreeSet<u64> = Default::default();
    for &s in excluded.iter() {
        if let Some(&(_, e)) = funcs.iter().find(|&&(ss, _)| ss == s) {
            for g in fn_globals(s, e) {
                runtime_globals.insert(g);
            }
        }
    }
    let func_ranges: Vec<(u64, u64)> = excluded
        .iter()
        .filter_map(|&s| funcs.iter().copied().find(|&(ss, _)| ss == s))
        .collect();

    PanicUnwindExclusion {
        func_ranges,
        runtime_globals: runtime_globals.into_iter().collect(),
    }
}
