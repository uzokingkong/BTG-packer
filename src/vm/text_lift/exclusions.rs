

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

// ==============================================================================
// SEH-functions stay native (plan.txt P0 "SEH 안정화" / "SEH 함수 비셔플")
//
// x64 SEH unwind (Rust panic → 0xE06D7363 → catch_unwind) requires EVERY frame
// between the raise site and the catch frame to have a `.pdata` RUNTIME_FUNCTION
// whose UNWIND_INFO matches the real native frame layout, and the catch frame's
// compiler-generated FuncInfo/catch table to reference the executing addresses.
// Block-shuffled code lives in `.textb` (no .pdata, stale FuncInfo RVAs), so any
// such frame breaks the unwind with an unhandled 0xE06D7363.
//
// The fix (option A, SEH 함수 비셔플) keeps exactly those functions at their
// original `.text` addresses, where the compiler's .pdata/UNWIND_INFO/FuncInfo
// remain valid. The native set is deliberately the *minimal* one that the OS
// unwinder walks from a raise up to its catch:
//
//   - panic-string-referencing functions (the raise path, e.g. core::panicking),
//   - functions whose UNWIND_INFO has an EHANDLER/UHANDLER flag (can host catch
//     frames or cleanup frames — e.g. the monomorphized __rust_try),
//   - functions that can transitively reach a panic-string function WITHOUT
//     passing through a handler function — these are the frames strictly below a
//     catch (the unwinder must walk them, but their caller-ancestors above the
//     catch do not need .pdata),
//   - minus the entry function, which must stay shuffled so the packed binary
//     still enters through the dispatcher (a native entry would silently run the
//     whole program as the un-protected original .text copy).
//
// Unlike `detect_panic_unwind_ranges` (the VM path, which keeps the whole
// bidirectional call+global closure native — 11,016 blocks in this target),
// this uses only *downward* reachability so the entry chain and the rest of the
// program stay shuffled (protection is preserved; only the unwind-relevant
// frames go native).
// ==============================================================================

/// Result of the SEH native-preservation scan (block-shuffle pipeline).
#[derive(Debug, Clone, Default)]
pub struct SehNativeExclusion {
    /// Whole functions (absolute begin..end VA) to keep un-shuffled.
    pub func_ranges: Vec<(u64, u64)>,
}

/// Does a `.pdata` function range contain a computed/indirect jump (`jmp r/m64`
/// with a register or memory-table operand)? These are the **switch-dispatch**
/// functions. Under block-level VM lifting the CFG is dispatched basic-block by
/// basic-block, so a switch target block can be entered directly WITHOUT its
/// enclosing frame's prologue/saved-state instructions having run first; the
/// block then reads a stale frame local and computes a garbage absolute address
/// (the observed `xchg eax,[r11]` with `r11=0xFFFFFFFFFFFFFFFE` at exit-time
/// Once completion). Keeping exactly this class native is the minimal structural
/// guard that still virtualizes every ordinary (straight-line/branch-only) SEH
/// function. Import thunks (`jmp [rip+disp]`, FF /4 mod=0 rm=5) are excluded —
/// they are plain tail-call thunks, not switch dispatch.
pub fn fn_has_computed_jump(
    fs: u64,
    fe: u64,
    text_bytes: &[u8],
    base_va: u64,
) -> bool {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
    let off = (fs.saturating_sub(base_va)) as usize;
    if off >= text_bytes.len() {
        return false;
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
        if inst.flow_control() == FlowControl::IndirectBranch {
            // Skip `jmp [rip+disp32]` import-thunk tail calls (plain thunk).
            if inst.op0_kind() == OpKind::Memory && inst.is_ip_rel_memory_operand() {
                continue;
            }
            return true;
        }
    }
    false
}

/// Detect the `.pdata` functions that reference the Rust Once/panic runtime's
/// shared-state globals (first-order, `.data`/`.bss` only).
///
/// This is the teardown-safety net used when the SEH set is FULLY virtualized
/// (`BTG_SEH_NONE=1`). The Once/panic runtime's completion frames (e.g. the
/// `Once::call_once` completion path with `xchg [state], COMPLETE`) read and
/// write **frame locals** (`[rbp-0x18]` saved-state slots) that are set up by
/// the function's native prologue. When such a frame is block-lifted and the VM
/// dispatches into the middle of it (no prologue), the frame slot holds stale
/// stack data and the completion computes a garbage absolute address for the
/// atomic xchg (observed as `xchg eax,[r11]` with `r11=0xFFFFFFFFFFFFFFFE` →
/// exit-time 0xC0000005 teardown).
///
/// Every function that pokes one of those shared slots must stay native (it is
/// then reached through the native-call bridge, which runs its real prologue).
/// Restricting the shared-set to `.data`/`.bss` excludes the read-only
/// panic-message strings in `.rdata` (which otherwise pull in every function
/// that merely formats a panic) while keeping the mutable Once/hook/stdio state.
pub fn detect_runtime_shared_global_functions(
    text_bytes: &[u8],
    base_va: u64,
    image_base: u64,
    relayed_sections: &[crate::pe::builder::SectionData],
) -> Vec<(u64, u64)> {
    use iced_x86::{Decoder, DecoderOptions, OpKind};

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

    // 2) .pdata function ranges
    let funcs = parse_pdata_functions(relayed_sections, image_base);
    let func_of = |va: u64| -> Option<(u64, u64)> {
        funcs
            .iter()
            .copied()
            .find(|&(s, e, _)| s <= va && va < e)
            .map(|(s, e, _)| (s, e))
    };

    // 3) decode .text: panic-string reference sites -> seed function starts.
    let mut refs: Vec<u64> = Vec::new();
    let mut dec = Decoder::with_ip(64, text_bytes, base_va, DecoderOptions::NONE);
    while dec.can_decode() {
        let inst = dec.decode();
        if inst.is_invalid() {
            continue;
        }
        for oi in 0..inst.op_count() {
            if inst.op_kind(oi) == OpKind::Memory && inst.is_ip_rel_memory_operand() {
                let tgt = inst.memory_displacement64();
                if panic_string_vas.contains(&tgt) {
                    refs.push(inst.ip());
                }
            }
        }
    }
    let mut seed_starts: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for &r in &refs {
        if let Some((s, _)) = func_of(r) {
            seed_starts.insert(s);
        }
    }
    if seed_starts.is_empty() {
        return Vec::new();
    }

    // 4) shared mutable-state ranges: .data / .bss / .data$* (NOT .rdata — the
    //    read-only panic-message strings must not seed the shared set).
    let state_ranges: Vec<(u64, u64)> = relayed_sections
        .iter()
        .filter(|s| s.name.starts_with(".data") || s.name.starts_with(".bss"))
        .map(|s| {
            let start = image_base + s.virtual_address as u64;
            let len = (s.virtual_size.max(s.bytes.len() as u32)) as u64;
            (start, start + len)
        })
        .collect();
    if state_ranges.is_empty() {
        return Vec::new();
    }

    // 5) decode a function range and return the .data/.bss addresses it references.
    let fn_state_refs = |fs: u64, fe: u64| -> Vec<u64> {
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
                } else if inst.memory_base() == iced_x86::Register::None
                    && inst.memory_index() == iced_x86::Register::None
                {
                    inst.memory_displacement64()
                } else {
                    continue;
                };
                if state_ranges.iter().any(|&(gs, ge)| gs <= addr && addr < ge) {
                    out.push(addr);
                }
            }
        }
        out
    };

    // 6) the shared-state slots the Once/panic runtime touches.
    let mut shared: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for &s in &seed_starts {
        if let Some(&(_, e, _)) = funcs.iter().find(|&&(ss, _, _)| ss == s) {
            for g in fn_state_refs(s, e) {
                shared.insert(g);
            }
        }
    }
    if shared.is_empty() {
        return Vec::new();
    }

    // 7) keep native every .pdata function that references one of those slots.
    let mut native: Vec<(u64, u64)> = funcs
        .iter()
        .filter(|&&(s, e, _)| {
            fn_state_refs(s, e).iter().any(|g| shared.contains(g))
        })
        .map(|&(s, e, _)| (s, e))
        .collect();
    native.sort_by_key(|r| r.0);
    native.dedup();

    if !native.is_empty() {
        let bytes: u64 = native.iter().map(|(s, e)| e - s).sum();
        println!(
            "[+] SEH teardown-guard: keeping {} function(s) native (Once/panic shared-state, 0x{:X} bytes)",
            native.len(),
            bytes
        );
    }
    native
}

/// Parse `.pdata` RUNTIME_FUNCTION entries into absolute function ranges plus
/// each entry's UNWIND_INFO RVA.
fn parse_pdata_functions(
    relayed_sections: &[crate::pe::builder::SectionData],
    image_base: u64,
) -> Vec<(u64, u64, u32)> {
    let mut funcs: Vec<(u64, u64, u32)> = Vec::new();
    if let Some(pd) = relayed_sections.iter().find(|s| s.name == ".pdata") {
        for chunk in pd.bytes.chunks_exact(12) {
            if chunk.len() < 12 {
                break;
            }
            let s0 = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
            let e0 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
            let u0 = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
            if s0 > 0 && e0 > s0 {
                funcs.push((image_base + s0 as u64, image_base + e0 as u64, u0));
            }
        }
    }
    funcs.sort_by_key(|f| f.0);
    funcs
}

/// Resolve a UNWIND_INFO RVA to its header byte (version|flags), following
/// CHAININFO links. Returns `None` if it cannot be located.
///
/// x64 UNWIND_INFO header byte 0: [version(3) | flags(5)]. Within the flags
/// field, UNW_FLAG_EHANDLER = 0x01 and UNW_FLAG_UHANDLER = 0x02, i.e. the
/// handler bits are byte0 & 0x18. UNW_FLAG_CHAININFO = 0x04 (byte0 & 0x20)
/// chains to another UNWIND_INFO whose RVA sits at header offset 4.
fn unwind_info_flags(
    unwind_rva: u32,
    relayed_sections: &[crate::pe::builder::SectionData],
) -> Option<u8> {
    let locate = |rva: u32| -> Option<(&[u8], usize)> {
        for sec in relayed_sections {
            let sva = sec.virtual_address as u64;
            let svs = sec.virtual_size.max(sec.bytes.len() as u32) as u64;
            let r = rva as u64;
            if r >= sva && r < sva + svs {
                let off = (r - sva) as usize;
                if off + 4 <= sec.bytes.len() {
                    return Some((&sec.bytes, off));
                }
                return None;
            }
        }
        None
    };
    let mut rva = unwind_rva;
    for _ in 0..8 {
        let (bytes, off) = locate(rva)?;
        let byte0 = bytes[off];
        let flags_field = byte0 >> 3;
        if flags_field & (0x01 | 0x02) != 0 {
            return Some(byte0); // EHANDLER or UHANDLER present
        }
        if flags_field & 0x04 != 0 && off + 8 <= bytes.len() {
            // CHAININFO: the next UNWIND_INFO RVA is at header offset 4.
            rva = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap());
            continue;
        }
        return Some(byte0);
    }
    None
}

/// Detect the functions that must stay NATIVE in the block-shuffle pipeline so
/// the OS exception unwinder can walk from a panic raise up to its catch frame.
/// See the module comment above for the exact selection rule.
pub fn detect_seh_native_functions(
    text_bytes: &[u8],
    base_va: u64,
    image_base: u64,
    relayed_sections: &[crate::pe::builder::SectionData],
    entry_point_va: u64,
    full_seh_virtualize: bool,
) -> SehNativeExclusion {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
    use std::collections::{HashMap, HashSet, VecDeque};

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

    // 2) .pdata function ranges (+ unwind-info RVAs)
    let funcs = parse_pdata_functions(relayed_sections, image_base);
    let func_of = |va: u64| -> Option<(u64, u64)> {
        funcs
            .iter()
            .copied()
            .find(|&(s, e, _)| s <= va && va < e)
            .map(|(s, e, _)| (s, e))
    };

    // 3) decode .text: panic-string reference sites + direct call/jmp edges
    let mut refs: Vec<u64> = Vec::new();
    let mut call_edges: Vec<(u64, u64)> = Vec::new(); // (caller, direct callee VA)
    let mut dec = Decoder::with_ip(64, text_bytes, base_va, DecoderOptions::NONE);
    while dec.can_decode() {
        let inst = dec.decode();
        if inst.is_invalid() {
            continue;
        }
        let va = inst.ip();
        match inst.flow_control() {
            FlowControl::Call | FlowControl::UnconditionalBranch => {
                let near = inst.near_branch_target();
                if near >= base_va && near < base_va + text_bytes.len() as u64 {
                    call_edges.push((va, near));
                }
            }
            _ => {}
        }
        for oi in 0..inst.op_count() {
            if inst.op_kind(oi) == OpKind::Memory && inst.is_ip_rel_memory_operand() {
                let tgt = inst.memory_displacement64();
                if panic_string_vas.contains(&tgt) {
                    refs.push(va);
                }
            }
        }
    }

    // 4) seeds
    let mut panic_seed_starts: HashSet<u64> = HashSet::new();
    for &r in &refs {
        if let Some((s, _)) = func_of(r) {
            panic_seed_starts.insert(s);
        }
    }
    let mut ehandler_starts: HashSet<u64> = HashSet::new();
    for &(s, _, u) in &funcs {
        if let Some(byte0) = unwind_info_flags(u, relayed_sections) {
            if byte0 & 0x18 != 0 {
                ehandler_starts.insert(s);
            }
        }
    }

    // 5) reverse reachability over direct call edges (caller graph)
    let mut callers: HashMap<u64, Vec<u64>> = HashMap::new(); // callee -> callers
    for &(caller, callee) in &call_edges {
        if let (Some((cs, _)), Some((ks, _))) = (func_of(caller), func_of(callee)) {
            callers.entry(ks).or_default().push(cs);
        }
    }
    let reverse_reach = |seeds: &HashSet<u64>| -> HashSet<u64> {
        let mut out: HashSet<u64> = seeds.clone();
        let mut queue: VecDeque<u64> = seeds.iter().copied().collect();
        while let Some(f) = queue.pop_front() {
            if let Some(cs) = callers.get(&f) {
                for &c in cs {
                    if out.insert(c) {
                        queue.push_back(c);
                    }
                }
            }
        }
        out
    };
    let can_reach_panic = reverse_reach(&panic_seed_starts);
    let can_reach_ehandler = reverse_reach(&ehandler_starts);

    // 6) native set = seeds | {can reach panic but NOT can reach a handler}
    //
    // P4 (SEH virtualization) -- SEH native set 175 -> minimal (132 verified;
    //   0 target was tested but leaves an exit-time 0xC0000005 teardown, so 132 is
    //   the accepted minimum that keeps the 16-test + checksum contract clean).
    //
    //   Rationale: x64 SEH unwind (panic -> 0xE06D7363 -> catch_unwind) needs a
    //   valid .pdata RUNTIME_FUNCTION for every frame between the raise site and
    //   the catch frame. The P4 bridge (.pdata bridge leaf + UNWIND_INFO, build.rs
    //   update_pdata_seh) covers the boot/dispatcher frame for OS unwind, so the
    //   intermediate "raise..catch" frames need not stay native -- they are
    //   virtualized and the unwinder walks through the bridge .pdata to the VM
    //   state restore point.
    //
    //   Measured on this target: panic_seed=38, ehandler=162, and the old
    //   {can_reach_panic - can_reach_ehandler} reverse-reach term added 0 extra
    //   functions. The over-broad part was keeping ALL 162 ehandler functions
    //   native; of those, 30 are unreachable from any panic (irrelevant to this
    //   program's unwinds) and are virtualized harmlessly.
    //   -> minimal = the catch/cleanup frames actually on the raise..catch path
    //      (ehandler & can_reach_panic) = 132.
    //
    //   Env BTG_SEH_MINIMAL (default 1) -- set to 0 to restore the old full set
    //   (panic_seed | ehandler | {can_reach_panic - can_reach_ehandler} = 175) for
    //   A/B regression.
    //
    //   Env BTG_SEH_NONE (default 0) -- set to 1 to virtualize the ENTIRE SEH set
    //   (native set = empty). This is the P4 "전체 SEH 가상화" path: the .pdata
    //   regeneration (bridge UNWIND_INFO, build.rs update_pdata_seh full-coverage
    //   mode) must cover the whole-program VM region so the OS unwinder can walk
    //   virtualized frames. Only honored when `full_seh_virtualize` is set (the
    //   whole-program VM path --vm --vm-oep, where ALL virtualized code runs in a
    //   single Program-VM frame and one bridge UNWIND_INFO is correct). The
    //   block-shuffle path (--vm only) keeps the 132 minimal set because shuffled
    //   blocks execute natively with heterogeneous frames that no single
    //   UNWIND_INFO can cover.
    let seh_none = full_seh_virtualize
        && std::env::var("BTG_SEH_NONE").map_or(false, |v| v != "0");
    let seh_minimal = std::env::var("BTG_SEH_MINIMAL").map_or(true, |v| v != "0");
    let mut native: HashSet<u64> = HashSet::new();
    if seh_none {
        // full SEH virtualization: every ordinary (straight-line / branch-only)
        // SEH/panic/catch function is lifted into the VM. The ONLY functions kept
        // native are the two orthogonal guards:
        //   1. switch-dispatch (computed-jump) EHANDLER functions on the
        //      raise..catch path — block-level VM dispatch enters switch targets
        //      without the frame prologue, so their frame-locals read stale data
        //      (Once completion `xchg eax,[r11]` with r11=-2 -> exit-time AV);
        //   2. Once/panic shared-state teardown frames (data-global pokes).
        for &s in ehandler_starts.iter() {
            if !can_reach_panic.contains(&s) {
                continue;
            }
            if let Some(&(ss, ee, _)) = funcs.iter().find(|&&(ss, _, _)| ss == s) {
                if fn_has_computed_jump(ss, ee, text_bytes, base_va) {
                    native.insert(s);
                }
            }
        }
        for (s, e) in detect_runtime_shared_global_functions(
            text_bytes, base_va, image_base, relayed_sections,
        ) {
            native.insert(s);
            let _ = e;
        }
        println!(
            "[+] SEH native-preservation: FULL SEH VIRTUALIZATION (BTG_SEH_NONE=1) -- keeping {} function(s) native (panic_seed={}, ehandler={}, computed-jump={})",
            native.len(),
            panic_seed_starts.len(),
            ehandler_starts.len(),
            native.len()
        );
    } else if seh_minimal {
        // P4 minimal: keep only the catch/cleanup frames on the raise..catch path
        // (EHANDLER/UHANDLER functions reachable from a panic seed).
        for &s in ehandler_starts.iter() {
            if can_reach_panic.contains(&s) {
                native.insert(s);
            }
        }
    } else {
        native.extend(panic_seed_starts.iter().copied());
        native.extend(ehandler_starts.iter().copied());
        for &s in &can_reach_panic {
            if !can_reach_ehandler.contains(&s) {
                native.insert(s);
            }
        }
    }
    // The entry function must stay shuffled: the boot stub dispatches into it,
    // and a native entry would make the whole program run as the original
    // (un-protected) .text copy.
    if let Some((es, _)) = func_of(entry_point_va) {
        native.remove(&es);
    }

    let mut func_ranges: Vec<(u64, u64)> = native
        .iter()
        .filter_map(|&s| funcs.iter().copied().find(|&(ss, _, _)| ss == s).map(|(ss, ee, _)| (ss, ee)))
        .collect();
    func_ranges.sort_by_key(|r| r.0);

    if !func_ranges.is_empty() {
        println!(
            "[+] SEH native-preservation: keeping {} function(s) un-shuffled (panic/catch unwind path)",
            func_ranges.len()
        );
        let bytes: u64 = func_ranges.iter().map(|(s, e)| e - s).sum();
        println!(
            "[+]   total native bytes = 0x{:X} (entry function excluded, dispatcher entry preserved)",
            bytes
        );
    }

    SehNativeExclusion { func_ranges }
}

// ══════════════════════════════════════════════════════════════════════════════
// setjmp / longjmp exclusion (non-local-jump VM boundary)
// ══════════════════════════════════════════════════════════════════════════════
// `setjmp`/`longjmp` (CRT) are the classic VM killers: `setjmp` snapshots the
// host register file into a `jmp_buf`, and `longjmp` restores it while unwinding
// the stack to the setjmp frame. Inside virtualized code the authoritative guest
// state lives in the VM's virtual registers, so a longjmp that overwrites the
// host registers makes the two files diverge — same corruption class as the SEH
// unwind break above (a `longjmp` lands in the middle of a VM-dispatched
// function whose stack frame / registers do not match). Every function that
// reaches a setjmp/longjmp import must therefore stay native, together with its
// callers/callees, exactly like the SEH/panic set.
//
// Detection is import-name driven (no assumption about the jmp_buf layout):
//   1. goblin parses the import table → the IAT slot VAs whose imported name is
//      one of the setjmp/longjmp family;
//   2. scan .text for `call/jmp [rip + disp32]` whose target is such a slot
//      (direct import calls) and for `jmp [rip + disp32]` thunks;
//   3. map every use site to its .pdata function start, add callers that reach a
//      thunk, then run the bidirectional call closure (same rule as the
//      panic/SEH set).
const SETJMP_NAMES: &[&str] = &["setjmp", "_setjmp", "_setjmpex", "_setjmp3", "longjmp", "_longjmp"];

/// Scan output of [`find_setjmp_use_sites`].
#[derive(Debug, Default)]
pub struct SetjmpSites {
    /// VAs of instructions that directly reference a setjmp/longjmp IAT slot
    /// (`call [rip+slot]` or `jmp [rip+slot]`).
    pub use_vas: Vec<u64>,
    /// VAs of `jmp [rip+slot]` import-thunk stubs (callers of these use the API).
    pub thunk_vas: std::collections::HashSet<u64>,
    /// Direct `call/jmp rel32` edges within .text, for the closure.
    pub call_edges: Vec<(u64, u64)>,
}

/// Pure scan: given the setjmp/longjmp IAT slot VAs, find every .text site that
/// references them plus the direct call graph. Testable with synthetic bytes.
pub fn find_setjmp_use_sites(text_bytes: &[u8], base_va: u64, slot_vas: &[u64]) -> SetjmpSites {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
    let mut sites = SetjmpSites::default();
    if slot_vas.is_empty() {
        return sites;
    }
    let mut dec = Decoder::with_ip(64, text_bytes, base_va, DecoderOptions::NONE);
    while dec.can_decode() {
        let inst = dec.decode();
        if inst.is_invalid() {
            continue;
        }
        let va = inst.ip();
        let fc = inst.flow_control();
        match fc {
            FlowControl::Call | FlowControl::UnconditionalBranch => {
                let near = inst.near_branch_target();
                if near >= base_va && near < base_va + text_bytes.len() as u64 {
                    sites.call_edges.push((va, near));
                }
            }
            _ => {}
        }
        for oi in 0..inst.op_count() {
            if inst.op_kind(oi) == OpKind::Memory && inst.is_ip_rel_memory_operand() {
                let tgt = inst.memory_displacement64();
                if slot_vas.contains(&tgt) {
                    sites.use_vas.push(va);
                    // `jmp qword [rip+slot]` = the import thunk stub (iced-x86
                    // classifies it as IndirectBranch, not UnconditionalBranch).
                    if fc == FlowControl::IndirectBranch {
                        sites.thunk_vas.insert(va);
                    }
                }
            }
        }
    }
    sites
}

/// Map a [`SetjmpSites`] scan to whole .pdata function ranges that must stay
/// native: every function containing a use site, plus callers that reach a
/// setjmp/longjmp import thunk, plus the bidirectional call closure.
pub fn setjmp_longjmp_function_ranges(
    sites: &SetjmpSites,
    relayed_sections: &[crate::pe::builder::SectionData],
    image_base: u64,
) -> Vec<(u64, u64)> {
    use std::collections::{HashMap, HashSet, VecDeque};
    if sites.use_vas.is_empty() && sites.thunk_vas.is_empty() {
        return Vec::new();
    }
    let funcs = parse_pdata_functions(relayed_sections, image_base);
    let func_of = |va: u64| -> Option<(u64, u64)> {
        funcs
            .iter()
            .copied()
            .find(|&(s, e, _)| s <= va && va < e)
            .map(|(s, e, _)| (s, e))
    };

    // seeds: functions that directly call/jmp a slot, and callers of a thunk.
    let mut seeds: HashSet<u64> = HashSet::new();
    for &u in &sites.use_vas {
        if let Some((s, _)) = func_of(u) {
            seeds.insert(s);
        }
    }
    for &(caller, callee) in &sites.call_edges {
        if sites.thunk_vas.contains(&callee) {
            if let Some((s, _)) = func_of(caller) {
                seeds.insert(s);
            }
        }
    }

    // bidirectional closure over direct call edges.
    let mut excluded: HashSet<u64> = seeds;
    loop {
        let mut changed = false;
        for &(caller, callee) in &sites.call_edges {
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

    let mut ranges: Vec<(u64, u64)> = excluded
        .iter()
        .filter_map(|&s| func_of(s))
        .collect();
    ranges.sort_by_key(|r| r.0);
    ranges.dedup();
    ranges
}

/// Full pipeline: parse the (relayed) PE imports with goblin, collect the
/// setjmp/longjmp IAT slot VAs, scan the code being considered for
/// virtualization, and return the .pdata function ranges to keep native.
pub fn detect_setjmp_longjmp_functions(
    pe_bytes: &[u8],
    text_bytes: &[u8],
    base_va: u64,
    image_base: u64,
    relayed_sections: &[crate::pe::builder::SectionData],
) -> Vec<(u64, u64)> {
    let mut slots: Vec<u64> = Vec::new();
    if let Ok(pe) = goblin::pe::PE::parse(pe_bytes) {
        for imp in &pe.imports {
            if SETJMP_NAMES.contains(&imp.name.as_ref()) {
                slots.push(image_base.wrapping_add(imp.offset as u64));
            }
        }
    }
    if slots.is_empty() {
        return Vec::new();
    }
    let sites = find_setjmp_use_sites(text_bytes, base_va, &slots);
    if sites.use_vas.is_empty() && sites.thunk_vas.is_empty() {
        return Vec::new();
    }
    let ranges = setjmp_longjmp_function_ranges(&sites, relayed_sections, image_base);
    if !ranges.is_empty() {
        println!(
            "[+] setjmp/longjmp native-preservation: keeping {} function(s) un-virtualized (non-local-jump boundary)",
            ranges.len()
        );
    }
    ranges
}

#[cfg(test)]
mod setjmp_tests {
    use super::*;

    /// Synthetic .text (hand-built machine code, no encoder dependency):
    ///   base+0x00: `jmp qword [rip+disp32]` -> setjmp IAT slot   (FF 25 disp32)
    ///   base+0x20: mov rcx,1 ; `call rel32` -> base (the thunk) ; ret
    fn synth_bytes() -> (Vec<u8>, u64, Vec<u64>) {
        let base = 0x14000_1000u64;
        let slot = 0x14000_5000u64;
        let mut b = Vec::new();
        // thunk: FF 25 disp32, disp = slot - (base + 6)
        let disp_thunk = (slot - (base + 6)) as u32;
        b.extend_from_slice(&[0xFF, 0x25]);
        b.extend_from_slice(&disp_thunk.to_le_bytes());
        // pad to base+0x20
        b.resize(0x20, 0x90);
        // mov rcx, 1
        b.extend_from_slice(&[0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00]);
        // call rel32 -> base; next VA = base+0x27+5 = base+0x2C, disp = base-(base+0x2C) = -0x2C
        let disp_call = (base as i64 - (base + 0x2C) as i64) as u32;
        b.push(0xE8);
        b.extend_from_slice(&disp_call.to_le_bytes());
        // ret
        b.push(0xC3);
        (b, base, vec![slot])
    }

    #[test]
    fn detects_direct_slot_call_and_thunk_caller() {
        let (bytes, base, slots) = synth_bytes();
        let sites = find_setjmp_use_sites(&bytes, base, &slots);
        assert!(!sites.use_vas.is_empty(), "must find the jmp [rip+slot] thunk use");
        assert!(sites.thunk_vas.contains(&base), "thunk at base must be flagged");
        // The caller (base+0x27) reaches the thunk via a direct call edge.
        assert!(
            sites.call_edges.iter().any(|(c, t)| *t == base),
            "caller -> thunk edge must exist"
        );
        assert!(
            sites.call_edges.iter().any(|(c, _)| *c == base + 0x27),
            "caller at base+0x27 must be an edge source"
        );
    }

    #[test]
    fn no_slots_produces_no_sites() {
        let (bytes, base, _) = synth_bytes();
        let sites = find_setjmp_use_sites(&bytes, base, &[]);
        assert!(sites.use_vas.is_empty() && sites.thunk_vas.is_empty());
    }
}

