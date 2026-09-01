use super::find_subslice;

#[derive(Debug, Clone, Default)]
pub struct SehNativeExclusion {
    /// Whole functions (absolute begin..end VA) to keep un-shuffled.
    pub func_ranges: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SehOwnershipMode {
    Preserve,
    Guarded,
    Full,
}

fn seh_ownership_mode(full_seh_virtualize: bool) -> SehOwnershipMode {
    if !full_seh_virtualize {
        return SehOwnershipMode::Preserve;
    }
    match std::env::var("BTG_SEH_OWNERSHIP")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "full" | "strict" => SehOwnershipMode::Full,
        "guarded" => SehOwnershipMode::Guarded,
        "preserve" | "native" => SehOwnershipMode::Preserve,
        _ if std::env::var("BTG_SEH_NONE").map_or(false, |v| v != "0") => {
            // The legacy switch's literal contract is now enforced: no input
            // SEH/panic function remains native.  Callers needing the former
            // safety-net behavior must request BTG_SEH_OWNERSHIP=guarded.
            SehOwnershipMode::Full
        }
        // The whole-program bridge covers unwind metadata, but a block-level
        // dispatcher cannot safely enter the middle of a function that relies
        // on a prologue-created frame local (notably Rust Once cleanup
        // switch-dispatch frames).  Keep those narrowly identified functions
        // native by default.  `full` remains available as an explicit
        // conformance/diagnostic mode.
        _ => SehOwnershipMode::Guarded,
    }
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
pub fn fn_has_computed_jump(fs: u64, fe: u64, text_bytes: &[u8], base_va: u64) -> bool {
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
        .filter(|&&(s, e, _)| fn_state_refs(s, e).iter().any(|g| shared.contains(g)))
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
pub(crate) fn parse_pdata_functions(
    relayed_sections: &[crate::pe::builder::SectionData],
    image_base: u64,
) -> Vec<(u64, u64, u32)> {
    let mut funcs: Vec<(u64, u64, u32)> = relayed_sections
        .iter()
        .find(|section| section.name == ".pdata")
        .into_iter()
        .flat_map(|section| section.bytes.chunks_exact(12))
        // Parse each record independently to preserve the legacy consumer's
        // tolerance of one malformed entry without duplicating PE decoding.
        .filter_map(|record| crate::pe::unwind::parse_runtime_functions(record).ok())
        .flatten()
        .map(|function| {
            (
                image_base + function.begin_address as u64,
                image_base + function.end_address as u64,
                function.unwind_info_address,
            )
        })
        .collect();
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
pub(crate) fn unwind_info_flags(
    unwind_rva: u32,
    relayed_sections: &[crate::pe::builder::SectionData],
) -> Option<u8> {
    use crate::pe::unwind::{parse_unwind_chain, RvaSection, UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER};

    let sections: Vec<RvaSection<'_>> = relayed_sections
        .iter()
        .map(|section| RvaSection {
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size,
            bytes: &section.bytes,
        })
        .collect();
    let chain = parse_unwind_chain(unwind_rva, &sections, 8).ok()?;
    let info = chain
        .iter()
        .map(|(_, info)| info)
        .find(|info| info.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0)
        .unwrap_or(&chain[0].1);
    Some((info.flags << 3) | info.version)
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
    let ownership_mode = seh_ownership_mode(full_seh_virtualize);
    let seh_none = ownership_mode != SehOwnershipMode::Preserve;
    let seh_minimal = std::env::var("BTG_SEH_MINIMAL").map_or(true, |v| v != "0");
    let mut native: HashSet<u64> = HashSet::new();
    if ownership_mode == SehOwnershipMode::Full {
        // P1-2 strict ownership contract: no input .text function may remain
        // native merely because it participates in SEH/Rust panic handling.
        // Computed dispatch and Once state must be represented by the guest
        // frame/personality bridge instead of being hidden behind an allowlist.
        println!(
            "[+] SEH ownership: FULL (BTG_SEH_OWNERSHIP=full) -- 0 SEH/panic native functions"
        );
    } else if seh_none {
        // full SEH virtualization: every ordinary (straight-line / branch-only)
        // SEH/panic/catch function is lifted into the VM. The ONLY functions kept
        // native are the two orthogonal guards:
        //   1. switch-dispatch (computed-jump) EHANDLER functions on the
        //      raise..catch path — block-level VM dispatch enters switch targets
        //      without the frame prologue, so their frame-locals read stale data
        //      (Once completion `xchg eax,[r11]` with r11=-2 -> exit-time AV);
        //   2. Once/panic shared-state teardown frames (data-global pokes).
        let mut computed_jump_starts = HashSet::new();
        for &s in ehandler_starts.iter() {
            if !can_reach_panic.contains(&s) {
                continue;
            }
            if let Some(&(ss, ee, _)) = funcs.iter().find(|&&(ss, _, _)| ss == s) {
                if fn_has_computed_jump(ss, ee, text_bytes, base_va) {
                    native.insert(s);
                    computed_jump_starts.insert(s);
                }
            }
        }
        let shared_state_ranges = detect_runtime_shared_global_functions(
            text_bytes,
            base_va,
            image_base,
            relayed_sections,
        );
        let shared_state_count = shared_state_ranges.len();
        for (s, e) in shared_state_ranges {
            native.insert(s);
            let _ = e;
        }
        println!(
            "[+] SEH ownership: GUARDED -- keeping {} function(s) native (panic_seed={}, ehandler={}, computed-jump={}, shared-state={}, overlap={})",
            native.len(),
            panic_seed_starts.len(),
            ehandler_starts.len(),
            computed_jump_starts.len(),
            shared_state_count,
            computed_jump_starts.len() + shared_state_count - native.len()
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
        .filter_map(|&s| {
            funcs
                .iter()
                .copied()
                .find(|&(ss, _, _)| ss == s)
                .map(|(ss, ee, _)| (ss, ee))
        })
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

#[cfg(test)]
mod typed_unwind_adapter_tests {
    use super::*;
    use crate::pe::builder::SectionData;
    use crate::pe::unwind::{UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER};

    fn section(name: &str, virtual_address: u32, bytes: Vec<u8>) -> SectionData {
        SectionData {
            name: name.to_owned(),
            virtual_address,
            virtual_size: bytes.len() as u32,
            characteristics: 0,
            bytes,
        }
    }

    #[test]
    fn pdata_adapter_preserves_absolute_legacy_shape_and_skips_invalid_records() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x2000u32.to_le_bytes());
        bytes.extend_from_slice(&0x2040u32.to_le_bytes());
        bytes.extend_from_slice(&0x5000u32.to_le_bytes());
        bytes.extend_from_slice(&0x3000u32.to_le_bytes());
        bytes.extend_from_slice(&0x2ff0u32.to_le_bytes());
        bytes.extend_from_slice(&0x5010u32.to_le_bytes());

        assert_eq!(
            parse_pdata_functions(&[section(".pdata", 0x4000, bytes)], 0x140000000),
            vec![(0x140002000, 0x140002040, 0x5000)]
        );
    }

    #[test]
    fn unwind_flags_adapter_follows_typed_aligned_chain_trailer() {
        let mut bytes = vec![(UNW_FLAG_CHAININFO << 3) | 1, 0, 0, 0];
        bytes.extend_from_slice(&0x2000u32.to_le_bytes());
        bytes.extend_from_slice(&0x2040u32.to_le_bytes());
        bytes.extend_from_slice(&0x5010u32.to_le_bytes());
        bytes.extend_from_slice(&[(UNW_FLAG_EHANDLER << 3) | 1, 0, 0, 0]);
        bytes.extend_from_slice(&0x12345678u32.to_le_bytes());

        assert_eq!(
            unwind_info_flags(0x5000, &[section(".xdata", 0x5000, bytes)]),
            Some((UNW_FLAG_EHANDLER << 3) | 1)
        );
    }
}
