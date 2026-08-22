use super::find_subslice;
use super::seh::{parse_pdata_functions, unwind_info_flags};

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
// Detection is import-name driven where possible, with MSVC static-runtime
// signatures for the x64 intrinsic implementations (no jmp_buf assumption):
//   1. goblin parses the import table → the IAT slot VAs whose imported name is
//      one of the setjmp/longjmp family;
//   2. scan .text for `call/jmp [rip + disp32]` whose target is such a slot
//      (direct import calls) and for `jmp [rip + disp32]` thunks;
//   3. map every use site to its .pdata function start, add callers that reach a
//      thunk, then run the bidirectional call closure (same rule as the
//      panic/SEH set).
const SETJMP_NAMES: &[&str] = &[
    "setjmp",
    "_setjmp",
    "_setjmpex",
    "_setjmp3",
    "longjmp",
    "_longjmp",
];

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
                let to_add = if caller_in {
                    callee_start
                } else {
                    caller_start
                };
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

    let mut ranges: Vec<(u64, u64)> = excluded.iter().filter_map(|&s| func_of(s)).collect();
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
    let mut sites = find_setjmp_use_sites(text_bytes, base_va, &slots);

    // MSVC x64 commonly links setjmp/longjmp from the static vcruntime even in
    // /MD executables.  Seed the same call-closure from stable context save and
    // restore prefixes when no import name is available.
    const MSVC_SETJMP_PREFIX: &[u8] = &[
        0x48, 0x89, 0x11, 0x48, 0x89, 0x59, 0x08, 0x48, 0x89, 0x69, 0x18, 0x48, 0x89, 0x71, 0x20,
    ];
    const MSVC_LONGJMP_PREFIX: &[u8] = &[
        0x48, 0x83, 0xEC, 0x48, 0x48, 0x85, 0xD2, 0x75, 0x03, 0x48, 0xFF, 0xC2, 0x4D, 0x33, 0xD2,
    ];
    for signature in [MSVC_SETJMP_PREFIX, MSVC_LONGJMP_PREFIX] {
        let mut from = 0usize;
        while let Some(pos) = find_subslice(text_bytes, signature, from) {
            sites.use_vas.push(base_va + pos as u64);
            from = pos + signature.len();
        }
    }
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
        assert!(
            !sites.use_vas.is_empty(),
            "must find the jmp [rip+slot] thunk use"
        );
        assert!(
            sites.thunk_vas.contains(&base),
            "thunk at base must be flagged"
        );
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
