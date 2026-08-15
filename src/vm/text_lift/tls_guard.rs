// ==============================================================================
// TLS-callback exclusion (P5 — .text on-disk plaintext 0, gate)
//
// The Windows loader runs TLS callbacks (AddressOfCallBacks array) BEFORE the
// process entry point (our boot stub). Any such callback lives in the original
// `.text` (it is CRT/_tls_used init code). If `.text` is encrypted at rest, the
// loader executes the ciphertext callback -> 0xC0000005. So the P5 goal
// "`.text` on-disk plaintext 0" is gated on keeping exactly the TLS-callback
// reachable functions plaintext while encrypting the rest.
//
// This scanner finds those functions structurally:
//   1. read TLS directory (DataDirectory[9]) -> AddressOfCallBacks -> array of
//      callback function VAs (null-terminated),
//   2. map each callback VA to its .pdata function range,
//   3. add every function transitively reached from a callback over direct
//      call edges (both callers and callees), because the callback calls CRT
//      init helpers that themselves poke the TLS slots the callback set up.
//
// The result is a set of whole-function [begin,end) ranges to keep PLAINTEXT.
// `collect_protected_rva_ranges` in patch_data.rs consumes this so a future
// at-rest `.text` encryptor skips exactly these ranges. It is a pure PE
// structural analysis (no disassembly policy change), fully unit-testable, and
// does not alter the working 16-test pack path when .text encryption is off.
// ==============================================================================

/// Result of the TLS-callback reachable-function scan.
#[derive(Debug, Clone, Default)]
pub struct TlsCallbackExclusion {
    /// Absolute [begin..end) VA ranges of functions that must stay plaintext.
    pub func_ranges: Vec<(u64, u64)>,
    /// Absolute VAs of every TLS callback entry point (for diagnostics).
    pub callback_entries: Vec<u64>,
}

/// Find every TLS-callback-reachable function in `.text`.
///
/// `data_directories[9]` is the TLS directory (IMAGE_TLS_DIRECTORY64).
/// `AddressOfCallBacks` sits at offset 0x18 (24) within it.
pub fn detect_tls_callback_ranges(
    text_bytes: &[u8],
    base_va: u64,
    image_base: u64,
    relayed_sections: &[crate::pe::builder::SectionData],
    data_directories: &[crate::pe::builder::DataDirectory],
) -> TlsCallbackExclusion {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};

    // 0) .pdata function ranges (absolute begin..end).
    let mut funcs: Vec<(u64, u64)> = Vec::new();
    if let Some(pd) = relayed_sections.iter().find(|s| s.name == ".pdata") {
        for chunk in pd.bytes.chunks_exact(12) {
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

    // 1) TLS directory -> AddressOfCallBacks array.
    let tls_dir = data_directories.get(9).copied().unwrap_or(crate::pe::builder::DataDirectory { virtual_address: 0, size: 0 });
    let mut callback_vas: Vec<u64> = Vec::new();
    if tls_dir.virtual_address != 0 && tls_dir.size >= 0x18 + 8 {
        for sec in relayed_sections {
            let sva = sec.virtual_address as u64;
            let svs = sec.virtual_size.max(sec.bytes.len() as u32) as u64;
            let r = tls_dir.virtual_address as u64;
            if r >= sva && r < sva + svs {
                let off = (r - sva) as usize;
                if off + 0x20 <= sec.bytes.len() {
                    let callbacks_va =
                        u64::from_le_bytes(sec.bytes[off + 0x18..off + 0x20].try_into().unwrap());
                    // callbacks array lives in some relayed section.
                    for cbsec in relayed_sections {
                        let cva = cbsec.virtual_address as u64;
                        let cvs = cbsec.virtual_size.max(cbsec.bytes.len() as u32) as u64;
                        let cb_rva = callbacks_va.saturating_sub(image_base);
                        if cb_rva as u64 >= cva && (cb_rva as u64) < cva + cvs {
                            let coff = (cb_rva as u64 - cva) as usize;
                            let mut i = coff;
                            while i + 8 <= cbsec.bytes.len() {
                                let fva = u64::from_le_bytes(
                                    cbsec.bytes[i..i + 8].try_into().unwrap(),
                                );
                                if fva == 0 {
                                    break;
                                }
                                callback_vas.push(fva);
                                i += 8;
                            }
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
    if callback_vas.is_empty() {
        return TlsCallbackExclusion::default();
    }

    // 2) seed = .pdata function range containing each callback VA.
    let mut native: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for &cb in &callback_vas {
        if let Some((s, _)) = func_of(cb) {
            native.insert(s);
        }
    }

    // 3) direct call edges within .text; forward (callee) transitive closure.
    //    The loader invokes the callback before the boot stub, so every function
    //    the callback transitively CALLS runs in plaintext and must be kept
    //    plaintext. Callers of the callback are irrelevant (nothing in .text
    //    invokes the loader-driven callback), so we do NOT walk backwards — that
    //    would pull in the whole CRT init call graph.
    let mut callees: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();
    let mut dec = Decoder::with_ip(64, text_bytes, base_va, DecoderOptions::NONE);
    while dec.can_decode() {
        let inst = dec.decode();
        if inst.is_invalid() {
            continue;
        }
        let va = inst.ip();
        if matches!(inst.flow_control(), FlowControl::Call | FlowControl::UnconditionalBranch) {
            let near = inst.near_branch_target();
            if near >= base_va && near < base_va + text_bytes.len() as u64 {
                callees.entry(va).or_default().push(near);
            }
        }
    }
    let mut queue: Vec<u64> = native.iter().copied().collect();
    while let Some(fs) = queue.pop() {
        let fe = funcs.iter().find(|&&(ss, _)| ss == fs).map(|&(_, e)| e).unwrap_or(fs + 1);
        let mut d = Decoder::with_ip(64, &text_bytes[(fs - base_va) as usize..], fs, DecoderOptions::NONE);
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
            if matches!(inst.flow_control(), FlowControl::Call | FlowControl::UnconditionalBranch) {
                let near = inst.near_branch_target();
                if near >= base_va && near < base_va + text_bytes.len() as u64 {
                    if let Some((cs, _)) = func_of(near) {
                        if native.insert(cs) {
                            queue.push(cs);
                        }
                    }
                }
            }
        }
    }

    let mut func_ranges: Vec<(u64, u64)> = native
        .iter()
        .filter_map(|&s| funcs.iter().copied().find(|&(ss, _)| ss == s))
        .collect();
    func_ranges.sort_by_key(|r| r.0);

    if !func_ranges.is_empty() {
        let bytes: u64 = func_ranges.iter().map(|(s, e)| e - s).sum();
        println!(
            "[+] P5 TLS-callback exclusion: {} function(s), 0x{:X} bytes kept plaintext (TLS init reachability)",
            func_ranges.len(), bytes
        );
    }

    TlsCallbackExclusion {
        func_ranges,
        callback_entries: callback_vas,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::builder::{DataDirectory, SectionData};

    fn section(name: &str, va: u32, bytes: Vec<u8>) -> SectionData {
        SectionData {
            name: name.to_string(),
            virtual_address: va,
            virtual_size: bytes.len() as u32,
            characteristics: 0,
            bytes,
        }
    }

    fn pdata_entry(begin: u32, end: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&begin.to_le_bytes());
        b.extend_from_slice(&end.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b
    }

    // Build a tiny synthetic image:
    //  .text @RVA 0x1000, image_base 0x140000000
    //  callback fn A @0x140001000 (call B; ret)   -- the TLS callback
    //  fn B       @0x140001006 (xor rax,rax; ret) -- A's callee
    //  fn C       @0x14000100a (shl rax,0)        -- unrelated
    //  .pdata covers A[0x1000,0x1006) B[0x1006,0x100a) C[0x100a,0x100e)
    //  .rdata holds TLS dir @0x2000: AddressOfCallBacks -> 0x140003000
    //  .rdata callbacks array @0x3000: [0x140001000, 0]
    fn sample_exclusion() -> TlsCallbackExclusion {
        let image_base = 0x140000000u64;
        let base_va = image_base + 0x1000;

        // A @ offset 0: call rel32 to B (offset 6), then ret.
        let a_ip = base_va; // call sits at base_va, next ip = base_va+5
        let b_va = base_va + 6;
        let disp = (b_va as i64 - (a_ip as i64 + 5)) as i32;
        let mut text = Vec::new();
        text.extend_from_slice(&0xe8u8.to_le_bytes());
        text.extend_from_slice(&disp.to_le_bytes());
        text.extend_from_slice(&[0xc3]); // ret (A: 6B total)
        // B @ offset 6: xor rax,rax; ret (4B)
        text.extend_from_slice(&[0x48, 0x31, 0xc0, 0xc3]);
        // C @ offset 10: shl rax,0 (4B)
        text.extend_from_slice(&[0x48, 0xc1, 0xe0, 0x00]);

        // .pdata with the three function ranges.
        let pdata_bytes = {
            let mut v = Vec::new();
            v.extend(pdata_entry(0x1000, 0x1000 + 6)); // A
            v.extend(pdata_entry(0x1000 + 6, 0x1000 + 10)); // B
            v.extend(pdata_entry(0x1000 + 10, 0x1000 + 14)); // C
            v
        };

        // .rdata: TLS dir @0x2000, callbacks array @0x3000.
        let mut rdata = vec![0u8; 0x1100]; // covers 0x2000..0x3100
        let tls_off = 0x2000 - 0x2000; // rdata va = 0x2000
        // IMAGE_TLS_DIRECTORY64: put AddressOfCallBacks at +0x18.
        rdata[tls_off + 0x18..tls_off + 0x20].copy_from_slice(&(image_base + 0x3000).to_le_bytes());
        let cb_off = 0x3000 - 0x2000;
        rdata[cb_off..cb_off + 8].copy_from_slice(&(image_base + 0x1000).to_le_bytes()); // -> A
        // null terminator already zero.

        let relayed = vec![
            section(".text", 0x1000, text),
            section(".pdata", 0x1000 + 0x200, pdata_bytes),
            section(".rdata", 0x2000, rdata),
        ];
        let mut dirs = vec![DataDirectory { virtual_address: 0, size: 0 }; 16];
        dirs[9] = DataDirectory {
            virtual_address: 0x2000,
            size: 40,
        };

        detect_tls_callback_ranges(&relayed[0].bytes, base_va, image_base, &relayed, &dirs)
    }

    #[test]
    fn tls_callback_reaches_callee_but_not_unrelated() {
        let ex = sample_exclusion();
        // Callback A and its callee B are kept plaintext; unrelated C is not.
        assert_eq!(ex.callback_entries, vec![0x140001000]);
        let ranges = &ex.func_ranges;
        assert!(ranges.contains(&(0x140001000, 0x140001006)), "A in ranges");
        assert!(ranges.contains(&(0x140001006, 0x14000100a)), "B in ranges");
        assert!(
            !ranges.contains(&(0x14000100a, 0x14000100e)),
            "C (unrelated) must NOT be in ranges"
        );
    }

    #[test]
    fn tls_callback_no_dir_is_empty() {
        let image_base = 0x140000000u64;
        let base_va = image_base + 0x1000;
        let relayed = vec![
            section(".text", 0x1000, vec![0x48, 0x31, 0xc0]),
            section(".pdata", 0x1200, pdata_entry(0x1000, 0x1003)),
        ];
        let dirs = vec![DataDirectory { virtual_address: 0, size: 0 }; 16]; // no TLS dir
        let ex = detect_tls_callback_ranges(&relayed[0].bytes, base_va, image_base, &relayed, &dirs);
        assert!(ex.func_ranges.is_empty());
        assert!(ex.callback_entries.is_empty());
    }
}
