// ==============================================================================
// BTG Packer - Crash diagnostics (commercial-readiness-plan 3-3).
//
// Reverse-maps a faulting VA inside the protected binary's VM bytecode region
// back to the source-level facts a crash report should carry:
//
//     VM region -> containing block -> containing lifted instruction
//              -> original VA -> handler id -> crypto region -> dispatcher state
//
// Given `fault_va` (what the debugger's exception record / cdb reported), the
// caller passes the runtime VA where the bytecode region begins
// (`bytecode_base_va`) and gets a [`CrashSite`]. `bc_offset = fault_va -
// bytecode_base_va`; the block whose `bc_start..=bc_end` contains it names the
// VM type / handler / crypto region, and the containing lifted instruction
// (from `VmMapper.entries` / `.risc_entries`) names the original VA + disasm.
//
// This is a pack-time, offline analysis only — it consumes the map a `--map` /
// `--sym-map` pack collects and never changes the produced binary.
// ==============================================================================

use crate::vm::mapper::VmMapper;

/// One fully reverse-traced crash site (commercial-readiness-plan 3-3).
#[derive(Debug, Clone)]
pub struct CrashSite {
    /// Which VM region the fault landed in ("vm-bytecode" / "native").
    pub vm_region: String,
    /// Containing lifted basic block id (u32::MAX when unmapped).
    pub block_id: u32,
    /// Containing original instruction disassembly (empty when unmapped).
    pub instruction: String,
    /// Native VA of the faulting bytecode offset (bytecode_base_va + bc_offset).
    pub native_va: u64,
    /// Original (pre-pack) VA of the containing lifted instruction.
    pub original_va: u64,
    /// Handler id of the block (opcode byte at the block start; 0 when unknown).
    pub handler_id: u32,
    /// Dispatcher state snapshot passed in by the caller.
    pub dispatcher_state: String,
    /// Crypto region of the containing block
    /// ("plain"/"block-enc"/"reencrypt"/"m7"/"program-vm"/"ksa").
    pub crypto_region: String,
    /// The protected VA that faulted (== fault_va).
    pub protected_va: u64,
}

/// Reverse-map a faulting VA inside the bytecode region to a [`CrashSite`].
///
/// * `fault_va`          — the faulting address (from the crash/exception).
/// * `image_base`        — image base of the packed PE (unused beyond validation).
/// * `bytecode_base_va`  — runtime VA where the bytecode region begins.
/// * `dispatcher_state`  — free-form dispatcher state snapshot ("entry_block=3
///   mba=0x.. mode=reencrypt" etc).
///
/// Returns `None` when `fault_va` lies below `bytecode_base_va` (i.e. outside
/// the bytecode region entirely).
pub fn diagnose(
    m: &VmMapper,
    fault_va: u64,
    _image_base: u64,
    bytecode_base_va: u64,
    dispatcher_state: &str,
) -> Option<CrashSite> {
    let bc_offset: usize = fault_va.checked_sub(bytecode_base_va)? as usize;

    // Containing block: bc_start..=bc_end covers bc_offset.
    let block = m
        .blocks
        .iter()
        .find(|b| bc_offset >= b.bc_start && bc_offset <= b.bc_end);
    let block_id = block.map(|b| b.id).unwrap_or(u32::MAX);
    let vm_region = block
        .map(|b| if b.native { "native".to_string() } else { "vm-bytecode".to_string() })
        .unwrap_or_else(|| "vm-bytecode".to_string());
    let handler_id = block.map(|b| b.handler_id).unwrap_or(0);
    let crypto_region = block
        .map(|b| b.crypto_region.to_string())
        .unwrap_or_else(|| "plain".to_string());

    // Containing lifted instruction from the command-level map: the entry with
    // the greatest bc_offset <= bc_offset whose span (next entry's bc_offset)
    // still covers it. Fall back to RISC entries by poly_bc_offset.
    let entry = m
        .entries
        .iter()
        .filter(|e| e.bc_offset <= bc_offset)
        .max_by_key(|e| e.bc_offset);
    let risc_entry = m
        .risc_entries
        .iter()
        .filter(|e| e.poly_bc_offset <= bc_offset)
        .max_by_key(|e| e.poly_bc_offset);

    let (instruction, original_va) = match (entry, risc_entry) {
        (Some(e), Some(r)) if r.poly_bc_offset > e.bc_offset => (r.disasm.clone(), r.src_va),
        (Some(e), _) => (e.disasm.clone(), e.src_va),
        (None, Some(r)) => (r.disasm.clone(), r.src_va),
        (None, None) => (String::new(), 0),
    };

    let native_va = bytecode_base_va.wrapping_add(bc_offset as u64);

    Some(CrashSite {
        vm_region,
        block_id,
        instruction,
        native_va,
        original_va,
        handler_id,
        dispatcher_state: dispatcher_state.to_string(),
        crypto_region,
        protected_va: fault_va,
    })
}

/// Render a [`CrashSite`] as a human-readable reverse-trace (dump-demo).
pub fn render_diagnostic(c: &CrashSite) -> String {
    let mut s = String::new();
    s.push_str("== BTG crash diagnostic (reverse trace) ==\n");
    s.push_str(&format!("  VM region:        {}\n", c.vm_region));
    s.push_str(&format!("  block:            #{}\n", c.block_id));
    s.push_str(&format!("  handler id:       0x{:02X}\n", c.handler_id));
    s.push_str(&format!("  protected VA:     0x{:X}\n", c.protected_va));
    s.push_str(&format!("  native VA:        0x{:X}\n", c.native_va));
    s.push_str(&format!("  original VA:      0x{:X}\n", c.original_va));
    s.push_str(&format!("  instruction:      {}\n", c.instruction));
    s.push_str(&format!("  crypto region:    {}\n", c.crypto_region));
    s.push_str(&format!("  dispatcher state: {}\n", c.dispatcher_state));
    s.push_str("== end ==");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::mapper::{begin, end_block, record, record_block_start, take};
    use iced_x86::{Decoder, DecoderOptions};

    #[test]
    fn crash_address_reverse_trace_demo() {
        begin("test");
        let bytes1 = [0x48u8, 0x89, 0xd0]; // mov rax, rdx
        let mut dec = Decoder::with_ip(64, &bytes1, 0x140001000, DecoderOptions::NONE);
        let inst1 = dec.decode();
        record(0x000, &inst1, 0x140001000, "Program");
        let bytes2 = [0x48u8, 0x83, 0xc0, 0x01]; // add rax, 1
        let mut dec = Decoder::with_ip(64, &bytes2, 0x140001003, DecoderOptions::NONE);
        let inst2 = dec.decode();
        record(0x020, &inst2, 0x140001003, "Program");
        record_block_start(0x000, 0x140001000, false, "program", 0x3C, "program-vm");
        end_block(0x040, 0x140001007);
        let m = take().expect("map present");

        let cs = diagnose(&m, 0x140008000 + 0x2C, 0x140000000, 0x140008000, "entry_block=3 mode=reencrypt")
            .expect("diagnose");
        assert_eq!(cs.vm_region, "vm-bytecode");
        assert_eq!(cs.block_id, 0);
        assert_eq!(cs.original_va, 0x140001003, "resolves to containing original VA");
        assert!(cs.instruction.contains("add rax,1"), "instruction: {}", cs.instruction);
        assert_eq!(cs.handler_id, 0x3C, "handler id from block");
        assert_eq!(cs.crypto_region, "program-vm");
        assert_eq!(cs.protected_va, 0x14000802C);
        assert_eq!(cs.native_va, 0x14000802C);
        assert!(cs.dispatcher_state.contains("entry_block=3"));

        let text = render_diagnostic(&cs);
        assert!(text.contains("original VA:      0x140001003"));
        assert!(text.contains("crypto region:    program-vm"));
    }

    #[test]
    fn outside_bytecode_region_returns_none() {
        begin("test");
        let bytes = [0x48u8, 0x89, 0xd0];
        let mut dec = Decoder::with_ip(64, &bytes, 0x140001000, DecoderOptions::NONE);
        let inst = dec.decode();
        record(0x10, &inst, 0x140001000, "Program");
        let m = take().expect("map present");
        // fault_va below bytecode_base_va -> outside region -> None
        assert!(diagnose(&m, 0x1000, 0x140000000, 0x140008000, "x").is_none());
    }
}
