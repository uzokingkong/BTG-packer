// ==============================================================================
// BTG v42 - VM Bytecode Mapper (debugging aid)
// ==============================================================================
//
// When `--map` is passed to the packer, every lifted original x86-64
// instruction is recorded as a `MapEntry` that maps the *VM bytecode offset*
// where its translation begins back to the original virtual address (VA),
// the original instruction's length, and its disassembly.
//
// Why this helps: after a program is packed, the original code no longer
// exists in the file — only the VM bytecode does. When the packed binary
// crashes, a debugger (e.g. cdb / WinDbg) reports a faulting offset inside
// the embedded bytecode region. With the `.map` file you can translate
//   crash_offset = fault_va - bytecode_base_va
// and look up which original instruction that VM bytecode block came from,
// turning an opaque crash into "this original instruction misbehaved".
//
// The mapper is wired in as a no-op unless enabled, so a normal pack (no
// `--map`) is byte-for-byte unaffected. It is collected in a thread-local
// slot (the packer is single-threaded) so no lift function signature has to
// change; the lifter calls `record()` and `main.rs` drains the result after
// the build and writes it to `<output>.map`.
//
// Map file format (one line per lifted instruction):
//   <bytecode_offset> <kind> <original_va> <len> <disassembly>
// kind is one of KSA | Block | Program, indicating which lift path recorded it.
// ==============================================================================

use iced_x86::Instruction;
use std::cell::RefCell;
use std::io::Write;

/// One lifted original instruction -> where in the VM bytecode its
/// translation begins.
#[derive(Debug, Clone)]
pub struct MapEntry {
    /// Byte offset into the VM bytecode stream where this instruction's
    /// lifted code begins.
    pub bc_offset: usize,
    /// Which lift path produced it: "KSA", "Block" or "Program".
    pub kind: &'static str,
    /// Original virtual address of the instruction (0 for KSA, which has no
    /// meaningful VA — it is boot-stub scaffolding, not user code).
    pub src_va: u64,
    /// Original instruction length in bytes.
    pub len: usize,
    /// Original instruction disassembly (iced-x86).
    pub disasm: String,
}

/// A block boundary recorded for the symbolic map: the VM bytecode offset range
/// and the original basic-block VA range it was lifted from. Recorded by
/// `lift_cfg_switch` for the Program CFG lift so a faulting bytecode offset can
/// be reverse-mapped to the enclosing original block (and, via .pdata, function).
#[derive(Debug, Clone)]
pub struct MapBlock {
    /// Sequential block index (order emitted in the CFG lift).
    pub id: u32,
    /// Bytecode offset where this block's lifted code begins.
    pub bc_start: usize,
    /// Bytecode offset just past this block's lifted code.
    pub bc_end: usize,
    /// Original start VA of the source basic block.
    pub src_va: u64,
    /// End VA of the source basic block (start + sum of instruction lengths).
    pub src_va_end: u64,
    /// Whether this block was excluded from VMization (kept native).
    pub native: bool,
}

#[derive(Debug, Default)]
pub struct VmMapper {
    pub entries: Vec<MapEntry>,
    /// Block boundaries for the symbolic map (Program lift).
    pub blocks: Vec<MapBlock>,
    /// Human label for the current map (e.g. "program" / "ksa").
    pub label: String,
}

thread_local! {
    static SLOT: RefCell<Option<VmMapper>> = const { RefCell::new(None) };
}

/// Enable recording for the given phase. Repeated calls reset the map.
pub fn begin(label: &str) {
    SLOT.with(|s| {
        *s.borrow_mut() = Some(VmMapper {
            entries: Vec::new(),
            blocks: Vec::new(),
            label: label.to_string(),
        })
    });
}

/// Is recording currently enabled?
pub fn active() -> bool {
    SLOT.with(|s| s.borrow().is_some())
}

/// Record one lifted original instruction.
///
/// `bc_offset` is the VM bytecode offset at which this instruction's
/// translation begins (the caller must pass `builder.bytes.len()` captured
/// *before* emitting the instruction's bytecode).
pub fn record(
    bc_offset: usize,
    inst: &Instruction,
    src_va: u64,
    kind: &'static str,
) {
    SLOT.with(|s| {
        if let Some(m) = s.borrow_mut().as_mut() {
            m.entries.push(MapEntry {
                bc_offset,
                kind,
                src_va,
                len: inst.len(),
                disasm: format!("{:X} {}", inst.ip(), inst),
            });
        }
    });
}

/// Record the start of a lifted basic block in the symbolic map.
///
/// Call once per block, immediately after emitting its entry label (so
/// `bc_start` = bytecode offset where this block's code begins). The block is
/// closed by [`end_block`] with the offset just past its code.
pub fn record_block_start(bc_start: usize, src_va: u64, native: bool) {
    SLOT.with(|s| {
        if let Some(m) = s.borrow_mut().as_mut() {
            m.blocks.push(MapBlock {
                id: m.blocks.len() as u32,
                bc_start,
                bc_end: bc_start, // filled by end_block
                src_va,
                src_va_end: src_va, // filled by end_block
                native,
            });
        }
    });
}

/// Close the most recently opened block: record the bytecode offset just past
/// it and the source end VA (derived from the block's instruction lengths).
pub fn end_block(bc_end: usize, src_va_end: u64) {
    SLOT.with(|s| {
        if let Some(m) = s.borrow_mut().as_mut() {
            if let Some(b) = m.blocks.last_mut() {
                b.bc_end = bc_end;
                b.src_va_end = src_va_end;
            }
        }
    });
}

/// Take the accumulated map (disabling further recording) if any.
pub fn take() -> Option<VmMapper> {
    SLOT.with(|s| s.borrow_mut().take())
}

/// Render the map to a human-readable text file body.
pub fn render(m: &VmMapper) -> String {
    let mut out = String::new();
    out.push_str("; BTG VM bytecode map\n");
    out.push_str(&format!("; phase: {}\n", m.label));
    out.push_str("; format: bc_offset kind src_va len disasm\n");
    out.push_str("; ----- basic blocks (symbolic map) -----\n");
    for b in &m.blocks {
        out.push_str(&format!(
            "block {} bc=0x{:X}..0x{:X} va=0x{:X}..0x{:X} {}\n",
            b.id,
            b.bc_start,
            b.bc_end,
            b.src_va,
            b.src_va_end,
            if b.native { "native" } else { "vm" }
        ));
    }
    out.push_str("; ----- lifted instructions -----\n");
    for e in &m.entries {
        out.push_str(&format!(
            "0x{:X} {} 0x{:X} {} {}\n",
            e.bc_offset, e.kind, e.src_va, e.len, e.disasm
        ));
    }
    out
}

/// Write the map to `path`. Returns the number of entries written.
pub fn write_map_to(m: &VmMapper, path: &std::path::Path) -> std::io::Result<usize> {
    let body = render(m);
    let mut f = std::fs::File::create(path)?;
    f.write_all(body.as_bytes())?;
    Ok(m.entries.len())
}

/// Render the block-level symbolic map body (`.sym`).
///
/// Emits, in order:
///   1. header (image base, count of blocks)
///   2. function table from `.pdata` (`func <va_start> <va_end>`)
///   3. per-block entries: `block <id> bc=<start>..<end> va=<start>..<end> [vm|native] func=<va>`
///   4. a reverse index over lifted instructions grouped by block, so a faulting
///      bytecode offset can be reverse-mapped to block + original VA + disasm.
pub fn render_sym(m: &VmMapper, funcs: &[(u64, u64)], image_base: u64) -> String {
    let mut out = String::new();
    out.push_str("; BTG VM symbolic map (M10)\n");
    out.push_str(&format!("; image_base: 0x{:X}\n", image_base));
    out.push_str(&format!("; blocks: {}\n", m.blocks.len()));
    out.push_str("; ----- functions (.pdata) -----\n");
    for &(fs, fe) in funcs {
        out.push_str(&format!("func 0x{:X} 0x{:X}\n", fs, fe));
    }
    out.push_str("; ----- blocks -----\n");
    out.push_str("; format: block <id> bc=<bc_start>..<bc_end> va=<va_start>..<va_end> <vm|native> func=<func_start>\n");
    // attribute each block to a .pdata function
    for b in &m.blocks {
        let func_start = funcs
            .iter()
            .rev()
            .find(|&&(fs, _)| fs <= b.src_va)
            .map(|&(fs, _)| format!("0x{:X}", fs))
            .unwrap_or_else(|| String::from("-"));
        out.push_str(&format!(
            "block {} bc=0x{:X}..0x{:X} va=0x{:X}..0x{:X} {} func={}\n",
            b.id, b.bc_start, b.bc_end, b.src_va, b.src_va_end,
            if b.native { "native" } else { "vm" },
            func_start,
        ));
    }
    out.push_str("; ----- lifted instructions (reverse index) -----\n");
    out.push_str("; format: bc_offset block_id src_va len disasm\n");
    // group entries by block via bc range
    let mut bi = 0usize;
    for e in &m.entries {
        if e.kind != "Program" {
            continue;
        }
        // advance block index to the block containing this bc offset
        while bi + 1 < m.blocks.len() && e.bc_offset >= m.blocks[bi + 1].bc_start {
            bi += 1;
        }
        let bid = if bi < m.blocks.len() && e.bc_offset >= m.blocks[bi].bc_start && e.bc_offset < m.blocks[bi].bc_end {
            m.blocks[bi].id
        } else {
            u32::MAX
        };
        out.push_str(&format!(
            "0x{:X} {} 0x{:X} {} {}\n",
            e.bc_offset, bid, e.src_va, e.len, e.disasm
        ));
    }
    out
}

/// Write the block-level symbolic map to `path`. Returns the number of blocks.
pub fn write_sym_to(
    m: &VmMapper,
    path: &std::path::Path,
    funcs: &[(u64, u64)],
    image_base: u64,
) -> std::io::Result<usize> {
    let body = render_sym(m, funcs, image_base);
    let mut f = std::fs::File::create(path)?;
    f.write_all(body.as_bytes())?;
    Ok(m.blocks.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Code, Decoder, DecoderOptions};

    #[test]
    fn record_render_roundtrip() {
        begin("test");
        let bytes = [0x48u8, 0x89, 0xd0]; // mov rax, rdx
        let mut dec = Decoder::with_ip(64, &bytes, 0x140001000, DecoderOptions::NONE);
        let inst = dec.decode();
        record(0x10, &inst, 0x140001000, "Block");
        let m = take().expect("map present");
        assert_eq!(m.entries.len(), 1);
        let body = render(&m);
        assert!(body.contains("0x10 Block 0x140001000"));
        assert!(body.contains("mov rax, rdx") || body.contains("mov rax,rdx"));
    }
}
