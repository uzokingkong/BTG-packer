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
    /// VM type of this block: "native" | "vm" | "program" | "risc".
    pub vm_type: &'static str,
    /// VM handler (opcode) id for this block (0 when not applicable/unknown).
    pub handler_id: u32,
    /// Crypto region of this block:
    /// "plain" | "block-enc" | "reencrypt" | "m7" | "program-vm" | "ksa".
    pub crypto_region: &'static str,
}

/// P3 (G1): 상용(RISC→poly) 프로그램 lift에서 lift된 원본 명령 하나를 기록하는
/// 매핑 엔트리 — "원본 VA → RISC micro-op 인덱스 → 폴리 바이트코드 오프셋" 체인의
/// 명령 단위 레코드. `poly_bc_offset`은 lift 시점(commercial.rs)엔 0이고,
/// `PolymorphicEncoder::encode_with_offsets` 후 [`fill_risc_poly_offsets`]가 첫
/// micro-op의 오프셋으로 채운다.
#[derive(Debug, Clone)]
pub struct RiscMapEntry {
    /// 원본 명령 가상 주소.
    pub src_va: u64,
    /// 원본 명령 길이(바이트).
    pub len: usize,
    /// 원본 명령 디스어셈블리.
    pub disasm: String,
    /// 이 명령이 lift된 첫 RISC micro-op 인덱스 (RiscProgram.instrs 기준).
    pub risc_op_start: usize,
    /// 이 명령이 만든 RISC micro-op 수.
    pub risc_op_count: usize,
    /// 첫 micro-op의 폴리 바이트코드 오프셋 (인코딩 후 채움).
    pub poly_bc_offset: usize,
}

#[derive(Debug, Default)]
pub struct VmMapper {
    pub entries: Vec<MapEntry>,
    /// Block boundaries for the symbolic map (Program lift).
    pub blocks: Vec<MapBlock>,
    /// 상용(RISC→poly) 프로그램 lift의 명령 단위 매핑 (P3).
    pub risc_entries: Vec<RiscMapEntry>,
    /// micro-op 인덱스 → 원본 VA (per-micro-op CSV 매핑용, lift 시점에 채움).
    pub risc_op_src: Vec<u64>,
    /// micro-op 인덱스 → 폴리 바이트코드 오프셋 (`fill_risc_poly_offsets`가 채움).
    pub risc_offsets: Vec<usize>,
    /// Human label for the current map (e.g. "program" / "ksa").
    pub label: String,
    /// P3-3: base VA of the bytecode region (protected_va = base_va + bc_offset).
    pub base_va: u64,
    /// P3-3: bytecode stream snapshot (opcode at an offset names the handler).
    pub bytecode: Vec<u8>,
    /// P3-3: dispatcher mode for crypto-region classification.
    pub dispatcher_mode: String,
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
            risc_entries: Vec::new(),
            risc_op_src: Vec::new(),
            risc_offsets: Vec::new(),
            label: label.to_string(),
            base_va: 0,
            bytecode: Vec::new(),
            dispatcher_mode: String::new(),
        })
    });
}

/// Is recording currently enabled?
pub fn active() -> bool {
    SLOT.with(|s| s.borrow().is_some())
}

/// P3-3: record the bytecode region's base VA (for protected-VA mapping).
pub fn set_base_va(base: u64) {
    SLOT.with(|s| {
        if let Some(m) = s.borrow_mut().as_mut() {
            m.base_va = base;
        }
    });
}

/// P3-3: record a bytecode snapshot so handler ids can be resolved.
pub fn set_bytecode(bytes: Vec<u8>) {
    SLOT.with(|s| {
        if let Some(m) = s.borrow_mut().as_mut() {
            m.bytecode = bytes;
        }
    });
}

/// P3-3: record the dispatcher mode (plain/reencrypt/m7/commercial).
pub fn set_dispatcher_mode(mode: &str) {
    SLOT.with(|s| {
        if let Some(m) = s.borrow_mut().as_mut() {
            m.dispatcher_mode = mode.to_string();
        }
    });
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
pub fn record_block_start(
    bc_start: usize,
    src_va: u64,
    native: bool,
    vm_type: &'static str,
    handler_id: u32,
    crypto_region: &'static str,
) {
    SLOT.with(|s| {
        if let Some(m) = s.borrow_mut().as_mut() {
            m.blocks.push(MapBlock {
                id: m.blocks.len() as u32,
                bc_start,
                bc_end: bc_start, // filled by end_block
                src_va,
                src_va_end: src_va, // filled by end_block
                native,
                vm_type,
                handler_id,
                crypto_region,
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

/// P3 (G1): 상용(RISC) 리프트의 원본 명령 하나를 매핑에 기록한다 (lift 시점,
/// commercial.rs). 폴리 바이트코드 오프셋은 인코딩 후 [`fill_risc_poly_offsets`]가
/// 채운다. `risc_op_start`는 프로그램(`RiscProgram.instrs`) 기준 절대 micro-op
/// 인덱스다.
pub fn record_risc_entry(
    src_va: u64,
    len: usize,
    disasm: String,
    risc_op_start: usize,
    risc_op_count: usize,
) {
    SLOT.with(|s| {
        if let Some(m) = s.borrow_mut().as_mut() {
            m.risc_entries.push(RiscMapEntry {
                src_va,
                len,
                disasm,
                risc_op_start,
                risc_op_count,
                poly_bc_offset: 0,
            });
            // per-micro-op 원본 VA 맵 확장 (CSV per-micro-op 행용)
            let end = risc_op_start + risc_op_count;
            if m.risc_op_src.len() < end {
                m.risc_op_src.resize(end, src_va);
            }
            for i in risc_op_start..end {
                m.risc_op_src[i] = src_va;
            }
        }
    });
}

/// P3 (G1): `PolymorphicEncoder::encode_with_offsets`가 계산한 per-micro-op 폴리
/// 바이트코드 오프셋을 받아 각 RISC 엔트리의 첫 micro-op 오프셋을 채운다
/// (place.rs가 상용 lift를 인코딩한 직후 호출).
pub fn fill_risc_poly_offsets(offsets: &[usize]) {
    SLOT.with(|s| {
        if let Some(m) = s.borrow_mut().as_mut() {
            m.risc_offsets = offsets.to_vec();
            for e in m.risc_entries.iter_mut() {
                if e.risc_op_count > 0 && e.risc_op_start < offsets.len() {
                    e.poly_bc_offset = offsets[e.risc_op_start];
                }
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
            "block {} bc=0x{:X}..0x{:X} va=0x{:X}..0x{:X} {} vm_type={} handler=0x{:X} crypto={}\n",
            b.id,
            b.bc_start,
            b.bc_end,
            b.src_va,
            b.src_va_end,
            if b.native { "native" } else { "vm" },
            b.vm_type,
            b.handler_id,
            b.crypto_region,
        ));
    }
    out.push_str("; ----- lifted instructions -----\n");
    for e in &m.entries {
        out.push_str(&format!(
            "0x{:X} {} 0x{:X} {} {}\n",
            e.bc_offset, e.kind, e.src_va, e.len, e.disasm
        ));
    }
    out.push_str("; ----- commercial RISC lift (src_va -> micro-op -> poly bc offset) -----\n");
    out.push_str("; format: poly_bc_offset RiscProg src_va len op=<start>..<end> disasm\n");
    for e in &m.risc_entries {
        out.push_str(&format!(
            "0x{:X} RiscProg 0x{:X} {} op={}..{} {}\n",
            e.poly_bc_offset,
            e.src_va,
            e.len,
            e.risc_op_start,
            e.risc_op_start + e.risc_op_count,
            e.disasm
        ));
    }
    out.push_str("; ----- promoted mapping (original VA -> protected VA -> block -> vm type -> handler -> crypto region) -----\n");
    out.push_str("; format: src_va protected_va block vm_type handler crypto_region bc_offset disasm\n");
    for e in &m.entries {
        let block_id = m
            .blocks
            .iter()
            .find(|b| e.bc_offset >= b.bc_start && e.bc_offset < b.bc_end.max(b.bc_start + 1))
            .map(|b| b.id);
        let handler = m
            .bytecode
            .get(e.bc_offset)
            .copied()
            .map(|op| {
                let name = crate::vm::bytecode::OPCODE_INFO
                    .iter()
                    .find(|&&(o, _, _)| o == op)
                    .map(|&(_, n, _)| n)
                    .unwrap_or("-");
                format!("0x{:02X} {}", op, name)
            })
            .unwrap_or_else(|| "-".to_string());
        let pva = if m.base_va != 0 {
            format!("0x{:X}", m.base_va + e.bc_offset as u64)
        } else {
            "-".to_string()
        };
        let region = m
            .blocks
            .iter()
            .find(|b| e.bc_offset >= b.bc_start && e.bc_offset < b.bc_end.max(b.bc_start + 1))
            .map(|b| b.crypto_region.to_string())
            .unwrap_or_else(|| "plain".to_string());
        out.push_str(&format!(
            "0x{:X} {} {} {} {} {} 0x{:X} {}\n",
            e.src_va,
            pva,
            block_id.map(|b| format!("#{}", b)).unwrap_or_else(|| "-".to_string()),
            e.kind,
            handler,
            region,
            e.bc_offset,
            e.disasm
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
    out.push_str("; format: block <id> bc=<bc_start>..<bc_end> va=<va_start>..<va_end> <vm|native> func=<func_start> vm_type=<> handler=<> crypto=<>\n");
    // attribute each block to a .pdata function
    for b in &m.blocks {
        let func_start = funcs
            .iter()
            .rev()
            .find(|&&(fs, _)| fs <= b.src_va)
            .map(|&(fs, _)| format!("0x{:X}", fs))
            .unwrap_or_else(|| String::from("-"));
        out.push_str(&format!(
            "block {} bc=0x{:X}..0x{:X} va=0x{:X}..0x{:X} {} func={} vm_type={} handler=0x{:X} crypto={}\n",
            b.id, b.bc_start, b.bc_end, b.src_va, b.src_va_end,
            if b.native { "native" } else { "vm" },
            func_start,
            b.vm_type,
            b.handler_id,
            b.crypto_region,
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
    out.push_str("; ----- commercial RISC lifted instructions (reverse index) -----\n");
    out.push_str("; format: poly_bc_offset op=<start>..<end> src_va len disasm\n");
    for e in &m.risc_entries {
        out.push_str(&format!(
            "0x{:X} op={}..{} 0x{:X} {} {}\n",
            e.poly_bc_offset,
            e.risc_op_start,
            e.risc_op_start + e.risc_op_count,
            e.src_va,
            e.len,
            e.disasm
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

/// P3 (G1): 상용(RISC) lift의 micro-op 단위 CSV를 `path`에 기록한다.
/// 열: `src_va,risc_op_index,poly_bc_offset` — micro-op 하나마다 한 행으로
/// "원본 VA → RISC micro-op 인덱스 → 폴리 바이트코드 오프셋" 체인을 담는다.
/// 기록된 micro-op 수를 반환한다. (단순 CSV 포맷 — 매핑 파일 산출물.)
pub fn write_risc_csv_to(m: &VmMapper, path: &std::path::Path) -> std::io::Result<usize> {
    let mut out = String::new();
    out.push_str("src_va,risc_op_index,poly_bc_offset\n");
    let n = m.risc_offsets.len();
    for i in 0..n {
        let src = m.risc_op_src.get(i).copied().unwrap_or(0);
        out.push_str(&format!("0x{:X},{},{}\n", src, i, m.risc_offsets[i]));
    }
    let mut f = std::fs::File::create(path)?;
    f.write_all(out.as_bytes())?;
    Ok(n)
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

    /// P3 (G1): 상용 RISC 리프트 매핑 기록 → 폴리 오프셋 채움 → .map/.sym 렌더링
    /// + per-micro-op CSV 라운드트립 검증.
    #[test]
    fn risc_entry_render_and_csv() {
        begin("test");
        record_risc_entry(0x140001000, 7, "mov rax,100".to_string(), 0, 2);
        record_risc_entry(0x140001007, 3, "add rax,rbx".to_string(), 2, 1);
        fill_risc_poly_offsets(&[0, 6, 9]);
        let m = take().expect("map present");
        assert_eq!(m.risc_entries.len(), 2);
        assert_eq!(m.risc_entries[0].poly_bc_offset, 0, "first op offset");
        assert_eq!(m.risc_entries[1].poly_bc_offset, 9, "second op offset");
        assert_eq!(m.risc_op_src, vec![0x140001000, 0x140001000, 0x140001007]);

        let map_body = render(&m);
        assert!(map_body.contains("RiscProg"));
        assert!(map_body.contains("op=0..2"));
        assert!(map_body.contains("0x140001000"));

        let sym_body = render_sym(&m, &[], 0x140000000);
        assert!(sym_body.contains("op=2..3"));
        assert!(sym_body.contains("0x140001007"));

        let dir = std::env::temp_dir();
        let p = dir.join("btg_risc_map_test.csv");
        let n = write_risc_csv_to(&m, &p).expect("write csv");
        assert_eq!(n, 3);
        let text = std::fs::read_to_string(&p).expect("read csv");
        assert!(text.starts_with("src_va,risc_op_index,poly_bc_offset"));
        assert!(text.contains("0x140001000,0,0"));
        assert!(text.contains("0x140001000,1,6"));
        assert!(text.contains("0x140001007,2,9"));
        let _ = std::fs::remove_file(&p);
    }

    /// P3-3 (map 승격): MapBlock에 추가된 vm_type/handler_id/crypto_region 컬럼이
    /// record_block_start + render/render_sym에서 채워지고 렌더링되는지 확인한다.
    #[test]
    fn block_extended_columns_roundtrip() {
        begin("test");
        record_block_start(0x100, 0x140001000, false, "program", 0x3C, "program-vm");
        end_block(0x200, 0x140001007);
        let m = take().expect("map present");
        assert_eq!(m.blocks.len(), 1);
        let b = &m.blocks[0];
        assert_eq!(b.vm_type, "program");
        assert_eq!(b.handler_id, 0x3C);
        assert_eq!(b.crypto_region, "program-vm");
        assert_eq!(b.native, false);

        let map_body = render(&m);
        assert!(map_body.contains("vm_type=program"));
        assert!(map_body.contains("handler=0x3C"));
        assert!(map_body.contains("crypto=program-vm"));

        let sym_body = render_sym(&m, &[], 0x140000000);
        assert!(sym_body.contains("vm_type=program"));
        assert!(sym_body.contains("handler=0x3C"));
        assert!(sym_body.contains("crypto=program-vm"));
    }
}
