// ==============================================================================
// BTG Pipeline - RT_RCDATA Resource Registration (PE Resource Directory rebuild)
// ==============================================================================
//
// `--rsrc-register` (with `--payload-relocate`): registers the relocated
// encrypted payload (.vdata) as *official* RT_RCDATA resources by rebuilding
// the PE resource directory (DataDirectory[2]).
//
// Strategy (zero section-table surgery):
//   * If the target already has a .rsrc section -> append the new directory
//     tree to the END of that section (original root entries preserved
//     verbatim — their offsets stay valid because nothing moves).
//   * Otherwise -> append the tree to the .vdata (payload) section itself.
//   * DataDirectory[2] is repointed at the appended tree (set in build.rs).
//
// Resource data entries point at the payload chunk RVAs inside .vdata, so
// resource viewers (PE-bear, Resource Hacker) and LoadResource/LoadLibraryEx
// see the payload as normal RT_RCDATA resources (IDs 1..K).
// ==============================================================================

use crate::pipeline::PipelineContext;
use anyhow::Result;

/// RT_RCDATA resource type id
const RT_RCDATA: u32 = 10;
/// fallback type id when the target already uses type 10
const ALT_TYPE_ID: u32 = 0x40;
/// per-resource chunk size (payload split into chunks)
const CHUNK_SIZE: u32 = 0x10000;
/// max number of RT_RCDATA resources
const MAX_CHUNKS: usize = 64;

#[derive(Debug, Clone, Default)]
struct RootInfo {
    named: u16,
    entries: Vec<(u32, u32)>,
}

/// Parse the root resource directory of a section.
fn parse_root(sec: &[u8]) -> RootInfo {
    let mut root = RootInfo::default();
    if sec.len() < 16 {
        return root;
    }
    let u16at = |o: usize| u16::from_le_bytes([sec[o], sec[o + 1]]);
    let u32at = |o: usize| u32::from_le_bytes([sec[o], sec[o + 1], sec[o + 2], sec[o + 3]]);
    root.named = u16at(12);
    let ids = u16at(14);
    for i in 0..(root.named as usize + ids as usize) {
        let off = 16 + i * 8;
        if off + 8 <= sec.len() {
            root.entries.push((u32at(off), u32at(off + 4)));
        }
    }
    root
}

/// Build a PE resource directory tree registering `chunks` as RT_RCDATA
/// resources with IDs 1..K, preserving the original root entries.
///
/// `base_off` = offset of the tree within its section. **All directory-entry
/// offsets are relative to the resource base (= the RVA stored in
/// DataDirectory[2]), NOT the section start.** The tree is emitted with
/// offsets relative to its own root, so the root must sit exactly at the
/// resource base.
fn build_tree(root: &RootInfo, chunks: &[(u32, u32)], base_off: usize) -> Vec<u8> {
    let k = chunks.len();
    let total_root_entries = root.entries.len() + 1;
    let mut out = Vec::with_capacity(16 + total_root_entries * 8 + k * (16 + 8 + 24) + k * 16);

    // layout (offsets relative to tree start == resource base)
    let type_dir_off = 16 + total_root_entries * 8;
    let name_dirs_off = type_dir_off + 16 + k * 8;
    let data_entries_off = name_dirs_off + k * 24;
    let rel = |local: usize| local as u32; // relative to resource base

    // ── root IMAGE_RESOURCE_DIRECTORY ─────────────────────────────────────────
    out.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    out.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    out.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
    out.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
    out.extend_from_slice(&root.named.to_le_bytes());
    out.extend_from_slice(&((root.entries.len() + 1) as u16).to_le_bytes());
    for (name, off) in &root.entries {
        out.extend_from_slice(&name.to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
    }
    let type_id = if root.entries.iter().any(|(n, _)| *n == RT_RCDATA) {
        ALT_TYPE_ID
    } else {
        RT_RCDATA
    };
    out.extend_from_slice(&type_id.to_le_bytes());
    out.extend_from_slice(&(rel(type_dir_off) | 0x8000_0000).to_le_bytes());

    // ── type-level directory (one entry per chunk name) ────────────────────────
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // NumberOfNamedEntries
    out.extend_from_slice(&(k as u16).to_le_bytes());
    for i in 0..k {
        out.extend_from_slice(&((i + 1) as u32).to_le_bytes());
        out.extend_from_slice(&(rel(name_dirs_off + i * 24) | 0x8000_0000).to_le_bytes());
    }

    // ── name-level directories (one language entry each, lang id = 0) ──────────
    for i in 0..k {
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // NumberOfNamedEntries
        out.extend_from_slice(&1u16.to_le_bytes()); // NumberOfIdEntries
        out.extend_from_slice(&0u32.to_le_bytes()); // lang id
        out.extend_from_slice(&rel(data_entries_off + i * 16).to_le_bytes());
    }

    // ── IMAGE_RESOURCE_DATA_ENTRY per chunk ────────────────────────────────────
    for (rva, size) in chunks {
        out.extend_from_slice(&rva.to_le_bytes()); // OffsetToData (RVA)
        out.extend_from_slice(&size.to_le_bytes()); // Size
        out.extend_from_slice(&0u32.to_le_bytes()); // CodePage
        out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    }

    let _ = base_off; // tree is placed at base_off; offsets are root-relative
    out
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Split the payload into RT_RCDATA chunk entries (absolute RVAs).
fn chunk_payload(payload_rva: u32, payload_len: u32) -> Vec<(u32, u32)> {
    let mut chunks = Vec::new();
    let mut off = 0u32;
    let mut remaining = payload_len;
    while remaining > 0 && chunks.len() < MAX_CHUNKS {
        let sz = remaining.min(CHUNK_SIZE);
        chunks.push((payload_rva + off, sz));
        off += sz;
        remaining -= sz;
    }
    if remaining > 0 {
        if let Some(last) = chunks.last_mut() {
            last.1 += remaining;
        }
    }
    chunks
}

/// One parsed resource directory entry.
#[derive(Clone, Debug)]
struct PEntry {
    /// Raw Name field: integer ID, or (high bit set) offset of a UTF-16 name
    /// string relative to the resource base.
    name: u32,
    is_dir: bool,
    /// OffsetToData low 31 bits, relative to the resource base.
    target: u32,
}

/// Parse a resource directory at absolute offset `off` within `sec`.
fn parse_dir(sec: &[u8], off: usize) -> Vec<PEntry> {
    let u16at = |o: usize| u16::from_le_bytes([sec[o], sec[o + 1]]);
    let u32at = |o: usize| u32::from_le_bytes([sec[o], sec[o + 1], sec[o + 2], sec[o + 3]]);
    let nname = u16at(off + 12) as usize;
    let nid = u16at(off + 14) as usize;
    let mut out = Vec::with_capacity(nname + nid);
    for i in 0..(nname + nid) {
        let eo = off + 16 + i * 8;
        let name = u32at(eo);
        let raw = u32at(eo + 4);
        let is_dir = raw & 0x8000_0000 != 0;
        out.push(PEntry {
            name,
            is_dir,
            target: raw & 0x7fff_ffff,
        });
    }
    out
}

/// Rebuild a resource section preserving every original resource (icon,
/// version, manifest, ...) and appending the payload RT_RCDATA subtree.
///
/// Returns new section bytes. The rebuilt root directory sits at offset 0, so
/// the caller must set DataDirectory[2] = .rsrc section VA.
fn rebuild_rsrc_section(sec: &[u8], sec_rva: u32, chunks: &[(u32, u32)]) -> Vec<u8> {
    fn u32at(d: &[u8], o: usize) -> u32 {
        u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
    }

    enum Node {
        Dir {
            name: u32,
            name_str: Option<Vec<u8>>,
            children: Vec<Node>,
        },
        Leaf {
            name: u32,
            name_str: Option<Vec<u8>>,
            rva: u32,
            size: u32,
            codepage: u32,
            reserved: u32,
            internal: bool,
            blob: Vec<u8>,
        },
    }

    fn read_name_str(sec: &[u8], name: u32) -> Option<Vec<u8>> {
        if name & 0x8000_0000 == 0 {
            return None;
        }
        let off = (name & 0x7fff_ffff) as usize;
        if off + 2 > sec.len() {
            return None;
        }
        let ln = u16::from_le_bytes([sec[off], sec[off + 1]]) as usize;
        let end = off + 2 + ln * 2;
        if end > sec.len() {
            return None;
        }
        Some(sec[off + 2..end].to_vec())
    }

    fn collect(sec: &[u8], sec_rva: u32, entries: &[PEntry]) -> Vec<Node> {
        let mut nodes = Vec::new();
        for e in entries {
            let name = e.name;
            let name_str = read_name_str(sec, name);
            let target = e.target as usize;
            if e.is_dir {
                let sub = parse_dir(sec, target);
                nodes.push(Node::Dir {
                    name,
                    name_str,
                    children: collect(sec, sec_rva, &sub),
                });
            } else {
                let rva = u32at(sec, target);
                let size = u32at(sec, target + 4);
                let codepage = u32at(sec, target + 8);
                let reserved = u32at(sec, target + 12);
                let internal = rva >= sec_rva && (rva as u64) < sec_rva as u64 + sec.len() as u64;
                let blob = if internal {
                    let bo = (rva - sec_rva) as usize;
                    let n = size as usize;
                    let avail = sec.len().saturating_sub(bo);
                    sec[bo..bo + n.min(avail)].to_vec()
                } else {
                    Vec::new()
                };
                nodes.push(Node::Leaf {
                    name,
                    name_str,
                    rva,
                    size,
                    codepage,
                    reserved,
                    internal,
                    blob,
                });
            }
        }
        nodes
    }

    fn emit_name(name: &u32, name_str: Option<&[u8]>, buf: &mut Vec<u8>) -> u32 {
        match name_str {
            Some(s) => {
                let so = align4(buf.len()) as u32;
                let ln = (s.len() / 2) as u16;
                buf.resize(so as usize + 2 + s.len(), 0);
                buf[so as usize..][..2].copy_from_slice(&ln.to_le_bytes());
                buf[so as usize + 2..][..s.len()].copy_from_slice(s);
                0x8000_0000 | so
            }
            None => *name,
        }
    }

    fn emit_nodes(nodes: &[Node], sec_rva: u32, buf: &mut Vec<u8>) -> u32 {
        let start = align4(buf.len()) as u32;
        let n = nodes.len();
        buf.resize(start as usize + 16 + n * 8, 0);
        let mut entries: Vec<(u32, u32)> = Vec::with_capacity(n);
        for node in nodes {
            match node {
                Node::Dir {
                    name,
                    name_str,
                    children,
                } => {
                    let nf = emit_name(name, name_str.as_deref(), buf);
                    let child_off = emit_nodes(children, sec_rva, buf);
                    entries.push((nf, 0x8000_0000 | child_off));
                }
                Node::Leaf {
                    name,
                    name_str,
                    rva,
                    size,
                    codepage,
                    reserved,
                    internal,
                    blob,
                } => {
                    let nf = emit_name(name, name_str.as_deref(), buf);
                    let mut out_rva = *rva;
                    if *internal && !blob.is_empty() {
                        let bo = align4(buf.len()) as u32;
                        buf.resize(bo as usize + blob.len(), 0);
                        buf[bo as usize..][..blob.len()].copy_from_slice(blob);
                        out_rva = sec_rva + bo;
                    }
                    let de = align4(buf.len()) as u32;
                    buf.resize(de as usize + 16, 0);
                    buf[de as usize..][..4].copy_from_slice(&out_rva.to_le_bytes());
                    buf[de as usize + 4..][..4].copy_from_slice(&size.to_le_bytes());
                    buf[de as usize + 8..][..4].copy_from_slice(&codepage.to_le_bytes());
                    buf[de as usize + 12..][..4].copy_from_slice(&reserved.to_le_bytes());
                    entries.push((nf, de));
                }
            }
        }
        let nname = nodes
            .iter()
            .filter(|nd| match nd {
                Node::Dir { name, .. } | Node::Leaf { name, .. } => name & 0x8000_0000 != 0,
            })
            .count() as u16;
        let nid = (n - nname as usize) as u16;
        buf[start as usize..][..4].copy_from_slice(&0u32.to_le_bytes());
        buf[start as usize + 4..][..4].copy_from_slice(&0u32.to_le_bytes());
        buf[start as usize + 8..][..2].copy_from_slice(&0u16.to_le_bytes());
        buf[start as usize + 10..][..2].copy_from_slice(&0u16.to_le_bytes());
        buf[start as usize + 12..][..2].copy_from_slice(&nname.to_le_bytes());
        buf[start as usize + 14..][..2].copy_from_slice(&nid.to_le_bytes());
        for (i, (nf, of)) in entries.iter().enumerate() {
            let eo = start as usize + 16 + i * 8;
            buf[eo..][..4].copy_from_slice(&nf.to_le_bytes());
            buf[eo + 4..][..4].copy_from_slice(&of.to_le_bytes());
        }
        start
    }

    // ── Parse original tree ────────────────────────────────────────────────────
    let root_entries = parse_dir(sec, 0);
    let mut nodes = collect(sec, sec_rva, &root_entries);

    // ── Append the RT_RCDATA type entry (avoid collision with existing type 10)
    let has_10 = nodes.iter().any(|nd| match nd {
        Node::Dir { name, .. } | Node::Leaf { name, .. } => *name == RT_RCDATA,
    });
    let type_id = if has_10 { ALT_TYPE_ID } else { RT_RCDATA };
    let mut rcd = Vec::new();
    for (i, (rva, size)) in chunks.iter().enumerate() {
        rcd.push(Node::Leaf {
            name: (i + 1) as u32,
            name_str: None,
            rva: *rva,
            size: *size,
            codepage: 0,
            reserved: 0,
            internal: false,
            blob: Vec::new(),
        });
    }
    nodes.push(Node::Dir {
        name: type_id,
        name_str: None,
        children: rcd,
    });

    let mut buf: Vec<u8> = Vec::new();
    emit_nodes(&nodes, sec_rva, &mut buf);
    buf
}

/// Register the relocated payload as official RT_RCDATA resources.
pub fn run(ctx: &mut PipelineContext) -> Result<()> {
    if ctx.payload_len == 0 {
        println!("[!] --rsrc-register: no relocated payload found — run with --payload-relocate");
        return Ok(());
    }

    let chunks = chunk_payload(ctx.payload_rva, ctx.payload_len);
    println!(
        "[+] RT_RCDATA: registering {} payload chunks ({} bytes total) as resources",
        chunks.len(),
        ctx.payload_len
    );

    // ── Target section: original .rsrc if present, else the .vdata payload sec ──
    let use_rsrc = ctx.patched_sections.iter().any(|s| s.name == ".rsrc");

    if use_rsrc {
        let sec = ctx
            .patched_sections
            .iter_mut()
            .find(|s| s.name == ".rsrc")
            .expect("checked above");
        // Rebuild the whole tree at the .rsrc start so the root IS the resource
        // base: every original resource (icon/version/manifest/...) keeps its
        // structure (offsets recomputed), internal blobs are relocated and their
        // data-entry RVAs rewritten, and the RT_RCDATA payload subtree is
        // appended. DataDirectory[2] = .rsrc VA.
        let rebuilt = rebuild_rsrc_section(&sec.bytes, sec.virtual_address, &chunks);
        sec.bytes = rebuilt;
        sec.virtual_size = sec.virtual_size.max(sec.bytes.len() as u32);
        ctx.rsrc_dir_rva = sec.virtual_address;
        ctx.rsrc_dir_size = sec.bytes.len() as u32;
        println!(
            "[+] RT_RCDATA: resource directory @RVA 0x{:X} ({} bytes) rebuilt at .rsrc start (original resources preserved)",
            ctx.rsrc_dir_rva, ctx.rsrc_dir_size
        );
    } else if let Some(ps) = ctx.payload_section_data.as_mut() {
        let base_off = align4(ps.bytes.len());
        let tree = build_tree(&RootInfo::default(), &chunks, base_off);
        let dir_rva = ps.virtual_address + base_off as u32;
        if ps.bytes.len() < base_off {
            ps.bytes.resize(base_off, 0);
        }
        ps.bytes.extend_from_slice(&tree);
        ps.virtual_size = ps.virtual_size.max(ps.bytes.len() as u32);
        ctx.rsrc_dir_rva = dir_rva;
        ctx.rsrc_dir_size = tree.len() as u32;
        println!(
            "[+] RT_RCDATA: resource directory @RVA 0x{:X} ({} bytes) appended to .vdata",
            dir_rva,
            tree.len()
        );
    } else {
        return Err(anyhow::anyhow!(
            "--rsrc-register: no .rsrc section and no payload section available"
        ));
    }

    Ok(())
}
