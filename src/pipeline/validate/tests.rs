use super::*;

#[test]
fn test_expected_chunks_basic() {
    // 545 bytes -> single chunk (fits in 0x10000)
    let c = expected_chunks(0x8000, 545);
    assert_eq!(c, vec![(0x8000, 545)]);
}

#[test]
fn test_expected_chunks_split_and_overflow_absorb() {
    // 0x20001 bytes -> 0x10000 + 0x10000 + 1 -> three chunks
    let c = expected_chunks(0x8000, 0x20001);
    assert_eq!(c.len(), 3);
    assert_eq!(c[0], (0x8000, 0x10000));
    assert_eq!(c[1], (0x18000, 0x10000));
    assert_eq!(c[2], (0x28000, 1));
    // zero payload -> no chunks
    assert!(expected_chunks(0x8000, 0).is_empty());
}

/// Build a minimal RT_RCDATA resource tree identical in layout to
/// rsrc_register::build_tree (k = 1 chunk), placed at `base_off` inside a
/// section. Returns the tree bytes (already section-relative).
fn build_synthetic_tree(base_off: usize, chunk: (u32, u32)) -> Vec<u8> {
    let k = 1usize;
    // tree-local offsets (base_off added exactly once via `abs`, matching
    // rsrc_register::build_tree — locals are relative to the tree start)
    let type_dir_off = 16 + 8;
    let name_dirs_off = type_dir_off + 16 + k * 8;
    let data_entries_off = name_dirs_off + k * 24;
    // Tree pointers are relative to the tree root (resource base), matching
    // rsrc_register::build_tree — NOT relative to the section start.
    let _ = base_off;
    let abs = |local: usize| local as u32;

    let mut out = Vec::new();
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // NumberOfNamedEntries
    out.extend_from_slice(&1u16.to_le_bytes()); // NumberOfIdEntries
    out.extend_from_slice(&RT_RCDATA.to_le_bytes());
    out.extend_from_slice(&(abs(type_dir_off) | 0x8000_0000).to_le_bytes());

    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(k as u16).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(abs(name_dirs_off) | 0x8000_0000).to_le_bytes());

    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // lang id
    out.extend_from_slice(&abs(data_entries_off).to_le_bytes());

    out.extend_from_slice(&chunk.0.to_le_bytes());
    out.extend_from_slice(&chunk.1.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

#[test]
fn test_walk_resource_tree_synthetic() {
    // payload section: RVA 0x8000, virtual 0x100, raw at file 0x200
    let payload_sec = SectionInfo {
        name: ".vdata".to_string(),
        rva: 0x8000,
        virtual_size: 0x100,
        raw_ptr: 0x200,
        raw_size: 0x100,
        characteristics: 0x4000_0040,
    };
    // resource section: RVA 0x9000, virtual 0x200, raw at file 0x300
    let rsrc_sec = SectionInfo {
        name: ".rsrc".to_string(),
        rva: 0x9000,
        virtual_size: 0x200,
        raw_ptr: 0x300,
        raw_size: 0x200,
        characteristics: 0x4000_0040,
    };
    let sections = vec![payload_sec, rsrc_sec.clone()];

    // tree at base_off 0x40 of the .rsrc section (file 0x340, section off 0x40);
    // chunk = payload 0x40 bytes. dir_rva = 0x9000 + 0x40.
    let tree = build_synthetic_tree(0x40, (0x8000, 0x40));
    assert_eq!(tree.len(), 0x58);

    // compose a fake file: [..0x340 = zeroes][tree][..]
    let mut file = vec![0u8; 0x500];
    file[0x340..0x340 + tree.len()].copy_from_slice(&tree);

    let entries = walk_resource_tree(&rsrc_sec, &file, 0x9000 + 0x40, 0x58, &sections).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0],
        ResDataEntry {
            offset_rva: 0x8000,
            size: 0x40
        }
    );
}

#[test]
fn test_walk_resource_tree_rejects_oob_entry() {
    let rsrc_sec = SectionInfo {
        name: ".rsrc".to_string(),
        rva: 0x9000,
        virtual_size: 0x200,
        raw_ptr: 0x300,
        raw_size: 0x200,
        characteristics: 0x4000_0040,
    };
    let payload_sec = SectionInfo {
        name: ".vdata".to_string(),
        rva: 0x8000,
        virtual_size: 0x100,
        raw_ptr: 0x200,
        raw_size: 0x100,
        characteristics: 0x4000_0040,
    };
    let sections = vec![payload_sec, rsrc_sec.clone()];

    // Corrupt tree: data entry points at RVA 0x7000 (outside any section).
    // Data entry sits at tree-relative 0x48 (section offset 0x88).
    let mut tree = build_synthetic_tree(0x40, (0x8000, 0x40));
    tree[0x48..0x4C].copy_from_slice(&0x7000u32.to_le_bytes());

    let mut file = vec![0u8; 0x500];
    file[0x340..0x340 + tree.len()].copy_from_slice(&tree);

    let res = walk_resource_tree(&rsrc_sec, &file, 0x9000 + 0x40, 0x58, &sections);
    assert!(
        res.is_err(),
        "data entry outside all sections must fail validation"
    );
}
