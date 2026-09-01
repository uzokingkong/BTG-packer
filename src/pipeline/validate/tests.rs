use super::*;

#[test]
fn final_route_gate_accepts_absent_disabled_metadata() {
    validate_route_metadata_inventory(None, &[], &[], &[], &[], &[]).unwrap();
}

fn route_gate_fixture() -> (
    Vec<u8>,
    Vec<SectionInfo>,
    Vec<crate::vm::route_table::OriginalTargetRva>,
    Vec<crate::vm::route_metadata::GeneratedRouteDestination>,
    Vec<crate::vm::route_metadata::RvaSpan>,
) {
    use crate::analysis::program_model::FunctionId;
    use crate::vm::poly::VmArchitectureFamily;
    use crate::vm::route_table::{
        EntryVip, FunctionRoute, GatewayKind, MaterializedRouteTable, OriginalTargetRva,
    };
    let original = OriginalTargetRva(0x2100);
    let table = MaterializedRouteTable::from_sorted_entries(vec![(
        original,
        FunctionRoute {
            function_id: FunctionId(7),
            family: VmArchitectureFamily::Register,
            entry_vip: EntryVip(0),
            gateway: GatewayKind::CrossFamily,
        },
    )]);
    let _canonical = table.to_metadata().unwrap().bytes;
    let bytes = vec![0xa5; 32];
    let sections = vec![SectionInfo {
        name: ".vmroute".into(),
        rva: 0x5000,
        virtual_size: bytes.len() as u32,
        raw_ptr: 0,
        raw_size: bytes.len() as u32,
        characteristics: 0x4000_0040,
    }];
    (
        bytes,
        sections,
        vec![original],
        vec![crate::vm::route_metadata::GeneratedRouteDestination {
            original,
            destination_rva: 0x3100,
        }],
        vec![crate::vm::route_metadata::RvaSpan {
            start: 0x3000,
            end: 0x4000,
        }],
    )
}

#[test]
fn final_route_gate_accepts_enabled_authoritative_inventory() {
    let (bytes, sections, originals, destinations, ranges) = route_gate_fixture();
    validate_route_metadata_inventory(
        Some(&bytes),
        &originals,
        &destinations,
        &ranges,
        &bytes,
        &sections,
    )
    .unwrap();
}

#[test]
fn final_route_gate_rejects_modified_commitment() {
    let (mut bytes, sections, originals, destinations, ranges) = route_gate_fixture();
    let staged = bytes.clone();
    bytes[0] ^= 0xff;
    let error = validate_route_metadata_inventory(
        Some(&staged),
        &originals,
        &destinations,
        &ranges,
        &bytes,
        &sections,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("differs from staged"));
}

#[test]
fn complete_vm_coverage_requires_exact_nonzero_totals() {
    let full = crate::pipeline::VmCoverageMetrics {
        vm_blocks: 12,
        total_blocks: 12,
        vm_instructions: 51,
        total_instructions: 51,
        vm_functions: 7,
        total_functions: 7,
        unresolved_internal_edges: Some(0),
        unsupported_instructions: Some(0),
        capability_mismatches: Some(0),
        ..Default::default()
    };
    let (complete, evidence) = complete_vm_coverage(Some(&full));
    assert!(complete);
    assert_eq!(
        evidence,
        "functions=7/7,blocks=12/12,instructions=51/51,unresolved_internal_edges=0,unsupported_instructions=0,capability_mismatches=0"
    );

    let partial = crate::pipeline::VmCoverageMetrics {
        vm_instructions: 50,
        ..full.clone()
    };
    assert!(!complete_vm_coverage(Some(&partial)).0);
    let unresolved = crate::pipeline::VmCoverageMetrics {
        unresolved_internal_edges: Some(1),
        ..full.clone()
    };
    assert!(!complete_vm_coverage(Some(&unresolved)).0);
    assert!(complete_vm_coverage(Some(&unresolved))
        .1
        .contains("unresolved_internal_edges=1"));
    let unmeasured = crate::pipeline::VmCoverageMetrics {
        unresolved_internal_edges: None,
        ..full.clone()
    };
    assert!(!complete_vm_coverage(Some(&unmeasured)).0);
    assert!(complete_vm_coverage(Some(&unmeasured))
        .1
        .contains("unresolved_internal_edges=unmeasured"));
    let unsupported = crate::pipeline::VmCoverageMetrics {
        unsupported_instructions: Some(1),
        ..full.clone()
    };
    assert!(!complete_vm_coverage(Some(&unsupported)).0);
    assert!(complete_vm_coverage(Some(&unsupported))
        .1
        .contains("unsupported_instructions=1"));
    let capability_unmeasured = crate::pipeline::VmCoverageMetrics {
        capability_mismatches: None,
        ..full
    };
    assert!(!complete_vm_coverage(Some(&capability_unmeasured)).0);
    assert!(complete_vm_coverage(Some(&capability_unmeasured))
        .1
        .contains("capability_mismatches=unmeasured"));
    assert!(!complete_vm_coverage(None).0);
}

#[test]
fn strict_report_rejects_partial_vm_coverage_with_exact_evidence() {
    let report = EffectiveProfileReport {
        ineffective_features: vec![
            "vm_commercial:incomplete-coverage;functions=6/7,blocks=11/12,instructions=50/51"
                .to_string(),
        ],
        vm_coverage_evidence: Some("functions=6/7,blocks=11/12,instructions=50/51".to_string()),
        ..Default::default()
    };
    let error = report.ensure_vm_full_coverage().unwrap_err().to_string();
    assert!(error.contains("functions=6/7"));
    assert!(report.ensure_strict().is_err());
}

#[test]
fn dispatcher_validator_accepts_rc1_44_byte_provider_record() {
    let mba_constant = 0xA5C3_197Du32;
    let id = 17;
    let offset = 0x2A40u64;
    let plain = b"independent region ciphertext";
    let meta = BlockCryptoMeta::new(id, offset, plain.len() as u32);
    let material = RegionCipherProvider::derive_block_key(&mba_constant.to_le_bytes(), &meta);
    assert_eq!(material.len(), 44, "RC1 key+nonce record ABI");

    let mut encrypted = plain.to_vec();
    let mut producer = RegionCipherProvider::from_key(&material);
    producer.encrypt_block(&meta, &mut encrypted).unwrap();
    assert_ne!(encrypted, plain);

    let recovered = decrypt_dispatcher_block(mba_constant, false, id, offset, &encrypted).unwrap();
    assert_eq!(recovered, plain);
}

#[test]
fn dispatcher_validator_rc1_context_mismatch_does_not_recover_plaintext() {
    let mba_constant = 0x41B2_09EFu32;
    let id = 5;
    let offset = 0x880u64;
    let plain = b"context-bound block";
    let meta = BlockCryptoMeta::new(id, offset, plain.len() as u32);
    let material = RegionCipherProvider::derive_block_key(&mba_constant.to_le_bytes(), &meta);
    let mut encrypted = plain.to_vec();
    RegionCipherProvider::from_key(&material)
        .encrypt_block(&meta, &mut encrypted)
        .unwrap();

    let wrong = decrypt_dispatcher_block(mba_constant, false, id + 1, offset, &encrypted).unwrap();
    assert_ne!(
        wrong, plain,
        "block identity must domain-separate the RC1 stream"
    );
}

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
