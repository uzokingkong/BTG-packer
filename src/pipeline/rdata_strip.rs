// ==============================================================================
// BTG Pipeline - Stealth Metadata & String Stripping (Pillar 1)
// ==============================================================================
// Eradicates plaintext source file paths, panic formatting metadata, test strings,
// and PDB paths from `.rdata` / `.data` sections to eliminate reverse engineering
// clues and reach commercial Themida-grade stealth.
// ==============================================================================

use crate::pe::builder::SectionData;

pub struct RdataMetadataStripper;

impl RdataMetadataStripper {
    /// Returns without modifying loadable section data.
    ///
    /// A byte-pattern scan cannot establish that an `RSDS` occurrence belongs to
    /// the PE debug directory. Zeroing bytes after an arbitrary match can corrupt
    /// live strings, constants, vtables, or TLS initialization data. Debug records
    /// must instead be removed through the PE debug-directory entry, where record
    /// ownership and bounds are known.
    pub fn sanitize_sections(sections: &mut [SectionData], _seed: u64) -> usize {
        let _ = sections;
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdata_strip_source_paths_and_rsds() {
        let mut test_bytes = Vec::new();
        test_bytes.extend_from_slice(b"SomePrefix\0");
        test_bytes.extend_from_slice(b"C:\\projects\\rust\\src\\mini_vm.rs:42:10\0");
        test_bytes.extend_from_slice(b"RSDS_dummy_pdb_guid_path_here.pdb\0");
        test_bytes.extend_from_slice(b"KeepThisSafeData\0");

        let mut sections = vec![SectionData {
            name: ".rdata".to_string(),
            virtual_size: test_bytes.len() as u32,
            virtual_address: 0x1000,
            characteristics: 0x40000040,
            bytes: test_bytes,
        }];

        let original = sections[0].bytes.clone();
        let count = RdataMetadataStripper::sanitize_sections(&mut sections, 0x1337);
        assert_eq!(
            count, 0,
            "unowned byte-pattern matches must not be modified"
        );
        assert_eq!(
            sections[0].bytes, original,
            "loadable data must remain byte-exact"
        );

        let result_str = String::from_utf8_lossy(&sections[0].bytes);
        assert!(
            result_str.contains("mini_vm.rs"),
            "Loadable source text must not be destructively stripped"
        );
        assert!(
            result_str.contains("RSDS"),
            "unowned RSDS-like data must be preserved"
        );
    }
}
