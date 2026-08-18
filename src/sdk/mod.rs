// ==============================================================================
// BTG - Commercial-Grade VM: Phase 4 SDK & LLVM Module
// ==============================================================================

pub mod llvm_interface;
pub mod markers;
pub mod selective;

pub use llvm_interface::{
    LlvmIngestionInterface, LlvmSynthesizer, LlvmVirtualFunction, PolyConsumptionRuntime,
};
pub use markers::{MarkerScanner, SIG_VM_END, SIG_VM_START, VmMarkerRegion};
pub use selective::SelectiveVirtualizer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marker_scanner_detection() {
        let mut sample_code = Vec::new();
        // Leading native bytes
        sample_code.extend_from_slice(&[0x90, 0x90, 0x48, 0x31, 0xC0]);
        // Insert VM_START
        sample_code.extend_from_slice(&SIG_VM_START);
        // Code inside VM marker (e.g. arithmetic loop)
        let inner_code = [0x48, 0xFF, 0xC0, 0x48, 0x83, 0xF8, 0x0A];
        sample_code.extend_from_slice(&inner_code);
        // Insert VM_END
        sample_code.extend_from_slice(&SIG_VM_END);
        // Trailing native bytes
        sample_code.extend_from_slice(&[0xC3]);

        let regions = MarkerScanner::scan_markers(&sample_code);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].length, inner_code.len());
        assert_eq!(
            &sample_code[regions[0].start_offset..regions[0].end_offset],
            &inner_code
        );
    }
}
