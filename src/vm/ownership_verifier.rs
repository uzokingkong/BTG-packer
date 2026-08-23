// ==============================================================================
// BTG - Function-Atomic VM/Native Ownership Verifier (Domit §38, §44, §82 #3)
// ==============================================================================
// Enforces whole-function atomicity for VM virtualization. A function must either
// be 100% virtualized or 100% native. Disallows fragmented intermediate boundaries
// within a single function body to prevent stack/register desynchronization.
// ==============================================================================

use std::collections::HashMap;

/// Ownership status of a function's basic blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionOwnership {
    /// Every block in the function is virtualized in VM.
    AllVm,
    /// Every block in the function remains native.
    AllNative,
    /// Invalid state: some blocks are in VM, while others are native.
    MixedBoundary,
}

/// Function ownership descriptor.
#[derive(Debug, Clone)]
pub struct FunctionOwnershipRecord {
    pub function_va: u64,
    pub total_blocks: usize,
    pub vm_blocks: usize,
    pub native_blocks: usize,
}

impl FunctionOwnershipRecord {
    pub fn new(function_va: u64) -> Self {
        Self {
            function_va,
            total_blocks: 0,
            vm_blocks: 0,
            native_blocks: 0,
        }
    }

    pub fn record_block(&mut self, is_vm: bool) {
        self.total_blocks += 1;
        if is_vm {
            self.vm_blocks += 1;
        } else {
            self.native_blocks += 1;
        }
    }

    pub fn ownership(&self) -> FunctionOwnership {
        if self.vm_blocks == self.total_blocks && self.total_blocks > 0 {
            FunctionOwnership::AllVm
        } else if self.native_blocks == self.total_blocks && self.total_blocks > 0 {
            FunctionOwnership::AllNative
        } else {
            FunctionOwnership::MixedBoundary
        }
    }
}

/// Verifies that all functions maintain strict all-or-nothing ownership.
#[derive(Debug, Default)]
pub struct OwnershipVerifier {
    records: HashMap<u64, FunctionOwnershipRecord>,
}

impl OwnershipVerifier {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    pub fn record_block(&mut self, function_va: u64, is_vm: bool) {
        self.records
            .entry(function_va)
            .or_insert_with(|| FunctionOwnershipRecord::new(function_va))
            .record_block(is_vm);
    }

    /// Verifies all recorded functions and returns any violations.
    pub fn verify(&self) -> Result<(), Vec<u64>> {
        let mut violations = Vec::new();
        for (&func_va, record) in &self.records {
            if record.ownership() == FunctionOwnership::MixedBoundary {
                violations.push(func_va);
            }
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ownership_verifier_enforces_atomicity() {
        let mut verifier = OwnershipVerifier::new();

        // Function 1: 100% VM -> OK
        verifier.record_block(0x140001000, true);
        verifier.record_block(0x140001000, true);

        // Function 2: 100% Native -> OK
        verifier.record_block(0x140002000, false);
        verifier.record_block(0x140002000, false);

        assert!(verifier.verify().is_ok());

        // Function 3: Mixed -> Violation
        verifier.record_block(0x140003000, true);
        verifier.record_block(0x140003000, false);

        let err = verifier.verify().unwrap_err();
        assert_eq!(err, vec![0x140003000]);
    }
}
