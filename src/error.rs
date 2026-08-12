// ==============================================================================
// BTG Packer - Domain-Specific Error Types (review P1-3).
//
// Replaces generic `anyhow` strings with strongly-typed, stage-categorized errors
// so callers (library users & CLI) can programmatically inspect failure causes.
// ==============================================================================

use thiserror::Error;

/// Stage 1: PE Parsing, Section & Relocation Errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    #[error("PE header parsing failed: {0}")]
    HeaderParseFailed(String),

    #[error("Invalid section '{name}': {reason}")]
    InvalidSection { name: String, reason: String },

    #[error("Relocation table processing failed: {0}")]
    RelocationFailed(String),

    #[error("Invalid Entry Point RVA 0x{0:X}")]
    InvalidEntryPoint(u64),

    #[error("Import/Export Table patch error: {0}")]
    ImportExportPatchFailed(String),
}

/// Stage 2: Graph & Physical Layout Errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    #[error("CFG Extractor failed to trace basic blocks: {0}")]
    ExtractorFailed(String),

    #[error("MicroSlicer chunking failed for block {block_id}: {reason}")]
    SlicerFailed { block_id: u32, reason: String },

    #[error("Physical layout shuffle failed: {0}")]
    LayoutShuffleFailed(String),

    #[error("Graph validation failed: {0}")]
    ValidationFailed(String),
}

/// Stage 3: VM Compiler, Lifter & Interpreter Errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum VmCompilerError {
    #[error("Unsupported instruction '{instruction}' (code: {code:?})")]
    UnsupportedInstruction { instruction: String, code: String },

    #[error("Reserved scratch register collision with '{register}' in instruction: {instruction}")]
    ScratchRegisterCollision { register: String, instruction: String },

    #[error("Jump displacement overflow for label {label}: offset = {disp}")]
    JumpDisplacementOverflow { label: u32, disp: i64 },

    #[error("Handler codegen validation failed: {0}")]
    HandlerCodegenValidationFailed(String),

    #[error("VM interpreter runtime error: {0}")]
    InterpreterRuntime(#[from] crate::vm::interp::VmError),
}

/// Stage 4: Obfuscation & MBA Polynomial Errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ObfuscationError {
    #[error("MBA polynomial generation failed: {0}")]
    MbaGenerationFailed(String),

    #[error("Expression simplification error: {0}")]
    ExpressionError(String),
}

/// Stage 5: Protection Pipeline & Crypto Errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    #[error("Section overflow: block {block_id} would overflow at offset {offset} (max: {max_size})")]
    SectionOverflow { block_id: u32, offset: usize, max_size: usize },

    #[error("Re-encryption payload build failed: {0}")]
    ReencryptionPayloadFailed(String),

    #[error("Patch data failed: {0}")]
    PatchDataFailed(String),
}

/// Top-level BTG Packer Error embracing all domain stage errors.
#[derive(Error, Debug)]
pub enum BtgError {
    #[error("PE Error: {0}")]
    Pe(#[from] PeError),

    #[error("Graph/CFG Error: {0}")]
    Graph(#[from] GraphError),

    #[error("VM Compiler Error: {0}")]
    Vm(#[from] VmCompilerError),

    #[error("Obfuscation Error: {0}")]
    Obfuscation(#[from] ObfuscationError),

    #[error("Pipeline Error: {0}")]
    Pipeline(#[from] PipelineError),

    // Backward compatibility variants
    #[error("PE parsing failed: {0}")]
    PeParsingFailed(String),

    #[error("Graph validation failed: {0}")]
    GraphValidationFailed(String),

    #[error("Relocation error: {0}")]
    RelocationError(String),

    #[error("Section overflow: block {block_id} would overflow at offset {offset}")]
    SectionOverflow { block_id: u32, offset: usize },

    #[error("Invalid entry point: {0}")]
    InvalidEntryPoint(String),

    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, BtgError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_formatting() {
        let err: BtgError = PeError::InvalidEntryPoint(0x140001000).into();
        assert_eq!(err.to_string(), "PE Error: Invalid Entry Point RVA 0x140001000");

        let vm_err: BtgError = VmCompilerError::ScratchRegisterCollision {
            register: "R15".to_string(),
            instruction: "mov r15, rax".to_string(),
        }.into();
        assert_eq!(
            vm_err.to_string(),
            "VM Compiler Error: Reserved scratch register collision with 'R15' in instruction: mov r15, rax"
        );

        let pipe_err: BtgError = PipelineError::SectionOverflow {
            block_id: 42,
            offset: 0x2000,
            max_size: 0x1000,
        }.into();
        assert_eq!(
            pipe_err.to_string(),
            "Pipeline Error: Section overflow: block 42 would overflow at offset 8192 (max: 4096)"
        );
    }
}
