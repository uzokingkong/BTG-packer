// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Multi-Entry Trigger Block Definition
// ==============================================================================


use iced_x86::Instruction;

#[derive(Debug, Clone)]
pub struct TriggerBlock {
    pub id: u32,
    pub name: String,
    pub raw_instructions: Vec<Instruction>, // Unencoded Instruction objects (Pass 1 & Pass 2)
    pub instructions: Vec<u8>,               // Final machine code bytes (Pass 3)
    pub entry_offsets: Vec<usize>,          // Multi-entry points relative to block start [0, 1]
    pub is_overlapped: bool,               // True if byte-overlapping prefix is prepended
    pub exit_target_id: Option<u32>,        // Target Block ID to route via Dispatcher
    pub state_key: u64,                     // Verification state key
}

impl TriggerBlock {
    pub fn new(id: u32, name: impl Into<String>, state_key: u64) -> Self {
        Self {
            id,
            name: name.into(),
            raw_instructions: Vec::new(),
            instructions: Vec::new(),
            entry_offsets: vec![0], // Default primary entry point
            is_overlapped: false,
            exit_target_id: None,
            state_key,
        }
    }
}
