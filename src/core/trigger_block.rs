use std::collections::HashMap;
use anyhow::{Result, anyhow};
use iced_x86::Instruction;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TriggerBlock {
    pub id: u32,
    pub seed: u32,
    pub raw_instructions: Vec<Instruction>,
    pub instructions: Vec<u8>,
    pub data: Vec<u8>,
    pub entries: HashMap<usize, EntryPointInfo>,
    pub jcc_info: Option<(usize, usize)>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EntryPointInfo {
    pub offset: usize,
    pub entry_type: EntryPointType,
    pub cpu_state: CpuState,
    pub execution_path: Vec<u32>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPointType {
    Normal,
    Misaligned(u8),
    Polymorphic,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CpuState {
    pub registers: HashMap<String, u64>,
    pub flags: u32,
    pub stack_delta: i32,
}

impl TriggerBlock {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            seed: 0,
            raw_instructions: Vec::new(),
            instructions: Vec::new(),
            data: Vec::new(),
            entries: HashMap::new(),
            jcc_info: None,
        }
    }

    pub fn add_entry_point(&mut self, info: EntryPointInfo) -> Result<()> {
        if self.entries.contains_key(&info.offset) {
            return Err(anyhow!("Entry point at offset {} already exists", info.offset));
        }
        
        if info.offset >= self.data.len() && !self.data.is_empty() {
            return Err(anyhow!(
                "Entry point offset {} >= block size {}",
                info.offset,
                self.data.len()
            ));
        }
        
        self.entries.insert(info.offset, info);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn verify_execution_path(&self, offset: usize) -> Result<bool> {
        let entry = self.entries.get(&offset)
            .ok_or_else(|| anyhow!("No entry point at offset {}", offset))?;
        
        Ok(!entry.execution_path.is_empty())
    }

    #[allow(dead_code)]
    pub fn validate_polymorphism(&self) -> Result<()> {
        if self.entries.len() < 2 {
            return Err(anyhow!("Polymorphism requires at least 2 entry points"));
        }
        
        let paths: Vec<_> = self.entries.values()
            .map(|e| &e.execution_path)
            .collect();
        
        for i in 0..paths.len() {
            for j in (i+1)..paths.len() {
                if paths[i] == paths[j] {
                    return Err(anyhow!("Entry points {} and {} have same path", i, j));
                }
            }
        }
        
        Ok(())
    }
}
