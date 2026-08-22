// ==============================================================================
// BTG - Unified VM Execution Context & ABI (Domit §49, §77)
// ==============================================================================
// Standardizes the runtime state structure across all execution paths
// (reference interpreter, poly interpreter, direct-threaded native harness,
// and commercial poly-direct runtime), preventing VM ABI drift.
// ==============================================================================

use std::collections::HashMap;

/// Unified runtime state container for the virtual machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmExecutionContext {
    /// 16 virtual general-purpose registers (VReg0..VReg15).
    pub regs: [u64; 16],
    /// 8 temporary working registers (Temp0..Temp7).
    pub temps: [u64; 8],
    /// x86/Virtual CPU status flags (CF, ZF, SF, OF, PF, AF).
    pub flags: u64,
    /// Virtual stack pointer offset (negative displacement from STACK_BASE).
    pub vsp: u64,
    /// Current virtual instruction pointer (VIP) byte offset in bytecode.
    pub vip: u64,
    /// Master domain key for key schedule re-synchronization.
    pub domain_key: u64,
    /// Simulated stack memory slice.
    pub stack: Vec<u64>,
    /// Simulated heap/scratch memory map.
    pub mem: HashMap<u64, u8>,
}

impl Default for VmExecutionContext {
    fn default() -> Self {
        Self {
            regs: [0; 16],
            temps: [0; 8],
            flags: 0,
            vsp: 0,
            vip: 0,
            domain_key: 0,
            stack: Vec::new(),
            mem: HashMap::new(),
        }
    }
}

impl VmExecutionContext {
    pub fn new(init_regs: &[u64; 16], domain_key: u64) -> Self {
        let mut ctx = Self::default();
        ctx.regs.copy_from_slice(init_regs);
        ctx.domain_key = domain_key;
        ctx
    }

    /// Read an unsigned integer of given width (1, 2, 4, 8 bytes) from memory.
    pub fn read_mem(&self, addr: u64, width: usize) -> u64 {
        let mut val = 0u64;
        for i in 0..width {
            let b = self.mem.get(&(addr + i as u64)).copied().unwrap_or(0);
            val |= (b as u64) << (i * 8);
        }
        val
    }

    /// Write an unsigned integer of given width (1, 2, 4, 8 bytes) to memory.
    pub fn write_mem(&mut self, addr: u64, val: u64, width: usize) {
        for i in 0..width {
            let b = ((val >> (i * 8)) & 0xFF) as u8;
            self.mem.insert(addr + i as u64, b);
        }
    }

    /// Push a 64-bit value to the virtual stack.
    pub fn push(&mut self, val: u64) {
        self.stack.push(val);
        self.vsp = self.vsp.wrapping_sub(8);
    }

    /// Pop a 64-bit value from the virtual stack.
    pub fn pop(&mut self) -> Option<u64> {
        self.vsp = self.vsp.wrapping_add(8);
        self.stack.pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_execution_context_stack_and_mem_ops() {
        let mut ctx = VmExecutionContext::default();
        ctx.push(0x1122_3344_5566_7788);
        assert_eq!(ctx.vsp, 0u64.wrapping_sub(8));
        assert_eq!(ctx.pop(), Some(0x1122_3344_5566_7788));
        assert_eq!(ctx.vsp, 0);

        ctx.write_mem(0x1000, 0xAABBCCDD, 4);
        assert_eq!(ctx.read_mem(0x1000, 4), 0xAABBCCDD);
    }
}
