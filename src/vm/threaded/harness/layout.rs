pub(crate) const OFF_CODE: usize = 0x1000;
pub(crate) const OFF_TABLE: usize = 0x8000;
pub(crate) const OFF_BYTECODE: usize = 0x9000;
pub(crate) const OFF_STATE: usize = 0xA000;
pub(crate) const OFF_STACK_BASE: usize = 0xE000;
pub(crate) const OFF_BRANCH_MAP: usize = 0xB000;
pub(crate) const ARENA_SIZE: usize = 0x40000;

pub(crate) const REGS_OFF: usize = 0x000; // [u64;16]
pub(crate) const TEMPS_OFF: usize = 0x080; // [u64;8]
pub(crate) const FLAGS_OFF: usize = 0x0C0; // u64
pub(crate) const VSP_OFF: usize = 0x0C8; // u64
pub(crate) const STATE_END: usize = 0x100;

pub(crate) const FLAG_MASK: u64 = 0x8D5; // CF|PF|AF|ZF|SF|OF // CF|PF|ZF|SF|OF  (PF bit 2 added)
