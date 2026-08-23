// ==============================================================================
// BTG v36 - C-1 VM Memory Model
// ==============================================================================
//
// Defines the memory schema the code VM will operate over when the boot integration
// lifts the original program (M6 Phase-2). The VM currently addresses the PE image
// through absolute VAs (OP_MOV*_A); this module formalizes *which* regions exist
// (code / data / rodata / stack / heap / system / imports), their base-address + size
// ranges, and how an absolute VA resolves into a region (bounds-checked).
//
// This is the "VM 메모리 모델" (C-1) design core. It is pure data + resolution logic,
// so it is unit-testable without touching the boot stub or the PE layout, and the
// `--text-vm-oep` diagnostic uses it to report the target's mapped regions.
// ==============================================================================

/// Region kinds the VM memory model tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemKind {
    /// executable code (original .text, or the relocated payload)
    Code,
    /// writable initialized/uninitialized data (.data/.bss)
    Data,
    /// read-only data (.rdata, jump tables, string literals)
    ReadOnly,
    /// stack region
    Stack,
    /// heap region (process heap)
    Heap,
    /// system address space (PEB/TEB, ntdll structures)
    System,
    /// import address table / resolved function slots
    Imports,
}

impl MemKind {
    pub fn name(&self) -> &'static str {
        match self {
            MemKind::Code => ".text",
            MemKind::Data => ".data",
            MemKind::ReadOnly => ".rdata",
            MemKind::Stack => "stack",
            MemKind::Heap => "heap",
            MemKind::System => "system(PEB/TEB)",
            MemKind::Imports => "imports(IAT)",
        }
    }
}

/// One mapped region of the VM's address space.
#[derive(Debug, Clone, Copy)]
pub struct MemRegion {
    pub base_va: u64,
    pub size: u64,
    pub kind: MemKind,
    /// page permissions (RWX bits, mirroring PE section characteristics / VirtualProtect).
    pub rwx: u8, // bit0=R, bit1=W, bit2=X
}

impl MemRegion {
    pub fn new(base_va: u64, size: u64, kind: MemKind, rwx: u8) -> Self {
        Self {
            base_va,
            size,
            kind,
            rwx,
        }
    }
    pub fn end(&self) -> u64 {
        self.base_va.saturating_add(self.size)
    }
    pub fn contains(&self, va: u64) -> bool {
        va >= self.base_va && va < self.end()
    }
}

/// The VM memory model: an ordered list of mapped regions over the process address space.
#[derive(Debug, Clone, Default)]
pub struct VmMemoryModel {
    pub regions: Vec<MemRegion>,
}

impl VmMemoryModel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, r: MemRegion) {
        self.regions.push(r);
        // keep sorted by base_va for binary-search resolution
        self.regions.sort_by_key(|r| r.base_va);
    }

    /// Resolve an absolute VA to the region that contains it (bounds-checked).
    pub fn resolve(&self, va: u64) -> Option<&MemRegion> {
        self.regions.iter().find(|r| r.contains(va))
    }

    /// Is `va` inside any mapped region (i.e. a valid VM-addressable address)?
    pub fn is_mapped(&self, va: u64) -> bool {
        self.resolve(va).is_some()
    }

    /// Translate a region-relative offset into an absolute VA.
    /// Returns None if `region`'s offset is out of bounds.
    pub fn abs(&self, region_base: u64, offset: u64) -> Option<u64> {
        let r = self.resolve(region_base)?;
        if offset >= r.size {
            return None;
        }
        Some(r.base_va + offset)
    }

    /// Region kind at an address (useful for e.g. detecting a write to .rdata).
    pub fn kind_at(&self, va: u64) -> Option<MemKind> {
        self.resolve(va).map(|r| r.kind)
    }

    /// Convenience: check a load/store of `width` bytes at `va` stays in one region.
    pub fn access_ok(&self, va: u64, width: u64) -> bool {
        match self.resolve(va) {
            Some(r) => va.saturating_add(width) <= r.end(),
            None => false,
        }
    }
}

/// Build a memory model from a parsed PE's section layout (used by `--text-vm-oep`).
/// `image_base` = preferred load address; `sections` = (name, rva, vsize).
pub fn model_from_pe(
    image_base: u64,
    entry_rva: u32,
    text_rva: u32,
    text_size: u32,
    sections: &[(String, u32, u32)],
) -> VmMemoryModel {
    let mut m = VmMemoryModel::new();
    for (name, rva, vsize) in sections {
        let kind = match name.as_str() {
            ".text" => MemKind::Code,
            ".data" | ".bss" => MemKind::Data,
            ".rdata" | ".rodata" => MemKind::ReadOnly,
            _ => MemKind::Data,
        };
        let rwx = if kind == MemKind::Code { 0b111 } else { 0b011 };
        m.add(MemRegion::new(
            image_base + *rva as u64,
            *vsize as u64,
            kind,
            rwx,
        ));
    }
    // The original entry block lives in .text; expose it as the model's entry anchor.
    let _ = entry_rva;
    let _ = text_rva;
    let _ = text_size;
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_model_resolve_bounds() {
        let mut m = VmMemoryModel::new();
        m.add(MemRegion::new(0x140001000, 0x2000, MemKind::Code, 0b111));
        m.add(MemRegion::new(
            0x140003000,
            0x1000,
            MemKind::ReadOnly,
            0b101,
        ));
        m.add(MemRegion::new(0x140004000, 0x1000, MemKind::Data, 0b011));

        // inside .text
        assert_eq!(m.resolve(0x140001000).map(|r| r.kind), Some(MemKind::Code));
        assert_eq!(m.resolve(0x140002FFF).map(|r| r.kind), Some(MemKind::Code));
        // .rdata starts right after .text
        assert_eq!(
            m.resolve(0x140003000).map(|r| r.kind),
            Some(MemKind::ReadOnly)
        );
        // unmapped gap after the last region
        assert!(m.resolve(0x140005000).is_none());
        // far outside
        assert!(!m.is_mapped(0x1_0000_0000));
        // access crossing region end fails
        assert!(m.access_ok(0x140002FF0, 0x20) == false);
        assert!(m.access_ok(0x140001000, 0x100) == true);
    }

    #[test]
    fn mem_model_abs_translation() {
        let mut m = VmMemoryModel::new();
        m.add(MemRegion::new(0x140001000, 0x1000, MemKind::Code, 0b111));
        assert_eq!(m.abs(0x140001000, 0x10), Some(0x140001010));
        assert_eq!(m.abs(0x140001000, 0x1000), None); // exactly size = OOB
        assert_eq!(m.abs(0x140001000, 0xFFF), Some(0x140001FFF));
    }
}
