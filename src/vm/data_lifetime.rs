//! Object-granular encrypted data with decrypt/use/re-encrypt lifetime control.

use crate::vm::seed_lifecycle::derive_seed;
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteralObject {
    pub class: DataClass,
    pub rva: u32,
    pub len: u32,
    pub references: Vec<u32>,
}

/// Shared production ABI for lifetime synchronization.  Legacy callers may
/// still place the table at `entry_state + 0x2000`, but production multi-family
/// placement now stores it once in the global `.vstate` tail so no virtual
/// stack or family-local state can overlap the atomic words.
pub const LIFETIME_SYNC_TABLE_OFFSET: u64 = 0x2000;
pub const LIFETIME_SYNC_ENTRY_SIZE: usize = 48;
pub const LIFETIME_SYNC_CAPACITY: usize = 256;
pub const LIFETIME_SYNC_TABLE_SIZE: usize = LIFETIME_SYNC_ENTRY_SIZE * LIFETIME_SYNC_CAPACITY;
// Keep the process-lifetime table metadata outside the transient cross-family
// return ABI at 0x5000..0x50a0.  In particular, 0x5020/0x5028 are the RCX/RDX
// return-slot pointers and are rewritten for every routed invocation.
pub const LIFETIME_SYNC_PTR_STATE_OFFSET: usize = 0x50A0;
pub const LIFETIME_SYNC_COUNT_STATE_OFFSET: usize = 0x50A8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifetimeSyncEntry {
    pub object_rva: u32,
    pub object_len: u32,
    pub object_va: u64,
    pub object_key: u64,
    pub lock_va: u64,
    pub refcount_va: u64,
    pub owner_va: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifetimeSyncTable {
    pub base_va: u64,
    pub entries: Vec<LifetimeSyncEntry>,
}

impl LifetimeSyncTable {
    /// Legacy in-stride constructor retained for compatibility with unit tests
    /// and non-commercial callers.  Production multi-family placement uses
    /// `build_at()` so the synchronization table lives in the global `.vstate`
    /// tail, outside every family's virtual-stack range.
    pub fn build(
        entry_state_va: u64,
        image_base: u64,
        build_key: u64,
        objects: &[LiteralObject],
    ) -> anyhow::Result<Self> {
        let base_va = entry_state_va
            .checked_add(LIFETIME_SYNC_TABLE_OFFSET)
            .ok_or_else(|| anyhow::anyhow!("data-lifetime sync table VA overflow"))?;
        Self::build_at(base_va, image_base, build_key, objects)
    }

    pub fn build_at(
        base_va: u64,
        image_base: u64,
        build_key: u64,
        objects: &[LiteralObject],
    ) -> anyhow::Result<Self> {
        let mut unique = std::collections::BTreeMap::new();
        for object in objects {
            unique.entry(object.rva).or_insert(object);
        }
        if unique.len() > LIFETIME_SYNC_CAPACITY {
            anyhow::bail!(
                "data-lifetime sync table capacity exceeded: {} > {}",
                unique.len(),
                LIFETIME_SYNC_CAPACITY
            );
        }
        let entries = unique
            .into_iter()
            .enumerate()
            .map(|(index, (object_rva, object))| LifetimeSyncEntry {
                object_rva,
                object_len: object.len,
                object_va: image_base + object_rva as u64,
                object_key: derive_seed(build_key, 0x5343_4F50_4544_4154 ^ object_rva as u64),
                lock_va: base_va + (index * LIFETIME_SYNC_ENTRY_SIZE) as u64,
                refcount_va: base_va + (index * LIFETIME_SYNC_ENTRY_SIZE + 4) as u64,
                owner_va: base_va + (index * LIFETIME_SYNC_ENTRY_SIZE + 8) as u64,
            })
            .collect();
        Ok(Self { base_va, entries })
    }

    pub fn validate_table(&self) -> anyhow::Result<()> {
        self.base_va
            .checked_add(LIFETIME_SYNC_TABLE_SIZE as u64)
            .ok_or_else(|| anyhow::anyhow!("data-lifetime sync table range overflow"))?;
        if self.entries.iter().enumerate().any(|(index, entry)| {
            entry.lock_va != self.base_va + (index * LIFETIME_SYNC_ENTRY_SIZE) as u64
                || entry.refcount_va != entry.lock_va + 4
                || entry.owner_va != entry.lock_va + 8
        }) {
            anyhow::bail!("data-lifetime sync table entry layout drift");
        }
        Ok(())
    }

    pub fn validate_stride(&self, stride: usize) -> anyhow::Result<()> {
        let start = LIFETIME_SYNC_TABLE_OFFSET as usize;
        let end = start
            .checked_add(LIFETIME_SYNC_TABLE_SIZE)
            .ok_or_else(|| anyhow::anyhow!("data-lifetime sync table range overflow"))?;
        let virtual_stack_start = crate::vm::commercial_build::COMMERCIAL_STATE_SIZE as usize;
        let virtual_stack_end = virtual_stack_start
            .checked_add(crate::vm::commercial_build::VIRTUAL_STACK_SIZE as usize)
            .ok_or_else(|| anyhow::anyhow!("commercial virtual-stack range overflow"))?;
        let overlaps_virtual_stack = start < virtual_stack_end && virtual_stack_start < end;
        let call_stack_start = stride
            .checked_sub(crate::vm::interp::CALL_STACK_SIZE)
            .ok_or_else(|| anyhow::anyhow!("VM family stride is smaller than call stack"))?;
        if overlaps_virtual_stack || end > call_stack_start || end > 0x5000 {
            anyhow::bail!(
                "data-lifetime sync table overlaps commercial virtual-stack/cross-family/call-stack state"
            );
        }
        self.validate_table()
    }
}

/// Builds a conservative reference graph for NUL-terminated literals in one
/// read-only PE section. Only direct RIP-relative x64 references are accepted;
/// objects with no statically proven reference are omitted. The returned
/// instruction RVAs let the production transformer prove that every selected
/// object use has a concrete rewrite site instead of encrypting data blindly.
pub fn analyze_referenced_literals(
    text: &[u8],
    text_rva: u32,
    data: &[u8],
    data_rva: u32,
    image_base: u64,
) -> Vec<LiteralObject> {
    let mut candidates = scan_literal_objects(data, data_rva);

    let ip = image_base.saturating_add(text_rva as u64);
    let mut decoder = Decoder::with_ip(64, text, ip, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if !instruction.is_ip_rel_memory_operand() {
            continue;
        }
        let target = instruction.ip_rel_memory_address();
        let Some(target_rva) = target
            .checked_sub(image_base)
            .and_then(|rva| u32::try_from(rva).ok())
        else {
            continue;
        };
        let Some(reference_rva) = instruction
            .ip()
            .checked_sub(image_base)
            .and_then(|rva| u32::try_from(rva).ok())
        else {
            continue;
        };
        if let Some(object) = candidates.iter_mut().find(|object| {
            target_rva >= object.rva && target_rva < object.rva.saturating_add(object.len)
        }) {
            object.references.push(reference_rva);
        } else if let Some(width) = direct_constant_load_width(&instruction) {
            let end = target_rva.saturating_add(width);
            let data_end = data_rva.saturating_add(data.len() as u32);
            if target_rva >= data_rva && end <= data_end {
                candidates.push(LiteralObject {
                    class: DataClass::ConstantPool,
                    rva: target_rva,
                    len: width,
                    references: vec![reference_rva],
                });
            }
        }
    }
    candidates.retain(|object| !object.references.is_empty());
    for object in &mut candidates {
        object.references.sort_unstable();
        object.references.dedup();
    }
    candidates
}

/// Exact-width, read-only RIP-relative loads only.  Excluding arithmetic RMW,
/// XCHG/CMPXCHG and memory destinations keeps constant-pool encryption from
/// changing writable/static state semantics.
pub(crate) fn direct_constant_load_width(instruction: &Instruction) -> Option<u32> {
    if !instruction.is_ip_rel_memory_operand()
        || instruction.op0_kind() != OpKind::Register
        || instruction.op1_kind() != OpKind::Memory
        || !matches!(instruction.memory_size().size(), 4 | 8 | 16)
        || !matches!(
            instruction.mnemonic(),
            Mnemonic::Mov
                | Mnemonic::Movss
                | Mnemonic::Movsd
                | Mnemonic::Movups
                | Mnemonic::Movupd
                | Mnemonic::Movaps
                | Mnemonic::Movapd
                | Mnemonic::Movdqu
                | Mnemonic::Movdqa
        )
    {
        return None;
    }
    Some(instruction.memory_size().size() as u32)
}

/// True only when one reference can be protected without keeping its lifetime
/// scope active across a call or another unwind-capable control boundary.
pub(crate) fn is_unwind_safe_direct_reference(
    instruction: &Instruction,
    object: &LiteralObject,
    image_base: u64,
) -> bool {
    let Some(width) = direct_constant_load_width(instruction) else {
        return false;
    };
    let target = instruction.ip_rel_memory_address();
    let object_start = image_base.saturating_add(object.rva as u64);
    let object_end = image_base.saturating_add(object.rva.saturating_add(object.len) as u64);
    target >= object_start
        && target
            .checked_add(width as u64)
            .is_some_and(|end| end <= object_end)
}

/// Selects the strict subset whose address is loaded directly into a Win64
/// argument register and reaches a call in the same straight-line region.
/// Any control-flow boundary or overwrite of that register kills the proof.
pub fn select_call_scoped_literals(
    text: &[u8],
    text_rva: u32,
    image_base: u64,
    objects: &[LiteralObject],
) -> Vec<LiteralObject> {
    let mut proven = std::collections::BTreeMap::<u32, std::collections::BTreeSet<u32>>::new();
    let mut pending = std::collections::HashMap::<Register, (u32, u32)>::new();
    let mut decoder = Decoder::with_ip(
        64,
        text,
        image_base.saturating_add(text_rva as u64),
        DecoderOptions::NONE,
    );
    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.is_ip_rel_memory_operand() && instruction.code() != Code::Lea_r64_m {
            let target = instruction.ip_rel_memory_address();
            if let (Some(target_rva), Some(reference_rva)) = (
                target
                    .checked_sub(image_base)
                    .and_then(|v| u32::try_from(v).ok()),
                instruction
                    .ip()
                    .checked_sub(image_base)
                    .and_then(|v| u32::try_from(v).ok()),
            ) {
                if let Some(object) = objects.iter().find(|object| {
                    target_rva >= object.rva && target_rva < object.rva.saturating_add(object.len)
                }) {
                    proven.entry(object.rva).or_default().insert(reference_rva);
                }
            }
        }
        let is_call = matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        );
        if is_call {
            for &(object_rva, reference_rva) in pending.values() {
                proven.entry(object_rva).or_default().insert(reference_rva);
            }
            pending.clear();
            continue;
        }
        if !matches!(instruction.flow_control(), FlowControl::Next) {
            pending.clear();
            continue;
        }
        let destination = instruction.op0_register();
        if destination != Register::None {
            pending.remove(&destination.full_register());
        }
        if instruction.code() == Code::Lea_r64_m && instruction.is_ip_rel_memory_operand() {
            let dst = instruction.op0_register().full_register();
            if !matches!(
                dst,
                Register::RCX | Register::RDX | Register::R8 | Register::R9
            ) {
                continue;
            }
            let target = instruction.ip_rel_memory_address();
            let Some(rva) = target
                .checked_sub(image_base)
                .and_then(|v| u32::try_from(v).ok())
            else {
                continue;
            };
            if let Some(object) = objects
                .iter()
                .find(|object| rva >= object.rva && rva < object.rva.saturating_add(object.len))
            {
                let Some(reference_rva) = instruction
                    .ip()
                    .checked_sub(image_base)
                    .and_then(|value| u32::try_from(value).ok())
                else {
                    continue;
                };
                pending.insert(dst, (object.rva, reference_rva));
            }
        }
    }
    objects
        .iter()
        .filter(|object| {
            proven.get(&object.rva).is_some_and(|references| {
                object
                    .references
                    .iter()
                    .all(|reference| references.contains(reference))
            })
        })
        .cloned()
        .collect()
}

fn scan_literal_objects(data: &[u8], data_rva: u32) -> Vec<LiteralObject> {
    let mut objects = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        // UTF-16LE must be recognized before the byte-oriented NUL scan below;
        // otherwise every high zero byte splits `w\0i\0d\0e\0` into one-byte
        // fragments and no production object is ever formed.
        if offset % 2 == 0 {
            let mut end = offset;
            while end + 1 < data.len() && data[end].is_ascii_graphic() && data[end + 1] == 0 {
                end += 2;
            }
            let payload_len = end.saturating_sub(offset);
            if payload_len >= 8 && end + 1 < data.len() && data[end] == 0 && data[end + 1] == 0 {
                objects.push(LiteralObject {
                    class: DataClass::Utf16,
                    rva: data_rva.saturating_add(offset as u32),
                    len: (payload_len + 2) as u32,
                    references: Vec::new(),
                });
                offset = end + 2;
                continue;
            }
        }
        let start = offset;
        while offset < data.len() && data[offset] != 0 {
            offset += 1;
        }
        if offset < data.len() && offset > start {
            let bytes = &data[start..offset];
            if let Some(class) = classify_literal(bytes) {
                objects.push(LiteralObject {
                    class,
                    rva: data_rva.saturating_add(start as u32),
                    len: (bytes.len() + 1) as u32,
                    references: Vec::new(),
                });
            }
        }
        offset = offset.saturating_add(1);
    }
    objects
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClass {
    Ascii,
    Utf8,
    Utf16,
    FormatTable,
    VTable,
    Rtti,
    ConstantPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedDataObject {
    pub class: DataClass,
    ciphertext: Vec<u8>,
    key: u64,
    nonce: u64,
}

impl ProtectedDataObject {
    pub fn protect(class: DataClass, plaintext: &[u8], build_key: u64, object_id: u64) -> Self {
        let key = derive_seed(build_key, 0x4441_5441_4C49_4645 ^ object_id);
        let nonce = derive_seed(key, plaintext.len() as u64 ^ object_id.rotate_left(9));
        let mut ciphertext = plaintext.to_vec();
        crypt(&mut ciphertext, key, nonce);
        Self {
            class,
            ciphertext,
            key,
            nonce,
        }
    }

    pub fn encrypted_bytes(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Plaintext exists only in this temporary buffer. It is overwritten before
    /// the callback returns, including when the callback panics.
    pub fn with_plaintext<R>(&mut self, use_scope: impl FnOnce(&mut [u8]) -> R) -> R {
        let mut scope = PlaintextScope {
            bytes: self.ciphertext.clone(),
            key: self.key,
            nonce: self.nonce,
        };
        crypt(&mut scope.bytes, scope.key, scope.nonce);
        use_scope(&mut scope.bytes)
    }
}

struct PlaintextScope {
    bytes: Vec<u8>,
    key: u64,
    nonce: u64,
}
impl Drop for PlaintextScope {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

fn crypt(bytes: &mut [u8], key: u64, nonce: u64) {
    let mut state = derive_seed(key, nonce);
    for (i, byte) in bytes.iter_mut().enumerate() {
        if i & 7 == 0 {
            state = derive_seed(state, nonce ^ i as u64);
        }
        *byte ^= (state >> ((i & 7) * 8)) as u8;
    }
}

pub fn scoped_mask_byte(build_key: u64, object_rva: u32, index: u32) -> u8 {
    let object_key = derive_seed(build_key, 0x5343_4F50_4544_4154 ^ object_rva as u64);
    let lane = derive_seed(object_key, (index / 8) as u64);
    (lane >> ((index & 7) * 8)) as u8
}

pub fn toggle_section_object(
    sections: &mut [crate::pe::builder::SectionData],
    object: &LiteralObject,
    build_key: u64,
) -> bool {
    let Some(section) = sections.iter_mut().find(|section| {
        object.rva >= section.virtual_address
            && object.rva.saturating_add(object.len)
                <= section
                    .virtual_address
                    .saturating_add(section.bytes.len() as u32)
    }) else {
        return false;
    };
    let offset = (object.rva - section.virtual_address) as usize;
    for index in 0..object.len as usize {
        section.bytes[offset + index] ^= scoped_mask_byte(build_key, object.rva, index as u32);
    }
    true
}

pub fn section_object_bytes<'a>(
    sections: &'a [crate::pe::builder::SectionData],
    object: &LiteralObject,
) -> Option<&'a [u8]> {
    let section = sections.iter().find(|section| {
        object.rva >= section.virtual_address
            && object.rva.saturating_add(object.len)
                <= section
                    .virtual_address
                    .saturating_add(section.bytes.len() as u32)
    })?;
    let offset = (object.rva - section.virtual_address) as usize;
    Some(&section.bytes[offset..offset + object.len as usize])
}

/// Conservative literal classifier used before relocating selected objects.
pub fn classify_literal(bytes: &[u8]) -> Option<DataClass> {
    if bytes.len() >= 4
        && bytes.len() % 2 == 0
        && bytes
            .chunks_exact(2)
            .all(|u| u[1] == 0 && u[0].is_ascii_graphic())
    {
        return Some(DataClass::Utf16);
    }
    if bytes.len() >= 4
        && bytes
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        return Some(DataClass::Ascii);
    }
    if bytes.len() >= 4 && std::str::from_utf8(bytes).is_ok() {
        return Some(DataClass::Utf8);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{
        BlockEncoder, BlockEncoderOptions, Code, InstructionBlock, MemoryOperand, Register,
    };
    #[test]
    fn secrets_are_absent_at_rest_and_scope_reencrypts() {
        let secret = b"BTG-designated-secret-value";
        let mut object = ProtectedDataObject::protect(DataClass::Utf8, secret, 0xCAFE, 3);
        assert!(!object
            .encrypted_bytes()
            .windows(secret.len())
            .any(|w| w == secret));
        let before = object.encrypted_bytes().to_vec();
        object.with_plaintext(|plain| assert_eq!(plain, secret));
        assert_eq!(object.encrypted_bytes(), before.as_slice());
    }

    #[test]
    fn ascii_utf8_and_wide_literals_are_classified() {
        assert_eq!(classify_literal(b"secret-text"), Some(DataClass::Ascii));
        assert_eq!(
            classify_literal("비밀-data".as_bytes()),
            Some(DataClass::Utf8)
        );
        assert_eq!(classify_literal(b"w\0i\0d\0e\0"), Some(DataClass::Utf16));
    }

    #[test]
    fn reference_graph_keeps_only_directly_referenced_literals() {
        let image_base = 0x1400_0000_0u64;
        let text_rva = 0x1000u32;
        let data_rva = 0x3000u32;
        let mut lea = Instruction::with2(
            Code::Lea_r64_m,
            Register::RCX,
            MemoryOperand::with_base_displ(Register::RIP, (image_base + data_rva as u64) as i64),
        )
        .unwrap();
        lea.set_ip(image_base + text_rva as u64);
        let encoded = BlockEncoder::encode(
            64,
            InstructionBlock::new(&[lea], image_base + text_rva as u64),
            BlockEncoderOptions::NONE,
        )
        .unwrap()
        .code_buffer;
        let data = b"tracked-secret\0unreferenced-secret\0";
        let objects = analyze_referenced_literals(&encoded, text_rva, data, data_rva, image_base);
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].rva, data_rva);
        assert_eq!(objects[0].len, 15);
        assert_eq!(objects[0].references, vec![text_rva]);
    }

    #[test]
    fn reference_graph_adds_exact_width_read_only_constant_pool() {
        let image_base = 0x1400_0000_0u64;
        let text_rva = 0x1000u32;
        let data_rva = 0x3000u32;
        let mut load = Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RIP, (image_base + data_rva as u64) as i64),
        )
        .unwrap();
        load.set_ip(image_base + text_rva as u64);
        let encoded = BlockEncoder::encode(
            64,
            InstructionBlock::new(&[load], image_base + text_rva as u64),
            BlockEncoderOptions::NONE,
        )
        .unwrap()
        .code_buffer;
        let mut decoder = Decoder::with_ip(
            64,
            &encoded,
            image_base + text_rva as u64,
            DecoderOptions::NONE,
        );
        let decoded = decoder.decode();
        assert_eq!(
            decoded.ip_rel_memory_address(),
            image_base + data_rva as u64
        );
        assert_eq!(direct_constant_load_width(&decoded), Some(8));
        let data = [0x13, 0xA7, 0x02, 0xFE, 0x55, 0x91, 0xC4, 0x28];
        let objects = analyze_referenced_literals(&encoded, text_rva, &data, data_rva, image_base);
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].class, DataClass::ConstantPool);
        assert_eq!(objects[0].rva, data_rva);
        assert_eq!(objects[0].len, 8);
        assert_eq!(objects[0].references, vec![text_rva]);
        assert!(is_unwind_safe_direct_reference(
            &decoded,
            &objects[0],
            image_base
        ));
    }

    #[test]
    fn unwind_safe_scope_rejects_lea_call_argument_reference() {
        let image_base = 0x1400_0000_0u64;
        let text_rva = 0x1000u32;
        let data_rva = 0x3000u32;
        let mut lea = Instruction::with2(
            Code::Lea_r64_m,
            Register::RCX,
            MemoryOperand::with_base_displ(Register::RIP, (image_base + data_rva as u64) as i64),
        )
        .unwrap();
        lea.set_ip(image_base + text_rva as u64);
        let encoded = BlockEncoder::encode(
            64,
            InstructionBlock::new(&[lea], image_base + text_rva as u64),
            BlockEncoderOptions::NONE,
        )
        .unwrap()
        .code_buffer;
        let mut decoder = Decoder::with_ip(
            64,
            &encoded,
            image_base + text_rva as u64,
            DecoderOptions::NONE,
        );
        let decoded = decoder.decode();
        let object = LiteralObject {
            class: DataClass::Ascii,
            rva: data_rva,
            len: 8,
            references: vec![text_rva],
        };
        assert_eq!(direct_constant_load_width(&decoded), None);
        assert!(!is_unwind_safe_direct_reference(
            &decoded, &object, image_base
        ));
    }

    #[test]
    fn call_scope_requires_unclobbered_argument_in_straight_line_code() {
        let base = 0x1400_0000_0u64;
        let text_rva = 0x1000;
        let object = LiteralObject {
            class: DataClass::Ascii,
            rva: 0x3000,
            len: 8,
            references: vec![text_rva],
        };
        let instructions = [
            Instruction::with2(
                Code::Lea_r64_m,
                Register::RCX,
                MemoryOperand::with_base_displ(Register::RIP, (base + 0x3000) as i64),
            )
            .unwrap(),
            Instruction::with_branch(Code::Call_rel32_64, base + 0x2000).unwrap(),
        ];
        let code = BlockEncoder::encode(
            64,
            InstructionBlock::new(&instructions, base + text_rva as u64),
            BlockEncoderOptions::NONE,
        )
        .unwrap()
        .code_buffer;
        assert_eq!(
            select_call_scoped_literals(&code, text_rva, base, &[object]).len(),
            1
        );
    }

    #[test]
    fn production_section_toggle_is_ciphertext_at_rest_and_roundtrips() {
        let object = LiteralObject {
            class: DataClass::Ascii,
            rva: 0x2004,
            len: 12,
            references: vec![0x1000],
        };
        let mut section = crate::pe::builder::SectionData {
            name: ".rdata".into(),
            virtual_address: 0x2000,
            virtual_size: 0x100,
            characteristics: 0x4000_0040,
            bytes: b"pad!secret-data\0tail".to_vec(),
        };
        let before = section_object_bytes(std::slice::from_ref(&section), &object)
            .unwrap()
            .to_vec();
        assert!(toggle_section_object(
            std::slice::from_mut(&mut section),
            &object,
            0x1234
        ));
        assert_ne!(
            section_object_bytes(std::slice::from_ref(&section), &object).unwrap(),
            before
        );
        assert!(toggle_section_object(
            std::slice::from_mut(&mut section),
            &object,
            0x1234
        ));
        assert_eq!(
            section_object_bytes(std::slice::from_ref(&section), &object).unwrap(),
            before
        );
    }

    #[test]
    fn legacy_in_stride_sync_table_is_rejected_for_commercial_state() {
        let objects = [
            LiteralObject {
                class: DataClass::Ascii,
                rva: 0x3100,
                len: 8,
                references: vec![0x1100],
            },
            LiteralObject {
                class: DataClass::Utf16,
                rva: 0x3000,
                len: 10,
                references: vec![0x1200],
            },
        ];
        let table = LifetimeSyncTable::build(0x1400_8000_0, 0x1400_0000_0, 7, &objects).unwrap();
        assert!(
            table.validate_stride(0x8000).is_err(),
            "legacy +0x2000 placement overlaps the commercial virtual stack",
        );
        assert_eq!(table.entries[0].object_rva, 0x3000);
        assert_eq!(table.entries[0].lock_va, 0x1400_8200_0);
        assert_eq!(table.entries[0].refcount_va, 0x1400_8200_4);
        assert_eq!(table.entries[0].owner_va, 0x1400_8200_8);
        assert_eq!(table.entries[0].object_va, 0x1400_0300_0);
        assert_eq!(table.entries[1].lock_va, table.entries[0].lock_va + 48);
    }

    #[test]
    fn global_sync_table_exact_base_validates_without_stride_aliasing() {
        let objects = [LiteralObject {
            class: DataClass::Ascii,
            rva: 0x3000,
            len: 8,
            references: vec![0x1100],
        }];
        let base = 0x1401_0000_0;
        let table = LifetimeSyncTable::build_at(base, 0x1400_0000_0, 7, &objects).unwrap();
        table.validate_table().unwrap();
        assert_eq!(table.base_va, base);
        assert_eq!(table.entries[0].lock_va, base);
    }

    #[test]
    fn shared_sync_table_rejects_capacity_overflow() {
        let objects: Vec<_> = (0..=LIFETIME_SYNC_CAPACITY)
            .map(|index| LiteralObject {
                class: DataClass::Ascii,
                rva: 0x3000 + index as u32 * 8,
                len: 8,
                references: vec![0x1000],
            })
            .collect();
        assert!(LifetimeSyncTable::build(0x1400_0000_0, 0x1400_0000_0, 7, &objects).is_err());
    }

    #[test]
    fn production_graph_recognizes_wide_literal_as_one_object() {
        let base = 0x1400_0000_0u64;
        let text_rva = 0x1000;
        let data_rva = 0x3000;
        let instructions = [
            Instruction::with2(
                Code::Lea_r64_m,
                Register::RCX,
                MemoryOperand::with_base_displ(Register::RIP, (base + data_rva as u64) as i64),
            )
            .unwrap(),
            Instruction::with_branch(Code::Call_rel32_64, base + 0x2000).unwrap(),
        ];
        let code = BlockEncoder::encode(
            64,
            InstructionBlock::new(&instructions, base + text_rva as u64),
            BlockEncoderOptions::NONE,
        )
        .unwrap()
        .code_buffer;
        let data = b"w\0i\0d\0e\0\0\0tail\0";
        let objects = analyze_referenced_literals(&code, text_rva, data, data_rva, base);
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].class, DataClass::Utf16);
        assert_eq!(objects[0].len, 10);
        assert_eq!(
            select_call_scoped_literals(&code, text_rva, base, &objects).len(),
            1
        );
    }
}
