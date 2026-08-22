//! Object-granular encrypted data with decrypt/use/re-encrypt lifetime control.

use crate::vm::seed_lifecycle::derive_seed;
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, Register};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteralObject {
    pub class: DataClass,
    pub rva: u32,
    pub len: u32,
    pub references: Vec<u32>,
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
    if candidates.is_empty() {
        return candidates;
    }

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
        }
    }
    candidates.retain(|object| !object.references.is_empty());
    for object in &mut candidates {
        object.references.sort_unstable();
        object.references.dedup();
    }
    candidates
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
}
