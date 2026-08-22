//! Object-granular encrypted data with decrypt/use/re-encrypt lifetime control.

use crate::vm::seed_lifecycle::derive_seed;

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
}
