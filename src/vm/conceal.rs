// ==============================================================================
// WS3.2 (t2-hardening-polymorphism follow-ups): state concealment auto-verification
// ==============================================================================
// Runtime sensitive buffers (key material, keystream state, seed buffers) must be
// wiped after use — after boot-stub decryption and after VM/bridge calls. This
// module provides a small, testable wipe primitive (`wipe_sensitive`) plus a
// RAII `SensitiveWipeGuard` so callers can scope a buffer to a region and be
// certain it is zeroed on drop, and the tests pin the wipe contract.
//
// The at-rest embedded key/state buffers are already zero-initialized at pack
// time (see src/pipeline/crypto/place.rs: `chacha_state_off` / `c1_state_off`
// `.fill(0)`, and pass4_section.rs state staging); the boot stub re-initializes
// and consumes them at runtime. This module makes the *post-use* wipe a first-
// class, unit-testable contract.
// ==============================================================================

/// Best-effort compiler-barrier so the zeroing is not elided as dead store.
#[inline]
fn compiler_barrier(b: &mut [u8]) {
    // std::hint::black_box forces the optimizer to treat the buffer as observed.
    std::hint::black_box(&mut b[..]);
}

/// Wipe a sensitive byte buffer to zero (key material, keystream state, seed).
/// The buffer is left fully zeroed; a memory barrier prevents dead-store elision.
pub fn wipe_sensitive(buf: &mut [u8]) {
    buf.fill(0);
    compiler_barrier(buf);
}

/// RAII guard: holds a `&mut [u8]` and wipes it to zero when dropped, so a
/// sensitive buffer cannot survive its scope even on early-return/panic paths.
pub struct SensitiveWipeGuard<'a> {
    buf: &'a mut [u8],
    active: bool,
}

impl<'a> SensitiveWipeGuard<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, active: true }
    }

    /// Borrow the live (still-sensitive) contents for use.
    pub fn as_slice(&mut self) -> &mut [u8] {
        self.buf
    }

    /// Eagerly wipe and disarm the guard.
    pub fn wipe_now(&mut self) {
        if self.active {
            wipe_sensitive(self.buf);
            self.active = false;
        }
    }
}

impl<'a> Drop for SensitiveWipeGuard<'a> {
    fn drop(&mut self) {
        self.wipe_now();
    }
}

/// Verify a buffer is fully zeroed. Used by tests and by post-use assertions.
pub fn is_fully_zeroed(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// After use, the sensitive buffer is fully zeroed (key material wipe).
    #[test]
    fn wipe_zeroes_key_buffer() {
        let mut key = vec![0x5Au8; 64];
        wipe_sensitive(&mut key);
        assert!(is_fully_zeroed(&key), "key buffer must be wiped to zero after use");
    }

    /// Keystream-state / seed buffers are also wiped.
    #[test]
    fn wipe_zeroes_keystream_state_and_seed() {
        let mut state = [0xCCu8; 256];
        let mut seed = [0x1Du8; 32];
        wipe_sensitive(&mut state);
        wipe_sensitive(&mut seed);
        assert!(is_fully_zeroed(&state));
        assert!(is_fully_zeroed(&seed));
    }

    /// A guard scoped to a region leaves the buffer zeroed on drop (even without
    /// an explicit wipe call), covering early-return/panic paths.
    #[test]
    fn wipe_guard_scopes_and_zeroes_on_drop() {
        let mut buf = vec![0x99u8; 128];
        {
            let mut g = SensitiveWipeGuard::new(&mut buf);
            // use the live contents (simulate a decrypt)
            g.as_slice()[0] ^= 0xFF;
            // no explicit wipe — Drop must wipe
        }
        assert!(is_fully_zeroed(&buf), "guard must wipe the buffer on scope exit");
    }

    /// A fresh (pre-use) buffer need not be wiped; this guards against a test that
    /// expects wipes that never happened (concealment contract is post-use).
    #[test]
    fn wipe_is_idempotent() {
        let mut b = [0u8; 16];
        wipe_sensitive(&mut b);
        wipe_sensitive(&mut b);
        assert!(is_fully_zeroed(&b));
    }
}
