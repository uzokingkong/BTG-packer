use std::cell::RefCell;
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;

static GLOBAL_STATIC_COUNTER: AtomicU64 = AtomicU64::new(0x1337733113377331);
static INIT_ONCE: Once = Once::new();

struct TlsTracker {
    value: u64,
}

impl Drop for TlsTracker {
    fn drop(&mut self) {
        GLOBAL_STATIC_COUNTER.fetch_add(self.value, Ordering::SeqCst);
    }
}

thread_local! {
    static THREAD_DATA: RefCell<TlsTracker> = RefCell::new(TlsTracker { value: 0x42424242 });
}

#[inline(never)]
pub fn stage_tls_and_statics(seed: u64) -> u64 {
    INIT_ONCE.call_once(|| {
        GLOBAL_STATIC_COUNTER.fetch_xor(0xAAAAAAAA_55555555, Ordering::SeqCst);
    });

    THREAD_DATA.with(|tls| {
        let mut tracker = tls.borrow_mut();
        tracker.value = tracker.value.rotate_left(17) ^ seed;
    });

    let current_global = GLOBAL_STATIC_COUNTER.load(Ordering::SeqCst);

    let tls_val = THREAD_DATA.with(|tls| {
        tls.borrow().value
    });

    let result = current_global ^ tls_val.wrapping_mul(0x9E3779B185EBCA87);
    black_box(result)
}
