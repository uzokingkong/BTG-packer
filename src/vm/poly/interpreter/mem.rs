// ==============================================================================
// BTG - Polymorphic Interpreter: memory primitives - split from interpreter.rs
// ==============================================================================

use std::collections::HashMap;

/// 리틀엔디언 `width`바이트 메모리 읽기. 미기입 주소는 0으로 취급.
/// `src/vm/risc/mod.rs::mem_read`과 동일.
pub(crate) fn mem_read(mem: &HashMap<u64, u8>, addr: u64, width: u8) -> u64 {
    let mut v = 0u64;
    for i in 0..width {
        if let Some(&b) = mem.get(&addr.wrapping_add(i as u64)) {
            v |= (b as u64) << (i as u64 * 8);
        }
    }
    v
}

/// 리틀엔디언 `width`바이트 메모리 쓰기. `src/vm/risc/mod.rs::mem_write`과 동일.
pub(crate) fn mem_write(mem: &mut HashMap<u64, u8>, addr: u64, width: u8, val: u64) {
    for i in 0..width {
        mem.insert(addr.wrapping_add(i as u64), (val >> (i as u64 * 8)) as u8);
    }
}
