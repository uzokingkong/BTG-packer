use std::hint::black_box;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[inline(never)]
fn fragile_calculation(input: u64) -> u64 {
    if input & 1 == 0 {
        panic!("panicked at fragile calculation SEH test");
    }
    input.wrapping_mul(0xDEADBEEF)
}

#[inline(never)]
pub fn stage_exceptions(seed: u64) -> u64 {
    let _sig = black_box("panicked at stage_exceptions");
    // Temporarily suppress default panic printing to keep console clean
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let mut result_acc = seed;

    for i in 0..6u64 {
        let val = seed.wrapping_add(i);
        let res = catch_unwind(AssertUnwindSafe(|| {
            fragile_calculation(val)
        }));

        match res {
            Ok(output) => {
                result_acc ^= output.rotate_left(7);
            }
            Err(_) => {
                // Recovered from intentional panic!
                result_acc = result_acc.wrapping_add(0xCAFEBABE13377331 ^ i);
            }
        }
    }

    // Restore original panic hook
    std::panic::set_hook(orig_hook);

    black_box(result_acc)
}
