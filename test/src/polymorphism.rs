use std::hint::black_box;

pub trait TransformStage {
    fn name(&self) -> &'static str;
    fn process(&self, input: u64) -> u64;
}

struct RotateAddStage {
    shift: u32,
    constant: u64,
}

impl TransformStage for RotateAddStage {
    fn name(&self) -> &'static str {
        "RotateAdd"
    }

    #[inline(never)]
    fn process(&self, input: u64) -> u64 {
        input.rotate_left(self.shift).wrapping_add(self.constant)
    }
}

struct XorMixStage {
    mask: u64,
}

impl TransformStage for XorMixStage {
    fn name(&self) -> &'static str {
        "XorMix"
    }

    #[inline(never)]
    fn process(&self, input: u64) -> u64 {
        (input ^ self.mask).wrapping_mul(0x9E3779B185EBCA87)
    }
}

struct ConditionalFoldStage {
    threshold: u64,
}

impl TransformStage for ConditionalFoldStage {
    fn name(&self) -> &'static str {
        "ConditionalFold"
    }

    #[inline(never)]
    fn process(&self, input: u64) -> u64 {
        if input > self.threshold {
            input ^ (input >> 16)
        } else {
            input.wrapping_add(0x1337)
        }
    }
}

#[inline(never)]
fn fn_ptr_op1(x: u64) -> u64 { x.wrapping_mul(3) }
#[inline(never)]
fn fn_ptr_op2(x: u64) -> u64 { x.rotate_right(11) }
#[inline(never)]
fn fn_ptr_op3(x: u64) -> u64 { x ^ 0xAAAAAAAAAAAAAAAA }
#[inline(never)]
fn fn_ptr_op4(x: u64) -> u64 { !x }

#[inline(never)]
pub fn stage_polymorphism(seed: u64) -> u64 {
    // 1. Dynamic Vtable Dispatch Chain
    let pipeline: Vec<Box<dyn TransformStage>> = vec![
        Box::new(RotateAddStage { shift: 13, constant: 0x41414141 }),
        Box::new(XorMixStage { mask: 0x5A5A5A5A5A5A5A5A }),
        Box::new(ConditionalFoldStage { threshold: 0x7FFFFFFFFFFFFFFF }),
        Box::new(RotateAddStage { shift: 27, constant: 0xDEADBEEF }),
    ];

    let mut current = seed;

    for stage in &pipeline {
        current = stage.process(current);
        black_box(stage.name());
    }

    // 2. Closure Combinators & State Capture
    let mut captured_state = 0x123456789ABCDEF0u64;
    let mut closure_chain = |val: u64| -> u64 {
        captured_state ^= val;
        captured_state = captured_state.rotate_left(9).wrapping_add(val);
        captured_state
    };

    for i in 0..5 {
        current = closure_chain(current ^ (i as u64));
    }

    // 3. Function Pointer Array Dispatch
    let fn_table: [fn(u64) -> u64; 4] = [
        fn_ptr_op1,
        fn_ptr_op2,
        fn_ptr_op3,
        fn_ptr_op4,
    ];

    for (idx, func) in fn_table.iter().enumerate() {
        current = func(current ^ (idx as u64));
    }

    black_box(current)
}
