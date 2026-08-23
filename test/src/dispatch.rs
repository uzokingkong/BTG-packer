use std::hint::black_box;

pub enum Operation {
    Add,
    Subtract,
    Xor,
    Multiply,
    Rotate,
    Mix,
    Fold,
    Final,
}

pub trait Executor {
    fn execute(&self, value: u64, arg: u64) -> u64;
}

struct AddExecutor;
struct XorExecutor;
struct RotateExecutor;
struct MultiplyExecutor;

impl Executor for AddExecutor {
    #[inline(never)]
    fn execute(&self, value: u64, arg: u64) -> u64 {
        value.wrapping_add(arg)
    }
}

impl Executor for XorExecutor {
    #[inline(never)]
    fn execute(&self, value: u64, arg: u64) -> u64 {
        value ^ arg.rotate_left(13)
    }
}

impl Executor for RotateExecutor {
    #[inline(never)]
    fn execute(&self, value: u64, arg: u64) -> u64 {
        value.rotate_left((arg % 63) as u32 + 1)
    }
}

impl Executor for MultiplyExecutor {
    #[inline(never)]
    fn execute(&self, value: u64, arg: u64) -> u64 {
        value.wrapping_mul(arg | 1)
    }
}

#[inline(never)]
pub fn dispatcher(
    operation: Operation,
    value: u64,
    arg: u64,
) -> u64 {
    let result = match operation {
        Operation::Add => {
            let e = AddExecutor;
            e.execute(value, arg)
        }

        Operation::Subtract => {
            value.wrapping_sub(arg)
        }

        Operation::Xor => {
            let e = XorExecutor;
            e.execute(value, arg)
        }

        Operation::Multiply => {
            let e = MultiplyExecutor;
            e.execute(value, arg)
        }

        Operation::Rotate => {
            let e = RotateExecutor;
            e.execute(value, arg)
        }

        Operation::Mix => {
            let x = value ^ arg;
            x.rotate_left(17)
                .wrapping_mul(0x9E3779B1)
        }

        Operation::Fold => {
            value ^ (value >> 32)
        }

        Operation::Final => {
            !value ^ 0xDEADC0DECAFEBABE
        }
    };

    black_box(result)
}