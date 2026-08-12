use std::hint::black_box;

#[derive(Clone, Copy)]
enum State {
    Init,
    Add,
    Xor,
    Rotate,
    Multiply,
    Fold,
    Finish,
}

pub struct MachineState {
    value: u64,
    state: State,
}

impl MachineState {
    #[inline(never)]
    pub fn new(value: u64) -> Self {
        Self {
            value,
            state: State::Init,
        }
    }

    #[inline(never)]
    pub fn step(&mut self, tick: u32) {
        self.state = match (self.state, tick % 6) {
            (State::Init, _) => State::Add,

            (State::Add, 0) => State::Xor,
            (State::Add, _) => State::Add,

            (State::Xor, _) => State::Rotate,

            (State::Rotate, _) => State::Multiply,

            (State::Multiply, t) if t & 1 == 0 => State::Fold,
            (State::Multiply, _) => State::Xor,

            (State::Fold, _) => State::Finish,

            (State::Finish, _) => State::Add,
        };

        match self.state {
            State::Init => {
                self.value ^= 0x1111;
            }

            State::Add => {
                self.value = self.value.wrapping_add(
                    0x1000 + tick as u64,
                );
            }

            State::Xor => {
                self.value ^= 0xA5A5A5A5A5A5A5A5;
            }

            State::Rotate => {
                self.value =
                    self.value.rotate_left((tick % 63) + 1);
            }

            State::Multiply => {
                self.value = self.value.wrapping_mul(3);
            }

            State::Fold => {
                self.value ^= self.value >> 32;
            }

            State::Finish => {
                self.value = self.value
                    .wrapping_add(0xDEADBEEF);
            }
        }

        black_box(self.value);
    }

    #[inline(never)]
    pub fn finish(self) -> u64 {
        black_box(
            self.value
                ^ self.value.rotate_right(17),
        )
    }
}