use std::hint::black_box;

pub struct MiniVM {
    registers: [u64; 8],
    stack: Vec<u64>,
    ip: usize,
}

impl MiniVM {
    pub fn new() -> Self {
        Self {
            registers: [0; 8],
            stack: Vec::with_capacity(64),
            ip: 0,
        }
    }

    #[inline(never)]
    pub fn execute(&mut self, code: &[u8]) -> u64 {
        self.ip = 0;

        while self.ip < code.len() {
            let opcode = code[self.ip];
            self.ip += 1;

            match opcode {
                0x00 => break, // HALT
                0x01 => {
                    // PUSH_CONST u64
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&code[self.ip..self.ip + 8]);
                    self.ip += 8;
                    let val = u64::from_le_bytes(bytes);
                    self.stack.push(val);
                }
                0x02 => {
                    // POP
                    self.stack.pop();
                }
                0x03 => {
                    // ADD
                    let b = self.stack.pop().unwrap_or(0);
                    let a = self.stack.pop().unwrap_or(0);
                    self.stack.push(a.wrapping_add(b));
                }
                0x04 => {
                    // SUB
                    let b = self.stack.pop().unwrap_or(0);
                    let a = self.stack.pop().unwrap_or(0);
                    self.stack.push(a.wrapping_sub(b));
                }
                0x05 => {
                    // XOR
                    let b = self.stack.pop().unwrap_or(0);
                    let a = self.stack.pop().unwrap_or(0);
                    self.stack.push(a ^ b);
                }
                0x06 => {
                    // ROL u8
                    let shift = code[self.ip] as u32;
                    self.ip += 1;
                    let val = self.stack.pop().unwrap_or(0);
                    self.stack.push(val.rotate_left(shift));
                }
                0x07 => {
                    // MUL_PRIME
                    let val = self.stack.pop().unwrap_or(0);
                    self.stack.push(val.wrapping_mul(0x9E3779B185EBCA87));
                }
                0x08 => {
                    // DUP
                    if let Some(&top) = self.stack.last() {
                        self.stack.push(top);
                    }
                }
                0x09 => {
                    // STORE_REG u8
                    let reg = code[self.ip] as usize & 7;
                    self.ip += 1;
                    let val = self.stack.pop().unwrap_or(0);
                    self.registers[reg] = val;
                }
                0x0A => {
                    // LOAD_REG u8
                    let reg = code[self.ip] as usize & 7;
                    self.ip += 1;
                    self.stack.push(self.registers[reg]);
                }
                0x0B => {
                    // JMP target_u16
                    let target = u16::from_le_bytes([code[self.ip], code[self.ip + 1]]) as usize;
                    self.ip = target;
                }
                0x0C => {
                    // JMP_IF_ZERO target_u16
                    let target = u16::from_le_bytes([code[self.ip], code[self.ip + 1]]) as usize;
                    self.ip += 2;
                    let val = self.stack.pop().unwrap_or(0);
                    if val == 0 {
                        self.ip = target;
                    }
                }
                _ => {}
            }
        }

        let mut res = self.stack.pop().unwrap_or(0);
        for &r in &self.registers {
            res ^= r.rotate_right(13);
        }

        black_box(res)
    }
}

#[inline(never)]
pub fn stage_mini_vm(seed: u64) -> u64 {
    let mut bytecode = Vec::new();

    // Push seed as constant
    bytecode.push(0x01);
    bytecode.extend_from_slice(&seed.to_le_bytes());

    // STORE_REG 0
    bytecode.push(0x09);
    bytecode.push(0x00);

    // Push loop counter 16
    bytecode.push(0x01);
    bytecode.extend_from_slice(&16u64.to_le_bytes());

    // STORE_REG 1 (counter)
    bytecode.push(0x09);
    bytecode.push(0x01);

    // LOOP_HEAD (offset 23)
    let loop_head = bytecode.len() as u16;

    // LOAD_REG 0
    bytecode.push(0x0A);
    bytecode.push(0x00);

    // Push constant 0x1337
    bytecode.push(0x01);
    bytecode.extend_from_slice(&0x1337u64.to_le_bytes());

    // XOR
    bytecode.push(0x05);

    // ROL 7
    bytecode.push(0x06);
    bytecode.push(7);

    // MUL_PRIME
    bytecode.push(0x07);

    // STORE_REG 0
    bytecode.push(0x09);
    bytecode.push(0x00);

    // Decrement counter: LOAD_REG 1, Push 1, SUB, DUP, STORE_REG 1
    bytecode.push(0x0A);
    bytecode.push(0x01);
    bytecode.push(0x01);
    bytecode.extend_from_slice(&1u64.to_le_bytes());
    bytecode.push(0x04);
    bytecode.push(0x08); // DUP
    bytecode.push(0x09);
    bytecode.push(0x01);

    // JMP_IF_ZERO -> EXIT (target will be added)
    bytecode.push(0x0C);
    let jmp_patch_idx = bytecode.len();
    bytecode.push(0); // placeholder
    bytecode.push(0);

    // JMP loop_head
    bytecode.push(0x0B);
    bytecode.extend_from_slice(&loop_head.to_le_bytes());

    // EXIT
    let exit_offset = bytecode.len() as u16;
    let bytes = exit_offset.to_le_bytes();
    bytecode[jmp_patch_idx] = bytes[0];
    bytecode[jmp_patch_idx + 1] = bytes[1];

    // Push final LOAD_REG 0
    bytecode.push(0x0A);
    bytecode.push(0x00);

    // HALT
    bytecode.push(0x00);

    let mut vm = MiniVM::new();
    let result = vm.execute(&bytecode);
    black_box(result)
}
