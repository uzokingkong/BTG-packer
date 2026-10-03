//! Bootstrap instruction VM for trusted, self-contained crypto IR. Every
//! operation and control transfer dispatches through a bounded program table.
//! This compiler accepts no external calls or indirect native control flow.
use anyhow::{ensure, Result};
use iced_x86::{Code, FlowControl, Instruction as I, MemoryOperand as M, Register as R};
use std::collections::{HashMap, HashSet};

pub(crate) const STATE_SIZE: usize = 16;
pub(crate) struct Blob {
    pub code: Vec<u8>,
    pub program_range: std::ops::Range<usize>,
}
struct Node {
    instruction: I,
    label: Option<String>,
    target: Option<String>,
    rip: Option<String>,
}
fn node(i: I) -> Node {
    Node {
        instruction: i,
        label: None,
        target: None,
        rip: None,
    }
}
fn p(s: &mut Vec<Node>, i: I) {
    s.push(node(i));
}
fn label(s: &mut Vec<Node>, name: &str) {
    let mut n = node(I::with(Code::Nopd));
    n.label = Some(name.into());
    s.push(n);
}
fn branch(s: &mut Vec<Node>, code: Code, name: &str) {
    let mut n = node(I::with_branch(code, 0).unwrap());
    n.target = Some(name.into());
    s.push(n);
}
fn imm(s: &mut Vec<Node>, r: R, value: u64) {
    p(s, I::with2(Code::Mov_r64_imm64, r, value).unwrap());
}
fn lea(s: &mut Vec<Node>, r: R, name: &str) {
    let mut n = node(I::with2(Code::Lea_r64_m, r, M::with_base_displ(R::RIP, 0)).unwrap());
    n.rip = Some(name.into());
    s.push(n);
}
fn state(offset: i64) -> M {
    M::with_base_displ(R::RAX, offset)
}
fn continuation(s: &mut Vec<Node>, state_va: u64, pc: usize) {
    p(s, I::with1(Code::Push_r64, R::RAX).unwrap());
    imm(s, R::RAX, state_va);
    p(
        s,
        I::with2(Code::Mov_rm64_imm32, state(0), pc as i32).unwrap(),
    );
    p(s, I::with1(Code::Pop_r64, R::RAX).unwrap());
}

pub(crate) fn compile(input: &[(I, Option<String>)], state_va: u64) -> Result<Blob> {
    ensure!(
        !input.is_empty() && input.len() <= 65536,
        "crypto VM instruction budget exceeded"
    );
    let mut source_labels = HashMap::new();
    for (pc, (i, l)) in input.iter().enumerate() {
        ensure!(
            !i.is_ip_rel_memory_operand(),
            "crypto VM does not accept source RIP memory"
        );
        if !matches!(
            i.flow_control(),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::Call
        ) {
            if let Some(l) = l {
                source_labels.insert(l.clone(), pc);
            }
        }
    }
    // Determine root returns without descending into local CALL bodies. Their
    // native return continuations must retain the shared execution budget.
    let mut root_returns = HashSet::new();
    let mut visited = HashSet::new();
    let mut pending = vec![0usize];
    while let Some(pc) = pending.pop() {
        if pc >= input.len() || !visited.insert(pc) {
            continue;
        }
        let (instruction, target) = &input[pc];
        match instruction.flow_control() {
            FlowControl::Return => {
                root_returns.insert(pc);
            }
            FlowControl::Exception => {}
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                let target = target
                    .as_ref()
                    .and_then(|name| source_labels.get(name))
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("crypto VM unresolved root branch"))?;
                pending.push(target);
                if instruction.flow_control() == FlowControl::ConditionalBranch {
                    pending.push(pc + 1);
                }
            }
            _ => pending.push(pc + 1),
        }
    }
    let mut s = Vec::new();
    label(&mut s, "vm_base");
    p(&mut s, I::with(Code::Pushfq));
    for r in [R::RAX, R::RCX] {
        p(&mut s, I::with1(Code::Push_r64, r).unwrap());
    }
    imm(&mut s, R::RAX, state_va);
    p(&mut s, I::with2(Code::Mov_rm64_imm32, state(0), 0).unwrap());
    p(
        &mut s,
        I::with2(Code::Mov_r64_rm64, R::RCX, R::RDX).unwrap(),
    );
    p(&mut s, I::with2(Code::Shl_rm64_imm8, R::RCX, 10).unwrap());
    p(
        &mut s,
        I::with2(Code::Add_rm64_imm32, R::RCX, 8192).unwrap(),
    );
    p(
        &mut s,
        I::with2(Code::Mov_rm64_r64, state(8), R::RCX).unwrap(),
    );
    for r in [R::RCX, R::RAX] {
        p(&mut s, I::with1(Code::Pop_r64, r).unwrap());
    }
    p(&mut s, I::with(Code::Popfq));
    label(&mut s, "vm_fetch");
    p(&mut s, I::with(Code::Pushfq));
    for r in [R::RAX, R::RCX, R::RDX] {
        p(&mut s, I::with1(Code::Push_r64, r).unwrap());
    }
    p(&mut s, I::with2(Code::Sub_rm64_imm32, R::RSP, 8).unwrap());
    imm(&mut s, R::RAX, state_va);
    p(&mut s, I::with2(Code::Cmp_rm64_imm32, state(8), 0).unwrap());
    branch(&mut s, Code::Je_rel32_64, "vm_fail");
    p(&mut s, I::with1(Code::Dec_rm64, state(8)).unwrap());
    p(
        &mut s,
        I::with2(Code::Mov_r64_rm64, R::RCX, state(0)).unwrap(),
    );
    p(
        &mut s,
        I::with2(Code::Cmp_rm64_imm32, R::RCX, input.len() as i32).unwrap(),
    );
    branch(&mut s, Code::Jae_rel32_64, "vm_fail");
    lea(&mut s, R::RDX, "vm_program");
    p(
        &mut s,
        I::with2(
            Code::Movsxd_r64_rm32,
            R::RCX,
            M::new(R::RDX, R::RCX, 4, 0, 0, false, R::None),
        )
        .unwrap(),
    );
    lea(&mut s, R::RDX, "vm_base");
    p(
        &mut s,
        I::with2(Code::Add_rm64_r64, R::RCX, R::RDX).unwrap(),
    );
    p(
        &mut s,
        I::with2(Code::Mov_rm64_r64, M::with_base(R::RSP), R::RCX).unwrap(),
    );
    // Restore the guest image and jump through a checked dispatch target. The
    // target occupies the saved-flags slot; guest RSP is exact at handler entry.
    for (r, off) in [(R::RDX, 8), (R::RCX, 16), (R::RAX, 24)] {
        p(
            &mut s,
            I::with2(Code::Mov_r64_rm64, r, M::with_base_displ(R::RSP, off)).unwrap(),
        );
    }
    p(
        &mut s,
        I::with1(Code::Push_rm64, M::with_base_displ(R::RSP, 32)).unwrap(),
    );
    p(&mut s, I::with(Code::Popfq));
    // Copy the target without clobbering restored registers.
    p(
        &mut s,
        I::with1(Code::Push_rm64, M::with_base(R::RSP)).unwrap(),
    );
    p(
        &mut s,
        I::with1(Code::Pop_rm64, M::with_base_displ(R::RSP, 32)).unwrap(),
    );
    p(
        &mut s,
        I::with2(Code::Lea_r64_m, R::RSP, M::with_base_displ(R::RSP, 40)).unwrap(),
    );
    p(
        &mut s,
        I::with1(Code::Jmp_rm64, M::with_base_displ(R::RSP, -8)).unwrap(),
    );
    label(&mut s, "vm_fail");
    p(&mut s, I::with2(Code::Mov_rm64_imm32, state(0), 0).unwrap());
    p(&mut s, I::with2(Code::Mov_rm64_imm32, state(8), 0).unwrap());
    p(&mut s, I::with(Code::Ud2));
    for (pc, (i, target)) in input.iter().enumerate() {
        label(&mut s, &format!("h{pc}"));
        match i.flow_control() {
            FlowControl::ConditionalBranch
            | FlowControl::UnconditionalBranch
            | FlowControl::Call => {
                let destination = target
                    .as_ref()
                    .and_then(|name| source_labels.get(name))
                    .copied()
                    .ok_or_else(|| {
                        anyhow::anyhow!("crypto VM unresolved native control at {pc}")
                    })?;
                if i.flow_control() == FlowControl::ConditionalBranch {
                    branch(&mut s, i.code(), &format!("taken{pc}"));
                    continuation(&mut s, state_va, pc + 1);
                    branch(&mut s, Code::Jmp_rel32_64, "vm_fetch");
                    label(&mut s, &format!("taken{pc}"));
                    continuation(&mut s, state_va, destination);
                    branch(&mut s, Code::Jmp_rel32_64, "vm_fetch");
                } else if i.flow_control() == FlowControl::Call {
                    continuation(&mut s, state_va, destination);
                    branch(&mut s, Code::Call_rel32_64, "vm_fetch");
                    continuation(&mut s, state_va, pc + 1);
                    branch(&mut s, Code::Jmp_rel32_64, "vm_fetch");
                } else {
                    continuation(&mut s, state_va, destination);
                    branch(&mut s, Code::Jmp_rel32_64, "vm_fetch");
                }
            }
            FlowControl::Next => {
                ensure!(
                    pc + 1 < input.len(),
                    "crypto VM source falls past its instruction region"
                );
                p(&mut s, *i);
                continuation(&mut s, state_va, pc + 1);
                branch(&mut s, Code::Jmp_rel32_64, "vm_fetch");
            }
            FlowControl::Return => {
                if root_returns.contains(&pc) {
                    p(&mut s, I::with1(Code::Push_r64, R::RAX).unwrap());
                    imm(&mut s, R::RAX, state_va);
                    p(&mut s, I::with2(Code::Mov_rm64_imm32, state(0), 0).unwrap());
                    p(&mut s, I::with2(Code::Mov_rm64_imm32, state(8), 0).unwrap());
                    p(&mut s, I::with1(Code::Pop_r64, R::RAX).unwrap());
                }
                p(&mut s, *i);
            }
            FlowControl::Exception => p(&mut s, *i),
            _ => anyhow::bail!("crypto VM unsupported native control at {pc}"),
        }
    }
    let table_index = s.len();
    for pc in 0..input.len() {
        let mut n = node(I::with_declare_byte(&[0; 4]).unwrap());
        if pc == 0 {
            n.label = Some("vm_program".into());
        }
        s.push(n);
    }
    let opts = iced_x86::BlockEncoderOptions::DONT_FIX_BRANCHES;
    let mut ips = Vec::new();
    let mut labels = HashMap::new();
    let mut ip = 0u64;
    for n in &s {
        if let Some(name) = &n.label {
            labels.insert(name.clone(), ip);
        }
        ips.push(ip);
        let mut instruction = n.instruction;
        instruction.set_ip(ip);
        if n.target.is_some() {
            instruction.set_near_branch64(ip);
        }
        if n.rip.is_some() {
            instruction.set_memory_displacement64(ip);
        }
        let arr = [instruction];
        ip += iced_x86::BlockEncoder::encode(64, iced_x86::InstructionBlock::new(&arr, ip), opts)?
            .code_buffer
            .len() as u64;
    }
    ensure!(ip < 1024 * 1024, "crypto VM native module budget exceeded");
    let program_start = ips[table_index] as usize;
    for pc in 0..input.len() {
        let offset = labels[&format!("h{pc}")] as i32;
        s[table_index + pc].instruction = I::with_declare_byte(&offset.to_le_bytes()).unwrap();
    }
    let mut code = Vec::new();
    for (n, ip) in s.iter().zip(ips) {
        let mut instruction = n.instruction;
        instruction.set_ip(ip);
        if let Some(target) = &n.target {
            instruction.set_near_branch64(labels[target]);
        }
        if let Some(target) = &n.rip {
            instruction.set_memory_displacement64(labels[target]);
        }
        let arr = [instruction];
        code.extend(
            iced_x86::BlockEncoder::encode(64, iced_x86::InstructionBlock::new(&arr, ip), opts)?
                .code_buffer,
        );
    }
    Ok(Blob {
        code,
        program_range: program_start..program_start + input.len() * 4,
    })
}
