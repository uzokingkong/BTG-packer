

// ==============================================================================
// C-1 fix (switch jump-table resolution):  resolve `Jmp_rm64` jump-table
// terminators in the original program so they dispatch *inside the VM*
// (compare-and-jump chain) instead of falling back to the native bridge,
// which jumped into the middle of an original function at a case-label
// address (where the enclosing function's prologue — e.g. `lea rbx,[table]` —
// never ran), causing 0xC0000005 on the exit path.
// ==============================================================================

use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};

/// Read `len` bytes from the original image at absolute VA `va`.
fn read_image(relayed: &[crate::pe::builder::SectionData], image_base: u64, va: u64, len: usize) -> Option<Vec<u8>> {
    for s in relayed {
        let start = image_base + s.virtual_address as u64;
        if va >= start && va + len as u64 <= start + s.bytes.len() as u64 {
            let off = (va - start) as usize;
            return Some(s.bytes[off..off + len].to_vec());
        }
    }
    None
}
fn read_u32(relayed: &[crate::pe::builder::SectionData], image_base: u64, va: u64) -> Option<u32> {
    read_image(relayed, image_base, va, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}
fn read_u64(relayed: &[crate::pe::builder::SectionData], image_base: u64, va: u64) -> Option<u64> {
    read_image(relayed, image_base, va, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Absolute target of a RIP-relative `lea` (or a `mov r64,imm64` absolute load).
fn lea_target(inst: &iced_x86::Instruction) -> Option<u64> {
    match inst.code() {
        Code::Lea_r64_m | Code::Lea_r32_m if inst.is_ip_rel_memory_operand() => {
            Some(inst.memory_displacement64())
        }
        Code::Mov_r64_imm64 => Some(inst.immediate64()),
        _ => None,
    }
}

/// Resolve switch jump-tables in the original program.
///
/// Returns `Vec<(jmp_inst_va, idx_vreg, Vec<(case_value, target_block_va)>)>`
/// where `idx_vreg` is the VM vreg number of the index register used to select
/// the jump-table entry. Case targets that fall outside the lifted `.text`
/// range are dropped.
pub fn resolve_switch_cases(
    text_bytes: &[u8],
    base_va: u64,
    relayed: &[crate::pe::builder::SectionData],
    image_base: u64,
) -> Vec<(u64, u8, Vec<(i64, u64)>)> {
    let text_end = base_va + text_bytes.len() as u64;
    let mut dec = Decoder::with_ip(64, text_bytes, base_va, DecoderOptions::NONE);
    let mut insts: Vec<iced_x86::Instruction> = Vec::new();
    while dec.can_decode() {
        let i = dec.decode();
        insts.push(i);
    }
    let mut last_def: [Option<usize>; 16] = [None; 16];
    let mut out = Vec::new();
    fn reg_idx(r: Register) -> Option<usize> {
        if r.is_gpr() { Some(r.full_register().number() as usize) } else { None }
    }
    for (i, inst) in insts.iter().enumerate() {
        if inst.code() == Code::Jmp_rm64 {
            resolve_one(&insts, &last_def, i, &mut out, relayed, image_base, base_va, text_end);
        }
        if inst.op0_kind() == OpKind::Register {
            if let Some(ri) = reg_idx(inst.op0_register()) {
                last_def[ri] = Some(i);
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn resolve_one(
    insts: &[iced_x86::Instruction],
    last_def: &[Option<usize>; 16],
    i: usize,
    out: &mut Vec<(u64, u8, Vec<(i64, u64)>)>,
    relayed: &[crate::pe::builder::SectionData],
    image_base: u64,
    base_va: u64,
    text_end: u64,
) {
    fn reg_idx(r: Register) -> Option<usize> {
        if r.is_gpr() { Some(r.full_register().number() as usize) } else { None }
    }
    let inst = &insts[i];
    let jmp_va = inst.ip();
    let mut key_va = inst.ip();
    let mut idx_reg = Register::None;
    let mut table = None;
    let mut scale = 0u32;
    let mut relative = false;

    if inst.op0_kind() == OpKind::Memory {
        idx_reg = if inst.memory_index() != Register::None { inst.memory_index() } else { inst.memory_base() };
        if idx_reg == Register::None { return; }
        scale = inst.memory_index_scale();
        table = if inst.is_ip_rel_memory_operand() {
            Some(inst.memory_displacement64())
        } else {
            let base_reg = inst.memory_base();
            match reg_idx(base_reg) {
                Some(ri) => match last_def[ri] {
                    Some(j) => lea_target(&insts[j]),
                    None => None,
                },
                None => None,
            }
        };
    } else if inst.op0_kind() == OpKind::Register {
        let tgt_reg = inst.op0_register();
        let ti = reg_idx(tgt_reg).unwrap_or(0);
        let mut li = match last_def[ti] { Some(li) => li, None => return };
        // If the last def of the jmp target is an `add rT,rX` (the relative jump-table
        // idiom `...movsxd rT,[rB+rI*4]; add rT,rB; jmp rT`), the load is one step back.
        let ld0 = &insts[li];
        if matches!(ld0.code(), Code::Add_r64_rm64 | Code::Add_rm64_r64)
            && ld0.op0_kind() == OpKind::Register
            && ld0.op0_register() == tgt_reg
        {
            relative = true;
            if li == 0 { return; }
            li -= 1;
        }
        let ld = &insts[li];
        let is_load = matches!(ld.code(), Code::Movsxd_r64_rm32 | Code::Mov_r64_rm64 | Code::Mov_r32_rm32);
        if !is_load || ld.op1_kind() != OpKind::Memory { return; }
        relative = relative || matches!(ld.code(), Code::Movsxd_r64_rm32);
        idx_reg = if ld.memory_index() != Register::None { ld.memory_index() } else { ld.memory_base() };
        if idx_reg == Register::None { return; }
        scale = ld.memory_index_scale();
        // key the switch on the LOAD (index is still valid here); the jmp rT then
        // falls through to the native bridge only for the "no case matched" default.
        key_va = ld.ip();
        if ld.is_ip_rel_memory_operand() {
            table = lea_target(ld);
        } else {
            let base_reg = ld.memory_base();
            table = match reg_idx(base_reg) {
                Some(ri) => match last_def[ri] {
                    Some(j) => lea_target(&insts[j]),
                    None => None,
                },
                None => None,
            };
        }
    } else {
        return;
    }

    let table = match table { Some(t) => t, None => return };
    if scale != 4 && scale != 8 { return; }
    let Ok(idx_vreg) = crate::vm::lifter::vreg(idx_reg) else { return };
    let mut cases = Vec::new();
    let mut idx = 0i64;
    loop {
        let entry_va = table.wrapping_add((idx as u64).wrapping_mul(scale as u64));
        let target = if relative {
            read_u32(relayed, image_base, entry_va).map(|v| table.wrapping_add((v as i32 as i64) as u64))
        } else if scale == 8 {
            read_u64(relayed, image_base, entry_va)
        } else {
            read_u32(relayed, image_base, entry_va).map(|v| v as u64)
        };
        match target {
            Some(t) if t >= base_va && t < text_end => { cases.push((idx, t)); idx += 1; }
            _ => break,
        }
        if idx > 4096 { break; }
    }
    if !cases.is_empty() {
        out.push((key_va, idx_vreg, cases));
    }
}
