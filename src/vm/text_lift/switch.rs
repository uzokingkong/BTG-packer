// ==============================================================================
// C-1 fix (switch jump-table resolution):  resolve `Jmp_rm64` jump-table
// terminators in the original program so they dispatch *inside the VM*
// (compare-and-jump chain) instead of falling back to the native bridge,
// which jumped into the middle of an original function at a case-label
// address (where the enclosing function's prologue — e.g. `lea rbx,[table]` —
// never ran), causing 0xC0000005 on the exit path.
// ==============================================================================

use crate::analysis::program_model::RvaRange;
use crate::analysis::switch_targets::{
    resolve_switch_targets, SwitchEntryEncoding, SwitchSection, SwitchTableLayout,
};
use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};

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
        if r.is_gpr() {
            Some(r.full_register().number() as usize)
        } else {
            None
        }
    }
    for (i, inst) in insts.iter().enumerate() {
        if inst.code() == Code::Jmp_rm64 {
            resolve_one(
                &insts, &last_def, i, &mut out, relayed, image_base, base_va, text_end,
            );
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
        if r.is_gpr() {
            Some(r.full_register().number() as usize)
        } else {
            None
        }
    }
    let inst = &insts[i];
    let mut key_va = inst.ip();
    let mut idx_reg = Register::None;
    let mut table = None;
    let mut scale = 0u32;
    let mut relative = false;

    if inst.op0_kind() == OpKind::Memory {
        idx_reg = if inst.memory_index() != Register::None {
            inst.memory_index()
        } else {
            inst.memory_base()
        };
        if idx_reg == Register::None {
            return;
        }
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
        let mut li = match last_def[ti] {
            Some(li) => li,
            None => return,
        };
        // If the last def of the jmp target is an `add rT,rX` (the relative jump-table
        // idiom `...movsxd rT,[rB+rI*4]; add rT,rB; jmp rT`), the load is one step back.
        let ld0 = &insts[li];
        if matches!(ld0.code(), Code::Add_r64_rm64 | Code::Add_rm64_r64)
            && ld0.op0_kind() == OpKind::Register
            && ld0.op0_register() == tgt_reg
        {
            relative = true;
            if li == 0 {
                return;
            }
            li -= 1;
        }
        let ld = &insts[li];
        let is_load = matches!(
            ld.code(),
            Code::Movsxd_r64_rm32 | Code::Mov_r64_rm64 | Code::Mov_r32_rm32
        );
        if !is_load || ld.op1_kind() != OpKind::Memory {
            return;
        }
        relative = relative || matches!(ld.code(), Code::Movsxd_r64_rm32);
        idx_reg = if ld.memory_index() != Register::None {
            ld.memory_index()
        } else {
            ld.memory_base()
        };
        if idx_reg == Register::None {
            return;
        }
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

    let table = match table {
        Some(t) => t,
        None => return,
    };
    if scale != 4 && scale != 8 {
        return;
    }
    let Ok(idx_vreg) = crate::vm::lifter::vreg(idx_reg) else {
        return;
    };
    // Compatibility bridge: instruction-shape recovery above remains legacy,
    // but table reads and executable-range checks are delegated to the typed,
    // bounds-checked resolver.  Project only the dense prefix back to the old
    // public `(case_value, target_va)` shape.
    let Some(table_rva) = table
        .checked_sub(image_base)
        .and_then(|v| u32::try_from(v).ok())
    else {
        return;
    };
    let Some(site_rva) = key_va
        .checked_sub(image_base)
        .and_then(|v| u32::try_from(v).ok())
    else {
        return;
    };
    let Some(text_start_rva) = base_va
        .checked_sub(image_base)
        .and_then(|v| u32::try_from(v).ok())
    else {
        return;
    };
    let Some(text_end_rva) = text_end
        .checked_sub(image_base)
        .and_then(|v| u32::try_from(v).ok())
    else {
        return;
    };
    let sections: Vec<_> = relayed
        .iter()
        .map(|s| SwitchSection {
            name: &s.name,
            rva: s.virtual_address,
            bytes: &s.bytes,
        })
        .collect();
    let Some(entry_count) = relayed.iter().find_map(|s| {
        let end = s
            .virtual_address
            .checked_add(u32::try_from(s.bytes.len()).ok()?)?;
        (s.virtual_address <= table_rva && table_rva < end)
            .then(|| ((end - table_rva) / scale).min(4097))
    }) else {
        return;
    };
    let encoding = if relative {
        SwitchEntryEncoding::Rel32 {
            base_rva: table_rva,
        }
    } else if scale == 8 {
        SwitchEntryEncoding::Va64
    } else {
        SwitchEntryEncoding::Rva32
    };
    let Ok(targets) = resolve_switch_targets(
        site_rva,
        SwitchTableLayout::Direct {
            table_rva,
            encoding,
        },
        entry_count,
        image_base,
        &sections,
        &[RvaRange {
            start: text_start_rva,
            end: text_end_rva,
        }],
    ) else {
        return;
    };
    let mut cases = Vec::new();
    for target in targets.targets {
        if target.case_value != cases.len() as u32 {
            break;
        }
        cases.push((
            i64::from(target.case_value),
            image_base + u64::from(target.target_rva),
        ));
    }
    if !cases.is_empty() {
        out.push((key_va, idx_vreg, cases));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::builder::SectionData;

    const IMAGE_BASE: u64 = 0x140000000;
    const TEXT_RVA: u32 = 0x1000;
    const TABLE_RVA: u32 = 0x3000;

    fn section(bytes: Vec<u8>) -> SectionData {
        SectionData {
            name: ".rdata".to_owned(),
            virtual_address: TABLE_RVA,
            virtual_size: bytes.len() as u32,
            characteristics: 0,
            bytes,
        }
    }

    #[test]
    fn legacy_shape_uses_typed_va64_dense_prefix() {
        let base = IMAGE_BASE + u64::from(TEXT_RVA);
        let table = IMAGE_BASE + u64::from(TABLE_RVA);
        let mut text = vec![0u8; 0x40];
        // lea rbx,[rip+table]; jmp qword ptr [rbx+rax*8]
        text[..10].copy_from_slice(&[0x48, 0x8d, 0x1d, 0xf9, 0x1f, 0x00, 0x00, 0xff, 0x24, 0xc3]);
        let mut data = Vec::new();
        data.extend_from_slice(&(base + 0x20).to_le_bytes());
        data.extend_from_slice(&(base + 0x30).to_le_bytes());
        data.extend_from_slice(&(table + 0x100).to_le_bytes());

        let got = resolve_switch_cases(&text, base, &[section(data)], IMAGE_BASE);
        assert_eq!(
            got,
            vec![(base + 7, 0, vec![(0, base + 0x20), (1, base + 0x30)])]
        );
    }

    #[test]
    fn legacy_shape_uses_typed_signed_rel32_targets() {
        let base = IMAGE_BASE + u64::from(TEXT_RVA);
        let mut text = vec![0u8; 0x40];
        // lea rbx,[rip+table]; movsxd rcx,[rbx+rax*4]; add rcx,rbx; jmp rcx
        text[..16].copy_from_slice(&[
            0x48, 0x8d, 0x1d, 0xf9, 0x1f, 0x00, 0x00, 0x48, 0x63, 0x0c, 0x83, 0x48, 0x01, 0xd9,
            0xff, 0xe1,
        ]);
        let mut data = Vec::new();
        data.extend_from_slice(&(-0x1fe0i32).to_le_bytes());
        data.extend_from_slice(&(-0x1fd0i32).to_le_bytes());
        data.extend_from_slice(&(0x100i32).to_le_bytes());

        let got = resolve_switch_cases(&text, base, &[section(data)], IMAGE_BASE);
        assert_eq!(
            got,
            vec![(base + 7, 0, vec![(0, base + 0x20), (1, base + 0x30)])]
        );
    }
}
