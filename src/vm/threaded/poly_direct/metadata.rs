use crate::vm::poly::VirtualIsaSpec;

use super::codegen_util::{
    state_disp, FLAGS_OFF, K_IMM, K_NONE, K_REG, REGS_OFF, TEMPS_OFF, VSP_OFF,
};

/// Construct the descriptor metadata consumed by the native operand decoder.
/// Offsets are u16 so a descriptor can select either P2-14 physical state bank.
pub(crate) fn build_operand_tables(spec: &VirtualIsaSpec) -> (Vec<u16>, Vec<u8>) {
    let mut offsets = vec![0u16; 256];
    let mut kinds = vec![K_NONE; 256];
    for raw in 0u16..256 {
        let raw = raw as u8;
        let payload = raw & 0x3F;
        let (offset, kind) = match raw & 0xC0 {
            0x80 => {
                let index = spec.decode_reg(payload) as i32;
                (state_disp(REGS_OFF + index * 8) as u16, K_REG)
            }
            0xC0 => (
                state_disp(TEMPS_OFF + ((payload & 7) as i32) * 8) as u16,
                K_REG,
            ),
            0x40 => (
                state_disp(if payload == 0x01 { FLAGS_OFF } else { VSP_OFF }) as u16,
                K_REG,
            ),
            _ => {
                if let Some(width) = spec.immediate_width(raw) {
                    (width as u16, K_IMM)
                } else if let Some(width) = spec.branch_target_width(raw) {
                    (width as u16, K_NONE)
                } else {
                    (0, K_NONE)
                }
            }
        };
        offsets[raw as usize] = offset;
        kinds[raw as usize] = kind;
    }
    (offsets, kinds)
}

#[cfg(test)]
mod tests {
    use super::super::codegen_util::install_runtime_layout;
    use super::*;
    use crate::vm::poly::VmArchitectureFamily;
    use crate::vm::threaded::VmRuntimeLayout;

    #[test]
    fn operand_offsets_preserve_second_bank_without_truncation() {
        let seed = 0x5032_3134_5542_3136;
        let layout = VmRuntimeLayout::from_seed(seed);
        let _guard = install_runtime_layout(&layout);
        let spec = VirtualIsaSpec::from_seed_and_family(seed, VmArchitectureFamily::Register);
        let (offsets, kinds) = build_operand_tables(&spec);
        assert!(offsets.iter().any(|offset| *offset > u8::MAX as u16));
        assert!(offsets
            .iter()
            .zip(kinds)
            .any(|(offset, kind)| kind == K_REG && *offset >= 0x400));
    }
}
